# Alpine FDE — Operator & User Guide

This guide serves as both the complete functional requirement specification and the operator runbook for Alpine FDE. All operations are invoked as `./bin/alpine-fde`.

---

## Functional Requirements & Security Guarantees

Alpine FDE satisfies the following core functional requirements:

* **FR-1: Full-Disk Encryption at Rest (LUKS2 + Argon2id):**
  All filesystem storage (root, `/home`, system binaries, swap) is encrypted at rest using LUKS2 with Argon2id KDF and high-entropy key material. No plaintext data or persistent secrets exist on unencrypted storage (the ESP holds only signature-verified boot binaries).
* **FR-2: Automated Passwordless Boot (TPM 2.0 Policy Binding):**
  During normal boots, the root volume unseals 100% automatically via the hardware TPM 2.0 with zero password prompts, releasing the volume key only when running under verified UEFI Secure Boot (`PCR 7`) and untampered kernel measurements (`PCR 11`).
* **FR-3: Anti Evil-Maid & Fail-Closed Tampering Defense:**
  If an attacker boots modified media, alters kernel command-line parameters, disables Secure Boot, or modifies firmware keys, the TPM refuses to release the key. The bootloader presents an explicit diagnostic reason and security warning, limits recovery passphrase attempts to 3 strikes, and executes immediate fail-closed poweroff (`poweroff -f`) without dropping into an interactive shell.
* **FR-4: TPM-Free Kernel Upgrades & Seamless Rollback:**
  Kernel upgrades (`apk upgrade`) and rollbacks boot passwordlessly without requiring TPM re-enrollment or re-sealing. Unified Kernel Images (UKIs) embed release-key-signed policy signatures (`.pcrsig`) verified by a single standing TPM token pinning the release public key (`PolicyAuthorize`).
* **FR-5: Flexible Storage Topologies:**
  Supports standard single-disk, accelerated hybrid storage (`--bcache` SSD caching HDD in strictly crash-safe writethrough mode), and multi-disk redundancy (Btrfs RAID1) with synchronized TPM policies. Optional ephemeral encrypted swap (`--swap`) wipes its key on poweroff.
* **FR-6: Automated Boot & Login Firmware Auditing:**
  Firmware and platform integrity are automatically audited on every boot (via a lightweight oneshot OpenRC service `alpine-fde-audit`) and on every interactive user login (via `/etc/profile.d/alpine-fde.sh`). Audits compare live PCR 0–3, PCR 7, and the TCG event log against `/etc/alpine-fde/baseline.json`. If firmware drift or tampering is detected, clear security alerts are logged to syslog and displayed immediately upon login, while `alpine-fde audit` allows manual inspection and `--accept` re-baselining.
* **FR-7: Unattended-Until-Reboot Installation Ceremony:**
  The installation command (`alpine-fde install`) runs unattended through all disk partitioning, formatting, bootstrap, and firmware NVRAM enrollment, prompting for credentials (user account, recovery passphrase, encrypted release key passphrase) only as the final interactive step before rebooting directly to disk.
* **FR-8: Zero-Exfiltration Key Custody:**
  Release signing keys (`release.pem`) are generated in-chroot and encrypted at rest (AES-256 PBKDF2), never leaving the encrypted container. No off-machine key backups or air-gapped signing ceremonies are required; catastrophic drive destruction is recovered via a single reboot to UEFI setup to reset Setup Mode.

---

## 1. Prerequisites & Firmware Preparation

Before beginning installation, your target machine must be configured in UEFI setup:

1. **Set Firmware Administrator Password (recommended, not enforced):** Protects UEFI settings against physical tampering. This is a manual prerequisite — `alpine-fde doctor` cannot probe it, so verify it yourself. Without it, an attacker with physical access can enter firmware setup, enroll their own boot keys, and install a bootkit. The disk still cannot be decrypted (the TPM seal fails closed on any Secure Boot key change), but the bootkit can fake the passphrase prompt to phish your recovery passphrase. The firmware admin password closes that first step.
2. **Clear Secure Boot Keys (Enter Setup Mode):**
   - In firmware setup, choose **Clear Secure Boot Keys** or **Delete All Keys** (sets `SetupMode: 1`).
   - Ensure **Secure Boot is OFF** during initial installation.
   > [!IMPORTANT]
   > Authenticated NVRAM variable writes (`PK`, `KEK`, `db`) require `SetupMode == 1`. If the vendor PK is not cleared, installation preflight will abort (`exit 64`) to prevent write errors or bricked firmware states.
3. **Boot Live Installation Media:** Boot an official Alpine Linux Standard live USB on the target machine.

---

## 2. Installation Ceremonies

Alpine FDE supports two primary storage layouts. Choose the one that matches your hardware:

### Topology A: Default Single- or Multi-Disk (NVMe or SATA SSD)
Partitions the disk(s) into an unencrypted ESP (`p1`) and an Argon2id LUKS2 container (`p2`) formatted with Btrfs (`@`, `@home`, `@snapshots`).

Single disk:

```sh
./bin/alpine-fde install --disk /dev/nvme0n1
```

Two or more disks (repeatable `--disk`): data and metadata are mirrored across the drives in a Btrfs RAID1 pool, and each disk is wrapped in its own independent LUKS2 container sealed to the machine's TPM 2.0 with synchronized policies:

```sh
./bin/alpine-fde install --disk /dev/nvme0n1 --disk /dev/nvme1n1
```

### Topology B: Accelerated Hybrid Storage (`--bcache`)
Accelerates one or more high-capacity backing drives (repeatable `--disk`) with a fast NVMe caching drive (`--bcache`):
- ESP (`p1`) and the bcache caching set (`p2`) reside on the fast NVMe drive.
- Each backing drive is used WHOLE as the backing device (bcache semantics: no partition table on the backing drive), registering as `/dev/bcache0`, `/dev/bcache1`, …
- A LUKS2 container sits directly on every `/dev/bcacheN` in strictly enforced **`writethrough`** mode.

Single backing drive (fast NVMe caching a slow HDD or SSD):

```sh
./bin/alpine-fde install --disk /dev/sda --bcache /dev/nvme0n1
```

Multiple backing drives (e.g. one fast NVMe caching two large HDDs): the decrypted `/dev/bcacheN` volumes are aggregated into a mirrored Btrfs root (RAID1, as in the multi-disk default above):

```sh
./bin/alpine-fde install --bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb
```

### Optional Ephemeral Swap Partition (`--swap [size]`)

Disk swap is **omitted by default**. If paging / virtual memory is needed, provide `--swap` (e.g., `--swap 4G` or `--swap 8G`):

- **Partitioning:** Allocates an additional swap partition on the target drive.
- **Ephemeral Encryption (Approach A):** Configured via `/etc/crypttab` to initialize with a fresh random key from `/dev/urandom` on every boot (`swap,cipher=aes-xts-plain64,size=512`).
- **Zero Key Residuals:** When the system powers off, the random key vanishes from RAM. Residual swap ciphertext on disk cannot be decrypted by any party.
- **Hibernation Non-Goal:** Hibernation (suspend-to-disk) remains strictly unsupported (ADR-7); ephemeral keys cannot resume memory state across power cycles.

Example with swap:

```sh
./bin/alpine-fde install --disk /dev/nvme0n1 --swap 4G
```

---

## 3. Installation & First-Boot Experience

The installation workflow is designed to fail fast during setup and complete trust finalization automatically on first boot.

### Step 1: Run the Installer (Live Media)

Boot the official Alpine Linux live USB and run `./bin/alpine-fde install` with your target drive(s):

```sh
./bin/alpine-fde install --disk /dev/nvme0n1
```

The installer executes all heavy system, package, and firmware setup operations first:
1. **Disk Partitioning & Formatting:** Partitions the target disk(s) into ESP and LUKS2 containers formatted with Btrfs.
2. **Base System Bootstrap:** Installs the Alpine base system, kernel, boot manager, and administration tools (`doas`).
3. **Platform Key Generation:** Generates your custom Secure Boot platform keys (`PK`, `KEK`, `db`) and your release signing key on the encrypted target root.
4. **Firmware NVRAM Enrollment:** Enrolls your custom platform keys into UEFI NVRAM (`db → KEK → PK`), closing Setup Mode.
5. **Bootloader & UKI Build:** Builds and Authenticode-signs `systemd-boot` and the initial Unified Kernel Image (UKI).
6. **Initial TPM Sealing:** Seals an initial TPM 2.0 token to the signed UKI measurement (PCR 11), ensuring the upcoming reboot unlocks without manual password intervention.

> [!TIP]
> **Fast Fail-Debug Loop:** All disk operations, package downloads, firmware writes, and UKI signing execute before asking for credentials. If any hardware, network, or firmware step fails, the installer aborts immediately so failures are discovered fast during setup without wasting time re-typing passwords.

### Step 2: Credential Ceremony (Final Step Before Reboot)

Once all installation, firmware enrollment, and build steps succeed, the installer prompts for exactly three credentials (no-echo), in this order:
1. **LUKS2 recovery passphrase:** Enrolled into keyslot 0 as your emergency fallback passphrase. Entropy floors are enforced; you are re-prompted until they are met.
2. **User account password:** Sets up your local administrative user account for login. **Press Enter to reuse the recovery passphrase** instead of typing a new one.
3. **Release signing key passphrase:** Encrypts `/etc/alpine-fde/keys/release.pem` at rest with AES-256 (PBKDF2 HMAC-SHA256, ≥ 600,000 iterations). **Press Enter to reuse the recovery passphrase** instead of typing a new one.

The installer then scrubs temporary keys from memory, unmounts the filesystems, and reboots directly into the target disk.

### Step 3: First Boot & Automated Trust Finalization

Upon reboot, the machine boots from the target disk:
1. **Early-Boot Secure Boot Guard in initrd (Refuses to Boot if Secure Boot is Disabled):**
   - In the initrd/initramfs, the early-boot hook verifies the firmware Secure Boot state (`secureboot == 1 && setup_mode == 0`) **before** attempting to unseal or unlock the root disk.
   - **If Secure Boot is OFF / disabled:** The initrd **strictly refuses to boot**. It aborts the boot process immediately with a fatal security error, never evaluates the TPM token, never prompts for any passphrase, and never unseals the root filesystem. It prints an explicit notice on the console instructing the user that Secure Boot must be enabled in UEFI setup, waits for user confirmation (*Press Enter to reboot*), and reboots directly into UEFI firmware setup. The initrd will completely refuse to boot the operating system until Secure Boot is active.
   - **If Secure Boot is ON / enabled:** The initrd proceeds to evaluate the TPM 2.0 token against PCR 11, unsealing the root container **100% automatically with zero password prompts**.
2. **Automated Finalization (Runs on First Boot Until Success):**
   - The standalone OpenRC service (`alpine-fde-finalize`) runs automatically before reaching the login prompt:
     - Detects provisional state directly from the LUKS2 token (`pcrs: [11]`) and `baseline.json` (`expected_pcr7: "pending"`).
     - Captures the verified Secure Boot state (`PCR 7`) as the trusted baseline (`audit --init`), updating `/etc/alpine-fde/baseline.json`.
     - Upgrades the TPM seal from provisional {PCR 11} to **{PCR 7, PCR 11}** (bound to both firmware configuration and the signed UKI).
     - Purges the temporary setup key from Keyslot 2.
     - **Auto-removes itself upon completion:** Unregisters itself from OpenRC (`rc-update del alpine-fde-finalize default`) and deletes the service script (`rm -f /etc/init.d/alpine-fde-finalize`).
   - If an unexpected error or power loss interrupts the process, the provisional token and service remain in place, automatically retrying on the next boot until completion.

When the login prompt appears, the system is **100% finalized**. There are no leftover unfinalized items, zero synthetic state files, and zero service overhead on future normal boots.

### Step 4: Zero-Exfiltration Key Custody

Alpine FDE implements a **Zero-Exfiltration** security posture:
* Platform and release signing keys (`/etc/alpine-fde/keys/`) **never leave the encrypted root filesystem**.
* Keys are **never backed up off-machine**, eliminating remote backup server compromise or lost USB keys as an attack vector.
* For all common recovery procedures (failed ESP, kernel repair, cache SSD replacement, or RAID1 member replacement), keys are accessed directly in-place from the unlocked root volume (`/mnt/etc/alpine-fde/keys`).
* In the catastrophic event of total root drive destruction, verified boot is restored by entering UEFI setup once to reset Secure Boot to Setup Mode, followed by a fresh installation.

---

## 4. Daily Operations

### Command Reference

Everything runs through a single tool: `./bin/alpine-fde <command>` (examples earlier in this guide show the full path; on an installed system the commands are on `PATH` as `alpine-fde <command>`). Lifecycle steps such as TPM enrollment and first-boot finalization run **automatically** — you never invoke them (see [§3](#3-installation--first-boot-experience)).

| Command | What it does | When you use it |
|---|---|---|
| `install` | The guided installation ceremony: partitions and encrypts disk(s) (supports single-disk, `--bcache` hybrid, multi-disk RAID1, and optional ephemeral encrypted swap via `--swap [size]`), installs Alpine base, enrolls Secure Boot keys, and seals the disk key to the TPM (see [§2](#2-installation-ceremonies) and [§3](#3-installation--first-boot-experience)). | Setting up a new machine — run once, from live media. |
| `ukictl` | Builds or removes the signed boot image for a kernel. Runs automatically on kernel upgrades; you run it manually when rebuilding boot images during recovery ([Runbook 1](#runbook-1-broken-cache-ssd--esp-rebuild-hybrid-bcache-setup), [Runbook 2](#runbook-2-failed-drive-replacement-in-btrfs-raid1)) or for custom kernels. | Only in recovery or custom-kernel scenarios. |
| `rotate` | Changes the recovery passphrase — no re-encryption, no TPM re-enrollment. | When the passphrase was shared or may be compromised ([Runbook 4](#runbook-4-recovery-passphrase-rotation)). |
| `audit` | Verifies the running machine against its trusted baseline (firmware state and boot measurements). `--init` records the first baseline; `--accept` accepts a verified new one after a legitimate change. | After firmware/BIOS updates that prompt for the recovery passphrase ([Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update)). |
| `status` | Shows the current trust state at a glance: Secure Boot state, TPM seal, keyslots, and boot images. | Any time you want to confirm the machine is sealed, signed, and finalized. |
| `bootnext` | Boots a retained kernel once, on the next reboot only. | Testing a rollback to a previous kernel — see [Booting Alternative or Retained Kernels](#booting-alternative-or-retained-kernels). |
| `pre-upgrade` | Snapshots the root filesystem so a failed upgrade can be rolled back. | Before upgrades or risky experiments — see [Btrfs Snapshots & Userspace Rollback](#btrfs-snapshots--userspace-rollback). |
| `doctor` | Checks the environment before an install (missing packages, TPM presence, Secure Boot state), and the trust chain afterwards. | Before installing on a new machine, and as the first sanity check when something looks wrong. |
| `enroll-tpm` | Seals or re-enrolls the LUKS2 container to the TPM 2.0 policy. Runs automatically during installation and UKI builds. | During disaster recovery ([Runbook 2](#runbook-2-multi-disk-raid1-member-replacement--re-sync), [Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update)) after drive replacement or PCR 7 drift re-baselining. |
| `finalize` | Completes trust finalization: baseline capture, {PCR 7, PCR 11} token upgrade, and temporary keyslot purge. Runs automatically on first boot via `alpine-fde-finalize`. | Emergency manual completion if first-boot finalization was interrupted. |

> [!NOTE]
> **Flags and exit codes:** Global flags (`--disk`, `--bcache`, `--swap`, `--yes`, `--root`, `--esp`, `--fs`) must come **before** the subcommand — e.g. `alpine-fde --root /mnt audit --accept`, as used in the runbooks below. `--version` and `--help` are always available. Exit codes are stable and safe to rely on in scripts: `0` success, `1` drift or check failed, `2` usage error, `3` not implemented, `64` fail-closed error.

### Verifying Trust & Finalization Status (`status`)

You can inspect the running trust chain and finalization state at any time:

```sh
alpine-fde status
```

Status is evaluated directly from **cryptographic and system ground truth** rather than a synthetic tracking file:
- **Secure Boot & Firmware:** Verifies active Secure Boot (`SecureBoot=1`) and custom platform keys (`SetupMode=0`) via `efivarfs`.
- **TPM 2.0 Seal Binding:** Inspects the LUKS2 header token (`cryptsetup luksDump`) to confirm the token policy binds both **{PCR 7, PCR 11}** (finalized) rather than {PCR 11} only (provisional).
- **Keyslot Status:** Confirms that the recovery passphrase (Keyslot 0) and sealed TPM key (Keyslot 1) are active, and that the ephemeral install key (Keyslot 2) has been purged.
- **Baseline State:** Confirms `/etc/alpine-fde/baseline.json` holds a finalized SHA-256 digest for `expected_pcr7` rather than `"pending"`.
- **First-Boot Service:** Confirms that the one-shot `alpine-fde-finalize` service has completed and removed itself (`/etc/init.d/alpine-fde-finalize` is absent).

### Kernel Upgrades & Signing Key Passphrase Prompt
Alpine package upgrades (`apk upgrade`) that install or update a kernel are handled automatically:
1. The initramfs is rebuilt with early-boot unseal support.
2. The boot image is rebuilt for the new kernel and **signed with your release signing key** — this is what lets the TPM keep trusting it without any re-enrollment.
   > [!NOTE]
   > Because your release signing key is encrypted at rest, `apk upgrade` prompts interactively for your **release signing key passphrase** during the upgrade. Unattended/non-interactive upgrades will fail loudly if the passphrase is not provided.
3. Next boot: boots into the new kernel **100% passwordless**. No TPM re-enrollment is required.

### Btrfs Snapshots & Userspace Rollback
Before major system changes or upgrades, take an atomic snapshot:

```sh
alpine-fde pre-upgrade
```

This creates a read-only snapshot of `@` under `/.snapshots/<timestamp>` (subvolume `@snapshots`). If an upgrade breaks userspace, restore the snapshot:
```sh
# Mount top-level Btrfs volume
mount -o subvolid=5 /dev/mapper/root-crypt /mnt

# Move broken root subvolume and restore snapshot to @
mv /mnt/@ /mnt/@broken
btrfs subvolume snapshot /mnt/@snapshots/<timestamp> /mnt/@

# Unmount and reboot
umount /mnt
reboot
```
*(Restoring a snapshot changes only filesystem contents — it requires no re-signing and no re-enrollment, so rollback boots stay passwordless).*

### Booting Alternative or Retained Kernels
Up to 3 kernels are retained on the ESP. To boot a previous kernel one time:

```sh
# View available entries
bootctl list

# Select kernel for next boot only
alpine-fde bootnext alpine-fde-6.6.x-lts.efi
```

The system reboots into the previous kernel **without requiring a password**, because each retained boot image carries its own signature that the TPM accepts.

### Automated Boot & Login Auditing (Firmware Drift Detection)

In addition to manual `alpine-fde audit` execution, platform firmware integrity is monitored automatically at two key points without any background daemons:

1. **On Every Boot (`alpine-fde-audit` oneshot service):**
   Runs in the OpenRC `default` runlevel scheduled with `after *` to execute **last immediately before the login prompt**. This guarantees that its warning notice is not scrolled off-screen by startup logs from other services (networking, sshd, chrony, etc.). It compares current PCR 0..3, PCR 7, and the TCG event log against `/etc/alpine-fde/baseline.json`. If any measurement drifts, it logs an explicit warning to syslog/dmesg and writes a security notice to `/etc/issue` and `/etc/motd`. The service then terminates immediately (0 MB resident memory, 0 CPU overhead).

2. **On Every Login (`/etc/profile.d/alpine-fde.sh`):**
   When an operator logs into an interactive shell, the profile hook checks whether firmware drift was detected. If drifted, it displays a high-visibility security alert banner right at the terminal, instructing the user on how to verify and accept or investigate.

---

## 5. Disaster Recovery & Hardware Maintenance

---

### The Console Experience When Something Is Wrong

Alpine FDE provides high-visibility console warnings across all critical failure domains: early-boot TPM unseal failures, pre-unseal Secure Boot guard halts, boot-time firmware drift detection, interactive login drift alerts, and first-boot finalization warnings.

#### 1. Early-Boot TPM Unseal Failure (Initramfs Console)

When hardware, firmware, or boot components change, the TPM refuses to release the volume encryption key. The early-boot initramfs hook halts the automated boot sequence, displays the exact diagnostic failure reason and a security warning, and prompts for the recovery passphrase:

```text
:: Alpine FDE: TPM unseal failed!
:: REASON: TPM policy authorization failed (PCR 7 / PCR 11 mismatch).
::
:: WARNING: Boot integrity verification failed!
:: This typically occurs due to:
::   1. A legitimate firmware/BIOS update or Secure Boot key modification (PCR 7 changed).
::   2. A modified or corrupted kernel / UKI boot image (PCR 11 changed).
::   3. An unauthorized physical tampering attempt (Evil Maid attack).
::
:: If you did NOT recently update firmware or install system updates,
:: do NOT enter your passphrase. Power off immediately and inspect your machine!
::
Enter recovery passphrase for /dev/nvme0n1p2 (attempt 1 of 3): [no-echo]
```

**Key Security Guarantees During Unseal Failure:**
1. **Diagnostic Failure Reason:** The initramfs hook explicitly identifies whether unseal failed due to PCR 7 drift (firmware/NVRAM changes), PCR 11 drift (kernel/cmdline tampering), or TPM communication/lockout errors.
2. **Evil-Maid Security Advisory:** Warns the operator that an unexpected recovery prompt may indicate an evil-maid attack or physical tampering, instructing them to power off if unexpected.
3. **Fail-Closed 3-Strike Rule:** The operator is granted a maximum of 3 attempts to enter the Keyslot 0 recovery passphrase. If the 3rd attempt fails, the system executes **`poweroff -f` immediately**. Dropping into an interactive rescue shell is strictly blocked, preventing dictionary attacks and memory inspection.

#### 2. Initrd Refuses to Boot When Secure Boot Is Disabled (Initramfs Console)

If the machine boots while Secure Boot is disabled in firmware setup during the provisional window, the early-boot hook in the initrd **strictly refuses to boot**. It halts immediately before attempting any unsealing or prompting for passphrases:

```text
:: Alpine FDE: Pre-unseal Secure Boot guard FAILED!
:: REASON: Secure Boot is disabled or in Setup Mode (secureboot=0, setup_mode=0).
::
:: CRITICAL: The initrd strictly refuses to boot while Secure Boot is OFF!
:: The encrypted root volume will NOT be unlocked.
:: You must enable Secure Boot in your UEFI/BIOS firmware setup.
::
Press Enter to reboot into UEFI Firmware Setup...
```

#### 3. Boot-Time Firmware Drift Warning (`alpine-fde-audit` OpenRC Service)

When the oneshot `alpine-fde-audit` service runs during system boot and detects a mismatch against `/etc/alpine-fde/baseline.json`, it logs an explicit warning to OpenRC console output and syslog:

```text
 * Starting alpine-fde-audit ...
[WARN] Alpine FDE: Platform firmware drift detected during boot!
[WARN] One or more PCR measurements do not match the trusted baseline.
[WARN] Details logged to /var/log/messages; review with 'alpine-fde audit'.
 [ !! ]
```

It also updates the pre-login console banner (`/etc/issue`) and `/etc/motd`:

```text
*******************************************************************************
* WARNING: Alpine FDE detected firmware/platform drift on this machine!       *
* Measurements differ from /etc/alpine-fde/baseline.json                      *
* Run 'alpine-fde audit' to inspect, or 'alpine-fde audit --accept' if valid. *
*******************************************************************************
```

#### 4. Interactive Login Security Alert (`/etc/profile.d/alpine-fde.sh`)

When an operator logs into an interactive shell, if firmware drift is detected, an alert banner is displayed immediately at the top of the terminal session:

```text
================================================================================
[SECURITY ALERT] Alpine FDE Firmware Drift Detected!
================================================================================
Platform measurements have drifted from the trusted baseline:
  - PCR 0 (Firmware):    DRIFT
  - PCR 7 (Secure Boot): DRIFT
  - TCG Event Log:       DRIFT

If you recently updated firmware or BIOS settings, verify and accept via:
  alpine-fde audit --accept && alpine-fde enroll-tpm
Otherwise, investigate potential unauthorized firmware modification!
================================================================================
```

#### 5. First-Boot Finalization Failure (`alpine-fde-finalize`)

Because the initrd pre-unseal guard already blocks boot if Secure Boot is disabled, by the time the OS reaches userspace, Secure Boot is already active (`secureboot=1, setup_mode=0`). Any failure during first-boot finalization would stem from a hardware TPM communication error or storage/keyslot update fault:

```text
 * Starting alpine-fde-finalize ...
WARNING: Alpine FDE trust finalization failed!
ERROR: TPM token upgrade failed (tpm2_create returned exit code 1).
The provisional seal and keyslot remain intact to retry on next boot,
or you can inspect and complete manually with: alpine-fde finalize
 [ !! ]
```

*(Note: If an operator manually executes `alpine-fde finalize` from an external live media environment where Secure Boot is toggled off, it will guard against that and report `Secure Boot guard failed: secureboot=0 setup_mode=0`).*

---

### Runbook 1: Broken Cache SSD & ESP Rebuild (Hybrid bcache Setup)

**Scenario:** In an accelerated single-disk or multi-disk hybrid setup (`--disk /dev/sda --bcache /dev/nvme0n1` or `--bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb`), the NVMe SSD physically fails, taking down both the ESP (`p1`) and the cache partition (`p2`).

Because the system was installed in **`writethrough`** mode, **100% of your data remains intact on the backing disk(s) (`/dev/sda`, `/dev/sdb`)**.

#### Step 1: Boot Recovery Live Media
Boot from an Alpine Linux live USB.

#### Step 2: Assemble Backing Device in Standalone Mode
Without the caching drive present, load the bcache module and register the backing disk(s) directly (each backing drive is used WHOLE — bcache semantics):
```sh
modprobe bcache
mdev -s
echo /dev/sda > /sys/fs/bcache/register
# For multi-disk setups, register all backing drives:
# echo /dev/sdb > /sys/fs/bcache/register
# The virtual block devices appear at /dev/bcache0 (and /dev/bcache1)
```

#### Step 3: Unlock and Mount Root Filesystem
Unlock LUKS2 using your **recovery passphrase**:
```sh
cryptsetup open /dev/bcache0 root-crypt
# For multi-disk setups:
# cryptsetup open /dev/bcache1 root2

# Mount Btrfs root subvolume (single device or RAID1 pool):
mount -o subvol=@ /dev/mapper/root-crypt /mnt
mount -o subvol=@home /dev/mapper/root-crypt /mnt/home
```

#### Step 4: Prepare the Replacement SSD
Install a replacement NVMe SSD and identify its device node (e.g. `NEW_SSD="/dev/nvme0n1"`):
```sh
export NEW_SSD="/dev/nvme0n1"

# 1. Partition the new SSD (p1: ESP sized ≥ 128MB-512MB, p2: remainder for cache)
printf 'label: gpt
start=2048, size=1048576, type=uefi, name="esp"
type=linux, name="cache"
' | sfdisk "$NEW_SSD"

# 2. Format the new ESP
mkfs.vfat -F 32 -n EFI "${NEW_SSD}p1"
mkdir -p /mnt/efi
mount "${NEW_SSD}p1" /mnt/efi

# 3. Create the new bcache caching set
make-bcache -C "${NEW_SSD}p2"

# 4. Attach new cache to the running backing device(s) in writethrough mode
echo "${NEW_SSD}p2" > /sys/fs/bcache/register
CSET_UUID=$(bcache-super-show "${NEW_SSD}p2" | grep cset.uuid | awk '{print $2}')
echo "$CSET_UUID" > /sys/block/bcache0/bcache/attach
echo writethrough > /sys/block/bcache0/bcache/cache_mode
# For multi-disk setups, attach remaining backing devices:
# echo "$CSET_UUID" > /sys/block/bcache1/bcache/attach
# echo writethrough > /sys/block/bcache1/bcache/cache_mode
```

#### Step 5: Rebuild the ESP inside Chroot
Enter chroot to reinstall and re-sign boot binaries:
```sh
# Bind-mount virtual filesystems
mount --bind /dev /mnt/dev
mount --bind /proc /mnt/proc
mount --bind /sys /mnt/sys
mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars

chroot /mnt /bin/sh
```

Inside chroot:
```sh
export NEW_SSD="/dev/nvme0n1"

# 1. Update /etc/fstab with the new ESP PARTUUID
ESP_PARTUUID=$(blkid -s PARTUUID -o value "${NEW_SSD}p1")
sed -i -E "s#(UUID|PARTUUID)=[^ ]+ /efi#PARTUUID=$ESP_PARTUUID /efi#" /etc/fstab

# 2. Install systemd-boot onto the new ESP
bootctl install --esp-path=/efi

# 3. Sign systemd-boot with your custom release key (prompts for release.pem passphrase)
sbsign --key /etc/alpine-fde/keys/release.pem --cert /etc/alpine-fde/keys/release.crt --output /efi/EFI/systemd/systemd-bootx64.efi.signed /efi/EFI/systemd/systemd-bootx64.efi
mv /efi/EFI/systemd/systemd-bootx64.efi.signed /efi/EFI/systemd/systemd-bootx64.efi

sbsign --key /etc/alpine-fde/keys/release.pem --cert /etc/alpine-fde/keys/release.crt --output /efi/EFI/BOOT/BOOTX64.EFI.signed /efi/EFI/BOOT/BOOTX64.EFI
mv /efi/EFI/BOOT/BOOTX64.EFI.signed /efi/EFI/BOOT/BOOTX64.EFI

# 4. Rebuild signed UKIs on the new ESP for the target kernel
TARGET_KVER=$(ls -1 /lib/modules | sort -V | tail -n1)
alpine-fde ukictl build "$TARGET_KVER"

# Exit chroot and unmount
exit
umount -R /mnt
```

#### Step 6: Reboot
Reboot the machine. Because Secure Boot keys in UEFI NVRAM were unchanged and the new UKI was signed by the same `release.pem`, **the machine boots and automatically unseals via TPM with zero passwords required**.

---

### Runbook 2: Failed Drive Replacement in Btrfs RAID1

**Scenario:** In a multi-disk RAID1 installation (`--disk /dev/nvme0n1 --disk /dev/nvme1n1`), one drive fails.

#### Step 1: Degraded Boot or Live Media Rescue
Boot using Alpine live USB media, open the surviving member (`cryptsetup open /dev/nvme0n1p2 root1`), and mount degraded (`mount -o degraded,subvol=@ /dev/mapper/root1 /mnt`).

#### Step 2: Replace Hardware and Re-format Container
1. Replace the failed hardware drive with a new drive (`/dev/nvme1n1`).
2. Partition and format the replacement container with LUKS2 using pinned Argon2id parameters:
   ```sh
   printf 'label: gpt\ntype=linux, name="root"\n' | sfdisk /dev/nvme1n1
   cryptsetup luksFormat --type luks2 --pbkdf argon2id \
     --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
     /dev/nvme1n1p1
   cryptsetup open /dev/nvme1n1p1 root-repl
   ```

#### Step 3: Replace the Device in Btrfs
```sh
btrfs filesystem show /mnt
btrfs replace start 2 /dev/mapper/root-repl /mnt
```

#### Step 4: Seal Replacement Container to TPM 2.0
```sh
LUKS_UUID=$(cryptsetup luksUUID /dev/nvme1n1p1)
alpine-fde --root /mnt enroll-tpm --uuid "$LUKS_UUID"
```

#### Step 5: Update crypttab and Rebuild UKI
Update `/mnt/etc/crypttab` with the new container UUID and rebuild the UKI:
```sh
TARGET_KVER=$(ls -1 /mnt/lib/modules | sort -V | tail -n1)
alpine-fde --root /mnt ukictl build "$TARGET_KVER"
```

#### Variation: Failed Backing Drive in Accelerated Multi-Disk Hybrid Setup (`--bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb`)

If a backing HDD (e.g. `/dev/sdb`) fails in an accelerated hybrid RAID1 setup:

1. **Boot live media and assemble surviving array degraded:**
   ```sh
   modprobe bcache
   echo /dev/sda > /sys/fs/bcache/register
   cryptsetup open /dev/bcache0 root1
   mount -o degraded,subvol=@ /dev/mapper/root1 /mnt
   ```
2. **Install replacement drive** (e.g. `/dev/sdc`) — it is used WHOLE as the
   backing device (bcache semantics: no partition table on the backing drive).
   Wipe stale superblocks first (bcache refuses devices with leftover
   signatures):
   ```sh
   dd if=/dev/zero of=/dev/sdc bs=1M count=1
   dd if=/dev/zero of=/dev/sdc bs=1M count=1 seek=$(( $(blockdev --getsize64 /dev/sdc) / 1048576 - 1 ))
   ```
3. **Format as bcache backing device and attach to the NVMe caching set:**
   ```sh
   make-bcache -B /dev/sdc
   echo /dev/sdc > /sys/fs/bcache/register
   # Registered as /dev/bcache1
   CSET_UUID=$(bcache-super-show /dev/nvme0n1p2 | grep cset.uuid | awk '{print $2}')
   echo "$CSET_UUID" > /sys/block/bcache1/bcache/attach
   echo writethrough > /sys/block/bcache1/bcache/cache_mode
   ```
4. **Format LUKS2 on `/dev/bcache1` with Argon2id parameters:**
   ```sh
   cryptsetup luksFormat --type luks2 --pbkdf argon2id \
     --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
     /dev/bcache1
   cryptsetup open /dev/bcache1 root-repl
   ```
5. **Rebuild Btrfs RAID1 array and seal to TPM 2.0:**
   ```sh
   btrfs replace start <missing-devid> /dev/mapper/root-repl /mnt
   LUKS_UUID=$(cryptsetup luksUUID /dev/bcache1)
   alpine-fde --root /mnt enroll-tpm --uuid "$LUKS_UUID"
   ```

---

### Runbook 3: PCR 7 Drift After Firmware/BIOS Update

**Scenario:** Following a motherboard BIOS update, UEFI variables change, causing PCR 7 to drift. Booting prompts for the **recovery passphrase**.

1. Enter your **recovery passphrase** at the boot prompt to complete boot into Alpine.
2. Verify the cause of the drift:
   ```sh
   alpine-fde audit
   ```
3. If the changes are legitimate (expected firmware update), accept the new baseline:
   ```sh
   alpine-fde audit --accept
   ```
4. Re-enroll keyslot 1 to the new PCR 7 value:
   ```sh
   alpine-fde enroll-tpm
   ```
5. Subsequent boots resume passwordless automatic unlock.

---

### Runbook 4: Recovery Passphrase Rotation

**Scenario:** The recovery passphrase was shared or is suspected of being compromised.

Run the passphrase rotation command:
```sh
alpine-fde rotate
```
* Prompts for the existing passphrase, verifies the entropy floor on the new passphrase, and updates LUKS2 keyslot 0.
* Volume encryption keys and TPM 2.0 seals remain untouched (no re-encryption or TPM re-enrollment required).

---

### Runbook 5: Boot Reconstruction & Drive Replacement (Zero-Exfiltration)

**Scenario:** The boot partition (ESP) was corrupted or wiped, or a drive was replaced. Because private keys are never exported or backed up off-machine (Zero-Exfiltration), recovery is performed using keys directly from the unlocked encrypted drive, or via a single firmware reset for complete drive replacements.

#### Case A: In-Place Boot Reconstruction (ESP Rebuild / Bootloader Corruption)
If the encrypted root container is intact:
1. **Boot Alpine Live USB and unlock root:**
   ```sh
   cryptsetup open /dev/nvme0n1p2 root-crypt
   mount -o subvol=@ /dev/mapper/root-crypt /mnt
   mount /dev/nvme0n1p1 /mnt/efi
   ```
2. **Rebuild bootloader and UKIs:**
   The keys reside inside the unlocked root volume at `/mnt/etc/alpine-fde/keys/`. Run `ukictl build`:
   ```sh
   TARGET_KVER=$(ls -1 /mnt/lib/modules | sort -V | tail -n1)
   alpine-fde --root /mnt ukictl build "$TARGET_KVER"
   ```
   *(Prompts for your release signing key passphrase to decrypt `/mnt/etc/alpine-fde/keys/release.pem`)*
3. **Unmount and reboot:**
   ```sh
   umount -R /mnt
   reboot
   ```
   *(The system boots and unlocks automatically via TPM 2.0).*

#### Case B: Total Root Drive Destruction & Replacement
If the physical drive hosting the root container has suffered catastrophic hardware failure:
1. **No key backups required:** Because private keys are strictly confined to the encrypted disk, there are no remote keys to restore or leak.
2. **Reboot into UEFI Firmware Setup:** Clear existing Secure Boot keys to return the machine to **Setup Mode** (`SetupMode=1`).
3. **Install fresh drive & run installer:**
   Boot an Alpine live USB with the replacement drive installed and run `./bin/alpine-fde install`:
   ```sh
   ./bin/alpine-fde install --disk /dev/nvme0n1
   ```
   The installer generates a fresh platform key set and release key, writes authenticated variables to NVRAM, seals the new container to the TPM, and restores passwordless boot.
