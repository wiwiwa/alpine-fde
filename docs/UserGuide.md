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
  Kernel upgrades (`apk upgrade`) and rollbacks boot passwordlessly without requiring TPM re-enrollment or re-sealing. Unified Kernel Images (UKIs) embed release-key-signed policy signatures (`.pcrsig`) verified by a standing TPM token pair (one policy per console variant) pinning the release public key (`PolicyAuthorize`).
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
2. **Clear Secure Boot Keys (Enter Setup Mode) — OR keep a platform key enrolled (deferred-enrollment mode):**
   - Default (write flow): in firmware setup, choose **Clear Secure Boot Keys** or **Delete All Keys** (sets `SetupMode: 1`), and ensure **Secure Boot is OFF** during initial installation.
   - Alternative (factory/custom PK deployments, proven on a real the target server the target server): keep the platform's own PK/KEK/db (e.g. via the firmware's **Restore Default Policy Entries**) with Secure Boot ON. The installer then makes **no NVRAM writes**; after the install it stages the release certificate (`db.cer` + the vendor option-ROM certificate) on the ESP and, as its final output, prints the step-by-step firmware-UI import instructions and reboots into firmware setup (after your explicit Enter confirmation) for you to import them into the **existing** key database via the firmware UI. Secure Boot can stay enabled throughout this mode. Do not import the staged `KEK.cer`/`PK.cer` in this mode — the platform's own PK/KEK stay.
   > [!IMPORTANT]
   > Authenticated NVRAM variable writes (`PK`, `KEK`, `db`) require `SetupMode == 1`. If a platform key IS enrolled (`SetupMode == 0` with a PK present), the install switches to the deferred-enrollment mode above instead of writing NVRAM. Only a contradictory state (`SetupMode == 0` with no PK) aborts preflight (`exit 64`).
3. **Enable the SHA-256 PCR bank (mechanism requirement — checked before install):** some boards ship their TPM restricted to **SHA-1-only** PCRs (the target server: BIOS `Tpm2Algorithm = SHA1`). The seal is SHA-256 and cannot be created on such a machine — the symptom used to be an install that ran to completion and only died at the final reseal. In firmware setup, set the TPM algorithm / PCR bank to **SHA-256** (Dell: `Security → TPM Advanced Settings → TPM2 Algorithm Selection = SHA256`) and reboot. The install preflight now reads the PCR bank selection and **aborts before any disk mutation** if SHA-256 is missing (`alpine-fde doctor` reports the same as a `[fail]` line with this remedy).
4. **Boot Live Installation Media:** Boot an official Alpine Linux Standard live USB on the target machine.

### Real-Hardware & Firmware Notes (vendor-agnostic)

Findings from live bare-metal installs (2026-09 through 2026-10). The installer and boot hook adapt to this firmware automatically where they can; the firmware-side prerequisites below **cannot** be automated and must be satisfied by the operator. These statements are vendor-agnostic — for vendor-specific remediation paths (BIOS-settings navigation, management-controller workflows, exact firmware names), see the deployment notes under `docs/research/` (e.g. `docs/research/dell-poweredge-r640.md`).

1. **No software reboot-to-firmware-setup (`OsIndications` unsupported).** Some firmware exposes no `OsIndicationsSupported` variable, so software boot-straight-into-setup is impossible — enter firmware setup with the vendor's POST key (commonly F2). The early-boot Secure Boot guard detects the missing support at boot, prints the full manual steps (import the staged keys from the ESP's `alpine-fde-keys` directory in the documented order, enable Secure Boot, save and exit), prompts *Press Enter to reboot*, and reboots plainly — press the setup key during the next POST (see [§3 Step 3](#step-3-first-boot--automated-trust-finalization)).
2. **Key import goes through `efi-updatevar`, not raw efivarfs writes.** Some firmware refused `sign-efi-sig-list`-format packets written directly to `efivarfs`, but accepts the native `EFI_VARIABLE_AUTHENTICATION_2` packets the installer emits via `efi-updatevar` (efitools). Authenticated **deletes** additionally need signed-empty packets plus `chattr -i` on the efivarfs node first — efivarfs marks authenticated variables immutable at creation, so any removal attempt dies `EPERM` without it. The installer handles all of this; the operator takeaways are: make sure `efitools` (`efi-updatevar`) and `e2fsprogs` (`chattr`) are available on the live host, and never hand-write the variables with `cat`/`printf` redirection.
3. **Flash SB-capable storage and NIC firmware BEFORE enabling Secure Boot.** With Secure Boot enforced, out-of-band device firmware — NIC PXE option ROMs and storage-controller (RAID) option ROMs — can fail the firmware's UEFI0072 Secure Boot policy checks at POST if the option ROM is stale or unsigned. In the verified failure, the storage controller's option ROM refusal blocked RAID initialization (disks invisible to the installer). **Prerequisite: flash current, SB-capable controller and NIC firmware via the management controller before enabling Secure Boot.** If it bites anyway, the POST screen offers **F1 (continue)** / **F2 (setup)**.
4. **db contents: reset + release+vendor rebuild.** The db is no longer custom-only. During enrollment (Setup Mode, before the KEK and PK writes) the installer **resets db** — an authenticated delete of its existing content — and then **rebuilds it in one authenticated write** as the Alpine FDE release certificate **plus the vendor trust anchors** shipped in `certs/vendor/` (default: the Microsoft Option ROM UEFI CA, the option-ROM CA that authorizes signed NIC PXE / storage option ROMs, which is what fails UEFI0072 when missing). `dbx` is never touched — it stays the revocation list. The rebuild **replaces** the whole variable, so re-installs never accumulate duplicate certificates. Knobs: `ALPINE_FDE_DB_VENDOR=none` restores the minimal release-cert-only db (the old behavior); `ALPINE_FDE_DB_VENDOR_DIR` points at an alternative vendor directory. The vendor `.cer` files are additionally staged to the ESP's `alpine-fde-keys/` directory so an operator can append them via the firmware UI on boards where the NVRAM writes cannot run.
5. **After "Delete All Policy Entries", OS-side NVRAM writes may be refused: recover via the firmware UI and the staged files.** On some firmware, OS-side authenticated writes of PK/KEK/db (`efi-updatevar`) that succeeded the day before were refused with `EACCES` ("wrong filesystem permissions") after the operator used the firmware's **Delete All Policy Entries** — the wipe changes the variable-storage state in a way the kernel-visible efivarfs does not explain, and the installer cannot work around it. The install degrades gracefully: it stages the key material to the ESP's `alpine-fde-keys/` directory and continues. That directory now carries everything the firmware UI needs, **no extra LUKS unlock required**: the `.auth` packets (for `KeyTool.efi` / `efi-updatevar` repair only — the setup UI cannot import them), the **import-ready certificates** `db.cer` (the release cert, from `release.crt`), `KEK.cer`, `PK.cer`, the vendor option-ROM CA `.cer`, and a `README.txt` repeating the runbook below. Documented recovery:
   1. Reboot into firmware setup (the vendor's POST key) and open Security / Secure Boot / Key Management.
   2. Import **`db.cer`** into the Key Database — **and then the vendor option-ROM CA `.cer` into db as well.** The db holds BOTH the release certificate (it authorizes the signed bootloader/kernel) and the vendor option-ROM CA: under custom keys, without the vendor cert, signed NIC PXE / storage option ROMs fail the firmware's UEFI0072 Secure Boot policy at POST (the storage controller can refuse to initialize and the disks vanish — see item 3).
   3. Import **`KEK.cer`** into the Key Exchange Key.
   4. Import **`PK.cer`** into the Platform Key **last** — enrolling the PK flips the platform to **User Mode** and locks the key database; no further key imports are possible until the PK is removed again.
   5. **Enable Secure Boot** (the platform must show User Mode, Custom mode), set the firmware administrator password, save and exit, and let the install/first boot finish (first boot stays guarded until the keys are imported, ADR-20).

   All the staged `.cer` files are **DER** — some firmware imports `.cer` files in DER encoding only (a PEM `.cer` is rejected with "The import operation did not complete successfully"; observed live). `db.cer` is the DER encoding of the keydir's `release.crt`, converted at staging time.
6. **Boot entries are created for you.** `install` creates ONE firmware boot entry per kernel version — **`Alpine FDE - <kver> (<date>)`** pointing directly at the default UKI `\EFI\Linux\alpine-fde-<kver>.efi`; the firmware loads it directly (systemd-boot stays only the removable-media fallback). The serial UKI file (`\EFI\Linux\alpine-fde-<kver>-serial.efi`) still installs to the ESP per kernel but has NO NVRAM entry (ADR-22) — it exists as the automation's headless provisioning/recovery vehicle, booted one-shot via the management controller (see [Step 3](#step-3-first-boot--automated-trust-finalization)). Idempotent: re-installs and rebuilds reuse or recreate the entry (no manual `efibootmgr` run is needed), and pruning a kernel removes its entry with it — at most three entries (one per kernel) stand. **NVRAM commit latency (live-verified):** many firmwares commit `efibootmgr -c` writes BEFORE the new entry appears in the listing — the install re-reads the listing up to **48 times, 10 s apart (~480 s bounded, `ALPINE_FDE_BOOTENTRY_RETRY_MAX`/`_SLEEP` tunable)**, and verified hardware needed >50 s and up to ~2 min per entry — a re-partitioned ESP on the same hardware once needed **>4 min** (2026-10-03), which is why the bound was raised. The retry messages are expected; do not interrupt the step. The ESP's fallback loader (`\EFI\BOOT\BOOTX64.EFI`) boots the UKIs meanwhile even while the named entry is still pending, and a re-run converges idempotently.
7. **TPM restricted to SHA-1 PCRs: some firmware ships `Tpm2Algorithm = SHA1`.** If the BIOS's TPM Advanced Settings limit the TPM to the SHA-1 PCR bank, every SHA-256 PCR read returns an empty selection while the SHA-1 bank looks healthy — the install completes, but the final reseal cannot read PCR 0 and the baseline finalize dies `cannot read PCR 0`. The preflight catches exactly this before disk mutation (see Prerequisite 3). **Remedy: set the TPM2 algorithm selection to SHA256 in the firmware's TPM settings (management-controller or BIOS UI) and apply — the scheduled BIOS job reboots the machine itself.** User-space `tpm2_pcrallocate` may fail with an authorization error while the platform hierarchy is firmware-owned, so the firmware setting (or a firmware-level TPM Clear) is the only working path. Beware the **TPM dictionary-attack lockout** during recovery: repeated failed token-policy unseals across boots max the DA counter (`tpm2_getcap properties-variable` → `inLockout: 1`), which surfaces as bizarre session-creation errors on every auth'ed command; clear it with `tpm2_dictionarylockout -c -p ""` (default empty lockout auth) before diagnosing anything else.
8. **Live install media may lack tools and only carry its own package repo.** The stock ISO's repository list can point at the CD media alone, so package fetches fail until a network repo is added. In live-env prep, add your distribution's network repo to `/etc/apk/repositories` (`setup-apkrepos` can do this; the installer's live-env preflight apk-adds missing live tools from exactly this mirror), and install the NVRAM tooling (`efibootmgr`) for boot-entry work.
9. **Removable-media boot attachments may not survive power cycles.** If the machine suddenly no longer boots from the installer media after a power cycle, re-attach the virtual media in the management controller before retrying the boot.
10. **A forced `reboot -f` from the initrd can wedge the shutdown in a storage-driver path (observed live).** The console freezes mid shutdown while the management controller still reports PowerState On. Recovery is a management-controller power CYCLE (ForceOff → ForceOn, not a plain power-on) — and the `OsIndications` boot-to-firmware-setup request, once written, SURVIVES the power cycle, so the next boot still enters firmware setup where it was requested.
11. **The firmware setup UI renders on VIDEO only.** While the machine sits in firmware setup, the serial console shows nothing (serial/SOL stays silent for the entire setup UI). Do firmware-UI work (key imports, TPM/BIOS settings) from a video console — a physical head or the management controller's virtual console.
12. **PCR 1 (BIOS-settings) drift after firmware/NVRAM work is expected.** BIOS-settings changes — including the firmware/NVRAM enrollment work above — move PCR 1, and the boot/login audit reports the drift afterwards. Verify the cause with `alpine-fde audit` and re-baseline with `alpine-fde audit --accept` (then `alpine-fde reseal` to restore passwordless unlock) — the [Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update) sequence.

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

Disk swap is **omitted by default**. If paging / virtual memory is needed, provide `--swap` (bare — the 4G default — or sized, e.g. `--swap 4G` or `--swap 8G`; sizes take a K/M/G/T suffix and are validated fail-closed):

- **Partitioning:** Allocates an additional **ephemeral swap partition as the LAST partition on the primary disk** (p3 of the first `--disk`; with `--bcache`, p3 of the cache device, since the backing drive is whole-disk by bcache semantics; with RAID1, p3 of the primary disk only).
- **Ephemeral Encryption (Approach A):** Each boot the guest's OpenRC `dmcrypt` service creates a **plain dm-crypt mapping** over the partition with a fresh random key from `/dev/urandom` (aes-xts-plain64, 512-bit key) and `mkswap`s it; the boot `swap` service then activates `/dev/mapper/swap`. **No LUKS header ever persists** — the partition carries only undecryptable ciphertext residue. The swap never enters `/etc/crypttab` (that file is spliced into the initramfs for the root containers; the swap mounts late, in normal boot).
- **Zero Key Residuals:** When the system powers off, the random key vanishes from RAM. Residual swap ciphertext on disk cannot be decrypted by any party.
- **Hibernation Non-Goal:** Hibernation (suspend-to-disk) remains strictly unsupported (ADR-7); ephemeral keys cannot resume memory state across power cycles.
- **Install-time:** nothing swap-related runs during the install (no `mkswap`/`swapon` — the volume is formatted at every boot activation); the installer only creates the partition and writes the boot-time config (`/etc/conf.d/dmcrypt`, fstab, `rc-update add dmcrypt boot`).

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
4. **Firmware NVRAM Enrollment:** Enrolls your custom platform keys into UEFI NVRAM (`db → KEK → PK`), closing Setup Mode. In deferred-enrollment mode (a platform key is already enrolled — see [§1](#1-prerequisites--firmware-preparation)) this step makes **no** NVRAM writes; the certificate import happens via the firmware UI after the install.
5. **Bootloader & UKI Build:** Builds and Authenticode-signs `systemd-boot` (removable-media fallback only) and the initial UKI pair (default + serial console variants).
6. **Initial TPM Sealing (placeholder):** Seals a provisional TPM 2.0 token to the installer's PCR-11 *prediction*. On real firmware this prediction cannot match the actual boot measurement (live-verified), so the first reboot intentionally does NOT unlock via this token — the first boot's container-opening credential is the provisioning escrow on the ESP (see Step 3), which the first boot converts into real-measurement {PCR 7, PCR 11} seals.
7. **UEFI Boot Entry:** Creates the single firmware boot entry **`Alpine FDE - <kver> (<date>)`** → `\EFI\Linux\alpine-fde-<kver>.efi` (first in `BootOrder`); the serial UKI is installed to the ESP as a FILE only — no NVRAM entry (it is the automation one-shot vehicle, [Step 3](#step-3-first-boot--automated-trust-finalization)) — previously the operator ran `efibootmgr` by hand after every fresh install (on firmware with no EFI variable support, the step prints the exact manual commands instead of failing).
8. **Dual Console (two UKI variants):** The build emits TWO full UKIs per kernel — the DEFAULT variant (`console=ttyS0,115200 console=tty0`: kernel and initrd messages print to **both** consoles, and the virtual console is `/dev/console` for initrd userspace, so the unseal prompt renders on the screen) and the SERIAL/RECOVERY variant (`-serial.efi`, `console=tty0 console=ttyS0,115200`: the serial UART is `/dev/console` — the remote/passphrase lane). Only the DEFAULT variant has a firmware boot entry; the SERIAL variant boots only when one-shot via the automation recipe ([Step 3](#step-3-first-boot--automated-trust-finalization)). The installed system still gets a serial login prompt (getty) on `ttyS0` at 115200 baud — headless machines are usable out of the box.

> [!TIP]
> **Fast Fail-Debug Loop:** All disk operations, package downloads, firmware writes, and UKI signing execute before asking for credentials. If any hardware, network, or firmware step fails, the installer aborts immediately so failures are discovered fast during setup without wasting time re-typing passwords.

### Step 2: Account Setup (Final Step Before Reboot)

Once all installation, firmware enrollment, and build steps succeed, the installer asks for exactly one credential:
1. **User account name [admin]:** your local administrative account (wheel `doas`; root SSH stays disabled by policy).

> [!NOTE]
> **No passphrases at install.** The disk's random volume keys are escrowed on the ESP for the first boot (see Step 3) — the recovery passphrase is deliberately NOT set yet: you set it at the first boot, on the machine, where it is confirmed and becomes your admin login too (ADR-21). Headless installs stage `ALPINE_FDE_ADMIN_PUBKEY=<path>` (an OpenSSH PUBLIC key on the installer host) as `authorized_keys` for the admin account + wheel `doas` — the staged key works from the first boot; `@home` is created mode 0755 so sshd's strict-modes walk passes.

**Headless access — `ALPINE_FDE_ADMIN_PUBKEY=<path>`:** point this environment variable at an OpenSSH PUBLIC key on the installer host to stage it as `authorized_keys` for the admin account and grant wheel `doas` (`permit nopass :wheel`). Without it, the created account is password-LOCKED (`adduser -D`) and — with root SSH disabled by policy — a fresh headless install has no working login path at all. Root SSH stays disabled either way; `admin@` + wheel `doas` is the access path. The `@home` subvolume is created mode **0755** (not the root-only 0700 a fresh subvolume defaults to) so operator accounts are loginable and sshd's strict-modes walk can see `~/.ssh/authorized_keys` — a 0700 `@home` silently breaks pubkey auth. **Live-verified caveat (2026-10-03, Dell R640): the staged pubkey alone does NOT enable login on a fresh install** — Alpine builds sshd without PAM and hard-refuses locked accounts (`User admin not allowed because account is locked`) for EVERY auth method, pubkey included. The account unlocks at the first-boot provisioning ceremony (the ×2 passphrase set → `chpasswd`), which is what makes both the password and the staged pubkey work; headless automation must therefore drive the first-boot ceremony (the serial-UKI recipe above) before SSH is available.

The installer then scrubs temporary keys from memory, unmounts the filesystems, and reboots directly into the target disk.

### Step 3: First Boot & Automated Trust Finalization

Upon reboot, the machine boots from the target disk:
1. **Early-Boot Secure Boot Guard in initrd (Refuses to Boot if Secure Boot is Disabled):**
   - In the initrd/initramfs, the early-boot hook verifies the firmware Secure Boot state (`secureboot == 1 && setup_mode == 0`) **before** attempting to unseal or unlock the root disk.
   - **If Secure Boot is OFF / disabled:** The initrd **strictly refuses to boot**. It aborts the boot process immediately with a fatal security error, never evaluates the TPM token, never prompts for any passphrase, and never unseals the root filesystem. It prints an explicit notice on the console instructing the user that Secure Boot must be enabled in UEFI setup, waits for user confirmation (*Press Enter to reboot*), and reboots. How the next boot reaches firmware setup depends on the firmware: if it supports the UEFI `OsIndications` boot-to-setup mechanism, the reboot enters setup automatically; if not (e.g. the target server, where `OsIndicationsSupported` is absent — see [§1](#1-prerequisites--firmware-preparation)), the guard instead prints the manual **F2-during-POST** instructions (import the `.auth` keys from the ESP, enable Secure Boot, save and exit) and reboots plainly, leaving you to catch F2 during POST. The initrd will completely refuse to boot the operating system until Secure Boot is active.
   - **If Secure Boot is ON / enabled:** The initrd evaluates the TPM 2.0 token against PCR 11. On the **first boot the token cannot match, by design** — the provisional seal is anchored to the installer's PCR-11 *prediction* (the ukify model digest), which necessarily diverges from the real stub's measurement (live-verified on the target server). The first boot therefore runs the **PROVISIONING ESCROW flow** (ADR-21): the hook mounts the ESP, consumes the staged volume-key escrow, reads the REAL PCR 7 + 11 on the machine, **self-seals {PCR 7, PCR 11} tokens per container** from those real measurements, and unlocks the containers with the escrowed keys — **no passphrase prompt at unlock**.
2. **Automated Finalization (Runs on First Boot Until Success):**
   - The standalone OpenRC service (`alpine-fde-finalize`) runs automatically before reaching the login prompt:
     - Detects the provisioning state from ground truth on disk (the LUKS2 token's PCR binding and the pending baseline — details in [Architecture §9.1](Architecture.md#91-provision--install-lifecycle-unattended-until-reboot-install--in-chroot-credential-ceremony--first-boot-auto-finalization-adr-20-amended)).
     - Captures the verified Secure Boot state (`PCR 7`) as the trusted baseline (`audit --init`), updating `/etc/alpine-fde/baseline.json`.
     - Upgrades the TPM seal from provisional {PCR 11} to **{PCR 7, PCR 11}** (bound to both firmware configuration and the signed UKI).
     - Purges the temporary setup key from Keyslot 2.
     - **The provisioning ceremony (the operator's only typing):** the console prompts for the **recovery passphrase twice (set + confirm)** — enrolled into keyslot 0 as the emergency fallback — and sets the **admin account password** to the same secret (one passphrase: disk recovery, admin login). The provisioning escrow on the ESP is then **deleted** (the window where the volume keys were escrowed closes here).
     - **Auto-removes itself upon completion:** Unregisters itself from OpenRC (`rc-update del alpine-fde-finalize default`) and deletes the service script (`rm -f /etc/init.d/alpine-fde-finalize`).
   - If an unexpected error or power loss interrupts the process, the provisioning escrow and service remain in place, automatically retrying on the next boot until completion.
   - **No drift warning on the second boot:** the install performs no boot-order reorder (ADR-22 — the serial lane is an ESP artifact, one-shot via the automation recipe below), so PCR 1 does not move between boots, and the baseline is captured on this boot — the audit compares like against like from here on.
2. **Automated Finalization (Runs on First Boot Until Success):**
   - The standalone OpenRC service (`alpine-fde-finalize`) runs automatically before reaching the login prompt:
     - Detects the provisional state from ground truth on disk (the LUKS2 token's PCR binding and the pending baseline — details in [Architecture §9.1](Architecture.md#91-provision--install-lifecycle-unattended-until-reboot-install--in-chroot-credential-ceremony--first-boot-auto-finalization-adr-20-amended)).
     - Captures the verified Secure Boot state (`PCR 7`) as the trusted baseline (`audit --init`), updating `/etc/alpine-fde/baseline.json`.
     - Upgrades the TPM seal from provisional {PCR 11} to **{PCR 7, PCR 11}** (bound to both firmware configuration and the signed UKI).
     - Purges the temporary setup key from Keyslot 2.
     - (ADR-21, design — implementation pending) Authorizes the completion chain with the confirmed first-boot passphrase, staged in tmpfs (0600, root-only, scrubbed immediately after consumption): unlocks the encrypted `release.pem` (passphrase-as-default) and sets the admin account password from the same secret. Until this lands, the service cannot complete unattended on a real machine and the operator runs the post-install heal (`alpine-fde finalize` + `kernel build` + `reseal` with hand-passed credentials).
     - **Auto-removes itself upon completion:** Unregisters itself from OpenRC (`rc-update del alpine-fde-finalize default`) and deletes the service script (`rm -f /etc/init.d/alpine-fde-finalize`).
   - If an unexpected error or power loss interrupts the process, the provisional token and service remain in place, automatically retrying on the next boot until completion.

3. **Headless provisioning & recovery — the AUTOMATION RECIPE (serial UKI one-shot, ADR-22):** the firmware NVRAM carries only the DEFAULT UKI entry per kernel; the SERIAL UKI file (`\EFI\Linux\alpine-fde-<kver>-serial.efi`) still installs to the ESP per kernel and is the headless provisioning/recovery vehicle for AI-agent automation (end users never need the serial lane — the default UKI's first-boot read rides the video console). The recipe: via the **management controller** (vendor-agnostic — its one-shot `UefiTarget` boot source), boot the serial UKI's ESP path DIRECTLY for the next boot only; no firmware boot entry is created or modified. The serial console then carries the provisioning prompts, because the serial UKI binds `/dev/console` to the serial UART: on the FIRST boot that is the recovery passphrase asked **TWICE (enter + confirm)** — the ADR-21 provisioning ceremony — and later recovery/drift reads surface on the same console. The boot item is TEMPORARY: a one-shot boot source overrides the next boot only and is self-cleaning, so there is nothing to clean up; after provisioning the default UKI boots **passwordless** as usual.

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

Everything runs through a single tool with **7 verbs**: `./bin/alpine-fde <command>` (examples earlier in this guide show the full path; on an installed system the commands are on `PATH` as `alpine-fde <command>`). Lifecycle steps such as TPM enrollment and first-boot finalization run **automatically** — you never invoke them (see [§3](#3-installation--first-boot-experience)).

| Command | What it does | When you use it |
|---|---|---|
| `install` | The guided installation ceremony: partitions and encrypts disk(s) (supports single-disk, `--bcache` hybrid, multi-disk RAID1, and optional ephemeral encrypted swap via `--swap [size]`), installs Alpine base, enrolls Secure Boot keys, and seals the disk key to the TPM (see [§2](#2-installation-ceremonies) and [§3](#3-installation--first-boot-experience)). | Setting up a new machine — run once, from live media. |
| `audit` | Verifies the running machine against its trusted baseline (firmware state and boot measurements). `--init` records the first baseline; `--accept` accepts a verified new one after a legitimate change. | After firmware/BIOS updates that prompt for the recovery passphrase ([Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update)). |
| `reseal` | Seals or re-enrolls the LUKS2 container(s) to the TPM 2.0 policy — **no `--uuid` seals EVERY crypttab container in one command** (multi-container machines); `--uuid <LUKS-UUID|block-dev>` targets a single container. Runs automatically during installation and UKI builds. | During disaster recovery ([Runbook 2](#runbook-2-failed-drive-replacement-in-btrfs-raid1), [Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update)) after drive replacement or PCR 7 drift re-baselining, or after a TPM clear. |
| `passwd` | Changes the recovery passphrase — no re-encryption, no TPM re-enrollment. | When the passphrase was shared or may be compromised ([Runbook 4](#runbook-4-recovery-passphrase-rotation)). |
| `status` | Shows the current trust state at a glance: Secure Boot state, TPM seal, keyslots, and boot images. | Any time you want to confirm the machine is sealed, signed, and finalized. |
| `doctor` | Checks the environment before an install (missing packages, TPM presence, Secure Boot state), and the trust chain afterwards. | Before installing on a new machine, and as the first sanity check when something looks wrong. |
| `kernel` | Manages the signed boot images per kernel: `kernel build` / `kernel remove` / `kernel prune`, plus `kernel next` to boot a retained kernel once, on the next reboot only. Build/remove run automatically on kernel upgrades; you run them manually when rebuilding boot images during recovery ([Runbook 1](#runbook-1-broken-cache-ssd--esp-rebuild-hybrid-bcache-setup), [Runbook 2](#runbook-2-failed-drive-replacement-in-btrfs-raid1)) or for custom kernels. `kernel next` — see [Booting Alternative or Retained Kernels](#booting-alternative-or-retained-kernels). | Only in recovery, rollback-testing, or custom-kernel scenarios. |

**Internal (machine tier):** `provision`, `pcrsign`, and `finalize` remain callable for human recovery but are NOT part of the daily operator surface (the internal automation boundary is defined in [Architecture §8.1](Architecture.md#81-alpine-fde-cli--the-user-facing-tool)). There is no `pre-upgrade` verb — pre-upgrade snapshots are AUTOMATIC (the apk trigger; see [Btrfs Snapshots & Userspace Rollback](#btrfs-snapshots--userspace-rollback)).

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
Automatic pre-upgrade snapshots ship enabled: at **every `apk` transaction** (upgrades AND additions — a package install can touch the boot chain), a read-only snapshot of the root (`@`) is taken into `/.snapshots/alpine-fde-auto-<UTC-timestamp>` by the apk trigger installed at `/etc/apk/triggers/alpine-fde-snapshot.trigger`. The keep-N retention deletes the oldest automatic snapshots beyond **5** (change it in `/etc/conf.d/alpine-fde-snapshot`, or export `ALPINE_FDE_SNAPSHOT_KEEP`); manual snapshots are never pruned.

> [!NOTE]
> **Snapshot timing:** apk triggers run *after* a transaction commits, so each snapshot captures the just-completed state — which is exactly the rollback point for the **next** transaction. To undo the most recent `apk` transaction, restore the **second-newest** `alpine-fde-auto-*` snapshot (the newest is the broken state itself).

Before experiments or other risky changes, you can still take one yourself (it is one command; manual snapshots land under `/.snapshots/<name>` on the `@snapshots` subvolume and are never pruned automatically):

```sh
btrfs subvolume snapshot -r / /.snapshots/pre-upgrade-$(date +%Y%m%d-%H%M%S)
```

If an upgrade breaks userspace, restore the snapshot:
```sh
# Mount top-level Btrfs volume
mount -o subvolid=5 /dev/mapper/root-crypt /mnt

# Move broken root subvolume and restore snapshot to @
mv /mnt/@ /mnt/@broken
btrfs subvolume snapshot /mnt/@snapshots/<alpine-fde-auto-...-or-timestamp> /mnt/@

# Unmount and reboot
umount /mnt
reboot
```
*(Restoring a snapshot changes only filesystem contents — it requires no re-signing and no re-enrollment, so rollback boots stay passwordless). Automatic snapshots apply to btrfs roots only (the §4 default layout); an ext4 root (`--fs ext4`) simply skips them.*

### Booting Alternative or Retained Kernels
Up to 3 kernels are retained on the ESP. To boot a previous kernel one time:

```sh
# View the retained boot images (the digest-manifest section lists them; the
# entry id is the UKI file name without the .efi suffix)
alpine-fde status

# Select kernel for next boot only
alpine-fde kernel next alpine-fde-6.6.9-0-lts
```

The setting is one-shot: it is consumed by the **next** boot only, after which the boot menu default applies again. The system reboots into the previous kernel **without requiring a password**, because each retained boot image carries its own signature that the TPM accepts.

### Automated Boot & Login Auditing (Firmware Drift Detection)

In addition to manual `alpine-fde audit` execution, platform firmware integrity is monitored automatically at two key points without any background daemons:

1. **On Every Boot (`alpine-fde-audit` oneshot service):**
   Runs **last, immediately before the login prompt**. This guarantees that its warning notice is not scrolled off-screen by startup logs from other services (networking, sshd, chrony, etc.). It compares current PCR 0..3, PCR 7, and the TCG event log against `/etc/alpine-fde/baseline.json` using the same comparison logic as `alpine-fde audit`. If any measurement drifts, it logs an explicit warning to syslog and writes a security notice to `/etc/issue` and `/etc/motd` (the machine's own banner text is preserved — the alert is a self-delimiting block prepended above it), and stages the detailed login banner at `/run/alpine-fde/audit-drift`. When a later boot audit **matches** the baseline, the standing alert (marker + banners) is retired automatically. A missing baseline (pre-provisioning) skips quietly with a syslog line; a failed check (TPM unreachable) is logged and skipped without ever clearing an existing alert or blocking the boot — drift is a result, not a boot failure. The service then terminates immediately (0 MB resident memory, 0 CPU overhead). The first-boot finalizer (`alpine-fde-finalize`) never touches this service — each oneshot manages only itself.

2. **On Every Login (`/etc/profile.d/alpine-fde.sh`):**
   When an operator logs into an **interactive** shell (non-interactive sessions such as `scp` or CI runners stay silent), the profile hook checks for the staged drift marker (`/run/alpine-fde/audit-drift`). If present, it displays the high-visibility security alert banner right at the terminal, instructing the user on how to verify and accept or investigate.

3. **Acknowledging an alert:** after verifying the drift is benign (firmware/BIOS update?), run `alpine-fde audit --accept` to re-baseline (then `alpine-fde reseal` to restore passwordless unlock) — or, on a machine that matches again, a plain `alpine-fde audit` retires the alert. Both clear the login marker and strip the `/etc/issue` + `/etc/motd` notice.

---

## 5. Disaster Recovery & Hardware Maintenance

---

### The Console Experience When Something Is Wrong

Alpine FDE provides high-visibility console warnings across all critical failure domains: early-boot TPM unseal failures, pre-unseal Secure Boot guard halts, boot-time firmware drift detection, interactive login drift alerts, and first-boot finalization warnings.

#### 1. Early-Boot TPM Unseal Failure (Initramfs Console)

When hardware, firmware, or boot components change, the TPM refuses to release the volume encryption key. The early-boot initramfs hook never prompts blind: before the recovery-passphrase prompt it prints a **reason preamble** — one canonical sentence mapped from the refusal class the hook actually detected — followed by a remediation closing line, and the prompt itself carries a bounded `(attempt N of 3)` counter (§8.2 step 5):

```text
alpine-fde-unseal: the TPM refused the sealed blob under the current PCR state (drift / foreign TPM / DA lock) — recovery passphrase path (§8.2)
alpine-fde-unseal: the expected firmware/Secure Boot configuration changed — if this was you (firmware update, SB toggle), this is expected
alpine-fde-unseal: after boot, run: audit, then reseal to restore passwordless unlock
alpine-fde-unseal: (attempt 1 of 3) enter the recovery passphrase for root (keyslot 0):
```

**The three refusal classes and the preamble each prints** (these are the SAME sentences the hook prints — the wording is pinned identical between this guide, [Architecture.md §8.2 step 5](Architecture.md#82-unlock-path--initramfs-hook), and the shipped hook):

| Refusal class | When the hook detects it | Preamble printed before the prompt |
|---|---|---|
| `seal_refused` (PCR 7 drift) | The TPM refused the sealed blob under the current PCR state — a firmware/BIOS update, Secure Boot key change, or other firmware configuration change moved PCR 7 | the expected firmware/Secure Boot configuration changed — if this was you (firmware update, SB toggle), this is expected |
| `sig_refused` (signature/PCR 11 mismatch) | The boot entry's release-key `.pcrsig` signature is missing or fails verification at the I3 gate, before any TPM session is opened | the booted kernel image failed signature/PCR policy — likely a foreign or unsigned UKI |
| `token_missing` (TPM cleared / seal gone) | No `systemd-tpm2` token exists on any container, or the TPM is absent from / refused by the machine | the TPM seal is absent — the TPM may have been cleared |

Every class also prints the same closing line before the prompt: `after boot, run: audit, then reseal to restore passwordless unlock`. See [Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update) for the post-firmware-update recovery sequence.

**Honest caveat:** the preamble is an anti-footgun for the legitimate operator, not anti-tamper. It is the hook's own classification of a refusal it genuinely detected — it tells *you* that a passwordless-unlock failure has an expected, fixable cause — but it is not a trusted statement about an attacker: an attacker who controls the boot chain controls the console too, and can print anything.

**Key Security Guarantees During Unseal Failure:**
1. **Diagnostic Failure Reason (warn-before-prompt):** The hook identifies the refusal class it actually detected — PCR 7 drift (firmware/Secure Boot configuration), signature/PCR 11 mismatch (foreign or unsigned boot image), or an absent token/TPM — and prints that class's preamble before asking for the passphrase (§8.2 step 5).
2. **Evil-Maid Security Advisory:** An unexpected recovery prompt may indicate an evil-maid attack or physical tampering. The preamble is guidance, not proof of legitimacy — if you did NOT recently update firmware or change Secure Boot configuration, do NOT enter your passphrase; power off and inspect the machine.
3. **Fail-Closed 3-Strike Rule:** The operator is granted a maximum of 3 attempts to enter the Keyslot 0 recovery passphrase (counted across all RAID1 members — each prompt shows `(attempt N of 3)`). If the 3rd attempt fails, the system executes **`poweroff -f` immediately**. Dropping into an interactive rescue shell is strictly blocked, preventing dictionary attacks and memory inspection.

#### 2. Initrd Refuses to Boot When Secure Boot Is Disabled (Initramfs Console)

If the machine boots while Secure Boot is disabled in firmware setup during the provisional window, the early-boot hook in the initrd **strictly refuses to boot**. It halts immediately before attempting any unsealing or prompting for passphrases:

```text
alpine-fde-unseal: Secure Boot guard: secureboot=0 setup_mode=0 — Secure Boot is OFF — refusing to unlock (pre-unseal guard, ADR-20)
alpine-fde-unseal: the container will NOT be unlocked: no token path, no recovery passphrase — enable Secure Boot with this machine's platform keys in the firmware setup (UEFI)
alpine-fde-unseal: OsIndications: boot-to-firmware-setup requested
alpine-fde-unseal: Press Enter to reboot into the firmware setup (the container was NOT unlocked; no passphrase was requested)
alpine-fde-unseal: rebooting into the firmware setup (Secure Boot must be enabled)
```

On firmware **without** the `OsIndications` boot-to-setup mechanism (e.g. the target server — the `OsIndicationsSupported` variable is absent, so no OS request can reboot straight into setup), the tail of the exchange differs: the guard prints the manual import/enable steps and reboots plainly instead of expecting the firmware to auto-enter setup:

```text
alpine-fde-unseal: Secure Boot guard: secureboot=0 setup_mode=0 — Secure Boot is OFF — refusing to unlock (pre-unseal guard, ADR-20)
alpine-fde-unseal: the container will NOT be unlocked: no token path, no recovery passphrase — enable Secure Boot with this machine's platform keys in the firmware setup (UEFI)
alpine-fde-unseal: OsIndications not supported by this firmware — at the next boot, press F2 during POST to enter the firmware setup and:
alpine-fde-unseal:   1. import the keys from the ESP partition (alpine-fde-keys: db.auth, kek.auth, pk.auth — in that order, or the .cer certificates) or verify they are present
alpine-fde-unseal:   2. enable Secure Boot
alpine-fde-unseal:   3. save and exit
alpine-fde-unseal: Press Enter to reboot (press F2 during POST to enter the firmware setup)
alpine-fde-unseal: rebooting — press F2 during POST to enter the firmware setup
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

It also updates the pre-login console banner (`/etc/issue`) and `/etc/motd` (the `BEGIN`/`END` rule lines delimit the alert so a later matching audit can strip exactly this block and leave the machine's own banner text untouched):

```text
#--- alpine-fde-audit: drift alert BEGIN ---#
*******************************************************************************
* WARNING: Alpine FDE detected firmware/platform drift on this machine!       *
* Measurements differ from /etc/alpine-fde/baseline.json                      *
* Run 'alpine-fde audit' to inspect, or 'alpine-fde audit --accept' if valid. *
*******************************************************************************
#--- alpine-fde-audit: drift alert END ---#
```

#### 4. Interactive Login Security Alert (`/etc/profile.d/alpine-fde.sh`)

When an operator logs into an interactive shell and the boot-time audit has staged the drift marker (`/run/alpine-fde/audit-drift`), the alert banner is displayed immediately at the top of the terminal session — one line per drifted check, exactly as the comparison reported it:

```text
================================================================================
[SECURITY ALERT] Alpine FDE Firmware Drift Detected!
================================================================================
Platform measurements have drifted from the trusted baseline:
  - pcr7 DRIFT
  - eventlog DRIFT

If you recently updated firmware or BIOS settings, verify and accept via:
  alpine-fde audit --accept && alpine-fde reseal
Otherwise, investigate potential unauthorized firmware modification!
================================================================================
```

The banner disappears once the drift is resolved and acknowledged: the next matching boot audit, a plain `alpine-fde audit`, or `alpine-fde audit --accept` all retire it.

#### 5. First-Boot Finalization Failure (`alpine-fde-finalize`)

Because the initrd pre-unseal guard already blocks boot if Secure Boot is disabled, by the time the OS reaches userspace, Secure Boot is already active (`secureboot=1, setup_mode=0`). Any failure during first-boot finalization would stem from a hardware TPM communication error or storage/keyslot update fault. The service never fails the boot: it reports loudly, stays provisional, and retries on the next boot:

```text
 * Starting alpine-fde-finalize ...
WARNING: Alpine FDE trust is NOT finalized (install state: provisional-booted).
First-boot finalization FAILED (see the messages above; details in the finalize-attempt marker).
The volume stays safely locked under the provisional seal; the service will retry on the next boot,
or complete it manually with: alpine-fde finalize
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

# 2. Install the systemd-boot boot manager onto the new ESP: a guarded file
#    copy of the loader binary the systemd-boot package ships (Alpine ships
#    no bootctl binary — never invoke bootctl)
ldr=''
for p in /usr/share/systemd/bootctl/systemd-bootx64.efi /usr/lib/systemd/boot/efi/systemd-bootx64.efi; do
  [ -f "$p" ] && { ldr="$p"; break; }
done
[ -n "$ldr" ] || { echo "ERROR: no systemd-boot loader EFI binary found (apk add systemd-boot)" >&2; exit 1; }
mkdir -p /efi/EFI/systemd /efi/EFI/BOOT

# 3. Sign the loader with your custom release key and install it to BOTH ESP
#    homes (prompts for release.pem passphrase). The firmware verifies the
#    FIRST loaded image, so the fallback path must be signed too.
sbsign --key /etc/alpine-fde/keys/release.pem --cert /etc/alpine-fde/keys/release.crt "$ldr" --output /efi/EFI/BOOT/BOOTX64.EFI
cp /efi/EFI/BOOT/BOOTX64.EFI /efi/EFI/systemd/systemd-bootx64.efi

# 4. Rebuild signed UKIs on the new ESP for the target kernel
TARGET_KVER=$(ls -1 /lib/modules | sort -V | tail -n1)
alpine-fde kernel build "$TARGET_KVER"

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
alpine-fde --root /mnt reseal --uuid "$LUKS_UUID"
```

#### Step 5: Update crypttab and Rebuild UKI
Update `/mnt/etc/crypttab` with the new container UUID and rebuild the UKI:
```sh
TARGET_KVER=$(ls -1 /mnt/lib/modules | sort -V | tail -n1)
alpine-fde --root /mnt kernel build "$TARGET_KVER"
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
   alpine-fde --root /mnt reseal --uuid "$LUKS_UUID"
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
   alpine-fde reseal
   ```
5. Subsequent boots resume passwordless automatic unlock.

---

### Runbook 4: Recovery Passphrase Rotation

**Scenario:** The recovery passphrase was shared or is suspected of being compromised.

Run the passphrase rotation command:
```sh
alpine-fde passwd
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
   The keys reside inside the unlocked root volume at `/mnt/etc/alpine-fde/keys/`. Run `kernel build`:
   ```sh
   TARGET_KVER=$(ls -1 /mnt/lib/modules | sort -V | tail -n1)
   alpine-fde --root /mnt kernel build "$TARGET_KVER"
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
