# Debian FDE — Operator & User Guide

> [!NOTE]
> **Wave 2 Architecture Preview:** This guide covers the operational workflows, multi-disk topologies, and disaster recovery procedures designed for Wave 2. If running against the current `main` codebase, refer to the shipped single-disk ext4 workflow in [README.md](../README.md).

---

## 1. Prerequisites & Firmware Preparation

Before beginning installation, your target machine must be configured in UEFI setup:

1. **Set Firmware Administrator Password:** Protects UEFI settings against physical tampering.
2. **Clear Secure Boot Keys (Enter Setup Mode):**
   - In firmware setup, choose **Clear Secure Boot Keys** or **Delete All Keys** (sets `SetupMode: 1`).
   - Ensure **Secure Boot is OFF** during initial installation.
   > [!IMPORTANT]
   > Authenticated NVRAM variable writes (`PK`, `KEK`, `db`) require `SetupMode == 1`. If the vendor PK is not cleared, installation preflight will abort (`exit 64`) to prevent write errors or bricked firmware states.
3. **Boot Live Installation Media:** Boot an official Debian Live or Alpine Linux live USB on the target machine.

---

## 2. Installation Ceremonies

Debian FDE supports three primary storage layouts. Choose the one that matches your hardware:

### Topology A: Default Single-Disk (NVMe or SATA SSD)
Partitions the disk into an unencrypted ESP (`p1`) and an Argon2id LUKS2 container (`p2`) formatted with Btrfs (`@`, `@home`, `@snapshots`):

```sh
./bin/debian-fde install --disk /dev/nvme0n1
```

### Topology B: Accelerated Hybrid Storage (`--bcache`)
Accelerates a high-capacity HDD or slow SSD (`--disk`) using a fast NVMe caching drive (`--bcache`):
- ESP (`p1`) and bcache caching set (`p2`) reside on the fast NVMe drive.
- Backing device (`p1`) resides on the HDD.
- LUKS2 container is created directly on `/dev/bcache0` in strictly enforced **`writethrough`** mode.

```sh
./bin/debian-fde install --disk /dev/sda --bcache /dev/nvme0n1
```

### Topology C: Multi-Disk Btrfs RAID1 (Dual or Multi-Drive)
Mirrors both data and metadata across two or more physical drives (`-d raid1 -m raid1`). Each disk is wrapped in its own independent LUKS2 container sealed to the machine's TPM 2.0 with synchronized policies:

```sh
./bin/debian-fde install --disk /dev/nvme0n1 --disk /dev/nvme1n1
```

---

## 3. The Single-Reboot Ceremony & First-Boot Setup

The installation process minimizes operator friction by requiring **only a single reboot into BIOS**. Throughout the entire window between installation and first-boot finalization, the volume is protected exclusively by your recovery passphrase in LUKS2 keyslot 0 — no TPM token exists until Secure Boot has been verified (§9.1).

1. **Installer Phase (Live Host) — Stage 1:**
   - The operator enters the permanent recovery passphrase, which is enrolled into LUKS2 keyslot 0 with Argon2id and entropy verification. **Keyslot 0 is the only keyslot during installation** — no provisional TPM token is ever created (§9.1).
   - The installer partitions disks (per topology §2), formats the filesystem, and installs base Debian via `debootstrap`.
   - In-chroot provisioning executes in strictly ordered sequence (§9.1):
     1. Installs the §3.3 explicit-additions package set (`linux-image-amd64`, `dracut`, `systemd-cryptsetup`, `cryptsetup`, `systemd-boot`, `systemd-boot-tools`, `systemd-ukify`, `sbsigntool`, `openssl`, `tpm2-tools`, `jq`, `sudo`, `zram-tools`, filesystem/microcode tools), configures admin user and network services.
     2. Writes initial baseline with `pcr7: "pending"`.
     3. Provisions platform keys: generates `PK`, `KEK`, `db`, and `release.pem` on the encrypted root volume (ADR-18).
     4. Enrolls authenticated UEFI NVRAM variables in strict order (`db → KEK → PK` last).
     5. Builds signed bootloader (`systemd-bootx64.efi`) and initial signed UKI with `.pcrsig` via `ukictl build` (TPM enrollment is **skipped**: the baseline and install state are not finalized yet, §8.1).
     6. Encrypts `release.pem` with AES-256 (PBKDF2 HMAC-SHA256, ≥ 600,000 iterations, entropy floor enforced) to eliminate plaintext keys at rest across reboot (ADR-18).
     7. Installs kernel post-installation hooks (`/etc/kernel/postinst.d/zz-debian-fde`).
     8. Writes state `installed` to `/etc/debian-fde/install-state.json`.
   - The installer sets `OsIndications` bit 0 and reboots directly into BIOS.

2. **Firmware Phase (One-Time BIOS Toggle) — Stage 2:**
   - The machine reboots into UEFI firmware setup.
   - Toggle **Secure Boot: ON** with the custom enrolled keys (firmware is now in User Mode 0), then save and exit.

3. **First Boot Phase (Trust Finalization) — Stage 3:**
   - The system boots under custom Secure Boot. The initramfs prompts **once** for the keyslot 0 recovery passphrase — the single documented manual passphrase unlock of the whole ceremony (§9.1).
   - The first-boot finalize service evaluates Secure Boot state (`fw_sb_state`):
     - **If Secure Boot is OFF:**
       The guard halts fail-closed (`exit 64`) with BIOS instructions: reboot into firmware setup and toggle Secure Boot ON. **No TPM enrollment is performed and nothing is wiped** — the volume remains safely locked by the keyslot 0 recovery passphrase (§9.1). After enabling Secure Boot, boot again and finalization resumes.
     - **If Secure Boot is ON:**
       Trust finalization executes (crash-idempotent: if interrupted, it resumes on the next boot after the recovery passphrase entry):
       1. **Capture the Finalized Baseline:** `audit --init` records the verified custom Secure Boot PCR 7 state (§8.4).
       2. **Seal the TPM Token:** Performs the single Mechanism A″ enrollment into keyslot 1, bound to {PCR 7, PCR 11} (`enroll-tpm`, executed for each member container in RAID1 topologies).
       3. **Off-Machine Backup:** Writes state `finalized` to `/etc/debian-fde/install-state.json` and prompts operator to back up keys off-machine:
          ```sh
          scp -r /etc/debian-fde/keys/ admin@backup-host:/secure/storage/debian-fde-backup/
          ```

4. **Normal Operation — Stage 4:**
   - Every subsequent boot is **100% passwordless**: the initramfs unseals the volume via the TPM token in keyslot 1, bound to the Secure Boot state (PCR 7) and the measured UKI (PCR 11).

Keyslot lifecycle summary (§9.1):

| Install state | Keyslot 0 | Keyslot 1 | TPM token |
|---|---|---|---|
| `installed` (post-install, pre-first-boot) | Recovery passphrase | (Empty) | (None) |
| `finalized` (post-first-boot) | Recovery passphrase | Sealed TPM passphrase | `systemd-tpm2` (PCR 7 + PCR 11) |

---

## 4. Daily Operations

### Kernel Upgrades & Signing Key Passphrase Prompt
Debian package upgrades (`apt upgrade`) trigger kernel post-installation hooks automatically:
1. dracut rebuilds the hostonly initramfs.
2. `ukify` predicts the digest at build time; measurement happens in systemd-stub at boot.
3. The kernel hook signs the UKI binary and embeds the `.pcrsig` signature using `/etc/debian-fde/keys/release.pem`.
   > [!NOTE]
   > Because `release.pem` is encrypted with AES-256 for local at-rest protection (ADR-18), `apt upgrade` prompts interactively for your **release signing key passphrase** during the hook execution. Unattended/non-interactive upgrades will fail loudly if the passphrase is not provided.
4. Next boot: boots into the new kernel **100% passwordless**. No TPM re-enrollment is required.

### Btrfs Snapshots & Userspace Rollback
Before major system changes or upgrades, take an atomic snapshot:

```sh
debian-fde pre-upgrade
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
*(Restoring filesystem contents under `@` does not perturb PCR 11 measurements, requiring no kernel re-signing).*

### Booting Alternative or Retained Kernels
Up to 3 kernels are retained on the ESP. To boot a previous kernel one time:

```sh
# View available entries
bootctl list

# Select kernel for next boot only
debian-fde bootnext debian-fde-6.12.0-1-amd64.efi
```

The system reboots into the previous kernel **without requiring a password**, because each retained UKI carries its own signed `.pcrsig` validated against the TPM token.

---

## 5. Disaster Recovery & Hardware Maintenance

---

### Runbook 1: Broken Cache SSD & ESP Rebuild (Hybrid bcache Setup)

**Scenario:** In an accelerated `--bcache` setup (`--disk /dev/sda --bcache /dev/nvme0n1`), the NVMe SSD physically fails, taking down both the ESP (`p1`) and the cache partition (`p2`).

Because the system was installed in **`writethrough`** mode, **100% of your data remains intact on the backing disk (`/dev/sda1`)**.

#### Step 1: Boot Recovery Live Media
Boot from a Debian Live USB or Alpine Linux recovery drive.

#### Step 2: Assemble Backing Device in Standalone Mode
Without the caching drive present, load the bcache module and register the backing disk directly:
```sh
modprobe bcache
echo /dev/sda1 > /sys/fs/bcache/register
# The virtual block device appears at /dev/bcache0
```

#### Step 3: Unlock and Mount Root Filesystem
Unlock LUKS2 using your **recovery passphrase**:
```sh
cryptsetup open /dev/bcache0 root-crypt

# Mount Btrfs root subvolume
mount -o subvol=@ /dev/mapper/root-crypt /mnt
mount -o subvol=@home /dev/mapper/root-crypt /mnt/home
```

#### Step 4: Prepare the Replacement SSD
Install a replacement NVMe SSD and identify its device node (e.g. `NEW_SSD="/dev/nvme0n1"`):
```sh
export NEW_SSD="/dev/nvme0n1"

# 1. Partition the new SSD (p1: ESP sized ≥ 512MB-1GB per formula, p2: remainder for cache)
printf 'label: gpt
start=2048, size=2097152, type=uefi, name="esp"
type=linux, name="cache"
' | sfdisk "$NEW_SSD"

# 2. Format the new ESP
mkfs.vfat -F 32 -n EFI "${NEW_SSD}p1"
mkdir -p /mnt/efi
mount "${NEW_SSD}p1" /mnt/efi

# 3. Create the new bcache caching set
make-bcache -C "${NEW_SSD}p2"

# 4. Attach new cache to the running backing device in writethrough mode
echo "${NEW_SSD}p2" > /sys/fs/bcache/register
CSET_UUID=$(bcache-super-show "${NEW_SSD}p2" | grep cset.uuid | awk '{print $2}')
echo "$CSET_UUID" > /sys/block/bcache0/bcache/attach
echo writethrough > /sys/block/bcache0/bcache/cache_mode
```

#### Step 5: Rebuild the ESP inside Chroot
Enter chroot to reinstall and re-sign boot binaries:
```sh
# Bind-mount virtual filesystems
mount --bind /dev /mnt/dev
mount --bind /proc /mnt/proc
mount --bind /sys /mnt/sys
mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars

chroot /mnt /bin/bash
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
sbsign --key /etc/debian-fde/keys/release.pem --cert /etc/debian-fde/keys/release.crt --output /efi/EFI/systemd/systemd-bootx64.efi.signed /efi/EFI/systemd/systemd-bootx64.efi
mv /efi/EFI/systemd/systemd-bootx64.efi.signed /efi/EFI/systemd/systemd-bootx64.efi

sbsign --key /etc/debian-fde/keys/release.pem --cert /etc/debian-fde/keys/release.crt --output /efi/EFI/BOOT/BOOTX64.EFI.signed /efi/EFI/BOOT/BOOTX64.EFI
mv /efi/EFI/BOOT/BOOTX64.EFI.signed /efi/EFI/BOOT/BOOTX64.EFI

# 4. Rebuild signed UKIs on the new ESP for the target kernel
TARGET_KVER=$(ls -1 /lib/modules | sort -V | tail -n1)
debian-fde ukictl build "$TARGET_KVER"

# Exit chroot and unmount
exit
umount -R /mnt
```

#### Step 6: Reboot
Reboot the machine. Because Secure Boot keys in UEFI NVRAM were unchanged and the new UKI was signed by the same `release.pem`, **the machine boots and automatically unseals via TPM with zero passwords required**.

---

### Runbook 2: Failed Drive Replacement in Btrfs RAID1

**Scenario:** In a multi-disk RAID1 installation (`--disk /dev/nvme0n1 --disk /dev/nvme1n1`), one drive fails.

> [!NOTE]
> If the failed drive was the **primary drive holding the ESP**, you must also partition the replacement disk with an ESP (`p1`), format it with FAT32, and rebuild/re-sign the bootloader and UKIs following Runbook 1 (Steps 4 & 5).

#### Step 1: Degraded Boot or Live Media Rescue
Because a missing member stalls `sysroot.mount` fail-closed by design, boot using one of two methods:
1. **Live Rescue Media:** Boot a live USB, open the surviving member (`cryptsetup open /dev/nvme0n1p2 root1`), and mount degraded (`mount -o degraded,subvol=@ /dev/mapper/root1 /mnt`).
2. **Signed Rescue UKI:** If provisioned, select the `debian-fde-rescue` boot entry (which embeds `rootflags=subvol=@,degraded ro` and filters devices via `rd.luks.uuid`; requires `rd.luks.options=tpm2-device=auto` for passwordless unseal, otherwise prompts for the recovery passphrase).

#### Step 2: Replace Hardware and Re-format Container
1. Replace the failed hardware drive with a new drive (`/dev/nvme1n1`).
2. Partition and format the replacement container with LUKS2 using pinned Argon2id cost parameters:
   ```sh
   # Important: When prompted, enter the SAME recovery passphrase as keyslot 0
   # on the existing RAID members. This allows password-cache=yes
   # to unlock all array members with a single passphrase entry during fallback.
   cryptsetup luksFormat --type luks2 --pbkdf argon2id \
     --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
     /dev/nvme1n1p1
   cryptsetup open /dev/nvme1n1p1 root-repl
   ```

#### Step 3: Replace the Device in Btrfs
```sh
# Find missing device id
btrfs filesystem show /mnt
# Replace missing drive (e.g. device id 2)
btrfs replace start 2 /dev/mapper/root-repl /mnt
```

#### Step 4: Seal Replacement Container to TPM 2.0
```sh
# Obtain the UUID of the replacement container
LUKS_UUID=$(cryptsetup luksUUID /dev/nvme1n1p1)

# Seal container to TPM using debian-fde CLI (referencing target root)
debian-fde --root /mnt enroll-tpm --uuid "$LUKS_UUID"
```
*(Behind the scenes, `debian-fde enroll-tpm` executes `systemd-cryptenroll` with `--tpm2-pcrs=7` and `--tpm2-public-key-pcrs=11` anchored to `/mnt/etc/debian-fde/keys/release.pub`).*

#### Step 5: Update crypttab
Update `/mnt/etc/crypttab` with the new partition UUID (`password-cache=yes`).

#### Step 6: Rebuild UKI and Initrd
Because crypttab is embedded inside the initrd/UKI, regenerate the UKI and PCR 11 signatures before rebooting so the initramfs unlocks the new container:
```sh
# Identify running or target kernel version
TARGET_KVER=$(ls -1 /mnt/lib/modules | sort -V | tail -n1)

# Rebuild UKI and initrd with updated crypttab (prompts for release.pem passphrase)
debian-fde --root /mnt ukictl build "$TARGET_KVER"
```

---

### Runbook 3: PCR 7 Drift After Firmware/BIOS Update

**Scenario:** Following a motherboard BIOS update, UEFI variables change, causing PCR 7 to drift. Booting prompts for the **recovery passphrase**.

1. Enter your **recovery passphrase** at the boot prompt to complete boot into Debian.
2. Verify the cause of the drift:
   ```sh
   debian-fde audit
   ```
3. If the changes are legitimate (expected firmware update), accept the new baseline:
   ```sh
   debian-fde audit --accept
   ```
4. Re-enroll keyslot 1 to the new PCR 7 value:
   ```sh
   debian-fde enroll-tpm
   ```
5. Subsequent boots resume passwordless automatic unlock.

---

### Runbook 4: Recovery Passphrase Rotation

**Scenario:** The recovery passphrase was shared or is suspected of being compromised.

Run the passphrase rotation command:
```sh
debian-fde rotate
```
* Prompts for the existing passphrase, verifies the entropy floor on the new passphrase, and updates LUKS2 keyslot 0.
* Volume encryption keys and TPM 2.0 seals remain untouched (no re-encryption or TPM re-enrollment required).
