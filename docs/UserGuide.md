# Alpine FDE — Operator & User Guide

> [!NOTE]
> **Wave 2 Architecture Preview:** This guide covers the operational workflows, multi-disk topologies, and disaster recovery procedures designed for Alpine FDE. If running against legacy commands, note that `./bin/debian-fde` remains supported as a backwards-compatible alias for `./bin/alpine-fde`.

---

## 1. Prerequisites & Firmware Preparation

Before beginning installation, your target machine must be configured in UEFI setup:

1. **Set Firmware Administrator Password:** Protects UEFI settings against physical tampering.
2. **Clear Secure Boot Keys (Enter Setup Mode):**
   - In firmware setup, choose **Clear Secure Boot Keys** or **Delete All Keys** (sets `SetupMode: 1`).
   - Ensure **Secure Boot is OFF** during initial installation.
   > [!IMPORTANT]
   > Authenticated NVRAM variable writes (`PK`, `KEK`, `db`) require `SetupMode == 1`. If the vendor PK is not cleared, installation preflight will abort (`exit 64`) to prevent write errors or bricked firmware states.
3. **Boot Live Installation Media:** Boot an official Alpine Linux Standard live USB on the target machine.

---

## 2. Installation Ceremonies

Alpine FDE supports four primary storage layouts. Choose the one that matches your hardware:

### Topology A: Default Single-Disk (NVMe or SATA SSD)
Partitions the disk into an unencrypted ESP (`p1`) and an Argon2id LUKS2 container (`p2`) formatted with Btrfs (`@`, `@home`, `@snapshots`):

```sh
./bin/alpine-fde install --disk /dev/nvme0n1
```

### Topology B: Accelerated Hybrid Storage (`--bcache`)
Accelerates a high-capacity HDD or slow SSD (`--disk`) using a fast NVMe caching drive (`--bcache`):
- ESP (`p1`) and bcache caching set (`p2`) reside on the fast NVMe drive.
- Backing device (`p1`) resides on the HDD.
- LUKS2 container is created directly on `/dev/bcache0` in strictly enforced **`writethrough`** mode.

```sh
./bin/alpine-fde install --disk /dev/sda --bcache /dev/nvme0n1
```

### Topology C: Multi-Disk Btrfs RAID1 (Dual or Multi-Drive)
Mirrors both data and metadata across two or more physical drives (`-d raid1 -m raid1`). Each disk is wrapped in its own independent LUKS2 container sealed to the machine's TPM 2.0 with synchronized policies:

```sh
./bin/alpine-fde install --disk /dev/nvme0n1 --disk /dev/nvme1n1
```

### Topology D: Accelerated Multi-Disk Hybrid Storage (`--bcache` + Multi-`--disk`)
Combines SSD caching acceleration with multi-drive Btrfs RAID1 redundancy (e.g. one fast NVMe SSD caching two large mechanical hard drives):
- ESP (`p1`) and shared bcache caching set (`p2`) reside on the fast NVMe drive (`--bcache`).
- Backing devices (`p1`) reside on each HDD (`/dev/sda`, `/dev/sdb`), registering as `/dev/bcache0` and `/dev/bcache1`.
- Independent LUKS2 dm-crypt containers sit directly on top of each `/dev/bcacheN` device in strictly enforced **`writethrough`** mode.
- Btrfs root filesystem mirrors data and metadata across both decrypted volumes (`-d raid1 -m raid1`).

```sh
./bin/alpine-fde install --bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb
```

---

## 3. The Fully Automated Ceremony & First-Boot Trust Finalization

Alpine FDE eliminates all manual prompts during installation. The entire process runs unattended from the live USB through to the booted system:

1. **Installer Phase (Live Host) — Stage 1 (Unattended):**
   - Run `./bin/alpine-fde install --disk ...` (with `--yes` or non-interactively).
   - The installer partitions disks according to the chosen topology, formats the root container with an internal **ephemeral install key** in keyslot 0 (kept only in tmpfs, never written to disk), and installs the minimal Alpine base system via `apk add --root`.
   - In-chroot provisioning executes unattended in strict sequence:
     1. Installs the explicit additions package set (`linux-lts`, `cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `sbsigntool`, `openssl`, `tpm2-tools`, `jq`, filesystem tools).
     2. Generates custom platform keys (`PK`, `KEK`, `db`) and `release.pem` (mode `0600`).
     3. Enrolls authenticated UEFI NVRAM variables in strict order (`db → KEK → PK` last).
     4. Builds signed `systemd-bootx64.efi` and signed UKI with embedded `.pcrsig` via `ukictl build`.
     5. **Provisional TPM Sealing:** Seals keyslot 1 with a **Provisional TPM Token** bound via `PolicyAuthorize` over **PCR 11 only** (matching the signed UKI).
     6. Drops an unfinalized warning banner into `/etc/motd` and `/etc/issue`.
     7. Writes state `installed` to `/etc/alpine-fde/install-state.json`.
   - Cleans up and reboots directly into the target disk.

2. **First Boot Phase (Provisional UKI Unseal) — Stage 2 (Automated):**
   - The machine powers on under custom Secure Boot keys.
   - The initramfs hook matches the provisional token against the measured UKI in PCR 11 and **automatically unlocks the root filesystem without asking for any password**.
   - The system boots straight to the normal multi-user login prompt (console / SSH reachability).
   - The `/etc/motd` banner alerts the operator:
     ```text
     ================================================================================
     [!] Alpine FDE: System running in PROVISIONAL mode!
         - Disk is unlocked via provisional UKI measurement (PCR 11 only).
         - No permanent recovery passphrase is set.
         - Release signing key is unencrypted at rest.

     >> To complete setup, run:
        sudo alpine-fde finalize
     ================================================================================
     ```

3. **Trust Finalization Phase — Stage 3 (`alpine-fde finalize`):**
   - The administrator logs in and runs:
     ```sh
     sudo alpine-fde finalize
     ```
   - The interactive finalization wizard executes:
     1. **Sets Permanent Recovery Passphrase:** Prompts the operator to choose a permanent recovery passphrase (enforcing §13 entropy floor). Enrolls it into keyslot 0 (Argon2id) and purges the ephemeral install key.
     2. **Encrypts Release Signing Key:** Prompts operator for a passphrase to encrypt `/etc/alpine-fde/keys/release.pem` with AES-256 PBKDF2 ($\ge$ 600,000 iterations, ADR-18), tightening permissions to `0400`.
     3. **Upgrades TPM Seal:** Captures actual Secure Boot PCR 7 baseline via `audit --init` and upgrades the keyslot 1 token to **{PCR 7, PCR 11}** (Mechanism B).
     4. **Cleans Up:** Clears the unfinalized MOTD banner and writes state `finalized` to `/etc/alpine-fde/install-state.json`.
     5. **Backup:** Prompts operator to back up `/etc/alpine-fde/keys/` off-machine via `scp`:
        ```sh
        scp -r /etc/alpine-fde/keys/ admin@backup-host:/secure/storage/alpine-fde-backup/
        ```

4. **Normal Operation — Stage 4:**
   - Every subsequent boot is **100% passwordless**: unseals via the permanent TPM token bound to both Secure Boot state (PCR 7) and measured UKI (PCR 11).
   - **Drift Protection:** If PCR 7 drifts (firmware update) or PCR 11 drifts (kernel change), the initramfs prompts for the **recovery passphrase** (up to 3 attempts, then `poweroff -f`).

Keyslot lifecycle summary (§9.1):

| Install state | Keyslot 0 | Keyslot 1 | TPM token |
|---|---|---|---|
| `installed` (post-install, pre-first-boot) | Ephemeral install key (tmpfs) | Sealed provisional secret | Provisional Token: Bound to PCR 11 |
| `provisional-booted` (first boot, pre-finalize) | Ephemeral install key (unprompted) | Sealed provisional secret | Provisional Token: Bound to PCR 11 (MOTD active) |
| `finalized` (post-`finalize`) | Permanent recovery passphrase | Finalized sealed secret | Mechanism B Token: Bound to PCR 7 + PCR 11 |

---

## 4. Daily Operations

### Kernel Upgrades & Signing Key Passphrase Prompt
Alpine package upgrades (`apk upgrade`) trigger APK triggers automatically:
1. `mkinitfs` (or Dracut) rebuilds the initramfs with early-boot unseal capabilities.
2. `ukify` predicts the digest at build time; measurement happens in `systemd-efistub` at boot.
3. The APK trigger signs the UKI binary and embeds the `.pcrsig` signature using `/etc/alpine-fde/keys/release.pem`.
   > [!NOTE]
   > Because `release.pem` is encrypted with AES-256 for local at-rest protection (ADR-18), `apk upgrade` prompts interactively for your **release signing key passphrase** during the trigger execution. Unattended/non-interactive upgrades will fail loudly if the passphrase is not provided.
4. Next boot: boots into the new kernel **100% passwordless**. No TPM re-enrollment is required.

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
*(Restoring filesystem contents under `@` does not perturb PCR 11 measurements, requiring no kernel re-signing).*

### Booting Alternative or Retained Kernels
Up to 3 kernels are retained on the ESP. To boot a previous kernel one time:

```sh
# View available entries
bootctl list

# Select kernel for next boot only
alpine-fde bootnext alpine-fde-6.6.x-lts.efi
```

The system reboots into the previous kernel **without requiring a password**, because each retained UKI carries its own signed `.pcrsig` validated against the TPM token.

---

## 5. Disaster Recovery & Hardware Maintenance

---

### Runbook 1: Broken Cache SSD & ESP Rebuild (Hybrid bcache Setup)

**Scenario:** In an accelerated single-disk or multi-disk hybrid setup (`--disk /dev/sda --bcache /dev/nvme0n1` or `--bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb`), the NVMe SSD physically fails, taking down both the ESP (`p1`) and the cache partition (`p2`).

Because the system was installed in **`writethrough`** mode, **100% of your data remains intact on the backing disk(s) (`/dev/sda1`, `/dev/sdb1`)**.

#### Step 1: Boot Recovery Live Media
Boot from an Alpine Linux live USB.

#### Step 2: Assemble Backing Device in Standalone Mode
Without the caching drive present, load the bcache module and register the backing disk(s) directly:
```sh
modprobe bcache
echo /dev/sda1 > /sys/fs/bcache/register
# For multi-disk setups, register all backing drives:
# echo /dev/sdb1 > /sys/fs/bcache/register
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
   echo /dev/sda1 > /sys/fs/bcache/register
   cryptsetup open /dev/bcache0 root1
   mount -o degraded,subvol=@ /dev/mapper/root1 /mnt
   ```
2. **Install replacement drive** (e.g. `/dev/sdc`) and partition it with a backing partition:
   ```sh
   printf 'label: gpt\ntype=linux, name="backing"\n' | sfdisk /dev/sdc
   ```
3. **Format as bcache backing device and attach to the NVMe caching set:**
   ```sh
   make-bcache -B /dev/sdc1
   echo /dev/sdc1 > /sys/fs/bcache/register
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
