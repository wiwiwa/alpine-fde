#!/usr/bin/env bash
# tests/unit/install_dryrun.sh — `debian-fde install` dry-run plan contract
# (docs/Architecture.md §4/§4.1, §8.2, §9.1, §13; UserGuide §2):
#   * default runner is dry-run; prints the COMPLETE action plan and EXECUTES
#     nothing
#   * G-ST1: Btrfs is the DEFAULT root fs (mkfs.btrfs + @/@home/@snapshots
#     subvolumes + subvol fstab + rootflags=subvol=@); --fs ext4 keeps the
#     legacy flat path verbatim
#   * G-ST2/ADR-17: --bcache <dev> hybrid topology (ESP+cache on the cache
#     dev, make-bcache -C/-B, writethrough pinned, LUKS2 on /dev/bcache0,
#     dracut 20-bcache.conf)
#   * G-ST3: repeatable --disk = Btrfs RAID1 (per-role partitioning, per-member
#     LUKS2, raid1 mkfs, per-member crypttab with password-cache=yes)
#   * G-IL4/5/8/11/G-KC7: §9.1 in-chroot provisioning sequence (baseline
#     pending on target, key ceremony, NVRAM enrollment db→KEK→PK, in-chroot
#     ukictl build, keys_encrypt_release, hooks, state installed, OsIndications,
#     teardown, reboot — suppressed by DEBIAN_FDE_INSTALL_NO_REBOOT=1)
#   * destructive runners gated behind --yes; package-list lint; §13 passphrase
#     floor unit checks (shared with rotate)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/debian-fde-install-dryrun.XXXXXX)
export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_HOOKS_DIR=$T/hooks   # dry-run must not require the real hooks tree
FAKEDISK=$T/disk.img
: >"$FAKEDISK"

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

run_install() { # args...
    INS_OUT=$("$REPO/bin/debian-fde" install "$@" 2>&1)
    INS_RC=$?
}

# --- 1. usage errors ---------------------------------------------------------------
run_install
assert_eq "no --disk -> usage rc 2" "2" "$INS_RC"
export DEBIAN_FDE_INSTALL_RUNNER=nonsense
run_install --disk "$FAKEDISK"
assert_eq "unknown runner -> usage rc 2" "2" "$INS_RC"
export DEBIAN_FDE_INSTALL_RUNNER=chroot
run_install --disk "$FAKEDISK"
assert_eq "destructive runner without --yes -> usage rc 2" "2" "$INS_RC"
unset DEBIAN_FDE_INSTALL_RUNNER
run_install --fs xfs --disk "$FAKEDISK"
assert_eq "G-ST1: --fs xfs rejected (btrfs|ext4 only) -> usage rc 2" "2" "$INS_RC"
assert_contains "--fs error names the valid values" "$INS_OUT" "btrfs or ext4"
run_install --bcache /dev/nvme0n1
assert_eq "G-ST2: --bcache without --disk -> usage rc 2" "2" "$INS_RC"
assert_contains "--bcache without --disk: error says what is needed" "$INS_OUT" "--disk"
run_install --bcache /dev/nvme0n1 --disk a --disk b
assert_eq "--bcache takes exactly one backing disk -> rc 2" "2" "$INS_RC"
run_install --fs ext4 --disk a --disk b
assert_eq "G-ST3: --fs ext4 is single-disk only -> rc 2" "2" "$INS_RC"

# --- 2. dry-run prints the full plan (G-ST1: btrfs default) ------------------------
export DEBIAN_FDE_INSTALL_RUNNER=dry-run
run_install --disk "$FAKEDISK"
assert_eq "dry-run rc 0" "0" "$INS_RC"
assert_contains "plan: sfdisk GPT partitioning" "$INS_OUT" "sfdisk"
assert_contains "plan: uefi ESP partition" "$INS_OUT" "type=uefi"
assert_contains "plan: luksFormat luks2" "$INS_OUT" "luksFormat --type luks2"
assert_contains "plan: Argon2id KDF pinned" "$INS_OUT" "--pbkdf argon2id"
assert_contains "plan: argon2id memory pin" "$INS_OUT" "--pbkdf-memory 1048576"
assert_contains "plan: argon2id time pin" "$INS_OUT" "--iter-time 2000"
assert_contains "plan: keyslot 0 is the passphrase slot" "$INS_OUT" "--key-slot 0"
assert_contains "plan: NO provisional token at Stage 1 (§9.1)" "$INS_OUT" "luksFormat"
assert_contains "plan: G-ST1 mkfs.btrfs is the default root fs" "$INS_OUT" "mkfs.btrfs -U"
assert_eq "plan: exactly 3 btrfs subvolume records (@ @home @snapshots)" "3" \
    "$(grep -c 'btrfs subvolume create' <<<"$INS_OUT")"
assert_contains "plan: subvol @ created" "$INS_OUT" "btrfs subvolume create /mnt/@"
assert_contains "plan: subvol @home created" "$INS_OUT" "btrfs subvolume create /mnt/@home"
assert_contains "plan: subvol @snapshots created" "$INS_OUT" "btrfs subvolume create /mnt/@snapshots"
assert_contains "plan: @ mounted as root" "$INS_OUT" "mount -o subvol=@ /dev/mapper/root-crypt /mnt"
assert_contains "plan: @home mounted" "$INS_OUT" "mount -o subvol=@home /dev/mapper/root-crypt /mnt/home"
assert_contains "plan: @snapshots mounted" "$INS_OUT" "mount -o subvol=@snapshots /dev/mapper/root-crypt /mnt/.snapshots"
assert_contains "plan: mkfs.vfat ESP" "$INS_OUT" "mkfs.vfat -F 32"
assert_contains "plan: debootstrap minbase trixie" "$INS_OUT" "debootstrap --variant=minbase trixie"
assert_contains "plan: debian mirror" "$INS_OUT" "http://deb.debian.org/debian"
assert_contains "plan: apt no-recommends policy" "$INS_OUT" "APT::Install-Recommends"
assert_contains "plan: non-free-firmware component" "$INS_OUT" "non-free-firmware"
assert_contains "plan: apt update" "$INS_OUT" "apt-get update"
assert_contains "plan: one-transaction package install" "$INS_OUT" "apt-get install -y --no-install-recommends"
assert_contains "plan: microcode included" "$INS_OUT" "microcode"
# §3.3: jq ships in the SAME transaction (dependency of the debian-fde CLI),
# in the §3.3 documented position (zram-tools, jq, sudo)
APT_TXN=$(grep -m1 'apt-get install -y --no-install-recommends' <<<"$INS_OUT")
assert_contains "plan: apt transaction includes jq (§3.3 order)" "$APT_TXN" " zram-tools jq sudo "
assert_contains "plan: apt transaction includes btrfs-progs (default fs)" "$APT_TXN" "btrfs-progs"
assert_not_contains "plan: apt transaction has no e2fsprogs under btrfs default" "$APT_TXN" "e2fsprogs"
assert_contains "plan: user creation" "$INS_OUT" "useradd -m -s /bin/bash admin"
assert_contains "plan: networkd config" "$INS_OUT" "20-debian-fde.network"
# G-ST4/§8.2: single-disk crypttab is ONE root entry, NO password-cache
assert_contains "plan: crypttab with mandatory tpm2-device" "$INS_OUT" "luks,tpm2-device=auto,discard"
assert_not_contains "plan: single topology crypttab has NO password-cache (verbatim §8.2)" \
    "$(grep -F 'none luks,tpm2-device=auto,discard' <<<"$INS_OUT")" "password-cache"
# G-ST10/§8.2: btrfs rootflags + fail-closed pins verbatim
assert_contains "plan: G-ST10 rootflags=subvol=@ on the btrfs cmdline" "$INS_OUT" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
assert_contains "plan: fail-closed cmdline pins verbatim" "$INS_OUT" "rd.shell=0 rd.emergency=poweroff"
assert_contains "plan: dracut hostonly" "$INS_OUT" "hostonly=yes"
assert_contains "plan: dracut legacy crypt module omitted" "$INS_OUT" "omit_dracutmodules"
# G-ST1: subvol fstab forms
assert_contains "plan: fstab root subvol form" "$INS_OUT" "btrfs subvol=@,defaults 0 1"
assert_contains "plan: fstab @home subvol form" "$INS_OUT" "btrfs subvol=@home,defaults 0 2"
assert_contains "plan: fstab @snapshots subvol form" "$INS_OUT" "btrfs subvol=@snapshots,defaults 0 2"
assert_contains "plan: ESP fstab line" "$INS_OUT" "PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2"
assert_not_contains "plan: no ext4 fstab root line under btrfs default" "$INS_OUT" "/ ext4 defaults 0 1"
assert_contains "plan: bootctl install (ESP layout for the in-chroot build)" "$INS_OUT" "bootctl install"
assert_contains "plan: /etc/debian-fde conf drop" "$INS_OUT" "etc/debian-fde/debian-fde.conf"
assert_contains "plan: kernel hooks installed" "$INS_OUT" "etc/kernel/postinst.d"
assert_contains "plan: tree staged to /opt/debian-fde" "$INS_OUT" "opt/debian-fde"
assert_contains "plan: next-step hint (audit --init)" "$INS_OUT" "audit --init"
assert_contains "plan: teardown (umount + luks close)" "$INS_OUT" "cryptsetup close root-crypt"
# §4 topology recorded in the target conf (absent file = btrfs default, doc'd)
assert_contains "plan: conf records ROOT_FS=btrfs" "$INS_OUT" "ROOT_FS=btrfs"
assert_contains "plan: conf records BCACHE=0" "$INS_OUT" "BCACHE=0"
assert_contains "plan: conf records the default (absent file = btrfs/0)" "$INS_OUT" \
    "Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0"

# --- 2b. §9.1 in-chroot provisioning sequence --------------------------------------
assert_contains "plan: §9.1 step 2 — pending baseline ON TARGET (baseline writer)" \
    "$INS_OUT" "inst_baseline_pending_write /mnt"
assert_not_contains "plan: NO host-baseline copy anywhere (§9.1)" "$INS_OUT" \
    "cp /etc/debian-fde/baseline.json"
assert_contains "plan: §9.1 step 3 — in-chroot platform-key ceremony" "$INS_OUT" \
    "/opt/debian-fde/bin/debian-fde provision stage1 --mode in-chroot"
assert_contains "plan: §9.1 step 4 — NVRAM enrollment db->KEK->PK via fw_auth_enroll" \
    "$INS_OUT" "fw_auth_enroll /sys/firmware/efi/efivars /etc/debian-fde/keys"
assert_contains "plan: §9.1 step 5 — in-chroot ukictl build (boot manager + UKI)" \
    "$INS_OUT" "/opt/debian-fde/bin/debian-fde ukictl build"
assert_contains "plan: §9.1 step 6 — keys_encrypt_release (release.pem encrypted)" \
    "$INS_OUT" "keys_encrypt_release"
assert_contains "plan: §9.1 step 8 — state installed via istate_write" "$INS_OUT" \
    "inst_state_write installed"
assert_contains "plan: OsIndications bit 0 record" "$INS_OUT" "fw_osindications_set"
assert_contains "plan: efivars bound into the target (§9.1)" "$INS_OUT" \
    "mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars"
assert_contains "plan: teardown includes the efivars umount" "$INS_OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"
assert_contains "plan: reboot record (§9.1 single-reboot ceremony)" "$INS_OUT" "reboot"
# G-IL8: NO host-side signing machinery anywhere in the plan (the §3.3 target
# package names legitimately CONTAIN the substrings — pin the command records)
assert_eq "plan: zero sbsign command records (in-chroot build)" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*sbsign --' <<<"$INS_OUT")"
assert_eq "plan: zero ukify command records (in-chroot build)" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*ukify build' <<<"$INS_OUT")"
assert_eq "plan: zero sbverify records" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*sbverify' <<<"$INS_OUT")"
assert_not_contains "plan: zero --keydir signing references" "$INS_OUT" "release.pem"
assert_not_contains "plan: no <signing-medium> placeholder" "$INS_OUT" "<signing-medium>"
# plan-order discipline (§9.1): baseline pending BEFORE the key ceremony; the
# ceremony BEFORE enrollment; enrollment BEFORE the build; state BEFORE OsIndications
line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }
I_BASE=$(line_no "$INS_OUT" "inst_baseline_pending_write")
I_KEYGEN=$(line_no "$INS_OUT" "provision stage1 --mode in-chroot")
I_ENROLL=$(line_no "$INS_OUT" "fw_auth_enroll")
I_BUILD=$(line_no "$INS_OUT" "ukictl build")
I_ENCRYPT=$(line_no "$INS_OUT" "keys_encrypt_release")
I_HOOKS=$(line_no "$INS_OUT" "etc/kernel/postinst.d")
I_STATE=$(line_no "$INS_OUT" "inst_state_write installed")
I_OSIND=$(line_no "$INS_OUT" "fw_osindications_set")
I_TEARDOWN=$(line_no "$INS_OUT" "umount -R /mnt")
assert_eq "order: baseline pending before key ceremony" "1" "$(( I_BASE < I_KEYGEN ? 1 : 0 ))"
assert_eq "order: key ceremony before NVRAM enrollment" "1" "$(( I_KEYGEN < I_ENROLL ? 1 : 0 ))"
assert_eq "order: enrollment before ukictl build" "1" "$(( I_ENROLL < I_BUILD ? 1 : 0 ))"
assert_eq "order: build before keys_encrypt_release" "1" "$(( I_BUILD < I_ENCRYPT ? 1 : 0 ))"
assert_eq "order: hooks after keys_encrypt_release (§9.1 step 7)" "1" "$(( I_ENCRYPT < I_HOOKS ? 1 : 0 ))"
assert_eq "order: state write before OsIndications" "1" "$(( I_STATE < I_OSIND ? 1 : 0 ))"
assert_eq "order: OsIndications before teardown" "1" "$(( I_OSIND < I_TEARDOWN ? 1 : 0 ))"
# dry-run config drops stay in plan order (debootstrap before policy before apt)
D_DEBOOT=$(line_no "$INS_OUT" "debootstrap --variant=minbase")
D_POLICY=$(line_no "$INS_OUT" "etc/apt/apt.conf.d/90debian-fde")
D_APTUPD=$(line_no "$INS_OUT" "apt-get update")
assert_eq "order: debootstrap before policy write" "1" "$(( D_DEBOOT < D_POLICY ? 1 : 0 ))"
assert_eq "order: policy write before apt update" "1" "$(( D_POLICY < D_APTUPD ? 1 : 0 ))"

# --- 2c. NO_REBOOT seam (CI) ---------------------------------------------------------
DEBIAN_FDE_INSTALL_NO_REBOOT=1 run_install --disk "$FAKEDISK"
assert_eq "NO_REBOOT=1: rc 0" "0" "$INS_RC"
assert_not_contains "NO_REBOOT=1: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK" --no-reboot
assert_eq "--no-reboot flag: rc 0" "0" "$INS_RC"
assert_not_contains "--no-reboot flag: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK"
assert_contains "default: reboot record present" "$INS_OUT" "reboot #"

# --- 3. G-ST1b: --fs ext4 keeps the legacy flat path verbatim ------------------------
run_install --disk "$FAKEDISK" --fs ext4
assert_eq "ext4 dry-run rc 0" "0" "$INS_RC"
assert_contains "ext4: mkfs.ext4 verbatim" "$INS_OUT" "mkfs.ext4 -F -U"
assert_contains "ext4: flat mount verbatim" "$INS_OUT" \
    "mount /dev/mapper/root-crypt /mnt && mkdir -p /mnt/efi && mount"
assert_not_contains "ext4: no mkfs.btrfs" "$INS_OUT" "mkfs.btrfs"
assert_not_contains "ext4: no subvolume records" "$INS_OUT" "btrfs subvolume"
assert_not_contains "ext4: no subvol fstab" "$INS_OUT" "subvol="
assert_not_contains "ext4: no rootflags (legacy cmdline verbatim)" "$INS_OUT" "rootflags"
assert_eq "ext4: legacy cmdline pins verbatim" "1" \
    "$(grep -Ec 'root=UUID=[0-9a-f-]{36} ro rd.shell=0 rd.emergency=poweroff' <<<"$INS_OUT")"
assert_contains "ext4: legacy fstab verbatim" "$INS_OUT" "/ ext4 defaults 0 1"
assert_contains "ext4: conf records ROOT_FS=ext4" "$INS_OUT" "ROOT_FS=ext4"
APT_TXN_EXT4=$(grep -m1 'apt-get install -y --no-install-recommends' <<<"$INS_OUT")
assert_contains "ext4: apt transaction includes e2fsprogs" "$APT_TXN_EXT4" "e2fsprogs"
assert_not_contains "ext4: apt transaction has no btrfs-progs" "$APT_TXN_EXT4" "btrfs-progs"

# --- 4. G-ST2/ADR-17: --bcache hybrid topology ---------------------------------------
CACHEDEV=$T/cache.img
: >"$CACHEDEV"
run_install --disk "$FAKEDISK" --bcache "$CACHEDEV"
assert_eq "bcache dry-run rc 0" "0" "$INS_RC"
assert_contains "bcache: cache dev partitioned (ESP p1 + cache p2)" "$INS_OUT" 'name="cache"'
assert_contains "bcache: backing dev partitioned (p1 only)" "$INS_OUT" 'name="backing"'
assert_contains "bcache: make-bcache -C on cache p2" "$INS_OUT" "make-bcache -C ${CACHEDEV}2"
assert_contains "bcache: make-bcache -B on backing p1" "$INS_OUT" "make-bcache -B ${FAKEDISK}1"
assert_contains "bcache: cache set attached to bcache0" "$INS_OUT" \
    "/sys/block/bcache0/bcache/attach"
assert_contains "bcache: WRITETHROUGH pinned (literal, ADR-17)" "$INS_OUT" \
    "echo writethrough > /sys/block/bcache0/bcache/cache_mode"
assert_eq "bcache: LUKS2 ON TOP of /dev/bcache0 (key invariant)" "1" \
    "$(grep -Ec 'luksFormat --type luks2 [^ ]*.* /dev/bcache0' <<<"$INS_OUT")"
assert_contains "bcache: ESP lands on the CACHE dev (§4.1 topology 2)" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${CACHEDEV}1"
assert_contains "bcache: dracut 20-bcache.conf dropped" "$INS_OUT" "etc/dracut.conf.d/20-bcache.conf"
assert_contains "bcache: conf forces the bcache driver" "$INS_OUT" 'force_drivers+=" bcache "'
assert_contains "bcache: conf installs the bcache udev registration pieces" "$INS_OUT" \
    'install_items+=" /lib/udev/rules.d/69-bcache.rules /lib/udev/bcache-register "'
assert_contains "bcache: conf records BCACHE=1" "$INS_OUT" "BCACHE=1"
APT_TXN_BC=$(grep -m1 'apt-get install -y --no-install-recommends' <<<"$INS_OUT")
assert_contains "bcache: apt transaction includes bcache-tools" "$APT_TXN_BC" "bcache-tools"
BC_CRYPTTAB=$(grep -F 'none luks,tpm2-device=auto,discard' <<<"$INS_OUT")
assert_contains "bcache: crypttab is a single root entry (NO password-cache)" "$BC_CRYPTTAB" \
    "root UUID="
assert_not_contains "bcache: crypttab has no password-cache (verbatim §8.2)" "$BC_CRYPTTAB" "password-cache"
assert_not_contains "bcache: no RAID1 mkfs" "$INS_OUT" "\-d raid1"

# --- 5. G-ST3: repeatable --disk = Btrfs RAID1 ----------------------------------------
DISK2=$T/disk2.img
: >"$DISK2"
run_install --disk "$FAKEDISK" --disk "$DISK2"
assert_eq "raid1 dry-run rc 0" "0" "$INS_RC"
assert_contains "raid1: primary partitioned ESP p1 + LUKS p2" "$INS_OUT" "sfdisk $FAKEDISK"
assert_contains "raid1: secondary partitioned (single root partition)" "$INS_OUT" "sfdisk $DISK2"
assert_not_contains "raid1: secondary has NO ESP partition" "$INS_OUT" "type=uefi*$DISK2"
assert_eq "raid1: exactly 2 luksFormat records (per member)" "2" \
    "$(grep -c 'luksFormat --type luks2' <<<"$INS_OUT")"
assert_contains "raid1: mkfs.btrfs raid1 data+metadata" "$INS_OUT" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "raid1: primary mapper is root1" "1" \
    "$(grep -Ec 'cryptsetup open .* root1$' <<<"$INS_OUT")"
assert_eq "raid1: secondary mapper is root2" "1" \
    "$(grep -Ec 'cryptsetup open .* root2$' <<<"$INS_OUT")"
assert_eq "raid1: crypttab root1 entry with password-cache=yes" "1" \
    "$(grep -Ec 'root1 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "raid1: crypttab root2 entry with password-cache=yes" "1" \
    "$(grep -Ec 'root2 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "raid1: ESP formatted ONCE (primary only)" "1" \
    "$(grep -c 'mkfs.vfat -F 32' <<<"$INS_OUT")"
assert_contains "raid1: ESP on the primary disk p1" "$INS_OUT" "mkfs.vfat -F 32 -n EFI ${FAKEDISK}1"
assert_eq "raid1: target metadata carries BOTH member uuids" "1" \
    "$(grep -Ec 'inst_resolve_target_metadata \S+ /mnt [0-9a-f-]{36} [0-9a-f-]{36}$' <<<"$INS_OUT")"
assert_contains "raid1: teardown closes both members" "$INS_OUT" \
    "cryptsetup close root1 && cryptsetup close root2"
assert_eq "raid1: single topology crypttab entry (root, no suffix) absent" "0" \
    "$(grep -Ec 'PLAN    \| root UUID=' <<<"$INS_OUT")"

# --- 6. dry-run has no side effects ------------------------------------------------------
CSUM_BEFORE=$(sha256sum <"$FAKEDISK")
run_install --disk "$FAKEDISK"
CSUM_AFTER=$(sha256sum <"$FAKEDISK")
assert_eq "fake disk untouched by dry-run" "$CSUM_BEFORE" "$CSUM_AFTER"
assert_not_contains "dry-run created no keyfile temp leakage in plan" "$INS_OUT" "key-file /tmp/debian-fde-diskkey"
assert_not_contains "dry-run created no keyfile temp leakage in plan (M-01 tmpfs seam)" "$INS_OUT" "key-file /dev/shm/debian-fde-diskkey"

# --- 7. L-06: DEBIAN_FDE_YES only counts as consent when it is exactly "1" -----
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_INSTALL_NO_REBOOT=1
DEBIAN_FDE_YES=0 run_install --disk "$FAKEDISK"
assert_eq "L-06: DEBIAN_FDE_YES=0 is NOT consent -> usage rc 2" "2" "$INS_RC"
assert_contains "L-06: refusal explains the --yes requirement" "$INS_OUT" "requires --yes"
DEBIAN_FDE_YES=no run_install --disk "$FAKEDISK"
assert_eq "L-06: DEBIAN_FDE_YES=no is NOT consent -> usage rc 2" "2" "$INS_RC"
unset DEBIAN_FDE_INSTALL_RUNNER DEBIAN_FDE_INSTALL_NO_REBOOT

# --- 8. M-02: injected operator inputs die at the boundary (usage rc 2) --------
run_install --disk "$FAKEDISK" --user 'x; rm -rf /'
assert_eq "M-02: injected --user -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: error names the invalid user" "$INS_OUT" "invalid --user"
run_install --disk '/dev/sda; reboot -f'
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$INS_RC"
DEBIAN_FDE_ESP_SIZE='512M; reboot' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected ESP size -> usage rc 2" "2" "$INS_RC"
DEBIAN_FDE_MIRROR='http://evil.example/debian; rm -rf /' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected mirror -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --bcache '/dev/nvme0n1; reboot -f'
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$INS_RC"
# WR-01: --keydir/DEBIAN_FDE_KEYDIR rides into eval'd plan records — same rule
DEBIAN_FDE_KEYDIR='/x; touch /tmp/pwned' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected keydir (env DEBIAN_FDE_KEYDIR) -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: injected keydir error names the variable" "$INS_OUT" "DEBIAN_FDE_KEYDIR"

# --- 9. BR-01: passphrase staging contract (direct call, THIS shell) ----------
DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_INSTALL_RUNNER
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_TMPDIR=$T
DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
inst_ensure_passphrase_floor # production call-site order (install.sh, §13 floor)
_BR_RC=0
inst_resolve_disk_passphrase || _BR_RC=$?
assert_eq "BR-01: direct call returns rc 0" "0" "$_BR_RC"
assert_eq "BR-01: resolver stages _IRD_KEYFILE (non-empty)" "1" \
    "$([ -n "${_IRD_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "BR-01: key-file still EXISTS after the call (scrub trap in main shell)" "1" \
    "$([ -f "${_IRD_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "BR-01: key-file holds the verified passphrase" "correct-horse-battery-stapler-42" \
    "$(cat "${_IRD_KEYFILE:-/dev/null}")"
assert_eq "BR-01: _ird_kf carrier matches the staged key-file" "${_IRD_KEYFILE:-}" "${_ird_kf:-}"
assert_eq "BR-01: plaintext env unset in the MAIN shell (L-04b)" "1" \
    "$([ -z "${DEBIAN_FDE_DISK_PASSPHRASE:-}" ] && echo 1 || echo 0)"
rm -f "${_IRD_KEYFILE:-}"
unset _BR_RC _IRD_KEYFILE _ird_kf DEBIAN_FDE_DISK_PASSPHRASE DEBIAN_FDE_TMPDIR
trap cleanup EXIT # the resolver re-armed the EXIT trap; restore fixture cleanup
unset DEBIAN_FDE_INSTALL_RUNNER DEBIAN_FDE_YES

# --- 10. package-list lint (§3.3, topology-conditional) ------------------------
PKG_LIST=$(install_package_list)
REQUIRED="systemd-cryptsetup systemd-boot systemd-boot-tools systemd-ukify dracut linux-image-amd64 tpm2-tools cryptsetup sbsigntool openssl zram-tools jq sudo btrfs-progs systemd-resolved"
for want in $REQUIRED; do
    FOUND=0
    for w in $PKG_LIST; do
        [ "$w" = "$want" ] && FOUND=1
    done
    assert_eq "package list (default) contains $want" "1" "$FOUND"
done
for bad in e2fsprogs bcache-tools grub-pc grub-efi shim-signed initramfs-tools clevis clevis-luks ifupdown rsyslog nano cron; do
    case " $PKG_LIST " in
        *" $bad "*) assert_eq "package list (default) must NOT contain $bad" "absent" "present" ;;
        *) assert_eq "package list (default) must NOT contain $bad" "absent" "absent" ;;
    esac
done
PKG_EXT4=$(INST_ROOT_FS=ext4 install_package_list)
case " $PKG_EXT4 " in
    *e2fsprogs*) assert_eq "package list (--fs ext4) contains e2fsprogs" "1" "1" ;;
    *) assert_eq "package list (--fs ext4) contains e2fsprogs" "1" "0" ;;
esac
case " $PKG_EXT4 " in
    *btrfs-progs*) assert_eq "package list (--fs ext4) has no btrfs-progs" "0" "1" ;;
    *) assert_eq "package list (--fs ext4) has no btrfs-progs" "0" "0" ;;
esac
PKG_BC=$(INST_BCACHE=1 install_package_list)
case " $PKG_BC " in
    *bcache-tools*) assert_eq "package list (--bcache) contains bcache-tools" "1" "1" ;;
    *) assert_eq "package list (--bcache) contains bcache-tools" "1" "0" ;;
esac

# --- 11. passphrase floor (§13, C-G12) -----------------------------------------
# shellcheck source=../../lib/cmd/rotate.sh
source "$REPO/lib/cmd/rotate.sh"
assert_rc "floor ok: 16+ chars plain" 0 passphrase_floor_ok 'sixteen-chars-ok!'
assert_rc "floor ok: 12 chars 3 classes" 0 passphrase_floor_ok 'Xylophone42Dogs!'
assert_rc "floor ok: long with classes" 0 passphrase_floor_ok 'Tr0ub4dor&extra-long'
assert_rc "floor fail: too short" 1 passphrase_floor_ok 'Ab3!'
assert_rc "floor fail: 12 chars 2 classes" 1 passphrase_floor_ok 'abcdefghijklm'
assert_rc "floor fail: 15 chars 1 class" 1 passphrase_floor_ok 'abcdefghijklmno'
assert_rc "floor fail: blocklisted substring" 1 passphrase_floor_ok 'My-Secret-password-123'
assert_rc "floor fail: common sequence" 1 passphrase_floor_ok 'qwertyuiop123'
assert_rc "floor fail: empty" 1 passphrase_floor_ok ''

# --- 12. G-I9 (§13): ESP sizing — measured UKI x retention + headroom ----------
MIB=$((1024 * 1024))
assert_eq "sizing: 96MiB UKI, retention 3, 64MiB headroom -> 352M" "352M" \
    "$(inst_esp_size_compute $((96 * MIB)) 3 $((64 * MIB)))"
assert_eq "sizing: unmeasurable (empty) -> 512M default" "512M" \
    "$(inst_esp_size_compute '' 3 $((64 * MIB)))"
printf 'uki-bytes' >"$T/uki.efi"
assert_eq "sizing: measured via probe file" "65M" \
    "$(DEBIAN_FDE_UKI_FILE=$T/uki.efi inst_esp_size)"
assert_eq "sizing: env override wins over measurement" "1G" \
    "$(DEBIAN_FDE_UKI_FILE=$T/uki.efi DEBIAN_FDE_ESP_SIZE=1G inst_esp_size)"

# --- 13. help text (G-ST1/2/3, gap 7) ------------------------------------------
HELP_OUT=$("$REPO/bin/debian-fde" install --help 2>&1)
HELP_RC=$?
assert_eq "install --help rc 0" "0" "$HELP_RC"
assert_contains "help: --fs documented" "$HELP_OUT" "--fs btrfs|ext4"
assert_contains "help: --bcache documented" "$HELP_OUT" "--bcache CACHE_DEV"
assert_contains "help: repeatable --disk documented" "$HELP_OUT" "--disk DEVICE2"
assert_contains "help: --no-reboot documented" "$HELP_OUT" "--no-reboot"
assert_contains "help: SetupMode gate documented" "$HELP_OUT" "SetupMode"
assert_contains "help: btrfs default documented" "$HELP_OUT" "Btrfs root with subvolumes"
assert_contains "help: snapshots operator-pruned (retention note)" "$HELP_OUT" "pruned by the operator"

# --- 14. pre-upgrade stub (ext4 root -> graceful skip rc 0 per ADR-13) ---------
PRE_OUT=$("$REPO/bin/debian-fde" pre-upgrade 2>&1)
PRE_RC=$?
assert_eq "pre-upgrade skips ext4 root gracefully (rc 0)" "0" "$PRE_RC"
assert_contains "pre-upgrade explains ext4 stance" "$PRE_OUT" "btrfs"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
