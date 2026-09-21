#!/usr/bin/env bash
# tests/unit/install_dryrun.sh — `debian-fde install` dry-run plan contract
# (docs/Architecture.md §3.3, §4/§4.1, §8.1, §9.1, §13; ADR-17/ADR-20):
#   * default runner is dry-run; prints the COMPLETE action plan and EXECUTES
#     nothing
#   * G-C23/ADR-20: UNATTENDED — no operator passphrase prompt anywhere; the
#     internal ephemeral install key is staged on tmpfs (never persisted),
#     used for luksFormat keyslot 0 + all cryptsetup open via --key-file,
#     and scrubbed at teardown (I1)
#   * G-C1/C2/C3/§3.3: apk populate (`apk add --root <mnt> --initdb
#     alpine-base`), ONE in-chroot `apk add --no-cache` additions txn,
#     /etc/apk/repositories drop (apt/dpkg drops retired)
#   * G-ST1: Btrfs default root fs (@/@home/@snapshots + subvol fstab +
#     rootflags=subvol=@); --fs ext4 keeps the flat path verbatim
#   * G-ST2/ADR-17: --bcache single-backing hybrid topology (ESP+cache on the
#     cache dev, make-bcache -C/-B, writethrough pinned, LUKS2 on
#     /dev/bcache0)
#   * G-C27/§4.1: MULTI-BACKING bcache (--disk D1 --disk D2 --bcache CACHE):
#     shared cache set, independent LUKS2 container per /dev/bcacheN, btrfs
#     raid1 pool across the opened mappers, per-member crypttab, ESP only on
#     the cache dev
#   * G-ST3: repeatable --disk without --bcache = Btrfs RAID1
#   * G-C24/ADR-20 step 6: provisional TPM enrollment guest line after the
#     in-chroot ukictl build (Mechanism B, PCR 11 only, keyslot 1)
#   * G-C25/§9.1 step 8: unfinalized MOTD/issue banner; G-C28: banner BEFORE
#     the `installed` state write
#   * G-C26: NO OsIndications record anywhere — direct reboot to disk after
#     unmount + ephemeral-key scrub
#   * destructive runners gated behind --yes; §3.3 package-list lint;
#     ephemeral-key staging contract (0600, tmpfs, >=256-bit)

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
run_install --fs ext4 --disk a --disk b
assert_eq "G-ST3: --fs ext4 is single-disk only -> rc 2" "2" "$INS_RC"

# --- 2. dry-run prints the full plan (G-ST1: btrfs default, ADR-20 unattended) -----
export DEBIAN_FDE_INSTALL_RUNNER=dry-run
run_install --disk "$FAKEDISK"
assert_eq "dry-run rc 0" "0" "$INS_RC"
assert_contains "plan: sfdisk GPT partitioning" "$INS_OUT" "sfdisk"
assert_contains "plan: uefi ESP partition" "$INS_OUT" "type=uefi"
assert_contains "plan: luksFormat luks2" "$INS_OUT" "luksFormat --type luks2"
assert_contains "plan: Argon2id KDF pinned" "$INS_OUT" "--pbkdf argon2id"
assert_contains "plan: argon2id memory pin" "$INS_OUT" "--pbkdf-memory 1048576"
assert_contains "plan: argon2id time pin" "$INS_OUT" "--iter-time 2000"
assert_contains "plan: keyslot 0 is the ephemeral-key slot (G-C23)" "$INS_OUT" "--key-slot 0"
assert_contains "plan: keyslot 0 comment names the ephemeral install key (ADR-20)" \
    "$INS_OUT" "keyslot 0: ephemeral install key"
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
# G-C1/§3.3: apk populate replaces debootstrap
assert_contains "plan: §3.3 apk populate (alpine-base, --initdb)" "$INS_OUT" \
    "apk add --root /mnt --initdb alpine-base"
assert_not_contains "plan: debootstrap retired" "$INS_OUT" "debootstrap"
assert_contains "plan: in-chroot apk additions txn (--no-cache)" "$INS_OUT" "apk add --no-cache"
assert_not_contains "plan: apt retired" "$INS_OUT" "apt-get"
# §3.3: /etc/apk/repositories drop replaces apt sources + dpkg trims
assert_contains "plan: /etc/apk/repositories drop" "$INS_OUT" "etc/apk/repositories"
assert_contains "plan: repositories drop pins the Alpine CDN main repo" "$INS_OUT" \
    "dl-cdn.alpinelinux.org/alpine"
assert_not_contains "plan: apt sources drop retired" "$INS_OUT" "apt/sources.list.d"
assert_not_contains "plan: dpkg trims drop retired" "$INS_OUT" "dpkg.cfg.d"
# G-C23: unattended — zero interactive prompt records anywhere
assert_not_contains "plan: NO passphrase prompt (unattended, G-C23)" "$INS_OUT" \
    "Set disk encryption passphrase"
assert_not_contains "plan: NO repeat-prompt" "$INS_OUT" "Repeat passphrase"
assert_not_contains "plan: NO interactive passwd record (ADR-20 zero-touch)" "$INS_OUT" "passwd"
assert_not_contains "plan: NO operator passphrase env consumption" "$INS_OUT" \
    "DEBIAN_FDE_DISK_PASSPHRASE"
assert_contains "plan: user account created (§8.1 user account row)" "$INS_OUT" "adduser"
assert_contains "plan: OpenRC networking enabled (§9.1 step 1)" "$INS_OUT" "rc-update add networking boot"
assert_contains "plan: network interfaces drop" "$INS_OUT" "etc/network/interfaces"
assert_not_contains "plan: systemd-networkd drop retired" "$INS_OUT" "20-debian-fde.network"
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
assert_contains "plan: /etc/alpine-fde conf drop" "$INS_OUT" "etc/alpine-fde/alpine-fde.conf"
assert_contains "plan: kernel hooks installed (Alpine kernel-hooks.d layout)" "$INS_OUT" \
    "etc/kernel-hooks.d"
assert_contains "plan: tree staged to /opt/alpine-fde" "$INS_OUT" "opt/alpine-fde"
assert_contains "plan: teardown (umount + luks close)" "$INS_OUT" "cryptsetup close root-crypt"
# §4 topology recorded in the target conf (absent file = btrfs default, doc'd)
assert_contains "plan: conf records ROOT_FS=btrfs" "$INS_OUT" "ROOT_FS=btrfs"
assert_contains "plan: conf records BCACHE=0" "$INS_OUT" "BCACHE=0"
assert_contains "plan: conf records the default (absent file = btrfs/0)" "$INS_OUT" \
    "Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0"

# --- 2b. §9.1 in-chroot provisioning sequence (ADR-20 steps 1-9) --------------------
assert_contains "plan: §9.1 step 2 — pending baseline ON TARGET (baseline writer)" \
    "$INS_OUT" "inst_baseline_pending_write /mnt"
assert_not_contains "plan: NO host-baseline copy anywhere (§9.1)" "$INS_OUT" \
    "cp /etc/alpine-fde/baseline.json"
assert_contains "plan: §9.1 step 3 — in-chroot platform-key ceremony" "$INS_OUT" \
    "/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot"
assert_contains "plan: §9.1 step 4 — NVRAM enrollment db->KEK->PK via fw_auth_enroll" \
    "$INS_OUT" "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys"
assert_contains "plan: §9.1 step 5 — in-chroot ukictl build (boot manager + UKI)" \
    "$INS_OUT" "/opt/alpine-fde/bin/alpine-fde ukictl build"
# G-C24/§9.1 step 6: provisional TPM enrollment guest line (Mechanism B, PCR 11)
assert_contains "plan: §9.1 step 6 — provisional seal guest line (seal_provisional)" \
    "$INS_OUT" 'seal_provisional /etc/alpine-fde/keys /dev/mapper/$m'
assert_contains "plan: step 6 pin — provisional Mechanism B (PCR 11) -> keyslot 1" \
    "$INS_OUT" "provisional Mechanism B seal (PCR 11) -> keyslot 1"
assert_contains "plan: step 6 consumes the UKI .pcrsig (stage-1 build output)" \
    "$INS_OUT" "only-section=.pcrsig"
assert_contains "plan: step 6 authorizes luksAddKey with the ephemeral key" \
    "$INS_OUT" "token_add_keyslot"
assert_not_contains "plan: keys_encrypt_release moved to finalize (ADR-20 Stage 3)" \
    "$INS_OUT" "keys_encrypt_release"
# G-C25/§9.1 step 8: unfinalized banner to /etc/motd AND /etc/issue
assert_contains "plan: §9.1 step 8 — MOTD banner drop" "$INS_OUT" "PLAN  write  /etc/motd"
assert_contains "plan: §9.1 step 8 — issue banner drop" "$INS_OUT" "PLAN  write  /etc/issue"
assert_contains "plan: banner says NOT finalized (G-C25)" "$INS_OUT" "NOT finalized"
assert_contains "plan: banner directs to alpine-fde finalize" "$INS_OUT" "alpine-fde finalize"
assert_contains "plan: banner names the pending permanent recovery passphrase" "$INS_OUT" \
    "set your permanent recovery passphrase"
# G-C28/§9.1 step 9: state `installed` — written AFTER the banner
assert_contains "plan: §9.1 step 9 — state installed via istate_write" "$INS_OUT" \
    "inst_state_write installed"
# G-C26: NO OsIndications anywhere (firmware-trip flow retired)
assert_eq "plan: ZERO OsIndications records (G-C26)" "0" \
    "$(grep -c 'fw_osindications_set' <<<"$INS_OUT")"
assert_contains "plan: explicit ephemeral-key scrub record (I1, §9.1 teardown)" \
    "$INS_OUT" "rm -f <ephemeral-keyfile> # I1: ephemeral install key scrubbed"
assert_contains "plan: direct reboot record (ADR-20: no firmware trip)" "$INS_OUT" \
    "reboot # §9.1: direct reboot to disk (ADR-20)"
assert_contains "plan: efivars bound into the target (§9.1)" "$INS_OUT" \
    "mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars"
assert_contains "plan: teardown includes the efivars umount" "$INS_OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"
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
# ceremony BEFORE enrollment; enrollment BEFORE the build; build BEFORE the
# provisional seal; banner BEFORE the state write (§9.1 step 8/9); teardown
# BEFORE the scrub; scrub BEFORE the reboot (G-C26)
line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }
I_BASE=$(line_no "$INS_OUT" "inst_baseline_pending_write")
I_KEYGEN=$(line_no "$INS_OUT" "provision stage1 --mode in-chroot")
I_ENROLL=$(line_no "$INS_OUT" "fw_auth_enroll")
I_BUILD=$(line_no "$INS_OUT" "ukictl build")
I_SEAL=$(line_no "$INS_OUT" "seal_provisional")
I_BANNER=$(line_no "$INS_OUT" "PLAN  write  /etc/motd")
I_STATE=$(line_no "$INS_OUT" "inst_state_write installed")
I_TEARDOWN=$(line_no "$INS_OUT" "umount -R /mnt")
I_SCRUB=$(line_no "$INS_OUT" "rm -f <ephemeral-keyfile>")
I_REBOOT=$(line_no "$INS_OUT" "reboot #")
assert_eq "order: baseline pending before key ceremony" "1" "$(( I_BASE < I_KEYGEN ? 1 : 0 ))"
assert_eq "order: key ceremony before NVRAM enrollment" "1" "$(( I_KEYGEN < I_ENROLL ? 1 : 0 ))"
assert_eq "order: enrollment before ukictl build" "1" "$(( I_ENROLL < I_BUILD ? 1 : 0 ))"
assert_eq "order: build before provisional seal (the .pcrsig comes from the UKI)" "1" \
    "$(( I_BUILD < I_SEAL ? 1 : 0 ))"
assert_eq "order: provisional seal before banner" "1" "$(( I_SEAL < I_BANNER ? 1 : 0 ))"
assert_eq "order: G-C28 — banner BEFORE state write (§9.1 step 8/9)" "1" \
    "$(( I_BANNER < I_STATE ? 1 : 0 ))"
assert_eq "order: state write before teardown" "1" "$(( I_STATE < I_TEARDOWN ? 1 : 0 ))"
assert_eq "order: G-C26 — teardown before the ephemeral scrub" "1" \
    "$(( I_TEARDOWN < I_SCRUB ? 1 : 0 ))"
assert_eq "order: scrub before the direct reboot" "1" "$(( I_SCRUB < I_REBOOT ? 1 : 0 ))"
# apk populate order: rootfs populate before the repositories drop before the txn
I_POPULATE=$(line_no "$INS_OUT" "apk add --root /mnt --initdb")
I_REPOS=$(line_no "$INS_OUT" "etc/apk/repositories")
I_TXN=$(line_no "$INS_OUT" "apk add --no-cache")
assert_eq "order: apk populate before repositories drop" "1" "$(( I_POPULATE < I_REPOS ? 1 : 0 ))"
assert_eq "order: repositories drop before the additions txn" "1" "$(( I_REPOS < I_TXN ? 1 : 0 ))"

# --- 2c. NO_REBOOT seam (CI) ---------------------------------------------------------
DEBIAN_FDE_INSTALL_NO_REBOOT=1 run_install --disk "$FAKEDISK"
assert_eq "NO_REBOOT=1: rc 0" "0" "$INS_RC"
assert_not_contains "NO_REBOOT=1: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK" --no-reboot
assert_eq "--no-reboot flag: rc 0" "0" "$INS_RC"
assert_not_contains "--no-reboot flag: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK"
assert_contains "default: reboot record present" "$INS_OUT" "reboot #"

# --- 3. G-ST1b: --fs ext4 keeps the flat path verbatim -------------------------------
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
APK_TXN_EXT4=$(grep -m1 'apk add --no-cache' <<<"$INS_OUT")
assert_contains "ext4: apk txn includes e2fsprogs" "$APK_TXN_EXT4" "e2fsprogs"
assert_not_contains "ext4: apk txn has no btrfs-progs" "$APK_TXN_EXT4" "btrfs-progs"

# --- 4. G-ST2/ADR-17: --bcache single-backing hybrid topology ------------------------
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
APK_TXN_BC=$(grep -m1 'apk add --no-cache' <<<"$INS_OUT")
assert_contains "bcache: apk txn includes bcache-tools" "$APK_TXN_BC" "bcache-tools"
BC_CRYPTTAB=$(grep -F 'none luks,tpm2-device=auto,discard' <<<"$INS_OUT")
assert_contains "bcache: crypttab is a single root entry (NO password-cache)" "$BC_CRYPTTAB" \
    "root UUID="
assert_not_contains "bcache: crypttab has no password-cache (verbatim §8.2)" "$BC_CRYPTTAB" "password-cache"
assert_not_contains "bcache: no RAID1 mkfs" "$INS_OUT" "\-d raid1"
# G-C24: single-mapper provisional seal line follows the build
assert_contains "bcache: provisional seal addresses the root-crypt mapper" "$INS_OUT" \
    'seal_provisional /etc/alpine-fde/keys /dev/mapper/$m'
assert_contains "bcache: provisional seal loop covers root-crypt" "$INS_OUT" \
    "for m in root-crypt"

# --- 4b. G-C27/§4.1 topology 4: MULTI-BACKING bcache (2 backings) --------------------
DISKB=$T/diskb.img
: >"$DISKB"
run_install --disk "$FAKEDISK" --disk "$DISKB" --bcache "$CACHEDEV"
assert_eq "bcache-multi dry-run rc 0" "0" "$INS_RC"
assert_contains "bcache-multi: cache dev partitioned (ESP p1 + shared cache p2)" "$INS_OUT" \
    'name="cache"'
assert_eq "bcache-multi: EACH backing disk partitioned into a backing set" "2" \
    "$(grep -c 'name=\"backing\"' <<<"$INS_OUT")"
assert_contains "bcache-multi: make-bcache -C on the shared cache set" "$INS_OUT" \
    "make-bcache -C ${CACHEDEV}2"
assert_eq "bcache-multi: make-bcache -B per backing p1 (2 backings)" "2" \
    "$(grep -c 'make-bcache -B ' <<<"$INS_OUT")"
assert_contains "bcache-multi: backing p1 registered (sda1)" "$INS_OUT" \
    "echo ${FAKEDISK}1 > /sys/fs/bcache/register"
assert_contains "bcache-multi: backing p1 registered (sdb1)" "$INS_OUT" \
    "echo ${DISKB}1 > /sys/fs/bcache/register"
assert_contains "bcache-multi: bcache0 attached to the shared cset (writethrough)" "$INS_OUT" \
    "/sys/block/bcache0/bcache/attach"
assert_contains "bcache-multi: bcache1 attached to the shared cset (writethrough)" "$INS_OUT" \
    "/sys/block/bcache1/bcache/attach"
assert_eq "bcache-multi: writethrough pinned on BOTH members" "2" \
    "$(grep -o 'echo writethrough > /sys/block/bcache' <<<"$INS_OUT" | wc -l)"
assert_eq "bcache-multi: one independent LUKS2 container per /dev/bcacheN" "2" \
    "$(grep -Ec 'luksFormat --type luks2 [^ ]*.* /dev/bcache[01]($| )' <<<"$INS_OUT")"
assert_eq "bcache-multi: bcache0 opened as root1" "1" \
    "$(grep -Ec 'open +/dev/bcache0 root1($| )' <<<"$INS_OUT")"
assert_eq "bcache-multi: bcache1 opened as root2" "1" \
    "$(grep -Ec 'open +/dev/bcache1 root2$' <<<"$INS_OUT")"
assert_contains "bcache-multi: btrfs raid1 pool across the opened mappers" "$INS_OUT" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "bcache-multi: ESP formatted ONCE, ONLY on the cache dev" "1" \
    "$(grep -c 'mkfs.vfat -F 32' <<<"$INS_OUT")"
assert_contains "bcache-multi: ESP on the cache dev p1" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${CACHEDEV}1"
assert_not_contains "bcache-multi: NO ESP on backing disks" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${FAKEDISK}1"
assert_eq "bcache-multi: per-member crypttab root1 (password-cache=yes)" "1" \
    "$(grep -Ec 'root1 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "bcache-multi: per-member crypttab root2 (password-cache=yes)" "1" \
    "$(grep -Ec 'root2 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "bcache-multi: target metadata carries BOTH member uuids" "1" \
    "$(grep -Ec 'inst_resolve_target_metadata \S+ /mnt [0-9a-f-]{36} [0-9a-f-]{36}$' <<<"$INS_OUT")"
assert_contains "bcache-multi: teardown closes both members" "$INS_OUT" \
    "cryptsetup close root1 && cryptsetup close root2"
assert_contains "bcache-multi: provisional seal loop covers both members" "$INS_OUT" \
    "for m in root1 root2"
assert_contains "bcache-multi: conf records BCACHE=1" "$INS_OUT" "BCACHE=1"

# --- 5. G-ST3: repeatable --disk (no bcache) = Btrfs RAID1 ---------------------------
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
assert_contains "raid1: provisional seal loop covers both members" "$INS_OUT" \
    "for m in root1 root2"

# --- 6. dry-run has no side effects -----------------------------------------------------
CSUM_BEFORE=$(sha256sum <"$FAKEDISK")
run_install --disk "$FAKEDISK"
CSUM_AFTER=$(sha256sum <"$FAKEDISK")
assert_eq "fake disk untouched by dry-run" "$CSUM_BEFORE" "$CSUM_AFTER"
assert_not_contains "dry-run: no real ephemeral keyfile path leaks into the plan (M-01 tmpfs seam)" \
    "$INS_OUT" "/dev/shm/debian-fde-ephkey"
assert_contains "dry-run: ephemeral keyfile is a placeholder" "$INS_OUT" "<ephemeral-keyfile>"

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
DEBIAN_FDE_MIRROR='http://evil.example/alpine; rm -rf /' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected mirror -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --bcache '/dev/nvme0n1; reboot -f'
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$INS_RC"
# WR-01: --keydir/DEBIAN_FDE_KEYDIR rides into eval'd records — same rule
DEBIAN_FDE_KEYDIR='/x; touch /tmp/pwned' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected keydir (env DEBIAN_FDE_KEYDIR) -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: injected keydir error names the variable" "$INS_OUT" "DEBIAN_FDE_KEYDIR"

# --- 9. G-C23: ephemeral-key staging contract (direct call, THIS shell) --------
# unattended: openssl rand (>=256-bit) staged under the tmpfs seam, mode 0600,
# byte-stable for luksFormat/open/--key-file consumers; dry-run stages nothing.
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_INSTALL_RUNNER
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_TMPDIR=$T
DEBIAN_FDE_INSTALL_RUNNER=dry-run inst_stage_ephemeral_key
assert_eq "G-C23: dry-run stages NOTHING (empty _IME_KEYFILE)" "1" \
    "$([ -z "${_IME_KEYFILE:-}" ] && echo 1 || echo 0)"
inst_stage_ephemeral_key
_EPH_RC=0
assert_rc "G-C23: direct call returns rc 0" 0 inst_stage_ephemeral_key
assert_eq "G-C23: resolver stages _IME_KEYFILE (non-empty)" "1" \
    "$([ -n "${_IME_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "G-C23: key staged under the tmpfs seam (DEBIAN_FDE_TMPDIR)" "1" \
    "$([[ "${_IME_KEYFILE:-}" == "$T"/debian-fde-ephkey.* ]] && echo 1 || echo 0)"
assert_eq "G-C23: key-file mode 0600" "600" "$(stat -c '%a' "${_IME_KEYFILE:-}")"
assert_eq "G-C23: key material is 256-bit hex (64 chars, openssl rand -hex 32)" "64" \
    "$(wc -c <"${_IME_KEYFILE:-/dev/null}" | tr -d '[:space:]')"
assert_eq "G-C23: _ime_kf carrier matches the staged key-file" "${_IME_KEYFILE:-}" "${_ime_kf:-}"
rm -f "${_IME_KEYFILE:-}"
unset _IME_KEYFILE _ime_kf DEBIAN_FDE_TMPDIR
trap cleanup EXIT # the resolver re-armed the EXIT trap; restore fixture cleanup
unset DEBIAN_FDE_INSTALL_RUNNER DEBIAN_FDE_YES

# --- 10. package-list lint (§3.3, topology-conditional) ------------------------
PKG_LIST=$(install_package_list)
REQUIRED="cryptsetup systemd-boot systemd-efistub ukify linux-lts tpm2-tools tpm2-tss-policy tpm2-tss-tcti-device sbsigntool openssl jq btrfs-progs"
for want in $REQUIRED; do
    FOUND=0
    for w in $PKG_LIST; do
        [ "$w" = "$want" ] && FOUND=1
    done
    assert_eq "package list (default) contains $want" "1" "$FOUND"
done
for bad in debootstrap apt apt-get dpkg systemd-cryptsetup dracut linux-image-amd64 \
    e2fsprogs bcache-tools grub shim-signed initramfs-tools clevis sudo; do
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

# --- 11. G-I9 (§13): ESP sizing — measured UKI x retention + headroom ----------
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

# --- 12. help text (G-C23/C24/C25/C26/C27) --------------------------------------
HELP_OUT=$("$REPO/bin/debian-fde" install --help 2>&1)
HELP_RC=$?
assert_eq "install --help rc 0" "0" "$HELP_RC"
assert_contains "help: --fs documented" "$HELP_OUT" "--fs btrfs|ext4"
assert_contains "help: --bcache documented" "$HELP_OUT" "--bcache CACHE_DEV"
assert_contains "help: repeatable --disk documented" "$HELP_OUT" "--disk DEVICE2"
assert_contains "help: --no-reboot documented" "$HELP_OUT" "--no-reboot"
assert_contains "help: SetupMode gate documented" "$HELP_OUT" "SetupMode"
assert_contains "help: btrfs default documented" "$HELP_OUT" "Btrfs root with subvolumes"
assert_contains "help: unattended contract documented (no prompts)" "$HELP_OUT" "unattended"
assert_contains "help: ephemeral install key documented" "$HELP_OUT" "ephemeral"
assert_contains "help: direct reboot documented (no firmware trip)" "$HELP_OUT" "direct reboot"
assert_contains "help: finalize handoff documented" "$HELP_OUT" "finalize"

# --- 13. pre-upgrade stub (ext4 root -> graceful skip rc 0 per ADR-13) ---------
PRE_OUT=$("$REPO/bin/debian-fde" pre-upgrade 2>&1)
PRE_RC=$?
assert_eq "pre-upgrade skips ext4 root gracefully (rc 0)" "0" "$PRE_RC"
assert_contains "pre-upgrade explains ext4 stance" "$PRE_OUT" "btrfs"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
