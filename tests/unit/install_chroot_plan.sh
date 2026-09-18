#!/usr/bin/env bash
# tests/unit/install_chroot_plan.sh — `debian-fde install` chroot-runner contract
# (docs/Architecture.md §3.3, §4/§4.1, §8.1-8.4, §9.1, §13): drives the REAL
# installer with PATH-stubbed collaborators (sfdisk/cryptsetup/mkfs.btrfs/
# btrfs/mount/debootstrap/chroot/lsblk/...) recording argv to a log file, then
# asserts OBSERVED effects: the staged target tree contents, §9.1 plan
# execution order, fail-closed preconditions, and the on-target baseline/state.
#
# Topologies executed here: single-disk (deep) and Btrfs RAID1 (per-member
# LUKS2 + raid1 mkfs). The bcache hybrid topology is pinned at the record level
# in install_dryrun.sh (its sysfs attach writes cannot run in a container).
#
# Conventions (E2E-mock rule): real handler, stubbed collaborators, asserted
# files/argv/exit codes — never return values of internal helpers.

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

T=$(mktemp -d /tmp/debian-fde-install-chroot.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_HOOKS_DIR=$T/hooks
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T          # M-01/L-04: secrets + plan temp files live HERE, not /tmp
export DEBIAN_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export DEBIAN_FDE_INSTALL_NO_REBOOT=1   # CI seam: no reboot record in unit runs
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'

PARTUUID_CANON='5f2a9b01-02'            # canned ESP PARTUUID the lsblk stub reports
GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
export PARTUUID_CANON

DISK=$T/disk.img
: >"$DISK"

# --- stub collaborators -------------------------------------------------------
mkdir -p "$T/stub"

make_stub() { # NAME — log argv, exit 0
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.ext4 mkfs.vfat mount umount debootstrap chroot \
    apt-get useradd usermod passwd systemctl bootctl btrfs; do
    make_stub "$s"
done

# cryptsetup — log argv; BR-01: fail closed when a --key-file argument names a
# file that does not exist AT EXECUTION TIME (a scrub trap armed in a subshell
# deletes the staged passphrase key-file before any plan step can use it —
# this assert kills the old vacuous find-based L-04a pass)
cat >"$T/stub/cryptsetup" <<'EOF'
#!/bin/sh
prev=''
for a in "$@"; do
    if [ "$prev" = "--key-file" ] && [ ! -f "$a" ]; then
        printf 'cryptsetup --key-file target missing at execution time: %s\n' "$a" \
            >>"$DEBIAN_FDE_TEST_LOG"
        exit 91
    fi
    prev=$a
done
printf 'cryptsetup %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
exit 0
EOF

# id — pretend to be root (preflight check)
cat >"$T/stub/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF

# lsblk — log argv; report the canned PARTUUID for `-no PARTUUID <dev>`
cat >"$T/stub/lsblk" <<'EOF'
#!/bin/sh
printf 'lsblk %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' "$PARTUUID_CANON" ;;
esac
exit 0
EOF

chmod +x "$T/stub/cryptsetup" "$T/stub/id" "$T/stub/lsblk"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$DEBIAN_FDE_HOOKS_DIR"
for h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$DEBIAN_FDE_EFIVARS_DIR/$1-$GUID_GLOBAL"
}
mkdir -p "$DEBIAN_FDE_EFIVARS_DIR"
mkvar SetupMode 1   # §9.1 preflight: Stage 1 runs with the vendor PK cleared

run_install() { # extra args pass through (e.g. a second --disk)
    : >"$DEBIAN_FDE_TEST_LOG"
    rm -rf "$DEBIAN_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" "$@" 2>&1)
    RC=$?
}

# =============================================================================
# Preflight fail-closed BEFORE any destructive step — the SetupMode gate is
# FIRST (§9.1): with SetupMode=0 nothing executes (full matrix in
# install_preflight_setupmode.sh).
# =============================================================================
mkvar SetupMode 0
run_install
assert_eq "SetupMode=0 -> fail-closed 64 before any mutation" "64" "$RC"
assert_contains "SetupMode=0: error says what to fix" "$OUT" "clear the vendor PK in BIOS"
assert_eq "SetupMode=0: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
mkvar SetupMode 1

# =============================================================================
# §9.1 Stage 1 execution (single-disk, Btrfs default): plan runs rc 0 under
# stubs; BR-01: the staged passphrase key-file SURVIVES until the cryptsetup
# plan steps run.
# =============================================================================
run_install
assert_eq "chroot install rc 0" "0" "$RC"
assert_not_contains "BR-01: --key-file names an EXISTING file at cryptsetup execution time" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "key-file target missing at execution time"
assert_contains "BR-01: luksFormat ran scripted via the staged key-file" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "cryptsetup luksFormat"

LUKS_UUID=$(grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
ROOTFS_UUID=$(grep -oE -- '-U [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
assert_eq "fixture: luksFormat pinned an explicit uuid" "1" "$([ -n "$LUKS_UUID" ] && echo 1 || echo 0)"
assert_eq "fixture: mkfs.btrfs pinned an explicit uuid" "1" "$([ -n "$ROOTFS_UUID" ] && echo 1 || echo 0)"
# G-ST1: the btrfs filesystem + subvolume flow ran against the mapper
assert_contains "G-ST1: mkfs.btrfs ran on the mapper" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mkfs.btrfs -U $ROOTFS_UUID /dev/mapper/root-crypt"
assert_contains "G-ST1: subvolume @ created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@"
assert_contains "G-ST1: subvolume @home created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@home"
assert_contains "G-ST1: subvolume @snapshots created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@snapshots"
assert_contains "G-ST1: @ remounted as root" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mount -o subvol=@ /dev/mapper/root-crypt $DEBIAN_FDE_INSTALL_MNT"

MNT_ETC=$DEBIAN_FDE_INSTALL_MNT/etc
assert_file_exists "target: apt no-recommends policy" "$MNT_ETC/apt/apt.conf.d/90debian-fde"
assert_contains "apt policy: recommends off" "$(cat "$MNT_ETC/apt/apt.conf.d/90debian-fde")" 'APT::Install-Recommends "false";'
assert_file_exists "target: apt sources drop" "$MNT_ETC/apt/sources.list.d/debian-fde.sources"
assert_contains "apt sources: non-free-firmware" "$(cat "$MNT_ETC/apt/sources.list.d/debian-fde.sources")" "Components: main non-free-firmware"
# G-ST4/§8.2: single topology crypttab is ONE root entry, NO password-cache
assert_eq "crypttab verbatim per §8.2 (single topology, no password-cache)" \
    "root UUID=$LUKS_UUID none luks,tpm2-device=auto,discard" \
    "$(cat "$MNT_ETC/crypttab")"
# G-ST1: subvol fstab forms + resolved ESP PARTUUID (G-I4)
assert_contains "fstab: root subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID / btrfs subvol=@,defaults 0 1"
assert_contains "fstab: @home subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID /home btrfs subvol=@home,defaults 0 2"
assert_contains "fstab: @snapshots subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID /.snapshots btrfs subvol=@snapshots,defaults 0 2"
assert_contains "fstab: real ESP PARTUUID (placeholder resolved)" "$(cat "$MNT_ETC/fstab")" "PARTUUID=$PARTUUID_CANON /efi vfat umask=0077 0 2"
assert_not_contains "fstab: no unresolved placeholder" "$(cat "$MNT_ETC/fstab")" "<esp-partuuid>"
assert_file_exists "target: networkd drop" "$MNT_ETC/systemd/network/20-debian-fde.network"
assert_contains "networkd: dhcp" "$(cat "$MNT_ETC/systemd/network/20-debian-fde.network")" "DHCP=yes"
assert_file_exists "target: dpkg trims drop" "$MNT_ETC/dpkg/dpkg.cfg.d/90debian-fde-minimal"
assert_file_exists "target: dracut conf" "$MNT_ETC/dracut.conf.d/10-debian-fde.conf"
assert_contains "dracut: hostonly" "$(cat "$MNT_ETC/dracut.conf.d/10-debian-fde.conf")" "hostonly=yes"
assert_not_contains "single topology: no 20-bcache.conf drop" "$(ls "$MNT_ETC/dracut.conf.d/")" "20-bcache.conf"
assert_eq "cmdline.txt verbatim: rootflags + §8.2 fail-closed pins" \
    "root=UUID=$LUKS_UUID rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff" \
    "$(cat "$MNT_ETC/debian-fde/cmdline.txt")"
# §4: topology recorded in the target conf (absent file = btrfs default, doc'd)
assert_contains "conf: ROOT_FS=btrfs recorded" "$(cat "$MNT_ETC/debian-fde/debian-fde.conf")" "ROOT_FS=btrfs"
assert_contains "conf: BCACHE=0 recorded" "$(cat "$MNT_ETC/debian-fde/debian-fde.conf")" "BCACHE=0"
assert_contains "conf: ESP_PATH=/efi persisted (CR-01)" "$(cat "$MNT_ETC/debian-fde/debian-fde.conf")" "ESP_PATH=/efi"
assert_contains "conf: absent-file default documented" "$(cat "$MNT_ETC/debian-fde/debian-fde.conf")" \
    "Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0"

# =============================================================================
# §9.1 step 2/8: pending baseline + install-state ON TARGET (no host copy)
# =============================================================================
TGT_BL=$MNT_ETC/debian-fde/baseline.json
assert_file_exists "§9.1 step 2: pending baseline written ON TARGET" "$TGT_BL"
assert_rc "on-target pending baseline validates" 0 baseline_validate "$TGT_BL"
assert_eq "on-target baseline: expected_pcr7 pending" "pending" "$(baseline_get "$TGT_BL" expected_pcr7)"
assert_eq "G-I4: target.luks_uuid resolved onto the pending baseline" "$LUKS_UUID" \
    "$(baseline_get_in "$TGT_BL" target luks_uuid)"
assert_eq "G-I4: target.esp_partuuid resolved" "$PARTUUID_CANON" \
    "$(baseline_get_in "$TGT_BL" target esp_partuuid)"
assert_eq "§9.1: NO host-baseline copy anywhere" "0" \
    "$(grep -c 'cp .*baseline.json' "$DEBIAN_FDE_TEST_LOG")"
assert_file_exists "§9.1 step 8: install-state written ON TARGET" \
    "$MNT_ETC/debian-fde/install-state.json"
assert_eq "install-state: state=installed" "installed" \
    "$(istate_get "$MNT_ETC/debian-fde/install-state.json" state)"
# §9.1 teardown: OsIndications bit 0 set on the (fixture) efivars
assert_file_exists "§9.1: OsIndications set (reboot into BIOS)" \
    "$DEBIAN_FDE_EFIVARS_DIR/OsIndications-$GUID_GLOBAL"
assert_eq "§9.1: OsIndications payload is u64le 1" "070000000100000000000000" \
    "$(cat "$DEBIAN_FDE_EFIVARS_DIR/OsIndications-$GUID_GLOBAL" | od -An -vtx1 | tr -d ' \n')"

# =============================================================================
# §9.1 in-chroot sequence: order + argv as observed through the chroot stub
# =============================================================================
LOG=$(cat "$DEBIAN_FDE_TEST_LOG")
assert_contains "§9.1 step 1: apt transaction ran in-guest" "$LOG" "apt-get install -y --no-install-recommends"
APT_TXN_LOG=$(grep -m1 'apt-get install' "$DEBIAN_FDE_TEST_LOG")
assert_contains "apt transaction includes btrfs-progs (default fs, topology-conditional)" \
    "$APT_TXN_LOG" "btrfs-progs"
MCU_EXPECT=$(inst_microcode_pkgs)
assert_contains "H-02: apt txn carries the HOST-resolved microcode ($MCU_EXPECT)" \
    "$APT_TXN_LOG" "$MCU_EXPECT"
assert_contains "§9.1 step 3: platform-key ceremony invoked in-chroot" "$LOG" \
    "provision stage1 --mode in-chroot --keydir /etc/debian-fde/keys"
assert_contains "§9.1 step 4: NVRAM enrollment db->KEK->PK in-chroot" "$LOG" \
    "fw_auth_enroll /sys/firmware/efi/efivars /etc/debian-fde/keys"
assert_contains "ESP layout for the in-chroot build" "$LOG" \
    "bootctl install --esp-path=/efi --boot-path=/efi"
assert_contains "§9.1 step 5: ukictl build in-chroot (boot manager + UKI)" "$LOG" \
    "debian-fde ukictl build"
assert_contains "§9.1 step 6: keys_encrypt_release in-chroot" "$LOG" "keys_encrypt_release"
first_line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }
L_SFDISK=$(first_line_no "$LOG" "sfdisk")
L_DEBOOT=$(first_line_no "$LOG" "debootstrap")
L_POLICY=$(first_line_no "$OUT" "etc/apt/apt.conf.d/90debian-fde")
L_APTUPD=$(first_line_no "$LOG" "apt-get update")
L_KEYGEN=$(first_line_no "$LOG" "provision stage1 --mode in-chroot")
L_ENROLL=$(first_line_no "$LOG" "fw_auth_enroll")
L_BUILD=$(first_line_no "$LOG" "ukictl build")
L_ENCRYPT=$(first_line_no "$LOG" "keys_encrypt_release")
L_UMNTR=$(first_line_no "$LOG" "umount -R")
assert_eq "order: sfdisk before debootstrap" "1" "$(( L_SFDISK < L_DEBOOT ? 1 : 0 ))"
assert_eq "order: debootstrap before policy write" "1" "$(( L_DEBOOT > 0 && L_POLICY > 0 && L_DEBOOT < L_POLICY ? 1 : 0 ))"
assert_eq "order: keygen before enrollment" "1" "$(( L_KEYGEN < L_ENROLL ? 1 : 0 ))"
assert_eq "order: enrollment before ukictl build" "1" "$(( L_ENROLL < L_BUILD ? 1 : 0 ))"
assert_eq "order: build before keys_encrypt_release" "1" "$(( L_BUILD < L_ENCRYPT ? 1 : 0 ))"
assert_eq "order: keys_encrypt_release before teardown" "1" "$(( L_ENCRYPT < L_UMNTR ? 1 : 0 ))"
# G-IL8: NO installer-side signing machinery executed
assert_eq "zero sbsign/ukify/sbverify executions" "0" \
    "$(grep -Ec '^(sbsign|ukify|sbverify)' <<<"$LOG")"
# G-U7 (§8.3): boot-manager self-update masked
assert_eq "target: systemd-boot-update.service masked" "1" \
    "$([ -L "$MNT_ETC/systemd/system/systemd-boot-update.service" ] && [ "$(readlink "$MNT_ETC/systemd/system/systemd-boot-update.service")" = "/dev/null" ] && echo 1 || echo 0)"
# §9.1 step 7 / G-I2: flat hook templates installed executable
for d in postinst.d postrm.d; do
    assert_file_exists "target: kernel hook installed: $d/zz-debian-fde" "$MNT_ETC/kernel/$d/zz-debian-fde"
    assert_eq "target kernel hook executable: $d/zz-debian-fde" "1" "$([ -x "$MNT_ETC/kernel/$d/zz-debian-fde" ] && echo 1 || echo 0)"
done
assert_file_exists "target: boot-manager re-sign hook" "$MNT_ETC/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade"
assert_file_exists "target: initramfs post-update hook" "$MNT_ETC/initramfs/post-update.d/zz-debian-fde"

# =============================================================================
# H-02: binds (incl. the §9.1 efivars bind) run BEFORE guest steps and are
# torn down BEFORE `umount -R`; microcode resolved HOST-side.
# =============================================================================
assert_contains "H-02: /proc bound into the target" "$LOG" \
    "mount -t proc proc $DEBIAN_FDE_INSTALL_MNT/proc"
assert_contains "H-02: /sys bound into the target" "$LOG" \
    "mount --bind /sys $DEBIAN_FDE_INSTALL_MNT/sys"
assert_contains "H-02: /dev bound into the target" "$LOG" \
    "mount --bind /dev $DEBIAN_FDE_INSTALL_MNT/dev"
assert_contains "§9.1: efivars bound into the target" "$LOG" \
    "mount --bind /sys/firmware/efi/efivars $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
L_BINDT=$(first_line_no "$LOG" "mount --bind /dev")
L_BINDU=$(first_line_no "$LOG" "umount $DEBIAN_FDE_INSTALL_MNT/dev")
assert_eq "H-02: binds torn down before umount -R" "1" "$(( L_BINDT > 0 && L_BINDU > L_BINDT && L_UMNTR > L_BINDU ? 1 : 0 ))"
assert_contains "H-02: teardown umounts the efivars bind" "$LOG" \
    "umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
assert_not_contains "H-02: no in-chroot vendor detection left in the plan" "$OUT" \
    'grep -m1 vendor_id /proc/cpuinfo'
# L-04b: guest steps never see DEBIAN_FDE_DISK_PASSPHRASE
assert_contains "L-04b: chroot invocation strips the passphrase variable" \
    "$LOG" "-u DEBIAN_FDE_DISK_PASSPHRASE"

# =============================================================================
# G-ST3: RAID1 execution — per-role partitioning, per-member LUKS2, raid1
# mkfs, per-member crypttab with password-cache=yes, member_uuids metadata.
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
run_install --disk "$DISK2"
assert_eq "raid1 chroot install rc 0" "0" "$RC"
LOG2=$(cat "$DEBIAN_FDE_TEST_LOG")
assert_contains "raid1: primary partitioned (ESP + LUKS)" "$LOG2" "sfdisk $DISK"
assert_contains "raid1: secondary partitioned (root only)" "$LOG2" "sfdisk $DISK2"
assert_eq "raid1: secondary got NO ESP (single mkfs.vfat on primary p1)" "1" \
    "$(grep -c "^mkfs.vfat" <<<"$LOG2")"
assert_contains "raid1: ESP on primary p1" "$LOG2" "mkfs.vfat -F 32 -n EFI ${DISK}1"
assert_eq "raid1: exactly 2 per-member luksFormat records" "2" \
    "$(grep -c 'luksFormat --type luks2' <<<"$LOG2")"
assert_contains "raid1: mkfs.btrfs -d raid1 -m raid1 over both mappers" "$LOG2" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "raid1: primary opened as root1" "1" \
    "$(grep -Ec 'cryptsetup open .* root1$' <<<"$LOG2")"
assert_eq "raid1: secondary opened as root2" "1" \
    "$(grep -Ec 'cryptsetup open .* root2$' <<<"$LOG2")"
MEM1_UUID=$(grep -oE -- '--uuid [0-9a-f-]{36}' <<<"$LOG2" | sed -n 1p | awk '{print $2}')
MEM2_UUID=$(grep -oE -- '--uuid [0-9a-f-]{36}' <<<"$LOG2" | sed -n 2p | awk '{print $2}')
assert_eq "raid1: crypttab member entries verbatim (password-cache=yes on BOTH)" \
    "root1 UUID=$MEM1_UUID none luks,tpm2-device=auto,password-cache=yes,discard
root2 UUID=$MEM2_UUID none luks,tpm2-device=auto,password-cache=yes,discard" \
    "$(cat "$MNT_ETC/crypttab")"
assert_eq "raid1: baseline target.luks_uuid = PRIMARY member" "$MEM1_UUID" \
    "$(baseline_get_in "$MNT_ETC/debian-fde/baseline.json" target luks_uuid)"
assert_eq "raid1: baseline target.member_uuids (additive schema)" "$MEM1_UUID $MEM2_UUID" \
    "$(baseline_get_in "$MNT_ETC/debian-fde/baseline.json" target member_uuids)"
assert_contains "raid1: cmdline rootflags pins verbatim" "$(cat "$MNT_ETC/debian-fde/cmdline.txt")" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
L_CLOSE1=$(first_line_no "$LOG2" "cryptsetup close root1")
L_CLOSE2=$(first_line_no "$LOG2" "cryptsetup close root2")
assert_eq "raid1: teardown closes both members (primary first)" "1" \
    "$(( L_CLOSE1 > 0 && L_CLOSE2 > L_CLOSE1 ? 1 : 0 ))"

# =============================================================================
# G4/F-1 (§8.1/§3.3): the tooling copy into /opt/debian-fde ships ONLY the
# product script tree (bin/ lib/ hooks/ docs/) — NEVER VCS/harness residue.
# Residue is seeded in a THROWAWAY tree — never the real tests/ dirs.
# =============================================================================
DEBIAN_FDE_TREE=$T/tree
mkdir -p "$DEBIAN_FDE_TREE"
for d in bin lib hooks docs; do
    cp -r "$REPO/$d" "$DEBIAN_FDE_TREE/$d"
done
mkdir -p "$DEBIAN_FDE_TREE/.git/objects" "$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run" \
    "$DEBIAN_FDE_TREE/tests/.cache"
printf 'residue' >"$DEBIAN_FDE_TREE/.git/HEAD"
printf 'residue' >"$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run/marker"
truncate -s 20M "$DEBIAN_FDE_TREE/tests/.cache/blob-20M"

run_install_tree() { # TREE — run_install against a different tooling tree
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$(DEBIAN_FDE_CMD_DIR="$1/lib/cmd" "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
    RC=$?
}

run_install_tree "$DEBIAN_FDE_TREE"
assert_eq "tooling copy from seeded tree: rc 0" "0" "$RC"

OPT=$DEBIAN_FDE_INSTALL_MNT/opt/debian-fde
assert_file_exists "tooling copy: bin/debian-fde shipped" "$OPT/bin/debian-fde"
assert_file_exists "tooling copy: lib/ shipped" "$OPT/lib/cmd/install.sh"
assert_file_exists "tooling copy: hooks/ shipped" "$OPT/hooks/postinst.d-zz-debian-fde"
assert_file_exists "tooling copy: docs/ shipped" "$OPT/docs/Architecture.md"

RESIDUE=$(find "$OPT" \( -name '.git' -o -name 'tests' -o -name 'fixtures' \
    -o -name '*.cache*' -o -name '*.runs*' -o -name 'blob-20M' -o -name 'soak-run' \) | wc -l)
assert_eq "tooling copy: zero VCS/harness residue at any depth" "0" "$RESIDUE"
NODES=$(find "$OPT" \( -type b -o -type c \) | wc -l)
assert_eq "tooling copy: zero device nodes in target" "0" "$NODES"
COPY_LINE=$(grep -m1 'cp -r' <<<"$OUT")
assert_contains "tooling copy step: enumerates bin" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/bin"
assert_contains "tooling copy step: enumerates docs" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/docs"
assert_not_contains "tooling copy step: never the whole tree root" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE "

# =============================================================================
# G-I3 (§13/T2b): the entropy floor is enforced on the INTERACTIVE path too —
# no-echo prompt x2, passphrase_floor_ok, then a key-file for scripted
# luksFormat/open — before any destructive step.
# =============================================================================
run_install_stdin() { # STDIN_FILE — drive `install` with piped "prompts"
    : >"$DEBIAN_FDE_TEST_LOG"
    rm -rf "$DEBIAN_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" <"$1" 2>&1)
    RC=$?
}
unset DEBIAN_FDE_DISK_PASSPHRASE

printf 'weakpass\nweakpass\n' >"$T/pass-weak"
run_install_stdin "$T/pass-weak"
assert_eq "interactive weak passphrase -> rc 2" "2" "$RC"
assert_contains "interactive weak: floor error" "$OUT" "entropy floor"
assert_eq "interactive weak: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

printf 'short\nshort\n' >"$T/pass-short"
run_install_stdin "$T/pass-short"
assert_eq "interactive short passphrase -> rc 2" "2" "$RC"

printf 'Tr0ub4dor&extra-long\nother-passphrase-entirely\n' >"$T/pass-mismatch"
run_install_stdin "$T/pass-mismatch"
assert_eq "interactive passphrase mismatch -> rc 2" "2" "$RC"
assert_contains "interactive mismatch: error explains" "$OUT" "do not match"
assert_eq "interactive mismatch: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

printf 'correct-horse-battery-stapler-42\ncorrect-horse-battery-stapler-42\n' >"$T/pass-strong"
run_install_stdin "$T/pass-strong"
assert_eq "interactive strong passphrase -> rc 0" "0" "$RC"
assert_contains "interactive strong: luksFormat scripted via key-file (M-01: tmpfs seam)" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "--key-file $DEBIAN_FDE_TMPDIR/debian-fde-diskkey"
assert_not_contains "interactive passphrase never echoed into output" "$OUT" "correct-horse-battery-stapler-42"
assert_not_contains "interactive passphrase never logged by stubs" "$(cat "$DEBIAN_FDE_TEST_LOG")" "correct-horse-battery-stapler-42"

# env-passphrase weak case stays fail-closed with zero destructive commands
export DEBIAN_FDE_DISK_PASSPHRASE='weak'
run_install
assert_eq "env weak passphrase -> rc 2" "2" "$RC"
assert_eq "env weak: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
unset DEBIAN_FDE_DISK_PASSPHRASE

# =============================================================================
# M-02: operator-controlled values are validated at the boundary BEFORE any
# plan record exists; WR-01 covers the eval'd --keydir path.
# =============================================================================
export DEBIAN_FDE_INSTALL_USER='x; rm -rf /'
run_install
assert_eq "M-02: injected --user (env) -> usage rc 2" "2" "$RC"
assert_contains "M-02: error names the invalid user" "$OUT" "invalid --user"
assert_eq "M-02: injected --user: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
unset DEBIAN_FDE_INSTALL_USER
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --user 'x; rm -rf /' 2>&1)
RC=$?
assert_eq "M-02: injected --user (flag) -> usage rc 2" "2" "$RC"
OUT=$("$REPO/bin/debian-fde" install --disk '/dev/sda; reboot -f' 2>&1)
RC=$?
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$RC"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --bcache '/dev/nvme0n1; echo pwned' 2>&1)
RC=$?
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$RC"

: >"$DEBIAN_FDE_TEST_LOG"
rm -f /tmp/pwned
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --keydir '/x; touch /tmp/pwned' 2>&1)
RC=$?
assert_eq "WR-01: injected --keydir -> usage rc 2" "2" "$RC"
assert_contains "WR-01: error names DEBIAN_FDE_KEYDIR" "$OUT" "DEBIAN_FDE_KEYDIR"
assert_eq "WR-01: injected --keydir: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
assert_eq "WR-01: injected --keydir executed nothing (no /tmp/pwned)" "0" \
    "$([ -e /tmp/pwned ] && echo 1 || echo 0)"
rm -f /tmp/pwned
OUT=$(DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42' \
    "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1 </dev/null)
RC=$?
assert_eq "M-02: clean run still rc 0 (validation does not over-reject)" "0" "$RC"

# =============================================================================
# L-04a/WR-02: a failed plan step leaves NO temp files behind and the abort
# trap tears the binds down. The failing step is a LATE host record
# (fw_osindications_set, made failing via the efivars seam: the OsIndications
# target file is removed and the directory made unwritable) so the plan's own
# teardown never runs — the ONLY bind-umount line in the log is the trap's.
# =============================================================================
rm -f "$DEBIAN_FDE_EFIVARS_DIR/OsIndications-$GUID_GLOBAL"
chmod 555 "$DEBIAN_FDE_EFIVARS_DIR"
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
run_install
assert_eq "L-04a: failed host step -> fail-closed 64" "64" "$RC"
assert_contains "L-04a: the failing step is named" "$OUT" "cannot write"
assert_eq "L-04a: plan temp file scrubbed on failed step" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-plan.*' 2>/dev/null | wc -l)"
assert_eq "L-04a: passphrase key-file scrubbed on failed step" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-diskkey.*' 2>/dev/null | wc -l)"
assert_eq "WR-02 fixture: plan teardown never ran (die before teardown)" "0" \
    "$(grep -c 'umount -R' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "WR-02: abort trap tore the binds down (incl. efivars)" "1" \
    "$(grep -c "^umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars\$" "$DEBIAN_FDE_TEST_LOG")"
chmod 755 "$DEBIAN_FDE_EFIVARS_DIR"
unset DEBIAN_FDE_DISK_PASSPHRASE

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
