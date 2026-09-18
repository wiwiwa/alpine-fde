#!/usr/bin/env bash
# tests/unit/install_osindications.sh — §9.1 teardown contract: the installer
# sets OsIndications bit 0 (fw_osindications_set, lib/firmware.sh) so the next
# boot enters BIOS setup — strictly AFTER the ceremony state write
# (`installed`) and BEFORE the teardown/reboot; the reboot record itself is
# suppressed by the DEBIAN_FDE_INSTALL_NO_REBOOT=1 / --no-reboot CI seam.
# Variable-file mechanics live in nvram_auth_enroll.sh; chroot execution (the
# real variable write) in install_chroot_plan.sh — this file pins the PLAN
# level: order, lanes (host/guest), and the seam across topologies.

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

T=$(mktemp -d /tmp/debian-fde-install-osind.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_HOOKS_DIR=$T/hooks   # dry-run must not require the real hooks tree

DISK=$T/disk.img
: >"$DISK"

line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

# =============================================================================
# Single-disk dry-run: order state write -> OsIndications -> teardown
# =============================================================================
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
RC=$?
assert_eq "dry-run rc 0" "0" "$RC"
assert_eq "exactly ONE OsIndications record" "1" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_OSIND=$(line_no "$OUT" "fw_osindications_set")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
I_REBOOT=$(line_no "$OUT" "reboot #")
assert_eq "order: state write BEFORE OsIndications" "1" "$(( I_STATE > 0 && I_OSIND > I_STATE ? 1 : 0 ))"
assert_eq "order: OsIndications BEFORE teardown" "1" "$(( I_UMOUNT > 0 && I_OSIND < I_UMOUNT ? 1 : 0 ))"
assert_eq "order: teardown BEFORE reboot" "1" "$(( I_REBOOT > 0 && I_UMOUNT < I_REBOOT ? 1 : 0 ))"
assert_eq "OsIndications record is a HOST step (live firmware NVRAM)" "1" \
    "$(grep -cE '^PLAN  host +fw_osindications_set' <<<"$OUT")"
assert_contains "teardown umounts the efivars bind" "$OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"

# =============================================================================
# NO_REBOOT seams (env + flag)
# =============================================================================
OUT=$(DEBIAN_FDE_INSTALL_NO_REBOOT=1 "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
assert_eq "NO_REBOOT=1: rc 0" "0" "$?"
assert_eq "NO_REBOOT=1: no reboot record" "0" "$(grep -c 'reboot #' <<<"$OUT")"
assert_eq "NO_REBOOT=1: OsIndications still set (harness reboots itself)" "1" \
    "$(grep -c 'fw_osindications_set' <<<"$OUT")"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --no-reboot 2>&1)
assert_eq "--no-reboot: rc 0" "0" "$?"
assert_eq "--no-reboot: no reboot record" "0" "$(grep -c 'reboot #' <<<"$OUT")"

# =============================================================================
# Topology invariance: RAID1 and bcache plans keep the same ceremony tail
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --disk "$DISK2" 2>&1)
assert_eq "raid1 dry-run rc 0" "0" "$?"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_OSIND=$(line_no "$OUT" "fw_osindications_set")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
assert_eq "raid1: state write BEFORE OsIndications" "1" "$(( I_STATE > 0 && I_OSIND > I_STATE ? 1 : 0 ))"
assert_eq "raid1: OsIndications BEFORE teardown" "1" "$(( I_UMOUNT > 0 && I_OSIND < I_UMOUNT ? 1 : 0 ))"

CACHE=$T/cache.img
: >"$CACHE"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --bcache "$CACHE" 2>&1)
assert_eq "bcache dry-run rc 0" "0" "$?"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_OSIND=$(line_no "$OUT" "fw_osindications_set")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
assert_eq "bcache: state write BEFORE OsIndications" "1" "$(( I_STATE > 0 && I_OSIND > I_STATE ? 1 : 0 ))"
assert_eq "bcache: OsIndications BEFORE teardown" "1" "$(( I_UMOUNT > 0 && I_OSIND < I_UMOUNT ? 1 : 0 ))"

# =============================================================================
# qemu lane: the OsIndications write is a HOST comment (the CI guest runs it)
# =============================================================================
export DEBIAN_FDE_INSTALL_RUNNER=qemu
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T
export DEBIAN_FDE_INSTALL_SCRIPT=$T/guest.sh
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
export DEBIAN_FDE_INSTALL_NO_REBOOT=1
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars
mkdir -p "$T/stub" "$T/hooks" "$T/efivars" "$T/root"
make_stub() {
    printf '#!/bin/sh\nexit 0\n' >"$T/stub/$1"
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount debootstrap chroot \
    apt-get useradd usermod passwd systemctl bootctl lsblk btrfs cryptsetup; do
    make_stub "$s"
done
printf '#!/bin/sh\nprintf "0\\n"\n' >"$T/stub/id"
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"
for h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done
printf '\007\000\000\000\001' >"$T/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
assert_eq "qemu emit rc 0" "0" "$?"
SCRIPT=$DEBIAN_FDE_INSTALL_SCRIPT
assert_eq "qemu: OsIndications is a host comment" "1" \
    "$(grep -c '^# HOST: fw_osindications_set' "$SCRIPT")"
assert_eq "qemu: OsIndications is NOT an executable guest line" "0" \
    "$(grep -c '^fw_osindications_set' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
