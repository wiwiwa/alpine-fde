#!/usr/bin/env bash
# tests/unit/install_osindications.sh — G-C26 (docs/Architecture.md §9.1
# Teardown & Direct Reboot; ADR-20): the firmware-trip flow is RETIRED. The
# OsIndications bit-0 write (fw_osindications_set) and the
# reboot-into-BIOS-setup step must NEVER appear in any plan or emitted
# script; Stage 1 ends with teardown (unmount + container close), the
# explicit ephemeral-key scrub (I1 — G-C23), and a PLAIN direct reboot to
# disk. Order pinned across topologies and both lanes:
#   state `installed` -> teardown -> scrub -> reboot (suppressed by the
#   DEBIAN_FDE_INSTALL_NO_REBOOT=1 / --no-reboot CI seam).
# Variable-file mechanics live in nvram_auth_enroll.sh; chroot execution in
# install_chroot_plan.sh — this file pins the PLAN level: lanes (host/guest),
# order, and the topology invariance of the retired trip.

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
# Single-disk dry-run: NO OsIndications; state -> teardown -> scrub -> reboot
# =============================================================================
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
RC=$?
assert_eq "dry-run rc 0" "0" "$RC"
assert_eq "G-C26: ZERO OsIndications records (single)" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
assert_eq "G-C26: NO reboot-to-BIOS-setup comment (retired)" "0" \
    "$(grep -c 'BIOS setup' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
I_REBOOT=$(line_no "$OUT" "reboot #")
assert_eq "order: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "order: teardown BEFORE the ephemeral-key scrub (I1)" "1" \
    "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"
assert_eq "order: scrub BEFORE the direct reboot" "1" "$(( I_REBOOT > 0 && I_SCRUB < I_REBOOT ? 1 : 0 ))"
assert_eq "scrub record is a HOST step (the staged key lives host-side, I1)" "1" \
    "$(grep -cE '^PLAN  host +rm -f <ephemeral-keyfile>' <<<"$OUT")"
assert_contains "reboot record is a PLAIN direct reboot (no firmware trip)" "$OUT" \
    "reboot # §9.1: direct reboot to disk (ADR-20)"
assert_contains "teardown umounts the efivars bind" "$OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"

# =============================================================================
# NO_REBOOT seams (env + flag): the reboot record is suppressed, the scrub isn't
# =============================================================================
OUT=$(DEBIAN_FDE_INSTALL_NO_REBOOT=1 "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
assert_eq "NO_REBOOT=1: rc 0" "0" "$?"
assert_eq "NO_REBOOT=1: no reboot record" "0" "$(grep -c 'reboot #' <<<"$OUT")"
assert_eq "NO_REBOOT=1: ephemeral-key scrub still present (harness reboots itself)" "1" \
    "$(grep -c 'rm -f <ephemeral-keyfile>' <<<"$OUT")"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --no-reboot 2>&1)
assert_eq "--no-reboot: rc 0" "0" "$?"
assert_eq "--no-reboot: no reboot record" "0" "$(grep -c 'reboot #' <<<"$OUT")"

# =============================================================================
# Topology invariance: RAID1 and both bcache topologies keep the same tail
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --disk "$DISK2" 2>&1)
assert_eq "raid1 dry-run rc 0" "0" "$?"
assert_eq "raid1: ZERO OsIndications records" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "raid1: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "raid1: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"

CACHE=$T/cache.img
: >"$CACHE"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --bcache "$CACHE" 2>&1)
assert_eq "bcache dry-run rc 0" "0" "$?"
assert_eq "bcache: ZERO OsIndications records" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "bcache: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "bcache: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"

DISKB=$T/diskb.img
: >"$DISKB"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --disk "$DISKB" --bcache "$CACHE" 2>&1)
assert_eq "bcache-multi dry-run rc 0" "0" "$?"
assert_eq "bcache-multi: ZERO OsIndications records" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "bcache-multi: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "bcache-multi: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"
assert_contains "bcache-multi: teardown closes every member container" "$OUT" \
    "cryptsetup close root1 && cryptsetup close root2"

# =============================================================================
# qemu lane: the scrub is a HOST comment; no OsIndications anywhere in the
# emitted script (neither lane carries the retired firmware trip)
# =============================================================================
export DEBIAN_FDE_INSTALL_RUNNER=qemu
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T
export DEBIAN_FDE_INSTALL_SCRIPT=$T/guest.sh
export DEBIAN_FDE_INSTALL_NO_REBOOT=1
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars
mkdir -p "$T/stub" "$T/hooks" "$T/efivars" "$T/root"
make_stub() {
    printf '#!/bin/sh\nexit 0\n' >"$T/stub/$1"
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount apk adduser addgroup rc-update \
    bootctl lsblk btrfs cryptsetup; do
    make_stub "$s"
done
printf '#!/bin/sh\ncase " $* " in *" rand "*) printf "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";; esac\nexit 0\n' >"$T/stub/openssl"
chmod +x "$T/stub/openssl"
printf '#!/bin/sh\nprintf "0\\n"\n' >"$T/stub/id"
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"
mkdir -p "$DEBIAN_FDE_HOOKS_DIR/kernel-hooks.d" "$DEBIAN_FDE_HOOKS_DIR/mkinitfs/features.d" \
    "$DEBIAN_FDE_HOOKS_DIR/apk/triggers" "$DEBIAN_FDE_HOOKS_DIR/openrc"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done
printf '\007\000\000\000\001' >"$T/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
assert_eq "qemu emit rc 0" "0" "$?"
SCRIPT=$DEBIAN_FDE_INSTALL_SCRIPT
assert_eq "qemu: ZERO OsIndications records (both lanes)" "0" \
    "$(grep -c 'fw_osindications_set' "$SCRIPT")"
assert_eq "qemu: ephemeral-key scrub is a host comment" "1" \
    "$(grep -c '^# HOST: rm -f .*debian-fde-ephkey' "$SCRIPT")"
assert_eq "qemu: no reboot record (CI seam)" "0" "$(grep -c '^# HOST: reboot' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
