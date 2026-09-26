#!/usr/bin/env bash
# tests/unit/install_osindications.sh — G-C26 (docs/Architecture.md §9.1
# Teardown & Direct Reboot; ADR-20 AMENDED by the user's flow directives):
# the OsIndications firmware trip is BACK — but ONLY on the DEFERRED-
# enrollment path, as a RUNTIME-CONDITIONAL tail record: the plan probes PK
# on the LIVE efivars at execution time and only when the firmware refused
# NVRAM enrollment does it print the manual-import instructions, take an
# explicit Enter confirmation, and reboot INTO FIRMWARE SETUP
# (fw_osindications_set, bit 0). The enrolled path keeps the PLAIN direct
# reboot to disk. The trip record appears exactly ONCE per plan, always
# guarded by the runtime verdict — never an unconditional generate-time
# write. Order pinned across topologies and both lanes:
#   state `installed` -> teardown -> scrub -> verdict probe ->
#   deferred instructions -> [Enter confirm -> firmware trip |
#   direct reboot]  (confirm/trip/reboot suppressed by the
#   ALPINE_FDE_INSTALL_NO_REBOOT=1 / --no-reboot CI seam).
# Variable-file mechanics live in nvram_auth_enroll.sh; chroot execution in
# install_chroot_plan.sh — this file pins the PLAN level: lanes (host/guest),
# order, and the topology invariance of the deferred trip.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-install-osind.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_HOOKS_DIR=$T/hooks   # dry-run must not require the real hooks tree
# The runner DEFAULT is chroot (real execution — the product); this file pins
# the PLAN level (lanes/order/topology), so every early lane is pinned to
# dry-run explicitly. The qemu lane below re-exports its own runner.
export ALPINE_FDE_INSTALL_RUNNER=dry-run

DISK=$T/disk.img
: >"$DISK"

line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

# =============================================================================
# Single-disk dry-run: the DEFERRED trip tail; state -> teardown -> scrub ->
# verdict probe -> instructions -> confirm -> firmware trip | direct reboot
# =============================================================================
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1)
RC=$?
assert_eq "dry-run rc 0" "0" "$RC"
assert_eq "G-C26: exactly ONE OsIndications trip record (single)" "1" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
assert_eq "G-C26: the trip record is RUNTIME-CONDITIONAL (else-branch of the live-PK verdict)" "1" \
    "$(grep -c 'else fw_osindications_set' <<<"$OUT")"
assert_eq "G-C26: the trip record names the firmware-setup boot (OsIndications bit 0)" "1" \
    "$(grep -c 'enters firmware setup (OsIndications bit 0)' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt && cryptsetup close")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
I_PROBE=$(line_no "$OUT" "if fw_var_present")
I_INSTR=$(line_no "$OUT" "Secure Boot key material is staged under")
I_CONFIRM=$(line_no "$OUT" "press Enter to reboot into firmware setup")
I_TRIP=$(line_no "$OUT" "fw_osindications_set")
I_DIRECT=$(line_no "$OUT" "direct reboot to disk (NVRAM enrollment succeeded")
assert_eq "order: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "order: teardown BEFORE the ephemeral-key scrub (I1)" "1" \
    "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"
assert_eq "order: scrub BEFORE the enrollment verdict probe (the tail is post-teardown)" "1" \
    "$(( I_SCRUB > 0 && I_SCRUB < I_PROBE ? 1 : 0 ))"
assert_eq "order: verdict probe BEFORE the deferred instructions (instructions LAST, user directive 3)" "1" \
    "$(( I_PROBE > 0 && I_PROBE < I_INSTR ? 1 : 0 ))"
assert_eq "order: instructions BEFORE the Enter confirmation BEFORE the firmware trip" "1" \
    "$(( I_INSTR > 0 && I_INSTR < I_CONFIRM && I_CONFIRM < I_TRIP ? 1 : 0 ))"
assert_eq "order: the firmware trip BEFORE the enrolled direct reboot (both runtime-conditional tails)" "1" \
    "$(( I_TRIP > 0 && I_TRIP < I_DIRECT ? 1 : 0 ))"
assert_eq "scrub record is a HOST step (the staged key lives host-side, I1)" "1" \
    "$(grep -cE '^PLAN  host +rm -f <ephemeral-keyfile>' <<<"$OUT")"
assert_contains "enrolled path keeps a PLAIN direct reboot to disk (ADR-20)" "$OUT" \
    "direct reboot to disk (NVRAM enrollment succeeded, ADR-20)"
assert_contains "teardown umounts the efivars bind" "$OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"

# =============================================================================
# NO_REBOOT seams (env + flag): the confirm + firmware trip + direct reboot
# are suppressed; the verdict probe, the deferred instructions and the scrub
# are NOT (the harness reboots itself)
# =============================================================================
OUT=$(ALPINE_FDE_INSTALL_NO_REBOOT=1 "$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1)
assert_eq "NO_REBOOT=1: rc 0" "0" "$?"
assert_eq "NO_REBOOT=1: NO OsIndications trip record (CI seam)" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
assert_eq "NO_REBOOT=1: NO Enter-confirmation record (CI seam)" "0" \
    "$(grep -c 'press Enter to reboot into firmware setup' <<<"$OUT")"
assert_eq "NO_REBOOT=1: NO direct-reboot record (CI seam)" "0" \
    "$(grep -c 'then reboot' <<<"$OUT")"
assert_eq "NO_REBOOT=1: the deferred instructions still print (CI seam suppresses only the reboots)" "1" \
    "$(grep -c 'Secure Boot key material is staged under' <<<"$OUT")"
assert_eq "NO_REBOOT=1: ephemeral-key scrub still present (harness reboots itself)" "1" \
    "$(grep -c 'rm -f <ephemeral-keyfile>' <<<"$OUT")"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --no-reboot 2>&1)
assert_eq "--no-reboot: rc 0" "0" "$?"
assert_eq "--no-reboot: NO OsIndications trip record (CI seam)" "0" "$(grep -c 'fw_osindications_set' <<<"$OUT")"
assert_eq "--no-reboot: NO reboot records at all (CI seam)" "0" "$(grep -c 'then reboot' <<<"$OUT")"

# =============================================================================
# Topology invariance: RAID1 and both bcache topologies keep the same tail
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --disk "$DISK2" 2>&1)
assert_eq "raid1 dry-run rc 0" "0" "$?"
assert_eq "raid1: exactly ONE runtime-conditional OsIndications record" "1" "$(grep -c 'else fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt && cryptsetup close")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "raid1: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "raid1: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"

CACHE=$T/cache.img
: >"$CACHE"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --bcache "$CACHE" 2>&1)
assert_eq "bcache dry-run rc 0" "0" "$?"
assert_eq "bcache: exactly ONE runtime-conditional OsIndications record" "1" "$(grep -c 'else fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt && cryptsetup close")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "bcache: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "bcache: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"

DISKB=$T/diskb.img
: >"$DISKB"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --disk "$DISKB" --bcache "$CACHE" 2>&1)
assert_eq "bcache-multi dry-run rc 0" "0" "$?"
assert_eq "bcache-multi: exactly ONE runtime-conditional OsIndications record" "1" "$(grep -c 'else fw_osindications_set' <<<"$OUT")"
I_STATE=$(line_no "$OUT" "inst_state_write installed")
I_UMOUNT=$(line_no "$OUT" "umount -R /mnt && cryptsetup close")
I_SCRUB=$(line_no "$OUT" "rm -f <ephemeral-keyfile>")
assert_eq "bcache-multi: state write BEFORE teardown" "1" "$(( I_STATE > 0 && I_UMOUNT > I_STATE ? 1 : 0 ))"
assert_eq "bcache-multi: teardown BEFORE the scrub" "1" "$(( I_UMOUNT > 0 && I_SCRUB > I_UMOUNT ? 1 : 0 ))"
assert_contains "bcache-multi: teardown closes every member container" "$OUT" \
    "cryptsetup close root1 && cryptsetup close root2"

# =============================================================================
# qemu lane: the scrub is a HOST comment; the emitted script (CI seam
# NO_REBOOT=1) carries NO OsIndications trip, NO Enter confirmation and NO
# reboot record — the deferred tail's rebooting legs are seam-suppressed
# =============================================================================
export ALPINE_FDE_INSTALL_RUNNER=qemu
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T
export ALPINE_FDE_INSTALL_SCRIPT=$T/guest.sh
export ALPINE_FDE_INSTALL_NO_REBOOT=1
export ALPINE_FDE_EFIVARS_DIR=$T/efivars
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
mkdir -p "$ALPINE_FDE_HOOKS_DIR/kernel-hooks.d" "$ALPINE_FDE_HOOKS_DIR/mkinitfs/features.d" \
    "$ALPINE_FDE_HOOKS_DIR/apk/triggers" "$ALPINE_FDE_HOOKS_DIR/openrc"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    printf '#!/bin/sh\nexit 0\n' >"$ALPINE_FDE_HOOKS_DIR/$h"
    chmod +x "$ALPINE_FDE_HOOKS_DIR/$h"
done
printf '\007\000\000\000\001' >"$T/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1)
assert_eq "qemu emit rc 0" "0" "$?"
SCRIPT=$ALPINE_FDE_INSTALL_SCRIPT
assert_eq "qemu: ZERO OsIndications records (both lanes)" "0" \
    "$(grep -c 'fw_osindications_set' "$SCRIPT")"
assert_eq "qemu: ephemeral-key scrub is a host comment" "1" \
    "$(grep -c '^# HOST: rm -f .*alpine-fde-ephkey' "$SCRIPT")"
assert_eq "qemu: no reboot record (CI seam)" "0" "$(grep -c '^# HOST: reboot' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
