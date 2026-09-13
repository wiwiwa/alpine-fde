#!/usr/bin/env bash
# tests/unit/keys_offline_guard.sh — I4 custody guard (docs/Architecture.md
# §6 PCR7 note, §11 I4, §8.4): release/enrollment PRIVATE keys must never be
# written inside the protected machine's root or its /etc/debian-fde/keys dir.
#   * keys_offline_guard() fails closed (64) when the keydir resolves inside
#     the target root (or IS the target's /etc/debian-fde/keys), passes when
#     the keydir is a separate offline medium
#   * `provision stage1 --keydir <under-root>` fails 64 and NO key material
#     lands there (e2e, real handler)
#   * `install` preflight replaces its inline key checks with
#     keys_require + keys_offline_guard against the install mountpoint

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
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/debian-fde-keys-guard.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_INSTALL_MNT=$T/root   # install's target root for the guard
mkdir -p "$T/root/etc/debian-fde/keys" "$T/root/notkeys" "$T/usb/keys"

# guard_rc ARGS... — run keys_offline_guard in an inner subshell (die exits
# THAT subshell); the outer function still runs and prints the rc
guard_rc() {
    (keys_offline_guard "$@") >/dev/null 2>&1
    echo $?
}

# =============================================================================
# G-B7: keys_offline_guard (lib/keys.sh)
# =============================================================================
assert_eq "guard: keydir IS target /etc/debian-fde/keys -> 64" "64" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/etc/debian-fde/keys")"
assert_eq "guard: keydir under target root -> 64" "64" \
    "$(guard_rc "$T/root/notkeys")"
assert_eq "guard: keydir == target root itself -> 64" "64" \
    "$(guard_rc "$T/root")"
assert_eq "guard: keydir on separate medium -> 0" "0" \
    "$(guard_rc "$T/usb/keys")"
assert_eq "guard: empty keydir -> 0 (caller checks presence)" "0" "$(guard_rc '')"
# component-aware: /etc/debian-fde/keys-backup is NOT /etc/debian-fde/keys
DEBIAN_FDE_ROOT='' assert_eq "guard: no root, keydir == /etc/debian-fde/keys -> 64" "64" \
    "$(DEBIAN_FDE_ROOT= guard_rc /etc/debian-fde/keys)"
assert_eq "guard: no root, lookalike sibling dir -> 0" "0" \
    "$(DEBIAN_FDE_ROOT= guard_rc /etc/debian-fde/keys-backup)"

# =============================================================================
# S-H1: symlinked-root spelling + NOT-YET-EXISTING keydir (the normal
# `provision stage1` shape — stage1 creates the keydir). readlink -f fails on
# the missing leaf, so the guard must normalize the LONGEST EXISTING prefix of
# BOTH paths and compare the keydir against the root in raw AND normalized form.
# =============================================================================
ln -s "$DEBIAN_FDE_ROOT" "$T/rootlink"
assert_eq "guard S-H1: symlinked root, keydir not yet existing -> 64" "64" \
    "$(guard_rc "$T/rootlink/newdir/keys")"
assert_eq "guard S-H1: symlinked root, /etc/debian-fde/keys not yet existing -> 64" "64" \
    "$(guard_rc "$T/rootlink/etc/debian-fde/keys")"
assert_eq "guard S-H1: canonical spelling, keydir not yet existing -> 64" "64" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/newdir2/keys")"
assert_eq "guard S-H1: symlinked root, existing keydir under it -> 64" "64" \
    "$(guard_rc "$T/rootlink/notkeys")"
assert_eq "guard S-H1: relative keydir spelled through the symlink -> 64" "64" \
    "$(cd "$T" && guard_rc "rootlink/reldir/keys")"
ln -s "$T/usb" "$T/usblink"
assert_eq "guard S-H1: offline medium through a symlink spelling -> 0" "0" \
    "$(cd "$T" && guard_rc "usblink/keys")"

# =============================================================================
# G-B7: provision stage1 e2e — keydir under the target root fails 64, no
# release.pem lands there
# =============================================================================
G_RC=$("$REPO/bin/debian-fde" provision stage1 --keydir "$T/root/etc/debian-fde/keys" 2>&1; echo "RC=$?")
assert_eq "stage1: keydir under target root -> 64" "64" "$(printf '%s' "$G_RC" | sed -n 's/^RC=//p')"
assert_contains "stage1: error names custody (I4)" "$G_RC" "I4"
assert_eq "stage1: no release.pem landed under root" "0" \
    "$([ -e "$T/root/etc/debian-fde/keys/release.pem" ] && echo 1 || echo 0)"
assert_eq "stage1: no release.priv.pem landed under root" "0" \
    "$([ -e "$T/root/etc/debian-fde/keys/release.priv.pem" ] && echo 1 || echo 0)"

# and the sane path still works: keydir on the (simulated) offline medium
assert_rc "stage1: keydir outside target root -> 0" 0 \
    "$REPO/bin/debian-fde" provision stage1 --keydir "$T/usb/keys"
assert_eq "stage1: release.pem landed on the medium" "1" \
    "$([ -f "$T/usb/keys/release.pem" ] && echo 1 || echo 0)"

# =============================================================================
# G-B7: install preflight — keys_require + keys_offline_guard against the
# install mountpoint (inline duplication deleted)
# =============================================================================
mkdir -p "$T/stub" "$T/hooks"
printf '#!/bin/sh\necho 0\n' >"$T/stub/id"
chmod +x "$T/stub/id"
# preflight checks flat hook templates + required binaries after the keydir —
# fixture both so a passing keydir reaches rc 0
for h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    : >"$T/hooks/$h"
done
for b in sfdisk cryptsetup mkfs.ext4 mkfs.vfat debootstrap sbsign lsblk; do
    printf '#!/bin/sh\nexit 0\n' >"$T/stub/$b"
    chmod +x "$T/stub/$b"
done
export PATH="$T/stub:$PATH"
export DEBIAN_FDE_HOOKS_DIR=$T/hooks

DISK=$T/disk.img
: >"$DISK"
BL='1111111111111111111111111111111111111111111111111111111111111111'
BL_CREATED_AT='2026-09-17T00:00:00Z' BL_PCR0="$BL" BL_PCR1="$BL" \
    BL_PCR2="$BL" BL_PCR3="$BL" BL_PCR7='pending' \
    baseline_write "$(sp_baseline_file)"

# function-level preflight checks (die inside the inner subshell yields rc)
inst_preflight_rc() { # KEYDIR
    (DEBIAN_FDE_KEYDIR=$1 inst_preflight "$DISK") >/dev/null 2>&1
    echo $?
}
mkdir -p "$T/root/under-mnt"
for f in release.pem release.pub release.crt; do
    : >"$T/root/under-mnt/$f"
    : >"$T/usb/keys/$f"
done

assert_eq "install preflight: keydir under mountpoint -> 64" "64" "$(inst_preflight_rc "$T/root/under-mnt")"
rm -f "$T/usb/keys/release.pub"
assert_eq "install preflight: missing key material -> 64 (keys_require)" "64" "$(inst_preflight_rc "$T/usb/keys")"
PF_OUT=$( (DEBIAN_FDE_KEYDIR=$T/usb/keys inst_preflight "$DISK") 2>&1 )
assert_contains "install preflight: missing material message from keys.sh" "$PF_OUT" "release key material incomplete"
: >"$T/usb/keys/release.pub"
assert_eq "install preflight: valid offline keydir passes" "0" "$(inst_preflight_rc "$T/usb/keys")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
