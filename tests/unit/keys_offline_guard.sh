#!/usr/bin/env bash
# tests/unit/keys_offline_guard.sh — I4/ADR-18 CUSTODY guard (docs/Architecture.md
# §9.1 steps 3+6, §11 I4, ADR-18; RESOLVED-1): the protected target root must
# never hold PLAINTEXT private key material. keys_offline_guard() classifies:
#   * keydir OUTSIDE the target root (offline medium)          -> 0 (any state)
#   * keydir INSIDE the root holding an ENCRYPTED release.pem  -> 0 (ADR-18)
#   * keydir INSIDE the root with plaintext private keys       -> 64 (fail closed)
#   * keydir INSIDE the root with no encrypted release.pem     -> 64 (the
#     pre-generation refusal: offline `provision stage1` must not create
#     plaintext keys under the root — generation there is the --mode in-chroot
#     ceremony's job, which encrypts before reboot)
#   * empty/unset KEYDIR -> 0 (callers check presence separately)
# Path matching is component-aware over the LONGEST EXISTING PREFIX of both
# paths, matched in raw AND normalized form (S-H1: a symlinked-root spelling
# must not bypass the guard, and the not-yet-created keydir is still caught).
#   * `provision stage1 --keydir <under-root>` fails 64 and NO key material
#     lands there (e2e, real handler; offline mode is the default)
#   * `install` preflight: keys_require + keys_offline_guard against the mount
#
# NOTE: with DEBIAN_FDE_ROOT unset the guard has no custody target and passes —
# presence is keys_check's job (the old literal-/etc/alpine-fde/keys pin is
# subsumed by the root-relative classification).

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

T=$(mktemp -d /tmp/debian-fde-keys-guard.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_ROOT=$T/root
mkdir -p "$T/root/etc/alpine-fde/keys" "$T/root/notkeys" "$T/usb/keys"

GUARD_PASS='ci-custody-passphrase-600000'
ENC_PEM=$T/release.encrypted.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
    -in "$REPO/fixtures/keys/release.pem" -passout pass:"$GUARD_PASS" \
    -out "$ENC_PEM" 2>/dev/null
[ -s "$ENC_PEM" ] || { echo "fixture: encrypted PEM build failed" >&2; exit 1; }

# guard_rc ARGS... — run keys_offline_guard in an inner subshell (die exits
# THAT subshell); the outer function still runs and prints the rc
guard_rc() {
    (keys_offline_guard "$@") >/dev/null 2>&1
    echo $?
}

# enc_rc FILE — keys_is_encrypted verdict from an inner subshell (rc 0/1)
enc_rc() { ( keys_is_encrypted "$1" ) >/dev/null 2>&1; echo $?; }

# =============================================================================
# RESOLVED-1: offline medium passes in ANY state; empty keydir is not a guard
# concern (caller checks presence)
# =============================================================================
assert_eq "guard: offline medium (empty keydir) -> 0" "0" "$(guard_rc "$T/usb/keys")"
cp "$REPO/fixtures/keys/release.pem" "$T/usb/keys/release.pem"
assert_eq "guard: offline medium with PLAINTEXT release.pem -> 0" "0" "$(guard_rc "$T/usb/keys")"
cp "$ENC_PEM" "$T/usb/keys/release.pem"
assert_eq "guard: offline medium with ENCRYPTED release.pem -> 0" "0" "$(guard_rc "$T/usb/keys")"
rm -f "$T/usb/keys/release.pem"
assert_eq "guard: empty keydir arg -> 0 (caller checks presence)" "0" "$(guard_rc '')"

# =============================================================================
# RESOLVED-1: inside the target root — empty/not-yet-created and plaintext are
# refused; the encrypted release.pem end state passes
# =============================================================================
assert_eq "guard: keydir IS target /etc/alpine-fde/keys (empty) -> 64" "64" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys")"
assert_eq "guard: keydir under target root (empty) -> 64" "64" \
    "$(guard_rc "$T/root/notkeys")"
assert_eq "guard: keydir == target root itself -> 64" "64" \
    "$(guard_rc "$T/root")"

cp "$REPO/fixtures/keys/release.pem" "$T/root/notkeys/release.pem"
G_OUT=$( (keys_offline_guard "$T/root/notkeys") 2>&1 )
assert_eq "guard: PLAINTEXT release.pem inside root -> 64" "64" "$(guard_rc "$T/root/notkeys")"
assert_contains "guard: plaintext message names the violation (PLAINTEXT + ADR-18)" "$G_OUT" "PLAINTEXT"
assert_contains "guard: plaintext message cites ADR-18" "$G_OUT" "ADR-18"

cp "$REPO/fixtures/keys/release.pem" "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.priv.pem"
assert_eq "guard: stale plaintext release.priv.pem inside root -> 64" "64" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys")"
cp "$REPO/fixtures/keys/release.pem" "$T/root/notkeys/pk.priv.pem"
assert_eq "guard: stale plaintext pk.priv.pem inside root -> 64" "64" \
    "$(guard_rc "$T/root/notkeys")"
rm -f "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.priv.pem" "$T/root/notkeys/pk.priv.pem"

cp "$ENC_PEM" "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.pem"
cp "$REPO/fixtures/keys/release.crt" "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.crt"
cp "$REPO/fixtures/keys/release.pub" "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.pub"
assert_eq "guard: ENCRYPTED release.pem inside root (ADR-18 end state) -> 0" "0" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys")"
cp "$REPO/fixtures/keys/release.pem" "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/pk.priv.pem"
assert_eq "guard: encrypted release.pem + STALE plaintext pk.priv.pem -> 64" "64" \
    "$(guard_rc "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys")"
rm -f "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/pk.priv.pem"
rm -f "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.pem" \
    "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.crt" \
    "$DEBIAN_FDE_ROOT/etc/alpine-fde/keys/release.pub"

cp "$ENC_PEM" "$T/usb/keys/release.pem"
assert_eq "guard: offline medium, ENCRYPTED release.pem, -> 0 (any state ok offline)" "0" \
    "$(guard_rc "$T/usb/keys")"
rm -f "$T/usb/keys/release.pem"

# component-aware: /etc/alpine-fde/keys-backup is NOT /etc/alpine-fde/keys
assert_eq "guard: lookalike sibling dir (empty, under root) -> 64 (under-root rule)" "64" \
    "$(guard_rc "$T/root/etc/alpine-fde/keys-backup")"

# =============================================================================
# S-H1: symlinked-root spelling + NOT-YET-EXISTING keydir (the normal
# `provision stage1` shape — stage1 creates the keydir). readlink -f fails on
# the missing leaf, so the guard must normalize the LONGEST EXISTING prefix of
# BOTH paths and compare the keydir against the root in raw AND normalized form.
# A not-yet-existing keydir under the root holds no encrypted release.pem —
# refused (offline stage1 must not generate there).
# =============================================================================
ln -s "$DEBIAN_FDE_ROOT" "$T/rootlink"
assert_eq "guard S-H1: symlinked root, keydir not yet existing -> 64" "64" \
    "$(guard_rc "$T/rootlink/newdir/keys")"
assert_eq "guard S-H1: symlinked root, /etc/alpine-fde/keys not yet existing -> 64" "64" \
    "$(guard_rc "$T/rootlink/etc/alpine-fde/keys")"
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
# G-B7: provision stage1 e2e (default = OFFLINE mode) — keydir under the target
# root fails 64, no key material lands there; the offline medium still works
# and keeps the plaintext release.pem (offline semantics unchanged, ADR-18)
# =============================================================================
G_RC=$("$REPO/bin/debian-fde" provision stage1 --keydir "$T/root/etc/alpine-fde/keys" 2>&1; echo "RC=$?")
assert_eq "stage1: keydir under target root -> 64" "64" "$(printf '%s' "$G_RC" | sed -n 's/^RC=//p')"
assert_eq "stage1: no release.pem landed under root" "0" \
    "$([ -e "$T/root/etc/alpine-fde/keys/release.pem" ] && echo 1 || echo 0)"
assert_eq "stage1: no release.priv.pem landed under root" "0" \
    "$([ -e "$T/root/etc/alpine-fde/keys/release.priv.pem" ] && echo 1 || echo 0)"

assert_rc "stage1: keydir on the offline medium -> 0" 0 \
    "$REPO/bin/debian-fde" provision stage1 --keydir "$T/usb/keys"
assert_eq "stage1: release.pem landed on the medium" "1" \
    "$([ -f "$T/usb/keys/release.pem" ] && echo 1 || echo 0)"
assert_eq "stage1 offline: release.pem stays PLAINTEXT on the medium (default mode unchanged)" "1" \
    "$(enc_rc "$T/usb/keys/release.pem")"

# =============================================================================
# Install-side wiring note (coordination): lib/cmd/install.sh is being reworked
# concurrently (Wave 2 in-chroot flow) and no longer calls keys_offline_guard
# from inst_preflight as of this writing — its re-wiring is pinned by THAT
# wave's tests (install_chroot_plan / install_dryrun). The GUARD CONTRACT it
# must honor is pinned here at function level, including the explicit
# TARGET_ROOT call form (guard KEYDIR MOUNTPOINT) the installer used:
# =============================================================================
assert_eq "guard: explicit mount form — keydir under the mount -> 64" "64" \
    "$(guard_rc "$T/root/notkeys" "$T/root")"
cp "$ENC_PEM" "$T/root/notkeys/release.pem"
assert_eq "guard: explicit mount form — ENCRYPTED release.pem under the mount -> 0 (ADR-18)" "0" \
    "$(guard_rc "$T/root/notkeys" "$T/root")"
cp "$REPO/fixtures/keys/release.pem" "$T/root/notkeys/release.pem"
M_OUT=$( (keys_offline_guard "$T/root/notkeys" "$T/root") 2>&1 )
assert_eq "guard: explicit mount form — PLAINTEXT release.pem under the mount -> 64" "64" \
    "$(guard_rc "$T/root/notkeys" "$T/root")"
assert_contains "guard: mount-form refusal cites the custody rule" "$M_OUT" "PLAINTEXT"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
