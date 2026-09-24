#!/usr/bin/env bash
# tests/unit/boot_manager_resign_guard.sh — boot-manager re-sign guard
# (docs/Architecture.md §8.3, §11, ADR-8): after a successful ukictl build the
# kernel hook hooks/kernel-hooks.d/alpine-fde-build.hook re-signs the boot
# manager binaries a systemd-boot refresh may have re-flashed
# (ESP:/EFI/systemd/systemd-bootx64.efi and /EFI/BOOT/BOOTX64.EFI). The test
# drives the REAL hook through its kernel-hooks.d convention
# (`alpine-fde-build.hook add <kver>`) with a recording `alpine-fde` stub on
# the ALPINE_FDE_BIN seam (the ukictl build step succeeds) plus PATH-stubbed
# sbsign/sbverify, and asserts OBSERVED effects: exact argv, ESP paths,
# verify-FIRST idempotence (review LO-05: sbsign appends signatures —
# re-signing an already-signed binary stacks a dual signature, the
# §9.6/s16 revocation failure mode), sbverify-gated install, fail-closed 64 +
# build-failed marker under $ROOT/etc/alpine-fde when the key is missing or a
# binary fails verification.
#
#   * the ukictl-build contract itself (verbatim argv, child rc propagation,
#     marker wording, broken-invocation fail-closed) is asserted by
#     tests/unit/kernel_hooks_wire.sh
#   * install-side wiring (hook installed + enabled executable) is asserted
#     by the install dry-run plan
#   * the ADR-18 encrypted-release.pem unlock path is exercised in the keys
#     unit suite; here release.pem is PLAINTEXT (offline medium), so sbsign
#     must receive the keydir path itself — pinned by the release.pem leg
#     below.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/alpine-fde-bootmgr-guard.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

HOOK=$REPO/hooks/kernel-hooks.d/alpine-fde-build.hook
KVER=6.6.63-0-lts
assert_file_exists "boot-manager re-sign hook exists (kernel-hooks.d template)" "$HOOK"
assert_eq "hook is executable (enabled by the kernel hook runner convention)" "1" \
    "$([ -x "$HOOK" ] && echo 1 || echo 0)"

export ALPINE_FDE_ESP=$T/esp
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_KEYDIR=$T/keys
export ALPINE_FDE_LIB_DIR=$REPO/lib
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_TEST_SBV_STATE=$T/sbv-state
mkdir -p "$T/bin" "$ALPINE_FDE_ESP/EFI/systemd" "$ALPINE_FDE_ESP/EFI/BOOT" \
    "$ALPINE_FDE_KEYDIR" "$ALPINE_FDE_ROOT/etc/alpine-fde" "$T/stub"
printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
printf 'key-material' >"$ALPINE_FDE_KEYDIR/release.pem"
printf 'key-material' >"$ALPINE_FDE_KEYDIR/release.crt"
MARKER=$ALPINE_FDE_ROOT/etc/alpine-fde/build-failed

# recording alpine-fde stub on the ALPINE_FDE_BIN seam: the ukictl build step
# succeeds (its own contract lives in kernel_hooks_wire.sh); argv goes to a
# SEPARATE log so the sbsign/sbverify log below stays the "signing tools ran"
# record the guard legs assert on
export ALPINE_FDE_BIN=$T/bin/alpine-fde
cat >"$ALPINE_FDE_BIN" <<EOF
#!/bin/sh
printf 'alpine-fde %s\n' "\$*" >>"$T/calls.log"
exit \${ALPINE_FDE_FAKE_RC:-0}
EOF
chmod +x "$ALPINE_FDE_BIN"
export ALPINE_FDE_FAKE_RC=0

# stubs: sbsign "signs" by copying input to --output; sbverify behaves per
# ALPINE_FDE_TEST_SBV_MODE — "pass" (always accept), "fail" (always reject),
# "failonce" (reject exactly the first invocation, then accept); both record argv
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
out=''
prev=''
for a in "$@"; do
    [ "$prev" = "--output" ] && out=$a
    prev=$a
done
last=''
for a in "$@"; do last=$a; done
if [ -n "$out" ]; then
    mkdir -p "${out%/*}"
    printf 'signed(%s)' "$last" >"$out"
fi
exit 0
EOF
cat >"$T/stub/sbverify" <<'EOF'
#!/bin/sh
printf 'sbverify %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
n=$(cat "$ALPINE_FDE_TEST_SBV_STATE" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" >"$ALPINE_FDE_TEST_SBV_STATE"
case "${ALPINE_FDE_TEST_SBV_MODE:-pass}" in
    fail) exit 1 ;;
    failonce) [ "$n" -le 1 ] && exit 1 ;;
esac
exit 0
EOF
chmod +x "$T/stub/sbsign" "$T/stub/sbverify"
export PATH="$T/stub:$PATH"

run_hook() { sh "$HOOK" add "$KVER" >/dev/null 2>&1; echo $?; }
reset_stubs() { : >"$ALPINE_FDE_TEST_LOG"; : >"$T/calls.log"; printf '0' >"$ALPINE_FDE_TEST_SBV_STATE"; }

# =============================================================================
# G-U7 / LO-05: already-verifying binaries -> idempotent no-op (never re-sign)
# =============================================================================
reset_stubs
export ALPINE_FDE_TEST_SBV_MODE=pass
assert_eq "hook: verify-pass run rc 0" "0" "$(run_hook)"
assert_eq "hook: boot manager untouched when it already verifies" "unsigned-systemd-boot" \
    "$(cat "$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: fallback loader untouched when it already verifies" "unsigned-fallback" \
    "$(cat "$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI")"
assert_eq "hook: zero sbsign calls on the verify-pass path" "0" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG")"
assert_eq "hook: sbverify ran once per ESP binary" "2" \
    "$(grep -c '^sbverify' "$ALPINE_FDE_TEST_LOG")"
assert_eq "hook: no build-failed marker on the no-op path" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# G-U7: verify fails on the CURRENT binary -> sign, then gate the signed output
# (failonce: first sbverify rejects the flashed binary, second accepts the
# signed result) — the real sign-then-install path
# =============================================================================
reset_stubs
export ALPINE_FDE_TEST_SBV_MODE=failonce
assert_eq "hook: sign-after-failed-verify rc 0" "0" "$(run_hook)"
assert_eq "hook: boot manager re-signed after failed verify" "signed($ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi)" \
    "$(cat "$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: fallback loader untouched (its verify passed)" "unsigned-fallback" \
    "$(cat "$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI")"
assert_contains "hook: sbsign uses the keydir release.pem" "$(cat "$ALPINE_FDE_TEST_LOG")" "sbsign --key $ALPINE_FDE_KEYDIR/release.pem --cert $ALPINE_FDE_KEYDIR/release.crt"
assert_contains "hook: sbverify gates with the release.crt" "$(cat "$ALPINE_FDE_TEST_LOG")" "sbverify --cert $ALPINE_FDE_KEYDIR/release.crt"
L_SBSIGN1=$(grep -nm1 '^sbsign' "$ALPINE_FDE_TEST_LOG" | cut -d: -f1)
L_SBVERIFY1=$(grep -nm1 '^sbverify' "$ALPINE_FDE_TEST_LOG" | cut -d: -f1)
assert_eq "hook: verify happens BEFORE sign (verify-first order)" "1" "$(( L_SBVERIFY1 < L_SBSIGN1 ? 1 : 0 ))"
assert_eq "hook: exactly one re-sign (only the failed-verify binary)" "1" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG")"
assert_eq "hook: no staging leftovers on success" "0" \
    "$(find "$ALPINE_FDE_ESP" -name '*.signed.*' | wc -l)"
assert_eq "hook: no build-failed marker on success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# G-U7: sbverify failure (gate) -> rc 64 + marker, binary NOT replaced
# =============================================================================
reset_stubs
export ALPINE_FDE_TEST_SBV_MODE=fail
printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
assert_eq "hook: sbverify failure -> rc 64" "64" "$(run_hook)"
assert_eq "hook: failure marker persisted (ADR-8)" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "hook: marker names the verification failure" "$(cat "$MARKER")" "sbverify"
assert_eq "hook: unverified binary NOT installed" "unsigned-systemd-boot" \
    "$(cat "$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: sign attempted before the gate rejected it (1 sbsign call)" "1" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG")"
assert_eq "hook: verify + gate attempted for the first target (2 sbverify calls)" "2" \
    "$(grep -c '^sbverify' "$ALPINE_FDE_TEST_LOG")"
assert_eq "hook: staging leftovers cleaned on failure" "0" \
    "$(find "$ALPINE_FDE_ESP" -name '*.signed.*' | wc -l)"
unset ALPINE_FDE_TEST_SBV_MODE

# =============================================================================
# G-U7: missing key material -> rc 64 + marker, nothing invoked
# =============================================================================
rm -f "$MARKER"
mv "$ALPINE_FDE_KEYDIR/release.pem" "$T/release.pem.bak"
reset_stubs
assert_eq "hook: missing release.pem -> rc 64" "64" "$(run_hook)"
assert_eq "hook: marker persisted for missing key" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_eq "hook: nothing invoked without the key" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
mv "$T/release.pem.bak" "$ALPINE_FDE_KEYDIR/release.pem"

# missing keydir entirely
rm -f "$MARKER"
reset_stubs
assert_eq "hook: missing keydir -> rc 64" "64" "$(ALPINE_FDE_KEYDIR=$T/nokeys run_hook)"
assert_eq "hook: marker persisted for missing keydir" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"

# missing ESP binary (bootctl not run / layout broken)
rm -f "$MARKER"
reset_stubs
mv "$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI" "$T/BOOTX64.bak"
assert_eq "hook: missing ESP binary -> rc 64" "64" "$(run_hook)"
assert_contains "hook: marker names the missing binary" "$(cat "$MARKER")" "BOOTX64"
mv "$T/BOOTX64.bak" "$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"

# a success after failures clears the stale marker
reset_stubs
export ALPINE_FDE_TEST_SBV_MODE=pass
assert_eq "hook: recovery run rc 0" "0" "$(run_hook)"
assert_eq "hook: stale marker cleared after success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"
unset ALPINE_FDE_TEST_SBV_MODE

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
