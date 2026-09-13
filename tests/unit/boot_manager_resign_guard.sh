#!/usr/bin/env bash
# tests/unit/boot_manager_resign_guard.sh — boot-manager re-sign guard
# (docs/Architecture.md §8.3, §11, ADR-8): a systemd-boot package upgrade
# re-flashes ESP:/EFI/systemd/systemd-bootx64.efi and /EFI/BOOT/BOOTX64.EFI.
# The hook drives the REAL template with PATH-stubbed sbsign/sbverify and
# asserts OBSERVED effects: exact argv, ESP paths, verify-FIRST idempotence
# (review LO-05: sbsign appends signatures — re-signing an already-signed
# binary stacks a dual signature, the §9.6/s16 revocation failure mode),
# sbverify-gated install, fail-closed 64 + build-failed marker when the key
# is missing or a binary fails verification.
#
#   * install-side wiring (masked systemd-boot-update.service, hook installed
#     + enabled executable) is asserted by tests/unit/install_chroot_plan.sh
#     and the install dry-run plan.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/debian-fde-bootmgr-guard.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

HOOK=$REPO/hooks/systemd-boot-upgrade-zz-debian-fde
assert_file_exists "boot-manager re-sign hook template exists" "$HOOK"
assert_eq "hook template is executable (enabled by run-parts convention)" "1" \
    "$([ -x "$HOOK" ] && echo 1 || echo 0)"

export DEBIAN_FDE_ESP=$T/esp
export DEBIAN_FDE_KEYDIR=$T/keys
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TEST_LOG=$T/cmd.log
export DEBIAN_FDE_TEST_SBV_STATE=$T/sbv-state
mkdir -p "$DEBIAN_FDE_ESP/EFI/systemd" "$DEBIAN_FDE_ESP/EFI/BOOT" "$DEBIAN_FDE_KEYDIR" "$T/root/etc/debian-fde" "$T/stub"
printf 'unsigned-systemd-boot' >"$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
printf 'key-material' >"$DEBIAN_FDE_KEYDIR/release.pem"
printf 'key-material' >"$DEBIAN_FDE_KEYDIR/release.crt"
MARKER=$DEBIAN_FDE_ROOT/etc/debian-fde/build-failed

# stubs: sbsign "signs" by copying input to --output; sbverify behaves per
# DEBIAN_FDE_TEST_SBV_MODE — "pass" (always accept), "fail" (always reject),
# "failonce" (reject exactly the first invocation, then accept); both record argv
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
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
printf 'sbverify %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
n=$(cat "$DEBIAN_FDE_TEST_SBV_STATE" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" >"$DEBIAN_FDE_TEST_SBV_STATE"
case "${DEBIAN_FDE_TEST_SBV_MODE:-pass}" in
    fail) exit 1 ;;
    failonce) [ "$n" -le 1 ] && exit 1 ;;
esac
exit 0
EOF
chmod +x "$T/stub/sbsign" "$T/stub/sbverify"
export PATH="$T/stub:$PATH"

run_hook() { sh "$HOOK" >/dev/null 2>&1; echo $?; }
reset_stubs() { : >"$DEBIAN_FDE_TEST_LOG"; printf '0' >"$DEBIAN_FDE_TEST_SBV_STATE"; }

# =============================================================================
# G-U7 / LO-05: already-verifying binaries -> idempotent no-op (never re-sign)
# =============================================================================
reset_stubs
export DEBIAN_FDE_TEST_SBV_MODE=pass
assert_eq "hook: verify-pass run rc 0" "0" "$(run_hook)"
assert_eq "hook: boot manager untouched when it already verifies" "unsigned-systemd-boot" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: fallback loader untouched when it already verifies" "unsigned-fallback" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI")"
assert_eq "hook: zero sbsign calls on the verify-pass path" "0" \
    "$(grep -c '^sbsign' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "hook: sbverify ran once per ESP binary" "2" \
    "$(grep -c '^sbverify' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "hook: no build-failed marker on the no-op path" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# G-U7: verify fails on the CURRENT binary -> sign, then gate the signed output
# (failonce: first sbverify rejects the flashed binary, second accepts the
# signed result) — the real sign-then-install path
# =============================================================================
reset_stubs
export DEBIAN_FDE_TEST_SBV_MODE=failonce
assert_eq "hook: sign-after-failed-verify rc 0" "0" "$(run_hook)"
assert_eq "hook: boot manager re-signed after failed verify" "signed($DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi)" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: fallback loader untouched (its verify passed)" "unsigned-fallback" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI")"
assert_contains "hook: sbsign uses the keydir release.pem" "$(cat "$DEBIAN_FDE_TEST_LOG")" "sbsign --key $DEBIAN_FDE_KEYDIR/release.pem --cert $DEBIAN_FDE_KEYDIR/release.crt"
assert_contains "hook: sbverify gates with the release.crt" "$(cat "$DEBIAN_FDE_TEST_LOG")" "sbverify --cert $DEBIAN_FDE_KEYDIR/release.crt"
L_SBSIGN1=$(grep -nm1 '^sbsign' "$DEBIAN_FDE_TEST_LOG" | cut -d: -f1)
L_SBVERIFY1=$(grep -nm1 '^sbverify' "$DEBIAN_FDE_TEST_LOG" | cut -d: -f1)
assert_eq "hook: verify happens BEFORE sign (verify-first order)" "1" "$(( L_SBVERIFY1 < L_SBSIGN1 ? 1 : 0 ))"
assert_eq "hook: exactly one re-sign (only the failed-verify binary)" "1" \
    "$(grep -c '^sbsign' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "hook: no staging leftovers on success" "0" \
    "$(find "$DEBIAN_FDE_ESP" -name '*.signed.*' | wc -l)"
assert_eq "hook: no build-failed marker on success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# G-U7: sbverify failure (gate) -> rc 64 + marker, binary NOT replaced
# =============================================================================
reset_stubs
export DEBIAN_FDE_TEST_SBV_MODE=fail
printf 'unsigned-systemd-boot' >"$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
assert_eq "hook: sbverify failure -> rc 64" "64" "$(run_hook)"
assert_eq "hook: failure marker persisted (ADR-8)" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "hook: marker names the verification failure" "$(cat "$MARKER")" "sbverify"
assert_eq "hook: unverified binary NOT installed" "unsigned-systemd-boot" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: sign attempted before the gate rejected it (1 sbsign call)" "1" \
    "$(grep -c '^sbsign' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "hook: verify + gate attempted for the first target (2 sbverify calls)" "2" \
    "$(grep -c '^sbverify' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "hook: staging leftovers cleaned on failure" "0" \
    "$(find "$DEBIAN_FDE_ESP" -name '*.signed.*' | wc -l)"
unset DEBIAN_FDE_TEST_SBV_MODE

# =============================================================================
# G-U7: missing key material -> rc 64 + marker, nothing invoked
# =============================================================================
rm -f "$MARKER"
mv "$DEBIAN_FDE_KEYDIR/release.pem" "$T/release.pem.bak"
reset_stubs
assert_eq "hook: missing release.pem -> rc 64" "64" "$(run_hook)"
assert_eq "hook: marker persisted for missing key" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_eq "hook: nothing invoked without the key" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
mv "$T/release.pem.bak" "$DEBIAN_FDE_KEYDIR/release.pem"

# missing keydir entirely
rm -f "$MARKER"
reset_stubs
assert_eq "hook: missing keydir -> rc 64" "64" "$(DEBIAN_FDE_KEYDIR=$T/nokeys run_hook)"
assert_eq "hook: marker persisted for missing keydir" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"

# missing ESP binary (bootctl not run / layout broken)
rm -f "$MARKER"
reset_stubs
mv "$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI" "$T/BOOTX64.bak"
assert_eq "hook: missing ESP binary -> rc 64" "64" "$(run_hook)"
assert_contains "hook: marker names the missing binary" "$(cat "$MARKER")" "BOOTX64"
mv "$T/BOOTX64.bak" "$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI"

# a success after failures clears the stale marker
reset_stubs
export DEBIAN_FDE_TEST_SBV_MODE=pass
assert_eq "hook: recovery run rc 0" "0" "$(run_hook)"
assert_eq "hook: stale marker cleared after success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"
unset DEBIAN_FDE_TEST_SBV_MODE

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
