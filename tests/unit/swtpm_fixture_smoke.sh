#!/usr/bin/env bash
# tests/unit/swtpm_fixture_smoke.sh — self-test of the swtpm fixture
# (harness-infra test; run before any e2e per docs/Architecture.md §12).
#
# Covers: start → getcap ok → pcrread prints a digest → pcrextend changes
# PCR 7 → stop → reset idempotent → fresh start has PCR 7 back at zero.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"

STATE_DIR=$(mktemp -d /tmp/debian-fde-swtpm-smoke.XXXXXX)
ZERO64=$(printf '0%.0s' {1..64})
EXTEND64=$(printf 'ab%.0s' {1..32})

# 1. start: fixture reports ready and exports the TCTI config
assert_rc "fixture start" 0 swtpm_start "$STATE_DIR"
assert_eq "SWTPM_TCTI exported" "swtpm:path=$STATE_DIR/sock" "$SWTPM_TCTI"

# 2. tpm2_getcap against the exported TCTI must succeed
assert_rc "tpm2_getcap properties-fixed" 0 tpm2_getcap -T "$SWTPM_TCTI" properties-fixed

# 3. pcrread prints a 64-hex-char sha256 digest for PCR 7
PCR7=$(swtpm_pcrread "$STATE_DIR" 7)
assert_eq "pcrread rc" 0 "$?"
if [[ "$PCR7" =~ ^[0-9a-f]{64}$ ]]; then
    assert_eq "pcrread prints sha256 digest" 64 "${#PCR7}"
else
    assert_eq "pcrread prints sha256 digest" "64-hex-digest" "malformed:[$PCR7]"
fi

# Fresh TPM state: PCR 7 must start at zero
assert_eq "fresh PCR7 is zero" "$ZERO64" "$PCR7"

# 4. pcrextend changes PCR 7 (drift simulation works)
assert_rc "pcrextend PCR7" 0 swtpm_pcrextend "$STATE_DIR" 7 "$EXTEND64"
PCR7_AFTER=$(swtpm_pcrread "$STATE_DIR" 7)
assert_ne "PCR7 changed after extend" "$PCR7" "$PCR7_AFTER"
assert_not_contains "PCR7 is not zero after extend" "$PCR7_AFTER" "$ZERO64"

# 5. stop: process gone afterwards
assert_rc "fixture stop" 0 swtpm_stop "$STATE_DIR"
if kill -0 "$(cat "$STATE_DIR/pid" 2>/dev/null)" 2>/dev/null; then
    assert_eq "swtpm process exited after stop" "exited" "still-running"
else
    assert_eq "swtpm process exited after stop" "exited" "exited"
fi

# 6. reset is idempotent (safe to call twice)
assert_rc "reset #1" 0 swtpm_reset "$STATE_DIR"
assert_rc "reset #2 (idempotent)" 0 swtpm_reset "$STATE_DIR"

# 7. fresh start on the reset dir: PCR 7 back to zero
assert_rc "restart after reset" 0 swtpm_start "$STATE_DIR"
PCR7_FRESH=$(swtpm_pcrread "$STATE_DIR" 7)
assert_eq "PCR7 back to zero on fresh state" "$ZERO64" "$PCR7_FRESH"

swtpm_stop "$STATE_DIR" || true
rm -rf "$STATE_DIR"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
