#!/usr/bin/env bash
# tests/unit/policy_digest_tpm_crosscheck.sh — the normative cross-check for the
# combined {7,11} policy digest (§6.1.1 step 3): the offline policy_digest must
# equal the digest of a REAL TPM trial session after PolicyPCR over the same
# live PCR values (swtpm via the W0 fixture). Never trust our own math alone.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"

# helpers beyond W0's lib.sh set
assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TPMDIR=$(mktemp -d /tmp/debian-fde-crosscheck.XXXXXX)
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
# Route the W0 tpm() TCTI wrapper at the fixture (the fixture exports SWTPM_TCTI).
DEBIAN_FDE_TCTI=$SWTPM_TCTI
export DEBIAN_FDE_TCTI

# pcr_hex <pcr> — read a PCR via binary output + od (POSIX). NOTE: the W0
# fixture's swtpm_pcrread awk only matches single-digit PCR lines
# ("11:" has no space before the colon), so this test reads PCRs directly.
pcr_hex() {
    tpm pcrread -Q -o "$TPMDIR/pcr.bin" "sha256:$1"
    od -An -v -tx1 "$TPMDIR/pcr.bin" | tr -d ' \n'
}

# tpm_session_policy_digest — trial session over live PCRs {7,11}; prints the
# session's policy digest. Trial (not --policy-session): same digest math.
tpm_session_policy_digest() {
    local ctx="$TPMDIR/sess.ctx" out
    tpm startauthsession -S "$ctx" >/dev/null
    tpm policypcr -S "$ctx" -l sha256:7,11 >/dev/null
    out=$(tpm getpolicydigest -S "$ctx" --hex | awk '{print $NF}' | sed 's/^0x//')
    tpm flushcontext -s "$ctx" >/dev/null 2>&1 || true
    printf '%s\n' "$out"
}

# --- case 1: distinct extensions for PCR 7 and PCR 11 ---------------------------
swtpm_pcrextend "$TPMDIR" 7 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
swtpm_pcrextend "$TPMDIR" 11 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
d7=$(pcr_hex 7)
d11=$(pcr_hex 11)
mine=$(policy_digest "$d7" "$d11")
tpm_digest=$(tpm_session_policy_digest)
assert_eq "offline policy_digest == live TPM session digest (case 1)" "$tpm_digest" "$mine"

# --- case 2: further extension on PCR 11 only (kernel-image drift simulation) ---
case1_digest=$mine
swtpm_pcrextend "$TPMDIR" 11 1234567812345678123456781234567812345678123456781234567812345678
d7=$(pcr_hex 7)
d11=$(pcr_hex 11)
mine=$(policy_digest "$d7" "$d11")
tpm_digest=$(tpm_session_policy_digest)
assert_eq "offline policy_digest == live TPM session digest (case 2, d11 drifted)" "$tpm_digest" "$mine"
assert_ne "digest changed after the PCR 11 drift" "$case1_digest" "$mine"

# cleanup: the fixture's EXIT trap (swtpm_cleanup_all) stops the daemon
finish
