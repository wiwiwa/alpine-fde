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

# --- case 3: §6.1.1 step 4b — sealed-object policy digest (PolicyAuthorize) -----
# The LIVE oracle for policy_sealed_digest: drive a REAL policy session through
# PolicyPCR + PolicyAuthorize (signature ticket from the release key fixture)
# and require the SESSION digest after PolicyAuthorize to equal the offline
# double hash over the same keyName — our math must match what the TPM computes,
# byte for byte (swtpm, tpm2-tools 5.8).
KEYDIR="$REPO/fixtures/keys"
tpm loadexternal -C o -G rsa -u "$KEYDIR/release.pub" -c "$TPMDIR/rel.ctx" \
    -n "$TPMDIR/name.bin" >/dev/null 2>&1
assert_rc "case 3: loadexternal produced the verifying area" 0 $?
NAME_HEX=$(od -An -v -tx1 "$TPMDIR/name.bin" | tr -d ' \n')
# approved policy = the {7,11} trial digest the session currently holds
policy_digest_bin "$d7" "$d11" >"$TPMDIR/trial3.bin"
assert_eq "case 3: session digest after PolicyPCR == approved-policy bytes" \
    "$(policy_digest "$d7" "$d11")" \
    "$(od -An -v -tx1 "$TPMDIR/trial3.bin" | tr -d ' \n')"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TPMDIR/sig3.bin" "$TPMDIR/trial3.bin" 2>/dev/null
tpm verifysignature -c "$TPMDIR/rel.ctx" -m "$TPMDIR/trial3.bin" -s "$TPMDIR/sig3.bin" \
    -f rsassa -g sha256 -t "$TPMDIR/ticket3.bin" >/dev/null 2>&1
assert_rc "case 3: TPM2_VerifySignature issued the release-key ticket" 0 $?
tpm startauthsession --policy-session -S "$TPMDIR/sess3.ctx" >/dev/null
tpm policypcr -S "$TPMDIR/sess3.ctx" -l sha256:7,11 >/dev/null
tpm policyauthorize -S "$TPMDIR/sess3.ctx" -i "$TPMDIR/trial3.bin" \
    -n "$TPMDIR/name.bin" -t "$TPMDIR/ticket3.bin" >/dev/null 2>&1
assert_rc "case 3: TPM2_PolicyAuthorize accepted the ticket + keyName" 0 $?
session3=$(tpm getpolicydigest -S "$TPMDIR/sess3.ctx" --hex | awk '{print $NF}' | sed 's/^0x//')
sealed3=$(policy_sealed_digest "$NAME_HEX")
assert_eq "offline policy_sealed_digest == live session digest after PolicyAuthorize (case 3)" \
    "$session3" "$sealed3"
assert_ne "case 3: sealed digest differs from the pre-authorize trial digest" "$sealed3" \
    "$(policy_digest "$d7" "$d11")"
tpm flushcontext -s "$TPMDIR/sess3.ctx" >/dev/null 2>&1 || true

# cleanup: the fixture's EXIT trap (swtpm_cleanup_all) stops the daemon
finish
