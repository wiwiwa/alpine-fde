#!/usr/bin/env bash
# tests/unit/pcrsign_policyauthorize_accept.sh — G-B5 (§6.1.1 end + I5): the
# pcrsign release-key signature must satisfy a REAL TPM PolicyAuthorize. Full
# chain on swtpm (tpm2-tools 5.8):
#
#   trial {7,11} policy digest (lib/policy.sh, the pcrsign-signed message)
#     -> keyName of the release public area (loadexternal + readpublic, step 4b)
#     -> seal a dummy secret under the sealed-object policy digest (tpm2_create
#        -L, policy digest incl. keyName digest update)
#     -> policy session: PolicyPCR + PolicyAuthorize with OUR signature
#     -> tpm2_unseal returns the secret  (the OBSERVED effect: acceptance)
#
# Signed-message semantics pinned by this test (verified against libtpms
# PolicyAuthorize.c + Policy_spt.c PolicyContextUpdate, and empirically on
# swtpm): PolicyAuthorize checks H(approvedPolicy || policyRef) — with an empty
# policyRef that is exactly the raw 32-byte policyDigest pcrsign signs — then
# CLEARS the session digest and recomputes it as
#     sealed = H( H( zero32 || CC_PolicyAuthorize(0x0000016a) || keyName ) || policyRef )
# (the second round runs even for an empty policyRef — a DOUBLE hash).
# DOC CONVERGENCE (wave 2b): docs/Architecture.md §6.1.1 step 4b no longer shows
# the single-hash form H(policyDigest || keyName || policyRef) — it now records
# the corrected double-hash form with TPM_CC_PolicyAuthorize(0x0000016a), i.e.
# the formula pinned and asserted above. Doc and test agree; the formula pin
# here remains normative against regression.
#
# swtpm-leniency caveat (§6.1.1): no negative crypto is asserted against swtpm
# here — negative controls live at the openssl level (policy_digest_golden.sh).
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
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"

KEYDIR="$REPO/fixtures/keys"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/debian-fde-pa-accept.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT

TPMDIR="$TMP/swtpm"
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
# Route the repo-wide tpm() TCTI wrapper (lib/common.sh) at the fixture
DEBIAN_FDE_TCTI=$SWTPM_TCTI
export DEBIAN_FDE_TCTI
flushall() { tpm flushcontext -t >/dev/null 2>&1 || true; }
flushall

# --- live PCR values (extended so the {7,11} selection is meaningful) -------------
swtpm_pcrextend "$TPMDIR" 7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
swtpm_pcrextend "$TPMDIR" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc
pcr_hex() {
    tpm pcrread -Q -o "$TMP/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$TMP/pcr.bin" | tr -d ' \n'
}
D7=$(pcr_hex 7)
D11=$(pcr_hex 11)
[ ${#D7} -eq 64 ] && [ ${#D11} -eq 64 ] || {
    echo "FAIL: could not read live PCR values (d7='$D7' d11='$D11')" >&2
    exit 1
}

# --- §6.1.1 steps 3–4: trial digest + OUR release-key signature (openssl level) ---
TRIAL=$(policy_digest "$D7" "$D11")
policy_digest_bin "$D7" "$D11" >"$TMP/trial.bin"
policy_sign "$D7" "$D11" "$KEYDIR/release.pem" "$TMP/sig.bin"
policy_verify "$TMP/sig.bin" "$D7" "$D11" "$KEYDIR/release.pub"
assert_rc "our signature verifies openssl-level over the trial digest" 0 $?

# --- §6.1.1 step 4b: keyName of the release public area -----------------------------
# The in-TPM verification below (ticket flow) requires the area tpm2-tools
# converts the PEM to (attrs 0x00060040); the task-pinned 0x00020012 recording
# area is rejected with RC_ATTRIBUTES (keys.sh header, documented deviation).
# The sealed policy must pin the name of the VERIFYING area, so we take the
# name tpm2 computes from the release PEM itself.
tpm loadexternal -C n -G rsa -u "$KEYDIR/release.pub" -c "$TMP/rel.ctx" -n "$TMP/name.bin" >/dev/null 2>&1
tpm readpublic -c "$TMP/rel.ctx" -n "$TMP/name-readpublic.bin" >/dev/null 2>&1
cmp -s "$TMP/name.bin" "$TMP/name-readpublic.bin"
assert_rc "keyName: loadexternal -n == readpublic -n" 0 $?
flushall
# sanity: the repo's recording path (keys_keyname, 0x00020012 area) still works
keys_keyname "$KEYDIR/release.pub" "$TMP/name-recorded.bin"
[ "$(xxd -p "$TMP/name-recorded.bin" | tr -d '\n')" = "$(jq -r .keyname_hex "$KEYDIR/release-facts.json")" ]
assert_rc "keys_keyname still reproduces the fixture keyName (recording path)" 0 $?
flushall

# --- sealed-object policy digest — policy_sealed_digest (lib/policy.sh) -----------
# The pinned §6.1.1 step 4b formula lives in that function's header comment;
# the offline golden is fixtures/policy-digest/sealed-digest.golden (asserted in
# policy_digest_golden.sh). This live chain is the normative TPM oracle.
NAME_HEX=$(xxd -p "$TMP/name.bin" | tr -d '\n')
SEALED=$(policy_sealed_digest "$NAME_HEX")

# --- seal a dummy secret under the sealed policy digest ------------------------------
printf 'dummy-secret-for-policyauthorize-accept\n' >"$TMP/secret.txt"
tpm createprimary -C o -g sha256 -G rsa -c "$TMP/prim.ctx" >/dev/null 2>&1
tpm create -C "$TMP/prim.ctx" -g sha256 -i "$TMP/secret.txt" -L "$SEALED" \
    -u "$TMP/seal.pub" -r "$TMP/seal.priv" >/dev/null 2>&1
assert_rc "tpm2_create sealed the secret under the sealed policy digest" 0 $?
flushall
tpm load -C "$TMP/prim.ctx" -u "$TMP/seal.pub" -r "$TMP/seal.priv" -c "$TMP/seal.ctx" >/dev/null 2>&1
assert_rc "tpm2_load loaded the sealed object" 0 $?
flushall

# --- policy session: PolicyPCR + PolicyAuthorize(our signature) ----------------------
tpm startauthsession --policy-session -S "$TMP/sess.ctx" >/dev/null 2>&1
tpm policypcr -S "$TMP/sess.ctx" -l sha256:7,11 >/dev/null 2>&1
assert_rc "PolicyPCR satisfied over live PCRs {7,11}" 0 $?
# in-TPM signature verification (owner hierarchy — NULL produces no ticket)
tpm loadexternal -C o -G rsa -u "$KEYDIR/release.pub" -c "$TMP/rel2.ctx" -n "$TMP/name2.bin" >/dev/null 2>&1
tpm verifysignature -c "$TMP/rel2.ctx" -m "$TMP/trial.bin" -s "$TMP/sig.bin" \
    -f rsassa -g sha256 -t "$TMP/ticket.bin" >/dev/null 2>&1
assert_rc "TPM accepted OUR release-key signature (TPM2_VerifySignature)" 0 $?
tpm policyauthorize -S "$TMP/sess.ctx" -i "$TMP/trial.bin" -n "$TMP/name.bin" \
    -t "$TMP/ticket.bin" >/dev/null 2>&1
assert_rc "TPM2_PolicyAuthorize accepted the pcrsign signature" 0 $?
flushall
SESSION=$(tpm getpolicydigest -S "$TMP/sess.ctx" --hex 2>/dev/null | awk '{print $NF}' | sed 's/^0x//')
assert_eq "session digest after PolicyAuthorize == sealed-object policy digest" "$SEALED" "$SESSION"

# --- observed effect: unseal returns the secret ---------------------------------------
tpm unseal -c "$TMP/seal.ctx" -p "session:$TMP/sess.ctx" -o "$TMP/unsealed.txt" >/dev/null 2>&1
assert_rc "tpm2_unseal succeeded under the authorized policy" 0 $?
assert_eq "unsealed output equals the sealed dummy secret (acceptance proven)" \
    "$(cat "$TMP/secret.txt")" "$(cat "$TMP/unsealed.txt")"
flushall

finish
