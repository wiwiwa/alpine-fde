#!/usr/bin/env bash
# tests/unit/policy_digest_golden.sh — combined {7,11} PolicyPCR digest + pcrsign
# contract against the committed golden vector (§6.1.1, B-G2). TPM-free: the live
# TPM cross-check lives in policy_digest_tpm_crosscheck.sh.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# helpers beyond W0's lib.sh set (assert.sh's assert_rc has a different
# signature, so define the two missing ones here instead of mixing libraries)
assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

GOLDEN="$REPO/fixtures/policy-digest/golden.json"
D7=$(jq -r .pcr7_digest "$GOLDEN")
D11=$(jq -r .pcr11_digest "$GOLDEN")
Pcrd=$(jq -r .pcr_digest "$GOLDEN")
POL=$(jq -r .policy_digest "$GOLDEN")

# --- helpers ------------------------------------------------------------------
assert_eq "golden pcr_digest: formula reproduces fixture" "$Pcrd" "$(policy_pcr_digest "$D7" "$D11")"
assert_eq "golden policy_digest: reproduces 8764f34f... (B-G2 vector)" "$POL" "$(policy_digest "$D7" "$D11")"

# Second vector pinned from an independent live swtpm trial session
# (d7/d11 from pcrextend, session digest from tpm2_policypcr) — the offline
# formula matched the TPM exactly; pinned here so regressions show without a TPM.
assert_eq "session-derived vector af1776b6... reproduces" \
    "af1776b6be427541afb66f45aad59f93105b29628698d64cd7b113728c1ec67e" \
    "$(policy_digest \
        51beab2769a47b52acbf5702aadfa6234d8ec47be019b146b1214b45bf859616 \
        fa6e8cc0c8646dad93cedb36efdc847861116987550f10f22e88c2096630dbaa)"

# value-dependence: a different d7 must change the digest (no constant digests)
D7ALT=$(printf '%063d0' 2 | tr -d '\n') # 64 chars, not the golden value
assert_ne "policy_digest is value-dependent in d7" "$POL" "$(policy_digest "$D7ALT" "$D11")"

# --- input validation ----------------------------------------------------------
rc=0; policy_check_digest "$D7" || rc=1
assert_rc "policy_check_digest accepts a sha256 digest" 0 $rc
rc=0; policy_check_digest "8764f34f" || rc=1
assert_rc "policy_check_digest rejects short strings" 1 $rc
rc=0; policy_check_digest "zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64" || rc=1
assert_rc "policy_check_digest rejects non-hex" 1 $rc

# --- §6.1.1 step 4b: sealed-object policy digest (PolicyAuthorize) ---------------
# PINNED formula (docs/Architecture.md §6.1.1 step 4b; matches libtpms
# PolicyAuthorize.c / Policy_spt.c): PolicyAuthorize CLEARS the session digest,
# then recomputes it as a DOUBLE hash — the second round runs even for the empty
# policyRef:
#   sealed = SHA256( SHA256( zero32 || CC_PolicyAuthorize(0x0000016a) || keyName )
#                    || policyRef(empty) )
# keyName = the VERIFYING-area Name hex of the release key fixture (the area
# tpm2_loadexternal/tpm2_readpublic produce for fixtures/keys/release.pub —
# attrs 0x00060040). NOTE: this is deliberately NOT the recording-area
# keyname_hex in release-facts.json (attrs 0x00020012 — different TPMT_PUBLIC,
# different Name; see the keys.sh header deviation note): the sealed policy
# pins the name of the area that will VERIFY at session time (§6.1.1 step 4b).
FIXED_KEYNAME=000b2a076d4f4509c26f83730abb1e5598768a00a45a5fd2d3cda399eeaaf38aac68
assert_ne "sealed-digest: verifying-area keyName differs from recording-area keyname_hex (attrs differ)" \
    "$(jq -r .keyname_hex "$REPO/fixtures/keys/release-facts.json")" "$FIXED_KEYNAME"
SEALED_GOLDEN=$(cat "$REPO/fixtures/policy-digest/sealed-digest.golden")
assert_eq "sealed-digest: policy_sealed_digest reproduces sealed-digest.golden" \
    "$SEALED_GOLDEN" "$(policy_sealed_digest "$FIXED_KEYNAME")"

# value-dependence: flipping ONE keyName hex digit must change the digest
KEYNAME_FLIP="${FIXED_KEYNAME%?}1"
assert_ne "sealed-digest: value-dependent in keyName (one hex digit flipped)" \
    "$SEALED_GOLDEN" "$(policy_sealed_digest "$KEYNAME_FLIP")"

# input validation: fail closed (die 64) — odd length, non-hex, empty
rc=0; (policy_sealed_digest "$(printf '%063d' 7)") >/dev/null 2>&1 || rc=$?
assert_rc "sealed-digest: odd-length keyName hex -> die 64" 64 $rc
rc=0; (policy_sealed_digest "zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64zz64") >/dev/null 2>&1 || rc=$?
assert_rc "sealed-digest: non-hex keyName -> die 64" 64 $rc
rc=0; (policy_sealed_digest "") >/dev/null 2>&1 || rc=$?
assert_rc "sealed-digest: empty keyName -> die 64" 64 $rc

# --- raw message bytes: exactly 32 bytes (the PolicyAuthorize message) ----------
policy_digest_bin "$D7" "$D11" >"$TMP/msg.bin"
n=$(wc -c <"$TMP/msg.bin" | tr -d '[:space:]')
assert_eq "raw policyDigest message is 32 bytes" 32 "$n"

# --- sign + verify roundtrip (RSASSA-PKCS1-v1_5 over SHA256) --------------------
KEYDIR="$REPO/fixtures/keys"
policy_sign "$D7" "$D11" "$KEYDIR/release.pem" "$TMP/sig.bin"
assert_file_exists "policy_sign produced a signature" "$TMP/sig.bin"
sz=$(wc -c <"$TMP/sig.bin" | tr -d '[:space:]')
assert_eq "RSA-2048 signature is 256 bytes" 256 "$sz"
rc=0; policy_verify "$TMP/sig.bin" "$D7" "$D11" "$KEYDIR/release.pub" || rc=1
assert_rc "policy_verify accepts the correct signature" 0 $rc
rc=0; policy_verify "$TMP/sig.bin" "$D7ALT" "$D11" "$KEYDIR/release.pub" || rc=1
assert_rc "policy_verify rejects a signature over other PCR values" 1 $rc
# openssl cross-verification (independent of policy_verify's own code path)
openssl dgst -sha256 -verify "$KEYDIR/release.pub" -signature "$TMP/sig.bin" "$TMP/msg.bin" >/dev/null 2>&1
assert_rc "openssl independently verifies the signature" 0 $?

# --- negative control (a): foreign key must be rejected (§12, G-B6) ---------------
# generate a second, untrusted keypair in-test; signatures it produces over the
# exact same policyDigest bytes must NOT verify against the release pubkey
# (and vice versa). openssl-level only — never swtpm for negative crypto.
openssl genrsa -out "$TMP/foreign.pem" 2048 2>/dev/null
openssl rsa -in "$TMP/foreign.pem" -pubout -out "$TMP/foreign.pub" 2>/dev/null
policy_sign "$D7" "$D11" "$TMP/foreign.pem" "$TMP/foreign-sig.bin"
assert_file_exists "negative-a: foreign key produced a signature" "$TMP/foreign-sig.bin"
rc=0; policy_verify "$TMP/foreign-sig.bin" "$D7" "$D11" "$KEYDIR/release.pub" || rc=1
assert_rc "negative-a: foreign-key signature REJECTED by release pubkey" 1 $rc
rc=0; policy_verify "$TMP/sig.bin" "$D7" "$D11" "$TMP/foreign.pub" || rc=1
assert_rc "negative-a: release-key signature REJECTED by foreign pubkey" 1 $rc

# --- negative control (b): wrong PCR selection must be rejected (§12, G-B6) -------
# build the {11}-only PolicyPCR policyDigest (selection serialized by hand):
#   policyDigest_{11} = H(zero32 || CC_PolicyPCR || TPML{11} || H(d11_raw))
# with TPML{11} = count=1, sha256, sizeofSelect=3, select bytes 00 08 00
# (bit 11). A signature over THAT digest describes a different policy than
# ours and must be rejected by policy_verify for the {7,11} selection.
pcrd11=$(printf '%s' "$D11" | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')
TPML_11='00000001000b03000800'
sel11=$(printf '%s%s%s%s' "$POLICY_ZERO32" "$POLICY_CC_PCR" "$TPML_11" "$pcrd11" \
    | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')
assert_ne "negative-b: {11}-only digest differs from the {7,11} digest" "$sel11" "$POL"
printf '%s' "$sel11" | policy_hex_to_bin >"$TMP/sel11.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sel11.sig" "$TMP/sel11.bin"
rc=0; policy_verify "$TMP/sel11.sig" "$D7" "$D11" "$KEYDIR/release.pub" || rc=1
assert_rc "negative-b: signature over {11}-only selection REJECTED for {7,11}" 1 $rc
# sanity: the same signature DOES verify over the digest it was made for
openssl dgst -sha256 -verify "$KEYDIR/release.pub" -signature "$TMP/sel11.sig" "$TMP/sel11.bin" >/dev/null 2>&1
assert_rc "negative-b: {11}-only signature is valid over its own digest (test sanity)" 0 $?

# --- pcrsign JSON artifact (systemd-measure sign shape, pcrs [7,11]) ------------
policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$TMP/pcrsig.json"
assert_eq "pcrsig JSON: pcrs are [7,11]" "[7,11]" "$(jq -c '.sha256[0].pcrs' "$TMP/pcrsig.json")"
assert_eq "pcrsig JSON: pol == recomputed policy digest" "$POL" "$(jq -r '.sha256[0].pol' "$TMP/pcrsig.json")"
assert_eq "pcrsig JSON: pkfp == DER-SPKI sha256" \
    "$(policy_pubkey_fp "$KEYDIR/release.pub")" "$(jq -r '.sha256[0].pkfp' "$TMP/pcrsig.json")"
jq -r '.sha256[0].sig' "$TMP/pcrsig.json" | openssl base64 -d -A >"$TMP/sig-from-json.bin" 2>/dev/null
cmp -s "$TMP/sig.bin" "$TMP/sig-from-json.bin"
assert_rc "pcrsig JSON: sig decodes to the identical signature bytes" 0 $?

# --- S-M4: policy_pubkey_fp contract — unparseable key: rc 1, EMPTY stdout ------------
# (consumed by policy_sign_json here AND by `ukictl build`, which guards on this
# exact contract: failure must never yield the well-known SHA256("") fingerprint)
printf 'deliberately not a key' >"$TMP/corrupt.pub"
rc=0; out=$(policy_pubkey_fp "$TMP/corrupt.pub") || rc=$?
assert_rc "policy_pubkey_fp: corrupt key fails (rc 1, S-M4)" 1 $rc
assert_eq "policy_pubkey_fp: corrupt key -> EMPTY stdout (never SHA256(''))" "" "$out"
rc=0; out=$(policy_pubkey_fp "$TMP/absent.pub") || rc=$?
assert_rc "policy_pubkey_fp: absent key fails (rc 1)" 1 $rc
assert_eq "policy_pubkey_fp: absent key -> EMPTY stdout" "" "$out"
assert_eq "policy_pubkey_fp: valid key still yields the DER-SPKI sha256" \
    "$(openssl pkey -pubin -in "$KEYDIR/release.pub" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')" \
    "$(policy_pubkey_fp "$KEYDIR/release.pub")"
# policy_sign_json fails closed (64) on the corrupt pubkey — before emitting JSON
rc=0
(policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$TMP/corrupt.pub" "$TMP/nope-s4.json") >/dev/null 2>&1 || rc=$?
assert_rc "policy_sign_json: corrupt release.pub -> die 64 (S-M4)" 64 $rc
[ ! -e "$TMP/nope-s4.json" ]
assert_rc "policy_sign_json: corrupt pub -> no artifact emitted" 0 $?

# --- S-L1: policy_sign must not leak its message temp when digest validation dies ----
LEAK=$(mktemp -d)
rc=0
( export TMPDIR="$LEAK"
  policy_sign 'zz-not-hex' "$D11" "$KEYDIR/release.pem" "$LEAK/out.sig" ) >/dev/null 2>&1 || rc=$?
assert_rc "policy_sign: invalid hex digest -> die 64" 64 $rc
assert_eq "policy_sign: no temp leak on the invalid-hex die path (S-L1)" "0" \
    "$(find "$LEAK" -name 'alpine-fde-policy.*' 2>/dev/null | wc -l | tr -d '[:space:]')"
rm -rf "$LEAK"

finish
