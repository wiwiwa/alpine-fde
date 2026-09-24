#!/usr/bin/env bash
# tests/unit/token_schema.sh — G-B8 (§7.2 + §12 interop oracle dependency): pin
# the EXACT emitted field-set of the systemd-tpm2 token the Mechanism B sealer
# writes. Dash-form upstream names, literal field-set assert:
#   type, keyslots, tpm2-blob, tpm2-pcrs, tpm2-pcr-bank, tpm2-policy-hash,
#   tpm2-primary-alg, tpm2-pubkey, tpm2-signature — NOTHING else, NO underscore
#   spellings (tpm2_blob & co would be silently ignored by some consumers and
#   break the oracle). tpm2-policy-hash is the upstream-257-mandatory sealed
#   digest; tpm2-primary-alg "rsa" pins the SRK parent template (upstream
#   defaults ECC) — both ADR-19 interop findings (see the SCHEMA DELTA note in
#   tests/lib/interop-oracle.sh and tests/unit/interop_token_framing.sh).
#   * b64 pubkey equality: tpm2-pubkey decodes to the DER SubjectPublicKeyInfo
#     of release.pub
#   * keyslots shape: exactly one string element, != "0"
#   * blob shape: decodes; the private TPM2B length prefix is plausible
#   * live leg: the token EMITTED by seal_provisional on a real swtpm + LUKS2
#     fixture carries the same exact field-set (the §12 oracle consumes this
#     file, not the builder)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd" # BEFORE seal.sh (sibling resolution)
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/debian-fde-token-schema.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
DEBIAN_FDE_TMPDIR=$TMP/tmp
KEYDIR=$REPO/fixtures/keys

EXACT_FIELDS="keyslots,tpm2-blob,tpm2-pcr-bank,tpm2-pcrs,tpm2-policy-hash,tpm2-primary-alg,tpm2-pubkey,tpm2-signature,type"
DER=$(openssl pkey -pubin -in "$KEYDIR/release.pub" -outform DER 2>/dev/null | openssl base64 -A)

# schema_check FILE PCRSLIST — the literal field-set + shape pins
schema_check() { # FILE DESC_PREFIX PCRSLIST EXPECTED_SLOT
    _sc_f=$1 _sc_p=$2 _sc_pcrs=$3 _sc_slot=$4
    assert_eq "$_sc_p: exact field-set (dash-form, nothing else)" "$EXACT_FIELDS" \
        "$(jq -rS 'keys | sort | join(",")' "$_sc_f")"
    assert_not_contains "$_sc_p: no underscore spellings" "$(tr -d ' \n' <"$_sc_f")" "tpm2_"
    assert_eq "$_sc_p: type" "systemd-tpm2" "$(jq -r '.type' "$_sc_f")"
    assert_eq "$_sc_p: pcr-bank" "sha256" "$(jq -r '.["tpm2-pcr-bank"]' "$_sc_f")"
    assert_eq "$_sc_p: pcrs for the mode" "$_sc_pcrs" "$(jq -c '.["tpm2-pcrs"]' "$_sc_f")"
    assert_eq "$_sc_p: policy-hash is 64 lowercase hex chars (upstream 257 mandatory)" "yes" \
        "$(jq -r '.["tpm2-policy-hash"]' "$_sc_f" | grep -qE '^[0-9a-f]{64}$' && echo yes || echo no)"
    assert_eq "$_sc_p: primary-alg rsa" '"rsa"' "$(jq -c '.["tpm2-primary-alg"]' "$_sc_f")"
    assert_eq "$_sc_p: b64 pubkey == DER of release.pub" "$DER" \
        "$(jq -r '.["tpm2-pubkey"]' "$_sc_f")"
    assert_eq "$_sc_p: pubkey b64 decodes to valid DER (openssl parses it)" "0" \
        "$(printf '%s' "$(jq -r '.["tpm2-pubkey"]' "$_sc_f")" | openssl base64 -d -A 2>/dev/null |
            openssl pkey -pubin -inform DER -noout -text 2>/dev/null >/dev/null && echo 0 || echo 1)"
    assert_eq "$_sc_p: keyslots shape: one string element == $_sc_slot" \
        "[\"$_sc_slot\"]" "$(jq -c '.keyslots' "$_sc_f")"
    assert_eq "$_sc_p: keyslots element is a string, not \"0\"" "yes" \
        "$(jq -r '(.keyslots | length) == 1 and (.keyslots[0] | type) == "string" and .keyslots[0] != "0" | if . then "yes" else "no" end' "$_sc_f")"
    assert_eq "$_sc_p: signature is non-empty base64" "yes" \
        "$(jq -r '.["tpm2-signature"] | length > 0 | if . then "yes" else "no" end' "$_sc_f")"
    assert_eq "$_sc_p: blob decodes with a plausible private TPM2B prefix" "yes" \
        "$(printf '%s' "$(jq -r '.["tpm2-blob"]' "$_sc_f")" | openssl base64 -d -A 2>/dev/null >"$TMP/blob.bin"
            _bs=$(wc -c <"$TMP/blob.bin")
            _pl=$((0x$(xxd -p -l 2 "$TMP/blob.bin")))
            [ "$_pl" -gt 0 ] && [ "$_pl" -lt "$_bs" ] && echo yes || echo no)"
}

# --- 1. unit level: token_build_json ------------------------------------------------
TOKU=$TMP/token-unit.json
# blob fixture with a valid TPM2B_PRIVATE prefix (len=2 + 2 bytes); the
# policy-hash VALUE semantic (== policy_sealed_digest of the release keyName)
# is pinned by interop_token_framing.sh — here only the field-set/shape
token_build_json '[7, 11]' "$DER" "c2ln" "AAJhYg==" 1 \
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" "$TOKU"
assert_rc "token_build_json rc 0" 0 $?
schema_check "$TOKU" "unit token" '[7,11]' 1

# --- 2. live leg: the token EMITTED by seal_provisional ------------------------------
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
DEBIAN_FDE_TCTI=$SWTPM_TCTI
export DEBIAN_FDE_TCTI
swtpm_pcrextend "$TPMDIR" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc
pcr_hex() {
    tpm pcrread -Q -o "$TMP/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$TMP/pcr.bin" | tr -d ' \n'
}
D11=$(pcr_hex 11)
ZERO32=0000000000000000000000000000000000000000000000000000000000000000
POL11=$(printf '%s%s%s%s' "$ZERO32" 0000017f 00000001000b03000800 \
    "$(echo -n "$D11" | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')" |
    policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')
printf '%s' "$POL11" | policy_hex_to_bin >"$TMP/msg.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sig.bin" "$TMP/msg.bin"
PKFP=$(policy_pubkey_fp "$KEYDIR/release.pub")
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$TMP/sig.bin")" --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$TMP/pcrsig.json"

LUKS=$TMP/luks.img
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null

TOKL=$TMP/token-live.json
seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig.json" "$TOKL"
assert_rc "seal_provisional rc 0 (live leg)" 0 $?
schema_check "$TOKL" "live emitted token" '[11]' "$(jq -r '.keyslots[0]' "$TOKL")"
assert_eq "live: token signature == the .pcrsig signature" \
    "$(jq -r '.sha256[0].sig' "$TMP/pcrsig.json")" "$(jq -r '.["tpm2-signature"]' "$TOKL")"

finish
