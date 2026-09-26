#!/usr/bin/env bash
# tests/unit/s18_foreign_pcrsig_host.sh — ZERO-BOOT host-side migration of the
# offline negatives from tests/e2e/s18-foreign-pcrsig.sh (boot-min queue 30,
# move 1): the §6.1 signing negative controls (G-T5/G-E14, G-B4-11), replicated
# against REAL artifacts (release-key-signed .pcrsig JSON in the systemd-measure
# sign shape, a real foreign RSA keypair, a real swtpm for the live PCR anchor,
# a real LUKS2 container for the token-side control) with NO VM boot.
#
# s18's own design note is the mandate here: "Host-side proofs per control (no
# TPM involved): the verification recipe itself is cross-checked". This suite
# asserts EVERY control against the lib-level gate the hook's I3 openssl check
# mirrors — seal_verify_pcrsig (G-B6: release-key verify over the entry's own
# (pol, sig) pair + freshness over the expected digest) — AND against the raw
# openssl verification recipe the e2e pins (_sig_verifies idiom):
#
#   control: foreign      — same pol entries, every sig re-signed by a FOREIGN
#                           RSA key (value right, SIGNER wrong): release.pub
#                           REFUSES the foreign sig over the same pol (exact
#                           bytes), the gate dies 64 (does NOT verify); the
#                           pol entries stay IDENTICAL (only the signer moved).
#   control: wrongsel     — release-signed pols RELABELED pcrs [11] -> [7,11]:
#                           the sig still verifies over its pol bytes, but the
#                           signed pol is the LADDER digest, never the token's
#                           combined {7,11} pol -> gate dies 64 (stale/tampered).
#   control: staled7      — a well-formed release-signed combined {7,11}
#                           policyDigest over a STALE d7: sig verifies, but the
#                           signed pol != the fresh policy_digest over the live
#                           d7 -> gate dies 64 (stale/tampered).
#   control: pcrsig11only — the payload carries ONLY the release ladder's [11]
#                           entries while the gate demands {7,11}: NO entry for
#                           the selection -> gate dies 64 (G-B4-11 direct).
#   control: tok11        — the TOKEN's tpm2-pcrs RELABELED [7,11] -> [11] on
#                           the real LUKS2 container (the s13 export->mutate->
#                           import mechanism, via lib/token.sh): the gate taken
#                           with the token's [11] selection against the ladder
#                           .pcrsig refuses (the ladder pol is not the sealed
#                           {7,11} pol) — G-B4-11 inverse (metadata write).
#   control: missing      — an ABSENT .pcrsig fails the gate (die 64).
#   GREEN baseline        — the release combined {7,11} .pcrsig verifies through
#                           the same gate over the live PCR anchor.
#
# NOT migrated (VM-only, stays in s18): in-guest console behaviors — the hook's
# I3 refusal sentinels, the 3-strike recovery loop, the PCR-7-unchanged
# forensics against the LIVE boot console, the refusal-precedes-prompt ordering.
#
# Seams (identical to seal_mechanism_b.sh): tests/unit/lib.sh asserts; the
# swtpm fixture (SWTPM_TCTI -> ALPINE_FDE_TCTI); lib/{common,policy,keys,
# token,seal}.sh; ALPINE_FDE_TMPDIR for I1 staging.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# the lib self-load seam (house style: seal_mechanism_b.sh) — seal.sh resolves
# token.sh through ALPINE_FDE_CMD_DIR; must be exported BEFORE seal.sh is sourced
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/alpine-fde-s18host.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp # I1: staging must land HERE, mode 600
KEYDIR=$REPO/fixtures/keys

# assert_ne <desc> <a> <b> — pass iff a != b (unit lib.sh ships no assert_ne)
assert_ne() {
    if [ "$2" != "$3" ]; then
        assert_eq "$1" "differ" "differ"
    else
        assert_eq "$1" "differ" "equal:[$2]"
    fi
}

TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI
flushall() { tpm flushcontext -t >/dev/null 2>&1 || true; }
flushall

# --- live PCR anchor (the "enrolled" register; deterministic extends) -----------
swtpm_pcrextend "$TPMDIR" 7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
swtpm_pcrextend "$TPMDIR" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc
pcr_hex() {
    tpm pcrread -Q -o "$TMP/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$TMP/pcr.bin" | tr -d ' \n'
}
D7=$(pcr_hex 7)
D11=$(pcr_hex 11)
[ ${#D7} -eq 64 ] && [ ${#D11} -eq 64 ] || {
    echo "FAIL: could not read live PCR values" >&2
    exit 1
}
FRESH=$(policy_digest "$D7" "$D11")
D7_STALE=$(printf 's18host-stale-d7' | sha256sum | awk '{print $1}')
D11_SYN=$(printf 's18host-synthetic-d11' | sha256sum | awk '{print $1}')

# --- the release artifacts -------------------------------------------------------
# the release COMBINED {7,11} .pcrsig (what the finalized enrollment is signed
# over — the e2e's uki-pcrsig-combined.json stand-in)
REL_JSON=$TMP/pcrsig-release.json
policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$REL_JSON"
# the release LADDER ([11]-only entries — the ukify PCR-signing pass stand-in)
POL11=$(seal_digest_11 "$D11")
printf '%s' "$POL11" | policy_hex_to_bin >"$TMP/pol11.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/pol11.sig" "$TMP/pol11.bin" 2>/dev/null
PKFP=$(policy_pubkey_fp "$KEYDIR/release.pub")
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$TMP/pol11.sig")" --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$TMP/pcrsig-ladder.json"
# the FOREIGN keypair (valid, well-formed, nothing to do with the release identity)
openssl genrsa -out "$TMP/foreign.pem" 2048 2>/dev/null
openssl rsa -in "$TMP/foreign.pem" -pubout -out "$TMP/foreign.pub" 2>/dev/null
assert_ne "foreign key is NOT the release key (distinct key material)" \
    "$(sha256sum <"$TMP/foreign.pub")" "$(sha256sum <"$KEYDIR/release.pub")"

# _sig_verifies <json> <entry> <pubkey> — the hook-side verification recipe,
# host-side (pinned by s18): sig (base64) is an RSA-SHA256 signature over the
# RAW pol bytes.
_sig_verifies() {
    local json="$1" e="$2" pub="$3"
    jq -r ".sha256[$e].pol" "$json" | policy_hex_to_bin >"$TMP/vpol.bin"
    jq -r ".sha256[$e].sig" "$json" | openssl base64 -d -A >"$TMP/vpol.sig" 2>/dev/null
    openssl dgst -sha256 -verify "$pub" -signature "$TMP/vpol.sig" "$TMP/vpol.bin" >/dev/null 2>&1
}
# gate_refused <json> <sel> <fresh> <msg-needle> — seal_verify_pcrsig must die
# 64 with the pinned refusal class (subshell: die exits)
gate_refused() { # <label> <json> <sel> <fresh> <needle>
    ( seal_verify_pcrsig "$KEYDIR" "$2" "$3" "$4" ) 2>"$TMP/gate.err"
    [ "$?" -eq 64 ] && assert_eq "$1 (gate rc)" "64" "64" ||
        assert_eq "$1 (gate rc)" "64" "$?"
    assert_contains "$1 (refusal class)" "$(cat "$TMP/gate.err")" "$5"
}
# gate_green <json> <sel> <fresh> — the same gate PASSES a good artifact
gate_green() { # <label> <json> <sel> <fresh>
    ( seal_verify_pcrsig "$KEYDIR" "$2" "$3" "$4" ) 2>"$TMP/gate.err"
    assert_rc "$1" 0 $?
}

# --- GREEN baseline: the release combined .pcrsig verifies -----------------------
gate_green "GREEN baseline: release {7,11} .pcrsig verifies over the live anchor" \
    "$REL_JSON" "7,11" "$FRESH"
_sig_verifies "$REL_JSON" 0 "$KEYDIR/release.pub"
assert_rc "positive recipe: release.pub verifies the release sig over pol" 0 $?

# --- control 1: FOREIGN — every sig re-signed by the foreign key ------------------
FOR_JSON=$TMP/pcrsig-foreign.json
cp "$REL_JSON" "$FOR_JSON"
N_ENTRIES=$(jq '.sha256 | length' "$REL_JSON")
for ((e = 0; e < N_ENTRIES; e++)); do
    jq -r ".sha256[$e].pol" "$REL_JSON" | policy_hex_to_bin >"$TMP/pol.bin"
    openssl dgst -sha256 -sign "$TMP/foreign.pem" -out "$TMP/pol.sig" "$TMP/pol.bin" 2>/dev/null
    sig=$(openssl base64 -A -in "$TMP/pol.sig")
    # update the ACCUMULATOR: every entry must move to the foreign signer
    jq --arg sig "$sig" ".sha256[$e].sig = \$sig" "$FOR_JSON" >"$TMP/acc.json"
    mv "$TMP/acc.json" "$FOR_JSON"
done
assert_eq "[foreign] forged .pcrsig keeps the SAME pol entries (only the signer moved)" \
    "$(jq -c '[.sha256[].pol]' "$REL_JSON")" "$(jq -c '[.sha256[].pol]' "$FOR_JSON")"
_sig_verifies "$REL_JSON" 0 "$KEYDIR/release.pub"
    assert_rc "[foreign] positive control [0]: release.pub verifies the RELEASE sig over pol" 0 $?
_sig_verifies "$FOR_JSON" 0 "$KEYDIR/release.pub"
    assert_rc "[foreign] NEGATIVE control [0]: release.pub REFUSES the foreign sig over the same pol" 1 $?
_sig_verifies "$FOR_JSON" 0 "$TMP/foreign.pub"
    assert_rc "[foreign] sanity [0]: foreign.pub verifies the foreign sig (well-formed, foreign-signed)" 0 $?
gate_refused "[foreign] G-B6 gate" "$FOR_JSON" "7,11" "$FRESH" "does NOT verify"

# --- control 2: WRONGSEL — release pols relabeled [11] -> [7,11] ------------------
WRONGSEL=$TMP/pcrsig-wrongsel.json
cp "$TMP/pcrsig-ladder.json" "$WRONGSEL"
jq '.sha256[0].pcrs = [7, 11]' "$WRONGSEL" >"$TMP/acc.json" && mv "$TMP/acc.json" "$WRONGSEL"
_sig_verifies "$WRONGSEL" 0 "$KEYDIR/release.pub"
    assert_rc "[wrongsel] positive control [0]: the release sig still verifies over its pol bytes" 0 $?
assert_eq "[wrongsel] the entry is relabeled to the foreign selection [7,11]" "[7,11]" \
    "$(jq -c '.sha256[0].pcrs' "$WRONGSEL")"
assert_ne "[wrongsel] the signed pol is the LADDER digest, not the combined {7,11} pol" \
    "$POL11" "$FRESH"
gate_refused "[wrongsel] G-B6 gate" "$WRONGSEL" "7,11" "$FRESH" "stale/tampered"

# --- control 3: STALED7 — release-signed {7,11} digest over a STALE d7 ------------
STALE_JSON=$TMP/pcrsig-staled7.json
policy_sign_json "$D7_STALE" "$D11_SYN" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$STALE_JSON"
_sig_verifies "$STALE_JSON" 0 "$KEYDIR/release.pub"
    assert_rc "[staled7] positive control [0]: release.pub verifies the release sig over the (stale) pol bytes" 0 $?
assert_ne "[staled7] NEGATIVE control: the stale pol != the fresh pol over the live d7 + real d11" \
    "$(jq -r '.sha256[0].pol' "$STALE_JSON")" "$FRESH"
gate_refused "[staled7] G-B6 gate" "$STALE_JSON" "7,11" "$FRESH" "stale/tampered"

# --- control 4: PCRSIG11ONLY — only [11] ladder entries, token demands {7,11} -----
# (no forge needed: the mismatch IS the omission — G-B4-11 direct)
LADDER=$TMP/pcrsig-ladder.json
assert_eq "[pcrsig11only] NEGATIVE control: NO entry carries the token's pcrs [7,11] selection" "0" \
    "$(jq '[.sha256[] | select((.pcrs | join(",")) == "7,11")] | length' "$LADDER")"
_sig_verifies "$LADDER" 0 "$KEYDIR/release.pub"
    assert_rc "[pcrsig11only] positive control [0]: the [11] entries are release-signed (the omission is the only defect)" 0 $?
gate_refused "[pcrsig11only] G-B6 gate" "$LADDER" "7,11" "$FRESH" "no pcrs=[7,11] entry"

# --- control 5: TOK11 — the TOKEN's pcrs relabeled [7,11] -> [11] (metadata write) --
LUKS=$TMP/luks.img
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
PRE=$TMP/pre.json
token_dump "$LUKS" "$PRE"
TOK=$TMP/token-fin.json
seal_finalized "$KEYDIR" "$LUKS" "$REL_JSON" "$TOK"
assert_rc "standing enrollment sealed for the token-side control" 0 $?
token_add_keyslot "$LUKS" "$SEAL_PASS_FILE" "$SEAL_SLOT" "$TMP/k0"
TID=$(token_next_id "$LUKS")
token_import "$LUKS" "$TOK" "$TID"
assert_rc "standing token imported" 0 $?
# the s13 export->mutate->import mechanism (host-side metadata write)
jq '.["tpm2-pcrs"] = [11]' "$TOK" >"$TMP/tok11.json"
token_remove "$LUKS" "$TID"
( token_import "$LUKS" "$TMP/tok11.json" "$TID" ) 2>/dev/null
assert_rc "[tok11] token PCR-selection relabel landed (host-side metadata tamper)" 0 $?
TOK11_CHK=$TMP/tok11-chk.json
cryptsetup token export "$LUKS" --token-id "$TID" --json-file "$TOK11_CHK" 2>/dev/null
assert_eq "[tok11] NEGATIVE control: the token's tpm2-pcrs relabeled to [11]" "[11]" \
    "$(jq -c '.["tpm2-pcrs"]' "$TOK11_CHK")"
assert_eq "[tok11] the payload keeps the release ladder (every entry stays [11], release-signed)" \
    "[11]" "$(jq -c '[.sha256[].pcrs[]]' "$LADDER")"
_sig_verifies "$LADDER" 0 "$KEYDIR/release.pub"
    assert_rc "[tok11] positive control [0]: the ladder entry the hook will take is release-signed" 0 $?
# the gate taken with the TOKEN's [11] selection over the ladder .pcrsig: the
# ladder pol is not the sealed {7,11} pol -> refuse (G-B4-11 inverse)
gate_refused "[tok11] G-B6 gate over the token's relabeled selection" "$LADDER" "11" "$FRESH" "stale/tampered"

# --- control 6: MISSING .pcrsig -----------------------------------------------------
gate_refused "[missing] G-B6 gate" "$TMP/does-not-exist.pcrsig.json" "7,11" "$FRESH" "no pcrs=[7,11] entry"

swtpm_stop "$TPMDIR" || true
finish
