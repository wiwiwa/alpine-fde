#!/usr/bin/env bash
# tests/unit/seal_mechanism_b.sh — G-B3/G-B6 (§6.1/§7.1/§9.1 step 6, ADR-19/
# ADR-20): Mechanism B sealing, exercised against the swtpm fixture with REAL
# tpm2-tools handlers and a real file-backed LUKS2 container. Pinned here:
#   * seal_provisional — PolicyAuthorize over the PCR-11-only signed policy
#     (approved digest = the 11-only selection digest the UKI .pcrsig signs)
#   * seal_finalized — the finalized {7,11} construction (static d7 re-captured
#     live) refuses an 11-only .pcrsig and vice versa (G-B6 wrong-selection)
#   * signature rejection before embedding (G-B6): signature that does not
#     verify over the embedded pol / pol that does not match the freshly
#     computed digest / foreign-key signature -> die 64, NO token written, NO
#     passphrase staged (openssl-level negatives per the swtpm-leniency caveat)
#   * the 11-only policy digest formula == a live TPM PolicyPCR trial session
#     (the normative oracle, same method as policy_digest_tpm_crosscheck.sh)
#   * seal_unseal round-trip: the sealed blob in the token unseals under a
#     policy session over the live PCRs with our release-key signature and
#     returns EXACTLY the staged random volume passphrase (>= 256-bit)
#   * PCR-drift negatives: extending PCR 11 after sealing makes the session
#     unseal fail (both modes); extending PCR 7 kills the finalized seal
# swtpm-leniency caveat (§6.1.1): no signature-acceptance negative is asserted
# against swtpm in-TPM — the G-B6 negatives above are openssl-level.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# the lib self-load seam (house style: enroll_precondition_matrix.sh) — seal.sh
# resolves its siblings (token.sh) through DEBIAN_FDE_CMD_DIR; must be exported
# BEFORE seal.sh is sourced
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
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

TMP=$(mktemp -d /tmp/debian-fde-seal-b.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
DEBIAN_FDE_TMPDIR=$TMP/tmp # I1: passphrase staging must land HERE, mode 600
KEYDIR=$REPO/fixtures/keys
KEY2=$TMP/key2 # foreign release key (G-B6)
mkdir -p "$KEY2"

TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
DEBIAN_FDE_TCTI=$SWTPM_TCTI
export DEBIAN_FDE_TCTI
flushall() { tpm flushcontext -t >/dev/null 2>&1 || true; }
flushall

# --- live PCR state -------------------------------------------------------------------
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

# --- 11-only policy digest fixture machinery (INDEPENDENT of lib/seal.sh) --------------
# Raw formula (TPM 2.0 Part 3 PolicyPCR): H(zero32 || CC_PolicyPCR || TPML{11} ||
# H(d11_raw)); TPML{11} = count=1, sha256, sizeofSelect=3, select bytes 00 08 00.
ZERO32=0000000000000000000000000000000000000000000000000000000000000000
CC_PCR=0000017f
TPML11=00000001000b03000800
digest11_raw() { # D11HEX -> trial digest hex (test-local, independent computation)
    printf '%s%s%s%s' "$ZERO32" "$CC_PCR" "$TPML11" \
        "$(echo -n "$1" | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')" |
        policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}'
}
POL11=$(digest11_raw "$D11")
POL711=$(policy_digest "$D7" "$D11")
printf '%s' "$POL11" | policy_hex_to_bin >"$TMP/msg11.bin"
printf '%s' "$POL711" | policy_hex_to_bin >"$TMP/msg711.bin"
BADPOL=0000000000000000000000000000000000000000000000000000000000000000
printf '%s' "$BADPOL" | policy_hex_to_bin >"$TMP/msg-badpol.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sig11.bin" "$TMP/msg11.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sig711.bin" "$TMP/msg711.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sig-badpol.bin" "$TMP/msg-badpol.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/sig-wrongmsg.bin" "$TMP/msg711.bin"

# raw .pcrsig JSON fixtures in the systemd-measure sign shape (existing fields only)
pcrsig_make() { # OUT POL SIGBIN PCRSLIST PKFP
    _pm_b64=$(openssl base64 -A -in "$3")
    jq -n --arg pol "$2" --arg sig "$_pm_b64" --argjson pcrs "$4" --arg pkfp "$5" \
        '{"sha256": [{"pcrs": $pcrs, "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$1"
}
PKFP=$(policy_pubkey_fp "$KEYDIR/release.pub")
[ -n "$PKFP" ] || {
    echo "FAIL: cannot fingerprint the release public key" >&2
    exit 1
}
pcrsig_make "$TMP/pcrsig-11.json" "$POL11" "$TMP/sig11.bin" '[11]' "$PKFP"
pcrsig_make "$TMP/pcrsig-711.json" "$POL711" "$TMP/sig711.bin" '[7, 11]' "$PKFP"
# tampered: sig does not verify over the embedded pol (sig is over a DIFFERENT message)
pcrsig_make "$TMP/pcrsig-badsig.json" "$POL11" "$TMP/sig-wrongmsg.bin" '[11]' "$PKFP"
# tampered: pol replaced with zeros — but the sig VALIDLY signs the zeros digest
pcrsig_make "$TMP/pcrsig-badpol.json" "$BADPOL" "$TMP/sig-badpol.bin" '[11]' "$PKFP"

# foreign-key variant: same pol digest, signed by a DIFFERENT key (G-B6)
openssl genrsa -out "$KEY2/release.pem" 2048 2>/dev/null
openssl rsa -in "$KEY2/release.pem" -pubout -out "$KEY2/release.pub" 2>/dev/null
openssl dgst -sha256 -sign "$KEY2/release.pem" -out "$TMP/sig-fgn.bin" "$TMP/msg11.bin"
pcrsig_make "$TMP/pcrsig-foreign.json" "$POL11" "$TMP/sig-fgn.bin" '[11]' "$PKFP"

# --- real file-backed LUKS2 container (recovery slot 0) ---------------------------------
LUKS=$TMP/luks.img
LUKS_UUID=
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
LUKS_UUID=$(cryptsetup luksUUID "$LUKS" 2>/dev/null)
[ -n "$LUKS_UUID" ] || {
    echo "FAIL: LUKS2 fixture did not format" >&2
    exit 1
}

# --- raw unseal oracle (test-local, mirrors pcrsign_policyauthorize_accept.sh) ---------
RAW_PRIV=$TMP/raw-priv.bin
RAW_PUB=$TMP/raw-pub.bin
blob_extract() { # TOKENJSON — split tpm2-blob into priv/pub halves (the priv
    # half KEEPS its TPM2B length prefix — tpm2_load consumes the TPM2B form)
    printf '%s' "$(jq -r '.["tpm2-blob"]' "$1")" | openssl base64 -d -A >"$TMP/blob.bin"
    _be_plen=$((0x$(xxd -p -l 2 "$TMP/blob.bin")))
    dd if="$TMP/blob.bin" of="$RAW_PRIV" bs=1 count=$((2 + _be_plen)) status=none
    dd if="$TMP/blob.bin" of="$RAW_PUB" bs=1 skip=$((2 + _be_plen)) status=none
}
raw_unseal() { # TOKENJSON SELECTION MSGBIN SIGBIN NAMEBIN OUTFILE -> rc 0 iff the TPM unseals
    _ru_tok=$1 _ru_sel=$2 _ru_msg=$3 _ru_sig=$4 _ru_name=$5 _ru_out=$6
    blob_extract "$_ru_tok"
    flushall
    tpm loadexternal -C o -G rsa -u "$KEYDIR/release.pub" -c "$TMP/ru-ro.ctx" >/dev/null 2>&1 || return 1
    tpm verifysignature -c "$TMP/ru-ro.ctx" -m "$_ru_msg" -s "$_ru_sig" \
        -f rsassa -g sha256 -t "$TMP/ru-tick.bin" >/dev/null 2>&1 || return 1
    flushall
    tpm createprimary -C o -g sha256 -G rsa -c "$TMP/ru-p.ctx" >/dev/null 2>&1 || return 1
    tpm load -C "$TMP/ru-p.ctx" -u "$RAW_PUB" -r "$RAW_PRIV" -c "$TMP/ru-s.ctx" >/dev/null 2>&1 || return 1
    flushall
    tpm startauthsession --policy-session -S "$TMP/ru-us.ctx" >/dev/null 2>&1 || return 1
    tpm policypcr -S "$TMP/ru-us.ctx" -l "sha256:$_ru_sel" >/dev/null 2>&1 || return 1
    tpm policyauthorize -S "$TMP/ru-us.ctx" -i "$_ru_msg" -n "$_ru_name" -t "$TMP/ru-tick.bin" >/dev/null 2>&1 || return 1
    tpm unseal -c "$TMP/ru-s.ctx" -p "session:$TMP/ru-us.ctx" -o "$_ru_out" >/dev/null 2>&1
    _ru_rc=$?
    flushall
    return "$_ru_rc"
}
assert_no_token() { # DESC PATH
    if [ -e "$2" ]; then assert_eq "$1 (no token written)" "absent" "present"; else assert_eq "$1 (no token written)" "absent" "absent"; fi
}
assert_no_pass() { # DESC
    assert_eq "$1 (no passphrase staged)" "" "$(find "$TMP/tmp" -name 'debian-fde-seal-pass.*' -print -quit)"
}

# --- 1. preconditions (fail-closed 64, nothing staged) ---------------------------------
NK=$TMP/no-such-keydir
NKOUT=$TMP/nk-token.json
rm -f "$NKOUT"

( seal_provisional "$NK" "$LUKS" "$TMP/pcrsig-11.json" "$NKOUT" ) 2>/dev/null
assert_rc "missing keydir -> die 64" 64 $?
assert_no_token "missing keydir" "$NKOUT"

BADK=$TMP/bad-keydir
mkdir -p "$BADK"
( seal_provisional "$BADK" "$LUKS" "$TMP/pcrsig-11.json" "$NKOUT" ) 2>/dev/null
assert_rc "keydir without release.pub -> die 64" 64 $?
assert_no_token "keydir without release.pub" "$NKOUT"

( seal_provisional "$KEYDIR" "$LUKS" "$TMP/no-such.pcrsig.json" "$NKOUT" ) 2>/dev/null
assert_rc "missing .pcrsig -> die 64" 64 $?
assert_no_token "missing .pcrsig" "$NKOUT"

( DEBIAN_FDE_TCTI=swtpm:path=$TMP/definitely-not-here/sock seal_provisional \
    "$KEYDIR" "$LUKS" "$TMP/pcrsig-11.json" "$NKOUT" ) 2>/dev/null
assert_rc "unusable TCTI -> die 64" 64 $?
assert_no_token "unusable TCTI" "$NKOUT"
assert_no_pass "precondition negatives"

# --- 2. the 11-only digest formula == live TPM trial session (normative oracle) --------
flushall
tpm startauthsession --policy-session -S "$TMP/t11.ctx" >/dev/null 2>&1
tpm policypcr -S "$TMP/t11.ctx" -l sha256:11 >/dev/null 2>&1
LIVE11=$(tpm getpolicydigest -S "$TMP/t11.ctx" --hex 2>/dev/null | awk '{print $NF}' | sed 's/^0x//')
flushall
assert_eq "seal_digest_11 == live PolicyPCR{11} session digest" "$LIVE11" "$(seal_digest_11 "$D11")"

# --- 3. seal_provisional happy path ------------------------------------------------------
TOK11=$TMP/token-prov.json
rm -f "$TOK11"
SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE=''
seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig-11.json" "$TOK11"
assert_rc "seal_provisional rc 0" 0 $?
[ -e "$TOK11" ] && assert_eq "provisional token written" "present" "present" ||
    assert_eq "provisional token written" "present" "absent"
assert_eq "token type" "systemd-tpm2" "$(jq -r '.type' "$TOK11")"
assert_eq "provisional pcrs are [11]" "[11]" "$(jq -c '.["tpm2-pcrs"]' "$TOK11")"
assert_eq "pcr bank sha256" "sha256" "$(jq -r '.["tpm2-pcr-bank"]' "$TOK11")"
assert_eq "keyslots shape [\"1\"] (slot != 0)" '["1"]' "$(jq -c '.keyslots' "$TOK11")"
assert_eq "token signature == .pcrsig signature" \
    "$(jq -r '.sha256[0].sig' "$TMP/pcrsig-11.json")" "$(jq -r '.["tpm2-signature"]' "$TOK11")"
DER=$(openssl pkey -pubin -in "$KEYDIR/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
assert_eq "token pubkey is the b64 DER of release.pub" "$DER" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")"
[ -n "$SEAL_PASS_FILE" ] && [ -f "$SEAL_PASS_FILE" ] &&
    assert_eq "passphrase staged" "present" "present" ||
    assert_eq "passphrase staged" "present" "absent"
assert_eq "passphrase staged under DEBIAN_FDE_TMPDIR (I1)" "1" \
    "$(case $SEAL_PASS_FILE in "$TMP/tmp"/*) echo 1;; *) echo 0;; esac)"
assert_eq "passphrase file mode 600" "600" "$(stat -c %a "$SEAL_PASS_FILE")"
assert_eq "passphrase is >= 256-bit (64 hex chars)" "64" "$(tr -d '\n' <"$SEAL_PASS_FILE" | wc -c)"
assert_eq "approved policy digest pinned == fixture pol" "$POL11" "$SEAL_POL"
assert_eq "SEAL_MODE" "provisional" "$SEAL_MODE"
PROV_PASS_FILE=$SEAL_PASS_FILE
PROV_PASS=$(cat "$PROV_PASS_FILE")

# the blob in the token is the real sealed object: unseal oracle via the raw chain
blob_extract "$TOK11"
flushall
tpm loadexternal -C n -G rsa -u "$KEYDIR/release.pub" -c "$TMP/nul.ctx" -n "$TMP/name.bin" >/dev/null 2>&1
flushall
raw_unseal "$TOK11" 11 "$TMP/msg11.bin" "$TMP/sig11.bin" "$TMP/name.bin" "$TMP/unsealed.txt"
assert_rc "raw tpm2_unseal of the token blob succeeds under {11} session" 0 $?
assert_eq "unsealed bytes == staged random volume passphrase" \
    "$(cat "$SEAL_PASS_FILE")" "$(cat "$TMP/unsealed.txt")"

# lib-level unseal helper round-trips too
seal_unseal "$KEYDIR" "$TMP/pcrsig-11.json" provisional "$TOK11" "$TMP/unsealed2.txt"
assert_rc "seal_unseal(provisional) rc 0" 0 $?
assert_eq "seal_unseal output == staged passphrase" "$(cat "$SEAL_PASS_FILE")" "$(cat "$TMP/unsealed2.txt")"

# --- 4. seal_finalized happy path ---------------------------------------------------------
TOK711=$TMP/token-fin.json
rm -f "$TOK711"
seal_finalized "$KEYDIR" "$LUKS" "$TMP/pcrsig-711.json" "$TOK711"
assert_rc "seal_finalized rc 0" 0 $?
assert_eq "finalized pcrs are [7, 11]" "[7,11]" "$(jq -c '.["tpm2-pcrs"]' "$TOK711")"
assert_eq "finalized approved digest == policy_digest(d7_live, d11_live)" "$POL711" "$SEAL_POL"
assert_eq "finalized keyslot != 0" "1" "$SEAL_SLOT"
raw_unseal "$TOK711" 7,11 "$TMP/msg711.bin" "$TMP/sig711.bin" "$TMP/name.bin" "$TMP/unsealed-fin.txt"
assert_rc "raw tpm2_unseal of the finalized blob succeeds under {7,11} session" 0 $?
assert_eq "finalized unseal bytes == its staged passphrase" \
    "$(cat "$SEAL_PASS_FILE")" "$(cat "$TMP/unsealed-fin.txt")"

# --- 5. G-B6: enroll-side signature rejection — die 64, NOTHING written --------------------
NW=$TMP/neg-token.json
rm -f "$NW"
PASS_BEFORE=$(find "$TMP/tmp" -name 'debian-fde-seal-pass.*' | sort)

( seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig-711.json" "$NW" ) 2>/dev/null
assert_rc "provisional rejects a {7,11}-signed .pcrsig (wrong selection)" 64 $?
assert_no_token "wrong-selection provisional" "$NW"
( seal_finalized "$KEYDIR" "$LUKS" "$TMP/pcrsig-11.json" "$NW" ) 2>/dev/null
assert_rc "finalized rejects an 11-only .pcrsig (wrong selection)" 64 $?
assert_no_token "wrong-selection finalized" "$NW"
( seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig-badsig.json" "$NW" ) 2>/dev/null
assert_rc "signature that does not verify over the embedded pol -> die 64" 64 $?
assert_no_token "bad signature" "$NW"
( seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig-badpol.json" "$NW" ) 2>/dev/null
assert_rc "pol mismatching the freshly computed digest -> die 64" 64 $?
assert_no_token "bad pol" "$NW"
( seal_provisional "$KEYDIR" "$LUKS" "$TMP/pcrsig-foreign.json" "$NW" ) 2>/dev/null
assert_rc "foreign-key signature -> die 64" 64 $?
assert_no_token "foreign-key signature" "$NW"
assert_eq "G-B6 negatives staged NO passphrase" "$PASS_BEFORE" \
    "$(find "$TMP/tmp" -name 'debian-fde-seal-pass.*' | sort)"

# --- 6. PCR-drift negatives (observed at the TPM) --------------------------------------------
# (a) PCR 7 drift: the finalized construction refuses a missing-PCR7 state
swtpm_pcrextend "$TPMDIR" 7 3232323232323232323232323232323232323232323232323232323232323232
raw_unseal "$TOK711" 7,11 "$TMP/msg711.bin" "$TMP/sig711.bin" "$TMP/name.bin" "$TMP/drift7.txt"
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "PCR 7 drift: finalized session unseal REFUSED" "refused" "refused" ||
    assert_eq "PCR 7 drift: finalized session unseal REFUSED" "refused" "accepted"
( seal_finalized "$KEYDIR" "$LUKS" "$TMP/pcrsig-711.json" "$NW" ) 2>/dev/null
assert_rc "finalized seal with drifted PCR 7 (stale signed d7) -> die 64" 64 $?
assert_no_token "drifted-finalized seal" "$NW"
# (b) PCR 11 drift: both modes' session unseals must fail
swtpm_pcrextend "$TPMDIR" 11 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
raw_unseal "$TOK11" 11 "$TMP/msg11.bin" "$TMP/sig11.bin" "$TMP/name.bin" "$TMP/drift11a.txt"
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "PCR 11 drift: provisional session unseal REFUSED" "refused" "refused" ||
    assert_eq "PCR 11 drift: provisional session unseal REFUSED" "refused" "accepted"
raw_unseal "$TOK711" 7,11 "$TMP/msg711.bin" "$TMP/sig711.bin" "$TMP/name.bin" "$TMP/drift11b.txt"
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "PCR 11 drift: finalized session unseal REFUSED" "refused" "refused" ||
    assert_eq "PCR 11 drift: finalized session unseal REFUSED" "refused" "accepted"

# --- 7. LUKS2 choreography on the real container (G-B5 primitives) --------------------------
# A standing provisional token is not enough: the random volume passphrase must
# wrap a NEW keyslot and the token must reference it. Assert OBSERVED effects.
PRE7=$TMP/pre7.json
POST7=$TMP/post7.json
token_dump "$LUKS" "$PRE7"
SLOT=$(token_free_slot "$LUKS")
assert_eq "first free keyslot after format is 1" "1" "$SLOT"
token_add_keyslot "$LUKS" "$PROV_PASS_FILE" "$SLOT" "$TMP/k0"
assert_rc "luksAddKey added keyslot 1 with the staged passphrase" 0 $?
TID=$(token_next_id "$LUKS")
token_import "$LUKS" "$TOK11" "$TID"
assert_rc "atomic token import rc 0" 0 $?
token_dump "$LUKS" "$POST7"
assert_eq "exactly one systemd-tpm2 token in LUKS2 metadata" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$POST7")"
assert_eq "token references keyslot 1" '["1"]' \
    "$(jq -c 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value.keyslots)' "$POST7")"
printf '%s' "$PROV_PASS" >"$TMP/unlock-prov"
cryptsetup open --test-passphrase --key-slot 1 --key-file "$TMP/unlock-prov" "$LUKS" 2>/dev/null
assert_rc "the UNSEALED passphrase unlocks the new keyslot (observed effect)" 0 $?
token_post_assert "$PRE7" "$POST7" \
    "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1
assert_rc "token_post_assert (provisional) passes on the real metadata" 0 $?

# post-assert negatives (tamper matrix)
jq '.keyslots["0"].kdf.salt = "VEFNUVJFRUQ="' "$POST7" >"$TMP/post-s0.json"
token_post_assert "$PRE7" "$TMP/post-s0.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1 2>/dev/null
assert_rc "post-assert: recovery slot 0 modified -> refuse" 1 $?
jq --arg t "$TID" '.tokens[$t].keyslots = ["0"]' "$POST7" >"$TMP/post-slot0.json"
token_post_assert "$PRE7" "$TMP/post-slot0.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1 2>/dev/null
assert_rc "post-assert: token bound to slot 0 -> refuse" 1 $?
jq --arg t "$TID" '.tokens[$t]["tpm2-pubkey"] = "Rk9SRUlHTg=="' "$POST7" >"$TMP/post-pub.json"
token_post_assert "$PRE7" "$TMP/post-pub.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1 2>/dev/null
assert_rc "post-assert: foreign pubkey in token -> refuse" 1 $?
jq --arg t "$TID" '.tokens[$t]["tpm2-pcrs"] = [7, 11]' "$POST7" >"$TMP/post-pcrs.json"
token_post_assert "$PRE7" "$TMP/post-pcrs.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1 2>/dev/null
assert_rc "post-assert: wrong pcrs for mode -> refuse" 1 $?
jq --arg t "$TID" '.tokens["9"] = .tokens[$t]' "$POST7" >"$TMP/post-two.json"
token_post_assert "$PRE7" "$TMP/post-two.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK11")" '[11]' 1 2>/dev/null
assert_rc "post-assert: two systemd-tpm2 tokens -> refuse" 1 $?

# --- 8. seal_upgrade_token (ADR-20 Stage 3): provisional -> {7,11} swap ----------------------
UPG=$TMP/token-upgraded.json
rm -f "$UPG"
D7N=$(pcr_hex 7)
D11N=$(pcr_hex 11)
policy_sign_json "$D7N" "$D11N" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$TMP/pcrsig-711-now.json"
seal_upgrade_token "$KEYDIR" "$LUKS" "$TMP/pcrsig-711-now.json" "$UPG" "$TMP/k0"
assert_rc "seal_upgrade_token rc 0" 0 $?
UPGPOST=$TMP/upg-post.json
token_dump "$LUKS" "$UPGPOST"
assert_eq "upgrade: exactly ONE systemd-tpm2 token remains" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$UPGPOST")"
assert_eq "upgrade: final token is the {7,11} construction" "[7,11]" \
    "$(jq -c 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pcrs"])' "$UPGPOST")"
NEWSLOT=$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value.keyslots[0])' "$UPGPOST")
[ -n "$NEWSLOT" ] && [ "$NEWSLOT" != "0" ] && [ "$NEWSLOT" != "1" ] &&
    assert_eq "upgrade: token bound to a fresh slot ($NEWSLOT), provisional slot 1 retired" "fresh" "fresh" ||
    assert_eq "upgrade: token bound to a fresh slot, provisional slot 1 retired" "fresh" "got:$NEWSLOT"
assert_eq "upgrade: provisional keyslot 1 is GONE" "false" \
    "$(jq -r '(.keyslots // {}) | has("1")' "$UPGPOST")"
assert_eq "upgrade: recovery slot 0 byte-identical" \
    "$(jq -rS '.keyslots["0"]' "$PRE7")" "$(jq -rS '.keyslots["0"]' "$UPGPOST")"
# the upgraded seal is a REAL {7,11} seal: unseal returns a passphrase that
# unlocks the fresh slot, and the OLD provisional passphrase unlocks nothing
seal_unseal "$KEYDIR" "$TMP/pcrsig-711-now.json" finalized "$UPG" "$TMP/upg-pass"
assert_rc "upgrade: seal_unseal(finalized) of the new token rc 0" 0 $?
cryptsetup open --test-passphrase --key-slot "$NEWSLOT" --key-file "$TMP/upg-pass" "$LUKS" 2>/dev/null
assert_rc "upgrade: the new passphrase unlocks the new keyslot" 0 $?
cryptsetup open --test-passphrase --key-slot 1 --key-file "$TMP/unlock-prov" "$LUKS" 2>/dev/null
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "upgrade: the retired provisional passphrase unlocks NOTHING" "dead" "dead" ||
    assert_eq "upgrade: the retired provisional passphrase unlocks NOTHING" "dead" "still-valid"
swtpm_stop "$TPMDIR" || true

finish
