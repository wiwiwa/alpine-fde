#!/usr/bin/env bash
# tests/integration/keys_rsa3072_chain.sh — ADR-16 release-key strength gate (RSA
# >= 3072 bits) + the 3072-bit seal chain end-to-end:
#   * a test-time-generated 3072-bit release keydir passes keys_check, and
#     keys_rsa_bits reports 3072; its TPMT_PUBLIC (keys_tpmt_public) pins
#     keyBits=3072 (0x0c00) at the marshaled offset and loads on the TPM
#     (keys_keyname) — the §6.1.1 step 4b keyName area stays well-formed
#   * 3072-bit chain: seal_provisional -> seal_unseal round-trip against the
#     swtpm fixture with a file-backed LUKS2 container returns EXACTLY the
#     staged random volume passphrase
#   * keys_check stays size-blind (completeness contract used by ukictl build)
#   * the ENROLL PATH ENTRY (enrl_preconditions) refuses a 2048-bit release key
#     fail-closed rc 2 citing ADR-16 (fail-closed at enroll, orchestrator
#     decision) — red-first: today it would pass
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
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
# shellcheck source=../../lib/cmd/enroll-tpm.sh
source "$REPO/lib/cmd/enroll-tpm.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/alpine-fde-rsa3072.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp # seal staging must land HERE
export ALPINE_FDE_ROOT=$TMP/root
mkdir -p "$(sp_etc_dir)"

# --- key fixtures (generated at test time; keep runtime sane: one 3072 + one 2048)
KEY3072=$TMP/keys3072
KEY2048=$TMP/keys2048
mkdir -p "$KEY3072" "$KEY2048"
openssl genrsa -out "$KEY3072/release.pem" 3072 2>/dev/null
openssl pkey -in "$KEY3072/release.pem" -pubout -out "$KEY3072/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEY3072/release.pem" -out "$KEY3072/release.crt" \
    -subj /CN=alpine-fde-rsa3072-ci 2>/dev/null
openssl genrsa -out "$KEY2048/release.pem" 2048 2>/dev/null
openssl pkey -in "$KEY2048/release.pem" -pubout -out "$KEY2048/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEY2048/release.pem" -out "$KEY2048/release.crt" \
    -subj /CN=alpine-fde-rsa2048-negative 2>/dev/null
for _k in "$KEY3072" "$KEY2048"; do
    [ -s "$_k/release.pem" ] && [ -s "$_k/release.pub" ] || {
        echo "FAIL: key generation failed for $_k" >&2
        exit 1
    }
done

# --- swtpm + live PCR state -----------------------------------------------------------
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI
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

# --- file-backed LUKS2 container (recovery slot 0) -------------------------------------
LUKS=$TMP/luks.img
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
[ -n "$(cryptsetup luksUUID "$LUKS" 2>/dev/null)" ] || {
    echo "FAIL: LUKS2 fixture did not format" >&2
    exit 1
}

# --- 1. the 3072-bit release key: size report, keydir check, TPMT_PUBLIC ---------------
assert_eq "keys_rsa_bits reports 3072 for the 3072-bit key" "3072" \
    "$(keys_rsa_bits "$KEY3072/release.pub")"
keys_check "$KEY3072"
assert_rc "keys_check passes for the complete 3072-bit keydir" 0 $?
# keys_check is the COMPLETENESS contract (ukictl build loud-fail marker) and
# stays size-blind; the SIZE policy is enforced at the enroll path entry (below)
keys_check "$KEY2048"
assert_rc "keys_check stays size-blind (2048 keydir passes completeness)" 0 $?

keys_tpmt_public "$KEY3072/release.pub" "$TMP/rel3072.tpm2b"
assert_rc "keys_tpmt_public builds the 3072-bit public area" 0 $?
# TPM2B_PUBLIC = 2-byte total length + TPMT_PUBLIC; keyBits sits after the
# 14-byte fixed header (type+nameAlg+attrs+authPolicy+symmetric+scheme)
assert_eq "tpmt public area pins keyBits=3072 (0x0c00)" "0c00" \
    "$(xxd -p -s 16 -l 2 "$TMP/rel3072.tpm2b")"
keys_keyname "$KEY3072/release.pub" "$TMP/rel3072.name"
assert_rc "the 3072-bit public area loads on the TPM (keyName computable)" 0 $?
[ -s "$TMP/rel3072.name" ] &&
    assert_eq "keyName reported for the 3072-bit area" "present" "present" ||
    assert_eq "keyName reported for the 3072-bit area" "present" "absent"

# --- 2. 3072-bit seal chain: seal_provisional -> seal_unseal round-trip -----------------
POL11=$(seal_digest_11 "$D11")
printf '%s' "$POL11" | policy_hex_to_bin >"$TMP/msg11.bin"
openssl dgst -sha256 -sign "$KEY3072/release.pem" -out "$TMP/sig11.bin" "$TMP/msg11.bin"
PKFP=$(policy_pubkey_fp "$KEY3072/release.pub")
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$TMP/sig11.bin")" --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$TMP/pcrsig-11.json"
TOK=$TMP/token3072.json
rm -f "$TOK"
SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE=''
seal_provisional "$KEY3072" "$LUKS" "$TMP/pcrsig-11.json" "$TOK"
assert_rc "seal_provisional with the 3072-bit release key rc 0" 0 $?
[ -e "$TOK" ] &&
    assert_eq "3072-bit provisional token written" "present" "present" ||
    assert_eq "3072-bit provisional token written" "present" "absent"
[ -n "$SEAL_PASS_FILE" ] && [ -f "$SEAL_PASS_FILE" ] &&
    assert_eq "passphrase staged by the 3072-bit seal" "present" "present" ||
    assert_eq "passphrase staged by the 3072-bit seal" "present" "absent"
PROV_PASS=$(cat "$SEAL_PASS_FILE")
seal_unseal "$KEY3072" "$TMP/pcrsig-11.json" provisional "$TOK" "$TMP/unsealed.txt"
assert_rc "seal_unseal(3072 key, provisional) rc 0" 0 $?
assert_eq "unsealed bytes == staged random volume passphrase" "$PROV_PASS" \
    "$(cat "$TMP/unsealed.txt")"
keys_scrub "$SEAL_PASS_FILE"

# --- 3. ADR-16 gate at the ENROLL PATH ENTRY (enrl_preconditions) ------------------------
# enroll precondition fixture: final baseline + SB on/SetupMode=0 + live PCR 7
# match + resolvable LUKS uuid (the guard fires right after the keydir check)
EFIVARS=$TMP/efivars
BYUUID=$TMP/by-uuid
UUID=12345678-90ab-cdef-1234-567890abcdef
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS
export ALPINE_FDE_BY_UUID_DIR=$BYUUID
mkdir -p "$EFIVARS" "$BYUUID"
mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkvar SecureBoot 1
mkvar SetupMode 0
: >"$BYUUID/$UUID"
BL_PCR0="$D7" BL_PCR1="$D7" BL_PCR2="$D7" BL_PCR3="$D7" BL_PCR7="$D7" \
    BL_TARGET_LUKS_UUID="$UUID" baseline_write "$(sp_baseline_file)"

ALPINE_FDE_KEYDIR=$KEY2048
PRE2048_OUT=$(enrl_preconditions 2>&1)
PRE2048_RC=$?
assert_eq "enroll path entry: 2048-bit release key -> refuse rc 2 (ADR-16)" "2" "$PRE2048_RC"
assert_contains "enroll-path refusal cites ADR-16" "$PRE2048_OUT" "ADR-16"
assert_contains "enroll-path refusal names the offending key size" "$PRE2048_OUT" "2048"
assert_contains "enroll-path refusal states the floor" "$PRE2048_OUT" "3072"

ALPINE_FDE_KEYDIR=$KEY3072
enrl_preconditions 2>"$TMP/pre3072.err"
assert_rc "enroll path entry: 3072-bit release key passes" 0 $?
assert_eq "resolved pubkey is the 3072-bit keydir's release.pub" "$KEY3072/release.pub" "$ENRL_PRE_PUB"

swtpm_stop "$TPMDIR" || true
finish
