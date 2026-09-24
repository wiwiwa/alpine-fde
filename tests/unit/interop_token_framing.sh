#!/usr/bin/env bash
# tests/unit/interop_token_framing.sh — ADR-19 interop conformance contract for
# the §7.2 token + the sealed-secret framing (the two deltas that made upstream
# systemd-cryptsetup 257 refuse the product token / reject its unsealed secret):
#
#   (a) the token JSON carries "tpm2-policy-hash" — 64 lowercase hex chars, the
#       digest the blob is ACTUALLY sealed under (policy_sealed_digest over the
#       release key's TPM Name) — plus "tpm2-primary-alg": "rsa" (upstream
#       defaults to an ECC SRK parent and would load the wrong template).
#       Upstream 257 token validation refuses the token unconditionally without
#       the field ("TPM2 token data lacks 'tpm2-policy-hash' field",
#       cryptsetup-token-systemd-tpm2.c / tpm2-util.c tpm2_parse_luks2_json).
#   (b) the FRAMING contract: the LUKS2 keyslot passphrase is
#       base64(unsealed secret) — upstream's plugin hands base64mem(secret) to
#       cryptsetup as the passphrase ("Before using this key as passphrase we
#       base64 encode it, for compat with homed"). The sealer therefore stages
#       SEAL_PASS_FILE in exactly that form: 64 canonical base64 chars (no
#       padding, no newline) of 48 raw random bytes (384-bit), and seal_unseal
#       emits the same form. token_post_assert refuses a metadata token without
#       a well-formed tpm2-policy-hash.
#   TPM-level round-trip proof (raw secret inside the blob == the base64
#   decode of the staged passphrase) lives in seal_mechanism_b.sh; the
#   upstream-consumes-it-all proof lives in interop_oracle_mechb.sh + s19/s20.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd" # BEFORE seal.sh (sibling resolution)
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
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/alpine-fde-token-framing.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp
KEYDIR=$REPO/fixtures/keys
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI

DER=$(openssl pkey -pubin -in "$KEYDIR/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
SEALHASH=$(printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')

# --- 1. the token carries the upstream-mandatory fields ----------------------
TOKU=$TMP/token-unit.json
rm -f "$TOKU"
token_build_json '[7, 11]' "$DER" "c2ln" "AAJhYg==" 1 "$SEALHASH" "$TOKU"
assert_rc "token_build_json rc 0" 0 $?
assert_eq "token: tpm2-policy-hash present" "present" \
    "$([[ -n "$(jq -r '.["tpm2-policy-hash"] // empty' "$TOKU")" ]] && echo present || echo absent)"
assert_eq "token: tpm2-policy-hash is the sealed digest" "$SEALHASH" \
    "$(jq -r '.["tpm2-policy-hash"]' "$TOKU")"
assert_eq "token: tpm2-policy-hash is 64 LOWERCASE hex chars" "yes" \
    "$(jq -r '.["tpm2-policy-hash"]' "$TOKU" | grep -qE '^[0-9a-f]{64}$' && echo yes || echo no)"
assert_eq "token: tpm2-primary-alg rsa (upstream defaults ECC SRK)" '"rsa"' \
    "$(jq -c '.["tpm2-primary-alg"]' "$TOKU")"
assert_eq "token: keyslots cross-reference [\"1\"]" '["1"]' "$(jq -c '.keyslots' "$TOKU")"

# the stored policy hash is the digest the blob is sealed under:
# policy_sealed_digest over the release key's VERIFYING TPM Name
NAME_HEX=$(keys_keyname_verifying "$KEYDIR/release.pub" "$TMP/name.hex" && tr -d ' \n' <"$TMP/name.hex")
[ -n "$NAME_HEX" ] && assert_eq "fixture: release key TPM Name computed" "present" "present" ||
    assert_eq "fixture: release key TPM Name computed" "present" "absent"
TOKL=$TMP/token-live-name.json
token_build_json '[7, 11]' "$DER" "c2ln" "AAJhYg==" 1 "$(policy_sealed_digest "$NAME_HEX")" "$TOKL"
assert_rc "token_build_json rc 0 (live keyName policy hash)" 0 $?
assert_eq "token: policy-hash == policy_sealed_digest(release keyName)" \
    "$(policy_sealed_digest "$NAME_HEX")" "$(jq -r '.["tpm2-policy-hash"]' "$TOKL")"

# fail-closed: a non-64-hex policy hash is refused, nothing written
TOKB=$TMP/token-bad.json
rm -f "$TOKB"
( token_build_json '[7, 11]' "$DER" "c2ln" "AAJhYg==" 1 "not-a-digest" "$TOKB" ) 2>/dev/null
assert_rc "token_build_json refuses a malformed policy hash (die 64)" 64 $?
assert_eq "token_build_json wrote nothing on refusal" "absent" \
    "$([[ -e "$TOKB" ]] && echo present || echo absent)"

# --- 2. token_post_assert refuses a token without tpm2-policy-hash ------------
PH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mk_meta() { # <out> <with_policy_hash:yes/no>
    if [ "$2" = "yes" ]; then
        jq -n --arg der "$DER" --arg ph "$PH" '{
            "keyslots": { "0": {"type": "luks2"}, "1": {"type": "luks2"} },
            "tokens": { "3": {"type": "systemd-tpm2", "keyslots": ["1"],
                               "tpm2-blob": "AAEAC0RhdGE=", "tpm2-pcrs": [7, 11],
                               "tpm2-pcr-bank": "sha256", "tpm2-pubkey": $der,
                               "tpm2-signature": "U0lH", "tpm2-policy-hash": $ph} }
        }' >"$1"
    else
        jq -n --arg der "$DER" '{
            "keyslots": { "0": {"type": "luks2"}, "1": {"type": "luks2"} },
            "tokens": { "3": {"type": "systemd-tpm2", "keyslots": ["1"],
                               "tpm2-blob": "AAEAC0RhdGE=", "tpm2-pcrs": [7, 11],
                               "tpm2-pcr-bank": "sha256", "tpm2-pubkey": $der,
                               "tpm2-signature": "U0lH"} }
        }' >"$1"
    fi
}
mk_meta "$TMP/post-pol.json" yes
mk_meta "$TMP/post-nopol.json" no
token_post_assert "$TMP/post-nopol.json" "$TMP/post-pol.json" "$DER" '[7,11]' 1
assert_rc "post-assert accepts a token carrying tpm2-policy-hash" 0 $?
token_post_assert "$TMP/post-nopol.json" "$TMP/post-nopol.json" "$DER" '[7,11]' 1 2>/dev/null
assert_rc "post-assert REFUSES a token lacking tpm2-policy-hash" 1 $?

# --- 3. framing: the staged passphrase IS base64(secret) -----------------------
SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE=''
ALPINE_FDE_SEAL_STAGE=$TMP/stage mkdir_dummy=$TMP/stage
mkdir -p "$TMP/stage"
ALPINE_FDE_SEAL_STAGE=$TMP/stage seal_gen_passphrase
assert_rc "seal_gen_passphrase rc 0" 0 $?
assert_eq "passphrase staged under the seal stage dir" "1" \
    "$(case $SEAL_PASS_FILE in "$TMP/stage"/*) echo 1;; *) echo 0;; esac)"
assert_eq "passphrase file mode 600" "600" "$(stat -c %a "$SEAL_PASS_FILE")"
assert_eq "passphrase has NO trailing newline (byte-exact consumers)" "64" \
    "$(tr -d '\n' <"$SEAL_PASS_FILE" | wc -c)"
assert_eq "passphrase is exactly 64 bytes on disk (no newline)" "64" "$(wc -c <"$SEAL_PASS_FILE")"
assert_eq "passphrase is canonical base64 (64 chars, no padding)" "yes" \
    "$(tr -d '\n' <"$SEAL_PASS_FILE" | grep -qE '^[A-Za-z0-9+/]{64}$' && echo yes || echo no)"
assert_eq "passphrase decodes to 48 raw bytes (384-bit secret)" "48" \
    "$(openssl base64 -d -A <"$SEAL_PASS_FILE" 2>/dev/null | wc -c)"
assert_eq "passphrase is NOT the legacy 64-hex form" "no" \
    "$(tr -d '\n' <"$SEAL_PASS_FILE" | grep -qE '^[0-9a-f]{64}$' && echo yes || echo no)"
# two stages never collide (randomness, not a pinned value)
PASS1=$(cat "$SEAL_PASS_FILE")
SEAL_PASS_FILE=''
ALPINE_FDE_SEAL_STAGE=$TMP/stage seal_gen_passphrase
PASS2=$(cat "$SEAL_PASS_FILE")
assert_eq "a second stage yields a DIFFERENT passphrase" "different" \
    "$([[ -n "$PASS1" && "$PASS1" != "$PASS2" ]] && echo different || echo same)"

# --- 4. hygiene ----------------------------------------------------------------
bash -n "$REPO/lib/token.sh" && assert_eq "lib/token.sh: bash -n clean" "0" "0" ||
    assert_eq "lib/token.sh: bash -n clean" "0" "1"
bash -n "$REPO/lib/seal.sh" && assert_eq "lib/seal.sh: bash -n clean" "0" "0" ||
    assert_eq "lib/seal.sh: bash -n clean" "0" "1"
bash -n "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" &&
    assert_eq "hooks/mkinitfs/alpine-fde-unseal.sh: bash -n clean" "0" "0" ||
    assert_eq "hooks/mkinitfs/alpine-fde-unseal.sh: bash -n clean" "0" "1"

finish
