#!/usr/bin/env bash
# tests/unit/seal_rotation_reanchor.sh — G-B7 (§9.6): the enrollment key source
# is KEYDIR-explicit (aligned with pcrsign's --keydir resolution), never
# baseline-pinned, so the K1 -> K2 release-key rotation + re-enroll anchors the
# seal under K2. Real swtpm + real file-backed LUKS2 container + the REAL CLI:
#   * seal under K1 -> standing enrollment (K1-anchored session unseals)
#   * swap ALPINE_FDE_KEYDIR to K2 (baseline STILL pins the K1 pub path — the
#     decoy proves enroll never consults it) -> re-enroll
#   * the fresh token's pubkey is K2; a K2-anchored session unseals the fresh
#     blob and its passphrase unlocks the fresh keyslot
#   * a K1-anchored session REFUSES: the sealed policy pins K2's keyName, so
#     the K1 ticket cannot satisfy PolicyAuthorize (I3 fail-closed)
#   * the retired K1 passphrase unlocks nothing (old slot killed in the same
#     run the fresh seal stood)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd" # BEFORE seal.sh (sibling resolution)
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
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/alpine-fde-rotation.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp" "$TMP/by-uuid" "$TMP/efivars" "$TMP/root/etc/alpine-fde"
ALPINE_FDE_TMPDIR=$TMP/tmp

# ADR-16: the enroll path fails closed on any release key < RSA-3072, so both
# rotation credentials are hermetic suite-generated RSA-3072 keydirs (same
# release.pem/release.pub/release.crt shaping as keys_rsa3072_chain.sh) — the
# shared fixtures/keys dir stays RSA-2048 and is never used here
new_keydir() { # DIR CN — complete keydir contract for one rotation credential
    mkdir -p "$1"
    openssl genrsa -out "$1/release.pem" 3072 2>/dev/null
    openssl pkey -in "$1/release.pem" -pubout -out "$1/release.pub" 2>/dev/null
    openssl req -new -x509 -key "$1/release.pem" -out "$1/release.crt" \
        -subj "/CN=$2" 2>/dev/null
    [ -s "$1/release.pem" ] && [ -s "$1/release.pub" ] && [ -s "$1/release.crt" ] || {
        echo "FAIL: cannot generate the RSA-3072 rotation keydir $1" >&2
        exit 1
    }
}
K1=$TMP/key1
K2=$TMP/key2
new_keydir "$K1" alpine-fde-rotation-k1
new_keydir "$K2" alpine-fde-rotation-k2

TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
export ALPINE_FDE_TCTI=$SWTPM_TCTI

swtpm_pcrextend "$TPMDIR" 7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
swtpm_pcrextend "$TPMDIR" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc
pcr_hex() {
    tpm pcrread -Q -o "$TMP/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$TMP/pcr.bin" | tr -d ' \n'
}
D7=$(pcr_hex 7)
D11=$(pcr_hex 11)

# --- real LUKS2 container + lifecycle env -----------------------------------------
LUKS=$TMP/luks.img
UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
truncate -s 32M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
ln -sf "$LUKS" "$TMP/by-uuid/$UUID"
printf '\007\000\000\000\001' >"$TMP/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf '\007\000\000\000\000' >"$TMP/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
# baseline via the real writer; keys.release_pub_path deliberately still pins
# K1 — the DECOY proving the enrollment is KEYDIR-explicit (G-B7)
BL_PCR0="$D7" BL_PCR1="$D7" BL_PCR2="$D7" BL_PCR3="$D7" BL_PCR7="$D7" \
    BL_KEYS_RELEASE_PUB_PATH="$K1/release.pub" \
    BL_TARGET_LUKS_UUID="$UUID" \
    baseline_write "$TMP/root/etc/alpine-fde/baseline.json"

fde() { # KEYDIR args... — the production CLI against the real container
    local kd=$1
    shift
    ALPINE_FDE_BIN_TEST=1 \
        ALPINE_FDE_ROOT="$TMP/root" \
        ALPINE_FDE_EFIVARS_DIR="$TMP/efivars" \
        ALPINE_FDE_BY_UUID_DIR="$TMP/by-uuid" \
        ALPINE_FDE_KEYDIR="$kd" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_ENROLL_LOCK="$TMP/enroll.lock" \
        ALPINE_FDE_TMPDIR="$TMP/tmp" \
        ALPINE_FDE_LUKS_KEYFILE="$TMP/k0" \
        "$REPO/bin/alpine-fde" "$@"
}
token_doc() { # DUMPFILE OUT — extract the first systemd-tpm2 token document
    jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value)' "$1" >"$2"
}

# --- K1 .pcrsig + K1-sealed enrollment --------------------------------------------
policy_sign_json "$D7" "$D11" "$K1/release.pem" "$K1/release.pub" "$TMP/pcrsig-k1.json"
fde "$K1" enroll-tpm --uuid "$UUID" --pcrsig "$TMP/pcrsig-k1.json" 2>"$TMP/enroll-k1.err"
ENROLL_K1_RC=$?
assert_rc "K1 enrollment (explicit pcrsig) rc 0" 0 $ENROLL_K1_RC

DUMP1=$TMP/dump1.json
cryptsetup luksDump --dump-json-metadata "$LUKS" >"$DUMP1"
assert_eq "K1: exactly one systemd-tpm2 token" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$DUMP1")"
K1_DER=$(openssl pkey -pubin -in "$K1/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
assert_eq "K1: token pubkey is the K1 release key" "$K1_DER" \
    "$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pubkey"])' "$DUMP1")"

token_doc "$DUMP1" "$TMP/tok-k1.json"
seal_unseal "$K1" "$TMP/pcrsig-k1.json" finalized "$TMP/tok-k1.json" "$TMP/pass-k1"
assert_rc "K1-anchored session unseals the standing blob" 0 $?
K1_SLOT=$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value.keyslots[0])' "$DUMP1")
cryptsetup open --test-passphrase --key-slot "$K1_SLOT" --key-file "$TMP/pass-k1" "$LUKS" 2>/dev/null
assert_rc "K1 passphrase unlocks its keyslot (pre-rotation sanity)" 0 $?

# --- rotation: swap the KEYDIR to K2 (baseline still pins K1!) and re-enroll ------
fde "$K2" enroll-tpm --uuid "$UUID" 2>"$TMP/enroll-k2.err"
ENROLL_K2_RC=$?
assert_rc "K2 re-enrollment rc 0 (standing K1 token retired in the same run)" 0 $ENROLL_K2_RC
# the pcrsig for K2 did not exist — the in-process re-sign fallback from the
# K2 keydir is the G-B7 contract; assert the error capture if it failed
if [ "$ENROLL_K2_RC" -ne 0 ]; then
    echo "--- K2 enroll stderr:" >&2
    cat "$TMP/enroll-k2.err" >&2
fi

DUMP2=$TMP/dump2.json
cryptsetup luksDump --dump-json-metadata "$LUKS" >"$DUMP2"
assert_eq "K2: exactly one systemd-tpm2 token remains" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$DUMP2")"
K2_DER=$(openssl pkey -pubin -in "$K2/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
assert_eq "rotation: token pubkey is now K2" "$K2_DER" \
    "$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pubkey"])' "$DUMP2")"
assert_eq "rotation: enrolled.json records the K2 keydir pub" "$K2/release.pub" \
    "$(jq -r '.pubkey' "$TMP/root/etc/alpine-fde/enrolled.json")"
K2_SLOT=$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value.keyslots[0])' "$DUMP2")
[ -n "$K2_SLOT" ] && [ "$K2_SLOT" != "0" ] && [ "$K2_SLOT" != "$K1_SLOT" ] &&
    assert_eq "rotation: token bound to a FRESH slot ($K2_SLOT != $K1_SLOT)" "fresh" "fresh" ||
    assert_eq "rotation: token bound to a FRESH slot" "fresh" "got:$K2_SLOT"
assert_eq "rotation: the K1 keyslot was retired" "false" \
    "$(jq -r --arg k "$K1_SLOT" '(.keyslots // {}) | has($k)' "$DUMP2")"
assert_eq "rotation: recovery slot 0 untouched" \
    "$(jq -rS '.keyslots["0"]' "$DUMP1")" "$(jq -rS '.keyslots["0"]' "$DUMP2")"

# K2-anchored session unseals the fresh blob; the passphrase unlocks the slot
token_doc "$DUMP2" "$TMP/tok-k2.json"
policy_sign_json "$D7" "$D11" "$K2/release.pem" "$K2/release.pub" "$TMP/pcrsig-k2-verify.json"
seal_unseal "$K2" "$TMP/pcrsig-k2-verify.json" finalized "$TMP/tok-k2.json" "$TMP/pass-k2"
assert_rc "K2-anchored session unseals the re-anchored blob" 0 $?
cryptsetup open --test-passphrase --key-slot "$K2_SLOT" --key-file "$TMP/pass-k2" "$LUKS" 2>/dev/null
assert_rc "the K2-sealed passphrase unlocks the fresh keyslot" 0 $?

# K1-anchored session REFUSES against the K2-pinned blob (keyName mismatch)
seal_unseal "$K1" "$TMP/pcrsig-k1.json" finalized "$TMP/tok-k2.json" "$TMP/pass-k1-stale" 2>/dev/null
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "K1-anchored session REFUSES the K2 seal (fail-closed, I3)" "refused" "refused" ||
    assert_eq "K1-anchored session REFUSES the K2 seal (fail-closed, I3)" "refused" "accepted"
# the retired K1 passphrase unlocks nothing anymore
cryptsetup open --test-passphrase --key-slot "$K1_SLOT" --key-file "$TMP/pass-k1" "$LUKS" 2>/dev/null
_rc=$?
[ "$_rc" -ne 0 ] && assert_eq "the retired K1 passphrase unlocks NOTHING" "dead" "dead" ||
    assert_eq "the retired K1 passphrase unlocks NOTHING" "dead" "still-valid"

finish
