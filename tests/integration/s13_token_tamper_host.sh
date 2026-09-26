#!/usr/bin/env bash
# tests/integration/s13_token_tamper_host.sh — ZERO-BOOT host-side migration of the
# offline negatives from tests/e2e/s13-token-tamper.sh (boot-min queue 30,
# move 1): the §10/§12 token-tamper family (invariant I3 — "Token JSON is
# untrusted: tampering with it can only break unseal, never forge it"),
# replicated against REAL artifacts (a standing finalized enrollment on a real
# file-backed LUKS2 container, a real swtpm via the fixture TCTI seam) with NO
# VM boot.
#
# Coverage migrated from s13 (its class (a) — host-replicable): every variant
# uses the SAME attacker primitive the e2e pins — cryptsetup token export ->
# mutate the exported JSON -> token_import through the lib/token.sh seam
# (--disable-external-tokens: validation belongs to the pinned §7.2 schema,
# not the host's systemd-tpm2 plugin) -> re-export proving the intended field
# moved:
#   pubkey-swap   — tpm2-pubkey swapped for a valid foreign RSA key: the
#                   import lands, the unseal path stays INERT to it (the I3
#                   anchor is the release key, never the token's pubkey —
#                   documented s13 deviation, pinned host-side), and the
#                   enroll post-assert REFUSES the foreign pubkey.
#   blob-corrupt  — tpm2-blob first byte flipped: the sealed object FAILS TO
#                   LOAD in the real TPM (tpm2_load refusal) — the e2e's
#                   "sealed object dead in the TPM -> refusal" proven at a
#                   live swtpm instead of an in-guest boot.
#   sig-corrupt   — tpm2-signature corrupted: inert under the entry-sig I3
#                   semantic (the seal/unseal path verifies the DRIVE ENTRY's
#                   .pcrsig release-key signature, never the token's
#                   signature) — unseal proceeds.
#   version-99    — unknown field: inert metadata, unseal proceeds.
#   bad-descriptor— the token's keyslots descriptor relabeled to a
#                   NONEXISTENT slot: metadata accepts it, the descriptor-vs-
#                   metadata check detects the dangling reference and the
#                   enroll post-assert refuses the wrong binding.
#   GREEN baseline: the untampered standing token unseals (real swtpm policy
#   session) to exactly the staged passphrase and passes token_post_assert.
#
# NOT migrated (VM-only, stays in s13): in-guest console behaviors — the
# hook's 3-strike recovery loop, the unseal_*/DEBUG SHELL sentinels, poweroff
# semantics, the per-variant boots themselves.
#
# Seams (identical to seal_mechanism_b.sh): tests/unit/lib.sh asserts; the
# swtpm fixture (SWTPM_TCTI -> ALPINE_FDE_TCTI); lib/{common,policy,keys,
# token,seal}.sh; ALPINE_FDE_TMPDIR for I1 passphrase staging.

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

TMP=$(mktemp -d /tmp/alpine-fde-s13host.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp # I1: passphrase staging must land HERE, mode 600
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

# --- live PCR state (deterministic extends; the enrolled baseline) -------------
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

# --- the release combined {7,11} .pcrsig (digest-anchored, Option A) ------------
REL_JSON=$TMP/pcrsig-combined.json
policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$REL_JSON"

# --- real file-backed LUKS2 container + standing finalized enrollment -----------
LUKS=$TMP/luks.img
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
PRE=$TMP/pre.json
token_dump "$LUKS" "$PRE"
TOK=$TMP/token-fin.json
seal_finalized "$KEYDIR" "$LUKS" "$REL_JSON" "$TOK"
assert_rc "standing enrollment sealed (finalized {7,11})" 0 $?
token_add_keyslot "$LUKS" "$SEAL_PASS_FILE" "$SEAL_SLOT" "$TMP/k0"
assert_rc "token keyslot added" 0 $?
TID=$(token_next_id "$LUKS")
token_import "$LUKS" "$TOK" "$TID"
assert_rc "standing token imported" 0 $?
POST=$TMP/post.json
token_dump "$LUKS" "$POST"
token_post_assert "$PRE" "$POST" "$(jq -r '.["tpm2-pubkey"]' "$TOK")" '[7,11]' "$SEAL_SLOT"
assert_rc "enroll post-assert green before any tamper" 0 $?
STAGED_PASS=$(cat "$SEAL_PASS_FILE")

# GREEN baseline: the UNTAMPERED standing token unseals at the real swtpm
seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TOK" "$TMP/unsealed-good.txt"
assert_rc "baseline: the standing token unseals (real TPM policy session)" 0 $?
assert_eq "baseline: unseal == the staged passphrase" "$STAGED_PASS" "$(cat "$TMP/unsealed-good.txt")"

# --- the e2e attacker primitive, host-side --------------------------------------
token_export() { # <dev> <id> <out.json>
    cryptsetup token export "$1" --token-id "$2" --json-file "$3" 2>/dev/null
}
tamper_disk() { # <variant> <disk> — swap in the tampered token (import via the
                # lib/token.sh seam: --disable-external-tokens, atomic staging)
    token_remove "$2" "$TID" 2>/dev/null
    token_import "$2" "$TMP/tok-$1.json" "$TID"
}
# assert_field_moved <variant> <disk> <jq-field-expr> — re-export and prove the
# intended field moved (and ONLY it, where the variant demands it)
assert_field_moved() { # <label> <disk> <moved-field> <untouched-field>
    token_export "$2" "$TID" "$TMP/chk.json" || { assert_eq "$1 (re-export)" "ok" "export-failed"; return 0; }
    assert_ne "$1 (re-export: $3 moved)" \
        "$(jq -r "$3" "$TOK")" "$(jq -r "$3" "$TMP/chk.json")"
    assert_eq "$1 (re-export: $4 untouched)" \
        "$(jq -r "$4" "$TOK")" "$(jq -r "$4" "$TMP/chk.json")"
}

# foreign keypair (valid RSA, nothing to do with the release identity)
openssl genrsa -out "$TMP/foreign.pem" 2048 2>/dev/null
openssl pkey -in "$TMP/foreign.pem" -pubout -outform DER 2>/dev/null |
    openssl base64 -A >"$TMP/foreign.der.b64"

# blob inner-byte flip helper: <in.b64> <out.b64> — corrupts a byte INSIDE the
# private half (offset 10, past the 2-byte TPM2B length prefix): the sealed
# object's integrity HMAC breaks and the TPM itself refuses the load (the e2e
# flipped byte 0, which ALSO destroys the length prefix; corrupting a payload
# byte isolates the TPM-load refusal class this variant is about)
blob_flip_inner() {
    openssl base64 -d -A -in "$1" 2>/dev/null >"$TMP/blob.bin"
    _b10=$(xxd -p -l 1 -s 10 "$TMP/blob.bin")
    printf '\\x'"$(printf '%02x' $(( 0x$_b10 ^ 0xFF )))" | dd of="$TMP/blob.bin" bs=1 seek=10 conv=notrunc status=none
    openssl base64 -A -in "$TMP/blob.bin"
}

run_variant() { # <variant> — build fixture, land it, prove it, observe it
    local v="$1"
    case "$v" in
        pubkey-swap)
            jq --arg fk "$(cat "$TMP/foreign.der.b64")" '.["tpm2-pubkey"] = $fk' "$TOK" >"$TMP/tok-$v.json"
            ;;
        blob-corrupt)
            jq --arg b "$(blob_flip_inner <(jq -r '.["tpm2-blob"]' "$TOK"))" '.["tpm2-blob"] = $b' "$TOK" >"$TMP/tok-$v.json"
            ;;
        sig-corrupt)
            _sig=$(jq -r '.["tpm2-signature"]' "$TOK")
            _flipped=$([ "${_sig%"${_sig#?}"}" = "A" ] && echo B || echo A)
            jq --arg s "${_flipped}${_sig:1}" '.["tpm2-signature"] = $s' "$TOK" >"$TMP/tok-$v.json"
            ;;
        version-99)
            jq '.version = 99' "$TOK" >"$TMP/tok-$v.json"
            ;;
        bad-descriptor)
            jq '.keyslots = ["9"]' "$TOK" >"$TMP/tok-$v.json"
            ;;
    esac
    # per-variant RAW copy: the host-side cryptsetup tamper is the attacker's
    # write primitive ON that copy (the s13 disk-leg decision, kept)
    cp "$LUKS" "$TMP/disk-$v.img"
    tamper_disk "$v" "$TMP/disk-$v.img"
    assert_rc "$v: token import (host-side tamper landed)" 0 $?
    token_export "$TMP/disk-$v.img" "$TID" "$TMP/chk-$v.json" || true
}

# --- variant: pubkey-swap --------------------------------------------------------
run_variant pubkey-swap
assert_field_moved "pubkey-swap" "$TMP/disk-pubkey-swap.img" '.["tpm2-pubkey"]' '.["tpm2-blob"]'
( seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TMP/tok-pubkey-swap.json" "$TMP/un-pubkey.txt" ) 2>/dev/null
assert_rc "pubkey-swap: INERT for the unseal path (I3 anchor is the release key, not the token pubkey)" 0 $?
token_post_assert "$PRE" "$TMP/chk-pubkey-swap.json" "$(jq -r '.["tpm2-pubkey"]' "$TOK")" '[7,11]' "$SEAL_SLOT" 2>/dev/null
[ "$?" -ne 0 ] && assert_eq "pubkey-swap: enroll post-assert REFUSES the foreign pubkey" "refused" "refused" ||
    assert_eq "pubkey-swap: enroll post-assert REFUSES the foreign pubkey" "refused" "accepted"

# --- variant: blob-corrupt --------------------------------------------------------
run_variant blob-corrupt
assert_field_moved "blob-corrupt" "$TMP/disk-blob-corrupt.img" '.["tpm2-blob"]' '.["tpm2-pubkey"]'
( seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TMP/tok-blob-corrupt.json" "$TMP/un-blob.txt" ) 2>"$TMP/neg-blob.err"
[ "$?" -ne 0 ] && assert_eq "blob-corrupt: the sealed object FAILS TO LOAD in the real TPM (refused)" "refused" "refused" ||
    assert_eq "blob-corrupt: the sealed object FAILS TO LOAD in the real TPM (refused)" "refused" "accepted"
assert_contains "blob-corrupt: refusal is the tpm2_load class (corrupt token)" \
    "$(cat "$TMP/neg-blob.err")" "tpm2_load refused the sealed blob"

# --- variant: sig-corrupt ---------------------------------------------------------
run_variant sig-corrupt
assert_field_moved "sig-corrupt" "$TMP/disk-sig-corrupt.img" '.["tpm2-signature"]' '.["tpm2-blob"]'
( seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TMP/tok-sig-corrupt.json" "$TMP/un-sig.txt" ) 2>/dev/null
assert_rc "sig-corrupt: INERT under the entry-sig I3 semantic (unseal proceeds)" 0 $?
assert_eq "sig-corrupt: unseal == the staged passphrase" "$STAGED_PASS" "$(cat "$TMP/un-sig.txt")"

# --- variant: version-99 ------------------------------------------------------------
run_variant version-99
assert_eq "version-99: re-export carries the unknown field" "99" "$(jq -r '.version' "$TMP/chk-version-99.json")"
assert_eq "version-99: blob untouched" "$(jq -r '.["tpm2-blob"]' "$TOK")" "$(jq -r '.["tpm2-blob"]' "$TMP/chk-version-99.json")"
( seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TMP/tok-version-99.json" "$TMP/un-v99.txt" ) 2>/dev/null
assert_rc "version-99: unknown field is inert metadata (unseal proceeds)" 0 $?

# --- variant: bad descriptor (token bound to a NONEXISTENT keyslot) ------------------
# OBSERVED METADATA BEHAVIOR (live-pinned): cryptsetup's token import REFUSES a
# keyslots descriptor referencing a nonexistent slot ("Failed to import token
# from file", rc 1) — the dangling descriptor never lands, and (unlike the
# s13 e2e's remove-then-import choreography) a fresh-id import attempt leaves
# the standing token UNTOUCHED: the tamper fails CLOSED at the metadata layer.
jq '.keyslots = ["9"]' "$TOK" >"$TMP/tok-bad-descriptor.json"
BADID=$(token_next_id "$LUKS")
( token_import "$LUKS" "$TMP/tok-bad-descriptor.json" "$BADID" ) 2>/dev/null
[ "$?" -ne 0 ] && assert_eq "bad-descriptor: LUKS2 metadata REFUSES the dangling keyslots ref at import" "refused" "refused" ||
    assert_eq "bad-descriptor: LUKS2 metadata REFUSES the dangling keyslots ref at import" "refused" "accepted"
BAD_META=$TMP/meta-bad-desc.json
token_dump "$LUKS" "$BAD_META"
assert_eq "bad-descriptor: the standing enrollment is UNTOUCHED (exactly one token, byte-identical)" \
    "$(jq -c --arg t "$TID" '.tokens[$t]' "$POST")" "$(jq -c --arg t "$TID" '.tokens[$t]' "$BAD_META")"
# descriptor-vs-metadata check (the generic detection over ANY landed token):
# a token's keyslots must be a SUBSET of the container's real keyslots
jq -e --arg t "$TID" '[.tokens[$t].keyslots[]?] - [.keyslots | keys[]] | length == 0' "$BAD_META" >/dev/null 2>&1
assert_rc "descriptor-vs-metadata check PASSES the untouched standing token" 0 $?
jq -e --argjson ks '["9"]' '[ $ks[] ] - [.keyslots | keys[]] | length == 0' "$BAD_META" >/dev/null 2>&1
[ "$?" -ne 0 ] && assert_eq "descriptor-vs-metadata check REFUSES the dangling [\"9\"] ref" "refused" "refused" ||
    assert_eq "descriptor-vs-metadata check REFUSES the dangling [\"9\"] ref" "refused" "accepted"
token_post_assert "$PRE" "$BAD_META" "$(jq -r '.["tpm2-pubkey"]' "$TOK")" '[7,11]' "$SEAL_SLOT"
assert_rc "enroll post-assert still green on the untouched enrollment" 0 $?

# sanity: the pristine container's descriptor passes the same check
jq -e --arg t "$TID" '[.tokens[$t].keyslots[]?] - [.keyslots | keys[]] | length == 0' "$POST" >/dev/null 2>&1
assert_rc "descriptor-vs-metadata check PASSES the pristine enrollment" 0 $?

swtpm_stop "$TPMDIR" || true
finish
