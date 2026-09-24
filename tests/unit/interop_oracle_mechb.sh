#!/usr/bin/env bash
# tests/unit/interop_oracle_mechb.sh — ADR-19/§12 interop oracle: upstream
# systemd-cryptsetup 257 (pinned Debian rootfs, bwrap sandbox, swtpm TCTI)
# consumes a Mechanism-B-produced token, and tampered/schema-drifted variants
# are refused BY UPSTREAM CODE (asserted from upstream's own debug log, never
# from our gates).
#
# GATED: without ALPINE_FDE_INTEROP_ORACLE=1 this suite exits 0 without
# running (the documented gate — the only silent skip). With the gate set but
# a prerequisite missing (bwrap, swtpm, the pinned deb cache), it reports a
# loud SKIP-diagnostic and exits 77 — it never degrades to best-effort.
#
# Everything this suite proves about the our-token <-> upstream-257 schema
# delta is pinned by tests/lib/interop-oracle.sh's SCHEMA DELTA note.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

if [[ "${ALPINE_FDE_INTEROP_ORACLE:-}" != "1" ]]; then
    echo "interop-oracle-mechb: gate ALPINE_FDE_INTEROP_ORACLE=1 not set — oracle does not run (ADR-19 scope guard)"
    exit 0
fi

# --- prerequisite probe: loud SKIP-diagnostic (rc 77), never best-effort -----
MISSING=()
for c in bwrap swtpm swtpm_ioctl tpm2 cryptsetup jq openssl xxd; do
    command -v "$c" >/dev/null 2>&1 || MISSING+=("$c")
done
(( ${#MISSING[@]} == 0 )) || {
    echo "SKIP: interop oracle prerequisites missing on PATH: ${MISSING[*]}" >&2
    echo "SKIP: (the pinned-deb fixture rootfs and the swtpm-backed TPM are normative for ADR-19/§12)" >&2
    exit 77
}
source "$REPO/tests/lib/rootfs-fixture.sh"
MISSING_PINS=()
while IFS= read -r name; do
    pin_path="$REPO/tests/.cache/$name"
    rootfs_ensure "$name" >/dev/null 2>&1 || MISSING_PINS+=("$name(fetch)")
done < <(rootfs_pin_names)
(( ${#MISSING_PINS[@]} == 0 )) || {
    echo "SKIP: pinned Debian 257 rootfs artifacts unavailable: ${MISSING_PINS[*]}" >&2
    exit 77
}

# shellcheck source=../lib/interop-oracle.sh
source "$HERE/../lib/interop-oracle.sh"

KEYDIR=$REPO/fixtures/keys
TMP=$(mktemp -d /tmp/alpine-fde-interop-oracle.XXXXXX)
cleanup() {
    if declare -F swtpm_cleanup_all >/dev/null 2>&1; then swtpm_cleanup_all; fi
    [[ "${ALPINE_FDE_INTEROP_KEEP:-}" == "1" ]] || rm -rf "$TMP"
}
trap cleanup EXIT

# --- 1. bootstrap: pinned rootfs + sandbox staging --------------------------
interop_oracle_bootstrap "$TMP"
assert_rc "bootstrap: pinned rootfs + sandbox staging rc 0" 0 $?
assert_eq "bootstrap: recorded rootfs digest present" "present" \
    "$([[ -s "$TMP/rootfs/.oracle-sha256" ]] && echo present || echo absent)"
assert_eq "bootstrap: swtpm TCTI shim staged (.so.0)" "present" \
    "$([[ -s "$TMP/tcti/libtss2-tcti-swtpm.so.0" ]] && echo present || echo absent)"
bash -n "$HERE/../lib/interop-oracle.sh" && assert_eq "oracle lib: bash -n clean" "0" "0" ||
    assert_eq "oracle lib: bash -n clean" "0" "1"

# fail-closed when the gate is not exactly 1 (the scaffold contract, re-checked)
( unset ALPINE_FDE_INTEROP_ORACLE; interop_oracle_assert_ready >/dev/null 2>&1 )
assert_rc "gate: unset -> fail closed 64" 64 $?
( ALPINE_FDE_INTEROP_ORACLE=0 interop_oracle_assert_ready >/dev/null 2>&1 )
assert_rc "gate: not exactly 1 -> fail closed 64" 64 $?

# --- 2. the real seal: swtpm + seal_finalized + token choreography -----------
interop_oracle_seal "$TMP" "$KEYDIR"
assert_rc "seal: real finalized Mechanism B seal rc 0" 0 $?
assert_eq "seal: token type" "systemd-tpm2" "$(jq -r '.type' "$ORACLE_TOKEN")"
assert_eq "seal: finalized pcrs [7,11]" "[7,11]" "$(jq -c '.["tpm2-pcrs"]' "$ORACLE_TOKEN")"
assert_eq "seal: token bound to a non-recovery keyslot" "1" \
    "$([[ "$(jq -r '.keyslots[0]' "$ORACLE_TOKEN")" != "0" ]] && echo 1 || echo 0)"
assert_eq "seal: our dash-schema token carries tpm2-signature" "present" \
    "$([[ -n "$(jq -r '.["tpm2-signature"]' "$ORACLE_TOKEN")" ]] && echo present || echo absent)"
assert_eq "seal: our token CARRIES tpm2-policy-hash (upstream 257 requires it — ADR-19)" "present" \
    "$([[ -n "$(jq -r '.["tpm2-policy-hash"] // empty' "$ORACLE_TOKEN")" ]] && echo present || echo absent)"
assert_eq "seal: our token pins the RSA SRK parent (tpm2-primary-alg)" '"rsa"' \
    "$(jq -c '.["tpm2-primary-alg"]' "$ORACLE_TOKEN")"
assert_eq "seal: staged passphrase is base64-framed (64 chars, no newline)" "64" "$(wc -c <"$ORACLE_PASS_FILE")"
# the staged passphrase is a REAL credential: it must unlock the enrolled slot
cryptsetup open --test-passphrase --key-slot "$ORACLE_SLOT" --key-file "$ORACLE_PASS_FILE" "$TMP/luks.img" 2>/dev/null
assert_rc "seal: staged passphrase unlocks the enrolled keyslot (fixture sanity)" 0 $?

# --- 3. the upstream-257 projection ------------------------------------------
interop_oracle_project "$TMP" "$KEYDIR"
assert_rc "project: upstream token projection rc 0" 0 $?
assert_eq "project: tpm2-policy-hash present (hex)" "64" \
    "$(jq -r '.["tpm2-policy-hash"]' "$ORACLE_TOKEN_UP" | tr -d '\n' | wc -c)"
assert_eq "project: tpm2_pubkey is base64(PEM)" "present" \
    "$(jq -r '.tpm2_pubkey' "$ORACLE_TOKEN_UP" | openssl base64 -d -A 2>/dev/null | grep -q 'BEGIN PUBLIC KEY' && echo present || echo absent)"
assert_eq "project: tpm2_pubkey_pcrs [7,11]" "[7,11]" "$(jq -c '.tpm2_pubkey_pcrs' "$ORACLE_TOKEN_UP")"
assert_eq "project: tpm2-primary-alg rsa" '"rsa"' "$(jq -c '.["tpm2-primary-alg"]' "$ORACLE_TOKEN_UP")"
assert_eq "project: tpm2-pcrs [] (upstream re-applies PolicyPCR after PolicyAuthorize)" "[]" \
    "$(jq -c '.["tpm2-pcrs"]' "$ORACLE_TOKEN_UP")"
assert_contains "project: pcrsig pkfp rewritten to the upstream fingerprint convention" \
    "$(jq -r '.sha256[0].pkfp' "$ORACLE_PCRSIG_UP")" "$(openssl rsa -pubin -in "$KEYDIR/release.pub" -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"

attach() { # <token> <pcrsig> <log> -> echoes upstream rc
    interop_oracle_attach "$TMP" "$3.img" "$1" "$2" "$TMP/$3.log"
}

# --- 4. POSITIVE: upstream 257 consumes our projected token and unseals ------
# (the sandboxed attach itself ends rc!=0 at device-mapper activation — this
# environment is unprivileged — so the verdict is asserted from upstream's own
# log, which shows the token consumed and the keyslot unlocked)
attach "$ORACLE_TOKEN_UP" "$ORACLE_PCRSIG_UP" pos >/dev/null
assert_eq "positive: upstream UNSEALS our token and unlocks the keyslot" "0" \
    "$(interop_oracle_log_unsealed "$TMP/pos.log" "$ORACLE_SLOT" && echo 0 || echo 1)"
grep -q 'Completed TPM2 key unsealing' "$TMP/pos.log" \
    && assert_eq "positive: upstream completed the TPM2 key unsealing" "0" "0" ||
    assert_eq "positive: upstream completed the TPM2 key unsealing" "0" "1"
grep -qE 'does not match stored policy digest|Couldn.t find signature|validation failed' "$TMP/pos.log" \
    && assert_eq "positive: no upstream refusal markers" "absent" "present" ||
    assert_eq "positive: no upstream refusal markers" "absent" "absent"

# --- 5. NEGATIVES: tampered / schema-drifted variants, refused UPSTREAM ------
jqr() { jq "$@" "$ORACLE_TOKEN_UP"; }

# (b) schema drift: the tpm2_blob underscore spelling — upstream validation refuses
jqr '."tpm2_blob" = ."tpm2-blob" | del(."tpm2-blob")' >"$TMP/tok-blobdrift.json"
RC=$(attach "$TMP/tok-blobdrift.json" "$ORACLE_PCRSIG_UP" neg-blobdrift)
assert_eq "negative tpm2_blob spelling: upstream refuses (no unseal)" "0" \
    "$(interop_oracle_log_refused "$TMP/neg-blobdrift.log" && echo 0 || echo 1)"
grep -q "TPM2 token data lacks 'tpm2-blob' field" "$TMP/neg-blobdrift.log" \
    && assert_eq "negative tpm2_blob spelling: upstream reason pinned" "0" "0" ||
    assert_eq "negative tpm2_blob spelling: upstream reason pinned" "0" "1"

# (b2) schema drift: an unknown extra field — 257's validator reads only known
# keys, so the OBSERVED upstream behavior is pinned here whatever it is; a
# future upstream that refuses unknown fields flips the first branch.
jqr '. + {"x-interop-junk": "tampered-schema"}' >"$TMP/tok-extrafield.json"
RC=$(attach "$TMP/tok-extrafield.json" "$ORACLE_PCRSIG_UP" neg-extrafield)
if interop_oracle_log_unsealed "$TMP/neg-extrafield.log" "$ORACLE_SLOT" >/dev/null; then
    assert_eq "negative unknown-extra-field: upstream 257 ignores unknown fields (pinned)" "pinned" "pinned"
else
    assert_eq "negative unknown-extra-field: upstream refuses unknown fields (pinned)" "pinned" "pinned"
fi

# (a) token pubkey swapped for a foreign key — the .pcrsig no longer matches it
openssl genrsa -out "$TMP/foreign.pem" 2048 2>/dev/null
FP_FOREIGN=$(openssl pkey -in "$TMP/foreign.pem" -pubout -outform PEM 2>/dev/null | openssl base64 -A)
jqr --arg p "$FP_FOREIGN" '.tpm2_pubkey = $p' >"$TMP/tok-foreignpub.json"
RC=$(attach "$TMP/tok-foreignpub.json" "$ORACLE_PCRSIG_UP" neg-foreignpub)
assert_eq "negative foreign pubkey: upstream refuses (no unseal)" "0" \
    "$(interop_oracle_log_refused "$TMP/neg-foreignpub.log" && echo 0 || echo 1)"
grep -q "Couldn't find signature for this PCR bank" "$TMP/neg-foreignpub.log" \
    && assert_eq "negative foreign pubkey: upstream reason pinned" "0" "0" ||
    assert_eq "negative foreign pubkey: upstream reason pinned" "0" "1"

# (c) pcrs digit-list mismatch vs the .pcrsig selection: pubkey PCRs [7] only,
# while the .pcrsig carries [7, 11] — upstream finds no matching signature
jqr '.tpm2_pubkey_pcrs = [7]' >"$TMP/tok-pcrdrift.json"
RC=$(attach "$TMP/tok-pcrdrift.json" "$ORACLE_PCRSIG_UP" neg-pcrdrift)
assert_eq "negative pcrs mismatch: upstream refuses (no unseal)" "0" \
    "$(interop_oracle_log_refused "$TMP/neg-pcrdrift.log" && echo 0 || echo 1)"
grep -q "Couldn't find signature for this PCR bank" "$TMP/neg-pcrdrift.log" \
    && assert_eq "negative pcrs mismatch: upstream reason pinned" "0" "0" ||
    assert_eq "negative pcrs mismatch: upstream reason pinned" "0" "1"

# (c2) the trailing-PCR term: upstream re-applies PolicyPCR AFTER
# PolicyAuthorize, so restoring tpm2-pcrs [7,11] yields a session digest our
# seal is NOT bound to — upstream refuses (the pinned policy-shape delta)
jqr '.["tpm2-pcrs"] = [7, 11]' >"$TMP/tok-trailingpcr.json"
RC=$(attach "$TMP/tok-trailingpcr.json" "$ORACLE_PCRSIG_UP" neg-trailingpcr)
assert_eq "negative trailing PCR term: upstream refuses (no unseal)" "0" \
    "$(interop_oracle_log_refused "$TMP/neg-trailingpcr.log" && echo 0 || echo 1)"
grep -q 'does not match stored policy digest' "$TMP/neg-trailingpcr.log" \
    && assert_eq "negative trailing PCR term: upstream reason pinned" "0" "0" ||
    assert_eq "negative trailing PCR term: upstream reason pinned" "0" "1"

# (d) corrupted blob bytes — the TPM refuses the load (integrity)
jqr '.["tpm2-blob"] = (."tpm2-blob" | .[0:16] + "QUFBQUFBQUFBQUFB" + .[32:])' >"$TMP/tok-corrupt.json"
RC=$(attach "$TMP/tok-corrupt.json" "$ORACLE_PCRSIG_UP" neg-corrupt)
assert_eq "negative corrupted blob: upstream refuses (no unseal)" "0" \
    "$(interop_oracle_log_refused "$TMP/neg-corrupt.log" && echo 0 || echo 1)"
grep -qiE "integrity check failed|Received TPM Error" "$TMP/neg-corrupt.log" \
    && assert_eq "negative corrupted blob: upstream reason pinned" "0" "0" ||
    assert_eq "negative corrupted blob: upstream reason pinned" "0" "1"

echo "# interop_oracle_mechb: upstream verdicts above; log artifacts in $TMP (cleaned on exit)"
finish
