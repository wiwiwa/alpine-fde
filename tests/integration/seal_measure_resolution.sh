#!/usr/bin/env bash
# tests/integration/seal_measure_resolution.sh — real-server blocker #17: the
# ADR-20 Stage-1 step-6 provisional seal (seal_provisional) against a UKI whose
# .pcrsig was produced by the BUNDLED measure shim (no d11 anchor field — the
# oracle sign output carries pcrs/pkfp/pol/sig only). Contract:
#
#   1. GUEST SHAPE, ONLY THE SHIM PRESENT (ALPINE_FDE_MEASURE_BIN=''): the seal
#      RECOMPUTES the expected d11 from the UKI's own sections via the
#      centralized measure resolution (measure_pcr11_from_uki) and succeeds —
#      live PCR 11 is left at ZERO the whole time (no live-PCR oracle).
#   2. NO MEASURE IMPLEMENTATION (scratch tree without lib/measure.sh): the
#      refusal is the LOUD SPECIFIC rc 64 "cannot recompute the anchored
#      PCR-11 digest (...)" — NEVER "stale/tampered" over an empty computed
#      side (that misleading verdict is exactly what the live server printed).
#   3. A GENUINE mismatch (tampered pol, valid sig key material) still says
#      "stale/tampered" — with a NON-EMPTY computed side.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
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
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}
command -v ukify >/dev/null 2>&1 || {
    echo "FAIL: ukify not available — the blocker-#17 pins need a REAL ukify-built UKI" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/alpine-fde-seal-mr.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp" "$TMP/efivars"
export ALPINE_FDE_TMPDIR=$TMP/tmp

# --- keydir: RSA-3072 (ADR-16 floor) --------------------------------------------
KD=$TMP/keys
mkdir -p "$KD"
openssl genrsa -out "$KD/release.pem" 3072 2>/dev/null
openssl pkey -in "$KD/release.pem" -pubout -out "$KD/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KD/release.pem" -out "$KD/db.crt" -days 30 \
    -subj "/CN=alpine-fde-seal-mr" 2>/dev/null
cp "$KD/release.pem" "$KD/db.key"

# --- REAL swtpm left at ZERO PCR 11 (the recomputation must not consult it) ----
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || { echo "FAIL: swtpm did not start" >&2; exit 1; }
export ALPINE_FDE_TCTI=$SWTPM_TCTI

# --- real LUKS2 container with keyslot 0 ----------------------------------------
LUKS=$TMP/luks.img
truncate -s 32M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null

# --- build a REAL UKI with the real ukify + ONLY THE BUNDLED SHIM ---------------
KVER=6.18.53-0-lts
printf 'root=UUID=22222222-2222-2222-2222-222222222222 ro rd.shell=0' >"$TMP/cmdline.txt"
printf 'ID=alpine\nNAME="Alpine Linux"\n' >"$TMP/os-release"
printf '%s' "$KVER" >"$TMP/uname.txt"
head -c 4096 /dev/urandom >"$TMP/linux.bin"
head -c 512 /dev/urandom >"$TMP/initrd.img"
mkdir -p "$TMP/stage"
ALPINE_FDE_CMD_DIR="$REPO/lib/cmd" ALPINE_FDE_MEASURE_BIN='' \
    measure_resolve "$TMP/stage" >"$TMP/resolve.out" 2>/dev/null
assert_rc "shim resolution succeeds with the system binary seam-absent" 0 $?
assert_contains "resolution staged the shim at the requested stable dir" \
    "$(cat "$TMP/resolve.out")" "$TMP/stage/systemd-measure"
ALPINE_FDE_MEASURE_BIN='' ukify build \
    "--linux=$TMP/linux.bin" "--initrd=$TMP/initrd.img" "--cmdline=@$TMP/cmdline.txt" \
    "--os-release=@$TMP/os-release" "--uname=$KVER" \
    --pcr-banks=sha256 --phases=enter-initrd \
    "--pcr-private-key=$KD/release.pem" "--pcr-public-key=$KD/release.pub" \
    "--tools=$TMP/stage" --measure --json=short \
    "--output=$TMP/uki.efi" >/dev/null 2>"$TMP/ukify.err"
assert_rc "real ukify build against the shim rc 0" 0 $?

# extract the .pcrsig exactly like the ADR-20 step-6 record does
objcopy -O binary --only-section=.pcrsig "$TMP/uki.efi" "$TMP/pcrsig.json" 2>/dev/null
assert_file_exists ".pcrsig extracted from the built UKI" "$TMP/pcrsig.json"
assert_eq "the shim-built entry is ANCHOR-LESS (no d11 field — the blocker-#17 shape)" \
    "" "$(jq -r '.sha256[0].d11 // empty' "$TMP/pcrsig.json")"

# --- run_prov PCRSIG [UKI] [REPO] — provisional seal in a FRESH process -------
# (a subshell of THIS test would inherit the already-sourced measure functions;
# the no-implementation pin needs a process that never saw lib/measure.sh)
run_prov() {
    local sig=$1 uki=${2:-} tree=${3:-$REPO}
    cat >"$TMP/prov-entry.sh" <<PROVEOF
#!/bin/bash
set -u
export ALPINE_FDE_CMD_DIR="$tree/lib/cmd"
. "$tree/lib/common.sh"
. "$tree/lib/policy.sh"
. "$tree/lib/keys.sh"
. "$tree/lib/seal.sh"
. "$tree/lib/token.sh"
SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE='' \
    ALPINE_FDE_SEAL_STAGE="$TMP/tmp" \
    seal_provisional "$KD" "$LUKS" "$sig" "$TMP/token-out.json" $uki
PROVEOF
    bash "$TMP/prov-entry.sh" 2>"$TMP/prov.err"
}

# --- 1. guest shape, only the shim: recompute from the UKI, seal rc 0 -----------
run_prov "$TMP/pcrsig.json" "$TMP/uki.efi"
PROV_RC=$?
assert_rc "blocker #17: provisional seal over an anchor-less shim-built pcrsig rc 0 (only the shim present)" 0 "$PROV_RC"
if [ "$PROV_RC" -eq 0 ]; then
    assert_contains "recomputation went through the measure implementation (log)" \
        "$(cat "$TMP/prov.err")" "via the measure implementation"
    assert_eq "token binds PCR 11 only" "[11]" "$(jq -c '.["tpm2-pcrs"]' "$TMP/token-out.json")"
else
    cat "$TMP/prov.err" >&2
fi

# --- 1b. live PCR 11 was NEVER consulted: EXTEND it to a wrong value and re-seal
swtpm_pcrextend "$TPMDIR" 11 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff >/dev/null 2>&1
assert_rc "fixture: live PCR 11 extended to a wrong value" 0 $?
run_prov "$TMP/pcrsig.json" "$TMP/uki.efi"
NOLIVE_RC=$?
assert_rc "recomputation ignores the LIVE PCR 11 (seal rc 0 over the wrong live register)" 0 "$NOLIVE_RC"

# --- 2. NO measure implementation: loud specific rc 64, NEVER 'tampered' ---------
rm -rf "$TMP/notree"
mkdir -p "$TMP/notree"
cp -r "$REPO/lib" "$REPO/bin" "$TMP/notree/"
rm -f "$TMP/notree/lib/measure.sh"
run_prov "$TMP/pcrsig.json" "$TMP/uki.efi" "$TMP/notree"
NOIMPL_RC=$?
assert_rc "no measure implementation -> fail-closed 64" 64 "$NOIMPL_RC"
assert_contains "refusal names the recomputation failure (loud + specific)" \
    "$(cat "$TMP/prov.err")" "cannot recompute the anchored PCR-11 digest"
if grep -q "stale/tampered" "$TMP/prov.err"; then
    _fail "no-implementation refusal must NOT say stale/tampered (the misleading server verdict)"
else
    _pass "no-implementation refusal does NOT claim stale/tampered"
fi

# --- 3. a GENUINE mismatch still says stale/tampered, with a real computed side --
# a bit-flip breaks the SIGNATURE first; to reach the stale/tampered compare,
# the forged entry must carry a DIFFERENT but correctly-signed policy (signed
# over some other d11 — exactly what a stale .pcrsig from an older build is)
D11_OTHER=9f2d4c8b7a61503e2d1c0b9a88776655443322110ff1e2d3c4b5a6978899002f
pol2=$(seal_digest_11 "$D11_OTHER")
bin2=$(mktemp "$TMP/pol2.XXXXXX")
printf '%s' "$pol2" | policy_hex_to_bin >"$bin2"
sig2=$(openssl dgst -sha256 -sign "$KD/db.key" "$bin2" 2>/dev/null | openssl base64 -A)
rm -f "$bin2"
pkfp=$(openssl rsa -pubin -in "$KD/release.pub" -RSAPublicKey_out -outform DER 2>/dev/null |
    openssl dgst -sha256 -hex | awk '{print $NF}')
jq -n --arg pol "$pol2" --arg sig "$sig2" --arg pkfp "$pkfp" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$TMP/pcrsig-stale.json"
run_prov "$TMP/pcrsig-stale.json" "$TMP/uki.efi"
TAMPER_RC=$?
assert_rc "genuine pol mismatch refused rc 64" 64 "$TAMPER_RC"
assert_contains "genuine mismatch says stale/tampered" \
    "$(cat "$TMP/prov.err")" "stale/tampered"
COMPUTED=$(sed -n 's/.*computed \([0-9a-f]\{64\}\).*/\1/p' "$TMP/prov.err" | head -1)
[ -n "$COMPUTED" ] &&
    _pass "the tamper verdict carries a NON-EMPTY computed side ($COMPUTED)" ||
    _fail "the tamper verdict carried an EMPTY computed side (the blocker-#17 misleading shape)"

finish
