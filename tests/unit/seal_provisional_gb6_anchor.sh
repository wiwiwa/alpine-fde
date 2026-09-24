#!/usr/bin/env bash
# tests/unit/seal_provisional_gb6_anchor.sh — the G-B6 gate for the PROVISIONAL
# {11} selection must be DIGEST-ANCHORED when the entry carries a d11 component
# (Option A — the same contract the finalized {7,11} selection already has),
# keeping the live-PCR oracle for legacy anchor-less entries.
#
# WHY (live defect 2026-09-24, s22 registry + standalone): the fixture swtpm is
# ZERO-ON-RESTART (it dies at every clean qemu exit; every start is a
# startup-clear) and a host-side reseed lands the EXTEND-FROM-ZERO register,
#     PCR' = sha256(0^32 || digest) != digest,
# so a live-PCR G-B6 oracle runs against a register that can never equal the
# booted d11 the {11} policy was composed over — the seal refused its own
# correctly-signed policy ("signed d4b3226b != computed 19e36724"). With the
# anchor the gate is a pure data check; the REAL verification stays where it
# belongs: the token's boot-time PolicyPCR session against the guest's own
# re-derived register (pinned end-to-end by tests/e2e/s22-handoff-immunity.sh
# boot 2). The in-guest installer's entries keep working unchanged: they carry
# no anchor and hit the live oracle against the very TPM the machine booted
# with — where live d11 IS the postphase value.
#
# Pinned here against a REAL swtpm left at ZERO PCR 11 (proving the anchored
# gate reads no live PCRs) and a real LUKS2 container:
#   * anchored entry, pol == seal_digest_11(entry d11)     -> seal rc 0
#   * anchored entry, tampered pol                          -> rc 64 (fail-closed)
#   * legacy anchor-less entry vs the zero register         -> rc 64 (oracle kept)

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
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

TMP=$(mktemp -d /tmp/debian-fde-prov-gb6.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp" "$TMP/efivars"
DEBIAN_FDE_TMPDIR=$TMP/tmp

# ADR-16 floor: the seal path refuses release keys < RSA-3072
KD=$TMP/keys
mkdir -p "$KD"
openssl genrsa -out "$KD/release.pem" 3072 2>/dev/null
openssl pkey -in "$KD/release.pem" -pubout -out "$KD/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KD/release.pem" -out "$KD/db.crt" -days 30 \
    -subj "/CN=debian-fde-prov-gb6" 2>/dev/null
cp "$KD/release.pem" "$KD/db.key"
[ -s "$KD/db.key" ] && [ -s "$KD/release.pub" ] || {
    echo "FAIL: cannot generate the RSA-3072 keydir" >&2
    exit 1
}

# REAL swtpm, deliberately left at ZERO PCR 11 — the anchored gate must not
# consult it (the live oracle against this register is exactly what failed).
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || { echo "FAIL: swtpm did not start" >&2; exit 1; }
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
ZERO64=$(printf '0%.0s' {1..64})
LIVE11=$(tpm pcrread -Q -o "$TMP/p11.bin" sha256:11 >/dev/null 2>&1; od -An -v -tx1 "$TMP/p11.bin" | tr -d ' \n')
assert_eq "fixture: live PCR 11 is zero (the oracle path would refuse)" "$ZERO64" "$LIVE11"

# the boot's landed register (the digest the {11} policy is composed over)
D11_BOOT=1a70097f3a5c9b3d117842dac69bdf732088c360fda92a6e45994d46b83f7f3b

# real LUKS2 container with keyslot 0 (token_free_slot must find slot 1)
LUKS=$TMP/luks.img
truncate -s 32M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null

# prov_entry <out.json> <anchored 0|1> [tamper 0|1] — the s22 Stage-1 step-6
# composition (release-key-signed seal_digest_11 over the booted d11), with
# the digest-anchor field the anchored G-B6 gate reads
prov_entry() {
    local out=$1 anchored=$2 tamper=${3:-0}
    local pol bin sig pkfp
    pol=$(seal_digest_11 "$D11_BOOT") || return 1
    if [ "$tamper" = "1" ]; then
        pol=$(printf '%s' "$pol" | sed 's/^a/b/; s/^b/a/; s/^c/d/; s/^d/c/' | head -c 64)
    fi
    bin=$(mktemp "$TMP/debian-fde-pol.XXXXXX") || return 1
    printf '%s' "$pol" | policy_hex_to_bin >"$bin" || { rm -f "$bin"; return 1; }
    sig=$(mktemp "$TMP/debian-fde-sig.XXXXXX") || { rm -f "$bin"; return 1; }
    openssl dgst -sha256 -sign "$KD/db.key" -out "$sig" "$bin" 2>/dev/null ||
        { rm -f "$bin" "$sig"; return 1; }
    sig=$(openssl base64 -A -in "$sig") || { rm -f "$bin" "$sig"; return 1; }
    rm -f "$bin"
    pkfp=$(openssl rsa -pubin -in "$KD/release.pub" -RSAPublicKey_out -outform DER 2>/dev/null |
        sha256sum | cut -d' ' -f1)
    if [ "$anchored" = "1" ]; then
        jq -n --arg pol "$pol" --arg sig "$sig" --arg pkfp "$pkfp" --arg d11 "$D11_BOOT" \
            '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig, "d11": $d11}]}' >"$out"
    else
        jq -n --arg pol "$pol" --arg sig "$sig" --arg pkfp "$pkfp" \
            '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$out"
    fi
}

run_prov() { # PCRSIG OUT.TOKEN — seal_provisional against the zeroed fixture.
    # SUBSHELL: the seal libs die(64) fail-closed on a refused gate; a subshell
    # turns that into a capturable rc (and no staged secrets cross out).
    (
        SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE='' \
            DEBIAN_FDE_SEAL_STAGE="$TMP/tmp" \
            seal_provisional "$KD" "$LUKS" "$1" "$2"
    ) 2>"$TMP/prov.err"
}

# 1. anchored entry: G-B6 is a pure data check — rc 0 despite the zero register
prov_entry "$TMP/pcrsig-anchored.json" 1
run_prov "$TMP/pcrsig-anchored.json" "$TMP/token-anchored.json"
PROV_ANCHORED_RC=$?
assert_rc "provisional seal with a d11-anchored entry rc 0 (no live PCR read)" 0 "$PROV_ANCHORED_RC"
if [ "$PROV_ANCHORED_RC" -eq 0 ]; then
    assert_eq "anchored seal: token binds PCR 11 only" "[11]" \
        "$(jq -c '.["tpm2-pcrs"]' "$TMP/token-anchored.json")"
    assert_eq "anchored seal: exactly one staged volume passphrase (caller choreography)" "1" \
        "$(find "$TMP/tmp" -name 'debian-fde-seal-pass.*' | wc -l)"
    find "$TMP/tmp" -name 'debian-fde-seal-pass.*' -exec dd if=/dev/zero of={} bs=1k count=1 status=none \; -delete
else
    echo "--- anchored provisional stderr:" >&2
    cat "$TMP/prov.err" >&2
    assert_eq "anchored seal: token binds PCR 11 only" "[11]" "skipped-rc-$PROV_ANCHORED_RC"
fi

# 2. anchored entry with a tampered pol: fail-closed 64
prov_entry "$TMP/pcrsig-tampered.json" 1 1
run_prov "$TMP/pcrsig-tampered.json" "$TMP/token-tampered.json"
TAMPER_RC=$?
[ "$TAMPER_RC" -eq 64 ] &&
    assert_eq "tampered anchored pol refused rc 64 (fail-closed)" "refused" "refused" ||
    assert_eq "tampered anchored pol refused rc 64 (fail-closed)" "64" "got:$TAMPER_RC"

# 3. legacy anchor-less entry: the live-PCR oracle is KEPT — against the zero
# register it must refuse (the policy was composed over the booted d11)
prov_entry "$TMP/pcrsig-legacy.json" 0
run_prov "$TMP/pcrsig-legacy.json" "$TMP/token-legacy.json"
LEGACY_RC=$?
[ "$LEGACY_RC" -eq 64 ] &&
    assert_eq "anchor-less entry keeps the live-PCR oracle (refused on the zero register)" "refused" "refused" ||
    assert_eq "anchor-less entry keeps the live-PCR oracle (refused on the zero register)" "64" "got:$LEGACY_RC"

finish
