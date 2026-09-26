#!/usr/bin/env bash
# tests/integration/s03_stale_enrollment_host.sh — ZERO-BOOT host-side migration of
# the offline negatives from tests/e2e/s03-stale-enrollment.sh (boot-min queue
# 30, move 1): every assertion here runs against REAL artifacts (a real
# file-backed LUKS2 container, a real swtpm via the fixture TCTI seam, real
# openssl/cryptsetup/tpm2-tools) with NO VM boot.
#
# Coverage migrated from s03 (its class (a) — host-replicable):
#   flavor 1 (missing .pcrsig / stale policy) — the G-B6 gate
#     (lib/seal.sh seal_verify_pcrsig) refuses:
#       * an 11-only ladder .pcrsig when the finalized {7,11} selection is
#         demanded (NO entry for the token's selection) — the host-side
#         residue of s03's UKI-6.3.0-built-without-PCR-signing defect;
#       * an ABSENT .pcrsig file (die 64 before anything is touched);
#       * a release-signed combined pol computed over a STALE d7 — the
#         boot-time live-PCR oracle (seal_unseal) refuses the enrollment
#         whose signed policy no longer matches the register a faithful
#         boot reproduces ("stale enrollment", s15-style drift, same
#         fail-closed seam).
#   flavor 2 (removed enrollment) — the s03 _host_wipe_enrollment stand-in
#     (lib/token.sh token_remove + token_kill_slot) lands on the REAL
#     container and the wipe is DETECTABLE host-side: zero systemd-tpm2
#     tokens, only the slot-0 recovery passphrase remains, the enroll
#     post-assert (token_post_assert) refuses, and the retired enrollment
#     credential unlocks NOTHING.
#   GREEN on good artifacts: a digest-anchored combined {7,11} enrollment
#     (policy_sign_json over live fixture PCRs) seals, stands in real LUKS2
#     metadata, passes token_post_assert, unlocks its keyslot, and unseals
#     back to the exact staged passphrase.
#
# NOT migrated (VM-only, stays in s03): in-guest console behaviors — the
# hook's 3-strike recovery loop, prompt-synchronized serial feeds, the
# unseal_token_missing/unseal_3strike sentinels, poweroff-vs-shell; the
# variant-UKI ukify/sbverify build pins (build-level, owned elsewhere).
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

TMP=$(mktemp -d /tmp/alpine-fde-s03host.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp # I1: passphrase staging must land HERE, mode 600
KEYDIR=$REPO/fixtures/keys

TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI
flushall() { tpm flushcontext -t >/dev/null 2>&1 || true; }
flushall

# --- live PCR state (the enrolled baseline; deterministic extends) ------------
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
D7_STALE=9999999999999999999999999999999999999999999999999999999999999999 # the pre-update register

# --- the GOOD combined {7,11} .pcrsig (digest-anchored, Option A) --------------
REL_JSON=$TMP/pcrsig-combined.json
policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$REL_JSON"
assert_eq "good combined .pcrsig pins the {7,11} selection" "[7,11]" "$(jq -c '.sha256[0].pcrs' "$REL_JSON")"
assert_eq "good combined .pcrsig pol == fresh policy_digest(d7, d11)" "$FRESH" "$(jq -r '.sha256[0].pol' "$REL_JSON")"

# --- real file-backed LUKS2 container (recovery slot 0) ------------------------
LUKS=$TMP/luks.img
truncate -s 24M "$LUKS"
printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$LUKS" 2>/dev/null
LUKS_UUID=$(cryptsetup luksUUID "$LUKS" 2>/dev/null)
[ -n "$LUKS_UUID" ] || {
    echo "FAIL: LUKS2 fixture did not format" >&2
    exit 1
}
PRE=$TMP/pre.json
token_dump "$LUKS" "$PRE"

# --- GREEN: the healthy finalized enrollment on the real container -------------
TOK=$TMP/token-fin.json
rm -f "$TOK"
seal_finalized "$KEYDIR" "$LUKS" "$REL_JSON" "$TOK"
assert_rc "seal_finalized over the good .pcrsig rc 0" 0 $?
assert_eq "standing token is systemd-tpm2" "systemd-tpm2" "$(jq -r '.type' "$TOK")"
assert_eq "standing token pins {PCR 7, PCR 11}" "[7,11]" "$(jq -c '.["tpm2-pcrs"]' "$TOK")"
[ -n "${SEAL_SLOT:-}" ] && [ "${SEAL_SLOT:-}" != "0" ] &&
    assert_eq "token keyslot != 0 (recovery slot 0 untouched)" "fresh" "fresh" ||
    assert_eq "token keyslot != 0 (recovery slot 0 untouched)" "fresh" "got:${SEAL_SLOT:-<unset>}"
token_add_keyslot "$LUKS" "$SEAL_PASS_FILE" "$SEAL_SLOT" "$TMP/k0"
assert_rc "luksAddKey added the token keyslot" 0 $?
TID=$(token_next_id "$LUKS")
token_import "$LUKS" "$TOK" "$TID"
assert_rc "atomic token import rc 0" 0 $?
POST=$TMP/post.json
token_dump "$LUKS" "$POST"
assert_eq "exactly one systemd-tpm2 token in LUKS2 metadata" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$POST")"
assert_eq "metadata token pins {7,11}" "[7,11]" \
    "$(jq -c 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pcrs"])' "$POST")"
token_post_assert "$PRE" "$POST" "$(jq -r '.["tpm2-pubkey"]' "$TOK")" '[7,11]' "$SEAL_SLOT"
assert_rc "token_post_assert green on the healthy enrollment" 0 $?
cryptsetup open --test-passphrase --key-slot "$SEAL_SLOT" --key-file "$SEAL_PASS_FILE" "$LUKS" 2>/dev/null
assert_rc "the enrollment credential unlocks the real container" 0 $?
seal_unseal "$KEYDIR" "$REL_JSON" finalized "$TOK" "$TMP/unsealed.txt"
assert_rc "seal_unseal (the boot-time live-PCR oracle) unseals the standing token" 0 $?
assert_eq "unseal returns exactly the staged passphrase" "$(cat "$SEAL_PASS_FILE")" "$(cat "$TMP/unsealed.txt")"

# --- NEGATIVE 1: stale enrollment — signed pol over a STALE d7 -----------------
# (s03 "stale enrollment", drift flavor: the token's PCR policy no longer
# matches the register a faithful boot measures. RED-first: the good artifact
# is mutated by re-signing its pol over the stale register.)
STALE_JSON=$TMP/pcrsig-stale.json
policy_sign_json "$D7_STALE" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$STALE_JSON"
( seal_verify_pcrsig "$KEYDIR" "$STALE_JSON" "7,11" "$FRESH" ) 2>"$TMP/neg-stale.err"
assert_rc "G-B6 gate: stale-d7 pol vs fresh digest -> die 64" 64 $?
assert_contains "stale refusal names the digest mismatch" "$(cat "$TMP/neg-stale.err")" "stale/tampered"
( seal_unseal "$KEYDIR" "$STALE_JSON" finalized "$TOK" "$TMP/unsealed-stale.txt" ) 2>"$TMP/neg-stale2.err"
[ "$?" -ne 0 ] && assert_eq "stale enrollment: boot-time live-PCR oracle REFUSES" "refused" "refused" ||
    assert_eq "stale enrollment: boot-time live-PCR oracle REFUSES" "refused" "accepted"

# --- NEGATIVE 2: missing .pcrsig entry — the 11-only ladder vs {7,11} ----------
# (s03 flavor 1: a UKI built WITHOUT the PCR-signing step carries no policy
# for the token's selection. The gate must find NO [7,11] entry.)
POL11=$(seal_digest_11 "$D11")
printf '%s' "$POL11" | policy_hex_to_bin >"$TMP/pol11.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$TMP/pol11.sig" "$TMP/pol11.bin" 2>/dev/null
PKFP=$(policy_pubkey_fp "$KEYDIR/release.pub")
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$TMP/pol11.sig")" --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$TMP/pcrsig-11only.json"
( seal_verify_pcrsig "$KEYDIR" "$TMP/pcrsig-11only.json" "7,11" "$FRESH" ) 2>"$TMP/neg-11only.err"
assert_rc "G-B6 gate: NO [7,11] entry in the payload .pcrsig -> die 64" 64 $?
assert_contains "no-entry refusal names the wrong-selection class" "$(cat "$TMP/neg-11only.err")" "no pcrs=[7,11] entry"
( seal_finalized "$KEYDIR" "$LUKS" "$TMP/pcrsig-11only.json" "$TMP/neg-token.json" ) 2>/dev/null
assert_rc "finalized seal against an 11-only .pcrsig -> die 64 (nothing enrolled)" 64 $?

# --- NEGATIVE 3: ABSENT .pcrsig (the ADR-8 signing-key-absent defect) ----------
( seal_finalized "$KEYDIR" "$LUKS" "$TMP/does-not-exist.pcrsig.json" "$TMP/neg-token.json" ) 2>/dev/null
assert_rc "missing .pcrsig file -> die 64 before any enrollment" 64 $?
assert_eq "no token written by any flavor-1 negative" "absent" \
    "$([ -e "$TMP/neg-token.json" ] && echo present || echo absent)"

# --- NEGATIVE 4: wiped enrollment (s03 flavor 2, host-side stand-in) -----------
# token_remove + luksKillSlot over every non-recovery slot — the attacker/
# accident primitive, through the lib/token.sh seams.
WIPE_SLOT=$SEAL_SLOT
token_remove "$LUKS" "$TID"
assert_rc "token removed from LUKS2 metadata" 0 $?
token_kill_slot "$LUKS" "$WIPE_SLOT" "$TMP/k0"
assert_rc "token keyslot killed" 0 $?
WIPED=$TMP/wiped.json
token_dump "$LUKS" "$WIPED"
assert_eq "wiped enrollment: ZERO systemd-tpm2 tokens remain" "0" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$WIPED")"
assert_eq "wiped enrollment: only the slot-0 recovery passphrase remains" '["0"]' \
    "$(jq -c '.keyslots | keys' "$WIPED")"
token_post_assert "$PRE" "$WIPED" "$(jq -r '.["tpm2-pubkey"]' "$TOK")" '[7,11]' "$WIPE_SLOT" 2>/dev/null
[ "$?" -ne 0 ] && assert_eq "wiped enrollment: enroll post-assert REFUSES (detectable host-side)" "refused" "refused" ||
    assert_eq "wiped enrollment: enroll post-assert REFUSES (detectable host-side)" "refused" "accepted"
cryptsetup open --test-passphrase --key-slot "$WIPE_SLOT" --key-file "$SEAL_PASS_FILE" "$LUKS" 2>/dev/null
[ "$?" -ne 0 ] && assert_eq "wiped enrollment: the retired credential unlocks NOTHING (no self-heal)" "dead" "dead" ||
    assert_eq "wiped enrollment: the retired credential unlocks NOTHING (no self-heal)" "dead" "still-valid"
assert_eq "recovery slot 0 survived the wipe byte-identical" \
    "$(jq -rS '.keyslots["0"]' "$PRE")" "$(jq -rS '.keyslots["0"]' "$WIPED")"

swtpm_stop "$TPMDIR" || true
finish
