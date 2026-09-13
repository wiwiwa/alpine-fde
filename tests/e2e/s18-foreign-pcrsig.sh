#!/usr/bin/env bash
# tests/e2e/s18-foreign-pcrsig.sh — §6.1 signing negative control (G-T5):
# "signature from a FOREIGN key — must fail closed at unlock."
#
# Tamper: the payload-drive `.pcrsig` is REPLACED by a JSON carrying the SAME
# predicted PCR-11 policy digests (same pol entries — the prediction for THIS
# UKI is correct) but every `sig` re-signed by a FOREIGN RSA key. The outer
# sbsign signature is OURS (the release UKI is booted unmodified), so the
# firmware happily boots it — Secure Boot cannot see the payload drive. The
# TPM policy is where the foreign signer must die: the token's sealed policy
# pivots on the RELEASE public key (PolicyAuthorize, §6.1 A″); a policy
# signature from any other key must fail verification -> the token path is
# refused -> documented fallback prompt -> bounded retries (3) -> clean
# poweroff. NEVER `Entering emergency mode.` (H-G1).
#
# Host-side proofs (no TPM involved): the verification recipe itself is
# cross-checked — release.pub verifies the RELEASE sig over pol (positive),
# release.pub REFUSES the foreign sig over the same pol (the negative
# control, exact bytes), foreign.pub verifies the foreign sig (well-formed).
# The pol entries are asserted IDENTICAL between the release and the foreign
# JSON: only the signer moved — the refusal cannot be a stale prediction.
#
# In-guest: PCR 7 asserted equal to the enrolled boot (no drift confound) and
# the post-phase PCR 11 asserted equal to the signed pol (the G-T13 property
# — the pol MATCHED, so the refusal is exactly the foreign-signature
# verification, not a value mismatch).
#
# Reuses s00b's enrolled artifacts via DEBIAN_FDE_E2E_STATE (run-e2e.sh sets
# it); otherwise builds + boots them itself (2 boots).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/disk-fixture.sh
source "$TESTS/lib/disk-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

RUN="$TESTS/e2e/.runs/s18-foreign-pcrsig-$(date +%s)"
mkdir -p "$RUN"
T0=$SECONDS

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while boots run, else a mid-boot prune unlinks console.log.
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!
# HI-02: the refresher must die on EVERY exit path (early `exit 1`s leak it
# forever and it poisons later prunes). Chain with swtpm cleanup; pre-set the
# flag so swtpm_start does not overwrite this trap.
_SWTPM_CLEANUP_TRAP_SET=1
trap 'kill "$REFRESHER" 2>/dev/null; swtpm_cleanup_all 2>/dev/null' EXIT INT TERM

# IN-03: the restart path lives in the fixture (swtpm_ensure); the state dir
# is passed explicitly (the snapshot's $RUN/state/tpm is the live fixture).
_ensure_tpm() { swtpm_ensure "$1"; }

# wait_attempt: s09/s12 pattern (counting occurrences survives kernel printk
# interleave).
wait_attempt() {
    local n="$1" tmo="$2" dir="$3" i=0 c
    while ((i < tmo)); do
        c=$(grep -cF "awaiting console line" "$dir/console.log" 2>/dev/null || true)
        [[ -n "$c" ]] && ((c >= n)) && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# --- enrolled state: reuse s00b's or bootstrap it (boot 1) -----------------------
STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00b state — building + booting it (boot 1 of 2: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s18: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    esp_make "$RUN_ENROLLED/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s18: enroll boot attempt $_attempt failed"
        ((_attempt < 2)) && { swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1; }
        rm -f "$RUN_ENROLLED/console.log"
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s18: enroll boot did not reach UNSEALED — state unusable"; exit 1; }
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared s00b state into OUR run dir (sibling prunes; the permall
# copy seals to the same SRK).
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"
swtpm_start "$STATE/tpm" || { echo "s18: swtpm restart failed"; exit 1; }

# --- console-fallback UKI variant (release-signed: extra cmdline word) -----------
echo "# building console-fallback UKI (cmdline + debian-fde-console-fallback)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" "debian-fde-console-fallback" || exit 1
assert_file_exists "console-fallback UKI built" "$RUN/harness.efi"
assert_rc "outer sbsign signature is OURS (the firmware boots the UKI)" 0 \
    sbverify --cert "$STATE/keys/db.crt" "$RUN/harness.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/harness.efi" || exit 1

# --- the foreign-signed .pcrsig ---------------------------------------------------
# FOREIGN keypair (the "compromised/foreign signer"): a valid, well-formed
# RSA key that has NOTHING to do with the enrolled release identity.
openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -out "$RUN/foreign.pub" 2>/dev/null
assert_file_exists "foreign keypair generated" "$RUN/foreign.pub"
assert_rc "foreign key is NOT the release key (distinct key material)" 1 \
    cmp -s "$RUN/foreign.pub" "$STATE/keys/release.pub"

# re-sign EVERY bank entry's pol with the foreign key (structure preserved,
# only .sig moves); pol entries are the CORRECT prediction for this UKI —
# that is the point: the value is right, the SIGNER is wrong.
REL_JSON="$RUN/uki-pcrsig.json"
FOR_JSON="$RUN/pcrsig-foreign.json"
cp "$REL_JSON" "$FOR_JSON"
N_ENTRIES=$(jq '.sha256 | length' "$REL_JSON")
if (( N_ENTRIES >= 1 )); then
    _assert_result ok "release .pcrsig carries $N_ENTRIES signed pol entries" ""
else
    _assert_result not-ok "release .pcrsig carries signed pol entries" "length=0"
fi
for ((e = 0; e < N_ENTRIES; e++)); do
    jq -r ".sha256[$e].pol" "$REL_JSON" | xxd -r -p >"$RUN/pol.bin"
    openssl dgst -sha256 -sign "$RUN/foreign.key" -out "$RUN/pol.sig" "$RUN/pol.bin"
    SIG_B64=$(openssl base64 -A -in "$RUN/pol.sig")
    # NB: update the ACCUMULATOR (FOR_JSON), not the release JSON — each
    # entry must stay foreign-signed across iterations
    jq --arg sig "$SIG_B64" ".sha256[$e].sig = \$sig" "$FOR_JSON" >"$FOR_JSON.tmp"
    mv "$FOR_JSON.tmp" "$FOR_JSON"
done
assert_eq "foreign .pcrsig keeps the SAME pol entries (only the signer moved)" \
    "$(jq -c '[.sha256[].pol]' "$REL_JSON")" "$(jq -c '[.sha256[].pol]' "$FOR_JSON")"

# _sig_verifies <json> <entry> <pubkey> — the unlock-side verification recipe,
# host-side: sig (base64) is an RSA-SHA256 signature over the RAW pol bytes.
# (Pinned empirically 2026-09-17 against ukify 261/systemd-measure output.)
_sig_verifies() {
    local json="$1" e="$2" pub="$3"
    jq -r ".sha256[$e].pol" "$json" | xxd -r -p >"$RUN/vpol.bin"
    jq -r ".sha256[$e].sig" "$json" | openssl base64 -d -A >"$RUN/vpol.sig" 2>/dev/null
    openssl dgst -sha256 -verify "$pub" -signature "$RUN/vpol.sig" "$RUN/vpol.bin" >/dev/null 2>&1
}
# EVERY entry must move to the foreign signer (entry 0 == enter-initrd is the
# one the unlock consumes — a partially re-signed JSON would leave a VALID
# release entry behind and the negative control would be vacuous)
for ((e = 0; e < N_ENTRIES; e++)); do
    assert_rc "positive control [$e]: release.pub verifies the RELEASE sig over pol" 0 \
        _sig_verifies "$REL_JSON" "$e" "$STATE/keys/release.pub"
    assert_rc "NEGATIVE control [$e]: release.pub REFUSES the foreign sig over the same pol" 1 \
        _sig_verifies "$FOR_JSON" "$e" "$STATE/keys/release.pub"
    assert_rc "sanity [$e]: foreign.pub verifies the foreign sig (well-formed, foreign-signed)" 0 \
        _sig_verifies "$FOR_JSON" "$e" "$RUN/foreign.pub"
done

# foreign payload drive — the ONLY tampered artifact on the wire
uki_pcrsig_disk "$RUN/pcrsig-foreign.img" "$FOR_JSON" || exit 1
assert_file_exists "foreign .pcrsig payload drive built" "$RUN/pcrsig-foreign.img"

# --- boot: SB-on vars, enrolled disk, FOREIGN .pcrsig on the payload drive -------
B="$RUN/boot-foreign"
mkdir -p "$B"
cp "$RUN/harness.efi" "$B/harness.efi"
cp "$RUN/pcrsig-foreign.img" "$B/pcrsig.img"
cp "$RUN/esp.img" "$B/esp.img"
cp "$STATE/disk.img" "$B/disk.img"
echo "# boot: release-signed UKI + FOREIGN .pcrsig (TCG, up to $QEMU_TIMEOUT s)"
qemu_run "$B" "$B/esp.img" "$B/disk.img" "$STATE/vars-enrolled.fd" "$STATE/tpm" "$B/pcrsig.img"
for n in 1 2 3; do
    if wait_attempt "$n" 300 "$B"; then
        _assert_result ok "guest awaiting passphrase $n/3 (fallback armed after refusal)" ""
    else
        _assert_result not-ok "guest awaiting passphrase $n/3" "no attempt $n marker in console"
        break
    fi
    feed_line "$B/serial.sock" "debian-fde-foreign-wrong-passphrase-$n"
done
qemu_wait "$B" "$QEMU_TIMEOUT"
LOG=$(cat "$B/console.log" 2>/dev/null || true)

# --- PCR forensics: the refusal must be the SIGNER, not the values ---------------
pcr_of() { grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR7=$(pcr_of "$B/console.log" 7)
PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
PCR11_POST=$(grep -oE 'debian-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$B/console.log" 2>/dev/null | head -1 | cut -d= -f2)
assert_eq "PCR 7 unchanged vs the enrolled boot (no drift confound — only the signer moved)" \
    "$PCR7_ENROLLED" "$PCR7"
POL0=$(jq -r '.sha256[0].pol' "$FOR_JSON")
POL_DIGEST=$(uki_pcr11_policy_digest "$PCR11_POST")
if [[ -n "$PCR11_POST" ]]; then
    assert_eq "post-phase PCR 11 state == the signed pol (the pol MATCHED at unlock)" \
        "$POL0" "$POL_DIGEST"
else
    _assert_result not-ok "post-phase PCR 11 state == the signed pol" \
        "no postphase PCR 11 line in console"
fi

# --- assertions: firmware boots -> policy refuses the FOREIGN signer -------------
assert_contains "init ran (firmware booted our release signature — SB saw no tamper)" "$LOG" \
    "debian-fde-harness: init started"
assert_contains "TPM char device appeared" "$LOG" "/dev/tpmrm0 present"
assert_contains "token discovered (the token path is attempted)" "$LOG" \
    "$(sentinel_of token_discovered)"
# OBSERVED (2026-09-17, this sandbox): with the pol MATCHED and the signature
# FOREIGN, 257.13's plugin logs "Adding PCR signature policy." (table key
# pcr_sig_added) and the TPM refuses the signature at Esys_VerifySignature
# (TPM_RC_SIGNATURE — "Failed to validate signature in TPM"), followed by the
# pinned tpm2_refused sentinel. This is a DIFFERENT refusal class than the
# stale-pol case (s07's pcr_sig_missing — "Couldn't find signature for this
# PCR bank"): here the value matches and the SIGNER is rejected. A dedicated
# table key for "Failed to validate signature in TPM" is a follow-up for the
# sentinel-table owner (the table is not scenario-owned; never inlined here).
assert_contains "policy matched — the plugin attempted the signature (pcr_sig_added)" "$LOG" \
    "$(sentinel_of pcr_sig_added)"
assert_contains "TPM2 unseal refused (foreign signer fails closed)" "$LOG" \
    "$(sentinel_of tpm2_refused)"
# the refusal must strictly precede the first passphrase attempt (the fallback
# loop may only arm AFTER the token path failed)
_ref_line=$(grep -nm1 -F "$(sentinel_of tpm2_refused)" "$B/console.log" 2>/dev/null | cut -d: -f1)
_att1_line=$(grep -nm1 -F "passphrase attempt 1/3" "$B/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_att1_line:-}" ]] && (( _ref_line < _att1_line )); then
    _assert_result ok "token refusal FIRST (line $_ref_line < first attempt line $_att1_line)" ""
else
    _assert_result not-ok "token refusal FIRST" "ref=$_ref_line attempt1=$_att1_line"
fi
assert_contains "fallback armed only after the refusal" "$LOG" \
    "debian-fde-harness: token refused (rc="
for n in 1 2 3; do
    assert_contains "wrong passphrase $n rejected by real cryptsetup" "$LOG" \
        "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc="
done
if [[ "$(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)" == "3" ]]; then
    _assert_result ok "exactly 3 passphrase attempts (bounded retries, no 4th)" ""
else
    _assert_result not-ok "exactly 3 passphrase attempts (bounded retries, no 4th)" \
        "rejection lines: $(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)"
fi
assert_contains "cryptsetup evidence (sentinel cryptsetup_nokey)" "$LOG" \
    "$(sentinel_of cryptsetup_nokey)"
assert_contains "PROMPT-FAILED (retries exhausted, deterministic end)" "$LOG" \
    "debian-fde: PROMPT-FAILED"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no interactive ask-password prompt (the fallback is the harness loop)" "$LOG" \
    "$(sentinel_of prompt_re)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (poweroff, not timeout-kill — no hang)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill — no hang)" \
        "qemu still running or qemu.pid missing"
fi

# keep the run dir small (the state dir is not ours to prune)
rm -f "$RUN/pol.bin" "$RUN/pol.sig" "$RUN/vpol.bin" "$RUN/vpol.sig"

kill "$REFRESHER" 2>/dev/null
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s18-foreign-pcrsig: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s18-foreign-pcrsig: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
