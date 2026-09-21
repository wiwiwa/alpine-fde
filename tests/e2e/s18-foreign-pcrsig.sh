#!/usr/bin/env bash
# tests/e2e/s18-foreign-pcrsig.sh — §6.1 signing negative controls (G-T5/G-E14):
# a forged .pcrsig must FAIL CLOSED at unlock, for EVERY forgery class:
#   control 1  foreign-key    — same (correct) pol entries, every sig re-signed
#                               by a FOREIGN RSA key (the value is right, the
#                               SIGNER is wrong);
#   control 2  wrong-selection — release-signed pols RELABELED pcrs [11] ->
#                               [7,11]: the signature is well-formed and
#                               release-signed, but the entry no longer matches
#                               the PCR selection the token pins (pcrs != the
#                               policy selection — §6.1 "pcrs ≠ {7,11}");
#   control 3  stale-d7       — a well-formed release-signed COMBINED {7,11}
#                               policyDigest computed over a STALE PCR 7
#                               (§6.1 "signature over a stale d7").
#
# Tamper geometry (all controls): the payload-drive `.pcrsig` is REPLACED; the
# outer sbsign signature is OURS (the release UKI boots unmodified), so the
# firmware happily boots it — Secure Boot cannot see the payload drive. The
# TPM policy is where each forgery must die: the token's sealed policy pivots
# on the RELEASE public key (PolicyAuthorize, §6.1 A″) over the LIVE PCR
# digest — wrong signer, wrong selection, or stale digest all refuse -> the
# token path is refused -> documented fallback prompt -> bounded retries (3)
# -> clean poweroff. NEVER `Entering emergency mode.` (H-G1).
#
# Host-side proofs per control (no TPM involved): the verification recipe
# itself is cross-checked — release.pub verifies the RELEASE sig over pol
# (positive), release.pub REFUSES the foreign sig (control 1 negative, exact
# bytes), and each forged JSON's shape/selection/freshness is pinned
# (controls 2/3). Control 1 additionally asserts the pol entries IDENTICAL
# between the release and the foreign JSON: only the signer moved.
#
# In-guest (every control): the post-phase PCR 11 asserted equal to the signed
# pol where the pol is the true prediction (control 1 — the G-T13 property:
# the pol MATCHED, so the refusal is exactly the forgery, not a value
# mismatch); controls 2/3 assert the refusal sentinel of their class.
#
# Reuses s00b's enrolled artifacts via DEBIAN_FDE_E2E_STATE (run-e2e.sh sets
# it); otherwise builds + boots them itself (bootstrap boot + 3 control boots).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/disk-fixture.sh
source "$TESTS/lib/disk-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13, §12)
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
# the stale-d7 forge signs the §6.1.1 combined {7,11} policyDigest — the
# product's own TPM-free policy math (host-side: openssl + awk only)
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"

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
    echo "# no s00b state — building + booting it (bootstrap: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s18: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    cp "$RUN_ENROLLED/uki-pcrsig.json" "$RUN/uki-pcrsig.json"   # prediction of the BOOTED UKI
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
    CONSOLE="$RUN_ENROLLED/console.log" assert_pcr11_prediction "S-18 bootstrap"
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

# --- the THREE forged .pcrsig variants (§6.1/§12 negative controls) ----------------
# FOREIGN keypair (the "compromised/foreign signer"): a valid, well-formed
# RSA key that has NOTHING to do with the enrolled release identity.
openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -out "$RUN/foreign.pub" 2>/dev/null
assert_file_exists "foreign keypair generated" "$RUN/foreign.pub"
assert_rc "foreign key is NOT the release key (distinct key material)" 1 \
    cmp -s "$RUN/foreign.pub" "$STATE/keys/release.pub"

# _sig_verifies <json> <entry> <pubkey> — the unlock-side verification recipe,
# host-side: sig (base64) is an RSA-SHA256 signature over the RAW pol bytes.
# (Pinned empirically 2026-09-17 against ukify 261/systemd-measure output.)
_sig_verifies() {
    local json="$1" e="$2" pub="$3"
    jq -r ".sha256[$e].pol" "$json" | xxd -r -p >"$RUN/vpol.bin"
    jq -r ".sha256[$e].sig" "$json" | openssl base64 -d -A >"$RUN/vpol.sig" 2>/dev/null
    openssl dgst -sha256 -verify "$pub" -signature "$RUN/vpol.sig" "$RUN/vpol.bin" >/dev/null 2>&1
}

REL_JSON="$RUN/uki-pcrsig.json"
N_ENTRIES=$(jq '.sha256 | length' "$REL_JSON")
if (( N_ENTRIES >= 1 )); then
    _assert_result ok "release .pcrsig carries $N_ENTRIES signed pol entries" ""
else
    _assert_result not-ok "release .pcrsig carries signed pol entries" "length=0"
fi

# stale-d7 forge inputs: the §6.1.1 combined {7,11} policyDigest over a STALE
# PCR 7 and a synthetic PCR 11 (the refusal class is the stale d7 term; the
# post-boot freshness negative re-derives the FRESH pol from the live console
# PCRs and asserts it differs)
D7_STALE=$(printf 's18-stale-d7' | sha256sum | awk '{print $1}')
D11_SYN=$(printf 's18-synthetic-d11' | sha256sum | awk '{print $1}')

_forge_foreign() { # <out.json> — control 1: same pols, EVERY sig moved to the
                   # foreign key (value right, SIGNER wrong)
    local out="$1" e sig
    cp "$REL_JSON" "$out"
    for ((e = 0; e < N_ENTRIES; e++)); do
        jq -r ".sha256[$e].pol" "$REL_JSON" | xxd -r -p >"$RUN/pol.bin"
        openssl dgst -sha256 -sign "$RUN/foreign.key" -out "$RUN/pol.sig" "$RUN/pol.bin"
        sig=$(openssl base64 -A -in "$RUN/pol.sig")
        # NB: update the ACCUMULATOR (out), not the release JSON — each entry
        # must stay foreign-signed across iterations
        jq --arg sig "$sig" ".sha256[$e].sig = \$sig" "$out" >"$out.tmp"
        mv "$out.tmp" "$out"
    done
}
_forge_wrongsel() { # <out.json> — control 2: release-signed pols RELABELED
                    # pcrs [11] -> [7,11] (pcrs != the token's selection)
    local out="$1" e
    cp "$REL_JSON" "$out"
    for ((e = 0; e < N_ENTRIES; e++)); do
        jq '.sha256['"$e"'].pcrs = [7, 11]' "$out" >"$out.tmp"
        mv "$out.tmp" "$out"
    done
}
_forge_staled7() { # <out.json> — control 3: well-formed release-signed {7,11}
                   # policyDigest over a STALE d7 (§6.1.1 step 3, wrong d7)
    local out="$1" pol sig
    policy_digest_bin "$D7_STALE" "$D11_SYN" >"$RUN/pol.bin"
    pol=$(policy_digest "$D7_STALE" "$D11_SYN")
    openssl dgst -sha256 -sign "$STATE/keys/db.key" -out "$RUN/pol.sig" "$RUN/pol.bin"
    sig=$(openssl base64 -A -in "$RUN/pol.sig")
    jq -n --arg pol "$pol" --arg sig "$sig" \
        '{sha256: [{pcrs: [7, 11], pol: $pol, sig: $sig}]}' >"$out"
}

# _forge_recipe <variant> <json> — the host-side positive/negative controls;
# every control must fail the recipe BEFORE the boot is worth spending
_forge_recipe() {
    local variant="$1" json="$2" e
    case "$variant" in
        foreign)
            assert_eq "[$variant] forged .pcrsig keeps the SAME pol entries (only the signer moved)" \
                "$(jq -c '[.sha256[].pol]' "$REL_JSON")" "$(jq -c '[.sha256[].pol]' "$json")"
            # EVERY entry must move to the foreign signer (entry 0 == enter-initrd is
            # the one the unlock consumes — a partially re-signed JSON would leave a
            # VALID release entry behind and the negative control would be vacuous)
            for ((e = 0; e < N_ENTRIES; e++)); do
                assert_rc "[$variant] positive control [$e]: release.pub verifies the RELEASE sig over pol" 0 \
                    _sig_verifies "$REL_JSON" "$e" "$STATE/keys/release.pub"
                assert_rc "[$variant] NEGATIVE control [$e]: release.pub REFUSES the foreign sig over the same pol" 1 \
                    _sig_verifies "$json" "$e" "$STATE/keys/release.pub"
                assert_rc "[$variant] sanity [$e]: foreign.pub verifies the foreign sig (well-formed, foreign-signed)" 0 \
                    _sig_verifies "$json" "$e" "$RUN/foreign.pub"
            done
            ;;
        wrongsel)
            assert_rc "[$variant] positive control [0]: the release sig still verifies over its pol bytes" 0 \
                _sig_verifies "$json" 0 "$STATE/keys/release.pub"
            assert_eq "[$variant] NEGATIVE control: NO entry carries the token's pcrs [11] selection anymore" "0" \
                "$(jq '[.sha256[] | select(.pcrs == [11])] | length' "$json")"
            assert_eq "[$variant] every entry is relabeled to the foreign selection [7,11]" \
                "$(jq -c '[.sha256[].pcrs]' "$json")" \
                "$(jq -cn --argjson n "$N_ENTRIES" '[range(0; $n) | [7, 11]]')"
            ;;
        staled7)
            assert_rc "[$variant] positive control [0]: release.pub verifies the release sig over the (stale) pol bytes" 0 \
                _sig_verifies "$json" 0 "$STATE/keys/release.pub"
            assert_eq "[$variant] the signed pol IS the well-formed {7,11} digest over the stale d7" \
                "$(policy_digest "$D7_STALE" "$D11_SYN")" "$(jq -r '.sha256[0].pol' "$json")"
            ;;
    esac
}

# _refusal_sentinel <variant> — the in-guest refusal sentinel of each class
_refusal_sentinel() {
    case "$1" in
        # OBSERVED (2026-09-17, this sandbox): with the pol MATCHED and the
        # signature FOREIGN, 257.13's plugin logs "Adding PCR signature policy."
        # and the TPM refuses the signature at Esys_VerifySignature
        # (TPM_RC_SIGNATURE), followed by the pinned tpm2_refused sentinel — a
        # DIFFERENT refusal class than the stale/mismatched-pol case (s07's
        # pcr_sig_missing — "Couldn't find signature for this PCR bank").
        foreign) printf '%s\n' "$(sentinel_of tpm2_refused)" ;;
        wrongsel | staled7) printf '%s\n' "$(sentinel_of pcr_sig_missing)" ;;
    esac
}

for VARIANT in foreign wrongsel staled7; do
    FOR_JSON="$RUN/pcrsig-$VARIANT.json"
    case "$VARIANT" in
        foreign) _forge_foreign "$FOR_JSON" ;;
        wrongsel) _forge_wrongsel "$FOR_JSON" ;;
        staled7) _forge_staled7 "$FOR_JSON" ;;
    esac
    _forge_recipe "$VARIANT" "$FOR_JSON"

    # forged payload drive — the ONLY tampered artifact on the wire
    uki_pcrsig_disk "$RUN/pcrsig-$VARIANT.img" "$FOR_JSON" || exit 1
    assert_file_exists "[$VARIANT] forged .pcrsig payload drive built" "$RUN/pcrsig-$VARIANT.img"

    # --- boot: SB-on vars, enrolled disk, FORGED .pcrsig on the payload drive ----
    B="$RUN/boot-$VARIANT"
    mkdir -p "$B"
    cp "$RUN/harness.efi" "$B/harness.efi"
    cp "$RUN/pcrsig-$VARIANT.img" "$B/pcrsig.img"
    cp "$RUN/esp.img" "$B/esp.img"
    cp "$STATE/disk.img" "$B/disk.img"
    echo "# [$VARIANT] boot: release-signed UKI + forged .pcrsig (TCG, up to $QEMU_TIMEOUT s)"
    qemu_run "$B" "$B/esp.img" "$B/disk.img" "$STATE/vars-enrolled.fd" "$STATE/tpm" "$B/pcrsig.img"
    for n in 1 2 3; do
        if wait_attempt "$n" 300 "$B"; then
            _assert_result ok "[$VARIANT] guest awaiting passphrase $n/3 (fallback armed after refusal)" ""
        else
            _assert_result not-ok "[$VARIANT] guest awaiting passphrase $n/3" "no attempt $n marker in console"
            break
        fi
        feed_line "$B/serial.sock" "debian-fde-$VARIANT-wrong-passphrase-$n"
    done
    qemu_wait "$B" "$QEMU_TIMEOUT"
    CONSOLE="$B/console.log" assert_pcr11_prediction "S-18 $VARIANT"
    LOG=$(cat "$B/console.log" 2>/dev/null || true)

    # --- control-1 forensics: the refusal must be the SIGNER, not the values -----
    pcr_of() { grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
    if [[ "$VARIANT" == "foreign" ]]; then
        PCR7=$(pcr_of "$B/console.log" 7)
        PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
        PCR11_POST=$(grep -oE 'debian-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$B/console.log" 2>/dev/null | head -1 | cut -d= -f2)
        assert_eq "[$VARIANT] PCR 7 unchanged vs the enrolled boot (no drift confound — only the signer moved)" \
            "$PCR7_ENROLLED" "$PCR7"
        POL0=$(jq -r '.sha256[0].pol' "$FOR_JSON")
        POL_DIGEST=$(uki_pcr11_policy_digest "$PCR11_POST")
        if [[ -n "$PCR11_POST" ]]; then
            assert_eq "[$VARIANT] post-phase PCR 11 state == the signed pol (the pol MATCHED at unlock)" \
                "$POL0" "$POL_DIGEST"
        else
            _assert_result not-ok "[$VARIANT] post-phase PCR 11 state == the signed pol" \
                "no postphase PCR 11 line in console"
        fi
        assert_contains "[$VARIANT] policy matched — the plugin attempted the signature (pcr_sig_added)" "$LOG" \
            "$(sentinel_of pcr_sig_added)"
    fi
    if [[ "$VARIANT" == "staled7" ]]; then
        # freshness negative over the LIVE console PCRs: the fresh {7,11} digest
        # over the boot's real d7/d11 differs from the stale-signed pol
        D7_LIVE=$(pcr_of "$B/console.log" 7)
        D11_LIVE=$(grep -oE 'debian-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$B/console.log" 2>/dev/null | head -1 | cut -d= -f2)
        if [[ -n "$D7_LIVE" && -n "$D11_LIVE" ]]; then
            assert_ne "[$VARIANT] NEGATIVE control: the stale pol != the fresh pol over the LIVE PCRs" \
                "$(jq -r '.sha256[0].pol' "$FOR_JSON")" "$(policy_digest "$D7_LIVE" "$D11_LIVE")"
        else
            _assert_result not-ok "[$VARIANT] freshness negative (live PCRs on console)" \
                "no PCR evidence in console"
        fi
    fi

    # --- assertions: firmware boots -> policy refuses the FORGERY fail-closed ----
    assert_contains "[$VARIANT] init ran (firmware booted our release signature — SB saw no tamper)" "$LOG" \
        "$(sentinel_of harness_init_started)"
    assert_contains "[$VARIANT] TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
    assert_contains "[$VARIANT] token discovered (the token path is attempted)" "$LOG" \
        "$(sentinel_of token_discovered)"
    assert_contains "[$VARIANT] token path REFUSED ($VARIANT forgery fails closed)" "$LOG" \
        "$(_refusal_sentinel "$VARIANT")"
    # the refusal must strictly precede the first passphrase attempt (the fallback
    # loop may only arm AFTER the token path failed)
    _ref_line=$(grep -nm1 -F "$(_refusal_sentinel "$VARIANT")" "$B/console.log" 2>/dev/null | cut -d: -f1)
    _att1_line=$(grep -nm1 -F "passphrase attempt 1/3" "$B/console.log" 2>/dev/null | cut -d: -f1)
    if [[ -n "${_ref_line:-}" && -n "${_att1_line:-}" ]] && (( _ref_line < _att1_line )); then
        _assert_result ok "[$VARIANT] token refusal FIRST (line $_ref_line < first attempt line $_att1_line)" ""
    else
        _assert_result not-ok "[$VARIANT] token refusal FIRST" "ref=$_ref_line attempt1=$_att1_line"
    fi
    assert_contains "[$VARIANT] fallback armed only after the refusal" "$LOG" \
        "debian-fde-harness: token refused (rc="
    for n in 1 2 3; do
        assert_contains "[$VARIANT] wrong passphrase $n rejected by real cryptsetup" "$LOG" \
            "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc="
    done
    if [[ "$(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)" == "3" ]]; then
        _assert_result ok "[$VARIANT] exactly 3 passphrase attempts (bounded retries, no 4th)" ""
    else
        _assert_result not-ok "[$VARIANT] exactly 3 passphrase attempts (bounded retries, no 4th)" \
            "rejection lines: $(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)"
    fi
    assert_contains "[$VARIANT] cryptsetup evidence (sentinel cryptsetup_nokey)" "$LOG" \
        "$(sentinel_of cryptsetup_nokey)"
    assert_contains "[$VARIANT] PROMPT-FAILED (retries exhausted, deterministic end)" "$LOG" \
        "$(sentinel_of harness_prompt_failed)"
    assert_not_contains "[$VARIANT] never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
    assert_not_contains "[$VARIANT] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
    assert_not_contains "[$VARIANT] no interactive ask-password prompt (the fallback is the harness loop)" "$LOG" \
        "$(sentinel_of prompt_re)"
    assert_not_contains "[$VARIANT] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
    assert_contains "[$VARIANT] clean poweroff sentinel" "$LOG" "$(sentinel_of harness_poweroff)"
    # IN-08: honest in both directions (missing pid file is not a clean exit)
    if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "[$VARIANT] guest exited (poweroff, not timeout-kill — no hang)" ""
    else
        _assert_result not-ok "[$VARIANT] guest exited (poweroff, not timeout-kill — no hang)" \
            "qemu still running or qemu.pid missing"
    fi
done

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
