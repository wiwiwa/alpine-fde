#!/usr/bin/env bash
# tests/e2e/s18-foreign-pcrsig.sh — §6.1 signing negative controls (G-T5/G-E14,
# G-B4-11): a forged .pcrsig must FAIL CLOSED at the SHIPPED mkinitfs unseal
# hook (§8.2; ADR-13 — the harness DEFAULT unlock), for EVERY forgery class:
#   control 1  foreign      — same (correct) pol entries, every sig re-signed
#                             by a FOREIGN RSA key (the value is right, the
#                             SIGNER is wrong) -> the hook's I3 openssl gate
#                             refuses against /.extra/tpm2-pcr-public-key.pem;
#   control 2  wrongsel     — release-signed pols RELABELED pcrs [11] ->
#                             [7,11]: the relabeled entries are well-formed
#                             and release-signed, but the token's signature
#                             covers the ENROLLED combined {7,11} pol, not
#                             the relabel-stolen ladder pol -> the hook's I3
#                             openssl gate refuses (no verifiable pair);
#   control 3  staled7      — a well-formed release-signed COMBINED {7,11}
#                             policyDigest computed over a STALE PCR 7 ->
#                             the token's signature covers the FRESH combined
#                             pol -> I3 refuses the stale (pol, sig) pair;
#   control 4  pcrsig11only — G-B4-11 direct: the payload drive carries ONLY
#                             the release ladder's [11] entries while the
#                             token pins {7,11} -> the hook finds no entry
#                             for the token's PCR selection -> I3 refuses;
#   control 5  tok11        — G-B4-11 inverse: the token's tpm2-pcrs RELABELED
#                             to [11] (metadata write) while the .pcrsig keeps
#                             its ladder -> the hook takes the [11] selection
#                             but the token's signature still covers the
#                             enrolled combined {7,11} pol, never the ladder
#                             pol the payload carries -> I3 refuses.
#
# Tamper geometry (controls 1-4): the payload-drive `.pcrsig` is REPLACED (the
# outer sbsign signature is OURS — the release UKI boots unmodified; Secure
# Boot cannot see the payload drive). Control 5 tampers the token JSON
# instead (the s13 mechanism). The hook's I3 openssl gate is where every
# forgery dies (live-pinned 2026-09-22, see _refusal_sentinel): the token's
# release signature covers exactly the enrolled combined {7,11} pol, so a
# forged payload never hands the gate a verifiable (pol, sig) pair — the gate
# refuses before any TPM session. (The TPM policy session class is the
# PCR-drift refusal exercised by s01/s12/s15.)
# Every refusal then runs the hook's bounded recovery loop -> 3 wrong
# answers -> 3-strike fail-closed `poweroff -f`. NEVER an emergency shell.
#
# Host-side proofs per control (no TPM involved): the verification recipe
# itself is cross-checked — release.pub verifies the RELEASE sig over pol
# (positive), release.pub REFUSES the foreign sig (control 1 negative, exact
# bytes), and each forged JSON's shape/selection/freshness is pinned.
# Control 1 additionally asserts the pol entries IDENTICAL between the
# release and the foreign JSON: only the signer moved.
#
# NB (G-T13): NO assert_pcr11_prediction on these boots — the hook fails
# closed INSIDE its own invocation, so /init never reaches its post-hook
# postphase PCR 11 reading. Tamper scoping is asserted instead: PCR 7
# unchanged vs the enrolled boot (the forgery lives on the payload drive /
# token JSON, not in the firmware measurement).
#
# Reuses s00b's enrolled artifacts via ALPINE_FDE_E2E_STATE (run-e2e.sh sets
# it); otherwise builds + boots them itself (bootstrap boot + 5 control boots).

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
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH
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

# _reanchor_tpm <dir> — before EVERY control boot the fixture TPM must be a
# FRESH, ZEROED instance. swtpm_ensure's restore path (or a live instance
# carrying the previous boot's final values) hands the next boot a register
# whose provenance the scenario cannot vouch for, and the fixture proxy's
# 2026-09-22 command-drop defect (silently dropped SET_DATAFD/commands — see
# the tests/lib report) produced both the silent pre-BdsDxe hang and the
# degraded-measurement boots (PCR 0 = 2152…, 2× EFI-stub "Failed to measure",
# PCR 7 off the enrolled value) that failed the wrongsel control. The
# enrolled-PCR-7 comparison is only honest if the pre-boot register is
# ASSERTED zero, not assumed — so scrub the volatile state, start with
# startup-clear (the SRK in the permall persists, which the token's seal
# needs), verify, and refuse to spend the boot otherwise.
_reanchor_tpm() {
    local dir="$1" d0 d7 attempt
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    swtpm_start "$dir" || { echo "s18: swtpm restart failed before a control boot"; exit 1; }
    # Zero-proof with a bounded recycle-retry (2026-09-24 hardening): a single
    # pcrread against a just-started instance can return EMPTY under load
    # (registry: "pcr0= pcr7=" aborted a control boot whose start probe had
    # just PASSED) — and an empty read must never be conflated with a
    # cumulative register. A fresh startup-clear start ALWAYS lands zeros, so
    # recycling on ANY nonconforming read is strictly honest: only a fixture
    # that cannot serve a zero register after a forced recycle aborts the
    # scenario (a real defect, loudly).
    for attempt in 1 2 3; do
        d0=$(swtpm_pcrread "$dir" 0)
        d7=$(swtpm_pcrread "$dir" 7)
        if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ ]]; then
            break
        fi
        echo "s18: re-anchor readback attempt $attempt not zero (pcr0=${d0:-<empty>} pcr7=${d7:-<empty>}) — recycling the fixture"
        if (( attempt == 3 )); then
            _assert_result not-ok "fixture: control-boot TPM re-anchored (PCRs 0 and 7 zero before the boot)" \
                "pcr0=${d0:-<empty>} pcr7=${d7:-<empty>} after 3 forced recycles — refusing to spend the boot"
            echo "s18: TPM not zeroed before a control boot — aborting"; exit 1
        fi
        swtpm_stop "$dir" 2>/dev/null || true
        swtpm_start "$dir" || { echo "s18: swtpm restart (re-anchor retry) failed"; exit 1; }
    done
    _assert_result ok "fixture: control-boot TPM re-anchored (PCRs 0 and 7 zero before the boot)" ""
    # settle: libtpms re-initializes from the tpmstate dir at qemu's CMD_INIT
    # and the control-channel proxy has just bound — a guest TPM command
    # arriving mid-setup times out and the firmware DROPS the measurement
    # (exactly the degraded-boot signature: EFI stub "Failed to measure",
    # PCR 0/7 off the enrolled values). Warm the whole path with real
    # commands through the proxy and give the setup a bounded moment.
    local k
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
}

# --- enrolled state: reuse s00b's or bootstrap it (bootstrap boot) -------------
STATE="${ALPINE_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -d "$STATE/keys" && -f "$STATE/vars-enrolled.fd" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00b state — building + booting it (bootstrap: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s18: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    esp_make "$RUN_ENROLLED/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s18: no enter-initrd d11 prediction from the build"; exit 1; }
    for _attempt in 1 2 3; do
        # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the pristine
        # base (LOCK_SH via overlay_create; discarded after the attempt) — the
        # bootstrap boot cannot persist anything to the base before the
        # HOST-SIDE enrollment below writes the standing token (the s12 idiom).
        OVERLAY_BOOT="$RUN_ENROLLED/disk-bootstrap-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_BOOT" || {
            echo "s18: overlay create failed (bootstrap attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_BOOT" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        # EARLY degradation gate (the same TPM-command-timeout class the
        # control boots gate on): the EFI stub logs its measurement failures
        # in the first minute, long before the hook prompt — discard a
        # degraded boot without spending the (900 s) prompt wait on it.
        _i=0
        while (( _i < 900 )); do
            kill -0 "$(cat "$RUN_ENROLLED/qemu.pid" 2>/dev/null)" 2>/dev/null || break
            grep -q "EFI stub: WARNING: Failed to measure data for event" \
                "$RUN_ENROLLED/console.log" 2>/dev/null && break
            grep -qE "$(sentinel_of unseal_prompt_re)" \
                "$RUN_ENROLLED/console.log" 2>/dev/null && break
            sleep 2
            _i=$((_i + 2))
        done
        if grep -q "EFI stub: WARNING: Failed to measure data for event" \
            "$RUN_ENROLLED/console.log" 2>/dev/null; then
            echo "s18: bootstrap boot $_attempt lost firmware measurements (EFI stub 'Failed to measure') — discarding"
            if (( _attempt < 3 )); then
                qemu_kill "$RUN_ENROLLED"
                overlay_discard "$OVERLAY_BOOT"   # the discarded attempt's overlay is ephemeral
                swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
                rm -f "$RUN_ENROLLED/console.log"
                continue
            fi
        fi
        # 900 s: this box's boots crawl under background tenants (the hook's
        # read has no timeout — the feed stays prompt-synchronized); a late
        # prompt is a slow boot, never a missing one.
        if uki_wait_hook_prompt 1 900 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        overlay_discard "$OVERLAY_BOOT"   # the attempt's overlay is ephemeral
        # faithfulness: UNSEALED reached, no measurement-loss warnings, and
        # the postphase PCR 11 equals the build's enter-initrd prediction
        # (G-T13 — a mismatch means the register this state is enrolled
        # against would NOT be the register a faithful boot reproduces, and
        # the enroll's own G-B6 gate would refuse it later).
        _d11_boot=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' \
            "$RUN_ENROLLED/console.log" 2>/dev/null | head -1 | cut -d= -f2)
        if grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" \
            && ! grep -q "EFI stub: WARNING: Failed to measure data for event" \
                "$RUN_ENROLLED/console.log" 2>/dev/null \
            && [[ -n "$_d11_boot" && "$_d11_boot" == "$D11" ]]; then
            break
        fi
        echo "s18: bootstrap boot attempt $_attempt failed or unfaithful (TPM degraded / postphase d11 != prediction)"
        if (( _attempt < 3 )); then
            qemu_kill "$RUN_ENROLLED" 2>/dev/null
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s18: bootstrap boot did not reach UNSEALED — state unusable"; exit 1; }
    grep -q "EFI stub: WARNING: Failed to measure data for event" "$RUN_ENROLLED/console.log" && {
        echo "s18: bootstrap boot degraded after 3 attempts — state unusable"; exit 1; }
    # host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): the combined {7,11} entry the hook extracts.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s18: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s18: no PCR 7 in the bootstrap console"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    EFIVARS="$RUN_ENROLLED/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || {
        echo "s18: production enroll-tpm FAILED"; exit 1; }
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    cp "$RUN_ENROLLED/uki-pcrsig-combined.json" "$RUN/uki-pcrsig.json"   # the BOOTED enrollment's pcrsig
    swtpm_stop "$RUN_ENROLLED/tpm"
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
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"
swtpm_start "$STATE/tpm" || { echo "s18: swtpm restart failed"; exit 1; }

# --- the release UKI variant (outer sbsign signature is OURS) --------------------
echo "# building the release UKI variant (fresh signed prediction for the forgeries)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" || exit 1
assert_file_exists "release UKI built" "$RUN/harness.efi"
assert_rc "outer sbsign signature is OURS (the firmware boots the UKI)" 0 \
    sbverify --cert "$STATE/keys/db.crt" "$RUN/harness.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/harness.efi" || exit 1
D11_PRED=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_PRED" ]] || { echo "s18: no enter-initrd d11 prediction from the build"; exit 1; }

# --- the FIVE forged fixtures (§6.1/§12/§8.2 negative controls) --------------------
# FOREIGN keypair (the "compromised/foreign signer"): a valid, well-formed
# RSA key that has NOTHING to do with the enrolled release identity.
openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -out "$RUN/foreign.pub" 2>/dev/null
assert_file_exists "foreign keypair generated" "$RUN/foreign.pub"
assert_rc "foreign key is NOT the release key (distinct key material)" 1 \
    cmp -s "$RUN/foreign.pub" "$STATE/keys/release.pub"

# _sig_verifies <json> <entry> <pubkey> — the hook-side verification recipe,
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
# PCR 7 and a synthetic PCR 11.
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
                    # pcrs [11] -> [7,11] (the entry exists, the policy is
                    # not the token's {7,11} policy)
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
# control 4 (pcrsig11only): the payload drive carries the release LADDER as-is
# ([11] entries only) while the token pins {7,11} — no forge needed, the
# mismatch IS the omission (G-B4-11 direct)

# control 5 (tok11): the TOKEN's tpm2-pcrs relabeled [7,11] -> [11] (LUKS2
# metadata write, the s13 mechanism); the payload keeps the release ladder
_tok11_tamper_disk() { # <disk-copy> — relabel the token's PCR selection
    local disk="$1"
    cryptsetup token export "$disk" --json-file "$RUN/tok11-orig.json" 2>/dev/null \
        || cryptsetup token export "$disk" --token-id 0 --json-file "$RUN/tok11-orig.json"
    jq '.["tpm2-pcrs"] = [11]' "$RUN/tok11-orig.json" >"$RUN/tok11.json"
    cryptsetup token remove --token-id 0 "$disk" 2>/dev/null
    # --disable-external-tokens (the lib/token.sh token_import discipline): the
    # systemd-tpm2 PLUGIN validation refuses the export->edit->import
    # roundtrip ("wrong or missing parameters" — live-replicated 2026-09-22);
    # validation belongs to the pinned §7.2 schema, not to the host's plugin.
    cryptsetup token import "$disk" --token-id 0 --json-file "$RUN/tok11.json" \
        --disable-external-tokens
}

# _forge_recipe <variant> <json> — the host-side positive/negative controls;
# every control must fail the recipe BEFORE the boot is worth spending
_forge_recipe() {
    local variant="$1" json="$2" e
    case "$variant" in
        foreign)
            assert_eq "[$variant] forged .pcrsig keeps the SAME pol entries (only the signer moved)" \
                "$(jq -c '[.sha256[].pol]' "$REL_JSON")" "$(jq -c '[.sha256[].pol]' "$json")"
            # EVERY entry must move to the foreign signer (a partially
            # re-signed JSON would leave a VALID release entry behind and the
            # negative control would be vacuous)
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
        pcrsig11only)
            assert_eq "[$variant] NEGATIVE control: NO entry carries the token's pcrs [7,11] selection" "0" \
                "$(jq '[.sha256[] | select((.pcrs | join(",")) == "7,11")] | length' "$json")"
            assert_eq "[$variant] the drive carries only [11] ladder entries (G-B4-11 direct)" \
                "$(jq -c '[.sha256[].pcrs]' "$json")" \
                "$(jq -c '[.sha256[].pcrs]' "$REL_JSON")"
            assert_rc "[$variant] positive control [0]: the [11] entries are release-signed (the omission is the only defect)" 0 \
                _sig_verifies "$json" 0 "$STATE/keys/release.pub"
            ;;
        tok11)
            # token-side control: the re-exported token must pin [11] now
            cryptsetup token export "$RUN/boot-tok11/disk.img" --json-file "$RUN/tok11-chk.json" 2>/dev/null \
                || cryptsetup token export "$RUN/boot-tok11/disk.img" --token-id 0 --json-file "$RUN/tok11-chk.json"
            assert_eq "[$variant] NEGATIVE control: the token's tpm2-pcrs relabeled to [11]" \
                "[11]" "$(jq -c '.["tpm2-pcrs"]' "$RUN/tok11-chk.json")"
            assert_eq "[$variant] the payload keeps the release ladder ([11] entries, release-signed)" \
                "$(jq -c '[.sha256[].pcrs]' "$REL_JSON")" "$(jq -c '[.sha256[].pcrs]' "$json")"
            assert_rc "[$variant] positive control [0]: the ladder entry the hook will take is release-signed" 0 \
                _sig_verifies "$json" 0 "$STATE/keys/release.pub"
            ;;
    esac
}

# _refusal_sentinel <variant> — the hook's refusal class of each forgery.
# Live-pinned against the SHIPPED hook (re-pinned 2026-09-24 for the I3
# entry-sig redesign): the openssl gate now verifies the DRIVE ENTRY's OWN
# (pol, sig) pair against the /.extra release key — NOT the token's
# tpm2-signature. So the refusal class splits by whether the forgery leaves
# the entry's (pol, sig) correspondence intact:
#   foreign, pcrsig11only — the gate itself refuses (no entry whose sig
#     verifies against the release key for the token's selection):
#     unseal_sig_refused, BEFORE any TPM session.
#   wrongsel, staled7, tok11 — the entry's (pol, sig) pair is internally
#     consistent AND release-signed (relabeling pcrs / aging d7 / relabeling
#     the token's selection never touches the signed bytes), so the openssl
#     gate passes and the TPM-policy session refuses instead
#     (unseal_seal_refused: PolicyPCR over the token's selection cannot
#     rebuild the sealed policy from a wrong/stale pol). Console evidence
#     2026-09-23 registry: all three printed the seal refusal.
# Both classes are fail-closed identically (bounded recovery loop -> 3-strike
# poweroff) — the I3 invariant ("forgery can only break, never forge") holds
# in both.
_refusal_sentinel() {
    case "$1" in
        wrongsel | staled7 | tok11)
            printf '%s\n' "$(sentinel_of unseal_seal_refused)" ;;
        *)
            printf '%s\n' "$(sentinel_of unseal_sig_refused)" ;;
    esac
}

# _token_info_pcrs <variant> — what the hook's token line must show
_token_info_pcrs() {
    case "$1" in
        tok11) printf '11]' ;;
        *) printf '7,11]' ;;
    esac
}

for VARIANT in foreign wrongsel staled7 pcrsig11only tok11; do
    FOR_JSON="$RUN/pcrsig-$VARIANT.json"
    case "$VARIANT" in
        foreign) _forge_foreign "$FOR_JSON" ;;
        wrongsel) _forge_wrongsel "$FOR_JSON" ;;
        staled7) _forge_staled7 "$FOR_JSON" ;;
        pcrsig11only) cp "$REL_JSON" "$FOR_JSON" ;;
        tok11) cp "$REL_JSON" "$FOR_JSON" ;;
    esac

    # forged payload drive — the ONLY tampered artifact on the wire (except
    # tok11, whose extra tamper is the relabeled token on the disk copy)
    uki_pcrsig_disk "$RUN/pcrsig-$VARIANT.img" "$FOR_JSON" || exit 1
    assert_file_exists "[$VARIANT] forged .pcrsig payload drive built" "$RUN/pcrsig-$VARIANT.img"

    # --- boot: SB-on vars, enrolled disk, FORGED .pcrsig on the payload drive ----
    B="$RUN/boot-$VARIANT"
    mkdir -p "$B"
    cp "$RUN/harness.efi" "$B/harness.efi"
    cp "$RUN/pcrsig-$VARIANT.img" "$B/pcrsig.img"
    cp "$RUN/esp.img" "$B/esp.img"
    # Wave-2 2b disk-leg classification:
    #   tok11 — the boot disk carries a HOST-side cryptsetup tamper (token
    #           export/import) and a post-build host-side recipe read
    #           (_forge_recipe) — cryptsetup cannot operate on qcow2, so this
    #           leg keeps its per-boot RAW copy (decision rule 3);
    #   all other controls — read-mostly base boots (the hook refuses before
    #           any unlock; the assertions are console-only), so each boot
    #           attempt runs a fresh QCOW2 OVERLAY over the pristine $STATE
    #           snapshot (decision rule 1; created per attempt in the boot
    #           loop below, discarded after it — a degradation retry gets a
    #           fresh overlay over the same pristine base).
    if [[ "$VARIANT" == "tok11" ]]; then
        cp "$STATE/disk.img" "$B/disk.img"
        BOOTIMG="$B/disk.img"
    else
        BOOTIMG="$B/disk.qcow2"
    fi
    # per-boot VARS copy: the vars pflash is WRITABLE, and a varstore mutated
    # by an earlier control boot's firmware pass must never leak into this
    # boot's Secure Boot policy measurement (every copy starts from the same
    # enrolled template — the SB identity is unchanged, the cross-boot
    # mutation channel is gone)
    cp "$STATE/vars-enrolled.fd" "$B/vars.fd"
    # every control boot must run on a fresh, ZEROED instance of the SAME
    # state dir: a clean guest exit terminates the swtpm (the
    # shutdown/STORE_VOLATILE control-channel proxy forwards CMD_SHUTDOWN —
    # s00 note), and without the restart the NEXT qemu dies at startup
    # ("Failed to send CMD_SET_DATAFD", empty console — live-evidenced
    # 2026-09-22, boot-wrongsel). The SRK persists in the permall; the
    # re-anchor below SCRUBS the stored volatile state so each boot re-derives
    # its PCRs from zero (asserted, not assumed — see _reanchor_tpm) and the
    # enrolled-PCR-7 comparison stays honest.
    _reanchor_tpm "$STATE/tpm"
    if [[ "$VARIANT" == "tok11" ]]; then
        tamper_rc=0
        _tok11_tamper_disk "$B/disk.img" || tamper_rc=$?
        if (( tamper_rc == 0 )); then
            _assert_result ok "[$VARIANT] token PCR-selection relabel landed (host-side tamper)" ""
        else
            _assert_result not-ok "[$VARIANT] token PCR-selection relabel landed" "cryptsetup import/export failed"
        fi
    fi
    # host-side controls first: the forgery recipe itself must fail/behave as
    # pinned BEFORE the boot is worth spending
    _forge_recipe "$VARIANT" "$FOR_JSON"
    # pcr_of <console.log> <pcr> — the harness PCR-print parser (forensics
    # below AND the degraded-boot detector share it)
    pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
    PCR0_ENROLLED=$(pcr_of "$STATE/console.log" 0)
    # _boot_degraded <dir> — TRUE when this boot's firmware measurement is not
    # FAITHFUL: PCR 0 differs from the enrolled boot (TPM command timeouts
    # under host load drop PEI-phase measurements — live-evidenced 2026-09-22,
    # runs 1790041809/…452666/…47710: degraded boots measured
    # PCR0/PCR7 = 2152…/ec30… with 2 EFI stub "Failed to measure" warnings,
    # every faithful boot measured the enrolled 8bbb…/ed63… with none), or the
    # console carries the stub warnings while the hook's PCR print never landed
    # (boot stuck before the hook started). A degraded boot would make the
    # PCR 7 forensics indict the forgery for a HARNESS artifact — the control
    # must run on a faithful boot, so these are discarded and re-run.
    _boot_degraded() {
        local p0
        p0=$(pcr_of "$1/console.log" 0)
        if [[ -n "$p0" ]]; then
            [[ -n "$PCR0_ENROLLED" && "$p0" != "$PCR0_ENROLLED" ]] && return 0
            return 1
        fi
        grep -q "EFI stub: WARNING: Failed to measure data for event" \
            "$1/console.log" 2>/dev/null && return 0
        return 1
    }

    echo "# [$VARIANT] boot: release-signed UKI + forged .pcrsig (TCG, up to $QEMU_TIMEOUT s)"
    _attempt=1
    while :; do
        if [[ "$VARIANT" != "tok11" ]]; then
            overlay_create "$STATE/disk.img" "$BOOTIMG" || {
                echo "s18: overlay create failed ([$VARIANT] boot $_attempt)"; exit 1; }
        fi
        qemu_run "$B" "$B/esp.img" "$BOOTIMG" "$B/vars.fd" "$STATE/tpm" "$B/pcrsig.img"
        # EARLY degradation gate: the hook prints the live PCRs BEFORE the
        # token line, the refusal and the recovery prompts — so a boot that
        # lost firmware measurements to TPM command timeouts (see
        # _boot_degraded) is detectable — and cheap to discard — long before
        # the prompt cycle. Bounded: a boot whose PCR print never lands is
        # broken anyway and falls through to the loud prompt assertions.
        _p0=""
        _i=0
        while (( _i < 600 )); do
            kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null || break
            _p0=$(pcr_of "$B/console.log" 0)
            [[ -n "$_p0" ]] && break
            grep -q "EFI stub: WARNING: Failed to measure data for event" \
                "$B/console.log" 2>/dev/null && break
            sleep 2
            _i=$((_i + 2))
        done
        if { [[ -n "$_p0" ]] || grep -q "EFI stub: WARNING: Failed to measure data for event" \
                "$B/console.log" 2>/dev/null; } && _boot_degraded "$B"; then
            if (( _attempt < 5 )); then
                echo "s18: [$VARIANT] boot $_attempt lost firmware measurements to host load" \
                     "(EFI stub 'Failed to measure' / PCR 0 off the enrolled value) — discarding and re-running"
                qemu_kill "$B"
                if [[ "$VARIANT" != "tok11" ]]; then
                    overlay_discard "$BOOTIMG"   # the retry gets a FRESH overlay over the pristine base
                fi
                cp "$STATE/vars-enrolled.fd" "$B/vars.fd"
                _reanchor_tpm "$STATE/tpm"
                _attempt=$((_attempt + 1))
                continue
            fi
            echo "s18: [$VARIANT] still degraded after $_attempt boots — continuing (the PCR 7 forensics will fail loudly)"
        fi
        # every control refuses -> the hook's bounded loop reads 3 WRONG
        # answers through its OWN prompt (no read timeout: the feed must be
        # prompt-synchronized), ending in the 3-strike fail-closed poweroff.
        # 900 s per prompt (was 300, then 600): this box's boots were
        # live-seen reaching the hook prompt at ~7 min (consolidated run) and
        # past the 600 s mark (2026-09-22, tok11 — the prompt line landed as
        # the wait expired). A late prompt is a slow boot, never a missing
        # one. Prompt arrivals are RECORDED here and asserted after the
        # (possibly retried) boot, so a retried boot never double-counts
        # assertions.
        _FED=(0 0 0)
        for n in 1 2 3; do
            if uki_wait_hook_prompt "$n" 900 "$B"; then
                _FED[$((n - 1))]=1
                feed_line "$B/serial.sock" "alpine-fde-$VARIANT-wrong-passphrase-$n"
            else
                break
            fi
        done
        qemu_wait "$B" "$QEMU_TIMEOUT"
        if [[ "$VARIANT" != "tok11" ]]; then
            overlay_discard "$BOOTIMG"   # the control's overlay is ephemeral (console-only asserts)
        fi
        break
    done
    for n in 1 2 3; do
        if [[ "${_FED[$((n - 1))]}" == 1 ]]; then
            _assert_result ok "[$VARIANT] hook awaiting recovery passphrase $n/3" ""
        else
            _assert_result not-ok "[$VARIANT] hook awaiting recovery passphrase $n/3" \
                "no prompt $n in console"
            break
        fi
    done
    LOG=$(cat "$B/console.log" 2>/dev/null || true)

    # --- control forensics: the refusal must be the FORGERY, not a confound -----
    PCR7=$(pcr_of "$B/console.log" 7)
    PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
    assert_eq "[$VARIANT] PCR 7 unchanged vs the enrolled boot (no drift confound — only the drive/token moved)" \
        "$PCR7_ENROLLED" "$PCR7"
    if [[ "$VARIANT" == "staled7" ]]; then
        # freshness negative over the LIVE console PCR 7 + this build's signed
        # enter-initrd prediction: the fresh {7,11} digest differs from the
        # stale-signed pol (the refusal is the stale d7, not bad signing)
        D7_LIVE=$PCR7
        if [[ -n "$D7_LIVE" ]]; then
            assert_ne "[$VARIANT] NEGATIVE control: the stale pol != the fresh pol over the LIVE d7 + the build's d11" \
                "$(jq -r '.sha256[0].pol' "$FOR_JSON")" "$(policy_digest "$D7_LIVE" "$D11_PRED")"
        else
            _assert_result not-ok "[$VARIANT] freshness negative (live PCRs on console)" \
                "no PCR evidence in console"
        fi
    fi

    # --- assertions: firmware boots -> the hook refuses the FORGERY fail-closed --
    assert_contains "[$VARIANT] init ran (firmware booted our release signature — SB saw no tamper)" "$LOG" \
        "$(sentinel_of harness_init_started)"
    assert_contains "[$VARIANT] TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
    assert_contains "[$VARIANT] hook ran the enter-initrd extend" "$LOG" \
        "$(sentinel_of unseal_pcrextend_ok)"
    assert_contains "[$VARIANT] hook discovered the token (selection: $(_token_info_pcrs "$VARIANT"))" "$LOG" \
        "$(sentinel_of unseal_token_info)$(_token_info_pcrs "$VARIANT")"
    assert_contains "[$VARIANT] hook REFUSED the forgery ($VARIANT fails closed)" "$LOG" \
        "$(_refusal_sentinel "$VARIANT")"
    # the refusal must strictly precede the first passphrase prompt (the
    # recovery loop may only arm AFTER the token path failed)
    _ref_line=$(grep -nm1 -F "$(_refusal_sentinel "$VARIANT")" "$B/console.log" 2>/dev/null | cut -d: -f1)
    _p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$B/console.log" 2>/dev/null | cut -d: -f1)
    if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
        _assert_result ok "[$VARIANT] hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
    else
        _assert_result not-ok "[$VARIANT] hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
    fi
    PROMPTS=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
    assert_eq "[$VARIANT] exactly 3 recovery-passphrase prompts (bounded loop, no 4th)" "3" "$PROMPTS"
    assert_contains "[$VARIANT] 3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
    assert_contains "[$VARIANT] fail-closed poweroff (no shell is offered)" "$LOG" \
        "$(sentinel_of unseal_poweroff)"
    assert_not_contains "[$VARIANT] never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
    assert_not_contains "[$VARIANT] never unlocked (recovery passphrase)" "$LOG" \
        "$(sentinel_of unseal_pass_unlocked)"
    assert_not_contains "[$VARIANT] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
    assert_not_contains "[$VARIANT] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
    # IN-08: honest in both directions (missing pid file is not a clean exit)
    if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "[$VARIANT] guest exited (hook poweroff -f, not timeout-kill — no hang)" ""
    else
        _assert_result not-ok "[$VARIANT] guest exited (hook poweroff -f, not timeout-kill — no hang)" \
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
