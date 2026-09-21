#!/usr/bin/env bash
# tests/e2e/s07-loader-options.sh — §12 tamper row: "tampered loader-entry
# `options` (must fail — systemd-stub measures the effective cmdline into
# PCR 11)".
#
# Implementation note (task deviation, empirically pinned 2026-09-14): the
# task's literal "loader/entries .conf with modified options" does NOT reach
# a UKI on Debian trixie — sd-boot 257.13 boots a type1 UKI entry but DROPS
# its `options` line; the Debian sd-boot build has no \EFI\Linux UKI
# auto-entry scan; firmware Boot#### OptionalData is dropped by the stub
# (with SB on AND off); and UKI addons are not picked up by this stub build
# (verified from \EFI\BOOT\BOOTX64.addon.efi and \loader\addons). The
# loader-level cmdline injection is therefore structurally dead in this
# stack — itself a relevant fail-closed finding (documented in
# tests/e2e/README.md).
#
# The INVARIANT under test — I5: a UKI unseals iff signature-valid AND the
# trial digest over the CURRENT PCR 7 + PCR 11 values is release-key-signed
# and present in the token — is exercised via a release-key-signed UKI
# VARIANT whose .cmdline carries one extra word (the compromised-signer
# model: a backdoored cmdline inside otherwise-valid signed artifacts).
# systemd-stub measures the tampered .cmdline into PCR 11 -> the PCR 11
# trial value drifts away from every signed .pcrsig entry -> unseal
# refused -> fail closed. The guest's `debian-fde-cmdline` print proves the
# tamper actually reached the kernel (without it, a refusal could be a
# false pass from an unrelated mismatch).
# REQUIRED: init ran; debian-fde-cmdline contains the extra word; PCR 11
#           differs from the enrolled boot; TPM2 unseal refused; UNSEALED /
#           unlocked / emergency shell NEVER; clean poweroff.
#
# Reuses s00 artifacts when DEBIAN_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots them itself (2 boots).

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
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13/G-E9)
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s07-lite-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
TAMPER_WORD="debian-fde-loader-tamper"

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

STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 2: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s07: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
        "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
    qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
    ENROLL_WAIT_RC=$?
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break_early=1 || break_early=0
    if (( break_early == 0 )); then
        echo "s07: enroll boot attempt 1 failed (qemu_wait rc=$ENROLL_WAIT_RC)"
        swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
        rm -f "$RUN_ENROLLED/console.log"
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
    fi
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s07: enroll boot did not reach UNSEALED — state unusable"
        exit 1
    }
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared s00 state into OUR run dir: sibling prunes may remove
# the state dir mid-run; from here on this scenario only touches the local
# copy (the swtpm permall carries the seed -> the copy seals to the same SRK).
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

swtpm_start "$STATE/tpm" || { echo "s07: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
cp "$STATE/disk.img" "$RUN/disk.img"
cp "$STATE/vars-enrolled.fd" "$RUN/vars-enrolled.fd"
assert_contains "enrolled vars in use: SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"

# --- the tamper: tampered-cmdline UKI + STALE .pcrsig payload -------------------
# Attack model: a compromised/redirected build ships a UKI whose .cmdline
# carries an extra word; the attacker CANNOT re-sign PCR policies (the
# release key is offline, I4), so the .pcrsig payload on the raw payload
# drive still predicts the CLEAN cmdline's PCR 11. The payload is unsigned
# on the wire, so shipping a stale one is precisely the attacker's
# primitive. Host-side: prove the tampered UKI's own prediction DIVERGES
# from the shipped (clean) one, then boot the tampered UKI with the stale
# payload: the stub measures the tampered effective cmdline into PCR 11 ->
# the trial digest matches NO signed .pcrsig entry -> fail closed.
echo "# building tampered-cmdline UKI variant (cmdline + $TAMPER_WORD, same release key)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" "$TAMPER_WORD" || exit 1
assert_file_exists "tampered-cmdline UKI built (signed with the release key)" "$RUN/harness.efi"
# the tampered UKI carries its OWN (matching) .pcrsig — the attacker would
# ship the STALE clean one instead; keep both for the divergence proof
cp "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-tampered.json"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"   # ship the STALE (clean) prediction
cp "$RUN/pcrsig.img" "$RUN/pcrsig-stale.img"
if python3 - "$RUN/uki-pcrsig.json" "$STATE/uki-pcrsig.json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
sys.exit(0 if a["sha256"][0]["pol"] != b["sha256"][0]["pol"] else 1)
PYEOF
then
    _assert_result ok "tampered prediction diverges from the shipped (clean) .pcrsig" ""
else
    _assert_result not-ok "tampered prediction diverges from the shipped (clean) .pcrsig" \
        "pol digests identical — the tamper would not drift PCR 11"
fi
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot the tampered-cmdline UKI (SB-enrolled vars) ---------------------------
echo "# booting: tampered cmdline addon + enrolled disk (TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"
qemu_wait "$RUN" "$QEMU_TIMEOUT"
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- PCR forensics -------------------------------------------------------------
pcr_of() { grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR11=$(pcr_of "$CONSOLE" 11)
PCR11_ENROLLED=$(pcr_of "$STATE/console.log" 11)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran (UKI started via the tampered boot entry)" "$LOG" \
    "debian-fde-harness: init started"
if grep -aqE 'debian-fde-cmdline2? .*rdinit=/init loglevel=7' "$CONSOLE" 2>/dev/null; then
    _assert_result ok "embedded cmdline intact in /proc/cmdline" ""
else
    _assert_result not-ok "embedded cmdline intact in /proc/cmdline" \
        "no whole debian-fde-cmdline line carries the embedded cmdline"
fi
if grep -aqE 'debian-fde-cmdline2? .*debian-fde-loader-tamper' "$CONSOLE" 2>/dev/null; then
    _assert_result ok "tamper word reached the kernel (stub measured the effective cmdline)" ""
else
    _assert_result not-ok "tamper word reached the kernel (stub measured the effective cmdline)" \
        "no whole debian-fde-cmdline line carries the tamper word"
fi
if [[ -n "$PCR11" && "$PCR11" != "$PCR11_ENROLLED" ]]; then
    _assert_result ok "PCR 11 drifted (stub measured the effective cmdline)" ""
else
    _assert_result not-ok "PCR 11 drifted (stub measured the effective cmdline)" \
        "PCR11=$PCR11 enrolled=$PCR11_ENROLLED"
fi
if grep -qF "$(sentinel_of pcr_sig_missing)" "$CONSOLE" 2>/dev/null \
    || grep -qF "$(sentinel_of tpm2_refused)" "$CONSOLE" 2>/dev/null; then
    _assert_result ok "TPM2 unseal refused (drifted PCR 11 matches NO signed .pcrsig entry)" ""
else
    _assert_result not-ok "TPM2 unseal refused (drifted PCR 11 matches NO signed .pcrsig entry)" \
        "neither signature-lookup failure nor tpm2_refused in console"
fi
assert_contains "harness fail-closed sentinel" "$LOG" "debian-fde: PROMPT-FAILED"

# G-T13/G-E9 (boot reaches the UKI stub): the stub measured the TAMPERED
# effective cmdline into PCR 11 — the drifted pre-unlock reading must equal
# the tampered UKI's OWN signed prediction ($RUN/uki-pcrsig.json, rebuilt
# above with the extra cmdline word), proving the prediction formula covers
# the cmdline measurement the tamper relied on.
assert_pcr11_prediction "S-07"
assert_not_contains "interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never unlocked (harness sentinel)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# keep run dirs small (state dir is not ours to prune)
rm -rf "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
echo "RUNDIR $RUN"
kill "$REFRESHER" 2>/dev/null
if (( TESTS_FAIL == 0 )); then
    echo "# s07-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s07-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
