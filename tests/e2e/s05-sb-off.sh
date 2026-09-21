#!/usr/bin/env bash
# tests/e2e/s05-sb-off.sh — §10 row "SB disabled / firmware keys changed":
#   Boots? ✅ (SB off -> firmware boots the unsigned-for-it UKI)
#   Auto-unlock? ❌ — PCR 7 carries the firmware-measured SB state; with the
#   platform in setup mode / custom keys gone, PCR 7 drifts away from the
#   value the token was enrolled under -> the static PolicyPCR(7) term of the
#   sealed object no longer matches -> the real 257.13 systemd-cryptsetup
#   TPM2 unseal REFUSES -> tries=1 retry cap -> deterministic lockout.
#
# REQUIRED: PCRs printed (7 non-zero: SB-off state is measured too), PCR 7
#           differs from the enrolled boot's PCR 7, PCR 11 UNCHANGED (the
#           refusal is purely the PCR 7 drift), token_discovered,
#           tpm2_refused, retry cap; UNSEALED / unlocked / emergency shell
#           / interactive prompt NEVER; clean poweroff.
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

RUN="$TESTS/e2e/.runs/s05-lite-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"

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
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s05: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # the sandbox is shared with sibling agents whose housekeeping has been
    # observed to SIGKILL mid-flight QEMUs — retry the bootstrap boot once
    # (the disk restarts blank and /init re-enrolls; the TPM must be RESET so
    # PCR 11 carries only one phase extension, else the .pcrsig never matches)
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        ENROLL_WAIT_RC=$?
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s05: enroll boot attempt $_attempt failed (qemu_wait rc=$ENROLL_WAIT_RC)"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s05: enroll boot did not reach UNSEALED — state unusable"
        echo "--- qemu_wait rc: $ENROLL_WAIT_RC"
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
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"

# swtpm: the SRK must be the one the token is sealed to -> reuse the state dir
swtpm_start "$STATE/tpm" || { echo "s05: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
cp "$STATE/disk.img" "$RUN/disk.img"
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
# tamper = stock vars copy (no PK, SecureBoot off): SB disabled, keys gone
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
assert_not_contains "unenrolled vars: no PK" "$(keys_vars_get "$RUN/vars-unenrolled.fd" PK)" "blob"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot with SB OFF ----------------------------------------------------------
echo "# booting: SB-off vars + enrolled disk (TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"
qemu_wait "$RUN" "$QEMU_TIMEOUT"
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- PCR forensics -------------------------------------------------------------
pcr_of() { grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR7=$(pcr_of "$CONSOLE" 7)
PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
PCR11=$(pcr_of "$CONSOLE" 11)
PCR11_ENROLLED=$(pcr_of "$STATE/console.log" 11)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "TPM char device appeared" "$LOG" "/dev/tpmrm0 present"
assert_contains "firmware booted the UKI despite SB off (init + PCRs)" "$LOG" "debian-fde-pcr sha256:7=$PCR7"
ZERO=$(printf '0%.0s' {1..64})
if [[ -n "$PCR7" && "$PCR7" != "$ZERO" ]]; then
    _assert_result ok "PCR 7 non-zero (SB-off state measured by firmware)" ""
else
    _assert_result not-ok "PCR 7 non-zero (SB-off state measured by firmware)" "PCR7=${PCR7:-absent}"
fi
if [[ -n "$PCR7" && "$PCR7" != "$PCR7_ENROLLED" ]]; then
    _assert_result ok "PCR 7 drifted vs enrolled boot (7=$PCR7 vs enrolled 7=$PCR7_ENROLLED)" ""
else
    _assert_result not-ok "PCR 7 drifted vs enrolled boot" \
        "PCR7=$PCR7 enrolled=$PCR7_ENROLLED"
fi
assert_eq "PCR 11 unchanged (refusal is purely PCR 7 drift)" "$PCR11_ENROLLED" "$PCR11"

# G-T13/G-E9 (boot reaches the UKI stub): the SB-off tamper drifts PCR 7 only
# — the PRE-UNLOCK PCR 11 reading must still equal the signed prediction.
assert_pcr11_prediction "S-05"

assert_contains "token discovered" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "TPM2 unseal refused (PCR 7 drift)" "$LOG" "$(sentinel_of tpm2_refused)"
assert_contains "retry cap reached (deterministic lockout)" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "harness fail-closed sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_not_contains "interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never unlocked (harness sentinel)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
# IN-08: an absent pid file (qemu_run failed outright) must not read as a
# clean "guest exited" — the check is honest in both directions
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
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s05-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s05-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
