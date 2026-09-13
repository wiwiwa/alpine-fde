#!/usr/bin/env bash
# tests/e2e/s01-happy-lite.sh — LITE tamper variant (Wave 1 agent C; Wave 2
# resolved the fallback feeding — see tests/e2e/README.md).
#
# Boot the S-00-enrolled disk (token sealed under the SB-ENROLLED PCR 7 state,
# sealed to the same swtpm SRK) with UNENROLLED vars (Secure Boot OFF):
#   * firmware boots the (now unsigned-for-this-firmware) UKI — SB off;
#   * PCR 7 drifted -> the .pcrsig policy still matches (PCR 11 unchanged) and
#     PolicyAuthorize still pivots, but the static PolicyPCR(7) term of the
#     sealed object no longer matches -> the REAL 257.13 systemd-cryptsetup
#     TPM2 unseal FAILS (attempt 0, EAGAIN);
#   * the fallback passphrase prompt cannot run in this initrd (no ask-password
#     agent, no controlling TTY — serial-fed input is NOT consumed; and a key
#     file in the attach position would DISPLACE the token path entirely in
#     257.13), so the UKI runs the unlock with tries=1: after the single
#     refused token attempt systemd-cryptsetup ends in "Too many attempts to
#     activate; giving up." — deterministic lockout, no prompt involved.
#
# REQUIRED: token_discovered (token found), tpm2_refused (unseal rejected),
#           retry_cap appears, the interactive prompt NEVER appears,
#           unlocked/UNSEALED NEVER appear, clean poweroff, no emergency shell.
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
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s01-lite-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"

STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" && -f "$STATE/pcrsig.img" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 2: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s01-lite: swtpm failed"; exit 1; }
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
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s01-lite: enroll boot did not reach UNSEALED — state unusable"; exit 1; }
    STATE="$RUN_ENROLLED"
fi

# swtpm: the SRK must be the one the token is sealed to -> reuse s00's state dir
swtpm_start "$STATE/tpm" || { echo "s01-lite: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
cp "$STATE/disk.img" "$RUN/disk.img"
# negative fixture: stock vars copy (no PK, SecureBoot off)
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
assert_not_contains "unenrolled vars: no PK" "$(keys_vars_get "$RUN/vars-unenrolled.fd" PK)" "blob"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot with SB OFF ----------------------------------------------------------
echo "# booting tamper variant: SB-off vars + enrolled disk (TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"

# The unlock flow runs unattended: token refused (attempt 0) -> wrong key file
# refused (attempt 1) -> retry cap at tries=2 -> PROMPT-FAILED -> poweroff.
# No interactive feeding — wait for the guest to exit.
qemu_wait "$RUN" "$QEMU_TIMEOUT"
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- assertions ---------------------------------------------------------------
assert_contains "token discovered" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "TPM2 unseal refused (PCR 7 drift)" "$LOG" "$(sentinel_of tpm2_refused)"
assert_contains "retry cap reached" "$LOG" "$(sentinel_of retry_cap)"
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

echo "# run dir: $RUN"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s01-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s01-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
