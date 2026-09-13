#!/usr/bin/env bash
# tests/e2e/s12-wrong-passphrase.sh — §10 row "SB disabled -> way out:
# passphrase", i.e. the §10 "Passphrase forgotten + TPM refuses" negative and
# its positive control (the §6.1 recovery fallback).
#
# Boot A (negative, the scenario of record): SB-off vars -> PCR 7 drift ->
# token unseal REFUSED (attempted first, no key file) -> the harness
# /init console passphrase fallback (armed via the `debian-fde-console-fallback`
# cmdline word — see tests/lib/uki-build.sh) reads up to 3 lines from
# /dev/console and feeds each to a PLAIN `cryptsetup open --key-file` attach
# (NO tpm2-device= — passphrase attempts never touch the token path). Three
# wrong passphrases -> the cryptsetup_nokey sentinel x3 -> attempts
# exhausted -> PROMPT-FAILED -> poweroff. No emergency shell.
#
# Boot B (positive control): same fixtures, wrong, wrong, CORRECT (slot-0)
# passphrase -> the plain attach activates the volume -> UNSEALED via the
# passphrase slot. Proves the loop's rejections are real passphrase
# verification and closes the §6.1 recovery way out end-to-end.
#
# PRODUCTION NOTE: production uses systemd-tty-ask-password-agent inside the
# dracut initramfs (dracut ships it); this console loop is a harness-only
# equivalent because the busybox harness initrd has no ask-password agent
# socket and no controlling TTY (ask_password_auto returns ENOENT — see
# tests/e2e/README.md).
#
# Reuses s00 artifacts when DEBIAN_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots them itself (3 boots).

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

RUN="$TESTS/e2e/.runs/s12-lite-$(date +%s)"
mkdir -p "$RUN"

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

# wait_attempt <n> <timeout-s> <dir> — wait until the guest announced the nth
# passphrase attempt. Counts occurrences of "awaiting console line" instead of
# grepping the digit: kernel printk can interleave into the init's echo line
# (observed live: "attempt 2//3"), which breaks digit matching.
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

STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -d "$STATE/keys" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 3: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s12: swtpm failed"; exit 1; }
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
        echo "s12: enroll boot attempt $_attempt failed (qemu_wait rc=$ENROLL_WAIT_RC)"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s12: enroll boot did not reach UNSEALED — state unusable"
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

UKI_MIB=$(( ($(stat -c%s "$STATE/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))

# --- console-fallback UKI (signed UKI variant: extra cmdline word) -------------
echo "# building console-fallback UKI (cmdline + debian-fde-console-fallback)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" "debian-fde-console-fallback" || exit 1
assert_file_exists "console-fallback UKI built" "$RUN/harness.efi"
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1
# negative fixture: SB off -> the token refuses on PCR 7 drift; the passphrase
# slot (keyslot 0) is PCR-independent and remains the way out (§10)
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"

# === BOOT A: 3 wrong passphrases -> exhausted -> poweroff ======================
A="$RUN/boot-a"
mkdir -p "$A"
cp "$RUN/harness.efi" "$A/harness.efi"
cp "$RUN/pcrsig.img" "$A/pcrsig.img"
cp "$RUN/esp.img" "$A/esp.img"
cp "$STATE/disk.img" "$A/disk.img"

swtpm_start "$STATE/tpm" || { echo "s12: swtpm start (boot A) failed"; exit 1; }
echo "# boot A: SB-off + console fallback, feeding 3 WRONG passphrases"
qemu_run "$A" "$A/esp.img" "$A/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$A/pcrsig.img"
for n in 1 2 3; do
    if wait_attempt "$n" 300 "$A"; then
        _assert_result ok "boot A: guest awaiting passphrase $n/3" ""
    else
        _assert_result not-ok "boot A: guest awaiting passphrase $n/3" "no attempt $n marker in console"
        break
    fi
    feed_line "$A/serial.sock" "debian-fde-wrong-passphrase-$n"
done
qemu_wait "$A" "$QEMU_TIMEOUT"
LOG_A=$(cat "$A/console.log" 2>/dev/null || true)

# ordering proof: the token refusal line strictly precedes the first
# passphrase attempt (the loop must only arm AFTER the token path failed)
_ref_line=$(grep -nm1 -F "$(sentinel_of tpm2_refused)" "$A/console.log" 2>/dev/null | cut -d: -f1)
_att1_line=$(grep -nm1 -F 'passphrase attempt 1/3' "$A/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_att1_line:-}" ]] && (( _ref_line < _att1_line )); then
    _assert_result ok "boot A: token refusal FIRST (line $_ref_line < first attempt line $_att1_line)" ""
else
    _assert_result not-ok "boot A: token refusal FIRST" "ref=$_ref_line attempt1=$_att1_line"
fi

assert_contains "boot A: token attempted first (discovered)" "$LOG_A" "$(sentinel_of token_discovered)"
assert_contains "boot A: token refused before any passphrase attempt" "$LOG_A" \
    "$(sentinel_of tpm2_refused)"
assert_contains "boot A: fallback armed only after refusal" "$LOG_A" \
    "debian-fde-harness: token refused (rc="
for n in 1 2 3; do
    assert_contains "boot A: wrong passphrase $n rejected by cryptsetup" "$LOG_A" \
        "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc="
done
# kernel printk can interleave into the init's own echo lines (observed live:
# a watchdog message split "attempts exhausted" mid-print), so the terminal
# condition is asserted by COUNT of genuine rejections, not one fragile line
if [[ "$(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG_A" || true)" == "3" ]]; then
    _assert_result ok "boot A: exactly 3 cryptsetup rejections (3-strikes, no 4th attempt)" ""
else
    _assert_result not-ok "boot A: exactly 3 cryptsetup rejections (3-strikes, no 4th attempt)" \
        "rejection lines: $(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG_A" || true)"
fi
assert_contains "boot A: cryptsetup evidence (sentinel cryptsetup_nokey)" "$LOG_A" \
    "$(sentinel_of cryptsetup_nokey)"
assert_contains "boot A: PROMPT-FAILED" "$LOG_A" "debian-fde: PROMPT-FAILED"
assert_not_contains "boot A: never UNSEALED" "$LOG_A" "debian-fde: UNSEALED"
assert_not_contains "boot A: no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
assert_contains "boot A: clean poweroff sentinel" "$LOG_A" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$A/qemu.pid" ]] && ! kill -0 "$(cat "$A/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "boot A: guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "boot A: guest exited (poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# === BOOT B: wrong, wrong, CORRECT -> passphrase slot unlocks ==================
swtpm_stop "$STATE/tpm"   # free the state dir; boot B needs the same SRK
swtpm_start "$STATE/tpm" || { echo "s12: swtpm start (boot B) failed"; exit 1; }
B="$RUN/boot-b"
mkdir -p "$B"
cp "$RUN/harness.efi" "$B/harness.efi"
cp "$RUN/pcrsig.img" "$B/pcrsig.img"
cp "$RUN/esp.img" "$B/esp.img"
cp "$STATE/disk.img" "$B/disk.img"   # fresh copy: header untouched by boot A

echo "# boot B: same fixtures, 2 wrong + 1 CORRECT passphrase (recovery positive)"
qemu_run "$B" "$B/esp.img" "$B/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$B/pcrsig.img"
for n in 1 2; do
    if wait_attempt "$n" 300 "$B"; then
        _assert_result ok "boot B: guest awaiting passphrase $n/3" ""
    else
        _assert_result not-ok "boot B: guest awaiting passphrase $n/3" "no attempt $n marker in console"
        break
    fi
    feed_line "$B/serial.sock" "debian-fde-wrong-passphrase-$n"
done
if wait_attempt 3 300 "$B"; then
    _assert_result ok "boot B: guest awaiting passphrase 3/3" ""
    feed_line "$B/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
else
    _assert_result not-ok "boot B: guest awaiting passphrase 3/3" "no attempt 3 marker in console"
fi
qemu_wait "$B" "$QEMU_TIMEOUT"
LOG_B=$(cat "$B/console.log" 2>/dev/null || true)

_ref_line=$(grep -nm1 -F "$(sentinel_of tpm2_refused)" "$B/console.log" 2>/dev/null | cut -d: -f1)
_att1_line=$(grep -nm1 -F 'passphrase attempt 1/3' "$B/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_att1_line:-}" ]] && (( _ref_line < _att1_line )); then
    _assert_result ok "boot B: token refusal FIRST (line $_ref_line < first attempt line $_att1_line)" ""
else
    _assert_result not-ok "boot B: token refusal FIRST" "ref=$_ref_line attempt1=$_att1_line"
fi

assert_contains "boot B: token refused first (same tamper context)" "$LOG_B" \
    "$(sentinel_of tpm2_refused)"
for n in 1 2; do
    assert_contains "boot B: wrong passphrase $n rejected" "$LOG_B" \
        "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc="
done
assert_contains "boot B: correct slot-0 passphrase UNLOCKED (recovery way out)" "$LOG_B" \
    "debian-fde-harness: passphrase unlock ok (attempt 3)"
assert_contains "boot B: harness UNSEALED sentinel" "$LOG_B" "debian-fde: UNSEALED"
assert_not_contains "boot B: no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
assert_contains "boot B: clean poweroff sentinel" "$LOG_B" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "boot B: guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "boot B: guest exited (poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# keep run dirs small
rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s12-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s12-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
