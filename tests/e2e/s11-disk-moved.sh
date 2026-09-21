#!/usr/bin/env bash
# tests/e2e/s11-disk-moved.sh — §10 row "Disk moved to another machine":
# the volume key is sealed to THIS TPM's SRK (systemd-owned primary, derived
# from the TPM's storage seed). Booting the SAME disk.img + ESP + enrolled
# vars against a FOREIGN TPM (a second, fresh swtpm state = different seed =
# different SRK) must refuse to unseal: fail closed, never unlock, clean
# poweroff, no hang.
#
# Boot 1: s00-style enrollment against swtpm A (the disk's token is sealed
#         to A's SRK).
# Boot 2: fresh swtpm B (never seen by the sealing ceremony) + the SAME
#         disk/ESP/vars -> the token lookup runs but unsealing against the
#         foreign SRK is refused (tries=1 lockout, s01 precedent).

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

# _snap SRC DST — copy the console log (snapshots live in SNAPDIR under
# ${TMPDIR:-/tmp} so sibling .runs housekeeping cannot take them down; see
# s04-unsigned-uki.sh header).
_snap() { [ -f "$1" ] && cp "$1" "$2" || true; }

# _snap_while_running QEMU-PID CONSOLE SNAP — keep SNAP fresh (5 s cadence)
# while qemu runs; run in background, `wait` it after qemu_wait.
_snap_while_running() {
    while kill -0 "$1" 2>/dev/null; do
        [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
        sleep 5
    done
    [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
    return 0
}

RUN="$TESTS/e2e/.runs/s11-disk-moved-$(date +%s)"
# console snapshots OUTSIDE .runs — survive sibling .runs housekeeping
SNAPDIR="${TMPDIR:-/tmp}/secpc-e2e-s11-$(date +%s)"
mkdir -p "$RUN" "$SNAPDIR"
# prefix housekeeping — never the invocation's chained state dirs
# (CR-02/MD-03: DEBIAN_FDE_PROTECT_DIRS, exported by run-e2e.sh)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's11-disk-moved-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
CONSOLE="$RUN/console.log"
ENROLL="$RUN/enroll-boot"   # boot 1 (enrollment against swtpm A) artifacts
mkdir -p "$ENROLL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$ENROLL" 2>/dev/null || true; }

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    swtpm_start "$1"
}

# --- boot 1: enroll against swtpm A (s00 pattern) --------------------------------
_swtpm_ensure "$ENROLL/tpm" || { echo "s11: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s11: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3).
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 1/2: enrollment against TPM A (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$ENROLL" "$ENROLL/esp.img" "$ENROLL/disk.img" "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$ENROLL/qemu.pid")" "$ENROLL/console.log" "$SNAPDIR/console-enroll.snap" &
    _snap_poller1=$!
    qemu_wait "$ENROLL" "$QEMU_TIMEOUT"
    wait "$_snap_poller1"
    if grep -q "debian-fde: UNSEALED" "$SNAPDIR/console-enroll.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# enroll attempt $_att did not reach UNSEALED (external kill/prune race or regression) — retrying"
done
[ "$BOOT_OK" -eq 1 ] || { echo "s11: enroll boot did not reach UNSEALED in 3 attempts — state unusable"; tail -5 "$SNAPDIR/console-enroll.snap" 2>/dev/null; exit 1; }
echo "# enrollment boot reached UNSEALED — token sealed to TPM A's SRK"
# G-T13/G-E9 for boot 1 (reaches the UKI stub): pair the helper with the
# enrolled UKI's signed prediction + this boot's console.
cp "$ENROLL/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
_CONSOLE_SAVE="$CONSOLE"
CONSOLE="$ENROLL/console.log"
assert_pcr11_prediction "S-11 [enroll]"
CONSOLE="$_CONSOLE_SAVE"

# --- boot 2: the same disk against a FOREIGN TPM ---------------------------------
_ensure_run
# fresh swtpm state = fresh storage seed = different SRK (and different
# endorsement hierarchy); the firmware still boots (UKI signature is
# TPM-independent) but the sealed volume key is unobtainable.
cp "$ENROLL/disk.img" "$RUN/disk.img"
BOOT_OK=0
for _att in 1 2 3; do
    _swtpm_ensure "$RUN/tpm-foreign" || { echo "s11: foreign swtpm failed"; exit 1; }
    echo "# boot 2/2: same disk against foreign TPM B (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$ENROLL/esp.img" "$RUN/disk.img" "$ENROLL/vars-enrolled.fd" "$RUN/tpm-foreign" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$RUN/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-foreign.snap" &
    _snap_poller2=$!
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    wait "$_snap_poller2"
    if grep -q "debian-fde: POWEROFF" "$SNAPDIR/console-foreign.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# foreign-TPM boot attempt $_att: no completed boot (external kill/prune race?) — retrying"
done
LOG=$(cat "$SNAPDIR/console-foreign.snap" 2>/dev/null || true)
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill)" \
        "no decisive sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-foreign.snap" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "token JSON requested (firmware booted, token path reached)" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "TPM2 unseal refused (foreign SRK)" "$LOG" "$(sentinel_of tpm2_refused)"
assert_contains "deterministic lockout (retry cap)" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "harness PROMPT-FAILED sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no PCR signature policy consumption" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_not_contains "interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# G-T13/G-E9 for boot 2 (foreign TPM B): a virgin TPM measures the SAME
# section chain + phase word from zero, so the PRE-UNLOCK PCR 11 reading —
# and thus the prediction — is unchanged even though the SRK (and the seal)
# is foreign. $RUN/uki-pcrsig.json is already the booted UKI's prediction.
assert_pcr11_prediction "S-11 [foreign]"

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s11-disk-moved: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s11-disk-moved: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
