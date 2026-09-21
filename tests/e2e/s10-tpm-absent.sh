#!/usr/bin/env bash
# tests/e2e/s10-tpm-absent.sh — §10 row "TPM cleared / absent / DA-locked":
# the ABSENT leg. The enrolled disk boots on a machine WITHOUT any TPM
# (qemu: the -chardev/-tpmdev/-device tpm-tis pair is omitted entirely;
# no swtpm daemon is started). The real 257.13 systemd-cryptsetup token
# path must fail closed: the sentinel-table pins tpm_absent_nodevice /
# tpm_absent_notfound / tpm_absent_fallback, NO unlock, no hang (clean
# poweroff inside the hard timeout), no emergency shell — matches the s01
# precedent (tries=1, deterministic lockout, the interactive prompt cannot
# run in this initrd).
#
# Boot 1: s00-style enrollment (the token must exist for the guest to take
#         the systemd-tpm2 token path that reports the TPM-absent sentinels).
# Boot 2: same disk/ESP/vars, NO TPM device pair -> refuse + poweroff.

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

# TPM-absent sentinels: carried (values identical, name-for-name) in the
# DEFAULT sentinel table tests/sentinels-260.2.txt as
# tpm_absent_nodevice / tpm_absent_notfound / tpm_absent_fallback (all three
# observed on this exact path in the 257.13 console, run s10-tpm-absent-*,
# 2026-09-14; byte-verified per the table's provenance comments). The OLD
# `tpm_absent` pin ("Could not find TPM2 device", libcryptsetup-token
# plugin) belongs to a DIFFERENT code path and is never printed when the
# TPM scan finds nothing — the table entry was replaced by these three.
#
# NB: no assert_pcr11_prediction here (G-E9): this machine has NO TPM at all
# — no PCR 11 state exists to predict, the post-phase reading is empty, and
# G-T13 is defined only where a measured PCR 11 exists.

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

RUN="$TESTS/e2e/.runs/s10-tpm-absent-$(date +%s)"
# console snapshots OUTSIDE .runs — survive sibling .runs housekeeping
SNAPDIR="${TMPDIR:-/tmp}/secpc-e2e-s10-$(date +%s)"
mkdir -p "$RUN" "$SNAPDIR"
# prefix housekeeping — never the invocation's chained state dirs
# (CR-02/MD-03: DEBIAN_FDE_PROTECT_DIRS, exported by run-e2e.sh)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's10-tpm-absent-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
CONSOLE="$RUN/console.log"
ENROLL="$RUN/enroll-boot"   # boot 1 (enrollment) artifacts
mkdir -p "$ENROLL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$ENROLL" 2>/dev/null || true; }

# _qemu_run_no_tpm <run> <esp> <disk> <vars> [pcrsig] — qemu.sh's invocation
# MINUS the TPM device pair (chardev chrtpm / tpmdev tpm0 / device tpm-tis):
# the scenario-under-test is precisely a TPM-less machine. Deliberate local
# replication (qemu.sh is owned by the harness; its contract — drive map,
# serial socket, console.log, qemu.pid — is preserved so qemu_wait/qemu_kill
# keep working). Reuses the lib's internal OVMF-code helper.
_qemu_run_no_tpm() {
    local run="$1" esp="$2" disk="$3" vars="$4" pcrsig="${5:-}"
    local sock="$run/serial.sock"
    rm -f "$sock" "$run/console.log" "$run/qemu.pid"
    local -a args=(
        -machine q35 -m 2048
        -display none -nodefaults
        -drive "if=pflash,format=raw,readonly=on,file=$(_qemu_ovmf_code)"
        -drive "if=pflash,format=raw,file=$vars"
        -drive "file=$esp,format=raw,if=virtio"
        -drive "file=$disk,format=raw,if=virtio"
        -chardev "socket,id=ser0,path=$sock,server=on,wait=off,logfile=$run/console.log"
        -serial chardev:ser0
    )
    if [ -n "$pcrsig" ]; then
        args+=(-drive "file=$pcrsig,format=raw,if=virtio")
    fi
    qemu-system-x86_64 "${args[@]}" >"$run/qemu.stdout" 2>"$run/qemu.stderr" &
    echo $! >"$run/qemu.pid"
}

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    swtpm_start "$1"
}

# --- boot 1: enroll (s00 pattern) ------------------------------------------------
_swtpm_ensure "$ENROLL/tpm" || { echo "s10: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s10: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3).
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 1/2: enrollment (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
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
[ "$BOOT_OK" -eq 1 ] || { echo "s10: enroll boot did not reach UNSEALED in 3 attempts — state unusable"; tail -5 "$SNAPDIR/console-enroll.snap" 2>/dev/null; exit 1; }
echo "# enrollment boot reached UNSEALED — token present on disk"

# --- boot 2: the scenario — same disk, NO TPM device at all ----------------------
_ensure_run
cp "$ENROLL/disk.img" "$RUN/disk.img"
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 2/2: TPM-less machine (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    _qemu_run_no_tpm "$RUN" "$ENROLL/esp.img" "$RUN/disk.img" "$ENROLL/vars-enrolled.fd" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$RUN/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-absent.snap" &
    _snap_poller2=$!
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    wait "$_snap_poller2"
    if grep -q "debian-fde: POWEROFF" "$SNAPDIR/console-absent.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# TPM-less boot attempt $_att: no completed boot (external kill/prune race?) — retrying"
done
LOG=$(cat "$SNAPDIR/console-absent.snap" 2>/dev/null || true)
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill)" \
        "no decisive sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-absent.snap" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "harness saw no TPM character device" "$LOG" "/dev/tpmrm0 ABSENT after timeout"
assert_contains "token path reached (plugin got the token JSON request)" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "TPM-absent sentinel (plugin: no tpmrm node)" "$LOG" "$(sentinel_of tpm_absent_nodevice)"
assert_contains "TPM-absent sentinel (plugin: no TPM2 device)" "$LOG" "$(sentinel_of tpm_absent_notfound)"
assert_contains "deterministic fallback decision (never hang)" "$LOG" "$(sentinel_of tpm_absent_fallback)"
assert_contains "deterministic lockout (retry cap)" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "harness PROMPT-FAILED sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_not_contains "no UNSEALED on the enrollment boot's behalf either" "$LOG" "$(sentinel_of pcr_sig_added)"

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s10-tpm-absent: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s10-tpm-absent: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
