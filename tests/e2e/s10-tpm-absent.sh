#!/usr/bin/env bash
# tests/e2e/s10-tpm-absent.sh — §10 row "TPM cleared / absent / DA-locked":
# the ABSENT leg, against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 —
# the harness DEFAULT unlock). The enrolled disk boots on a machine WITHOUT
# any TPM (qemu: the -chardev/-tpmdev/-device tpm-tis pair is omitted entirely;
# no swtpm daemon is started). The hook must fail closed: its PCR 11 extend
# fails (sentinel unseal_tpm_absent: "TPM absent or refused the PCR 11
# extend — recovery passphrase path"), the token path is skipped entirely,
# and the hook's BOUNDED keyslot-0 recovery loop reads from /dev/console —
# three fed WRONG answers are rejected by real cryptsetup passphrase
# verification, the loop EXHAUSTS at exactly 3 (no 4th prompt), and the
# 3-strike ends in fail-closed `poweroff -f` (§8.2 — NO shell is ever
# offered). No unlock, no hang (clean poweroff inside the hard timeout), no
# emergency shell. (The recovery way OUT itself — the CORRECT passphrase on a
# TPM-less machine — is the s12 positive control's shape; this scenario pins
# the fail-closed negative.)
#
# Boot 1: baseline (token-less disk) -> the hook's recovery loop, fed the
#         slot-0 passphrase -> UNSEALED; then the REAL production CLI
#         enrolls the finalized {7,11} Mechanism B token host-side against
#         the fixture swtpm (the token must exist for the scenario boot to
#         be the §8.2 enrolled-disk boot).
# Boot 2: same disk/ESP/vars, NO TPM device pair -> tpm_absent -> bounded
#         loop -> 3-strike fail-closed.
#
# NB: no assert_pcr11_prediction here (G-E9): this machine has NO TPM at all
# — no PCR 11 state exists to predict, the post-phase reading is empty, and
# G-T13 is defined only where a measured PCR 11 exists.

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
# (CR-02/MD-03: ALPINE_FDE_PROTECT_DIRS, exported by run-e2e.sh)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's10-tpm-absent-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
CONSOLE="$RUN/console.log"
ENROLL="$RUN/enroll-boot"   # boot 1 (baseline + enrollment) artifacts
mkdir -p "$ENROLL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$ENROLL" 2>/dev/null || true; }

# Boot 2 (the TPM-less machine) rides the SHARED qemu_run path: with
# ALPINE_FDE_QEMU_NO_TPM=1 qemu_argv omits the chardev/tpmdev/tpm-tis trio —
# the guest has NO TPM character device, everything else (OVMF pins,
# accelerator choice, console bridge fronting <run>/serial.sock, console.log
# tee, qemu.pid) is exactly the production wiring. The historical local
# _qemu_run_no_tpm replication (direct chardev + direct feed) carried the
# legacy UART-backpressure feed-loss risk the bridge exists to fix.
_no_tpm_qemu_run() {
    ALPINE_FDE_QEMU_NO_TPM=1 qemu_run "$@"
}

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    swtpm_start "$1"
}

# --- boot 1: baseline + enroll (s00/s05 pattern) ----------------------------------
_swtpm_ensure "$ENROLL/tpm" || { echo "s10: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s10: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3). The token-less disk puts
# the hook's BOUNDED recovery loop in control: the feed is
# prompt-synchronized (the hook has NO read timeout).
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 1/2: baseline (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$ENROLL" "$ENROLL/esp.img" "$ENROLL/disk.img" "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$ENROLL"; then
        feed_line "$ENROLL/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    _snap_while_running "$(cat "$ENROLL/qemu.pid")" "$ENROLL/console.log" "$SNAPDIR/console-enroll.snap" &
    _snap_poller1=$!
    qemu_wait "$ENROLL" "$QEMU_TIMEOUT"
    wait "$_snap_poller1"
    if grep -q "alpine-fde: UNSEALED" "$SNAPDIR/console-enroll.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# baseline attempt $_att did not reach UNSEALED (external kill/prune race or regression) — retrying"
    ((_att < 3)) && { swtpm_reset "$ENROLL/tpm" && swtpm_start "$ENROLL/tpm" || exit 1; }
    rm -f "$ENROLL/console.log"
done
[ "$BOOT_OK" -eq 1 ] || { echo "s10: baseline boot did not reach UNSEALED in 3 attempts — state unusable"; tail -5 "$SNAPDIR/console-enroll.snap" 2>/dev/null; exit 1; }
LOG_B1=$(cat "$SNAPDIR/console-enroll.snap" 2>/dev/null || true)
assert_contains "boot 1: hook recovery loop opened (no token on the fresh volume)" "$LOG_B1" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "boot 1: fed slot-0 passphrase unsealed via the recovery path" "$LOG_B1" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "boot 1: volume UNSEALED" "$LOG_B1" "$(sentinel_of harness_unsealed)"

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted
# console's PCR 7, d11 = the build's enter-initrd prediction; the combined
# {7,11} entry is what the hook extracts for the finalized token.
D11=$(cat "$ENROLL/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11" ]] || { echo "s10: no enter-initrd d11 prediction from the build"; exit 1; }
swtpm_ensure "$ENROLL/tpm" || { echo "s10: swtpm restart (enroll) failed"; exit 1; }
PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$ENROLL/console.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_ENROLLED" ]] || { echo "s10: no PCR 7 in the baseline console"; exit 1; }
# digest-anchored enroll (Option A): no reseeding and no live-read assertion —
# the CLI compares the entry's recorded d7/d11 against the baseline (pure
# data, no live TPM read); the fixture only needs to be SERVING for the seal.
uki_pcrsig_append_combined "$ENROLL/uki-pcrsig.json" "$ENROLL/uki-pcrsig-combined.json" \
    "$PCR7_ENROLLED" "$D11" "$RUN/keys" || exit 1
uki_pcrsig_disk "$ENROLL/pcrsig.img" "$ENROLL/uki-pcrsig-combined.json" || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
# enroll precondition (CLI, enrl_preconditions #2): a FINALIZED baseline at
# $ALPINE_FDE_ROOT/etc/alpine-fde/baseline.json. Stamp the booted d7 into a
# scenario-local cli-state root — the same seam s06/s09/s12/s13 use; without
# it enroll-tpm dies "no baseline at /etc/alpine-fde/baseline.json".
uki_baseline_stamp "$ENROLL/cli-state" "$PCR7_ENROLLED"
uki_host_enroll_finalized "$EFIVARS" "$ENROLL/uki-pcrsig-combined.json" \
    "$ENROLL/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$ENROLL/cli-state" || {
    echo "s10: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$ENROLL/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
echo "# enrollment boot reached UNSEALED + token enrolled — disk carries the finalized {7,11} token"

# --- boot 2: the scenario — same disk, NO TPM device at all ----------------------
# The hook extends nothing (no TPM), skips the token path entirely, and opens
# its bounded keyslot-0 recovery loop on the console. The loop has NO read
# timeout: three WRONG answers are fed prompt-synchronized so the boot ends in
# the 3-strike fail-closed poweroff, never a timeout-kill.
_ensure_run
cp "$ENROLL/disk.img" "$RUN/disk.img"
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 2/2: TPM-less machine (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    _no_tpm_qemu_run "$RUN" "$ENROLL/esp.img" "$RUN/disk.img" "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$RUN/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-absent.snap" &
    _snap_poller2=$!
    _fed=0
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 300 "$RUN"; then
            feed_line "$RUN/serial.sock" "alpine-fde-tpm-absent-wrong-passphrase-$n"
            _fed=$n
        else
            break
        fi
    done
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    wait "$_snap_poller2"
    # DECISIVE SENTINEL SCOPE (2026-09-23): a 3-strike refusal boot powers off
    # from INSIDE the hook (_fdh_poweroff -> `poweroff -f` in the initrd), so
    # the harness's own "alpine-fde: POWEROFF" line (printed by /init only on
    # the post-UNSEALED path) can NEVER appear — gating on it made every green
    # TPM-absent boot burn all 3 attempts and report not-ok. The terminal
    # evidence is the hook's own 3-strike give-up + fail-closed poweroff pair.
    if grep -qF "$(sentinel_of unseal_3strike)" "$SNAPDIR/console-absent.snap" 2>/dev/null \
        && grep -qF "$(sentinel_of unseal_poweroff)" "$SNAPDIR/console-absent.snap" 2>/dev/null \
        && [ "$_fed" -eq 3 ]; then
        BOOT_OK=1
        break
    fi
    echo "# TPM-less boot attempt $_att: no completed 3-strike (external kill/prune race?) — retrying"
done
LOG=$(cat "$SNAPDIR/console-absent.snap" 2>/dev/null || true)
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "guest exited (3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (3-strike poweroff, not timeout-kill)" \
        "no decisive sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-absent.snap" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "harness saw no TPM character device" "$LOG" "/dev/tpmrm0 ABSENT after timeout"
assert_not_contains "no TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
assert_contains "hook: PCR 11 extend refused -> recovery passphrase path (§8.2)" "$LOG" \
    "$(sentinel_of unseal_tpm_absent)"
# with the extend refused the hook skips the token path entirely: the token
# discovery / signature gate lines must NEVER appear
assert_not_contains "token path never ran (no token discovery)" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "token path never ran (no signature gate)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
assert_not_contains "token path never ran (no seal refusal)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
PROMPTS=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "exactly 3 recovery-passphrase prompts (bounded loop, no 4th)" "3" "$PROMPTS"
assert_contains "3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "fail-closed poweroff (no shell is offered)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s10-tpm-absent: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s10-tpm-absent: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
