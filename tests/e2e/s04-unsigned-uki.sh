#!/usr/bin/env bash
# tests/e2e/s04-unsigned-uki.sh — §10 row "Kernel updated, unsigned UKI":
# the FIRMWARE gate (ADR-5/§5) must refuse an unsigned UKI under enrolled
# Secure Boot vars — no kernel, no initrd, no guest sentinels at all.
#
# Boot 1 (positive control, same session, same vars file): the SIGNED
#   harness UKI boots; the fixture disk is TOKEN-LESS, so the unlock runs
#   through the SHIPPED mkinitfs unseal hook's (§8.2; ADR-13) bounded
#   keyslot-0 recovery-passphrase prompt (fed over serial,
#   prompt-synchronized) and reaches `debian-fde: UNSEALED` — proves
#   firmware, ESP path, harness AND hook are healthy in THIS session, so
#   boot 2's refusal is attributable to the missing signature alone.
# Boot 2 (the scenario): the same ESP slot carries the UNSIGNED build
#   ($run/uki-unsigned.efi — the `uki_build` no-sign path: no .pcrsig and no
#   sbsign signature). Enrolled vars still have SecureBoot ON → the firmware
#   must refuse: assert the firmware RAN (BdsDxe boot-manager lines) but the
#   guest NEVER started — no guest banner ("init started"), no PCR lines, no
#   harness sentinels within the boot budget. The firmware does not power
#   off on refusal — the harness hard-timeout kill is the expected end.
#
# Host-side static controls: `sbverify --list` confirms the control UKI
# carries a signature and the unsigned build carries none.
#
# EMPIRICAL (verified 2026-09-14): when QEMU exits, the swtpm it is
# passthrough-connected to TERMINATES and unlinks its sockets (reproduced
# with a plain OVMF boot). A swtpm_start is therefore required before EVERY
# boot; the fixture restarts cleanly on the same state dir (stale pid file
# handled). Before each boot the ctrl socket is sanity-checked so a dead
# swtpm fails the setup LOUDLY instead of vacuously passing negatives.

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
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH

# _snap SRC DST — copy the console log right after the boot. Resilience
# against a concurrent sibling scenario's broad .runs housekeeping deleting
# run dirs mid-boot (observed 2026-09-14): snapshots go to SNAPDIR under
# ${TMPDIR:-/tmp}, outside the pruned tree.
_snap() { [ -f "$1" ] && cp "$1" "$2" || true; }

# _snap_while_running QEMU-PID CONSOLE SNAP — keep SNAP fresh (5 s cadence)
# while qemu runs, so a mid-boot deletion of the run dir loses at most the
# last 5 s of console (all decisive sentinels print before poweroff). Run in
# background; `wait` it after qemu_wait.
_snap_while_running() {
    while kill -0 "$1" 2>/dev/null; do
        [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
        sleep 5
    done
    [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
    return 0
}

RUN="$TESTS/e2e/.runs/s04-unsigned-$(date +%s)"
# console snapshots live OUTSIDE .runs: a concurrent sibling scenario's broad
# .runs housekeeping can delete whole run dirs mid-boot (observed 2026-09-14),
# and the assertion surface must survive that
SNAPDIR="${TMPDIR:-/tmp}/secpc-e2e-s04-$(date +%s)"
mkdir -p "$RUN" "$SNAPDIR"
# housekeeping: keep the 2 newest runs of this prefix (current run included) —
# never the invocation's chained state dirs (CR-02/MD-03: DEBIAN_FDE_PROTECT_DIRS)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's04-unsigned-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
CONSOLE="$RUN/console.log"
CONTROL="$RUN/control-boot"   # boot 1 (signed positive control) artifacts
mkdir -p "$CONTROL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$CONTROL" 2>/dev/null || true; }

# --- fixtures (s00 pattern) ----------------------------------------------------
swtpm_start "$CONTROL/tpm" || { echo "s04: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$CONTROL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$CONTROL" "$RUN/keys" "$CONTROL/harness.efi" || { echo "s04: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$CONTROL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$CONTROL/esp.img" "$ESP_MIB" "$CONTROL/harness.efi" || exit 1
disk_make_luks "$CONTROL/disk.img" 128 || exit 1

# --- host-side static controls: signed vs unsigned ------------------------------
sbverify --list "$CONTROL/harness.efi" >"$RUN/sbverify-signed.txt" 2>&1
if grep -q '^signature ' "$RUN/sbverify-signed.txt"; then
    _assert_result ok "control UKI carries an sbverify signature" ""
else
    _assert_result not-ok "control UKI carries an sbverify signature" \
        "no 'signature N' in sbverify output: $(head -3 "$RUN/sbverify-signed.txt" | tr '\n' ' ')"
fi
sbverify --list "$CONTROL/uki-unsigned.efi" >"$RUN/sbverify-unsigned.txt" 2>&1
if grep -qF "$(sentinel_of sbverify_no_sig)" "$RUN/sbverify-unsigned.txt"; then
    _assert_result ok "scenario UKI is unsigned (sbverify)" ""
else
    _assert_result not-ok "scenario UKI is unsigned (sbverify)" \
        "expected the sbverify_no_sig sentinel: $(head -3 "$RUN/sbverify-unsigned.txt" | tr '\n' ' ')"
fi

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
# The probe is BOUNDED (timeout 10, the fixture-probe pattern): swtpm 0.10.2
# sometimes stops servicing its data socket after the ctrl handshake, and an
# unbounded tpm2_getcap hangs forever on it (observed live 2026-09-23) —
# failing fast lets the caller's restart path recover.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && timeout 10 tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    # swtpm_ensure, NOT raw swtpm_start: a live-but-wedged instance (probe
    # failed while the pidfile is alive) makes swtpm_start refuse with
    # "already running" and there is no recovery — swtpm_ensure is the
    # promoted restart path (bounded probe -> persist volatile state ->
    # kill + start; IN-03; observed live 2026-09-23).
    swtpm_ensure "$1"
}

# _wedge_wait <dir> <timeout-s> — qemu_wait + the swtpm data-loop WEDGE guard
# (mitigation 2026-09-23; gdb poll-dump root cause: swtpm 0.10.2 de-registers
# the data client when a ctrl-channel client EOFs and never re-adds it — the
# data connection sits with Recv-Q > 0, absent from swtpm's poll set, and the
# guest stalls forever). Wedge signature, sampled every 5 s: qemu alive +
# console.log size unchanged for >60 s + Recv-Q > 0 on <dir>/tpm/sock.
# Recovery: qemu_kill + swtpm_stop + swtpm_start (fresh startup-clear), loud
# WEDGE-RECOVERED line, return 43 (distinct from qemu_wait's 0/64/124) so the
# caller's bounded retry re-runs the boot; 44 = recovery restart failed.
_wedge_wait() {
    local dir="$1" timeout="$2" pid
    pid=$(cat "$dir/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout)) sz last_sz last_chg
    last_sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
    last_chg=$SECONDS
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            pkill -9 -f "python3 - $dir/qmp.sock" 2>/dev/null
            serial_bridge_stop "$dir"
            return 0
        fi
        _qmp_kicker_start "$dir"
        sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
        if ((sz != last_sz)); then last_sz=$sz; last_chg=$SECONDS; fi
        if ((SECONDS - last_chg > 60)); then
            if ss -xn 2>/dev/null | awk -v s="$dir/tpm/sock" '$0 ~ s && ($3 + 0) > 0 { found = 1 } END { exit !found }'; then
                echo "WEDGE-RECOVERED: swtpm data-loop stall (console idle >60 s, Recv-Q>0 on $dir/tpm/sock) — killing qemu, restarting swtpm fresh"
                qemu_kill "$dir"
                swtpm_stop "$dir" >/dev/null 2>&1
                if ! swtpm_start "$dir" >/dev/null 2>&1; then
                    echo "WEDGE-RECOVERED: swtpm restart FAILED — caller must abort"
                    return 44
                fi
                return 43
            fi
        fi
        sleep 5
    done
    qemu_kill "$dir"
    return 124
}

# --- boot 1: positive control (signed UKI, same vars file) ----------------------
# Retry loop: concurrent sibling agents on this box have been observed to kill
# qemu/tpm processes and prune .runs mid-boot; a boot without its decisive
# sentinel is treated as an infra anomaly and retried (max 3).
BOOT_OK=0
for _att in 1 2 3; do
    _swtpm_ensure "$CONTROL/tpm" || { echo "s04: swtpm failed"; exit 1; }
    echo "# boot 1/2: signed control (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the pristine
    # base (base LOCK_SH for the boot; overlay discarded after the attempt —
    # a retry is free, no run-dir pollution)
    OVERLAY_B1="$CONTROL/disk-boot1-$_att.qcow2"
    overlay_create "$CONTROL/disk.img" "$OVERLAY_B1" || { echo "s04: overlay create failed"; exit 1; }
    qemu_run "$CONTROL" "$CONTROL/esp.img" "$OVERLAY_B1" "$CONTROL/vars-enrolled.fd" "$CONTROL/tpm" "$CONTROL/pcrsig.img"
    # the token-less disk leaves the SHIPPED unseal hook's bounded keyslot-0
    # recovery prompt as the ONLY way in: feed the slot-0 passphrase,
    # prompt-synchronized (the hook's read has NO timeout)
    if uki_wait_hook_prompt 1 300 "$CONTROL"; then
        feed_line "$CONTROL/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    fi
    _snap_while_running "$(cat "$CONTROL/qemu.pid")" "$CONTROL/console.log" "$SNAPDIR/console-control.snap" &
    _snap_poller1=$!
    _wedge_wait "$CONTROL" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
    wait "$_snap_poller1"
    overlay_discard "$OVERLAY_B1"   # the attempt's overlay is ephemeral
    if grep -q "debian-fde: POWEROFF" "$SNAPDIR/console-control.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# control boot attempt $_att: no completed boot (external kill/prune race?) — retrying"
done
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "control boot completed (guest ran to poweroff)" ""
else
    _assert_result not-ok "control boot completed (guest ran to poweroff)" \
        "no decisive sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-control.snap" 2>/dev/null | tr '\n' ' ')"
fi
CLOG=$(cat "$SNAPDIR/console-control.snap" 2>/dev/null || true)
assert_contains "control boot: init ran" "$CLOG" "debian-fde-harness: init started"
assert_contains "control boot: hook unlocked via the recovery passphrase (token-less disk)" "$CLOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "control boot: firmware accepted signed UKI -> UNSEALED" "$CLOG" "debian-fde: UNSEALED"
assert_contains "control boot: clean poweroff" "$CLOG" "debian-fde: POWEROFF"

# --- boot 2: the scenario — UNSIGNED UKI on the ESP, SB vars unchanged ----------
_ensure_run
esp_make "$RUN/esp-unsigned.img" "$ESP_MIB" "$CONTROL/uki-unsigned.efi" || exit 1
REFUSAL_OK=0
for _att in 1 2 3; do
    _swtpm_ensure "$CONTROL/tpm" || { echo "s04: swtpm restart failed"; exit 1; }
    echo "# boot 2/2: UNSIGNED UKI under enrolled vars (TCG, attempt $_att, refusal budget 150 s) ..."
    OVERLAY_B2="$RUN/disk-boot2-$_att.qcow2"
    overlay_create "$CONTROL/disk.img" "$OVERLAY_B2" || { echo "s04: overlay create failed"; exit 1; }
    qemu_run "$RUN" "$RUN/esp-unsigned.img" "$OVERLAY_B2" "$CONTROL/vars-enrolled.fd" "$CONTROL/tpm" "$CONTROL/pcrsig.img"
    _snap_while_running "$(cat "$RUN/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-refusal.snap" &
    _snap_poller2=$!
    _wedge_wait "$RUN" 150 || true   # 43: swtpm already restarted fresh
    wait "$_snap_poller2"
    overlay_discard "$OVERLAY_B2"
    if grep -qF "$(sentinel_of ovmf_sb_denied)" "$SNAPDIR/console-refusal.snap" 2>/dev/null; then
        REFUSAL_OK=1
        break
    fi
    echo "# refusal boot attempt $_att: no firmware decision captured (external kill/prune race?) — retrying"
done
LOG=$(cat "$SNAPDIR/console-refusal.snap" 2>/dev/null || true)
if [ "$REFUSAL_OK" -eq 1 ]; then
    _assert_result ok "refusal boot: firmware rendered its decision" ""
else
    _assert_result not-ok "refusal boot: firmware rendered its decision" \
        "no ovmf_sb_denied sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-refusal.snap" 2>/dev/null | tr '\n' ' ')"
fi
# The firmware RAN, tried our boot entry and REFUSED it before starting
# (observed OVMF serial output for an unsigned UKI under enrolled vars:
# "failed to load Boot0002" followed by the ovmf_sb_denied sentinel),
# then fell through to the boot-manager menu — nothing can power
# the machine off, so the harness hard-timeout kill (rc 124) is the
# expected termination.
if [ -s "$SNAPDIR/console-refusal.snap" ]; then
    _assert_result ok "refusal boot: console captured (qemu started)" ""
else
    _assert_result not-ok "refusal boot: console captured (qemu started)" "empty/missing console snapshot"
fi
assert_contains "refusal: firmware tried the ESP boot entry" "$LOG" "$(sentinel_of ovmf_bds_loading)"
assert_contains "refusal: Access Denied (Secure Boot rejected the unsigned image)" "$LOG" \
    "$(sentinel_of ovmf_sb_denied)"
assert_contains "refusal: no bootable option remained" "$LOG" "$(sentinel_of ovmf_no_bootable)"
assert_not_contains "refusal: boot entry never STARTED (refused at load)" "$LOG" "$(sentinel_of ovmf_bds_starting)"
# nothing booted that could power off — the firmware sits at the boot-manager
# menu until the harness hard-timeout kill (the POWEROFF/kernel-powerdown
# negatives below pin that down; a timeout kill is the expected termination).

assert_not_contains "refusal: no guest init banner" "$LOG" "debian-fde-harness: init started"
for pcr in 0 7 11; do
    assert_not_contains "refusal: no PCR $pcr line" "$LOG" "debian-fde-pcr sha256:$pcr="
done
assert_not_contains "refusal: the unseal hook never ran (no enter-initrd extend)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_not_contains "refusal: no hook token discovery" "$LOG" "$(sentinel_of unseal_token_info)"
assert_not_contains "refusal: never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "refusal: never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "refusal: never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "refusal: no hook recovery prompt" "$LOG" "$(sentinel_of unseal_prompt_re)"
assert_not_contains "refusal: no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_not_contains "refusal: no harness poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
assert_not_contains "refusal: no Linux kernel banner" "$LOG" "$(sentinel_of linux_banner)"

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s04-unsigned-uki: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s04-unsigned-uki: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
