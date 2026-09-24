#!/usr/bin/env bash
# tests/unit/serial_feed_race.sh — regression test for the intermittent serial
# feed loss (root-caused 2026-09-22, see tests/lib/serial.sh header).
#
# MECHANISM (live-evidenced, qemu 11.1.1 + KVM): qemu serves ONE client on the
# serial chardev socket; when the guest's UART cannot absorb input (vCPU
# descheduled under host load), undelivered bytes sit in the kernel socket
# receive queue, and a feeder that CLOSES its connection during that
# backpressure window destroys them. Only ~8 bytes already in the UART FIFO
# survive — the passphrase arrives truncated/unterminated and the hook's
# prompt hangs until the 420s timeout kill.
#
# REPRODUCER: a QMP-paused vCPU is a DETERMINISTIC backpressure window (host
# load makes the same window appear for seconds at a time; the pause merely
# makes it boundable and stable). The test:
#   phase 1  boot via qemu_run (the production wiring), then feed 6
#            passphrase-length lines through feed_line with a guest that
#            delays its reads, UNDER ARTIFICIAL HOST LOAD (ALPINE_FDE_
#            FEEDRACE_LOAD spinners, default 4) — every feed must be consumed.
#   phase 2  a second boot with -qmp: pause the vCPU, feed ONE 63-char line
#            with the REAL feed_line (connect -> send -> hold -> close), then
#            resume and require the guest to receive the WHOLE line. With the
#            direct-to-qemu wiring this is the red reproducer (only the ~8
#            FIFO bytes arrive, the read times out); with the console bridge
#            the feed is delivered in full.
#
# Boots a minimal echo-guest UKI (busybox init: sleeps, reads a console line,
# echoes it back) — no LUKS/TPM-unlock machinery, so a run stays ~2 min.
# Fixture artifacts are cached under tests/.cache/serial-feed-race/.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
export ALPINE_FDE_ACCEL="${ALPINE_FDE_ACCEL:-kvm}"

LOAD="${ALPINE_FDE_FEEDRACE_LOAD:-4}"   # host spinners (artificial load)
FIXDIR="${ALPINE_FDE_CACHE_DIR:-$TESTS/.cache}/serial-feed-race"
WORK=$(mktemp -d)
RUN="$WORK/run"
mkdir -p "$RUN"

# --- host load (the failure is load-correlated; generate it) ---------------------
# TRAP OWNERSHIP (leak fixed 2026-09-22): swtpm_start() installs its own
# `trap swtpm_cleanup_all EXIT INT TERM` on the first successful start, which
# SILENTLY REPLACES this test's _cleanup traps — a killed/interrupted run then
# leaks the spinners (busy loops at 100% CPU each, observed burning 437% for
# 7 h), qemu and the bridge. Every swtpm start therefore goes through
# _tpm_start, which re-arms this test's traps AFTER the fixture has set its
# own; _cleanup itself still calls swtpm_cleanup_all, so the fixture cleanup
# is preserved. qemu pids are tracked in TRACKED_QEMU_PIDS as a var-level
# backstop beside the $RUN/qemu.pid file (the run dir can be wiped mid-test).
spinners=()
TRACKED_QEMU_PIDS=()
spin_kill() {
    local p
    for p in "${spinners[@]:-}"; do
        kill "$p" 2>/dev/null
    done
    sleep 0.2
    for p in "${spinners[@]:-}"; do
        kill -9 "$p" 2>/dev/null
    done
    return 0
}
_cleanup() {
    local p
    for p in "${TRACKED_QEMU_PIDS[@]:-}"; do
        [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null
    done
    qemu_kill "$RUN" 2>/dev/null          # reaps its bridge too (serial_bridge_stop)
    serial_bridge_stop "$RUN" 2>/dev/null
    swtpm_cleanup_all 2>/dev/null
    spin_kill
    # keep the evidence on failure (stalled-boot triage: console/swtpm/proxy
    # logs); only a passing run cleans up after itself
    if (( ${TESTS_FAIL:-0} == 0 )) && [[ "${_FEEDRACE_OK:-0}" = "1" ]]; then
        rm -rf "$WORK"
    fi
    return 0
}
_rearm_traps() {
    trap _cleanup EXIT
    trap '_cleanup; exit 143' TERM INT
    return 0
}
_tpm_start() {   # _tpm_start <dir> — swtpm_start + re-arm this test's traps
    swtpm_start "$@" || return $?
    _rearm_traps
}
_track_qemu_pid() {   # _track_qemu_pid <run-dir> — remember the boot's qemu pid
    local pid
    pid=$(cat "$1/qemu.pid" 2>/dev/null) || return 0
    [[ -n "$pid" ]] && TRACKED_QEMU_PIDS+=("$pid")
    return 0
}
_rearm_traps
for ((_i = 0; _i < LOAD; _i++)); do
    (while :; do :; done) & spinners+=($!)
done

# --- minimal echo-guest fixture (cached; kernel + busybox from the pinned debs) --
# The cache is trusted ONLY via the .cache-ok marker written after a COMPLETE
# build (a partial build — e.g. a disk-full kill mid-extraction — must never
# be reused: stale keys + fresh enrollment would fail Secure Boot confusingly).
fixture_build() {
    if [[ -f "$FIXDIR/.cache-ok" ]]; then
        return 0
    fi
    rm -rf "$FIXDIR"
    mkdir -p "$FIXDIR"
    keys_create "$FIXDIR/keys" || return 1
    uki_release_key_floor "$FIXDIR/keys" || return 1
    keys_vars_enrolled "$FIXDIR/keys" "$FIXDIR/vars-enrolled.fd" || return 1
    uki_guest_tree "$FIXDIR/tree" >&2 || return 1
    local r="$FIXDIR/initrd-root"
    rm -rf "$r"
    mkdir -p "$r/bin" "$r/usr/bin" "$r/proc" "$r/sys" "$r/dev" "$r/run" "$r/tmp"
    cp "$FIXDIR/tree/usr/bin/busybox" "$r/bin/busybox" || return 1
    for _a in sh sleep cat mount mkdir poweroff stty; do
        ln -sf busybox "$r/bin/$_a"
    done
    cat >"$r/init" <<'INIT'
#!/bin/sh
export PATH=/usr/bin:/bin:/sbin
/bin/busybox mkdir -p /proc /sys /dev /run /tmp
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs dev /dev
[ -c /dev/console ] && exec >/dev/console 2>&1 </dev/console
FR_DELAY=0
FR_ROUNDS=6
for _w in $(cat /proc/cmdline); do
    case "$_w" in
        fr-delay=*) FR_DELAY=${_w#fr-delay=} ;;
        fr-rounds=*) FR_ROUNDS=${_w#fr-rounds=} ;;
    esac
done
echo "FEEDRACE READY delay=$FR_DELAY rounds=$FR_ROUNDS"
n=0
while [ "$n" -lt "$FR_ROUNDS" ]; do
    n=$((n + 1))
    /bin/busybox sleep "$FR_DELAY"      # the busy-hook window: UART not read
    line=
    read -t 60 -r line                  # canonical mode, tty-echoes the input
    rc=$?
    echo "FEEDRACE ECHO$n rc=$rc line=[$line]"
done
echo "FEEDRACE DONE"
/bin/busybox poweroff -f
INIT
    chmod 755 "$r/init"
    (cd "$r" && find . -print0 | cpio -0 -o -H newc --quiet >"$FIXDIR/initrd.cpio") || return 1
    printf 'ID=feedrace\nVERSION_ID=1\nNAME=feedrace\n' >"$FIXDIR/osrel.txt"
    printf '%s\n' "console=ttyS0 rdinit=/init loglevel=3" >"$FIXDIR/cmdline.txt"
    ukify build --linux "$FIXDIR/tree/vmlinuz" --initrd "$FIXDIR/initrd.cpio" \
        --cmdline="@$FIXDIR/cmdline.txt" --os-release="$FIXDIR/osrel.txt" \
        --output "$FIXDIR/uki-unsigned.efi" >&2 || return 1
    sbsign --key "$FIXDIR/keys/db.key" --cert "$FIXDIR/keys/db.crt" \
        --output "$FIXDIR/boot.efi" "$FIXDIR/uki-unsigned.efi" >&2 || return 1
    touch "$FIXDIR/.cache-ok"
    return 0
}

console_wait() { # console_wait <dir> <pattern> <timeout-s>
    local dir=$1 pat=$2 tmo=$3 i=0
    while ((i < tmo)); do
        grep -q "$pat" "$dir/console.log" 2>/dev/null && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

esp_for() { # esp_for <dir>
    local mib
    mib=$(( ($(stat -c%s "$FIXDIR/boot.efi") + 1048575) / 1048576 ))
    esp_make "$1" $((mib * 2 + 8)) "$FIXDIR/boot.efi"
}

echo "# building echo-guest fixture (cached: $FIXDIR) ..."
fixture_build || { echo "serial_feed_race: fixture build failed"; exit 1; }
truncate -s 32M "$RUN/disk.img"
_tpm_start "$RUN/tpm" || { echo "serial_feed_race: swtpm failed"; exit 1; }

LONGLINE=$(printf 'C%.0s' $(seq 1 63))   # 63 chars + \n: exceeds the UART FIFO

# === phase 1: production wiring (qemu_run), repeated feeds under load =============
# guest sleeps 2s before each read — the "hook busy between prompts" window —
# while 4 host spinners starve everything. Every feed must be consumed.
echo "# phase 1: qemu_run boot, 6 feeds (63-byte lines) under load=$LOAD ..."
fixture_cmdline_refresh() { # rebuild ONLY the cmdline variant of the fixture UKI
    printf '%s\n' "console=ttyS0 rdinit=/init loglevel=3 fr-delay=$1 fr-rounds=$2" \
        >"$FIXDIR/cmdline.txt"
    ukify build --linux "$FIXDIR/tree/vmlinuz" --initrd "$FIXDIR/initrd.cpio" \
        --cmdline="@$FIXDIR/cmdline.txt" --os-release="$FIXDIR/osrel.txt" \
        --output "$FIXDIR/uki-unsigned.efi" >&2 || return 1
    sbsign --key "$FIXDIR/keys/db.key" --cert "$FIXDIR/keys/db.crt" \
        --output "$FIXDIR/boot.efi" "$FIXDIR/uki-unsigned.efi" >&2
}
fixture_cmdline_refresh 2 7 || { echo "serial_feed_race: cmdline refresh failed"; exit 1; }
esp_for "$RUN/esp.img" || { echo "serial_feed_race: esp_make failed"; exit 1; }

boot_retry() { # boot_retry <dir> <boot-cmd...> — run a boot, wait READY; on a
    # silent/hung boot (a PRE-EXISTING intermittent infra failure, observed
    # with and without the bridge; the scenarios retry their baseline boots
    # for the same reason) dump diagnostics and retry, up to 3 attempts.
    local dir=$1 attempt
    shift
    for attempt in 1 2 3; do
        "$@"
        if console_wait "$dir" "FEEDRACE READY" 120; then
            return 0
        fi
        echo "#   boot attempt $attempt did not reach READY — console bytes: $(stat -c%s "$dir/console.log" 2>/dev/null) qemu.stderr: $(tail -c 200 "$dir/qemu.stderr" 2>/dev/null | tr '\n' '|')"
        qemu_kill "$dir"
        swtpm_reset "$dir/tpm" >/dev/null 2>&1
        _tpm_start "$dir/tpm" >/dev/null 2>&1 || return 1
    done
    return 1
}

boot_retry "$RUN" qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" \
    "$FIXDIR/vars-enrolled.fd" "$RUN/tpm" \
    || { echo "serial_feed_race: guest never became READY (console: $(tail -c 200 "$RUN/console.log" 2>/dev/null | tr -d '\033' | head -c 200))"; exit 1; }
_track_qemu_pid "$RUN"
echo "# guest READY; feeding 6 lines with the production feed_line under load"
p1_fail=0
for n in 1 2 3 4 5 6; do
    feed_line "$RUN/serial.sock" "probe-long-line-$n-$LONGLINE"
    if console_wait "$RUN" "FEEDRACE ECHO$n rc=0 line=\[probe-long-line-$n-$LONGLINE\]" 45; then
        echo "#   feed $n DELIVERED"
    else
        echo "#   feed $n LOST — console tail: $(tail -c 300 "$RUN/console.log" | tr -d '\033')"
        p1_fail=$((p1_fail + 1))
    fi
done
if ((p1_fail == 0)); then
    _assert_result ok "phase1: 6/6 feeds consumed under load (qemu_run + bridge)" ""
else
    _assert_result not-ok "phase1: 6/6 feeds consumed under load (qemu_run + bridge)" \
        "$p1_fail/6 feeds lost"
fi
qemu_kill "$RUN"

# === phase 2: deterministic backpressure (QMP pause) + the real feed_line ========
# pause -> feed_line (connect/send/hold/CLOSE) -> resume -> the WHOLE 63-char
# line must reach the guest. Red with direct-to-qemu wiring (close destroys the
# queued input), green with the console bridge.
echo "# phase 2: QMP-paused vCPU (deterministic backpressure) + real feed_line"
qemu_kill "$RUN"          # reaps the phase-1 bridge BEFORE the run dir is wiped
# stop the phase-1 swtpm + proxy BEFORE the wipe: their pidfiles live in the
# run dir, and a wiped dir orphans both (leaked setsid'd pair, ppid 1 —
# observed live 2026-09-22)
swtpm_stop "$RUN/tpm" 2>/dev/null
rm -rf "$RUN"; mkdir -p "$RUN"
truncate -s 32M "$RUN/disk.img"
fixture_cmdline_refresh 0 4 || { echo "serial_feed_race: cmdline refresh failed"; exit 1; }
esp_for "$RUN/esp.img" || { echo "serial_feed_race: esp_make failed"; exit 1; }
_tpm_start "$RUN/tpm" || { echo "serial_feed_race: swtpm failed (phase 2)"; exit 1; }
phase2_boot() {
    if declare -F serial_bridge_start >/dev/null; then
        serial_bridge_start "$RUN" || return 1
    fi
    rm -f "$RUN/console.log" "$RUN/qemu.pid"
    mapfile -t _args < <(qemu_argv "$RUN" "$RUN/esp.img" "$RUN/disk.img" \
        "$FIXDIR/vars-enrolled.fd" "$RUN/tpm")
    qemu-system-x86_64 "${_args[@]}" -qmp "unix:$RUN/qmp.sock,server=on,wait=off" \
        >"$RUN/qemu.stdout" 2>"$RUN/qemu.stderr" &
    echo $! >"$RUN/qemu.pid"
}
boot_retry "$RUN" phase2_boot \
    || { echo "serial_feed_race: guest never became READY (phase 2)"; exit 1; }
_track_qemu_pid "$RUN"
echo "# guest READY; pausing vCPU and feeding the 63-char line via feed_line"

qmp_cmd() {
    python3 - "$RUN/qmp.sock" "$1" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1]); s.settimeout(5)
f = s.makefile("rw")
json.loads(f.readline())                       # greeting
f.write('{"execute":"qmp_capabilities"}\n'); f.flush(); json.loads(f.readline())
f.write('{"execute":"%s"}\n' % sys.argv[2]); f.flush()
json.loads(f.readline())
PY
}
qmp_cmd stop
feed_line "$RUN/serial.sock" "$LONGLINE"
sleep 2          # the feeder has closed now; qemu-side state settles while paused
qmp_cmd cont
echo "# vCPU resumed; waiting for the guest's read result"
full="FEEDRACE ECHO1 rc=0 line=\\[$LONGLINE\\]"
if console_wait "$RUN" "$full" 90; then
    _assert_result ok "phase2: feed_line survives UART backpressure (whole 63-char line consumed)" ""
else
    _assert_result not-ok "phase2: feed_line survives UART backpressure (whole 63-char line consumed)" \
        "console tail: $(tail -c 300 "$RUN/console.log" | tr -d '\033')"
fi
qemu_kill "$RUN"
swtpm_stop "$RUN/tpm"

if (( TESTS_FAIL == 0 )); then
    _FEEDRACE_OK=1
fi
echo "# serial_feed_race: pass=$TESTS_PASS fail=$TESTS_FAIL (work dir kept on failure: $WORK)"
(( TESTS_FAIL == 0 )) || exit 1
exit 0
