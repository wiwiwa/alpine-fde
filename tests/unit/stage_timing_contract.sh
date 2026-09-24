#!/usr/bin/env bash
# tests/unit/stage_timing_contract.sh — pins the per-step timing contract of
# the e2e harness (tests/README.md "Runner contract details": "Step timing").
#
# Three hermetic sections — NO qemu, NO swtpm, NO boots:
#   1. tests/lib/stage-timing.sh: stage_begin/stage_end/stage_timed emission
#      formats, fail-closed begin/end discipline (no nested stages, no
#      mismatched end, no end without begin), and the runner-side harvest
#      (stage_timing_json -> "{label: seconds}" JSON, last label wins).
#   2. tests/lib/qemu.sh boot timing: the `# boot <run-dir-basename>: powered
#      down|killed after <seconds>s` lines qemu_wait emits on the clean and
#      timeout paths (probed via _qemu_boot_note + a fake qemu.pid; qemu_wait's
#      timeout path is exercised against a plain `sleep` child).
#   3. tests/lib/serial.sh console mirror: every bridge boot writes
#      <run>/console-timed.log — each console line prefixed with an epoch
#      timestamp, original bytes/lines/order preserved, appending across a
#      qemu reconnect within one boot, fresh file per bridge start, and
#      console.log itself untouched (qemu owns it byte-identical).
#
# The mirror is probed against a FAKE qemu upstream (a python AF_UNIX server
# that sends phase-1 bytes, closes, and completes the split line after the
# bridge reconnects) — no guest, no console.log writer in play.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

WORK=$(mktemp -d /tmp/alpine-fde-stage-timing.XXXXXX)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
trap 'trap - INT; kill -INT $$; exit 130' INT
trap 'trap - TERM; kill -TERM $$; exit 143' TERM

# =====================================================================================
# part 1 — tests/lib/stage-timing.sh
# =====================================================================================
assert_file_exists "stage-timing lib present" "$TESTS/lib/stage-timing.sh"
# shellcheck source=../lib/stage-timing.sh
source "$TESTS/lib/stage-timing.sh"

T1="$WORK/t1.log"
{
    stage_begin build
    sleep 1
    stage_end build
} >"$T1" 2>"$WORK/t1.err"
assert_eq "begin+end pair exits clean (rc 0)" "0" "$?"
assert_contains "begin line format: '# stage <label>: begin <epoch>'" \
    "$(cat "$T1")" "# stage build: begin "
assert_contains "done line format: '# stage <label>: done <seconds>s'" \
    "$(cat "$T1")" "# stage build: done "
EPOCH=$(sed -n 's/^# stage build: begin \([0-9]\{1,\}\)$/\1/p' "$T1")
assert_rc "begin epoch is a bare integer unix epoch" 0 test "$EPOCH" -ge 1767225600
SECS=$(sed -n 's/^# stage build: done \([0-9]\{1,\}\)s$/\1/p' "$T1")
assert_rc "done seconds reflect the measured duration (>= 1 for a 1s stage)" 0 \
    test "${SECS:-0}" -ge 1
assert_rc "done seconds stay consistent with the begin epoch" 0 \
    bash -c "test \$(( \$(date +%s) - $EPOCH )) -ge ${SECS:-999}"

# fail-closed discipline: every error is loud (stderr names the label), rc != 0
( stage_end build ) >"$WORK/e1.out" 2>"$WORK/e1.err"
assert_eq "stage_end with no open stage fails closed" "1" "$?"
assert_contains "stage_end without begin names the error loudly" \
    "$(cat "$WORK/e1.err")" "no open stage"

( stage_begin a; stage_begin b ) >"$WORK/e2.out" 2>"$WORK/e2.err"
assert_eq "nested stage_begin fails closed" "1" "$?"
assert_contains "nested begin names the still-open stage" \
    "$(cat "$WORK/e2.err")" "still open"

( stage_begin a; stage_end b ) >"$WORK/e3.out" 2>"$WORK/e3.err"
assert_eq "mismatched stage_end fails closed" "1" "$?"
assert_contains "mismatched end names both labels" \
    "$(cat "$WORK/e3.err")" "mismatch"

( stage_begin 'bad"label' ) >"$WORK/e4.out" 2>"$WORK/e4.err"
assert_eq "label with a quote character is refused (never breaks the JSON harvest)" "1" "$?"
assert_contains "refused label is named loudly" "$(cat "$WORK/e4.err")" "stage-timing: ERROR"

( stage_begin "" ) >"$WORK/e5.out" 2>"$WORK/e5.err"
assert_eq "empty label is refused" "1" "$?"

T2="$WORK/t2.log"
{
    stage_timed timed-ok -- sleep 1
} >"$T2" 2>&1
assert_eq "stage_timed passes a clean command through (rc 0)" "0" "$?"
assert_contains "stage_timed emits the begin line" "$(cat "$T2")" "# stage timed-ok: begin "
assert_contains "stage_timed emits the done line" "$(cat "$T2")" "# stage timed-ok: done "

{ stage_timed timed-fail -- false; } >"$WORK/t3.log" 2>&1
assert_eq "stage_timed propagates the command's failure rc" "1" "$?"
assert_contains "a failing stage still records its done line (elapsed is valid regardless of rc)" \
    "$(cat "$WORK/t3.log")" "# stage timed-fail: done "

( stage_timed missing-sep -- ) >/dev/null 2>&1
assert_eq "stage_timed without 'label -- cmd' shape is a usage error (rc 64)" "64" "$?"

# harvest (the runner-side parser; "parse, don't trust env")
cat >"$WORK/run.log" <<'EOF'
# stage snap: done 1s
ok 1 - some assertion
# stage build: done 245s
# stage snap: done 3s
EOF
assert_eq "harvest: '# stage ... done' lines -> {label: seconds} JSON, last write wins" \
    '{"build":245,"snap":3}' \
    "$(stage_timing_json "$WORK/run.log" | jq -cS .)"
: >"$WORK/empty.log"
assert_eq "harvest: no stage lines -> empty output (row keeps the old schema)" \
    "" "$(stage_timing_json "$WORK/empty.log")"
assert_eq "harvest: missing log file -> empty output" \
    "" "$(stage_timing_json "$WORK/does-not-exist.log")"
printf '# stage build: begin 1790000000\n# stage build: done not-a-number\n' >"$WORK/junk.log"
assert_eq "harvest: malformed done lines are ignored, never mis-parsed" \
    "" "$(stage_timing_json "$WORK/junk.log")"

# =====================================================================================
# part 2 — tests/lib/qemu.sh boot timing
# =====================================================================================
assert_file_exists "qemu lib present" "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"

BOOT="$WORK/runs/boot-a"
mkdir -p "$BOOT"
_QEMU_BOOT_T0["$BOOT"]=$(( $(date +%s) - 7 ))
{ _qemu_boot_note "$BOOT" powered; } >"$WORK/b1.log" 2>&1
assert_rc "clean-exit boot line: '# boot <basename>: powered down after <N>s'" 0 \
    grep -Eq '^# boot boot-a: powered down after [0-9]+s$' "$WORK/b1.log"
BSECS=$(sed -n 's/^# boot boot-a: powered down after \([0-9]\{1,\}\)s$/\1/p' "$WORK/b1.log")
assert_rc "boot seconds reflect the recorded launch epoch (7s ± 1)" 0 \
    test "${BSECS:-0}" -ge 6 -a "${BSECS:-0}" -le 8

{ _qemu_boot_note "$BOOT" killed; } >"$WORK/b2.log" 2>&1
assert_rc "timeout-path boot line: '# boot <basename>: killed after <N>s'" 0 \
    grep -Eq '^# boot boot-a: killed after [0-9]+s$' "$WORK/b2.log"

# no recorded epoch: fall back to the qemu.pid mtime (boot launch), never emit garbage
BOOT2="$WORK/runs/boot-b"
mkdir -p "$BOOT2"
touch -d '30 seconds ago' "$BOOT2/qemu.pid"
{ _qemu_boot_note "$BOOT2" powered; } >"$WORK/b3.log" 2>&1
B3=$(sed -n 's/^# boot boot-b: powered down after \([0-9]\{1,\}\)s$/\1/p' "$WORK/b3.log")
assert_rc "no in-process epoch: qemu.pid mtime is the fallback (>= 28s)" 0 \
    test "${B3:-0}" -ge 28

BOOT3="$WORK/runs/boot-c"
mkdir -p "$BOOT3"
assert_eq "no epoch and no pid file: nothing emitted (rc 0, no line)" \
    "" "$(_qemu_boot_note "$BOOT3" powered)"

# qemu_wait end-to-end: CLEAN path (pid already dead -> powered line, rc 0)
BOOT4="$WORK/runs/boot-d"
mkdir -p "$BOOT4"
DEAD_PID=$(bash -c 'echo $$')
echo "$DEAD_PID" >"$BOOT4/qemu.pid"
_QEMU_BOOT_T0["$BOOT4"]=$(( $(date +%s) - 2 ))
qemu_wait "$BOOT4" 5 >"$WORK/b4.log" 2>&1
assert_eq "qemu_wait on a dead guest exits 0 (clean poweroff)" "0" "$?"
assert_rc "qemu_wait clean path emits the powered-down line on SCENARIO stdout" 0 \
    grep -Eq '^# boot boot-d: powered down after [0-9]+s$' "$WORK/b4.log"

# qemu_wait end-to-end: TIMEOUT path (live `sleep` child -> killed line, rc 124)
BOOT5="$WORK/runs/boot-e"
mkdir -p "$BOOT5"
sleep 60 & LIVE_PID=$!
echo "$LIVE_PID" >"$BOOT5/qemu.pid"
qemu_wait "$BOOT5" 1 >"$WORK/b5.log" 2>&1
assert_eq "qemu_wait timeout path returns 124 (timeout-class)" "124" "$?"
assert_rc "qemu_wait timeout path also emits the elapsed (killed line)" 0 \
    grep -Eq '^# boot boot-e: killed after [0-9]+s$' "$WORK/b5.log"
kill -9 "$LIVE_PID" 2>/dev/null
wait "$LIVE_PID" 2>/dev/null

# =====================================================================================
# part 3 — tests/lib/serial.sh console mirror (<run>/console-timed.log)
# =====================================================================================
assert_file_exists "serial lib present" "$TESTS/lib/serial.sh"
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"

cat >"$WORK/fake-qemu.py" <<'PYEOF'
import os, socket, sys, time
path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(4)
# phase 1: two complete lines + a SPLIT line, then close (forces the bridge's
# reconnect path mid-line)
c, _ = srv.accept()
time.sleep(1.0)          # let the test's console client attach first
c.sendall(b"line one\nline two\npar")
time.sleep(0.3)
c.close()
# phase 2 (reconnect, same bridge, same boot): complete the split line
c, _ = srv.accept()
time.sleep(0.3)
c.sendall(b"tial\nline three\n")
time.sleep(0.3)
c.close()
srv.close()
PYEOF

MIR="$WORK/runs/mirror"
mkdir -p "$MIR"
python3 "$WORK/fake-qemu.py" "$(_qemu_serial_sock "$MIR")" &
FAKE_QEMU=$!
serial_bridge_start "$MIR"
assert_eq "bridge starts against the fake qemu upstream (rc 0)" "0" "$?"
serial_read_until "$MIR/serial.sock" "line three" 15 >/dev/null 2>&1
assert_eq "client still receives the exact console stream (read_until finds the last line)" "0" "$?"
kill "$FAKE_QEMU" 2>/dev/null
wait "$FAKE_QEMU" 2>/dev/null

TIMED="$MIR/console-timed.log"
assert_file_exists "mirror file written beside console.log" "$TIMED"
assert_rc "every mirror line is '<epoch> <original line>'" 0 \
    grep -Eq '^[0-9]+\.[0-9]{3} line one$' "$TIMED"
assert_rc "mirror line for the second console line" 0 \
    grep -Eq '^[0-9]+\.[0-9]{3} line two$' "$TIMED"
assert_rc "mirror line for the third console line" 0 \
    grep -Eq '^[0-9]+\.[0-9]{3} line three$' "$TIMED"
assert_rc "a console line SPLIT across the qemu reconnect mirrors as ONE line (append across reconnects)" 0 \
    grep -Eq '^[0-9]+\.[0-9]{3} partial$' "$TIMED"
assert_eq "mirror preserves exact original lines in order (timestamps stripped)" \
    "line one/line two/partial/line three" \
    "$(sed -E 's/^[0-9]+\.[0-9]{3} //' "$TIMED" | paste -sd/ -)"
assert_rc "mirror timestamps are ascending (chronological)" 0 \
    awk -F. '{ if ($1 < prev) exit 1; prev = $1 }' "$TIMED"
assert_rc "console.log is untouched by the bridge (qemu owns it, byte-identical substrate)" 1 \
    test -e "$MIR/console.log"

# fresh mirror per boot: a new serial_bridge_start (qemu_run's per-boot entry)
# truncates the mirror, never appends the previous boot's lines into it
serial_bridge_start "$MIR"
assert_eq "bridge restarts for the next boot (rc 0)" "0" "$?"
assert_eq "mirror is FRESH per boot (restarted bridge truncates it)" "" "$(cat "$TIMED")"
serial_bridge_stop "$MIR"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# stage_timing_contract: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
