#!/usr/bin/env bash
# tests/lib/serial.sh — guest-console session layer for the e2e harness.
#
# ARCHITECTURE (defect: intermittent feed loss under load, root-caused
# 2026-09-22): the guest's ttyS0 is exposed by qemu as a `-chardev socket,
# server=on,wait=off` unix socket. QEMU SERVES EXACTLY ONE CLIENT at a time
# and — the load-bearing fact — when the frontend (the 16550 UART emulation)
# cannot absorb input fast enough (the guest vCPU is descheduled for seconds
# under host load / TCG), the undelivered bytes stay in the kernel socket
# receive queue; if the client then CLOSES the connection, that queued input
# is destroyed. Only the bytes already moved into the UART FIFO (~8) survive;
# the rest never reach the guest. Live evidence (qemu 11.1.1, KVM, QMP-paused
# vCPU = deterministic backpressure, 64-byte feed):
#
#   close 0s/2s into a 5s pause  -> 8 of 64 bytes delivered, line unterminated
#   connection HELD through the  -> all 64 bytes delivered, pause 5s AND 20s
#   same pause
#
# The historical `feed_line` (connect -> send -> fixed 5s hold -> close) is
# exactly the losing shape: the 5s hold only masks the drop when the guest
# drains the UART within 5s of the feed. Under load it sometimes does not —
# hence the intermittent ~50% prompt hangs that killed whole scenarios.
#
# THE FIX: a persistent host-side BRIDGE (serial_bridge_start) that owns the
# qemu-side connection for the whole boot and NEVER closes it, exposing the
# console on <run>/serial.sock to any number of short-lived clients (feed_line,
# serial.py read_until/drain). A feed client's close is then harmless — its
# bytes sit on the BRIDGE connection, which stays open until qemu exits, so
# qemu delivers them whenever the guest's UART drains. This is the same
# single-persistent-session pattern dracut/virt-test harnesses use. The
# bridge broadcasts console output to every connected client and forwards
# input from any client, so concurrent readers + feeders coexist.
#
# CLI wrappers (serial_read_until / serial_write_line / serial_drain) are
# thin wrappers around tests/lib/serial.py and now talk to the BRIDGE socket
# ($RUN/serial.sock — unchanged path for every caller).

if [[ -n "${_ALPINE_FDE_SERIAL_SH_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_SERIAL_SH_SOURCED=1

_serial_py() {
    printf '%s\n' "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/serial.py"
}

serial_read_until() { python3 "$(_serial_py)" "$1" read_until "$2" "$3"; }
serial_write_line() { python3 "$(_serial_py)" "$1" write_line "$2"; }
serial_drain() { python3 "$(_serial_py)" "$1" drain "$2"; }

# --- the console bridge -----------------------------------------------------------

# qemu-side (internal) socket path qemu_argv wires the chardev to; the bridge
# fronts the PUBLIC <run>/serial.sock every caller uses.
_qemu_serial_sock() { printf '%s/serial-qemu.sock' "$1"; }

serial_bridge_log() { printf '%s/serial-bridge.log' "$1"; }

# serial_bridge_start <run-dir> — (re)start the persistent console bridge for
# <run-dir>. Idempotent: a bridge already serving this run dir is replaced.
# The bridge listens on <run>/serial.sock immediately (clients never block on
# qemu startup) and connects upstream to the qemu socket with retry, so start
# order vs qemu_run does not matter. Detached (setsid), pid in
# <run>/serial-bridge.pid; qemu_kill / serial_bridge_stop reap it.
serial_bridge_start() {
    local run="$1" py
    [[ -n "$run" ]] || { echo "serial_bridge_start: usage: serial_bridge_start <run-dir>" >&2; return 64; }
    serial_bridge_stop "$run"
    py="$run/serial-bridge.py"
    cat >"$py" <<'BRIDGEPY'
#!/usr/bin/env python3
"""serial-bridge.py — persistent qemu serial-console bridge (tests/lib/serial.sh).

Owns the ONE qemu chardev-socket client connection for the whole boot (never
closes it — see the defect note in tests/lib/serial.sh: closing the qemu-side
connection while the guest UART is backpressured destroys in-flight input).
Fronts <listen-path> to any number of short-lived console clients: output is
broadcast to all clients, input from any client goes to the guest.

Usage: serial-bridge.py <qemu-sock-path> <listen-path> <log-path>
"""
import select
import socket
import sys
import time

CHUNK = 65536


def log(path, msg):
    try:
        with open(path, "a") as f:
            f.write(f"{time.time():.3f} {msg}\n")
    except OSError:
        pass


def main():
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <qemu-sock> <listen-path> <log-path>",
              file=sys.stderr)
        return 64
    qemu_path, listen_path, log_path = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        import os
        os.unlink(listen_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(listen_path)
    srv.listen(8)

    up = None                      # the qemu-side connection (NEVER closed by us
    up_buf = b""                   #  while qemu lives; reconnected on EOF)
    clients = []                   # connected console clients
    stat = {"in": 0, "out": 0}     # bytes: in = to guest, out = to clients

    def connect_up():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(qemu_path)
        except OSError:
            s.close()
            return None
        s.setblocking(False)
        return s

    log(log_path, f"bridge up: {listen_path} -> {qemu_path}")
    started = time.monotonic()
    ever_connected = False        # the qemu socket may be created AFTER us
    up_gone_since = None          # (qemu_run starts the bridge first) — retry
    while True:                   # the connect until it appears
        if up is None:
            up = connect_up()
            if up is not None:
                log(log_path, "qemu connection established")
                ever_connected = True
                up_gone_since = None
            else:
                # EXIT POLICY: before the FIRST successful connect we keep
                # retrying (bounded) — that is the normal qemu_run startup
                # race, never a leak. After a real connection was lost
                # (qemu died / guest powered off), retry for a bounded
                # window and then exit — a scenario's next boot always
                # starts a fresh bridge (qemu_run), so a lingering
                # reconnect loop would only leak one process per boot.
                if not ever_connected:
                    if time.monotonic() - started > 120.0:
                        log(log_path, "qemu socket never appeared in 120s — exiting")
                        return 0
                else:
                    if up_gone_since is None:
                        up_gone_since = time.monotonic()
                    if not clients or time.monotonic() - up_gone_since > 60.0:
                        log(log_path, "qemu gone — exiting (no clients)"
                            if not clients else "qemu gone 60s — exiting")
                        return 0
        rl = [srv] + ([up] if up is not None else []) + clients
        try:
            r, _, _ = select.select(rl, [], [], 0.5)
        except (InterruptedError, OSError):
            continue
        if srv in r:
            try:
                conn, _ = srv.accept()
            except OSError:
                conn = None
            if conn is not None:
                conn.setblocking(True)
                clients.append(conn)
                log(log_path, f"client connected (total {len(clients)})")
        if up is not None and up in r:
            try:
                data = up.recv(CHUNK)
            except (BlockingIOError, InterruptedError):
                data = None
            except OSError:
                data = b""
            if data:
                stat["out"] += len(data)
                dead = []
                for c in clients:
                    try:
                        c.sendall(data)
                    except OSError:
                        dead.append(c)
                for c in dead:
                    clients.remove(c)
                    try:
                        c.close()
                    except OSError:
                        pass
                log(log_path, f"client gone (total {len(clients)})") if dead else None
            elif data == b"":
                # qemu closed (exit/restart): drop and reconnect-retry
                log(log_path, f"qemu connection lost (in={stat['in']} out={stat['out']})")
                try:
                    up.close()
                except OSError:
                    pass
                up = None
                up_gone_since = None
        for c in [x for x in clients if x in r]:
            try:
                data = c.recv(CHUNK)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                data = b""
            if data:
                stat["in"] += len(data)
                log(log_path, f"feed: {len(data)} bytes to guest (total in={stat['in']})")
                if up is not None:
                    try:
                        up.sendall(data)   # blocking: qemu's socket buffer is
                    except OSError:        # far deeper than any feed line
                        pass
            else:
                clients.remove(c)
                try:
                    c.close()
                except OSError:
                    pass
                log(log_path, f"client closed (total {len(clients)})")


if __name__ == "__main__":
    sys.exit(main())
BRIDGEPY
    chmod 755 "$py"
    : >"$(serial_bridge_log "$run")"
    # detach: the bridge must outlive the scenario shell's foreground work but
    # stay discoverable/reapable via the pid file (the swtpm-fixture pattern)
    setsid python3 "$py" "$(_qemu_serial_sock "$run")" "$run/serial.sock" \
        "$(serial_bridge_log "$run")" >/dev/null 2>&1 &
    echo $! >"$run/serial-bridge.pid"
    # bound the "is it listening" wait — the bind happens immediately
    local i=0
    while (( i < 50 )); do
        [[ -S "$run/serial.sock" ]] && return 0
        sleep 0.1
        i=$((i + 1))
    done
    echo "serial_bridge_start: bridge did not come up ($run/serial.sock missing)" >&2
    return 1
}

# serial_bridge_stop <run-dir> — reap the bridge (qemu_kill calls this; the
# socket file goes with it, so a stale listener can never answer a new boot).
# The pidfile may be gone (caller wiped the run dir), so fall back to matching
# the bridge process by its UNIQUE upstream-socket argument.
serial_bridge_stop() {
    # Wave-2 2b disk locking: drop this boot's base-chain LOCK_SH fds (the
    # single release choke point — qemu_wait/qemu_kill and every scenario
    # wait guard call serial_bridge_stop on every exit path). Idempotent.
    if declare -p QEMU_DISK_LOCK_FDS >/dev/null 2>&1; then
        local _sbl_fd
        for _sbl_fd in "${QEMU_DISK_LOCK_FDS[@]}"; do
            eval "exec ${_sbl_fd}<&-" 2>/dev/null
        done
        QEMU_DISK_LOCK_FDS=()
    fi
    local run="$1" pid pidfile
    pidfile="$run/serial-bridge.pid"
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
        rm -f "$pidfile"
    fi
    pkill -9 -f "serial-bridge\\.py [^ ]*$(_qemu_serial_sock "$run")( |$)" 2>/dev/null || true
    rm -f "$run/serial.sock" "$run/serial-bridge.py"
    return 0
}

# feed_line <sock> <text> — feed one console line to the guest (IN-03: the
# single promoted copy). <sock> is the PUBLIC bridge socket ($RUN/serial.sock).
#
# Delivery is lossless REGARDLESS of guest UART backpressure (root cause in
# the header): the bridge owns the qemu-side connection and never closes it
# during a boot, so these bytes can never be orphaned by a client close.
# The hold before close is kept at the historical 5s for the one caller shape
# that still talks to qemu DIRECTLY (s10's _qemu_run_no_tpm wiring, which this
# file must keep working unchanged): there the hold is the only mitigation.
# For the bridge path the hold is superfluous. The connect retries briefly
# (the bridge binds before qemu starts, but never say never).
# ALPINE_FDE_SERIAL_DEBUG=1 logs the feed boundary (bytes, latency) to stderr.
feed_line() {
    python3 - "$1" "$2" <<'PYEOF'
import os, socket, sys, time
sock, text = sys.argv[1], sys.argv[2]
dbg = os.environ.get("ALPINE_FDE_SERIAL_DEBUG")
payload = (text + "\n").encode()
t0 = time.monotonic()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
deadline = time.monotonic() + 5.0
last = None
while True:
    try:
        s.connect(sock)
        break
    except (FileNotFoundError, ConnectionRefusedError) as e:
        last = e
        if time.monotonic() > deadline:
            print(f"feed_line: cannot connect to {sock}: {last}", file=sys.stderr)
            sys.exit(1)
        time.sleep(0.1)
s.sendall(payload)
t_send = time.monotonic()
time.sleep(5)   # hold: direct-wiring mitigation; superfluous via the bridge
s.close()
if dbg:
    print(f"feed_line: {len(payload)} bytes -> {sock} "
          f"(conn+send {(t_send - t0) * 1000:.1f} ms)", file=sys.stderr)
PYEOF
}
