#!/usr/bin/env bash
# tests/lib/serial.sh — thin shell wrapper around tests/lib/serial.py.
# Usage: serial_cmd <sock> <subcommand> [args...]   (see serial.py --help)

if [[ -n "${_DEBIAN_FDE_SERIAL_SH_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_SERIAL_SH_SOURCED=1

_serial_py() {
    printf '%s\n' "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/serial.py"
}

serial_read_until() { python3 "$(_serial_py)" "$1" read_until "$2" "$3"; }
serial_write_line() { python3 "$(_serial_py)" "$1" write_line "$2"; }
serial_drain() { python3 "$(_serial_py)" "$1" drain "$2"; }

# feed_line <sock> <text> — feed one console line to the guest (IN-03: the
# single promoted copy; was duplicated across s00b/s09/s12/s18). The chardev
# session must STAY OPEN ~5s or QEMU drops in-flight serial input.
feed_line() {
    python3 - "$1" "$2" <<'PYEOF'
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall((sys.argv[2] + "\n").encode())
time.sleep(5)   # keep the session open while the guest UART drains
s.close()
PYEOF
}
