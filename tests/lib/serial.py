#!/usr/bin/env python3
"""serial.py — stdlib-only serial-socket client for the Debian FDE e2e harness.

Talks to a QEMU `-chardev socket,id=...,server=on,wait=off` unix socket
(the guest's ttyS0). No pexpect/expect dependency (neither exists on this
sandbox — verified); pure `socket`.

CLI:
    serial.py sock read_until  <pattern> <timeout-s>   exit 0 on match
    serial.py sock write_line  <text>                  send text + \n
    serial.py sock drain       <timeout-s>             print everything readable

Library:
    from serial import Serial
    s = Serial("/path/to/serial.sock")
    s.read_until("login:", 120.0)
    s.write_line("passphrase")
"""

import os
import socket
import sys
import time


class SerialTimeout(Exception):
    """read_until did not see the pattern within the timeout."""


class Serial:
    def __init__(self, path, timeout=120.0):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # QEMU creates the socket early; wait for it to accept connections.
        deadline = time.monotonic() + 30.0
        last_err = None
        while time.monotonic() < deadline:
            try:
                self.sock.connect(path)
                break
            except (FileNotFoundError, ConnectionRefusedError) as e:
                last_err = e
                time.sleep(0.2)
        else:
            raise ConnectionError(f"cannot connect to {path}: {last_err}")
        self.sock.settimeout(0.5)
        self.buf = b""

    def _read_some(self):
        # MD-06: recv() returning b"" is peer EOF (dead QEMU) — raise instead
        # of tight-looping on a closed socket until the deadline.
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return
        if data == b"":
            raise ConnectionError(f"serial EOF on {self.path} (guest/qemu died?)")
        self.buf += data
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    def read_until(self, pattern, timeout=120.0):
        """Block until `pattern` (bytes-like or str) appears in the stream.
        Returns everything read up to and including the match."""
        pat = pattern.encode() if isinstance(pattern, str) else pattern
        deadline = time.monotonic() + timeout
        while True:
            idx = self.buf.find(pat)
            if idx >= 0:
                out, self.buf = self.buf[: idx + len(pat)], self.buf[idx + len(pat):]
                return out
            if time.monotonic() > deadline:
                raise SerialTimeout(f"pattern {pattern!r} not seen within {timeout}s")
            self._read_some()

    def write_line(self, text):
        """Send text + newline (console Enter)."""
        self.sock.sendall((text + "\n").encode())

    def drain(self, timeout=1.0):
        """Read (and echo) whatever arrives within `timeout` seconds."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._read_some()
        out, self.buf = self.buf, b""
        return out

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, cmd = argv[1], argv[2]
    s = Serial(path)
    try:
        if cmd == "read_until" and len(argv) == 5:
            try:
                s.read_until(argv[3], float(argv[4]))
                return 0
            except SerialTimeout as e:
                print(f"serial.py: {e}", file=sys.stderr)
                return 1
        if cmd == "write_line" and len(argv) == 4:
            s.write_line(argv[3])
            return 0
        if cmd == "drain" and len(argv) == 4:
            s.drain(float(argv[3]))
            return 0
        print(__doc__, file=sys.stderr)
        return 2
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
