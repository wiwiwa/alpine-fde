#!/usr/bin/env bash
# tests/unit/dispatch_alpine_entry.sh — bin/alpine-fde entry-point contract (§8.1):
#   * bin/alpine-fde is executable and dispatches identically to bin/debian-fde
#     (same rc, equivalent stdout) on a stub cmd dir via DEBIAN_FDE_CMD_DIR
#   * usage/--version/error banners reflect the INVOKED name (alpine-fde vs
#     debian-fde) — POSIX ash has no `exec -a`, so bin/alpine-fde signals its
#     name via an env var the dispatcher reads for PROG
#   * the install help line describes the minimal Alpine rootfs (apk), not
#     Debian (G-A3, Debian→Alpine pivot rev C)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
ALPINE="$REPO/bin/alpine-fde"
DEBIAN="$REPO/bin/debian-fde"

T=$(mktemp -d /tmp/debian-fde-aentry.XXXXXX)
trap 'rm -rf "$T"' EXIT
CMD=$T/cmd
mkdir -p "$CMD"

# stub: echo the forwarded args, nothing else
cat >"$CMD/status.sh" <<'EOF'
cmd_status_main() {
    printf 'STUB|ARGS=%s\n' "$*"
}
EOF

sp() {
    env -u DEBIAN_FDE_PROG -u DEBIAN_FDE_ROOT \
        DEBIAN_FDE_CONF="$T/absent.conf" \
        DEBIAN_FDE_CMD_DIR="$CMD" \
        "$@"
}

# --- entry point is executable ----------------------------------------------------
assert_eq "bin/alpine-fde is executable" "yes" "$([ -x "$ALPINE" ] && echo yes || echo no)"

# --- dispatch equivalence with bin/debian-fde --------------------------------------
out_a=$(sp "$ALPINE" --root /tmp/fake-root status a b)
rc_a=$?
out_d=$(sp "$DEBIAN" --root /tmp/fake-root status a b)
rc_d=$?
assert_contains "alpine-fde dispatch reaches the stub cmd" "$out_a" "STUB|ARGS=a b"
assert_eq "alpine-fde dispatch rc matches debian-fde" "$rc_d" "$rc_a"
assert_eq "alpine-fde stdout equivalent to debian-fde" "$out_d" "$out_a"

# --- banners reflect the INVOKED name ----------------------------------------------
out=$(sp "$ALPINE" --version)
assert_eq "--version prints the invoked name (alpine-fde)" "alpine-fde 0.1.0" "$out"
out=$(sp "$DEBIAN" --version)
assert_eq "--version prints the invoked name (debian-fde)" "debian-fde 0.1.0" "$out"

out=$(sp "$ALPINE" --help 2>&1)
assert_contains "usage header uses the invoked name" "$out" "Usage: alpine-fde"
assert_not_contains "alpine usage never claims to be debian-fde" "$out" "Usage: debian-fde"
out=$(sp "$DEBIAN" --help 2>&1)
assert_contains "debian usage keeps its own name" "$out" "Usage: debian-fde"

rc=0
out=$(sp "$ALPINE" __no_such_cmd__ 2>&1 >/dev/null) || rc=$?
assert_eq "unknown subcommand -> usage rc 2" "2" "$rc"
assert_contains "error banner uses the invoked name" \
    "$out" "alpine-fde: error: unknown subcommand: __no_such_cmd__"

# --- install help line describes the Alpine rootfs (G-A3) ---------------------------
out=$(sp "$ALPINE" --help 2>&1)
assert_contains "install help line says minimal Alpine rootfs (apk)" "$out" "minimal Alpine rootfs (apk)"
assert_not_contains "install help line no longer says Debian" "$out" "minimal Debian rootfs"

# --- config help line points at the Alpine conf path (§8.4) -------------------------
assert_contains "usage config line names /etc/alpine-fde/alpine-fde.conf" \
    "$out" "/etc/alpine-fde/alpine-fde.conf"
assert_not_contains "usage config line has no legacy /etc/debian-fde path" \
    "$out" "/etc/debian-fde/"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
