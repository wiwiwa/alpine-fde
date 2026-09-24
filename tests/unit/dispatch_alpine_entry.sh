#!/usr/bin/env bash
# tests/unit/dispatch_alpine_entry.sh — bin/alpine-fde entry-point contract (§8.1):
#   * bin/alpine-fde is THE product entrance (executable; the retired
#     bin/debian-fde alias is dropped, no compat shim) and dispatches on a
#     stub cmd dir via ALPINE_FDE_CMD_DIR
#   * usage/--version/error banners say "alpine-fde"
#   * the install help line describes the minimal Alpine rootfs (apk), not
#     Debian (G-A3, Debian→Alpine pivot rev C)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
ALPINE="$REPO/bin/alpine-fde"

T=$(mktemp -d /tmp/alpine-fde-aentry.XXXXXX)
trap 'rm -rf "$T"' EXIT
CMD=$T/cmd
mkdir -p "$CMD"

# stub: echo the forwarded args, nothing else
cat >"$CMD/status.sh" <<'STUBEOF'
cmd_status_main() {
    printf 'STUB|ARGS=%s\n' "$*"
}
STUBEOF

sp() {
    env -u ALPINE_FDE_PROG -u ALPINE_FDE_ROOT \
        ALPINE_FDE_CONF="$T/absent.conf" \
        ALPINE_FDE_CMD_DIR="$CMD" \
        "$@"
}

# --- entry point is executable ----------------------------------------------------
assert_eq "bin/alpine-fde is executable" "yes" "$([ -x "$ALPINE" ] && echo yes || echo no)"

# --- the retired debian-fde entrance is gone (alias dropped, §8.1) ------------------
assert_eq "bin/debian-fde no longer exists (no compat shim)" "yes" \
    "$([ -e "$REPO/bin/debian-fde" ] && echo no || echo yes)"

# --- dispatch reaches the stub cmd --------------------------------------------------
out=$(sp "$ALPINE" --root /tmp/fake-root status a b)
rc=$?
assert_contains "alpine-fde dispatch reaches the stub cmd" "$out" "STUB|ARGS=a b"
assert_eq "alpine-fde dispatch rc 0" "0" "$rc"

# --- banners say alpine-fde ---------------------------------------------------------
out=$(sp "$ALPINE" --version)
assert_eq "--version prints alpine-fde" "alpine-fde 0.1.0" "$out"

out=$(sp "$ALPINE" --help 2>&1)
assert_contains "usage header says alpine-fde" "$out" "Usage: alpine-fde"
assert_not_contains "usage never claims the retired debian-fde name" "$out" "debian-fde"

rc=0
out=$(sp "$ALPINE" __no_such_cmd__ 2>&1 >/dev/null) || rc=$?
assert_eq "unknown subcommand -> usage rc 2" "2" "$rc"
assert_contains "error banner says alpine-fde" \
    "$out" "alpine-fde: error: unknown subcommand: __no_such_cmd__"

# --- install help line describes the Alpine rootfs (G-A3) ---------------------------
assert_contains "install help line says minimal Alpine rootfs (apk)" "$out" "minimal Alpine rootfs (apk)"
assert_not_contains "install help line no longer says Debian" "$out" "minimal Debian rootfs"

# --- config help line points at the Alpine conf path (§8.4) -------------------------
assert_contains "usage config line names /etc/alpine-fde/alpine-fde.conf" \
    "$out" "/etc/alpine-fde/alpine-fde.conf"
assert_not_contains "usage config line has no legacy /etc/debian-fde path" \
    "$out" "/etc/debian-fde/"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
