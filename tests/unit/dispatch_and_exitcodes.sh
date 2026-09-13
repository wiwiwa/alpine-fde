#!/bin/sh
# dispatch_and_exitcodes.sh — unit tests for bin/debian-fde dispatcher wiring and the
# exit-code contract end-to-end, using an injected DEBIAN_FDE_CMD_DIR with stub
# command files. No TPM, no real command implementations involved.

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)
SP="$REPO_ROOT/bin/debian-fde"

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

CMD="$tmp/cmd"
mkdir -p "$CMD"

cat >"$CMD/status.sh" <<'EOF'
# stub: report which env vars the dispatcher forwarded
cmd_status_main() {
    printf 'STUB status|ROOT=%s|TCTI=%s|YES=%s|DRY=%s|ESP=%s|DISK=%s|KEYDIR=%s|ARGS=%s\n' \
        "${DEBIAN_FDE_ROOT-}" "${DEBIAN_FDE_TCTI-}" "${DEBIAN_FDE_YES-}" "${DEBIAN_FDE_DRY_RUN-}" \
        "${DEBIAN_FDE_ESP-}" "${DEBIAN_FDE_DISK-}" "${DEBIAN_FDE_KEYDIR-}" "$*"
}
EOF

cat >"$CMD/rotate.sh" <<'EOF'
cmd_rotate_main() { return 5; }
EOF

cat >"$CMD/bootnext.sh" <<'EOF'
cmd_bootnext_main() { printf 'ENTRY=%s\n' "${1:-}"; }
EOF

cat >"$CMD/enroll-tpm.sh" <<'EOF'
# hyphenated subcommand: entry point must be cmd_enroll_tpm_main
cmd_enroll_tpm_main() { printf 'ENROLL-STUB\n'; }
EOF

: >"$CMD/provision.sh" # empty: no cmd_provision_main -> dispatcher must exit 3

# sp — run the dispatcher with a scrubbed environment and injected cmd dir
sp() {
    env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_ROOT -u DEBIAN_FDE_ESP -u DEBIAN_FDE_DISK \
        -u DEBIAN_FDE_KEYDIR -u DEBIAN_FDE_YES -u DEBIAN_FDE_DRY_RUN \
        DEBIAN_FDE_CONF="$tmp/absent.conf" \
        DEBIAN_FDE_CMD_DIR="$CMD" \
        "$SP" "$@"
}

# spc — like sp, but with an explicit config file as $1
spc() {
    _conf=$1
    shift
    env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_ROOT -u DEBIAN_FDE_ESP -u DEBIAN_FDE_DISK \
        -u DEBIAN_FDE_KEYDIR -u DEBIAN_FDE_YES -u DEBIAN_FDE_DRY_RUN \
        DEBIAN_FDE_CONF="$_conf" \
        DEBIAN_FDE_CMD_DIR="$CMD" \
        "$SP" "$@"
}

# --- --version / --help ---
rc=0
out=$(sp --version 2>/dev/null) || rc=$?
assert_rc "--version exits 0" "0" "$rc"
assert_contains "--version prints name and version" "$out" "debian-fde 0.1.0"

rc=0
out=$(sp --help 2>/dev/null) || rc=$?
assert_rc "--help exits 0" "0" "$rc"
assert_contains "--help goes to stdout with usage" "$out" "Usage:"
assert_contains "--help lists subcommands (provision)" "$out" "provision"
assert_contains "--help lists subcommands (pcrsign)" "$out" "pcrsign"
assert_contains "--help lists subcommands (doctor)" "$out" "doctor"

rc=0
out=$(sp -h 2>/dev/null) || rc=$?
assert_rc "-h alias exits 0" "0" "$rc"

# --- usage errors: exit 2, usage text on stderr ---
rc=0
out=$(sp 2>&1 >/dev/null) || rc=$?
assert_rc "no args exits 2" "2" "$rc"
assert_contains "no args prints usage to stderr" "$out" "Usage:"

rc=0
out=$(sp frobnicate 2>&1 >/dev/null) || rc=$?
assert_rc "unknown subcommand exits 2" "2" "$rc"
assert_contains "unknown subcommand named in error" "$out" "unknown subcommand: frobnicate"
assert_contains "unknown subcommand prints usage" "$out" "Usage:"

rc=0
out=$(sp --bogus status 2>&1 >/dev/null) || rc=$?
assert_rc "unknown option exits 2" "2" "$rc"
assert_contains "unknown option named in error" "$out" "unknown option: --bogus"

rc=0
out=$(sp --tcti 2>&1 >/dev/null) || rc=$?
assert_rc "option missing its value exits 2" "2" "$rc"
assert_contains "missing value named in error" "$out" "requires an argument"

# --- happy dispatch through a stub ---
rc=0
out=$(sp status) || rc=$?
assert_rc "stub subcommand exits with its rc" "0" "$rc"
assert_eq "stub sees clean env (no flags given)" \
    "STUB status|ROOT=|TCTI=|YES=|DRY=|ESP=|DISK=|KEYDIR=|ARGS=" "$out"

# --- global flags forwarded to the subcommand environment + arg passthrough ---
rc=0
out=$(sp --tcti swtpm --yes --dry-run --root /r --esp /e --disk /d --keydir /k status --init x) || rc=$?
assert_rc "flags + subcommand + args accepted" "0" "$rc"
assert_eq "global flags forwarded, extra args passed through" \
    "STUB status|ROOT=/r|TCTI=swtpm|YES=1|DRY=1|ESP=/e|DISK=/d|KEYDIR=/k|ARGS=--init x" "$out"

# --- subcommand exit status propagates ---
rc=0
out=$(sp rotate 2>/dev/null) || rc=$?
assert_rc "cmd exit status propagates (rotate -> 5)" "5" "$rc"

# --- positional arguments reach the command ---
out=$(sp bootnext Linux-rollback)
assert_eq "positional arg passthrough (bootnext)" "ENTRY=Linux-rollback" "$out"

# --- hyphenated subcommand maps to underscore function ---
out=$(sp enroll-tpm)
assert_eq "enroll-tpm routes to cmd_enroll_tpm_main" "ENROLL-STUB" "$out"

# --- not-implemented contract: exit 3, clean message ---
rc=0
out=$(sp provision 2>&1 >/dev/null) || rc=$?
assert_rc "cmd file without entry function -> exit 3" "3" "$rc"
assert_contains "missing entry function says not implemented" "$out" "not implemented"

rc=0
out=$(sp ukictl 2>&1 >/dev/null) || rc=$?
assert_rc "missing cmd file -> exit 3" "3" "$rc"
assert_contains "missing cmd file says not implemented" "$out" "not implemented"

rc=0
out=$(sp doctor 2>&1 >/dev/null) || rc=$?
assert_rc "doctor routes with same contract (stub absent -> exit 3)" "3" "$rc"

# --- pcrsign registration (G-B4): known subcommand, cmd file resolved from the
# --- INJECTED cmd dir. The stub dir has no pcrsign.sh, so the dispatcher must
# --- reach the not-implemented branch (3), not usage (2). The full pcrsign
# --- behavior lives in pcrsign_cli.sh.
rc=0
out=$(sp pcrsign 2>&1 >/dev/null) || rc=$?
assert_rc "pcrsign is registered (no stub cmd file -> exit 3, not 2)" "3" "$rc"
assert_contains "pcrsign missing cmd file says not implemented" "$out" "not implemented"

# --- config file feeds the subcommand environment; CLI flags beat the file ---
conf="$tmp/debian-fde.conf"
printf 'DEBIAN_FDE_ROOT=/fromconf\n# comment\n' >"$conf"
out=$(spc "$conf" status)
assert_contains "config file value reaches cmd env" "$out" "ROOT=/fromconf"

out=$(spc "$conf" --root /fromcli status)
assert_contains "explicit flag beats config file" "$out" "ROOT=/fromcli"

finish
