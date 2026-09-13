#!/bin/sh
# common_exitcodes.sh — unit tests for lib/common.sh: exit-code contract, logging,
# die(), strict_mode(), require_cmds(), config loader. No TPM required.

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/common.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- exit-code contract constants ---
assert_eq "DEBIAN_FDE_OK is 0" "0" "$DEBIAN_FDE_OK"
assert_eq "DEBIAN_FDE_DRIFT is 1" "1" "$DEBIAN_FDE_DRIFT"
assert_eq "DEBIAN_FDE_USAGE is 2" "2" "$DEBIAN_FDE_USAGE"
assert_eq "DEBIAN_FDE_NOT_IMPLEMENTED is 3" "3" "$DEBIAN_FDE_NOT_IMPLEMENTED"
assert_eq "DEBIAN_FDE_FAIL_CLOSED is 64" "64" "$DEBIAN_FDE_FAIL_CLOSED"

# --- sourcing the library is side-effect-free ---
assert_eq "sourcing common.sh does not enable strict mode" \
    "" "$(case $- in *e*) echo strict-enabled ;; esac)"

# --- logging: stderr only, prefixed ---
assert_eq "info stays off stdout" "" "$(info hi 2>/dev/null)"
assert_contains "info goes to stderr with prefix" "$(info hi 2>&1 >/dev/null)" "debian-fde: info: hi"
assert_contains "warn goes to stderr with prefix" "$(warn careful 2>&1 >/dev/null)" "debian-fde: warn: careful"
assert_contains "err goes to stderr with prefix" "$(err bad 2>&1 >/dev/null)" "debian-fde: error: bad"

# --- die ---
rc=0
msg=$(die boom 2>&1) || rc=$?
assert_rc "die exits fail-closed (64)" "64" "$rc"
assert_contains "die logs the message" "$msg" "boom"

rc=0
msg=$(die -r 2 usage-mistake 2>&1) || rc=$?
assert_rc "die -r overrides the exit code" "2" "$rc"
assert_contains "die -r still logs the message" "$msg" "usage-mistake"

# --- strict_mode ---
# NOTE: the probes below deliberately do NOT sit in a tested context (`|| rc=$?`,
# `if`, ...): shells suppress errexit inside the non-final branch of AND-OR lists,
# which would defeat the very behavior under test. rc is captured directly instead.
out=$(strict_mode; false; echo UNREACHED)
rc=$?
assert_rc "strict_mode: errexit stops at first failure" "1" "$rc"
assert_eq "strict_mode: nothing runs after the failure" "" "$out"

out=$(strict_mode; printf '%s' "$NO_SUCH_VAR_DEFINED_ANYWHERE") 2>/dev/null
rc=$?
assert_rc "strict_mode: unset variable expansion is fatal" "1" "$rc"
assert_eq "strict_mode: unset variable printed nothing" "" "$out"

# --- require_cmds ---
rc=0
require_cmds sh pwd >/dev/null 2>&1 || rc=$?
assert_rc "require_cmds passes for present commands" "0" "$rc"

rc=0
msg=$(require_cmds sh __no_such_binary_xyz 2>&1) || rc=$?
assert_rc "require_cmds dies fail-closed on missing command" "64" "$rc"
assert_contains "require_cmds names the missing command" "$msg" "__no_such_binary_xyz"

# --- config_path ---
assert_eq "config_path default" "/etc/debian-fde/debian-fde.conf" "$(DEBIAN_FDE_CONF='' config_path)"
assert_eq "config_path DEBIAN_FDE_CONF override" "/x/y.conf" "$(DEBIAN_FDE_CONF=/x/y.conf config_path)"

# --- load_config: missing file ---
rc=0
DEBIAN_FDE_CONF="$tmp/does-not-exist.conf" load_config || rc=$?
assert_rc "load_config missing file is a no-op success" "0" "$rc"

# --- load_config: parsing ---
conf="$tmp/debian-fde.conf"
{
    printf '# full-line comment\n'
    printf '\n'
    printf 'DEBIAN_FDE_TEST_A=hello\n'
    printf 'DEBIAN_FDE_TEST_B="quoted value"\n'
    printf "DEBIAN_FDE_TEST_C='single quoted'\n"
    printf 'DEBIAN_FDE_TEST_D=trailing ws stripped   \n'
    printf '   DEBIAN_FDE_TEST_E = spaced   \n'
    printf 'DEBIAN_FDE_TEST_F=has=equals\n'
    printf 'BAD-KEY=nope\n'
    printf '1BADKEY=nope\n'
    printf 'NOEQUALS\n'
} >"$conf"

errfile="$tmp/load.err"
out=$(DEBIAN_FDE_CONF="$conf" load_config >/dev/null 2>"$errfile"; printf '%s|%s|%s|%s|%s|%s' \
    "${DEBIAN_FDE_TEST_A-}" "${DEBIAN_FDE_TEST_B-}" "${DEBIAN_FDE_TEST_C-}" \
    "${DEBIAN_FDE_TEST_D-}" "${DEBIAN_FDE_TEST_E-}" "${DEBIAN_FDE_TEST_F-}")
assert_eq "load_config parses values, quotes, comments, spacing" \
    "hello|quoted value|single quoted|trailing ws stripped|spaced|has=equals" "$out"
assert_contains "load_config warns on invalid key (BAD-KEY)" "$(cat "$errfile")" "BAD-KEY"
assert_contains "load_config warns on invalid key (1BADKEY)" "$(cat "$errfile")" "1BADKEY"
assert_contains "load_config warns on line without '='" "$(cat "$errfile")" "NOEQUALS"

# --- load_config: environment wins over file ---
# explicit export: prefix-assignment persistence after a function call is not portable
out=$(export DEBIAN_FDE_CONF="$conf" DEBIAN_FDE_TEST_A=envwins; load_config; printf '%s' "${DEBIAN_FDE_TEST_A-}") 2>/dev/null
assert_eq "environment variable wins over config file" "envwins" "$out"


finish
