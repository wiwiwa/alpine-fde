#!/usr/bin/env bash
# tests/lib/assert.sh — TAP-ish assertion helpers for the Alpine FDE harness.
#
# Usage: source tests/lib/assert.sh, then call the helpers. Each assertion
# prints `ok N - <name>` or `not ok N - <name> <detail>` and updates the
# counters $TESTS_PASS / $TESTS_FAIL. Safe to source from a test file AND
# from the runner (include guard prevents counter reset).
#
# Conventions:
#   assert_eq <name> <expected> <actual>
#   assert_ne <name> <a> <b>            # passes when a != b
#   assert_rc <name> <expected_rc> <cmd> [args...]   # output kept in $ASSERT_RC_OUTPUT
#
# assert_rc deliberately runs <cmd> in the CALLER's shell (no subshell), so
# commands that export variables or otherwise mutate the environment keep
# their side effects; combined output is captured into $ASSERT_RC_OUTPUT.
#   assert_contains <name> <haystack> <needle>
#   assert_not_contains <name> <haystack> <needle>
#   assert_file_exists <name> <path>

if [[ -n "${_ALPINE_FDE_ASSERT_SH_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_ASSERT_SH_SOURCED=1

export TESTS_PASS=0
export TESTS_FAIL=0
export ASSERT_RC_OUTPUT=""

# ---------------------------------------------------------------------------
# PER-SCENARIO CONSUMED-BLOB CLEANUP ON EXIT (Wave-2 queue item 24 ext,
# 2026-09-25 ENOSPC follow-up). Every e2e scenario sources this lib at
# startup, but until now only tests/run-e2e.sh's `_run_one` finalize called
# `harness-cleanup.sh prune-blobs` — a scenario invoked STANDALONE
# (`bash tests/e2e/sXX.sh`) never passed through the runner, so its run dir
# kept the whole ~0.5-1.5 GB consumed-blob set, and repeated standalone runs
# by parallel work lanes refilled tests/e2e/.runs to ENOSPC. So the shared
# lib arms the cleanup itself:
#
#   alpine_fde_arm_exit_prune   chain-safe (re)armer. A source-time `trap`
#                               alone would NOT survive: scenarios set their
#                               own EXIT traps AFTER sourcing this lib (the
#                               REFRESHER/swtpm_cleanup_all pattern), which
#                               replaces any handler registered here. So the
#                               armer prepends our handler to whatever EXIT
#                               handler currently exists, and is re-invoked
#                               from every _assert_result — the first
#                               assertion AFTER a scenario's own `trap` call
#                               re-chains us in front of it (idempotent:
#                               skips when the chain is already in place).
#   alpine_fde_exit_prune       the EXIT handler. No-op unless a run dir was
#                               actually created ($RUN set — the uniform
#                               scenario convention — under a `.runs` dir and
#                               existing); otherwise delegates to the REAL
#                               `prune-blobs` (no deletion logic duplicated
#                               here), report on STDERR so stdout stays the
#                               scenario's TAP/`RUNDIR` contract surface.
#
# Covered invocation paths: STANDALONE (the hole that caused the refill),
# registry `_run_one` (serial and -j workers alike — there the scenario exits
# first, so the runner's later call lands on prune-blobs' `.blobs-pruned`
# marker and is a cheap no-op), and anything else that exits the scenario
# process normally (SIGKILL remains unreachable by construction).
# Failure tolerance: the handler can never change the scenario's exit code
# (its own status is discarded, and bash preserves the pre-trap exit status).
alpine_fde_exit_prune() {
    local d="${RUN:-}" lib="${TESTS:-}/lib/harness-cleanup.sh"
    [[ -n "$d" && "$d" == /*.runs/* && -d "$d" && -f "$lib" ]] || return 0
    bash "$lib" prune-blobs "$d" 1>&2 || true
    return 0
}

alpine_fde_arm_exit_prune() {
    local cur body
    cur=$(trap -p EXIT 2>/dev/null) || return 0
    [[ "$cur" == *alpine_fde_exit_prune* ]] && return 0
    if [[ -z "$cur" ]]; then
        trap 'alpine_fde_exit_prune' EXIT
        return 0
    fi
    # Chain: ours first, then the pre-existing handler verbatim. `trap -p`
    # prints the handler single-quoted with the outer quotes stripped here —
    # an embedded single quote would come back `'\''`-escaped and NOT survive
    # this round-trip; every current scenario EXIT handler is quote-free
    # (`kill "$REFRESHER" ...; swtpm_cleanup_all ...` / a function name).
    body=${cur#trap -- \'}
    body=${body%\' EXIT}
    trap -- "alpine_fde_exit_prune
${body}" EXIT
}

# Internal: record + print one result. $1 ok|not-ok, $2 name, $3 detail.
_assert_result() {
    local status="$1" name="$2" detail="$3"
    if [[ "$status" == "ok" ]]; then
        TESTS_PASS=$((TESTS_PASS + 1))
        printf 'ok %d - %s\n' "$((TESTS_PASS + TESTS_FAIL))" "$name"
    else
        TESTS_FAIL=$((TESTS_FAIL + 1))
        printf 'not ok %d - %s %s\n' "$((TESTS_PASS + TESTS_FAIL))" "$name" "$detail"
    fi
    # (Re)arm the standalone-exit blob cleanup — cheap (one fork), idempotent;
    # this is the arming point that makes the chain survive scenarios setting
    # their own EXIT trap after sourcing this lib.
    alpine_fde_arm_exit_prune
}

assert_eq() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "expected [$expected], got [$actual]"
    fi
}

assert_ne() {
    local name="$1" a="$2" b="$3"
    if [[ "$a" != "$b" ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "both values are [$a]"
    fi
}

assert_rc() {
    local name="$1" expected_rc="$2" rc tmpout
    shift 2
    tmpout=$(mktemp)
    "$@" >"$tmpout" 2>&1
    rc=$?
    ASSERT_RC_OUTPUT=$(<"$tmpout")
    rm -f "$tmpout"
    if [[ "$rc" == "$expected_rc" ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "expected rc=$expected_rc, got rc=$rc; output: ${ASSERT_RC_OUTPUT:0:200}"
    fi
}

assert_contains() {
    local name="$1" haystack="$2" needle="$3"
    if [[ -z "$needle" ]]; then
        # An empty needle matches every haystack ([[ x == *""* ]] is always
        # true) — the classic shape is a fail-loud sentinel_of whose exit 64
        # dies inside the command substitution, leaving an empty needle.
        # Record not-ok instead of banking a vacuous pass.
        _assert_result not-ok "$name" "empty needle — vacuous pass refused"
    elif [[ "$haystack" == *"$needle"* ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "haystack does not contain [$needle]; haystack: ${haystack:0:200}"
    fi
}

assert_not_contains() {
    local name="$1" haystack="$2" needle="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "haystack must not contain [$needle]"
    fi
}

assert_file_exists() {
    local name="$1" path="$2"
    if [[ -e "$path" ]]; then
        _assert_result ok "$name" ""
    else
        _assert_result not-ok "$name" "file does not exist: $path"
    fi
}
