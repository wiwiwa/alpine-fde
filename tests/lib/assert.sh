#!/usr/bin/env bash
# tests/lib/assert.sh — TAP-ish assertion helpers for the Debian FDE harness.
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

if [[ -n "${_DEBIAN_FDE_ASSERT_SH_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_ASSERT_SH_SOURCED=1

export TESTS_PASS=0
export TESTS_FAIL=0
export ASSERT_RC_OUTPUT=""

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
