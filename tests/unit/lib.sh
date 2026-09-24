#!/bin/sh
# lib.sh — tiny assert helpers for Alpine FDE unit tests.
# Usage: source this file, run asserts, end with `finish`.

TEST_PASS=0
TEST_FAIL=0

_pass() {
    TEST_PASS=$((TEST_PASS + 1))
    printf 'ok: %s\n' "$1"
}

_fail() {
    TEST_FAIL=$((TEST_FAIL + 1))
    printf 'FAIL: %s\n' "$1"
}

# assert_eq <desc> <expected> <actual>
assert_eq() {
    if [ "$2" = "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (expected [$2], got [$3])"
    fi
}

# assert_rc <desc> <expected_rc> <actual_rc>
assert_rc() {
    if [ "$2" = "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (expected rc=$2, got rc=$3)"
    fi
}

# assert_contains <desc> <haystack> <needle>
assert_contains() {
    if [ -z "$3" ]; then
        _fail "$1 (empty needle — vacuous pass refused)"
        return 0
    fi
    case $2 in
        *"$3"*)
            _pass "$1"
            ;;
        *)
            _fail "$1 ([$2] does not contain [$3])"
            ;;
    esac
}

# finish — print summary; exit nonzero if any assert failed
finish() {
    printf -- '---- %d passed, %d failed ----\n' "$TEST_PASS" "$TEST_FAIL"
    [ "$TEST_FAIL" -eq 0 ]
}

return 0
