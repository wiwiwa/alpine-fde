#!/usr/bin/env bash
# tests/run-unit.sh — run every tests/unit/*.sh sequentially and print a
# TAP-ish summary. Exits nonzero if any assertion or test file failed.
# A file that exits 0 while emitting ZERO assertions is itself a failure
# (vacuous pass), and a run that observes no assertions at all (1..0) fails.
#
# Usage: tests/run-unit.sh [pattern]
#   pattern: optional glob matched against unit test filenames (default '*')

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

PATTERN="${1:-*}"
UNIT_DIR="$HERE/unit"
# compgen -G, NOT pathname expansion: a word without wildcard chars is never
# subject to nullglob (it stays a literal path and rc-127s below), while
# compgen matches the word as a glob either way — so a non-matching pattern
# yields an empty list and the clean no-input exit class.
mapfile -t TEST_FILES < <(compgen -G "$UNIT_DIR/$PATTERN.sh")
# Library files (sourced by tests, never executed) are not tests.
TEST_FILES=(${TEST_FILES[@]%%*/lib.sh})

if (( ${#TEST_FILES[@]} == 0 )); then
    echo "run-unit: no test files matching $UNIT_DIR/$PATTERN.sh" >&2
    exit 66   # EX_NOINPUT
fi

FILE_FAILS=0
for t in "${TEST_FILES[@]}"; do
    name=$(basename "$t")
    echo "# --- $name"
    out=$(bash "$t" 2>&1)
    rc=$?
    printf '%s\n' "$out"
    # Aggregate this file's assertion counters from its output. Two house
    # styles coexist: TAP ("ok N - name" / "not ok N - name") from tests/lib/
    # and lib.sh's "ok: name" / "FAIL: name". Count both.
    p=$(grep -cE '^ok([: ]|$)' <<<"$out" || true)
    f=$(grep -cE '^(not ok|FAIL:)' <<<"$out" || true)
    TESTS_PASS=$((TESTS_PASS + p))
    TESTS_FAIL=$((TESTS_FAIL + f))
    if (( rc != 0 )) && (( f == 0 )); then
        # File failed without emitting a not-ok line (crash, set -e, bad exit).
        TESTS_FAIL=$((TESTS_FAIL + 1))
        FILE_FAILS=$((FILE_FAILS + 1))
        echo "not ok $((TESTS_PASS + TESTS_FAIL)) - $name exited rc=$rc without a TAP failure" \
            | sed 's/^/# /'
    fi
    if (( rc == 0 )) && (( p == 0 && f == 0 )); then
        # Vacuous pass: the file exited clean but asserted nothing. A runner
        # that lets this exit 0 makes silent test rot invisible.
        TESTS_FAIL=$((TESTS_FAIL + 1))
        FILE_FAILS=$((FILE_FAILS + 1))
        echo "not ok $((TESTS_PASS + TESTS_FAIL)) - $name emitted no assertions (vacuous pass)" \
            | sed 's/^/# /'
    fi
    if grep -q '^not ok ' <<<"$out"; then
        FILE_FAILS=$((FILE_FAILS + 1))
    fi
done

TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
if (( TOTAL == 0 )); then
    echo "# run-unit: no assertions observed across ${#TEST_FILES[@]} file(s) — vacuous run" >&2
    exit 1
fi
echo "# pass=$TESTS_PASS fail=$TESTS_FAIL files=$FILE_FAILS"
(( TESTS_FAIL == 0 && FILE_FAILS == 0 )) || exit 1
exit 0
