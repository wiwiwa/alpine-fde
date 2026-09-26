#!/usr/bin/env bash
# tests/run-integration.sh — run tests/integration/*.sh in parallel (default
# jobs: nproc) and print a TAP-ish summary. Exits nonzero if any assertion or
# test file failed. A file that exits 0 while emitting ZERO assertions is
# itself a failure (vacuous pass), and a run that observes no assertions at
# all (1..0) fails.
#
# Same runner semantics as tests/run-unit.sh; this tier owns the HEAVY suites
# (swtpm daemon spawns, real ukify/sbsign artifact builds, live-seal chains,
# qemu/serial harness drills) that must not sit on the sub-second unit lane.
#
# Usage: tests/run-integration.sh [-j <jobs>] [pattern]
#   -j, --jobs: number of parallel jobs (default: nproc, or ALPINE_FDE_TEST_JOBS)
#   pattern: optional glob matched against integration test filenames (default '*')

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

JOBS="${ALPINE_FDE_TEST_JOBS:-$(nproc 2>/dev/null || echo 4)}"
PATTERN="*"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        -j*)
            JOBS="${1#-j}"
            shift
            ;;
        *)
            PATTERN="$1"
            shift
            ;;
    esac
done

if ! [[ "$JOBS" =~ ^[0-9]+$ ]] || (( JOBS < 1 )); then
    JOBS=1
fi

INTEGRATION_DIR="$HERE/integration"
# compgen -G, NOT pathname expansion: a word without wildcard chars is never
# subject to nullglob (it stays a literal path and rc-127s below), while
# compgen matches the word as a glob either way — so a non-matching pattern
# yields an empty list and the clean no-input exit class.
mapfile -t TEST_FILES < <(compgen -G "$INTEGRATION_DIR/$PATTERN.sh")
# Library files (sourced by tests, never executed) are not tests.
TEST_FILES=(${TEST_FILES[@]%%*/lib.sh})

if (( ${#TEST_FILES[@]} == 0 )); then
    echo "run-integration: no test files matching $INTEGRATION_DIR/$PATTERN.sh" >&2
    exit 66   # EX_NOINPUT
fi

TMP_OUT=$(mktemp -d /tmp/alpine-fde-run-integration.XXXXXX)
cleanup() {
    local pids
    pids=$(jobs -p 2>/dev/null)
    [[ -n "$pids" ]] && kill $pids 2>/dev/null
    rm -rf "$TMP_OUT"
}
trap cleanup EXIT INT TERM

# Run test files in parallel up to JOBS concurrency
running=0
for i in "${!TEST_FILES[@]}"; do
    t="${TEST_FILES[$i]}"
    (
        trap - INT SIGQUIT
        bash "$t" >"$TMP_OUT/$i.out" 2>&1
        echo $? >"$TMP_OUT/$i.rc"
    ) &
    (( running++ ))
    if (( running >= JOBS )); then
        wait -n
        (( running-- ))
    fi
done
wait

FILE_FAILS=0
for i in "${!TEST_FILES[@]}"; do
    t="${TEST_FILES[$i]}"
    name=$(basename "$t")
    echo "# --- $name"
    out=$(cat "$TMP_OUT/$i.out" 2>/dev/null || true)
    rc=$(cat "$TMP_OUT/$i.rc" 2>/dev/null || echo 1)
    printf '%s\n' "$out"
    # Aggregate this file's assertion counters from its output. Two house
    # styles coexist: TAP ("ok N - name" / "not ok N - name") from tests/lib/
    # and lib.sh's "ok: name" / "FAIL: name". Count both. A TAP skip marker
    # ("ok ... # SKIP") counts as a pass — a gated suite that loudly skips is
    # a pass, not a vacuous one.
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
    echo "# run-integration: no assertions observed across ${#TEST_FILES[@]} file(s) — vacuous run" >&2
    exit 1
fi
echo "# pass=$TESTS_PASS fail=$TESTS_FAIL files=$FILE_FAILS"
(( TESTS_FAIL == 0 && FILE_FAILS == 0 )) || exit 1
exit 0
