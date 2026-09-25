#!/usr/bin/env bash
# tests/unit/s20_canary_serial_guard.sh — serial-corruption guard contract for
# s20-raid1-member-loss.sh's end-to-end canary read-back (assertion
# "[phase 3b] canary intact end-to-end"). HERMETIC: no qemu, no boots — the
# scenario artifact is pinned by content (run_e2e_parallel_contract.sh RED-
# mutation idiom; greps, never executes, the scenario).
#
# Bug this pins (runs 1790321112 solo + registry results-20260925T063641Z):
# the canary hash traveled as ONE exact-text labeled emission over the lossy
# TCG serial console. A doubled-byte burst either garbled the label
# ("CANARY-SHAA 80fc…" — parse produced []) or landed INSIDE the hash
# ("…c66f4 4f4663…" — the [0-9a-f]{64} slice returned shifted garbage), and
# assertion 63 compared that garbage. The scenario already carries corruption
# guards for the same class (R2RC, RDG legs) — the canary legs had none.
#
# Pinned invariants:
#   G1  the EXPECTED hash is host ground truth: computed from the
#       deterministic canary content on the HOST — a lossy console capture
#       must never define the expectation (no CANARY_SHA=$(grep …console…)).
#   G2  the bootstrap write leg emits the hash TWICE in independent textures
#       (labeled + BARE 64-hex line), and the scenario asserts the console
#       CONTAINS the host ground truth (corroboration the write ran as
#       intended) instead of deriving the expectation from it.
#   G3  the phase-2 read leg has a bare re-derivation retry (compact payload,
#       own sentinel, wait_console_soft) and the parse accepts EITHER a bare
#       64-hex line or a CANARY-labeled line (label-garble tolerant).
#   G4  the phase-3b read leg has the same bare re-derivation retry, and the
#       acceptance check matches the host ground truth against the CANDIDATE
#       SET of well-formed live reads (whichever well-formed emission landed
#       — never a single sliced slice of one possibly-garbled line).
#
# RED-first: before the fix, G1/G2/G3/G4 fail against the unguarded scenario.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

SCENARIO="$TESTS/e2e/s20-raid1-member-loss.sh"
assert_file_exists "s20 scenario present" "$SCENARIO"
assert_rc "s20 scenario: bash -n clean" 0 bash -n "$SCENARIO"
SC=$(cat "$SCENARIO")

# --- G1: expected value is HOST ground truth, never a console capture --------
assert_contains "G1: CANARY_SHA computed host-side from the deterministic content" "$SC" \
    'CANARY_SHA=$(printf'
assert_not_contains "G1: CANARY_SHA never derived from the (lossy) console capture" "$SC" \
    'CANARY_SHA=$(grep'

# --- G2: bootstrap double emission + corroboration (not derivation) ----------
assert_contains "G2: bootstrap write leg emits a BARE 64-hex line too" "$SC" \
    'sha256sum /btop/@/canary.txt | cut -d" " -f1'
assert_contains "G2: bootstrap console CORROBORATES host ground truth (containment)" "$SC" \
    'bootstrap: canary written as intended'

# --- G3: phase 2 bare re-derivation retry + tolerant parse -------------------
assert_contains "G3: phase-2 bare re-derivation leg present (own sentinel)" "$SC" \
    'P2C-52-DONE'
assert_contains "G3: phase-2 parse reads bare 64-hex lines (label-garble tolerant)" "$SC" \
    'P2_CANARY_CANDS'
assert_contains "G3: phase-2 canary check matches host truth against candidate set" "$SC" \
    '[phase 2] canary intact on the degraded pool (raid1 data readable)" \
    "$P2_CANARY_CANDS" "$CANARY_SHA"'

# --- G4: phase 3b bare re-derivation retry + candidate-set acceptance ---------
assert_contains "G4: phase-3b bare re-derivation leg present (own sentinel)" "$SC" \
    'C3B-50-DONE'
assert_contains "G4: phase-3b re-derivation soft-waited (corruption guard idiom)" "$SC" \
    'wait_console_soft "$P3B" "C3B-50-DONE"'
assert_contains "G4: phase-3b parse reads bare 64-hex lines (label-garble tolerant)" "$SC" \
    'P3B_CANARY_CANDS'
assert_contains "G4: acceptance check matches host truth against candidate set" "$SC" \
    '[phase 3b] canary intact end-to-end (raid1 rebuild acceptance check)" \
    "$P3B_CANARY_CANDS" "$CANARY_SHA"'

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# s20_canary_serial_guard: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
