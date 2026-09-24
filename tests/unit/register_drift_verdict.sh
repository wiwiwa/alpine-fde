#!/usr/bin/env bash
# tests/unit/register_drift_verdict.sh — fixture_drift_verdict (tests/lib/
# swtpm-fixture.sh): the s00b boot-B register-drift trigger in the DIGEST-
# ANCHORED enroll era. Since Option A (lib/cmd/enroll-tpm.sh) the CLI compares
# the pcrsig entry's recorded d7 against baseline.expected_pcr7 with NO live
# TPM read and can enroll rc 0 over a drifted register (fail-at-unseal
# replaces fail-at-seal, unit-pinned in enroll_precondition_matrix.sh 9b) —
# so the harness's §9.4 accept/vote machinery must fire on the HARNESS-side
# comparison. Regression pinned here (2026-09-24 registry red): the ADR-16
# rekey class (release-key floor reissue + varstore rebuild AFTER the baseline
# was finalized — the db cert is measured into PCR 7) shifts live PCR 7 while
# the CLI succeeds rc 0; the verdict must be "amend" (single faithful full-
# mode reading), not the old marker-only "no drift" that left boot C's
# PolicyPCR refusing the standing token.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"

# the two live-observed register modes (run s00b-enroll-1790225093)
D0_FULL="8bbb4647faf3336767a28f9799b8aa76eaeb61591ce5da88ca4da03f8782f6a2"
D0_TRUNC="2152c1552152c1552152c1552152c1552152c1552152c1552152c1552152c155"
D7_BASE="f663b572a3b8fbb4243d3cb759a5263d180301d556934f7f6adb3507609a87ec"
D7_LIVE="a2e9ed6c97f16f7a8c4af0266dcfb9d3fca973b0b2e3402cd09631ffc40c3772"

v() {   # v <rc> <marker> <d0> <d7> <rekeyed> — bl fixed to (D0_FULL, D7_BASE)
    fixture_drift_verdict "$1" "$2" "$3" "$4" "$D0_FULL" "$D7_BASE" "$5"
}

# --- legacy live-read oracle: the CLI's own "PCR 7 drift" marker -------------
assert_eq "legacy marker -> vote (rc != 0, the pre-Option-A shape)" \
    "vote" "$(v 2 1 "$D0_FULL" "$D7_LIVE" 0)"
assert_eq "legacy marker -> vote (even rc 0 — marker is authoritative)" \
    "vote" "$(v 0 1 "$D0_FULL" "$D7_LIVE" 1)"

# --- no drift ----------------------------------------------------------------
assert_eq "healthy enroll: live d7 == baseline -> none" \
    "none" "$(v 0 0 "$D0_FULL" "$D7_BASE" 0)"
assert_eq "rc != 0 without the legacy marker -> none (assertions report)" \
    "none" "$(v 2 0 "$D0_FULL" "$D7_LIVE" 0)"
assert_eq "unreadable readback (empty d7) -> none (cannot judge)" \
    "none" "$(v 0 0 "$D0_FULL" "" 1)"
assert_eq "unreadable readback (garbage d0) -> none" \
    "none" "$(v 0 0 "nope" "$D7_LIVE" 1)"

# --- THE regression: digest-anchored enroll rc 0 over a rekeyed varstore -----
assert_eq "rekey class: rc 0 + live d7 drifted + PCR 0 full == baseline -> amend" \
    "amend" "$(v 0 0 "$D0_FULL" "$D7_LIVE" 1)"
# PCR 11 is not a verdict input: verified live (run s00b-enroll-1790225093),
# boot B/C's postphase PCR 11 == the sealed d11 while only PCR 7 diverged

# --- ambiguous modes keep the 3-reading majority vote ------------------------
assert_eq "drift WITHOUT rekey, full-mode d0 -> vote (unknown provenance)" \
    "vote" "$(v 0 0 "$D0_FULL" "$D7_LIVE" 0)"
assert_eq "rekeyed but TRUNCATED d0 (bimodal degraded register) -> vote" \
    "vote" "$(v 0 0 "$D0_TRUNC" "$D7_LIVE" 1)"

if (( TESTS_FAIL == 0 )); then
    echo "# register_drift_verdict: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# register_drift_verdict: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
