#!/usr/bin/env bash
# tests/unit/harness_standalone_blob_cleanup.sh — pins the STANDALONE-EXIT
# blob-cleanup contract (Wave-2 queue item 24 ext, 2026-09-25 ENOSPC
# follow-up).
#
# WHY. Commit 2b61e1f wired `harness-cleanup.sh prune-blobs` into
# tests/run-e2e.sh's `_run_one` finalize only — registry-path runs cleaned
# up, but a scenario invoked STANDALONE (`bash tests/e2e/sXX.sh`) never
# passed through the runner and kept its whole ~0.5-1.5 GB consumed-blob
# set; repeated standalone runs by parallel work lanes refilled
# tests/e2e/.runs to 17G and pushed the box to ENOSPC again. The fix arms
# the cleanup in the ONE lib every scenario sources at startup
# (tests/lib/assert.sh — `alpine_fde_exit_prune` + the chain-safe
# `alpine_fde_arm_exit_prune`, re-armed from every assertion outcome), and
# makes `prune-blobs` itself idempotent (`.blobs-pruned` marker) so the
# runner's later finalize call double-fires into a cheap no-op.
#
# HERMETICITY. No runner, no boots, zero writes to the real
# tests/e2e/.runs: each pin runs a FAKE scenario script in a mktemp sandbox
# that sources the REAL tests/lib/assert.sh, creates a run dir under a
# sandbox `.runs` dir full of fake blobs + evidence, and exits (pass / fail
# / with its own EXIT trap, mirroring the REFRESHER/swtpm_cleanup_all
# scenarios). The REAL tests/lib/harness-cleanup.sh is exercised directly
# for the prune-blobs side (marker, exemption).
#
# Contract pinned:
#   1. STANDALONE exit deletes the run dir's consumed blobs, keeps all
#      evidence, keeps the run dir, reports on STDERR only (stdout stays the
#      TAP/`RUNDIR` contract surface), and drops the `.blobs-pruned` marker.
#   2. A failing scenario's exit code passes through UNCHANGED (cleanup must
#      never alter it) and the cleanup still fires.
#   3. A scenario with its OWN EXIT trap (the `trap '...; swtpm_cleanup_all'
#      EXIT INT TERM` shape, installed AFTER the lib was sourced) keeps BOTH
#      handlers: the scenario's runs AND the blobs are cleaned (chain, not
#      clobber).
#   4. DOUBLE-FIRE: a second prune-blobs on the same dir is a cheap no-op —
#      marker present, prior tally re-reported ("blob item(s)"), nothing
#      deleted twice, rc 0.
#   5. STATE-CHAIN EXEMPTION: s00-bootstrap-*/s00b-enroll-* run dirs keep
#      their blobs on the standalone path AND on a direct prune-blobs call
#      (the exemption moved INTO the lib, keyed on the dir basename — the
#      standalone path has no scenario id).
#   6. ESCAPE HATCH: HARNESS_CLEANUP_KEEP_BLOBS=1 keeps blobs on the
#      standalone path and writes no marker.
#   7. DRY-RUN: HARNESS_CLEANUP_DRYRUN=1 reports WOULD, deletes nothing, and
#      writes NO marker (a dry-run leaves the dir exactly as found).
#   8. NO RUN DIR: sourcing assert.sh and exiting without ever creating a
#      run dir ($RUN unset) is a silent no-op — no cleanup output anywhere.
#
# RED/GREEN: against the pre-fix tree, 1/2/3/4/5/7 fail (assert.sh had no
# exit hook; prune-blobs had no marker and no basename exemption); 6 and 8
# pin the guards and pass before and after. The file exits nonzero while any
# pin fails.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REAL_ASSERT="$TESTS/lib/assert.sh"
REAL_CLEANUP="$TESTS/lib/harness-cleanup.sh"
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

assert_file_exists "assert lib under test present" "$REAL_ASSERT"
assert_file_exists "harness-cleanup lib under test present" "$REAL_CLEANUP"

SBX_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dfde-standalone-cln.XXXXXX")
cleanup() { rm -rf "$SBX_ROOT"; }
trap cleanup EXIT
trap 'trap - INT; kill -INT $$; exit 130' INT
trap 'trap - TERM; kill -TERM $$; exit 143' TERM
trap 'exit 129' HUP

RUNS="$SBX_ROOT/e2e/.runs"
mkdir -p "$RUNS"

# make_scenario <file> <dirname-prefix> [own-trap] — a fake standalone
# scenario: sources the REAL assert.sh, builds a realistic blob+evidence run
# dir under the SANDBOX .runs, optionally installs its own EXIT trap FIRST
# (the scenario-typical order: libs sourced, then the scenario's own trap —
# exactly the ordering that clobbers a naive source-time trap), then asserts
# once (the arming point) and exits with the given rc.
make_scenario() {
    local file=$1 prefix=$2 own_trap=${3:-}
    {
        printf '#!/usr/bin/env bash\n'
        printf '# fake standalone scenario (hermetic contract pin)\n'
        printf 'set -u\n'
        printf 'TESTS=%q\n' "$TESTS"
        printf 'source "$TESTS/lib/assert.sh"\n'
        printf 'RUN=%q\n' "$RUNS/$prefix-$(date +%s)-$$"
        printf '%s\n' \
            'mkdir -p "$RUN/tooling/opt" "$RUN/keys" "$RUN/phase1"' \
            'truncate -s 1m "$RUN/uki-unsigned.efi" "$RUN/esp.img" \' \
            '    "$RUN/disk.img" "$RUN/disk.img.prebootb" "$RUN/phase1/harness.efi"' \
            'truncate -s 1m "$RUN/tooling/opt/libcrypto.so.3"' \
            'printf "console line\n" >"$RUN/console.log"' \
            'printf "console line\n" >"$RUN/phase1/console-timed.log"' \
            'printf "root=UUID=x\n" >"$RUN/cmdline.txt"' \
            'printf "{}\n" >"$RUN/pcrsign.json"' \
            'printf "K\n" >"$RUN/keys/db.key"'
        if [[ "$own_trap" == "own-trap" ]]; then
            # the scenario-typical own EXIT trap (s05/s09/s12/s21 REFRESHER
            # shape), installed AFTER the lib was sourced — the chain must
            # survive this
            printf '%s\n' \
                'trap '"'"'printf "scenario-trap-ran\n" >"$RUN/.scenario-trap"'"'"' EXIT INT TERM'
        fi
        printf '%s\n' \
            'assert_eq "smoke" "one" "one"   # any assertion: the arming point' \
            'echo "RUNDIR $RUN"' \
            "exit \$SCEN_RC"
    } >"$file"
    chmod +x "$file"
}

# run_scenario <file> <out> <err> [rc] — standalone invocation, exactly what
# a work lane does: `bash tests/e2e/sXX.sh`
run_scenario() {
    ( cd "$SBX_ROOT" && SCEN_RC="${4:-0}" bash "$1" ) >"$2" 2>"$3"
}

newest_run_dir() {   # newest_run_dir <prefix>
    ls -dt "$RUNS"/"$1"-* 2>/dev/null | head -1
}

assert_cleaned() {   # assert_cleaned <label> <dir> — blobs gone, evidence kept
    local label=$1 dir=$2 f
    assert_file_exists "$label: run dir itself survives" "$dir"
    for f in uki-unsigned.efi esp.img disk.img disk.img.prebootb \
             phase1/harness.efi tooling/opt/libcrypto.so.3; do
        assert_rc "$label: consumed blob deleted: $f" 0 test ! -e "$dir/$f"
    done
    for f in console.log phase1/console-timed.log cmdline.txt pcrsign.json \
             keys/db.key; do
        assert_file_exists "$label: evidence retained: $f" "$dir/$f"
    done
}

assert_blobs_kept() {   # assert_blobs_kept <label> <dir>
    local label=$1 dir=$2 f
    for f in uki-unsigned.efi esp.img disk.img disk.img.prebootb \
             phase1/harness.efi tooling/opt/libcrypto.so.3 console.log; do
        assert_file_exists "$label: blob retained: $f" "$dir/$f"
    done
}

# =============================================================================
# Pin 1 — standalone PASS: cleanup fires at scenario exit, stderr-only report
# =============================================================================
S1="$SBX_ROOT/s1.sh"; make_scenario "$S1" "s12-lite"
run_scenario "$S1" "$SBX_ROOT/s1.out" "$SBX_ROOT/s1.err" 0
assert_eq "pin 1: standalone pass scenario exits 0" "0" "$?"
D1=$(newest_run_dir s12-lite)
assert_cleaned "pin 1" "$D1"
assert_contains "pin 1: cleanup reported on STDERR" "$(cat "$SBX_ROOT/s1.err")" "prune-blobs"
assert_rc "pin 1: stdout stays contract-clean (no harness-cleanup noise)" 0 \
    test -z "$(grep harness-cleanup "$SBX_ROOT/s1.out")"
assert_file_exists "pin 1: .blobs-pruned marker written by the pass" "$D1/.blobs-pruned"

# =============================================================================
# Pin 2 — standalone FAIL: exit code passes through unchanged, cleanup fires
# =============================================================================
S2="$SBX_ROOT/s2.sh"; make_scenario "$S2" "s04-unsigned"
run_scenario "$S2" "$SBX_ROOT/s2.out" "$SBX_ROOT/s2.err" 3
assert_eq "pin 2: failing scenario's exit code UNCHANGED by the cleanup" "3" "$?"
assert_cleaned "pin 2" "$(newest_run_dir s04-unsigned)"

# =============================================================================
# Pin 3 — scenario's OWN EXIT trap: chain, not clobber (both handlers run)
# =============================================================================
S3="$SBX_ROOT/s3.sh"; make_scenario "$S3" "s05-lite" own-trap
run_scenario "$S3" "$SBX_ROOT/s3.out" "$SBX_ROOT/s3.err" 0
assert_eq "pin 3: scenario with own EXIT trap exits 0" "0" "$?"
D3=$(newest_run_dir s05-lite)
assert_file_exists "pin 3: the scenario's own EXIT handler still ran" "$D3/.scenario-trap"
assert_cleaned "pin 3" "$D3"

# =============================================================================
# Pin 4 — DOUBLE-FIRE: a second prune-blobs is a cheap marker no-op
# =============================================================================
FIRE2=$(bash "$REAL_CLEANUP" prune-blobs "$D1" 2>&1)
assert_eq "pin 4: second prune-blobs exits 0" "0" "$?"
assert_contains "pin 4: second call says already pruned" "$FIRE2" "already pruned"
assert_contains "pin 4: no-op re-reports the prior pass tally" "$FIRE2" "blob item(s)"
assert_rc "pin 4: second call deleted nothing further (evidence intact)" 0 \
    test -e "$D1/console.log"

# =============================================================================
# Pin 5 — STATE-CHAIN EXEMPTION: s00-bootstrap-*/s00b-enroll-* blobs kept
# =============================================================================
S5A="$SBX_ROOT/s5a.sh"; make_scenario "$S5A" "s00-bootstrap"
run_scenario "$S5A" "$SBX_ROOT/s5a.out" "$SBX_ROOT/s5a.err" 0
assert_eq "pin 5a: s00-bootstrap standalone run exits 0" "0" "$?"
D5A=$(newest_run_dir s00-bootstrap)
assert_blobs_kept "pin 5a: s00-bootstrap blobs kept (standalone path)" "$D5A"
EXEMPT_OUT=$(bash "$REAL_CLEANUP" prune-blobs "$D5A" 2>&1)
assert_eq "pin 5a: direct prune-blobs exits 0 on an exempt dir" "0" "$?"
assert_contains "pin 5a: direct call names the state-chain exemption" \
    "$EXEMPT_OUT" "exempt"
assert_rc "pin 5a: direct call keeps s00 blobs too" 0 test -e "$D5A/esp.img"
S5B="$SBX_ROOT/s5b.sh"; make_scenario "$S5B" "s00b-enroll"
run_scenario "$S5B" "$SBX_ROOT/s5b.out" "$SBX_ROOT/s5b.err" 0
assert_eq "pin 5b: s00b-enroll standalone run exits 0" "0" "$?"
D5B=$(newest_run_dir s00b-enroll)
assert_blobs_kept "pin 5b: s00b-enroll blobs kept (standalone path)" "$D5B"

# =============================================================================
# Pin 6 — ESCAPE HATCH: HARNESS_CLEANUP_KEEP_BLOBS=1 keeps blobs standalone
# =============================================================================
S6="$SBX_ROOT/s6.sh"; make_scenario "$S6" "s07-lite"
( cd "$SBX_ROOT" && SCEN_RC=0 HARNESS_CLEANUP_KEEP_BLOBS=1 bash "$S6" ) \
    >"$SBX_ROOT/s6.out" 2>"$SBX_ROOT/s6.err"
assert_eq "pin 6: KEEP_BLOBS run exits 0 (hatch never breaks the run)" "0" "$?"
D6=$(newest_run_dir s07-lite)
assert_blobs_kept "pin 6: escape hatch keeps blobs (standalone path)" "$D6"
assert_rc "pin 6: hatch path writes NO marker (dir left as found)" 0 \
    test ! -e "$D6/.blobs-pruned"

# =============================================================================
# Pin 7 — DRY-RUN standalone: reports WOULD, deletes nothing, no marker
# =============================================================================
S7="$SBX_ROOT/s7.sh"; make_scenario "$S7" "s08-firmware"
( cd "$SBX_ROOT" && SCEN_RC=0 HARNESS_CLEANUP_DRYRUN=1 bash "$S7" ) \
    >"$SBX_ROOT/s7.out" 2>"$SBX_ROOT/s7.err"
assert_eq "pin 7: DRYRUN run exits 0" "0" "$?"
D7=$(newest_run_dir s08-firmware)
assert_contains "pin 7: dry-run says WOULD" "$(cat "$SBX_ROOT/s7.err")" "WOULD"
assert_blobs_kept "pin 7: dry-run deletes nothing" "$D7"
assert_rc "pin 7: dry-run writes NO marker" 0 test ! -e "$D7/.blobs-pruned"

# =============================================================================
# Pin 8 — NO RUN DIR: assert.sh alone must stay a silent no-op
# =============================================================================
cat >"$SBX_ROOT/s8.sh" <<EOF
#!/usr/bin/env bash
set -u
TESTS=$(printf '%q' "$TESTS")
source "\$TESTS/lib/assert.sh"
assert_eq "no run dir anywhere" "a" "a"
exit 0
EOF
( cd "$SBX_ROOT" && bash "$SBX_ROOT/s8.sh" ) >"$SBX_ROOT/s8.out" 2>"$SBX_ROOT/s8.err"
assert_eq "pin 8: lib-only script exits 0" "0" "$?"
assert_rc "pin 8: no harness-cleanup output when no run dir was created" 0 \
    test -z "$(grep harness-cleanup "$SBX_ROOT/s8.err" "$SBX_ROOT/s8.out")"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# harness_standalone_blob_cleanup: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
