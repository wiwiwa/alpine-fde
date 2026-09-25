#!/usr/bin/env bash
# tests/unit/harness_run_dir_cleanup_contract.sh — pins the per-scenario BLOB
# CLEANUP contract of tests/run-e2e.sh + tests/lib/harness-cleanup.sh
# (Wave-2 queue item 24: "should the disk image be removed after each test
# case?" -> YES; consumed input blobs are deleted at each scenario's
# completion, evidence is kept).
#
# WHY. A scenario run dir holds ~0.5-1.5 GB of CONSUMED input blobs (uki-*.efi
# @~107-111 MB each, harness.efi, measure-throwaway.efi, initrd.cpio, esp.img,
# disk.img + the disk.img.prebootb restore copy, pcrsig *.img, unpacked
# tooling trees). PRUNE_CAP_MB cannot bound a live wave (prune-runs only runs
# at registry start/exit/_print_done and its fresh-window exempts in-flight
# dirs), so peak .runs == the whole wave's working set and a killed registry
# strands all of it (two ENOSPC-killed runs, 2026-09-25). The fix: after the
# result fragment is written (so the dir is never cleaned before its row
# exists), the runner deletes the scenario's consumed blobs in place.
#
# HERMETICITY. tests/run-e2e.sh is READ-ONLY here — it runs from a mktemp
# SANDBOX copy that is byte-identical to the real file. Leaf deps are stubbed
# (env-check.sh, lib/qemu.sh, the three harness self-tests, the G-T11b
# artifact scan) and scenarios are stub s*-* scripts that create a run dir
# full of fake blobs, print `RUNDIR <dir>` and exit — NO qemu, NO swtpm, NO
# boots, zero writes to the real tests/e2e/.runs. lib/harness-cleanup.sh is
# the REAL file (it is the other half of the unit under test), reached
# through a shim that no-ops only the process-killing `sweep` (a unit test
# must never kill real processes) and pins RUNS_DIR to the sandbox .runs.
#
# Contract pinned:
#   1. Serial path, PASS: after the runner finalizes a scenario its run dir
#      has NO consumed blobs left (uki-*.efi, esp.img, disk.img,
#      disk.img.prebootb, phase copies, the unpacked tooling tree) while ALL
#      evidence survives (console*.log, *.txt, *.json state, keys/, phase
#      logs, the run dir itself).
#   2. FAIL path: a scenario that exits nonzero gets the same cleanup (the
#      runner finalizes fail rows too).
#   3. State-chain exemption: s00/s00b run dirs are the producers every
#      consumer snapshots from (ALPINE_FDE_E2E_STATE) and what the G-T11b
#      artifact scan reads post-run — their blobs are NEVER cleaned, pass or
#      fail.
#   4. Worker path (-j > 1): the cleanup fires from the parallel finalize
#      path too, for pass AND fail rows.
#   5. Escape hatch: HARNESS_CLEANUP_KEEP_BLOBS=1 disables the cleanup
#      wholesale (debugging aid) — blobs survive, run still succeeds.
#   6. prune-blobs self-defense (direct calls on the real library): refuses
#      paths that are not under a `.runs` dir; HARNESS_CLEANUP_DRYRUN=1
#      reports without deleting.
#
# RED/GREEN: against the pre-fix runner every pin in 1/2/4 fails (the blobs
# survive); 3/5/6 pass before and after (they pin the guards, not the
# cleanup). The file exits nonzero while any pin fails.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REAL_RUNNER="$TESTS/run-e2e.sh"
REAL_CLEANUP="$TESTS/lib/harness-cleanup.sh"
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

# --- part 0: preconditions -------------------------------------------------------
assert_file_exists "runner under test present" "$REAL_RUNNER"
assert_file_exists "harness-cleanup library under test present" "$REAL_CLEANUP"
assert_file_exists "assert lib present" "$TESTS/lib/assert.sh"
assert_rc "jq available (results-JSON checks)" 0 command -v jq
assert_rc "truncate available (hermetic fake blobs)" 0 command -v truncate

SBX_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dfde-blobcln.XXXXXX")
AVAIL_KB=$(df -Pk "$SBX_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')
assert_rc "sandbox filesystem headroom: >= 256 MB free (got ${AVAIL_KB:-?} KB)" \
    0 test "${AVAIL_KB:-0}" -ge 262144
cleanup() { rm -rf "$SBX_ROOT"; }
trap cleanup EXIT
trap 'trap - INT; kill -INT $$; exit 130' INT
trap 'trap - TERM; kill -TERM $$; exit 143' TERM
trap 'exit 129' HUP

# build_sandbox <dir> — runner copy + REAL harness-cleanup (sweep-shimmed) +
# stubbed leaf deps + blob-creating stub scenarios
build_sandbox() {
    local sbx=$1
    mkdir -p "$sbx/e2e" "$sbx/lib" "$sbx/unit" "$sbx/ctl"
    cp "$REAL_RUNNER" "$sbx/run-e2e.sh"
    chmod +x "$sbx/run-e2e.sh"
    # the REAL cleanup library, verbatim — the shim below is the ONLY wrapper
    cp "$REAL_CLEANUP" "$sbx/lib/harness-cleanup.real.sh"
    cmp -s "$REAL_CLEANUP" "$sbx/lib/harness-cleanup.real.sh" || {
        echo "harness_run_dir_cleanup_contract: failed to copy $REAL_CLEANUP" >&2
        exit 97
    }
    cp "$TESTS/lib/stage-timing.sh" "$sbx/lib/stage-timing.sh"
    # shim: sweep (process kills) and disk-state (real-disk noise) are the
    # only entries a unit test must not run for real; everything else —
    # prune-blobs, prune-runs, registry-exit — delegates to the real file,
    # with RUNS_DIR pinned to the sandbox .runs by run_registry below.
    cat >"$sbx/lib/harness-cleanup.sh" <<EOF
#!/usr/bin/env bash
# contract-test shim: delegate to the REAL library, minus process sweeps
REAL="$sbx/lib/harness-cleanup.real.sh"
case "\${1:-}" in
    sweep|disk-state) exit 0 ;;
    *) exec bash "\$REAL" "\$@" ;;
esac
EOF
    chmod +x "$sbx/lib/harness-cleanup.sh"

    cat >"$sbx/env-check.sh" <<'EOF'
#!/usr/bin/env bash
# contract-test stub: environment gate always passes
exit 0
EOF
    cat >"$sbx/lib/qemu.sh" <<'EOF'
#!/usr/bin/env bash
# contract-test stub: no KVM probe — deterministic accel for the results JSON
qemu_accel() { printf '%s' kvm; }
EOF
    local selftest
    for selftest in e2e_infra_smoke swtpm_fixture_smoke swtpm_proxy_data_plane; do
        printf '#!/usr/bin/env bash\n# contract-test stub (no swtpm/infra)\necho "ok 1 - stub %s"\nexit 0\n' \
            "$selftest" >"$sbx/unit/$selftest.sh"
    done
    printf '#!/usr/bin/env bash\n# contract-test stub: G-T11b artifact scan (no state to scan)\necho "ok 1 - stub artifact scan"\nexit 0\n' \
        >"$sbx/e2e/e2e_infra_smoke.sh"
    chmod +x "$sbx/env-check.sh" \
        "$sbx/lib/qemu.sh" \
        "$sbx/unit/"e2e_infra_smoke.sh "$sbx/unit/"swtpm_fixture_smoke.sh \
        "$sbx/unit/"swtpm_proxy_data_plane.sh \
        "$sbx/e2e/e2e_infra_smoke.sh"

    # blob-creating stub scenarios for one chain-producer id (s00) and three
    # independent ids (s04/s05 run in the wave; s12 for the serial run)
    local id file
    for id in s00 s00b s04 s05 s12; do
        case "$id" in
            s00)  file=s00-bootstrap-lite.sh ;;
            s00b) file=s00b-enroll-cache.sh ;;
            s04)  file=s04-unsigned-uki.sh ;;
            s05)  file=s05-sb-off.sh ;;
            s12)  file=s12-wrong-passphrase.sh ;;
        esac
        cat >"$sbx/e2e/$file" <<'STUB'
#!/usr/bin/env bash
# contract-test stub scenario: builds a realistic run-dir blob set, prints
# RUNDIR like every real scenario does, then passes or fails on demand
set -u
id=${0##*/}; id=${id%%-*}
runs=${PAR_CLN_RUNS:?PAR_CLN_RUNS unset}
run="$runs/$(printf '%s-stub-%s' "$id" "$(date +%s)")"
mkdir -p "$run/phase1" "$run/keys" "$run/tooling/opt"
# the consumed-blob classes observed live (sizes are fake; classes are real)
truncate -s 1m "$run/uki-unsigned.efi" "$run/esp.img" "$run/disk.img" \
    "$run/disk.img.prebootb" "$run/phase1/harness.efi"
truncate -s 1m "$run/tooling/opt/libcrypto.so.3"
# the evidence classes that must survive the cleanup
printf 'console line\n' >"$run/console-b1.log"
printf 'console line\n' >"$run/phase1/console.log"
printf 'console-timed line\n' >"$run/phase1/console-timed.log"
printf 'root=UUID=x\n' >"$run/cmdline.txt"
printf 'PRETTY_NAME=stub\n' >"$run/os-release.txt"
printf '0123456789abcdef\n' >"$run/pcr11-measure.txt"
printf '{"expected_pcr7": "x"}\n' >"$run/pcrsign.json"
printf 'K\n' >"$run/keys/db.key"
kind_var="PAR_CLN_KIND_${id}"
kind=${!kind_var:-pass}
case "$kind" in
    fail)
        echo "not ok 1 - stub $id blew up"
        echo "RUNDIR $run"
        exit 3
        ;;
    *)
        echo "ok 1 - stub $id"
        echo "RUNDIR $run"
        ;;
esac
STUB
        chmod +x "$sbx/e2e/$file"
    done
}

# run_registry <sbx> <stdout-file> <stderr-file> [runner args...]
run_registry() {
    local sbx=$1 outf=$2 errf=$3
    shift 3
    (
        cd "$sbx" || exit 97
        export PAR_CLN_RUNS="$sbx/e2e/.runs"
        export HARNESS_CLEANUP_RUNS_DIR="$sbx/e2e/.runs"   # prune-runs stays hermetic
        export TMPDIR="$sbx/ctl"
        export ALPINE_FDE_E2E_TMP_MIN_FREE_MB=64
        bash ./run-e2e.sh "$@"
    ) >"$outf" 2>"$errf"
}

export_kinds() {
    local spec
    for spec in "$@"; do
        export "PAR_CLN_KIND_${spec%%=*}=${spec#*=}"
    done
}

# stub_run_dir <sbx> <id> — the run dir the stub scenario created (unique per
# id because each stub embeds its id in the dir name)
stub_run_dir() {
    local sbx=$1 id=$2 hit
    hit=$(ls -dt "$sbx"/e2e/.runs/"$id"-stub-* 2>/dev/null | head -1)
    printf '%s' "$hit"
}

# assert_cleaned <label> <rundir> — blobs gone, evidence kept, dir kept
assert_cleaned() {
    local label=$1 dir=$2 f
    assert_file_exists "$label: the run dir itself survives" "$dir"
    for f in uki-unsigned.efi esp.img disk.img disk.img.prebootb \
             phase1/harness.efi tooling/opt/libcrypto.so.3; do
        assert_rc "$label: consumed blob deleted: $f" 0 test ! -e "$dir/$f"
    done
    assert_rc "$label: unpacked tooling scratch tree deleted" 0 test ! -d "$dir/tooling"
    for f in console-b1.log phase1/console.log phase1/console-timed.log \
             cmdline.txt os-release.txt pcr11-measure.txt pcrsign.json \
             keys/db.key; do
        assert_file_exists "$label: evidence retained: $f" "$dir/$f"
    done
}

# assert_blobs_kept <label> <rundir> — every blob still there (exemption /
# escape hatch pins)
assert_blobs_kept() {
    local label=$1 dir=$2 f
    for f in uki-unsigned.efi esp.img disk.img disk.img.prebootb \
             phase1/harness.efi tooling/opt/libcrypto.so.3 console-b1.log; do
        assert_file_exists "$label: blob retained: $f" "$dir/$f"
    done
}

# results_json <sbx> — newest aggregated results file in the sandbox .runs
results_json() {
    ls -t "$1"/e2e/.runs/results-*.json 2>/dev/null | head -1
}

# =============================================================================
# Run A — SERIAL path (JOBS=1): pass cleanup + state-chain exemption
# =============================================================================
SBX_A="$SBX_ROOT/a"
build_sandbox "$SBX_A"
export_kinds s12=pass s00=pass s00b=pass
run_registry "$SBX_A" "$SBX_A/ctl/out" "$SBX_A/ctl/err" s12 s00 s00b
assert_eq "run A (serial, all pass): runner exit 0" "0" "$?"
assert_rc "run A: results JSON parses, 3 rows" 0 \
    jq -e '.scenarios | type == "array" and length == 3' "$(results_json "$SBX_A")"
assert_cleaned "run A serial pass s12" "$(stub_run_dir "$SBX_A" s12)"
# the state-chain producers are EXEMPT: consumers snapshot from these dirs and
# the G-T11b artifact scan reads them after the whole run — blobs stay
assert_blobs_kept "run A chain producer s00 (exempt)" "$(stub_run_dir "$SBX_A" s00)"
assert_blobs_kept "run A chain producer s00b (exempt)" "$(stub_run_dir "$SBX_A" s00b)"
# the cleanup report is appended to the scenario's captured .out (the runner
# keeps stdout contract-clean), alongside the scenario's own output
S12_OUT=$(cat "$(results_json "$SBX_A").dir/s12.out" 2>/dev/null)
assert_contains "run A: cleanup is on the record in s12's captured .out" \
    "$S12_OUT" "prune-blobs"
assert_contains "run A: cleanup report names the dir and the freed total" \
    "$S12_OUT" "blob item(s)"

# =============================================================================
# Run B — FAIL path, serial: a failing scenario is finalized and cleaned too
# =============================================================================
SBX_B="$SBX_ROOT/b"
build_sandbox "$SBX_B"
export_kinds s12=fail s04=pass
run_registry "$SBX_B" "$SBX_B/ctl/out" "$SBX_B/ctl/err" s12 s04
assert_eq "run B (fail row present): runner exit 1" "1" "$?"
assert_rc "run B: s12 row is fail" 0 \
    jq -e '.scenarios[] | select(.id == "s12") | .status == "fail"' "$(results_json "$SBX_B")"
assert_cleaned "run B fail s12" "$(stub_run_dir "$SBX_B" s12)"
assert_cleaned "run B pass s04" "$(stub_run_dir "$SBX_B" s04)"

# =============================================================================
# Run C — WORKER path (-j 2): cleanup fires from the parallel finalize path,
# for pass AND fail rows
# =============================================================================
SBX_C="$SBX_ROOT/c"
build_sandbox "$SBX_C"
export_kinds s04=pass s05=fail
run_registry "$SBX_C" "$SBX_C/ctl/out" "$SBX_C/ctl/err" -j 2 s04 s05
assert_eq "run C (-j 2 with a fail row): runner exit 1" "1" "$?"
assert_cleaned "run C worker pass s04" "$(stub_run_dir "$SBX_C" s04)"
assert_cleaned "run C worker fail s05" "$(stub_run_dir "$SBX_C" s05)"
assert_rc "run C: results JSON parses, 2 rows" 0 \
    jq -e '.scenarios | type == "array" and length == 2' "$(results_json "$SBX_C")"

# =============================================================================
# Run D — escape hatch: HARNESS_CLEANUP_KEEP_BLOBS=1 disables the cleanup
# =============================================================================
SBX_D="$SBX_ROOT/d"
build_sandbox "$SBX_D"
export_kinds s12=pass
SBX_D_KEEP=1
run_registry_with_keep() {
    (
        cd "$SBX_D" || exit 97
        export PAR_CLN_RUNS="$SBX_D/e2e/.runs"
        export HARNESS_CLEANUP_RUNS_DIR="$SBX_D/e2e/.runs"
        export TMPDIR="$SBX_D/ctl"
        export ALPINE_FDE_E2E_TMP_MIN_FREE_MB=64
        export HARNESS_CLEANUP_KEEP_BLOBS="$SBX_D_KEEP"
        bash ./run-e2e.sh "$@"
    ) >"$SBX_D/ctl/out" 2>"$SBX_D/ctl/err"
}
run_registry_with_keep s12
assert_eq "run D (KEEP_BLOBS=1): runner exit 0 (hatch never breaks the run)" "0" "$?"
assert_blobs_kept "run D escape hatch keeps blobs" "$(stub_run_dir "$SBX_D" s12)"

# =============================================================================
# Run E — prune-blobs self-defense (direct calls on the REAL library)
# =============================================================================
SBX_E="$SBX_ROOT/e"
mkdir -p "$SBX_E/e2e/.runs/s12-stub-1" "$SBX_E/not-runs/s12-stub-1"
for d in "$SBX_E/e2e/.runs/s12-stub-1" "$SBX_E/not-runs/s12-stub-1"; do
    truncate -s 64k "$d/esp.img"
    printf 'log\n' >"$d/console-b1.log"
done
# E1: dry-run reports but changes nothing
DRY_OUT=$(HARNESS_CLEANUP_DRYRUN=1 bash "$SBX_A/lib/harness-cleanup.real.sh" \
    prune-blobs "$SBX_E/e2e/.runs/s12-stub-1" 2>&1)
assert_rc "run E1: dry-run keeps the blob on disk" 0 test -e "$SBX_E/e2e/.runs/s12-stub-1/esp.img"
assert_contains "run E1: dry-run says WOULD" "$DRY_OUT" "WOULD"
# E2: refuse anything not shaped <...>/.runs/<dir>
REFUSE_OUT=$(bash "$SBX_A/lib/harness-cleanup.real.sh" \
    prune-blobs "$SBX_E/not-runs/s12-stub-1" 2>&1)
assert_rc "run E2: non-.runs path refused — blob untouched" 0 \
    test -e "$SBX_E/not-runs/s12-stub-1/esp.img"
assert_contains "run E2: refusal is loud" "$REFUSE_OUT" "refus"
# E3: the real deletion pass, direct
bash "$SBX_A/lib/harness-cleanup.real.sh" prune-blobs "$SBX_E/e2e/.runs/s12-stub-1" >/dev/null 2>&1
assert_rc "run E3: direct prune-blobs deletes the blob" 0 test ! -e "$SBX_E/e2e/.runs/s12-stub-1/esp.img"
assert_file_exists "run E3: direct prune-blobs keeps the console log" \
    "$SBX_E/e2e/.runs/s12-stub-1/console-b1.log"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# harness_run_dir_cleanup_contract: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
