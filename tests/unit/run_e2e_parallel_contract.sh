#!/usr/bin/env bash
# tests/unit/run_e2e_parallel_contract.sh — pins the parallel-matrix contract
# of tests/run-e2e.sh (tests/README.md: "Parallel matrix (-j N)", "Prune
# safety under -j", "Results aggregation under -j").
#
# HERMETICITY. tests/run-e2e.sh is READ-ONLY here. Its argument-validation
# block (contract point 1) is probed on the REAL file — invalid -j exits 64
# at the parse gate, before the env gate / sweep / self-tests / any scenario.
# Everything else runs the runner from a mktemp SANDBOX copy that is byte
# identical (unless PAR_CONTRACT_MUTATION is set, see below) and whose leaf
# dependencies are stubbed: env-check.sh, lib/qemu.sh, lib/harness-cleanup.sh,
# the three harness self-tests under unit/, and e2e/e2e_infra_smoke.sh (the
# G-T11b artifact scan). Scenarios are stub s*-* scripts that echo `ok`
# lines / sleep / exit with a coded status — NO qemu, NO swtpm, NO boots, and
# zero writes to the real tests/e2e/.runs (the sandbox has its own .runs).
#
# Contract pinned:
#   1. -j validation: 0 / -1 / abc / attached / missing arg / env presets all
#      exit 64 with a diagnostic naming -j / ALPINE_FDE_E2E_JOBS.
#   1b. Duplicate ids on the command line: rejected at the same parse gate
#      with exit 64 (under -j they would fork twin boots sharing one .out
#      capture — silent log clobber).
#   2. Phase ordering: s00 -> s00b -> s01c (the merged lifecycle pipeline,
#      Wave-2 task 5b) always run FIRST and sequentially, in chain order,
#      whatever the requested order; the rest share up to N slots.
#   3. Aggregation: one results-<ts>.json with the sequential schema
#      (id/status/seconds rows, top-level accel/jobs), rows in INVOCATION
#      order — never completion order (the slowest scenario is requested
#      first and must still be row 1); the JSON always PARSES and every
#      requested id yields exactly one row — a missing worker fragment is a
#      loud internal error (exit 70), never a trailing comma + dropped row
#      (live bug: results-20260924T060251Z.RG7GyV.json, malformed s22/s18).
#   4. Status classes under -j: exit!=0 -> fail, exit 124 -> timeout (named
#      "timeout-class", never a plain fail), exit 0 with zero `ok` lines ->
#      fail (vacuous guard); all-pass -> runner exit 0.
#   5. Prune protection: with jobs > 1 ALPINE_FDE_PROTECT_DIRS covers the
#      s00/s00b state-chain dirs AND every existing .runs dir, re-collected
#      before EACH worker fork (a late fork protects dirs a finished peer
#      created; a peer's own fork predates its dir).
#   6. Step timing (additive): a scenario whose log carries
#      `# stage <label>: done <seconds>s` lines yields a row with a `stages`
#      object ({label: seconds}); rows without stage lines keep the EXACT
#      previous schema (no stages key) — the change is purely additive.
#
# RED scaffolding (not used in CI): PAR_CONTRACT_MUTATION=<name> applies one
# hand-rolled mutation to the SANDBOX COPY ONLY (never the real file) to
# demonstrate that the assertions bite:
#   no-j-validation | no-phase-hoist | frag-index-collision | no-vacuous-guard
#   | timeout-as-fail | no-latefork-reprotect | jobs-field-dropped
#   | frag-dropped | no-dup-reject | stages-dropped
# Each name must make this file exit nonzero. Empty/unset (default) = the
# verbatim runner = GREEN.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REAL_RUNNER="$TESTS/run-e2e.sh"
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

# --- part 0: preconditions -------------------------------------------------------
assert_file_exists "runner under test present" "$REAL_RUNNER"
assert_file_exists "assert lib present" "$TESTS/lib/assert.sh"
assert_rc "jq available (JSON contract checks)" 0 command -v jq
assert_rc "flock available (stub concurrency meter)" 0 command -v flock

MUT=${PAR_CONTRACT_MUTATION:-}
SBX_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dfde-parctl.XXXXXX")
# Fast-fail if tmpfs is nearly full: this test shares \$TMPDIR with concurrent
# harness activity (a third disk-full incident is two too many). POSIX df -P -k
# (BusyBox has no -m); headroom in 1K blocks, asserted as >= 1 GB.
AVAIL_KB=$(df -Pk "$SBX_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')
assert_rc "tmpfs headroom: >= 1 GB free under \$TMPDIR before starting (got ${AVAIL_KB:-?} KB)" \
    0 test "${AVAIL_KB:-0}" -ge 1048576
cleanup() { rm -rf "$SBX_ROOT"; }
# /tmp is a small tmpfs shared with concurrent harness activity: the sandbox
# must NEVER outlive this process, including on abort. Route signals to an
# immediate exit so the single EXIT trap does the cleanup (a handler that
# rm -rf's directly would leave the script running mid-run with its sandbox
# gone, re-creating stray state). SIGKILL cannot be trapped — nothing here
# may depend on surviving one.
trap cleanup EXIT
trap 'trap - INT; kill -INT $$; exit 130' INT
trap 'trap - TERM; kill -TERM $$; exit 143' TERM
trap 'exit 129' HUP

# _scenario_file <id> — the registry's real script filename for a stubbed id
_scenario_file() {
    case "$1" in
        s00)  echo s00-bootstrap-lite.sh ;;
        s00b) echo s00b-enroll-cache.sh ;;
        s01)  echo s01-happy-lite.sh ;;
        s01c) echo s01-lifecycle-chain.sh ;;
        s02)  echo s02-rollback.sh ;;
        s03)  echo s03-stale-enrollment.sh ;;
        s04)  echo s04-unsigned-uki.sh ;;
        s07)  echo s07-loader-options.sh ;;
        s09)  echo s09-tpm-da-locked.sh ;;
        *)    return 1 ;;
    esac
}

# apply_mutation <runner-copy> — RED-only; single-point mutations of the COPY
apply_mutation() {
    local f=$1
    case "$MUT" in
        "")                    return 0 ;;
        no-j-validation)       sed -i 's/^if \[\[ ! "\$JOBS" =~ .*\]\]; then/if false; then/' "$f" ;;
        no-phase-hoist)        sed -i 's/for _canon in s00 s00b s01c; do/for _canon in __hoist_disabled__; do/' "$f" ;;
        frag-index-collision)  sed -i 's/frag="\${FRAG\[\$idx\]}"/frag="${FRAG[0]}"/' "$f" ;;
        no-vacuous-guard)      sed -i 's/-lt 1 \]\]/-lt 0 ]]/' "$f" ;;
        timeout-as-fail)       sed -i 's/st=timeout/st=fail/' "$f" ;;
        no-latefork-reprotect) sed -i 's/_protect_all_runs   # late forks protect peers.*/: # mutation: late-fork re-collection removed/' "$f" ;;
        jobs-field-dropped)    sed -i 's/jobs\\": \$JOBS,/jobs\\": 1,/' "$f" ;;
        # Drop s04's fragment (worker died before _frag_write): the aggregator
        # must fail loudly (exit 70), never emit a comma for the missing row.
        frag-dropped)          sed -i 's|^_frag_write() {.*$|&\n    [[ "$2" == "s04" ]] \&\& return 0  # mutation: fragment dropped|' "$f" ;;
        # Revert the duplicate-id parse-gate rejection to the old silent
        # twin-boot behavior.
        no-dup-reject)         sed -i 's/^_reject_duplicate_ids$/: # mutation: duplicate-id rejection disabled/' "$f" ;;
        # Drop the additive stages key from every fragment: the staged-row
        # assertions must bite (Step timing contract point 6).
        stages-dropped)        sed -i 's/, "stages": %s}//' "$f" ;;
        *) echo "run_e2e_parallel_contract: unknown mutation '$MUT'" >&2; exit 95 ;;
    esac
}

# build_sandbox <dir> — verbatim runner copy + stubbed leaf deps + stub scenarios
build_sandbox() {
    local sbx=$1 id
    mkdir -p "$sbx/e2e" "$sbx/lib" "$sbx/unit" "$sbx/ctl" "$sbx/state" "$sbx/tmp"
    cp "$REAL_RUNNER" "$sbx/run-e2e.sh"
    # stage-timing.sh is a pure function library (no sockets, no fixtures, no
    # state) — the runner sources it for the stages harvest, so the sandbox
    # carries it VERBATIM rather than stubbed.
    cp "$TESTS/lib/stage-timing.sh" "$sbx/lib/stage-timing.sh"
    apply_mutation "$sbx/run-e2e.sh"
    chmod +x "$sbx/run-e2e.sh"

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
    cat >"$sbx/lib/harness-cleanup.sh" <<'EOF'
#!/usr/bin/env bash
# contract-test stub: never sweeps real processes, never prunes real .runs
exit 0
EOF
    local selftest
    for selftest in e2e_infra_smoke swtpm_fixture_smoke swtpm_proxy_data_plane; do
        printf '#!/usr/bin/env bash\n# contract-test stub (no swtpm/infra)\necho "ok 1 - stub %s"\nexit 0\n' \
            "$selftest" >"$sbx/unit/$selftest.sh"
    done
    printf '#!/usr/bin/env bash\n# contract-test stub: G-T11b artifact scan (no state to scan)\necho "ok 1 - stub artifact scan"\nexit 0\n' \
        >"$sbx/e2e/e2e_infra_smoke.sh"

    # The runner executes these directly (./env-check.sh, ./unit/... .sh,
    # scenarios by absolute path) — without +x the env gate exits 64 and
    # every downstream assertion cascades.
    chmod +x "$sbx/env-check.sh" \
        "$sbx/lib/qemu.sh" "$sbx/lib/harness-cleanup.sh" \
        "$sbx/unit/"e2e_infra_smoke.sh "$sbx/unit/"swtpm_fixture_smoke.sh \
        "$sbx/unit/"swtpm_proxy_data_plane.sh \
        "$sbx/e2e/e2e_infra_smoke.sh"

    for id in s00 s00b s01 s01c s02 s03 s04 s07 s09; do
        _scenario_file "$id" >/dev/null || continue
        cat >"$sbx/e2e/$(_scenario_file "$id")" <<'STUB'
#!/usr/bin/env bash
# contract-test stub scenario: hermetic; behavior from PAR_CONTRACT_KIND_<id>
set -u
id=${0##*/}; id=${id%%-*}
# the merged lifecycle pipeline's stub shares the s01- filename prefix with
# s01's own stub — disambiguate by the file's full name (the real runner does
# the same via the registry's script-name column)
[[ "$0" == *lifecycle-chain* ]] && id=s01c
ctl=${PAR_CONTRACT_DIR:?PAR_CONTRACT_DIR unset}
kind_var="PAR_CONTRACT_KIND_${id}"
kind=${!kind_var:-pass}
order() { printf '%s %s\n' "$1" "$id" >>"$ctl/order.log"; }
protect_dump() { printf '%s\n' "${ALPINE_FDE_PROTECT_DIRS-}" >>"$ctl/protect-$id.log"; }
conc() { local op=$1 n pk
    ( flock 9
      n=$(cat "$ctl/conc" 2>/dev/null || echo 0)
      if [[ "$op" == "+" ]]; then
          n=$((n + 1))
          printf '%s\n' "$n" >"$ctl/conc"
          pk=$(cat "$ctl/peak" 2>/dev/null || echo 0)
          (( n > pk )) && printf '%s\n' "$n" >"$ctl/peak"
      else
          (( n > 0 )) && n=$((n - 1))
          printf '%s\n' "$n" >"$ctl/conc"
      fi
    ) 9>"$ctl/lock"
}
order begin
conc +
protect_dump
rc=0
case "$kind" in
    pass)     echo "ok 1 - stub $id" ;;
    slowpass) sleep "${PAR_CONTRACT_SLOW:-3}"; echo "ok 1 - stub $id" ;;
    staged)   echo "# stage snap: done 1s"; echo "# stage build: done 2s"; echo "ok 1 - stub $id (staged)" ;;
    timeout)  sleep "$(( ${PAR_CONTRACT_SLOW:-3} + 2 ))"; rc=124 ;;
    fail)     echo "not ok 1 - stub $id blew up"; rc=3 ;;
    vacuous)  echo "stub $id: no assertions here" ;;
    state)    echo "ok 1 - stub $id"; printf 'RUNDIR %s/%s-state\n' "${PAR_CONTRACT_STATE:?}" "$id" ;;
    creator)  mkdir -p "${PAR_CONTRACT_RUNS:?}/peer-created-by-$id"; echo "ok 1 - stub $id" ;;
    *)        echo "ok 1 - stub $id" ;;
esac
conc -
order end
exit "$rc"
STUB
        chmod +x "$sbx/e2e/$(_scenario_file "$id")"
    done
}

# run_registry <sbx> <stdout-file> <stderr-file> [runner args...]
run_registry() {
    local sbx=$1 outf=$2 errf=$3
    shift 3
    (
        cd "$sbx" || exit 97
        export PAR_CONTRACT_DIR="$sbx/ctl"
        export PAR_CONTRACT_STATE="$sbx/state"
        export PAR_CONTRACT_RUNS="$sbx/e2e/.runs"
        export TMPDIR="$sbx/tmp"
        # Above the 16 MB contract floor: abort rather than squeeze a shared
        # tmpfs if headroom evaporates mid-run.
        export ALPINE_FDE_E2E_TMP_MIN_FREE_MB=512
        bash ./run-e2e.sh "$@"
    ) >"$outf" 2>"$errf"
}

# export_kinds <id=kind ...> — per-id stub behavior (exported through the runner)
export_kinds() {
    local spec
    for spec in "$@"; do
        export "PAR_CONTRACT_KIND_${spec%%=*}=${spec#*=}"
    done
}

# check <name> <arithmetic-condition words...> — boolean assertion helper
check() {
    local name=$1 r
    shift
    if (("$@")); then r=y; else r=n; fi
    assert_eq "$name" "y" "$r"
}

# ev_line <event> <id> — first order.log line number for an event, 0 if absent
ev_line() {
    local n
    n=$(grep -n "^$1 $2\$" "$ORDER_LOG" 2>/dev/null | head -1 | cut -d: -f1)
    echo "${n:-0}"
}

SBX_A="$SBX_ROOT/a"
CTL_A="$SBX_A/ctl"
build_sandbox "$SBX_A"

# --- part 1: contract point 1 — -j / ALPINE_FDE_E2E_JOBS validation ---------------
# Against the REAL file by default: invalid -j exits at the parse gate
# (before env gate / sweep / self-tests / scenarios) so this is side-effect
# free. Under a mutation, the mutated sandbox copy so the RED run stays
# hermetic end to end.
if [[ -n "$MUT" ]]; then
    VAL_RUNNER="$SBX_A/run-e2e.sh"
else
    VAL_RUNNER="$REAL_RUNNER"
fi

_bad_jobs_probe() { # <name> <envspec|-> <needle> <args...>
    local name=$1 envspec=$2 needle=$3 rc err
    shift 3
    if [[ "$envspec" == "-" ]]; then
        err=$(bash "$VAL_RUNNER" "$@" 2>&1 >/dev/null)
    else
        err=$(env "$envspec" bash "$VAL_RUNNER" "$@" 2>&1 >/dev/null)
    fi
    rc=$?
    assert_eq "$name: exit 64 (env/prerequisite class)" "64" "$rc"
    assert_contains "$name: diagnostic names the -j/ALPINE_FDE_E2E_JOBS seam" "$err" "$needle"
}
_bad_jobs_probe "-j 0"                 "-" "ALPINE_FDE_E2E_JOBS" -j 0
_bad_jobs_probe "-j -1"                "-" "ALPINE_FDE_E2E_JOBS" -j -1
_bad_jobs_probe "-j abc"               "-" "ALPINE_FDE_E2E_JOBS" -j abc
_bad_jobs_probe "attached -jabc"       "-" "ALPINE_FDE_E2E_JOBS" -jabc
_bad_jobs_probe "--jobs=0"             "-" "ALPINE_FDE_E2E_JOBS" --jobs=0
_bad_jobs_probe "-j with missing arg"  "-" "-j"                 -j
_bad_jobs_probe "env ALPINE_FDE_E2E_JOBS=abc" "ALPINE_FDE_E2E_JOBS=abc" "ALPINE_FDE_E2E_JOBS"
_bad_jobs_probe "env ALPINE_FDE_E2E_JOBS=0"   "ALPINE_FDE_E2E_JOBS=0"   "ALPINE_FDE_E2E_JOBS"

# contract point 1b — duplicate ids rejected at the parse gate (same env/arg
# exit class as -j). Parse-gate exit: side-effect free on the real file. Under
# the no-dup-reject mutation these run the mutated SANDBOX copy, whose
# scenarios are stubs — still hermetic.
_dup_probe() { # <name> <args...>
    local name=$1 rc err
    shift
    err=$(bash "$VAL_RUNNER" "$@" 2>&1 >/dev/null)
    rc=$?
    assert_eq "$name: exit 64 (invalid-arg class)" "64" "$rc"
    assert_contains "$name: diagnostic names the duplicate id" "$err" "duplicate scenario id"
}
_dup_probe "duplicate id (-j 2 s01 s01)" -j 2 s01 s01
_dup_probe "duplicate id (s00 s00)"      s00 s00

# GREEN-only sanity: the sandbox copy IS the real runner byte for byte, so the
# sandbox assertions below pin the shipped file, not a fork of it.
if [[ -z "$MUT" ]]; then
    assert_rc "sandbox copy is byte-identical to tests/run-e2e.sh" 0 cmp -s "$REAL_RUNNER" "$SBX_A/run-e2e.sh"
else
    assert_rc "mutation applied to the sandbox copy (RED run)" 1 cmp -s "$REAL_RUNNER" "$SBX_A/run-e2e.sh"
fi

# --- part 2: contract points 2, 3, 4 (+ state-chain prune protection) -------------
# Requested order is deliberately jumbled: s03 (slowest, timeout-class) FIRST,
# the state chain in the middle — the runner must hoist s00 -> s00b -> s01c
# ahead of everything, run them sequentially, then share s01/s02/s03/s04 over
# 3 slots. (s01c = the merged lifecycle pipeline stub; Wave-2 task 5b.)
export_kinds s00=state s00b=state s01=slowpass s02=fail s03=timeout s04=vacuous s01c=pass
mkdir -p "$SBX_A/e2e/.runs/pre-existing-peer"
ORDER_LOG="$CTL_A/order.log"
run_registry "$SBX_A" "$CTL_A/out" "$CTL_A/err" -j 3 s03 s00 s01 s00b s02 s04 s01c
RA_RC=$?
assert_eq "run A (-j 3, mixed statuses): runner exit 1 (scenario-class failure)" "1" "$RA_RC"
if (( RA_RC != 1 )); then
    sed 's/^/# run A stderr: /' "$CTL_A/err" 2>/dev/null | head -15
fi

# point 2 — phase ordering
b_s00=$(ev_line begin s00);  e_s00=$(ev_line end s00)
b_s00b=$(ev_line begin s00b); e_s00b=$(ev_line end s00b)
b_s01c=$(ev_line begin s01c); e_s01c=$(ev_line end s01c)
check "s00 ran (began and ended)" b_s00 '> 0 &&' e_s00 '> 0'
check "state chain order: s00 begin < s00 end < s00b begin < s00b end (sequential)" \
    b_s00 '> 0 &&' e_s00 '> b_s00 &&' b_s00b '> e_s00 &&' e_s00b '> b_s00b'
check "hoisted pipeline: s01c begins after s00b ends and runs to completion (chain member)" \
    b_s01c '> e_s00b &&' e_s01c '> b_s01c'
par_before_chain=0
for _p in s01 s02 s03 s04; do
    (($(ev_line begin "$_p") > e_s01c)) || par_before_chain=1
done
unset _p
assert_eq "state chain (incl. the s01c pipeline) completes before ANY parallel-wave scenario begins" "0" "$par_before_chain"

# point 2 — worker slots
PEAK=$(cat "$CTL_A/peak" 2>/dev/null || echo 0)
check "parallel wave actually ran concurrently (peak >= 2)" "PEAK >= 2"
check "worker slots capped at -j 3 (peak <= 3)" "PEAK <= 3"

# point 3 — results aggregation
RESULT_JSON=$(ls -t "$SBX_A/e2e/.runs/"results-*.json 2>/dev/null | head -1)
assert_file_exists "run A aggregated into one results-<ts>.json" "$RESULT_JSON"
assert_eq "run A results: top-level jobs == 3" "3" "$(jq -r '.jobs' "$RESULT_JSON" 2>/dev/null)"
assert_eq "run A results: top-level accel/tcg_only schema preserved" "kvm false" \
    "$(jq -r '"\(.accel) \(.tcg_only)"' "$RESULT_JSON" 2>/dev/null)"
assert_eq "run A results: 7 rows, one per requested scenario" "7" \
    "$(jq -r '.scenarios | length' "$RESULT_JSON" 2>/dev/null)"
assert_eq "run A results: rows in INVOCATION order, never completion order" \
    '["s03","s00","s01","s00b","s02","s04","s01c"]' \
    "$(jq -c '[.scenarios[].id]' "$RESULT_JSON" 2>/dev/null)"
assert_eq "run A results: sequential status classes (timeout/fail/pass)" \
    '["timeout","pass","pass","pass","fail","fail","pass"]' \
    "$(jq -c '[.scenarios[].status]' "$RESULT_JSON" 2>/dev/null)"
assert_rc "run A results: every row has numeric seconds >= 0" 0 \
    jq -e '[.scenarios[].seconds] | all(type == "number" and . >= 0)' "$RESULT_JSON"
assert_rc "run A results: JSON parses cleanly (schema consumers depend on it — never a trailing comma + dropped row)" 0 \
    jq -e '.scenarios | type == "array"' "$RESULT_JSON"
assert_rc "run A results: every requested id yields exactly one row (no dropped/duplicate rows)" 0 \
    jq -e '([.scenarios[].id] | length) == 7 and ([.scenarios[].id] | unique | length) == 7' "$RESULT_JSON"

# point 4 — loud per-scenario diagnostics
A_ERR=$(cat "$CTL_A/err" 2>/dev/null)
A_OUT=$(cat "$CTL_A/out" 2>/dev/null)
assert_contains "rc-124 scenario named timeout-class (never a plain fail)" "$A_ERR" "timeout-class"
assert_contains "exit-0 zero-assertion scenario failed as vacuous pass" "$A_ERR" "ZERO assertions"
assert_contains "run A tallies 3 failed scenarios (1 timeout-class + 2 fail-class)" "$A_OUT" "3 scenario(s) failed"
assert_contains "run A ran the G-T11b artifact scan over the built state" "$A_OUT" "artifact scan: clean"

# point 5 — protect set covers the state-chain dirs and pre-existing .runs dirs
for _w in s01 s02 s03 s04; do
    _pw=$(cat "$CTL_A/protect-$_w.log" 2>/dev/null)
    assert_contains "worker $_w: protect set covers s00's state dir" "$_pw" "$SBX_A/state/s00-state"
    assert_contains "worker $_w: protect set covers s00b's state dir" "$_pw" "$SBX_A/state/s00b-state"
done
unset _w _pw
assert_contains "worker s01: protect set covers pre-existing .runs peer dir" \
    "$(cat "$CTL_A/protect-s01.log" 2>/dev/null)" "$SBX_A/e2e/.runs/pre-existing-peer"
assert_contains "worker s04: protect set covers pre-existing .runs peer dir" \
    "$(cat "$CTL_A/protect-s04.log" 2>/dev/null)" "$SBX_A/e2e/.runs/pre-existing-peer"
# the hoisted pipeline consumes the ENROLLED chain state — its protect set
# must already cover the s00/s00b state dirs when it runs (Wave-2 task 5b)
assert_contains "hoisted pipeline s01c: protect set covers s00's state dir" \
    "$(cat "$CTL_A/protect-s01c.log" 2>/dev/null)" "$SBX_A/state/s00-state"
assert_contains "hoisted pipeline s01c: protect set covers s00b's state dir" \
    "$(cat "$CTL_A/protect-s01c.log" 2>/dev/null)" "$SBX_A/state/s00b-state"

# --- part 3: contract point 5 — re-collected before EACH worker fork ---------------
# -j 2 over [s09 slowpass 3s, s01 creator, s07 staged]: s01 (fast) finishes while
# s09 sleeps; s07 is the LATE fork and must protect the dir s01 created, while
# s01's own fork predates that dir (proves the mechanism, not a tautology).
# s07 is also the STAGED row for contract point 6 (its stub emits two
# `# stage ... done` lines; the others emit none — additivity both ways).
SBX_B="$SBX_ROOT/b"
CTL_B="$SBX_B/ctl"
build_sandbox "$SBX_B"
export_kinds s09=slowpass s01=creator s07=staged
run_registry "$SBX_B" "$CTL_B/out" "$CTL_B/err" -j 2 s09 s01 s07
assert_eq "run B (-j 2, all pass): runner exit 0" "0" "$?"
assert_contains "late fork s07 protects peer dir created by s01 (pre-fork re-collection)" \
    "$(cat "$CTL_B/protect-s07.log" 2>/dev/null)" "$SBX_B/e2e/.runs/peer-created-by-s01"
assert_not_contains "s01's own fork predates its peer dir (mechanism check)" \
    "$(cat "$CTL_B/protect-s01.log" 2>/dev/null)" "peer-created-by-s01"
RESULT_JSON_B=$(ls -t "$SBX_B/e2e/.runs/"results-*.json 2>/dev/null | head -1)
assert_file_exists "run B aggregated results-<ts>.json" "$RESULT_JSON_B"
assert_rc "run B results: JSON parses cleanly, 3 rows (all-pass run)" 0 \
    jq -e '.scenarios | type == "array" and length == 3' "$RESULT_JSON_B"

# point 6 — Step timing: additive stages object on staged rows, absent elsewhere
assert_rc "run B results: staged row carries the stages object harvested from '# stage ... done' lines" 0 \
    jq -e '.scenarios[] | select(.id == "s07") | .stages == {"snap": 1, "build": 2}' "$RESULT_JSON_B"
assert_rc "run B results: rows WITHOUT stage lines keep the exact previous schema (no stages key)" 0 \
    jq -e '.scenarios[] | select(.id != "s07") | has("stages") | not' "$RESULT_JSON_B"
assert_rc "run A results: no row carries a stages key when no scenario emits stage lines (additive)" 0 \
    jq -e '[.scenarios[] | has("stages")] | all(.) == false' "$RESULT_JSON"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# run_e2e_parallel_contract: pass=$TESTS_PASS fail=$TESTS_FAIL mutation=${MUT:-none}"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
