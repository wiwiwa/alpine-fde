#!/usr/bin/env bash
# tests/run-e2e.sh — e2e orchestrator for the Debian FDE harness (§12).
#
# Usage: tests/run-e2e.sh [-j N] [scenario-id ...]
#   Runs named scenarios (default: every registered scenario), aggregates
#   results into a JSON summary (stdout + tests/e2e/.runs/results-<ts>.json).
#
#   -j N | -jN | --jobs=N   run up to N scenarios CONCURRENTLY (default 1 =
#                           today's sequential behavior; env
#                           DEBIAN_FDE_E2E_JOBS presets it). The state chain
#                           s00 -> s00b always runs first and alone; the
#                           remaining requested scenarios are independent
#                           state consumers (they snapshot their inputs) and
#                           share up to N worker slots. See tests/README.md
#                           "Runner contract details" for the parallel
#                           prune-safety and results-aggregation contract.
#
# Failure classes (§12):
#   exit 64 — environment/prerequisite failure (env-check, missing tools,
#             invalid -j / DEBIAN_FDE_E2E_JOBS)
#   exit 65 — HARNESS-FAILURE: the infra self-test failed before any scenario
#             ran (never reported as a scenario failure)
#   exit 1  — one or more scenario-class failures (including registry ids
#             whose scenario file is missing, and vacuous zero-scenario runs)
#
# Registry status (updated 2026-09-19, W2b): s00/s00b are the full §12
# bootstrap chain; s01–s18 carry pinned/observed statuses in
# tests/e2e/results-final.json. The W2b multi-drive rows s19–s22 (§10 BASE
# matrix + §12 S-19..S-22) are LITERAL table rows now — they bootstrap
# IN-SCENARIO (each builds its own fixtures and consumes no s00/s00b state),
# so the -j scheduler's s00/s00b hoist cannot misorder them and they are NOT
# in _STATE_CONSUMERS.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS="$HERE"
RUNS="$HERE/e2e/.runs"
mkdir -p "$RUNS"

# --- argument parsing (-j N; ids) ------------------------------------------------
# Parsed BEFORE the env gate so a runner misuse (bad -j) fails fast with the
# env-class exit code instead of running the full prerequisite check first.
JOBS="${DEBIAN_FDE_E2E_JOBS:-1}"
REQUESTED=()
_parse_args() {
    local args=("$@") i=0 a
    while ((i < ${#args[@]})); do
        a=${args[i]}
        case "$a" in
            -j|--jobs)
                if ((i + 1 >= ${#args[@]})); then
                    echo "run-e2e: $a requires a numeric argument (>= 1)" >&2
                    exit 64
                fi
                JOBS=${args[$((i + 1))]}
                i=$((i + 2))
                ;;
            -j*)
                JOBS=${a#-j}
                i=$((i + 1))
                ;;
            --jobs=*)
                JOBS=${a#--jobs=}
                i=$((i + 1))
                ;;
            *)
                REQUESTED+=("$a")
                i=$((i + 1))
                ;;
        esac
    done
}
_parse_args "$@"
if [[ ! "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "run-e2e: invalid job count '$JOBS' (-j / DEBIAN_FDE_E2E_JOBS want an integer >= 1)" >&2
    exit 64
fi

# --- env gate ------------------------------------------------------------------
if ! "$TESTS/env-check.sh"; then
    echo "run-e2e: env-check failed — not running scenarios" >&2
    exit 64
fi
for c in ukify objdump cpio xz openssl depmod; do
    if ! command -v "$c" >/dev/null 2>&1; then
        echo "run-e2e: missing e2e-specific prereq: $c" >&2
        exit 64
    fi
done
# --- accelerator selection (loud, greppable, once per run) ------------------------
# tests/lib/qemu.sh owns the decision (DEBIAN_FDE_ACCEL=kvm|tcg; kvm is the
# default and REQUIRED — no /dev/kvm is a fail-closed 64 here, tcg is the
# explicit dev opt-out); the runner only asks for it up front so the choice is
# on the record BEFORE any scenario boots, and lands it in the results JSON
# ("accel"/"tcg_only").
# Worker scenarios re-derive the same decision in their own process (it is
# deterministic per machine) and log the same greppable line.
# shellcheck source=lib/qemu.sh
source "$TESTS/lib/qemu.sh"
ACCEL=$(qemu_accel) || {
    echo "run-e2e: KVM (/dev/kvm) is required for e2e — see qemu-accel lines above" >&2
    exit 64
}

# --- harness self-test gate (§12) -------------------------------------------------
# "Harness self-tests run before e2e so infra breakage reports as
# harness-failure, not scenario-failure." The smoke exercises the key/disk/UKI
# fixtures, the serial client and the registry contract; if IT is broken, no
# scenario result from this run can be trusted.
echo "== harness self-test: e2e_infra_smoke"
if ! SMOKE_OUT=$(bash "$TESTS/unit/e2e_infra_smoke.sh" 2>&1); then
    printf '%s\n' "$SMOKE_OUT"
    echo "run-e2e: HARNESS-FAILURE — infra smoke failed (not a scenario failure)" >&2
    exit 65
fi
printf '%s\n' "$SMOKE_OUT" | tail -1

# --- scenario registry ----------------------------------------------------------
# id <TAB> script-name <TAB> status-hint   (the RUNTIME status is derived from
# file existence: a scenario runs iff tests/e2e/s<nn>-*.sh matches; a registry
# id with no matching file reports MISSING and FAILS the run — see the
# tightened contract in tests/README.md). The full S-00..S-17 matrix lives in
# docs/Architecture.md §12 and the T-bucket gap report; each row must resolve
# to exactly one id (registry-completeness check in
# tests/unit/e2e_infra_smoke.sh greps this literal table).
REGISTRY="
s00	s00-bootstrap-lite.sh	ready
s00b	s00b-enroll-cache.sh	ready
s01	s01-happy-lite.sh	ready
s02	s02-rollback.sh	ready
s03	s03-stale-enrollment.sh	ready
s04	s04-unsigned-uki.sh	ready
s05	s05-sb-off.sh	ready
s06	s06-token-trap.sh	ready
s07	s07-loader-options.sh	ready
s08	s08-firmware-drift.sh	ready
s09	s09-tpm-da-locked.sh	ready
s10	s10-tpm-absent.sh	ready
s11	s11-disk-moved.sh	ready
s12	s12-wrong-passphrase.sh	ready
s13	s13-token-tamper.sh	ready
s14	s14-kernel-update.sh	ready
s15	s15-pcr7-drift.sh	ready
s16	s16-key-rotation.sh	ready
s17	s17-tpm-clear.sh	ready
s19	s19-bcache-crash.sh	ready
s20	s20-raid1-member-loss.sh	ready
s21	s21-finalize-guard.sh	ready
s22	s22-handoff-immunity.sh	ready
"
# Extension scenario BEYOND the §10/§12 matrix (the §6.1 signing negative
# control) is appended at runtime, NOT as a literal table line: the literal
# table keeps exactly the §10/§12 matrix rows (now 22: s00–s17 + the W2b
# multi-drive rows s19–s22). The infra smoke (tests/unit/e2e_infra_smoke.sh)
# pins per-id §10/§12 coverage + no duplicates + an 18-row floor (dynamic
# count — it does not pin 18 exactly anymore). (printf with \t escapes keeps
# raw tabs out of this file text; at runtime the row is a normal
# TAB-separated registry entry.)
#   s18  s18-foreign-pcrsig.sh  (G-T5: foreign-key .pcrsig negative control)
REGISTRY="${REGISTRY}$(printf '\n%s\t%s\t%s\n' "s18" "s18-foreign-pcrsig.sh" "ready")"

# _script_for <id> — resolve a scenario id by filename convention
# (tests/e2e/s<nn>-*.sh; bash globs expand sorted, lowest name wins);
# empty output = not implemented yet.
_script_for() {
    local id="$1" hit
    for hit in "$HERE/e2e/${id}-"*.sh; do
        [[ -f "$hit" ]] && { printf '%s\n' "$hit"; return 0; }
    done
    return 0
}

# scenarios that reuse the ENROLLED s00b artifacts via DEBIAN_FDE_E2E_STATE
_STATE_CONSUMERS=" s01 s05 s06 s07 s09 s12 s13 s18 "

# CR-02/MD-03 prune contract: scenario prunes must never delete the state
# dirs this invocation chains on (s00's populated state -> s00b -> the state
# consumers AND the final G-T11b artifact scan). run-e2e owns the protected
# set; scenarios filter it out of their prune pipelines.
export DEBIAN_FDE_PROTECT_DIRS=""
_protect_add() {   # _protect_add <dir> — append to the colon-separated set
    [[ -n "$1" ]] || return 0
    DEBIAN_FDE_PROTECT_DIRS="${DEBIAN_FDE_PROTECT_DIRS:+${DEBIAN_FDE_PROTECT_DIRS}:}$1"
    export DEBIAN_FDE_PROTECT_DIRS
}

# Parallel prune safety (-j > 1): a peer's rundir must never be pruned
# mid-run, so every EXISTING .runs dir is fed to the filter the scenarios
# already honor (DEBIAN_FDE_PROTECT_DIRS) — the "protect all peer dirs"
# option of the prune contract. Chosen over a DEBIAN_FDE_NO_PRUNE flag
# because the prune filters live in the scenario scripts themselves; this
# way the runner alone disables pruning. Called once before the parallel
# phase AND before each worker fork, so later workers also protect the dirs
# earlier peers have created in the meantime. A dir created after the last
# fork of a given peer is still safe: every scenario keeps its own rundir
# the freshest (5 s touch loop) and prunes only target dirs beyond the 2
# newest by mtime — with N workers the N active dirs are the newest.
_protect_all_runs() {
    local d
    for d in "$RUNS"/*/; do
        [[ -d "$d" ]] || continue
        _protect_add "${d%/}"
    done
}

# MD-05(b): outer wall-clock bound per scenario — one regression in a lib
# must time the scenario out, never re-open the 8h-hang class for the run.
SCENARIO_BUDGET="${DEBIAN_FDE_SCENARIO_BUDGET:-7200}"

# --- selection -------------------------------------------------------------------
# REQUESTED was built by _parse_args (ids only, -j stripped). Default: every
# registered scenario in registry order (s00b rides the matrix ids via the
# letter-suffix match).
if ((${#REQUESTED[@]} == 0)); then
    mapfile -t REQUESTED < <(awk -F '\t' '$1 ~ /^s[0-9][0-9][a-z]?$/ {print $1}' <<<"$REGISTRY")
fi

# --- run --------------------------------------------------------------------------
TS=$(date -u +%Y%m%dT%H%M%SZ)
# IN-01: 1-second timestamps collide under concurrent invocations — mktemp suffix
RESULTS=$(mktemp "$RUNS/results-$TS.XXXXXX.json")
FAILED=0
RAN=0

# IN-07: ids are interpolated into the results JSON — escape the two chars
# that would break it (defensive; ids come from the registry in practice)
_json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '%s' "$s"
}

# Per-scenario result fragments (IN-01: mktemp-unique; one JSON row per file,
# plus the scenario's captured output at "<frag>.log"). Parallel workers write
# them; the final aggregation reads them back IN REQUESTED ORDER — the JSON
# rows and the summary table are deterministic (registry order in the default
# selection, invocation order for named scenarios), never completion order.
# Index-keyed (not id-keyed) so repeated ids on the command line keep today's
# two-runs-two-rows behavior.
declare -a FRAG=()
for _i in "${!REQUESTED[@]}"; do
    FRAG[$_i]=$(mktemp "$RUNS/frag-$TS.XXXXXX.json")
done
unset _i

_frag_write() {    # _frag_write <frag> <id> <status> <seconds>
    printf '{"id": "%s", "status": "%s", "seconds": %s}\n' \
        "$(_json_escape "$2")" "$(_json_escape "$3")" "$4" >"$1"
}
_frag_field() {    # _frag_field <status|seconds> <frag>
    if [[ "$1" == "status" ]]; then
        sed -n 's/.*"status": "\([^"]*\)".*/\1/p' "$2"
    else
        sed -n 's/.*"seconds": \([0-9]*\).*/\1/p' "$2"
    fi
}

# _run_one <index> <id> — execute ONE scenario: outer wall-clock budget
# (MD-05b), vacuous-pass guard (MD-05a), status classification, fragment
# emission. Shared verbatim by the sequential loop and the parallel workers.
# It NEVER writes scenario output to stdout — everything lands in
# "<frag>.log" so the caller controls every print (no interleaved writes,
# IN-01). s00/s00b RUNDIR capture only takes effect in the sequential phase
# (background workers are subshells; the phase split guarantees s00/s00b
# never fork).
_run_one() {
    local idx="$1" id="$2" script hint out rc st t0 secs frag
    frag="${FRAG[$idx]}"
    : >"${frag}.log"
    script=$(_script_for "$id")
    hint=$(awk -F '\t' -v i="$id" '$1 == i {print $3; exit}' <<<"$REGISTRY")
    if [[ -z "$hint" ]]; then
        echo "run-e2e: unknown scenario id: $id" >&2
        _frag_write "$frag" "$id" unknown 0
        return 0
    fi
    if [[ -z "$script" ]]; then
        # Tightened contract (tests/README.md): a registered id whose scenario
        # file is absent is a FAILURE, not a pending pass — otherwise a run
        # with zero scenarios present would exit 0.
        echo "== $id: FAILURE (registered but no tests/e2e/$id-*.sh present)" >"${frag}.log"
        _frag_write "$frag" "$id" missing 0
        return 0
    fi
    t0=$SECONDS
    # state chaining (§12): s00b consumes s00's populated (NOT yet enrolled)
    # state; the state consumers reuse S-00b's ENROLLED artifacts — the full
    # §12 S-00 leaves the disk populated and the baseline finalized, the
    # enrollment happens from the guest in S-00b.
    if [[ "$id" == "s00b" && -n "${S00_RUNDIR:-}" ]]; then
        export DEBIAN_FDE_S00_STATE="$S00_RUNDIR"
    fi
    if [[ "$_STATE_CONSUMERS" == *" $id "* && -n "${S00B_RUNDIR:-}" ]]; then
        export DEBIAN_FDE_E2E_STATE="$S00B_RUNDIR"
    fi
    # MD-05(b): hard outer budget (status `timeout`); MD-05(a): an exit-0
    # scenario with zero assertions is a vacuous pass and fails here.
    out=$(timeout --kill-after=30 "$SCENARIO_BUDGET" bash "$script" 2>&1)
    rc=$?
    if (( rc == 124 )); then
        st=timeout
        # rc 124 is timeout(1)'s status, but the scenario ITSELF can also end
        # 124 (e.g. a wrapped `timeout` stage leaking its rc) — name the rc
        # generically instead of asserting the outer budget was exceeded.
        echo "run-e2e: $id exited rc=124 (timeout-class status; outer budget ${SCENARIO_BUDGET}s or a scenario-internal timeout)" >&2
    elif (( rc != 0 )); then
        st=fail
    elif [[ "$(grep -c '^ok ' <<<"$out" || true)" -lt 1 ]]; then
        st=fail
        echo "run-e2e: $id exited 0 with ZERO assertions — vacuous pass counted as failure" >&2
    else
        st=pass
    fi
    secs=$((SECONDS - t0))
    printf '%s\n' "$out" >"${frag}.log"
    if [[ "$id" == "s00" && "$st" == "pass" ]]; then
        S00_RUNDIR=$(awk '/^RUNDIR /{print $2; exit}' <<<"$out")
        _protect_add "$S00_RUNDIR"   # CR-02/MD-03: prunes must spare s00's state
    fi
    if [[ "$id" == "s00b" && "$st" == "pass" ]]; then
        S00B_RUNDIR=$(awk '/^RUNDIR /{print $2; exit}' <<<"$out")
        _protect_add "$S00B_RUNDIR"  # CR-02/MD-03: prunes must spare s00b's state
    fi
    _frag_write "$frag" "$id" "$st" "$secs"
}

# _print_done <index> — completion line for one scenario (its captured output
# first, then the `== id: status (secs)` summary). Called on completion order
# in parallel mode; the final JSON table below is REQUESTED-ordered.
_print_done() {
    local frag="${FRAG[$1]}"
    cat "${frag}.log"
    echo "== ${REQUESTED[$1]}: $(_frag_field status "$frag") ($(_frag_field seconds "$frag")s)"
}

# _run_seq <index> — sequential phase entry: launch line, run, completion line.
_run_seq() {
    local idx="$1" id script
    id="${REQUESTED[$idx]}"
    script=$(_script_for "$id")
    [[ -n "$script" ]] && echo "== $id: running ($script)"
    _run_one "$idx" "$id"
    _print_done "$idx"
}

# Parallel phase bookkeeping (pid -> requested-index / fragment)
declare -A PAR_IDX=() PAR_FRAG=()

# _par_reap_one — block until SOME worker exits, then print its result
# (completion order). Non-interactive bash reaps background children as they
# die, so `kill -0` going stale is the done-signal.
_par_reap_one() {
    local pid idx frag
    while :; do
        for pid in "${!PAR_IDX[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                wait "$pid" 2>/dev/null
                idx=${PAR_IDX[$pid]}
                frag=${PAR_FRAG[$pid]}
                unset "PAR_IDX[$pid]" "PAR_FRAG[$pid]"
                _print_done "$idx"
                return 0
            fi
        done
        sleep 2
    done
}

if (( JOBS == 1 )); then
    # Default: exactly today's sequential behavior, invocation order preserved.
    for _i in "${!REQUESTED[@]}"; do
        _run_seq "$_i"
    done
    unset _i
else
    # Bounded parallel matrix. Dependency phases: the s00 -> s00b state chain
    # runs FIRST and always sequentially (each snapshot feeds the next); every
    # other requested scenario is an independent state consumer (it snapshots
    # its inputs at start) and may run in parallel up to JOBS.
    ORDER_SEQ=()
    ORDER_PAR=()
    for _canon in s00 s00b; do
        for _i in "${!REQUESTED[@]}"; do
            if [[ "${REQUESTED[$_i]}" == "$_canon" ]]; then
                ORDER_SEQ+=("$_i")
            fi
        done
    done
    for _i in "${!REQUESTED[@]}"; do
        case "${REQUESTED[$_i]}" in s00|s00b) continue ;; esac
        ORDER_PAR+=("$_i")
    done
    unset _canon _i

    for _i in "${ORDER_SEQ[@]}"; do
        _run_seq "$_i"
    done
    unset _i

    _protect_all_runs   # parallel prune safety (see above)
    for _i in "${ORDER_PAR[@]}"; do
        while ((${#PAR_IDX[@]} >= JOBS)); do
            _par_reap_one
        done
        _protect_all_runs   # late forks protect peers' already-created dirs
        _id=${REQUESTED[$_i]}
        _script=$(_script_for "$_id")
        [[ -n "$_script" ]] && echo "== $_id: running ($_script)"
        ( _run_one "$_i" "$_id" ) &
        _pid=$!
        PAR_IDX[$_pid]=$_i
        PAR_FRAG[$_pid]="${FRAG[$_i]}"
    done
    unset _i _id _script _pid
    while ((${#PAR_IDX[@]} > 0)); do
        _par_reap_one
    done
fi

# --- G-T11b artifact scan over what this invocation BUILT -------------------------
# tests/e2e/e2e_infra_smoke.sh scans the s00/s00b artifacts (ESP, UKI, payload
# drives, LUKS header) for private key material. A hit is a HARNESS-detected
# invariant violation — reported distinctly, never silently ignored.
if [[ -n "${S00_RUNDIR:-}" || -n "${S00B_RUNDIR:-}" ]]; then
    echo "== artifact scan: e2e_infra_smoke (G-T11b)"
    SCAN_RC=0
    SCAN_OUT=$(DEBIAN_FDE_S00_STATE="${S00_RUNDIR:-}" DEBIAN_FDE_E2E_STATE="${S00B_RUNDIR:-}" \
        bash "$HERE/e2e/e2e_infra_smoke.sh" 2>&1) || SCAN_RC=$?
    printf '%s\n' "$SCAN_OUT"
    if (( SCAN_RC == 0 )); then
        echo "== artifact scan: clean"
    elif (( SCAN_RC == 64 )); then
        # CR-02: rc 64 = "nothing to scan" (state dir gone) — a distinct SKIP
        # class, NEVER a key-material failure
        echo "== artifact scan: SKIP — nothing to scan (rc 64: no state dir available)"
    else
        echo "run-e2e: ARTIFACT-SCAN FAILURE — key material in built state (see above)" >&2
        FAILED=$((FAILED + 1))
    fi
fi

# --- aggregate --------------------------------------------------------------------
# Read the per-scenario fragments back IN REQUESTED ORDER (registry order in
# the default selection) and tally the failure classes exactly as before:
#   RAN     — scenarios that actually executed (pass/fail/timeout)
#   FAILED  — fail/timeout/missing/unknown rows
# (the vacuous zero-scenario guard below is unchanged).
for _i in "${!REQUESTED[@]}"; do
    _st=$(_frag_field status "${FRAG[$_i]}")
    case "$_st" in
        pass) RAN=$((RAN + 1)) ;;
        fail|timeout) RAN=$((RAN + 1)); FAILED=$((FAILED + 1)) ;;
        missing|unknown) FAILED=$((FAILED + 1)) ;;
        *) echo "run-e2e: corrupt result fragment: ${FRAG[$_i]}" >&2; FAILED=$((FAILED + 1)) ;;
    esac
done
unset _i _st
if (( RAN == 0 )); then
    # Vacuous run: nothing executed (e.g. every registered file absent).
    echo "# run-e2e: no scenario executed — vacuous run counted as failure" >&2
    FAILED=$((FAILED + 1))
fi
{
    echo '{'
    echo "  \"timestamp\": \"$TS\","
    echo "  \"tcg_only\": $([[ "$ACCEL" == "kvm" ]] && echo false || echo true),"
    echo "  \"accel\": \"$ACCEL\","
    echo "  \"jobs\": $JOBS,"
    echo "  \"scenarios_ran\": $RAN,"
    echo "  \"scenarios\": ["
    first=1
    for _i in "${!REQUESTED[@]}"; do
        ((first == 0)) && echo ","
        first=0
        row=$(cat "${FRAG[$_i]}")
        printf '    %s' "$row"
    done
    echo ""
    echo "  ]"
    echo '}'
} | tee "$RESULTS"

# Fragments + captured scenario output are intermediates: the durable artifacts
# are the per-scenario console.log in each rundir and the aggregated $RESULTS.
rm -f "${FRAG[@]}" "${FRAG[@]/%.json/.json.log}"

echo "# results: $RESULTS"
if ((FAILED > 0)); then
    echo "# run-e2e: $FAILED scenario(s) failed"
    exit 1
fi
echo "# run-e2e: all requested scenarios passed"
exit 0
