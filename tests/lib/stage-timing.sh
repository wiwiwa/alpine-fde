#!/usr/bin/env bash
# tests/lib/stage-timing.sh — per-step timing instrumentation for the e2e
# harness (tests/README.md "Runner contract details": "Step timing").
#
# Usage (source, then):
#   stage_begin <label>              emit "# stage <label>: begin <epoch>"
#   stage_end <label>                emit "# stage <label>: done <seconds>s"
#   stage_timed <label> -- cmd...    begin, run, end (propagates cmd's rc)
#   stage_timing_json <logfile>      runner-side harvest: the log's `done`
#                                    lines as a one-line {label: seconds}
#                                    JSON object (last label wins); empty
#                                    output when the log has no stage lines.
#
# Emissions go to the CALLER's stdout — the scenario log run-e2e captures
# per scenario — and are harvested by tests/run-e2e.sh into the OPTIONAL
# additive `stages` object on each results-<ts>.json row.
#
# Fail-closed discipline: begin/end misuse (a begin while another stage is
# open, an end naming a different label, an end with nothing open, an empty
# or non-harvestable label) prints a loud `stage-timing: ERROR: ...` line to
# stderr and returns nonzero — a scenario that wants fatal behavior wraps
# the call (s00b's run_stage exits 1 on it). Labels must be free of quotes
# and control characters: they become JSON object keys in the results file.
#
# Cheap by design: no subshells, no forks per call (epoch from bash's
# EPOCHREALTIME when available, date(1) only as a pre-bash-5 fallback), no
# traps, no temp files.

if [[ -n "${_ALPINE_FDE_STAGE_TIMING_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_STAGE_TIMING_SOURCED=1

_STAGE_OPEN_LABEL=""   # at most ONE stage open at a time (flat, no nesting)
_STAGE_T0=""           # its begin epoch

_stage_timing_error() {   # _stage_timing_error <message...> — loud, rc 1
    printf 'stage-timing: ERROR: %s\n' "$*" >&2
    return 1
}

_stage_timing_label_ok() {   # <label> — harvestable (JSON-key-safe) labels only
    local label="${1:-}"
    [[ -n "$label" ]] || return 1
    [[ "$label" == *[\"\\]* ]] && return 1
    [[ "$label" == *[[:cntrl:]]* ]] && return 1
    return 0
}

stage_begin() {   # stage_begin <label>
    local label="${1:-}" now
    if ! _stage_timing_label_ok "$label"; then
        _stage_timing_error "stage_begin [$label]: label must be non-empty and free of quotes/control characters (it becomes a JSON key in the results file)"
        return 1
    fi
    if [[ -n "$_STAGE_OPEN_LABEL" ]]; then
        _stage_timing_error "stage_begin [$label] while stage [$_STAGE_OPEN_LABEL] is still open — nested stages are not supported, end [$_STAGE_OPEN_LABEL] first"
        return 1
    fi
    if [[ -n "${EPOCHREALTIME:-}" ]]; then
        now=${EPOCHREALTIME%.*}
    else
        now=$(date +%s)
    fi
    _STAGE_OPEN_LABEL="$label"
    _STAGE_T0="$now"
    printf '# stage %s: begin %s\n' "$label" "$now"
    return 0
}

stage_end() {   # stage_end <label>
    local label="${1:-}" now secs
    if [[ -z "$_STAGE_OPEN_LABEL" ]]; then
        _stage_timing_error "stage_end [$label] with no open stage — every end needs a matching begin"
        return 1
    fi
    if [[ "$label" != "$_STAGE_OPEN_LABEL" ]]; then
        _stage_timing_error "stage_end [$label] mismatches the open stage [$_STAGE_OPEN_LABEL]"
        return 1
    fi
    if [[ -n "${EPOCHREALTIME:-}" ]]; then
        now=${EPOCHREALTIME%.*}
    else
        now=$(date +%s)
    fi
    secs=$((now - _STAGE_T0))
    ((secs >= 0)) || secs=0
    _STAGE_OPEN_LABEL=""
    _STAGE_T0=""
    printf '# stage %s: done %ds\n' "$label" "$secs"
    return 0
}

stage_timed() {   # stage_timed <label> -- cmd...
    local label="${1:-}" rc=0
    if (( $# < 3 )) || [[ "$2" != "--" ]]; then
        _stage_timing_error "stage_timed wants <label> -- cmd... (got $# args)"
        return 64
    fi
    shift 2
    stage_begin "$label" || return 1
    "$@" || rc=$?
    stage_end "$label" || return 1   # a measured stage records its elapsed even on failure
    return "$rc"
}

stage_timing_json() {   # stage_timing_json <logfile> — parse, don't trust env
    local log="${1:-}" pairs
    [[ -n "$log" && -f "$log" ]] || return 0
    pairs=$(sed -n 's/^# stage \(.*\): done \([0-9]\{1,\}\)s$/\1\t\2/p' "$log" 2>/dev/null |
        jq -cRn '[inputs | split("\t") | {(.[0]): (.[1] | tonumber)}] | add // empty')
    printf '%s' "$pairs"
    return 0
}
