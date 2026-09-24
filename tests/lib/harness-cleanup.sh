#!/usr/bin/env bash
# tests/lib/harness-cleanup.sh — stale-process sweep for the e2e harness.
#
# Usage:
#   tests/lib/harness-cleanup.sh sweep           # full stale-leftover sweep
#   tests/lib/harness-cleanup.sh prune-runs      # run-dir disk-hygiene prune
#                                                # (tests/e2e/.runs; rules below)
#   tests/lib/harness-cleanup.sh disk-state      # one-line disk/run-dir report
#   tests/lib/harness-cleanup.sh registry-exit   # EXIT-trap pass: remove the
#                                                # registry TMPDIR only (no
#                                                # process sweep)
#   HARNESS_CLEANUP_DRYRUN=1 ... sweep|prune-runs  # report, change nothing
#
# Called by tests/run-e2e.sh at registry start (full `sweep`, BEFORE the first
# scenario) and in the registry EXIT trap (`registry-exit` — deliberately NOT
# a process sweep: at trap time this registry's own scenarios may still own
# live boots under abnormal exits, so the EXIT pass only removes the TMPDIR
# the registry created; stale-process hygiene is a START-of-registry job).
#
# WHY (2026-09-22 incident): a registry killed with SIGKILL leaves its whole
# process tree behind — the cleanup traps never run. We then had 34 busy-loop
# spinner processes burning 437% CPU for 7 h, plus orphaned swtpm/proxy/bridge
# pairs, while a filled tmpfs (each scenario's ukify intermediates are
# ~850 MB) killed the registry mid-run.
#
# ---------------------------------------------------------------------------
# KILL CRITERIA (audited contract — the sweep must never kill a live boot):
#
# A. qemu-system-x86_64:
#      kill iff its RUN DIR (dirname of the chardev logfile= / serial-qemu.sock
#      / first file= argument) is GONE, or its mtime is >= 12 h old, or (run
#      dir unattributable) the PROCESS itself is >= 12 h old.
#      NEVER killed while its run dir sits under tests/e2e/.runs and is
#      younger than 12 h — a concurrent developer boot always survives.
#
# B. swtpm socket --tpm2 (dir = its --tpmstate dir=):
#      - dir gone                                   -> kill
#      - dir under /tmp AND no live qemu sibling
#        AND dir idle >= 10 min                     -> kill
#      - dir elsewhere (e.g. .runs) AND dir >= 12 h
#        AND no live qemu sibling                   -> kill
#      The 10-min idle guard protects the live-test window where
#      boot_retry/swtpm_ensure legitimately holds a swtpm with no qemu for a
#      few seconds; a live fixture's dir mtime is minutes old, stale junk is
#      hours old. NEVER killed while under tests/e2e/.runs and younger
#      than 12 h.
#
# C. swtpm-ctrl-proxy.py strays (the file is RETIRED AND DELETED; rule C reaps
#    leftover proxy PROCESSES from pre-deletion sessions; dir = dirname of its
#    listen <dir>/sock.ctrl arg):
#      - dir gone                                   -> kill
#      - dir under /tmp AND no live swtpm sibling
#        AND dir idle >= 10 min                     -> kill
#      - dir elsewhere AND dir >= 12 h AND no live
#        swtpm sibling                              -> kill
#
# D. tests/unit/serial_feed_race.sh processes (the test shell AND its CPU-
#    spinner subshells — forks keep the parent cmdline):
#      kill iff ORPHANED (parent pid no longer alive). A live developer or
#      registry run has a live parent and is never touched; the orphans left
#      by a SIGKILLed ancestor are reaped over up to 3 rounds (killing the
#      orphaned test shell reparents its spinners, which the next round
#      then finds orphaned too).
#
# NOT swept (deliberately): serial-bridge.py — it self-exits (<= 60 s after
# qemu disappears, <= 120 s if qemu never appeared; see tests/lib/serial.sh),
# so sweeping it would only race its own exit policy.
#
# Self-match safety: patterns are matched against `ps -eo pid,ppid,state,args`
# output where the args must contain the harness program names; this script's
# own argv (`bash .../harness-cleanup.sh sweep`) never contains them, and
# $$/$PPID are excluded regardless.

set -u

HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)

# A /tmp-origin swtpm/proxy is killed only after its dir has been idle this
# many minutes (protects the live between-boots window of a running test).
IDLE_MIN_TMP="${HARNESS_CLEANUP_IDLE_MIN_TMP:-10}"
# Outside /tmp: a run dir at least this many minutes old is stale (12 h).
STALE_MIN="${HARNESS_CLEANUP_STALE_MIN:-720}"
DRYRUN=0
[[ "${HARNESS_CLEANUP_DRYRUN:-0}" == "1" ]] && DRYRUN=1

PSFILE=$(mktemp)
trap 'rm -f "$PSFILE" 2>/dev/null' EXIT

declare -A DOOM=()
ADDED=0
KILLED=0

_now() { date +%s; }

_dir_mtime() { stat -c %Y "$1" 2>/dev/null || printf ''; }

_scan() { ps -eo pid=,ppid=,state=,args= >"$PSFILE" 2>/dev/null; }

_args_of() {   # args_of <pid> — full argv (single line) from the ps snapshot
    awk -v p="$1" '$1 == p { $1 = ""; $2 = ""; $3 = ""; sub(/^ +/, ""); print; exit }' "$PSFILE"
}

_ppid_of() { awk -v p="$1" '$1 == p {print $2; exit}' "$PSFILE"; }

# _orphaned <ppid> — true iff a process with this parent is an orphan: the
# parent is gone, is a zombie, or is the init reaper (ppid 1 = the real parent
# already died and the kernel reparented).
_orphaned() {
    local p=$1 st
    [[ -n "$p" && "$p" != "0" ]] || return 0
    [[ "$p" == "1" ]] && return 0
    st=$(awk -v p="$p" '$1 == p {print $3; exit}' "$PSFILE")
    [[ -z "$st" || "$st" == *Z* ]] && return 0
    return 1
}

_proc_age_min() {   # proc_age_min <pid> — process age in minutes (0 on error)
    local s
    s=$(ps -o etimes= -p "$1" 2>/dev/null | tr -d ' ')
    [[ -n "$s" ]] || { printf '0'; return 0; }
    (( s / 60 ))
}

_dir_idle_min() {   # dir_idle_min <dir> — minutes since mtime ('' = no dir)
    local m now
    m=$(_dir_mtime "$1")
    [[ -n "$m" ]] || { printf ''; return 0; }
    now=$(_now)
    printf '%s\n' $(( (now - m) / 60 ))
}

# doom <pid> <kind> <reason> — queue a kill (idempotent); prints the decision.
# Under HARNESS_CLEANUP_DRYRUN=1 the decision is only REPORTED, nothing is
# queued and nothing dies (audit mode).
doom() {
    local pid=$1 kind=$2 why=$3
    [[ -n "$pid" ]] || return 1
    [[ -n "${DOOM[$pid]:-}" ]] && return 1
    if ((DRYRUN)); then
        echo "harness-cleanup: WOULD kill pid $pid ($kind): $why"
        return 1
    fi
    DOOM[$pid]=$kind
    echo "harness-cleanup: kill pid $pid ($kind): $why"
    ADDED=$((ADDED + 1))
    return 0
}

_apply_kills() {
    local pid
    for pid in "${!DOOM[@]}"; do
        kill -TERM "$pid" 2>/dev/null
    done
    sleep 1.5   # grace: an orphaned serial_feed_race.sh TERM-trap runs its own cleanup
    for pid in "${!DOOM[@]}"; do
        kill -KILL "$pid" 2>/dev/null
    done
    KILLED=${#DOOM[@]}
}

# _live_pids_matching <awk-pattern> [exclude-doom:1|0] — pids in the snapshot
# whose args match <awk-pattern> (extended regex on the whole line).
_live_pids_matching() {
    local pat=$1 nodoom=${2:-0} p
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if ((nodoom)); then
            [[ -n "${DOOM[$p]:-}" ]] && continue
        fi
        printf '%s\n' "$p"
    done < <(awk -v pat="^$pat\$" '$0 ~ pat {print $1}' "$PSFILE")
}

# _live_qemu_for_dir <dir> — live (non-doomed) qemu whose argv references
# <dir>/sock.ctrl (the tpmdev chardev path qemu_argv wires to swtpm's control
# socket). "Live qemu sibling" for rules B/C.
_live_qemu_for_dir() {
    local d=$1 p
    while IFS= read -r p; do
        [[ -n "${DOOM[$p]:-}" ]] && continue
        _args_of "$p" | grep -qF -- "$d/sock.ctrl" && { printf '%s\n' "$p"; break; }
    done < <(_live_pids_matching '.*qemu-system-x86_64.*' 0)
}

# _live_swtpm_for_dir <dir> — live (non-doomed) swtpm whose --tpmstate is <dir>.
_live_swtpm_for_dir() {
    local d=$1 p args
    while IFS= read -r p; do
        [[ -n "${DOOM[$p]:-}" ]] && continue
        args=$(_args_of "$p")
        [[ "$args" == *"--tpmstate dir=$d "* || "$args" == *"--tpmstate dir=$d" ]] \
            && { printf '%s\n' "$p"; break; }
    done < <(_live_pids_matching '.*swtpm socket .*' 0)
}

_qemu_rundir() {   # qemu_rundir <args> — the boot run dir, best effort
    local args=$1 m
    if [[ "$args" =~ logfile=([^ ]+) ]]; then
        dirname -- "${BASH_REMATCH[1]}"
    elif [[ "$args" =~ ([^[:space:]]*)/serial-qemu\.sock ]]; then
        dirname -- "${BASH_REMATCH[1]}"
    elif [[ "$args" =~ file=([^ ]+) ]]; then
        dirname -- "${BASH_REMATCH[1]}"
    else
        printf ''
    fi
}

# --- rule A: qemu -----------------------------------------------------------------
rule_qemu() {
    local pid args dir idle page
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        args=$(_args_of "$pid")
        dir=$(_qemu_rundir "$args")
        if [[ -z "$dir" ]]; then
            # run dir unattributable (e.g. an alive-but-ancient mystery guest);
            # fall back to PROCESS age — a live boot's qemu is minutes old.
            page=$(_proc_age_min "$pid")
            if (( page >= STALE_MIN )); then
                doom "$pid" qemu "run dir unattributable and process ${page} min old"
            fi
            continue
        fi
        if [[ ! -d "$dir" ]]; then
            doom "$pid" qemu "run dir gone: $dir"
            continue
        fi
        idle=$(_dir_idle_min "$dir")
        if [[ -n "$idle" ]] && (( idle >= STALE_MIN )); then
            doom "$pid" qemu "run dir stale (${idle} min >= ${STALE_MIN}): $dir"
        fi
        # else: protected (a run dir under tests/e2e/.runs younger than 12 h is
        # a live boot — never touched; same for any fresh dir).
    done < <(_live_pids_matching '.*qemu-system-x86_64.*' 0)
}

# --- rule B: swtpm ----------------------------------------------------------------
rule_swtpm() {
    local pid args dir idle
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        args=$(_args_of "$pid")
        [[ "$args" =~ --tpmstate\ dir=([^ ]+) ]] || continue   # not a state holder
        dir=${BASH_REMATCH[1]}
        if [[ ! -d "$dir" ]]; then
            doom "$pid" swtpm "tpmstate dir gone: $dir"
            continue
        fi
        if [[ -n "$(_live_qemu_for_dir "$dir")" ]]; then
            continue   # live boot in progress
        fi
        idle=$(_dir_idle_min "$dir")
        if [[ "$dir" == /tmp/* ]]; then
            if [[ -n "$idle" ]] && (( idle >= IDLE_MIN_TMP )); then
                doom "$pid" swtpm "/tmp tpmstate, no live qemu, idle ${idle} min: $dir"
            fi
        elif [[ -n "$idle" ]] && (( idle >= STALE_MIN )); then
            doom "$pid" swtpm "tpmstate stale (${idle} min >= ${STALE_MIN}), no live qemu: $dir"
        fi
    done < <(_live_pids_matching '.*swtpm socket .*' 0)
}

# --- rule C: swtpm-ctrl-proxy strays (file deleted; processes linger) ---------------
rule_proxy() {
    local pid args listen dir idle
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        args=$(_args_of "$pid")
        [[ "$args" =~ swtpm-ctrl-proxy\.py\ ([^ ]+)\  ]] || [[ "$args" =~ swtpm-ctrl-proxy\.py\ ([^ ]+)$ ]] || continue
        listen=${BASH_REMATCH[1]}
        dir=${listen%/sock.ctrl}
        [[ "$dir" != "$listen" ]] || continue   # unexpected listen shape: hands off
        if [[ ! -d "$dir" ]]; then
            doom "$pid" swtpm-ctrl-proxy "tpm dir gone: $dir"
            continue
        fi
        if [[ -n "$(_live_swtpm_for_dir "$dir")" ]]; then
            continue   # its swtpm lives
        fi
        idle=$(_dir_idle_min "$dir")
        if [[ "$dir" == /tmp/* ]]; then
            if [[ -n "$idle" ]] && (( idle >= IDLE_MIN_TMP )); then
                doom "$pid" swtpm-ctrl-proxy "/tmp tpm dir, no live swtpm, idle ${idle} min: $dir"
            fi
        elif [[ -n "$idle" ]] && (( idle >= STALE_MIN )); then
            doom "$pid" swtpm-ctrl-proxy "tpm dir stale (${idle} min >= ${STALE_MIN}), no live swtpm: $dir"
        fi
    done < <(_live_pids_matching '.*swtpm-ctrl-proxy[.]py.*' 0)
}

# --- rule D: orphaned serial_feed_race processes (test shell + spinners) -----------
# Forked subshells (the ALPINE_FDE_FEEDRACE_LOAD spinners) keep the parent
# cmdline, so one pattern covers both; only ORPHANS (dead parent) are killed.
rule_orphans() {
    local pid ppid args
    while IFS= read -r pid; do
        [[ -n "$pid" ]] || continue
        [[ "$pid" == "$$" || "$pid" == "$PPID" ]] && continue
        ppid=$(_ppid_of "$pid")
        if ! _orphaned "$ppid"; then
            continue   # a live registry / developer shell owns it: hands off
        fi
        doom "$pid" serial-feed-race-orphan "parent $ppid gone (SIGKILLed ancestor)"
    done < <(_live_pids_matching '.*serial_feed_race[.]sh.*' 0)
}

cmd_sweep() {
    local round
    for round in 1 2 3; do
        _scan
        ADDED=0
        rule_qemu
        rule_swtpm
        rule_proxy
        rule_orphans
        ((ADDED == 0)) && break
        _apply_kills
        sleep 0.3   # let orphans reparent before the next scan
    done
    echo "harness-cleanup: sweep done ($KILLED killed$([[ "$DRYRUN" == 1 ]] && printf ' [dry-run]'))"
    return 0
}

# ---------------------------------------------------------------------------
# RUN-DIR PRUNING (`prune-runs`) — registry disk-hygiene contract (2026-09-22:
# tests/e2e/.runs grew to 23 GB / 83 dirs and filled the disk; per-scenario
# best-effort pruning cannot help on SIGKILL and races under -j concurrency,
# so the REGISTRY prunes .runs itself between scenarios and on its abort trap).
#
# PRUNE RULES (audited contract — never deletes outside tests/e2e/.runs, and
# only ever immediate DIRECTORIES of it; results-*/frag-* JSON files and any
# dir not shaped <scenario-prefix>-<all-numeric-timestamp> are never touched):
#
#   (a) per scenario-prefix (dir name up to the trailing timestamp, e.g.
#       s18-foreign-pcrsig-1790049776 -> s18-foreign-pcrsig): keep the newest
#       PRUNE_KEEP dirs (mtime, newest first); the surplus is deleted.
#   (b) total cap: if the summed size of .runs exceeds PRUNE_CAP_MB, delete
#       oldest-first (by mtime) — surplus-from-(a) first, then remaining run
#       dirs oldest-first — until .runs is under PRUNE_FLOOR_MB.
#   (c) IN-FLIGHT GUARD: a dir modified within the last PRUNE_FRESH_MIN
#       minutes is NEVER deleted by either rule (a live scenario/agent is
#       still writing it) — this is what makes abort-path pruning safe.
#
# Constants are env-tunable for tests; the defaults are the audited contract.
RUNS_DIR="${HARNESS_CLEANUP_RUNS_DIR:-$TESTS/e2e/.runs}"
PRUNE_KEEP="${HARNESS_CLEANUP_PRUNE_KEEP:-2}"              # (a) newest kept per prefix
PRUNE_CAP_MB="${HARNESS_CLEANUP_PRUNE_CAP_MB:-8192}"       # (b) trigger: total .runs size
PRUNE_FLOOR_MB="${HARNESS_CLEANUP_PRUNE_FLOOR_MB:-6144}"   # (b) shrink until under this
PRUNE_FRESH_MIN="${HARNESS_CLEANUP_PRUNE_FRESH_MIN:-10}"   # (c) in-flight window (minutes)
# (d) STATE-PROVIDER EXEMPTION (2026-09-23): these prefixes are the state
# every consumer scenario snapshots from (s00b-enroll-* is ALPINE_FDE_E2E_STATE
# for the whole s0x ladder; s00-bootstrap-* feeds s00b). Losing their newest
# dir to the total-cap shrink cascades into instant aborts across every
# downstream scenario (observed live: s08-s17 abort cascade). Their size is
# bounded — rebuilt at most once per registry — so their newest PRUNE_KEEP
# dirs are exempt from rule (b) (rule (a) still prunes beyond-newest surplus).
PRUNE_PROTECT="${HARNESS_CLEANUP_PRUNE_PROTECT:-s00b-enroll s00-bootstrap}"

# _runs_disk_state — ONE-LINE disk report (used/avail + .runs size). Printed by
# `disk-state` and at the end of every `prune-runs`; run-e2e calls it at
# registry start and relies on prune-runs' line after each prune.
_runs_disk_state() {
    local used avail total dirs
    read -r used avail < <(df -Pm -- "$RUNS_DIR" 2>/dev/null | awk 'NR==2 {print $3, $4}')
    total=$(du -sm -- "$RUNS_DIR" 2>/dev/null | awk '{print $1}')
    dirs=$(find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
    echo "harness-cleanup: disk: used ${used:-?} MB / avail ${avail:-?} MB; $RUNS_DIR ${total:-?} MB in ${dirs} run dirs"
}

cmd_disk_state() { _runs_disk_state; }

# _prune_rows — emit "mtime<TAB>size_mb<TAB>prefix<TAB>name" for every immediate
# DIRECTORY of $RUNS_DIR. prefix/name are split from the trailing timestamp;
# an unrecognized shape (prefix split fails, or the tail is not all-numeric)
# is emitted with prefix "?" and never pruned. Symlinks are skipped (find
# -type d does not follow them), so an .runs symlink can never widen the rm.
_prune_rows() {
    local d p ts m s
    while IFS= read -r d; do
        p=${d##*/}; ts=${p##*-}; p=${p%-*}
        # recognized run-dir shape: <prefix>-<all-numeric-timestamp>
        [[ "$ts" =~ ^[0-9]+$ && "$ts" != "${d##*/}" && -n "$p" ]] || p="?"
        m=$(_dir_mtime "$d")
        s=$(du -sm -- "$d" 2>/dev/null | awk '{print $1}')
        printf '%s\t%s\t%s\t%s\n' "${m:-0}" "${s:-0}" "$p" "${d##*/}"
    done < <(find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d -print 2>/dev/null)
}

cmd_prune_runs() {
    if [[ ! -d "$RUNS_DIR" ]]; then
        echo "harness-cleanup: prune-runs: $RUNS_DIR missing — nothing to prune"
        return 0
    fi
    case "$RUNS_DIR" in
        /*.runs) ;;   # absolute, basename .runs — the only shape we prune into
        *) echo "harness-cleanup: refusing to prune odd run dir '$RUNS_DIR'" >&2; return 0 ;;
    esac
    local now total m size pfx name line freed=0 ndel=0 keep_fresh=0 keep_shape=0 keep_prot=0
    local -A cap_exempt=()
    now=$(_now)
    total=$(du -sm -- "$RUNS_DIR" 2>/dev/null | awk '{print $1}')
    total=${total:-0}

    local -a rows sorted
    mapfile -t rows < <(_prune_rows | LC_ALL=C sort -t $'\t' -k1,1nr -k4,4)
    local -A kept_by_prefix=() is_fresh=() is_top=()
    for line in "${rows[@]}"; do
        IFS=$'\t' read -r m size pfx name <<<"$line"
        if [[ "$pfx" == "?" ]]; then
            continue   # reported below, never a prune candidate
        fi
        if (( now - m < PRUNE_FRESH_MIN * 60 )); then
            is_fresh[$name]=1
        fi
        (( kept_by_prefix[$pfx] = ${kept_by_prefix[$pfx]:-0} + 1 ))
        (( ${kept_by_prefix[$pfx]} <= PRUNE_KEEP )) && is_top[$name]=1
    done

    # (a) per-prefix surplus: beyond the newest PRUNE_KEEP per scenario-prefix.
    local -A doomed=()   # name -> reason
    for line in "${rows[@]}"; do
        IFS=$'\t' read -r m size pfx name <<<"$line"
        [[ "$pfx" == "?" ]] && continue
        [[ -n "${is_fresh[$name]:-}" ]] && continue                       # rule (c)
        [[ -n "${is_top[$name]:-}" ]] && continue                         # rule (a) keep
        doomed[$name]="beyond newest $PRUNE_KEEP for prefix $pfx"
    done

    # (b) total cap: still over the cap once (a) lands — keep deleting
    # oldest-first (now including each prefix's kept newest) until under the
    # floor. Fresh dirs (rule c) stay out of the pool entirely; a protected
    # state-provider prefix's kept-newest dirs are exempt (rule d).
    if (( total > PRUNE_CAP_MB )); then
        local need=$(( total - PRUNE_FLOOR_MB ))
        while IFS=$'\t' read -r m size pfx name; do
            (( freed >= need )) && break
            [[ "$pfx" == "?" ]] && continue
            [[ -n "${is_fresh[$name]:-}" ]] && continue                   # rule (c)
            [[ -n "${doomed[$name]:-}" ]] && continue                     # already queued
            if [[ -n "${is_top[$name]:-}" && " $PRUNE_PROTECT " == *" $pfx "* ]]; then
                cap_exempt[$name]=1                                       # rule (d)
                continue
            fi
            doomed[$name]="total cap ${PRUNE_CAP_MB} MB exceeded (oldest-first)"
        done < <(_prune_rows | LC_ALL=C sort -t $'\t' -k1,1n -k4,4)
    fi

    # Apply (or, under HARNESS_CLEANUP_DRYRUN=1, only report) the decisions.
    for line in "${rows[@]}"; do
        IFS=$'\t' read -r m size pfx name <<<"$line"
        if [[ -n "${doomed[$name]:-}" ]]; then
            if ((DRYRUN)); then
                echo "harness-cleanup: WOULD delete run dir $name ($size MB): ${doomed[$name]}"
            else
                echo "harness-cleanup: delete run dir $name ($size MB): ${doomed[$name]}"
                rm -rf -- "$RUNS_DIR/$name"
            fi
            freed=$((freed + size)); ndel=$((ndel + 1))
        elif [[ "$pfx" == "?" ]]; then
            keep_shape=$((keep_shape + 1))
            ((DRYRUN)) && echo "harness-cleanup: keep $name (unrecognized dir shape — not a run dir)"
        elif [[ -n "${is_fresh[$name]:-}" ]]; then
            keep_fresh=$((keep_fresh + 1))
            ((DRYRUN)) && echo "harness-cleanup: keep $name (IN-FLIGHT: modified < $PRUNE_FRESH_MIN min ago)"
        elif [[ -n "${cap_exempt[$name]:-}" ]]; then
            keep_prot=$((keep_prot + 1))
            ((DRYRUN)) && echo "harness-cleanup: keep $name (state-provider prefix $pfx — exempt from the total cap)"
        else
            ((DRYRUN)) && echo "harness-cleanup: keep $name (newest $PRUNE_KEEP for prefix $pfx)"
        fi
    done

    {
        echo "harness-cleanup: prune-runs done ($ndel deleted, ${freed} MB freed$([[ "$DRYRUN" == 1 ]] && printf ' [dry-run]'))"
        (( keep_fresh || keep_shape || keep_prot )) && \
            echo "harness-cleanup: prune-runs kept $keep_fresh in-flight + $keep_shape unrecognized dir(s) + $keep_prot state-provider dir(s)"
    } >&2
    _runs_disk_state
    return 0
}

# cmd_registry_exit — the registry EXIT-trap pass. Deliberately NOT a process
# sweep (see header): remove only the TMPDIR this registry created. Guarded by
# the dfde-e2e- basename so an inherited value can never widen the rm.
cmd_registry_exit() {
    local d="${ALPINE_FDE_E2E_TMPDIR:-}"
    [[ -n "$d" ]] || return 0
    if [[ "$(basename "$d")" != dfde-e2e-* ]]; then
        echo "harness-cleanup: refusing to remove odd TMPDIR '$d'" >&2
        return 0
    fi
    rm -rf -- "$d"
    return 0
}

case "${1:-sweep}" in
    sweep)          cmd_sweep ;;
    prune-runs)     cmd_prune_runs ;;
    disk-state)     cmd_disk_state ;;
    registry-exit)  cmd_registry_exit ;;
    *)
        echo "usage: $0 [sweep|prune-runs|disk-state|registry-exit]" >&2
        exit 64
        ;;
esac
