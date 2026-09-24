#!/usr/bin/env bash
# tests/lib/swtpm-fixture.sh — swtpm (software TPM 2.0) lifecycle for the
# Alpine FDE test harness.
#
# Usage: source tests/lib/swtpm-fixture.sh, then:
#   swtpm_start <state-dir>       start detached; exports SWTPM_TCTI on success
#   swtpm_stop <state-dir>        graceful shutdown (ctrl socket), kill fallback
#   swtpm_reset <state-dir>       stop + wipe state; next start is a fresh TPM
#   swtpm_ensure <dir>            rc 0 iff a swtpm serves <dir>, else restart
#   swtpm_seed_pcrs <dir> <d7> <d11>    between-boot reseeding (pcrextend 7+11)
#   swtpm_pcrextend <dir> <pcr> <hex>   extend (drift simulation); hex = 64 chars
#   swtpm_pcrread <dir> <pcr>     print raw sha256 digest (no 0x, lowercase)
#   swtpm_da_lockout <dir>        arm + engage dictionary-attack lockout (s09)
#   swtpm_da_locked_probe <dir>   rc 0 iff DA-protected auth is refused (locked)
#   swtpm_da_state <dir>          print "counter=<hex> inLockout=<0|1>"
#   swtpm_cleanup_all             trap-based cleanup of every started fixture
#
# EMPIRICAL TCTI DECISION (tpm2-tools 5.8 / tpm2-tss swtpm TCTI, verified on
# this sandbox): the TCTI config is
#     SWTPM_TCTI="swtpm:path=<state-dir>/sock"
# tpm2-tss derives the CONTROL socket by appending ".ctrl" to the given path
# (libtss2-tcti-swtpm.so contains the literal "%s.ctrl" format). The fixture
# therefore names the swtpm sockets "<dir>/sock" (server) and "<dir>/sock.ctrl"
# (control) — both bound DIRECTLY by swtpm; no proxy fronts them. A unixio
# TCTI works; no TCP fallback is needed. Additionally swtpm MUST run with
# "--flags not-need-init,startup-clear":
#   - not-need-init   : tpm2-tools never sends the ctrl-channel INIT command
#   - startup-clear   : swtpm issues TPM2_Startup itself; without it every
#                       command fails with "TPM not initialized by
#                       TPM2_Startup" and tpm2_startup is rejected (0x1c4)
# Fresh state dir => all PCRs are zero (sha256:7 = 64 x "0"), verified.
#
# Detachment gotcha (verified): swtpm dies with its parent shell, so it is
# started via `setsid ... &` with the pid recorded in <state-dir>/pid.
#
# LIFETIME ACROSS BOOTS (simplified design, user-approved): there is NO
# proxy — host tpm2 tools and the guest tpm-emulator talk DIRECT to swtpm's
# public sockets. The discipline that makes this safe: all host-side TPM
# work happens BETWEEN boots (qemu 100% dead), so the single-client
# conflicts (qemu pins swtpm's data plane during a boot -> host commands
# hang forever; see tests/README.md's "swtpm 0.10.2 data-loop stall" section for the gory
# live-verified anatomy) cannot occur.
#
# swtpm DIES at every clean qemu exit: qemu's tpm-emulator sends
# CMD_SHUTDOWN over the control socket at teardown (swtpm processes it,
# replies success, marks itself shut-down — never stores volatile state)
# and then closes both chardevs, and swtpm exits on the EOF. A restart on
# the same state dir (swtpm_ensure, the one promoted restart path) starts
# FRESH with startup-clear: only the SRK / DA lockout state persist in
# tpm2-00.permall, ALL PCRs are zero. The scenarios therefore reseed the
# between-boot register state explicitly:
#     swtpm_ensure <dir>                       # restart after the EOF death
#     swtpm_seed_pcrs <dir> <d7> <D11>         # pcrextend 7 + 11
# where <d7> is the boot console's `alpine-fde-pcr sha256:7=` digest and
# <D11> the build's pcr11-enter-initrd.txt prediction. That makes the CLI's
# live-PCR drift check (cli_pcr7_drift: live d7 == expected d7) pass
# naturally and PolicyPCR(d7, d11) match — digest-anchored sealing needs no
# other live state. Any stale tpm2-00.volatilestate is removed before a
# start (a volatilestate on disk would make the next qemu boot CUMULATIVE —
# libtpms re-initializes from the tpmstate dir at qemu's CMD_INIT and the
# restored blob defeats the boot's Startup-CLEAR, defect s15-4); nothing in
# this design writes one anymore. swtpm_reset still removes the whole state
# dir (a genuinely fresh TPM). The store/restore machinery this retires
# is RETIRED AND DELETED; its design survives only as the README's
# "data-loop stall" section for reference.

if [[ -n "${_ALPINE_FDE_SWTPM_FIXTURE_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_SWTPM_FIXTURE_SOURCED=1

SWTPM_ACTIVE_DIRS=()
_SWTPM_CLEANUP_TRAP_SET=0

# Internal: server (data) socket path for a state dir — swtpm binds it
# directly (the guest tpm-emulator's chardev and the host TCTI share it
# only in the disciplined between-boots window; never simultaneously).
_swtpm_server_sock() { printf '%s/sock' "$1"; }
# Internal: control socket path — swtpm binds it directly; tpm2-tss TCTI
# appends ".ctrl" to the server path, qemu_argv passes it as the tpmdev
# chardev.
_swtpm_ctrl_sock() { printf '%s/sock.ctrl' "$1"; }

# Internal: TCTI config string for a state dir.
_swtpm_tcti_for() { printf 'swtpm:path=%s/sock' "$1"; }

# Internal: true if the pid recorded in <dir>/pid is alive.
_swtpm_pid_alive() {
    local pidfile="$1/pid" pid
    [[ -f "$pidfile" ]] || return 1
    pid=$(cat "$pidfile" 2>/dev/null) || return 1
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

swtpm_start() {
    local dir="$1"
    if [[ -z "$dir" ]]; then
        echo "swtpm_start: usage: swtpm_start <state-dir>" >&2
        return 64
    fi
    if _swtpm_pid_alive "$dir"; then
        echo "swtpm_start: swtpm already running for $dir (pid $(cat "$dir/pid"))" >&2
        return 1
    fi
    rm -f "$dir/pid"   # stale pidfile from a previous run
    mkdir -p "$dir"
    # Nothing in the simplified design writes a volatilestate any more, but a
    # STALE one (left by an older run of the store/restore fallback) would
    # make the next qemu boot CUMULATIVE (defect s15-4 — see the lifetime
    # note above): purge it so every start is a clean startup-clear.
    rm -f "$dir/tpm2-00.volatilestate"
    local -a log_args=()
    # SWTPM_TIMED_LOG=1: timestamped command trace — swtpm's --log has no
    # native timestamps, so the log stream goes through ts(1) (moreutils) into
    # tpm-cmd.log. Per-line wall-clock deltas show WHICH TPM operation costs
    # the emulated firmware its minutes (RSA CreatePrimary vs extends vs
    # GetCapability). Composes with SWTPM_FIXTURE_VERBOSE (same level=20).
    # SWTPM_FIXTURE_VERBOSE=1 alone: same trace without timestamps.
    local timed_log_fifo=""
    if [[ "${SWTPM_TIMED_LOG:-}" == "1" ]]; then
        timed_log_fifo="$dir/.tpm-log.fifo"
        mkfifo "$timed_log_fifo"
        ts '%.s' <"$timed_log_fifo" >"$dir/tpm-cmd.log" &
        echo $! >"$dir/ts.pid"
        log_args=(--log "fd=9,level=${SWTPM_LOG_LEVEL:-20}")
    elif [[ "${SWTPM_FIXTURE_VERBOSE:-}" == "1" ]]; then
        log_args=(--log "file=$dir/tpm-cmd.log,level=20")
    fi
    # DIRECT wiring (simplified design): swtpm binds BOTH public sockets
    # itself. The guest tpm-emulator and the host tpm2 tools each get the
    # full single-client budget of their plane — safe because the harness
    # only touches the host side between boots (qemu dead).
    #
    # The spawn runs INSIDE a plain subshell that writes <dir>/pid itself:
    # when the CALLER runs with job control (set -m — s22's watchdog
    # discipline), bash makes a background job a process-group LEADER, so
    # util-linux setsid auto-forks and the recorded $! (the setsid parent)
    # dies instantly — swtpm_start's readiness loop then breaks on the
    # dead-parent check and declares a healthy, re-parented, UNPINNED swtpm
    # "not ready" (live defect 2026-09-24: two s22 standalone runs lost at
    # the first fixture start; unit-pinned in swtpm_fixture_smoke.sh case 8).
    # Job control is off inside a ( ) subshell, so setsid execs in place and
    # the pid written there IS the swtpm process.
    if [[ -n "$timed_log_fifo" ]]; then
        exec 9>"$timed_log_fifo"   # swtpm inherits fd 9 as its log fd
    fi
    (
        setsid swtpm socket \
            --tpm2 \
            --tpmstate "dir=$dir" \
            --ctrl "type=unixio,path=$(_swtpm_ctrl_sock "$dir")" \
            --server "type=unixio,path=$(_swtpm_server_sock "$dir")" \
            --flags not-need-init,startup-clear \
            "${log_args[@]+"${log_args[@]}"}" \
            >>"$dir/swtpm.log" 2>&1 &
        echo $! >"$dir/pid"
    )
    local pid=""
    pid=$(cat "$dir/pid" 2>/dev/null)
    if [[ -n "$timed_log_fifo" ]]; then
        exec 9>&-
    fi

    # Wait for sockets to appear, then probe with a real TPM command so the
    # fixture is deterministic the moment swtpm_start returns.
    local i sock ctrl tcti
    sock=$(_swtpm_server_sock "$dir"); ctrl=$(_swtpm_ctrl_sock "$dir")
    tcti=$(_swtpm_tcti_for "$dir")
    for i in $(seq 1 100); do   # up to 10 s
        # per-command timeout (defect: a probe could block FOREVER when
        # swtpm stops servicing its data socket — observed live 2026-09-23,
        # tpm2_getcap hung 11+ min on a 22-byte unread command; the loop's
        # own bound never fires while the probe blocks). A timed-out probe
        # fails this iteration; the loop retries on the next tick.
        if [[ -S "$sock" && -S "$ctrl" ]] \
           && timeout 10 tpm2_getcap -T "$tcti" properties-fixed >/dev/null 2>&1; then
            SWTPM_ACTIVE_DIRS+=("$dir")
            export SWTPM_TCTI="$tcti"
            if ((_SWTPM_CLEANUP_TRAP_SET == 0)); then
                trap swtpm_cleanup_all EXIT INT TERM
                _SWTPM_CLEANUP_TRAP_SET=1
            fi
            return 0
        fi
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    echo "swtpm_start: swtpm did not become ready in $dir; logs:" >&2
    tail -5 "$dir/swtpm.log" >&2 2>/dev/null
    return 1
}

swtpm_stop() {
    local dir="$1" pid
    [[ -d "$dir" ]] || return 0
    if [[ -S "$(_swtpm_ctrl_sock "$dir")" ]] && command -v swtpm_ioctl >/dev/null 2>&1; then
        # Graceful shutdown over the ctrl socket ("stop and exit"). HI-01: this
        # ioctl can block indefinitely on a socket wedged by a SIGKILLed qemu
        # client — bound it; the SIGTERM/SIGKILL escalation below is the fallback.
        timeout 10 swtpm_ioctl -s --unix "$(_swtpm_ctrl_sock "$dir")" >/dev/null 2>&1
    fi
    # Wait for the process to exit; escalate to SIGTERM/SIGKILL if needed.
    local i
    for i in $(seq 1 50); do   # up to 5 s
        _swtpm_pid_alive "$dir" || break
        sleep 0.1
        (( i == 20 )) && kill "$(cat "$dir/pid")" 2>/dev/null
        (( i == 40 )) && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    done
    if _swtpm_pid_alive "$dir"; then
        pid=$(cat "$dir/pid")
        kill -9 "$pid" 2>/dev/null
        echo "swtpm_stop: pid $pid in $dir survived SIGKILL?" >&2
        return 1
    fi
    rm -f "$dir/pid"
    return 0
}

swtpm_reset() {
    local dir="$1"
    if [[ -z "$dir" ]]; then
        echo "swtpm_reset: usage: swtpm_reset <state-dir>" >&2
        return 64
    fi
    swtpm_stop "$dir"
    rm -rf "$dir"
    mkdir -p "$dir"
}

# swtpm_ensure <dir> — rc 0 iff a swtpm is serving <dir>; otherwise the single
# promoted restart path (IN-03: was duplicated per-scenario as _ensure_tpm):
# hard-kill any stale holder, unlink dead sockets, start fresh on the SAME
# state dir (the permall — SRK, DA lockout state — persists). With the
# simplified design this path fires after EVERY boot: qemu's clean exit
# CMD_SHUTDOWNs swtpm and closes the chardevs, and swtpm exits on the EOF —
# the next host-side TPM touch must restart the stack and the scenario must
# reseed the PCRs (swtpm_seed_pcrs).
#
# DEFECT s15-3 (live-verified 2026-09-22, tests in /tmp repro + real s15 runs):
# the probe used to be `timeout 20 swtpm_pcrread ...` — but swtpm_pcrread is a
# SHELL FUNCTION and timeout(1) can only exec binaries, so the probe failed
# with 127 on EVERY call, and every swtpm_ensure call degraded into a
# kill+restart. The probe stays a direct tpm2 binary invocation.
swtpm_ensure() {
    local dir="$1"
    # bounded DIRECT tpm2 probe — never `timeout <fixture-function>`
    if timeout 20 tpm2_pcrread -T "$(_swtpm_tcti_for "$dir")" sha256:0 >/dev/null 2>&1; then
        return 0
    fi
    # EOF-exit path: swtpm is dead (or a wedged leftover — kill it either
    # way) and possibly left a stale tpm2-00.volatilestate behind (older
    # fallback runs); a fresh startup-clear start needs it gone (s15-4).
    [ -f "$dir/pid" ] && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    rm -f "$dir/pid" "$dir/tpm2-00.volatilestate" \
        "$dir/sock" "$dir/sock.ctrl"
    swtpm_start "$dir"
}

# swtpm_seed_pcrs <dir> <d7> <d11> — between-boot register reseeding
# (simplified design): after the restart the PCRs are zero; extend the booted
# PCR 7 digest (the console's `alpine-fde-pcr sha256:7=` line) and the build's
# enter-initrd PCR 11 prediction so the CLI's live-PCR drift check and the
# PolicyPCR(d7, d11) seal both see exactly the state the guest booted with.
swtpm_seed_pcrs() {
    local dir="$1" d7="$2" d11="$3"
    if [[ -z "$dir" || -z "$d7" || -z "$d11" ]]; then
        echo "swtpm_seed_pcrs: usage: swtpm_seed_pcrs <dir> <d7> <d11>" >&2
        return 64
    fi
    swtpm_pcrextend "$dir" 7 "$d7"  || return $?
    swtpm_pcrextend "$dir" 11 "$d11"
}

swtpm_pcrextend() {
    local dir="$1" pcr="$2" hex="$3"
    if [[ ! "$hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "swtpm_pcrextend: <hex> must be 64 hex chars (sha256), got: $hex" >&2
        return 64
    fi
    # per-command timeout: same defect class as the readiness probe — a
    # command that blocks when swtpm stops servicing its sockets must fail
    # bounded, never hang its caller.
    timeout 10 tpm2_pcrextend -Q -T "$(_swtpm_tcti_for "$dir")" "$pcr:sha256=$hex"
}

swtpm_pcrread() {
    local dir="$1" pcr="$2" out
    # Note: no -Q here — tpm2_pcrread -Q suppresses the PCR value itself.
    out=$(timeout 10 tpm2_pcrread -T "$(_swtpm_tcti_for "$dir")" "sha256:$pcr") || return $?
    # Output line: "    7 : 0xHEX" -> print bare lowercase hex.
    # tpm2_pcrread renders single-digit indices with a SEPARATED colon
    # ("    7 : 0x…") but two-digit indices with the colon GLUED to the
    # index ("    11: 0x…", $2 is the value there) — match both forms
    # (defect: the old second branch `$1 p == p` never matched, so every
    # PCR 11+ read returned empty; exposed by the swtpm_seed_pcrs smoke).
    awk -v p="$pcr" '$1 == p && $2 == ":" { sub(/^0x/, "", $3); print tolower($3) }
                     $1 == p ":" { sub(/^0x/, "", $2); print tolower($2) }' <<<"$out"
}

# --- dictionary-attack lockout (§10 row "DA-locked by other tooling") ----------
# Arm + engage DA lockout deterministically (verified empirically against this
# swtpm/libtpms, tpm2-tools 5.8):
#   1. TPM2_DictionaryAttackParameters: max-tries=2, lockout-recovery=9999 s
#      (the window outlives any TCG boot budget).
#   2. Two failed authorizations against the DA-protected LOCKOUT hierarchy
#      (`tpm2_clear` with a wrong auth -> TPM_RC_BAD_AUTH 0x98e) exhaust the
#      budget -> the TPM enters lockout. (Auth failures on the owner hierarchy
#      do NOT count: libtpms answers "authorization failure without DA
#      implications" for those — the lockout hierarchy is the reliable knob.)
#   3. Positive enforcement proof: a further DA-protected op (arming again)
#      must be refused with TPM_RC_LOCKOUT / "TPM is in DA lockout mode".
# The lockout state persists in tpm2-00.permall across fixture restarts.
swtpm_da_lockout() {
    local dir="$1" err
    if [[ -z "$dir" ]]; then
        echo "swtpm_da_lockout: usage: swtpm_da_lockout <state-dir>" >&2
        return 64
    fi
    tpm2_dictionarylockout -T "$(_swtpm_tcti_for "$dir")" -s -n 2 -l 9999 || {
        echo "swtpm_da_lockout: arming DictionaryAttackParameters failed" >&2
        return 1
    }
    tpm2_clear -T "$(_swtpm_tcti_for "$dir")" alpine-fde-da-wrong-auth >/dev/null 2>&1
    tpm2_clear -T "$(_swtpm_tcti_for "$dir")" alpine-fde-da-wrong-auth >/dev/null 2>&1
    if ! swtpm_da_locked_probe "$dir"; then
        echo "swtpm_da_lockout: lockout did not engage (enforcement probe passed)" >&2
        return 1
    fi
    return 0
}

# swtpm_da_locked_probe <dir> — rc 0 iff a DA-protected authorization is
# currently REFUSED because the TPM is in lockout (TPM_RC_LOCKOUT, 0x921).
swtpm_da_locked_probe() {
    local dir="$1" err
    err=$(tpm2_dictionarylockout -T "$(_swtpm_tcti_for "$dir")" -s -n 2 -l 9999 2>&1)
    [[ "$err" == *"DA lockout mode"* || "$err" == *"0x921"* ]]
}

# swtpm_da_state <dir> — print "counter=<hex> inLockout=<0|1>" (TPM_PT_LOCKOUT_
# COUNTER + TPMA_PERMANENT.inLockout). NB (verified, libtpms): BOTH reads report
# 0 even while an armed lockout window is ENFORCED (DA-protected authorizations
# are refused with TPM_RC_LOCKOUT) — the counter readout is quirked; the
# enforcement probe above is the reliable observable. Consumers: s09 (G-T15).
swtpm_da_state() {
    local out
    out=$(tpm2_getcap -T "$(_swtpm_tcti_for "$1")" properties-variable 2>/dev/null)
    printf 'counter=%s inLockout=%s\n' \
        "$(awk '/TPM2_PT_LOCKOUT_COUNTER/ {print $2}' <<<"$out")" \
        "$(awk '/^  inLockout:/ {print $2; exit}' <<<"$out")"
}

# fixture_drift_verdict <cli_rc> <drift_marker 0|1> <live_d0> <live_d7>
#                       <bl_d0> <bl_d7> <rekeyed 0|1>
#   Print the s00b boot-B register-drift verdict: "none" | "amend" | "vote".
#
# WHY THIS EXISTS (regression 2026-09-24, registry red): the enroll flow is
# DIGEST-ANCHORED (Option A — lib/cmd/enroll-tpm.sh compares the pcrsig
# entry's recorded d7 against baseline.expected_pcr7, NO live TPM read, unit-
# pinned rc-0-despite-live-drift in tests/unit/enroll_precondition_matrix.sh).
# When a scenario re-anchors the machine's SB varstore AFTER the baseline was
# finalized (the ADR-16 release-key floor reissue + keys_vars_enrolled rebuild
# — the db cert is measured into PCR 7), boot B's live PCR 7 diverges from the
# baseline BY CONSTRUCTION, the CLI still enrolls rc 0 sealing the STALE d7,
# the legacy "PCR 7 drift" trigger never fires, and boot C's real PolicyPCR
# refuses the standing token (the zero-input path is lost). The harness must
# therefore detect the drift ITSELF (console readback vs baseline) and run the
# §9.4 accept/vote machinery:
#   vote   — legacy live-read drift message, or an unexplained full-mode d0
#            divergence: a single reading cannot say which bimodal mode is
#            faithful; the caller collects up to 3 readings and amends to the
#            MAJORITY pair (the 2026-09-22 truncated-register defense).
#   amend  — the DETERMINISTIC rekey class: the caller reissued the key +
#            rebuilt the varstore this run AND PCR 0 (firmware-only, rekey-
#            unaffected) still equals the baseline — a full-mode register, so
#            THIS reading is faithful and a single-reading §9.4 accept is
#            sound (saves three otherwise-wasted boot-B passes).
#   none   — no drift (healthy enroll, unreadable readback, or rc != 0
#            without the legacy marker: the scenario's own assertions report).
# Unit-pinned matrix: tests/unit/register_drift_verdict.sh.
fixture_drift_verdict() {
    local rc="$1" marker="$2" d0="$3" d7="$4" bl_d0="$5" bl_d7="$6" rekeyed="$7"
    local hexre='^[0-9a-f]{64}$'
    [ "$marker" = "1" ] && { echo vote; return 0; }
    [ "$rc" = "0" ] || { echo none; return 0; }
    # an unreadable readback judges nothing — let the scenario assertions speak
    [[ "$d7" =~ $hexre && "$d0" =~ $hexre ]] || { echo none; return 0; }
    [ "$d7" = "$bl_d7" ] && { echo none; return 0; }
    if [ "$rekeyed" = "1" ] && [ "$d0" = "$bl_d0" ]; then
        echo amend
    else
        echo vote
    fi
    return 0
}

swtpm_cleanup_all() {
    local d
    for d in "${SWTPM_ACTIVE_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d"
    done
    SWTPM_ACTIVE_DIRS=()
}
