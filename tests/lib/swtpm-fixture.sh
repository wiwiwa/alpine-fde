#!/usr/bin/env bash
# tests/lib/swtpm-fixture.sh — swtpm (software TPM 2.0) lifecycle for the
# Debian FDE test harness.
#
# Usage: source tests/lib/swtpm-fixture.sh, then:
#   swtpm_start <state-dir>       start detached; exports SWTPM_TCTI on success
#   swtpm_stop <state-dir>        graceful shutdown (ctrl socket), kill fallback
#   swtpm_reset <state-dir>       stop + wipe state; next start is a fresh TPM
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
# (control). A unixio TCTI works; no TCP fallback is needed. Additionally
# swtpm MUST run with "--flags not-need-init,startup-clear":
#   - not-need-init   : tpm2-tools never sends the ctrl-channel INIT command
#   - startup-clear   : swtpm issues TPM2_Startup itself; without it every
#                       command fails with "TPM not initialized by
#                       TPM2_Startup" and tpm2_startup is rejected (0x1c4)
# Fresh state dir => all PCRs are zero (sha256:7 = 64 x "0"), verified.
#
# Detachment gotcha (verified): swtpm dies with its parent shell, so it is
# started via `setsid ... &` with the pid recorded in <state-dir>/pid.

if [[ -n "${_DEBIAN_FDE_SWTPM_FIXTURE_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_SWTPM_FIXTURE_SOURCED=1

SWTPM_ACTIVE_DIRS=()
_SWTPM_CLEANUP_TRAP_SET=0

# Internal: server socket path for a state dir.
_swtpm_server_sock() { printf '%s/sock' "$1"; }
# Internal: control socket path — tpm2-tss TCTI appends ".ctrl" to the server path.
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

    setsid swtpm socket \
        --tpm2 \
        --tpmstate "dir=$dir" \
        --ctrl "type=unixio,path=$( _swtpm_ctrl_sock "$dir")" \
        --server "type=unixio,path=$(_swtpm_server_sock "$dir")" \
        --flags not-need-init,startup-clear \
        >>"$dir/swtpm.log" 2>&1 &
    local pid=$!
    echo "$pid" >"$dir/pid"

    # Wait for sockets to appear, then probe with a real TPM command so the
    # fixture is deterministic the moment swtpm_start returns.
    local i sock ctrl tcti
    sock=$(_swtpm_server_sock "$dir"); ctrl=$(_swtpm_ctrl_sock "$dir"); tcti=$(_swtpm_tcti_for "$dir")
    for i in $(seq 1 100); do   # up to 10 s
        if [[ -S "$sock" && -S "$ctrl" ]] \
           && tpm2_getcap -T "$tcti" properties-fixed >/dev/null 2>&1; then
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
    echo "swtpm_start: swtpm did not become ready in $dir; log:" >&2
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
# state dir (the permall — SRK, DA lockout state — persists; PCRs reset).
swtpm_ensure() {
    local dir="$1"
    if timeout 20 swtpm_pcrread "$dir" 0 >/dev/null 2>&1; then
        return 0
    fi
    [ -f "$dir/pid" ] && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    rm -f "$dir/pid" "$dir/sock" "$dir/sock.ctrl"
    swtpm_start "$dir"
}

swtpm_pcrextend() {
    local dir="$1" pcr="$2" hex="$3"
    if [[ ! "$hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "swtpm_pcrextend: <hex> must be 64 hex chars (sha256), got: $hex" >&2
        return 64
    fi
    tpm2_pcrextend -Q -T "$(_swtpm_tcti_for "$dir")" "$pcr:sha256=$hex"
}

swtpm_pcrread() {
    local dir="$1" pcr="$2" out
    # Note: no -Q here — tpm2_pcrread -Q suppresses the PCR value itself.
    out=$(tpm2_pcrread -T "$(_swtpm_tcti_for "$dir")" "sha256:$pcr") || return $?
    # Output line: "    7 : 0xHEX" -> print bare lowercase hex.
    awk -v p="$pcr" '$1 == p && $2 == ":" { sub(/^0x/, "", $3); print tolower($3) }' <<<"$out"
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
    tpm2_clear -T "$(_swtpm_tcti_for "$dir")" debian-fde-da-wrong-auth >/dev/null 2>&1
    tpm2_clear -T "$(_swtpm_tcti_for "$dir")" debian-fde-da-wrong-auth >/dev/null 2>&1
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

swtpm_cleanup_all() {
    local d
    for d in "${SWTPM_ACTIVE_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d"
    done
    SWTPM_ACTIVE_DIRS=()
}
