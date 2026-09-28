#!/usr/bin/env bash
# tests/unit/openrc_audit_oneshot.sh — FR-6 boot-time audit oneshot:
# hooks/openrc/alpine-fde-audit (the OpenRC init script) +
# aud_service_main (lib/cmd/audit.sh, the §8.1 machine/lib entrance: the init
# script SOURCES the lib module — it never execs the `alpine-fde` CLI) +
# hooks/profile.d/alpine-fde.sh (the interactive login alert) + the install
# wiring (init script + profile.d shipped, `rc-update add alpine-fde-audit
# default`) + the finalize NON-INTERFERENCE pin (finalize touches only its
# own service; the audit oneshot is never removed by it).
#
# aud_service_main behavior contract (drift is a RESULT, never a boot failure
# — rc 0 on EVERY path):
#   * baseline missing            -> syslog skip line, quiet, exit 0
#   * comparison error (TPM/ESP)  -> console WARN + syslog, exit 0, existing
#                                    drift state left untouched
#   * match                       -> marker + banners REMOVED (idempotent
#                                    recovery), one syslog line, exit 0
#   * drift                       -> boxed alert prepended to /etc/issue and
#                                    /etc/motd (operator content PRESERVED),
#                                    detailed login banner staged at the drift
#                                    marker (/run/alpine-fde/audit-drift),
#                                    every drifted check logged to syslog,
#                                    console [WARN] block, exit 0
#   * re-run on drift             -> idempotent: exactly ONE alert block in
#                                    issue/motd (no unbounded prepend growth)
# The REAL lib/cmd/audit.sh is exercised; the machine collaborators
# (tpm_pcr_read, fw_sb_state, fw_var_sha256, eventlog_info, dmi_field,
# sbverify_boot_binaries, logger) are RECORDING STUBS defined AFTER the module
# is sourced, so they override the real implementations (§8.1 test seam).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

SVC_HOOK=$REPO/hooks/openrc/alpine-fde-audit
PROFILE_HOOK=$REPO/hooks/profile.d/alpine-fde.sh
FINALIZE_LIB=$REPO/lib/cmd/finalize.sh
AUDIT_LIB=$REPO/lib/cmd/audit.sh
INSTALL_LIB=$REPO/lib/cmd/install.sh

T=$(mktemp -d /tmp/alpine-fde-audit-oneshot.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

ROOT=$T/root
LOG=$T/syslog.log
export ALPINE_FDE_ROOT=$ROOT
export ALPINE_FDE_CMD_DIR=$REPO/lib/cmd

ZERO64=$(printf '0%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
    21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 \
    41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 \
    61 62 63 64)
ONE64=$(printf '1%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 \
    21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 \
    41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 \
    61 62 63 64)

# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

write_baseline() { # PCR0 PCR7 — final baseline fixture
    BL_PCR0=$1 BL_PCR1=$1 BL_PCR2=$1 BL_PCR3=$1 BL_PCR7=$2 \
        BL_CREATED_AT=2026-09-28T00:00:00Z baseline_write "$(sp_baseline_file)"
}

write_operator_content() { # the operator's own issue/motd content
    printf 'Welcome to alpine-fde (operator issue text)\n' >"$ROOT/etc/issue"
    printf 'operator motd text\n' >"$ROOT/etc/motd"
}

# run_svc — source the REAL audit module in a subshell, override the machine
# collaborators with recording stubs, run aud_service_main.
# Env inputs: TPM_PCR0..3/TPM_PCR7 (live PCRs), SB_SB/SB_SM (secureboot/
# setupmode), EVENTLOG_SHA (empty = eventlog absent), AUD_ERROR=1 (tpm stub
# fails). Outputs: SVC_RC, SVC_OUT (stderr+stdout), $LOG (syslog lines).
run_svc() {
    : >"$LOG"
    SVC_OUT=$(
        exec 2>&1
        TPM_PCR0=${TPM_PCR0:-$ZERO64} TPM_PCR1=${TPM_PCR1:-$ZERO64} \
            TPM_PCR2=${TPM_PCR2:-$ZERO64} TPM_PCR3=${TPM_PCR3:-$ZERO64} \
            TPM_PCR7=${TPM_PCR7:-$ZERO64}
        SB_SB=${SB_SB:-1} SB_SM=${SB_SM:-0}
        EVENTLOG_SHA=${EVENTLOG_SHA:-ev-sha-1}
        export ALPINE_FDE_ROOT=$ROOT
        # shellcheck disable=SC1090
        . "$AUDIT_LIB"
        tpm_pcr_read() {
            [ "${AUD_ERROR:-0}" = "1" ] && return 1
            eval "printf '%s\n' \"\$TPM_PCR$1\""
        }
        fw_sb_state() { printf 'secureboot=%s setup_mode=%s efi-rp\n' "$SB_SB" "$SB_SM"; }
        fw_var_sha256() { printf 'fp-%s\n' "$1"; }
        dmi_field() { printf 'dmi-%s\n' "$1"; }
        eventlog_path() { printf '%s\n' "$ROOT/sys/kernel/security/tpm0/binary_bios_measurements"; }
        eventlog_info() {
            [ -n "$EVENTLOG_SHA" ] || return 1
            printf '%s 1024\n' "$EVENTLOG_SHA"
        }
        sbverify_boot_binaries() { SBVERIFY_FAILED=0; }
        logger() { printf '%s\n' "$*" >>"$LOG"; }
        aud_service_main
    )
    SVC_RC=$?
}

marker_file=$ROOT/run/alpine-fde/audit-drift
issue_file=$ROOT/etc/issue
motd_file=$ROOT/etc/motd

# =============================================================================
# 0. static contract: the oneshot init script + the login hook + the wiring
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (missing: $2)"; fi
}
assert_file_exists "static: init script exists" "$SVC_HOOK"
assert_eq "static: openrc-run shebang" "#!/sbin/openrc-run" "$(head -n1 "$SVC_HOOK")"
SVC_TXT=$(cat "$SVC_HOOK")
assert_contains "static: depend() needs localmount" "$SVC_TXT" "need localmount"
assert_contains "static: runs LAST before the login prompt (§8.1: after *)" "$SVC_TXT" "after *"
assert_contains "static: start() defined (oneshot shape — no command= daemon)" "$SVC_TXT" "start()"
assert_contains "static: sources the lib module directly (machine/lib entrance)" "$SVC_TXT" "audit.sh"
assert_contains "static: invokes the lib-level entry aud_service_main" "$SVC_TXT" "aud_service_main"
assert_not_contains "static: NEVER execs the alpine-fde CLI (§8.1 entrance rule)" "$SVC_TXT" "bin/alpine-fde"
assert_contains "static: drift is never a boot failure (rc 0 contract named)" "$SVC_TXT" "return 0"
assert_contains "static: missing runtime degrades via syslog (logger)" "$SVC_TXT" "logger"

assert_file_exists "static: profile.d login hook exists" "$PROFILE_HOOK"
PROF_TXT=$(cat "$PROFILE_HOOK")
assert_contains "static: profile.d reads the drift marker" "$PROF_TXT" "/run/alpine-fde/audit-drift"
assert_contains "static: profile.d marker path is an ALPINE_FDE_* test seam" "$PROF_TXT" "ALPINE_FDE_DRIFT_MARKER"
assert_contains "static: profile.d guards to INTERACTIVE shells" "$PROF_TXT" '*i*'
assert_contains "static: profile.d prints the staged alert" "$PROF_TXT" "cat"

INSTALL_TXT=$(cat "$INSTALL_LIB")
assert_contains "static: install wires the oneshot rc-update (default runlevel)" "$INSTALL_TXT" \
    "rc-update add alpine-fde-audit default"
assert_contains "static: install ships the init script to /etc/init.d" "$INSTALL_TXT" \
    "cp \$_im_hooks/openrc/alpine-fde-audit \$_im_mnt/etc/init.d/alpine-fde-audit"
assert_contains "static: install ships the profile.d login hook" "$INSTALL_TXT" \
    "cp \$_im_hooks/profile.d/alpine-fde.sh \$_im_mnt/etc/profile.d/alpine-fde.sh"
assert_contains "static: install preflight requires the oneshot templates (fail-closed)" "$INSTALL_TXT" \
    "openrc/alpine-fde-audit profile.d/alpine-fde.sh"

# --- finalize NON-INTERFERENCE pin: finalize self-manages ONLY its own service
FIN_TXT=$(cat "$FINALIZE_LIB")
assert_not_contains "finalize pin: never references the audit oneshot" "$FIN_TXT" "alpine-fde-audit"
assert_not_contains "finalize pin: never enables/disables any service (rc-update)" "$FIN_TXT" "rc-update"
assert_not_contains "finalize pin: never touches /etc/init.d" "$FIN_TXT" "/etc/init.d"
assert_not_contains "finalize pin: never touches the profile.d hook" "$FIN_TXT" "profile.d"

# --- the audit module carries the oneshot entry + the runtime-alert clearing
AUD_TXT=$(cat "$AUDIT_LIB")
assert_contains "audit lib: aud_service_main entry exists" "$AUD_TXT" "aud_service_main()"
assert_contains "audit lib: runtime-alert clearing helper exists" "$AUD_TXT" "aud_clear_runtime_alert"

# =============================================================================
# 1. baseline missing -> skip quietly with a syslog line, rc 0
rm -rf "$ROOT"
mkdir -p "$ROOT"
run_svc
assert_rc "no-baseline: rc 0 (never fails the boot)" "0" "$SVC_RC"
assert_contains "no-baseline: syslog skip line" "$(cat "$LOG")" "skipped"
assert_not_contains "no-baseline: quiet on the console" "$SVC_OUT" "WARN"
assert_eq "no-baseline: no marker written" "0" "$([ -e "$marker_file" ] && echo 1 || echo 0)"

# =============================================================================
# 2. match -> quiet, one syslog line, nothing written, rc 0
write_baseline "$ZERO64" "$ZERO64"
write_operator_content
run_svc
assert_rc "match: rc 0" "0" "$SVC_RC"
assert_eq "match: quiet on the console" "" "$SVC_OUT"
assert_contains "match: syslog match line" "$(cat "$LOG")" "match"
assert_eq "match: no marker" "0" "$([ -e "$marker_file" ] && echo 1 || echo 0)"
assert_contains "match: operator issue content untouched" "$(cat "$issue_file")" "operator issue text"
assert_not_contains "match: no alert block in issue" "$(cat "$issue_file")" "WARNING: Alpine FDE"

# =============================================================================
# 3. drift -> alert block in issue + motd (operator content preserved), the
# login banner staged at the marker, syslog DRIFT lines, console [WARN], rc 0.
write_baseline "$ZERO64" "$ZERO64"
write_operator_content
TPM_PCR7=$ONE64 run_svc
assert_rc "drift: rc 0 (drift is a RESULT, not a boot failure)" "0" "$SVC_RC"
assert_contains "drift: console [WARN] block" "$SVC_OUT" "[WARN] Alpine FDE: Platform firmware drift detected during boot!"
assert_contains "drift: console names the review command" "$SVC_OUT" "alpine-fde audit"
for f in "$issue_file" "$motd_file"; do
    assert_contains "drift: boxed alert in $f" "$(cat "$f")" "WARNING: Alpine FDE detected firmware/platform drift on this machine!"
    assert_contains "drift: alert names the accept path in $f" "$(cat "$f")" "alpine-fde audit --accept"
    assert_contains "drift: operator content PRESERVED in $f" "$(cat "$f")" "$(basename "$f" | sed 's/^motd$/motd text/;s/^issue$/issue text/')"
done
assert_file_exists "drift: login banner staged at the marker" "$marker_file"
assert_contains "drift: marker carries the login alert" "$(cat "$marker_file")" "[SECURITY ALERT] Alpine FDE Firmware Drift Detected!"
assert_contains "drift: marker names the drifted PCR" "$(cat "$marker_file")" "pcr7"
assert_contains "drift: marker names the accept+reseal recovery" "$(cat "$marker_file")" "alpine-fde audit --accept && alpine-fde reseal"
assert_contains "drift: syslog DRIFT record" "$(cat "$LOG")" "DRIFT"
assert_contains "drift: syslog alert record" "$(cat "$LOG")" "drift detected"

# --- 3b. idempotent re-run on persistent drift: exactly ONE block, no growth
TPM_PCR7=$ONE64 run_svc
assert_rc "drift re-run: rc 0" "0" "$SVC_RC"
assert_eq "drift re-run: exactly one boxed alert in issue (no prepend growth)" "1" \
    "$(grep -c 'WARNING: Alpine FDE detected firmware/platform drift' "$issue_file")"
assert_eq "drift re-run: operator content still present exactly once" "1" \
    "$(grep -c 'operator issue text' "$issue_file")"

# =============================================================================
# 4. recovery: the drifted machine boots matching again -> marker + banners
# REMOVED, operator content intact, rc 0
TPM_PCR7=$ZERO64 run_svc
assert_rc "recovery: rc 0" "0" "$SVC_RC"
assert_eq "recovery: marker removed" "0" "$([ -e "$marker_file" ] && echo 1 || echo 0)"
assert_not_contains "recovery: alert stripped from issue" "$(cat "$issue_file")" "WARNING: Alpine FDE"
assert_not_contains "recovery: alert stripped from motd" "$(cat "$motd_file")" "WARNING: Alpine FDE"
assert_contains "recovery: operator issue content intact" "$(cat "$issue_file")" "operator issue text"
assert_contains "recovery: operator motd content intact" "$(cat "$motd_file")" "operator motd text"

# =============================================================================
# 5. comparison error (TPM unreachable at boot) -> console WARN + syslog, rc 0,
# EXISTING drift state left untouched (a failed check never silently clears)
write_operator_content
TPM_PCR7=$ONE64 run_svc                     # establish drift state first
AUD_ERROR=1 TPM_PCR7=$ZERO64 run_svc        # next boot: the TPM read fails
assert_rc "error: rc 0 (never fails the boot)" "0" "$SVC_RC"
assert_contains "error: console WARN" "$SVC_OUT" "boot audit failed"
assert_contains "error: syslog failure line" "$(cat "$LOG")" "failed"
assert_contains "error: existing alert left in issue (fail-safe, no silent clear)" "$(cat "$issue_file")" "WARNING: Alpine FDE"
assert_file_exists "error: existing marker left in place" "$marker_file"

# =============================================================================
# 6. pending baseline fields warn but never drift (finalize pending on the
# deferred-enrollment path): no marker, rc 0
rm -rf "$ROOT"
mkdir -p "$ROOT"
BL_PCR0=pending BL_PCR1=pending BL_PCR2=pending BL_PCR3=pending BL_PCR7=pending \
    BL_CREATED_AT=2026-09-28T00:00:00Z baseline_write "$(sp_baseline_file)"
TPM_PCR7=$ZERO64 run_svc
assert_rc "pending: rc 0" "0" "$SVC_RC"
assert_eq "pending: no marker (pending fields do not drift)" "0" "$([ -e "$marker_file" ] && echo 1 || echo 0)"
assert_eq "pending: quiet" "" "$SVC_OUT"

# =============================================================================
# 7. runtime-alert clearing helper (the `alpine-fde audit` / --accept
# acknowledge path shares it): marker + banners removed, content preserved
write_baseline "$ZERO64" "$ZERO64"
write_operator_content
TPM_PCR7=$ONE64 run_svc                     # drift again
assert_file_exists "ack: marker present before the acknowledge" "$marker_file"
(
    . "$AUDIT_LIB"
    logger() { :; }
    aud_clear_runtime_alert
) >/dev/null 2>&1
assert_eq "ack: marker cleared by aud_clear_runtime_alert" "0" "$([ -e "$marker_file" ] && echo 1 || echo 0)"
assert_not_contains "ack: banner stripped from issue" "$(cat "$issue_file")" "WARNING: Alpine FDE"
assert_contains "ack: operator content preserved" "$(cat "$issue_file")" "operator issue text"

# =============================================================================
# 8. the login hook (profile.d) prints the staged banner for interactive
# shells and stays silent for non-interactive ones. The marker path rides the
# ALPINE_FDE_DRIFT_MARKER seam (the shipped default is the guest
# /run/alpine-fde/audit-drift).
export ALPINE_FDE_DRIFT_MARKER=$marker_file
mkdir -p "${marker_file%/*}"
{
    printf '[SECURITY ALERT] Alpine FDE Firmware Drift Detected!\n'
    printf '  - pcr7 DRIFT\n'
} >"$marker_file"
PROF_OUT=$(bash -ic ". '$PROFILE_HOOK'" 2>/dev/null)
assert_contains "profile.d (interactive): prints the staged alert" "$PROF_OUT" "SECURITY ALERT"
PROF_OUT_QUIET=$( . "$PROFILE_HOOK" </dev/null )
assert_not_contains "profile.d: non-interactive shell stays silent (interactive \$- guard)" "$PROF_OUT_QUIET" "SECURITY ALERT"

finish
