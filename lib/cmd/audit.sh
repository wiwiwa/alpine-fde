#!/bin/sh
# audit.sh — `alpine-fde audit`: compare live PCR 0..3+7, Secure Boot state and
# the TCG event log (v1 scope: existence + size + sha256, C-G10) against the
# baseline (§8.4, §9.5).
#
# Exit contract: 0 = match, 1 = drift detected (a result, not a crash),
# 64 = fail-closed error (TPM unreachable, missing/invalid baseline).
# (The bucket-C gap list sketched "2 = error"; W0's global exit-code contract
# reserves 2 for CLI usage, so runtime errors map to 64 fail-closed.)
#
#   audit --init    finalize a PENDING baseline from live values (first boot
#                   into the final SB state, §9.1); refuses if already final
#   audit --accept  re-baseline after explicit operator confirmation (§9.4;
#                   required before PCR 7 drift recovery) + last-audit.json
#   audit --yes     non-interactive confirmation for --accept (CI)

if [ -n "${ALPINE_FDE_AUDIT_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_AUDIT_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

audit_usage() {
    cat >&2 <<'EOF'
Usage: alpine-fde audit [--init | --accept | --yes]

Compare PCR 0..3 + 7, Secure Boot state and the TCG event log against
/etc/alpine-fde/baseline.json. Exit 0 match / 1 drift / 64 error.

  --init    finalize a pending baseline from live values (first boot)
  --accept  re-baseline after operator confirmation (PCR 7 drift recovery)
  --yes     skip the interactive confirmation (CI; implies --accept)
EOF
}

# aud_baseline_pcr BASELINE IDX — baseline value for pcr idx (7 → expected_pcr7)
aud_baseline_pcr() {
    if [ "$2" = "7" ]; then
        baseline_get "$1" expected_pcr7
    else
        baseline_get "$1" "pcr$2"
    fi
}

# aud_pcr_report BASELINE — print per-PCR verdict lines; sets AUD_DRIFT=1 on
# drift. Pending baseline fields warn but do not drift (finalization pending).
aud_pcr_report() {
    _apr_bl=$1
    AUD_DRIFT=0
    for _apr_i in 0 1 2 3 7; do
        _apr_base=$(aud_baseline_pcr "$_apr_bl" "$_apr_i")
        _apr_live=''
        if ! _apr_live=$(tpm_pcr_read "$_apr_i") || [ -z "$_apr_live" ]; then
            die "audit: cannot read live PCR $_apr_i (TCTI: ${ALPINE_FDE_TCTI:-<default>})"
        fi
        case $_apr_base in
            pending)
                printf 'pcr%-2s live=%s baseline=pending   (finalize with: alpine-fde audit --init)\n' "$_apr_i" "$_apr_live"
                ;;
            "$_apr_live")
                printf 'pcr%-2s live=%s baseline=%s   match\n' "$_apr_i" "$_apr_live" "$_apr_base"
                ;;
            *)
                printf 'pcr%-2s live=%s baseline=%s   DRIFT\n' "$_apr_i" "$_apr_live" "$_apr_base"
                AUD_DRIFT=1
                ;;
        esac
    done
}

# aud_sb_report BASELINE — Secure Boot state + key fingerprints vs baseline
aud_sb_report() {
    _asr_bl=$1
    _asr_sb=$(fw_sb_state) || true
    _asr_live_sb=$(printf '%s' "$_asr_sb" | sed -n 's/.*secureboot=\([01]\).*/\1/p')
    _asr_live_sm=$(printf '%s' "$_asr_sb" | sed -n 's/.*setup_mode=\([01]\).*/\1/p')
    _asr_base_sb=$(baseline_get_in "$_asr_bl" sb_state secure_boot)
    _asr_base_sm=$(baseline_get_in "$_asr_bl" sb_state setup_mode)
    if [ -n "$_asr_base_sb" ] && [ "$_asr_live_sb" != "$_asr_base_sb" ]; then
        printf 'secureboot live=%s baseline=%s   DRIFT\n' "$_asr_live_sb" "$_asr_base_sb"
        AUD_DRIFT=1
    elif [ -z "$_asr_base_sb" ]; then
        # L-2: nothing was compared — "match" would be dishonest wording
        printf 'secureboot live=%s baseline=not recorded (finalize with --init)\n' "$_asr_live_sb"
    else
        printf 'secureboot live=%s baseline=%s   match\n' "$_asr_live_sb" "$_asr_base_sb"
    fi
    if [ -n "$_asr_base_sm" ] && [ "$_asr_live_sm" != "$_asr_base_sm" ]; then
        printf 'setupmode live=%s baseline=%s   DRIFT\n' "$_asr_live_sm" "$_asr_base_sm"
        AUD_DRIFT=1
    elif [ -z "$_asr_base_sm" ]; then
        printf 'setupmode live=%s baseline=not recorded (finalize with --init)\n' "$_asr_live_sm"
    fi
    for _asr_pair in PK:pk_fp KEK:kek_fp db:db_fp dbx:dbx_fp; do
        _asr_var=${_asr_pair%%:*}
        _asr_key=${_asr_pair#*:}
        _asr_base_fp=$(baseline_get_in "$_asr_bl" sb_state "$_asr_key")
        _asr_live_fp=$(fw_var_sha256 "$_asr_var") || _asr_live_fp=''
        if [ -z "$_asr_base_fp" ]; then
            # L-2: an unrecorded fingerprint means later-APPEARING key material
            # would otherwise be silent; say so (PCR 7 comparison compensates
            # for dbx/PK/KEK/db, which are all measured into PCR 7)
            printf '%-8s fp live=%s baseline=not recorded (finalize with --init)\n' \
                "$_asr_var" "${_asr_live_fp:-<absent>}"
            continue
        fi
        if [ "$_asr_live_fp" != "$_asr_base_fp" ]; then
            printf '%-8s fp live=%s baseline=%s   DRIFT\n' "$_asr_var" "${_asr_live_fp:-<absent>}" "$_asr_base_fp"
            AUD_DRIFT=1
        fi
    done
}

# aud_fw_report BASELINE — §9.5 firmware identity (fw.vendor / fw.version,
# recorded at finalize from the DMI id seam). INFORMATIONAL by decision: audit
# is a detective control and firmware updates legitimately change the vendor /
# BIOS version strings — the SECURITY signal for firmware change is PCR 0
# drift (aud_pcr_report) plus the event-log tripwire (aud_eventlog_report).
# A changed (or newly absent) identity string is therefore reported as an info
# line and never sets AUD_DRIFT.
aud_fw_report() {
    _afr_bl=$1
    for _afr_pair in vendor:sys_vendor version:bios_version; do
        _afr_k=${_afr_pair%%:*}
        _afr_dmi=${_afr_pair#*:}
        _afr_base=$(baseline_get_in "$_afr_bl" fw "$_afr_k")
        _afr_live=$(dmi_field "$_afr_dmi")
        if [ -z "$_afr_base" ]; then
            # L-2: nothing was compared — "match" would be dishonest wording
            printf 'fw %-7s live=%s baseline=not recorded (finalize with --init)\n' \
                "$_afr_k" "${_afr_live:-<absent>}"
        elif [ "$_afr_live" != "$_afr_base" ]; then
            printf 'fw %-7s live=%s baseline=%s   info (informational — PCR 0 drift is the security signal)\n' \
                "$_afr_k" "${_afr_live:-<absent>}" "$_afr_base"
        else
            printf 'fw %-7s live=%s baseline=%s   match\n' \
                "$_afr_k" "$_afr_live" "$_afr_base"
        fi
    done
}

# aud_eventlog_report BASELINE — v1 scope: existence + size + sha256
aud_eventlog_report() {
    _aer_bl=$1
    _aer_base_sha=$(baseline_get_in "$_aer_bl" fw eventlog_sha256)
    if ! _aer_live=$(eventlog_info); then
        if [ -n "$_aer_base_sha" ]; then
            printf 'eventlog absent at %s (baseline records %s)   DRIFT\n' "$(eventlog_path)" "$_aer_base_sha"
            AUD_DRIFT=1
        else
            printf 'eventlog absent at %s (no baseline record)   info\n' "$(eventlog_path)"
        fi
        return 0
    fi
    _aer_live_sha=$(printf '%s' "$_aer_live" | cut -d' ' -f1)
    _aer_live_sz=$(printf '%s' "$_aer_live" | cut -d' ' -f2)
    if [ -z "$_aer_base_sha" ]; then
        # L-2: the §9.5 v1 tripwire is not armed on this machine — the eventlog
        # APPEARING after a finalize-without-log must be loud, never silent
        warn "eventlog present at $(eventlog_path) but the baseline records none — §9.5 v1 tripwire NOT armed (finalize with: alpine-fde audit --init)"
        printf 'eventlog sha256=%s size=%s   not recorded (finalize with --init)\n' "$_aer_live_sha" "$_aer_live_sz"
        return 0
    fi
    _aer_base_sz=$(baseline_get_in "$_aer_bl" fw eventlog_size)
    if [ "$_aer_live_sha" = "$_aer_base_sha" ]; then
        printf 'eventlog sha256=%s size=%s   match\n' "$_aer_live_sha" "$_aer_live_sz"
    elif [ "$_aer_live_sz" = "$_aer_base_sz" ]; then
        # SAME SIZE, DIFFERENT DIGEST — NOT drift (R640 2026-10-08): the TCG
        # log is a FIXED-SIZE buffer whose fill order varies per boot path
        # (the console-redirection, the boot-device one-shots and the LC jobs
        # reorder events at identical length), so its whole-buffer digest is
        # per-boot UNSTABLE. Pinning it re-wrote the drift marker on every
        # boot no matter how many times the operator accepted — the alert
        # could never clear on real hardware. The stable facts (the size and
        # the buffer's presence/absence) stay armed; the unstable digest is
        # reported INFORMATIONALLY and never trips AUD_DRIFT.
        printf 'eventlog sha256 live=%s baseline=%s (size %s — stable; the digest is per-boot volatile, not drift)   info\n' \
            "$_aer_live_sha" "$_aer_base_sha" "$_aer_live_sz"
    else
        printf 'eventlog sha256 live=%s baseline=%s (size %s vs %s)   DRIFT\n' \
            "$_aer_live_sha" "$_aer_base_sha" "$_aer_live_sz" "${_aer_base_sz:-?}"
        AUD_DRIFT=1
    fi
}

# aud_sbverify_report — §8.3: audit runs sbverify over the ESP boot binaries
# (boot manager + fallback loader). A PRESENT binary that fails verification
# is firmware-visible tampering: count it as drift. Absent ESP/binaries are
# reported as skipped (an installer environment has no ESP yet — not drift).
aud_sbverify_report() {
    sbverify_boot_binaries
    if [ "${SBVERIFY_FAILED:-0}" -gt 0 ]; then
        AUD_DRIFT=1
    fi
}

aud_next_steps() {
    cat >&2 <<'EOF'
PCR 7 drift recovery (§9.4): confirm the drift is benign (firmware/dbx update?
or tampering?), then:
  alpine-fde audit --accept      # re-baseline (operator confirmation)
  alpine-fde reseal          # re-enroll — ONE cryptenroll covers all retained UKIs;
                                 # cryptenroll re-captures the new CURRENT PCR 7 into
                                 # the static policy (A″: no signing medium needed, the
                                 # UKIs' signatures stay untouched; §9.4)
EOF
}

# aud_write_last_audit FILE BASELINE RESULT ACCEPTED — last-audit.json.
# M-3 (the baseline_finalize_from_live / reseal_record pattern): the document is
# staged in a temp file NEXT TO the target, chmod 600 BEFORE the rename, then
# moved into place ATOMICALLY — no default-umask window and no torn
# last-audit.json (a failed stage leaves the previous document untouched
# instead of truncating it). rc 1 with a loud err on failure; rc 0 otherwise.
aud_write_last_audit() {
    _aw_f=$1 _aw_bl=$2 _aw_result=$3 _aw_acc=$4
    _aw_dir=${_aw_f%/*}
    mkdir -p "$_aw_dir" || {
        err "audit: cannot create state directory $_aw_dir"
        return 1
    }
    _aw_tmp=$(mktemp "$_aw_dir/.last-audit.XXXXXX") || {
        err "audit: cannot create temp file for last-audit.json in $_aw_dir"
        return 1
    }
    if ! cat >"$_aw_tmp" <<EOF
{
  "schema_version": 1,
  "audited_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "result": "$_aw_result",
  "accepted": "$_aw_acc",
  "pcr0": "$(baseline_get "$_aw_bl" pcr0)",
  "pcr1": "$(baseline_get "$_aw_bl" pcr1)",
  "pcr2": "$(baseline_get "$_aw_bl" pcr2)",
  "pcr3": "$(baseline_get "$_aw_bl" pcr3)",
  "expected_pcr7": "$(baseline_get "$_aw_bl" expected_pcr7)",
  "eventlog_sha256": "$(baseline_get_in "$_aw_bl" fw eventlog_sha256)",
  "eventlog_size": "$(baseline_get_in "$_aw_bl" fw eventlog_size)"
}
EOF
    then
        rm -f "$_aw_tmp"
        err "audit: serializing last-audit.json failed"
        return 1
    fi
    chmod 600 "$_aw_tmp"
    if ! mv -f "$_aw_tmp" "$_aw_f"; then
        rm -f "$_aw_tmp"
        err "audit: installing last-audit.json failed: $_aw_f"
        return 1
    fi
    return 0
}

cmd_audit_main() {
    _am_init=0
    _am_accept=0
    while [ $# -gt 0 ]; do
        case $1 in
            --init) _am_init=1 ;;
            --accept) _am_accept=1 ;;
            --yes)
                _am_accept=1
                ALPINE_FDE_YES=1
                ;;
            -h | --help)
                audit_usage
                return 0
                ;;
            *) die -r "$ALPINE_FDE_USAGE" "audit: unknown argument: $1" ;;
        esac
        shift
    done

    require_pkgs tpm2:tpm2-tools
    _am_bl=$(sp_baseline_file)
    [ -f "$_am_bl" ] || die "audit: no baseline at $_am_bl (run 'alpine-fde provision stage1')"
    baseline_validate "$_am_bl" || die "audit: baseline invalid: $_am_bl"
    tpm_available || die "audit: no TPM reachable via TCTI '${ALPINE_FDE_TCTI:-<default>}'"

    if [ "$_am_init" -eq 1 ]; then
        if baseline_is_final "$_am_bl"; then
            die "audit: baseline already finalized (use 'audit --accept' to re-baseline)"
        fi
        info "finalizing pending baseline from live values (first boot in the final SB state)"
        baseline_finalize_from_live
        aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" ok no
        printf 'alpine-fde: baseline finalized: %s\n' "$_am_bl" >&2
        return 0
    fi

    aud_pcr_report "$_am_bl"
    aud_sb_report "$_am_bl"
    aud_fw_report "$_am_bl"
    aud_eventlog_report "$_am_bl"
    aud_sbverify_report

    if [ "$AUD_DRIFT" -eq 1 ]; then
        aud_next_steps
    fi

    if [ "$_am_accept" -eq 1 ]; then
        if [ -z "${ALPINE_FDE_YES:-}" ]; then
            printf 'alpine-fde: re-baseline (overwrite baseline.json with live values)? type ACCEPT: ' >&2
            if [ -t 0 ]; then
                read -r _am_conf </dev/tty 2>/dev/null || read -r _am_conf || _am_conf=''
            else
                read -r _am_conf || _am_conf=''
            fi
            if [ "$_am_conf" != "ACCEPT" ]; then
                die "audit: re-baseline not confirmed"
            fi
        fi
        baseline_finalize_from_live
        # FR-6 acknowledge path: the re-baseline retires any standing
        # boot-audit alert (drift marker + issue/motd banners)
        aud_clear_runtime_alert
        aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" ok yes
        printf 'alpine-fde: baseline re-baselined from live values (accepted); %s updated\n' "$_am_bl" >&2
        return 0
    fi

    aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" \
        "$([ "$AUD_DRIFT" -eq 1 ] && printf drift || printf ok)" no
    if [ "$AUD_DRIFT" -eq 1 ]; then
        return "$ALPINE_FDE_DRIFT"
    fi
    # FR-6 acknowledge path: an operator-run `alpine-fde audit` that finds NO
    # drift retires any standing boot-audit alert (drift marker + issue/motd
    # banners) — the same helper the --accept re-baseline uses below.
    aud_clear_runtime_alert
    printf 'alpine-fde: all checked values match the baseline\n' >&2
    return 0
}

# =============================================================================
# FR-6: the BOOT-TIME audit entry (docs/Architecture.md §8.1 internal-
# automation row; docs/UserGuide.md §4 "Automated Boot & Login Auditing").
#
# The OpenRC oneshot hooks/openrc/alpine-fde-audit (default runlevel, `after *`
# — run LAST before the login prompt) SOURCES this module and calls
# aud_service_main — the §8.1 machine/lib entrance rule: machine scripts NEVER
# exec the `alpine-fde` CLI. The comparison itself is the SAME logic the CLI
# path runs (aud_pcr_report / aud_sb_report / aud_fw_report /
# aud_eventlog_report / aud_sbverify_report) — one implementation, two doors.
#
# artifacts (all under ${ALPINE_FDE_ROOT}):
#   <root>/run/alpine-fde/audit-drift   the drift MARKER — its content IS the
#                                       login banner; hooks/profile.d/
#                                       alpine-fde.sh cats it at interactive
#                                       login (ALPINE_FDE_DRIFT_MARKER seam)
#   <root>/etc/issue + <root>/etc/motd  the boxed pre-login alert
# ----------------------------------------------------------------------------

AUD_ALERT_BEGIN='#--- alpine-fde-audit: drift alert BEGIN ---#'
AUD_ALERT_END='#--- alpine-fde-audit: drift alert END ---#'

# aud_drift_marker / aud_issue_file / aud_motd_file — the runtime artifact
# paths (ALPINE_FDE_ROOT seam; empty root = the guest absolute paths the
# shipped profile.d hook and docs name)
aud_drift_marker() {
    printf '%s/run/alpine-fde/audit-drift\n' "${ALPINE_FDE_ROOT:-}"
}

aud_issue_file() { printf '%s/etc/issue\n' "${ALPINE_FDE_ROOT:-}"; }
aud_motd_file() { printf '%s/etc/motd\n' "${ALPINE_FDE_ROOT:-}"; }

# aud_log — syslog only (busybox logger); a logging failure is never fatal
aud_log() { logger -t alpine-fde-audit "$*" 2>/dev/null || :; }

# aud_alert_block — the /etc/issue + /etc/motd notice (docs/UserGuide.md §5.3)
aud_alert_block() {
    cat <<EOF
$AUD_ALERT_BEGIN
*******************************************************************************
* WARNING: Alpine FDE detected firmware/platform drift on this machine!       *
* Measurements differ from /etc/alpine-fde/baseline.json                      *
* Run 'alpine-fde audit' to inspect, or 'alpine-fde audit --accept' if valid. *
*******************************************************************************
$AUD_ALERT_END
EOF
}

# aud_login_alert REPORT — the detailed interactive-login banner staged at the
# drift marker (docs/UserGuide.md §5.4); the DRIFT lines are the drifted
# checks exactly as the comparison reported them
aud_login_alert() {
    _ala_lines=$(printf '%s\n' "$1" | grep 'DRIFT' | awk '{printf "  - %s DRIFT\n", $1}')
    cat <<EOF
================================================================================
[SECURITY ALERT] Alpine FDE Firmware Drift Detected!
================================================================================
Platform measurements have drifted from the trusted baseline:
${_ala_lines:-  - platform measurements DRIFT}

If you recently updated firmware or BIOS settings, verify and accept via:
  alpine-fde audit --accept && alpine-fde reseal
Otherwise, investigate potential unauthorized firmware modification!
================================================================================
EOF
}

# aud_apply_alert FILE BLOCK — strip any PREVIOUS alert block, then prepend
# the fresh BLOCK above the operator's own content. The block is
# self-delimiting (AUD_ALERT_BEGIN/END), so the operator's issue/motd text is
# preserved across drift boots WITHOUT keeping a backup copy, and the prepend
# can never grow the file unboundedly. Staged to a temp file next to the
# target and moved into place (the aud_write_last_audit / M-3 atomic pattern).
aud_apply_alert() {
    _aaf_f=$1 _aaf_blk=$2
    [ -f "$_aaf_f" ] || { mkdir -p "${_aaf_f%/*}" 2>/dev/null || :; : >"$_aaf_f" || return 1; }
    _aaf_tmp=$(mktemp "${_aaf_f%/*}/.alpine-fde-audit.XXXXXX") || return 1
    if ! { printf '%s\n' "$_aaf_blk"; sed "/^$AUD_ALERT_BEGIN\$/,/^$AUD_ALERT_END\$/d" "$_aaf_f"; } >"$_aaf_tmp" ||
        ! mv -f "$_aaf_tmp" "$_aaf_f"; then
        rm -f "$_aaf_tmp" 2>/dev/null || :
        return 1
    fi
    return 0
}

# aud_strip_alert FILE — remove a previously written alert block (the match /
# acknowledge recovery path); rewrites the file only when a block is present
aud_strip_alert() {
    _asf_f=$1
    [ -f "$_asf_f" ] || return 0
    grep -q "^$AUD_ALERT_BEGIN\$" "$_asf_f" || return 0
    _asf_tmp=$(mktemp "${_asf_f%/*}/.alpine-fde-audit.XXXXXX") || return 1
    if ! sed "/^$AUD_ALERT_BEGIN\$/,/^$AUD_ALERT_END\$/d" "$_asf_f" >"$_asf_tmp" ||
        ! mv -f "$_asf_tmp" "$_asf_f"; then
        rm -f "$_asf_tmp" 2>/dev/null || :
        return 1
    fi
    return 0
}

# aud_clear_runtime_alert — retire a standing boot-audit alert: the drift
# marker + the issue/motd banners. Shared by the oneshot match path and the
# CLI acknowledge path (`alpine-fde audit` on a matching machine, and
# `--accept` after the re-baseline).
aud_clear_runtime_alert() {
    rm -f "$(aud_drift_marker)" 2>/dev/null || :
    aud_strip_alert "$(aud_issue_file)" || :
    aud_strip_alert "$(aud_motd_file)" || :
    return 0
}

# aud_service_main — the oneshot behavior contract (rc 0 on EVERY path — drift
# is a RESULT, never a boot failure):
#   baseline missing            -> syslog skip line, quiet, exit 0
#   baseline invalid            -> syslog skip line, quiet, exit 0
#   comparison error (TPM/ESP)  -> console WARN + syslog, exit 0; any EXISTING
#                                  drift state is left untouched (a failed
#                                  check never silently clears an alert)
#   match                       -> marker + banners REMOVED (idempotent
#                                  recovery), one syslog line, exit 0
#   drift                       -> boxed alert prepended to /etc/issue and
#                                  /etc/motd, the login banner staged at the
#                                  drift marker, every drifted check logged to
#                                  syslog, the console [WARN] block, exit 0
aud_service_main() {
    strict_mode
    _aum_bl=$(sp_baseline_file)
    if [ ! -f "$_aum_bl" ]; then
        aud_log "no baseline at $_aum_bl — boot audit skipped (provision the machine first)"
        return 0
    fi
    if ! baseline_validate "$_aum_bl"; then
        aud_log "baseline invalid: $_aum_bl — boot audit skipped"
        return 0
    fi
    # quiet-by-construction comparison: the report text is captured (stderr
    # included — die/warn stay out of the boot console on the success paths);
    # the subshell contains a die (TPM read failure maps to rc 64) and
    # propagates only its rc
    _aum_rc=0
    _aum_report=$(
        {
            aud_pcr_report "$_aum_bl"
            aud_sb_report "$_aum_bl"
            aud_fw_report "$_aum_bl"
            aud_eventlog_report "$_aum_bl"
            aud_sbverify_report
        } 2>&1
    ) || _aum_rc=$?
    if [ "$_aum_rc" -ne 0 ]; then
        warn "alpine-fde-audit: boot audit failed (rc $_aum_rc) — the check is skipped, boot is NOT blocked, existing alerts stay (details in syslog)"
        aud_log "boot audit failed (rc $_aum_rc): $(printf '%s\n' "$_aum_report" | head -n 1)"
        return 0
    fi
    if ! printf '%s\n' "$_aum_report" | grep -q 'DRIFT'; then
        aud_clear_runtime_alert
        aud_log "all checked values match the baseline"
        return 0
    fi
    _aum_marker=$(aud_drift_marker)
    mkdir -p "${_aum_marker%/*}" 2>/dev/null || :
    _aum_login=$(aud_login_alert "$_aum_report")
    _aum_tmp=$(mktemp "${_aum_marker%/*}/.alpine-fde-audit.XXXXXX") &&
        printf '%s\n' "$_aum_login" >"$_aum_tmp" &&
        mv -f "$_aum_tmp" "$_aum_marker" 2>/dev/null || :
    aud_apply_alert "$(aud_issue_file)" "$(aud_alert_block)" || aud_log "cannot write the /etc/issue alert"
    aud_apply_alert "$(aud_motd_file)" "$(aud_alert_block)" || aud_log "cannot write the /etc/motd alert"
    printf '%s\n' "$_aum_report" | grep 'DRIFT' | while IFS= read -r _aum_line; do
        aud_log "DRIFT: $_aum_line"
    done
    aud_log "firmware/platform drift detected — alerts written to /etc/issue and /etc/motd; the login banner is staged (alpine-fde audit to inspect, --accept to re-baseline)"
    # docs/UserGuide.md §5.3 — the boot-console warning block
    cat >&2 <<'EOF'
[WARN] Alpine FDE: Platform firmware drift detected during boot!
[WARN] One or more PCR measurements do not match the trusted baseline.
[WARN] Details logged to /var/log/messages; review with 'alpine-fde audit'.
EOF
    return 0
}
