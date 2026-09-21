#!/bin/sh
# audit.sh — `debian-fde audit`: compare live PCR 0..3+7, Secure Boot state and
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

if [ -n "${DEBIAN_FDE_AUDIT_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_AUDIT_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

audit_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde audit [--init | --accept | --yes]

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
            die "audit: cannot read live PCR $_apr_i (TCTI: ${DEBIAN_FDE_TCTI:-<default>})"
        fi
        case $_apr_base in
            pending)
                printf 'pcr%-2s live=%s baseline=pending   (finalize with: debian-fde audit --init)\n' "$_apr_i" "$_apr_live"
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
        warn "eventlog present at $(eventlog_path) but the baseline records none — §9.5 v1 tripwire NOT armed (finalize with: debian-fde audit --init)"
        printf 'eventlog sha256=%s size=%s   not recorded (finalize with --init)\n' "$_aer_live_sha" "$_aer_live_sz"
        return 0
    fi
    _aer_base_sz=$(baseline_get_in "$_aer_bl" fw eventlog_size)
    if [ "$_aer_live_sha" = "$_aer_base_sha" ]; then
        printf 'eventlog sha256=%s size=%s   match\n' "$_aer_live_sha" "$_aer_live_sz"
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
  debian-fde audit --accept      # re-baseline (operator confirmation)
  debian-fde enroll-tpm          # re-enroll — ONE cryptenroll covers all retained UKIs;
                                 # cryptenroll re-captures the new CURRENT PCR 7 into
                                 # the static policy (A″: no signing medium needed, the
                                 # UKIs' signatures stay untouched; §9.4)
EOF
}

# aud_write_last_audit FILE BASELINE RESULT ACCEPTED — last-audit.json
aud_write_last_audit() {
    _aw_f=$1 _aw_bl=$2 _aw_result=$3 _aw_acc=$4
    _aw_dir=${_aw_f%/*}
    mkdir -p "$_aw_dir"
    cat >"$_aw_f" <<EOF
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
    chmod 600 "$_aw_f"
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
                DEBIAN_FDE_YES=1
                ;;
            -h | --help)
                audit_usage
                return 0
                ;;
            *) die -r "$DEBIAN_FDE_USAGE" "audit: unknown argument: $1" ;;
        esac
        shift
    done

    require_pkgs tpm2:tpm2-tools
    _am_bl=$(sp_baseline_file)
    [ -f "$_am_bl" ] || die "audit: no baseline at $_am_bl (run 'debian-fde provision stage1')"
    baseline_validate "$_am_bl" || die "audit: baseline invalid: $_am_bl"
    tpm_available || die "audit: no TPM reachable via TCTI '${DEBIAN_FDE_TCTI:-<default>}'"

    if [ "$_am_init" -eq 1 ]; then
        if baseline_is_final "$_am_bl"; then
            die "audit: baseline already finalized (use 'audit --accept' to re-baseline)"
        fi
        info "finalizing pending baseline from live values (first boot in the final SB state)"
        baseline_finalize_from_live
        aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" ok no
        printf 'debian-fde: baseline finalized: %s\n' "$_am_bl" >&2
        return 0
    fi

    aud_pcr_report "$_am_bl"
    aud_sb_report "$_am_bl"
    aud_eventlog_report "$_am_bl"
    aud_sbverify_report

    if [ "$AUD_DRIFT" -eq 1 ]; then
        aud_next_steps
    fi

    if [ "$_am_accept" -eq 1 ]; then
        if [ -z "${DEBIAN_FDE_YES:-}" ]; then
            printf 'debian-fde: re-baseline (overwrite baseline.json with live values)? type ACCEPT: ' >&2
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
        aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" ok yes
        printf 'debian-fde: baseline re-baselined from live values (accepted); %s updated\n' "$_am_bl" >&2
        return 0
    fi

    aud_write_last_audit "$(sp_last_audit_file)" "$_am_bl" \
        "$([ "$AUD_DRIFT" -eq 1 ] && printf drift || printf ok)" no
    if [ "$AUD_DRIFT" -eq 1 ]; then
        return "$DEBIAN_FDE_DRIFT"
    fi
    printf 'debian-fde: all checked values match the baseline\n' >&2
    return 0
}
