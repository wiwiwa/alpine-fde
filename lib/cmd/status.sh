#!/bin/sh
# status.sh — `debian-fde status`: read-only snapshot (§8.1; C-G14): Secure Boot
# state, PCR readings vs baseline, LUKS2 token summary, boot entries, manifest
# freshness, last audit, last enrollment. Report only — always exits 0 unless
# a runtime error occurs (die, fail-closed 64); drift is shown, not enforced
# (that is `audit`'s job).

if [ -n "${DEBIAN_FDE_STATUS_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_STATUS_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi
if [ -z "${DEBIAN_FDE_ESP_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../esp.sh"
fi
if [ -z "${DEBIAN_FDE_INSTALL_STATE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../install-state.sh"
fi

status_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde status

Snapshot: Secure Boot state, PCRs vs baseline, LUKS2 systemd-tpm2 tokens,
bootctl entries, digest manifest freshness, last enrollment, last audit.
Report only; exit 0.
EOF
}

# st_baseline_pcr BASELINE IDX — baseline value for pcr idx (7 → expected_pcr7)
st_baseline_pcr() {
    if [ "$2" = "7" ]; then
        baseline_get "$1" expected_pcr7
    else
        baseline_get "$1" "pcr$2"
    fi
}

# st_pcr_line IDX BASELINE — one "pcrN live/base verdict" line (no TPM = error)
st_pcr_line() {
    _spl_i=$1 _spl_bl=$2
    _spl_base=$(st_baseline_pcr "$_spl_bl" "$_spl_i") || _spl_base=''
    if ! _spl_live=$(tpm_pcr_read "$_spl_i") || [ -z "$_spl_live" ]; then
        printf 'pcr%-2s <unreadable>\n' "$_spl_i"
        return 0
    fi
    case $_spl_base in
        pending) printf 'pcr%-2s live=%s base=pending\n' "$_spl_i" "$_spl_live" ;;
        '') printf 'pcr%-2s live=%s base=<no baseline>\n' "$_spl_i" "$_spl_live" ;;
        "$_spl_live") printf 'pcr%-2s live=%s base=%s  match\n' "$_spl_i" "$_spl_live" "$_spl_base" ;;
        *) printf 'pcr%-2s live=%s base=%s  DRIFT\n' "$_spl_i" "$_spl_live" "$_spl_base" ;;
    esac
}

# st_manifest_kvers FILE — kernel_version values from digests.json, one per
# line. sed parse (status stays jq-free); manifest entries are jq-pretty-printed
# with one field per line — same fixed-layout parsing style as baseline_get.
st_manifest_kvers() {
    sed -n 's/^.*"kernel_version": *"\([^"]*\)".*/\1/p' "$1"
}

# st_token_pcrs FILE — "tpm2-pcrs" of the first systemd-tpm2 token, joined
# with commas (e.g. "7" / "7,11"); empty when absent. jq-based (format-
# tolerant: real cryptsetup emits compact JSON — see tests/unit/luks_json_parsers.sh).
st_token_pcrs() {
    jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2")
        | .value["tpm2-pcrs"] // [] | join(",")) // empty' "$1" 2>/dev/null
}

# st_token_pubkey_fp FILE — "sha256:<hex>" of the first systemd-tpm2 token's
# tpm2-public-key (base64 DER in the token JSON); rc 1 when the token carries
# no public key. Display-only per I3 — the token is untrusted input.
st_token_pubkey_fp() {
    _stf_b64=$(jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2")
        | .value["tpm2-public-key"]? // empty)' "$1" 2>/dev/null | head -n1) || return 1
    [ -n "$_stf_b64" ] || return 1
    # L-3: a base64 -d failure must not hash leftover/empty bytes into a
    # plausible-looking fingerprint — a tampered/corrupt token would otherwise
    # display as a valid-looking diagnostic (display-only per I3, but honest).
    # (Decode checked on its own: capturing the decoded bytes through "$()"
    # would strip meaningful trailing newline bytes before hashing.)
    if ! printf '%s' "$_stf_b64" | base64 -d >/dev/null 2>&1; then
        printf 'token pubkey fp: <undecodable>\n'
        return 1
    fi
    printf 'sha256:%s\n' "$(printf '%s' "$_stf_b64" | base64 -d 2>/dev/null | sha256sum | cut -d' ' -f1)"
}

cmd_status_main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        status_usage
        return 0
    fi
    [ $# -eq 0 ] || die -r "$DEBIAN_FDE_USAGE" "status: unexpected arguments: $*"

    _st_bl=$(sp_baseline_file)
    # Install-state row (§8.1/§9.1, G-IL12): the lifecycle headline. SILENT for
    # pre-state-machine installs (no state file), a quiet line when finalized,
    # PROMINENT warnings + the resume hint while the ceremony is unfinished —
    # state=installed (Stage 1 done in-chroot; Stage-2 finalization pending)
    # or state=provisional-booted (ADR-20 as amended: first boot done via the
    # provisional PCR-11-only token; the recovery passphrase is already set,
    # the {7,11} token upgrade + ephemeral purge are not). Report-only: rc 0.
    _st_isf=$(istate_file)
    if [ -f "$_st_isf" ]; then
        printf '== Install state\n'
        _st_is=$(istate_state)
        case $_st_is in
            installed)
                printf '    WARNING: installation is NOT finalized (install state: installed)\n'
                printf '    The alpine-fde-finalize OpenRC service completes finalization\n'
                printf '    automatically on next boot; to resume manually now:\n'
                printf '    alpine-fde finalize\n'
                ;;
            provisional-booted)
                printf '    WARNING: PROVISIONAL trust window ACTIVE (install state: provisional-booted)\n'
                printf '    First boot unlocked via the ADR-20 provisional token (PCR 11 only);\n'
                printf '    the recovery passphrase is set, but the {7,11} token upgrade and\n'
                printf '    ephemeral keyslot purge are pending. The service retries next\n'
                printf '    boot; to crash-resume manually now:\n'
                printf '    alpine-fde finalize\n'
                ;;
            finalized)
                printf '    install state: finalized\n'
                ;;
            *)
                printf '    WARNING: unreadable install state in %s\n' "$_st_isf"
                ;;
        esac
        printf '\n'
    fi

    printf '== Secure Boot (efivars: %s)\n' "$(fw_efivars_dir)"
    if _st_sb=$(fw_sb_state); then
        printf '    %s\n' "$_st_sb"
    else
        printf '    %s (not confirmed on)\n' "$_st_sb"
    fi

    printf '\n== PCRs vs baseline\n'
    if [ -f "$_st_bl" ] && baseline_validate "$_st_bl"; then
        for _st_i in 0 1 2 3 7; do
            printf '    '
            st_pcr_line "$_st_i" "$_st_bl"
        done
    else
        printf '    baseline missing/invalid: %s\n' "$_st_bl"
    fi

    printf '\n== LUKS2 tokens\n'
    _st_uuid=$(baseline_get_in "$_st_bl" target luks_uuid 2>/dev/null) || _st_uuid=''
    if [ -n "$_st_uuid" ] && [ -e "${DEBIAN_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}/$_st_uuid" ] \
        && command -v "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" >/dev/null 2>&1; then
        _st_dev="${DEBIAN_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}/$_st_uuid"
        # L-5: an unwritable TMPDIR must not abort the read-only report with
        # rc 1 (outside the 0/2/64 contract) — skip the section loudly instead.
        if ! _st_json=$(mktemp "${TMPDIR:-/tmp}/debian-fde-status.XXXXXX"); then
            printf '    mktemp failed — LUKS2 token section skipped (TMPDIR: %s)\n' "${TMPDIR:-/tmp}"
            _st_json=''
        fi
        if [ -n "$_st_json" ]; then
            if "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" luksDump --dump-json-metadata "$_st_dev" >"$_st_json" 2>/dev/null; then
                printf '    luks uuid: %s\n' "$_st_uuid"
                printf '    systemd-tpm2 tokens: %s\n' "$(luks_json_count_type "$_st_json" systemd-tpm2)"
                _st_slot=$(luks_json_token_keyslot "$_st_json" systemd-tpm2)
                [ -n "$_st_slot" ] && printf '    token keyslot: %s\n' "$_st_slot"
                # token display fields (I3: display-only — the token JSON is
                # untrusted input, shown for diagnosis, never verified against)
                _st_pcrs=$(st_token_pcrs "$_st_json")
                [ -n "$_st_pcrs" ] && printf '    token pcrs: %s\n' "$_st_pcrs"
                if _st_fp=$(st_token_pubkey_fp "$_st_json"); then
                    printf '    token pubkey fp: %s\n' "$_st_fp"
                elif [ -n "$_st_fp" ]; then
                    # L-3: the function already printed the "<undecodable>" line
                    printf '    %s\n' "$_st_fp"
                fi
                printf '    keyslots present: '
                for _st_s in 0 1 2 3 4 5 6 7; do
                    [ -n "$(luks_json_slot_blob "$_st_json" "$_st_s")" ] && printf '%s ' "$_st_s"
                done
                printf '\n'
            else
                printf '    luksDump failed for %s\n' "$_st_dev"
            fi
            rm -f "$_st_json"
        fi
    else
        printf '    (LUKS device unknown or cryptsetup unavailable)\n'
    fi

    printf '\n== Boot entries\n'
    if command -v "${DEBIAN_FDE_BOOTCTL:-bootctl}" >/dev/null 2>&1; then
        "${DEBIAN_FDE_BOOTCTL:-bootctl}" list --no-legend 2>/dev/null | sed 's/^/    /' \
            || printf '    bootctl list failed\n'
    else
        printf '    bootctl not found\n'
    fi

    printf '\n== Digest manifest (ukictl build)\n'
    _st_mf=$(sp_manifest_file)
    if [ -f "$_st_mf" ]; then
        printf '    %s\n' "$_st_mf"
        printf '    kernel entries: %s\n' "$(grep -c '"kernel_version"' "$_st_mf")"
        printf '    updated: %s\n' "$(date -u -r "$_st_mf" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf '?')"
        # per-kernel manifest-vs-ESP diff (§8.1 status row): every manifest
        # entry must have its UKI on the ESP and vice versa — a MISSING entry
        # means a manifest kernel has no bootable image, an EXTRA file means an
        # unsigned/unmanaged UKI boots outside the signed flow. Findings are
        # REPORTED only; exit stays 0 (drift enforcement is audit's job).
        printf '    manifest vs ESP (%s):\n' "$(esp_uki_dir)"
        for _st_k in $(st_manifest_kvers "$_st_mf"); do
            if [ -f "$(esp_uki_path "$_st_k")" ]; then
                printf '      %s  OK\n' "$_st_k"
            else
                printf '      %s  MISSING (manifest entry, no UKI on ESP)\n' "$_st_k"
            fi
        done
        for _st_k in $(esp_list_kvers); do
            _st_extra=1
            for _st_mk in $(st_manifest_kvers "$_st_mf"); do
                if [ "$_st_k" = "$_st_mk" ]; then
                    _st_extra=0
                    break
                fi
            done
            if [ "$_st_extra" -eq 1 ]; then
                printf '      %s  EXTRA (UKI on ESP, no manifest entry)\n' "$_st_k"
            fi
        done
    else
        printf '    missing (%s) — no UKI built yet?\n' "$_st_mf"
    fi

    printf '\n== ESP boot binaries (sbverify)\n'
    sbverify_boot_binaries | sed 's/^/    /'

    printf '\n== Build status\n'
    _st_bf=$(sp_etc_dir)/build-failed
    if [ -f "$_st_bf" ]; then
        printf '    FAILED BUILD MARKER PRESENT (%s):\n' "$_st_bf"
        sed 's/^/      /' "$_st_bf"
        printf '    attach the signing medium and re-run: debian-fde ukictl build (§9.2)\n'
    else
        printf '    ok (no failure marker)\n'
    fi

    printf '\n== Last enrollment\n'
    _st_ef=$(sp_enrolled_file)
    if [ -f "$_st_ef" ]; then
        printf '    keyslot: %s mode: %s wipe: %s at: %s\n' \
            "$(baseline_get "$_st_ef" token_keyslot 2>/dev/null)" \
            "$(baseline_get "$_st_ef" policy_mode 2>/dev/null)" \
            "$(baseline_get "$_st_ef" wipe_slot 2>/dev/null)" \
            "$(baseline_get "$_st_ef" enrolled_at 2>/dev/null)"
    else
        printf '    none recorded (%s)\n' "$_st_ef"
    fi

    printf '\n== Last audit\n'
    _st_af=$(sp_last_audit_file)
    if [ -f "$_st_af" ]; then
        printf '    result: %s accepted: %s at: %s\n' \
            "$(baseline_get "$_st_af" result 2>/dev/null)" \
            "$(baseline_get "$_st_af" accepted 2>/dev/null)" \
            "$(baseline_get "$_st_af" audited_at 2>/dev/null)"
    else
        printf '    none recorded (%s)\n' "$_st_af"
    fi
    return 0
}
