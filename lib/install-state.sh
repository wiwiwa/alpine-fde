#!/bin/sh
# install-state.sh — /etc/alpine-fde/install-state.json: the install ceremony
# state machine (§8.4, §9.1, ADR-20; gaps G-IL1/G-D11). The vocabulary is
# exactly `installed` → `provisional-booted` → `finalized`:
#
#   `installed`            Stage 1 done (unattended in-chroot provisioning +
#                          provisional PCR-11 seal + direct reboot pending);
#                          volume protected by the ephemeral install key plus
#                          the provisional token
#   `provisional-booted`   Stage 2 done (first boot unlocked via the
#                          provisional token; Secure Boot verified ON by the
#                          first-boot service); MOTD warning banner active;
#                          awaiting `alpine-fde finalize`
#   `finalized`            Stage 3 done (recovery passphrase set, release.pem
#                          encrypted, Secure Boot verified, baseline final,
#                          {PCR 7, PCR 11} Mechanism B token standing for
#                          every crypttab member, MOTD cleared)
#
# Document schema v1 (every value quoted except schema_version):
#   { "schema_version": 1, "state": "installed|provisional-booted|finalized", "updated_at": "<ISO8601 UTC>" }
#
# Writes are ATOMIC (temp document next to the target + mv) so a crash
# mid-write leaves the previous state readable — the §9.1 crash idempotency
# depends on it. Library only: sourcing has no side effects.
#
# Also owns the ADR-20 unfinalized MOTD warning banner helpers
# (fde_motd_banner / fde_motd_strip): `install` drops the banner into
# /etc/motd + /etc/issue at Stage 1 step 8; `finalize` strips the exact same
# line at Stage 3 step 4. Single source here so the two commands can never
# drift apart.

if [ -n "${DEBIAN_FDE_INSTALL_STATE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_INSTALL_STATE_LOADED=1

# Pull in common.sh (exit codes, logging) and baseline.sh (sp_etc_dir) the
# same way the cmd files resolve their siblings. When this file lives at
# <tree>/lib/install-state.sh, the cmd dir is <tree>/lib/cmd.
_is_cmd_dir=${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_is_lib_dir=${_is_cmd_dir%/*}
if [ -z "${DEBIAN_FDE_COMMON_LOADED:-}" ] && [ -r "$_is_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from DEBIAN_FDE_CMD_DIR / install tree
    . "$_is_lib_dir/common.sh"
fi
if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ] && [ -r "$_is_lib_dir/baseline.sh" ]; then
    # shellcheck disable=SC1090
    . "$_is_lib_dir/baseline.sh"
fi

# istate_file — $(sp_etc_dir)/install-state.json; DEBIAN_FDE_INSTALL_STATE
# overrides the path wholesale (tests).
istate_file() {
    if [ -n "${DEBIAN_FDE_INSTALL_STATE:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_INSTALL_STATE"
        return 0
    fi
    printf '%s/install-state.json\n' "$(sp_etc_dir)"
}

# istate_get FILE KEY — top-level scalar value (fixed 2-space layout, same
# parser style as baseline_get); empty when absent
istate_get() {
    sed -n "s/^  \"$2\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1"
}

# istate_state [FILE] — print the state value; empty + warn when the document
# is absent (pre-state-machine installs) or carries no readable state. An
# explicit FILE argument is read as-is (consumed by enroll-tpm.sh's G-IL7
# install-state reader); without one the path resolves via istate_file.
# Report only: rc 0, the CALLER decides what empty/garbage means.
# shellcheck disable=SC2120  # the FILE arg is passed by external consumers (enroll-tpm.sh G-IL7 reader, tests)
istate_state() {
    if [ -n "${1:-}" ]; then
        _is_f=$1
    else
        _is_f=$(istate_file)
    fi
    if [ ! -f "$_is_f" ]; then
        warn "install-state: no state file at $_is_f (pre-state-machine install?)"
        return 0
    fi
    _is_s=$(istate_get "$_is_f" state)
    if [ -z "$_is_s" ]; then
        warn "install-state: no readable state in $_is_f"
        return 0
    fi
    printf '%s\n' "$_is_s"
}

# istate_is_finalized — rc 0 iff the state reads exactly `finalized`
istate_is_finalized() {
    [ "$(istate_state 2>/dev/null)" = "finalized" ]
}

# istate_is_provisional_booted — rc 0 iff the state reads exactly
# `provisional-booted` (Stage 2 done, finalize pending — the ADR-20 window
# `finalize` and `status` must recognize)
istate_is_provisional_booted() {
    [ "$(istate_state 2>/dev/null)" = "provisional-booted" ]
}

# istate_write STATE — validate (installed|provisional-booted|finalized,
# fail-closed 64 on anything else) and atomically install the state document
# (temp next to the target + chmod 600 BEFORE the rename — no partial
# document, no umask window; same pattern as enrl_record / baseline finalize).
istate_write() {
    _is_new=$1
    case $_is_new in
        installed | provisional-booted | finalized) : ;;
        *)
            die "istate_write: unknown install state '$_is_new' (want: installed|provisional-booted|finalized)"
            ;;
    esac
    _is_f=$(istate_file)
    _is_dir=${_is_f%/*}
    if ! mkdir -p "$_is_dir"; then
        die "istate_write: cannot create state directory $_is_dir"
    fi
    _is_tmp=$(mktemp "$_is_dir/.install-state.XXXXXX") || {
        die "istate_write: cannot create temp document in $_is_dir"
    }
    {
        printf '{\n'
        printf '  "schema_version": 1,\n'
        printf '  "state": "%s",\n' "$_is_new"
        printf '  "updated_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '}\n'
    } >"$_is_tmp" || {
        rm -f "$_is_tmp"
        die "istate_write: cannot write temp document in $_is_dir"
    }
    chmod 600 "$_is_tmp"
    if ! mv -f "$_is_tmp" "$_is_f"; then
        rm -f "$_is_tmp"
        die "istate_write: atomic replace of $_is_f failed"
    fi
    return 0
}

# --- ADR-8/§9.1 Stage 2 attempt marker ------------------------------------------
# Distinguishes "finalization was ATTEMPTED and failed" from "never attempted"
# without extending the canonical state vocabulary (the machine stays exactly
# installed -> provisional-booted -> finalized). The first-boot OpenRC service
# writes the marker on ANY failure (guard or completion step) and the
# completion chain clears it when `finalized` is written; `alpine-fde
# finalize` (Stage 3 crash-resume) writes it on its bounded-retry exhaustion.
# A separate best-effort file — the state document's vocabulary is never
# widened by a transient failure.

# istate_attempt_file — the marker path; DEBIAN_FDE_INSTALL_ATTEMPT overrides
# wholesale (tests).
istate_attempt_file() {
    if [ -n "${DEBIAN_FDE_INSTALL_ATTEMPT:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_INSTALL_ATTEMPT"
        return 0
    fi
    printf '%s/finalize-attempt.txt\n' "$(sp_etc_dir)"
}

# istate_attempt_write REASON — (re)write the marker with the reason; atomic
# (temp + mv) and mode 600, same discipline as istate_write.
istate_attempt_write() {
    _ia_reason=$1
    _ia_f=$(istate_attempt_file)
    _ia_dir=${_ia_f%/*}
    mkdir -p "$_ia_dir" || return 1
    _ia_tmp=$(mktemp "$_ia_dir/.finalize-attempt.XXXXXX") || return 1
    printf 'attempted=%s reason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_ia_reason" \
        >"$_ia_tmp" || {
        rm -f "$_ia_tmp"
        return 1
    }
    chmod 600 "$_ia_tmp"
    mv -f "$_ia_tmp" "$_ia_f" || {
        rm -f "$_ia_tmp"
        return 1
    }
    return 0
}

# istate_attempt_read — the marker content (empty when absent); report only.
istate_attempt_read() {
    _ia_f=$(istate_attempt_file)
    [ -f "$_ia_f" ] && cat "$_ia_f"
    return 0
}

# istate_attempt_present — rc 0 iff the marker exists
istate_attempt_present() {
    [ -f "$(istate_attempt_file)" ]
}

# istate_attempt_clear — remove the marker; idempotent, rc 0 always.
istate_attempt_clear() {
    rm -f "$(istate_attempt_file)" 2>/dev/null
    return 0
}

# --- ADR-20 unfinalized MOTD warning banner (Stage 1 step 8 / Stage 3 step 4) ---
# The banner is ONE exact line so it can be dropped by `install` and stripped
# line-exactly by `finalize` without ever touching operator content around it.

# fde_motd_banner — print the unfinalized warning banner (single source;
# consumed by `install` (write) and `finalize` (strip))
fde_motd_banner() {
    printf '%s\n' \
        'WARNING: Alpine FDE trust is NOT finalized. This system boots via a provisional auto-unlock seal (PCR 11 only). Run "alpine-fde finalize" to set your permanent recovery passphrase, verify Secure Boot, and complete TPM enrollment. Until then, treat this machine as untrusted.'
}

# fde_motd_strip FILE — remove the banner line from FILE (other content
# preserved byte-for-byte); missing FILE is a silent no-op; the rewrite is
# atomic (temp next to the target + mv). rc 0 always: a banner that cannot be
# stripped (unreadable file) is reported by the CALLER, never a hard stop —
# the trust state lives in install-state.json, not in the MOTD.
fde_motd_strip() {
    _fms_f=$1
    [ -n "$_fms_f" ] && [ -f "$_fms_f" ] || return 0
    _fms_dir=${_fms_f%/*}
    _fms_tmp=$(mktemp "$_fms_dir/.debian-fde-motd.XXXXXX") || return 0
    grep -F -v -x -- "$(fde_motd_banner)" "$_fms_f" >"$_fms_tmp" 2>/dev/null
    mv -f "$_fms_tmp" "$_fms_f" 2>/dev/null || {
        rm -f "$_fms_tmp"
        return 0
    }
    return 0
}

return 0
