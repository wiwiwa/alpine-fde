#!/bin/sh
# trust-state.sh — GROUND-TRUTH trust state (project decision queue:
# install-state.json is DEAD in the design — item 10b). There is NO persisted lifecycle
# state document: provisional vs finalized is DERIVED, on every read, from the
# facts the ceremony itself leaves behind:
#
#   * the standing LUKS2 systemd-tpm2 token's pcrs:
#       [11]    = provisional (install-time anchoring, the ADR-20 window)
#       [7, 11] = the finalized Mechanism B seal
#   * the keyslot inventory:
#       keyslot 0 = the operator's recovery passphrase (normative, §7.2)
#       keyslot 1 = the token's sealed slot (normative)
#       keyslot 2 = the TEMPORARY ephemeral install key — its PRESENCE is the
#                   install-time marker; it is purged at finalization (§9.1
#                   Stage 2), so "token {7,11} AND no ephemeral slot" is the
#                   completed shape
#   * the baseline's expected_pcr7:
#       "pending"          = install-time anchoring (captured at Stage 1)
#       a real digest      = finalized anchoring (audit --init at Stage 2/3)
#
# ts_state therefore classifies:
#   finalized    token [7,11] AND no ephemeral keyslot AND baseline final
#   provisional  token [11] — or a mid-completion crash shape (token [7,11]
#                with the ephemeral keyslot still present: the purge/upgrade
#                loop is per-member and crash-idempotent, §9.1)
#   unknown      anything else (no token, exotic pcrs, unreadable metadata,
#                contradictory baseline) — every consumer fails CLOSED on it
#
# Also owns the ADR-8 Stage-2 ATTEMPT MARKER (a best-effort diagnostic file,
# NOT lifecycle state: it records "finalization was ATTEMPTED and failed"
# with the reason — a fact no ground-truth read can reconstruct. It is never
# consulted for trust decisions; the advisory names it for the operator).
#
# Library only: sourcing has no side effects.

if [ -n "${ALPINE_FDE_TRUST_STATE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_TRUST_STATE_LOADED=1

# Pull in common.sh (exit codes, logging) and baseline.sh (sp_etc_dir +
# baseline_is_final + the luks_json_* parsers) the same way the cmd files
# resolve their siblings. When this file lives at <tree>/lib/trust-state.sh,
# the cmd dir is <tree>/lib/cmd.
_ts_cmd_dir=${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_ts_lib_dir=${_ts_cmd_dir%/*}
if [ -z "${ALPINE_FDE_COMMON_LOADED:-}" ] && [ -r "$_ts_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from ALPINE_FDE_CMD_DIR / install tree
    . "$_ts_lib_dir/common.sh"
fi
if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ] && [ -r "$_ts_lib_dir/baseline.sh" ]; then
    # shellcheck disable=SC1090
    . "$_ts_lib_dir/baseline.sh"
fi

# ts_cryptsetup — the cryptsetup seam (the same override token/reseal use)
ts_cryptsetup() { "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }

# ts_crypttab_file — <root>/etc/crypttab (ALPINE_FDE_CRYPTTAB overrides; tests)
ts_crypttab_file() {
    if [ -n "${ALPINE_FDE_CRYPTTAB:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_CRYPTTAB"
        return 0
    fi
    printf '%s/etc/crypttab\n' "${ALPINE_FDE_ROOT:-}"
}

# ts_first_member — the FIRST crypttab LUKS member as a resolvable
# /dev/disk/by-uuid path (the derivation reads ONE member: the choreography
# converges every member before the trust state can flip, §9.1). Prints the
# path; rc 1 + empty output when the crypttab has no LUKS members or the
# device is not (yet) resolvable — never dies (degrade-safe callers exist).
ts_first_member() {
    _tsf_ct=$(ts_crypttab_file)
    [ -f "$_tsf_ct" ] || return 1
    _tsf_u=$(awk '
        /^[[:space:]]*#/ { next }
        NF < 4 { next }
        $4 ~ /(^|,)luks(,|$)/ {
            if (match($2, /^UUID=[^,]*/)) { print substr($2, 6); exit }
        }
    ' "$_tsf_ct" 2>/dev/null)
    [ -n "$_tsf_u" ] || return 1
    _tsf_d="${ALPINE_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}/$_tsf_u"
    [ -e "$_tsf_d" ] || return 1
    printf '%s\n' "$_tsf_d"
}

# ts_read_meta DEV OUTFILE — quiet LUKS2 metadata dump (rc 0 iff readable).
# The REPORT-ONLY counterpart of token_dump (which dies 64): derivation
# callers classify unreadable metadata as `unknown`, never abort.
ts_read_meta() {
    ts_cryptsetup luksDump --dump-json-metadata "$1" >"$2" 2>/dev/null
}

# ts_token_pcrs META_JSON — the standing systemd-tpm2 token's tpm2-pcrs
# (jq -c form, e.g. "[11]"); empty when no token stands. Format-tolerant
# (compact single-line cryptsetup output parses like the pretty shape).
ts_token_pcrs() {
    jq -c 'first(.tokens // {} | to_entries[]
        | select(.value.type? == "systemd-tpm2")
        | .value["tpm2-pcrs"] // empty) // empty' "$1" 2>/dev/null
}

# ts_sealed_slots META_JSON — the keyslots referenced by systemd-tpm2 tokens,
# one per line (the sealed inventory)
ts_sealed_slots() {
    jq -r '(.tokens // {} | .[] | select(.type? == "systemd-tpm2")
        | .keyslots[]?) // empty' "$1" 2>/dev/null
}

# ts_ephemeral_slots META_JSON — the TEMPORARY install keyslot candidates
# (§7.2: keyslot 2; §9.1 Stage 2 purges it): the passphrase slots NOT
# referenced by any systemd-tpm2 token AND not keyslot 0 — §7.2 pins the
# operator's recovery passphrase at keyslot 0, so a non-token slot != 0 can
# only be the temporary ephemeral slot. Prints candidates one per line; empty
# when none (finalization completed / crash resume). The CALLER fails loud on
# more than one candidate (a corrupted handoff is never silently purged).
ts_ephemeral_slots() {
    _tes_meta=$1
    jq -r '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)
            | select(. != 0)] | sort | .[]' "$_tes_meta" 2>/dev/null || return 0
}

# ts_ephemeral_present META_JSON — rc 0 iff at least one temporary ephemeral
# keyslot stands (the install-time keyslot-2 marker, §7.2)
ts_ephemeral_present() {
    [ -n "$(ts_ephemeral_slots "$1")" ]
}

# ts_recovery_slot_ok META_JSON — rc 0 iff exactly ONE passphrase slot remains
# beyond the token-referenced slots and it IS keyslot 0 (the recovery slot,
# §7.2 — the amended at-rest shape after the ephemeral purge, I1)
ts_recovery_slot_ok() {
    jq -e '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)] == [0]' "$1" \
        >/dev/null 2>&1
}

# ts_state META_JSON BASELINE_FILE — the ground-truth classification
# (finalized | provisional | unknown), printed. The rules are the module
# header's; an unreadable/missing baseline counts as NOT final (fail-closed:
# the finalized verdict requires the positive baseline digest evidence).
ts_state() {
    _tst_meta=$1
    _tst_bl=$2
    _tst_pcrs=$(ts_token_pcrs "$_tst_meta")
    case $_tst_pcrs in
        '') printf 'unknown\n'; return 0 ;;
    esac
    if [ "$_tst_pcrs" = "[11]" ] || [ "$_tst_pcrs" = "[7,11]" ]; then
        # The finalized selection is PCR 11 (the pipeline speaks [11] end to
        # end); [7,11] is the legacy Mechanism B shape and stays finalized.
        # In both shapes the surviving ephemeral keyslot is the per-member
        # mid-completion crash form — still unfinalized (§9.1).
        if ts_ephemeral_present "$_tst_meta"; then
            printf 'provisional\n'
            return 0
        fi
        if [ -n "$_tst_bl" ] && [ -f "$_tst_bl" ] && baseline_is_final "$_tst_bl"; then
            printf 'finalized\n'
        else
            printf 'unknown\n'
        fi
        return 0
    fi
    printf 'unknown\n'
}

# ts_label — the degrade-safe top-level derivation for report/gate consumers:
# resolves the first crypttab member, reads its metadata, classifies against
# the host baseline. Prints finalized | provisional | unknown; EMPTY when
# there is nothing to derive from (no crypttab member, device unresolvable,
# metadata unreadable) — never dies, never warns (callers own the wording).
ts_label() {
    _tsl_dev=$(ts_first_member) || return 0
    _tsl_meta=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-tstate.XXXXXX") || return 0
    if ! ts_read_meta "$_tsl_dev" "$_tsl_meta"; then
        rm -f "$_tsl_meta"
        return 0
    fi
    ts_state "$_tsl_meta" "$(sp_baseline_file 2>/dev/null)"
    rm -f "$_tsl_meta"
}

# --- ADR-8/§9.1 Stage 2 attempt marker ------------------------------------------
# Distinguishes "finalization was ATTEMPTED and failed" from "never attempted"
# WITHOUT inventing lifecycle state (the ground truth above is the only trust
# verdict). The first-boot OpenRC service writes the marker on ANY failure
# (guard or completion step) and the completion chain clears it on success;
# `alpine-fde finalize` (Stage 3 crash-resume) writes it on its bounded-retry
# exhaustion. A separate best-effort diagnostic: nothing reads it to decide
# anything — it is named in the advisory so the operator sees WHY.

# fde_attempt_file — the marker path; ALPINE_FDE_ATTEMPT_MARKER overrides
# wholesale (tests).
fde_attempt_file() {
    if [ -n "${ALPINE_FDE_ATTEMPT_MARKER:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_ATTEMPT_MARKER"
        return 0
    fi
    printf '%s/finalize-attempt.txt\n' "$(sp_etc_dir)"
}

# fde_attempt_write REASON — (re)write the marker with the reason; atomic
# (temp + mv) and mode 600, same discipline as the baseline finalize.
fde_attempt_write() {
    _fa_reason=$1
    _fa_f=$(fde_attempt_file)
    _fa_dir=${_fa_f%/*}
    mkdir -p "$_fa_dir" || return 1
    _fa_tmp=$(mktemp "$_fa_dir/.finalize-attempt.XXXXXX") || return 1
    printf 'attempted=%s reason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_fa_reason" \
        >"$_fa_tmp" || {
        rm -f "$_fa_tmp"
        return 1
    }
    chmod 600 "$_fa_tmp"
    mv -f "$_fa_tmp" "$_fa_f" || {
        rm -f "$_fa_tmp"
        return 1
    }
    return 0
}

# fde_attempt_read — the marker content (empty when absent); report only.
fde_attempt_read() {
    _fa_f=$(fde_attempt_file)
    [ -f "$_fa_f" ] && cat "$_fa_f"
    return 0
}

# fde_attempt_present — rc 0 iff the marker exists
fde_attempt_present() {
    [ -f "$(fde_attempt_file)" ]
}

# fde_attempt_clear — remove the marker; idempotent, rc 0 always.
fde_attempt_clear() {
    rm -f "$(fde_attempt_file)" 2>/dev/null
    return 0
}

return 0
