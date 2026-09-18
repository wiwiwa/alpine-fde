#!/bin/sh
# finalize.sh — `debian-fde finalize`: first-boot trust finalization (§9.1
# Stage 3, gaps G-IL9/G-IL10); driven at boot by debian-fde-finalize.service.
#
# Install-state machine (§8.4): `installed` → `finalized`. Per state:
#   * file absent      → pre-state-machine install: loud no-op, rc 0
#   * finalized        → loud no-op ("already finalized"), rc 0
#   * installed        → proceed
#   * anything else    → fail closed (64)
# Proceeding, in order (every step idempotent/resumable — §9.1 crash
# idempotency: an interrupted run converges on the next invocation):
#   1. Secure Boot guard: fw_sb_state (READ-ONLY consumer) must report
#      secureboot=1 setup_mode=0, else exit 64 with the §9.1 instruction text.
#      ZERO enrollment attempts happen before the guard passes (§12 S-21).
#   2. Baseline: `audit --init` finalizes the pending baseline (shared cmd);
#      skipped when the baseline is already final (crash between the audit
#      and the enrollment).
#   3. Enrollment: for EVERY member UUID in <root>/etc/crypttab (finalize owns
#      per-member iteration; the storage bucket owns the crypttab FORMAT), the
#      shared ensure-once core (enrl_ensure_once) enrolls exactly once — a
#      standing token converges with ZERO TPM operations (§8.3).
#   4. Install state `finalized` is written LAST; then the audit summary and
#      the §9.1 prompt to back up /etc/debian-fde/keys/ off-machine via scp.
#
# Tool dependencies resolve through the audit/enroll internals with loud
# failures (ADR-8); finalize adds no package-manager step of its own.

if [ -n "${DEBIAN_FDE_FINALIZE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_FINALIZE_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi
if [ -z "${DEBIAN_FDE_INSTALL_STATE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../install-state.sh"
fi
if [ -z "${DEBIAN_FDE_AUDIT_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/audit.sh"
fi
if [ -z "${DEBIAN_FDE_ENROLL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/enroll-tpm.sh"
fi

# The G-IL7 build-path gate (enrl_ensure_gate_skip) refuses the ensure-once
# enrollment while the install state is not `finalized` — it protects
# `ukictl build` from Stage-1 in-chroot provisioning. Finalize is the one
# cmd that MUST enroll inside exactly that window: §9.1 keeps the state at
# `installed` until every member stands (the `finalized` write is the LAST
# mutation, so a crash never reports finalized with tokens missing). Finalize
# has already validated the same invariants up front and fail-closed harder
# (state must read exactly `installed`, SB guard, baseline final), so the
# gate is neutralized HERE ONLY — enroll-tpm.sh itself is untouched.
enrl_ensure_gate_skip() { return 1; }

finalize_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde finalize

First-boot trust finalization (§9.1 Stage 3; runs via
debian-fde-finalize.service at boot). Requires install state `installed` and
Secure Boot ON with the custom keys (secureboot=1, setup_mode=0), then:
  1. finalize the pending baseline (audit --init; skipped when already final)
  2. enroll every crypttab member container to the TPM (ensure-once)
  3. write install state `finalized` and print the backup reminder
Interrupted runs converge on the next invocation (crash idempotency, §9.1).
EOF
}

# fin_crypttab_file — <root>/etc/crypttab (DEBIAN_FDE_CRYPTTAB overrides; tests)
fin_crypttab_file() {
    if [ -n "${DEBIAN_FDE_CRYPTTAB:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_CRYPTTAB"
        return 0
    fi
    printf '%s/etc/crypttab\n' "${DEBIAN_FDE_ROOT:-}"
}

# fin_crypttab_uuids FILE — every LUKS member UUID, one per line, first-seen
# order, duplicates collapsed. Same line grammar as enroll-tpm.sh's
# enrl_crypttab_uuid (that helper exits after the FIRST match — the single-
# disk volume; finalize must reach every RAID1 member).
fin_crypttab_uuids() {
    [ -f "$1" ] || return 0
    awk '
        /^[[:space:]]*#/ { next }
        NF < 4 { next }
        $4 ~ /(^|,)luks(,|$)/ {
            if (match($2, /^UUID=[^,]*/)) {
                u = substr($2, 6)
                if (!(u in seen)) { seen[u] = 1; print u }
            }
        }
    ' "$1"
}

cmd_finalize_main() {
    strict_mode

    while [ $# -gt 0 ]; do
        case $1 in
            -h | --help)
                finalize_usage
                return 0
                ;;
            *)
                die -r "$DEBIAN_FDE_USAGE" "finalize: unknown argument: $1"
                ;;
        esac
    done

    # --- state gate (§8.4): `installed` proceeds; absent/finalized are loud
    # no-ops; anything else fails closed
    _fm_f=$(istate_file)
    if [ ! -f "$_fm_f" ]; then
        warn "finalize: no install state at $_fm_f — nothing to finalize (pre-state-machine install)"
        return 0
    fi
    _fm_state=$(istate_state)
    case $_fm_state in
        finalized)
            info "install state is already finalized ($_fm_f) — nothing to do"
            return 0
            ;;
        installed) : ;;
        *)
            die "finalize: unexpected install state '${_fm_state:-<unreadable>}' in $_fm_f — refusing (want: installed)"
            ;;
    esac

    # --- Secure Boot guard (§9.1 Stage 3): verified boot with OUR keys, or no
    # enrollment attempt happens at all — the volume stays protected by the
    # keyslot 0 recovery passphrase only (§10 first-boot row)
    _fm_sb=$(fw_sb_state) || true
    case $_fm_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "finalize: Secure Boot is not enabled with your custom keys. Reboot into BIOS setup and toggle Secure Boot ON to complete TPM enrollment. (fw_sb_state: $_fm_sb — the volume remains safely locked by the keyslot 0 recovery passphrase)"
            ;;
    esac

    # --- baseline: audit --init finalizes the pending baseline; a previous
    # run's final baseline is reused as-is (crash between audit and enrollment)
    _fm_bl=$(sp_baseline_file)
    [ -f "$_fm_bl" ] || die "finalize: no baseline at $_fm_bl — Stage 1 provisioning must write a pending baseline before finalization (§9.1)"
    baseline_validate "$_fm_bl" || die "finalize: baseline invalid: $_fm_bl"
    if baseline_is_final "$_fm_bl"; then
        info "baseline already final — skipping audit --init (resumed finalization, §9.1 crash idempotency)"
    else
        info "finalizing the baseline from live values (audit --init, §9.1 Stage 3)"
        cmd_audit_main --init
    fi

    # --- per-member enrollment: every crypttab LUKS member gets the ONE A''
    # enrollment via the shared ensure-once core; a standing token = zero TPM
    # operations (§8.3 one-enrollment invariant)
    _fm_pub=$(baseline_get_in "$_fm_bl" keys release_pub_path)
    [ -n "$_fm_pub" ] || die "finalize: baseline keys.release_pub_path is empty"
    [ -f "$_fm_pub" ] || die "finalize: release public key not found: $_fm_pub"

    _fm_ct=$(fin_crypttab_file)
    _fm_members=$(fin_crypttab_uuids "$_fm_ct")
    [ -n "$_fm_members" ] || die "finalize: no LUKS member UUIDs found in $_fm_ct — cannot finalize enrollment"

    for _fm_uuid in $_fm_members; do
        _fm_dev="$(enrl_by_uuid_dir)/$_fm_uuid"
        [ -e "$_fm_dev" ] || die "finalize: member device not resolvable: $_fm_dev — refusing to finalize a partially enrolled array"
        if ! enrl_ensure_once "$_fm_dev" "$_fm_pub"; then
            die "finalize: enrollment failed for member $_fm_uuid — install state stays 'installed'; fix the cause and re-run finalize (§9.1 crash idempotency)"
        fi
        if [ "$ENRL_ENROLLED" -eq 1 ]; then
            printf 'debian-fde: member %s: enrolled (keyslot %s, token %s)\n' \
                "$_fm_uuid" "$ENRL_SLOT" "$ENRL_TOKEN_ID" >&2
        else
            printf 'debian-fde: member %s: token already stands — no TPM operations (§8.3)\n' "$_fm_uuid" >&2
        fi
    done

    # --- the state transition is the LAST mutation (§9.1)
    istate_write finalized

    # --- audit summary + §9.1 off-machine backup prompt
    printf 'debian-fde: audit summary: baseline %s: expected_pcr7=%s secureboot=%s setup_mode=%s\n' \
        "$_fm_bl" \
        "$(baseline_get "$_fm_bl" expected_pcr7)" \
        "$(baseline_get_in "$_fm_bl" sb_state secure_boot)" \
        "$(baseline_get_in "$_fm_bl" sb_state setup_mode)" >&2
    cat >&2 <<EOF
debian-fde: install finalized — back up the key material off-machine now (§9.1):
  scp -r $(sp_etc_dir)/keys/ admin@backup-host:/secure/storage/debian-fde-backup/
EOF
    return 0
}

return 0
