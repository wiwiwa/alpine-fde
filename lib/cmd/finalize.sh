#!/bin/sh
# finalize.sh — `alpine-fde finalize` (Stage 3: guided / crash-resume) AND
# fin_service_main (Stage 2: the NON-INTERACTIVE first-boot auto-finalizer the
# OpenRC oneshot hooks/openrc/alpine-fde-finalize runs), per the AMENDED
# ADR-20 lifecycle (§8.1 finalize row; §9.1 Stage 2/3; §7.2 keyslot table).
#
# KEYSLOT CHOREOGRAPHY (AMENDED — §7.2 keyslot table + §9.1; this reconciles
# and REPLACES the old "keyslot 0 = ephemeral handoff" notes): the §9.1
# step 4 credential ceremony during Stage 1 already left the handoff shape
#   keyslot 0 = the OPERATOR'S RECOVERY PASSPHRASE (Argon2id, §13-floored)
#   keyslot 1 = the PROVISIONAL token slot (Mechanism B, PCR 11 only)
#   keyslot 2 = the TEMPORARY ephemeral install key — purged at completion
# There is NO key handoff to finalize (the old DEBIAN_FDE_LUKS_KEYFILE /
# ephemeral-keyfile seam is RETIRED):
#   * Stage 3 (guided) is authorized by the OPERATOR'S RECOVERY PASSPHRASE —
#     verified against keyslot 0 (no-echo prompt or the documented
#     ALPINE_FDE_RECOVERY_PASSPHRASE seam); a wrong passphrase is a BOUNDED
#     retry (3 attempts) then die 64 + the ADR-8 attempt marker.
#   * Stage 2 (service) is authorized by RE-UNSEALING the standing provisional
#     token in USERSPACE (lib/seal.sh seal_unseal over the live PCRs with the
#     UKI's .pcrsig) — never by stored credentials.
#
# The completion chain (§9.1 Stage 2 == Stage 3; fin_completion_steps):
#   Secure Boot guard (secureboot=1 AND setup_mode=0, else fail-closed 64 /
#   advisory+retry) -> audit --init (crash-skip when the baseline is already
#   final) -> for EVERY member: TEMPORARY ephemeral keyslot purge (crash-skip
#   when absent; §9.1 Stage 2 step 4) THEN the token upgrade to {PCR 7, PCR 11}
#   (crash-skip when a standing token is already {7,11}; §9.1 Stage 2 step 3).
#   The purge runs FIRST because the re-unsealed provisional credential
#   authorizes both keyslot mutations and stops verifying once the upgrade
#   retires the provisional keyslot — see the ORDER CONSTRAINT at the loop.
#   Afterwards: ADR-8 marker clear -> state `finalized` written LAST (I1's
#   two-keyslot at-rest state holds). ADR-20 #4: there is NO MOTD/issue
#   banner step — the unfinalized-banner path is removed (no banners, no
#   manual commands; install no longer writes one either).
#   Every step is crash-idempotent (§9.1: interrupted runs converge on the
#   next boot / invocation).
#
# Credential seams (scripting/CI; interactive fallbacks are the guided path):
#   ALPINE_FDE_RECOVERY_PASSPHRASE  the keyslot-0 recovery passphrase for the
#                                   guided Stage 3 (else double no-echo prompt)
#   ALPINE_FDE_PCRSIG               a release-key-signed {7,11} .pcrsig for
#                                   the token upgrade (else the policy is
#                                   re-signed in-process from the keydir's
#                                   release.pem over the live PCRs, §9.4 —
#                                   in the Stage 2 service a locked
#                                   release.pem fails CLOSED: advisory +
#                                   attempt marker + retry next boot)
#
# Tool dependencies resolve through the audit/seal internals with loud
# failures (ADR-8); finalize adds no package-manager step of its own.

if [ -n "${ALPINE_FDE_FINALIZE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_FINALIZE_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi
if [ -z "${ALPINE_FDE_INSTALL_STATE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../install-state.sh"
fi
if [ -z "${ALPINE_FDE_AUDIT_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/audit.sh"
fi
if [ -z "${ALPINE_FDE_ENROLL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/enroll-tpm.sh"
fi
if [ -z "${ALPINE_FDE_SEAL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../seal.sh"
fi
if [ -z "${ALPINE_FDE_KEYS_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../keys.sh"
fi
if ! command -v passphrase_floor_ok >/dev/null 2>&1; then
    # the §13 entropy floor (§9.1) lives in lib/cmd/rotate.sh (shared with
    # `rotate` and keys_encrypt_release)
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/rotate.sh"
fi

finalize_usage() {
    cat >&2 <<'EOF'
Usage: alpine-fde finalize

Trust finalization (§8.1 finalize row; §9.1 Stage 3; ADR-20 amended). Requires
install state `installed` or `provisional-booted` and Secure Boot ON with the
custom keys (secureboot=1, setup_mode=0). The recovery passphrase set during
the Stage-1 credential ceremony (keyslot 0) authorizes everything — you are
prompted for it (no-echo; a wrong passphrase is retried up to 3 times).
Guided steps, in order:
  1. verify the recovery passphrase against keyslot 0 (bounded retry; ADR-8
      marker on exhaustion)
  2. ensure release.pem is encrypted (AES-256 PBKDF2, ADR-18; skipped when the
      Stage-1 ceremony already encrypted it) and chmod 0400
  3. verify Secure Boot is active (no enrollment under an unverified boot)
  4. capture the baseline (audit --init; skipped when already final)
  5. purge the temporary ephemeral install keyslot from every member
      (§9.1 Stage 2 step 4; authorized by the same credential while it still
      verifies — see the ORDER CONSTRAINT in fin_completion_steps)
  6. upgrade every crypttab member's token to Mechanism B {PCR 7, PCR 11}
      (I1's two-keyslot at-rest state)
  7. write install state `finalized` and print the backup reminder
      (ADR-20 #4: no banner step — /etc/motd and /etc/issue are never touched)
Interrupted runs converge on the next invocation (crash idempotency, §9.1).
EOF
}

# fin_crypttab_file — <root>/etc/crypttab (ALPINE_FDE_CRYPTTAB overrides; tests)
fin_crypttab_file() {
    if [ -n "${ALPINE_FDE_CRYPTTAB:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_CRYPTTAB"
        return 0
    fi
    printf '%s/etc/crypttab\n' "${ALPINE_FDE_ROOT:-}"
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

# fin_cryptsetup — the cryptsetup seam (same override enroll-tpm/token.sh use)
fin_cryptsetup() { "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }

# fin_member_devs — every crypttab LUKS member as a resolvable
# /dev/disk/by-uuid path, one per line. ANY unresolvable member is a loud die:
# finalize never operates on a partial array.
fin_member_devs() {
    _fmd_ct=$(fin_crypttab_file)
    _fmd_uuids=$(fin_crypttab_uuids "$_fmd_ct")
    [ -n "$_fmd_uuids" ] ||
        die "finalize: no LUKS member UUIDs found in $_fmd_ct — cannot finalize"
    for _fmd_u in $_fmd_uuids; do
        _fmd_d="$(enrl_by_uuid_dir)/$_fmd_u"
        [ -e "$_fmd_d" ] ||
            die "finalize: member device not resolvable: $_fmd_d — refusing to finalize a partial array"
        printf '%s\n' "$_fmd_d"
    done
}

# fin_recovery_verifies DEV PASS_FILE — rc 0 iff the candidate recovery
# passphrase already opens SOME keyslot (the Stage 3 authorization check and
# the crash-idempotency skip check; the recovery slot sits at keyslot 0, §7.2)
fin_recovery_verifies() {
    fin_cryptsetup open --test-passphrase "$1" \
        --key-file "$2" >/dev/null 2>&1
}

# fin_ephemeral_slots DEV META_JSON — the TEMPORARY install keyslot candidates
# (§7.2: keyslot 2; §9.1 Stage 2 step 4 purges it): the passphrase slots NOT
# referenced by any systemd-tpm2 token AND not keyslot 0 — §7.2 pins the
# operator's recovery passphrase at keyslot 0, so a non-token slot != 0 can
# only be the temporary ephemeral slot. Prints candidates one per line; empty
# when none (crash resume). The CALLER fails loud on more than one candidate
# (a corrupted handoff is never silently purged).
fin_ephemeral_slots() {
    _fes_dev=$1
    _fes_meta=$2
    jq -r '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)
            | select(. != 0)] | sort | .[]' "$_fes_meta" 2>/dev/null || return 0
}

# fin_recovery_slot_ok META_JSON — rc 0 iff exactly ONE passphrase slot remains
# beyond the token-referenced slots and it IS keyslot 0 (the recovery slot,
# §7.2 — the amended at-rest shape after the ephemeral purge, I1)
fin_recovery_slot_ok() {
    jq -e '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)] == [0]' "$1" \
        >/dev/null 2>&1
}

# fin_token_pcrs META_JSON — the standing systemd-tpm2 token's tpm2-pcrs
# (jq -c form, e.g. "[11]"); empty when no token stands
fin_token_pcrs() {
    jq -c 'first(.tokens // {} | to_entries[]
        | select(.value.type? == "systemd-tpm2")
        | .value["tpm2-pcrs"] // empty) // empty' "$1" 2>/dev/null
}

# fin_read_recovery_passphrase VAR — the keyslot-0 recovery passphrase into
# VAR: ALPINE_FDE_RECOVERY_PASSPHRASE seam, else the guided double no-echo
# prompt. Enforces the §13 entropy floor (passphrase_floor_ok) BEFORE anything
# else can happen (fail-closed 64; the floor is the same one `rotate`
# enforces).
fin_read_recovery_passphrase() {
    _frr_var=$1
    if [ -n "${ALPINE_FDE_RECOVERY_PASSPHRASE:-}" ]; then
        _frr_val=$ALPINE_FDE_RECOVERY_PASSPHRASE
    elif [ -t 0 ]; then
        _frr_p1=
        _frr_p2=
        printf 'Recovery passphrase (keyslot 0, set during the Stage-1 ceremony): ' >&2
        _frr_restore=0
        if stty -echo 2>/dev/null; then
            _frr_restore=1
        fi
        IFS= read -r _frr_p1 || _frr_p1=''
        if [ "$_frr_restore" = 1 ]; then
            stty echo 2>/dev/null
        fi
        printf '\nRepeat passphrase: ' >&2
        _frr_restore=0
        if stty -echo 2>/dev/null; then
            _frr_restore=1
        fi
        IFS= read -r _frr_p2 || _frr_p2=''
        if [ "$_frr_restore" = 1 ]; then
            stty echo 2>/dev/null
        fi
        printf '\n' >&2
        if [ -z "$_frr_p1" ] || [ "$_frr_p1" != "$_frr_p2" ]; then
            die -r "$ALPINE_FDE_USAGE" "finalize: recovery passphrases empty or do not match"
        fi
        _frr_val=$_frr_p1
        unset _frr_p1 _frr_p2
    else
        die "finalize: no recovery passphrase available — provide ALPINE_FDE_RECOVERY_PASSPHRASE or run interactively (§9.1 Stage 3)"
    fi
    if ! passphrase_floor_ok "$_frr_val"; then
        die "finalize: recovery passphrase rejected by the §13 entropy floor (>=12 chars/3 classes or >=16 chars, no common-password hits, no control characters) — refusing (T2b)"
    fi
    eval "$_frr_var=\$_frr_val"
    return 0
}

# fin_uki_pcrsig STAGE OUT — extract the .pcrsig from the ESP UKI (the Stage-1
# `ukictl build` output; the same extraction the provisional enrollment used)
# for the Stage 2 userspace re-unseal of the provisional token.
fin_uki_pcrsig() {
    _fup_stage=$1
    _fup_out=$2
    command -v objcopy >/dev/null 2>&1 || return 1
    _fup_esp=${ALPINE_FDE_ESP:-}
    if [ -z "$_fup_esp" ] && command -v esp_dir >/dev/null 2>&1; then
        _fup_esp=$(esp_dir 2>/dev/null || true)
    fi
    [ -n "$_fup_esp" ] || _fup_esp=/efi
    _fup_uki=$(ls "$_fup_esp"/EFI/Linux/alpine-fde-*.efi 2>/dev/null | head -n 1)
    [ -n "$_fup_uki" ] && [ -f "$_fup_uki" ] || return 1
    objcopy -O binary --only-section=.pcrsig "$_fup_uki" "$_fup_out" 2>/dev/null ||
        return 1
    [ -s "$_fup_out" ]
}

# fin_provisional_unseal DEV STAGE OUT_PASSFILE — §9.1 Stage 2 authorization:
# re-unseal the standing PROVISIONAL token (Mechanism B, PCR 11) in USERSPACE
# via lib/seal.sh (seal_unseal over the live PCRs with the UKI's .pcrsig).
# NEVER a stored credential. rc 0 + the provisional passphrase in OUT_PASSFILE
# (a 0600 passfile the caller scrubs).
fin_provisional_unseal() {
    _fpn_dev=$1
    _fpn_stage=$2
    _fpn_out=$3
    fin_uki_pcrsig "$_fpn_stage" "$_fpn_stage/pcrsig-prov.json" || {
        err "finalize: cannot extract the provisional .pcrsig from the ESP UKI (§9.1 Stage 2 unseal)"
        return 1
    }
    _fpn_meta=$(mktemp "$_fpn_stage/meta.XXXXXX") || return 1
    token_dump "$_fpn_dev" "$_fpn_meta" || {
        rm -f "$_fpn_meta"
        return 1
    }
    _fpn_tid=$(jq -r 'first(.tokens // {} | to_entries[]
        | select(.value.type? == "systemd-tpm2") | .key) // empty' "$_fpn_meta")
    rm -f "$_fpn_meta"
    [ -n "$_fpn_tid" ] || {
        err "finalize: $_fpn_dev: no standing systemd-tpm2 token to re-unseal (§9.1 Stage 2)"
        return 1
    }
    fin_cryptsetup token export --token-id "$_fpn_tid" "$_fpn_dev" \
        >"$_fpn_stage/token.json" 2>/dev/null || {
        err "finalize: token export failed for $_fpn_dev"
        return 1
    }
    seal_unseal "$(keys_dir)" "$_fpn_stage/pcrsig-prov.json" provisional \
        "$_fpn_stage/token.json" "$_fpn_out" || return 1
    chmod 600 "$_fpn_out" 2>/dev/null || :
    [ -s "$_fpn_out" ]
}

# fin_completion_steps AUTHFILE — the §9.1 Stage 2 == Stage 3 completion chain,
# shared verbatim by the guided command and the first-boot service (ADR-20
# amended): Secure Boot guard -> audit --init -> token upgrade {PCR 7, PCR 11}
# per member -> temporary ephemeral keyslot purge per member -> ADR-8 marker
# clear -> state `finalized` LAST (no banner step, ADR-20 #4).
# AUTHFILE is an existing valid volume credential (guided: the verified
# recovery passfile at keyslot 0; service: the re-unsealed provisional
# passfile) authorizing the upgrade's luksAddKey and the ephemeral kill.
# Deaths are loud (die 64): the guided path surfaces them directly, the
# service runs this in a failure-contained subshell.
fin_completion_steps() {
    _fcs_auth=$1
    [ -n "$_fcs_auth" ] && [ -f "$_fcs_auth" ] ||
        die "fin_completion_steps: an authorizing passfile is required"

    # --- Secure Boot guard (READ-ONLY; §9.1 Stage 2 step 2 / §12 S-21) --------
    # Verified boot with OUR keys, or no enrollment / audit / token mutation /
    # purge happens at all: the volume stays protected by the recovery
    # passphrase (keyslot 0) plus the standing seal.
    _fcs_sb=$(fw_sb_state 2>/dev/null) || true
    case $_fcs_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "finalize: Secure Boot is not enabled with your custom keys. Reboot into BIOS setup and toggle Secure Boot ON to complete trust finalization. (fw_sb_state: $_fcs_sb — no enrollment, no wiping, no baseline capture, no purge; the volume remains safely locked)"
            ;;
    esac

    # --- baseline capture (audit --init; §9.1 Stage 2 step 3) ------------------
    # A previous run's final baseline is reused as-is (crash between the audit
    # and the token upgrade).
    _fcs_bl=$(sp_baseline_file)
    [ -f "$_fcs_bl" ] ||
        die "finalize: no baseline at $_fcs_bl — Stage 1 provisioning must write a pending baseline before finalization (§9.1)"
    baseline_validate "$_fcs_bl" || die "finalize: baseline invalid: $_fcs_bl"
    if baseline_is_final "$_fcs_bl"; then
        info "baseline already final — skipping audit --init (resumed finalization, §9.1 crash idempotency)"
    else
        info "finalizing the baseline from live values (audit --init, §9.1 Stage 2/3)"
        cmd_audit_main --init
    fi

    # --- token upgrade to Mechanism B {PCR 7, PCR 11}, per member --------------
    _fcs_keydir=$(keys_dir)
    [ -n "$_fcs_keydir" ] ||
        die "finalize: no release key directory configured (set --keydir / KEY_PATH / ALPINE_FDE_KEYDIR)"
    [ -d "$_fcs_keydir" ] || die "finalize: release key directory not found: $_fcs_keydir"
    [ -f "$_fcs_keydir/release.pub" ] ||
        die "finalize: release public key not found: $_fcs_keydir/release.pub"
    _fcs_tmpdir=${ALPINE_FDE_TMPDIR:-/dev/shm}
    _fcs_stage=$(mktemp -d "$_fcs_tmpdir/alpine-fde-fin.XXXXXX") ||
        die "finalize: cannot create the staging directory in $_fcs_tmpdir"
    chmod 700 "$_fcs_stage"
    if [ -n "${ALPINE_FDE_PCRSIG:-}" ]; then
        _fcs_pcrsig=$ALPINE_FDE_PCRSIG
    else
        # in-process re-sign fallback (§9.4): needs an UNLOCKED release.pem —
        # in the amended lifecycle release.pem is already encrypted by the
        # Stage-1 ceremony, so without ALPINE_FDE_KEY_PASSPHRASE (or a
        # provided ALPINE_FDE_PCRSIG) this fails CLOSED (the service maps the
        # failure to advisory + retry next boot)
        _fcs_pcrsig=$(enrl_sign_pcrsig "$_fcs_stage" "$_fcs_keydir") ||
            die "finalize: cannot produce the signed {7,11} policy (.pcrsig) — ALPINE_FDE_PCRSIG or an unlockable release.pem is required (§9.1)"
    fi
    # --- per-member keyslot mutations (§9.1 Stage 2 steps 3-4) -----------------
    # ORDER CONSTRAINT — authorization liveness of the NON-INTERACTIVE service:
    # the re-unsealed provisional credential (AUTHFILE) authorizes BOTH
    # keyslot mutations, but it stops verifying the moment the upgrade RETIRES
    # the provisional keyslot (§7.2) — so the temporary ephemeral purge
    # (§9.1 Stage 2 step 4) runs BEFORE the token upgrade (§9.1 Stage 2 step
    # 3), per member. Each mutation is independently crash-idempotent, so the
    # reorder changes no observable end state: after BOTH, EXACTLY the
    # recovery keyslot 0 remains beyond the sealed token (I1).
    for _fcs_dev in $(fin_member_devs); do
        # (i) purge the temporary ephemeral keyslot (§9.1 Stage 2 step 4) —
        # keyslot 2 is the temporary install key; the kill is authorized by
        # AUTHFILE (a DIFFERENT keyslot — cryptsetup requires it).
        _fcs_meta=$(mktemp "$_fcs_tmpdir/alpine-fde-fin-meta.XXXXXX") ||
            die "finalize: mktemp failed"
        token_dump "$_fcs_dev" "$_fcs_meta"
        _fcs_eph=$(fin_ephemeral_slots "$_fcs_dev" "$_fcs_meta")
        rm -f "$_fcs_meta"
        case $(printf '%s' "$_fcs_eph" | grep -c .) in
            0)
                info "finalize: $(basename "$_fcs_dev"): no temporary ephemeral keyslot remains — skipping the purge (crash resume, §9.1)"
                ;;
            1)
                (token_kill_slot "$_fcs_dev" "$_fcs_eph" "$_fcs_auth") ||
                    die "finalize: $(basename "$_fcs_dev"): purging the temporary ephemeral keyslot (keyslot $_fcs_eph) failed — fix and retry (§9.1 crash idempotency)"
                info "finalize: $(basename "$_fcs_dev"): temporary ephemeral install key purged (keyslot $_fcs_eph)"
                ;;
            *)
                die "finalize: $(basename "$_fcs_dev"): multiple non-token passphrase slots ($_fcs_eph) — refusing to purge a corrupted handoff (§7.2)"
                ;;
        esac

        # (ii) token upgrade to Mechanism B {PCR 7, PCR 11} (§9.1 Stage 2 step 3)
        _fcs_cur=$(mktemp "$_fcs_tmpdir/alpine-fde-fin-cur.XXXXXX") ||
            die "finalize: mktemp failed"
        token_dump "$_fcs_dev" "$_fcs_cur"
        _fcs_pcrs=$(fin_token_pcrs "$_fcs_cur")
        rm -f "$_fcs_cur"
        if [ "$_fcs_pcrs" = "[7,11]" ]; then
            info "finalize: $(basename "$_fcs_dev"): token already {PCR 7, PCR 11} — skipping the upgrade (crash resume, zero TPM operations)"
        else
            # subshell isolation: the seal/token mutators die fail-closed —
            # contain them so the member context is what the operator sees
            if ! (seal_upgrade_token "$_fcs_keydir" "$_fcs_dev" "$_fcs_pcrsig" \
                "$_fcs_stage/token-$(basename "$_fcs_dev").json" "$_fcs_auth"); then
                die "finalize: token upgrade failed for $(basename "$_fcs_dev") — install state stays unfinalized; the standing seal remains; fix the cause and retry (§9.1 crash idempotency)"
            fi
            printf 'alpine-fde: member %s: token upgraded to Mechanism B {PCR 7, PCR 11}\n' \
                "$(basename "$_fcs_dev")" >&2
        fi

        # (iii) exactly the recovery keyslot 0 remains beyond the sealed token
        _fcs_meta=$(mktemp "$_fcs_tmpdir/alpine-fde-fin-meta.XXXXXX") ||
            die "finalize: mktemp failed"
        token_dump "$_fcs_dev" "$_fcs_meta"
        if ! fin_recovery_slot_ok "$_fcs_meta"; then
            rm -f "$_fcs_meta"
            die "finalize: $(basename "$_fcs_dev"): unexpected passphrase slots beyond the sealed token — exactly the recovery keyslot 0 must remain (§7.2/I1); manual intervention required"
        fi
        rm -f "$_fcs_meta"
    done
    rm -rf "$_fcs_stage"
    unset ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || :

    # ADR-20 amendment #4: the unfinalized MOTD/issue banner path is REMOVED —
    # nothing is written to /etc/motd or /etc/issue here (install no longer
    # drops a banner either; the operator's own content is never touched).

    # --- the state transition is the LAST mutation (§9.1); the ADR-8 marker ---
    # is cleared first: a successful completion means NO pending failure
    istate_attempt_clear
    istate_write finalized
    return 0
}

# fin_service_main — §9.1 Stage 2: the NON-INTERACTIVE first-boot completion
# (ADR-20 amended; the OpenRC oneshot hooks/openrc/alpine-fde-finalize runs
# this). NEVER prompts. Authorization = re-unsealing the standing provisional
# token in userspace (fin_provisional_unseal) — NOT stored credentials.
#   state `finalized`                       -> silent exit 0
#   state missing / unreadable / garbage    -> degrade: exit 0 (nothing to do)
#   `installed` | `provisional-booted`      -> the completion chain
# ANY failure writes the ADR-8 attempt marker (istate_attempt_write) and
# returns NONZERO — the wrapper maps that to the advisory; boot is NEVER
# blocked and the next boot retries.
fin_service_main() {
    strict_mode
    _fsv_state=$(istate_state 2>/dev/null)
    case $_fsv_state in
        finalized) return 0 ;;
        installed | provisional-booted) : ;;
        *) return 0 ;;
    esac
    _fsv_tmpdir=${ALPINE_FDE_TMPDIR:-/dev/shm}
    _fsv_stage=$(mktemp -d "$_fsv_tmpdir/alpine-fde-svc.XXXXXX") || {
        istate_attempt_write "service: no staging directory in $_fsv_tmpdir"
        return 1
    }
    chmod 700 "$_fsv_stage"
    _fsv_auth="$_fsv_stage/prov-pass.bin"
    _fsv_devs=$(fin_member_devs) || {
        istate_attempt_write "service: crypttab members unresolvable"
        rm -rf "$_fsv_stage"
        return 1
    }
    # first member only (POSIX-safe: this function runs under the OpenRC
    # service shell, where $'...' is not available)
    _fsv_first=$(printf '%s\n' "$_fsv_devs" | head -n 1)
    if ! fin_provisional_unseal "$_fsv_first" "$_fsv_stage" "$_fsv_auth"; then
        istate_attempt_write "service: provisional token re-unseal failed (PCR drift / missing UKI .pcrsig / locked release.pem) — will retry next boot"
        rm -rf "$_fsv_stage"
        return 1
    fi
    # failure-contained completion: die inside the chain must not escape into
    # an OpenRC failure — this function's nonzero return IS the contract
    if ! (fin_completion_steps "$_fsv_auth"); then
        istate_attempt_write "service: completion step failed — will retry next boot"
        rm -rf "$_fsv_stage"
        return 1
    fi
    rm -rf "$_fsv_stage"
    return 0
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
                die -r "$ALPINE_FDE_USAGE" "finalize: unknown argument: $1"
                ;;
        esac
    done

    # --- state gate (§8.4/G-D11): installed | provisional-booted proceed;
    # absent/finalized are loud no-ops; anything else fails closed
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
        installed | provisional-booted) : ;;
        *)
            die "finalize: unexpected install state '${_fm_state:-<unreadable>}' in $_fm_f — refusing (want: installed|provisional-booted)"
            ;;
    esac

    # --- members: every crypttab LUKS member (finalize owns per-member
    # iteration; the storage bucket owns the crypttab FORMAT)
    _fm_devs=$(fin_member_devs)
    set -- $_fm_devs
    _fm_first=$1

    # --- STEP 1: the operator's recovery passphrase — VERIFIED against
    # keyslot 0, never re-entered (§9.1 amended: the Stage-1 credential
    # ceremony already enrolled it). Bounded retry: 3 attempts, then
    # die 64 + the ADR-8 attempt marker. I1 hygiene: the staged passphrase is
    # scrubbed on EVERY exit path — die, signal, or success.
    _fm_stage=''
    _fm_passfile=''
    _fin_cleanup() {
        [ -z "${_fm_passfile:-}" ] || keys_scrub "$_fm_passfile"
        [ -z "${_fm_stage:-}" ] || rm -rf "$_fm_stage" 2>/dev/null || :
        return 0
    }
    trap _fin_cleanup EXIT
    _fm_tmpdir=${ALPINE_FDE_TMPDIR:-/dev/shm}
    _fm_passfile=$(mktemp "$_fm_tmpdir/alpine-fde-fin-pass.XXXXXX") ||
        die "finalize: cannot stage the recovery passphrase in $_fm_tmpdir"
    chmod 600 "$_fm_passfile"
    _fm_try=0
    while :; do
        _fm_try=$((_fm_try + 1))
        _fm_pass=''
        fin_read_recovery_passphrase _fm_pass
        printf '%s' "$_fm_pass" >"$_fm_passfile"
        unset _fm_pass 2>/dev/null || :
        if fin_recovery_verifies "$_fm_first" "$_fm_passfile"; then
            info "finalize: recovery passphrase verified against keyslot 0 (attempt $_fm_try) — authorizing the completion (§9.1)"
            break
        fi
        warn "finalize: the recovery passphrase does not verify against keyslot 0 (attempt $_fm_try/3)"
        if [ "$_fm_try" -ge 3 ]; then
            istate_attempt_write "guided finalize: recovery passphrase rejected after $_fm_try attempts"
            die "finalize: the recovery passphrase does not verify against keyslot 0 (after $_fm_try attempts) — the passphrase set during the Stage-1 credential ceremony is required (§9.1; ADR-8 marker written)"
        fi
    done

    # --- STEP 2: ensure release.pem is encrypted (ADR-18; local operation) -----
    # The Stage-1 credential ceremony (§9.1 step 4, 3/3) already encrypted it:
    # normally a crash-skip. Kept for pre-amendment installs.
    if [ -z "${ALPINE_FDE_KEY_PASSPHRASE:-}" ] && [ -n "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
        ALPINE_FDE_KEY_PASSPHRASE=$ALPINE_FDE_KEY_PASSPHRASE
    fi
    _fm_keypass=${ALPINE_FDE_KEY_PASSPHRASE:-}
    _fm_keydir=$(keys_dir)
    [ -n "$_fm_keydir" ] || die "finalize: no release key directory configured (set --keydir / KEY_PATH / ALPINE_FDE_KEYDIR)"
    [ -d "$_fm_keydir" ] || die "finalize: release key directory not found: $_fm_keydir"
    [ -f "$_fm_keydir/release.pem" ] || die "finalize: release.pem not found in $_fm_keydir (ADR-18)"
    if keys_is_encrypted "$_fm_keydir/release.pem"; then
        info "finalize: release.pem is already encrypted (ADR-18) — skipping (crash resume, §9.1)"
    else
        keys_encrypt_release "$_fm_keydir" ||
            die "finalize: release.pem encryption failed (§9.1 Stage 3 step 2)"
        info "finalize: release.pem encrypted (AES-256 PBKDF2, ADR-18)"
    fi
    chmod 0400 "$_fm_keydir/release.pem" 2>/dev/null || :

    # --- STEP 3..8: the shared completion chain (§9.1 Stage 2 == Stage 3) ------
    # SB guard -> audit --init -> token upgrade {PCR 7, PCR 11} per member ->
    # ephemeral keyslot purge per member -> state finalized.
    # The in-process re-sign fallback (§9.4) re-uses the release-key
    # passphrase staged above (same process, no new exposure).
    if [ -n "$_fm_keypass" ] && [ -z "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
        ALPINE_FDE_KEY_PASSPHRASE=$_fm_keypass
    fi
    _fm_stage=$(mktemp -d "$_fm_tmpdir/alpine-fde-fin.XXXXXX") ||
        die "finalize: cannot create the staging directory in $_fm_tmpdir"
    chmod 700 "$_fm_stage"
    fin_completion_steps "$_fm_passfile"

    # --- audit summary + §9.1 off-machine backup prompt (guided only) ----------
    _fm_bl=$(sp_baseline_file)
    printf 'alpine-fde: audit summary: baseline %s: expected_pcr7=%s secureboot=%s setup_mode=%s\n' \
        "$_fm_bl" \
        "$(baseline_get "$_fm_bl" expected_pcr7)" \
        "$(baseline_get_in "$_fm_bl" sb_state secure_boot)" \
        "$(baseline_get_in "$_fm_bl" sb_state setup_mode)" >&2
    cat >&2 <<EOF
alpine-fde: install finalized — back up the key material off-machine now (§9.1):
  scp -r $(sp_etc_dir)/keys/ admin@backup-host:/secure/storage/alpine-fde-backup/
EOF
    keys_scrub "$_fm_passfile"
    return 0
}

return 0
