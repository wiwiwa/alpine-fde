#!/bin/sh
# finalize.sh — `debian-fde finalize`: the GUIDED trust finalization command
# (§8.1 finalize row; §9.1 Stage 3 steps 1-5; ADR-20; gap G-D10). At boot only
# the OpenRC ADVISORY oneshot (hooks/openrc/alpine-fde-finalize) exists — it
# NEVER runs this command, it only points the operator here. Every step is
# crash-idempotent, so an interrupted run converges on the next invocation
# (§9.1: "the provisional token and keyslot 0 remain safe until successfully
# replaced").
#
# State machine (§8.4, G-D11): `installed` | `provisional-booted` proceed;
# `finalized` and an absent state file are loud no-ops (rc 0); anything else
# fails closed (64).
#
# Order is the doc's listed order (§8.1 finalize row / §9.1 Stage 3) — the
# LOCAL steps run before the Secure Boot gate, the TPM/audit mutations only
# after it:
#   1. Set the permanent recovery passphrase (§13 entropy floor, Argon2id) in
#      the NEXT FREE keyslot and PURGE the ephemeral install key. Recorded
#      design decision (the REAL install handoff — install.sh SLOT CONTRACT):
#      keyslot 0 = ephemeral install key, keyslot 1 = provisional token.
#      finalize identifies the ephemeral slot from the live LUKS2 metadata as
#      the passphrase slot NOT referenced by any systemd-tpm2 token (works for
#      ANY index), adds the recovery passphrase to the next free slot
#      (authorized by the handed-over ephemeral key / DEBIAN_FDE_LUKS_KEYFILE),
#      then KILLS the ephemeral slot — a kill must be authorized from a
#      DIFFERENT keyslot, so the just-added recovery passphrase is the
#      authorizing credential — and verifies exactly ONE passphrase slot
#      beyond the token-referenced slots remains (the recovery slot).
#      Crash-skip: a recovery passphrase that already verifies in any slot
#      skips the add; a missing ephemeral slot skips the purge.
#   2. Encrypt release.pem in place (AES-256 PBKDF2 >= 600k iterations,
#      ADR-18, via keys_encrypt_release; DEBIAN_FDE_KEY_PASSPHRASE /
#      ALPINE_FDE_KEY_PASSPHRASE seam or interactive prompt), permissions
#      tightened to 0400. Crash-skip: keys_is_encrypted guard.
#   3. Secure Boot gate (READ-ONLY fw_sb_state): secureboot=1 AND
#      setup_mode=0, else exit 64 with the §9.1 instruction text — NO
#      enrollment, NO wiping, NO baseline capture happens under an unverified
#      boot (§12 S-21 invariant).
#   4. Capture the baseline: `audit --init` finalizes pending pcr7
#      (crash-skip when the baseline is already final).
#   5. Upgrade the token: replace the provisional PCR-11 keyslot token with
#      the finalized Mechanism B {PCR 7, PCR 11} token via
#      seal_upgrade_token — for EVERY member container in RAID1 topologies.
#      Crash-skip: a standing token whose tpm2-pcrs are already [7,11] skips.
#   6. Cleanup: strip the unfinalized MOTD/issue banner (fde_motd_banner /
#      fde_motd_strip from lib/install-state.sh — the same single text
#      `install` drops at Stage 1).
#   7. Write state `finalized` LAST, then the audit summary and the §9.1
#      off-machine backup prompt (scp).
#
# Credential seams (scripting/CI; interactive fallbacks are the guided path):
#   DEBIAN_FDE_RECOVERY_PASSPHRASE  the new keyslot-0 recovery passphrase
#                                   (else double no-echo prompt)
#   DEBIAN_FDE_LUKS_KEYFILE         an existing-passphrase key file
#                                   authorizing luksAddKey/luksKillSlot (the
#                                   enroll-tpm.sh seam; in the ADR-20 flow
#                                   this carries the ephemeral install key
#                                   handed over by the boot chain)
#   DEBIAN_FDE_PCRSIG               a release-key-signed {7,11} .pcrsig for
#                                   the token upgrade (else the policy is
#                                   re-signed in-process from the keydir's
#                                   release.pem over the live PCRs, §9.4)
#
# Tool dependencies resolve through the audit/seal internals with loud
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
if [ -z "${DEBIAN_FDE_SEAL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../seal.sh"
fi
if ! command -v passphrase_floor_ok >/dev/null 2>&1; then
    # the §13 entropy floor (§9.1 Stage 3 step 1) lives in lib/cmd/rotate.sh
    # (shared with `rotate` and keys_encrypt_release)
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/rotate.sh"
fi

finalize_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde finalize

Trust finalization (§8.1 finalize row; §9.1 Stage 3; ADR-20). Requires install
state `installed` or `provisional-booted` and Secure Boot ON with the custom
keys (secureboot=1, setup_mode=0). Guided steps, in order:
  1. set the permanent recovery passphrase in the next free keyslot and
      purge the ephemeral install key (§13 entropy floor enforced)
  2. encrypt release.pem with AES-256 PBKDF2 (ADR-18) and chmod 0400
  3. verify Secure Boot is active (no enrollment under an unverified boot)
  4. capture the baseline (audit --init; skipped when already final)
  5. upgrade every crypttab member's token to Mechanism B {PCR 7, PCR 11}
  6. clear the unfinalized MOTD/issue banner
  7. write install state `finalized` and print the backup reminder
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

# fin_cryptsetup — the cryptsetup seam (same override enroll-tpm/token.sh use)
fin_cryptsetup() { "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }

# fin_recovery_verifies DEV PASS_FILE — rc 0 iff the candidate recovery
# passphrase already opens SOME keyslot (the crash-idempotency skip check;
# the recovery slot may sit at ANY index — never a token-referenced one)
fin_recovery_verifies() {
    fin_cryptsetup open --test-passphrase "$1" \
        --key-file "$2" >/dev/null 2>&1
}

# fin_ephemeral_slot DEV META_JSON AUTH_FILE — the ephemeral install key's
# keyslot: among the passphrase slots NOT referenced by any systemd-tpm2
# token (any index — the recorded design decision), the one the handed-over
# ephemeral key (AUTH_FILE = DEBIAN_FDE_LUKS_KEYFILE) actually opens. Empty
# when none: after the recovery passphrase is added, a surviving non-token
# slot could be the RECOVERY slot — the auth key then verifies nowhere and a
# re-run correctly skips the purge (crash-resume shape).
fin_ephemeral_slot() {
    _fes_dev=$1
    _fes_meta=$2
    _fes_auth=$3
    _fes_cands=$(jq -r '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)]
        | sort | .[]' "$_fes_meta" 2>/dev/null) || return 0
    for _fes_s in $_fes_cands; do
        if fin_cryptsetup open --test-passphrase --key-slot "$_fes_s" \
            "$_fes_dev" --key-file "$_fes_auth" >/dev/null 2>&1; then
            printf '%s\n' "$_fes_s"
            return 0
        fi
    done
    return 0
}

# fin_stray_slots META_JSON — count of EXTRA passphrase slots beyond the ONE
# recovery slot among the slots NOT referenced by the systemd-tpm2 token
# (must be 0: exactly ONE passphrase slot remains beyond the sealed one, §9.1)
fin_stray_slots() {
    jq '
        [.keyslots // {} | keys[] | tonumber] as $slots
        | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
            | .keyslots[]? | tonumber]) as $sealed
        | [$slots[] | select(. as $s | $sealed | index($s) | not)]
        | length - 1' "$1" 2>/dev/null
}

# fin_token_pcrs META_JSON — the standing systemd-tpm2 token's tpm2-pcrs
# (jq -c form, e.g. "[11]"); empty when no token stands
fin_token_pcrs() {
    jq -c 'first(.tokens // {} | to_entries[]
        | select(.value.type? == "systemd-tpm2")
        | .value["tpm2-pcrs"] // empty) // empty' "$1" 2>/dev/null
}

# fin_read_recovery_passphrase VAR — the new keyslot-0 passphrase into VAR:
# DEBIAN_FDE_RECOVERY_PASSPHRASE seam, else the guided double no-echo prompt.
# Enforces the §13 entropy floor (passphrase_floor_ok) BEFORE anything else
# can happen (fail-closed 64; the floor is the same one `rotate` enforces).
fin_read_recovery_passphrase() {
    _frr_var=$1
    if [ -n "${DEBIAN_FDE_RECOVERY_PASSPHRASE:-}" ]; then
        _frr_val=$DEBIAN_FDE_RECOVERY_PASSPHRASE
    elif [ -t 0 ]; then
        _frr_p1=
        _frr_p2=
        printf 'Set the permanent recovery passphrase (§13: >=12 chars with 3 character classes, or >=16 chars): ' >&2
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
            die -r "$DEBIAN_FDE_USAGE" "finalize: recovery passphrases empty or do not match"
        fi
        _frr_val=$_frr_p1
    else
        die "finalize: no recovery passphrase available — provide DEBIAN_FDE_RECOVERY_PASSPHRASE or run interactively (§9.1 Stage 3)"
    fi
    if ! passphrase_floor_ok "$_frr_val"; then
        die "finalize: recovery passphrase rejected by the §13 entropy floor (>=12 chars/3 classes or >=16 chars, no common-password hits, no control characters) — refusing (T2b)"
    fi
    eval "$_frr_var=\$_frr_val"
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
                die -r "$DEBIAN_FDE_USAGE" "finalize: unknown argument: $1"
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
    _fm_ct=$(fin_crypttab_file)
    _fm_members=$(fin_crypttab_uuids "$_fm_ct")
    [ -n "$_fm_members" ] || die "finalize: no LUKS member UUIDs found in $_fm_ct — cannot finalize"
    _fm_devs=''
    for _fm_uuid in $_fm_members; do
        _fm_dev="$(enrl_by_uuid_dir)/$_fm_uuid"
        [ -e "$_fm_dev" ] || die "finalize: member device not resolvable: $_fm_dev — refusing to finalize a partial array"
        _fm_devs="$_fm_devs $_fm_dev"
    done

    # --- STEP 1: permanent recovery passphrase (next free keyslot) + ephemeral
    # purge (§9.1 Stage 3 step 1; local operations — before the SB gate).
    # Handoff shape (install.sh SLOT CONTRACT): keyslot 0 = ephemeral install
    # key, keyslot 1 = provisional token; the recovery passphrase goes into
    # the NEXT FREE slot and the ephemeral slot is killed after — authorized
    # by the recovery passphrase (a kill must validate against a DIFFERENT
    # keyslot than the one being killed).
    # I1 hygiene: the staged passphrase (and the token staging directory) is
    # scrubbed on EVERY exit path — die, signal, or success.
    _fm_stage=''
    _fm_passfile=''
    _fin_cleanup() {
        [ -z "${_fm_passfile:-}" ] || keys_scrub "$_fm_passfile"
        [ -z "${_fm_stage:-}" ] || rm -rf "$_fm_stage" 2>/dev/null || :
        return 0
    }
    trap _fin_cleanup EXIT
    _fm_pass=''
    fin_read_recovery_passphrase _fm_pass
    _fm_tmpdir=${DEBIAN_FDE_TMPDIR:-/dev/shm}
    _fm_passfile=$(mktemp "$_fm_tmpdir/debian-fde-fin-pass.XXXXXX") ||
        die "finalize: cannot stage the recovery passphrase in $_fm_tmpdir"
    chmod 600 "$_fm_passfile"
    printf '%s' "$_fm_pass" >"$_fm_passfile"
    unset _fm_pass 2>/dev/null || :
    _fm_auth=${DEBIAN_FDE_LUKS_KEYFILE:-}
    [ -n "$_fm_auth" ] ||
        die "finalize: no existing-passphrase key file (DEBIAN_FDE_LUKS_KEYFILE) — cannot authorize the recovery add and the ephemeral purge (§9.1 Stage 3)"
    [ -f "$_fm_auth" ] ||
        die "finalize: existing-passphrase key file not found: $_fm_auth — cannot authorize the recovery add (wrong passphrase or missing handoff file?)"
    for _fm_dev in $_fm_devs; do
        _fm_pre=$(mktemp "${TMPDIR:-/tmp}/debian-fde-fin-pre.XXXXXX") ||
            die "finalize: mktemp failed"
        token_dump "$_fm_dev" "$_fm_pre"
        if fin_recovery_verifies "$_fm_dev" "$_fm_passfile"; then
            info "finalize: $(basename "$_fm_dev"): the recovery passphrase already verifies — skipping the add (crash resume, §9.1)"
        else
            # subshell: the token.sh mutators die fail-closed on cryptsetup
            # failures — isolate them so THIS die (with the member context)
            # fires instead of a bare set -e process exit
            _fm_slot=$(token_free_slot "$_fm_dev")
            (token_add_keyslot "$_fm_dev" "$_fm_passfile" "$_fm_slot" "$_fm_auth") ||
                die "finalize: $(basename "$_fm_dev"): adding the recovery passphrase (next free keyslot $_fm_slot) failed (wrong existing-passphrase key file?) — state stays unfinalized; nothing else was changed (§9.1)"
            info "finalize: $(basename "$_fm_dev"): permanent recovery passphrase set in keyslot $_fm_slot (Argon2id, §13)"
        fi
        _fm_eph=$(fin_ephemeral_slot "$_fm_dev" "$_fm_pre" "$_fm_auth")
        if [ -n "$_fm_eph" ]; then
            # the kill is authorized by the NEW recovery passphrase: cryptsetup
            # requires the authorizing credential to validate against a
            # DIFFERENT keyslot than the one being killed
            (token_kill_slot "$_fm_dev" "$_fm_eph" "$_fm_passfile") ||
                die "finalize: $(basename "$_fm_dev"): purging the ephemeral install key (keyslot $_fm_eph) failed — the recovery passphrase IS set; fix and re-run (§9.1 crash idempotency)"
            info "finalize: $(basename "$_fm_dev"): ephemeral install key purged (keyslot $_fm_eph)"
        else
            info "finalize: $(basename "$_fm_dev"): no ephemeral install key remains — skipping the purge (crash resume, §9.1)"
        fi
        token_dump "$_fm_dev" "$_fm_pre"
        _fm_stray=$(fin_stray_slots "$_fm_pre")
        [ "${_fm_stray:-0}" -eq 0 ] ||
            die "finalize: $(basename "$_fm_dev"): $_fm_stray unexpected passphrase slot(s) beyond the token-referenced slots — exactly ONE passphrase slot (the recovery slot) must remain beyond the sealed token (§9.1); manual intervention required"
        rm -f "$_fm_pre"
    done

    # --- STEP 2: encrypt release.pem (ADR-18; local operation) ---------------
    # ALPINE_FDE_* is the canonical env spelling (§8.1); the passphrase is
    # re-armed below for the token-upgrade's in-process re-sign fallback (the
    # same-process seam keys_encrypt_release legitimately unsets).
    if [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ] && [ -n "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
        DEBIAN_FDE_KEY_PASSPHRASE=$ALPINE_FDE_KEY_PASSPHRASE
    fi
    _fm_keypass=${DEBIAN_FDE_KEY_PASSPHRASE:-}
    _fm_keydir=$(keys_dir)
    [ -n "$_fm_keydir" ] || die "finalize: no release key directory configured (set --keydir / KEY_PATH / DEBIAN_FDE_KEYDIR)"
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

    # --- STEP 3: Secure Boot gate (READ-ONLY; §9.1 Stage 3) -------------------
    # Verified boot with OUR keys, or no enrollment / audit / token mutation
    # happens at all (§12 S-21): the volume stays protected by the recovery
    # passphrase plus the standing provisional seal.
    _fm_sb=$(fw_sb_state) || true
    case $_fm_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "finalize: Secure Boot is not enabled with your custom keys. Reboot into BIOS setup and toggle Secure Boot ON to complete trust finalization. (fw_sb_state: $_fm_sb — no enrollment, no wiping, no baseline capture; the volume remains safely locked)"
            ;;
    esac

    # --- STEP 4: capture the baseline (audit --init; §9.1 Stage 3 step 3) -----
    # A previous run's final baseline is reused as-is (crash between the audit
    # and the token upgrade).
    _fm_bl=$(sp_baseline_file)
    [ -f "$_fm_bl" ] || die "finalize: no baseline at $_fm_bl — Stage 1 provisioning must write a pending baseline before finalization (§9.1)"
    baseline_validate "$_fm_bl" || die "finalize: baseline invalid: $_fm_bl"
    if baseline_is_final "$_fm_bl"; then
        info "baseline already final — skipping audit --init (resumed finalization, §9.1 crash idempotency)"
    else
        info "finalizing the baseline from live values (audit --init, §9.1 Stage 3)"
        cmd_audit_main --init
    fi

    # --- STEP 5: upgrade the token to Mechanism B {PCR 7, PCR 11} -------------
    # per member (RAID1), via seal_upgrade_token (crash-safe choreography: the
    # provisional seal stays standing until the finalized one does). A standing
    # {7,11} token skips (crash resume; zero TPM operations).
    [ -f "$_fm_keydir/release.pub" ] || die "finalize: release public key not found: $_fm_keydir/release.pub"
    _fm_stage=$(mktemp -d "$_fm_tmpdir/debian-fde-fin.XXXXXX") ||
        die "finalize: cannot create the staging directory in $_fm_tmpdir"
    chmod 700 "$_fm_stage"
    # re-arm the release-key passphrase for the in-process re-sign fallback
    # (§9.4; keys_encrypt_release unsets it after step 2) — same process, no
    # new exposure
    if [ -n "$_fm_keypass" ] && [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ]; then
        DEBIAN_FDE_KEY_PASSPHRASE=$_fm_keypass
    fi
    if [ -n "${DEBIAN_FDE_PCRSIG:-}" ]; then
        _fm_pcrsig=$DEBIAN_FDE_PCRSIG
    else
        _fm_pcrsig=$(enrl_sign_pcrsig "$_fm_stage" "$_fm_keydir") ||
            die "finalize: cannot produce the signed {7,11} policy (.pcrsig) — DEBIAN_FDE_PCRSIG or the keydir release.pem is required (§9.1 Stage 3)"
    fi
    for _fm_uuid in $_fm_members; do
        _fm_dev="$(enrl_by_uuid_dir)/$_fm_uuid"
        _fm_cur=$(mktemp "${TMPDIR:-/tmp}/debian-fde-fin-cur.XXXXXX") ||
            die "finalize: mktemp failed"
        token_dump "$_fm_dev" "$_fm_cur"
        _fm_pcrs=$(fin_token_pcrs "$_fm_cur")
        rm -f "$_fm_cur"
        if [ "$_fm_pcrs" = "[7,11]" ]; then
            info "finalize: member $_fm_uuid: token already {PCR 7, PCR 11} — skipping the upgrade (crash resume, zero TPM operations)"
        else
            # subshell isolation: same rationale as the step-1 mutators
            if ! (seal_upgrade_token "$_fm_keydir" "$_fm_dev" "$_fm_pcrsig" \
                "$_fm_stage/token-$_fm_uuid.json" "$_fm_passfile"); then
                die "finalize: token upgrade failed for member $_fm_uuid — install state stays unfinalized; the provisional seal remains standing; fix the cause and re-run finalize (§9.1 crash idempotency)"
            fi
            printf 'debian-fde: member %s: token upgraded to Mechanism B {PCR 7, PCR 11}\n' \
                "$_fm_uuid" >&2
        fi
    done
    rm -rf "$_fm_stage"
    unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :

    # --- STEP 6: clear the unfinalized MOTD/issue banner (§9.1 Stage 3 step 4)
    _fm_root=${DEBIAN_FDE_ROOT:-}
    fde_motd_strip "${_fm_root}/etc/motd"
    fde_motd_strip "${_fm_root}/etc/issue"
    info "finalize: unfinalized MOTD/issue banner cleared"

    # --- STEP 7: the state transition is the LAST mutation (§9.1) -------------
    istate_write finalized

    # --- audit summary + §9.1 off-machine backup prompt -----------------------
    printf 'debian-fde: audit summary: baseline %s: expected_pcr7=%s secureboot=%s setup_mode=%s\n' \
        "$_fm_bl" \
        "$(baseline_get "$_fm_bl" expected_pcr7)" \
        "$(baseline_get_in "$_fm_bl" sb_state secure_boot)" \
        "$(baseline_get_in "$_fm_bl" sb_state setup_mode)" >&2
    cat >&2 <<EOF
debian-fde: install finalized — back up the key material off-machine now (§9.1):
  scp -r $(sp_etc_dir)/keys/ admin@backup-host:/secure/storage/debian-fde-backup/
EOF
    keys_scrub "$_fm_passfile"
    return 0
}

return 0
