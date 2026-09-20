#!/bin/sh
# rotate.sh — `debian-fde rotate`: change the keyslot-0 (recovery) passphrase via
# `cryptsetup luksChangeKey` (§8.1, §9.4). The volume key is untouched — no
# re-encryption; TPM seals are untouched — no re-seal needed.
#
# Optional --reseat-tpm additionally wipes + re-creates the TPM enrollment in
# ONE Mechanism B sealing run (never a bare wipe — delegated to
# enroll-tpm.sh's precondition-checked flow; ADR-19: no systemd-cryptenroll
# anywhere — the seal is tpm2-tools + the LUKS2 token choreography).
#
# Passphrase floor (§13 / C-G12, enforced fail-closed):
#   >= 12 chars with >= 3 character classes, or >= 16 chars (any classes);
#   small common-password blocklist (case-insensitive substring match).

if [ -n "${DEBIAN_FDE_ROTATE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_ROTATE_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

# passphrase_floor_ok PASSPHRASE — rc 0 iff it meets the §13 entropy floor
# Control characters are rejected first: the interactive TTY prompt can never
# produce them, but DEBIAN_FDE_NEW_PASSPHRASE (documented CI/scripting path)
# can — and a passphrase containing e.g. a newline is untypeable at the §10
# boot prompt (the documented data-loss row, silently armed).
passphrase_floor_ok() {
    _pf_p=$1
    [ -n "$_pf_p" ] || return 1
    case $_pf_p in
        *[[:cntrl:]]*) return 1 ;;
    esac
    _pf_len=${#_pf_p}
    _pf_classes=0
    case $_pf_p in
        *[[:lower:]]*) _pf_has_lower=1 ;;
        *) _pf_has_lower=0 ;;
    esac
    case $_pf_p in
        *[[:upper:]]*) _pf_has_upper=1 ;;
        *) _pf_has_upper=0 ;;
    esac
    case $_pf_p in
        *[[:digit:]]*) _pf_has_digit=1 ;;
        *) _pf_has_digit=0 ;;
    esac
    case $_pf_p in
        *[![:alnum:]]*) _pf_has_other=1 ;;
        *) _pf_has_other=0 ;;
    esac
    _pf_classes=$((_pf_has_lower + _pf_has_upper + _pf_has_digit + _pf_has_other))
    # common-password blocklist (small, heuristic; case-insensitive substring)
    _pf_lc=$(printf '%s' "$_pf_p" | tr '[:upper:]' '[:lower:]')
    case $_pf_lc in
        *password* | *passwort* | *123456* | *654321* | *qwerty* | *letmein* | \
            *welcome* | *admin* | *login* | *master* | *monkey* | *dragon* | \
            *iloveyou* | *sunshine* | *trustno1* | *superman* | *batman* | \
            *shadow* | *michael* | *jennifer* | *changeme* | *debian-fde* | \
            *correcthorse* | *asdfgh* | *zxcvbn* | *abcdef* | *qazwsx* | \
            *1q2w3e* | *abc123* | *hunter2*)
            return 1
            ;;
    esac
    [ "$_pf_len" -ge 16 ] && return 0
    [ "$_pf_len" -ge 12 ] && [ "$_pf_classes" -ge 3 ] && return 0
    return 1
}

rotate_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde rotate [--reseat-tpm] [--dry-run]

Change the keyslot-0 (recovery) passphrase: cryptsetup luksChangeKey on the
baseline's LUKS device, Argon2id KDF pins preserved. The volume key and all
TPM seals are untouched (no re-encryption, no re-seal, §9.4).
  --reseat-tpm   additionally wipe+re-enroll the TPM seal in ONE Mechanism B
                 sealing run (enroll-tpm preconditions apply; ADR-19)
Passphrases: DEBIAN_FDE_OLD_PASSPHRASE / DEBIAN_FDE_NEW_PASSPHRASE env or
interactive prompt. New passphrase must meet the §13 floor (>=12 chars/3
classes or >=16 chars, no common-password blocklist hits).
EOF
}

# rot_device — resolve the LUKS device from the baseline target
rot_device() {
    _rd_bl=$(sp_baseline_file)
    [ -f "$_rd_bl" ] || die "rotate: no baseline at $_rd_bl"
    baseline_validate "$_rd_bl" || die "rotate: baseline invalid"
    _rd_uuid=$(baseline_get_in "$_rd_bl" target luks_uuid)
    [ -n "$_rd_uuid" ] || die "rotate: baseline target.luks_uuid empty (set by install)"
    _rd_dev="${DEBIAN_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}/$_rd_uuid"
    [ -e "$_rd_dev" ] || die "rotate: LUKS device not resolvable: $_rd_dev"
    printf '%s\n' "$_rd_dev"
}

# rot_prompt PASSPHRASE-VARNAME PROMPT — read twice-matched passphrase into
# the named variable (interactive only)
rot_prompt() {
    _rp_var=$1 _rp_prompt=$2
    printf '%s: ' "$_rp_prompt" >&2
    stty -echo 2>/dev/null || true
    read -r _rp_a </dev/tty || _rp_a=''
    printf '\n(confirm): ' >&2
    read -r _rp_b </dev/tty || _rp_b=''
    stty echo 2>/dev/null || true
    printf '\n' >&2
    if [ "$_rp_a" != "$_rp_b" ]; then
        die "rotate: passphrases do not match"
    fi
    eval "$_rp_var=\$_rp_a"
}

# rot_luksdump DEV OUTFILE — luksDump JSON via the cryptsetup seam
rot_luksdump() {
    _rl_dev=$1 _rl_out=$2
    "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" luksDump --dump-json-metadata "$_rl_dev" >"$_rl_out" 2>/dev/null
}

cmd_rotate_main() {
    _rm_reseat=0
    while [ $# -gt 0 ]; do
        case $1 in
            --reseat-tpm) _rm_reseat=1 ;;
            --dry-run) DEBIAN_FDE_DRY_RUN=1 ;;  # consumed by enroll-tpm on --reseat-tpm
            -h | --help)
                rotate_usage
                return 0
                ;;
            *) die -r "$DEBIAN_FDE_USAGE" "rotate: unknown argument: $1" ;;
        esac
        shift
    done

    require_pkgs cryptsetup:cryptsetup jq:jq
    _rm_dev=$(rot_device)

    if [ -n "${DEBIAN_FDE_DRY_RUN:-}" ]; then
        info "dry-run: would run: cryptsetup luksChangeKey --key-slot 0 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-file <old> $_rm_dev <new>"
        if [ "$_rm_reseat" -eq 1 ]; then
            info "dry-run: would then re-seat the TPM seal (enroll-tpm --reseat)"
        fi
        return 0
    fi

    # Passphrase acquisition (env for CI, prompt otherwise)
    _rm_old=${DEBIAN_FDE_OLD_PASSPHRASE:-}
    _rm_new=${DEBIAN_FDE_NEW_PASSPHRASE:-}
    if [ -z "$_rm_new" ]; then
        rot_prompt _rm_new "new keyslot-0 passphrase"
    fi
    if ! passphrase_floor_ok "$_rm_new"; then
        die "rotate: new passphrase rejected by the §13 entropy floor (>=12 chars/3 classes or >=16 chars, no blocklist hits, no control characters) — refusing (T2b)"
    fi
    if [ -z "$_rm_old" ]; then
        rot_prompt _rm_old "current keyslot-0 passphrase"
    fi

    # Keyslot-0 change with LUKS2 metadata before/after assertions: every slot
    # except 0 (and all tokens) must be byte-identical; slot 0 must change.
    # Temp files holding the passphrases MUST live on tmpfs (§11 I1: neither
    # secret is ever plaintext on disk) — default /dev/shm, overridable via
    # DEBIAN_FDE_TMPDIR (tests / exotic setups); never ${TMPDIR:-/tmp}.
    _rm_tmpdir=${DEBIAN_FDE_TMPDIR:-/dev/shm}
    _rm_pre=$(mktemp "$_rm_tmpdir/debian-fde-rot-pre.XXXXXX") ||
        die "rotate: cannot create temp file in $_rm_tmpdir"
    _rm_post=$(mktemp "$_rm_tmpdir/debian-fde-rot-post.XXXXXX") || {
        rm -f "$_rm_pre"
        die "rotate: cannot create temp file in $_rm_tmpdir"
    }
    _rm_oldf=$(mktemp "$_rm_tmpdir/debian-fde-rot-old.XXXXXX") || {
        rm -f "$_rm_pre" "$_rm_post"
        die "rotate: cannot create temp file in $_rm_tmpdir"
    }
    _rm_newf=$(mktemp "$_rm_tmpdir/debian-fde-rot-new.XXXXXX") || {
        rm -f "$_rm_pre" "$_rm_post" "$_rm_oldf"
        die "rotate: cannot create temp file in $_rm_tmpdir"
    }
    rot_luksdump "$_rm_dev" "$_rm_pre" || die "rotate: cannot read LUKS2 metadata of $_rm_dev"
    # M-2 (§11 I1 hygiene): every exit path — normal, SIGINT, SIGTERM — must
    # zeroize the passphrase files before unlinking them and remove all four
    # temp files. A multi-second 1-GiB-Argon2id luksChangeKey is a wide window;
    # an interrupted run must not leave plaintext passphrases on tmpfs.
    _rot_cleanup() {
        for _rot_f in "${_rm_oldf:-}" "${_rm_newf:-}"; do
            [ -n "$_rot_f" ] && : >"$_rot_f" 2>/dev/null
        done
        rm -f "${_rm_oldf:-}" "${_rm_newf:-}" "${_rm_pre:-}" "${_rm_post:-}" 2>/dev/null
        return 0
    }
    trap _rot_cleanup EXIT
    trap 'trap - INT; _rot_cleanup; exit 130' INT
    trap 'trap - TERM; _rot_cleanup; exit 143' TERM
    printf '%s' "$_rm_old" >"$_rm_oldf"
    printf '%s' "$_rm_new" >"$_rm_newf"
    chmod 600 "$_rm_oldf" "$_rm_newf"
    _rm_rc=0
    if ! "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" luksChangeKey \
        --key-slot 0 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
        --key-file "$_rm_oldf" "$_rm_dev" "$_rm_newf"; then
        err "rotate: luksChangeKey failed (wrong current passphrase?)"
        _rm_rc=1
    fi
    [ "$_rm_rc" -eq 0 ] || die "rotate: keyslot 0 not changed"

    # H-1: luksChangeKey returned 0 — keyslot 0 WAS re-keyed, the OLD passphrase
    # no longer unlocks. Every failure from here on must say so before dying
    # (§10 "passphrase forgotten + TPM refuses = data loss"): an operator who
    # concludes "rotate failed" keeps the old passphrase record. Suppressed only
    # where the slot-0 assertions prove the change did NOT take effect.
    _rot_rekey_warn() {
        err "rotate: keyslot 0 WAS re-keyed to the NEW passphrase before this failure — the OLD passphrase no longer unlocks. Investigate with: cryptsetup luksDump --dump-json-metadata <dev>"
    }
    if ! rot_luksdump "$_rm_dev" "$_rm_post"; then
        _rot_rekey_warn
        die "rotate: cannot re-read LUKS2 metadata"
    fi
    # tokens unchanged
    _rm_tok_pre=$(luks_json_count_type "$_rm_pre" systemd-tpm2)
    _rm_tok_post=$(luks_json_count_type "$_rm_post" systemd-tpm2)
    if [ "$_rm_tok_pre" != "$_rm_tok_post" ]; then
        err "rotate: assertion failed: token count changed ($_rm_tok_pre -> $_rm_tok_post) — TPM seals must be untouched"
        _rm_rc=1
    fi
    # every keyslot except 0 byte-identical
    for _rm_slot in 1 2 3 4 5 6 7; do
        _rm_b=$(luks_json_slot_blob "$_rm_pre" "$_rm_slot")
        [ -n "$_rm_b" ] || continue
        if [ "$_rm_b" != "$(luks_json_slot_blob "$_rm_post" "$_rm_slot")" ]; then
            err "rotate: assertion failed: keyslot $_rm_slot changed — only keyslot 0 may change"
            _rm_rc=1
        fi
    done
    # slot 0 must exist and differ
    _rm_s0pre=$(luks_json_slot_blob "$_rm_pre" 0)
    _rm_s0post=$(luks_json_slot_blob "$_rm_post" 0)
    _rm_was_rekeyed=1
    if [ -z "$_rm_s0post" ]; then
        err "rotate: assertion failed: keyslot 0 vanished"
        _rm_rc=1
        _rm_was_rekeyed=0
    elif [ "$_rm_s0pre" = "$_rm_s0post" ]; then
        err "rotate: assertion failed: keyslot 0 unchanged — change did not take effect"
        _rm_rc=1
        _rm_was_rekeyed=0
    fi
    if [ "$_rm_rc" -ne 0 ] && [ "$_rm_was_rekeyed" -eq 1 ]; then
        _rot_rekey_warn
    fi
    [ "$_rm_rc" -eq 0 ] || die "rotate: post-assertions failed"

    printf 'debian-fde: keyslot-0 passphrase changed (volume key and TPM seals untouched)\n' >&2

    if [ "$_rm_reseat" -eq 1 ]; then
        info "re-seating the TPM seal (single wipe+enroll Mechanism B run, ADR-19)"
        if [ ! -f "$(sp_cmd_dir)/enroll-tpm.sh" ]; then
            die "rotate: enroll-tpm.sh not found next to rotate.sh — cannot --reseat-tpm"
        fi
        # shellcheck disable=SC1090
        . "$(sp_cmd_dir)/enroll-tpm.sh"
        cmd_enroll_tpm_main --reseat
    fi
    return 0
}
