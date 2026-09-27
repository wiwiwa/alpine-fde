#!/bin/sh
# passwd.sh — `alpine-fde passwd`: change the keyslot-0 (recovery) passphrase via
# `cryptsetup luksChangeKey` (§8.1, §9.4). The volume key is untouched — no
# re-encryption; TPM seals are untouched — no re-seal needed.
#
# Optional --reseat-tpm additionally wipes + re-creates the TPM enrollment in
# ONE Mechanism B sealing run (never a bare wipe — delegated to
# reseal.sh's precondition-checked flow; ADR-19: no systemd-cryptenroll
# anywhere — the seal is tpm2-tools + the LUKS2 token choreography).
#
# Passphrase floor (§13 / C-G12, enforced fail-closed):
#   >= 12 chars with >= 3 character classes, or >= 16 chars (any classes);
#   small common-password blocklist (case-insensitive substring match).

if [ -n "${ALPINE_FDE_PASSWD_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_PASSWD_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

# passphrase_floor_ok PASSPHRASE — rc 0 iff it meets the §13 entropy floor
# Control characters are rejected first: the interactive TTY prompt can never
# produce them, but ALPINE_FDE_NEW_PASSPHRASE (documented CI/scripting path)
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
            *shadow* | *michael* | *jennifer* | *changeme* | *alpine-fde* | \
            *correcthorse* | *asdfgh* | *zxcvbn* | *abcdef* | *qazwsx* | \
            *1q2w3e* | *abc123* | *hunter2*)
            return 1
            ;;
    esac
    [ "$_pf_len" -ge 16 ] && return 0
    [ "$_pf_len" -ge 12 ] && [ "$_pf_classes" -ge 3 ] && return 0
    return 1
}

passwd_usage() {
    cat >&2 <<'EOF'
Usage: alpine-fde passwd [--reseat-tpm]

Change the keyslot-0 (recovery) passphrase: cryptsetup luksChangeKey on the
baseline's LUKS device, Argon2id KDF pins preserved. The volume key and all
TPM seals are untouched (no re-encryption, no re-seal, §9.4).
  --reseat-tpm   additionally wipe+re-enroll the TPM seal in ONE Mechanism B
                 sealing run (reseal preconditions apply; ADR-19)
Passphrases: ALPINE_FDE_OLD_PASSPHRASE / ALPINE_FDE_NEW_PASSPHRASE env or
interactive prompt. New passphrase must meet the §13 floor (>=12 chars/3
classes or >=16 chars, no common-password blocklist hits).
EOF
}

# passwd_device — resolve the LUKS device from the baseline target
passwd_device() {
    _rd_bl=$(sp_baseline_file)
    [ -f "$_rd_bl" ] || die "passwd: no baseline at $_rd_bl"
    baseline_validate "$_rd_bl" || die "passwd: baseline invalid"
    _rd_uuid=$(baseline_get_in "$_rd_bl" target luks_uuid)
    [ -n "$_rd_uuid" ] || die "passwd: baseline target.luks_uuid empty (set by install)"
    _rd_dev="${ALPINE_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}/$_rd_uuid"
    [ -e "$_rd_dev" ] || die "passwd: LUKS device not resolvable: $_rd_dev"
    printf '%s\n' "$_rd_dev"
}

# passwd_prompt PASSPHRASE-VARNAME PROMPT — read twice-matched passphrase into
# the named variable (interactive only)
passwd_prompt() {
    _rp_var=$1 _rp_prompt=$2
    printf '%s: ' "$_rp_prompt" >&2
    stty -echo 2>/dev/null || true
    read -r _rp_a </dev/tty || _rp_a=''
    printf '\n(confirm): ' >&2
    read -r _rp_b </dev/tty || _rp_b=''
    stty echo 2>/dev/null || true
    printf '\n' >&2
    fde_strip_trailing_cr _rp_a
    fde_strip_trailing_cr _rp_b
    if [ "$_rp_a" != "$_rp_b" ]; then
        die "passwd: passphrases do not match"
    fi
    eval "$_rp_var=\$_rp_a"
}

# passwd_luksdump DEV OUTFILE — luksDump JSON via the cryptsetup seam
passwd_luksdump() {
    _rl_dev=$1 _rl_out=$2
    "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" luksDump --dump-json-metadata "$_rl_dev" >"$_rl_out" 2>/dev/null
}

cmd_passwd_main() {
    _rm_reseat=0
    while [ $# -gt 0 ]; do
        case $1 in
            --reseat-tpm) _rm_reseat=1 ;;
            -h | --help)
                passwd_usage
                return 0
                ;;
            *) die -r "$ALPINE_FDE_USAGE" "passwd: unknown argument: $1" ;;
        esac
        shift
    done

    require_pkgs cryptsetup:cryptsetup jq:jq
    _rm_dev=$(passwd_device)

    # Passphrase acquisition (env for CI, prompt otherwise)
    _rm_old=${ALPINE_FDE_OLD_PASSPHRASE:-}
    _rm_new=${ALPINE_FDE_NEW_PASSPHRASE:-}
    if [ -z "$_rm_new" ]; then
        passwd_prompt _rm_new "new keyslot-0 passphrase"
    fi
    if ! passphrase_floor_ok "$_rm_new"; then
        die "passwd: new passphrase rejected by the §13 entropy floor (>=12 chars/3 classes or >=16 chars, no blocklist hits, no control characters) — refusing (T2b)"
    fi
    if [ -z "$_rm_old" ]; then
        passwd_prompt _rm_old "current keyslot-0 passphrase"
    fi

    # Keyslot-0 change with LUKS2 metadata before/after assertions: every slot
    # except 0 (and all tokens) must be byte-identical; slot 0 must change.
    # Temp files holding the passphrases MUST live on tmpfs (§11 I1: neither
    # secret is ever plaintext on disk) — default /dev/shm, overridable via
    # ALPINE_FDE_TMPDIR (tests / exotic setups); never ${TMPDIR:-/tmp}.
    _rm_tmpdir=${ALPINE_FDE_TMPDIR:-/dev/shm}
    _rm_pre=$(mktemp "$_rm_tmpdir/alpine-fde-passwd-pre.XXXXXX") ||
        die "passwd: cannot create temp file in $_rm_tmpdir"
    _rm_post=$(mktemp "$_rm_tmpdir/alpine-fde-passwd-post.XXXXXX") || {
        rm -f "$_rm_pre"
        die "passwd: cannot create temp file in $_rm_tmpdir"
    }
    _rm_oldf=$(mktemp "$_rm_tmpdir/alpine-fde-passwd-old.XXXXXX") || {
        rm -f "$_rm_pre" "$_rm_post"
        die "passwd: cannot create temp file in $_rm_tmpdir"
    }
    _rm_newf=$(mktemp "$_rm_tmpdir/alpine-fde-passwd-new.XXXXXX") || {
        rm -f "$_rm_pre" "$_rm_post" "$_rm_oldf"
        die "passwd: cannot create temp file in $_rm_tmpdir"
    }
    passwd_luksdump "$_rm_dev" "$_rm_pre" || die "passwd: cannot read LUKS2 metadata of $_rm_dev"
    # M-2 (§11 I1 hygiene): every exit path — normal, SIGINT, SIGTERM — must
    # zeroize the passphrase files before unlinking them and remove all four
    # temp files. A multi-second 1-GiB-Argon2id luksChangeKey is a wide window;
    # an interrupted run must not leave plaintext passphrases on tmpfs.
    _passwd_cleanup() {
        for _passwd_f in "${_rm_oldf:-}" "${_rm_newf:-}"; do
            [ -n "$_passwd_f" ] && : >"$_passwd_f" 2>/dev/null
        done
        rm -f "${_rm_oldf:-}" "${_rm_newf:-}" "${_rm_pre:-}" "${_rm_post:-}" 2>/dev/null
        return 0
    }
    trap _passwd_cleanup EXIT
    trap 'trap - INT; _passwd_cleanup; exit 130' INT
    trap 'trap - TERM; _passwd_cleanup; exit 143' TERM
    printf '%s' "$_rm_old" >"$_rm_oldf"
    printf '%s' "$_rm_new" >"$_rm_newf"
    chmod 600 "$_rm_oldf" "$_rm_newf"
    _rm_rc=0
    if ! "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" luksChangeKey \
        --key-slot 0 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
        --key-file "$_rm_oldf" "$_rm_dev" "$_rm_newf"; then
        err "passwd: luksChangeKey failed (wrong current passphrase?)"
        _rm_rc=1
    fi
    [ "$_rm_rc" -eq 0 ] || die "passwd: keyslot 0 not changed"

    # H-1: luksChangeKey returned 0 — keyslot 0 WAS re-keyed, the OLD passphrase
    # no longer unlocks. Every failure from here on must say so before dying
    # (§10 "passphrase forgotten + TPM refuses = data loss"): an operator who
    # concludes "passwd failed" keeps the old passphrase record. Suppressed only
    # where the slot-0 assertions prove the change did NOT take effect.
    _passwd_rekey_warn() {
        err "passwd: keyslot 0 WAS re-keyed to the NEW passphrase before this failure — the OLD passphrase no longer unlocks. Investigate with: cryptsetup luksDump --dump-json-metadata <dev>"
    }
    if ! passwd_luksdump "$_rm_dev" "$_rm_post"; then
        _passwd_rekey_warn
        die "passwd: cannot re-read LUKS2 metadata"
    fi
    # tokens unchanged
    _rm_tok_pre=$(luks_json_count_type "$_rm_pre" systemd-tpm2)
    _rm_tok_post=$(luks_json_count_type "$_rm_post" systemd-tpm2)
    if [ "$_rm_tok_pre" != "$_rm_tok_post" ]; then
        err "passwd: assertion failed: token count changed ($_rm_tok_pre -> $_rm_tok_post) — TPM seals must be untouched"
        _rm_rc=1
    fi
    # every keyslot except 0 byte-identical
    for _rm_slot in 1 2 3 4 5 6 7; do
        _rm_b=$(luks_json_slot_blob "$_rm_pre" "$_rm_slot")
        [ -n "$_rm_b" ] || continue
        if [ "$_rm_b" != "$(luks_json_slot_blob "$_rm_post" "$_rm_slot")" ]; then
            err "passwd: assertion failed: keyslot $_rm_slot changed — only keyslot 0 may change"
            _rm_rc=1
        fi
    done
    # slot 0 must exist and differ
    _rm_s0pre=$(luks_json_slot_blob "$_rm_pre" 0)
    _rm_s0post=$(luks_json_slot_blob "$_rm_post" 0)
    _rm_was_rekeyed=1
    if [ -z "$_rm_s0post" ]; then
        err "passwd: assertion failed: keyslot 0 vanished"
        _rm_rc=1
        _rm_was_rekeyed=0
    elif [ "$_rm_s0pre" = "$_rm_s0post" ]; then
        err "passwd: assertion failed: keyslot 0 unchanged — change did not take effect"
        _rm_rc=1
        _rm_was_rekeyed=0
    fi
    if [ "$_rm_rc" -ne 0 ] && [ "$_rm_was_rekeyed" -eq 1 ]; then
        _passwd_rekey_warn
    fi
    [ "$_rm_rc" -eq 0 ] || die "passwd: post-assertions failed"

    printf 'alpine-fde: keyslot-0 passphrase changed (volume key and TPM seals untouched)\n' >&2

    if [ "$_rm_reseat" -eq 1 ]; then
        info "re-seating the TPM seal (single wipe+enroll Mechanism B run, ADR-19)"
        if [ ! -f "$(sp_cmd_dir)/reseal.sh" ]; then
            die "passwd: reseal.sh not found next to passwd.sh — cannot --reseat-tpm"
        fi
        # shellcheck disable=SC1090
        . "$(sp_cmd_dir)/reseal.sh"
        cmd_reseal_main --reseat
    fi
    return 0
}
