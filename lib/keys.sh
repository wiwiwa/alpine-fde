#!/bin/sh
# keys.sh — release-key handling (docs/Architecture.md I4/ADR-11, gap B-G7).
#
# The release keypair lives on the offline signing medium; only its directory
# path is configured (DEBIAN_FDE_KEYDIR flag / KEY_PATH config key). Conventional
# file names inside the key directory:
#   release.pem — RSA private key (PEM)  — sbsign + policy signatures
#   release.crt — X.509 certificate      — sbsign + sbverify
#   release.pub — public key (PEM)       — .pcrpkey section, keyName computation
#
# Absent key material is a LOUD failure (exit 64) before any ESP mutation
# (ADR-8); `ukictl build` also persists a failure marker (its own concern).
#
# Also provides the TPMT_PUBLIC/TPM2B_PUBLIC builder for the release public key
# — the byte-exact public area whose TPM Name pins the release key inside the
# sealed object's PolicyAuthorize policy (§6.1.1 step 4b). Empirically verified
# against tpm2_loadexternal on swtpm (tpm2-tools 5.8):
#   - TPM2B_PUBLIC = 2-byte total length prefix over TPMT_PUBLIC
#   - TPMT_PUBLIC: type=RSA(0001), nameAlg=sha256(000b),
#     attrs=fixedTPM|fixedParent|decrypt=0x00020012 (task-pinned; loads + names
#     fine — NOT "sign", see the NOTE below),
#     authPolicy=empty, symmetric=NULL(0010), scheme=NULL(0010, NO hash byte —
#     the hash is chosen at verify time), keyBits, exponent=65537 (literal),
#     unique=TPM2B_PUBLIC_KEY_RSA(modulus)
#   - keyName = 000b || SHA256(TPMT_PUBLIC bytes) — equals tpm2_readpublic output
#
# NOTE (empirical): 0x00020012 is fixedTPM|fixedParent|decrypt — NOT sign
# (earlier comments here misstated it as "sign"; TPMA_OBJECT_DECRYPT=0x20000,
# TPMA_OBJECT_SIGN_ENCRYPT=0x40000 in the TSS2 header, and tpm2-tools
# readpublic renders exactly fixedtpm|fixedparent|decrypt). The area
# tpm2-tools builds when IT converts a PEM (attrs 0x00060040:
# userwithauth|decrypt|sign) additionally allows in-TPM
# `tpm2_verifysignature`; this pinned recording area loads and computes its
# Name but the TPM rejects in-TPM verification with RC_ATTRIBUTES — hence the
# two areas have DIFFERENT Names. NORMATIVE RULE (§6.1.1 step 4b): the sealed
# policy must pin the keyName of the area that will VERIFY at session time —
# the tpm2-tools PEM conversion — NOT this recording area's name.
#
# Depends on: lib/common.sh, lib/policy.sh (policy_hex_to_bin), openssl,
# tpm2-tools via the tpm() TCTI wrapper (only for keys_keyname).
# ADR-18 custody (keys_is_encrypted / keys_encrypt_release / keys_unlock):
# openssl only; the §13 passphrase floor is reused from lib/cmd/rotate.sh
# (sourced lazily via $DEBIAN_FDE_CMD_DIR when keys_encrypt_release needs it).

if [ -n "${DEBIAN_FDE_KEYS_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_KEYS_LOADED=1

# Self-load common.sh (die/info/require helpers) so guest-side one-liners like
# `. /opt/debian-fde/lib/keys.sh && keys_encrypt_release <keydir>` (§9.1 step
# 6, fresh chroot shell — functions do not cross the chroot boundary) work
# standalone. Pattern: lib/install-state.sh.
_is_cmd_dir=${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}
_is_lib_dir=${_is_cmd_dir%/*}
if [ -z "${DEBIAN_FDE_COMMON_LOADED:-}" ] && [ -r "$_is_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from DEBIAN_FDE_CMD_DIR / install tree
    . "$_is_lib_dir/common.sh"
fi

# keys_dir — effective release-key directory ($DEBIAN_FDE_KEYDIR overrides $KEY_PATH)
keys_dir() {
    printf '%s\n' "${DEBIAN_FDE_KEYDIR:-${KEY_PATH:-}}"
}

# keys_check [dir] — rc 0 iff the directory exists and holds all three files;
# on failure prints a one-line reason (used by ukictl build for the loud-fail
# marker BEFORE any ESP mutation). ADR-18 semantics: release.pem is the
# ENCRYPTED on-target key — the messages point at the scp backup / signing
# medium restore paths (G-KC8).
keys_check() {
    _keys_d=${1:-$(keys_dir)}
    if [ -z "$_keys_d" ]; then
        printf '%s\n' "release key directory not configured (set --keydir / KEY_PATH / DEBIAN_FDE_KEYDIR)"
        return 1
    fi
    if [ ! -d "$_keys_d" ]; then
        printf '%s\n' "release key directory not found: $_keys_d (encrypted key expected at $_keys_d/release.pem — restore the scp backup or attach the signing medium, ADR-18/I4)"
        return 1
    fi
    for _keys_f in release.pem release.crt release.pub; do
        if [ ! -f "$_keys_d/$_keys_f" ]; then
            if [ "$_keys_f" = release.pem ]; then
                printf '%s\n' "release.pem is missing (encrypted key expected at $_keys_d/release.pem — restore the scp backup or attach the signing medium, ADR-18)"
            else
                printf '%s\n' "release key material incomplete: $_keys_d/$_keys_f is missing"
            fi
            return 1
        fi
    done
    return 0
}

# keys_require [dir] — die (fail-closed, 64) unless keys_check passes
keys_require() {
    _keys_reason=''
    if ! _keys_reason=$(keys_check "$@"); then
        die "release key: $_keys_reason"
    fi
}

# --- ADR-18: encrypted release.pem custody (G-KC2/G-KC4, RESOLVED-1/4) ----------

# KEYS_PBKDF2_ITER — the ADR-18 PKCS#8 PBKDF2 iteration count (>= 600000)
KEYS_PBKDF2_ITER=600000

# keys_scrub FILE... — zeroize plaintext files THEN unlink (I4 hygiene: no
# plaintext private material survives on disk after use). Best effort per file;
# never fails the caller (strict-mode safe).
keys_scrub() {
    for _ks_f in "$@"; do
        [ -n "$_ks_f" ] || continue
        if [ -f "$_ks_f" ]; then
            _ks_sz=$(wc -c <"$_ks_f" 2>/dev/null || echo 0)
            case $_ks_sz in
                '' | *[!0-9]*) _ks_sz=0 ;;
            esac
            if [ "$_ks_sz" -gt 0 ]; then
                dd if=/dev/zero of="$_ks_f" bs=65536 \
                    count=$(( (_ks_sz + 65535) / 65536 )) conv=notrunc 2>/dev/null || :
            fi
        fi
        rm -f "$_ks_f" 2>/dev/null || :
    done
    return 0
}

# _keys_read_passphrase PROMPT — one passphrase line from stdin without echo
# (stty -echo when stdin is a tty); prompt on stderr, value on stdout. Same
# shape as install.sh's inst_read_passphrase (keys.sh is a lib: self-contained).
_keys_read_passphrase() {
    _krp_prompt=$1
    printf '%s' "$_krp_prompt" >&2
    _krp_restore=0
    if [ -t 0 ] && stty -echo 2>/dev/null; then
        _krp_restore=1
    fi
    _krp_val=''
    IFS= read -r _krp_val || _krp_val=''
    if [ "$_krp_restore" = 1 ]; then
        stty echo 2>/dev/null
    fi
    printf '\n' >&2
    printf '%s' "$_krp_val"
    return 0
}

# keys_is_encrypted FILE — rc 0 iff FILE is a PKCS#8 EncryptedPrivateKeyInfo in
# the exact ADR-18 form: PBES2 with PBKDF2-hmacWithSHA256, aes-256-cbc, and
# iteration count >= $KEYS_PBKDF2_ITER (ADR-18 "standard OpenSSL PKCS#8
# interoperability"). rc 1 otherwise — including plaintext PEMs, garbage,
# missing files, and conformant-except-parameters PKCS#8 (wrong PRF, wrong
# cipher, iter below the floor). Deliberately rc-only (never dies): callers
# use it as a classifier. openssl absent => rc 1 (not-encrypted verdict, the
# fail-closed direction for every caller).
keys_is_encrypted() {
    _kie_f=$1
    [ -n "$_kie_f" ] && [ -f "$_kie_f" ] || return 1
    _kie_asn=$(openssl asn1parse -in "$_kie_f" 2>/dev/null) || return 1
    case $_kie_asn in
        *:PBES2*) : ;;
        *) return 1 ;;
    esac
    case $_kie_asn in
        *:PBKDF2*) : ;;
        *) return 1 ;;
    esac
    case $_kie_asn in
        *hmacWithSHA256*) : ;;
        *) return 1 ;;
    esac
    case $_kie_asn in
        *:aes-256-cbc*) : ;;
        *) return 1 ;;
    esac
    # iteration count = the first INTEGER after the :PBKDF2 OBJECT line
    # (PBKDF2 params: SEQUENCE { salt OCTET STRING, INTEGER iter, ... }).
    # asn1parse prints larger INTEGERs in HEX (e.g. 600000 -> :0927C0) —
    # convert to decimal before the >= floor comparison.
    _kie_iter=$(printf '%s\n' "$_kie_asn" | awk '
        /:PBKDF2/ { seen = 1; next }
        seen && /INTEGER/ {
            v = $0
            sub(/.*:/, "", v)
            gsub(/[[:space:]]/, "", v)
            print v
            exit
        }')
    case $_kie_iter in
        '' | *[!0-9a-fA-F]*) return 1 ;;
    esac
    case $_kie_iter in
        *[!0-9]*)
            _kie_iter=$(printf '%s' "$_kie_iter" | awk '{
                v = 0
                for (i = 1; i <= length($0); i++) {
                    c = tolower(substr($0, i, 1))
                    if (c >= "a" && c <= "f") d = index("abcdef", c) + 9
                    else d = c + 0
                    v = v * 16 + d
                }
                printf "%d", v
            }')
            case $_kie_iter in
                '' | *[!0-9]*) return 1 ;;
            esac
            ;;
    esac
    [ "$_kie_iter" -ge "$KEYS_PBKDF2_ITER" ]
}

# keys_encrypt_release KEYDIR — encrypt $KEYDIR/release.pem in place to the
# ADR-18 form (see keys_is_encrypted) and scrub ALL plaintext copies
# (release.priv.pem duplicate + tmp staging — zeroize + rm). The §13 entropy
# floor (passphrase_floor_ok from lib/cmd/rotate.sh) is enforced BEFORE any
# ciphertext exists; floor violations are usage-class rc 2.
# Passphrase credential mechanism (RESOLVED-4): DEBIAN_FDE_KEY_PASSPHRASE env
# -> interactive double no-echo TTY prompt -> loud die 64. The variable is
# unset on completion (the passphrase never lingers in the environment).
# Idempotent: an already-encrypted release.pem is left untouched (crash-resume
# of the §9.1 step-6 install flow).
keys_encrypt_release() {
    [ $# -eq 1 ] || die "keys_encrypt_release: usage: keys_encrypt_release <keydir>"
    _ker_d=$1
    _ker_src="$_ker_d/release.pem"
    [ -f "$_ker_src" ] || die "keys_encrypt_release: no release.pem at $_ker_src (ADR-18)"
    if keys_is_encrypted "$_ker_src"; then
        warn "keys_encrypt_release: $_ker_src is already encrypted (ADR-18) — leaving it as-is"
        return 0
    fi
    if [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ]; then
        if [ -t 0 ]; then
            _ker_p1=$(_keys_read_passphrase 'Set release-key encryption passphrase (§13: >=12 chars with 3 character classes, or >=16 chars): ')
            _ker_p2=$(_keys_read_passphrase 'Repeat passphrase: ')
            if [ -z "$_ker_p1" ] || [ "$_ker_p1" != "$_ker_p2" ]; then
                die -r "$DEBIAN_FDE_USAGE" "keys_encrypt_release: passphrases empty or do not match"
            fi
            DEBIAN_FDE_KEY_PASSPHRASE=$_ker_p1
        else
            die "keys_encrypt_release: release.pem is not encrypted and no passphrase is available — provide DEBIAN_FDE_KEY_PASSPHRASE or run interactively (ADR-18)"
        fi
    fi
    unset _ker_p1 _ker_p2 2>/dev/null || :
    if ! command -v passphrase_floor_ok >/dev/null 2>&1; then
        # resolution order (first readable rotate.sh wins):
        #   1. the cmd-dir seam (CLI context: DEBIAN_FDE_CMD_DIR always set)
        #   2. the cmd/ sibling of THIS file (any self-contained tree)
        #   3. the documented tooling-copy destination (§8.1/§9.1: the guest
        #      one-liner runs from /opt/debian-fde with no cmd-dir env)
        #   4. the installed-tree default
        _ker_cands=""
        if [ -n "${DEBIAN_FDE_CMD_DIR:-}" ]; then
            _ker_cands="$DEBIAN_FDE_CMD_DIR"
        fi
        if [ -n "${_is_lib_dir:-}" ]; then
            _ker_cands="$_ker_cands $_is_lib_dir/cmd"
        fi
        _ker_cands="$_ker_cands /opt/debian-fde/lib/cmd /usr/share/debian-fde/lib/cmd"
        for _ker_cmd_dir in $_ker_cands; do
            if [ -f "$_ker_cmd_dir/rotate.sh" ]; then
                # shellcheck disable=SC1090  # resolved via the cmd dir seam
                . "$_ker_cmd_dir/rotate.sh"
                break
            fi
        done
        unset _ker_self _ker_cmd_dir _ker_cands 2>/dev/null || :
    fi
    command -v passphrase_floor_ok >/dev/null 2>&1 \
        || die "keys_encrypt_release: passphrase_floor_ok unavailable (lib/cmd/rotate.sh not found via DEBIAN_FDE_CMD_DIR, the lib sibling, /opt/debian-fde, or the installed tree)"
    if ! passphrase_floor_ok "$DEBIAN_FDE_KEY_PASSPHRASE"; then
        die -r "$DEBIAN_FDE_USAGE" "keys_encrypt_release: release-key passphrase below entropy floor (§13: ≥12 chars/3 classes or ≥16; not a common pattern) — refusing before any ciphertext is written (ADR-18)"
    fi
    _ker_tmp=$(mktemp "${DEBIAN_FDE_TMPDIR:-/dev/shm}/debian-fde-enc.XXXXXX") \
        || die "keys_encrypt_release: mktemp failed (${DEBIAN_FDE_TMPDIR:-/dev/shm} usable?)"
    chmod 600 "$_ker_tmp" 2>/dev/null || :
    if ! DEBIAN_FDE_KEY_PASSPHRASE="$DEBIAN_FDE_KEY_PASSPHRASE" \
        openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 \
        -iter "$KEYS_PBKDF2_ITER" -in "$_ker_src" \
        -passout env:DEBIAN_FDE_KEY_PASSPHRASE -out "$_ker_tmp"; then
        keys_scrub "$_ker_tmp"
        die "keys_encrypt_release: openssl pkcs8 encryption failed for $_ker_src"
    fi
    # round-trip guard: the staged ciphertext must decrypt with the SAME
    # passphrase before it replaces the plaintext (wrong-passphrase = loud 64)
    if ! DEBIAN_FDE_KEY_PASSPHRASE="$DEBIAN_FDE_KEY_PASSPHRASE" \
        openssl pkcs8 -in "$_ker_tmp" -passin env:DEBIAN_FDE_KEY_PASSPHRASE -out /dev/null 2>/dev/null; then
        keys_scrub "$_ker_tmp"
        unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
        die "keys_encrypt_release: staged ciphertext failed round-trip verification (wrong passphrase?) — no changes made"
    fi
    if ! keys_is_encrypted "$_ker_tmp"; then
        keys_scrub "$_ker_tmp"
        unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
        die "keys_encrypt_release: post-assert failed — staged output is not ADR-18-conformant PKCS#8 (PBES2/hmacWithSHA256/aes-256-cbc/iter>=$KEYS_PBKDF2_ITER)"
    fi
    if ! mv -f "$_ker_tmp" "$_ker_src"; then
        keys_scrub "$_ker_tmp"
        unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
        die "keys_encrypt_release: cannot replace $_ker_src with the encrypted form"
    fi
    chmod 600 "$_ker_src" 2>/dev/null || :
    # scrub ALL plaintext copies: the stage1 duplicate + (best effort) staging
    keys_scrub "$_ker_d/release.priv.pem" "$_ker_tmp"
    unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
    return 0
}

# keys_unlock KEYDIR — print a USABLE release.pem path for signing operations
# (ADR-18/§9.2): if $KEYDIR/release.pem is the ADR-18 encrypted form, decrypt
# it ONCE to tmpfs (${DEBIAN_FDE_TMPDIR:-/dev/shm}, mode 600, scrubbed by the
# CALLER's cleanup net) and print the decrypted path; if it is plaintext
# (offline medium / legacy), print the input path unchanged. Passphrase
# credential mechanism (RESOLVED-4): DEBIAN_FDE_KEY_PASSPHRASE env -> no-echo
# TTY prompt ([ -t 0 ]) -> loud die 64. A wrong passphrase is a distinct loud
# die 64 with the tmp staging scrubbed.
keys_unlock() {
    [ $# -eq 1 ] || die "keys_unlock: usage: keys_unlock <keydir>"
    _ku_d=$1
    _ku_src="$_ku_d/release.pem"
    [ -f "$_ku_src" ] || die "keys_unlock: release.pem is missing (encrypted key expected at $_ku_src — restore the scp backup or attach the signing medium, ADR-18/I4)"
    if ! keys_is_encrypted "$_ku_src"; then
        printf '%s\n' "$_ku_src"
        return 0
    fi
    if [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ]; then
        if [ -t 0 ]; then
            DEBIAN_FDE_KEY_PASSPHRASE=$(_keys_read_passphrase 'release.pem is encrypted — enter the release-key passphrase: ')
            if [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ]; then
                die "keys_unlock: passphrase required; provide DEBIAN_FDE_KEY_PASSPHRASE or run interactively (ADR-18)"
            fi
        else
            die "keys_unlock: release.pem is encrypted: passphrase required; provide DEBIAN_FDE_KEY_PASSPHRASE or run interactively (ADR-18)"
        fi
    fi
    _ku_out=$(mktemp "${DEBIAN_FDE_TMPDIR:-/dev/shm}/debian-fde-unlock.XXXXXX") \
        || die "keys_unlock: mktemp failed (${DEBIAN_FDE_TMPDIR:-/dev/shm} usable?)"
    chmod 600 "$_ku_out" 2>/dev/null || :
    if ! DEBIAN_FDE_KEY_PASSPHRASE="$DEBIAN_FDE_KEY_PASSPHRASE" \
        openssl pkcs8 -in "$_ku_src" -passin env:DEBIAN_FDE_KEY_PASSPHRASE -out "$_ku_out" 2>/dev/null; then
        keys_scrub "$_ku_out"
        unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
        die "keys_unlock: wrong passphrase for $_ku_src (decryption failed) — release key stays locked (ADR-18)"
    fi
    unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
    printf '%s\n' "$_ku_out"
}

# keys_offline_guard KEYDIR [TARGET_ROOT] — CUSTODY guard (I4 + ADR-18,
# RESOLVED-1; fail-closed 64): the protected machine's root must never hold
# PLAINTEXT private key material.
#   * KEYDIR outside TARGET_ROOT (offline medium)                 -> pass
#   * KEYDIR inside TARGET_ROOT holding the ENCRYPTED release.pem -> pass
#     (the ADR-18 in-chroot end state: $ROOT/etc/debian-fde/keys)
#   * KEYDIR inside TARGET_ROOT with plaintext private keys       -> die 64
#   * KEYDIR inside TARGET_ROOT with no encrypted release.pem     -> die 64
#     (the pre-generation refusal: offline `provision stage1` must not create
#     plaintext keys under the root — generating there is the --mode in-chroot
#     ceremony's job, which encrypts before reboot, §9.1 steps 3+6)
# An empty/unset KEYDIR is not an error here (rc 0) — callers check presence
# separately (keys_check/keys_require). An empty/unset TARGET_ROOT passes:
# with no custody target the guard has nothing to classify.
#
# Comparison is path-component aware. Normalization resolves the LONGEST
# EXISTING PREFIX of each path (walk dirname until readlink -f succeeds,
# re-append the non-existent tail — readlink -f alone fails on a
# not-yet-created keydir, which is the normal `provision stage1` case) and the
# keydir is matched against the root in BOTH raw and normalized form (S-H1: a
# symlinked-root spelling must not bypass the guard). "Inside the root" also
# covers the target's /etc/debian-fde/keys key-holding directory explicitly,
# so an empty under-root keydir is refused even before the root itself exists.
keys_offline_guard() {
    _kg_d=$1
    _kg_root=${2:-${DEBIAN_FDE_ROOT:-}}
    [ -n "$_kg_d" ] || return 0
    # _kg_norm PATH — canonical spelling of the longest EXISTING prefix (S-H1)
    _kg_norm() {
        _kg_p=$1
        case $_kg_p in
            /*) ;;
            *) _kg_p="$PWD/$_kg_p" ;;
        esac
        _kg_tail=''
        while :; do
            if _kg_r=$(readlink -f "$_kg_p" 2>/dev/null) && [ -n "$_kg_r" ]; then
                printf '%s%s' "$_kg_r" "$_kg_tail"
                return 0
            fi
            case $_kg_p in
                */*) _kg_tail="/${_kg_p##*/}$_kg_tail"; _kg_p=${_kg_p%/*} ;;
                *) printf '%s%s' "$_kg_p" "$_kg_tail"; return 0 ;;
            esac
        done
    }
    _kg_dir_raw=$_kg_d
    _kg_dir=$(_kg_norm "$_kg_d")
    _kg_inside=0
    if [ -n "$_kg_root" ]; then
        _kg_r=$(_kg_norm "$_kg_root")
        for _kg_cand in "$_kg_dir_raw" "$_kg_dir"; do
            case $_kg_cand in
                "$_kg_r" | "$_kg_r"/*) _kg_inside=1 ;;
            esac
        done
        _kg_etc=$(_kg_norm "${_kg_root}/etc/debian-fde/keys")
        for _kg_cand in "$_kg_dir_raw" "$_kg_dir"; do
            case $_kg_cand in
                "$_kg_etc" | "$_kg_etc"/*) _kg_inside=1 ;;
            esac
        done
    fi
    [ "$_kg_inside" -eq 1 ] || return 0
    # ADR-18: inside the target root ONLY the encrypted release.pem is legal
    _kg_enc="$_kg_d/release.pem"
    if [ -f "$_kg_enc" ] && keys_is_encrypted "$_kg_enc"; then
        # ...and no OTHER plaintext private key may hide next to it
        for _kg_p in release.priv.pem pk.priv.pem kek.priv.pem db.priv.pem; do
            if [ -f "$_kg_d/$_kg_p" ]; then
                die "keys: PLAINTEXT private key material inside the protected target root: $_kg_d/$_kg_p — only the encrypted release.pem may live on the target (I4/ADR-18)"
            fi
        done
        return 0
    fi
    for _kg_p in release.pem release.priv.pem pk.priv.pem kek.priv.pem db.priv.pem; do
        if [ -f "$_kg_d/$_kg_p" ]; then
            die "keys: PLAINTEXT private key material inside the protected target root: $_kg_d/$_kg_p — only the encrypted release.pem may live on the target (I4/ADR-18)"
        fi
    done
    die "keys: keydir $_kg_d is inside the protected target root and holds no encrypted release.pem — private keys must stay offline (I4/ADR-18)"
}

# keys_tpmt_public <pubkey.pem> <out.tpm2b> — build the TPM2B_PUBLIC for the
# release public key (see header for the exact construction).
keys_tpmt_public() {
    [ $# -eq 2 ] || die "keys_tpmt_public: usage: keys_tpmt_public <pubkey.pem> <out.tpm2b>"
    _keys_mod=$(openssl rsa -pubin -in "$1" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')
    case $_keys_mod in
        '' | *[!0-9A-Fa-f]*)
            die "keys_tpmt_public: cannot read modulus from $1 (not a valid RSA public key?)"
            ;;
    esac
    # S-L2: the exponent must come from the key — silently marshaling a
    # hardcoded 65537 for a key with a different one would yield a wrong
    # public area (and thus a wrong keyName)
    _keys_exp=$(openssl rsa -pubin -in "$1" -noout -text 2>/dev/null \
        | sed -n 's/.*Exponent: \([0-9]*\).*/\1/p')
    if [ "$_keys_exp" != 65537 ]; then
        die "keys_tpmt_public: unsupported RSA public exponent '${_keys_exp:-<none>}' in $1 (only 65537 is marshaled)"
    fi
    _keys_bits=$(( ${#_keys_mod} * 4 ))
    keys_build_tpmt_public "$_keys_mod" "$_keys_bits" >"$2" \
        || die "keys_tpmt_public: building TPMT_PUBLIC failed"
}

# keys_build_tpmt_public <modulus-hex> <keybits> — raw TPM2B_PUBLIC on stdout.
# Takes the modulus as a hex STRING (no binary plumbing) and marshals the whole
# area as one hex string -> policy_hex_to_bin, so byte order is reviewable.
# Separated from keys_tpmt_public so tests can pin the exact byte construction.
keys_build_tpmt_public() {
    _keys_mod=$1
    _keys_bits=$2
    _keys_ulen=$(printf '%04x' $(( ${#_keys_mod} / 2 )))  # unique: TPM2B length
    _keys_inner="0001"                                    # type: TPM_ALG_RSA
    _keys_inner="$_keys_inner""000b"                      # nameAlg: TPM_ALG_SHA256
    _keys_inner="$_keys_inner""00020012"                  # attrs: fixedTPM|fixedParent|decrypt (NOT sign — see header NOTE, M-2)
    _keys_inner="$_keys_inner""0000"                      # authPolicy: TPM2B_DIGEST, empty
    _keys_inner="$_keys_inner""0010"                      # symmetric: TPM_ALG_NULL
    _keys_inner="$_keys_inner""0010"                      # scheme: TPM_ALG_NULL (no hash byte)
    _keys_inner="$_keys_inner"$(printf '%04x' "$_keys_bits")  # keyBits
    _keys_inner="$_keys_inner""00010001"                  # exponent: 65537 (literal)
    _keys_inner="$_keys_inner""$_keys_ulen""$_keys_mod"   # unique: TPM2B_PUBLIC_KEY_RSA
    _keys_tlen=$(printf '%04x' $(( ${#_keys_inner} / 2 )))  # TPM2B_PUBLIC total length
    printf '%s%s' "$_keys_tlen" "$_keys_inner" | policy_hex_to_bin
}

# keys_keyname <pubkey.pem> <out.name> — the TPM Name of the release public area:
# build TPMT_PUBLIC, load it external (null hierarchy) via the configured TCTI,
# read the name back from the TPM (authoritative), flush the transient object.
# Requires TPM access (swtpm in tests; the real TPM on the enrolled machine).
keys_keyname() {
    [ $# -eq 2 ] || die "keys_keyname: usage: keys_keyname <pubkey.pem> <out.name>"
    _keys_tmp=$(mktemp -d "${TMPDIR:-/tmp}/debian-fde-keyname.XXXXXX") || die "keys: mktemp failed"
    # subshell: a die inside keys_tpmt_public (unparseable key) must not
    # strand _keys_tmp (S-L1)
    if ! (keys_tpmt_public "$1" "$_keys_tmp/pub.tpm2b"); then
        rm -rf "$_keys_tmp"
        die "keys_keyname: release public area construction failed for $1"
    fi
    if ! tpm loadexternal -C n -u "$_keys_tmp/pub.tpm2b" -c "$_keys_tmp/pub.ctx" -n "$2" >/dev/null 2>&1; then
        rm -rf "$_keys_tmp"
        die "keys_keyname: tpm2_loadexternal failed (TCTI: ${DEBIAN_FDE_TCTI:-default})"
    fi
    tpm flushcontext "$_keys_tmp/pub.ctx" >/dev/null 2>&1 || tpm flushcontext -t >/dev/null 2>&1 || true
    rm -rf "$_keys_tmp"
}

return 0
