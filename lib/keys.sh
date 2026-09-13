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

if [ -n "${DEBIAN_FDE_KEYS_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_KEYS_LOADED=1

# keys_dir — effective release-key directory ($DEBIAN_FDE_KEYDIR overrides $KEY_PATH)
keys_dir() {
    printf '%s\n' "${DEBIAN_FDE_KEYDIR:-${KEY_PATH:-}}"
}

# keys_check [dir] — rc 0 iff the directory exists and holds all three files;
# on failure prints a one-line reason (used by ukictl build for the loud-fail
# marker BEFORE any ESP mutation)
keys_check() {
    _keys_d=${1:-$(keys_dir)}
    if [ -z "$_keys_d" ]; then
        printf '%s\n' "release key directory not configured (set --keydir / KEY_PATH / DEBIAN_FDE_KEYDIR)"
        return 1
    fi
    if [ ! -d "$_keys_d" ]; then
        printf '%s\n' "release key directory not found: $_keys_d (attach the signing medium, I4)"
        return 1
    fi
    for _keys_f in release.pem release.crt release.pub; do
        if [ ! -f "$_keys_d/$_keys_f" ]; then
            printf '%s\n' "release key material incomplete: $_keys_d/$_keys_f is missing"
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

# keys_offline_guard KEYDIR [TARGET_ROOT] — custody guard (I4, fail-closed 64):
# the release/enrollment PRIVATE keys must never live inside the protected
# machine. Refuses when KEYDIR resolves inside TARGET_ROOT (default
# $DEBIAN_FDE_ROOT) or is the target's /etc/debian-fde/keys key-holding
# directory (or under it). Comparison is path-component aware. Normalization
# resolves the LONGEST EXISTING PREFIX of each path (walk dirname until
# readlink -f succeeds, re-append the non-existent tail — readlink -f alone
# fails on a not-yet-created keydir, which is the normal `provision stage1`
# case) and the keydir is matched against the root in BOTH raw and normalized
# form (S-H1: a symlinked-root spelling must not bypass the guard). An
# empty/unset KEYDIR is not an error here — callers check presence separately
# (keys_check/keys_require).
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
    if [ -n "$_kg_root" ]; then
        _kg_r=$(_kg_norm "$_kg_root")
        for _kg_cand in "$_kg_dir_raw" "$_kg_dir"; do
            case $_kg_cand in
                "$_kg_r" | "$_kg_r"/*)
                    die "keys: keydir $_kg_d is inside the protected target root — private keys must stay offline (I4)"
                    ;;
            esac
        done
    fi
    _kg_etc=$(_kg_norm "${_kg_root}/etc/debian-fde/keys")
    for _kg_cand in "$_kg_dir_raw" "$_kg_dir"; do
        case $_kg_cand in
            "$_kg_etc" | "$_kg_etc"/*)
                die "keys: keydir $_kg_d is the target's /etc/debian-fde/keys — private keys must stay offline (I4)"
                ;;
        esac
    done
    return 0
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
