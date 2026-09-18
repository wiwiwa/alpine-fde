#!/bin/sh
# provision.sh — `debian-fde provision`: one-time signing ceremony + baseline
# seeding (§8.1, §9.1; gaps C-G2/C-G3).
#
#   provision stage1 [--keydir D] [--force]
#       On the OFFLINE signing medium (I4): release keypair RSA-3072 + cert
#       (one identity for UKI sbsign AND policy signatures, ADR-11), plus
#       enrollment-only PK/KEK/db keypairs; builds EFI_SIGNATURE_LIST blobs and
#       authenticated variable update packets (WIN_CERTIFICATE_EFI_PKCS) for
#       PK/KEK/db — pure sh+openssl, golden-vector testable; prints firmware
#       enrollment guidance (virt-fw-vars for CI, KeyTool for real hardware);
#       writes the PENDING baseline (expected_pcr7="pending" — PCR 7 changes
#       only on the next boot after key enrollment, C-G2).
#   provision stage2 | provision --capture-baseline
#       Post-first-boot capture: live PCR 0..3+7, Secure Boot state + key
#       fingerprints, firmware identity, TCG event log v1 record → finalizes
#       the baseline (same code path as `audit --init`).
#
# No TPM operations mutate state here; reads only.

if [ -n "${DEBIAN_FDE_PROVISION_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_PROVISION_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

if [ -z "${DEBIAN_FDE_KEYS_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../keys.sh"
fi

# --- EFI binary primitives (pure sh; byte output via awk "%c", gawk/mawk OK) ---

# bin_to_hex — binary stdin → lowercase hex string
bin_to_hex() {
    od -An -v -tx1 | tr -d ' \n'
}

# hex_to_bin — hex string on stdin → raw bytes on stdout. Portable: awk emits
# OCTAL ESCAPES and one printf '%b' converts them (printf "%c" with values >127
# UTF-8-encodes under gawk in a UTF-8 locale; '%b' + \ooo is byte-exact and
# keeps NULs because the intermediate is ASCII text, never raw NUL bytes).
hex_to_bin() {
    _h2b_esc=$(awk '{
        s = tolower($0)
        h = "0123456789abcdef"
        out = ""
        for (i = 1; i + 1 <= length(s); i += 2) {
            hi = index(h, substr(s, i, 1)) - 1
            lo = index(h, substr(s, i + 1, 1)) - 1
            out = out sprintf("\\%03o", hi * 16 + lo)
        }
        printf "%s", out
    }')
    printf '%b' "$_h2b_esc"
}

# le16_hex N / le32_hex N — little-endian hex encoding of an integer
le16_hex() {
    printf '%04x' "$1" | awk '{ printf "%s%s", substr($0, 3, 2), substr($0, 1, 2) }'
}

le32_hex() {
    printf '%08x' "$1" | awk '{ printf "%s%s%s%s", substr($0, 7, 2), substr($0, 5, 2), substr($0, 3, 2), substr($0, 1, 2) }'
}

# guid_le_hex DASHED-GUID — EFI GUID mixed-endian byte encoding:
# first three fields little-endian, last two big-endian (raw)
guid_le_hex() {
    printf '%s\n' "$1" | awk -F- '
    {
        d1 = $1; d2 = $2; d3 = $3
        printf "%s%s%s%s%s",
            substr(d1, 7, 2) substr(d1, 5, 2) substr(d1, 3, 2) substr(d1, 1, 2),
            substr(d2, 3, 2) substr(d2, 1, 2),
            substr(d3, 3, 2) substr(d3, 1, 2),
            $4, $5
    }'
}

# ascii_utf16le_hex STRING — UTF-16LE hex of an ASCII string (00 interleaved)
ascii_utf16le_hex() {
    printf '%s' "$1" | bin_to_hex | sed 's/../&00/g'
}

# efi_time_hex ISO8601-UTC — 16-byte EFI_TIME encoding ("...Z" suffix parsed;
# positional field extraction — regex FS gives no leading empty field)
efi_time_hex() {
    printf '%s\n' "$1" | awk '
    {
        gsub(/[^0-9]/, " ")
        y = $1; mo = $2; d = $3; h = $4; mi = $5; s = $6
        y16 = sprintf("%04x", y)
        printf "%s%02x%02x%02x%02x%02x%02x", substr(y16, 3, 2) substr(y16, 1, 2), mo, d, h, mi, s, 0
        printf "00000000"   # nanosecond
        printf "0000"       # timezone: 0 = UTC
        printf "00"         # daylight
        printf "00"         # pad2
    }'
}

# EFI_CERT_X509_GUID (signature type for DER certs), byte-encoded
PROV_GUID_X509_HEX='c3c0cfa53e88f24fa63a95c5e9d3a5c3'
# EFI_CERT_X509_SHA256_GUID (revocation entries: sha256 of a cert's TBS section
# + zero EFI_TIME = revoked always; UEFI spec / edk2 gEfiCertX509Sha256Guid
# {0x3bd2a492,0x96c0,0x4079,{0xb4,0x20,0xfc,0xf9,0x8e,0xf1,0x03,0xed}}),
# byte-encoded
PROV_GUID_X509_SHA256_HEX='92a4d23bc0967940b420fcf98ef103ed'

# Known EFI variable GUIDs (PK and KEK live in the global namespace; db/dbx in
# the image-security-database namespace)
PROV_GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'   # EFI_GLOBAL_VARIABLE
PROV_GUID_DBASE='d719b2cb-3d3a-4596-a3bc-dad00e67656f'    # EFI_IMAGE_SECURITY_DATABASE
PROV_EFI_ATTRS=7                                          # NV + BS + RT

# esl_build CERT-DER-FILE [OWNER-GUID-DASHED] — EFI_SIGNATURE_LIST on stdout:
# SignatureType(16) + ListSize u32le + HeaderSize u32le(0) + SignatureSize u32le
# + per-entry: owner GUID(16) + cert bytes
esl_build() {
    _esl_cert=$1
    _esl_owner=${2:-}
    [ -f "$_esl_cert" ] || die "esl_build: cert file missing: $_esl_cert"
    case $_esl_owner in
        '') _esl_ohex='00000000000000000000000000000000' ;;
        *-*) _esl_ohex=$(guid_le_hex "$_esl_owner") ;;
        *) die "esl_build: owner GUID must be a dashed UUID or empty" ;;
    esac
    _esl_clen=$(($(wc -c <"$_esl_cert") + 0))
    _esl_ssig=$((16 + _esl_clen))
    _esl_slist=$((16 + 12 + _esl_ssig))
    {
        printf '%s%s%s%s%s' "$PROV_GUID_X509_HEX" "$(le32_hex "$_esl_slist")" "$(le32_hex 0)" "$(le32_hex "$_esl_ssig")" "$_esl_ohex" | hex_to_bin
        cat "$_esl_cert"
    }
}

# esl_sha256_revocation_build OWNER HASHHEX... — EFI_SIGNATURE_LIST of type
# EFI_CERT_X509_SHA256 on stdout (dbx revocation entries, §6 PCR 7): one entry
# per 64-hex To-Be-Signed sha256; each entry = owner GUID(16) + sha256(32) +
# zero EFI_TIME(16) — TimeOfRevocation zero means revoked always. OWNER is a
# dashed UUID or '' (zero GUID). dbx lists may hold many entries in one list.
esl_sha256_revocation_build() {
    _esr_owner=$1
    shift
    case $_esr_owner in
        '') _esr_ohex='00000000000000000000000000000000' ;;
        *-*) _esr_ohex=$(guid_le_hex "$_esr_owner") ;;
        *) die "esl_sha256_revocation_build: owner GUID must be a dashed UUID or empty" ;;
    esac
    _esr_n=0
    _esr_entries=''
    for _esr_h in "$@"; do
        # L-01: validate ALL 64 chars are hex (the old first-char-only glob let
        # 'a' + 63 junk chars through into the dbx ESL as a corrupt entry)
        case $_esr_h in
            '' | *[!0-9a-fA-F]*)
                die "esl_sha256_revocation_build: not a hex sha256: $_esr_h"
                ;;
        esac
        [ ${#_esr_h} -eq 64 ] || die "esl_sha256_revocation_build: hash must be 64 hex chars: $_esr_h"
        _esr_entries="$_esr_entries$_esr_ohex$(printf '%s' "$_esr_h" | tr 'A-F' 'a-f')00000000000000000000000000000000"
        _esr_n=$((_esr_n + 1))
    done
    [ "$_esr_n" -ge 1 ] || die "esl_sha256_revocation_build: at least one hash required"
    _esr_ssig=$((16 + 48))
    _esr_slist=$((16 + 12 + _esr_n * _esr_ssig))
    printf '%s%s%s%s%s' "$PROV_GUID_X509_SHA256_HEX" "$(le32_hex "$_esr_slist")" "$(le32_hex 0)" "$(le32_hex "$_esr_ssig")" "$_esr_entries" | hex_to_bin
}

# prov_cert_tbs_sha256 CERT — sha256 (64 lowercase hex) of the DER-encoded
# tbsCertificate element (header included) — the value dbx EFI_CERT_X509_SHA256
# entries revoke. Accepts DER or PEM input; dies loudly on garbage (ADR-8).
prov_cert_tbs_sha256() {
    _ptc_f=$1
    [ -f "$_ptc_f" ] || die "prov_cert_tbs_sha256: cert file missing: $_ptc_f"
    _ptc_der=$(mktemp "${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}/debian-fde-tbs.XXXXXX")
    if ! openssl asn1parse -inform DER -in "$_ptc_f" >/dev/null 2>&1; then
        openssl x509 -in "$_ptc_f" -outform DER -out "$_ptc_der" 2>/dev/null ||
            { rm -f "$_ptc_der"; die "prov_cert_tbs_sha256: not a parseable certificate: $_ptc_f"; }
        _ptc_src=$_ptc_der
    else
        _ptc_src=$_ptc_f
    fi
    _ptc_asn=$(openssl asn1parse -inform DER -in "$_ptc_src" 2>/dev/null)
    # tbsCertificate = the depth-1 SEQUENCE; take its offset/hl/l from asn1parse
    _ptc_line=$(printf '%s\n' "$_ptc_asn" | grep -m1 'd=1' || true)
    _ptc_off=$(printf '%s' "$_ptc_line" | sed -n 's/^[[:space:]]*\([0-9]*\):.*/\1/p')
    _ptc_hl=$(printf '%s' "$_ptc_line" | sed -n 's/.*hl=\([0-9]*\).*/\1/p')
    _ptc_len=$(printf '%s' "$_ptc_line" | sed -n 's/.*l=[[:space:]]*\([0-9]*\).*/\1/p')
    if [ -z "$_ptc_off" ] || [ -z "$_ptc_hl" ] || [ -z "$_ptc_len" ]; then
        rm -f "$_ptc_der"
        die "prov_cert_tbs_sha256: cannot locate tbsCertificate in $_ptc_f"
    fi
    _ptc_hash=$(tail -c +"$((_ptc_off + 1))" "$_ptc_src" | head -c "$((_ptc_hl + _ptc_len))" | sha256sum | cut -d' ' -f1)
    rm -f "$_ptc_der"
    [ ${#_ptc_hash} -eq 64 ] || die "prov_cert_tbs_sha256: tbs hash extraction failed for $_ptc_f"
    printf '%s\n' "$_ptc_hash"
}

# esl_le32_at HEX CHARS-OFFSET — decode the little-endian u32 at a 1-indexed
# hex-char offset (chars 2n-1..2n are byte n); portable hex decode
esl_le32_at() {
    printf '%s' "$1" | cut -c "$2"-$(( $2 + 7 )) | awk '
    {
        h = "0123456789abcdef"
        v = 0
        # little-endian u32: reverse BYTE pairs, most significant byte last
        for (j = 4; j >= 1; j--) {
            b = 16 * (index(h, tolower(substr($0, 2 * j - 1, 1))) - 1) \
                + (index(h, tolower(substr($0, 2 * j, 1))) - 1)
            v = v * 256 + b
        }
        printf "%d", v
    }'
}

# esl_verify FILE — structural sanity of a signature list (sizes consistent);
# rc 0 ok. Layout: type(16) listsize(4@16) headersize(4@20) sigsize(4@24) data,
# where data holds N >= 1 fixed-size signatures (28 + N*sigsize == total).
esl_verify() {
    _esv_f=$1
    [ -s "$_esv_f" ] || return 1
    _esv_hex=$(bin_to_hex <"$_esv_f")
    _esv_total=$(wc -c <"$_esv_f")
    _esv_list=$(esl_le32_at "$_esv_hex" 33)
    _esv_ssig=$(esl_le32_at "$_esv_hex" 49)
    [ "$_esv_list" -eq "$((_esv_total + 0))" ] || return 1
    [ "$_esv_ssig" -gt 16 ] || return 1
    [ $(( (_esv_total - 28) % _esv_ssig )) -eq 0 ] || return 1
    [ $(( (_esv_total - 28) / _esv_ssig )) -ge 1 ] || return 1
    return 0
}

# auth_packet_build PRIVKEY CERT VARNAME VARGUID ATTRS PAYLOADFILE TIMESTAMP OUT
# Full UEFI EFI_VARIABLE_AUTHENTICATION_2 — what efivarfs/firmware/KeyTool
# parse for a time-based authenticated update:
#   EFI_TIME(16) + EFI_VARIABLE_DATA{VariableGuid(16, LE), DataSize u32le,
#   UnicodeName(UTF-16LE, NUL-terminated)} + WIN_CERTIFICATE_UEFI_GUID
#   (dwLength u32le = 8 + p7, wRevision u16le 0x0200, wCertificateType u16le
#   0x0EF7) + PKCS#7 SignedData (DETACHED — the verifier supplies the
#   descriptor, exactly like efitools KeyTool / shim verify EFI updates).
# The signed descriptor covers name+guid+attrs+time+payload; the envelope
# (GUID/DataSize/name) is what firmware and fw_var_write's identity preflight
# read — without it the packet is unparsable (refused as identity mismatch).
auth_packet_build() {
    _ap_key=$1 _ap_cert=$2 _ap_var=$3 _ap_guid=$4 _ap_attrs=$5 _ap_pay=$6 _ap_ts=$7 _ap_out=$8
    for _ap_f in "$_ap_key" "$_ap_cert" "$_ap_pay"; do
        [ -f "$_ap_f" ] || die "auth_packet_build: missing input: $_ap_f"
    done
    _ap_desc_hex=$(ascii_utf16le_hex "$_ap_var")$(guid_le_hex "$_ap_guid")$(le32_hex "$_ap_attrs")$(efi_time_hex "$_ap_ts")
    _ap_tmp=${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}
    _ap_desc=$(mktemp "$_ap_tmp/debian-fde-desc.XXXXXX")
    _ap_p7=$(mktemp "$_ap_tmp/debian-fde-p7.XXXXXX")
    {
        printf '%s' "$_ap_desc_hex" | hex_to_bin
        cat "$_ap_pay"
    } >"$_ap_desc"
    if ! openssl smime -sign -binary -in "$_ap_desc" -signer "$_ap_cert" -inkey "$_ap_key" \
        -outform DER -out "$_ap_p7" >/dev/null 2>&1; then
        rm -f "$_ap_desc" "$_ap_p7"
        die "auth_packet_build: openssl smime -sign failed for var $_ap_var"
    fi
    _ap_p7sz=$(($(wc -c <"$_ap_p7") + 0))
    _ap_name_hex=$(ascii_utf16le_hex "$_ap_var")0000 # UTF-16LE + NUL terminator
    _ap_name_bytes=$(( (${#_ap_var} + 1) * 2 ))
    _ap_data_sz_hex=$(le32_hex $(( _ap_name_bytes + 8 + _ap_p7sz )))
    {
        efi_time_hex "$_ap_ts" | hex_to_bin                 # EFI_TIME
        guid_le_hex "$_ap_guid" | hex_to_bin                # VariableGuid
        printf '%s' "$_ap_data_sz_hex" | hex_to_bin         # EFI_VARIABLE_DATA.DataSize
        printf '%s' "$_ap_name_hex" | hex_to_bin            # UnicodeName + NUL
        printf '%s%s%s' "$(le32_hex $((8 + _ap_p7sz)))" "$(le16_hex 512)" "$(le16_hex 3831)" | hex_to_bin
        cat "$_ap_p7"
    } >"$_ap_out"
    rm -f "$_ap_desc" "$_ap_p7"
}

# --- stage 1: key ceremony ------------------------------------------------------

prov_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde provision stage1 [--keydir DIR] [--mode in-chroot|offline] [--force]
       debian-fde provision stage2 | debian-fde provision --capture-baseline

stage1  key ceremony (ADR-18):
        --mode offline (default)
            on the OFFLINE signing medium (I4): release keypair (RSA-3072,
            signs UKIs and policy digests, ADR-11) + PK/KEK/db enrollment
            keypairs; EFI_SIGNATURE_LISTs + authenticated update packets;
            firmware enrollment guidance; writes the PENDING baseline
            (expected_pcr7 pending until first boot in the final SB state).
        --mode in-chroot
            the §9.1 step-3 ceremony on the target's encrypted root volume:
            keydir defaults to $DEBIAN_FDE_ROOT/etc/debian-fde/keys; after the
            packet build the release.pem is ENCRYPTED (AES-256 PBKDF2
            HMAC-SHA256, >=600000 iterations, §13 passphrase floor; ADR-18) and
            the PK/KEK/db private keys are shredded — the target keeps certs +
            packets + the encrypted release.pem ONLY. Passphrase:
            DEBIAN_FDE_KEY_PASSPHRASE or interactive prompt.
stage2  capture live PCR 0..3+7 + Secure Boot fingerprints + event log and
        finalize the baseline (same path as `audit --init`).
EOF
}

# prov_keygen DIR PREFIX BITS CN — private key, public key, PEM cert + DER cert
# (the DER copy is what EFI_SIGNATURE_LISTs must embed). L-03: openssl failures
# are LOUD (no 2>/dev/null; under the dispatcher's set -e a silenced failure
# used to terminate stage1 with no message at all, ADR-8).
prov_keygen() {
    _pk_dir=$1 _pk_prefix=$2 _pk_bits=$3 _pk_cn=$4
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$_pk_bits" -out "$_pk_dir/$_pk_prefix.priv.pem" ||
        die "prov_keygen: openssl genpkey failed for $_pk_prefix (disk full? entropy?)"
    openssl pkey -in "$_pk_dir/$_pk_prefix.priv.pem" -pubout -out "$_pk_dir/$_pk_prefix.pub.pem" ||
        die "prov_keygen: openssl pkey -pubout failed for $_pk_prefix"
    openssl req -new -x509 -key "$_pk_dir/$_pk_prefix.priv.pem" \
        -out "$_pk_dir/$_pk_prefix.cert.pem" -days 3650 -sha256 \
        -subj "/O=Debian FDE/CN=$_pk_cn" ||
        die "prov_keygen: openssl req failed for $_pk_prefix"
    openssl x509 -in "$_pk_dir/$_pk_prefix.cert.pem" -outform DER -out "$_pk_dir/$_pk_prefix.cert.der" ||
        die "prov_keygen: openssl x509 -outform DER failed for $_pk_prefix"
    chmod 600 "$_pk_dir/$_pk_prefix.priv.pem"
}

prov_stage1() {
    # arg handling done by caller; $@ contains stage1 args from index 1
    _s1_keydir='' _s1_force=0
    _s1_revoke=''
    # ADR-18/RESOLVED-2: the ceremony defaults to the offline signing medium;
    # --mode in-chroot runs the §9.1 step-3 flow on the target's encrypted root
    _s1_mode=offline
    while [ $# -gt 0 ]; do
        case $1 in
            --keydir)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "stage1: --keydir requires an argument"
                _s1_keydir=$2
                shift
                ;;
            --mode)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "stage1: --mode requires an argument"
                case $2 in
                    in-chroot | offline) _s1_mode=$2 ;;
                    *)
                        die -r "$DEBIAN_FDE_USAGE" "stage1: --mode must be 'in-chroot' or 'offline' (got: $2)"
                        ;;
                esac
                shift
                ;;
            --revoke-cert)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "stage1: --revoke-cert requires an argument"
                # L-02: accumulate NEWLINE-separated (space-joined paths would
                # word-split + glob-expand operator-controlled file paths)
                _s1_revoke="$_s1_revoke$2
"
                shift
                ;;
            --force) _s1_force=1 ;;
            *) die -r "$DEBIAN_FDE_USAGE" "stage1: unknown argument: $1" ;;
        esac
        shift
    done
    _s1_keydir=${_s1_keydir:-${DEBIAN_FDE_KEYDIR:-}}
    if [ -z "$_s1_keydir" ] && [ "$_s1_mode" = "in-chroot" ]; then
        # ADR-18: the in-chroot ceremony lives at the target's key-holding dir
        [ -n "${DEBIAN_FDE_ROOT:-}" ] \
            || die "stage1: --mode in-chroot requires DEBIAN_FDE_ROOT (or an explicit --keydir) — the keydir defaults to \$DEBIAN_FDE_ROOT/etc/debian-fde/keys (ADR-18)"
        _s1_keydir="${DEBIAN_FDE_ROOT}/etc/debian-fde/keys"
    fi
    if [ -z "$_s1_keydir" ]; then
        die "stage1: no key directory — pass --keydir (offline signing medium, I4) or use --mode in-chroot (ADR-18)"
    fi
    # I4 custody: the OFFLINE ceremony must never target the protected root —
    # the guard refuses a keydir under the root that holds no encrypted
    # release.pem (fails closed before ANY key material is written). The
    # in-chroot ceremony is the ADR-18-sanctioned exception: it generates on
    # the target's ENCRYPTED root volume and encrypts+shreds before reboot
    # (§9.1 steps 3+6), so the guard does not apply to it.
    if [ "$_s1_mode" = "offline" ]; then
        keys_offline_guard "$_s1_keydir"
    fi
    require_pkgs openssl:openssl

    for _s1_f in release.pem release.pub release.crt \
        pk.priv.pem pk.pub.pem pk.cert.pem \
        kek.priv.pem kek.pub.pem kek.cert.pem \
        db.priv.pem db.pub.pem db.cert.pem \
        dbx.esl dbx.auth; do
        if [ -e "$_s1_keydir/$_s1_f" ] && [ "$_s1_force" -eq 0 ]; then
            die "stage1: $_s1_keydir/$_s1_f already exists (use --force to overwrite)"
        fi
    done
    # M-03: --force regenerates all four keypairs, wiping the previous KEK
    # private key. dbx.esl/dbx.auth left over from an earlier --revoke-cert run
    # would be signed by that JUST-DELETED key — enrolling them would resurrect
    # stale revocation state. Remove them loudly; rebuilding requires an
    # explicit --revoke-cert re-run (never leave stage1's output inconsistent
    # with what it prints).
    if [ "$_s1_force" -eq 1 ] && [ -z "$_s1_revoke" ] &&
        { [ -e "$_s1_keydir/dbx.esl" ] || [ -e "$_s1_keydir/dbx.auth" ]; }; then
        rm -f "$_s1_keydir/dbx.esl" "$_s1_keydir/dbx.auth"
        warn "stage1: --force without --revoke-cert — removed STALE dbx.esl/dbx.auth (signed by the deleted KEK); re-run with --revoke-cert to rebuild the revocation list"
    fi
    mkdir -p "$_s1_keydir"

    info "generating release key (RSA-3072; the one identity for UKI + policy signatures, ADR-11)"
    prov_keygen "$_s1_keydir" release 3072 "Debian FDE Release Key"
    # release key also under the keys.sh convention (keys_check/sbsign/enroll
    # read release.pem/release.crt/release.pub — ADR-11 single identity)
    cp "$_s1_keydir/release.priv.pem" "$_s1_keydir/release.pem"
    cp "$_s1_keydir/release.pub.pem" "$_s1_keydir/release.pub"
    cp "$_s1_keydir/release.cert.pem" "$_s1_keydir/release.crt"
    chmod 600 "$_s1_keydir/release.pem"
    info "generating enrollment-only keys (PK, KEK, db — RSA-2048)"
    prov_keygen "$_s1_keydir" pk 2048 "Debian FDE Platform Key"
    prov_keygen "$_s1_keydir" kek 2048 "Debian FDE Key Exchange Key"
    prov_keygen "$_s1_keydir" db 2048 "Debian FDE Database Key"
    # ESLs must embed DER certificates — fail loudly on a malformed cert (ADR-8)
    for _s1_p in release pk kek db; do
        if ! openssl x509 -inform DER -in "$_s1_keydir/$_s1_p.cert.der" -noout >/dev/null 2>&1; then
            die "stage1: $_s1_keydir/$_s1_p.cert.der is not a valid DER certificate"
        fi
    done

    _s1_ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    info "building EFI_SIGNATURE_LISTs and authenticated update packets"
    # db is authenticated by the KEK, KEK by the PK, PK by itself (self-signed)
    esl_build "$_s1_keydir/db.cert.der" >"$_s1_keydir/db.esl"
    esl_build "$_s1_keydir/kek.cert.der" >"$_s1_keydir/kek.esl"
    esl_build "$_s1_keydir/pk.cert.der" >"$_s1_keydir/pk.esl"
    # db is authenticated by the KEK, KEK by the PK, PK by itself (self-signed)
    auth_packet_build "$_s1_keydir/kek.priv.pem" "$_s1_keydir/kek.cert.pem" \
        db "$PROV_GUID_DBASE" "$PROV_EFI_ATTRS" "$_s1_keydir/db.esl" "$_s1_ts" "$_s1_keydir/db.auth"
    auth_packet_build "$_s1_keydir/pk.priv.pem" "$_s1_keydir/pk.cert.pem" \
        KEK "$PROV_GUID_GLOBAL" "$PROV_EFI_ATTRS" "$_s1_keydir/kek.esl" "$_s1_ts" "$_s1_keydir/kek.auth"
    auth_packet_build "$_s1_keydir/pk.priv.pem" "$_s1_keydir/pk.cert.pem" \
        PK "$PROV_GUID_GLOBAL" "$PROV_EFI_ATTRS" "$_s1_keydir/pk.esl" "$_s1_ts" "$_s1_keydir/pk.auth"

    # §6 (PCR 7 row): "provision removes vendor certs from db so the expected
    # value is fully ours" — our db.esl holds ONLY our cert (an authenticated
    # db update REPLACES the whole variable), and each --revoke-cert is
    # additionally revoked via a dbx EFI_CERT_X509_SHA256 entry (KEK-signed,
    # sha256 of the cert's TBS), so firmware rejects it even if re-added.
    if [ -n "$_s1_revoke" ]; then
        info "building dbx revocation list (vendor certs, EFI_CERT_X509_SHA256)"
        _s1_rev_hashes=''
        # L-02: iterate the newline-separated list without word splitting
        while IFS= read -r _s1_rc; do
            [ -n "$_s1_rc" ] || continue
            [ -f "$_s1_rc" ] || die "stage1: --revoke-cert file missing: $_s1_rc"
            _s1_rh=$(prov_cert_tbs_sha256 "$_s1_rc")
            info "  revoking $_s1_rc (tbs sha256 $_s1_rh)"
            _s1_rev_hashes="$_s1_rev_hashes $_s1_rh"
        done <<EOF
$_s1_revoke
EOF
        # shellcheck disable=SC2086
        esl_sha256_revocation_build '' $_s1_rev_hashes >"$_s1_keydir/dbx.esl"
        # dbx is authenticated by the KEK (or PK) per the UEFI spec
        auth_packet_build "$_s1_keydir/kek.priv.pem" "$_s1_keydir/kek.cert.pem" \
            dbx "$PROV_GUID_DBASE" "$PROV_EFI_ATTRS" "$_s1_keydir/dbx.esl" "$_s1_ts" "$_s1_keydir/dbx.auth"
    fi

    # --- ADR-18 in-chroot custody finalization (§9.1 step 6, RESOLVED-3) ---------
    # Before reboot NO plaintext signing key may remain on the target: encrypt
    # release.pem in place (PBES2 aes-256-cbc / hmacWithSHA256 / iter
    # 600000, §13 passphrase floor; keys_encrypt_release also scrubs the
    # release.priv.pem duplicate + staging), then zeroize+rm the enrollment
    # private keys — the target keeps certs + packets + the encrypted
    # release.pem ONLY. Post-asserts fail closed (64) on any violation.
    if [ "$_s1_mode" = "in-chroot" ]; then
        info "ADR-18 custody: encrypting release.pem on the target (PBES2 aes-256-cbc, hmacWithSHA256, iter $KEYS_PBKDF2_ITER) before reboot"
        keys_encrypt_release "$_s1_keydir"
        keys_scrub "$_s1_keydir/release.priv.pem" \
            "$_s1_keydir/pk.priv.pem" "$_s1_keydir/kek.priv.pem" "$_s1_keydir/db.priv.pem"
        if ! keys_is_encrypted "$_s1_keydir/release.pem"; then
            die "stage1: custody post-assert failed: $_s1_keydir/release.pem is not ADR-18-encrypted — refusing to finish (I4/ADR-18)"
        fi
        for _s1_p in release.priv.pem pk.priv.pem kek.priv.pem db.priv.pem; do
            if [ -e "$_s1_keydir/$_s1_p" ]; then
                die "stage1: custody post-assert failed: plaintext $_s1_p survived on the target (I4/ADR-18)"
            fi
        done
    fi

    if [ "$_s1_mode" = "in-chroot" ]; then
        info "custody checklist (ADR-18): release.pem ENCRYPTED at $_s1_keydir/release.pem — confirmed (PBES2 aes-256-cbc, hmacWithSHA256, iter $KEYS_PBKDF2_ITER)"
        info "  pk/kek/db private keys shredded after the packet build — the target keeps certs +"
        info "  packets + the encrypted release.pem ONLY"
        info "  back up $_s1_keydir (certs + packets + encrypted release.pem) off-machine via scp (ADR-18)"
    else
        info "custody checklist (I4/ADR-18): the medium holds the keypairs; the target must never"
        info "  receive plaintext private keys — the only private key that may live on the target"
        info "  is the ENCRYPTED release.pem (ADR-18); the medium also holds pk/kek/db private keys"
        info "  — needed only for re-provisioning"
    fi
    info "firmware enrollment (CI, offline vars):"
    printf '  virt-fw-vars --input OVMF_VARS.fd --output OVMF_VARS.debian-fde.fd \\\n' >&2
    printf '      --secure-boot --set-pk  "PK,%s" %s/pk.esl \\\n' "$PROV_GUID_GLOBAL" "$_s1_keydir" >&2
    printf '      --set-kek "KEK,%s" %s/kek.esl --set-db "db,%s" %s/db.esl\n' "$PROV_GUID_GLOBAL" "$_s1_keydir" "$PROV_GUID_DBASE" "$_s1_keydir" >&2
    info "firmware enrollment (real hardware): copy pk.esl/kek.esl/db.esl (+ .auth packets) to a"
    info "  FAT USB stick and enroll via the firmware setup UI or KeyTool.efi (efitools);"
    info "  if the UI accepts only .auth/.esl files, use the .auth packets"
    if [ -n "$_s1_revoke" ]; then
        info "vendor-cert revocation (§6 PCR 7): enroll dbx.esl/dbx.auth alongside db — the dbx"
        info "  entries revoke the vendor certs by TBS hash so the expected PCR 7 value is fully ours"
        printf '  virt-fw-vars: add  --set-dbx "dbx,%s" %s/dbx.esl\n' "$PROV_GUID_DBASE" "$_s1_keydir" >&2
    fi

    info "writing PENDING baseline (expected_pcr7=pending; finalizes after first boot: audit --init)"
    # BL_* variables are the baseline_write env contract (consumed in baseline.sh)
    # shellcheck disable=SC2034  # env-contract for baseline_write
    BL_PCR0='pending'
    BL_PCR1='pending'
    BL_PCR2='pending'
    BL_PCR3='pending'
    BL_PCR7='pending'
    if tpm_available; then
        for _s1_i in 0 1 2 3; do
            if _s1_v=$(tpm_pcr_read "$_s1_i") && [ -n "$_s1_v" ]; then
                eval "BL_PCR$_s1_i=\$_s1_v"
            fi
        done
    else
        warn "no TPM reachable — pcr0..3 left pending in the baseline"
    fi
    if _s1_sb=$(fw_sb_state); then
        BL_SB_SECURE_BOOT=$(printf '%s' "$_s1_sb" | sed -n 's/.*secureboot=\([01]\).*/\1/p')
        BL_SB_SETUP_MODE=$(printf '%s' "$_s1_sb" | sed -n 's/.*setup_mode=\([01]\).*/\1/p')
    fi
    for _s1_pair in PK:pk_fp KEK:kek_fp db:db_fp dbx:dbx_fp; do
        _s1_fp=$(fw_var_sha256 "${_s1_pair%%:*}") || _s1_fp=''
        eval "BL_SB_$(printf '%s' "${_s1_pair#*:}" | tr '[:lower:]' '[:upper:]')=\$_s1_fp"
    done
    BL_FW_VENDOR=$(dmi_field sys_vendor)
    BL_FW_VERSION=$(dmi_field bios_version)
    if _s1_el=$(eventlog_info); then
        BL_FW_EVENTLOG_SHA256=$(printf '%s' "$_s1_el" | cut -d' ' -f1)
        BL_FW_EVENTLOG_SIZE=$(printf '%s' "$_s1_el" | cut -d' ' -f2)
    fi
    BL_KEYS_RELEASE_PUB_PATH="$_s1_keydir/release.pub"
    BL_KEYS_RELEASE_CERT_PATH="$_s1_keydir/release.crt"
    BL_TARGET_LUKS_UUID=''
    BL_TARGET_ESP_PARTUUID=''
    _s1_bl=$(sp_baseline_file)
    baseline_write "$_s1_bl"
    baseline_validate "$_s1_bl" || die "stage1: produced an invalid baseline"
    printf 'debian-fde: provision stage1 complete — baseline: %s\n' "$_s1_bl" >&2
    return 0
}

prov_stage2() {
    _s2_bl=$(sp_baseline_file)
    [ -f "$_s2_bl" ] || die "stage2: no baseline at $_s2_bl (run 'debian-fde provision stage1' first)"
    _s2_force=0
    while [ $# -gt 0 ]; do
        case $1 in
            --force) _s2_force=1 ;;
            *) die -r "$DEBIAN_FDE_USAGE" "stage2: unknown argument: $1" ;;
        esac
        shift
    done
    if baseline_is_final "$_s2_bl"; then
        [ "$_s2_force" -eq 1 ] || die "stage2: baseline already finalized — use 'debian-fde audit --accept' to re-baseline (§9.4)"
        [ "${DEBIAN_FDE_YES:-0}" = "1" ] || die "stage2: --force over a FINAL baseline overwrites the PCR 7 binding — set DEBIAN_FDE_YES=1 to confirm, or use 'debian-fde audit --accept' (§9.4)"
        warn "stage2: --force re-capturing a FINAL baseline (operator-confirmed)"
    fi
    info "capturing live PCR 0..3+7, Secure Boot fingerprints, event log; finalizing baseline"
    baseline_finalize_from_live
    printf 'debian-fde: baseline finalized: %s\n' "$_s2_bl" >&2
    return 0
}

cmd_provision_main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        prov_usage
        return 0
    fi
    _pm_stage=${1:-}
    [ -n "$_pm_stage" ] || {
        prov_usage
        return "$DEBIAN_FDE_USAGE"
    }
    shift
    case $_pm_stage in
        stage1)
            prov_stage1 "$@"
            ;;
        stage2 | --capture-baseline)
            prov_stage2 "$@"
            ;;
        *)
            die -r "$DEBIAN_FDE_USAGE" "provision: unknown stage: $_pm_stage (want stage1 | stage2 | --capture-baseline)"
            ;;
    esac
}
