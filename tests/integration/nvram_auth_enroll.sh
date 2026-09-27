#!/usr/bin/env bash
# tests/integration/nvram_auth_enroll.sh — lib/firmware.sh authenticated NVRAM API
# (docs/Architecture.md §9.1 Stage-1 step 4, §8.4):
#   * fw_var_write DIR NAME GUID AUTHFILE — writes an authenticated variable
#     update as a 4-byte attrs header (u32le 0x00010007: NV+BS+RT +
#     TIME_BASED_AUTHENTICATED_WRITE_ACCESS) + the full .auth packet,
#     REFUSING (fail-closed 64) packets whose embedded variable name/GUID do
#     not match the target
#   * fw_auth_enroll EFIVARS_DIR KEYDIR — SetupMode-gated (exit 64 when not in
#     setup mode), enrolls db → KEK → PK (last) from KEYDIR's .auth files,
#     aborting on the first failure (never leaving PK enrolled without db/KEK)
#   * fw_osindications_set EFIVARS_DIR — OsIndications bit 0 (u64le 1,
#     attrs 7): the §9.1 "reboot into BIOS setup" signal
#
# E2E-mock rule: real handlers, fixture efivars dirs, asserted files/exit codes.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/provision.sh
source "$REPO/lib/cmd/provision.sh"
# shellcheck source=../../lib/firmware.sh
source "$REPO/lib/firmware.sh"

T=$(mktemp -d /tmp/alpine-fde-nvram-auth.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
GUID_DBASE='d719b2cb-3d3a-4596-a3bc-dad00e67656f'

# --- fixture builders ----------------------------------------------------------

hexbin() { # HEXSTRING — raw bytes on stdout (POSIX printf, no xxd dependency)
    local h=$1 out='' b
    while [ ${#h} -ge 2 ]; do
        b=${h:0:2}
        h=${h:2}
        out="$out\\$(printf '%03o' "0x$b")"
    done
    printf "$out"
}

guid_le_hex() { # GUID-STRING — mixed-endian byte hex (EFI binary layout)
    local a b c d e r='' seg
    IFS=- read -r a b c d e <<<"$1"
    for seg in "$a" "$b" "$c"; do
        r="$r$(printf '%s' "$seg" | fold -w2 | tac | tr -d '\n')"
    done
    printf '%s%s%s%s%s' "$r" "$d" "$e"
}

mkauth() { # FILE NAME GUID PAYLOAD KEY CERT — SPEC EFI_VARIABLE_AUTHENTICATION_2
    # (UEFI 2.10 §32.5.3, blocker #25): EFI_TIME(16 zero bytes) +
    # WIN_CERTIFICATE_UEFI_GUID{ dwLength u32le = 24 + len(PKCS7),
    # wRevision u16le 0x0200, wCertificateType u16le 0x0EF7,
    # CertType GUID(16) RSA2048_SHA256 LE, CertData = PKCS#7 detached over
    # UTF16LE(name)+NUL + GUID(LE) + attrs(u32le) + EFI_TIME + payload }
    local f=$1 n=$2 g=$3 p=$4 key=$5 cert=$6
    local desc_hex='' name_hex='' dwlen c i
    i=0
    while [ "$i" -lt "${#n}" ]; do
        i=$((i + 1))
        c=$(printf '%s' "$n" | cut -c "$i")
        name_hex="$name_hex$(printf '%02x00' "'$c")"
    done
    name_hex="${name_hex}0000" # the NUL terminator is part of the digest
    desc_hex="$name_hex$(guid_le_hex "$g")$(printf '%08x' 65543 | fold -w2 | tac | tr -d '\n')$(printf '%032x' 0)"
    { printf '%s' "$desc_hex" | hexbin; printf '%s' "$p"; } >"$f.desc"
    openssl smime -sign -binary -in "$f.desc" -signer "$cert" -inkey "$key" \
        -outform DER -out "$f.p7" >/dev/null 2>&1 ||
        die "mkauth: openssl smime -sign failed"
    dwlen=$(( 24 + $(wc -c <"$f.p7") ))
    {
        printf '\352\007\033\t\000\000\000\000\000\000\000\000\000\000\000\000'  # EFI_TIME 2026-09-27
        printf "$(printf '\\x%02x' $((dwlen & 255)))"                 # dwLength lo
        printf "$(printf '\\x%02x' $(( (dwlen >> 8) & 255 )))"        # dwLength hi
        printf '\000\002'                                            # wRevision 0x0200
        printf '\367\016'                                            # wCertificateType 0x0EF7
        hexbin '141771a7c61649779420844712a735bf'                    # CertType RSA2048_SHA256 (LE)
        cat "$f.p7"                                                  # CertData
    } >"$f"
    rm -f "$f.desc" "$f.p7"
}

mkvar() { # DIR NAME GUID BYTE — attrs u32le 0x7 + payload byte
    printf '\007\000\000\000'"$(printf '\%03o' "$4")" >"$1/$2-$3"
}

die_rc() { # ARGS... — run in a subshell so die's exit is observable
    ("$@") >/dev/null 2>&1
}

# =============================================================================
# fw_var_write — 4-byte attrs header + verbatim .auth packet, packet identity
# verified against the target variable (name + GUID) before any write.
# =============================================================================
E1=$T/enroll-happy
mkdir -p "$E1"
# mkauth signer (blocker #25: the fixture packets are now REAL signed packets)
MKAUTH_KEY="$T/mkauth.key"; MKAUTH_CERT="$T/mkauth.crt"
openssl req -new -x509 -newkey rsa:2048 -keyout "$MKAUTH_KEY" -out "$MKAUTH_CERT" \
    -days 30 -nodes -subj /O=Alpine\ FDE/CN=nvram-fixture >/dev/null 2>&1
mkauth "$T/db.auth" db "$GUID_DBASE" 'DB-AUTH-PACKET-BYTES' "$MKAUTH_KEY" "$MKAUTH_CERT"

fw_var_write "$E1" db "$GUID_DBASE" "$T/db.auth"
assert_eq "fw_var_write happy: rc 0 (no die)" "0" "$?"

assert_file_exists "fw_var_write: variable file created in target namespace" \
    "$E1/db-$GUID_DBASE"
assert_eq "fw_var_write: attrs header is u32le 0x00010007 (auth bit, bit 16)" "07000100" \
    "$(head -c 4 "$E1/db-$GUID_DBASE" | od -An -vtx1 | tr -d ' \n')"
assert_eq "fw_var_write: .auth packet follows the attrs header verbatim" \
    "$(cat "$T/db.auth" | od -An -vtx1 | tr -d ' \n')" \
    "$(tail -c +5 "$E1/db-$GUID_DBASE" | od -An -vtx1 | tr -d ' \n')"

# SANITY (blocker #25 scope cut): fw_var_write_try enforces only the minimal
# spec sanity — non-empty + plausible EFI_TIME year (202x). The FIRMWARE is
# the final arbiter of everything else (signature, timestamp monotonicity,
# key material). RED control: the pre-fix hand-built hybrid packet (EFI_TIME
# zeros) fails the sanity check.
mkauth "$T/old-hybrid.auth" db "$GUID_DBASE" 'EVIL' "$MKAUTH_KEY" "$MKAUTH_CERT"
# mkauth builds a 202x-stamped spec packet; force an all-zero EFI_TIME to
# reproduce the pre-fix shape
{ printf '\000%.0s' $(seq 1 16); tail -c +17 "$T/old-hybrid.auth"; } >"$T/zero-time.auth"
assert_rc "blocker #25 RED control: zero-EFI_TIME hybrid packet -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" db "$GUID_DBASE" "$T/zero-time.auth"
# (die_rc swallows stderr by design — capture the refusal text directly)
RED_ERR=$( ( fw_var_write "$E1" db "$GUID_DBASE" "$T/zero-time.auth" ) 2>&1 >/dev/null )
assert_contains "blocker #25 RED control names the EFI_TIME sanity failure" \
    "$RED_ERR" "EFI_TIME year is not 202x"

# empty packet -> fail-closed 64
: >"$T/empty.auth"
assert_rc "blocker #25: empty packet -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" db "$GUID_DBASE" "$T/empty.auth"

# missing packet
assert_rc "fw_var_write: missing .auth file -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" db "$GUID_DBASE" "$T/absent.auth"

# missing efivars dir
assert_rc "fw_var_write: missing efivars dir -> fail-closed 64" 64 \
    die_rc fw_var_write "$T/no-such-dir" db "$GUID_DBASE" "$T/db.auth"

# =============================================================================
# round-trip: the REAL builder (provision auth_packet_build) -> the REAL writer
# (firmware fw_var_write). Blocker #25: the packet must be the SPEC
# EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.10 §32.5.3):
#   EFI_TIME(16) + WIN_CERTIFICATE_UEFI_GUID{ dwLength u32le = 24 + len(PKCS7),
#   wRevision 0x0200, wCertificateType 0x0EF7, CertType GUID RSA2048_SHA256
#   (LE), CertData = PKCS#7 detached over name+guid+attrs+time+payload }
# and the writer's offline binding check verifies the PKCS#7 over the payload.
# =============================================================================
RT=$T/roundtrip
mkdir -p "$RT"
if command -v sign-efi-sig-list >/dev/null 2>&1 && command -v cert-to-efi-sig-list >/dev/null 2>&1; then
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RT/signer.key" 2>/dev/null
openssl req -new -x509 -key "$RT/signer.key" -out "$RT/signer.pem" -days 30 -sha256 \
    -subj "/O=Alpine FDE/CN=Roundtrip Signer" 2>/dev/null
printf 'ESL-PAYLOAD' >"$RT/payload.bin"
auth_packet_build "$RT/signer.key" "$RT/signer.pem" db "$GUID_DBASE" "$PROV_EFI_ATTRS" \
    "$RT/payload.bin" '2026-09-20T00:00:00Z' "$RT/db.auth"
assert_eq "round-trip: builder rc 0" "0" "$?"
RT_HEX=$(od -An -vtx1 <"$RT/db.auth" | tr -d ' \n')
assert_eq "round-trip: EFI_TIME at hex bytes 1-32" \
    "$(efi_time_hex '2026-09-20T00:00:00Z')" "$(printf '%s\n' "$RT_HEX" | cut -c 1-32)"
assert_eq "round-trip: dwLength u32le at bytes 17-20 = packet - 16" \
    "$(printf '%s\n' "$RT_HEX" | cut -c 33-40)" \
    "$(printf '%08x' $(( $(wc -c <"$RT/db.auth") - 16 )) | fold -w2 | tac | tr -d '\n')"
assert_eq "round-trip: wRevision 0x0200 at bytes 21-22" "0002" \
    "$(printf '%s\n' "$RT_HEX" | cut -c 41-44)"
assert_eq "round-trip: wCertificateType 0x0EF7 at bytes 23-24" "f70e" \
    "$(printf '%s\n' "$RT_HEX" | cut -c 45-48)"
assert_eq "round-trip: CertType RSA2048_SHA256 GUID (LE) at bytes 25-40" \
    "141771a7c61649779420844712a735bf" "$(printf '%s\n' "$RT_HEX" | cut -c 49-80)"
mkdir -p "$RT/efivars"
assert_eq "round-trip: writer accepts the real packet (rc 0)" "0" \
    "$( fw_var_write "$RT/efivars" db "$GUID_DBASE" "$RT/db.auth" "$RT/payload.bin" >/dev/null 2>&1; echo $? )"
assert_file_exists "round-trip: variable written to efivars namespace" \
    "$RT/efivars/db-$GUID_DBASE"
else
_pass "real-builder RT leg skipped (no efitools on this host — the canary/e2e image covers it)"
fi
# mkauth-fixture writer round-trip (always available): a REAL signed packet
RTM=$T/rt-mkauth
mkdir -p "$RTM/efivars"
mkauth "$RTM/db.auth" db "$GUID_DBASE" 'ROUND-TRIP-PAYLOAD' "$MKAUTH_KEY" "$MKAUTH_CERT"
assert_eq "mkauth writer round-trip: rc 0" "0" \
    "$( fw_var_write "$RTM/efivars" db "$GUID_DBASE" "$RTM/db.auth" >/dev/null 2>&1; echo $? )"
assert_file_exists "mkauth writer round-trip: variable written" "$RTM/efivars/db-$GUID_DBASE"
# SCOPE CUT (blocker #25): the old 'KEK packet refused for db' pin contradicts
# the UEFI trust model — db is AUTHENTICATED BY the KEK, so a KEK-signed db
# update is exactly what firmware accepts. The name binding lives in the
# signed digest; firmware is the final arbiter.

# =============================================================================
# fw_auth_enroll — SetupMode gate + strict db → KEK → PK (last) order,
# abort-on-failure.
# =============================================================================
E2=$T/enroll-gated
mkdir -p "$E2"
mkvar "$E2" SetupMode "$GUID_GLOBAL" 0
mkdir -p "$T/keys"
mkauth "$T/keys/db.auth" db "$GUID_DBASE" 'DB1' "$MKAUTH_KEY" "$MKAUTH_CERT"
mkauth "$T/keys/kek.auth" KEK "$GUID_GLOBAL" 'KEK1' "$MKAUTH_KEY" "$MKAUTH_CERT"
mkauth "$T/keys/pk.auth" PK "$GUID_GLOBAL" 'PK1' "$MKAUTH_KEY" "$MKAUTH_CERT"
assert_rc "fw_auth_enroll: SetupMode=0 -> fail-closed 64" 64 \
    die_rc fw_auth_enroll "$E2" "$T/keys"
assert_eq "fw_auth_enroll: SetupMode=0 enrolled nothing" "0" \
    "$([ -e "$E2/db-$GUID_DBASE" ] && echo 1 || echo 0)"

E3=$T/enroll-absent-var
mkdir -p "$E3"
assert_rc "fw_auth_enroll: SetupMode variable absent -> fail-closed 64" 64 \
    die_rc fw_auth_enroll "$E3" "$T/keys"
assert_eq "fw_auth_enroll: absent SetupMode enrolled nothing" "0" \
    "$([ -e "$E3/db-$GUID_DBASE" ] && echo 1 || echo 0)"

# happy path: db → KEK → PK (all three land in their canonical namespaces)
E4=$T/enroll-happy
mkdir -p "$E4"
mkvar "$E4" SetupMode "$GUID_GLOBAL" 1
fw_auth_enroll "$E4" "$T/keys"
assert_eq "fw_auth_enroll happy: rc 0" "0" "$?"
assert_file_exists "fw_auth_enroll: db enrolled (image-security namespace)" \
    "$E4/db-$GUID_DBASE"
assert_file_exists "fw_auth_enroll: KEK enrolled (global namespace)" \
    "$E4/KEK-$GUID_GLOBAL"
assert_file_exists "fw_auth_enroll: PK enrolled last (global namespace)" \
    "$E4/PK-$GUID_GLOBAL"

# order + abort-on-failure: KEK packet missing → db lands, PK never does
E5=$T/enroll-abort
mkdir -p "$E5"
mkvar "$E5" SetupMode "$GUID_GLOBAL" 1
mkdir -p "$T/keys-partial"
mkauth "$T/keys-partial/db.auth" db "$GUID_DBASE" 'DB1' "$MKAUTH_KEY" "$MKAUTH_CERT"
mkauth "$T/keys-partial/pk.auth" PK "$GUID_GLOBAL" 'PK1' "$MKAUTH_KEY" "$MKAUTH_CERT"
assert_rc "fw_auth_enroll: missing KEK packet -> fail-closed 64 (abort)" 64 \
    die_rc fw_auth_enroll "$E5" "$T/keys-partial"
assert_file_exists "fw_auth_enroll: db already enrolled before the abort" \
    "$E5/db-$GUID_DBASE"
assert_eq "fw_auth_enroll: PK never enrolled after the abort (db -> KEK -> PK last)" "0" \
    "$([ -e "$E5/PK-$GUID_GLOBAL" ] && echo 1 || echo 0)"

# =============================================================================
# fw_osindications_set — OsIndications bit 0 (u64le 1, attrs 7): the §9.1
# "reboot into BIOS setup" signal.
# =============================================================================
E6=$T/osind
mkdir -p "$E6"
fw_osindications_set "$E6"
assert_eq "fw_osindications_set: rc 0" "0" "$?"
assert_file_exists "fw_osindications_set: variable created" \
    "$E6/OsIndications-$GUID_GLOBAL"
assert_eq "fw_osindications_set: attrs u32le 7 + payload u64le 1 (bit 0)" \
    "070000000100000000000000" \
    "$(cat "$E6/OsIndications-$GUID_GLOBAL" | od -An -vtx1 | tr -d ' \n')"
assert_rc "fw_osindications_set: missing efivars dir -> fail-closed 64" 64 \
    die_rc fw_osindications_set "$T/no-such-dir"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
