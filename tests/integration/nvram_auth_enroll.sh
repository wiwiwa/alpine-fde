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

mkauth() { # FILE NAME GUID PAYLOAD — minimal EFI_VARIABLE_AUTHENTICATION_2:
    # EFI_TIME(16 zero bytes) + EFI_VARIABLE_DATA{GUID(16), DataSize u32le,
    # UnicodeName (UTF-16LE), VariableData}
    local f=$1 n=$2 g=$3 p=$4
    local size=$(( ${#n} * 2 + ${#p} ))
    local name_hex='' c hex
    while IFS= read -r c || [ -n "$c" ]; do
        [ -n "$c" ] || continue
        name_hex="$name_hex$(printf '%02x00' "'$c")"
    done < <(printf '%s\n' "$n" | fold -w1)
    hex=$(printf '%032d' 0)
    hex="$hex$(guid_le_hex "$g")"
    hex="$hex$(printf '%08x' "$size" | fold -w2 | tac | tr -d '\n')"
    hex="$hex$name_hex"
    hex="$hex$(printf '%s' "$p" | od -An -vtx1 | tr -d ' \n')"
    hexbin "$hex" >"$f"
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
mkauth "$T/db.auth" db "$GUID_DBASE" 'DB-AUTH-PACKET-BYTES'

fw_var_write "$E1" db "$GUID_DBASE" "$T/db.auth"
assert_eq "fw_var_write happy: rc 0 (no die)" "0" "$?"

assert_file_exists "fw_var_write: variable file created in target namespace" \
    "$E1/db-$GUID_DBASE"
assert_eq "fw_var_write: attrs header is u32le 0x00010007 (auth bit, bit 16)" "07000100" \
    "$(head -c 4 "$E1/db-$GUID_DBASE" | od -An -vtx1 | tr -d ' \n')"
assert_eq "fw_var_write: .auth packet follows the attrs header verbatim" \
    "$(cat "$T/db.auth" | od -An -vtx1 | tr -d ' \n')" \
    "$(tail -c +5 "$E1/db-$GUID_DBASE" | od -An -vtx1 | tr -d ' \n')"

# GUID mismatch: a packet naming a different GUID must be refused fail-closed
mkauth "$T/wrong-guid.auth" db "$GUID_GLOBAL" 'EVIL'
assert_rc "fw_var_write: GUID mismatch -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" db "$GUID_DBASE" "$T/wrong-guid.auth"
assert_eq "fw_var_write: GUID mismatch wrote nothing" "0" \
    "$([ -e "$E1/db-$GUID_DBASE-eviltmp" ] && echo 1 || echo 0)"

# NAME mismatch: a db packet aimed at KEK must be refused
assert_rc "fw_var_write: NAME mismatch -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" KEK "$GUID_GLOBAL" "$T/db.auth"
assert_eq "fw_var_write: NAME mismatch wrote nothing" "0" \
    "$([ -e "$E1/KEK-$GUID_GLOBAL" ] && echo 1 || echo 0)"

# missing packet
assert_rc "fw_var_write: missing .auth file -> fail-closed 64" 64 \
    die_rc fw_var_write "$E1" db "$GUID_DBASE" "$T/absent.auth"

# missing efivars dir
assert_rc "fw_var_write: missing efivars dir -> fail-closed 64" 64 \
    die_rc fw_var_write "$T/no-such-dir" db "$GUID_DBASE" "$T/db.auth"

# =============================================================================
# round-trip: the REAL builder (provision auth_packet_build) → the REAL writer
# (firmware fw_var_write). The 2026-09-20 real-hardware install died here: the
# builder emitted EFI_TIME + WIN_CERTIFICATE + PKCS7 with NO EFI_VARIABLE_DATA
# envelope, so the writer's identity preflight read the WIN_CERT header bytes
# as the variable GUID and refused. The packet must be the full UEFI
# EFI_VARIABLE_AUTHENTICATION_2 (what firmware/KeyTool parse):
#   EFI_TIME(16) + EFI_VARIABLE_DATA{GUID(16), DataSize u32le,
#   UnicodeName UTF-16LE} + WIN_CERT{dwLength, wRevision 0x0200,
#   wCertificateType 0x0EF7} + PKCS#7
# =============================================================================
RT=$T/roundtrip
mkdir -p "$RT"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RT/signer.key" 2>/dev/null
openssl req -new -x509 -key "$RT/signer.key" -out "$RT/signer.pem" -days 30 -sha256 \
    -subj "/O=Alpine FDE/CN=Roundtrip Signer" 2>/dev/null
printf 'ESL-PAYLOAD' >"$RT/payload.bin"
auth_packet_build "$RT/signer.key" "$RT/signer.pem" db "$GUID_DBASE" "$PROV_EFI_ATTRS" \
    "$RT/payload.bin" '2026-09-20T00:00:00Z' "$RT/db.auth"
assert_eq "round-trip: builder rc 0" "0" "$?"
RT_HEX=$(bin_to_hex <"$RT/db.auth")
assert_eq "round-trip: GUID at bytes 17-32 (EFI_VARIABLE_DATA, LE)" \
    "$(guid_le_hex "$GUID_DBASE")" "$(printf '%s\n' "$RT_HEX" | cut -c 33-64)"
RT_DS=$((16#$(printf '%s\n' "$RT_HEX" | cut -c 65-72 | fold -w2 | tac | tr -d '\n')))
# exact: DataSize = name(6, incl NUL) + WIN_CERT(8+p7); total = 16+16+4+DataSize
assert_eq "round-trip: DataSize = packet - 36 (name + cert body)" \
    "$(( $(wc -c <"$RT/db.auth") - 36 ))" "$RT_DS"
assert_eq "round-trip: UnicodeName 'db' at byte 37" "640062000000" \
    "$(printf '%s\n' "$RT_HEX" | cut -c 73-84)"
mkdir -p "$RT/efivars"
assert_eq "round-trip: writer accepts the real packet (rc 0)" "0" \
    "$( fw_var_write "$RT/efivars" db "$GUID_DBASE" "$RT/db.auth" >/dev/null 2>&1; echo $? )"
assert_file_exists "round-trip: variable written to efivars namespace" \
    "$RT/efivars/db-$GUID_DBASE"
# tamper control: a packet aimed at KEK must not program db
auth_packet_build "$RT/signer.key" "$RT/signer.pem" KEK "$GUID_GLOBAL" "$PROV_EFI_ATTRS" \
    "$RT/payload.bin" '2026-09-20T00:00:00Z' "$RT/kek.auth"
assert_rc "round-trip: KEK packet refused for db (fail-closed 64)" 64 \
    die_rc fw_var_write "$RT/efivars" db "$GUID_DBASE" "$RT/kek.auth"

# =============================================================================
# fw_auth_enroll — SetupMode gate + strict db → KEK → PK (last) order,
# abort-on-failure.
# =============================================================================
E2=$T/enroll-gated
mkdir -p "$E2"
mkvar "$E2" SetupMode "$GUID_GLOBAL" 0
mkdir -p "$T/keys"
mkauth "$T/keys/db.auth" db "$GUID_DBASE" 'DB1'
mkauth "$T/keys/kek.auth" KEK "$GUID_GLOBAL" 'KEK1'
mkauth "$T/keys/pk.auth" PK "$GUID_GLOBAL" 'PK1'
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
mkauth "$T/keys-partial/db.auth" db "$GUID_DBASE" 'DB1'
mkauth "$T/keys-partial/pk.auth" PK "$GUID_GLOBAL" 'PK1'
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
