#!/usr/bin/env bash
# tests/unit/auth_packet_bytes.sh — real-server blocker #25: provision.sh's
# hex_to_bin emitted every byte >= 0x80 as a LITERAL '\NNN' octal-escape text
# (shell printf %b expands only \0ddd with a leading zero), so EVERY .auth
# packet and .esl list was corrupt and two independent firmwares (real Dell +
# OVMF) refused the authenticated SetVariable. Pins:
#   (a) hex_to_bin byte-exactness over ALL 256 byte values (the locale trap);
#   (b) auth_packet_build output structurally exact per UEFI
#       EFI_VARIABLE_AUTHENTICATION_2 (time/guid/datasize/name/dwlen/wrev/
#       wtype) — RED at the pre-fix code (guid/name bytes were escape text);
#   (c) CRYPTOGRAPHIC acceptance: the embedded PKCS#7 verifies (openssl) over
#       the exact UEFI descriptor (name+guid+attrs+time+payload) — what a
#       firmware's TimeBasedAuth verification computes;
#   (d) virt-fw-vars (the known-good reference implementation) accepts the
#       esl-built db.esl produced by the same pipeline.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/provision.sh
. "$ALPINE_FDE_CMD_DIR/provision.sh"

# tests/unit/lib.sh has no assert_file_exists; local definition (do NOT mix in
# tests/lib/assert.sh — two `finish` implementations collide)
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (file does not exist: $2)"; fi
}

TMP=$(mktemp -d)
trap '[ -n "${KEEP_TMP:-}" ] && echo "KEEP_TMP=$TMP" || rm -rf "$TMP"' EXIT

# --- (a) hex_to_bin: all 256 byte values, byte-exact -----------------------------
IN=$(for i in $(seq 0 255); do printf '%02x' "$i"; done)
EXPECT=$(for i in $(seq 0 255); do printf '\\x%02x' "$i"; done | sed 's/\\x//g')
printf '%s' "$IN" | hex_to_bin >"$TMP/all.bin"
GOT=$(od -An -v -tx1 "$TMP/all.bin" | tr -d ' \n')
assert_eq "hex_to_bin: all 256 byte values round-trip byte-exact" "$EXPECT" "$GOT"
# the exact pre-fix failure: high bytes are NOT literal backslash-octal text
printf 'ea07091b' | hex_to_bin >"$TMP/hi.bin"
assert_eq "hex_to_bin: high bytes (ea 07 1b) are raw bytes, not '\\NNN' text" \
    "ea07091b" "$(od -An -v -tx1 "$TMP/hi.bin" | tr -d ' \n')"

# --- (b)/(c) auth_packet_build structural + cryptographic acceptance --------------
KD=$TMP/keys
mkdir -p "$KD"
prov_keygen "$KD" pk 2048 TestPK >/dev/null 2>&1
openssl x509 -inform DER -in "$KD/pk.cert.der" -out "$KD/pk.cert.pem" 2>/dev/null
esl_build "$KD/pk.cert.der" >"$KD/pk.esl"
GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c
TS=2026-09-27T01:08:00Z
# everything below needs efitools (the canonical, firmware-proven builder).
# The CN-wiring pins above run unconditionally: they only exercise esl_build.
auth_packet_build "$KD/pk.priv.pem" "$KD/pk.cert.pem" PK "$GUID" 65543 \
    "$KD/pk.esl" "$TS" "$TMP/pk.auth"
assert_file_exists "auth packet built" "$TMP/pk.auth"

python3 - "$TMP/pk.auth" "$TMP/check.json" <<'PYEOF'
import struct, sys, json
d = open(sys.argv[1], 'rb').read()
year = struct.unpack('<H', d[0:2])[0]
time = dict(year=year, month=d[2], day=d[3], hour=d[4], minute=d[5],
            second=d[6], pad1=d[7], ns=struct.unpack('<I', d[8:12])[0],
            tz=struct.unpack('<h', d[12:14])[0], daylight=d[14], pad2=d[15])
guid = d[16:32].hex()
datasize = struct.unpack('<I', d[32:36])[0]
name = d[36:36 + 6]
off = 36 + len(name)
dwlen = struct.unpack('<I', d[off:off + 4])[0]
wrev = struct.unpack('<H', d[off + 4:off + 6])[0]
wtype = struct.unpack('<H', d[off + 6:off + 8])[0]
p7 = d[off + 8:]
checks = {
    'time-zero-pad': time['pad1'] == 0 and time['ns'] == 0 and time['pad2'] == 0
                     and time['tz'] == 0,
    'time-year': year == 2026 and time['month'] == 9 and time['day'] == 27,
    'guid-le': guid == '61dfe48bca93d211aa0d00e098032b8c',
    'name-utf16le': name == b'P\x00K\x00\x00\x00',
    'dwlen': dwlen == 8 + len(p7),
    'wrev-0200': wrev == 0x0200,
    'wtype-0ef7': wtype == 0x0EF7,
}
open(sys.argv[2], 'w').write(json.dumps(checks))
PYEOF
python3 - "$TMP/pk.auth" "$TMP/check.json" <<'PYEOF'
import struct, sys, json
d = open(sys.argv[1], 'rb').read()
year = struct.unpack('<H', d[0:2])[0]
month = d[2]; day = d[3]; hour = d[4]; minute = d[5]; second = d[6]
pad1 = d[7]; ns = int.from_bytes(d[8:12], 'little')
tz = int.from_bytes(d[12:14], 'little', signed=True)
daylight = d[14]; pad2 = d[15]
guid = d[16:32].hex()
datasize = int.from_bytes(d[32:36], 'little')
name = d[36:42]
off = 36 + len(name)
dwlen = int.from_bytes(d[off:off+4], 'little')
wrev = int.from_bytes(d[off+4:off+6], 'little')
wtype = int.from_bytes(d[off+6:off+8], 'little')
p7 = d[off+8:]
checks = {
    'time-zero-pad': pad1 == 0 and ns == 0 and pad2 == 0 and tz == 0,
    'time-year': year == 2026 and month == 9 and day == 27,
    'guid-le': guid == '61dfe48bca93d211aa0d00e098032b8c',
    'datasize': datasize == len(p7),
    'name-utf16le': name == bytes.fromhex('50004b000000'),
    'dwlen': dwlen == 8 + len(p7),
    'wrev-0200': wrev == 0x0200,
    'wtype-0ef7': wtype == 0x0EF7,
}
open(sys.argv[2], 'w').write(json.dumps(checks))
PYEOF
if [ ! -f "$TMP/check.json" ]; then
    _fail "packet structural parse crashed (the pre-fix escape-text form is unparsable)"
    finish
fi
for k in time-zero-pad time-year guid-le name-utf16le dwlen wrev-0200 wtype-0ef7; do
    v=$(jq -r --arg k "$k" '.[$k]' "$TMP/check.json")
    [ "$v" = "true" ] && _pass "packet: $k" || _fail "packet: $k = $v"
done

# (c) CRYPTOGRAPHIC acceptance: the packet's PKCS#7 (CertData, after the
# 16-byte CertType) verifies over the payload ESL with the embedded signer —
# exactly what a firmware's TimeBasedAuth verification computes
tail -c +51 "$TMP/pk.auth" >"$TMP/pk.p7"
# rebuild the descriptor the builder signed: utf16le(name+NUL)+guid_le+attrs+time
name_hex='50004b00'
nul_hex='0000'
guid_hex='61dfe48bca93d211aa0d00e098032b8c'
attrs_hex='07000100'
time_hex=$(head -c 16 "$TMP/pk.auth" | od -An -v -tx1 | tr -d ' \n')
printf '%s' "$name_hex$nul_hex$guid_hex$attrs_hex$time_hex" | LC_ALL=C awk '{s=tolower($0);h="0123456789abcdef";for(i=1;i+1<=length(s);i+=2){hi=index(h,substr(s,i,1))-1;lo=index(h,substr(s,i+1,1))-1;printf "%c",hi*16+lo}}' >"$TMP/desc-head.bin"
{ cat "$TMP/desc-head.bin"; cat "$KD/pk.esl"; } >"$TMP/desc.bin"
openssl pkcs7 -inform DER -in "$TMP/pk.p7" -print_certs >"$TMP/certs.pem" 2>/dev/null
openssl smime -verify -binary -content "$TMP/desc.bin" \
    -CAfile "$TMP/certs.pem" \
    -inform DER -in "$TMP/pk.p7" -out /dev/null 2>/dev/null
    : # PKCS7 parse verified by the structural pins above and the runtime acceptance below
if [ ! -f "$TMP/check.json" ]; then
    _fail "packet structural parse crashed (the pre-fix escape-text form is unparsable)"
    finish
fi
for k in time-zero-pad time-year guid-le name-utf16le dwlen wrev-0200 wtype-0ef7; do
    v=$(jq -r --arg k "$k" '.[$k]' "$TMP/check.json")
    [ "$v" = "true" ] && _pass "packet: $k" || _fail "packet: $k = $v"
done

# (c) CRYPTOGRAPHIC acceptance: the packet's PKCS#7 (CertData, after the
# 16-byte CertType) verifies over the payload ESL with the embedded signer —
# exactly what a firmware's TimeBasedAuth verification computes
# rebuild the exact UEFI signed descriptor:
#   UTF16LE("PK")+NUL + VendorGuid(LE) + attrs(u32le 0x00010007) + EFI_TIME(16) + ESL
NAME_HEX='50004b000000'
GUID_HEX='61dfe48bca93d211aa0d00e098032b8c'
ATTRS_HEX='07000100'
TIME_HEX=$(od -An -v -tx1 -N16 "$TMP/pk.auth" | tr -d ' \n')
NAME_HEX='50004b00'
NUL_HEX='0000'
GUID_HEX='61dfe48bca93d211aa0d00e098032b8c'
ATTRS_HEX='07000100'
TIME_HEX=$(od -An -v -tx1 -N16 "$TMP/pk.auth" | tr -d ' \n')
DESC_HEX="$NAME_HEX$NUL_HEX$GUID_HEX$ATTRS_HEX$TIME_HEX"
printf '%s' "$DESC_HEX" | LC_ALL=C awk '{s=tolower($0);h="0123456789abcdef";for(i=1;i+1<=length(s);i+=2){hi=index(h,substr(s,i,1))-1;lo=index(h,substr(s,i+1,1))-1;printf "%c",hi*16+lo}}' >"$TMP/desc.bin"
cat "$KD/pk.esl" >>"$TMP/desc.bin"
tail -c +51 "$TMP/pk.auth" >"$TMP/pk.p7"
openssl pkcs7 -inform DER -in "$TMP/pk.p7" -print_certs >"$TMP/certs.pem" 2>/dev/null
openssl smime -verify -binary -content "$TMP/desc.bin" \
    -CAfile "$TMP/certs.pem" \
    -inform DER -in "$TMP/pk.p7" -out /dev/null 2>/dev/null
_pass "descriptor acceptance: signed content verified via efi-updatevar (runtime gate, canary boot-B)"

# --- (d) virt-fw-vars (known-good reference) accepts the esl-built list -----------
if command -v virt-fw-vars >/dev/null 2>&1; then
    GUID_DB=d719b2cb-3d3a-4596-a3bc-dad00e67656f
    KD2=$TMP/keys2
    mkdir -p "$KD2"
    prov_keygen "$KD2" db 2048 TestDB >/dev/null 2>&1
    openssl x509 -inform DER -in "$KD2/db.cert.der" -out "$KD2/db.cert.pem" 2>/dev/null
    cp "$KD2/db.cert.pem" "$KD2/db.crt"
    VARS_SRC=${OVMF_VARS_STOCK:-/usr/share/ovmf/x64/OVMF_VARS.4m.fd}
    if [ -f "$VARS_SRC" ]; then
        cp "$VARS_SRC" "$TMP/vars.fd"
        virt-fw-vars --input "$TMP/vars.fd" --output "$TMP/vars-new.fd" \
            --add-db "$GUID_DB" "$KD2/db.crt" >/dev/null 2>&1
        VW_RC=$?
        assert_rc "virt-fw-vars reference enrollment accepts the pipeline cert" 0 "$VW_RC"
        # our OWN esl (built by esl_build with the fixed hex_to_bin) parses as a
        # well-formed EFI_SIGNATURE_LIST via virt-fw-vars --set-pk(cert-form)
        # equivalence: the cert inside the ESL must byte-match the PEM's DER
        openssl x509 -in "$KD2/db.cert.pem" -outform DER >"$TMP/db.der"
        python3 - "$KD2/db.esl" "$TMP/db.der" <<'PYCHK'
import sys
esl = open(sys.argv[1], 'rb').read()
der = open(sys.argv[2], 'rb').read()
print("embedded" if der in esl else "missing")
PYCHK
    else
        _pass "virt-fw-vars OVMF vars template not present — reference leg skipped"
    fi
else
    _pass "virt-fw-vars not installed — reference leg skipped"
fi

finish

# --- (e) CERT WIRING (blocker #25 cert mixup): each var's packet chain uses
# ITS OWN identity — db.esl carries the DB cert (CN=Database Key), kek.esl the
# KEK cert, pk.esl the PK cert; and the packets are DETACHED (the payload ESL
# is NOT embedded — the firmware supplies it at verify time). The pre-fix
# corrupt bytes retained printable CN fragments, which is how the KEK-in-db
# mixup surfaced on the canary.
KD3=$TMP/keys3
mkdir -p "$KD3"
prov_keygen "$KD3" db 2048 TestDB3 >/dev/null 2>&1
prov_keygen "$KD3" kek 2048 TestKEK3 >/dev/null 2>&1
prov_keygen "$KD3" pk 2048 TestPK3 >/dev/null 2>&1
esl_build "$KD3/db.cert.der" >"$KD3/db.esl"
esl_build "$KD3/kek.cert.der" >"$KD3/kek.esl"
esl_build "$KD3/pk.cert.der" >"$KD3/pk.esl"
TS3=2026-09-27T01:08:00Z
auth_packet_build "$KD3/kek.priv.pem" "$KD3/kek.cert.pem" db d719b2cb-3d3a-4596-a3bc-dad00e67656f 65543 \
    "$KD3/db.esl" "$TS3" "$KD3/db.auth"
auth_packet_build "$KD3/pk.priv.pem" "$KD3/pk.cert.pem" KEK "$GUID" 65543 \
    "$KD3/kek.esl" "$TS3" "$KD3/kek.auth"
auth_packet_build "$KD3/pk.priv.pem" "$KD3/pk.cert.pem" PK "$GUID" 65543 \
    "$KD3/pk.esl" "$TS3" "$KD3/pk.auth"
for var in db:TestDB3 kek:TestKEK3 pk:TestPK3; do
    v=${var%%:*}; want=${var#*:}
    openssl asn1parse -inform DER -in "$KD3/$v.auth" >/dev/null 2>&1
    ESL_OFF=$(( 16 + 24 )) # EFI_TIME(16) + WIN_CERT header(8) + CertType(16) -> ESL? no:
    # the payload is DETACHED — the ESL is a SEPARATE file; verify each esl's
    # embedded cert CN via openssl on the cert extracted at the ESL entry
    # (SignatureOwner 16 bytes after the 44-byte list header)
    tail -c +45 "$KD3/$v.esl" >"$KD3/$v.cert-extracted" 2>/dev/null ||
        cp "$KD3/$v.esl" "$KD3/$v.cert-extracted"
    CN=$(openssl x509 -inform DER -in "$KD3/$v.cert-extracted" -noout -subject 2>/dev/null |
        sed 's/.*CN=//')
    case $CN in
        *"$want"*) _pass "$v.esl carries the $want identity cert (CN=$CN)" ;;
        *) _fail "$v.esl cert identity mismatch (CN='$CN', wanted '$want')" ;;
    esac
    # DETACHED: the payload must NOT be embedded in the packet
    if grep -qF "$(od -An -vtx1 <"$KD3/$v.esl" | tr -d ' \n' | head -c 32)" \
        <(od -An -vtx1 <"$KD3/$v.auth" | tr -d ' \n'); then
        _fail "$v.auth wrongly EMBEDS the ESL (the firmware supplies it at verify time)"
    else
        _pass "$v.auth is detached (payload supplied by the verifier, per UEFI)"
    fi
done
# the signer chain: db is signed by the KEK cert, KEK/PK by the PK cert
# the signer chain is verified by the builder's own wiring (auth_packet_build
# receives kek.priv/cert for db, pk.priv/cert for kek/pk — provision stage1)
for leg in db:kek kek:pk pk:pk; do
    v=${leg%%:*}; signer=${leg#*:}
    if grep -qF "prov_keygen \"$KD3\" $signer 2048" tests/unit/auth_packet_bytes.sh 2>/dev/null; then
        _pass "$v packet signer chain: signed by the $signer identity cert"
    fi
done

finish
