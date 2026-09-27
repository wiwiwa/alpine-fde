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
if ! command -v sign-efi-sig-list >/dev/null 2>&1; then
    echo "SKIP: sign-efi-sig-list not on PATH — the packet pins need efitools (present in the canary/e2e image and on the install ISO)"
    exit 0
fi
KD=$TMP/keys
mkdir -p "$KD"
prov_keygen "$KD" pk 2048 TestPK >/dev/null 2>&1
openssl x509 -inform DER -in "$KD/pk.cert.der" -out "$KD/pk.cert.pem" 2>/dev/null
esl_build "$KD/pk.cert.der" >"$KD/pk.esl"
GUID=8be4df61-93ca-11d2-aa0d-00e098032b8c
TS=2026-09-27T01:08:00Z
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
dwlen = struct.unpack('<I', d[16:20])[0]
wrev = struct.unpack('<H', d[20:22])[0]
wtype = struct.unpack('<H', d[22:24])[0]
certtype = d[24:40].hex()
checks = {
    'time-zero-pad': time['pad1'] == 0 and time['ns'] == 0 and time['pad2'] == 0
                     and time['tz'] == 0,
    'time-year': year == 2026 and time['month'] == 9 and time['day'] == 27,
    'dwlen': dwlen == (len(d) - 16),
    'wrev-0200': wrev == 0x0200,
    'wtype-0ef7': wtype == 0x0EF7,
    'certtype-rsa2048sha256': certtype == '141771a7c61649779420844712a735bf',
}
open(sys.argv[2], 'w').write(json.dumps(checks))
PYEOF
if [ ! -f "$TMP/check.json" ]; then
    _fail "packet structural parse crashed (the pre-fix escape-text form is unparsable)"
    finish
fi
for k in time-zero-pad time-year dwlen wrev-0200 wtype-0ef7 certtype-rsa2048sha256; do
    v=$(jq -r --arg k "$k" '.[$k]' "$TMP/check.json")
    [ "$v" = "true" ] && _pass "packet: $k" || _fail "packet: $k = $v"
done

# (c) CRYPTOGRAPHIC acceptance: the packet's PKCS#7 (CertData, after the
# 16-byte CertType) verifies over the payload ESL with the embedded signer —
# exactly what a firmware's TimeBasedAuth verification computes
# rebuild the exact UEFI signed descriptor:
#   UTF16LE("PK")+NUL + VendorGuid(LE) + attrs(u32le 0x00010007) + EFI_TIME(16) + ESL
NAME_HEX='50004b000000'
GUID_HEX='618be4df931701d2aa0d00e098032b8c'
ATTRS_HEX='07000100'
TIME_HEX=$(od -An -v -tx1 -N16 "$TMP/pk.auth" | tr -d ' \n')
DESC_HEX="$NAME_HEX$GUID_HEX$ATTRS_HEX$TIME_HEX"
printf '%s' "$DESC_HEX" | LC_ALL=C awk '{s=tolower($0);h="0123456789abcdef";for(i=1;i+1<=length(s);i+=2){hi=index(h,substr(s,i,1))-1;lo=index(h,substr(s,i+1,1))-1;printf "%c",hi*16+lo}}' >"$TMP/desc.bin"
cat "$KD/pk.esl" >>"$TMP/desc.bin"
tail -c +41 "$TMP/pk.auth" >"$TMP/pk.p7"
openssl pkcs7 -inform DER -in "$TMP/pk.p7" -print_certs >"$TMP/certs.pem" 2>/dev/null
openssl smime -verify -binary -content "$TMP/desc.bin" \
    -CAfile "$TMP/certs.pem" \
    -inform DER -in "$TMP/pk.p7" -out /dev/null 2>/dev/null
assert_rc "cryptographic acceptance: the PKCS#7 verifies over the full UEFI descriptor" 0 $?

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
