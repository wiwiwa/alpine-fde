#!/usr/bin/env bash
# tests/unit/provision_stage1_keys.sh — provision ceremony primitives:
#   * EFI_SIGNATURE_LIST builder vs hand-computed golden vectors (spec layout:
#     type(16) listsize u32le headersize u32le sigsize u32le [owner GUID(16)+cert])
#   * EFI_TIME / GUID mixed-endian / UTF-16LE encodings vs golden hex
#   * authenticated variable packets: WIN_CERTIFICATE_EFI_PKCS structure +
#     openssl PKCS#7 verification
#   * `debian-fde provision stage1` end-to-end: key material, ESLs, packets,
#     pending baseline; refuse-overwrite + --force behavior
#   * `provision stage2` finalizes the baseline (needs a TPM: swtpm fixture)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/provision.sh
source "$REPO/lib/cmd/provision.sh"

T=$(mktemp -d /tmp/debian-fde-provision.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
export DEBIAN_FDE_ROOT="$T/root"    # baseline lands at $T/root/etc/debian-fde

# --- golden: EFI_CERT_X509_GUID mixed-endian + ESL layout ---------------------
# synthetic 8-byte "cert" 11 12 .. 18, zero owner GUID
printf '\021\022\023\024\025\026\027\030' >"$T/mini.der"
esl_build "$T/mini.der" >"$T/mini.esl"
GOLDEN_ESL='c3c0cfa53e88f24fa63a95c5e9d3a5c3'    # EFI_CERT_X509_GUID, byte order
GOLDEN_ESL+='34000000'                           # SignatureListSize = 28+24 = 52
GOLDEN_ESL+='00000000'                           # SignatureHeaderSize = 0
GOLDEN_ESL+='18000000'                           # SignatureSize = 16+8 = 24
GOLDEN_ESL+='00000000000000000000000000000000'   # owner GUID (zero)
GOLDEN_ESL+='1112131415161718'                   # cert bytes
assert_eq "ESL golden vector (layout+GUID endianness)" "$GOLDEN_ESL" "$(bin_to_hex <"$T/mini.esl")"

# owner GUID variant: db namespace GUID bytes appear after the 28-byte header
esl_build "$T/mini.der" 'd719b2cb-3d3a-4596-a3bc-dad00e67656f' >"$T/mini-owner.esl"
assert_eq "ESL owner GUID encoded mixed-endian" \
    "cbb219d73a3d9645a3bcdad00e67656f" \
    "$(bin_to_hex <"$T/mini-owner.esl" | cut -c 57-88)"

# --- golden: encodings ----------------------------------------------------------
assert_eq "guid_le_hex global var GUID" \
    "61dfe48bca93d211aa0d00e098032b8c" \
    "$(guid_le_hex '8be4df61-93ca-11d2-aa0d-00e098032b8c')"
assert_eq "le32_hex 0x7" "07000000" "$(le32_hex 7)"
assert_eq "le16_hex 0x0200" "0002" "$(le16_hex 512)"
assert_eq "efi_time golden (2026-09-14T01:02:03Z)" \
    "ea07090e010203000000000000000000" \
    "$(efi_time_hex '2026-09-14T01:02:03Z')"
assert_eq "ascii_utf16le_hex 'db'" "64006200" "$(ascii_utf16le_hex 'db')"
# roundtrip binary → hex → binary
printf '\001\002\000\377hex' >"$T/rnd.bin"
bin_to_hex <"$T/rnd.bin" | hex_to_bin >"$T/rnd2.bin"
assert_eq "hex_to_bin/bin_to_hex roundtrip (incl NUL)" \
    "$(od -An -tx1 <"$T/rnd.bin" | tr -d ' \n')" \
    "$(od -An -tx1 <"$T/rnd2.bin" | tr -d ' \n')"

# --- auth packet: structure + PKCS7 verification --------------------------------
TS='2026-09-14T01:02:03Z'
# throwaway 2048-bit signer (openssl, fast enough for tests)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/signer.key" 2>/dev/null
openssl req -new -x509 -key "$T/signer.key" -out "$T/signer.pem" -days 30 -sha256 -subj "/O=Debian FDE/CN=Test Signer" 2>/dev/null
printf '\021\042\063\104' >"$T/payload.bin"    # 11 22 33 44
auth_packet_build "$T/signer.key" "$T/signer.pem" db 'd719b2cb-3d3a-4596-a3bc-dad00e67656f' 7 \
    "$T/payload.bin" "$TS" "$T/db.auth"

# descriptor golden (what gets signed): name+guid+attrs+time+payload
GOLDEN_DESC='64006200'
GOLDEN_DESC+='cbb219d73a3d9645a3bcdad00e67656f'
GOLDEN_DESC+='07000000'
GOLDEN_DESC+='ea07090e010203000000000000000000'
GOLDEN_DESC+='11223344'
# packet = EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME(16) + EFI_VARIABLE_DATA
# {GUID(16) + DataSize(4) + UTF-16 name incl NUL (6 for 'db')} + WIN_CERT(8) + p7
assert_eq "packet size = full EFI_VARIABLE_AUTHENTICATION_2 envelope" "1" \
    "$(( $(wc -c <"$T/db.auth") >= 16 + 16 + 4 + 6 + 8 + 50 ? 1 : 0 ))"
assert_eq "EFI_TIME prefix" "ea07090e010203000000000000000000" \
    "$(bin_to_hex <"$T/db.auth" | cut -c 1-32)"
assert_eq "EFI_VARIABLE_DATA GUID at bytes 17-32 (LE)" \
    "cbb219d73a3d9645a3bcdad00e67656f" \
    "$(bin_to_hex <"$T/db.auth" | cut -c 33-64)"
assert_eq "UnicodeName 'db'+NUL at byte 37" "640062000000" \
    "$(bin_to_hex <"$T/db.auth" | cut -c 73-84)"
assert_eq "wRevision 0x0200 + wCertificateType 0x0EF7 (LE, after envelope)" "0002f70e" \
    "$(bin_to_hex <"$T/db.auth" | cut -c 93-100)"
DWLEN=$((16#$(bin_to_hex <"$T/db.auth" | cut -c 85-92 | awk '{print substr($0,7,2) substr($0,5,2) substr($0,3,2) substr($0,1,2)}')))
PKCS7_LEN=$(( $(wc -c <"$T/db.auth") - 24 - 26 ))
assert_eq "dwLength = 8 + CertData" "$((8 + PKCS7_LEN))" "$DWLEN"
# DataSize covers the name + WIN_CERT body; packet = 36 + DataSize exactly
DS=$((16#$(bin_to_hex <"$T/db.auth" | cut -c 65-72 | awk '{print substr($0,7,2) substr($0,5,2) substr($0,3,2) substr($0,1,2)}')))
assert_eq "DataSize = name(6) + 8 + CertData" "$((6 + 8 + PKCS7_LEN))" "$DS"
# extract CertData (PKCS#7 is DETACHED) and verify it over the reconstructed
# descriptor — the same data a firmware/KeyTool verifier would use
tail -c +51 "$T/db.auth" >"$T/db.p7"
printf '%s' "$GOLDEN_DESC" | hex_to_bin >"$T/desc.bin"
openssl smime -verify -inform DER -in "$T/db.p7" -content "$T/desc.bin" \
    -CAfile "$T/signer.pem" -out /dev/null 2>"$T/verify.err"
assert_eq "PKCS7 signature verifies over the descriptor (detached)" "0" "$?"
# negative control: a flipped payload byte must fail verification
printf '%s' "${GOLDEN_DESC%44}45" | hex_to_bin >"$T/desc-bad.bin"
openssl smime -verify -inform DER -in "$T/db.p7" -content "$T/desc-bad.bin" \
    -CAfile "$T/signer.pem" -out /dev/null 2>/dev/null
assert_ne "PKCS7 rejects a tampered descriptor (nonzero rc)" "0" "$?"

# --- real stage1 end-to-end -------------------------------------------------------
assert_rc "no TPM before fixture: stage1 still works (warns, pcrs pending)" 0 env -u DEBIAN_FDE_TCTI "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys"
for f in release.pem release.pub release.crt pk.priv.pem pk.cert.pem kek.priv.pem kek.cert.pem db.priv.pem db.cert.pem; do
    assert_file_exists "stage1 produced $f" "$T/keys/$f"
done
for f in db.esl kek.esl pk.esl db.auth kek.auth pk.auth; do
    assert_file_exists "stage1 produced $f" "$T/keys/$f"
done
for f in release.cert.der pk.cert.der kek.cert.der db.cert.der; do
    assert_file_exists "stage1 produced $f (DER for ESL)" "$T/keys/$f"
done
for f in db.esl kek.esl pk.esl; do
    assert_rc "esl_verify ok: $f" 0 esl_verify "$T/keys/$f"
done
assert_eq "db.esl starts with X509 sig-type GUID" "c3c0cfa5" "$(bin_to_hex <"$T/keys/db.esl" | cut -c 1-8)"
# key permissions: private keys not world-readable
PERM=$(stat -c %a "$T/keys/release.pem")
assert_eq "release.pem mode 600" "600" "$PERM"
# corrupted listsize detected
cp "$T/keys/db.esl" "$T/db.esl.corrupt"
python3 - "$T/db.esl.corrupt" <<'EOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
b[16] ^= 0xFF   # flip a byte of SignatureListSize
open(p, 'wb').write(bytes(b))
EOF
assert_rc "esl_verify rejects corrupted size field" 1 esl_verify "$T/db.esl.corrupt"
# pending baseline written under $DEBIAN_FDE_ROOT
BL=$(sp_baseline_file)
assert_file_exists "stage1 wrote baseline" "$BL"
assert_rc "stage1 baseline validates" 0 baseline_validate "$BL"
assert_eq "baseline expected_pcr7 pending" "pending" "$(baseline_get "$BL" expected_pcr7)"
assert_eq "baseline keys.release_pub_path" "$T/keys/release.pub" "$(baseline_get_in "$BL" keys release_pub_path)"
# refuse overwrite without --force
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 refuses existing keydir (rc 64)" "64" "$RC"
assert_rc "stage1 --force overwrites" 0 "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" --force

# --- G-B1: vendor-cert revocation (§6 PCR 7 — "expected value is fully ours") -----
# dbx entries of type EFI_CERT_X509_SHA256 revoke vendor certs by the SHA256 of
# their To-Be-Signed section, so firmware policy rejects them even when present
# in db; our db.esl (only our cert) replaces db wholesale via auth-var semantics.

# unit: pure X509_SHA256 ESL builder vs golden vector
FIXED_HASH='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
esl_sha256_revocation_build '' "$FIXED_HASH" >"$T/unit-dbx.esl"
GOLDEN_DBX='92a4d23bc0967940b420fcf98ef103ed'    # EFI_CERT_X509_SHA256 GUID, mixed-endian
GOLDEN_DBX+='5c000000'                            # SignatureListSize = 28 + 64 = 92
GOLDEN_DBX+='00000000'                            # SignatureHeaderSize = 0
GOLDEN_DBX+='40000000'                            # SignatureSize = 16 owner + 48 data
GOLDEN_DBX+='00000000000000000000000000000000'    # owner GUID (zero)
GOLDEN_DBX+=$FIXED_HASH                           # sha256(cert TBS)
GOLDEN_DBX+='00000000000000000000000000000000'    # TimeOfRevocation zero = revoked always
assert_eq "dbx ESL golden vector (X509_SHA256 layout)" "$GOLDEN_DBX" "$(bin_to_hex <"$T/unit-dbx.esl")"
esl_sha256_revocation_build 'd719b2cb-3d3a-4596-a3bc-dad00e67656f' "$FIXED_HASH" >"$T/unit-dbx-owner.esl"
assert_eq "dbx ESL owner GUID encoded mixed-endian" \
    "cbb219d73a3d9645a3bcdad00e67656f" \
    "$(bin_to_hex <"$T/unit-dbx-owner.esl" | cut -c 57-88)"
assert_rc "dbx ESL passes esl_verify" 0 esl_verify "$T/unit-dbx.esl"

# multi-entry (N=2) dbx list: SignatureListSize arithmetic must scale with the
# entry count (28 + N*64), both hashes must appear in input order, and an
# UPPERCASE hash must be normalized to lowercase (§6 revocation lists hold
# many entries in one list)
DBX_H1='1111111111111111111111111111111111111111111111111111111111111111'
DBX_H2=$(printf 'AB%.0s' {1..32})   # 64 hex chars, uppercase on purpose
esl_sha256_revocation_build '' "$DBX_H1" "$DBX_H2" >"$T/unit-dbx2.esl"
GOLDEN_DBX2='92a4d23bc0967940b420fcf98ef103ed'    # EFI_CERT_X509_SHA256 GUID
GOLDEN_DBX2+='9c000000'                            # SignatureListSize = 28 + 2*64 = 156
GOLDEN_DBX2+='00000000'                            # SignatureHeaderSize = 0
GOLDEN_DBX2+='40000000'                            # SignatureSize = 64 (unchanged per entry)
GOLDEN_DBX2+="00000000000000000000000000000000$DBX_H1$(printf '0%.0s' {1..32})"
GOLDEN_DBX2+="00000000000000000000000000000000$(printf '%s' "$DBX_H2" | tr 'A-F' 'a-f')$(printf '0%.0s' {1..32})"
assert_eq "dbx ESL N=2 golden (size arithmetic + input order + lowercase)" \
    "$GOLDEN_DBX2" "$(bin_to_hex <"$T/unit-dbx2.esl")"
assert_eq "dbx ESL N=2 total bytes = 28 + 2*64" "156" "$(wc -c <"$T/unit-dbx2.esl" | tr -d '[:space:]')"
assert_rc "dbx ESL N=2 passes esl_verify" 0 esl_verify "$T/unit-dbx2.esl"

# unit: TBS extraction vs independent asn1parse offset arithmetic
openssl req -new -x509 -newkey rsa:2048 -nodes -keyout "$T/vendor.key" \
    -out "$T/vendor.crt.pem" -days 30 -sha256 -subj "/O=Vendor/CN=Vendor Test CA" 2>/dev/null
openssl x509 -in "$T/vendor.crt.pem" -outform DER -out "$T/vendor.crt.der"
TBS=$(prov_cert_tbs_sha256 "$T/vendor.crt.der")
ASN=$(openssl asn1parse -inform DER -in "$T/vendor.crt.der")
OFF=$(printf '%s\n' "$ASN" | sed -n 's/^[[:space:]]*\([0-9]*\):d=1.*/\1/p' | head -1)
HL=$(printf '%s\n' "$ASN" | sed -n 's/^[[:space:]]*[0-9]*:d=1[[:space:]]*hl=\([0-9]*\).*/\1/p' | head -1)
LN=$(printf '%s\n' "$ASN" | sed -n 's/^[[:space:]]*[0-9]*:d=1[[:space:]]*hl=[0-9]*[[:space:]]*l=[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
INDEP=$(tail -c +"$((OFF + 1))" "$T/vendor.crt.der" | head -c "$((HL + LN))" | sha256sum | cut -d' ' -f1)
assert_eq "TBS sha256 matches independent asn1parse extraction" "$INDEP" "$TBS"
assert_ne "TBS hash differs from the whole-cert hash" "$TBS" "$(sha256sum <"$T/vendor.crt.der" | cut -d' ' -f1)"
assert_eq "TBS hash is 64 hex chars" "64" "${#TBS}"

# stage1 e2e with --revoke-cert: dbx.esl + dbx.auth, KEK-authenticated
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" --force --revoke-cert "$T/vendor.crt.pem" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 --revoke-cert rc 0" "0" "$RC"
assert_file_exists "stage1 produced dbx.esl" "$T/keys/dbx.esl"
assert_file_exists "stage1 produced dbx.auth" "$T/keys/dbx.auth"
assert_rc "dbx.esl passes esl_verify" 0 esl_verify "$T/keys/dbx.esl"
EXPECTED_DBX='92a4d23bc0967940b420fcf98ef103ed'    # EFI_CERT_X509_SHA256 GUID
EXPECTED_DBX+='5c000000'                           # SignatureListSize = 92
EXPECTED_DBX+='00000000'                           # SignatureHeaderSize = 0
EXPECTED_DBX+='40000000'                           # SignatureSize = 64
EXPECTED_DBX+='00000000000000000000000000000000'   # owner GUID (zero)
EXPECTED_DBX+=$TBS                                 # sha256(vendor cert TBS)
EXPECTED_DBX+='00000000000000000000000000000000'   # TimeOfRevocation zero
assert_eq "dbx.esl golden (vendor cert TBS, zero revocation time)" "$EXPECTED_DBX" "$(bin_to_hex <"$T/keys/dbx.esl")"
# the auth packet is a KEK-signed EFI_VARIABLE_AUTHENTICATION_2 over dbx
# (envelope: TIME(32) + GUID(32) + DataSize(8) + 'dbx'+NUL(16) hex chars)
assert_eq "dbx.auth wRevision 0x0200 + wCertificateType 0x0EF7 (LE)" "0002f70e" \
    "$(bin_to_hex <"$T/keys/dbx.auth" | cut -c 97-104)"
assert_eq "dbx.auth EFI_VARIABLE_DATA GUID at bytes 17-32 (LE)" \
    "cbb219d73a3d9645a3bcdad00e67656f" \
    "$(bin_to_hex <"$T/keys/dbx.auth" | cut -c 33-64)"
tail -c +53 "$T/keys/dbx.auth" >"$T/dbx.p7"
# descriptor = name + guid + attrs + EFI_TIME (read from the packet header, as
# a firmware/KeyTool verifier does) + payload
TS_HEX=$(bin_to_hex <"$T/keys/dbx.auth" | cut -c 1-32)
DESC_HEX=$(ascii_utf16le_hex 'dbx')$(guid_le_hex 'd719b2cb-3d3a-4596-a3bc-dad00e67656f')$(le32_hex 7)$TS_HEX$(bin_to_hex <"$T/keys/dbx.esl")
printf '%s' "$DESC_HEX" | hex_to_bin >"$T/dbx-desc.bin"
openssl smime -verify -inform DER -in "$T/dbx.p7" -content "$T/dbx-desc.bin" \
    -CAfile "$T/keys/kek.cert.pem" -out /dev/null 2>"$T/dbx-verify.err"
assert_eq "dbx.auth PKCS7 verifies under the KEK cert (detached)" "0" "$?"
# fail-closed on a missing revocation input
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" --force --revoke-cert "$T/nope.pem" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 --revoke-cert missing file -> 64" "64" "$RC"

# --- M-03: `--force` WITHOUT `--revoke-cert` must not leave stale dbx artifacts ---
# --force wipes the KEK private key; a dbx.esl/dbx.auth left over from a
# previous --revoke-cert run would be signed by that JUST-DELETED key —
# enrolling it would resurrect stale revocation state. The stale packets must
# be removed loudly (rebuild needs an explicit --revoke-cert re-run).
M3_OUT=$("$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" --force 2>&1)
M3_RC=$?
assert_eq "M-03: --force without --revoke-cert rc 0" "0" "$M3_RC"
assert_contains "M-03: loud warn names the stale dbx artifacts" "$M3_OUT" "STALE dbx"
assert_eq "M-03: stale dbx.esl removed (was signed by the deleted KEK)" "0" \
    "$([ -e "$T/keys/dbx.esl" ] && echo 1 || echo 0)"
assert_eq "M-03: stale dbx.auth removed" "0" \
    "$([ -e "$T/keys/dbx.auth" ] && echo 1 || echo 0)"

# --- L-01: dbx hash validation must cover ALL 64 hex chars -------------------------
L1_BAD="a$(printf 'z%.0s' $(seq 1 63))"   # 64 chars, first hex, tail junk
L1_RC=$( ( esl_sha256_revocation_build '' "$L1_BAD" ) >/dev/null 2>&1; echo $? )
assert_eq "L-01: 64-char hash with non-hex tail rejected (was: accepted)" "64" "$L1_RC"
L1_RC=$( ( esl_sha256_revocation_build '' '' ) >/dev/null 2>&1; echo $? )
assert_eq "L-01: empty hash rejected" "64" "$L1_RC"
L1_SHORT=$(printf 'a%.0s' $(seq 1 63))
L1_RC=$( ( esl_sha256_revocation_build '' "$L1_SHORT" ) >/dev/null 2>&1; echo $? )
assert_eq "L-01: 63 hex chars still rejected (length check intact)" "64" "$L1_RC"

# --- L-02: --revoke-cert paths accumulate safely (paths with spaces survive) --------
cp "$T/vendor.crt.pem" "$T/vendor cert.pem"
L2_OUT=$("$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys" --force \
    --revoke-cert "$T/vendor cert.pem" 2>&1)
L2_RC=$?
assert_eq "L-02: --revoke-cert path with spaces rc 0" "0" "$L2_RC"
assert_eq "L-02: dbx.esl golden for the space-containing path" "$EXPECTED_DBX" \
    "$(bin_to_hex <"$T/keys/dbx.esl")"

# --- L-03: keygen failure is LOUD (openssl stderr not silenced, ADR-8) --------------
mkdir -p "$T/badopenssl"
printf '#!/bin/sh\nprintf "simulated-openssl-failure (L-03: stderr must not be silenced)\\n" >&2\nexit 1\n' \
    >"$T/badopenssl/openssl"
chmod +x "$T/badopenssl/openssl"
L3_OUT=$(PATH="$T/badopenssl:$PATH" "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys-l03" 2>&1)
L3_RC=$?
assert_ne "L-03: broken openssl fails the run" "0" "$L3_RC"
assert_contains "L-03: openssl failure message is visible (was: 2>/dev/null)" "$L3_OUT" "simulated-openssl-failure"

# without --revoke-cert, no dbx artifacts are produced (never invent vendor hashes)
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --keydir "$T/keys-norevoke" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 without --revoke-cert rc 0" "0" "$RC"
assert_eq "no dbx.esl without --revoke-cert" "0" "$([ -e "$T/keys-norevoke/dbx.esl" ] && echo 1 || echo 0)"

# --- ADR-18/G-KC3: provision stage1 --mode in-chroot|offline (default offline) ------
# in-chroot mode: keydir defaults to $DEBIAN_FDE_ROOT/etc/debian-fde/keys; the
# ceremony REQUIRES encryption at the end (keys_encrypt_release, PBES2
# aes-256-cbc/hmacWithSHA256/iter 600000) and SHREDS the pk/kek/db (+release
# duplicate) plaintext private keys after the ESL/auth-packet build — the
# target keeps certs + packets + the encrypted release.pem ONLY. Offline mode
# (the default) is byte-for-byte unchanged: plaintext keys stay on the medium.
IC_PASS='ci-inchroot-passphrase-600000'
enc_rc() { ( keys_is_encrypted "$1" ) >/dev/null 2>&1; echo $?; }

# usage pin: --mode validates its value (usage-class rc 2)
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --mode garbage --keydir "$T/mode-garbage" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 --mode garbage -> usage rc 2" "2" "$RC"

# the in-chroot ceremony end-to-end with the env credential seam (RESOLVED-4)
IC_OUT=$(DEBIAN_FDE_KEY_PASSPHRASE=$IC_PASS "$REPO/bin/debian-fde" provision stage1 --mode in-chroot 2>&1)
IC_RC=$?
assert_eq "stage1 --mode in-chroot rc 0 (default keydir = \$DEBIAN_FDE_ROOT/etc/debian-fde/keys)" "0" "$IC_RC"
ICK="$DEBIAN_FDE_ROOT/etc/debian-fde/keys"
assert_file_exists "in-chroot: release.pem at the default keydir" "$ICK/release.pem"
assert_eq "in-chroot: release.pem is ENCRYPTED (ADR-18)" "0" "$(enc_rc "$ICK/release.pem")"
assert_eq "in-chroot: encrypted release.pem mode 600" "600" "$(stat -c %a "$ICK/release.pem")"
openssl pkcs8 -in "$ICK/release.pem" -passin pass:"$IC_PASS" -out /dev/null 2>/dev/null
assert_eq "in-chroot: release.pem decrypts with the ceremony passphrase (standard PKCS#8)" "0" "$?"
# custody: NO plaintext private key survives anywhere in the keydir
for f in release.priv.pem pk.priv.pem kek.priv.pem db.priv.pem; do
    assert_eq "in-chroot: no plaintext $f on the target" "0" "$([ -e "$ICK/$f" ] && echo 1 || echo 0)"
done
PLAIN_REMNANT=$(find "$ICK" -name '*priv*' -print 2>/dev/null)
assert_eq "in-chroot: readdir finds NO *priv* plaintext anywhere under the keydir" "" "$PLAIN_REMNANT"
# the target keeps certs + packets + public material
for f in release.pub release.crt release.cert.der \
    pk.pub.pem pk.cert.pem pk.cert.der \
    kek.pub.pem kek.cert.pem kek.cert.der \
    db.pub.pem db.cert.pem db.cert.der \
    db.esl kek.esl pk.esl db.auth kek.auth pk.auth; do
    assert_file_exists "in-chroot: kept $f (certs + packets survive)" "$ICK/$f"
done
# stage-end checklist pins (G-KC8): encrypted-confirmed + iter count + scp
# backup reminder; the stale "keep release.pem OFF the target machine" line is GONE
assert_contains "in-chroot: checklist confirms the ENCRYPTED release.pem" "$IC_OUT" "ENCRYPTED"
assert_contains "in-chroot: checklist pins the 600000 iteration count" "$IC_OUT" "600000"
assert_contains "in-chroot: checklist reminds the scp off-machine backup" "$IC_OUT" "scp"
assert_not_contains "in-chroot: stale 'keep release.pem OFF the target machine' line removed" \
    "$IC_OUT" "keep release.pem OFF the target machine"
# the PENDING baseline still lands (§9.1 step 2 semantics)
assert_eq "in-chroot: baseline expected_pcr7 pending" "pending" \
    "$(baseline_get "$(sp_baseline_file)" expected_pcr7)"

# explicit --keydir wins over the default
IC2="$T/inchroot-explicit"
IC2_OUT=$(DEBIAN_FDE_KEY_PASSPHRASE=$IC_PASS "$REPO/bin/debian-fde" provision stage1 --mode in-chroot --keydir "$IC2" 2>&1)
assert_eq "stage1 --mode in-chroot --keydir DIR rc 0" "0" "$?"
assert_eq "in-chroot explicit keydir: release.pem encrypted there" "0" "$(enc_rc "$IC2/release.pem")"

# credential seam: in-chroot without env passphrase and without a tty -> loud 64
IC3="$T/inchroot-nocred"
IC3_RC=$( ( unset DEBIAN_FDE_KEY_PASSPHRASE; "$REPO/bin/debian-fde" provision stage1 --mode in-chroot --keydir "$IC3" ) </dev/null >/dev/null 2>&1; echo $? )
assert_eq "in-chroot without credential -> 64 (loud, ADR-18)" "64" "$IC3_RC"
assert_eq "in-chroot without credential: no ciphertext produced" "1" "$(enc_rc "$IC3/release.pem" 2>/dev/null || echo 1)"
# floor-violating passphrase: rc 2 BEFORE any ciphertext exists
IC4="$T/inchroot-floor"
IC4_RC=$(DEBIAN_FDE_KEY_PASSPHRASE=short "$REPO/bin/debian-fde" provision stage1 --mode in-chroot --keydir "$IC4" >/dev/null 2>&1; echo $?)
assert_eq "in-chroot floor-violating passphrase -> rc 2" "2" "$IC4_RC"
assert_eq "in-chroot floor violation: no ciphertext written" "1" "$(enc_rc "$IC4/release.pem" 2>/dev/null || echo 1)"

# explicit --mode offline (the documented default) is unchanged: plaintext on the medium
OF3="$T/keys-offline-explicit"
RC=$( ( "$REPO/bin/debian-fde" provision stage1 --mode offline --keydir "$OF3" ) >/dev/null 2>&1; echo $? )
assert_eq "stage1 --mode offline rc 0" "0" "$RC"
assert_eq "offline mode: release.pem stays PLAINTEXT on the medium" "1" "$(enc_rc "$OF3/release.pem")"

# --- stage2 finalization on the swtpm fixture --------------------------------------
# baseline_finalize_from_live (§8.1/§9.1 guard) refuses to finalize unless
# Secure Boot is ON with SetupMode=0 — inject a matching efivars fixture
EV=$T/efivars
mkdir -p "$EV"
printf '\007\000\000\000\001' >"$EV/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf '\007\000\000\000\000' >"$EV/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf '\007\000\000\000\001\002\003\004' >"$EV/PK-8be4df61-93ca-11d2-aa0d-00e098032b8c"
export DEBIAN_FDE_EFIVARS_DIR=$EV
STATE=$T/swtpm
assert_rc "swtpm starts" 0 swtpm_start "$STATE"
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
assert_rc "stage2 finalizes pending baseline" 0 "$REPO/bin/debian-fde" provision stage2
assert_rc "baseline now final" 0 baseline_is_final "$BL"
PCR7=$(tpm_pcr_read 7)
assert_eq "expected_pcr7 == live swtpm PCR7 (zero digest)" "$PCR7" "$(baseline_get "$BL" expected_pcr7)"
assert_eq "pcr0 captured" "$(tpm_pcr_read 0)" "$(baseline_get "$BL" pcr0)"
_exp_sb=$(fw_sb_state | sed -n 's/.*secureboot=\([01]\).*/\1/p')
assert_eq "sb_state.secure_boot == live efivarfs value" "$_exp_sb" "$(baseline_get_in "$BL" sb_state secure_boot)"
# stage2 refuses to run twice on a final baseline
RC=$( ( "$REPO/bin/debian-fde" provision stage2 ) >/dev/null 2>&1; echo $? )
assert_eq "stage2 on final baseline dies fail-closed" "64" "$RC"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
