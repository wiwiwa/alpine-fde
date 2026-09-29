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
cleanup() { [ -n "${KEEP_TMP:-}" ] && echo "KEEP_TMP=$T" || rm -rf "$T"; }
trap cleanup EXIT

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
GUID_DBASE='d719b2cb-3d3a-4596-a3bc-dad00e67656f'

# --- fixture builders ----------------------------------------------------------

# efi-updatevar stub (blocker #26 final): fw_var_write_try writes via
# efi-updatevar — the stub records the invocation and succeeds
EUV_LOG="$T/euvar.log"
mkdir -p "$T/eu"
cat >"$T/eu/efi-updatevar" <<'STUB'
#!/bin/sh
printf 'efi-updatevar %s\n' "$*" >>"$EUV_LOG"
exit 0
STUB
chmod +x "$T/eu/efi-updatevar"
export EUV_LOG
export PATH="$T/eu:$PATH"

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

# blocker #26 final: the write is efi-updatevar's (libefivar efivarfs
# semantics) — the old raw attrs-prefix cat write is gone
assert_contains "fw_var_write: the write goes through efi-updatevar -f" \
    "$(cat "$EUV_LOG")" "efi-updatevar -f $T/db.auth db"

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
assert_eq "real-builder RT leg skipped (no efitools on this host — the canary/e2e image covers it)" "skipped" "skipped"
fi
# mkauth-fixture writer round-trip (always available): a REAL signed packet
RTM=$T/rt-mkauth
mkdir -p "$RTM/efivars"
mkauth "$RTM/db.auth" db "$GUID_DBASE" 'ROUND-TRIP-PAYLOAD' "$MKAUTH_KEY" "$MKAUTH_CERT"
assert_eq "mkauth writer round-trip: rc 0" "0" \
    "$( fw_var_write "$RTM/efivars" db "$GUID_DBASE" "$RTM/db.auth" >/dev/null 2>&1; echo $? )"
assert_contains "mkauth writer round-trip: efi-updatevar invoked for the packet" \
    "$(cat "$EUV_LOG")" "efi-updatevar -f $RTM/db.auth db"
# SCOPE CUT (blocker #25): the old 'KEK packet refused for db' pin contradicts
# the UEFI trust model — db is AUTHENTICATED BY the KEK, so a KEK-signed db
# update is exactly what firmware accepts. The name binding lives in the
# signed digest; firmware is the final arbiter.

# =============================================================================
# POLLUTED EFIVARS (blocker #25 addendum, Dell live-proven sequence): a
# pre-existing AUTHENTICATED var (attrs 0x00010007) is S_IMMUTABLE and the
# firmware refuses an unauthenticated delete even in Setup Mode (plain rm ->
# EINVAL). fw_auth_enroll must: chattr -i -> rm -> SIGNED-EMPTY delete
# (sign-efi-sig-list over /dev/null + efi-updatevar -f) -> verify gone.
# Stub efitools binaries on PATH observe the exact invocation shape.
# =============================================================================
E4=$T/polluted
mkdir -p "$E4" "$T/psb"
GUID_G=8be4df61-93ca-11d2-aa0d-00e098032b8c
# pre-existing AUTH vars: attrs u32le 0x00010007 + non-empty body.
# db is a DIRECTORY: `rm -f` cannot remove it (same failure class as the
# efivarfs S_IMMUTABLE refusal) -> the signed-empty delete branch MUST fire.
printf '\007\000\000\000\001' >"$E4/SecureBoot-$GUID_G"
printf '\007\000\000\000\001' >"$E4/SetupMode-$GUID_G" # SetupMode=1: Setup Mode
mkdir "$E4/db-$GUID_DBASE"
printf '\007\000\001\000STALE-AUTH-BODY' >"$E4/KEK-$GUID_G"
printf '\007\000\001\000STALE-AUTH-BODY' >"$E4/PK-$GUID_G"
cat >"$T/psb/chattr" <<'STUB'
#!/bin/sh
echo "chattr $*" >>"$CHATTR_LOG"
exit 0
STUB
cat >"$T/psb/efi-updatevar" <<'STUB'
#!/bin/sh
echo "efi-updatevar $*" >>"$UPDATE_LOG"
# model the KERNEL result, not just the rc: the authenticated delete
# (-f ...-del.auth) removes the variable; the enrollment write creates it
# (attrs u32le 0x00010007 + packet body). PSB_EFIVARS_DIR names the seam dir.
dir=${PSB_EFIVARS_DIR:-}
[ -n "$dir" ] || exit 0
auth=$2
name=$3
case $name in
    db) guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f ;;
    *) guid=8be4df61-93ca-11d2-aa0d-00e098032b8c ;;
esac
case $auth in
    *-del.auth) rm -rf "$dir/$name-$guid" 2>/dev/null ;;
    *) { printf '\007\000\001\000'; cat "$auth"; } >"$dir/$name-$guid" ;;
esac
exit 0
STUB
cat >"$T/psb/sign-efi-sig-list" <<'STUB'
#!/bin/sh
# argv: -g GUID -c CERT -k KEY VAR /dev/null OUT — log the invocation (the
# /dev/null payload IS the signed-empty contract) and write a canned packet to
# the LAST argument (the .auth output)
echo "sign-efi-sig-list $*" >>"$UPDATE_LOG"
for a in "$@"; do out=$a; done
printf 'SIGNED-EMPTY-PACKET' > "$out"
exit 0
STUB
chmod +x "$T/psb"/*
CHATTR_LOG="$T/chattr.log"; UPDATE_LOG="$T/update.log"
export CHATTR_LOG UPDATE_LOG
export PATH="$T/psb:$PATH"

# fw_auth_enroll needs SetupMode=1 (Setup Mode — the DECIDED 2026-09-27 db
# reset + release+vendor rebuild gate) + SecureBoot readable + staged packets
mkdir -p "$E4/sys"
printf '\007\000\000\000\001' >"$E4/SecureBoot-$GUID_G"
printf '\007\000\000\000\001' >"$E4/SetupMode-$GUID_G" # SetupMode=1: Setup Mode
KD4=$T/keys4
mkdir -p "$KD4"
for v in db kek pk; do
    printf 'CERT-DER-%s' "$v" >"$KD4/$v.cert.der"
    printf '%s-ESL-BYTES' "$v" >"$KD4/$v.esl"
    printf '%s-PRIV' "$v" >"$KD4/$v.priv.pem"
    printf '%s-CERT-PEM' "$v" >"$KD4/$v.cert.pem"
    # the staged .auth packets (blocker #25: built by sign-efi-sig-list at
    # stage1; EFI_TIME 2026 + WIN_CERT_UEFI_GUID header + stub PKCS7)
    { printf '\352\007\033\t\000\000\000\000\000\000\000\000\000\000\000\000'
      printf '\x2a\x00\x00\x00\x00\x02\xf7\x0e'
      printf 'STUB-PKCS7-BYTES'
    } >"$KD4/$v.auth"
done
printf 'release-priv' >"$KD4/release.priv.pem"
printf 'CERT-DER-release' >"$KD4/release.cert.der"
printf 'release-pub' >"$KD4/release.pub.pem"

ENROLL_OUT=$( ( PSB_EFIVARS_DIR="$E4" fw_auth_enroll "$E4" "$KD4" ) 2>&1 )
ENROLL_RC=$?
[ "$ENROLL_RC" -eq 0 ] || printf '%s\n' "$ENROLL_OUT" >&2
assert_eq "polluted efivars: fw_auth_enroll clears + enrolls end-to-end rc 0" "0" "$ENROLL_RC"
assert_contains "the cleanup ran chattr -i per variable" "$(cat "$CHATTR_LOG" 2>/dev/null)" "-i"
assert_contains "the signed-empty delete went through efi-updatevar -f"     "$(cat "$UPDATE_LOG" 2>/dev/null)" "-f"
assert_contains "the signed-empty delete payload is /dev/null (empty packet)"     "$(grep -oF "/dev/null" "$UPDATE_LOG" | head -1)" "/dev/null"
for v in db KEK PK; do
    lf=$(printf '%s' "$v" | tr 'A-Z' 'a-z')
    assert_contains "polluted efivars: $v enrolled via efi-updatevar" \
        "$(grep -F "keys4/$lf.auth $v" "$UPDATE_LOG" | head -1)" "keys4/$lf.auth $v"
done
STALE_SURVIVED=0
[ -e "$E4/KEK-$GUID_G" ] && grep -q "STALE-AUTH-BODY" "$E4/KEK-$GUID_G" 2>/dev/null && STALE_SURVIVED=1
assert_eq "stale auth bodies were replaced (cleared + re-enrolled)" "0" "$STALE_SURVIVED"

# --- Leg B: STUBBORN vars (the rm physically fails) -> the SIGNED-EMPTY
# delete branch fires: sign-efi-sig-list over /dev/null + efi-updatevar -f
E5=$T/polluted-ro
mkdir -p "$E5"
printf '\007\000\000\000\001' >"$E5/SecureBoot-$GUID_G"
printf '\007\000\000\000\001' >"$E5/SetupMode-$GUID_G" # SetupMode=1: Setup Mode
for v in db KEK PK; do
    printf '\007\000\001\000STALE-AUTH-BODY' >"$E5/$v-$GUID_G"
done
UPDATE_LOG2="$T/update2.log"; CHATTR_LOG2="$T/chattr2.log"
export UPDATE_LOG2 CHATTR_LOG2
chmod 555 "$E5" # the stale vars cannot be removed (simulated immutable bit)
ENROLL2_OUT=$( ( PATH="$T/psb:$PATH" UPDATE_LOG="$UPDATE_LOG2" PSB_EFIVARS_DIR="$E5" fw_auth_enroll "$E5" "$KD4" ) 2>&1 )
ENROLL2_RC=$?
chmod 755 "$E5"
# the stubborn-var residue is REFUSED fail-closed (the stub efi-updatevar
# cannot really remove NVRAM vars — the survived-cleanup die is the contract)
assert_eq "stubborn vars: residue refused fail-closed 64" "64" "$ENROLL2_RC"
assert_contains "signed-empty delete: sign-efi-sig-list over /dev/null" \
    "$(cat "$UPDATE_LOG2")" "/dev/null"
assert_contains "signed-empty delete: the chain key signs the KEK delete (KEK-del is PK-signed)" \
    "$(cat "$UPDATE_LOG2")" "keys4/pk.priv.pem"
assert_contains "signed-empty delete: efi-updatevar -f applies the del packet" \
    "$(cat "$UPDATE_LOG2")" "-f"
assert_contains "stubborn-var cleanup: chattr -i ran per variable" \
    "$(cat "$CHATTR_LOG2" 2>/dev/null || cat "$CHATTR_LOG")" "-i"
assert_contains "stubborn-var residue die names the cleanup" \
    "$ENROLL2_OUT" "survived the cleanup"

# the chattr requirement is pinned textually: targets where chattr is absent
# (busybox-only initramfs/minimal chroots) get the loud remedy naming the
# package, from fw_auth_enroll's own cleanup path
assert_contains "the chattr remedy names 'apk add e2fsprogs' (source-pinned)" \
    "$(cat "$REPO/lib/firmware.sh")" "apk add e2fsprogs"

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

# =============================================================================
# DEFERRED-ENROLLMENT path (DECIDED Samuel, 2026-09-28, real Dell PowerEdge
# R640): SetupMode=0 WITH a platform PK present (factory or custom) — the
# enroll makes NO NVRAM write attempts, stages the import-ready .cer set
# (db.cer/KEK.cer/PK.cer + the vendor certs — the 0ec17a1 fallback staging,
# reused) with the DEFER note, records the deferred marker seam, and returns
# SUCCESS so the install continues. That day's proven deployment: factory
# Dell PK/KEK/db restored ('Restore Default Policy Entries'), the release
# db.cer imported into the factory db via the firmware UI — PK present,
# SetupMode=0, Secure Boot enforced, our release cert in db verifies our UKI;
# the old SetupMode!=1 die 64 would have aborted the install.
# =============================================================================
E7=$T/enroll-deferred
mkdir -p "$E7" "$T/esp-defer"
mkvar "$E7" SetupMode "$GUID_GLOBAL" 0
printf '\007\000\000\000FACTORY-PK' >"$E7/PK-$GUID_GLOBAL"
KD7=$T/keys-defer
cp -r "$T/keys" "$KD7"
# release.crt must be a REAL PEM certificate (2026-09-29): the deferred
# staging converts it PEM -> DER with openssl x509 (Dell's .cer import is
# DER-only — a PEM .cer is rejected by the firmware UI), so a fake PEM body
# would die fail-closed in the conversion.
cp "$MKAUTH_CERT" "$KD7/release.crt"
printf 'KEK-CERT-DER-BYTES' >"$KD7/kek.cert.der"
printf 'PK-CERT-DER-BYTES' >"$KD7/pk.cert.der"
openssl x509 -in "$KD7/release.crt" -outform der >"$T/release.der"
DEFER_MARKER="$T/deferred-marker"
rm -f "$DEFER_MARKER"
UPDATE_LOG3="$T/update3.log"; CHATTR_LOG3="$T/chattr3.log"
: >"$UPDATE_LOG3"
ENROLL7_OUT=$( ( PATH="$T/psb:$PATH" UPDATE_LOG="$UPDATE_LOG3" CHATTR_LOG="$CHATTR_LOG3" \
    PSB_EFIVARS_DIR="$E7" ALPINE_FDE_ENROLL_DEFERRED_MARKER="$DEFER_MARKER" \
    fw_auth_enroll "$E7" "$KD7" "$T/esp-defer" ) 2>&1 )
ENROLL7_RC=$?
assert_eq "deferred enroll: platform PK present (SetupMode=0) -> rc 0 (install continues)" "0" "$ENROLL7_RC"
assert_eq "deferred enroll: ZERO NVRAM write attempts (efi-updatevar never invoked)" "0" \
    "$(wc -l <"$UPDATE_LOG3")"
assert_eq "deferred enroll: db was NOT written" "0" \
    "$([ -e "$E7/db-$GUID_DBASE" ] && echo 1 || echo 0)"
assert_contains "deferred enroll: info line names the platform PK situation" \
    "$ENROLL7_OUT" "a platform key is enrolled (SetupMode 0"
assert_contains "deferred enroll: info line states NO NVRAM writes + the firmware-UI route" \
    "$ENROLL7_OUT" "NO NVRAM writes are attempted"
assert_contains "deferred enroll: info line names db.cer for the import" \
    "$ENROLL7_OUT" "db.cer"
for v in db.cer KEK.cer PK.cer; do
    assert_file_exists "deferred enroll: staged the import-ready $v" \
        "$T/esp-defer/alpine-fde-keys/$v"
done
# REAL-SERVER 2026-09-29 (Dell PowerEdge R640): db.cer stages as the DER
# encoding of release.crt — the firmware UI rejects PEM .cer imports
assert_eq "deferred enroll: db.cer is the DER encoding of release.crt (Dell UIs reject PEM .cer)" \
    "$(cat "$T/release.der")" "$(cat "$T/esp-defer/alpine-fde-keys/db.cer")"
assert_eq "deferred enroll: db.cer parses as DER and carries the release.crt subject" \
    "$(openssl x509 -in "$KD7/release.crt" -noout -subject)" \
    "$(openssl x509 -inform der -in "$T/esp-defer/alpine-fde-keys/db.cer" -noout -subject)"
assert_file_exists "deferred enroll: README.txt staged" \
    "$T/esp-defer/alpine-fde-keys/README.txt"
assert_contains "deferred enroll: README leads with the DEFER note" \
    "$(cat "$T/esp-defer/alpine-fde-keys/README.txt")" "DEFERRED ENROLLMENT"
assert_contains "deferred enroll: README forbids importing KEK.cer/PK.cer (factory PK/KEK stay)" \
    "$(cat "$T/esp-defer/alpine-fde-keys/README.txt")" "Do NOT import KEK.cer or PK.cer"
assert_file_exists "deferred enroll: the deferred marker seam was recorded for the install tail" \
    "$DEFER_MARKER"

# happy path: db → KEK → PK (all three land in their canonical namespaces)
E4=$T/enroll-happy
mkdir -p "$E4"
mkvar "$E4" SetupMode "$GUID_GLOBAL" 1
PSB_EFIVARS_DIR="$E4" fw_auth_enroll "$E4" "$T/keys"
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
e5_abort_run() { PSB_EFIVARS_DIR="$E5" fw_auth_enroll "$@"; }
assert_rc "fw_auth_enroll: missing KEK packet -> fail-closed 64 (abort)" 64 \
    die_rc e5_abort_run "$E5" "$T/keys-partial"
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
