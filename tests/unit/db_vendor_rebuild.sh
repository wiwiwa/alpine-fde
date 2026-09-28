#!/usr/bin/env bash
# tests/unit/db_vendor_rebuild.sh — DECIDED (Samuel, 2026-09-27): db
# reset + release+vendor rebuild (UEFI0072 option-ROM authorization).
#   (1) prov_db_esl_build composes db.esl as release cert + every vendor
#       *.cer (LC_ALL=C sorted basenames) — deterministic byte order;
#   (2) empty vendor dir == release-cert-only (the old behavior);
#   (3) ALPINE_FDE_DB_VENDOR=none == release-cert-only (minimal-db knob);
#   (4) ALPINE_FDE_DB_VENDOR_DIR overrides the vendor directory; the DEFAULT
#       resolution finds the shipped certs/vendor (Microsoft Option ROM UEFI
#       CA 2023) from the repo layout;
#   (5) a malformed vendor cert dies fail-closed 64 (never a silent skip);
#   (6) esl_verify WALKS the concatenated SignatureListSize chain (combined
#       lists have per-list SignatureSizes) and still rejects corruption;
#   (7) fw_auth_enroll ordering pin: db reset (authenticated delete) precedes
#       the db write, db write precedes KEK, KEK precedes PK; dbx is NEVER
#       targeted by the reset or the write;
#   (8) SetupMode=0 WITH a platform PK -> the DEFERRED-ENROLLMENT path (no
#       NVRAM writes, .cer staging, rc 0 — DECIDED 2026-09-28, real Dell
#       PowerEdge R640); SetupMode=0 with NO PK (no real firmware state) ->
#       fail-closed 64 with an actionable message, and nothing is written;
#   (9) the ESP fallback stages every vendor .cer under its basename.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

# tests/unit/lib.sh has no assert_file_exists; local definition
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (file does not exist: $2)"; fi
}

export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/firmware.sh
source "$REPO/lib/firmware.sh"
# shellcheck source=../../lib/cmd/provision.sh
. "$ALPINE_FDE_CMD_DIR/provision.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
GUID_DBASE='d719b2cb-3d3a-4596-a3bc-dad00e67656f'

# --- fixtures ------------------------------------------------------------------

KD=$TMP/keys
mkdir -p "$KD"
openssl req -new -x509 -newkey rsa:2048 -keyout "$KD/release.priv.pem" \
    -out "$KD/release.cert.pem" -days 30 -nodes \
    -subj "/O=Alpine FDE/CN=Vendor Rebuild Test Release" >/dev/null 2>&1
openssl x509 -in "$KD/release.cert.pem" -outform DER -out "$KD/release.cert.der" 2>/dev/null

VDIR=$TMP/vendor
mkdir -p "$VDIR"
# created in REVERSE sorted order on purpose: composition must be
# filename-sorted, never creation/readdir order
mkvendor() { # FILE CN
    openssl req -new -x509 -newkey rsa:2048 -keyout "$TMP/vk.pem" \
        -out "$TMP/vc.pem" -days 30 -nodes -subj "/O=Vendor/CN=$2" >/dev/null 2>&1
    openssl x509 -in "$TMP/vc.pem" -outform DER -out "$1" 2>/dev/null
}
mkvendor "$VDIR/b-vendor.cer" "Vendor B"
mkvendor "$VDIR/a-vendor.cer" "Vendor A"
mkvendor "$VDIR/c-option-rom.cer" "Vendor C Option ROM"

# db_vendor_dir: the default resolution from the repo layout must find the
# SHIPPED vendor dir with the Microsoft Option ROM UEFI CA 2023 cert
assert_eq "db_vendor_dir default resolves to <tree>/certs/vendor" \
    "$REPO/lib/../certs/vendor" "$(db_vendor_dir)"
assert_eq "db_vendor_dir: ALPINE_FDE_DB_VENDOR_DIR wins" \
    "$VDIR" "$(ALPINE_FDE_DB_VENDOR_DIR=$VDIR db_vendor_dir)"

# --- (1) combined composition, deterministic ------------------------------------
ALPINE_FDE_DB_VENDOR_DIR=$VDIR prov_db_esl_build "$KD" "$KD/db.esl" 2>/dev/null
assert_file_exists "combined db.esl built" "$KD/db.esl"
esl_build "$KD/release.cert.der" >"$TMP/rel.esl"
esl_build "$VDIR/a-vendor.cer" >"$TMP/a.esl"
esl_build "$VDIR/b-vendor.cer" >"$TMP/b.esl"
esl_build "$VDIR/c-option-rom.cer" >"$TMP/c.esl"
cat "$TMP/rel.esl" "$TMP/a.esl" "$TMP/b.esl" "$TMP/c.esl" >"$TMP/expected-combined.esl"
assert_eq "combined db.esl = release + vendor certs in LC_ALL=C sorted filename order" \
    "$(wc -c <"$TMP/expected-combined.esl")" "$(wc -c <"$KD/db.esl")"
cmp -s "$TMP/expected-combined.esl" "$KD/db.esl"
assert_eq "combined db.esl byte-identical to the sorted concatenation" "0" "$?"

# determinism: rebuild -> identical bytes (and never readdir order:
# b-vendor.cer was created FIRST; the sorted composition still puts a- first)
ALPINE_FDE_DB_VENDOR_DIR=$VDIR prov_db_esl_build "$KD" "$KD/db.esl.2" 2>/dev/null
cmp -s "$KD/db.esl" "$KD/db.esl.2"
assert_eq "rebuild is deterministic (identical bytes; re-installs never accumulate)" "0" "$?"
RELEASE_BYTES=$(wc -c <"$TMP/rel.esl")
A_BYTES=$(wc -c <"$TMP/a.esl")
assert_eq "first list is the RELEASE cert ESL (release cert first in the blob)" \
    "$(head -c "$RELEASE_BYTES" "$KD/db.esl" | od -An -vtx1 | tr -d ' \n')" \
    "$(od -An -vtx1 <"$TMP/rel.esl" | tr -d ' \n')"
assert_eq "second list is the a-vendor cert (sorted, not creation order)" \
    "$(dd if="$KD/db.esl" bs=1 skip="$RELEASE_BYTES" count="$A_BYTES" 2>/dev/null | od -An -vtx1 | tr -d ' \n')" \
    "$(od -An -vtx1 <"$TMP/a.esl" | tr -d ' \n')"

# (6) esl_verify walks the concatenated chain; corruption still rejected
esl_verify "$KD/db.esl"
assert_rc "esl_verify accepts the combined multi-list blob" 0 "$?"
cp "$KD/db.esl" "$TMP/db.esl.corrupt"
python3 - "$TMP/db.esl.corrupt" <<'EOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
b[16] ^= 0xFF   # flip a byte of the FIRST list's SignatureListSize
open(p, 'wb').write(bytes(b))
EOF
esl_verify "$TMP/db.esl.corrupt"
assert_rc "esl_verify rejects a corrupted SignatureListSize in the chain" 1 "$?"
esl_verify "$TMP/rel.esl"
assert_rc "esl_verify accepts a single-list ESL (N=1 walk; kek.esl/pk.esl case)" 0 "$?"

# --- (2) empty vendor dir == release-only ---------------------------------------
EMPTY=$TMP/vendor-empty
mkdir -p "$EMPTY"
ALPINE_FDE_DB_VENDOR_DIR=$EMPTY prov_db_esl_build "$KD" "$KD/db-empty.esl" 2>/dev/null
assert_eq "empty vendor dir -> release-cert-only db.esl (the old behavior)" \
    "$(od -An -vtx1 <"$TMP/rel.esl" | tr -d ' \n')" \
    "$(od -An -vtx1 <"$KD/db-empty.esl" | tr -d ' \n')"

# --- (3) ALPINE_FDE_DB_VENDOR=none == release-only -------------------------------
ALPINE_FDE_DB_VENDOR=none prov_db_esl_build "$KD" "$KD/db-none.esl" 2>/dev/null
assert_eq "ALPINE_FDE_DB_VENDOR=none -> release-cert-only db.esl (minimal db knob)" \
    "$(od -An -vtx1 <"$TMP/rel.esl" | tr -d ' \n')" \
    "$(od -An -vtx1 <"$KD/db-none.esl" | tr -d ' \n')"
RC=$( (ALPINE_FDE_DB_VENDOR=sometimes ALPINE_FDE_DB_VENDOR_DIR=$EMPTY \
    prov_db_esl_build "$KD" "$KD/db-bad.esl") >/dev/null 2>&1; echo $? )
assert_eq "ALPINE_FDE_DB_VENDOR garbage value -> fail-closed 64" "64" "$RC"

# --- (4) ALPINE_FDE_DB_VENDOR_DIR override ---------------------------------------
V2=$TMP/vendor2
mkdir -p "$V2"
mkvendor "$V2/solo.cer" "Solo Override"
ALPINE_FDE_DB_VENDOR_DIR=$V2 prov_db_esl_build "$KD" "$KD/db-override.esl" 2>/dev/null
esl_build "$V2/solo.cer" >"$TMP/solo.esl"
cat "$TMP/rel.esl" "$TMP/solo.esl" >"$TMP/expected-override.esl"
cmp -s "$TMP/expected-override.esl" "$KD/db-override.esl"
assert_eq "ALPINE_FDE_DB_VENDOR_DIR override: release + override-dir certs only" "0" "$?"

# default resolution finds the SHIPPED Microsoft Option ROM UEFI CA 2023
prov_db_esl_build "$KD" "$KD/db-shipped.esl" 2>/dev/null
esl_build "$REPO/certs/vendor/microsoft-option-rom-uefi-ca-2023.cer" >"$TMP/ms.esl"
cat "$TMP/rel.esl" "$TMP/ms.esl" >"$TMP/expected-shipped.esl"
cmp -s "$TMP/expected-shipped.esl" "$KD/db-shipped.esl"
assert_eq "default db.esl = release + shipped Microsoft Option ROM UEFI CA 2023" "0" "$?"

# --- (5) malformed vendor cert dies loudly ---------------------------------------
BAD=$TMP/vendor-bad
mkdir -p "$BAD"
printf 'THIS IS NOT A CERTIFICATE' >"$BAD/garbage.cer"
RC=$( (ALPINE_FDE_DB_VENDOR_DIR=$BAD prov_db_esl_build "$KD" "$KD/db-bad.esl") >/dev/null 2>&1; echo $? )
assert_eq "malformed vendor cert -> fail-closed 64 (ADR-8, never a silent skip)" "64" "$RC"

# =============================================================================
# (7)(8)(9) fw_auth_enroll: reset-first ordering, SetupMode gate, ESP staging
# =============================================================================
SB=$TMP/stub-bin
mkdir -p "$SB"
EUV_LOG=$TMP/euv.log
CHATTR_LOG=$TMP/chattr.log
SESL_LOG=$TMP/sesl.log
export EUV_LOG CHATTR_LOG SESL_LOG
# sign-efi-sig-list stub: log the invocation, write the del packet to the LAST arg
cat >"$SB/sign-efi-sig-list" <<'STUB'
#!/bin/sh
printf 'sign-efi-sig-list %s\n' "$*" >>"$SESL_LOG"
out=""
for a in "$@"; do out=$a; done
printf 'SIGNED-EMPTY-PACKET' >"$out"
exit 0
STUB
# chattr stub: log, succeed
cat >"$SB/chattr" <<'STUB'
#!/bin/sh
printf 'chattr %s\n' "$*" >>"$CHATTR_LOG"
exit 0
STUB
# efi-updatevar stub: log, then model the kernel result — the authenticated
# delete (-f ...-del.auth) removes the variable from the seam efivars dir;
# the .auth enrollment writes create the variable file (attrs + body)
cat >"$SB/efi-updatevar" <<'STUB'
#!/bin/sh
printf 'efi-updatevar %s\n' "$*" >>"$EUV_LOG"
dir=${ALPINE_FDE_SEAM_EFIVARS:-}
[ -n "$dir" ] || exit 0
auth=$2
name=$3
case $name in
    db)
        guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f
        case $auth in
            *-del.auth) rm -rf "$dir/db-$guid" ;;
            *) { printf '\007\000\001\000'; cat "$auth"; } >"$dir/db-$guid" ;;
        esac
        ;;
    dbx) exit 0 ;;
    *)
        guid=8be4df61-93ca-11d2-aa0d-00e098032b8c
        case $auth in
            *-del.auth) rm -rf "$dir/$name-$guid" ;;
            *) { printf '\007\000\001\000'; cat "$auth"; } >"$dir/$name-$guid" ;;
        esac
        ;;
esac
exit 0
STUB
chmod +x "$SB"/*

mkpacket() { # FILE — minimal .auth packet passing fw_var_write_try's
    # EFI_TIME-year preflight (byte 2 = 0x07)
    printf '\352\007\033\t\000\000\000\000\000\000\000\000\000\000\000\000' >"$1"
    printf '\x2a\x00\x00\x00\x00\x02\xf7\x0e' >>"$1"
    printf 'STUB-PKCS7-BYTES' >>"$1"
}

EK=$TMP/enroll-keys
mkdir -p "$EK"
for v in db kek pk; do
    mkpacket "$EK/$v.auth"
done
printf 'KEKPRIV' >"$EK/kek.priv.pem"
printf 'KEKCERT' >"$EK/kek.cert.pem"
printf 'PKPRIV' >"$EK/pk.priv.pem"
printf 'PKCERT' >"$EK/pk.cert.pem"
# the operator's OWN certs in the keydir artifact forms (REAL-SERVER
# 2026-09-28: the ESP fallback stages them as import-ready db.cer/KEK.cer/
# PK.cer — the firmware setup UI cannot import .auth packets)
printf 'RELEASE-CRT-PEM' >"$EK/release.crt"
printf 'KEK-CERT-DER' >"$EK/kek.cert.der"
printf 'PK-CERT-DER' >"$EK/pk.cert.der"

# (7) ordering pin: pre-existing vendor db (a DIRECTORY: the plain rm is
# refused, so the RESET must go through the signed-empty delete machinery)
# + pre-existing vendor KEK (plain file) + chain keys on disk
E1=$TMP/enroll-ordered
mkdir -p "$E1"
printf '\007\000\000\000\001' >"$E1/SecureBoot-$GUID_GLOBAL"
printf '\007\000\000\000\001' >"$E1/SetupMode-$GUID_GLOBAL" # payload 1 = Setup Mode
mkdir "$E1/db-$GUID_DBASE" # stubborn vendor db: rm -f cannot remove it
printf '\007\000\001\000VENDORDB-BYTES' >"$E1/db-$GUID_DBASE/body"
printf '\007\000\000\000VENDORKEK' >"$E1/KEK-$GUID_GLOBAL"
: >"$EUV_LOG"
OUT=$(PATH="$SB:$PATH" ALPINE_FDE_DB_VENDOR=none ALPINE_FDE_DB_VENDOR_DIR="$EMPTY" \
    ALPINE_FDE_SEAM_EFIVARS="$E1" fw_auth_enroll "$E1" "$EK" 2>&1)
RC=$?
assert_eq "enroll with a stubborn pre-existing vendor db: rc 0" "0" "$RC"
DEL_LINE=$(grep -c -F "db-del.auth db" "$EUV_LOG")
DB_LINE=$(grep -c -F "$EK/db.auth db" "$EUV_LOG")
KEK_LINE=$(grep -c -F "$EK/kek.auth KEK" "$EUV_LOG")
PK_LINE=$(grep -c -F "$EK/pk.auth PK" "$EUV_LOG")
assert_eq "the db RESET ran (authenticated delete via the signed-empty packet)" "1" "$DEL_LINE"
assert_eq "the db write ran" "1" "$DB_LINE"
assert_eq "the KEK write ran" "1" "$KEK_LINE"
assert_eq "the PK write ran" "1" "$PK_LINE"
assert_eq "ordering: reset < db < KEK < PK (strict order)" "1" \
    "$([ "$DEL_LINE" -eq 1 ] && [ "$DB_LINE" -eq 1 ] && [ "$KEK_LINE" -eq 1 ] && [ "$PK_LINE" -eq 1 ] \
        && [ "$(grep -n -F "db-del.auth db" "$EUV_LOG" | cut -d: -f1)" -lt "$(grep -n -F "$EK/db.auth db" "$EUV_LOG" | cut -d: -f1)" ] \
        && [ "$(grep -n -F "$EK/db.auth db" "$EUV_LOG" | cut -d: -f1)" -lt "$(grep -n -F "$EK/kek.auth KEK" "$EUV_LOG" | cut -d: -f1)" ] \
        && [ "$(grep -n -F "$EK/kek.auth KEK" "$EUV_LOG" | cut -d: -f1)" -lt "$(grep -n -F "$EK/pk.auth PK" "$EUV_LOG" | cut -d: -f1)" ] && echo 1 || echo 0)"
assert_eq "dbx is NEVER targeted (no dbx anywhere in the write log)" "0" "$(grep -c "dbx" "$EUV_LOG")"
assert_eq "no dbx-del.auth was ever created (dbx must never be reset)" "0" \
    "$([ -e "$E1/dbx-del.auth" ] && echo 1 || echo 0)"
assert_contains "the db reset is announced as the db RESET (not a generic rm)" "$OUT" "db RESET"
assert_contains "the reset reused the signed-empty delete machinery (sign-efi-sig-list over /dev/null)" \
    "$(cat "$SESL_LOG")" "db /dev/null"

# (8) SetupMode=0 WITH a platform PK -> the DEFERRED-ENROLLMENT path (DECIDED
# Samuel, 2026-09-28, real Dell PowerEdge R640): NO NVRAM writes, the
# import-ready .cer staging with the defer note, rc 0 (install continues).
# SetupMode=0 WITHOUT a PK (a state no real firmware reports) stays
# fail-closed 64 with the actionable Setup-Mode remedy.
E2=$TMP/enroll-usermode
mkdir -p "$E2"
printf '\007\000\000\000\001' >"$E2/SecureBoot-$GUID_GLOBAL"
printf '\007\000\000\000\000' >"$E2/SetupMode-$GUID_GLOBAL" # payload 0 = user mode
printf '\007\000\000\000\001' >"$E2/PK-$GUID_GLOBAL"        # a PK is enrolled
: >"$EUV_LOG"
ESP2=$TMP/esp-usermode
OUT2=$(PATH="$SB:$PATH" ALPINE_FDE_DB_VENDOR=none ALPINE_FDE_DB_VENDOR_DIR="$EMPTY" \
    fw_auth_enroll "$E2" "$EK" "$ESP2" 2>&1)
RC2=$?
assert_eq "SetupMode=0 with a platform PK -> DEFERRED path, rc 0 (install continues)" "0" "$RC2"
assert_contains "the deferred info line names the platform PK + the firmware-UI route" \
    "$OUT2" "enrollment DEFERS to the firmware-UI import"
assert_contains "the deferred info line says the platform PK/KEK stay" \
    "$OUT2" "the platform's PK/KEK stay"
assert_eq "SetupMode=0: NOTHING was written (log empty)" "0" "$(grep -c . "$EUV_LOG")"
assert_eq "the deferred staging carries db.cer (the import-ready release cert)" "1" \
    "$([ -f "$ESP2/alpine-fde-keys/db.cer" ] && echo 1 || echo 0)"
E2B=$TMP/enroll-usermode-nopk
mkdir -p "$E2B"
printf '\007\000\000\000\001' >"$E2B/SecureBoot-$GUID_GLOBAL"
printf '\007\000\000\000\000' >"$E2B/SetupMode-$GUID_GLOBAL"
RC=$( (PATH="$SB:$PATH" ALPINE_FDE_DB_VENDOR=none ALPINE_FDE_DB_VENDOR_DIR="$EMPTY" \
    fw_auth_enroll "$E2B" "$EK") >/dev/null 2>&1; echo $? )
assert_eq "SetupMode=0 with NO platform PK -> fail-closed 64" "64" "$RC"
OUT2B=$(PATH="$SB:$PATH" ALPINE_FDE_DB_VENDOR=none ALPINE_FDE_DB_VENDOR_DIR="$EMPTY" \
    fw_auth_enroll "$E2B" "$EK" 2>&1)
assert_contains "the SetupMode gate message is actionable (names the Setup Mode remedy)" \
    "$OUT2B" "Clear Secure Boot Keys"
assert_contains "the SetupMode gate names the design boundary (not this flow's job)" \
    "$OUT2B" "not this flow's job"
assert_eq "SetupMode=0: NOTHING was written (log empty)" "0" "$(grep -c . "$EUV_LOG")"

# (9) ESP fallback stages vendor certs under their basenames
E3=$TMP/enroll-esp
mkdir -p "$E3"
printf '\007\000\000\000\001' >"$E3/SecureBoot-$GUID_GLOBAL"
printf '\007\000\000\000\001' >"$E3/SetupMode-$GUID_GLOBAL"
FAILBIN=$TMP/stub-fail
mkdir -p "$FAILBIN"
printf '#!/bin/sh\nexit 1\n' >"$FAILBIN/efi-updatevar"
chmod +x "$FAILBIN/efi-updatevar"
ESP3=$TMP/esp3
OUT3=$(PATH="$FAILBIN:$PATH" ALPINE_FDE_DB_VENDOR_DIR="$VDIR" \
    fw_auth_enroll "$E3" "$EK" "$ESP3" 2>&1)
RC3=$?
assert_eq "write-refused enrollment degrades to the ESP fallback (rc 0)" "0" "$RC3"
for f in db.auth kek.auth pk.auth README.txt '!import_all_auth_files' a-vendor.cer b-vendor.cer c-option-rom.cer; do
    assert_eq "ESP fallback staged $f" "1" "$([ -e "$ESP3/alpine-fde-keys/$f" ] && echo 1 || echo 0)"
done
# REAL-SERVER 2026-09-28 (Dell PowerEdge R640): the operator's OWN certs land
# as import-ready db.cer/KEK.cer/PK.cer (the UI imports X.509, not .auth)
for pair in 'db.cer release.crt' 'KEK.cer kek.cert.der' 'PK.cer pk.cert.der'; do
    cer=${pair%% *}; src=${pair#* }
    assert_eq "ESP fallback staged the import-ready $cer" "1" \
        "$([ -f "$ESP3/alpine-fde-keys/$cer" ] && echo 1 || echo 0)"
    assert_eq "$cer is a byte-for-byte copy of $src" \
        "$(cat "$EK/$src")" "$(cat "$ESP3/alpine-fde-keys/$cer")"
done
assert_contains "the ESP staging info names the staged vendor certs" "$OUT3" "vendor certs:"
assert_contains "the fallback README explains the vendor .cer files" \
    "$(cat "$ESP3/alpine-fde-keys/README.txt")" "Option ROM"

finish
