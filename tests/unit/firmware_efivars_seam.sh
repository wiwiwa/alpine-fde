#!/bin/sh
# firmware_efivars_seam.sh — unit tests for lib/firmware.sh with an injected
# efivars directory (ALPINE_FDE_EFIVARS_DIR). No real firmware or TPM required.

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/firmware.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

GUID='8be4df61-93ca-11d2-aa0d-00e098032b8c'

# mkvar_byte DIR NAME DECBYTE — attrs header (u32, 0x7) + one payload byte
mkvar_byte() {
    printf '\007\000\000\000' >"$1/$2-$GUID"
    _oct=$(printf '%03o' "$3")
    printf '%b' "\\$_oct" >>"$1/$2-$GUID"
}

# mkvar_str DIR NAME STRING — attrs header + string payload
mkvar_str() {
    printf '\007\000\000\000%s' "$3" >"$1/$2-$GUID"
}

# mkvar_attrsonly DIR NAME — attrs header only (empty payload = effectively unset)
mkvar_attrsonly() {
    printf '\007\000\000\000' >"$1/$2-$GUID"
}

# --- fw_efivars_dir resolution ---
assert_eq "fw_efivars_dir default" "/sys/firmware/efi/efivars" \
    "$(ALPINE_FDE_EFIVARS_DIR='' fw_efivars_dir)"
assert_eq "fw_efivars_dir ALPINE_FDE_EFIVARS_DIR override" "/x/efivars" \
    "$(ALPINE_FDE_EFIVARS_DIR=/x/efivars fw_efivars_dir)"

# --- secure state: SB on, not in setup mode, PK set ---
secure="$tmp/secure"
mkdir -p "$secure"
mkvar_byte "$secure" SecureBoot 1
mkvar_byte "$secure" SetupMode 0
mkvar_str "$secure" PK "PKPAYLOAD"
ALPINE_FDE_EFIVARS_DIR="$secure"
out=$(fw_sb_state)
rc=$?
assert_rc "fw_sb_state: secure state -> rc 0" "0" "$rc"
assert_eq "fw_sb_state: secure state kv" "secureboot=1 setup_mode=0 pk=1" "$out"

# --- SB explicitly off -> drift rc ---
sb_off="$tmp/sb_off"
mkdir -p "$sb_off"
mkvar_byte "$sb_off" SecureBoot 0
mkvar_byte "$sb_off" SetupMode 0
mkvar_str "$sb_off" PK "PKPAYLOAD"
ALPINE_FDE_EFIVARS_DIR="$sb_off"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: SB off -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: SB off kv" "secureboot=0 setup_mode=0 pk=1" "$out"

# --- setup mode ---
setupmode="$tmp/setupmode"
mkdir -p "$setupmode"
mkvar_byte "$setupmode" SecureBoot 1
mkvar_byte "$setupmode" SetupMode 1
mkvar_str "$setupmode" PK "PKPAYLOAD"
ALPINE_FDE_EFIVARS_DIR="$setupmode"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: setup mode still rc 0 (SB on)" "0" "$rc"
assert_eq "fw_sb_state: setup mode reported" "secureboot=1 setup_mode=1 pk=1" "$out"

# --- attrs-only payload counts as absent ---
attrsonly="$tmp/attrsonly"
mkdir -p "$attrsonly"
mkvar_attrsonly "$attrsonly" SecureBoot
mkvar_attrsonly "$attrsonly" PK
ALPINE_FDE_EFIVARS_DIR="$attrsonly"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: attrs-only SecureBoot -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: attrs-only treated as absent" "secureboot=0 setup_mode=1 pk=0" "$out"

# --- efivars dir missing entirely -> documented degraded kv, rc 1 ---
ALPINE_FDE_EFIVARS_DIR="$tmp/no-such-dir"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: missing dir -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: missing dir kv" "secureboot=0 setup_mode=1 pk=0" "$out"

# --- dir present but no variables at all -> same degraded kv ---
empty="$tmp/empty"
mkdir -p "$empty"
# shellcheck disable=SC2034  # consumed by fw_sb_state subshells below
ALPINE_FDE_EFIVARS_DIR="$empty"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: empty dir -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: empty dir kv" "secureboot=0 setup_mode=1 pk=0" "$out"

# --- S-M5 canonical-GUID resolution: KEK/db/dbx + fw_var_sha256 rc semantics ----
# NEW-2: the guard-integrity set is not only the SecureBoot/SetupMode/PK trio.
# KEK is canonical in EFI_GLOBAL_VARIABLE; db/dbx are canonical BOTH there and
# in the EFI_IMAGE_SECURITY_DATABASE_GUID. A vendor-namespace lookalike never
# counts; TWO canonical namespaces at once is ambiguous (die 64) — and
# fw_var_sha256 must propagate that rc 64 instead of collapsing it into rc 1
# "absent", so consumers warn loudly instead of recording a silently-empty
# fingerprint (provision.sh:456 / audit.sh:102 degrade via `|| _fp=''`).
VGUID='11223344-5566-7788-9900-aabbccddeeff'          # vendor-namespace lookalike
DBXGUID='d719b2cb-3d3a-4596-a3bc-dad00e67656f'        # EFI_IMAGE_SECURITY_DATABASE

# fw_var_sha256 (lib/baseline.sh) needs die/log helpers — pull the lib tree in
export ALPINE_FDE_CMD_DIR="$REPO_ROOT/lib/cmd"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/baseline.sh"

mklookalike() { # DIR NAME STRING — vendor-namespace lookalike variable
    printf '\007\000\000\000%s' "$3" >"$1/$2-$VGUID"
}

# (a) canonical + vendor lookalike SecureBoot -> canonical wins
sbc="$tmp/sb-canonical-plus-lookalike"
mkdir -p "$sbc"
mkvar_byte "$sbc" SecureBoot 1
mklookalike "$sbc" SecureBoot 'X'
assert_eq "SecureBoot: canonical wins over vendor lookalike" \
    "$sbc/SecureBoot-$GUID" "$(fw_find_var "$sbc" SecureBoot)"

# (c) lookalike-only SecureBoot (canonical absent) -> treated as absent
sbv="$tmp/sb-lookalike-only"
mkdir -p "$sbv"
mklookalike "$sbv" SecureBoot 'X'
rc=0
out=$(fw_find_var "$sbv" SecureBoot) || rc=$?
assert_rc "SecureBoot: lookalike-only -> absent (rc 1)" 1 "$rc"
assert_eq "SecureBoot: lookalike-only prints nothing" "" "$out"

# (d) KEK: canonical (EFI_GLOBAL_VARIABLE) + vendor lookalike -> canonical wins
# (before NEW-2 KEK fell through to the ambiguity die on the lookalike)
kek="$tmp/kek-canonical-plus-lookalike"
mkdir -p "$kek"
mkvar_str "$kek" KEK 'KEKCANON'
mklookalike "$kek" KEK 'kek-lookalike'
assert_eq "KEK: canonical wins over vendor lookalike" \
    "$kek/KEK-$GUID" "$(fw_find_var "$kek" KEK)"

# (d) db: canonical in EFI_GLOBAL_VARIABLE + vendor lookalike -> canonical wins
dbg="$tmp/db-global-plus-lookalike"
mkdir -p "$dbg"
mkvar_str "$dbg" db 'DBCANON'
mklookalike "$dbg" db 'db-lookalike'
assert_eq "db: EFI_GLOBAL_VARIABLE canonical wins over vendor lookalike" \
    "$dbg/db-$GUID" "$(fw_find_var "$dbg" db)"

# (d) dbx: canonical in EFI_IMAGE_SECURITY_DATABASE + vendor lookalike -> wins
dbxg="$tmp/dbx-imgsec-plus-lookalike"
mkdir -p "$dbxg"
printf '\007\000\000\000%s' 'DBXCANON' >"$dbxg/dbx-$DBXGUID"
mklookalike "$dbxg" dbx 'dbx-lookalike'
assert_eq "dbx: EFI_IMAGE_SECURITY canonical wins over vendor lookalike" \
    "$dbxg/dbx-$DBXGUID" "$(fw_find_var "$dbxg" dbx)"

# (d) dbx: canonical lookup also resolves the EFI_GLOBAL_VARIABLE copy
dbxg2="$tmp/dbx-global"
mkdir -p "$dbxg2"
mkvar_str "$dbxg2" dbx 'DBXGLOBAL'
assert_eq "dbx: EFI_GLOBAL_VARIABLE canonical lookup" \
    "$dbxg2/dbx-$GUID" "$(fw_find_var "$dbxg2" dbx)"

# (d) db: lookalike-only (no canonical copy) -> absent, never the lookalike
dbv="$tmp/db-lookalike-only"
mkdir -p "$dbv"
mklookalike "$dbv" db 'db-lookalike'
rc=0
out=$(fw_find_var "$dbv" db) || rc=$?
assert_rc "db: lookalike-only -> absent (rc 1)" 1 "$rc"

# (b) db/dbx present in BOTH canonical namespaces -> ambiguous, die 64
dbamb="$tmp/db-two-canonical"
mkdir -p "$dbamb"
mkvar_str "$dbamb" db 'DBA'
printf '\007\000\000\000%s' 'DBB' >"$dbamb/db-$DBXGUID"
rc=0
out=$(fw_find_var "$dbamb" db 2>/dev/null) || rc=$?
assert_rc "db: both canonical namespaces -> die 64" 64 "$rc"
assert_eq "db: ambiguity prints nothing on stdout" "" "$out"
dbxamb="$tmp/dbx-two-canonical"
mkdir -p "$dbxamb"
mkvar_str "$dbxamb" dbx 'DBXA'
printf '\007\000\000\000%s' 'DBXB' >"$dbxamb/dbx-$DBXGUID"
rc=0
out=$(fw_find_var "$dbxamb" dbx 2>/dev/null) || rc=$?
assert_rc "dbx: both canonical namespaces -> die 64" 64 "$rc"

# --- fw_var_sha256: absent rc 1, ambiguity rc 64 (NOT collapsed), payload sha --
ALPINE_FDE_EFIVARS_DIR="$dbamb"
rc=0
out=$(fw_var_sha256 PK) || rc=$?
assert_rc "fw_var_sha256: absent variable -> rc 1" 1 "$rc"
rc=0
out=$(fw_var_sha256 db 2>/dev/null) || rc=$?
assert_rc "fw_var_sha256: ambiguity -> rc 64 (not collapsed to 1)" 64 "$rc"
assert_eq "fw_var_sha256: ambiguity prints no fingerprint" "" "$out"
_fvs_err=$(fw_var_sha256 db 2>&1 >/dev/null)
assert_contains "fw_var_sha256: ambiguity warns loudly" "$_fvs_err" \
    "ambiguous EFI variable db"

ALPINE_FDE_EFIVARS_DIR="$kek"
# known payload "KEKCANON" behind the 4-byte attrs header
KEK_SHA=$(printf 'KEKCANON' | sha256sum | cut -d' ' -f1)
assert_eq "fw_var_sha256: sha256 of payload after attrs header" "$KEK_SHA" \
    "$(fw_var_sha256 KEK)"

# --- fw_auth_enroll / fw_osindications_set: pre-existing variable clearing ---
# blocker #25: fw_auth_enroll now builds packets via the efitools pipeline —
# this leg requires cert-to-efi-sig-list/sign-efi-sig-list on the host (the
# canary/e2e image and the install ISO ship them); skipped loudly elsewhere.
# Real-server blocker (bcache-multi live run, SetupMode==1 verified by the
# function's own gate): `fw_var_write db` -> write error: Invalid argument.
# The write shape was correct; the vendor db (and KEK/PK) variable still
# existed after the vendor PK was cleared, and efivarfs/firmware refuse a
# SetVariable that would CHANGE an existing variable's attributes (vendor db =
# plain NV+BS+RT; ours adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS) -> EINVAL.
# The fix: fw_auth_enroll removes any pre-existing variable of the same
# name/GUID immediately before each authenticated write (SetupMode==1 is a
# fail-closed gate above, and db -> KEK -> PK order protects the half-enrolled
# trust root). CI never hits this (offline virt-fw-vars on a fresh OVMF_VARS);
# the seam's writes are plain file writes, so these pins observe the rm
# contract through the info/warn lines and the re-created variable's attrs
# header, plus the enriched die message's manual-enrollment remedy.

# efitools stubs (blocker #25): fw_auth_enroll shells out to cert-to-efi-sig-list
# + sign-efi-sig-list — this seam tests the ENROLL choreography (rm-first,
# chattr -i, attrs header), not the packet bytes, so canned stubs suffice.
mkdir -p "$tmp/stub-bin"
cat >"$tmp/stub-bin/cert-to-efi-sig-list" <<'STUB'
#!/bin/sh
OUT=""
for a in "$@"; do OUT=$a; done
printf 'STUB-ESL' > "$OUT"
STUB
chmod +x "$tmp/stub-bin/cert-to-efi-sig-list"
cat >"$tmp/stub-bin/sign-efi-sig-list" <<'STUB'
#!/bin/sh
OUT=""
prev=""
for a in "$@"; do
    [ "$prev" = "-k" ] && { printf 'STUB-AUTH-PACKET-BYTES' > "$a"; }
    prev=$a
    OUT=$a
done
exit 0
STUB
chmod +x "$tmp/stub-bin/sign-efi-sig-list"
cat >"$tmp/stub-bin/efi-updatevar" <<'STUB'
#!/bin/sh
# efi-updatevar stub (blocker #26 final): models the kernel result —
# -f AUTH VARNAME writes attrs(0x00010007) + AUTH body into the efivars dir
# the seam exports (well-known per-var GUIDs: db=d719b2cb…, KEK/PK=8be4df61…)
auth=$2
name=$3
dir=${ALPINE_FDE_SEAM_EFIVARS:-}
[ -n "$dir" ] || exit 0
case $name in
    db) guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f ;;
    *) guid=8be4df61-93ca-11d2-aa0d-00e098032b8c ;;
esac
{ printf '\007\000\001\000'; cat "$auth"; } > "$dir/$name-$guid"
exit 0
STUB
chmod +x "$tmp/stub-bin/efi-updatevar"
export PATH="$tmp/stub-bin:$PATH"

# mkauth FILE NAME GUID PAYLOAD — minimal EFI_VARIABLE_AUTHENTICATION_2 packet
# (EFI_TIME 16 zero bytes + EFI_VARIABLE_DATA{GUID, DataSize u32le,
# UnicodeName UTF-16LE} + payload) that clears fw_var_write's identity
# preflight, so fw_auth_enroll proceeds to the actual write in the seam.
mkauth() {
    _ma_file=$1
    _ma_name=$2
    _ma_guid=$3
    _ma_payload=$4
    _ma_size=$(( ${#_ma_name} * 2 + ${#_ma_payload} ))
    _ma_hex=$(printf '%032x' 0 | sed 's/^../ea07/')"$(fw_guid_le_hex "$_ma_guid")"  # EFI_TIME 2026 (year LE ea07)
    _ma_hex=$_ma_hex$(printf '%08x' "$_ma_size" | fold -w2 | tac | tr -d '\n')
    _ma_hex=$_ma_hex$(fw_name_utf16_hex "$_ma_name")
    _ma_hex=$_ma_hex$(printf '%s' "$_ma_payload" | od -An -vtx1 | tr -d ' \n')
    _ma_out=''
    for _ma_b in $(printf '%s\n' "$_ma_hex" | fold -w2); do
        _ma_out=$_ma_out"\\$(printf '%03o' "0x$_ma_b")"
    done
    # shellcheck disable=SC2059  # the octal escapes ARE the packet bytes
    printf "$_ma_out" >"$_ma_file"
}

FAKEYS="$tmp/fa-keys"
mkdir -p "$FAKEYS"
mkauth "$FAKEYS/db.auth" db "$DBXGUID" 'DB1'
mkauth "$FAKEYS/kek.auth" KEK "$GUID" 'KEK1'
mkauth "$FAKEYS/pk.auth" PK "$GUID" 'PK1'
# the operator's OWN certificates — the exact inputs the .auth packets were
# built from (REAL-SERVER 2026-09-28: staged as db.cer/KEK.cer/PK.cer because
# the firmware setup UI imports X.509 certs, not .auth packets). Formats as
# stored in a real keydir: release.crt is PEM, kek/pk .cert.der are DER.
# release.crt must be a REAL certificate (2026-09-29): the staging converts
# it PEM -> DER with openssl x509 (Dell .cer import is DER-only), so the
# db.cer pin compares against a live conversion of this exact cert.
openssl req -x509 -newkey rsa:2048 -keyout "$tmp/release.key" \
    -out "$FAKEYS/release.crt" -days 30 -nodes \
    -subj "/CN=alpine-fde-test-release" 2>/dev/null
openssl x509 -in "$FAKEYS/release.crt" -outform der >"$tmp/release.der"
printf 'KEK-CERT-DER' >"$FAKEYS/kek.cert.der"
printf 'PK-CERT-DER' >"$FAKEYS/pk.cert.der"
# the sbctl-flow store swap stages these PEM certs (the keydir contract:
# prov_keygen ships PEM + DER for every cert)
printf 'KEK-CERT-PEM' >"$FAKEYS/kek.cert.pem"
printf 'PK-CERT-PEM' >"$FAKEYS/pk.cert.pem"
# the ESP fallback stages the .auth packets AND the .esl lists (KeyTool.efi
# "enroll from file" consumes the signed .esl form)
printf 'DB-ESL' >"$FAKEYS/db.esl"
printf 'KEK-ESL' >"$FAKEYS/kek.esl"
printf 'PK-ESL' >"$FAKEYS/pk.esl"
# dbx variant: dbx.auth/dbx.esl are staged ONLY when present in KEYDIR
FAKEYS_DBX="$tmp/fa-keys-dbx"
cp -r "$FAKEYS" "$FAKEYS_DBX"
printf 'DBX-AUTH' >"$FAKEYS_DBX/dbx.auth"
printf 'DBX-ESL' >"$FAKEYS_DBX/dbx.esl"

# (a) THE SBCTL FLOW — the success path (R640-proven 2026-10-06): the store
# is created (if fresh), reset clears the stale variables, the cert swap
# stages OUR certs into the store, enroll-keys lands PK/KEK/db, SetupMode
# flips to 0, and the SUCCESS path stages NOTHING to the ESP.
fa="$tmp/enroll-sbctl-ok"
mkdir -p "$fa"
mkvar_byte "$fa" SetupMode 1
printf '\007\000\000\000STALEDB' >"$fa/db-$DBXGUID"
printf '\007\000\000\000STALEKEK' >"$fa/KEK-$GUID"
printf '\007\000\000\000STALEPK' >"$fa/PK-$GUID"
STORE="$tmp/sbctl-store"; rm -rf "$STORE"
SBLOG="$tmp/sbctl.log"; : >"$SBLOG"
cat >"$tmp/sbctl-stub" <<STUB
#!/bin/sh
echo "\$1" >>"$SBLOG"
case "\$1" in
  reset) rm -f "$fa"/PK-* "$fa"/KEK-* "$fa"/db-* "$fa"/dbx-* ;;
  create-keys)
    mkdir -p "$STORE/keys/db" "$STORE/keys/KEK" "$STORE/keys/PK"
    printf 'SBCTL-DB-PEM' >"$STORE/keys/db/db.pem"
    printf 'SBCTL-KEY' >"$STORE/keys/db/db.key"
    printf 'SBCTL-KEK-PEM' >"$STORE/keys/KEK/KEK.pem"
    printf 'SBCTL-KEY' >"$STORE/keys/KEK/KEK.key"
    printf 'SBCTL-PK-PEM' >"$STORE/keys/PK/PK.pem"
    printf 'SBCTL-KEY' >"$STORE/keys/PK/PK.key" ;;
  enroll-keys)
    printf '\007\000\000\000NEWPK' >"$fa/PK-$GUID"
    printf '\007\000\000\000NEWKEK' >"$fa/KEK-$GUID"
    printf '\007\000\000\000NEWDB' >"$fa/db-$DBXGUID"
    mkvar_byte "$fa" SetupMode 0 ;;
esac
STUB
chmod +x "$tmp/sbctl-stub"
rm -rf "$tmp/esp-a"
rc=0
out=$(ALPINE_FDE_SEAM_EFIVARS="$fa" ALPINE_FDE_SBCTL="$tmp/sbctl-stub" \
    ALPINE_FDE_SBCTL_STORE="$STORE" fw_auth_enroll "$fa" "$FAKEYS" "$tmp/esp-a" 2>&1) || rc=$?
assert_rc "enroll: the sbctl flow -> rc 0" 0 "$rc"
assert_eq "enroll: the invocation order is create-keys -> reset -> enroll-keys" "create-keys
reset
enroll-keys" "$(cat "$SBLOG")"
assert_eq "enroll: the store db.pem is the release cert (the swap)" \
    "$(cat "$FAKEYS/release.crt")" "$(cat "$STORE/keys/db/db.pem")"
assert_eq "enroll: the store KEK.pem is kek.cert.pem (the swap)" \
    "$(cat "$FAKEYS/kek.cert.pem")" "$(cat "$STORE/keys/KEK/KEK.pem")"
assert_eq "enroll: the store PK.pem is pk.cert.pem (the swap)" \
    "$(cat "$FAKEYS/pk.cert.pem")" "$(cat "$STORE/keys/PK/PK.pem")"
assert_eq "enroll: db carries the sbctl-enrolled payload (the stale one is gone)" \
    "$(printf '\007\000\000\000NEWDB')" "$(cat "$fa/db-$DBXGUID")"
assert_eq "enroll: SetupMode flipped to 0 (user mode)" "0" \
    "$(tail -c 1 "$fa/SetupMode-$GUID" | od -An -tu1 | tr -d ' ')"
assert_eq "enroll: the SUCCESS path stages NOTHING to the ESP" "0" \
    "$([ -e "$tmp/esp-a/alpine-fde-keys" ] && echo 1 || echo 0)"
assert_contains "enroll: the completion info names the chain" "$out" \
    "enrollment complete"

# (b) sbctl reset failure -> stage-and-die (the certs land on the ESP for the
# UI repair; the die carries the UI-clear remedy; create-keys ran first)
fb="$tmp/enroll-reset-fails"
mkdir -p "$fb"
mkvar_byte "$fb" SetupMode 1
printf '\007\000\000\000OLDB' >"$fb/db-$DBXGUID"
STORE2="$tmp/sbctl-store2"; rm -rf "$STORE2"
SBLOG2="$tmp/sbctl2.log"; : >"$SBLOG2"
rm -rf "$tmp/esp-b"
cat >"$tmp/sbctl-stub-fail" <<STUB
#!/bin/sh
echo "\$1" >>"$SBLOG2"
[ "\$1" = reset ] && exit 1
[ "\$1" = create-keys ] && { mkdir -p "$STORE2/keys/db"; printf 'X' >"$STORE2/keys/db/db.pem"; }
exit 0
STUB
chmod +x "$tmp/sbctl-stub-fail"
rc=0
out=$(ALPINE_FDE_SEAM_EFIVARS="$fb" ALPINE_FDE_SBCTL="$tmp/sbctl-stub-fail" \
    ALPINE_FDE_SBCTL_STORE="$STORE2" fw_auth_enroll "$fb" "$FAKEYS" "$tmp/esp-b" 2>&1) || rc=$?
assert_rc "enroll: reset failure -> fail-closed 64" 64 "$rc"
assert_contains "enroll: the reset die names the clear-PK remedy" "$out" \
    "sbctl reset failed — the platform keys could not be cleared"
assert_eq "enroll: create-keys ran before reset (the store precedes the clear)" "create-keys
reset" "$(cat "$SBLOG2")"
assert_eq "enroll: the failure staged the repair kit (db.cer on the ESP)" "1" \
    "$([ -f "$tmp/esp-b/alpine-fde-keys/db.cer" ] && echo 1 || echo 0)"
assert_contains "enroll: the fallback warn fires on the failure path" "$out" \
    "firmware enrollment incomplete — first boot stays guarded"

# (c) enroll-keys failure -> stage-and-die (the reset succeeded; the land failed)
fc="$tmp/enroll-land-fails"
mkdir -p "$fc"
mkvar_byte "$fc" SetupMode 1
STORE3="$tmp/sbctl-store3"; rm -rf "$STORE3"
rm -rf "$tmp/esp-c"
cat >"$tmp/sbctl-stub-land" <<STUB
#!/bin/sh
[ "\$1" = reset ] && rm -f "$fc"/PK-* "$fc"/KEK-* "$fc"/db-* "$fc"/dbx-*
[ "\$1" = create-keys ] && { mkdir -p "$STORE3/keys/db"; printf 'X' >"$STORE3/keys/db/db.pem"; }
[ "\$1" = enroll-keys ] && exit 1
exit 0
STUB
chmod +x "$tmp/sbctl-stub-land"
rc=0
out=$(ALPINE_FDE_SEAM_EFIVARS="$fc" ALPINE_FDE_SBCTL="$tmp/sbctl-stub-land" \
    ALPINE_FDE_SBCTL_STORE="$STORE3" fw_auth_enroll "$fc" "$FAKEYS" "$tmp/esp-c" 2>&1) || rc=$?
assert_rc "enroll: enroll-keys failure -> fail-closed 64" 64 "$rc"
assert_contains "enroll: the land die names sbctl enroll-keys" "$out" \
    "sbctl enroll-keys failed — the keys did not land"
assert_eq "enroll: the land failure staged the repair kit" "1" \
    "$([ -f "$tmp/esp-c/alpine-fde-keys/db.cer" ] && echo 1 || echo 0)"

# (d) sbctl absent -> fail-closed with the install remedy (the emitted chain
# runs require_pkgs sbctl:sbctl; the function guards independently)
fd="$tmp/enroll-nosbctl"
mkdir -p "$fd"
mkvar_byte "$fd" SetupMode 1
rc=0
out=$(ALPINE_FDE_SEAM_EFIVARS="$fd" ALPINE_FDE_SBCTL=/nonexistent/sbctl \
    fw_auth_enroll "$fd" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: sbctl absent -> fail-closed 64" 64 "$rc"
assert_contains "enroll: the sbctl-absent die names the engine requirement" "$out" \
    "sbctl is not installed — the enrollment engine requires it"

# (e) fw_var_write split (blocker #26 final): the write is ALWAYS efi-updatevar's;
# on a read-only efivars dir the try returns rc 1 (non-die), the wrapper dies 64.
fwro="$tmp/varwrite-ro"
mkdir -p "$fwro" "$tmp/stub-ro2"
printf '#!/bin/sh\nexit 1\n' >"$tmp/stub-ro2/efi-updatevar"
chmod +x "$tmp/stub-ro2/efi-updatevar"
chmod 555 "$fwro"
# the failing efi-updatevar stub models the firmware refusing the write
rc=0
out=$(PATH="$tmp/stub-ro2:$PATH" fw_var_write_try "$fwro" db "$DBXGUID" "$FAKEYS/db.auth" 2>&1) || rc=$?
assert_rc "fw_var_write_try: refused write -> rc 1, no die" 1 "$rc"
assert_eq "fw_var_write_try: nothing written to the read-only dir" "0" \
    "$([ -e "$fwro/db-$DBXGUID" ] && echo 1 || echo 0)"
rc=0
out=$(PATH="$tmp/stub-ro2:$PATH" fw_var_write "$fwro" db "$DBXGUID" "$FAKEYS/db.auth" 2>&1) || rc=$?
assert_rc "fw_var_write wrapper: refused write -> fail-closed 64" 64 "$rc"
assert_contains "fw_var_write wrapper: die names the variable path" "$out" \
    "cannot write $fwro/db-$DBXGUID"
assert_contains "fw_var_write wrapper: die keeps the manual-enrollment remedy" "$out" \
    "FAT USB stick"
assert_contains "fw_var_write wrapper: die names KeyTool.efi" "$out" \
    "KeyTool.efi"

# (f) REFUSED mode (user directive, 2026-10-06, real Dell PowerEdge R640):
# SetupMode==0 WITH a platform PK (factory or custom) — NO NVRAM writes AT
# ALL; the enroll stages the import-ready .cer set (the 0ec17a1 staging,
# reused) with the ENROLLMENT-REFUSED note prepended to README.txt, and DIES
# 64 — the install must not half-finish behind a manual UI step, and an
# existing platform key is untouchable from the OS (no private half). The
# remediation is deterministic: clear the PK (firmware setup UI "Clear All
# Secure Boot keys", or iDRAC Redfish SecureBoot.ResetKeys DeletePK —
# verified on this R640) so SetupMode becomes 1, then re-run: completed steps
# skip via crash resume and the enroll goes fully automatic. (Retires the
# 2026-09-28 DEFERRED-ENROLLMENT mode; the marker seam is no longer recorded.)
ff="$tmp/enroll-refused"
mkdir -p "$ff"
mkvar_byte "$ff" SetupMode 0
mkvar_str "$ff" PK 'FACTORY-PK-PAYLOAD'
rm -rf "$tmp/esp-f"
FFMARKER="$tmp/deferred-marker"
rm -f "$FFMARKER"
rc=0
out=$(ALPINE_FDE_SEAM_EFIVARS="$ff" ALPINE_FDE_ENROLL_DEFERRED_MARKER="$FFMARKER" \
    fw_auth_enroll "$ff" "$FAKEYS" "$tmp/esp-f" 2>&1) || rc=$?
assert_rc "enroll refused: platform PK present (SetupMode 0) -> fail-closed 64" 64 "$rc"
assert_eq "enroll refused: ZERO write attempts against the efivars seam" "0" \
    "$(printf '%s\n' "$out" | grep -c 'cannot write')"
assert_eq "enroll refused: the efivars seam gained NO variable (db untouched)" "0" \
    "$([ -e "$ff/db-$DBXGUID" ] && echo 1 || echo 0)"
assert_contains "enroll refused: die names the refused state" "$out" \
    "SetupMode is 0 with a platform key enrolled — refusing to continue"
assert_contains "enroll refused: die gives the clear-PK remediation (UI + iDRAC)" "$out" \
    "Clear All Secure Boot keys"
assert_contains "enroll refused: die notes crash-resume for the re-run" "$out" \
    "completed install steps skip via crash resume"
assert_contains "enroll refused: fallback summary names the platform-PK reason" "$out" \
    "a platform key is already enrolled (factory or custom) — NO NVRAM writes were attempted"
assert_contains "enroll refused: the guarded-first-boot warn still fires" "$out" \
    "firmware enrollment incomplete — first boot stays guarded until the keys are imported"
# the staged set is byte-identical to the retired deferred-mode staging (0ec17a1 reuse)
for _f_f in db.auth kek.auth pk.auth db.cer KEK.cer PK.cer README.txt '!import_all_auth_files'; do
    assert_eq "enroll refused: staged $_f_f" "1" \
        "$([ -f "$tmp/esp-f/alpine-fde-keys/$_f_f" ] && echo 1 || echo 0)"
done
assert_eq "enroll refused: db.cer is the DER encoding of release.crt (not a PEM copy)" \
    "$(cat "$tmp/release.der")" "$(cat "$tmp/esp-f/alpine-fde-keys/db.cer")"
_f_readme=$(cat "$tmp/esp-f/alpine-fde-keys/README.txt")
assert_contains "enroll refused: README leads with the REFUSED note" "$_f_readme" \
    "ENROLLMENT REFUSED"
assert_contains "enroll refused: README carries the clear-PK remediation" "$_f_readme" \
    "Setup Mode becomes 1"
assert_eq "enroll refused: the deferred marker seam is NO LONGER recorded (mode retired)" "0" \
    "$([ -f "$FFMARKER" ] && echo 1 || echo 0)"

# (g) SetupMode==0 WITHOUT a platform PK — a state no real firmware reports
# (user mode with no PK) — stays FAIL-CLOSED 64 (the gate below the deferred
# branch must not swallow genuinely unexpected states).
fg="$tmp/enroll-usermode-nopk"
mkdir -p "$fg"
mkvar_byte "$fg" SetupMode 0
rc=0
out=$(fw_auth_enroll "$fg" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: SetupMode=0 with NO platform PK -> fail-closed 64" 64 "$rc"
assert_contains "enroll: the unexpected-state die names the observed SetupMode" "$out" \
    "SetupMode is 0"
assert_eq "enroll: the unexpected-state die enrolled nothing" "0" \
    "$([ -e "$fg/db-$DBXGUID" ] && echo 1 || echo 0)"

# same hazard, decided call for the other direct writer: fw_osindications_set
# removes a pre-existing OsIndications before rewriting (same-attrs overwrite
# is legal, but rm-first is harmless and keeps the write shape uniform)
fo="$tmp/osind-preexisting"
mkdir -p "$fo"
printf '\007\000\000\000\001\000\000\000\000\000\000\000' >"$fo/OsIndications-$GUID"
rc=0
out=$(fw_osindications_set "$fo" 2>&1) || rc=$?
assert_rc "osindications: pre-existing var -> rc 0" 0 "$rc"
assert_contains "osindications: pre-existing var removed first" "$out" \
    "removing pre-existing OsIndications"
assert_eq "osindications: rewritten attrs 7 + payload u64le 1" \
    "070000000100000000000000" \
    "$(od -An -vtx1 <"$fo/OsIndications-$GUID" | tr -d ' \n')"
fo2="$tmp/osind-clean"
mkdir -p "$fo2"
rc=0
out=$(fw_osindications_set "$fo2" 2>&1) || rc=$?
assert_rc "osindications: clean path -> rc 0" 0 "$rc"
assert_eq "osindications: clean path emits no rm info noise" "0" \
    "$(printf '%s\n' "$out" | grep -c 'removing pre-existing')"

: # no finish in the lib-sourced context
