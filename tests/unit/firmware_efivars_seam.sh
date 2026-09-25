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
    _ma_hex=$(printf '%032d' 0)"$(fw_guid_le_hex "$_ma_guid")"
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

# (a) pre-existing vendor db/KEK/PK are removed before each authenticated write
fa="$tmp/enroll-preexisting"
mkdir -p "$fa"
mkvar_byte "$fa" SetupMode 1
# vendor-shaped variables: plain attrs 0x7, real firmware keeps db/KEK after
# the vendor PK is cleared (Setup Mode permits removing them)
printf '\007\000\000\000VENDORDB' >"$fa/db-$DBXGUID"
printf '\007\000\000\000VENDORKEK' >"$fa/KEK-$GUID"
printf '\007\000\000\000VENDORPK' >"$fa/PK-$GUID"
rc=0
out=$(fw_auth_enroll "$fa" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: pre-existing vendor vars -> rc 0" 0 "$rc"
assert_contains "enroll: info line for pre-existing vendor db" "$out" \
    "removing pre-existing vendor db"
assert_contains "enroll: info line for pre-existing vendor KEK" "$out" \
    "removing pre-existing vendor KEK"
assert_contains "enroll: info line for pre-existing vendor PK" "$out" \
    "removing pre-existing vendor PK"
assert_eq "enroll: db re-created with auth attrs prefix" "07000001" \
    "$(head -c 4 "$fa/db-$DBXGUID" | od -An -vtx1 | tr -d ' \n')"
assert_eq "enroll: KEK re-created with auth attrs prefix" "07000001" \
    "$(head -c 4 "$fa/KEK-$GUID" | od -An -vtx1 | tr -d ' \n')"
assert_eq "enroll: PK re-created with auth attrs prefix" "07000001" \
    "$(head -c 4 "$fa/PK-$GUID" | od -An -vtx1 | tr -d ' \n')"

# (b) rm failure: warn (non-fatal), write still attempted, die names the
# manual-USB remedy (fail-closed preserved, real error reported)
fb="$tmp/enroll-rm-fails"
mkdir -p "$fb"
mkvar_byte "$fb" SetupMode 1
# a DIRECTORY at the variable path: rm -f fails (EISDIR) and the subsequent
# write redirection fails too — models an unremovable stubborn variable
mkdir "$fb/db-$DBXGUID"
rc=0
out=$(fw_auth_enroll "$fb" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: rm failure -> still fail-closed 64" 64 "$rc"
assert_contains "enroll: rm failure warns (non-fatal)" "$out" \
    "could not remove pre-existing vendor db"
assert_contains "enroll: write still attempted after rm failure" "$out" \
    "cannot write"
assert_contains "enroll: die names the manual USB stick remedy" "$out" \
    "FAT USB stick"
assert_contains "enroll: die names KeyTool.efi / firmware setup UI" "$out" \
    "KeyTool.efi"

# (c) absent variables -> no rm info noise (clean path unchanged)
fc="$tmp/enroll-clean"
mkdir -p "$fc"
mkvar_byte "$fc" SetupMode 1
rc=0
out=$(fw_auth_enroll "$fc" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: clean path -> rc 0" 0 "$rc"
assert_eq "enroll: clean path emits no rm info noise" "0" \
    "$(printf '%s\n' "$out" | grep -c 'removing pre-existing')"

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

finish
