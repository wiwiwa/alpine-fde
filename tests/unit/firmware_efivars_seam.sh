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
assert_eq "enroll: db re-created with auth attrs prefix" "07000100" \
    "$(head -c 4 "$fa/db-$DBXGUID" | od -An -vtx1 | tr -d ' \n')"
assert_eq "enroll: KEK re-created with auth attrs prefix" "07000100" \
    "$(head -c 4 "$fa/KEK-$GUID" | od -An -vtx1 | tr -d ' \n')"
assert_eq "enroll: PK re-created with auth attrs prefix" "07000100" \
    "$(head -c 4 "$fa/PK-$GUID" | od -An -vtx1 | tr -d ' \n')"

# (b) write refusal -> NON-FATAL ESP fallback (queue 26 ext, user directive:
# "write .esl to EFI partition, if write to efivars failed, and show
# instruction to import the file into uefi bios"): the rm failure warns, the
# refused db write warns WITHOUT dying, the KEK and PK writes are STILL
# attempted (the same firmware will refuse them too — harmless and
# diagnostic), all key material is staged under <ESP>/alpine-fde-keys, the
# numbered manual-import instructions are printed, and the install CONTINUES.
fb="$tmp/enroll-rm-fails"
mkdir -p "$fb"
mkvar_byte "$fb" SetupMode 1
# a DIRECTORY at the variable path: rm -f fails (EISDIR) and the subsequent
# write redirection fails too — models an unremovable stubborn variable
mkdir "$fb/db-$DBXGUID"
rm -rf "$tmp/esp-b"
rc=0
out=$(fw_auth_enroll "$fb" "$FAKEYS" "$tmp/esp-b" 2>&1) || rc=$?
assert_rc "enroll: write refusal -> ESP fallback, install continues (rc 0)" 0 "$rc"
assert_contains "enroll: rm failure warns (non-fatal)" "$out" \
    "could not remove pre-existing vendor db"
assert_contains "enroll: refused db write warns (non-fatal, no die)" "$out" \
    "cannot write $fb/db-$DBXGUID"
assert_contains "enroll: KEK write still attempted after the db refusal" "$out" \
    "enrolled KEK"
assert_contains "enroll: PK write still attempted after the db refusal" "$out" \
    "enrolled PK"
for _b_f in db.auth kek.auth pk.auth db.esl kek.esl pk.esl; do
    assert_eq "enroll: fallback staged $_b_f under <esp>/alpine-fde-keys" "1" \
        "$([ -f "$tmp/esp-b/alpine-fde-keys/$_b_f" ] && echo 1 || echo 0)"
done
assert_contains "enroll: fallback names the staging directory" "$out" \
    "$tmp/esp-b/alpine-fde-keys"
assert_contains "enroll: fallback per-file cp info line" "$out" \
    "staged db.auth"
assert_contains "enroll: instruction 1 — copy to a FAT USB stick (or use the ESP files)" \
    "$out" "1. copy the alpine-fde-keys directory to a FAT USB stick"
assert_contains "enroll: instruction 2 — reboot into firmware setup" "$out" \
    "2. reboot into the firmware setup"
assert_contains "enroll: instruction 3 — db.auth, kek.auth, pk.auth in that order" "$out" \
    "3. under Secure Boot key management import, in this order: db.auth"
assert_contains "enroll: instruction 3 — .esl via KeyTool.efi" "$out" \
    "KeyTool.efi"
assert_contains "enroll: instruction 4 — administrator password" "$out" \
    "4. while in firmware setup, set an administrator"
assert_contains "enroll: instruction 5 — crash resume + guarded first boot" "$out" \
    "5. boot the installed system"
assert_contains "enroll: instruction 5 names the ADR-20 guarded first boot" "$out" \
    "ADR-20"
assert_contains "enroll: final WARN — first boot stays guarded" "$out" \
    "firmware enrollment incomplete — first boot stays guarded until the keys are imported"
# the fallback is NOT the old fail-closed die: no die text may leak through
assert_eq "enroll: fallback path does not die" "0" \
    "$(printf '%s\n' "$out" | grep -c 'refusing to program')"

# (c) absent variables -> no rm info noise, NO fallback noise (clean path
# unchanged; 2-arg call also pins the ESP_DIR default for old callers)
fc="$tmp/enroll-clean"
mkdir -p "$fc"
mkvar_byte "$fc" SetupMode 1
rc=0
out=$(fw_auth_enroll "$fc" "$FAKEYS" 2>&1) || rc=$?
assert_rc "enroll: clean path -> rc 0" 0 "$rc"
assert_eq "enroll: clean path emits no rm info noise" "0" \
    "$(printf '%s\n' "$out" | grep -c 'removing pre-existing')"
assert_eq "enroll: clean path emits ZERO fallback noise (no staging dir named)" "0" \
    "$(printf '%s\n' "$out" | grep -c 'alpine-fde-keys')"
assert_eq "enroll: clean path prints no manual instructions" "0" \
    "$(printf '%s\n' "$out" | grep -c 'firmware enrollment incomplete')"

# (d) failure injection: read-only efivars dir at write time -> ALL THREE
# writes are attempted and refused (db first — the db failure does NOT stop
# the KEK/PK attempts, same firmware refuses them identically; attempting is
# harmless and diagnostic), then the fallback stages everything (including
# the dbx pair when present) and the install continues rc 0
fd="$tmp/enroll-readonly"
mkdir -p "$fd"
mkvar_byte "$fd" SetupMode 1
chmod 555 "$fd"
rm -rf "$tmp/esp-d"
rc=0
out=$(fw_auth_enroll "$fd" "$FAKEYS_DBX" "$tmp/esp-d" 2>&1) || rc=$?
chmod 755 "$fd"
assert_rc "enroll: read-only efivars -> fallback, install continues (rc 0)" 0 "$rc"
assert_eq "enroll: ALL THREE write attempts made and refused" "3" \
    "$(printf '%s\n' "$out" | grep -c 'cannot write')"
assert_contains "enroll: db refusal warned first" "$out" \
    "cannot write $fd/db-$DBXGUID"
assert_contains "enroll: KEK refusal warned" "$out" \
    "cannot write $fd/KEK-$GUID"
assert_contains "enroll: PK refusal warned" "$out" \
    "cannot write $fd/PK-$GUID"
for _d_f in db.auth kek.auth pk.auth db.esl kek.esl pk.esl dbx.auth dbx.esl; do
    assert_eq "enroll: fallback staged $_d_f (incl. dbx pair when present)" "1" \
        "$([ -f "$tmp/esp-d/alpine-fde-keys/$_d_f" ] && echo 1 || echo 0)"
done
assert_eq "enroll: nothing was written to the read-only efivars dir" "0" \
    "$([ -e "$fd/db-$DBXGUID" ] && echo 1 || echo 0)"
assert_contains "enroll: numbered instructions present after total refusal" "$out" \
    "1. copy the alpine-fde-keys directory to a FAT USB stick"
assert_contains "enroll: final WARN after total refusal" "$out" \
    "firmware enrollment incomplete — first boot stays guarded until the keys are imported"

# (e) fw_var_write split: the TRY form returns rc 1 on a refused write (no
# die — the identity preflight still dies), the wrapper keeps the die.
fwro="$tmp/varwrite-ro"
mkdir -p "$fwro"
chmod 555 "$fwro"
rc=0
out=$(fw_var_write_try "$fwro" db "$DBXGUID" "$FAKEYS/db.auth" 2>&1) || rc=$?
assert_rc "fw_var_write_try: refused write -> rc 1, no die" 1 "$rc"
assert_eq "fw_var_write_try: nothing written to the read-only dir" "0" \
    "$([ -e "$fwro/db-$DBXGUID" ] && echo 1 || echo 0)"
rc=0
out=$(fw_var_write "$fwro" db "$DBXGUID" "$FAKEYS/db.auth" 2>&1) || rc=$?
assert_rc "fw_var_write wrapper: refused write -> fail-closed 64" 64 "$rc"
assert_contains "fw_var_write wrapper: die names the variable path" "$out" \
    "cannot write $fwro/db-$DBXGUID"
assert_contains "fw_var_write wrapper: die keeps the manual-enrollment remedy" "$out" \
    "FAT USB stick"
assert_contains "fw_var_write wrapper: die names KeyTool.efi" "$out" \
    "KeyTool.efi"

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
