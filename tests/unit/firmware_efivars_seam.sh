#!/bin/sh
# firmware_efivars_seam.sh — unit tests for lib/firmware.sh with an injected
# efivars directory (DEBIAN_FDE_EFIVARS_DIR). No real firmware or TPM required.

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
    "$(DEBIAN_FDE_EFIVARS_DIR='' fw_efivars_dir)"
assert_eq "fw_efivars_dir DEBIAN_FDE_EFIVARS_DIR override" "/x/efivars" \
    "$(DEBIAN_FDE_EFIVARS_DIR=/x/efivars fw_efivars_dir)"

# --- secure state: SB on, not in setup mode, PK set ---
secure="$tmp/secure"
mkdir -p "$secure"
mkvar_byte "$secure" SecureBoot 1
mkvar_byte "$secure" SetupMode 0
mkvar_str "$secure" PK "PKPAYLOAD"
DEBIAN_FDE_EFIVARS_DIR="$secure"
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
DEBIAN_FDE_EFIVARS_DIR="$sb_off"
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
DEBIAN_FDE_EFIVARS_DIR="$setupmode"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: setup mode still rc 0 (SB on)" "0" "$rc"
assert_eq "fw_sb_state: setup mode reported" "secureboot=1 setup_mode=1 pk=1" "$out"

# --- attrs-only payload counts as absent ---
attrsonly="$tmp/attrsonly"
mkdir -p "$attrsonly"
mkvar_attrsonly "$attrsonly" SecureBoot
mkvar_attrsonly "$attrsonly" PK
DEBIAN_FDE_EFIVARS_DIR="$attrsonly"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: attrs-only SecureBoot -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: attrs-only treated as absent" "secureboot=0 setup_mode=1 pk=0" "$out"

# --- efivars dir missing entirely -> documented degraded kv, rc 1 ---
DEBIAN_FDE_EFIVARS_DIR="$tmp/no-such-dir"
rc=0
out=$(fw_sb_state) || rc=$?
assert_rc "fw_sb_state: missing dir -> rc 1" "1" "$rc"
assert_eq "fw_sb_state: missing dir kv" "secureboot=0 setup_mode=1 pk=0" "$out"

# --- dir present but no variables at all -> same degraded kv ---
empty="$tmp/empty"
mkdir -p "$empty"
# shellcheck disable=SC2034  # consumed by fw_sb_state subshells below
DEBIAN_FDE_EFIVARS_DIR="$empty"
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
export DEBIAN_FDE_CMD_DIR="$REPO_ROOT/lib/cmd"
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
DEBIAN_FDE_EFIVARS_DIR="$dbamb"
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

DEBIAN_FDE_EFIVARS_DIR="$kek"
# known payload "KEKCANON" behind the 4-byte attrs header
KEK_SHA=$(printf 'KEKCANON' | sha256sum | cut -d' ' -f1)
assert_eq "fw_var_sha256: sha256 of payload after attrs header" "$KEK_SHA" \
    "$(fw_var_sha256 KEK)"

finish
