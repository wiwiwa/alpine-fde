#!/usr/bin/env bash
# tests/unit/baseline_schema.sh — baseline.json v1 (lib/baseline.sh): write,
# read, validate, finalize (pending→final), surgical field updates; validation
# rejects unknown schema_version, missing keys, malformed pcr values.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

T=$(mktemp -d /tmp/debian-fde-baseline-schema.XXXXXX)
F=$T/baseline.json
HEX_A=$(printf 'a%.0s' {1..64})
HEX_B=$(printf 'b%.0s' {1..64})

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

# --- write + validate a pending baseline -------------------------------------
BL_PCR0="$HEX_A"
BL_PCR1='pending'
BL_PCR2="$HEX_B"
BL_PCR3='pending'
BL_PCR7='pending'
BL_SB_SECURE_BOOT=1
baseline_write "$F"
assert_file_exists "baseline_write creates the file" "$F"
assert_rc "pending baseline validates" 0 baseline_validate "$F"
assert_rc "is_pending on pending baseline" 0 baseline_is_pending "$F"
assert_rc "is_final false on pending baseline" 1 baseline_is_final "$F"
assert_eq "baseline_write pins 0600 regardless of ambient umask (I-2)" "600" "$(stat -c '%a' "$F")"

# --- reader -------------------------------------------------------------------
assert_eq "schema_version read" "1" "$(baseline_get "$F" schema_version)"
assert_eq "pcr0 read" "$HEX_A" "$(baseline_get "$F" pcr0)"
assert_eq "expected_pcr7 read" "pending" "$(baseline_get "$F" expected_pcr7)"
assert_eq "nested sb_state.secure_boot read" "1" "$(baseline_get_in "$F" sb_state secure_boot)"
assert_eq "missing top-level key reads empty" "" "$(baseline_get "$F" nonexistent)"
assert_eq "missing nested key reads empty" "" "$(baseline_get_in "$F" sb_state nonexistent)"

# --- finalization (surgical pcr replace) --------------------------------------
baseline_set_pcr "$F" expected_pcr7 "$HEX_B"
assert_rc "finalized baseline validates" 0 baseline_validate "$F"
assert_rc "is_final after finalize" 0 baseline_is_final "$F"
assert_rc "is_pending false after finalize" 1 baseline_is_pending "$F"
assert_eq "expected_pcr7 now $HEX_B" "$HEX_B" "$(baseline_get "$F" expected_pcr7)"
assert_eq "pcr0 untouched by set_pcr" "$HEX_A" "$(baseline_get "$F" pcr0)"
assert_eq "created_at preserved by set_pcr" "$(head -3 "$F" | sed -n 's/.*"created_at": "\(.*\)",/\1/p')" \
    "$(baseline_get "$F" created_at)"

# set_pcr rejects non-hex non-pending values (die exits — run in a subshell)
OUT=$( (baseline_set_pcr "$F" pcr1 "nothex") 2>&1 )
assert_eq "set_pcr rejects garbage value (rc)" "64" "$( (baseline_set_pcr "$F" pcr1 "nothex") >/dev/null 2>&1; echo $? )"
assert_contains "set_pcr error mentions bad value" "$OUT" "bad value"

# --- nested field update -------------------------------------------------------
baseline_set_field "$F" '    ' sb_state db_fp deadbeef01
assert_eq "set_field writes nested value" "deadbeef01" "$(baseline_get_in "$F" sb_state db_fp)"
assert_rc "set_field result still validates" 0 baseline_validate "$F"
baseline_set_field "$F" '    ' fw eventlog_sha256 "$HEX_A"
baseline_set_field "$F" '    ' fw eventlog_size 4096
assert_eq "fw.eventlog_sha256 updated" "$HEX_A" "$(baseline_get_in "$F" fw eventlog_sha256)"
assert_eq "fw.eventlog_size updated" "4096" "$(baseline_get_in "$F" fw eventlog_size)"

# set_field to an unknown object/key fails loudly
OUT=$( (baseline_set_field "$F" '    ' nope key v) 2>&1 )
assert_eq "set_field unknown key fails rc" "64" "$( (baseline_set_field "$F" '    ' nope key v) >/dev/null 2>&1; echo $?)"
assert_rc "file intact after failed set_field" 0 baseline_validate "$F"
assert_eq "failed set_field leaves no .tmp litter next to the baseline (M-3)" "" \
    "$(find "$T" -maxdepth 1 -name '*.tmp' -print -quit)"

# --- baseline_load_env roundtrip ----------------------------------------------
baseline_load_env "$F"
assert_eq "load_env pcr0" "$HEX_A" "$BL_PCR0"
assert_eq "load_env expected_pcr7" "$HEX_B" "$BL_PCR7"
assert_eq "load_env sb db_fp" "deadbeef01" "${BL_SB_DB_FP:-}"
assert_eq "load_env fw eventlog_size" "4096" "${BL_FW_EVENTLOG_SIZE:-}"
# write from the loaded env reproduces a valid baseline
F2=$T/rewrite.json
baseline_write "$F2"
assert_rc "rewrite from loaded env validates" 0 baseline_validate "$F2"
assert_eq "rewrite preserves pcr0" "$(baseline_get "$F" pcr0)" "$(baseline_get "$F2" pcr0)"

# --- validation rejects ---------------------------------------------------------
reject_variant() { # NAME JSON-TRANSFORM-SED
    printf '%s' "$1"
}
# unknown schema_version
sed 's/"schema_version": "1"/"schema_version": "2"/' "$F" >"$T/v2.json"
assert_rc "schema_version 2 rejected" 1 baseline_validate "$T/v2.json"
sed 's/"schema_version": "1"/"schema_version": "banana"/' "$F" >"$T/vb.json"
assert_rc "schema_version garbage rejected" 1 baseline_validate "$T/vb.json"
grep -v '"schema_version"' "$F" >"$T/no-schema.json"
assert_rc "missing schema_version rejected" 1 baseline_validate "$T/no-schema.json"
# missing required keys
grep -v '"pcr2"' "$F" >"$T/no-pcr2.json"
assert_rc "missing pcr2 rejected" 1 baseline_validate "$T/no-pcr2.json"
grep -v '"dbx_fp"' "$F" >"$T/no-dbx.json"
assert_rc "missing sb_state.dbx_fp rejected" 1 baseline_validate "$T/no-dbx.json"
grep -v '"luks_uuid"' "$F" >"$T/no-uuid.json"
assert_rc "missing target.luks_uuid rejected" 1 baseline_validate "$T/no-uuid.json"
# malformed pcr values (not hex64, not pending)
sed "s/\"pcr1\": \"pending\"/\"pcr1\": \"abc123\"/" "$F" >"$T/bad-pcr.json"
assert_rc "short pcr value rejected" 1 baseline_validate "$T/bad-pcr.json"
sed "s/\"expected_pcr7\": \"$HEX_B\"/\"expected_pcr7\": \"zzzz\"/" "$F" >"$T/bad-pcr7.json"
assert_rc "garbage expected_pcr7 rejected" 1 baseline_validate "$T/bad-pcr7.json"
# empty created_at
sed 's/"created_at": ".*"/"created_at": ""/' "$F" >"$T/no-date.json"
assert_rc "empty created_at rejected" 1 baseline_validate "$T/no-date.json"
# unreadable / garbage file
assert_rc "missing file rejected" 1 baseline_validate "$T/does-not-exist.json"
printf 'not json at all\n' >"$T/garbage.json"
assert_rc "garbage file rejected" 1 baseline_validate "$T/garbage.json"

# --- baseline_write rejects JSON-breaking values --------------------------------
_rc=$( (BL_PCR0='break"json' baseline_write "$T/bad.json") >/dev/null 2>&1; echo $? )
assert_eq "baseline_write rejects embedded quote" "64" "$_rc"
assert_not_contains "bad baseline not written" "$(ls "$T")" "bad.json"
_rc=$( (BL_PCR0='back\\slash' baseline_write "$T/bad2.json") >/dev/null 2>&1; echo $? )
assert_eq "baseline_write rejects embedded backslash" "64" "$_rc"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))