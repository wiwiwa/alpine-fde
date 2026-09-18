#!/usr/bin/env bash
# tests/unit/install_state_machine.sh — G-IL1 (§8.4, §9.1): the install-state
# document install-state.json and its state machine `installed` → `finalized`
# (no provisional token anywhere):
#   * atomic write: a fault or crash mid-write leaves the previous document
#     intact — readers never observe partial content
#   * fail-closed validation: unknown states are refused (die 64), never written
#   * readers: empty + warn when the file is absent (pre-state-machine installs)
#   * DEBIAN_FDE_ROOT scoping round-trip + DEBIAN_FDE_INSTALL_STATE override

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
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"

T=$(mktemp -d /tmp/debian-fde-istate.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_ROOT=$T/root
mkdir -p "$(sp_etc_dir)"

run_write() { # STATE — istate_write in a subshell: its die must not kill the test
    W_RC=0
    ( istate_write "$1" ) >/dev/null 2>&1 || W_RC=$?
}

# --- 1. absent file: reader warns + empty (pre-state-machine installs) ---------
OUT=$(istate_state 2>"$T/err-absent")
assert_eq "absent: rc-free reader, empty state" "" "$OUT"
assert_contains "absent: warns about the missing state file" "$(cat "$T/err-absent")" "install-state"
assert_rc "absent: not finalized" 1 istate_is_finalized

# --- 2. write `installed` → schema + read-back ---------------------------------
F=$(istate_file)
run_write installed
assert_eq "write installed: rc 0" "0" "$W_RC"
assert_eq "installed: reads back" "installed" "$(istate_state)"
assert_rc "installed: not finalized yet" 1 istate_is_finalized
assert_eq "schema_version is 1" "1" "$(jq -r '.schema_version' "$F")"
assert_eq "state field round-trips" "installed" "$(jq -r '.state' "$F")"
assert_ne "updated_at stamped" "" "$(jq -r '.updated_at' "$F")"
assert_eq "state document mode pinned 600" "600" "$(stat -c %a "$F")"

# --- 3. transition to `finalized` ----------------------------------------------
run_write finalized
assert_eq "finalized: reads back" "finalized" "$(istate_state)"
assert_rc "finalized: istate_is_finalized rc 0" 0 istate_is_finalized

# --- 4. unknown states fail closed (no provisional token anywhere) --------------
BEFORE=$(cat "$F")
run_write 'sb_pending'
assert_eq "provisional vocabulary 'sb_pending' refused (64)" "64" "$W_RC"
run_write 'sb_disabled_fallback'
assert_eq "'sb_disabled_fallback' refused (64)" "64" "$W_RC"
run_write 'totally-bogus'
assert_eq "unknown state refused (64)" "64" "$W_RC"
run_write ''
assert_eq "empty state refused (64)" "64" "$W_RC"
assert_eq "document untouched after every refusal" "$BEFORE" "$(cat "$F")"

# --- 5. atomicity: failed rename leaves the previous document intact ------------
FAKEBIN=$T/bin
mkdir -p "$FAKEBIN"
printf '#!/bin/sh\necho "mv fault injection: rename failed" >&2\nexit 1\n' >"$FAKEBIN/mv"
chmod +x "$FAKEBIN/mv"
OLD_PATH=$PATH
export PATH="$FAKEBIN:$PATH"
run_write installed
assert_eq "interrupted rename -> 64" "64" "$W_RC"
assert_eq "rename fault: previous document intact (atomic replace)" "finalized" "$(istate_state)"
assert_contains "rename fault: document still valid JSON" "$(cat "$F")" '"state": "finalized"'
assert_eq "no temp litter after the failed write" "" \
    "$(find "$(sp_etc_dir)" -maxdepth 1 -name '.install-state.*' -print -quit)"
export PATH="$OLD_PATH"

# --- 6. DEBIAN_FDE_ROOT scoping round-trip --------------------------------------
ROOT1=$T/root1
ROOT2=$T/root2
export DEBIAN_FDE_ROOT=$ROOT1
mkdir -p "$(sp_etc_dir)"
run_write installed
assert_eq "root1: installed" "installed" "$(istate_state)"
export DEBIAN_FDE_ROOT=$ROOT2
mkdir -p "$(sp_etc_dir)"
assert_eq "root2: no state (scoped, absent)" "" "$(istate_state 2>/dev/null)"
run_write finalized
assert_eq "root2: finalized" "finalized" "$(istate_state)"
export DEBIAN_FDE_ROOT=$ROOT1
assert_eq "root1 unaffected by the root2 write" "installed" "$(istate_state)"

# --- 7. DEBIAN_FDE_INSTALL_STATE override round-trip (test seam) -----------------
OV=$T/custom-state.json
export DEBIAN_FDE_INSTALL_STATE=$OV
assert_eq "override: absent initially" "" "$(istate_state 2>/dev/null)"
run_write finalized
assert_file_exists "override: write landed at DEBIAN_FDE_INSTALL_STATE" "$OV"
assert_eq "override: read-back" "finalized" "$(istate_state)"
unset DEBIAN_FDE_INSTALL_STATE
assert_eq "override removed: back to the root-scoped path" "installed" "$(istate_state)"

# --- 8. optional FILE argument (consumed by enroll-tpm.sh's G-IL7 reader):
# an explicit path is read as-is, the env/root-scoped default stays untouched
ARGA=$T/state-a.json
ARGB=$T/state-b.json
printf '{\n  "schema_version": 1,\n  "state": "finalized",\n  "updated_at": "x"\n}\n' >"$ARGA"
printf '{\n  "schema_version": 1,\n  "state": "installed",\n  "updated_at": "x"\n}\n' >"$ARGB"
export DEBIAN_FDE_INSTALL_STATE=$ARGA
assert_eq "explicit FILE arg read as-is" "installed" "$(istate_state "$ARGB")"
assert_eq "no-arg call still honors the env override" "finalized" "$(istate_state)"
unset DEBIAN_FDE_INSTALL_STATE

# --- 9. unparseable document: empty + warn, never finalized ----------------------
export DEBIAN_FDE_ROOT=$ROOT1
printf 'not json at all' >"$(sp_etc_dir)/install-state.json"
OUT=$(istate_state 2>"$T/err-garbage")
assert_eq "garbage document: empty state" "" "$OUT"
assert_contains "garbage document: warns" "$(cat "$T/err-garbage")" "install-state"
assert_rc "garbage document: not finalized" 1 istate_is_finalized

# --- 9. crash mid-rename (SIGKILL): readers see old-or-new, never partial --------
run_write installed
assert_eq "crash setup: valid document in place" "installed" "$(istate_state)"
F=$(istate_file)
mkdir -p "$T/bin-kill"
printf '#!/bin/sh\nkill -9 "$PPID"\n' >"$T/bin-kill/mv"
chmod +x "$T/bin-kill/mv"
export PATH="$T/bin-kill:$PATH"
run_write finalized
assert_ne "power loss mid-rename kills the writer" "0" "$W_RC"
assert_eq "crash: previous document intact" "installed" "$(istate_state)"
assert_contains "crash: document valid JSON (never partial)" "$(cat "$F")" '"state": "installed"'
export PATH="$OLD_PATH"
run_write finalized
assert_eq "recovery: a write after the crash succeeds" "finalized" "$(istate_state)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
