#!/usr/bin/env bash
# tests/unit/openrc_finalize_advisory.sh — ADR-20 (§9.1 Stage 2): the first-boot
# OpenRC service hooks/openrc/alpine-fde-finalize is ADVISORY ONLY. The
# fail-closed Secure Boot gate lives in the GUIDED `alpine-fde finalize`
# (lib/cmd/finalize.sh STEP 3); the boot-time artifact NEVER runs it.
#
# The REAL hook script is exercised (sourced; start() invoked) against the REAL
# collaborators lib/install-state.sh + lib/firmware.sh. Only the seams are
# stubbed: DEBIAN_FDE_INSTALL_STATE (state file), DEBIAN_FDE_EFIVARS_DIR
# (firmware state), and a PATH set of RECORDING stubs for the finalize/TPM/LUKS
# vocabulary (observability tripwire — the hook may at most print).
#
# Pinned invariants (rc 0 ALWAYS — never blocks boot):
#   * unfinalized (provisional-booted) ⇒ prints install state + read-only SB
#     state + "Run: alpine-fde finalize" guidance
#   * finalized ⇒ rc 0, silent (no nag)
#   * Secure Boot OFF + unfinalized ⇒ STILL rc 0 (advisory-only is the
#     contract); the SB state is printed as-is and the guidance points at
#     finalize, where the fail-closed gate lives
#   * the hook NEVER invokes the finalize implementation: zero recording-stub
#     invocations (cryptsetup / cryptenroll / tpm / the CLI entrypoints), the
#     cmd_* handlers are never even defined, the state file is never written
#   * robustness: missing / corrupt state file, and even missing libraries ⇒
#     rc 0, advisory text, no die/crash output on the console

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (missing: $2)"; fi
}
assert_not_contains() {
    case $2 in
        *"$3"*) _fail "$1 ([$2] must not contain [$3])" ;;
        *) _pass "$1" ;;
    esac
}

HOOK=$REPO/hooks/openrc/alpine-fde-finalize
T=$(mktemp -d /tmp/alpine-fde-advisory.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
STATE=$T/etc/install-state.json
CALL_LOG=$T/calls.log

export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_INSTALL_STATE=$STATE
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS

cleanup() { rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "${STATE%/*}" "$T/root"

# --- seams ---------------------------------------------------------------------
# Recording tripwire: the advisory hook may at most PRINT. Any invocation of the
# finalize/enroll/token/LUKS/TPM vocabulary is logged here and fails the suite.
record_stub() { # NAME — a stub that logs its own invocation and fails loudly
    cat >"$FAKEBIN/$1" <<EOF
#!/bin/sh
printf 'CALL $1 %s\n' "\$*" >>'$CALL_LOG'
exit 1
EOF
    chmod +x "$FAKEBIN/$1"
}
record_stub cryptsetup   # LUKS keyslot/token operations (lib/cmd/finalize.sh)
record_stub systemd-cryptenroll # ADR-19 tripwire (never anywhere)
record_stub cryptenroll  # the alpine-fde enroll verb
record_stub tpm          # tpm2-tools wrapper (mechanism B seal ops)
record_stub tpm2         # direct tpm2-tools
record_stub alpine-fde   # the CLI entrypoint (`alpine-fde finalize`)
record_stub debian-fde   # historical CLI entrypoint
: >"$CALL_LOG"

# --- efivarfs fixture -----------------------------------------------------------
mkvar() { # NAME BYTE — attrs header (NV+BS+RT=7) + payload byte
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" \
        >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkcertvar() { # NAME CONTENT
    printf '\007\000\000\000%s' "$2" \
        >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_state() { # SECUREBOOT SETUPMODE — full key tree
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
    mkcertvar PK pk-cert-v1
    mkcertvar KEK kek-cert-v1
    mkcertvar db db-cert-v1
    mkcertvar dbx dbx-cert-v1
}
write_state() { # STATE — the §8.4 install-state document
    printf '{\n  "schema_version": 1,\n  "state": "%s",\n  "updated_at": "x"\n}\n' \
        "$1" >"$STATE"
}

# --- driver: source the REAL hook in a subshell and call start() -----------------
# The cmd dir points at the REAL lib/cmd (the hook derives the lib dir from it
# and sources the REAL install-state.sh + firmware.sh). PATH carries the
# recording stubs. Output is merged stdout+stderr (what would hit the console).
run_hook() {
    ADV_OUT=$(
        export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
        export PATH="$FAKEBIN:$PATH"
        # shellcheck disable=SC1090
        . "$HOOK"
        start
    ) 2>&1
    ADV_RC=$?
}
# Variant with the LIBRARIES absent (broken install): the hook must still be a
# silent-success advisory (command -v guards).
run_hook_no_libs() {
    ADV_OUT=$(
        export DEBIAN_FDE_CMD_DIR="$T/absent/cmd"
        export PATH="$FAKEBIN:$PATH"
        # shellcheck disable=SC1090
        . "$HOOK"
        start
    ) 2>&1
    ADV_RC=$?
}
reset_calls() { : >"$CALL_LOG"; }
calls() { grep -c . "$CALL_LOG" 2>/dev/null || true; }

# =================================================================================
# 0. static contract: the artifact exists, is an openrc oneshot, and carries no
# finalize-implementation vocabulary at all (belt to the dynamic braces below).
assert_file_exists "static: advisory hook exists" "$HOOK"
assert_eq "static: openrc-run shebang" "#!/sbin/openrc-run" "$(head -n1 "$HOOK")"
HOOK_TXT=$(cat "$HOOK")
assert_contains "static: depend() needs localmount" "$HOOK_TXT" "need localmount"
assert_contains "static: state-aware (finalized check)" "$HOOK_TXT" "istate_is_finalized"
assert_not_contains "static: no LUKS vocabulary" "$HOOK_TXT" "cryptsetup"
assert_not_contains "static: no cryptenroll vocabulary" "$HOOK_TXT" "cryptenroll"
assert_not_contains "static: no tpm vocabulary" "$HOOK_TXT" "tpm"
case $HOOK_TXT in
    *"$REPO/bin/debian-fde"* | *"$REPO/bin/alpine-fde"* | *"cmd/finalize.sh"*)
        _fail "static: must not reference the finalize implementation" ;;
    *) _pass "static: must not reference the finalize implementation" ;;
esac

# =================================================================================
# 1. Unfinalized (provisional-booted: Stage 2 done, finalize pending) ⇒ rc 0
# ALWAYS, prints the state + the read-only SB state + the finalize guidance.
sb_state 1 0
write_state provisional-booted
reset_calls
run_hook
assert_eq "provisional-booted: rc 0 (never blocks boot)" "0" "$ADV_RC"
assert_contains "provisional-booted: names the install state" "$ADV_OUT" \
    "provisional-booted"
assert_contains "provisional-booted: prints the read-only SB state" "$ADV_OUT" \
    "secureboot=1 setup_mode=0 pk=1"
assert_contains "provisional-booted: directs to the guided command" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_eq "provisional-booted: ZERO recorded invocations (advisory only)" "0" \
    "$(calls)"
assert_eq "provisional-booted: state file untouched" "provisional-booted" \
    "$(sed -n 's/^  "state": "\(.*\)",$/\1/p' "$STATE")"

# =================================================================================
# 2. Finalized ⇒ rc 0, silent (no finalize nag on every boot).
write_state finalized
reset_calls
run_hook
assert_eq "finalized: rc 0" "0" "$ADV_RC"
assert_eq "finalized: quiet" "" "$ADV_OUT"
assert_eq "finalized: ZERO recorded invocations" "0" "$(calls)"

# =================================================================================
# 3. Secure Boot OFF + unfinalized ⇒ STILL rc 0 (advisory-only is the ADR-20
# contract; the fail-closed SB gate lives in the guided finalize, which the
# guidance names).
sb_state 0 0
write_state provisional-booted
reset_calls
run_hook
assert_eq "SB off: rc 0 (advisory never blocks or fails boot)" "0" "$ADV_RC"
assert_contains "SB off: SB state printed as-is (secureboot=0)" "$ADV_OUT" \
    "secureboot=0 setup_mode=0 pk=1"
assert_contains "SB off: guidance still names the finalize gate" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_not_contains "SB off: no fail-closed exit-code text on the console" \
    "$ADV_OUT" "error:"
assert_eq "SB off: ZERO recorded invocations" "0" "$(calls)"

# =================================================================================
# 4. The hook NEVER defines or reaches the finalize implementation: with the
# REAL libs sourced, no cmd_* handler exists in the hook's shell, and the
# recording tripwire across EVERY leg above saw nothing.
run_hook
assert_eq "impl isolation: rc 0" "0" "$ADV_RC"
run_defs() {
    (
        export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
        export PATH="$FAKEBIN:$PATH"
        # shellcheck disable=SC1090
        . "$HOOK"
        printf '%s\n' \
            "cmd_finalize_main=$(command -v cmd_finalize_main || echo absent)" \
            "cmd_enroll_main=$(command -v cmd_enroll_main || echo absent)" \
            "seal_make_token=$(command -v seal_make_token || echo absent)" \
            "seal_upgrade_token=$(command -v seal_upgrade_token || echo absent)"
        start >/dev/null 2>&1
    ) 2>&1
}
DEFS=$(run_defs)
assert_contains "impl isolation: cmd_finalize_main never defined" "$DEFS" \
    "cmd_finalize_main=absent"
assert_contains "impl isolation: cmd_enroll_main never defined" "$DEFS" \
    "cmd_enroll_main=absent"
assert_contains "impl isolation: seal_make_token never defined" "$DEFS" \
    "seal_make_token=absent"
assert_contains "impl isolation: seal_upgrade_token never defined" "$DEFS" \
    "seal_upgrade_token=absent"
assert_eq "impl isolation: ZERO invocations across all legs" "0" "$(calls)"

# =================================================================================
# 5. Robustness: missing / corrupt state file (and even missing libraries) ⇒
# rc 0, advisory text, no crash traceback on the console.
rm -f "$STATE"
reset_calls
run_hook
assert_eq "absent state: rc 0" "0" "$ADV_RC"
assert_contains "absent state: still advisory (state unknown)" "$ADV_OUT" "unknown"
assert_contains "absent state: still names the finalize guidance" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_not_contains "absent state: no die/error output" "$ADV_OUT" "error:"
assert_eq "absent state: ZERO recorded invocations" "0" "$(calls)"

printf 'not json at all {{\n' >"$STATE"
reset_calls
run_hook
assert_eq "corrupt state: rc 0" "0" "$ADV_RC"
assert_contains "corrupt state: still advisory (state unreadable)" "$ADV_OUT" \
    "unknown"
assert_contains "corrupt state: still names the finalize guidance" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_not_contains "corrupt state: no crash traceback markers" "$ADV_OUT" \
    "syntax error"
assert_eq "corrupt state: ZERO recorded invocations" "0" "$(calls)"

# 5b. libraries entirely missing (broken/partial install) — the command -v
# guards degrade to the placeholder SB line and the guidance, rc 0 still.
rm -f "$STATE"
reset_calls
run_hook_no_libs
assert_eq "no libs: rc 0" "0" "$ADV_RC"
assert_contains "no libs: placeholder SB line" "$ADV_OUT" \
    "secureboot=? setup_mode=? pk=?"
assert_contains "no libs: still names the finalize guidance" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_eq "no libs: ZERO recorded invocations" "0" "$(calls)"

finish
