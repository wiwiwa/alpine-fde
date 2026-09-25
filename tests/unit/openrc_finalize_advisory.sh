#!/usr/bin/env bash
# tests/unit/openrc_finalize_advisory.sh — ADR-20 AMENDED (§9.1 Stage 2, user
# amendments #3+#4): the first-boot OpenRC service hooks/openrc/
# alpine-fde-finalize is the AUTO-FINALIZER and its SB guard is the SECOND
# BLOCKING LAYER (the first is the initramfs pre-unseal guard, §8.2 step 1):
# when the state is provisional (installed/provisional-booted) AND the final
# Secure Boot state holds (secureboot=1 && setup_mode=0) it INVOKES the
# non-interactive completion (fin_service_main, lib/cmd/finalize.sh — guard ->
# audit --init -> token upgrade {PCR 7, PCR 11} -> ephemeral purge -> state
# finalized; the MOTD banner path is REMOVED). On SB-guard failure the service
# BLOCKS finalization loudly (no chain invocation, no mutation) and exits 0
# for OpenRC — boot proceeds, finalization does NOT, retry next boot. On any
# NON-guard completion failure it prints the ADR-8 advisory warning, exits 0
# and retries on the next boot. finalized / missing / corrupt state / missing
# libraries => silent degrade-safe exit 0.
#
# The REAL hook script is exercised (sourced; start() invoked) against the REAL
# collaborators lib/install-state.sh + lib/firmware.sh. The completion entry
# point is intercepted with a RECORDING STUB (fin_service_main defined before
# the hook runs; finalize.sh honors ALPINE_FDE_FINALIZE_LOADED and returns
# early, so the stub stands in for the whole completion chain). The full
# REAL-chain service simulation lives in tests/unit/finalize_service_guard.sh.
#
# Pinned invariants (rc 0 ALWAYS — the service never fails the boot itself):
#   * provisional + SB final          => completion chain INVOKED once, silent
#   * provisional + SB guard failure  => completion chain NOT invoked (guard
#                                       BLOCKS finalization), loud blocking
#                                       notice, retry-next-boot text, rc 0
#   * completion failure (stub rc 1)  => rc 0, loud advisory (ADR-8), rc 0
#   * finalized                        => silent rc 0, chain NOT invoked
#   * missing / corrupt state          => silent rc 0 (degrade safe), not invoked
#   * libraries missing                => silent rc 0 (degrade safe)

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
EFIVARS=$T/efivars
STATE=$T/etc/install-state.json
ATTEMPT=$T/etc/finalize-attempt.txt
CALL_LOG=$T/calls.log

export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_INSTALL_STATE=$STATE
export ALPINE_FDE_INSTALL_ATTEMPT=$ATTEMPT
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS

cleanup() { rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$EFIVARS" "${STATE%/*}" "$T/root"

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
# SVC_RC / SVC_CALLS: the recording stub's rc and invocation count. The stub is
# defined BEFORE the hook is sourced; finalize.sh honors
# ALPINE_FDE_FINALIZE_LOADED (the hook exports it? no — the HOOK sees it already
# set in its environment and skips sourcing finalize.sh), so the stub survives.
run_hook() { # SVC_RC — the rc the completion stub returns
    SVC_CALLS=0
    ADV_OUT=$(
        exec 2>&1
        export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
        ALPINE_FDE_FINALIZE_LOADED=1
        export ALPINE_FDE_FINALIZE_LOADED
        SVC_RC=$1
        fin_service_main() {
            printf 'CALL fin_service_main\n' >>"$CALL_LOG"
            return $SVC_RC
        }
        # shellcheck disable=SC1090
        . "$HOOK"
        start
    ) 2>&1
    ADV_RC=$?
    SVC_CALLS=$(grep -c . "$CALL_LOG" 2>/dev/null || true)
    : >"$CALL_LOG"
}
# Variant with the LIBRARIES absent (broken install): silent degrade, rc 0.
run_hook_no_libs() {
    ADV_OUT=$(
        exec 2>&1
        ALPINE_FDE_CMD_DIR="$T/absent/cmd"
        export ALPINE_FDE_CMD_DIR
        SVC_RC=0
        fin_service_main() { return 0; }
        # shellcheck disable=SC1090
        . "$HOOK"
        start
    ) 2>&1
    ADV_RC=$?
}

# =================================================================================
# 0. static contract: the artifact exists, is an openrc oneshot, wires the
# completion entrypoint (fin_service_main) and its own degrade-safe guard rails.
assert_file_exists "static: finalize hook exists" "$HOOK"
assert_eq "static: openrc-run shebang" "#!/sbin/openrc-run" "$(head -n1 "$HOOK")"
HOOK_TXT=$(cat "$HOOK")
assert_contains "static: depend() needs localmount" "$HOOK_TXT" "need localmount"
assert_contains "static: invokes the completion chain (fin_service_main)" "$HOOK_TXT" \
    "fin_service_main"
assert_contains "static: skip-sourcing guard so a stub seam is possible" "$HOOK_TXT" \
    "ALPINE_FDE_FINALIZE_LOADED"
assert_contains "static: reads the install state (finalized is a no-op)" "$HOOK_TXT" \
    "istate_state"
assert_contains "static: read-only final SB guard before the completion" "$HOOK_TXT" \
    "fw_sb_state"
assert_contains "static: the guard branch names the initramfs pre-unseal guard (second-layer framing)" \
    "$HOOK_TXT" "pre-unseal"
assert_contains "static: failure path writes the ADR-8 attempt marker" "$HOOK_TXT" \
    "istate_attempt_write"
assert_contains "static: advisory names the retry contract" "$HOOK_TXT" "next boot"
assert_not_contains "static: no LUKS vocabulary in the hook itself" "$HOOK_TXT" "cryptsetup"
assert_not_contains "static: no cryptenroll vocabulary in the hook itself" "$HOOK_TXT" \
    "cryptenroll"
assert_not_contains "static: no raw tpm2 vocabulary in the hook itself" "$HOOK_TXT" "tpm2 "
assert_eq "static: systemd unit deleted" "0" \
    "$([ -e "$REPO/hooks/systemd/alpine-fde-finalize.service" ] && echo 1 || echo 0)"

# =================================================================================
# 1. provisional-booted + final SB state ⇒ the completion chain IS invoked
# (ADR-20 amended Stage 2 — the inverted contract), success is silent, rc 0.
sb_state 1 0
write_state provisional-booted
run_hook 0
assert_eq "provisional+SB-final: rc 0 (never blocks boot)" "0" "$ADV_RC"
assert_eq "provisional+SB-final: completion chain invoked exactly once" "1" "$SVC_CALLS"
assert_eq "provisional+SB-final: silent on success (no advisory)" "" "$ADV_OUT"

# =================================================================================
# 2. SB guard failure (secureboot=0) ⇒ the SECOND BLOCKING LAYER (ADR-20 #3):
# the completion chain is NOT invoked, the BLOCKED notice is loud, rc 0 for
# OpenRC (boot proceeds; finalization does NOT) — §9.1 Stage 2 / §12 S-21.
sb_state 0 0
write_state provisional-booted
run_hook 0
assert_eq "SB-off: rc 0 (the service never fails the boot itself)" "0" "$ADV_RC"
assert_eq "SB-off: completion chain NOT invoked (the guard blocks finalization)" "0" \
    "$SVC_CALLS"
assert_contains "SB-off: BLOCKED notice (guard, not a soft advisory)" "$ADV_OUT" \
    "BLOCKED"
assert_contains "SB-off: notice prints the read-only SB state" "$ADV_OUT" \
    "secureboot=0"
assert_contains "SB-off: notice names the not-finalized state" "$ADV_OUT" \
    "provisional-booted"
assert_contains "SB-off: notice names the initramfs pre-unseal guard (the first layer)" \
    "$ADV_OUT" "pre-unseal"
assert_contains "SB-off: notice names the retry contract" "$ADV_OUT" "next boot"
assert_not_contains "SB-off: NO manual-command guidance on the guard branch (SB-off finalize dies 64 anyway)" \
    "$ADV_OUT" "alpine-fde finalize"

# --- 2b. SetupMode=1 is equally a guard failure (keys not in final state) --------
sb_state 1 1
write_state provisional-booted
run_hook 0
assert_eq "SetupMode=1: rc 0" "0" "$ADV_RC"
assert_eq "SetupMode=1: completion chain NOT invoked" "0" "$SVC_CALLS"
assert_contains "SetupMode=1: BLOCKED notice prints the setup-mode state" "$ADV_OUT" \
    "setup_mode=1"

# =================================================================================
# 3. Completion failure (chain rc != 0) ⇒ rc 0, loud ADR-8 advisory, retry next
# boot. The attempt marker itself is fin_service_main's contract (asserted end-
# to-end in finalize_service_guard.sh); here the loud console message is pinned.
sb_state 1 0
write_state provisional-booted
run_hook 1
assert_eq "chain-fail: rc 0 (boot is NEVER blocked)" "0" "$ADV_RC"
assert_eq "chain-fail: completion chain WAS attempted" "1" "$SVC_CALLS"
assert_contains "chain-fail: loud advisory (ADR-8)" "$ADV_OUT" "WARNING"
assert_contains "chain-fail: advisory names the not-finalized state" "$ADV_OUT" \
    "provisional-booted"
assert_contains "chain-fail: advisory names the retry contract" "$ADV_OUT" "next boot"

# =================================================================================
# 4. finalized ⇒ silent rc 0, the chain is NOT invoked (idempotent, no nag).
sb_state 1 0
write_state finalized
run_hook 0
assert_eq "finalized: rc 0" "0" "$ADV_RC"
assert_eq "finalized: completion chain NOT invoked" "0" "$SVC_CALLS"
assert_eq "finalized: quiet" "" "$ADV_OUT"

# =================================================================================
# 5. Robustness: missing / corrupt state file ⇒ silent rc 0 (degrade safe), the
# chain is never invoked, no crash traceback on the console.
rm -f "$STATE"
run_hook 0
assert_eq "absent state: rc 0" "0" "$ADV_RC"
assert_eq "absent state: completion chain NOT invoked" "0" "$SVC_CALLS"
assert_eq "absent state: quiet (degrade safe)" "" "$ADV_OUT"

printf 'not json at all {{\n' >"$STATE"
run_hook 0
assert_eq "corrupt state: rc 0" "0" "$ADV_RC"
assert_eq "corrupt state: completion chain NOT invoked" "0" "$SVC_CALLS"
assert_eq "corrupt state: quiet (degrade safe)" "" "$ADV_OUT"
assert_not_contains "corrupt state: no crash traceback markers" "$ADV_OUT" \
    "syntax error"

# 5b. libraries entirely missing (broken/partial install) — silent degrade, rc 0.
run_hook_no_libs
assert_eq "no libs: rc 0" "0" "$ADV_RC"
assert_eq "no libs: quiet" "" "$ADV_OUT"

finish
