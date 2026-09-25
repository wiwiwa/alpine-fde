#!/usr/bin/env bash
# tests/unit/mechanical_ex_pins.sh — task 8 mechanical pins (.tasks.md policy):
#
#   1. `sh -ex` adoption on the DIRECTLY-EXECUTED scripts:
#        - bin/alpine-fde (the dispatcher: everything it sources — lib/*.sh,
#          lib/cmd/*.sh — runs under its -e/-u/-x, so runtime tracing and
#          errexit come from the entry point; see exemption below)
#        - ./install (remote bootstrap; its header documents the guarded
#          expected-nonzero probes that make -e/-x safe)
#        - the EMITTED guest script (lib/cmd/install.sh qemu runner emission)
#   2. SOURCED-MODULE EXEMPTION (documented, enforced both ways):
#        lib/*.sh and lib/cmd/*.sh are sourceable unit-test modules. They do
#        NOT set -ex at top level: a top-level `set -ex` would leak errexit/
#        xtrace into the sourcing test shell (and into hooks that source
#        them). Runtime strictness is provided by the executing entry point
#        (dispatcher `#!/bin/sh -ex`, strict_mode in cmd mains). This pin
#        FAILS if a module grows a top-level `set -ex` — the author must
#        either revert it or move the module to the executable carrier list
#        above with a suite-backed rationale.
#   3. The user-facing `--dry-run` flag is REMOVED (task 8): not in the
#        dispatcher usage/flag table, no `info "dry-run` plan printers in
#        lib/cmd. The install dry-run RUNNER lane (ALPINE_FDE_INSTALL_RUNNER=
#        dry-run, the default plan printer pinned by tests/unit/install_dryrun.sh)
#        is a DIFFERENT mechanism and stays.
#   4. Guarded-probe spot checks: expected-nonzero probes in the dispatcher
#        sit inside `if`/`!` guards so `-e` cannot abort prematurely.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

DISPATCHER="$REPO/bin/alpine-fde"

# =============================================================================
# 1. -ex on the executable carriers
#    The INTERACTIVE dispatcher keeps errexit-only by default (its console
#    output is a pinned contract); xtrace is opt-in via ALPINE_FDE_TRACE=1.
#    The PLUMBING scripts (guest emission, ./install bootstrap) trace by
#    default — there the operator is the tracing audience (.tasks.md policy).
# =============================================================================
assert_eq "dispatcher shebang is plain sh (no default xtrace)" "#!/bin/sh" "$(head -n1 "$DISPATCHER")"
assert_contains "dispatcher runs under errexit (set -eu)" "$(cat "$DISPATCHER")" "set -eu"
assert_contains "dispatcher exposes the ALPINE_FDE_TRACE opt-in xtrace seam" \
    "$(cat "$DISPATCHER")" 'ALPINE_FDE_TRACE'
assert_contains "./alpine-fde bootstrap carries -x (set -eux)" "$(cat "$REPO/alpine-fde")" "set -eux"
assert_contains "emitted guest script shebang carries -ex (install.sh qemu emission)" \
    "$(cat "$REPO/lib/cmd/install.sh")" '#!/bin/sh -ex'
assert_contains "emitted guest script carries set -eux (install.sh qemu emission)" \
    "$(cat "$REPO/lib/cmd/install.sh")" 'set -eux'

# =============================================================================
# 2. sourced-module exemption, enforced both ways
# =============================================================================
EXEMPT_VIOLATIONS=$(grep -lE '^set -ex' "$REPO"/lib/*.sh "$REPO"/lib/cmd/*.sh 2>/dev/null)
assert_eq "no sourced lib module sets -ex at top level (exemption discipline)" "" "$EXEMPT_VIOLATIONS"

# =============================================================================
# 3. user-facing --dry-run is gone; the install dry-run RUNNER lane stays
# =============================================================================
assert_not_contains "dispatcher has no --dry-run flag/usage text" "$(cat "$DISPATCHER")" "--dry-run"
assert_not_contains "dispatcher does not reference the DRY_RUN variable" "$(cat "$DISPATCHER")" "DRY_RUN"
DRY_INFO=$(grep -rn 'info "dry-run' "$REPO/lib/cmd/" 2>/dev/null)
assert_eq "no dry-run plan printers (info \"dry-run ...) in lib/cmd" "" "$DRY_INFO"
assert_contains "install dry-run RUNNER lane retained (distinct mechanism)" \
    "$(cat "$REPO/lib/cmd/install.sh")" 'SPC_INSTALL_RUNNERS='

# =============================================================================
# 4. guarded-probe spot checks (dispatcher runs under -e; expected-nonzero
#    probes must be if/||-guarded)
# =============================================================================
assert_contains "dispatcher: entry-function probe is if-guarded (not bare)" \
    "$(cat "$DISPATCHER")" 'if ! command -v "$sp_fn"'
assert_contains "dispatcher: cmd-file existence probe is if-guarded (not bare)" \
    "$(cat "$DISPATCHER")" 'if [ ! -f "$sp_cmd_file" ]'
assert_contains "dispatcher: subcommand membership probe is if-guarded (not bare)" \
    "$(cat "$DISPATCHER")" 'if ! is_subcommand "$sp_cmd"'

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
