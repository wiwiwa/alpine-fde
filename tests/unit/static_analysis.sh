#!/usr/bin/env bash
# tests/unit/static_analysis.sh — static analysis + policy pins over the owned
# shell surface. Replaces tests/unit/mechanical_ex_pins.sh's mechanical
# shebang/set-option text greps (.tasks.md policy: "Static Analysis Over Bash
# Tests" — shellcheck subsumes "does the script carry #!/bin/sh -eu" pins).
#
#   1. SHELLCHECK pass (severity=warning) over:
#        bin/alpine-fde, ./alpine-fde (POSIX sh entry points),
#        lib/*.sh, lib/cmd/*.sh (POSIX sh sourced modules),
#        tests/lib/*.sh (bash test-surface libs).
#      Results are cached under tests/.shellcheck-cache (gitignored via the
#      repo's `.*` rule), keyed by file content + shellcheck version + flags:
#      a cold pass over the whole surface costs ~20s of shellcheck CPU, which
#      would blow the unit lane's <2s wall budget; a warm (cached) pass costs
#      milliseconds. Any finding -> FAIL with the shellcheck output.
#
#   2. THE -ex POLICY, semantic part only (the mechanical part is shellcheck
#      now): lib/*.sh and lib/cmd/*.sh are SOURCED modules — unit suites and
#      hooks source them — so a top-level `set -ex` would leak errexit/xtrace
#      into the sourcing shell. Runtime strictness comes from the executing
#      entry point (dispatcher `#!/bin/sh -eu` + ALPINE_FDE_TRACE opt-in;
#      plumbing scripts and the EMITTED guest script trace by default, pinned
#      by install_qemu_emit.sh against the generated artifact).
#      This pin FAILS if a module grows a top-level `set -ex`: revert it, or
#      move the module to the executable-carrier list with a suite-backed
#      rationale.
#
#   3. RETIRED-FLAG contract: the user-facing --dry-run is gone (task 8, done
#      2026-09-25). The install dry-run RUNNER lane (ALPINE_FDE_INSTALL_RUNNER,
#      default plan printer, pinned behaviorally by install_dryrun.sh) is a
#      different mechanism and stays.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

SHELLCHECK=$(command -v shellcheck || command -v "$HOME/.local/bin/shellcheck" || true)
SEVERITY=warning

# =============================================================================
# 0. the analyzer itself is part of the contract
# =============================================================================
assert_contains "shellcheck is available on PATH (or ~/.local/bin)" "$SHELLCHECK" "/"

CACHE_DIR="$REPO/tests/.shellcheck-cache"
mkdir -p "$CACHE_DIR"
SC_VERSION=$("$SHELLCHECK" --version | awk '/^version:/{print $2}')

# raw TAP emitters over tests/lib/assert.sh's internal recorder (this suite
# sources assert.sh directly, not unit/lib.sh, so it has no _pass/_fail).
# _assert_result local-assigns $3 unconditionally -> always pass a detail arg.
sc_pass() { _assert_result ok "$1" ""; }
sc_fail() { _assert_result not-ok "$1" "${2:-}"; }

# sc_check <dialect> <files...> — shellcheck each file, cached by
# content+tool+flags. On a cache miss the file is checked (bundled per run so
# a cold pass spawns one shellcheck per dialect, not per file); a nonzero rc
# FAILS with the analyzer output. Cache entries are only written for CLEAN
# results: editing a file back to dirty always re-checks it.
sc_cache_key() { # <dialect> <file>
    printf '%s|%s|%s|%s|%s\n' "$SC_VERSION" "$SEVERITY" "$1" \
        "$(sha256sum <"$2" | awk '{print $1}')" "$(basename "$2")" \
        | sha256sum | awk '{print $1}'
}

sc_check() {
    local dialect=$1; shift
    local files=() f key todo=()
    for f in "$@"; do
        key=$(sc_cache_key "$dialect" "$f")
        if [[ -s "$CACHE_DIR/$key" ]]; then
            sc_pass "shellcheck [-s dialect, severity=warning] clean (cached): ${f#"$REPO"/}"
        else
            files+=("$f")
            todo+=("$f:$key")
        fi
    done
    local rc=0 out
    if (( ${#files[@]} > 0 )); then
        out=$("$SHELLCHECK" -s "$dialect" --severity="$SEVERITY" "${files[@]}" 2>&1)
        rc=$?
        if (( rc == 0 )); then
            for f in "${files[@]}"; do
                sc_pass "shellcheck [-s dialect, severity=warning] clean: ${f#"$REPO"/}"
            done
            for f in "${todo[@]}"; do
                key=${f#*:}; f=${f%%:*}
                printf 'clean %s\n' "$(date -u +%FT%TZ)" >"$CACHE_DIR/$key" 2>/dev/null || :
            done
        else
            for f in "${files[@]}"; do
                sc_fail "shellcheck [-s dialect, severity=warning]: ${f#"$REPO"/} has findings" "(see analyzer output above)"
            done
            printf '%s\n' "$out"
        fi
    fi
}

SH_FILES=("$REPO/bin/alpine-fde" "$REPO/alpine-fde" "$REPO"/lib/*.sh "$REPO"/lib/cmd/*.sh)
BASH_FILES=("$REPO"/tests/lib/*.sh)

# =============================================================================
# 1. shellcheck over the owned shell surface (cached, sub-second warm)
# =============================================================================
time_sc0=$SECONDS
sc_check sh "${SH_FILES[@]}"
sc_check bash "${BASH_FILES[@]}"
echo "# static_analysis: shellcheck pass took $((SECONDS - time_sc0))s (0s = warm cache)"

# =============================================================================
# 2. sourced-module -ex exemption, enforced both ways (policy, not mechanics)
# =============================================================================
EXEMPT_VIOLATIONS=$(grep -lE '^set -ex' "$REPO"/lib/*.sh "$REPO"/lib/cmd/*.sh 2>/dev/null)
assert_eq "no sourced lib module sets -ex at top level (exemption discipline)" "" "$EXEMPT_VIOLATIONS"

# =============================================================================
# 3. retired user-facing --dry-run stays retired; the RUNNER lane stays
# =============================================================================
DISPATCHER="$REPO/bin/alpine-fde"
assert_not_contains "dispatcher has no --dry-run flag/usage text" "$(cat "$DISPATCHER")" "--dry-run"
assert_not_contains "dispatcher does not reference the DRY_RUN variable" "$(cat "$DISPATCHER")" "DRY_RUN"
DRY_INFO=$(grep -rn 'info "dry-run' "$REPO/lib/cmd/" 2>/dev/null)
assert_eq "no dry-run plan printers (info \"dry-run ...) in lib/cmd" "" "$DRY_INFO"
assert_contains "install dry-run RUNNER lane retained (distinct mechanism)" \
    "$(cat "$REPO/lib/cmd/install.sh")" 'SPC_INSTALL_RUNNERS='

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
