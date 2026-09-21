#!/usr/bin/env bash
# tests/lib/sentinels.sh — the single promoted console-sentinel lookup
# (MD-02/IN-03: was duplicated per-scenario; scenarios source this instead of
# defining their own sentinel_of).
#
# Versioned selection seam (G-E2): the table is resolved
#   1. explicit file pin      — SENTINELS_FILE (absolute/relative path), else
#   2. legacy env override    — SENTINELS (pre-seam spelling, same semantics), else
#   3. versioned default      — tests/sentinels-$SENTINELS_VER.txt with
#                               SENTINELS_VER defaulting to 260.2 (the Alpine
#                               contract, §12). SENTINELS_VER=257.13 loads the
#                               Debian-era record.
#
# sentinel_of <name> — print the pinned string for <name> from the selected
# table. UNKNOWN NAMES FAIL LOUDLY (stderr + exit 64): a silently empty result
# would turn every assert_contains into a vacuous pass (an empty needle
# matches any haystack), which is exactly the silent-rot the harness contract
# forbids.

if [[ -n "${_DEBIAN_FDE_SENTINELS_SH_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_SENTINELS_SH_SOURCED=1

SENTINELS_VER="${SENTINELS_VER:-260.2}"
SENTINELS="${SENTINELS_FILE:-${SENTINELS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sentinels-${SENTINELS_VER}.txt}}"

sentinel_of() {
    local v
    v=$(awk -F '\t' -v n="$1" '$1 == n {print $2; exit}' "$SENTINELS")
    if [[ -z "$v" ]]; then
        echo "sentinel_of: unknown sentinel: $1 (table: $SENTINELS)" >&2
        exit 64
    fi
    printf '%s\n' "$v"
}
