#!/usr/bin/env bash
# tests/lib/sentinels.sh — the single promoted console-sentinel lookup
# (MD-02/IN-03: was duplicated per-scenario; scenarios source this instead of
# defining their own sentinel_of).
#
# sentinel_of <name> — print the pinned string for <name> from the versioned
# sentinel table. UNKNOWN NAMES FAIL LOUDLY (stderr + exit 64): a silently
# empty result would turn every assert_contains into a vacuous pass (an empty
# needle matches any haystack), which is exactly the silent-rot the harness
# contract forbids.

if [[ -n "${_DEBIAN_FDE_SENTINELS_SH_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_SENTINELS_SH_SOURCED=1

SENTINELS="${SENTINELS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sentinels-257.13.txt}"

sentinel_of() {
    local v
    v=$(awk -F '\t' -v n="$1" '$1 == n {print $2; exit}' "$SENTINELS")
    if [[ -z "$v" ]]; then
        echo "sentinel_of: unknown sentinel: $1 (table: $SENTINELS)" >&2
        exit 64
    fi
    printf '%s\n' "$v"
}
