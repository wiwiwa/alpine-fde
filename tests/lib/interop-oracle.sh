#!/usr/bin/env bash
# tests/lib/interop-oracle.sh — ADR-19 interop oracle SCAFFOLD (gap G-E11).
#
# Scope (ADR-19/§12): upstream systemd-cryptsetup/cryptenroll 257 runs under
# bwrap against a swtpm-backed TPM and asserts the REVERSE direction of
# Mechanism B — a token produced by our sealer is enrolled/unsealed by
# upstream systemd code, and tampered/schema-drifted tokens are refused. The
# oracle is CI-ONLY: it never runs in `install`, the initramfs, or any shipped
# path; the Alpine target carries zero bwrap/Debian footprint.
#
# This file is the scaffold only: the gate, the fail-closed bwrap
# requirement, the pinned-deb fixture-rootfs assembly (SHA256-recorded) and
# the scope guard. The oracle BODY (Mechanism-B token feed into upstream
# cryptenroll/cryptsetup) lands later.
#
# Usage (source, then):
#   interop_oracle_gate_ok        -> rc 0 iff DEBIAN_FDE_INTEROP_ORACLE=1
#   interop_oracle_assert_ready   -> fail-closed rc 64 without the gate env
#                                    or without bwrap on PATH
#   interop_oracle_rootfs <dest>  -> assemble the fixture rootfs from the
#                                    ALREADY-PINNED 257 debs (rootfs-fixture.sh
#                                    table), record the tree SHA256; requires
#                                    interop_oracle_assert_ready first
#   interop_scope_check [tree]    -> rc 1 when the SHIPPED bin/+lib/+hooks
#                                    under <tree> (default: this repo) carry
#                                    bwrap/Debian-runtime references

if [[ -n "${_DEBIAN_FDE_INTEROP_ORACLE_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_INTEROP_ORACLE_SOURCED=1

_INTEROP_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/rootfs-fixture.sh
source "$_INTEROP_HERE/rootfs-fixture.sh"

# interop_oracle_gate_ok — the explicit opt-in gate. ANY other value ( unset,
# 0, yes, …) means the oracle does not run.
interop_oracle_gate_ok() {
    [[ "${DEBIAN_FDE_INTEROP_ORACLE:-}" == "1" ]]
}

# interop_oracle_assert_ready — fail-closed preconditions: gate env AND bwrap.
# Every refusal is rc 64 (the harness usage/prerequisite class) with the
# reason on stderr — the oracle must never degrade into "best effort".
interop_oracle_assert_ready() {
    if ! interop_oracle_gate_ok; then
        echo "interop-oracle: gate DEBIAN_FDE_INTEROP_ORACLE=1 not set — oracle does not run (ADR-19 scope guard)" >&2
        return 64
    fi
    if ! command -v bwrap >/dev/null 2>&1; then
        echo "interop-oracle: bwrap not available — refusing (ADR-19: CI-only interop oracle)" >&2
        return 64
    fi
    return 0
}

# interop_oracle_rootfs <dest-dir> — assemble the oracle fixture rootfs from
# the ALREADY-PINNED 257 deb table (rootfs-fixture.sh; every artifact
# SHA256-verified at fetch, rootfs_ensure). The assembled tree is recorded by
# a SHA256 manifest digest (sorted per-file sha256s, then one digest over
# that manifest) written to <dest>/.oracle-sha256 and printed on stdout.
# The digest makes the oracle's userspace input reproducible: a drift in ANY
# pinned deb changes the recorded digest and is visible.
interop_oracle_rootfs() {
    local dest="$1" name
    interop_oracle_assert_ready || return $?
    [[ -n "$dest" ]] || { echo "interop-oracle: rootfs dest required" >&2; return 64; }
    mkdir -p "$dest"
    for name in $(rootfs_pin_names); do
        rootfs_deb_extract "$name" "$dest" || {
            echo "interop-oracle: pinned deb extraction failed: $name" >&2
            return 1
        }
    done
    local manifest digest
    manifest=$(mktemp) || return 1
    (cd "$dest" && find . -type f -print0 | sort -z \
        | xargs -0 sha256sum >"$manifest") || { rm -f "$manifest"; return 1; }
    digest=$(sha256sum "$manifest" | awk '{print $1}')
    rm -f "$manifest"
    printf '%s\n' "$digest" >"$dest/.oracle-sha256"
    printf '%s\n' "$digest"
    return 0
}

# interop_scope_check [tree] — the ADR-19 scope guard: the SHIPPED paths
# (bin/, lib/, hooks/ under <tree>) must carry NO bwrap footprint and NO
# references to the Debian runtime fixture (the pinned-deb cache machinery,
# the Debian archive hosts/images). This is what keeps the oracle "CI-only":
# if any of these strings appear in shipped code, the oracle (or its Debian
# fixture) has leaked into the Alpine product. rc 0 = clean, rc 1 = leaks
# (printed). Text files only (-I); hits name file + line.
interop_scope_check() {
    local tree="${1:-$(cd "$_INTEROP_HERE/.." && pwd)/..}"
    tree=$(cd "$tree" 2>/dev/null && pwd) || {
        echo "interop-scope: tree not found: $1" >&2
        return 64
    }
    local leaks
    leaks=$(grep -rInE 'bwrap|bubblewrap|rootfs-fixture|interop-oracle|deb\.debian\.org|cloud\.debian\.org|debian-13' \
        "$tree/bin" "$tree/lib" "$tree/hooks" 2>/dev/null || true)
    if [[ -n "$leaks" ]]; then
        echo "interop-scope: SHIPPED paths carry oracle/Debian-runtime references (ADR-19 violation):" >&2
        printf '%s\n' "$leaks" >&2
        return 1
    fi
    return 0
}
