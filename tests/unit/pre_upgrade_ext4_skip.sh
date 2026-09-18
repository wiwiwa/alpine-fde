#!/usr/bin/env bash
# tests/unit/pre_upgrade_ext4_skip.sh — `debian-fde pre-upgrade` (§8.1, ADR-13):
# Btrfs is the DEFAULT root (ADR-13, §4), so a btrfs root must produce a real
# READ-ONLY snapshot — `btrfs subvolume snapshot -r /@ /.snapshots/<UTC-ts>`
# (source per the mounted subvol layout; target under the @snapshots mount,
# §9.1) — rc 0, naming the created snapshot. A missing /.snapshots is a loud
# 64 with the layout hint (not a silent rc 3). ext4 and unknown roots keep the
# graceful rc-0 skip (message unchanged).
# Seams: DEBIAN_FDE_ROOT_FSTYPE overrides `stat -f` detection for tests;
# `btrfs` is a PATH stub recording argv and materializing the snapshot dir.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

run_pu() { # FSTYPE — drive the real handler with the fstype seam
    PU_OUT=$(DEBIAN_FDE_ROOT_FSTYPE="$1" "$REPO/bin/debian-fde" pre-upgrade 2>&1)
    PU_RC=$?
}

# --- 1. ext4 (the old default) -> graceful skip, rc 0 ---------------------------
run_pu ext4
assert_eq "ext4 root -> rc 0 (skip, not a failure)" "0" "$PU_RC"
assert_contains "skip message cites ADR-13" "$PU_OUT" "skipped (ext4 root; snapshots need btrfs, ADR-13)"

# --- 2. other non-btrfs roots skip the same way ------------------------------------
run_pu unknown
assert_eq "unknown fstype -> rc 0 (skip)" "0" "$PU_RC"
assert_contains "skip message names the fstype" "$PU_OUT" "skipped (unknown root; snapshots need btrfs, ADR-13)"

# --- 3. btrfs (the DEFAULT root) -> read-only snapshot, rc 0 ------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
FAKEBIN="$TMP/bin"
ROOT="$TMP/root"
mkdir -p "$FAKEBIN" "$ROOT/.snapshots"
# Stub btrfs: record the full argv (path via $BTRFS_LOG) and materialize any
# /.snapshots/<ts> target, so the success leg proves the exact invocation.
cat >"$FAKEBIN/btrfs" <<'EOF'
#!/bin/sh
[ -n "${BTRFS_LOG:-}" ] && printf '%s\n' "$*" >>"$BTRFS_LOG"
for a in "$@"; do
    case $a in */.snapshots/*) mkdir -p "$a" ;; esac
done
exit 0
EOF
chmod +x "$FAKEBIN/btrfs"

PU_OUT=$(PATH="$FAKEBIN:$PATH" BTRFS_LOG="$TMP/btrfs.argv" DEBIAN_FDE_ROOT="$ROOT" \
    DEBIAN_FDE_ROOT_FSTYPE=btrfs "$REPO/bin/debian-fde" pre-upgrade 2>&1)
PU_RC=$?
assert_eq "btrfs root -> rc 0 (snapshot created)" "0" "$PU_RC"
assert_eq "btrfs invoked exactly once" "1" "$(wc -l <"$TMP/btrfs.argv")"
ARGV=$(sed -n '1p' "$TMP/btrfs.argv")
assert_eq "btrfs argv: subcommand + read-only form" "subvolume snapshot -r" \
    "$(printf '%s' "$ARGV" | cut -d' ' -f1-3)"
assert_contains "btrfs argv: read-only flag present" "$ARGV" " -r "
TS=$(cd "$ROOT/.snapshots" && ls)
assert_eq "timestamp shape: UTC YYYYMMDDTHHMMSSZ" "ok" \
    "$(printf '%s' "$TS" | grep -qE '^[0-9]{8}T[0-9]{6}Z$' && echo ok || echo bad)"
assert_eq "btrfs argv: exact (subvolume snapshot -r /@ <root>/.snapshots/<ts>)" \
    "subvolume snapshot -r /@ $ROOT/.snapshots/$TS" "$ARGV"
assert_contains "output names the created snapshot path" "$PU_OUT" "$ROOT/.snapshots/$TS"
assert_file_exists "snapshot materialized under /.snapshots/<ts>" "$ROOT/.snapshots/$TS"

# --- 4. btrfs with /.snapshots missing -> loud 64 with the §9.1 layout hint ----------
ROOT2="$TMP/root2"
mkdir -p "$ROOT2"
PU_OUT=$(PATH="$FAKEBIN:$PATH" BTRFS_LOG="$TMP/btrfs2.argv" DEBIAN_FDE_ROOT="$ROOT2" \
    DEBIAN_FDE_ROOT_FSTYPE=btrfs "$REPO/bin/debian-fde" pre-upgrade 2>&1)
PU_RC=$?
assert_eq "missing /.snapshots -> loud 64 (not rc 3)" "64" "$PU_RC"
assert_contains "64 message cites the §9.1 layout (@snapshots at /.snapshots)" "$PU_OUT" "@snapshots"
assert_eq "missing /.snapshots: btrfs never invoked" "" "$(cat "$TMP/btrfs2.argv" 2>/dev/null)"

# --- 5. help text: purpose, snapshot path, retention note ----------------------------
PU_OUT=$("$REPO/bin/debian-fde" pre-upgrade --help 2>&1)
PU_RC=$?
assert_eq "--help -> rc 0" "0" "$PU_RC"
assert_contains "help names the snapshot path" "$PU_OUT" "/.snapshots/<"
assert_contains "help carries the retention note" "$PU_OUT" "never pruned automatically"
assert_contains "help points at the delete verb" "$PU_OUT" "btrfs subvolume delete"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
