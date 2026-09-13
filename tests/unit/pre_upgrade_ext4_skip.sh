#!/usr/bin/env bash
# tests/unit/pre_upgrade_ext4_skip.sh — `debian-fde pre-upgrade` (G-U10, §8.1/
# ADR-13): ext4 is the DEFAULT root, so a non-btrfs root must be a graceful
# no-op (info "skipped ...", rc 0) — a rc-3 NOT_IMPLEMENTED there is a false
# failure. btrfs roots keep the honest rc 3 (snapshots unimplemented).
# Seam: DEBIAN_FDE_ROOT_FSTYPE overrides the `stat -f` detection for tests.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

run_pu() { # FSTYPE — drive the real handler with the fstype seam
    PU_OUT=$(DEBIAN_FDE_ROOT_FSTYPE="$1" "$REPO/bin/debian-fde" pre-upgrade 2>&1)
    PU_RC=$?
}

# --- 1. ext4 (the default root) -> graceful skip, rc 0 ---------------------------
run_pu ext4
assert_eq "ext4 root -> rc 0 (skip, not a failure)" "0" "$PU_RC"
assert_contains "skip message cites ADR-13" "$PU_OUT" "skipped (ext4 root; snapshots need btrfs, ADR-13)"

# --- 2. other non-btrfs roots skip the same way ------------------------------------
run_pu unknown
assert_eq "unknown fstype -> rc 0 (skip)" "0" "$PU_RC"
assert_contains "skip message names the fstype" "$PU_OUT" "skipped (unknown root; snapshots need btrfs, ADR-13)"

# --- 3. btrfs -> honest not-implemented, rc 3 (unchanged) ---------------------------
run_pu btrfs
assert_eq "btrfs root -> rc 3 (not implemented)" "3" "$PU_RC"
assert_contains "btrfs message says snapshots unimplemented" "$PU_OUT" "not implemented"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
