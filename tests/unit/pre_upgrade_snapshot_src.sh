#!/usr/bin/env bash
# tests/unit/pre_upgrade_snapshot_src.sh — pin the btrfs snapshot SOURCE
# resolution of `alpine-fde pre-upgrade` (lib/cmd/pre-upgrade.sh,
# _pu_snapshot_src). RED-first for the queue-30 live finding: the §9.1 layout
# mounts subvol=@ AS /, and the pre-fix logic took the snapshot source from
# mountinfo's FS-ROOT field ("/@") — a path that does not exist inside the
# @ mount's own namespace, so every in-guest snapshot failed closed (rc 64)
# on the exact layout the product installs (live: s01c live-ops leg,
# 2026-09-26). The pinned contract: the snapshot source is the root mount's
# MOUNT POINT (the snapper layout — snapshot the subvolume at the path where
# it is actually visible), never the fs-root field.
#
# Hermetic: fixture mountinfo files only, no TPM, no mounts.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/cmd/pre-upgrade.sh
. "$REPO/lib/cmd/pre-upgrade.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# §9.1-shaped mountinfo: the root mount IS the @ subvolume (fs-root /@)
cat >"$WORK/mountinfo-91" <<'EOF'
18 1 0:17 / / rw,relatime - overlay /dev/sda1 rw
36 25 0:34 /@ / rw,relatime,space_cache=v2,subvolid=256,subvol=/@ - btrfs /dev/mapper/root rw,ssd
37 36 0:34 /@home /home rw,relatime,subvolid=257,subvol=/@home - btrfs /dev/mapper/root rw,ssd
38 36 0:34 /@data /data rw,relatime,subvolid=258,subvol=/@data - btrfs /dev/mapper/root rw,ssd
EOF

# exotic-but-legal: the TOP-LEVEL btrfs volume mounted at / (fs-root "/")
cat >"$WORK/mountinfo-toplevel" <<'EOF'
36 25 0:34 / / rw,relatime,space_cache=v2,subvolid=5 - btrfs /dev/mapper/root rw,ssd
EOF

# non-btrfs root: the helper must report "no resolution" (the caller then
# skips gracefully — pre-upgrade's ext4 skip path)
cat >"$WORK/mountinfo-ext4" <<'EOF'
36 25 0:34 / / rw,relatime - ext4 /dev/vdb rw
EOF

# contract 1 — the §9.1 layout (fs-root /@, mounted at /): the snapshot
# source is the MOUNT POINT "/", never the fs-root "/@"
SRC=$(_pu_snapshot_src "$WORK/mountinfo-91" "/")
assert_eq "pre-upgrade source (§9.1: subvol=@ mounted as /) is the mount point /" \
    "/" "$SRC"

# contract 2 — a nested-root mount (ALPINE_FDE_ROOT=/data, subvol mounted
# there): the source is THAT mount point
SRC=$(_pu_snapshot_src "$WORK/mountinfo-91" "/data/")
assert_eq "pre-upgrade source (subvol mounted at /data) is /data" \
    "/data" "$SRC"

# contract 3 — top-level volume mounted at /: the mount point IS the source
SRC=$(_pu_snapshot_src "$WORK/mountinfo-toplevel" "/")
assert_eq "pre-upgrade source (top-level volume at /) is /" "/" "$SRC"

# contract 4 — no btrfs root mount: rc 1 = no resolution (the caller's
# graceful ext4 skip), never a bogus path
OUT=$(_pu_snapshot_src "$WORK/mountinfo-ext4" "/")
assert_rc "pre-upgrade source: non-btrfs root resolves to nothing (rc 1)" 1 \
    _pu_snapshot_src "$WORK/mountinfo-ext4" "/"
assert_eq "pre-upgrade source: non-btrfs root prints no path" "" "$OUT"

# contract 5 — missing mountinfo: rc 1, no crash
assert_rc "pre-upgrade source: missing mountinfo is rc 1 (graceful)" 1 \
    _pu_snapshot_src "$WORK/mountinfo-absent" "/"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# pre_upgrade_snapshot_src: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
