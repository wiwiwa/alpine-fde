#!/usr/bin/env bash
# tests/unit/pre_upgrade_auto_retain.sh — user decision item 9: the LIB-LEVEL
# auto-snapshot + keep-N retention flow (lib/cmd/pre-upgrade.sh
# pu_auto_snapshot_main / _pu_auto_retain) that the apk auto-snapshot trigger
# (hooks/apk/triggers/alpine-fde-snapshot.trigger) calls:
#
#   * gate: ONLY on a btrfs root mount carrying the @ subvolume (§4/§9.1);
#     non-btrfs roots and foreign subvolumes degrade quietly (rc 0, logged)
#   * snapshot: read-only (`btrfs subvolume snapshot -r`), tagged
#     `alpine-fde-auto-<UTC-timestamp>`, into <root>/.snapshots; the printed
#     stdout contract is exactly the snapshot path
#   * retention: keep the newest ALPINE_FDE_SNAPSHOT_KEEP (default 5)
#     alpine-fde-auto-* snapshots, `btrfs subvolume delete` the older excess;
#     MANUAL snapshots (any other name) are never touched; a failed delete is
#     over-retention (warn), never a lost snapshot
#   * fail-closed (rc 64): a btrfs root with /.snapshots missing, or a failed
#     `btrfs subvolume snapshot` — the lost rollback point is announced loudly
#   * same-second transactions: the second snapshot gets a -N suffix, never
#     clobbers the first
#   * invalid ALPINE_FDE_SNAPSHOT_KEEP falls back to the default 5
#
# Hermetic: fixture mountinfo + PATH-stubbed btrfs that SIMULATES snapshots
# (mkdir the destination, record every argv); no TPM, no mounts.

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
ROOT=$WORK/root
trap 'rm -rf "$WORK"' EXIT

# §9.1-shaped mountinfo: subvol=/@ mounted AS the root (queue-30 contract:
# the snapshot source is the MOUNT POINT, never the fs-root field)
cat >"$WORK/mountinfo-91" <<EOF
18 1 0:17 / / rw,relatime - overlay /dev/sda1 rw
36 25 0:34 /@ $ROOT rw,relatime,space_cache=v2,subvolid=256,subvol=/@ - btrfs /dev/mapper/root rw,ssd
37 36 0:34 /@home $ROOT/home rw,relatime,subvolid=257,subvol=/@home - btrfs /dev/mapper/root rw,ssd
EOF

# same layout, but the mounted root subvolume is NOT @ (foreign layout)
cat >"$WORK/mountinfo-foreign" <<EOF
36 25 0:34 /@legacy $ROOT rw,relatime,subvolid=256,subvol=/@legacy - btrfs /dev/mapper/root rw,ssd
EOF

# non-btrfs root (ext4 via --fs ext4)
cat >"$WORK/mountinfo-ext4" <<EOF
36 25 0:34 / $ROOT rw,relatime - ext4 /dev/vdb rw
EOF

# --- btrfs stub: simulate snapshot/delete, record argv --------------------------
mkdir -p "$WORK/stub" "$ROOT/.snapshots"
cat >"$WORK/stub/btrfs" <<'EOF'
#!/bin/sh
printf '%s\n' "btrfs $*" >>"${BTRFS_LOG:?}"
case "$1$2" in
    subvolumesnapshot) mkdir -p "$5" ;;   # snapshot -r SRC DEST ($5)
    subvolumedelete) rm -rf "$3" ;;       # delete DEST
esac
exit 0
EOF
chmod +x "$WORK/stub/btrfs"
BTRFS_LOG=$WORK/btrfs.log
export BTRFS_LOG

run_main() { # [EXTRA env via caller] -> stdout; rc in $?; stderr -> $WORK/err.log
    ALPINE_FDE_MOUNTINFO=$WORK/mountinfo-91 ALPINE_FDE_ROOT=$ROOT \
        ALPINE_FDE_SNAPSHOT_KEEP=${ALPINE_FDE_SNAPSHOT_KEEP:-5} \
        PATH="$WORK/stub:$PATH" pu_auto_snapshot_main 2>"$WORK/err.log"
}

new_snap() { # NAME — pre-existing auto snapshot (a plain dir stands in)
    mkdir -p "$ROOT/.snapshots/$1"
}
reset_snaps() {
    rm -rf "$ROOT/.snapshots" && mkdir -p "$ROOT/.snapshots"; : >"$BTRFS_LOG"
}
auto_names() { # -> alpine-fde-auto-* names, oldest first
    ( cd "$ROOT/.snapshots" && ls -1d alpine-fde-auto-* 2>/dev/null ) | sort
}

# =============================================================================
# gate: degrade quietly (rc 0) off the §9.1 btrfs-@ layout
# =============================================================================
OUT=$(ALPINE_FDE_MOUNTINFO=$WORK/mountinfo-ext4 ALPINE_FDE_ROOT=$ROOT \
    PATH="$WORK/stub:$PATH" pu_auto_snapshot_main 2>"$WORK/err.log"); RC=$?
assert_eq "ext4 root: graceful skip rc 0" "0" "$RC"
assert_eq "ext4 root: no snapshot attempted" "" "$OUT"
assert_eq "ext4 root: skip is announced (the degrade line)" "1" \
    "$(grep -c "skipped" "$WORK/err.log")"

OUT=$(ALPINE_FDE_MOUNTINFO=$WORK/mountinfo-foreign ALPINE_FDE_ROOT=$ROOT \
    PATH="$WORK/stub:$PATH" pu_auto_snapshot_main 2>"$WORK/err.log"); RC=$?
assert_eq "foreign-subvol root: graceful skip rc 0" "0" "$RC"
assert_eq "foreign-subvol root: no snapshot attempted" "" "$OUT"
assert_contains "foreign-subvol root: skip names the /@ gate" \
    "$(cat "$WORK/err.log")" "not /@"

OUT=$(ALPINE_FDE_MOUNTINFO=$WORK/absent ALPINE_FDE_ROOT=$ROOT \
    PATH="$WORK/stub:$PATH" pu_auto_snapshot_main 2>/dev/null); RC=$?
assert_eq "missing mountinfo: graceful skip rc 0" "0" "$RC"
assert_eq "missing mountinfo: no snapshot attempted" "" "$OUT"

# =============================================================================
# happy path: read-only, tagged, /.snapshots, path printed, source = the mount
# =============================================================================
reset_snaps
OUT=$(run_main); RC=$?
assert_eq "happy path: rc 0" "0" "$RC"
assert_contains "happy path: stdout is exactly the tagged snapshot path" \
    "$(printf '%s' "$OUT" | sed 's#.*/##')" "alpine-fde-auto-"
assert_eq "happy path: snapshot lands under <root>/.snapshots" "$ROOT/.snapshots" \
    "$(dirname "$OUT")"
assert_eq "happy path: exactly one btrfs call (no delete at keep 5 / 1 snap)" "1" \
    "$(wc -l <"$BTRFS_LOG" | tr -d ' ')"
assert_contains "snapshot source is the root MOUNT POINT" "$(cat "$BTRFS_LOG")" \
    "snapshot -r $ROOT "
assert_contains "snapshot is read-only (-r)" "$(cat "$BTRFS_LOG")" "snapshot -r"
assert_contains "creation announced with the keep-N" "$(cat "$WORK/err.log")" "keep 5"

# =============================================================================
# retention: keep-N — N existing + this one => the oldest is deleted, N kept
# =============================================================================
reset_snaps
new_snap alpine-fde-auto-20260101T000000Z
new_snap alpine-fde-auto-20260102T000000Z
new_snap alpine-fde-auto-20260103T000000Z
new_snap pre-upgrade-20260104T000000Z   # a MANUAL snapshot — never touched
ALPINE_FDE_SNAPSHOT_KEEP=2
OUT=$(run_main); RC=$?
unset ALPINE_FDE_SNAPSHOT_KEEP
assert_eq "keep-2: rc 0" "0" "$RC"
assert_eq "keep-2: ends at exactly 2 auto snapshots" "2" \
    "$(auto_names | wc -l | tr -d ' ')"
assert_eq "keep-2: the two NEWEST are kept" \
    "alpine-fde-auto-20260103T000000Z
$(printf '%s' "$OUT" | sed 's#.*/##')" "$(auto_names)"
assert_contains "keep-2: the OLDEST was btrfs-deleted" "$(cat "$BTRFS_LOG")" \
    "delete $ROOT/.snapshots/alpine-fde-auto-20260101T000000Z"
assert_not_contains "keep-2: the manual snapshot is never touched" \
    "$(cat "$BTRFS_LOG")" "pre-upgrade-20260104T000000Z"

# boundary: fewer than N existing => nothing deleted
reset_snaps
new_snap alpine-fde-auto-20260101T000000Z
new_snap alpine-fde-auto-20260102T000000Z
ALPINE_FDE_SNAPSHOT_KEEP=3
_ignore=$(run_main)
unset ALPINE_FDE_SNAPSHOT_KEEP
assert_eq "boundary: 2 existing + 1 new, keep-3 => nothing deleted" "0" \
    "$(grep -c " delete " "$BTRFS_LOG")"
assert_eq "boundary: all 3 present" "3" "$(auto_names | wc -l | tr -d ' ')"

# default: NO ALPINE_FDE_SNAPSHOT_KEEP => default 5
reset_snaps
for d in 1 2 3 4 5 6 7; do
    new_snap "alpine-fde-auto-2026010${d}T000000Z"
done
ALPINE_FDE_SNAPSHOT_KEEP=
_ignore=$(run_main)
unset ALPINE_FDE_SNAPSHOT_KEEP
assert_eq "default keep: 8 -> 5 (the shipped default)" "5" \
    "$(auto_names | wc -l | tr -d ' ')"

# invalid keep value: falls back to the default, never a crash
reset_snaps
for d in 1 2 3 4 5 6 7 8 9; do
    new_snap "alpine-fde-auto-2026010${d}T000000Z"
done
ALPINE_FDE_SNAPSHOT_KEEP=bananas
OUT=$(run_main); RC=$?
unset ALPINE_FDE_SNAPSHOT_KEEP
assert_eq "invalid keep: rc 0 (snapshot still taken)" "0" "$RC"
assert_eq "invalid keep: default 5 applied" "5" \
    "$(auto_names | wc -l | tr -d ' ')"

# =============================================================================
# fail-closed: missing /.snapshots on a btrfs-@ root; failed snapshot cmd
# =============================================================================
rm -rf "$ROOT/.snapshots"
OUT=$(run_main); RC=$?
assert_eq "missing /.snapshots: fail-closed rc 64" "64" "$RC"
assert_eq "missing /.snapshots: no path printed" "" "$OUT"
assert_contains "missing /.snapshots: loud diagnosis" "$(cat "$WORK/err.log")" \
    "FAILED"

# failed `btrfs subvolume snapshot`: rc 64, loud
mkdir -p "$ROOT/.snapshots"
printf '#!/bin/sh\nexit 1\n' >"$WORK/stub/btrfs"
chmod +x "$WORK/stub/btrfs"
OUT=$(run_main); RC=$?
assert_eq "failed btrfs snapshot: fail-closed rc 64" "64" "$RC"
assert_eq "failed btrfs snapshot: no path printed" "" "$OUT"
assert_contains "failed btrfs snapshot: loud diagnosis" "$(cat "$WORK/err.log")" \
    "FAILED"

# failed retention delete: snapshot kept, warn (over-retention), rc 0
cat >"$WORK/stub/btrfs" <<'EOF'
#!/bin/sh
printf '%s\n' "btrfs $*" >>"${BTRFS_LOG:?}"
case "$1$2" in
    subvolumesnapshot) mkdir -p "$5" ;;
    subvolumedelete) exit 1 ;;   # the prune always fails
esac
exit 0
EOF
chmod +x "$WORK/stub/btrfs"
new_snap alpine-fde-auto-20260101T000000Z   # an older auto snapshot: creates
# a real excess (count 2 > keep 1) so the prune actually attempts a delete
ALPINE_FDE_SNAPSHOT_KEEP=1
OUT=$(run_main); RC=$?
unset ALPINE_FDE_SNAPSHOT_KEEP
assert_eq "failed prune: rc 0 (the snapshot itself succeeded)" "0" "$RC"
assert_contains "failed prune: path still printed" \
    "$(printf '%s' "$OUT" | sed 's#.*/##')" "alpine-fde-auto-"
assert_contains "failed prune: over-retention warn" "$(cat "$WORK/err.log")" \
    "retention prune failed"

# =============================================================================
# same-second transactions: no clobber — the collision gets a -N suffix
# (deterministic: a stub `date` pins the timestamp the lib will stamp)
# =============================================================================
reset_snaps
TS=20260929T120000Z
mkdir -p "$WORK/stub2"
printf '#!/bin/sh\necho %s\n' "$TS" >"$WORK/stub2/date"
chmod +x "$WORK/stub2/date"
mkdir -p "$ROOT/.snapshots/alpine-fde-auto-$TS"   # occupy the pinned second
OUT=$(ALPINE_FDE_MOUNTINFO=$WORK/mountinfo-91 ALPINE_FDE_ROOT=$ROOT \
    ALPINE_FDE_SNAPSHOT_KEEP=5 PATH="$WORK/stub2:$WORK/stub:$PATH" \
    pu_auto_snapshot_main 2>"$WORK/err.log"); RC=$?
assert_eq "same-second collision: rc 0" "0" "$RC"
assert_eq "same-second collision: -1 suffix, never a clobber" \
    "alpine-fde-auto-$TS-1" "$(printf '%s' "$OUT" | sed 's#.*/##')"
assert_eq "same-second collision: both snapshots exist" "2" \
    "$(auto_names | wc -l | tr -d ' ')"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# pre_upgrade_auto_retain: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
