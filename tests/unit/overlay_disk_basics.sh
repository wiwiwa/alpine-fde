#!/usr/bin/env bash
# overlay_disk_basics.sh — unit pins for tests/lib/overlay-disk.sh's per-boot
# overlay contract (Wave-2 2b pilots s03/s12/s20):
#   * overlay_create yields an EMPTY QCOW2 backed onto the raw base (-F raw),
#     with LOCK_SH held on the chain until discard;
#   * a write into the overlay never reaches the base (the pristine-base
#     invariant every consumer boot relies on);
#   * overlay_discard unlinks the overlay AND releases the lock, so a fresh
#     overlay per attempt (create -> boot -> discard -> create again) works
#     against the SAME base — the s12 multi-attempt idiom;
#   * a missing base fails loudly (no silent empty overlay).
# Run under tests/run-unit.sh (bash); needs qemu-img/qemu-io/jq on PATH.

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/tests/lib/overlay-disk.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

base="$tmp/disk.img"
truncate -s 16M "$base"
printf 'magic' | dd of="$base" bs=1 seek=4096 conv=notrunc status=none

info() { qemu-img info --output=json -- "$1"; }

# --- create: empty QCOW2 over the raw base, lock held -------------------------
ov1="$tmp/boot1.qcow2"
rc=0; overlay_create "$base" "$ov1" || rc=$?
assert_rc "overlay_create over a raw base succeeds" 0 "$rc"
assert_eq "overlay backs onto the (resolved) raw base" "$(readlink -f "$base")" \
    "$(info "$ov1" | jq -r '."backing-filename"')"
assert_eq "backing format is raw (the -F raw contract)" "raw" \
    "$(info "$ov1" | jq -r '."backing-filename-format"')"
assert_eq "overlay virtual size == base size (no resize smuggled in)" \
    "$(stat -c%s "$base")" "$(info "$ov1" | jq -r '."virtual-size"')"
if (( ${#OVERLAY_LOCK_FDS[@]} > 0 )); then
    _pass "create holds a LOCK_SH fd on the chain (OVERLAY_LOCK_FDS non-empty)"
else
    _fail "create holds a LOCK_SH fd on the chain (OVERLAY_LOCK_FDS empty)"
fi

# --- isolation: an overlay write never reaches the base -----------------------
qemu-io -c "write -P 0xaa 0 64k" "$ov1" >/dev/null 2>&1
assert_eq "base bytes untouched by an overlay write (pristine-base invariant)" \
    "magic" "$(dd if="$base" bs=1 skip=4096 count=5 status=none)"

# --- discard: unlink + lock release; the next create on the SAME base works ---
overlay_discard "$ov1"
assert_eq "discard removed the overlay file" "" "$(ls "$tmp"/boot1.qcow2 2>/dev/null)"
assert_eq "discard released every chain fd (OVERLAY_LOCK_FDS empty)" "0" \
    "$(echo "${#OVERLAY_LOCK_FDS[@]}")"
ov2="$tmp/boot2.qcow2"
rc=0; overlay_create "$base" "$ov2" || rc=$?
assert_rc "fresh overlay per attempt: re-create on the same base succeeds post-discard" 0 "$rc"
overlay_discard "$ov2"

# --- loud failure on a missing base -------------------------------------------
rc=0; overlay_create "$tmp/absent.img" "$tmp/x.qcow2" 2>/dev/null || rc=$?
assert_rc "overlay_create on a missing base fails loudly (rc 1)" 1 "$rc"
assert_eq "no overlay left behind by the failed create" "" \
    "$(ls "$tmp"/x.qcow2 2>/dev/null)"

finish
