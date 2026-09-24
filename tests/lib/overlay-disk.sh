#!/usr/bin/env bash
# tests/lib/overlay-disk.sh — EPHEMERAL QCOW2 OVERLAY + BASE-IMAGE LOCKING for
# the e2e scenarios (Wave-2 2b, promoted into Wave-1 validation 2026-09-24).
#
# WHY: consumers boot a pristine base disk state (e.g. the s00b generator's
# enrolled state) without mutating it. Before overlays, every consumer either
# copied the base (run-dir pollution, prune pressure) or mutated it in place
# (a failed attempt destroyed the state for every later attempt). With a
# QCOW2 overlay per boot/attempt:
#   * the base stays pristine — a failed attempt is `rm <overlay>` (free);
#   * concurrent consumers cannot corrupt each other's base;
#   * the base is protected by LOCK_SH during every boot (and the generator
#     publishes rebuilt state under LOCK_EX + atomic mv — readers keep the
#     old inode, no lock needed for the final install).
#
# LOCKING CONTRACT:
#   * overlay_lock_acquire <base-img> — walks the whole backing chain
#     (qemu-img info) and takes LOCK_SH on EVERY parent file for the
#     current shell; the fds stay open in OVERLAY_LOCK_FDS until
#     overlay_lock_release. A boot holds the locks for its whole lifetime.
#   * overlay_publish <staging> <final> [lockdir] — LOCK_EX on
#     <lockdir>/<final>.lock (default: the final's directory), then atomic
#     `mv` — readers with the old inode open are never disturbed.
#   * deadlock safety: acquire parents outermost-first (the chain root is
#     locked before its overlay); release in reverse. Always pair acquire
#     with release (or let process exit release — the kernel drops flocks).
#
# qemu drive format: overlays are QCOW2; qemu_run passes the disk to qemu
# with a per-extension format (`.qcow2` -> qcow2, anything else -> raw) —
# base images stay raw, overlays are named *.qcow2.

if [[ -n "${_ALPINE_FDE_OVERLAY_DISK_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_OVERLAY_DISK_SOURCED=1

OVERLAY_LOCK_FDS=()

# _overlay_backing_chain <img> — print the image and every backing parent,
# base first (outermost). Uses qemu-img info; a raw/chain-less image yields
# just itself.
_overlay_backing_chain() {
    local img=$1 parent
    img=$(readlink -f -- "$img")
    local -a chain=("$img")
    local guard=0
    while ((guard < 8)); do
        guard=$((guard + 1))
        parent=$(qemu-img info --output=json -- "${chain[${#chain[@]} - 1]}" 2>/dev/null |
            jq -r '."backing-filename" // empty') || parent=""
        [[ -z "$parent" ]] && break
        parent=$(readlink -f -- "$parent")
        # cycle guard: a malformed chain must not spin
        [[ " ${chain[*]} " == *" $parent "* ]] && break
        chain+=("$parent")
    done
    printf '%s\n' "${chain[@]}"
}

# overlay_lock_acquire <base-img> — LOCK_SH every file of the backing chain
# (base first). Appends the acquired fds to OVERLAY_LOCK_FDS.
overlay_lock_acquire() {
    local img=$1 f
    while IFS= read -r f; do
        local fd
        exec {fd}<"$f" || {
            echo "overlay-lock: cannot open $f for LOCK_SH" >&2
            overlay_lock_release
            return 1
        }
        flock -s "$fd" || {
            echo "overlay-lock: LOCK_SH failed on $f" >&2
            exec {fd}<&-
            overlay_lock_release
            return 1
        }
        OVERLAY_LOCK_FDS+=("$fd")
    done < <(_overlay_backing_chain "$img")
    return 0
}

# overlay_lock_release — drop every lock acquired by overlay_lock_acquire.
overlay_lock_release() {
    local fd
    for fd in "${OVERLAY_LOCK_FDS[@]}"; do
        eval "exec ${fd}<&-" 2>/dev/null
    done
    OVERLAY_LOCK_FDS=()
}

# overlay_create <base-img> <out-img> — a QCOW2 overlay with <base-img>
# (raw) as its backing file. The overlay is empty until written.
overlay_create() {
    local base=$1 out=$2
    base=$(readlink -f -- "$base")
    qemu-img create -f qcow2 -b "$base" -F raw -- "$out" >/dev/null || return 1
    overlay_lock_acquire "$out"
}

# overlay_discard <out-img> — drop an attempt's overlay (release + unlink).
overlay_discard() {
    local out=$1
    overlay_lock_release
    rm -f -- "$out"
}

# overlay_publish <staging-img> <final-img> [lockdir] — LOCK_EX + atomic mv
# (the generator-side publish: readers keep the old inode; no lock needed on
# their side for the install instant).
overlay_publish() {
    local staging=$1 final=$2 lockdir=${3:-$(dirname "$2")}
    mkdir -p "$lockdir"
    local lockfile="$lockdir/$(basename "$final").lock"
    ( flock -x 9
      mv -f -- "$staging" "$final"
    ) 9>"$lockfile"
}
