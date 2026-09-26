#!/bin/sh
# pre-upgrade.sh — `alpine-fde pre-upgrade`: optional root-filesystem snapshot
# before upgrades (§8.1; C-G16). Btrfs is the default root (ADR-13, §4): take
# a READ-ONLY snapshot of the root subvolume into /.snapshots/<UTC-timestamp>
# (the @snapshots mount, §9.1 layout; UserGuide §4 rollback flow). ext4 roots
# (available via --fs ext4) skip gracefully — rc 0.

if [ -n "${ALPINE_FDE_PREUPGRADE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_PREUPGRADE_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

# _pu_snapshot_src MOUNTINFO ROOT — resolve the btrfs snapshot SOURCE for
# the root mount from mountinfo. Prints the path + rc 0 when the root mount
# is btrfs; rc 1 (no path) = no resolution, the caller falls back.
#
# THE CONTRACT (queue-30 live finding, s01c live-ops leg 2026-09-26): the
# §9.1 layout mounts subvol=@ AS /, and mountinfo's FS-ROOT field for that
# mount reads "/@" — the subvolume's path in the FILESYSTEM's namespace.
# From INSIDE the mount the same subvolume is visible at the MOUNT POINT;
# "/@" does not exist inside the @ mount, so snapshotting the fs-root path
# failed closed on the exact layout the product installs. The snapshot
# source is therefore always the mount point (the snapper layout: snapshot
# the subvolume at the path where it is actually visible).
_pu_snapshot_src() {
    _pss_mif=$1 _pss_root=$2
    _pss_mp=${_pss_root%/}
    [ -n "$_pss_mp" ] || _pss_mp=/
    _pss_fstype=$(awk -v mp="$_pss_mp" '{
        fs = ""
        for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break }
        if ($5 == mp && fs == "btrfs") { print fs; exit }
    }' "$_pss_mif" 2>/dev/null) || _pss_fstype=""
    [ "$_pss_fstype" = "btrfs" ] || return 1
    # the mount point IS the subvolume (the §9.1 layout mounts subvol=@ as /)
    printf '%s\n' "$_pss_mp"
    return 0
}

cmd_pre_upgrade_main() {
    strict_mode

    case ${1:-} in
        -h | --help)
            cat >&2 <<'EOF'
Usage: alpine-fde pre-upgrade

Snapshot the root filesystem before upgrades (§8.1). On a btrfs root this
creates a read-only snapshot of the root subvolume under
/.snapshots/<UTC-timestamp> (the @snapshots subvolume, §9.1 layout); a broken
upgrade is rolled back from there (UserGuide §4). Snapshots are never pruned automatically —
remove old ones with `btrfs subvolume delete`.
Non-btrfs roots (ext4) skip gracefully — rc 0.
EOF
            return 0
            ;;
    esac
    [ $# -eq 0 ] || die -r "$ALPINE_FDE_USAGE" "pre-upgrade: unexpected arguments: $*"
    # Root fstype detection (ALPINE_FDE_ROOT_FSTYPE overrides, for tests).
    # G-D9: derive the fstype from /proc/self/mountinfo FIRST — busybox stat
    # (the §3.1 Alpine host toolchain) has no `-f -c %T`, so a stat-first probe
    # degrades to `unknown` and silently skips every btrfs snapshot. `stat -f`
    # is only the FALLBACK (non-Linux mounts absent from mountinfo); the result
    # and its source are announced loudly either way.
    # IN-03: like every other command, honor --root/ALPINE_FDE_ROOT — detect the
    # TARGET root, not unconditionally the live /.
    _pu_mif=${ALPINE_FDE_MOUNTINFO:-/proc/self/mountinfo}
    if [ -n "${ALPINE_FDE_ROOT_FSTYPE:-}" ]; then
        _pu_fstype=$ALPINE_FDE_ROOT_FSTYPE
        _pu_fssrc=override
    else
        _pu_root=${ALPINE_FDE_ROOT:-}
        # mountinfo mount points carry no trailing slash (except the root "/")
        _pu_mp=${_pu_root%/}
        [ -n "$_pu_mp" ] || _pu_mp=/
        _pu_fstype=$(awk -v mp="$_pu_mp" '{
            fs = ""
            for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break }
            if ($5 == mp && fs != "") { print fs; exit }
        }' "$_pu_mif" 2>/dev/null) || _pu_fstype=""
        if [ -n "$_pu_fstype" ]; then
            _pu_fssrc=mountinfo
        else
            _pu_fstype=$(stat -f -c %T "${_pu_root:-/}/" 2>/dev/null) || _pu_fstype=unknown
            [ -n "$_pu_fstype" ] || _pu_fstype=unknown
            _pu_fssrc=stat
        fi
    fi
    # G-D9: loud either way — never degrade silently to an unchecked fstype.
    info "pre-upgrade: root fstype: $_pu_fstype ($_pu_fssrc)"
    # ext4 (and unknown) roots are a graceful no-op: reporting them as
    # failures would flag every `--fs ext4` install. Only btrfs snapshots.
    if [ "$_pu_fstype" != "btrfs" ]; then
        info "pre-upgrade: skipped ($_pu_fstype root; snapshots need btrfs, ADR-13)"
        return 0
    fi

    # btrfs root: read-only snapshot of the root subvolume into /.snapshots.
    require_cmds btrfs
    _pu_snapdir=${ALPINE_FDE_ROOT:-}/.snapshots
    if [ ! -d "$_pu_snapdir" ]; then
        err "pre-upgrade: $_pu_snapdir missing — expected the §9.1 layout with the @snapshots subvolume mounted at /.snapshots"
        return "$ALPINE_FDE_FAIL_CLOSED"
    fi
    # Source subvolume path: resolved by _pu_snapshot_src (the root mount's
    # MOUNT POINT — see the helper's contract comment); the fstab subvol=
    # option is the last resort when mountinfo carries no btrfs root mount
    # (practically unreachable: the fstype gate above already required a
    # btrfs root). The ALPINE_FDE_ROOT_FSTYPE test seam pins the default so
    # stub tests assert a deterministic argv.
    _pu_src=${ALPINE_FDE_ROOT:-}/
    [ "$_pu_src" = "/" ] || _pu_src=${_pu_src%/}
    if [ -z "${ALPINE_FDE_ROOT_FSTYPE:-}" ]; then
        if ! _pu_src=$(_pu_snapshot_src "${ALPINE_FDE_MOUNTINFO:-/proc/self/mountinfo}" "${ALPINE_FDE_ROOT:-}"); then
            _pu_src=""
            _pu_sv=$(awk '!/^[[:space:]]*#/ && $4 ~ /subvol=/ {
                n = split($4, o, ",")
                for (i = 1; i <= n; i++) {
                    p = index(o[i], "subvol=")
                    if (p > 0) {
                        sv = substr(o[i], p + 7)
                        if (sv !~ /^\//) sv = "/" sv
                        print sv
                        exit
                    }
                }
            }' "${ALPINE_FDE_ROOT:-}/etc/fstab" 2>/dev/null) || _pu_sv=""
            if [ -n "$_pu_sv" ]; then
                _pu_src=$_pu_sv
            fi
        fi
    fi
    _pu_ts=$(date -u +%Y%m%dT%H%M%SZ)
    _pu_snap="$_pu_snapdir/$_pu_ts"
    # btrfs prints its own "Create a readonly snapshot ..." line on STDOUT —
    # silence it: this command's stdout contract is exactly the snapshot path
    # (a scripting consumer does SNAP=$(alpine-fde pre-upgrade); queue 30).
    if ! btrfs subvolume snapshot -r "$_pu_src" "$_pu_snap" >/dev/null; then
        err "pre-upgrade: btrfs snapshot failed ($_pu_src -> $_pu_snap)"
        return "$ALPINE_FDE_FAIL_CLOSED"
    fi
    printf '%s\n' "$_pu_snap"
    info "pre-upgrade: read-only snapshot created: $_pu_snap"
    return 0
}
