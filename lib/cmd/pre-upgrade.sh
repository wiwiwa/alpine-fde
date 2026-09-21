#!/bin/sh
# pre-upgrade.sh — `debian-fde pre-upgrade`: optional root-filesystem snapshot
# before upgrades (§8.1; C-G16). Btrfs is the default root (ADR-13, §4): take
# a READ-ONLY snapshot of the root subvolume into /.snapshots/<UTC-timestamp>
# (the @snapshots mount, §9.1 layout; UserGuide §4 rollback flow). ext4 roots
# (available via --fs ext4) skip gracefully — rc 0.

if [ -n "${DEBIAN_FDE_PREUPGRADE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_PREUPGRADE_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

cmd_pre_upgrade_main() {
    strict_mode

    case ${1:-} in
        -h | --help)
            cat >&2 <<'EOF'
Usage: debian-fde pre-upgrade

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
    [ $# -eq 0 ] || die -r "$DEBIAN_FDE_USAGE" "pre-upgrade: unexpected arguments: $*"
    # Root fstype detection (DEBIAN_FDE_ROOT_FSTYPE overrides, for tests).
    # G-D9: derive the fstype from /proc/self/mountinfo FIRST — busybox stat
    # (the §3.1 Alpine host toolchain) has no `-f -c %T`, so a stat-first probe
    # degrades to `unknown` and silently skips every btrfs snapshot. `stat -f`
    # is only the FALLBACK (non-Linux mounts absent from mountinfo); the result
    # and its source are announced loudly either way.
    # IN-03: like every other command, honor --root/DEBIAN_FDE_ROOT — detect the
    # TARGET root, not unconditionally the live /.
    _pu_mif=${DEBIAN_FDE_MOUNTINFO:-/proc/self/mountinfo}
    if [ -n "${DEBIAN_FDE_ROOT_FSTYPE:-}" ]; then
        _pu_fstype=$DEBIAN_FDE_ROOT_FSTYPE
        _pu_fssrc=override
    else
        _pu_root=${DEBIAN_FDE_ROOT:-}
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
    _pu_snapdir=${DEBIAN_FDE_ROOT:-}/.snapshots
    if [ ! -d "$_pu_snapdir" ]; then
        err "pre-upgrade: $_pu_snapdir missing — expected the §9.1 layout with the @snapshots subvolume mounted at /.snapshots"
        return "$DEBIAN_FDE_FAIL_CLOSED"
    fi
    # Source subvolume path: the live mounted layout wins (/proc/self/mountinfo
    # fs-root of the root mount, e.g. /@); fall back to the fstab subvol=
    # option; default /@ (the §4 standard layout). The DEBIAN_FDE_ROOT_FSTYPE
    # test seam pins the default so stub tests assert a deterministic argv.
    _pu_src=/@
    if [ -z "${DEBIAN_FDE_ROOT_FSTYPE:-}" ]; then
        _pu_mi=$(awk -v mp="${DEBIAN_FDE_ROOT:-}/" '{
            fs = ""
            for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break }
            if ($5 == mp && fs == "btrfs") { print $4; exit }
        }' /proc/self/mountinfo 2>/dev/null) || _pu_mi=""
        if [ -n "$_pu_mi" ]; then
            _pu_src=$_pu_mi
        else
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
            }' "${DEBIAN_FDE_ROOT:-}/etc/fstab" 2>/dev/null) || _pu_sv=""
            if [ -n "$_pu_sv" ]; then
                _pu_src=$_pu_sv
            fi
        fi
    fi
    _pu_ts=$(date -u +%Y%m%dT%H%M%SZ)
    _pu_snap="$_pu_snapdir/$_pu_ts"
    if ! btrfs subvolume snapshot -r "$_pu_src" "$_pu_snap"; then
        err "pre-upgrade: btrfs snapshot failed ($_pu_src -> $_pu_snap)"
        return "$DEBIAN_FDE_FAIL_CLOSED"
    fi
    printf '%s\n' "$_pu_snap"
    info "pre-upgrade: read-only snapshot created: $_pu_snap"
    return 0
}
