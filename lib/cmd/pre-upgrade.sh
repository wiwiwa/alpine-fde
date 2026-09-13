#!/bin/sh
# pre-upgrade.sh — `debian-fde pre-upgrade`: optional root-filesystem snapshot
# before upgrades (§8.1; C-G16). v1 scope: STUB — Debian FDE installs use ext4
# roots (ADR-13); snapshots require btrfs (optional later). Detects the root
# filesystem type and says so; exits 3 (not implemented).

if [ -n "${DEBIAN_FDE_PREUPGRADE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_PREUPGRADE_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

cmd_pre_upgrade_main() {
    strict_mode

    case ${1:-} in
        -h | --help)
            cat >&2 <<'EOF'
Usage: debian-fde pre-upgrade

Snapshot the root filesystem before upgrades. btrfs-backed roots only
(§8.1); non-btrfs roots (the ext4 default) skip gracefully — rc 0.
Snapshot support itself is not implemented yet (btrfs roots: exit 3).
EOF
            return 0
            ;;
    esac
    [ $# -eq 0 ] || die -r "$DEBIAN_FDE_USAGE" "pre-upgrade: unexpected arguments: $*"
    # Root fstype detection (DEBIAN_FDE_ROOT_FSTYPE overrides, for tests).
    # IN-03: like every other command, honor --root/DEBIAN_FDE_ROOT — stat the
    # TARGET root, not unconditionally the live /.
    # ext4 is the DEFAULT root by design (ADR-13): a non-btrfs root is a
    # graceful no-op — reporting it as a NOT_IMPLEMENTED failure would flag
    # every default install. Only btrfs reaches the honest rc 3.
    if [ -n "${DEBIAN_FDE_ROOT_FSTYPE:-}" ]; then
        _pu_fstype=$DEBIAN_FDE_ROOT_FSTYPE
    else
        _pu_fstype=$(stat -f -c %T "${DEBIAN_FDE_ROOT:-}/" 2>/dev/null) || _pu_fstype=unknown
    fi
    if [ "$_pu_fstype" = "btrfs" ]; then
        err "pre-upgrade: root filesystem is btrfs, but snapshots are not implemented yet"
        return "$DEBIAN_FDE_NOT_IMPLEMENTED"
    fi
    info "pre-upgrade: skipped ($_pu_fstype root; snapshots need btrfs, ADR-13)"
    return 0
}
