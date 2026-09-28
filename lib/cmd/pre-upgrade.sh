#!/bin/sh
# pre-upgrade.sh — the btrfs snapshot flow (§8.1; C-G16; user decision item
# 9). The retired `alpine-fde pre-upgrade` CLI verb stays library-only: this
# module is the callable seam for BOTH snapshot doors —
#   * the MANUAL door: cmd_pre_upgrade_main (human recovery; retained for
#     parity with the documented one-command flow)
#   * the AUTOMATIC door: pu_auto_snapshot_main — the entry the apk
#     auto-snapshot trigger (hooks/apk/triggers/alpine-fde-snapshot.trigger,
#     §4) calls at every apk transaction, with keep-N retention over the
#     `alpine-fde-auto-*` snapshots (ALPINE_FDE_SNAPSHOT_KEEP, default 5)
# Btrfs is the default root (ADR-13, §4): snapshots are READ-ONLY copies of
# the root subvolume into /.snapshots/<name> (the @snapshots mount, §9.1
# layout; UserGuide §4 rollback flow). ext4 roots (--fs ext4) skip
# gracefully — rc 0.

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

# _pu_auto_retain SNAPDIR KEEP — keep-N retention over the TAGGED auto
# snapshots (user decision item 9). Keeps the newest KEEP entries matching
# "$SNAPDIR"/alpine-fde-auto-* (the names embed a UTC timestamp, so the glob
# sorts chronologically) and `btrfs subvolume delete`s the older excess.
# MANUAL snapshots (any other name, e.g. the documented pre-upgrade-* form)
# are NEVER touched. rc 0 when every excess delete succeeded; rc 1 when at
# least one delete failed (over-retention — a prune failure never destroys a
# snapshot, the caller warns and keeps the rc). The deleted names are
# reported in the global $_pu_auto_deleted (space-separated basenames).
_pu_auto_retain() {
    _par_dir=$1 _par_keep=$2
    _pu_auto_deleted=""
    # glob into the positional params (sorted); a non-match stays literal
    set -- "$_par_dir"/alpine-fde-auto-*
    [ -e "$1" ] || return 0
    _par_count=$#
    [ "$_par_count" -gt "$_par_keep" ] || return 0
    _par_excess=$((_par_count - _par_keep))
    _par_i=1
    _par_rc=0
    for _par_snap in "$@"; do
        if [ "$_par_i" -le "$_par_excess" ]; then
            if btrfs subvolume delete "$_par_snap" >/dev/null 2>&1; then
                _pu_auto_deleted="$_pu_auto_deleted ${_par_snap##*/}"
            else
                _par_rc=1
            fi
        fi
        _par_i=$((_par_i + 1))
    done
    return "$_par_rc"
}

# _pu_auto_keep VALUE — validate the retention value; prints the normalized
# keep-N (>= 1), rc 0; on an empty/invalid value prints the default 5, rc 1
# (the caller may log the fallback).
_pu_auto_keep() {
    case ${1:-} in
        '' | *[!0-9]*) printf '5\n'; return 1 ;;
    esac
    [ "$1" -ge 1 ] || { printf '5\n'; return 1; }
    printf '%s\n' "$1"
    return 0
}

# pu_auto_snapshot_main — the AUTOMATIC door (user decision item 9): one
# read-only snapshot of the root subvolume into
# /.snapshots/alpine-fde-auto-<UTC-timestamp> (the §9.1 @snapshots mount),
# then keep-N retention (ALPINE_FDE_SNAPSHOT_KEEP, default 5 — the shipped
# /etc/conf.d/alpine-fde-snapshot value; a garbage value falls back to 5).
#
# Called by the apk auto-snapshot trigger at EVERY apk transaction, so the
# trigger-time semantics are the transaction's OWN semantics (documented in
# the trigger): apk triggers run AFTER the transaction's file commit, so the
# snapshot captures the just-completed state — which is exactly the rollback
# point for the NEXT transaction ("pre-upgrade" = the state before the next
# transaction; undo the most recent transaction by restoring the
# second-newest alpine-fde-auto-* snapshot).
#
# Gate (degrade QUIETLY, rc 0): only a btrfs root mount whose subvolume is
# @ (§4/§9.1). Fail-CLOSED (rc 64): a btrfs-@ root with /.snapshots missing,
# or a failed `btrfs subvolume snapshot` — a lost rollback point is announced
# loudly. Stdout contract: exactly the created snapshot path.
pu_auto_snapshot_main() {
    strict_mode

    _pas_mif=${ALPINE_FDE_MOUNTINFO:-/proc/self/mountinfo}
    _pas_root=${ALPINE_FDE_ROOT:-}
    _pas_mp=${_pas_root%/}
    [ -n "$_pas_mp" ] || _pas_mp=/

    # ---- gate: btrfs root + the @ subvolume (§4/§9.1); else quiet skip ----
    if ! _pas_src=$(_pu_snapshot_src "$_pas_mif" "$_pas_root"); then
        info "pre-upgrade: auto snapshot skipped (no btrfs root mount at $_pas_mp; snapshots need btrfs, ADR-13)"
        return 0
    fi
    _pas_subvol=$(awk -v mp="$_pas_mp" '{
        if ($5 != mp) next
        for (i = 6; i <= NF; i++) {
            if ($i == "-") break
            n = split($i, o, ",")
            for (j = 1; j <= n; j++)
                if (index(o[j], "subvol=") == 1) { print substr(o[j], 8); exit }
        }
    }' "$_pas_mif" 2>/dev/null) || _pas_subvol=""
    case ${_pas_subvol:-} in
        /@ | @) ;;
        *)
            info "pre-upgrade: auto snapshot skipped (root subvolume is '${_pas_subvol:-<toplevel>}', not /@ — the §9.1 layout gates the automatic flow)"
            return 0
            ;;
    esac

    # ---- retention value: env seam, default 5 ----
    if ! _pas_keep=$(_pu_auto_keep "${ALPINE_FDE_SNAPSHOT_KEEP:-}"); then
        warn "pre-upgrade: invalid ALPINE_FDE_SNAPSHOT_KEEP '${ALPINE_FDE_SNAPSHOT_KEEP:-}' — falling back to 5"
    fi

    # ---- snapshot: read-only, tagged, into /.snapshots ----
    require_cmds btrfs
    _pas_snapdir="$_pas_mp/.snapshots"
    if [ ! -d "$_pas_snapdir" ]; then
        err "pre-upgrade: auto snapshot FAILED: $_pas_snapdir missing — expected the §9.1 layout with @snapshots mounted at /.snapshots"
        return "$ALPINE_FDE_FAIL_CLOSED"
    fi
    _pas_ts=$(date -u +%Y%m%dT%H%M%SZ)
    _pas_snap="$_pas_snapdir/alpine-fde-auto-$_pas_ts"
    _pas_n=0
    # same-second transactions never clobber: the collision gets a -N suffix
    while [ -e "$_pas_snap" ]; do
        _pas_n=$((_pas_n + 1))
        _pas_snap="$_pas_snapdir/alpine-fde-auto-$_pas_ts-$_pas_n"
    done
    # btrfs prints its own line on STDOUT — silenced: this entry's stdout
    # contract is exactly the snapshot path (the trigger propagates nothing).
    if ! btrfs subvolume snapshot -r "$_pas_src" "$_pas_snap" >/dev/null; then
        err "pre-upgrade: auto snapshot FAILED (btrfs subvolume snapshot -r $_pas_src $_pas_snap)"
        return "$ALPINE_FDE_FAIL_CLOSED"
    fi
    printf '%s\n' "$_pas_snap"

    # ---- retention: keep-N over the tagged snapshots ----
    # A prune failure is over-retention, never a lost snapshot: warn and keep
    # rc 0 (the snapshot is the deliverable; the prune is housekeeping).
    if ! _pu_auto_retain "$_pas_snapdir" "$_pas_keep"; then
        warn "pre-upgrade: retention prune failed ($_pu_auto_deleted deleted; some alpine-fde-auto-* snapshots could not be removed) — snapshots are over-retained, never lost"
    fi
    info "pre-upgrade: auto snapshot created: $_pas_snap (retention: keep $_pas_keep)"
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
upgrade is rolled back from there (UserGuide §4). This manual command never
prunes — remove old snapshots with `btrfs subvolume delete`. (The AUTOMATIC
pre-upgrade flow — the apk trigger, item 9 — tags its snapshots
alpine-fde-auto-* and prunes them itself, keep-N, default 5.)
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
