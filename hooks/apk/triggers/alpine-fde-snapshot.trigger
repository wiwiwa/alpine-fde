#!/bin/sh
# alpine-fde-snapshot.trigger — apk trigger: AUTOMATIC pre-upgrade snapshots
# (user decision item 9; docs/Architecture.md §4/§8.1). The sibling of the
# kernel trigger (alpine-fde.trigger): at every apk transaction that installs
# files anywhere on the system, the btrfs snapshot flow of
# lib/cmd/pre-upgrade.sh (pu_auto_snapshot_main) takes a READ-ONLY snapshot
# of the @ root subvolume into /.snapshots/alpine-fde-auto-<UTC-timestamp>
# and prunes the tagged set to the newest ALPINE_FDE_SNAPSHOT_KEEP (default
# 5; the shipped default lives in /etc/conf.d/alpine-fde-snapshot). Additions
# are covered too — a package transaction can touch the boot chain.
#
# .trigger directive (the watched-dir stanza; same staging convention as the
# kernel trigger — /etc/apk/triggers/):
#
#   alpine-fde-snapshot=/lib/apk/exec/alpine-fde-snapshot.trigger
#   /
#
# (Watching "/" is the pragmatic "EVERY transaction": any package that
# installs files under / fires the trigger.)
#
# TRIGGER-TIME SEMANTICS (the decided shape, mirrored from the kernel
# trigger): apk triggers run AFTER the transaction's file commit, so the
# snapshot captures the just-completed state. That state IS the rollback
# point for the NEXT transaction — "pre-upgrade" means "the state before the
# next transaction": to undo the most recent apk transaction, restore the
# SECOND-NEWEST alpine-fde-auto-* snapshot (the newest is the broken state
# itself). This is the only shape an apk trigger can have; the rollback
# guarantee the docs promise is unchanged.
#
# Failure semantics: the snapshot is rollback INSURANCE, not boot-chain
# integrity (ADR-8's loud failure is the KERNEL trigger's job). A graceful
# skip — non-btrfs root, or a root subvolume that is not @ (§4/§9.1) — is a
# logged line + rc 0. A fail-closed snapshot (missing /.snapshots, btrfs
# failure; lib rc 64) propagates to apk: the transaction has already
# committed, but the lost rollback point is announced loudly. A MISSING LIB
# MODULE degrades to rc 0 (logged) — never fail an apk transaction for
# missing insurance.
#
# Env: ALPINE_FDE_ROOT (marker root, default /); ALPINE_FDE_SNAPSHOT_KEEP
# (retention seam — overrides /etc/conf.d/alpine-fde-snapshot, default 5);
# ALPINE_FDE_LIB_DIR (runtime; derived from this script's location, falling
# back to /usr/share/alpine-fde/lib). The env namespace is ALPINE_FDE_* only
# (§8.1).
#
# §8.1 machine/lib entrance: this trigger NEVER execs the `alpine-fde` CLI —
# it sources lib/cmd/pre-upgrade.sh and calls its lib-level entry
# (pu_auto_snapshot_main) directly.

set -u

case ${1:-} in
    describe)
        echo "take a rollback snapshot of the root subvolume (alpine-fde auto pre-upgrade snapshots)"
        exit 0
        ;;
esac

ALPINE_FDE_ROOT=${ALPINE_FDE_ROOT:-}

# best-effort syslog + stderr line (apk surfaces stderr; syslog persists it)
snap_log() {
    printf '%s\n' "alpine-fde-snapshot trigger: $*" >&2
    logger -t alpine-fde-snapshot "trigger: $*" 2>/dev/null || :
}

# retention default: the installed-config value ships in
# /etc/conf.d/alpine-fde-snapshot; the ALPINE_FDE_SNAPSHOT_KEEP env seam
# overrides it (unset here = the env wins), the lib default of 5 is last.
if [ -z "${ALPINE_FDE_SNAPSHOT_KEEP:-}" ] && [ -f /etc/conf.d/alpine-fde-snapshot ]; then
    # shellcheck disable=SC1091  # installed-config value, may be absent
    . /etc/conf.d/alpine-fde-snapshot
fi

# §8.1: source the lib module; the snapshot flow (pu_auto_snapshot_main)
# carries the fstype/subvolume gate, the read-only snapshot, and the keep-N
# retention (lib/cmd/pre-upgrade.sh — one implementation, both doors).
ALPINE_FDE_LIB_DIR=${ALPINE_FDE_LIB_DIR:-}
if [ -z "$ALPINE_FDE_LIB_DIR" ]; then
    _trig_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ -f "$_trig_dir/../../lib/cmd/pre-upgrade.sh" ]; then
        ALPINE_FDE_LIB_DIR="$_trig_dir/../../lib"
    else
        ALPINE_FDE_LIB_DIR=/usr/share/alpine-fde/lib
    fi
fi
if [ ! -f "$ALPINE_FDE_LIB_DIR/cmd/pre-upgrade.sh" ]; then
    snap_log "alpine-fde runtime not found at $ALPINE_FDE_LIB_DIR (cmd/pre-upgrade.sh) — auto snapshot skipped (rollback insurance is best-effort, rc 0)"
    exit 0
fi
ALPINE_FDE_CMD_DIR="$ALPINE_FDE_LIB_DIR/cmd"
# shellcheck disable=SC1090  # resolved via the runtime lib dir
. "$ALPINE_FDE_CMD_DIR/pre-upgrade.sh"

# apk protocol: called once per transaction with the changed watched
# directory(ies) as arguments — the watched dirs are irrelevant here (the
# snapshot is always of the root subvolume), so the arguments are ignored.
pu_auto_snapshot_main
rc=$?
if [ "$rc" -ne 0 ]; then
    snap_log "auto snapshot FAILED (rc $rc) — this apk transaction has NO rollback snapshot; the next one will. Check the alpine-fde diagnostics above."
fi
exit "$rc"
