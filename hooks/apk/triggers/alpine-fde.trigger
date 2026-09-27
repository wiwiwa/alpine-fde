#!/bin/sh
# alpine-fde.trigger — apk trigger template (docs/Architecture.md §8.3;
# ADR-19/ADR-13, gap G-C16). Intercepts kernel installations/upgrades and
# rebuilds the signed UKI for every installed kernel version through
# `alpine-fde kernel build` (initramfs -> ukify --measure -> sbsign -> ESP ->
# manifest -> prune). Replaces the retired Debian
# /etc/initramfs/post-update.d template.
#
# .trigger directive (the control stanza `alpine-fde install` writes into the
# package's .trigger file — the watched-dir directive that makes apk run this
# script after any transaction touching kernel modules):
#
#   alpine-fde=/lib/apk/exec/alpine-fde.trigger
#   /lib/modules
#
# apk protocol: called once with `describe` (print a description, change
# nothing), then once per transaction with the changed watched directory(ies)
# as arguments. With no argument the script defaults to /lib/modules.
#
# ADR-8: a failing build must fail loudly — the nonzero exit propagates to
# apk, the failure marker is persisted under /etc/alpine-fde for
# `alpine-fde status`, and the PREVIOUS default UKI is never touched. Operator
# recovery: re-run `alpine-fde kernel build <kver>` (enter the release-key
# passphrase when prompted); unattended, provide ALPINE_FDE_KEY_PASSPHRASE
# via your credential agent, then `apk fix` (ADR-18).
#
# Env: ALPINE_FDE_ROOT (marker root, default /); ALPINE_FDE_LIB_DIR (runtime;
# derived from this script's location, falling back to /usr/share/alpine-fde/lib).
# The env namespace is ALPINE_FDE_* only (§8.1).

set -u

case ${1:-} in
    describe)
        echo "rebuild the signed UKIs for installed kernels (alpine-fde)"
        exit 0
        ;;
esac

ALPINE_FDE_ROOT=${ALPINE_FDE_ROOT:-}
if [ -n "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
    export ALPINE_FDE_KEY_PASSPHRASE
fi

FDE_ETC="$ALPINE_FDE_ROOT/etc/alpine-fde"
marker="$FDE_ETC/build-failed"

# §8.1 machine/lib entrance: this trigger NEVER execs the `alpine-fde` CLI —
# it sources the lib/cmd build module directly and calls its entry point in a
# SUBSHELL per kernel (the cmd entry `exit`s internally; the subshell contains
# that and propagates the rc to apk).
ALPINE_FDE_LIB_DIR=${ALPINE_FDE_LIB_DIR:-}
if [ -z "$ALPINE_FDE_LIB_DIR" ]; then
    _trig_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    if [ -f "$_trig_dir/../../lib/cmd/kernel-build.sh" ]; then
        ALPINE_FDE_LIB_DIR="$_trig_dir/../../lib"
    else
        ALPINE_FDE_LIB_DIR=/usr/share/alpine-fde/lib
    fi
fi
if [ ! -f "$ALPINE_FDE_LIB_DIR/cmd/kernel-build.sh" ]; then
    echo "alpine-fde trigger: alpine-fde runtime not found at $ALPINE_FDE_LIB_DIR (cmd/kernel-build.sh) — cannot rebuild UKIs (ADR-8)" >&2
    exit 64
fi
ALPINE_FDE_CMD_DIR="$ALPINE_FDE_LIB_DIR/cmd"
# shellcheck disable=SC1090  # resolved via the runtime lib dir
. "$ALPINE_FDE_CMD_DIR/kernel-build.sh"

# watched dirs: apk hands the changed directories; default /lib/modules
if [ $# -ge 1 ]; then
    :
else
    set -- /lib/modules
fi

for dir in "$@"; do
    [ -d "$dir" ] || continue
    for kver in "$dir"/*; do
        [ -d "$kver" ] || continue
        kver=${kver##*/}
        ( cmd_kernel_build_main "$kver" )
        rc=$?
        if [ "$rc" -ne 0 ]; then
            mkdir -p "$FDE_ETC" 2>/dev/null || :
            {
                printf 'apk trigger: kernel build failed for kernel %s\n' "$kver"
                printf 'time: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                printf 'recovery: re-run "alpine-fde kernel build %s" (enter the release-key passphrase when prompted); unattended: provide ALPINE_FDE_KEY_PASSPHRASE via your credential agent, then "apk fix"\n' "$kver"
            } >>"$marker" 2>/dev/null || :
            exit "$rc"
        fi
    done
done

# success — clear any stale marker from a previous failed attempt
rm -f "$marker" 2>/dev/null || :
exit 0
