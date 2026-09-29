#!/bin/sh
# cmd/kernel.sh — `alpine-fde kernel` dispatcher (docs/Architecture.md §8.1).
# Sub-verbs: build <kver> (lib/cmd/kernel-build.sh), remove <kver>
# (lib/cmd/kernel-remove.sh), prune [kver] (the build's step-7 keep-set prune,
# exposed standalone), next <entry> (one-shot boot entry — the absorbed
# `bootnext` verb, lib/cmd/kernel-next.sh). Called by bin/alpine-fde as
# cmd_kernel_main with the remaining args.
#
# The former `enroll` sub-verb (the build's ensure-once enrollment step, G-R3)
# is internal again: the operator surface for a standalone re-enrollment is
# `alpine-fde reseal`; the build runs the step itself via the shared
# reseal_run/reseal_ensure_once core.

cmd_kernel_usage() {
    cat >&2 <<EOF
Usage: $PROG kernel <verb> [args...]

Verbs:
  build [--re-sign-all] [kver]  assemble, measure, sign, install a UKI,
                                ensure the TPM enrollment and update
                                manifest + predictions (default kver: the
                                running kernel)
  remove <kver>                 remove that kernel's UKI and manifest entry
                                (wire: hooks/kernel-hooks.d/alpine-fde-remove.hook
                                + hooks/apk/triggers/alpine-fde.trigger)
  prune [kver]                  prune the ESP + manifest to the keep set
                                (current kernel + RETENTION older; default
                                kver: the manifest's current kernel)
  next [<entry-id>]             set a one-shot boot entry (rollback); without
                                argument, print the current one-shot entry
EOF
}

# _kernel_prune_current_kver — resolve the prune's current kernel: the
# manifest's current_kernel, else `uname -r` when its module tree exists,
# else a loud usage failure.
_kernel_prune_current_kver() {
    _kpk_manifest=${1:?}
    _kpk_kver=$(jq -r '.current_kernel // empty' "$_kpk_manifest" 2>/dev/null || :)
    if [ -z "$_kpk_kver" ]; then
        _kpk_run=$(uname -r 2>/dev/null)
        if [ -n "$_kpk_run" ] && [ -d "${ALPINE_FDE_ROOT:-}/lib/modules/$_kpk_run" ]; then
            _kpk_kver=$_kpk_run
        fi
    fi
    [ -n "$_kpk_kver" ] || {
        err "kernel prune: no current kernel resolvable (manifest .current_kernel empty and uname -r not installed under ${ALPINE_FDE_ROOT:-/}/lib/modules) — pass the kver explicitly"
        return 1
    }
    printf '%s\n' "$_kpk_kver"
}

cmd_kernel_prune_main() {
    strict_mode
    _kpk_kver=${1:-}
    [ $# -le 1 ] || {
        err "kernel prune: too many arguments"
        cmd_kernel_usage
        exit "$ALPINE_FDE_USAGE"
    }
    for _kpk_lib in common.sh manifest.sh esp.sh; do
        # shellcheck disable=SC1090  # sibling libraries next to this command
        . "${ALPINE_FDE_CMD_DIR:?}/../$_kpk_lib"
    done
    # the NVRAM boot-entry sweep lives in the install lane (one efibootmgr
    # implementation serves install/build/prune)
    # shellcheck disable=SC1091  # sibling in the same command directory
    . "$ALPINE_FDE_CMD_DIR/install.sh"
    load_config
    _kpk_etc="${ALPINE_FDE_ROOT:-}/etc/alpine-fde"
    _kpk_manifest="$_kpk_etc/digests.json"
    [ -f "$_kpk_manifest" ] || {
        err "kernel prune: no manifest at $_kpk_manifest (nothing to prune)"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    }
    if [ -z "$_kpk_kver" ]; then
        _kpk_kver=$(_kernel_prune_current_kver "$_kpk_manifest") || {
            cmd_kernel_usage
            exit "$ALPINE_FDE_USAGE"
        }
    fi
    if ! esp_validate_kver "$_kpk_kver"; then
        err "kernel prune: invalid kernel version: '$_kpk_kver' (alphanumerics, '.', '_', '-' only)"
        exit "$ALPINE_FDE_USAGE"
    fi
    _kpk_retention=${RETENTION:-2}
    case $_kpk_retention in
        '' | *[!0-9]*)
            die "kernel prune: invalid retention '$_kpk_retention' (expected a non-negative integer)"
            ;;
    esac
    # two-UKI design bound: at most THREE kernel versions (current + 2) — the
    # same clamp the build applies (a higher RETENTION is clamped, loudly)
    if [ "$_kpk_retention" -gt 2 ]; then
        warn "kernel prune: RETENTION=$_kpk_retention exceeds the three-version bound (current + 2 previous) — clamping to 2"
        _kpk_retention=2
    fi
    # shellcheck disable=SC2086  # word split intended: one kver per line
    _kpk_keep=$(esp_compute_keep "$_kpk_kver" "$_kpk_retention")
    # shellcheck disable=SC2086  # word split intended: one kver per line
    manifest_prune_to "$_kpk_manifest" $_kpk_keep
    # LO-04: a prune rm failure would silently diverge ESP from manifest (§9.2)
    # shellcheck disable=SC2086  # word split intended: one kver per line
    if ! esp_prune_ukis $_kpk_keep; then
        err "kernel prune: ESP prune failed — ESP and manifest would diverge (§9.2)"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi
    # the NVRAM boot entries ride the same keep-set decision (at most six
    # entries, version-pairs, oldest pruned first; best-effort skip without
    # efivarfs)
    # shellcheck disable=SC2086  # word split intended: one kver per line
    inst_bootentry_prune $_kpk_keep
    info "kernel prune: keep set ($_kpk_keep); ESP + manifest + NVRAM entries pruned"
    return 0
}

cmd_kernel_main() {
    _uk_verb=${1:-}
    [ -n "$_uk_verb" ] || {
        err "kernel: no verb given"
        cmd_kernel_usage
        exit "$ALPINE_FDE_USAGE"
    }
    shift
    case $_uk_verb in
        build)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$ALPINE_FDE_CMD_DIR/kernel-build.sh"
            cmd_kernel_build_main "$@"
            ;;
        remove)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$ALPINE_FDE_CMD_DIR/kernel-remove.sh"
            cmd_kernel_remove_main "$@"
            ;;
        prune)
            cmd_kernel_prune_main "$@"
            ;;
        next)
            # one-shot boot entry (the absorbed `bootnext` verb, §8.1)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$ALPINE_FDE_CMD_DIR/kernel-next.sh"
            cmd_kernel_next_main "$@"
            ;;
        *)
            err "kernel: unknown verb: $_uk_verb"
            cmd_kernel_usage
            exit "$ALPINE_FDE_USAGE"
            ;;
    esac
}
