#!/bin/sh
# cmd/ukictl.sh — `debian-fde ukictl` dispatcher (docs/Architecture.md §8.1).
# Verbs: build <kver> (lib/cmd/ukictl-build.sh), remove <kver>
# (lib/cmd/ukictl-remove.sh), enroll (the build's ensure-once enrollment step,
# alias of enroll-tpm — G-R3). Called by bin/debian-fde as cmd_ukictl_main with
# the remaining args.

cmd_ukictl_usage() {
    cat >&2 <<EOF
Usage: $PROG ukictl <verb> [args...]

Verbs:
  build [--re-sign-all] [kver]  assemble, measure, sign, install a UKI,
                                ensure the A'' TPM enrollment and update
                                manifest + predictions (default kver: the
                                running kernel)
  enroll [args...]              run the single A'' TPM enrollment step of
                                build (alias of enroll-tpm; TPM-clear
                                recovery) — passes through its flags
  remove <kver>                 remove that kernel's UKI and manifest entry
                                (wire: /etc/kernel/postrm.d/zz-debian-fde)
EOF
}

cmd_ukictl_main() {
    _uk_verb=${1:-}
    [ -n "$_uk_verb" ] || {
        err "ukictl: no verb given"
        cmd_ukictl_usage
        exit "$DEBIAN_FDE_USAGE"
    }
    shift
    case $_uk_verb in
        build)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$DEBIAN_FDE_CMD_DIR/ukictl-build.sh"
            cmd_ukictl_build_main "$@"
            ;;
        enroll)
            # G-R3: the enrollment step of build, exposed standalone (the
            # dispatcher help promises build/sign/enroll/prune)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$DEBIAN_FDE_CMD_DIR/enroll-tpm.sh"
            cmd_enroll_tpm_main "$@"
            ;;
        remove)
            # shellcheck disable=SC1091  # sibling in the same command directory
            . "$DEBIAN_FDE_CMD_DIR/ukictl-remove.sh"
            cmd_ukictl_remove_main "$@"
            ;;
        *)
            err "ukictl: unknown verb: $_uk_verb"
            cmd_ukictl_usage
            exit "$DEBIAN_FDE_USAGE"
            ;;
    esac
}
