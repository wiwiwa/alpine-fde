# /etc/profile.d/alpine-fde.sh — FR-6 interactive login drift alert
# (docs/Architecture.md §8.1 "Internal Automation" row; docs/UserGuide.md §4
# "Automated Boot & Login Auditing" + §5.4). Installed by `alpine-fde install`
# (§9.1 in-chroot step 8).
#
# The boot-time oneshot (alpine-fde-audit, /etc/init.d/alpine-fde-audit)
# stages the detailed alert banner at /run/alpine-fde/audit-drift when it
# detects firmware/platform drift; this hook cats it at the top of the next
# INTERACTIVE login shell. The alert is retired by:
#   * the next boot-time audit that MATCHES the baseline, or
#   * `alpine-fde audit` on a matching machine, or
#   * `alpine-fde audit --accept` after a verified re-baseline
#     (then `alpine-fde reseal` restores passwordless unlock).
#
# Non-interactive shells (scp sftp channels, CI runners, cron) stay
# machine-readable: the banner prints only when $- marks the shell interactive.

case $- in
    *i*) : ;;
    *) return 0 2>/dev/null || : ;;
esac

# ALPINE_FDE_DRIFT_MARKER is a test/CI seam; the guest path is the default.
if [ -f "${ALPINE_FDE_DRIFT_MARKER:-/run/alpine-fde/audit-drift}" ]; then
    cat "${ALPINE_FDE_DRIFT_MARKER:-/run/alpine-fde/audit-drift}"
fi
