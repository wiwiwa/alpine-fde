#!/usr/bin/env bash
# tests/unit/initramfs_update_hook.sh — initrd-affecting updates rebuild the UKI
# (docs/Architecture.md §8.3): hooks/post-update.d-zz-debian-fde is the
# template for /etc/initramfs/post-update.d/zz-debian-fde (Debian
# /etc/initramfs/post-update.d convention, $1 = kernel version). It calls
# `ukictl build <kver>` through DEBIAN_FDE_BIN; the child's exit code
# propagates (ADR-8 loud failure + persisted marker).
#
# The test drives the REAL hook with a DEBIAN_FDE_BIN recording stub and
# asserts the kernel version is passed verbatim and the child rc propagates.
# Install-side wiring (copied into the target, executable) is asserted by
# tests/unit/install_chroot_plan.sh.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/debian-fde-postupdate.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

HOOK=$REPO/hooks/post-update.d-zz-debian-fde
assert_file_exists "initramfs post-update hook template exists" "$HOOK"
assert_eq "hook template is executable (run-parts convention)" "1" \
    "$([ -x "$HOOK" ] && echo 1 || echo 0)"

FAKE=$T/bin/debian-fde
mkdir -p "$T/bin" "$T/root/etc/debian-fde"
cat >"$FAKE" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$T/calls.log"
exit \$DEBIAN_FDE_FAKE_RC
EOF
chmod +x "$FAKE"
: >"$T/calls.log"
export DEBIAN_FDE_BIN=$FAKE
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_FAKE_RC=0
MARKER=$T/root/etc/debian-fde/build-failed

run_hook() { # ARGS... — drive the real hook
    : >"$T/rc.log"
    sh "$HOOK" "$@" >/dev/null 2>&1
    echo $?
}

# =============================================================================
# G-U8: happy path — kver verbatim, child rc propagates
# =============================================================================
assert_eq "hook: happy path rc 0" "0" "$(run_hook 6.12.8-1-amd64)"
assert_eq "hook: ukictl build called with the kver verbatim" "ukictl build 6.12.8-1-amd64" \
    "$(cat "$T/calls.log")"
assert_eq "hook: no marker on success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# child failure propagates + marker persisted (ADR-8)
printf 'stale-marker-content' >"$MARKER"
: >"$T/calls.log"
export DEBIAN_FDE_FAKE_RC=5
assert_eq "hook: child rc 5 propagates" "5" "$(run_hook 6.12.9-1-amd64)"
assert_eq "hook: failure invoked ukictl build for the right kver" "ukictl build 6.12.9-1-amd64" \
    "$(cat "$T/calls.log")"
assert_eq "hook: failure marker persisted" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "hook: marker names the failed kernel" "$(cat "$MARKER")" "6.12.9-1-amd64"

# child rc 64 (e.g. missing signing key) propagates unmodified
: >"$T/calls.log"
export DEBIAN_FDE_FAKE_RC=64
assert_eq "hook: child rc 64 propagates" "64" "$(run_hook 6.12.9-1-amd64)"
export DEBIAN_FDE_FAKE_RC=0

# no kernel version argument -> no-op success (run-parts safety)
: >"$T/calls.log"
assert_eq "hook: no kver arg -> rc 0" "0" "$(run_hook)"
assert_eq "hook: no kver arg -> child never invoked" "0" "$(wc -l <"$T/calls.log")"

# success after failure clears the stale marker
assert_eq "hook: recovery run rc 0" "0" "$(run_hook 6.12.9-1-amd64)"
assert_eq "hook: stale marker cleared after success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
