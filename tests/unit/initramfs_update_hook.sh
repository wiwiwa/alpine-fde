#!/usr/bin/env bash
# tests/unit/initramfs_update_hook.sh — G-C16 (§8.3 + ADR-19, resolution R7):
# the APK trigger replaces the retired Debian /etc/initramfs/post-update.d
# template. hooks/apk/triggers/alpine-fde.trigger watches /lib/modules and
# rebuilds the signed UKI for every installed kernel version through
# `alpine-fde ukictl build <kver>` (ALPINE_FDE_BIN seam);
# the child's exit code propagates (ADR-8 loud failure + persisted marker
# under /etc/alpine-fde, recovery = `apk fix`).
#
# The test drives the REAL trigger with a recording `alpine-fde` stub.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/alpine-fde-trigger.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

TRIGGER=$REPO/hooks/apk/triggers/alpine-fde.trigger
assert_file_exists "apk trigger template exists" "$TRIGGER"
assert_eq "trigger template is executable" "1" "$([ -x "$TRIGGER" ] && echo 1 || echo 0)"
sh -n "$TRIGGER" >/dev/null 2>&1
assert_eq "trigger parses under POSIX sh (busybox ash)" "0" "$?"

mkdir -p "$T/bin" "$T/root/etc/alpine-fde" "$T/lib/modules/6.6.63-0-lts" "$T/lib/modules/6.6.62-0-lts"
FAKE=$T/bin/alpine-fde
cat >"$FAKE" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$T/calls.log"
exit \$ALPINE_FDE_FAKE_RC
EOF
chmod +x "$FAKE"
: >"$T/calls.log"
export ALPINE_FDE_BIN=$FAKE
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_FAKE_RC=0
MARKER=$T/root/etc/alpine-fde/build-failed

run_trigger() { # <args...>
    : >"$T/calls.log"
    sh "$TRIGGER" "$@" >"$T/out.log" 2>&1
    echo $?
}

# =============================================================================
# describe pass: informational, never builds (apk contract)
# =============================================================================
assert_eq "trigger: describe rc 0" "0" "$(run_trigger describe)"
assert_eq "trigger: describe never invokes the binary" "0" "$(wc -l <"$T/calls.log" | tr -d ' ')"
assert_ne "trigger: describe prints a description" "" "$(cat "$T/out.log")"

# =============================================================================
# trigger run: builds the UKI for EVERY kernel version under the watched dir
# =============================================================================
assert_eq "trigger: run rc 0" "0" "$(run_trigger "$T/lib/modules")"
assert_eq "trigger: one ukictl build per installed kernel" "2" \
    "$(wc -l <"$T/calls.log" | tr -d ' ')"
assert_contains "trigger: builds the current kernel verbatim" \
    "$(cat "$T/calls.log")" "ukictl build 6.6.63-0-lts"
assert_contains "trigger: builds the retained kernel verbatim" \
    "$(cat "$T/calls.log")" "ukictl build 6.6.62-0-lts"
assert_eq "trigger: no marker on success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# ADR-8: child failure propagates + marker persisted under /etc/alpine-fde
# (the glob walks sorted order, so the FIRST failure is the retained
# 6.6.62 kernel; the trigger exits on it immediately)
# =============================================================================
export ALPINE_FDE_FAKE_RC=64
assert_eq "trigger: child rc 64 propagates" "64" "$(run_trigger "$T/lib/modules")"
assert_eq "trigger: failure invoked ukictl build once, then stopped" "1" \
    "$(wc -l <"$T/calls.log" | tr -d ' ')"
assert_contains "trigger: failure was for the first-sorted kernel" \
    "$(cat "$T/calls.log")" "ukictl build 6.6.62-0-lts"
assert_eq "trigger: failure marker persisted" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "trigger: marker names the failed kernel" "$(cat "$MARKER")" "6.6.62-0-lts"
assert_contains "trigger: marker recovery names apk fix" "$(cat "$MARKER")" "apk fix"
export ALPINE_FDE_FAKE_RC=0

# success clears the stale marker
assert_eq "trigger: recovery run rc 0" "0" "$(run_trigger "$T/lib/modules")"
assert_eq "trigger: stale marker cleared after success" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# no watched dir argument: defaults to /lib/modules; rc 0 either way (the
# test host may or may not carry /lib/modules entries — both are fine, the
# marker must stay clear)
# =============================================================================
assert_eq "trigger: no argument defaults to /lib/modules rc 0" "0" "$(run_trigger)"
assert_eq "trigger: no marker from the default-dir run" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
