#!/usr/bin/env bash
# tests/unit/kernel_hooks_wire.sh — G-C16 (§8.3 + ADR-19, resolution R7):
# behavioral contract of the Alpine /etc/kernel-hooks.d/ hooks (the
# ukify-kernel-hook convention replaces the retired Debian dpkg templates):
#
#   hooks/kernel-hooks.d/alpine-fde-build.hook   (add|update -> ukictl build)
#   hooks/kernel-hooks.d/alpine-fde-remove.hook  (remove     -> ukictl remove)
#
# Convention: the kernel hook runner invokes `<hook> <event> <kver>` with
# event in {add, update, remove}. The build hook acts on add/update, the
# remove hook on remove; anything else is a no-op rc 0. A hook invoked
# without event/kver is a broken invocation and must fail closed (rc 64,
# loud diagnostics) — silently "succeeding" would mask a UKI that was never
# built/pruned. The child's exit code propagates unmodified; a failing child
# persists the ADR-8 build-failed marker under $ROOT/etc/alpine-fde (the
# build hook clears it again on a later successful build; its recovery copy
# names `apk fix`). After a successful build the hook re-signs the boot
# manager on the ESP (verify-first, from the retired Debian upgrade hook).
#
# The test drives the REAL hook scripts with a recording `alpine-fde` stub
# (ALPINE_FDE_BIN / ALPINE_FDE_BIN seam) plus sbsign/sbverify stubs.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/alpine-fde-kernelhooks.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

BUILD=$REPO/hooks/kernel-hooks.d/alpine-fde-build.hook
REMOVE=$REPO/hooks/kernel-hooks.d/alpine-fde-remove.hook
TRIGGER=$REPO/hooks/apk/triggers/alpine-fde.trigger

assert_file_exists "kernel build hook exists" "$BUILD"
assert_file_exists "kernel remove hook exists" "$REMOVE"
assert_eq "build hook is executable" "1" "$([ -x "$BUILD" ] && echo 1 || echo 0)"
assert_eq "remove hook is executable" "1" "$([ -x "$REMOVE" ] && echo 1 || echo 0)"
sh -n "$BUILD" >/dev/null 2>&1
assert_eq "build hook parses under POSIX sh (busybox ash)" "0" "$?"
sh -n "$REMOVE" >/dev/null 2>&1
assert_eq "remove hook parses under POSIX sh (busybox ash)" "0" "$?"

# --- recording alpine-fde stub + boot-manager stubs -----------------------------
FAKE=$T/bin/alpine-fde
mkdir -p "$T/bin" "$T/root/etc/alpine-fde" "$T/stub" "$T/esp/EFI/systemd" "$T/esp/EFI/BOOT"
cat >"$FAKE" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$T/calls.log"
exit \$ALPINE_FDE_FAKE_RC
EOF
chmod +x "$FAKE"
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
out=''
prev=''
for a in "$@"; do
    [ "$prev" = "--output" ] && out=$a
    prev=$a
done
last=''
for a in "$@"; do last=$a; done
[ -n "$out" ] && printf 'signed' >"$out"
exit 0
EOF
cat >"$T/stub/sbverify" <<'EOF'
#!/bin/sh
f=''
for a in "$@"; do f=$a; done
[ "$(tail -c 6 "$f")" = "signed" ]
EOF
chmod +x "$T/stub/sbsign" "$T/stub/sbverify"
printf 'unsigned-boot-manager' >"$T/esp/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$T/esp/EFI/BOOT/BOOTX64.EFI"

: >"$T/calls.log"
export ALPINE_FDE_BIN=$FAKE
export ALPINE_FDE_BIN=$FAKE
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_ESP=$T/esp
export ALPINE_FDE_KEYDIR=$REPO/fixtures/keys
export ALPINE_FDE_LIB_DIR=$REPO/lib
export PATH="$T/stub:$PATH"
export ALPINE_FDE_FAKE_RC=0
MARKER=$T/root/etc/alpine-fde/build-failed

run_hook() { # <hook> <args...>
    local hook=$1
    shift
    : >"$T/calls.log"
    sh "$hook" "$@" >"$T/out.log" 2>&1
    echo $?
}
no_calls() { assert_eq "$1" "0" "$(wc -l <"$T/calls.log" | tr -d ' ')"; }

# =============================================================================
# build hook: add/update -> `ukictl build <kver>` verbatim (§8.3)
# =============================================================================
assert_eq "build: add event rc 0" "0" "$(run_hook "$BUILD" add 6.6.63-0-lts)"
assert_eq "build: add invoked ukictl build with the kver verbatim" \
    "ukictl build 6.6.63-0-lts" "$(cat "$T/calls.log")"
assert_eq "build: no marker on success" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"

assert_eq "build: update event rc 0" "0" "$(run_hook "$BUILD" update 6.6.63-0-lts)"
assert_eq "build: update invoked ukictl build verbatim" \
    "ukictl build 6.6.63-0-lts" "$(cat "$T/calls.log")"

# remove events are the remove hook's business
assert_eq "build: remove event is a no-op rc 0" "0" "$(run_hook "$BUILD" remove 6.6.63-0-lts)"
no_calls "build: remove event never invokes the binary"

# =============================================================================
# remove hook: remove -> `ukictl remove <kver>` (§8.3 prune)
# =============================================================================
assert_eq "remove: remove event rc 0" "0" "$(run_hook "$REMOVE" remove 6.6.63-0-lts)"
assert_eq "remove: invoked ukictl remove with the kver verbatim" \
    "ukictl remove 6.6.63-0-lts" "$(cat "$T/calls.log")"
assert_eq "remove: add event is a no-op rc 0" "0" "$(run_hook "$REMOVE" add 6.6.63-0-lts)"
no_calls "remove: add event never invokes the binary"
assert_eq "remove: update event is a no-op rc 0" "0" "$(run_hook "$REMOVE" update 6.6.63-0-lts)"
no_calls "remove: update event never invokes the binary"

# =============================================================================
# ADR-8: child failure propagates + marker persisted under /etc/alpine-fde,
# then cleared on recovery
# =============================================================================
export ALPINE_FDE_FAKE_RC=64
assert_eq "build: child rc 64 propagates unmodified" "64" \
    "$(run_hook "$BUILD" update 6.6.64-0-lts)"
assert_eq "build: build-failed marker persisted" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "build: marker names the failed kernel" "$(cat "$MARKER")" "6.6.64-0-lts"
assert_contains "build: marker recovery names apk fix" "$(cat "$MARKER")" "apk fix"
assert_contains "build: marker names the canonical passphrase seam" \
    "$(cat "$MARKER")" "ALPINE_FDE_KEY_PASSPHRASE"
export ALPINE_FDE_FAKE_RC=0
assert_eq "build: recovery run rc 0" "0" "$(run_hook "$BUILD" update 6.6.64-0-lts)"
assert_eq "build: stale marker cleared after successful build" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

export ALPINE_FDE_FAKE_RC=5
assert_eq "remove: child rc 5 propagates unmodified" "5" \
    "$(run_hook "$REMOVE" remove 6.6.64-0-lts)"
assert_eq "remove: build-failed marker persisted" "1" "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "remove: marker names the failed kernel" "$(cat "$MARKER")" "6.6.64-0-lts"
assert_contains "remove: marker recovery names apk fix" "$(cat "$MARKER")" "apk fix"
export ALPINE_FDE_FAKE_RC=0

# =============================================================================
# broken invocations fail closed, loudly (rc 64 pinned)
# =============================================================================
assert_eq "build: missing kver fails closed (64)" "64" "$(run_hook "$BUILD" add)"
no_calls "build: missing kver never invokes the binary"
assert_ne "build: missing kver prints loud diagnostics" "" "$(cat "$T/out.log")"
assert_eq "remove: missing kver fails closed (64)" "64" "$(run_hook "$REMOVE" remove)"
no_calls "remove: missing kver never invokes the binary"

# =============================================================================
# boot-manager re-sign rides the build hook (reused Debian logic, verify-first)
# =============================================================================
assert_eq "build: boot-manager re-sign rc 0" "0" "$(run_hook "$BUILD" add 6.6.65-0-lts)"
assert_eq "build: re-sign left a signed boot manager on the ESP" "signed" \
    "$(tail -c 6 "$T/esp/EFI/systemd/systemd-bootx64.efi")"
assert_eq "build: re-sign left a signed fallback loader on the ESP" "signed" \
    "$(tail -c 6 "$T/esp/EFI/BOOT/BOOTX64.EFI")"
# verify-first: an already-signed binary is not re-signed (sbsign APPENDS)
assert_eq "build: verify-first re-run rc 0 (idempotent)" "0" \
    "$(run_hook "$BUILD" add 6.6.65-0-lts)"

# =============================================================================
# apk trigger artifact: present, parses, carries the trigger dir directive,
# and mentions NO dpkg-era anything
# =============================================================================
assert_file_exists "apk trigger exists" "$TRIGGER"
sh -n "$TRIGGER" >/dev/null 2>&1
assert_eq "apk trigger parses under POSIX sh" "0" "$?"
TRIG_C=$(cat "$TRIGGER")
assert_contains "apk trigger: watched dir directive is /lib/modules" "$TRIG_C" "/lib/modules"
assert_contains "apk trigger: names its exec path" "$TRIG_C" "/lib/apk/exec/alpine-fde.trigger"

# =============================================================================
# NO dpkg / DEB_MAINT_PARAMS anywhere in the new Alpine artifacts
# =============================================================================
for f in "$BUILD" "$REMOVE" "$TRIGGER"; do
    C=$(cat "$f")
    assert_not_contains "$(basename "$f"): no dpkg references" "$C" "dpkg"
    assert_not_contains "$(basename "$f"): no DEB_MAINT_PARAMS" "$C" "DEB_MAINT_PARAMS"
    assert_not_contains "$(basename "$f"): no /etc/debian-fde marker path" "$C" "etc/debian-fde"
done

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
