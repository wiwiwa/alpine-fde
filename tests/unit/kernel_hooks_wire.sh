#!/usr/bin/env bash
# tests/unit/kernel_hooks_wire.sh — behavioral contract of the two primary
# dpkg kernel hooks (docs/Architecture.md §8.3, gap G-U12/F2):
#
#   hooks/postinst.d-zz-debian-fde → /etc/kernel/postinst.d/zz-debian-fde
#   hooks/postrm.d-zz-debian-fde   → /etc/kernel/postrm.d/zz-debian-fde
#
# dpkg convention: run-parts invokes each hook with $1 = the kernel ABI
# version and DEB_MAINT_PARAMS = "$@" of the maintainer script (e.g.
# "configure 6.12.8-1"). postinst acts on configure passes, postrm on remove
# passes (manual invocations without DEB_MAINT_PARAMS act too); the child's
# exit code propagates to dpkg unmodified; a failing child persists the
# ADR-8 build-failed marker under $DEBIAN_FDE_ROOT/etc/debian-fde (postinst
# clears it again on a later successful build). A hook invoked without $1 is
# a broken invocation and must fail closed (non-zero rc, loud diagnostics) —
# silently "succeeding" would mask a UKI that was never built/pruned.
#
# The test drives the REAL hook scripts from the repo tree with a
# DEBIAN_FDE_BIN recording stub (same seam as
# tests/unit/initramfs_update_hook.sh). Install-side file placement is
# covered by tests/unit/install_chroot_plan.sh.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

T=$(mktemp -d /tmp/debian-fde-kernelhooks.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

POSTINST=$REPO/hooks/postinst.d-zz-debian-fde
POSTRM=$REPO/hooks/postrm.d-zz-debian-fde

assert_file_exists "postinst hook template exists" "$POSTINST"
assert_file_exists "postrm hook template exists" "$POSTRM"
assert_eq "postinst hook is executable (run-parts convention)" "1" \
    "$([ -x "$POSTINST" ] && echo 1 || echo 0)"
assert_eq "postrm hook is executable (run-parts convention)" "1" \
    "$([ -x "$POSTRM" ] && echo 1 || echo 0)"
sh -n "$POSTINST" >/dev/null 2>&1
assert_eq "postinst hook parses under POSIX sh (dash/busybox ash)" "0" "$?"
sh -n "$POSTRM" >/dev/null 2>&1
assert_eq "postrm hook parses under POSIX sh (dash/busybox ash)" "0" "$?"

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

# run_hook <hook> <maint-params|-> [kver] — drive the REAL hook; echoes the
# hook's exit code, keeps its combined output in $T/out.log, resets the stub
# call log. "-" means: invoke without DEB_MAINT_PARAMS (manual invocation).
run_hook() {
    local hook=$1 params=$2
    shift 2
    : >"$T/calls.log"
    if [ "$params" = "-" ]; then
        env -u DEB_MAINT_PARAMS sh "$hook" "$@" >"$T/out.log" 2>&1
    else
        DEB_MAINT_PARAMS="$params" sh "$hook" "$@" >"$T/out.log" 2>&1
    fi
    echo $?
}

no_calls() { # <name> — the stub was never invoked
    assert_eq "$1" "0" "$(wc -l <"$T/calls.log")"
}

# =============================================================================
# postinst: configure pass — `ukictl build <kver>`, rc propagation (§8.3)
# =============================================================================
assert_eq "postinst: configure pass rc 0" "0" \
    "$(run_hook "$POSTINST" "configure 6.12.8-1" 6.12.8-1-amd64)"
assert_eq "postinst: ukictl build called once with the ABI kver verbatim" \
    "ukictl build 6.12.8-1-amd64" "$(cat "$T/calls.log")"
assert_eq "postinst: no marker on successful build" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# no DEB_MAINT_PARAMS = manual invocation — the hook acts on those too
assert_eq "postinst: manual invocation rc 0" "0" \
    "$(run_hook "$POSTINST" - 6.12.8-1-amd64)"
assert_eq "postinst: manual invocation still calls ukictl build" \
    "ukictl build 6.12.8-1-amd64" "$(cat "$T/calls.log")"

# =============================================================================
# postinst: non-configure passes are skipped (dpkg contract)
# =============================================================================
assert_eq "postinst: abort-upgrade pass is a no-op rc 0" "0" \
    "$(run_hook "$POSTINST" "abort-upgrade" 6.12.8-1-amd64)"
no_calls "postinst: abort-upgrade pass never invokes the stub"

# =============================================================================
# postinst: ADR-8 — child failure propagates + marker persisted, then cleared
# =============================================================================
export DEBIAN_FDE_FAKE_RC=64
assert_eq "postinst: child rc 64 propagates unmodified" "64" \
    "$(run_hook "$POSTINST" "configure 6.12.9-1" 6.12.9-1-amd64)"
assert_eq "postinst: build-failed marker persisted" "1" \
    "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "postinst: marker names the failed kernel" \
    "$(cat "$MARKER")" "6.12.9-1-amd64"
assert_contains "postinst: marker states the reason (build failed)" \
    "$(cat "$MARKER")" "ukictl build failed"
export DEBIAN_FDE_FAKE_RC=0
assert_eq "postinst: recovery run rc 0" "0" \
    "$(run_hook "$POSTINST" "configure 6.12.9-1" 6.12.9-1-amd64)"
assert_eq "postinst: stale marker cleared after successful build" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

# =============================================================================
# postrm: remove pass — `ukictl remove <kver>`, rc propagation (§8.3)
# =============================================================================
assert_eq "postrm: remove pass rc 0" "0" \
    "$(run_hook "$POSTRM" "remove 6.12.8-1" 6.12.8-1-amd64)"
assert_eq "postrm: ukictl remove called once with the ABI kver verbatim" \
    "ukictl remove 6.12.8-1-amd64" "$(cat "$T/calls.log")"
assert_eq "postrm: no marker on successful prune" "0" \
    "$([ -e "$MARKER" ] && echo 1 || echo 0)"

assert_eq "postrm: manual invocation rc 0" "0" \
    "$(run_hook "$POSTRM" - 6.12.8-1-amd64)"
assert_eq "postrm: manual invocation still calls ukictl remove" \
    "ukictl remove 6.12.8-1-amd64" "$(cat "$T/calls.log")"

# =============================================================================
# postrm: non-remove passes are skipped (dpkg contract)
# =============================================================================
assert_eq "postrm: upgrade pass is a no-op rc 0" "0" \
    "$(run_hook "$POSTRM" "upgrade" 6.12.8-1-amd64)"
no_calls "postrm: upgrade pass never invokes the stub"

# =============================================================================
# postrm: ADR-8 — failed prune propagates rc + persists the marker
# =============================================================================
export DEBIAN_FDE_FAKE_RC=5
assert_eq "postrm: child rc 5 propagates unmodified" "5" \
    "$(run_hook "$POSTRM" "remove 6.12.9-1" 6.12.9-1-amd64)"
assert_eq "postrm: build-failed marker persisted" "1" \
    "$([ -f "$MARKER" ] && echo 1 || echo 0)"
assert_contains "postrm: marker names the failed kernel" \
    "$(cat "$MARKER")" "6.12.9-1-amd64"
assert_contains "postrm: marker states the reason (remove failed)" \
    "$(cat "$MARKER")" "ukictl remove failed"
export DEBIAN_FDE_FAKE_RC=0

# =============================================================================
# broken invocation (no $1) must fail closed, loudly (ADR-8 spirit; the
# codebase-wide fail-closed exit is 64 — pinned exactly)
# =============================================================================
assert_eq "postinst: missing kver fails closed (64)" "64" \
    "$(run_hook "$POSTINST" -)"
no_calls "postinst: missing kver never invokes the stub"
assert_ne "postinst: missing kver prints loud diagnostics" "" \
    "$(cat "$T/out.log")"

assert_eq "postrm: missing kver fails closed (64)" "64" \
    "$(run_hook "$POSTRM" -)"
no_calls "postrm: missing kver never invokes the stub"
assert_ne "postrm: missing kver prints loud diagnostics" "" \
    "$(cat "$T/out.log")"

# =============================================================================
# postrm: LO-03 — the dpkg ERROR-RESTORE pass (abort-remove) must NOT prune:
# `abort-remove <ver>` contains "remove" as a substring but the kernel is being
# RESTORED — pruning its UKI would delete a live entry.
# =============================================================================
assert_eq "postrm: abort-remove pass is a no-op rc 0" "0" \
    "$(run_hook "$POSTRM" "abort-remove 6.12.8-1" 6.12.8-1-amd64)"
no_calls "postrm: abort-remove pass never invokes the stub"
assert_eq "postrm: abort-upgrade pass is a no-op rc 0" "0" \
    "$(run_hook "$POSTRM" "abort-upgrade" 6.12.8-1-amd64)"
no_calls "postrm: abort-upgrade pass never invokes the stub"
assert_eq "postrm: plain remove pass still acts after the gate change" "0" \
    "$(run_hook "$POSTRM" "remove 6.12.8-1" 6.12.8-1-amd64)"
assert_eq "postrm: plain remove invoked the stub" "ukictl remove 6.12.8-1-amd64" \
    "$(cat "$T/calls.log")"
assert_eq "postrm: purge pass still acts" "0" \
    "$(run_hook "$POSTRM" "purge 6.12.8-1" 6.12.8-1-amd64)"
assert_eq "postrm: purge invoked the stub" "ukictl remove 6.12.8-1-amd64" \
    "$(cat "$T/calls.log")"

# =============================================================================
# postinst: IN-04 — the hook APPENDS its recovery line below the build's own
# marker reason (the build names the exact failing step; overwriting it with
# the generic hook text destroys the diagnosis).
# =============================================================================
export DEBIAN_FDE_FAKE_RC=64
rm -f "$MARKER"
printf 'ukictl build failed for kernel 6.12.10-1\nreason: cmdline pins guard: conflicting pin override rd.shell=1\ntime: t\n' >"$MARKER"
assert_eq "postinst: failing run with pre-seeded build marker rc 64" "64" \
    "$(run_hook "$POSTINST" "configure 6.12.10-1" 6.12.10-1-amd64)"
assert_contains "postinst: build's own marker reason survives the hook" \
    "$(cat "$MARKER")" "conflicting pin override rd.shell=1"
assert_contains "postinst: hook recovery line appended below it" \
    "$(cat "$MARKER")" "recovery:"
rm -f "$MARKER"
export DEBIAN_FDE_FAKE_RC=0

# =============================================================================
# boot-manager hook (LO-05): verify-first — an already-signed binary is NOT
# re-signed (sbsign APPENDS; a manual re-run during a rotation window must not
# stack a dual signature onto the boot manager).
# =============================================================================
BOOT_HOOK=$REPO/hooks/systemd-boot-upgrade-zz-debian-fde
assert_file_exists "boot-manager hook template exists" "$BOOT_HOOK"
sh -n "$BOOT_HOOK" >/dev/null 2>&1
assert_eq "boot-manager hook parses under POSIX sh" "0" "$?"

BESP=$T/esp
BFAKE=$T/bootbin
mkdir -p "$BFAKE" "$BESP/EFI/systemd" "$BESP/EFI/BOOT"
printf 'unsigned-boot-manager' >"$BESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$BESP/EFI/BOOT/BOOTX64.EFI"
# stubs: sbsign marks the output "signed" and logs; sbverify accepts ONLY
# signed content (== verifies against the current key)
cat >"$BFAKE/sbsign" <<EOF
#!/bin/sh
echo "sbsign \$*" >>'$T/sbsign.log'
out=""
next_out=0
for a in "\$@"; do
    [ "\$next_out" = 1 ] && out=\$a && next_out=0
    [ "\$a" = "--output" ] && next_out=1
done
for src in "\$@"; do :; done   # POSIX: last arg is the source file
{ cat "\$src"; printf 'signed'; } >"\$out"
EOF
cat >"$BFAKE/sbverify" <<EOF
#!/bin/sh
for f in "\$@"; do :; done      # POSIX: last arg is the file to verify
[ "\$(tail -c 6 "\$f")" = "signed" ] || exit 1
EOF
chmod +x "$BFAKE/sbsign" "$BFAKE/sbverify"
: >"$T/sbsign.log"

run_boot_hook() {
    : >"$T/sbsign.log"
    PATH="$BFAKE:$PATH" DEBIAN_FDE_ESP="$BESP" DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" \
        DEBIAN_FDE_ROOT=$T/root \
        sh "$BOOT_HOOK" >"$T/out.log" 2>&1
    echo $?
}

assert_eq "boot hook: first run signs the unsigned binaries rc 0" "0" "$(run_boot_hook)"
assert_eq "boot hook: first run invoked sbsign for both binaries" "2" \
    "$(grep -c . "$T/sbsign.log")"
assert_eq "boot hook: systemd-bootx64 now signed" "signed" \
    "$(tail -c 6 "$BESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "boot hook: fallback loader now signed" "signed" \
    "$(tail -c 6 "$BESP/EFI/BOOT/BOOTX64.EFI")"

assert_eq "boot hook: manual re-run rc 0 (idempotent)" "0" "$(run_boot_hook)"
assert_eq "boot hook: re-run does NOT re-sign an already-verified binary" "0" \
    "$(grep -c . "$T/sbsign.log")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
