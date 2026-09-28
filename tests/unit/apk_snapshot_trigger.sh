#!/usr/bin/env bash
# tests/unit/apk_snapshot_trigger.sh — user decision item 9: the APK
# AUTO-SNAPSHOT trigger (docs/Architecture.md §4/§8.1; the sibling of the
# kernel trigger hooks/apk/triggers/alpine-fde.trigger):
#
#   hooks/apk/triggers/alpine-fde-snapshot.trigger
#
# Contract pinned here:
#   * artifact: present, executable, parses under POSIX sh (busybox ash),
#     watched-dir directive is "/" (EVERY apk transaction that installs
#     files — upgrades AND adds can touch the boot chain), names its exec
#     path, `describe` prints a description and changes nothing
#   * §8.1 machine/lib entrance: the trigger SOURCES the lib
#     (lib/cmd/pre-upgrade.sh -> pu_auto_snapshot_main) and NEVER execs the
#     `alpine-fde` CLI
#   * rc propagation: a fail-closed snapshot (lib rc 64) propagates to apk
#     (ADR-8 spirit: the lost rollback point is announced, never swallowed);
#     rc 0 on the graceful paths
#   * degrade-safe: a MISSING lib module is a logged skip + rc 0 — the
#     snapshot is rollback INSURANCE and must never fail an apk transaction
#     that already committed (the kernel trigger's loud ADR-8 failure is
#     load-bearing; this trigger's is deliberately not)
#   * staging (lib/cmd/install.sh): the plan copies BOTH the trigger (to
#     /etc/apk/triggers/, +x) and the retention default (hooks/conf.d/
#     alpine-fde-snapshot -> /etc/conf.d/alpine-fde-snapshot) — plain `cp`
#     overwrite records, idempotent under crash-resume re-run
#
# Hermetic: stub lib tree + PATH-stubbed logger/btrfs; no TPM, no mounts.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

TRIGGER=$REPO/hooks/apk/triggers/alpine-fde-snapshot.trigger
CONF=$REPO/hooks/conf.d/alpine-fde-snapshot
INSTALL=$REPO/lib/cmd/install.sh

# =============================================================================
# artifact contract (mirrors the kernel-trigger pins in kernel_hooks_wire.sh)
# =============================================================================
assert_file_exists "snapshot trigger exists" "$TRIGGER"
assert_eq "snapshot trigger is executable" "1" "$([ -x "$TRIGGER" ] && echo 1 || echo 0)"
sh -n "$TRIGGER" >/dev/null 2>&1
assert_eq "snapshot trigger parses under POSIX sh (busybox ash)" "0" "$?"
TRIG_C=$(cat "$TRIGGER")
assert_contains "snapshot trigger: watched dir directive is / (every transaction)" \
    "$TRIG_C" $'\n#   /\n'
assert_contains "snapshot trigger: names its exec path" "$TRIG_C" \
    "/lib/apk/exec/alpine-fde-snapshot.trigger"
assert_not_contains "snapshot trigger: no dpkg-era anything" "$TRIG_C" "dpkg"
assert_not_contains "snapshot trigger: no CLI exec (§8.1 machine/lib entrance)" \
    "$TRIG_C" "alpine-fde kernel"
assert_contains "snapshot trigger: sources the lib module" "$TRIG_C" \
    "cmd/pre-upgrade.sh"
assert_contains "snapshot trigger: honors the retention seam" "$TRIG_C" \
    "ALPINE_FDE_SNAPSHOT_KEEP"

# retention default config artifact
assert_file_exists "retention conf exists" "$CONF"
sh -n "$CONF" >/dev/null 2>&1
assert_eq "retention conf parses under POSIX sh" "0" "$?"
assert_contains "retention conf: keep-N default 5" "$(cat "$CONF")" \
    "ALPINE_FDE_SNAPSHOT_KEEP=5"

# `describe` — print a description, change nothing (apk protocol)
OUT=$(sh "$TRIGGER" describe 2>&1)
assert_rc "describe rc 0" 0 sh "$TRIGGER" describe
assert_contains "describe prints a description" "$OUT" "snapshot"

# =============================================================================
# behavioral: the REAL trigger driven against a RECORDING stub lib tree
# =============================================================================
T=$(mktemp -d /tmp/alpine-fde-snaptrig.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

mkdir -p "$T/fakelib/cmd" "$T/stub" "$T/root/etc"
cat >"$T/fakelib/cmd/pre-upgrade.sh" <<EOF
#!/bin/sh
# stub module: records the entry argv, exits with the scripted rc
pu_auto_snapshot_main() {
    printf '%s\n' "auto-snapshot \$*" >>"$T/calls.log"
    exit \$ALPINE_FDE_FAKE_RC
}
EOF
chmod +x "$T/fakelib/cmd/pre-upgrade.sh"
cat >"$T/stub/logger" <<EOF
#!/bin/sh
printf '%s\n' "logger \$*" >>"$T/logger.log"
exit 0
EOF
chmod +x "$T/stub/logger"

run_trigger() { # <fake-rc> <args...>
    ALPINE_FDE_FAKE_RC=$1
    shift
    : >"$T/calls.log"; : >"$T/logger.log"
    ALPINE_FDE_LIB_DIR=$T/fakelib ALPINE_FDE_ROOT=$T/root \
        ALPINE_FDE_FAKE_RC=$ALPINE_FDE_FAKE_RC PATH="$T/stub:$PATH" \
        sh "$TRIGGER" "$@" >"$T/out.log" 2>&1
    echo $?
}

# contract: happy path — lib entry invoked, rc 0
assert_eq "trigger: lib entry invoked, rc 0" "0" "$(run_trigger 0 /)"
assert_eq "trigger: invoked pu_auto_snapshot_main verbatim" \
    "auto-snapshot " "$(cat "$T/calls.log")"

# contract: rc propagation — lib rc 64 (fail-closed snapshot) reaches apk
assert_eq "trigger: fail-closed lib rc propagates (64)" "64" "$(run_trigger 64 /)"

# contract: degrade-safe — a MISSING lib module is rc 0 + a logged line
assert_eq "trigger: missing lib module degrades to rc 0" "0" "$(
    : >"$T/logger.log"
    ALPINE_FDE_LIB_DIR=$T/absent ALPINE_FDE_ROOT=$T/root PATH="$T/stub:$PATH" \
        sh "$TRIGGER" / >"$T/out.log" 2>&1
    echo $?
)"
assert_file_exists "trigger: missing-lib skip is logged to syslog" "$T/logger.log"

# contract: NOT a CLI exec — the trigger text never spawns the `alpine-fde`
# binary (the §8.1 machine/lib entrance: sourced module + direct lib call)
assert_not_contains "trigger: no CLI dispatch call" "$(cat "$TRIGGER")" \
    'bin/alpine-fde'

# =============================================================================
# staging contract (lib/cmd/install.sh): trigger + retention conf staged,
# idempotent plain-copy records (crash-resume re-run safe)
# =============================================================================
assert_contains "staging: preflight checklist lists the snapshot trigger" \
    "$(cat "$INSTALL")" "apk/triggers/alpine-fde-snapshot.trigger"
assert_contains "staging: preflight checklist lists the retention conf" \
    "$(cat "$INSTALL")" "conf.d/alpine-fde-snapshot"
assert_contains "staging: plan copies the snapshot trigger into the target" \
    "$(cat "$INSTALL")" \
    'cp $_im_hooks/apk/triggers/alpine-fde-snapshot.trigger $_im_mnt/etc/apk/triggers/alpine-fde-snapshot.trigger'
assert_contains "staging: plan copies the retention conf into the target" \
    "$(cat "$INSTALL")" \
    'cp $_im_hooks/conf.d/alpine-fde-snapshot $_im_mnt/etc/conf.d/alpine-fde-snapshot'
assert_contains "staging: plan chmod +x the snapshot trigger" \
    "$(cat "$INSTALL")" \
    'chmod +x $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh $_im_mnt/etc/apk/triggers/alpine-fde.trigger $_im_mnt/etc/apk/triggers/alpine-fde-snapshot.trigger'

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# apk_snapshot_trigger: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
