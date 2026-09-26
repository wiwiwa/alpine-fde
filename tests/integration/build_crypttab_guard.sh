#!/usr/bin/env bash
# tests/integration/build_crypttab_guard.sh — G-U4 (§8.2): verified coupling guard.
# systemd-cryptsetup adds tpm2-tss to the initrd only when /etc/crypttab carries
# a tpm2-device= option AT BUILD TIME; omitting it silently disables all TPM
# unlock. `ukictl build` therefore refuses (rc 64 + ADR-8 marker) before the
# initramfs builder ever runs, unless root's crypttab line carries tpm2-device=.
# The INITRAMFS_CMD stub records invocations: on a guard failure dracut-equivalent
# must run ZERO times; on success at least once.
#
# G-ST4 topology-awareness (§8.2 crypttab contract / §4.1): the guard parses ALL
# non-comment entries whose target is `root` or `root<N>` (RAID1 root1/root2);
# tpm2-device= is required on EVERY such entry; a multi-entry (RAID1) file
# additionally requires password-cache=yes on every entry (single-disk entries
# MAY carry it — allowed, not required); with BCACHE=1 persisted in
# alpine-fde.conf the file must be bcache-shaped (exactly ONE root entry).
#
# real-server blocker #10: BCACHE=1 covered both bcache AND bcache-multi, so
# the exactly-one count rule false-positived on bcache-multi's correct
# root1+root2 crypttab. The conf persists TOPOLOGY=<single|bcache|bcache-multi|
# raid1> and the count rule is topology-aware (single/bcache ⇒ 1;
# bcache-multi/raid1 ⇒ >=2); an OLD conf without TOPOLOGY keeps the legacy
# BCACHE=1 ⇒ exactly-one rule (back-compat, section 10); invalid TOPOLOGY
# warns and defaults to single.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"

assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}
assert_file_absent() {
    if [ ! -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file unexpectedly exists: $2)"
    fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

KVER=6.12.8-1-amd64
ROOT="$TMP/root"
ESP="$TMP/esp"
CALLS="$TMP/initramfs.calls"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"

# recording INITRAMFS_CMD stub: appends the kver per invocation, writes output
REC="$TMP/record-initramfs.sh"
cat >"$REC" <<EOF
#!/bin/sh
set -eu
[ \$# -eq 2 ] || exit 2
printf '%s\n' "\$2" >>'$CALLS'
printf 'stub initramfs for %s\n' "\$2" >"\$1"
EOF
chmod +x "$REC"

# invocations so far (0 when the stub never ran)
calls() {
    if [ -f "$CALLS" ]; then
        wc -l <"$CALLS" | tr -d '[:space:]'
    else
        printf '0'
    fi
}

build() {
    # env -i style explicit pass-through: guard verdicts must not depend on
    # leaked shell state between scenarios
    env ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP" \
        ALPINE_FDE_KEYDIR="$REPO/fixtures/keys" ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REC {out} {kver}" \
        RETENTION=1 \
        "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
}

# --- 1. crypttab missing entirely --------------------------------------------------
rm -f "$ROOT/etc/crypttab" "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 1: missing crypttab fails closed (64)" 64 $?
assert_file_exists "crypttab 1: ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "crypttab 1: marker names the crypttab guard" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "crypttab guard"
assert_eq "crypttab 1: initramfs builder never invoked" "0" "$(calls)"
assert_eq "crypttab 1: no ESP mutation" "" "$(find "$ESP" -type f -name '*.efi' -print)"

# --- 2. root line WITHOUT tpm2-device= (commented compliant line must not count) ---
printf '%s\n' \
    '# root UUID=11111111-1111-1111-1111-111111111111 none luks,tpm2-device=auto,discard' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 2: root line without tpm2-device= fails closed (64)" 64 $?
assert_contains "crypttab 2: marker names the missing tpm2-device option" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "tpm2-device"
assert_eq "crypttab 2: initramfs builder never invoked" "0" "$(calls)"

# --- 3. tpm2-device= only on a non-root line ----------------------------------------
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,discard' \
    'swap /dev/mapper/cryptswap none luks,tpm2-device=auto' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS"
build
assert_rc "crypttab 3: tpm2-device= on a non-root line is not sufficient" 64 $?
assert_eq "crypttab 3: initramfs builder never invoked" "0" "$(calls)"

# --- 4. compliant crypttab -> build proceeds ----------------------------------------
printf '%s\n' \
    '# comment lines ignored' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 4: compliant crypttab lets the build succeed" 0 $?
assert_eq "crypttab 4: initramfs builder invoked at least once" "1" "$(calls)"
assert_file_exists "crypttab 4: UKI installed" "$ESP/EFI/Linux/alpine-fde-$KVER.efi"
assert_file_absent "crypttab 4: failure marker cleared" "$ROOT/etc/alpine-fde/build-failed"

# --- 5. RAID1 crypttab (root1/root2, tpm2-device + password-cache) -> proceeds ------
printf '%s\n' \
    '# RAID1 members (§4.1 topology 3, written by the installer)' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 5: RAID1 root1/root2 with tpm2-device+password-cache passes" 0 $?
assert_eq "crypttab 5: initramfs builder invoked" "1" "$(calls)"

# --- 6. RAID1 member WITHOUT tpm2-device= -> fails closed ---------------------------
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 6: RAID1 member without tpm2-device= fails closed (64)" 64 $?
assert_contains "crypttab 6: marker names the missing tpm2-device option" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "tpm2-device"
assert_eq "crypttab 6: initramfs builder never invoked" "0" "$(calls)"

# --- 7. RAID1 members WITHOUT password-cache=yes -> fails closed ---------------------
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 7: RAID1 members without password-cache=yes fail closed (64)" 64 $?
assert_contains "crypttab 7: marker names the missing password-cache option" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "password-cache"
assert_eq "crypttab 7: initramfs builder never invoked" "0" "$(calls)"

# --- 8. single-disk entry WITH password-cache=yes -> passes (allowed, not required) --
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 8: single-disk entry MAY carry password-cache=yes" 0 $?
assert_eq "crypttab 8: initramfs builder invoked" "1" "$(calls)"

# --- 9. conf BCACHE=1: bcache-shaped single-root crypttab passes ----------------------
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' >"$TMP/alpine-fde.conf"
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 9: BCACHE=1 with a single root entry (bcache shape) passes" 0 $?
assert_eq "crypttab 9: initramfs builder invoked" "1" "$(calls)"

# --- 10. conf BCACHE=1 with a RAID1-shaped file -> fails closed -----------------------
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 10: BCACHE=1 refuses a multi-entry (RAID1) crypttab (64)" 64 $?
assert_contains "crypttab 10: marker names the bcache single-entry requirement" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "bcache"
assert_eq "crypttab 10: initramfs builder never invoked" "0" "$(calls)"
# NOTE: section 10 IS the back-compat leg for blocker #10 — an OLD conf
# (BCACHE=1, no TOPOLOGY key) must keep the historical exactly-one rule.

# =============================================================================
# real-server blocker #10: the persisted conf covered bcache AND bcache-multi
# with the single BCACHE=1 flag, so crypttab_tpm2_check's "BCACHE=1 ⇒ exactly
# one root entry" count rule false-positived on bcache-multi's CORRECT
# root1+root2 crypttab (the live run died "found 2"). The conf now persists
# TOPOLOGY=<single|bcache|bcache-multi|raid1> and the count rule is
# topology-aware: single/bcache ⇒ exactly 1; bcache-multi/raid1 ⇒ >=2.
# =============================================================================

# --- 11. TOPOLOGY=bcache-multi with the correct 2-entry crypttab -> passes ----
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=bcache-multi' >"$TMP/alpine-fde.conf"
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 11 (blocker #10): TOPOLOGY=bcache-multi accepts its correct root1+root2 crypttab" 0 $?
assert_eq "crypttab 11 (blocker #10): initramfs builder invoked" "1" "$(calls)"
assert_file_absent "crypttab 11 (blocker #10): failure marker cleared" "$ROOT/etc/alpine-fde/build-failed"

# --- 12. TOPOLOGY=single: exactly-one rule intact ------------------------------
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=0' 'TOPOLOGY=single' >"$TMP/alpine-fde.conf"
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 12: TOPOLOGY=single accepts a single root entry" 0 $?
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 12: TOPOLOGY=single refuses a 2-entry crypttab (64)" 64 $?
assert_eq "crypttab 12: initramfs builder never invoked" "0" "$(calls)"

# --- 13. TOPOLOGY=bcache (plain): exactly-one rule intact ----------------------
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=bcache' >"$TMP/alpine-fde.conf"
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 13: TOPOLOGY=bcache accepts a single root entry (bcache shape)" 0 $?
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 13: TOPOLOGY=bcache refuses a 2-entry crypttab (64)" 64 $?
assert_eq "crypttab 13: initramfs builder never invoked" "0" "$(calls)"

# --- 14. invalid TOPOLOGY -> warn + default to single --------------------------
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=topo-nonsense' >"$TMP/alpine-fde.conf"
printf '%s\n' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
IV_OUT=$(env ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP" \
    ALPINE_FDE_KEYDIR="$REPO/fixtures/keys" ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REC {out} {kver}" \
    RETENTION=1 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" 2>&1 >/dev/null)
assert_rc "crypttab 14: invalid TOPOLOGY defaults to single (1-entry crypttab passes)" 0 $?
assert_contains "crypttab 14: invalid TOPOLOGY warns and names the default" "$IV_OUT" \
    "invalid TOPOLOGY"
assert_contains "crypttab 14: the warn names the default" "$IV_OUT" "defaulting to single"
# the defaulted single rule still bites a 2-entry file
printf '%s\n' \
    'root1 UUID=33333333-3333-3333-3333-333333333333 none luks,tpm2-device=auto,password-cache=yes,discard' \
    'root2 UUID=44444444-4444-4444-4444-444444444444 none luks,tpm2-device=auto,password-cache=yes,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "crypttab 14: invalid TOPOLOGY defaulted to single refuses a 2-entry crypttab (64)" 64 $?
rm -f "$TMP/alpine-fde.conf" # restore the absent-conf default for later legs

# =============================================================================
# direct lib legs: initramfs_topology resolves INI_TOPOLOGY/INI_BCACHE
# =============================================================================
ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/initramfs.sh
source "$REPO/lib/initramfs.sh"
export ALPINE_FDE_CONF="$TMP/alpine-fde.conf" # the direct legs read THIS conf

# TOPOLOGY=bcache-multi: INI_TOPOLOGY set AND INI_BCACHE stays 1 (bcache.ko
# is still required in the initrd for a bcache-multi root)
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=bcache-multi' >"$TMP/alpine-fde.conf"
INI_TOPOLOGY=''; INI_BCACHE=0; _INI_TOPO_WARNED=0
initramfs_topology </dev/null
assert_eq "topology lib: TOPOLOGY=bcache-multi resolves INI_TOPOLOGY" "bcache-multi" "$INI_TOPOLOGY"
assert_eq "topology lib: TOPOLOGY=bcache-multi keeps INI_BCACHE=1 (bcache.ko needed)" "1" "$INI_BCACHE"

# back-compat: OLD conf without TOPOLOGY — INI_TOPOLOGY empty, BCACHE drives
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' >"$TMP/alpine-fde.conf"
INI_TOPOLOGY=''; INI_BCACHE=0; _INI_TOPO_WARNED=0
initramfs_topology </dev/null
assert_eq "topology lib: conf without TOPOLOGY leaves INI_TOPOLOGY empty (legacy derive)" "" "$INI_TOPOLOGY"
assert_eq "topology lib: conf without TOPOLOGY keeps deriving INI_BCACHE from BCACHE" "1" "$INI_BCACHE"

# TOPOLOGY=single: INI_BCACHE forced 0 even if a stale BCACHE=1 lingers
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=single' >"$TMP/alpine-fde.conf"
INI_TOPOLOGY=''; INI_BCACHE=1; _INI_TOPO_WARNED=0
initramfs_topology </dev/null
assert_eq "topology lib: TOPOLOGY=single resolves INI_TOPOLOGY" "single" "$INI_TOPOLOGY"
assert_eq "topology lib: TOPOLOGY=single forces INI_BCACHE=0 (no bcache.ko)" "0" "$INI_BCACHE"

# invalid TOPOLOGY: warn-once + default single, INI_BCACHE 0
printf '%s\n' 'ROOT_FS=btrfs' 'BCACHE=1' 'TOPOLOGY=nonsense' >"$TMP/alpine-fde.conf"
IV_WARN=$(
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" # subshell: assignments do not leak
    INI_TOPOLOGY=''; INI_BCACHE=1; _INI_TOPO_WARNED=0
    initramfs_topology </dev/null 2>&1
)
assert_eq "topology lib: invalid TOPOLOGY defaults INI_TOPOLOGY to single" "single" "$INI_TOPOLOGY"
assert_eq "topology lib: invalid TOPOLOGY forces INI_BCACHE=0" "0" "$INI_BCACHE"
assert_contains "topology lib: invalid TOPOLOGY warns" "$IV_WARN" "invalid TOPOLOGY"
rm -f "$TMP/alpine-fde.conf"

finish
