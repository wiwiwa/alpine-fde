#!/usr/bin/env bash
# tests/unit/initrd_audit.sh — G-U3 (§8.2/§12/I6): initrd inventory audit on
# every build. Required unlock artifacts (token lib at the multiarch systemd
# path, libtss2 libs, TPM kernel modules + tpmrm0 udev rules) and deny rules
# (no compilers, package tools, unnecessary shells). Any miss is a loud ADR-8
# build failure (rc 64 + build-failed marker naming the artifact, no ESP
# mutation). The lsinitrd collaborator is the configurable fake
# fixtures/initramfs/lsinitrd-fake.sh.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

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

. "$REPO/lib/common.sh"
. "$REPO/lib/initramfs.sh"

FAKE="$REPO/fixtures/initramfs/lsinitrd-fake.sh"

# --- inventories -----------------------------------------------------------------
inv_complete="$TMP/inv-complete.txt"
cat >"$inv_complete" <<'EOF'
-rw-r--r--   1 root root  22k usr/lib/x86_64-linux-gnu/systemd/libcryptsetup-token-systemd-tpm2.so
-rw-r--r--   1 root root 500k usr/lib/x86_64-linux-gnu/libtss2-esys.so.0.0.0
-rw-r--r--   1 root root  20k usr/lib/x86_64-linux-gnu/libtss2-mu.so.0.0.0
-rw-r--r--   1 root root  12k usr/lib/x86_64-linux-gnu/libtss2-rc.so.0.0.0
-rw-r--r--   1 root root  30k usr/lib/x86_64-linux-gnu/libtss2-sys.so.0.0.0
-rw-r--r--   1 root root  10k usr/lib/x86_64-linux-gnu/libtss2-tctildr.so.0.0.0
-rw-r--r--   1 root root  10k usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0.0.0
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm.ko
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm_tis.ko
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm_crb.ko
-rw-r--r--   1 root root  383 usr/lib/udev/rules.d/60-tpm-udev.rules
-rwxr-xr-x   1 root root  60k usr/bin/systemd-cryptsetup
-rwxr-xr-x   1 root root  90k bin/sh
EOF
# scenario 1: complete minus the systemd-tpm2 token lib
grep -v 'libcryptsetup-token-systemd-tpm2' "$inv_complete" >"$TMP/inv-missing-token.txt"
# scenario 2: complete + compiler, package tool, and a shell beyond the allowlist
{ cat "$inv_complete"
  printf '%s\n' \
      '-rwxr-xr-x 1 root root 900k usr/bin/gcc-12' \
      '-rwxr-xr-x 1 root root 200k usr/bin/dpkg-query' \
      '-rwxr-xr-x 1 root root 800k usr/bin/bash'
} >"$TMP/inv-deny.txt"

# --- scenario 1: missing token lib -> rc != 0, reason names the artifact ----------
_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$TMP/inv-missing-token.txt" \
    initrd_audit "$TMP/whatever.img"
assert_rc "audit 1: missing token lib fails the audit" 1 $?
assert_contains "audit 1: reason names the missing artifact" \
    "$_initrd_audit_reason" "libcryptsetup-token-systemd-tpm2.so"

# --- scenario 2: compiler/package-tool/shell present -> rc != 0 --------------------
_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$TMP/inv-deny.txt" \
    initrd_audit "$TMP/whatever.img"
assert_rc "audit 2: compiler present fails the audit" 1 $?
assert_contains "audit 2: reason names the denied compiler" "$_initrd_audit_reason" "gcc-12"

# --- scenario 3: complete multiarch inventory -> rc 0 -------------------------------
_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$inv_complete" \
    initrd_audit "$TMP/whatever.img"
assert_rc "audit 3: complete multiarch inventory passes" 0 $?
assert_eq "audit 3: no failure reason on success" "" "$_initrd_audit_reason"

# --- audit invokes the lister on the built initrd -----------------------------------
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$inv_complete" \
    LSINITRD_FAKE_ARGV="$TMP/ls.argv" \
    initrd_audit "$TMP/workdir/initrd.img" 2>/dev/null
assert_eq "audit runs the lister with the initrd image as its argument" \
    "initrd.img" "$(basename "$(head -n 1 "$TMP/ls.argv" 2>/dev/null)")"

# --- MD-04: fixture-variant inventories (dracut-shaped deny rules) -------------------
# LSINITRD_FAKE_VARIANT emits dracut-shaped inventories (fixtures/initramfs/
# lsinitrd-fake.sh): `base` is a compliant Debian dracut inventory INCLUDING
# usr/bin/dash + the /bin/sh -> dash symlink (Debian's dracut ships dash as the
# initrd shell — allowed, see the dash resolution in lib/initramfs.sh); the
# other variants add exactly one denied artifact class. Audit-level: each deny
# variant fails rc 1 naming the artifact; base passes.
_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_VARIANT=base \
    initrd_audit "$TMP/whatever.img" 2>/dev/null
assert_rc "audit 5: dracut-shaped base inventory (dash shell) passes" 0 $?
assert_eq "audit 5: no reason on the dracut-shaped base" "" "$_initrd_audit_reason"

_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_VARIANT=clang \
    initrd_audit "$TMP/whatever.img" 2>/dev/null
assert_rc "audit 6: clang present fails the audit" 1 $?
assert_contains "audit 6: reason names the denied clang" "$_initrd_audit_reason" "usr/bin/clang"

_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_VARIANT=triplet-gcc \
    initrd_audit "$TMP/whatever.img" 2>/dev/null
assert_rc "audit 7: triplet-prefixed toolchain present fails the audit" 1 $?
assert_contains "audit 7: reason names the denied triplet gcc" "$_initrd_audit_reason" "x86_64-linux-gnu-gcc-12"

_initrd_audit_reason=''
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_VARIANT=busybox \
    initrd_audit "$TMP/whatever.img" 2>/dev/null
assert_rc "audit 8: busybox present fails the audit" 1 $?
assert_contains "audit 8: reason names the denied busybox" "$_initrd_audit_reason" "usr/bin/busybox"

# --- scenario 4: full real `ukictl build` over the fake inventory --------------------
KVER=6.12.8-1-amd64
ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/debian-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/debian-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
# compliant crypttab: the G-U4 guard owns that precondition; this file tests
# the initrd inventory audit (§8.2/I6) in isolation
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"

# 4a: non-compliant inventory (missing token lib) -> rc 64 + marker, ESP untouched
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$TMP/inv-missing-token.txt" \
LSINITRD_FAKE_ARGV="$TMP/build-ls.argv" \
DEBIAN_FDE_BIN_TEST=1 DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_ESP="$ESP" \
DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" DEBIAN_FDE_NO_INSTALL=1 \
DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
RETENTION=1 \
    "$REPO/bin/debian-fde" ukictl build "$KVER" >/dev/null 2>&1
assert_rc "audit 4a: full build fails closed (64) on a non-compliant inventory" 64 $?
assert_file_exists "audit 4a: ADR-8 failure marker persisted" "$ROOT/etc/debian-fde/build-failed"
assert_contains "audit 4a: marker names the missing artifact" \
    "$(cat "$ROOT/etc/debian-fde/build-failed")" "libcryptsetup-token-systemd-tpm2.so"
assert_eq "audit 4a: no ESP mutation (no UKI installed)" "" \
    "$(find "$ESP" -type f -name '*.efi' -print)"
assert_file_absent "audit 4a: no predictions.json (failure was pre-ESP)" \
    "$ROOT/etc/debian-fde/predictions.json"
assert_eq "audit 4a: lsinitrd ran against the built initrd (audit is wired)" \
    "initrd.img" "$(basename "$(head -n 1 "$TMP/build-ls.argv" 2>/dev/null)")"

# 4b: compliant inventory -> full build succeeds
LSINITRD_CMD="$FAKE" LSINITRD_FAKE_INV="$inv_complete" \
DEBIAN_FDE_BIN_TEST=1 DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_ESP="$ESP" \
DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" DEBIAN_FDE_NO_INSTALL=1 \
DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
RETENTION=1 \
    "$REPO/bin/debian-fde" ukictl build "$KVER" >/dev/null 2>&1
assert_rc "audit 4b: full build succeeds over a compliant fake inventory" 0 $?
assert_file_exists "audit 4b: UKI installed on the ESP" \
    "$ESP/EFI/Linux/debian-fde-$KVER.efi"
assert_file_absent "audit 4b: failure marker cleared on success" \
    "$ROOT/etc/debian-fde/build-failed"

# 4c-4f: MD-04 full-build legs over the fixture variants — a denied artifact
# must fail the build closed (64 + ADR-8 marker naming it, ESP untouched); the
# dracut-shaped base (dash) must BUILD, because the dash allow rule is
# load-bearing for every real production dracut initrd.
variant_build() {
    LSINITRD_CMD="$FAKE" LSINITRD_FAKE_VARIANT="$1" \
    DEBIAN_FDE_BIN_TEST=1 DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_ESP="$ESP" \
    DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=1 \
        "$REPO/bin/debian-fde" ukictl build "$KVER" >/dev/null 2>&1
}
ESP_BEFORE_MD04=$(find "$ESP" -type f -exec sha256sum {} \; | sort)

rm -f "$ROOT/etc/debian-fde/build-failed"
variant_build clang
assert_rc "audit 4c: full build fails closed (64) with clang in the inventory" 64 $?
assert_file_exists "audit 4c: ADR-8 marker persisted" "$ROOT/etc/debian-fde/build-failed"
assert_contains "audit 4c: marker names the denied clang" \
    "$(cat "$ROOT/etc/debian-fde/build-failed")" "usr/bin/clang"
assert_eq "audit 4c: ESP untouched by the denied-inventory build" \
    "$ESP_BEFORE_MD04" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"

rm -f "$ROOT/etc/debian-fde/build-failed"
variant_build triplet-gcc
assert_rc "audit 4d: full build fails closed (64) with a triplet-prefixed toolchain" 64 $?
assert_contains "audit 4d: marker names the triplet gcc" \
    "$(cat "$ROOT/etc/debian-fde/build-failed")" "x86_64-linux-gnu-gcc-12"

rm -f "$ROOT/etc/debian-fde/build-failed"
variant_build busybox
assert_rc "audit 4e: full build fails closed (64) with busybox in the inventory" 64 $?
assert_contains "audit 4e: marker names the denied busybox" \
    "$(cat "$ROOT/etc/debian-fde/build-failed")" "usr/bin/busybox"
assert_eq "audit 4e: ESP untouched by the denied-inventory build" \
    "$ESP_BEFORE_MD04" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"

variant_build base
assert_rc "audit 4f: full build SUCCEEDS over the dracut-shaped base (dash allowed)" 0 $?
assert_file_absent "audit 4f: successful build cleared the stale marker" \
    "$ROOT/etc/debian-fde/build-failed"

finish
