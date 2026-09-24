#!/usr/bin/env bash
# tests/unit/initrd_audit.sh — G-C11 (§8.2/§12/I6, orchestrator resolution R9):
# initrd inventory audit of the mkinitfs initramfs on every build. Required
# unlock artifacts (Alpine shape): the alpine-fde-unseal.sh hook itself,
# cryptsetup, openssl, the exact tpm2 verbs the hook runs, libtss2 libs, TPM
# kernel modules + the tpmrm0 udev rule, and per persisted topology the root
# fs driver (btrfs default / ext4) and — for BCACHE=1 — bcache.ko +
# 69-bcache.rules. Deny rules: no compilers (gcc/cc/make/clang, triplet
# toolchains), no package tools (apk/apt/dpkg), no foreign shells
# (bash/zsh/dash) — busybox/ash/sh are ALLOWED: busybox IS the mkinitfs init
# framework; the "no interactive shell" guarantee moved to hook level
# (tests/unit/hooks_mkinitfs_unseal.sh, G-C8). Any miss is a loud ADR-8
# build failure (rc 64 + build-failed marker naming the artifact, no ESP
# mutation). The lister is the configurable fake
# fixtures/initramfs/cpio-lister-fake.sh (cpio-shaped inventory).
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

# deterministic topology: absent conf ⇒ btrfs default (per-call conf legs
# below override this for ROOT_FS=ext4 / BCACHE=1)
export ALPINE_FDE_CONF="$TMP/conf-default-absent"

FAKE="$REPO/fixtures/initramfs/cpio-lister-fake.sh"
IMG="$TMP/whatever.img"
AUDIT_CONF='' # optional per-call ALPINE_FDE_CONF override (topology legs)

# run_audit <inventory-file | V:variant> — drive the audit in THIS shell with
# literal var-prefix assignments (they export to the lister child). rc lands
# in $RUN_AUDIT_RC, the failure reason in $_initrd_audit_reason.
RUN_AUDIT_RC=0
run_audit() {
    _initrd_audit_reason=''
    local spec=$1
    if [ -n "$AUDIT_CONF" ]; then
        if [ "${spec#V:}" != "$spec" ]; then
            ALPINE_FDE_CONF="$AUDIT_CONF" INITRD_LISTER_CMD="$FAKE" \
                LISTER_FAKE_VARIANT="${spec#V:}" initrd_audit "$IMG" 2>/dev/null
        else
            ALPINE_FDE_CONF="$AUDIT_CONF" INITRD_LISTER_CMD="$FAKE" \
                LISTER_FAKE_INV="$spec" initrd_audit "$IMG" 2>/dev/null
        fi
    else
        if [ "${spec#V:}" != "$spec" ]; then
            INITRD_LISTER_CMD="$FAKE" LISTER_FAKE_VARIANT="${spec#V:}" initrd_audit "$IMG" 2>/dev/null
        else
            INITRD_LISTER_CMD="$FAKE" LISTER_FAKE_INV="$spec" initrd_audit "$IMG" 2>/dev/null
        fi
    fi
    RUN_AUDIT_RC=$?
}

# =============================================================================
# 1. required artifact classes — each missing class fails the audit and the
#    reason names the artifact
# =============================================================================
inv="$TMP/inv-base.txt"
cat >"$inv" <<'EOF'
usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh
usr/bin/cryptsetup
usr/lib/libcryptsetup.so.2
usr/bin/openssl
usr/lib/libcrypto.so.3
usr/bin/tpm2_pcrextend
usr/bin/tpm2_startauthsession
usr/bin/tpm2_policypcr
usr/bin/tpm2_policyauthorize
usr/bin/tpm2_loadexternal
usr/bin/tpm2_verifysignature
usr/bin/tpm2_createprimary
usr/bin/tpm2_load
usr/bin/tpm2_unseal
usr/bin/tpm2_flushcontext
usr/lib/libtss2-esys.so.0
usr/lib/libtss2-mu.so.0
usr/lib/libtss2-rc.so.0
usr/lib/libtss2-sys.so.0
usr/lib/libtss2-tctildr.so.0
usr/lib/libtss2-tcti-device.so.0
kernel/drivers/char/tpm/tpm.ko
kernel/drivers/char/tpm/tpm_tis.ko
kernel/drivers/char/tpm/tpm_crb.ko
usr/lib/udev/rules.d/60-tpm.rules
kernel/fs/btrfs/btrfs.ko
bin/busybox
bin/ash
bin/sh
EOF

grep -v 'alpine-fde-unseal\.sh$' "$inv" >"$TMP/inv-m1.txt"
run_audit "$TMP/inv-m1.txt"
assert_rc "audit 1a: missing unseal hook fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1a: reason names the hook" "$_initrd_audit_reason" "alpine-fde-unseal.sh"

grep -v 'usr/bin/tpm2_unseal$' "$inv" >"$TMP/inv-m2.txt"
run_audit "$TMP/inv-m2.txt"
assert_rc "audit 1b: missing tpm2_unseal fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1b: reason names tpm2_unseal" "$_initrd_audit_reason" "tpm2_unseal"

grep -v 'libtss2-tcti-device' "$inv" >"$TMP/inv-m3.txt"
run_audit "$TMP/inv-m3.txt"
assert_rc "audit 1c: missing libtss2 TCTI fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1c: reason names libtss2-tcti-device" "$_initrd_audit_reason" "libtss2-tcti-device"

grep -v 'kernel/drivers/char/tpm/tpm_tis\.ko$' "$inv" >"$TMP/inv-m4.txt"
run_audit "$TMP/inv-m4.txt"
assert_rc "audit 1d: missing TPM kernel module fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1d: reason names tpm_tis.ko" "$_initrd_audit_reason" "tpm_tis.ko"

grep -v '60-tpm\.rules$' "$inv" >"$TMP/inv-m5.txt"
run_audit "$TMP/inv-m5.txt"
assert_rc "audit 1e: missing TPM udev rule fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1e: reason names the TPM udev rule requirement" "$_initrd_audit_reason" "udev rule"

grep -v 'btrfs\.ko$' "$inv" >"$TMP/inv-m6.txt"
run_audit "$TMP/inv-m6.txt"
assert_rc "audit 1f: missing btrfs.ko fails the audit (default topology)" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1f: reason names btrfs.ko" "$_initrd_audit_reason" "btrfs.ko"

# =============================================================================
# 2. deny classes — compilers, package tools, foreign shells (busybox/ash OK)
# =============================================================================
run_audit <(cat "$inv"; printf '%s\n' usr/bin/gcc)
assert_rc "audit 2a: gcc present fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2a: reason names the denied compiler" "$_initrd_audit_reason" "usr/bin/gcc"

run_audit <(cat "$inv"; printf '%s\n' usr/bin/make)
assert_rc "audit 2b: make present fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2b: reason names the denied make" "$_initrd_audit_reason" "usr/bin/make"

run_audit <(cat "$inv"; printf '%s\n' usr/bin/x86_64-linux-gnu-gcc-12)
assert_rc "audit 2c: triplet-prefixed toolchain fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2c: reason names the triplet gcc" "$_initrd_audit_reason" "x86_64-linux-gnu-gcc-12"

run_audit <(cat "$inv"; printf '%s\n' usr/sbin/apk)
assert_rc "audit 2d: apk present fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2d: reason names the denied package tool" "$_initrd_audit_reason" "usr/sbin/apk"

run_audit <(cat "$inv"; printf '%s\n' usr/bin/bash usr/bin/zsh usr/bin/dash)
assert_rc "audit 2e: foreign shells fail the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2e: reason names the denied bash" "$_initrd_audit_reason" "usr/bin/bash"
assert_contains "audit 2e: reason names the denied dash" "$_initrd_audit_reason" "usr/bin/dash"

# =============================================================================
# 3. compliant inventories pass — busybox/ash/sh allowed (I6 resolution R9)
# =============================================================================
run_audit "$inv"
assert_rc "audit 3a: compliant Alpine inventory (busybox+ash+sh) passes" 0 "$RUN_AUDIT_RC"
assert_eq "audit 3a: no failure reason on success" "" "$_initrd_audit_reason"

run_audit V:alpine-base
assert_rc "audit 3b: alpine-base variant passes (busybox is the init framework)" 0 "$RUN_AUDIT_RC"

# =============================================================================
# 4. topology-driven requirements (§8.2/§4.1)
# =============================================================================
run_audit V:ext4-ok
assert_rc "audit 4a: ext4-only inventory fails under the default (btrfs) topology" 1 "$RUN_AUDIT_RC"
assert_contains "audit 4a: reason names btrfs.ko" "$_initrd_audit_reason" "btrfs.ko"

printf 'ROOT_FS=ext4\n' >"$TMP/conf-ext4"
AUDIT_CONF=$TMP/conf-ext4
run_audit V:ext4-ok
assert_rc "audit 4b: ext4-ok passes under ROOT_FS=ext4" 0 "$RUN_AUDIT_RC"
AUDIT_CONF=$TMP/conf-ext4
run_audit V:alpine-base
assert_rc "audit 4c: btrfs-shaped inventory fails under ROOT_FS=ext4" 1 "$RUN_AUDIT_RC"
assert_contains "audit 4c: reason names ext4.ko (conf-driven requirement)" \
    "$_initrd_audit_reason" "ext4.ko"

printf 'ROOT_FS=btrfs\nBCACHE=1\n' >"$TMP/conf-bcache"
AUDIT_CONF=$TMP/conf-bcache
run_audit V:bcache-ok
assert_rc "audit 4d: bcache-ok passes under BCACHE=1" 0 "$RUN_AUDIT_RC"
AUDIT_CONF=$TMP/conf-bcache
run_audit V:bcache-missing
assert_rc "audit 4e: BCACHE=1 without bcache artifacts fails" 1 "$RUN_AUDIT_RC"
assert_contains "audit 4e: reason names bcache.ko" "$_initrd_audit_reason" "bcache.ko"
AUDIT_CONF=''
run_audit V:bcache-missing
assert_rc "audit 4f: bcache artifacts NOT required without BCACHE=1" 0 "$RUN_AUDIT_RC"

# =============================================================================
# 5. lister invocation + missing-lister semantics
# =============================================================================
_initrd_audit_reason=''
INITRD_LISTER_CMD="$FAKE" LISTER_FAKE_INV="$inv" LISTER_FAKE_ARGV="$TMP/ls.argv" \
    initrd_audit "$IMG" 2>/dev/null
assert_eq "audit 5a: the lister ran against the initrd image argument" \
    "whatever.img" "$(basename "$(head -n 1 "$TMP/ls.argv" 2>/dev/null)")"

_initrd_audit_reason=''
INITRD_LISTER_CMD="$TMP/no-such-lister" initrd_audit "$TMP/img" 2>/dev/null
assert_rc "audit 5b: no lister + no INITRAMFS_CMD override = loud failure" 1 $?
assert_contains "audit 5b: reason names the lister seam" "$_initrd_audit_reason" "lister"

_initrd_audit_reason=''
INITRD_LISTER_CMD="$TMP/no-such-lister" INITRAMFS_CMD="stub {out} {kver}" \
    initrd_audit "$TMP/img" 2>/dev/null
assert_rc "audit 5c: no lister + INITRAMFS_CMD override = loud skip (override owns contents)" 0 $?
assert_eq "audit 5c: no failure reason on the skipped audit" "" "$_initrd_audit_reason"

# =============================================================================
# 6. full real `ukictl build` over the fake inventory (audit is wired)
# =============================================================================
KVER=6.6.63-0-lts
ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
printf '%s\n' "root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard" \
    >"$ROOT/etc/crypttab"

build() { # <variant>
    env INITRD_LISTER_CMD="$FAKE" LISTER_FAKE_VARIANT="$1" \
        ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP" \
        ALPINE_FDE_KEYDIR="$REPO/fixtures/keys" ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=1 \
        "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
}

# 6a: non-compliant inventory (missing hook) -> rc 64 + marker, ESP untouched
rm -f "$ROOT/etc/alpine-fde/build-failed"
build missing-hook
assert_rc "audit 6a: full build fails closed (64) on a missing unseal hook" 64 $?
assert_file_exists "audit 6a: ADR-8 failure marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "audit 6a: marker names the missing hook" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "alpine-fde-unseal.sh"
assert_eq "audit 6a: no ESP mutation (no UKI installed)" "" \
    "$(find "$ESP" -type f -name '*.efi' -print)"

# 6b: compliant inventory -> full build succeeds
build alpine-base
assert_rc "audit 6b: full build succeeds over a compliant fake inventory" 0 $?
assert_file_exists "audit 6b: UKI installed on the ESP" \
    "$ESP/EFI/Linux/alpine-fde-$KVER.efi"
assert_file_absent "audit 6b: failure marker cleared on success" \
    "$ROOT/etc/alpine-fde/build-failed"

# 6c: a denied package tool must fail the build closed (ESP untouched)
ESP_BEFORE=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
rm -f "$ROOT/etc/alpine-fde/build-failed"
build deny-apk
assert_rc "audit 6c: full build fails closed (64) with apk in the inventory" 64 $?
assert_contains "audit 6c: marker names the denied package tool" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "usr/sbin/apk"
assert_eq "audit 6c: ESP untouched by the denied-inventory build" \
    "$ESP_BEFORE" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"

# 6d: the dracut-era dash allow rule is GONE — dash in the inventory now fails
rm -f "$ROOT/etc/alpine-fde/build-failed"
build deny-shell
assert_rc "audit 6d: full build fails closed with dash in the inventory" 64 $?
assert_contains "audit 6d: marker names the denied dash" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "usr/bin/dash"

finish
