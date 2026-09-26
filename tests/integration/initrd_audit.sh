#!/usr/bin/env bash
# tests/integration/initrd_audit.sh — G-C11 (§8.2/§12/I6, orchestrator resolution R9):
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

. "$REPO/lib/common.sh"
. "$REPO/lib/initramfs.sh"

# deterministic topology: absent conf ⇒ btrfs default (per-call conf legs
# below override this for ROOT_FS=ext4 / BCACHE=1)
export ALPINE_FDE_CONF="$TMP/conf-default-absent"

FAKE="$REPO/fixtures/initramfs/cpio-lister-fake.sh"
IMG="$TMP/whatever.img"
AUDIT_CONF='' # optional per-call ALPINE_FDE_CONF override (topology legs)
AUDIT_ROOT='' # optional blocker #12 kernel-reality context (target root)
AUDIT_KVER='' # optional blocker #12 kernel-reality context (kver)

# run_audit <inventory-file | V:variant> — drive the audit in THIS shell with
# literal var-prefix assignments (they export to the lister child). rc lands
# in $RUN_AUDIT_RC, the failure reason in $_initrd_audit_reason. When
# AUDIT_ROOT + AUDIT_KVER are set (blocker #12 kernel-reality legs) they are
# passed as the audit's target-root/kver arguments.
RUN_AUDIT_RC=0
run_audit() {
    _initrd_audit_reason=''
    local spec=$1
    if [ -n "$AUDIT_ROOT" ] && [ -n "$AUDIT_KVER" ]; then
        if [ "${spec#V:}" != "$spec" ]; then
            ALPINE_FDE_CONF="$AUDIT_CONF" INITRD_LISTER_CMD="$FAKE" \
                LISTER_FAKE_VARIANT="${spec#V:}" initrd_audit "$IMG" "$AUDIT_KVER" "$AUDIT_ROOT" 2>/dev/null
        else
            ALPINE_FDE_CONF="$AUDIT_CONF" INITRD_LISTER_CMD="$FAKE" \
                LISTER_FAKE_INV="$spec" initrd_audit "$IMG" "$AUDIT_KVER" "$AUDIT_ROOT" 2>/dev/null
        fi
        RUN_AUDIT_RC=$?
        return 0
    fi
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
assert_rc "audit 1d: tpm_tis.ko missing while tpm_crb.ko is packed -> still covered (blocker #12: core + ONE interface)" 0 "$RUN_AUDIT_RC"
grep -v 'kernel/drivers/char/tpm/tpm_tis\.ko$' "$inv" | grep -v 'kernel/drivers/char/tpm/tpm_crb\.ko$' >"$TMP/inv-m4b.txt"
run_audit "$TMP/inv-m4b.txt"
assert_rc "audit 1d: NO interface driver (tis AND crb gone) fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1d: reason names the interface requirement" "$_initrd_audit_reason" "tpm"
grep -v 'kernel/drivers/char/tpm/tpm\.ko$' "$inv" >"$TMP/inv-m4c.txt"
run_audit "$TMP/inv-m4c.txt"
assert_rc "audit 1d: missing tpm.ko CORE fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 1d: reason names the tpm core" "$_initrd_audit_reason" "tpm.ko"

grep -v '60-tpm\.rules$' "$inv" >"$TMP/inv-m5.txt"
run_audit "$TMP/inv-m5.txt"
assert_rc "audit 1e: missing TPM udev rule is a loud WARN, not a failure (devtmpfs creates tpmrm0 in-kernel; boot-lane finding #11)" \
    0 "$RUN_AUDIT_RC"

grep -v 'btrfs\.ko$' "$inv" >"$TMP/inv-m6.txt"
run_audit "$TMP/inv-m6.txt"
assert_rc "audit 1f: missing btrfs.ko fails the audit (default topology)" 1 "$RUN_AUDIT_RC"

assert_contains "audit 1f: reason names btrfs.ko" "$_initrd_audit_reason" "btrfs.ko"

# --- boot-lane finding #10 (s23 attempt 10, run ...-1790429268): Alpine 6.18
# kernels ship COMPRESSED modules (tpm.ko.gz, tpm_tis.ko.gz, tpm_crb.ko.gz,
# btrfs.ko.gz) and mkinitfs packs them verbatim — the audit's anchored
# basename match must accept the compression suffix or every real install
# fails the initrd audit ("required unlock artifact(s) missing: tpm.ko
# tpm_tis.ko tpm_crb.ko btrfs.ko") despite a correct initramfs.
invz="$TMP/inv-compressed.txt"
sed -e 's/tpm\.ko$/tpm.ko.gz/' -e 's/tpm_tis\.ko$/tpm_tis.ko.gz/' \
    -e 's/tpm_crb\.ko$/tpm_crb.ko.gz/' -e 's/btrfs\.ko$/btrfs.ko.gz/' "$inv" >"$invz"
run_audit "$invz"
assert_rc "audit 1g: compressed modules (.ko.gz) satisfy the module requirements" 0 "$RUN_AUDIT_RC"


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

# REAL-SERVER BLOCKER #14: apk is EXEMPT from the package-tool deny —
# mkinitfs's own `base` feature ships /sbin/apk + the etc/apk skeleton by
# design (stock Alpine modloop/rebase flow); the deny keeps the Debian-side
# families (apt/dpkg).
run_audit <(cat "$inv"; printf '%s\n' usr/sbin/apk etc/apk etc/apk/keys)
assert_rc "audit 2d: stock mkinitfs apk payload PASSES the audit (blocker #14 exemption)" 0 "$RUN_AUDIT_RC"

run_audit <(cat "$inv"; printf '%s\n' usr/bin/apt-get)
assert_rc "audit 2d-2: apt present fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2d-2: reason names the denied package tool" "$_initrd_audit_reason" "usr/bin/apt-get"

run_audit <(cat "$inv"; printf '%s\n' usr/bin/dpkg)
assert_rc "audit 2d-3: dpkg present fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 2d-3: reason names the denied package tool" "$_initrd_audit_reason" "usr/bin/dpkg"

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
# (blocker #14: the deny uses dpkg/apt — apk is mkinitfs-stock and exempt)
ESP_BEFORE=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
rm -f "$ROOT/etc/alpine-fde/build-failed"
build deny-dpkg
assert_rc "audit 6c: full build fails closed (64) with dpkg in the inventory" 64 $?
assert_contains "audit 6c: marker names the denied package tool" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "usr/bin/dpkg"
assert_eq "audit 6c: ESP untouched by the denied-inventory build" \
    "$ESP_BEFORE" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"

# =============================================================================
# 7. KERNEL-REALITY verdicts (real-server blocker #12): the live 6.18.53-0-lts
#    run failed "required unlock artifact(s) missing: tpm.ko tpm_tis.ko
#    tpm_crb.ko btrfs.ko bcache.ko 69-bcache.rules" even though mkinitfs ran —
#    the audit judged kernel modules by EXACT bare .ko inventory names, blind
#    to (i) modules the kernel BUILT IN (no .ko file ships anywhere —
#    modules.builtin is the ground truth) and (ii) compression suffixes
#    (.ko.gz/.xz/.zst). New contract, when the caller passes the target root
#    + kver: a kernel module is SATISFIED when it is (a) in the initrd
#    inventory (compression-suffix tolerant), or (b) declared built-in in the
#    target's modules.builtin. A miss carries a VERDICT:
#    missing-from-initrd (in the target tree but not packed — mkinitfs
#    request bug) vs missing-from-target-tree (the kernel does not ship it).
# =============================================================================
KTGT="$TMP/target"
mkdir -p "$KTGT/lib/modules/6.18.53-0-lts/kernel/drivers/char/tpm" \
    "$KTGT/lib/modules/6.18.53-0-lts/kernel/fs/btrfs" \
    "$KTGT/lib/modules/6.18.53-0-lts/kernel/drivers/md/bcache"
# the kernel BUILT tpm.ko and tpm_crb.ko in — no .ko file exists anywhere
printf '%s\n' \
    'kernel/drivers/char/tpm/tpm.ko' \
    'kernel/drivers/char/tpm/tpm_crb.ko' \
    >"$KTGT/lib/modules/6.18.53-0-lts/modules.builtin"
# tpm_tis shipped COMPRESSED; btrfs/bcache shipped plain
printf 'gz' >"$KTGT/lib/modules/6.18.53-0-lts/kernel/drivers/char/tpm/tpm_tis.ko.gz"
printf 'ko' >"$KTGT/lib/modules/6.18.53-0-lts/kernel/fs/btrfs/btrfs.ko"

# 7a: everything satisfied — compressed-in-initrd + built-in — PASSES
# (base = the full compliant section-1 inventory; the three tpm .ko files are
# REMOVED because the kernel built them in; tpm_tis ships packed as .ko.gz)
inv7="$TMP/inv-kr-ok.txt"
{
    grep -v 'kernel/drivers/char/tpm/tpm\.ko$' "$inv" |
        grep -v 'kernel/drivers/char/tpm/tpm_tis\.ko$' |
        grep -v 'kernel/drivers/char/tpm/tpm_crb\.ko$'
    printf '%s\n' \
        'kernel/drivers/char/tpm/tpm_tis.ko.gz' \
        'kernel/drivers/md/bcache/bcache.ko' \
        'usr/lib/udev/rules.d/69-bcache.rules'
} >"$inv7"
AUDIT_CONF=$TMP/conf-bcache AUDIT_ROOT=$KTGT AUDIT_KVER=6.18.53-0-lts
printf 'ROOT_FS=btrfs\nBCACHE=1\nTOPOLOGY=bcache-multi\n' >"$AUDIT_CONF"
run_audit "$inv7"
assert_rc "audit 7a: built-in + compressed-suffix modules satisfy the audit" 0 "$RUN_AUDIT_RC"
AUDIT_ROOT='' AUDIT_KVER=''

# 7b: btrfs.ko in the TARGET TREE but not packed -> missing-from-initrd verdict
grep -v 'kernel/fs/btrfs/btrfs\.ko$' "$inv7" >"$TMP/inv-kr-7b.txt"
AUDIT_CONF=$TMP/conf-bcache AUDIT_ROOT=$KTGT AUDIT_KVER=6.18.53-0-lts
run_audit "$TMP/inv-kr-7b.txt"
assert_rc "audit 7b: btrfs.ko absent from the initrd fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 7b: verdict = missing-from-initrd (in the tree, not packed)" \
    "$_initrd_audit_reason" "btrfs.ko=missing-from-initrd"
AUDIT_ROOT='' AUDIT_KVER=''

# 7c: bcache.ko in NEITHER initrd nor target tree -> missing-from-target-tree
grep -v 'kernel/drivers/md/bcache/bcache\.ko$' "$inv7" >"$TMP/inv-kr-7c.txt"
rm -rf "$KTGT/lib/modules/6.18.53-0-lts/kernel/drivers/md"
AUDIT_CONF=$TMP/conf-bcache AUDIT_ROOT=$KTGT AUDIT_KVER=6.18.53-0-lts
run_audit "$TMP/inv-kr-7c.txt"
assert_rc "audit 7c: bcache.ko absent everywhere fails the audit" 1 "$RUN_AUDIT_RC"
assert_contains "audit 7c: verdict = missing-from-target-tree" \
    "$_initrd_audit_reason" "bcache.ko=missing-from-target-tree"
# 69-bcache.rules is a REAL FILE — never satisfied by kernel reality
assert_contains "audit 7c: the bcache udev rule is still required as a file" \
    "$_initrd_audit_reason" "required unlock artifact(s) missing:"
AUDIT_ROOT='' AUDIT_KVER=''

# 7d: compressed packed modules satisfy the audit even WITHOUT kernel context
inv7d="$TMP/inv-kr-7d.txt"
sed 's/\.ko$/.ko.gz/' "$inv" >"$inv7d"
AUDIT_CONF='' AUDIT_ROOT='' AUDIT_KVER=''
run_audit "$inv7d"
assert_rc "audit 7d: compression-suffix-tolerant match works without kernel context" 0 "$RUN_AUDIT_RC"

# 7e: the live-run shape — tpm modules BUILT-IN (nothing tpm-packed) — no
#     longer false-positives when the caller passes the target context
inv7e="$TMP/inv-kr-7e.txt"
{
    grep -v 'kernel/drivers/char/tpm/tpm\.ko$' "$inv" |
        grep -v 'kernel/drivers/char/tpm/tpm_tis\.ko$' |
        grep -v 'kernel/drivers/char/tpm/tpm_crb\.ko$'
    printf '%s\n' \
        'kernel/drivers/md/bcache/bcache.ko' \
        'usr/lib/udev/rules.d/69-bcache.rules'
} >"$inv7e"
AUDIT_CONF=$TMP/conf-bcache AUDIT_ROOT=$KTGT AUDIT_KVER=6.18.53-0-lts
run_audit "$inv7e"
assert_rc "audit 7e: live-run shape (built-in tpm, no tpm .ko files packed) passes" 0 "$RUN_AUDIT_RC"
AUDIT_ROOT='' AUDIT_KVER=''

# 6d: the dracut-era dash allow rule is GONE — dash in the inventory now fails
rm -f "$ROOT/etc/alpine-fde/build-failed"
build deny-shell
assert_rc "audit 6d: full build fails closed with dash in the inventory" 64 $?
assert_contains "audit 6d: marker names the denied dash" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "usr/bin/dash"

finish
