#!/usr/bin/env bash
# tests/unit/initramfs_splice_unseal.sh — real-server blocker #23: stock
# mkinitfs 3.14.1 has NO user-hook mechanism, so the §8.2 unseal hook is
# packed (custom_files) but NEVER invoked — boot B mounts the raw encrypted
# container and lands in the recovery shell. The fix is the pinned splice
# (lib/initramfs.sh initramfs_splice_unseal): unpack the cpio, insert the
# unseal invocation after the nlplug-findfs anchor (drivers + /dev up) and
# the state-flip before the switch_root tail, inject /etc/crypttab, repack —
# idempotent via the ALPINE-FDE-SPLICE markers. Pins:
#   (a) the splice lands EXACTLY once (markers), in the right ORDER
#       (nlplug-findfs < unseal < resume_from_disk < root mount < flip <
#       switch_root), with /etc/crypttab injected and the archive valid;
#   (b) idempotent re-run: no double-splice;
#   (c) initrd_audit FAILS the unspliced initrd with the 'PACKED BUT NEVER
#       CALLED' verdict and PASSES the spliced one (full artifact set);
#   (d) the splice block introduces NO interactive shell (s90 idiom, splice
#       level);
#   (e) structural surprises die loud (missing crypttab; unknown image).
# The fixture initramfs-init is the STOCK mkinitfs 3.14.1 file (vendored at
# fixtures/initramfs/initramfs-init) — the splice anchors are pinned against
# the real shipped bytes, not a paraphrase.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/initramfs.sh
source "$REPO/lib/initramfs.sh"

STOCK_INIT=$REPO/fixtures/initramfs/initramfs-init
HOOK=$REPO/hooks/mkinitfs/alpine-fde-unseal.sh
[ -f "$STOCK_INIT" ] || { echo "FAIL: stock initramfs-init fixture missing: $STOCK_INIT" >&2; exit 1; }
[ -f "$HOOK" ] || { echo "FAIL: unseal hook missing: $HOOK" >&2; exit 1; }
command -v cpio >/dev/null 2>&1 || { echo "FAIL: cpio required" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# build_initrd OUT SPLICED_NO — synthetic gzip-cpio initrd with the stock
# init, the hook (custom_files path), and the full audit artifact set
build_initrd() {
    local out=$1
    local w
    w="$TMP/root-$(basename "$out" .img)"
    rm -rf "$w"
    mkdir -p "$w/usr/share/mkinitfs" "$w/usr/share/alpine-fde/mkinitfs" \
        "$w/usr/bin" "$w/usr/lib" "$w/lib/modules" "$w/etc"
    # the REAL archive path: stock mkinitfs installs the init at /init
    # (initfs_base: install -m755 "$init" "$tmpdir/init")
    cp "$STOCK_INIT" "$w/init"
    chmod 755 "$w/init"   # stock mkinitfs installs the init 0755
    cp "$HOOK" "$w/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    : >"$w/usr/bin/cryptsetup"
    : >"$w/usr/bin/openssl"
    local v
    for v in $_INITRD_AUDIT_TPM2_BINS; do : >"$w/usr/bin/$v"; done
    for v in $_INITRD_AUDIT_TSS_LIBS; do : >"$w/usr/lib/$v.so"; done
    : >"$w/lib/modules/tpm.ko"
    : >"$w/lib/modules/tpm_tis.ko"
    : >"$w/lib/modules/btrfs.ko"
    mkdir -p "$w/usr/lib/udev/rules.d"
    cp "$REPO/hooks/udev/60-tpm.rules" "$w/usr/lib/udev/rules.d/60-tpm.rules"
    printf 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard\n' \
        >"$w/etc/crypttab"
    (cd "$w" && find . | sort | cpio --quiet --renumber-inodes -o -H newc | gzip -9) >"$out"
    rm -rf "$w"
}

CTAB="$TMP/crypttab"
printf 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard\n' >"$CTAB"

# --- (a) splice once: markers, order, crypttab, validity --------------------------
IMG=$TMP/initrd-a.img
build_initrd "$IMG"
# RED control: the UNSPLICED image must fail verification with the founding
# verdict of this blocker class
if initramfs_splice_verify "$IMG" 2>/dev/null; then
    _fail "RED control: the UNSPLICED image passed splice verification — the pin is vacuous"
else
    _pass "RED control: unspliced image fails splice verification (packed-but-never-called is detectable)"
fi

initramfs_splice_unseal "$IMG" "$CTAB"
SPLICE_RC=$?
assert_rc "splice rc 0 over the stock initramfs-init" 0 "$SPLICE_RC"

W="$TMP/extract-a"
mkdir -p "$W"
gzip -dc "$IMG" | cpio --quiet -idm -D "$W" 2>/dev/null
INIT=$W/init
[ -f "$INIT" ] || INIT=""
if [ -z "$INIT" ]; then
    _fail "spliced archive does not contain the initramfs /init"
    finish
fi
assert_eq "splice marker appears exactly twice (open+close) after ONE splice" "2" \
    "$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$INIT")"
# boot-lane finding #25 (s23 attempt 24): the spliced init mounts efivarfs
# BEFORE the hook — the hook's SB guard reads the efivars SB state and the
# stock initramfs never mounts it ('secureboot=unreadable').
INIT_MNT_IDX=$(grep -n 'mount -t efivarfs' "$INIT" | head -1 | cut -d: -f1)
INIT_HOOK_IDX=$(grep -n 'alpine-fde-unseal.sh' "$INIT" | head -1 | cut -d: -f1)
assert_eq "splice: the initramfs mounts efivarfs before the unseal hook" "1" \
    "$([ -n "$INIT_MNT_IDX" ] && [ -n "$INIT_HOOK_IDX" ] && [ "$INIT_MNT_IDX" -lt "$INIT_HOOK_IDX" ] && echo 1 || echo 0)"
# boot-lane finding #24 (s23 attempt 27): the splice REWRITES the init via awk
# and must restore the executable bit — boot B died "Failed to execute /init
# (error -13)" (EACCES) when the packed /init lost +x.
assert_eq "spliced /init keeps the EXECUTABLE bit (the kernel execs it)" "1" \
    "$([ -x "$INIT" ] && echo 1 || echo 0)"
assert_eq "flip marker appears exactly twice (open+close)" "2" \
    "$(grep -cF "$INITRAMFS_SPLICE_FLIP_MARKER" "$INIT")"
assert_eq "the unseal hook invocation is present (canonical custom_files path)" "1" \
    "$(grep -cE '^		FDE_NEWROOT=.*alpine-fde-unseal\.sh$' "$INIT")"
assert_eq "the state-flip hook invocation (blocker #23 splice B) is present" "1" \
    "$(grep -cE '^		FDE_STATE_ONLY=1 FDE_NEWROOT=.*alpine-fde-unseal\.sh$' "$INIT")"
assert_eq "/etc/crypttab injected into the archive" "1" "$(grep -c 'luks,tpm2-device' "$W/etc/crypttab")"
NL=$(grep -nF "$(printf '\t\t"$KOPT_root"')" "$INIT" | head -1 | cut -d: -f1)
SA=$(grep -nF "$INITRAMFS_SPLICE_MARKER" "$INIT" | head -1 | cut -d: -f1)
RS=$(grep -nF '	resume_from_disk' "$INIT" | head -1 | cut -d: -f1)
MT=$(grep -nF '"${KOPT_root#ZFS=}"' "$INIT" | awk -F: -v r="$RS" '$1 > r {print $1; exit}')
FL=$(grep -nF "$INITRAMFS_SPLICE_FLIP_MARKER" "$INIT" | head -1 | cut -d: -f1)
SW=$(grep -nF '	exec switch_root' "$INIT" | head -1 | cut -d: -f1)
assert_eq "splice-point ordering: nlplug < unseal < resume < mount < flip < switch_root" "1" \
    "$(( NL < SA && SA < RS && RS < MT && MT < FL && FL < SW ? 1 : 0 ))"
assert_contains "the splice redirects the root mount to the mapped container" \
    "$(cat "$INIT")" "KOPT_root=/dev/mapper/root"
sh -n "$INIT" && _pass "the spliced initramfs-init still parses (sh -n)" ||
    _fail "the spliced initramfs-init no longer parses"

# --- (b) idempotent re-run: no double splice ---------------------------------------
before=$(gzip -dc "$IMG" | cpio --quiet -it 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
marks_before=$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$INIT")
initramfs_splice_unseal "$IMG" "$CTAB"
assert_rc "idempotent re-run rc 0" 0 $?
W2="$TMP/extract-b"
mkdir -p "$W2"
gzip -dc "$IMG" | cpio --quiet -idm -D "$W2" 2>/dev/null
INIT2=$W2/init
assert_eq "idempotent re-run: marker count UNCHANGED (no double splice)" \
    "$marks_before" "$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$INIT2")"
assert_eq "idempotent re-run: the hook invocations still exactly 2 (unseal + state-flip)" "2" \
    "$(grep -cE '^		(FDE_STATE_ONLY=1 )?FDE_NEWROOT=.*alpine-fde-unseal\.sh$' "$INIT2")"
after=$(gzip -dc "$IMG" | cpio --quiet -it 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
assert_eq "idempotent re-run: archive inventory byte-stable" "$before" "$after"

# --- (c) audit integration: unspliced FAILS with the founding verdict; spliced
#     PASSES the splice verdict (full artifact set for the rest of the audit) --
UNSPLICED=$TMP/initrd-unspliced.img
build_initrd "$UNSPLICED"
INI_ROOT_FS=btrfs initrd_audit "$UNSPLICED" >/dev/null 2>&1
AUD_RC=$?
assert_rc "audit FAILS the unspliced initrd (loud verdict)" 1 "$AUD_RC"
_initrd_audit_reason=''
initrd_audit "$UNSPLICED" >/dev/null 2>&1
assert_contains "audit verdict names the PACKED BUT NEVER CALLED class" \
    "$(printf '%s' "$_initrd_audit_reason" | tr '\n' ' ')" "PACKED BUT NEVER CALLED"
INI_ROOT_FS=btrfs initrd_audit "$IMG" >/dev/null 2>&1
assert_rc "audit PASSES the spliced initrd (full artifact set)" 0 $?

# --- (c2) BUSYBOX ROUND-TRIP (real-server blocker #24): the Alpine target
# ships ONLY busybox cpio (mkinitfs depends on busybox; no GNU cpio apk) and
# busybox cpio REJECTS GNU's -D flag ("unrecognized option: D") — the splice
# died on the live run as "cpio extraction failed (gzip)". Pin: run BOTH new
# cpio pipelines (extraction `gzip -dc | cpio -idm`, repack
# `find . | sort | cpio -o -H newc | gzip`) against the GUEST'S OWN busybox
# applets (spool busybox via the spool musl loader, argv-dispatched), then
# byte-compare the round-trip: unpack->repack->unpack must preserve the
# spliced initramfs-init (markers + hook call) and /etc/crypttab. Flag-level
# compatibility beyond these two pipelines is out of scope here; this
# round-trip covers the splice path exactly. The leg runs in a SUBSHELL (the
# applet shims are function-local) and prints one line per check.
SPOOL=${ALPINE_FDE_SPOOL:-/tmp/mirror-work/spool}
BB_APK=$(ls "$SPOOL"/busybox-[0-9]*.apk 2>/dev/null | head -n 1)
MUSL_APK=$(ls "$SPOOL"/musl-[0-9]*.apk 2>/dev/null | head -n 1)
if [ -n "$BB_APK" ] && [ -n "$MUSL_APK" ]; then
    BB_RESULT=$(
        set -e
        mkdir -p "$TMP/bb/bin" "$TMP/bb/lib"
        tar -xzf "$BB_APK" -C "$TMP/bb" bin/busybox 2>/dev/null
        tar -xzf "$MUSL_APK" -C "$TMP/bb" lib/ld-musl-x86_64.so.1 2>/dev/null
        BB="$TMP/bb/bin/busybox"
        LD="$TMP/bb/lib/ld-musl-x86_64.so.1"
        [ -x "$BB" ] || { echo "no busybox"; exit 97; }
        for app in cpio gzip gunzip find sort mkdir; do ln -sf busybox "$TMP/bb/bin/$app"; done
        BBIMG=$TMP/initrd-bb.img
        cp "$IMG" "$BBIMG"
        rm -rf "$TMP/bbw"
        mkdir -p "$TMP/bbw"
        # extraction under the guest applet (busybox cpio -idm; NO -D)
        gzip -dc "$BBIMG" | (cd "$TMP/bbw" && cpio -idm 2>/dev/null)
        [ -f "$TMP/bbw/$INITRAMFS_INIT_PATH" ] || { echo "no-init"; exit 65; }
        [ -f "$TMP/bbw/etc/crypttab" ] || { echo "no-crypttab"; exit 66; }
        echo "extract-markers=$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$TMP/bbw/$INITRAMFS_INIT_PATH")"
        # repack under the guest applets
        (cd "$TMP/bbw" && find . | sort | cpio -o -H newc 2>/dev/null) |
            gzip -9 >"$TMP/bb-roundtrip.img"
        echo "repack-bytes=$(wc -c <"$TMP/bb-roundtrip.img")"
        rm -rf "$TMP/bbx"
        mkdir -p "$TMP/bbx"
        gzip -dc "$TMP/bb-roundtrip.img" | (cd "$TMP/bbx" && cpio -idm 2>/dev/null)
        echo "reinit-lines=$(wc -l <"$TMP/bbx/$INITRAMFS_INIT_PATH")"
        echo "reinit-markers=$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$TMP/bbx/$INITRAMFS_INIT_PATH")"
        echo "crypttab=$(grep -c 'luks,tpm2-device' "$TMP/bbx/etc/crypttab" 2>/dev/null)"
        cmp -s "$INIT2" "$TMP/bbx/$INITRAMFS_INIT_PATH" && echo "init-identical=yes" || echo "init-identical=no"
        echo OK
    ) 2>/dev/null
    BB_RC=$?
    assert_rc "blocker #24: extract+repack pipelines run under the guest's own busybox cpio" 0 "$BB_RC"
    if [ "$BB_RC" -eq 0 ]; then
        assert_contains "busybox extraction: splice markers preserved" "$BB_RESULT" "extract-markers=2"
        assert_contains "round-trip: repacked image carries the spliced init" "$BB_RESULT" \
            "reinit-lines=$(wc -l <"$INIT2")"
        assert_contains "round-trip: splice markers preserved after repack" "$BB_RESULT" "reinit-markers=2"
        assert_contains "round-trip: /etc/crypttab preserved" "$BB_RESULT" "crypttab=1"
        assert_contains "round-trip: busybox-repacked initramfs-init is byte-identical" "$BB_RESULT" "init-identical=yes"
    else
        printf '%s\n' "$BB_RESULT" >&2
        _fail "blocker #24 busybox round-trip failed (rc=$BB_RC): $BB_RESULT"
    fi
else
    _pass "busybox round-trip skipped (no spool)"
fi

# --- (d) no interactive shell in either splice block -------------------------------
if sed -n "/$INITRAMFS_SPLICE_MARKER/,/$INITRAMFS_SPLICE_MARKER/p" "$INIT2" |
    grep -qE '(^|[[:space:]])(sh|recovery_shell)([[:space:]]|$)'; then
    _fail "the splice block introduces an interactive shell (§8.2 contract void)"
else
    _pass "the splice block adds NO interactive shell (s90 idiom, splice level)"
fi

# --- (e) structural surprises die loud ----------------------------------------------
FRESH=$TMP/initrd-fresh.img
build_initrd "$FRESH"
out=$(initramfs_splice_unseal "$FRESH" "$TMP/does-not-exist" 2>&1)
RC=$?
assert_rc "missing crypttab -> loud die" 64 "$RC"
assert_contains "missing-crypttab refusal says the hook cannot resolve the container" \
    "$out" "crypttab not found"
printf 'not-an-initrd' >"$TMP/junk.img"
out=$(initramfs_splice_unseal "$TMP/junk.img" "$CTAB" 2>&1)
RC=$?
assert_rc "unknown image -> loud die" 64 "$RC"
assert_contains "unknown-image refusal names the compression check" "$out" "unknown initrd compression"

finish
