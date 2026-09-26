#!/usr/bin/env bash
# tests/unit/ukictl_build_kernel_resolve.sh — real-server blocker #9b: robust
# kernel-image resolution in `ukictl build`. The verbatim
# `<root>/boot/vmlinuz-<kver>` path only exists in fixture sandboxes; real
# Alpine kernel packages ship the UNVERSIONED FLAVOR image
# (/boot/vmlinuz-lts for linux-lts — the live run died with
# "required build input missing: /boot/vmlinuz-6.18.35-0-lts"). Contract:
#   * priority 1: <root>/boot/vmlinuz-<kver> (previous verbatim path, still
#     first — the e2e fixtures and every existing pin keep working)
#   * priority 2: <root>/boot/vmlinuz-<flavor> — the flavor suffix of the kver
#     (6.18.35-0-lts -> lts), the linux-<flavor> package's canonical image
#   * priority 3: glob <root>/boot/vmlinuz-* excluding the already-probed
#     candidates (last resort)
#   * every candidate must be a regular NON-EMPTY file (a 0-byte image is a
#     broken install, not a resolvable kernel)
#   * total miss -> fail-closed 64 with the CANDIDATES PROBED listed and the
#     remedy (which package / what to ls); ADR-8 marker persisted; ESP untouched
#   * the initramfs is NOT subject to this: the build GENERATES it via the
#     lib/initramfs.sh seam (mkinitfs -o <out> <kver>) — nothing is read from
#     /boot/initramfs-* (report-only note; no pin possible on a non-path)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}

KEYDIR="$REPO/fixtures/keys"
KVER=6.18.35-0-lts # the live-run kernel: linux-lts on real Alpine
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# fixture_root NAME — sandbox root + ESP with every build input EXCEPT the
# kernel image (callers create /boot/vmlinuz-* variants per leg)
fixture_root() {
    ROOT="$TMP/$1-root"
    ESP="$TMP/$1-esp"
    mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
    cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
    cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
    printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
        >"$ROOT/etc/crypttab"
    jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
        '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/alpine-fde/baseline.json"
    . "$REPO/lib/common.sh"
    . "$REPO/lib/manifest.sh"
    . "$REPO/lib/keys.sh"
    manifest_new "6.18.35-0-lts" "fp-old" | manifest_atomic_write "$ROOT/etc/alpine-fde/digests.json"
}

alpine-fde() { # ROOT ESP args...
    _fr_root=$1
    _fr_esp=$2
    shift 2
    ALPINE_FDE_BIN_TEST=1 \
        ALPINE_FDE_ROOT="$_fr_root" \
        ALPINE_FDE_ESP="$_fr_esp" \
        ALPINE_FDE_KEYDIR="$KEYDIR" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        "$REPO/bin/alpine-fde" "$@"
}

# signer argv log (pins WHICH kernel image ukify consumed)
wrap_signers() {
    WRAPBIN="$TMP/wrapbin-$1"
    ARGVLOG="$TMP/signer-argv-$1.log"
    mkdir -p "$WRAPBIN"
    for b in ukify sbsign sbverify; do
        real=$(command -v "$b")
        cat >"$WRAPBIN/$b" <<EOF
#!/bin/sh
printf '%s %s\n' "$b" "\$*" >>'$ARGVLOG'
exec $real "\$@"
EOF
        chmod +x "$WRAPBIN/$b"
    done
    : >"$ARGVLOG"
}

# =============================================================================
# priority 2: ONLY the flavor image present -> the live-run shape MUST build
# =============================================================================
fixture_root flavor
printf 'flavor-image-payload' >"$ROOT/boot/vmlinuz-lts" # real Alpine linux-lts layout
wrap_signers flavor
out=$(PATH="$WRAPBIN:$PATH" alpine-fde "$ROOT" "$ESP" ukictl build "$KVER" 2>&1)
assert_rc "flavor-only root: ukictl build succeeds (blocker 9b headline)" 0 $?
assert_contains "flavor-only: ukify consumed the FLAVOR image (--linux)" "$(cat "$ARGVLOG")" \
    "--linux=$ROOT/boot/vmlinuz-lts"
assert_file_exists "flavor-only: UKI installed for the full kver" "$ESP/EFI/Linux/alpine-fde-$KVER.efi"
assert_eq "flavor-only: manifest entry carries the full kver" "1" \
    "$(jq --arg kver "$KVER" '[.digests[] | select(.kernel_version == $kver)] | length' "$ROOT/etc/alpine-fde/digests.json")"
[ -e "$ROOT/etc/alpine-fde/build-failed" ] && rc_m=1 || rc_m=0
assert_rc "flavor-only: no failure marker after the resolved build" 0 "$rc_m"

# =============================================================================
# priority 1: versioned image still wins when BOTH exist (no behavior change)
# =============================================================================
fixture_root both
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER" # versioned (fixture/e2e shape)
printf 'flavor-image-payload' >"$ROOT/boot/vmlinuz-lts"
wrap_signers both
out=$(PATH="$WRAPBIN:$PATH" alpine-fde "$ROOT" "$ESP" ukictl build "$KVER" 2>&1)
assert_rc "versioned+flavor root: build succeeds" 0 $?
assert_contains "versioned+flavor: the VERSIONED image is consumed (priority 1 unchanged)" \
    "$(cat "$ARGVLOG")" "--linux=$ROOT/boot/vmlinuz-$KVER"
assert_ne "versioned+flavor: the flavor image was NOT consumed" \
    "1" "$(grep -c -- "--linux=$ROOT/boot/vmlinuz-lts" "$ARGVLOG" 2>/dev/null; true)"

# =============================================================================
# priority 3: glob fallback — neither the versioned nor the flavor image, but
# another /boot/vmlinuz-* exists -> resolved as the last resort
# =============================================================================
fixture_root glob
printf 'glob-image-payload' >"$ROOT/boot/vmlinuz-virt"
wrap_signers glob
out=$(PATH="$WRAPBIN:$PATH" alpine-fde "$ROOT" "$ESP" ukictl build "$KVER" 2>&1)
assert_rc "glob-only root: build resolves via the /boot/vmlinuz-* glob" 0 $?
assert_contains "glob-only: ukify consumed the globbed image" "$(cat "$ARGVLOG")" \
    "--linux=$ROOT/boot/vmlinuz-virt"

# =============================================================================
# total miss: NO kernel image anywhere -> fail-closed 64, candidates + remedy
# =============================================================================
fixture_root none
wrap_signers none
ESP_BEFORE=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
out=$(PATH="$WRAPBIN:$PATH" alpine-fde "$ROOT" "$ESP" ukictl build "$KVER" 2>&1)
assert_rc "bare root: no kernel image anywhere -> exit 64" 64 $?
assert_contains "bare root: the failure names the required input" "$out" "required build input missing"
assert_contains "bare root: failure names the kver" "$out" "$KVER"
assert_contains "bare root: failure lists the probed candidate (versioned)" "$out" \
    "$ROOT/boot/vmlinuz-$KVER"
assert_contains "bare root: failure lists the probed candidate (flavor)" "$out" \
    "$ROOT/boot/vmlinuz-lts"
assert_contains "bare root: failure names the remedy package" "$out" "linux-lts"
assert_contains "bare root: failure points at the ls remedy" "$out" "ls $ROOT/boot"
assert_file_exists "bare root: ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "bare root: marker names the missing input" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "$KVER"
assert_eq "bare root: ESP byte-identical (loud refusal before any signer)" "$ESP_BEFORE" \
    "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"
assert_eq "bare root: no signer ever ran" "0" "$(wc -l <"$ARGVLOG")"

# =============================================================================
# non-trivial sanity: a ZERO-BYTE flavor image is NOT a resolvable kernel
# =============================================================================
fixture_root zerobyte
: >"$ROOT/boot/vmlinuz-lts" # exists but empty (broken install)
out=$(alpine-fde "$ROOT" "$ESP" ukictl build "$KVER" 2>&1)
assert_rc "zero-byte flavor image: NOT resolved -> exit 64" 64 $?
assert_contains "zero-byte: failure lists the rejected candidate" "$out" "$ROOT/boot/vmlinuz-lts"
assert_file_exists "zero-byte: ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"

finish
