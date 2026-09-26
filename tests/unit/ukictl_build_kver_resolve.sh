#!/usr/bin/env bash
# tests/unit/ukictl_build_kver_resolve.sh — real-server blocker #11: the
# no-kver-argument fallback of `ukictl build`. The install plan's guest record
# used to call `ukictl build` with NO kver, so the build fell back to
# `uname -r` — the LIVE ISO's kernel — while the TARGET's installed linux-lts
# is a different version (/lib/modules/<live-kver> does not exist in the
# target). Contract for the NO-ARG invocation:
#   1. exactly ONE directory under <root>/lib/modules  -> use it (the
#      in-chroot invocation sanity case)
#   2. `uname -r` — ONLY when its module dir actually exists in the target
#      (back-compat for a booted target)
#   3. otherwise fail closed (64) LISTING the available /lib/modules dirs +
#      ADR-8 marker + the initramfs builder never invoked
# An EXPLICIT kver argument always wins unchanged. (The install record itself
# now derives the target kver in-guest and passes it — pinned in
# tests/unit/install_chroot_plan.sh.)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# file-existence assert (unit/lib.sh has no helper; do NOT mix in
# tests/lib/assert.sh — two `finish` implementations collide)
assert_file_exists() { # <desc> <path>
    test -e "$2"
    assert_rc "$1" 0 $?
}

KEYDIR="$REPO/fixtures/keys"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# controllable `uname -r` (the live-ISO kernel the old fallback relied on)
UNAMEBIN="$TMP/bin"
mkdir -p "$UNAMEBIN"
cat >"$UNAMEBIN/uname" <<EOF
#!/bin/sh
[ "\$1" = "-r" ] && { printf '%s\n' "\$UNAME_KVER"; exit 0; }
exec /bin/uname "\$@"
EOF
chmod +x "$UNAMEBIN/uname"

fixture_root() { # NAME — root+ESP with every build input EXCEPT the kernel
    ROOT="$TMP/$1-root"
    ESP="$TMP/$1-esp"
    rm -f "$CALLS" # per-leg initramfs call counter
    mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
    cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
    cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
    printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
        >"$ROOT/etc/crypttab"
}

build() { # args... -> ukictl build (no-arg legs pass NO kver)
    _bk_root=$1
    _bk_esp=$2
    shift 2
    ALPINE_FDE_BIN_TEST=1 \
        ALPINE_FDE_ROOT="$_bk_root" \
        ALPINE_FDE_ESP="$_bk_esp" \
        ALPINE_FDE_KEYDIR="$KEYDIR" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REC {out} {kver}" \
        RETENTION=2 \
        PATH="$UNAMEBIN:$PATH" \
        "$REPO/bin/alpine-fde" ukictl build "$@"
}

# recording INITRAMFS_CMD stub (call counter for the fail-closed pin)
CALLS="$TMP/initramfs.calls"
REC="$TMP/record-initramfs.sh"
cat >"$REC" <<EOF
#!/bin/sh
set -eu
[ \$# -eq 2 ] || exit 2
printf '%s\n' "\$2" >>'$CALLS'
printf 'stub initramfs for %s\n' "\$2" >"\$1"
EOF
chmod +x "$REC"

initramfs_calls() { # count INITRAMFS_CMD invocations so far
    [ -f "$CALLS" ] && wc -l <"$CALLS" | tr -d '[:space:]' || printf '0'
}

# =============================================================================
# leg 1 (headline): NO kver arg + exactly ONE /lib/modules dir -> use it
# =============================================================================
fixture_root single
mkdir -p "$ROOT/lib/modules/6.18.35-0-lts"
printf 'modules-payload' >"$ROOT/lib/modules/6.18.35-0-lts/modules.order"
printf 'flavor-image-payload' >"$ROOT/boot/vmlinuz-lts" # flavor fallback (9b)
export UNAME_KVER=6.6.0-0-live # the LIVE ISO kernel — NOT installed in the target
export UNAME_KVER=6.6.0-0-live; out=$(build "$ROOT" "$ESP" 2>&1)
assert_rc "kver 1: no-arg + single module tree -> build succeeds" 0 $?
assert_file_exists "kver 1: UKI built for the TARGET's installed kernel" \
    "$ESP/EFI/Linux/alpine-fde-6.18.35-0-lts.efi"
assert_eq "kver 1: initramfs builder invoked once" "1" "$(initramfs_calls "$ROOT")"

# =============================================================================
# leg 2: NO kver arg + multiple dirs + uname -r NOT among them -> fail closed
# =============================================================================
fixture_root multi
mkdir -p "$ROOT/lib/modules/6.18.35-0-lts" "$ROOT/lib/modules/6.12.8-1-amd64"
export UNAME_KVER=6.6.0-0-live; out=$(build "$ROOT" "$ESP" 2>&1)
rc=$?
assert_rc "kver 2: ambiguous module trees + missing uname kver -> fail closed (64)" 64 "$rc"
assert_contains "kver 2: the error lists the available module dirs" "$out" \
    "6.18.35-0-lts"
assert_contains "kver 2: the error lists BOTH available module dirs" "$out" \
    "6.12.8-1-amd64"
assert_contains "kver 2: the error names the offending live kernel" "$out" \
    "6.6.0-0-live"
assert_file_exists "kver 2: ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_eq "kver 2: initramfs builder never invoked" "0" "$(initramfs_calls "$ROOT")"

# =============================================================================
# leg 3: NO kver arg + uname -r IS an installed module tree -> used (back-compat)
# =============================================================================
fixture_root booted
mkdir -p "$ROOT/lib/modules/6.18.35-0-lts" "$ROOT/lib/modules/6.12.8-1-amd64"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-6.12.8-1-amd64"
export UNAME_KVER=6.12.8-1-amd64; out=$(build "$ROOT" "$ESP" 2>&1)
assert_rc "kver 3: uname -r matching an installed module tree is used (back-compat)" 0 $?
assert_file_exists "kver 3: UKI built for the RUNNING kernel" \
    "$ESP/EFI/Linux/alpine-fde-6.12.8-1-amd64.efi"

# =============================================================================
# leg 4: an EXPLICIT kver argument always wins unchanged
# =============================================================================
fixture_root explicit
mkdir -p "$ROOT/lib/modules/6.18.35-0-lts" "$ROOT/lib/modules/6.12.8-1-amd64"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-6.12.8-1-amd64"
printf 'flavor-image-payload' >"$ROOT/boot/vmlinuz-lts"
export UNAME_KVER=6.12.8-1-amd64; out=$(build "$ROOT" "$ESP" 6.18.35-0-lts 2>&1)
assert_rc "kver 4: explicit kver argument wins over every fallback" 0 $?
assert_file_exists "kver 4: UKI built for the EXPLICIT kver" \
    "$ESP/EFI/Linux/alpine-fde-6.18.35-0-lts.efi"

finish
