#!/usr/bin/env bash
# tests/unit/build_crypttab_guard.sh — G-U4 (§8.2): verified coupling guard.
# systemd-cryptsetup adds tpm2-tss to the initrd only when /etc/crypttab carries
# a tpm2-device= option AT BUILD TIME; omitting it silently disables all TPM
# unlock. `ukictl build` therefore refuses (rc 64 + ADR-8 marker) before the
# initramfs builder ever runs, unless root's crypttab line carries tpm2-device=.
# The INITRAMFS_CMD stub records invocations: on a guard failure dracut-equivalent
# must run ZERO times; on success at least once.
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

KVER=6.12.8-1-amd64
ROOT="$TMP/root"
ESP="$TMP/esp"
CALLS="$TMP/initramfs.calls"
mkdir -p "$ROOT/boot" "$ROOT/etc/debian-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/debian-fde/cmdline.txt"
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
    env DEBIAN_FDE_BIN_TEST=1 DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_ESP="$ESP" \
        DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
        INITRAMFS_CMD="$REC {out} {kver}" \
        RETENTION=1 \
        "$REPO/bin/debian-fde" ukictl build "$KVER" >/dev/null 2>&1
}

# --- 1. crypttab missing entirely --------------------------------------------------
rm -f "$ROOT/etc/crypttab" "$CALLS" "$ROOT/etc/debian-fde/build-failed"
build
assert_rc "crypttab 1: missing crypttab fails closed (64)" 64 $?
assert_file_exists "crypttab 1: ADR-8 marker persisted" "$ROOT/etc/debian-fde/build-failed"
assert_contains "crypttab 1: marker names the crypttab guard" \
    "$(cat "$ROOT/etc/debian-fde/build-failed" 2>/dev/null)" "crypttab guard"
assert_eq "crypttab 1: initramfs builder never invoked" "0" "$(calls)"
assert_eq "crypttab 1: no ESP mutation" "" "$(find "$ESP" -type f -name '*.efi' -print)"

# --- 2. root line WITHOUT tpm2-device= (commented compliant line must not count) ---
printf '%s\n' \
    '# root UUID=11111111-1111-1111-1111-111111111111 none luks,tpm2-device=auto,discard' \
    'root UUID=22222222-2222-2222-2222-222222222222 none luks,discard' \
    >"$ROOT/etc/crypttab"
rm -f "$CALLS" "$ROOT/etc/debian-fde/build-failed"
build
assert_rc "crypttab 2: root line without tpm2-device= fails closed (64)" 64 $?
assert_contains "crypttab 2: marker names the missing tpm2-device option" \
    "$(cat "$ROOT/etc/debian-fde/build-failed" 2>/dev/null)" "tpm2-device"
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
rm -f "$CALLS" "$ROOT/etc/debian-fde/build-failed"
build
assert_rc "crypttab 4: compliant crypttab lets the build succeed" 0 $?
assert_eq "crypttab 4: initramfs builder invoked at least once" "1" "$(calls)"
assert_file_exists "crypttab 4: UKI installed" "$ESP/EFI/Linux/debian-fde-$KVER.efi"
assert_file_absent "crypttab 4: failure marker cleared" "$ROOT/etc/debian-fde/build-failed"

finish
