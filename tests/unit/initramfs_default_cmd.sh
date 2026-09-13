#!/usr/bin/env bash
# tests/unit/initramfs_default_cmd.sh — G-U5 (§8.2/ADR-13): the DEFAULT dracut
# invocation (INITRAMFS_CMD unset) pins the mandated module set
#   systemd systemd-cryptsetup tpm2-tss kernel-modules
# and never requests the legacy crypt/90crypt module (competing non-systemd
# prompt path). Dracut is a PATH shim that records argv and touches the output
# file; assertions are over the recorded argv (exact command contract).
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

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- dracut PATH shim: record argv (one word per line), emit a fake initrd -----
SHIM="$TMP/shim"
mkdir -p "$SHIM"
cat >"$SHIM/dracut" <<EOF
#!/bin/sh
# test shim: record argv, touch the output file (last positional arg)
printf '%s\n' "\$@" >'$TMP/dracut.argv'
for _arg in "\$@"; do :; done
: >"\$_arg"
exit 0
EOF
chmod +x "$SHIM/dracut"

PATH="$SHIM:$PATH"
. "$REPO/lib/common.sh"
. "$REPO/lib/initramfs.sh"
unset INITRAMFS_CMD

initramfs_build "$TMP/initrd.img" "6.12.8-1-amd64"
assert_rc "default initramfs_build (INITRAMFS_CMD unset) succeeds via the dracut shim" 0 $?
assert_file_exists "shim produced the initrd output file" "$TMP/initrd.img"

ARGV=$TMP/dracut.argv
assert_file_exists "dracut shim recorded argv" "$ARGV"
ARGS=$(cat "$ARGV")
assert_contains "default dracut invocation keeps --hostonly (ADR-13)" "$ARGS" "--hostonly"
assert_contains "default dracut invocation keeps --force" "$ARGS" "--force"
assert_contains "default dracut invocation keeps --kver" "$ARGS" "--kver"
assert_contains "default dracut invocation targets the requested kernel" "$ARGS" "6.12.8-1-amd64"
assert_contains "default dracut invocation writes the requested output" "$ARGS" "$TMP/initrd.img"

assert_contains "module set pinned to the §8.2 mandated set (-m list)" "$ARGS" \
    "systemd systemd-cryptsetup tpm2-tss kernel-modules"
assert_eq "legacy crypt/90crypt module not requested (§8.2)" "" \
    "$(grep -Ex 'crypt|90crypt' "$ARGV" || true)"

finish
