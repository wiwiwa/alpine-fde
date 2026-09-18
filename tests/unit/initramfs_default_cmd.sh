#!/usr/bin/env bash
# tests/unit/initramfs_default_cmd.sh — G-U5 (§8.2/ADR-13): the DEFAULT dracut
# invocation (INITRAMFS_CMD unset) pins the mandated module set
#   systemd systemd-cryptsetup tpm2-tss kernel-modules
# and never requests the legacy crypt/90crypt module (competing non-systemd
# prompt path). Dracut is a PATH shim that records argv and touches the output
# file; assertions are over the recorded argv (exact command contract).
# G-ST5: the root-fs topology module is appended via --add (btrfs by default,
# nothing for ROOT_FS=ext4); bcache wiring is NEVER on the argv — it rides the
# installer's /etc/dracut.conf.d/20-bcache.conf conf.d drop.
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

# --- G-ST5: topology modules ride OUTSIDE the pinned -m set (§8.2/§4.1) -----------
# The root filesystem driver is appended via --add (add_dracutmodules): btrfs
# explicitly (the default topology); ext4 needs no add (hostonly collects the
# active rootfs driver). The bcache force_drivers/install_items wiring is NOT
# passed on the argv: it rides the installer's /etc/dracut.conf.d/20-bcache.conf
# drop, which dracut applies on top of this pinned invocation (nothing removed).

# deterministic topology: absent conf ⇒ btrfs default
export DEBIAN_FDE_CONF="$TMP/conf-absent"

initramfs_build "$TMP/initrd-topo-default.img" "6.12.8-1-amd64"
assert_rc "topology btrfs (default): initramfs_build succeeds" 0 $?
ARGS_BTRAF=$(cat "$ARGV")
assert_contains "topology btrfs: module appended via --add (add_dracutmodules)" \
    "$ARGS_BTRAF" "--add"
assert_contains "topology btrfs: the added module is btrfs" "$ARGS_BTRAF" "btrfs"
assert_contains "topology btrfs: pinned -m set unchanged" "$ARGS_BTRAF" \
    "systemd systemd-cryptsetup tpm2-tss kernel-modules"
assert_eq "topology btrfs: legacy crypt module still not requested" "" \
    "$(printf '%s\n' "$ARGS_BTRAF" | grep -Ex 'crypt|90crypt' || true)"

printf 'ROOT_FS=ext4\n' >"$TMP/conf-ext4"
DEBIAN_FDE_CONF="$TMP/conf-ext4" initramfs_build "$TMP/initrd-topo-ext4.img" "6.12.8-1-amd64"
assert_rc "topology ext4 (conf ROOT_FS=ext4): initramfs_build succeeds" 0 $?
ARGS_EXT4=$(cat "$ARGV")
assert_eq "topology ext4: no --add / no btrfs module (hostonly collects the rootfs driver)" "" \
    "$(printf '%s\n' "$ARGS_EXT4" | grep -Ex -- '--add|btrfs' || true)"
assert_contains "topology ext4: pinned -m set unchanged" "$ARGS_EXT4" \
    "systemd systemd-cryptsetup tpm2-tss kernel-modules"

printf 'ROOT_FS=btrfs\nBCACHE=1\n' >"$TMP/conf-bcache"
DEBIAN_FDE_CONF="$TMP/conf-bcache" initramfs_build "$TMP/initrd-topo-bc.img" "6.12.8-1-amd64"
assert_rc "topology bcache (conf BCACHE=1): initramfs_build succeeds" 0 $?
ARGS_BC=$(cat "$ARGV")
assert_eq "topology bcache: NO bcache wiring on the argv (rides 20-bcache.conf conf.d)" "" \
    "$(printf '%s\n' "$ARGS_BC" | grep -i bcache || true)"
assert_contains "topology bcache: btrfs still added" "$ARGS_BC" "btrfs"

finish
