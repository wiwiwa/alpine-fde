#!/usr/bin/env bash
# tests/unit/initramfs_default_cmd.sh — G-C10 (§8.3/ADR-13): the DEFAULT
# initramfs builder (INITRAMFS_CMD unset) is Alpine-native **mkinitfs**:
#   mkinitfs -c /etc/mkinitfs/mkinitfs.conf -F "<features>" -o <out> <kver>
# with the feature set pinned to: base, cryptsetup, the root-filesystem
# driver (btrfs default / ext4 per the persisted topology, §4.1) and the
# custom `alpine-fde` feature (the Early-Boot Unseal Hook + its binaries,
# hooks/mkinitfs/features.d/alpine-fde.files). Bcache artifacts are NOT
# argv-wired — they ride the static features.d file list (G-C8 item 6).
# The INITRAMFS_CMD override seam (CI determinism, B-G9) still wins when
# set. mkinitfs is a PATH shim that records argv and touches the output
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

# --- mkinitfs PATH shim: record argv (one word per line), create the output ---
SHIM="$TMP/shim"
mkdir -p "$SHIM"
cat >"$SHIM/mkinitfs" <<EOF
#!/bin/sh
# test shim: record argv, touch the -o output file
printf '%s\n' "\$@" >'$TMP/mkinitfs.argv'
prev=
for a in "\$@"; do
    [ "\$prev" = "-o" ] && : >"\$a"
    prev=\$a
done
exit 0
EOF
chmod +x "$SHIM/mkinitfs"

PATH="$SHIM:$PATH"
. "$REPO/lib/common.sh"
. "$REPO/lib/initramfs.sh"
unset INITRAMFS_CMD

# deterministic topology: absent conf ⇒ btrfs default
export DEBIAN_FDE_CONF="$TMP/conf-absent"

initramfs_build "$TMP/initrd.img" "6.6.63-0-lts"
assert_rc "default initramfs_build (INITRAMFS_CMD unset) succeeds via the mkinitfs shim" 0 $?
assert_file_exists "shim produced the initrd output file" "$TMP/initrd.img"

ARGV=$TMP/mkinitfs.argv
assert_file_exists "mkinitfs shim recorded argv" "$ARGV"
ARGS=$(cat "$ARGV")

# --- exact CLI shape (mkinitfs -c <conf> -F <features> -o <out> <kver>) --------
assert_contains "default invocation carries -c (config)" "$ARGS" "-c"
assert_eq "config path pinned to /etc/mkinitfs/mkinitfs.conf" \
    "/etc/mkinitfs/mkinitfs.conf" "$(grep -A1 -x -- '-c' "$ARGV" | tail -n 1)"
assert_contains "default invocation carries -o (output)" "$ARGS" "-o"
assert_eq "output path is the requested file" "$TMP/initrd.img" \
    "$(grep -A1 -x -- '-o' "$ARGV" | tail -n 1)"
assert_contains "kver passed verbatim as the trailing positional" "$ARGS" "6.6.63-0-lts"

# --- pinned feature set ---------------------------------------------------------
FEATURES=$(grep -A1 -x -- '-F' "$ARGV" | tail -n 1)
assert_contains "feature set includes base" "$FEATURES" "base"
assert_contains "feature set includes cryptsetup" "$FEATURES" "cryptsetup"
assert_contains "feature set includes the alpine-fde hook feature" "$FEATURES" "alpine-fde"
assert_contains "default topology: btrfs fs driver feature" "$FEATURES" "btrfs"
assert_eq "no dracut argv leaks into the mkinitfs invocation" "" \
    "$(grep -E '^--(hostonly|force|kver|add)$' "$ARGV" || true)"

# --- G-ST5 topology: ROOT_FS=ext4 flips the fs driver feature --------------------
printf 'ROOT_FS=ext4\n' >"$TMP/conf-ext4"
DEBIAN_FDE_CONF="$TMP/conf-ext4" initramfs_build "$TMP/initrd-ext4.img" "6.6.63-0-lts"
assert_rc "topology ext4 (conf ROOT_FS=ext4): initramfs_build succeeds" 0 $?
FEATURES_EXT4=$(grep -A1 -x -- '-F' "$ARGV" | tail -n 1)
assert_contains "topology ext4: ext4 driver feature present" "$FEATURES_EXT4" "ext4"
assert_not_contains() {
    case $2 in
        *"$3"*) _fail "$1 (haystack must not contain [$3])" ;;
        *) _pass "$1" ;;
    esac
}
assert_not_contains "topology ext4: no btrfs feature" "$FEATURES_EXT4" "btrfs"
assert_contains "topology ext4: cryptsetup still pinned" "$FEATURES_EXT4" "cryptsetup"

# --- BCACHE=1: nothing on the argv (bcache rides features.d/alpine-fde.files) ----
printf 'ROOT_FS=btrfs\nBCACHE=1\n' >"$TMP/conf-bcache"
DEBIAN_FDE_CONF="$TMP/conf-bcache" initramfs_build "$TMP/initrd-bc.img" "6.6.63-0-lts"
assert_rc "topology bcache (conf BCACHE=1): initramfs_build succeeds" 0 $?
FEATURES_BC=$(grep -A1 -x -- '-F' "$ARGV" | tail -n 1)
assert_not_contains "topology bcache: no bcache wiring on the argv (rides alpine-fde.files)" \
    "$FEATURES_BC" "bcache"
assert_contains "topology bcache: btrfs still pinned" "$FEATURES_BC" "btrfs"

# --- INITRAMFS_CMD override seam still wins (CI determinism, B-G9/G-C10) ---------
REC="$TMP/record-initramfs.sh"
CALLS="$TMP/override.calls"
cat >"$REC" <<EOF
#!/bin/sh
set -eu
[ \$# -eq 2 ] || exit 2
printf '%s\n' "\$2" >>'$CALLS'
printf 'stub initramfs for %s\n' "\$2" >"\$1"
EOF
chmod +x "$REC"
INITRAMFS_CMD="$REC {out} {kver}" initramfs_build "$TMP/initrd-ovr.img" "6.6.63-1-lts"
assert_rc "INITRAMFS_CMD override: initramfs_build succeeds via the stub" 0 $?
assert_file_exists "INITRAMFS_CMD override: stub produced the output" "$TMP/initrd-ovr.img"
assert_eq "INITRAMFS_CMD override: kver passed via the {kver} placeholder" \
    "6.6.63-1-lts" "$(cat "$CALLS")"
assert_not_contains "INITRAMFS_CMD override: mkinitfs shim NOT invoked for this kver" \
    "$(cat "$ARGV")" "6.6.63-1-lts"

finish
