#!/bin/sh
# stub-generate.sh — INITRAMFS_CMD stub for unit tests / CI (no dracut available).
# Usage (as wired by lib/initramfs.sh): stub-generate.sh <out> <kver>
# Writes deterministic per-kver content so the ukify PCR 11 prediction is stable.
set -eu
[ $# -eq 2 ] || { echo "usage: stub-generate.sh <out> <kver>" >&2; exit 2; }
printf 'alpine-fde stub initramfs for kernel %s\n' "$2" >"$1"
