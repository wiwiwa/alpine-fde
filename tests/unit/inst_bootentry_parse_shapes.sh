#!/usr/bin/env bash
# tests/unit/inst_bootentry_parse_shapes.sh — inst_bootentry_parse consumes
# BOTH efibootmgr -v output shapes (the R640 2026-10-06: the Alpine build
# prints the loader path BARE after the HD() device path — no File( wrapper —
# and the File(-only parse emitted an empty loader field, shifting the find's
# fields by one and breaking the boot-entry reuse loop forever, 218a575).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$HERE/../..
# shellcheck source=lib.sh
source "$HERE/lib.sh"

eval "$(sed -n '/^inst_bootentry_parse()/,/^}/p' "$REPO/lib/cmd/install.sh")"
command -v inst_bootentry_parse >/dev/null || { echo "FAIL: the parse not extracted"; exit 1; }

DEBIAN_LINE='Boot0000* Alpine FDE - 6.18.55-0-lts (2026-10-06)	HD(1,GPT,11111111-2222-3333-4444-555555555555,0x800,0x100000)/File(\EFI\Linux\alpine-fde-6.18.55-0-lts.efi)'
ALPINE_LINE='Boot0000* Alpine FDE - 6.18.55-0-lts (2026-10-06)	HD(1,GPT,11111111-2222-3333-4444-555555555555,0x800,0x100000)/\EFI\Linux\alpine-fde-6.18.55-0-lts.efi'
FOREIGN_LINE='Boot0003* AlpineLinux	HD(1,GPT,99999999-8888-7777-6666-555555555555,0x800,0x100000)'

# the Debian shape: the loader inside File(...)
OUT=$(printf '%s\n' "$DEBIAN_LINE" | inst_bootentry_parse)
read -r N G L K V LBL <<<"$OUT"
assert_eq "debian shape: loader" '\efi\linux\alpine-fde-6.18.55-0-lts.efi' "$L"
assert_eq "debian shape: kver" '6.18.55-0-lts' "$K"
assert_eq "debian shape: variant" 'default' "$V"
assert_eq "debian shape: guid" '11111111-2222-3333-4444-555555555555' "$G"
assert_eq "debian shape: label" 'alpine fde - 6.18.55-0-lts (2026-10-06)' "$LBL"

# the Alpine shape: the BARE loader path (no File( wrapper) — the regression
OUT=$(printf '%s\n' "$ALPINE_LINE" | inst_bootentry_parse)
read -r N G L K V LBL <<<"$OUT"
assert_eq "alpine shape: loader (bare path)" '\efi\linux\alpine-fde-6.18.55-0-lts.efi' "$L"
assert_eq "alpine shape: kver" '6.18.55-0-lts' "$K"
assert_eq "alpine shape: variant" 'default' "$V"
assert_eq "alpine shape: guid" '11111111-2222-3333-4444-555555555555' "$G"

# the foreign ISO leftover: KVER/VARIANT '-' (the cleanup sweeps by label)
OUT=$(printf '%s\n' "$FOREIGN_LINE" | inst_bootentry_parse)
read -r N G L K V LBL <<<"$OUT"
assert_eq "foreign shape: kver is '-'" '-' "$K"
# the parse carries the raw label as the variant for non-family entries —
# the family_cleanup's alpinelinux sweep matches on the LABEL field
assert_eq "foreign shape: variant carries the label" 'alpinelinux' "$V"

finish
