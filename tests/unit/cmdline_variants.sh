#!/usr/bin/env bash
# tests/unit/cmdline_variants.sh — the TWO-UKI console-variant cmdline
# composition (lib/cmdline.sh; Samuel, 2026-09-29). ONE composition function
# emits BOTH variants; the console word pair is the only difference:
#   default — console=ttyS0,115200 console=tty0  (tty0 LAST: the virtual
#             console becomes /dev/console for initrd userspace; kernel printk
#             still fans out to the serial UART, and the unseal hook's
#             dual-emission fan-out covers serial explicitly)
#   serial  — console=tty0 console=ttyS0,115200 (serial LAST: /dev/console is
#             the UART — the remote/recovery lane, the -serial UKI)
# Pins: the §8.2 H-G1 pins rd.shell=0 rd.emergency=poweroff present in BOTH
# variants AFTER the console words; rootflags only for btrfs; EXTRA words last;
# the serial derivation flips ONLY the console pair; unknown variants die
# fail-closed (a typo must never build a UKI with the wrong /dev/console).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmdline.sh
source "$REPO/lib/cmdline.sh"

UUID=00000000-0000-0000-0000-000000000000

# --- variant list + console word pairs ------------------------------------------
assert_eq "variants: the canonical list is default then serial" \
    "$(printf 'default\nserial')" "$(cmdline_variants)"
assert_eq "console words: default is ttyS0 first, tty0 LAST" \
    "console=ttyS0,115200 console=tty0" "$(cmdline_console_words default)"
assert_eq "console words: serial is tty0 first, ttyS0 LAST" \
    "console=tty0 console=ttyS0,115200" "$(cmdline_console_words serial)"

# --- composition: btrfs + ext4, both variants -------------------------------------
assert_eq "compose: default/btrfs — rootflags, tty0 last, pins after the consoles" \
    "root=UUID=$UUID rootflags=subvol=@ ro console=ttyS0,115200 console=tty0 rd.shell=0 rd.emergency=poweroff" \
    "$(cmdline_compose default "$UUID" 1)"
assert_eq "compose: serial/btrfs — ttyS0 last, SAME pins" \
    "root=UUID=$UUID rootflags=subvol=@ ro console=tty0 console=ttyS0,115200 rd.shell=0 rd.emergency=poweroff" \
    "$(cmdline_compose serial "$UUID" 1)"
assert_eq "compose: default/ext4 — no rootflags" \
    "root=UUID=$UUID ro console=ttyS0,115200 console=tty0 rd.shell=0 rd.emergency=poweroff" \
    "$(cmdline_compose default "$UUID" 0)"
assert_eq "compose: serial/ext4 — no rootflags" \
    "root=UUID=$UUID ro console=tty0 console=ttyS0,115200 rd.shell=0 rd.emergency=poweroff" \
    "$(cmdline_compose serial "$UUID" 0)"

# --- the two variants differ ONLY in the console word order ------------------------
DEF=$(cmdline_compose default "$UUID" 1)
SER=$(cmdline_compose serial "$UUID" 1)
assert_eq "pair: the non-console content is byte-identical" \
    "$(printf '%s' "$DEF" | sed 's/console=[^ ]* //g')" \
    "$(printf '%s' "$SER" | sed 's/console=[^ ]* //g')"

# --- EXTRA words append AFTER the pins in BOTH variants ----------------------------
assert_eq "extra: appends after the pins (default)" \
    "root=UUID=$UUID rootflags=subvol=@ ro console=ttyS0,115200 console=tty0 rd.shell=0 rd.emergency=poweroff quiet" \
    "$(cmdline_compose default "$UUID" 1 quiet)"
assert_eq "extra: appends after the pins (serial)" \
    "root=UUID=$UUID ro console=tty0 console=ttyS0,115200 rd.shell=0 rd.emergency=poweroff intel_iommu=on" \
    "$(cmdline_compose serial "$UUID" 0 intel_iommu=on)"

# --- serial derivation flips ONLY the console pair ---------------------------------
assert_eq "serial_of: the composed default line flips to the serial variant" "$SER" \
    "$(cmdline_serial_of "$DEF")"
assert_eq "serial_of: the serial line round-trips unchanged" "$SER" \
    "$(cmdline_serial_of "$SER")"
assert_eq "serial_of: a console-less line passes through unchanged" \
    "root=UUID=$UUID ro rd.shell=0 rd.emergency=poweroff" \
    "$(cmdline_serial_of "root=UUID=$UUID ro rd.shell=0 rd.emergency=poweroff")"

# --- file derivation seam -----------------------------------------------------------
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
printf '%s\n' "$DEF" >"$T/cmdline.txt"
cmdline_serial_file "$T/cmdline.txt" "$T/cmdline-serial.txt"
assert_rc "serial_file: rc 0" 0 $?
assert_eq "serial_file: the derived file is the serial variant" "$SER" "$(cat "$T/cmdline-serial.txt")"
out=$(cmdline_serial_file "$T/missing.txt" "$T/out.txt" 2>&1)
assert_rc "serial_file: a missing default fails (rc 1, nothing written)" 1 $?
assert_eq "serial_file: no output written on failure" "0" "$([ -e "$T/out.txt" ] && echo 1 || echo 0)"

# --- unknown variants die fail-closed -----------------------------------------------
out=$(cmdline_console_words typoo 2>&1)
RC=$?
assert_rc "unknown variant: die fail-closed 64" 64 "$RC"
assert_contains "unknown variant: the die names the variant" "$out" "typoo"

finish
