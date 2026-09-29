#!/bin/sh
# cmdline.sh — kernel-cmdline composition for the TWO UKI console variants
# (two-UKI boot design, Samuel 2026-09-29). ONE composition function emits BOTH
# variants; the console word PAIR is the only difference:
#
#   default  console=ttyS0,115200 console=tty0   — tty0 LAST: the virtual
#               console becomes /dev/console for initrd userspace (the unseal
#               hook's prompt renders on the SCREEN); kernel printk still fans
#               out to the serial UART because the EARLIER console=ttyS0 word
#               registers it, and the hook's dual-emission fan-out
#               (hooks/mkinitfs/alpine-fde-unseal.sh) covers serial explicitly.
#   serial   console=tty0 console=ttyS0,115200   — serial LAST: /dev/console is
#               the UART — the remote/recovery lane (the -serial UKI, NVRAM
#               entry "Alpine FDE - <kver> serial (<date>)").
#
# LAST-CONSOLE-WINS decides /dev/console ONLY; every console= device receives
# the kernel messages regardless of order. Both variants carry the SAME
# non-console content (root=, rootflags, the §8.2 H-G1 pins rd.shell=0
# rd.emergency=poweroff, ALPINE_FDE_CMDLINE_EXTRA last) so a variant flip never
# changes what is measured beyond the console words themselves.
#
# Consumers: lib/cmd/install.sh (writes /etc/alpine-fde/cmdline.txt = default
# + /etc/alpine-fde/cmdline-serial.txt = serial at install time) and
# lib/cmd/kernel-build.sh (builds BOTH UKIs; derives the serial file from the
# default via cmdline_serial_of when the target predates cmdline-serial.txt).
#
# Depends on: lib/common.sh (die).

if [ -n "${ALPINE_FDE_CMDLINE_LIB_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_CMDLINE_LIB_LOADED=1

# cmdline_variants — the canonical variant list, one per line, DEFAULT FIRST
# (the order both the ESP/NVRAM boot priority and the build pipeline keep)
cmdline_variants() {
    printf '%s\n' default
    printf '%s\n' serial
}

# cmdline_console_words VARIANT — the dual-console word pair for VARIANT
# (default|serial). Unknown variants die fail-closed: a typo must never
# silently build a UKI with the wrong /dev/console.
cmdline_console_words() {
    case $1 in
        default) printf '%s\n' 'console=ttyS0,115200 console=tty0' ;;
        serial) printf '%s\n' 'console=tty0 console=ttyS0,115200' ;;
        *) die "cmdline: unknown cmdline variant '$1' (expected: default|serial)" ;;
    esac
}

# cmdline_compose VARIANT LUKS-UUID BTRFS(0|1) [EXTRA-WORD...] — print the FULL
# kernel cmdline line for VARIANT. EXTRA words (ALPINE_FDE_CMDLINE_EXTRA, one
# argument per word or a single pre-split argument) append AFTER the pins — a
# user extra containing console= words becomes the LAST console= and thus wins
# /dev/console — acceptable (their explicit choice), NOT a pin violation (the
# §8.2 G-U6 guard checks only the rd.* pins).
cmdline_compose() {
    _cc_variant=$1
    _cc_uuid=$2
    _cc_btrfs=$3
    shift 3
    _cc_extra=''
    for _cc_w in "$@"; do
        _cc_extra="$_cc_extra${_cc_extra:+ }$_cc_w"
    done
    _cc_console=$(cmdline_console_words "$_cc_variant") || return $?
    if [ "$_cc_btrfs" = "1" ]; then
        printf 'root=UUID=%s rootflags=subvol=@ ro %s rd.shell=0 rd.emergency=poweroff%s\n' \
            "$_cc_uuid" "$_cc_console" "${_cc_extra:+ $_cc_extra}"
    else
        printf 'root=UUID=%s ro %s rd.shell=0 rd.emergency=poweroff%s\n' \
            "$_cc_uuid" "$_cc_console" "${_cc_extra:+ $_cc_extra}"
    fi
}

# cmdline_serial_of LINE — derive the SERIAL variant line from a DEFAULT line:
# the console pair is flipped when present (the only legal difference between
# the variants); a line without the default pair (legacy fixtures, a
# console-less cmdline) passes through unchanged.
cmdline_serial_of() {
    case $1 in
        *'console=ttyS0,115200 console=tty0'*)
            printf '%s\n' "$1" | sed 's/console=ttyS0,115200 console=tty0/console=tty0 console=ttyS0,115200/'
            ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# cmdline_serial_file DEFAULT-FILE OUT-FILE — write the serial-variant cmdline
# file derived from an existing default file (the kernel-build seam for targets
# installed before cmdline-serial.txt existed). rc 1 when the default is
# unreadable; never writes OUT on failure.
cmdline_serial_file() {
    [ -f "$1" ] || return 1
    _csf_line=$(cat "$1") || return 1
    cmdline_serial_of "$_csf_line" >"$2"
}

return 0
