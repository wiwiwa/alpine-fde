#!/bin/sh
# firmware.sh — efivarfs seam: read Secure Boot / SetupMode / PK state from an
# INJECTABLE efivars directory (env DEBIAN_FDE_EFIVARS_DIR, default
# /sys/firmware/efi/efivars). EFI variable files are a 4-byte u32 attributes
# header followed by the payload; payload byte 0 is the SecureBoot/SetupMode value.

if [ -n "${DEBIAN_FDE_FIRMWARE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_FIRMWARE_LOADED=1

# EFI_GLOBAL_VARIABLE — the firmware's own namespace. S-M5: a same-named
# variable in a vendor namespace is creatable by root and must never be
# mistaken for the firmware's SB state (the §8.4 guard trusts it).
FW_GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
# EFI_IMAGE_SECURITY_DATABASE_GUID — second canonical home of db/dbx (KEK has
# no home here; PK/SecureBoot/SetupMode are EFI_GLOBAL_VARIABLE-only).
FW_GUID_IMAGE_SECURITY='d719b2cb-3d3a-4596-a3bc-dad00e67656f'

# fw_efivars_dir — effective efivars directory ($DEBIAN_FDE_EFIVARS_DIR overrides)
fw_efivars_dir() {
    printf '%s\n' "${DEBIAN_FDE_EFIVARS_DIR:-/sys/firmware/efi/efivars}"
}

# fw_find_var DIR NAME — print the efivarfs file for NAME; rc 1 if none exists.
# S-M5: for the guard-integrity primitives (SecureBoot/SetupMode/PK/KEK/db/dbx)
# ONLY canonical namespace files match — a vendor-namespace lookalike is
# treated as absent, never as the firmware's variable. db/dbx are canonical in
# TWO namespaces (EFI_GLOBAL_VARIABLE + EFI_IMAGE_SECURITY_DATABASE): exactly
# one resolves, both at once is AMBIGUOUS and dies fail-closed. For any other
# NAME, more than one namespace match is AMBIGUOUS and dies fail-closed instead
# of silently picking the first (the die fires inside the caller's command
# substitution; every consumer degrades fail-closed on its non-zero rc).
fw_find_var() {
    case $2 in
        SecureBoot | SetupMode | PK | KEK)
            if [ -e "$1/$2-$FW_GUID_GLOBAL" ]; then
                printf '%s\n' "$1/$2-$FW_GUID_GLOBAL"
                return 0
            fi
            return 1
            ;;
        db | dbx)
            _fw_canon=''
            _fw_n=0
            for _fw_g in "$FW_GUID_GLOBAL" "$FW_GUID_IMAGE_SECURITY"; do
                if [ -e "$1/$2-$_fw_g" ]; then
                    _fw_canon="$1/$2-$_fw_g"
                    _fw_n=$((_fw_n + 1))
                fi
            done
            if [ "$_fw_n" -gt 1 ]; then
                die "firmware: ambiguous EFI variable $2 ($_fw_n canonical namespace matches in $1) — refusing to pick one (S-M5)"
            fi
            [ -n "$_fw_canon" ] || return 1
            printf '%s\n' "$_fw_canon"
            ;;
        *)
            _fw_hit=''
            _fw_n=0
            for _fw_f in "$1/$2-"*; do
                if [ -e "$_fw_f" ]; then
                    _fw_hit=$_fw_f
                    _fw_n=$((_fw_n + 1))
                fi
            done
            if [ "$_fw_n" -gt 1 ]; then
                die "firmware: ambiguous EFI variable $2 ($_fw_n namespace matches in $1) — refusing to pick one (S-M5)"
            fi
            [ -n "$_fw_hit" ] || return 1
            printf '%s\n' "$_fw_hit"
            ;;
    esac
}

# fw_var_u8 DIR NAME — print payload byte 0 (after the attrs header) as decimal;
# rc 1 if the variable is absent, unreadable, or its payload is empty
fw_var_u8() {
    _fw_file=$(fw_find_var "$1" "$2") || return 1
    _fw_b=$(dd if="$_fw_file" bs=1 skip=4 count=1 2>/dev/null | od -An -tu1 | tr -d '[:space:]')
    if [ -z "$_fw_b" ]; then
        return 1
    fi
    printf '%s\n' "$_fw_b"
}

# fw_var_present DIR NAME — rc 0 iff the variable exists with a non-empty payload
# (an attrs-only file counts as not set)
fw_var_present() {
    _fw_file=$(fw_find_var "$1" "$2") || return 1
    _fw_sz=$(wc -c <"$_fw_file" 2>/dev/null | tr -d '[:space:]') || return 1
    [ "$_fw_sz" -gt 4 ]
}

# fw_sb_state — print "secureboot=N setup_mode=N pk=N".
# rc 0 only when Secure Boot is confirmed enabled (payload byte == 1); rc 1
# otherwise (directory missing, variable missing/unreadable, or SB off) —
# the kv line is always printed. Use in a condition context under strict mode.
fw_sb_state() {
    _fw_dir=$(fw_efivars_dir)
    _fw_sb=0
    _fw_setup=1
    _fw_pk=0
    if [ -d "$_fw_dir" ]; then
        if _fw_v=$(fw_var_u8 "$_fw_dir" SecureBoot); then
            _fw_sb=$_fw_v
        fi
        if _fw_v=$(fw_var_u8 "$_fw_dir" SetupMode); then
            _fw_setup=$_fw_v
        fi
        if fw_var_present "$_fw_dir" PK; then
            _fw_pk=1
        fi
    fi
    printf 'secureboot=%s setup_mode=%s pk=%s\n' "$_fw_sb" "$_fw_setup" "$_fw_pk"
    [ "$_fw_sb" -eq 1 ]
}
