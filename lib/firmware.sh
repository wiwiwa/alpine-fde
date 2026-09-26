#!/bin/sh
# firmware.sh — efivarfs seam: read Secure Boot / SetupMode / PK state from an
# INJECTABLE efivars directory (env ALPINE_FDE_EFIVARS_DIR, default
# /sys/firmware/efi/efivars). EFI variable files are a 4-byte u32 attributes
# header followed by the payload; payload byte 0 is the SecureBoot/SetupMode value.

if [ -n "${ALPINE_FDE_FIRMWARE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_FIRMWARE_LOADED=1

# Self-load common.sh (info/die) — the §9.1 step-4 guest one-liner
# `. /opt/alpine-fde/lib/firmware.sh && fw_auth_enroll …` runs in a fresh
# chroot shell where nothing is preloaded. Pattern: lib/install-state.sh.
_is_cmd_dir=${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_is_lib_dir=${_is_cmd_dir%/*}
if [ -z "${ALPINE_FDE_COMMON_LOADED:-}" ] && [ -r "$_is_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from ALPINE_FDE_CMD_DIR / install tree
    . "$_is_lib_dir/common.sh"
fi

# EFI_GLOBAL_VARIABLE — the firmware's own namespace. S-M5: a same-named
# variable in a vendor namespace is creatable by root and must never be
# mistaken for the firmware's SB state (the §8.4 guard trusts it).
FW_GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
# EFI_IMAGE_SECURITY_DATABASE_GUID — second canonical home of db/dbx (KEK has
# no home here; PK/SecureBoot/SetupMode are EFI_GLOBAL_VARIABLE-only).
FW_GUID_IMAGE_SECURITY='d719b2cb-3d3a-4596-a3bc-dad00e67656f'

# fw_efivars_dir — effective efivars directory ($ALPINE_FDE_EFIVARS_DIR overrides)
fw_efivars_dir() {
    printf '%s\n' "${ALPINE_FDE_EFIVARS_DIR:-/sys/firmware/efi/efivars}"
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

# fw_guid_le_hex GUID-STRING — mixed-endian binary byte hex of an EFI GUID
# (first three fields byte-reversed, last two verbatim) as used inside EFI
# data structures; consumed by fw_var_write's packet identity check.
fw_guid_le_hex() {
    _fgl_a=${1%%-*}
    _fgl_rest=${1#*-}
    _fgl_b=${_fgl_rest%%-*}
    _fgl_rest=${_fgl_rest#*-}
    _fgl_c=${_fgl_rest%%-*}
    _fgl_rest=${_fgl_rest#*-}
    _fgl_d=${_fgl_rest%%-*}
    _fgl_e=${_fgl_rest#*-}
    _fgl_out=''
    for _fgl_seg in "$_fgl_a" "$_fgl_b" "$_fgl_c"; do
        # byte-reverse the segment two hex digits at a time (fold+tac are
        # coreutils; the installer host always has them, ADR-15 host tools)
        _fgl_r=$(printf '%s\n' "$_fgl_seg" | fold -w2 | tac | tr -d '\n')
        _fgl_out="$_fgl_out$_fgl_r"
    done
    printf '%s%s%s%s%s\n' "$_fgl_out" "$_fgl_d" "$_fgl_e"
}

# fw_hex_le_dec HEXLE — decode a little-endian hex byte string to decimal
fw_hex_le_dec() {
    printf '%d\n' "0x$(printf '%s\n' "$1" | fold -w2 | tac | tr -d '\n')"
}

# fw_name_utf16_hex NAME — UTF-16LE byte hex of an ASCII variable name
fw_name_utf16_hex() {
    _fnu_out=''
    for _fnu_c in $(printf '%s\n' "$1" | fold -w1); do
        _fnu_out="$_fnu_out$(printf '%02x00' "'$_fnu_c")"
    done
    printf '%s\n' "$_fnu_out"
}

# fw_var_write_try DIR NAME GUID AUTHFILE — the try-form of fw_var_write: rc 0
# on an enrolled variable, rc 1 when the kernel/firmware REFUSED the write
# (no die). Queue 26 ext: real firmware refused the db SetVariable with EINVAL
# even with correct attrs/SetupMode/no pre-existing vars, so the enroll flow
# needs a non-fatal probe. The IDENTITY preflight still dies fail-closed: a
# packet whose embedded GUID/UnicodeName does not name the target variable, a
# truncated packet, a missing packet, or a missing efivars dir is a BUG (or a
# custody error), never a firmware quirk — an .auth packet aimed at another
# variable must never be able to program this one.
fw_var_write_try() {
    _fwv_dir=$1
    _fwv_name=$2
    _fwv_guid=$3
    _fwv_auth=$4
    [ -d "$_fwv_dir" ] ||
        die "firmware: no efivars directory $_fwv_dir — cannot enroll $_fwv_name (UEFI boot required)"
    [ -f "$_fwv_auth" ] ||
        die "firmware: authenticated update packet missing: $_fwv_auth (run the key ceremony first)"
    _fwv_hex=$(od -An -vtx1 "$_fwv_auth" | tr -d ' \n')
    # EFI_VARIABLE_AUTHENTICATION_2: EFI_TIME (16 bytes) then EFI_VARIABLE_DATA:
    # GUID (16 bytes) at offset 16, DataSize u32le at 32, UnicodeName at 36.
    _fwv_got_guid=$(printf '%s\n' "$_fwv_hex" | cut -c33-64)
    [ "$_fwv_got_guid" = "$(fw_guid_le_hex "$_fwv_guid")" ] ||
        die "firmware: $_fwv_auth does not name GUID $_fwv_guid — refusing to program $_fwv_name (packet identity mismatch)"
    _fwv_datasize=$(fw_hex_le_dec "$(printf '%s\n' "$_fwv_hex" | cut -c65-72)")
    _fwv_size=$(wc -c <"$_fwv_auth" | tr -d '[:space:]')
    [ "$_fwv_size" -ge $((_fwv_datasize + 36)) ] ||
        die "firmware: $_fwv_auth truncated (DataSize $_fwv_datasize > packet body) — refusing to program $_fwv_name"
    _fwv_got_name=$(printf '%s\n' "$_fwv_hex" | cut -c73-$((72 + 4 * ${#_fwv_name})))
    [ "$_fwv_got_name" = "$(fw_name_utf16_hex "$_fwv_name")" ] ||
        die "firmware: $_fwv_auth does not name variable $_fwv_name — refusing to program it (packet identity mismatch)"
    # ONE write() of attrs+packet: the kernel's efivarfs performs SetVariable
    # on the first write to the file — writing the 4-byte attrs header and
    # then appending the packet would attempt to create the variable with an
    # EMPTY body and fail with EIO on real firmware (2026-09-20 live metal).
    # Attrs 0x00010007 = NV+BS+RT + TIME_BASED_AUTHENTICATED_WRITE_ACCESS
    # (u32le, bit 16 — UEFI spec; 0x01000000 is ENHANCED_AUTHENTICATED_ACCESS,
    # refused with EINVAL on most firmware): without the auth bit firmware
    # refuses an authenticated update outright; the value must match the attrs
    # signed into the packet descriptor (provision PROV_EFI_ATTRS).
    { printf '\007\000\001\000'; cat "$_fwv_auth"; } >"$_fwv_dir/$_fwv_name-$_fwv_guid" ||
        return 1
    info "firmware: enrolled $_fwv_name ($_fwv_guid) from $_fwv_auth"
    return 0
}

# fw_var_write DIR NAME GUID AUTHFILE — die-on-failure wrapper (compatibility
# for direct callers and the pin in tests/unit/nvram_auth_enroll.sh): the
# refused SetVariable is fatal here, with the full manual-enrollment remedy.
fw_var_write() {
    fw_var_write_try "$@" && return 0
    die "firmware: cannot write $1/$2-$3 (kernel/firmware refused the authenticated SetVariable) — if the variable re-appears or EINVAL persists, complete enrollment manually: copy the .auth files from the key directory to a FAT USB stick and enroll via the firmware setup UI / KeyTool.efi, then re-run install (completed steps skip via crash resume)"
}

# fw_auth_esp_fallback ESP_DIR KEYDIR — the graceful degradation when the
# firmware refuses NVRAM enrollment (blocker #12 declutter): stages ONLY
# db.auth/kek.auth/pk.auth + README.txt (the numbered import steps, printable
# before the reboot) + the empty at-firmware marker !import_all_auth_files
# (sorts first in firmware file browsers; the filename IS the instruction) to
# <ESP_DIR>/alpine-fde-keys — the .esl/.dbx/.cert material stays on the
# target's /etc/alpine-fde/keys for repair use — and prints ONE info line;
# the numbered manual-import instructions are DEFERRED to the very end of the
# install (the plan tail). Historical note: the queue-26-ext directive ("write
# the key material to the EFI partition when the efivars write fails and show
# how to import it") is still satisfied — the staging is unchanged in spirit;
# the numbered instructions moved to the install tail and the staged set is
# decluttered to the three import files.
fw_auth_esp_fallback() {
    _fef_esp=$1
    _fef_keys=$2
    _fef_dst=$_fef_esp/alpine-fde-keys
    mkdir -p "$_fef_dst" ||
        die "firmware: cannot create $_fef_dst to stage the Secure Boot key material (firmware refused NVRAM enrollment AND the ESP fallback is unavailable) — copy the .auth files from $_fef_keys to a FAT USB stick and enroll via the firmware setup UI / KeyTool.efi manually"
    # USER DIRECTIVE (blocker #12 ESP staging declutter): the user-facing
    # import directory stages ONLY the three import files — db.auth, kek.auth,
    # pk.auth — plus a printable README.txt (host-side reference before the
    # reboot) and the EMPTY at-firmware marker !import_all_auth_files (the `!`
    # prefix sorts FIRST in firmware file browsers and the filename IS the
    # instruction; no recognizable key extension, so import pickers that
    # filter by extension won't offer it — it is a reminder, not an
    # importable). The .esl/.dbx/.cert material is NOT staged: it stays on the
    # target's /etc/alpine-fde/keys for repair use. The numbered manual-import
    # instructions are NOT printed here — they are DEFERRED to the very end of
    # the install (the plan tail, immediately before the final
    # confirm/reboot); the fallback stages silently.
    for _fef_f in db.auth kek.auth pk.auth; do
        [ -f "$_fef_keys/$_fef_f" ] ||
            die "firmware: cannot stage $_fef_dst/$_fef_f — the packet is missing from $_fef_keys (§9.1 step 4 platform-key ceremony bug)"
        cp "$_fef_keys/$_fef_f" "$_fef_dst/$_fef_f" ||
            die "firmware: cannot stage $_fef_keys/$_fef_f -> $_fef_dst/$_fef_f (ESP fallback)"
        info "firmware: staged $_fef_f into $_fef_dst (ESP fallback)"
    done
    : >"$_fef_dst/!import_all_auth_files"
    cat >"$_fef_dst/README.txt" <<'EOF'
alpine-fde — Secure Boot key import (the firmware refused NVRAM enrollment)

This directory holds EXACTLY the three files to import, in this order:

  1. db.auth   — Key Database (trusts the alpine-fde signatures)
  2. kek.auth  — Key Exchange Key
  3. pk.auth   — Platform Key — import LAST; it locks the key database

(!import_all_auth_files is only a reminder marker — not importable.)

How: reboot into the firmware setup (BIOS/UEFI). Under Security / Secure
Boot / Key Management (wording varies by vendor) use "enqueue", "import" or
KeyTool.efi "enroll from file" — pick each file above IN THE ORDER above.
Then set an administrator (supervisor) password while still in setup.
Reboot: the first boot unlocks via the sealed TPM token and auto-finalizes
under Secure Boot; it REFUSES to boot until the keys are imported (that is
the design, ADR-20).
EOF
    info "firmware: Secure Boot key material staged to $_fef_dst — NVRAM enrollment was refused by the firmware (staged: db.auth kek.auth pk.auth README.txt !import_all_auth_files — nothing else)"
    info "firmware: the manual-import instructions are DEFERRED to the very end of the install (after every other step, immediately before the final confirm/reboot) — the install continues"
    warn "firmware enrollment incomplete — first boot stays guarded until the keys are imported; the manual-import instructions print at the end of the install"
    return 0
}

# fw_auth_enroll EFIVARS_DIR KEYDIR [ESP_DIR] — the §9.1 Stage-1 step-4
# enrollment: authenticated updates into NVRAM in strict order db → KEK → PK
# (last) from KEYDIR's .auth packets (db in the image-security database
# namespace, KEK/PK in EFI_GLOBAL_VARIABLE). Gated: requires SetupMode==1
# (fail-closed 64 — authenticated writes outside setup mode fail or, worse,
# brick the boot entry). A REFUSED write (firmware EINVAL even with correct
# attrs, queue 26 ext) is no longer fatal: every remaining variable is still
# attempted (same firmware refuses them identically — harmless and
# diagnostic), then the key material is staged to ESP_DIR (default /efi, the
# in-chroot ESP mount) via fw_auth_esp_fallback (silently — the manual-import
# instructions are DEFERRED to the very end of the install, the plan tail);
# the install continues. A missing/mismatched
# PACKET still dies fail-closed (fw_var_write_try preflight): that is a bug,
# not a firmware quirk.
fw_auth_enroll() {
    _fae_dir=$1
    _fae_keys=$2
    _fae_esp=${3:-/efi}
    _fae_setup=$(fw_var_u8 "$_fae_dir" SetupMode) ||
        die "firmware: SetupMode state unknown at $_fae_dir — refusing to enroll (§9.1 preflight: clear the vendor PK in BIOS setup first)"
    [ "$_fae_setup" = "1" ] ||
        die "firmware: not in Setup Mode (setup_mode=$_fae_setup) — refusing to enroll (§9.1: clear the vendor PK in BIOS setup first)"
    _fae_failed=''
    for _fae_v in db KEK PK; do
        _fae_guid=$FW_GUID_GLOBAL
        [ "$_fae_v" = "db" ] && _fae_guid=$FW_GUID_IMAGE_SECURITY
        # Real firmware keeps the vendor db (and KEK/PK) variable after the
        # vendor PK is cleared — Setup Mode does NOT imply empty variables on
        # all firmwares — and efivarfs/firmware refuse a SetVariable that would
        # CHANGE an existing variable's attributes (vendor db = plain
        # NV+BS+RT; ours adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS), dying
        # with EINVAL (2026-09 bcache-multi live server, SetupMode==1 verified
        # by the gate above). CI never hits this: it enrolls via offline
        # virt-fw-vars on a fresh OVMF_VARS, where no variable pre-exists.
        # Remove any pre-existing variable of the same name/GUID before the
        # authenticated write. Safe by construction: SetupMode==1 is a
        # fail-closed gate above, and the db -> KEK -> PK order protects the
        # half-enrolled trust root.
        if [ -e "$_fae_dir/$_fae_v-$_fae_guid" ]; then
            info "firmware: removing pre-existing vendor $_fae_v — Setup Mode permits it"
            rm -f "$_fae_dir/$_fae_v-$_fae_guid" ||
                warn "firmware: could not remove pre-existing vendor $_fae_v — attempting the authenticated write anyway (its failure will report the real error)"
        fi
        # provision stage1 ships the packets as db.auth / kek.auth / pk.auth
        _fae_lc=$(printf '%s' "$_fae_v" | tr '[:upper:]' '[:lower:]')
        # Try-form: a refused SetVariable warns and remembers; it does NOT
        # stop the loop — after a db refusal the KEK/PK attempts fail
        # identically on the same firmware, but attempting them costs nothing
        # and their warns are the diagnostic record of what was tried.
        if ! fw_var_write_try "$_fae_dir" "$_fae_v" "$_fae_guid" "$_fae_keys/$_fae_lc.auth"; then
            warn "firmware: cannot write $_fae_dir/$_fae_v-$_fae_guid (firmware refused the authenticated SetVariable) — staging the key material to the ESP for manual enrollment"
            _fae_failed=1
        fi
    done
    [ -z "$_fae_failed" ] || fw_auth_esp_fallback "$_fae_esp" "$_fae_keys"
    return 0
}

# fw_osindications_set EFIVARS_DIR — set OsIndications bit 0 (EFI_GLOBAL_VARIABLE,
# u64le payload 1, attributes 7): signals the firmware to enter BIOS setup on
# the next boot (§9.1 teardown: the single-reboot ceremony).
fw_osindications_set() {
    _fod_dir=$1
    [ -d "$_fod_dir" ] ||
        die "firmware: no efivars directory $_fod_dir — cannot set OsIndications (UEFI boot required)"
    # Same pre-existing-variable hazard fw_auth_enroll guards (see there): a
    # stale OsIndications from a previous run carries the same attrs (plain 7),
    # so an overwrite is legal — but rm-first is harmless and keeps the write
    # shape uniform across both writers.
    if [ -e "$_fod_dir/OsIndications-$FW_GUID_GLOBAL" ]; then
        info "firmware: removing pre-existing OsIndications — rewriting it fresh"
        rm -f "$_fod_dir/OsIndications-$FW_GUID_GLOBAL" ||
            warn "firmware: could not remove pre-existing OsIndications — attempting the write anyway"
    fi
    printf '\007\000\000\000\001\000\000\000\000\000\000\000' \
        >"$_fod_dir/OsIndications-$FW_GUID_GLOBAL" ||
        die "firmware: cannot write $_fod_dir/OsIndications-$FW_GUID_GLOBAL"
    info "firmware: OsIndications bit 0 set — next boot enters BIOS setup (§9.1)"
    return 0
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
