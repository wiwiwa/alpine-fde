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
    printf '%s%s%s\n' "$_fgl_out" "$_fgl_d" "$_fgl_e"
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
    [ -s "$_fwv_auth" ] ||
        die "firmware: $_fwv_auth is empty — refusing to program $_fwv_name"
    # minimal sanity (blocker #25): the packet MUST start with a plausible
    # EFI_TIME — the year's HIGH byte is 0x07 for the 202x era. The old
    # hand-rolled/hybrid packets started with zeros (or escape text) and are
    # refused here.
    _fwv_year_hi=$(tail -c +2 "$_fwv_auth" | head -c 1 | od -An -v -tx1 | tr -d ' \n')
    [ "$_fwv_year_hi" = "07" ] ||
        die "firmware: $_fwv_auth is not a spec EFI_VARIABLE_AUTHENTICATION_2 packet (EFI_TIME year is not 202x) — refusing to program $_fwv_name"
    # efivarfs marks AUTHENTICATED variables' inodes S_IMMUTABLE at creation —
    # clear the bit best-effort before the write (re-runs against OUR OWN
    # previously enrolled variables die EPERM at open otherwise).
    chattr -i "$_fwv_dir/$_fwv_name-$_fwv_guid" >/dev/null 2>&1 || :
    # REAL-SERVER blocker #26 (final precision fix): the RAW cat-style write
    # (4-byte attrs prefix + packet in one write) is REFUSED by real firmware
    # (Dell: all three authenticated writes) while efi-updatevar -f with the
    # same-class packets is ACCEPTED — libefivar implements the proper
    # efivarfs open/attrs semantics. The write is therefore ALWAYS
    # efi-updatevar's; no native cat fallback.
    command -v efi-updatevar >/dev/null 2>&1 ||
        die "firmware: the authenticated write of $_fwv_name requires efi-updatevar — apk add efitools (the raw efivarfs write is refused by real firmware, blocker #26 final)"
    efi-updatevar -f "$_fwv_auth" "$_fwv_name" >/dev/null 2>&1 || return 1
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

# fw_auth_esp_fallback ESP_DIR KEYDIR [DEFER_NOTE] — the graceful degradation
# when the firmware refuses NVRAM enrollment (blocker #12 declutter): stages
# the three .auth packets (db.auth/kek.auth/pk.auth) + the operator's OWN
# certificates as import-ready db.cer/KEK.cer/PK.cer (REAL-SERVER 2026-09-28,
# Dell PowerEdge R640: the firmware setup UI imports X.509 .cer/.der/.crt
# ONLY — it cannot import .auth packets, so without the certs the operator
# had NO importable files for PK/KEK/db and had to unlock the LUKS target to
# fish release.crt/kek.cert.der/pk.cert.der out of /etc/alpine-fde/keys) +
# the vendor .cer set + README.txt (the operator decision tree, printable
# before the reboot) + the empty at-firmware marker !import_all_auth_files
# (sorts first in firmware file browsers; the filename IS the instruction) to
# <ESP_DIR>/alpine-fde-keys — the .esl/.dbx material stays on the target's
# /etc/alpine-fde/keys for repair use — and prints ONE info line; the
# numbered manual-import instructions are DEFERRED to the very end of the
# install (the plan tail). DEFER_NOTE (optional, the deferred-enrollment mode
# of fw_auth_enroll: a platform PK is already enrolled and NO NVRAM writes
# were attempted) is prepended to README.txt verbatim and swaps the reason in
# the summary info line — the staged FILE SET is byte-identical either way.
# Historical note: the queue-26-ext directive ("write
# the key material to the EFI partition when the efivars write fails and show
# how to import it") is still satisfied — the staging is unchanged in spirit;
# the numbered instructions moved to the install tail and the staged set is
# the import-ready file set (packets + certs).
fw_auth_esp_fallback() {
    _fef_esp=$1
    _fef_keys=$2
    _fef_defer=${3:-}
    _fef_dst=$_fef_esp/alpine-fde-keys
    mkdir -p "$_fef_dst" ||
        die "firmware: cannot create $_fef_dst to stage the Secure Boot key material (firmware refused NVRAM enrollment AND the ESP fallback is unavailable) — copy the .auth files from $_fef_keys to a FAT USB stick and enroll via the firmware setup UI / KeyTool.efi manually"
    # USER DIRECTIVE (blocker #12 ESP staging declutter): the user-facing
    # import directory stages ONLY import-ready material — the three .auth
    # packets (db.auth, kek.auth, pk.auth), the operator's OWN certificates as
    # import-ready db.cer/KEK.cer/PK.cer (REAL-SERVER 2026-09-28, below), the
    # vendor .cer set, plus a printable README.txt (host-side reference before
    # the reboot) and the EMPTY at-firmware marker !import_all_auth_files (the
    # `!` prefix sorts FIRST in firmware file browsers and the filename IS the
    # instruction; no recognizable key extension, so import pickers that
    # filter by extension won't offer it — it is a reminder, not an
    # importable). The .esl/.dbx material is NOT staged: it stays on the
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
    # REAL-SERVER 2026-09-28 (Dell PowerEdge R640): the firmware's setup UI
    # cannot import .auth packets — it imports X.509 certificates (.cer/.der/
    # .crt) only. Stage the operator's OWN certificates alongside the packets,
    # named after the variables the UI manages, so a UI-only repair never
    # needs an extra LUKS unlock to copy the certs out of
    # /etc/alpine-fde/keys. These ARE the inputs the .auth packets were built
    # from (provision stage1: db.esl = release.crt + vendor certs — blocker
    # #25 cert-mixup fix, the db authorizes BOOT-IMAGE signers; kek.esl =
    # kek.cert.der; pk.esl = pk.cert.der), so the keydir must already carry
    # them; a missing cert is a custody bug and dies fail-closed like a
    # missing packet. Formats as stored: release.crt is PEM, kek/pk
    # .cert.der are DER — firmware UIs accept both.
    for _fef_pair in 'db.cer release.crt' 'KEK.cer kek.cert.der' 'PK.cer pk.cert.der'; do
        _fef_cer=${_fef_pair%% *}
        _fef_src=${_fef_pair#* }
        [ -f "$_fef_keys/$_fef_src" ] ||
            die "firmware: cannot stage $_fef_dst/$_fef_cer — $_fef_src is missing from $_fef_keys (the .auth packets are built from these certs; provision stage1 custody bug)"
        cp "$_fef_keys/$_fef_src" "$_fef_dst/$_fef_cer" ||
            die "firmware: cannot stage $_fef_keys/$_fef_src -> $_fef_dst/$_fef_cer (ESP fallback, operator cert)"
        info "firmware: staged $_fef_cer (from $_fef_src) into $_fef_dst (ESP fallback)"
    done
    # DECIDED 2026-09-27 (db reset + release+vendor rebuild, UEFI0072): stage
    # every vendor .cer under its basename alongside the import files — on
    # boards where our NVRAM writes cannot run, the db.auth alone carries the
    # combined db, but an operator repairing via the firmware UI may need to
    # append the vendor anchors (e.g. Microsoft Option ROM UEFI CA 2023 for
    # NIC PXE / PERC option ROMs) individually. The .esl/.dbx material is
    # still NOT staged (the declutter directive stands for repair lists).
    _fef_vcerts=''
    if [ "${ALPINE_FDE_DB_VENDOR:-all}" != "none" ]; then
        _fef_vdir=$(db_vendor_dir)
        if [ -d "$_fef_vdir" ]; then
            while IFS= read -r _fef_c; do
                [ -n "$_fef_c" ] || continue
                cp "$_fef_c" "$_fef_dst/$(basename "$_fef_c")" ||
                    die "firmware: cannot stage $_fef_c -> $_fef_dst (ESP fallback, vendor cert)"
                info "firmware: staged vendor cert $(basename "$_fef_c") into $_fef_dst (ESP fallback)"
                _fef_vcerts="$_fef_vcerts $(basename "$_fef_c")"
            done <<EOF
$(find "$_fef_vdir" -maxdepth 1 -type f -name '*.cer' | LC_ALL=C sort)
EOF
        fi
    fi
    : >"$_fef_dst/!import_all_auth_files"
    # DEFER_NOTE (deferred-enrollment mode only): prepended verbatim so the
    # operator reads the platform-PK-present situation BEFORE the generic
    # decision tree below (whose STEP 1 assumes the refused-writes case)
    if [ -n "$_fef_defer" ]; then
        printf '%s\n' "$_fef_defer" >"$_fef_dst/README.txt" ||
            die "firmware: cannot write $_fef_dst/README.txt (ESP fallback)"
    fi
    cat >>"$_fef_dst/README.txt" <<'EOF'
alpine-fde — Secure Boot key import (decision tree)

STEP 1 — did the firmware ACCEPT the installer's NVRAM writes?

  (a) YES (the install reported enrollment complete, or Secure Boot /
      Key Management in firmware setup already shows the alpine-fde
      Platform Key) -> NOTHING to do. This directory is a leftover
      staging copy and may be deleted.

  (b) NO (the install said the firmware REFUSED the writes) -> import
      from THIS directory through the firmware setup UI, as below.

STEP 2 (refused case only) — import order in the firmware UI:

  The firmware setup UI imports X.509 CERTIFICATES (.cer/.der/.crt) — it
  cannot import .auth packets. The import-ready certificates are staged
  here next to the packets:

    1. db.cer  — Key Database (the alpine-fde release certificate;
                 trusts the signed bootloader/kernel)
       microsoft-option-rom-uefi-ca-2023.cer — vendor option-ROM CA,
                 import into db AS WELL (see WHY below)
    2. KEK.cer — Key Exchange Key
    3. PK.cer  — Platform Key — import LAST: enrolling the Platform Key
                 flips the platform to User Mode and locks the key
                 database (after PK, no more key imports are possible
                 until the PK is removed again)

  WHY db needs BOTH certificates: under custom keys the db must carry the
  release certificate PLUS the vendor option-ROM CA (Microsoft Option ROM
  UEFI CA 2023) — without the vendor cert, signed NIC PXE / storage (PERC)
  option ROMs fail the firmware's UEFI0072 Secure Boot policy at POST (seen
  live on Dell PowerEdge: a refused PERC option ROM blocks the RAID
  controller and the disks vanish). The db.auth packet stages both in one
  write; when importing through the UI you import them as the two files
  listed above.

  Formats: db.cer is PEM, KEK.cer / PK.cer are DER — firmware UIs accept
  both. (The vendor .cer basename matches certs/vendor/; it differs when
  ALPINE_FDE_DB_VENDOR_DIR points elsewhere.)

  The .auth packets staged alongside (db.auth kek.auth pk.auth) are for
  KeyTool.efi / efi-updatevar repair only — the firmware setup UI cannot
  import them.

How: reboot into the firmware setup (BIOS/UEFI; Dell PowerEdge: F2 during
POST). Under Security / Secure Boot / Key Management (wording varies by
vendor) use the certificate "enqueue" / "import from file" action — pick
each file above IN THE ORDER above, db (both certificates) -> KEK -> PK
last. Then enable Secure Boot (the platform must show User Mode, Custom
mode). Then set an administrator (supervisor) password while still in
setup. Reboot: the first boot unlocks via the sealed TPM token and
auto-finalizes under Secure Boot; it REFUSES to boot until the keys are
imported (that is the design, ADR-20).

(!import_all_auth_files is only a reminder marker — not importable.)
EOF
    _fef_why="NVRAM enrollment was refused by the firmware"
    [ -n "$_fef_defer" ] &&
        _fef_why="a platform key is already enrolled (factory or custom) — NO NVRAM writes were attempted"
    info "firmware: Secure Boot key material staged to $_fef_dst — $_fef_why (staged: db.auth kek.auth pk.auth db.cer KEK.cer PK.cer README.txt !import_all_auth_files${_fef_vcerts:+; vendor certs:$_fef_vcerts})"
    info "firmware: the manual-import instructions are DEFERRED to the very end of the install (after every other step, immediately before the final confirm/reboot) — the install continues"
    warn "firmware enrollment incomplete — first boot stays guarded until the keys are imported; the manual-import instructions print at the end of the install"
    return 0
}

# fw_auth_enroll EFIVARS_DIR KEYDIR [ESP_DIR] — the §9.1 Stage-1 step-4
# enrollment: db RESET + authenticated updates into NVRAM in strict order
# reset-db → db → KEK → PK (last) from KEYDIR's .auth packets (db in the
# image-security database namespace, KEK/PK in EFI_GLOBAL_VARIABLE).
# DECIDED (Samuel, 2026-09-27, UEFI0072): db is first RESET — the existing db
# content is deleted (authenticated-delete machinery: chattr -i + rm, the
# SIGNED-EMPTY efitools delete as the fallback) while Setup Mode is still
# active — then REBUILT as ONE combined authenticated write from db.auth
# (release cert + vendor certs; stage1 composes the ESL, no APPEND_ATTRIBUTE
# write, so re-installs never accumulate duplicates). dbx is NEVER targeted:
# it is the revocation list and stays exactly as the vendor/operator set it.
# Gated: SetupMode==1 runs the write flow; a platform PK PRESENT with
# SetupMode==0 takes the DEFERRED-ENROLLMENT path (DECIDED Samuel, 2026-09-28,
# real Dell PowerEdge R640): no NVRAM writes at all — the release certificate
# is imported into the EXISTING (factory or custom) key database via the
# firmware setup UI from the staged .cer files (fw_auth_esp_fallback with the
# defer note), and the enroll returns SUCCESS so the install continues. That
# day's proven deployment mode: 'Restore Default Policy Entries' put the
# factory Dell PK/KEK/db/dbx back (the vendor db carries the Microsoft
# option-ROM CAs that keep the PERC/NIC option ROMs booting under Secure
# Boot), then the release db.cer is imported into the factory db through the
# firmware UI — PK present, SetupMode=0, Secure Boot enforced, our release
# cert in db verifies our UKI. The old behavior (die 64 on any SetupMode!=1)
# would have aborted that install. The same day also proved the OS-write path
# is simply unreliable on this board (even in Setup Mode the firmware refuses
# OS-side authenticated NVRAM writes after a UI-side wipe), so the UI import
# from the staged files is the deterministic enrollment path. A
# SetupMode!=1 WITHOUT a platform PK (a state no real firmware reports) stays
# fail-closed 64. A REFUSED write (firmware EINVAL even with correct attrs,
# queue 26
# ext) is no longer fatal: every remaining variable is still attempted (same
# firmware refuses them identically — harmless and diagnostic), then the key
# material is staged to ESP_DIR (default /efi, the in-chroot ESP mount) via
# fw_auth_esp_fallback (silently — the manual-import instructions are
# DEFERRED to the very end of the install, the plan tail); the install
# continues. A missing/mismatched
# PACKET still dies fail-closed (fw_var_write_try preflight): that is a bug,
# not a firmware quirk.
fw_auth_enroll() {
    _fae_dir=$1
    _fae_keys=$2
    _fae_esp=${3:-/efi}
    _fae_setup=$(fw_var_u8 "$_fae_dir" SetupMode) ||
        die "firmware: SetupMode state unknown at $_fae_dir — refusing to enroll (§9.1 preflight: clear the vendor PK in BIOS setup first)"
    # DECIDED 2026-09-27: the db reset + release+vendor rebuild runs ONLY in
    # Setup Mode. SetupMode != 1 without a platform PK (a state no real
    # firmware reports — user mode with no PK) is fail-closed 64.
    if [ "$_fae_setup" != "1" ]; then
        if [ "$_fae_setup" = "0" ] && fw_var_present "$_fae_dir" PK; then
            # DEFERRED-ENROLLMENT path (REAL-SERVER 2026-09-28, Dell PowerEdge
            # R640): the platform trusts its OWN PK (factory or custom); the
            # install's job shrinks to getting OUR release certificate into
            # the existing db — a UI import, not an NVRAM write. Stage the
            # import-ready .cer set (fw_auth_esp_fallback, with the defer
            # note) and return success; the install tail prints the
            # deferred-import instructions and reboots into firmware setup.
            info "firmware: a platform key is enrolled (SetupMode 0 — factory or custom PK) — enrollment DEFERS to the firmware-UI import: NO NVRAM writes are attempted; import the release certificate (db.cer) plus the vendor certificate INTO THE EXISTING key database via the firmware setup UI from the staged files (the platform's PK/KEK stay — do not import PK.cer/KEK.cer)"
            fw_auth_esp_fallback "$_fae_esp" "$_fae_keys" \
                'YOUR SITUATION — DEFERRED ENROLLMENT (a platform key is already enrolled, factory or custom): the installer made NO NVRAM writes. Import db.cer AND the vendor option-ROM certificate INTO THE EXISTING key database (db) via the firmware setup UI. Do NOT import KEK.cer or PK.cer and do NOT clear or replace the platform key — the existing PK and KEK stay. Secure Boot can remain ENABLED throughout. The generic decision tree below applies to the OTHER mode (firmware refused the installer'\''s NVRAM writes).'
            # install-tail seam: the plan's verdict record reads this marker
            # (host tmpfs, bind-mounted into the chroot) to route the completion
            # message + the firmware-setup reboot to the deferred branch
            if [ -n "${ALPINE_FDE_ENROLL_DEFERRED_MARKER:-}" ]; then
                : >"$ALPINE_FDE_ENROLL_DEFERRED_MARKER" 2>/dev/null ||
                    die "firmware: cannot record the deferred-enrollment marker at $ALPINE_FDE_ENROLL_DEFERRED_MARKER — the install tail could not learn the deferred verdict (fix the marker directory and re-run; completed steps skip via crash resume)"
            fi
            return 0
        fi
        die "firmware: SetupMode is $_fae_setup (user mode, NO platform key present — a state no real firmware reports) — refusing the db reset + enrollment: this flow resets and rebuilds db ONLY in Setup Mode (reboot into BIOS setup, 'Clear Secure Boot Keys' to remove the vendor PK so SetupMode becomes 1, keep Secure Boot OFF, then re-run); resetting db outside Setup Mode requires different authorization and is not this flow's job"
    fi
    info "firmware: Setup Mode — db reset + release+vendor rebuild, then KEK -> PK (PK last)"
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
        # authenticated write — for db this IS the decided db RESET (the
        # rebuild replaces the whole variable, so no APPEND_ATTRIBUTE write is
        # ever needed and re-installs never accumulate duplicates). Safe by
        # construction: SetupMode==1 is a fail-closed gate above, and the
        # reset-db -> db -> KEK -> PK order protects the half-enrolled trust
        # root.
        if [ -e "$_fae_dir/$_fae_v-$_fae_guid" ]; then
            if [ "$_fae_v" = "db" ]; then
                info "firmware: db RESET — deleting the pre-existing db before the release+vendor rebuild (authenticated delete, Setup Mode)"
            else
                info "firmware: removing pre-existing vendor $_fae_v"
            fi
            # REAL-SERVER blocker #25 addendum (Dell, live-proven): efivarfs
            # marks AUTHENTICATED variables' inodes S_IMMUTABLE at creation.
            # chattr -i is required before ANY removal attempt.
            command -v chattr >/dev/null 2>&1 ||
                die "firmware: clearing the pre-existing $_fae_v requires chattr — apk add e2fsprogs (efivarfs marks authenticated variables immutable; blocker #25 addendum)"
            chattr -i "$_fae_dir/$_fae_v-$_fae_guid" >/dev/null 2>&1 || :
            rm -f "$_fae_dir/$_fae_v-$_fae_guid" 2>/dev/null || :
            if [ -e "$_fae_dir/$_fae_v-$_fae_guid" ]; then
                # SIGNED-EMPTY delete fallback (the blocker #25 addendum
                # machinery, REUSED for the db reset — no separate deleter):
                # efitools signs the EMPTY payload and efi-updatevar -f
                # performs the authenticated remove. Chain: db-del by the KEK
                # key, KEK/PK-del by the PK key. The chain keys are usually
                # already shredded at this point of the install (stage1
                # custody) — when they are absent the attempt degrades to the
                # write below + the shared final gate, never a silent skip.
                if command -v efi-updatevar >/dev/null 2>&1 &&
                    command -v sign-efi-sig-list >/dev/null 2>&1; then
                    case $_fae_v in
                        db)  _fae_dkey="$_fae_keys/kek.priv.pem"; _fae_dcert="$_fae_keys/kek.cert.pem" ;;
                        *)   _fae_dkey="$_fae_keys/pk.priv.pem"; _fae_dcert="$_fae_keys/pk.cert.pem" ;;
                    esac
                    if [ -f "$_fae_dkey" ] && [ -f "$_fae_dcert" ]; then
                        chattr -i "$_fae_dir/$_fae_v-$_fae_guid" >/dev/null 2>&1 || :
                        sign-efi-sig-list -g "$_fae_guid" -c "$_fae_dcert" -k "$_fae_dkey" \
                            "$_fae_v" /dev/null "$_fae_dir/$_fae_v-del.auth" >/dev/null 2>&1 ||
                            die "firmware: sign-efi-sig-list failed for the $_fae_v signed-empty delete (blocker #25 addendum)"
                        chattr -i "$_fae_dir/$_fae_v-$_fae_guid" >/dev/null 2>&1 || :
                        efi-updatevar -f "$_fae_dir/$_fae_v-del.auth" "$_fae_v" >/dev/null 2>&1 ||
                            warn "firmware: efi-updatevar refused the $_fae_v signed-empty delete (blocker #25 addendum)"
                    else
                        warn "firmware: the $_fae_v delete was refused and the signed-delete chain keys ($_fae_dkey) are not on disk (shredded after stage1, ADR-18) — attempting the authenticated write anyway; the shared gate below refuses to enroll over a surviving variable"
                    fi
                else
                    warn "firmware: the unauthenticated delete of $_fae_v was refused and the signed-delete tools (efitools) are missing — attempting the authenticated write anyway; the shared gate below refuses to enroll over a surviving variable"
                fi
            fi
            # SHARED final gate: the variable MUST be gone before enrolling —
            # never enroll over a live trust anchor
            if [ -e "$_fae_dir/$_fae_v-$_fae_guid" ]; then
                rm -rf "$_fae_dir/$_fae_v-$_fae_guid" 2>/dev/null || :
                [ -e "$_fae_dir/$_fae_v-$_fae_guid" ] &&
                    die "firmware: $_fae_v survived the cleanup — refusing to enroll over a live trust anchor (blocker #25 addendum)"
            fi
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

# db_vendor_dir — resolve the vendor-cert directory for the db reset+rebuild
# (DECIDED 2026-09-27, UEFI0072 option-ROM authorization). Resolution order:
#   1. $ALPINE_FDE_DB_VENDOR_DIR (explicit override)
#   2. "certs/vendor" next to the lib tree — one relative shape covers the
#      repo checkout (lib/cmd -> <repo>/certs/vendor), the installed tree
#      (/usr/share/alpine-fde/lib/cmd -> /usr/share/alpine-fde/certs/vendor)
#      and the in-target tooling copy (/opt/alpine-fde likewise)
# The directory may be absent: an empty vendor set simply means a
# release-cert-only db (the old behavior). Consumers decide whether that is
# an error for their flow. Only *.cer (DER) files are consumed.
db_vendor_dir() {
    if [ -n "${ALPINE_FDE_DB_VENDOR_DIR:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_DB_VENDOR_DIR"
        return 0
    fi
    _dvd_cmd=${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
    printf '%s\n' "${_dvd_cmd%/*}/../certs/vendor"
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
