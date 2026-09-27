#!/usr/bin/env bash
# tests/unit/install_bootentry.sh — task #27: `alpine-fde install` creates the
# UEFI boot entry (efibootmgr) as an in-guest step — Boot0005 "Alpine FDE" on
# the real Dell PowerEdge was typed BY HAND after the fresh install, and after
# a re-partition the hand-made entry kept the OLD partition GUID and died
# "Boot Failed". Pins:
#   * the plan carries exactly ONE in-guest boot-entry record, AFTER the
#     provisional seal (the loader is staged by then) and BEFORE the teardown,
#     with the require_pkgs efibootmgr:efibootmgr probe;
#   * the efibootmgr binary is delivered by the §3.3 target package set;
#   * inst_bootentry_ensure: creates the entry against the ESP's CURRENT
#     partition GUID (from the §8.4 target metadata) + \EFI\BOOT\BOOTX64.EFI,
#     REUSES a same-label entry already pointing there (no duplicate),
#     DELETES + recreates same-label entries at dead/old GUIDs, places the
#     entry FIRST in BootOrder preserving the rest, and SKIPS with the exact
#     manual efibootmgr command when efivarfs is absent (no EFI vars support).
#
# Hermetic: a fake efibootmgr (ALPINE_FDE_EFIBOOTMGR seam, the repo's
# fake-binary seam pattern) keeps its NVRAM in a state file and logs every
# invocation; the baseline seam (ALPINE_FDE_ROOT) carries the canned ESP
# PARTUUID. The EFI entry format the fake emits mirrors real `efibootmgr -v`
# output (Boot<4hex>* <label><TAB>HD(1,GPT,<guid>,…)/File(\EFI\BOOT\…)) — the
# approximation is the fake's state machine, not the parsed format.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-bootentry.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_ROOT=$T/root          # baseline seam: <root>/etc/alpine-fde/baseline.json
export ALPINE_FDE_EFIVARS_DIR=$T/efivars
export ALPINE_FDE_EFIBOOTMGR=$T/stub/efibootmgr
export ALPINE_FDE_HOOKS_DIR=$T/hooks    # dry-run must not require the real hooks tree

GUID=11111111-2222-3333-4444-555555555555   # the CURRENT ESP partition GUID
OLD=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee    # a dead/old partition GUID
export GUID
ESPDIR=$T/esp                               # the staged ESP (loader present)

mkdir -p "$T/root/etc/alpine-fde" "$T/stub" "$ESPDIR/EFI/BOOT" "$T/nvram" "$T/efivars"
: >"$ESPDIR/EFI/BOOT/BOOTX64.EFI"
printf '{\n  "schema_version": 1,\n  "target": {\n    "esp_partuuid": "%s"\n  }\n}\n' "$GUID" \
    >"$T/root/etc/alpine-fde/baseline.json"

# --- the fake efibootmgr (state-file NVRAM + invocation log) -------------------
NVRAM=$T/nvram
export NVRAM
cat >"$T/stub/efibootmgr" <<'EOF'
#!/bin/sh
# fake efibootmgr: NVRAM = $NVRAM/entries ("num|guid|label|loader" lines) +
# $NVRAM/order (BootOrder CSV); every invocation logged to $NVRAM/log
printf 'efibootmgr %s\n' "$*" >>"$NVRAM/log"
case " $* " in
    *" -v "*)
        printf 'BootCurrent: 0002\nTimeout: 0 seconds\n'
        if [ -f "$NVRAM/order" ]; then printf 'BootOrder: %s\n' "$(cat "$NVRAM/order")"; fi
        while IFS='|' read -r num guid label loader; do
            [ -n "$num" ] || continue
            printf 'Boot%s* %s\tHD(1,GPT,%s,0x800,0x100000)/File(%s)\n' \
                "$num" "$label" "$guid" "$loader"
        done <"$NVRAM/entries"
        ;;
    *" -c "*)
        d=''; p=''; l=''; L=''
        prev=''
        for a in "$@"; do
            case $prev in
                -d) d=$a ;;
                -p) p=$a ;;
                -l) l=$a ;;
                -L) L=$a ;;
            esac
            prev=$a
        done
        printf 'efibootmgr -c ARGS d=%s p=%s L=%s l=%s\n' "$d" "$p" "$L" "$l" >>"$NVRAM/log"
        num=''
        i=1
        while [ "$i" -le 65535 ]; do
            cand=$(printf '%04x' "$i")
            if ! grep -q "^$cand|" "$NVRAM/entries"; then
                num=$cand
                break
            fi
            i=$((i + 1))
        done
        printf '%s|%s|%s|%s\n' "$num" "${FAKE_NEW_GUID:-$GUID}" "$L" "$l" >>"$NVRAM/entries"
        printf 'Boot%s* created\n' "$num"
        ;;
    *" -B "*)
        prev=''
        for a in "$@"; do
            if [ "$prev" = "-b" ]; then
                grep -v "^$a|" "$NVRAM/entries" >"$NVRAM/entries.new" || :
                mv "$NVRAM/entries.new" "$NVRAM/entries"
            fi
            prev=$a
        done
        ;;
    *" -o "*)
        prev=''
        for a in "$@"; do
            if [ "$prev" = "-o" ]; then printf '%s\n' "$a" >"$NVRAM/order"; fi
            prev=$a
        done
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/efibootmgr"

reset_nvram() { # [entry lines...] [order CSV]
    : >"$NVRAM/entries"
    rm -f "$NVRAM/order"
    : >"$NVRAM/log"
    if [ -n "${2:-}" ]; then printf '%s\n' "$2" >"$NVRAM/order"; fi
    if [ -n "${1:-}" ]; then printf '%s\n' "$1" >"$NVRAM/entries"; fi
}

line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

# =============================================================================
# 1. fresh NVRAM: the entry is created against the CURRENT partition GUID,
#    loader \EFI\BOOT\BOOTX64.EFI, and lands FIRST in BootOrder
# =============================================================================
reset_nvram '' '0002,0003'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
printf '0003|66666666-7777-8888-9999-000000000000|UEFI Shell|\\EFI\\shell.efi\n' >>"$NVRAM/entries"
assert_rc "fresh NVRAM: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_contains "fresh: the entry is created" "$ASSERT_RC_OUTPUT" "created boot entry"
CREATE=$(grep -F 'efibootmgr -c ARGS' "$NVRAM/log")
assert_contains "fresh: -c targets disk + partition (/dev/sda -p 1)" "$CREATE" "d=/dev/sda p=1"
assert_contains "fresh: -c carries the capitalized label" "$CREATE" "L=Alpine FDE"
assert_contains "fresh: -c carries the loader path" "$CREATE" "l=\EFI\BOOT\BOOTX64.EFI"
assert_contains "fresh: the entry pins the ESP's CURRENT partition GUID" "$ASSERT_RC_OUTPUT" "$GUID"
assert_eq "fresh: FIRST in BootOrder (Windows + shell preserved behind)" \
    "0001,0002,0003" "$(cat "$NVRAM/order")"

# =============================================================================
# 2. idempotent reuse: an existing same-label entry at the CURRENT GUID +
#    loader is reused — NO duplicate created
# =============================================================================
reset_nvram "0005|$GUID|Alpine FDE|\EFI\BOOT\BOOTX64.EFI" '0005,0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "reuse: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_eq "reuse: NO -c (no duplicate)" "0" "$(grep -cF 'efibootmgr -c ARGS' "$NVRAM/log")"
assert_contains "reuse: info names the reused entry" "$ASSERT_RC_OUTPUT" "reusing boot entry Boot0005"
assert_contains "reuse: no duplicate created" "$ASSERT_RC_OUTPUT" "no duplicate created"
assert_eq "reuse: entries unchanged (still exactly one Alpine FDE)" "1" "$(grep -c 'Alpine FDE' "$NVRAM/entries")"
assert_eq "reuse: BootOrder rewritten with the entry FIRST" "0005,0002" "$(cat "$NVRAM/order")"

# =============================================================================
# 3. stale-GUID replacement: a same-label entry at an OLD partition GUID is
#    deleted + recreated (the real-server "Boot Failed" shape); unrelated
#    entries and their BootOrder positions survive
# =============================================================================
reset_nvram "0005|$OLD|Alpine FDE|\EFI\BOOT\BOOTX64.EFI" '0002,0005'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "stale: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_contains "stale: the delete ran (log -b 0005 -B)" "$(cat "$NVRAM/log")" "efibootmgr -b 0005 -B"
assert_contains "stale: die-free recreate names the new entry" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_eq "stale: the old entry is GONE" "0" "$(grep -c "^0005|" "$NVRAM/entries")"
assert_eq "stale: the replacement carries the CURRENT GUID" "1" "$(grep -c "$GUID" "$NVRAM/entries")"
assert_contains "stale: the delete explains the Boot Failed shape" "$ASSERT_RC_OUTPUT" "old partition GUID"
assert_eq "stale: the replacement is FIRST, the unrelated entry kept" "0001,0002" "$(cat "$NVRAM/order")"

# =============================================================================
# 4. duplicate pile-up: two same-label entries at the current GUID+loader
#    collapse to ONE (re-run hygiene)
# =============================================================================
reset_nvram "0007|$GUID|Alpine FDE|\EFI\BOOT\BOOTX64.EFI" '0007,0008'
printf '0008|%s|Alpine FDE|\\EFI\\BOOT\\BOOTX64.EFI\n' "$GUID" >>"$NVRAM/entries"
assert_rc "dup: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_contains "dup: the second duplicate was deleted" "$(cat "$NVRAM/log")" "efibootmgr -b 0008 -B"
assert_eq "dup: exactly one same-label entry survives" "1" "$(grep -c 'Alpine FDE' "$NVRAM/entries")"

# =============================================================================
# 5. NO EFI variable support: skip gracefully, print the EXACT manual command
# =============================================================================
reset_nvram '' ''
mv "$T/efivars" "$T/efivars.gone"
assert_rc "no-EFI: rc 0 (skip, never fail the install)" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_eq "no-EFI: nothing created" "0" "$(grep -c . "$NVRAM/entries")"
assert_contains "no-EFI: the skip names the manual efibootmgr command" "$ASSERT_RC_OUTPUT" \
    "efibootmgr -c -d /dev/sda -p 1 -L 'Alpine FDE' -l '\EFI\BOOT\BOOTX64.EFI'"
assert_contains "no-EFI: the manual command tells how to go FIRST in BootOrder" "$ASSERT_RC_OUTPUT" "efibootmgr -o"
assert_contains "no-EFI: the manual command names the partition GUID to pin" "$ASSERT_RC_OUTPUT" "$GUID"
mv "$T/efivars.gone" "$T/efivars"

# 5b. efibootmgr present but REPORTING no support (libefivar's wording):
#     the same graceful skip
reset_nvram '' ''
cat >"$T/stub/efibootmgr-unsupported" <<'EOF'
#!/bin/sh
printf 'efibootmgr: EFI variables are not supported on this system.\n' >&2
exit 2
EOF
chmod +x "$T/stub/efibootmgr-unsupported"
SAVED_EB=$ALPINE_FDE_EFIBOOTMGR
ALPINE_FDE_EFIBOOTMGR=$T/stub/efibootmgr-unsupported
assert_rc "no-support: rc 0 (skip)" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
ALPINE_FDE_EFIBOOTMGR=$SAVED_EB
assert_contains "no-support: skip names the manual command" "$ASSERT_RC_OUTPUT" \
    "efibootmgr -c -d /dev/sda -p 1"

# =============================================================================
# 6. fail-closed guards: missing staged loader dies; missing baseline dies
# (die exits — run each in a command substitution so only the subshell dies)
# =============================================================================
reset_nvram '' ''
mv "$ESPDIR/EFI/BOOT/BOOTX64.EFI" "$T/loader.gone"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" 2>&1)
GUARD_RC=$?
assert_eq "guard: missing staged loader -> die (fail-closed 64)" "64" "$GUARD_RC"
assert_contains "guard: the die names the unstaged loader" "$OUT" "BOOTX64.EFI is missing"
mv "$T/loader.gone" "$ESPDIR/EFI/BOOT/BOOTX64.EFI"

mv "$T/root/etc/alpine-fde/baseline.json" "$T/baseline.gone"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" 2>&1)
GUARD_RC=$?
assert_eq "guard: missing baseline -> die (fail-closed 64)" "64" "$GUARD_RC"
assert_contains "guard: the die names the baseline" "$OUT" "baseline.json"
mv "$T/baseline.gone" "$T/root/etc/alpine-fde/baseline.json"

# =============================================================================
# 7. inst_bootentry_parse: label matching is EXACT (a longer label sharing the
#    prefix is not ours); GUID + loader extracted lowercased from -v output
# =============================================================================
LIST=$(printf 'Boot0009* Alpine FDE\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\BOOT\\BOOTX64.EFI)\nBoot000A* Alpine FDE2\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\BOOT\\BOOTX64.EFI)\nBoot000B* Ubuntu\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\shimx64.EFI)\n' "$GUID" "$GUID" "$GUID")
PARSED=$(printf '%s\n' "$LIST" | inst_bootentry_parse "Alpine FDE")
assert_eq "parse: ours=1 for the exact label" "0009 $GUID 1 1" "$(printf '%s\n' "$PARSED" | grep '^0009')"
assert_eq "parse: prefix-sharing label NOT ours" "1" "$(printf '%s\n' "$PARSED" | grep -c '^000a.* 0$')"
assert_eq "parse: foreign entry not ours, loader flag 0" "000b $GUID 0 0" "$(printf '%s\n' "$PARSED" | grep '^000b')"
assert_eq "parse: inst_bootentry_find picks OURS" "0009" "$(inst_bootentry_find "$PARSED" "$GUID")"

# =============================================================================
# 8. the PLAN: exactly one in-guest boot-entry record, after the provisional
#    seal, before the teardown; efibootmgr pinned in the target package set
# =============================================================================
export ALPINE_FDE_INSTALL_RUNNER=dry-run
export ALPINE_FDE_INSTALL_NO_REBOOT=1
DISK=$T/disk.img
: >"$DISK"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1)
assert_eq "dry-run rc 0" "0" "$?"
assert_eq "plan: exactly ONE boot-entry record" "1" "$(grep -c 'inst_bootentry_ensure' <<<"$OUT")"
assert_eq "plan: the record is a GUEST step (in-chroot, task #27)" "1" \
    "$(grep -cE '^PLAN  guest +.*inst_bootentry_ensure' <<<"$OUT")"
assert_contains "plan: the record probes require_pkgs efibootmgr:efibootmgr" "$OUT" \
    "require_pkgs efibootmgr:efibootmgr"
I_SEAL=$(line_no "$OUT" "seal_provisional")
I_ENTRY=$(line_no "$OUT" "inst_bootentry_ensure")
I_UMOUNT=$(line_no "$OUT" "umount /mnt/sys/firmware/efi/efivars 2>/dev/null || umount -l /mnt/sys/firmware/efi/efivars 2>/dev/null")
assert_eq "order: boot entry AFTER the provisional seal (loader staged)" "1" \
    "$(( I_SEAL > 0 && I_ENTRY > I_SEAL ? 1 : 0 ))"
assert_eq "order: boot entry BEFORE the teardown (chroot still sees the ESP)" "1" \
    "$(( I_UMOUNT > 0 && I_ENTRY < I_UMOUNT ? 1 : 0 ))"
assert_eq "package set: efibootmgr pinned (target delivery + mirror closure)" "1" \
    "$(install_package_list | tr ' ' '\n' | grep -cx 'efibootmgr')"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
