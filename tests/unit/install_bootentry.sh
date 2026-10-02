#!/usr/bin/env bash
# tests/unit/install_bootentry.sh — task #27 + the DEFAULT-ONLY BOOT DESIGN
# (Samuel, 2026-10-02; supersedes the two-UKI NVRAM pair): the lane creates ONE
# firmware (NVRAM) boot entry per kernel version — the DEFAULT UKI — and the
# firmware loads the UKI DIRECTLY (systemd-boot stays only the removable-media
# fallback — never the default boot path). The SERIAL NVRAM lane is RETIRED:
# the serial UKI FILE still builds + installs to the ESP per kernel and the
# automation one-shots it via UefiTarget, but NO serial entry is ever created
# and retired serial entries are SWEPT. On the real Dell PowerEdge the entry
# was typed BY HAND after the fresh install, and after a re-partition the
# hand-made entry kept the OLD partition GUID and died "Boot Failed". Pins:
#   * the plan carries exactly ONE in-guest boot-entry record, AFTER the
#     provisional seal (the UKI pair is staged by then) and BEFORE the
#     teardown, with the require_pkgs efibootmgr:efibootmgr probe and the
#     in-guest kver derivation (blocker #11 shape);
#   * the efibootmgr binary is delivered by the §3.3 target package set;
#   * inst_bootentry_ensure: creates the DEFAULT entry —
#       "Alpine FDE - <kver> (<date>)" -> \EFI\Linux\alpine-fde-<kver>.efi
#     against the ESP's CURRENT partition GUID, FIRST in BootOrder, REUSING
#     family entries already pointing there (no duplicate), DELETING +
#     recreating family entries at dead/old GUIDs and stale loaders (a rebuild
#     re-stamps the date in the label), deleting the pre-two-UKI LEGACY
#     entries AND the RETIRED SERIAL entries (serial labels / -serial.efi
#     loaders — the NVRAM carries default entries only), and SKIPPING with the
#     exact manual efibootmgr command when efivarfs is absent (no EFI vars
#     support);
#   * inst_bootentry_prune: boot entries of kernels OUTSIDE the keep set, all
#     RETIRED serial entries, and LEGACY entries are deleted, BootOrder
#     rewritten over the survivors with the relative order preserved — at most
#     3 kernel versions = 3 entries.
#
# Hermetic: a fake efibootmgr (ALPINE_FDE_EFIBOOTMGR seam, the repo's
# fake-binary seam pattern) keeps its NVRAM in a state file and logs every
# invocation; the baseline seam (ALPINE_FDE_ROOT) carries the canned ESP
# PARTUUID; ALPINE_FDE_BOOTENTRY_DATE pins the label date. The EFI entry
# format the fake emits mirrors real `efibootmgr -v` output
# (Boot<4hex>* <label><TAB>HD(1,GPT,<guid>,…)/File(\EFI\Linux\…)) — the
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
export ALPINE_FDE_HOOKS_DIR=$T/hooks    # the emission lane must not require the real hooks tree
export ALPINE_FDE_BOOTENTRY_DATE=2026-09-29
export ALPINE_FDE_BOOTENTRY_RETRY_SLEEP=0 # keep the retry legs instant outside the lag/never fakes

KVER=6.12.8-1-amd64
LBL_DEF="Alpine FDE - $KVER (2026-09-29)"
LBL_SER="Alpine FDE - $KVER serial (2026-09-29)"
LDR_DEF='\EFI\Linux\alpine-fde-6.12.8-1-amd64.efi'
LDR_SER='\EFI\Linux\alpine-fde-6.12.8-1-amd64-serial.efi'
export KVER LBL_DEF LBL_SER LDR_DEF LDR_SER

GUID=11111111-2222-3333-4444-555555555555   # the CURRENT ESP partition GUID
OLD=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee    # a dead/old partition GUID
export GUID
ESPDIR=$T/esp                               # the staged ESP (the UKI pair)

mkdir -p "$T/root/etc/alpine-fde" "$T/stub" "$ESPDIR/EFI/Linux" "$T/nvram" "$T/efivars"
printf 'default-uki' >"$ESPDIR/EFI/Linux/alpine-fde-$KVER.efi"
printf 'serial-uki' >"$ESPDIR/EFI/Linux/alpine-fde-$KVER-serial.efi"
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
    rm -f "$NVRAM/lag"
    : >"$NVRAM/log"
    if [ -n "${2:-}" ]; then printf '%s\n' "$2" >"$NVRAM/order"; fi
    if [ -n "${1:-}" ]; then printf '%s\n' "$1" >"$NVRAM/entries"; fi
}

line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

# =============================================================================
# 1. fresh NVRAM: the DEFAULT entry is created against the CURRENT partition
#    GUID — default -> the UKI, FIRST in BootOrder. The SERIAL NVRAM lane is
#    RETIRED: no serial entry is ever created (the serial UKI FILE stays on
#    the ESP — one-shot via UefiTarget).
# =============================================================================
reset_nvram '' '0002,0003'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
printf '0003|66666666-7777-8888-9999-000000000000|UEFI Shell|\\EFI\\shell.efi\n' >>"$NVRAM/entries"
assert_rc "fresh NVRAM: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "fresh: the entry is created (default named)" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_eq "fresh: exactly ONE entry created" "1" "$(grep -cF 'efibootmgr -c ARGS' "$NVRAM/log")"
CREATE=$(grep -F 'efibootmgr -c ARGS' "$NVRAM/log" | head -1)
assert_contains "fresh: -c targets disk + partition (/dev/sda -p 1)" "$CREATE" "d=/dev/sda p=1"
assert_contains "fresh: the label carries kver + date" "$(cat "$NVRAM/entries")" "$LBL_DEF"
assert_contains "fresh: the entry points at the DEFAULT UKI (firmware-direct)" \
    "$(cat "$NVRAM/entries")" "$LDR_DEF"
assert_eq "fresh: NO serial entry is created (the serial NVRAM lane is retired)" \
    "0" "$(grep -cF "$LBL_SER" "$NVRAM/entries")"
assert_eq "fresh: BootOrder = the default entry FIRST, others preserved" \
    "0001,0002,0003" "$(cat "$NVRAM/order")"

# =============================================================================
# 1b. RETIRED SERIAL SWEEP: serial NVRAM entries (the retired two-UKI lane —
#     the same-kver serial at the CURRENT GUID, an old-kver serial at a dead
#     GUID) are SWEPT by the ensure; the NVRAM carries DEFAULT entries only.
#     The serial UKI FILE stays on the ESP (one-shot via UefiTarget) — only
#     the NVRAM lane is retired.
# =============================================================================
reset_nvram "0005|$GUID|$LBL_SER|$LDR_SER
0006|$OLD|Alpine FDE - 6.1.0-1-amd64 serial (2026-08-01)|\EFI\Linux\alpine-fde-6.1.0-1-amd64-serial.efi
0007|$GUID|$LBL_DEF|$LDR_DEF" '0005,0006,0007'
assert_rc "serial sweep: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "serial sweep: the current-GUID serial entry was deleted" "$(cat "$NVRAM/log")" "efibootmgr -b 0005 -B"
assert_contains "serial sweep: the dead-GUID serial entry was deleted" "$(cat "$NVRAM/log")" "efibootmgr -b 0006 -B"
assert_contains "serial sweep: the standing DEFAULT entry is REUSED (no duplicate)" "$ASSERT_RC_OUTPUT" "reusing boot entry Boot0007"
assert_eq "serial sweep: NO serial entry remains" "0" "$(grep -c 'serial' "$NVRAM/entries")"
assert_eq "serial sweep: no create needed (the default entry already stands)" "0" "$(grep -cF 'efibootmgr -c ARGS' "$NVRAM/log")"
assert_eq "serial sweep: BootOrder = the default entry FIRST" "0007" "$(cat "$NVRAM/order")"

# =============================================================================
# 2. idempotent reuse: an existing same-kver DEFAULT entry at the CURRENT
#    GUID + loader is reused — NO duplicate created — and the retired serial
#    sibling standing next to it is SWEPT (the NVRAM carries default entries
#    only)
# =============================================================================
reset_nvram "0005|$GUID|$LBL_DEF|$LDR_DEF
0006|$GUID|$LBL_SER|$LDR_SER" '0005,0006,0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "reuse: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_eq "reuse: NO -c (no duplicate)" "0" "$(grep -cF 'efibootmgr -c ARGS' "$NVRAM/log")"
assert_contains "reuse: info names the reused default entry" "$ASSERT_RC_OUTPUT" "reusing boot entry Boot0005"
assert_contains "reuse: the retired serial sibling was swept" "$(cat "$NVRAM/log")" "efibootmgr -b 0006 -B"
assert_eq "reuse: entries unchanged (exactly the default entry)" "1" "$(grep -c "Alpine FDE - " "$NVRAM/entries")"
assert_eq "reuse: BootOrder rewritten with the default entry in front" "0005,0002" "$(cat "$NVRAM/order")"

# =============================================================================
# 3. stale-GUID replacement: a DEFAULT family entry at an OLD partition GUID
#    is deleted + recreated (the real-server "Boot Failed" shape); the
#    unrelated entry survives
# =============================================================================
reset_nvram "0005|$OLD|$LBL_DEF|$LDR_DEF
0006|66666666-7777-8888-9999-000000000000|UEFI Shell|\\EFI\\shell.efi" '0002,0005,0006'
assert_rc "stale: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "stale: the delete ran (log -b 0005 -B)" "$(cat "$NVRAM/log")" "efibootmgr -b 0005 -B"
assert_contains "stale: die-free recreate names the new entry" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_eq "stale: the old-GUID entry is GONE" "0" "$(grep -c "^0005|" "$NVRAM/entries")"
assert_eq "stale: the replacement carries the CURRENT GUID" "1" "$(grep -c "$GUID" "$NVRAM/entries")"
assert_contains "stale: the delete explains the Boot Failed shape" "$ASSERT_RC_OUTPUT" "old partition GUID"

# =============================================================================
# 4. stale-loader replacement + legacy cleanup: a rebuild re-stamps the label
#    date (family entry at the right GUID, stale loader -> replaced) and the
#    pre-two-UKI "Alpine FDE" entries (the boot-manager path) are deleted
# =============================================================================
reset_nvram "0005|$GUID|Alpine FDE - $KVER (2026-01-01)|$LDR_DEF
0006|$GUID|Alpine FDE|\EFI\BOOT\BOOTX64.EFI" '0005,0006'
assert_rc "stale-loader/legacy: rc 0" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "stale-loader: the old-date family entry was replaced" "$(cat "$NVRAM/log")" "efibootmgr -b 0005 -B"
assert_contains "legacy: the pre-two-UKI 'Alpine FDE' entry was deleted" "$(cat "$NVRAM/log")" "efibootmgr -b 0006 -B"
assert_contains "legacy: the deletion says why (retired boot-manager path)" "$ASSERT_RC_OUTPUT" \
    "legacy boot entry Boot0006"
assert_eq "legacy: the BOOTX64 entry is gone" "0" "$(grep -c 'BOOTX64' "$NVRAM/entries")"
assert_eq "stale-loader: exactly the current default entry remains" "1" "$(grep -c "Alpine FDE - " "$NVRAM/entries")"

# =============================================================================
# 5. NO EFI variable support: skip gracefully, print the EXACT manual command
#    for the DEFAULT entry only (the serial NVRAM lane is retired)
# =============================================================================
reset_nvram '' ''
mv "$T/efivars" "$T/efivars.gone"
assert_rc "no-EFI: rc 0 (skip, never fail the install)" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_eq "no-EFI: nothing created" "0" "$(grep -c . "$NVRAM/entries")"
assert_contains "no-EFI: the skip names the manual command for the DEFAULT entry" "$ASSERT_RC_OUTPUT" \
    "efibootmgr -c -d /dev/sda -p 1 -L '$LBL_DEF' -l '$LDR_DEF'"
assert_eq "no-EFI: NO serial manual command (the serial NVRAM lane is retired)" "0" \
    "$(grep -cF "$LBL_SER" <<<"$ASSERT_RC_OUTPUT")"
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
assert_rc "no-support: rc 0 (skip)" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
ALPINE_FDE_EFIBOOTMGR=$SAVED_EB
assert_contains "no-support: skip names the manual command" "$ASSERT_RC_OUTPUT" \
    "efibootmgr -c -d /dev/sda -p 1"

# =============================================================================
# 6. fail-closed guards: an UNSTAGED DEFAULT UKI dies (the firmware loads the
# file DIRECTLY); the SERIAL UKI is NOT guarded (the serial NVRAM lane is
# retired — the file is ESP-only for the UefiTarget one-shot); a missing
# baseline dies (die exits — run each in a command substitution so only the
# subshell dies)
# =============================================================================
reset_nvram '' ''
mv "$ESPDIR/EFI/Linux/alpine-fde-$KVER.efi" "$T/uki.gone"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER" 2>&1)
GUARD_RC=$?
assert_eq "guard: unstaged DEFAULT UKI -> die (fail-closed 64)" "64" "$GUARD_RC"
assert_contains "guard: the die names the unstaged default UKI" "$OUT" "alpine-fde-$KVER.efi is missing"
mv "$T/uki.gone" "$ESPDIR/EFI/Linux/alpine-fde-$KVER.efi"

mv "$ESPDIR/EFI/Linux/alpine-fde-$KVER-serial.efi" "$T/uki-serial.gone"
reset_nvram '' ''
assert_rc "guard: a missing SERIAL UKI does not block the default entry (retired lane)" 0 \
    inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
mv "$T/uki-serial.gone" "$ESPDIR/EFI/Linux/alpine-fde-$KVER-serial.efi"

mv "$T/root/etc/alpine-fde/baseline.json" "$T/baseline.gone"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER" 2>&1)
GUARD_RC=$?
assert_eq "guard: missing baseline -> die (fail-closed 64)" "64" "$GUARD_RC"
assert_contains "guard: the die names the baseline" "$OUT" "baseline.json"
mv "$T/baseline.gone" "$T/root/etc/alpine-fde/baseline.json"

# =============================================================================
# 6b. NVRAM write-latency retry (real Dell PowerEdge R640, 2026-09-28): the
# create's BootOrder update persisted but the new Boot variable was NOT yet
# visible in the immediate post-create listing — and the FIRST bounded verify
# (5 attempts, 2s apart, ~10s) STILL missed it; the entry was present + correct
# only when run by hand minutes later (the boot then worked). The retry is
# raised to 10 attempts / ALPINE_FDE_BOOTENTRY_RETRY_SLEEP apart (default 5s,
# ~50s total). Pins:
#   (a) a fake efibootmgr whose listing LAGS N reads behind the create (each
#       of the first N listings after -c omits our pair) must PASS via the
#       bounded backoff: (a1) a lag of 7 — beyond the retired 5-attempt bound —
#       and (a2) a lag of 2 — comfortably within the new bound;
#   (b) a fake that NEVER shows the entries still fails fail-closed 64, with
#       the die naming the NEW bound (10 attempts, ~50s) and firmware NVRAM
#       write latency (Dell) as the likely cause.
# The wrapper delegates to the base fake (state-file NVRAM) and filters its
# -v output — the approximation is the lag, not the parsed format.
# =============================================================================
cat >"$T/stub/efibootmgr-lagging" <<'EOF'
#!/bin/sh
# lagging fake: the first $NVRAM/lag-count -v reads after each -c omit our
# entries (a stale NVRAM view that outlives the retired 5-attempt bound)
BASE=${ALPINE_FDE_EFIBOOTMGR_BASE}
case " $* " in
    *" -c "*)
        printf '%s\n' "${FAKE_LAG_COUNT:-1}" >"$NVRAM/lag"
        exec "$BASE" "$@" ;;
    *" -v "*)
        if [ -f "$NVRAM/lag" ]; then
            n=$(cat "$NVRAM/lag")
            n=$((n - 1))
            if [ "$n" -gt 0 ]; then printf '%s\n' "$n" >"$NVRAM/lag"; else rm -f "$NVRAM/lag"; fi
            "$BASE" -v | grep -v 'Alpine FDE - '
            exit 0
        fi
        exec "$BASE" "$@" ;;
    *)
        exec "$BASE" "$@" ;;
esac
EOF
chmod +x "$T/stub/efibootmgr-lagging"
cat >"$T/stub/efibootmgr-never" <<'EOF'
#!/bin/sh
# never-shows fake: our entries NEVER appear in the -v listing
BASE=${ALPINE_FDE_EFIBOOTMGR_BASE}
case " $* " in
    *" -v "*)
        "$BASE" "$@" | grep -v 'Alpine FDE - '
        exit 0 ;;
    *)
        exec "$BASE" "$@" ;;
esac
EOF
chmod +x "$T/stub/efibootmgr-never"
SAVED_EB=$ALPINE_FDE_EFIBOOTMGR
ALPINE_FDE_EFIBOOTMGR_BASE=$SAVED_EB

# (a1) lag of 7 listings: BEYOND the retired 5-attempt bound — the raised
#      10-attempt retry must recover it (R640-shaped regression guard)
export ALPINE_FDE_EFIBOOTMGR_BASE
ALPINE_FDE_EFIBOOTMGR=$T/stub/efibootmgr-lagging
ALPINE_FDE_BOOTENTRY_RETRY_SLEEP=0
FAKE_LAG_COUNT=7
reset_nvram '' '0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "lag7 (beyond the retired 5-attempt bound): rc 0 via the raised retry" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "lag7: the entry is created (not reused)" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_contains "lag7: the retry warned about NVRAM latency while waiting" "$ASSERT_RC_OUTPUT" "NVRAM write latency"
assert_contains "lag7: the warn names the raised attempt bound" "$ASSERT_RC_OUTPUT" "attempt 1/24"
assert_eq "lag7: the entry is at the front in order" \
    "0001,0002" "$(cat "$NVRAM/order")"
assert_eq "lag7: the recovered entry pins the CURRENT GUID" "1" "$(grep -c "|$GUID|Alpine FDE - " "$NVRAM/entries")"

# (a2) lag of 2 listings: lands WITHIN the new bound (the common shape)
FAKE_LAG_COUNT=2
reset_nvram '' '0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "lag2 (within the new bound): rc 0 via the retry" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER"
assert_contains "lag2: the entry is created (not reused)" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_eq "lag2: the entry is at the front" "0001,0002" "$(cat "$NVRAM/order")"
FAKE_LAG_COUNT=

# (b) never-visible listing: fail-closed 64 with the latency clause
ALPINE_FDE_EFIBOOTMGR=$T/stub/efibootmgr-never
reset_nvram '' '0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" "$KVER" 2>&1)
NEVER_RC=$?
assert_eq "never: rc 64 (still fail-closed, no entry-number guessing)" "64" "$NEVER_RC"
assert_contains "never: the die keeps the refuse-to-guess clause" "$OUT" "refusing to guess the entry number"
assert_contains "never: the die names NVRAM write latency (Dell) as the likely cause" "$OUT" "NVRAM write latency"
assert_contains "never: the die reports the RAISED bounded attempts" "$OUT" "after 24 attempts (~240s)"
assert_eq "never: the DEFAULT entry WAS created in the fake NVRAM (the write, not the read, succeeded)" "1" \
    "$(grep -c "|$GUID|Alpine FDE - " "$NVRAM/entries")"
assert_eq "never: BootOrder untouched (no guessing)" "0002" "$(cat "$NVRAM/order")"

ALPINE_FDE_EFIBOOTMGR=$SAVED_EB
ALPINE_FDE_BOOTENTRY_RETRY_SLEEP=

# =============================================================================
# 7. inst_bootentry_parse: the label family grammar — kver+variant extracted
#    from "Alpine FDE - <kver>[ serial] (<date>)"; prefix-sharing and foreign
#    labels are NOT ours; the pre-two-UKI labels parse as LEGACY; the loader
#    path comes lowercased from the -v device path
# =============================================================================
LIST=$(printf 'Boot0009* %s\tHD(1,GPT,%s,0x800,0x100000)/File(%s)\nBoot000A* %s\tHD(1,GPT,%s,0x800,0x100000)/File(%s)\nBoot000B* Alpine FDE2 (2026-09-29)\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\shimx64.EFI)\nBoot000C* Alpine FDE\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\BOOT\\BOOTX64.EFI)\nBoot000D* Ubuntu\tHD(1,GPT,%s,0x800,0x100000)/File(\\EFI\\shimx64.EFI)\n' \
    "$LBL_DEF" "$GUID" "$LDR_DEF" "$LBL_SER" "$GUID" "$LDR_SER" "$GUID" "$GUID" "$GUID")
PARSED=$(printf '%s\n' "$LIST" | inst_bootentry_parse)
assert_eq "parse: the default label family parses (kver + variant + loader + label)" \
    "0009 $(printf '%s' "$GUID" | tr A-Z a-z) $(printf '%s' "$LDR_DEF" | tr A-Z a-z) $KVER default $(printf '%s' "$LBL_DEF" | tr A-Z a-z)" \
    "$(printf '%s\n' "$PARSED" | grep '^0009')"
assert_eq "parse: the serial label family parses" \
    "000a $(printf '%s' "$GUID" | tr A-Z a-z) $(printf '%s' "$LDR_SER" | tr A-Z a-z) $KVER serial $(printf '%s' "$LBL_SER" | tr A-Z a-z)" \
    "$(printf '%s\n' "$PARSED" | grep '^000a')"
assert_eq "parse: a prefix-sharing label is NOT ours" "1" "$(printf '%s\n' "$PARSED" | grep -c '^000b .* - - ')"
assert_eq "parse: the pre-two-UKI 'Alpine FDE' label parses as LEGACY" \
    "1" "$(printf '%s\n' "$PARSED" | grep -c '^000c .* LEGACY default')"
assert_eq "parse: a foreign entry is not ours" "1" "$(printf '%s\n' "$PARSED" | grep -c '^000d .* - - ')"
assert_eq "parse: inst_bootentry_find picks OUR default entry" "0009" \
    "$(inst_bootentry_find "$PARSED" "$(printf '%s' "$GUID" | tr A-Z a-z)" \
        "$(printf '%s' "$LDR_DEF" | tr A-Z a-z)" "$KVER" default)"

# =============================================================================
# 8. inst_bootentry_prune: entries of kernels OUTSIDE the keep set are deleted,
#    RETIRED serial entries are deleted EVEN FOR kept kernels, LEGACY entries
#    are deleted, foreign entries and kept-kver DEFAULT entries survive;
#    BootOrder is rewritten over the survivors with the relative order
#    preserved
# =============================================================================
reset_nvram "0001|$GUID|Alpine FDE - 6.12.10-1-amd64 (2026-09-29)|\EFI\Linux\alpine-fde-6.12.10-1-amd64.efi
0002|$GUID|Alpine FDE - 6.12.10-1-amd64 serial (2026-09-29)|\EFI\Linux\alpine-fde-6.12.10-1-amd64-serial.efi
0003|$GUID|Alpine FDE - 6.1.0-1-amd64 (2026-08-01)|\EFI\Linux\alpine-fde-6.1.0-1-amd64.efi
0004|$GUID|Alpine FDE - 6.1.0-1-amd64 serial (2026-08-01)|\EFI\Linux\alpine-fde-6.1.0-1-amd64-serial.efi
0005|$GUID|Alpine FDE|\EFI\BOOT\BOOTX64.EFI
0006|$GUID|Windows Boot Manager|\EFI\Microsoft\bootmgfw.efi" '0001,0002,0003,0004,0005,0006'
assert_rc "prune: rc 0" 0 inst_bootentry_prune 6.12.10-1-amd64 6.12.9-1-amd64
assert_eq "prune: the 6.1.0 entries are GONE" "0" "$(grep -c '6.1.0-1-amd64' "$NVRAM/entries")"
assert_eq "prune: the LEGACY entry is GONE" "0" "$(grep -c 'BOOTX64' "$NVRAM/entries")"
assert_eq "prune: RETIRED serial entries are swept EVEN FOR kept kernels" "0" "$(grep -c 'serial' "$NVRAM/entries")"
assert_eq "prune: the kept DEFAULT entry survives" "1" "$(grep -c '6.12.10-1-amd64' "$NVRAM/entries")"
assert_eq "prune: foreign entries survive" "1" "$(grep -c 'Windows Boot Manager' "$NVRAM/entries")"
assert_eq "prune: BootOrder over the survivors, relative order preserved" \
    "0001,0006" "$(cat "$NVRAM/order")"

# =============================================================================
# 9. the PLAN: exactly one in-guest boot-entry record (with the in-guest kver
#    derivation), after the provisional seal, before the teardown; efibootmgr
#    pinned in the target package set.
#    (Item 17d: the dry-run plan printer is RETIRED — the record-level pins
#    moved to the qemu EMISSION shape, the inspectable lane that remains; the
#    preflight now runs in this lane, so the collaborators are stubbed.)
# =============================================================================
export ALPINE_FDE_INSTALL_RUNNER=qemu
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_NO_REBOOT=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_TMPDIR=$T
export ALPINE_FDE_INSTALL_SCRIPT=$T/guest.sh
export ALPINE_FDE_EFIVARS_DIR=$T/efivars
mkdir -p "$T/stub" "$T/efivars" "$ALPINE_FDE_HOOKS_DIR"/kernel-hooks.d "$ALPINE_FDE_HOOKS_DIR"/mkinitfs/features.d \
    "$ALPINE_FDE_HOOKS_DIR"/apk/triggers "$ALPINE_FDE_HOOKS_DIR"/conf.d "$ALPINE_FDE_HOOKS_DIR"/openrc "$ALPINE_FDE_HOOKS_DIR"/profile.d
make_stub() {
    printf '#!/bin/sh\nexit 0\n' >"$T/stub/$1"
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount apk adduser addgroup rc-update cert-to-efi-sig-list sign-efi-sig-list \
    lsblk btrfs cryptsetup; do
    make_stub "$s"
done
printf '#!/bin/sh\ncase " $* " in *" rand "*) printf "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";; esac\nexit 0\n' >"$T/stub/openssl"
chmod +x "$T/stub/openssl"
printf '#!/bin/sh\nprintf "0\\n"\n' >"$T/stub/id"
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    mkinitfs/features.d/alpine-fde.modules \
    apk/triggers/alpine-fde.trigger apk/triggers/alpine-fde-snapshot.trigger conf.d/alpine-fde-snapshot openrc/alpine-fde-finalize \
    openrc/alpine-fde-audit profile.d/alpine-fde.sh; do
    printf '#!/bin/sh\nexit 0\n' >"$ALPINE_FDE_HOOKS_DIR/$h"
    chmod +x "$ALPINE_FDE_HOOKS_DIR/$h"
done
printf '\007\000\000\000\001' >"$T/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
DISK=$T/disk.img
: >"$DISK"
rm -f "$ALPINE_FDE_INSTALL_SCRIPT"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1)
PLAN_RC=$?
OUT="$OUT
$(cat "$ALPINE_FDE_INSTALL_SCRIPT" 2>/dev/null || :)"
assert_eq "qemu emit rc 0" "0" "$PLAN_RC"
assert_eq "plan: exactly ONE boot-entry record" "1" "$(grep -c 'inst_bootentry_ensure' <<<"$OUT")"
assert_eq "plan: the record is a GUEST step (in-chroot, task #27)" "1" \
    "$(grep -cE '^export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; .*inst_bootentry_ensure' <<<"$OUT")"
LINE=$(grep -m1 'inst_bootentry_ensure' <<<"$OUT")
assert_contains "plan: the record carries the in-guest /lib/modules kver derivation" "$LINE" \
    'cd /lib/modules'
assert_contains "plan: the record probes require_pkgs efibootmgr:efibootmgr" "$OUT" \
    "require_pkgs efibootmgr:efibootmgr"
I_SEAL=$(line_no "$OUT" "seal_provisional")
I_ENTRY=$(line_no "$OUT" "inst_bootentry_ensure")
I_UMOUNT=$(line_no "$OUT" "umount $T/mnt/sys/firmware/efi/efivars 2>/dev/null || umount -l")
assert_eq "order: boot entry AFTER the provisional seal (UKI pair staged)" "1" \
    "$(( I_SEAL > 0 && I_ENTRY > I_SEAL ? 1 : 0 ))"
assert_eq "order: boot entry BEFORE the teardown (chroot still sees the ESP)" "1" \
    "$(( I_UMOUNT > 0 && I_ENTRY < I_UMOUNT ? 1 : 0 ))"
assert_eq "package set: efibootmgr pinned (target delivery + mirror closure)" "1" \
    "$(install_package_list | tr ' ' '\n' | grep -cx 'efibootmgr')"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
