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
export ALPINE_FDE_HOOKS_DIR=$T/hooks    # the emission lane must not require the real hooks tree

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
    rm -f "$NVRAM/lag"
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
# 6b. NVRAM write-latency retry (real Dell PowerEdge R640, 2026-09-28): the
# create's BootOrder update persisted but the new Boot variable was NOT yet
# visible in the immediate post-create listing — and the FIRST bounded verify
# (5 attempts, 2s apart, ~10s) STILL missed it; the entry was present + correct
# only when run by hand minutes later (the boot then worked). The retry is
# raised to 10 attempts / ALPINE_FDE_BOOTENTRY_RETRY_SLEEP apart (default 5s,
# ~50s total). Pins:
#   (a) a fake efibootmgr whose listing LAGS N reads behind the create (each
#       of the first N listings after -c omits our entry) must PASS via the
#       bounded backoff, re-verifying the SAME label + GUID + loader match:
#       (a1) a lag of 7 reads — BEYOND the retired 5-attempt bound (the old
#            code fails this leg; the R640-shaped regression guard) — and
#       (a2) a lag of 2 reads — comfortably within the new bound;
#   (b) a fake that NEVER shows the entry still fails fail-closed 64, with the
#       die naming the NEW bound (10 attempts, ~50s) and firmware NVRAM write
#       latency (Dell) as the likely cause.
# The wrapper delegates to the base fake (state-file NVRAM) and filters its
# -v output — the approximation is the lag, not the parsed format.
# =============================================================================
cat >"$T/stub/efibootmgr-lagging" <<'EOF'
#!/bin/sh
# lagging fake: the first $NVRAM/lag-count -v reads after each -c omit our
# entry (a stale NVRAM view that outlives the retired 5-attempt bound)
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
            "$BASE" -v | grep -v 'Alpine FDE'
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
# never-shows fake: our entry NEVER appears in the -v listing
BASE=${ALPINE_FDE_EFIBOOTMGR_BASE}
case " $* " in
    *" -v "*)
        "$BASE" "$@" | grep -v 'Alpine FDE'
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
assert_rc "lag7 (beyond the retired 5-attempt bound): rc 0 via the raised retry" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_contains "lag7: the entry is created (not reused)" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_contains "lag7: the retry warned about NVRAM latency while waiting" "$ASSERT_RC_OUTPUT" "NVRAM write latency"
assert_contains "lag7: the warn names the raised attempt bound" "$ASSERT_RC_OUTPUT" "attempt 1/10"
assert_eq "lag7: the recovered entry pins the CURRENT GUID + is FIRST" "0001,0002" "$(cat "$NVRAM/order")"
assert_eq "lag7: the recovered entry carries the ESP's GUID" "1" "$(grep -c "^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]|$GUID|Alpine FDE" "$NVRAM/entries")"

# (a2) lag of 2 listings: lands WITHIN the new bound (the common shape)
FAKE_LAG_COUNT=2
reset_nvram '' '0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
assert_rc "lag2 (within the new bound): rc 0 via the retry" 0 inst_bootentry_ensure /dev/sda1 "$ESPDIR"
assert_contains "lag2: the entry is created (not reused)" "$ASSERT_RC_OUTPUT" "created boot entry"
assert_eq "lag2: the recovered entry is FIRST" "0001,0002" "$(cat "$NVRAM/order")"
FAKE_LAG_COUNT=

# (b) never-visible listing: fail-closed 64 with the latency clause
ALPINE_FDE_EFIBOOTMGR=$T/stub/efibootmgr-never
reset_nvram '' '0002'
printf '0002|99999999-8888-7777-6666-555555555555|Windows Boot Manager|\\EFI\\Microsoft\\bootmgfw.efi\n' >>"$NVRAM/entries"
OUT=$(inst_bootentry_ensure /dev/sda1 "$ESPDIR" 2>&1)
NEVER_RC=$?
assert_eq "never: rc 64 (still fail-closed, no entry-number guessing)" "64" "$NEVER_RC"
assert_contains "never: the die keeps the refuse-to-guess clause" "$OUT" "refusing to guess the entry number"
assert_contains "never: the die names NVRAM write latency (Dell) as the likely cause" "$OUT" "NVRAM write latency"
assert_contains "never: the die reports the RAISED bounded attempts" "$OUT" "after 10 attempts (~50s)"
assert_eq "never: the entry WAS created in the fake NVRAM (the write, not the read, succeeded)" "1" \
    "$(grep -c "^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]|$GUID|Alpine FDE" "$NVRAM/entries")"
assert_eq "never: BootOrder untouched (no guessing)" "0002" "$(cat "$NVRAM/order")"

ALPINE_FDE_EFIBOOTMGR=$SAVED_EB
ALPINE_FDE_BOOTENTRY_RETRY_SLEEP=

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
#    seal, before the teardown; efibootmgr pinned in the target package set.
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
    "$ALPINE_FDE_HOOKS_DIR/apk/triggers" "$ALPINE_FDE_HOOKS_DIR/conf.d" "$ALPINE_FDE_HOOKS_DIR/openrc" "$ALPINE_FDE_HOOKS_DIR/profile.d"
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
assert_contains "plan: the record probes require_pkgs efibootmgr:efibootmgr" "$OUT" \
    "require_pkgs efibootmgr:efibootmgr"
I_SEAL=$(line_no "$OUT" "seal_provisional")
I_ENTRY=$(line_no "$OUT" "inst_bootentry_ensure")
I_UMOUNT=$(line_no "$OUT" "umount $T/mnt/sys/firmware/efi/efivars 2>/dev/null || umount -l")
assert_eq "order: boot entry AFTER the provisional seal (loader staged)" "1" \
    "$(( I_SEAL > 0 && I_ENTRY > I_SEAL ? 1 : 0 ))"
assert_eq "order: boot entry BEFORE the teardown (chroot still sees the ESP)" "1" \
    "$(( I_UMOUNT > 0 && I_ENTRY < I_UMOUNT ? 1 : 0 ))"
assert_eq "package set: efibootmgr pinned (target delivery + mirror closure)" "1" \
    "$(install_package_list | tr ' ' '\n' | grep -cx 'efibootmgr')"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
