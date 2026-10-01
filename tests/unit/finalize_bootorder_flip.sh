#!/usr/bin/env bash
# tests/unit/finalize_bootorder_flip.sh — the SERIAL-FIRST flip-back on trust
# finalization. lib/cmd/install.sh orders the SERIAL UKI boot entry FIRST on
# serial-attached machines (the first boot's one recovery passphrase is read
# from /dev/console, which the default UKI binds to the video console — the
# "SERIAL-FIRST FIRST BOOT" note). Once fin_completion_steps SUCCEEDS the
# default UKI must lead again (video console = the richer operator surface):
# lib/cmd/finalize.sh _fin_bootorder_default_first re-writes BootOrder to
# default, serial, then every other entry in its existing relative order.
# Pins:
#   * the flip keys on kver + variant, NOT the label date — fixture labels
#     carry dates that differ from the kver on purpose;
#   * best-effort fail-open: a missing efibootmgr returns 0 QUIETLY (a
#     BootOrder that will not flip must never break finalization);
#   * an already-default-first BootOrder is still re-issued (idempotent -o,
#     keep-it-simple);
#   * with only the SERIAL entry present, the serial entry still leads.
# Hermetic: `uname` + `efibootmgr` stubs on PATH (the fake keeps its fixture
# entries + BootOrder in a state dir and logs every -o argument).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
source "$HERE/lib.sh"

. "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
. "$REPO/lib/cmd/finalize.sh"

T=$(mktemp -d /tmp/alpine-fde-bootorder.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

KVER=6.18.54-0-lts
export KVER

STUB=$T/stub
NVRAM=$T/nvram
mkdir -p "$STUB" "$NVRAM"
export NVRAM

# uname stub: the running kernel the entry labels must match; the fake
# efibootmgr keeps fixture entries + BootOrder in a state dir, rewrites the
# order on -o and records every csv it is given. make_stubs() is re-invoked
# by fixture() — the missing-efibootmgr leg deletes the stub and every later
# leg needs it back.
make_stubs() {
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$KVER" >"$STUB/uname"
    cat >"$STUB/efibootmgr" <<'EOF'
#!/bin/sh
printf 'efibootmgr %s\n' "$*" >>"$NVRAM/log"
case " $* " in
    *" -v "*)
        printf 'BootCurrent: 0003\nTimeout: 0 seconds\n'
        printf 'BootOrder: %s\n' "$(cat "$NVRAM/order")"
        while IFS='|' read -r num label; do
            [ -n "$num" ] || continue
            printf 'Boot%s* %s\tHD(1,GPT,11111111-2222-3333-4444-555555555555,0x800,0x100000)/File(\\EFI\\Linux\\alpine-fde.efi)\n' \
                "$num" "$label"
        done <"$NVRAM/entries"
        ;;
    *" -o "*)
        prev=''
        for a in "$@"; do
            case $prev in
                -o) printf '%s\n' "$a" >"$NVRAM/order_new" ;;
            esac
            prev=$a
        done
        cp "$NVRAM/order_new" "$NVRAM/order"
        ;;
esac
EOF
chmod +x "$STUB/uname" "$STUB/efibootmgr"
}
make_stubs

fixture() {
    make_stubs
    # dates differ from the kver ON PURPOSE: the flip keys on kver + variant
    printf '0000|Alpine FDE - %s (2026-10-01)\n' "$KVER" >"$NVRAM/entries"
    printf '0003|Alpine FDE - %s serial (2026-09-30)\n' "$KVER" >>"$NVRAM/entries"
    printf '0002|Windows Boot Manager\n' >>"$NVRAM/entries"
    printf '0004|UEFI: Built-in EFI Shell\n' >>"$NVRAM/entries"
    printf '%s\n' "${1:-0003,0000,0002,0004}" >"$NVRAM/order"
    rm -f "$NVRAM/order_new" "$NVRAM/log"
}

PATH="$STUB:$PATH"
export PATH

# --- leg 1: serial-first fixture flips to default-first -----------------------
fixture
_fin_bootorder_default_first
assert_rc "flip rc 0 on the healthy fixture" 0 $?
assert_eq "BootOrder re-written default,serial,then-others" \
    "0000,0003,0002,0004" "$(cat "$NVRAM/order_new" 2>/dev/null)"

# --- leg 2: missing efibootmgr -> quiet rc 0, nothing attempted ---------------
fixture
rm -f "$STUB/efibootmgr"
_fin_bootorder_default_first
assert_rc "missing efibootmgr is a quiet 0" 0 $?
assert_eq "missing efibootmgr issues no -o" "" "$(cat "$NVRAM/order_new" 2>/dev/null)"

# --- leg 3: already default-first is still re-issued (idempotent -o) ----------
fixture 0000,0003,0002,0004
_fin_bootorder_default_first
assert_rc "already-default-first rc 0" 0 $?
assert_eq "already-default-first still issues the -o" \
    "0000,0003,0002,0004" "$(cat "$NVRAM/order_new" 2>/dev/null)"

# --- leg 4: only the SERIAL entry exists -> it still leads --------------------
printf '0003|Alpine FDE - %s serial (2026-09-30)\n' "$KVER" >"$NVRAM/entries"
printf '0002|Windows Boot Manager\n' >>"$NVRAM/entries"
printf '%s\n' "0003,0002" >"$NVRAM/order"
rm -f "$NVRAM/order_new"
_fin_bootorder_default_first
assert_rc "serial-only fixture rc 0" 0 $?
assert_eq "serial-only entry still leads" "0003,0002" "$(cat "$NVRAM/order_new" 2>/dev/null)"

finish
