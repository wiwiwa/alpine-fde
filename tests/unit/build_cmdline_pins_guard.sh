#!/usr/bin/env bash
# tests/unit/build_cmdline_pins_guard.sh — G-U6 (§8.2 H-G1; G-C9 resolution
# R10): the fail-closed cmdline pins rd.shell=0 rd.emergency=poweroff remain
# REQUIRED build inputs. On the Alpine/mkinitfs target the pins are inert
# defense-in-depth (mkinitfs processes no rd.* knobs): the "no shell after 3
# strikes, poweroff -f instead" guarantee is OWNED by the §8.2 Early-Boot
# Unseal Hook (tests/unit/hooks_mkinitfs_unseal.sh). The pins are still
# enforced because any rd.* knob consumer on the boot path must never see an
# emergency-shell escape hatch. A user-edited cmdline.txt missing a pin (or
# carrying an overriding duplicate — the effective value would be
# argument-order dependent) must fail the build closed (rc 64 + ADR-8 marker
# naming the pin, initramfs builder never invoked, ESP untouched).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}
assert_file_absent() {
    if [ ! -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file unexpectedly exists: $2)"
    fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- HW-2 direct legs: the guard rejects CONFLICTING knob occurrences, not just
# missing pins. `rd.shell=1 rd.shell=0` contains the pin as a standalone word but
# the effective value is dracut-getarg-order dependent — an override is morally
# identical to a removal and must fail closed (§8.2 H-G1).
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/initramfs.sh
source "$REPO/lib/initramfs.sh"

CP="$TMP/pins-direct.txt"
printf '%s\n' 'root=UUID=x rw rd.shell=1 rd.shell=0 rd.emergency=poweroff' >"$CP"
out=$(cmdline_pins_check "$CP" 2>&1); rc=$?
assert_rc "pins direct: rd.shell=1 overriding rd.shell=0 is rejected" 1 "$rc"
assert_contains "pins direct: override rejection names the conflicting word" "$out" "rd.shell=1"
assert_contains "pins direct: override rejection cites the guard" "$out" "cmdline pins guard"

printf '%s\n' 'rd.emergency=shell rd.emergency=poweroff rd.shell=0' >"$CP"
cmdline_pins_check "$CP" >/dev/null 2>&1
assert_rc "pins direct: rd.emergency=shell override is rejected" 1 $?

printf '%s\n' 'rd.shell=1 rd.shell=0' >"$CP"
cmdline_pins_check "$CP" >/dev/null 2>&1
assert_rc "pins direct: override without the emergency pin is rejected too" 1 $?

printf '%s\n' 'root=UUID=x rw rd.shell=0 rd.emergency=poweroff quiet' >"$CP"
cmdline_pins_check "$CP" >/dev/null 2>&1
assert_rc "pins direct: exact single pins still pass" 0 $?


KVER=6.12.8-1-amd64
ROOT="$TMP/root"
ESP="$TMP/esp"
CALLS="$TMP/initramfs.calls"
CMDLINE="$ROOT/etc/alpine-fde/cmdline.txt"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$CMDLINE"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
# compliant crypttab: the G-U4 guard owns that precondition; this file tests
# the cmdline pins guard (§8.2 H-G1) in isolation
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"

REC="$TMP/record-initramfs.sh"
cat >"$REC" <<EOF
#!/bin/sh
set -eu
[ \$# -eq 2 ] || exit 2
printf '%s\n' "\$2" >>'$CALLS'
printf 'stub initramfs for %s\n' "\$2" >"\$1"
EOF
chmod +x "$REC"

calls() {
    if [ -f "$CALLS" ]; then
        wc -l <"$CALLS" | tr -d '[:space:]'
    else
        printf '0'
    fi
}

build() {
    env DEBIAN_FDE_BIN_TEST=1 DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_ESP="$ESP" \
        DEBIAN_FDE_KEYDIR="$REPO/fixtures/keys" DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
        INITRAMFS_CMD="$REC {out} {kver}" \
        RETENTION=1 \
        "$REPO/bin/debian-fde" ukictl build "$KVER" >/dev/null 2>&1
}

# --- 1. rd.shell=0 stripped ----------------------------------------------------------
printf '%s\n' 'root=UUID=00000000-0000-0000-0000-000000000000 rw rd.emergency=poweroff' >"$CMDLINE"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "pins 1: missing rd.shell=0 fails closed (64)" 64 $?
assert_contains "pins 1: marker names the missing pin" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "rd.shell=0"
assert_eq "pins 1: initramfs builder never invoked" "0" "$(calls)"
assert_eq "pins 1: no ESP mutation" "" "$(find "$ESP" -type f -name '*.efi' -print)"

# --- 2. rd.emergency=poweroff stripped ------------------------------------------------
printf '%s\n' 'root=UUID=00000000-0000-0000-0000-000000000000 rw rd.shell=0' >"$CMDLINE"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "pins 2: missing rd.emergency=poweroff fails closed (64)" 64 $?
assert_contains "pins 2: marker names the missing pin" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "rd.emergency=poweroff"
assert_eq "pins 2: initramfs builder never invoked" "0" "$(calls)"

# --- 3. pin embedded inside a longer token must NOT count ------------------------------
printf '%s\n' 'root=UUID=00000000-0000-0000-0000-000000000000 rw xrd.shell=0 rd.emergency=poweroff' >"$CMDLINE"
rm -f "$CALLS"
build
assert_rc "pins 3: glued-in rd.shell=0 lookalike is not a pin" 64 $?
assert_eq "pins 3: initramfs builder never invoked" "0" "$(calls)"

# --- 4. both pins present -> build proceeds ---------------------------------------------
cp "$REPO/fixtures/uki/cmdline.txt" "$CMDLINE"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
build
assert_rc "pins 4: pinned cmdline lets the build succeed" 0 $?
assert_eq "pins 4: initramfs builder invoked at least once" "1" "$(calls)"
assert_file_exists "pins 4: UKI installed" "$ESP/EFI/Linux/alpine-fde-$KVER.efi"
assert_file_absent "pins 4: failure marker cleared" "$ROOT/etc/alpine-fde/build-failed"

# --- 5. overriding duplicate pin must NOT pass (HW-2) ----------------------------------
printf '%s\n' 'root=UUID=00000000-0000-0000-0000-000000000000 rw rd.shell=1 rd.shell=0 rd.emergency=poweroff' >"$CMDLINE"
rm -f "$CALLS" "$ROOT/etc/alpine-fde/build-failed"
ESP_BEFORE5=$(find "$ESP" -type f -name '*.efi' -print | sort)
build
assert_rc "pins 5: conflicting rd.shell=1 override fails the build closed (64)" 64 $?
assert_contains "pins 5: marker names the override" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed" 2>/dev/null)" "rd.shell=1"
assert_eq "pins 5: initramfs builder never invoked" "0" "$(calls)"
assert_eq "pins 5: no ESP mutation" "$ESP_BEFORE5" "$(find "$ESP" -type f -name '*.efi' -print | sort)"

# --- 6. emergency-shell value override (same class) -------------------------------------
printf '%s\n' 'root=UUID=00000000-0000-0000-0000-000000000000 rw rd.shell=0 rd.emergency=shell rd.emergency=poweroff' >"$CMDLINE"
rm -f "$CALLS"
build
assert_rc "pins 6: rd.emergency=shell override fails closed (64)" 64 $?
assert_eq "pins 6: initramfs builder never invoked" "0" "$(calls)"

finish
