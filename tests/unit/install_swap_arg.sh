#!/usr/bin/env bash
# tests/unit/install_swap_arg.sh — ADR-7 amended (task 4): `install --swap`
# argument contract over lib/cmd/install.sh:
#   1. inst_swap_size_check accepts digits+K/M/G/T (either case) and FAILS
#      CLOSED with the usage exit code (rc 2) on garbage, on bare numbers
#      (ambiguous unit — the sfdisk MiB arithmetic must never misread it) and
#      on empty;
#   2. inst_swap_size resolves the 4G default when no size was given;
#   3. inst_size_mib normalizes suffixed sizes to whole MiB (the unit the
#      swap-partition sfdisk arithmetic computes in);
#   4. the subcommand-level `--swap` flag parses BOTH spellings — bare
#      `--swap` (default size) and `--swap 8G` — INCLUDING when another flag
#      follows (`--swap --disk X` must consume the default, never eat
#      `--disk`), and the dispatcher's global `--swap` (env ALPINE_FDE_SWAP,
#      '1' or a size) is consumed the same way;
#   5. absent --swap: INST_SWAP stays 0 and the emitted plan (the qemu
#      emission shape — item 17d retired the dry-run plan printer) carries
#      NO swap records at all (no swap partition, no dmcrypt drop, no fstab
#      swap line, no cryptsetup-openrc in the txn) — the ADR-7 default is
#      still "no disk swap".
# Executed-record level pins (dmcrypt drop, fstab line on the real target
# tree) live in tests/integration/install_chroot_plan.sh; full emission pins in
# tests/integration/install_dryrun.sh.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/install.sh
. "$ALPINE_FDE_CMD_DIR/install.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
: >"$TMP/disk.img"

# --- 1. inst_swap_size_check: valid forms --------------------------------------
for good in 4G 512M 2T 2048K 4g 512m 8192M 1T; do
    inst_swap_size_check "$good"
    assert_rc "swap size check accepts '$good'" 0 "$?"
done

# --- 2. inst_swap_size_check: garbage fails closed with the usage rc -----------
for bad in banana '' 12 '4G; reboot' '$(reboot)' G 4X 4GG '-4G' ' 4G'; do
    RC=0
    (inst_swap_size_check "$bad") 2>/dev/null || RC=$?
    assert_eq "swap size check rejects '$bad' with the usage rc 2" "2" "$RC"
done

# --- 3. default size ------------------------------------------------------------
assert_eq "swap size: unset INST_SWAP_SIZE resolves the 4G default" "4G" \
    "$(INST_SWAP_SIZE='' inst_swap_size)"
assert_eq "swap size: an explicit size wins over the default" "8G" \
    "$(INST_SWAP_SIZE=8G inst_swap_size)"

# --- 4. inst_size_mib normalization (the sfdisk arithmetic unit) ----------------
assert_eq "size mib: 4G -> 4096" "4096" "$(inst_size_mib 4G)"
assert_eq "size mib: 512M -> 512" "512" "$(inst_size_mib 512M)"
assert_eq "size mib: 2T -> 2097152" "2097152" "$(inst_size_mib 2T)"
assert_eq "size mib: 2048K -> 2" "2" "$(inst_size_mib 2048K)"
assert_eq "size mib: 1g (lowercase) -> 1024" "1024" "$(inst_size_mib 1g)"
inst_size_mib banana >/dev/null 2>&1
assert_rc "size mib: garbage -> rc 1" 1 "$?"

# --- 5. subcommand flag parsing (qemu-emission CLI; no execution) ---------------
# Item 17d: the dry-run runner is retired — these CLI-parse legs drive the
# qemu emission lane instead (still no execution; the preflight runs, so the
# collaborators are stubbed exactly like tests/unit/install_osindications.sh).
export ALPINE_FDE_INSTALL_RUNNER=qemu
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$TMP/mnt
export ALPINE_FDE_TMPDIR=$TMP
export ALPINE_FDE_INSTALL_SCRIPT=$TMP/guest.sh
export ALPINE_FDE_EFIVARS_DIR=$TMP/efivars
mkdir -p "$TMP/stub" "$TMP/efivars" "$TMP/hooks"/kernel-hooks.d "$TMP/hooks"/mkinitfs/features.d \
    "$TMP/hooks/apk/triggers" "$TMP/hooks/openrc" "$TMP/hooks/profile.d"
make_stub() {
    printf '#!/bin/sh\nexit 0\n' >"$TMP/stub/$1"
    chmod +x "$TMP/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount apk adduser addgroup rc-update cert-to-efi-sig-list sign-efi-sig-list \
    lsblk btrfs cryptsetup; do
    make_stub "$s"
done
printf '#!/bin/sh\ncase " $* " in *" rand "*) printf "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";; esac\nexit 0\n' >"$TMP/stub/openssl"
chmod +x "$TMP/stub/openssl"
printf '#!/bin/sh\nprintf "0\\n"\n' >"$TMP/stub/id"
chmod +x "$TMP/stub/id"
export PATH="$TMP/stub:$PATH"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    mkinitfs/features.d/alpine-fde.modules \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize \
    openrc/alpine-fde-audit profile.d/alpine-fde.sh; do
    printf '#!/bin/sh\nexit 0\n' >"$TMP/hooks/$h"
    chmod +x "$TMP/hooks/$h"
done
printf '\007\000\000\000\001' >"$TMP/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"

run_swap_install() { # args... -> SWAP_OUT (stderr + emitted plan) / SWAP_RC
    rm -f "$ALPINE_FDE_INSTALL_SCRIPT"
    SWAP_OUT=$(ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
        "$REPO/bin/alpine-fde" install "$@" 2>&1)
    SWAP_RC=$?
    SWAP_OUT="$SWAP_OUT
$(cat "$ALPINE_FDE_INSTALL_SCRIPT" 2>/dev/null || :)"
}

# bare --swap: default size, plan present
run_swap_install --disk "$TMP/disk.img" --swap
assert_eq "--swap (bare): emission rc 0" "0" "$SWAP_RC"
assert_contains "--swap (bare): plan info names the default 4G" "$SWAP_OUT" "swap=4G"
assert_contains "--swap (bare): sfdisk carries a 4096M swap partition" "$SWAP_OUT" \
    'name="swap", size=+4096M'
# --swap 8G: explicit size
run_swap_install --disk "$TMP/disk.img" --swap 8G
assert_eq "--swap 8G: emission rc 0" "0" "$SWAP_RC"
assert_contains "--swap 8G: sfdisk carries an 8192M swap partition" "$SWAP_OUT" \
    'name="swap", size=+8192M'
assert_contains "--swap 8G: plan info names the size" "$SWAP_OUT" "swap=8G"
# --swap followed by another flag: the flag is NOT eaten as the size
run_swap_install --swap --disk "$TMP/disk.img"
assert_eq "--swap --disk: emission rc 0 (the next flag was not eaten)" "0" "$SWAP_RC"
assert_contains "--swap --disk: default size still applied" "$SWAP_OUT" "swap=4G"
# garbage size: fail-closed 2 BEFORE any plan record
run_swap_install --disk "$TMP/disk.img" --swap banana
assert_eq "--swap banana: usage rc 2" "2" "$SWAP_RC"
assert_contains "--swap banana: error names the size format" "$SWAP_OUT" \
    "K/M/G/T suffix"
run_swap_install --disk "$TMP/disk.img" --swap '4G; reboot'
assert_eq "--swap '4G; reboot': usage rc 2 (M-02: shell metacharacters never reach a record)" "2" "$SWAP_RC"

# --- 6. dispatcher global --swap (env ALPINE_FDE_SWAP) ---------------------------
SWAP_OUT=$(ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
    ALPINE_FDE_SWAP=1 "$REPO/bin/alpine-fde" install --disk "$TMP/disk.img" 2>&1)
SWAP_OUT="$SWAP_OUT
$(cat "$ALPINE_FDE_INSTALL_SCRIPT" 2>/dev/null || :)"
assert_contains "global --swap=1 (bare flag env): default 4G" "$SWAP_OUT" "swap=4G"
SWAP_OUT=$(ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
    ALPINE_FDE_SWAP=2G "$REPO/bin/alpine-fde" install --disk "$TMP/disk.img" 2>&1)
SWAP_OUT="$SWAP_OUT
$(cat "$ALPINE_FDE_INSTALL_SCRIPT" 2>/dev/null || :)"
assert_contains "global --swap=2G (sized env): 2G partition" "$SWAP_OUT" \
    'name="swap", size=+2048M'
ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
    ALPINE_FDE_SWAP=banana "$REPO/bin/alpine-fde" install --disk "$TMP/disk.img" >/dev/null 2>&1
assert_eq "global --swap=banana (garbage env): usage rc 2" "2" "$?"
# the dispatcher global flag itself parses both spellings — bare --swap right
# before the subcommand must NOT eat the subcommand word (it is not size-shaped)
SWAP_OUT=$(ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
    "$REPO/bin/alpine-fde" --swap install 2>&1)
assert_eq "dispatcher: bare global --swap + subcommand -> install runs (rc 2 = the missing --disk usage error, never 'no subcommand')" "2" "$?"
assert_contains "dispatcher: bare global --swap did not eat the subcommand word" "$SWAP_OUT" \
    "no target disk"
SWAP_OUT=$(ALPINE_FDE_HOOKS_DIR="$TMP/hooks" \
    "$REPO/bin/alpine-fde" --swap 2G install 2>&1)
assert_contains "dispatcher: global --swap 2G consumes the size and still reaches install" "$SWAP_OUT" \
    "no target disk"

# --- 7. absent --swap: zero swap records ----------------------------------------
run_swap_install --disk "$TMP/disk.img"
assert_eq "no swap: INST_SWAP resolves 0" "0" "$(inst_swap_enabled)"
assert_contains "no swap: plan info says swap=none" "$SWAP_OUT" "swap=none"
assert_eq "no swap: ZERO swap partitions in sfdisk" "0" \
    "$(grep -c 'name="swap"' <<<"$SWAP_OUT")"
assert_eq "no swap: ZERO dmcrypt records" "0" "$(grep -c 'dmcrypt' <<<"$SWAP_OUT")"
assert_eq "no swap: ZERO fstab swap lines" "0" \
    "$(grep -c 'none swap defaults' <<<"$SWAP_OUT")"
assert_eq "no swap: NO cryptsetup-openrc in the apk txn" "0" \
    "$(grep -c 'cryptsetup-openrc' <<<"$SWAP_OUT")"
assert_eq "no swap: crypttab write carries NO swap entry (the initramfs-spliced file must never learn the swap)" "0" \
    "$(grep -F '>/etc/crypttab' <<<"$SWAP_OUT" | grep -c 'swap')"

# --- 8. package list: cryptsetup-openrc only with --swap (failure-#2 guard) -----
INST_SWAP=0 PKG_NO_SWAP=$(install_package_list)
INST_SWAP=1 PKG_SWAP=$(install_package_list)
case " $PKG_NO_SWAP " in
    *cryptsetup-openrc*) assert_eq "package list (no --swap) has NO cryptsetup-openrc" "0" "1" ;;
    *) assert_eq "package list (no --swap) has NO cryptsetup-openrc" "0" "0" ;;
esac
case " $PKG_SWAP " in
    *cryptsetup-openrc*) assert_eq "package list (--swap) contains cryptsetup-openrc (the dmcrypt service provider)" "1" "1" ;;
    *) assert_eq "package list (--swap) contains cryptsetup-openrc (the dmcrypt service provider)" "1" "0" ;;
esac

finish
