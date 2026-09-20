#!/usr/bin/env bash
# tests/unit/install_preflight_setupmode.sh — G-IL2 (docs/Architecture.md §9.1
# Stage-1 preflight, UserGuide §1): `install` must gate on firmware Setup Mode
# BEFORE ANY disk mutation:
#   * inst_preflight's FIRST check is the firmware SetupMode==1 gate
#     (fw_sb_state over the DEBIAN_FDE_EFIVARS_DIR seam)
#   * SetupMode=0        ⇒ fail-closed 64, "clear vendor PK in BIOS" guidance,
#                          ZERO plan records (no destructive command executed)
#   * SetupMode=1        ⇒ proceed — the full ADR-20 unattended plan runs
#                          under stubs: G-C23 ephemeral key, G-C25 banner,
#                          state `installed`, G-C26 (no OsIndications)
#   * absent efivars     ⇒ fail-closed 64
#   * SetupMode variable absent (attrs-only/missing) ⇒ fail-closed 64
#   * the §13 passphrase-floor preflight step is RETIRED (the floor moved to
#     finalize — ADR-20); the run is unattended end to end

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/debian-fde-install-setupmode.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_HOOKS_DIR=$T/hooks
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T
export DEBIAN_FDE_TEST_LOG=$T/cmd.log
export DEBIAN_FDE_INSTALL_NO_REBOOT=1
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
DISK=$T/disk.img
: >"$DISK"

# --- stub collaborators (log argv, exit 0) -------------------------------------
mkdir -p "$T/stub"
make_stub() { # NAME
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"$DEBIAN_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount apk adduser addgroup rc-update \
    bootctl lsblk btrfs reboot chroot; do
    make_stub "$s"
done
cat >"$T/stub/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
chmod +x "$T/stub/id"
# lsblk: report the canned ESP PARTUUID for `-no PARTUUID <dev>`
cat >"$T/stub/lsblk" <<'EOF'
#!/bin/sh
printf 'lsblk %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' '5f2a9b01-02' ;;
esac
exit 0
EOF
chmod +x "$T/stub/lsblk"
# openssl: deterministic 256-bit hex body (G-C23 ephemeral key)
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
printf 'openssl %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
case " $* " in
    *" rand "*) printf 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' ;;
esac
exit 0
EOF
chmod +x "$T/stub/openssl"
# cryptsetup: log only (no key-file existence check needed here)
make_stub cryptsetup
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$DEBIAN_FDE_HOOKS_DIR/kernel-hooks.d" "$DEBIAN_FDE_HOOKS_DIR/mkinitfs/features.d" \
    "$DEBIAN_FDE_HOOKS_DIR/apk/triggers" "$DEBIAN_FDE_HOOKS_DIR/openrc"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$DEBIAN_FDE_EFIVARS_DIR/$1-$GUID_GLOBAL"
}

run_install() {
    : >"$DEBIAN_FDE_TEST_LOG"
    rm -rf "$DEBIAN_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1 </dev/null)
    RC=$?
}

# =============================================================================
# SetupMode=0 -> fail-closed 64 BEFORE any disk mutation (zero plan records)
# =============================================================================
mkdir -p "$DEBIAN_FDE_EFIVARS_DIR"
mkvar SetupMode 0

run_install
assert_eq "SetupMode=0 -> fail-closed 64" "64" "$RC"
assert_contains "SetupMode=0: error says what to fix" "$OUT" "clear the vendor PK in BIOS"
assert_contains "SetupMode=0: error reports the observed state" "$OUT" "setup_mode=0"
assert_eq "SetupMode=0: ZERO destructive commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
assert_eq "SetupMode=0: mountpoint never created" "0" \
    "$([ -e "$DEBIAN_FDE_INSTALL_MNT" ] && echo 1 || echo 0)"

# =============================================================================
# FIRST check: the SetupMode gate fires before every other preflight check —
# even with a target disk that would independently fail the disk check.
# =============================================================================
: >"$DEBIAN_FDE_TEST_LOG"
OUT=$("$REPO/bin/debian-fde" install --disk "$T/does-not-exist.img" 2>&1 </dev/null)
RC=$?
assert_eq "ordering: bad disk + SetupMode=0 -> still the SetupMode 64" "64" "$RC"
assert_contains "ordering: SetupMode gate is FIRST (disk check not reached)" "$OUT" \
    "clear the vendor PK in BIOS"
assert_not_contains "ordering: disk-not-found is NOT the reported failure" "$OUT" \
    "target disk not found"

# =============================================================================
# absent efivars / absent SetupMode variable -> fail-closed 64
# =============================================================================
rm -rf "$DEBIAN_FDE_EFIVARS_DIR"
run_install
assert_eq "absent efivars dir -> fail-closed 64" "64" "$RC"
assert_contains "absent efivars: error explains" "$OUT" "efivars"
assert_eq "absent efivars: ZERO destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

mkdir -p "$DEBIAN_FDE_EFIVARS_DIR" # dir exists, SetupMode variable absent
run_install
assert_eq "SetupMode variable absent -> fail-closed 64" "64" "$RC"
assert_eq "SetupMode variable absent: ZERO destructive commands" "0" \
    "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

# =============================================================================
# SetupMode=1 -> proceed: the full ADR-20 unattended plan runs under stubs
# =============================================================================
mkvar SetupMode 1

run_install
assert_eq "SetupMode=1 -> chroot install rc 0 (unattended)" "0" "$RC"
assert_contains "SetupMode=1: partitioning ran" "$(cat "$DEBIAN_FDE_TEST_LOG")" "sfdisk"
assert_contains "SetupMode=1: luksFormat ran (ephemeral keyslot 0, G-C23)" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "luksFormat"
assert_file_exists "SetupMode=1: MOTD banner dropped (G-C25)" \
    "$DEBIAN_FDE_INSTALL_MNT/etc/motd"
assert_contains "SetupMode=1: MOTD banner says NOT finalized" \
    "$(cat "$DEBIAN_FDE_INSTALL_MNT/etc/motd")" "NOT finalized"
assert_file_exists "SetupMode=1: install-state written" \
    "$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/install-state.json"
assert_contains "SetupMode=1: state=installed" \
    "$(cat "$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/install-state.json")" '"installed"'
assert_eq "SetupMode=1: NO OsIndications write (G-C26)" "0" \
    "$(find "$DEBIAN_FDE_EFIVARS_DIR" -name 'OsIndications-*' 2>/dev/null | wc -l)"
assert_not_contains "SetupMode=1: NO passphrase-floor prompt (retired to finalize)" "$OUT" \
    "entropy floor"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
