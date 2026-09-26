#!/usr/bin/env bash
# tests/unit/install_preflight_setupmode.sh — G-IL2 (docs/Architecture.md §9.1
# Stage-1 preflight, UserGuide §1): `install` must gate on firmware Setup Mode
# BEFORE ANY disk mutation:
#   * inst_preflight's FIRST check is the firmware SetupMode==1 gate
#     (fw_sb_state over the ALPINE_FDE_EFIVARS_DIR seam)
#   * SetupMode=0        ⇒ fail-closed 64, "clear vendor PK in BIOS" guidance,
#                          ZERO plan records (no destructive command executed)
#   * SetupMode=1        ⇒ proceed — the full ADR-20 unattended plan runs
#                          under stubs: G-C23 ephemeral key, G-C25 NO banner
#                          (ADR-20 #4: the banner path is removed — /etc/motd
#                          and /etc/issue stay untouched), state `installed`,
#                          G-C26 (no OsIndications)
#   * absent efivars     ⇒ fail-closed 64
#   * SetupMode variable absent (attrs-only/missing) ⇒ fail-closed 64
#   * the §13 passphrase-floor preflight step is RETIRED (the floor moved into
#     the §9.1 step-4 credential ceremony — ADR-20 amended); the ceremony
#     prompts are fed from an ANSWERS FILE on stdin (the documented test/CI
#     seam — no flag, no credential env var)

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

T=$(mktemp -d /tmp/alpine-fde-install-setupmode.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_INSTALL_NO_REBOOT=1
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
DISK=$T/disk.img
: >"$DISK"

# --- stub collaborators (log argv, exit 0) -------------------------------------
mkdir -p "$T/stub"
make_stub() { # NAME
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"$ALPINE_FDE_TEST_LOG"
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
printf 'lsblk %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' '5f2a9b01-02' ;;
esac
exit 0
EOF
chmod +x "$T/stub/lsblk"
# openssl: deterministic 256-bit hex body (G-C23 ephemeral key); pkcs8/asn1parse
# emulate the ADR-18 PKCS#8 envelope so the §9.1 step-4 release-key ceremony
# (keys_encrypt_release) runs for real — same emulation install_chroot_plan uses.
MARKER='fake-pbes2-encrypted-ADR18'
export MARKER
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
printf 'openssl %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
case " $* " in
    *" rand "*) printf 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' ;;
    *" asn1parse "*)
        in=''
        prev=''
        for a in "$@"; do
            [ "$prev" = "-in" ] && in=$a
            prev=$a
        done
        if [ -f "$in" ] && grep -q "$MARKER" "$in" 2>/dev/null; then
            printf '    0:d=0 hl=4 l= 828 cons: SEQUENCE\n    4:d=1 hl=2 l= 61 cons: SEQUENCE\n    6:d=2 hl=2 l= 9 prim: OBJECT :PBES2\n   17:d=2 hl=2 l= 48 cons: SEQUENCE\n   19:d=3 hl=2 l= 25 cons: SEQUENCE\n   21:d=4 hl=2 l= 9 prim: OBJECT :PBKDF2\n   43:d=4 hl=2 l= 14 cons: SEQUENCE\n   45:d=5 hl=2 l= 8 prim: OCTET STRING\n   55:d=5 hl=2 l= 2 prim: INTEGER :0927C0\n   59:d=3 hl=2 l= 13 cons: SEQUENCE\n   61:d=4 hl=2 l= 8 prim: OBJECT :hmacWithSHA256\n   77:d=2 hl=2 l= 27 cons: SEQUENCE\n   79:d=3 hl=2 l= 9 prim: OBJECT :aes-256-cbc\n'
        else
            exit 1
        fi
        ;;
    *" pkcs8 "*)
        in=''
        out=''
        prev=''
        for a in "$@"; do
            [ "$prev" = "-in" ] && in=$a
            [ "$prev" = "-out" ] && out=$a
            prev=$a
        done
        if [ -n "$out" ]; then
            printf '%s\n' "$MARKER" >"$out"
            [ -f "$in" ] && cat "$in" >>"$out"
        fi
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/openssl"
# cryptsetup: log only (no key-file existence check needed here)
make_stub cryptsetup
# chroot: when the guest line is the §9.1 step-3 platform-key ceremony, leave
# the UNencrypted release.pem it generates on the target — the input the §9.1
# step-4 credential ceremony (3/3) encrypts (same emulation install_chroot_plan
# uses; the generic log-only stub would leave nothing for the ceremony).
cat >"$T/stub/chroot" <<EOF
#!/bin/sh
printf '%s %s\n' "chroot" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
case "\$*" in
    *"provision stage1"*)
        mkdir -p "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys"
        printf -- '-----BEGIN PRIVATE KEY-----\nfake-plaintext-release-key\n-----END PRIVATE KEY-----\n' \\
            >"$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem"
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/chroot"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$ALPINE_FDE_HOOKS_DIR/kernel-hooks.d" "$ALPINE_FDE_HOOKS_DIR/mkinitfs/features.d" \
    "$ALPINE_FDE_HOOKS_DIR/apk/triggers" "$ALPINE_FDE_HOOKS_DIR/openrc"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    printf '#!/bin/sh\nexit 0\n' >"$ALPINE_FDE_HOOKS_DIR/$h"
    chmod +x "$ALPINE_FDE_HOOKS_DIR/$h"
done

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$ALPINE_FDE_EFIVARS_DIR/$1-$GUID_GLOBAL"
}

# §9.1 step-4 credential-ceremony answers (the documented test/CI seam), in
# the item-12 AMENDED order: the recovery passphrase is asked FIRST (lines 1-2,
# confirm-typed, §13 floor); the account password (2/3) and the release-key
# passphrase (3/3) DEFAULT to the recovery passphrase on bare Enter (lines 3-4
# are empty).
ANSWERS=$T/answers
cat >"$ANSWERS" <<'EOF'
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz


EOF

run_install() {
    : >"$ALPINE_FDE_TEST_LOG"
    rm -rf "$ALPINE_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1 <"$ANSWERS")
    RC=$?
}

# =============================================================================
# SetupMode=0 -> fail-closed 64 BEFORE any disk mutation (zero plan records)
# =============================================================================
mkdir -p "$ALPINE_FDE_EFIVARS_DIR"
mkvar SetupMode 0

run_install
assert_eq "SetupMode=0 -> fail-closed 64" "64" "$RC"
assert_contains "SetupMode=0: error says what to fix" "$OUT" "clear the vendor PK in BIOS"
assert_contains "SetupMode=0: error reports the observed state" "$OUT" "setup_mode=0"
assert_eq "SetupMode=0: ZERO destructive commands executed" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
assert_eq "SetupMode=0: mountpoint never created" "0" \
    "$([ -e "$ALPINE_FDE_INSTALL_MNT" ] && echo 1 || echo 0)"

# =============================================================================
# FIRST check: the SetupMode gate fires before every other preflight check —
# even with a target disk that would independently fail the disk check.
# =============================================================================
: >"$ALPINE_FDE_TEST_LOG"
OUT=$("$REPO/bin/alpine-fde" install --disk "$T/does-not-exist.img" 2>&1 </dev/null)
RC=$?
assert_eq "ordering: bad disk + SetupMode=0 -> still the SetupMode 64" "64" "$RC"
assert_contains "ordering: SetupMode gate is FIRST (disk check not reached)" "$OUT" \
    "clear the vendor PK in BIOS"
assert_not_contains "ordering: disk-not-found is NOT the reported failure" "$OUT" \
    "target disk not found"

# =============================================================================
# absent efivars / absent SetupMode variable -> fail-closed 64
# =============================================================================
rm -rf "$ALPINE_FDE_EFIVARS_DIR"
run_install
assert_eq "absent efivars dir -> fail-closed 64" "64" "$RC"
assert_contains "absent efivars: error explains" "$OUT" "efivars"
assert_eq "absent efivars: ZERO destructive commands" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"

mkdir -p "$ALPINE_FDE_EFIVARS_DIR" # dir exists, SetupMode variable absent
run_install
assert_eq "SetupMode variable absent -> fail-closed 64" "64" "$RC"
assert_eq "SetupMode variable absent: ZERO destructive commands" "0" \
    "$(wc -l <"$ALPINE_FDE_TEST_LOG")"

# =============================================================================
# SetupMode=1 -> proceed: the full ADR-20 unattended plan runs under stubs
# =============================================================================
mkvar SetupMode 1

run_install
assert_eq "SetupMode=1 -> chroot install rc 0 (unattended)" "0" "$RC"
assert_contains "SetupMode=1: partitioning ran" "$(cat "$ALPINE_FDE_TEST_LOG")" "sfdisk"
assert_contains "SetupMode=1: luksFormat ran (ephemeral keyslot 0, G-C23)" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "luksFormat"
assert_eq "SetupMode=1: NO MOTD banner written (G-C25, ADR-20 #4: banner path removed)" "0" \
    "$([ -e "$ALPINE_FDE_INSTALL_MNT/etc/motd" ] && echo 1 || echo 0)"
assert_eq "SetupMode=1: /etc/issue untouched (ADR-20 #4)" "0" \
    "$([ -e "$ALPINE_FDE_INSTALL_MNT/etc/issue" ] && echo 1 || echo 0)"
assert_file_exists "SetupMode=1: install-state written" \
    "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/install-state.json"
assert_contains "SetupMode=1: state=installed" \
    "$(cat "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/install-state.json")" '"installed"'
assert_eq "SetupMode=1: NO OsIndications write (G-C26)" "0" \
    "$(find "$ALPINE_FDE_EFIVARS_DIR" -name 'OsIndications-*' 2>/dev/null | wc -l)"
assert_not_contains "SetupMode=1: NO interactive disk-passphrase prompt (retired; the ceremony is the only credential seam)" "$OUT" \
    "Set disk encryption passphrase"

# =============================================================================
# Exhausted stdin at the ceremony is FAIL-CLOSED (EOF): die 64 with the
# explicit EOF message — no bounded-attempt wording, no unbounded re-prompt.
# =============================================================================
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1 </dev/null)
RC=$?
assert_eq "exhausted stdin (EOF) -> fail-closed 64" "64" "$RC"
assert_contains "exhausted stdin: the EOF fail-closed message" "$OUT" \
    "end of input while waiting for a credential prompt (EOF)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
