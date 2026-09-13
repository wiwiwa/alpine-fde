#!/usr/bin/env bash
# tests/unit/install_qemu_emit.sh — `debian-fde install` qemu-runner contract
# (docs/Architecture.md §8.1): DEBIAN_FDE_INSTALL_RUNNER=qemu with
# DEBIAN_FDE_INSTALL_SCRIPT=<tmpfile> emits the guest-side plan as a script
# without executing anything:
#   * `set -eu` (repo standard guard) + shebang header
#   * guest config writes as single-quote-escaped printf lines — crypttab and
#     apt policy VERBATIM (a broken escape loses trailing content, wave-1 bug)
#   * host steps emitted as comments
#   * the script is NOT executed (stub log stays empty) and is chmod 700
#
# Conventions (E2E-mock rule): real handler, stubbed collaborators, asserted
# files/argv/exit codes — never return values of internal helpers.

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

T=$(mktemp -d /tmp/debian-fde-install-qemu.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_INSTALL_RUNNER=qemu
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_HOOKS_DIR=$T/hooks
export DEBIAN_FDE_KEYDIR=$T/keys
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export DEBIAN_FDE_INSTALL_SCRIPT=$T/guest-install.sh
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'

DISK=$T/disk.img
: >"$DISK"
: >"$DEBIAN_FDE_TEST_LOG"

# --- stub collaborators: present for preflight, logging for the no-exec assert
mkdir -p "$T/stub"
make_stub() { # NAME — log argv, exit 0
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk cryptsetup mkfs.ext4 mkfs.vfat mount umount debootstrap chroot \
    apt-get useradd usermod passwd systemctl bootctl sbverify sbsign lsblk ukify; do
    make_stub "$s"
done
cat >"$T/stub/id" <<'EOF'   # pretend to be root (preflight check, never logged)
#!/bin/sh
printf '0\n'
EOF
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$DEBIAN_FDE_KEYDIR"
: >"$DEBIAN_FDE_KEYDIR/release.pem"
: >"$DEBIAN_FDE_KEYDIR/release.pub"
: >"$DEBIAN_FDE_KEYDIR/release.crt"

mkdir -p "$DEBIAN_FDE_HOOKS_DIR"
for h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done

BL_REQUIRED_PCR='1111111111111111111111111111111111111111111111111111111111111111'
BL_CREATED_AT='2026-09-17T00:00:00Z' \
    BL_PCR0="$BL_REQUIRED_PCR" BL_PCR1="$BL_REQUIRED_PCR" \
    BL_PCR2="$BL_REQUIRED_PCR" BL_PCR3="$BL_REQUIRED_PCR" \
    BL_PCR7='pending' \
    BL_KEYS_RELEASE_PUB_PATH="$DEBIAN_FDE_KEYDIR/release.pub" \
    BL_KEYS_RELEASE_CERT_PATH="$DEBIAN_FDE_KEYDIR/release.crt" \
    baseline_write "$(sp_baseline_file)"
assert_rc "fixture: baseline validates" 0 baseline_validate "$(sp_baseline_file)"

# --- run: emit the guest script -------------------------------------------------
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
RC=$?
SCRIPT=$DEBIAN_FDE_INSTALL_SCRIPT

assert_eq "qemu emit rc 0" "0" "$RC"
assert_file_exists "guest script written" "$SCRIPT"
assert_contains "stderr names the emitted script" "$OUT" "guest install script written: $SCRIPT"

# --- header: shebang + repo standard guard --------------------------------------
assert_eq "emitted script: shebang is first line" "#!/bin/sh" "$(head -n1 "$SCRIPT")"
assert_contains "emitted script: set -eu guard" "$(cat "$SCRIPT")" 'set -eu'

# --- guest config writes: verbatim single-quote-escaped printf lines ------------
LUKS_UUID=$(grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$SCRIPT" | head -1 | awk '{print $2}')
assert_eq "fixture: luksFormat comment pins an explicit uuid" "1" "$([ -n "$LUKS_UUID" ] && echo 1 || echo 0)"
assert_eq "crypttab line verbatim (§8.2)" \
    "printf '%s\n' 'root UUID=$LUKS_UUID none luks,tpm2-device=auto,discard' >/etc/crypttab" \
    "$(grep -F "none luks,tpm2-device=auto,discard' >/etc/crypttab" "$SCRIPT")"
assert_eq "apt policy lines verbatim incl. trailing content (wave-1 escape class)" \
    "printf '%s\n' 'APT::Install-Recommends \"false\";' 'APT::Install-Suggests \"false\";' 'Acquire::Languages \"none\";' >/etc/apt/apt.conf.d/90debian-fde" \
    "$(grep -F 'APT::Install-Recommends' "$SCRIPT")"
assert_eq "dracut conf verbatim (embedded double quotes survive)" \
    "printf '%s\n' 'hostonly=yes' 'hostonly_cmdline=no' 'omit_dracutmodules+=\" crypt \"' >/etc/dracut.conf.d/10-debian-fde.conf" \
    "$(grep -F 'omit_dracutmodules' "$SCRIPT")"
assert_eq "guest step emitted executable: apt-get update" "1" "$(grep -cx 'apt-get update' "$SCRIPT")"

# --- host steps are comments ------------------------------------------------------
assert_eq "host step emitted as comment: debootstrap" "1" \
    "$(grep -c '^# HOST: debootstrap --variant=minbase' "$SCRIPT")"
assert_eq "host step emitted as comment: sfdisk" "1" \
    "$(grep -c '^# HOST: .*sfdisk' "$SCRIPT")"
assert_eq "host step emitted as comment: tree copy" "1" \
    "$(grep -c '^# HOST: .*cp -r .*opt/debian-fde' "$SCRIPT")"
assert_eq "host teardown emitted as comment" "1" \
    "$(grep -c '^# HOST: .*cryptsetup close root-crypt' "$SCRIPT")"
assert_eq "no host step left executable" "0" \
    "$(grep -c '^debootstrap' "$SCRIPT")"

# --- emitted script is sound but NEVER executed -----------------------------------
assert_rc "emitted script parses (escape loop sound)" 0 sh -n "$SCRIPT"
assert_eq "nothing was executed (stub log empty)" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
assert_eq "target root untouched (no host step ran)" "0" "$([ -e "$DEBIAN_FDE_INSTALL_MNT" ] && echo 1 || echo 0)"

# --- H-02 / H-03 / CR-01: new plan steps are emitted in the right lanes ------------
# H-02: the proc/sys/dev binds are HOST steps (comments for the CI harness)
assert_eq "host step emitted as comment: /proc bind (H-02)" "1" \
    "$(grep -c '^# HOST: .*mount -t proc proc' "$SCRIPT")"
assert_eq "host step emitted as comment: bind teardown (H-02)" "1" \
    "$(grep -cF "# HOST: umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc" "$SCRIPT")"
# H-03: dracut runs IN the guest (executable line); ukify/sbsign are installer-env
# (host) steps — the signing key never enters the guest script as an executable line
assert_eq "guest step emitted executable: first-boot dracut (H-03)" "1" \
    "$(grep -c 'dracut --force --kver' "$SCRIPT")"
assert_eq "host step emitted as comment: first-boot ukify (H-03)" "1" \
    "$(grep -c '^# HOST: .*ukify build --linux' "$SCRIPT")"
assert_eq "host step emitted as comment: first-boot UKI sbsign (H-03)" "1" \
    "$(grep -cF "sbsign --key $DEBIAN_FDE_KEYDIR/release.pem --cert $DEBIAN_FDE_KEYDIR/release.crt --output $DEBIAN_FDE_INSTALL_MNT/efi/EFI/Linux/debian-fde-" "$SCRIPT")"
assert_eq "first-boot UKI carries the enter-initrd phase (H-03)" "1" \
    "$(grep -c '\--phase enter-initrd' "$SCRIPT")"
assert_eq "UKI lands in the §8.4 ESP layout (H-03)" "1" \
    "$(grep -c 'EFI/Linux/debian-fde-' "$SCRIPT")"
# CR-01: the resolved ESP mount is persisted into the target's debian-fde.conf
assert_eq "conf drop emitted: ESP_PATH=/efi (CR-01)" "1" \
    "$(grep -c "ESP_PATH=/efi" "$SCRIPT")"

# --- permissions -------------------------------------------------------------------
assert_eq "emitted script chmod 700" "700" "$(stat -c '%a' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
