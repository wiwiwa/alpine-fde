#!/usr/bin/env bash
# tests/unit/install_qemu_emit.sh — `debian-fde install` qemu-runner contract
# (docs/Architecture.md §8.1, §9.1): DEBIAN_FDE_INSTALL_RUNNER=qemu with
# DEBIAN_FDE_INSTALL_SCRIPT=<tmpfile> emits the guest-side plan as a script
# without executing anything:
#   * `set -eu` (repo standard guard) + shebang header
#   * guest config writes as single-quote-escaped printf lines — crypttab and
#     apt policy VERBATIM (a broken escape loses trailing content, wave-1 bug)
#   * host steps emitted as comments (block layer, binds, metadata, state)
#   * the §9.1 in-chroot provisioning sequence appears as EXECUTABLE guest
#     lines (apt set, platform-key ceremony, NVRAM enrollment, bootctl,
#     ukictl build, keys_encrypt_release)
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
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export DEBIAN_FDE_INSTALL_SCRIPT=$T/guest-install.sh
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
export DEBIAN_FDE_INSTALL_NO_REBOOT=1   # CI seam: the harness reboots itself
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
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
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount debootstrap chroot \
    apt-get useradd usermod passwd systemctl bootctl lsblk btrfs cryptsetup; do
    make_stub "$s"
done
cat >"$T/stub/id" <<'EOF'   # pretend to be root (preflight check, never logged)
#!/bin/sh
printf '0\n'
EOF
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$DEBIAN_FDE_HOOKS_DIR" "$DEBIAN_FDE_EFIVARS_DIR"
for h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    printf '#!/bin/sh\nexit 0\n' >"$DEBIAN_FDE_HOOKS_DIR/$h"
    chmod +x "$DEBIAN_FDE_HOOKS_DIR/$h"
done
# §9.1 preflight: firmware in Setup Mode
printf '\007\000\000\000\001' >"$DEBIAN_FDE_EFIVARS_DIR/SetupMode-$GUID_GLOBAL"

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
assert_eq "crypttab line verbatim (§8.2, single topology: no password-cache)" \
    "printf '%s\n' 'root UUID=$LUKS_UUID none luks,tpm2-device=auto,discard' >/etc/crypttab" \
    "$(grep -F "none luks,tpm2-device=auto,discard' >/etc/crypttab" "$SCRIPT")"
assert_eq "apt policy lines verbatim incl. trailing content (wave-1 escape class)" \
    "printf '%s\n' 'APT::Install-Recommends \"false\";' 'APT::Install-Suggests \"false\";' 'Acquire::Languages \"none\";' >/etc/apt/apt.conf.d/90debian-fde" \
    "$(grep -F 'APT::Install-Recommends' "$SCRIPT")"
assert_eq "dracut conf verbatim (embedded double quotes survive)" \
    "printf '%s\n' 'hostonly=yes' 'hostonly_cmdline=no' 'omit_dracutmodules+=\" crypt \"' >/etc/dracut.conf.d/10-debian-fde.conf" \
    "$(grep -F 'omit_dracutmodules' "$SCRIPT")"
assert_contains "cmdline drop emitted with btrfs rootflags + fail-closed pins" "$(cat "$SCRIPT")" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
assert_eq "guest step emitted executable: apt-get update" "1" "$(grep -cx 'apt-get update' "$SCRIPT")"

# --- host steps are comments ------------------------------------------------------
assert_eq "host step emitted as comment: debootstrap" "1" \
    "$(grep -c '^# HOST: debootstrap --variant=minbase' "$SCRIPT")"
assert_eq "host step emitted as comment: sfdisk" "1" \
    "$(grep -c '^# HOST: .*sfdisk' "$SCRIPT")"
assert_eq "host step emitted as comment: mkfs.btrfs" "1" \
    "$(grep -c '^# HOST: .*mkfs.btrfs' "$SCRIPT")"
assert_eq "host step emitted as comment: luksFormat" "1" \
    "$(grep -c '^# HOST: .*luksFormat --type luks2' "$SCRIPT")"
assert_eq "host step emitted as comment: tree copy" "1" \
    "$(grep -c '^# HOST: .*cp -r .*opt/debian-fde' "$SCRIPT")"
assert_eq "host step emitted as comment: pending baseline on target (§9.1 step 2)" "1" \
    "$(grep -c '^# HOST: inst_baseline_pending_write' "$SCRIPT")"
assert_eq "host step emitted as comment: state write (§9.1 step 8)" "1" \
    "$(grep -c '^# HOST: inst_state_write installed' "$SCRIPT")"
assert_eq "host step emitted as comment: OsIndications (§9.1 teardown)" "1" \
    "$(grep -c '^# HOST: fw_osindications_set' "$SCRIPT")"
assert_eq "host teardown emitted as comment" "1" \
    "$(grep -c '^# HOST: .*cryptsetup close root-crypt' "$SCRIPT")"
assert_eq "no host step left executable" "0" \
    "$(grep -c '^debootstrap' "$SCRIPT")"
assert_eq "no reboot record (DEBIAN_FDE_INSTALL_NO_REBOOT=1 CI seam)" "0" \
    "$(grep -c '^# HOST: reboot' "$SCRIPT")"

# --- §9.1 in-chroot provisioning sequence: EXECUTABLE guest lines ----------------
assert_eq "guest: platform-key ceremony (§9.1 step 3, explicit keydir)" "1" \
    "$(grep -cx '/opt/debian-fde/bin/debian-fde provision stage1 --mode in-chroot --keydir /etc/debian-fde/keys' "$SCRIPT")"
assert_eq "guest: NVRAM enrollment db->KEK->PK (§9.1 step 4)" "1" \
    "$(grep -cx 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/debian-fde/keys' "$SCRIPT")"
assert_eq "guest: bootctl install (ESP layout)" "1" \
    "$(grep -cx 'bootctl install --esp-path=/efi --boot-path=/efi' "$SCRIPT")"
assert_eq "guest: ukictl build (§9.1 step 5)" "1" \
    "$(grep -cx '/opt/debian-fde/bin/debian-fde ukictl build' "$SCRIPT")"
assert_eq "guest: keys_encrypt_release (§9.1 step 6, cmd-dir + keydir)" "1" \
    "$(grep -cx 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/keys.sh && keys_encrypt_release /etc/debian-fde/keys' "$SCRIPT")"
# F1/F2 (cycle-2 gate): guest one-liners run in a FRESH chroot shell — the line
# exports the cmd dir BEFORE sourcing libs (floor/rotate resolution + die/info)
assert_eq "guest: keys line exports cmd-dir then sources libs" "1" \
    "$(grep -c 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && \. /opt/debian-fde/lib/keys\.sh && keys_encrypt_release /etc/debian-fde/keys' "$SCRIPT")"
assert_eq "guest: firmware line exports cmd-dir then sources libs" "1" \
    "$(grep -c 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && \. /opt/debian-fde/lib/firmware\.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/debian-fde/keys' "$SCRIPT")"
# order inside the emitted script: ceremony -> enrollment -> build -> encrypt
S_KEYGEN=$(grep -n 'provision stage1 --mode in-chroot' "$SCRIPT" | cut -d: -f1)
S_ENROLL=$(grep -n 'fw_auth_enroll' "$SCRIPT" | cut -d: -f1)
S_BUILD=$(grep -n 'ukictl build' "$SCRIPT" | cut -d: -f1)
S_ENCRYPT=$(grep -n 'keys_encrypt_release' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: keygen before enrollment" "1" "$(( S_KEYGEN < S_ENROLL ? 1 : 0 ))"
assert_eq "emitted order: enrollment before build" "1" "$(( S_ENROLL < S_BUILD ? 1 : 0 ))"
assert_eq "emitted order: build before encrypt" "1" "$(( S_BUILD < S_ENCRYPT ? 1 : 0 ))"

# --- emitted script is sound but NEVER executed -----------------------------------
assert_rc "emitted script parses (escape loop sound)" 0 sh -n "$SCRIPT"
assert_eq "nothing was executed (stub log empty)" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
assert_eq "target root untouched (no host step ran)" "0" "$([ -e "$DEBIAN_FDE_INSTALL_MNT" ] && echo 1 || echo 0)"

# --- H-02 binds emitted in the right lane ------------------------------------------
assert_eq "host step emitted as comment: /proc bind (H-02)" "1" \
    "$(grep -c '^# HOST: .*mount -t proc proc' "$SCRIPT")"
assert_eq "host step emitted as comment: efivars bind (§9.1)" "1" \
    "$(grep -c '^# HOST: .*mount --bind /sys/firmware/efi/efivars' "$SCRIPT")"
assert_eq "host step emitted as comment: bind teardown (H-02)" "1" \
    "$(grep -cF "# HOST: umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc" "$SCRIPT")"

# --- conf drop (§4 topology + CR-01) -------------------------------------------------
assert_contains "conf drop emitted: ROOT_FS=btrfs (§4)" "$(cat "$SCRIPT")" "ROOT_FS=btrfs"
assert_contains "conf drop emitted: BCACHE=0 (§4)" "$(cat "$SCRIPT")" "BCACHE=0"
assert_contains "conf drop emitted: ESP_PATH=/efi (CR-01)" "$(cat "$SCRIPT")" "ESP_PATH=/efi"

# --- permissions -------------------------------------------------------------------
assert_eq "emitted script chmod 700" "700" "$(stat -c '%a' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
