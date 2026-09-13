#!/usr/bin/env bash
# tests/unit/install_chroot_plan.sh — `debian-fde install` chroot-runner contract
# (docs/Architecture.md §3.3, §8.1-8.4, §13): drives the REAL installer with
# PATH-stubbed collaborators (sfdisk/cryptsetup/mkfs/mount/debootstrap/chroot/
# lsblk/...) recording argv to a log file, then asserts OBSERVED effects: the
# staged target tree contents, plan execution order, fail-closed preconditions,
# and baseline target metadata.
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

T=$(mktemp -d /tmp/debian-fde-install-chroot.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_HOOKS_DIR=$T/hooks
export DEBIAN_FDE_KEYDIR=$T/keys
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T          # M-01/L-04: secrets + plan temp files live HERE, not /tmp
export DEBIAN_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command

PARTUUID_CANON='5f2a9b01-02'            # canned ESP PARTUUID the lsblk stub reports
export PARTUUID_CANON

DISK=$T/disk.img
: >"$DISK"

# --- stub collaborators -------------------------------------------------------
mkdir -p "$T/stub"

make_stub() { # NAME — log argv, exit 0
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.ext4 mkfs.vfat mount umount debootstrap chroot \
    apt-get useradd usermod passwd systemctl bootctl sbverify ukify; do
    make_stub "$s"
done

# cryptsetup — log argv; BR-01: fail closed when a --key-file argument names a
# file that does not exist AT EXECUTION TIME (a scrub trap armed in a subshell
# deletes the staged passphrase key-file before any plan step can use it —
# this assert kills the old vacuous find-based L-04a pass)
cat >"$T/stub/cryptsetup" <<'EOF'
#!/bin/sh
prev=''
for a in "$@"; do
    if [ "$prev" = "--key-file" ] && [ ! -f "$a" ]; then
        printf 'cryptsetup --key-file target missing at execution time: %s\n' "$a" \
            >>"$DEBIAN_FDE_TEST_LOG"
        exit 91
    fi
    prev=$a
done
printf 'cryptsetup %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
exit 0
EOF

# id — pretend to be root (preflight check)
cat >"$T/stub/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF

# lsblk — log argv; report the canned PARTUUID for `-no PARTUUID <dev>`
cat >"$T/stub/lsblk" <<'EOF'
#!/bin/sh
printf 'lsblk %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' "$PARTUUID_CANON" ;;
esac
exit 0
EOF

# sbsign — log argv; materialize the --output file so the plan's real `mv`/`cp` succeed
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
out=''
prev=''
for a in "$@"; do
    [ "$prev" = "--output" ] && out=$a
    prev=$a
done
if [ -n "$out" ]; then
    mkdir -p "${out%/*}"
    : >"$out"
fi
exit 0
EOF

# mount — log argv; simulate mounting: the root mountpoint materializes with a
# /boot holding a kernel+initrd pair (the §8.4 first-boot UKI step resolves the
# kver from it), and an ESP mount (*/efi) appears holding the boot-manager
# layout `bootctl install` would have created
cat >"$T/stub/mount" <<'EOF'
#!/bin/sh
printf 'mount %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
case $2 in
    */efi)
        mkdir -p "$2/EFI/systemd" "$2/EFI/BOOT"
        : >"$2/EFI/systemd/systemd-bootx64.efi"
        ;;
    */mnt)
        # the encrypted root mount: materialize /boot with a kernel+initrd pair
        # (the §8.4 first-boot UKI step resolves the kver from it). NOTE: only
        # the root mountpoint — the H-02 bind argv is `mount --bind /sys
        # <mnt>/sys`, where $2 is the SOURCE path; never touch it.
        mkdir -p "$2" "$2/boot"
        : >"$2/boot/vmlinuz-6.1.0-1-amd64"
        : >"$2/boot/initrd.img-6.1.0-1-amd64"
        ;;
    *)
        mkdir -p "$2" 2>/dev/null || true
        ;;
esac
exit 0
EOF

chmod +x "$T/stub/id" "$T/stub/lsblk" "$T/stub/sbsign" "$T/stub/mount" "$T/stub/cryptsetup"
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

run_install() { # env overrides are set by the caller before invoking
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
    RC=$?
}

# =============================================================================
# G-I10 (§8.1): preflight must validate the baseline BEFORE any destructive
# step — a broken/missing baseline dies 64 with sfdisk never invoked.
# =============================================================================
mv "$(sp_baseline_file)" "$T/baseline.bak"

run_install
assert_eq "missing baseline -> fail-closed 64" "64" "$RC"
assert_contains "missing baseline: error names the baseline" "$OUT" "baseline"
assert_contains "missing baseline: error tells how to fix" "$OUT" "provision stage1"
assert_eq "missing baseline: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

printf '{"schema_version": "999"}\n' >"$(sp_baseline_file)"
run_install
assert_eq "invalid baseline -> fail-closed 64" "64" "$RC"
assert_eq "invalid baseline: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

mv "$T/baseline.bak" "$(sp_baseline_file)"
assert_rc "fixture: restored baseline validates" 0 baseline_validate "$(sp_baseline_file)"

# =============================================================================
# G-I1 (§3.3/§8.2): config drops execute in plan order — after mount +
# debootstrap, before the first apt use — so the target root receives apt
# policy/sources, crypttab, fstab, networkd, dracut conf and cmdline.txt.
# =============================================================================
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
run_install
assert_eq "chroot install rc 0" "0" "$RC"
# BR-01: the staged passphrase key-file must SURVIVE until the cryptsetup plan
# step runs (the stub above fails the step when --key-file names a missing
# file — a subshell scrub trap deleting it early fails the whole install 64)
assert_not_contains "BR-01: --key-file names an EXISTING file at cryptsetup execution time" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "key-file target missing at execution time"
assert_contains "BR-01: luksFormat ran scripted via the staged key-file" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "cryptsetup luksFormat"

LUKS_UUID=$(grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
ROOTFS_UUID=$(grep -oE -- '-U [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
assert_eq "fixture: luksFormat pinned an explicit uuid" "1" "$([ -n "$LUKS_UUID" ] && echo 1 || echo 0)"
assert_eq "fixture: mkfs.ext4 pinned an explicit uuid" "1" "$([ -n "$ROOTFS_UUID" ] && echo 1 || echo 0)"

MNT_ETC=$DEBIAN_FDE_INSTALL_MNT/etc
assert_file_exists "target: apt no-recommends policy" "$MNT_ETC/apt/apt.conf.d/90debian-fde"
assert_contains "apt policy: recommends off" "$(cat "$MNT_ETC/apt/apt.conf.d/90debian-fde")" 'APT::Install-Recommends "false";'
assert_contains "apt policy: suggests off" "$(cat "$MNT_ETC/apt/apt.conf.d/90debian-fde")" 'APT::Install-Suggests "false";'
assert_file_exists "target: apt sources drop" "$MNT_ETC/apt/sources.list.d/debian-fde.sources"
assert_contains "apt sources: mirror" "$(cat "$MNT_ETC/apt/sources.list.d/debian-fde.sources")" "URIs: http://deb.debian.org/debian"
assert_contains "apt sources: suite" "$(cat "$MNT_ETC/apt/sources.list.d/debian-fde.sources")" "Suites: trixie"
assert_contains "apt sources: non-free-firmware" "$(cat "$MNT_ETC/apt/sources.list.d/debian-fde.sources")" "Components: main non-free-firmware"
assert_eq "crypttab verbatim per §8.2" \
    "root UUID=$LUKS_UUID none luks,tpm2-device=auto,discard" \
    "$(cat "$MNT_ETC/crypttab")"
assert_contains "fstab: encrypted root line" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID / ext4 defaults 0 1"
assert_file_exists "target: networkd drop" "$MNT_ETC/systemd/network/20-debian-fde.network"
assert_contains "networkd: dhcp" "$(cat "$MNT_ETC/systemd/network/20-debian-fde.network")" "DHCP=yes"
assert_file_exists "target: dracut conf" "$MNT_ETC/dracut.conf.d/10-debian-fde.conf"
assert_contains "dracut: hostonly" "$(cat "$MNT_ETC/dracut.conf.d/10-debian-fde.conf")" "hostonly=yes"
assert_contains "dracut: legacy crypt module omitted" "$(cat "$MNT_ETC/dracut.conf.d/10-debian-fde.conf")" 'omit_dracutmodules+=" crypt "'
assert_eq "cmdline.txt verbatim with §8.2 fail-closed pins" \
    "root=UUID=$LUKS_UUID ro rd.shell=0 rd.emergency=poweroff" \
    "$(cat "$MNT_ETC/debian-fde/cmdline.txt")"

# plan order: sfdisk -> debootstrap -> policy write -> apt-get update
first_line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }
I_SFDISK=$(first_line_no "$OUT" "sfdisk")
I_DEBOOT=$(first_line_no "$OUT" "debootstrap")
I_POLICY=$(first_line_no "$OUT" "etc/apt/apt.conf.d/90debian-fde")
I_APTUPD=$(first_line_no "$OUT" "apt-get update")
assert_eq "order: sfdisk before debootstrap" "1" "$(( I_SFDISK < I_DEBOOT ? 1 : 0 ))"
assert_eq "order: debootstrap before policy write" "1" "$(( I_DEBOOT < I_POLICY ? 1 : 0 ))"
assert_eq "order: policy write before first apt use" "1" "$(( I_POLICY < I_APTUPD ? 1 : 0 ))"
L_SFDISK=$(first_line_no "$(cat "$DEBIAN_FDE_TEST_LOG")" "sfdisk")
L_DEBOOT=$(first_line_no "$(cat "$DEBIAN_FDE_TEST_LOG")" "debootstrap")
assert_eq "stub log: sfdisk ran before debootstrap" "1" "$(( L_SFDISK < L_DEBOOT ? 1 : 0 ))"
# §3.3: the recorded one-transaction apt invocation carries jq in the §3.3
# documented position (zram-tools, jq, sudo) — the /opt/debian-fde tooling copy
# must be runnable in-guest for §9.1's enroll-from-booted-system path
APT_TXN_LOG=$(grep -m1 'apt-get install' "$DEBIAN_FDE_TEST_LOG")
assert_contains "stub log: apt transaction includes jq (§3.3 order)" "$APT_TXN_LOG" " zram-tools jq sudo "

# =============================================================================
# G-I2 (§8.3): flat hook templates map to /etc/kernel/{postinst,postrm}.d/
# zz-debian-fde destinations, executable; preflight accepts the flat layout.
# =============================================================================
for d in postinst.d postrm.d; do
    assert_file_exists "target: kernel hook installed: $d/zz-debian-fde" "$MNT_ETC/kernel/$d/zz-debian-fde"
    assert_eq "target kernel hook executable: $d/zz-debian-fde" "1" "$([ -x "$MNT_ETC/kernel/$d/zz-debian-fde" ] && echo 1 || echo 0)"
done
assert_not_contains "preflight: no flat-layout complaint" "$OUT" "hooks directory missing"
# G-U7 (§8.3): boot-manager re-sign hook installed + enabled; self-update masked
assert_file_exists "target: boot-manager re-sign hook" "$MNT_ETC/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade"
assert_eq "target: boot-manager re-sign hook executable" "1" \
    "$([ -x "$MNT_ETC/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade" ] && echo 1 || echo 0)"
assert_eq "target: systemd-boot-update.service masked" "1" \
    "$([ -L "$MNT_ETC/systemd/system/systemd-boot-update.service" ] && [ "$(readlink "$MNT_ETC/systemd/system/systemd-boot-update.service")" = "/dev/null" ] && echo 1 || echo 0)"
# G-U8 (§8.3): initramfs post-update hook installed + enabled
assert_file_exists "target: initramfs post-update hook" "$MNT_ETC/initramfs/post-update.d/zz-debian-fde"
assert_eq "target: initramfs post-update hook executable" "1" \
    "$([ -x "$MNT_ETC/initramfs/post-update.d/zz-debian-fde" ] && echo 1 || echo 0)"

# =============================================================================
# G-I4 (§8.4): post-sfdisk the ESP PARTUUID is resolved into fstab (no literal
# placeholder) and the copied baseline's target.* fields are populated —
# rotate/enroll on the installed system key off them.
# =============================================================================
assert_contains "fstab: real ESP PARTUUID (placeholder resolved)" "$(cat "$MNT_ETC/fstab")" "PARTUUID=$PARTUUID_CANON /efi vfat umask=0077 0 2"
assert_not_contains "fstab: no unresolved placeholder" "$(cat "$MNT_ETC/fstab")" "<esp-partuuid>"
TGT_BL=$MNT_ETC/debian-fde/baseline.json
assert_file_exists "target: baseline copied" "$TGT_BL"
assert_rc "copied baseline still validates" 0 baseline_validate "$TGT_BL"
assert_eq "copied baseline: target.luks_uuid" "$LUKS_UUID" "$(baseline_get_in "$TGT_BL" target luks_uuid)"
assert_eq "copied baseline: target.esp_partuuid" "$PARTUUID_CANON" "$(baseline_get_in "$TGT_BL" target esp_partuuid)"

# =============================================================================
# H-02 (I-H2): the chroot runner binds /proc /sys /dev into the target BEFORE
# the guest steps and tears the binds down BEFORE `umount -R`; microcode is
# resolved HOST-side (the bare chroot has no /proc — in-guest detection
# provably no-oped to amd64-microcode on every host).
# =============================================================================
assert_contains "H-02: /proc bound into the target" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mount -t proc proc $DEBIAN_FDE_INSTALL_MNT/proc"
assert_contains "H-02: /sys bound into the target" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mount --bind /sys $DEBIAN_FDE_INSTALL_MNT/sys"
assert_contains "H-02: /dev bound into the target" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mount --bind /dev $DEBIAN_FDE_INSTALL_MNT/dev"
L_BINDT=$(first_line_no "$(cat "$DEBIAN_FDE_TEST_LOG")" "mount --bind /dev")
L_BINDU=$(first_line_no "$(cat "$DEBIAN_FDE_TEST_LOG")" "umount $DEBIAN_FDE_INSTALL_MNT/dev")
L_UMNTR=$(first_line_no "$(cat "$DEBIAN_FDE_TEST_LOG")" "umount -R")
assert_eq "H-02: binds torn down before umount -R" "1" "$(( L_BINDT > 0 && L_BINDU > L_BINDT && L_UMNTR > L_BINDU ? 1 : 0 ))"
# microcode: literal package(s) in the recorded apt transaction, matching the
# HOST CPU vendor (unit matrix: intel | amd64 | both-if-unknown)
printf 'vendor_id\t: GenuineIntel\n' >"$T/cpu-intel"
printf 'vendor_id\t: AuthenticAMD\n' >"$T/cpu-amd"
: >"$T/cpu-unknown"
assert_eq "H-02: microcode resolver: GenuineIntel -> intel-microcode" "intel-microcode" \
    "$(inst_microcode_pkgs "$T/cpu-intel")"
assert_eq "H-02: microcode resolver: AuthenticAMD -> amd64-microcode" "amd64-microcode" \
    "$(inst_microcode_pkgs "$T/cpu-amd")"
assert_eq "H-02: microcode resolver: unreadable/unknown -> BOTH (safe superset)" \
    "intel-microcode amd64-microcode" "$(inst_microcode_pkgs "$T/cpu-unknown")"
MCU_EXPECT=$(inst_microcode_pkgs)
assert_contains "H-02: apt txn carries the HOST-resolved microcode ($MCU_EXPECT)" \
    "$APT_TXN_LOG" "$MCU_EXPECT"
assert_not_contains "H-02: no in-chroot vendor detection left in the plan" "$OUT" \
    'grep -m1 vendor_id /proc/cpuinfo'

# =============================================================================
# H-03 (I-H3): the FIRST-BOOT UKI is authored + signed from the INSTALLER env:
# dracut (target root, via the H-02 binds) -> ukify (cmdline from
# /etc/debian-fde/cmdline.txt, phase enter-initrd) -> sbsign (release key from
# --keydir; the key NEVER enters the target, I4) -> §8.4 ESP layout.
# =============================================================================
assert_contains "H-03: dracut builds the guest initrd (via chroot)" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "dracut --force --kver"
UKIFY_LOG=$(grep -m1 'ukify build' "$DEBIAN_FDE_TEST_LOG")
assert_contains "H-03: ukify builds from the target kernel" "$UKIFY_LOG" \
    "ukify build --linux $DEBIAN_FDE_INSTALL_MNT/boot/vmlinuz-6.1.0-1-amd64"
assert_contains "H-03: ukify consumes the initrd dracut produced" "$UKIFY_LOG" \
    "--initrd $DEBIAN_FDE_INSTALL_MNT/boot/initrd.img-6.1.0-1-amd64"
assert_contains "H-03: cmdline from /etc/debian-fde/cmdline.txt" "$UKIFY_LOG" \
    "--cmdline $(cat "$DEBIAN_FDE_INSTALL_MNT/etc/debian-fde/cmdline.txt")"
assert_contains "H-03: enter-initrd phase pinned" "$UKIFY_LOG" "--phase enter-initrd"
SBSIGN_UKI=$(grep 'sbsign' "$DEBIAN_FDE_TEST_LOG" | grep 'debian-fde-6.1.0-1-amd64.efi' | head -n 1)
assert_contains "H-03: UKI signed with the release key from --keydir" "$SBSIGN_UKI" \
    "--key $DEBIAN_FDE_KEYDIR/release.pem"
assert_file_exists "H-03: signed first-boot UKI installed (§8.4 layout)" \
    "$DEBIAN_FDE_INSTALL_MNT/efi/EFI/Linux/debian-fde-6.1.0-1-amd64.efi"
assert_contains "H-03: sbverify over the installed UKI" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "sbverify --cert $DEBIAN_FDE_KEYDIR/release.crt"
assert_eq "H-03/I4: the release key appears in NO guest (chroot) step" "0" \
    "$(grep '^chroot ' "$DEBIAN_FDE_TEST_LOG" | grep -c 'release.pem')"

# =============================================================================
# CR-01: the resolved ESP mount is persisted at install as ESP_PATH in
# /etc/debian-fde/debian-fde.conf (the build side reads it; CLI default /efi).
# =============================================================================
assert_file_exists "CR-01: debian-fde.conf dropped into the target" \
    "$MNT_ETC/debian-fde/debian-fde.conf"
assert_contains "CR-01: ESP_PATH=/efi persisted" "$(cat "$MNT_ETC/debian-fde/debian-fde.conf")" \
    "ESP_PATH=/efi"

# =============================================================================
# L-04b: guest steps never see DEBIAN_FDE_DISK_PASSPHRASE — the chroot
# invocation strips it from the inherited environment.
# =============================================================================
assert_contains "L-04b: chroot invocation strips the passphrase variable" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "-u DEBIAN_FDE_DISK_PASSPHRASE"

# =============================================================================
# G-I9 (§13): ESP sizing — measured UKI size x retention (current+2) +
# headroom, rounded up to whole MiB; unmeasurable -> fixed default 512M;
# DEBIAN_FDE_ESP_SIZE env override wins over measurement.
# =============================================================================
MIB=$((1024 * 1024))
assert_eq "sizing: 96MiB UKI, retention 3, 64MiB headroom -> 352M" "352M" \
    "$(inst_esp_size_compute $((96 * MIB)) 3 $((64 * MIB)))"
assert_eq "sizing: unmeasurable (empty) -> 512M default" "512M" \
    "$(inst_esp_size_compute '' 3 $((64 * MIB)))"
assert_eq "sizing: junk measurement -> 512M default" "512M" \
    "$(inst_esp_size_compute not-a-number 3 $((64 * MIB)))"
assert_eq "sizing: sub-MiB result rounds up" "65M" \
    "$(inst_esp_size_compute 1000 3 $((64 * MIB + 1)))"
assert_eq "sizing: retention falls back when garbage" "352M" \
    "$(inst_esp_size_compute $((96 * MIB)) junk $((64 * MIB)))"
printf 'uki-bytes' >"$T/uki.efi"
assert_eq "sizing: measured via probe file" "65M" \
    "$(DEBIAN_FDE_UKI_FILE=$T/uki.efi inst_esp_size)"
assert_eq "sizing: env override wins over measurement" "1G" \
    "$(DEBIAN_FDE_UKI_FILE=$T/uki.efi DEBIAN_FDE_ESP_SIZE=1G inst_esp_size)"
assert_eq "sizing: no measurement no override -> 512M" "512M" "$(inst_esp_size)"

# =============================================================================
# G4/F-1 (§8.1/§3.3): the tooling copy into /opt/debian-fde ships ONLY the
# product script tree (bin/ lib/ hooks/ docs/) — NEVER the working tree's VCS
# or harness residue (.git, tests/, fixtures/, caches, e2e run dirs). A dirty
# checkout holds 100MB+ blobs and root-owned device nodes (soak residue):
# `cp -r <whole tree>` bloats the §3.3-minimal target and dies on the node.
# Residue is seeded in a THROWAWAY tree — never the real tests/ dirs (a live
# e2e soak may own them).
# =============================================================================
DEBIAN_FDE_TREE=$T/tree
mkdir -p "$DEBIAN_FDE_TREE"
for d in bin lib hooks docs; do
    cp -r "$REPO/$d" "$DEBIAN_FDE_TREE/$d"
done
mkdir -p "$DEBIAN_FDE_TREE/.git/objects" "$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run" \
    "$DEBIAN_FDE_TREE/tests/.cache" "$DEBIAN_FDE_TREE/fixtures"
printf 'residue' >"$DEBIAN_FDE_TREE/.git/HEAD"
printf 'residue' >"$DEBIAN_FDE_TREE/fixtures/marker"
printf 'residue' >"$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run/marker"
truncate -s 100M "$DEBIAN_FDE_TREE/tests/.cache/blob-100M"
# char device like the soak's node residue — seeds only where privileges allow
mknod "$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-node" c 1 3 2>/dev/null || true

run_install_tree() { # TREE — run_install against a different tooling tree
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$(DEBIAN_FDE_CMD_DIR="$1/lib/cmd" "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
    RC=$?
}

run_install_tree "$DEBIAN_FDE_TREE"
assert_eq "tooling copy from seeded tree: rc 0" "0" "$RC"

OPT=$DEBIAN_FDE_INSTALL_MNT/opt/debian-fde
assert_file_exists "tooling copy: bin/debian-fde shipped" "$OPT/bin/debian-fde"
assert_file_exists "tooling copy: lib/ shipped" "$OPT/lib/cmd/install.sh"
assert_file_exists "tooling copy: hooks/ shipped" "$OPT/hooks/postinst.d-zz-debian-fde"
assert_file_exists "tooling copy: docs/ shipped" "$OPT/docs/Architecture.md"

RESIDUE=$(find "$OPT" \( -name '.git' -o -name 'tests' -o -name 'fixtures' \
    -o -name '*.cache*' -o -name '*.runs*' -o -name 'blob-100M' -o -name 'soak-run' \) | wc -l)
assert_eq "tooling copy: zero VCS/harness residue at any depth" "0" "$RESIDUE"
NODES=$(find "$OPT" \( -type b -o -type c \) | wc -l)
assert_eq "tooling copy: zero device nodes in target" "0" "$NODES"
OPT_MIB=$(du -sm "$OPT" | cut -f1)
assert_eq "tooling copy: §3.3 size budget holds (no 100M blob)" "1" "$(( OPT_MIB <= 50 ? 1 : 0 ))"

COPY_LINE=$(grep -m1 'cp -r' <<<"$OUT")
assert_contains "tooling copy step: enumerates bin" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/bin"
assert_contains "tooling copy step: enumerates lib" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/lib"
assert_contains "tooling copy step: enumerates hooks" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/hooks"
assert_contains "tooling copy step: enumerates docs" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/docs"
assert_not_contains "tooling copy step: never the whole tree root" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE "

# =============================================================================
# G-I3 (§13/T2b): the entropy floor is enforced on the INTERACTIVE path too —
# no-echo prompt x2, passphrase_floor_ok, then a key-file for scripted
# luksFormat/open — before any destructive step.
# =============================================================================
run_install_stdin() { # STDIN_FILE — drive `install` with piped "prompts"
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" <"$1" 2>&1)
    RC=$?
}
unset DEBIAN_FDE_DISK_PASSPHRASE

printf 'weakpass\nweakpass\n' >"$T/pass-weak"
run_install_stdin "$T/pass-weak"
assert_eq "interactive weak passphrase -> rc 2" "2" "$RC"
assert_contains "interactive weak: floor error" "$OUT" "entropy floor"
assert_eq "interactive weak: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

printf 'short\nshort\n' >"$T/pass-short"
run_install_stdin "$T/pass-short"
assert_eq "interactive short passphrase -> rc 2" "2" "$RC"

printf 'Tr0ub4dor&extra-long\nother-passphrase-entirely\n' >"$T/pass-mismatch"
run_install_stdin "$T/pass-mismatch"
assert_eq "interactive passphrase mismatch -> rc 2" "2" "$RC"
assert_contains "interactive mismatch: error explains" "$OUT" "do not match"
assert_eq "interactive mismatch: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

printf 'correct-horse-battery-stapler-42\ncorrect-horse-battery-stapler-42\n' >"$T/pass-strong"
run_install_stdin "$T/pass-strong"
assert_eq "interactive strong passphrase -> rc 0" "0" "$RC"
assert_contains "interactive strong: luksFormat scripted via key-file (M-01: tmpfs seam)" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "--key-file $DEBIAN_FDE_TMPDIR/debian-fde-diskkey"
assert_not_contains "interactive passphrase never echoed into output" "$OUT" "correct-horse-battery-stapler-42"
assert_not_contains "interactive passphrase never logged by stubs" "$(cat "$DEBIAN_FDE_TEST_LOG")" "correct-horse-battery-stapler-42"

# env-passphrase weak case stays fail-closed with zero destructive commands
export DEBIAN_FDE_DISK_PASSPHRASE='weak'
run_install
assert_eq "env weak passphrase -> rc 2" "2" "$RC"
assert_eq "env weak: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
unset DEBIAN_FDE_DISK_PASSPHRASE

# =============================================================================
# H-03 gate: missing signing key -> fail-closed 64 + ADR-8 marker BEFORE any
# destructive step; DEBIAN_FDE_INSTALL_SKIP_UKI=1 is the loud operator opt-out.
# =============================================================================
mv "$DEBIAN_FDE_KEYDIR/release.pem" "$T/release.pem.bak"
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
run_install
assert_eq "H-03 gate: missing release.pem -> fail-closed 64 (ADR-8)" "64" "$RC"
assert_contains "H-03 gate: error names the first-boot UKI" "$OUT" "first-boot UKI"
assert_contains "H-03 gate: error points at the opt-out" "$OUT" "DEBIAN_FDE_INSTALL_SKIP_UKI"
assert_file_exists "H-03 gate: ADR-8 marker persisted" "$DEBIAN_FDE_ROOT/etc/debian-fde/build-failed"
assert_contains "H-03 gate: marker records the reason" "$(cat "$DEBIAN_FDE_ROOT/etc/debian-fde/build-failed")" "reason:"
assert_eq "H-03 gate: zero destructive commands" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"

OUT=$(DEBIAN_FDE_INSTALL_SKIP_UKI=1 "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1)
RC=$?
assert_eq "H-03 skip: DEBIAN_FDE_INSTALL_SKIP_UKI=1 -> rc 0" "0" "$RC"
assert_contains "H-03 skip: loud warn (ADR-8)" "$OUT" "DEBIAN_FDE_INSTALL_SKIP_UKI=1"
# IR-01: the custody gate is ONE check — preflight + step-0 duplication warned
# twice in skip mode; exactly one warn line must reach the operator
assert_eq "IR-01: skip warn emitted exactly once (gate deduped)" "1" \
    "$(grep -c 'DEBIAN_FDE_INSTALL_SKIP_UKI=1' <<<"$OUT")"
assert_eq "H-03 skip: no UKI authored" "0" "$(grep -c 'ukify build' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "H-03 skip: boot manager NOT signed (key absent)" "0" "$(grep -c '^sbsign' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "H-03 skip: no key material copied into the target" "0" \
    "$(grep -c 'release.pub' "$DEBIAN_FDE_TEST_LOG")"
mv "$T/release.pem.bak" "$DEBIAN_FDE_KEYDIR/release.pem"
unset DEBIAN_FDE_DISK_PASSPHRASE

# =============================================================================
# M-02: operator-controlled values are validated at the boundary BEFORE any
# plan record exists — `--user 'x; rm -rf /'` must never reach a plan record.
# =============================================================================
export DEBIAN_FDE_INSTALL_USER='x; rm -rf /'
run_install
assert_eq "M-02: injected --user (env) -> usage rc 2" "2" "$RC"
assert_contains "M-02: error names the invalid user" "$OUT" "invalid --user"
assert_eq "M-02: injected --user: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
unset DEBIAN_FDE_INSTALL_USER
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --user 'x; rm -rf /' 2>&1)
RC=$?
assert_eq "M-02: injected --user (flag) -> usage rc 2" "2" "$RC"
OUT=$("$REPO/bin/debian-fde" install --disk '/dev/sda; reboot -f' 2>&1)
RC=$?
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$RC"

# WR-01: --keydir is interpolated into eval'd plan records (cp / sbsign
# arguments) — the same M-02 boundary must reject metacharacters BEFORE any
# record exists, and the injected command must never execute
: >"$DEBIAN_FDE_TEST_LOG"
rm -f /tmp/pwned
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --keydir '/x; touch /tmp/pwned' 2>&1)
RC=$?
assert_eq "WR-01: injected --keydir -> usage rc 2" "2" "$RC"
assert_contains "WR-01: error names DEBIAN_FDE_KEYDIR" "$OUT" "DEBIAN_FDE_KEYDIR"
assert_eq "WR-01: injected --keydir: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
assert_eq "WR-01: injected --keydir executed nothing (no /tmp/pwned)" "0" \
    "$([ -e /tmp/pwned ] && echo 1 || echo 0)"
rm -f /tmp/pwned
OUT=$(DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42' \
    "$REPO/bin/debian-fde" install --disk "$DISK" 2>&1 </dev/null)
RC=$?
assert_eq "M-02: clean run still rc 0 (validation does not over-reject)" "0" "$RC"

# =============================================================================
# L-04a: a failed plan step leaves NO temp files behind (plan file + staged
# passphrase key-file are scrubbed by the combined EXIT trap). The failing
# step is a HOST record (eval'd for real; the log-only chroot stub masks
# inner guest failures by design).
# =============================================================================
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
exit 1
EOF
chmod +x "$T/stub/sbsign"
export DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
run_install
assert_eq "L-04a: failed host step -> fail-closed 64" "64" "$RC"
assert_contains "L-04a: the failing step is named" "$OUT" "host step failed"
assert_eq "L-04a: plan temp file scrubbed on failed step" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-plan.*' 2>/dev/null | wc -l)"
assert_eq "L-04a: passphrase key-file scrubbed on failed step" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-diskkey.*' 2>/dev/null | wc -l)"
# WR-02: the abort trap tears the H-02 binds down best-effort. The die hits at
# §6b (sbsign) — the plan's own teardown (§7) never ran, so the ONLY
# `umount <mnt>/dev /sys /proc` line in the log can come from the trap.
assert_eq "WR-02 fixture: plan teardown never ran (die at §6b)" "0" \
    "$(grep -c 'umount -R' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "WR-02: abort trap tore the H-02 binds down (/dev /sys /proc)" "1" \
    "$(grep -c "^umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc\$" "$DEBIAN_FDE_TEST_LOG")"
unset DEBIAN_FDE_DISK_PASSPHRASE

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
