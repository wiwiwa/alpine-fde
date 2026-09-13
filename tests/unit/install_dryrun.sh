#!/usr/bin/env bash
# tests/unit/install_dryrun.sh — `debian-fde install` dry-run plan contract:
#   * default runner is dry-run; prints the COMPLETE action plan (partition,
#     LUKS2/argon2id pins, mkfs, debootstrap minbase, apt policy, package
#     transaction, crypttab/fstab, bootctl+sbsign, /etc/debian-fde copy, kernel
#     hooks, ukictl build delegation, teardown) and EXECUTES nothing
#   * destructive runners are gated behind --yes; unknown runner -> rc 2
#   * package-list lint: §3.3 required set present, forbidden packages absent
#   * §13 passphrase floor unit checks (shared with rotate)

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

T=$(mktemp -d /tmp/debian-fde-install-dryrun.XXXXXX)
export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_HOOKS_DIR=$T/hooks   # dry-run must not require the real hooks tree
FAKEDISK=$T/disk.img
: >"$FAKEDISK"

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

run_install() { # args...
    INS_OUT=$("$REPO/bin/debian-fde" install "$@" 2>&1)
    INS_RC=$?
}

# --- 1. usage errors ---------------------------------------------------------------
run_install
assert_eq "no --disk -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --runner nonsense 2>/dev/null || true
export DEBIAN_FDE_INSTALL_RUNNER=nonsense
run_install --disk "$FAKEDISK"
assert_eq "unknown runner -> usage rc 2" "2" "$INS_RC"
export DEBIAN_FDE_INSTALL_RUNNER=chroot
run_install --disk "$FAKEDISK"
assert_eq "destructive runner without --yes -> usage rc 2" "2" "$INS_RC"
unset DEBIAN_FDE_INSTALL_RUNNER

# --- 2. dry-run prints the full plan ---------------------------------------------------
export DEBIAN_FDE_INSTALL_RUNNER=dry-run
run_install --disk "$FAKEDISK"
assert_eq "dry-run rc 0" "0" "$INS_RC"
assert_contains "plan: sfdisk GPT partitioning" "$INS_OUT" "sfdisk"
assert_contains "plan: uefi ESP partition" "$INS_OUT" "type=uefi"
assert_contains "plan: luksFormat luks2" "$INS_OUT" "luksFormat --type luks2"
assert_contains "plan: Argon2id KDF pinned" "$INS_OUT" "--pbkdf argon2id"
assert_contains "plan: argon2id memory pin" "$INS_OUT" "--pbkdf-memory 1048576"
assert_contains "plan: argon2id time pin" "$INS_OUT" "--iter-time 2000"
assert_contains "plan: keyslot 0 is the passphrase slot" "$INS_OUT" "--key-slot 0"
assert_contains "plan: explicit luks uuid (RFC4122 shape)" "$INS_OUT" "$(grep -oE 'luksFormat .*' <<<"$INS_OUT" | grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')"
assert_contains "plan: mkfs.ext4" "$INS_OUT" "mkfs.ext4"
assert_contains "plan: mkfs.vfat ESP" "$INS_OUT" "mkfs.vfat -F 32"
assert_contains "plan: debootstrap minbase trixie" "$INS_OUT" "debootstrap --variant=minbase trixie"
assert_contains "plan: debian mirror" "$INS_OUT" "http://deb.debian.org/debian"
assert_contains "plan: apt no-recommends policy" "$INS_OUT" "APT::Install-Recommends"
assert_contains "plan: non-free-firmware component" "$INS_OUT" "non-free-firmware"
assert_contains "plan: apt update" "$INS_OUT" "apt-get update"
assert_contains "plan: one-transaction package install" "$INS_OUT" "apt-get install -y --no-install-recommends"
assert_contains "plan: microcode included" "$INS_OUT" "microcode"
# §3.3: jq ships in the SAME transaction (dependency of the debian-fde CLI —
# the /opt/debian-fde tooling copy must run in-guest for §9.1 enroll), in the
# §3.3 documented position (zram-tools, jq, sudo)
APT_TXN=$(grep -m1 'apt-get install -y --no-install-recommends' <<<"$INS_OUT")
assert_contains "plan: apt transaction includes jq (§3.3 order)" "$APT_TXN" " zram-tools jq sudo "
assert_contains "plan: user creation" "$INS_OUT" "useradd -m -s /bin/bash admin"
assert_contains "plan: networkd config" "$INS_OUT" "20-debian-fde.network"
assert_contains "plan: crypttab with mandatory tpm2-device" "$INS_OUT" "luks,tpm2-device=auto,discard"
assert_contains "plan: fail-closed cmdline pins" "$INS_OUT" "rd.shell=0 rd.emergency=poweroff"
assert_contains "plan: dracut hostonly" "$INS_OUT" "hostonly=yes"
assert_contains "plan: dracut legacy crypt module omitted" "$INS_OUT" "omit_dracutmodules"
assert_contains "plan: bootctl install" "$INS_OUT" "bootctl install"
assert_contains "plan: boot manager signed (sbsign)" "$INS_OUT" "sbsign"
assert_contains "plan: signature verified (sbverify)" "$INS_OUT" "sbverify"
assert_contains "plan: /etc/debian-fde copied into root" "$INS_OUT" "etc/debian-fde/baseline.json"
assert_contains "plan: release pub key copied (only pub material)" "$INS_OUT" "release.pub"
COPY_LINE=$(grep 'cp .*etc/debian-fde/baseline.json' <<<"$INS_OUT")
assert_contains "plan copy line carries pub cert" "$COPY_LINE" "release.crt"
assert_not_contains "plan /etc/debian-fde copy: NO private key material" "$COPY_LINE" "release.pem"
assert_contains "plan: kernel hooks installed" "$INS_OUT" "etc/kernel/postinst.d"
assert_contains "plan: tree staged to /opt/debian-fde" "$INS_OUT" "opt/debian-fde"
assert_contains "plan: first-boot UKI precedes the §9.1 from-booted-system ukictl build hint" "$INS_OUT" "ukictl build"
assert_contains "plan: teardown (umount + luks close)" "$INS_OUT" "cryptsetup close root-crypt"
assert_contains "plan: next-step hint (audit --init)" "$INS_OUT" "audit --init"

# --- 2b. plan additions: §3.3 user/trims, hooks, target resolution, ESP sizing ----
# G-I5 (§3.3): the admin user gets its sudo grant in the same transaction
assert_contains "plan: admin user sudo grant" "$INS_OUT" "usermod -aG sudo admin"
# G-I13 (§3.3): dpkg path-exclude trims (docs/man/non-C.UTF-8 locales)
assert_contains "plan: dpkg minimal trims drop" "$INS_OUT" "etc/dpkg/dpkg.cfg.d/90debian-fde-minimal"
assert_contains "plan: trims exclude docs" "$INS_OUT" "path-exclude=/usr/share/doc/*"
assert_contains "plan: trims exclude man pages" "$INS_OUT" "path-exclude=/usr/share/man/*"
assert_contains "plan: trims exclude locales" "$INS_OUT" "path-exclude=/usr/share/locale/*"
# dry-run drops stay in plan order (debootstrap before policy write before apt)
D_DEBOOT=$(grep -Fnm1 'debootstrap' <<<"$INS_OUT" | cut -d: -f1)
D_POLICY=$(grep -Fnm1 'etc/apt/apt.conf.d/90debian-fde' <<<"$INS_OUT" | cut -d: -f1)
D_APTUPD=$(grep -Fnm1 'apt-get update' <<<"$INS_OUT" | cut -d: -f1)
assert_eq "dry-run order: debootstrap before policy write" "1" "$(( D_DEBOOT < D_POLICY ? 1 : 0 ))"
assert_eq "dry-run order: policy write before apt update" "1" "$(( D_POLICY < D_APTUPD ? 1 : 0 ))"
# G-U7 (§8.3): boot-manager self-update masked; re-sign hook installed+enabled
assert_contains "plan: systemd-boot-update.service masked" "$INS_OUT" "systemd-boot-update.service"
assert_contains "plan: boot-manager re-sign hook installed" "$INS_OUT" "zz-debian-fde-systemd-boot-upgrade"
# G-U8 (§8.3): initramfs post-update hook triggers UKI rebuilds
assert_contains "plan: initramfs post-update hook installed" "$INS_OUT" "etc/initramfs/post-update.d/zz-debian-fde"
# G-I4 (§8.4): target metadata resolution is a real plan step
assert_contains "plan: target metadata resolution step" "$INS_OUT" "inst_resolve_target_metadata"
# G-I9 (§13): ESP sized from measured UKI x retention + headroom; default 512M;
# env override wins
assert_contains "plan: default ESP size 512M" "$INS_OUT" "size=+512M"
DEBIAN_FDE_ESP_SIZE=1G run_install --disk "$FAKEDISK"
assert_eq "ESP size override run rc 0" "0" "$INS_RC"
assert_contains "plan: ESP size override wins" "$INS_OUT" "size=+1G"

# --- 2c. tooling copy exclusion policy (G4/F-1, §8.1/§3.3) -------------------
# the plan's copy step is visible and enumerates the shipped dirs; exactly ONE
# info line states the exclusion policy (product tree only, residue stays out).
run_install --disk "$FAKEDISK"
assert_eq "dry-run (policy check) rc 0" "0" "$INS_RC"
COPY_STEP=$(grep -m1 'cp -r' <<<"$INS_OUT")
for d in bin lib hooks docs; do
    assert_contains "dry-run copy step ships $d" "$COPY_STEP" "cp -r $REPO/$d/"
done
assert_not_contains "dry-run copy step never copies the tree root" "$COPY_STEP" "cp -r $REPO "
assert_eq "exactly one info line states the exclusion policy" "1" "$(grep -c 'tooling copy:' <<<"$INS_OUT")"
assert_contains "info line names the shipped dirs" "$INS_OUT" "tooling copy: product script tree only (bin lib hooks docs)"
assert_contains "info line names the excluded residue" "$INS_OUT" "residue"

# --- 3. dry-run has no side effects ------------------------------------------------------
CSUM_BEFORE=$(sha256sum <"$FAKEDISK")
run_install --disk "$FAKEDISK"
CSUM_AFTER=$(sha256sum <"$FAKEDISK")
assert_eq "fake disk untouched by dry-run" "$CSUM_BEFORE" "$CSUM_AFTER"
assert_not_contains "dry-run created no keyfile temp leakage in plan" "$INS_OUT" "key-file /tmp/debian-fde-diskkey"
assert_not_contains "dry-run created no keyfile temp leakage in plan (M-01 tmpfs seam)" "$INS_OUT" "key-file /dev/shm/debian-fde-diskkey"

# --- 3b. plan additions: H-02 binds + host-side microcode, H-03 first-boot UKI,
#         CR-01 persisted ESP_PATH ------------------------------------------------
run_install --disk "$FAKEDISK"
assert_eq "plan-shape run rc 0" "0" "$INS_RC"
# H-02: /proc /sys /dev binds + teardown, and the microcode packages resolved
# HOST-side (literal in the apt transaction, no in-chroot detection)
assert_contains "plan: /proc bound into the target (H-02)" "$INS_OUT" "mount -t proc proc /mnt/proc"
assert_contains "plan: /sys bound into the target (H-02)" "$INS_OUT" "mount --bind /sys /mnt/sys"
assert_contains "plan: /dev bound into the target (H-02)" "$INS_OUT" "mount --bind /dev /mnt/dev"
assert_contains "plan: binds torn down before umount -R (H-02)" "$INS_OUT" "umount /mnt/dev /mnt/sys /mnt/proc"
assert_contains "plan: microcode packages literal (H-02 host-side resolve)" "$INS_OUT" "microcode"
assert_not_contains "plan: no in-chroot vendor detection (H-02)" "$INS_OUT" 'grep -m1 vendor_id /proc/cpuinfo'
# H-03: first-boot UKI authored + signed from the installer env
assert_contains "plan: dracut builds the guest initrd (H-03)" "$INS_OUT" "dracut --force --kver"
assert_contains "plan: ukify assembles the first-boot UKI (H-03)" "$INS_OUT" "ukify build --linux"
assert_contains "plan: cmdline from /etc/debian-fde/cmdline.txt (H-03)" "$INS_OUT" "--cmdline"
assert_contains "plan: enter-initrd phase (H-03)" "$INS_OUT" "--phase enter-initrd"
assert_contains "plan: UKI signed with the release key (H-03)" "$INS_OUT" "sbsign --key <signing-medium>/release.pem"
assert_contains "plan: UKI lands in the §8.4 ESP layout (H-03)" "$INS_OUT" "EFI/Linux/debian-fde-"
assert_contains "plan: UKI verified after signing (H-03)" "$INS_OUT" "sbverify --cert <signing-medium>/release.crt"
assert_not_contains "plan/H-I4: the signing key path never appears in a guest step" \
    "$(grep '^PLAN  guest ' <<<"$INS_OUT" || true)" "release.pem"
# CR-01: resolved ESP mount persisted for the build side
assert_contains "plan: ESP_PATH persisted into debian-fde.conf (CR-01)" "$INS_OUT" "ESP_PATH=/efi"

# --- 3c. L-06: DEBIAN_FDE_YES only counts as consent when it is exactly "1" -----
export DEBIAN_FDE_INSTALL_RUNNER=chroot
DEBIAN_FDE_YES=0 run_install --disk "$FAKEDISK"
assert_eq "L-06: DEBIAN_FDE_YES=0 is NOT consent -> usage rc 2" "2" "$INS_RC"
assert_contains "L-06: refusal explains the --yes requirement" "$INS_OUT" "requires --yes"
DEBIAN_FDE_YES=no run_install --disk "$FAKEDISK"
assert_eq "L-06: DEBIAN_FDE_YES=no is NOT consent -> usage rc 2" "2" "$INS_RC"
DEBIAN_FDE_YES=1 run_install --disk "$FAKEDISK"
assert_eq "L-06: DEBIAN_FDE_YES=1 still consents (rc 64 = preflight root check)" "64" "$INS_RC"
unset DEBIAN_FDE_INSTALL_RUNNER

# --- 3d. M-02: injected operator inputs die at the boundary (usage rc 2) --------
run_install --disk "$FAKEDISK" --user 'x; rm -rf /'
assert_eq "M-02: injected --user -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: error names the invalid user" "$INS_OUT" "invalid --user"
run_install --disk '/dev/sda; reboot -f'
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$INS_RC"
DEBIAN_FDE_ESP_SIZE='512M; reboot' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected ESP size -> usage rc 2" "2" "$INS_RC"
DEBIAN_FDE_MIRROR='http://evil.example/debian; rm -rf /' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected mirror -> usage rc 2" "2" "$INS_RC"
# WR-01: the keydir rides into eval'd plan records too (cp/sbsign arguments) —
# the env path must die at the same M-02 boundary
DEBIAN_FDE_KEYDIR='/x; touch /tmp/pwned' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected keydir (env DEBIAN_FDE_KEYDIR) -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: injected keydir error names the variable" "$INS_OUT" "DEBIAN_FDE_KEYDIR"

# --- 3e. BR-01: passphrase staging contract (direct call, THIS shell) ----------
# The resolver must be called DIRECTLY (never in command substitution): it sets
# _IRD_KEYFILE, arms its scrub trap in the MAIN shell, and really unsets the
# plaintext env variable. BR-01 was: a subshell call deleted the staged key-file
# the instant the subshell exited — gone before any plan step could use it.
DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_INSTALL_RUNNER
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_TMPDIR=$T
DEBIAN_FDE_DISK_PASSPHRASE='correct-horse-battery-stapler-42'
inst_ensure_passphrase_floor # production call-site order (install.sh, §13 floor)
_BR_RC=0
inst_resolve_disk_passphrase || _BR_RC=$?
assert_eq "BR-01: direct call returns rc 0" "0" "$_BR_RC"
assert_eq "BR-01: resolver stages _IRD_KEYFILE (non-empty)" "1" \
    "$([ -n "${_IRD_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "BR-01: key-file still EXISTS after the call (scrub trap in main shell)" "1" \
    "$([ -f "${_IRD_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "BR-01: key-file holds the verified passphrase" "correct-horse-battery-stapler-42" \
    "$(cat "${_IRD_KEYFILE:-/dev/null}")"
assert_eq "BR-01: _ird_kf carrier matches the staged key-file" "${_IRD_KEYFILE:-}" "${_ird_kf:-}"
assert_eq "BR-01: plaintext env unset in the MAIN shell (L-04b)" "1" \
    "$([ -z "${DEBIAN_FDE_DISK_PASSPHRASE:-}" ] && echo 1 || echo 0)"
rm -f "${_IRD_KEYFILE:-}"
unset _BR_RC _IRD_KEYFILE _ird_kf DEBIAN_FDE_DISK_PASSPHRASE DEBIAN_FDE_TMPDIR
trap cleanup EXIT # the resolver re-armed the EXIT trap; restore fixture cleanup
unset DEBIAN_FDE_INSTALL_RUNNER DEBIAN_FDE_YES

# --- 4. package-list lint (§3.3) ------------------------------------------------------------
PKG_LIST=$(install_package_list)
REQUIRED="systemd-cryptsetup systemd-boot systemd-boot-tools systemd-ukify dracut linux-image-amd64 tpm2-tools cryptsetup sbsigntool openssl zram-tools jq sudo"
for want in $REQUIRED; do
    FOUND=0
    for w in $PKG_LIST; do
        [ "$w" = "$want" ] && FOUND=1
    done
    assert_eq "package list contains $want" "1" "$FOUND"
done
FORBIDDEN="grub-pc grub-efi shim-signed initramfs-tools clevis clevis-luks ifupdown rsyslog nano cron cron-daemon-common"
for bad in $FORBIDDEN; do
    case " $PKG_LIST " in
        *" $bad "*) assert_eq "package list must NOT contain $bad" "absent" "present" ;;
        *) assert_eq "package list must NOT contain $bad" "absent" "absent" ;;
    esac
done

# --- 5. passphrase floor (§13, C-G12) ---------------------------------------------------------
# shellcheck source=../../lib/cmd/rotate.sh
source "$REPO/lib/cmd/rotate.sh"
assert_rc "floor ok: 16+ chars plain" 0 passphrase_floor_ok 'sixteen-chars-ok!'
assert_rc "floor ok: 12 chars 3 classes" 0 passphrase_floor_ok 'Xylophone42Dogs!'
assert_rc "floor ok: long with classes" 0 passphrase_floor_ok 'Tr0ub4dor&extra-long'
assert_rc "floor fail: too short" 1 passphrase_floor_ok 'Ab3!'
assert_rc "floor fail: 12 chars 2 classes" 1 passphrase_floor_ok 'abcdefghijklm'
assert_rc "floor fail: 15 chars 1 class" 1 passphrase_floor_ok 'abcdefghijklmno'
assert_rc "floor fail: blocklisted substring" 1 passphrase_floor_ok 'My-Secret-password-123'
assert_rc "floor fail: common sequence" 1 passphrase_floor_ok 'qwertyuiop123'
assert_rc "floor fail: empty" 1 passphrase_floor_ok ''

# --- 6. pre-upgrade stub (ext4 root -> graceful skip rc 0 per ADR-13) ----------------------------
PRE_OUT=$("$REPO/bin/debian-fde" pre-upgrade 2>&1)
PRE_RC=$?
assert_eq "pre-upgrade skips ext4 root gracefully (rc 0)" "0" "$PRE_RC"
assert_contains "pre-upgrade explains ext4 stance" "$PRE_OUT" "btrfs"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
