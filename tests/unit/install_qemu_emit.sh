#!/usr/bin/env bash
# tests/unit/install_qemu_emit.sh — `alpine-fde install` qemu-runner contract
# (docs/Architecture.md §8.1, §9.1; ADR-20): ALPINE_FDE_INSTALL_RUNNER=qemu
# with ALPINE_FDE_INSTALL_SCRIPT=<tmpfile> emits the guest-side plan as a
# script without executing anything:
#   * `set -eu` (repo standard guard) + shebang header
#   * guest config writes as single-quote-escaped printf lines — crypttab and
#     the /etc/apk/repositories drop VERBATIM (a broken escape loses trailing
#     content, wave-1 bug)
#   * host steps emitted as comments (block layer, apk populate, binds,
#     metadata, state, ephemeral-key scrub)
#   * the §9.1 in-chroot provisioning sequence appears as EXECUTABLE guest
#     lines (apk additions txn, user account, platform-key ceremony, NVRAM
#     enrollment, bootctl, ukictl build, G-C24 provisional seal)
#   * G-C25: the MOTD/issue banner is emitted as guest printf lines
#   * G-C26: NO OsIndications record in either lane; the direct reboot is
#     suppressed by the CI seam (the harness reboots itself)
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
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-install-qemu.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=qemu
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export ALPINE_FDE_INSTALL_SCRIPT=$T/guest-install.sh
export ALPINE_FDE_INSTALL_NO_REBOOT=1   # CI seam: the harness reboots itself
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
DISK=$T/disk.img
: >"$DISK"
: >"$ALPINE_FDE_TEST_LOG"

# --- stub collaborators: present for preflight, logging for the no-exec assert
mkdir -p "$T/stub"
make_stub() { # NAME — log argv, exit 0
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount apk adduser addgroup rc-update \
    bootctl lsblk btrfs cryptsetup reboot; do
    make_stub "$s"
done
# openssl — deterministic 256-bit hex body (the staged ephemeral key, G-C23)
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
case " $* " in
    *" rand "*) printf 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' ;;
esac
exit 0
EOF
chmod +x "$T/stub/openssl"
cat >"$T/stub/id" <<'EOF'   # pretend to be root (preflight check, never logged)
#!/bin/sh
printf '0\n'
EOF
chmod +x "$T/stub/id"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
mkdir -p "$ALPINE_FDE_HOOKS_DIR/kernel-hooks.d" "$ALPINE_FDE_HOOKS_DIR/mkinitfs/features.d" \
    "$ALPINE_FDE_HOOKS_DIR/apk/triggers" "$ALPINE_FDE_HOOKS_DIR/openrc" "$ALPINE_FDE_EFIVARS_DIR"
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    printf '#!/bin/sh\nexit 0\n' >"$ALPINE_FDE_HOOKS_DIR/$h"
    chmod +x "$ALPINE_FDE_HOOKS_DIR/$h"
done
# §9.1 preflight: firmware in Setup Mode
printf '\007\000\000\000\001' >"$ALPINE_FDE_EFIVARS_DIR/SetupMode-$GUID_GLOBAL"

# --- run: emit the guest script (UNATTENDED: stdin closed) -----------------------
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1 </dev/null)
RC=$?
SCRIPT=$ALPINE_FDE_INSTALL_SCRIPT

assert_eq "qemu emit rc 0 (unattended)" "0" "$RC"
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
assert_eq "repositories drop verbatim (G-C1: replaces apt sources)" \
    "printf '%s\n' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main' 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' >/etc/apk/repositories" \
    "$(grep -F 'dl-cdn.alpinelinux.org' "$SCRIPT")"
# ADR-13: dracut is REJECTED on Alpine (mkinitfs, G-C8) — the emitted guest
# script carries NO dracut config residue
assert_eq "emitted script: NO dracut conf drop (ADR-13)" "0" \
    "$(grep -c 'dracut' "$SCRIPT")"
assert_contains "cmdline drop emitted with btrfs rootflags + fail-closed pins" "$(cat "$SCRIPT")" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"

# --- physical-media block sequence (real-install defects 1+2): the physical ---
# boot environment does NOT auto-load the block modules and /dev is not settled
assert_eq "emitted: modprobe btrfs host record (physical boot does not auto-load btrfs)" "1" \
    "$(grep -c '^# HOST: if command -v modprobe >/dev/null 2>&1; then modprobe btrfs; fi' "$SCRIPT")"
assert_eq "emitted: coldplug (mdev -s) host record" "1" \
    "$(grep -c '^# HOST: if command -v mdev >/dev/null 2>&1; then mdev -s; fi' "$SCRIPT")"
S_MODP=$(grep -n 'then modprobe btrfs; fi' "$SCRIPT" | cut -d: -f1)
S_COLD=$(grep -n 'then mdev -s; fi' "$SCRIPT" | cut -d: -f1 | head -1)
S_HSFD=$(grep -n '^# HOST: .*sfdisk' "$SCRIPT" | cut -d: -f1 | head -1)
assert_eq "emitted order: modprobe btrfs BEFORE the coldplug" "1" \
    "$(( S_MODP > 0 && S_MODP < S_COLD ? 1 : 0 ))"
assert_eq "emitted order: coldplug BEFORE partitioning" "1" \
    "$(( S_COLD > 0 && S_COLD < S_HSFD ? 1 : 0 ))"
assert_eq "guest step emitted executable: apk additions txn (§9.1 step 1)" "1" \
    "$(grep -Ec '^apk add --no-cache ' "$SCRIPT")"
assert_eq "guest step emitted executable: user account (locked, unattended)" "1" \
    "$(grep -cx 'adduser -D -s /bin/ash admin && addgroup admin wheel' "$SCRIPT")"
assert_eq "guest step emitted executable: OpenRC networking" "1" \
    "$(grep -cx 'rc-update add networking boot' "$SCRIPT")"
assert_eq "guest: finalize advisory enabled for the default runlevel (§9.1 step 7)" "1" \
    "$(grep -cx 'rc-update add alpine-fde-finalize default' "$SCRIPT")"

# --- REAL-INSTALL DEFECT 6 (e2e-invisible): the repositories drop MUST land
# BEFORE the apk populate in the emitted plan — apk resolves against the
# TARGET's /etc/apk/repositories, so a populate-first run dies on a real
# server (`unable to select packages: alpine-base`). The real apk populate
# path is NOT exercised by local e2e (the harness stamps a pinned rootfs
# payload) — this ordering pin is the harness-level guard.
S_REPOS=$(grep -n '>/etc/apk/repositories' "$SCRIPT" | cut -d: -f1)
S_APKPOP=$(grep -n '^# HOST: apk add --root' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: repositories drop BEFORE apk populate (real-install defect 6)" "1" \
    "$(( S_REPOS > 0 && S_APKPOP > 0 && S_REPOS < S_APKPOP ? 1 : 0 ))"

# --- RESET of a previous FAILED attempt (user report): emitted as HOST ------
# comments (the reset runs host-side in every lane), runtime-guarded so a
# pristine machine no-ops; ordering puts the reset block before partitioning.
assert_eq "emitted: reset status record (guarded: previous failed install detected)" "1" \
    "$(grep -c "^# HOST: if mountpoint -q $ALPINE_FDE_INSTALL_MNT 2>/dev/null || ls " "$SCRIPT")"
assert_eq "emitted: 4 guarded stale-mount umount records (btrfs default: home .snapshots esp root)" "4" \
    "$(grep -c '^# HOST: if mountpoint -q .*; then umount ' "$SCRIPT")"
assert_eq "emitted: guarded stale-mapper close record (rootN glob + root-crypt, name-stripped)" "1" \
    "$(grep -c '^# HOST: for m in /dev/mapper/root\[0-9\]\* /dev/mapper/root-crypt; do \[ -e "\$m" \] || continue; cryptsetup close "\${m#/dev/mapper/}"' "$SCRIPT")"
assert_eq "emitted: guarded live-bcache STOP record (set dirs only, register file skipped)" "1" \
    "$(grep -c '^# HOST: for d in /sys/fs/bcache/\*/; do \[ -f "\${d}stop" \] || continue; u="\${d%/}"; echo "\${u##\*/}" > "\$u/stop"' "$SCRIPT")"
S_RESET=$(grep -n 'previous failed install detected' "$SCRIPT" | cut -d: -f1)
S_BCSTOP=$(grep -n 'stopped live bcache set' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: reset records BEFORE partitioning" "1" \
    "$(( S_RESET > 0 && S_BCSTOP > 0 && S_BCSTOP < S_HSFD ? 1 : 0 ))"
assert_contains "emitted: reset records no-op-safe under set -eu (guarded warn branches)" \
    "$(cat "$SCRIPT")" "could not unmount stale mount"

# --- host steps are comments ------------------------------------------------------
assert_eq "host step emitted as comment: apk populate (§3.3, replaces debootstrap)" "1" \
    "$(grep -c '^# HOST: apk add --root .* --initdb alpine-base' "$SCRIPT")"
assert_eq "host step emitted as comment: sfdisk" "1" \
    "$(grep -c '^# HOST: .*sfdisk' "$SCRIPT")"
assert_eq "host step emitted as comment: mkfs.btrfs" "1" \
    "$(grep -c '^# HOST: .*mkfs.btrfs' "$SCRIPT")"
assert_eq "host step emitted as comment: luksFormat (keyslot 0, ephemeral key)" "1" \
    "$(grep -c '^# HOST: .*luksFormat --type luks2' "$SCRIPT")"
# Comment-proof --batch-mode check (w2-lint-leg1): the record's own trailing
# comment NAMES --batch-mode, so a plain `grep -vc -- --batch-mode` is defeated
# by it — strip the `# HOST: ` record prefix and the trailing ` #` comment
# FIRST, then count unbatched records. (A bare `s/#.*$//` would eat the whole
# host record — in the qemu lane it IS a comment line — and false-positive.)
assert_eq "emitted: EVERY luksFormat runs --batch-mode on the COMMAND, comment stripped (real-install defect 5: no interactive dangerous-action YES)" "0" \
    "$(grep 'luksFormat' "$SCRIPT" | sed 's/^# HOST: //; s/ *#.*$//' | grep -vc -- '--batch-mode')"
# RED guard: the check must be able to FAIL — drop the flag while the comment
# still vouches for it, on a scratch copy, and the fixed expression flags it
sed 's/cryptsetup --batch-mode luksFormat/cryptsetup luksFormat/' "$SCRIPT" >"$T/script-nobatch.sh"
assert_eq "emitted: --batch-mode check is comment-proof (flag dropped, comment kept -> flagged)" "1" \
    "$(grep 'luksFormat' "$T/script-nobatch.sh" | sed 's/^# HOST: //; s/ *#.*$//' | grep -vc -- '--batch-mode')"
assert_contains "emitted: luksFormat carries the --batch-mode global option" "$(cat "$SCRIPT")" \
    "cryptsetup --batch-mode luksFormat"
assert_eq "host step emitted as comment: tree copy (G-C7: /opt/alpine-fde)" "1" \
    "$(grep -c '^# HOST: .*cp -r .*opt/alpine-fde' "$SCRIPT")"
assert_eq "host step emitted as comment: pending baseline on target (§9.1 step 2)" "1" \
    "$(grep -c '^# HOST: inst_baseline_pending_write' "$SCRIPT")"
assert_eq "host step emitted as comment: state write (§9.1 step 9)" "1" \
    "$(grep -c '^# HOST: inst_state_write installed' "$SCRIPT")"
assert_eq "host step emitted as comment: ephemeral-key scrub (G-C26, I1)" "1" \
    "$(grep -c '^# HOST: rm -f /dev/shm/alpine-fde-ephkey' "$SCRIPT")"
assert_eq "host teardown emitted as comment" "1" \
    "$(grep -c '^# HOST: .*cryptsetup close root-crypt' "$SCRIPT")"
assert_eq "no host step left executable" "0" \
    "$(grep -c '^apk add --root' "$SCRIPT")"
assert_eq "no reboot record (ALPINE_FDE_INSTALL_NO_REBOOT=1 CI seam)" "0" \
    "$(grep -c '^# HOST: reboot' "$SCRIPT")"
assert_eq "G-C26: NO OsIndications record in either lane" "0" \
    "$(grep -c 'fw_osindications_set' "$SCRIPT")"
# ADR-20 amended (§9.1 step 4): release.pem encryption lives in the INTERACTIVE
# in-chroot credential ceremony (inst_ceremony_release_key -> keys_encrypt_release,
# ADR-18) — Stage 1 must carry NO EXECUTABLE keys_encrypt_release invocation (the
# name may appear only inside inert ceremony-record comments naming the ADR-18
# mechanism). Docs: §9.1 step 4, T2c, ADR-18/ADR-20 ("encrypted ... in Stage 1
# before reboot" — via the ceremony).
assert_eq "ADR-20: NO executable keys_encrypt_release in Stage 1 (ceremony-owned, ADR-18)" "0" \
    "$(grep -c '^[^#]*keys_encrypt_release' "$SCRIPT")"
# G-C7: the tooling tree lands at /opt/alpine-fde (§8.1/§12) — the OLD
# /opt/debian-fde spelling must not survive anywhere in the emitted plan.
assert_not_contains "G-C7: NO /opt/debian-fde anywhere in the emitted qemu script" \
    "$(cat "$SCRIPT")" "/opt/debian-fde"

# --- §9.1 in-chroot provisioning sequence: EXECUTABLE guest lines ----------------
assert_eq "guest: platform-key ceremony (§9.1 step 3, explicit keydir)" "1" \
    "$(grep -cx '/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys' "$SCRIPT")"
assert_eq "guest: NVRAM enrollment db->KEK->PK (§9.1 step 4)" "1" \
    "$(grep -cx 'export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys' "$SCRIPT")"
assert_eq "guest: bootctl install (ESP layout)" "1" \
    "$(grep -cx 'bootctl install --esp-path=/efi --boot-path=/efi' "$SCRIPT")"
assert_eq "guest: ukictl build (§9.1 step 5)" "1" \
    "$(grep -cx '/opt/alpine-fde/bin/alpine-fde ukictl build' "$SCRIPT")"
# G-C24: the provisional seal guest line (lib-line pattern; PCR 11; keyslot 1)
assert_eq "guest: provisional seal line (§9.1 step 6, lib-line pattern)" "1" \
    "$(grep -c 'export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && objcopy' "$SCRIPT")"
assert_contains "guest: provisional seal consumes the UKI .pcrsig" "$(cat "$SCRIPT")" \
    "only-section=.pcrsig"
assert_contains "guest: provisional seal line pins the slot contract" "$(cat "$SCRIPT")" \
    "provisional Mechanism B seal (PCR 11) -> keyslot 1"
# order inside the emitted script: ceremony -> enrollment -> build -> seal
S_KEYGEN=$(grep -n 'provision stage1 --mode in-chroot' "$SCRIPT" | cut -d: -f1)
S_ENROLL=$(grep -n 'fw_auth_enroll' "$SCRIPT" | cut -d: -f1)
S_BUILD=$(grep -n 'ukictl build' "$SCRIPT" | cut -d: -f1)
S_SEAL=$(grep -n 'seal_provisional' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: keygen before enrollment" "1" "$(( S_KEYGEN < S_ENROLL ? 1 : 0 ))"
assert_eq "emitted order: enrollment before build" "1" "$(( S_ENROLL < S_BUILD ? 1 : 0 ))"
assert_eq "emitted order: build before the provisional seal" "1" "$(( S_BUILD < S_SEAL ? 1 : 0 ))"

# --- G-C25: the unfinalized banner is emitted as guest printf lines ---------------
assert_contains "banner: /etc/motd printf drop" "$(cat "$SCRIPT")" ">/etc/motd"
assert_contains "banner: /etc/issue printf drop" "$(cat "$SCRIPT")" ">/etc/issue"
assert_contains "banner: NOT finalized text emitted" "$(cat "$SCRIPT")" "NOT finalized"
assert_contains "banner: finalize directive emitted" "$(cat "$SCRIPT")" "alpine-fde finalize"
assert_contains "banner: pending-recovery-passphrase notice emitted" "$(cat "$SCRIPT")" \
    "set your permanent recovery passphrase"
S_MOTD=$(grep -n '>/etc/motd' "$SCRIPT" | cut -d: -f1)
S_STATE=$(grep -n 'inst_state_write installed' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: banner BEFORE the state write (G-C28)" "1" \
    "$(( S_MOTD > 0 && S_STATE > S_MOTD ? 1 : 0 ))"

# --- emitted script is sound but NEVER executed -----------------------------------
assert_rc "emitted script parses (escape loop sound)" 0 sh -n "$SCRIPT"
assert_eq "nothing was executed (stub log empty)" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
assert_eq "target root untouched (no host step ran)" "0" "$([ -e "$ALPINE_FDE_INSTALL_MNT" ] && echo 1 || echo 0)"

# --- H-02 binds emitted in the right lane ------------------------------------------
assert_eq "host step emitted as comment: /proc bind (H-02)" "1" \
    "$(grep -c '^# HOST: .*mount -t proc proc' "$SCRIPT")"
assert_eq "host step emitted as comment: efivars bind (§9.1)" "1" \
    "$(grep -c '^# HOST: .*mount --bind /sys/firmware/efi/efivars' "$SCRIPT")"
assert_eq "host step emitted as comment: bind teardown (H-02)" "1" \
    "$(grep -cF "# HOST: umount $ALPINE_FDE_INSTALL_MNT/dev $ALPINE_FDE_INSTALL_MNT/sys $ALPINE_FDE_INSTALL_MNT/proc" "$SCRIPT")"

# --- conf drop (§4 topology + CR-01) -------------------------------------------------
assert_contains "conf drop emitted: ROOT_FS=btrfs (§4)" "$(cat "$SCRIPT")" "ROOT_FS=btrfs"
assert_contains "conf drop emitted: BCACHE=0 (§4)" "$(cat "$SCRIPT")" "BCACHE=0"
assert_contains "conf drop emitted: ESP_PATH=/efi (CR-01)" "$(cat "$SCRIPT")" "ESP_PATH=/efi"

# --- permissions -------------------------------------------------------------------
assert_eq "emitted script chmod 700" "700" "$(stat -c '%a' "$SCRIPT")"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
