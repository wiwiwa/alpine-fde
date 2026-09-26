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
#   * G-C25 (ADR-20 amendment #4): NO MOTD/issue banner — no guest printf
#     drop to /etc/motd or /etc/issue and none of the banner vocabulary
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
    lsblk btrfs cryptsetup reboot; do
    make_stub "$s"
done
# nslookup — preflight-only DNS probe (host-side, never a plan step): succeed
# silently like the id stub, keep the "stub log empty" no-exec assert intact
cat >"$T/stub/nslookup" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$T/stub/nslookup"
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

# --- header: shebang + repo standard guard (task 8: -ex adoption on the emitted guest script) ---
assert_eq "emitted script: shebang is first line" "#!/bin/sh -ex" "$(head -n1 "$SCRIPT")"
assert_contains "emitted script: set -eux guard" "$(cat "$SCRIPT")" 'set -eux'

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
# item 26a (ADR-7 AMENDED — zram removed from the design): zero zram residue in
# the emitted guest script (no package entry, no conf.d drop, no rc-update)
assert_eq "emitted: ZERO zram mentions anywhere (item 26a: zram removed from the install path)" "0" \
    "$(grep -ic 'zram' "$SCRIPT")"
# item 26b lane placement (DNS preflight): the nslookup mirror probe is a
# HOST-side preflight step — inst_preflight runs at plan-build/emit time in
# every non-dry-run lane and is NEVER a plan record, so the emitted guest
# script carries ZERO nslookup commands and a fixture guest needs NO resolver
# to install. The target's DNS story still travels: the resolv.conf SEED is a
# `# HOST:` comment record the CI harness executes before the in-chroot apk
# transaction.
assert_eq "emitted: ZERO nslookup records (26b: the DNS preflight is host-side in every lane, never guest work)" "0" \
    "$(grep -c 'nslookup' "$SCRIPT")"
assert_eq "emitted: target resolv.conf seed travels as a HOST comment (26b: in-chroot apk needs DNS)" "1" \
    "$(grep -c '^# HOST: .*seeded target /etc/resolv.conf from the live env' "$SCRIPT")"

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

# --- item 26 ext (real-install failure #5): target apk KEYRING seed ---------
# apk verifies mirror indexes against the TARGET's <mnt>/etc/apk/keys only —
# absent on a fresh rootfs, and --initdb does NOT copy the host keyring — so
# the populate dies `UNTRUSTED signature` on any real server. The seed travels
# as a guarded `# HOST:` comment record the CI harness executes between the
# repositories drop and the apk populate.
S_KEYSEED=$(grep -n 'cp -a /etc/apk/keys' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted: apk keyring seed as a guarded HOST comment (26ext: populate dies UNTRUSTED without the target keyring)" "1" \
    "$(grep -c '^# HOST: mkdir -p .* && if \[ -d /etc/apk/keys \]; then cp -a /etc/apk/keys .* && echo .*apk keyring seeded from the live env' "$SCRIPT")"
assert_contains "emitted: keys-seed guard carries the no-live-keyring warn branch" "$(cat "$SCRIPT")" \
    "no keyring on the live env"
assert_eq "emitted order: repositories drop BEFORE keys seed BEFORE apk populate (26ext)" "1" \
    "$(( S_REPOS > 0 && S_KEYSEED > 0 && S_APKPOP > 0 && S_REPOS < S_KEYSEED && S_KEYSEED < S_APKPOP ? 1 : 0 ))"

# --- RESET of a previous FAILED attempt (user report): emitted as HOST ------
# comments (the reset runs host-side in every lane), runtime-guarded so a
# pristine machine no-ops; ordering puts the reset block before partitioning.
assert_eq "emitted: reset status record (guarded: previous failed install detected)" "1" \
    "$(grep -c "^# HOST: if mountpoint -q $ALPINE_FDE_INSTALL_MNT 2>/dev/null || ls " "$SCRIPT")"
# item 26d: ONE guarded RECURSIVE stale-tree umount record (covers the stale
# chroot binds — /mnt/proc /mnt/sys /mnt/dev /mnt/.../efivars — a fixed list
# misses); the fixed-list records are gone
assert_eq "emitted: 1 guarded RECURSIVE stale-tree umount record (item 26d)" "1" \
    "$(grep -c '^# HOST: if mountpoint -q .*; then umount -R ' "$SCRIPT")"
assert_eq "emitted: zero FIXED-list stale-mount umount records remain (item 26d)" "0" \
    "$(grep -c 'unmounted stale mount' "$SCRIPT")"
assert_eq "emitted: guarded stale-mapper close record (rootN glob + root-crypt, name-stripped)" "1" \
    "$(grep -c '^# HOST: for m in /dev/mapper/root\[0-9\]\* /dev/mapper/root-crypt; do \[ -e "\$m" \] || continue; cryptsetup close "\${m#/dev/mapper/}"' "$SCRIPT")"
assert_eq "emitted: guarded live-bcache STOP record (set dirs only, register file skipped)" "1" \
    "$(grep -c '^# HOST: for d in /sys/fs/bcache/\*/; do \[ -f "\${d}stop" \] || continue; u="\${d%/}"; echo "\${u##\*/}" > "\$u/stop"' "$SCRIPT")"
S_RESET=$(grep -n 'previous failed install detected' "$SCRIPT" | cut -d: -f1)
S_BCSTOP=$(grep -n 'stopped live bcache set' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: reset records BEFORE partitioning" "1" \
    "$(( S_RESET > 0 && S_BCSTOP > 0 && S_BCSTOP < S_HSFD ? 1 : 0 ))"
assert_contains "emitted: reset records no-op-safe under set -eu (guarded warn branches)" \
    "$(cat "$SCRIPT")" "could not recursively unmount stale target tree"

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
assert_eq "guest: platform-key ceremony (§9.1 step 3, explicit keydir, custody DEFERRED)" "1" \
    "$(grep -cx '/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys --defer-custody' "$SCRIPT")"
# item 12/reorder close-out (user ruling: LUKS recovery is the FIRST password
# asked, period): the emitted provision record carries --defer-custody —
# provision stage1's own keys_encrypt_release prompt would otherwise ask the
# release-key passphrase BEFORE the ceremony (no hint, recovery not yet asked).
# ceremony 3/3 (inst_ceremony_release_key) completes the encryption in-chroot;
# its keys_is_encrypted gate only skips on an ALREADY-encrypted file, so the
# plaintext stage1 leaves behind is naturally re-encrypted.
assert_contains "emitted: defer-custody — provision record defers release.pem encryption to ceremony 3/3 (release-key prompt may not precede the LUKS recovery)" \
    "$(grep -m1 'provision stage1' "$SCRIPT")" "--defer-custody"
assert_eq "guest: NVRAM enrollment db->KEK->PK (§9.1 step 4)" "1" \
    "$(grep -cx 'export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys /efi' "$SCRIPT")"
# real-server blocker #7: the boot manager installs by GUARDED FILE COPY of
# the systemd-boot loader EFI binary — never a bootctl invocation (Alpine
# ships NO bootctl binary; the retired record died POST-ceremony)
assert_eq "guest: boot manager installed by guarded file copy (loader probed fail-closed in-chroot, blocker #7)" "1" \
    "$(grep -c 'for p in /usr/share/systemd/bootctl/systemd-bootx64.efi /usr/lib/systemd/boot/efi/systemd-bootx64.efi; do \[ -f "\$p" \]' "$SCRIPT")"
assert_contains "guest: the guarded copy record targets BOTH ESP homes (canonical + removable fallback)" "$(cat "$SCRIPT")" \
    'cp "$ldr" /efi/EFI/systemd/systemd-bootx64.efi && cp "$ldr" /efi/EFI/BOOT/BOOTX64.EFI'
assert_contains "guest: the guarded copy record dies fail-closed when no loader binary exists" "$(cat "$SCRIPT")" \
    'no systemd-boot loader EFI binary found in-chroot'
assert_eq "blocker #7: ZERO bootctl invocations anywhere in the emitted script" "0" \
    "$(grep -Ec 'bootctl( |$)' "$SCRIPT")"
# real-server blocker #8: the build line must configure the release-key dir
# (ukictl build resolves keys_dir() with NO default) and feed the passphrase
# from the ceremony-staged 0600 seam file — never argv.
assert_contains "blocker #8: the emitted build line exports the in-chroot release-key dir" "$(cat "$SCRIPT")" \
    "export ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys"
assert_contains "blocker #8: the emitted build line feeds ALPINE_FDE_KEY_PASSPHRASE from the staged seam file (never argv)" "$(cat "$SCRIPT")" \
    'ALPINE_FDE_KEY_PASSPHRASE=$(cat'
assert_eq "guest: ukictl build (§9.1 step 5) — with the blocker #8 keydir export + staged passphrase seam" "1" \
    "$(grep -c 'export ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys; \[ -r .*alpine-fde-release-pass\.[A-Za-z0-9]* \] && ALPINE_FDE_KEY_PASSPHRASE=\$(cat .*alpine-fde-release-pass\.[A-Za-z0-9]*) && export ALPINE_FDE_KEY_PASSPHRASE; /opt/alpine-fde/bin/alpine-fde ukictl build' "$SCRIPT")"
# G-C24: the provisional seal guest line (lib-line pattern; PCR 11; keyslot 1)
assert_eq "guest: provisional seal line (§9.1 step 6, lib-line pattern)" "1" \
    "$(grep -c 'export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && objcopy' "$SCRIPT")"
assert_contains "guest: provisional seal consumes the UKI .pcrsig" "$(cat "$SCRIPT")" \
    "only-section=.pcrsig"
assert_contains "guest: provisional seal line pins the slot contract" "$(cat "$SCRIPT")" \
    "provisional Mechanism B seal (PCR 11) -> keyslot 1"
# order inside the emitted script: ceremony -> enrollment -> build -> seal
# item 12: the ceremony records run recovery FIRST, then user password, then
# release key
S_CERR=$(grep -n 'inst_ceremony_recovery' "$SCRIPT" | cut -d: -f1)
S_CERU=$(grep -n 'inst_ceremony_user_password' "$SCRIPT" | cut -d: -f1)
S_CERK=$(grep -n 'inst_ceremony_release_key' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: item 12 — recovery (1/3) BEFORE user password (2/3) BEFORE release key (3/3)" "1" \
    "$(( S_CERR > 0 && S_CERR < S_CERU && S_CERU < S_CERK ? 1 : 0 ))"
# item 27: the emitted ceremony record targets the LUKS CONTAINER dev (the
# luksFormat target), never the mapper — e2e is blind to this class (the
# fixture pre-seeds keyslot 0 and never really executes the host ceremony).
# The qemu runner is a REAL runner: the record carries the staged key path,
# not the dry-run placeholder.
CER_REC_EMIT=$(grep -m1 'inst_ceremony_recovery' "$SCRIPT")
assert_contains "item 27: emitted ceremony record targets the PRIMARY LUKS CONTAINER dev" "$CER_REC_EMIT" \
    " ${DISK}2 # §9.1 step 4 credential ceremony (1/3)"
assert_not_contains "item 27: emitted ceremony record NEVER names /dev/mapper" "$CER_REC_EMIT" "/dev/mapper/"
assert_eq "item 27 lint: ZERO cryptsetup container-ops (luksFormat/luksAddKey/luksRemoveKey) target /dev/mapper in the emitted script" "0" \
    "$(grep 'cryptsetup' "$SCRIPT" | grep -E 'luksFormat|luksAddKey|luksRemoveKey' | grep -c '/dev/mapper/')"
S_SEAL=$(grep -n 'seal_provisional' "$SCRIPT" | cut -d: -f1)
# item 27 extended: the emitted seal/token choreography addresses the CONTAINER
# dev (token_free_slot/luksAddKey/token import consume the LUKS2 HEADER)
assert_contains "item 27: emitted seal record targets the CONTAINER via the loop var (loop list carries the dev)" "$(grep -m1 'seal_provisional' "$SCRIPT")" \
    "seal_provisional /etc/alpine-fde/keys \$d /run/alpine-fde/pcrsig.json"
assert_contains "item 27: emitted seal loop list carries the PRIMARY CONTAINER dev" "$(grep -m1 'seal_provisional' "$SCRIPT")" \
    "for d in ${DISK}2; do"
assert_eq "item 27 lint (extended): the emitted seal/token choreography NEVER receives /dev/mapper" "0" \
    "$(grep -m1 'seal_provisional' "$SCRIPT" | grep -c '/dev/mapper/')"
S_KEYGEN=$(grep -n 'provision stage1 --mode in-chroot' "$SCRIPT" | cut -d: -f1)
S_ENROLL=$(grep -n 'fw_auth_enroll' "$SCRIPT" | cut -d: -f1)
S_BUILD=$(grep -n 'ukictl build' "$SCRIPT" | cut -d: -f1)
S_COPY=$(grep -n 'BOOTX64.EFI' "$SCRIPT" | head -1 | cut -d: -f1)
assert_eq "emitted order: keygen before enrollment" "1" "$(( S_KEYGEN < S_ENROLL ? 1 : 0 ))"
assert_eq "emitted order (user flow directive): NVRAM enrollment BEFORE the credential ceremony (mechanical first)" "1" \
    "$(( S_ENROLL > 0 && S_ENROLL < S_CERR ? 1 : 0 ))"
assert_eq "emitted order (user flow directive): boot-manager guarded copy BEFORE the credential ceremony" "1" \
    "$(( S_COPY > 0 && S_COPY < S_CERR ? 1 : 0 ))"
assert_eq "emitted order: enrollment before build" "1" "$(( S_ENROLL < S_BUILD ? 1 : 0 ))"
assert_eq "emitted order: build before the provisional seal" "1" "$(( S_BUILD < S_SEAL ? 1 : 0 ))"

# --- G-C25 (ADR-20 amendment #4): NO unfinalized banner is emitted ----------------
assert_eq "banner: ZERO /etc/motd printf drops (banner path removed, ADR-20 #4)" "0" \
    "$(grep -c '>/etc/motd' "$SCRIPT" || true)"
assert_eq "banner: ZERO /etc/issue printf drops (banner path removed, ADR-20 #4)" "0" \
    "$(grep -c '>/etc/issue' "$SCRIPT" || true)"
assert_not_contains "banner: NO not-finalized text emitted" "$(cat "$SCRIPT")" "NOT finalized"
assert_not_contains "banner: NO finalize directive emitted" "$(cat "$SCRIPT")" \
    "alpine-fde finalize"
assert_not_contains "banner: NO pending-recovery-passphrase notice emitted" "$(cat "$SCRIPT")" \
    "set your permanent recovery passphrase"
S_STATE=$(grep -n 'inst_state_write installed' "$SCRIPT" | cut -d: -f1)
assert_eq "emitted order: the state write still stands (G-C28 amended, no banner record)" "1" \
    "$(( S_STATE > 0 ? 1 : 0 ))"
# user flow directive: the state write (and every other mechanical step) is
# EMITTED BEFORE the credential-ceremony records
assert_eq "emitted order (user flow directive): state write BEFORE the credential ceremony (mechanical first)" "1" \
    "$(( S_STATE > 0 && S_STATE < S_CERR ? 1 : 0 ))"

# --- ESP-fallback tail (user directives): verdict probe + deferred ----------
# instructions as the LAST records (host comments for the harness); under the
# CI seam (NO_REBOOT=1) the Enter-confirmation + firmware-setup trip + direct
# reboot records are not emitted.
assert_contains "tail: enrollment verdict probe record (runtime-conditional PK probe on the live efivars seam)" "$(cat "$SCRIPT")" \
    "if fw_var_present $ALPINE_FDE_EFIVARS_DIR PK; then INST_SB_ENROLLED=1; else INST_SB_ENROLLED=0; fi"
S_SCRUB=$(grep -n '^# HOST: rm -f /dev/shm/alpine-fde-ephkey' "$SCRIPT" | cut -d: -f1)
S_PROBE=$(grep -n 'INST_SB_ENROLLED=1' "$SCRIPT" | cut -d: -f1)
S_INSTR=$(grep -n 'alpine-fde: Secure Boot key material is staged under /efi/alpine-fde-keys' "$SCRIPT" | cut -d: -f1)
assert_eq "tail order (user directive 3): scrub BEFORE verdict probe BEFORE the deferred instructions (instructions LAST)" "1" \
    "$(( S_SCRUB > 0 && S_SCRUB < S_PROBE && S_PROBE < S_INSTR ? 1 : 0 ))"
assert_contains "tail: deferred instructions name the DIRECT-from-ESP import first (user directive 2)" "$(cat "$SCRIPT")" \
    "import DIRECTLY from the internal ESP"
assert_eq "CI seam: NO Enter-confirmation record emitted under NO_REBOOT" "0" \
    "$(grep -c 'press Enter to reboot into firmware setup' "$SCRIPT")"
assert_eq "CI seam: NO firmware-setup trip record emitted under NO_REBOOT" "0" \
    "$(grep -c 'fw_osindications_set' "$SCRIPT")"
assert_eq "CI seam: NO reboot record emitted under NO_REBOOT" "0" \
    "$(grep -c 'then reboot' "$SCRIPT")"

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
