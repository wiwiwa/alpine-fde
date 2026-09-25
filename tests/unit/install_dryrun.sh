#!/usr/bin/env bash
# tests/unit/install_dryrun.sh — `alpine-fde install` dry-run plan contract
# (docs/Architecture.md §3.3, §4/§4.1, §8.1, §9.1, §13; ADR-17/ADR-20):
#   * default runner is dry-run; prints the COMPLETE action plan and EXECUTES
#     nothing
#   * G-C23/ADR-20: UNATTENDED — no operator passphrase prompt anywhere; the
#     internal ephemeral install key is staged on tmpfs (never persisted),
#     used for luksFormat keyslot 0 + all cryptsetup open via --key-file,
#     and scrubbed at teardown (I1)
#   * G-C1/C2/C3/§3.3: apk populate (`apk add --root <mnt> --initdb
#     alpine-base`), ONE in-chroot `apk add --no-cache` additions txn,
#     /etc/apk/repositories drop (apt/dpkg drops retired)
#   * G-ST1: Btrfs default root fs (@/@home/@snapshots + subvol fstab +
#     rootflags=subvol=@); --fs ext4 keeps the flat path verbatim
#   * G-ST2/ADR-17: --bcache single-backing hybrid topology (ESP+cache on the
#     cache dev, make-bcache -C/-B, writethrough pinned, LUKS2 on
#     /dev/bcache0)
#   * G-C27/§4.1: MULTI-BACKING bcache (--disk D1 --disk D2 --bcache CACHE):
#     shared cache set, independent LUKS2 container per /dev/bcacheN, btrfs
#     raid1 pool across the opened mappers, per-member crypttab, ESP only on
#     the cache dev
#   * G-ST3: repeatable --disk without --bcache = Btrfs RAID1
#   * G-C24/ADR-20 step 6: provisional TPM enrollment guest line after the
#     in-chroot ukictl build (Mechanism B, PCR 11 only, keyslot 1)
#   * G-C25/§9.1 step 8: unfinalized MOTD/issue banner; G-C28: banner BEFORE
#     the `installed` state write
#   * G-C26: NO OsIndications record anywhere — direct reboot to disk after
#     unmount + ephemeral-key scrub
#   * destructive runners gated behind --yes; §3.3 package-list lint;
#     ephemeral-key staging contract (0600, tmpfs, >=256-bit)

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

T=$(mktemp -d /tmp/alpine-fde-install-dryrun.XXXXXX)
export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_HOOKS_DIR=$T/hooks   # dry-run must not require the real hooks tree
FAKEDISK=$T/disk.img
: >"$FAKEDISK"

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

run_install() { # args...
    INS_OUT=$("$REPO/bin/alpine-fde" install "$@" 2>&1)
    INS_RC=$?
}

# --- 1. usage errors ---------------------------------------------------------------
run_install
assert_eq "no --disk -> usage rc 2" "2" "$INS_RC"
export ALPINE_FDE_INSTALL_RUNNER=nonsense
run_install --disk "$FAKEDISK"
assert_eq "unknown runner -> usage rc 2" "2" "$INS_RC"
export ALPINE_FDE_INSTALL_RUNNER=chroot
run_install --disk "$FAKEDISK"
assert_eq "destructive runner without --yes -> usage rc 2" "2" "$INS_RC"
unset ALPINE_FDE_INSTALL_RUNNER
run_install --fs xfs --disk "$FAKEDISK"
assert_eq "G-ST1: --fs xfs rejected (btrfs|ext4 only) -> usage rc 2" "2" "$INS_RC"
assert_contains "--fs error names the valid values" "$INS_OUT" "btrfs or ext4"
run_install --bcache /dev/nvme0n1
assert_eq "G-ST2: --bcache without --disk -> usage rc 2" "2" "$INS_RC"
assert_contains "--bcache without --disk: error says what is needed" "$INS_OUT" "--disk"
run_install --fs ext4 --disk a --disk b
assert_eq "G-ST3: --fs ext4 is single-disk only -> rc 2" "2" "$INS_RC"

# --- 2. dry-run prints the full plan (G-ST1: btrfs default, ADR-20 unattended) -----
export ALPINE_FDE_INSTALL_RUNNER=dry-run
run_install --disk "$FAKEDISK"
assert_eq "dry-run rc 0" "0" "$INS_RC"
assert_contains "plan: sfdisk GPT partitioning" "$INS_OUT" "sfdisk"
assert_contains "plan: uefi ESP partition" "$INS_OUT" "type=uefi"
assert_contains "plan: luksFormat luks2" "$INS_OUT" "luksFormat --type luks2"
# Comment-proof --batch-mode check (w2-lint-leg1): the plan record's trailing
# comment NAMES --batch-mode, so a plain `grep -vc -- --batch-mode` is defeated
# by it — strip the trailing ` #` comment FIRST, then count unbatched records
assert_eq "plan: EVERY luksFormat runs --batch-mode on the COMMAND, comment stripped (no interactive dangerous-action YES, real-install defect 5)" "0" \
    "$(grep 'luksFormat' <<<"$INS_OUT" | sed 's/ *#.*$//' | grep -vc -- '--batch-mode')"
# RED guard: the check must be able to FAIL — drop the flag while the comment
# still vouches for it, on a scratch copy of the plan, and the fixed expr flags it
NOBATCH_PLAN=$(grep 'luksFormat' <<<"$INS_OUT" | sed 's/cryptsetup --batch-mode luksFormat/cryptsetup luksFormat/')
assert_eq "plan: --batch-mode check is comment-proof (flag dropped, comment kept -> flagged)" "1" \
    "$(grep 'luksFormat' <<<"$NOBATCH_PLAN" | sed 's/ *#.*$//' | grep -vc -- '--batch-mode')"
assert_contains "plan: Argon2id KDF pinned" "$INS_OUT" "--pbkdf argon2id"
assert_contains "plan: argon2id memory pin" "$INS_OUT" "--pbkdf-memory 1048576"
assert_contains "plan: argon2id time pin" "$INS_OUT" "--iter-time 2000"
assert_contains "plan: keyslot 2 is the TEMPORARY ephemeral-key slot (§9.1: a temporary keyslot)" \
    "$INS_OUT" "--key-slot 2"
assert_contains "plan: ephemeral keyslot comment names the temporary slot (§9.1 Stage 2 purge)" \
    "$INS_OUT" "keyslot 2: ephemeral install key"
assert_not_contains "plan: keyslot 0 NOT used at luksFormat (reserved for the ceremony, §7.2)" \
    "$(grep -F 'luksFormat' <<<"$INS_OUT")" "--key-slot 0"
assert_contains "plan: G-ST1 mkfs.btrfs is the default root fs" "$INS_OUT" "mkfs.btrfs -U"
assert_eq "plan: exactly 3 btrfs subvolume records (@ @home @snapshots)" "3" \
    "$(grep -c 'btrfs subvolume create' <<<"$INS_OUT")"
assert_contains "plan: subvol @ created" "$INS_OUT" "btrfs subvolume create /mnt/@"
assert_contains "plan: subvol @home created" "$INS_OUT" "btrfs subvolume create /mnt/@home"
assert_contains "plan: subvol @snapshots created" "$INS_OUT" "btrfs subvolume create /mnt/@snapshots"
assert_contains "plan: @ mounted as root" "$INS_OUT" "mount -o subvol=@ /dev/mapper/root-crypt /mnt"
assert_contains "plan: @home mounted" "$INS_OUT" "mount -o subvol=@home /dev/mapper/root-crypt /mnt/home"
assert_contains "plan: @snapshots mounted" "$INS_OUT" "mount -o subvol=@snapshots /dev/mapper/root-crypt /mnt/.snapshots"
assert_contains "plan: mkfs.vfat ESP" "$INS_OUT" "mkfs.vfat -F 32"
# G-C1/§3.3: apk populate replaces debootstrap
assert_contains "plan: §3.3 apk populate (alpine-base, --initdb)" "$INS_OUT" \
    "apk add --root /mnt --initdb alpine-base"
assert_not_contains "plan: debootstrap retired" "$INS_OUT" "debootstrap"
assert_contains "plan: in-chroot apk additions txn (--no-cache)" "$INS_OUT" "apk add --no-cache"
assert_not_contains "plan: apt retired" "$INS_OUT" "apt-get"
# §3.1/§3.3/ADR-16 delivery + §8.3/ADR-19: the additions txn carries the
# mkinitfs/ukify/doas set verbatim
APK_TXN=$(grep -m1 'apk add --no-cache' <<<"$INS_OUT")
for want in mkinitfs py3-pefile doas ukify-kernel-hook; do
    assert_contains "plan: apk txn includes $want (§3.1)" "$APK_TXN" "$want"
done
# item 26a (ADR-7 AMENDED — zram removed from the design; --swap partition is
# the queued task-4 feature): zram-init is REMOVED from the install path — NOT
# reordered. Zero zram residue in the whole plan: no package entry, no conf.d
# drop, no rc-update enable (the enable ran BEFORE the txn that installed the
# package — real-server failure #2, "service zram-init does not exist").
assert_not_contains "plan: NO zram-init in the apk txn (item 26a: zram removed, ADR-7 amended)" \
    "$APK_TXN" "zram-init"
assert_not_contains "plan: NO zram-init conf.d drop anywhere (item 26a)" "$INS_OUT" \
    "etc/conf.d/zram-init"
assert_not_contains "plan: NO zram-init rc-update record anywhere (item 26a)" "$INS_OUT" \
    "rc-update add zram-init"
assert_eq "plan: ZERO zram mentions anywhere in the plan (item 26a: design has zero zram)" "0" \
    "$(grep -ic 'zram' <<<"$INS_OUT")"
assert_eq "plan: fstab carries NO swap line (ADR-7: no disk swap)" "0" \
    "$(grep -Ec 'UUID=.*swap' <<<"$INS_OUT")"
# §3.3: /etc/apk/repositories drop replaces apt sources + dpkg trims
assert_contains "plan: /etc/apk/repositories drop" "$INS_OUT" "etc/apk/repositories"
assert_contains "plan: repositories drop pins the Alpine CDN main repo" "$INS_OUT" \
    "dl-cdn.alpinelinux.org/alpine"
assert_not_contains "plan: apt sources drop retired" "$INS_OUT" "apt/sources.list.d"
assert_not_contains "plan: dpkg trims drop retired" "$INS_OUT" "dpkg.cfg.d"
# G-C23/ADR-20 amended: unattended until REBOOT — the plan carries the three
# §9.1 step 4 credential-ceremony records; the no-echo prompts themselves live
# ONLY in the qemu/chroot execution path (never in the dry-run plan text) and
# there is NO flag/env credential seam (S-24).
assert_not_contains "plan: NO passphrase prompt text in the plan" "$INS_OUT" \
    "Set disk encryption passphrase"
assert_not_contains "plan: NO repeat-prompt text in the plan" "$INS_OUT" "Repeat passphrase"
assert_contains "plan: ceremony (1/3) user account password record" "$INS_OUT" \
    "inst_ceremony_user_password"
assert_contains "plan: ceremony user record targets the created account" "$INS_OUT" \
    "inst_ceremony_user_password admin"
assert_contains "plan: ceremony (2/3) recovery passphrase record" "$INS_OUT" \
    "inst_ceremony_recovery"
assert_contains "plan: ceremony recovery record pins keyslot 0 (§7.2)" "$INS_OUT" \
    "recovery passphrase -> keyslot 0"
assert_contains "plan: ceremony recovery record names the ephemeral authorization" "$INS_OUT" \
    "authorized by the staged ephemeral install key"
assert_contains "plan: ceremony recovery record pins Argon2id" "$INS_OUT" \
    "KDF pinned: Argon2id"
assert_contains "plan: §13 entropy-floor retry record (re-prompt until met)" "$INS_OUT" \
    "re-prompt until met"
# item 12 (AMENDED, user ruling 2026-09-25): the ceremony asks the DISK
# RECOVERY PASSPHRASE FIRST; the user password and the release-key passphrase
# DEFAULT to it on bare Enter, each prompted with an explicit hint.
assert_contains "plan: item 12 — user-password record carries the Enter-to-reuse hint (empty = reuse recovery)" "$INS_OUT" \
    "press Enter to reuse the recovery passphrase"
CER_REL_LINE=$(grep -m1 'inst_ceremony_release_key' <<<"$INS_OUT")
assert_contains "plan: item 12 — release-key record carries the Enter-to-reuse hint (empty = reuse recovery)" "$CER_REL_LINE" \
    "press Enter to reuse the recovery passphrase"
assert_contains "plan: ceremony (3/3) release-key record (keys_encrypt_release, ADR-18)" \
    "$INS_OUT" "inst_ceremony_release_key"
assert_contains "plan: ceremony release record pins keys_encrypt_release" "$INS_OUT" \
    "keys_encrypt_release"
assert_contains "plan: ceremony release record pins AES-256 PBKDF2 (ADR-18)" "$INS_OUT" \
    "AES-256 PBKDF2"
assert_eq "plan: exactly three ceremony records" "3" \
    "$(grep -c 'credential ceremony ([123]/3)' <<<"$INS_OUT")"
# item 27 (real-server failure #4, "Device /dev/mapper/root1 is not a valid
# LUKS device" at ceremony 2/3): the ceremony targets the LUKS CONTAINER
# devices (the luksFormat targets) — the /dev/mapper/* nodes are the DECRYPTED
# views and container-ops against them fail. e2e is BLIND to this class: the
# fixture pre-seeds keyslot 0 and the host ceremony path is never really
# executed there — these plan-level pins are the harness guard.
CER_REC_LINE=$(grep -m1 'inst_ceremony_recovery' <<<"$INS_OUT")
assert_contains "item 27: ceremony recovery record targets the PRIMARY LUKS CONTAINER dev (the luksFormat target)" \
    "$CER_REC_LINE" "inst_ceremony_recovery <ephemeral-keyfile> ${FAKEDISK}2"
assert_not_contains "item 27: ceremony recovery record NEVER names /dev/mapper (mapper = decrypted view)" \
    "$CER_REC_LINE" "/dev/mapper/"
assert_eq "item 27 lint: ZERO cryptsetup container-ops (luksFormat/luksAddKey/luksRemoveKey) target /dev/mapper anywhere in the plan" "0" \
    "$(grep 'cryptsetup' <<<"$INS_OUT" | grep -E 'luksFormat|luksAddKey|luksRemoveKey' | grep -c '/dev/mapper/')"
assert_eq "item 27 lint (extended, class-killer): ZERO seal_provisional/token_* choreography calls receive /dev/mapper anywhere in the plan (token_free_slot/luksAddKey/token import consume the LUKS2 HEADER = container)" "0" \
    "$(grep -E 'seal_provisional|token_(add_keyslot|import|next_id|free_slot)' <<<"$INS_OUT" | grep -c '/dev/mapper/')"
# the mapper stays the right address for the DECRYPTED-VIEW ops (mkfs/mount)
assert_eq "item 27 sanity: mkfs still targets the MAPPER (decrypted view — correct)" "1" \
    "$(grep -Ec 'mkfs\.btrfs -U [0-9a-f-]{36} /dev/mapper/root-crypt' <<<"$INS_OUT")"
assert_not_contains "plan: NO credential env seam in the plan (ADR-20 amended)" "$INS_OUT" \
    "ALPINE_FDE_RECOVERY_PASSPHRASE"
assert_not_contains "plan: NO release-key passphrase env in the plan" "$INS_OUT" \
    "ALPINE_FDE_KEY_PASSPHRASE"
assert_not_contains "plan: NO operator passphrase env consumption" "$INS_OUT" \
    "ALPINE_FDE_DISK_PASSPHRASE"
assert_contains "plan: user account created (§8.1 user account row)" "$INS_OUT" "adduser"
assert_contains "plan: OpenRC networking enabled (§9.1 step 1)" "$INS_OUT" "rc-update add networking boot"
assert_contains "plan: network interfaces drop" "$INS_OUT" "etc/network/interfaces"
assert_not_contains "plan: systemd-networkd drop retired" "$INS_OUT" "20-alpine-fde.network"
# G-ST4/§8.2: single-disk crypttab is ONE root entry, NO password-cache
assert_contains "plan: crypttab with mandatory tpm2-device" "$INS_OUT" "luks,tpm2-device=auto,discard"
assert_not_contains "plan: single topology crypttab has NO password-cache (verbatim §8.2)" \
    "$(grep -F 'none luks,tpm2-device=auto,discard' <<<"$INS_OUT")" "password-cache"
# G-ST10/§8.2: btrfs rootflags + fail-closed pins verbatim
assert_contains "plan: G-ST10 rootflags=subvol=@ on the btrfs cmdline" "$INS_OUT" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
assert_contains "plan: fail-closed cmdline pins verbatim" "$INS_OUT" "rd.shell=0 rd.emergency=poweroff"
# ADR-13/§3.3: dracut is REJECTED on Alpine (mkinitfs is the initramfs
# generator, G-C8) — no dracut config residue may appear in the plan
assert_not_contains "plan: NO dracut conf drop (ADR-13: mkinitfs, not dracut)" "$INS_OUT" \
    "dracut.conf.d"
assert_not_contains "plan: NO omit_dracutmodules pin (ADR-13)" "$INS_OUT" "omit_dracutmodules"
assert_not_contains "plan: NO dracut hostonly pin (ADR-13)" "$INS_OUT" "hostonly=yes"
# G-ST1: subvol fstab forms
assert_contains "plan: fstab root subvol form" "$INS_OUT" "btrfs subvol=@,defaults 0 1"
assert_contains "plan: fstab @home subvol form" "$INS_OUT" "btrfs subvol=@home,defaults 0 2"
assert_contains "plan: fstab @snapshots subvol form" "$INS_OUT" "btrfs subvol=@snapshots,defaults 0 2"
assert_contains "plan: ESP fstab line" "$INS_OUT" "PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2"
assert_not_contains "plan: no ext4 fstab root line under btrfs default" "$INS_OUT" "/ ext4 defaults 0 1"
assert_contains "plan: bootctl install (ESP layout for the in-chroot build)" "$INS_OUT" "bootctl install"
assert_contains "plan: /etc/alpine-fde conf drop" "$INS_OUT" "etc/alpine-fde/alpine-fde.conf"
assert_contains "plan: kernel hooks installed (Alpine kernel-hooks.d layout)" "$INS_OUT" \
    "etc/kernel-hooks.d"
assert_contains "plan: tree staged to /opt/alpine-fde" "$INS_OUT" "opt/alpine-fde"
assert_contains "plan: teardown (umount + luks close)" "$INS_OUT" "cryptsetup close root-crypt"
# §4 topology recorded in the target conf (absent file = btrfs default, doc'd)
assert_contains "plan: conf records ROOT_FS=btrfs" "$INS_OUT" "ROOT_FS=btrfs"
assert_contains "plan: conf records BCACHE=0" "$INS_OUT" "BCACHE=0"
assert_contains "plan: conf records the default (absent file = btrfs/0)" "$INS_OUT" \
    "Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0"

# --- 2b. §9.1 in-chroot provisioning sequence (ADR-20 steps 1-9) --------------------
assert_contains "plan: §9.1 step 2 — pending baseline ON TARGET (baseline writer)" \
    "$INS_OUT" "inst_baseline_pending_write /mnt"
assert_not_contains "plan: NO host-baseline copy anywhere (§9.1)" "$INS_OUT" \
    "cp /etc/alpine-fde/baseline.json"
assert_contains "plan: §9.1 step 3 — in-chroot platform-key ceremony" "$INS_OUT" \
    "/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot"
assert_contains "plan: §9.1 step 4 — NVRAM enrollment db->KEK->PK via fw_auth_enroll" \
    "$INS_OUT" "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys"
assert_contains "plan: §9.1 step 5 — in-chroot ukictl build (boot manager + UKI)" \
    "$INS_OUT" "/opt/alpine-fde/bin/alpine-fde ukictl build"
# G-C24/§9.1 step 6: provisional TPM enrollment guest line (Mechanism B, PCR 11)
# item 27 extended (class-killer lint): the seal/token choreography consumes
# the LUKS2 HEADER (token_free_slot luksDump, luksAddKey, token import) — it
# must address the CONTAINER dev, never the decrypted mapper view
assert_contains "plan: §9.1 step 6 — provisional seal guest line (seal_provisional) targets the CONTAINER dev" \
    "$INS_OUT" 'seal_provisional /etc/alpine-fde/keys $d'
assert_contains "plan: §9.1 step 6 — provisional seal loop covers the PRIMARY CONTAINER dev" \
    "$INS_OUT" "for d in ${FAKEDISK}2; do"
assert_contains "plan: step 6 pin — provisional Mechanism B (PCR 11) -> keyslot 1" \
    "$INS_OUT" "provisional Mechanism B seal (PCR 11) -> keyslot 1"
assert_contains "plan: step 6 consumes the UKI .pcrsig (stage-1 build output)" \
    "$INS_OUT" "only-section=.pcrsig"
assert_contains "plan: step 6 authorizes luksAddKey with the ephemeral key" \
    "$INS_OUT" "token_add_keyslot"
# G-C25/§9.1 step 8: unfinalized banner to /etc/motd AND /etc/issue
assert_contains "plan: §9.1 step 8 — MOTD banner drop" "$INS_OUT" "PLAN  write  /etc/motd"
assert_contains "plan: §9.1 step 8 — issue banner drop" "$INS_OUT" "PLAN  write  /etc/issue"
assert_contains "plan: banner says NOT finalized (G-C25)" "$INS_OUT" "NOT finalized"
assert_contains "plan: banner directs to alpine-fde finalize" "$INS_OUT" "alpine-fde finalize"
assert_contains "plan: banner names the pending permanent recovery passphrase" "$INS_OUT" \
    "set your permanent recovery passphrase"
# G-C28/§9.1 step 9: state `installed` — written AFTER the banner
assert_contains "plan: §9.1 step 9 — state installed via istate_write" "$INS_OUT" \
    "inst_state_write installed"
# G-C26: NO OsIndications anywhere (firmware-trip flow retired)
assert_eq "plan: ZERO OsIndications records (G-C26)" "0" \
    "$(grep -c 'fw_osindications_set' <<<"$INS_OUT")"
assert_contains "plan: explicit ephemeral-key scrub record (I1, §9.1 teardown)" \
    "$INS_OUT" "rm -f <ephemeral-keyfile> # I1: ephemeral install key scrubbed"
assert_contains "plan: direct reboot record (ADR-20: no firmware trip)" "$INS_OUT" \
    "reboot # §9.1: direct reboot to disk (ADR-20)"
assert_contains "plan: efivars bound into the target (§9.1)" "$INS_OUT" \
    "mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars"
assert_contains "plan: teardown includes the efivars umount" "$INS_OUT" \
    "umount /mnt/dev /mnt/sys /mnt/proc /mnt/sys/firmware/efi/efivars"
# G-IL8: NO host-side signing machinery anywhere in the plan (the §3.3 target
# package names legitimately CONTAIN the substrings — pin the command records)
assert_eq "plan: zero sbsign command records (in-chroot build)" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*sbsign --' <<<"$INS_OUT")"
assert_eq "plan: zero ukify command records (in-chroot build)" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*ukify build' <<<"$INS_OUT")"
assert_eq "plan: zero sbverify records" "0" \
    "$(grep -Ec 'PLAN  (host|guest) .*sbverify' <<<"$INS_OUT")"
assert_not_contains "plan: no <signing-medium> placeholder" "$INS_OUT" "<signing-medium>"
assert_eq "plan: release.pem named ONLY by the ceremony record" "1" \
    "$(grep -c 'release.pem' <<<"$INS_OUT")"
# plan-order discipline (§9.1): baseline pending BEFORE the key ceremony; the
# CREDENTIAL ceremony (§9.1 step 4, ADR-20 amended) after the platform keys and
# BEFORE NVRAM enrollment; enrollment BEFORE the build; build BEFORE the
# provisional seal; banner BEFORE the state write (§9.1 step 8/9); teardown
# BEFORE the scrub; scrub BEFORE the reboot (G-C26)
line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }
I_BASE=$(line_no "$INS_OUT" "inst_baseline_pending_write")
I_KEYGEN=$(line_no "$INS_OUT" "provision stage1 --mode in-chroot")
I_CERU=$(line_no "$INS_OUT" "inst_ceremony_user_password")
I_CERR=$(line_no "$INS_OUT" "inst_ceremony_recovery")
I_CERK=$(line_no "$INS_OUT" "inst_ceremony_release_key")
I_ENROLL=$(line_no "$INS_OUT" "fw_auth_enroll")
I_BUILD=$(line_no "$INS_OUT" "ukictl build")
I_SEAL=$(line_no "$INS_OUT" "seal_provisional")
I_BANNER=$(line_no "$INS_OUT" "PLAN  write  /etc/motd")
I_STATE=$(line_no "$INS_OUT" "inst_state_write installed")
# anchor on the TEARDOWN record's `&& umount -R /mnt` — since item 26d the
# reset block also carries a bare `umount -R /mnt` (earlier in the plan)
I_TEARDOWN=$(line_no "$INS_OUT" "&& umount -R /mnt")
I_SCRUB=$(line_no "$INS_OUT" "rm -f <ephemeral-keyfile>")
I_REBOOT=$(line_no "$INS_OUT" "reboot #")
assert_eq "order: baseline pending before key ceremony" "1" "$(( I_BASE < I_KEYGEN ? 1 : 0 ))"
assert_eq "order: §9.1 step 4 — platform keys BEFORE the credential ceremony" "1" \
    "$(( I_KEYGEN > 0 && I_KEYGEN < I_CERR ? 1 : 0 ))"
assert_eq "order: item 12 — ceremony asks the recovery passphrase FIRST (1/3)" "1" \
    "$(( I_CERR > 0 && I_CERR < I_CERU ? 1 : 0 ))"
assert_eq "order: item 12 — user password (2/3) before release key (3/3)" "1" \
    "$(( I_CERU > 0 && I_CERU < I_CERK ? 1 : 0 ))"
assert_eq "order: ceremony BEFORE NVRAM enrollment" "1" \
    "$(( I_CERK > 0 && I_CERK < I_ENROLL ? 1 : 0 ))"
assert_eq "order: key ceremony before NVRAM enrollment" "1" "$(( I_KEYGEN < I_ENROLL ? 1 : 0 ))"
assert_eq "order: enrollment before ukictl build" "1" "$(( I_ENROLL < I_BUILD ? 1 : 0 ))"
assert_eq "order: build before provisional seal (the .pcrsig comes from the UKI)" "1" \
    "$(( I_BUILD < I_SEAL ? 1 : 0 ))"
assert_eq "order: provisional seal before banner" "1" "$(( I_SEAL < I_BANNER ? 1 : 0 ))"
assert_eq "order: G-C28 — banner BEFORE state write (§9.1 step 8/9)" "1" \
    "$(( I_BANNER < I_STATE ? 1 : 0 ))"
assert_eq "order: state write before teardown" "1" "$(( I_STATE < I_TEARDOWN ? 1 : 0 ))"
assert_eq "order: G-C26 — teardown before the ephemeral scrub" "1" \
    "$(( I_TEARDOWN < I_SCRUB ? 1 : 0 ))"
assert_eq "order: scrub before the direct reboot" "1" "$(( I_SCRUB < I_REBOOT ? 1 : 0 ))"
# apk order (REAL-INSTALL DEFECT 6, e2e-invisible class): the
# /etc/apk/repositories drop MUST PRECEDE the populate — apk resolves against
# the TARGET's <mnt>/etc/apk/repositories, so a populate-first plan sees zero
# repos and dies on a real server with `unable to select packages:
# alpine-base`. The real apk populate path is NOT exercised by local e2e (the
# harness stamps a pinned rootfs payload), so this ordering pin is the
# harness-level guard (mirrors the item-23 lint approach). The populate still
# precedes the in-chroot additions txn.
I_POPULATE=$(line_no "$INS_OUT" "apk add --root /mnt --initdb")
I_REPOS=$(line_no "$INS_OUT" "etc/apk/repositories")
I_TXN=$(line_no "$INS_OUT" "apk add --no-cache")
assert_eq "order: repositories drop BEFORE apk populate (real-install defect 6: apk resolves against the TARGET's repositories — populate-first dies 'unable to select packages: alpine-base'; real apk path is e2e-invisible, this pin is the harness-level guard)" "1" \
    "$(( I_REPOS > 0 && I_REPOS < I_POPULATE ? 1 : 0 ))"
assert_eq "order: apk populate before the additions txn" "1" "$(( I_POPULATE < I_TXN ? 1 : 0 ))"

# --- 2b-item26b. target DNS seed (real-install failure #3): the in-chroot apk
#         transaction resolves the mirror via the TARGET's /etc/resolv.conf —
#         absent on a fresh rootfs (the installer had ZERO resolv.conf
#         handling). A guarded host record copies the live env's resolver into
#         the target BEFORE the transaction; no-op + warn when the live env has
#         no resolv.conf.
assert_contains "26b: seeding record is a guarded host record (only-if-host-file-exists, warn branch, || : tail)" "$INS_OUT" \
    "if [ -f /etc/resolv.conf ]; then mkdir -p /mnt/etc && cp /etc/resolv.conf /mnt/etc/resolv.conf && echo 'alpine-fde: info: seeded target /etc/resolv.conf from the live env (in-chroot apk needs DNS)'; else echo 'alpine-fde: warn: live env has no /etc/resolv.conf — target DNS seed skipped (in-chroot apk may fail to resolve the mirror)'; fi || :"
I_SEED=$(line_no "$INS_OUT" "cp /etc/resolv.conf /mnt/etc/resolv.conf")
assert_eq "26b: target DNS seed precedes the in-chroot apk transaction" "1" \
    "$(( I_SEED > 0 && I_TXN > 0 && I_SEED < I_TXN ? 1 : 0 ))"
assert_eq "26b: target DNS seed also precedes the user-account guest step" "1" \
    "$(( I_SEED > 0 && I_SEED < "$(line_no "$INS_OUT" "adduser")" ? 1 : 0 ))"

# --- 2a. RESET of a previous FAILED attempt (user report: "install show reset
#         failed installation status, when install restarts again, so that new
#         install is able to continue") — runtime-guarded plan records at the
#         START of the disk-prep section, BEFORE partitioning; on a pristine
#         machine every guard is a no-op (busybox/ash, set -eu-safe).
# item 26d (user-directed): the mount teardown is ONE guarded RECURSIVE
# `umount -R <mnt>` — the old FIXED list (home/.snapshots/esp/root) missed the
# stale chroot binds an attempt that died mid-chroot leaves behind (/mnt/proc,
# /mnt/sys, /mnt/dev, /mnt/sys/firmware/efi/efivars); the installer's own
# teardown already relies on `umount -R` (accepted busybox dependency).
R_STATUS=$(line_no "$INS_OUT" "previous failed install detected")
R_REC=$(line_no "$INS_OUT" "recursively unmounted stale target tree /mnt'")
R_MAP=$(line_no "$INS_OUT" "closed stale mapper")
R_BCS=$(line_no "$INS_OUT" "stopped live bcache set")
O_SFD=$(line_no "$INS_OUT" "| sfdisk $FAKEDISK")
assert_eq "reset: guarded status record states a previous failed install is being reset" "1" \
    "$(( R_STATUS > 0 ? 1 : 0 ))"
assert_eq "reset: status record comes FIRST (before the teardown records)" "1" \
    "$(( R_STATUS > 0 && R_STATUS < R_REC ? 1 : 0 ))"
assert_eq "reset: ONE guarded RECURSIVE stale-tree umount record (item 26d — covers stale chroot binds the fixed list missed)" "1" \
    "$(( R_REC > 0 ? 1 : 0 ))"
assert_eq "reset: zero FIXED-list stale-mount umount records remain (item 26d: folded into the -R line)" "0" \
    "$(grep -c "unmounted stale mount /mnt" <<<"$INS_OUT")"
assert_eq "reset: recursive umount BEFORE the mapper closes" "1" \
    "$(( R_REC < R_MAP ? 1 : 0 ))"
assert_eq "reset: live-bcache STOP record after the mapper closes (bcache teardown IS in scope: a stale live set must release the devices before the dd wipe)" "1" \
    "$(( R_MAP < R_BCS ? 1 : 0 ))"
assert_eq "reset: the WHOLE reset block precedes partitioning (a re-run can continue)" "1" \
    "$(( R_STATUS > 0 && R_BCS > 0 && R_BCS < O_SFD ? 1 : 0 ))"
# guard text pinned verbatim: runtime `mountpoint` probe + warn-branch + the
# `|| :` no-op tail (expected-nonzero probes are guarded, never bare, under
# the repo's set -eu norm); records survive BOTH the host eval path and the
# emitted ash guest script
assert_contains "reset: recursive umount is runtime-guarded + no-op-safe (mountpoint probe, warn branch, || : tail; -R primary teardown, item 26d)" "$INS_OUT" \
    "if mountpoint -q /mnt 2>/dev/null; then umount -R /mnt && echo 'alpine-fde: info: reset: recursively unmounted stale target tree /mnt' || echo 'alpine-fde: warn: reset: could not recursively unmount stale target tree /mnt'; fi || :"
assert_contains "reset: status record guard probes mounts AND mapper nodes AND live bcache sets" "$INS_OUT" \
    "if mountpoint -q /mnt 2>/dev/null || ls /dev/mapper/root[0-9]* >/dev/null 2>&1 || [ -e /dev/mapper/root-crypt ] || ls /sys/fs/bcache/*/ >/dev/null 2>&1; then echo 'alpine-fde: info: reset: previous failed install detected"
assert_contains "reset: mapper loop globs stale rootN + root-crypt, name-stripped, existence-guarded" "$INS_OUT" \
    'for m in /dev/mapper/root[0-9]* /dev/mapper/root-crypt; do [ -e "$m" ] || continue; cryptsetup close "${m#/dev/mapper/}"'
assert_contains "reset: mapper close carries the warn branch + || : no-op tail" "$INS_OUT" \
    "could not close stale mapper"
# live bcache sets from the failed attempt MUST be stopped in the reset block
# (before partitioning), NOT inside the bcache flow: echoing the set UUID into
# /sys/fs/bcache/<uuid>/stop releases the backing device — wiping a CLAIMED
# backing device leaves the in-kernel set diverged, and the stale set can
# re-register the device mid-install. The dd head+tail superblock wipe in
# front of make-bcache (7619960) then operates on a RELEASED device.
assert_contains "reset: bcache-stop loop writes each set UUID into its own stop file (dirs only — the register control file is skipped)" "$INS_OUT" \
    'for d in /sys/fs/bcache/*/; do [ -f "${d}stop" ] || continue; u="${d%/}"; echo "${u##*/}" > "$u/stop"'
assert_contains "reset: bcache-stop reports what it stopped" "$INS_OUT" "stopped live bcache set"
assert_contains "reset: bcache-stop carries the warn branch + || : no-op tail" "$INS_OUT" \
    "could not stop bcache set"

# --- 2c. NO_REBOOT seam (CI) ---------------------------------------------------------
ALPINE_FDE_INSTALL_NO_REBOOT=1 run_install --disk "$FAKEDISK"
assert_eq "NO_REBOOT=1: rc 0" "0" "$INS_RC"
assert_not_contains "NO_REBOOT=1: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK" --no-reboot
assert_eq "--no-reboot flag: rc 0" "0" "$INS_RC"
assert_not_contains "--no-reboot flag: reboot record suppressed" "$INS_OUT" "reboot #"
run_install --disk "$FAKEDISK"
assert_contains "default: reboot record present" "$INS_OUT" "reboot #"

# --- 3. G-ST1b: --fs ext4 keeps the flat path verbatim -------------------------------
run_install --disk "$FAKEDISK" --fs ext4
assert_eq "ext4 dry-run rc 0" "0" "$INS_RC"
assert_contains "ext4: mkfs.ext4 verbatim" "$INS_OUT" "mkfs.ext4 -F -U"
assert_contains "ext4: flat mount verbatim" "$INS_OUT" \
    "mount /dev/mapper/root-crypt /mnt && mkdir -p /mnt/efi && mount"
assert_not_contains "ext4: no mkfs.btrfs" "$INS_OUT" "mkfs.btrfs"
assert_not_contains "ext4: no subvolume records" "$INS_OUT" "btrfs subvolume"
assert_not_contains "ext4: no subvol fstab" "$INS_OUT" "subvol="
assert_not_contains "ext4: no rootflags (legacy cmdline verbatim)" "$INS_OUT" "rootflags"
assert_eq "ext4: legacy cmdline pins verbatim" "1" \
    "$(grep -Ec 'root=UUID=[0-9a-f-]{36} ro rd.shell=0 rd.emergency=poweroff' <<<"$INS_OUT")"
assert_contains "ext4: legacy fstab verbatim" "$INS_OUT" "/ ext4 defaults 0 1"
assert_contains "ext4: conf records ROOT_FS=ext4" "$INS_OUT" "ROOT_FS=ext4"
APK_TXN_EXT4=$(grep -m1 'apk add --no-cache' <<<"$INS_OUT")
assert_contains "ext4: apk txn includes e2fsprogs" "$APK_TXN_EXT4" "e2fsprogs"
assert_not_contains "ext4: apk txn has no btrfs-progs" "$APK_TXN_EXT4" "btrfs-progs"
# item 26d: the reset mount teardown is topology-independent now — ONE
# recursive record covers ext4 exactly as it covers btrfs subvols
assert_contains "ext4: reset keeps the single guarded recursive umount (item 26d)" "$INS_OUT" \
    "recursively unmounted stale target tree /mnt'"

# --- 4. G-ST2/ADR-17: --bcache single-backing hybrid topology ------------------------
CACHEDEV=$T/cache.img
: >"$CACHEDEV"
run_install --disk "$FAKEDISK" --bcache "$CACHEDEV"
assert_eq "bcache dry-run rc 0" "0" "$INS_RC"
assert_contains "bcache: cache dev partitioned (ESP p1 + cache p2)" "$INS_OUT" 'name="cache"'
# PHYSICAL-MEDIA BLOCK (real-install defects 1-4): modules are not auto-loaded
# on a physical boot, /dev needs coldplug after sfdisk, stale superblocks make
# make-bcache refuse the device, and the backing device is the WHOLE disk.
assert_not_contains "bcache: backing dev NOT partitioned (backing = WHOLE disk, bcache semantics)" \
    "$INS_OUT" 'name="backing"'
assert_contains "bcache: modprobe bcache before any bcache work" "$INS_OUT" \
    "if command -v modprobe >/dev/null 2>&1; then modprobe bcache; fi"
assert_contains "bcache: modprobe btrfs before any btrfs work" "$INS_OUT" \
    "if command -v modprobe >/dev/null 2>&1; then modprobe btrfs; fi"
assert_contains "bcache: early coldplug (mdev -s) before partitioning" "$INS_OUT" "mdev -s"
O_BCMOD=$(line_no "$INS_OUT" "modprobe bcache")
O_BTMOD=$(line_no "$INS_OUT" "modprobe btrfs")
O_COLD1=$(line_no "$INS_OUT" "mdev -s")
O_CSFD=$(line_no "$INS_OUT" "sfdisk $CACHEDEV")
O_COLD2=$(line_no "$INS_OUT" "partition device nodes must exist before make-bcache")
O_WIPEC=$(line_no "$INS_OUT" "dd if=/dev/zero of=${CACHEDEV}2 bs=1M count=1")
O_WIPEB=$(line_no "$INS_OUT" "dd if=/dev/zero of=$FAKEDISK bs=1M count=1")
O_MAKEC=$(line_no "$INS_OUT" "make-bcache -C")
assert_eq "bcache: order — modprobe bcache before modprobe btrfs before coldplug" "1" \
    "$(( O_BCMOD > 0 && O_BCMOD < O_BTMOD && O_BTMOD < O_COLD1 ? 1 : 0 ))"
assert_eq "bcache: order — modules + coldplug BEFORE partitioning" "1" \
    "$(( O_COLD1 > 0 && O_COLD1 < O_CSFD ? 1 : 0 ))"
assert_eq "bcache: order — post-sfdisk coldplug BEFORE the superblock wipe" "1" \
    "$(( O_CSFD > 0 && O_CSFD < O_COLD2 && O_COLD2 < O_WIPEC ? 1 : 0 ))"
assert_eq "bcache: order — superblock wipes BEFORE make-bcache (defect 3)" "1" \
    "$(( O_WIPEC > 0 && O_WIPEB > 0 && O_WIPEB < O_MAKEC && O_WIPEC < O_MAKEC ? 1 : 0 ))"
# reset-block bcache stop precedes the dd wipe: a stale LIVE set must release
# the backing device first (wiping a claimed device leaves the in-kernel set
# diverged; the stale set can re-register the device mid-install)
O_BCSTOP=$(line_no "$INS_OUT" "stopped live bcache set")
assert_eq "bcache: order — stale-set STOP (reset block) BEFORE the superblock wipe" "1" \
    "$(( O_BCSTOP > 0 && O_BCSTOP < O_WIPEC ? 1 : 0 ))"
assert_contains "bcache: stale-superblock wipe covers the cache p2 TAIL" "$INS_OUT" \
    "dd if=/dev/zero of=${CACHEDEV}2 bs=1M count=1 seek="
assert_contains "bcache: stale-superblock wipe (head) on the WHOLE backing disk" "$INS_OUT" \
    "dd if=/dev/zero of=$FAKEDISK bs=1M count=1 && dd if=/dev/zero of=$FAKEDISK bs=1M count=1 seek="
assert_contains "bcache: make-bcache -C on cache p2" "$INS_OUT" "make-bcache -C ${CACHEDEV}2"
assert_eq "bcache: make-bcache -B on the WHOLE backing disk" "1" \
    "$(grep -Ec "make-bcache -B $FAKEDISK( |$)" <<<"$INS_OUT")"
assert_not_contains "bcache: NO make-bcache -B on the backing PARTITION (defect: p1)" "$INS_OUT" \
    "make-bcache -B ${FAKEDISK}1"
assert_contains "bcache: WHOLE backing disk registered" "$INS_OUT" \
    "echo $FAKEDISK > /sys/fs/bcache/register"
assert_not_contains "bcache: NO backing-p1 registration" "$INS_OUT" \
    "echo ${FAKEDISK}1 > /sys/fs/bcache/register"
assert_contains "bcache: cache set attached to bcache0" "$INS_OUT" \
    "/sys/block/bcache0/bcache/attach"
assert_contains "bcache: WRITETHROUGH pinned (literal, ADR-17)" "$INS_OUT" \
    "echo writethrough > /sys/block/bcache0/bcache/cache_mode"
assert_eq "bcache: LUKS2 ON TOP of /dev/bcache0 (key invariant)" "1" \
    "$(grep -Ec 'luksFormat --type luks2 [^ ]*.* /dev/bcache0' <<<"$INS_OUT")"
assert_contains "bcache: ESP lands on the CACHE dev (§4.1 topology 2)" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${CACHEDEV}1"
# ADR-13: the bcache driver/kernel-args intent is carried by the mkinitfs
# features.d inventory (bcache.ko + 69-bcache.rules, hooks/mkinitfs/features.d/
# alpine-fde.files) and the cmdline builder — NOT by a dracut conf drop
assert_not_contains "bcache: NO dracut 20-bcache.conf drop (ADR-13)" "$INS_OUT" \
    "dracut.conf.d/20-bcache.conf"
assert_not_contains "bcache: NO dracut force_drivers pin" "$INS_OUT" "force_drivers"
assert_contains "bcache: conf records BCACHE=1" "$INS_OUT" "BCACHE=1"
APK_TXN_BC=$(grep -m1 'apk add --no-cache' <<<"$INS_OUT")
assert_contains "bcache: apk txn includes bcache-tools" "$APK_TXN_BC" "bcache-tools"
BC_CRYPTTAB=$(grep -F 'none luks,tpm2-device=auto,discard' <<<"$INS_OUT")
assert_contains "bcache: crypttab is a single root entry (NO password-cache)" "$BC_CRYPTTAB" \
    "root UUID="
assert_not_contains "bcache: crypttab has no password-cache (verbatim §8.2)" "$BC_CRYPTTAB" "password-cache"
assert_not_contains "bcache: no RAID1 mkfs" "$INS_OUT" "\-d raid1"
# G-C24: single-mapper provisional seal line follows the build
# item 27 extended: the seal addresses the CONTAINER (/dev/bcache0), not the mapper
assert_contains "bcache: provisional seal addresses the CONTAINER via the loop var (loop list carries /dev/bcache0 — item 27)" "$INS_OUT" \
    'seal_provisional /etc/alpine-fde/keys $d'
assert_contains "bcache: provisional seal loop covers the single container (/dev/bcache0 — item 27)" "$INS_OUT" \
    "for d in /dev/bcache0; do"

# --- 4b. G-C27/§4.1 topology 4: MULTI-BACKING bcache (2 backings) --------------------
DISKB=$T/diskb.img
: >"$DISKB"
run_install --disk "$FAKEDISK" --disk "$DISKB" --bcache "$CACHEDEV"
assert_eq "bcache-multi dry-run rc 0" "0" "$INS_RC"
assert_contains "bcache-multi: cache dev partitioned (ESP p1 + shared cache p2)" "$INS_OUT" \
    'name="cache"'
assert_eq "bcache-multi: backing disks NOT partitioned (backing = WHOLE disk)" "0" \
    "$(grep -c 'name=\"backing\"' <<<"$INS_OUT")"
assert_contains "bcache-multi: make-bcache -C on the shared cache set" "$INS_OUT" \
    "make-bcache -C ${CACHEDEV}2"
assert_eq "bcache-multi: make-bcache -B on the WHOLE first backing disk" "1" \
    "$(grep -Ec "make-bcache -B $FAKEDISK( |$)" <<<"$INS_OUT")"
assert_eq "bcache-multi: make-bcache -B on the WHOLE second backing disk" "1" \
    "$(grep -Ec "make-bcache -B $DISKB( |$)" <<<"$INS_OUT")"
assert_eq "bcache-multi: exactly 2 make-bcache -B records (2 backings)" "2" \
    "$(grep -c 'make-bcache -B ' <<<"$INS_OUT")"
O_BCOLD2=$(line_no "$INS_OUT" "partition device nodes must exist before make-bcache")
O_BWIPE2=$(line_no "$INS_OUT" "dd if=/dev/zero of=${CACHEDEV}2 bs=1M count=1")
O_BMAKE2=$(line_no "$INS_OUT" "make-bcache -C")
assert_eq "bcache-multi: order — post-sfdisk coldplug + wipe BEFORE make-bcache (defects 2+3)" "1" \
    "$(( O_BCOLD2 > 0 && O_BCOLD2 < O_BWIPE2 && O_BWIPE2 < O_BMAKE2 ? 1 : 0 ))"
assert_not_contains "bcache-multi: NO make-bcache -B on a backing PARTITION (defect: p1)" "$INS_OUT" \
    "make-bcache -B ${FAKEDISK}1"
assert_eq "bcache-multi: stale-superblock wipe records cover EVERY member (cache p2 + both disks, 3)" "3" \
    "$(grep -c 'dd if=/dev/zero of=' <<<"$INS_OUT")"
assert_contains "bcache-multi: WHOLE first backing disk registered" "$INS_OUT" \
    "echo $FAKEDISK > /sys/fs/bcache/register"
assert_contains "bcache-multi: WHOLE second backing disk registered" "$INS_OUT" \
    "echo $DISKB > /sys/fs/bcache/register"
assert_not_contains "bcache-multi: NO backing-p1 registration" "$INS_OUT" \
    "echo ${FAKEDISK}1 > /sys/fs/bcache/register"
assert_contains "bcache-multi: bcache0 attached to the shared cset (writethrough)" "$INS_OUT" \
    "/sys/block/bcache0/bcache/attach"
assert_contains "bcache-multi: bcache1 attached to the shared cset (writethrough)" "$INS_OUT" \
    "/sys/block/bcache1/bcache/attach"
assert_eq "bcache-multi: writethrough pinned on BOTH members" "2" \
    "$(grep -o 'echo writethrough > /sys/block/bcache' <<<"$INS_OUT" | wc -l)"
assert_eq "bcache-multi: one independent LUKS2 container per /dev/bcacheN" "2" \
    "$(grep -Ec 'luksFormat --type luks2 [^ ]*.* /dev/bcache[01]($| )' <<<"$INS_OUT")"
assert_eq "bcache-multi: bcache0 opened as root1" "1" \
    "$(grep -Ec 'open +/dev/bcache0 root1($| )' <<<"$INS_OUT")"
assert_eq "bcache-multi: bcache1 opened as root2" "1" \
    "$(grep -Ec 'open +/dev/bcache1 root2$' <<<"$INS_OUT")"
assert_contains "bcache-multi: btrfs raid1 pool across the opened mappers" "$INS_OUT" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "bcache-multi: ESP formatted ONCE, ONLY on the cache dev" "1" \
    "$(grep -c 'mkfs.vfat -F 32' <<<"$INS_OUT")"
assert_contains "bcache-multi: ESP on the cache dev p1" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${CACHEDEV}1"
assert_not_contains "bcache-multi: NO ESP on backing disks" "$INS_OUT" \
    "mkfs.vfat -F 32 -n EFI ${FAKEDISK}1"
assert_eq "bcache-multi: per-member crypttab root1 (password-cache=yes)" "1" \
    "$(grep -Ec 'root1 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "bcache-multi: per-member crypttab root2 (password-cache=yes)" "1" \
    "$(grep -Ec 'root2 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "bcache-multi: target metadata carries BOTH member uuids" "1" \
    "$(grep -Ec 'inst_resolve_target_metadata \S+ /mnt [0-9a-f-]{36} [0-9a-f-]{36}$' <<<"$INS_OUT")"
assert_contains "bcache-multi: teardown closes both members" "$INS_OUT" \
    "cryptsetup close root1 && cryptsetup close root2"
assert_contains "bcache-multi: provisional seal loop covers both member CONTAINERS (bcache0+bcache1, item 27)" "$INS_OUT" \
    "for d in /dev/bcache0 /dev/bcache1; do"
assert_contains "bcache-multi: conf records BCACHE=1" "$INS_OUT" "BCACHE=1"

# --- 5. G-ST3: repeatable --disk (no bcache) = Btrfs RAID1 ---------------------------
DISK2=$T/disk2.img
: >"$DISK2"
run_install --disk "$FAKEDISK" --disk "$DISK2"
assert_eq "raid1 dry-run rc 0" "0" "$INS_RC"
assert_contains "raid1: primary partitioned ESP p1 + LUKS p2" "$INS_OUT" "sfdisk $FAKEDISK"
assert_contains "raid1: secondary partitioned (single root partition)" "$INS_OUT" "sfdisk $DISK2"
assert_not_contains "raid1: secondary has NO ESP partition" "$INS_OUT" "type=uefi*$DISK2"
assert_eq "raid1: exactly 2 luksFormat records (per member)" "2" \
    "$(grep -c 'luksFormat --type luks2' <<<"$INS_OUT")"
assert_contains "raid1: mkfs.btrfs raid1 data+metadata" "$INS_OUT" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "raid1: primary mapper is root1" "1" \
    "$(grep -Ec 'cryptsetup open .* root1$' <<<"$INS_OUT")"
assert_eq "raid1: secondary mapper is root2" "1" \
    "$(grep -Ec 'cryptsetup open .* root2$' <<<"$INS_OUT")"
assert_eq "raid1: crypttab root1 entry with password-cache=yes" "1" \
    "$(grep -Ec 'root1 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "raid1: crypttab root2 entry with password-cache=yes" "1" \
    "$(grep -Ec 'root2 UUID=[0-9a-f-]{36} none luks,tpm2-device=auto,password-cache=yes,discard' <<<"$INS_OUT")"
assert_eq "raid1: ESP formatted ONCE (primary only)" "1" \
    "$(grep -c 'mkfs.vfat -F 32' <<<"$INS_OUT")"
assert_contains "raid1: ESP on the primary disk p1" "$INS_OUT" "mkfs.vfat -F 32 -n EFI ${FAKEDISK}1"
assert_eq "raid1: target metadata carries BOTH member uuids" "1" \
    "$(grep -Ec 'inst_resolve_target_metadata \S+ /mnt [0-9a-f-]{36} [0-9a-f-]{36}$' <<<"$INS_OUT")"
assert_contains "raid1: teardown closes both members" "$INS_OUT" \
    "cryptsetup close root1 && cryptsetup close root2"
assert_eq "raid1: single topology crypttab entry (root, no suffix) absent" "0" \
    "$(grep -Ec 'PLAN    \| root UUID=' <<<"$INS_OUT")"
assert_contains "raid1: provisional seal loop covers both member CONTAINERS (primary p2 + secondary p1, item 27)" "$INS_OUT" \
    "for d in ${FAKEDISK}2 ${DISK2}1; do"

# --- 6. dry-run has no side effects -----------------------------------------------------
CSUM_BEFORE=$(sha256sum <"$FAKEDISK")
run_install --disk "$FAKEDISK"
CSUM_AFTER=$(sha256sum <"$FAKEDISK")
assert_eq "fake disk untouched by dry-run" "$CSUM_BEFORE" "$CSUM_AFTER"
assert_not_contains "dry-run: no real ephemeral keyfile path leaks into the plan (M-01 tmpfs seam)" \
    "$INS_OUT" "/dev/shm/alpine-fde-ephkey"
assert_contains "dry-run: ephemeral keyfile is a placeholder" "$INS_OUT" "<ephemeral-keyfile>"

# --- 7. L-06: ALPINE_FDE_YES only counts as consent when it is exactly "1" -----
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_INSTALL_NO_REBOOT=1
ALPINE_FDE_YES=0 run_install --disk "$FAKEDISK"
assert_eq "L-06: ALPINE_FDE_YES=0 is NOT consent -> usage rc 2" "2" "$INS_RC"
assert_contains "L-06: refusal explains the --yes requirement" "$INS_OUT" "requires --yes"
ALPINE_FDE_YES=no run_install --disk "$FAKEDISK"
assert_eq "L-06: ALPINE_FDE_YES=no is NOT consent -> usage rc 2" "2" "$INS_RC"
unset ALPINE_FDE_INSTALL_RUNNER ALPINE_FDE_INSTALL_NO_REBOOT

# --- 8. M-02: injected operator inputs die at the boundary (usage rc 2) --------
run_install --disk "$FAKEDISK" --user 'x; rm -rf /'
assert_eq "M-02: injected --user -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: error names the invalid user" "$INS_OUT" "invalid --user"
run_install --disk '/dev/sda; reboot -f'
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$INS_RC"
ALPINE_FDE_ESP_SIZE='512M; reboot' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected ESP size -> usage rc 2" "2" "$INS_RC"
ALPINE_FDE_MIRROR='http://evil.example/alpine; rm -rf /' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected mirror -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --bcache '/dev/nvme0n1; reboot -f'
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$INS_RC"
# WR-01: --keydir/ALPINE_FDE_KEYDIR rides into eval'd records — same rule
ALPINE_FDE_KEYDIR='/x; touch /tmp/pwned' run_install --disk "$FAKEDISK"
assert_eq "M-02: injected keydir (env ALPINE_FDE_KEYDIR) -> usage rc 2" "2" "$INS_RC"
assert_contains "M-02: injected keydir error names the variable" "$INS_OUT" "ALPINE_FDE_KEYDIR"

# --- 9. G-C23: ephemeral-key staging contract (direct call, THIS shell) --------
# unattended: openssl rand (>=256-bit) staged under the tmpfs seam, mode 0600,
# byte-stable for luksFormat/open/--key-file consumers; dry-run stages nothing.
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_INSTALL_RUNNER
export ALPINE_FDE_YES=1
export ALPINE_FDE_TMPDIR=$T
ALPINE_FDE_INSTALL_RUNNER=dry-run inst_stage_ephemeral_key
assert_eq "G-C23: dry-run stages NOTHING (empty _IME_KEYFILE)" "1" \
    "$([ -z "${_IME_KEYFILE:-}" ] && echo 1 || echo 0)"
inst_stage_ephemeral_key
_EPH_RC=0
assert_rc "G-C23: direct call returns rc 0" 0 inst_stage_ephemeral_key
assert_eq "G-C23: resolver stages _IME_KEYFILE (non-empty)" "1" \
    "$([ -n "${_IME_KEYFILE:-}" ] && echo 1 || echo 0)"
assert_eq "G-C23: key staged under the tmpfs seam (ALPINE_FDE_TMPDIR)" "1" \
    "$([[ "${_IME_KEYFILE:-}" == "$T"/alpine-fde-ephkey.* ]] && echo 1 || echo 0)"
assert_eq "G-C23: key-file mode 0600" "600" "$(stat -c '%a' "${_IME_KEYFILE:-}")"
assert_eq "G-C23: key material is 256-bit hex (64 chars, openssl rand -hex 32)" "64" \
    "$(wc -c <"${_IME_KEYFILE:-/dev/null}" | tr -d '[:space:]')"
assert_eq "G-C23: _ime_kf carrier matches the staged key-file" "${_IME_KEYFILE:-}" "${_ime_kf:-}"
rm -f "${_IME_KEYFILE:-}"
unset _IME_KEYFILE _ime_kf ALPINE_FDE_TMPDIR
trap cleanup EXIT # the resolver re-armed the EXIT trap; restore fixture cleanup
unset ALPINE_FDE_INSTALL_RUNNER ALPINE_FDE_YES

# --- 9b. §8.1 provision row / ADR-18: --keydir is CONSUMED (staged from the ---
#         signing medium, NO in-chroot keygen) — README "provision stage1 on
#         USB -> install --keydir" flow
KEYDIR=$T/medium-keys
mkdir -p "$KEYDIR"
for f in release.pem release.pub release.crt db.cert.der kek.cert.der pk.cert.der \
    db.esl kek.esl pk.esl db.auth kek.auth pk.auth; do
    printf 'key-material' >"$KEYDIR/$f"
done
ALPINE_FDE_KEYDIR=$KEYDIR run_install --disk "$FAKEDISK" --keydir "$KEYDIR"
assert_eq "keydir: dry-run rc 0" "0" "$INS_RC"
assert_contains "keydir: plan stages release.pem FROM the medium onto the encrypted root" \
    "$INS_OUT" "cp $KEYDIR/release.pem"
assert_contains "keydir: plan stages the db.auth packet (fw_auth_enroll input)" \
    "$INS_OUT" "$KEYDIR/db.auth"
assert_contains "keydir: staged keys dir locked to 0700" "$INS_OUT" "chmod 700 /mnt/etc/alpine-fde/keys"
assert_contains "keydir: staged key files locked to 0600" "$INS_OUT" "chmod 600 /mnt/etc/alpine-fde/keys"
assert_not_contains "keydir: NO in-chroot keygen when the medium supplies the keys" \
    "$INS_OUT" "provision stage1 --mode in-chroot"
assert_contains "keydir: NVRAM enrollment still consumes the staged packets" "$INS_OUT" \
    "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys"
K_STAGE=$(line_no "$INS_OUT" "cp $KEYDIR/release.pem")
K_ENROLL=$(line_no "$INS_OUT" "fw_auth_enroll")
assert_eq "keydir: staging BEFORE NVRAM enrollment (plan order)" "1" \
    "$(( K_STAGE > 0 && K_ENROLL > K_STAGE ? 1 : 0 ))"
assert_not_contains "keydir: key material NEVER staged to the ESP" "$INS_OUT" \
    "cp $KEYDIR/.*efi"
# missing/invalid key material fails closed BEFORE any plan record exists
ALPINE_FDE_KEYDIR=$KEYDIR run_install --disk "$FAKEDISK" --keydir "$T/no-such-dir"
assert_eq "keydir: nonexistent medium dir -> usage rc 2" "2" "$INS_RC"
rm -f "$KEYDIR/kek.auth"
ALPINE_FDE_KEYDIR=$KEYDIR run_install --disk "$FAKEDISK" --keydir "$KEYDIR"
assert_eq "keydir: missing key artifact (kek.auth) -> usage rc 2" "2" "$INS_RC"
assert_contains "keydir: error names the missing artifact" "$INS_OUT" "kek.auth"
printf 'key-material' >"$KEYDIR/kek.auth"

# --- 9c. §8.1 flags contract: `install --esp` sets the ESP mount point -------
#         (relative to the target root; flows into fstab, mount plan,
#         ESP_PATH, bootctl and the UKI extraction path)
run_install --disk "$FAKEDISK" --esp /boot/efi
assert_eq "esp: --esp /boot/efi dry-run rc 0" "0" "$INS_RC"
assert_contains "esp: fstab entry uses the flag mount point" "$INS_OUT" \
    "PARTUUID=<esp-partuuid> /boot/efi vfat umask=0077 0 2"
assert_contains "esp: ESP_PATH persisted from the flag" "$INS_OUT" "ESP_PATH=/boot/efi"
assert_contains "esp: mount plan creates the flag mount point" "$INS_OUT" \
    "mkdir -p /mnt/home /mnt/.snapshots /mnt/boot/efi"
assert_contains "esp: ESP mounted at the flag mount point" "$INS_OUT" \
    "mount $FAKEDISK"$(printf '%s' "1")" /mnt/boot/efi"
assert_contains "esp: bootctl install targets the flag mount point" "$INS_OUT" \
    "bootctl install --esp-path=/boot/efi --boot-path=/boot/efi"
assert_contains "esp: UKI extraction reads the flag mount point" "$INS_OUT" \
    "/boot/efi/EFI/Linux/alpine-fde-*.efi"
# dispatcher global --esp (env ALPINE_FDE_ESP) is consumed too
ALPINE_FDE_ESP=/boot/efi run_install --disk "$FAKEDISK"
assert_eq "esp: env ALPINE_FDE_ESP dry-run rc 0" "0" "$INS_RC"
assert_contains "esp: env ALPINE_FDE_ESP flows into ESP_PATH" "$INS_OUT" "ESP_PATH=/boot/efi"
# invalid values fail loudly rc 2 BEFORE any plan record
run_install --disk "$FAKEDISK" --esp /
assert_eq "esp: / rejected -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --esp boot/efi
assert_eq "esp: value without leading / rejected -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --esp '/boot efi'
assert_eq "esp: value with a space rejected -> usage rc 2" "2" "$INS_RC"
run_install --disk "$FAKEDISK" --esp ''
assert_eq "esp: empty value rejected -> usage rc 2" "2" "$INS_RC"
# default unchanged: /efi
run_install --disk "$FAKEDISK"
assert_contains "esp: default stays /efi (fstab)" "$INS_OUT" \
    "PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2"
assert_contains "esp: default stays /efi (ESP_PATH)" "$INS_OUT" "ESP_PATH=/efi"

# --- 10. package-list lint (§3.3, topology-conditional) ------------------------
PKG_LIST=$(install_package_list)
REQUIRED="cryptsetup systemd-boot systemd-efistub ukify ukify-kernel-hook py3-pefile mkinitfs linux-lts tpm2-tools tpm2-tss-policy tpm2-tss-tcti-device sbsigntool openssl jq doas btrfs-progs"
for want in $REQUIRED; do
    FOUND=0
    for w in $PKG_LIST; do
        [ "$w" = "$want" ] && FOUND=1
    done
    assert_eq "package list (default) contains $want" "1" "$FOUND"
done
for bad in debootstrap apt apt-get dpkg systemd-cryptsetup dracut linux-image-amd64 \
    e2fsprogs bcache-tools grub shim-signed initramfs-tools clevis sudo zram-init; do
    case " $PKG_LIST " in
        *" $bad "*) assert_eq "package list (default) must NOT contain $bad" "absent" "present" ;;
        *) assert_eq "package list (default) must NOT contain $bad" "absent" "absent" ;;
    esac
done
PKG_EXT4=$(INST_ROOT_FS=ext4 install_package_list)
case " $PKG_EXT4 " in
    *e2fsprogs*) assert_eq "package list (--fs ext4) contains e2fsprogs" "1" "1" ;;
    *) assert_eq "package list (--fs ext4) contains e2fsprogs" "1" "0" ;;
esac
case " $PKG_EXT4 " in
    *btrfs-progs*) assert_eq "package list (--fs ext4) has no btrfs-progs" "0" "1" ;;
    *) assert_eq "package list (--fs ext4) has no btrfs-progs" "0" "0" ;;
esac
PKG_BC=$(INST_BCACHE=1 install_package_list)
case " $PKG_BC " in
    *bcache-tools*) assert_eq "package list (--bcache) contains bcache-tools" "1" "1" ;;
    *) assert_eq "package list (--bcache) contains bcache-tools" "1" "0" ;;
esac

# --- 11. G-I9 (§13): ESP sizing — measured UKI x retention + headroom ----------
MIB=$((1024 * 1024))
assert_eq "sizing: 96MiB UKI, retention 3, 64MiB headroom -> 352M" "352M" \
    "$(inst_esp_size_compute $((96 * MIB)) 3 $((64 * MIB)))"
assert_eq "sizing: unmeasurable (empty) -> 512M default" "512M" \
    "$(inst_esp_size_compute '' 3 $((64 * MIB)))"
printf 'uki-bytes' >"$T/uki.efi"
assert_eq "sizing: measured via probe file" "65M" \
    "$(ALPINE_FDE_UKI_FILE=$T/uki.efi inst_esp_size)"
assert_eq "sizing: env override wins over measurement" "1G" \
    "$(ALPINE_FDE_UKI_FILE=$T/uki.efi ALPINE_FDE_ESP_SIZE=1G inst_esp_size)"

# --- 12. help text (G-C23/C24/C25/C26/C27) --------------------------------------
HELP_OUT=$("$REPO/bin/alpine-fde" install --help 2>&1)
HELP_RC=$?
assert_eq "install --help rc 0" "0" "$HELP_RC"
assert_contains "help: --fs documented" "$HELP_OUT" "--fs btrfs|ext4"
assert_contains "help: --bcache documented" "$HELP_OUT" "--bcache CACHE_DEV"
assert_contains "help: repeatable --disk documented" "$HELP_OUT" "--disk DEVICE2"
assert_contains "help: --no-reboot documented" "$HELP_OUT" "--no-reboot"
assert_contains "help: SetupMode gate documented" "$HELP_OUT" "SetupMode"
assert_contains "help: btrfs default documented" "$HELP_OUT" "Btrfs root with subvolumes"
assert_contains "help: unattended contract documented (unattended until reboot)" "$HELP_OUT" \
    "unattended"
assert_contains "help: credential ceremony documented (ADR-20 amended)" "$HELP_OUT" \
    "credential ceremony"
assert_contains "help: no-echo prompts documented" "$HELP_OUT" "no-echo"
assert_contains "help: NO credential flag/env seam documented" "$HELP_OUT" "no flag"
assert_contains "help: ephemeral install key documented" "$HELP_OUT" "ephemeral"
assert_contains "help: direct reboot documented (no firmware trip)" "$HELP_OUT" "direct reboot"
assert_contains "help: finalize handoff documented" "$HELP_OUT" "finalize"

# --- 13. pre-upgrade stub (ext4 root -> graceful skip rc 0 per ADR-13) ---------
PRE_OUT=$("$REPO/bin/alpine-fde" pre-upgrade 2>&1)
PRE_RC=$?
assert_eq "pre-upgrade skips ext4 root gracefully (rc 0)" "0" "$PRE_RC"
assert_contains "pre-upgrade explains ext4 stance" "$PRE_OUT" "btrfs"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
