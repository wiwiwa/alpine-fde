#!/usr/bin/env bash
# tests/unit/install_chroot_plan.sh — `debian-fde install` chroot-runner contract
# (docs/Architecture.md §3.3, §4/§4.1, §8.1-8.4, §9.1, §13; ADR-20): drives the
# REAL installer with PATH-stubbed collaborators (sfdisk/cryptsetup/mkfs.btrfs/
# btrfs/mount/apk/adduser/...) recording argv to a log file, then asserts
# OBSERVED effects: the staged target tree contents, §9.1 plan execution
# order, fail-closed preconditions, and the on-target baseline/state.
#
# ADR-20 AMENDED contract pinned here at EXECUTION level:
#   * G-C23: the internal ephemeral install key is staged (openssl stub),
#     formats the TEMPORARY keyslot 2 (§7.2: keyslot 0 = recovery, keyslot 1
#     = provisional token), is used via --key-file for luksFormat/open AND
#     authorizes the ceremony's recovery luksAddKey, and is SCRUBBED at
#     teardown — no DEBIAN_FDE_DISK_PASSPHRASE anywhere
#   * §9.1 step 4 credential ceremony (ADR-20 amended): the THREE no-echo
#     prompts are the only credential seam — executed host-side (plan
#     records), fed from an ANSWERS FILE on stdin (the documented test/CI
#     seam); no flag and no env var carries any credential; a run with
#     stdin CLOSED fails closed 64; secrets never appear in argv/logs
#   * G-C1/C2/C3: apk populate + in-chroot apk additions txn + repositories
#     drop (debootstrap/apt retired)
#   * G-C24: provisional seal guest line runs after the in-chroot build
#   * G-C25/C28: MOTD/issue banner on target, written BEFORE the state write
#   * G-C26: NO OsIndications write; teardown scrubs the ephemeral key
#
# Topologies executed here: single-disk (deep) and Btrfs RAID1 (per-member
# LUKS2 + raid1 mkfs). The bcache topologies are pinned at the record level
# in install_dryrun.sh (their sysfs attach writes cannot run in a container).
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
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"
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
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T          # M-01/L-04: secrets + plan temp files live HERE, not /tmp
export DEBIAN_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export DEBIAN_FDE_INSTALL_NO_REBOOT=1   # CI seam: no reboot record in unit runs
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars

PARTUUID_CANON='5f2a9b01-02'            # canned ESP PARTUUID the lsblk stub reports
GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
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
for s in sfdisk mkfs.btrfs mkfs.ext4 mkfs.vfat mount umount apk adduser addgroup \
    rc-update bootctl btrfs reboot chroot; do
    make_stub "$s"
done

# openssl — log argv; deterministic 256-bit hex body (the staged ephemeral
# install key; G-C23). pkcs8/asn1parse emulate the ADR-18 PKCS#8 envelope so
# the §9.1 step 4 release-key ceremony (keys_encrypt_release) runs for real:
#   * `pkcs8 -topk8 ... -out F`  -> writes the MARKER + copies -in (fake
#     ciphertext), exit 0 (the round-trip `-out /dev/null` call also passes)
#   * `asn1parse -in F`          -> conformant PBES2/PBKDF2/hmacWithSHA256/
#     aes-256-cbc/iter>=600000 output ONLY for marker files (keys_is_encrypted
#     verdicts), exit 1 otherwise (plaintext PEM = not-encrypted)
MARKER='fake-pbes2-encrypted-ADR18'
export MARKER
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
printf '%s %s\n' "openssl" "$*" >>"$DEBIAN_FDE_TEST_LOG"
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

# cryptsetup — log argv; BR-01: fail closed when a --key-file argument names a
# file that does not exist AT EXECUTION TIME (a scrub trap armed in a subshell
# deletes the staged key-file before any plan step can use it — this assert
# kills the old vacuous find-based L-04a pass)
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

chmod +x "$T/stub/cryptsetup" "$T/stub/id" "$T/stub/lsblk" "$T/stub/openssl"

# chroot — log argv; when the guest line is the §9.1 step 3 platform-key
# ceremony, simulate its OUTPUT on the target (the in-chroot keygen leaves an
# UNencrypted release.pem in /etc/alpine-fde/keys — the input the §9.1 step 4
# credential ceremony encrypts). Every other guest line is logged only.
cat >"$T/stub/chroot" <<EOF
#!/bin/sh
printf '%s %s\n' "chroot" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
case "\$*" in
    *"provision stage1"*)
        mkdir -p "$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/keys"
        printf -- '-----BEGIN PRIVATE KEY-----\nfake-plaintext-release-key\n-----END PRIVATE KEY-----\n' \\
            >"$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem"
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/chroot"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
# hooks/ Alpine layout (G-C16): the templates install's preflight requires
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
mkdir -p "$DEBIAN_FDE_EFIVARS_DIR"
mkvar SetupMode 1   # §9.1 preflight: Stage 1 runs with the vendor PK cleared

# §9.1 step 4 credential-ceremony answers (the documented test/CI seam: the
# three no-echo prompts read stdin; six lines = confirm-typed pairs for the
# account password, the recovery passphrase and the release-key passphrase —
# every value passes the §13 entropy floor and none is blocklisted)
ANSWERS=$T/answers
cat >"$ANSWERS" <<'EOF'
U5er-P4ss-X9k2-!qmwjpz
U5er-P4ss-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz
R3lease-K3ypass-X7!qmz
R3lease-K3ypass-X7!qmz
EOF

first_line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

run_install() { # extra args pass through (e.g. a second --disk); answers on stdin
    : >"$DEBIAN_FDE_TEST_LOG"
    rm -rf "$DEBIAN_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" "$@" <"$ANSWERS" 2>&1)
    RC=$?
}

# =============================================================================
# Preflight fail-closed BEFORE any destructive step — the SetupMode gate is
# FIRST (§9.1): with SetupMode=0 nothing executes (full matrix in
# install_preflight_setupmode.sh).
# =============================================================================
mkvar SetupMode 0
run_install
assert_eq "SetupMode=0 -> fail-closed 64 before any mutation" "64" "$RC"
assert_contains "SetupMode=0: error says what to fix" "$OUT" "clear the vendor PK in BIOS"
assert_eq "SetupMode=0: zero commands executed" "0" "$(wc -l <"$DEBIAN_FDE_TEST_LOG")"
mkvar SetupMode 1

# =============================================================================
# §9.1 Stage 1 execution (single-disk, Btrfs default): plan runs rc 0 under
# stubs — UNATTENDED (stdin closed). G-C23: the staged ephemeral key SURVIVES
# until the cryptsetup plan steps run and is SCRUBBED at teardown.
# =============================================================================
run_install
assert_eq "§9.1 Stage 1 chroot install rc 0 (ceremony answers on stdin)" "0" "$RC"
assert_not_contains "BR-01: --key-file names an EXISTING file at cryptsetup execution time" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "key-file target missing at execution time"
assert_contains "BR-01: luksFormat ran scripted via the staged ephemeral key-file" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "cryptsetup luksFormat"
EPHKEY=$(grep -oE "$T/debian-fde-ephkey\.[A-Za-z0-9]{6}" <<<"$OUT" | head -1)
assert_eq "G-C23: ephemeral key staged under the tmpfs seam" "1" \
    "$([ -n "$EPHKEY" ] && echo 1 || echo 0)"
assert_contains "G-C23: keyslot 2 (TEMPORARY) formatted with the ephemeral key via --key-file" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid"
assert_eq "G-C23: keyslot 0 NEVER used at luksFormat (reserved for the ceremony, §7.2)" "0" \
    "$(grep -Fc 'luksFormat --key-slot 0' "$DEBIAN_FDE_TEST_LOG")"
assert_contains "G-C23: open uses the same staged key-file" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "cryptsetup open --key-file $EPHKEY"
assert_eq "G-C23: NO operator passphrase consumed anywhere" "0" \
    "$(grep -c 'DEBIAN_FDE_DISK_PASSPHRASE=' <<<"$OUT")"
assert_not_contains "G-C23: NO interactive passphrase prompt in the run" "$OUT" \
    "Set disk encryption passphrase"

# =============================================================================
# §9.1 step 4 credential ceremony (ADR-20 amended): executed host-side, the
# ONLY credential seam is stdin (the answers file) — no flag, no env var.
# =============================================================================
assert_contains "ceremony (1/3): user password set in-chroot via chpasswd" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "chroot $DEBIAN_FDE_INSTALL_MNT /usr/sbin/chpasswd"
assert_eq "ceremony: NO interactive passwd(1) step anywhere" "0" \
    "$(grep -Ec '[/:]passwd( |$)' <<<"$(cat "$DEBIAN_FDE_TEST_LOG")")"
assert_contains "ceremony (2/3): recovery passphrase enrolled into keyslot 0 via luksAddKey" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "cryptsetup luksAddKey --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --key-file $EPHKEY /dev/mapper/root-crypt"
assert_contains "ceremony (3/3): release.pem encrypted via keys_encrypt_release (ADR-18 pkcs8)" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256"
assert_eq "ceremony: NO secret ever appears in command argv (the log IS the argv record)" "0" \
    "$(grep -Ec 'U5er-P4ss|Fin4l-Rec0very|R3lease-K3ypass' <<<"$(cat "$DEBIAN_FDE_TEST_LOG")")"
assert_eq "ceremony: NO credential env seam in the emitted run" "0" \
    "$(grep -Ec 'DEBIAN_FDE_(KEY|RECOVERY|DISK)_PASSPHRASE=' <<<"$OUT")"
assert_eq "ceremony: recovery passfile scrubbed (keys_scrub, I1)" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-ceremony.*' 2>/dev/null | wc -l)"
assert_eq "ceremony: encrypt stage scrubbed (keys_encrypt_release tmp)" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-enc.*' 2>/dev/null | wc -l)"
assert_eq "ceremony (3/3): release.pem on target IS the encrypted form" "1" \
    "$(grep -qc 'fake-pbes2-encrypted-ADR18' "$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem" && echo 1 || echo 0)"
assert_eq "ceremony (3/3): encrypted release.pem locked 0400" "400" \
    "$(stat -c '%a' "$DEBIAN_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem")"
# ceremony order: AFTER the platform keys, BEFORE NVRAM enrollment (§9.1)
O_KEYGEN=$(first_line_no "$OUT" "provision stage1 --mode in-chroot")
O_CERU=$(first_line_no "$OUT" "host: inst_ceremony_user_password")
O_CERR=$(first_line_no "$OUT" "host: inst_ceremony_recovery")
O_CERK=$(first_line_no "$OUT" "host: inst_ceremony_release_key")
O_ENROLL=$(first_line_no "$OUT" "fw_auth_enroll")
assert_eq "order: platform keys BEFORE the ceremony (release.pem must exist)" "1" \
    "$(( O_KEYGEN > 0 && O_KEYGEN < O_CERU ? 1 : 0 ))"
assert_eq "order: ceremony (1/3) before (2/3) before (3/3)" "1" \
    "$(( O_CERU > 0 && O_CERU < O_CERR && O_CERR < O_CERK ? 1 : 0 ))"
assert_eq "order: ceremony BEFORE NVRAM enrollment" "1" \
    "$(( O_CERK > 0 && O_CERK < O_ENROLL ? 1 : 0 ))"

LUKS_UUID=$(grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
ROOTFS_UUID=$(grep -oE -- '-U [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$DEBIAN_FDE_TEST_LOG" | head -1 | awk '{print $2}')
assert_eq "fixture: luksFormat pinned an explicit uuid" "1" "$([ -n "$LUKS_UUID" ] && echo 1 || echo 0)"
assert_eq "fixture: mkfs.btrfs pinned an explicit uuid" "1" "$([ -n "$ROOTFS_UUID" ] && echo 1 || echo 0)"
# G-ST1: the btrfs filesystem + subvolume flow ran against the mapper
assert_contains "G-ST1: mkfs.btrfs ran on the mapper" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mkfs.btrfs -U $ROOTFS_UUID /dev/mapper/root-crypt"
assert_contains "G-ST1: subvolume @ created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@"
assert_contains "G-ST1: subvolume @home created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@home"
assert_contains "G-ST1: subvolume @snapshots created" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "btrfs subvolume create $DEBIAN_FDE_INSTALL_MNT/@snapshots"
assert_contains "G-ST1: @ remounted as root" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "mount -o subvol=@ /dev/mapper/root-crypt $DEBIAN_FDE_INSTALL_MNT"

MNT_ETC=$DEBIAN_FDE_INSTALL_MNT/etc
# G-C1/C2/C3: apk populate + repositories drop (apt/dpkg retired)
assert_contains "§3.3: apk populate ran on the target" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "apk add --root $DEBIAN_FDE_INSTALL_MNT --initdb alpine-base"
assert_file_exists "target: /etc/apk/repositories drop" "$MNT_ETC/apk/repositories"
assert_contains "repositories: Alpine CDN pinned" "$(cat "$MNT_ETC/apk/repositories")" \
    "dl-cdn.alpinelinux.org/alpine"
assert_eq "target: NO apt policy drop" "0" "$([ -e "$MNT_ETC/apt" ] && echo 1 || echo 0)"
assert_eq "target: NO dpkg trims drop" "0" "$([ -e "$MNT_ETC/dpkg" ] && echo 1 || echo 0)"
# G-ST4/§8.2: single topology crypttab is ONE root entry, NO password-cache
assert_eq "crypttab verbatim per §8.2 (single topology, no password-cache)" \
    "root UUID=$LUKS_UUID none luks,tpm2-device=auto,discard" \
    "$(cat "$MNT_ETC/crypttab")"
# G-ST1: subvol fstab forms + resolved ESP PARTUUID (G-I4)
assert_contains "fstab: root subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID / btrfs subvol=@,defaults 0 1"
assert_contains "fstab: @home subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID /home btrfs subvol=@home,defaults 0 2"
assert_contains "fstab: @snapshots subvol form" "$(cat "$MNT_ETC/fstab")" "UUID=$ROOTFS_UUID /.snapshots btrfs subvol=@snapshots,defaults 0 2"
assert_contains "fstab: real ESP PARTUUID (placeholder resolved)" "$(cat "$MNT_ETC/fstab")" "PARTUUID=$PARTUUID_CANON /efi vfat umask=0077 0 2"
assert_not_contains "fstab: no unresolved placeholder" "$(cat "$MNT_ETC/fstab")" "<esp-partuuid>"
assert_file_exists "target: network interfaces drop (OpenRC)" "$MNT_ETC/network/interfaces"
assert_contains "interfaces: dhcp" "$(cat "$MNT_ETC/network/interfaces")" "dhcp"
# §3.1/ADR-7: swap is zram-only — zram-init config dropped + service enabled;
# the target fstab carries NO swap line (no disk swap anywhere)
assert_file_exists "target: zram-init boot config dropped (§3.1, ADR-7)" "$MNT_ETC/conf.d/zram-init"
assert_contains "zram-init config: swap device pinned (type0=0)" \
    "$(cat "$MNT_ETC/conf.d/zram-init")" "type0=0"
assert_contains "target: zram-init service enabled for boot" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "rc-update add zram-init boot"
assert_eq "fstab: zero swap lines (ADR-7: no disk swap)" "0" \
    "$(grep -c 'swap' "$MNT_ETC/fstab")"
# §3.1 additions set lands in the in-guest apk transaction
CHROOT_TXN=$(grep -m1 'apk add --no-cache' "$DEBIAN_FDE_TEST_LOG")
for want in mkinitfs py3-pefile zram-init doas ukify-kernel-hook; do
    assert_contains "apk txn includes $want (§3.1, executed)" "$CHROOT_TXN" "$want"
done
# ADR-13: dracut is REJECTED on Alpine (mkinitfs, G-C8) — no dracut config
# residue may land on the target in ANY topology
assert_eq "target: NO dracut.conf.d directory (ADR-13)" "0" \
    "$([ -e "$MNT_ETC/dracut.conf.d" ] && echo 1 || echo 0)"
assert_eq "cmdline.txt verbatim: rootflags + §8.2 fail-closed pins" \
    "root=UUID=$LUKS_UUID rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff" \
    "$(cat "$MNT_ETC/alpine-fde/cmdline.txt")"
# §4: topology recorded in the target conf (absent file = btrfs default, doc'd)
assert_contains "conf: ROOT_FS=btrfs recorded" "$(cat "$MNT_ETC/alpine-fde/alpine-fde.conf")" "ROOT_FS=btrfs"
assert_contains "conf: BCACHE=0 recorded" "$(cat "$MNT_ETC/alpine-fde/alpine-fde.conf")" "BCACHE=0"
assert_contains "conf: ESP_PATH=/efi persisted (CR-01)" "$(cat "$MNT_ETC/alpine-fde/alpine-fde.conf")" "ESP_PATH=/efi"
assert_contains "conf: absent-file default documented" "$(cat "$MNT_ETC/alpine-fde/alpine-fde.conf")" \
    "Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0"

# =============================================================================
# §9.1 step 2/8/9: pending baseline + banner + install-state ON TARGET
# =============================================================================
TGT_BL=$MNT_ETC/alpine-fde/baseline.json
assert_file_exists "§9.1 step 2: pending baseline written ON TARGET" "$TGT_BL"
assert_rc "on-target pending baseline validates" 0 baseline_validate "$TGT_BL"
assert_eq "on-target baseline: expected_pcr7 pending" "pending" "$(baseline_get "$TGT_BL" expected_pcr7)"
assert_eq "G-I4: target.luks_uuid resolved onto the pending baseline" "$LUKS_UUID" \
    "$(baseline_get_in "$TGT_BL" target luks_uuid)"
assert_eq "G-I4: target.esp_partuuid resolved" "$PARTUUID_CANON" \
    "$(baseline_get_in "$TGT_BL" target esp_partuuid)"
assert_eq "§9.1: NO host-baseline copy anywhere" "0" \
    "$(grep -c 'cp .*baseline.json' "$DEBIAN_FDE_TEST_LOG")"
# G-C25: unfinalized banner on /etc/motd AND /etc/issue — the SHARED
# single-source line (lib/install-state.sh fde_motd_banner; the ONLY banner
# definition in the tree), dropped line-exactly so finalize's fde_motd_strip
# removes exactly it
assert_file_exists "G-C25: MOTD banner on target" "$MNT_ETC/motd"
assert_eq "G-C25: MOTD banner IS the shared single-source line (fde_motd_banner)" \
    "$(fde_motd_banner)" "$(cat "$MNT_ETC/motd")"
assert_eq "G-C25: banner is ONE line (line-exact strip contract)" "1" \
    "$(wc -l <"$MNT_ETC/motd")"
assert_eq "G-C25: /etc/issue carries the SAME single line" \
    "$(cat "$MNT_ETC/motd")" "$(cat "$MNT_ETC/issue")"
assert_file_exists "§9.1 step 9: install-state written ON TARGET" \
    "$MNT_ETC/alpine-fde/install-state.json"
assert_eq "install-state: state=installed" "installed" \
    "$(istate_get "$MNT_ETC/alpine-fde/install-state.json" state)"
# G-C28: banner BEFORE the state write (observed order of the host-step infos)
L_MOTD=$(printf '%s\n' "$OUT" | grep -Fnm1 ">$DEBIAN_FDE_INSTALL_MNT/etc/motd" | cut -d: -f1)
L_STATE=$(printf '%s\n' "$OUT" | grep -Fnm1 "host: inst_state_write installed" | cut -d: -f1)
assert_eq "G-C28: MOTD banner drop runs BEFORE the state write" "1" \
    "$(( L_MOTD > 0 && L_STATE > L_MOTD ? 1 : 0 ))"
# G-C26: NO OsIndications write anywhere (firmware-trip flow retired)
assert_eq "G-C26: efivars dir holds NO OsIndications variable" "0" \
    "$(find "$DEBIAN_FDE_EFIVARS_DIR" -name 'OsIndications-*' 2>/dev/null | wc -l)"
assert_not_contains "G-C26: NO OsIndications step in the run" "$OUT" "fw_osindications_set"

# =============================================================================
# §9.1 in-chroot sequence: order + argv as observed through the chroot stub
# =============================================================================
LOG=$(cat "$DEBIAN_FDE_TEST_LOG")
assert_contains "§9.1 step 1: apk additions txn ran in-guest" "$LOG" "apk add --no-cache"
APK_TXN_LOG=$(grep -m1 'apk add --no-cache' "$DEBIAN_FDE_TEST_LOG")
assert_contains "apk txn includes btrfs-progs (default fs, topology-conditional)" \
    "$APK_TXN_LOG" "btrfs-progs"
assert_contains "§9.1 step 1: user account created in-guest (locked; password set by the §9.1 step 4 ceremony)" "$LOG" \
    "adduser -D -s /bin/ash admin"
assert_contains "§9.1 step 1: OpenRC networking enabled in-guest" "$LOG" \
    "rc-update add networking boot"
assert_contains "§9.1 step 3: platform-key ceremony invoked in-chroot" "$LOG" \
    "provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys"
assert_contains "§9.1 step 4: NVRAM enrollment db->KEK->PK in-chroot" "$LOG" \
    "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys"
assert_contains "ESP layout for the in-chroot build" "$LOG" \
    "bootctl install --esp-path=/efi --boot-path=/efi"
assert_contains "§9.1 step 5: ukictl build in-chroot (boot manager + UKI, G-C7 CLI path)" "$LOG" \
    "/opt/alpine-fde/bin/alpine-fde ukictl build"
# G-C24: provisional seal guest line after the build
assert_contains "§9.1 step 6: provisional seal guest line ran in-chroot" "$LOG" \
    'seal_provisional /etc/alpine-fde/keys /dev/mapper/$m'
assert_contains "§9.1 step 6: guest line pins the provisional slot contract" "$LOG" \
    "provisional Mechanism B seal (PCR 11) -> keyslot 1"
# ADR-20 AMENDED: release.pem is encrypted IN STAGE 1 by the §9.1 step 4
# credential ceremony (keys_encrypt_release, executed host-side); finalize
# only CONSUMES the encrypted release.pem
assert_contains "ADR-20 amended: release.pem encrypted in Stage 1 (ceremony 3/3 ran)" \
    "$OUT" "host: inst_ceremony_release_key"
# I1 (§11): the Stage-1 provisional-seal one-liner must scrub its secrets —
# the random volume passphrase (overwrite-then-unlink, the shared keys_scrub
# idiom) and the seal work dir (blob halves + primary.ctx under the
# /tmp-defaulted stage) — not just /run/alpine-fde
SEAL_LINE=$(grep -m1 'seal_provisional' <<<"$LOG")
assert_contains "I1: seal one-liner scrubs SEAL_PASS_FILE (keys_scrub idiom)" \
    "$SEAL_LINE" 'keys_scrub "$SEAL_PASS_FILE"'
assert_contains "I1: seal one-liner scrubs the seal work dir (blob halves + primary.ctx)" \
    "$SEAL_LINE" 'debian-fde-seal.'
assert_contains "I1: seal one-liner still removes /run/alpine-fde" "$SEAL_LINE" \
    'rm -rf /run/alpine-fde'
L_SFDISK=$(first_line_no "$LOG" "sfdisk")
L_APKPOP=$(first_line_no "$LOG" "apk add --root")
L_POLICY=$(first_line_no "$OUT" "etc/apk/repositories")
L_APKUPD=0
L_KEYGEN=$(first_line_no "$LOG" "provision stage1 --mode in-chroot")
L_ENROLL=$(first_line_no "$LOG" "fw_auth_enroll")
L_BUILD=$(first_line_no "$LOG" "ukictl build")
L_SEAL=$(first_line_no "$LOG" "seal_provisional")
L_UMNTR=$(first_line_no "$LOG" "umount -R")
L_SCRUB=$(printf '%s\n' "$OUT" | grep -Fnm1 "host: rm -f $EPHKEY" | cut -d: -f1)
assert_eq "order: sfdisk before apk populate" "1" "$(( L_SFDISK < L_APKPOP ? 1 : 0 ))"
assert_eq "order: populate before repositories drop" "1" \
    "$(( L_APKPOP > 0 && L_POLICY > 0 && L_APKPOP < L_POLICY ? 1 : 0 ))"
assert_eq "order: keygen before enrollment" "1" "$(( L_KEYGEN < L_ENROLL ? 1 : 0 ))"
assert_eq "order: enrollment before ukictl build" "1" "$(( L_ENROLL < L_BUILD ? 1 : 0 ))"
assert_eq "order: build before the provisional seal (.pcrsig source)" "1" \
    "$(( L_BUILD < L_SEAL ? 1 : 0 ))"
assert_eq "order: teardown before the ephemeral-key scrub (G-C26/I1)" "1" \
    "$(( L_UMNTR > 0 && L_SCRUB > L_UMNTR ? 1 : 0 ))"
# G-C23/I1: the ephemeral key does NOT survive the run
assert_eq "G-C23: ephemeral key-file scrubbed at teardown" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-ephkey.*' 2>/dev/null | wc -l)"
# G-IL8: NO installer-side signing machinery executed
assert_eq "zero sbsign/ukify/sbverify executions" "0" \
    "$(grep -Ec '^(sbsign|ukify|sbverify)' <<<"$LOG")"
# G-U7 (§8.3): boot-manager self-update masked
assert_eq "target: systemd-boot-update.service masked" "1" \
    "$([ -L "$MNT_ETC/systemd/system/systemd-boot-update.service" ] && [ "$(readlink "$MNT_ETC/systemd/system/systemd-boot-update.service")" = "/dev/null" ] && echo 1 || echo 0)"
# §9.1 step 7 / ADR-20 / G-I2: hooks shipped to their Alpine destinations,
# executable; the first-boot finalize ADVISORY ships to /etc/init.d/ and is
# enabled for the default runlevel (the GUIDED finalize command itself is
# never run at boot)
for h in kernel-hooks.d/alpine-fde-build.hook kernel-hooks.d/alpine-fde-remove.hook; do
    assert_file_exists "target: kernel hook shipped: $h" "$MNT_ETC/$h"
    assert_eq "target kernel hook executable: $h" "1" "$([ -x "$MNT_ETC/$h" ] && echo 1 || echo 0)"
done
# §8.2/ADR-13: the hook ships to the EXACT path the features.d inventory lists
# (/usr/share/alpine-fde/mkinitfs/… — what mkinitfs packs when the alpine-fde
# feature is enabled) and the feature is REGISTERED in /etc/mkinitfs/
# mkinitfs.conf (full contract: tests/unit/featuresd_contract.sh)
assert_file_exists "target: mkinitfs unseal hook shipped (features.d path)" \
    "$DEBIAN_FDE_INSTALL_MNT/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
assert_eq "target: mkinitfs unseal hook executable" "1" \
    "$([ -x "$DEBIAN_FDE_INSTALL_MNT/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh" ] && echo 1 || echo 0)"
assert_eq "target: retired /etc/mkinitfs hook path NOT used" "0" \
    "$([ -e "$MNT_ETC/mkinitfs/alpine-fde-unseal.sh" ] && echo 1 || echo 0)"
assert_file_exists "target: mkinitfs features.d entry shipped" "$MNT_ETC/mkinitfs/features.d/alpine-fde.files"
assert_contains "target: alpine-fde feature registered in mkinitfs.conf (§8.2/ADR-13)" \
    "$(cat "$MNT_ETC/mkinitfs/mkinitfs.conf")" "alpine-fde"
assert_file_exists "target: apk trigger shipped" "$MNT_ETC/apk/triggers/alpine-fde.trigger"
assert_eq "target: apk trigger executable" "1" \
    "$([ -x "$MNT_ETC/apk/triggers/alpine-fde.trigger" ] && echo 1 || echo 0)"
assert_file_exists "target: finalize advisory shipped to /etc/init.d" \
    "$MNT_ETC/init.d/alpine-fde-finalize"
assert_eq "target: finalize advisory executable" "1" \
    "$([ -x "$MNT_ETC/init.d/alpine-fde-finalize" ] && echo 1 || echo 0)"
assert_eq "target: advisory is the shipped hook, byte-for-byte" \
    "$(cat "$DEBIAN_FDE_HOOKS_DIR/openrc/alpine-fde-finalize")" \
    "$(cat "$MNT_ETC/init.d/alpine-fde-finalize")"
assert_contains "target: finalize advisory enabled for the default runlevel" "$LOG" \
    "rc-update add alpine-fde-finalize default"
assert_eq "target: NO systemd finalize unit shipped (ADR-20 Stage 3)" "0" \
    "$([ -e "$MNT_ETC/systemd/system/debian-fde-finalize.service" ] && echo 1 || echo 0)"
assert_eq "target: NO multi-user.target.wants enable record" "0" \
    "$(grep -c 'multi-user.target.wants' <<<"$LOG")"

# =============================================================================
# H-02: binds (incl. the §9.1 efivars bind) run BEFORE guest steps and are
# torn down BEFORE `umount -R`.
# =============================================================================
assert_contains "H-02: /proc bound into the target" "$LOG" \
    "mount -t proc proc $DEBIAN_FDE_INSTALL_MNT/proc"
assert_contains "H-02: /sys bound into the target" "$LOG" \
    "mount --bind /sys $DEBIAN_FDE_INSTALL_MNT/sys"
assert_contains "H-02: /dev bound into the target" "$LOG" \
    "mount --bind /dev $DEBIAN_FDE_INSTALL_MNT/dev"
assert_contains "§9.1: efivars bound into the target" "$LOG" \
    "mount --bind /sys/firmware/efi/efivars $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
L_BINDT=$(first_line_no "$LOG" "mount --bind /dev")
L_BINDU=$(first_line_no "$LOG" "umount $DEBIAN_FDE_INSTALL_MNT/dev")
assert_eq "H-02: binds torn down before umount -R" "1" "$(( L_BINDT > 0 && L_BINDU > L_BINDT && L_UMNTR > L_BINDU ? 1 : 0 ))"
assert_contains "H-02: teardown umounts the efivars bind" "$LOG" \
    "umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
# L-04b: guest steps never see DEBIAN_FDE_DISK_PASSPHRASE (defensive strip stays)
assert_contains "L-04b: chroot invocation strips the passphrase variable" \
    "$LOG" "-u DEBIAN_FDE_DISK_PASSPHRASE"

# =============================================================================
# G-ST3: RAID1 execution — per-role partitioning, per-member LUKS2 (ephemeral
# key each), raid1 mkfs, per-member crypttab with password-cache=yes,
# member_uuids metadata, per-member provisional seal loop.
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
run_install --disk "$DISK2" </dev/null
assert_eq "raid1 chroot install rc 0 (unattended)" "0" "$RC"
LOG2=$(cat "$DEBIAN_FDE_TEST_LOG")
assert_contains "raid1: primary partitioned (ESP + LUKS)" "$LOG2" "sfdisk $DISK"
assert_contains "raid1: secondary partitioned (root only)" "$LOG2" "sfdisk $DISK2"
assert_eq "raid1: secondary got NO ESP (single mkfs.vfat on primary p1)" "1" \
    "$(grep -c "^mkfs.vfat" <<<"$LOG2")"
assert_contains "raid1: ESP on primary p1" "$LOG2" "mkfs.vfat -F 32 -n EFI ${DISK}1"
assert_eq "raid1: exactly 2 per-member luksFormat records" "2" \
    "$(grep -c 'luksFormat --type luks2' <<<"$LOG2")"
assert_contains "raid1: mkfs.btrfs -d raid1 -m raid1 over both mappers" "$LOG2" \
    "-d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2"
assert_eq "raid1: primary opened as root1" "1" \
    "$(grep -Ec 'cryptsetup open .* root1$' <<<"$LOG2")"
assert_eq "raid1: secondary opened as root2" "1" \
    "$(grep -Ec 'cryptsetup open .* root2$' <<<"$LOG2")"
MEM1_UUID=$(grep -oE -- '--uuid [0-9a-f-]{36}' <<<"$LOG2" | sed -n 1p | awk '{print $2}')
MEM2_UUID=$(grep -oE -- '--uuid [0-9a-f-]{36}' <<<"$LOG2" | sed -n 2p | awk '{print $2}')
assert_eq "raid1: crypttab member entries verbatim (password-cache=yes on BOTH)" \
    "root1 UUID=$MEM1_UUID none luks,tpm2-device=auto,password-cache=yes,discard
root2 UUID=$MEM2_UUID none luks,tpm2-device=auto,password-cache=yes,discard" \
    "$(cat "$MNT_ETC/crypttab")"
assert_eq "raid1: baseline target.luks_uuid = PRIMARY member" "$MEM1_UUID" \
    "$(baseline_get_in "$MNT_ETC/alpine-fde/baseline.json" target luks_uuid)"
assert_eq "raid1: baseline target.member_uuids (additive schema)" "$MEM1_UUID $MEM2_UUID" \
    "$(baseline_get_in "$MNT_ETC/alpine-fde/baseline.json" target member_uuids)"
assert_contains "raid1: cmdline rootflags pins verbatim" "$(cat "$MNT_ETC/alpine-fde/cmdline.txt")" \
    "rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
# G-C24: the provisional seal loop covers BOTH members in raid1
SEAL_LINE2=$(grep -m1 'seal_provisional' <<<"$LOG2")
assert_contains "raid1: provisional seal loop covers root1 and root2" "$SEAL_LINE2" \
    "for m in root1 root2"
L_CLOSE1=$(first_line_no "$LOG2" "cryptsetup close root1")
L_CLOSE2=$(first_line_no "$LOG2" "cryptsetup close root2")
assert_eq "raid1: teardown closes both members (primary first)" "1" \
    "$(( L_CLOSE1 > 0 && L_CLOSE2 > L_CLOSE1 ? 1 : 0 ))"
EPHKEY2=$(grep -oE "$T/debian-fde-ephkey\.[A-Za-z0-9]{6}" <<<"$OUT" | head -1)
assert_eq "raid1: ephemeral key scrubbed at teardown" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-ephkey.*' 2>/dev/null | wc -l)"

# =============================================================================
# G4/F-1 (§8.1/§3.3): the tooling copy into /opt/alpine-fde ships ONLY the
# product script tree (bin/ lib/ hooks/ docs/) — NEVER VCS/harness residue.
# Residue is seeded in a THROWAWAY tree — never the real tests/ dirs.
# =============================================================================
DEBIAN_FDE_TREE=$T/tree
mkdir -p "$DEBIAN_FDE_TREE"
for d in bin lib hooks docs; do
    cp -r "$REPO/$d" "$DEBIAN_FDE_TREE/$d"
done
mkdir -p "$DEBIAN_FDE_TREE/.git/objects" "$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run" \
    "$DEBIAN_FDE_TREE/tests/.cache"
printf 'residue' >"$DEBIAN_FDE_TREE/.git/HEAD"
printf 'residue' >"$DEBIAN_FDE_TREE/tests/e2e/.runs/soak-run/marker"
truncate -s 20M "$DEBIAN_FDE_TREE/tests/.cache/blob-20M"

run_install_tree() { # TREE — run_install against a different tooling tree
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$(DEBIAN_FDE_CMD_DIR="$1/lib/cmd" "$REPO/bin/debian-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
    RC=$?
}

run_install_tree "$DEBIAN_FDE_TREE"
assert_eq "tooling copy from seeded tree: rc 0" "0" "$RC"

OPT=$DEBIAN_FDE_INSTALL_MNT/opt/alpine-fde
assert_file_exists "tooling copy: bin/debian-fde shipped" "$OPT/bin/debian-fde"
assert_file_exists "tooling copy: lib/ shipped" "$OPT/lib/cmd/install.sh"
assert_file_exists "tooling copy: hooks/ shipped (Alpine layout)" "$OPT/hooks/kernel-hooks.d/alpine-fde-build.hook"
assert_file_exists "tooling copy: docs/ shipped" "$OPT/docs/Architecture.md"

RESIDUE=$(find "$OPT" \( -name '.git' -o -name 'tests' -o -name 'fixtures' \
    -o -name '*.cache*' -o -name '*.runs*' -o -name 'blob-20M' -o -name 'soak-run' \) | wc -l)
assert_eq "tooling copy: zero VCS/harness residue at any depth" "0" "$RESIDUE"
NODES=$(find "$OPT" \( -type b -o -type c \) | wc -l)
assert_eq "tooling copy: zero device nodes in target" "0" "$NODES"
COPY_LINE=$(grep -m1 'cp -r' <<<"$OUT")
assert_contains "tooling copy step: enumerates bin" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/bin"
assert_contains "tooling copy step: enumerates docs" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE/docs"
assert_not_contains "tooling copy step: never the whole tree root" "$COPY_LINE" "cp -r $DEBIAN_FDE_TREE "
# G-C7 (§8.1/§12): the tooling tree lands at /opt/alpine-fde and the guest CLI
# is /opt/alpine-fde/bin/alpine-fde, with the debian-fde name kept as the
# §8.1 backwards-compat alias symlink.
assert_contains "G-C7: tooling-copy record stages into /opt/alpine-fde" "$COPY_LINE" \
    "$DEBIAN_FDE_INSTALL_MNT/opt/alpine-fde"
assert_not_contains "G-C7: tooling-copy record free of /opt/debian-fde" "$COPY_LINE" \
    "/opt/debian-fde"
assert_eq "G-C7/§8.1: guest CLI staged: /usr/local/bin/alpine-fde -> /opt/alpine-fde/bin/alpine-fde" \
    "/opt/alpine-fde/bin/alpine-fde" \
    "$(readlink "$DEBIAN_FDE_INSTALL_MNT/usr/local/bin/alpine-fde")"
assert_eq "G-C7/§8.1: debian-fde backwards-compat alias kept (-> alpine-fde)" \
    "alpine-fde" "$(readlink "$DEBIAN_FDE_INSTALL_MNT/usr/local/bin/debian-fde")"
assert_not_contains "G-C7: NO /opt/debian-fde anywhere in the full emitted plan" "$OUT" \
    "/opt/debian-fde"

# =============================================================================
# M-02: operator-controlled values are validated at the boundary BEFORE any
# plan record exists; WR-01 covers the eval'd --keydir path.
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
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --bcache '/dev/nvme0n1; echo pwned' 2>&1)
RC=$?
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$RC"

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
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
RC=$?
assert_eq "M-02: clean run still rc 0 (validation does not over-reject)" "0" "$RC"

# =============================================================================
# §9.1 step 4 negative seam proof: with stdin CLOSED the ceremony fails
# closed — the prompts are the ONLY credential seam (no flag, no env var).
# Runs LAST against the main-run fixtures: it mutates the target before it
# dies (config drops execute before the ceremony), so every later section
# re-runs install and re-derives its own state.
# =============================================================================
NEG_OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1 </dev/null)
NEG_RC=$?
assert_eq "ceremony: stdin closed -> fail-closed 64 (prompts are the only seam)" "64" "$NEG_RC"
assert_contains "ceremony: the failure names the empty/unequal answers" "$NEG_OUT" \
    "did not match"
assert_contains "ceremony: the die names ceremony (1/3) (fail happens at the FIRST prompt pair)" \
    "$NEG_OUT" "inst_ceremony_user_password"

# =============================================================================
# §8.1 provision row / ADR-18: `install --keydir` is CONSUMED — the
# operator-supplied key material is staged FROM THE MEDIUM onto the encrypted
# root (restrictive perms) and the in-chroot keygen ceremony is SKIPPED for
# those artifacts. Never any key material on the ESP (I2).
# =============================================================================
KEYDIR=$T/medium-keys
mkdir -p "$KEYDIR"
for f in release.pem release.pub release.crt db.cert.der kek.cert.der pk.cert.der \
    db.esl kek.esl pk.esl db.auth kek.auth pk.auth; do
    printf 'key-material' >"$KEYDIR/$f"
done
: >"$DEBIAN_FDE_TEST_LOG"
rm -rf "$DEBIAN_FDE_INSTALL_MNT"
OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" --keydir "$KEYDIR" <"$ANSWERS" 2>&1)
RC=$?
assert_eq "keydir: chroot install rc 0 (medium-staged keys)" "0" "$RC"
assert_contains "keydir: release.pem staged from the medium (host record)" "$OUT" \
    "cp $KEYDIR/release.pem"
assert_contains "keydir: db.auth staged from the medium (host record)" "$OUT" \
    "$KEYDIR/db.auth"
assert_eq "keydir: NO in-chroot keygen ceremony ran" "0" \
    "$(grep -c 'provision stage1' "$DEBIAN_FDE_TEST_LOG")"
assert_contains "keydir: NVRAM enrollment still consumes /etc/alpine-fde/keys" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys"
assert_file_exists "keydir: release.pem on the encrypted root" "$MNT_ETC/alpine-fde/keys/release.pem"
assert_eq "keydir: staged keys dir mode 0700" "700" "$(stat -c '%a' "$MNT_ETC/alpine-fde/keys")"
assert_eq "keydir: staged key files mode 0600" "600" "$(stat -c '%a' "$MNT_ETC/alpine-fde/keys/kek.auth")"
L_KSTAGE=$(first_line_no "$OUT" "cp $KEYDIR/release.pem")
L_KENROLL=$(first_line_no "$OUT" "fw_auth_enroll")
assert_eq "keydir: staging before NVRAM enrollment" "1" \
    "$(( L_KSTAGE > 0 && L_KENROLL > L_KSTAGE ? 1 : 0 ))"
assert_eq "keydir: NO key material anywhere on the ESP (I2)" "0" \
    "$(find "$DEBIAN_FDE_INSTALL_MNT/efi" -name 'release*' -o -name '*.auth' -o -name '*.esl' 2>/dev/null | wc -l)"
# default (no --keydir): in-chroot ceremony unchanged
run_install
assert_eq "keydir: default run (no --keydir) rc 0" "0" "$RC"
assert_contains "keydir: default run keeps the in-chroot ceremony" "$(cat "$DEBIAN_FDE_TEST_LOG")" \
    "provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys"

# =============================================================================
# L-04a/WR-02: a failed plan step leaves NO temp files behind and the abort
# trap tears the binds down. The failing step is a LATE host record (the
# §9.1 step 9 state write, made failing by chmod 555 on the target's
# alpine-fde config dir — istate_write's atomic mv dies) so the plan's own
# teardown never runs — the ONLY bind-umount line in the log is the trap's.
# =============================================================================
run_install
assert_eq "L-04a fixture: clean run wrote the state" "installed" \
    "$(istate_get "$MNT_ETC/alpine-fde/install-state.json" state)"
chmod 555 "$MNT_ETC/alpine-fde"
run_install
assert_eq "L-04a: failed host step -> fail-closed 64" "64" "$RC"
assert_contains "L-04a: the failing step is named" "$OUT" "baseline_set_field"
assert_eq "L-04a: plan temp file scrubbed on failed step" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-plan.*' 2>/dev/null | wc -l)"
assert_eq "L-04a: ephemeral key-file scrubbed on failed step (I1)" "0" \
    "$(find "$DEBIAN_FDE_TMPDIR" -name 'debian-fde-ephkey.*' 2>/dev/null | wc -l)"
assert_eq "WR-02 fixture: plan teardown never ran (die before teardown)" "0" \
    "$(grep -c 'umount -R' "$DEBIAN_FDE_TEST_LOG")"
assert_eq "WR-02: abort trap tore the binds down (incl. efivars)" "1" \
    "$(grep -c "^umount $DEBIAN_FDE_INSTALL_MNT/dev $DEBIAN_FDE_INSTALL_MNT/sys $DEBIAN_FDE_INSTALL_MNT/proc $DEBIAN_FDE_INSTALL_MNT/sys/firmware/efi/efivars\$" "$DEBIAN_FDE_TEST_LOG")"
chmod 755 "$MNT_ETC/alpine-fde"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
