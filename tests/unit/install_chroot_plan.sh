#!/usr/bin/env bash
# tests/unit/install_chroot_plan.sh — `alpine-fde install` chroot-runner contract
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
#     teardown — no ALPINE_FDE_DISK_PASSPHRASE anywhere
#   * §9.1 step 4 credential ceremony (ADR-20 amended): the THREE no-echo
#     prompts are the only credential seam — executed host-side (plan
#     records), fed from an ANSWERS FILE on stdin (the documented test/CI
#     seam); no flag and no env var carries any credential; a run with
#     stdin CLOSED fails closed 64; secrets never appear in argv/logs
#   * G-C1/C2/C3: apk populate + in-chroot apk additions txn + repositories
#     drop (debootstrap/apt retired)
#   * G-C24: provisional seal guest line runs after the in-chroot build
#   * G-C25 (ADR-20 amendment #4): NO MOTD/issue banner — install never
#     touches /etc/motd or /etc/issue; state `installed` is the last write
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
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-install-chroot.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T          # M-01/L-04: secrets + plan temp files live HERE, not /tmp
export ALPINE_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export ALPINE_FDE_INSTALL_NO_REBOOT=1   # CI seam: no reboot record in unit runs
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

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
printf '%s %s\n' "$1" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.ext4 mkfs.vfat mount umount apk adduser addgroup \
    rc-update btrfs reboot chroot modprobe mdev nslookup; do
    make_stub "$s"
done

# apk — log argv; serve the fixture systemd-boot apk for the preflight
# loader-binary probe (apk fetch --stdout; real-server blocker #7), pass
# everything else
cat >"$T/stub/apk" <<EOF
#!/bin/sh
printf '%s %s\n' "apk" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
case "\$*" in
    *fetch*systemd-boot*)
        [ -n "\$LOADER_APK_FIXTURE" ] && [ -f "\$LOADER_APK_FIXTURE" ] && cat "\$LOADER_APK_FIXTURE"
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/apk"

# real-server blocker #7 fixtures: the systemd-boot apk the preflight fetches
# from the configured mirror — one WITH the loader EFI binary (the common
# case), one WITHOUT (the decisive-negative preflight die)
PKGROOT=$T/pkgroot
mkdir -p "$PKGROOT/usr/share/systemd/bootctl"
: >"$PKGROOT/usr/share/systemd/bootctl/systemd-bootx64.efi"
tar -czf "$T/systemd-boot-loader.apk" -C "$PKGROOT" usr
mkdir -p "$T/pkgroot-noloader/etc"
: >"$T/pkgroot-noloader/etc/placeholder"
tar -czf "$T/systemd-boot-noloader.apk" -C "$T/pkgroot-noloader" etc
export LOADER_APK_FIXTURE=$T/systemd-boot-loader.apk
# loader-probe PREFIX seam: point the LIVE-env probe at an empty sandbox so
# the preflight deterministically exercises the mirror apk-fetch branch (the
# dev/CI host itself may or may not carry a loader binary)
export ALPINE_FDE_LOADER_PROBE_PREFIX=$T/no-live-loader

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
printf '%s %s\n' "openssl" "$*" >>"$ALPINE_FDE_TEST_LOG"
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
            >>"$ALPINE_FDE_TEST_LOG"
        exit 91
    fi
    prev=$a
done
printf 'cryptsetup %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
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
printf 'lsblk %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' "$PARTUUID_CANON" ;;
esac
exit 0
EOF

chmod +x "$T/stub/cryptsetup" "$T/stub/id" "$T/stub/lsblk" "$T/stub/openssl"

# mountpoint — the reset records' runtime probe for stale target mounts: log
# argv and report NOT-a-mountpoint (pristine semantics, exit 1) so the reset
# guards no-op on this sandbox; the faked-state run below flips it to exit 0.
cat >"$T/stub/mountpoint" <<'EOF'
#!/bin/sh
printf 'mountpoint %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
exit 1
EOF
chmod +x "$T/stub/mountpoint"

# chroot — log argv; when the guest line is the §9.1 step 3 platform-key
# ceremony, simulate its OUTPUT on the target (the in-chroot keygen leaves an
# UNencrypted release.pem in /etc/alpine-fde/keys — the input the §9.1 step 4
# credential ceremony encrypts). Every other guest line is logged only.
cat >"$T/stub/chroot" <<EOF
#!/bin/sh
printf '%s %s\n' "chroot" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
case "\$*" in
    *"provision stage1"*)
        mkdir -p "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys"
        printf -- '-----BEGIN PRIVATE KEY-----\nfake-plaintext-release-key\n-----END PRIVATE KEY-----\n' \\
            >"$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem"
        ;;
    *"/usr/sbin/chpasswd"*)
        # item 12: snapshot the piped user:password line so the test can prove
        # the empty-Enter default REALLY reused the recovery passphrase
        cat >"\$CHPASSWD_CAPTURE"
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/chroot"
export PATH="$T/stub:$PATH"

# --- fixtures ------------------------------------------------------------------
# hooks/ Alpine layout (G-C16): the templates install's preflight requires
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
mkdir -p "$ALPINE_FDE_EFIVARS_DIR"
mkvar SetupMode 1   # §9.1 preflight: Stage 1 runs with the vendor PK cleared

# §9.1 step 4 credential-ceremony answers (the documented test/CI seam: the
# no-echo prompts read stdin). item 12 (AMENDED): the ceremony asks the
# RECOVERY PASSPHRASE FIRST (confirm-typed pair); the user password and the
# release-key passphrase DEFAULT to it on bare Enter — the S-24 empty-line
# convention now applies to BOTH optional fields (empty line = reuse recovery):
# 4 lines = recovery pair + one empty Enter per derived prompt.
ANSWERS=$T/answers
cat >"$ANSWERS" <<'EOF'
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz


EOF
export CHPASSWD_CAPTURE=$T/chpasswd.stdin   # the chroot stub snapshots chpasswd stdin here

first_line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

run_install() { # extra args pass through (e.g. a second --disk); answers on stdin
    : >"$ALPINE_FDE_TEST_LOG"
    rm -rf "$ALPINE_FDE_INSTALL_MNT"
    OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" "$@" <"$ANSWERS" 2>&1)
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
assert_eq "SetupMode=0: zero commands executed" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
mkvar SetupMode 1

# =============================================================================
# §9.1 Stage 1 execution (single-disk, Btrfs default): plan runs rc 0 under
# stubs — UNATTENDED (stdin closed). G-C23: the staged ephemeral key SURVIVES
# until the cryptsetup plan steps run and is SCRUBBED at teardown.
# =============================================================================
run_install
assert_eq "§9.1 Stage 1 chroot install rc 0 (ceremony answers on stdin)" "0" "$RC"
assert_not_contains "BR-01: --key-file names an EXISTING file at cryptsetup execution time" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "key-file target missing at execution time"
assert_contains "BR-01: luksFormat ran scripted via the staged ephemeral key-file" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "cryptsetup --batch-mode luksFormat"
EPHKEY=$(grep -oE "$T/alpine-fde-ephkey\.[A-Za-z0-9]{6}" <<<"$OUT" | head -1)
assert_eq "G-C23: ephemeral key staged under the tmpfs seam" "1" \
    "$([ -n "$EPHKEY" ] && echo 1 || echo 0)"
assert_contains "G-C23: keyslot 2 (TEMPORARY) formatted with the ephemeral key via --key-file" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "cryptsetup --batch-mode luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid"
assert_eq "G-C23: keyslot 0 NEVER used at luksFormat (reserved for the ceremony, §7.2)" "0" \
    "$(grep -Fc 'luksFormat --key-slot 0' "$ALPINE_FDE_TEST_LOG")"
assert_contains "G-C23: open uses the same staged key-file" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "cryptsetup open --key-file $EPHKEY"
assert_eq "G-C23: NO operator passphrase consumed anywhere" "0" \
    "$(grep -c 'ALPINE_FDE_DISK_PASSPHRASE=' <<<"$OUT")"
assert_not_contains "G-C23: NO interactive passphrase prompt in the run" "$OUT" \
    "Set disk encryption passphrase"

# =============================================================================
# PHYSICAL-MEDIA block sequence (real-install defects 1+2) + batch-mode LUKS
# (defect 5): executed at the observed-argv level through the stubs.
# =============================================================================
LOG=$(cat "$ALPINE_FDE_TEST_LOG")
# execution level: the log records the stubs' argv — the guard text itself is
# pinned verbatim at the plan-text level (install_dryrun.sh / install_qemu_emit.sh)
assert_contains "physical: btrfs module loaded explicitly (not auto-loaded on a physical boot)" "$LOG" \
    "modprobe btrfs"
assert_contains "physical: coldplug (mdev -s) settles /dev before partitioning" "$LOG" \
    "mdev -s"
L_MODP=$(first_line_no "$LOG" "modprobe btrfs")
L_COLDP=$(first_line_no "$LOG" "mdev -s")
L_HSFD=$(first_line_no "$LOG" "sfdisk")
# real-server blocker #7 (bootctl): the preflight resolves the loader EFI
# binary BEFORE any disk mutation — live env first, then the mirror's
# systemd-boot apk (fixture-served); only a DECISIVE negative dies.
assert_contains "blocker #7: preflight resolves the loader binary via the mirror systemd-boot apk (decisive positive)" "$OUT" \
    "ships the loader EFI binary"
L_LDPROBE=$(first_line_no "$LOG" "apk fetch --quiet --stdout systemd-boot")
assert_eq "blocker #7: the loader-binary preflight probe runs BEFORE partitioning" "1" \
    "$(( L_LDPROBE > 0 && L_LDPROBE < L_HSFD ? 1 : 0 ))"
assert_eq "physical: order — modprobe BEFORE coldplug BEFORE sfdisk" "1" \
    "$(( L_MODP > 0 && L_MODP < L_COLDP && L_COLDP < L_HSFD ? 1 : 0 ))"
assert_eq "defect 5: EVERY executed luksFormat ran --batch-mode (zero interactive dangerous-action prompts)" "0" \
    "$(grep 'luksFormat' "$ALPINE_FDE_TEST_LOG" | grep -vc -- '--batch-mode')"

# =============================================================================
# §9.1 step 4 credential ceremony (ADR-20 amended): executed host-side, the
# ONLY credential seam is stdin (the answers file) — no flag, no env var.
# =============================================================================
assert_contains "ceremony (1/3): user password set in-chroot via chpasswd" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "chroot $ALPINE_FDE_INSTALL_MNT /usr/sbin/chpasswd"
assert_eq "ceremony: NO interactive passwd(1) step anywhere" "0" \
    "$(grep -Ec '[/:]passwd( |$)' <<<"$(cat "$ALPINE_FDE_TEST_LOG")")"
# item 12: recovery FIRST; the two derived prompts defaulted to it on bare Enter
assert_contains "item 12: recovery prompt hint shown (press Enter to reuse)" "$OUT" \
    "press Enter to reuse the recovery passphrase"
assert_eq "item 12: the empty-Enter user password REALLY was the recovery passphrase (chpasswd stdin snapshot)" \
    "admin:Fin4l-Rec0very-X9k2-!qmwjpz" "$(cat "$CHPASSWD_CAPTURE")"
assert_eq "item 12: release-key prompt ALSO defaulted (exactly 2 hints: user password + release key)" "2" \
    "$(grep -c 'reusing the recovery passphrase' <<<"$OUT")"
# item 27 (real-server failure #4): the recovery enrollment targets the LUKS
# CONTAINER devices (the luksFormat targets) — a /dev/mapper/* node is the
# DECRYPTED view and luksAddKey against it fails "not a valid LUKS device".
# e2e is BLIND to this class: the fixture pre-seeds keyslot 0 and the host
# ceremony path is never really executed there — these execution-level pins
# are the harness guard.
ADDKEY=$(grep -m1 'luksAddKey' "$ALPINE_FDE_TEST_LOG")
assert_contains "item 27: recovery luksAddKey targets the PRIMARY LUKS CONTAINER dev (${DISK}2)" "$ADDKEY" \
    "cryptsetup luksAddKey --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --key-file $EPHKEY ${DISK}2"
assert_not_contains "item 27: recovery luksAddKey NEVER targets /dev/mapper (mapper = decrypted view)" "$ADDKEY" "/dev/mapper/"
LUKSDUMP_CER=$(grep -m1 'luksDump' "$ALPINE_FDE_TEST_LOG")
assert_not_contains "item 27: ceremony crash-resume luksDump also targets the CONTAINER (not the mapper)" "$LUKSDUMP_CER" "/dev/mapper/"
assert_contains "item 27: ceremony crash-resume luksDump probes the container dev" "$LUKSDUMP_CER" "luksDump ${DISK}2"
assert_eq "item 27 lint: ZERO executed cryptsetup container-ops (luksFormat/luksAddKey/luksRemoveKey) targeted /dev/mapper" "0" \
    "$(grep 'cryptsetup' "$ALPINE_FDE_TEST_LOG" | grep -E 'luksFormat|luksAddKey|luksRemoveKey' | grep -c '/dev/mapper/')"
assert_contains "ceremony (3/3): release.pem encrypted via keys_encrypt_release (ADR-18 pkcs8)" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256"
assert_eq "ceremony: NO secret ever appears in command argv (the log IS the argv record)" "0" \
    "$(grep -Ec 'U5er-P4ss|Fin4l-Rec0very|R3lease-K3ypass' <<<"$(cat "$ALPINE_FDE_TEST_LOG")")"
assert_eq "ceremony: NO credential env seam in the emitted run" "0" \
    "$(grep -Ec 'ALPINE_FDE_(KEY|RECOVERY|DISK)_PASSPHRASE=' <<<"$OUT")"
assert_eq "ceremony: recovery passfile scrubbed (keys_scrub, I1)" "0" \
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-ceremony.*' 2>/dev/null | wc -l)"
assert_eq "ceremony: encrypt stage scrubbed (keys_encrypt_release tmp)" "0" \
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-enc.*' 2>/dev/null | wc -l)"
assert_eq "ceremony (3/3): release.pem on target IS the encrypted form" "1" \
    "$(grep -qc 'fake-pbes2-encrypted-ADR18' "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem" && echo 1 || echo 0)"
assert_eq "ceremony (3/3): encrypted release.pem locked 0400" "400" \
    "$(stat -c '%a' "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem")"
# ceremony order: AFTER the platform keys (release.pem must exist) and AFTER
# every MECHANICAL step (user flow directive: the credential ceremony is the
# LAST interactive section); item 12: recovery passphrase asked FIRST
O_KEYGEN=$(first_line_no "$OUT" "provision stage1 --mode in-chroot")
O_CERU=$(first_line_no "$OUT" "host: inst_ceremony_user_password")
O_CERR=$(first_line_no "$OUT" "host: inst_ceremony_recovery")
O_CERK=$(first_line_no "$OUT" "host: inst_ceremony_release_key")
O_ENROLL=$(first_line_no "$OUT" "fw_auth_enroll")
O_COPY=$(first_line_no "$OUT" "EFI/BOOT/BOOTX64.EFI")
O_HOOKS=$(first_line_no "$OUT" "etc/kernel-hooks.d/alpine-fde-build.hook")
O_STATE=$(first_line_no "$OUT" "host: inst_state_write installed")
assert_eq "order: platform keys BEFORE the ceremony (release.pem must exist)" "1" \
    "$(( O_KEYGEN > 0 && O_KEYGEN < O_CERR ? 1 : 0 ))"
assert_eq "order: item 12 — recovery (1/3) BEFORE user password (2/3) BEFORE release key (3/3)" "1" \
    "$(( O_CERR > 0 && O_CERR < O_CERU && O_CERU < O_CERK ? 1 : 0 ))"
assert_eq "order (user flow directive): NVRAM enrollment BEFORE the credential ceremony (mechanical first)" "1" \
    "$(( O_ENROLL > 0 && O_ENROLL < O_CERR ? 1 : 0 ))"
assert_eq "order (user flow directive): boot-manager guarded file copy BEFORE the credential ceremony" "1" \
    "$(( O_COPY > 0 && O_COPY < O_CERR ? 1 : 0 ))"
assert_eq "order (user flow directive): hooks staging BEFORE the credential ceremony (no secret; a ukictl-build input)" "1" \
    "$(( O_HOOKS > 0 && O_HOOKS < O_CERR ? 1 : 0 ))"
assert_eq "order (user flow directive): install-state write BEFORE the credential ceremony (mechanical)" "1" \
    "$(( O_STATE > 0 && O_STATE < O_CERR ? 1 : 0 ))"

LUKS_UUID=$(grep -oE -- '--uuid [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$ALPINE_FDE_TEST_LOG" | head -1 | awk '{print $2}')
ROOTFS_UUID=$(grep -oE -- '-U [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$ALPINE_FDE_TEST_LOG" | head -1 | awk '{print $2}')
assert_eq "fixture: luksFormat pinned an explicit uuid" "1" "$([ -n "$LUKS_UUID" ] && echo 1 || echo 0)"
assert_eq "fixture: mkfs.btrfs pinned an explicit uuid" "1" "$([ -n "$ROOTFS_UUID" ] && echo 1 || echo 0)"
# G-ST1: the btrfs filesystem + subvolume flow ran against the mapper
assert_contains "G-ST1: mkfs.btrfs ran on the mapper" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "mkfs.btrfs -U $ROOTFS_UUID /dev/mapper/root-crypt"
assert_contains "G-ST1: subvolume @ created" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "btrfs subvolume create $ALPINE_FDE_INSTALL_MNT/@"
assert_contains "G-ST1: subvolume @home created" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "btrfs subvolume create $ALPINE_FDE_INSTALL_MNT/@home"
assert_contains "G-ST1: subvolume @snapshots created" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "btrfs subvolume create $ALPINE_FDE_INSTALL_MNT/@snapshots"
assert_contains "G-ST1: @ remounted as root" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "mount -o subvol=@ /dev/mapper/root-crypt $ALPINE_FDE_INSTALL_MNT"

MNT_ETC=$ALPINE_FDE_INSTALL_MNT/etc
# G-C1/C2/C3: apk populate + repositories drop (apt/dpkg retired)
assert_contains "§3.3: apk populate ran on the target" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "apk add --root $ALPINE_FDE_INSTALL_MNT --initdb alpine-base"
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
# item 26a (ADR-7 AMENDED — zram removed from the design): NO zram-init
# anywhere in the install path — no conf.d drop on the target, no rc-update
# enable (which ran BEFORE the txn installing the package: real-server failure
# #2, "service zram-init does not exist"), no package entry. NOT a reorder.
assert_eq "target: NO zram-init conf.d drop (item 26a, ADR-7 amended)" "0" \
    "$([ -e "$MNT_ETC/conf.d/zram-init" ] && echo 1 || echo 0)"
assert_eq "target: NO zram-init rc-update record executed (item 26a)" "0" \
    "$(grep -c 'rc-update add zram-init' "$ALPINE_FDE_TEST_LOG")"
assert_eq "fstab: zero swap lines (ADR-7: no disk swap)" "0" \
    "$(grep -c 'swap' "$MNT_ETC/fstab")"
# §3.1 additions set lands in the in-guest apk transaction
CHROOT_TXN=$(grep -m1 'apk add --no-cache' "$ALPINE_FDE_TEST_LOG")
for want in mkinitfs py3-pefile doas ukify-kernel-hook; do
    assert_contains "apk txn includes $want (§3.1, executed)" "$CHROOT_TXN" "$want"
done
assert_not_contains "apk txn has NO zram-init (item 26a, ADR-7 amended)" "$CHROOT_TXN" "zram-init"
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
# §9.1 step 2/8/9: pending baseline + install-state ON TARGET
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
    "$(grep -c 'cp .*baseline.json' "$ALPINE_FDE_TEST_LOG")"
# G-C25 (ADR-20 amendment #4): NO unfinalized banner is ever written — the
# banner path is REMOVED; install creates neither /etc/motd nor /etc/issue on
# the target and never synthesizes or touches operator content
assert_eq "G-C25: NO /etc/motd written (banner path removed, ADR-20 #4)" "0" \
    "$([ -e "$MNT_ETC/motd" ] && echo 1 || echo 0)"
assert_eq "G-C25: NO /etc/issue written (banner path removed, ADR-20 #4)" "0" \
    "$([ -e "$MNT_ETC/issue" ] && echo 1 || echo 0)"
assert_eq "G-C25: NO banner helper invoked anywhere in the run" "0" \
    "$(grep -c 'fde_motd_banner' <<<"$OUT")"
assert_file_exists "§9.1 step 9: install-state written ON TARGET" \
    "$MNT_ETC/alpine-fde/install-state.json"
assert_eq "install-state: state=installed" "installed" \
    "$(istate_get "$MNT_ETC/alpine-fde/install-state.json" state)"
# G-C28 (amended): `installed` is the LAST state write (the banner record it
# used to follow was removed with the banner path, ADR-20 #4)
L_STATE=$(printf '%s\n' "$OUT" | grep -Fnm1 "host: inst_state_write installed" | cut -d: -f1)
assert_eq "G-C28: inst_state_write installed is a host plan record" "1" \
    "$(( L_STATE > 0 ? 1 : 0 ))"
# G-C26 (AMENDED by the user's flow directives): the OsIndications firmware
# trip is BACK — but ONLY on the DEFERRED-enrollment path, as a
# runtime-conditional TAIL record. The default fixture run is DEFERRED (the
# in-chroot enrollment is stubbed, so PK is absent on the live efivars);
# under the CI seam (NO_REBOOT) the confirm + trip + reboot records are not
# emitted — the verdict probe + the deferred instructions are.
assert_eq "G-C26: efivars dir holds NO OsIndications variable under the CI seam" "0" \
    "$(find "$ALPINE_FDE_EFIVARS_DIR" -name 'OsIndications-*' 2>/dev/null | wc -l)"
assert_contains "deferred enrollment: the verdict probe record probes PK on the live efivars" "$OUT" \
    "if fw_var_present $ALPINE_FDE_EFIVARS_DIR PK; then INST_SB_ENROLLED=1; else INST_SB_ENROLLED=0; fi"
assert_contains "deferred enrollment: the manual-import instructions print at the VERY END (EXECUTED output, not the record echo)" "$OUT" \
    "alpine-fde: Secure Boot key material is staged under /efi/alpine-fde-keys"
assert_contains "deferred enrollment: instructions name the DIRECT-from-ESP import FIRST (user directive 2)" "$OUT" \
    "import DIRECTLY from the internal ESP"
assert_not_contains "CI seam: NO Enter-confirmation record under NO_REBOOT" "$OUT" \
    "press Enter to reboot into firmware setup"
assert_not_contains "CI seam: NO firmware-setup trip record under NO_REBOOT" "$OUT" \
    "fw_osindications_set"
assert_not_contains "CI seam: NO reboot record under NO_REBOOT" "$OUT" "then reboot"

# =============================================================================
# §9.1 in-chroot sequence: order + argv as observed through the chroot stub
# =============================================================================
LOG=$(cat "$ALPINE_FDE_TEST_LOG")
assert_contains "§9.1 step 1: apk additions txn ran in-guest" "$LOG" "apk add --no-cache"
APK_TXN_LOG=$(grep -m1 'apk add --no-cache' "$ALPINE_FDE_TEST_LOG")
assert_contains "apk txn includes btrfs-progs (default fs, topology-conditional)" \
    "$APK_TXN_LOG" "btrfs-progs"
assert_contains "§9.1 step 1: user account created in-guest (locked; password set by the §9.1 step 4 ceremony)" "$LOG" \
    "adduser -D -s /bin/ash admin"
assert_contains "§9.1 step 1: OpenRC networking enabled in-guest" "$LOG" \
    "rc-update add networking boot"
assert_contains "§9.1 step 3: platform-key ceremony invoked in-chroot (custody DEFERRED to ceremony 3/3)" "$LOG" \
    "provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys --defer-custody"
# item 12/reorder close-out (user ruling: LUKS recovery is the FIRST password
# asked, period): the executed guest record carries --defer-custody — provision
# stage1's own keys_encrypt_release prompt would otherwise be the FIRST
# password asked (no hint, recovery not yet asked). With the defer, the ONLY
# release-key prompt in the whole run belongs to ceremony 3/3 (the "exactly 2
# hints" pin above already proves its Enter-to-reuse default fired), and the
# ceremony DOES encrypt the plaintext stage1 leaves (the pin below).
assert_contains "defer-custody: the executed provision record defers release.pem encryption to ceremony 3/3" "$OUT" \
    "provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys --defer-custody"
assert_eq "defer-custody: NO release-key prompt before the ceremony (exactly ONE reusing-hint per derived prompt, both ceremony-owned)" "2" \
    "$(grep -c 'reusing the recovery passphrase' <<<"$OUT")"
assert_contains "§9.1 step 4: NVRAM enrollment db->KEK->PK in-chroot" "$LOG" \
    "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys /efi"
# real-server blocker #7: the boot manager installs by GUARDED FILE COPY of
# the systemd-boot loader EFI binary — never a bootctl invocation (Alpine
# ships NO bootctl binary; the retired record died "/bin/sh: bootctl: not
# found" POST-ceremony)
COPY_LOG=$(grep -m1 'BOOTX64.EFI' "$ALPINE_FDE_TEST_LOG")
assert_contains "blocker #7: boot manager installed by guarded file copy (loader probed fail-closed in-chroot)" "$COPY_LOG" \
    'for p in /usr/share/systemd/bootctl/systemd-bootx64.efi /usr/lib/systemd/boot/efi/systemd-bootx64.efi'
assert_contains "blocker #7: the copy record targets BOTH ESP homes (canonical + removable-media fallback)" "$COPY_LOG" \
    'cp "$ldr" /efi/EFI/systemd/systemd-bootx64.efi && cp "$ldr" /efi/EFI/BOOT/BOOTX64.EFI'
assert_contains "blocker #7: the copy record dies fail-closed when no loader binary exists" "$COPY_LOG" \
    'no systemd-boot loader EFI binary found in-chroot'
assert_eq "blocker #7: ZERO bootctl invocations anywhere in the run" "0" \
    "$(grep -Ec 'bootctl( |$)' <<<"$OUT $(cat "$ALPINE_FDE_TEST_LOG")")"
assert_contains "§9.1 step 5: ukictl build in-chroot (boot manager + UKI, G-C7 CLI path)" "$LOG" \
    "/opt/alpine-fde/bin/alpine-fde ukictl build"
# G-C24: provisional seal guest line after the build
# item 27 extended: the seal/token choreography consumes the LUKS2 HEADER —
# it must address the CONTAINER dev (${DISK}2), never the mapper
assert_contains "§9.1 step 6: provisional seal guest line ran in-chroot against the CONTAINER dev" "$LOG" \
    "seal_provisional /etc/alpine-fde/keys \$d /run/alpine-fde/pcrsig.json /run/alpine-fde/token-\${d##*/}.json"
assert_contains "§9.1 step 6: the seal loop list carries the PRIMARY CONTAINER dev" "$LOG" \
    "for d in ${DISK}2; do"
assert_eq "item 27 lint (extended): the seal/token choreography record NEVER receives /dev/mapper" "0" \
    "$(grep -m1 'seal_provisional' "$ALPINE_FDE_TEST_LOG" | grep -c '/dev/mapper/')"
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
    "$SEAL_LINE" 'alpine-fde-seal.'
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
# user directive 3: the deferred instructions print at the VERY END — after
# the scrub; the verdict probe precedes them
O_PROBE=$(first_line_no "$OUT" "INST_SB_ENROLLED=1")
O_INSTR=$(first_line_no "$OUT" "alpine-fde: Secure Boot key material is staged under /efi/alpine-fde-keys")
assert_eq "order (user directive 3): scrub BEFORE the enrollment verdict probe BEFORE the deferred instructions" "1" \
    "$(( L_SCRUB > 0 && O_PROBE > L_SCRUB && O_INSTR > O_PROBE ? 1 : 0 ))"

# =============================================================================
# item 26b (real-install failure #3): DNS preflight + target resolv.conf seed.
# The apk populate resolves the mirror via the LIVE env resolver; the in-chroot
# transaction resolves via the TARGET's /etc/resolv.conf (absent on a fresh
# rootfs). Preflight probes the mirror host with a busybox-safe nslookup (the
# probe FAILS CLOSED before any mutation when resolution fails); a guarded
# host record seeds the live resolver into the target before the transaction.
# =============================================================================
LOG=$(cat "$ALPINE_FDE_TEST_LOG")
assert_contains "26b: DNS preflight probed the mirror host (busybox nslookup)" "$LOG" \
    "nslookup dl-cdn.alpinelinux.org"
L_DNSPROBE=$(first_line_no "$LOG" "nslookup dl-cdn")
assert_eq "26b: DNS preflight runs BEFORE any disk mutation (before partitioning)" "1" \
    "$(( L_DNSPROBE > 0 && L_DNSPROBE < L_HSFD ? 1 : 0 ))"
if [ -f /etc/resolv.conf ]; then
    assert_file_exists "26b: target /etc/resolv.conf seeded from the live env" "$MNT_ETC/resolv.conf"
    # cp is a real host command (not a stub) — order via the runner's own
    # host/guest info lines in OUT
    L_SEEDCP=$(printf '%s\n' "$OUT" | grep -Fnm1 "cp /etc/resolv.conf $ALPINE_FDE_INSTALL_MNT/etc/resolv.conf" | cut -d: -f1)
    L_SEEDTXN=$(printf '%s\n' "$OUT" | grep -Fnm1 "guest: apk add --no-cache" | cut -d: -f1)
    assert_eq "26b: target DNS seed executed BEFORE the in-chroot apk transaction" "1" \
        "$(( L_SEEDCP > 0 && L_SEEDTXN > 0 && L_SEEDCP < L_SEEDTXN ? 1 : 0 ))"
fi
# =============================================================================
# item 26 ext (real-install failure #5): target apk KEYRING seed. apk verifies
# mirror indexes against the TARGET's <mnt>/etc/apk/keys ONLY — absent on a
# fresh rootfs, and --initdb does NOT copy the host keyring — so the populate
# dies `UNTRUSTED signature` on any real server (the repositories seeding alone
# is half the fix). ONE guarded host record seeds the live keyring after the
# repositories drop, BEFORE the populate.
# =============================================================================
L_KEYSEED=$(first_line_no "$OUT" "cp -a /etc/apk/keys $ALPINE_FDE_INSTALL_MNT/etc/apk/")
L_HREPOS=$(first_line_no "$OUT" "etc/apk/repositories")
L_HPOP=$(first_line_no "$OUT" "host: apk add --root $ALPINE_FDE_INSTALL_MNT --initdb alpine-base")
assert_eq "26ext: keys-seed record is a host plan record" "1" "$(( L_KEYSEED > 0 ? 1 : 0 ))"
assert_eq "26ext: order repositories drop -> keys seed -> apk populate" "1" \
    "$(( L_HREPOS > 0 && L_KEYSEED > 0 && L_HPOP > 0 && L_HREPOS < L_KEYSEED && L_KEYSEED < L_HPOP ? 1 : 0 ))"
assert_contains "26ext: guard carries the host-keydir-missing warn branch" "$OUT" \
    "no keyring on the live env"
if [ -d /etc/apk/keys ]; then
    assert_file_exists "26ext: target keyring seeded from the live env" "$MNT_ETC/apk/keys"
else
    assert_eq "26ext: no live keyring -> warn branch executed, target keyring NOT faked" "1" \
        "$([ ! -e "$MNT_ETC/apk/keys" ] && grep -qF 'alpine-fde: warn: no keyring on the live env' <<<"$OUT" && echo 1 || echo 0)"
fi
# =============================================================================
# real-server blocker #7 (bootctl): loader-binary preflight FAILS CLOSED —
# with a mirror systemd-boot package that carries NO loader EFI binary the
# install dies 64 BEFORE any disk mutation (the retired bootctl record used
# to die POST-ceremony: "/bin/sh: bootctl: not found").
# =============================================================================
LOADER_APK_FIXTURE=$T/systemd-boot-noloader.apk
: >"$ALPINE_FDE_TEST_LOG"
NL_OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
NL_RC=$?
LOADER_APK_FIXTURE=$T/systemd-boot-loader.apk
assert_eq "blocker #7: loader-less systemd-boot package -> fail-closed 64 (preflight, before partitioning)" "64" "$NL_RC"
assert_contains "blocker #7: the error names the decisive negative" "$NL_OUT" \
    "ships NO loader EFI binary"
assert_contains "blocker #7: the error says what to fix" "$NL_OUT" \
    "fix the mirror/package set before installing"
assert_eq "blocker #7: nothing executed but the mirror fetch probe" "1" \
    "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
assert_contains "blocker #7: that one command IS the package fetch probe" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "apk fetch --quiet --stdout systemd-boot"

# live-env positive: with the probe PREFIX seam seeded, the live env itself
# satisfies the loader preflight (no mirror fetch needed)
mkdir -p "$T/live-loader/usr/lib/systemd/boot/efi"
: >"$T/live-loader/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
ALPINE_FDE_LOADER_PROBE_PREFIX=$T/live-loader
LV_OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
LV_RC=$?
ALPINE_FDE_LOADER_PROBE_PREFIX=$T/no-live-loader
assert_eq "blocker #7: loader present in the live env -> preflight passes" "0" "$LV_RC"
assert_contains "blocker #7: the live-env probe reports the resolved loader path" "$LV_OUT" \
    "loader EFI binary present in the live env"

# G-C23/I1: the ephemeral key does NOT survive the run
assert_eq "G-C23: ephemeral key-file scrubbed at teardown" "0" \
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-ephkey.*' 2>/dev/null | wc -l)"
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
    "$ALPINE_FDE_INSTALL_MNT/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
assert_eq "target: mkinitfs unseal hook executable" "1" \
    "$([ -x "$ALPINE_FDE_INSTALL_MNT/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh" ] && echo 1 || echo 0)"
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
    "$(cat "$ALPINE_FDE_HOOKS_DIR/openrc/alpine-fde-finalize")" \
    "$(cat "$MNT_ETC/init.d/alpine-fde-finalize")"
assert_contains "target: finalize advisory enabled for the default runlevel" "$LOG" \
    "rc-update add alpine-fde-finalize default"
assert_eq "target: NO systemd finalize unit shipped (ADR-20 Stage 3)" "0" \
    "$([ -e "$MNT_ETC/systemd/system/alpine-fde-finalize.service" ] && echo 1 || echo 0)"
assert_eq "target: NO multi-user.target.wants enable record" "0" \
    "$(grep -c 'multi-user.target.wants' <<<"$LOG")"

# =============================================================================
# H-02: binds (incl. the §9.1 efivars bind) run BEFORE guest steps and are
# torn down BEFORE `umount -R`.
# =============================================================================
assert_contains "H-02: /proc bound into the target" "$LOG" \
    "mount -t proc proc $ALPINE_FDE_INSTALL_MNT/proc"
assert_contains "H-02: /sys bound into the target" "$LOG" \
    "mount --bind /sys $ALPINE_FDE_INSTALL_MNT/sys"
assert_contains "H-02: /dev bound into the target" "$LOG" \
    "mount --bind /dev $ALPINE_FDE_INSTALL_MNT/dev"
assert_contains "§9.1: efivars bound into the target" "$LOG" \
    "mount --bind /sys/firmware/efi/efivars $ALPINE_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
L_BINDT=$(first_line_no "$LOG" "mount --bind /dev")
L_BINDU=$(first_line_no "$LOG" "umount $ALPINE_FDE_INSTALL_MNT/dev")
assert_eq "H-02: binds torn down before umount -R" "1" "$(( L_BINDT > 0 && L_BINDU > L_BINDT && L_UMNTR > L_BINDU ? 1 : 0 ))"
assert_contains "H-02: teardown umounts the efivars bind" "$LOG" \
    "umount $ALPINE_FDE_INSTALL_MNT/dev $ALPINE_FDE_INSTALL_MNT/sys $ALPINE_FDE_INSTALL_MNT/proc $ALPINE_FDE_INSTALL_MNT/sys/firmware/efi/efivars"
# L-04b: guest steps never see ALPINE_FDE_DISK_PASSPHRASE (defensive strip stays)
assert_contains "L-04b: chroot invocation strips the passphrase variable" \
    "$LOG" "-u ALPINE_FDE_DISK_PASSPHRASE"

# =============================================================================
# RESET of a previous FAILED attempt (user report: "install show reset failed
# installation status, when install restarts again, so that new install is
# able to continue"). E2E-mock: REAL records, PATH-stubbed collaborators,
# observed argv/effects. The pristine main run above: the guards no-op'd
# (nothing under the target root is a mountpoint; no mapper-dir seam set, so
# the records glob the real /dev/mapper, which carries no root* nodes here).
# =============================================================================
MAIN_LOG=$(cat "$ALPINE_FDE_TEST_LOG")
assert_contains "reset: pristine run — the runtime probe RAN (records evaluated, not skipped)" "$MAIN_LOG" \
    "mountpoint -q $ALPINE_FDE_INSTALL_MNT"
# the reset umount did NOT fire in the pristine run: no `umount -R <mnt>` line
# BEFORE partitioning (the plan TEARDOWN later fires the same argv — scope by
# line order, not by count)
O_RESET_UM=$(grep -nx "umount -R $ALPINE_FDE_INSTALL_MNT" <<<"$MAIN_LOG" | cut -d: -f1 | head -1)
O_MAIN_SFD=$(first_line_no "$MAIN_LOG" "sfdisk")
assert_eq "reset: pristine run — the recursive stale-tree umount did NOT fire before partitioning" "1" \
    "$(( O_RESET_UM == 0 || O_RESET_UM > O_MAIN_SFD ? 1 : 0 ))"
# anchor on line START: the host record echo (`info "host: ...echo 'alpine-fde:
# info: reset: previous...'") also CONTAINS the phrase; only the FIRED echo
# output begins the line with it
assert_eq "reset: pristine run — the guarded status echo did NOT fire" "0" \
    "$(grep -c '^alpine-fde: info: reset: previous failed install detected' <<<"$OUT")"
O_RESET=$(first_line_no "$OUT" "if mountpoint -q $ALPINE_FDE_INSTALL_MNT ")
O_HSFD=$(first_line_no "$OUT" "| sfdisk $DISK")
assert_eq "reset: records precede partitioning (a re-run can continue)" "1" \
    "$(( O_RESET > 0 && O_RESET < O_HSFD ? 1 : 0 ))"

# FAKED stale state: mountpoint reports "is a mountpoint", the mapper-dir seam
# (ALPINE_FDE_INSTALL_MAPPER_DIR) points at a sandbox dir holding fake stale
# nodes, and a fake sysfs bcache set dir holds a stop file — every reset
# action must FIRE, in order, BEFORE partitioning, each with a status line.
mkdir -p "$T/fake-mapper" "$T/fake-bcache/1111aaaa-2b3c-4d5e-6f70-8192a3b4c5d6"
: >"$T/fake-mapper/root-crypt"
: >"$T/fake-mapper/root1"
: >"$T/fake-bcache/1111aaaa-2b3c-4d5e-6f70-8192a3b4c5d6/stop"  # real set dirs carry a stop file
cat >"$T/stub/mountpoint" <<'EOF'
#!/bin/sh
printf 'mountpoint %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
exit 0
EOF
chmod +x "$T/stub/mountpoint"
ALPINE_FDE_INSTALL_MAPPER_DIR=$T/fake-mapper \
    ALPINE_FDE_INSTALL_BCACHE_SYSFS=$T/fake-bcache run_install
assert_eq "reset (faked stale state): install rc 0 with the reset armed" "0" "$RC"
FAKED_LOG=$(cat "$ALPINE_FDE_TEST_LOG")
L_RSFD=$(first_line_no "$FAKED_LOG" "sfdisk")
# item 26d: the mount teardown is ONE guarded RECURSIVE umount (a failed
# attempt that died mid-chroot leaves stale binds — /mnt/proc, /mnt/sys,
# /mnt/dev, efivars — a fixed list misses)
L_RREC=$(grep -nx "umount -R $ALPINE_FDE_INSTALL_MNT" <<<"$FAKED_LOG" | cut -d: -f1 | head -1)
L_RCLOSE1=$(first_line_no "$FAKED_LOG" "cryptsetup close root1")
L_RCLOSE=$(first_line_no "$FAKED_LOG" "cryptsetup close root-crypt")
assert_eq "reset (faked): stale target tree RECURSIVELY unmounted BEFORE partitioning (item 26d)" "1" \
    "$(( L_RREC > 0 && L_RREC < L_RSFD ? 1 : 0 ))"
assert_eq "reset (faked): stale root1 mapping closed (rootN glob, seam dir) BEFORE partitioning" "1" \
    "$(( L_RCLOSE1 > 0 && L_RCLOSE1 < L_RSFD ? 1 : 0 ))"
assert_eq "reset (faked): stale root-crypt mapping closed BEFORE partitioning" "1" \
    "$(( L_RCLOSE > 0 && L_RCLOSE < L_RSFD ? 1 : 0 ))"
assert_eq "reset (faked): mapper closes after the recursive umount" "1" \
    "$(( L_RREC < L_RCLOSE1 && L_RCLOSE1 < L_RCLOSE ? 1 : 0 ))"
assert_contains "reset (faked): status — previous failed install detected (the user's visibility ask)" \
    "$OUT" "previous failed install detected"
assert_contains "reset (faked): per-item status — stale tree recursively unmounted (item 26d)" "$OUT" \
    "recursively unmounted stale target tree $ALPINE_FDE_INSTALL_MNT"
assert_contains "reset (faked): per-item status — stale mapper closed" "$OUT" \
    "closed stale mapper $T/fake-mapper/root-crypt"
assert_eq "reset (faked): live bcache set STOPPED — set UUID echoed into its own stop file" \
    "1111aaaa-2b3c-4d5e-6f70-8192a3b4c5d6" \
    "$(cat "$T/fake-bcache/1111aaaa-2b3c-4d5e-6f70-8192a3b4c5d6/stop")"
L_BCSTOP=$(first_line_no "$OUT" "stopped live bcache set")
L_RSFD_OUT=$(first_line_no "$OUT" "| sfdisk $DISK")   # same capture as L_BCSTOP (OUT, not the argv log)
assert_eq "reset (faked): bcache stop reported BEFORE partitioning" "1" \
    "$(( L_BCSTOP > 0 && L_RSFD_OUT > 0 && L_BCSTOP < L_RSFD_OUT ? 1 : 0 ))"
# restore pristine semantics for the later sections
cat >"$T/stub/mountpoint" <<'EOF'
#!/bin/sh
printf 'mountpoint %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
exit 1
EOF
chmod +x "$T/stub/mountpoint"
unset ALPINE_FDE_INSTALL_MAPPER_DIR ALPINE_FDE_INSTALL_BCACHE_SYSFS

# =============================================================================
# G-ST3: RAID1 execution — per-role partitioning, per-member LUKS2 (ephemeral
# key each), raid1 mkfs, per-member crypttab with password-cache=yes,
# member_uuids metadata, per-member provisional seal loop.
# =============================================================================
DISK2=$T/disk2.img
: >"$DISK2"
run_install --disk "$DISK2" </dev/null
assert_eq "raid1 chroot install rc 0 (unattended)" "0" "$RC"
LOG2=$(cat "$ALPINE_FDE_TEST_LOG")
assert_contains "raid1: primary partitioned (ESP + LUKS)" "$LOG2" "sfdisk $DISK"
assert_contains "raid1: secondary partitioned (root only)" "$LOG2" "sfdisk $DISK2"
assert_eq "raid1: secondary got NO ESP (single mkfs.vfat on primary p1)" "1" \
    "$(grep -c "^mkfs.vfat" <<<"$LOG2")"
assert_contains "raid1: ESP on primary p1" "$LOG2" "mkfs.vfat -F 32 -n EFI ${DISK}1"
assert_eq "raid1: exactly 2 per-member luksFormat records" "2" \
    "$(grep -c 'luksFormat --type luks2' <<<"$LOG2")"
assert_eq "raid1: BOTH member luksFormat records ran --batch-mode (defect 5)" "2" \
    "$(grep -c 'cryptsetup --batch-mode luksFormat' <<<"$LOG2")"
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
# G-C24: the provisional seal loop covers BOTH member CONTAINERS in raid1
# (item 27: primary p2 + secondary p1 — the luksFormat targets)
SEAL_LINE2=$(grep -m1 'seal_provisional' <<<"$LOG2")
assert_contains "raid1: provisional seal loop covers both member CONTAINERS (item 27)" "$SEAL_LINE2" \
    "for d in ${DISK}2 ${DISK2}1; do"
assert_eq "raid1/item 27: the seal choreography record NEVER receives /dev/mapper" "0" \
    "$(grep -c '/dev/mapper/' <<<"$SEAL_LINE2")"
L_CLOSE1=$(first_line_no "$LOG2" "cryptsetup close root1")
L_CLOSE2=$(first_line_no "$LOG2" "cryptsetup close root2")
assert_eq "raid1: teardown closes both members (primary first)" "1" \
    "$(( L_CLOSE1 > 0 && L_CLOSE2 > L_CLOSE1 ? 1 : 0 ))"
EPHKEY2=$(grep -oE "$T/alpine-fde-ephkey\.[A-Za-z0-9]{6}" <<<"$OUT" | head -1)
assert_eq "raid1: ephemeral key scrubbed at teardown" "0" \
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-ephkey.*' 2>/dev/null | wc -l)"
# item 27: in raid1 the ceremony enrolls BOTH member CONTAINERS (primary p2 +
# secondary p1 — the luksFormat targets), never the mappers
assert_eq "raid1/item 27: exactly 2 recovery luksAddKey records (one per member container)" "2" \
    "$(grep -c 'luksAddKey' "$ALPINE_FDE_TEST_LOG")"
assert_contains "raid1/item 27: primary container enrolled (${DISK}2)" "$(grep 'luksAddKey' "$ALPINE_FDE_TEST_LOG")" \
    "--key-slot 0 --key-file $EPHKEY2 ${DISK}2"
assert_contains "raid1/item 27: secondary container enrolled (${DISK2}1)" "$(grep 'luksAddKey' "$ALPINE_FDE_TEST_LOG")" \
    "--key-slot 0 --key-file $EPHKEY2 ${DISK2}1"
assert_eq "raid1/item 27: zero luksAddKey records target /dev/mapper" "0" \
    "$(grep 'luksAddKey' "$ALPINE_FDE_TEST_LOG" | grep -c '/dev/mapper/')"

# =============================================================================
# G4/F-1 (§8.1/§3.3): the tooling copy into /opt/alpine-fde ships ONLY the
# product script tree (bin/ lib/ hooks/ docs/) — NEVER VCS/harness residue.
# Residue is seeded in a THROWAWAY tree — never the real tests/ dirs.
# =============================================================================
ALPINE_FDE_TREE=$T/tree
mkdir -p "$ALPINE_FDE_TREE"
for d in bin lib hooks docs; do
    cp -r "$REPO/$d" "$ALPINE_FDE_TREE/$d"
done
mkdir -p "$ALPINE_FDE_TREE/.git/objects" "$ALPINE_FDE_TREE/tests/e2e/.runs/soak-run" \
    "$ALPINE_FDE_TREE/tests/.cache"
printf 'residue' >"$ALPINE_FDE_TREE/.git/HEAD"
printf 'residue' >"$ALPINE_FDE_TREE/tests/e2e/.runs/soak-run/marker"
truncate -s 20M "$ALPINE_FDE_TREE/tests/.cache/blob-20M"

run_install_tree() { # TREE — run_install against a different tooling tree
    : >"$ALPINE_FDE_TEST_LOG"
    OUT=$(ALPINE_FDE_CMD_DIR="$1/lib/cmd" "$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
    RC=$?
}

run_install_tree "$ALPINE_FDE_TREE"
assert_eq "tooling copy from seeded tree: rc 0" "0" "$RC"

OPT=$ALPINE_FDE_INSTALL_MNT/opt/alpine-fde
assert_file_exists "tooling copy: bin/alpine-fde shipped" "$OPT/bin/alpine-fde"
assert_file_exists "tooling copy: lib/ shipped" "$OPT/lib/cmd/install.sh"
assert_file_exists "tooling copy: hooks/ shipped (Alpine layout)" "$OPT/hooks/kernel-hooks.d/alpine-fde-build.hook"
assert_file_exists "tooling copy: docs/ shipped" "$OPT/docs/Architecture.md"

RESIDUE=$(find "$OPT" \( -name '.git' -o -name 'tests' -o -name 'fixtures' \
    -o -name '*.cache*' -o -name '*.runs*' -o -name 'blob-20M' -o -name 'soak-run' \) | wc -l)
assert_eq "tooling copy: zero VCS/harness residue at any depth" "0" "$RESIDUE"
NODES=$(find "$OPT" \( -type b -o -type c \) | wc -l)
assert_eq "tooling copy: zero device nodes in target" "0" "$NODES"
COPY_LINE=$(grep -m1 'cp -r' <<<"$OUT")
assert_contains "tooling copy step: enumerates bin" "$COPY_LINE" "cp -r $ALPINE_FDE_TREE/bin"
assert_contains "tooling copy step: enumerates docs" "$COPY_LINE" "cp -r $ALPINE_FDE_TREE/docs"
assert_not_contains "tooling copy step: never the whole tree root" "$COPY_LINE" "cp -r $ALPINE_FDE_TREE "
# G-C7 (§8.1/§12): the tooling tree lands at /opt/alpine-fde and the guest CLI
# is /usr/local/bin/alpine-fde -> /opt/alpine-fde/bin/alpine-fde; the retired
# debian-fde name is staged nowhere (alias dropped, §8.1).
assert_contains "G-C7: tooling-copy record stages into /opt/alpine-fde" "$COPY_LINE" \
    "$ALPINE_FDE_INSTALL_MNT/opt/alpine-fde"
assert_not_contains "G-C7: tooling-copy record free of /opt/debian-fde" "$COPY_LINE" \
    "/opt/debian-fde"
assert_eq "G-C7/§8.1: guest CLI staged: /usr/local/bin/alpine-fde -> /opt/alpine-fde/bin/alpine-fde" \
    "/opt/alpine-fde/bin/alpine-fde" \
    "$(readlink "$ALPINE_FDE_INSTALL_MNT/usr/local/bin/alpine-fde")"
assert_not_contains "G-C7/§8.1: retired debian-fde alias not staged" "$OUT" \
    "usr/local/bin/debian-fde"
assert_not_contains "G-C7: NO /opt/debian-fde anywhere in the full emitted plan" "$OUT" \
    "/opt/debian-fde"

# =============================================================================
# M-02: operator-controlled values are validated at the boundary BEFORE any
# plan record exists; WR-01 covers the eval'd --keydir path.
# =============================================================================
export ALPINE_FDE_INSTALL_USER='x; rm -rf /'
run_install
assert_eq "M-02: injected --user (env) -> usage rc 2" "2" "$RC"
assert_contains "M-02: error names the invalid user" "$OUT" "invalid --user"
assert_eq "M-02: injected --user: zero commands executed" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
unset ALPINE_FDE_INSTALL_USER
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --user 'x; rm -rf /' 2>&1)
RC=$?
assert_eq "M-02: injected --user (flag) -> usage rc 2" "2" "$RC"
OUT=$("$REPO/bin/alpine-fde" install --disk '/dev/sda; reboot -f' 2>&1)
RC=$?
assert_eq "M-02: injected --disk -> usage rc 2" "2" "$RC"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --bcache '/dev/nvme0n1; echo pwned' 2>&1)
RC=$?
assert_eq "M-02: injected --bcache -> usage rc 2" "2" "$RC"

: >"$ALPINE_FDE_TEST_LOG"
rm -f /tmp/pwned
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --keydir '/x; touch /tmp/pwned' 2>&1)
RC=$?
assert_eq "WR-01: injected --keydir -> usage rc 2" "2" "$RC"
assert_contains "WR-01: error names ALPINE_FDE_KEYDIR" "$OUT" "ALPINE_FDE_KEYDIR"
assert_eq "WR-01: injected --keydir: zero commands executed" "0" "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
assert_eq "WR-01: injected --keydir executed nothing (no /tmp/pwned)" "0" \
    "$([ -e /tmp/pwned ] && echo 1 || echo 0)"
rm -f /tmp/pwned
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
RC=$?
assert_eq "M-02: clean run still rc 0 (validation does not over-reject)" "0" "$RC"

# =============================================================================
# item 26b: DNS preflight FAILS CLOSED — with an unresolvable mirror the
# install dies 64 with an actionable error BEFORE any disk mutation (a live
# ISO without DNS died later at apk populate; the preflight moves the failure
# in front of every destructive step).
# =============================================================================
cat >"$T/stub/nslookup" <<'EOF'
#!/bin/sh
printf '%s %s\n' "nslookup" "$*" >>"$ALPINE_FDE_TEST_LOG"
exit 1
EOF
chmod +x "$T/stub/nslookup"
DNS_OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
DNS_RC=$?
assert_eq "26b: unresolvable mirror -> fail-closed 64 (preflight, before disk-prep)" "64" "$DNS_RC"
assert_contains "26b: the error names the unresolvable mirror host" "$DNS_OUT" \
    "live env cannot resolve dl-cdn.alpinelinux.org"
assert_contains "26b: the error says what to fix (configure networking first)" "$DNS_OUT" \
    "configure networking (DHCP/DNS) before installing"
# the failed run's log was truncated by run start — re-prove "nothing
# destructive executed" on a fresh run with a clean log
: >"$ALPINE_FDE_TEST_LOG"
DNS_OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
DNS_RC=$?
assert_eq "26b: repeat (fresh log): unresolvable mirror -> fail-closed 64" "64" "$DNS_RC"
assert_eq "26b: repeat (fresh log): the ONLY stubbed commands are the two preflight probes (mirror DNS + blocker-#7 loader fetch), ZERO mutations" "2" \
    "$(wc -l <"$ALPINE_FDE_TEST_LOG")"
assert_contains "26b: repeat (fresh log): the mirror probe ran" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "nslookup dl-cdn.alpinelinux.org"
assert_contains "26b: repeat (fresh log): the loader-binary fetch probe ran (blocker #7 preflight)" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "apk fetch --quiet --stdout systemd-boot"
# restore the succeeding probe
make_stub nslookup

# =============================================================================
# §9.1 step 4 negative seam proof: with stdin CLOSED the ceremony fails
# closed — the prompts are the ONLY credential seam (no flag, no env var).
# Runs LAST against the main-run fixtures: it mutates the target before it
# dies (config drops execute before the ceremony), so every later section
# re-runs install and re-derives its own state.
# =============================================================================
NEG_OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1 </dev/null)
NEG_RC=$?
assert_eq "ceremony: stdin closed -> fail-closed 64 (prompts are the only seam)" "64" "$NEG_RC"
# item 12: recovery is asked FIRST, so the closed-stdin failure happens there
# (the mismatch loop re-prompts unboundedly per the user directive — bounded
# attempts are GONE; with scripted input EXHAUSTED the prompt read hits EOF
# and dies fail-closed: the leg is bounded by INPUT, not by count)
assert_contains "ceremony: the die names ceremony (1/3) recovery (item 12: asked first)" "$NEG_OUT" \
    "inst_ceremony_recovery"
assert_contains "ceremony: the failure is the EOF fail-closed die (bounded by input, not by count)" "$NEG_OUT" \
    "end of input while waiting for a credential prompt (EOF)"

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
: >"$ALPINE_FDE_TEST_LOG"
rm -rf "$ALPINE_FDE_INSTALL_MNT"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" --keydir "$KEYDIR" <"$ANSWERS" 2>&1)
RC=$?
assert_eq "keydir: chroot install rc 0 (medium-staged keys)" "0" "$RC"
assert_contains "keydir: release.pem staged from the medium (host record)" "$OUT" \
    "cp $KEYDIR/release.pem"
assert_contains "keydir: db.auth staged from the medium (host record)" "$OUT" \
    "$KEYDIR/db.auth"
assert_eq "keydir: NO in-chroot keygen ceremony ran" "0" \
    "$(grep -c 'provision stage1' "$ALPINE_FDE_TEST_LOG")"
assert_contains "keydir: NVRAM enrollment still consumes /etc/alpine-fde/keys" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys /efi"
assert_file_exists "keydir: release.pem on the encrypted root" "$MNT_ETC/alpine-fde/keys/release.pem"
assert_eq "keydir: staged keys dir mode 0700" "700" "$(stat -c '%a' "$MNT_ETC/alpine-fde/keys")"
assert_eq "keydir: staged key files mode 0600" "600" "$(stat -c '%a' "$MNT_ETC/alpine-fde/keys/kek.auth")"
L_KSTAGE=$(first_line_no "$OUT" "cp $KEYDIR/release.pem")
L_KENROLL=$(first_line_no "$OUT" "fw_auth_enroll")
assert_eq "keydir: staging before NVRAM enrollment" "1" \
    "$(( L_KSTAGE > 0 && L_KENROLL > L_KSTAGE ? 1 : 0 ))"
assert_eq "keydir: NO key material anywhere on the ESP (I2)" "0" \
    "$(find "$ALPINE_FDE_INSTALL_MNT/efi" -name 'release*' -o -name '*.auth' -o -name '*.esl' 2>/dev/null | wc -l)"
# default (no --keydir): in-chroot ceremony unchanged
run_install
assert_eq "keydir: default run (no --keydir) rc 0" "0" "$RC"
assert_contains "keydir: default run keeps the in-chroot ceremony" "$(cat "$ALPINE_FDE_TEST_LOG")" \
    "provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys"

# =============================================================================
# ESP-fallback tail EXECUTION (user directives 1+3): with the reboot seam
# DISABLED —
#   deferred path (PK absent on the live efivars): the manual-import
#     instructions print LAST, an EXPLICIT Enter confirmation is waited for,
#     OsIndications bit 0 is SET, and the installer reboots INTO FIRMWARE
#     SETUP (no direct disk reboot);
#   success path (PK present): DIRECT reboot to disk — no instructions, no
#     confirmation, no firmware trip.
# =============================================================================
ANSWERS5=$T/answers-confirm
cat >"$ANSWERS5" <<'EOF'
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz


EOF
rm -f "$ALPINE_FDE_EFIVARS_DIR"/PK-* "$ALPINE_FDE_EFIVARS_DIR"/OsIndications-*
: >"$ALPINE_FDE_TEST_LOG"
rm -rf "$ALPINE_FDE_INSTALL_MNT"
ALPINE_FDE_INSTALL_NO_REBOOT=0
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS5" 2>&1)
RC=$?
assert_eq "deferred tail: install rc 0 (reboot seam disabled)" "0" "$RC"
assert_contains "deferred tail: EXPLICIT Enter confirmation before the firmware reboot" "$OUT" \
    "press Enter to reboot into firmware setup"
assert_eq "deferred tail: OsIndications bit 0 SET for the firmware-setup reboot" "1" \
    "$([ -f "$ALPINE_FDE_EFIVARS_DIR/OsIndications-$GUID_GLOBAL" ] && echo 1 || echo 0)"
assert_eq "deferred tail: the reboot executed (into firmware setup, after the trip)" "1" \
    "$(grep -c '^reboot ' "$ALPINE_FDE_TEST_LOG")"
assert_contains "deferred tail: the instructions EXECUTED (printed last, line-anchored output)" "$OUT" \
    "alpine-fde: Secure Boot key material is staged under /efi/alpine-fde-keys"
assert_contains "deferred tail: the final message reports the refused enrollment" "$OUT" \
    "firmware NVRAM enrollment was REFUSED"
assert_not_contains "deferred tail: NO direct-disk reboot message on the deferred path" "$OUT" \
    "direct reboot to disk (NVRAM enrollment succeeded)"

# success path: PK enrolled (probe sees it) -> direct reboot, no trip
mkvar PK 1
: >"$ALPINE_FDE_TEST_LOG"
rm -rf "$ALPINE_FDE_INSTALL_MNT"
rm -f "$ALPINE_FDE_EFIVARS_DIR"/OsIndications-*
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS5" 2>&1)
RC=$?
assert_eq "success tail: install rc 0" "0" "$RC"
assert_eq "success tail: NO OsIndications write (direct reboot, no firmware trip)" "0" \
    "$(find "$ALPINE_FDE_EFIVARS_DIR" -name 'OsIndications-*' 2>/dev/null | wc -l)"
assert_eq "success tail: the DIRECT reboot executed" "1" \
    "$(grep -c '^reboot ' "$ALPINE_FDE_TEST_LOG")"
assert_contains "success tail: final message reports the direct reboot" "$OUT" \
    "direct reboot to disk (NVRAM enrollment succeeded)"
assert_eq "success tail: NO deferred-instruction EXECUTION output (echo-side record text may appear; the branch must not run)" "0" \
    "$(grep -c '^alpine-fde: Secure Boot key material is staged under' <<<"$OUT")"
assert_eq "success tail: NO Enter-confirmation EXECUTION output" "0" \
    "$(grep -c '^alpine-fde: review the manual-import instructions above' <<<"$OUT")"
rm -f "$ALPINE_FDE_EFIVARS_DIR"/PK-*
ALPINE_FDE_INSTALL_NO_REBOOT=1

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
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-plan.*' 2>/dev/null | wc -l)"
assert_eq "L-04a: ephemeral key-file scrubbed on failed step (I1)" "0" \
    "$(find "$ALPINE_FDE_TMPDIR" -name 'alpine-fde-ephkey.*' 2>/dev/null | wc -l)"
assert_eq "WR-02 fixture: plan teardown never ran (die before teardown)" "0" \
    "$(grep -c 'umount -R' "$ALPINE_FDE_TEST_LOG")"
assert_eq "WR-02: abort trap tore the binds down (incl. efivars)" "1" \
    "$(grep -c "^umount $ALPINE_FDE_INSTALL_MNT/dev $ALPINE_FDE_INSTALL_MNT/sys $ALPINE_FDE_INSTALL_MNT/proc $ALPINE_FDE_INSTALL_MNT/sys/firmware/efi/efivars\$" "$ALPINE_FDE_TEST_LOG")"
chmod 755 "$MNT_ETC/alpine-fde"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
