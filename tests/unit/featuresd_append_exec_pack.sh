#!/usr/bin/env bash
# tests/unit/featuresd_append_exec_pack.sh — the §9.1 step-7 features.d
# module-append record, verified END-TO-END on the REAL chroot runner path
# (dispatched follow-up to real-server blocker #12):
#
#   the record that appends the target's RESOLVED tpm/btrfs/bcache module
#   files to <mnt>/etc/mkinitfs/features.d/alpine-fde.files must
#   (a) execute as a HOST plan record — a guest record would run INSIDE the
#       chroot where <mnt> does not exist, so the scan would find nothing and
#       append nothing (the hypothesized defect shape),
#   (b) execute BEFORE the in-guest `ukictl build` record (mkinitfs reads the
#       feature file at build time),
#   (c) append GUEST-RELATIVE paths (the <mnt> prefix stripped) that resolve
#       under the target root — the guest sees them at the identical path
#       after chroot(8),
#   (d) feed a mkinitfs-semantics pack of the staged feature file that the
#       initrd audit judges COMPLIANT with the previously "missing" modules
#       (.ko.gz server shape, compression-tolerant) — and the NEGATIVE
#       control (the same pack WITHOUT the module lines) must fail the audit
#       with `missing-from-initrd` verdicts, i.e. the exact console failure
#       the 6.18.53-0-lts server run produced.
#
# The pack is mkinitfs's own resolution semantics re-implemented read-only:
# every non-comment features.d entry is glob-expanded against the TARGET
# root and the matches are cpio'd at their guest-relative paths (newc +
# gzip — what initrd_lister's default `gzip -dc | cpio -it` reads back).
# tests/integration has no ukictl-build fixture on this branch, so this
# unit-level real-pack is the mkinitfs packing acceptance leg.

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

T=$(mktemp -d /tmp/alpine-fde-featuresd-append.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T          # secrets + plan temp files live HERE, not /tmp
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_INSTALL_NO_REBOOT=1
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

PARTUUID_CANON='5f2a9b01-02'
GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
export PARTUUID_CANON

DISK=$T/disk.img
: >"$DISK"

KVER=6.18.53-0-lts # the live-server kernel shape: modules ship as .ko.gz

# --- stub collaborators (install_chroot_plan.sh idiom) ------------------------
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

# loader-probe fixture: the preflight fetches the loader from the mirror apk
PKGROOT=$T/pkgroot
mkdir -p "$PKGROOT/usr/share/systemd/bootctl"
: >"$PKGROOT/usr/share/systemd/bootctl/systemd-bootx64.efi"
tar -czf "$T/systemd-boot-loader.apk" -C "$PKGROOT" usr
export LOADER_APK_FIXTURE=$T/systemd-boot-loader.apk
export ALPINE_FDE_LOADER_PROBE_PREFIX=$T/no-live-loader

# openssl stub (ADR-18 envelope emulator, install_chroot_plan.sh idiom)
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
            printf '    0:d=0 hl=4 l= 828 cons: SEQUENCE\n    4:d=1 hl=2 l= 61 cons: SEQUENCE\n    6:d=2 hl=2 l= 9 prim: OBJECT :PBES2\n   17:d=1 hl=2 l= 48 cons: SEQUENCE\n   19:d=2 hl=2 l= 9 prim: OBJECT :PBKDF2\n   43:d=2 hl=2 l= 14 cons: SEQUENCE\n   45:d=3 hl=2 l= 8 prim: OCTET STRING\n   55:d=3 hl=2 l= 2 prim: INTEGER :0927C0\n   59:d=2 hl=2 l= 13 cons: SEQUENCE\n   61:d=3 hl=2 l= 9 prim: OBJECT :hmacWithSHA256\n   77:d=1 hl=2 l= 27 cons: SEQUENCE\n   79:d=2 hl=2 l= 9 prim: OBJECT :aes-256-cbc\n'
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

cat >"$T/stub/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF

cat >"$T/stub/lsblk" <<'EOF'
#!/bin/sh
printf 'lsblk %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
case " $* " in
    *" PARTUUID "*) printf '%s\n' "$PARTUUID_CANON" ;;
esac
exit 0
EOF

cat >"$T/stub/mountpoint" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$T/stub/cryptsetup" "$T/stub/id" "$T/stub/lsblk" "$T/stub/openssl" \
    "$T/stub/mountpoint"

# chroot stub: the stage1 ceremony arm writes the plaintext release.pem AND
# seeds the TARGET's kernel module tree (the apk linux-lts transaction's
# output, simulated — server shape: .ko.gz). The append record's host-side
# scan runs LATER in plan order, so this is exactly the reality it must see.
cat >"$T/stub/chroot" <<EOF
#!/bin/sh
printf '%s %s\n' "chroot" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
case "\$*" in
    *"provision stage1"*)
        mkdir -p "$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys"
        printf -- '-----BEGIN PRIVATE KEY-----\nfake-plaintext-release-key\n-----END PRIVATE KEY-----\n' \\
            >"$ALPINE_FDE_INSTALL_MNT/etc/alpine-fde/keys/release.pem"
        mkdir -p "$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/char/tpm" \\
            "$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/fs/btrfs" \\
            "$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/md/bcache"
        printf 'tpm' >"$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/char/tpm/tpm.ko.gz"
        printf 'tpmtis' >"$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/char/tpm/tpm_tis.ko.gz"
        printf 'tpmcrb' >"$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/char/tpm/tpm_crb.ko.gz"
        printf 'btrfs' >"$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/fs/btrfs/btrfs.ko.gz"
        printf 'bcache' >"$ALPINE_FDE_INSTALL_MNT/lib/modules/$KVER/kernel/drivers/md/bcache/bcache.ko.gz"
        ;;
esac
exit 0
EOF
chmod +x "$T/stub/chroot"

export PATH="$T/stub:$PATH"

# --- fixtures: the REAL hook templates (the staged feature file must be the
# shipped one — its entries drive the pack leg below) --------------------------
mkdir -p "$ALPINE_FDE_HOOKS_DIR"
cp -R "$REPO/hooks/." "$ALPINE_FDE_HOOKS_DIR/"

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$ALPINE_FDE_EFIVARS_DIR/$1-$GUID_GLOBAL"
}
mkdir -p "$ALPINE_FDE_EFIVARS_DIR"
mkvar SetupMode 1

# §9.1 step 4 ceremony answers (recovery pair + two bare-Enter defaults)
ANSWERS=$T/answers
cat >"$ANSWERS" <<'EOF'
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz


EOF

first_line_no() { printf '%s\n' "$1" | grep -Fnm1 "$2" | cut -d: -f1; }

# =============================================================================
# §9.1 Stage 1 on the REAL chroot runner: the full plan executes (host records
# eval'd host-side, guest records via chroot(8) — stubbed). One run feeds all
# the pins below.
# =============================================================================
: >"$ALPINE_FDE_TEST_LOG"
OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" <"$ANSWERS" 2>&1)
RC=$?
assert_eq "§9.1 Stage 1 chroot install rc 0 (ceremony answers on stdin)" "0" "$RC"

# --- (a) the append record executes as a HOST record --------------------------
APPEND_LINE=$(printf '%s\n' "$OUT" | grep -Fm1 'features.d/alpine-fde.files; td=' || true)
assert_eq "the module-append record is present in the executed plan" "1" \
    "$([ -n "$APPEND_LINE" ] && echo 1 || echo 0)"
case ${APPEND_LINE-} in
    *'info: host: '*) assert_eq "the module-append record executes as a HOST record (a guest record would scan <mnt> inside the chroot, where <mnt> does not exist)" "1" "1" ;;
    *) assert_eq "the module-append record executes as a HOST record (a guest record would scan <mnt> inside the chroot, where <mnt> does not exist)" "1" "0" ;;
esac

# --- (b) execution order: append BEFORE the in-guest build record -------------
O_APPEND=$(first_line_no "$OUT" 'features.d/alpine-fde.files; td=')
O_BLD=$(first_line_no "$OUT" 'guest: export ALPINE_FDE_ROOT=/')
assert_eq "the module-append record executes BEFORE the in-guest ukictl build record" "1" \
    "$(( O_APPEND > 0 && O_BLD > O_APPEND ? 1 : 0 ))"

# --- (c) appended lines are GUEST-RELATIVE and target-root-resolvable ---------
FEAT=$ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/features.d/alpine-fde.files
assert_file_exists "the feature file is staged into the target root" "$FEAT"
MOD_LINES=$(grep "^/lib/modules/$KVER/" "$FEAT" || true)
assert_eq "the host-side scan appended RESOLVED module lines (non-empty — the scan did not no-op)" "1" \
    "$([ -n "$MOD_LINES" ] && echo 1 || echo 0)"
assert_eq "every appended module line is GUEST-RELATIVE (the <mnt> prefix is stripped — chroot(8) resolves the identical path)" "0" \
    "$(grep -c "^$ALPINE_FDE_INSTALL_MNT/" <<<"$MOD_LINES")"
assert_eq "every appended module line resolves to a real file under the TARGET root" "0" \
    "$(while IFS= read -r l; do
           [ -n "$l" ] || continue
           [ -f "$ALPINE_FDE_INSTALL_MNT$l" ] || { printf 'x'; break; }
       done <<<"$MOD_LINES" | wc -c)"
for m in tpm.ko.gz tpm_tis.ko.gz btrfs.ko.gz bcache.ko.gz; do
    assert_contains "the server .ko.gz shape is appended: $m" "$MOD_LINES" "/$m"
done

# =============================================================================
# (d) mkinitfs packing ACCEPTANCE: pack the STAGED feature file with mkinitfs's
# resolution semantics (glob-expand each entry against the target root, cpio
# the matches at their guest-relative paths, newc+gzip) and run the REAL
# initrd_audit with the DEFAULT lister — the previously "missing" modules must
# now be in-initrd. Negative control: the same staged file WITHOUT the module
# entries must FAIL the audit with `missing-from-initrd` verdicts — the exact
# 6.18.53-0-lts server failure this chain exists to prevent.
# =============================================================================
pack() { # <features-file> <out-img> — mkinitfs-semantics read-only pack
    : >"$T/cpio.list"
    while IFS= read -r entry; do
        case $entry in
            '' | '#'*) continue ;;
        esac
        # shellcheck disable=SC2086  # the entry MUST glob against the root
        for f in "$ALPINE_FDE_INSTALL_MNT"${entry}; do
            [ -f "$f" ] && printf '%s\0' "${f#"$ALPINE_FDE_INSTALL_MNT"/}" >>"$T/cpio.list"
        done
    done <"$1"
    (cd "$ALPINE_FDE_INSTALL_MNT" && cpio -0 -o -H newc 2>/dev/null | gzip) \
        <"$T/cpio.list" >"$2"
}

# userland the feature file lists (the audit's required set): the install
# staged only the hook — seed the rest so the pack covers every entry
mkdir -p "$ALPINE_FDE_INSTALL_MNT/usr/bin" "$ALPINE_FDE_INSTALL_MNT/usr/lib" \
    "$ALPINE_FDE_INSTALL_MNT/usr/lib/udev/rules.d"
for b in cryptsetup openssl tpm2_pcrextend tpm2_startauthsession tpm2_policypcr \
    tpm2_policyauthorize tpm2_loadexternal tpm2_verifysignature \
    tpm2_createprimary tpm2_load tpm2_unseal tpm2_flushcontext; do
    : >"$ALPINE_FDE_INSTALL_MNT/usr/bin/$b"
done
for l in libcryptsetup.so.12 libcrypto.so.3 libssl.so.3 libtss2-esys.so.0 \
    libtss2-mu.so.0 libtss2-rc.so.0 libtss2-sys.so.0 libtss2-tctildr.so.0 \
    libtss2-tcti-device.so.0; do
    : >"$ALPINE_FDE_INSTALL_MNT/usr/lib/$l"
done
: >"$ALPINE_FDE_INSTALL_MNT/usr/lib/udev/rules.d/60-tpm.rules"
: >"$ALPINE_FDE_INSTALL_MNT/usr/lib/udev/rules.d/69-bcache.rules"

. "$REPO/lib/initramfs.sh"
printf 'ROOT_FS=btrfs\nBCACHE=1\nTOPOLOGY=bcache\n' >"$T/conf"
ALPINE_FDE_CONF=$T/conf
export ALPINE_FDE_CONF

pack "$FEAT" "$T/initrd.img"
INITRD_AUDIT_OUT=$(initrd_audit "$T/initrd.img" "$KVER" "$ALPINE_FDE_INSTALL_MNT" 2>&1)
assert_eq "ACCEPTANCE: the packed initrd (staged feature file, .ko.gz server shape) passes the real initrd_audit" "0" "$?"
assert_contains "ACCEPTANCE: the audit verdict is COMPLIANT (every previously-missing module resolved in-initrd)" \
    "$INITRD_AUDIT_OUT" "inventory compliant"

grep -v '^/lib/modules' "$FEAT" >"$T/nomod.files"
pack "$T/nomod.files" "$T/initrd-nomod.img"
INITRD_AUDIT_OUT=$(initrd_audit "$T/initrd-nomod.img" "$KVER" "$ALPINE_FDE_INSTALL_MNT" 2>&1)
assert_eq "RED control: the SAME pack WITHOUT the module lines FAILS the audit (the pin cannot pass vacuously)" "1" "$?"
assert_contains "RED control: the failure carries the server verdicts tpm.ko=missing-from-initrd" \
    "$INITRD_AUDIT_OUT" "tpm.ko=missing-from-initrd"
assert_contains "RED control: the failure carries the server verdicts btrfs.ko=missing-from-initrd" \
    "$INITRD_AUDIT_OUT" "btrfs.ko=missing-from-initrd"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
