#!/bin/sh
# cpio-lister-fake.sh — INITRD_LISTER_CMD stub for the initrd inventory audit
# (G-C11, docs/Architecture.md §8.2/§12/I6). Emits a cpio-shaped inventory
# (one archive path per line, `cpio -it` style) of an Alpine/mkinitfs
# initramfs. Replaces the Debian-era lsinitrd-fake.sh.
#
# Usage (as invoked by lib/initramfs.sh initrd_audit): cpio-lister-fake.sh <initrd-img>
#   LISTER_FAKE_INV     file holding the inventory, one path per line
#   LISTER_FAKE_ARGV    if set, the recorded argv is written there (one word
#                       per line) so tests can assert how the audit invoked
#                       the lister
#   LISTER_FAKE_VARIANT when set, emit a built-in Alpine-shaped inventory
#                       instead of LISTER_FAKE_INV:
#     alpine-base      compliant mkinitfs inventory for the DEFAULT topology
#                      (btrfs root) — INCLUDING bin/busybox + bin/ash + bin/sh
#                      (busybox IS the init framework: allowed, I6/G-C11)
#     ext4-ok          ext4.ko INSTEAD of btrfs.ko (ROOT_FS=ext4)
#     missing-btrfs    NO filesystem driver at all (fails both topologies)
#     bcache-ok        alpine-base + bcache.ko + 69-bcache.rules (BCACHE=1)
#     bcache-missing   alpine-base WITHOUT the bcache artifacts (fails under
#                      BCACHE=1; passes without it)
#     missing-hook     no alpine-fde-unseal.sh (the unlock path itself gone)
#     missing-tpm2     tpm2_unseal binary absent
#     missing-tpmrule  TPM udev rule absent
#     missing-tpmrule  TPM udev rule absent
#     deny-gcc         alpine-base + gcc + triplet gcc + make     (deny)
#     deny-dpkg        alpine-base + usr/bin/dpkg                 (deny)
#     deny-shell       alpine-base + bash + zsh + dash            (deny)
set -eu
[ $# -eq 1 ] || { echo "usage: cpio-lister-fake.sh <initrd-img>" >&2; exit 2; }
if [ -n "${LISTER_FAKE_ARGV:-}" ]; then
    printf '%s\n' "$@" >"$LISTER_FAKE_ARGV"
fi
if [ -n "${LISTER_FAKE_VARIANT:-}" ]; then
    _clf_emit_core() { # every required unlock artifact EXCEPT the fs driver + bcache
        cat <<'EOF'
usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh
usr/bin/cryptsetup
usr/lib/libcryptsetup.so.2
usr/bin/openssl
usr/lib/libcrypto.so.3
usr/bin/tpm2_pcrextend
usr/bin/tpm2_startauthsession
usr/bin/tpm2_policypcr
usr/bin/tpm2_policyauthorize
usr/bin/tpm2_loadexternal
usr/bin/tpm2_verifysignature
usr/bin/tpm2_createprimary
usr/bin/tpm2_load
usr/bin/tpm2_unseal
usr/bin/tpm2_flushcontext
usr/lib/libtss2-esys.so.0
usr/lib/libtss2-mu.so.0
usr/lib/libtss2-rc.so.0
usr/lib/libtss2-sys.so.0
usr/lib/libtss2-tctildr.so.0
usr/lib/libtss2-tcti-device.so.0
kernel/drivers/char/tpm/tpm.ko
kernel/drivers/char/tpm/tpm_tis.ko
kernel/drivers/char/tpm/tpm_crb.ko
usr/lib/udev/rules.d/60-tpm.rules
bin/busybox
bin/ash
bin/sh
EOF
    }
    _clf_emit_fs_btrfs() {
        printf '%s\n' 'kernel/fs/btrfs/btrfs.ko'
    }
    _clf_emit_fs_ext4() {
        printf '%s\n' 'kernel/fs/ext4/ext4.ko'
    }
    _clf_emit_bcache() {
        cat <<'EOF'
kernel/drivers/md/bcache/bcache.ko
usr/lib/udev/rules.d/69-bcache.rules
EOF
    }
    case $LISTER_FAKE_VARIANT in
        alpine-base)
            _clf_emit_core
            _clf_emit_fs_btrfs
            ;;
        ext4-ok)
            _clf_emit_core
            _clf_emit_fs_ext4
            ;;
        missing-btrfs)
            _clf_emit_core
            ;;
        bcache-ok)
            _clf_emit_core
            _clf_emit_fs_btrfs
            _clf_emit_bcache
            ;;
        bcache-missing)
            _clf_emit_core
            _clf_emit_fs_btrfs
            ;;
        missing-hook)
            _clf_emit_core | grep -v 'alpine-fde-unseal\.sh$'
            _clf_emit_fs_btrfs
            ;;
        missing-tpm2)
            _clf_emit_core | grep -v 'usr/bin/tpm2_unseal$'
            _clf_emit_fs_btrfs
            ;;
        missing-tpmrule)
            _clf_emit_core | grep -v '60-tpm\.rules$'
            _clf_emit_fs_btrfs
            ;;
        deny-gcc)
            _clf_emit_core
            _clf_emit_fs_btrfs
            printf '%s\n' usr/bin/gcc usr/bin/x86_64-linux-gnu-gcc-12 usr/bin/make
            ;;
        deny-dpkg)
            _clf_emit_core
            _clf_emit_fs_btrfs
            printf '%s\n' usr/bin/dpkg
            ;;
        deny-dpkg)
            _clf_emit_core
            _clf_emit_fs_btrfs
            printf '%s\n' usr/bin/dpkg
            ;;
        deny-shell)
            _clf_emit_core
            _clf_emit_fs_btrfs
            printf '%s\n' usr/bin/bash usr/bin/zsh usr/bin/dash
            ;;
        *)
            echo "cpio-lister-fake: unknown LISTER_FAKE_VARIANT: $LISTER_FAKE_VARIANT" >&2
            exit 3
            ;;
    esac
    exit 0
fi
[ -n "${LISTER_FAKE_INV:-}" ] || {
    echo "cpio-lister-fake: LISTER_FAKE_INV is not set" >&2
    exit 3
}
cat "$LISTER_FAKE_INV"
