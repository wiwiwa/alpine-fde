#!/bin/sh
# lsinitrd-fake.sh — LSINITRD_CMD stub for the initrd inventory audit (G-U3,
# docs/Architecture.md §8.2/I6). Emits a configurable lsinitrd-style inventory.
#
# Usage (as invoked by lib/initramfs.sh initrd_audit): lsinitrd-fake.sh <initrd-img>
#   LSINITRD_FAKE_INV  file holding the inventory, one path per line; optional
#                      lsinitrd-style permission prefix is allowed (initrd_audit
#                      parses the trailing whitespace-separated field as path)
#   LSINITRD_FAKE_ARGV if set, the recorded argv is written there (one word per
#                      line) so tests can assert how the audit invoked the lister
#   LSINITRD_FAKE_VARIANT when set, emit a built-in dracut-shaped inventory
#                      instead of LSINITRD_FAKE_INV (MD-04 deny-rule legs +
#                      G-ST5 topology-artifact legs):
#                        base          compliant Debian dracut shape for the
#                                      DEFAULT topology (btrfs root); /bin/sh is
#                                      a symlink to usr/bin/dash (Debian's dracut
#                                      ships dash as the initrd shell — the audit
#                                      must allow it, see lib/initramfs.sh)
#                        btrfs-ok      alias of base (btrfs.ko present)
#                        ext4-ok       ext4.ko INSTEAD of btrfs.ko (ROOT_FS=ext4)
#                        missing-btrfs NO filesystem driver at all (⇒ audit 64
#                                      under btrfs AND ext4 topologies)
#                        bcache-ok     base + bcache.ko + 69-bcache.rules +
#                                      bcache-register (BCACHE=1 compliant)
#                        bcache-missing base WITHOUT the bcache artifacts (⇒ 64
#                                      under BCACHE=1; passes without it)
#                        clang         base + usr/bin/clang{,-17}     (deny: clang)
#                        triplet-gcc   base + usr/bin/x86_64-linux-gnu-{gcc-12,
#                                      ld.bfd}                        (deny: triplet)
#                        busybox       base + usr/bin/busybox (deny: shell+coreutils host)
set -eu
[ $# -eq 1 ] || { echo "usage: lsinitrd-fake.sh <initrd-img>" >&2; exit 2; }
if [ -n "${LSINITRD_FAKE_ARGV:-}" ]; then
    printf '%s\n' "$@" >"$LSINITRD_FAKE_ARGV"
fi
if [ -n "${LSINITRD_FAKE_VARIANT:-}" ]; then
    _lif_emit_core() { # every required unlock artifact EXCEPT the fs driver
        cat <<'EOF'
-rw-r--r--   1 root root  22k usr/lib/x86_64-linux-gnu/systemd/libcryptsetup-token-systemd-tpm2.so
-rw-r--r--   1 root root 500k usr/lib/x86_64-linux-gnu/libtss2-esys.so.0.0.0
-rw-r--r--   1 root root  20k usr/lib/x86_64-linux-gnu/libtss2-mu.so.0.0.0
-rw-r--r--   1 root root  12k usr/lib/x86_64-linux-gnu/libtss2-rc.so.0.0.0
-rw-r--r--   1 root root  30k usr/lib/x86_64-linux-gnu/libtss2-sys.so.0.0.0
-rw-r--r--   1 root root  10k usr/lib/x86_64-linux-gnu/libtss2-tctildr.so.0.0.0
-rw-r--r--   1 root root  10k usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0.0.0
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm.ko
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm_tis.ko
-rw-r--r--   1 root root  15k kernel/drivers/char/tpm/tpm_crb.ko
-rw-r--r--   1 root root  383 usr/lib/udev/rules.d/60-tpm-udev.rules
-rwxr-xr-x   1 root root  60k usr/bin/systemd-cryptsetup
lrwxrwxrwx   1 root root   13 bin/sh -> usr/bin/dash
-rwxr-xr-x   1 root root 130k usr/bin/dash
EOF
    }
    _lif_emit_fs_btrfs() {
        printf '%s\n' '-rw-r--r--   1 root root  950k kernel/fs/btrfs/btrfs.ko'
    }
    _lif_emit_fs_ext4() {
        printf '%s\n' '-rw-r--r--   1 root root  680k kernel/fs/ext4/ext4.ko'
    }
    _lif_emit_bcache() {
        cat <<'EOF'
-rw-r--r--   1 root root  58k kernel/drivers/md/bcache/bcache.ko
-rw-r--r--   1 root root  383 usr/lib/udev/rules.d/69-bcache.rules
-rwxr-xr-x   1 root root  22k usr/lib/udev/bcache-register
EOF
    }
    _lif_emit_clang() {
        _lif_emit_core
        _lif_emit_fs_btrfs
        cat <<'EOF'
-rwxr-xr-x   1 root root 1.2M usr/bin/clang
-rwxr-xr-x   1 root root 1.2M usr/bin/clang-17
EOF
    }
    _lif_emit_triplet_gcc() {
        _lif_emit_core
        _lif_emit_fs_btrfs
        cat <<'EOF'
-rwxr-xr-x   1 root root 1.1M usr/bin/x86_64-linux-gnu-gcc-12
-rwxr-xr-x   1 root root 900k usr/bin/x86_64-linux-gnu-ld.bfd
EOF
    }
    _lif_emit_busybox() {
        _lif_emit_core
        _lif_emit_fs_btrfs
        cat <<'EOF'
-rwxr-xr-x   1 root root 550k usr/bin/busybox
EOF
    }
    case $LSINITRD_FAKE_VARIANT in
        base | btrfs-ok)
            _lif_emit_core
            _lif_emit_fs_btrfs
            ;;
        ext4-ok)
            _lif_emit_core
            _lif_emit_fs_ext4
            ;;
        missing-btrfs)
            _lif_emit_core
            ;;
        bcache-ok)
            _lif_emit_core
            _lif_emit_fs_btrfs
            _lif_emit_bcache
            ;;
        bcache-missing)
            _lif_emit_core
            _lif_emit_fs_btrfs
            ;;
        clang) _lif_emit_clang ;;
        triplet-gcc) _lif_emit_triplet_gcc ;;
        busybox) _lif_emit_busybox ;;
        *)
            echo "lsinitrd-fake: unknown LSINITRD_FAKE_VARIANT: $LSINITRD_FAKE_VARIANT" >&2
            exit 3
            ;;
    esac
    exit 0
fi
[ -n "${LSINITRD_FAKE_INV:-}" ] || {
    echo "lsinitrd-fake: LSINITRD_FAKE_INV is not set" >&2
    exit 3
}
cat "$LSINITRD_FAKE_INV"
