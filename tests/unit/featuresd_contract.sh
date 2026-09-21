#!/usr/bin/env bash
# tests/unit/featuresd_contract.sh — the mkinitfs hook staging + feature
# registration contract (docs/Architecture.md §8.2/ADR-13, §9.1 step 7; G-C8):
#   * ONE pinned contract: the path listed in
#     hooks/mkinitfs/features.d/alpine-fde.files —
#     /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh — is EXACTLY where
#     `install` stages the unseal hook in the target tree, and exactly what
#     mkinitfs packs into the initramfs when the `alpine-fde` feature is
#     enabled (mkinitfs copies every features.d/<feature>.files entry from the
#     target tree at build time — a path mkinitfs cannot resolve is silently
#     omitted, so the staged tree must carry it)
#   * the target's /etc/mkinitfs/mkinitfs.conf `features=` line is patched to
#     include `alpine-fde` (IDEMPOTENT under re-run — exactly one occurrence),
#     otherwise real mkinitfs builds omit the hook entirely
#   * every absolute (glob-free) path listed in features.d exists and is
#     executable in the staged target tree after the plan runs (the apk stub
#     materializes the §3.1 package set the way a real transaction would; the
#     glob lines — kernel modules / libs — are inventory for mkinitfs itself
#     and are skipped here, documented)
#
# Drives the REAL installer (chroot runner) with PATH-stubbed collaborators —
# same E2E-mock rule as install_chroot_plan.sh.

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

T=$(mktemp -d /tmp/debian-fde-featuresd.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_INSTALL_RUNNER=chroot
export DEBIAN_FDE_YES=1
export DEBIAN_FDE_INSTALL_MNT=$T/mnt
export DEBIAN_FDE_HOOKS_DIR=$T/hooks
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T
export DEBIAN_FDE_TEST_LOG=$T/cmd.log
export DEBIAN_FDE_INSTALL_NO_REBOOT=1
export DEBIAN_FDE_EFIVARS_DIR=$T/efivars

PARTUUID_CANON='5f2a9b01-02'
GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
export PARTUUID_CANON

DISK=$T/disk.img
: >"$DISK"

# --- stub collaborators --------------------------------------------------------
mkdir -p "$T/stub"
make_stub() { # NAME — log argv, exit 0
    cat >"$T/stub/$1" <<EOF
#!/bin/sh
printf '%s %s\n' "$1" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount adduser addgroup \
    rc-update bootctl btrfs reboot chroot; do
    make_stub "$s"
done

# apk — log argv AND materialize the §3.1 set the way the real transaction
# would: every absolute glob-free path listed in the SHIPPED features.d file
# is created executable in the target tree (mkinitfs copies features.d entries
# from the target tree at build time — the contract under test here is that
# install stages the pieces IT owns so the inventory resolves).
cat >"$T/stub/apk" <<EOF
#!/bin/sh
printf '%s %s\n' "apk" "\$*" >>"\$DEBIAN_FDE_TEST_LOG"
if [ "\$1" = "add" ]; then
    while IFS= read -r _ap_line; do
        case \$_ap_line in '#'*) continue ;; '' ) continue ;; *'*') continue ;; esac
        case \$_ap_line in /*) ;; *) continue ;; esac
        mkdir -p "\$DEBIAN_FDE_INSTALL_MNT\${_ap_line%/*}"
        : >"\$DEBIAN_FDE_INSTALL_MNT\$_ap_line"
        chmod 755 "\$DEBIAN_FDE_INSTALL_MNT\$_ap_line"
    done <"$REPO/hooks/mkinitfs/features.d/alpine-fde.files"
fi
exit 0
EOF

# openssl — deterministic 256-bit hex body (staged ephemeral key, G-C23)
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
case " $* " in
    *" rand "*) printf 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' ;;
esac
exit 0
EOF
cat >"$T/stub/id" <<'EOF'
#!/bin/sh
printf '0\n'
EOF
cat >"$T/stub/lsblk" <<'EOF'
#!/bin/sh
case " $* " in
    *" PARTUUID "*) printf '%s\n' "$PARTUUID_CANON" ;;
esac
exit 0
EOF
cat >"$T/stub/cryptsetup" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$T/stub/apk" "$T/stub/openssl" "$T/stub/id" "$T/stub/lsblk" "$T/stub/cryptsetup"
export PATH="$T/stub:$PATH"

# --- fixtures: the REAL shipped hooks tree + SetupMode=1 ------------------------
mkdir -p "$DEBIAN_FDE_HOOKS_DIR" "$DEBIAN_FDE_EFIVARS_DIR"
cp -r "$REPO/hooks/." "$DEBIAN_FDE_HOOKS_DIR/"
chmod +x "$DEBIAN_FDE_HOOKS_DIR"/kernel-hooks.d/*.hook "$DEBIAN_FDE_HOOKS_DIR"/mkinitfs/*.sh \
    "$DEBIAN_FDE_HOOKS_DIR"/apk/triggers/*.trigger "$DEBIAN_FDE_HOOKS_DIR"/openrc/*
printf '\007\000\000\000\001' >"$DEBIAN_FDE_EFIVARS_DIR/SetupMode-$GUID_GLOBAL"

FEATURES=$DEBIAN_FDE_INSTALL_MNT/etc/mkinitfs/features.d/alpine-fde.files
HOOK_DST=$(awk '!done && $0 !~ /^#/ && $0 != "" {print; done=1}' "$REPO/hooks/mkinitfs/features.d/alpine-fde.files")

run_install() {
    : >"$DEBIAN_FDE_TEST_LOG"
    OUT=$("$REPO/bin/debian-fde" install --disk "$DISK" 2>&1 </dev/null)
    RC=$?
}

# =============================================================================
# the plan runs clean (unattended, stdin closed)
# =============================================================================
run_install
assert_eq "featuresd contract: chroot install rc 0" "0" "$RC"

# =============================================================================
# (c) the features.d entry path == install's copy destination (ONE path, the
#     /usr/share/alpine-fde/mkinitfs tree mkinitfs reads at build time)
# =============================================================================
assert_eq "featuresd entry lists a single absolute hook path under /usr/share/alpine-fde" \
    "/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh" "$HOOK_DST"
assert_contains "install stages the hook TO the features.d path" "$OUT" \
    "cp $DEBIAN_FDE_HOOKS_DIR/mkinitfs/alpine-fde-unseal.sh $DEBIAN_FDE_INSTALL_MNT$HOOK_DST"
assert_eq "install does NOT stage the hook to the retired /etc/mkinitfs path" "0" \
    "$(grep -c "cp $DEBIAN_FDE_HOOKS_DIR/mkinitfs/alpine-fde-unseal.sh $DEBIAN_FDE_INSTALL_MNT/etc/mkinitfs/alpine-fde-unseal" <<<"$OUT")"

# =============================================================================
# (a) every absolute glob-free path in features.d exists + is executable in
#     the staged target tree after the plan runs (the hook is install's own
#     staging duty; the rest is materialized by the apk stub as the §3.1 set)
# =============================================================================
assert_file_exists "features.d entry staged byte-for-byte" "$DEBIAN_FDE_INSTALL_MNT$HOOK_DST"
assert_eq "staged hook is the SHIPPED hook, byte-for-byte" \
    "$(cat "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh")" \
    "$(cat "$DEBIAN_FDE_INSTALL_MNT$HOOK_DST")"
assert_eq "staged hook is executable" "1" \
    "$([ -x "$DEBIAN_FDE_INSTALL_MNT$HOOK_DST" ] && echo 1 || echo 0)"
_missing=0
while IFS= read -r _fd_line; do
    case $_fd_line in
    '#'*) continue ;;
    '' ) continue ;;
    *'*') continue ;; # glob lines (modules/libs): mkinitfs build-time inventory
    esac
    case $_fd_line in
    /*) ;;
    *) continue ;;
    esac
    if [ ! -x "$DEBIAN_FDE_INSTALL_MNT$_fd_line" ]; then
        _missing=$((_missing + 1))
        printf 'featuresd miss: %s\n' "$_fd_line" >&2
    fi
done <"$REPO/hooks/mkinitfs/features.d/alpine-fde.files"
assert_eq "every absolute features.d path resolves in the staged target tree" "0" "$_missing"

# =============================================================================
# (b) the staged mkinitfs.conf registers the alpine-fde feature — and the
#     registration is IDEMPOTENT under re-run (exactly ONE occurrence)
# =============================================================================
assert_file_exists "target: /etc/mkinitfs/mkinitfs.conf staged" \
    "$DEBIAN_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf"
assert_contains "mkinitfs.conf features= includes alpine-fde" \
    "$(cat "$DEBIAN_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf")" "alpine-fde"
run_install
assert_eq "featuresd contract: re-run rc 0 (idempotency fixture)" "0" "$RC"
assert_eq "mkinitfs.conf registration is idempotent (ONE alpine-fde token after re-run)" "1" \
    "$(grep -o 'alpine-fde' "$DEBIAN_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf" | wc -l)"
assert_contains "re-run: registration host record present (grep-guard form)" \
    "$OUT" "mkinitfs.conf"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
