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
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-featuresd.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=chroot
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_INSTALL_NO_REBOOT=1
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

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
printf '%s %s\n' "$1" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
exit 0
EOF
    chmod +x "$T/stub/$1"
}
for s in sfdisk mkfs.btrfs mkfs.vfat mount umount adduser addgroup \
    rc-update bootctl btrfs reboot nslookup; do
    make_stub "$s"
done

# openssl — deterministic 256-bit hex body (staged ephemeral key, G-C23) plus
# the ADR-18 PKCS#8 envelope emulation (same pattern as install_chroot_plan.sh)
# so the §9.1 step 4 release-key ceremony (keys_encrypt_release) runs for real:
#   * `pkcs8 -topk8 ... -out F`  -> writes the MARKER + copies -in (fake
#     ciphertext), exit 0 (the round-trip `-out /dev/null` call also passes)
#   * `asn1parse -in F`          -> conformant PBES2/PBKDF2/hmacWithSHA256/
#     aes-256-cbc output ONLY for marker files (keys_is_encrypted verdicts),
#     exit 1 otherwise (plaintext PEM = not-encrypted)
MARKER='fake-pbes2-encrypted-ADR18'
export MARKER
cat >"$T/stub/openssl" <<'EOF'
#!/bin/sh
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
esac
exit 0
EOF
# would: every absolute glob-free path listed in the SHIPPED features.d file
# is created executable in the target tree (mkinitfs copies features.d entries
# from the target tree at build time — the contract under test here is that
# install stages the pieces IT owns so the inventory resolves).
cat >"$T/stub/apk" <<EOF
#!/bin/sh
printf '%s %s\n' "apk" "\$*" >>"\$ALPINE_FDE_TEST_LOG"
if [ "\$1" = "add" ]; then
    while IFS= read -r _ap_line; do
        case \$_ap_line in '#'*) continue ;; '' ) continue ;; *'*') continue ;; esac
        case \$_ap_line in /*) ;; *) continue ;; esac
        mkdir -p "\$ALPINE_FDE_INSTALL_MNT\${_ap_line%/*}"
        : >"\$ALPINE_FDE_INSTALL_MNT\$_ap_line"
        chmod 755 "\$ALPINE_FDE_INSTALL_MNT\$_ap_line"
    done <"$REPO/hooks/mkinitfs/features.d/alpine-fde.files"
fi
exit 0
EOF

# id — pretend to be root (preflight check)
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
chmod +x "$T/stub/apk" "$T/stub/openssl" "$T/stub/id" "$T/stub/lsblk" "$T/stub/cryptsetup" \
    "$T/stub/chroot"
export PATH="$T/stub:$PATH"

# --- fixtures: the REAL shipped hooks tree + SetupMode=1 ------------------------
mkdir -p "$ALPINE_FDE_HOOKS_DIR" "$ALPINE_FDE_EFIVARS_DIR"
cp -r "$REPO/hooks/." "$ALPINE_FDE_HOOKS_DIR/"
chmod +x "$ALPINE_FDE_HOOKS_DIR"/kernel-hooks.d/*.hook "$ALPINE_FDE_HOOKS_DIR"/mkinitfs/*.sh \
    "$ALPINE_FDE_HOOKS_DIR"/apk/triggers/*.trigger "$ALPINE_FDE_HOOKS_DIR"/openrc/*
printf '\007\000\000\000\001' >"$ALPINE_FDE_EFIVARS_DIR/SetupMode-$GUID_GLOBAL"

FEATURES=$ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/features.d/alpine-fde.files
HOOK_DST=$(awk '!done && $0 !~ /^#/ && $0 != "" {print; done=1}' "$REPO/hooks/mkinitfs/features.d/alpine-fde.files")

# §9.1 step 4 credential-ceremony answers (ADR-20 amended): the ONLY credential
# seam is stdin; no flag and no env var exists (S-24). item 12 (AMENDED): the
# ceremony asks the RECOVERY PASSPHRASE FIRST; the user password and the
# release-key passphrase DEFAULT to it on bare Enter — the empty-line
# convention now applies to BOTH optional fields (empty = reuse recovery).
ANSWERS=$T/answers
cat >"$ANSWERS" <<'EOF'
Fin4l-Rec0very-X9k2-!qmwjpz
Fin4l-Rec0very-X9k2-!qmwjpz


EOF

run_install() {
    : >"$ALPINE_FDE_TEST_LOG"
    OUT=$("$REPO/bin/alpine-fde" install --disk "$DISK" 2>&1 <"$ANSWERS")
    RC=$?
}

# =============================================================================
# the plan runs clean (unattended except the ADR-20 amended credential
# ceremony — answers piped on stdin, the documented test/CI seam)
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
    "cp $ALPINE_FDE_HOOKS_DIR/mkinitfs/alpine-fde-unseal.sh $ALPINE_FDE_INSTALL_MNT$HOOK_DST"
assert_eq "install does NOT stage the hook to the retired /etc/mkinitfs path" "0" \
    "$(grep -c "cp $ALPINE_FDE_HOOKS_DIR/mkinitfs/alpine-fde-unseal.sh $ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/alpine-fde-unseal" <<<"$OUT")"

# =============================================================================
# (a) every absolute glob-free path in features.d exists + is executable in
#     the staged target tree after the plan runs (the hook is install's own
#     staging duty; the rest is materialized by the apk stub as the §3.1 set)
# =============================================================================
assert_file_exists "features.d entry staged byte-for-byte" "$ALPINE_FDE_INSTALL_MNT$HOOK_DST"
assert_eq "staged hook is the SHIPPED hook, byte-for-byte" \
    "$(cat "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh")" \
    "$(cat "$ALPINE_FDE_INSTALL_MNT$HOOK_DST")"
assert_eq "staged hook is executable" "1" \
    "$([ -x "$ALPINE_FDE_INSTALL_MNT$HOOK_DST" ] && echo 1 || echo 0)"
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
    if [ ! -x "$ALPINE_FDE_INSTALL_MNT$_fd_line" ]; then
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
    "$ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf"
assert_contains "mkinitfs.conf features= includes alpine-fde" \
    "$(cat "$ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf")" "alpine-fde"
run_install
assert_eq "featuresd contract: re-run rc 0 (idempotency fixture)" "0" "$RC"
assert_eq "mkinitfs.conf registration is idempotent (ONE alpine-fde token after re-run)" "1" \
    "$(grep -o 'alpine-fde' "$ALPINE_FDE_INSTALL_MNT/etc/mkinitfs/mkinitfs.conf" | wc -l)"
assert_contains "re-run: registration host record present (grep-guard form)" \
    "$OUT" "mkinitfs.conf"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
