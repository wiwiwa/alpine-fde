#!/usr/bin/env bash
# tests/integration/install_guest_script_lint.sh — physical-install harness lint over
# the EMITTED guest script (the artifact install.sh writes for in-QEMU / real
# execution), pinning the 5 real-server install defects fixed in 7619960.
# The e2e fixture is a pristine virtio disk on a module-loaded, /dev-settled,
# never-coldplugged ISO — those defects were invisible to e2e. The lint runs
# over the EMITTED artifact (captured via the install_qemu_emit.sh idiom), so
# it guards the shape a real boot actually executes:
#   R1  a `modprobe bcache` + `modprobe btrfs` + `mdev -s` preamble exists
#       BEFORE the first sfdisk/make-bcache record (defect 1)
#   R2  a SECOND `mdev -s` (device-node rescan) appears after the sfdisk
#       partitioning step and before make-bcache (defect 2)
#   R3  a `dd` head+tail stale-superblock wipe precedes EVERY make-bcache
#       invocation (defect 3)
#   R4  ZERO unbatched cryptsetup invocations: prompt-capable calls
#       (luksFormat/luksAddKey) carry --batch-mode (or -q); every `cryptsetup
#       open` is non-interactive via --key-file (defect 5, G-C23)
#   R5  bcache BACKING devices are whole-disk: no partition-suffix device
#       (`[0-9]p[0-9]`) and no backing arg that is a digit/pN suffix of a
#       device the script itself references (defect 4)
#   R6  ZERO bootctl invocations anywhere in the script (real-server blocker
#       #7: Alpine ships NO bootctl binary — the boot manager installs by
#       guarded file copy; command-position match only, the loader package
#       path /usr/share/systemd/bootctl/ legitimately contains the word)
#   R7  every BOOTX64.EFI boot-manager copy is GUARDED: the record must carry
#       the in-chroot loader probe (fail-closed), never a bare cp
# Every pin EXERCISES the lint: the GREEN pins lint the captured artifacts;
# the RED pins apply single-point mutations reproducing the pre-7619960 shapes
# to a scratch copy and require the lint to flag the exact rule
# (run_e2e_parallel_contract.sh RED-mutation idiom). A lint that cannot fail
# is a FAILURE.

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

T=$(mktemp -d /tmp/alpine-fde-install-guestlint.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_INSTALL_RUNNER=qemu
export ALPINE_FDE_YES=1
export ALPINE_FDE_INSTALL_MNT=$T/mnt
export ALPINE_FDE_HOOKS_DIR=$T/hooks
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TEST_LOG=$T/cmd.log   # PATH stubs append one line per command
export ALPINE_FDE_INSTALL_NO_REBOOT=1   # CI seam: the harness reboots itself
export ALPINE_FDE_EFIVARS_DIR=$T/efivars

GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'
DISK=$T/disk.img          # single-topology backing
DISKB=$T/diskb.img        # bcache-topology backing (WHOLE disk)
CACHE=$T/cache.img        # bcache cache dev (ESP p1 + cache p2)
: >"$DISK"; : >"$DISKB"; : >"$CACHE"
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
    lsblk btrfs cryptsetup reboot make-bcache bcache-super-show; do
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
# §9.1 preflight: firmware in Setup Mode (rewritten before each emit — the
# preflight gate must pass for BOTH captured topologies)
setup_setupmode() { printf '\007\000\000\000\001' >"$ALPINE_FDE_EFIVARS_DIR/SetupMode-$GUID_GLOBAL"; }
setup_setupmode

emit_guest_script() { # OUTFILE args... — capture the emitted artifact (no exec)
    local out=$1; shift
    setup_setupmode
    ALPINE_FDE_INSTALL_SCRIPT=$out "$REPO/bin/alpine-fde" install "$@" 2>"$T/emit.err" </dev/null
}

# --- capture the EMITTED artifacts: single topology + bcache topology ----------
SCRIPT_SINGLE=$T/guest-single.sh
OUT=$(emit_guest_script "$SCRIPT_SINGLE" --disk "$DISK")
assert_eq "capture: single-topology emit rc 0" "0" "$?"
assert_file_exists "capture: single-topology script written" "$SCRIPT_SINGLE"

SCRIPT_BCACHE=$T/guest-bcache.sh
OUTFILE=$SCRIPT_BCACHE
OUT=$(emit_guest_script "$OUTFILE" --disk "$DISKB" --bcache "$CACHE")
assert_eq "capture: bcache-topology emit rc 0" "0" "$?"
assert_file_exists "capture: bcache-topology script written" "$SCRIPT_BCACHE"

# ============================================================================
# lint_guest_script FILE — the harness lint under test. Appends one
# "R<n>: <diagnostic>" line per violation to $LINT_DIAG and returns nonzero
# iff any rule fired. R0 = artifact guard (not a block-device install plan).
# ============================================================================
lint_guest_script() { # FILE
    local f=$1
    LINT_DIAG=''
    local bad=0

    first() { # PATTERN (ERE) -> first matching line no, 0 if none
        local n
        n=$(grep -Enm1 -- "$1" "$f" 2>/dev/null | cut -d: -f1)
        printf '%s' "${n:-0}"
    }
    first_fixed() { # FIXED-STRING -> first matching line no, 0 if none
        local n
        n=$(grep -Fnm1 -- "$1" "$f" 2>/dev/null | cut -d: -f1)
        printf '%s' "${n:-0}"
    }
    violate() { # TAG MESSAGE
        LINT_DIAG+="$1: $2"$'\n'
        bad=$((bad + 1))
    }

    # R0 artifact guard: the lint is only meaningful over a block-device plan
    # (anchor the COMMAND form `make-bcache -C|-B` — the rescan record's
    # trailing comment names "make-bcache" too and must not anchor anything)
    local n_block n_sfd n_make
    n_block=$(first 'sfdisk |make-bcache -[CB] ')
    n_sfd=$(first 'sfdisk ')
    n_make=$(first 'make-bcache -[CB] ')
    if [ "$n_block" -eq 0 ]; then
        violate R0 "no sfdisk/make-bcache record — not a guest install script: $f"
        printf '%s' "$LINT_DIAG"
        return 1
    fi

    # --- R1: modprobe bcache + modprobe btrfs + mdev -s preamble BEFORE the
    #         first sfdisk/make-bcache record (defect 1)
    if [ "$n_make" -gt 0 ]; then
        local n_bcmod
        n_bcmod=$(first 'then modprobe bcache; fi')
        [ "$n_bcmod" -gt 0 ] && [ "$n_bcmod" -lt "$n_block" ] ||
            violate R1 "modprobe bcache preamble missing or not before the first block record (line $n_block)"
    fi
    if [ "$(first 'mkfs.btrfs')" -gt 0 ]; then
        local n_btmod
        n_btmod=$(first 'then modprobe btrfs; fi')
        [ "$n_btmod" -gt 0 ] && [ "$n_btmod" -lt "$n_block" ] ||
            violate R1 "modprobe btrfs preamble missing or not before the first block record (line $n_block)"
    fi
    local n_cold
    n_cold=$(first 'then mdev -s; fi')
    [ "$n_cold" -gt 0 ] && [ "$n_cold" -lt "$n_block" ] ||
        violate R1 "coldplug (mdev -s) preamble missing or not before the first block record (line $n_block)"

    # --- R2: a SECOND mdev -s rescan after sfdisk, before make-bcache (defect 2)
    if [ "$n_make" -gt 0 ]; then
        local n_cold2
        n_cold2=$(grep -n 'then mdev -s; fi' "$f" | sed -n 2p | cut -d: -f1)
        if [ -z "${n_cold2:-}" ] || [ "$n_cold2" -eq 0 ]; then
            violate R2 "no post-sfdisk mdev -s rescan (partition device nodes never settled)"
        else
            { [ "$n_sfd" -gt 0 ] && [ "$n_cold2" -gt "$n_sfd" ] && [ "$n_cold2" -lt "$n_make" ]; } ||
                violate R2 "post-sfdisk mdev -s rescan out of order (sfdisk@$n_sfd, rescan@$n_cold2, make-bcache@$n_make)"
        fi
    fi

    # --- R3: dd head+tail stale-superblock wipe BEFORE EVERY make-bcache (defect 3)
    local ln rest dev n_head n_tail
    while IFS=: read -r ln rest; do
        [ -n "${rest:-}" ] || continue
        # fields: # HOST: make-bcache -C|-B <dev>
        set -- $rest
        dev=${5:-}
        [ -n "$dev" ] || { violate R3 "make-bcache record without a device argument (line $ln)"; continue; }
        n_head=$(first_fixed "of=$dev bs=1M count=1 && ")
        n_tail=$(first_fixed "of=$dev bs=1M count=1 seek=")
        [ "$n_head" -gt 0 ] && [ "$n_head" -lt "$ln" ] ||
            violate R3 "make-bcache $dev (line $ln): no preceding dd HEAD wipe"
        [ "$n_tail" -gt 0 ] && [ "$n_tail" -lt "$ln" ] ||
            violate R3 "make-bcache $dev (line $ln): no preceding dd TAIL wipe"
    done <<EOF
$(grep -nE -- 'make-bcache -[CB] ' "$f")
EOF

    # --- R4: ZERO unbatched cryptsetup invocations (defect 5): prompt-capable
    #         calls (luksFormat/luksAddKey) carry --batch-mode (or -q); every
    #         `cryptsetup open` is non-interactive via --key-file (G-C23).
    #         Command-position match only — the apk package name `cryptsetup`
    #         must NOT trip this rule.
    local line l
    while IFS= read -r line; do
        l=${line#\# HOST: }
        l=${l%%' #'*}   # strip the trailing record comment — the luksFormat
        case $l in      # comment NAMES --batch-mode and must not vouch for it
        cryptsetup\ *|*\&\&\ cryptsetup\ *|*\;\ cryptsetup\ *|*\|\|\ cryptsetup\ *) ;;
        *) continue ;;
        esac
        case $l in
        cryptsetup\ *|*\&\&\ cryptsetup\ *|*\;\ cryptsetup\ *|*\|\|\ cryptsetup\ *) ;;
        *) continue ;;
        esac
        case $l in
        *luksFormat* | *luksAddKey*)
            case $l in
            *--batch-mode* | *' -q '*) ;;
            *) violate R4 "unbatched prompt-capable cryptsetup (interactive dangerous-action YES): $l" ;;
            esac
            ;;
        *' open '*)
            case $l in
            *--key-file*) ;;
            *) violate R4 "cryptsetup open without --key-file (interactive passphrase prompt, G-C23): $l" ;;
            esac
            ;;
        esac
    done <"$f"

    # --- R5: bcache BACKING devices are WHOLE disk (defect 4): no
    #         partition-suffix device (`[0-9]p[0-9]`) and no backing arg that
    #         is a digit/pN suffix of a device the script itself references.
    #         A digit-ENDING whole disk (/dev/nvme0n1) is legitimate and must
    #         NOT be flagged.
    local d tok
    local -a toks
    # token set: EVERY absolute path the script references (not just /dev/*) —
    # a file-backed fixture path (.../diskb.img1) is exactly the same
    # partition-of-a-referenced-base bug shape as /dev/sda1
    mapfile -t toks < <(grep -oE '/[A-Za-z0-9/._-]+' "$f" | sort -u)
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        case $d in
        *[0-9]p[0-9])
            violate R5 "bcache backing device is a PARTITION (pN suffix): $d"
            continue
            ;;
        esac
        for tok in ${toks[@]+"${toks[@]}"}; do
            [ "$tok" = "$d" ] && continue
            case $d in
            "$tok"p[0-9] | "$tok"p[0-9][0-9] | "$tok"[0-9] | "$tok"[0-9][0-9])
                violate R5 "bcache backing device is a partition of referenced device $tok: $d"
                ;;
            esac
        done
    done < <(grep -oE -- 'make-bcache -B [^ ]+' "$f" | awk '{print $3}')

    # --- R6 (real-server blocker #7): ZERO bootctl invocations anywhere —
    #         Alpine ships NO bootctl binary; the boot manager installs by
    #         guarded file copy (R7). Command-position match only: the
    #         loader's own package path (/usr/share/systemd/bootctl/)
    #         legitimately contains the word.
    local r6pat='(^|[;&|][[:space:]]*)bootctl( |$)|bootctl install'
    if grep -En -- "$r6pat" "$f" >/dev/null 2>&1; then
        violate R6 "bootctl invocation present (Alpine ships no bootctl binary — blocker #7): $(grep -Enm1 -- "$r6pat" "$f")"
    fi

    # --- R7 (blocker #7): every BOOTX64.EFI boot-manager copy is GUARDED —
    #         the record must carry the in-chroot loader probe (fail-closed
    #         when no loader binary is installed by the package), never a
    #         bare cp onto the firmware fallback path.
    while IFS= read -r line; do
        case $line in *BOOTX64.EFI*cp\ *|*cp\ *BOOTX64.EFI*) ;; *) continue ;; esac
        case $line in
        *'for p in /usr/share/systemd/bootctl/systemd-bootx64.efi'*) : ;;
        *) violate R7 "unguarded BOOTX64.EFI copy (no fail-closed loader probe on the record): $line" ;;
        esac
    done <"$f"

    printf '%s' "$LINT_DIAG"
    return "$((bad > 0 ? 1 : 0))"
}

# mutate() FILE SED-EXPR — scratch-copy single-point mutation (RED idiom);
# ERE mode (the R1 combined mutation uses `|` alternation)
mutated() { # SRC SED-EXPR -> scratch copy path in $MUTATED
    MUTATED=$T/mutated-$$.sh
    sed -E -e "$2" "$1" >"$MUTATED"
}

lint_must_fail() { # SCRIPT TAG MSG — RED pin: the lint MUST flag TAG
    local diag rc
    diag=$(lint_guest_script "$1")
    rc=$?
    assert_eq "$3 (lint rc)" "1" "$rc"
    assert_contains "$3 (diagnostic names the rule)" "$diag" "$2"
}

# ============================================================================
# GREEN: the current tree's emitted artifacts lint CLEAN
# ============================================================================
DIAG=$(lint_guest_script "$SCRIPT_SINGLE")
assert_eq "GREEN: single-topology emitted script lints clean (rc 0)" "0" "$?"
DIAG=$(lint_guest_script "$SCRIPT_BCACHE")
assert_eq "GREEN: bcache-topology emitted script lints clean (rc 0)" "0" "$?"
assert_eq "GREEN: bcache-topology lint emits ZERO diagnostics" "0" "$(printf '%s' "$DIAG" | grep -c . )"

# R0 artifact guard: the lint refuses to pass a non-plan artifact vacuously
: >"$T/empty.sh"
lint_must_fail "$T/empty.sh" "R0:" "R0 guard: empty artifact is rejected"
printf '#!/bin/sh\nset -eu\n' >"$T/noop.sh"
lint_must_fail "$T/noop.sh" "R0:" "R0 guard: script without any block record is rejected"

# ============================================================================
# RED: every rule's failure mode, by mutation reproducing the pre-7619960
# shapes on a scratch copy of the captured bcache artifact
# ============================================================================

# R1 (defect 1): strip the whole modprobe+mdev preamble
mutated "$SCRIPT_BCACHE" '/then modprobe (bcache|btrfs); fi|then mdev -s; fi/d'
lint_must_fail "$MUTATED" "R1:" "R1 RED: preamble stripped (modprobe bcache+btrfs+mdev -s) is flagged"

# R1 (defect 1, btrfs variant): strip ONLY the btrfs modprobe
mutated "$SCRIPT_BCACHE" '/then modprobe btrfs; fi/d'
lint_must_fail "$MUTATED" "R1:" "R1 RED: missing modprobe btrfs is flagged"

# R1 (defect 1, bcache variant): strip ONLY the bcache modprobe
mutated "$SCRIPT_BCACHE" '/then modprobe bcache; fi/d'
lint_must_fail "$MUTATED" "R1:" "R1 RED: missing modprobe bcache is flagged"

# R2 (defect 2): drop the post-sfdisk mdev -s rescan (the SECOND coldplug line)
mutated "$SCRIPT_BCACHE" '/coldplug: partition device nodes must exist before make-bcache/d'
lint_must_fail "$MUTATED" "R2:" "R2 RED: missing post-sfdisk mdev -s rescan is flagged"

# R2 (ordering variant): rescan demoted BELOW make-bcache (too late to matter)
mutated "$SCRIPT_BCACHE" \
    '/coldplug: partition device nodes must exist before make-bcache/d
/make-bcache -B /a\
# HOST: if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: partition device nodes must exist before make-bcache'
lint_must_fail "$MUTATED" "R2:" "R2 RED: post-sfdisk rescan AFTER make-bcache (out of order) is flagged"

# R3 (defect 3): drop the WHOLE-disk backing dd head+tail wipe
# (custom sed address delimiter — the captured device path contains slashes)
mutated "$SCRIPT_BCACHE" "\#of=$DISKB bs=1M count=1#d"
lint_must_fail "$MUTATED" "R3:" "R3 RED: make-bcache -B without the preceding dd wipe is flagged"

# R3 (tail variant): keep the head wipe, strip the seek= tail wipe
mutated "$SCRIPT_BCACHE" "s| && dd if=/dev/zero of=$DISKB bs=1M count=1 seek=|[REDACTED]|"
lint_must_fail "$MUTATED" "R3:" "R3 RED: head-only wipe (no seek= tail) is flagged"

# R4 (defect 5): strip --batch-mode from the luksFormat record
mutated "$SCRIPT_BCACHE" 's/cryptsetup --batch-mode luksFormat/cryptsetup luksFormat/'
lint_must_fail "$MUTATED" "R4:" "R4 RED: unbatched luksFormat (interactive YES) is flagged"

# R4 (G-C23 variant): make `cryptsetup open` interactive (no --key-file)
mutated "$SCRIPT_BCACHE" 's/cryptsetup open --key-file [^ ]* /cryptsetup open /'
lint_must_fail "$MUTATED" "R4:" "R4 RED: cryptsetup open without --key-file is flagged"

# R5 (defect 4, nvme class): backing handed to make-bcache as a PARTITION
# (shape-independent: mutates whatever the backing arg is)
mutated "$SCRIPT_BCACHE" "s|make-bcache -B [^ ]+|make-bcache -B /dev/nvme0n1p2|"
lint_must_fail "$MUTATED" "R5:" "R5 RED: backing as nvme partition (/dev/nvme0n1p2) is flagged"

# R5 (defect 4, sda class): digit-suffixed backing whose whole disk the script
# itself references (the pre-7619960 registration shape)
mutated "$SCRIPT_BCACHE" \
    's|make-bcache -B [^ ]+|make-bcache -B /dev/sda1|; /make-bcache -B /a\
# HOST: echo /dev/sda > /sys/fs/bcache/register'
lint_must_fail "$MUTATED" "R5:" "R5 RED: backing as /dev/sda1 (whole /dev/sda referenced) is flagged"

# R5 negative control: a digit-ENDING WHOLE disk (/dev/nvme0n1) is legitimate —
# the lint targets the partition-suffix bug class, not digit endings per se
mutated "$SCRIPT_BCACHE" "s|$DISKB|/dev/nvme0n1|g"
DIAG=$(lint_guest_script "$MUTATED")
assert_eq "R5 control: whole-disk /dev/nvme0n1 backing lints clean (rc 0)" "0" "$?"

# R6 (blocker #7): reinject the retired bootctl invocation
mutated "$SCRIPT_BCACHE" '/ldr=./a\
bootctl install --esp-path=/efi --boot-path=/efi'
lint_must_fail "$MUTATED" "R6:" "R6 RED: a bootctl invocation in the emitted script is flagged"

# R6 negative control: the loader's own PACKAGE PATH may contain the word —
# the guarded copy record itself must NOT trip R6
DIAG=$(lint_guest_script "$SCRIPT_SINGLE")
assert_eq "R6 control: the guarded copy record (package path contains the word) lints clean" "0" "$?"

# R7 (blocker #7): replace the guarded copy with a BARE cp (no loader probe)
mutated "$SCRIPT_BCACHE" 's|ldr=.*guarded file copy.*|cp /usr/share/systemd/bootctl/systemd-bootx64.efi /efi/EFI/BOOT/BOOTX64.EFI # bare unguarded copy|'
lint_must_fail "$MUTATED" "R7:" "R7 RED: an unguarded BOOTX64.EFI copy (no fail-closed loader probe) is flagged"

# --- soundness: the lint never mutates the artifact, and both captured
#     artifacts still parse (the lint is read-only over the emitted script)
assert_rc "lint is read-only: emitted script still parses" 0 sh -n "$SCRIPT_BCACHE"
assert_rc "capture: emitted script was NEVER executed (stub log empty)" 0 test ! -s "$ALPINE_FDE_TEST_LOG"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
