#!/bin/sh
# initramfs.sh — initramfs-builder seam (docs/Architecture.md §8.2/§8.3,
# ADR-13, G-C10). `ukictl build` consumes the initrd for the kernel being
# built; who builds it is swappable:
#
#   default : mkinitfs -c /etc/mkinitfs/mkinitfs.conf -F <features> -o <out> <kver>
#             (Alpine-native builder; ADR-13 — dracut rejected). The feature
#             set is pinned: base, cryptsetup, the root-fs driver feature
#             (btrfs default / ext4 per the persisted topology, §4.1) and the
#             custom `alpine-fde` feature carrying the Early-Boot Unseal Hook
#             and everything it needs (hooks/mkinitfs/features.d/
#             alpine-fde.files, G-C8). Bcache artifacts ride the static
#             features.d list — nothing topology-specific on the argv.
#   override: INITRAMFS_CMD in /etc/alpine-fde/alpine-fde.conf — a command
#             template in which the literal placeholders {kver} and {out} are
#             replaced before execution, e.g.
#               INITRAMFS_CMD="fixtures/initramfs/stub-generate.sh {out} {kver}"
#             (sandbox/CI uses the stub: builder output varies with host
#             state, which would churn pcr11_digest per build; the stub is
#             deterministic.)
#
# Determinism contract (B-G9 seam): CI builds MUST use a fixed input set so
# pcr11_digest is reproducible across runs.

if [ -n "${ALPINE_FDE_INITRAMFS_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_INITRAMFS_LOADED=1

# --- persisted topology conf (§4.1/§8.2; G-ST4/G-ST5) -----------------------------
# The installer persists the provisioned topology in
# /etc/alpine-fde/alpine-fde.conf as ROOT_FS=btrfs|ext4 and BCACHE=0|1. Both
# the crypttab guard and the initrd inventory audit resolve the topology
# through this reader — a tiny LOCAL targeted parse (esp.sh style: load_config
# parity without clobbering the caller's environment; esp.sh and
# install-state.sh are separate modules and are NOT sourced from here).
# Absent/invalid conf ⇒ the documented btrfs default, warned ONCE per process.

# _initramfs_conf_get KEY — print the first KEY= value (surrounding quotes
# stripped), empty when the conf is absent or the key unset.
_initramfs_conf_get() {
    _icg_key=$1
    if command -v config_path >/dev/null 2>&1; then
        _icg_conf=$(config_path)
    else
        _icg_conf=/etc/alpine-fde/alpine-fde.conf
    fi
    if [ -z "$_icg_conf" ] || [ ! -f "$_icg_conf" ]; then
        return 0
    fi
    _icg_val=$(sed -n "s/^[[:space:]]*${_icg_key}[[:space:]]*=[[:space:]]*//p" \
        "$_icg_conf" 2>/dev/null | head -n 1 | sed 's/[[:space:]]*$//')
    case $_icg_val in
        '"'*)
            case $_icg_val in
                '"'*'"') _icg_val=${_icg_val#\"}; _icg_val=${_icg_val%\"} ;;
            esac
            ;;
        "'"*)
            case $_icg_val in
                "'"*"'") _icg_val=${_icg_val%\'}; _icg_val=${_icg_val#\'} ;;
            esac
            ;;
    esac
    printf '%s\n' "$_icg_val"
}

INI_ROOT_FS=btrfs
INI_BCACHE=0
INI_TOPOLOGY='' # '' = legacy conf WITHOUT a TOPOLOGY key (derive from BCACHE)
_INI_TOPO_WARNED=0

# initramfs_topology — resolve INI_ROOT_FS (btrfs|ext4), INI_BCACHE (0|1) and
# INI_TOPOLOGY (single|bcache|bcache-multi|raid1|'') from the persisted conf.
# Absent or invalid ROOT_FS ⇒ btrfs default; a note is warned at most once
# per process. REAL-SERVER BLOCKER #10: BCACHE=1 covered both bcache AND
# bcache-multi, so crypttab_tpm2_check's count rule could not tell them apart
# — the conf now carries TOPOLOGY and:
#   * TOPOLOGY present+valid → INI_TOPOLOGY=<value>; INI_BCACHE derives FROM
#     it (bcache|bcache-multi ⇒ 1 — the bcache.ko initrd need is identical;
#     single|raid1 ⇒ 0)
#   * TOPOLOGY absent (OLD conf) → INI_TOPOLOGY stays '' and INI_BCACHE
#     derives from BCACHE exactly as before (BACK-COMPAT: the historical
#     BCACHE=1 ⇒ exactly-one crypttab rule keeps applying)
#   * TOPOLOGY invalid → warn + default to single (INI_BCACHE=0)
initramfs_topology() {
    _ito_fs=$(_initramfs_conf_get ROOT_FS)
    _ito_note=''
    case $_ito_fs in
        btrfs | ext4)
            INI_ROOT_FS=$_ito_fs
            ;;
        '')
            INI_ROOT_FS=btrfs
            _ito_note='no ROOT_FS in alpine-fde.conf — defaulting to btrfs (§4.1)'
            ;;
        *)
            INI_ROOT_FS=btrfs
            _ito_note="invalid ROOT_FS '$_ito_fs' in alpine-fde.conf — defaulting to btrfs (§4.1)"
            ;;
    esac
    _ito_topo=$(_initramfs_conf_get TOPOLOGY)
    case $_ito_topo in
        single | bcache | bcache-multi | raid1)
            INI_TOPOLOGY=$_ito_topo
            case $_ito_topo in
                bcache | bcache-multi) INI_BCACHE=1 ;;
                *) INI_BCACHE=0 ;;
            esac
            ;;
        '')
            INI_TOPOLOGY=''
            case $(_initramfs_conf_get BCACHE) in
                1) INI_BCACHE=1 ;;
                *) INI_BCACHE=0 ;;
            esac
            ;;
        *)
            INI_TOPOLOGY=single
            INI_BCACHE=0
            _ito_note="$_ito_note invalid TOPOLOGY '$_ito_topo' in alpine-fde.conf — defaulting to single (§4.1)"
            ;;
    esac
    if [ "$_INI_TOPO_WARNED" -eq 0 ] && [ -n "$_ito_note" ]; then
        warn "initramfs: $_ito_note"
        _INI_TOPO_WARNED=1
    fi
    return 0
}

# initramfs_features — print the pinned mkinitfs feature set for the persisted
# topology (§4.1): base + cryptsetup + root-fs driver + alpine-fde.
initramfs_features() {
    initramfs_topology
    _inf_fs=btrfs
    [ "$INI_ROOT_FS" = "ext4" ] && _inf_fs=ext4
    # boot-lane finding #22 (s23 attempt 22, run ...-1790451796): the platform
    # STORAGE driver families MUST ride the initramfs — without them boot B
    # never sees its own disk ("/dev/vdb absent; only loop/ram in
    # /sys/class/block; Mounting root: failed -> emergency shell"). mkinitfs's
    # own stock default set carries the same families (ata nvme scsi virtio).
    printf '%s\n' "base cryptsetup virtio ata nvme scsi $_inf_fs alpine-fde"
}

# initramfs_build <out> <kver> — produce the initramfs for <kver> at <out>.
initramfs_build() {
    _ini_out=$1
    _ini_kver=$2
    if [ -n "${INITRAMFS_CMD:-}" ]; then
        _ini_cmd=$(printf '%s' "$INITRAMFS_CMD" \
            | sed -e "s/{kver}/$_ini_kver/g" -e "s@{out}@$_ini_out@g")
        info "initramfs: INITRAMFS_CMD override: $_ini_cmd"
        sh -c "$_ini_cmd" || die "initramfs: INITRAMFS_CMD failed (rc=$?): $_ini_cmd"
    else
        require_cmds mkinitfs
        # §8.3/ADR-13 (G-C10): the Alpine-native builder with the pinned
        # feature set — cryptsetup (unlock), the root-fs driver, and the
        # custom alpine-fde feature (the §8.2 Early-Boot Unseal Hook +
        # features.d/alpine-fde.files payload). mkinitfs collects every file
        # the feature lists, so nothing topology-specific rides the argv.
        _ini_features=$(initramfs_features)
        info "initramfs: mkinitfs features: $_ini_features"
        mkinitfs -c /etc/mkinitfs/mkinitfs.conf \
            -F "$_ini_features" \
            -o "$_ini_out" "$_ini_kver" \
            || die "initramfs: mkinitfs failed for kernel $_ini_kver"
    fi
    [ -f "$_ini_out" ] || die "initramfs: builder produced no output at $_ini_out"
}

# --- initramfs unseal splice (real-server blocker #23) ---------------------------
# mkinitfs 3.14.1's initramfs-init has NO user-hook mechanism (no sourced
# /etc/mkinitfs/* hook, no feature .sh, no crypttab consumer — verified against
# the stock usr/share/mkinitfs/initramfs-init). The §8.2 Early-Boot Unseal Hook
# rides in via mkinitfs.conf custom_files
# (/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh) but is NEVER invoked:
# boot B tries to mount the raw encrypted container and lands in the
# recovery shell. The fix is a pinned POST-PROCESS of the built initrd:
# unpack the cpio, splice the unseal call into initramfs-init at the exact
# point where drivers + /dev are up (after nlplug-findfs) and BEFORE the root
# mount attempt, inject /etc/crypttab (nothing else packs it), and repack.
#
# TWO splice points, one idempotent step (marker ALPINE-FDE-SPLICE-v1):
#   splice A (pre-mount, after the nlplug-findfs invocation): run the hook,
#             then point KOPT_root at the mapped container — the stock mount
#             uses "$KOPT_root" and the cmdline names the raw LUKS UUID.
#   splice B (post-mount, before the mount-move/switch_root tail): flip the
#             ADR-20 install-state marker on the mounted NEWROOT via the
#             hook's FDE_STATE_ONLY mode (the hook's own flip is guarded by
#             the state file existing on NEWROOT, which only exists mounted).
#
# Splice ordering contract (ADR-20): the hook is fail-closed by construction
# (bounded recovery prompt -> poweroff -f, never a shell); the splice adds no
# interactive path of its own.

INITRAMFS_SPLICE_MARKER='ALPINE-FDE-SPLICE-v1'
INITRAMFS_SPLICE_FLIP_MARKER='ALPINE-FDE-SPLICE-FLIP-v1'
INITRAMFS_INIT_PATH='init'
INITRAMFS_HOOK_PATH='usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh'

# initramfs_detect_comp FILE — print the compression name (gzip|xz|zstd|lz4|
# none) from the magic bytes; dies loud on an unknown image (blocker #23).
initramfs_detect_comp() {
    _idc_magic=$(od -An -tx1 -N6 "$1" 2>/dev/null | tr -d ' \n')
    case $_idc_magic in
        1f8b*) printf '%s\n' gzip ;;
        fd377a585a00*) printf '%s\n' xz ;;
        28b52ffd*) printf '%s\n' zstd ;;
        04224d18*) printf '%s\n' lz4 ;;
        '') die "initramfs splice: cannot read the initrd image: $1" ;;
        *) die "initramfs splice: unknown initrd compression (magic $_idc_magic) in $1 — refusing to splice" ;;
    esac
}

# _initramfs_splice_block A|B — print the splice block (tab-indented to match
# the initramfs-init body) for the given point:
#   A: after the nlplug-findfs invocation, before resume_from_disk/the mount —
#      run the fail-closed unseal hook, then point KOPT_root at the mapped
#      container (the stock mount uses "$KOPT_root"; the cmdline names the raw
#      LUKS UUID).
#   B: after the root is mounted, before the mount-move/switch_root tail —
#      flip the ADR-20 install-state marker via the hook's FDE_STATE_ONLY
#      mode (the hook's own flip needs the state file on a MOUNTED NEWROOT,
#      which only exists past splice A's mount).

# --- initramfs unseal splice (real-server blocker #23) ---------------------------
# mkinitfs 3.14.1's initramfs-init has NO user-hook mechanism (no sourced
# /etc/mkinitfs/* hook, no feature .sh, no crypttab consumer — verified against
# the stock usr/share/mkinitfs/initramfs-init). The §8.2 Early-Boot Unseal Hook
# rides in via mkinitfs.conf custom_files
# (/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh) but is NEVER invoked:
# boot B tries to mount the raw encrypted container and lands in the recovery
# shell. The fix is a pinned POST-PROCESS of the built initrd: unpack the cpio,
# splice the unseal call into initramfs-init at the exact point where drivers +
# /dev are up (after nlplug-findfs) and BEFORE the root mount attempt, inject
# /etc/crypttab (nothing else packs it), and repack.
#
# TWO splice points, one idempotent step (markers ALPINE-FDE-SPLICE-v1 and
# ALPINE-FDE-SPLICE-FLIP-v1):
#   splice A (pre-mount, after the nlplug-findfs invocation): run the hook,
#             then point KOPT_root at the mapped container — the stock mount
#             uses "$KOPT_root" and the cmdline names the raw LUKS UUID.
#   splice B (post-mount, before the mount-move/switch_root tail): flip the
#             ADR-20 install-state marker on the mounted NEWROOT via the
#             hook's FDE_STATE_ONLY mode (the hook's own flip needs the state
#             file on a MOUNTED NEWROOT, which only exists past splice A's
#             mount).
#
# Splice ordering contract (ADR-20): the hook is fail-closed by construction
# (bounded recovery prompt -> poweroff -f, never a shell); the splice adds no
# interactive path of its own. The splice point ordering is pinned by
# tests/unit/initramfs_splice_unseal.sh: nlplug-findfs < splice A < hook
# invocation < resume_from_disk < root mount < splice B < switch_root.

INITRAMFS_SPLICE_MARKER='ALPINE-FDE-SPLICE-v1'
INITRAMFS_SPLICE_FLIP_MARKER='ALPINE-FDE-SPLICE-FLIP-v1'
INITRAMFS_INIT_PATH='init'
INITRAMFS_HOOK_PATH='usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh'

# initramfs_detect_comp FILE — print the compression name (gzip|xz|zstd|lz4|
# none) from the magic bytes; dies loud on an unknown image (blocker #23).
initramfs_detect_comp() {
    _idc_magic=$(od -An -tx1 -N6 "$1" 2>/dev/null | tr -d ' \n')
    case $_idc_magic in
        1f8b*) printf '%s\n' gzip ;;
        fd377a585a00*) printf '%s\n' xz ;;
        28b52ffd*) printf '%s\n' zstd ;;
        04224d18*) printf '%s\n' lz4 ;;
        '') die "initramfs splice: cannot read the initrd image: $1" ;;
        *) die "initramfs splice: unknown initrd compression (magic $_idc_magic) in $1 — refusing to splice" ;;
    esac
}

# _initramfs_splice_block A|B — print the splice block (tab-indented to match
# the initramfs-init body) for the given point; see the section comment.
_initramfs_splice_block() {
    case $1 in
        A)
            printf '\t# >>> alpine-fde unseal splice (real-server blocker #23; %s) >>>\n' "$INITRAMFS_SPLICE_MARKER"
            printf '\t# boot-lane finding #25 (s23 attempt 24): the SB guard reads the\n'
            printf '\t# efivars SB state - the stock initramfs never mounts efivarfs.\n'
            printf '\tmodprobe efivarfs 2>/dev/null\n'
            printf '\tmount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null\n'
            printf '\t# §8.2 Early-Boot Unseal Hook: Secure-Boot-guarded TPM 2.0 unseal of\n'
            printf '\t# the root container. Fail-closed by construction: bounded recovery\n'
            printf '\t# prompt -> poweroff -f, NEVER a shell (ADR-20). Runs AFTER\n'
            printf '\t# nlplug-findfs (drivers + /dev up) and BEFORE the root mount.\n'
            printf '\tif [ -x /%s ]; then\n' "$INITRAMFS_HOOK_PATH"
            printf '\t\tFDE_NEWROOT="$sysroot" /%s\n' "$INITRAMFS_HOOK_PATH"
            printf '\t\t# the hook opened the mapped container — mount THAT, not the raw UUID\n'
            printf '\t\tif [ -e /dev/mapper/root ]; then\n'
            printf '\t\t\tKOPT_root=/dev/mapper/root\n'
            printf '\t\tfi\n'
            printf '\tfi\n'
            printf '\t# <<< alpine-fde unseal splice (%s) <<<\n' "$INITRAMFS_SPLICE_MARKER"
            ;;
        B)
            printf '\t# >>> alpine-fde state-flip splice (real-server blocker #23; %s) >>>\n' "$INITRAMFS_SPLICE_FLIP_MARKER"
            printf '\t# the root is mounted now: flip the ADR-20 install-state marker\n'
            printf '\t# (installed -> provisional-booted) via the hook state-only mode\n'
            printf '\tif [ -x /%s ] && [ -f "$sysroot/etc/alpine-fde/install-state.json" ]; then\n' "$INITRAMFS_HOOK_PATH"
            printf '\t\tFDE_STATE_ONLY=1 FDE_NEWROOT="$sysroot" /%s\n' "$INITRAMFS_HOOK_PATH"
            printf '\tfi\n'
            printf '\t# <<< alpine-fde state-flip splice (%s) <<<\n' "$INITRAMFS_SPLICE_FLIP_MARKER"
            ;;
    esac
}

# _initramfs_splice_insert INIT ANCHOR_EXACT BLOCK_FILE AFTER|BEFORE — insert
# BLOCK_FILE's contents after/before the FIRST line of INIT exactly equal to
# ANCHOR_EXACT. rc 1 + stderr reason when the anchor is absent (mkinitfs
# version drift — the caller dies loud, never splices blind).
_initramfs_splice_insert() {
    _isi_init=$1 _isi_anchor=$2 _isi_block=$3 _isi_pos=$4
    awk '
        function flush_block() {
            while ((getline bline < blockfile) > 0) print bline
            close(blockfile)
        }
        BEGIN {
            blockfile = ARGV[2]
            anchor = ARGV[3]
            pos = ARGV[4]
            delete ARGV[2]; delete ARGV[3]; delete ARGV[4]
        }
        { lines[++n] = $0 }
        END {
            at = 0
            for (i = 1; i <= n; i++)
                if (lines[i] == anchor) { at = i; break }
            if (at == 0) {
                print "initramfs splice: anchor line not found: [" anchor "] — mkinitfs version drift, refusing to splice blind" > "/dev/stderr"
                exit 1
            }
            for (i = 1; i <= n; i++) {
                if (pos == "before" && i == at) flush_block()
                print lines[i]
                if (pos == "after" && i == at) flush_block()
            }
        }
    ' "$_isi_init" "$_isi_block" "$_isi_anchor" "$_isi_pos" >"$_isi_init.new"
}

# initramfs_splice_unseal INITRD CRYPTTAB — idempotent splice; rc 0 on success
# (spliced now, or already spliced), die 64 loud on any structural surprise.
# INITRAMFS_CMD override builds are SKIPPED with a loud warn (CI stub builders
# own their initrd contents; the audit mirrors the same skip).
initramfs_splice_unseal() {
    [ $# -eq 2 ] || die "initramfs_splice_unseal: usage: <initrd> <crypttab>"
    _isu_img=$1
    _isu_crypttab=$2
    [ -f "$_isu_img" ] || die "initramfs splice: initrd not found: $_isu_img"
    if [ -n "${INITRAMFS_CMD:-}" ]; then
        warn "initramfs splice: skipped — INITRAMFS_CMD override owns the initrd contents (blocker #23)"
        return 0
    fi
    require_cmds gzip cpio
    _isu_comp=$(initramfs_detect_comp "$_isu_img")

    _isu_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-splice.XXXXXX") ||
        die "initramfs splice: mktemp failed"
    case $_isu_comp in
        gzip) _isu_dc="gzip -dc" ;;
        xz) _isu_dc="xz -dc" ;;
        zstd) _isu_dc="zstd -dc" ;;
        lz4) _isu_dc="lz4 -dc" ;;
        none) _isu_dc="cat" ;;
    esac
    # REAL-SERVER BLOCKER #24: the Alpine target's cpio is BUSYBOX (mkinitfs
    # depends on busybox; no GNU cpio apk exists in the closure) and busybox
    # rejects GNU's -D/--quiet — the portable form is cd + `cpio -idm` on
    # stdin (verified against the spool busybox 1.37 applet).
    $_isu_dc "$_isu_img" 2>/dev/null |
        (cd "$_isu_work" && cpio -idm 2>/dev/null) ||
        {
            rm -rf "$_isu_work"
            die "initramfs splice: cpio extraction failed on $_isu_img ($_isu_comp)"
        }
    _isu_init="$_isu_work/$INITRAMFS_INIT_PATH"
    [ -f "$_isu_init" ] || {
        rm -rf "$_isu_work"
        die "initramfs splice: $INITRAMFS_INIT_PATH not found in $_isu_img — not a stock mkinitfs initramfs?"
    }

    # boot-lane finding #24 (s23 attempt 27): the splice rewrites the init via
    # awk (> file), which recreates it with umask perms — the EXECUTABLE bit is
    # lost and boot B dies "Failed to execute /init (error -13)". Preserve the
    # original mode and restore it after the rewrite.
    _isu_mode=$(stat -c '%a' "$_isu_init")
    if [ "$(grep -cF "$INITRAMFS_SPLICE_MARKER" "$_isu_init" 2>/dev/null)" -gt 0 ]; then
        # idempotent re-entry on an ALREADY-spliced image: refresh only the
        # crypttab when the caller supplies one and the archive lacks it
        if [ -n "$_isu_crypttab" ] && [ ! -f "$_isu_work/etc/crypttab" ]; then
            [ -f "$_isu_crypttab" ] ||
                die "initramfs splice: crypttab not found: $_isu_crypttab (the hook cannot resolve the root container without it)"
            mkdir -p "$_isu_work/etc"
            cp "$_isu_crypttab" "$_isu_work/etc/crypttab"
        fi
    else
        [ -f "$_isu_crypttab" ] ||
            die "initramfs splice: crypttab not found: $_isu_crypttab (the hook cannot resolve the root container without it)"
        mkdir -p "$_isu_work/etc"
        cp "$_isu_crypttab" "$_isu_work/etc/crypttab"

        # splice A: anchor = the nlplug-findfs invocation's closing line
        # (2-tab indented "$KOPT_root" — the only 2-tab occurrence in the file;
        # the overlay mount's 3-tab "$KOPT_root" /media/root-ro never matches)
        _initramfs_splice_block A >"$_isu_work/blockA"
        _isi_err=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-splice-err.XXXXXX")
        if ! _initramfs_splice_insert "$_isu_init" \
            "$(printf '\t\t"$KOPT_root"')" "$_isu_work/blockA" after \
            2>"$_isi_err"; then
            _isu_reason=$(cat "$_isi_err")
            rm -rf "$_isu_work" "$_isi_err"
            die "initramfs splice: $_isu_reason"
        fi
        mv "$_isu_init.new" "$_isu_init"
        rm -f "$_isi_err"

        # splice B: anchor = the mount-move/switch_root tail's first line
        _initramfs_splice_block B >"$_isu_work/blockB"
        _isi_err=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-splice-err.XXXXXX")
        if ! _initramfs_splice_insert "$_isu_init" \
            "$(printf '\tcat "$ROOT"/proc/mounts 2>/dev/null | while read -r _dev DIR _type _opts ; do')" \
            "$_isu_work/blockB" before 2>"$_isi_err"; then
            _isu_reason=$(cat "$_isi_err")
            rm -rf "$_isu_work" "$_isi_err"
            die "initramfs splice: $_isu_reason"
        fi
        mv "$_isu_init.new" "$_isu_init"
        rm -f "$_isi_err"
    fi

    # repack (same flags as stock sbin/mkinitfs initfs_cpio)
    case $_isu_comp in
        gzip) _isu_c="gzip -9" ;;
        xz) _isu_c="xz -T0" ;;
        zstd) _isu_c="zstd -T0" ;;
        lz4) _isu_c="lz4" ;;
        none) _isu_c="cat" ;;
    esac
    # boot-lane finding #24: restore the executable mode BEFORE the repack —
    # the awk rewrite recreated the init with umask perms (EACCES at boot).
    chmod "$_isu_mode" "$_isu_init"

    (cd "$_isu_work" && find . | sort | cpio --quiet --renumber-inodes -o -H newc) |
        $_isu_c >"$_isu_img" ||
        {
            rm -rf "$_isu_work"
            die "initramfs splice: repack failed"
        }


    # self-verify: markers + hook invocation + parseability of the SHIPPED image
    initramfs_splice_verify "$_isu_img" ||
        die "initramfs splice: self-verification failed — refusing to ship the initrd (blocker #23)"
    return 0
}

# initramfs_splice_init_content INITRD OUTDIR — extract usr/share/mkinitfs/
# initramfs-init from INITRD into OUTDIR; prints the extracted path; dies loud
# when absent. Shared by the splice self-check and the audit.
initramfs_splice_init_content() {
    _msc_img=$1
    _msc_out=$2
    [ -f "$_msc_img" ] || die "initramfs splice: initrd not found: $_msc_img"
    require_cmds gzip cpio
    mkdir -p "$_msc_out"
    # busybox-safe (blocker #24): cd instead of -D, no --quiet, extract ALL
    # (busybox -i [EXTR] pattern support varies) — the file check below gates
    gzip -dc "$_msc_img" 2>/dev/null |
        (cd "$_msc_out" && cpio -idm 2>/dev/null) ||
        true
    _msc_f="$_msc_out/$INITRAMFS_INIT_PATH"
    [ -f "$_msc_f" ] ||
        die "initramfs splice: $INITRAMFS_INIT_PATH not found in $_msc_img"
    printf '%s\n' "$_msc_f"
}

# initramfs_splice_verify INITRD — the splice self-check/audit primitive:
# both markers appear EXACTLY once, the hook invocation is present, the splice
# point ordering holds (nlplug-findfs < unseal < resume_from_disk < root mount
# < state-flip < switch_root), no interactive shell was added, and the spliced
# init parses. rc 0; rc 1 with $_initrd_splice_reason on any miss.
initramfs_splice_verify() {
    _msv_img=$1
    _initrd_splice_reason=''
    command -v gzip >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1 || {
        _initrd_splice_reason="initramfs splice: gzip/cpio not available — cannot verify the splice"
        err "initrd audit: $_initrd_splice_reason"
        return 1
    }
    _msv_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-splice-verify.XXXXXX") ||
        die "initramfs splice verify: mktemp failed"
    _msv_init=$(initramfs_splice_init_content "$_msv_img" "$_msv_work")
    _msv_fail() {
        _initrd_splice_reason=$1
        err "initrd audit: $_initrd_splice_reason"
        rm -rf "$_msv_work"
        return 1
    }
    for _msv_mark in "$INITRAMFS_SPLICE_MARKER" "$INITRAMFS_SPLICE_FLIP_MARKER"; do
        _msv_marks=$(grep -cF "$_msv_mark" "$_msv_init")
        [ "$_msv_marks" -eq 2 ] || {
            rm -rf "$_msv_work"
            _msv_fail "initramfs splice: the '$_msv_mark' marker appears $_msv_marks time(s) in $INITRAMFS_INIT_PATH (expected 2: open+close) — the unseal hook is PACKED BUT NEVER CALLED (blocker #23 class)"
            return 1
        }
    done
    grep -qF "$INITRAMFS_HOOK_PATH" "$_msv_init" || {
        rm -rf "$_msv_work"
        _msv_fail "initramfs splice: the unseal hook invocation is missing from $INITRAMFS_INIT_PATH (blocker #23)"
        return 1
    }
    # ordering: nlplug anchor < splice A < resume_from_disk < root mount < splice B
    _msv_nlplug=$(grep -nF "$(printf '\t\t"$KOPT_root"')" "$_msv_init" | head -n 1 | cut -d: -f1)
    _msv_spliceA=$(grep -nF "$INITRAMFS_SPLICE_MARKER" "$_msv_init" | head -n 1 | cut -d: -f1)
    _msv_resume=$(grep -nF '	resume_from_disk' "$_msv_init" | head -n 1 | cut -d: -f1)
    # the root MOUNT (not an earlier helper reference): first occurrence AFTER
    # the resume_from_disk call inside the root branch
    _msv_mount=$(grep -nF '"${KOPT_root#ZFS=}"' "$_msv_init" |
        { while IFS=: read -r n _; do [ "$n" -gt "$_msv_resume" ] && { echo "$n"; break; }; done; })
    _msv_flip=$(grep -nF "$INITRAMFS_SPLICE_FLIP_MARKER" "$_msv_init" | head -n 1 | cut -d: -f1)
    _msv_switch=$(grep -nF '	exec switch_root' "$_msv_init" | head -n 1 | cut -d: -f1)
    if [ -z "$_msv_nlplug" ] || [ -z "$_msv_spliceA" ] || [ -z "$_msv_resume" ] ||
        [ -z "$_msv_mount" ] || [ -z "$_msv_flip" ] || [ -z "$_msv_switch" ] ||
        [ "$_msv_nlplug" -ge "$_msv_spliceA" ] || [ "$_msv_spliceA" -ge "$_msv_resume" ] ||
        [ "$_msv_resume" -ge "$_msv_mount" ] || [ "$_msv_mount" -ge "$_msv_flip" ] ||
        [ "$_msv_flip" -ge "$_msv_switch" ]; then
        rm -rf "$_msv_work"
        _msv_fail "initramfs splice: splice-point ordering violated (nlplug=$_msv_nlplug unseal=$_msv_spliceA resume=$_msv_resume mount=$_msv_mount flip=$_msv_flip switch_root=$_msv_switch) — the unseal must run after drivers are up and BEFORE the root mount (blocker #23)"
        return 1
    fi
    # the splice block adds NO interactive shell (the s90 no-emergency idiom,
    # at the splice level)
    sed -n "/$INITRAMFS_SPLICE_MARKER/,/$INITRAMFS_SPLICE_MARKER/p" "$_msv_init" |
        grep -qE '(^|[[:space:]])(sh|recovery_shell)([[:space:]]|$)' && {
        rm -rf "$_msv_work"
        _msv_fail "initramfs splice: the splice block introduces an interactive shell — the §8.2 no-shell contract is void"
        return 1
    }
    if ! sh -n "$_msv_init" 2>/dev/null; then
        rm -rf "$_msv_work"
        _msv_fail "initramfs splice: the spliced $INITRAMFS_INIT_PATH no longer parses (sh -n failed)"
        return 1
    fi
    rm -rf "$_msv_work"
    return 0
}

# --- initrd inventory audit (§8.2/§12/I6, G-C11 — resolution R9) -----------------
# The unlock artifacts are load-bearing: a missing piece means boots prompt,
# or worse, the hook cannot run at all (G2 lost). The audit runs on EVERY
# build and any miss is a loud failure (ADR-8) naming the artifact.
#
# Alpine/mkinitfs shape (ADR-13): the unlock path IS the §8.2 hook — so the
# REQUIRED set is the hook script itself plus every binary/lib/module it
# needs (mirrors hooks/mkinitfs/features.d/alpine-fde.files, G-C8). busybox
# and ash are ALLOWED: busybox IS the mkinitfs init framework (ADR-13); the
# "no interactive shell" guarantee moved to hook level — the unseal hook
# never offers one and its own unit test proves it (G-C8, resolution R9).

# Required unlock artifacts (§8.2/G-C8): the hook + its exact tpm2 verbs.
_INITRD_AUDIT_HOOK="alpine-fde-unseal.sh"
_INITRD_AUDIT_CRYPT="cryptsetup openssl"
_INITRD_AUDIT_TPM2_BINS="tpm2_pcrextend tpm2_startauthsession tpm2_policypcr \
tpm2_policyauthorize tpm2_loadexternal tpm2_verifysignature tpm2_createprimary \
tpm2_load tpm2_unseal tpm2_flushcontext"
_INITRD_AUDIT_TSS_LIBS="libtss2-esys libtss2-mu libtss2-rc libtss2-sys libtss2-tctildr libtss2-tcti-device"
# blocker #12 refinement: the TPM requirement is tpm.ko CORE + at least ONE
# interface driver (tpm_tis OR tpm_crb) — see initrd_audit.
_INITRD_AUDIT_TPM_CORE="tpm.ko"
_INITRD_AUDIT_TPM_IFACE="tpm_tis.ko tpm_crb.ko"

# initrd_lister <initrd-img> — print the initramfs inventory, one archive
# path per line (cpio -it shape). Default: the mkinitfs image is a gzipped
# cpio archive, so the built-in lister is `gzip -dc | cpio -it` (busybox
# provides both on the Alpine target). INITRD_LISTER_CMD overrides the lister
# (a single command receiving the image path as its argument).
initrd_lister() {
    _il_img=$1
    if [ -n "${INITRD_LISTER_CMD:-}" ]; then
        "$INITRD_LISTER_CMD" "$_il_img" 2>/dev/null
    else
        gzip -dc "$_il_img" 2>/dev/null | cpio -it 2>/dev/null
    fi
}

# initrd_audit <initrd-img> — audit the cpio inventory of the built initramfs
# (§8.2/I6):
#   rc 0  inventory compliant
#   rc 1  miss — one-line reason in $_initrd_audit_reason (and on stderr)
# When no lister is available AND the initramfs came from an INITRAMFS_CMD
# override (CI stub builders own their contents, §8.1 B-G9), the audit is
# skipped with a loud warn; on the default mkinitfs path a missing lister is
# a loud failure.
initrd_audit() {
    _ia_img=$1
    _ia_kver=${2:-} # blocker #12: target kernel — enables modules.builtin
    _ia_root=${3:-} # blocker #12: target root — enables the tree verdicts
    _initrd_audit_reason=''
    # an INITRAMFS_CMD override owns the initrd contents (CI stub builders
    # emit deterministic placeholder payloads the cpio lister cannot parse);
    # an EXPLICIT INITRD_LISTER_CMD re-enables the audit regardless
    if [ -n "${INITRAMFS_CMD:-}" ] && [ -z "${INITRD_LISTER_CMD:-}" ]; then
        warn "initrd audit: skipped — INITRAMFS_CMD override owns the initrd contents (§8.2/I6); set INITRD_LISTER_CMD to audit it"
        return 0
    fi
    if [ -n "${INITRD_LISTER_CMD:-}" ] &&
        ! command -v "$INITRD_LISTER_CMD" >/dev/null 2>&1; then
        if [ -n "${INITRAMFS_CMD:-}" ]; then
            warn "initrd audit: skipped — no lister ($INITRD_LISTER_CMD); INITRAMFS_CMD override owns the initrd contents (§8.2/I6)"
            return 0
        fi
        _initrd_audit_reason="initrd audit: lister not available ($INITRD_LISTER_CMD) — cannot audit the initramfs inventory (§8.2/I6)"
        err "$_initrd_audit_reason"
        return 1
    fi
    if [ -z "${INITRD_LISTER_CMD:-}" ] &&
        { ! command -v gzip >/dev/null 2>&1 || ! command -v cpio >/dev/null 2>&1; }; then
        if [ -n "${INITRAMFS_CMD:-}" ]; then
            warn "initrd audit: skipped — no gzip/cpio lister; INITRAMFS_CMD override owns the initrd contents (§8.2/I6)"
            return 0
        fi
        _initrd_audit_reason="initrd audit: gzip/cpio not available — cannot audit the initramfs inventory (§8.2/I6)"
        err "$_initrd_audit_reason"
        return 1
    fi
    _ia_inv=$(initrd_lister "$_ia_img") || {
        _initrd_audit_reason="initrd audit: lister failed on $_ia_img"
        err "$_initrd_audit_reason"
        return 1
    }

    # blocker #23 verdict: the unseal splice must be IN the initramfs-init —
    # the hook being merely PACKED (custom_files) while never INVOKED is the
    # exact 'packed but never called' failure class the splice exists to kill.
    # Scoped to FULL stock initramfs images (initramfs-init present): synthetic
    # partial images (module-payload fixtures) carry no init to splice.
    if printf '%s\n' "$_ia_inv" | grep -q "^$INITRAMFS_INIT_PATH$"; then
        if ! initramfs_splice_verify "$_ia_img"; then
            _initrd_audit_reason="$_initrd_splice_reason"
            return 1
        fi
        if ! printf '%s\n' "$_ia_inv" | grep -q "^etc/crypttab$"; then
            _initrd_audit_reason="initrd audit: /etc/crypttab is missing from the initramfs — the unseal hook cannot resolve the root container (blocker #23)"
            err "$_initrd_audit_reason"
            return 1
        fi
    else
        warn "initrd audit: splice verdict not applicable — no $INITRAMFS_INIT_PATH in the image (synthetic partial initramfs)"
    fi

    # _ia_has BASENAME — inventory carries a path whose last component matches.
    # REAL-SERVER BLOCKER #12: kernel modules are matched COMPRESSION-SUFFIX
    # TOLERANT — Alpine kernel packages ship .ko.gz/.ko.xz/.ko.zst and the
    # live 6.18.53-0-lts run packed .ko.gz modules the exact-name match could
    # not see (the audit false-positived "tpm.ko ... btrfs.ko missing" while
    # the initrd carried every one of them as .ko.gz).
    _ia_has() {
        case $1 in
            *.ko)
                _ia_b=${1%.ko}
                printf '%s\n' "$_ia_inv" |
                    grep -Eq "(^|/)${_ia_b}\.ko(\.gz|\.xz|\.zst)?$"
                ;;
            *)
                printf '%s\n' "$_ia_inv" | grep -Eq "(^|/)$1\$"
                ;;
        esac
    }

    # REAL-SERVER BLOCKER #12: kernel-reality context. When the caller passes
    # the target root + kver (ukictl build does), modules are also judged
    # against /lib/modules/<kver>/modules.builtin — a module the KERNEL BUILT
    # IN ships no .ko file anywhere, so requiring one in the inventory
    # false-positives forever.
    _ia_builtin=''
    if [ -n "${_ia_kver:-}" ] && [ -n "${_ia_root:-}" ] &&
        [ -f "${_ia_root}/lib/modules/${_ia_kver}/modules.builtin" ]; then
        _ia_builtin=$(cat "${_ia_root}/lib/modules/${_ia_kver}/modules.builtin")
    fi

    # _ia_mod_sat NAME — kernel module SATISFIED: packed in the initrd
    # (compression-suffix tolerant) or built-in (modules.builtin)
    _ia_mod_sat() {
        _ia_has "$1" && return 0
        [ -n "$_ia_builtin" ] &&
            printf '%s\n' "$_ia_builtin" | grep -q "/$1\$"
    }

    # _ia_verdicts collects the per-artifact SELF-DIAGNOSIS appended to the
    # failure reason (blocker #12d): a miss is
    #   missing-from-initrd      = the TARGET TREE has the module but mkinitfs
    #                              did not pack it (feature-file request bug —
    #                              check the staged alpine-fde.files)
    #   missing-from-target-tree = the kernel does not ship it at all
    #   missing                  = no kernel context was provided (legacy)
    _ia_missing=''
    _ia_verdicts=''
    _ia_require_mod() {
        if ! _ia_mod_sat "$1"; then
            _ia_missing="$_ia_missing $1"
            if [ -n "${_ia_kver:-}" ] && [ -n "${_ia_root:-}" ] &&
                [ -d "${_ia_root}/lib/modules/${_ia_kver}" ]; then
                if find "${_ia_root}/lib/modules/${_ia_kver}" -name "${1}*" -print -quit 2>/dev/null | grep -q .; then
                    _ia_verdicts="$_ia_verdicts $1=missing-from-initrd"
                else
                    _ia_verdicts="$_ia_verdicts $1=missing-from-target-tree"
                fi
            else
                _ia_verdicts="$_ia_verdicts $1=missing"
            fi
        fi
        return 0
    }

    # required: the §8.2 unseal hook itself + cryptsetup/openssl + the exact
    # tpm2 verbs the hook runs + libtss2 + the TPM kernel modules
    for _ia_name in "$_INITRD_AUDIT_HOOK" $_INITRD_AUDIT_CRYPT $_INITRD_AUDIT_TPM2_BINS \
        $_INITRD_AUDIT_TSS_LIBS; do
        case $_ia_name in
            libtss2-*)
                # substring match: sonamed shared objects (libtss2-esys.so.0)
                case $_ia_inv in
                    *"$_ia_name"*) ;;
                    *) _ia_missing="$_ia_missing $_ia_name" ;;
                esac
                ;;
            *)
                case $_ia_name in
                    alpine-fde-unseal.sh)
                        case $_ia_inv in
                            *"$_ia_name"*) ;;
                            *) _ia_missing="$_ia_missing $_ia_name" ;;
                        esac
                        ;;
                    *)
                        if ! _ia_has "$_ia_name"; then
                            _ia_missing="$_ia_missing $_ia_name"
                        fi
                        ;;
                esac
                ;;
        esac
    done

    # TPM kernel modules (blocker #12 refinement): require the tpm.ko CORE
    # plus AT LEAST ONE interface driver that exists for the target kernel
    # (tpm_tis OR tpm_crb — suffix-tolerant or built-in). Requiring all three
    # false-positived kernels that ship only one interface driver; the install
    # record additionally names the DETECTED driver from /sys/class/tpm.
    _ia_require_mod tpm.ko
    if ! _ia_mod_sat tpm_tis.ko && ! _ia_mod_sat tpm_crb.ko; then
        _ia_missing="$_ia_missing tpm_tis.ko|tpm_crb.ko"
        _ia_v=missing
        if [ -n "${_ia_kver:-}" ] && [ -n "${_ia_root:-}" ] &&
            [ -d "${_ia_root}/lib/modules/${_ia_kver}" ]; then
            if find "${_ia_root}/lib/modules/${_ia_kver}" \
                \( -name 'tpm_tis.ko*' -o -name 'tpm_crb.ko*' \) -print -quit 2>/dev/null | grep -q .; then
                _ia_v=missing-from-initrd
            else
                _ia_v=missing-from-target-tree
            fi
        fi
        _ia_verdicts="$_ia_verdicts tpm_tis.ko|tpm_crb.ko=$_ia_v"
    fi

    # required per persisted topology (§8.2/§4.1, G-ST5): the root filesystem
    # driver (btrfs.ko by default; ext4.ko when the conf says ROOT_FS=ext4)
    # and — for hybrid bcache (BCACHE=1) — bcache.ko + 69-bcache.rules
    # (without them /dev/bcache0 never registers and cryptsetup cannot open
    # the container). A missing fs driver is the same G2-loss/I6 class: the
    # initrd cannot mount root, ever. The 69-bcache.rules UDEV RULE is a real
    # FILE — kernel-reality (built-in) never satisfies it.
    initramfs_topology
    _ia_topo=''
    case $INI_ROOT_FS in
        ext4) _ia_topo='ext4.ko' ;;
        *) _ia_topo='btrfs.ko' ;;
    esac
    if [ "$INI_BCACHE" = "1" ]; then
        _ia_topo="$_ia_topo bcache.ko 69-bcache.rules"
    fi
    for _ia_name in $_ia_topo; do
        case $_ia_name in
            69-bcache.rules)
                case $_ia_inv in
                    *"$_ia_name"*) ;;
                    *) _ia_missing="$_ia_missing $_ia_name" ;;
                esac
                ;;
            *.ko)
                _ia_require_mod "$_ia_name"
                ;;
            *)
                if ! _ia_has "$_ia_name"; then
                    _ia_missing="$_ia_missing $_ia_name"
                fi
                ;;
        esac
    done
    if [ -n "$_ia_missing" ]; then
        _initrd_audit_reason="initrd audit: required unlock artifact(s) missing:$_ia_missing
initrd audit: artifact verdicts:$_ia_verdicts — in-initrd/built-in = satisfied; missing-from-initrd = the target tree HAS the module but mkinitfs did not pack it (check the staged /etc/mkinitfs/features.d/alpine-fde.files); missing-from-target-tree = the kernel does not ship it; missing = no kernel context given"
        err "$_initrd_audit_reason"
        return 1
    fi

    # the TPM udev rule (creates /dev/tpmrm0) — per-line match. boot-lane
    # finding #11: DOWNGRADED to a loud warn. devtmpfs creates /dev/tpmrm0
    # in-kernel (the mkinitfs init runs devtmpfs/mdev, not udev), and NOTHING
    # in the pinned Alpine closure ships a *tpm*.rules file — the hard
    # requirement was unsatisfiable on real installs and failed the audit
    # after every genuinely-required artifact had passed.
    _ia_rule=$(printf '%s\n' "$_ia_inv" | grep -E 'rules\.d/[^[:space:]]*tpm[^[:space:]]*\.rules' | head -n 1)
    if [ -z "$_ia_rule" ]; then
        warn "initrd audit: TPM udev rule (tpmrm0) absent from the initramfs (§8.2) — devtmpfs creates the node in-kernel; continuing"
    fi

    # deny rules: compilers / package tools / foreign shells. Parse the
    # trailing path field (bare cpio -it paths have no permission prefix).
    #
    # MD-04 carry-over: the compiler set covers clang, make/gmake and
    # triplet-prefixed toolchain binaries (the *-*linux*-* globs subsume
    # every arch triplet and version suffix).
    #
    # Package tools are denied: the initramfs must not be able to mutate or
    # query the package database. REAL-SERVER BLOCKER #14: apk is EXEMPT —
    # mkinitfs's own `base` feature ships /sbin/apk + the etc/apk skeleton by
    # design (modloop/rebase flow, stock Alpine), so an apk hit is upstream
    # behavior, not foreign payload; the foreign-tooling threat is the
    # Debian-side families, which stay denied (see the deny case below).
    #
    # Foreign shells (bash/zsh/dash/ksh/...) are denied; busybox, ash and sh
    # are ALLOWED — busybox IS the mkinitfs init framework (ADR-13) and the
    # §8.2 hook offers no interactive path of its own (G-C8 resolution R9).
    _ia_deny=$(printf '%s\n' "$_ia_inv" | while IFS= read -r _ia_line; do
        _ia_path=${_ia_line##* }
        [ -n "$_ia_path" ] || continue
        _ia_base=${_ia_path##*/}
        # boot-lane finding #13: package tools are denied as EXECUTABLES by
        # PATH (bin//sbin/) — mkinitfs's base layout creates an EMPTY etc/apk
        # DIRECTORY in every initramfs (its init's own scratch dir), and a
        # bare directory entry is not a tool. The basename-only deny would
        # have read the directory as a package tool.
        case $_ia_path in
            # boot-lane finding #14: apk is NOT deniable — mkinitfs's OWN base
            # feature ships /sbin/apk (now /usr/sbin/apk) and its init uses
            # apk.static for repository boots: every real Alpine initramfs
            # carries it. Only foreign package tools are denied.
            *bin/dpkg* | *bin/apt*)
                printf 'denied package tool: %s\n' "$_ia_path"
                continue ;;
        esac
        case $_ia_base in
            gcc | gcc-* | cc | clang | clang-* | tcc | make | gmake \
                | ld | ld.gold | ld.bfd \
                | *-linux-gnu-gcc | *-linux-gnu-ld \
                | *-*linux*-gcc | *-*linux*-gcc-* | *-*linux*-ld | *-*linux*-ld-*)
                printf 'denied compiler: %s\n' "$_ia_path"
                ;;
            apt | apt-* | dpkg | dpkg-*)
                printf 'denied package tool: %s\n' "$_ia_path"
                ;;
            bash | zsh | dash | ksh | csh | tcsh | fish)
                printf 'denied shell (allowlist: busybox/ash — the init framework): %s\n' "$_ia_path"
                ;;
        esac
    done)
    if [ -n "$_ia_deny" ]; then
        _initrd_audit_reason="initrd audit: denied artifact in initramfs: $_ia_deny"
        err "$_initrd_audit_reason"
        return 1
    fi

    info "initrd audit: inventory compliant (hook, cryptsetup, tpm2 verbs, libtss2, TPM modules + udev rule, $INI_ROOT_FS fs driver; no deny hits)"
    return 0
}

# --- crypttab guard (§8.2 verified coupling, G-U4/G-ST4) --------------------------
# systemd-cryptsetup adds tpm2-tss to the initrd only when /etc/crypttab carries
# a tpm2-device= option AT BUILD TIME; omitting it silently disables ALL TPM
# unlock. The build therefore refuses to generate an initramfs unless the root
# entries are guarded — per the topology the installer wrote (§8.2 crypttab
# contract, §4.1):
#   * single-disk / bcache: ONE entry with target `root`
#   * multi-disk Btrfs RAID1: entries `root1`, `root2`, … each carrying
#     password-cache=yes (fallback prompts only once across members)
#   * tpm2-device= is MANDATORY on EVERY root/root<N> entry
#   * count rule (TOPOLOGY-aware, real-server blocker #10): TOPOLOGY=single
#     or bcache ⇒ exactly ONE root/root<N> entry; TOPOLOGY=bcache-multi or
#     raid1 ⇒ at least TWO (one per member container); a LEGACY conf without
#     the TOPOLOGY key keeps the historical BCACHE=1 ⇒ exactly-one rule
#     root entry (the LUKS2 container on /dev/bcache0)

# crypttab_tpm2_check <crypttab-path> — rc 0 iff <path> exists and EVERY
# non-comment entry whose target is `root` or `root<N>` carries tpm2-device=;
# a multi-entry (RAID1) file additionally requires password-cache=yes on each
# such entry, and the root/root<N> COUNT is topology-checked (blocker #10:
# TOPOLOGY=single|bcache ⇒ exactly 1; bcache-multi|raid1 ⇒ >=2; a legacy conf
# without TOPOLOGY keeps BCACHE=1 ⇒ exactly 1). Comments/blank
# lines ignored; a tpm2-device= on any non-root line is not sufficient. On
# failure prints a one-line reason (stdout) for the ADR-8 marker.
crypttab_tpm2_check() {
    _ct_file=$1
    if [ ! -f "$_ct_file" ]; then
        printf '%s\n' "crypttab guard: $_ct_file is missing — initrd would silently lack TPM unlock (§8.2)"
        return 1
    fi
    initramfs_topology
    _ct_entries=$(awk '$1 !~ /^#/ && NF && $1 ~ /^root[0-9]*$/ { print }' \
        "$_ct_file" 2>/dev/null)
    if [ -z "$_ct_entries" ]; then
        printf '%s\n' "crypttab guard: no root/root<N> entry in $_ct_file — initrd would silently lack TPM unlock (§8.2)"
        return 1
    fi
    _ct_n=$(printf '%s\n' "$_ct_entries" | grep -c .)
    # REAL-SERVER BLOCKER #10: the count rule is TOPOLOGY-aware. INI_TOPOLOGY
    # '' = legacy conf WITHOUT the TOPOLOGY key — keep the historical
    # BCACHE=1 ⇒ exactly-one rule verbatim (back-compat: an old conf must
    # keep failing the same way it always did).
    case $INI_TOPOLOGY in
        single | bcache)
            if [ "$_ct_n" -ne 1 ]; then
                printf '%s\n' "crypttab guard: TOPOLOGY=$INI_TOPOLOGY requires exactly one root entry (the single LUKS2 container), found $_ct_n in $_ct_file (§8.2/§4.1)"
                return 1
            fi
            ;;
        bcache-multi | raid1)
            if [ "$_ct_n" -lt 2 ]; then
                printf '%s\n' "crypttab guard: TOPOLOGY=$INI_TOPOLOGY requires at least two root/root<N> entries (one per member container), found $_ct_n in $_ct_file (§8.2/§4.1)"
                return 1
            fi
            ;;
        *)
            if [ "$INI_BCACHE" = "1" ] && [ "$_ct_n" -ne 1 ]; then
                printf '%s\n' "crypttab guard: BCACHE=1 topology requires exactly one root entry (the LUKS2 container on the bcache device), found $_ct_n in $_ct_file (§8.2/§4.1)"
                return 1
            fi
            ;;
    esac
    _ct_bad=''
    while IFS= read -r _ct_line; do
        [ -n "$_ct_line" ] || continue
        if ! printf '%s\n' "$_ct_line" | grep -Eq '(^|[[:space:],])tpm2-device='; then
            # shellcheck disable=SC2086  # word split intended: field 1 = target
            set -- $_ct_line
            _ct_bad="$_ct_bad $1"
        fi
    done <<EOF
$_ct_entries
EOF
    if [ -n "$_ct_bad" ]; then
        printf '%s\n' "crypttab guard: root entry(s)$_ct_bad have no tpm2-device= option in $_ct_file — omitting it silently disables TPM unlock (§8.2)"
        return 1
    fi
    if [ "$_ct_n" -gt 1 ]; then
        _ct_nopc=''
        while IFS= read -r _ct_line; do
            [ -n "$_ct_line" ] || continue
            if ! printf '%s\n' "$_ct_line" |
                grep -Eq '(^|[[:space:],])password-cache=yes([[:space:],]|$)'; then
                # shellcheck disable=SC2086  # word split intended: field 1 = target
                set -- $_ct_line
                _ct_nopc="$_ct_nopc $1"
            fi
        done <<EOF
$_ct_entries
EOF
        if [ -n "$_ct_nopc" ]; then
            printf '%s\n' "crypttab guard: multi-entry (RAID1) crypttab: root entry(s)$_ct_nopc lack password-cache=yes in $_ct_file — fallback passphrase prompts would repeat per member (§8.2/§4.1)"
            return 1
        fi
    fi
    return 0
}

# --- fail-closed cmdline pins (§8.2 H-G1, G-U6; G-C9 resolution R10) --------------
# `rd.shell=0 rd.emergency=poweroff` (pinned in the UKI cmdline, embedded
# verbatim from the cmdline.txt build input) is INERT on the Alpine/mkinitfs
# target — mkinitfs init processes no rd.* knobs. The pins are kept as
# DEFENSE-IN-DEPTH for any boot-path component that does honor the systemd
# dracut-era knobs (e.g. tooling booting the kernel without our UKI). The
# fail-closed guarantee itself is OWNED by the §8.2 Early-Boot Unseal Hook:
# 3 failed recovery attempts end in `poweroff -f` and the hook never spawns a
# shell (tests/unit/hooks_mkinitfs_unseal.sh). A user-edited cmdline.txt
# missing the pins must still fail the rebuild closed, not silently drop the
# belt-and-braces layer.

# cmdline_pins_check <cmdline-file> — rc 0 iff BOTH pins are present as
# standalone words AND no conflicting occurrence of either knob exists in
# <file>. An overriding duplicate (`rd.shell=1 rd.shell=0`) is morally
# identical to a removal — the effective value would be argument-order
# dependent for any knob-consuming consumer, so any rd.shell=/rd.emergency=
# word that is not exactly the pin fails the check (review HW-2). On failure
# prints a one-line reason (stdout) naming the conflict or the missing pin(s),
# for the ADR-8 marker.
cmdline_pins_check() {
    _cp_file=$1
    if [ ! -f "$_cp_file" ]; then
        printf '%s\n' "cmdline pins guard: $_cp_file is missing (§8.2 H-G1)"
        return 1
    fi
    _cp_hit_shell=0
    _cp_hit_emerg=0
    _cp_conflict=''
    while IFS= read -r _cp_line || [ -n "$_cp_line" ]; do
        for _cp_word in $_cp_line; do
            case $_cp_word in
                rd.shell=0) _cp_hit_shell=1 ;;
                rd.emergency=poweroff) _cp_hit_emerg=1 ;;
                rd.shell=* | rd.emergency=*)
                    _cp_conflict="$_cp_conflict $_cp_word"
                    ;;
            esac
        done
    done <"$_cp_file"
    if [ -n "$_cp_conflict" ]; then
        printf '%s\n' "cmdline pins guard: $_cp_file has conflicting pin override(s):$_cp_conflict — only the exact pins rd.shell=0 rd.emergency=poweroff may appear (§8.2 H-G1)"
        return 1
    fi
    _cp_missing=''
    [ "$_cp_hit_shell" -eq 1 ] || _cp_missing="$_cp_missing rd.shell=0"
    [ "$_cp_hit_emerg" -eq 1 ] || _cp_missing="$_cp_missing rd.emergency=poweroff"
    if [ -n "$_cp_missing" ]; then
        printf '%s\n' "cmdline pins guard: $_cp_file missing required fail-closed pin(s):$_cp_missing (§8.2 H-G1)"
        return 1
    fi
    return 0
}

return 0
