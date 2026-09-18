#!/bin/sh
# initramfs.sh — initramfs-builder seam (docs/Architecture.md §8.1/§8.3, B-G9).
# `ukictl build` consumes the initrd for the kernel being built; who builds it
# is swappable:
#
#   default : dracut --hostonly --force --kver <kver> <out>   (Debian trixie)
#   override: INITRAMFS_CMD in /etc/debian-fde/debian-fde.conf — a command template
#             in which the literal placeholders {kver} and {out} are replaced
#             before execution, e.g.
#               INITRAMFS_CMD="dracut --hostonly --force --kver {kver} {out}"
#               INITRAMFS_CMD="fixtures/initramfs/stub-generate.sh {out} {kver}"
#             (sandbox/CI uses the stub: dracut output varies with host state,
#             which would churn pcr11_digest per build; the stub is deterministic.)
#
# Determinism contract (B-G9 seam, R3 owns the dracut module set): CI builds MUST
# use a fixed input set so pcr11_digest is reproducible across runs.

if [ -n "${DEBIAN_FDE_INITRAMFS_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_INITRAMFS_LOADED=1

# --- persisted topology conf (§4.1/§8.2; G-ST4/G-ST5) -----------------------------
# The installer persists the provisioned topology in
# /etc/debian-fde/debian-fde.conf as ROOT_FS=btrfs|ext4 and BCACHE=0|1. Both
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
        _icg_conf=/etc/debian-fde/debian-fde.conf
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
_INI_TOPO_WARNED=0

# initramfs_topology — resolve INI_ROOT_FS (btrfs|ext4) and INI_BCACHE (0|1)
# from the persisted conf. Absent or invalid ROOT_FS ⇒ btrfs default; a note
# is warned at most once per process.
initramfs_topology() {
    _ito_fs=$(_initramfs_conf_get ROOT_FS)
    _ito_note=''
    case $_ito_fs in
        btrfs | ext4)
            INI_ROOT_FS=$_ito_fs
            ;;
        '')
            INI_ROOT_FS=btrfs
            _ito_note='no ROOT_FS in debian-fde.conf — defaulting to btrfs (§4.1)'
            ;;
        *)
            INI_ROOT_FS=btrfs
            _ito_note="invalid ROOT_FS '$_ito_fs' in debian-fde.conf — defaulting to btrfs (§4.1)"
            ;;
    esac
    case $(_initramfs_conf_get BCACHE) in
        1) INI_BCACHE=1 ;;
        *) INI_BCACHE=0 ;;
    esac
    if [ "$_INI_TOPO_WARNED" -eq 0 ] && [ -n "$_ito_note" ]; then
        warn "initramfs: $_ito_note"
        _INI_TOPO_WARNED=1
    fi
    return 0
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
        require_cmds dracut
        # §8.2/ADR-13: pin the mandated module set — the systemd unlock path
        # only; the legacy `crypt`/90crypt module is omitted (-m restricts the
        # set, so no dracut-default or config-added prompt path leaks in).
        #
        # Topology modules ride OUTSIDE the pinned -m set (G-ST5, §8.2/§4.1):
        # the root filesystem driver is appended via --add (add_dracutmodules)
        # — btrfs explicitly (the default topology); ext4 needs no add (dracut
        # hostonly collects the active rootfs driver). The bcache
        # force_drivers/install_items wiring is NEVER passed on this argv: it
        # rides the installer's /etc/dracut.conf.d/20-bcache.conf drop, which
        # dracut applies on top of this invocation (nothing removed here).
        initramfs_topology
        _ini_add=''
        if [ "$INI_ROOT_FS" = "btrfs" ]; then
            _ini_add="--add btrfs"
        fi
        # shellcheck disable=SC2086  # deliberate word split; empty ⇒ no arg
        dracut --hostonly --force \
            -m "systemd systemd-cryptsetup tpm2-tss kernel-modules" \
            $_ini_add \
            --kver "$_ini_kver" "$_ini_out" \
            || die "initramfs: dracut failed for kernel $_ini_kver"
    fi
    [ -f "$_ini_out" ] || die "initramfs: builder produced no output at $_ini_out"
}

# --- initrd inventory audit (§8.2/§12/I6) ---------------------------------------
# The unlock artifacts are load-bearing: their absence means tokens are silently
# ignored and every boot prompts (G2 lost). The audit runs on EVERY build and
# any miss is a loud failure (ADR-8) naming the artifact.

# Required unlock artifacts (§8.2):
_INITRD_AUDIT_TOKEN_LIB="usr/lib/x86_64-linux-gnu/systemd/libcryptsetup-token-systemd-tpm2.so"
_INITRD_AUDIT_TSS_LIBS="libtss2-esys libtss2-mu libtss2-rc libtss2-sys libtss2-tctildr libtss2-tcti-device"
_INITRD_AUDIT_TPM_MODULES="tpm.ko tpm_tis.ko tpm_crb.ko"

# initrd_audit <initrd-img> — audit the lsinitrd inventory of the built
# initramfs: required unlock artifacts present, deny rules clean (no compilers
# gcc/clang/ld, incl. Debian triplet-prefixed toolchain binaries, no package
# tools apt/apt-*/dpkg/dpkg-*, no busybox, no shells beyond the minimal
# allowlist `sh` — dash allowed: Debian dracut ships it as the initrd shell).
#   rc 0  inventory compliant
#   rc 1  miss — one-line reason in $_initrd_audit_reason (and on stderr)
# LSINITRD_CMD overrides the lister (default: lsinitrd). When no lister exists
# AND the initramfs came from an INITRAMFS_CMD override (CI stub builders own
# their contents, §8.1 B-G9), the audit is skipped with a loud warn; on the
# default dracut path a missing lister is a loud failure (dracut ships it).
initrd_audit() {
    _ia_img=$1
    _initrd_audit_reason=''
    _ia_cmd=${LSINITRD_CMD:-lsinitrd}
    if ! command -v "$_ia_cmd" >/dev/null 2>&1; then
        if [ -n "${INITRAMFS_CMD:-}" ]; then
            warn "initrd audit: skipped — no lsinitrd ($_ia_cmd); INITRAMFS_CMD override owns the initrd contents (§8.2/I6)"
            return 0
        fi
        _initrd_audit_reason="initrd audit: lsinitrd not available ($_ia_cmd) — cannot audit the initramfs inventory (§8.2/I6)"
        err "$_initrd_audit_reason"
        return 1
    fi
    _ia_inv=$("$_ia_cmd" "$_ia_img" 2>/dev/null) || {
        _initrd_audit_reason="initrd audit: lsinitrd failed on $_ia_img"
        err "$_initrd_audit_reason"
        return 1
    }

    # required: token lib at the multiarch systemd path, libtss2, TPM modules
    _ia_missing=''
    case $_ia_inv in
        *"$_INITRD_AUDIT_TOKEN_LIB"*) ;;
        *) _ia_missing=" $_INITRD_AUDIT_TOKEN_LIB" ;;
    esac
    for _ia_name in $_INITRD_AUDIT_TSS_LIBS $_INITRD_AUDIT_TPM_MODULES; do
        case $_ia_inv in
            *"$_ia_name"*) ;;
            *) _ia_missing="$_ia_missing $_ia_name" ;;
        esac
    done

    # required per persisted topology (§8.2/§4.1, G-ST5): the root filesystem
    # driver (btrfs.ko by default; ext4.ko when the conf says ROOT_FS=ext4)
    # and — for hybrid bcache (BCACHE=1) — bcache.ko + 69-bcache.rules +
    # bcache-register (without them /dev/bcache0 never registers and
    # systemd-cryptsetup cannot open the container). A missing fs driver is
    # the same G2-loss/I6 class: the initrd cannot mount root, ever.
    initramfs_topology
    _ia_topo=''
    case $INI_ROOT_FS in
        ext4) _ia_topo='ext4.ko' ;;
        *) _ia_topo='btrfs.ko' ;;
    esac
    if [ "$INI_BCACHE" = "1" ]; then
        _ia_topo="$_ia_topo bcache.ko 69-bcache.rules bcache-register"
    fi
    for _ia_name in $_ia_topo; do
        case $_ia_inv in
            *"$_ia_name"*) ;;
            *) _ia_missing="$_ia_missing $_ia_name" ;;
        esac
    done
    if [ -n "$_ia_missing" ]; then
        _initrd_audit_reason="initrd audit: required unlock artifact(s) missing:$_ia_missing"
        err "$_initrd_audit_reason"
        return 1
    fi

    # required: the TPM udev rule (creates /dev/tpmrm0) — per-line match
    _ia_rule=$(printf '%s\n' "$_ia_inv" | grep -E 'rules\.d/[^[:space:]]*tpm[^[:space:]]*\.rules' | head -n 1)
    if [ -z "$_ia_rule" ]; then
        _initrd_audit_reason="initrd audit: TPM udev rule (tpmrm0) missing (§8.2)"
        err "$_initrd_audit_reason"
        return 1
    fi

    # deny rules: compilers / package tools / shells beyond the allowlist.
    # Parse the trailing path field (real lsinitrd lines carry a permission
    # prefix; a bare path list works too).
    #
    # MD-04: the compiler set also covers clang and Debian's triplet-prefixed
    # toolchain binaries (the exact naming of native/cross toolchain files:
    # x86_64-linux-gnu-gcc[-12], x86_64-linux-gnu-ld.bfd, ...; the generic
    # *-*linux*-* globs subsume every Debian arch triplet and version suffix).
    # busybox is denied: one binary carries a full shell + coreutils host and
    # defeats the `sh`-only allowlist.
    #
    # dash is deliberately ALLOWED (MD-04 dash resolution): Debian's dracut
    # builds every default initrd around the dash module — /bin/sh IS a
    # (symlink to) usr/bin/dash — so denying dash fails every real production
    # build on a mandated artifact. The dracut-shaped `base` fixture
    # (LSINITRD_FAKE_VARIANT=base) pins this. The allowlist intent still holds:
    # the interactive/fat shells below stay denied, as does the busybox
    # multiplexer. Revisit only if the dracut module set changes (R3).
    _ia_deny=$(printf '%s\n' "$_ia_inv" | while IFS= read -r _ia_line; do
        _ia_path=${_ia_line##* }
        [ -n "$_ia_path" ] || continue
        _ia_base=${_ia_path##*/}
        case $_ia_base in
            gcc | gcc-* | cc | clang | clang-* | tcc | ld | ld.gold | ld.bfd \
                | *-linux-gnu-gcc | *-linux-gnu-ld \
                | *-*linux*-gcc | *-*linux*-gcc-* | *-*linux*-ld | *-*linux*-ld-*)
                printf 'denied compiler: %s\n' "$_ia_path"
                ;;
            apt | apt-* | dpkg | dpkg-*)
                printf 'denied package tool: %s\n' "$_ia_path"
                ;;
            bash | zsh | ksh | csh | tcsh | fish | ash)
                printf 'denied shell (allowlist: sh; dash = Debian dracut initrd shell): %s\n' "$_ia_path"
                ;;
            busybox)
                printf 'denied shell/coreutils host (busybox; allowlist: sh): %s\n' "$_ia_path"
                ;;
        esac
    done)
    if [ -n "$_ia_deny" ]; then
        _initrd_audit_reason="initrd audit: denied artifact in initramfs: $_ia_deny"
        err "$_initrd_audit_reason"
        return 1
    fi

    info "initrd audit: inventory compliant (token lib, libtss2, TPM modules + udev rules, $INI_ROOT_FS fs driver; no deny hits)"
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
#   * BCACHE=1 (persisted conf) ⇒ the file must be bcache-shaped: exactly one
#     root entry (the LUKS2 container on /dev/bcache0)

# crypttab_tpm2_check <crypttab-path> — rc 0 iff <path> exists and EVERY
# non-comment entry whose target is `root` or `root<N>` carries tpm2-device=;
# a multi-entry (RAID1) file additionally requires password-cache=yes on each
# such entry, and BCACHE=1 requires exactly one root entry. Comments/blank
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
    if [ "$INI_BCACHE" = "1" ] && [ "$_ct_n" -ne 1 ]; then
        printf '%s\n' "crypttab guard: BCACHE=1 topology requires exactly one root entry (the LUKS2 container on the bcache device), found $_ct_n in $_ct_file (§8.2/§4.1)"
        return 1
    fi
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

# --- fail-closed cmdline pins (§8.2 H-G1, G-U6) -----------------------------------
# systemd's bounded passphrase loop drops to the initrd EMERGENCY SHELL on
# exhaustion; `rd.shell=0 rd.emergency=poweroff` (pinned in the UKI cmdline,
# embedded verbatim from /etc/debian-fde/cmdline.txt) ends three strikes in
# poweroff — never an unauthenticated shell. A user-edited cmdline.txt missing
# the pins must fail the rebuild closed, not silently embed the escape hatch.

# cmdline_pins_check <cmdline-file> — rc 0 iff BOTH pins are present as
# standalone words AND no conflicting occurrence of either knob exists in
# <file>. An overriding duplicate (`rd.shell=1 rd.shell=0`) is morally
# identical to a removal — the effective value is dracut-getarg-order
# dependent, so any rd.shell=/rd.emergency= word that is not exactly the pin
# fails the check (review HW-2). On failure prints a one-line reason (stdout)
# naming the conflict or the missing pin(s), for the ADR-8 marker.
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
