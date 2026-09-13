#!/bin/sh
# install.sh — `debian-fde install`: guided disk setup + minimal Debian rootfs +
# signed boot chain (§8.1, §3.3; C-G7/C-G12).
#
# RUNNER SEAM (DEBIAN_FDE_INSTALL_RUNNER):
#   dry-run (default)  print the complete action plan, execute nothing
#   chroot             guided local install from the live ISO: host steps run
#                      now, guest steps run via `chroot <mnt> sh -c`
#   qemu               emit the guest-side plan as a script for the CI harness
#                      (host steps emitted as comments) — no execution
#
# Real (non-dry-run) runs are gated behind --yes and preconditions (root,
# target disk, signing medium, hooks tree).
#
# Plan steps are tagged host|guest; file drops into the target root are done
# host-side at $MNT (chroot) or emitted as guest printf lines (qemu).

if [ -n "${DEBIAN_FDE_INSTALL_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_INSTALL_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

if [ -z "${DEBIAN_FDE_KEYS_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../keys.sh"
fi

SPC_INSTALL_RUNNERS='dry-run chroot qemu'

inst_runner() { printf '%s\n' "${DEBIAN_FDE_INSTALL_RUNNER:-dry-run}"; }
inst_mnt() { printf '%s\n' "${DEBIAN_FDE_INSTALL_MNT:-/mnt}"; }
inst_suite() { printf '%s\n' "${DEBIAN_FDE_SUITE:-trixie}"; }
inst_mirror() { printf '%s\n' "${DEBIAN_FDE_MIRROR:-http://deb.debian.org/debian}"; }
# --- ESP sizing (§13): measured UKI size x retention + headroom ---------------
INST_ESP_RETENTION=3 # current + 2 retained UKIs (§9.3)
INST_ESP_HEADROOM_BYTES=$((64 * 1024 * 1024))
INST_ESP_DEFAULT=512M

# inst_uki_size_probe — byte size of a measurable UKI artifact (CI harness /
# re-install contexts set DEBIAN_FDE_UKI_FILE); empty output = unmeasurable.
inst_uki_size_probe() {
    _ips_f=${DEBIAN_FDE_UKI_FILE:-}
    if [ -n "$_ips_f" ] && [ -f "$_ips_f" ]; then
        wc -c <"$_ips_f" | tr -d '[:space:]'
    fi
    return 0
}

# inst_esp_size_compute MEASURED_BYTES RETENTION HEADROOM_BYTES — ESP size for
# the sfdisk plan: measured UKI size x retention + headroom, rounded UP to
# whole MiB. Unmeasurable (empty/non-numeric) or garbage inputs fall back to
# the fixed default (§13: override via DEBIAN_FDE_ESP_SIZE wins regardless).
inst_esp_size_compute() {
    _ies_m=$1
    _ies_r=$2
    _ies_h=$3
    case $_ies_m in
        '' | *[!0-9]*)
            printf '%s\n' "$INST_ESP_DEFAULT"
            return 0
            ;;
    esac
    case $_ies_r in
        '' | *[!0-9]* | 0) _ies_r=$INST_ESP_RETENTION ;;
    esac
    case $_ies_h in
        '' | *[!0-9]*) _ies_h=0 ;;
    esac
    _ies_b=$((_ies_m * _ies_r + _ies_h))
    printf '%sM\n' $(( (_ies_b + 1048575) / 1048576 ))
}

inst_esp_size() {
    # env override wins (§13)
    if [ -n "${DEBIAN_FDE_ESP_SIZE:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_ESP_SIZE"
        return 0
    fi
    _ies_m=$(inst_uki_size_probe)
    inst_esp_size_compute "$_ies_m" "$INST_ESP_RETENTION" "$INST_ESP_HEADROOM_BYTES"
}
inst_user() { printf '%s\n' "${DEBIAN_FDE_INSTALL_USER:-admin}"; }

# inst_microcode_pkgs [CPUINFO] — CPU-vendor microcode package(s) for the apt
# transaction, resolved HOST-side at plan-build time (I-H2: the bare chroot has
# no /proc, so in-guest detection provably no-ops — every chroot install
# silently got amd64-microcode, even on Intel). GenuineIntel ->
# intel-microcode; AuthenticAMD -> amd64-microcode; unreadable/unknown -> BOTH
# (safe superset — §3.1: microcode is security-relevant, never skip it).
inst_microcode_pkgs() {
    _imp_f=${1:-/proc/cpuinfo}
    _imp_v=''
    if [ -r "$_imp_f" ]; then
        _imp_v=$(grep -m1 -E 'vendor_id|vendor' "$_imp_f" 2>/dev/null || true)
    fi
    case $_imp_v in
        *GenuineIntel*) printf '%s\n' 'intel-microcode' ;;
        *AuthenticAMD*) printf '%s\n' 'amd64-microcode' ;;
        *) printf '%s\n' 'intel-microcode amd64-microcode' ;;
    esac
}

# inst_shell_safe LABEL VALUE — M-02 boundary validation: every value below is
# interpolated into plan records that are eval'd (host) or `sh -c`'d (guest);
# this allow-list keeps shell metacharacters out BEFORE any plan record exists
# (e.g. --user 'x; rm -rf /' must die as a usage error, never reach a record).
inst_shell_safe() {
    _iss_label=$1
    _iss_val=$2
    case $_iss_val in
        '' | *[!a-zA-Z0-9_./:=+~-]*)
            die -r "$DEBIAN_FDE_USAGE" "install: $_iss_label contains characters that are not allowed: $_iss_val"
            ;;
    esac
    return 0
}

# inst_uki_marker_write KEYDIR — persist the ADR-8 loud-failure marker (§8.3
# marker convention, `reason:` line consumed by `debian-fde status`); best effort.
inst_uki_marker_write() {
    _ium_dir=$(sp_etc_dir)
    mkdir -p "$_ium_dir" 2>/dev/null || true
    {
        printf 'install: first-boot UKI not authored\n'
        printf 'time: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'reason: release signing key absent: %s/release.pem (ADR-8; set DEBIAN_FDE_INSTALL_SKIP_UKI=1 to skip knowingly)\n' "$1"
    } >"$_ium_dir/build-failed" 2>/dev/null ||
        warn "install: cannot persist the ADR-8 marker at $_ium_dir/build-failed"
    return 0
}

# inst_uki_gate KEYDIR — the ONE first-boot UKI custody gate (H-03/I-H3, ADR-8;
# IR-01: this was duplicated in preflight + plan-build step 0, warning twice in
# skip mode). Non-dry-run only — dry-run never gates (the plan prints the
# <signing-medium> shape). Verdict via rc:
#   release.pem present -> keys_require (I4 material check); rc 0 (author+sign)
#   absent + SKIP_UKI=1 -> ONE loud warn; rc 1 (knowingly-unbootable opt-out)
#   absent, no opt-out  -> fail-closed 64 + the ADR-8 marker
# The verdict is published in INST_UKI_SKIP (preflight consumes it at plan
# build; no second check, no second warn).
INST_UKI_SKIP=0
inst_uki_gate() {
    _iug_dir=$1
    if [ -f "$_iug_dir/release.pem" ]; then
        keys_require "$_iug_dir"
        return 0
    fi
    if [ "${DEBIAN_FDE_INSTALL_SKIP_UKI:-}" = "1" ]; then
        warn "install: release key absent + DEBIAN_FDE_INSTALL_SKIP_UKI=1 — no first-boot UKI, no boot-manager signing (ADR-8)"
        return 1
    fi
    inst_uki_marker_write "$_iug_dir"
    die "install: release signing key absent ($_iug_dir/release.pem) — the first-boot UKI cannot be authored (ADR-8); marker: $(sp_etc_dir)/build-failed — set DEBIAN_FDE_INSTALL_SKIP_UKI=1 to install anyway"
}

# the self-contained Debian FDE tree (parent of lib/) — hooks/ + bin/ live here
inst_tree() {
    _it_lib=$(sp_cmd_dir)
    printf '%s\n' "${_it_lib%/*/*}"
}
inst_hooks_dir() { printf '%s\n' "${DEBIAN_FDE_HOOKS_DIR:-$(inst_tree)/hooks}"; }
sp_keydir() { printf '%s\n' "${DEBIAN_FDE_KEYDIR:-}"; }

# inst_tooling_copy_cmd TREE MNT — the §8.1 self-contained tooling copy: ship
# ONLY the product script tree (bin/ lib/ hooks/ docs/) into <mnt>/opt/debian-fde.
# Explicit per-directory copies (§3.3): never descends into VCS/harness residue
# (.git, tests/, fixtures/, caches, run dirs — a dirty checkout holds 100MB+
# blobs and root-owned device nodes that a whole-tree `cp -r` copies or dies
# on); plain per-dir `cp -r src/. dst/` is POSIX/busybox-ash and rerun-safe.
inst_tooling_copy_cmd() {
    _itc_tree=$1
    _itc_mnt=$2
    _itc_mkdir="mkdir -p $_itc_mnt/opt $_itc_mnt/usr/local/bin"
    _itc_cps=''
    for _itc_d in bin lib hooks docs; do
        _itc_mkdir="$_itc_mkdir $_itc_mnt/opt/debian-fde/$_itc_d"
        _itc_cps="$_itc_cps && cp -r $_itc_tree/$_itc_d/. $_itc_mnt/opt/debian-fde/$_itc_d/"
    done
    printf '%s%s && ln -sf /opt/debian-fde/bin/debian-fde %s/usr/local/bin/debian-fde\n' \
        "$_itc_mkdir" "$_itc_cps" "$_itc_mnt"
    return 0
}

install_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde install --disk DEVICE [--keydir DIR] [--user NAME] [--yes]

Guided install to a blank disk (§4): GPT (ESP + LUKS2), Argon2id luksFormat
with entropy-floored passphrase slot 0, ext4 root, debootstrap --variant=minbase
trixie (§3.3), apt policy (no-recommends, main+non-free-firmware), minimal
package set in ONE transaction, user account, networkd, crypttab
(tpm2-device=auto), bootctl install + sbsign of the boot manager (release key
from the signing medium, I4), /etc/debian-fde + kernel hooks copied into the
root, and the FIRST-BOOT UKI authored + signed from the installer environment
(dracut → ukify → sbsign; the signing key never enters the target, I4;
DEBIAN_FDE_INSTALL_SKIP_UKI=1 skips it knowingly — ADR-8).

Runner (DEBIAN_FDE_INSTALL_RUNNER): dry-run (default) prints the plan;
chroot executes (root, live ISO, --yes required); qemu emits a guest script.
Passphrase for luksFormat: DEBIAN_FDE_DISK_PASSPHRASE or interactive prompt
(§13 entropy floor enforced). Env: DEBIAN_FDE_ESP_SIZE (default 512M),
DEBIAN_FDE_MIRROR, DEBIAN_FDE_SUITE (default trixie), DEBIAN_FDE_INSTALL_MNT,
DEBIAN_FDE_INSTALL_USER.
EOF
}

# inst_part DEV N — partition device name (p-suffix after a digit-ending disk)
inst_part() {
    case $1 in
        *[0-9]) printf '%sp%s\n' "$1" "$2" ;;
        *) printf '%s%s\n' "$1" "$2" ;;
    esac
}

# passphrase_floor_ok lives in rotate.sh; install needs it too. Source
# rotate.sh for the shared function (include guard makes this idempotent).
inst_ensure_passphrase_floor() {
    if ! command -v passphrase_floor_ok >/dev/null 2>&1; then
        # shellcheck disable=SC1090
        . "$(sp_cmd_dir)/rotate.sh"
    fi
}

# --- plan records -----------------------------------------------------------
# SPC_PLAN holds "KIND<TAB>CMD" lines (guest cmds must be single-line shell);
# file drops are executed/emitted at plan-build time (order-independent).
SPC_PLAN=''

inst_plan_add() {
    _ipa_kind=$1
    shift
    if [ "$(inst_runner)" = "dry-run" ]; then
        printf 'PLAN  %-6s %s\n' "$_ipa_kind" "$*"
        return 0
    fi
    SPC_PLAN="$SPC_PLAN$_ipa_kind	$*
"
    return 0
}

# inst_plan_write RELPATH LINE... — drop a file into the target root.
# Config drops execute IN PLAN ORDER (§3.3: after mount + debootstrap, before
# the first apt use): the chroot runner defers them as host plan records
# (eager writes would land before the target is mounted, G-I1); dry-run prints
# them; qemu emits guest printf lines.
inst_plan_write() {
    _ipw_p=$1
    shift
    case $(inst_runner) in
        dry-run)
            printf 'PLAN  write  %s (%s lines)\n' "$_ipw_p" "$#"
            for _ipw_l in "$@"; do
                printf 'PLAN    | %s\n' "$_ipw_l"
            done
            ;;
        chroot)
            _ipw_cmd="printf '%s\\n'"
            for _ipw_l in "$@"; do
                _ipw_q=$(printf '%s' "$_ipw_l" | sed "s/'/'\\\\''/g")
                _ipw_cmd="$_ipw_cmd '$_ipw_q'"
            done
            inst_plan_add host "mkdir -p $(inst_mnt)${_ipw_p%/*} && $_ipw_cmd >$(inst_mnt)$_ipw_p"
            ;;
        qemu)
            # guest-side write, single command line; single-quote escape each line
            _ipw_cmd="printf '%s\\n'"
            for _ipw_l in "$@"; do
                _ipw_q=$(printf '%s' "$_ipw_l" | sed "s/'/'\\\\''/g")
                _ipw_cmd="$_ipw_cmd '$_ipw_q'"
            done
            inst_plan_add guest "$_ipw_cmd >$_ipw_p"
            ;;
    esac
    return 0
}

# inst_plan_run KIND CMD... — append a command plan record
inst_plan_run() {
    _ipr_kind=$1
    shift
    inst_plan_add "$_ipr_kind" "$*"
}

# inst_execute_plan — run accumulated records (non-dry-run runners)
inst_execute_plan() {
    case $(inst_runner) in
        chroot)
            # plan on fd3: executed commands keep the real stdin (tty) so
            # interactive prompts (passwd, luksFormat) never eat plan lines
            _ie_plan=$(mktemp "${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}/debian-fde-plan.XXXXXX")
            printf '%s' "$SPC_PLAN" >"$_ie_plan"
            # L-04a + WR-02: a die mid-plan must leave NOTHING behind — one
            # combined EXIT trap scrubs the plan file AND the staged passphrase
            # key-file, then tears the H-02 binds down best-effort (never
            # masking the real exit code; skipped when we died before the
            # mountpoint was even resolved)
            trap '
                rm -f "$_ie_plan" "${_ird_kf:-}" 2>/dev/null
                if [ -n "${_im_mnt:-}" ]; then
                    umount "$_im_mnt/dev" "$_im_mnt/sys" "$_im_mnt/proc" 2>/dev/null || :
                fi
            ' EXIT
            while IFS='	' read -r _ie_kind _ie_cmd <&3; do
                [ -n "$_ie_cmd" ] || continue
                if [ "$_ie_kind" = "host" ]; then
                    info "host: $_ie_cmd"
                    # shellcheck disable=SC2086  # plan lines are shell
                    eval "$_ie_cmd" || die "install: host step failed: $_ie_cmd"
                else
                    info "guest: $_ie_cmd"
                    # shellcheck disable=SC2086
                    # L-04b: strip the passphrase variable at the boundary —
                    # chroot(1) passes the parent environment to the guest
                    chroot "$(inst_mnt)" /usr/bin/env -u DEBIAN_FDE_DISK_PASSPHRASE /bin/sh -c "$_ie_cmd" ||
                        die "install: guest step failed: $_ie_cmd"
                fi
            done 3<"$_ie_plan"
            trap - EXIT
            rm -f "$_ie_plan"
            ;;
        qemu)
            _ie_out=${DEBIAN_FDE_INSTALL_SCRIPT:-/tmp/debian-fde-install-guest.sh}
            {
                printf '#!/bin/sh\n# debian-fde install — guest-side plan (generated; runner=qemu)\n# Host-side steps are comments; the CI harness executes them itself.\nset -eu\n'
                printf '%s' "$SPC_PLAN" | while IFS='	' read -r _ie_kind _ie_cmd; do
                    [ -n "$_ie_cmd" ] || continue
                    if [ "$_ie_kind" = "guest" ]; then
                        printf '%s\n' "$_ie_cmd"
                    else
                        printf '# HOST: %s\n' "$_ie_cmd"
                    fi
                done
            } >"$_ie_out"
            chmod 700 "$_ie_out"
            printf 'debian-fde: guest install script written: %s\n' "$_ie_out" >&2
            ;;
    esac
    return 0
}

# inst_resolve_target_metadata ESPDEV MNT LUKSUUID — post-sfdisk target
# resolution (§8.4, executed in plan order by the chroot runner): resolve the
# ESP PARTUUID, patch the fstab placeholder and populate the copied baseline's
# target.* fields (rotate/enroll on the installed system key off them).
inst_resolve_target_metadata() {
    _irt_esp=$1
    _irt_mnt=$2
    _irt_uuid=$3
    _irt_pu=$(lsblk -no PARTUUID "$_irt_esp" 2>/dev/null | head -n 1 | tr -d '[:space:]')
    [ -n "$_irt_pu" ] || die "install: cannot resolve ESP PARTUUID for $_irt_esp (post-sfdisk)"
    sed "s|<esp-partuuid>|$_irt_pu|" "$_irt_mnt/etc/fstab" >"$_irt_mnt/etc/fstab.tmp" ||
        die "install: fstab PARTUUID patch failed"
    mv "$_irt_mnt/etc/fstab.tmp" "$_irt_mnt/etc/fstab"
    _irt_bl="$_irt_mnt/etc/debian-fde/baseline.json"
    [ -f "$_irt_bl" ] || die "install: no copied baseline at $_irt_bl — cannot set target metadata"
    baseline_set_field "$_irt_bl" '    ' target esp_partuuid "$_irt_pu"
    baseline_set_field "$_irt_bl" '    ' target luks_uuid "$_irt_uuid"
    info "install: resolved target: esp_partuuid=$_irt_pu luks_uuid=$_irt_uuid"
    return 0
}

# --- static package set (§3.3) — lint target for the harness -----------------
install_package_list() {
    # one transaction so linux-image-amd64's linux-initramfs-tool resolves to
    # dracut, not initramfs-tools; microcode is appended separately (CPU-dependent);
    # jq is the debian-fde CLI's own dependency — the /opt/debian-fde tooling copy
    # must be runnable in-guest for §9.1's enroll-from-booted-system path (§3.3)
    printf '%s\n' 'systemd-cryptsetup systemd-boot systemd-boot-tools systemd-ukify dracut linux-image-amd64 tpm2-tools cryptsetup sbsigntool openssl zram-tools jq sudo'
}

# inst_preflight DISK — fail-closed checks for a real run
inst_preflight() {
    _if_disk=$1
    [ "$(id -u)" = "0" ] || die "install: must run as root (live ISO environment)"
    [ -b "$_if_disk" ] || [ -f "$_if_disk" ] || die "install: target disk not found: $_if_disk"
    # baseline must exist and validate BEFORE any destructive step (§8.1, §8.4):
    # it is copied into the target root and rotated/enroll read it there
    _if_bl=$(sp_baseline_file)
    [ -f "$_if_bl" ] || die "install: no baseline at $_if_bl — run 'provision stage1' first (§9.1)"
    baseline_validate "$_if_bl" || die "install: baseline invalid: $_if_bl (re-run 'provision stage1')"
    _if_keydir=$(sp_keydir)
    [ -n "$_if_keydir" ] || die "install: no signing medium — pass --keydir (I4)"
    # shared keys.sh seams (I4): the ONE UKI custody gate (routing: the
    # FIRST-BOOT UKI is signed from this installer env with <keydir>/release.pem
    # — the private key is the gating artifact; see inst_uki_gate), then the
    # offline-custody guard.
    inst_uki_gate "$_if_keydir" && INST_UKI_SKIP=0 || INST_UKI_SKIP=1
    keys_offline_guard "$_if_keydir" "$(inst_mnt)"
    # hooks/ ships FLAT templates: <name> maps to its run-parts destination
    # (§8.3) — postinst.d-zz-debian-fde → /etc/kernel/postinst.d/zz-debian-fde
    for _if_h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
        systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
        [ -f "$(inst_hooks_dir)/$_if_h" ] || die "install: hook template missing: $(inst_hooks_dir)/$_if_h"
    done
    # ukify runs INSTALLER-side (first-boot UKI authored from this env, H-03)
    require_pkgs sfdisk:util-linux cryptsetup:cryptsetup mkfs.ext4:e2fsprogs \
        mkfs.vfat:dosfstools debootstrap:debootstrap sbsign:sbsigntool \
        lsblk:util-linux ukify:systemd-ukify
    return 0
}

# inst_read_passphrase PROMPT — read one passphrase line from stdin without
# echo (stty -echo when stdin is a tty); prompt on stderr, value on stdout.
inst_read_passphrase() {
    _irp_prompt=$1
    printf '%s' "$_irp_prompt" >&2
    _irp_restore=0
    if [ -t 0 ] && stty -echo 2>/dev/null; then
        _irp_restore=1
    fi
    _irp_val=''
    IFS= read -r _irp_val || _irp_val=''
    if [ "$_irp_restore" = 1 ]; then
        stty echo 2>/dev/null
    fi
    printf '\n' >&2
    printf '%s' "$_irp_val"
    return 0
}

# inst_resolve_disk_passphrase — the §13 passphrase contract: env variable or
# interactive no-echo prompt (asked twice); BOTH paths pass passphrase_floor_ok
# before a key-file for scripted luksFormat/open is staged. Sets the global
# _IRD_KEYFILE to the staged key-file path (empty for dry-run) and returns rc;
# dies 2 on floor violation.
# BR-01: callers MUST invoke this DIRECTLY — never in command substitution.
# The EXIT trap scrubbing the key-file has to be armed in the MAIN shell; a
# subshell call (`x=$(inst_resolve_disk_passphrase)`) fired the trap at
# subshell exit, deleting the key-file before any plan step ran, and the
# unset of DEBIAN_FDE_DISK_PASSPHRASE never reached the caller.
inst_resolve_disk_passphrase() {
    _IRD_KEYFILE=''
    if [ "$(inst_runner)" = "dry-run" ]; then
        return 0
    fi
    if [ -n "${DEBIAN_FDE_DISK_PASSPHRASE:-}" ]; then
        _ird_pass=$DEBIAN_FDE_DISK_PASSPHRASE
    else
        _ird_p1=$(inst_read_passphrase 'Set disk encryption passphrase (§13: >=12 chars with 3 character classes, or >=16 chars): ')
        _ird_p2=$(inst_read_passphrase 'Repeat passphrase: ')
        if [ -z "$_ird_p1" ] || [ "$_ird_p1" != "$_ird_p2" ]; then
            die -r "$DEBIAN_FDE_USAGE" "install: passphrases empty or do not match"
        fi
        _ird_pass=$_ird_p1
    fi
    passphrase_floor_ok "$_ird_pass" \
        || die -r "$DEBIAN_FDE_USAGE" "install: disk passphrase below entropy floor (§13: ≥12 chars/3 classes or ≥16; not a common pattern)"
    # M-01 (§11 I1): the plaintext passphrase lives ONLY on tmpfs — same rule
    # as rotate.sh: DEBIAN_FDE_TMPDIR seam, default /dev/shm, NEVER /tmp
    _IRD_KEYFILE=$(mktemp "${DEBIAN_FDE_TMPDIR:-/dev/shm}/debian-fde-diskkey.XXXXXX")
    printf '%s' "$_ird_pass" >"$_IRD_KEYFILE"
    chmod 600 "$_IRD_KEYFILE"
    # scrub on any exit path; cleared after a successful execute. THIS shell:
    # inst_execute_plan's combined L-04a/WR-02 trap replaces it mid-plan, and
    # the `${_ird_kf:-}` in that trap only expands to this key-file because we
    # never left this shell (BR-01).
    _ird_kf=$_IRD_KEYFILE
    trap 'rm -f "$_ird_kf" 2>/dev/null' EXIT
    # L-04b: the key-file above is the only carrier from here on — the
    # plaintext must not ride the environment into guest steps
    unset DEBIAN_FDE_DISK_PASSPHRASE _ird_pass
    return 0
}

cmd_install_main() {
    _im_disk=${DEBIAN_FDE_DISK:-}
    _im_yes=0
    while [ $# -gt 0 ]; do
        case $1 in
            --disk)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --disk requires an argument"
                _im_disk=$2
                shift
                ;;
            --keydir)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --keydir requires an argument"
                DEBIAN_FDE_KEYDIR=$2
                shift
                ;;
            --user)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --user requires an argument"
                DEBIAN_FDE_INSTALL_USER=$2
                shift
                ;;
            -y | --yes) _im_yes=1 ;;
            --dry-run) DEBIAN_FDE_DRY_RUN=1 ;;
            -h | --help)
                install_usage
                return 0
                ;;
            *) die -r "$DEBIAN_FDE_USAGE" "install: unknown argument: $1" ;;
        esac
        shift
    done

    case $(inst_runner) in
        dry-run) : ;;
        chroot | qemu) : ;;
        *)
            die -r "$DEBIAN_FDE_USAGE" "install: unknown runner '$(inst_runner)' (want: $SPC_INSTALL_RUNNERS)"
            ;;
    esac
    if [ "$(inst_runner)" != "dry-run" ] && [ "$_im_yes" -eq 0 ] && [ "${DEBIAN_FDE_YES:-}" != "1" ]; then
        # L-06: gate on the AFFIRMATIVE value — "0"/"no" are refusals, not
        # consent (aligns with prov_stage2's = "1" comparison)
        die -r "$DEBIAN_FDE_USAGE" "install: destructive run (runner=$(inst_runner)) requires --yes"
    fi
    [ -n "$_im_disk" ] || die -r "$DEBIAN_FDE_USAGE" "install: no target disk — pass --disk"

    # --- M-02: validate operator inputs at the boundary ------------------------
    # everything below is interpolated into plan records (eval / sh -c) and
    # must be metacharacter-free BEFORE any record is built (and before
    # preflight, so a rejected value executes nothing)
    inst_shell_safe '--disk' "$_im_disk"
    case $(inst_user) in
        '' | [-]* | *[!a-zA-Z0-9_.-]*)
            die -r "$DEBIAN_FDE_USAGE" "install: invalid --user '$(inst_user)' (allowed: letters, digits, '.', '_', '-')"
            ;;
    esac
    inst_shell_safe 'DEBIAN_FDE_INSTALL_MNT' "$(inst_mnt)"
    inst_shell_safe 'DEBIAN_FDE_SUITE' "$(inst_suite)"
    inst_shell_safe 'DEBIAN_FDE_MIRROR' "$(inst_mirror)"
    inst_shell_safe 'DEBIAN_FDE_ESP_SIZE' "$(inst_esp_size)"
    inst_shell_safe 'DEBIAN_FDE_HOOKS_DIR' "$(inst_hooks_dir)"
    # WR-01: --keydir/DEBIAN_FDE_KEYDIR rides into eval'd plan records (cp,
    # sbsign arguments) — same boundary rule as --disk. Validated only when
    # non-empty: an empty keydir is legal (dry-run substitutes the literal
    # <signing-medium> placeholder below, which is never validated).
    [ -n "$(sp_keydir)" ] && inst_shell_safe 'DEBIAN_FDE_KEYDIR' "$(sp_keydir)"

    if [ "$(inst_runner)" != "dry-run" ]; then
        inst_preflight "$_im_disk"
    fi

    # --- resolved layout values (placeholders stay literal in dry-run) --------
    _im_esp=$(inst_part "$_im_disk" 1)
    _im_luks=$(inst_part "$_im_disk" 2)
    _im_mnt=$(inst_mnt)
    _im_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_uuid='<luks-uuid>'
    _im_rootfs_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_rootfs_uuid='<rootfs-uuid>'
    _im_keydir=$(sp_keydir)
    [ -n "$_im_keydir" ] || _im_keydir='<signing-medium>'
    _im_hooks=$(inst_hooks_dir)
    _im_tree=$(inst_tree)
    _im_user=$(inst_user)

    info "install plan: disk=$_im_disk esp=$_im_esp luks=$_im_luks mnt=$_im_mnt runner=$(inst_runner)"

    # --- 0. first-boot UKI custody gate (H-03/I-H3, ADR-8) ----------------------
    # The gate itself ran ONCE in inst_preflight (inst_uki_gate — IR-01: the
    # old step-0 re-check re-warned in skip mode). Here we only consume the
    # verdict. Dry-run never gated: it resolves the opt-out from the env alone.
    _im_uki_skip=0
    case $(inst_runner) in
        dry-run)
            [ "${DEBIAN_FDE_INSTALL_SKIP_UKI:-}" = "1" ] && _im_uki_skip=1
            ;;
        *)
            _im_uki_skip=$INST_UKI_SKIP
            ;;
    esac

    # --- 1. partition + LUKS + filesystems ------------------------------------
    # §13/T2b: the entropy floor is enforced on BOTH paths (env + interactive
    # prompt asked twice) BEFORE any destructive step; the verified passphrase
    # is staged as a key-file so luksFormat/open run scripted (no re-prompt)
    inst_ensure_passphrase_floor
    # BR-01: DIRECT call (no command substitution) — the resolver arms the
    # key-file scrub trap in THIS shell and publishes _IRD_KEYFILE; a subshell
    # call deleted the staged key-file before any plan step could use it
    inst_resolve_disk_passphrase ||
        die -r "$DEBIAN_FDE_USAGE" "install: cannot resolve the disk passphrase"
    _im_lukskey=$_IRD_KEYFILE
    _im_keyfile_arg=''
    [ -n "$_im_lukskey" ] && _im_keyfile_arg="--key-file $_im_lukskey"
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    inst_plan_run host "cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --uuid $_im_uuid $_im_keyfile_arg $_im_luks # passphrase: §13 floor enforced; interactive when no key-file"
    inst_plan_run host "cryptsetup open $_im_keyfile_arg $_im_luks root-crypt"
    inst_plan_run host "mkfs.ext4 -F -U $_im_rootfs_uuid /dev/mapper/root-crypt"
    inst_plan_run host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_plan_run host "mount /dev/mapper/root-crypt $_im_mnt && mkdir -p $_im_mnt/efi && mount $_im_esp $_im_mnt/efi"

    # --- 2. minimal rootfs (§3.3) ---------------------------------------------
    inst_plan_run host "debootstrap --variant=minbase $(inst_suite) $_im_mnt $(inst_mirror)"

    # --- 3. config drops (host-side writes; guest printf lines under qemu) ----
    inst_plan_write /etc/apt/apt.conf.d/90debian-fde \
        'APT::Install-Recommends "false";' \
        'APT::Install-Suggests "false";' \
        'Acquire::Languages "none";'
    inst_plan_write /etc/apt/sources.list.d/debian-fde.sources \
        'Types: deb' \
        "URIs: $(inst_mirror)" \
        "Suites: $(inst_suite)" \
        'Components: main non-free-firmware' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg'
    inst_plan_write /etc/crypttab \
        "root UUID=$_im_uuid none luks,tpm2-device=auto,discard"
    inst_plan_write /etc/fstab \
        "UUID=$_im_rootfs_uuid / ext4 defaults 0 1" \
        'PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2'
    inst_plan_write /etc/systemd/network/20-debian-fde.network \
        '[Match]' \
        'Name=en* eth*' \
        '' \
        '[Network]' \
        'DHCP=yes'
    # §3.3 trims: no man pages/docs/locales beyond C.UTF-8 (dpkg path-exclude)
    inst_plan_write /etc/dpkg/dpkg.cfg.d/90debian-fde-minimal \
        'path-exclude=/usr/share/doc/*' \
        'path-include=/usr/share/doc/*/copyright' \
        'path-exclude=/usr/share/man/*' \
        'path-exclude=/usr/share/locale/*'
    inst_plan_write /etc/dracut.conf.d/10-debian-fde.conf \
        'hostonly=yes' \
        'hostonly_cmdline=no' \
        'omit_dracutmodules+=" crypt "'
    inst_plan_write /etc/debian-fde/cmdline.txt \
        "root=UUID=$_im_uuid ro rd.shell=0 rd.emergency=poweroff"
    # CR-01: persist the resolved ESP mount for the build side (§8.4) — esp.sh
    # reads ESP_PATH so on-target kernel-hook UKI builds land on the ESP this
    # install actually created (CLI default /efi), never a created-on-root
    # /boot/efi fallback
    inst_plan_write /etc/debian-fde/debian-fde.conf 'ESP_PATH=/efi'
    # H-02: the bare debootstrap chroot has no /proc /sys /dev — bind them
    # before the first guest step so maintainer scripts (dracut hostonly in
    # the apt transaction) and the guest environment behave
    inst_plan_run host "mkdir -p $_im_mnt/proc $_im_mnt/sys $_im_mnt/dev && mount -t proc proc $_im_mnt/proc && mount --bind /sys $_im_mnt/sys && mount --bind /dev $_im_mnt/dev"

    # --- 4. packages (ONE transaction) + user ---------------------------------
    inst_plan_run guest 'apt-get update'
    # H-02: microcode resolved HOST-side (inst_microcode_pkgs) and emitted as a
    # literal — in-chroot detection provably no-ops (no /proc in the chroot)
    inst_plan_run guest "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(install_package_list) $(inst_microcode_pkgs)"
    inst_plan_run guest "useradd -m -s /bin/bash $_im_user"
    # §3.3: the admin user is created WITH its sudo grant
    inst_plan_run guest "usermod -aG sudo $_im_user"
    inst_plan_run guest "passwd $_im_user # interactive password prompt"
    inst_plan_run guest 'systemctl enable systemd-networkd.service systemd-resolved.service'

    # --- 5. Debian FDE tree (product script tree ONLY, §3.3), baseline, hooks ---
    info "tooling copy: product script tree only (bin lib hooks docs) — VCS/harness residue excluded (§3.3)"
    inst_plan_run host "$(inst_tooling_copy_cmd "$_im_tree" "$_im_mnt")"
    if [ "$_im_uki_skip" = 0 ]; then
        inst_plan_run host "mkdir -p $_im_mnt/etc/debian-fde/keys && cp $(sp_baseline_file) $_im_mnt/etc/debian-fde/baseline.json && cp $_im_keydir/release.pub $_im_keydir/release.crt $_im_mnt/etc/debian-fde/keys/"
    else
        # H-03 skip mode: no key material present — ship baseline only
        inst_plan_run host "mkdir -p $_im_mnt/etc/debian-fde/keys && cp $(sp_baseline_file) $_im_mnt/etc/debian-fde/baseline.json"
    fi
    inst_plan_run host "mkdir -p $_im_mnt/etc/kernel/postinst.d $_im_mnt/etc/kernel/postrm.d $_im_mnt/etc/initramfs/post-update.d && cp $_im_hooks/postinst.d-zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde && cp $_im_hooks/postrm.d-zz-debian-fde $_im_mnt/etc/kernel/postrm.d/zz-debian-fde && cp $_im_hooks/systemd-boot-upgrade-zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade && cp $_im_hooks/post-update.d-zz-debian-fde $_im_mnt/etc/initramfs/post-update.d/zz-debian-fde && chmod +x $_im_mnt/etc/kernel/postinst.d/zz-debian-fde $_im_mnt/etc/kernel/postrm.d/zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade $_im_mnt/etc/initramfs/post-update.d/zz-debian-fde"

    # --- 6. boot manager: install + SIGN (release key from the medium) --------
    # G-U7: the boot-manager self-update service is masked — ESP binaries are
    # only ever written by our SIGNED flow (re-sign hook covers upgrades, §8.3)
    inst_plan_run host "mkdir -p $_im_mnt/etc/systemd/system && ln -sf /dev/null $_im_mnt/etc/systemd/system/systemd-boot-update.service"
    inst_plan_run guest 'bootctl install --esp-path=/efi --boot-path=/efi'
    if [ "$_im_uki_skip" = 0 ]; then
        inst_plan_run host "sbsign --key $_im_keydir/release.pem --cert $_im_keydir/release.crt --output $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi.signed $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi && mv $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi.signed $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi"
        inst_plan_run host "cp $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi $_im_mnt/efi/EFI/BOOT/BOOTX64.EFI"
        inst_plan_run host "sbverify --cert $_im_keydir/release.crt $_im_mnt/efi/EFI/systemd/systemd-bootx64.efi"
    fi

    # --- 6b. FIRST-BOOT UKI — authored + signed from the INSTALLER env ---------
    # (H-03/I-H3: without a bootable UKI the installed disk cannot perform
    # §9.1's documented first boot — one passphrase prompt, audit --init
    # finalizes). Chain, all with the target root mounted at $_im_mnt:
    #   dracut (guest, target root, via the H-02 binds; kver from /boot)
    #   → ukify build (installer env; --linux/--initrd from the target,
    #     --cmdline from /etc/debian-fde/cmdline.txt, phase enter-initrd)
    #   → sbsign with the release key from --keydir (I4: the key never enters
    #     the target — the installer env is not the target)
    #   → ESP install in the §8.4 ukictl-build layout
    #   (EFI/Linux/debian-fde-<kver>.efi) — then sbverify.
    # NO token enrollment here: §9.1's ensure-once enroll happens from the
    # booted system (it has the finalized baseline + TPM access).
    if [ "$_im_uki_skip" = 0 ]; then
        inst_plan_run guest 'kver=$(ls -1v /boot 2>/dev/null | sed -n "s/^vmlinuz-//p" | tail -n 1); [ -n "$kver" ] || exit 64; dracut --force --kver "$kver" "/boot/initrd.img-$kver" "$kver"'
        inst_plan_run host "mkdir -p $_im_mnt/efi/EFI/Linux && kver=\$(ls -1v $_im_mnt/boot 2>/dev/null | sed -n 's/^vmlinuz-//p' | tail -n 1) && { [ -n \"\$kver\" ] || { echo 'install: no kernel image found in the target /boot (apt transaction failed?)' >&2; false; }; } && ukify build --linux $_im_mnt/boot/vmlinuz-\$kver --initrd $_im_mnt/boot/initrd.img-\$kver --cmdline \"\$(cat $_im_mnt/etc/debian-fde/cmdline.txt)\" --phase enter-initrd --output $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi && sbsign --key $_im_keydir/release.pem --cert $_im_keydir/release.crt --output $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi.signed $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi && mv $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi.signed $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi && sbverify --cert $_im_keydir/release.crt $_im_mnt/efi/EFI/Linux/debian-fde-\$kver.efi"
    fi

    # --- 7. baseline target metadata + teardown (H-02 binds first) -------------
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid"
    inst_plan_run guest 'printf "debian-fde: after FIRST BOOT, in the installed system (§9.1): debian-fde audit --init && debian-fde enroll-tpm && debian-fde ukictl build\\n" >> /etc/issue'
    inst_plan_run host "umount $_im_mnt/dev $_im_mnt/sys $_im_mnt/proc && umount -R $_im_mnt && cryptsetup close root-crypt"

    if [ "$(inst_runner)" != "dry-run" ]; then
        inst_execute_plan
        trap - EXIT
        rm -f "$_im_lukskey" 2>/dev/null
        printf 'debian-fde: install complete — reboot, then run "debian-fde audit --init" in the new system (§9.1)\n' >&2
    else
        printf 'debian-fde: dry-run plan complete (%s) — after a real install, run "debian-fde audit --init" at first boot (§9.1); execute with DEBIAN_FDE_INSTALL_RUNNER=chroot + --yes\n' "$(inst_runner)" >&2
    fi
    return 0
}
