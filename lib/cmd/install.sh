#!/bin/sh
# install.sh — `debian-fde install`: guided disk setup + minimal Debian rootfs +
# the §9.1 Stage-1 ceremony (chroot provisioning + single-reboot finalization).
#
# TOPOLOGIES (§4.1):
#   single  --disk DISK                      ESP p1 + LUKS2 p2, Btrfs default
#   bcache  --disk BACKING --bcache CACHE    ESP p1 + cache p2 on CACHE, backing
#                                            p1 on BACKING, /dev/bcache0 under
#                                            LUKS2, writethrough pinned (ADR-17)
#   raid1   --disk D1 --disk D2 [--disk Dn]  D1: ESP p1 + LUKS p2; Dn: LUKS p1
#                                            only; mkfs.btrfs -d raid1 -m raid1
#
# RUNNER SEAM (DEBIAN_FDE_INSTALL_RUNNER):
#   dry-run (default)  print the complete action plan, execute nothing
#   chroot             guided local install from the live ISO: host steps run
#                      now, guest steps run via `chroot <mnt> sh -c`
#   qemu               emit the guest-side plan as a script for the CI harness
#                      (host steps emitted as comments) — no execution
#
# Plan steps are tagged host|guest; file drops into the target root are done
# host-side at $MNT (chroot) or emitted as guest printf lines (qemu).
#
# DEBIAN_FDE_INSTALL_NO_REBOOT=1 (or --no-reboot) suppresses the final reboot
# record (CI seam): the plan ends after teardown.

if [ -n "${DEBIAN_FDE_INSTALL_LOADED:-}" ]; then
  return 0
fi
DEBIAN_FDE_INSTALL_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

# The install ceremony state machine (§8.4 install-state.json) is owned by the
# install-state module; consume its API when landed (istate_write), else the
# additive documented schema is written in place (see inst_state_write).
if [ -z "${DEBIAN_FDE_INSTALL_STATE_LOADED:-}" ]; then
  _spci_state_lib=$(sp_cmd_dir)/install-state.sh
  [ -f "$_spci_state_lib" ] ||
    _spci_state_lib=$(sp_cmd_dir)/../install-state.sh
  if [ -f "$_spci_state_lib" ]; then
    # shellcheck disable=SC1090
    . "$_spci_state_lib"
  fi
  unset _spci_state_lib
fi

# firmware seam (fw_sb_state/fw_var_write/fw_auth_enroll/fw_osindications_set)
if [ -z "${DEBIAN_FDE_FIRMWARE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../firmware.sh"
fi

SPC_INSTALL_RUNNERS='dry-run chroot qemu'

inst_runner() { printf '%s\n' "${DEBIAN_FDE_INSTALL_RUNNER:-dry-run}"; }
inst_mnt() { printf '%s\n' "${DEBIAN_FDE_INSTALL_MNT:-/mnt}"; }
inst_suite() { printf '%s\n' "${DEBIAN_FDE_SUITE:-trixie}"; }
inst_mirror() { printf '%s\n' "${DEBIAN_FDE_MIRROR:-http://deb.debian.org/debian}"; }
# --- resolved topology (§4.1): fs + bcache flags ------------------------------
# ROOT_FS: btrfs (default) | ext4. BCACHE: 0 | 1. Recorded into the target's
# /etc/debian-fde/debian-fde.conf; an ABSENT conf file (or absent keys) means
# the built-in defaults ROOT_FS=btrfs, BCACHE=0 — consumers must not require
# the file to exist.
INST_ROOT_FS=${INST_ROOT_FS:-btrfs}
INST_BCACHE=${INST_BCACHE:-0}

inst_root_fs() { printf '%s\n' "${INST_ROOT_FS:-btrfs}"; }
inst_bcache() { printf '%s\n' "${INST_BCACHE:-0}"; }
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
  printf '%sM\n' $(((_ies_b + 1048575) / 1048576))
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
Usage: debian-fde install --disk DEVICE [--disk DEVICE2 ...] [--fs btrfs|ext4]
                          [--bcache CACHE_DEV] [--no-reboot] [--yes]

Guided Stage-1 install (§9.1): firmware Setup Mode gate (SetupMode=1 required —
clear the vendor PK in BIOS first), partition + LUKS2 (Argon2id, recovery
passphrase keyslot 0, §13 entropy floor), Btrfs root with subvolumes
@/@home/@snapshots (default; --fs ext4 for a flat ext4 root; snapshots are
retained until pruned by the operator), debootstrap --variant=minbase trixie
(§3.3), apt policy, minimal package set, then the in-chroot provisioning
sequence (package set, pending baseline, platform-key ceremony, firmware NVRAM
enrollment db -> KEK -> PK, signed boot manager + UKI via `ukictl build`,
release.pem encryption, kernel hooks, install-state=installed), OsIndications
bit 0 and a reboot straight into BIOS setup: toggle Secure Boot ON and the
first boot finalizes (audit --init + TPM enrollment).

Topologies (§4.1): --disk (repeatable for Btrfs RAID1: primary ESP+LUKS,
secondaries LUKS only); --bcache CACHE_DEV for hybrid acceleration (ESP+cache
on the cache dev, LUKS2 on /dev/bcache0, writethrough pinned). --fs ext4 is
single-disk only.

Runner (DEBIAN_FDE_INSTALL_RUNNER): dry-run (default) prints the plan;
chroot executes (root, live ISO, --yes required); qemu emits a guest script.
Passphrase for luksFormat: DEBIAN_FDE_DISK_PASSPHRASE or interactive prompt
(§13 entropy floor enforced). Env: DEBIAN_FDE_ESP_SIZE (default 512M),
DEBIAN_FDE_MIRROR, DEBIAN_FDE_SUITE (default trixie), DEBIAN_FDE_INSTALL_MNT,
DEBIAN_FDE_INSTALL_USER, DEBIAN_FDE_DISKS (dispatcher-provided disk list).
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
                    umount "$_im_mnt/dev" "$_im_mnt/sys" "$_im_mnt/proc" \
                        "$_im_mnt/sys/firmware/efi/efivars" 2>/dev/null || :
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

# inst_baseline_members_set FILE VALUE — additively set target.member_uuids
# (schema extension: luks_uuid stays the PRIMARY member for compatibility).
# baseline_set_field only REPLACES known keys; this inserts the field after
# target.luks_uuid (or replaces it on re-runs) without touching the rest of
# the fixed layout.
inst_baseline_members_set() {
  _ibm_f=$1
  _ibm_v=$2
  _bl_sane "$_ibm_v" || die "install: member_uuids value would break JSON: $_ibm_v"
  if baseline_has_key_in "$_ibm_f" target member_uuids; then
    baseline_set_field "$_ibm_f" '    ' target member_uuids "$_ibm_v"
    return 0
  fi
  _ibm_err=$(awk -v v="$_ibm_v" '
        !done && index($0, "    \"luks_uuid\": \"") == 1 {
            print
            printf "    \"member_uuids\": \"%s\",\n", v
            done = 1
            next
        }
        { print }
        END { exit !done }
    ' "$_ibm_f" 2>&1 >"$_ibm_f.tmp") || {
    rm -f "$_ibm_f.tmp" 2>/dev/null
    die "install: cannot set target.member_uuids: ${_ibm_err:-no target.luks_uuid anchor}"
  }
  mv "$_ibm_f.tmp" "$_ibm_f"
  return 0
}

# inst_resolve_target_metadata ESPDEV MNT LUKSUUID [MEMBER_UUIDS...] —
# post-sfdisk target resolution (§8.4, executed in plan order by the chroot
# runner): resolve the ESP PARTUUID, patch the fstab placeholder and populate
# the ON-TARGET pending baseline's target.* fields. luks_uuid stays the
# PRIMARY member's container UUID for compatibility; the full per-member list
# rides additively in target.member_uuids (space-separated; RAID1 consumers
# enroll/audit per member later).
inst_resolve_target_metadata() {
  _irt_esp=$1
  _irt_mnt=$2
  _irt_uuid=$3
  shift 3
  _irt_pu=$(lsblk -no PARTUUID "$_irt_esp" 2>/dev/null | head -n 1 | tr -d '[:space:]')
  [ -n "$_irt_pu" ] || die "install: cannot resolve ESP PARTUUID for $_irt_esp (post-sfdisk)"
  sed "s|<esp-partuuid>|$_irt_pu|" "$_irt_mnt/etc/fstab" >"$_irt_mnt/etc/fstab.tmp" ||
    die "install: fstab PARTUUID patch failed"
  mv "$_irt_mnt/etc/fstab.tmp" "$_irt_mnt/etc/fstab"
  _irt_bl="$_irt_mnt/etc/debian-fde/baseline.json"
  [ -f "$_irt_bl" ] || die "install: no on-target baseline at $_irt_bl — cannot set target metadata"
  baseline_set_field "$_irt_bl" '    ' target esp_partuuid "$_irt_pu"
  baseline_set_field "$_irt_bl" '    ' target luks_uuid "$_irt_uuid"
  if [ $# -gt 0 ]; then
    _irt_members=$_irt_uuid
    for _irt_m in "$@"; do
      _irt_members="$_irt_members $_irt_m"
    done
    inst_baseline_members_set "$_irt_bl" "$_irt_members"
    info "install: resolved target: esp_partuuid=$_irt_pu luks_uuid=$_irt_uuid member_uuids=$_irt_members"
  else
    info "install: resolved target: esp_partuuid=$_irt_pu luks_uuid=$_irt_uuid"
  fi
  return 0
}

# --- static package set (§3.3) — lint target for the harness -----------------
# Topology-conditional (§3.3/§13): btrfs-progs by default, e2fsprogs for
# --fs ext4, bcache-tools when --bcache is given.
install_package_list() {
  # one transaction so linux-image-amd64's linux-initramfs-tool resolves to
  # dracut, not initramfs-tools; microcode is appended separately (CPU-dependent);
  # jq is the debian-fde CLI's own dependency — the /opt/debian-fde tooling copy
  # must be runnable in-guest for the §9.1 in-chroot ceremony (§3.3)
  # systemd-resolved ships SEPARATE from systemd on trixie (Debian 12+);
  # the §9.1 plan enables systemd-resolved.service — without this package
  # the guest enable step dies ("Unit ... does not exist")
  _ipl='systemd-cryptsetup systemd-boot systemd-boot-tools systemd-ukify systemd-resolved dracut linux-image-amd64 tpm2-tools cryptsetup sbsigntool openssl zram-tools jq sudo'
  case $(inst_root_fs) in
  ext4) _ipl="$_ipl e2fsprogs" ;;
  *) _ipl="$_ipl btrfs-progs" ;;
  esac
  if [ "$(inst_bcache)" = "1" ]; then
    _ipl="$_ipl bcache-tools"
  fi
  printf '%s\n' "$_ipl"
}

# inst_setupmode_gate — G-IL2 (§9.1 preflight, UserGuide §1): the FIRST
# preflight check, BEFORE any disk mutation. Authenticated NVRAM writes
# (db/KEK/PK) require SetupMode==1; a vendor PK still installed would make the
# in-chroot enrollment fail (or worse, brick the boot entry) — fail closed 64
# with the operator fix. Runs over the DEBIAN_FDE_EFIVARS_DIR seam.
inst_setupmode_gate() {
  _isg_dir=$(fw_efivars_dir)
  [ -d "$_isg_dir" ] ||
    die "install: no efivarfs at $_isg_dir — cannot verify firmware Setup Mode (§9.1 preflight: boot the installer media in UEFI mode)"
  fw_var_present "$_isg_dir" SetupMode ||
    die "install: SetupMode variable absent at $_isg_dir — not a setup-mode UEFI environment (§9.1 preflight)"
  _isg_state=$(fw_sb_state || true)
  _isg_setup=${_isg_state#*setup_mode=}
  _isg_setup=${_isg_setup%% *}
  [ "$_isg_setup" = "1" ] ||
    die "install: firmware is NOT in Setup Mode ($_isg_state) — clear the vendor PK in BIOS setup first (§9.1 preflight)"
  info "install: firmware Setup Mode confirmed ($_isg_state)"
  return 0
}

# inst_bootstrap_bin — the bootstrap tool: debootstrap, or mmdebstrap as the
# accepted alternative (§13 host tools). Neither present => debootstrap (the
# canonical name; preflight installs it on demand, ADR-15).
inst_bootstrap_bin() {
  if command -v debootstrap >/dev/null 2>&1; then
    printf '%s\n' debootstrap
  elif command -v mmdebstrap >/dev/null 2>&1; then
    printf '%s\n' mmdebstrap
  else
    printf '%s\n' debootstrap
  fi
  return 0
}

# inst_preflight DISKS... — fail-closed checks for a real run. ORDER IS
# NORMATIVE (§9.1): the firmware Setup Mode gate FIRST (zero disk mutation
# before it), then environment/tool checks.
inst_preflight() {
  inst_setupmode_gate
  [ "$(id -u)" = "0" ] || die "install: must run as root (live ISO environment)"
  for _if_disk in "$@"; do
    [ -b "$_if_disk" ] || [ -f "$_if_disk" ] || die "install: target disk not found: $_if_disk"
  done
  # hooks/ ships FLAT templates: <name> maps to its run-parts destination
  # (§8.3) — postinst.d-zz-debian-fde → /etc/kernel/postinst.d/zz-debian-fde
  for _if_h in postinst.d-zz-debian-fde postrm.d-zz-debian-fde \
    systemd-boot-upgrade-zz-debian-fde post-update.d-zz-debian-fde; do
    [ -f "$(inst_hooks_dir)/$_if_h" ] || die "install: hook template missing: $(inst_hooks_dir)/$_if_h"
  done
  # §13 host tool set — topology-conditional. mmdebstrap is an accepted
  # debootstrap alternative; sbsign/ukify are NOT host-required (the boot
  # manager + UKI are built + signed IN-CHROOT by ukictl build, §9.1 step 5).
  require_pkgs sfdisk:util-linux cryptsetup:cryptsetup mkfs.vfat:dosfstools \
    lsblk:util-linux
  case $(inst_root_fs) in
  ext4) require_pkgs mkfs.ext4:e2fsprogs ;;
  *) require_pkgs mkfs.btrfs:btrfs-progs ;;
  esac
  if ! command -v debootstrap >/dev/null 2>&1 && ! command -v mmdebstrap >/dev/null 2>&1; then
    require_pkgs debootstrap:debootstrap
  fi
  if [ "$(inst_bcache)" = "1" ]; then
    require_pkgs make-bcache:bcache-tools
  fi
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
  passphrase_floor_ok "$_ird_pass" ||
    die -r "$DEBIAN_FDE_USAGE" "install: disk passphrase below entropy floor (§13: ≥12 chars/3 classes or ≥16; not a common pattern)"
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

# inst_baseline_pending_write MNT — §9.1 Stage-1 step 2: write the initial
# baseline (pcr7 "pending" schema, provision-stage1 semantics) DIRECTLY on the
# target via the baseline writer — NO host-baseline copy exists anywhere.
inst_baseline_pending_write() {
  _ibp_mnt=$1
  _ibp_dir=$_ibp_mnt/etc/debian-fde
  mkdir -p "$_ibp_dir"
  unset BL_CREATED_AT BL_PCR0 BL_PCR1 BL_PCR2 BL_PCR3 BL_PCR7 \
    BL_SB_SECURE_BOOT BL_SB_SETUP_MODE BL_SB_PK_FP BL_SB_KEK_FP \
    BL_SB_DB_FP BL_SB_DBX_FP BL_FW_VENDOR BL_FW_VERSION \
    BL_FW_EVENTLOG_SHA256 BL_FW_EVENTLOG_SIZE \
    BL_KEYS_RELEASE_PUB_PATH BL_KEYS_RELEASE_CERT_PATH \
    BL_TARGET_LUKS_UUID BL_TARGET_ESP_PARTUUID
  baseline_write "$_ibp_dir/baseline.json"
  info "install: pending baseline written on target: $_ibp_dir/baseline.json (§9.1 step 2)"
  return 0
}

# inst_state_write STATE — §9.1 Stage-1 step 8: record the ceremony state
# machine (installed → [reboot to BIOS] → finalized) in
# <mnt>/etc/debian-fde/install-state.json. Consumes the install-state module's
# istate_write STATE (target root via DEBIAN_FDE_ROOT, atomic write); if the
# module is not landed, the additive documented schema is written in place.
inst_state_write() {
  _isw_state=$1
  if command -v istate_write >/dev/null 2>&1; then
    _isw_saved=${DEBIAN_FDE_ROOT:-}
    DEBIAN_FDE_ROOT=$(inst_mnt)
    istate_write "$_isw_state"
    unset DEBIAN_FDE_ROOT
    [ -n "$_isw_saved" ] && DEBIAN_FDE_ROOT=$_isw_saved
    info "install: install-state written: $_isw_state ($(inst_mnt)/etc/debian-fde/install-state.json)"
    return 0
  fi
  _isw_file=$(inst_mnt)/etc/debian-fde/install-state.json
  mkdir -p "${_isw_file%/*}"
  printf '{\n  "schema_version": 1,\n  "state": "%s",\n  "updated_at": "%s"\n}\n' \
    "$_isw_state" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$_isw_file" ||
    die "install: cannot write $_isw_file"
  info "install: install-state written: $_isw_state ($_isw_file)"
  return 0
}

cmd_install_main() {
  _im_yes=0
  _im_bcache=''
  _im_fs=''
  _im_no_reboot=0
  # §8.1: --disk is repeatable and ACCUMULATES. DEBIAN_FDE_DISKS (the
  # dispatcher-provided list from repeated global --disk flags) is CONSUMED
  # here, never re-parsed; the legacy single DEBIAN_FDE_DISK seeds the list.
  _im_disks=${DEBIAN_FDE_DISKS:-}
  if [ -z "$_im_disks" ] && [ -n "${DEBIAN_FDE_DISK:-}" ]; then
    _im_disks=$DEBIAN_FDE_DISK
  fi
  while [ $# -gt 0 ]; do
    case $1 in
    --disk)
      [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --disk requires an argument"
      _im_disks="$_im_disks $2"
      shift
      ;;
    --fs)
      [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --fs requires an argument"
      _im_fs=$2
      shift
      ;;
    --bcache)
      [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "install: --bcache requires an argument"
      _im_bcache=$2
      shift
      ;;
    --no-reboot) _im_no_reboot=1 ;;
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
  _im_disks=${_im_disks# }

  case $(inst_runner) in
  dry-run | chroot | qemu) : ;;
  *)
    die -r "$DEBIAN_FDE_USAGE" "install: unknown runner '$(inst_runner)' (want: $SPC_INSTALL_RUNNERS)"
    ;;
  esac
  if [ "$(inst_runner)" != "dry-run" ] && [ "$_im_yes" -eq 0 ] && [ "${DEBIAN_FDE_YES:-}" != "1" ]; then
    # L-06: gate on the AFFIRMATIVE value — "0"/"no" are refusals, not
    # consent (aligns with prov_stage2's = "1" comparison)
    die -r "$DEBIAN_FDE_USAGE" "install: destructive run (runner=$(inst_runner)) requires --yes"
  fi

  # --- topology flags (§4.1) --------------------------------------------------
  INST_ROOT_FS=btrfs
  case $_im_fs in
  '') : ;;
  btrfs) : ;;
  ext4) INST_ROOT_FS=ext4 ;;
  *)
    die -r "$DEBIAN_FDE_USAGE" "install: --fs must be btrfs or ext4 (got: $_im_fs)"
    ;;
  esac
  INST_BCACHE=0
  if [ -n "$_im_bcache" ]; then
    INST_BCACHE=1
  fi

  # --- M-02: validate operator inputs at the boundary ------------------------
  # everything below is interpolated into plan records (eval / sh -c) and
  # must be metacharacter-free BEFORE any record is built (and before
  # preflight, so a rejected value executes nothing)
  [ -n "$_im_disks" ] || die -r "$DEBIAN_FDE_USAGE" "install: no target disk — pass --disk (repeatable for RAID1)"
  if [ "$INST_BCACHE" = "1" ]; then
    inst_shell_safe '--bcache' "$_im_bcache"
    if [ -z "$_im_disks" ]; then
      die -r "$DEBIAN_FDE_USAGE" "install: --bcache needs a backing disk — pass --disk BACKING"
    fi
  fi
  _im_n=0
  for _im_d in $_im_disks; do
    inst_shell_safe '--disk' "$_im_d"
    _im_n=$((_im_n + 1))
  done
  if [ "$INST_BCACHE" = "1" ] && [ "$_im_n" -gt 1 ]; then
    die -r "$DEBIAN_FDE_USAGE" "install: --bcache takes exactly one backing --disk (multi-disk root requires Btrfs RAID1)"
  fi
  if [ "$INST_ROOT_FS" = "ext4" ] && [ "$_im_n" -gt 1 ]; then
    die -r "$DEBIAN_FDE_USAGE" "install: --fs ext4 is single-disk only — multi-disk root requires Btrfs RAID1"
  fi
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
  # WR-01: --keydir rides into eval'd records — same boundary rule. Kept for
  # compatibility; the §9.1 flow generates keys in-chroot, so it is OPTIONAL.
  [ -n "$(sp_keydir)" ] && inst_shell_safe 'DEBIAN_FDE_KEYDIR' "$(sp_keydir)"

  if [ "$(inst_runner)" != "dry-run" ]; then
    inst_preflight $_im_disks
  fi

  # --- resolved layout values (placeholders stay literal in dry-run) --------
  _im_mnt=$(inst_mnt)
  _im_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_uuid='<luks-uuid>'
  _im_rootfs_uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_rootfs_uuid='<rootfs-uuid>'
  _im_hooks=$(inst_hooks_dir)
  _im_tree=$(inst_tree)
  _im_user=$(inst_user)
  _im_topology=single
  if [ "$INST_BCACHE" = "1" ]; then
    _im_topology=bcache
  elif [ "$_im_n" -ge 2 ]; then
    _im_topology=raid1
  fi

  # per-role devices (§4.1)
  set -- $_im_disks
  _im_disk=$1
  _im_esp=$(inst_part "$_im_disk" 1)
  _im_luks=$(inst_part "$_im_disk" 2)
  _im_mapper=/dev/mapper/root-crypt
  _im_close='cryptsetup close root-crypt'
  _im_members_devs=''
  _im_members_mappers=''
  _im_members_uuids=''
  if [ "$_im_topology" = "bcache" ]; then
    _im_esp=$(inst_part "$_im_bcache" 1)
    _im_cache=$(inst_part "$_im_bcache" 2)
    _im_backing=$(inst_part "$_im_disk" 1)
    _im_luks=/dev/bcache0
  elif [ "$_im_topology" = "raid1" ]; then
    _im_mapper=/dev/mapper/root1
    _im_close='cryptsetup close root1'
    _im_i=1
    for _im_d in $_im_disks; do
      [ "$_im_i" -eq 1 ] && {
        _im_i=2
        continue
      }
      _im_md=$(inst_part "$_im_d" 1)
      _im_mu=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_mu="<luks-uuid-$_im_i>"
      _im_members_devs="$_im_members_devs $_im_md"
      _im_members_mappers="$_im_members_mappers /dev/mapper/root$_im_i"
      _im_members_uuids="$_im_members_uuids $_im_mu"
      _im_close="$_im_close && cryptsetup close root$_im_i"
      _im_i=$((_im_i + 1))
    done
    _im_members_devs=${_im_members_devs# }
    _im_members_mappers=${_im_members_mappers# }
    _im_members_uuids=${_im_members_uuids# }
  fi

  info "install plan: topology=$_im_topology fs=$(inst_root_fs) disks=$_im_disks esp=$_im_esp luks=$_im_luks mnt=$_im_mnt runner=$(inst_runner)"

  # --- 0. §13/T2b: passphrase resolution BEFORE any destructive step ---------
  # entropy floor enforced on BOTH paths (env + interactive prompt asked
  # twice); the verified passphrase is staged as a key-file so luksFormat/
  # open run scripted (no re-prompt). BR-01: DIRECT call (no command
  # substitution) — the resolver arms the key-file scrub trap in THIS shell.
  inst_ensure_passphrase_floor
  inst_resolve_disk_passphrase ||
    die -r "$DEBIAN_FDE_USAGE" "install: cannot resolve the disk passphrase"
  _im_lukskey=$_IRD_KEYFILE
  _im_keyfile_arg=''
  [ -n "$_im_lukskey" ] && _im_keyfile_arg="--key-file $_im_lukskey"

  # --- 1. partition + block layer (§4.1, per topology) -----------------------
  case $_im_topology in
  single)
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    ;;
  bcache)
    # ADR-17: ESP p1 + cache p2 on the FAST dev; backing p1 on the --disk
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    inst_plan_run host "printf 'label: gpt\nstart=2048, type=linux, name=\"backing\"\n' | sfdisk $_im_disk"
    inst_plan_run host "make-bcache -C $_im_cache"
    inst_plan_run host "make-bcache -B $_im_backing"
    inst_plan_run host "echo $_im_cache > /sys/fs/bcache/register && echo $_im_backing > /sys/fs/bcache/register"
    inst_plan_run host "CSET_UUID=\$(bcache-super-show $_im_cache | awk '/cset.uuid/ {print \$2}') && echo \"\$CSET_UUID\" > /sys/block/bcache0/bcache/attach && echo writethrough > /sys/block/bcache0/bcache/cache_mode # writethrough pinned (ADR-17: crash-safe, ciphertext-only cache)"
    ;;
  raid1)
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    # secondaries: LUKS2 container p1 ONLY (no ESP on member disks)
    _im_i=1
    for _im_d in $_im_disks; do
      [ "$_im_i" -eq 1 ] && {
        _im_i=2
        continue
      }
      inst_plan_run host "printf 'label: gpt\nstart=2048, type=linux, name=\"root\"\n' | sfdisk $_im_d"
      _im_i=$((_im_i + 1))
    done
    ;;
esac
# (Alpine mdev coldplug is handled by the guarded inst_wait_node_line records
# above — a bare `mdev -s` here would die 127 on hosts without mdev.)

# --- 2. LUKS2 keyslot 0 — the permanent recovery passphrase (§9.1: NO
  #        provisional TPM token is created during Stage 1) -------------------
  inst_plan_run host "cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --uuid $_im_uuid $_im_keyfile_arg $_im_luks # passphrase: §13 floor enforced; interactive when no key-file"
  inst_plan_run host "cryptsetup open $_im_keyfile_arg $_im_luks root-crypt"
  if [ "$_im_topology" = "raid1" ]; then
    # close/rename: primary mapper is root1 in RAID1 topologies; members
    # luksFormat/open zipped with the uuids resolved in the layout block
    inst_plan_run host "cryptsetup close root-crypt && cryptsetup open $_im_keyfile_arg $_im_luks root1"
    _im_i=1
    set -- $_im_members_uuids
    for _im_md in $_im_members_devs; do
      _im_i=$((_im_i + 1))
      _im_mu=$1
      shift
      inst_plan_run host "cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --uuid $_im_mu $_im_keyfile_arg $_im_md"
      inst_plan_run host "cryptsetup open $_im_keyfile_arg $_im_md root$_im_i"
    done
  fi

  # --- 3. filesystem + subvolumes (§4/§9.1) ----------------------------------
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    if [ "$_im_topology" = "raid1" ]; then
      inst_plan_run host "mkfs.btrfs -U $_im_rootfs_uuid -d raid1 -m raid1 $_im_mapper $_im_members_mappers"
    else
      inst_plan_run host "mkfs.btrfs -U $_im_rootfs_uuid $_im_mapper"
    fi
    inst_plan_run host "mount $_im_mapper $_im_mnt"
    inst_plan_run host "btrfs subvolume create $_im_mnt/@"
    inst_plan_run host "btrfs subvolume create $_im_mnt/@home"
    inst_plan_run host "btrfs subvolume create $_im_mnt/@snapshots"
    inst_plan_run host "umount $_im_mnt"
    inst_plan_run host "mount -o subvol=@ $_im_mapper $_im_mnt && mkdir -p $_im_mnt/home $_im_mnt/.snapshots $_im_mnt/efi"
    inst_plan_run host "mount -o subvol=@home $_im_mapper $_im_mnt/home"
    inst_plan_run host "mount -o subvol=@snapshots $_im_mapper $_im_mnt/.snapshots"
    inst_plan_run host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_plan_run host "mount $_im_esp $_im_mnt/efi"
  else
    inst_plan_run host "mkfs.ext4 -F -U $_im_rootfs_uuid $_im_mapper"
    inst_plan_run host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_plan_run host "mount $_im_mapper $_im_mnt && mkdir -p $_im_mnt/efi && mount $_im_esp $_im_mnt/efi"
  fi

  # --- 4. minimal rootfs (§3.3) ---------------------------------------------
  inst_plan_run host "$(inst_bootstrap_bin) --variant=minbase $(inst_suite) $_im_mnt $(inst_mirror)"

  # --- 5. config drops (host-side writes; guest printf lines under qemu) -----
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
  # §8.2 crypttab contract: single entry (single/bcache) has NO
  # password-cache; RAID1 gets one entry PER MEMBER with password-cache=yes
  # so the recovery passphrase is prompted only once across members.
  if [ "$_im_topology" = "raid1" ]; then
    set -- "root1 UUID=$_im_uuid none luks,tpm2-device=auto,password-cache=yes,discard"
    _im_i=1
    for _im_u in $_im_members_uuids; do
      _im_i=$((_im_i + 1))
      set -- "$@" "root$_im_i UUID=$_im_u none luks,tpm2-device=auto,password-cache=yes,discard"
    done
    inst_plan_write /etc/crypttab "$@"
  else
    inst_plan_write /etc/crypttab \
      "root UUID=$_im_uuid none luks,tpm2-device=auto,discard"
  fi
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_write /etc/fstab \
      "UUID=$_im_rootfs_uuid / btrfs subvol=@,defaults 0 1" \
      "UUID=$_im_rootfs_uuid /home btrfs subvol=@home,defaults 0 2" \
      "UUID=$_im_rootfs_uuid /.snapshots btrfs subvol=@snapshots,defaults 0 2" \
      'PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2'
  else
    inst_plan_write /etc/fstab \
      "UUID=$_im_rootfs_uuid / ext4 defaults 0 1" \
      'PARTUUID=<esp-partuuid> /efi vfat umask=0077 0 2'
  fi
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
  if [ "$_im_topology" = "bcache" ]; then
    # §8.2: hostonly chroot collection cannot detect bcache ambiently —
    # force the driver + its udev registration pieces into the initrd
    inst_plan_write /etc/dracut.conf.d/20-bcache.conf \
      'force_drivers+=" bcache "' \
      'install_items+=" /lib/udev/rules.d/69-bcache.rules /lib/udev/bcache-register "'
  fi
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_write /etc/debian-fde/cmdline.txt \
      "root=UUID=$_im_uuid rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
  else
    inst_plan_write /etc/debian-fde/cmdline.txt \
      "root=UUID=$_im_uuid ro rd.shell=0 rd.emergency=poweroff"
  fi
  # CR-01 + §4.1: persist the resolved topology + ESP mount for the build
  # side. ABSENT conf file (or absent keys) = defaults: ROOT_FS=btrfs,
  # BCACHE=0 — consumers must not require the file to exist.
  inst_plan_write /etc/debian-fde/debian-fde.conf \
    '# debian-fde runtime config (KEY=VALUE).' \
    '# Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0.' \
    "ROOT_FS=$(inst_root_fs)" \
    "BCACHE=$(inst_bcache)" \
    'ESP_PATH=/efi'
  # H-02: the bare debootstrap chroot has no /proc /sys /dev — bind them
  # before the first guest step so maintainer scripts (dracut hostonly in
  # the apt transaction) and the guest environment behave. §9.1 also binds
  # the efivars so the in-chroot NVRAM enrollment reaches the live firmware.
  inst_plan_run host "mkdir -p $_im_mnt/proc $_im_mnt/sys $_im_mnt/dev && mount -t proc proc $_im_mnt/proc && mount --bind /sys $_im_mnt/sys && mount --bind /dev $_im_mnt/dev"
  inst_plan_run host "mkdir -p $_im_mnt/sys/firmware/efi/efivars && mount --bind /sys/firmware/efi/efivars $_im_mnt/sys/firmware/efi/efivars"

  # --- 6. tooling copy (host) — the in-chroot CLI lives at /opt/debian-fde ---
  info "tooling copy: product script tree only (bin lib hooks docs) — VCS/harness residue excluded (§3.3)"
  inst_plan_run host "$(inst_tooling_copy_cmd "$_im_tree" "$_im_mnt")"
  # G-U7: the boot-manager self-update service is masked — ESP binaries are
  # only ever written by our SIGNED flow (§8.3)
  inst_plan_run host "mkdir -p $_im_mnt/etc/systemd/system && ln -sf /dev/null $_im_mnt/etc/systemd/system/systemd-boot-update.service"

  # --- 7. in-chroot provisioning (§9.1, STRICTLY ORDERED) --------------------
  # step 1: apt §3.3 set + user + network services
  inst_plan_run guest 'apt-get update'
  # H-02: microcode resolved HOST-side and emitted as a literal — in-chroot
  # detection provably no-ops (no /proc in the chroot)
  inst_plan_run guest "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $(install_package_list) $(inst_microcode_pkgs)"
  inst_plan_run guest "useradd -m -s /bin/bash $_im_user"
  # §3.3: the admin user is created WITH its sudo grant
  inst_plan_run guest "usermod -aG sudo $_im_user"
  inst_plan_run guest "passwd $_im_user # interactive password prompt"
  inst_plan_run guest 'systemctl enable systemd-networkd.service systemd-resolved.service'
  # step 2: pending baseline written ON-TARGET via the baseline writer
  inst_plan_run host "inst_baseline_pending_write $_im_mnt"
  # step 3: platform-key ceremony — PK/KEK/db + release.pem generated on the
  # encrypted root (ADR-18) by the custody flow (CLI invoked in-chroot)
  inst_plan_run guest '/opt/debian-fde/bin/debian-fde provision stage1 --mode in-chroot --keydir /etc/debian-fde/keys'
  # step 4: NVRAM enrollment db → KEK → PK (last) via the bind-mounted
  # efivars (SetupMode was gate-checked host-side in preflight)
  inst_plan_run guest 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/debian-fde/keys'
  # ESP layout for the in-chroot build (systemd-boot binaries from the apt
  # transaction; ukictl build signs them, §9.1 step 5)
  inst_plan_run guest 'bootctl install --esp-path=/efi --boot-path=/efi'
  # step 5: signed boot manager + initial UKI (baseline pending ⇒ enrollment
  # skipped by the state gate — kernel updates are TPM-free either way)
  inst_plan_run guest '/opt/debian-fde/bin/debian-fde ukictl build'
  # step 6: release.pem encrypted at rest before the reboot (ADR-18, I4)
  inst_plan_run guest 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/keys.sh && keys_encrypt_release /etc/debian-fde/keys'
  # step 7: kernel hooks (flat templates → run-parts destinations, §8.3)
  inst_plan_run host "mkdir -p $_im_mnt/etc/kernel/postinst.d $_im_mnt/etc/kernel/postrm.d $_im_mnt/etc/initramfs/post-update.d && cp $_im_hooks/postinst.d-zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde && cp $_im_hooks/postrm.d-zz-debian-fde $_im_mnt/etc/kernel/postrm.d/zz-debian-fde && cp $_im_hooks/systemd-boot-upgrade-zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade && cp $_im_hooks/post-update.d-zz-debian-fde $_im_mnt/etc/initramfs/post-update.d/zz-debian-fde && chmod +x $_im_mnt/etc/kernel/postinst.d/zz-debian-fde $_im_mnt/etc/kernel/postrm.d/zz-debian-fde $_im_mnt/etc/kernel/postinst.d/zz-debian-fde-systemd-boot-upgrade $_im_mnt/etc/initramfs/post-update.d/zz-debian-fde"
  # §8.4: resolve the ESP PARTUUID into fstab + target metadata on the
  # on-target pending baseline (luks_uuid = primary; member_uuids additive)
  if [ "$_im_topology" = "raid1" ]; then
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid $_im_members_uuids"
  else
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid"
  fi
  # step 8: ceremony state machine — `installed` (reboot → BIOS → finalize)
  inst_plan_run host "inst_state_write installed"
  inst_plan_run guest 'printf "debian-fde: first boot finalizes trust (§9.1): unlock with the recovery passphrase — the finalize service verifies Secure Boot ON, captures the baseline (audit --init) and enrolls the TPM\n" >> /etc/issue'

  # --- 8. OsIndications bit 0 → teardown → reboot (§9.1 teardown) -----------
  inst_plan_run host "fw_osindications_set $(fw_efivars_dir)"
  inst_plan_run host "umount $_im_mnt/dev $_im_mnt/sys $_im_mnt/proc $_im_mnt/sys/firmware/efi/efivars && umount -R $_im_mnt && $_im_close"

  if [ "$_im_no_reboot" = "0" ] && [ "${DEBIAN_FDE_INSTALL_NO_REBOOT:-}" != "1" ]; then
    inst_plan_run host 'reboot # §9.1: next boot enters BIOS setup — toggle Secure Boot ON'
  else
    info "install: reboot suppressed (DEBIAN_FDE_INSTALL_NO_REBOOT/--no-reboot) — CI seam"
  fi

  if [ "$(inst_runner)" != "dry-run" ]; then
    inst_execute_plan
    trap - EXIT
    rm -f "$_im_lukskey" 2>/dev/null
    printf 'debian-fde: install complete — the machine reboots into BIOS setup: toggle Secure Boot ON; the first boot finalizes (§9.1)\n' >&2
  else
    printf 'debian-fde: dry-run plan complete (%s) — execute with DEBIAN_FDE_INSTALL_RUNNER=chroot + --yes (§9.1)\n' "$(inst_runner)" >&2
  fi
  return 0
}
