#!/bin/sh
# install.sh — `alpine-fde install`: fully automated unattended Stage-1
# install (§9.1/ADR-20): partition + block layer, LUKS2 keyslot 0 formatted
# with the internal ephemeral install key (never persisted, I1), minimal
# Alpine rootfs (§3.3 apk populate), and the in-chroot provisioning ceremony
# ending in a provisional TPM token (PCR 11 only) + direct reboot to disk.
#
# TOPOLOGIES (§4.1):
#   single       --disk DISK                       ESP p1 + LUKS2 p2, Btrfs
#   bcache       --disk BACKING --bcache CACHE     ESP p1 + cache p2 on CACHE,
#                                                  backing p1 on BACKING,
#                                                  /dev/bcache0 under LUKS2,
#                                                  writethrough pinned (ADR-17)
#   bcache-multi --disk D1 --disk D2 --bcache C    shared cache set on C p2,
#                                                  backing p1 per disk, ONE
#                                                  independent LUKS2 container
#                                                  per /dev/bcacheN, btrfs
#                                                  raid1 pool across members,
#                                                  ESP only on the cache dev
#   raid1        --disk D1 --disk D2 [--disk Dn]   D1: ESP p1 + LUKS p2;
#                                                  Dn: LUKS p1 only;
#                                                  mkfs.btrfs -d raid1 -m raid1
#
# SLOT CONTRACT (ADR-20 keyslot choreography, §8.1 finalize row; consumed by
# finalize's slot discovery — NO marker is ever written to disk):
#   keyslot 0 = internal ephemeral install key (luksFormat --key-slot 0)
#   keyslot 1 = provisional token slot (Mechanism B, PCR 11 only)
# finalize adds the operator recovery passphrase to the NEXT FREE keyslot
# (authorized by the handed-over ephemeral key) and then kills keyslot 0 (the
# ephemeral slot) on EVERY member container — leaving exactly ONE passphrase
# slot beyond the token-referenced slots (the recovery slot).
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
# record (CI seam): the plan ends after teardown + ephemeral-key scrub.

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

# firmware seam (fw_sb_state/fw_var_present/fw_efivars_dir — the §9.1
# Setup Mode preflight gate; the OsIndications firmware trip is RETIRED,
# ADR-20 Teardown & Direct Reboot)
if [ -z "${DEBIAN_FDE_FIRMWARE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../firmware.sh"
fi

SPC_INSTALL_RUNNERS='dry-run chroot qemu'

inst_runner() { printf '%s\n' "${DEBIAN_FDE_INSTALL_RUNNER:-dry-run}"; }
inst_mnt() { printf '%s\n' "${DEBIAN_FDE_INSTALL_MNT:-/mnt}"; }
inst_mirror() { printf '%s\n' "${DEBIAN_FDE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/v3.24/main}"; }
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

# inst_repo_lines — the /etc/apk/repositories drop (§3.3): the configured
# mirror (main component) plus its community twin (same URL stem).
inst_repo_lines() {
  _irl_m=$(inst_mirror)
  printf '%s\n' "$_irl_m" "${_irl_m%/main}/community"
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

# the self-contained FDE tree (parent of lib/) — hooks/ + bin/ live here
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
Usage: alpine-fde install --disk DEVICE [--disk DEVICE2 ...] [--fs btrfs|ext4]
                          [--bcache CACHE_DEV] [--no-reboot] [--yes]

Fully automated unattended Stage-1 install (§9.1/ADR-20): firmware Setup Mode
gate (SetupMode=1 required — clear the vendor PK in BIOS first), partition +
block layer, LUKS2 keyslot 0 formatted with the INTERNAL EPHEMERAL INSTALL
KEY (openssl rand, >=256-bit, staged on tmpfs mode 0600, scrubbed at
teardown — the operator is NEVER prompted during install; the recovery
passphrase and the §13 entropy floor move to `finalize`), a
Btrfs root with subvolumes @/@home/@snapshots (default; --fs ext4 gives a
flat ext4 root), apk populate of a minimal Alpine base (§3.3: apk add --root
<mnt> --initdb alpine-base, one in-chroot apk additions transaction),
repositories/network config, then the in-chroot provisioning sequence
(§9.1 steps 1-9): additions set, user account, pending baseline,
platform-key ceremony, firmware NVRAM enrollment db -> KEK -> PK, bootctl
install + signed boot manager and UKI via `ukictl build`, PROVISIONAL TPM
token sealed into keyslot 1 (Mechanism B, PCR 11 only, from the UKI's
.pcrsig), unfinalized MOTD/issue banner, install-state=installed — then
teardown (unmount + ephemeral-key scrub) and a direct reboot to disk (no
firmware trip): enable Secure Boot and run `alpine-fde finalize` at first
login.

Topologies (§4.1): --disk repeatable for Btrfs RAID1 (primary ESP+LUKS,
secondaries LUKS only); --bcache CACHE_DEV for hybrid acceleration (ESP+cache
on the cache dev, LUKS2 on /dev/bcache0, writethrough pinned); --bcache with
MULTIPLE --disk: shared cache set, one independent LUKS2 container per
/dev/bcacheN, Btrfs RAID1 pool across the members, ESP only on the cache dev.
--fs ext4 is single-disk only.

Runner (DEBIAN_FDE_INSTALL_RUNNER): dry-run (default) prints the plan;
chroot executes (root, live ISO, --yes required); qemu emits a guest script.
Env: DEBIAN_FDE_ESP_SIZE (default 512M), DEBIAN_FDE_MIRROR,
DEBIAN_FDE_INSTALL_MNT, DEBIAN_FDE_INSTALL_USER, DEBIAN_FDE_DISKS
(dispatcher-provided disk list), DEBIAN_FDE_TMPDIR (ephemeral-key staging
seam, default /dev/shm).
EOF
}

# inst_part DEV N — partition device name (p-suffix after a digit-ending disk)
inst_part() {
  case $1 in
  *[0-9]) printf '%sp%s\n' "$1" "$2" ;;
  *) printf '%s%s\n' "$1" "$2" ;;
  esac
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
# Config drops execute IN PLAN ORDER (§3.3: after mount + apk populate,
# before the first in-guest apk use): the chroot runner defers them as host
# plan records (eager writes would land before the target is mounted, G-I1);
# dry-run prints them; qemu emits guest printf lines.
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
    # interactive prompts never eat plan lines
    _ie_plan=$(mktemp "${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}/debian-fde-plan.XXXXXX")
    printf '%s' "$SPC_PLAN" >"$_ie_plan"
    # L-04a + WR-02: a die mid-plan must leave NOTHING behind — one
    # combined EXIT trap scrubs the plan file AND the staged ephemeral
    # key-file, then tears the H-02 binds down best-effort (never
    # masking the real exit code; skipped when we died before the
    # mountpoint was even resolved)
    trap '
                rm -f "$_ie_plan" "${_ime_kf:-}" 2>/dev/null
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
        # L-04b: strip the legacy passphrase variable at the boundary —
        # chroot(1) passes the parent environment to the guest (the
        # unattended flow stages no operator passphrase at all; the
        # strip stays as defense against stale operator environments)
        chroot "$(inst_mnt)" /usr/bin/env -u DEBIAN_FDE_DISK_PASSPHRASE /bin/sh -c "$_ie_cmd" ||
          die "install: guest step failed: $_ie_cmd"
      fi
    done 3<"$_ie_plan"
    trap - EXIT
    rm -f "$_ie_plan"
    ;;
  qemu)
    _ie_out=${DEBIAN_FDE_INSTALL_SCRIPT:-/tmp/alpine-fde-install-guest.sh}
    {
      printf '#!/bin/sh\n# alpine-fde install — guest-side plan (generated; runner=qemu)\n# Host-side steps are comments; the CI harness executes them itself.\nset -eu\n'
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
    printf 'alpine-fde: guest install script written: %s\n' "$_ie_out" >&2
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
# rides additively in target.member_uuids (space-separated; RAID1/multi-bcache
# consumers enroll/audit per member later).
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
# The §3.3 explicit additions (Alpine): one in-chroot `apk add --no-cache`
# transaction. Topology-conditional: btrfs-progs by default, e2fsprogs for
# --fs ext4, bcache-tools when --bcache is given.
install_package_list() {
  _ipl='cryptsetup systemd-boot systemd-efistub ukify linux-lts tpm2-tools tpm2-tss-policy tpm2-tss-tcti-device sbsigntool openssl jq'
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

# inst_preflight DISKS... — fail-closed checks for a real run. ORDER IS
# NORMATIVE (§9.1): the firmware Setup Mode gate FIRST (zero disk mutation
# before it), then environment/tool checks.
inst_preflight() {
  inst_setupmode_gate
  [ "$(id -u)" = "0" ] || die "install: must run as root (live ISO environment)"
  for _if_disk in "$@"; do
    [ -b "$_if_disk" ] || [ -f "$_if_disk" ] || die "install: target disk not found: $_if_disk"
  done
  # hooks/ ships the Alpine layout (ADR-13/ADR-19, G-C16): kernel-hooks.d
  # build/remove hooks → /etc/kernel-hooks.d/, the mkinitfs unseal hook +
  # features.d entry → /etc/mkinitfs/, the apk trigger → /etc/apk/triggers/,
  # and the first-boot finalize ADVISORY oneshot → /etc/init.d/ (ADR-20
  # Stage 3: `finalize` itself is a GUIDED command — the boot artifact only
  # advises, it never runs it)
  for _if_h in kernel-hooks.d/alpine-fde-build.hook \
    kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    apk/triggers/alpine-fde.trigger openrc/alpine-fde-finalize; do
    [ -f "$(inst_hooks_dir)/$_if_h" ] || die "install: hook template missing: $(inst_hooks_dir)/$_if_h"
  done
  # §13 host tool set — topology-conditional. apk populates the rootfs;
  # openssl generates the ephemeral install key; sbsign/ukify are NOT
  # host-required (the boot manager + UKI are built + signed IN-CHROOT by
  # ukictl build, §9.1 step 5).
  require_pkgs apk:apk-tools sfdisk:util-linux cryptsetup:cryptsetup \
    mkfs.vfat:dosfstools lsblk:util-linux openssl:openssl
  case $(inst_root_fs) in
  ext4) require_pkgs mkfs.ext4:e2fsprogs ;;
  *) require_pkgs mkfs.btrfs:btrfs-progs ;;
  esac
  if [ "$(inst_bcache)" = "1" ]; then
    require_pkgs make-bcache:bcache-tools
  fi
  return 0
}

# inst_stage_ephemeral_key — G-C23 (§9.1 Stage 1 LUKS2 creation, ADR-20):
# generate the INTERNAL EPHEMERAL INSTALL KEY (openssl rand, 256-bit hex) and
# stage it under the tmpfs seam (${DEBIAN_FDE_TMPDIR:-/dev/shm}), mode 0600.
# The key is the ONLY credential of keyslot 0 between luksFormat and finalize:
# it drives luksFormat --key-slot 0 and every `cryptsetup open` via --key-file
# (the existing key-file staging machinery), and the provisional enrollment's
# luksAddKey authorization. The operator is NEVER prompted; the §13 recovery
# passphrase + entropy floor move to `finalize` (Stage 3). I1: the key NEVER
# persists — scrubbed by the explicit teardown plan record and on ANY exit
# path by the EXIT trap armed here (BR-01: callers MUST invoke this DIRECTLY
# in the main shell — inst_execute_plan's combined L-04a/WR-02 trap replaces
# it mid-plan and keeps scrubbing via the ${_ime_kf:-} carrier).
# Sets the global _IME_KEYFILE (empty for dry-run: nothing staged).
inst_stage_ephemeral_key() {
  _IME_KEYFILE=''
  if [ "$(inst_runner)" = "dry-run" ]; then
    return 0
  fi
  _ime_dir=${DEBIAN_FDE_TMPDIR:-/dev/shm}
  _IME_KEYFILE=$(mktemp "$_ime_dir/debian-fde-ephkey.XXXXXX") ||
    die "install: cannot stage the ephemeral install key ($_ime_dir usable?)"
  chmod 600 "$_IME_KEYFILE"
  if ! openssl rand -hex 32 | tr -d '\n' >"$_IME_KEYFILE"; then
    rm -f "$_IME_KEYFILE"
    die "install: generating the ephemeral install key failed"
  fi
  _ime_len=$(wc -c <"$_IME_KEYFILE" | tr -d '[:space:]')
  [ "$_ime_len" = "64" ] || {
    rm -f "$_IME_KEYFILE"
    die "install: staged ephemeral key has unexpected length ($_ime_len) — refusing"
  }
  # scrub on any exit path; cleared after a successful execute. THIS shell:
  # inst_execute_plan's combined L-04a/WR-02 trap replaces it mid-plan, and
  # the `${_ime_kf:-}` in that trap only expands to this key-file because we
  # never left this shell (BR-01).
  _ime_kf=$_IME_KEYFILE
  trap 'rm -f "$_ime_kf" 2>/dev/null' EXIT
  info "install: ephemeral install key staged ($_IME_KEYFILE, mode 0600, 256-bit) — never persisted (I1)"
  return 0
}

# G-C25 (§9.1 step 8): the unfinalized warning banner dropped to /etc/motd AND
# /etc/issue on the target is the SHARED SINGLE-SOURCE line from
# lib/install-state.sh (fde_motd_banner — consumed below at step 8 and stripped
# line-exactly by finalize's fde_motd_strip). Exactly ONE banner definition
# exists in the tree; install writes it, finalize strips it.

# inst_provisional_enroll_line EPHEMERAL_KEYFILE MAPPER_NAME... — G-C24
# (§9.1 step 6): the single-line GUEST command performing the provisional TPM
# enrollment per member container, mirroring the lib guest-line pattern
# (export cmd-dir; source the libs; call the seal contract). Mechanics:
#   1. extract the .pcrsig from the just-built UKI (stage-1 `ukictl build`
#      output on the ESP; objcopy section extraction, pcrsign contract)
#   2. per member: seal_provisional (Mechanism B, PCR 11 only) -> token JSON;
#      luksAddKey the sealed random passphrase into the token keyslot
#      (slot contract: keyslot 0 = ephemeral install key, keyslot 1 =
#      provisional token — token_free_slot returns 1 on the fresh container),
#      authorized by the staged ephemeral key; then token_import
inst_provisional_enroll_line() {
  _pel_key=$1
  shift
  _pel_ms=''
  for _pel_m in "$@"; do
    _pel_ms="$_pel_ms $_pel_m"
  done
  _pel_ms=${_pel_ms# }
  printf '%s\n' "export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && objcopy -O binary --only-section=.pcrsig \"\$(ls /efi/EFI/Linux/alpine-fde-*.efi | head -n 1)\" /run/alpine-fde/pcrsig.json && for m in $_pel_ms; do seal_provisional /etc/alpine-fde/keys /dev/mapper/\$m /run/alpine-fde/pcrsig.json /run/alpine-fde/token-\$m.json && token_add_keyslot /dev/mapper/\$m \"\$SEAL_PASS_FILE\" \"\$SEAL_SLOT\" $_pel_key && token_import /dev/mapper/\$m /run/alpine-fde/token-\$m.json \"\$(token_next_id /dev/mapper/\$m)\" || exit 1; done && rm -rf /run/alpine-fde # ADR-20 step 6: provisional Mechanism B seal (PCR 11) -> keyslot 1"
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

# inst_state_write STATE — §9.1 Stage-1 step 9: record the ceremony state
# machine (installed → provisional-booted → finalized) in
# <mnt>/etc/debian-fde/install-state.json. Consumes the install-state module's
# istate_write STATE (target root via DEBIAN_FDE_ROOT, atomic write); if the
# module is not landed, the additive documented schema is written in place.
# NOTE (§9.1): install writes only `installed` — the `provisional-booted`
# middle state is written by the first-boot finalize service (Stage 2).
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
  if [ "$INST_ROOT_FS" = "ext4" ] && [ "$_im_n" -gt 1 ]; then
    die -r "$DEBIAN_FDE_USAGE" "install: --fs ext4 is single-disk only — multi-disk root requires Btrfs RAID1"
  fi
  case $(inst_user) in
  '' | [-]* | *[!a-zA-Z0-9_.-]*)
    die -r "$DEBIAN_FDE_USAGE" "install: invalid --user '$(inst_user)' (allowed: letters, digits, '.', '_', '-')"
    ;;
  esac
  inst_shell_safe 'DEBIAN_FDE_INSTALL_MNT' "$(inst_mnt)"
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
    if [ "$_im_n" -ge 2 ]; then
      _im_topology=bcache-multi
    else
      _im_topology=bcache
    fi
  elif [ "$_im_n" -ge 2 ]; then
    _im_topology=raid1
  fi

  # per-role devices (§4.1). Multi-member topologies (raid1, bcache-multi)
  # accumulate the member LUKS devices, mapper paths, mapper NAMES (the
  # provisional-seal loop input) and container uuids; the PRIMARY member is
  # always member 1.
  set -- $_im_disks
  _im_disk=$1
  _im_esp=$(inst_part "$_im_disk" 1)
  _im_luks=$(inst_part "$_im_disk" 2)
  _im_mapper=/dev/mapper/root-crypt
  _im_mapper_names=root-crypt
  _im_close='cryptsetup close root-crypt'
  _im_members_devs=''
  _im_members_mappers=''
  _im_members_names=''
  _im_members_uuids=''
  if [ "$_im_topology" = "bcache" ]; then
    _im_esp=$(inst_part "$_im_bcache" 1)
    _im_cache=$(inst_part "$_im_bcache" 2)
    _im_backing=$(inst_part "$_im_disk" 1)
    _im_luks=/dev/bcache0
  elif [ "$_im_topology" = "bcache-multi" ]; then
    # G-C27/§4.1 topology 4: shared cache set; one LUKS2 container per
    # /dev/bcacheN; primary member (bcache0) = root1
    _im_esp=$(inst_part "$_im_bcache" 1)
    _im_cache=$(inst_part "$_im_bcache" 2)
    _im_luks=/dev/bcache0
    _im_mapper=/dev/mapper/root1
    _im_mapper_names=root1
    _im_close='cryptsetup close root1'
    _im_i=1
    for _im_d in $_im_disks; do
      [ "$_im_i" -eq 1 ] && {
        _im_i=2
        continue
      }
      _im_mu=$(cat /proc/sys/kernel/random/uuid 2>/dev/null) || _im_mu="<luks-uuid-$_im_i>"
      _im_members_devs="$_im_members_devs /dev/bcache$((_im_i - 1))"
      _im_members_mappers="$_im_members_mappers /dev/mapper/root$_im_i"
      _im_members_names="$_im_members_names root$_im_i"
      _im_members_uuids="$_im_members_uuids $_im_mu"
      _im_close="$_im_close && cryptsetup close root$_im_i"
      _im_i=$((_im_i + 1))
    done
    _im_members_devs=${_im_members_devs# }
    _im_members_mappers=${_im_members_mappers# }
    _im_members_names=${_im_members_names# }
    _im_members_uuids=${_im_members_uuids# }
  elif [ "$_im_topology" = "raid1" ]; then
    _im_mapper=/dev/mapper/root1
    _im_mapper_names=root1
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
      _im_members_names="$_im_members_names root$_im_i"
      _im_members_uuids="$_im_members_uuids $_im_mu"
      _im_close="$_im_close && cryptsetup close root$_im_i"
      _im_i=$((_im_i + 1))
    done
    _im_members_devs=${_im_members_devs# }
    _im_members_mappers=${_im_members_mappers# }
    _im_members_names=${_im_members_names# }
    _im_members_uuids=${_im_members_uuids# }
  fi

  info "install plan: topology=$_im_topology fs=$(inst_root_fs) disks=$_im_disks esp=$_im_esp luks=$_im_luks mnt=$_im_mnt runner=$(inst_runner)"

  # --- 0. G-C23/ADR-20: ephemeral install key staged BEFORE any destructive
  #     step. Unattended: NO operator prompt, NO passphrase env consumption
  #     (the §13 recovery passphrase + floor moved to finalize). BR-01:
  #     DIRECT call (no command substitution) — the stager arms the key-file
  #     scrub trap in THIS shell.
  inst_stage_ephemeral_key || die "install: cannot stage the ephemeral install key"
  _im_lukskey=$_IME_KEYFILE
  _im_keyfile_arg=''
  [ -n "$_im_lukskey" ] && _im_keyfile_arg="--key-file $_im_lukskey"
  # plan-level display path: the real staged path (dry-run: literal
  # placeholder — nothing is staged, nothing persists)
  _im_lukskey_disp=${_im_lukskey:-'<ephemeral-keyfile>'}

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
  bcache-multi)
    # G-C27/§4.1 topology 4 (18f1213): ESP p1 + SHARED cache set p2 on the
    # fast dev; EACH backing disk partitioned into a backing set (p1); every
    # backing device registered (/dev/bcache0, /dev/bcache1, ...) and
    # attached to the shared cset UUID, writethrough pinned.
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    for _im_d in $_im_disks; do
      inst_plan_run host "printf 'label: gpt\nstart=2048, type=linux, name=\"backing\"\n' | sfdisk $_im_d"
    done
    inst_plan_run host "make-bcache -C $_im_cache"
    for _im_d in $_im_disks; do
      inst_plan_run host "make-bcache -B $(inst_part "$_im_d" 1)"
    done
    _im_reg="echo $_im_cache > /sys/fs/bcache/register"
    for _im_d in $_im_disks; do
      _im_reg="$_im_reg && echo $(inst_part "$_im_d" 1) > /sys/fs/bcache/register"
    done
    inst_plan_run host "$_im_reg"
    _im_att=''
    _im_i=0
    for _im_d in $_im_disks; do
      _im_att="$_im_att && echo \"\$CSET_UUID\" > /sys/block/bcache$_im_i/bcache/attach && echo writethrough > /sys/block/bcache$_im_i/bcache/cache_mode"
      _im_i=$((_im_i + 1))
    done
    inst_plan_run host "CSET_UUID=\$(bcache-super-show $_im_cache | awk '/cset.uuid/ {print \$2}')$_im_att # writethrough pinned (ADR-17: crash-safe, ciphertext-only cache)"
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

  # --- 2. LUKS2 containers — G-C23: internal ephemeral install key, --------
  #     keyslot 0 (unattended; see the SLOT CONTRACT at the top of this file)
  inst_plan_run host "cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 --uuid $_im_uuid $_im_keyfile_arg $_im_luks # keyslot 0: ephemeral install key (unattended, ADR-20)"
  inst_plan_run host "cryptsetup open $_im_keyfile_arg $_im_luks root-crypt"
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
    # close/rename: primary mapper is root1 in multi-member topologies;
    # member luksFormat/open zipped with the uuids resolved in the layout
    # block — ONE independent LUKS2 container per member device (G-C27)
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
    if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
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

  # --- 4. minimal rootfs (§3.3): apk populate replaces debootstrap -----------
  inst_plan_run host "apk add --root $_im_mnt --initdb alpine-base"

  # --- 5. config drops (host-side writes; guest printf lines under qemu) -----
  # §3.3: /etc/apk/repositories replaces the apt sources + dpkg trims
  inst_plan_write /etc/apk/repositories $(inst_repo_lines)
  # §8.2 crypttab contract: single entry (single/bcache) has NO
  # password-cache; multi-member topologies (raid1, bcache-multi) get one
  # entry PER MEMBER with password-cache=yes.
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
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
  # §9.1 step 1: OpenRC networking (Alpine default: ifupdown-ng + udhcpc)
  inst_plan_write /etc/network/interfaces \
    'auto lo' \
    'iface lo inet loopback' \
    '' \
    'auto eth0' \
    'iface eth0 inet dhcp'
  # §3.3 trims: dracut-era initrd pins are dropped verbatim (the target
  # initramfs generator seam consumes ROOT_FS/BCACHE from the conf below)
  inst_plan_write /etc/dracut.conf.d/10-debian-fde.conf \
    'hostonly=yes' \
    'hostonly_cmdline=no' \
    'omit_dracutmodules+=" crypt "'
  if [ "$(inst_bcache)" = "1" ]; then
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
  # H-02: the freshly populated chroot has no /proc /sys /dev — bind them
  # before the first guest step so the in-chroot ceremony behaves. §9.1 also
  # binds the efivars so the in-chroot NVRAM enrollment reaches the live
  # firmware.
  inst_plan_run host "mkdir -p $_im_mnt/proc $_im_mnt/sys $_im_mnt/dev && mount -t proc proc $_im_mnt/proc && mount --bind /sys $_im_mnt/sys && mount --bind /dev $_im_mnt/dev"
  inst_plan_run host "mkdir -p $_im_mnt/sys/firmware/efi/efivars && mount --bind /sys/firmware/efi/efivars $_im_mnt/sys/firmware/efi/efivars"

  # --- 6. tooling copy (host) — the in-chroot CLI lives at /opt/debian-fde ---
  info "tooling copy: product script tree only (bin lib hooks docs) — VCS/harness residue excluded (§3.3)"
  inst_plan_run host "$(inst_tooling_copy_cmd "$_im_tree" "$_im_mnt")"
  # G-U7: the boot-manager self-update service is masked — ESP binaries are
  # only ever written by our SIGNED flow (§8.3)
  inst_plan_run host "mkdir -p $_im_mnt/etc/systemd/system && ln -sf /dev/null $_im_mnt/etc/systemd/system/systemd-boot-update.service"

  # --- 7. in-chroot provisioning (§9.1 steps 1-9, STRICTLY ORDERED) ----------
  # step 1: apk §3.3 additions set (one --no-cache transaction), user account
  # (ADR-20 zero-touch: created with a LOCKED password — credentials are the
  # operator's business at first login; no interactive passwd step exists),
  # and OpenRC networking.
  inst_plan_run guest "apk add --no-cache $(install_package_list)"
  inst_plan_run guest "adduser -D -s /bin/ash $_im_user && addgroup $_im_user wheel"
  inst_plan_run guest 'rc-update add networking boot'
  # step 2: pending baseline written ON-TARGET via the baseline writer
  inst_plan_run host "inst_baseline_pending_write $_im_mnt"
  # step 3: platform-key ceremony — PK/KEK/db + release.pem generated on the
  # encrypted root (ADR-18) by the custody flow (CLI invoked in-chroot)
  inst_plan_run guest '/opt/debian-fde/bin/debian-fde provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys'
  # step 4: NVRAM enrollment db → KEK → PK (last) via the bind-mounted
  # efivars (SetupMode was gate-checked host-side in preflight)
  inst_plan_run guest 'export DEBIAN_FDE_CMD_DIR=/opt/debian-fde/lib/cmd; . /opt/debian-fde/lib/common.sh && . /opt/debian-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys'
  # ESP layout for the in-chroot build (systemd-boot binaries from the apk
  # transaction; ukictl build signs them, §9.1 step 5)
  inst_plan_run guest 'bootctl install --esp-path=/efi --boot-path=/efi'
  # step 5: signed boot manager + initial UKI (baseline pending ⇒ the build's
  # ensure-once enrollment is state-gated OFF — the PROVISIONAL seal below
  # is the only enrollment of Stage 1)
  inst_plan_run guest '/opt/debian-fde/bin/debian-fde ukictl build'
  # step 6: PROVISIONAL TPM enrollment (G-C24) — Mechanism B, PCR 11 only,
  # .pcrsig from the just-built UKI; keyslot 1 per member container
  inst_plan_run guest "$(inst_provisional_enroll_line "$_im_lukskey_disp" $_im_mapper_names $_im_members_names)"
  # step 7: hooks + trigger + first-boot finalize advisory (§9.1 step 7;
  # ADR-13/ADR-19/ADR-20, G-C16 Alpine layout — flat templates copied to
  # their run-parts destinations; the advisory oneshot ships to /etc/init.d/
  # and is enabled for the default runlevel. ADR-20 Stage 3: `finalize` is a
  # GUIDED command — the boot artifact NEVER runs it, it only advises.)
  inst_plan_run host "mkdir -p $_im_mnt/etc/kernel-hooks.d $_im_mnt/etc/mkinitfs/features.d $_im_mnt/etc/apk/triggers $_im_mnt/etc/init.d && cp $_im_hooks/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook && cp $_im_hooks/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook && cp $_im_hooks/mkinitfs/alpine-fde-unseal.sh $_im_mnt/etc/mkinitfs/alpine-fde-unseal.sh && cp $_im_hooks/mkinitfs/features.d/alpine-fde.files $_im_mnt/etc/mkinitfs/features.d/alpine-fde.files && cp $_im_hooks/apk/triggers/alpine-fde.trigger $_im_mnt/etc/apk/triggers/alpine-fde.trigger && cp $_im_hooks/openrc/alpine-fde-finalize $_im_mnt/etc/init.d/alpine-fde-finalize && chmod +x $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/etc/mkinitfs/alpine-fde-unseal.sh $_im_mnt/etc/apk/triggers/alpine-fde.trigger $_im_mnt/etc/init.d/alpine-fde-finalize"
  inst_plan_run guest 'rc-update add alpine-fde-finalize default'
  # §8.4: resolve the ESP PARTUUID into fstab + target metadata on the
  # on-target pending baseline (luks_uuid = primary; member_uuids additive)
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid $_im_members_uuids"
  else
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid"
  fi
  # step 8 (G-C25): unfinalized warning banner to /etc/motd AND /etc/issue —
  # the shared single-source line (fde_motd_banner, lib/install-state.sh;
  # fail closed if the module did not load). The banner is expanded LINE BY
  # LINE into separate plan-write args — the plan file is line-oriented, so
  # embedded newlines would corrupt it (the shared banner is exactly one line).
  command -v fde_motd_banner >/dev/null 2>&1 ||
    die "install: banner helper fde_motd_banner missing (lib/install-state.sh not loaded?)"
  set --
  while IFS= read -r _im_bl; do
    set -- "$@" "$_im_bl"
  done <<EOF
$(fde_motd_banner)
EOF
  inst_plan_write /etc/motd "$@"
  inst_plan_write /etc/issue "$@"
  # step 9 (G-C28): ceremony state machine — `installed` (AFTER the banner;
  # the provisional-booted middle state is written by the first-boot service)
  inst_plan_run host "inst_state_write installed"

  # --- 8. teardown + scrub + DIRECT reboot (§9.1 Teardown; G-C26) -----------
  # The OsIndications bit-0 write / reboot-into-BIOS-setup firmware trip is
  # RETIRED (ADR-20): the plan ends with unmount, container close, the
  # explicit ephemeral-key scrub (I1), and a plain reboot to disk.
  inst_plan_run host "umount $_im_mnt/dev $_im_mnt/sys $_im_mnt/proc $_im_mnt/sys/firmware/efi/efivars && umount -R $_im_mnt && $_im_close"
  inst_plan_run host "rm -f $_im_lukskey_disp # I1: ephemeral install key scrubbed (§9.1 teardown)"

  if [ "$_im_no_reboot" = "0" ] && [ "${DEBIAN_FDE_INSTALL_NO_REBOOT:-}" != "1" ]; then
    inst_plan_run host 'reboot # §9.1: direct reboot to disk (ADR-20)'
  else
    info "install: reboot suppressed (DEBIAN_FDE_INSTALL_NO_REBOOT/--no-reboot) — CI seam"
  fi

  if [ "$(inst_runner)" != "dry-run" ]; then
    inst_execute_plan
    trap - EXIT
    rm -f "$_im_lukskey" 2>/dev/null
    printf 'alpine-fde: install complete — direct reboot to disk; first boot unlocks via the provisional token; run `alpine-fde finalize` after enabling Secure Boot (§9.1/ADR-20)\n' >&2
  else
    printf 'alpine-fde: dry-run plan complete (%s) — execute with DEBIAN_FDE_INSTALL_RUNNER=chroot + --yes (§9.1)\n' "$(inst_runner)" >&2
  fi
  return 0
}
