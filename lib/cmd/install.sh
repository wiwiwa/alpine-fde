#!/bin/sh
# install.sh — `alpine-fde install`: fully automated unattended Stage-1
# install (§9.1/ADR-20): partition + block layer, LUKS2 keyslot 0 formatted
# with the internal ephemeral install key (never persisted, I1), minimal
# Alpine rootfs (§3.3 apk populate), and the in-chroot provisioning ceremony
# ending in a provisional TPM token (PCR 11 only) + a direct reboot to disk —
# or, when the firmware REFUSED NVRAM enrollment, the manual key-import
# instructions, an explicit Enter confirmation, and a reboot INTO FIRMWARE
# SETUP (OsIndications) instead.
#
# FLOW ORDER (user directives, real-server blocker #7): every MECHANICAL step
# that needs no ceremony secret (NVRAM enrollment, boot-manager file copy,
# hooks/metadata/state staging) runs BEFORE the credential ceremony;
# the ceremony (recovery -> account -> release-key prompts) is the LAST
# interactive section; only the secret-dependent UKI build + provisional seal
# + teardown + the final reboot tail follow it. The boot manager is installed
# by GUARDED FILE COPY (Alpine ships NO bootctl binary — real-server blocker
# #7), never by invoking bootctl.
#
# TOPOLOGIES (§4.1):
#   single       --disk DISK                       ESP p1 + LUKS2 p2, Btrfs
#   bcache       --disk BACKING --bcache CACHE     ESP p1 + cache p2 on CACHE,
#                                                  backing = WHOLE BACKING disk
#                                                  (bcache semantics: NO
#                                                  partition table on the
#                                                  backing dev),
#                                                  /dev/bcache0 under LUKS2,
#                                                  writethrough pinned (ADR-17)
#   bcache-multi --disk D1 --disk D2 --bcache C    shared cache set on C p2,
#                                                  backing = WHOLE disk per
#                                                  disk, ONE
#                                                  independent LUKS2 container
#                                                  per /dev/bcacheN, btrfs
#                                                  raid1 pool across members,
#                                                  ESP only on the cache dev
#   raid1        --disk D1 --disk D2 [--disk Dn]   D1: ESP p1 + LUKS p2;
#                                                  Dn: LUKS p1 only;
#                                                  mkfs.btrfs -d raid1 -m raid1
#
# SLOT CONTRACT (ADR-20 amended keyslot choreography, §7.2 keyslot table +
# §9.1; consumed by finalize's slot discovery — NO marker is ever written to
# the LUKS2 metadata beyond the documented keyslots):
#   keyslot 0 = the OPERATOR'S RECOVERY PASSPHRASE, enrolled in-chroot by the
#               §9.1 step 4 credential ceremony (luksAddKey --key-slot 0,
#               Argon2id, authorized by the staged ephemeral install key)
#   keyslot 1 = provisional token slot (Mechanism B, PCR 11 only; upgraded to
#               {PCR 7, PCR 11} by the §9.1 Stage 2/3 completion)
#   keyslot 2 = the internal ephemeral install key — a TEMPORARY keyslot
#               (luksFormat --key-slot 2), the ceremony's authorizing
#               credential while staged; PURGED at first-boot finalization
#               (§9.1 Stage 2 step 4). I1's two-keyslot at-rest state (0 + 1)
#               is reached exactly there.
#
# RUNNER SEAM (ALPINE_FDE_INSTALL_RUNNER) — default chroot (the product);
#   the seam exists for tests (dry-run plan capture) and CI (qemu emission):
#   chroot (default)   guided local install from the live ISO: host steps run
#                      now, guest steps run via `chroot <mnt> sh -c`
#   dry-run            print the complete action plan, execute nothing
#   qemu               emit the guest-side plan as a script for the CI harness
#                      (host steps emitted as comments) — no execution
#
# Plan steps are tagged host|guest; file drops into the target root are done
# host-side at $MNT (chroot) or emitted as guest printf lines (qemu).
#
# ALPINE_FDE_INSTALL_NO_REBOOT=1 (or --no-reboot) suppresses the final reboot
# records (CI seam): the plan ends after teardown + ephemeral-key scrub + the
# enrollment verdict + (deferred path) the manual-import instructions; the
# Enter-confirmation and the reboot records themselves are not emitted.

if [ -n "${ALPINE_FDE_INSTALL_LOADED:-}" ]; then
  return 0
fi
ALPINE_FDE_INSTALL_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

# The install ceremony state machine (§8.4 install-state.json) is owned by the
# install-state module; consume its API when landed (istate_write), else the
# additive documented schema is written in place (see inst_state_write).
if [ -z "${ALPINE_FDE_INSTALL_STATE_LOADED:-}" ]; then
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
if [ -z "${ALPINE_FDE_FIRMWARE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../firmware.sh"
fi

SPC_INSTALL_RUNNERS='dry-run chroot qemu'

inst_runner() { printf '%s\n' "${ALPINE_FDE_INSTALL_RUNNER:-chroot}"; }
inst_mnt() { printf '%s\n' "${ALPINE_FDE_INSTALL_MNT:-/mnt}"; }
# reset-record seams (unit-testable only; a real run never sets these): the
# device-mapper directory the reset records glob for stale rootN/root-crypt
# mappings, and the sysfs bcache root the reset records scan for live sets.
inst_mapper_dir() { printf '%s\n' "${ALPINE_FDE_INSTALL_MAPPER_DIR:-/dev/mapper}"; }
inst_bcache_sysfs() { printf '%s\n' "${ALPINE_FDE_INSTALL_BCACHE_SYSFS:-/sys/fs/bcache}"; }
inst_mirror() { printf '%s\n' "${ALPINE_FDE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/v3.24/main}"; }
# --- resolved topology (§4.1): fs + bcache flags ------------------------------
# ROOT_FS: btrfs (default) | ext4. BCACHE: 0 | 1. Recorded into the target's
# /etc/alpine-fde/alpine-fde.conf; an ABSENT conf file (or absent keys) means
# the built-in defaults ROOT_FS=btrfs, BCACHE=0 — consumers must not require
# the file to exist.
INST_ROOT_FS=${INST_ROOT_FS:-btrfs}
INST_BCACHE=${INST_BCACHE:-0}
# ESP mount point (§8.1 --esp flag; env ALPINE_FDE_ESP; default /efi). A path
# UNDER the target root — the flag value flows into the fstab entry, the mount
# plan, the persisted ESP_PATH (§8.4) and the UKI extraction path.
INST_ESP_MNT=${INST_ESP_MNT:-}

inst_root_fs() { printf '%s\n' "${INST_ROOT_FS:-btrfs}"; }
inst_bcache() { printf '%s\n' "${INST_BCACHE:-0}"; }
inst_esp_mnt() { printf '%s\n' "${INST_ESP_MNT:-/efi}"; }
# --- ESP sizing (§13): measured UKI size x retention + headroom ---------------
INST_ESP_RETENTION=3 # current + 2 retained UKIs (§9.3)
INST_ESP_HEADROOM_BYTES=$((64 * 1024 * 1024))
INST_ESP_DEFAULT=512M

# inst_uki_size_probe — byte size of a measurable UKI artifact (CI harness /
# re-install contexts set ALPINE_FDE_UKI_FILE); empty output = unmeasurable.
inst_uki_size_probe() {
  _ips_f=${ALPINE_FDE_UKI_FILE:-}
  if [ -n "$_ips_f" ] && [ -f "$_ips_f" ]; then
    wc -c <"$_ips_f" | tr -d '[:space:]'
  fi
  return 0
}

# inst_esp_size_compute MEASURED_BYTES RETENTION HEADROOM_BYTES — ESP size for
# the sfdisk plan: measured UKI size x retention + headroom, rounded UP to
# whole MiB. Unmeasurable (empty/non-numeric) or garbage inputs fall back to
# the fixed default (§13: override via ALPINE_FDE_ESP_SIZE wins regardless).
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
  if [ -n "${ALPINE_FDE_ESP_SIZE:-}" ]; then
    printf '%s\n' "$ALPINE_FDE_ESP_SIZE"
    return 0
  fi
  _ies_m=$(inst_uki_size_probe)
  inst_esp_size_compute "$_ies_m" "$INST_ESP_RETENTION" "$INST_ESP_HEADROOM_BYTES"
}
inst_user() { printf '%s\n' "${ALPINE_FDE_INSTALL_USER:-admin}"; }
# ADR-18/§8.1 provision row: the offline-ceremony artifact set `install
# --keydir` consumes from the signing medium — exactly what `provision
# stage1` leaves there (certs + ESLs + .auth packets + the release key).
# ALL are required: a half-stocked medium fails closed BEFORE any plan
# record exists (missing artifacts would only surface mid-ceremony).
INST_KEYDIR_ARTIFACTS='release.pem release.pub release.crt db.cert.der kek.cert.der pk.cert.der db.esl kek.esl pk.esl db.auth kek.auth pk.auth'

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
    die -r "$ALPINE_FDE_USAGE" "install: $_iss_label contains characters that are not allowed: $_iss_val"
    ;;
  esac
  return 0
}

# the self-contained FDE tree (parent of lib/) — hooks/ + bin/ live here
inst_tree() {
  _it_lib=$(sp_cmd_dir)
  printf '%s\n' "${_it_lib%/*/*}"
}
inst_hooks_dir() { printf '%s\n' "${ALPINE_FDE_HOOKS_DIR:-$(inst_tree)/hooks}"; }
sp_keydir() { printf '%s\n' "${ALPINE_FDE_KEYDIR:-}"; }

# inst_tooling_copy_cmd TREE MNT — the §8.1 self-contained tooling copy: ship
# ONLY the product script tree (bin/ lib/ hooks/ docs/) into <mnt>/opt/alpine-fde.
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
    _itc_mkdir="$_itc_mkdir $_itc_mnt/opt/alpine-fde/$_itc_d"
    _itc_cps="$_itc_cps && cp -r $_itc_tree/$_itc_d/. $_itc_mnt/opt/alpine-fde/$_itc_d/"
  done
  printf '%s%s && ln -sf /opt/alpine-fde/bin/alpine-fde %s/usr/local/bin/alpine-fde\n' \
    "$_itc_mkdir" "$_itc_cps" "$_itc_mnt"
  return 0
}

# inst_loader_binary [PREFIX] — print the first existing systemd-boot LOADER
# EFI binary under PREFIX (default: the live env root) at the known package
# paths, rc 1 when none exists. Real-server blocker #7: Alpine ships NO
# bootctl binary (pkgs.alpinelinux.org contents search: zero hits, even edge)
# — the in-chroot `apk add systemd-boot` transaction SUCCEEDS yet the retired
# `bootctl install` record died "/bin/sh: bootctl: not found" POST-ceremony.
# The boot manager is therefore installed by FILE COPY of the loader binary
# the systemd-boot package ships (inst_bootmgr_copy_line); this probe backs
# the fail-closed preflight check.
# inst_loader_probe_prefix — the PREFIX the live-env loader probe runs under
# (test seam, ALPINE_FDE_LOADER_PROBE_PREFIX; a real run probes '/' — empty).
# Like inst_mapper_dir: unit tests point it at a sandbox so the probe's
# live-env/apk-fetch branches are deterministic on any host.
inst_loader_probe_prefix() { printf '%s\n' "${ALPINE_FDE_LOADER_PROBE_PREFIX:-}"; }

inst_loader_binary() {
  _ilb_p=${1:-}
  for _ilb_c in \
    usr/share/systemd/bootctl/systemd-bootx64.efi \
    usr/lib/systemd/boot/efi/systemd-bootx64.efi; do
    if [ -f "$_ilb_p/$_ilb_c" ]; then
      printf '%s\n' "$_ilb_p/$_ilb_c"
      return 0
    fi
  done
  return 1
}

# inst_bootmgr_copy_line ESP_MNT — the single-line GUEST command installing the
# systemd-boot boot manager by GUARDED FILE COPY (real-server blocker #7 —
# never a bootctl invocation). Probes the known loader paths IN-CHROOT at
# execution time and fails closed (exit 1 kills the plan) naming the package
# when none exists; otherwise copies the loader to BOTH ESP homes:
#   <esp>/EFI/systemd/systemd-bootx64.efi — canonical path (the kernel hook
#       verifies/re-signs it on every later transaction; the audit manifest
#       pins it)
#   <esp>/EFI/BOOT/BOOTX64.EFI — removable-media fallback path: boots on any
#       firmware with NO NVRAM dependency (the harness fixtures already model
#       BOOTX64 as the default entry)
# The in-chroot build (ukictl build, §8.3) signs the binaries; the
# systemd-boot-update.service mask (§6) stays consistent with the retired
# bootctl flow. Run BEFORE the credential ceremony (no secret involved).
inst_bootmgr_copy_line() {
  _bcl_esp=$1
  printf '%s\n' "ldr=''; for p in /usr/share/systemd/bootctl/systemd-bootx64.efi /usr/lib/systemd/boot/efi/systemd-bootx64.efi; do [ -f \"\$p\" ] && { ldr=\"\$p\"; break; }; done; [ -n \"\$ldr\" ] || { echo 'alpine-fde: ERROR: no systemd-boot loader EFI binary found in-chroot (probed /usr/share/systemd/bootctl/systemd-bootx64.efi, /usr/lib/systemd/boot/efi/systemd-bootx64.efi) — the systemd-boot package is missing or incomplete; the boot manager cannot be installed; fix the mirror/package set and re-run (completed steps skip via crash resume)' >&2; exit 1; }; mkdir -p $_bcl_esp/EFI/systemd $_bcl_esp/EFI/BOOT && cp \"\$ldr\" $_bcl_esp/EFI/systemd/systemd-bootx64.efi && cp \"\$ldr\" $_bcl_esp/EFI/BOOT/BOOTX64.EFI && echo \"alpine-fde: info: boot manager installed by guarded file copy: \$ldr -> $_bcl_esp/EFI/systemd/systemd-bootx64.efi + $_bcl_esp/EFI/BOOT/BOOTX64.EFI (removable-media fallback path, no NVRAM dependency; signed by the in-chroot build, §8.3)\" # boot manager via guarded file copy of the systemd-boot loader binary (fail-closed probe; real-server blocker #7)"
}

install_usage() {
  cat >&2 <<'EOF'
Usage: alpine-fde install --disk DEVICE [--disk DEVICE2 ...] [--fs btrfs|ext4]
                          [--bcache CACHE_DEV] [--no-reboot] [--yes]

Unattended-until-reboot Stage-1 install (§9.1/ADR-20 amended; unattended
except for the §9.1 step 4 credential-ceremony prompts): firmware Setup
Mode gate (SetupMode=1 required — clear the vendor PK in BIOS first),
partition + block layer, LUKS2 formatted in the TEMPORARY keyslot 2 with the
INTERNAL EPHEMERAL INSTALL KEY (openssl rand, >=256-bit, staged on tmpfs
mode 0600, scrubbed at teardown; keyslot 0 is reserved for the recovery
passphrase, keyslot 1 for the provisional token — §7.2), a
Btrfs root with subvolumes @/@home/@snapshots (default; --fs ext4 gives a
flat ext4 root),
apk populate of a minimal Alpine base (§3.3: apk add --root <mnt> --initdb
alpine-base, one in-chroot apk additions transaction), repositories/network
config, then the in-chroot provisioning sequence (§9.1): additions set, user
account, pending baseline, platform-key ceremony, the INTERACTIVE CREDENTIAL
CEREMONY (§9.1 step 4 — exactly three no-echo prompts: the account password,
the LUKS2 recovery passphrase into keyslot 0 with the §13 entropy floor
enforced via re-prompt until met, and the release-key passphrase encrypting
release.pem via keys_encrypt_release; there is no flag and no environment
seam for any credential) — with EVERY mechanical step BEFORE the ceremony
(firmware NVRAM enrollment db -> KEK -> PK, the boot manager installed by
guarded file copy of the systemd-boot loader EFI binary to
<esp>/EFI/BOOT/BOOTX64.EFI — Alpine ships no bootctl binary —, hooks, target
metadata, install-state=installed) so the
credential ceremony sits LAST; only the secret-dependent steps follow it
(signed UKI + boot manager via `ukictl build`, PROVISIONAL TPM token sealed
into keyslot 1, Mechanism B, PCR 11 only, from the UKI's .pcrsig), then
teardown (unmount + ephemeral-key scrub) and: a direct reboot to disk when
NVRAM enrollment succeeded — or, when the firmware refused it (key material
staged to <esp>/alpine-fde-keys), the manual-import instructions, an explicit
Enter confirmation, and a reboot INTO FIRMWARE SETUP (OsIndications) for the
manual key import: the first boot unlocks via the provisional token and
alpine-fde-finalize AUTO-FINALIZES under Secure Boot (§9.1 Stage 2);
`alpine-fde finalize` is the guided/crash-resume entry point (Stage 3).

Topologies (§4.1): --disk repeatable for Btrfs RAID1 (primary ESP+LUKS,
secondaries LUKS only); --bcache CACHE_DEV for hybrid acceleration (ESP+cache
on the cache dev, LUKS2 on /dev/bcache0, writethrough pinned); --bcache with
MULTIPLE --disk: shared cache set, one independent LUKS2 container per
/dev/bcacheN, Btrfs RAID1 pool across the members, ESP only on the cache dev.
--fs ext4 is single-disk only.

Runner: chroot executes (default; root, live ISO, --yes required; the three
credential ceremony prompts are asked in the execution path). ALPINE_FDE_INSTALL_RUNNER
is a test/CI seam, not a user setting: dry-run prints the plan only (no
prompt, no secret); qemu emits a guest script (CI artifact job).
Env: ALPINE_FDE_ESP_SIZE (default 512M), ALPINE_FDE_MIRROR,
ALPINE_FDE_INSTALL_MNT, ALPINE_FDE_INSTALL_USER, ALPINE_FDE_DISKS
(dispatcher-provided disk list), ALPINE_FDE_TMPDIR (ephemeral-key staging
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

# inst_wipe_superblocks_line DEV — single-line host record: dd-zero the HEAD
# and the TAIL of DEV before it is handed to make-bcache. Real (previously
# used) disks carry stale filesystem/bcache/LUKS signatures; bcache REFUSES a
# device with a leftover signature, so the wipe is mandatory before
# `make-bcache`. dd (head + tail) is the deterministic choice — wipefs is not
# guaranteed in the installer env. The tail seek is derived at RUN time from
# `blockdev --getsize64` (the plan line is eval'd / sh -c'd, so the
# substitution stays literal in dry-run/qemu output); head and tail are `&&`-
# chained so a failed wipe aborts the plan instead of reaching make-bcache.
inst_wipe_superblocks_line() {
  printf '%s\n' "dd if=/dev/zero of=$1 bs=1M count=1 && dd if=/dev/zero of=$1 bs=1M count=1 seek=\$(( \$(blockdev --getsize64 $1) / 1048576 - 1 )) # wipe stale superblocks (head+tail): bcache refuses devices with leftover signatures"
}

# --- reset records (a previous FAILED attempt) -------------------------------
# A failed install leaves the target mounted under <mnt> (subvol mounts + the
# ESP), stale /dev/mapper/rootN|root-crypt mappings open, LUKS superblocks on
# the members and (bcache topologies) a LIVE bcache set claiming the devices;
# a re-run would die on the busy mount / busy mapper name / claimed device.
# User requirement: "install show reset failed installation status, when
# install restarts again, so that new install is able to continue" — the
# records below tear the stale state down BEFORE partitioning and SAY what
# they reset. The records are RUNTIME-conditional inside the record text
# (generate-time cannot know machine state): every probe is guarded with a
# one-line busybox/ash form so the records are NO-OPS on a pristine machine
# and survive BOTH the host `eval` path and the emitted guest script under
# the repo's set -eu norm (expected-nonzero probes are guarded, never bare;
# the `|| :` tails keep a failed teardown from killing the eval'd plan).
# WHY stop-then-wipe for bcache: echoing the set UUID into its own
# /sys/fs/bcache/<uuid>/stop RELEASES the backing devices — wiping a CLAIMED
# backing device leaves the in-kernel set diverged, and the stale set can
# re-register a device mid-install. The dd head+tail superblock wipe in front
# of make-bcache (7619960) then operates on a released device.

# inst_reset_umount_rec_line MNT — the PRIMARY mount teardown of the reset
# block (item 26d, user-directed): ONE guarded RECURSIVE `umount -R <mnt>` of
# the stale target tree. The retired fixed list (subvols + ESP + root) missed
# the stale chroot binds a mid-chroot death leaves behind (/mnt/proc,
# /mnt/sys, /mnt/dev, /mnt/sys/firmware/efi/efivars — created at the H-02
# block, removed only by the plan teardown). `umount -R` is an accepted
# dependency: the installer's own §9.1 teardown already relies on it.
# mountpoint probe + warn branch + `|| :` no-op tail, single line, ash/busybox
# compatible.
inst_reset_umount_rec_line() {
  printf '%s\n' "if mountpoint -q $1 2>/dev/null; then umount -R $1 && echo 'alpine-fde: info: reset: recursively unmounted stale target tree $1' || echo 'alpine-fde: warn: reset: could not recursively unmount stale target tree $1'; fi || :"
}

# inst_reset_mapper_line MAPPER_DIR — guarded cryptsetup close of the stale
# rootN mappings (glob — the bcache-multi/raid1 naming) AND root-crypt (the
# single/bcache primary); the mapper NAME is stripped from the node path
# before close. Unmatched glob entries fail the [ -e ] guard (no-op).
inst_reset_mapper_line() {
  printf '%s\n' "for m in $1/root[0-9]* $1/root-crypt; do [ -e \"\$m\" ] || continue; cryptsetup close \"\${m#$1/}\" && echo \"alpine-fde: info: reset: closed stale mapper \$m\" || echo \"alpine-fde: warn: reset: could not close stale mapper \$m\"; done || :"
}

# inst_reset_bcache_line SYSFS_BCACHE — guarded stop of every LIVE bcache
# set: the glob matches set DIRECTORIES only (the `register` control file is
# skipped); each set's own UUID is echoed into ITS stop file.
inst_reset_bcache_line() {
  printf '%s\n' "for d in $1/*/; do [ -f \"\${d}stop\" ] || continue; u=\"\${d%/}\"; echo \"\${u##*/}\" > \"\$u/stop\" && echo \"alpine-fde: info: reset: stopped live bcache set \${u##*/}\" || echo \"alpine-fde: warn: reset: could not stop bcache set \${u##*/}\"; done || :"
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
# Config drops execute IN PLAN ORDER (§3.3: after mount, before the first
# in-guest apk use; EXCEPTION — the /etc/apk/repositories drop deliberately
# PRECEDES the apk populate, real-install defect 6: apk resolves against the
# TARGET's repositories): the chroot runner defers them as host plan records
# (eager writes would land before the target is mounted, G-I1); dry-run
# prints them; qemu emits guest printf lines.
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
    _ie_plan=$(mktemp "${ALPINE_FDE_TMPDIR:-${TMPDIR:-/tmp}}/alpine-fde-plan.XXXXXX")
    printf '%s' "$SPC_PLAN" >"$_ie_plan"
    # L-04a + WR-02: a die mid-plan must leave NOTHING behind — one
    # combined EXIT trap scrubs the plan file AND the staged ephemeral
    # key-file AND the in-target release-passphrase seam file (blocker
    # #8/#9, best-effort), then tears the H-02 binds down best-effort (never
    # masking the real exit code; skipped when we died before the
    # mountpoint was even resolved)
    trap '
                rm -f "$_ie_plan" "${_ime_kf:-}" "${_im_pf_host:-}" 2>/dev/null
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
        chroot "$(inst_mnt)" /usr/bin/env -u ALPINE_FDE_DISK_PASSPHRASE /bin/sh -c "$_ie_cmd" ||
          die "install: guest step failed: $_ie_cmd"
      fi
    done 3<"$_ie_plan"
    trap - EXIT
    rm -f "$_ie_plan"
    ;;
  qemu)
    _ie_out=${ALPINE_FDE_INSTALL_SCRIPT:-/tmp/alpine-fde-install-guest.sh}
    {
      printf '#!/bin/sh -ex\n# alpine-fde install — guest-side plan (generated; runner=qemu)\n# Host-side steps are comments; the CI harness executes them itself.\nset -eux\n'
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
  _irt_bl="$_irt_mnt/etc/alpine-fde/baseline.json"
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
# transaction. §3.1 rows: mkinitfs (the initramfs generator, ADR-13),
# py3-pefile (ukify's PCR-signature parsing, ADR-16 delivery), doas (admin,
# §3.1), and ukify-kernel-hook (fires /etc/kernel-hooks.d on kernel
# transactions, §8.3/ADR-19). Topology-conditional: btrfs-progs by default,
# e2fsprogs for --fs ext4, bcache-tools when --bcache is given.
# NO zram-init (item 26a, ADR-7 AMENDED): zram is removed from the design —
# the queued --swap feature (task 4) is the only swap story going forward.
install_package_list() {
  _ipl='cryptsetup systemd-boot systemd-efistub ukify ukify-kernel-hook py3-pefile mkinitfs linux-lts tpm2-tools tpm2-tss-policy tpm2-tss-tcti-device sbsigntool openssl jq doas'
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
# with the operator fix. Runs over the ALPINE_FDE_EFIVARS_DIR seam.
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
  # and the first-boot AUTO-FINALIZER oneshot → /etc/init.d/ (ADR-20 amended
  # Stage 2: the service runs the non-interactive completion when
  # provisional-booted under Secure Boot; `alpine-fde finalize` remains the
  # guided/crash-resume entry point, Stage 3)
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
  # real-server blocker #7 (bootctl): Alpine ships NO bootctl binary — the
  # in-chroot `apk add systemd-boot` transaction SUCCEEDS yet the binary is
  # absent — so the boot manager is installed by GUARDED FILE COPY of the
  # loader EFI binary the systemd-boot package ships (inst_bootmgr_copy_line).
  # PREFLIGHT (fail-closed BEFORE any disk mutation): resolve the loader
  # binary — live env first (inst_loader_binary), then the systemd-boot apk
  # fetched from the configured mirror. Only a DECISIVE negative (a readable
  # package listing carrying NO loader binary) dies; an unprobeable
  # environment (no apk, unreachable mirror, fixtures) SKIPS with a warn —
  # never a silent pass — and the plan's copy record re-probes in-chroot
  # fail-closed.
  if _if_loader=$(inst_loader_binary "$(inst_loader_probe_prefix)"); then
    info "install: loader EFI binary present in the live env ($_if_loader)"
  elif command -v apk >/dev/null 2>&1 && command -v tar >/dev/null 2>&1 &&
    _if_pkglist=$(apk fetch --quiet --stdout systemd-boot 2>/dev/null | tar -tz 2>/dev/null) &&
    [ -n "$_if_pkglist" ]; then
    if printf '%s\n' "$_if_pkglist" | grep -q 'systemd-bootx64\.efi$'; then
      info "install: the systemd-boot package at $(inst_mirror) ships the loader EFI binary (boot manager installs by guarded file copy)"
    else
      die "install: the systemd-boot package at $(inst_mirror) ships NO loader EFI binary (systemd-bootx64.efi) — the boot manager cannot be installed; fix the mirror/package set before installing (real-server blocker #7)"
    fi
  else
    warn "install: loader-binary preflight inconclusive (no apk in the live env, or the systemd-boot package is not fetchable from $(inst_mirror)) — the plan's copy record re-probes in-chroot, fail-closed"
  fi
  # item 26b (real-install failure #3): the apk populate resolves the mirror
  # via the LIVE env resolver and the in-chroot transaction via the TARGET's
  # /etc/resolv.conf — a live ISO without DNS died mid-populate. Probe FIRST
  # that the configured mirror host is resolvable from the live env, with a
  # busybox-safe probe (nslookup ships on the Alpine live ISO; getent does
  # not). Fail closed BEFORE any disk mutation with the operator fix. A
  # tool-less environment (containers/fixtures) skips the probe with a warn —
  # never a silent pass.
  _if_mhost=$(printf '%s' "$(inst_mirror)" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#[/:].*$##')
  if command -v nslookup >/dev/null 2>&1; then
    if nslookup "$_if_mhost" >/dev/null 2>&1; then
      info "install: live env resolves the mirror host $_if_mhost (DNS preflight ok)"
    else
      die "install: live env cannot resolve $_if_mhost — configure networking (DHCP/DNS) before installing"
    fi
  else
    warn "install: no nslookup in the live env — mirror DNS preflight SKIPPED ($_if_mhost unresolved)"
  fi
  return 0
}

# inst_stage_ephemeral_key — G-C23 (§9.1 Stage 1 LUKS2 creation, ADR-20):
# generate the INTERNAL EPHEMERAL INSTALL KEY (openssl rand, 256-bit hex) and
# stage it under the tmpfs seam (${ALPINE_FDE_TMPDIR:-/dev/shm}), mode 0600.
# The key is the ONLY credential of the TEMPORARY keyslot 2 (§7.2: keyslot 0
# is reserved for the §9.1 step 4 recovery ceremony) between luksFormat and
# finalization: it drives luksFormat --key-slot 2, every `cryptsetup open`
# via --key-file (the existing key-file staging machinery), the §9.1 step 4
# recovery-ceremony luksAddKey authorization, and the provisional
# enrollment's token luksAddKey. The ceremony prompts (account password,
# recovery passphrase, release-key passphrase) are the operator's §9.1 step 4
# input — the key itself is never shown or persisted. I1: the key NEVER
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
  _ime_dir=${ALPINE_FDE_TMPDIR:-/dev/shm}
  _IME_KEYFILE=$(mktemp "$_ime_dir/alpine-fde-ephkey.XXXXXX") ||
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

# --- §9.1 step 4: the interactive credential ceremony (ADR-20 amended) -------
# Exactly THREE no-echo questions, the only interactive input of the whole
# lifecycle, run in-chroot while the ephemeral install key (keyslot 2) is
# still staged to authorize the recovery luksAddKey. ORDER (item 12 AMENDED,
# user ruling 2026-09-25): the DISK RECOVERY PASSPHRASE is asked FIRST; the
# two derived credentials DEFAULT to it on bare Enter, each prompt carrying an
# explicit hint:
#   1/3 the LUKS2 recovery passphrase -> keyslot 0 of EVERY member CONTAINER
#       (luksAddKey --key-slot 0, Argon2id, authorized by the staged ephemeral
#       install key; §13 entropy floor enforced — re-prompt until met,
#       confirm-typed, bounded at 3 attempts then die 64). The confirmed value
#       is kept in memory (INST_RECOVERY_PASSPHRASE) ONLY for the two derived
#       prompts below and unset at the end of the ceremony.
#   2/3 the user account password (chpasswd in the target root) — bare Enter
#       reuses the recovery passphrase (hint shown; no re-confirm needed: the
#       recovery value was already confirm-typed)
#   3/3 the release-key passphrase -> release.pem encrypted via the existing
#       keys_encrypt_release (ADR-18, AES-256 PBKDF2; own §13 floor when
#       typed) — bare Enter reuses the recovery passphrase
# There is NO flag and NO environment seam for any credential INPUT (S-24):
# the prompts live ONLY in these functions, reached through the executed plan
# (chroot runner). The ONE outbound handoff is the release-key passphrase to
# the in-chroot build: the ceremony writes it to the 0600 tmpfs seam file
# staged at generate time (real-server blocker #8) so `ukictl build`'s
# keys_unlock can decrypt release.pem — never argv, never the log, scrubbed
# with the ephemeral key (I1). Dry-run/qemu emit the records as inert text —
# secrets never appear in plan text, argv, the environment, or on disk/ESP
# (I1/I4).
# DEVICE CONTRACT (item 27, real-server failure #4): the recovery enrollment
# targets the LUKS CONTAINER devices (the luksFormat targets) — the
# /dev/mapper/* nodes are the DECRYPTED views and cryptsetup container-ops
# (luksDump/luksAddKey) against them fail "not a valid LUKS device".

# inst_prompt_secret LABEL VARNAME — no-echo read of one secret into VARNAME.
# stty -echo on a tty (restored immediately); a plain stdin read otherwise,
# which is exactly the test/CI seam (an answers file on stdin). Control
# characters are rejected: the secret must be typeable at a console prompt.
inst_prompt_secret() {
  _ipl_label=$1
  _ipl_var=$2
  printf '%s' "$_ipl_label" >&2
  _ipl_tty=0
  if [ -t 0 ] && stty -echo 2>/dev/null; then
    _ipl_tty=1
  fi
  _ipl_val=''
  # EOF (Ctrl-D / exhausted scripted input) is fail-closed: looping prompts
  # would otherwise spin forever on exhausted ANSWERS streams (user directive:
  # mismatched confirms re-prompt instead of exiting).
  IFS= read -r _ipl_val ||
    die "install: end of input while waiting for a credential prompt (EOF) — aborting"
  if [ "$_ipl_tty" = "1" ]; then
    stty echo 2>/dev/null
  fi
  printf '\n' >&2
  case $_ipl_val in
  *[[:cntrl:]]*)
    die "install: the entered secret contains control characters — refusing (it must be typeable at a console prompt)"
    ;;
  esac
  eval "$_ipl_var=\$_ipl_val"
  unset _ipl_val
  return 0
}

# inst_ceremony_floor PASSPHRASE — §13 entropy floor, shared implementation
# (passphrase_floor_ok from lib/cmd/rotate.sh, lazily sourced): >=12 chars
# across >=3 character classes, or >=16 chars.
inst_ceremony_floor() {
  # shellcheck disable=SC1090
  command -v passphrase_floor_ok >/dev/null 2>&1 ||
    . "${ALPINE_FDE_CMD_DIR:-$(sp_cmd_dir)}/rotate.sh"
  passphrase_floor_ok "$1"
}

# inst_ceremony_keys_lib — lazily pull in lib/keys.sh (keys_encrypt_release /
# keys_is_encrypted / keys_scrub; ADR-18 custody, consumed as-is)
inst_ceremony_keys_lib() {
  command -v keys_encrypt_release >/dev/null 2>&1 && return 0
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-$(sp_cmd_dir)}/../keys.sh"
  return 0
}

# inst_ceremony_user_password USER MNT — ceremony 2/3 (item 12): set the
# account password in-chroot (chpasswd; the secret rides stdin through the
# pipe, never argv). Bare Enter defaults to the recovery passphrase (asked
# 1/3); a typed value is confirm-typed as before.
inst_ceremony_user_password() {
  _icu_user=$1
  _icu_mnt=$2
  [ -n "$_icu_user" ] && [ -n "$_icu_mnt" ] ||
    die "inst_ceremony_user_password: USER and MNT are required"
  inst_prompt_secret "alpine-fde: set the password for account '$_icu_user' (no-echo; press Enter to reuse the recovery passphrase): " _icu_p1
  if [ -z "$_icu_p1" ]; then
    [ -n "${INST_RECOVERY_PASSPHRASE:-}" ] ||
      die "install: the account passwords were empty or did not match"
    _icu_p1=$INST_RECOVERY_PASSPHRASE
    info "install: credential ceremony (2/3): account '$_icu_user' password: Enter — reusing the recovery passphrase"
  else
    while [ -z "$_icu_p1" ] || [ "$_icu_p1" != "${_icu_p2:-}" ]; do
      unset _icu_p1 _icu_p2
      warn "install: the account passwords were empty or did not match — re-prompt until met"
      inst_prompt_secret "alpine-fde: set the password for account '$_icu_user' (no-echo; press Enter to reuse the recovery passphrase): " _icu_p1
      if [ -z "$_icu_p1" ]; then
        [ -n "${INST_RECOVERY_PASSPHRASE:-}" ] ||
          die "install: the account passwords were empty and no recovery passphrase to reuse"
        _icu_p1=$INST_RECOVERY_PASSPHRASE
        info "install: credential ceremony (2/3): account '$_icu_user' password: Enter — reusing the recovery passphrase"
        break
      fi
      inst_prompt_secret "alpine-fde: repeat the password: " _icu_p2
    done
  fi
  printf '%s:%s\n' "$_icu_user" "$_icu_p1" | chroot "$_icu_mnt" /usr/sbin/chpasswd ||
    die "install: setting the '$_icu_user' password in-chroot failed"
  unset _icu_p1 _icu_p2
  info "install: credential ceremony (2/3): account '$_icu_user' password set in-chroot (no-echo; the account is loginable)"
  return 0
}

# inst_ceremony_recovery AUTH_KEYFILE CONTAINER_DEV... — ceremony 1/3 (item
# 12: asked FIRST): prompt the recovery passphrase (no-echo, confirm-typed,
# §13 floor — re-prompt until met, bounded at 3 attempts), stage it as a 0600
# tmpfs passfile and enroll it into keyslot 0 of EVERY member CONTAINER via
# luksAddKey, authorized by the staged ephemeral install key (keyslot 2
# credential). DEVICE CONTRACT (item 27): the CONTAINER_DEV arguments are the
# LUKS container devices (the luksFormat targets) — NEVER /dev/mapper/* nodes
# (the decrypted views; container-ops against them fail "not a valid LUKS
# device"). Crash resume: a container whose keyslot 0 is already populated is
# skipped. The confirmed value stays in INST_RECOVERY_PASSPHRASE for the two
# derived prompts (2/3, 3/3) and is unset at the end of the ceremony.
inst_ceremony_recovery() {
  _icr_auth=$1
  shift
  [ -n "$_icr_auth" ] && [ -f "$_icr_auth" ] ||
    die "install: the staged ephemeral install key is missing — cannot authorize the recovery enrollment (§9.1 step 4 1/3)"
  [ $# -ge 1 ] || die "inst_ceremony_recovery: no target container device given"
  while :; do
    inst_prompt_secret "alpine-fde: set the LUKS2 recovery passphrase (§13: >=12 chars with 3 character classes, or >=16 chars; permanent recovery credential, keyslot 0): " _icr_p1
    inst_prompt_secret "alpine-fde: repeat the recovery passphrase: " _icr_p2
    # shellcheck disable=SC2154  # inst_prompt_secret assigns its named target
    if [ -n "$_icr_p1" ] && [ "$_icr_p1" = "$_icr_p2" ] && inst_ceremony_floor "$_icr_p1"; then
      break
    fi
    unset _icr_p1 _icr_p2
    warn "install: recovery passphrase empty/mismatched or below the §13 entropy floor — re-prompt until met"
  done
  INST_RECOVERY_PASSPHRASE=$_icr_p1
  _icr_dir=${ALPINE_FDE_TMPDIR:-/dev/shm}
  _icr_pf=$(mktemp "$_icr_dir/alpine-fde-ceremony.XXXXXX") ||
    die "install: cannot stage the recovery passphrase ($_icr_dir usable?)"
  chmod 600 "$_icr_pf"
  printf '%s' "$_icr_p1" >"$_icr_pf"
  unset _icr_p1 _icr_p2
  inst_ceremony_keys_lib
  for _icr_d in "$@"; do
    case $_icr_d in /dev/mapper/*)
      die "install: $_icr_d is a decrypted mapper view — the recovery enrollment must target the LUKS CONTAINER device (item 27)"
      ;;
    esac
    if cryptsetup luksDump "$_icr_d" 2>/dev/null | grep -q '^0:'; then
      info "install: $_icr_d keyslot 0 already populated — recovery enrollment skipped (crash resume)"
      continue
    fi
    cryptsetup luksAddKey --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 \
      --key-slot 0 --key-file "$_icr_auth" "$_icr_d" "$_icr_pf" ||
      die "install: $_icr_d: enrolling the recovery passphrase into keyslot 0 failed (ephemeral-key authorization)"
    info "install: credential ceremony (1/3): recovery passphrase enrolled in keyslot 0 of $_icr_d (Argon2id, §13)"
  done
  keys_scrub "$_icr_pf"
  return 0
}

# inst_ceremony_release_key KEYDIR [SEAMFILE] — ceremony 3/3 (item 12): prompt
# the release-key passphrase (no-echo; bare Enter reuses the recovery
# passphrase; a typed value is confirm-typed with the §13 floor — re-prompt
# until met) and encrypt release.pem in place via the existing
# keys_encrypt_release (ADR-18, AES-256 PBKDF2), then lock it 0400. With
# SEAMFILE (real-server blocker #8, retargeted by #9): the confirmed
# passphrase is ALSO written to the 0600 seam file IN THE TARGET ROOT
# (<mnt>/run/alpine-fde-release-pass — the H-02 /dev bind is PLAIN, so a host
# tmpfs seam is invisible guest-side), handing it to the in-chroot
# `ukictl build`: its shell reads it into ALPINE_FDE_KEY_PASSPHRASE
# (RESOLVED-4, keys_unlock priority 1) — never argv, never the log, consumed
# (rm) by the build record itself and scrubbed by teardown + the die-path
# traps (I1). Crash resume: an already-encrypted release.pem
# (keys_is_encrypted) is skipped AND the seam file stays absent — the build's
# keys_unlock falls back to its interactive no-echo prompt.
inst_ceremony_release_key() {
  _ick_d=$1
  _ick_pf=${2:-}
  [ -n "$_ick_d" ] && [ -d "$_ick_d" ] ||
    die "install: release-key directory missing: ${_ick_d:-} (§9.1 step 3 must provision the platform keys first)"
  [ -f "$_ick_d/release.pem" ] ||
    die "install: no release.pem in $_ick_d (§9.1 step 3 platform-key ceremony)"
  inst_ceremony_keys_lib
  if keys_is_encrypted "$_ick_d/release.pem"; then
    info "install: credential ceremony (3/3): release.pem already encrypted (ADR-18) — skipping (crash resume)"
    chmod 0400 "$_ick_d/release.pem" 2>/dev/null || :
    unset INST_RECOVERY_PASSPHRASE
    return 0
  fi
  while :; do
    inst_prompt_secret "alpine-fde: set the release-key passphrase (encrypts release.pem; no-echo; press Enter to reuse the recovery passphrase): " _ick_p1
    if [ -z "$_ick_p1" ]; then
      [ -n "${INST_RECOVERY_PASSPHRASE:-}" ] ||
        die "install: release-key passphrase empty and no recovery passphrase to reuse"
      _ick_p1=$INST_RECOVERY_PASSPHRASE
      info "install: credential ceremony (3/3): release-key passphrase: Enter — reusing the recovery passphrase"
      break
    fi
    inst_prompt_secret "alpine-fde: repeat the release-key passphrase: " _ick_p2
    # shellcheck disable=SC2154  # inst_prompt_secret assigns its named target
    if [ -n "$_ick_p1" ] && [ "$_ick_p1" = "$_ick_p2" ] && inst_ceremony_floor "$_ick_p1"; then
      break
    fi
    unset _ick_p1 _ick_p2
    warn "install: release-key passphrase empty/mismatched or below the §13 entropy floor — re-prompt until met"
  done
  # shellcheck disable=SC2034  # env seam consumed by keys_encrypt_release
  ALPINE_FDE_KEY_PASSPHRASE=$_ick_p1
  unset _ick_p2
  keys_encrypt_release "$_ick_d" ||
    die "install: encrypting release.pem (keys_encrypt_release) failed"
  # real-server blocker #8/#9: hand the passphrase to the in-chroot build via
  # the 0600 seam file IN THE TARGET ROOT (a host-tmpfs seam is invisible
  # through the plain H-02 /dev bind) — the secret travels target-file ->
  # guest env, never argv/log; the build record consumes (rm) it right after
  # reading and teardown + the die-path traps own the rest (I1).
  if [ -n "$_ick_pf" ]; then
    mkdir -p "$(dirname "$_ick_pf")"
    _ick_um=$(umask)
    umask 077
    printf '%s' "$_ick_p1" >"$_ick_pf"
    umask "$_ick_um"
    chmod 600 "$_ick_pf"
  fi
  unset ALPINE_FDE_KEY_PASSPHRASE INST_RECOVERY_PASSPHRASE _ick_p1
  chmod 0400 "$_ick_d/release.pem"
  info "install: credential ceremony (3/3): release.pem encrypted (AES-256 PBKDF2, ADR-18), mode 0400"
  return 0
}

# G-C25 (ADR-20 amendment #4): the unfinalized warning banner path is REMOVED
# — install writes NO banner to /etc/motd or /etc/issue (the operator's own
# content is never synthesized or touched), and finalize never strips one.

# inst_provisional_enroll_line EPHEMERAL_KEYFILE CONTAINER_DEV... — G-C24
# (§9.1 step 6): the single-line GUEST command performing the provisional TPM
# enrollment per member container, mirroring the lib guest-line pattern
# (export cmd-dir; source the libs; call the seal contract). DEVICE CONTRACT
# (item 27, extended): the arguments are the LUKS CONTAINER devices (the
# luksFormat targets) — every choreography step consumes the LUKS2 HEADER
# (seal_provisional -> token_free_slot luksDump; token_add_keyslot ->
# luksAddKey; token_next_id/token_import -> header token ops) and would fail
# "not a valid LUKS device" against the decrypted /dev/mapper/* views.
# Mechanics:
#   1. extract the .pcrsig from the just-built UKI (stage-1 `ukictl build`
#      output on the ESP; objcopy section extraction, pcrsign contract)
#   2. per container: seal_provisional (Mechanism B, PCR 11 only) -> token
#      JSON; luksAddKey the sealed random passphrase into the token keyslot
#      (slot contract, §7.2: keyslot 0 = recovery passphrase (ceremony),
#      keyslot 1 = provisional token — token_free_slot returns 1 on the
#      freshly ceremoneied container, keyslot 2 = temporary ephemeral install
#      key), authorized by the staged ephemeral key; then token_import
inst_provisional_enroll_line() {
  _pel_key=$1
  shift
  _pel_cs=''
  for _pel_c in "$@"; do
    _pel_cs="$_pel_cs $_pel_c"
  done
  _pel_cs=${_pel_cs# }
  _pel_esp=$(inst_esp_mnt)
  # I1: the tail scrubs EVERYTHING the ceremony staged — the random volume
  # passphrase (keys_scrub: overwrite-then-unlink, the shared idiom) and the
  # seal work dir (seal.priv/seal.pub halves + primary.ctx under the
  # ${ALPINE_FDE_TMPDIR:-/tmp}-defaulted stage, seal.sh's mktemp pattern) —
  # not just /run/alpine-fde. The tpm2 argv contract is UNCHANGED (the
  # mkinitfs hook mirrors lib/seal.sh argv-for-argv).
  printf '%s\n' "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && objcopy -O binary --only-section=.pcrsig \"\$(ls $_pel_esp/EFI/Linux/alpine-fde-*.efi | head -n 1)\" /run/alpine-fde/pcrsig.json && for d in $_pel_cs; do seal_provisional /etc/alpine-fde/keys \$d /run/alpine-fde/pcrsig.json /run/alpine-fde/token-\${d##*/}.json && token_add_keyslot \$d \"\$SEAL_PASS_FILE\" \"\$SEAL_SLOT\" $_pel_key && token_import \$d /run/alpine-fde/token-\${d##*/}.json \"\$(token_next_id \$d)\" || exit 1; done && keys_scrub \"\$SEAL_PASS_FILE\" && rm -rf /run/alpine-fde \${ALPINE_FDE_TMPDIR:-\${TMPDIR:-/tmp}}/alpine-fde-seal.* # ADR-20 step 6: provisional Mechanism B seal (PCR 11) -> keyslot 1 on the CONTAINER dev (item 27); I1 seal-secret scrub"
}

# inst_baseline_pending_write MNT — §9.1 Stage-1 step 2: write the initial
# baseline (pcr7 "pending" schema, provision-stage1 semantics) DIRECTLY on the
# target via the baseline writer — NO host-baseline copy exists anywhere.
inst_baseline_pending_write() {
  _ibp_mnt=$1
  _ibp_dir=$_ibp_mnt/etc/alpine-fde
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
# <mnt>/etc/alpine-fde/install-state.json. Consumes the install-state module's
# istate_write STATE (target root via ALPINE_FDE_ROOT, atomic write); if the
# module is not landed, the additive documented schema is written in place.
# NOTE (§9.1): install writes only `installed` — the `provisional-booted`
# middle state is written by the first-boot finalize service (Stage 2).
inst_state_write() {
  _isw_state=$1
  if command -v istate_write >/dev/null 2>&1; then
    _isw_saved=${ALPINE_FDE_ROOT:-}
    ALPINE_FDE_ROOT=$(inst_mnt)
    istate_write "$_isw_state"
    unset ALPINE_FDE_ROOT
    [ -n "$_isw_saved" ] && ALPINE_FDE_ROOT=$_isw_saved
    info "install: install-state written: $_isw_state ($(inst_mnt)/etc/alpine-fde/install-state.json)"
    return 0
  fi
  _isw_file=$(inst_mnt)/etc/alpine-fde/install-state.json
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
  _im_esp_given=0
  # §8.1: --disk is repeatable and ACCUMULATES. ALPINE_FDE_DISKS (the
  # dispatcher-provided list from repeated global --disk flags) is CONSUMED
  # here, never re-parsed; the legacy single ALPINE_FDE_DISK seeds the list.
  _im_disks=${ALPINE_FDE_DISKS:-}
  if [ -z "$_im_disks" ] && [ -n "${ALPINE_FDE_DISK:-}" ]; then
    _im_disks=$ALPINE_FDE_DISK
  fi
  while [ $# -gt 0 ]; do
    case $1 in
    --disk)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --disk requires an argument"
      _im_disks="$_im_disks $2"
      shift
      ;;
    --fs)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --fs requires an argument"
      _im_fs=$2
      shift
      ;;
    --bcache)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --bcache requires an argument"
      _im_bcache=$2
      shift
      ;;
    --esp)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --esp requires an argument"
      INST_ESP_MNT=$2
      _im_esp_given=1
      shift
      ;;
    --no-reboot) _im_no_reboot=1 ;;
    --keydir)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --keydir requires an argument"
      ALPINE_FDE_KEYDIR=$2
      shift
      ;;
    --user)
      [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "install: --user requires an argument"
      ALPINE_FDE_INSTALL_USER=$2
      shift
      ;;
    -y | --yes) _im_yes=1 ;;
    -h | --help)
      install_usage
      return 0
      ;;
    *) die -r "$ALPINE_FDE_USAGE" "install: unknown argument: $1" ;;
    esac
    shift
  done
  _im_disks=${_im_disks# }

  case $(inst_runner) in
  dry-run | chroot | qemu) : ;;
  *)
    die -r "$ALPINE_FDE_USAGE" "install: unknown runner '$(inst_runner)' (want: $SPC_INSTALL_RUNNERS)"
    ;;
  esac
  if [ "$(inst_runner)" != "dry-run" ] && [ "$_im_yes" -eq 0 ] && [ "${ALPINE_FDE_YES:-}" != "1" ]; then
    # L-06: gate on the AFFIRMATIVE value — "0"/"no" are refusals, not
    # consent (aligns with prov_stage2's = "1" comparison)
    die -r "$ALPINE_FDE_USAGE" "install: destructive run (runner=$(inst_runner)) requires --yes"
  fi

  # --- topology flags (§4.1) --------------------------------------------------
  INST_ROOT_FS=btrfs
  case $_im_fs in
  '') : ;;
  btrfs) : ;;
  ext4) INST_ROOT_FS=ext4 ;;
  *)
    die -r "$ALPINE_FDE_USAGE" "install: --fs must be btrfs or ext4 (got: $_im_fs)"
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
  [ -n "$_im_disks" ] || die -r "$ALPINE_FDE_USAGE" "install: no target disk — pass --disk (repeatable for RAID1)"
  # §8.1 flags contract: --esp (flag wins; env ALPINE_FDE_ESP; default /efi)
  # names the ESP mount point UNDER the target root. Validated loudly (rc 2):
  # never '/', never empty, never a bare relative name, never shell-unsafe.
  if [ "$_im_esp_given" = "0" ]; then
    INST_ESP_MNT=${ALPINE_FDE_ESP:-/efi}
  fi
  # validate the RAW value (inst_esp_mnt defaults an empty INST_ESP_MNT —
  # an explicit --esp '' must die, never silently fall back to /efi)
  case ${INST_ESP_MNT-} in
  '' | / | [!/]*)
    die -r "$ALPINE_FDE_USAGE" "install: --esp must be a mount point under the target root (e.g. /efi or /boot/efi) — got: '${INST_ESP_MNT-}'"
    ;;
  esac
  inst_shell_safe 'ESP mount point' "${INST_ESP_MNT-}"
  if [ "$INST_BCACHE" = "1" ]; then
    inst_shell_safe '--bcache' "$_im_bcache"
    if [ -z "$_im_disks" ]; then
      die -r "$ALPINE_FDE_USAGE" "install: --bcache needs a backing disk — pass --disk BACKING"
    fi
  fi
  _im_n=0
  for _im_d in $_im_disks; do
    inst_shell_safe '--disk' "$_im_d"
    _im_n=$((_im_n + 1))
  done
  if [ "$INST_ROOT_FS" = "ext4" ] && [ "$_im_n" -gt 1 ]; then
    die -r "$ALPINE_FDE_USAGE" "install: --fs ext4 is single-disk only — multi-disk root requires Btrfs RAID1"
  fi
  case $(inst_user) in
  '' | [-]* | *[!a-zA-Z0-9_.-]*)
    die -r "$ALPINE_FDE_USAGE" "install: invalid --user '$(inst_user)' (allowed: letters, digits, '.', '_', '-')"
    ;;
  esac
  inst_shell_safe 'ALPINE_FDE_INSTALL_MNT' "$(inst_mnt)"
  inst_shell_safe 'ALPINE_FDE_MIRROR' "$(inst_mirror)"
  inst_shell_safe 'ALPINE_FDE_ESP_SIZE' "$(inst_esp_size)"
  inst_shell_safe 'ALPINE_FDE_HOOKS_DIR' "$(inst_hooks_dir)"
  # WR-01: --keydir rides into eval'd records — same boundary rule. CONSUMED
  # (not ignored): when given, the operator-supplied key material is staged
  # from the medium and the in-chroot keygen is skipped (§8.1 provision row,
  # ADR-18 — README "provision stage1 on USB -> install --keydir").
  [ -n "$(sp_keydir)" ] && inst_shell_safe 'ALPINE_FDE_KEYDIR' "$(sp_keydir)"
  _im_kd=$(sp_keydir)
  if [ -n "$_im_kd" ]; then
    [ -d "$_im_kd" ] ||
      die -r "$ALPINE_FDE_USAGE" "install: --keydir directory not found: $_im_kd (ADR-18: the signing medium from 'provision stage1')"
    for _im_kf in $INST_KEYDIR_ARTIFACTS; do
      [ -f "$_im_kd/$_im_kf" ] ||
        die -r "$ALPINE_FDE_USAGE" "install: --keydir missing key artifact: $_im_kd/$_im_kf (run 'provision stage1' on the medium first, ADR-18)"
    done
    info "install: --keydir given — key material will be staged from the medium ($_im_kd); NO in-chroot keygen (§8.1/ADR-18)"
  fi

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
  _im_esp_mnt=$(inst_esp_mnt)
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
    # bcache semantics: the BACKING device is the WHOLE data disk (its
    # superblock lives at LBA 0) — never a partition of it. Only the CACHE dev
    # is partitioned (ESP p1 + cache set p2).
    _im_backing=$_im_disk
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

  # item 27 (real-server failure #4): the CEREMONY must target the LUKS
  # CONTAINER devices — the luksFormat targets. _im_members_names holds MAPPER
  # names (the open views; the provisional-seal loop input), NOT container
  # devices: container ops against /dev/mapper/* fail "not a valid LUKS
  # device". Primary container first (mapper root1 <-> container 1), then the
  # member containers in open order.
  _im_containers=$_im_luks
  for _im_c in $_im_members_devs; do
    _im_containers="$_im_containers $_im_c"
  done

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

  # real-server blocker #8 + #9: the release-key PASSPHRASE SEAM for the
  # in-chroot build. Blocker #8 staged it on the HOST tmpfs (/dev/shm) —
  # but the H-02 /dev bind is a PLAIN bind (no sub-mounts), so guest-side
  # /dev/shm is the target's empty dir and the record's read failed silently
  # in-chroot (blocker #9; keys_unlock's 9a cache glob /dev/shm/
  # alpine-fde-release-pass.* is equally blind through the bind — the guest
  # keys_unlock gets the value via ALPINE_FDE_KEY_PASSPHRASE, priority 1,
  # which outranks the cache anyway; the 9a cache keeps serving HOST-side
  # callers where /dev/shm IS the host's). The seam therefore lives IN THE
  # TARGET ROOT: <mnt>/run/alpine-fde-release-pass (guest /run/
  # alpine-fde-release-pass), 0600, on the LUKS2 container, written by the
  # ceremony (3/3) at execute time, consumed-and-REMOVED by the build record
  # in the same breath, scrubbed by teardown + the die-path traps (I1).
  # Paths are plan-static; dry-run carries the literal <release-passfile>
  # placeholder (nothing staged, no secret in plan text).
  if [ "$(inst_runner)" = "dry-run" ]; then
    _im_pf_host=''
    _im_pf_guest='<release-passfile>'
    _im_passfile_disp='<release-passfile>'
  else
    _im_pf_host=$_im_mnt/run/alpine-fde-release-pass
    _im_passfile_disp=$_im_pf_host
    _im_pf_guest=/run/alpine-fde-release-pass
  fi

  # --- 1. partition + block layer (§4.1, per topology) -----------------------
  # 1a. RESET a previous FAILED attempt (user-reported, e2e-invisible class):
  #     emitted BEFORE partitioning in every lane so a re-run continues; see
  #     the reset-record block comment above inst_reset_umount_rec_line for the
  #     guard/no-op/status contract. The bcache set STOP is deliberately in
  #     this block, NOT in the bcache flow: the stale live set must release
  #     the devices before the dd head+tail wipe (which then operates on a
  #     released device — 7619960).
  _im_mdir=$(inst_mapper_dir)
  _im_bsys=$(inst_bcache_sysfs)
  inst_plan_run host "if mountpoint -q $_im_mnt 2>/dev/null || ls $_im_mdir/root[0-9]* >/dev/null 2>&1 || [ -e $_im_mdir/root-crypt ] || ls $_im_bsys/*/ >/dev/null 2>&1; then echo 'alpine-fde: info: reset: previous failed install detected — tearing down its stale target mounts + mapper mappings before re-partitioning'; fi || :"
  # item 26d: ONE recursive umount replaces the fixed per-mount list — it
  # covers the subvols, the ESP and any stale chroot binds in a single record
  inst_plan_run host "$(inst_reset_umount_rec_line $_im_mnt)"
  inst_plan_run host "$(inst_reset_mapper_line "$_im_mdir")"
  inst_plan_run host "$(inst_reset_bcache_line "$_im_bsys")"

  # PHYSICAL-MEDIA preconditions (real-install defects 1+2): a physical boot
  # does NOT auto-load the block modules and /dev is not necessarily settled —
  # load bcache/btrfs explicitly, then coldplug, BEFORE any bcache/btrfs work.
  # Explicit `command -v` presence checks (repo idiom — never `|| true`): on
  # the installer media modprobe/mdev (busybox) always exist; in module-less
  # fixture environments the records stay inert no-ops while remaining
  # fail-closed (`set -e` + the plan runner) for any REAL absence.
  if [ "$(inst_bcache)" = "1" ]; then
    inst_plan_run host "if command -v modprobe >/dev/null 2>&1; then modprobe bcache; fi # physical boot: the bcache module is not auto-loaded"
  fi
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_run host "if command -v modprobe >/dev/null 2>&1; then modprobe btrfs; fi # physical boot: the btrfs module is not auto-loaded"
  fi
  inst_plan_run host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: settle /dev before partitioning"
  case $_im_topology in
  single)
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    ;;
  bcache)
    # ADR-17: ESP p1 + cache p2 on the FAST dev; the backing device is the
    # WHOLE --disk (bcache semantics — the backing dev is NOT partitioned).
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    # coldplug AFTER sfdisk (defect 2): the cache p1/p2 device nodes only
    # appear once the partition table is re-read and coldplug settles.
    inst_plan_run host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: partition device nodes must exist before make-bcache"
    # wipe stale superblocks BEFORE make-bcache (defect 3)
    inst_plan_run host "$(inst_wipe_superblocks_line "$_im_cache")"
    inst_plan_run host "$(inst_wipe_superblocks_line "$_im_backing")"
    inst_plan_run host "make-bcache -C $_im_cache"
    inst_plan_run host "make-bcache -B $_im_backing"
    inst_plan_run host "echo $_im_cache > /sys/fs/bcache/register && echo $_im_backing > /sys/fs/bcache/register"
    inst_plan_run host "CSET_UUID=\$(bcache-super-show $_im_cache | awk '/cset.uuid/ {print \$2}') && echo \"\$CSET_UUID\" > /sys/block/bcache0/bcache/attach && echo writethrough > /sys/block/bcache0/bcache/cache_mode # writethrough pinned (ADR-17: crash-safe, ciphertext-only cache)"
    ;;
  bcache-multi)
    # G-C27/§4.1 topology 4 (18f1213): ESP p1 + SHARED cache set p2 on the
    # fast dev; EACH backing disk is used WHOLE (bcache semantics — the
    # backing dev is NOT partitioned); every backing device registered
    # (/dev/bcache0, /dev/bcache1, ...) and attached to the shared cset UUID,
    # writethrough pinned.
    inst_plan_run host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    # coldplug AFTER sfdisk (defect 2), then stale-superblock wipes
    # BEFORE make-bcache (defect 3) — cache p2 + every whole backing disk.
    inst_plan_run host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: partition device nodes must exist before make-bcache"
    inst_plan_run host "$(inst_wipe_superblocks_line "$_im_cache")"
    for _im_d in $_im_disks; do
      inst_plan_run host "$(inst_wipe_superblocks_line "$_im_d")"
    done
    inst_plan_run host "make-bcache -C $_im_cache"
    for _im_d in $_im_disks; do
      inst_plan_run host "make-bcache -B $_im_d"
    done
    _im_reg="echo $_im_cache > /sys/fs/bcache/register"
    for _im_d in $_im_disks; do
      _im_reg="$_im_reg && echo $_im_d > /sys/fs/bcache/register"
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

  # --- 2. LUKS2 containers — G-C23: internal ephemeral install key in the ---
  #     TEMPORARY keyslot 2 (unattended; see the SLOT CONTRACT at the top of
  #     this file — keyslot 0 is reserved for the §9.1 step 4 recovery
  #     ceremony, keyslot 1 for the provisional token)
  inst_plan_run host "cryptsetup --batch-mode luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid $_im_uuid $_im_keyfile_arg $_im_luks # keyslot 2: ephemeral install key (TEMPORARY keyslot — purged at first-boot finalization, §9.1 Stage 2; ADR-20); --batch-mode: NO interactive dangerous-action YES prompt (real-install defect 5)"
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
      inst_plan_run host "cryptsetup --batch-mode luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid $_im_mu $_im_keyfile_arg $_im_md # keyslot 2: ephemeral install key (TEMPORARY keyslot — purged at first-boot finalization, §9.1 Stage 2); --batch-mode: no interactive YES"
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
    inst_plan_run host "mount -o subvol=@ $_im_mapper $_im_mnt && mkdir -p $_im_mnt/home $_im_mnt/.snapshots $_im_mnt$_im_esp_mnt"
    inst_plan_run host "mount -o subvol=@home $_im_mapper $_im_mnt/home"
    inst_plan_run host "mount -o subvol=@snapshots $_im_mapper $_im_mnt/.snapshots"
    inst_plan_run host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_plan_run host "mount $_im_esp $_im_mnt$_im_esp_mnt"
  else
    inst_plan_run host "mkfs.ext4 -F -U $_im_rootfs_uuid $_im_mapper"
    inst_plan_run host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_plan_run host "mount $_im_mapper $_im_mnt && mkdir -p $_im_mnt$_im_esp_mnt && mount $_im_esp $_im_mnt$_im_esp_mnt"
  fi

  # --- 4. minimal rootfs (§3.3): apk populate (self-authored bootstrap) -------
  # REAL-INSTALL DEFECT 6 (user-reported on a real server; e2e-invisible — the
  # harness stamps a pinned rootfs payload): apk resolves against the TARGET's
  # <mnt>/etc/apk/repositories, so the repositories drop MUST precede the
  # populate record — populate-first sees zero repos and dies with `ERROR:
  # unable to select packages: alpine-base`. The drop is written exactly once,
  # here (NOT repeated in section 5).
  # shellcheck disable=SC2046  # intentional: one plan line per repository entry
  inst_plan_write /etc/apk/repositories $(inst_repo_lines)
  # item 26 ext (real-install failure #5): apk verifies mirror indexes against
  # the TARGET's <mnt>/etc/apk/keys ONLY — absent on a fresh rootfs, and
  # --initdb does NOT copy the host keyring — so without this seed the populate
  # dies `WARNING: ... APKINDEX.tar.gz: UNTRUSTED signature` on any real server
  # (the repositories drop alone is half the fix). Guarded host record: no-op +
  # warn when the live env has no keyring.
  inst_plan_run host "mkdir -p $_im_mnt/etc/apk && if [ -d /etc/apk/keys ]; then cp -a /etc/apk/keys $_im_mnt/etc/apk/ && echo 'alpine-fde: info: apk keyring seeded from the live env (apk verifies the mirror indexes against the target keyring)'; else echo 'alpine-fde: warn: no keyring on the live env (/etc/apk/keys) — apk will not trust any mirror'; fi || : # item 26 ext: seed the target keyring before the populate"
  inst_plan_run host "apk add --root $_im_mnt --initdb alpine-base"

  # --- 5. config drops (host-side writes; guest printf lines under qemu) -----
  # (the §3.3 /etc/apk/repositories drop now precedes the populate above —
  # real-install defect 6)
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
      "PARTUUID=<esp-partuuid> $_im_esp_mnt vfat umask=0077 0 2"
  else
    inst_plan_write /etc/fstab \
      "UUID=$_im_rootfs_uuid / ext4 defaults 0 1" \
      "PARTUUID=<esp-partuuid> $_im_esp_mnt vfat umask=0077 0 2"
  fi
  # NO zram-init (item 26a, ADR-7 AMENDED): zram is removed from the design —
  # no conf.d drop, no rc-update enable (the old enable ran BEFORE the in-chroot
  # txn that installed the package and died: "service zram-init does not
  # exist", real-server failure #2). NO disk swap line exists in fstab above
  # (hibernation unsupported, §2.2/ADR-7 — a hibernate image is unencrypted
  # volume-key state on disk); the optional --swap partition is queued task 4.
  # §9.1 step 1: OpenRC networking (Alpine default: ifupdown-ng + udhcpc)
  inst_plan_write /etc/network/interfaces \
    'auto lo' \
    'iface lo inet loopback' \
    '' \
    'auto eth0' \
    'iface eth0 inet dhcp'
  # ADR-13/§3.3: NO dracut config is written — the target initramfs generator
  # is mkinitfs (ADR-13; hook + features.d inventory staged at §9.1 step 7).
  # The bcache driver/udev intent of the retired dracut drop is carried by the
  # mkinitfs features.d inventory (hooks/mkinitfs/features.d/alpine-fde.files:
  # bcache.ko + 69-bcache.rules) and ROOT_FS/BCACHE ride the conf below.
  # The rd.shell=0/rd.emergency=poweroff cmdline pins below stay: they are the
  # H-G1 fail-closed contract enforced by the cmdline-pins guard (§8.2) on
  # every ukictl build — not a dracut module knob.
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_write /etc/alpine-fde/cmdline.txt \
      "root=UUID=$_im_uuid rootflags=subvol=@ ro rd.shell=0 rd.emergency=poweroff"
  else
    inst_plan_write /etc/alpine-fde/cmdline.txt \
      "root=UUID=$_im_uuid ro rd.shell=0 rd.emergency=poweroff"
  fi
  # CR-01 + §4.1: persist the resolved topology + ESP mount for the build
  # side. ABSENT conf file (or absent keys) = defaults: ROOT_FS=btrfs,
  # BCACHE=0, TOPOLOGY=single — consumers must not require the file to exist.
  # REAL-SERVER BLOCKER #10: TOPOLOGY is persisted EXPLICITLY — BCACHE=1
  # covered both bcache AND bcache-multi, which made
  # crypttab_tpm2_check's "BCACHE=1 ⇒ exactly one root entry" count rule
  # false-positive on bcache-multi's CORRECT root1+root2 crypttab (the live
  # run died "found 2"). Consumers: lib/initramfs.sh initramfs_topology
  # (INI_TOPOLOGY; old confs without the key keep deriving from BCACHE).
  inst_plan_write /etc/alpine-fde/alpine-fde.conf \
    '# alpine-fde runtime config (KEY=VALUE).' \
    '# Absent file or absent keys = built-in defaults: ROOT_FS=btrfs, BCACHE=0, TOPOLOGY=single.' \
    "ROOT_FS=$(inst_root_fs)" \
    "BCACHE=$(inst_bcache)" \
    "TOPOLOGY=$_im_topology" \
    "ESP_PATH=$_im_esp_mnt"
  # H-02: the freshly populated chroot has no /proc /sys /dev — bind them
  # before the first guest step so the in-chroot ceremony behaves. §9.1 also
  # binds the efivars so the in-chroot NVRAM enrollment reaches the live
  # firmware.
  inst_plan_run host "mkdir -p $_im_mnt/proc $_im_mnt/sys $_im_mnt/dev && mount -t proc proc $_im_mnt/proc && mount --bind /sys $_im_mnt/sys && mount --bind /dev $_im_mnt/dev"
  inst_plan_run host "mkdir -p $_im_mnt/sys/firmware/efi/efivars && mount --bind /sys/firmware/efi/efivars $_im_mnt/sys/firmware/efi/efivars"

  # --- 6. tooling copy (host) — the in-chroot CLI lives at /opt/alpine-fde ---
  info "tooling copy: product script tree only (bin lib hooks docs) — VCS/harness residue excluded (§3.3)"
  inst_plan_run host "$(inst_tooling_copy_cmd "$_im_tree" "$_im_mnt")"
  # G-U7: the boot-manager self-update service is masked — ESP binaries are
  # only ever written by our SIGNED flow (§8.3)
  inst_plan_run host "mkdir -p $_im_mnt/etc/systemd/system && ln -sf /dev/null $_im_mnt/etc/systemd/system/systemd-boot-update.service"

  # --- 7. in-chroot provisioning (§9.1 steps 1-9, STRICTLY ORDERED) ----------
  # step 1: apk §3.3 additions set (one --no-cache transaction), user account
  # (created locked here; the §9.1 step 4 credential ceremony below sets its
  # password in-chroot — the ONLY interactive step), and OpenRC networking.
  # item 26b (real-install failure #3): the in-chroot transaction resolves the
  # mirror via the TARGET's /etc/resolv.conf — absent on a fresh rootfs (the
  # installer has ZERO other resolv.conf handling). Seed the live env's
  # resolver into the target BEFORE the transaction; guarded host record:
  # no-op + warn when the live env has no resolv.conf (the preflight probe
  # above already covered the live side).
  inst_plan_run host "if [ -f /etc/resolv.conf ]; then mkdir -p $_im_mnt/etc && cp /etc/resolv.conf $_im_mnt/etc/resolv.conf && echo 'alpine-fde: info: seeded target /etc/resolv.conf from the live env (in-chroot apk needs DNS)'; else echo 'alpine-fde: warn: live env has no /etc/resolv.conf — target DNS seed skipped (in-chroot apk may fail to resolve the mirror)'; fi || : # item 26b: seed the target resolver before the in-chroot transaction"
  inst_plan_run guest "apk add --no-cache $(install_package_list)"
  # step 1b (§8.2/ADR-13): register the `alpine-fde` mkinitfs feature in the
  # target's /etc/mkinitfs/mkinitfs.conf. mkinitfs packs a feature's
  # features.d/<name>.files entries ONLY when the feature is enabled in that
  # conf — without this the staged unseal hook (§9.1 step 7) is silently
  # omitted from every real build. Host-side record (runs against the staged
  # tree right after the in-guest apk transaction installs mkinitfs and its
  # package-default conf); grep-guard makes the patch idempotent under
  # re-run; a missing conf (package not yet installed) is created with the
  # feature-only line rather than silently skipped.
  inst_plan_run host "f=$_im_mnt/etc/mkinitfs/mkinitfs.conf; grep -q alpine-fde \"\$f\" 2>/dev/null || { mkdir -p $_im_mnt/etc/mkinitfs; [ -f \"\$f\" ] && sed -i 's/^features=\"\\(.*\\)\"$/features=\"\\1 alpine-fde\"/' \"\$f\" || printf 'features=\"alpine-fde\"\n' >\"\$f\"; } # §8.2/ADR-13: enable the alpine-fde mkinitfs feature (idempotent)"
  inst_plan_run guest "adduser -D -s /bin/ash $_im_user && addgroup $_im_user wheel"
  inst_plan_run guest 'rc-update add networking boot'
  # step 2: pending baseline written ON-TARGET via the baseline writer
  inst_plan_run host "inst_baseline_pending_write $_im_mnt"
  # step 3: platform-key ceremony — with --keydir the operator-supplied
  # material is staged FROM THE MEDIUM onto the encrypted root (restrictive
  # perms; NEVER anything under the ESP, I2) and the in-chroot keygen is
  # SKIPPED; without it the ceremony generates everything on the encrypted
  # root (ADR-18) via the custody flow (CLI invoked in-chroot).
  # --defer-custody (item 12/reorder close-out, user ruling: the LUKS2
  # recovery passphrase is the FIRST password asked, period): stage1 must NOT
  # prompt for / encrypt the release key — its own keys_encrypt_release prompt
  # would otherwise precede the ceremony below with no hint and no recovery
  # context. stage1 leaves release.pem PLAINTEXT and ceremony 3/3
  # (inst_ceremony_release_key) encrypts it — its keys_is_encrypted gate only
  # skips on an ALREADY-encrypted file, so the natural flow completes custody.
  _im_keys=$_im_mnt/etc/alpine-fde/keys
  if [ -n "$_im_kd" ]; then
    inst_plan_run host "mkdir -p $_im_keys && cp $_im_kd/release.pem $_im_kd/release.pub $_im_kd/release.crt $_im_kd/db.cert.der $_im_kd/kek.cert.der $_im_kd/pk.cert.der $_im_kd/db.esl $_im_kd/kek.esl $_im_kd/pk.esl $_im_kd/db.auth $_im_kd/kek.auth $_im_kd/pk.auth $_im_keys/ && chmod 700 $_im_keys && chmod 600 $_im_keys/* # ADR-18/§8.1: operator-supplied key material staged from the signing medium (no in-chroot keygen)"
  else
    inst_plan_run guest '/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys --defer-custody'
  fi
  # step 4: NVRAM enrollment db → KEK → PK (last) via the bind-mounted
  # efivars (SetupMode was gate-checked host-side in preflight). The in-chroot
  # ESP mount ($_im_esp_mnt, §8.1 --esp/env ALPINE_FDE_ESP/default /efi) is
  # passed as the fallback staging dir (queue 26 ext): when the firmware
  # refuses the SetVariable, fw_auth_enroll stages the .auth/.esl key material
  # to <ESP>/alpine-fde-keys and prints manual-import instructions instead of
  # dying — the install continues.
  inst_plan_run guest "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys $_im_esp_mnt"
  # step 4b (REPLACED + MOVED BEFORE the ceremony — real-server blocker #7:
  # Alpine ships NO bootctl binary; the retired `bootctl install` record died
  # "/bin/sh: bootctl: not found" AFTER the credential ceremony had already
  # run): the boot manager installs by GUARDED FILE COPY of the loader EFI
  # binary the systemd-boot package ships — probed fail-closed in-chroot — to
  # BOTH ESP homes: EFI/systemd/systemd-bootx64.efi (canonical; re-signed by
  # the kernel hook on later transactions, pinned by the audit manifest) and
  # EFI/BOOT/BOOTX64.EFI (removable-media fallback path — boots on any
  # firmware with NO NVRAM dependency; the harness fixtures already model
  # BOOTX64 as the default entry). The in-chroot build signs it (§8.3); the
  # §6 systemd-boot-update.service mask stays consistent.
  inst_plan_run guest "$(inst_bootmgr_copy_line $_im_esp_mnt)"
  # step 7 (MOVED BEFORE the credential ceremony — no ceremony secret; the
  # staging is also a ukictl-build INPUT — the kernel hook fires on every
  # build): hooks + trigger + first-boot AUTO-FINALIZER (§9.1 step 7;
  # ADR-13/ADR-19/ADR-20, G-C16 Alpine layout — flat templates copied to
  # their run-parts destinations; the auto-finalizer oneshot ships to
  # /etc/init.d/ and is enabled for the default runlevel. ADR-20 amended
  # Stage 2: it runs the NON-INTERACTIVE completion when provisional-booted
  # under Secure Boot; `alpine-fde finalize` is the guided/crash-resume
  # entry point, Stage 3.)
  # §8.2/ADR-13 staging contract (ONE pinned path): the unseal hook ships to
  # EXACTLY the absolute path listed in
  # hooks/mkinitfs/features.d/alpine-fde.files —
  # /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh — because mkinitfs
  # copies a feature's inventory from the TARGET tree at build time (that
  # path, resolved under the target root, is the features.d entry). Staging
  # under /etc/mkinitfs would leave the listed path unresolved and the hook
  # silently omitted. The repo-wide convention (hooks_mkinitfs_unseal +
  # initrd_audit inventories) already pins the /usr/share/alpine-fde spelling.
  inst_plan_run host "mkdir -p $_im_mnt/etc/kernel-hooks.d $_im_mnt/etc/mkinitfs/features.d $_im_mnt/usr/share/alpine-fde/mkinitfs $_im_mnt/etc/apk/triggers $_im_mnt/etc/init.d && cp $_im_hooks/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook && cp $_im_hooks/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook && cp $_im_hooks/mkinitfs/alpine-fde-unseal.sh $_im_mnt/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh && cp $_im_hooks/mkinitfs/features.d/alpine-fde.files $_im_mnt/etc/mkinitfs/features.d/alpine-fde.files && cp $_im_hooks/apk/triggers/alpine-fde.trigger $_im_mnt/etc/apk/triggers/alpine-fde.trigger && cp $_im_hooks/openrc/alpine-fde-finalize $_im_mnt/etc/init.d/alpine-fde-finalize && chmod +x $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh $_im_mnt/etc/apk/triggers/alpine-fde.trigger $_im_mnt/etc/init.d/alpine-fde-finalize && find $_im_mnt/lib/modules/*/kernel -type f \( -name 'tpm.ko*' -o -name 'tpm_tis.ko*' -o -name 'tpm_crb.ko*' -o -name 'btrfs.ko*' -o -name 'bcache.ko*' \) 2>/dev/null | sed s:$_im_mnt:: >> $_im_mnt/etc/mkinitfs/features.d/alpine-fde.files; td=\$(basename \"\$(readlink -f /sys/class/tpm/tpm0/device/driver 2>/dev/null)\" 2>/dev/null); [ -n \"\$td\" ] && info \"install: detected TPM interface driver: \$td (the staged feature file packs every found tpm/btrfs/bcache module, blocker #12)\"; :"
  inst_plan_run guest 'rc-update add alpine-fde-finalize default'
  # §8.4 (MOVED BEFORE the ceremony — no ceremony secret): resolve the ESP
  # PARTUUID into fstab + target metadata on the
  # on-target pending baseline (luks_uuid = primary; member_uuids additive)
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid $_im_members_uuids"
  else
    inst_plan_run host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid"
  fi
  # step 8 (G-C25, ADR-20 #4): NO unfinalized banner is written — /etc/motd
  # and /etc/issue stay untouched (the banner path is removed).
  # step 9 (G-C28, MOVED BEFORE the ceremony — no ceremony secret): ceremony
  # state machine — `installed` (the last state write; the provisional-booted
  # middle state is written by the first-boot service)
  inst_plan_run host "inst_state_write installed"
  # step 4 (ADR-20 AMENDED, §9.1 step 4): the interactive CREDENTIAL CEREMONY —
  # three no-echo questions, the only interactive input of the whole lifecycle,
  # run in-chroot while the ephemeral install key (TEMPORARY keyslot 2) is
  # still staged to authorize the recovery luksAddKey. NO flag and NO
  # credential env seam exists (S-24): the prompts run only in the execution
  # path (these records are eval'd host-side by the chroot runner), every
  # typed secret is §13-floored with re-prompt until met, and no credential
  # ever appears in plan text, argv, the environment, or on disk/ESP (I1/I4).
  # Dry-run/qemu emit the records as inert text. ORDER (item 12 AMENDED,
  # normative): the recovery passphrase FIRST (1/3); the user password (2/3)
  # and the release-key passphrase (3/3) DEFAULT to it on bare Enter, each
  # prompt carrying a reuse hint. POSITION (user flow directive): the ceremony
  # is the LAST interactive section — EVERY mechanical step precedes it
  # (enrollment, boot-manager copy, hooks, metadata, state above);
  # only the SECRET-dependent steps follow (the signed UKI + boot-manager
  # build, which consumes the release-key custody the ceremony just
  # completed, and the provisional seal). The ceremony runs AFTER the
  # platform-key ceremony (so release.pem exists), BEFORE the provisional
  # seal (so keyslot 0 is occupied and token_free_slot yields 1). DEVICE
  # CONTRACT (item 27): the recovery record passes the CONTAINER devices
  # ($_im_containers, the luksFormat targets) — never the /dev/mapper/* views.
  inst_plan_run host "inst_ceremony_recovery $_im_lukskey_disp $_im_containers # §9.1 step 4 credential ceremony (1/3) — asked FIRST (item 12): LUKS2 recovery passphrase -> keyslot 0 of EVERY member CONTAINER via luksAddKey, authorized by the staged ephemeral install key. KDF pinned: Argon2id; §13 entropy floor enforced — re-prompt until met, confirm-typed"
  inst_plan_run host "inst_ceremony_user_password $_im_user $_im_mnt # §9.1 step 4 credential ceremony (2/3): user account password (no-echo; press Enter to reuse the recovery passphrase — item 12 default-on-empty)"
  inst_plan_run host "inst_ceremony_release_key $_im_keys $_im_passfile_disp # §9.1 step 4 credential ceremony (3/3): release.pem encrypted AES-256 PBKDF2 (keys_encrypt_release, ADR-18; press Enter to reuse the recovery passphrase — item 12), mode 0400; 2nd arg = the 0600 passphrase seam file IN THE TARGET ROOT (<mnt>/run/... — guest /run/...; blocker #8/#9)"
  # step 5 (SECRET-dependent — stays AFTER the ceremony): signed boot manager
  # + initial UKI (baseline pending ⇒ the build's ensure-once enrollment is
  # state-gated OFF — the PROVISIONAL seal below is the only enrollment of
  # Stage 1)
  # REAL-SERVER BLOCKER #8 + #9: the build record must (a) configure the
  # release-key directory — ukictl build resolves keys_dir() =
  # ALPINE_FDE_KEYDIR/KEY_PATH with NO default; the bare record died
  # "release key directory not configured (set --keydir / KEY_PATH /
  # ALPINE_FDE_KEYDIR)" — and (b) consume the release-key PASSPHRASE the
  # ceremony (3/3) staged to the 0600 seam file IN THE TARGET ROOT: the
  # in-guest shell reads it (guest /run/alpine-fde-release-pass — a host
  # tmpfs seam is invisible through the PLAIN H-02 /dev bind, blocker #9)
  # into ALPINE_FDE_KEY_PASSPHRASE (RESOLVED-4's blessed env mechanism —
  # keys_unlock priority 1, outranking the 9a /dev/shm cache glob, which
  # cannot see through the bind anyway) and REMOVES the file in the same
  # breath, so the secret travels target-file -> guest env, NEVER argv or
  # the log. Absent file (crash resume on an already-encrypted release.pem):
  # keys_unlock falls back to its interactive no-echo prompt.
  # REAL-SERVER BLOCKER #11: the record derives the TARGET's installed
  # kernel IN-GUEST (basename of the newest version-sorted directory under
  # /lib/modules — top-level dirs only, fail-closed when absent, which means
  # the linux-lts package did not install) and PASSES it to ukictl build:
  # the retired no-arg form fell back to `uname -r` — the LIVE ISO's kernel
  # — whose module tree does not exist in the target.
  inst_plan_run guest "export ALPINE_FDE_ROOT=/; export ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys; [ -s $_im_pf_guest ] && ALPINE_FDE_KEY_PASSPHRASE=\$(cat $_im_pf_guest) && rm -f $_im_pf_guest && export ALPINE_FDE_KEY_PASSPHRASE; kv=\$(cd /lib/modules 2>/dev/null && ls -1d */ 2>/dev/null | tr -d '/' | sort -V | tail -n 1); [ -n \"\$kv\" ] || { echo 'alpine-fde: ERROR: no kernel module tree under /lib/modules — the linux-lts kernel package did not install into the target; fix the mirror/package set and re-run (completed steps skip via crash resume)' >&2; exit 1; }; /opt/alpine-fde/bin/alpine-fde ukictl build \"\$kv\" # §9.1 step 5 (SECRET-dependent — after the ceremony): signed boot manager + initial UKI (baseline pending ⇒ the build's ensure-once enrollment is state-gated OFF — the PROVISIONAL seal is the only Stage 1 enrollment); blocker #8/#9: keydir exported (keys_dir has no default) + passphrase from the in-target 0600 seam file (never argv); blocker #11: target kver derived in-guest (uname -r is the LIVE ISO kernel); blocker #12: ALPINE_FDE_ROOT=/ — in-chroot the TARGET IS /, and without it the initrd audit has no kernel-reality context (verdicts degrade to bare 'missing' instead of suffix-tolerant satisfaction)"
  # step 6 (SECRET-dependent — stays AFTER the ceremony): PROVISIONAL TPM
  # enrollment (G-C24) — Mechanism B, PCR 11 only,
  # .pcrsig from the just-built UKI; keyslot 1 per member CONTAINER (item 27:
  # the choreography targets the container devs, never the mapper views)
  inst_plan_run guest "$(inst_provisional_enroll_line "$_im_lukskey_disp" $_im_containers)"

  # --- 8. teardown + scrub (§9.1 Teardown; I1) ------------------------------
  # Operationally AFTER the ceremony + secret-dependent steps (the guest build
  # + seal run inside the chroot this unmounts): unmount, container close, the
  # explicit ephemeral-key scrub (I1). The FINAL reboot is the plan's tail
  # (§9 below): a direct reboot to disk when the NVRAM enrollment succeeded —
  # or, when the firmware refused it, the manual-import instructions, an
  # explicit Enter confirmation, and a reboot INTO FIRMWARE SETUP
  # (OsIndications) for the manual key import.
  inst_plan_run host "umount $_im_mnt/dev $_im_mnt/sys $_im_mnt/proc $_im_mnt/sys/firmware/efi/efivars && umount -R $_im_mnt && $_im_close"
  inst_plan_run host "rm -f $_im_lukskey_disp $_im_passfile_disp # I1: ephemeral install key + release-passphrase seam file scrubbed (§9.1 teardown; blocker #8/#9)"

  # --- 9. enrollment verdict + ESP-fallback tail (user directives 1+3) ------
  # The NVRAM enrollment ran BEFORE the ceremony (mechanical); whether the
  # firmware ACCEPTED it is only knowable at RUN time (generate-time cannot
  # know machine state — the reset-record idiom): probe PK on the LIVE
  # efivars (the in-chroot enrollment wrote the bind-mounted live NVRAM).
  inst_plan_run host "if fw_var_present $(fw_efivars_dir) PK; then INST_SB_ENROLLED=1; else INST_SB_ENROLLED=0; fi # enrollment verdict: PK absent = NVRAM enrollment refused — manual key import still pending (deferred)"
  # DEFERRED path (user directive 3): the manual-import instructions print at
  # the VERY END of the install — after every mechanical step — naming the
  # DIRECT-from-ESP import FIRST (user directive 2: the key material is staged
  # on the internal ESP precisely so the firmware can load it from there).
  # The explicit Enter confirmation + the firmware-setup reboot follow
  # (emitted only when the reboot is not suppressed by the CI seam).
  inst_plan_run host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else printf '%s\n' 'alpine-fde: Secure Boot key material is staged under $_im_esp_mnt/alpine-fde-keys on the EFI System Partition — the firmware refused NVRAM enrollment; finish the import manually:' '  1. import DIRECTLY from the internal ESP when the firmware key-management UI can browse it (the three files to import are already at $_im_esp_mnt/alpine-fde-keys — this is why they are staged on the EFI partition); otherwise copy the alpine-fde-keys directory to a FAT USB stick' '  2. reboot into the firmware setup (BIOS/UEFI) — this installer reboots there after your confirmation below' '  3. in the firmware key-management UI import the THREE staged files in this order: db.auth (Key Database), then kek.auth (Key Exchange Key), then pk.auth (Platform Key — import LAST; it locks the key database)' '  4. in the firmware file browser you will see the marker file !import_all_auth_files — import the three .auth files (README.txt on the ESP repeats these steps — no need to memorize them)' '  5. while in firmware setup, set an administrator (supervisor) password' '  6. boot the installed system — completed install steps skip via crash resume; the first boot REFUSES to boot until the keys are imported (that is the design, ADR-20)'; fi # deferred enrollment: manual-import instructions printed LAST (user directive: instructions at the very end; direct-from-ESP import first; three .auth files + README.txt + marker enumerated)"
  if [ "$_im_no_reboot" = "0" ] && [ "${ALPINE_FDE_INSTALL_NO_REBOOT:-}" != "1" ]; then
    inst_plan_run host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else printf '%s' 'alpine-fde: review the manual-import instructions above, then press Enter to reboot into firmware setup (UEFI): ' >&2; IFS= read -r _im_enter || :; fi # deferred enrollment: EXPLICIT user confirmation before the firmware reboot (user directive)"
    inst_plan_run host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else fw_osindications_set $(fw_efivars_dir) && reboot; fi # deferred enrollment: next boot enters firmware setup (OsIndications bit 0) for the manual key import"
    inst_plan_run host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then reboot; fi # §9.1: direct reboot to disk (NVRAM enrollment succeeded, ADR-20)"
  else
    info "install: reboot suppressed (ALPINE_FDE_INSTALL_NO_REBOOT/--no-reboot) — CI seam"
  fi

  if [ "$(inst_runner)" != "dry-run" ]; then
    inst_execute_plan
    trap - EXIT
    rm -f "$_im_lukskey" "${_im_pf_host:-}" 2>/dev/null
    if [ "${INST_SB_ENROLLED:-}" = "1" ]; then
      printf 'alpine-fde: install complete — direct reboot to disk (NVRAM enrollment succeeded); first boot unlocks via the provisional token and auto-finalizes under Secure Boot (§9.1 Stage 2); `alpine-fde finalize` is the guided/crash-resume entry point (ADR-20)\n' >&2
    else
      printf 'alpine-fde: install complete — firmware NVRAM enrollment was REFUSED: the Secure Boot key material is staged under %s/alpine-fde-keys; the installer reboots into firmware setup for the manual key import (first boot stays guarded until the keys are imported, ADR-20)\n' "$_im_esp_mnt" >&2
    fi
  else
    printf 'alpine-fde: dry-run plan complete (%s) — real execution: re-run with --yes (§9.1)\n' "$(inst_runner)" >&2
  fi
  return 0
}
