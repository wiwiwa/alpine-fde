#!/bin/sh
# install.sh — `alpine-fde install`: fully automated unattended Stage-1
# install (§9.1/ADR-20): partition + block layer, LUKS2 keyslot 0 formatted
# with the internal ephemeral install key (never persisted, I1), minimal
# Alpine rootfs (§3.3 apk populate), and the in-chroot provisioning ceremony
# ending in a provisional TPM token (PCR 11 only) + a direct reboot to disk —
# or, when the firmware REFUSED NVRAM enrollment (or a platform key was
# ALREADY enrolled — factory or custom: the DEFERRED-ENROLLMENT mode, no
# NVRAM writes, the release certificate is imported via the firmware UI), the
# manual key-import instructions, an explicit Enter confirmation, and a reboot
# INTO FIRMWARE SETUP (OsIndications) instead.
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
#   the seam exists for tests/CI (the qemu emission is the inspectable shape —
#   item 17d: the dry-run plan printer is RETIRED):
#   chroot (default)   guided local install from the live ISO: host steps run
#                      now, guest steps run via `chroot <mnt> sh -c`
#   qemu               emit the guest-side plan as a script for the CI harness
#                      (host steps emitted as comments) — no execution
#
# Steps are tagged host|guest and EXECUTE AT THE POINT OF DECISION (item 17d:
# no plan accumulator); file drops into the target root are done host-side at
# $MNT (chroot) or emitted as guest printf lines (qemu).
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

# The install ceremony's lifecycle state is GROUND TRUTH (item 10b: there is
# no install-state.json (item 10b) — lib/trust-state.sh derives provisional vs finalized
# from the token pcrs + keyslot inventory + baseline expected_pcr7). Stage 1
# writes its anchoring facts: the pending baseline (step 2) and the
# provisional {PCR 11} token + temporary ephemeral keyslot 2 (step 6).

# firmware seam (fw_sb_state/fw_var_present/fw_efivars_dir — the §9.1
# Setup Mode preflight gate; the OsIndications firmware trip is RETIRED,
# ADR-20 Teardown & Direct Reboot)
if [ -z "${ALPINE_FDE_FIRMWARE_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../firmware.sh"
fi
# cmdline seam (cmdline_compose / cmdline_variants — the TWO-UKI console
# variants; the composition owns the /etc/alpine-fde/cmdline{,-serial}.txt pair)
if [ -z "${ALPINE_FDE_CMDLINE_LIB_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../cmdline.sh"
fi
# esp seam (esp_uki_name — the boot entries point at the per-variant UKI paths)
if [ -z "${ALPINE_FDE_ESP_LOADED:-}" ]; then
  # shellcheck disable=SC1090
  . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../esp.sh"
fi

SPC_INSTALL_RUNNERS='chroot qemu'

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

# inst_cmdline_extra_check — fail-closed validation of ALPINE_FDE_CMDLINE_EXTRA
# (the plan-time extra-cmdline seam: extra kernel words appended to the target
# cmdline.txt, e.g. console=ttyS0,115200 for a headless/serial console). The
# systemd-stub measures the cmdline into PCR 11, so the words MUST be present
# BEFORE the kernel build + provisional seal — a post-hoc append would break
# the seal; that is why this is an install-time seam and not a boot-time knob.
# A §8.2 H-G1 pin override (any rd.shell=/rd.emergency= word other than the
# exact pins) dies HERE, before any disk mutation: the seam must not become a
# silent escape hatch around the cmdline-pins guard (§8.2 G-U6).
inst_cmdline_extra_check() {
  _cex_raw=${ALPINE_FDE_CMDLINE_EXTRA:-}
  [ -n "$_cex_raw" ] || return 0
  for _cex_w in $_cex_raw; do
    case $_cex_w in
    rd.shell=* | rd.emergency=*)
      die "install: ALPINE_FDE_CMDLINE_EXTRA may not override the §8.2 H-G1 fail-closed pins ($_cex_w) — only the exact pins rd.shell=0 rd.emergency=poweroff may appear (§8.2)"
      ;;
    esac
  done
}

# inst_cmdline_extra — the validated extra words, whitespace-normalized to
# single-space separation (the kernel cmdline is space-separated), no leading/
# trailing space; empty when the seam is unset. Callers splice with
# ${extra:+ $extra}.
inst_cmdline_extra() {
  printf '%s' "${ALPINE_FDE_CMDLINE_EXTRA:-}" \
    | tr -s '[:space:]' ' ' | sed -e 's/^ //' -e 's/ $//'
}
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

# --- ephemeral crypt swap (ADR-7 amended, task 4: install --swap [SIZE]) -----
# Opt-in EPHEMERAL encrypted swap: a dedicated partition (the LAST partition on
# the primary disk) encrypted with a FRESH /dev/urandom key at every boot —
# plain dm-crypt, NO LUKS header ever persists, and the key exists only in
# kernel memory, so poweroff leaves nothing decryptable on disk. Hibernation
# stays UNSUPPORTED (ADR-7: a hibernate image is unencrypted volume-key state
# on disk). Nothing swap-related runs at INSTALL time (no mkswap/swapon — the
# volume is reformatted at every activation); install only creates the
# partition and writes the boot-time config. The guest-side activation
# mechanism is Alpine's OpenRC dmcrypt service (cryptsetup-openrc),
# NOT /etc/crypttab: on this OpenRC target nothing consumes a crypttab swap
# entry (the initramfs crypttab is spliced from /etc/crypttab for the ROOT
# containers only and must never carry the swap — it mounts late, normal boot).
INST_SWAP=${INST_SWAP:-0}
INST_SWAP_SIZE=${INST_SWAP_SIZE:-}
INST_SWAP_DEFAULT=4G

inst_swap_enabled() { printf '%s\n' "${INST_SWAP:-0}"; }
inst_swap_size() { printf '%s\n' "${INST_SWAP_SIZE:-$INST_SWAP_DEFAULT}"; }

# inst_swap_size_check VALUE — fail-closed (usage rc 2) format validation of
# the --swap size BEFORE any plan record exists (M-02 boundary discipline):
# digits with a MANDATORY single K/M/G/T suffix (either case, e.g. 4G, 512m).
# A bare sector count is rejected so the MiB arithmetic below can never
# misread the unit; the strict charset scan runs FIRST so shell metacharacters
# ('4G; reboot') can never ride a glob '*' into a plan record.
inst_swap_size_check() {
  case $1 in
  *[!0-9KkMmGgTt]*)
    die -r "$ALPINE_FDE_USAGE" "install: --swap size must be a number with a K/M/G/T suffix (e.g. 4G) — got: '$1'"
    ;;
  esac
  case $1 in
  [0-9]*[KkMmGgTt]) : ;;
  *)
    die -r "$ALPINE_FDE_USAGE" "install: --swap size must be a number with a K/M/G/T suffix (e.g. 4G) — got: '$1'"
    ;;
  esac
  case ${1%[KkMmGgTt]} in
  '' | *[!0-9]*)
    die -r "$ALPINE_FDE_USAGE" "install: --swap size must be a number with a K/M/G/T suffix (e.g. 4G) — got: '$1'"
    ;;
  esac
  return 0
}

# inst_size_mib SIZE — normalize a suffixed size (4G / 512M / 2T / 2048K) to
# whole MiB (integer math; K rounds down). Consumed by the swap-partition
# sfdisk arithmetic (the root/cache partition is sized "disk minus esp minus
# swap" at RUN time).
inst_size_mib() {
  case $1 in
  *[Tt]) _ism_n=${1%[Tt]}; printf '%s\n' $((_ism_n * 1048576)) ;;
  *[Gg]) _ism_n=${1%[Gg]}; printf '%s\n' $((_ism_n * 1024)) ;;
  *[Mm]) _ism_n=${1%[Mm]}; printf '%s\n' "$_ism_n" ;;
  *[Kk]) _ism_n=${1%[Kk]}; printf '%s\n' $((_ism_n / 1024)) ;;
  *) return 1 ;;
  esac
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
# ONLY the product tree (bin/ lib/ hooks/ docs/ certs/) into
# <mnt>/opt/alpine-fde. Explicit per-directory copies (§3.3): never descends
# into VCS/harness residue (.git, tests/, fixtures/, caches, run dirs — a
# dirty checkout holds 100MB+ blobs and root-owned device nodes that a
# whole-tree `cp -r` copies or dies on); plain per-dir `cp -r src/. dst/` is
# POSIX/busybox-ash and rerun-safe. certs/ ships the vendor trust anchors
# (certs/vendor, e.g. Microsoft Option ROM UEFI CA 2023) — the in-chroot
# stage1 ceremony resolves them at /opt/alpine-fde/certs/vendor for the
# combined db.esl (db reset + release+vendor rebuild, DECIDED 2026-09-27).
inst_tooling_copy_cmd() {
  _itc_tree=$1
  _itc_mnt=$2
  _itc_mkdir="mkdir -p $_itc_mnt/opt $_itc_mnt/usr/local/bin"
  _itc_cps=''
  for _itc_d in bin lib hooks docs certs; do
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
# The in-chroot build (kernel build, §8.3) signs the binaries; the
# systemd-boot-update.service mask (§6) stays consistent with the retired
# bootctl flow. Run BEFORE the credential ceremony (no secret involved).
inst_bootmgr_copy_line() {
  _bcl_esp=$1
  printf '%s\n' "ldr=''; for p in /usr/share/systemd/bootctl/systemd-bootx64.efi /usr/lib/systemd/boot/efi/systemd-bootx64.efi; do [ -f \"\$p\" ] && { ldr=\"\$p\"; break; }; done; [ -n \"\$ldr\" ] || { echo 'alpine-fde: ERROR: no systemd-boot loader EFI binary found in-chroot (probed /usr/share/systemd/bootctl/systemd-bootx64.efi, /usr/lib/systemd/boot/efi/systemd-bootx64.efi) — the systemd-boot package is missing or incomplete; the boot manager cannot be installed; fix the mirror/package set and re-run (completed steps skip via crash resume)' >&2; exit 1; }; mkdir -p $_bcl_esp/EFI/systemd $_bcl_esp/EFI/BOOT && sbsign --key /etc/alpine-fde/keys/release.pem --cert /etc/alpine-fde/keys/release.crt \"\$ldr\" --output $_bcl_esp/EFI/BOOT/BOOTX64.EFI && cp $_bcl_esp/EFI/BOOT/BOOTX64.EFI $_bcl_esp/EFI/systemd/systemd-bootx64.efi && echo \"alpine-fde: info: boot manager RELEASE-SIGNED (blocker #26 addendum: the firmware verifies the FIRST loaded image — an unsigned BOOTX64.EFI dies before the UKI is ever reached) -> $_bcl_esp/EFI/BOOT/BOOTX64.EFI + $_bcl_esp/EFI/systemd/systemd-bootx64.efi (removable-media fallback path, no NVRAM dependency; §8.3)\" # boot manager via guarded file copy of the systemd-boot loader binary (fail-closed probe; real-server blocker #7)"
}

# --- UEFI boot entries (NVRAM; task #27 + the default-only boot design) -------
# The install/build lane ends with the firmware loading the UKI DIRECTLY: ONE
# NVRAM boot entry per kernel version (Samuel, 2026-10-02 — the serial NVRAM
# lane RETIRED; the serial UKI FILE still builds + installs to the ESP per
# kernel and the automation one-shots it via the firmware's UefiTarget) —
#   "Alpine FDE - <kver> (<YYYY-MM-DD>)" -> \EFI\Linux\alpine-fde-<kver>.efi
# pinned to HD(1,GPT,<esp-part-guid>). The firmware loads the UKI
# directly — systemd-boot stays ONLY as the removable-media fallback
# (\EFI\BOOT\BOOTX64.EFI) and is NOT in the default boot path anymore (which
# also eliminates the boot-manager menu-wait failure mode). Before this
# existed, the operator ran efibootmgr BY HAND after every fresh install, and
# after a RE-partition the hand-made entry kept the OLD partition GUID and died
# "Boot Failed" — so the ensure below is IDEMPOTENT: a same-kver entry
# pointing at the CURRENT ESP partition GUID + loader is reused (never
# duplicated); family entries (same kver, anything else — old GUID,
# old loader, a rebuild's re-stamped date in the label, or a pre-two-UKI
# legacy "Alpine FDE" entry) are deleted and recreated, and the RETIRED
# SERIAL entries (the two-UKI shape: serial-labeled family entries at any
# GUID, or -serial.efi loaders) are SWEPT — the NVRAM carries DEFAULT
# entries only. RETENTION bounds the
# whole system at THREE kernel versions (current + 2 previous; the build lane
# clamps a higher RETENTION with a loud warn), i.e. AT MOST THREE NVRAM
# entries, oldest pruned first (inst_bootentry_prune, called
# from the build's prune step, `kernel prune` and `kernel remove`).
#
# The record runs IN-GUEST (chroot runner): the ESP is mounted at the §8.1
# --esp path and the live NVRAM is reachable through the §9.1 efivars bind —
# exactly how the step-4 fw_auth_enroll NVRAM writes work. When efibootmgr
# reports NO EFI variable support (non-EFI host / test container), the step
# SKIPS with the exact manual commands instead of failing the install.

# inst_bootentry_date — the build date carried in the NVRAM labels (UTC
# YYYY-MM-DD; ALPINE_FDE_BOOTENTRY_DATE is the test seam)
inst_bootentry_date() { printf '%s\n' "${ALPINE_FDE_BOOTENTRY_DATE:-$(date -u +%Y-%m-%d)}"; }

# inst_bootentry_label <kver> <variant> — the NVRAM boot-entry label
# (capitalized, user decision after the real Dell PowerEdge install): the
# kernel version + build date travel IN the label so the firmware menu shows
# which kernel boots, and so inst_bootentry_parse can family-match per kver
# across rebuilds (a rebuild on a later day re-labels the entry — the stale
# entry is deleted and recreated, never duplicated). DEFAULT entries only:
# the serial NVRAM lane is retired (the serial UKI is one-shot via UefiTarget).
inst_bootentry_label() {
  _ibel_d=$(inst_bootentry_date)
  case $2 in
  default) printf '%s\n' "Alpine FDE - $1 ($_ibel_d)" ;;
  *) die "install: unknown boot-entry variant '$2' (expected: default — the serial NVRAM lane is retired)" ;;
  esac
}

# inst_bootentry_loader <kver> <variant> — the loader path the entry points at:
# the UKI ITSELF on the ESP (firmware-direct load; the systemd-stub brings the
# initrd + cmdline up without any boot manager)
inst_bootentry_loader() {
  case $2 in
  default) printf '%s\n' "\\EFI\\Linux\\alpine-fde-$1.efi" ;;
  *) die "install: unknown boot-entry variant '$2' (expected: default — the serial NVRAM lane is retired)" ;;
  esac
}

# inst_efibootmgr — the efibootmgr binary (test seam, ALPINE_FDE_EFIBOOTMGR;
# a real run resolves the PATH binary delivered by the §3.3 package set +
# the guest record's require_pkgs probe)
inst_efibootmgr() { printf '%s\n' "${ALPINE_FDE_EFIBOOTMGR:-efibootmgr}"; }

# inst_part_split DEV — print "DISK PARTNUM" for a partition device (the
# inverse of inst_part): /dev/sda1 -> "/dev/sda 1",
# /dev/nvme0n1p1 -> "/dev/nvme0n1p1" minus p1 = "/dev/nvme0n1 1". rc 1 when
# DEV does not name a partition.
inst_part_split() {
  case $1 in
  *[0-9]p[0-9]*)
    _ips_n=${1##*p}
    printf '%s %s\n' "${1%p$_ips_n}" "$_ips_n"
    ;;
  *[0-9])
    _ips_n=${1##*[!0-9]}
    printf '%s %s\n' "${1%$_ips_n}" "$_ips_n"
    ;;
  *) return 1 ;;
  esac
}

# inst_bootentry_parse — stdin: `efibootmgr -v` output; stdout: ONE line per
# boot entry "NUM GUID LOADER KVER VARIANT" (num lowercased; guid lowercased,
# "-" when the device path carries no HD(…,GPT,…); LOADER the lowercased
# File(...) path text ('' when the device path carries none); KVER+VARIANT the
# parsed label family — "Alpine FDE - <kver>[ serial] (<date>)" per
# inst_bootentry_label, the literals LEGACY/LEGACY for the pre-two-UKI entries
# ("Alpine FDE", "Alpine FDE (serial)"), or -/- for foreign entries.
# efibootmgr -v entry lines: "Boot<4hex><*|space> <label> <device path>" — the
# label starts at column 11; the -v device path is what carries
# HD(1,GPT,<guid>,…)/File(\EFI\Linux\…) (plain efibootmgr prints no paths —
# the parse MUST consume -v output).
inst_bootentry_parse() {
  awk '
        tolower($0) ~ /^boot[0-9a-f][0-9a-f][0-9a-f][0-9a-f][* ]/ {
            num = tolower(substr($0, 5, 4))
            lc = tolower($0)
            rest = substr($0, 11)
            sub(/^[ \t]+/, "", rest)
            rl = tolower(rest)
            # the label ENDS at the first TAB (efibootmgr -v separates the
            # device path with one) — the family grammar below anchors the
            # date stamp at the END of the LABEL, not of the whole line
            _tab = index(rl, "\t")
            if (_tab > 1) rl = substr(rl, 1, _tab - 1)
            kver = "-"
            variant = "-"
            if (index(rl, "alpine fde - ") == 1) {
                body = substr(rl, 14)
                # the trailing " (<date>)" is the family stamp; without it the
                # label is not one of ours (a foreign label that merely shares
                # the prefix must never match)
                if (match(body, /\([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\)[ \t]*$/)) {
                    body = substr(body, 1, RSTART - 1)
                    sub(/[ \t]+$/, "", body)
                    variant = "default"
                    if (length(body) > 7 && substr(body, length(body) - 6) == " serial") {
                        variant = "serial"
                        body = substr(body, 1, length(body) - 7)
                    }
                    kver = body
                }
            } else if (rl == "alpine fde" || rl == "alpine fde (serial)") {
                # pre-two-UKI entries (the single-UKI scheme pointing at
                # \EFI\BOOT\BOOTX64.EFI) — always stale under the pair model
                kver = "LEGACY"
                variant = (rl == "alpine fde (serial)") ? "serial" : "default"
            }
            guid = "-"
            if (match(lc, /hd\([0-9]+,gpt,[0-9a-f][0-9a-f-]*,/)) {
                piece = substr(lc, RSTART, RLENGTH)
                sub(/^hd\([0-9]+,gpt,/, "", piece)
                sub(/,$/, "", piece)
                guid = piece
            }
            loader = ""
            if (match(lc, /file\([^)]*\)/)) {
                loader = substr(lc, RSTART + 5, RLENGTH - 6)
            }
            printf "%s %s %s %s %s %s\n", num, guid, loader, kver, variant, rl
        }
    '
}

# inst_bootentry_find LIST GUID LOADER KVER VARIANT [LABEL] — the first (of
# LIST, inst_bootentry_parse form) entry of the kver+variant family that
# already points at GUID + LOADER (the reuse case); with LABEL given, the
# LABEL must match too (a same-shape entry with a STALE label — a rebuild
# re-stamped the date — is not reusable; the label is what the firmware menu
# shows). Empty when none does.
inst_bootentry_find() {
  _ibf_lcguid=$2
  _ibf_lcldr=$3
  _ibf_lckver=$4
  _ibf_lcvar=$5
  _ibf_lclbl=${6:-}
  printf '%s\n' "$1" | while IFS=' ' read -r _ibf_n _ibf_g _ibf_l _ibf_k _ibf_v _ibf_lbl; do
    if [ "$_ibf_k" = "$_ibf_lckver" ] && [ "$_ibf_v" = "$_ibf_lcvar" ] &&
      [ "$_ibf_g" = "$_ibf_lcguid" ] && [ "$_ibf_l" = "$_ibf_lcldr" ] &&
      { [ -z "$_ibf_lclbl" ] || [ "${_ibf_lbl:-}" = "$_ibf_lclbl" ]; }; then
      printf '%s\n' "$_ibf_n"
      break
    fi
  done
  return 0
}

# inst_bootentry_efivars_ok — rc 0 when NVRAM writes are possible (efivarfs
# mounted AND efibootmgr answers); rc 1 otherwise. The caller decides
# skip-vs-fail per lane (the install SKIPS with manual commands; the build
# lane's prune warns).
inst_bootentry_efivars_ok() {
  [ -d "$(fw_efivars_dir)" ] || return 1
  _ibeo_eb=$(inst_efibootmgr)
  _ibeo_out=$("$_ibeo_eb" -v 2>&1) || {
    case $_ibeo_out in
    *"not supported"*) return 1 ;;
    *) return 1 ;;
    esac
  }
  return 0
}

# inst_bootentry_resolve_kver [KVER] — the boot-entry kernel version: the
# argument when given; otherwise (in-guest) the newest module tree under
# /lib/modules (the SAME derivation the build record pins, blocker #11) —
# rc 1 when unresolvable.
inst_bootentry_resolve_kver() {
  if [ -n "${1:-}" ]; then
    printf '%s\n' "$1"
    return 0
  fi
  _ibr_kv=$(cd /lib/modules 2>/dev/null && ls -1d */ 2>/dev/null | tr -d '/' | sort -V | tail -n 1)
  [ -n "$_ibr_kv" ] || return 1
  printf '%s\n' "$_ibr_kv"
}

# inst_bootentry_ensure ESPDEV ESP_MNT [KVER] — the in-guest executor
# (idempotent, crash-resume safe; re-runs converge). Ensures the SINGLE
# DEFAULT entry for KVER (derived in-guest when omitted), FIRST in BootOrder,
# everything else preserved behind. The SERIAL NVRAM lane is RETIRED: no
# serial entry is ever created, and retired serial entries are swept (the
# serial UKI FILE still installs to the ESP per kernel — the automation
# one-shots it via UefiTarget). ESPDEV is the ESP partition device (§4.1
# layout, e.g. /dev/sda1 — visible in-guest through the /dev bind), ESP_MNT
# the §8.1 ESP mount under the target root (/). The partition GUID the entry
# pins comes from the §8.4 target metadata (target.esp_partuuid in the
# on-target baseline — the SAME GUID fstab pins), NOT a fresh probe: the
# in-guest closure carries no lsblk (util-linux is live-side only).
# Fail-closed guards: the staged DEFAULT UKI must exist (the firmware loads
# it DIRECTLY — an entry at an unstaged UKI is a "Boot Failed" brick) and the
# baseline must resolve the ESP partition.
inst_bootentry_ensure() {
  _ibe_esp=$1
  _ibe_espdir=$2
  _ibe_kver=$(inst_bootentry_resolve_kver "${3:-}") ||
    die "install: no kernel version for the boot entries (pass the kver or install the kernel under /lib/modules)"
  _ibe_eb=$(inst_efibootmgr)
  # fail-closed: the staged DEFAULT UKI must exist BEFORE any NVRAM write (the
  # firmware loads the file DIRECTLY — an entry at an unstaged UKI is a
  # "Boot Failed" brick). The serial UKI is NOT guarded here — the serial
  # NVRAM lane is retired (no serial entry is created).
  _ibe_uki="$_ibe_espdir/EFI/Linux/$(esp_uki_name "$_ibe_kver" default)"
  [ -f "$_ibe_uki" ] ||
    die "install: $_ibe_uki is missing — refusing to create the default boot entry for $_ibe_kver before the UKI is staged (the kernel build must run first)"
  _ibe_bl=$(sp_baseline_file)
  [ -f "$_ibe_bl" ] ||
    die "install: no baseline at $_ibe_bl — cannot resolve the ESP partition the boot entries must point at"
  _ibe_pu=$(baseline_get_in "$_ibe_bl" target esp_partuuid)
  [ -n "$_ibe_pu" ] ||
    die "install: no target.esp_partuuid in $_ibe_bl — cannot resolve the ESP partition the boot entries must point at (the §8.4 target-metadata step must run first)"
  _ibe_lcpu=$(printf '%s' "$_ibe_pu" | tr '[:upper:]' '[:lower:]')
  _ibe_split=$(inst_part_split "$_ibe_esp") ||
    die "install: cannot split the ESP device into disk + partition number: $_ibe_esp"
  # shellcheck disable=SC2086  # exactly two words: DISK PARTNUM
  set -- $_ibe_split
  _ibe_disk=$1
  _ibe_pn=$2
  # NO EFI variable support (non-EFI host / test container): SKIP with the
  # exact manual commands — the removable-media loader path still boots, and a
  # hard failure here would strand the whole install after it completed
  _ibe_vars=$(fw_efivars_dir)
  _ibe_skip=0
  _ibe_list=''
  if [ ! -d "$_ibe_vars" ]; then
    _ibe_skip=1
  elif ! _ibe_list=$("$_ibe_eb" -v 2>&1); then
    case $_ibe_list in
    *"not supported"*) _ibe_skip=1 ;;
    *) die "install: efibootmgr -v failed: $_ibe_list" ;;
    esac
  fi
  if [ "$_ibe_skip" = "1" ]; then
    warn "install: no EFI variable support ($_ibe_vars) — SKIPPING the NVRAM boot entry (the removable-media path still boots); create it manually:"
    warn "install:   efibootmgr -c -d $_ibe_disk -p $_ibe_pn -L '$(inst_bootentry_label "$_ibe_kver" default)' -l '$(inst_bootentry_loader "$_ibe_kver" default)'   (then 'efibootmgr -o <NUM>,...' with the new number FIRST, pointing at the ESP partition GUID $_ibe_pu)"
    return 0
  fi
  # stale family entries FIRST: same-kver DEFAULT entries at ANY other GUID (a
  # re-partitioned ESP leaves the OLD partition GUID in NVRAM — the real
  # server booted them into "Boot Failed"), the pre-two-UKI LEGACY
  # entries (they point the default boot path at the boot manager), and the
  # RETIRED SERIAL entries (the two-UKI shape — any GUID; the serial NVRAM
  # lane is retired, the serial UKI is one-shot via UefiTarget). A same-family
  # entry at a stale LOADER (a rebuild re-stamps the date in the label; the
  # label no longer matches) is handled inside ensure_one's reuse check — a
  # non-reusable family entry at the right GUID is deleted there before the
  # create. Same-kver entries at the current GUID that merely DUPLICATE each
  # other collapse on the next ensure via inst_bootentry_find's first-match
  # reuse (re-run hygiene).
  inst_bootentry_family_cleanup "$_ibe_lcpu"
  # reuse-or-create the DEFAULT entry (the only NVRAM lane; the serial UKI
  # file stays ESP-only — one-shot via UefiTarget)
  _ibe_def_entry=$(inst_bootentry_ensure_one "$_ibe_eb" "$_ibe_disk" "$_ibe_pn" \
    "$(inst_bootentry_label "$_ibe_kver" default)" \
    "$(inst_bootentry_loader "$_ibe_kver" default)" \
    "$_ibe_kver" default "$_ibe_lcpu") || return $?
  # BootOrder: the default entry FIRST, the retained older versions behind
  # (oldest last — prune order)
  _ibe_fresh=$("$_ibe_eb" -v 2>/dev/null | inst_bootentry_parse)
  _ibe_reorder_front "$_ibe_eb" "$_ibe_def_entry" "$_ibe_fresh"
  info "install: boot entry standing for $_ibe_kver (default Boot$_ibe_def_entry; the firmware loads the UKI directly; the serial lane is retired — the serial UKI is one-shot via UefiTarget)"
  return 0
}

# inst_bootentry_ensure_one EB DISK PARTNUM LABEL LOADER KVER VARIANT GUID —
# reuse-or-create ONE NVRAM entry; prints the entry number. Reuses a family
# entry already at GUID+LOADER; otherwise deletes any OTHER family entry at
# the current GUID (a stale loader — the label changed under a rebuild), then
# creates (with the bounded NVRAM-latency retry). Dies fail-closed when the
# create never becomes visible.
inst_bootentry_ensure_one() {
  _ibeo_eb=$1
  _ibeo_disk=$2
  _ibeo_pn=$3
  _ibeo_lbl=$4
  _ibeo_ldr=$5
  _ibeo_kver=$6
  _ibeo_var=$7
  _ibeo_guid=$8
  _ibeo_lcldr=$(printf '%s' "$_ibeo_ldr" | tr '[:upper:]' '[:lower:]')
  _ibeo_lclbl=$(printf '%s' "$_ibeo_lbl" | tr '[:upper:]' '[:lower:]')
  _ibeo_fresh=$("$_ibeo_eb" -v 2>/dev/null | inst_bootentry_parse)
  _ibeo_mine=$(inst_bootentry_find "$_ibeo_fresh" "$_ibeo_guid" "$_ibeo_lcldr" \
    "$_ibeo_kver" "$_ibeo_var" "$_ibeo_lclbl")
  if [ -n "$_ibeo_mine" ]; then
    info "install: reusing boot entry Boot$_ibeo_mine '$_ibeo_lbl' (already points at HD(1,GPT,$_ibeo_guid) $_ibeo_ldr) — no duplicate created"
    printf '%s\n' "$_ibeo_mine"
    return 0
  fi
  # a same-family entry at the CURRENT GUID with a stale loader would duplicate
  # on create — retire it first (idempotent convergence beats NVRAM pile-up)
  for _ibeo_n in $(printf '%s\n' "$_ibeo_fresh" | awk -v k="$_ibeo_kver" -v v="$_ibeo_var" -v g="$_ibeo_guid" \
    '$4 == k && $5 == v && $2 == g { print $1 }'); do
    "$_ibeo_eb" -b "$_ibeo_n" -B >/dev/null ||
      die "install: cannot replace the stale boot entry Boot$_ibeo_n (family '$_ibeo_kver $_ibeo_var' at the current GUID, stale loader)"
    info "install: replaced boot entry Boot$_ibeo_n (family '$_ibeo_kver $_ibeo_var', stale loader) — re-created against the current UKI path"
  done
  "$_ibeo_eb" -c -d "$_ibeo_disk" -p "$_ibeo_pn" -L "$_ibeo_lbl" -l "$_ibeo_ldr" >/dev/null ||
    die "install: efibootmgr -c failed — the '$_ibeo_lbl' boot entry ($_ibeo_disk -p $_ibeo_pn -> $_ibeo_ldr) could not be created"
  # Real-server evidence (Dell PowerEdge R640, 2026-09-28): the create's
  # BootOrder update persisted, but the new Boot variable was NOT yet visible
  # in the immediate post-create listing — some firmware commits the variable
  # late (NVRAM write latency; it was still absent after the FIRST bounded
  # verify — 5 attempts, 2s apart, ~10s — and present + correct when run by
  # hand minutes later; the boot then worked). The old immediate verify
  # refused fail-closed and killed an otherwise-complete install, and the
  # first retry bound was still too tight for that firmware. Bounded backoff
  # (raised again, 2026-10-03 R640 evidence: an entry took >4 min to surface
  # and the 24-attempt bound died an otherwise-complete install): up to
  # ALPINE_FDE_BOOTENTRY_RETRY_MAX attempts (default 48, ~8 min at the 10s
  # default sleep — the count seam for slow firmware), each re-verifying the
  # SAME label + GUID + loader match (inst_bootentry_find), before declaring
  # failure.
  _ibeo_try=0
  while :; do
    _ibeo_fresh=$("$_ibeo_eb" -v 2>/dev/null | inst_bootentry_parse)
    _ibeo_mine=$(inst_bootentry_find "$_ibeo_fresh" "$_ibeo_guid" "$_ibeo_lcldr" \
      "$_ibeo_kver" "$_ibeo_var" "$_ibeo_lclbl")
    [ -n "$_ibeo_mine" ] && break
    _ibeo_try=$((_ibeo_try + 1))
    [ "$_ibeo_try" -ge "${ALPINE_FDE_BOOTENTRY_RETRY_MAX:-48}" ] && break
    warn "install: the '$_ibeo_lbl' entry is not in the efibootmgr listing yet (attempt $_ibeo_try/${ALPINE_FDE_BOOTENTRY_RETRY_MAX:-48}) — likely firmware NVRAM write latency (Dell); retrying"
    sleep "${ALPINE_FDE_BOOTENTRY_RETRY_SLEEP:-10}"
  done
  [ -n "$_ibeo_mine" ] ||
    die "install: the '$_ibeo_lbl' boot entry was created but is not in the efibootmgr listing after ${ALPINE_FDE_BOOTENTRY_RETRY_MAX:-48} attempts — refusing to guess the entry number (firmware NVRAM write latency; the R640 needed >50s and up to ~2min — the ESP fallback loader still boots the UKIs meanwhile; re-running the install converges idempotently)"
  info "install: created boot entry Boot$_ibeo_mine '$_ibeo_lbl' -> HD(1,GPT,$_ibeo_guid) $_ibeo_ldr"
  printf '%s\n' "$_ibeo_mine"
  return 0
}

# inst_bootentry_family_cleanup GUID — delete every stale family entry:
# kver+variant entries NOT at GUID (dead/old partition GUID — boots "Boot
# Failed"), the LEGACY pre-two-UKI entries, and the RETIRED SERIAL entries
# (the two-UKI shape — serial-labeled family entries at ANY GUID, plus
# entries whose loader still names a -serial.efi at the CURRENT GUID; the
# serial NVRAM lane is retired — the NVRAM carries default entries only, the
# serial UKI is one-shot via UefiTarget). A retired-serial delete failure is
# a warn (the entry still boots a staged UKI — never fatal), unlike the
# stale-GUID default delete (fail-closed die). Runs in the CALLER'S shell
# (here-doc, not a pipe) so the fail-closed die is real.
inst_bootentry_family_cleanup() {
  _ibfc_guid=$1
  _ibfc_eb=$(inst_efibootmgr)
  _ibfc_list=$("$_ibfc_eb" -v 2>/dev/null | inst_bootentry_parse)
  while IFS=' ' read -r _ibfc_n _ibfc_g _ibfc_l _ibfc_k _ibfc_v; do
    [ -n "${_ibfc_n:-}" ] || continue
    case $_ibfc_l in
    *-serial.efi)
      # a retired SERIAL loader (even under a hand-edited/foreign label) at
      # the CURRENT GUID — swept; dead-GUID entries fall through to the
      # branches below
      if [ "$_ibfc_g" = "$_ibfc_guid" ]; then
        if "$_ibfc_eb" -b "$_ibfc_n" -B >/dev/null 2>&1; then
          info "install: deleted retired serial boot entry Boot$_ibfc_n (loader $_ibfc_l; the serial NVRAM lane is retired — UefiTarget one-shot)"
        else
          warn "install: cannot delete the retired serial boot entry Boot$_ibfc_n (loader $_ibfc_l) — it still boots the staged serial UKI (re-run converges)"
        fi
        continue
      fi
      ;;
    esac
    case $_ibfc_k in
    -) continue ;; # foreign entry — never touched
    LEGACY)
      if "$_ibfc_eb" -b "$_ibfc_n" -B >/dev/null 2>&1; then
        info "install: deleted legacy boot entry Boot$_ibfc_n (pre-two-UKI 'Alpine FDE' entry; the firmware now loads the UKIs directly)"
      else
        warn "install: cannot delete the legacy boot entry Boot$_ibfc_n ('Alpine FDE') — it still boots the retired boot-manager path (re-run converges)"
      fi
      continue
      ;;
    serial)
      # the RETIRED serial-labeled family — swept at ANY GUID (the current
      # one included); the serial UKI file stays on the ESP for UefiTarget
      if "$_ibfc_eb" -b "$_ibfc_n" -B >/dev/null 2>&1; then
        info "install: deleted retired serial boot entry Boot$_ibfc_n ('$_ibfc_k $_ibfc_v'; the serial NVRAM lane is retired — UefiTarget one-shot)"
      else
        warn "install: cannot delete the retired serial boot entry Boot$_ibfc_n ('$_ibfc_k $_ibfc_v') — it still boots the staged serial UKI (re-run converges)"
      fi
      continue
      ;;
    esac
    if [ "$_ibfc_g" != "$_ibfc_guid" ]; then
      "$_ibfc_eb" -b "$_ibfc_n" -B >/dev/null ||
        die "install: cannot delete the stale boot entry Boot$_ibfc_n (label family '$_ibfc_k $_ibfc_v', partition GUID differs from the ESP's $_ibfc_guid — a stale GUID boots \"Boot Failed\")"
      info "install: deleted stale boot entry Boot$_ibfc_n (family '$_ibfc_k $_ibfc_v', old partition GUID) — the entry now resolves against the current ESP ($_ibfc_guid)"
    fi
  done <<EOF
$_ibfc_list
EOF
  return 0
}

# _ibe_reorder_front EB FIRST FRESH — place FIRST at the FRONT of BootOrder
# (the default entry of the ensured kver; the retained older versions keep
# their relative order behind, entries the listing has but BootOrder never
# mentioned appended defensively)
_ibe_reorder_front() {
  _ibr_eb=$1
  _ibr_first=$2
  _ibr_fresh=$3
  _ibr_all=$(printf '%s\n' "$_ibr_fresh" | awk 'NF { print $1 }' | tr '\n' ' ')
  _ibr_obo=$("$_ibr_eb" -v 2>/dev/null | awk '/^BootOrder:/ { sub(/^BootOrder:[ \t]*/, ""); print tolower($0) }' | tr ',' ' ')
  _ibr_new=" $_ibr_first "
  for _ibr_n in $_ibr_obo $_ibr_all; do
    if [ "$_ibr_n" = "$_ibr_first" ]; then continue; fi
    case " $_ibr_new " in
    *" $_ibr_n "*) continue ;;
    esac
    case " $_ibr_all " in
    *" $_ibr_n "*) _ibr_new="$_ibr_new$_ibr_n " ;;
    esac
  done
  _ibr_new=${_ibr_new% }
  _ibr_new=${_ibr_new# }
  _ibr_csv=$(printf '%s' "$_ibr_new" | tr ' ' ',')
  "$_ibr_eb" -o "$_ibr_csv" >/dev/null ||
    die "install: efibootmgr -o $_ibr_csv failed — the default boot entry (Boot$_ibr_first) could not be placed at the front of BootOrder"
  return 0
}

# inst_bootentry_prune KEEP-KVER... — sweep the NVRAM so it never outlives the
# ESP keep set (the default-only invariant: at most 3 kernel versions = at
# most 3 entries, oldest pruned first): deletes the boot entries of every kver
# NOT in the keep-set arguments plus any LEGACY and RETIRED SERIAL entries
# (the serial NVRAM lane is retired — swept regardless of the keep set; the
# NVRAM carries default entries only), then rewrites BootOrder over the
# survivors (relative order preserved). Called from the build's prune step,
# `kernel prune` and `kernel remove`. Best-effort SKIP (warn) when NVRAM is
# unreachable — the ESP prune must not fail because a build context has no
# efivarfs; the next ensure/prune on the machine converges.
inst_bootentry_prune() {
  _ibp_eb=$(inst_efibootmgr)
  if ! command -v "$_ibp_eb" >/dev/null 2>&1 && [ ! -f "$_ibp_eb" ]; then
    warn "install: efibootmgr not available — skipping the NVRAM boot-entry sweep (entries for pruned kernels remain until the next build on the machine)"
    return 0
  fi
  if ! inst_bootentry_efivars_ok; then
    warn "install: no EFI variable support — skipping the NVRAM boot-entry sweep (entries for pruned kernels remain until the next build on the machine)"
    return 0
  fi
  _ibp_list=$("$_ibp_eb" -v 2>/dev/null | inst_bootentry_parse)
  while IFS=' ' read -r _ibp_n _ibp_g _ibp_l _ibp_k _ibp_v; do
    [ -n "${_ibp_n:-}" ] || continue
    _ibp_drop=0
    case $_ibp_k in
    LEGACY) _ibp_drop=1 ;;
    serial) _ibp_drop=1 ;; # the RETIRED serial lane — swept regardless of the keep set
    -) _ibp_drop=0 ;;
    *)
      _ibp_hit=0
      for _ibp_w in "$@"; do
        [ "$_ibp_k" = "$_ibp_w" ] && _ibp_hit=1 && break
      done
      [ "$_ibp_hit" -eq 0 ] && _ibp_drop=1
      ;;
    esac
    case $_ibp_l in
    *-serial.efi) _ibp_drop=1 ;; # a retired SERIAL loader — swept even under a foreign/edited label
    esac
    if [ "$_ibp_drop" -eq 1 ]; then
      if "$_ibp_eb" -b "$_ibp_n" -B >/dev/null 2>&1; then
        case $_ibp_l in
        *-serial.efi) info "install: pruned boot entry Boot$_ibp_n ('$_ibp_k $_ibp_v') — the retired serial lane (NVRAM carries default entries only)" ;;
        *) info "install: pruned boot entry Boot$_ibp_n ('$_ibp_k $_ibp_v') — its kernel is outside the keep set" ;;
        esac
      else
        warn "install: cannot prune boot entry Boot$_ibp_n ('$_ibp_k $_ibp_v') — orphaned NVRAM entry remains (a re-run converges)"
      fi
    fi
  done <<EOF
$_ibp_list
EOF
  # BootOrder over the survivors only, RELATIVE ORDER PRESERVED (a deleted
  # entry may still be listed in BootOrder; the firmware tolerates it, but the
  # order should stay clean — and the prune must never promote an arbitrary
  # survivor to the front; the build's ensure owns the boot priority)
  _ibp_fresh=$("$_ibp_eb" -v 2>/dev/null | inst_bootentry_parse)
  _ibp_all=$(printf '%s\n' "$_ibp_fresh" | awk 'NF { print $1 }' | tr '\n' ' ')
  _ibp_obo=$("$_ibp_eb" -v 2>/dev/null | awk '/^BootOrder:/ { sub(/^BootOrder:[ \t]*/, ""); print tolower($0) }' | tr ',' ' ')
  _ibp_new=''
  for _ibp_n in $_ibp_obo $_ibp_all; do
    case " $_ibp_all " in
    *" $_ibp_n "*) ;;
    *) continue ;;
    esac
    case " $_ibp_new " in
    *" $_ibp_n "*) continue ;;
    esac
    _ibp_new="$_ibp_new$_ibp_n "
  done
  _ibp_new=${_ibp_new% }
  if [ -n "$_ibp_new" ]; then
    _ibp_csv=$(printf '%s' "$_ibp_new" | tr ' ' ',')
    "$_ibp_eb" -o "$_ibp_csv" >/dev/null ||
      warn "install: efibootmgr -o $_ibp_csv failed — BootOrder still names the pruned entries (the firmware skips them; a re-run converges)"
  fi
  return 0
}

# inst_bootentry_ensure_best_effort ESP_MNT KVER — the BUILD-lane spelling of
# the NVRAM pair ensure (the install record's inst_bootentry_ensure stays
# fail-closed — it is the install's last line; the build's ensure is
# BEST-EFFORT by design: after the ESP/manifest pair is consistent, a
# firmware-administration concern must never fail a build). Every
# resolution/precondition failure — no efivarfs, no efibootmgr, the ESP mount
# not resolvable to a partition device (test containers, offline builds), no
# baseline esp_partuuid — is a loud warn + skip; the next build ON the machine
# converges. Only run when the guard passes does the real ensure execute.
inst_bootentry_ensure_best_effort() {
  _ibem_mnt=$1
  _ibem_kver=$2
  _ibem_eb=$(inst_efibootmgr)
  if ! command -v "$_ibem_eb" >/dev/null 2>&1 && [ ! -f "$_ibem_eb" ]; then
    warn "kernel build: efibootmgr not available — skipping the NVRAM boot-entry pair for $_ibem_kver (the install/build on the machine converges)"
    return 0
  fi
  if ! inst_bootentry_efivars_ok; then
    warn "kernel build: no EFI variable support — skipping the NVRAM boot-entry pair for $_ibem_kver"
    return 0
  fi
  # the ESP partition device from the LIVE mount table (in-chroot /proc is
  # bound by the install record; a context without the ESP mounted — unit
  # sandboxes — cannot resolve it and skips)
  _ibem_dev=''
  for _ibem_m in "$_ibem_mnt" "$_ibem_mnt/"; do
    _ibem_dev=$(awk -v m="$_ibem_m" '$2 == m { print $1; exit }' /proc/mounts 2>/dev/null)
    [ -n "$_ibem_dev" ] && break
  done
  if [ -z "$_ibem_dev" ] || ! inst_part_split "$_ibem_dev" >/dev/null 2>&1; then
    warn "kernel build: the ESP mount $_ibem_mnt is not resolvable to a partition device — skipping the NVRAM boot-entry pair for $_ibem_kver"
    return 0
  fi
  if (inst_bootentry_ensure "$_ibem_dev" "$_ibem_mnt" "$_ibem_kver"); then
    return 0
  fi
  warn "kernel build: the NVRAM boot-entry pair for $_ibem_kver could not be ensured (see above) — the ESP/manifest pair is consistent; re-run the build on the machine to converge"
  return 0
}

install_usage() {
  cat >&2 <<'EOF'
Usage: alpine-fde install --disk DEVICE [--disk DEVICE2 ...] [--fs btrfs|ext4]
                          [--bcache CACHE_DEV] [--swap [SIZE]] [--no-reboot]
                          [--yes]

Unattended-until-reboot Stage-1 install (§9.1/ADR-20 amended; unattended
except for the §9.1 step 4 credential-ceremony prompts): firmware SetupMode
gate (SetupMode=1 for the NVRAM write flow — clear the vendor PK in BIOS
first — OR a platform key already enrolled, which takes the
deferred-enrollment mode: no NVRAM writes, the release certificate is
imported via the firmware UI after the install),
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
metadata) so the
credential ceremony sits LAST; only the secret-dependent steps follow it
(signed UKI + boot manager via `kernel build`, PROVISIONAL TPM token sealed
into keyslot 1, Mechanism B, PCR 11 only, from the UKI's .pcrsig), then
teardown (unmount + ephemeral-key scrub) and: a direct reboot to disk when
NVRAM enrollment succeeded — or, when the firmware refused it (key material
staged to <esp>/alpine-fde-keys) or a platform key was already enrolled (the
deferred-enrollment mode: import db.cer into the EXISTING db via the firmware
UI), the manual-import instructions, an explicit
Enter confirmation, and a reboot INTO FIRMWARE SETUP (OsIndications) for the
manual key import: the first boot unlocks via the provisional token and
alpine-fde-finalize AUTO-FINALIZES under Secure Boot (§9.1 Stage 2);
`alpine-fde finalize` is the guided/crash-resume entry point (Stage 3).
The UEFI boot entry (NVRAM, "Alpine FDE - <kver> (<date>)" ->
\EFI\Linux\alpine-fde-<kver>.efi at the ESP partition's
HD(1,GPT,<guid>)) is created IN-GUEST after the build — idempotently
(same-GUID entries reused; stale-GUID, legacy and RETIRED-SERIAL entries
swept — the NVRAM carries DEFAULT entries only; the serial UKI on the ESP is
one-shot via UefiTarget, never NVRAM-enrolled), FIRST in BootOrder, and
SKIPPED with the exact manual efibootmgr command when no EFI variable
support exists (task #27: the entry used to be typed by hand on the real
server after every install).

Topologies (§4.1): --disk repeatable for Btrfs RAID1 (primary ESP+LUKS,
secondaries LUKS only); --bcache CACHE_DEV for hybrid acceleration (ESP+cache
on the cache dev, LUKS2 on /dev/bcache0, writethrough pinned); --bcache with
MULTIPLE --disk: shared cache set, one independent LUKS2 container per
/dev/bcacheN, Btrfs RAID1 pool across the members, ESP only on the cache dev.
--fs ext4 is single-disk only.

--swap [SIZE] (ADR-7 amended, default SIZE 4G): add an EPHEMERAL encrypted
swap partition as the LAST partition on the primary disk (p3 of the first
--disk; in the --bcache topologies p3 of the CACHE dev, which plays the
primary role). Each boot the OpenRC dmcrypt service creates a PLAIN dm-crypt
mapping over it with a FRESH /dev/urandom key and mkswaps it; poweroff wipes
the key from memory, leaving undecryptable ciphertext residue — NO LUKS
header ever persists. mkswap/swapon never run at install time. Hibernation
(suspend-to-disk) stays UNSUPPORTED (ADR-7).

Runner: chroot executes (default; root, live ISO, --yes required; the three
credential ceremony prompts are asked in the execution path). ALPINE_FDE_INSTALL_RUNNER
is a test/CI seam, not a user setting: qemu emits a guest script (CI artifact
job; host steps as comments) without executing anything.
Env: ALPINE_FDE_ESP_SIZE (default 512M), ALPINE_FDE_MIRROR,
ALPINE_FDE_INSTALL_MNT, ALPINE_FDE_INSTALL_USER, ALPINE_FDE_DISKS
(dispatcher-provided disk list), ALPINE_FDE_TMPDIR (ephemeral-key staging
seam, default /dev/shm), ALPINE_FDE_SWAP (dispatcher-provided global --swap:
'1' = default size, otherwise the swap partition size).
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
# substitution stays literal in the qemu emission); head and tail are `&&`-
# chained so a failed wipe aborts the plan instead of reaching make-bcache.
inst_wipe_superblocks_line() {
  printf '%s\n' "dd if=/dev/zero of=$1 bs=1M count=1 && dd if=/dev/zero of=$1 bs=1M count=1 seek=\$(( \$(blockdev --getsize64 $1) / 1048576 - 1 )) # wipe stale superblocks (head+tail): bcache refuses devices with leftover signatures"
}

# inst_sfdisk_swap_line DEV MID_NAME ESP_MIB SWAP_MIB — the --swap primary-disk
# partitioning record (ADR-7 amended, task 4): ESP p1 unchanged, the MIDDLE
# partition (MID_NAME = root on the single/raid1 primary, cache in the bcache
# topologies) sized "disk - esp - swap" at RUN time, and the EPHEMERAL SWAP as
# the LAST partition at its fixed size. The runtime arithmetic mirrors the
# wipe-superblocks record idiom above: the command substitution stays literal
# in the qemu emission and resolves at execution; the 8 MiB slack
# absorbs the GPT overhead (33 backup sectors) + 1MiB alignment so the
# fixed-size swap partition always fits. A disk too small for its layout dies
# in sfdisk — fail-closed, never a silently truncated swap.
inst_sfdisk_swap_line() {
  printf '%s\n' "printf 'label: gpt\nstart=2048, size=+${3}M, type=uefi, name=\"esp\"\ntype=linux, name=\"${2}\", size=%sM\ntype=swap, name=\"swap\", size=+${4}M\n' \"\$(( \$(blockdev --getsize64 $1 2>/dev/null || stat -c %s $1) / 1048576 - ${3} - ${4} - 8 ))M\" | sfdisk $1 # ADR-7 (--swap): ephemeral swap is the LAST partition (plain dm-crypt, fresh /dev/urandom key per boot — NO LUKS header persists)"
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
# rootN mappings (glob — the bcache-multi/raid1 naming), root-crypt (the
# single/bcache primary) AND swap (the --swap ephemeral crypt mapping a
# previous --swap install may have left open); the mapper NAME is stripped
# from the node path before close. Unmatched glob entries fail the [ -e ]
# guard (no-op).
inst_reset_mapper_line() {
  printf '%s\n' "for m in $1/root[0-9]* $1/root-crypt $1/swap; do [ -e \"\$m\" ] || continue; cryptsetup close \"\${m#$1/}\" && echo \"alpine-fde: info: reset: closed stale mapper \$m\" || echo \"alpine-fde: warn: reset: could not close stale mapper \$m\"; done || :"
}

# inst_reset_bcache_line SYSFS_BCACHE — guarded stop of every LIVE bcache
# set: the glob matches set DIRECTORIES only (the `register` control file is
# skipped); each set's own UUID is echoed into ITS stop file.
inst_reset_bcache_line() {
  printf '%s\n' "for d in $1/*/; do [ -f \"\${d}stop\" ] || continue; u=\"\${d%/}\"; echo \"\${u##*/}\" > \"\$u/stop\" && echo \"alpine-fde: info: reset: stopped live bcache set \${u##*/}\" || echo \"alpine-fde: warn: reset: could not stop bcache set \${u##*/}\"; done || :"
}

# --- plan records (item 17d: DIRECT EXECUTION — no accumulator) --------------
# The two-phase accumulator (SPC_PLAN / inst_plan_add / inst_plan_run /
# inst_execute_plan) is RETIRED: every record EXECUTES at the point of
# decision via inst_exec — the chroot runner runs it now (host records via
# `eval` in THIS shell, guest records via `chroot <mnt> sh -c`), the qemu
# runner appends it to the guest script (guest records executable, host
# records as `# HOST:` comments for the CI harness). The emitted script is
# BYTE-IDENTICAL to the retired accumulator's emission (pinned against
# fixtures/install-guest-script/golden-single-btrfs.sh in
# tests/unit/install_qemu_emit.sh). Guest cmds must be single-line shell;
# file drops are executed/emitted at decision time (order-independent).

# inst_emit_out — the qemu guest-script path (test seam
# ALPINE_FDE_INSTALL_SCRIPT; the CI artifact job consumes it)
inst_emit_out() { printf '%s\n' "${ALPINE_FDE_INSTALL_SCRIPT:-/tmp/alpine-fde-install-guest.sh}"; }

# inst_exec KIND CMD... — execute ONE record at the point of decision (17d).
# chroot: host records eval in THIS shell — the §9.1 step 4 ceremony prompts
# read the real stdin directly (the retired fd3 plan-file indirection existed
# only to keep the read loop from eating plan lines); guest records run via
# `chroot <mnt> /usr/bin/env -u ALPINE_FDE_DISK_PASSPHRASE /bin/sh -c` with
# the same fail-closed die on failure. qemu: nothing executes — the record is
# appended to the guest script (header written on the FIRST record; the
# retired accumulator wrote the identical bytes in one shot at execute time).
# L-04a + WR-02: armed on the FIRST record — a die mid-plan leaves NOTHING
# behind: one combined EXIT trap scrubs the staged ephemeral key-file AND the
# in-target release-passphrase seam file (blocker #8/#9, best-effort), then
# tears the H-02 binds down best-effort (never masking the real exit code;
# skipped when we died before the mountpoint was even resolved).
inst_exec() {
  _iex_kind=$1
  shift
  case $(inst_runner) in
  chroot)
    if [ -z "${_IEX_TRAP_ARMED:-}" ]; then
      _IEX_TRAP_ARMED=1
      trap '
                rm -f "${_ime_kf:-}" 2>/dev/null
                if [ -n "${_im_mnt:-}" ]; then
                    # boot-lane finding #20: CHILD MOUNTS FIRST — the efivars
                    # bind hangs under /mnt/sys, so the parent must unmount
                    # after it (parent-first is EBUSY on every real install).
                    umount "$_im_mnt/sys/firmware/efi/efivars" 2>/dev/null || :
                    umount "$_im_mnt/dev" "$_im_mnt/sys" "$_im_mnt/proc" 2>/dev/null || :
                fi
            ' EXIT
    fi
    if [ "$_iex_kind" = "host" ]; then
      info "host: $*"
      # shellcheck disable=SC2086  # plan lines are shell
      eval "$*" || die "install: host step failed: $*"
    else
      info "guest: $*"
      # shellcheck disable=SC2086
      # L-04b: strip the legacy passphrase variable at the boundary —
      # chroot(1) passes the parent environment to the guest (the
      # unattended flow stages no operator passphrase at all; the
      # strip stays as defense against stale operator environments)
      chroot "$(inst_mnt)" /usr/bin/env -u ALPINE_FDE_DISK_PASSPHRASE /bin/sh -c "$*" ||
        die "install: guest step failed: $*"
    fi
    ;;
  qemu)
    _iex_out=$(inst_emit_out)
    if [ -z "${_IEX_EMIT_STARTED:-}" ]; then
      _IEX_EMIT_STARTED=1
      printf '#!/bin/sh -ex\n# alpine-fde install — guest-side plan (generated; runner=qemu)\n# Host-side steps are comments; the CI harness executes them itself.\nset -eux\n' >"$_iex_out"
    fi
    if [ "$_iex_kind" = "guest" ]; then
      printf '%s\n' "$*" >>"$_iex_out"
    else
      printf '# HOST: %s\n' "$*" >>"$_iex_out"
    fi
    ;;
  esac
  return 0
}

# inst_emit_finish — the tail of the retired inst_execute_plan: chroot disarms
# the combined L-04a/WR-02 trap (the caller then scrubs the staged secrets
# explicitly); qemu closes the guest script (chmod 700 + the stderr pointer).
inst_emit_finish() {
  case $(inst_runner) in
  chroot)
    trap - EXIT
    ;;
  qemu)
    _ief_out=$(inst_emit_out)
    chmod 700 "$_ief_out"
    printf 'alpine-fde: guest install script written: %s\n' "$_ief_out" >&2
    ;;
  esac
  return 0
}

# inst_plan_write RELPATH LINE... — drop a file into the target root at the
# point of decision. Config drops keep §3.3 plan order (after mount, before
# the first in-guest apk use; EXCEPTION — the /etc/apk/repositories drop
# deliberately PRECEDES the apk populate, real-install defect 6: apk resolves
# against the TARGET's repositories): the chroot runner executes the drop as a
# HOST step now — safe because the mount records precede every drop in
# decision order (the retired accumulator deferred them as plan records for
# the same reason, G-I1); qemu emits a guest printf line.
inst_plan_write() {
  _ipw_p=$1
  shift
  _ipw_cmd="printf '%s\\n'"
  for _ipw_l in "$@"; do
    _ipw_q=$(printf '%s' "$_ipw_l" | sed "s/'/'\\\\''/g")
    _ipw_cmd="$_ipw_cmd '$_ipw_q'"
  done
  case $(inst_runner) in
  chroot)
    inst_exec host "mkdir -p $(inst_mnt)${_ipw_p%/*} && $_ipw_cmd >$(inst_mnt)$_ipw_p"
    ;;
  qemu)
    # guest-side write, single command line; single-quote escape each line
    inst_exec guest "$_ipw_cmd >$_ipw_p"
    ;;
  esac
  return 0
}

# inst_inittab_getty_cmd INITTAB — the guarded, IDEMPOTENT guest record that
# ensures a busybox getty on ttyS0 (serial console — `console=ttyS0,115200` is
# now emitted BY DEFAULT in the dual-console cmdline, no EXTRA needed):
# appends the respawn line ONLY when no ttyS0 line
# exists yet (crash-resume / re-run safe; an operator's own ttyS0 line wins).
# REAL-SERVER BLOCKER (headless, Dell PowerEdge R640 2026-09-28): the guest
# shipped no serial getty, so on a headless server the operator had NO way
# into the booted system (the installer only MENTIONED console=ttyS0 in the
# cmdline docs).
inst_inittab_getty_cmd() {
  printf '%s\n' "grep -q '^ttyS0:' $1 2>/dev/null || printf '%s\\n' '# alpine-fde: serial console getty (headless access — real-server blocker, Dell PowerEdge R640 2026-09-28)' 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' >>$1 # blocker: headless serial getty (idempotent guarded append)"
}

# inst_sshd_config_cmd SSHD_CONFIG — the guarded, IDEMPOTENT guest record that
# ensures the headless-access sshd policy: PermitRootLogin no (root login via
# SSH stays DISABLED by design — the admin path is the §9.1 step 4 ceremony
# user account, whose password is set in-chroot) + PasswordAuthentication yes
# (password login for that account; key-only auth is not provisioned by the
# install). Appends a marked block ONLY when the marker is absent. The docs'
# "openssh-server (optional)" opinion (docs/Architecture.md §3.1) is
# OVERRIDDEN to REQUIRED by the same R640 headless blocker.
inst_sshd_config_cmd() {
  printf '%s\n' "grep -q 'alpine-fde: headless access' $1 2>/dev/null || printf '%s\\n' '' '# alpine-fde: headless access (real-server blocker, Dell PowerEdge R640 2026-09-28) — root SSH stays disabled; the ceremony account is the login path' 'PermitRootLogin no' 'PasswordAuthentication yes' >>$1 # blocker: sshd headless access (idempotent guarded append)"
}

# inst_dmcrypt_conf_cmd CONF_FILE SWAP_PART_DEV — the guarded, IDEMPOTENT
# guest record enabling the --swap ephemeral crypt volume in the TARGET's
# /etc/conf.d/dmcrypt (the OpenRC dmcrypt service's config — Alpine's OpenRC
# world has NO crypttab consumer outside the initramfs, and the swap must
# never enter the initramfs crypttab, see the ADR-7 block above). Each boot
# the dmcrypt service creates a PLAIN dm-crypt mapping (no LUKS header is
# ever written) keyed from /dev/urandom, mkswaps it (dmcrypt's default
# pre_mount for swap sections) and the boot `swap` service then swapon's
# /dev/mapper/swap (fstab line emitted separately). Poweroff drops the key
# from kernel memory — the on-disk ciphertext is undecryptable residue
# (Approach A, ADR-7 amended). Appends a marked block ONLY when the marker is
# absent (crash-resume / re-run safe; the package default conf coexists).
inst_dmcrypt_conf_cmd() {
  printf '%s\n' "grep -q 'alpine-fde: ephemeral crypt swap' $1 2>/dev/null || printf '%s\\n' '# alpine-fde: ephemeral crypt swap (ADR-7 amended, --swap: fresh /dev/urandom key per boot, wiped on poweroff; hibernation unsupported)' \"swap='swap'\" \"source='$2'\" \"options='-c aes-xts-plain64 -s 512 -d /dev/urandom'\" >>$1 # ADR-7: ephemeral swap (idempotent guarded append; dmcrypt default pre_mount='mkswap')"
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
# §3.1), openssh (headless access — real-server blocker, Dell PowerEdge R640
# 2026-09-28: WITHOUT it a headless server has NO way into the booted guest;
# sshd is enabled + pinned PermitRootLogin no in the §9.1 step 1 records), and
# ukify-kernel-hook (fires /etc/kernel-hooks.d on kernel
# transactions, §8.3/ADR-19). Topology-conditional: btrfs-progs by default,
# e2fsprogs for --fs ext4, bcache-tools when --bcache is given.
# NO zram-init (item 26a, ADR-7 AMENDED): zram is removed from the design —
# the queued --swap feature (task 4) is the only swap story going forward.
install_package_list() {
  # efibootmgr (task #27): the NVRAM boot entry ("Alpine FDE" -> the ESP
  # partition's HD(1,GPT,<guid>) -> \EFI\BOOT\BOOTX64.EFI) is created IN-GUEST
  # after the build (inst_bootentry_ensure) — the target must ship the tool
  # (efivar-libs rides as its apk dependency), and the mirror closure derives
  # from this list, so the pair can never under-approximate.
  _ipl='cryptsetup systemd-boot systemd-efistub ukify ukify-kernel-hook py3-pefile mkinitfs linux-lts tpm2-tools tpm2-tss-policy tpm2-tss-tcti-device sbsigntool efibootmgr openssl jq doas efitools openssh'
  case $(inst_root_fs) in
  ext4) _ipl="$_ipl e2fsprogs" ;;
  *) _ipl="$_ipl btrfs-progs" ;;
  esac
  if [ "$(inst_bcache)" = "1" ]; then
    # bcache-tools-udev (real-server blocker #14b): Alpine splits the udev
    # integration into a -udev SUBPACKAGE — without it /usr/lib/udev/rules.d/
    # 69-bcache.rules (+ bcache-register/probe-bcache helpers) never lands in
    # the target and the initrd audit's rules requirement can never pack.
    # NOTE: any future 'required rules file' must check the -udev subpackage,
    # not just the base package.
    _ipl="$_ipl bcache-tools bcache-tools-udev"
  fi
  if [ "$(inst_swap_enabled)" = "1" ]; then
    # ADR-7 amended (--swap): cryptsetup-openrc ships the OpenRC `dmcrypt`
    # service the ephemeral swap activation rides on — pinned explicitly so
    # the rc-update enable AFTER this txn can never hit the real-server
    # failure #2 class ("service dmcrypt does not exist").
    _ipl="$_ipl cryptsetup-openrc"
  fi
  printf '%s\n' "$_ipl"
}

# inst_live_tool_pairs — the LIVE-env tool requirements of the §9.1 preflight
# (the binary:package pairs the live-env require_pkgs probe consumes,
# SINGLE SOURCE): the live ISO may lack any
# of these tools, in which case the installer apk-adds the package from
# ALPINE_FDE_MIRROR. Exposed as data so consumers that PROVISION the live
# environment — the pinned local mirror, tests/lib/local-mirror.sh's
# mirror_package_list — derive the SAME set the preflight may install (the
# closure must cover it, or a real install dies at the first preflight probe;
# boot-lane finding #4: the virt ISO lacks sfdisk/lsblk, and the closure had
# no util-linux). Topology-conditional exactly like the preflight checks.
# Alpine 3.24 util-linux SPLIT (real R640 install, 2026-09-28): util-linux
# 2.42.3 no longer ships the lsblk/sfdisk binaries — upstream split them into
# standalone packages (pkgs.alpinelinux.org contents DB, v3.24/main: /bin/lsblk
# ships in `lsblk`, /sbin/sfdisk in `sfdisk`). The old sfdisk:util-linux /
# lsblk:util-linux pairs apk-added a package that does not provide the probed
# binary — a non-media live env dies at the first preflight probe (the ISO
# media itself still carried the tools, masking the split on the real run).
inst_live_tool_pairs() {
  printf '%s\n' apk:apk-tools sfdisk:sfdisk cryptsetup:cryptsetup \
    mkfs.vfat:dosfstools lsblk:lsblk openssl:openssl
  case $(inst_root_fs) in
  ext4) printf '%s\n' mkfs.ext4:e2fsprogs ;;
  *) printf '%s\n' mkfs.btrfs:btrfs-progs ;;
  esac
  if [ "$(inst_bcache)" = "1" ]; then
    # blocker #14b (main): bcache-tools-udev carries the udev integration
    # (69-bcache.rules + bcache-register/probe-bcache) — TARGET-side only
    # (delivered by the in-chroot apk txn; NO host tool to probe). It is
    # deliberately NOT a live pair: every line here MUST be binary:package
    # (require_pkgs probes the binary — bcache-tools-udev ships only rules +
    # helpers, so a bare entry dies the live install at the first probe,
    # real-server blocker #19). The package stays pinned in the MIRROR
    # closure (tests/lib/local-mirror.sh mirror_package_list).
    printf '%s\n' make-bcache:bcache-tools
  fi
}

# inst_setupmode_gate — G-IL2 (§9.1 preflight, UserGuide §1): the FIRST
# preflight check, BEFORE any disk mutation. TWO firmware states are supported:
#   SetupMode==1 (Setup Mode)            the NVRAM write flow (db reset +
#                                        release+vendor rebuild -> KEK -> PK)
#   SetupMode==0 WITH a platform PK      the DEFERRED-ENROLLMENT mode (DECIDED
#                                        Samuel, 2026-09-28, real Dell
#                                        PowerEdge R640): factory or custom
#                                        PK stays; the release certificate is
#                                        imported into the existing db via
#                                        the firmware UI after the install
#                                        (fw_auth_enroll stages the .cer set
#                                        and makes NO NVRAM writes)
# Anything else (SetupMode==0 with NO PK — a state no real firmware reports;
# SetupMode variable absent) fails closed 64 with the operator fix. Runs over
# the ALPINE_FDE_EFIVARS_DIR seam.
inst_setupmode_gate() {
  _isg_dir=$(fw_efivars_dir)
  [ -d "$_isg_dir" ] ||
    die "install: no efivarfs at $_isg_dir — cannot verify firmware Setup Mode (§9.1 preflight: boot the installer media in UEFI mode)"
  fw_var_present "$_isg_dir" SetupMode ||
    die "install: SetupMode variable absent at $_isg_dir — not a setup-mode UEFI environment (§9.1 preflight)"
  _isg_state=$(fw_sb_state || true)
  _isg_setup=${_isg_state#*setup_mode=}
  _isg_setup=${_isg_setup%% *}
  if [ "$_isg_setup" != "1" ]; then
    if [ "$_isg_setup" = "0" ] && fw_var_present "$_isg_dir" PK; then
      info "install: a platform key is already enrolled ($_isg_state) — deferred-enrollment mode: the installer makes NO NVRAM writes; the release certificate is imported via the firmware setup UI after the install"
      return 0
    fi
    die "install: firmware is NOT in Setup Mode ($_isg_state) — clear the vendor PK in BIOS setup first, or keep the platform key enrolled (deferred-enrollment mode: the release certificate is imported via the firmware UI) (§9.1 preflight)"
  fi
  info "install: firmware Setup Mode confirmed ($_isg_state)"
  return 0
}

# inst_preflight DISKS... — fail-closed checks for a real run. ORDER IS
# NORMATIVE (§9.1): the firmware Setup Mode gate FIRST (zero disk mutation
# before it), then environment/tool checks.
inst_preflight() {
  inst_setupmode_gate
  inst_cmdline_extra_check
  [ "$(id -u)" = "0" ] || die "install: must run as root (live ISO environment)"
  for _if_disk in "$@"; do
    [ -b "$_if_disk" ] || [ -f "$_if_disk" ] || die "install: target disk not found: $_if_disk"
  done
  # §13 R640 2026-09-29: firmware TPM settings can ship SHA-1-only (Dell
  # Tpm2Algorithm=SHA1) — the install would run to completion and only DIE at
  # the reseal/finalize, when the SHA-256 PCR bank turns out missing. A
  # READABLE TPM with no sha256 bank fails loud HERE, before any disk
  # mutation, with the exact firmware remedy; an unreadable/absent TPM (unit
  # tests, TPM-less hosts) only warns — the reseal/finalize still gates.
  _if_pcrbanks=$(tpm getcap pcrs 2>/dev/null) || _if_pcrbanks=''
  case $_if_pcrbanks in
    ''|*sha256*) warn "install: SHA-256 PCR bank UNVERIFIED (no TPM read) — confirm the firmware enables the SHA-256 bank before resealing (§13)" ;;
    *) die "install: no SHA-256 PCR bank — the TPM selects only: $_if_pcrbanks — fix in firmware setup (TPM settings -> enable the SHA-256 PCR bank / TPM2 Algorithm Selection = SHA256) and reboot BEFORE installing (the seal is SHA-256 and cannot be created without it)" ;;
  esac
  # hooks/ ships the Alpine layout (ADR-13/ADR-19, G-C16): kernel-hooks.d
  # build/remove hooks → /etc/kernel-hooks.d/, the mkinitfs unseal hook +
  # features.d entry → /etc/mkinitfs/, the apk trigger → /etc/apk/triggers/,
  # the first-boot AUTO-FINALIZER oneshot → /etc/init.d/ (ADR-20 amended
  # Stage 2: the service runs the non-interactive completion when
  # provisional-booted under Secure Boot; `alpine-fde finalize` remains the
  # guided/crash-resume entry point, Stage 3), and the FR-6 boot-time audit
  # oneshot → /etc/init.d/ + its login alert hook → /etc/profile.d/
  # User decision item 9: the AUTO-SNAPSHOT apk trigger
  # (apk/triggers/alpine-fde-snapshot.trigger → /etc/apk/triggers/, §4) and
  # its keep-N retention default (conf.d/alpine-fde-snapshot →
  # /etc/conf.d/alpine-fde-snapshot) ride the SAME staging.
  for _if_h in kernel-hooks.d/alpine-fde-build.hook \
    kernel-hooks.d/alpine-fde-remove.hook \
    mkinitfs/alpine-fde-unseal.sh mkinitfs/features.d/alpine-fde.files \
    mkinitfs/features.d/alpine-fde.modules \
    apk/triggers/alpine-fde.trigger apk/triggers/alpine-fde-snapshot.trigger \
    conf.d/alpine-fde-snapshot openrc/alpine-fde-finalize \
    openrc/alpine-fde-audit profile.d/alpine-fde.sh; do
    [ -f "$(inst_hooks_dir)/$_if_h" ] || die "install: hook template missing: $(inst_hooks_dir)/$_if_h"
  done
  # §13 host tool set — topology-conditional. apk populates the rootfs;
  # openssl generates the ephemeral install key; sbsign/ukify are NOT
  # host-required (the boot manager + UKI are built + signed IN-CHROOT by
  # kernel build, §9.1 step 5).
  # shellcheck disable=SC2046  # deliberate word split: the bin:pkg pairs never contain spaces
  require_pkgs $(inst_live_tool_pairs)
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
    elif awk -v h="$_if_mhost" 'f { next } { for (_i = 2; _i <= NF; _i++) if ($_i == h) { f = 1; exit } } END { exit f ? 0 : 1 }' /etc/hosts 2>/dev/null; then
      # boot-lane finding #7: a hosts-based mirror name is LEGITIMATE — the
      # actual consumer (apk's fetcher over musl getaddrinfo) consults
      # /etc/hosts, so nslookup-only is stricter than the real resolver chain
      # and false-negatives a working hosts-based setup (the s23 canary pins
      # the mirror name in the live env's /etc/hosts). Loud record; the name
      # must still reach the IN-CHROOT transaction — the plan seeds the
      # target's /etc/hosts alongside resolv.conf (item 26b).
      info "install: live env resolves the mirror host $_if_mhost (via /etc/hosts — hosts-based mirror name, no resolver consulted)"
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
# in the main shell — inst_exec's combined L-04a/WR-02 trap replaces
# it mid-plan and keeps scrubbing via the ${_ime_kf:-} carrier).
# Sets the global _IME_KEYFILE.
inst_stage_ephemeral_key() {
  _IME_KEYFILE=''
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
  # inst_exec's combined L-04a/WR-02 trap replaces it mid-plan, and
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
# staged at generate time (real-server blocker #8) so `kernel build`'s
# keys_unlock can decrypt release.pem — never argv, never the log, scrubbed
# with the ephemeral key (I1). qemu emits the records as inert text —
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
  fde_strip_trailing_cr _ipl_val
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
# (passphrase_floor_ok from lib/cmd/passwd.sh, lazily sourced): >=12 chars
# across >=3 character classes, or >=16 chars.
inst_ceremony_floor() {
  # shellcheck disable=SC1090
  command -v passphrase_floor_ok >/dev/null 2>&1 ||
    . "${ALPINE_FDE_CMD_DIR:-$(sp_cmd_dir)}/passwd.sh"
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
#   1. extract the .pcrsig from the just-built UKI (stage-1 `kernel build`
#      output on the ESP; objcopy section extraction, pcrsign contract)
#   2. per container: seal_provisional (Mechanism B, PCR 11 only) -> token
#      JSON; luksAddKey the sealed random passphrase into the token keyslot
#      (slot contract, §7.2: keyslot 0 = recovery passphrase (ceremony),
#      keyslot 1 = provisional token — token_free_slot returns 1 on the
#      freshly ceremoneied container, keyslot 2 = temporary ephemeral install
#      key), authorized by the staged ephemeral key; then token_import
#   3. per container (ADR-21 provisioning escrow, ADR-22): the container's
#      RANDOM VOLUME PASSPHRASE (the just-sealed $SEAL_PASS_FILE — keyslot 1's
#      credential) is staged as escrow: {target (the crypttab name, resolved
#      in-guest by UUID match), uuid (cryptsetup luksUUID), pass_b64} — one
#      ndjson record per member under /run (tmpfs, I1), assembled after the
#      loop into <ESP>/alpine-fde-provision/volume-keys.json and COMMITTED by
#      the empty <ESP>/alpine-fde-provision/REQUEST marker written LAST (the
#      boot-#1 hook consumes the escrow only when REQUEST stands — the
#      two-file order means a crash can never expose a partial escrow). The
#      Stage-2 ceremony replaces the escrow with the operator's passphrase
#      (keyslot 0); until then this ESP file is the ONLY bootstrap credential
#      of the first boot — any escrow leg failing is fail-closed (exit 1;
#      crash-resume re-runs converge). Fields are printf-composed (no shell
#      eval of secret material); the staging copies are scrubbed by the tail
#      (rm -rf /run/alpine-fde + keys_scrub).
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
  printf '%s\n' "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && uki=\$(ls $_pel_esp/EFI/Linux/alpine-fde-*.efi | head -n 1); objcopy -O binary --only-section=.pcrsig \"\$uki\" /run/alpine-fde/pcrsig.json && for d in $_pel_cs; do seal_provisional /etc/alpine-fde/keys \$d /run/alpine-fde/pcrsig.json /run/alpine-fde/token-\${d##*/}.json \$uki && token_add_keyslot \$d \"\$SEAL_PASS_FILE\" \"\$SEAL_SLOT\" $_pel_key && token_import \$d /run/alpine-fde/token-\${d##*/}.json \"\$(token_next_id \$d)\" && _eu=\$(cryptsetup luksUUID \"\$d\") && _et=\$(awk -v u=\"UUID=\$_eu\" '\$2==u {print \$1; exit}' /etc/crypttab) && [ -n \"\$_et\" ] && printf '{\"target\":\"%s\",\"uuid\":\"%s\",\"pass_b64\":\"%s\"}\n' \"\$_et\" \"\$_eu\" \"\$(openssl base64 -A <\"\$SEAL_PASS_FILE\")\" >>/run/alpine-fde/escrow.ndjson || exit 1; done && jq -s '{members: .}' /run/alpine-fde/escrow.ndjson >/run/alpine-fde/volume-keys.json && mkdir -p $_pel_esp/alpine-fde-provision && cp /run/alpine-fde/volume-keys.json $_pel_esp/alpine-fde-provision/volume-keys.json && sync && tr -s " \t\n" " " </etc/alpine-fde/cmdline.txt | sed "s/^ //;s/ $//" | sha256sum | awk "{print \$1}" >$_pel_esp/alpine-fde-provision/REQUEST && sync && rm -f /run/alpine-fde/escrow.ndjson /run/alpine-fde/volume-keys.json && keys_scrub \"\$SEAL_PASS_FILE\" && rm -rf /run/alpine-fde \${ALPINE_FDE_TMPDIR:-\${TMPDIR:-/tmp}}/alpine-fde-seal.* # ADR-20 step 6: provisional Mechanism B seal (PCR 11) -> keyslot 1 on the CONTAINER dev (item 27) + ADR-21/22 provisioning escrow: per-member {target(crypttab),uuid,pass_b64} of the RANDOM VOLUME PASSPHRASE staged on the ESP mount under alpine-fde-provision/ (volume-keys.json written FIRST, the empty REQUEST marker LAST — the boot-#1 hook consumes only a REQUEST-marked escrow; Stage-2 replaces it); I1 seal-secret scrub"
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

# §9.1 Stage-1 step 9 is RETIRED with install-state.json (item 10b): install
# records NO lifecycle document. The anchoring facts it used to summarize are
# written by their owning steps — the pending baseline (step 2,
# inst_baseline_pending_write) and the provisional {PCR 11} seal + temporary
# ephemeral keyslot 2 (step 6, the provisional enrollment) — and the trust
# state is DERIVED from them at every read (lib/trust-state.sh).

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
    --swap)
      # ADR-7 amended (task 4): OPTIONAL value — `--swap` alone takes the
      # default size; the next word is consumed as SIZE only when it does not
      # start with '-' (i.e. `--swap 4G` vs `--swap --disk X`). Garbage values
      # die at the M-02 validation below, before any record exists.
      if [ $# -ge 2 ]; then
        case $2 in
        -*) : ;;
        *) INST_SWAP_SIZE=$2; shift ;;
        esac
      fi
      INST_SWAP=1
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
  chroot | qemu) : ;;
  *)
    die -r "$ALPINE_FDE_USAGE" "install: unknown runner '$(inst_runner)' (want: $SPC_INSTALL_RUNNERS)"
    ;;
  esac
  if [ "$_im_yes" -eq 0 ] && [ "${ALPINE_FDE_YES:-}" != "1" ]; then
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
  # ADR-7 amended: the dispatcher-provided global `--swap` (env ALPINE_FDE_SWAP)
  # is CONSUMED here — '1' = flag without a size (default 4G); any other value
  # is the size. The subcommand-level --swap flag above wins by having already
  # set INST_SWAP/INST_SWAP_SIZE; a global size only fills an unset one.
  case ${ALPINE_FDE_SWAP:-} in
  '') : ;;
  1) INST_SWAP=1 ;;
  *)
    INST_SWAP=1
    [ -n "${INST_SWAP_SIZE:-}" ] || INST_SWAP_SIZE=$ALPINE_FDE_SWAP
    ;;
  esac

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
  # ADR-7 amended (--swap): fail-closed size format validation BEFORE any plan
  # record exists — garbage dies as a usage error (rc 2), never mid-plan.
  if [ "$(inst_swap_enabled)" = "1" ]; then
    inst_shell_safe '--swap size' "$(inst_swap_size)"
    inst_swap_size_check "$(inst_swap_size)"
  fi
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

  inst_preflight $_im_disks

  # --- resolved layout values -------------------------------------------------
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

  # ADR-7 amended (task 4, --swap): the ephemeral swap partition is the LAST
  # partition on the PRIMARY disk — p3 of the first --disk (single, raid1), or
  # p3 of the CACHE dev in the bcache topologies (the backing dev is WHOLE-disk
  # bcache semantics and cannot carry a partition). The ESP + root layout keeps
  # its roles; the middle partition's size becomes "disk - esp - swap",
  # computed at RUN time inside the sfdisk record (the wipe-superblocks record
  # idiom: command substitution stays literal in the qemu emission). No
  # --swap: the layout is byte-for-byte what it was before.
  _im_swap_dev=''
  if [ "$(inst_swap_enabled)" = "1" ]; then
    case $_im_topology in
    bcache | bcache-multi) _im_swap_dev=$(inst_part "$_im_bcache" 3) ;;
    *) _im_swap_dev=$(inst_part "$_im_disk" 3) ;;
    esac
    _im_esp_mib=$(inst_size_mib "$(inst_esp_size)") ||
      die "install: cannot normalize the ESP size to MiB: $(inst_esp_size)"
    _im_swap_mib=$(inst_size_mib "$(inst_swap_size)") ||
      die "install: cannot normalize the swap size to MiB: $(inst_swap_size)"
  fi

  info "install plan: topology=$_im_topology fs=$(inst_root_fs) disks=$_im_disks esp=$_im_esp luks=$_im_luks swap=$( [ "$(inst_swap_enabled)" = "1" ] && printf '%s' "$(inst_swap_size)" || printf 'none' ) mnt=$_im_mnt runner=$(inst_runner)"

  # --- 0. G-C23/ADR-20: ephemeral install key staged BEFORE any destructive
  #     step. Unattended: NO operator prompt, NO passphrase env consumption
  #     (the §13 recovery passphrase + floor moved to finalize). BR-01:
  #     DIRECT call (no command substitution) — the stager arms the key-file
  #     scrub trap in THIS shell.
  inst_stage_ephemeral_key || die "install: cannot stage the ephemeral install key"
  _im_lukskey=$_IME_KEYFILE
  _im_keyfile_arg=''
  [ -n "$_im_lukskey" ] && _im_keyfile_arg="--key-file $_im_lukskey"

  # real-server blocker #8 + #9: the release-key PASSPHRASE SEAM for the
  # in-chroot build. Blocker #8 staged it on the HOST tmpfs (/dev/shm) —
  # but the H-02 /dev bind is a PLAIN bind (no sub-mounts), so guest-side
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
  inst_exec host "if mountpoint -q $_im_mnt 2>/dev/null || ls $_im_mdir/root[0-9]* >/dev/null 2>&1 || [ -e $_im_mdir/root-crypt ] || [ -e $_im_mdir/swap ] || ls $_im_bsys/*/ >/dev/null 2>&1; then echo 'alpine-fde: info: reset: previous failed install detected — tearing down its stale target mounts + mapper mappings before re-partitioning'; fi || :"
  # item 26d: ONE recursive umount replaces the fixed per-mount list — it
  # covers the subvols, the ESP and any stale chroot binds in a single record
  inst_exec host "$(inst_reset_umount_rec_line $_im_mnt)"
  inst_exec host "$(inst_reset_mapper_line "$_im_mdir")"
  inst_exec host "$(inst_reset_bcache_line "$_im_bsys")"

  # PHYSICAL-MEDIA preconditions (real-install defects 1+2): a physical boot
  # does NOT auto-load the block modules and /dev is not necessarily settled —
  # load bcache/btrfs explicitly, then coldplug, BEFORE any bcache/btrfs work.
  # Explicit `command -v` presence checks (repo idiom — never `|| true`): on
  # the installer media modprobe/mdev (busybox) always exist; in module-less
  # fixture environments the records stay inert no-ops while remaining
  # fail-closed (`set -e` + the plan runner) for any REAL absence.
  if [ "$(inst_bcache)" = "1" ]; then
    inst_exec host "if command -v modprobe >/dev/null 2>&1; then modprobe bcache; fi # physical boot: the bcache module is not auto-loaded"
  fi
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_exec host "if command -v modprobe >/dev/null 2>&1; then modprobe btrfs; fi # physical boot: the btrfs module is not auto-loaded"
  fi
  inst_exec host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: settle /dev before partitioning"
  case $_im_topology in
  single)
    if [ "$(inst_swap_enabled)" = "1" ]; then
      inst_exec host "$(inst_sfdisk_swap_line "$_im_disk" root "$_im_esp_mib" "$_im_swap_mib")"
    else
      inst_exec host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    fi
    ;;
  bcache)
    # ADR-17: ESP p1 + cache p2 on the FAST dev; the backing device is the
    # WHOLE --disk (bcache semantics — the backing dev is NOT partitioned).
    if [ "$(inst_swap_enabled)" = "1" ]; then
      # --swap (ADR-7 amended): the backing dev cannot carry a partition, so
      # the swap is the LAST partition (p3) on the CACHE dev; the cache set
      # keeps p2, sized disk - esp - swap.
      inst_exec host "$(inst_sfdisk_swap_line "$_im_bcache" cache "$_im_esp_mib" "$_im_swap_mib")"
    else
      inst_exec host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    fi
    # coldplug AFTER sfdisk (defect 2): the cache p1/p2 device nodes only
    # appear once the partition table is re-read and coldplug settles.
    inst_exec host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: partition device nodes must exist before make-bcache"
    # wipe stale superblocks BEFORE make-bcache (defect 3)
    inst_exec host "$(inst_wipe_superblocks_line "$_im_cache")"
    inst_exec host "$(inst_wipe_superblocks_line "$_im_backing")"
    inst_exec host "make-bcache -C $_im_cache"
    inst_exec host "make-bcache -B $_im_backing"
    inst_exec host "echo $_im_cache > /sys/fs/bcache/register && echo $_im_backing > /sys/fs/bcache/register"
    inst_exec host "CSET_UUID=\$(bcache-super-show $_im_cache | awk '/cset.uuid/ {print \$2}') && echo \"\$CSET_UUID\" > /sys/block/bcache0/bcache/attach && echo writethrough > /sys/block/bcache0/bcache/cache_mode # writethrough pinned (ADR-17: crash-safe, ciphertext-only cache)"
    ;;
  bcache-multi)
    # G-C27/§4.1 topology 4 (18f1213): ESP p1 + SHARED cache set p2 on the
    # fast dev; EACH backing disk is used WHOLE (bcache semantics — the
    # backing dev is NOT partitioned); every backing device registered
    # (/dev/bcache0, /dev/bcache1, ...) and attached to the shared cset UUID,
    # writethrough pinned.
    if [ "$(inst_swap_enabled)" = "1" ]; then
      # --swap (ADR-7 amended): the backing disks cannot carry partitions, so
      # the swap is the LAST partition (p3) on the shared CACHE dev; the cache
      # set keeps p2, sized disk - esp - swap.
      inst_exec host "$(inst_sfdisk_swap_line "$_im_bcache" cache "$_im_esp_mib" "$_im_swap_mib")"
    else
      inst_exec host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"cache\"\n' | sfdisk $_im_bcache"
    fi
    # coldplug AFTER sfdisk (defect 2), then stale-superblock wipes
    # BEFORE make-bcache (defect 3) — cache p2 + every whole backing disk.
    inst_exec host "if command -v mdev >/dev/null 2>&1; then mdev -s; fi # coldplug: partition device nodes must exist before make-bcache"
    inst_exec host "$(inst_wipe_superblocks_line "$_im_cache")"
    for _im_d in $_im_disks; do
      inst_exec host "$(inst_wipe_superblocks_line "$_im_d")"
    done
    inst_exec host "make-bcache -C $_im_cache"
    for _im_d in $_im_disks; do
      inst_exec host "make-bcache -B $_im_d"
    done
    _im_reg="echo $_im_cache > /sys/fs/bcache/register"
    for _im_d in $_im_disks; do
      _im_reg="$_im_reg && echo $_im_d > /sys/fs/bcache/register"
    done
    inst_exec host "$_im_reg"
    _im_att=''
    _im_i=0
    for _im_d in $_im_disks; do
      _im_att="$_im_att && echo \"\$CSET_UUID\" > /sys/block/bcache$_im_i/bcache/attach && echo writethrough > /sys/block/bcache$_im_i/bcache/cache_mode"
      _im_i=$((_im_i + 1))
    done
    inst_exec host "CSET_UUID=\$(bcache-super-show $_im_cache | awk '/cset.uuid/ {print \$2}')$_im_att # writethrough pinned (ADR-17: crash-safe, ciphertext-only cache)"
    ;;
  raid1)
    if [ "$(inst_swap_enabled)" = "1" ]; then
      # --swap (ADR-7 amended): the swap rides the PRIMARY disk only (p3);
      # secondaries keep the single whole-disk root partition — btrfs raid1
      # tolerates member size differences (the smallest member bounds the pool)
      inst_exec host "$(inst_sfdisk_swap_line "$_im_disk" root "$_im_esp_mib" "$_im_swap_mib")"
    else
      inst_exec host "printf 'label: gpt\nstart=2048, size=+$(inst_esp_size), type=uefi, name=\"esp\"\ntype=linux, name=\"root\"\n' | sfdisk $_im_disk"
    fi
    # secondaries: LUKS2 container p1 ONLY (no ESP on member disks)
    _im_i=1
    for _im_d in $_im_disks; do
      [ "$_im_i" -eq 1 ] && {
        _im_i=2
        continue
      }
      inst_exec host "printf 'label: gpt\nstart=2048, type=linux, name=\"root\"\n' | sfdisk $_im_d"
      _im_i=$((_im_i + 1))
    done
    ;;
  esac

  # --- 2. LUKS2 containers — G-C23: internal ephemeral install key in the ---
  #     TEMPORARY keyslot 2 (unattended; see the SLOT CONTRACT at the top of
  #     this file — keyslot 0 is reserved for the §9.1 step 4 recovery
  #     ceremony, keyslot 1 for the provisional token)
  inst_exec host "cryptsetup --batch-mode luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid $_im_uuid $_im_keyfile_arg $_im_luks # keyslot 2: ephemeral install key (TEMPORARY keyslot — purged at first-boot finalization, §9.1 Stage 2; ADR-20); --batch-mode: NO interactive dangerous-action YES prompt (real-install defect 5)"
  inst_exec host "cryptsetup open $_im_keyfile_arg $_im_luks root-crypt"
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
    # close/rename: primary mapper is root1 in multi-member topologies;
    # member luksFormat/open zipped with the uuids resolved in the layout
    # block — ONE independent LUKS2 container per member device (G-C27)
    inst_exec host "cryptsetup close root-crypt && cryptsetup open $_im_keyfile_arg $_im_luks root1"
    _im_i=1
    set -- $_im_members_uuids
    for _im_md in $_im_members_devs; do
      _im_i=$((_im_i + 1))
      _im_mu=$1
      shift
      inst_exec host "cryptsetup --batch-mode luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 --uuid $_im_mu $_im_keyfile_arg $_im_md # keyslot 2: ephemeral install key (TEMPORARY keyslot — purged at first-boot finalization, §9.1 Stage 2); --batch-mode: no interactive YES"
      inst_exec host "cryptsetup open $_im_keyfile_arg $_im_md root$_im_i"
    done
  fi

  # --- 3. filesystem + subvolumes (§4/§9.1) ----------------------------------
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
      inst_exec host "mkfs.btrfs -U $_im_rootfs_uuid -d raid1 -m raid1 $_im_mapper $_im_members_mappers"
    else
      inst_exec host "mkfs.btrfs -U $_im_rootfs_uuid $_im_mapper"
    fi
    inst_exec host "mount $_im_mapper $_im_mnt"
    inst_exec host "btrfs subvolume create $_im_mnt/@"
    inst_exec host "btrfs subvolume create $_im_mnt/@home"
    inst_exec host "btrfs subvolume create $_im_mnt/@snapshots"
    inst_exec host "umount $_im_mnt"
    inst_exec host "mount -o subvol=@ $_im_mapper $_im_mnt && mkdir -p $_im_mnt/home $_im_mnt/.snapshots $_im_mnt$_im_esp_mnt"
    inst_exec host "mount -o subvol=@home $_im_mapper $_im_mnt/home && chmod 755 $_im_mnt/home # fresh subvol defaults to root-only 0700 — /home must be traversable (R640 2026-10-01: 0700 @home made every non-root user's authorized_keys invisible to sshd's strict-modes walk — pubkey auth silently failed)"
    inst_exec host "mount -o subvol=@snapshots $_im_mapper $_im_mnt/.snapshots"
    inst_exec host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_exec host "mount $_im_esp $_im_mnt$_im_esp_mnt"
  else
    inst_exec host "mkfs.ext4 -F -U $_im_rootfs_uuid $_im_mapper"
    inst_exec host "mkfs.vfat -F 32 -n EFI $_im_esp"
    inst_exec host "mount $_im_mapper $_im_mnt && mkdir -p $_im_mnt$_im_esp_mnt && mount $_im_esp $_im_mnt$_im_esp_mnt"
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
  inst_exec host "mkdir -p $_im_mnt/etc/apk && if [ -d /etc/apk/keys ]; then cp -a /etc/apk/keys $_im_mnt/etc/apk/ && echo 'alpine-fde: info: apk keyring seeded from the live env (apk verifies the mirror indexes against the target keyring)'; else echo 'alpine-fde: warn: no keyring on the live env (/etc/apk/keys) — apk will not trust any mirror'; fi || : # item 26 ext: seed the target keyring before the populate"
  inst_exec host "apk add --root $_im_mnt --initdb alpine-base"

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
  # ADR-7 amended (--swap): the boot `swap` service activates /dev/mapper/swap
  # (created per boot by dmcrypt BEFORE `swap` — its depend() orders it so when
  # the conf carries ^swap=); the mapper device path is the ONLY fstab-visible
  # handle (an ephemeral volume has no persistent UUID to pin — its signature
  # is rewritten at every boot).
  if [ "$(inst_swap_enabled)" = "1" ]; then
    _im_fstab_swap='/dev/mapper/swap none swap defaults 0 0'
  else
    _im_fstab_swap=''
  fi
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_write /etc/fstab \
      "UUID=$_im_rootfs_uuid / btrfs subvol=@,defaults 0 1" \
      "UUID=$_im_rootfs_uuid /home btrfs subvol=@home,defaults 0 2" \
      "UUID=$_im_rootfs_uuid /.snapshots btrfs subvol=@snapshots,defaults 0 2" \
      "PARTUUID=<esp-partuuid> $_im_esp_mnt vfat umask=0077 0 2" \
      ${_im_fstab_swap:+"$_im_fstab_swap"}
  else
    inst_plan_write /etc/fstab \
      "UUID=$_im_rootfs_uuid / ext4 defaults 0 1" \
      "PARTUUID=<esp-partuuid> $_im_esp_mnt vfat umask=0077 0 2" \
      ${_im_fstab_swap:+"$_im_fstab_swap"}
  fi
  # NO zram-init (item 26a, ADR-7 AMENDED): zram is removed from the design —
  # no conf.d drop, no rc-update enable (the old enable ran BEFORE the in-chroot
  # txn that installed the package and died: "service zram-init does not
  # exist", real-server failure #2). The opt-in disk swap story is the
  # --swap ephemeral partition (task 4, ADR-7 amended): the fstab line above is
  # emitted only with --swap, and the boot-time activation records ride BELOW
  # (after the in-chroot txn — the same failure-#2 discipline). Hibernation
  # stays unsupported (ADR-7 — a hibernate image is unencrypted volume-key
  # state on disk).
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
  # every kernel build — not a dracut module knob.
  _im_cmdline_extra=$(inst_cmdline_extra)
  # TWO-UKI CONSOLE VARIANTS (two-UKI boot design, Samuel 2026-09-29): the
  # cmdline composition is ONE function (lib/cmdline.sh cmdline_compose)
  # emitting BOTH variants; install writes BOTH build inputs:
  #   /etc/alpine-fde/cmdline.txt        DEFAULT — console=ttyS0,115200 THEN
  #                                      console=tty0: kernel messages print to
  #                                      BOTH consoles and tty0 LAST makes the
  #                                      virtual console /dev/console for initrd
  #                                      userspace (the unseal hook's prompt
  #                                      renders on the SCREEN; serial stays
  #                                      covered by the hook's dual-emission
  #                                      fan-out). This FLIPS the pre-two-UKI
  #                                      ordering (serial last) — that ordering
  #                                      now lives ONLY in the serial variant.
  #   /etc/alpine-fde/cmdline-serial.txt SERIAL/RECOVERY — console=tty0 THEN
  #                                      console=ttyS0,115200: serial LAST, the
  #                                      remote/passphrase lane (the -serial
  #                                      UKI, NVRAM entry "Alpine FDE - <kver>
  #                                      serial (<date>)").
  # The pre-two-UKI dual-console emission (tty0 first, serial last) was the
  # R640 2026-09-28 headless fix; the two-UKI design keeps BOTH orderings
  # available at boot instead of picking one for every boot.
  # ALPINE_FDE_CMDLINE_EXTRA still appends AFTER the pins in BOTH variants; a
  # user-provided extra containing console= words becomes the last console= and
  # thus wins /dev/console — acceptable (their explicit choice), NOT a pin
  # violation (the guard checks only the §8.2 H-G1 rd.* pins).
  _im_btrfs=0
  [ "$(inst_root_fs)" = "btrfs" ] && _im_btrfs=1
  # shellcheck disable=SC2086  # EXTRA is word-split deliberately
  inst_plan_write /etc/alpine-fde/cmdline.txt \
    "$(cmdline_compose default "$_im_uuid" "$_im_btrfs" $_im_cmdline_extra)"
  # shellcheck disable=SC2086  # word split intended (same EXTRA seam)
  inst_plan_write /etc/alpine-fde/cmdline-serial.txt \
    "$(cmdline_compose serial "$_im_uuid" "$_im_btrfs" $_im_cmdline_extra)"
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
  inst_exec host "mkdir -p $_im_mnt/proc $_im_mnt/sys $_im_mnt/dev && mount -t proc proc $_im_mnt/proc && mount --bind /sys $_im_mnt/sys && mount --bind /dev $_im_mnt/dev"
  # boot-lane finding #8 (s23 attempt 8): the ceremony's 0600 release-key
  # passphrase seam file lives in the LIVE env's /dev/shm (a tmpfs SUBMOUNT)
  # — a plain `mount --bind /dev` does NOT carry submounts, so the in-chroot
  # kernel build could not read the seam and fell back to its interactive
  # prompt (hung the unattended install). Bind the shm tree explicitly; the
  # blocker #8 contract (never argv, never on disk) then actually holds.
  inst_exec host "mkdir -p $_im_mnt/dev/shm && mount --bind /dev/shm $_im_mnt/dev/shm"
  # boot-lane finding #25 (s23 attempt 24): the LIVE env must have efivarfs
  # MOUNTED or the chroot's efivars bind is an empty sysfs dir — the in-chroot
  # NVRAM enrollment then fails and the install defers key import to the
  # operator ("staged kek.auth ... ESP fallback"; PK absent at the verdict).
  inst_exec host "mountpoint -q /sys/firmware/efi/efivars 2>/dev/null || mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || : # ensure the live env's efivarfs is mounted (NVRAM enrollment path)"
  mkdir -p "$_im_mnt/sys/firmware/efi/efivars"
  # the R640 (2026-10-06): the host-side BIND records /mnt/sys/... in
  # mountinfo — libefivar INSIDE the chroot resolves /sys/firmware/efi/efivars
  # against ITS root, finds no efivarfs mount at that path, and reports
  # "EFI variables are not supported" — the boot-entry create+poll then runs
  # blind 40× (the installer refused to guess the entry number, rc=64). The
  # mount must happen FROM INSIDE the chroot so mountinfo records the path
  # libefivar expects.
  inst_exec guest "mkdir -p /sys/firmware/efi/efivars && mount -t efivarfs efivarfs /sys/firmware/efi/efivars"
  # the R640 (2026-10-06): a missing/broken efivars bind made the in-guest
  # boot-entry record fail 40× SILENTLY ('not in the efibootmgr listing' —
  # the poll is blind without efivarfs) and the install aborted rc=64. Verify
  # LOUD immediately: the chroot must see at least one NVRAM variable.
  inst_exec guest "[ -d /sys/firmware/efi/efivars ] && [ -n \"\
\$(ls /sys/firmware/efi/efivars 2>/dev/null | head -1)\" ] && echo 'alpine-fde: efivars bind verified (the NVRAM is visible in-chroot)' || { echo 'alpine-fde: FATAL: the chroot cannot see the EFI variables (the efivars bind is missing or the LIVE env lacks efivarfs) — on the LIVE env run: mkdir -p /mnt/sys/firmware/efi/efivars && mount -t efivarfs efivarfs /mnt/sys/firmware/efi/efivars'; exit 64; }"

  # --- 6. tooling copy (host) — the in-chroot CLI lives at /opt/alpine-fde ---
  info "tooling copy: product script tree only (bin lib hooks docs) — VCS/harness residue excluded (§3.3)"
  inst_exec host "$(inst_tooling_copy_cmd "$_im_tree" "$_im_mnt")"
  # G-U7: the boot-manager self-update service is masked — ESP binaries are
  # only ever written by our SIGNED flow (§8.3)
  inst_exec host "mkdir -p $_im_mnt/etc/systemd/system && ln -sf /dev/null $_im_mnt/etc/systemd/system/systemd-boot-update.service"

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
  inst_exec host "if [ -f /etc/resolv.conf ]; then mkdir -p $_im_mnt/etc && cp /etc/resolv.conf $_im_mnt/etc/resolv.conf && echo 'alpine-fde: info: seeded target /etc/resolv.conf from the live env (in-chroot apk needs DNS)'; else echo 'alpine-fde: warn: live env has no /etc/resolv.conf — target DNS seed skipped (in-chroot apk may fail to resolve the mirror)'; fi || : # item 26b: seed the target resolver before the in-chroot transaction"
  # boot-lane finding #7 (companion to the hosts-aware preflight probe): a
  # hosts-based mirror name resolves through /etc/hosts, NOT the resolver —
  # seed the live env's hosts table too, or the IN-CHROOT transaction (which
  # resolves via the TARGET's files) cannot see it.
  inst_exec host "if [ -f /etc/hosts ]; then mkdir -p $_im_mnt/etc && cp /etc/hosts $_im_mnt/etc/hosts && echo 'alpine-fde: info: seeded target /etc/hosts from the live env (in-chroot apk resolves hosts-based mirror names)'; else echo 'alpine-fde: warn: live env has no /etc/hosts — target hosts seed skipped (in-chroot apk may fail to resolve a hosts-based mirror)'; fi || : # item 26b: seed the target hosts table before the in-chroot transaction"
  inst_exec guest "apk add --no-cache $(install_package_list)"
  # step 1b (§8.2/ADR-13): register the `alpine-fde` mkinitfs feature in the
  # target's /etc/mkinitfs/mkinitfs.conf. mkinitfs packs a feature's
  # features.d/<name>.files entries ONLY when the feature is enabled in that
  # conf — without this the staged unseal hook (§9.1 step 7) is silently
  # omitted from every real build. Host-side record (runs against the staged
  # tree right after the in-guest apk transaction installs mkinitfs and its
  # package-default conf); grep-guard makes the patch idempotent under
  # re-run; a missing conf (package not yet installed) is created with the
  # feature-only line rather than silently skipped.
  # REAL-SERVER BLOCKER (initramfs ran NO udevd — Dell PowerEdge R640 first
  # verified boot 2026-09-28): the features list carried `alpine-fde` but
  # never `udev`. With no udev feature mkinitfs ships no udevd — the
  # initramfs init runs nlplug-findfs + mdev, which never EXECUTES udev
  # rules. The shipped/registered rules (69-bcache.rules, 60-tpm.rules) sat
  # inert in the initrd: 69-bcache.rules never registered the bcache backing
  # devices (/dev/bcache* may never appear) and /dev/disk/by-uuid/* — udev
  # artifacts — never materialized, so the unseal hook's member resolution
  # starved: 30s device wait → token_missing on an INTACT seal. The record
  # therefore also ensures `udev` in the features list. The udev guard tests
  # the features LINE (sed-extracted), never the whole file: custom_files
  # carries /usr/lib/udev/ paths, and a whole-file word grep would be
  # satisfied by them — silently skipping the feature on the exact pre-fix
  # R640 re-run state (alpine-fde + custom_files present, udev absent).
  # With udev running, rule registration and by-uuid both work; the unseal
  # hook's nlplug resolver stays as belt-and-braces (nlplug-findfs functions
  # alongside udev).
  # REAL-SERVER BLOCKER #14: the same record registers `custom_files` —
  # mkinitfs 3.14.1 routes .files entries through ldtree(1), which silently
  # DROPS every non-ELF file (the unseal hook script and the udev rules);
  # custom_files copies them into the initramfs verbatim. Staged later at
  # step 7; mkinitfs reads the list at build time (idempotent).
  inst_exec host "f=$_im_mnt/etc/mkinitfs/mkinitfs.conf; grep -q alpine-fde \"\$f\" 2>/dev/null || { mkdir -p $_im_mnt/etc/mkinitfs; [ -f \"\$f\" ] && sed -i 's/^features=\"\\(.*\\)\"$/features=\"\\1 alpine-fde\"/' \"\$f\" || printf 'features=\"alpine-fde udev\"\n' >\"\$f\"; }; sed -n 's/^features=\"\\(.*\\)\"$/\\1/p' \"\$f\" 2>/dev/null | grep -qw udev || sed -i 's/^features=\"\\(.*\\)\"$/features=\"\\1 udev\"/' \"\$f\"; grep -q '^custom_files=' \"\$f\" 2>/dev/null || printf 'custom_files=\"/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh /usr/lib/udev/rules.d/69-bcache.rules /usr/lib/udev/rules.d/60-tpm.rules\"\n' >>\"\$f\" # §8.2/ADR-13: enable the alpine-fde + udev mkinitfs features (R640: no udev feature = no udevd in the initramfs — the udev rules never run, bcache registration + by-uuid starve) + register the non-ELF payload (hook script + udev rules) via custom_files (blocker #14, idempotent)"
  inst_exec guest "adduser -D -s /bin/ash $_im_user && addgroup $_im_user wheel; passwd -l root >/dev/null 2>&1 || : # root LOCKED at install (never empty-password; the first-boot ceremony sets root+admin to the operator's passphrase — ADR-21)"
  # HEADLESS ACCESS (R640 2026-10-01): adduser -D leaves the account LOCKED
  # (no password) and the sshd policy is PermitRootLogin no — without a
  # staged operator key the fresh install's SSH path is INOPERABLE. Set
  # ALPINE_FDE_ADMIN_PUBKEY (path to an OpenSSH PUBLIC key on the installer
  # host) to stage it for the admin account + wheel doas; unset = status quo.
  if [ -n "${ALPINE_FDE_ADMIN_PUBKEY:-}" ] && [ -r "$ALPINE_FDE_ADMIN_PUBKEY" ]; then
    _iap_b64=$(openssl base64 -A -in "$ALPINE_FDE_ADMIN_PUBKEY" 2>/dev/null || base64 -w0 "$ALPINE_FDE_ADMIN_PUBKEY")
    info "install: staging operator pubkey for $_im_user + wheel doas (headless access)"
    inst_exec guest "mkdir -p /home/$_im_user/.ssh && printf %s $_iap_b64 | base64 -d > /home/$_im_user/.ssh/authorized_keys && chown -R $_im_user:$_im_user /home/$_im_user/.ssh && chmod 700 /home/$_im_user/.ssh && chmod 600 /home/$_im_user/.ssh/authorized_keys && mkdir -p /etc/doas.d && printf 'permit nopass :wheel\n' > /etc/doas.d/alpine-fde.conf # headless: locked account + pubkey-only access + wheel doas"
  fi
  # STANDARD OPENRC ENROLLMENT (real-server blocker, R640 2026-09-30): the
  # freshly-populated target shipped a COMPLETELY EMPTY sysinit runlevel and a
  # boot runlevel with ONLY networking — no mdev, no hwdrivers, no modules.
  # Consequences at first boot: NIC drivers never load (/etc/modules ignored —
  # the `modules` service was not enrolled), /dev/disk/by-uuid never populates,
  # and btrfs multi-device assembly starves. The finalize service then fails
  # ("member device not resolvable") and the box is only reachable over serial.
  # Enroll the stock Alpine set (all providers ship in alpine-base/openrc —
  # failure-#2 discipline: this runs after the in-chroot apk transaction).
  inst_exec guest 'rc-update add devfs sysinit && rc-update add dmesg sysinit && rc-update add mdev sysinit && rc-update add hwdrivers sysinit'
  inst_exec guest 'rc-update add modules boot && rc-update add hostname boot && rc-update add bootmisc boot && rc-update add sysctl boot && rc-update add syslog boot && rc-update add btrfs-scan boot'
  inst_exec guest 'rc-update add mount-ro shutdown && rc-update add killprocs shutdown && rc-update add savecache shutdown && rc-update add local default'
  # NO-UDEV BY-UUID SEAM (same blocker): mdev does not populate
  # /dev/disk/by-uuid for the LUKS containers, and finalize/reseal resolve
  # members through it. Drop the same idempotent link-fixup the R640 rescue
  # proved out, run once per boot before the default-runlevel consumers.
  inst_plan_write /etc/local.d/00-fde-links.start \
    '#!/bin/sh' \
    '# create /dev/disk/by-uuid symlinks for the crypttab LUKS containers' \
    '# (mdev does not populate by-uuid for bcache members; no udev here)' \
    'mkdir -p /dev/disk/by-uuid' \
    "awk '\$4 ~ /luks/ { sub(/^UUID=/, \"\", \$2); print \$2 }' /etc/crypttab |" \
    'while read -r u; do' \
    '    [ -e "/dev/disk/by-uuid/$u" ] && continue' \
    '    dev=$(blkid 2>/dev/null | grep "$u" | cut -d: -f1 | head -1)' \
    '    [ -n "$dev" ] && ln -sf "$dev" "/dev/disk/by-uuid/$u"' \
    'done'
  inst_exec guest 'chmod +x /etc/local.d/00-fde-links.start'
  inst_exec guest 'rc-update add networking boot'
  # REAL-SERVER BLOCKER (headless, Dell PowerEdge R640 first verified boot
  # 2026-09-28): the guest shipped NEITHER a serial getty NOR sshd — on a
  # headless server the operator was locked out of the booted system entirely.
  # All records run AFTER the in-chroot apk transaction (real-server failure
  # #2 discipline: never enable/configure a service before its package
  # exists — openssh is in the §3.3 additions set above; /etc/inittab and
  # /etc/ssh/sshd_config come from alpine-base/openssh).
  inst_exec guest "$(inst_inittab_getty_cmd /etc/inittab)"
  inst_exec guest "$(inst_sshd_config_cmd /etc/ssh/sshd_config)"
  inst_exec guest 'rc-update add sshd default'
  # ADR-7 amended (--swap): ephemeral swap activation — ONLY with --swap, ONLY
  # after the in-chroot txn that installed cryptsetup-openrc (the `dmcrypt`
  # service provider; failure-#2 discipline). dmcrypt creates the plain
  # dm-crypt swap mapping from /dev/urandom and mkswaps it (default
  # pre_mount) each boot; the boot `swap` service then swapon's the mapper
  # (fstab line above). These stay OUT of the crypttab entirely: the target
  # /etc/crypttab is spliced into the initramfs for the ROOT containers, and
  # the swap must never be resolved by the initramfs (it mounts late, normal
  # boot). Idempotent guarded append (crash-resume safe).
  if [ "$(inst_swap_enabled)" = "1" ]; then
    inst_exec guest "$(inst_dmcrypt_conf_cmd /etc/conf.d/dmcrypt "$_im_swap_dev")"
    inst_exec guest 'rc-update add dmcrypt boot'
    inst_exec guest 'rc-update add swap boot'
  fi
  # step 2: pending baseline written ON-TARGET via the baseline writer
  inst_exec host "inst_baseline_pending_write $_im_mnt"
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
  # (the Stage-2 ceremony) encrypts it — its keys_is_encrypted gate only
  # skips on an ALREADY-encrypted file, so the natural flow completes custody.
  _im_keys=$_im_mnt/etc/alpine-fde/keys
  if [ -n "$_im_kd" ]; then
    inst_exec host "mkdir -p $_im_keys && cp $_im_kd/release.pem $_im_kd/release.pub $_im_kd/release.crt $_im_kd/db.cert.der $_im_kd/kek.cert.der $_im_kd/pk.cert.der $_im_kd/db.esl $_im_kd/kek.esl $_im_kd/pk.esl $_im_kd/db.auth $_im_kd/kek.auth $_im_kd/pk.auth $_im_keys/ && chmod 700 $_im_keys && chmod 600 $_im_keys/* # ADR-18/§8.1: operator-supplied key material staged from the signing medium (no in-chroot keygen)"
  else
    inst_exec guest '/opt/alpine-fde/bin/alpine-fde provision stage1 --mode in-chroot --keydir /etc/alpine-fde/keys --defer-custody'
  fi
  # step 4: NVRAM enrollment db → KEK → PK (last) via the bind-mounted
  # efivars (the firmware state was gate-checked host-side in preflight:
  # Setup Mode — or a platform PK already enrolled, the DEFERRED-enrollment
  # mode). The in-chroot
  # ESP mount ($_im_esp_mnt, §8.1 --esp/env ALPINE_FDE_ESP/default /efi) is
  # passed as the fallback staging dir (queue 26 ext): when the firmware
  # refuses the SetVariable, fw_auth_enroll stages the .auth/.esl key material
  # to <ESP>/alpine-fde-keys and prints manual-import instructions instead of
  # dying — the install continues. In the DEFERRED-enrollment mode (a platform
  # PK is already enrolled — factory or custom, REAL-SERVER 2026-09-28 Dell
  # PowerEdge R640) fw_auth_enroll makes NO NVRAM writes and stages the
  # import-ready .cer set instead; the ALPINE_FDE_ENROLL_DEFERRED_MARKER seam
  # (host /dev/shm, bind-mounted into the chroot at the H-02 step above) tells
  # the §9 tail verdict to route the deferred instructions + firmware-setup
  # reboot.
  inst_exec host "rm -f /dev/shm/alpine-fde-enroll-deferred # stale deferred marker from a previous boot/install must not misroute the §9 verdict"
  inst_exec guest "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; export ALPINE_FDE_ENROLL_DEFERRED_MARKER=/dev/shm/alpine-fde-enroll-deferred; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/firmware.sh && fw_auth_enroll /sys/firmware/efi/efivars /etc/alpine-fde/keys $_im_esp_mnt"
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
  inst_exec guest "$(inst_bootmgr_copy_line $_im_esp_mnt)"
  # step 7 (MOVED BEFORE the credential ceremony — no ceremony secret; the
  # staging is also a kernel-build INPUT — the kernel hook fires on every
  # build): hooks + trigger + first-boot AUTO-FINALIZER (§9.1 step 7;
  # ADR-13/ADR-19/ADR-20, G-C16 Alpine layout — flat templates copied to
  # their run-parts destinations; the auto-finalizer oneshot ships to
  # /etc/init.d/ and is enabled for the default runlevel. ADR-20 amended
  # Stage 2: it runs the NON-INTERACTIVE completion when provisional-booted
  # under Secure Boot; `alpine-fde finalize` is the guided/crash-resume
  # entry point, Stage 3.) The FR-6 boot-time audit rides the SAME staging:
  # hooks/openrc/alpine-fde-audit → /etc/init.d/alpine-fde-audit (the oneshot
  # that compares PCR 0..3+7 + the event log against the baseline every boot,
  # last before the login prompt) and hooks/profile.d/alpine-fde.sh →
  # /etc/profile.d/alpine-fde.sh (the interactive login drift alert).
  # §9.1 step 8 / docs/Architecture.md §9.1 item 8.
  # §8.2/ADR-13 staging contract (ONE pinned path): the unseal hook ships to
  # EXACTLY the absolute path pinned in the mkinitfs.conf `custom_files`
  # registration (step 1b) — /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh.
  # REAL-SERVER BLOCKER #14: mkinitfs 3.14.1's .files route (ldtree) drops
  # every non-ELF file, so the hook script + the shipped udev rules are packed
  # via custom_files (verbatim copy), the KERNEL MODULES ride
  # features.d/alpine-fde.modules (modules.dep closure), and .files carries
  # only the ELF userland. Staging under /etc/mkinitfs would leave the pinned
  # path unresolved and the hook silently omitted. The repo-wide convention
  # (hooks_mkinitfs_unseal + initrd_audit inventories) pins the
  # /usr/share/alpine-fde spelling.
  inst_exec host "mkdir -p $_im_mnt/etc/kernel-hooks.d $_im_mnt/etc/mkinitfs/features.d $_im_mnt/usr/share/alpine-fde/mkinitfs $_im_mnt/usr/lib/udev/rules.d $_im_mnt/etc/apk/triggers $_im_mnt/etc/conf.d $_im_mnt/etc/init.d $_im_mnt/etc/profile.d && cp $_im_hooks/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook && cp $_im_hooks/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook && cp $_im_hooks/mkinitfs/alpine-fde-unseal.sh $_im_mnt/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh && cp $_im_hooks/mkinitfs/features.d/alpine-fde.files $_im_mnt/etc/mkinitfs/features.d/alpine-fde.files && cp $_im_hooks/mkinitfs/features.d/alpine-fde.modules $_im_mnt/etc/mkinitfs/features.d/alpine-fde.modules && cp $_im_hooks/udev/60-tpm.rules $_im_mnt/usr/lib/udev/rules.d/60-tpm.rules && cp $_im_hooks/apk/triggers/alpine-fde.trigger $_im_mnt/etc/apk/triggers/alpine-fde.trigger && cp $_im_hooks/apk/triggers/alpine-fde-snapshot.trigger $_im_mnt/etc/apk/triggers/alpine-fde-snapshot.trigger && cp $_im_hooks/conf.d/alpine-fde-snapshot $_im_mnt/etc/conf.d/alpine-fde-snapshot && cp $_im_hooks/openrc/alpine-fde-finalize $_im_mnt/etc/init.d/alpine-fde-finalize && cp $_im_hooks/openrc/alpine-fde-audit $_im_mnt/etc/init.d/alpine-fde-audit && cp $_im_hooks/profile.d/alpine-fde.sh $_im_mnt/etc/profile.d/alpine-fde.sh && chmod +x $_im_mnt/etc/kernel-hooks.d/alpine-fde-build.hook $_im_mnt/etc/kernel-hooks.d/alpine-fde-remove.hook $_im_mnt/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh $_im_mnt/etc/apk/triggers/alpine-fde.trigger $_im_mnt/etc/apk/triggers/alpine-fde-snapshot.trigger $_im_mnt/etc/init.d/alpine-fde-finalize $_im_mnt/etc/init.d/alpine-fde-audit && find $_im_mnt/lib/modules/*/kernel -type f \( -name 'tpm.ko*' -o -name 'tpm_tis.ko*' -o -name 'tpm_crb.ko*' -o -name 'btrfs.ko*' -o -name 'bcache.ko*' \) 2>/dev/null | sed s:$_im_mnt/lib/modules/[^/]*/:: >> $_im_mnt/etc/mkinitfs/features.d/alpine-fde.modules; td=\$(basename \"\$(readlink -f /sys/class/tpm/tpm0/device/driver 2>/dev/null)\" 2>/dev/null); [ -n \"\$td\" ] && info \"install: detected TPM interface driver: \$td (the staged feature files pack every found tpm/btrfs/bcache module, blocker #12/#14)\"; :"
  inst_exec guest 'rc-update add alpine-fde-finalize default'
  # FR-6 (user decision queue item 10): the boot-time audit oneshot is enabled
  # for the default runlevel (runs LAST before the login prompt via `after *`)
  # — placed AFTER the package transaction per the real-server failure-#2
  # discipline (an rc-update record for a service the txn has not installed
  # kills the plan), and the record is idempotent (rc-update add on an enabled
  # service is a no-op; crash resume re-runs it safely).
  inst_exec guest 'rc-update add alpine-fde-audit default'
  # §8.4 (MOVED BEFORE the ceremony — no ceremony secret): resolve the ESP
  # PARTUUID into fstab + target metadata on the
  # on-target pending baseline (luks_uuid = primary; member_uuids additive)
  if [ "$_im_topology" = "raid1" ] || [ "$_im_topology" = "bcache-multi" ]; then
    inst_exec host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid $_im_members_uuids"
  else
    inst_exec host "inst_resolve_target_metadata $_im_esp $_im_mnt $_im_uuid"
  fi
  # step 8 (G-C25, ADR-20 #4): NO unfinalized banner is written — /etc/motd
  # and /etc/issue stay untouched (the banner path is removed).
  # step 9 is RETIRED (item 10b): NO install-state.json is written — the
  # anchoring facts live in the pending baseline (step 2) and, after the
  # ceremony, the provisional {PCR 11} seal + temporary ephemeral keyslot 2
  # (step 6). The trust state is derived from them (lib/trust-state.sh).
  # step 4 (ADR-20 AMENDED, §9.1 step 4): the interactive CREDENTIAL CEREMONY —
  # three no-echo questions, the only interactive input of the whole lifecycle,
  # run in-chroot while the ephemeral install key (TEMPORARY keyslot 2) is
  # still staged to authorize the recovery luksAddKey. NO flag and NO
  # credential env seam exists (S-24): the prompts run only in the execution
  # path (these records are eval'd host-side by the chroot runner), every
  # typed secret is §13-floored with re-prompt until met, and no credential
  # ever appears in plan text, argv, the environment, or on disk/ESP (I1/I4).
  # qemu emits the records as inert text. ORDER (item 12 AMENDED,
  # normative): the recovery passphrase FIRST (1/3); the user password (2/3)
  # and the release-key passphrase (3/3) DEFAULT to it on bare Enter, each
  # prompt carrying a reuse hint. POSITION (user flow directive): the ceremony
  # is the LAST interactive section — EVERY mechanical step precedes it
  # (enrollment, boot-manager copy, hooks, target metadata above);
  # only the SECRET-dependent steps follow (the signed UKI + boot-manager
  # build, which consumes the release-key custody the ceremony just
  # completed, and the provisional seal). The ceremony runs AFTER the
  # platform-key ceremony (so release.pem exists), BEFORE the provisional
  # seal (so keyslot 0 is occupied and token_free_slot yields 1). DEVICE
  # CONTRACT (item 27): the recovery record passes the CONTAINER devices
  # ($_im_containers, the luksFormat targets) — never the /dev/mapper/* views.
  # CREDENTIAL CEREMONY: SUPERSEDED by the ADR-21 provisioning-escrow flow —
  # Stage 1 prompts for NOTHING: no recovery keyslot is created (the first
  # boot's Stage-2 ceremony enrolls keyslot 0 from the operator's passphrase
  # ×2), the admin account stays pubkey-accessible (the staged
  # ALPINE_FDE_ADMIN_PUBKEY; its password is set by the same ceremony), and
  # release.pem encryption is DEFERRED to that ceremony (the file sits 0400
  # root-only inside the encrypted root until then — ADR-18 amended).
  # step 5 (SECRET-dependent — stays AFTER the ceremony): signed boot manager
  # + initial UKI (baseline pending ⇒ the build's ensure-once enrollment is
  # state-gated OFF — the PROVISIONAL seal below is the only enrollment of
  # Stage 1)
  # REAL-SERVER BLOCKER #8 + #9: the build record must (a) configure the
  # release-key directory — kernel build resolves keys_dir() =
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
  # the linux-lts package did not install) and PASSES it to kernel build:
  # the retired no-arg form fell back to `uname -r` — the LIVE ISO's kernel
  # — whose module tree does not exist in the target.
  inst_exec guest "export ALPINE_FDE_ROOT=/; export ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys; kv=\$(cd /lib/modules 2>/dev/null && ls -1d */ 2>/dev/null | tr -d '/' | sort -V | tail -n 1); [ -n \"\$kv\" ] || { echo 'alpine-fde: ERROR: no kernel module tree under /lib/modules — the linux-lts kernel package did not install into the target; fix the mirror/package set and re-run (completed steps skip via crash resume)' >&2; exit 1; }; /opt/alpine-fde/bin/alpine-fde kernel build \"\$kv\" # §9.1 step 5 (SECRET-dependent — after the ceremony): signed boot manager + initial UKI (baseline pending ⇒ the build's ensure-once enrollment is state-gated OFF — the PROVISIONAL seal is the only Stage 1 enrollment); blocker #8/#9: keydir exported (keys_dir has no default) + passphrase from the in-target 0600 seam file (never argv); blocker #11: target kver derived in-guest (uname -r is the LIVE ISO kernel); blocker #12: ALPINE_FDE_ROOT=/ — in-chroot the TARGET IS /, and without it the initrd audit has no kernel-reality context (verdicts degrade to bare 'missing' instead of suffix-tolerant satisfaction)"
  # step 6 (SECRET-dependent — stays AFTER the ceremony): PROVISIONAL TPM
  # enrollment (G-C24) — Mechanism B, PCR 11 only,
  # .pcrsig from the just-built UKI; keyslot 1 per member CONTAINER (item 27:
  # the choreography targets the container devs, never the mapper views)
  # boot-lane finding #17 (s23 attempt 16): load the LIVE kernel's TPM driver
  # HOST-side, before the seal guest line. The TCTI resolver's modprobe
  # recovery runs IN-CHROOT, where /lib/modules holds the TARGET kernel (the
  # live ISO runs a different flavor+version) — in-chroot modprobe can never
  # load the driver, /dev/tpmrm0 never appears, and the seal dies
  # "no usable TPM via TCTI '<default>'" after a successful UKI build.
  inst_exec host "modprobe tpm_crb 2>/dev/null; modprobe tpm_tis 2>/dev/null; : # blocker #18 companion: ensure the live kernel's TPM driver is loaded (host-side; the in-chroot modprobe resolves the target's module tree)"
  inst_exec guest "$(inst_provisional_enroll_line "$_im_lukskey" $_im_containers)"
  # step 6b (task #27, real-server follow-up): the UEFI BOOT ENTRY — the
  # install must end with the firmware pointing at the staged ESP, not leave
  # efibootmgr to the operator (done BY HAND on the real Dell PowerEdge after
  # the fresh install: Boot0005 "Alpine FDE" -> HD(1,GPT,<part-guid>) ->
  # \EFI\BOOT\BOOTX64.EFI, first in BootOrder). IN-GUEST (the ESP is mounted
  # and the live NVRAM is reachable through the §9.1 efivars bind, exactly
  # like the step-4 enrollment), AFTER the build (the loader is staged) and
  # BEFORE the teardown (the chroot still sees the ESP). Idempotent: a
  # same-label entry at the CURRENT ESP partition GUID + loader is REUSED,
  # same-label entries at dead/old GUIDs are deleted + recreated (a
  # re-partitioned ESP leaves entries that boot "Boot Failed"). No EFI
  # variable support (container): the record SKIPS with the exact manual
  # command instead of failing the completed install.
  # TARGET-TREE PERMISSIONS NORMALIZATION (R640 2026-10-02: / , /etc , /home all came up 0700 — the dispatcher's umask 077 propagates into the guest tree population, and a root-only / breaks EVERY non-root path: sshd strict-modes, pubkey auth, su, shell exec). Runs LATE — after the full population — normalizing only the DIRECTORY level (file modes keep their individual grants); placed BEFORE the bootentry step so a later NVRAM-latency failure cannot skip it.
  inst_exec guest "chmod 755 / /home /etc /var /usr /srv /opt 2>/dev/null; true"

  inst_exec guest "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/cmd/install.sh && require_pkgs efibootmgr:efibootmgr && inst_bootentry_ensure $_im_esp $_im_esp_mnt \$(cd /lib/modules 2>/dev/null && ls -1d */ 2>/dev/null | tr -d '/' | sort -V | tail -n 1) # task #27 + default-only boot design: the firmware NVRAM boot-entry (\"Alpine FDE - <kver> (<date>)\" -> \EFI\Linux\alpine-fde-<kver>.efi, FIRST in BootOrder; the firmware loads the UKI directly, systemd-boot is only the removable fallback; the serial NVRAM lane is RETIRED — retired serial entries are swept, the serial UKI on the ESP is one-shot via UefiTarget), HD(1,GPT,<esp-part-guid>), idempotent (family entries at dead GUIDs/stale loaders replaced; legacy single-UKI entries deleted)"

  # --- 8. teardown + scrub (§9.1 Teardown; I1) ------------------------------
  # Operationally AFTER the ceremony + secret-dependent steps (the guest build
  # + seal run inside the chroot this unmounts): unmount, container close, the
  # explicit ephemeral-key scrub (I1). The FINAL reboot is the plan's tail
  # (§9 below): a direct reboot to disk when the NVRAM enrollment succeeded —
  # or, when the firmware refused it OR a platform key was already enrolled
  # (the deferred-enrollment mode), the manual-import instructions, an
  # explicit Enter confirmation, and a reboot INTO FIRMWARE SETUP
  # (OsIndications) for the manual key import.
  # boot-lane findings #20 + #21 (s23 attempts 20-21): (a) the efivars bind is
  # a CHILD of /mnt/sys — unmounting the parent first fails EBUSY; children
  # first. (b) /mnt/dev is a bind of the live devtmpfs: the live env's own TPM
  # device references keep it busy at teardown. The install is COMPLETE at this
  # point (sealed, state written) — a busy host bind must not fail it: every
  # umount gets a lazy (-l) fallback, best-effort, never fatal.
  inst_exec host "umount $_im_mnt/sys/firmware/efi/efivars 2>/dev/null || umount -l $_im_mnt/sys/firmware/efi/efivars 2>/dev/null || :; umount $_im_mnt/dev 2>/dev/null || umount -l $_im_mnt/dev 2>/dev/null || :; umount $_im_mnt/sys 2>/dev/null || umount -l $_im_mnt/sys 2>/dev/null || :; umount $_im_mnt/proc 2>/dev/null || umount -l $_im_mnt/proc 2>/dev/null || :; umount -R $_im_mnt 2>/dev/null || umount -l $_im_mnt 2>/dev/null || :; $_im_close"
  inst_exec host "rm -f $_im_lukskey # I1: ephemeral install key scrubbed (§9.1 teardown)"

  # --- 9. enrollment verdict + ESP-fallback tail (user directives 1+3) ------
  # The NVRAM enrollment ran BEFORE the ceremony (mechanical); the outcome is
  # only knowable at RUN time (generate-time cannot know machine state — the
  # reset-record idiom): a DEFERRED-enrollment marker (the in-chroot
  # fw_auth_enroll wrote it on the bind-mounted host tmpfs when a platform PK
  # was already enrolled) routes to the deferred-import tail; otherwise probe
  # PK on the LIVE efivars (the in-chroot enrollment wrote the bind-mounted
  # live NVRAM): PK present = NVRAM enrollment succeeded, PK absent = refused
  # (staged, manual import pending).
  inst_exec host "if [ -e /dev/shm/alpine-fde-enroll-deferred ]; then INST_SB_ENROLLED=0; INST_SB_DEFERRED=1; elif fw_var_present $(fw_efivars_dir) PK; then INST_SB_ENROLLED=1; INST_SB_DEFERRED=0; else INST_SB_ENROLLED=0; INST_SB_DEFERRED=0; fi # enrollment verdict: deferred marker = a platform PK was already enrolled (factory or custom) — the release certificate import via the firmware UI is still pending; PK present = NVRAM enrollment succeeded; PK absent = enrollment refused — manual key import still pending (deferred)"
  inst_exec host "rm -f /dev/shm/alpine-fde-enroll-deferred # the verdict consumed the deferred marker (I1 seam hygiene)"
  # DEFERRED path (user directive 3): the manual-import instructions print at
  # the VERY END of the install — after every mechanical step — naming the
  # DIRECT-from-ESP import FIRST (user directive 2: the key material is staged
  # on the internal ESP precisely so the firmware can load it from there).
  # The explicit Enter confirmation + the firmware-setup reboot follow
  # (emitted only when the reboot is not suppressed by the CI seam).
  # Two instruction blocks, one per non-enrolled outcome:
  #   INST_SB_DEFERRED=1  a platform PK is ALREADY enrolled (factory or
  #                       custom): import db.cer + the vendor certificate
  #                       INTO THE EXISTING db; the PK/KEK stay (REAL-SERVER
  #                       2026-09-28, Dell PowerEdge R640 — the firmware UI
  #                       imports X.509 certificates only, and the vendor db
  #                       already carries the option-ROM CAs)
  #   otherwise (PK absent) the firmware refused the NVRAM writes: import the
  #                       staged CERTIFICATES in the db -> KEK -> PK order
  #                       (the UI cannot import .auth packets — those are
  #                       KeyTool.efi / efi-updatevar repair material)
  inst_exec host "if [ \"\${INST_SB_DEFERRED:-}\" = \"1\" ]; then printf '%s\n' 'alpine-fde: a platform key is ALREADY enrolled (factory or custom) — the installer made NO NVRAM writes; finish by importing the release certificate via the firmware UI:' '  1. the import-ready certificates are staged under $_im_esp_mnt/alpine-fde-keys on the EFI System Partition: db.cer (the alpine-fde release certificate) plus the vendor option-ROM certificate (e.g. microsoft-option-rom-uefi-ca-2023.cer); otherwise copy the alpine-fde-keys directory to a FAT USB stick' '  2. reboot into the firmware setup (BIOS/UEFI) — this installer reboots there after your confirmation below' '  3. in the firmware key-management UI import db.cer AND the vendor certificate INTO THE EXISTING key database (db) — Secure Boot can stay ENABLED throughout' '  4. do NOT import KEK.cer or PK.cer and do NOT clear or replace the platform key — the existing PK and KEK stay (README.txt on the ESP and the marker file !import_all_auth_files repeat these steps — no need to memorize them)' '  5. while in firmware setup, set an administrator (supervisor) password' '  6. boot the installed system — completed install steps skip via crash resume; the first boot REFUSES to boot until db.cer is imported (that is the design, ADR-20)'; fi # deferred enrollment (platform PK present): UI import of db.cer + the vendor cert into the EXISTING db printed LAST"
  inst_exec host "if [ \"\${INST_SB_DEFERRED:-}\" = \"1\" ]; then :; elif [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else printf '%s\n' 'alpine-fde: Secure Boot key material is staged under $_im_esp_mnt/alpine-fde-keys on the EFI System Partition — the firmware refused NVRAM enrollment; finish the import manually:' '  1. import DIRECTLY from the internal ESP when the firmware key-management UI can browse it (the files to import are already at $_im_esp_mnt/alpine-fde-keys — this is why they are staged on the EFI partition); otherwise copy the alpine-fde-keys directory to a FAT USB stick' '  2. reboot into the firmware setup (BIOS/UEFI) — this installer reboots there after your confirmation below' '  3. in the firmware key-management UI import the staged CERTIFICATES in this order (the firmware UI imports X.509 .cer files — it CANNOT import .auth packets): db.cer AND the vendor certificate (e.g. microsoft-option-rom-uefi-ca-2023.cer) for the Key Database, then KEK.cer (Key Exchange Key), then PK.cer (Platform Key — import LAST; it locks the key database)' '  4. the .auth packets staged alongside (db.auth kek.auth pk.auth) are for KeyTool.efi / efi-updatevar repair only; in the firmware file browser the marker file !import_all_auth_files and README.txt on the ESP repeat these steps — no need to memorize them' '  5. while in firmware setup, set an administrator (supervisor) password' '  6. boot the installed system — completed install steps skip via crash resume; the first boot REFUSES to boot until the keys are imported (that is the design, ADR-20)'; fi # deferred enrollment (firmware refused): manual-import instructions printed LAST (user directive: instructions at the very end; direct-from-ESP import first; the UI-importable .cer set db.cer + vendor cert + KEK.cer + PK.cer enumerated, the .auth packets named as repair-only; README.txt + marker enumerated)"
  if [ "$_im_no_reboot" = "0" ] && [ "${ALPINE_FDE_INSTALL_NO_REBOOT:-}" != "1" ]; then
    inst_exec host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else printf '%s' 'alpine-fde: review the manual-import instructions above, then press Enter to reboot into firmware setup (UEFI): ' >&2; IFS= read -r _im_enter || :; fi # deferred enrollment: EXPLICIT user confirmation before the firmware reboot (user directive)"
    inst_exec host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then :; else fw_osindications_set $(fw_efivars_dir) && reboot; fi # deferred enrollment: next boot enters firmware setup (OsIndications bit 0) for the manual key import"
    inst_exec host "if [ \"\${INST_SB_ENROLLED:-}\" = \"1\" ]; then reboot; fi # §9.1: direct reboot to disk (NVRAM enrollment succeeded, ADR-20)"
  else
    info "install: reboot suppressed (ALPINE_FDE_INSTALL_NO_REBOOT/--no-reboot) — CI seam"
  fi

  inst_emit_finish
  rm -f "$_im_lukskey" 2>/dev/null
  if [ "${INST_SB_ENROLLED:-}" = "1" ]; then
    printf 'alpine-fde: install complete — direct reboot to disk (NVRAM enrollment succeeded); first boot unlocks via the provisional token and auto-finalizes under Secure Boot (§9.1 Stage 2); `alpine-fde finalize` is the guided/crash-resume entry point (ADR-20)\n' >&2
  elif [ "${INST_SB_DEFERRED:-}" = "1" ]; then
    printf 'alpine-fde: install complete — a platform key is ALREADY enrolled (factory or custom): NO NVRAM writes were attempted; import the release certificate db.cer plus the vendor certificate INTO THE EXISTING key database via the firmware UI from %s/alpine-fde-keys — the installer reboots into firmware setup for the import (the existing PK and KEK stay; first boot stays guarded until db.cer is imported, ADR-20)\n' "$_im_esp_mnt" >&2
  else
    printf 'alpine-fde: install complete — firmware NVRAM enrollment was REFUSED: the Secure Boot key material is staged under %s/alpine-fde-keys; the installer reboots into firmware setup for the manual key import (first boot stays guarded until the keys are imported, ADR-20)\n' "$_im_esp_mnt" >&2
  fi
  return 0
}
