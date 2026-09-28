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

# --- UEFI boot entry (NVRAM; task #27, real-server follow-up) -----------------
# The install ends with the firmware pointing at the staged ESP: an NVRAM boot
# entry labeled "Alpine FDE" (capitalized, user decision after the real Dell
# PowerEdge install — Boot0005) targeting HD(1,GPT,<esp-part-guid>) ->
# \EFI\BOOT\BOOTX64.EFI, FIRST in BootOrder. Before this existed, the operator
# ran efibootmgr BY HAND after every fresh install, and after a RE-partition
# the hand-made entry kept the OLD partition GUID and died "Boot Failed" — so
# the ensure below is IDEMPOTENT: same-label entries pointing at the CURRENT
# ESP partition GUID + loader are reused (never duplicated), same-label
# entries pointing anywhere else are deleted and recreated.
#
# The record runs IN-GUEST (chroot runner): the ESP is mounted at the §8.1
# --esp path and the live NVRAM is reachable through the §9.1 efivars bind —
# exactly how the step-4 fw_auth_enroll NVRAM writes work. When efibootmgr
# reports NO EFI variable support (non-EFI host / test container), the step
# SKIPS with the exact manual command instead of failing the install.

# inst_bootentry_label — the NVRAM boot-entry label (capitalized, user decision)
inst_bootentry_label() { printf '%s\n' 'Alpine FDE'; }

# inst_bootentry_loader — the loader path the entry points at (the §8.3
# removable-media fallback home; the SAME binary the firmware loads with no
# NVRAM dependency, so the entry only ADDS an explicit boot-manager pick)
inst_bootentry_loader() { printf '%s\n' '\EFI\BOOT\BOOTX64.EFI'; }

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

# inst_bootentry_parse LABEL — stdin: `efibootmgr -v` output; stdout: ONE line
# per boot entry "NUM GUID LOADER OURS" (num + guid lowercased; guid "-" when
# the device path carries no HD(…,GPT,…); OURS=1 iff the entry's label is
# exactly LABEL). efibootmgr -v entry lines: "Boot<4hex><*|space> <label>
# <device path>" — the label starts at column 11; the -v device path is what
# carries HD(1,GPT,<guid>,…)/File(\EFI\BOOT\BOOTX64.EFI) (plain efibootmgr
# prints no paths — the parse MUST consume -v output).
inst_bootentry_parse() {
  awk -v lbl="$1" '
        tolower($0) ~ /^boot[0-9a-f][0-9a-f][0-9a-f][0-9a-f][* ]/ {
            num = tolower(substr($0, 5, 4))
            lc = tolower($0)
            rest = substr($0, 11)
            sub(/^[ \t]+/, "", rest)
            ours = 0
            if (index(rest, lbl) == 1) {
                after = substr(rest, length(lbl) + 1, 1)
                if (after == "" || after == " " || after == "\t") ours = 1
            }
            guid = "-"
            if (match(lc, /hd\([0-9]+,gpt,[0-9a-f][0-9a-f-]*,/)) {
                piece = substr(lc, RSTART, RLENGTH)
                sub(/^hd\([0-9]+,gpt,/, "", piece)
                sub(/,$/, "", piece)
                guid = piece
            }
            loader = (lc ~ /file\(\\efi\\boot\\bootx64\.efi\)/) ? 1 : 0
            printf "%s %s %d %d\n", num, guid, loader, ours
        }
    '
}

# inst_bootentry_find LIST LC_GUID — the first (of LIST, inst_bootentry_parse
# form) entry labeled for us that already points at LC_GUID + our loader (the
# reuse case); empty when none does.
inst_bootentry_find() {
  _ibf_lcguid=$2
  printf '%s\n' "$1" | while IFS=' ' read -r _ibf_n _ibf_g _ibf_l _ibf_o; do
    if [ "$_ibf_o" = "1" ] && [ "$_ibf_g" = "$_ibf_lcguid" ] && [ "$_ibf_l" = "1" ]; then
      printf '%s\n' "$_ibf_n"
      break
    fi
  done
  return 0
}

# inst_bootentry_ensure ESPDEV ESP_MNT — the in-guest executor (idempotent,
# crash-resume safe; re-runs converge). ESPDEV is the ESP partition device
# (§4.1 layout, e.g. /dev/sda1 — visible in-guest through the /dev bind),
# ESP_MNT the §8.1 ESP mount under the target root (/). The partition GUID the
# entry pins comes from the §8.4 target metadata (target.esp_partuuid in the
# on-target baseline — the SAME GUID fstab pins), NOT a fresh probe: the
# in-guest closure carries no lsblk (util-linux is live-side only).
inst_bootentry_ensure() {
  _ibe_esp=$1
  _ibe_espdir=$2
  _ibe_eb=$(inst_efibootmgr)
  _ibe_lbl=$(inst_bootentry_label)
  _ibe_ldr=$(inst_bootentry_loader)
  # fail-closed: the loader the entry points at must already be staged (§8.3
  # boot-manager copy + the kernel build's re-sign run BEFORE this record)
  [ -f "$_ibe_espdir/EFI/BOOT/BOOTX64.EFI" ] ||
    die "install: $_ibe_espdir/EFI/BOOT/BOOTX64.EFI is missing — refusing to create the '$_ibe_lbl' boot entry before the ESP is staged (the §8.3 boot-manager copy and the kernel build must run first)"
  _ibe_bl=$(sp_baseline_file)
  [ -f "$_ibe_bl" ] ||
    die "install: no baseline at $_ibe_bl — cannot resolve the ESP partition the '$_ibe_lbl' boot entry must point at"
  _ibe_pu=$(baseline_get_in "$_ibe_bl" target esp_partuuid)
  [ -n "$_ibe_pu" ] ||
    die "install: no target.esp_partuuid in $_ibe_bl — cannot resolve the ESP partition the '$_ibe_lbl' boot entry must point at (the §8.4 target-metadata step must run first)"
  _ibe_lcpu=$(printf '%s' "$_ibe_pu" | tr '[:upper:]' '[:lower:]')
  _ibe_split=$(inst_part_split "$_ibe_esp") ||
    die "install: cannot split the ESP device into disk + partition number: $_ibe_esp"
  # shellcheck disable=SC2086  # exactly two words: DISK PARTNUM
  set -- $_ibe_split
  _ibe_disk=$1
  _ibe_pn=$2
  # NO EFI variable support (non-EFI host / test container): SKIP with the
  # exact manual command — the removable-media loader path still boots, and a
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
    warn "install: no EFI variable support ($_ibe_vars) — SKIPPING the NVRAM boot entry (the removable-media path $_ibe_ldr still boots); create the entry manually:"
    warn "install:   efibootmgr -c -d $_ibe_disk -p $_ibe_pn -L '$_ibe_lbl' -l '$_ibe_ldr'   (then 'efibootmgr -o <NUM>,...' with the new number FIRST, pointing at the ESP partition GUID $_ibe_pu)"
    return 0
  fi
  # stale same-label entries FIRST (a re-partitioned ESP leaves the OLD
  # partition GUID in NVRAM — the real server booted them into "Boot
  # Failed"), and extra DUPLICATES of an already-matching entry (a re-run
  # pile-up) — then reuse-or-create against the CURRENT ESP partition
  _ibe_stale=''
  _ibe_keep=''
  while IFS=' ' read -r _ibe_n _ibe_g _ibe_l _ibe_o; do
    [ -n "${_ibe_n:-}" ] || continue
    [ "$_ibe_o" = "1" ] || continue
    if [ "$_ibe_g" = "$_ibe_lcpu" ] && [ "$_ibe_l" = "1" ]; then
      if [ -z "$_ibe_keep" ]; then
        _ibe_keep=$_ibe_n
      else
        _ibe_stale="$_ibe_stale $_ibe_n"
      fi
      continue
    fi
    _ibe_stale="$_ibe_stale $_ibe_n"
  done <<EOF
$(printf '%s\n' "$_ibe_list" | inst_bootentry_parse "$_ibe_lbl")
EOF
  for _ibe_n in $_ibe_stale; do
    "$_ibe_eb" -b "$_ibe_n" -B >/dev/null ||
      die "install: cannot delete the stale boot entry Boot$_ibe_n (label '$_ibe_lbl', partition GUID differs from the ESP's $_ibe_pu — a stale GUID boots \"Boot Failed\")"
    info "install: deleted stale boot entry Boot$_ibe_n (label '$_ibe_lbl', old partition GUID or duplicate) — the entry now resolves against the current ESP ($_ibe_pu)"
  done
  _ibe_fresh=$("$_ibe_eb" -v 2>/dev/null | inst_bootentry_parse "$_ibe_lbl")
  _ibe_mine=$_ibe_keep
  if [ -n "$_ibe_mine" ]; then
    info "install: reusing boot entry Boot$_ibe_mine '$_ibe_lbl' (already points at HD(1,GPT,$_ibe_pu) $_ibe_ldr) — no duplicate created"
  else
    "$_ibe_eb" -c -d "$_ibe_disk" -p "$_ibe_pn" -L "$_ibe_lbl" -l "$_ibe_ldr" >/dev/null ||
      die "install: efibootmgr -c failed — the '$_ibe_lbl' boot entry ($_ibe_disk -p $_ibe_pn -> $_ibe_ldr) could not be created"
    # Real-server evidence (Dell PowerEdge R640, 2026-09-28): the create's
    # BootOrder update persisted, but the new Boot variable was NOT yet visible
    # in the immediate post-create listing — some firmware commits the variable
    # late (NVRAM write latency; it was present and correct minutes later). The
    # old immediate verify refused fail-closed and killed an
    # otherwise-complete install. Bounded backoff: re-read the listing up to 5
    # attempts, 2s apart (~10s; ALPINE_FDE_NVRAM_RETRY_SLEEP is the test seam
    # for the interval), each re-verifying the SAME label + GUID +
    # loader match (inst_bootentry_find), before declaring failure.
    _ibe_try=0
    while :; do
      _ibe_fresh=$("$_ibe_eb" -v 2>/dev/null | inst_bootentry_parse "$_ibe_lbl")
      _ibe_mine=$(inst_bootentry_find "$_ibe_fresh" "$_ibe_lcpu")
      [ -n "$_ibe_mine" ] && break
      _ibe_try=$((_ibe_try + 1))
      [ "$_ibe_try" -ge 5 ] && break
      warn "install: the '$_ibe_lbl' entry is not in the efibootmgr listing yet (attempt $_ibe_try/5) — likely firmware NVRAM write latency (Dell); retrying"
      sleep "${ALPINE_FDE_NVRAM_RETRY_SLEEP:-2}"
    done
    [ -n "$_ibe_mine" ] ||
      die "install: the '$_ibe_lbl' boot entry was created but is not in the efibootmgr listing after 5 attempts (~10s) — refusing to guess the entry number (likely cause: firmware NVRAM write latency — some firmware, notably Dell, commits the new boot variable late; re-running the install converges idempotently, or create the entry manually)"
    info "install: created boot entry Boot$_ibe_mine '$_ibe_lbl' -> HD(1,GPT,$_ibe_pu) $_ibe_ldr"
  fi
  # FIRST in BootOrder: the previous order preserved behind us (still-existing
  # entries only — the deletes above do not rewrite BootOrder), entries the
  # listing has but BootOrder never mentioned appended defensively
  _ibe_all=$(printf '%s\n' "$_ibe_fresh" | awk 'NF { print $1 }' | tr '\n' ' ')
  _ibe_obo=$("$_ibe_eb" -v 2>/dev/null | awk '/^BootOrder:/ { sub(/^BootOrder:[ \t]*/, ""); print tolower($0) }' | tr ',' ' ')
  _ibe_new=" $_ibe_mine "
  for _ibe_n in $_ibe_obo $_ibe_all; do
    if [ "$_ibe_n" = "$_ibe_mine" ]; then continue; fi
    case $_ibe_new in
    *" $_ibe_n "*) continue ;;
    esac
    case " $_ibe_all " in
    *" $_ibe_n "*) _ibe_new="$_ibe_new$_ibe_n " ;;
    esac
  done
  _ibe_new=${_ibe_new% }
  _ibe_new=${_ibe_new# }
  _ibe_csv=$(printf '%s' "$_ibe_new" | tr ' ' ',')
  "$_ibe_eb" -o "$_ibe_csv" >/dev/null ||
    die "install: efibootmgr -o $_ibe_csv failed — '$_ibe_lbl' (Boot$_ibe_mine) could not be placed FIRST in BootOrder"
  info "install: Boot$_ibe_mine '$_ibe_lbl' is FIRST in BootOrder ($_ibe_csv)"
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
The UEFI boot entry (NVRAM, "Alpine FDE" -> the ESP partition's
HD(1,GPT,<guid>) -> \EFI\BOOT\BOOTX64.EFI) is created IN-GUEST after the
build — idempotently (same-GUID entries reused, stale-GUID entries replaced),
FIRST in BootOrder, and SKIPPED with the exact manual efibootmgr command when
no EFI variable support exists (task #27: the entry used to be typed by hand
on the real server after every install).

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
                rm -f "${_ime_kf:-}" "${_im_pf_host:-}" 2>/dev/null
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
# `kernel build`: its shell reads it into ALPINE_FDE_KEY_PASSPHRASE
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
#   1. extract the .pcrsig from the just-built UKI (stage-1 `kernel build`
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
  printf '%s\n' "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/seal.sh && require_pkgs objcopy:binutils && mkdir -p /run/alpine-fde && uki=\$(ls $_pel_esp/EFI/Linux/alpine-fde-*.efi | head -n 1); objcopy -O binary --only-section=.pcrsig \"\$uki\" /run/alpine-fde/pcrsig.json && for d in $_pel_cs; do seal_provisional /etc/alpine-fde/keys \$d /run/alpine-fde/pcrsig.json /run/alpine-fde/token-\${d##*/}.json \$uki && token_add_keyslot \$d \"\$SEAL_PASS_FILE\" \"\$SEAL_SLOT\" $_pel_key && token_import \$d /run/alpine-fde/token-\${d##*/}.json \"\$(token_next_id \$d)\" || exit 1; done && keys_scrub \"\$SEAL_PASS_FILE\" && rm -rf /run/alpine-fde \${ALPINE_FDE_TMPDIR:-\${TMPDIR:-/tmp}}/alpine-fde-seal.* # ADR-20 step 6: provisional Mechanism B seal (PCR 11) -> keyslot 1 on the CONTAINER dev (item 27); I1 seal-secret scrub"
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
  # Paths are plan-static and resolve for real in every lane (nothing is
  # staged until the ceremony writes the file at execute time).
  _im_pf_host=$_im_mnt/run/alpine-fde-release-pass
  _im_passfile_disp=$_im_pf_host
  _im_pf_guest=/run/alpine-fde-release-pass

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
    inst_exec host "mount -o subvol=@home $_im_mapper $_im_mnt/home"
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
  # DUAL CONSOLE BY DEFAULT (real-server, Dell PowerEdge R640 2026-09-28): the
  # pre-dual-console emission carried NO console= words, so a headless boot was
  # invisible on serial — the kernel logged to the (absent) video console only
  # and the initrd unseal hook's /dev/console went nowhere. We now emit
  # console=tty0 console=ttyS0,115200 BEFORE the rd.* pins: kernel messages
  # print to BOTH consoles, and the LAST console= word wins for /dev/console,
  # so the initrd unseal hook (and later /dev/console writers) land on serial.
  # ALPINE_FDE_CMDLINE_EXTRA still appends AFTER ours; a user-provided extra
  # containing console= words becomes the last console= and thus wins
  # /dev/console — acceptable (their explicit choice), NOT a pin violation
  # (the guard checks only the §8.2 H-G1 rd.* pins).
  if [ "$(inst_root_fs)" = "btrfs" ]; then
    inst_plan_write /etc/alpine-fde/cmdline.txt \
      "root=UUID=$_im_uuid rootflags=subvol=@ ro console=tty0 console=ttyS0,115200 rd.shell=0 rd.emergency=poweroff${_im_cmdline_extra:+ $_im_cmdline_extra}"
  else
    inst_plan_write /etc/alpine-fde/cmdline.txt \
      "root=UUID=$_im_uuid ro console=tty0 console=ttyS0,115200 rd.shell=0 rd.emergency=poweroff${_im_cmdline_extra:+ $_im_cmdline_extra}"
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
  inst_exec host "mkdir -p $_im_mnt/sys/firmware/efi/efivars && mount --bind /sys/firmware/efi/efivars $_im_mnt/sys/firmware/efi/efivars"

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
  inst_exec guest "adduser -D -s /bin/ash $_im_user && addgroup $_im_user wheel"
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
  # (inst_ceremony_release_key) encrypts it — its keys_is_encrypted gate only
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
  inst_exec host "inst_ceremony_recovery $_im_lukskey $_im_containers # §9.1 step 4 credential ceremony (1/3) — asked FIRST (item 12): LUKS2 recovery passphrase -> keyslot 0 of EVERY member CONTAINER via luksAddKey, authorized by the staged ephemeral install key. KDF pinned: Argon2id; §13 entropy floor enforced — re-prompt until met, confirm-typed"
  inst_exec host "inst_ceremony_user_password $_im_user $_im_mnt # §9.1 step 4 credential ceremony (2/3): user account password (no-echo; press Enter to reuse the recovery passphrase — item 12 default-on-empty)"
  inst_exec host "inst_ceremony_release_key $_im_keys $_im_passfile_disp # §9.1 step 4 credential ceremony (3/3): release.pem encrypted AES-256 PBKDF2 (keys_encrypt_release, ADR-18; press Enter to reuse the recovery passphrase — item 12), mode 0400; 2nd arg = the 0600 passphrase seam file IN THE TARGET ROOT (<mnt>/run/... — guest /run/...; blocker #8/#9)"
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
  inst_exec guest "export ALPINE_FDE_ROOT=/; export ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys; [ -s $_im_pf_guest ] && ALPINE_FDE_KEY_PASSPHRASE=\$(cat $_im_pf_guest) && rm -f $_im_pf_guest && export ALPINE_FDE_KEY_PASSPHRASE; kv=\$(cd /lib/modules 2>/dev/null && ls -1d */ 2>/dev/null | tr -d '/' | sort -V | tail -n 1); [ -n \"\$kv\" ] || { echo 'alpine-fde: ERROR: no kernel module tree under /lib/modules — the linux-lts kernel package did not install into the target; fix the mirror/package set and re-run (completed steps skip via crash resume)' >&2; exit 1; }; /opt/alpine-fde/bin/alpine-fde kernel build \"\$kv\" # §9.1 step 5 (SECRET-dependent — after the ceremony): signed boot manager + initial UKI (baseline pending ⇒ the build's ensure-once enrollment is state-gated OFF — the PROVISIONAL seal is the only Stage 1 enrollment); blocker #8/#9: keydir exported (keys_dir has no default) + passphrase from the in-target 0600 seam file (never argv); blocker #11: target kver derived in-guest (uname -r is the LIVE ISO kernel); blocker #12: ALPINE_FDE_ROOT=/ — in-chroot the TARGET IS /, and without it the initrd audit has no kernel-reality context (verdicts degrade to bare 'missing' instead of suffix-tolerant satisfaction)"
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
  inst_exec guest "export ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd; . /opt/alpine-fde/lib/common.sh && . /opt/alpine-fde/lib/cmd/install.sh && require_pkgs efibootmgr:efibootmgr && inst_bootentry_ensure $_im_esp $_im_esp_mnt # task #27: the Alpine FDE NVRAM boot entry -> HD(1,GPT,<esp-part-guid>) \EFI\BOOT\BOOTX64.EFI, FIRST in BootOrder (idempotent; stale-GUID entries replaced)"

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
  inst_exec host "rm -f $_im_lukskey $_im_passfile_disp # I1: ephemeral install key + release-passphrase seam file scrubbed (§9.1 teardown; blocker #8/#9)"

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
  rm -f "$_im_lukskey" "${_im_pf_host:-}" 2>/dev/null
  if [ "${INST_SB_ENROLLED:-}" = "1" ]; then
    printf 'alpine-fde: install complete — direct reboot to disk (NVRAM enrollment succeeded); first boot unlocks via the provisional token and auto-finalizes under Secure Boot (§9.1 Stage 2); `alpine-fde finalize` is the guided/crash-resume entry point (ADR-20)\n' >&2
  elif [ "${INST_SB_DEFERRED:-}" = "1" ]; then
    printf 'alpine-fde: install complete — a platform key is ALREADY enrolled (factory or custom): NO NVRAM writes were attempted; import the release certificate db.cer plus the vendor certificate INTO THE EXISTING key database via the firmware UI from %s/alpine-fde-keys — the installer reboots into firmware setup for the import (the existing PK and KEK stay; first boot stays guarded until db.cer is imported, ADR-20)\n' "$_im_esp_mnt" >&2
  else
    printf 'alpine-fde: install complete — firmware NVRAM enrollment was REFUSED: the Secure Boot key material is staged under %s/alpine-fde-keys; the installer reboots into firmware setup for the manual key import (first boot stays guarded until the keys are imported, ADR-20)\n' "$_im_esp_mnt" >&2
  fi
  return 0
}
