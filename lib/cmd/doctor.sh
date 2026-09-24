#!/bin/sh
# doctor.sh — `alpine-fde doctor`: environment readiness report (§8.1, §13).
# Checks binaries/packages, TPM reachability, Secure Boot state, apk/apt config,
# OVMF CI extras. READ-ONLY: never installs anything (no require_pkgs here,
# no `apk add`/`apt-get install` anywhere) and never mutates state.
# Exit 0 = ready, 1 = not ready (missing hard-required binaries or unreachable
# TPM); degraded-but-usable items are warnings only.

if [ -n "${ALPINE_FDE_DOCTOR_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_DOCTOR_LOADED=1

# Every bucket-C command file pulls the shared baseline/common/firmware layer
# (baseline.sh lazy-loads common.sh + firmware.sh relative to ALPINE_FDE_CMD_DIR).
if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090  # resolved from ALPINE_FDE_CMD_DIR / install tree
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi

# hard-required provisioning tools: binary:package — the Alpine set (§3.1/§13;
# installed on demand at command time per ADR-15; doctor only reports).
# systemd-cryptenroll, dracut and debootstrap are deliberately absent: none is
# packaged on Alpine v3.24 (ADR-19/ADR-13) and none belongs in the Alpine boot
# or unlock path.
ALPINE_FDE_DOCTOR_PKGS='
tpm2:tpm2-tools
cryptsetup:cryptsetup
ukify:ukify
bootctl:systemd-boot
sbsign:sbsigntool
openssl:openssl
mkinitfs:mkinitfs
'

# host-installer tools (§13): enforced by the `install` preflight before disk
# mutation; doctor only surfaces them — missing entries are warnings and never
# gate the verdict. make-bcache matters only for --bcache (§4.1).
ALPINE_FDE_DOCTOR_HOST_PKGS='
sfdisk:util-linux
lsblk:util-linux
mkfs.vfat:dosfstools
mkfs.btrfs:btrfs-progs
make-bcache:bcache-tools
'

# CI/e2e extras: reported, never gate the verdict
ALPINE_FDE_DOCTOR_CI_PKGS='
swtpm:swtpm
qemu-system-x86_64:qemu-system-x86
virt-fw-vars:virt-firmware
jq:jq
'

doctor_usage() {
    cat >&2 <<EOF
Usage: alpine-fde doctor

Environment readiness check (no changes): binaries/packages (auto-install
happens only in other commands, ADR-15), TPM presence, Secure Boot state,
apk/apt configuration, CI extras. Exit 0 ready / 1 not ready.
EOF
}

# doctor_binary_item PAIR — print "[ok]"/"[missing]" line for binary:package
doctor_binary_item() {
    _dbi_bin=${1%%:*}
    _dbi_pkg=${1#*:}
    if command -v "$_dbi_bin" >/dev/null 2>&1; then
        printf '[ok]      %-22s (%s)\n' "$_dbi_bin" "$_dbi_pkg"
        return 0
    fi
    printf '[missing] %-22s (%s) — commands needing it will install it on demand\n' "$_dbi_bin" "$_dbi_pkg"
    # backend-aware manual hint (ADR-15): the on-demand installer uses apk when
    # it is the present manager, else apt-get — the hint must match
    if command -v apk >/dev/null 2>&1; then
        printf '          manual: apk add %s\n' "$_dbi_pkg"
    else
        printf '          manual: apt-get install -y --no-install-recommends %s\n' "$_dbi_pkg"
    fi
    return 1
}

# doctor_optional_item PAIR — non-gating [ok]/[warn] line for an optional tool
# (host-installer set, §13): absence is a warning, never a hard failure.
doctor_optional_item() {
    _doi_bin=${1%%:*}
    _doi_pkg=${1#*:}
    if command -v "$_doi_bin" >/dev/null 2>&1; then
        printf '[ok]      %-22s (%s)\n' "$_doi_bin" "$_doi_pkg"
        return 0
    fi
    printf '[warn]    %-22s (%s) optional here — install preflight checks it (§13)\n' "$_doi_bin" "$_doi_pkg"
    return 1
}

# doctor_bootctl_version — report the systemd-boot version against the ADR-1
# pin (Alpine ≥ 3.24 ships 260.2). Older → warning naming the pin, never
# gating; bootctl missing is already covered by the hard-binary check.
doctor_bootctl_version() {
    command -v bootctl >/dev/null 2>&1 || return 0
    _dbv_out=$(bootctl --version 2>/dev/null) || _dbv_out=""
    # first line, last word, digits-and-dots only (real bootctl: "systemd 260.2")
    _dbv_tok=$(printf '%s\n' "$_dbv_out" | sed -n '1p')
    _dbv_tok=${_dbv_tok##*' '}
    _dbv_v=""
    case $_dbv_tok in
        *[!0-9.]*) ;;
        *.*) _dbv_v=$_dbv_tok ;;
    esac
    _dbv_maj=${_dbv_v%%.*}
    _dbv_min=${_dbv_v#*.}
    case "${_dbv_maj}${_dbv_min}" in
        ''|*[!0-9]*)
            printf '[info]    systemd-boot version unparsable (%s)\n' "$(printf '%s\n' "$_dbv_out" | sed -n '1p')"
            return 0
            ;;
    esac
    if [ "$_dbv_maj" -lt 260 ] || { [ "$_dbv_maj" -eq 260 ] && [ "$_dbv_min" -lt 2 ]; }; then
        printf '[warn]    systemd-boot %s is older than the ADR-1 pin 260.2 (Alpine ≥ 3.24)\n' "$_dbv_v"
    else
        printf '[ok]      systemd-boot %s (ADR-1 pin ≥ 260.2 satisfied)\n' "$_dbv_v"
    fi
    return 0
}

# doctor_pcr_bank_report — §13 "x86_64 UEFI machine with TPM 2.0 (SHA-256
# PCRs)": verify the TPM actually selects a SHA-256 PCR bank. Readiness must
# not rest on `tpm getcap properties-fixed` alone (tpm_available) or a
# SHA-1-only TPM would read READY. Goes through the same `tpm` seam as
# tpm_available (lib/common.sh / lib/baseline.sh), so tests stub it via the
# tpm2 binary on PATH; only reached when a TPM already answered.
#   sha256 bank selected → [ok]
#   probe fails / output unparsable → [warn], rc 0 — "cannot determine" is
#                          never a gate (mirrors the SB probe's warn-on-
#                          unreadable and bootctl's warn-on-unparsable rules)
#   banks parsed, none sha256 → [fail], rc 1 — the §13 baseline machine is
#                          absent; the caller counts it exactly like an
#                          unreachable TPM (the dominant gating convention in
#                          this section)
doctor_pcr_bank_report() {
    _dpb_out=$(tpm getcap pcrs 2>/dev/null) || {
        printf '[warn]    could not read PCR bank selection (tpm2 getcap pcrs failed) — SHA-256 bank unverified (§13)\n'
        return 0
    }
    # one "- <bank>: [ ... ]" line per selected bank (tpm2-tools 5.x); the
    # dash-less "<bank>:" header form (4.x-era output) is accepted too
    _dpb_banks=$(printf '%s\n' "$_dpb_out" | sed -n \
        -e 's/^[[:space:]]*-[[:space:]]*\([a-z0-9]*\):.*/\1/p' \
        -e 's/^[[:space:]]*\([a-z0-9]*\):.*/\1/p' | tr '\n' ' ')
    if [ -z "$_dpb_banks" ]; then
        printf '[warn]    could not parse PCR bank selection (unrecognized tpm2 getcap pcrs output) — SHA-256 bank unverified (§13)\n'
        return 0
    fi
    case $_dpb_banks in
        *sha256*)
            printf '[ok]      SHA-256 PCR bank present (§13: SHA-256 PCRs)\n'
            return 0
            ;;
    esac
    printf '[fail]    no SHA-256 PCR bank — TPM selects only: %s(§13 requires SHA-256 PCRs)\n' "$_dpb_banks"
    return 1
}

# doctor_apt_report — apt configuration probe (read-only; no network fetch)
doctor_apt_report() {
    if ! command -v apt-get >/dev/null 2>&1; then
        printf '[warn]    apt-get not found (non-Debian system?) — on-demand package install unavailable (ADR-15)\n'
        return 1
    fi
    if apt-get check >/dev/null 2>&1; then
        printf '[ok]      apt-get present, local package db consistent\n'
    else
        printf '[warn]    apt-get present but local package db inconsistent (apt-get check failed)\n'
    fi
    # Reachability proxy: resolve fetch URIs without downloading (read-only).
    if apt-get -o Debug::NoLocking=1 update --print-uris >/dev/null 2>&1; then
        printf '[ok]      apt repository configuration resolvable (no fetch performed)\n'
    else
        printf '[warn]    apt could not resolve repository URIs (run apt-get update? offline?)\n'
    fi
    return 0
}

# doctor_apk_report — apk repository probe (§8.1 "apk/network reachability").
# Same contract as the apt probe: warn-only, never gates, never installs
# (`apk update` refreshes the index only; `apk add` appears nowhere here).
doctor_apk_report() {
    if ! command -v apk >/dev/null 2>&1; then
        printf '[warn]    apk not found (non-Alpine system?) — on-demand package install unavailable (ADR-15)\n'
        return 1
    fi
    if apk update >/dev/null 2>&1; then
        printf '[ok]      apk repository index reachable (no packages installed)\n'
    else
        printf '[warn]    apk could not reach the repository index (apk update failed; offline?)\n'
    fi
    return 0
}

# doctor_ovmf_report — OVMF firmware (code + vars) presence for the CI/QEMU
# path (§8.1 "OVMF/QEMU prereqs (CI)", §3.1 CI host). Non-gating: present and
# absent are both informational. Env seam: ALPINE_FDE_OVMF_DIR overrides the
# search dir (same ALPINE_FDE_* convention as ALPINE_FDE_EFIVARS_DIR); unset,
# known install locations are tried.
doctor_ovmf_report() {
    _dov_dir=${ALPINE_FDE_OVMF_DIR:-}
    if [ -z "$_dov_dir" ]; then
        for _dov_dir in /usr/share/OVMF /usr/share/ovmf/x64 /usr/share/ovmf /usr/share/qemu; do
            [ -d "$_dov_dir" ] && break
        done
    fi
    if [ -z "$_dov_dir" ] || [ ! -d "$_dov_dir" ]; then
        printf '[warn]    OVMF firmware not found (CI/QEMU only; apk add edk2-ovmf)\n'
        return 1
    fi
    _dov_code=""
    for _dov_f in OVMF_CODE_4M.fd OVMF_CODE.fd; do
        if [ -f "$_dov_dir/$_dov_f" ]; then _dov_code=$_dov_dir/$_dov_f; break; fi
    done
    _dov_vars=""
    for _dov_f in OVMF_VARS_4M.fd OVMF_VARS.fd; do
        if [ -f "$_dov_dir/$_dov_f" ]; then _dov_vars=$_dov_dir/$_dov_f; break; fi
    done
    if [ -n "$_dov_code" ] && [ -n "$_dov_vars" ]; then
        printf '[ok]      OVMF code + vars present (%s)\n' "$_dov_dir"
        return 0
    fi
    if [ -n "$_dov_code" ] || [ -n "$_dov_vars" ]; then
        printf '[warn]    OVMF partially present in %s (code: %s, vars: %s)\n' \
            "$_dov_dir" "${_dov_code:-<none>}" "${_dov_vars:-<none>}"
        return 1
    fi
    printf '[warn]    OVMF firmware not found in %s (CI/QEMU only; apk add edk2-ovmf)\n' "$_dov_dir"
    return 1
}

# doctor_manual_prereqs — §13 manual prerequisites that no probe can check
# (read-only doctor, §8.1 "no changes"): the firmware admin password and the
# offline custody / off-machine backup plan for the release signing key.
# Purely informational [info] rows — they never gate the verdict or the exit
# code (G-A14).
doctor_manual_prereqs() {
    printf '[info]    manual prereq (§13): firmware admin password set — keeps the evil maid out of firmware setup (cannot be probed)\n'
    printf '[info]    manual prereq (§13): offline custody / off-machine backup plan for the release signing key (cannot be probed)\n'
    return 0
}

cmd_doctor_main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        doctor_usage
        return 0
    fi
    if [ "$#" -gt 0 ]; then
        die -r "$ALPINE_FDE_USAGE" "doctor: unexpected argument: $1"
    fi

    _dd_missing=0
    printf 'alpine-fde doctor — readiness report (no changes made)\n'
    printf '\nprovisioning tools (binary:package):\n'
    # shellcheck disable=SC2086  # deliberate word split over the list
    for _dd_pair in $ALPINE_FDE_DOCTOR_PKGS; do
        doctor_binary_item "$_dd_pair" || _dd_missing=$((_dd_missing + 1))
    done
    # ADR-1 pin readout — informational/warning, never gates
    doctor_bootctl_version || true

    printf '\nhost-installer tools (install preflight enforces these; warnings only here, §13):\n'
    # shellcheck disable=SC2086  # deliberate word split over the list
    for _dd_pair in $ALPINE_FDE_DOCTOR_HOST_PKGS; do
        doctor_optional_item "$_dd_pair" || true
    done

    printf '\nTPM:\n'
    if [ -n "${ALPINE_FDE_TCTI:-}" ]; then
        printf '[info]    TCTI override: %s\n' "$ALPINE_FDE_TCTI"
    fi
    if tpm_available; then
        printf '[ok]      TPM 2.0 reachable (tpm2 getcap properties-fixed)\n'
        # §13: readiness also requires the SHA-256 PCR bank (G-A13) — a
        # SHA-1-only TPM must not read READY. A [fail] here counts like the
        # unreachable-TPM [fail] above; the warn-on-probe-error path returns 0.
        doctor_pcr_bank_report || _dd_missing=$((_dd_missing + 1))
    else
        printf '[fail]    no TPM 2.0 answered (TCTI: %s)\n' "${ALPINE_FDE_TCTI:-<default discovery>}"
        _dd_missing=$((_dd_missing + 1))
    fi

    printf '\nSecure Boot (efivarfs: %s):\n' "$(fw_efivars_dir)"
    if _dd_sb=$(fw_sb_state); then
        printf '[ok]      %s\n' "$_dd_sb"
        case $_dd_sb in
            *setup_mode=1*)
                printf '[warn]    SetupMode=1 — firmware in key-enrollment mode; custom keys not active yet (§9.1)\n'
                ;;
        esac
    else
        printf '[warn]    Secure Boot not confirmed on: %s\n' "$_dd_sb"
        printf '          (enroll-tpm refuses to run until SB is on and SetupMode=0)\n'
    fi

    printf '\napt:\n'
    # H-01: the apt report is pure output — its rc-1 (apt-get absent, e.g. the
    # CI host per §8.1/§3.1) must not abort the run under errexit; apt problems
    # are warnings and the CI-extras section + verdict below still print.
    doctor_apt_report || true

    printf '\napk:\n'
    # H-01: same read-only/warn-only contract as the apt probe above — an
    # rc-1 here (apk absent, e.g. the Debian-era host) must not abort the run
    # under errexit; apk problems are warnings and the sections + verdict
    # below still print. Doctor never installs (no `apk add`).
    doctor_apk_report || true

    printf '\nCI extras (informational, non-gating):\n'
    # shellcheck disable=SC2086
    for _dd_pair in $ALPINE_FDE_DOCTOR_CI_PKGS; do
        doctor_binary_item "$_dd_pair" || true
    done
    # OVMF prereqs for the CI/QEMU path — informational, never gates (§8.1)
    doctor_ovmf_report || true

    printf '\nmanual prerequisites (§13, advisory — cannot be probed, never gates):\n'
    doctor_manual_prereqs

    printf '\nverdict: '
    if [ "$_dd_missing" -gt 0 ]; then
        printf 'NOT READY (%s problem(s) above)\n' "$_dd_missing"
        return 1
    fi
    printf 'READY\n'
    return 0
}
