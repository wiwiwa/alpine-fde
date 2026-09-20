#!/bin/sh
# doctor.sh — `debian-fde doctor`: environment readiness report (§8.1, §13).
# Checks binaries/packages, TPM reachability, Secure Boot state, apk/apt config,
# OVMF CI extras. READ-ONLY: never installs anything (no require_pkgs here,
# no `apk add`/`apt-get install` anywhere) and never mutates state.
# Exit 0 = ready, 1 = not ready (missing hard-required binaries or unreachable
# TPM); degraded-but-usable items are warnings only.

if [ -n "${DEBIAN_FDE_DOCTOR_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_DOCTOR_LOADED=1

# Every bucket-C command file pulls the shared baseline/common/firmware layer
# (baseline.sh lazy-loads common.sh + firmware.sh relative to DEBIAN_FDE_CMD_DIR).
if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090  # resolved from DEBIAN_FDE_CMD_DIR / install tree
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

# hard-required provisioning tools: binary:package — the Alpine set (§3.1/§13;
# installed on demand at command time per ADR-15; doctor only reports).
# systemd-cryptenroll, dracut and debootstrap are deliberately absent: none is
# packaged on Alpine v3.24 (ADR-19/ADR-13) and none belongs in the Alpine boot
# or unlock path.
DEBIAN_FDE_DOCTOR_PKGS='
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
DEBIAN_FDE_DOCTOR_HOST_PKGS='
sfdisk:util-linux
lsblk:util-linux
mkfs.vfat:dosfstools
mkfs.btrfs:btrfs-progs
make-bcache:bcache-tools
'

# CI/e2e extras: reported, never gate the verdict
DEBIAN_FDE_DOCTOR_CI_PKGS='
swtpm:swtpm
qemu-system-x86_64:qemu-system-x86
virt-fw-vars:virt-firmware
jq:jq
'

doctor_usage() {
    cat >&2 <<EOF
Usage: debian-fde doctor

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
# absent are both informational. Env seam: DEBIAN_FDE_OVMF_DIR overrides the
# search dir (same DEBIAN_FDE_* convention as DEBIAN_FDE_EFIVARS_DIR); unset,
# known install locations are tried.
doctor_ovmf_report() {
    _dov_dir=${DEBIAN_FDE_OVMF_DIR:-}
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

cmd_doctor_main() {
    if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
        doctor_usage
        return 0
    fi
    if [ "$#" -gt 0 ]; then
        die -r "$DEBIAN_FDE_USAGE" "doctor: unexpected argument: $1"
    fi

    _dd_missing=0
    printf 'debian-fde doctor — readiness report (no changes made)\n'
    printf '\nprovisioning tools (binary:package):\n'
    # shellcheck disable=SC2086  # deliberate word split over the list
    for _dd_pair in $DEBIAN_FDE_DOCTOR_PKGS; do
        doctor_binary_item "$_dd_pair" || _dd_missing=$((_dd_missing + 1))
    done
    # ADR-1 pin readout — informational/warning, never gates
    doctor_bootctl_version || true

    printf '\nhost-installer tools (install preflight enforces these; warnings only here, §13):\n'
    # shellcheck disable=SC2086  # deliberate word split over the list
    for _dd_pair in $DEBIAN_FDE_DOCTOR_HOST_PKGS; do
        doctor_optional_item "$_dd_pair" || true
    done

    printf '\nTPM:\n'
    if [ -n "${DEBIAN_FDE_TCTI:-}" ]; then
        printf '[info]    TCTI override: %s\n' "$DEBIAN_FDE_TCTI"
    fi
    if tpm_available; then
        printf '[ok]      TPM 2.0 reachable (tpm2 getcap properties-fixed)\n'
    else
        printf '[fail]    no TPM 2.0 answered (TCTI: %s)\n' "${DEBIAN_FDE_TCTI:-<default discovery>}"
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
    for _dd_pair in $DEBIAN_FDE_DOCTOR_CI_PKGS; do
        doctor_binary_item "$_dd_pair" || true
    done
    # OVMF prereqs for the CI/QEMU path — informational, never gates (§8.1)
    doctor_ovmf_report || true

    printf '\nverdict: '
    if [ "$_dd_missing" -gt 0 ]; then
        printf 'NOT READY (%s problem(s) above)\n' "$_dd_missing"
        return 1
    fi
    printf 'READY\n'
    return 0
}
