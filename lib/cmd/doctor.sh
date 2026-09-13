#!/bin/sh
# doctor.sh — `debian-fde doctor`: environment readiness report (§8.1, §13).
# Checks binaries/packages, TPM reachability, Secure Boot state, apt config,
# and CI extras. READ-ONLY: never installs anything (no require_pkgs here) and
# never mutates state. Exit 0 = ready, 1 = not ready (missing hard-required
# binaries or unreachable TPM); degraded-but-usable items are warnings only.

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

# hard-required provisioning tools: binary:package (installed on demand at
# command time per ADR-15; doctor only reports)
DEBIAN_FDE_DOCTOR_PKGS='
tpm2:tpm2-tools
cryptsetup:cryptsetup
systemd-cryptenroll:systemd-cryptsetup
ukify:systemd-ukify
bootctl:systemd-boot-tools
sbsign:sbsigntool
openssl:openssl
dracut:dracut
debootstrap:debootstrap
'

# CI/e2e extras: reported, never gate the verdict
DEBIAN_FDE_DOCTOR_CI_PKGS='
swtpm:swtpm
qemu-system-x86_64:qemu-system-x86
virt-fw-vars:virt-firmware
mkfs.vfat:dosfstools
jq:jq
'

doctor_usage() {
    cat >&2 <<EOF
Usage: debian-fde doctor

Environment readiness check (no changes): binaries/packages (auto-install
happens only in other commands, ADR-15), TPM presence, Secure Boot state,
apt configuration, CI extras. Exit 0 ready / 1 not ready.
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
    printf '          manual: apt-get install -y --no-install-recommends %s\n' "$_dbi_pkg"
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

    printf '\nCI extras (informational, non-gating):\n'
    # shellcheck disable=SC2086
    for _dd_pair in $DEBIAN_FDE_DOCTOR_CI_PKGS; do
        doctor_binary_item "$_dd_pair" || true
    done

    printf '\nverdict: '
    if [ "$_dd_missing" -gt 0 ]; then
        printf 'NOT READY (%s problem(s) above)\n' "$_dd_missing"
        return 1
    fi
    printf 'READY\n'
    return 0
}
