#!/usr/bin/env bash
# tests/env-check.sh — verify every prerequisite of the Debian FDE test
# harness (docs/Architecture.md §12 sandbox). Prints MISSING items and
# exits 1 if anything is absent; prints nothing per-item when all green.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
MISSING=()

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || MISSING+=("command: $1")
}

check_file() {
    [[ -f "$1" ]] || MISSING+=("file: $1")
}

# CI host toolchain (§3.1)
for c in tpm2_getcap tpm2_pcrread swtpm swtpm_setup swtpm_ioctl \
         qemu-system-x86_64 sbsign sbverify sbctl jq python3 \
         ar strings tar; do
    check_cmd "$c"
done

# ESP image tooling (no root needed) + offline OVMF var enrollment
check_cmd virt-fw-vars
check_cmd mkfs.vfat
check_cmd mcopy
check_cmd mdir

# Tools the scenarios/fixtures hard-require (MD-04: an env failure must
# surface here as the exit-64 class, never mid-scenario): cryptsetup (disk
# fixture), debugfs + sfdisk (rootfs payload derivation, uki-build.sh),
# truncate (disk/ESP/payload images), tpm2 multitool (s00b tooling payload).
check_cmd cryptsetup
check_cmd debugfs
check_cmd sfdisk
check_cmd truncate
check_cmd tpm2

# OVMF Secure Boot firmware
check_file /usr/share/ovmf/x64/OVMF_CODE.secboot.4m.fd
check_file /usr/share/ovmf/x64/OVMF_VARS.4m.fd

# OVMF fixture SHA256 pins (§3.1: the harness, not the doc, is the pin of
# record). CI pinning its own artifacts overrides via DEBIAN_FDE_OVMF_CODE_SHA256
# / DEBIAN_FDE_OVMF_VARS_SHA256 (see tests/lib/qemu.sh); a local file that
# matches neither is a loud failure naming the mismatch.
if [[ -f /usr/share/ovmf/x64/OVMF_CODE.secboot.4m.fd \
        && -f /usr/share/ovmf/x64/OVMF_VARS.4m.fd ]]; then
    # shellcheck source=lib/qemu.sh
    source "$HERE/lib/qemu.sh"
    if ! PIN_OUT=$(ovmf_pin_check 2>&1); then
        while IFS= read -r pin_line; do
            MISSING+=("$pin_line")
        done <<<"$PIN_OUT"
    fi
fi

if (( ${#MISSING[@]} > 0 )); then
    echo "env-check: MISSING prerequisites:" >&2
    for m in "${MISSING[@]}"; do
        echo "  $m" >&2
    done
    exit 1
fi

echo "env-check: all prerequisites present"
exit 0
