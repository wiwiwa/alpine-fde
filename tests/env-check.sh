#!/usr/bin/env bash
# tests/env-check.sh — verify every prerequisite of the Alpine FDE test
# harness (docs/Architecture.md §12 sandbox). CI host requirement: bash
# (the whole test suite is bash-based — §3.1; R3 keeps this gate in bash).
# Prints MISSING items and exits 1 if anything is absent; prints nothing
# per-item when all green (advisory WARNING lines — e.g. the KVM probe —
# never gate).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
MISSING=()

check_cmd() {
    command -v "$1" >/dev/null 2>&1 || MISSING+=("command: $1")
}

# CI host toolchain (§3.1). sbctl is deliberately NOT required (G-A13): it
# is Arch-native, absent from the §3.1 CI additions and from Alpine v3.24 —
# sbsign/sbverify already cover the signing-tooling requirement.
for c in tpm2_getcap tpm2_pcrread swtpm swtpm_setup swtpm_ioctl \
         qemu-system-x86_64 sbsign sbverify jq python3 \
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

# OVMF Secure Boot firmware (§3.1 CI `edk2-ovmf`). Resolution (G-A14):
#   1. ALPINE_FDE_OVMF_DIR — the only directory seam (the retired
#      DEBIAN_FDE_OVMF_DIR spelling is no longer honored). An explicit override
#      REPLACES the known-locations scan: an override dir without a code/vars
#      pair is a loud missing, never a silent fallback to system firmware.
#   2. Known locations covering the Debian AND Alpine edk2-ovmf layouts.
# The gate fails only when NO candidate ships a secboot code + vars pair.
ovmf_candidates() {
    local d
    if [[ -n "${ALPINE_FDE_OVMF_DIR:-}" ]]; then
        printf '%s\n' "$ALPINE_FDE_OVMF_DIR"
        return 0
    fi
    for d in /usr/share/ovmf/x64 /usr/share/OVMF /usr/share/OVMF/x64 \
             /usr/share/edk2-ovmf /usr/share/edk2-ovmf/x64; do
        printf '%s\n' "$d"
    done
}

# resolve_ovmf <code-out-var> <vars-out-var> — first candidate dir shipping a
# full pair; name variants cover 4m and non-4m OVMF builds across distros.
resolve_ovmf() {
    local d code vars
    while IFS= read -r d; do
        while read -r code vars; do
            if [[ -f "$d/$code" && -f "$d/$vars" ]]; then
                printf -v "$1" '%s' "$d/$code"
                printf -v "$2" '%s' "$d/$vars"
                return 0
            fi
        done <<'EOF'
OVMF_CODE.secboot.4m.fd OVMF_VARS.4m.fd
OVMF_CODE_4M.secboot.fd OVMF_VARS_4M.fd
OVMF_CODE.secboot.fd OVMF_VARS.fd
EOF
    done < <(ovmf_candidates)
    return 1
}

OVMF_CODE_R="" OVMF_VARS_R=""
if resolve_ovmf OVMF_CODE_R OVMF_VARS_R; then
    :  # resolved below; a missing pair is the only OVMF failure class
else
    MISSING+=("ovmf: no OVMF secboot code/vars pair found (set ALPINE_FDE_OVMF_DIR or install edk2-ovmf, §3.1)")
fi

# OVMF fixture SHA256 pins (§3.1: the harness, not the doc, is the pin of
# record). CI pinning its own artifacts overrides via ALPINE_FDE_OVMF_CODE_SHA256
# / ALPINE_FDE_OVMF_VARS_SHA256 (see tests/lib/qemu.sh); a local file that
# matches neither is a loud failure naming the mismatch. The resolved files
# are injected via qemu.sh's OVMF_CODE / OVMF_VARS_STOCK path-override seam.
if [[ -n "$OVMF_CODE_R" ]]; then
    # consumed by the sourced lib/qemu.sh pin check (_qemu_ovmf_code/_vars)
    # shellcheck disable=SC2034
    OVMF_CODE="$OVMF_CODE_R"
    # shellcheck disable=SC2034
    OVMF_VARS_STOCK="$OVMF_VARS_R"
    # shellcheck source=lib/qemu.sh
    source "$HERE/lib/qemu.sh"
    if ! PIN_OUT=$(ovmf_pin_check 2>&1); then
        while IFS= read -r pin_line; do
            MISSING+=("$pin_line")
        done <<<"$PIN_OUT"
    fi
fi

# Advisory KVM probe (§12; G-E7) — same /dev/kvm presence+writability
# semantics as lib/qemu.sh's _qemu_kvm_ok, minus the qemu probe guest: this
# gate stays cheap and side-effect-free (qemu.sh re-probes for real at
# qemu_run time). WARNING-class: never gates unit-only workflows — e2e fails
# closed on its own via _qemu_accel_choose unless ALPINE_FDE_ACCEL=tcg.
if [[ -e /dev/kvm && -w /dev/kvm ]]; then
    echo "env-check: KVM: /dev/kvm present+usable" >&2
else
    echo "env-check: WARNING: /dev/kvm missing or not writable — e2e will fail closed (ALPINE_FDE_ACCEL=tcg to opt out)" >&2
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
