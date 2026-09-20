#!/usr/bin/env bash
# env_check_seams.sh — unit tests for tests/env-check.sh seam behavior:
#   G-A13: sbctl (Arch-native, absent from the §3.1 CI additions and from
#          Alpine v3.24) is NOT a required command — its absence never gates.
#   G-A14: OVMF code/vars resolution via the ALPINE_FDE_OVMF_DIR directory
#          seam (DEBIAN_FDE_OVMF_DIR is the backwards-compatible alias;
#          ALPINE wins when both are set). An explicit override REPLACES the
#          known-locations scan (Debian + Alpine edk2-ovmf layouts): an
#          override without a code/vars pair is a loud missing, never a
#          silent system fallback; the gate fails only when NO candidate
#          ships a pair.
#   G-A15: the header names bash as a CI-host requirement (R3 resolution:
#          env-check stays bash; the §3.1 doc record must match).
#   G-E7:  advisory /dev/kvm probe — WARNING-class, non-gating, names the
#          DEBIAN_FDE_ACCEL=tcg opt-out, and never sources lib/qemu.sh.
#
# The gate runs in a fixture PATH: a stub dir holding a dummy executable for
# every required command (EXCEPT sbctl — deliberately absent to prove it is
# not required) plus symlinks to the few real binaries env-check's internals
# need (readlink/dirname for HERE, sha256sum/awk for the qemu.sh pin check,
# bash to exec the gate). PATH contains ONLY the fixture dir, so host
# tooling cannot leak in and the fixtures are hermetic.

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)
ENV_CHECK="$REPO_ROOT/tests/env-check.sh"

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"

# assert_lacks <desc> <haystack> <needle>
assert_lacks() {
    case $2 in
        *"$3"*) _fail "$1 ([$2] unexpectedly contains [$3])" ;;
        *) _pass "$1" ;;
    esac
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- fixture PATH -------------------------------------------------------------
fx="$tmp/stubbin"
mkdir -p "$fx"
REQUIRED_CMDS="tpm2_getcap tpm2_pcrread swtpm swtpm_setup swtpm_ioctl
qemu-system-x86_64 sbsign sbverify jq python3 ar strings tar
virt-fw-vars mkfs.vfat mcopy mdir cryptsetup debugfs sfdisk truncate tpm2"
for c in $REQUIRED_CMDS; do
    printf '#!/bin/sh\nexit 0\n' >"$fx/$c"
    chmod +x "$fx/$c"
done
# sbctl deliberately NOT stubbed (G-A13); real binaries the gate itself needs
# (env: applies the per-test seam overrides inside the fixture PATH):
for b in bash readlink dirname sha256sum awk env; do
    ln -s "$(command -v "$b")" "$fx/$b"
done

# mk_ovmf_dir <dir> <code-name> <vars-name> — fabricate an OVMF code/vars pair
mk_ovmf_dir() {
    mkdir -p "$1"
    printf 'FAKE-OVMF-CODE-%s' "$2" >"$1/$2"
    printf 'FAKE-OVMF-VARS-%s' "$3" >"$1/$3"
}

sha_of() { sha256sum "$1" | awk '{print $1}'; }

RC=0
OUT=""
run_env_check() {
    # `env` (not a literal assignment prefix) because "$@" words that look
    # like VAR=val are only assignment syntax when written literally.
    OUT=$(PATH="$fx" env "$@" bash "$ENV_CHECK" 2>&1)
    RC=$?
}

# fixtures: Alpine-layout pair (plain secboot names), alias dir carrying the
# Debian 4m names (also covers the 4m pair variant), and an empty override dir.
alpine_dir="$tmp/ovmf-alpine"
mk_ovmf_dir "$alpine_dir" OVMF_CODE.secboot.fd OVMF_VARS.fd
ALPINE_CODE_SHA=$(sha_of "$alpine_dir/OVMF_CODE.secboot.fd")
ALPINE_VARS_SHA=$(sha_of "$alpine_dir/OVMF_VARS.fd")

alias_dir="$tmp/ovmf-debian-4m"
mk_ovmf_dir "$alias_dir" OVMF_CODE.secboot.4m.fd OVMF_VARS.4m.fd
ALIAS_CODE_SHA=$(sha_of "$alias_dir/OVMF_CODE.secboot.4m.fd")
ALIAS_VARS_SHA=$(sha_of "$alias_dir/OVMF_VARS.4m.fd")

empty_dir="$tmp/ovmf-empty"
mkdir -p "$empty_dir"

# --- G-A13: sbctl absent from PATH -> gate stays green -------------------------
run_env_check ALPINE_FDE_OVMF_DIR="$alpine_dir" \
    DEBIAN_FDE_OVMF_CODE_SHA256="$ALPINE_CODE_SHA" \
    DEBIAN_FDE_OVMF_VARS_SHA256="$ALPINE_VARS_SHA"
assert_rc "G-A13: sbctl absent -> env-check rc 0" 0 "$RC"
assert_lacks "G-A13: output never names sbctl" "$OUT" "sbctl"

# --- G-A14: backwards-compatible alias dir (Debian 4m names) -------------------
run_env_check DEBIAN_FDE_OVMF_DIR="$alias_dir" \
    DEBIAN_FDE_OVMF_CODE_SHA256="$ALIAS_CODE_SHA" \
    DEBIAN_FDE_OVMF_VARS_SHA256="$ALIAS_VARS_SHA"
assert_rc "G-A14: DEBIAN_FDE_OVMF_DIR alias honored -> rc 0" 0 "$RC"
assert_contains "G-A14: alias pair found -> gate green" "$OUT" \
    "all prerequisites present"

# --- G-A14: ALPINE_FDE_OVMF_DIR wins when both seams are set -------------------
# Pins match ONLY the alpine dir's files: if resolution picked the alias dir
# instead, the pin check hashes the wrong pair and fails loudly.
run_env_check ALPINE_FDE_OVMF_DIR="$alpine_dir" DEBIAN_FDE_OVMF_DIR="$alias_dir" \
    DEBIAN_FDE_OVMF_CODE_SHA256="$ALPINE_CODE_SHA" \
    DEBIAN_FDE_OVMF_VARS_SHA256="$ALPINE_VARS_SHA"
assert_rc "G-A14: ALPINE_FDE_OVMF_DIR wins over alias -> rc 0" 0 "$RC"
assert_lacks "G-A14: losing alias dir never hashed (no pin mismatch)" "$OUT" \
    "ovmf-pin"

# --- G-A14: override dir WITHOUT a pair -> loud missing, never silent fallback --
run_env_check ALPINE_FDE_OVMF_DIR="$empty_dir"
assert_rc "G-A14: seam dir without pair -> rc 1" 1 "$RC"
assert_contains "G-A14: loud ovmf missing line" "$OUT" "ovmf:"

# --- G-E7: advisory KVM probe (host here has no usable /dev/kvm) ---------------
run_env_check ALPINE_FDE_OVMF_DIR="$alpine_dir" \
    DEBIAN_FDE_OVMF_CODE_SHA256="$ALPINE_CODE_SHA" \
    DEBIAN_FDE_OVMF_VARS_SHA256="$ALPINE_VARS_SHA"
assert_rc "G-E7: kvm state never changes env-check rc" 0 "$RC"
if [[ -e /dev/kvm && -w /dev/kvm ]]; then
    assert_lacks "G-E7: kvm usable -> no warning" "$OUT" "WARNING"
else
    assert_contains "G-E7: advisory names /dev/kvm" "$OUT" "/dev/kvm"
    assert_contains "G-E7: advisory names tcg opt-out" "$OUT" \
        "DEBIAN_FDE_ACCEL=tcg"
fi

# --- G-A15: header names bash as a CI-host requirement --------------------------
header=$(sed -n '2,8p' "$ENV_CHECK")
assert_contains "G-A15: header names bash as CI-host requirement" "$header" \
    "bash"

finish
