#!/usr/bin/env bash
# tests/unit/doctor_checks.sh — `debian-fde doctor` readiness contract:
# rc 0 when hard-required binaries + TPM are OK; rc 1 on missing binaries or
# unreachable TPM; Secure Boot / apt problems are warnings, never fatal;
# doctor performs NO state changes (never invokes apt-get install).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"

T=$(mktemp -d /tmp/debian-fde-doctor.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
mkdir -p "$FAKEBIN" "$EFIVARS"
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT

# efivar fixture helper: attrs u32le 0x7 + payload bytes
mkvar() { # NAME PAYLOAD-BYTE — attrs u32le 0x7 + payload byte
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}

# fake PATH: satisfy every hard-required binary EXCEPT tpm2 (real tpm2 must
# answer the swtpm fixture). The list mirrors lib/cmd/doctor.sh's table.
DOCTOR_BINS="cryptsetup systemd-cryptenroll ukify bootctl sbsign openssl dracut debootstrap"
for b in $DOCTOR_BINS; do
    ln -sf /usr/bin/true "$FAKEBIN/$b"
done
# fake apt-get: read-only subcommands OK; any install attempt leaves a marker
# (doctor must never install)
cat >"$FAKEBIN/apt-get" <<'EOF'
#!/bin/sh
for a in "$@"; do
    case $a in
        install) touch "${DEBIAN_FDE_DOCTOR_MARKER:-/nonexistent}" ;;
    esac
done
exit 0
EOF
chmod +x "$FAKEBIN/apt-get"
export PATH="$FAKEBIN:$PATH"

export DEBIAN_FDE_NO_INSTALL=1          # belt+braces: never touch apt even if logic changes
export DEBIAN_FDE_DOCTOR_MARKER="$T/marker"

# run_doctor ARGS... — capture rc + combined output
run_doctor() {
    DOCTOR_OUT=$("$REPO/bin/debian-fde" doctor "$@" 2>&1)
    DOCTOR_RC=$?
}

# --- 1. all good: swtpm up, SB on, binaries present ---------------------------
STATE=$T/swtpm
assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
mkvar SecureBoot 1
mkvar SetupMode 0
run_doctor
assert_eq "doctor rc 0 when ready" "0" "$DOCTOR_RC"
assert_contains "verdict is READY" "$DOCTOR_OUT" "READY"
assert_contains "tpm reported ok" "$DOCTOR_OUT" "TPM 2.0 reachable"
assert_contains "sb reported ok" "$DOCTOR_OUT" "secureboot=1 setup_mode=0 pk=0"
if [[ -e "$DEBIAN_FDE_DOCTOR_MARKER" ]]; then
    assert_eq "doctor never installs (no apt-get install)" "absent" "present"
else
    assert_eq "doctor never installs (no apt-get install)" "absent" "absent"
fi

# --- 2. missing hard-required binary → rc 1 -----------------------------------
rm "$FAKEBIN/debootstrap"
run_doctor
assert_eq "doctor rc 1 when a hard binary is missing" "1" "$DOCTOR_RC"
assert_contains "missing binary reported" "$DOCTOR_OUT" "[missing] debootstrap"
assert_contains "verdict NOT READY" "$DOCTOR_OUT" "NOT READY"
ln -sf /usr/bin/true "$FAKEBIN/debootstrap"

# --- 3. unreachable TPM → rc 1 --------------------------------------------------
export DEBIAN_FDE_TCTI="device:/nonexistent-tpmrm0"
run_doctor
assert_eq "doctor rc 1 when TPM unreachable" "1" "$DOCTOR_RC"
assert_contains "tpm failure reported" "$DOCTOR_OUT" "no TPM 2.0 answered"
assert_contains "verdict NOT READY (tpm)" "$DOCTOR_OUT" "NOT READY"

# --- 4. SB off / unreadable efivars → warning only, rc stays 0 ------------------
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
rm -f "$EFIVARS"/SecureBoot-*
mkvar SecureBoot 0
run_doctor
assert_eq "SB off is a warning, not fatal" "0" "$DOCTOR_RC"
assert_contains "sb warning present" "$DOCTOR_OUT" "Secure Boot not confirmed on"
assert_contains "verdict READY despite SB off" "$DOCTOR_OUT" "READY"

# SetupMode=1 warns (pre-enrollment state)
rm -f "$EFIVARS"/SetupMode-*
mkvar SetupMode 1
mkvar SecureBoot 1
run_doctor
assert_eq "SetupMode=1 warning does not gate" "0" "$DOCTOR_RC"
assert_contains "setup-mode hint present" "$DOCTOR_OUT" "SetupMode=1"

# --- 4b. apt-less host (CI/Arch per §3.1): the report is NOT truncated and the
# verdict still prints. H-01: an unguarded doctor_apt_report (rc 1 when
# apt-get is absent) killed the whole doctor run mid-report under errexit —
# no CI-extras section, no verdict. Apt problems are warnings, never fatal.
NOAPT_BIN=$T/bin-noapt
mkdir -p "$NOAPT_BIN"
_NOAPT_OLDIFS=$IFS
IFS=:
for _p in $PATH; do
    [ -d "$_p" ] || continue
    for _b in "$_p"/*; do
        [ -e "$_b" ] || continue
        _b=${_b##*/}
        [ "$_b" = "apt-get" ] && continue
        [ -e "$NOAPT_BIN/$_b" ] || ln -s "$_p/$_b" "$NOAPT_BIN/$_b" 2>/dev/null || true
    done
done
IFS=$_NOAPT_OLDIFS
if [ -e "$NOAPT_BIN/apt-get" ]; then
    assert_eq "apt-less fixture: no apt-get visible" "absent" "present"
else
    assert_eq "apt-less fixture: no apt-get visible" "absent" "absent"
fi
DOCTOR_OUT=$(PATH="$NOAPT_BIN" "$REPO/bin/debian-fde" doctor 2>&1)
DOCTOR_RC=$?
assert_eq "apt-less host: doctor completes with the verdict (H-01)" "0" "$DOCTOR_RC"
assert_contains "apt-less: apt warning present" "$DOCTOR_OUT" "apt-get not found"
assert_contains "apt-less: report NOT truncated — CI extras section prints" "$DOCTOR_OUT" "CI extras (informational, non-gating)"
assert_contains "apt-less: report NOT truncated — verdict prints" "$DOCTOR_OUT" "verdict:"
assert_contains "apt-less: verdict READY (apt is non-gating)" "$DOCTOR_OUT" "READY"
assert_eq "apt-less: doctor still never installs" "absent" \
    "$([ -e "$DEBIAN_FDE_DOCTOR_MARKER" ] && echo present || echo absent)"

# --- 5. doctor refuses extra args (usage rc 2) -----------------------------------
run_doctor bogus-arg
assert_eq "doctor rejects stray args with usage rc" "2" "$DOCTOR_RC"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
