#!/usr/bin/env bash
# tests/unit/doctor_checks.sh — `alpine-fde doctor` readiness contract:
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

T=$(mktemp -d /tmp/alpine-fde-doctor.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
mkdir -p "$FAKEBIN" "$EFIVARS"
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS

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
# answer the swtpm fixture). The list mirrors lib/cmd/doctor.sh's table — the
# Alpine hard set (§3.1/§13); systemd-cryptenroll, dracut and debootstrap do
# not exist on Alpine v3.24 (ADR-19/ADR-13) and must never appear in it.
DOCTOR_BINS="cryptsetup ukify bootctl sbsign openssl mkinitfs"
for b in $DOCTOR_BINS; do
    ln -sf /usr/bin/true "$FAKEBIN/$b"
done

# mirror_path DST EXCLUDE... — mirror $PATH into DST, skipping EXCLUDE
# binaries. Used to simulate hosts where a given tool is absent entirely.
mirror_path() {
    local dst=$1; shift
    mkdir -p "$dst"
    local oldIFS=$IFS p b x skip
    oldIFS=$IFS
    IFS=:
    for p in $PATH; do
        [ -d "$p" ] || continue
        for b in "$p"/*; do
            [ -e "$b" ] || continue
            b=${b##*/}
            skip=0
            for x in "$@"; do
                [ "$b" = "$x" ] && skip=1
            done
            [ "$skip" = 1 ] && continue
            [ -e "$dst/$b" ] || ln -s "$p/$b" "$dst/$b" 2>/dev/null || true
        done
    done
    IFS=$oldIFS
}
# fake apt-get: read-only subcommands OK; any install attempt leaves a marker
# (doctor must never install)
cat >"$FAKEBIN/apt-get" <<'EOF'
#!/bin/sh
for a in "$@"; do
    case $a in
        install) touch "${ALPINE_FDE_DOCTOR_MARKER:-/nonexistent}" ;;
    esac
done
exit 0
EOF
chmod +x "$FAKEBIN/apt-get"
export PATH="$FAKEBIN:$PATH"

export ALPINE_FDE_NO_INSTALL=1          # belt+braces: never touch apt even if logic changes
export ALPINE_FDE_DOCTOR_MARKER="$T/marker"

# run_doctor ARGS... — capture rc + combined output
run_doctor() {
    DOCTOR_OUT=$("$REPO/bin/alpine-fde" doctor "$@" 2>&1)
    DOCTOR_RC=$?
}

# --- 1. all good: swtpm up, SB on, binaries present ---------------------------
STATE=$T/swtpm
assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export ALPINE_FDE_TCTI=$SWTPM_TCTI
mkvar SecureBoot 1
mkvar SetupMode 0
run_doctor
assert_eq "doctor rc 0 when ready" "0" "$DOCTOR_RC"
assert_contains "verdict is READY" "$DOCTOR_OUT" "READY"
assert_contains "tpm reported ok" "$DOCTOR_OUT" "TPM 2.0 reachable"
assert_contains "sb reported ok" "$DOCTOR_OUT" "secureboot=1 setup_mode=0 pk=0"
assert_contains "mkinitfs is a hard binary on Alpine (ADR-13)" "$DOCTOR_OUT" "[ok]      mkinitfs"
assert_not_contains "no systemd-cryptenroll anywhere (ADR-19: absent on Alpine)" "$DOCTOR_OUT" "systemd-cryptenroll"
assert_not_contains "no dracut anywhere (ADR-13: rejected)" "$DOCTOR_OUT" "dracut"
assert_not_contains "no debootstrap anywhere (Alpine bootstraps via apk)" "$DOCTOR_OUT" "debootstrap"
if [[ -e "$ALPINE_FDE_DOCTOR_MARKER" ]]; then
    assert_eq "doctor never installs (no apt-get install)" "absent" "present"
else
    assert_eq "doctor never installs (no apt-get install)" "absent" "absent"
fi

# --- 2. missing hard-required binary → rc 1 -----------------------------------
rm "$FAKEBIN/mkinitfs"
run_doctor
assert_eq "doctor rc 1 when a hard binary is missing" "1" "$DOCTOR_RC"
assert_contains "missing binary reported" "$DOCTOR_OUT" "[missing] mkinitfs"
assert_contains "verdict NOT READY" "$DOCTOR_OUT" "NOT READY"
assert_contains "apk absent: manual hint is apt-get (ADR-15)" "$DOCTOR_OUT" \
    "manual: apt-get install -y --no-install-recommends mkinitfs"
ln -sf /usr/bin/true "$FAKEBIN/mkinitfs"

# --- 2b. host-installer tools (§13): warnings only, never gate ----------------
# §13: install preflight enforces sfdisk/lsblk/mkfs.* ; doctor only surfaces
# them — a missing host tool must print [warn], never [missing], never gate.
ln -sf /usr/bin/true "$FAKEBIN/sfdisk"
run_doctor
assert_contains "host-installer tool present reported ok" "$DOCTOR_OUT" "[ok]      sfdisk"
assert_eq "host-installer tools present: rc stays 0" "0" "$DOCTOR_RC"
rm "$FAKEBIN/sfdisk"
NOHOST_BIN=$T/bin-nohost
mirror_path "$NOHOST_BIN" apt-get sfdisk
DOCTOR_OUT=$(PATH="$NOHOST_BIN" "$REPO/bin/alpine-fde" doctor 2>&1)
DOCTOR_RC=$?
assert_contains "host-installer tool absent reported as warn (not [missing])" "$DOCTOR_OUT" "[warn]    sfdisk"
assert_not_contains "host-installer absence never hard-fails" "$DOCTOR_OUT" "[missing] sfdisk"
assert_contains "host-installer tools absent: verdict still prints READY" "$DOCTOR_OUT" "READY"
assert_eq "host-installer tools absent: rc stays 0" "0" "$DOCTOR_RC"

# --- 2c. apk repository probe (G-A9): read-only, warn-only --------------------
# §8.1 "apk/network reachability": mirrors the apt probe's H-01 semantics —
# apk absent or the index unreachable is a warning, never fatal, and doctor
# must never run `apk add` (marker file below catches any install attempt).
cat >"$FAKEBIN/apk" <<'EOF'
#!/bin/sh
for a in "$@"; do
    case $a in
        add) touch "${ALPINE_FDE_DOCTOR_MARKER:-/nonexistent}" ;;
    esac
done
exit 0
EOF
chmod +x "$FAKEBIN/apk"
run_doctor
assert_contains "apk index reachable reported (G-A9)" "$DOCTOR_OUT" "apk repository index reachable"
assert_eq "doctor never installs via apk add (marker)" "absent" \
    "$([ -e "$ALPINE_FDE_DOCTOR_MARKER" ] && echo present || echo absent)"

# G-A10: with apk the present manager, a missing binary's manual hint must be
# apk-flavored, not the apt-get line (ADR-15 dual backend)
rm "$FAKEBIN/mkinitfs"
run_doctor
assert_contains "apk present: manual hint is apk add (G-A10)" "$DOCTOR_OUT" "manual: apk add mkinitfs"
assert_not_contains "apk present: no apt-get manual hint (G-A10)" "$DOCTOR_OUT" "manual: apt-get"
ln -sf /usr/bin/true "$FAKEBIN/mkinitfs"

# index unreachable (PATH-stubbed apk fails `update`) → warning, not fatal
cat >"$FAKEBIN/apk" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$FAKEBIN/apk"
run_doctor
assert_contains "apk index unreachable warns (G-A9)" "$DOCTOR_OUT" "apk could not reach the repository index"
assert_eq "apk unreachable does not gate the verdict" "0" "$DOCTOR_RC"
assert_contains "apk unreachable: report not truncated — verdict prints" "$DOCTOR_OUT" "verdict:"
rm "$FAKEBIN/apk"

# apk absent entirely (Debian-era host) → warn + verdict intact
NOAPK_BIN=$T/bin-noapk
mirror_path "$NOAPK_BIN" apk
DOCTOR_OUT=$(PATH="$NOAPK_BIN" "$REPO/bin/alpine-fde" doctor 2>&1)
DOCTOR_RC=$?
assert_contains "apk absent warns (G-A9)" "$DOCTOR_OUT" "apk not found"
assert_eq "apk absent: rc stays 0" "0" "$DOCTOR_RC"
assert_contains "apk absent: verdict still prints" "$DOCTOR_OUT" "verdict:"
assert_eq "apk absent: doctor still never installs" "absent" \
    "$([ -e "$ALPINE_FDE_DOCTOR_MARKER" ] && echo present || echo absent)"

# --- 3. unreachable TPM → rc 1 --------------------------------------------------
export ALPINE_FDE_TCTI="device:/nonexistent-tpmrm0"
run_doctor
assert_eq "doctor rc 1 when TPM unreachable" "1" "$DOCTOR_RC"
assert_contains "tpm failure reported" "$DOCTOR_OUT" "no TPM 2.0 answered"
assert_contains "verdict NOT READY (tpm)" "$DOCTOR_OUT" "NOT READY"

# --- 4. SB off / unreadable efivars → warning only, rc stays 0 ------------------
export ALPINE_FDE_TCTI=$SWTPM_TCTI
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
DOCTOR_OUT=$(PATH="$NOAPT_BIN" "$REPO/bin/alpine-fde" doctor 2>&1)
DOCTOR_RC=$?
assert_eq "apt-less host: doctor completes with the verdict (H-01)" "0" "$DOCTOR_RC"
assert_contains "apt-less: apt warning present" "$DOCTOR_OUT" "apt-get not found"
assert_contains "apt-less: report NOT truncated — CI extras section prints" "$DOCTOR_OUT" "CI extras (informational, non-gating)"
assert_contains "apt-less: report NOT truncated — verdict prints" "$DOCTOR_OUT" "verdict:"
assert_contains "apt-less: verdict READY (apt is non-gating)" "$DOCTOR_OUT" "READY"
assert_eq "apt-less: doctor still never installs" "absent" \
    "$([ -e "$ALPINE_FDE_DOCTOR_MARKER" ] && echo present || echo absent)"

# --- 4c. OVMF code/vars report (G-A11): CI extras, non-gating ------------------
# §8.1 "OVMF/QEMU prereqs (CI)": presence read from the ALPINE_FDE_OVMF_DIR
# env seam (same ALPINE_FDE_* convention as ALPINE_FDE_EFIVARS_DIR); present
# AND absent are both non-gating.
export ALPINE_FDE_OVMF_DIR=$T/ovmf
mkdir -p "$ALPINE_FDE_OVMF_DIR"
run_doctor
assert_contains "OVMF absent warns (G-A11)" "$DOCTOR_OUT" "OVMF firmware not found"
assert_eq "OVMF absence does not gate" "0" "$DOCTOR_RC"
: >"$ALPINE_FDE_OVMF_DIR/OVMF_CODE.fd"
: >"$ALPINE_FDE_OVMF_DIR/OVMF_VARS.fd"
run_doctor
assert_contains "OVMF code+vars reported ok (G-A11)" "$DOCTOR_OUT" "OVMF code + vars present"
assert_eq "OVMF presence does not gate either" "0" "$DOCTOR_RC"
unset ALPINE_FDE_OVMF_DIR

# --- 4d. systemd-boot version vs the ADR-1 pin (G-A12) -------------------------
# ADR-1: Alpine ≥ 3.24 ships systemd-boot 260.2. Older → warning naming the
# pin (non-gating); bootctl missing is already covered by the hard check.
fake_bootctl_version() { # VERSION — PATH-stub bootctl printing "systemd VERSION"
    rm -f "$FAKEBIN/bootctl"        # sever the /usr/bin/true symlink first
    cat >"$FAKEBIN/bootctl" <<EOF
#!/bin/sh
if [ "\${1:-}" = "--version" ]; then
    printf 'systemd $1\n'
fi
exit 0
EOF
    chmod +x "$FAKEBIN/bootctl"
}
fake_bootctl_version 257.4
run_doctor
assert_contains "bootctl < 260.2 warns naming the ADR-1 pin (G-A12)" "$DOCTOR_OUT" "older than the ADR-1 pin"
assert_contains "old-bootctl warning names the pinned version 260.2" "$DOCTOR_OUT" "260.2"
assert_eq "bootctl older than pin does not gate" "0" "$DOCTOR_RC"
fake_bootctl_version 260.2
run_doctor
assert_contains "bootctl at pin reported ok (G-A12)" "$DOCTOR_OUT" "systemd-boot 260.2 (ADR-1 pin"
rm "$FAKEBIN/bootctl"
ln -sf /usr/bin/true "$FAKEBIN/bootctl"

# --- 4e. SHA-256 PCR bank (§13 "TPM 2.0 (SHA-256 PCRs)", G-A13) ----------------
# §13's baseline machine has SHA-256 PCRs; readiness must not rest on
# `getcap properties-fixed` alone or a SHA-1-only TPM reads READY. The probe
# goes through the repo's existing tpm seam (the same `tpm` wrapper
# tpm_available uses, lib/baseline.sh), so a PATH-stubbed tpm2 answering
# `getcap pcrs` stubs it deterministically (output mirrors real tpm2-tools 5.x:
# "selected-pcrs:" then one "- <bank>: [ ... ]" line per selected bank).
fake_tpm2_pcr_banks() { # BANKS... — PATH-stub tpm2 answering `getcap pcrs`
    rm -f "$FAKEBIN/tpm2"        # sever the /usr/bin/true-era symlink first
    cat >"$FAKEBIN/tpm2" <<EOF
#!/bin/sh
[ "\${1:-}" = getcap ] || exit 0
case \${2:-} in
    properties-fixed) exit 0 ;;
    pcrs)
        printf 'selected-pcrs:\n'
        for b in $*; do
            printf '  - %s: [ 0, 1, 2, 3 ]\n' "\$b"
        done
        ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$FAKEBIN/tpm2"
}

# (a) sha256 bank selected → [ok], rc unchanged (0), verdict stays READY
fake_tpm2_pcr_banks sha256 sha1
run_doctor
assert_contains "sha256 bank reported ok (G-A13)" "$DOCTOR_OUT" "SHA-256 PCR bank present"
assert_eq "sha256 bank present: rc unchanged" "0" "$DOCTOR_RC"
assert_contains "sha256 bank present: verdict still READY" "$DOCTOR_OUT" "verdict: READY"

# (c) rc 0 but unparsable/empty pcrs output → warn, never gate: "cannot
# determine" is not a confirmed absence, so it downgrades exactly like the
# SB probe (warn) instead of the unreachable-TPM convention ([fail])
fake_tpm2_pcr_banks
run_doctor
assert_contains "unparsable pcrs output warns (G-A13)" "$DOCTOR_OUT" "could not parse PCR bank selection"
assert_eq "unparsable pcrs output: rc stays 0" "0" "$DOCTOR_RC"
assert_contains "unparsable pcrs output: verdict still READY" "$DOCTOR_OUT" "verdict: READY"

# (b) only sha1 → doctor flags it and gates (the §13 machine is absent),
# following the dominant convention of this section: [fail] + NOT READY + rc 1,
# exactly like an unreachable TPM.
fake_tpm2_pcr_banks sha1
run_doctor
assert_contains "sha1-only TPM flagged (G-A13)" "$DOCTOR_OUT" "no SHA-256 PCR bank"
assert_contains "sha1-only TPM flags the banks it does have (G-A13)" "$DOCTOR_OUT" "sha1"
assert_contains "sha1-only: verdict NOT READY (G-A13)" "$DOCTOR_OUT" "NOT READY"
assert_not_contains "sha1-only TPM never reads READY (G-A13)" "$DOCTOR_OUT" "verdict: READY"
assert_eq "sha1-only TPM: rc 1 (gates like an unreachable TPM)" "1" "$DOCTOR_RC"

rm -f "$FAKEBIN/tpm2"        # restore the real tpm2 for any later sections

# --- 4f. §13 manual-prereq advisories (G-A14): informational, non-gating ------
# §13 lists two manual prerequisites doctor cannot probe (read-only, §8.1 "no
# changes"): the firmware admin password and offline custody / off-machine
# backup of the release signing key. Doctor must print both as advisory rows —
# they must never change the exit code or any check's verdict.
run_doctor
assert_contains "firmware-admin-password advisory present (G-A14)" "$DOCTOR_OUT" \
    "manual prereq (§13): firmware admin password set"
assert_contains "offline key custody advisory present (G-A14)" "$DOCTOR_OUT" \
    "manual prereq (§13): offline custody / off-machine backup plan"
assert_eq "advisories never gate: rc stays 0" "0" "$DOCTOR_RC"
assert_contains "advisories leave the verdict READY (G-A14)" "$DOCTOR_OUT" "verdict: READY"
assert_not_contains "advisories are info rows, never warnings (G-A14)" "$DOCTOR_OUT" "[warn]    manual prereq"
assert_not_contains "advisories never fail (G-A14)" "$DOCTOR_OUT" "[fail]    manual prereq"
# non-gating must hold in a NOT READY run too — same exact rc as before the
# advisories existed (§13: doctor is read-only; advisories change nothing)
rm "$FAKEBIN/mkinitfs"
run_doctor
assert_eq "advisories present in a failing run: rc unchanged (1)" "1" "$DOCTOR_RC"
assert_contains "advisory rows still print in a failing run (G-A14)" "$DOCTOR_OUT" \
    "manual prereq (§13): firmware admin password set"
ln -sf /usr/bin/true "$FAKEBIN/mkinitfs"

# --- 5. doctor refuses extra args (usage rc 2) -----------------------------------
run_doctor bogus-arg
assert_eq "doctor rejects stray args with usage rc" "2" "$DOCTOR_RC"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
