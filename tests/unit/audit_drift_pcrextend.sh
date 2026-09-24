#!/usr/bin/env bash
# tests/unit/audit_drift_pcrextend.sh — `debian-fde audit` against a live swtpm:
#   * --init finalizes a pending baseline (writes pcr0..3+7 + event log v1)
#   * swtpm_pcrextend drift -> rc 1 (drift), §9.4 next steps printed
#   * --accept --yes re-baselines (baseline.json + last-audit.json updated)
#   * exit contract: 0 match / 1 drift / 64 error (TPM unreachable)
#   * --init refuses an already-final baseline
#   * event log drift detected by sha256/size (v1 scope, C-G10)
#   * finalization requires Secure Boot on + SetupMode=0 (G-R1 guard): the
#     efivars fixture must present the final SB state for --init/--accept

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

T=$(mktemp -d /tmp/debian-fde-audit.XXXXXX)
STATE=$T/swtpm
EVENTLOG=$T/eventlog
EFIVARS=$T/efivars
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_EVENTLOG=$EVENTLOG
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
export DEBIAN_FDE_NO_INSTALL=1

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$(sp_etc_dir)" "$EFIVARS"
head -c 1024 /dev/urandom >"$EVENTLOG"

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkcertvar() { # NAME CONTENT — payload after the 4-byte attrs header
    printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_final() { # the final SB state the G-R1 guard requires, + key material for fingerprints
    mkvar SecureBoot 1
    mkvar SetupMode 0
    mkcertvar PK pk-cert-v1
    mkcertvar KEK kek-cert-v1
    mkcertvar db db-cert-v1
    mkcertvar dbx dbx-cert-v1
}

run_audit() { # args...
    AUD_OUT=$("$REPO/bin/debian-fde" audit "$@" 2>&1)
    AUD_RC=$?
}

BL=$(sp_baseline_file)
ZERO64=$(printf '0%.0s' {1..64})

# --- 1. no baseline -> fail-closed -------------------------------------------------
run_audit
assert_eq "audit without baseline -> 64" "64" "$AUD_RC"

# --- 2. TPM unreachable -> 64 (error, not drift) --------------------------------------
BL_PCR0="$ZERO64" BL_PCR7="$ZERO64" baseline_write "$BL"
export DEBIAN_FDE_TCTI='device:/nonexistent-tpmrm0'
run_audit
assert_eq "TPM unreachable -> 64" "64" "$AUD_RC"
assert_contains "error message mentions TPM" "$AUD_OUT" "no TPM reachable"

# --- 3. --init finalizes the pending baseline --------------------------------------------
# (empty DEBIAN_FDE_TCTI = tctildr default discovery, which never probes swtpm —
# the fixture TCTI must be set explicitly, C-G1)
assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
sb_final
BL_PCR0='pending' BL_PCR7='pending' baseline_write "$BL"
run_audit --init
assert_eq "audit --init rc 0" "0" "$AUD_RC"
assert_rc "baseline now final" 0 baseline_is_final "$BL"
assert_eq "expected_pcr7 == live swtpm PCR7" "$(swtpm_pcrread "$STATE" 7)" "$(baseline_get "$BL" expected_pcr7)"
assert_eq "pcr2 captured" "$(swtpm_pcrread "$STATE" 2)" "$(baseline_get "$BL" pcr2)"
assert_file_exists "last-audit.json written" "$(sp_last_audit_file)"
assert_eq "last-audit result ok" "ok" "$(baseline_get "$(sp_last_audit_file)" result)"
EL_SHA=$(sha256sum <"$EVENTLOG" | cut -d' ' -f1)
assert_eq "eventlog sha256 recorded" "$EL_SHA" "$(baseline_get_in "$BL" fw eventlog_sha256)"

# --- 4. --init refuses a final baseline -----------------------------------------------------
run_audit --init
assert_eq "--init on final baseline -> 64" "64" "$AUD_RC"
assert_contains "points to --accept" "$AUD_OUT" "audit --accept"

# --- 5. clean audit -> rc 0 --------------------------------------------------------------------
run_audit
assert_eq "clean audit rc 0" "0" "$AUD_RC"
assert_contains "match verdict" "$AUD_OUT" "all checked values match"
assert_eq "last-audit result ok" "ok" "$(baseline_get "$(sp_last_audit_file)" result)"

# --- 6. Secure Boot state drift (G-R6, §8.1/§9.5): SB on -> off -------------------
mkvar SecureBoot 0
run_audit
assert_eq "secureboot 1->0 -> rc 1 (drift)" "1" "$AUD_RC"
assert_contains "secureboot DRIFT line shows both values" "$AUD_OUT" "secureboot live=0 baseline=1   DRIFT"
mkvar SecureBoot 1
run_audit
assert_eq "secureboot restored -> clean again" "0" "$AUD_RC"

# --- 7. SetupMode drift (G-R6): 0 -> 1 ----------------------------------------------
mkvar SetupMode 1
run_audit
assert_eq "setup_mode 0->1 -> rc 1 (drift)" "1" "$AUD_RC"
assert_contains "setupmode DRIFT line" "$AUD_OUT" "setupmode live=1 baseline=0   DRIFT"
mkvar SetupMode 0
run_audit
assert_eq "setup_mode restored -> clean again" "0" "$AUD_RC"

# --- 8. dbx fingerprint drift (G-R6, §9.4 dbx-update detection) ----------------------
mkcertvar dbx dbx-cert-v2
run_audit
assert_eq "dbx fingerprint change -> rc 1 (drift)" "1" "$AUD_RC"
assert_contains "dbx fp DRIFT line" "$AUD_OUT" "dbx"
assert_contains "dbx DRIFT verdict" "$AUD_OUT" "DRIFT"
mkcertvar dbx dbx-cert-v1
run_audit
assert_eq "dbx restored -> clean again" "0" "$AUD_RC"

# --- 9. pcrextend drift on PCR 2 -> rc 1 + next steps ---------------------------------------------
EXT=$(printf 'ab%.0s' {1..32})
assert_rc "fixture pcrextend PCR2" 0 swtpm_pcrextend "$STATE" 2 "$EXT"
run_audit
assert_eq "drift -> rc 1" "1" "$AUD_RC"
assert_contains "pcr2 line shows DRIFT" "$AUD_OUT" "pcr2"
assert_contains "drift output prints §9.4 next steps (audit --accept)" "$AUD_OUT" "audit --accept"
assert_contains "G-XC5: §9.4 A″ next steps point at enroll-tpm (re-enroll)" "$AUD_OUT" \
    "debian-fde enroll-tpm"
assert_not_contains "G-XC5: NO re-sign wording in the §9.4 A″ next steps" "$AUD_OUT" \
    "re-sign"
assert_contains "L-1: next steps use the A″ single-enrollment wording" "$AUD_OUT" \
    "ONE cryptenroll covers all retained UKIs"
assert_not_contains "L-1: no Mechanism-A multi-enrollment wording" "$AUD_OUT" \
    "each kernel (fresh slots + tokens)"
assert_eq "last-audit result drift" "drift" "$(baseline_get "$(sp_last_audit_file)" result)"

# --- 10. --accept --yes re-baselines ------------------------------------------------------------------
run_audit --accept --yes
assert_eq "audit --accept rc 0" "0" "$AUD_RC"
assert_eq "baseline pcr2 re-baselined" "$(swtpm_pcrread "$STATE" 2)" "$(baseline_get "$BL" pcr2)"
assert_eq "last-audit accepted yes" "yes" "$(baseline_get "$(sp_last_audit_file)" accepted)"
assert_rc "audit clean after accept" 0 "$REPO/bin/debian-fde" audit

# --- 11. event log drift (sha256 change) ------------------------------------------------------------------
printf X >>"$EVENTLOG"
run_audit
assert_eq "eventlog drift -> rc 1" "1" "$AUD_RC"
assert_contains "eventlog DRIFT line" "$AUD_OUT" "eventlog sha256"
run_audit --accept --yes
assert_eq "eventlog re-baselined" "$(sha256sum <"$EVENTLOG" | cut -d' ' -f1)" "$(baseline_get_in "$BL" fw eventlog_sha256)"
assert_eq "eventlog size re-baselined" "$(wc -c <"$EVENTLOG" | tr -d ' ')" "$(baseline_get_in "$BL" fw eventlog_size)"

# --- 12. event log vanishes -> drift (baseline has a record) -------------------------------------------------
mv "$EVENTLOG" "$EVENTLOG.bak"
run_audit
assert_eq "missing eventlog -> drift" "1" "$AUD_RC"
assert_contains "eventlog absent reported" "$AUD_OUT" "eventlog absent"
mv "$EVENTLOG.bak" "$EVENTLOG"
run_audit --accept --yes
assert_rc "audit clean again" 0 true
run_audit
assert_eq "final state clean" "0" "$AUD_RC"

# --- 12b. L-2: empty baseline fields -> "not recorded", never a dishonest "match";
# an eventlog that APPEARS after finalize-without-log must warn loudly (tripwire
# otherwise never armed on that machine). Pending baseline, live material present.
BL_PCR0='pending' BL_PCR7='pending' baseline_write "$BL"
run_audit
assert_eq "pending baseline: audit stays rc 0 (unrecorded fields warn, not drift)" "0" "$AUD_RC"
assert_contains "L-2: secureboot unrecorded -> not recorded (finalize with --init)" \
    "$AUD_OUT" "not recorded (finalize with --init)"
assert_contains "L-2: key fingerprints unrecorded -> not recorded per var" \
    "$AUD_OUT" "PK"
assert_not_contains "L-2: unrecorded fields never print a 'match' verdict" \
    "$AUD_OUT" "   match"
assert_contains "L-2: live eventlog + empty baseline record -> loud tripwire warn" \
    "$AUD_OUT" "tripwire NOT armed"
run_audit --accept --yes
assert_eq "re-finalized for the sections below" "0" "$AUD_RC"

# --- 13. --accept without --yes: confirmation refused (G-R7, audit §8.1) -------------
BL_SHA_BEFORE=$(md5sum "$BL" | cut -d' ' -f1)
AUD_OUT=$("$REPO/bin/debian-fde" audit --accept </dev/null 2>&1)
AUD_RC=$?
assert_eq "unconfirmed --accept -> 64" "64" "$AUD_RC"
assert_contains "refusal says not confirmed" "$AUD_OUT" "not confirmed"
assert_eq "unconfirmed --accept leaves baseline untouched" "$BL_SHA_BEFORE" "$(md5sum "$BL" | cut -d' ' -f1)"

# --- 13b. --accept with piped ACCEPT: confirmation accepted via non-tty stdin ------
AUD_OUT=$(printf 'ACCEPT\n' | "$REPO/bin/debian-fde" audit --accept 2>&1)
AUD_RC=$?
assert_eq "piped ACCEPT confirmation -> rc 0" "0" "$AUD_RC"
assert_contains "piped ACCEPT updates baseline" "$AUD_OUT" "accepted"

# --- 14. bad usage -> rc 2 ------------------------------------------------------------------------------------
run_audit --bogus
assert_eq "unknown flag -> usage rc 2" "2" "$AUD_RC"

# --- 15. §8.3 sbverify over the ESP boot binaries (G-R4) ----------------------------
FAKEBIN=$T/bin
ESP=$T/esp
export DEBIAN_FDE_ESP=$ESP
export DEBIAN_FDE_KEYDIR=$T/keys
export DEBIAN_FDE_SBV_LOG=$T/sbverify.log DEBIAN_FDE_SBV_RC=$T/sbverify.rc
mkdir -p "$FAKEBIN" "$ESP/EFI/systemd" "$ESP/EFI/BOOT" "$T/keys"
printf 'CERT' >"$T/keys/release.crt"
: >"$ESP/EFI/systemd/systemd-bootx64.efi"
: >"$ESP/EFI/BOOT/BOOTX64.EFI"
cat >"$FAKEBIN/sbverify" <<'EOF'
#!/bin/sh
echo "CALL: $*" >>"$DEBIAN_FDE_SBV_LOG"
exit "$(cat "$DEBIAN_FDE_SBV_RC" 2>/dev/null || echo 0)"
EOF
chmod +x "$FAKEBIN/sbverify"
export PATH="$FAKEBIN:$PATH"

: >"$DEBIAN_FDE_SBV_LOG"
run_audit
assert_eq "sbverify pass -> audit stays clean (rc 0)" "0" "$AUD_RC"
assert_contains "sbverify pass line for the boot manager" "$AUD_OUT" "systemd-bootx64.efi"
assert_contains "sbverify pass line for the fallback loader" "$AUD_OUT" "BOOTX64.EFI"
SBV_CALLS=$(sed -n 's/^CALL: //p' "$DEBIAN_FDE_SBV_LOG")
assert_contains "sbverify invoked on the boot manager" "$SBV_CALLS" "$ESP/EFI/systemd/systemd-bootx64.efi"
assert_contains "sbverify invoked on the fallback loader" "$SBV_CALLS" "$ESP/EFI/BOOT/BOOTX64.EFI"

echo 1 >"$DEBIAN_FDE_SBV_RC"
run_audit
assert_eq "sbverify FAIL on a present binary -> drift (rc 1)" "1" "$AUD_RC"
assert_contains "sbverify FAIL line reported" "$AUD_OUT" "FAIL"
echo 0 >"$DEBIAN_FDE_SBV_RC"

# --- 16. §9.5 firmware identity (vendor/version) is INFORMATIONAL ---------------
# The baseline records fw.vendor/fw.version (baseline_finalize_from_live), but
# the ORCHESTRATOR DECISION for §9.5 is: audit reports a CHANGED vendor/version
# as an information line — firmware updates legitimately change these (audit is
# a detective control; PCR 0 drift is the security signal). A changed identity
# string must NOT flip the verdict to drift.
BL=$(sp_baseline_file)
baseline_set_field "$BL" '    ' fw vendor "BaselineCorp"
baseline_set_field "$BL" '    ' fw version "9.9"
DMI=$T/dmi
mkdir -p "$DMI"
printf 'Acme Corp' >"$DMI/sys_vendor"
printf '1.2.3' >"$DMI/bios_version"
export DEBIAN_FDE_DMI_DIR=$DMI
run_audit
assert_eq "changed firmware identity stays rc 0 (informational, not drift)" "0" "$AUD_RC"
assert_contains "changed fw vendor reported as an info line" "$AUD_OUT" \
    "fw vendor  live=Acme Corp baseline=BaselineCorp   info"
assert_contains "changed fw version reported as an info line" "$AUD_OUT" \
    "fw version live=1.2.3 baseline=9.9   info"
assert_not_contains "fw identity change is NEVER a DRIFT line" "$AUD_OUT" \
    "fw vendor  live=Acme Corp baseline=BaselineCorp   DRIFT"
assert_contains "verdict unchanged by the informational identity change" "$AUD_OUT" \
    "all checked values match"
assert_eq "last-audit result stays ok" "ok" "$(baseline_get "$(sp_last_audit_file)" result)"
# unchanged identity (live == baseline) reports match
printf 'BaselineCorp' >"$DMI/sys_vendor"
printf '9.9' >"$DMI/bios_version"
run_audit
assert_eq "unchanged firmware identity -> clean audit" "0" "$AUD_RC"
assert_contains "unchanged fw vendor reports match" "$AUD_OUT" \
    "fw vendor  live=BaselineCorp baseline=BaselineCorp   match"

# --- 17. last-audit.json is written ATOMICALLY (staged temp + rename, M-3) ------
LA=$(sp_last_audit_file)
LADIR=${LA%/*}
run_audit # a good write first
assert_eq "last-audit.json mode 600 (pinned before the rename)" "600" "$(stat -c %a "$LA")"
assert_eq "no staged temp left behind after a good write" "" \
    "$(find "$LADIR" -name '.last-audit.*' -print -quit)"
# torn-write: with the staged-temp pattern a READ-ONLY state directory makes the
# write FAIL LOUDLY and the previous last-audit.json survives UNTOUCHED (the
# direct `cat > file` it replaces would silently truncate the existing doc)
cp "$LA" "$T/last-audit.sentinel"
chmod 555 "$LADIR"
run_audit
assert_contains "unusable state dir: write fails LOUDLY" "$AUD_OUT" "cannot create temp file"
assert_eq "previous last-audit.json survives the failed write" \
    "$(md5sum <"$T/last-audit.sentinel")" "$(md5sum <"$LA")"
chmod 700 "$LADIR"
assert_eq "no staged temp left behind after the failed write" "" \
    "$(find "$LADIR" -name '.last-audit.*' -print -quit)"
run_audit
assert_eq "state dir writable again -> audit clean" "0" "$AUD_RC"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
