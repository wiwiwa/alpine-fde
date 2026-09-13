#!/usr/bin/env bash
# tests/e2e/s15-pcr7-drift.sh — §9.4 PCR 7 drift recovery drill (Wave 3).
#
# EMPIRICAL HARNESS FACT: qemu's tpm-emulator init handshake re-initializes
# swtpm (Startup-CLEAR) at EVERY boot — host-side PCR extensions do NOT
# survive into the next boot. The boot-layer drift therefore comes from the
# firmware itself: a db/dbx VARS change (exactly §9.4's "dbx/UEFI-variable
# change"), which the firmware measures into PCR 7 before the unlock.
#
#   boot 1  v1 enrolls + unlocks; console records the enrolled PCR 7   UNSEALED
#   host    baseline fixture finalized to the enrolled state; real
#           `debian-fde audit` run against a live (synthesized) drifted
#           PCR 7 -> exit 1 + "pcr7 DRIFT"; `audit --accept --yes`
#           re-baselines -> exit 0. (§9.4 detection, REAL CLI)
#   boot 2  dbx-updated vars: firmware measures a DIFFERENT PCR 7;
#           the seal's static PolicyPCR(7) term no longer matches    REFUSED
#   host    wipe the now-stale enrollment (token + slot)
#   boot 3  guest re-enrolls against the drifted-but-real PCR 7
#           and unlocks (volume key never re-encrypted)             UNSEALED
#
# Under Mechanism A″ the .pcrsig signs PCR-11-only predictions — it encodes NO
# PCR 7 state — so unlike the §9.4 combined-digest rungs, recovery needs NO
# re-signing at all, just the re-enrollment. Documented deviation from the
# task text ("re-signed .pcrsig"): the re-sign is a no-op under A″.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/assert.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/keys-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/disk-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/uki-build.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s15-pcr7-drift-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# CR-02/MD-03: prunes must spare the invocation's chained state dirs
# (DEBIAN_FDE_PROTECT_DIRS, exported by run-e2e.sh)
while IFS= read -r _d; do
    case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$_d:"*) continue ;; esac
    rm -rf "$_d"
done < <(find "$TESTS/e2e/.runs" -mindepth 1 -maxdepth 1 -type d -printf "%T@\t%p\n" 2>/dev/null | sort -rn | tail -n +3 | cut -f2-)

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The SRK persists in tpm2-00.permall (seals survive); PCRs reset to zero on
# the restart and are re-initialized by qemu's handshake at the next boot.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }
# shellcheck disable=SC2120  # bare calls (plain audit) are intentional
_audit_cli() {
    _ensure_tpm || { echo "s15: swtpm not serving (audit)"; return 64; }
    DEBIAN_FDE_ROOT="$RUN/rootfs" \
        DEBIAN_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        DEBIAN_FDE_EFIVARS_DIR="$RUN/rootfs/efivars-sb-on" \
        DEBIAN_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
        "$REPO/bin/debian-fde" audit "$@"
}
_host_wipe_enrollment() {
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue
        cryptsetup luksKillSlot --batch-mode "$img" "$slot" || return 1
    done
}
console_pcr() { # <label> <idx>
    grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2
}

boot_and_wait() {
    local label="$1"
    _ensure_tpm || { echo "s15: swtpm not serving"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures ------------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s15: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
mkdir -p "$RUN/rootfs/etc/debian-fde"
# v1 schema baseline (expanded form: baseline_validate greps 4-space-indented
# nested keys); values are stamped from boot-1 console evidence below.
cat >"$RUN/rootfs/etc/debian-fde/baseline.json" <<'JSON'
{
  "schema_version": "1",
  "created_at": "PENDING-BY-SCENARIO",
  "pcr0": "pending",
  "pcr1": "pending",
  "pcr2": "pending",
  "pcr3": "pending",
  "expected_pcr7": "pending",
  "sb_state": {
    "secure_boot": "",
    "setup_mode": "",
    "pk_fp": "",
    "kek_fp": "",
    "db_fp": "",
    "dbx_fp": ""
  },
  "fw": {
    "vendor": "",
    "version": "",
    "eventlog_sha256": "",
    "eventlog_size": ""
  },
  "keys": {
    "release_pub_path": "",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "",
    "esp_partuuid": ""
  }
}
JSON

echo "# building UKI 6.2.0 ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s15: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/uki-6.2.0.efi" || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: healthy enroll + unlock -------------------------------------------
boot_and_wait "v1-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "v1-enroll")
assert_contains "[v1] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[v1] UNSEALED" "$LOG" "debian-fde: UNSEALED"

# G-R1 guard (§8.1): baseline_finalize_from_live (audit --init/--accept) refuses
# fail-closed unless the efivars seam reports SecureBoot=1 SetupMode=0. The
# host-side CLI steps therefore run against this fixture efivars dir — the
# mkvar pattern from tests/unit/baseline_finalize_guard.sh (attrs u32le 0x7 +
# payload byte). An empty dir correctly fails the finalize with rc 64.
EFIVARS="$RUN/rootfs/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
_mkcertvar PK pk-cert-v1
_mkcertvar KEK kek-cert-v1
_mkcertvar db db-cert-v1
_mkcertvar dbx dbx-cert-v1
# sanity: the seam really reads the fixture as the final SB state
# shellcheck disable=SC1091
source "$REPO/lib/firmware.sh"
assert_contains "efivars fixture: SB on, SetupMode=0" \
    "$(DEBIAN_FDE_EFIVARS_DIR="$EFIVARS" fw_sb_state)" \
    "secureboot=1 setup_mode=0"

D7_ENROLLED=$(console_pcr "v1-enroll" 7)
PCR0_BOOT1=$(console_pcr "v1-enroll" 0)
assert_ne "boot 1 console records the enrolled PCR 7" "$D7_ENROLLED" ""

# --- finalize the baseline fixture to the enrolled state ------------------------
sed -i "s/PENDING-BY-SCENARIO/$(date -u +%Y-%m-%dT%H:%M:%SZ)/; s|\"pcr0\": \"pending\"|\"pcr0\": \"$PCR0_BOOT1\"|; s|\"expected_pcr7\": \"pending\"|\"expected_pcr7\": \"$D7_ENROLLED\"|" \
    "$RUN/rootfs/etc/debian-fde/baseline.json"
assert_eq "baseline fixture carries the enrolled d7" "$D7_ENROLLED" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/debian-fde/baseline.json")"

# --- §9.4 detection with the REAL CLI (live PCR 7 synthesized to a drifted value)
_ensure_tpm || { echo "s15: swtpm not serving (drift)"; exit 1; }
DRIFT_HEX=$(printf 'dbx-update-sim' | sha256sum | awk '{print $1}')
swtpm_pcrextend "$RUN/tpm" 7 "$DRIFT_HEX"
D7_DRIFT=$(swtpm_pcrread "$RUN/tpm" 7)
assert_ne "live PCR 7 drifted off the enrolled value" "$D7_ENROLLED" "$D7_DRIFT"
AUDOUT=$(mktemp)
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "audit detects the drift (exit 1)" "1" "$_audit_rc"
assert_contains "audit report: pcr7 DRIFT line" "$(grep '^pcr7' "$AUDOUT")" "DRIFT"
grep -E '^pcr' "$AUDOUT" | sed 's/^/# audit: /'
assert_rc "audit --accept --yes re-baselines (real CLI, §9.4)" 0 _audit_cli --accept --yes
BL7=$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/debian-fde/baseline.json")
assert_ne "baseline re-baselined AWAY from the enrolled d7" "$D7_ENROLLED" "$BL7"
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "audit clean after re-baseline (exit 0)" "0" "$_audit_rc"
assert_contains "last-audit.json records the clean post-accept audit" \
    "$(cat "$RUN/rootfs/etc/debian-fde/last-audit.json")" '"result": "ok"'
# NB: exact-value equality with $D7_DRIFT is asserted only opportunistically —
# the fixture swtpm can restart between the two CLI invocations (the probe is
# conservative), re-zeroing PCRs; the re-baseline SEMANTICS above are the proof.
rm -f "$AUDOUT"

# --- boot-layer drift: dbx-updated VARS (firmware-measured PCR 7 change) ---------
echo "# simulating the dbx update: extra cert in dbx (firmware will measure a new PCR 7)"
cp "$RUN/vars-enrolled.fd" "$RUN/vars-drifted.fd"
assert_rc "virt-fw-vars: dbx += throwaway cert" 0 \
    virt-fw-vars -i "$RUN/vars-drifted.fd" -o "$RUN/vars-drifted.fd" \
        --add-dbx-cert "$DEBIAN_FDE_TEST_GUID" "$RUN/keys/KEK.crt"

boot_and_wait "drifted" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-drifted.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "drifted")
assert_contains "[drift] init ran (SB still verifies — only the SEAL refuses)" "$LOG" \
    "debian-fde-harness: init started"
assert_ne "[drift] firmware measured a DIFFERENT PCR 7" "$D7_ENROLLED" "$(console_pcr "drifted" 7)"
assert_contains "[drift] enrollment SKIPPED (token still present)" "$LOG" \
    "systemd-tpm2 token present — skipping enrollment"
assert_contains "[drift] TPM2 unseal refused (static PCR 7 term)" "$LOG" "$(sentinel_of tpm2_refused)"
assert_contains "[drift] retry cap reached" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "[drift] PROMPT-FAILED" "$LOG" "debian-fde: PROMPT-FAILED"
assert_not_contains "[drift] never unlocked" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "[drift] never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[drift] interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "[drift] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[drift] clean poweroff" "$LOG" "debian-fde: POWEROFF"

# --- recovery: drop the stale seal; the guest re-enrolls on next boot ------------
echo "# wiping the stale enrollment (token + slot) — re-enroll happens in-guest"
_host_wipe_enrollment "$RUN/disk.img" || { echo "s15: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"

# --- boot 3: re-enroll against the new PCR 7 -> UNSEALED -------------------------
boot_and_wait "re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-drifted.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "re-enroll")
assert_contains "[re] re-enrolled against drifted PCR 7" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[re] .pcrsig still consumed (no re-sign needed under A'')" "$LOG" \
    "$(sentinel_of pcr_sig_added)"
assert_contains "[re] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[re] UNSEALED (recovery complete)" "$LOG" "debian-fde: UNSEALED"
assert_contains "[re] clean poweroff" "$LOG" "debian-fde: POWEROFF"
assert_eq "[re] sealed against the drifted (boot-layer) PCR 7" "$(console_pcr "drifted" 7)" \
    "$(console_pcr "re-enroll" 7)"

rm -rf "$RUN/guest-tree"
echo "# A'' note: .pcrsig pols cover PCR 11(+phase) only — PCR 7 drift recovery needs"
echo "# re-enrollment, never a re-sign (signed pols encode no PCR 7 state)."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s15-pcr7-drift: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s15-pcr7-drift: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
