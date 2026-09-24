#!/usr/bin/env bash
# tests/e2e/s15-pcr7-drift.sh — §9.4 PCR 7 drift recovery drill (Wave 3),
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness
# DEFAULT unlock).
#
# EMPIRICAL HARNESS FACT: qemu's tpm-emulator init handshake re-initializes
# swtpm (Startup-CLEAR) at EVERY boot — host-side PCR extensions do NOT
# survive into the next boot. The boot-layer drift therefore comes from the
# firmware itself: a db/dbx VARS change (exactly §9.4's "dbx/UEFI-variable
# change"), which the firmware measures into PCR 7 before the unlock.
#
#   boot 1  baseline (token-less disk): the hook's bounded recovery loop is
#           the only way in; the slot-0 passphrase is fed through the hook's
#           OWN prompt -> UNSEALED; console records the enrolled PCR 7.
#   host    the REAL production CLI enrolls the finalized {7,11} token
#           (combined .pcrsig entry over the enrolled d7 + the build's
#           enter-initrd d11); real `alpine-fde audit` run against a live
#           (synthesized) drifted PCR 7 -> exit 1 + "pcr7 DRIFT";
#           `audit --accept --yes` re-baselines -> exit 0. (§9.4 detection,
#           REAL CLI)
#   boot 2  dbx-updated vars: firmware measures a DIFFERENT PCR 7; the
#           hook's PolicyPCR({7,11}) session digest no longer matches the
#           sealed policy -> refusal (unseal_seal_refused) -> the hook's
#           BOUNDED recovery loop (3 fed WRONG answers) -> 3-strike
#           fail-closed `poweroff -f`. NEVER an emergency shell.
#   host    wipe the now-stale enrollment (token + slot) — the §9.4
#           operator step; re-stamp the baseline to the drifted d7 and
#           re-enroll: the fresh seal composes over the UNCHANGED enter-
#           initrd d11 and the DRIFTED d7 (no volume-key re-encryption).
#   boot 3  zero-input token unlock against the re-sealed {7,11} token
#           under the drifted-but-real PCR 7            UNSEALED
#
# Under the finalized Mechanism B contract the combined .pcrsig entry encodes
# the PCR 7 state (policy_digest(d7, d11)), so recovery needs a RE-SEAL over
# the drifted d7 — but no re-signing key ceremony beyond the release key the
# CLI already holds, and never a re-encryption of the volume.
#
# NB (G-T13): NO assert_pcr11_prediction on boot 2 — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading; the PCR 11 unchanged-equality vs the enrolled boot's
# console is the equivalent tamper-scoping evidence (the drift is PCR 7
# only). Boot 1 and boot 3 UNSEAL, so the postphase reading appears there
# and the signed prediction IS asserted.

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
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13, §12)
# shellcheck disable=SC1091
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck disable=SC1091
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

RUN="$TESTS/e2e/.runs/s15-pcr7-drift-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# CR-02/MD-03: prunes must spare the invocation's chained state dirs
# (ALPINE_FDE_PROTECT_DIRS, exported by run-e2e.sh)
while IFS= read -r _d; do
    case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$_d:"*) continue ;; esac
    rm -rf "$_d"
done < <(find "$TESTS/e2e/.runs" -mindepth 1 -maxdepth 1 -type d -printf "%T@\t%p\n" 2>/dev/null | sort -rn | tail -n +3 | cut -f2-)

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The SRK persists in tpm2-00.permall (seals survive); PCRs reset to zero on
# the restart and are re-initialized by qemu's handshake at the next boot.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }
# _fresh_pcrs — force ZEROED PCRs for the NEXT qemu boot (repro-proven
# 2026-09-24, registry s02/s15/s17): after a boot exits CLEANLY the proxy
# stores the volatile state and the fixture's restart RESTORES it into RAM
# (the host-side window feature); a boot served by that restored instance
# then EXTENDS OVER the previous boot's final values — PCR 0/7/11 all shift
# ("register instability") and every seal made under the stock measurements
# refuses (console evidence: PCR 0 8bbb4647… vs 0504784b… boot pairs).
# swtpm_stop + swtpm_start (the second start finds no volatile file) yields
# the documented per-boot zeroed-PCR semantics. Host-side windows that NEED
# the booted values (enroll/audit/re-seal preconditions) read them BEFORE
# this guard runs.
_fresh_pcrs() {
    local dir="$RUN/tpm" d0 k
    swtpm_stop "$dir" 2>/dev/null || true
    # a HALF-STARTED instance (readiness probe failed) still holds the state
    # dir's .lock and would make the restart below fail — kill it scoped to
    # this run dir and clear every socket/lock file it left behind
    pkill -9 -f "swtpm socket .*$dir/" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/.lock" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl" "$dir/swtpm.sock"
    swtpm_start "$dir" || { echo "s15: swtpm restart failed"; return 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    if [[ ! "$d0" =~ ^0{64}$ ]]; then
        echo "s15: TPM not zeroed before a boot (pcr0=$d0) — refusing a cumulative register"; return 1
    fi
    # settle: a guest TPM command arriving mid-setup times out and the
    # firmware DROPS the measurement (the degraded-boot register — s18's
    # _reanchor_tpm evidence); warm the whole path through the proxy first.
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    return 0
}
# shellcheck disable=SC2120  # bare calls (plain audit) are intentional
_audit_cli() {
    _ensure_tpm || { echo "s15: swtpm not serving (audit)"; return 64; }
    ALPINE_FDE_ROOT="$RUN/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$RUN/rootfs/efivars-sb-on" \
        ALPINE_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
        "$REPO/bin/alpine-fde" audit "$@"
}
_host_wipe_enrollment() {
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue
        # --key-file: the wipe needs to authenticate against the remaining
        # keyslot; an unattended stdin blocks FOREVER otherwise (repro 2026-09-24:
        # luksKillSlot sat 36 min waiting to read a passphrase)
        timeout 120 cryptsetup luksKillSlot --batch-mode --key-file "$RUN/kf-slot0" \
            "$img" "$slot" </dev/null || return 1
    done
}
console_pcr() { # <label> <idx>
    grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2
}

boot_and_wait() {
    local label="$1"
    _ensure_tpm || { echo "s15: swtpm not serving"; return 1; }
    _fresh_pcrs || { echo "s15: cannot zero the TPM PCRs for the boot"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures ------------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s15: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
mkdir -p "$RUN/rootfs/etc/alpine-fde"
# v1 schema baseline (expanded form: baseline_validate greps 4-space-indented
# nested keys); values are stamped from boot-1 console evidence below.
cat >"$RUN/rootfs/etc/alpine-fde/baseline.json" <<'JSON'
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

# --- boot 1: baseline (token-less disk) -> hook recovery loop -------------------
# The token-less disk puts the hook's BOUNDED recovery loop in control; the
# feed is prompt-synchronized (the hook has NO read timeout). This is the
# §12 first-boot passphrase way in; the finalized {7,11} enrollment then
# happens HOST-side via the REAL production CLI.
_ensure_tpm || { echo "s15: swtpm not serving (boot 1)"; exit 1; }
echo "# boot v1-baseline (token-less disk -> hook recovery loop, TCG, up to $QEMU_TIMEOUT s) ..."
for _attempt in 1 2; do
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-v1-baseline.log"
    grep -q "$(sentinel_of harness_unsealed)" "$RUN/console-v1-baseline.log" && break
    echo "# baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_reset "$RUN/tpm" && swtpm_start "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
done
LOG=$(log_of "v1-baseline")
assert_contains "[v1] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[v1] hook recovery loop opened (no token on the fresh volume)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[v1] fed slot-0 passphrase unsealed via the recovery path" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[v1] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_pcr11_prediction "S-15 v1-baseline"

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
    "$(ALPINE_FDE_EFIVARS_DIR="$EFIVARS" fw_sb_state)" \
    "secureboot=1 setup_mode=0"

D7_ENROLLED=$(console_pcr "v1-baseline" 7)
PCR0_BOOT1=$(console_pcr "v1-baseline" 0)
assert_ne "boot 1 console records the enrolled PCR 7" "$D7_ENROLLED" ""

# --- finalize the baseline fixture to the enrolled state ------------------------
sed -i "s/PENDING-BY-SCENARIO/$(date -u +%Y-%m-%dT%H:%M:%SZ)/; s|\"pcr0\": \"pending\"|\"pcr0\": \"$PCR0_BOOT1\"|; s|\"expected_pcr7\": \"pending\"|\"expected_pcr7\": \"$D7_ENROLLED\"|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline fixture carries the enrolled d7" "$D7_ENROLLED" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): the combined
# {7,11} entry is what the hook extracts for the finalized token.
D11=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11" ]] || { echo "s15: no enter-initrd d11 prediction from the build"; exit 1; }
swtpm_ensure "$RUN/tpm" || { echo "s15: swtpm restart (enroll) failed"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0-combined.json" \
    "$D7_ENROLLED" "$D11" "$RUN/keys" || exit 1
assert_eq "combined .pcrsig entry pol == policy_digest(enrolled d7, enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$D7_ENROLLED" "$D11")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.2.0-combined.json")"
# the payload drive of the enrolled boots carries the combined entry
uki_pcrsig_disk "$RUN/pcrsig-combined.img" "$RUN/uki-6.2.0-combined.json" || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.2.0-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s15: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

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
BL7=$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")
assert_ne "baseline re-baselined AWAY from the enrolled d7" "$D7_ENROLLED" "$BL7"
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "audit clean after re-baseline (exit 0)" "0" "$_audit_rc"
assert_contains "last-audit.json records the clean post-accept audit" \
    "$(cat "$RUN/rootfs/etc/alpine-fde/last-audit.json")" '"result": "ok"'
# NB: exact-value equality with $D7_DRIFT is asserted only opportunistically —
# the fixture swtpm can restart between the two CLI invocations (the probe is
# conservative), re-zeroing PCRs; the re-baseline SEMANTICS above are the proof.
rm -f "$AUDOUT"

# --- boot-layer drift: dbx-updated VARS (firmware-measured PCR 7 change) ---------
echo "# simulating the dbx update: extra cert in dbx (firmware will measure a new PCR 7)"
cp "$RUN/vars-enrolled.fd" "$RUN/vars-drifted.fd"
assert_rc "virt-fw-vars: dbx += throwaway cert" 0 \
    virt-fw-vars -i "$RUN/vars-drifted.fd" -o "$RUN/vars-drifted.fd" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$RUN/keys/KEK.crt"

# ONE boot: the hook refuses (stale d7) and its bounded loop reads 3 WRONG
# answers fed prompt-synchronized, ending in the 3-strike fail-closed poweroff
_ensure_tpm || { echo "s15: swtpm not serving (boot 2)"; exit 1; }
_fresh_pcrs || { echo "s15: cannot zero the TPM PCRs for boot 2"; exit 1; }
echo "# boot drifted: dbx-updated vars, stale {7,11} seal (TCG, up to $QEMU_TIMEOUT s)"
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-drifted.fd" "$RUN/tpm" "$RUN/pcrsig-combined.img"
for n in 1 2 3; do
    if uki_wait_hook_prompt "$n" 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "alpine-fde-drift-wrong-passphrase-$n"
    else
        _assert_result not-ok "[drift] hook awaiting recovery passphrase $n/3" \
            "no prompt $n in console"
        break
    fi
done
qemu_wait "$RUN" "$QEMU_TIMEOUT"
cp "$CONSOLE" "$RUN/console-drifted.log"
LOG=$(log_of "drifted")
assert_contains "[drift] init ran (SB still verifies — only the SEAL refuses)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_ne "[drift] firmware measured a DIFFERENT PCR 7" "$D7_ENROLLED" "$(console_pcr "drifted" 7)"
assert_contains "[drift] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[drift] hook discovered the {7,11} token" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[drift] I3 gate passed (the signature is NOT the defect)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "[drift] hook refused the stale seal (static PCR 7 term)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$RUN/console-drifted.log" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console-drifted.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "[drift] hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "[drift] hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
PROMPTS_DRIFT=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[drift] exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS_DRIFT"
assert_contains "[drift] 3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "[drift] fail-closed poweroff (no shell is offered)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[drift] never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[drift] never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[drift] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "[drift] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# tamper scoping: the hook extended PCR 11 exactly as at enroll (same UKI, same
# stub measurement) — the refusal is purely the PCR 7 drift
PCR11_ENROLLED=$(console_pcr "v1-baseline" 11)
PCR11_DRIFT=$(console_pcr "drifted" 11)
assert_eq "[drift] PCR 11 unchanged vs the enrolled boot (drift is PCR 7 only)" \
    "$PCR11_ENROLLED" "$PCR11_DRIFT"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[drift] guest exited (hook poweroff -f, not timeout-kill)" ""
else
    _assert_result not-ok "[drift] guest exited (hook poweroff -f, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# --- recovery: drop the stale seal; re-seal over the DRIFTED d7 -------------------
echo "# wiping the stale enrollment (token + slot) — the §9.4 operator step"
_host_wipe_enrollment "$RUN/disk.img" || { echo "s15: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"

# re-stamp the baseline to the DRIFTED (boot-layer) d7 and re-enroll: the fresh
# seal composes over the UNCHANGED d11 and the drifted d7 (no re-encryption)
D7_DRIFTED_BOOT=$(console_pcr "drifted" 7)
swtpm_ensure "$RUN/tpm" || { echo "s15: swtpm not serving (re-seal)"; exit 1; }
# digest-anchored re-seal (Option A): no reseeding — the CLI compares the
# re-signed entry's recorded d7/d11 against the re-stamped baseline (pure
# data, no live TPM read).
sed -i "s|\"expected_pcr7\": \".*\"|\"expected_pcr7\": \"$D7_DRIFTED_BOOT\"|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline re-stamped to the drifted d7" "$D7_DRIFTED_BOOT" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-drifted-combined.json" \
    "$D7_DRIFTED_BOOT" "$D11" "$RUN/keys" || exit 1
uki_pcrsig_disk "$RUN/pcrsig-drifted.img" "$RUN/uki-drifted-combined.json" || exit 1
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-drifted-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s15: re-seal enroll-tpm FAILED"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "re-sealed: exactly ONE standing systemd-tpm2 token" "1" "$NTOK"

# --- boot 3: re-sealed token under the drifted PCR 7 -> UNSEALED -----------------
boot_and_wait "re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-drifted.fd" "$RUN/pcrsig-drifted.img"
LOG=$(log_of "re-enroll")
assert_pcr11_prediction "S-15 re-enroll"
assert_contains "[re] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[re] re-sealed {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[re] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[re] unlocked via the TPM token (recovery complete)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[re] UNSEALED (recovery complete)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_contains "[re] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"
assert_eq "[re] sealed against the drifted (boot-layer) PCR 7" "$(console_pcr "drifted" 7)" \
    "$(console_pcr "re-enroll" 7)"

rm -rf "$RUN/guest-tree"
echo "# Mechanism B note: the combined {7,11} pol encodes the PCR 7 state — PCR 7 drift"
echo "# recovery needs a RE-SEAL over the drifted d7 (release key only, no re-encryption),"
echo "# never a re-signing ceremony; the volume key never moves."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s15-pcr7-drift: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s15-pcr7-drift: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
