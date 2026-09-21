#!/usr/bin/env bash
# tests/e2e/s17-tpm-clear.sh — §10 row "TPM cleared" + §9.4 recovery (Wave 3).
#
#   boot 1  v1 enrolls + unlocks (healthy baseline)              UNSEALED
#   host    swtpm_reset — wipe ALL TPM state (fresh SRK, PCRs 0)
#   boot 2  the token's sealed blob references a primary key that
#           no longer exists -> unseal fails closed              REFUSED
#   host    wipe the stale enrollment (token + keyslot)          operator step
#   boot 3  guest re-enrolls against the fresh TPM (new SRK,
#           firmware re-measured PCR 7)                          UNSEALED
#
# §10 expectations: TPM cleared -> Boots ✅ / Auto-unlock ❌ / re-enroll.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/assert.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/keys-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/disk-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13, §12)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s17-tpm-clear-$(date +%s)"
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
# the restart and are re-measured by the firmware at the next boot.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }

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

boot_and_wait() {
    local label="$1"
    _ensure_tpm || { echo "s17: swtpm not serving"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures ------------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s17: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s17: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/uki-6.2.0.efi" || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: healthy enroll + unlock --------------------------------------------
boot_and_wait "v1-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "v1-enroll")
assert_pcr11_prediction "S-17 v1-enroll"
assert_contains "[v1] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[v1] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
D7_PRE=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-v1-enroll.log" | head -1 | cut -d= -f2)
assert_ne "boot 1 console records a non-zero PCR 7" "$D7_PRE" ""

# --- clear the TPM (§9.4 "cleared TPM") ------------------------------------------
echo "# swtpm_reset: wiping ALL TPM state (fresh SRK, PCRs reset)"
swtpm_reset "$RUN/tpm"
swtpm_start "$RUN/tpm" || { echo "s17: swtpm restart after reset failed"; exit 1; }
ZERO7=$(printf '0%.0s' {1..64})
assert_eq "fresh TPM: PCR 7 is zero" "$ZERO7" "$(swtpm_pcrread "$RUN/tpm" 7)"

# --- boot 2: seal is dead — fail closed -------------------------------------------
boot_and_wait "cleared" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "cleared")
assert_pcr11_prediction "S-17 cleared"
assert_contains "[clr] init ran (still boots — firmware re-measures the fresh TPM)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[clr] TPM2 unseal refused (sealed blob lost with the old SRK)" "$LOG" \
    "$(sentinel_of tpm2_refused)"
assert_contains "[clr] retry cap reached" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "[clr] PROMPT-FAILED" "$LOG" "$(sentinel_of harness_prompt_failed)"
assert_not_contains "[clr] never unlocked" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "[clr] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "[clr] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[clr] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"

# --- recovery: wipe the dead seal; guest re-enrolls on the fresh TPM --------------
echo "# wiping the stale enrollment (token + slot) — re-enroll happens in-guest"
_host_wipe_enrollment "$RUN/disk.img" || { echo "s17: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"

# --- boot 3: re-enroll on the fresh TPM -> UNSEALED --------------------------------
boot_and_wait "re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "re-enroll")
assert_pcr11_prediction "S-17 re-enroll"
assert_contains "[re] re-enrolled on the fresh TPM" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[re] .pcrsig consumed" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_contains "[re] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[re] UNSEALED (recovery complete)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_contains "[re] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"
D7_RE=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-re-enroll.log" | head -1 | cut -d= -f2)
assert_eq "PCR 7 re-measured to the same enrolled state (console evidence)" "$D7_PRE" "$D7_RE"

rm -rf "$RUN/guest-tree"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s17-tpm-clear: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s17-tpm-clear: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
