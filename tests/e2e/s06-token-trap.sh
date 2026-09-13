#!/usr/bin/env bash
# tests/e2e/s06-token-trap.sh — §12 trap case (invariant I3):
#   "SB off + tampered token metadata + otherwise-legitimate PCR 11 signature
#    => unseal must still fail".
#
# The LUKS2 header travels with the disk, so an attacker can flip Secure Boot
# off AND rewrite the token JSON (host-side: cryptsetup token remove + token
# import) while the release-key-signed .pcrsig stays perfectly valid. The
# token's `tpm2_pubkey` here is swapped for a VALID foreign RSA public key —
# the most plausible-looking tamper. It cannot grant: the PolicyAuthorize
# node pins the enrollment keyName INSIDE the sealed blob, so a substituted
# key can only break the policy (I3: token JSON is untrusted).
#
# REQUIRED: tampered token verified host-side (pubkey swapped, blob/policy
#           intact), token_discovered (the token is still FOUND — it is valid
#           LUKS2 metadata), TPM2 unseal refused; UNSEALED / unlocked /
#           emergency shell NEVER; clean poweroff.
#
# Reuses s00 artifacts when DEBIAN_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots them itself (2 boots).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/disk-fixture.sh
source "$TESTS/lib/disk-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s06-lite-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while boots run, else a mid-boot prune unlinks console.log.
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!
# HI-02: the refresher must die on EVERY exit path (early `exit 1`s leak it
# forever and it poisons later prunes). Chain with swtpm cleanup; pre-set the
# flag so swtpm_start does not overwrite this trap.
_SWTPM_CLEANUP_TRAP_SET=1
trap 'kill "$REFRESHER" 2>/dev/null; swtpm_cleanup_all 2>/dev/null' EXIT INT TERM

STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 2: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s06: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # the sandbox is shared with sibling agents whose housekeeping has been
    # observed to SIGKILL mid-flight QEMUs — retry the bootstrap boot once
    # (the disk restarts blank and /init re-enrolls; the TPM must be RESET so
    # PCR 11 carries only one phase extension, else the .pcrsig never matches)
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        ENROLL_WAIT_RC=$?
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s06: enroll boot attempt $_attempt failed (qemu_wait rc=$ENROLL_WAIT_RC)"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s06: enroll boot did not reach UNSEALED — state unusable"
        echo "--- qemu_wait rc: $ENROLL_WAIT_RC"
        exit 1
    }
    STATE="$RUN_ENROLLED"
fi


# Snapshot the shared s00 state into OUR run dir: sibling prunes may remove
# the state dir mid-run; from here on this scenario only touches the local
# copy (the swtpm permall carries the seed -> the copy seals to the same SRK).
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"

# --- host-side tamper: swap the token's tpm2_pubkey for a foreign RSA key -----
# (verified empirically: a token assigned to an active keyslot is "in use" —
# remove + re-import at the same id is the attacker's write primitive; both
# are unprivileged metadata ops on a LUKS2 file.)
cp "$STATE/disk.img" "$RUN/disk.img"
cryptsetup token export "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-orig.json"
assert_file_exists "token exported (original)" "$RUN/token-orig.json"

openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -out "$RUN/foreign.pub" 2>/dev/null
FOREIGN_B64=$(base64 -w0 "$RUN/foreign.pub")
python3 - "$RUN/token-orig.json" "$RUN/token-trap.json" "$FOREIGN_B64" <<'PYEOF'
import json, sys
t = json.load(open(sys.argv[1]))
orig = t["tpm2_pubkey"]
assert orig != sys.argv[3], "foreign pubkey must differ from the enrolled one"
t["tpm2_pubkey"] = sys.argv[3]  # ONLY the pubkey is swapped
json.dump(t, open(sys.argv[2], "w"))
PYEOF
cryptsetup token remove --token-id 0 "$RUN/disk.img" 2>/dev/null
assert_rc "tampered token imported at id 0" 0 \
    cryptsetup token import "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-trap.json"
cryptsetup token export "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-check.json"
if python3 - "$RUN/token-orig.json" "$RUN/token-check.json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
ok = (a["tpm2_pubkey"] != b["tpm2_pubkey"]
      and a["tpm2-blob"] == b["tpm2-blob"]
      and a["tpm2-policy-hash"] == b["tpm2-policy-hash"]
      and a["tpm2_srk"] == b["tpm2_srk"])
sys.exit(0 if ok else 1)
PYEOF
then
    _assert_result ok "host-side tamper landed: ONLY tpm2_pubkey swapped (blob/policy-hash/srk intact)" ""
else
    _assert_result not-ok "host-side tamper landed: ONLY tpm2_pubkey swapped" "unexpected token JSON after re-import"
fi

# swtpm: the SRK must be the one the token is sealed to -> reuse the state dir
swtpm_start "$STATE/tpm" || { echo "s06: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"   # the .pcrsig remains perfectly VALID
# SB off: the trap combines a firmware-level downgrade with the metadata tamper
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot the trap: SB off + tampered token + valid .pcrsig ---------------------
echo "# booting the trap: SB-off vars + pubkey-swapped token + valid .pcrsig (TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"
qemu_wait "$RUN" "$QEMU_TIMEOUT"
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran (SB off boots the UKI)" "$LOG" "debian-fde-harness: init started"
assert_contains "token discovered (tampered token is still valid LUKS2 metadata)" "$LOG" \
    "$(sentinel_of token_discovered)"
if grep -qF "$(sentinel_of tpm2_refused)" "$CONSOLE" 2>/dev/null \
    || grep -qF "$(sentinel_of pcr_sig_missing)" "$CONSOLE" 2>/dev/null; then
    _assert_result ok "TPM2 unseal refused (swapped pubkey cannot rebuild the enrollment policy)" ""
else
    _assert_result not-ok "TPM2 unseal refused (swapped pubkey cannot rebuild the enrollment policy)" \
        "neither tpm2_refused nor signature-lookup failure in console"
fi
assert_contains "harness fail-closed sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_not_contains "interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never unlocked (harness sentinel)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# keep run dirs small (state dir is not ours to prune)
rm -rf "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s06-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s06-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
