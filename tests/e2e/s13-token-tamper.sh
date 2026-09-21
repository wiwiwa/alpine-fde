#!/usr/bin/env bash
# tests/e2e/s13-token-tamper.sh — §10/§12 token-tamper family (invariant I3:
# "Token JSON is untrusted: tampering with it can only break unseal, never
# forge it"). Parametrized over cryptsetup token import fixtures, all under
# SB-ENROLLED vars (pure metadata attack, trusted boot intact):
#   pubkey-swap     — tpm2_pubkey swapped for a VALID foreign RSA public key
#                     (PolicyAuthorize pivots on the keyName pinned inside the
#                     sealed blob -> the substitute key cannot rebuild the
#                     enrollment policy);
#   blob-corrupt    — tpm2-blob corrupted (first byte flipped);
#   policy-corrupt  — tpm2-policy-hash corrupted (first hex char flipped);
#   version-99      — otherwise-valid token + unknown "version": 99 field.
#
# Each variant boots the enrolled disk with its tampered token: the outcome
# must be fail-closed (unseal refused, never unlocked, clean poweroff, no
# emergency shell). Host-side pre-boot assertions prove every tamper actually
# landed (token remove + import is the attacker's unprivileged write
# primitive; an "in use" token cannot be overwritten directly).
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
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13/G-E9)
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s13-lite-$(date +%s)"
mkdir -p "$RUN"

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
    echo "# no s00 state — building + booting it (boot 1 of 5: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s13: swtpm failed"; exit 1; }
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
        echo "s13: enroll boot attempt $_attempt failed (qemu_wait rc=$ENROLL_WAIT_RC)"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s13: enroll boot did not reach UNSEALED — state unusable"
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

[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
UKI_MIB=$(( ($(stat -c%s "$STATE/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$STATE/harness.efi" || exit 1
cp "$STATE/vars-enrolled.fd" "$RUN/vars-enrolled.fd"

# --- token fixtures from the REAL enrolled token -------------------------------
cryptsetup token export "$STATE/disk.img" --token-id 0 --json-file "$RUN/token-orig.json"
assert_file_exists "original token exported" "$RUN/token-orig.json"

openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -out "$RUN/foreign.pub" 2>/dev/null
FOREIGN_PUB_B64=$(base64 -w0 "$RUN/foreign.pub")
python3 - "$RUN/token-orig.json" "$FOREIGN_PUB_B64" "$RUN" <<'PYEOF'
import base64, json, os, sys
t = json.load(open(sys.argv[1]))
out = lambda name: os.path.join(sys.argv[3], "tok-" + name + ".json")
# pubkey-swap: ONLY the pubkey replaced by a valid foreign RSA key
a = dict(t); a["tpm2_pubkey"] = sys.argv[2]
json.dump(a, open(out("pubkey-swap"), "w"))
# blob-corrupt: ONLY the sealed blob corrupted (first byte flipped)
b = base64.b64decode(t["tpm2-blob"])
c = dict(t); c["tpm2-blob"] = base64.b64encode(bytes([b[0] ^ 0xFF]) + b[1:]).decode()
json.dump(c, open(out("blob-corrupt"), "w"))
# policy-corrupt: ONLY the policy digest corrupted (first hex char flipped)
p = dict(t); h = t["tpm2-policy-hash"]
p["tpm2-policy-hash"] = ("0" if h[0] != "0" else "1") + h[1:]
json.dump(p, open(out("policy-corrupt"), "w"))
# version-99: otherwise-valid token + unknown field
v = dict(t); v["version"] = 99
json.dump(v, open(out("version-99"), "w"))
print("fixtures written", file=sys.stderr)
PYEOF

# tamper_disk <variant> <disk-copy> — swap in the tampered token (host-side
# attacker primitive; verified unprivileged on a LUKS2 file)
tamper_disk() {
    local variant="$1" disk="$2"
    cryptsetup token remove --token-id 0 "$disk" 2>/dev/null
    cryptsetup token import "$disk" --token-id 0 --json-file "$RUN/tok-$variant.json"
}

# assert_tamper_landed <variant> — re-export and prove the right field moved
assert_tamper_landed() {
    local variant="$1" disk="$2"
    cryptsetup token export "$disk" --token-id 0 --json-file "$RUN/chk-$variant.json"
    python3 - "$RUN/token-orig.json" "$RUN/chk-$variant.json" "$variant" <<'PYEOF'
import base64, json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
v = sys.argv[3]
if v == "pubkey-swap":
    ok = a["tpm2_pubkey"] != b["tpm2_pubkey"] and a["tpm2-blob"] == b["tpm2-blob"] \
         and a["tpm2-policy-hash"] == b["tpm2-policy-hash"]
elif v == "blob-corrupt":
    ok = base64.b64decode(a["tpm2-blob"]) != base64.b64decode(b["tpm2-blob"]) \
         and a["tpm2_pubkey"] == b["tpm2_pubkey"]
elif v == "policy-corrupt":
    ok = a["tpm2-policy-hash"] != b["tpm2-policy-hash"] and a["tpm2-blob"] == b["tpm2-blob"]
elif v == "version-99":
    ok = b.get("version") == 99 and a["tpm2-blob"] == b["tpm2-blob"] \
         and a["tpm2-policy-hash"] == b["tpm2-policy-hash"] \
         and a["tpm2_pubkey"] == b["tpm2_pubkey"]
else:
    ok = False
sys.exit(0 if ok else 1)
PYEOF
}

# run_variant <name> [expect-unlock] — boot the tampered disk, assert outcome.
# expect-unlock: for inert-metadata tampers (version-99) where the observed
# 257.13 behavior is an UNCHANGED unlock (documented deviation, see header).
run_variant() {
    local variant="$1" expect_unlock="${2:-}"
    local V="$RUN/boot-$variant"
    mkdir -p "$V"
    cp "$STATE/disk.img" "$V/disk.img"
    tamper_disk "$variant" "$V/disk.img" >/dev/null || {
        _assert_result not-ok "$variant: token import (host-side tamper)" "cryptsetup token import failed"
        return 0
    }
    _assert_result ok "$variant: token import (host-side tamper landed)" ""
    if assert_tamper_landed "$variant" "$V/disk.img"; then
        _assert_result ok "$variant: re-export proves the intended field moved" ""
    else
        _assert_result not-ok "$variant: re-export proves the intended field moved" \
            "token JSON after import does not match the fixture intent"
    fi

    swtpm_start "$STATE/tpm" || { echo "s13: swtpm restart ($variant) failed"; exit 1; }
    echo "# booting variant $variant (SB-enrolled vars, TCG, up to $QEMU_TIMEOUT s)"
    qemu_run "$V" "$RUN/esp.img" "$V/disk.img" "$RUN/vars-enrolled.fd" "$STATE/tpm" "$STATE/pcrsig.img"
    qemu_wait "$V" "$QEMU_TIMEOUT"
    local log
    log=$(cat "$V/console.log" 2>/dev/null || true)

    assert_contains "$variant: init ran" "$log" "debian-fde-harness: init started"
    assert_contains "$variant: token discovered (still valid LUKS2 metadata)" "$log" \
        "$(sentinel_of token_discovered)"
    if [[ "$expect_unlock" == "1" ]]; then
        # inert-metadata variant: the observed 257.13 behavior is an unchanged
        # unlock (documented deviation, see header) — assert THAT honestly
        _assert_result ok "$variant: unknown field is inert metadata (257.13 validate has no version check)" ""
        assert_contains "$variant: unlock followed the NORMAL signed-policy path" "$log" \
            "$(sentinel_of pcr_sig_added)"
        assert_contains "$variant: unlocked (field neither breaks nor forges)" "$log" \
            "$(sentinel_of unlocked)"
        assert_contains "$variant: harness UNSEALED sentinel" "$log" "debian-fde: UNSEALED"
    else
        if grep -qF "$(sentinel_of tpm2_refused)" "$V/console.log" 2>/dev/null \
            || grep -qF "$(sentinel_of pcr_sig_missing)" "$V/console.log" 2>/dev/null; then
            _assert_result ok "$variant: TPM2 unseal refused (tamper only breaks, never forges)" ""
        else
            _assert_result not-ok "$variant: TPM2 unseal refused (tamper only breaks, never forges)" \
                "neither tpm2_refused nor signature-lookup failure in console"
        fi
        assert_contains "$variant: harness fail-closed sentinel" "$log" "debian-fde: PROMPT-FAILED"
        assert_not_contains "$variant: never unlocked (token)" "$log" "$(sentinel_of unlocked)"
        assert_not_contains "$variant: never unlocked (harness sentinel)" "$log" "debian-fde: UNSEALED"
    fi
    assert_not_contains "$variant: no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    assert_contains "$variant: clean poweroff sentinel" "$log" "debian-fde: POWEROFF"
    # G-T13/G-E9 (every variant boot reaches the UKI stub): token-JSON tamper
    # breaks only the token path — the PRE-UNLOCK PCR 11 reading must equal
    # the enrolled UKI's signed prediction in EVERY variant.
    _CONSOLE_SAVE="$CONSOLE"
    CONSOLE="$V/console.log"
    assert_pcr11_prediction "S-13 [$variant]"
    CONSOLE="$_CONSOLE_SAVE"
    # IN-08: honest in both directions (missing pid file is not a clean exit)
    if [[ -f "$V/qemu.pid" ]] && ! kill -0 "$(cat "$V/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "$variant: guest exited (poweroff, not timeout-kill)" ""
    else
        _assert_result not-ok "$variant: guest exited (poweroff, not timeout-kill)" \
            "qemu still running or qemu.pid missing"
    fi
    swtpm_stop "$STATE/tpm"   # free the state dir for the next variant
    return 0
}

run_variant pubkey-swap
run_variant blob-corrupt
run_variant policy-corrupt
run_variant version-99 1   # inert-field variant: unlock expected (documented deviation)

# keep run dirs small
rm -rf "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s13-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s13-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
