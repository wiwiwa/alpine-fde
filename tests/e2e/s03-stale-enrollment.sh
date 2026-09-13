#!/usr/bin/env bash
# tests/e2e/s03-stale-enrollment.sh — §10 row "enrollment missing/stale" (Wave 3).
#
# Under Mechanism A'' the token pins ONLY the release pubkey (keyName pivoted
# inside the sealed object) — the per-kernel binding lives entirely in the
# release-key-signed .pcrsig delivered at boot. "Stale enrollment" therefore
# collapses to two concrete fail-closed flavors, BOTH proven here:
#
#   flavor 1 — a NEW UKI (6.3.0) built WITHOUT the PCR-signing step (no
#     .pcrsig section: the ADR-8 "signing key absent" mistake). Firmware still
#     boots it (PE signature valid), but find_signature() has no signed
#     policy to match the session digest -> unseal refused -> tries=1 lockout.
#
#   flavor 2 — a VALID UKI + valid .pcrsig, but the token was REMOVED
#     (cryptsetup token remove + luksKillSlot — the host-side stand-in for a
#     wiped enrollment). The booting initrd is built WITHOUT enrollment key
#     material (the production I6 shape: systemd's unlock path only), so the
#     harness's in-guest enroll cannot self-heal — its attempt fails loudly,
#     no token exists in the metadata -> nothing to satisfy -> refused ->
#     tries=1 lockout.
#
# §10 expectations both rows: Boots ✅ / Auto-unlock ❌ / fail-closed, never
# unlocked, never an emergency shell.

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
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s03-stale-enrollment-$(date +%s)"
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
# The SRK (storage primary seed) persists in tpm2-00.permall, so seals made by
# a previous boot still unseal after the restart (s01 precedent); PCRs reset
# and are re-measured by the firmware at the next boot — physically faithful.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }

_esp_set_default() {
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}
_esp_add_uki() {
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name"
}
_host_wipe_enrollment() { # <disk.img> — remove every systemd-tpm2 token + its keyslots
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue   # keep the slot-0 passphrase (recovery slot)
        cryptsetup luksKillSlot --batch-mode "$img" "$slot" || return 1
    done
}

# _vuki_build <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
# Variant UKI builder. VUKI_NO_PCRSIG=1 skips the ukify PCR-signing pass and
# the .pcrsig extraction (simulates a UKI built with the signing key absent —
# ADR-8's loud-failure condition, here proven fail-closed AT BOOT instead).
# VUKI_NO_RELPUB=1 omits the release PUBLIC key from the initrd payload — the
# production-shaped initrd (I6: systemd's unlock path, no enrollment tooling):
# an in-guest cryptenroll attempt then fails LOUDLY instead of self-healing.
_vuki_build() {
    local st="$1" tree="$2" kd="$3" un="$4" mk="$5" out="$6"
    mkdir -p "$st"
    local item
    for item in usr modules opt; do
        cp -al "$tree/$item" "$st/$item" || return 1
    done
    ln -sfn usr/bin "$st/bin"
    ln -sfn usr/sbin "$st/sbin"
    uki_initrd_write_init "$st"
    printf '# debian-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    if [[ -z "${VUKI_NO_RELPUB:-}" ]]; then
        cp "$kd/release.pub" "$st/rel.pub"
    fi
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=debian-fde-harness\nVERSION_ID=%s\nNAME=Debian FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    local -a pcrargs=()
    if [[ -z "${VUKI_NO_PCRSIG:-}" ]]; then
        pcrargs=(--pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub")
    fi
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" "${pcrargs[@]}" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s03: ukify (variant $un) failed" >&2
        return 1
    }
    if [[ -z "${VUKI_NO_PCRSIG:-}" ]]; then
        objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
        uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
    else
        truncate -s 64K "$out.pcrsig.img"   # zero payload: /init reads an empty .pcrsig
    fi
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" "$st.pcrsigned.efi" >/dev/null
}

boot_and_wait() { # <label> <esp> <disk> <vars> <pcrsig-img>
    local label="$1"
    _ensure_tpm || { echo "swtpm not serving"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures -----------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s03: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 (enrolled baseline) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s03: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" debian-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: healthy baseline (enroll + unlock) --------------------------------
boot_and_wait "v1-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "v1-enroll")
assert_contains "[v1] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[v1] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[v1] UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_contains "[v1] clean poweroff" "$LOG" "debian-fde: POWEROFF"

# --- flavor 1: new UKI with NO .pcrsig -----------------------------------------
echo "# building UKI 6.3.0 WITHOUT PCR signing (no .pcrsig section) ..."
VUKI_NO_PCRSIG=1 _vuki_build "$RUN/stage-6.3.0" "$RUN/guest-tree" "$RUN/keys" 6.3.0 v630 "$RUN/uki-6.3.0.efi" || {
    echo "s03: variant build failed"; exit 1; }
SEC63=$(objdump -h "$RUN/uki-6.3.0.efi" | awk '{print $2}')
assert_not_contains "uki 6.3.0 has NO .pcrsig section (the defect under test)" "$SEC63" ".pcrsig"
assert_rc "uki 6.3.0: sbverify clean (firmware WILL boot it)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.3.0.efi"
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.3.0.efi" debian-fde-6.3.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.3.0.efi" || exit 1

boot_and_wait "v3-nopcrsig" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.3.0.efi.pcrsig.img"
LOG=$(log_of "v3-nopcrsig")
assert_contains "[v3] init ran (firmware booted the UKI: SB signature valid)" "$LOG" \
    "debian-fde-harness: init started"
assert_contains "[v3] pcrsig payload missing (no policy to satisfy)" "$LOG" \
    "pcrsig payload MISSING"
assert_contains "[v3] retry cap reached (tries=1 lockout)" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "[v3] PROMPT-FAILED sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_not_contains "[v3] never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "[v3] never unlocked (harness)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[v3] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[v3] clean poweroff" "$LOG" "debian-fde: POWEROFF"

# --- flavor 2: valid UKI + valid .pcrsig, token removed -------------------------
# Production initramfs CANNOT self-heal (no enrollment tooling/key material in
# the initrd, I6) — the s00 harness's in-guest enroll is a bootstrap device.
# To model the production fail-closed shape, boot a UKI built WITHOUT the
# release pubkey in its initrd (enroll attempt fails loudly) against the
# wiped enrollment.
echo "# removing the enrollment host-side (token + its keyslot) ..."
_host_wipe_enrollment "$RUN/disk.img" || { echo "s03: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "token removed from LUKS2 metadata" "0" "$NTOK"
KSLOTS=$(disk_metadata "$RUN/disk.img" | jq -c '.keyslots | keys')
assert_eq "only the slot-0 passphrase remains" '["0"]' "$KSLOTS"

echo "# building UKI 6.2.0' without initrd key material (cannot self-enroll) ..."
VUKI_NO_RELPUB=1 _vuki_build "$RUN/stage-6.2.0nt" "$RUN/guest-tree" "$RUN/keys" 6.2.0 v620nt "$RUN/uki-6.2.0nt.efi" || {
    echo "s03: variant build failed"; exit 1; }
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.2.0nt.efi" || exit 1

boot_and_wait "v1-notoken" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0nt.efi.pcrsig.img"
LOG=$(log_of "v1-notoken")
assert_contains "[v1'] init ran (still boots)" "$LOG" "debian-fde-harness: init started"
assert_contains "[v1'] enroll attempt fails LOUD (no key material in initrd)" "$LOG" \
    "cryptenroll failed rc="
assert_not_contains "[v1'] no enrollment succeeded" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_not_contains "[v1'] no token discovered" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "[v1'] retry cap reached" "$LOG" "$(sentinel_of retry_cap)"
assert_contains "[v1'] PROMPT-FAILED sentinel" "$LOG" "debian-fde: PROMPT-FAILED"
assert_not_contains "[v1'] never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "[v1'] never unlocked (harness)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[v1'] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[v1'] clean poweroff" "$LOG" "debian-fde: POWEROFF"

# --- wrap up -------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.3.0" "$RUN/stage-6.2.0nt"
echo "# flavor verdicts: missing-.pcrsig -> fail-closed; removed-token (production-shaped" 
echo "# initrd, no self-enroll) -> fail-closed; harness-with-keymaterial would SELF-HEAL" 
echo "# (re-enroll on next boot) — which is the s15/s17 recovery path, not a tamper state."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s03-stale-enrollment: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s03-stale-enrollment: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
