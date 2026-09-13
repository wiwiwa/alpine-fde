#!/usr/bin/env bash
# tests/e2e/s14-kernel-update.sh — §9.2 kernel update + the H-G7 question (Wave 3).
#
# H-G7 asked: does 257.13 gate token acceptance on the token's stored digest
# list — i.e. does a NEW kernel's .pcrsig boot WITHOUT re-enrollment, or must
# the postinst hook's conditional re-enroll fire?
#
# Sequence: boot/enroll UKI 6.2.0 (state = s00), then build UKI 6.4.0 (new
# .pcrsig: different .initrd marker + .osrel + .uname -> different PCR 11
# section chain -> different signed pols), install it as the boot default,
# touch NOTHING in the TPM/LUKS2 world, boot it. The G4 property holds iff
# boot 2 unlocks passwordless with the enrollment SKIP line in the console
# and byte-identical LUKS2 metadata before/after.
#
# VERDICT (empirical, filled in by the run): see the "H-G7 VERDICT" line in
# the output and tests/e2e/README.md.

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

RUN="$TESTS/e2e/.runs/s14-kernel-update-$(date +%s)"
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

_esp_add_uki() {
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name"
}
_esp_set_default() {
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}
_meta_snapshot() { disk_metadata "$1" | jq -S . >"$2"; }

_vuki_build() { # <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
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
    cp "$kd/release.pub" "$st/rel.pub"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=debian-fde-harness\nVERSION_ID=%s\nNAME=Debian FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s14: ukify (variant $un) failed" >&2
        return 1
    }
    objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
    uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" "$st.pcrsigned.efi" >/dev/null
}

boot_and_wait() { # <label> <esp> <disk> <vars> <pcrsig-img>
    local label="$1"
    _ensure_tpm || { echo "s14: swtpm not serving"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures -----------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s14: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 (running kernel) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s14: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0.efi.pcrsig.json"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" debian-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: 6.2.0 enroll + unlock (s00 state) ---------------------------------
boot_and_wait "v1-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "v1-enroll")
assert_contains "[6.2.0] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[6.2.0] UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[6.2.0] interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "[6.2.0] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-v1.json"

# === §10 row "kernel update build failed" ======================================
# The postinst hook's ukictl build runs WITHOUT the release signing private key
# (offline medium not attached, I4). Production contract (§8.3, ADR-8): fail
# LOUDLY (non-zero + persisted marker), ship NOTHING, leave the previous UKI as
# the ESP default — the machine keeps booting + auto-unlocking (boot 2 below).
# Harness stand-in: the same build pipeline with the key absent; the production
# CLI preconditions on keys_check before any ESP mutation (lib/cmd/
# ukictl-build.sh step 0) and persists the marker — this leg proves the
# observable outcome end-to-end.
echo "# breaking the rebuild: release signing key ABSENT (ADR-8 loud failure)"
KEYLESS_DIR="$RUN/keys-keyless"   # no db.key/release material inside
mkdir -p "$KEYLESS_DIR"
assert_rc "failed rebuild: build WITHOUT the signing key fails non-zero (loud)" 1 \
    _vuki_build "$RUN/stage-keyless" "$RUN/guest-tree" "$KEYLESS_DIR" \
    6.3.0-broken v630 "$RUN/uki-keyless.efi"
assert_contains "failed rebuild names tool + variant (not a silent failure)" \
    "$ASSERT_RC_OUTPUT" "ukify (variant 6.3.0-broken) failed"
if [[ -e "$RUN/uki-keyless.efi" ]]; then
    _assert_result not-ok "failed rebuild ships NO UKI artifact" "uki-keyless.efi exists"
else
    _assert_result ok "failed rebuild ships NO UKI artifact" ""
fi
mcopy -i "$RUN/esp.img" ::/EFI/BOOT/BOOTX64.EFI "$RUN/default-after-failed.efi" 2>/dev/null
assert_rc "failed rebuild touches NOTHING on the ESP: default still byte-identical 6.2.0" 0 \
    cmp -s "$RUN/default-after-failed.efi" "$RUN/uki-6.2.0.efi"
ESPLS=$(mdir -i "$RUN/esp.img" ::/EFI/BOOT ::/EFI/Linux 2>/dev/null)
assert_not_contains "failed rebuild: no broken-variant UKI on the ESP" "$ESPLS" "6.3.0"

# --- boot 2: the OLD default UKI still boots + auto-unlocks ---------------------
boot_and_wait "old-default" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "old-default")
assert_contains "[old] init ran (failed update did not strand the machine)" "$LOG" \
    "debian-fde-harness: init started"
assert_contains "[old] enrollment SKIPPED (zero TPM operations)" "$LOG" \
    "systemd-tpm2 token present — skipping enrollment"
assert_not_contains "[old] no new enrollment after the failed rebuild" "$LOG" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[old] old default UKI still AUTO-UNLOCKS" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[old] UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[old] interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "[old] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[old] clean poweroff" "$LOG" "debian-fde: POWEROFF"

# --- kernel update: build 6.4.0 + install, ZERO TPM operations ------------------
echo "# building UKI 6.4.0 (kernel update; NO enrollment will be performed) ..."
_vuki_build "$RUN/stage-6.4.0" "$RUN/guest-tree" "$RUN/keys" 6.4.0 v640 "$RUN/uki-6.4.0.efi" || {
    echo "s14: variant build failed"; exit 1; }
assert_rc "uki 6.4.0: sbverify clean" 0 sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.4.0.efi"
POLS64=$(jq -r '.sha256[].pol' "$RUN/uki-6.4.0.efi.pcrsig.json" | sort)
POLS62=$(jq -r '.sha256[].pol' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
assert_ne "new kernel -> new signed pols (distinct PCR 11 prediction)" "$POLS62" "$POLS64"
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.4.0.efi" debian-fde-6.4.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.4.0.efi" || exit 1
ESPLS=$(mdir -i "$RUN/esp.img" ::/EFI/BOOT ::/EFI/Linux 2>/dev/null)
assert_contains "ESP retains 6.2.0 (old kernel kept for rollback)" "$ESPLS" "debian-fde-6.2.0.efi"
assert_contains "ESP has 6.4.0 as new default" "$ESPLS" "debian-fde-6.4.0.efi"

# --- boot 2: new kernel, existing token, no re-enroll ---------------------------
boot_and_wait "v2-noenroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.4.0.efi.pcrsig.img"
LOG=$(log_of "v2-noenroll")
assert_contains "[6.4.0] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[6.4.0] enrollment SKIPPED (zero TPM operations)" "$LOG" \
    "systemd-tpm2 token present — skipping enrollment"
assert_not_contains "[6.4.0] no new enrollment" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[6.4.0] token discovered" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "[6.4.0] NEW kernel's .pcrsig consumed" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_contains "[6.4.0] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[6.4.0] UNSEALED (kernel update passwordless)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[6.4.0] interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "[6.4.0] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[6.4.0] clean poweroff" "$LOG" "debian-fde: POWEROFF"
_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-v2.json"
assert_rc "LUKS2 metadata byte-identical across the update boot (no enrollment)" 0 \
    cmp -s "$RUN/meta-post-v1.json" "$RUN/meta-post-v2.json"

# --- verdict --------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.4.0"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# H-G7 VERDICT: 257.13 does NOT gate token acceptance on the token's stored"
    echo "# digest list — a new kernel's release-key-signed .pcrsig (pkfp+pol match)"
    echo "# unlocked the existing token with ZERO TPM operations (enrollment skip +"
    echo "# byte-identical LUKS2 metadata). G4 holds: kernel updates are TPM-free and"
    echo "# the postinst hook's conditional re-enroll is NOT needed for them."
    echo "# s14-kernel-update: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s14-kernel-update: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
