#!/usr/bin/env bash
# tests/e2e/s02-rollback.sh — §9.3 rollback after failed upgrade (Wave 3, LITE).
#
# ESP holds TWO release-key-signed UKIs, each with its OWN .pcrsig (per-kernel
# policy delivery, Mechanism A''):
#   * 6.2.0 — built first, booted, enrolled in-guest (token pins the release
#     pubkey keyName; sealed object carries the static PolicyPCR(7) term);
#   * 6.1.0 — an OLDER UKI rebuilt with ukify afterwards (different .initrd
#     marker line + .osrel VERSION_ID + .uname -> genuinely different PCR 11
#     section chain -> different .pcrsig pols), NEVER enrolled.
# Rollback action = make the older UKI the boot default (mtools default swap —
# the LITE stand-in for systemd-boot loader.conf/bootnext, task-mandated).
#
# Boot 2 (6.1.0) must reach `debian-fde: UNSEALED` with ZERO new enrollment: the
# token's PolicyAuthorize pivots on the release keyName, so the older kernel's
# freshly delivered .pcrsig (pkfp + pol match) satisfies find_signature()
# without any TPM operation. §10 row "old retained kernel (rollback)".
#
# Assertions (host side, after each boot): both UKI files present on the ESP
# and sbverify-clean; LUKS2 metadata (tokens + keyslots) byte-identical across
# boot 2 — rollback enrolled nothing.
#
# Artifacts: <rundir>/console-{6.2.0-enroll,6.1.0-rollback}.log + images.

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
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13/G-E9)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)

RUN="$TESTS/e2e/.runs/s02-rollback-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# prune .runs aggressively (disk ~90%): keep the 2 newest run dirs overall —
# but NEVER the invocation's chained state dirs (CR-02/MD-03: run-e2e exports
# DEBIAN_FDE_PROTECT_DIRS; deleting them defeated §12 chaining and made the
# final artifact scan report "nothing to scan" on a green run)
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

# --- ESP helpers (mtools on the file-backed image; no systemd-boot this wave) --
_esp_add_uki() { # <esp.img> <uki.efi> <name.efi> — conventional ::/EFI/Linux/ entry
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name"
}
_esp_set_default() { # <esp.img> <uki.efi> — swap the removable-path default
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}
_esp_ls() { mdir -i "$1" -/ :: ::/EFI 2>/dev/null; }
_meta_snapshot() { # <disk.img> <out.json> — canonical metadata dump (identity asserts)
    disk_metadata "$1" | jq -S . >"$2"
}

# _vuki_build <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
# Variant UKI builder (replicates uki_build's pack+ukify+objcopy+sbsign steps
# with a DIFFERENT measured content: init marker line, real .osrel, --uname —
# task-mandated because tests/lib/ is outside this scenario's ownership).
# Convention: <out>.pcrsig.img / <out>.pcrsig.json sit next to <out>.
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
    cp "$kd/release.pub" "$st/rel.pub"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=debian-fde-harness\nVERSION_ID=%s\nNAME=Debian FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s02: ukify (variant $un) failed" >&2
        return 1
    }
    objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
    uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
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
swtpm_start "$RUN/tpm" || { echo "s02: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
assert_contains "enrolled vars: SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"

echo "# building UKI 6.2.0 (current, will be enrolled) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s02: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0.efi.pcrsig.json"   # unify the naming convention
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
assert_file_exists "uki 6.2.0: .pcrsig extracted" "$RUN/uki-6.2.0.efi.pcrsig.json"

UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))   # two UKIs + headroom
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" debian-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: 6.2.0 enrolls + unlocks ------------------------------------------
boot_and_wait "6.2.0-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "6.2.0-enroll")
assert_contains "[6.2.0] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[6.2.0] TPM present" "$LOG" "/dev/tpmrm0 present"
assert_contains "[6.2.0] .pcrsig consumed" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_contains "[6.2.0] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[6.2.0] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[6.2.0] UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_contains "[6.2.0] clean poweroff" "$LOG" "debian-fde: POWEROFF"
# G-T13/G-E9 (boot reaches the UKI stub): $RUN/uki-pcrsig.json is 6.2.0's
# signed prediction (uki_build wrote it), $CONSOLE is this boot's console.
assert_pcr11_prediction "S-02 [6.2.0]"

_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-6.2.0.json"

# --- build the OLDER 6.1.0 UKI (own .pcrsig, never enrolled) -------------------
echo "# building UKI 6.1.0 (older, rollback target; no enrollment will exist for it) ..."
_vuki_build "$RUN/stage-6.1.0" "$RUN/guest-tree" "$RUN/keys" 6.1.0 v610 "$RUN/uki-6.1.0.efi" || {
    echo "s02: variant build failed"; exit 1; }
assert_file_exists "uki 6.1.0: .pcrsig extracted" "$RUN/uki-6.1.0.efi.pcrsig.json"
assert_rc "uki 6.1.0: sbverify clean (release cert)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.1.0.efi"
SEC61=$(objdump -h "$RUN/uki-6.1.0.efi" | awk '{print $2}')
for sec in .linux .initrd .cmdline .osrel .uname .pcrpkey .pcrsig; do
    assert_contains "uki 6.1.0: section $sec present" "$SEC61" "$sec"
done
# genuinely different measured content -> different signed pols, same release key
POLS62=$(jq -r '.sha256[].pol' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
POLS61=$(jq -r '.sha256[].pol' "$RUN/uki-6.1.0.efi.pcrsig.json" | sort)
assert_ne "pcrsig pols differ across UKIs (distinct PCR 11 predictions)" "$POLS62" "$POLS61"
PKFP62=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
PKFP61=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-6.1.0.efi.pcrsig.json" | sort)
assert_eq "pcrsig pkfp identical across UKIs (same release key)" "$PKFP62" "$PKFP61"

# --- rollback action: older UKI becomes the boot default -----------------------
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.1.0.efi" debian-fde-6.1.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.1.0.efi" || exit 1
ESPLS=$(_esp_ls "$RUN/esp.img")
assert_contains "ESP retains 6.2.0 entry" "$ESPLS" "debian-fde-6.2.0.efi"
assert_contains "ESP retains 6.1.0 entry" "$ESPLS" "debian-fde-6.1.0.efi"

# --- boot 2: 6.1.0 rollback must unlock passwordless ---------------------------
boot_and_wait "6.1.0-rollback" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.1.0.efi.pcrsig.img"
LOG=$(log_of "6.1.0-rollback")
assert_contains "[6.1.0] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[6.1.0] token found — enrollment SKIPPED" "$LOG" \
    "systemd-tpm2 token present — skipping enrollment"
assert_not_contains "[6.1.0] no new enrollment" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[6.1.0] token discovered" "$LOG" "$(sentinel_of token_discovered)"
assert_contains "[6.1.0] 6.1.0 .pcrsig consumed" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_contains "[6.1.0] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[6.1.0] UNSEALED (rollback passwordless)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[6.1.0] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[6.1.0] clean poweroff" "$LOG" "debian-fde: POWEROFF"
# G-T13/G-E9 for the ROLLBACK boot: pair the helper with 6.1.0's OWN signed
# prediction (the older UKI's pols differ — asserted above) — the pre-unlock
# PCR 11 reading under 6.1.0 must match 6.1.0's per-kernel signed policy.
cp "$RUN/uki-6.1.0.efi.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "S-02 [6.1.0]"

_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-6.1.0.json"
assert_rc "rollback boot changed NO LUKS2 metadata (no enrollment)" 0 \
    cmp -s "$RUN/meta-post-6.2.0.json" "$RUN/meta-post-6.1.0.json"

# --- wrap up -------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.1.0"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s02-rollback: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s02-rollback: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
