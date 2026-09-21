#!/usr/bin/env bash
# tests/e2e/s16-key-rotation.sh — §9.6 release-key rotation, end to end (Wave 3).
#
# K1 = original release key (in db, signs UKI+pcrsig, token pinned to it).
# K2 = fresh "offline medium" keypair. Sequence (boot-by-boot):
#
#   boot 1  K1 UKI enrolls + unlocks; real `audit --init` finalizes d7   UNSEALED
#   host    dual-sign the UKI: sbsign with K2 APPENDS a 2nd PE signature
#           (empirically verified: "Image was already signed; adding
#           additional signature"; sbverify --list shows both)
#   boot 2  dual-signed UKI, db still {K1}: firmware verifies via the OLD
#           signature, PCR 7 untouched                                  UNSEALED
#   host    ONE vars edit (§9.6 step 4): db += K2 AND dbx += K1
#   boot 3  dual-signed UKI + revoked K1 (db += K2 AND dbx += K1): the
#           firmware REJECTS the image — dual-signing does NOT survive
#           revocation, OVMF refuses ANY image carrying a revoked
#           signature (§9.6 corrected empirically) — so the guest never
#           starts; assert the rejection sentinel + fail-closed negatives.
#   host    real `audit` (drift, exit 1) -> `audit --accept --yes`;
#           wipe the K1 enrollment
#   boot 4  K2-built UKI (K2 pcrsig + K2 rel.pub in the initrd + K2 PE sig;
#           K2 in db): firmware boots it, guest re-enrolls under K2,
#           unlock via the K2-signed policy — passwordless, the §9.6
#           corrective re-sign proven end to end             UNSEALED
#
# Wall time is the longest of the family (~4-5 boots).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
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

RUN="$TESTS/e2e/.runs/s16-key-rotation-$(date +%s)"
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
# the restart and are re-measured by the firmware at the next boot. Post-boot
# PCR evidence therefore comes from the GUEST's console prints, not host reads.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }

# shellcheck disable=SC2120  # bare calls (plain audit) are intentional
_audit_cli() {
    _ensure_tpm || { echo "s16: swtpm not serving (audit)"; return 64; }
    DEBIAN_FDE_ROOT="$RUN/rootfs" \
        DEBIAN_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        DEBIAN_FDE_EFIVARS_DIR="$RUN/rootfs/efivars-sb-on" \
        DEBIAN_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
        "$REPO/bin/alpine-fde" audit "$@"
}
# shellcheck disable=SC2317  # invoked via assert_rc's "$@" (see tests/lib/assert.sh)
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
_esp_set_default() {
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}

# _vuki_build <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
#             [pcr-priv pcr-pub sign-key sign-cert relpub]
_vuki_build() {
    local st="$1" tree="$2" kd="$3" un="$4" mk="$5" out="$6"
    local ppriv="${7:-$kd/db.key}" ppub="${8:-$kd/release.pub}"
    local skey="${9:-$kd/db.key}" scert="${10:-$kd/db.crt}" relpub="${11:-$kd/release.pub}"
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
    cp "$relpub" "$st/rel.pub"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=debian-fde-harness\nVERSION_ID=%s\nNAME=Debian FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --pcr-banks=sha256 --pcr-private-key="$ppriv" --pcr-public-key="$ppub" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s16: ukify (variant $un) failed" >&2
        return 1
    }
    objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
    uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
    sbsign --key "$skey" --cert "$scert" --output "$out" "$st.pcrsigned.efi" >/dev/null
}

boot_and_wait() {
    local label="$1"
    _ensure_tpm || { echo "s16: swtpm not serving"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }
console_pcr7() { grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2; }
console_pcr0() { grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2; }

# --- fixtures: K1 ceremony + fresh K2 ("offline medium") ------------------------
swtpm_start "$RUN/tpm" || { echo "s16: swtpm failed"; exit 1; }
keys_create "$RUN/keys"                                  # K1 (current release key)
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
mkdir -p "$RUN/keys2"
openssl req -x509 -newkey rsa:2048 -keyout "$RUN/keys2/db.key" -out "$RUN/keys2/db.crt" \
    -days 30 -nodes -subj "/CN=debian-fde-test-release-v2" 2>/dev/null
openssl x509 -in "$RUN/keys2/db.crt" -pubkey -noout >"$RUN/keys2/release.pub"
assert_file_exists "K2 keypair generated (offline-medium stand-in)" "$RUN/keys2/db.key"

# G-R1 guard (§8.1): `audit --init` / `audit --accept` refuse fail-closed unless
# the efivars seam reports SecureBoot=1 SetupMode=0. The host-side CLI steps run
# against this fixture efivars dir — the mkvar pattern from
# tests/unit/baseline_finalize_guard.sh (attrs u32le 0x7 + payload byte).
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
# shellcheck disable=SC1091
source "$REPO/lib/firmware.sh"
assert_contains "efivars fixture: SB on, SetupMode=0" \
    "$(DEBIAN_FDE_EFIVARS_DIR="$EFIVARS" fw_sb_state)" \
    "secureboot=1 setup_mode=0"

mkdir -p "$RUN/rootfs/etc/alpine-fde"
sed "s/PENDING-BY-SCENARIO/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" >"$RUN/rootfs/etc/alpine-fde/baseline.json" <<'JSON'
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

echo "# building UKI 6.2.0 under K1 ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s16: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0-k1.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0-k1.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0-k1.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 3 + 12 )) "$RUN/uki-6.2.0-k1.efi" || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: K1 enroll + unlock + baseline --------------------------------------
boot_and_wait "k1-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0-k1.efi.pcrsig.img"
LOG=$(log_of "k1-enroll")
assert_pcr11_prediction "S-16 k1-enroll"
assert_contains "[K1] enrolled in-guest" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[K1] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_rc "audit --init finalizes pre-rotation baseline" 0 _audit_cli --init
D7_PRE=$(console_pcr7 "k1-enroll")
assert_ne "boot 1 console records a non-zero PCR 7" "$D7_PRE" ""
# stamp the baseline's PCR 7/0 from boot-1 console evidence: the fixture swtpm's
# live state is not durable across qemu boots/restarts, so the baseline records
# the OPERATOR-meaningful pre-rotation values, not the restarted-TPM zeros
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$D7_PRE\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(console_pcr0 k1-enroll)\",|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline fixture carries the pre-rotation d7" "$D7_PRE" \
    "$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")"

# --- §9.6 step 2: dual-sign (append K2 signature) --------------------------------
echo "# dual-signing the UKI (sbsign append; old K1 signature retained) ..."
assert_rc "sbsign appends the K2 signature" 0 \
    sbsign --key "$RUN/keys2/db.key" --cert "$RUN/keys2/db.crt" \
        --output "$RUN/uki-6.2.0-dual.efi" "$RUN/uki-6.2.0-k1.efi"
SIGLIST=$(sbverify --list "$RUN/uki-6.2.0-dual.efi" 2>&1)
assert_contains "dual-signed: signature 1 present" "$SIGLIST" "signature 1"
assert_contains "dual-signed: signature 2 present" "$SIGLIST" "signature 2"
assert_rc "dual-signed: K1 signature still verifies" 0 sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.2.0-dual.efi"
assert_rc "dual-signed: K2 signature verifies" 0 sbverify --cert "$RUN/keys2/db.crt" "$RUN/uki-6.2.0-dual.efi"
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.2.0-dual.efi" || exit 1

# --- §9.6 step 3: reboot BEFORE the db change (old key path, PCR 7 untouched) ----
boot_and_wait "dual-prerevoke" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0-k1.efi.pcrsig.img"
LOG=$(log_of "dual-prerevoke")
assert_pcr11_prediction "S-16 dual-prerevoke"
assert_contains "[dual] init ran (firmware verified via the OLD signature)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[dual] UNSEALED (PCR 7 unchanged pre-db-change)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_eq "PCR 7 unchanged after the dual-sign reboot (console evidence)" "$D7_PRE" "$(console_pcr7 "dual-prerevoke")"

# --- §9.6 step 4: db += K2 AND dbx += K1 in ONE vars edit -------------------------
cp "$RUN/vars-enrolled.fd" "$RUN/vars-rotated.fd"
assert_rc "virt-fw-vars: db += K2, dbx += K1 (one step)" 0 \
    virt-fw-vars -i "$RUN/vars-rotated.fd" -o "$RUN/vars-rotated.fd" \
        --add-db "$DEBIAN_FDE_TEST_GUID" "$RUN/keys2/db.crt" \
        --add-dbx-cert "$DEBIAN_FDE_TEST_GUID" "$RUN/keys/db.crt"
VARSDBG=$(virt-fw-vars -i "$RUN/vars-rotated.fd" -p 2>/dev/null | grep -cE '^(db|dbx)[[:space:]]*:')
assert_eq "rotated vars carry db and dbx blobs" "2" "$VARSDBG"

# --- §9.6 step 5: reboot into the rotated policy — firmware must REJECT ----------
# Pinned outcome (§9.6 corrected empirically): dual-signing does NOT survive
# revocation — OVMF refuses ANY image carrying a revoked signature, so the
# guest never starts. The firmware falls through to the boot-manager menu
# and cannot power the machine off; killing qemu once the rejection sentinel
# is on the console is the expected termination (s04 refusal shape).
echo "# booting dual-signed UKI with db={K1,K2} dbx={K1} — firmware must reject (revoked signature)"
_ensure_tpm || { echo "s16: swtpm not serving (boot3)"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-rotated.fd" "$RUN/tpm" "$RUN/uki-6.2.0-k1.efi.pcrsig.img"
FW_DEADLINE=$((SECONDS + 150))
REJECTED=0
while ((SECONDS < FW_DEADLINE)); do
    if grep -qF "$(sentinel_of ovmf_sb_denied)" "$CONSOLE" 2>/dev/null; then REJECTED=1; break; fi
    kill -0 "$(cat "$RUN/qemu.pid")" 2>/dev/null || break   # self-exited: terminal either way
    sleep 2
done
qemu_kill "$RUN"
cp "$CONSOLE" "$RUN/console-post-revoke.log"
LOG=$(log_of "post-revoke")
if ((REJECTED == 1)); then
    _assert_result ok "firmware REJECTS the dual-signed UKI (revoked-signature images never boot)" ""
else
    _assert_result not-ok "firmware REJECTS the dual-signed UKI (revoked-signature images never boot)" \
        "no ovmf_sb_denied sentinel in the 150 s refusal budget; last console: $(tail -2 "$CONSOLE" 2>/dev/null | tr '\n' ' ')"
fi
assert_not_contains "[rot] guest never started (refused at firmware load)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_not_contains "[rot] never unlocked" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "[rot] interactive prompt never appeared" "$LOG" "$(sentinel_of prompt_re)"
assert_not_contains "[rot] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_not_contains "[rot] never UNSEALED (revoked-signature refusal)" "$LOG" \
    "$(sentinel_of harness_unsealed)"

# --- recovery (§9.6 steps 5-6): re-baseline + re-enroll under K2 ------------------
# Detection with the REAL CLI: the baseline carries the pre-rotation d7; ANY
# live swtpm state after the rotation (a fresh instance reads zeros) differs
# from it, so the drift decision is deterministic despite fixture restarts.
AUDOUT=$(mktemp)
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "audit detects the rotation drift (exit 1)" "1" "$_audit_rc"
assert_contains "audit report: pcr7 DRIFT line" "$(grep '^pcr7' "$AUDOUT")" "DRIFT"
assert_rc "audit --accept --yes re-baselines over the new d7" 0 _audit_cli --accept --yes
BL7=$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")
assert_ne "baseline re-baselined AWAY from the pre-rotation d7" "$D7_PRE" "$BL7"
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "audit clean after re-baseline (exit 0)" "0" "$_audit_rc"
rm -f "$AUDOUT"
assert_rc "stale K1 enrollment wiped (token + slot)" 0 _host_wipe_enrollment "$RUN/disk.img"

echo "# building UKI 6.4.0 fully under K2 (pcrsig + PE sig + initrd rel.pub = K2) ..."
_vuki_build "$RUN/stage-6.4.0-k2" "$RUN/guest-tree" "$RUN/keys" 6.4.0 v640k2 \
    "$RUN/uki-6.4.0-k2.efi" \
    "$RUN/keys2/db.key" "$RUN/keys2/release.pub" \
    "$RUN/keys2/db.key" "$RUN/keys2/db.crt" \
    "$RUN/keys2/release.pub" || { echo "s16: K2 build failed"; exit 1; }
K1PKFP=$(jq -r '.sha256[].pkfp' "$RUN/uki-6.2.0-k1.efi.pcrsig.json" 2>/dev/null | sort -u | head -1)
K2PKFP=$(jq -r '.sha256[].pkfp' "$RUN/uki-6.4.0-k2.efi.pcrsig.json" | sort -u | head -1)
assert_ne "new .pcrsig is signed by a DIFFERENT key (pkfp K1 != K2)" "$K1PKFP" "$K2PKFP"
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.4.0-k2.efi" || exit 1

# --- §9.6 step 6-7: boot + verify passwordless under the new key ------------------
boot_and_wait "k2-re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-rotated.fd" "$RUN/uki-6.4.0-k2.efi.pcrsig.img"
LOG=$(log_of "k2-re-enroll")
cp "$RUN/uki-6.4.0-k2.efi.pcrsig.json" "$RUN/uki-pcrsig.json"   # prediction of the BOOTED (K2) UKI
assert_pcr11_prediction "S-16 k2-re-enroll"
assert_contains "[K2] init ran (firmware verifies via K2 in db)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[K2] re-enrolled under the NEW key" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[K2] K2-signed .pcrsig consumed" "$LOG" "$(sentinel_of pcr_sig_added)"
assert_contains "[K2] unlocked via token" "$LOG" "$(sentinel_of unlocked)"
assert_contains "[K2] UNSEALED (rotation complete)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_ne "PCR 7 is on the rotated value (console evidence, post-rotation)" "$D7_PRE" "$(console_pcr7 "k2-re-enroll")"
TOKENPUB=$(disk_token_json "$RUN/disk.img" | jq -r '.[] | select(.type == "systemd-tpm2") | .tpm2_pubkey' | base64 -d)
assert_eq "token now pins the K2 public key" \
    "$(printf '%s' "$TOKENPUB" | tr -d '\n' | sha256sum | awk '{print $1}')" \
    "$(tr -d '\n' <"$RUN/keys2/release.pub" | sha256sum | awk '{print $1}')"

rm -rf "$RUN/guest-tree" "$RUN/stage-6.4.0-k2"
echo "# DUAL-SIGN: sbsign append VERIFIED (2 signatures, both verify)."
echo "# DBX-REVOKE x DUAL-SIGNED UKI: OVMF REJECTS images carrying a revoked"
echo "# signature (§9.6 step 5 corrected: the corrective re-sign is mandatory,"
echo "# also for the boot manager) — pinned here; the K2-only re-signed boot"
echo "# then completes the rotation passwordless (boot 4 above)."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s16-key-rotation: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s16-key-rotation: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
