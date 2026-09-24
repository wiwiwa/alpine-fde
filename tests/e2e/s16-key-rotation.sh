#!/usr/bin/env bash
# tests/e2e/s16-key-rotation.sh — §9.6 release-key rotation, end to end (Wave 3),
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock).
#
# K1 = original release key (in db, signs UKI+pcrsig, token pinned to it).
# K2 = fresh "offline medium" keypair. Sequence (boot-by-boot):
#
#   boot 1  baseline (token-less disk): the hook's bounded recovery loop is
#           the only way in; the slot-0 passphrase is fed through the hook's
#           OWN prompt -> UNSEALED. Host: real `audit --init` finalizes d7,
#           then the REAL production CLI enrolls the finalized {7,11}
#           Mechanism B token under K1 (combined .pcrsig entry)   UNSEALED
#   host    dual-sign the UKI: sbsign with K2 APPENDS a 2nd PE signature
#           (empirically verified: "Image was already signed; adding
#           additional signature"; sbverify --list shows both)
#   boot 2  dual-signed UKI (SAME measured sections), db still {K1}: the
#           firmware verifies via the OLD signature, the hook's
#           PolicyPCR({7,11}) still matches (the appended PE signature
#           table is not a measured section)                   UNSEALED
#   host    ONE vars edit (§9.6 step 4): db += K2 AND dbx += K1
#   boot 3  dual-signed UKI + revoked K1 (db += K2 AND dbx += K1): the
#           firmware REJECTS the image — dual-signing does NOT survive
#           revocation, OVMF refuses ANY image carrying a revoked
#           signature (§9.6 corrected empirically) — so the guest never
#           starts; assert the rejection sentinel + fail-closed negatives.
#   host    real `audit` (drift, exit 1) -> `audit --accept --yes`;
#           wipe the K1 enrollment; build UKI 6.4.0 fully under K2 and
#           RE-SEAL via the production CLI (keydir = K2): the combined
#           {7,11} entry is signed by K2 and the fresh token pins the K2
#           public key — the §9.6 corrective re-sign + re-enroll.
#   boot 4  K2-built UKI (K2 pcrsig + K2 rel.pub in the initrd + K2 PE sig;
#           K2 in db): the firmware boots it, the hook's I3 gate verifies
#           the K2-signed entry against the initrd's K2 rel.pub, and the
#           PolicyPCR({7,11}) session matches the K2-sealed token —
#           passwordless, the §9.6 corrective rotation proven end to end
#                                                               UNSEALED
#
# Wall time is the longest of the family (~4-5 boots).
#
# NB (G-T13): NO assert_pcr11_prediction on boot 3 — the guest never starts
# (the refusal is at firmware load). Every UNSEALED boot asserts the
# prediction on its own console's post-phase reading.

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
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13, §12)
# shellcheck disable=SC1091
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck disable=SC1091
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

RUN="$TESTS/e2e/.runs/s16-key-rotation-$(date +%s)"
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
# the restart and are re-measured by the firmware at the next boot. Post-boot
# PCR evidence therefore comes from the GUEST's console prints, not host reads.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }

# shellcheck disable=SC2120  # bare calls (plain audit) are intentional
_audit_cli() {
    _ensure_tpm || { echo "s16: swtpm not serving (audit)"; return 64; }
    ALPINE_FDE_ROOT="$RUN/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$RUN/rootfs/efivars-sb-on" \
        ALPINE_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
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
    printf '# alpine-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$relpub" "$st/rel.pub"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=alpine-fde-harness\nVERSION_ID=%s\nNAME=Alpine FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    # the enter-initrd PCR 11 prediction for THIS exact build (ukify --measure):
    # the finalized {7,11} re-seal composes over the MEASURED PCR 11 of the
    # UKI that will boot it.
    if ! ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
            --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
            --uname="$un" \
            --measure --phases enter-initrd --pcr-banks=sha256 \
            --pcr-private-key="$ppriv" >"$st.measure.txt" 2>&1; then
        echo "s16: ukify --measure (variant $un) failed:" >&2
        cat "$st.measure.txt" >&2
        return 1
    fi
    sed -n 's/^11:sha256=\([0-9a-f]\{64\}\)$/\1/p' "$st.measure.txt" | head -1 >"$out.pcr11.txt"
    [[ -s "$out.pcr11.txt" ]] || { echo "s16: no enter-initrd d11 prediction (variant $un)" >&2; return 1; }
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

# _reanchor_tpm <dir> — before EVERY guest boot the fixture TPM must be a
# FRESH, ZEROED instance (the s00b/s18/s22 hardening; defect s15-4). A live
# instance carrying the previous boot's final register values (or a stale
# volatilestate the next start would restore) hands the boot a CUMULATIVE
# PCR 0/7/11 whose provenance the scenario cannot vouch for — observed live
# 2026-09-23: consecutive same-UKI same-vars boots measured three different
# PCR 7 digests and the standing token's {7,11} policy refused its own
# enrollment. Zeroed-pre-boot is ASSERTED, not assumed: graceful stop ->
# scrub volatile state + stale sockets -> startup-clear start (the SRK in
# the permall persists, which the token's seal needs) -> PCR 0/7 must read
# all-zero -> settle the proxy/setup path with real commands (s18: a guest
# TPM command arriving mid-setup times out and the firmware DROPS the
# measurement).
_reanchor_tpm() {
    local dir="$1" d0 d7 k
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    swtpm_start "$dir" || { echo "s16: swtpm_start (re-anchor) failed"; return 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    d7=$(swtpm_pcrread "$dir" 7)
    if [[ ! "$d0" =~ ^0{64}$ || ! "$d7" =~ ^0{64}$ ]]; then
        echo "s16: TPM not zeroed before boot (pcr0=$d0 pcr7=$d7) — refusing to spend the boot on a cumulative register"
        return 1
    fi
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    return 0
}

# _wedge_wait <dir> <timeout-s> — the swtpm data-loop WEDGE guard (s02/s04
# mitigation, 2026-09-23; gdb poll-dump root cause: swtpm 0.10.2 de-registers
# the data client when a ctrl-channel client EOFs and never re-adds it — the
# data connection sits with Recv-Q > 0, absent from swtpm's poll set, and the
# guest stalls forever). Wedge signature, sampled every 5 s: qemu alive +
# console.log size unchanged for >60 s + Recv-Q > 0 on <dir>/tpm/sock.
# Recovery: qemu_kill + swtpm_stop + swtpm_start (fresh startup-clear), loud
# WEDGE-RECOVERED line, return 43 so the caller's bounded retry re-runs the
# boot; 44 = recovery restart failed; 0 = qemu exited on its own.
_wedge_wait() {
    local dir="$1" timeout="$2" pid
    pid=$(cat "$dir/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout)) sz last_sz last_chg
    last_sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
    last_chg=$SECONDS
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            pkill -9 -f "python3 - $dir/qmp.sock" 2>/dev/null
            serial_bridge_stop "$dir"
            return 0
        fi
        _qmp_kicker_start "$dir"
        sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
        if ((sz != last_sz)); then last_sz=$sz; last_chg=$SECONDS; fi
        if ((SECONDS - last_chg > 60)); then
            if ss -xn 2>/dev/null | awk -v s="$dir/tpm/sock" '$0 ~ s && ($3 + 0) > 0 { found = 1 } END { exit !found }'; then
                echo "WEDGE-RECOVERED: swtpm data-loop stall (console idle >60 s, Recv-Q>0 on $dir/tpm/sock) — killing qemu, restarting swtpm fresh"
                qemu_kill "$dir"
                swtpm_stop "$dir" >/dev/null 2>&1
                if ! swtpm_start "$dir" >/dev/null 2>&1; then
                    echo "WEDGE-RECOVERED: swtpm restart FAILED — caller must abort"
                    return 44
                fi
                return 43
            fi
        fi
        sleep 5
    done
    qemu_kill "$dir"
    return 124
}

boot_and_wait() {
    local label="$1" wrc=0
    _reanchor_tpm "$RUN/tpm" || { echo "s16: TPM re-anchor before boot $label failed"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5" || {
        echo "s16: qemu_run FAILED for $label (rc=$?)" >&2
        return 1; }
    _wedge_wait "$RUN" "$QEMU_TIMEOUT" || wrc=$?
    if ((wrc == 43)); then
        echo "s16: $label wedged mid-boot (swtpm data-loop stall) — swtpm restarted fresh; caller retries"
    fi
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }
console_pcr7() { grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2; }
console_pcr0() { grep -oE 'alpine-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2; }

# --- fixtures: K1 ceremony + fresh K2 ("offline medium") ------------------------
swtpm_start "$RUN/tpm" || { echo "s16: swtpm failed"; exit 1; }
keys_create "$RUN/keys"                                  # K1 (current release key)
uki_release_key_floor "$RUN/keys" || exit 1              # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
mkdir -p "$RUN/keys2"
# ADR-16 floor applies to ANY key the seal path signs with — K2 is generated
# at 3072 directly (the CLI's keys_rsa3072_guard refuses anything smaller).
openssl req -x509 -newkey rsa:3072 -keyout "$RUN/keys2/db.key" -out "$RUN/keys2/db.crt" \
    -days 30 -nodes -subj "/CN=alpine-fde-test-release-v2" 2>/dev/null
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
    "$(ALPINE_FDE_EFIVARS_DIR="$EFIVARS" fw_sb_state)" \
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
cp "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0-k1.efi.pcrsig.json"
cp "$RUN/pcr11-enter-initrd.txt" "$RUN/uki-6.2.0-k1.efi.pcr11.txt"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0-k1.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 3 + 12 )) "$RUN/uki-6.2.0-k1.efi" || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"

# --- boot 1: baseline (token-less) + enroll under K1 -----------------------------
_reanchor_tpm "$RUN/tpm" || { echo "s16: TPM re-anchor before the K1 baseline boot failed"; exit 1; }
echo "# boot k1-baseline (token-less disk -> hook recovery loop, TCG, up to $QEMU_TIMEOUT s) ..."
for _attempt in 1 2; do
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-k1-baseline.log"
    grep -q "$(sentinel_of harness_unsealed)" "$RUN/console-k1-baseline.log" && break
    echo "# baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_reset "$RUN/tpm" && swtpm_start "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
done
LOG=$(log_of "k1-baseline")
assert_contains "[K1] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[K1] hook recovery loop opened (no token on the fresh volume)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[K1] fed slot-0 passphrase unsealed via the recovery path" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[K1] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_pcr11_prediction "S-16 k1-baseline"
assert_rc "audit --init finalizes pre-rotation baseline" 0 _audit_cli --init
D7_PRE=$(console_pcr7 "k1-baseline")
assert_ne "boot 1 console records a non-zero PCR 7" "$D7_PRE" ""
# stamp the baseline's PCR 7/0 from boot-1 console evidence: the fixture swtpm's
# live state is not durable across qemu boots/restarts, so the baseline records
# the OPERATOR-meaningful pre-rotation values, not the restarted-TPM zeros
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$D7_PRE\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(console_pcr0 k1-baseline)\",|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline fixture carries the pre-rotation d7" "$D7_PRE" \
    "$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")"

# host-side finalized enrollment under K1 (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): the combined {7,11}
# entry is what the hook extracts for the finalized token.
D11_K1=$(cat "$RUN/uki-6.2.0-k1.efi.pcr11.txt" 2>/dev/null)
[[ -n "$D11_K1" ]] || { echo "s16: no enter-initrd d11 prediction from the K1 build"; exit 1; }
swtpm_ensure "$RUN/tpm" || { echo "s16: swtpm restart (enroll) failed"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0-k1-combined.json" \
    "$D7_PRE" "$D11_K1" "$RUN/keys" || exit 1
uki_pcrsig_disk "$RUN/pcrsig-k1.img" "$RUN/uki-6.2.0-k1-combined.json" || exit 1
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.2.0-k1-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s16: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

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
# The dual-sign APPENDS a PE signature table — the stub's MEASURED sections
# (.linux/.initrd/.cmdline) are untouched, so the hook's PolicyPCR({7,11})
# still matches the K1-sealed policy.
boot_and_wait "dual-prerevoke" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/pcrsig-k1.img"
LOG=$(log_of "dual-prerevoke")
assert_pcr11_prediction "S-16 dual-prerevoke"
assert_contains "[dual] init ran (firmware verified via the OLD signature)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[dual] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[dual] standing {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[dual] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[dual] UNSEALED via the TPM token (PCR 7 unchanged pre-db-change)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[dual] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_eq "PCR 7 unchanged after the dual-sign reboot (console evidence)" "$D7_PRE" "$(console_pcr7 "dual-prerevoke")"

# --- §9.6 step 4: db += K2 AND dbx += K1 in ONE vars edit -------------------------
cp "$RUN/vars-enrolled.fd" "$RUN/vars-rotated.fd"
assert_rc "virt-fw-vars: db += K2, dbx += K1 (one step)" 0 \
    virt-fw-vars -i "$RUN/vars-rotated.fd" -o "$RUN/vars-rotated.fd" \
        --add-db "$ALPINE_FDE_TEST_GUID" "$RUN/keys2/db.crt" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$RUN/keys/db.crt"
VARSDBG=$(virt-fw-vars -i "$RUN/vars-rotated.fd" -p 2>/dev/null | grep -cE '^(db|dbx)[[:space:]]*:')
assert_eq "rotated vars carry db and dbx blobs" "2" "$VARSDBG"

# --- §9.6 step 5: reboot into the rotated policy — firmware must REJECT ----------
# Pinned outcome (§9.6 corrected empirically): dual-signing does NOT survive
# revocation — OVMF refuses ANY image carrying a revoked signature, so the
# guest never starts. The firmware falls through to the boot-manager menu
# and cannot power the machine off; killing qemu once the rejection sentinel
# is on the console is the expected termination (s04 refusal shape).
echo "# booting dual-signed UKI with db={K1,K2} dbx={K1} — firmware must reject (revoked signature)"
_reanchor_tpm "$RUN/tpm" || { echo "s16: TPM re-anchor before the post-revoke boot failed"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-rotated.fd" "$RUN/tpm" "$RUN/pcrsig-k1.img"
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
assert_not_contains "[rot] never unlocked" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[rot] interactive prompt never appeared" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
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

# re-seal under K2: the combined {7,11} entry signed by K2 over the ROTATED
# live d7 (the one the K2 UKI's own boots actually measure) and the K2 UKI's
# enter-initrd d11; the fresh token pins the K2 public key.
D11_K2=$(cat "$RUN/uki-6.4.0-k2.efi.pcr11.txt" 2>/dev/null)
[[ -n "$D11_K2" ]] || { echo "s16: no enter-initrd d11 prediction from the K2 build"; exit 1; }

# --- §9.6 step 6 (corrected 2026-09-23): boot the K2 UKI ONCE via the hook's
# recovery path BEFORE the re-seal, and compose the entry over the registers
# THAT boot lands --------------------------------------------------------------
# The CLI's G-B6 gate (seal_verify_pcrsig) requires the combined entry's
# signed pol == policy_digest(LIVE d7, LIVE d11) at enroll time, and the
# final passwordless boot requires the same pair at boot time. The K2 UKI's
# enter-initrd prediction (D11_K2) is what its own boots land PCR 11 on, and
# the ROTATED vars (db += K2, dbx += K1) measure a DIFFERENT PCR 7 than the
# pre-rotation db — so the only trustworthy source for the (d7, d11) pair is
# a real, re-anchored boot of the K2 UKI itself. With the K1 enrollment
# wiped, that first boot goes through the hook's bounded keyslot-0 recovery
# path (the §9.6 operator flow: boot the new kernel once with the recovery
# passphrase, then re-seal). (Registry 2026-09-23: without this boot the G-B6
# gate died "signed ca2593… != freshly computed 1888fa… over the live PCRs" —
# the live d11 was still the 6.2.0 dual-sign boot's value, never the K2
# prediction; and a pre-boot residual register read composed the entry over
# a d7 the K2 boots never measure.)
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.4.0-k2.efi" || exit 1
echo "# boot k2-recovery: K2 UKI, wiped enrollment -> hook recovery path (TCG, up to $QEMU_TIMEOUT s) ..."
K2REC_OK=0
for _att in 1 2; do
    _reanchor_tpm "$RUN/tpm" || { echo "s16: TPM re-anchor before the K2 recovery boot failed"; exit 1; }
    # payload drive content is irrelevant here: the enrollment is wiped, so
    # the hook skips the token path whatever the drive carries — the K1
    # ladder drive stands in until the K2 combined entry exists
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-rotated.fd" "$RUN/tpm" "$RUN/pcrsig-k1.img" || {
        echo "s16: qemu_run FAILED for k2-recovery (rc=$?)" >&2
        exit 1; }
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    _wedge_wait "$RUN" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
    grep -q "alpine-fde: UNSEALED" "$CONSOLE" && { K2REC_OK=1; break; }
    echo "# k2-recovery attempt $_att did not reach UNSEALED (infra anomaly) — retrying"
done
if ((K2REC_OK == 1)); then
    _assert_result ok "[k2rec] K2 UKI booted via the hook recovery path (enrollment wiped)" ""
else
    _assert_result not-ok "[k2rec] K2 UKI booted via the hook recovery path" \
        "no UNSEALED sentinel in 2 attempts; tail: $(tail -3 "$CONSOLE" 2>/dev/null | tr '\n' ' ')"
    exit 1
fi
LOG=$(cat "$RUN/console.log" 2>/dev/null || true)
assert_contains "[k2rec] hook ran the enter-initrd extend (K2 UKI's measured phase)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[k2rec] no token found (freshly wiped enrollment)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[k2rec] unlocked via the recovery passphrase" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
cp "$RUN/uki-6.4.0-k2.efi.pcrsig.json" "$RUN/uki-pcrsig.json"
CONSOLE_SAVE16="$CONSOLE"
CONSOLE="$RUN/console.log"
assert_pcr11_prediction "S-16 k2-recovery"
CONSOLE="$CONSOLE_SAVE16"
cp "$CONSOLE" "$RUN/console-k2-recovery.log"

# the re-anchored recovery boot LANDED the rotated measurement: the combined
# entry is composed over the BOOT'S OWN CONSOLE digest (digest-anchored, the
# 2026-09-24 s00b lesson) — NOT a fixture live read.
# WHY (live-verified regression): the simplified fixture is zero-on-restart
# (the swtpm dies at every clean qemu exit; every start is a startup-clear),
# so seeding a digest onto a zeroed PCR yields EXTEND-FROM-ZERO,
#     PCR' = sha256(0^32 || digest)  !=  digest,
# and a live read after swtpm_seed_pcrs is that artifact, never the booted
# value. The registry run composed the K2 seal over the artifact
# (b0e844c9… = extend-from-zero of the true d7 84222bbe…), re-stamped the
# baseline with it, and the real K2 boot's PolicyPCR then refused its own
# token (6 assertions red). The live reads below therefore serve only as the
# fixture WINDOW check: they must equal the independently computed
# extend-from-zero of the seeded digests (proves the register is a faithful
# reseed, not cumulative and not a wrong instance).
# _zero_extend <digest> — the post-reseed register value for <digest>.
_zero_extend() {
    printf '%064d%s' 0 "$1" | tr -d ' \n' | xxd -r -p | sha256sum | awk '{print $1}'
}
# _pcrread_live <dir> <index> — bare lowercase hex of a live PCR read, parsed
# tolerantly: tpm2_pcrread aligns single-digit PCRs as " 7 : 0x…" but
# two-digit ones as "11: 0x…" (no space), and the fixture's swtpm_pcrread
# awk only matches the single-digit shape (parse gap reported to the fixture
# owners). This parser accepts both alignments.
_pcrread_live() {
    timeout 10 tpm2_pcrread -T "swtpm:path=$1/sock" "sha256:$2" 2>/dev/null \
        | sed -n "s/^ *$2 *: *0x\([0-9a-fA-F]*\)$/\1/p" | head -1 | tr 'A-F' 'a-f'
}
D7_ROT=$(console_pcr7 "k2-recovery")
[[ -n "$D7_ROT" ]] || { echo "s16: k2-recovery console has no PCR 7 print — nothing to compose over"; exit 1; }
swtpm_stop "$RUN/tpm" 2>/dev/null || true
swtpm_start "$RUN/tpm" || { echo "s16: swtpm restart (K2 enroll) failed"; exit 1; }
# the recycle left ZEROED PCRs — reseed the recovery boot's landed registers
# (console d7 + the K2 prediction) so the fixture register is the booted
# state's designated reseed (the seal itself needs only the running swtpm;
# the digest-anchored G-B6 gate reads no live PCRs).
swtpm_seed_pcrs "$RUN/tpm" "$D7_ROT" "$D11_K2" || {
    echo "s16: swtpm_seed_pcrs (K2 enroll) failed"; exit 1; }
D7_SEED=''; D11_SEED=''
for _k in 1 2 3; do
    [[ -z "$D7_SEED" ]] && D7_SEED=$(_pcrread_live "$RUN/tpm" 7)
    [[ -z "$D11_SEED" ]] && D11_SEED=$(_pcrread_live "$RUN/tpm" 11)
    [[ -n "$D7_SEED" && -n "$D11_SEED" ]] && break
    sleep 2
done
[[ -n "$D7_SEED" && -n "$D11_SEED" ]] || {
    echo "s16: live PCR reads after the K2 recovery boot returned empty (d7=$D7_SEED d11=$D11_SEED)"
    echo "s16: read diagnostics: tpmdir=[$(ls "$RUN/tpm" 2>/dev/null | tr '\n' ' ')]"
    echo "s16: raw read7: [$(timeout 10 tpm2_pcrread -T "swtpm:path=$RUN/tpm/sock" sha256:7 2>&1 | head -4 | tr '\n' '|')]"
    echo "s16: raw read11: [$(timeout 10 tpm2_pcrread -T "swtpm:path=$RUN/tpm/sock" sha256:11 2>&1 | head -4 | tr '\n' '|')]"
    exit 1; }

assert_eq "K2 re-seal precondition: seeded live d7 == extend-from-zero(recovery console d7) (zero-on-restart fixture contract)" \
    "$(_zero_extend "$D7_ROT")" "$D7_SEED"
assert_eq "K2 re-seal precondition: seeded live d11 == extend-from-zero(the K2 enter-initrd prediction)" \
    "$(_zero_extend "$D11_K2")" "$D11_SEED"
assert_ne "the rotated vars moved PCR 7 off the pre-rotation value" "$D7_PRE" "$D7_ROT"
# the recovery boot IS the post-rotation measurement: re-stamp the rootfs
# baseline onto ITS OWN console digest (the audit --accept above re-baselined
# onto a PRE-recovery residual register, which no K2 boot ever measures —
# enroll-tpm's precondition 4 would die "PCR 7 drift" against it otherwise;
# same recalibration s00b applies). The b64 pcr0 term is not pinned by the
# CLI, only expected_pcr7 is consulted at enroll.
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$D7_ROT\",|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
uki_pcrsig_append_combined "$RUN/uki-6.4.0-k2.efi.pcrsig.json" "$RUN/uki-6.4.0-k2-combined.json" \
    "$D7_ROT" "$D11_K2" "$RUN/keys2" || exit 1
uki_pcrsig_disk "$RUN/pcrsig-k2.img" "$RUN/uki-6.4.0-k2-combined.json" || exit 1
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.4.0-k2-combined.json" \
    "$RUN/disk.img" "$RUN/keys2" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s16: K2 production enroll-tpm FAILED"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "K2 re-seal: exactly ONE standing systemd-tpm2 token" "1" "$NTOK"
# the token's tpm2-pubkey is the b64 DER SubjectPublicKeyInfo of release.pub
# (lib/token.sh schema pin) — compare DER-to-DER, never against the PEM text
TOKENPUB=$(disk_token_json "$RUN/disk.img" | jq -r '.[] | select(.type == "systemd-tpm2") | .["tpm2-pubkey"]' | base64 -d | sha256sum | awk '{print $1}')
assert_eq "token now pins the K2 public key" \
    "$TOKENPUB" \
    "$(openssl pkey -pubin -in "$RUN/keys2/release.pub" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.4.0-k2.efi" || exit 1

# --- §9.6 step 6-7: boot + verify passwordless under the new key ------------------
boot_and_wait "k2-re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-rotated.fd" "$RUN/pcrsig-k2.img"
LOG=$(log_of "k2-re-enroll")
cp "$RUN/uki-6.4.0-k2.efi.pcrsig.json" "$RUN/uki-pcrsig.json"   # prediction of the BOOTED (K2) UKI
assert_pcr11_prediction "S-16 k2-re-enroll"
assert_contains "[K2] init ran (firmware verifies via K2 in db)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[K2] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[K2] re-sealed {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[K2] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[K2] unlocked via the TPM token (rotation complete)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[K2] UNSEALED (rotation complete)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_ne "PCR 7 is on the rotated value (console evidence, post-rotation)" "$D7_PRE" "$(console_pcr7 "k2-re-enroll")"
assert_eq "the booted PCR 7 IS the value the K2 seal was composed over (no fixture drift confound)" \
    "$D7_ROT" "$(console_pcr7 "k2-re-enroll")"

rm -rf "$RUN/guest-tree" "$RUN/stage-6.4.0-k2"
echo "# DUAL-SIGN: sbsign append VERIFIED (2 signatures, both verify); the appended PE"
echo "# signature table is NOT a measured section — the hook's {7,11} unlock still"
echo "# matches after the dual-sign reboot."
echo "# DBX-REVOKE x DUAL-SIGNED UKI: OVMF REJECTS images carrying a revoked"
echo "# signature (§9.6 step 5 corrected: the corrective re-sign is mandatory,"
echo "# also for the boot manager) — pinned here; the K2-only re-signed + re-sealed"
echo "# boot then completes the rotation passwordless (boot 4 above)."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s16-key-rotation: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s16-key-rotation: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
