#!/usr/bin/env bash
# tests/e2e/s14-kernel-update.sh — §9.2 kernel update + the H-G7 question (Wave 3),
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock).
#
# H-G7 asked: does the unlock gate token acceptance on the token's stored digest
# list — i.e. does a NEW kernel's .pcrsig boot WITHOUT re-enrollment, or must
# the postinst hook's conditional re-enroll fire?
#
# VERDICT UNDER THE FINALIZED MECHANISM B CONTRACT (ADR-20, {7,11}): the
# hook's PolicyPCR({7,11}) session is bound to the ENROLL-time measured
# PCR 11 (== the release UKI's ukify --measure enter-initrd prediction), so
# a NEW kernel's UKI (different .initrd marker + .osrel + .uname -> different
# PCR 11 section chain) can NEVER match the standing token's sealed policy
# with zero TPM operations — the boot refuses fail-closed at the hook
# (unseal_seal_refused) and the §8.2 bounded recovery loop is the way in.
# The §8.3 production answer is the re-seal: `enroll-tpm` RETIRES the stale
# enrollment and stands the fresh seal in the same run (the {7,11} policy is
# re-composed over the UNCHANGED static PCR 7 and the NEW UKI's signed
# prediction — no volume-key re-encryption). This scenario pins BOTH halves
# end to end:
#
# Sequence (boot-by-boot):
#   boot 1  baseline (token-less disk): the hook's bounded recovery loop is
#           the only way in; the slot-0 passphrase is fed through the hook's
#           OWN prompt -> UNSEALED. Host-side: the REAL production CLI
#           enrolls the finalized {7,11} token under UKI 6.2.0 (state = s00).
#   host    build UKI 6.4.0 (new .pcrsig: different .initrd marker + .osrel +
#           .uname -> different PCR 11 section chain -> different signed
#           pols), install it as the boot default, touch NOTHING in the
#           TPM/LUKS2 world.
#   boot 2  the 6.4.0 boot: the hook discovers the standing {7,11} token,
#           the I3 signature gate PASSES (release-signed combined entry on
#           the payload drive), but the PolicyPCR({7,11}) session digest no
#           longer matches the sealed policy (PCR 11 moved) -> refusal ->
#           bounded loop (3 fed WRONG answers) -> 3-strike fail-closed
#           `poweroff -f`. NEVER an emergency shell. (The §10 "kernel
#           re-signed, its enrollment missing/stale" row, pinned.)
#   host    wipe-free re-seal: `enroll-tpm` RETIRES the stale enrollment in
#           the same run the fresh seal stands (cli_enroll_retire); the
#           combined .pcrsig entry is re-signed over the SAME d7 and the
#           6.4.0 d11; the volume key is never re-encrypted.
#   boot 3  the re-sealed 6.4.0 boot: zero-input token unlock -> UNSEALED.
#
# Plus the §10 row "kernel update build failed" (kept verbatim from the
# 2026-09-18 leg): the rebuild WITHOUT the release signing key fails LOUDLY,
# ships NOTHING, leaves the previous UKI as the ESP default — the machine
# keeps booting + auto-unlocking (asserted via the old default's hook
# unlock).
#
# Alpine contract (260.2 sentinel fixture): the kernel-update delivery path is
# the apk trigger + /etc/kernel-hooks.d convention (§8.3, ADR-19/ADR-13) — the
# update boots carry the alpine-fde tooling payload on their pcrsig drive
# tail (inert for the hook: /init reads only the first 64 KiB) and the
# scenario asserts the contract markers: the kernel hook + apk trigger ship
# in the payload and both invoke `alpine-fde ukictl build`. Every
# UKI-reaching UNSEALED boot additionally asserts ukify's enter-initrd PCR 11
# prediction against the guest's post-phase reading (G-T13, §12).

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

RUN="$TESTS/e2e/.runs/s14-kernel-update-$(date +%s)"
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
# The SRK (storage primary seed) persists in tpm2-00.permall, so seals made by
# a previous boot still unseal after the restart (s01 precedent); PCRs reset
# and are re-measured by the firmware at the next boot — physically faithful.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
# DEFECT s15-4 RESIDUAL (live-verified 2026-09-23, s14 boot 2): with the
# SHUTDOWN-intercepting proxy the swtpm SURVIVES qemu's clean exit, so
# swtpm_ensure returns 0 WITHOUT a restart — and the proxy's boot-exit
# CMD_STORE_VOLATILE has left tpm2-00.volatilestate on disk. A qemu boot that
# CMD_INITs against that file is CUMULATIVE (Startup-CLEAR defeated: the next
# boot extends OVER the previous boot's final values), so the firmware's PCR 7
# reading drifted on every boot after the first and the standing {7,11} seal
# refused on boots that must zero-input unlock. swtpm_start removes the file
# after consuming it, but the no-restart swtpm_ensure path never does — the
# scenario owns its boot cadence, so drop the stale file here: the live
# instance keeps the values in RAM (the host-side enroll window is unaffected;
# only a real crash-restart's durability is traded away), and every BOOT again
# starts from zeroed PCRs — the documented per-boot semantics.
_ensure_tpm() { swtpm_ensure "$RUN/tpm" && rm -f "$RUN/tpm/tpm2-00.volatilestate"; }

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
    printf '# alpine-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$kd/release.pub" "$st/rel.pub"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=alpine-fde-harness\nVERSION_ID=%s\nNAME=Alpine FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    # the enter-initrd PCR 11 prediction for THIS exact build (ukify --measure,
    # the same inputs the .pcrsig pol entries derive from) — consumed by the
    # re-seal composition (uki_pcrsig_append_combined): the finalized {7,11}
    # policy is bound to the MEASURED PCR 11 of the UKI that will boot it.
    if ! ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
            --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
            --uname="$un" \
            --measure --phases enter-initrd --pcr-banks=sha256 \
            --pcr-private-key="$kd/db.key" >"$st.measure.txt" 2>&1; then
        echo "s14: ukify --measure (variant $un) failed:" >&2
        cat "$st.measure.txt" >&2
        return 1
    fi
    sed -n 's/^11:sha256=\([0-9a-f]\{64\}\)$/\1/p' "$st.measure.txt" | head -1 >"$out.pcr11.txt"
    [[ -s "$out.pcr11.txt" ]] || { echo "s14: no enter-initrd d11 prediction (variant $un)" >&2; return 1; }
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

# QEMU-LIVENESS (the 2026-09-23 registry stall: s14 hung 12 min at an unfed
# prompt and nothing noticed the VM state). uki_wait_hook_prompt already
# checks the boot's qemu pid on EVERY iteration (QEMU-DIED + console tail,
# tests/lib/uki-build.sh); these helpers extend the same discipline to the
# scenario's post-wait branches: once a wait gave up, a dead qemu means the
# awaited prompt can NEVER appear — say so loudly and immediately instead of
# feeding a dead serial socket and burning qemu_wait's budget blind.
_qemu_alive() { # <run-dir> — 0 while the boot's qemu is still running
    local qpid
    qpid=$(cat "$1/qemu.pid" 2>/dev/null || true)
    [[ -n "$qpid" ]] && kill -0 "$qpid" 2>/dev/null
}
_qemu_died() { # <label> — loud QEMU-DIED + console tail
    echo "QEMU-DIED [$1]: qemu (pid $(cat "$RUN/qemu.pid" 2>/dev/null || echo '<none>')) is gone" >&2
    echo "QEMU-DIED console tail: $(tail -8 "$CONSOLE" 2>/dev/null | tr '\n' ' ')" >&2
}

# --- fixtures ------------------------------------------------------------------
# Diagnosability: keep the swtpm command trace on disk for EVERY boot
# (<run>/tpm/tpm-cmd.log, --log level=20). A blind failure — no TPM-side
# evidence — cost a full registry leg once (2026-09-23); the trace is cheap.
export SWTPM_FIXTURE_VERBOSE=1
swtpm_start "$RUN/tpm" || { echo "s14: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 (running kernel) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s14: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0.efi.pcrsig.json"
cp "$RUN/pcr11-enter-initrd.txt" "$RUN/uki-6.2.0.efi.pcr11.txt"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" alpine-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- §8.3 Alpine kernel-update delivery contract (apk trigger + kernel-hooks.d) --
# The update boots carry the alpine-fde tooling payload on their pcrsig drive
# tail; the scenario asserts the payload ships the kernel hook + apk trigger
# and both carry the `alpine-fde ukictl build` marker (§8.3, ADR-19/ADR-13).
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/alpine-fde"
for d in bin lib hooks; do
    cp -r "$REPO/$d" "$TOOLING/opt/alpine-fde/$d" || exit 1
done
tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt || { echo "s14: tooling tar failed"; exit 1; }
TOOLING_LISTING="$RUN/tooling.listing"
tar -tzf "$RUN/tooling.tar.gz" >"$TOOLING_LISTING"
if grep -qx "opt/alpine-fde/hooks/kernel-hooks.d/alpine-fde-build.hook" "$TOOLING_LISTING" \
    && grep -qx "opt/alpine-fde/hooks/apk/triggers/alpine-fde.trigger" "$TOOLING_LISTING" \
    && grep -qx "opt/alpine-fde/hooks/mkinitfs/alpine-fde-unseal.sh" "$TOOLING_LISTING" \
    && grep -qx "opt/alpine-fde/hooks/mkinitfs/features.d/alpine-fde.files" "$TOOLING_LISTING" \
    && grep -qx "opt/alpine-fde/bin/alpine-fde" "$TOOLING_LISTING"; then
    _assert_result ok "S-14 payload: kernel hook + apk trigger + mkinitfs hook/features.d ship in the tooling payload" ""
else
    _assert_result not-ok "S-14 payload: kernel hook + apk trigger + mkinitfs hook/features.d ship in the tooling payload" \
        "required entries missing from $TOOLING_LISTING"
fi
assert_contains "S-14 contract: the kernel hook invokes alpine-fde ukictl build (§8.3 marker)" \
    "$(cat "$TOOLING/opt/alpine-fde/hooks/kernel-hooks.d/alpine-fde-build.hook")" "ukictl build"
assert_contains "S-14 contract: the apk trigger invokes alpine-fde ukictl build (§8.3 marker)" \
    "$(cat "$TOOLING/opt/alpine-fde/hooks/apk/triggers/alpine-fde.trigger")" "ukictl build"
assert_contains "S-14 contract: the apk trigger watches the kernel module tree" \
    "$(cat "$TOOLING/opt/alpine-fde/hooks/apk/triggers/alpine-fde.trigger")" "/lib/modules"
assert_contains "S-14 contract: features.d lists the bcache driver (§4.1 hybrid pieces)" \
    "$(cat "$TOOLING/opt/alpine-fde/hooks/mkinitfs/features.d/alpine-fde.files")" "bcache.ko"

# efivars seam for the enroll-tpm I5 guard (mkvar pattern from
# tests/unit/baseline_finalize_guard.sh)
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0

# --- boot 1: baseline (token-less) + enroll under UKI 6.2.0 ----------------------
# The token-less disk puts the hook's BOUNDED recovery loop in control; the
# feed is prompt-synchronized (the hook has NO read timeout). This is the
# §12 first-boot passphrase way in; the finalized {7,11} enrollment then
# happens HOST-side via the REAL production CLI against the fixture swtpm.
_ensure_tpm || { echo "s14: swtpm not serving (boot 1)"; exit 1; }
echo "# boot v1-baseline (token-less disk -> hook recovery loop, TCG, up to $QEMU_TIMEOUT s) ..."
for _attempt in 1 2; do
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    elif ! _qemu_alive "$RUN"; then
        _qemu_died "v1-baseline"   # the prompt can never appear; qemu_wait reaps immediately
    fi
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-v1-baseline.log"
    grep -q "$(sentinel_of harness_unsealed)" "$RUN/console-v1-baseline.log" && break
    echo "# baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_reset "$RUN/tpm" && swtpm_start "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
done
LOG=$(log_of "v1-baseline")
assert_contains "[6.2.0] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[6.2.0] hook recovery loop opened (no token on the fresh volume)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[6.2.0] fed slot-0 passphrase unsealed via the recovery path" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[6.2.0] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_pcr11_prediction "S-14 v1-baseline"

# host-side finalized enrollment (the production CLI; the fixture is reseeded
# to the booted registers after the between-boots restart): d7 = the booted console's
# PCR 7, d11 = the 6.2.0 build's enter-initrd prediction; the combined {7,11}
# entry is what the hook extracts for the finalized token.
D11_62=$(cat "$RUN/uki-6.2.0.efi.pcr11.txt" 2>/dev/null)
[[ -n "$D11_62" ]] || { echo "s14: no enter-initrd d11 prediction from the 6.2.0 build"; exit 1; }
swtpm_ensure "$RUN/tpm" || { echo "s14: swtpm restart (enroll) failed"; exit 1; }
PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-v1-baseline.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_ENROLLED" ]] || { echo "s14: no PCR 7 in the baseline console"; exit 1; }
# digest-anchored enroll (Option A): no reseeding and no live-read assertion —
# the CLI compares the entry's recorded d7/d11 against the baseline (pure
# data, no live TPM read); the fixture only needs to be SERVING for the seal.
# the finalized baseline the enroll preconditions read (sp_etc_dir shape,
# s00 template): expected_pcr7 stamped from the booted console — the
# OPERATOR-meaningful value (== the anchor the CLI's digest comparison
# checks the entry's d7 against)
mkdir -p "$RUN/rootfs/etc/alpine-fde"
cat >"$RUN/rootfs/etc/alpine-fde/baseline.json" <<EOF
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcr0": "pending",
  "pcr1": "pending",
  "pcr2": "pending",
  "pcr3": "pending",
  "expected_pcr7": "$PCR7_ENROLLED",
  "sb_state": {
    "secure_boot": "1",
    "setup_mode": "0",
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
EOF
uki_pcrsig_append_combined "$RUN/uki-6.2.0.efi.pcrsig.json" "$RUN/uki-6.2.0-combined.json" \
    "$PCR7_ENROLLED" "$D11_62" "$RUN/keys" || exit 1
assert_eq "combined .pcrsig entry pol == policy_digest(booted d7, 6.2.0 enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$PCR7_ENROLLED" "$D11_62")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.2.0-combined.json")"
# the payload drive of the 6.2.0 boots carries the combined entry
uki_pcrsig_disk "$RUN/pcrsig-62.img" "$RUN/uki-6.2.0-combined.json" || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.2.0-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s14: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
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
    "$ASSERT_RC_OUTPUT" "ukify --measure (variant 6.3.0-broken) failed"
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
# The ESP default is still the 6.2.0 UKI bytes the enrollment measured, and the
# payload drive carries the combined {7,11} entry -> the hook's zero-input
# token path unlocks (§12 S-01 shape, no recovery prompt).
boot_and_wait "old-default" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/pcrsig-62.img"
LOG=$(log_of "old-default")
assert_pcr11_prediction "S-14 old-default"
assert_contains "[old] init ran (failed update did not strand the machine)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[old] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[old] standing {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[old] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[old] old default UKI still AUTO-UNLOCKS (hook token path)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[old] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "[old] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[old] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"
_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-old.json"
assert_rc "the failed-rebuild recovery boot performed NO enrollment (LUKS2 metadata byte-identical)" 0 \
    cmp -s "$RUN/meta-post-v1.json" "$RUN/meta-post-old.json"

# --- kernel update: build 6.4.0 + install, ZERO TPM operations ------------------
echo "# building UKI 6.4.0 (kernel update; NO enrollment will be performed) ..."
_vuki_build "$RUN/stage-6.4.0" "$RUN/guest-tree" "$RUN/keys" 6.4.0 v640 "$RUN/uki-6.4.0.efi" || {
    echo "s14: variant build failed"; exit 1; }
assert_rc "uki 6.4.0: sbverify clean" 0 sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.4.0.efi"
POLS64=$(jq -r '.sha256[].pol' "$RUN/uki-6.4.0.efi.pcrsig.json" | sort)
POLS62=$(jq -r '.sha256[].pol' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
assert_ne "new kernel -> new signed pols (distinct PCR 11 prediction)" "$POLS62" "$POLS64"
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.4.0.efi" alpine-fde-6.4.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.4.0.efi" || exit 1
ESPLS=$(mdir -i "$RUN/esp.img" ::/EFI/BOOT ::/EFI/Linux 2>/dev/null)
assert_contains "ESP retains 6.2.0 (old kernel kept for rollback)" "$ESPLS" "alpine-fde-6.2.0.efi"
assert_contains "ESP has 6.4.0 as new default" "$ESPLS" "alpine-fde-6.4.0.efi"
# the 6.4.0 boots' payload drive pairs the STANDING combined entry with the
# §8.3 tooling tail (inert for the hook: /init reads only the first 64 KiB)
cat "$RUN/pcrsig-62.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-tooling.img"

# --- boot 3: the 6.4.0 boot — the standing enrollment is STALE -------------------
# The hook discovers the {7,11} token and the I3 gate passes (the combined
# entry on the drive is release-signed), but the PolicyPCR({7,11}) session
# digest no longer matches the sealed policy: the new kernel moved the
# measured PCR 11 (the static PCR 7 term still matches). Refusal ->
# the hook's bounded loop (3 fed WRONG answers) -> 3-strike fail-closed.
# ONE boot: the feed is prompt-synchronized (the hook has NO read timeout).
echo "# boot v2-stale: new kernel, STALE standing enrollment (TCG, up to $QEMU_TIMEOUT s)"
_ensure_tpm || { echo "s14: swtpm not serving (v2-stale)"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig-tooling.img"
for n in 1 2 3; do
    if uki_wait_hook_prompt "$n" 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "alpine-fde-stale-wrong-passphrase-$n"
    else
        if ! _qemu_alive "$RUN"; then _qemu_died "v2-stale (awaiting prompt $n/3)"; fi
        _assert_result not-ok "[6.4.0-stale] hook awaiting recovery passphrase $n/3" \
            "no prompt $n in console (qemu $(if _qemu_alive "$RUN"; then echo alive; else echo DEAD; fi))"
        break
    fi
done
qemu_wait "$RUN" "$QEMU_TIMEOUT"
cp "$CONSOLE" "$RUN/console-v2-stale.log"
LOG=$(log_of "v2-stale")
assert_contains "[6.4.0-stale] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[6.4.0-stale] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[6.4.0-stale] standing {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[6.4.0-stale] I3 gate passed (the signature is NOT the defect)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "[6.4.0-stale] hook refused the STALE sealed policy (PCR 11 moved)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$RUN/console-v2-stale.log" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console-v2-stale.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "[6.4.0-stale] hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "[6.4.0-stale] hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
# feed the hook's bounded loop (NO read timeout: prompt-synchronized)
PROMPTS_STALE=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[6.4.0-stale] exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS_STALE"
assert_contains "[6.4.0-stale] 3-strike give-up (§8.2 fail-closed)" "$LOG" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[6.4.0-stale] fail-closed poweroff (no shell is offered)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[6.4.0-stale] never unlocked (token)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[6.4.0-stale] never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[6.4.0-stale] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "[6.4.0-stale] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# tamper scoping: the refusal is the PCR 11 movement, not a firmware drift —
# PCR 7 is unchanged, PCR 11 moved
PCR7_B1=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-v1-baseline.log" | head -1 | cut -d= -f2)
PCR7_STALE=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-v2-stale.log" | head -1 | cut -d= -f2)
PCR11_B1=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$RUN/console-v1-baseline.log" | head -1 | cut -d= -f2)
PCR11_STALE=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$RUN/console-v2-stale.log" | head -1 | cut -d= -f2)
assert_eq "[6.4.0-stale] PCR 7 unchanged (the static seal term still matches)" "$PCR7_B1" "$PCR7_STALE"
assert_ne "[6.4.0-stale] PCR 11 MOVED (the new kernel's stub measurement — the refusal's cause)" \
    "$PCR11_B1" "$PCR11_STALE"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[6.4.0-stale] guest exited (hook poweroff -f, not timeout-kill)" ""
else
    _assert_result not-ok "[6.4.0-stale] guest exited (hook poweroff -f, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# --- §9.2 recovery: the re-seal — enroll-tpm retires the stale enrollment -------
# The combined entry is re-signed over the SAME d7 and the 6.4.0 d11; the
# volume key is never re-encrypted (a fresh random passphrase seals a NEW
# keyslot; the stale token + its keyslot are retired in the same run).
echo "# re-sealing: enroll-tpm retires the stale enrollment and stands the fresh seal"
D11_64=$(cat "$RUN/uki-6.4.0.efi.pcr11.txt" 2>/dev/null)
[[ -n "$D11_64" ]] || { echo "s14: no enter-initrd d11 prediction from the 6.4.0 build"; exit 1; }
swtpm_ensure "$RUN/tpm" || { echo "s14: swtpm restart (re-seal) failed"; exit 1; }
# digest-anchored re-seal (Option A): no reseeding — the CLI compares the
# re-signed entry's recorded d7/d11 against the baseline (pure data); the
# kernel update is PCR-7-neutral BY CONSTRUCTION (d7 = the unchanged enrolled
# value, re-stamped into the entry).
uki_pcrsig_append_combined "$RUN/uki-6.4.0.efi.pcrsig.json" "$RUN/uki-6.4.0-combined.json" \
    "$PCR7_ENROLLED" "$D11_64" "$RUN/keys" || exit 1
assert_eq "re-sealed combined entry pol == policy_digest(same d7, 6.4.0 enter-initrd d11)" \
    "$(policy_digest "$PCR7_ENROLLED" "$D11_64")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.4.0-combined.json")"
# the re-sealed boot's payload drive carries the NEW combined entry + tooling tail
uki_pcrsig_disk "$RUN/pcrsig-64.img" "$RUN/uki-6.4.0-combined.json" || exit 1
cat "$RUN/pcrsig-64.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig64-tooling.img"
RETIRE_LOG=$(mktemp)
if ALPINE_FDE_ROOT="$RUN/rootfs" \
    ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
    ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
    ALPINE_FDE_KEYDIR="$RUN/keys" \
    ALPINE_FDE_LUKS_KEYFILE="$RUN/kf-slot0" \
    ALPINE_FDE_NO_INSTALL=1 \
    "$REPO/bin/alpine-fde" enroll-tpm --uuid "$RUN/disk.img" --pcrsig "$RUN/uki-6.4.0-combined.json" \
    >"$RETIRE_LOG" 2>&1; then
    _assert_result ok "re-seal: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" ""
else
    _assert_result not-ok "re-seal: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" \
        "output: $(tail -3 "$RETIRE_LOG" | tr '\n' ' ')"
fi
assert_contains "re-seal: the CLI RETIRED the stale enrollment in the same run" \
    "$(cat "$RETIRE_LOG")" "$(sentinel_of cli_enroll_retire)"
rm -f "$RETIRE_LOG"
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "re-seal: exactly ONE standing systemd-tpm2 token (no dead-slot accumulation)" "1" "$NTOK"
TOKPCRS=$(disk_token_json "$RUN/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
assert_eq "re-sealed token pins the finalized {PCR 7, PCR 11}" "[7,11]" "$TOKPCRS"
# LUKS2 metadata DID change (the stale enrollment was retired) — the old
# byte-identity no longer holds and must not be asserted

# --- boot 4: the re-sealed 6.4.0 boot — passwordless again ------------------------
boot_and_wait "v2-resealed" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/pcrsig64-tooling.img"
LOG=$(log_of "v2-resealed")
cp "$RUN/uki-6.4.0.efi.pcrsig.json" "$RUN/uki-pcrsig.json"   # prediction of the BOOTED UKI
assert_pcr11_prediction "S-14 v2-resealed"
assert_contains "[6.4.0-re] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[6.4.0-re] standing {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[6.4.0-re] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[6.4.0-re] re-sealed token UNLOCKED via the hook (passwordless kernel update)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[6.4.0-re] UNSEALED (kernel update complete under Mechanism B)" "$LOG" \
    "$(sentinel_of harness_unsealed)"
assert_not_contains "[6.4.0-re] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[6.4.0-re] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"

# --- verdict --------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.4.0" "$RUN/stage-keyless"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
echo "# H-G7 VERDICT under the finalized Mechanism B contract (ADR-20, {7,11}): the"
echo "# sealed policy is bound to the ENROLL-time measured PCR 11, so a new kernel's"
echo "# UKI CANNOT unlock the standing token with zero TPM operations — the §8.2 hook"
echo "# refuses it fail-closed (bounded recovery loop, 3-strike poweroff) and the §8.3"
echo "# answer is the re-seal: enroll-tpm retires the stale enrollment and stands the"
echo "# fresh {7,11} seal over the UNCHANGED d7 + the new UKI's signed prediction;"
echo "# the next boot unlocks passwordless. The §10 build-failed row holds: a keyless"
echo "# rebuild ships NOTHING and the old default keeps booting + auto-unlocking."
if (( TESTS_FAIL == 0 )); then
    echo "# s14-kernel-update: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s14-kernel-update: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
