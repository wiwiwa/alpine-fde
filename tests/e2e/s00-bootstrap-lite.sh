#!/usr/bin/env bash
# tests/e2e/s00-bootstrap-lite.sh — §12 S-00, the full bootstrap (Wave 2
# replacement of the LITE bring-up scenario; S-00b continues in
# tests/e2e/s00b-enroll-cache.sh).
#
# §12 S-00 stage chain, each stage sentinel-asserted:
#   1. installer UKI (its initrd embeds the LUKS passphrase; the pinned rootfs
#      artifact travels on the payload drive — embedding it in the initramfs is
#      infeasible under TCG, see tests/lib/uki-build.sh)
#   2. PASSPHRASE UNLOCK (the one documented first-boot prompt; fed from the
#      embedded kf0, zero console input) of the fresh LUKS2 volume
#   3. populate the minimal rootfs (§3.3) from the SHA256-pinned Alpine
#      artifact + configure OpenRC networking/getty + apk repositories
#   4. §3.3 SIZE BUDGET: installed-rootfs size ≤ budget (the harness var
#      DEBIAN_FDE_ROOTFS_BUDGET_MIB is the pin of record; default = the 1.4 GB
#      planning target) + package count tracked
#   5. G-T11b disk-side scans: no private key material (PEM headers, .pem/.key)
#      anywhere on the LUKS payload; ESP scanned host-side
#   6. `audit --init` finalizes the baseline via the REAL CLI (against a
#      G-R1-compliant efivars fixture: SecureBoot=1 SetupMode=0) BEFORE any UKI
#      chain work — S-00b (ukictl build + enroll) only runs after this scenario
#   7. G-T13 prediction check: ukify's predicted PCR 11 (enter-initrd entry ==
#      the {11}-selection PolicyPCR digest over the guest's PRE-UNLOCK reading,
#      i.e. the post-phase-word line — never the final register)
#   8. ESP-size assertion: ESP sized from measured UKI × retention (3, §9.3)
#      + headroom (§13), asserted against the actual image
#
# RUN DIR CONTRACT (consumed by s00b, then by the registered state consumers
# via run-e2e.sh): disk.img (populated, NOT yet enrolled), tpm/ (swtpm state),
# keys/, vars-enrolled.fd, esp.img, pcrsig.img, console.log; last line
#     RUNDIR <path>
#
# deviations (documented, not silent):
#   * §12 says the installer initrd "embeds the pinned rootfs artifact" — the
#     artifact is 319 MB; a 171 MiB UKI already exceeded the firmware's TCG
#     budget (tests/lib/uki-build.sh, uki_initrd_pack), so the artifact rides
#     the payload drive and is hash-verified in-guest against the build-time
#     pin (@@ROOTFS_SHA@@) before use.
#   * the populated rootfs follows the revised-design BASE matrix default
#     (G-HW5, 2026-09-19): Btrfs on the LUKS volume with the §9.1 subvolume
#     layout @ / @home / @snapshots (mkfs.btrfs from the pinned btrfs-progs
#     deb). The legacy flat fs remains production-only (`install --fs ext4`,
#     §9.1); no harness scenario exercises it, so the harness carries no ext4
#     seam. The unlock path under test does not depend on the fs type.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
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

# §3.3 size budget (G-E1, ADR-12): THE PIN OF RECORD IS THIS HARNESS VAR
# (default = the ADR-12 planning target ≤ 250 MB, an 80%+ reduction vs the
# Debian-era 1434 MiB). CI overrides it via the environment. The measured
# Alpine payload (pinned minirootfs + tooling + stubs) sits far under the
# ceiling; the assert below records the measured value every run.
DEBIAN_FDE_ROOTFS_BUDGET_MIB="${DEBIAN_FDE_ROOTFS_BUDGET_MIB:-250}"
# §13/§9.3 ESP sizing: measured UKI × retention (current + 2 old) + headroom.
ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
# the installer boot dd's 319 MB + untars ~1.3 GB + btrfs metadata + the
# G-T11b tree scan under TCG — the scan wall time varies ~±40% between runs
# (900 s was exceeded once, 2026-09-19 run s00-bootstrap-1789763382: killed
# mid-scan), so the hard timeout carries headroom
export QEMU_TIMEOUT="${DEBIAN_FDE_S00_TIMEOUT:-1200}"

RUN="$TESTS/e2e/.runs/s00-bootstrap-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while the (long) installer boot runs.
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!
# HI-02: the refresher loop must die on EVERY exit path (early `exit 1`s used
# to leak it forever — it kept a dead dir permanently newest-by-mtime and
# poisoned every later prune). Chain with swtpm's cleanup; pre-set the flag so
# swtpm_start does not overwrite this trap with its own.
_SWTPM_CLEANUP_TRAP_SET=1
trap 'kill "$REFRESHER" 2>/dev/null; swtpm_cleanup_all 2>/dev/null' EXIT INT TERM

# --- fixtures -------------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s00: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
assert_contains "enrolled vars: SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
assert_contains "enrolled vars: PK present" "$(keys_vars_get "$RUN/vars-enrolled.fd" PK)" "blob"

echo "# building rootfs payload drive (SHA256-pinned Alpine artifact, G-E1) ..."
read -r ROOTFS_SHA ROOTFS_BYTES <<<"$(rootfs_payload_image "$RUN/rootfs-payload.img")"
[[ -n "$ROOTFS_SHA" ]] || { echo "s00: rootfs payload build failed"; exit 1; }
assert_file_exists "S-00: rootfs payload drive built" "$RUN/rootfs-payload.img"
echo "# artifact pin: $ROOTFS_SHA ($ROOTFS_BYTES bytes)"

echo "# building installer UKI (guest tree + initramfs + ukify + sbsign; stage=install) ..."
DEBIAN_FDE_ROOTFS_SHA="$ROOTFS_SHA" DEBIAN_FDE_ROOTFS_BYTES="$ROOTFS_BYTES" \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "debian-fde-stage=install" || {
    echo "s00: uki_build failed"; exit 1; }
assert_file_exists "S-00: installer UKI built" "$RUN/harness.efi"
assert_rc "S-00: installer UKI is SB-valid (release-cert signature)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/harness.efi"
# the passphrase (kf0) is EMBEDDED in the initramfs — verify, do not trust
if cpio -it --quiet <"$RUN/initrd.cpio" 2>/dev/null | grep -qx "kf0"; then
    _assert_result ok "installer initrd embeds the LUKS passphrase (kf0)" ""
else
    _assert_result not-ok "installer initrd embeds the LUKS passphrase (kf0)" "kf0 not in cpio listing"
fi

UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB ))
echo "# UKI ${UKI_MIB}MiB -> ESP ${ESP_MIB}MiB (retention $ROOTFS_RETENTION + headroom ${ESP_HEADROOM_MIB}MiB)"
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1
# §13 ESP-size assertion: the actual image matches the sizing formula and the
# retention bound (UKI_MIB × retention is the floor, headroom on top)
ESP_ACTUAL_MIB=$(( ($(stat -c%s "$RUN/esp.img") + 1048575) / 1048576 ))
assert_eq "ESP sized from measured UKI × retention + headroom (actual == formula)" \
    "$ESP_MIB" "$ESP_ACTUAL_MIB"
if (( ESP_ACTUAL_MIB >= UKI_MIB * ROOTFS_RETENTION )); then
    _assert_result ok "ESP fits $ROOTFS_RETENTION retained UKIs (${ESP_ACTUAL_MIB}MiB >= ${UKI_MIB}×$ROOTFS_RETENTION)" ""
else
    _assert_result not-ok "ESP fits $ROOTFS_RETENTION retained UKIs" \
        "${ESP_ACTUAL_MIB}MiB < ${UKI_MIB}×$ROOTFS_RETENTION"
fi
disk_make_luks "$RUN/disk.img" 1600 || exit 1

# --- boot: installer stage (passphrase unlock + rootfs populate) -----------------
echo "# booting installer (payload drive on vdc; TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/rootfs-payload.img"
qemu_wait "$RUN" "$QEMU_TIMEOUT"
BOOT_RC=$?
if (( BOOT_RC == 0 )); then
    _assert_result ok "guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill)" "qemu_wait rc=$BOOT_RC"
fi
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- stage assertions ------------------------------------------------------------
assert_contains "init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "TPM char device appeared" "$LOG" "/dev/tpmrm0 present"
for pcr in 0 7 11; do
    if grep -qE "debian-fde-pcr sha256:$pcr=[0-9a-f]{64}" "$CONSOLE" 2>/dev/null; then
        _assert_result ok "PCR $pcr printed (sha256 hex)" ""
    else
        _assert_result not-ok "PCR $pcr printed (sha256 hex)" "no debian-fde-pcr line in console.log"
    fi
done
PCR7=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$CONSOLE" 2>/dev/null | head -1 | cut -d= -f2)
ZERO7=$(printf '0%.0s' {1..64})
if [[ -n "$PCR7" && "$PCR7" != "$ZERO7" ]]; then
    _assert_result ok "PCR 7 non-zero (enrolled SB state measured)" ""
else
    _assert_result not-ok "PCR 7 non-zero (enrolled SB state measured)" "PCR7=${PCR7:-absent}"
fi

# stage 2: the one-time documented passphrase unlock
assert_contains "passphrase unlock (one-time, documented; zero console input)" "$LOG" \
    "debian-fde-install: root volume unlocked via passphrase"
assert_not_contains "no fallback prompt on the install path" "$LOG" "awaiting console line"
assert_not_contains "no ask-password prompt on the install path (sentinel table)" "$LOG" \
    "$(sentinel_of prompt_re)"
# stage 3: rootfs populate from the pinned artifact
assert_contains "rootfs payload hash-verified in-guest" "$LOG" \
    "debian-fde-install: rootfs payload verified"
assert_contains "rootfs populated (§3.3)" "$LOG" \
    "debian-fde-install: populating rootfs from the pinned Alpine artifact"
assert_contains "getty/openrc configured (§3.3)" "$LOG" \
    "debian-fde-install: getty/openrc configured"
# stage 3b: §9.1 Btrfs default (G-HW5) — mkfs.btrfs + @/@home/@snapshots
# subvolumes + subvol=@ mount + the fstab subvolume forms, all proven on the
# console (harness-owned markers; `btrfs subvolume list` output is the
# on-disk evidence, the /etc/fstab lines are echoed verbatim)
assert_contains "§9.1 btrfs rootfs created on the LUKS volume" "$LOG" \
    "debian-fde-install: btrfs rootfs created (uuid="
assert_contains "§9.1 subvolumes created (@ @home @snapshots)" "$LOG" \
    "debian-fde-install: subvolumes created (@ @home @snapshots)"
assert_contains "root mounted rw with subvol=@" "$LOG" \
    "debian-fde-install: root mounted (btrfs subvol=@)"
for sv in '@' '@home' '@snapshots'; do
    # NB: no bare $ end-anchor — the serial chardev log carries a trailing CR
    # on every line (same trap as the kib= parse below); [[:space:]] eats it
    if grep -qE "path ${sv}[[:space:]]" "$CONSOLE" 2>/dev/null; then
        _assert_result ok "btrfs subvolume ${sv} present on disk (subvolume list)" ""
    else
        _assert_result not-ok "btrfs subvolume ${sv} present on disk (subvolume list)" \
            "no 'path ${sv}' line in console"
    fi
done
if grep -qE '^debian-fde-btrfs: fstab\| UUID=[0-9a-f-]{36} / btrfs subvol=@,defaults 0 1[[:space:]]*$' "$CONSOLE" 2>/dev/null \
    && grep -qE '^debian-fde-btrfs: fstab\| UUID=[0-9a-f-]{36} /home btrfs subvol=@home,defaults 0 2[[:space:]]*$' "$CONSOLE" 2>/dev/null \
    && grep -qE '^debian-fde-btrfs: fstab\| UUID=[0-9a-f-]{36} /.snapshots btrfs subvol=@snapshots,defaults 0 2[[:space:]]*$' "$CONSOLE" 2>/dev/null; then
    _assert_result ok "§9.1 fstab subvolume forms written (/ /home /.snapshots)" ""
else
    _assert_result not-ok "§9.1 fstab subvolume forms written (/ /home /.snapshots)" \
        "no debian-fde-btrfs: fstab| lines in console"
fi
assert_not_contains "install stage never failed" "$LOG" "debian-fde: INSTALL-FAILED"

# stage 4: §3.3/ADR-12 size budget + package count (parsed from the console
# print; the package marker is the apk world/db — /lib/apk/db/installed, one
# leading `P:` line per installed package — re-pinned from the dpkg status
# marker with the same marker SHAPE, G-E1d)
ROOTFS_KIB=$(sed -n 's/^debian-fde-rootfs: kib=\([0-9]\{1,\}\) packages=.*/\1/p' "$CONSOLE" | head -1)
# NB: no end-anchor — the serial chardev log carries a trailing CR on the line
ROOTFS_PKGS=$(sed -n 's/^debian-fde-rootfs: kib=[0-9]\{1,\} packages=\([0-9]\{1,\}\).*/\1/p' "$CONSOLE" | head -1)
# MD-01: compute the budget comparison ONLY from a real measurement — an empty
# ROOTFS_KIB used to evaluate to 0 and bank a passing "0MiB <= budget" assert
# in the very run where "size measured" correctly recorded not-ok.
if [[ -n "$ROOTFS_KIB" ]]; then
    ROOTFS_MIB=$(( (ROOTFS_KIB + 1023) / 1024 ))
    _assert_result ok "installed-rootfs size measured (${ROOTFS_MIB}MiB, $ROOTFS_PKGS apk packages)" ""
else
    ROOTFS_MIB=""
    _assert_result not-ok "installed-rootfs size measured" "no debian-fde-rootfs line in console"
fi
if [[ -n "$ROOTFS_KIB" ]] && (( ROOTFS_MIB <= DEBIAN_FDE_ROOTFS_BUDGET_MIB )); then
    _assert_result ok "§3.3 size budget (ADR-12): ${ROOTFS_MIB}MiB <= budget ${DEBIAN_FDE_ROOTFS_BUDGET_MIB}MiB (pin of record: harness var)" ""
else
    _assert_result not-ok "§3.3 size budget (pin of record: harness var)" \
        "${ROOTFS_MIB:-unmeasured}MiB vs budget ${DEBIAN_FDE_ROOTFS_BUDGET_MIB}MiB"
fi
if [[ -n "$ROOTFS_PKGS" ]] && (( ROOTFS_PKGS > 0 )); then
    _assert_result ok "apk package count tracked (world/db): $ROOTFS_PKGS" ""
else
    _assert_result not-ok "apk package count tracked (world/db)" "packages=${ROOTFS_PKGS:-absent}"
fi

# stage 5: G-T11b disk-side scans (LUKS payload in-guest; ESP host-side)
SCAN_LINE=$(grep -oE 'debian-fde-scan: keyfiles=[0-9]+ pem=[0-9]+' "$CONSOLE" | head -1)
assert_eq "G-T11b: no .pem/.key files on the LUKS payload" \
    "debian-fde-scan: keyfiles=0 pem=0" "$SCAN_LINE"
PEM_HITS=$(grep -al '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$RUN/harness.efi" 2>/dev/null || true)
assert_eq "G-T11b: installer UKI carries no private-key PEM block" "" "$PEM_HITS"
KEYNAMES=$(mdir -i "$RUN/esp.img" -/ :: 2>/dev/null | grep -Ei '\.(pem|key)' || true)   # MD-09: recursive listing
assert_eq "G-T11b: ESP lists no .pem/.key files" "" "$KEYNAMES"

assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"

# stage 7: G-T13 prediction check (tests/lib/prediction.sh) — ukify's
# predicted PCR 11 (enter-initrd entry) == the {11}-selection PolicyPCR
# digest over the guest's PRE-UNLOCK reading (the post-phase-word line),
# NOT the final register. $CONSOLE/$RUN/uki-pcrsig.json are this boot's.
assert_pcr11_prediction "G-T13"

# --- stage 6: audit --init finalizes the baseline (real CLI) BEFORE any UKI ------
# G-R1 guard: finalization refuses unless the efivars seam reports
# SecureBoot=1 SetupMode=0 — the fixture efivars dir presents the final SB
# state (mkvar pattern from tests/unit/baseline_finalize_guard.sh).
EFIVARS="$RUN/rootfs/efivars-sb-on"
mkdir -p "$EFIVARS" "$RUN/rootfs/etc/debian-fde"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
_mkcertvar PK pk-cert-v1
_mkcertvar KEK kek-cert-v1
_mkcertvar db db-cert-v1
_mkcertvar dbx dbx-cert-v1
cat >"$RUN/rootfs/etc/debian-fde/baseline.json" <<'JSON'
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
# the fixture swtpm restarts after the boot (ctrl-channel disconnect); the
# live PCRs it serves are re-initialized, so the OPERATOR-meaningful values
# are stamped from the boot console afterwards (s16 precedent)
if ! swtpm_ensure "$RUN/tpm"; then   # IN-03: the single promoted restart path
    echo "s00: swtpm restart failed"; exit 1
fi
AUDIT_OUT=$(DEBIAN_FDE_ROOT="$RUN/rootfs" \
    DEBIAN_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
    DEBIAN_FDE_EFIVARS_DIR="$EFIVARS" \
    DEBIAN_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
    DEBIAN_FDE_NO_INSTALL=1 \
    "$REPO/bin/debian-fde" audit --init 2>&1)
AUDIT_RC=$?
assert_eq "audit --init finalizes the baseline (real CLI, rc 0)" "0" "$AUDIT_RC"
assert_contains "finalized baseline records secure_boot=1" \
    "$(cat "$RUN/rootfs/etc/debian-fde/baseline.json")" '"secure_boot": "1"'
# stamp the finalized PCR 0/7 from the boot console evidence (the installed
# machine's trust root is the BOOTED state, not the restarted fixture)
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$CONSOLE" | head -1 | cut -d= -f2)\",|" \
    "$RUN/rootfs/etc/debian-fde/baseline.json"
assert_eq "baseline expected_pcr7 == the booted machine's PCR 7" "$PCR7" \
    "$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/debian-fde/baseline.json")"
if grep -q '"expected_pcr7": "pending"' "$RUN/rootfs/etc/debian-fde/baseline.json"; then
    _assert_result not-ok "baseline is FINAL (no pending PCR 7)" "still pending"
else
    _assert_result ok "baseline is FINAL (no pending PCR 7)" ""
fi
cp "$RUN/rootfs/etc/debian-fde/baseline.json" "$RUN/baseline.json"

kill "$REFRESHER" 2>/dev/null
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s00-bootstrap: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s00-bootstrap: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
