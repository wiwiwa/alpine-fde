#!/usr/bin/env bash
# tests/e2e/s08-firmware-drift.sh — §10 row "Firmware updated": PCR 0/2 are
# EXCLUDED from the seal policy (ADR-6) and covered by `audit` instead.
#
# Part 1 (guest): extend PCR 0 and PCR 2 of the boot TPM host-side (the
#   swtpm equivalent of a firmware update), then boot the enrolled harness:
#   the guest must STILL reach `debian-fde: UNSEALED` (the A″ policy binds
#   PCR 7 statically + signed PCR 11 only) and print the drifted PCR 0.
# Part 2 (host, real audit code path): run lib/cmd/audit.sh's
#   cmd_audit_main against a swtpm whose live PCR state is under host
#   control, via audit's documented seam env vars (DEBIAN_FDE_ROOT /
#   DEBIAN_FDE_TCTI / DEBIAN_FDE_EVENTLOG / DEBIAN_FDE_EFIVARS_DIR):
#     a) baseline captured from the LIVE (drifted) values -> rc 0 (match);
#     b) stale baseline (pcr0 rewritten) + mutated eventlog -> rc 1
#        (DEBIAN_FDE_DRIFT), DRIFT lines for pcr0 and the eventlog,
#        last-audit.json records result=drift.
#
# EMPIRICAL (verified 2026-09-14): when QEMU exits after the boot, the
# swtpm it is passthrough-connected to TERMINATES and unlinks its sockets
# (reproduced with a plain OVMF boot; swtpm_start restarts cleanly on the
# same state dir, and --flags startup-clear resets the PCR banks to zero).
# The audit therefore never reads the boot's post-mortem TPM: it restarts
# the SAME swtpm and reconstructs the post-firmware-update live state by
# re-applying the same PCR 0/2 extends host-side.

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

# _snap SRC DST — copy the console log (snapshots live in SNAPDIR under
# ${TMPDIR:-/tmp} so sibling .runs housekeeping cannot take them down; see
# s04-unsigned-uki.sh header).
_snap() { [ -f "$1" ] && cp "$1" "$2" || true; }

# _snap_while_running QEMU-PID CONSOLE SNAP — keep SNAP fresh (5 s cadence)
# while qemu runs; run in background, `wait` it after qemu_wait.
_snap_while_running() {
    while kill -0 "$1" 2>/dev/null; do
        [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
        sleep 5
    done
    [ -f "$2" ] && cp "$2" "$3" 2>/dev/null
    return 0
}

RUN="$TESTS/e2e/.runs/s08-firmware-$(date +%s)"
# console snapshots OUTSIDE .runs — survive sibling .runs housekeeping
SNAPDIR="${TMPDIR:-/tmp}/secpc-e2e-s08-$(date +%s)"
mkdir -p "$RUN" "$SNAPDIR"
# prefix housekeeping — never the invocation's chained state dirs
# (CR-02/MD-03: DEBIAN_FDE_PROTECT_DIRS, exported by run-e2e.sh)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's08-firmware-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
ENROLL="$RUN/enroll-boot"   # enrollment boot artifacts (tpm state reused for the audit)
CONSOLE="$ENROLL/console.log"   # the (single) boot lives in the enroll-boot dir
mkdir -p "$ENROLL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$ENROLL" 2>/dev/null || true; }

# audit seam runner: cmd_audit_main in an isolated subshell (it die()s on
# errors); stdout+stderr captured, rc propagated.
AUDIT_ROOT="$RUN/host-audit"
audit_run() {   # audit_run <out-file>  -> rc of cmd_audit_main
    (
        export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
        export DEBIAN_FDE_ROOT="$AUDIT_ROOT"
        export DEBIAN_FDE_TCTI="swtpm:path=$ENROLL/tpm/sock"
        export DEBIAN_FDE_EVENTLOG="$RUN/eventlog.fixture"
        export DEBIAN_FDE_EFIVARS_DIR="$AUDIT_ROOT/empty-efivars"   # no efivarfs on the host: SB section inert
        export DEBIAN_FDE_NO_INSTALL=1
        # shellcheck source=../../lib/cmd/audit.sh
        . "$REPO/lib/cmd/audit.sh"
        cmd_audit_main
    ) >"$1" 2>&1
}

# --- fixtures (s00 pattern) ----------------------------------------------------
swtpm_start "$ENROLL/tpm" || { echo "s08: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s08: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1

# --- simulate the firmware update: drift PCR 0 + PCR 2 BEFORE the boot ----------
PCR0_PRE=$(swtpm_pcrread "$ENROLL/tpm" 0)
DRIFT0=$(printf 'debian-fde-e2e-s08-firmware-update-pcr0' | sha256sum | cut -d' ' -f1)
DRIFT2=$(printf 'debian-fde-e2e-s08-firmware-update-pcr2' | sha256sum | cut -d' ' -f1)
swtpm_pcrextend "$ENROLL/tpm" 0 "$DRIFT0"
swtpm_pcrextend "$ENROLL/tpm" 2 "$DRIFT2"
PCR0_DRIFTED=$(swtpm_pcrread "$ENROLL/tpm" 0)
PCR2_DRIFTED=$(swtpm_pcrread "$ENROLL/tpm" 2)
ZERO64=$(printf '0%.0s' $(seq 1 64))
if [ "$PCR0_PRE" = "$ZERO64" ] && [ "$PCR0_DRIFTED" != "$ZERO64" ] && [ "$PCR2_DRIFTED" != "$ZERO64" ]; then
    _assert_result ok "PCR 0/2 drifted host-side before boot (firmware-update simulation; deterministic from zero)" "pcr0=$PCR0_DRIFTED"
else
    _assert_result not-ok "PCR 0/2 drifted host-side before boot (firmware-update simulation; deterministic from zero)" \
        "pre=$PCR0_PRE drifted=$PCR0_DRIFTED pcr2=$PCR2_DRIFTED"
fi

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    swtpm_start "$1"
}

# --- boot: drifted firmware, enrolled disk -> must STILL unseal (ADR-6) ----------
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3). Each attempt re-applies the
# PCR 0/2 drift if the (re)started swtpm's banks are zeroed — extends from the
# zero state are deterministic, so every attempt boots the same drifted state.
BOOT_OK=0
for _att in 1 2 3; do
    _swtpm_ensure "$ENROLL/tpm" || { echo "s08: swtpm failed"; exit 1; }
    if [ "$(swtpm_pcrread "$ENROLL/tpm" 0)" = "$ZERO64" ]; then
        swtpm_pcrextend "$ENROLL/tpm" 0 "$DRIFT0"
        swtpm_pcrextend "$ENROLL/tpm" 2 "$DRIFT2"
    fi
    echo "# booting with drifted PCR 0/2 (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$ENROLL" "$ENROLL/esp.img" "$ENROLL/disk.img" "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$ENROLL/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-boot.snap" &
    _snap_poller=$!
    qemu_wait "$ENROLL" "$QEMU_TIMEOUT"
    wait "$_snap_poller"
    if grep -q "debian-fde: UNSEALED" "$SNAPDIR/console-boot.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# boot attempt $_att did not reach UNSEALED (external kill/prune race or regression) — retrying"
done
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "boot completed: unsealed despite the drifted firmware" ""
else
    _assert_result not-ok "boot completed: unsealed despite the drifted firmware" \
        "no UNSEALED in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-boot.snap" 2>/dev/null | tr '\n' ' ')"
fi
LOG=$(cat "$SNAPDIR/console-boot.snap" 2>/dev/null || true)
assert_contains "init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "ADR-6: unseal despite PCR 0/2 drift" "$LOG" "debian-fde: UNSEALED"
assert_contains "clean poweroff" "$LOG" "debian-fde: POWEROFF"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"

# G-T13/G-E9 (boot reaches the UKI stub): the ADR-6 drift is PCR 0/2 only —
# the PRE-UNLOCK PCR 11 reading must equal the signed prediction. Pair the
# helper with this boot's console snapshot + the enrolled UKI's prediction.
cp "$ENROLL/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
_CONSOLE_SAVE="$CONSOLE"
CONSOLE="$SNAPDIR/console-boot.snap"
assert_pcr11_prediction "S-08"
CONSOLE="$_CONSOLE_SAVE"

GUEST_PCR0=$(grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$SNAPDIR/console-boot.snap" 2>/dev/null | head -1 | cut -d= -f2)
if [ -n "$GUEST_PCR0" ] && [ "$GUEST_PCR0" != "$ZERO64" ] && [ "$GUEST_PCR0" != "$PCR0_DRIFTED" ]; then
    _assert_result ok "guest observed PCR 0 drifted further (firmware extended on top of the update)" "pcr0=$GUEST_PCR0"
else
    _assert_result not-ok "guest observed PCR 0 drifted further (firmware extended on top of the update)" \
        "guest line missing, zero, or equal to the pre-boot value: [$GUEST_PCR0] pre=$PCR0_DRIFTED"
fi

# --- part 2: the REAL audit against a baseline, via its seam env vars -----------
_ensure_run
# The boot's swtpm died with QEMU (see header) — force a clean restart of the
# same state dir (stop whatever is left + start; PCR banks are reset to zero
# by startup-clear) and reconstruct the post-firmware-update live state by
# re-applying the same PCR 0/2 extends.
swtpm_stop "$ENROLL/tpm" || true
swtpm_start "$ENROLL/tpm" || { echo "s08: swtpm restart failed"; exit 1; }
if [ "$(swtpm_pcrread "$ENROLL/tpm" 0)" = "$ZERO64" ]; then
    _assert_result ok "audit setup: swtpm restarted with zeroed PCRs" ""
else
    _assert_result not-ok "audit setup: swtpm restarted with zeroed PCRs" "pcr0=$(swtpm_pcrread "$ENROLL/tpm" 0)"
fi
swtpm_pcrextend "$ENROLL/tpm" 0 "$DRIFT0"
swtpm_pcrextend "$ENROLL/tpm" 2 "$DRIFT2"
PCR0_POST=$(swtpm_pcrread "$ENROLL/tpm" 0)
PCR2_POST=$(swtpm_pcrread "$ENROLL/tpm" 2)
if [ "$PCR0_POST" = "$PCR0_DRIFTED" ] && [ "$PCR2_POST" = "$PCR2_DRIFTED" ]; then
    _assert_result ok "audit setup: post-update PCR 0/2 reconstructed (extend is stateless-deterministic)" ""
else
    _assert_result not-ok "audit setup: post-update PCR 0/2 reconstructed (extend is stateless-deterministic)" \
        "pcr0 $PCR0_POST vs $PCR0_DRIFTED; pcr2 $PCR2_POST vs $PCR2_DRIFTED"
fi
mkdir -p "$AUDIT_ROOT/etc/alpine-fde" "$AUDIT_ROOT/empty-efivars"
printf 'UEFI TCG event log fixture for s08\n' >"$RUN/eventlog.fixture"
EV_SHA=$(sha256sum "$RUN/eventlog.fixture" | cut -d' ' -f1)
EV_SZ=$(wc -c <"$RUN/eventlog.fixture" | tr -d '[:space:]')
LIVE_PCR1=$(swtpm_pcrread "$ENROLL/tpm" 1)
LIVE_PCR3=$(swtpm_pcrread "$ENROLL/tpm" 3)
LIVE_PCR7=$(swtpm_pcrread "$ENROLL/tpm" 7)

# baseline = LIVE values (match phase control); sb_state/target left empty —
# empty strings are valid per baseline_validate and make the efivarfs-dependent
# sections inert on this efivarfs-less host (isolate PCR/eventlog drift).
cat >"$AUDIT_ROOT/etc/alpine-fde/baseline.json" <<EOF
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcr0": "$PCR0_POST",
  "pcr1": "$LIVE_PCR1",
  "pcr2": "$PCR2_DRIFTED",
  "pcr3": "$LIVE_PCR3",
  "expected_pcr7": "$LIVE_PCR7",
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
    "eventlog_sha256": "$EV_SHA",
    "eventlog_size": "$EV_SZ"
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

# (a) match phase: baseline == live -> rc 0
AUDIT_RC=0
audit_run "$RUN/audit-match.log" || AUDIT_RC=$?
if [ "$AUDIT_RC" -eq 0 ] && grep -q "all checked values match the baseline" "$RUN/audit-match.log"; then
    _assert_result ok "audit: live-vs-fresh-baseline -> rc 0 match" ""
else
    _assert_result not-ok "audit: live-vs-fresh-baseline -> rc 0 match" \
        "rc=$AUDIT_RC log: $(tail -3 "$RUN/audit-match.log" | tr '\n' ' ')"
fi

# (b) drift phase: stale baseline pcr0 + mutated eventlog -> rc 1 + DRIFT lines
sed -i "s/\"pcr0\": \"$PCR0_POST\"/\"pcr0\": \"$(printf 'a%.0s' $(seq 1 64))\"/" \
    "$AUDIT_ROOT/etc/alpine-fde/baseline.json"
printf 'tampered\n' >>"$RUN/eventlog.fixture"
AUDIT_RC=0
audit_run "$RUN/audit-drift.log" || AUDIT_RC=$?
if [ "$AUDIT_RC" -eq 1 ]; then
    _assert_result ok "audit: stale pcr0 + mutated eventlog -> rc 1 (DEBIAN_FDE_DRIFT)" ""
else
    _assert_result not-ok "audit: stale pcr0 + mutated eventlog -> rc 1 (DEBIAN_FDE_DRIFT)" \
        "rc=$AUDIT_RC (expected 1) log: $(tail -3 "$RUN/audit-drift.log" | tr '\n' ' ')"
fi
assert_contains "audit: pcr0 DRIFT line" "$(cat "$RUN/audit-drift.log")" "pcr0"
DRIFT_LOG=$(cat "$RUN/audit-drift.log" 2>/dev/null || true)
if printf '%s\n' "$DRIFT_LOG" | grep -q '^pcr0 .* DRIFT$' &&
    printf '%s\n' "$DRIFT_LOG" | grep -q '^eventlog .* DRIFT$'; then
    _assert_result ok "audit: DRIFT lines for pcr0 AND eventlog" ""
else
    _assert_result not-ok "audit: DRIFT lines for pcr0 AND eventlog" "log: $DRIFT_LOG"
fi
if grep -q '"result": "drift"' "$AUDIT_ROOT/etc/alpine-fde/last-audit.json" 2>/dev/null; then
    _assert_result ok "audit: last-audit.json records result=drift" ""
else
    _assert_result not-ok "audit: last-audit.json records result=drift" "missing/incorrect last-audit.json"
fi

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s08-firmware-drift: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s08-firmware-drift: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
