#!/usr/bin/env bash
# tests/e2e/s08-firmware-drift.sh — §10 row "Firmware updated": PCR 0/2 are
# EXCLUDED from the seal policy (ADR-6) and covered by `audit` instead,
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness
# DEFAULT unlock).
#
# Part 1 (guest): extend PCR 0 and PCR 2 of the boot TPM host-side (the
#   swtpm equivalent of a firmware update), then boot the ENROLLED harness:
#   the hook's PolicyPCR({7,11}) session binds PCR 7 statically + signed
#   PCR 11 only, so the guest must STILL reach `debian-fde: UNSEALED` via
#   the hook's zero-input token path (unseal_unlocked) and print the drifted
#   PCR 0. Two boots:
#     boot 1  baseline (token-less disk) — the hook's BOUNDED recovery loop
#             is the only way in; the slot-0 passphrase is fed through the
#             hook's OWN prompt (uki_wait_hook_prompt; the hook has NO read
#             timeout) -> UNSEALED (the positive control);
#             then the REAL production CLI enrolls the finalized {7,11}
#             Mechanism B token host-side against the fixture swtpm
#             (uki_host_enroll_finalized; combined .pcrsig entry REQUIRED —
#             a ladder-only pcrsig is refused by the hook's I3 gate);
#     boot 2  the SCENARIO: same enrolled disk, drifted PCR 0/2 -> the hook
#             must unlock with ZERO console input (ADR-6: the A″ policy
#             never bound PCR 0/2; audit covers them instead).
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
#
# NB (G-T13): the scenario boot UNSEALES, so /init prints the post-hook
# postphase PCR 11 reading (the hook's single enter-initrd extend) and the
# signed prediction IS asserted on that console.

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
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

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
ENROLL="$RUN/enroll-boot"   # baseline boot + enrollment artifacts (tpm state reused for the audit)
CONSOLE="$ENROLL/console.log"   # the baseline boot lives in the enroll-boot dir
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
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s08: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1

# efivars seam for the enroll-tpm I5 guard (mkvar pattern from
# tests/unit/baseline_finalize_guard.sh): attrs u32le 0x7 + payload byte.
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0

# --- boot 1: baseline (token-less disk) -> the hook's recovery loop -------------
# The hook has NO read timeout: the feed is prompt-synchronized
# (uki_wait_hook_prompt). The passphrase unlock is the positive control for
# boot 2's zero-input token path.
for _attempt in 1 2; do
    qemu_run "$ENROLL" "$ENROLL/esp.img" "$ENROLL/disk.img" \
        "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$ENROLL"; then
        feed_line "$ENROLL/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    fi
    qemu_wait "$ENROLL" "$QEMU_TIMEOUT"
    grep -q "debian-fde: UNSEALED" "$ENROLL/console.log" && break
    echo "# baseline boot attempt $_attempt did not reach UNSEALED (infra anomaly) — retrying"
    if ((_attempt < 2)); then
        swtpm_reset "$ENROLL/tpm" && swtpm_start "$ENROLL/tpm" || exit 1
        rm -f "$ENROLL/console.log"
    fi
done
grep -q "debian-fde: UNSEALED" "$ENROLL/console.log" || {
    echo "s08: baseline boot did not reach UNSEALED — state unusable"; exit 1; }
LOG_B1=$(cat "$ENROLL/console.log" 2>/dev/null || true)
assert_contains "boot 1: init ran" "$LOG_B1" "$(sentinel_of harness_init_started)"
assert_contains "boot 1: hook recovery loop opened (no token on the fresh volume)" "$LOG_B1" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "boot 1: fed slot-0 passphrase unsealed via the recovery path" "$LOG_B1" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "boot 1: volume UNSEALED" "$LOG_B1" "$(sentinel_of harness_unsealed)"

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted
# console's PCR 7, d11 = the build's enter-initrd prediction; the combined
# {7,11} entry is what the hook extracts for the finalized token.
D11=$(cat "$ENROLL/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11" ]] || { echo "s08: no enter-initrd d11 prediction from the build"; exit 1; }
swtpm_ensure "$ENROLL/tpm" || { echo "s08: swtpm restart (enroll) failed"; exit 1; }
PCR7_ENROLLED=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$ENROLL/console.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_ENROLLED" ]] || { echo "s08: no PCR 7 in the baseline console"; exit 1; }
# digest-anchored enroll (Option A): no reseeding and no live-read assertion —
# the CLI compares the entry's recorded d7/d11 against the baseline (pure
# data, no live TPM read); the fixture only needs to be SERVING for the seal.
uki_pcrsig_append_combined "$ENROLL/uki-pcrsig.json" "$ENROLL/uki-pcrsig-combined.json" \
    "$PCR7_ENROLLED" "$D11" "$RUN/keys" || exit 1
assert_eq "combined .pcrsig entry pol == policy_digest(booted d7, enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$PCR7_ENROLLED" "$D11")" \
    "$(jq -r '.sha256[-1].pol' "$ENROLL/uki-pcrsig-combined.json")"
# the payload drive of boot 2 must carry the combined entry (a ladder-only
# pcrsig is refused by the hook's I3 gate)
uki_pcrsig_disk "$ENROLL/pcrsig.img" "$ENROLL/uki-pcrsig-combined.json" || exit 1
# enroll precondition (CLI, enrl_preconditions #2): a FINALIZED baseline at
# $DEBIAN_FDE_ROOT/etc/alpine-fde/baseline.json. Stamp the booted d7 into a
# scenario-local cli-state root — the same seam s06/s09/s12/s13 use; without
# it enroll-tpm dies "no baseline at /etc/alpine-fde/baseline.json".
uki_baseline_stamp "$ENROLL/cli-state" "$PCR7_ENROLLED"
printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
uki_host_enroll_finalized "$EFIVARS" "$ENROLL/uki-pcrsig-combined.json" \
    "$ENROLL/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$ENROLL/cli-state" || {
    echo "s08: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$ENROLL/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

# --- simulate the firmware update: drift PCR 0 + PCR 2 BEFORE the scenario boot --
# The baseline boot re-measured PCRs into the live fixture; a CLEAN restart of
# the same state dir (SRK persists in the permall) zeroes the banks again so
# the update simulation extends from zero — deterministic, and byte-reproducible
# for part 2's reconstruction. ZEROING IS EXPLICIT (2026-09-23): the fixture's
# shutdown-intercepting proxy stores the volatile state at every clean qemu
# exit and swtpm_start RESTORES it when the file is present (defect s15-2 —
# that restore is what keeps the booted d7 alive for the host-side enroll),
# so a bare stop/start hands the drift simulation the BOOTED d0, not zeros.
# Purging tpm2-00.volatilestate after the stop sends swtpm_start down its
# startup-clear path: banks zero, permall (SRK) intact.
swtpm_stop "$ENROLL/tpm" || true
rm -f "$ENROLL/tpm/tpm2-00.volatilestate"
swtpm_start "$ENROLL/tpm" || { echo "s08: swtpm restart (drift) failed"; exit 1; }
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

# --- boot 2: drifted firmware, enrolled disk -> must STILL unseal (ADR-6) --------
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3). Each attempt re-applies the
# PCR 0/2 drift if the (re)started swtpm's banks are zeroed — extends from the
# zero state are deterministic, so every attempt boots the same drifted state.
# NO console input: the hook's token path must unlock zero-input (§8.2 S-01).
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
assert_contains "init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
assert_contains "hook ran the enter-initrd extend (single phase word)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "hook discovered the {7,11} finalized token" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "hook unlocked via the TPM token with ZERO console input" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "ADR-6: unseal despite PCR 0/2 drift" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "never unlocked via the recovery passphrase" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"

# G-T13/G-E9 (boot reaches the UKI stub AND unseals, so /init printed the
# post-hook postphase reading): the ADR-6 drift is PCR 0/2 only — the hook's
# single enter-initrd extend must land exactly on the enrolled UKI's signed
# prediction. Pair the helper with this boot's console snapshot + prediction.
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
# same state dir (stop whatever is left, purge the stored volatile state, then
# start; PCR banks are reset to zero by startup-clear — see the drift-simulation
# note above: a restored volatilestate would hand back the booted banks) and
# reconstruct the post-firmware-update live state by re-applying the same
# PCR 0/2 extends.
swtpm_stop "$ENROLL/tpm" || true
rm -f "$ENROLL/tpm/tpm2-00.volatilestate"
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
