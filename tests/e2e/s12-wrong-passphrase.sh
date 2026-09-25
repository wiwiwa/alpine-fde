#!/usr/bin/env bash
# tests/e2e/s12-wrong-passphrase.sh — the §6.1 recovery-passphrase way out,
# driven through the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 + ADR-20
# amended — the harness DEFAULT unlock, tests/lib/uki-build.sh).
#
# Boot A (negative, the scenario of record): SB-off vars -> the ADR-20 amended
# PRE-UNSEAL SECURE BOOT GUARD blocks at the hook's FIRST step: refusal notice
# + "Press Enter to reboot" + OsIndications boot-to-firmware-setup + reboot.
# The container is NEVER unsealed with SB off — NO token path, NO recovery
# passphrase fallback (the old PCR-drift 3-strike leg is RETRACTED here). The
# hook parks on its Enter read; the scenario waits for the guard sentinel and
# hard-kills qemu BY PID. No emergency shell.
#
# Boot B (positive control, SB-ON DRIFT CONTEXT — the recovery fallback only
# exists under a verified boot): enrolled vars + a dbx update (s15's idiom)
# keep SecureBoot=1 while the firmware measures a NEW PCR 7 -> the guard
# PASSES -> the {7,11} token's PolicyPCR refuses the stale seal term ->
# the hook's BOUNDED keyslot-0 recovery-passphrase loop reads lines from
# /dev/console with its OWN prompt (unseal_prompt_re). Wrong, wrong, CORRECT
# (slot-0) passphrase -> the hook's plain `cryptsetup open --key-file` attach
# activates the volume -> unseal_pass_unlocked -> UNSEALED via the recovery
# slot. Proves the hook's rejections are real passphrase verification and
# closes the §9.4 drift-recovery way out end-to-end.
#
# NB (G-T13): NO assert_pcr11_prediction on boot A — the guard blocks INSIDE
# its own invocation before any extend, so /init never reaches its post-hook
# postphase PCR 11 reading; the boot's raw-zero PCR 11 vs the enrolled
# post-extend value is the equivalent scoping evidence. Boot B unlocks, so
# the postphase reading appears and the signed prediction IS asserted there.
#
# Reuses s00 state when ALPINE_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots the enrolled state itself
# (bootstrap boot + 2 scenario boots).

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
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
source "$TESTS/lib/prediction.sh"  # assert_pcr11_prediction (G-T13/G-E9)
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH

RUN="$TESTS/e2e/.runs/s12-lite-$(date +%s)"
mkdir -p "$RUN"
# the G-T13 prediction helper reads $CONSOLE (prediction.sh); boot B re-points
# it at that boot's archived console. Default it to THIS scenario's canonical
# console so the save/restore at the boot-B prediction can never trip `set -u`
# with an unbound variable (registry 2026-09-23: "CONSOLE: unbound variable"
# aborted the scenario AFTER every assertion had passed).
CONSOLE="$RUN/console.log"

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

STATE="${ALPINE_FDE_E2E_STATE:-}"
# _fresh_pcrs <tpm-dir> — force ZEROED PCRs for the NEXT qemu boot (repro-proven
# 2026-09-24): after a boot exits CLEANLY the swtpm proxy stores the volatile
# state and the fixture's restart RESTORES it into RAM; a boot served by that
# restored instance EXTENDS OVER the previous boot's final values (PCR 0/7/11
# all shift — the "register instability" consoles) and boot A's refusal
# evidence / boot B's PCR 11 equality would drift run-to-run. swtpm_stop +
# swtpm_start (the second start finds no volatile file) restores the
# documented per-boot zeroed-PCR semantics.
_fresh_pcrs() {
    local dir="$1" d0 k
    swtpm_stop "$dir" 2>/dev/null || true
    # a HALF-STARTED instance (readiness probe failed) still holds the state
    # dir's .lock and would make the restart below fail — kill it scoped to
    # this run dir and clear every socket/lock file it left behind
    pkill -9 -f "swtpm socket .*$dir/" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/.lock" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl" "$dir/swtpm.sock"
    swtpm_start "$dir" || { echo "s12: swtpm restart failed"; return 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    if [[ ! "$d0" =~ ^0{64}$ ]]; then
        echo "s12: TPM not zeroed before a boot (pcr0=$d0) — refusing a cumulative register"; return 1
    fi
    # settle: a guest TPM command arriving mid-setup times out and the
    # firmware DROPS the measurement (the degraded-boot register — s18's
    # _reanchor_tpm evidence); warm the whole path through the proxy first.
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    return 0
}
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -d "$STATE/keys" && -f "$STATE/vars-enrolled.fd" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (bootstrap: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s12: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # ---- bootstrap boot: token-less disk -> the hook's recovery-passphrase
    # path is the ONLY way in (the positive control, miniaturized). The hook
    # has NO read timeout: the feed is prompt-synchronized
    # (uki_wait_hook_prompt).
    for _attempt in 1 2; do
        # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the
        # pristine base (LOCK_SH via overlay_create; discarded after the
        # attempt) — the bootstrap boot cannot persist anything to the base
        # before the HOST-SIDE enrollment below writes the standing token
        OVERLAY_BOOT="$RUN_ENROLLED/disk-bootstrap-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_BOOT" || {
            echo "s12: overlay create failed (bootstrap attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_BOOT" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        overlay_discard "$OVERLAY_BOOT"   # the attempt's overlay is ephemeral
        grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s12: bootstrap boot attempt $_attempt failed"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s12: bootstrap boot did not reach UNSEALED — state unusable"
        exit 1
    }

    # ---- host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the
    # booted console's PCR 7, d11 = the build's enter-initrd prediction; the
    # combined {7,11} entry is what the hook extracts for the finalized token.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s12: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s12: no PCR 7 in the bootstrap console"; exit 1; }
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s12: no enter-initrd d11 prediction from the build"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    EFIVARS="$RUN_ENROLLED/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || {
        echo "s12: production enroll-tpm FAILED"; exit 1; }
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    swtpm_stop "$RUN_ENROLLED/tpm"
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared state into OUR run dir: sibling prunes may remove the
# state dir mid-run; from here on this scenario only touches the local copy
# (the swtpm permall carries the seed -> the copy seals to the same SRK).
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
# REBUILD the payload drive from the state's COMBINED pcrsig json when it
# exists (registry 2026-09-23/24, three runs): the stored pcrsig.img lags the
# finalized combined json (s00b rewrites the json during its majority-vote
# enroll passes), so the drive's {7,11} entry pol != policy_digest(live d7,
# postphase d11) and every zero-input token unlock dies at policyauthorize.
# The combined json is the seal-time G-B6 authority — rebuild from it.
if [[ -f "$STATE/uki-pcrsig-combined.json" ]]; then
    cp "$STATE/uki-pcrsig-combined.json" "$RUN/state/"
    uki_pcrsig_disk "$RUN/state/pcrsig.img" "$RUN/state/uki-pcrsig-combined.json" || {
        echo "s12: cannot rebuild the state payload drive from the combined pcrsig"; exit 1; }
fi
STATE="$RUN/state"
swtpm_start "$STATE/tpm" || { echo "s12: swtpm restart failed"; exit 1; }
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
# NB: no $RUN/disk.img copy — Wave-2 2b: the boot disks are QCOW2 OVERLAYS over
# the protective $STATE snapshot below; the base is copied into $RUN/state
# exactly once and never per boot.
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/harness.efi" || exit 1
# negative fixture: SB off -> the ADR-20 pre-unseal guard blocks the boot
# before ANY unlock attempt (boot A); boot B builds the SB-on drift context
# from the enrolled vars instead (dbx update — see the boot B block below)
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"

# === BOOT A: 3 wrong passphrases -> the hook's 3-strike -> fail-closed ========
A="$RUN/boot-a"
mkdir -p "$A"
cp "$RUN/harness.efi" "$A/harness.efi"
cp "$RUN/pcrsig.img" "$A/pcrsig.img"
cp "$RUN/esp.img" "$A/esp.img"
# Wave-2 2b: the boot runs on a fresh QCOW2 overlay over the pristine state
# base (LOCK_SH via overlay_create) — no per-boot disk copy, and any boot-time
# write dies with the discarded overlay instead of touching the shared base
overlay_create "$STATE/disk.img" "$A/disk.qcow2" || {
    echo "s12: overlay create failed (boot A)"; exit 1; }

echo "# boot A: SB-off vars — the ADR-20 pre-unseal guard must BLOCK (no prompts, no TPM ops)"
_fresh_pcrs "$STATE/tpm" || { echo "s12: cannot zero the TPM PCRs for boot A"; exit 1; }
qemu_run "$A" "$A/esp.img" "$A/disk.qcow2" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$A/pcrsig.img"
# The guard BLOCKS and parks on its "Press Enter" read — the only input is
# the Enter confirmation. Wait for the sentinel with a qemu-liveness poll,
# feed the Enter, wait for the reboot sentinel, then hard-kill qemu BY PID
# (a reboot loop would otherwise run to the timeout).
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_enter)" "$A/console.log" 2>/dev/null; do
    qpid=$(cat "$A/qemu.pid" 2>/dev/null || true)
    [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
    (( i < 300 )) || { echo "s12: the pre-unseal guard never armed (boot A)"; exit 1; }
    sleep 1
    i=$((i + 1))
done
feed_line "$A/serial.sock" ""   # the operator's Enter confirmation
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_reboot)" "$A/console.log" 2>/dev/null; do
    qpid=$(cat "$A/qemu.pid" 2>/dev/null || true)
    [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
    (( i < 60 )) || { echo "s12: the guard never rebooted after Enter (boot A)"; exit 1; }
    sleep 1
    i=$((i + 1))
done
qemu_kill "$A"   # BY PID (tests/lib/qemu.sh)
overlay_discard "$A/disk.qcow2"   # the attempt's overlay is ephemeral
LOG_A=$(cat "$A/console.log" 2>/dev/null || true)

# ordering proof: the guard fired BEFORE any TPM work — no enter-initrd extend
_guard_line=$(grep -nm1 -F "$(sentinel_of unseal_sb_guard)" "$A/console.log" 2>/dev/null | cut -d: -f1)
_ext_line=$(grep -nm1 -F "$(sentinel_of unseal_pcrextend_ok)" "$A/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_guard_line:-}" && -z "${_ext_line:-}" ]]; then
    _assert_result ok "boot A: the guard fired BEFORE any TPM work (line $_guard_line, no extend)" ""
else
    _assert_result not-ok "boot A: the guard fired BEFORE any TPM work" \
        "guard=$_guard_line pcrextend=$_ext_line"
fi

assert_contains "boot A: guard blocking refusal names the pre-unseal guard" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard)"
assert_contains "boot A: the refusal carries the LIVE secureboot=0 reading" "$LOG_A" \
    "secureboot=0"
assert_contains "boot A: Press-Enter confirmation prompt" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_enter)"
assert_contains "boot A: OsIndications boot-to-firmware-setup requested" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_osind)"
assert_contains "boot A: reboot into the firmware setup" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_reboot)"
assert_not_contains "boot A: NO enter-initrd extend (the guard precedes §8.2 step 2)" "$LOG_A" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_not_contains "boot A: NO token discovery (NEVER unsealed with SB off)" "$LOG_A" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "boot A: NO recovery-passphrase prompt (the fallback is RETRACTED under SB off)" "$LOG_A" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "boot A: NO 3-strike path (nothing to strike)" "$LOG_A" \
    "$(sentinel_of unseal_3strike)"
assert_not_contains "boot A: NO fail-closed poweroff (the terminal action is the REBOOT)" "$LOG_A" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "boot A: never unlocked via the TPM token" "$LOG_A" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "boot A: never unlocked via the recovery passphrase" "$LOG_A" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "boot A: never UNSEALED" "$LOG_A" "alpine-fde: UNSEALED"
assert_not_contains "boot A: no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
# tamper scoping: the hook NEVER extended any PCR — the boot's printed PCR 11
# is the raw pre-extend register, IDENTICAL to the enrolled console's print
# (the harness prints PCRs BEFORE invoking the hook; the extend never ran)
PCR11_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)
PCR11_A=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$A/console.log" | head -1 | cut -d= -f2)
assert_eq "boot A: boot PCR 11 is the raw pre-extend register (no extend ran)" \
    "$PCR11_ENROLLED" "$PCR11_A"
# the scenario hard-killed the parked guest (BY PID)
if [[ -f "$A/qemu.pid" ]] && ! kill -0 "$(cat "$A/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "boot A: guest torn down (qemu_kill BY PID after the guard sentinel)" ""
else
    _assert_result not-ok "boot A: guest torn down (qemu_kill BY PID after the guard sentinel)" \
        "qemu still running or qemu.pid missing"
fi

# === BOOT B: SB-ON DRIFT CONTEXT — wrong, wrong, CORRECT -> recovery unlocks ===
# ADR-20 amended: the recovery-passphrase demo must run under a VERIFIED boot
# (the fallback only exists with Secure Boot on). Drift context = the enrolled
# vars + a dbx update (s15's idiom): the firmware measures a NEW PCR 7 while
# SecureBoot stays 1, so the PRE-UNSEAL GUARD PASSES, the {7,11} token's
# PolicyPCR refuses on the stale seal term, and the bounded recovery loop is
# the way out — exactly §9.4's drift-recovery drill, minus the re-enroll.
swtpm_stop "$STATE/tpm"   # free the state dir; boot B needs the same SRK
swtpm_start "$STATE/tpm" || { echo "s12: swtpm start (boot B) failed"; exit 1; }
[[ -f "$STATE/vars-enrolled.fd" ]] || { echo "s12: no enrolled vars in the state snapshot"; exit 1; }
cp "$STATE/vars-enrolled.fd" "$RUN/vars-drifted.fd"
assert_rc "virt-fw-vars: dbx += throwaway cert (SB stays ON, PCR 7 will drift)" 0 \
    virt-fw-vars -i "$RUN/vars-drifted.fd" -o "$RUN/vars-drifted.fd" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$STATE/keys/KEK.crt"
B="$RUN/boot-b"
mkdir -p "$B"
cp "$RUN/harness.efi" "$B/harness.efi"
cp "$RUN/pcrsig.img" "$B/pcrsig.img"
cp "$RUN/esp.img" "$B/esp.img"
# Wave-2 2b: fresh overlay over the SAME pristine base — boot A's writes (if
# any) died with its discarded overlay, so B starts exactly where A started
overlay_create "$STATE/disk.img" "$B/disk.qcow2" || {
    echo "s12: overlay create failed (boot B)"; exit 1; }

echo "# boot B: SB-on drifted vars, 2 wrong + 1 CORRECT passphrase (recovery positive)"
_fresh_pcrs "$STATE/tpm" || { echo "s12: cannot zero the TPM PCRs for boot B"; exit 1; }
qemu_run "$B" "$B/esp.img" "$B/disk.qcow2" "$RUN/vars-drifted.fd" "$STATE/tpm" "$B/pcrsig.img"
for n in 1 2; do
    if uki_wait_hook_prompt "$n" 300 "$B"; then
        _assert_result ok "boot B: hook awaiting recovery passphrase $n/3" ""
    else
        _assert_result not-ok "boot B: hook awaiting recovery passphrase $n/3" \
            "no prompt $n in console"
        break
    fi
    feed_line "$B/serial.sock" "alpine-fde-wrong-passphrase-$n"
done
if uki_wait_hook_prompt 3 300 "$B"; then
    _assert_result ok "boot B: hook awaiting recovery passphrase 3/3" ""
    feed_line "$B/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
else
    _assert_result not-ok "boot B: hook awaiting recovery passphrase 3/3" \
        "no prompt 3 in console"
fi
# Post-unlock exit shape (repro-pinned 2026-09-24): the consumer context boots
# s00b's harness.efi, which BAKES the debug-shell seam (ALPINE_FDE_DEBUG_SHELL)
# for s00b's fed enrollment session. With STAGE=boot (the snapshot payload
# carries no login marker) an unlocked boot reaches UNSEALED + the postphase
# PCR 11 print and then hands the console to the harness DEBUG SHELL instead
# of powering off — the boot sat at "~ #" until the 300 s timeout-kill and
# the POWEROFF sentinel never appeared (registry s12 #27). Handle BOTH exit
# shapes: POWEROFF (own-state UKI) or a fed `poweroff -f` through the debug
# shell (consumer UKI). QEMU-LIVENESS: every poll iteration checks the boot's
# qemu pid.
B_SHAPE=''
i=0
while (( i < 180 )); do
    if grep -q "alpine-fde: POWEROFF" "$B/console.log" 2>/dev/null; then B_SHAPE=poweroff; break; fi
    if grep -q "DEBUG SHELL on console" "$B/console.log" 2>/dev/null; then B_SHAPE=debugshell; break; fi
    qpid=$(cat "$B/qemu.pid" 2>/dev/null || true)
    [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
    sleep 1
    i=$((i + 1))
done
if [[ "$B_SHAPE" == "debugshell" ]]; then
    feed_line "$B/serial.sock" 'poweroff -f'
fi
qemu_wait "$B" "$QEMU_TIMEOUT"
overlay_discard "$B/disk.qcow2"   # the attempt's overlay is ephemeral
LOG_B=$(cat "$B/console.log" 2>/dev/null || true)

assert_contains "boot B: the pre-unseal guard PASSED (SB on — verified boot confirmed)" "$LOG_B" \
    "secureboot=1 setup_mode=0"
assert_contains "boot B: hook ran the enter-initrd extend (the guard let the boot proceed)" "$LOG_B" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "boot B: hook discovered the {7,11} token" "$LOG_B" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "boot B: hook seal refusal on the SB-on PCR 7 drift (the tamper context)" "$LOG_B" \
    "$(sentinel_of unseal_seal_refused)"
# the refusal strictly precedes the first passphrase prompt (the recovery loop
# may only arm AFTER the token path failed)
_refb_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$B/console.log" 2>/dev/null | cut -d: -f1)
_p1b_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$B/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_refb_line:-}" && -n "${_p1b_line:-}" ]] && (( _refb_line < _p1b_line )); then
    _assert_result ok "boot B: hook refusal FIRST (line $_refb_line < first prompt line $_p1b_line)" ""
else
    _assert_result not-ok "boot B: hook refusal FIRST" "ref=$_refb_line prompt1=$_p1b_line"
fi
PROMPTS_B=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG_B" || true)
assert_eq "boot B: exactly 3 prompts (2 wrong + 1 correct, no 4th)" "3" "$PROMPTS_B"
assert_contains "boot B: correct slot-0 passphrase UNLOCKED via the recovery path" "$LOG_B" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "boot B: hook UNSEALED sentinel" "$LOG_B" "alpine-fde: UNSEALED"
assert_not_contains "boot B: never unlocked via the TPM token (PCR 7 drift refused the seal)" "$LOG_B" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "boot B: no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
# Clean-exit assertion, shape-aware (see the B_SHAPE detection above): the
# own-state UKI prints the harness POWEROFF sentinel; the consumer-context
# s00b UKI hands the unlocked console to its baked-in DEBUG SHELL and the
# scenario feeds the fail-closed `poweroff -f` — the boot still exits by its
# own poweroff, never a timeout-kill.
if [[ "$B_SHAPE" == "debugshell" ]]; then
    assert_contains "boot B: clean poweroff sentinel (debug-shell UKI shape)" "$LOG_B" \
        "DEBUG SHELL on console"
else
    assert_contains "boot B: clean poweroff sentinel" "$LOG_B" "$(sentinel_of harness_poweroff)"
fi
# G-T13/G-E9: boot B UNSEALED, so /init printed the post-hook postphase
# reading — the hook's single enter-initrd extend must land exactly on the
# booted UKI's signed prediction
_CONSOLE_SAVE="$CONSOLE"
CONSOLE="$B/console.log"
assert_pcr11_prediction "S-12 [B]"
CONSOLE="$_CONSOLE_SAVE"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "boot B: guest exited (poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "boot B: guest exited (poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# keep run dirs small
rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s12-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s12-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
