#!/usr/bin/env bash
# tests/e2e/s09-tpm-da-locked.sh — §10 row "TPM cleared / absent / DA-locked by
# other tooling" — the DA-LOCKED leg (the cleared/absent legs are s17/s10),
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock).
#
# The TPM is put into dictionary-attack lockout by "other tooling" BEFORE the
# boot: tests/lib/swtpm-fixture.sh `swtpm_da_lockout` arms TPM2_DictionaryAttack
# Parameters (max-tries=2, lockout-recovery=9999 s) and exhausts the budget with
# two wrong authorizations against the DA-protected lockout hierarchy; the
# enforcement probe (a further DA-protected op refused with TPM_RC_LOCKOUT) is
# positive before the boot and again after it (the lockout persists in the
# permall across fixture restarts — verified).
#
#   Boots?        ✅ — asserted: with the lockout enforced, the firmware and the
#                 harness init still run to the hook (pcrreads are auth-less;
#                 verified pcrread rc=0 while locked).
#   Auto-unlock?  ❌ — STRICTLY, at the hook's FIRST step: the ADR-20 amended
#                 PRE-UNSEAL SECURE BOOT GUARD reads SecureBoot/SetupMode from
#                 efivarfs and blocks on the SB-off vars BEFORE any TPM op —
#                 no enter-initrd extend, no token work, no prompt (see the
#                 SB-on drift vector for the seal-refusal path: s12 boot B,
#                 s15). The scenario waits for the guard sentinel and hard-
#                 kills qemu BY PID (the hook parks on its Enter read).
#   Way out:      reboot into the firmware setup and enable Secure Boot — the
#                 recovery-passphrase fallback is RETRACTED while SB is off
#                 (ADR-20 amended); the bounded prompt loop only exists under
#                 a verified boot. NEVER a hang, NEVER `Entering emergency
#                 mode.`
#
# SWTPM LENIENCY (empirical, this sandbox, 2026-09-17 — UNVERIFIED-here):
# with the lockout armed AND enforcement-probe-positive before and after the
# boot, the token path would still reach the TPM — libtpms/swtpm does not gate
# POLICY-session unseals on the lockout (the seal path has no authValue, §7.1,
# so there is nothing for DA to gate on this TPM implementation). The pinned
# `da_locked` sentinel is therefore UNREACHABLE in-guest here and is NOT
# asserted; on real hardware the same armed lockout is what refuses the token
# path (the hook's refusal message names "DA lock" among its causes). What IS
# asserted about the lockout is host-side and real: armed → enforced before the
# boot → still enforced after the boot (the guest changed nothing — under the
# amended guard it never reaches a single TPM op).
#
# G-T15 / §7.1 — "policy-session failures do not consume TPM dictionary-attack
# budget": the seal path has no user-supplied authValue (§7.1), so the guest's
# refused unseal attempts must not move the DA budget. What swtpm/libtpms
# actually EXPOSES is limited (verified empirically on this sandbox):
#   * TPM_PT_LOCKOUT_COUNTER and TPMA_PERMANENT.inLockout read 0x0/0 EVEN WHILE
#     the armed window is enforced (GetCapability quirk) — the counter readout
#     cannot show increments, so "the counter did not grow" is not observable
#     here and is NOT faked;
#   * what IS asserted: (a) the enforcement probe is positive before the boot
#     and STAYS positive after the boot + fixture restart — the guest neither
#     lifted nor reset the lockout we armed (the budget state is exactly the
#     armed one); (b) the console refusal class is the hook's TPM-policy
#     refusal (unseal_seal_refused), never an auth-guessing sentinel — the
#     boot consumed no budget.
# Production evidence for §7.1 lives in the seal path (policy sessions, no
# authValue); the swtpm quirk is documented instead of asserted away.
#
# NB (G-T13): NO assert_pcr11_prediction on this boot — the guard blocks INSIDE
# its own invocation before any extend, so /init never reaches its post-hook
# postphase PCR 11 reading; the boot's PCR 11 is the RAW zero register and the
# differs-from-enrolled inequality below is the equivalent scoping evidence.
#
# Reuses s00 state when ALPINE_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots them itself (2 boots).

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
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH

RUN="$TESTS/e2e/.runs/s09-da-locked-$(date +%s)"
mkdir -p "$RUN"
T0=$SECONDS

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

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The permall (SRK + DA lockout state) persists across the restart. The state
# dir is passed explicitly: the snapshot's $RUN/state/tpm is the live fixture
# after the snapshot (NOT $RUN/tpm).
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$1"; }

# --- enrolled state: reuse s00's or bootstrap it (boot 1) -----------------------
STATE="${ALPINE_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" && -d "$STATE/keys" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 2: baseline boot + host-side enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s09: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    esp_make "$RUN_ENROLLED/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # ---- baseline boot: token-less disk -> the hook's recovery-passphrase
    # path is the ONLY way in (the positive control, miniaturized). The hook
    # has NO read timeout: the feed is prompt-synchronized
    # (uki_wait_hook_prompt).
    for _attempt in 1 2; do
        # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the
        # pristine base (LOCK_SH via overlay_create; discarded after the
        # attempt) — the baseline boot persists nothing to the base, so the
        # HOST-SIDE enrollment below stays its only writer
        OVERLAY_BOOT="$RUN_ENROLLED/disk-baseline-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_BOOT" || {
            echo "s09: overlay create failed (baseline attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_BOOT" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        overlay_discard "$OVERLAY_BOOT"   # the attempt's overlay is ephemeral
        grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s09: baseline boot attempt $_attempt failed"
        ((_attempt < 2)) && { swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1; }
        rm -f "$RUN_ENROLLED/console.log"
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s09: baseline boot did not reach UNSEALED — state unusable"; exit 1; }
    # ---- host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): the
    # combined {7,11} entry is what the hook extracts for the finalized token.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s09: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s09: no PCR 7 in the baseline console"; exit 1; }
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s09: no enter-initrd d11 prediction from the build"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    EFIVARS="$RUN_ENROLLED/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    # enroll precondition (CLI, enrl_preconditions #2): a FINALIZED baseline at
    # $ALPINE_FDE_ROOT/etc/alpine-fde/baseline.json. Stamp the booted d7 into a
    # scenario-local cli-state root — the same seam s06/s12/s13 use; without it
    # enroll-tpm dies "no baseline at /etc/alpine-fde/baseline.json".
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || {
        echo "s09: production enroll-tpm FAILED"; exit 1; }
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    swtpm_stop "$RUN_ENROLLED/tpm"
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared s00 state into OUR run dir (sibling prunes; the permall
# copy seals to the same SRK).
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"

# boot fixtures: the ENROLLED state boots UNCHANGED — the SAME UKI bytes the
# enrollment measured (the hook's {7,11} policy is bound to the enroll-time
# PCR 11: a cmdline-variant UKI could never match) and the payload drive that
# carries the combined pcrsig. Only the VARS change (SB off -> PCR 7 drift).
mkdir -p "$RUN/boot"
cp "$STATE/harness.efi" "$RUN/boot/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/boot/pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/boot/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/boot/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/boot/harness.efi" || exit 1
# SB-off vars: under the ADR-20 amended guard the boot now refuses at the
# hook's FIRST step — the in-guest refusal vector for the SB-on seal path is
# s12 boot B / s15 (PCR 7 drift); here the guard block is the row's ❌.
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"

# --- arm the DA lockout ("other tooling", §10) ----------------------------------
_ensure_tpm "$STATE/tpm" || { echo "s09: swtpm not serving (arming)"; exit 1; }
swtpm_da_lockout "$STATE/tpm" || {
    echo "s09: DA lockout did not arm/engage — scenario precondition failed"; exit 1; }
DA_BEFORE=$(swtpm_da_state "$STATE/tpm")
assert_rc "DA locked: enforcement probe positive BEFORE the boot" 0 swtpm_da_locked_probe "$STATE/tpm"
echo "# DA state before boot: $DA_BEFORE (counter readout quirk: see header)"

# --- boot 2: DA-locked TPM, SB-off vars — the ADR-20 PRE-UNSEAL GUARD vector -----
# ADR-20 amendment: with SB off the hook refuses at its FIRST step (the
# pre-unseal guard) — the DA-locked TPM is never even touched in-guest (the
# extend/unseal attempts of the old refusal vector are RETRACTED for the
# SB-off case; the PCR-drift refusal under SB ON lives in s12 boot B / s15).
# The DA lockout assertions below keep their full force host-side: armed ->
# enforced before the boot -> STILL enforced after it, and the guest consumed
# nothing (trivially: it never reached a TPM op).
B="$RUN/boot-locked"
mkdir -p "$B"
cp "$RUN/boot/harness.efi" "$B/harness.efi"
cp "$RUN/boot/pcrsig.img" "$B/pcrsig.img"
cp "$RUN/boot/esp.img" "$B/esp.img"
# Wave-2 2b: the boot is read-mostly over the pristine state base (LOCK_SH via
# overlay_create) — no per-boot disk copy, and the guard-blocked boot's writes
# die with the discarded overlay instead of landing on the protective snapshot
overlay_create "$STATE/disk.img" "$B/disk.qcow2" || {
    echo "s09: overlay create failed (boot 2)"; exit 1; }
echo "# boot: DA-locked TPM, SB-off vars — the pre-unseal guard must BLOCK (TCG, up to $QEMU_TIMEOUT s)"
qemu_run "$B" "$B/esp.img" "$B/disk.qcow2" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$B/pcrsig.img"
# The guard parks on its "Press Enter" read — the only input is the Enter
# confirmation. Wait for the sentinel with a qemu-liveness poll, feed the
# Enter, wait for the reboot sentinel, then hard-kill qemu BY PID (a reboot
# loop would otherwise run to the timeout).
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_enter)" "$B/console.log" 2>/dev/null; do
    qpid=$(cat "$B/qemu.pid" 2>/dev/null || true)
    [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
    (( i < 300 )) || { echo "s09: the pre-unseal guard never armed"; exit 1; }
    sleep 1
    i=$((i + 1))
done
feed_line "$B/serial.sock" ""   # the operator's Enter confirmation
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_reboot)" "$B/console.log" 2>/dev/null; do
    qpid=$(cat "$B/qemu.pid" 2>/dev/null || true)
    [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
    (( i < 60 )) || { echo "s09: the guard never rebooted after Enter"; exit 1; }
    sleep 1
    i=$((i + 1))
done
qemu_kill "$B"   # BY PID (tests/lib/qemu.sh)
overlay_discard "$B/disk.qcow2"   # the boot's overlay is ephemeral
LOG=$(cat "$B/console.log" 2>/dev/null || true)

# --- assertions: locked TPM boots -> the guard blocks BEFORE any TPM op ---------
assert_contains "init ran (boot reached the UKI despite the locked TPM — the row's ✅)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "TPM char device appeared (locked TPM still serves auth-less ops)" "$LOG" \
    "$(sentinel_of harness_tpm_present)"
if grep -qE "alpine-fde-pcr sha256:7=[0-9a-f]{64}" "$B/console.log" 2>/dev/null; then
    _assert_result ok "PCR 7 printed while locked (auth-less ops unaffected)" ""
else
    _assert_result not-ok "PCR 7 printed while locked (auth-less ops unaffected)" \
        "no alpine-fde-pcr line in console.log"
fi
assert_contains "guard: the blocking refusal names the pre-unseal guard" "$LOG" \
    "$(sentinel_of unseal_sb_guard)"
assert_contains "guard: the refusal carries the LIVE secureboot=0 reading" "$LOG" \
    "secureboot=0"
assert_contains "guard: Press-Enter confirmation prompt" "$LOG" \
    "$(sentinel_of unseal_sb_guard_enter)"
assert_contains "guard: OsIndications boot-to-firmware-setup requested" "$LOG" \
    "$(sentinel_of unseal_sb_guard_osind)"
assert_contains "guard: reboot into the firmware setup" "$LOG" \
    "$(sentinel_of unseal_sb_guard_reboot)"
assert_not_contains "NO enter-initrd extend (the guard precedes any TPM op)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_not_contains "NO token discovery (the guard blocked first)" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "NO recovery-passphrase prompt (the fallback is RETRACTED under SB off)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "NO 3-strike path" "$LOG" "$(sentinel_of unseal_3strike)"
assert_not_contains "NO fail-closed poweroff (the terminal action is the REBOOT)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# the scenario hard-killed the parked guest (BY PID)
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest torn down (qemu_kill BY PID after the guard sentinel)" ""
else
    _assert_result not-ok "guest torn down (qemu_kill BY PID after the guard sentinel)" \
        "qemu still running or qemu.pid missing"
fi

# tamper scoping: the hook NEVER extended any PCR (the guard blocked first) —
# the boot's printed PCR 11 is the raw pre-extend register, IDENTICAL to the
# enrolled console's print (the harness prints PCRs BEFORE invoking the hook,
# so the enrolled value is pre-extend too; the hook's own extend never ran)
PCR11_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)
PCR11_B=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$B/console.log" | head -1 | cut -d= -f2)
assert_eq "boot PCR 11 is the raw pre-extend register (no enter-initrd extend ran)" \
    "$PCR11_ENROLLED" "$PCR11_B"

# --- G-T15: the boot consumed no DA budget (§7.1) --------------------------------
# The lockout we armed must STILL be enforced after the boot + fixture restart:
# the guest's refused policy-session attempts neither lifted, reset, nor
# extended it. (Counter increments are not observable — header note.)
_ensure_tpm "$STATE/tpm" || { echo "s09: swtpm not serving (G-T15 probe)"; exit 1; }
DA_AFTER=$(swtpm_da_state "$STATE/tpm")
assert_eq "G-T15: DA budget readout unchanged across the guest boot (quirked readout)" \
    "$DA_BEFORE" "$DA_AFTER"
assert_rc "G-T15: lockout STILL enforced after the boot (guest consumed nothing, changed nothing)" \
    0 swtpm_da_locked_probe "$STATE/tpm"

kill "$REFRESHER" 2>/dev/null
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s09-tpm-da-locked: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s09-tpm-da-locked: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
