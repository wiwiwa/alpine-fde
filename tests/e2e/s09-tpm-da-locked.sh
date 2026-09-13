#!/usr/bin/env bash
# tests/e2e/s09-tpm-da-locked.sh — §10 row "TPM cleared / absent / DA-locked by
# other tooling" — the DA-LOCKED leg (the cleared/absent legs are s17/s10).
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
#                 harness init still run to the unlock point (PCR extends and
#                 pcrreads are auth-less; verified pcrread rc=0 while locked).
#   Auto-unlock?  see the SWTPM LENIENCY note below — in-guest this sandbox
#                 CANNOT show the ❌; the row's refusal/fallback chain is
#                 exercised via the PCR 7 drift vector instead.
#   Way out:      the fallback prompt, with BOUNDED retries: the
#                 `debian-fde-console-fallback` UKI variant arms the console
#                 passphrase loop only AFTER the token refusal; three fed WRONG
#                 lines are rejected by real cryptsetup (cryptsetup_nokey), the
#                 loop EXHAUSTS at exactly 3 (no 4th attempt), PROMPT-FAILED,
#                 clean poweroff. NEVER a hang, NEVER `Entering emergency mode.`
#
# SWTPM LENIENCY (empirical, this sandbox, 2026-09-17 — UNVERIFIED-here):
# with the lockout armed AND enforcement-probe-positive before and after the
# boot, the real 257.13 systemd-cryptsetup token path still UNSEALED —
# libtpms/swtpm does not gate POLICY-session unseals on the lockout (the seal
# path has no authValue, §7.1, so there is nothing for DA to gate on this TPM
# implementation). The pinned `da_locked` sentinel ("TPM2 device is in
# dictionary attack lockout mode." — libsystemd-shared-257.so, consumed via the
# table) is therefore UNREACHABLE in-guest here and is NOT asserted; on real
# hardware the same armed lockout is what refuses the token path with exactly
# that sentinel (same leniency class as the swtpm caveat already pinned in
# docs/Architecture.md §6.1.1: negative crypto must not be proven on swtpm
# alone). What IS asserted about the lockout is host-side and real: armed →
# enforced before the boot → still enforced after the boot (the guest changed
# nothing) — plus, for the refusal chain, the SB-off variables make the token
# path fail in-guest for the row's real second effect (PCR 7 no longer matches
# the static seal term), driving the documented bounded fallback.
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
#     armed one); (b) the console refusal class is the PCR-drift unseal
#     refusal, never an auth-guessing sentinel — the boot consumed no budget.
# Production evidence for §7.1 lives in the systemd seal path (policy sessions,
# no authValue); the swtpm quirk is documented instead of asserted away.
#
# Reuses s00 artifacts when DEBIAN_FDE_E2E_STATE points at the s00 run dir
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

# wait_attempt: s12 pattern (counting occurrences survives kernel printk
# interleave).
wait_attempt() {
    local n="$1" tmo="$2" dir="$3" i=0 c
    while ((i < tmo)); do
        c=$(grep -cF "awaiting console line" "$dir/console.log" 2>/dev/null || true)
        [[ -n "$c" ]] && ((c >= n)) && return 0
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# --- enrolled state: reuse s00's or bootstrap it (boot 1) -----------------------
STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (boot 1 of 2: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s09: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    esp_make "$RUN_ENROLLED/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s09: enroll boot attempt $_attempt failed"
        ((_attempt < 2)) && { swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1; }
        rm -f "$RUN_ENROLLED/console.log"
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s09: enroll boot did not reach UNSEALED — state unusable"; exit 1; }
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

# --- console-fallback UKI variant (signed: extra cmdline word) -------------------
echo "# building console-fallback UKI (cmdline + debian-fde-console-fallback)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" "debian-fde-console-fallback" || exit 1
assert_file_exists "console-fallback UKI built" "$RUN/harness.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/harness.efi" || exit 1
# SB-off vars: with swtpm's DA leniency (header note) the in-guest refusal
# vector for the fallback chain is the PCR 7 drift of the static seal term —
# the locked TPM itself refuses nothing in-guest on this TPM implementation.
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

# --- boot 2: DA-locked TPM + fallback variant ------------------------------------
B="$RUN/boot-locked"
mkdir -p "$B"
cp "$RUN/harness.efi" "$B/harness.efi"
cp "$RUN/pcrsig.img" "$B/pcrsig.img"
cp "$RUN/esp.img" "$B/esp.img"
cp "$STATE/disk.img" "$B/disk.img"
echo "# boot: DA-locked TPM, SB-off vars, console fallback armed (TCG, up to $QEMU_TIMEOUT s)"
qemu_run "$B" "$B/esp.img" "$B/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$B/pcrsig.img"
for n in 1 2 3; do
    if wait_attempt "$n" 300 "$B"; then
        _assert_result ok "guest awaiting passphrase $n/3 (fallback armed after refusal)" ""
    else
        _assert_result not-ok "guest awaiting passphrase $n/3" "no attempt $n marker in console"
        break
    fi
    feed_line "$B/serial.sock" "debian-fde-da-wrong-passphrase-$n"
done
qemu_wait "$B" "$QEMU_TIMEOUT"
LOG=$(cat "$B/console.log" 2>/dev/null || true)

# --- assertions: locked TPM boots -> refusal -> bounded fallback -> poweroff -----
assert_contains "init ran (boot reached the UKI despite the locked TPM — the row's ✅)" "$LOG" \
    "debian-fde-harness: init started"
assert_contains "TPM char device appeared (locked TPM still serves auth-less ops)" "$LOG" \
    "/dev/tpmrm0 present"
if grep -qE "debian-fde-pcr sha256:7=[0-9a-f]{64}" "$B/console.log" 2>/dev/null; then
    _assert_result ok "PCR 7 printed while locked (auth-less ops unaffected)" ""
else
    _assert_result not-ok "PCR 7 printed while locked (auth-less ops unaffected)" \
        "no debian-fde-pcr line in console.log"
fi
assert_contains "enrollment SKIPPED (token present — only the TPM state changed)" "$LOG" \
    "systemd-tpm2 token present — skipping enrollment"
assert_contains "token discovered (the token path is attempted)" "$LOG" \
    "$(sentinel_of token_discovered)"
assert_contains "token path refused (see header: refusal vector under swtpm leniency)" "$LOG" \
    "$(sentinel_of tpm2_refused)"
# the refusal must strictly precede the first passphrase attempt (the fallback
# loop may only arm AFTER the token path failed)
_ref_line=$(grep -nm1 -F "$(sentinel_of tpm2_refused)" "$B/console.log" 2>/dev/null | cut -d: -f1)
_att1_line=$(grep -nm1 -F "passphrase attempt 1/3" "$B/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_att1_line:-}" ]] && (( _ref_line < _att1_line )); then
    _assert_result ok "token refusal FIRST (line $_ref_line < first attempt line $_att1_line)" ""
else
    _assert_result not-ok "token refusal FIRST" "ref=$_ref_line attempt1=$_att1_line"
fi
assert_contains "fallback armed only after the refusal" "$LOG" \
    "debian-fde-harness: token refused (rc="
for n in 1 2 3; do
    assert_contains "wrong passphrase $n rejected by real cryptsetup" "$LOG" \
        "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc="
done
if [[ "$(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)" == "3" ]]; then
    _assert_result ok "exactly 3 passphrase attempts (bounded retries, no 4th)" ""
else
    _assert_result not-ok "exactly 3 passphrase attempts (bounded retries, no 4th)" \
        "rejection lines: $(grep -cF 'rejected (cryptsetup rc=' <<<"$LOG" || true)"
fi
assert_contains "cryptsetup evidence (sentinel cryptsetup_nokey)" "$LOG" \
    "$(sentinel_of cryptsetup_nokey)"
assert_contains "PROMPT-FAILED (retries exhausted, deterministic end)" "$LOG" \
    "debian-fde: PROMPT-FAILED"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_not_contains "interactive prompt never appeared (harness loop is the fallback)" "$LOG" \
    "$(sentinel_of prompt_re)"
assert_contains "clean poweroff sentinel" "$LOG" "debian-fde: POWEROFF"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (poweroff, not timeout-kill — no hang)" ""
else
    _assert_result not-ok "guest exited (poweroff, not timeout-kill — no hang)" \
        "qemu still running or qemu.pid missing"
fi

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
