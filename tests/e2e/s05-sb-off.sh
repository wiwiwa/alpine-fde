#!/usr/bin/env bash
# tests/e2e/s05-sb-off.sh — §10 row "SB disabled / firmware keys changed",
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13):
#   Boots? ✅ (SB off -> firmware boots the unsigned-for-it UKI)
#   Auto-unlock? ❌ — PCR 7 carries the firmware-measured SB state; with the
#   platform in setup mode / custom keys gone, PCR 7 drifts away from the
#   value the FINALIZED {PCR 7, PCR 11} Mechanism B token was enrolled under
#   -> the hook's PolicyPCR({7,11}) session digest no longer matches the
#   sealed policy -> tpm2_unseal refuses ("the TPM refused the sealed blob
#   under the current PCR state") -> the hook's BOUNDED recovery-passphrase
#   loop reads keyslot-0 lines from /dev/console -> three wrong answers ->
#   3-strike fail-closed `poweroff -f` (NO shell is ever offered).
#
# REQUIRED (hook sentinels, tests/sentinels-260.2.txt Section 1): PCRs
#           printed (7 non-zero: SB-off state is measured too), PCR 7
#           differs from the enrolled boot's PCR 7, PCR 11 UNCHANGED (the
#           refusal is purely the PCR 7 drift), unseal_token_info
#           (pcrs=[7,11]), unseal_seal_refused, exactly 3 prompts fed,
#           unseal_3strike, unseal_poweroff; unseal_unlocked / UNSEALED /
#           emergency shell NEVER; guest exited by its own poweroff.
#
# NB (G-T13): NO assert_pcr11_prediction on this boot — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading. The PCR 11 unchanged-equality vs the enrolled console below
# is the equivalent tamper-scoping evidence (the drift is PCR 7 only).
#
# Self-bootstrap when ALPINE_FDE_E2E_STATE is absent: baseline boot (token-less
# disk -> the hook's recovery-passphrase path, the positive control) + the
# REAL production CLI enroll-tpm host-side against the fixture swtpm (the
# finalized {7,11} token), then the SB-off boot. 2 boots.

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
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH

RUN="$TESTS/e2e/.runs/s05-lite-$(date +%s)"
mkdir -p "$RUN"
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
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" && -d "$STATE/keys" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no state — self-bootstrapping (boot 1 of 2: baseline boot + host-side enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s05: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1

    # ---- baseline boot: token-less disk -> the hook's recovery-passphrase
    # path is the ONLY way in (positive control for the loop s05 then drives
    # to a 3-strike on the SB-off boot). The hook has NO read timeout: the
    # feed is prompt-synchronized (uki_wait_hook_prompt).
    for _attempt in 1 2; do
        # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the
        # pristine token-less base (LOCK_SH via overlay_create; discarded
        # after the attempt) — the bootstrap boot cannot persist anything to
        # the base before the HOST-SIDE enrollment below writes the standing
        # token (the enroll stays the only writer of disk.img)
        OVERLAY_B1="$RUN_ENROLLED/disk-baseline-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_B1" || {
            echo "s05: overlay create failed (baseline attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_B1" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        overlay_discard "$OVERLAY_B1"   # the attempt's overlay is ephemeral
        grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s05: baseline boot attempt $_attempt failed"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s05: baseline boot did not reach UNSEALED — state unusable"
        exit 1
    }

    # ---- host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data):
    #   d7  = the booted console's PCR 7 (the enrolled SB state)
    #   d11 = ukify --measure's enter-initrd prediction (== the hook's
    #         post-extend PCR 11 at enroll time, == every future boot of THIS
    #         UKI: the stub + the hook's single phase extend re-derive it)
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s05: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s05: no PCR 7 in the baseline console"; exit 1; }
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s05: no enter-initrd d11 prediction from the build"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    assert_eq "combined .pcrsig entry pol == policy_digest(booted d7, enter-initrd d11) (G-B6 shape)" \
        "$(policy_digest "$PCR7_ENROLLED" "$D11")" \
        "$(jq -r '.sha256[-1].pol' "$RUN_ENROLLED/uki-pcrsig-combined.json")"
    # the payload drive of EVERY subsequent boot must carry the combined entry
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    # the efivars seam presents the final SB state to enroll-tpm's I5 guard
    # (mkvar pattern from s00/tests/unit/baseline_finalize_guard.sh)
    EFIVARS="$RUN_ENROLLED/cli-state/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    uki_host_enroll_finalized "$RUN_ENROLLED/cli-state/efivars-sb-on" \
        "$RUN_ENROLLED/uki-pcrsig-combined.json" "$RUN_ENROLLED/disk.img" \
        "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" "$RUN_ENROLLED/cli-state" || {
        echo "s05: production enroll-tpm FAILED"; exit 1; }
    # positive control: the standing token is the finalized {7,11} dash-form
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    assert_contains "standing token carries tpm2-signature (§7.2)" "$TOK" '"tpm2-signature"'
    swtpm_stop "$RUN_ENROLLED/tpm"
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared state into OUR run dir: sibling prunes may remove the
# state dir mid-run; from here on this scenario only touches the local copy.
# The swtpm dir copy is PERMALL-ONLY: PCRs reset, the SRK seed persists — the
# SB-off boot re-derives PCR 7/11 from the firmware + the same UKI, exactly
# like the enrolled boot did.
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/state/" \
    || cp "$STATE/uki-pcrsig-combined.json" "$RUN/state/uki-pcrsig.json" 2>/dev/null
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"

# swtpm: the SRK must be the one the token is sealed to -> reuse the state dir
swtpm_start "$STATE/tpm" || { echo "s05: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
# NB: no $RUN/disk.img copy — Wave-2 2b: the SB-off boot runs on a QCOW2
# OVERLAY over the protective $RUN/state snapshot base; the base is copied
# into $RUN/state exactly once and never per boot, and the boot (a terminal
# 3-strike fail-closed leg) persists nothing.
# tamper = stock vars copy (no PK, SecureBoot off): SB disabled, keys gone
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
assert_not_contains "unenrolled vars: no PK" "$(keys_vars_get "$RUN/vars-unenrolled.fd" PK)" "blob"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot with SB OFF ----------------------------------------------------------
echo "# booting: SB-off vars + finalized-token disk, feeding 3 WRONG passphrases (TCG, up to $QEMU_TIMEOUT s) ..."
# Wave-2 2b: the scenario boot consumes the enrolled base read-mostly — fresh
# QCOW2 overlay (LOCK_SH via overlay_create), discarded after the boot
OVERLAY_SB_OFF="$RUN/disk-sboff.qcow2"
overlay_create "$RUN/state/disk.img" "$OVERLAY_SB_OFF" || {
    echo "s05: overlay create failed (SB-off boot)"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$OVERLAY_SB_OFF" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"
for n in 1 2 3; do
    if uki_wait_hook_prompt "$n" 300 "$RUN"; then
        _assert_result ok "guest awaiting recovery passphrase $n/3 (hook read path)" ""
        feed_line "$RUN/serial.sock" "alpine-fde-wrong-passphrase-$n"
    else
        _assert_result not-ok "guest awaiting recovery passphrase $n/3 (hook read path)" \
            "no prompt $n in console"
        break
    fi
done
qemu_wait "$RUN" "$QEMU_TIMEOUT"
overlay_discard "$OVERLAY_SB_OFF"   # the boot's overlay is ephemeral
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- PCR forensics -------------------------------------------------------------
pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR7=$(pcr_of "$CONSOLE" 7)
PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
PCR11=$(pcr_of "$CONSOLE" 11)
PCR11_ENROLLED=$(pcr_of "$STATE/console.log" 11)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran" "$LOG" "alpine-fde-harness: init started"
assert_contains "TPM char device appeared" "$LOG" "/dev/tpmrm0 present"
assert_contains "firmware booted the UKI despite SB off (init + PCRs)" "$LOG" "alpine-fde-pcr sha256:7=$PCR7"
ZERO=$(printf '0%.0s' {1..64})
if [[ -n "$PCR7" && "$PCR7" != "$ZERO" ]]; then
    _assert_result ok "PCR 7 non-zero (SB-off state measured by firmware)" ""
else
    _assert_result not-ok "PCR 7 non-zero (SB-off state measured by firmware)" "PCR7=${PCR7:-absent}"
fi
if [[ -n "$PCR7" && "$PCR7" != "$PCR7_ENROLLED" ]]; then
    _assert_result ok "PCR 7 drifted vs enrolled boot (7=$PCR7 vs enrolled 7=$PCR7_ENROLLED)" ""
else
    _assert_result not-ok "PCR 7 drifted vs enrolled boot" \
        "PCR7=$PCR7 enrolled=$PCR7_ENROLLED"
fi
assert_eq "PCR 11 unchanged (refusal is purely PCR 7 drift)" "$PCR11_ENROLLED" "$PCR11"

# --- the hook's refusal, prompts, and 3-strike fail-closed (§8.2) ---------------
assert_contains "hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "hook discovered the {7,11} token" "$LOG" "$(sentinel_of unseal_token_info)7,11]"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "hook refused the sealed blob BEFORE any passphrase prompt (line $_ref_line < $_p1_line)" ""
else
    _assert_result not-ok "hook refused the sealed blob BEFORE any passphrase prompt" \
        "ref=$_ref_line prompt1=$_p1_line"
fi
assert_contains "hook refusal sentinel (PCR 7 drift)" "$LOG" "$(sentinel_of unseal_seal_refused)"
PROMPTS=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS"
assert_contains "3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "fail-closed poweroff (no shell is offered)" "$LOG" "$(sentinel_of unseal_poweroff)"
assert_not_contains "never unlocked via the TPM token" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "never unlocked via the recovery passphrase" "$LOG" "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "never UNSEALED (harness sentinel)" "$LOG" "alpine-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# IN-08: an absent pid file (qemu_run failed outright) must not read as a
# clean "guest exited" — the check is honest in both directions
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (hook poweroff -f, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (hook poweroff -f, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# keep run dirs small (state dir is not ours to prune)
rm -rf "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s05-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s05-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
