#!/usr/bin/env bash
# tests/e2e/s07-loader-options.sh — §12 tamper row: "tampered loader-entry
# `options` (must fail — systemd-stub measures the effective cmdline into
# PCR 11)".
#
# Implementation note (task deviation, empirically pinned 2026-09-14): the
# task's literal "loader/entries .conf with modified options" does NOT reach
# a UKI on this stack — sd-boot boots a type1 UKI entry but DROPS its
# `options` line; firmware Boot#### OptionalData handling varies by build;
# and UKI addons are not picked up by this stub build (verified 2026-09-14;
# see tests/e2e/README.md). The loader-level cmdline injection is therefore
# structurally unreliable in this stack — itself a relevant fail-closed
# finding (documented in tests/e2e/README.md).
#
# The INVARIANT under test — I5: a UKI unseals iff signature-valid AND the
# trial digest over the CURRENT PCR 7 + PCR 11 values is release-key-signed
# and present in the token — is exercised via a release-key-signed UKI
# VARIANT whose .cmdline carries one extra word (the compromised-signer
# model: a backdoored cmdline inside otherwise-valid signed artifacts).
# systemd-stub measures the tampered .cmdline into PCR 11 -> the live PCR 11
# at the hook's policy session drifts away from the value the shipped
# (stale, clean-cmdline) combined .pcrsig entry was signed over -> the
# hook's PolicyAuthorize admits the (validly signed) entry but the policy
# session no longer matches -> tpm2_unseal refuses (unseal_seal_refused) ->
# the hook's BOUNDED recovery-passphrase loop -> 3 wrong answers -> 3-strike
# fail-closed `poweroff -f` (§8.2; ADR-13 — the harness DEFAULT unlock). The
# guest's `alpine-fde-cmdline` print proves the tamper actually reached the
# kernel (without it, a refusal could be a false pass from an unrelated
# mismatch).
#
# NB (G-T13): NO assert_pcr11_prediction on this boot — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading; the pre-extend PCR 11 drift vs the enrolled console is the
# equivalent tamper-scoping evidence (the tampered cmdline is measured by the
# stub BEFORE the hook's phase extension).
#
# REQUIRED: init ran; alpine-fde-cmdline contains the extra word; PCR 11
#           differs from the enrolled boot; unseal_token_info (pcrs=[7,11]);
#           unseal_seal_refused BEFORE the first prompt; exactly 3 prompts
#           fed; unseal_3strike + unseal_poweroff; unlocked / UNSEALED /
#           emergency shell NEVER; guest exited by its own poweroff.
#
# Reuses the enrolled s00b state when ALPINE_FDE_E2E_STATE points at the s00b
# run dir (run-e2e.sh sets it); otherwise builds + enrolls it itself
# (bootstrap boot + host-side production enroll, then the tamper boot).

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

RUN="$TESTS/e2e/.runs/s07-lite-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
TAMPER_WORD="alpine-fde-loader-tamper"

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
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" && -d "$STATE/keys" \
    && -f "$STATE/vars-enrolled.fd" ]]; then
    echo "# reusing enrolled state from $STATE"
else
    echo "# no state — self-bootstrapping (boot 1 of 2: baseline boot + host-side enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s07: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # baseline boot: token-less disk -> the hook's recovery-passphrase path
    # (prompt-synchronized feed: the hook has NO read timeout); the TPM must
    # be RESET on retry so PCR 11 carries only one phase extension
    for _attempt in 1 2; do
        # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the
        # pristine token-less base (LOCK_SH via overlay_create; discarded
        # after the attempt) — the bootstrap boot cannot persist anything to
        # the base before the HOST-SIDE enrollment below writes the standing
        # token
        OVERLAY_B1="$RUN_ENROLLED/disk-baseline-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_B1" || {
            echo "s07: overlay create failed (baseline attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_B1" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        qemu_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT"
        overlay_discard "$OVERLAY_B1"   # the attempt's overlay is ephemeral
        grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s07: baseline boot attempt $_attempt failed"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s07: baseline boot did not reach UNSEALED — state unusable"
        exit 1
    }
    # host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted console's PCR 7, d11 = the
    # build's enter-initrd prediction; the combined {7,11} entry is what the
    # hook extracts for the finalized token.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s07: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s07: no PCR 7 in the baseline console"; exit 1; }
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s07: no enter-initrd d11 prediction from the build"; exit 1; }
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
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || {
        echo "s07: production enroll-tpm FAILED"; exit 1; }
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
STATE="$RUN/state"

swtpm_start "$STATE/tpm" || { echo "s07: swtpm restart failed"; exit 1; }
# NB: no $RUN/disk.img copy — Wave-2 2b: the tamper boot runs on a QCOW2
# OVERLAY over the protective $RUN/state snapshot base; the base is copied
# into $RUN/state exactly once and never per boot, and the boot (a terminal
# 3-strike fail-closed leg) persists nothing.
cp "$STATE/vars-enrolled.fd" "$RUN/vars-enrolled.fd"
assert_contains "enrolled vars in use: SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"

# --- the tamper: tampered-cmdline UKI + STALE .pcrsig payload -------------------
# Attack model: a compromised/redirected build ships a UKI whose .cmdline
# carries an extra word; the attacker CANNOT re-sign PCR policies (the
# release key is offline, I4), so the .pcrsig payload on the raw payload
# drive still predicts the CLEAN cmdline's PCR 11. The payload is unsigned
# on the wire, so shipping a stale one is precisely the attacker's
# primitive. Host-side: prove the tampered UKI's own prediction DIVERGES
# from the shipped (clean) one, then boot the tampered UKI with the stale
# payload: the stub measures the tampered effective cmdline into PCR 11 ->
# the policy session's trial digest matches NO signed .pcrsig entry ->
# fail closed.
echo "# building tampered-cmdline UKI variant (cmdline + $TAMPER_WORD, same release key)"
uki_build "$RUN" "$STATE/keys" "$RUN/harness.efi" "$TAMPER_WORD" || exit 1
assert_file_exists "tampered-cmdline UKI built (signed with the release key)" "$RUN/harness.efi"
# the tampered UKI carries its OWN (matching) .pcrsig — the attacker would
# ship the STALE clean one instead; keep both for the divergence proof
cp "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-tampered.json"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"   # ship the STALE (clean) prediction
cp "$RUN/pcrsig.img" "$RUN/pcrsig-stale.img"
if python3 - "$RUN/uki-pcrsig.json" "$STATE/uki-pcrsig.json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
sys.exit(0 if a["sha256"][0]["pol"] != b["sha256"][0]["pol"] else 1)
PYEOF
then
    _assert_result ok "tampered prediction diverges from the shipped (clean) .pcrsig" ""
else
    _assert_result not-ok "tampered prediction diverges from the shipped (clean) .pcrsig" \
        "pol digests identical — the tamper would not drift PCR 11"
fi
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot the tampered-cmdline UKI (SB-enrolled vars) ---------------------------
echo "# booting: tampered-cmdline UKI + stale .pcrsig drive, feeding 3 WRONG passphrases (TCG, up to $QEMU_TIMEOUT s) ..."
# Wave-2 2b: the scenario boot consumes the enrolled base read-mostly — fresh
# QCOW2 overlay (LOCK_SH via overlay_create), discarded after the boot
OVERLAY_TAMPER="$RUN/disk-tamper.qcow2"
overlay_create "$RUN/state/disk.img" "$OVERLAY_TAMPER" || {
    echo "s07: overlay create failed (tamper boot)"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$OVERLAY_TAMPER" "$RUN/vars-enrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img"
# the hook's bounded loop has NO read timeout: feed 3 WRONG answers through
# the hook's OWN prompt (uki_wait_hook_prompt), else the boot could only end
# in a timeout-kill instead of the 3-strike poweroff
for n in 1 2 3; do
    if uki_wait_hook_prompt "$n" 300 "$RUN"; then
        _assert_result ok "hook awaiting recovery passphrase $n/3 (hook read path)" ""
        feed_line "$RUN/serial.sock" "alpine-fde-wrong-passphrase-$n"
    else
        _assert_result not-ok "hook awaiting recovery passphrase $n/3 (hook read path)" \
            "no prompt $n in console"
        break
    fi
done
qemu_wait "$RUN" "$QEMU_TIMEOUT"
overlay_discard "$OVERLAY_TAMPER"   # the boot's overlay is ephemeral
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- PCR forensics -------------------------------------------------------------
pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR11=$(pcr_of "$CONSOLE" 11)
PCR11_ENROLLED=$(pcr_of "$STATE/console.log" 11)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran (UKI started via the tampered boot entry)" "$LOG" \
    "alpine-fde-harness: init started"
assert_contains "hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "hook discovered the {7,11} token (still valid LUKS2 metadata)" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
if grep -aqE 'alpine-fde-cmdline2? .*rdinit=/init loglevel=7' "$CONSOLE" 2>/dev/null; then
    _assert_result ok "embedded cmdline intact in /proc/cmdline" ""
else
    _assert_result not-ok "embedded cmdline intact in /proc/cmdline" \
        "no whole alpine-fde-cmdline line carries the embedded cmdline"
fi
if grep -aqE 'alpine-fde-cmdline2? .*alpine-fde-loader-tamper' "$CONSOLE" 2>/dev/null; then
    _assert_result ok "tamper word reached the kernel (stub measured the effective cmdline)" ""
else
    _assert_result not-ok "tamper word reached the kernel (stub measured the effective cmdline)" \
        "no whole alpine-fde-cmdline line carries the tamper word"
fi
if [[ -n "$PCR11" && "$PCR11" != "$PCR11_ENROLLED" ]]; then
    _assert_result ok "PCR 11 drifted (stub measured the effective cmdline)" ""
else
    _assert_result not-ok "PCR 11 drifted (stub measured the effective cmdline)" \
        "PCR11=$PCR11 enrolled=$PCR11_ENROLLED"
fi
# ordering proof: the hook's refusal strictly precedes its first passphrase
# prompt (the recovery loop may only arm AFTER the token path failed)
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "hook refusal BEFORE any passphrase prompt (line $_ref_line < $_p1_line)" ""
else
    _assert_result not-ok "hook refusal BEFORE any passphrase prompt" \
        "ref=$_ref_line prompt1=$_p1_line"
fi
# the STALE combined entry is properly release-signed over the selection the
# token pins, so the hook's I3 gate ADMITS it — the refusal is the policy
# session: the live (drifted) PCR 11 trial digest no longer matches the
# signed pol, and tpm2_unseal refuses the sealed blob
assert_contains "unseal refused (drifted PCR 11 matches NO signed .pcrsig entry)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
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

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s07-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s07-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
