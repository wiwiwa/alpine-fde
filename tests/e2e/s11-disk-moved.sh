#!/usr/bin/env bash
# tests/e2e/s11-disk-moved.sh — §10 row "Disk moved to another machine",
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness
# DEFAULT unlock). The volume key is sealed to THIS TPM's SRK (the
# systemd-owned primary, derived from the TPM's storage seed). Booting the
# SAME disk.img + ESP + enrolled vars against a FOREIGN TPM (a second, fresh
# swtpm state = different seed = different SRK) must refuse to unseal:
#   the hook's I3 signature gate PASSES (the token + .pcrsig are untouched —
#   the refusal is the SRK, not the signing), then the sealed blob FAILS to
#   load under the foreign primary -> the hook's "the TPM refused the sealed
#   blob under the current PCR state (drift / foreign TPM / DA lock)"
#   refusal (unseal_seal_refused) -> its BOUNDED keyslot-0 recovery loop ->
#   three fed WRONG answers -> 3-strike fail-closed `poweroff -f` (§8.2, NO
#   shell is ever offered). Fail closed, never unlock, no hang.
#
# Boot 1: baseline (token-less disk) -> the hook's recovery loop, fed the
#         slot-0 passphrase -> UNSEALED; then the REAL production CLI
#         enrolls the finalized {7,11} Mechanism B token host-side against
#         swtpm A (the disk's token is sealed to A's SRK).
# Boot 2: fresh swtpm B (never seen by the sealing ceremony) + the SAME
#         disk/ESP/vars -> the token path runs but unsealing against the
#         foreign SRK is refused -> bounded loop -> 3-strike.
#
# NB (G-T13): NO assert_pcr11_prediction on boot 2 — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading. Tamper scoping is asserted instead: PCR 7 AND PCR 11
# unchanged vs the enrolled boot (a virgin TPM measures the SAME section
# chain + phase word from zero — only the SRK, and thus the seal, is
# foreign).

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
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13/G-E9, boot 1)
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

RUN="$TESTS/e2e/.runs/s11-disk-moved-$(date +%s)"
# console snapshots OUTSIDE .runs — survive sibling .runs housekeeping
SNAPDIR="${TMPDIR:-/tmp}/secpc-e2e-s11-$(date +%s)"
mkdir -p "$RUN" "$SNAPDIR"
# prefix housekeeping — never the invocation's chained state dirs
# (CR-02/MD-03: ALPINE_FDE_PROTECT_DIRS, exported by run-e2e.sh)
find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's11-disk-moved-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done
CONSOLE="$RUN/console.log"
ENROLL="$RUN/enroll-boot"   # boot 1 (baseline + enrollment against swtpm A) artifacts
mkdir -p "$ENROLL"
# _ensure_run — recreate the run dirs if a concurrent sibling's .runs pruning
# deleted them mid-scenario (observed 2026-09-14); idempotent.
_ensure_run() { mkdir -p "$RUN" "$ENROLL" 2>/dev/null || true; }

# _swtpm_ensure DIR — make sure a swtpm is serving DIR, (re)starting it when a
# prior boot/external kill took it down; tolerant when it is already alive.
_swtpm_ensure() {
    if [ -S "$1/sock.ctrl" ] && tpm2_getcap -T "swtpm:path=$1/sock" properties-fixed >/dev/null 2>&1; then
        return 0
    fi
    swtpm_start "$1"
}

# --- boot 1: baseline + enroll against swtpm A (s00/s05 pattern) ------------------
_swtpm_ensure "$ENROLL/tpm" || { echo "s11: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$ENROLL/vars-enrolled.fd" || exit 1
echo "# building harness UKI (guest tree + initramfs + ukify + sbsign) ..."
uki_build "$ENROLL" "$RUN/keys" "$ENROLL/harness.efi" || { echo "s11: uki_build failed"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$ENROLL/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$ENROLL/esp.img" "$ESP_MIB" "$ENROLL/harness.efi" || exit 1
disk_make_luks "$ENROLL/disk.img" 128 || exit 1
# Retry loop: concurrent sibling agents have been observed to kill qemu/tpm
# processes and prune .runs mid-boot; a boot that never reaches UNSEALED is
# treated as an infra anomaly and retried (max 3). The token-less disk puts
# the hook's BOUNDED recovery loop in control: the feed is
# prompt-synchronized (the hook has NO read timeout).
BOOT_OK=0
for _att in 1 2 3; do
    echo "# boot 1/2: baseline against TPM A (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    # Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the pristine
    # token-less base (LOCK_SH via overlay_create; discarded after the
    # attempt) — the baseline boot cannot persist anything to the base before
    # the HOST-SIDE enrollment below writes the standing token
    OVERLAY_B1="$ENROLL/disk-baseline-$_att.qcow2"
    overlay_create "$ENROLL/disk.img" "$OVERLAY_B1" || {
        echo "s11: overlay create failed (baseline attempt $_att)"; exit 1; }
    qemu_run "$ENROLL" "$ENROLL/esp.img" "$OVERLAY_B1" "$ENROLL/vars-enrolled.fd" "$ENROLL/tpm" "$ENROLL/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$ENROLL"; then
        feed_line "$ENROLL/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    _snap_while_running "$(cat "$ENROLL/qemu.pid")" "$ENROLL/console.log" "$SNAPDIR/console-enroll.snap" &
    _snap_poller1=$!
    qemu_wait "$ENROLL" "$QEMU_TIMEOUT"
    overlay_discard "$OVERLAY_B1"   # the attempt's overlay is ephemeral
    wait "$_snap_poller1"
    if grep -q "alpine-fde: UNSEALED" "$SNAPDIR/console-enroll.snap" 2>/dev/null; then
        BOOT_OK=1
        break
    fi
    echo "# baseline attempt $_att did not reach UNSEALED (external kill/prune race or regression) — retrying"
    ((_att < 3)) && { swtpm_reset "$ENROLL/tpm" && swtpm_start "$ENROLL/tpm" || exit 1; }
    rm -f "$ENROLL/console.log"
done
[ "$BOOT_OK" -eq 1 ] || { echo "s11: baseline boot did not reach UNSEALED in 3 attempts — state unusable"; tail -5 "$SNAPDIR/console-enroll.snap" 2>/dev/null; exit 1; }
LOG_B1=$(cat "$SNAPDIR/console-enroll.snap" 2>/dev/null || true)
assert_contains "boot 1: hook recovery loop opened (no token on the fresh volume)" "$LOG_B1" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "boot 1: fed slot-0 passphrase unsealed via the recovery path" "$LOG_B1" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "boot 1: volume UNSEALED" "$LOG_B1" "$(sentinel_of harness_unsealed)"
# G-T13/G-E9 for boot 1 (unseals, so /init printed the post-hook postphase
# reading): pair the helper with the enrolled UKI's signed prediction + this
# boot's console.
cp "$ENROLL/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
_CONSOLE_SAVE="$CONSOLE"
CONSOLE="$SNAPDIR/console-enroll.snap"
assert_pcr11_prediction "S-11 [enroll]"
CONSOLE="$_CONSOLE_SAVE"

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted
# console's PCR 7, d11 = the build's enter-initrd prediction; the combined
# {7,11} entry is what the hook extracts for the finalized token.
D11=$(cat "$ENROLL/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11" ]] || { echo "s11: no enter-initrd d11 prediction from the build"; exit 1; }
swtpm_ensure "$ENROLL/tpm" || { echo "s11: swtpm restart (enroll) failed"; exit 1; }
PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$ENROLL/console.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_ENROLLED" ]] || { echo "s11: no PCR 7 in the baseline console"; exit 1; }
# digest-anchored enroll (Option A): no reseeding and no live-read assertion —
# the CLI compares the entry's recorded d7/d11 against the baseline (pure
# data, no live TPM read); the fixture only needs to be SERVING for the seal.
uki_pcrsig_append_combined "$ENROLL/uki-pcrsig.json" "$ENROLL/uki-pcrsig-combined.json" \
    "$PCR7_ENROLLED" "$D11" "$RUN/keys" || exit 1
uki_pcrsig_disk "$ENROLL/pcrsig.img" "$ENROLL/uki-pcrsig-combined.json" || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
# enroll precondition (CLI, enrl_preconditions #2): a FINALIZED baseline at
# $ALPINE_FDE_ROOT/etc/alpine-fde/baseline.json. Stamp the booted d7 into a
# scenario-local cli-state root — the same seam s06/s09/s12/s13 use; without
# it enroll-tpm dies "no baseline at /etc/alpine-fde/baseline.json".
uki_baseline_stamp "$ENROLL/cli-state" "$PCR7_ENROLLED"
uki_host_enroll_finalized "$EFIVARS" "$ENROLL/uki-pcrsig-combined.json" \
    "$ENROLL/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$ENROLL/cli-state" || {
    echo "s11: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$ENROLL/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
echo "# enrollment landed — token sealed to TPM A's SRK"

# --- boot 2: the same disk against a FOREIGN TPM ---------------------------------
_ensure_run
# fresh swtpm state = fresh storage seed = different SRK (and different
# endorsement hierarchy); the firmware still boots (UKI signature is
# TPM-independent) but the sealed volume key is unobtainable.
# NB: no per-boot disk copy — Wave-2 2b: the foreign-TPM boot consumes the
# enrolled base read-mostly (a terminal 3-strike fail-closed leg), so every
# attempt runs a fresh QCOW2 OVERLAY over $ENROLL/disk.img (LOCK_SH via
# overlay_create, discarded after the attempt) and the base is never written.
BOOT_OK=0
for _att in 1 2 3; do
    _swtpm_ensure "$RUN/tpm-foreign" || { echo "s11: foreign swtpm failed"; exit 1; }
    echo "# boot 2/2: same disk against foreign TPM B (TCG, attempt $_att, up to $QEMU_TIMEOUT s) ..."
    OVERLAY_B2="$RUN/disk-foreign-$_att.qcow2"
    overlay_create "$ENROLL/disk.img" "$OVERLAY_B2" || {
        echo "s11: overlay create failed (foreign-TPM attempt $_att)"; exit 1; }
    qemu_run "$RUN" "$ENROLL/esp.img" "$OVERLAY_B2" "$ENROLL/vars-enrolled.fd" "$RUN/tpm-foreign" "$ENROLL/pcrsig.img"
    _snap_while_running "$(cat "$RUN/qemu.pid")" "$CONSOLE" "$SNAPDIR/console-foreign.snap" &
    _snap_poller2=$!
    # the hook's bounded loop has NO read timeout: feed 3 WRONG answers
    # through its OWN prompt, else the boot could only end in a timeout-kill
    # instead of the 3-strike poweroff
    _fed=0
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 300 "$RUN"; then
            feed_line "$RUN/serial.sock" "alpine-fde-foreign-tpm-wrong-passphrase-$n"
            _fed=$n
        else
            break
        fi
    done
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    overlay_discard "$OVERLAY_B2"   # the attempt's overlay is ephemeral
    wait "$_snap_poller2"
    # DECISIVE SENTINEL SCOPE (2026-09-23): a 3-strike refusal boot powers off
    # from INSIDE the hook (_fdh_poweroff -> `poweroff -f` in the initrd), so
    # the harness's own "alpine-fde: POWEROFF" line (printed by /init only on
    # the post-UNSEALED path) can NEVER appear — gating on it made every green
    # foreign-TPM boot burn all 3 attempts and report not-ok. The terminal
    # evidence is the hook's own 3-strike give-up + fail-closed poweroff pair.
    if grep -qF "$(sentinel_of unseal_3strike)" "$SNAPDIR/console-foreign.snap" 2>/dev/null \
        && grep -qF "$(sentinel_of unseal_poweroff)" "$SNAPDIR/console-foreign.snap" 2>/dev/null \
        && [ "$_fed" -eq 3 ]; then
        BOOT_OK=1
        break
    fi
    echo "# foreign-TPM boot attempt $_att: no completed 3-strike (external kill/prune race?) — retrying"
done
LOG=$(cat "$SNAPDIR/console-foreign.snap" 2>/dev/null || true)
if [ "$BOOT_OK" -eq 1 ]; then
    _assert_result ok "guest exited (3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (3-strike poweroff, not timeout-kill)" \
        "no decisive sentinel in 3 attempts; last console: $(tail -2 "$SNAPDIR/console-foreign.snap" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "init ran (firmware booted, the hook took the unlock)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "TPM char device appeared (foreign TPM serves auth-less ops)" "$LOG" \
    "$(sentinel_of harness_tpm_present)"
assert_contains "hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "hook discovered the {7,11} token (the token path is attempted)" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
# the I3 signature gate PASSES — the disk's token + .pcrsig are untouched;
# the refusal is the foreign SRK, not the signing
assert_not_contains "I3 signature gate passed (no signature refusal)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "TPM refused the sealed blob (foreign SRK)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$SNAPDIR/console-foreign.snap" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$SNAPDIR/console-foreign.snap" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
PROMPTS=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "exactly 3 recovery-passphrase prompts (bounded loop, no 4th)" "3" "$PROMPTS"
assert_contains "3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "fail-closed poweroff (no shell is offered)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# G-T13 tamper scoping for boot 2 (foreign TPM B): a virgin TPM measures the
# SAME section chain + phase word from zero, so PCR 7 AND PCR 11 are unchanged
# vs the enrolled boot — only the SRK (and thus the seal) is foreign.
pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
assert_eq "PCR 7 unchanged vs the enrolled boot (same vars, no drift confound)" \
    "$(pcr_of "$SNAPDIR/console-enroll.snap" 7)" \
    "$(pcr_of "$SNAPDIR/console-foreign.snap" 7)"
assert_eq "PCR 11 unchanged vs the enrolled boot (same UKI, same phase extend)" \
    "$(pcr_of "$SNAPDIR/console-enroll.snap" 11)" \
    "$(pcr_of "$SNAPDIR/console-foreign.snap" 11)"

echo "# run dir: $RUN"
if [ "$TESTS_FAIL" -eq 0 ]; then
    echo "# s11-disk-moved: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s11-disk-moved: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
