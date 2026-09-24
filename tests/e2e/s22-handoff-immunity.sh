#!/usr/bin/env bash
# tests/e2e/s22-handoff-immunity.sh — §12 S-22 (provisional-window immunity)
# + the §2.1 T2c provisional-window rows, on the AMENDED ADR-20 lifecycle.
#
# AMENDED WINDOW SHAPE (the re-pin): the old "no token in the window" premise
# is OBSOLETE — Stage 1 step 6 (lib/cmd/install.sh `seal_provisional`,
# Mechanism B PCR-11-only) leaves the handoff with
#   keyslot 0 = the OPERATOR'S RECOVERY PASSPHRASE (argon2id, from install)
#   keyslot 1 = the STANDING PROVISIONAL token (systemd-tpm2, tpm2-pcrs [11])
# so the window's immunity claim is no longer "there is no token to try" but:
#   * the STANDING signed UKI auto-unseals (the provisional seal is the
#     first-boot convenience — zero console input);
#   * a TAMPERED/FOREIGN UKI never unseals (the PolicyPCR(11) session digest
#     of any other boot misses the sealed policy — the attacker rebooting a
#     modified image gains nothing);
#   * the recovery passphrase at keyslot 0 is present FROM INSTALL and is the
#     TPM-independent way out;
#   * after the service completion (fin_completion_steps — the chain shared
#     VERBATIM by the guided command and the first-boot service, §9.1 Stage 2
#     == Stage 3) the token binds {PCR 7, PCR 11} — the finalized shape.
#
# Fixture (host-side; the provisional enrollment runs HOST-side against the
# file-backed LUKS2 image with the real seal library and the fixture swtpm —
# the tests/unit/keys_rsa3072_chain.sh seal_provisional recipe, committed to
# the guest-shaped values):
#   boot 1 (baseline): token-LESS disk -> the §8.2 hook's recovery-passphrase
#           path is the only way in -> fed slot-0 passphrase -> UNSEALED.
#           Proves recovery-at-keyslot-0 from install (T2c). The console's
#           postphase PCR 11 (== the build's enter-initrd prediction, G-T13)
#           is the value the provisional seal binds.
#   host:   compose the release-key-signed {11}-selection .pcrsig over the
#           LIVE (booted) PCR 11, then seal_provisional + token_add_keyslot +
#           token_import (the installer's own step-6 recipe) onto the image.
#           Host asserts: keyslots {0,1}, ONE systemd-tpm2 token, pcrs [11],
#           token on keyslot 1 — the amended window shape.
#   boot 2 (the standing signed UKI): SAME UKI, fresh swtpm start (same SRK,
#           PCRs re-derive deterministically) -> the hook discovers the
#           provisional token, the session matches, ZERO console input ->
#           UNSEALED. (The hook's Stage-2 installed->provisional-booted flip
#           cannot fire here: the harness mounts the unlocked root only later
#           — the documented DEVIATION in tests/lib/uki-build.sh; the flip is
#           unit-pinned in tests/unit/hooks_mkinitfs_unseal.sh.)
#   boot 3 (tampered UKI): a UKI VARIANT with one extra cmdline word (the
#           s07 attacker primitive) booted against the SAME provisional disk:
#           the token's signature still verifies (it signs the policy, not the
#           image) but the PolicyPCR(11) digest of the tampered boot MISSES ->
#           the TPM refuses the sealed blob -> the bounded recovery loop takes
#           three WRONG passphrases -> 3-strike fail-closed poweroff. NEVER
#           unlocked, no shell is ever offered.
#   host:   THE COMPLETION LEG on boot 2's image: the real guided finalize
#           (Stage 3) drives the shared completion chain — audit --init
#           finalizes the pending baseline from the live PCRs, seal_upgrade_
#           token replaces the provisional PCR-11 token with the {PCR 7,
#           PCR 11} construction (the combined release-key-signed policy
#           composed host-side), state `finalized` LAST. Host asserts: token
#           pcrs [7,11] on keyslot 1, keyslots {0,1}, recovery slot 0 intact.
#
# Fidelity notes (documented, not silent):
#   * The provisional enrollment is HOST-side, not in-guest: the amended
#     Stage-1 step 6 runs in the installer chroot against the SAME TPM the
#     machine boots with — here that is the fixture swtpm, and the seal
#     library + cryptsetup operate on the file-backed image directly (the
#     uki_host_enroll_finalized precedent in tests/lib/uki-build.sh). The
#     swtpm MUST still hold boot 1's live PCRs when seal_provisional runs
#     (its G-B6 gate verifies the .pcrsig against the LIVE register); the
#     scenario asserts live == console postphase before sealing, and stops
#     the swtpm afterwards so every later boot re-derives PCRs from zero
#     (startup-clear semantics — a boot stacking extends on the previous
#     boot's values would be a fixture lie).
#   * `cryptsetup open --token-only` (the old S-22 consumer primitive) is NOT
#     re-pinnable as a negative here — a token EXISTS in the amended window,
#     and that primitive SUCCEEDING is boot 2's affirmative (the hook runs
#     the same token policy session the primitive would).
#   * The completion leg runs the GUIDED command host-side because
#     fin_completion_steps is the shared Stage 2 == Stage 3 chain by
#     construction (lib/cmd/finalize.sh); the service-specific seams
#     (provisional-token re-unseal authorization, advisory containment) are
#     s21's legs. What S-22 pins here is the WINDOW EXIT: {7,11} binding.
#
# §12 negatives on every boot: no interactive passphrase prompt (prompt_re),
# no emergency shell (emergency_forbidden), sentinels via the table only.

set -u
set -m   # each background job gets its own process group: the watchdog can
         # kill the whole stage tree, not just the subshell leader

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
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
# the seal library closure for the host-side provisional enrollment (the
# tests/unit/keys_rsa3072_chain.sh source set)
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
DISK_MIB=1600
declare -A S22_RETRIES   # per-boot-dir degraded-boot re-run counter (bounded)

export QEMU_TIMEOUT="${ALPINE_FDE_S22_TIMEOUT:-1200}"

# §13-floor-OK recovery passphrase for the completion leg (the fixture's
# well-known slot-0 passphrase is floor-BLOCKLISTED; the completion's
# authorization rekeys keyslot 0 host-side first — the Stage-1 stand-in)
S22_RECOVERY='fde-s22-recovery-7c5d31'
S22_KEYPASS='fde-s22-release-pbkdf2-n9'

# --- hardening: bounded stages, loud failures, overall budget --------------------
# Calibrated 2026-09-24: the registry's outer SCENARIO_BUDGET is 1500 s (MD-05b)
# — an internal watchdog above the outer cap can never fire, so a hung s22
# dies as an anonymous outer rc=124 instead of this scenario's loud
# STAGE-TIMEOUT-OR-HANG. A full s22 pass builds 2 UKIs + boots 3 guests +
# runs the host-side provisional seal and finalize: ~500-800 s observed;
# 1350 s keeps ~1.7x margin inside the outer budget.
OVERALL_BUDGET="${ALPINE_FDE_S22_BUDGET:-1350}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {
    printf '\ns22: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's22: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    exit 125   # 125, NOT timeout(1)'s 124 (run-e2e contract)
}
_budget_check() {
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
run_stage_impl() {
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s22: stage $name (watchdog ${tmo}s)"
    ( "$@" ) &
    local pid=$! rc wrc
    # watchdog: fire ONLY if the stage's process is still the SAME one —
    # after a scenario/session death this subshell outlives its parent, pids
    # get recycled, and a bare `kill -9 -$pid` would murder an INNOCENT new
    # process group (a fresh qemu spawn) hours later (repro 2026-09-24: three
    # consecutive first boots lost qemu instantly to yesterday's orphans).
    # Identity = /proc/<pid>/stat field 22 (process start time): a recycled
    # pid has a different start time and the kill is skipped.
    local _st0; _st0=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
    ( sleep "$tmo"; \
      [[ -n "$_st0" && "$_st0" == "$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)" ]] \
        && kill -9 -"$pid" 2>/dev/null; exit 125 ) &
    local wpid=$!
    wait "$pid"; rc=$?
    kill "$wpid" 2>/dev/null
    wait "$wpid" 2>/dev/null; wrc=$?
    if (( wrc == 125 )); then
        _hang_fail STAGE-TIMEOUT "$name" "exceeded watchdog ${tmo}s"
    fi
    if (( rc != 0 )); then
        printf 's22: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
        (( soft == 1 )) && return "$rc"
        exit 1
    fi
    return 0
}
run_stage() { run_stage_impl 0 "$@"; }
_qemu_alive_or_die() {   # _qemu_alive_or_die <dir> <stage> — QEMU-LIVENESS guard
    local dir="$1" stage="$2" qpid
    qpid=$(cat "$dir/qemu.pid" 2>/dev/null || true)
    if [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null; then
        _hang_fail QEMU-DIED "$stage" \
            "qemu (pid ${qpid:-<none>}) is gone — sentinel can never appear; tail: $(tail -5 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
    fi
}
wait_console() {
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qF -- "$pat" "$dir/console.log" 2>/dev/null && return 0
        _qemu_alive_or_die "$dir" "console-wait:$pat"
        _budget_check "console-wait:$pat"
        sleep 1
        i=$((i + 1))
    done
    _hang_fail CONSOLE-WAIT "$pat" "not seen in ${tmo}s; tail: $(tail -3 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
}

RUN="$TESTS/e2e/.runs/s22-handoff-immunity-$(date +%s)"
mkdir -p "$RUN"

(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's22-handoff-immunity-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done

_exit_cleanup() {
    [[ -n "$CURRENT_QEMU_DIR" ]] && qemu_kill "$CURRENT_QEMU_DIR" 2>/dev/null
    local d
    for d in "${SWTPM_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d" 2>/dev/null
    done
    kill "$REFRESHER" 2>/dev/null
}
trap _exit_cleanup EXIT
_exit_on_int() { _exit_cleanup; exit 130; }
_exit_on_term() { _exit_cleanup; exit 143; }
trap _exit_on_int INT
trap _exit_on_term TERM
_rearm_trap() {
    trap _exit_cleanup EXIT
    trap _exit_on_int INT
    trap _exit_on_term TERM
}
_track_swtpm() { SWTPM_DIRS+=("$1"); }

# _reanchor_tpm <dir> — before EVERY guest boot the fixture TPM must be a
# FRESH, ZEROED instance. swtpm_ensure's restore path (or a live instance that
# survived the guest's clean exit carrying the previous boot's final values)
# hands the next boot a register whose provenance the scenario cannot vouch
# for, and the fixture proxy's 2026-09-22 command-drop defect (silently
# dropped SET_DATAFD/commands — see the tests/lib report) produced both the
# silent pre-BdsDxe hang and the degraded-measurement boots. Boot 2's
# affirmative (the provisional auto-unseal) depends on PCR 11 being exactly
# the boot's own enter-initrd extend, so the zero state is ASSERTED here, not
# assumed. The two host-side gates that DO need the booted values (the
# provisional seal after boot 1, the completion after boot 2) must RESEED
# them explicitly: the direct-socket fixture swtpm DIES at every clean qemu
# exit (EOF design) and swtpm_ensure's restart is a fresh startup-clear —
# there is no restore path to "keep" any more (the store/restore machinery
# is retired; see tests/lib/swtpm-fixture.sh's lifetime note). The reseed
# anchors on the boot's own console facts (the pre-token d7 print + the
# postphase d11), so the register the seal/audit gates read is exactly the
# one the guest booted with — the _reseed_from_console helper below.
_reanchor_tpm() {
    local dir="$1" d0 d7 d11
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_reanchor:$(basename "$dir")" 90 \
        swtpm_start "$dir"
    _rearm_trap
    d0=$(swtpm_pcrread "$dir" 0)
    d7=$(_pcrread "$dir" 7)
    d11=$(_pcrread "$dir" 11)
    if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ && "$d11" =~ ^0{64}$ ]]; then
        _assert_result ok "fixture: boot TPM re-anchored (PCRs 0, 7, 11 zero before the boot)" ""
    else
        _assert_result not-ok "fixture: boot TPM re-anchored (PCRs 0, 7, 11 zero before the boot)" \
            "pcr0=$d0 pcr7=$d7 pcr11=$d11 — refusing to spend the boot on a cumulative register"
        echo "s22: TPM not zeroed before a boot — aborting"; exit 1
    fi
    # settle: libtpms re-initializes at qemu's CMD_INIT and the control proxy
    # has just bound — a guest TPM command arriving mid-setup times out and
    # the firmware DROPS the measurement (the degraded-boot signature).
    local k
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
}

# _boot_hook <boot-dir> <esp-img> <disk-img> <vars.fd> <payload-or-empty>
#            [uki.efi] — boot on the SHIPPED §8.2 hook unlock. The caller owns
#            everything after qemu_run + aliveness (feeding, waiting). Each
#            boot gets its OWN vars copy: the vars pflash is WRITABLE, and a
#            varstore mutated by an earlier boot's firmware pass must never
#            leak into a later boot's measurement (the s18 lesson).
_boot_hook() {
    local bdir="$1" esp="$2" bimg="$3" vars="$4" payload="$5" uki="${6:-$RUN/harness.efi}"
    mkdir -p "$bdir"
    cp "$uki" "$bdir/harness.efi"
    cp "$bimg" "$bdir/disk.img"
    cp "$vars" "$bdir/vars.fd"
    _reanchor_tpm "$RUN/tpm"
    CURRENT_QEMU_DIR="$bdir"
    if [[ -n "$payload" ]]; then
        run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$esp" \
            "$bdir/disk.img" "$bdir/vars.fd" "$RUN/tpm" "$payload"
    else
        run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$esp" \
            "$bdir/disk.img" "$bdir/vars.fd" "$RUN/tpm"
    fi
    _qemu_alive "$bdir"
    _rearm_trap
    # EARLY degradation gate (the s18 lesson, live-evidenced 2026-09-22): the
    # hook prints the live PCRs before anything else it does, and a boot whose
    # PCR 0 is off lost firmware measurements to TPM command timeouts under
    # host load (the EFI stub then logs "Failed to measure data for event").
    # Such a boot would fail its own control — boot 2's provisional
    # auto-unseal NEEDS a faithful PCR 11 — so it is discarded and re-run ONCE
    # per boot dir on the re-anchored register. The per-boot disk/vars copies
    # are re-made by the recursive call; the PIN is per-UKI (PCR 0 measures
    # the firmware, identical across boots of the same image).
    local p0="" i=0 uki_name
    uki_name=$(basename "$uki")
    [[ "${S22_PIN_UKI:-}" != "$uki_name" ]] && S22_PCR0_PIN=""
    while (( i < 600 )); do
        kill -0 "$(cat "$bdir/qemu.pid" 2>/dev/null)" 2>/dev/null || break
        p0=$(pcr_of "$bdir/console.log" 0)
        [[ -n "$p0" ]] && break
        grep -q "EFI stub: WARNING: Failed to measure data for event" \
            "$bdir/console.log" 2>/dev/null && break
        sleep 2
        i=$((i + 2))
    done
    if grep -q "EFI stub: WARNING: Failed to measure data for event" \
           "$bdir/console.log" 2>/dev/null \
       && { [[ -z "${S22_PCR0_PIN:-}" ]] || [[ "$p0" != "$S22_PCR0_PIN" ]]; }; then
        local key
        key="retry_$(basename "$bdir")"
        S22_RETRIES[$key]=$(( ${S22_RETRIES[$key]:-0} + 1 ))
        if (( S22_RETRIES[$key] <= 3 )); then
            echo "s22: $(basename "$bdir") lost firmware measurements to host load" \
                 "(PCR 0 = ${p0:-<none>} vs pin ${S22_PCR0_PIN:-<unset>}) — discarding and re-running" \
                 "(attempt ${S22_RETRIES[$key]}/3)"
            qemu_kill "$bdir"
            _boot_hook "$@"
            return 0
        fi
        echo "s22: $(basename "$bdir") still degraded after 3 re-runs — continuing (its control will fail loudly)"
    fi
    if [[ -n "$p0" && -z "${S22_PCR0_PIN:-}" ]]; then
        S22_PCR0_PIN="$p0"
        S22_PIN_UKI="$uki_name"
    fi
}

_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s22: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s22: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

_ensure_tpm() {
    local dir="$1"
    swtpm_ensure "$dir" || {
        echo "s22: swtpm_ensure failed for $dir"; exit 1;
    }
}

# _reseed_from_console <console.log> — reconstruct the booted register in the
# fixture swtpm. After a clean qemu exit the fixture is DEAD (EOF design) and
# swtpm_ensure's restart is all-zero, so a host-side gate that must read the
# BOOTED values (the provisional seal's live-PCR G-B6 oracle, the completion's
# audit --init) re-extends the console's own facts: the pre-token PCR 7 print
# and the postphase PCR 11. Both are pinned to the build prediction by the
# per-boot G-T13 asserts, so the seeded register is exactly what the guest
# booted with — not a fixture lie but the fixture's designated reseed path
# (swtpm_seed_pcrs, the same discipline every between-boot scenario uses).
# Prints the seeded d11 (empty if the console carried no PCR prints).
_reseed_from_console() {
    local log="$1" d7 d11
    d7=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$log" | head -1 | cut -d= -f2)
    d11=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$log" | head -1 | cut -d= -f2)
    [[ -n "$d7" && -n "$d11" ]] || return 1
    swtpm_seed_pcrs "$RUN/tpm" "$d7" "$d11" || return 1
    printf '%s' "$d11"
}

# pcr_of <console.log> <pcr> — the harness PCR-print parser (the early
# degradation gate in _boot_hook reads the hook's pre-token PCR line with it)
pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }

# _pcrread <dir> <pcr> — local PCR reader for the seal-time G-B6 gates. The
# fixture's swtpm_pcrread anchors on the single-digit rendering ("0 : 0x…");
# tpm2-tools prints TWO-digit PCRs width-aligned ("11: 0x…" — no space before
# the colon), so the fixture function returns EMPTY for PCR 11 (live-verified
# 2026-09-22 against tpm2-tools 5.8) and every provisional/completion gate
# would read a drifted (empty) register. Parse both renderings here instead
# (tests/lib fix pending — reported to the harness owners).
_pcrread() {
    tpm2_pcrread -T "$(_swtpm_tcti_for "$1")" "sha256:$2" \
        | awk -v p="$2" '{ gsub(/:/, "", $1); if ($1 == p) { v = $NF; sub(/^0x/, "", v); print tolower(v) } }'
}

# ============================================================================
# Fixture: keys + vars + the LUKS2 container (keyslot 0 only — the FROM-INSTALL
# shape; the provisional token joins host-side after boot 1)
# ============================================================================
keys_create "$RUN/keys" || { echo "s22: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
assert_contains "fixture: enrolled vars SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
run_stage disk_make_luks 120 disk_make_luks "$RUN/disk.img" "$DISK_MIB"
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s22: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s22: empty LUKS uuid"; exit 1; }

# THE T2c FROM-INSTALL ASSERT: the recovery passphrase sits at keyslot 0
# (argon2id) before ANY enrollment exists — the TPM-independent way out
META0=$(disk_metadata "$RUN/disk.img")
assert_eq "S-22 from-install shape: keyslots == {0}" '["0"]' "$(jq -c '.keyslots | keys' <<<"$META0")"
assert_eq "S-22 from-install shape: keyslot 0 is argon2id (recovery, §7.2)" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META0")"
assert_eq "S-22 from-install shape: ZERO tokens before Stage-1 step 6" "{}" \
    "$(disk_token_json "$RUN/disk.img")"
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0
chmod 600 "$RUN/kf-slot0"

# --- the harness UKI (boot 1's AND boot 2's standing signed UKI) ---------------
run_stage uki_build 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi"
D11_PRED=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_PRED" ]] || { echo "s22: no enter-initrd d11 prediction from the build"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make 300 esp_make "$RUN/esp.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
# the tampered variant (boot 3): ONE extra cmdline word -> a different stub
# measurement -> a different pre-unlock PCR 11 (the s07 attacker primitive)
run_stage uki_build-tampered 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-tampered.efi" "alpine-fde-tampered"
run_stage esp_make-tampered 300 esp_make "$RUN/esp-tampered.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-tampered.efi"

_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"

# ============================================================================
# BOOT 1 — baseline: recovery-at-keyslot-0 is the ONLY way in (T2c from-install)
# ============================================================================
echo "# boot 1: token-less disk — the §8.2 hook recovery path (fed slot-0)"
_boot_hook "$RUN/boot1" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" ""
PROMPT_OK=0
# 900 s (was 300, then 600): a consolidated-run boot 1 was live-seen reaching
# the hook prompt at ~7 min wall, and a 2026-09-22 solo run saw the prompt
# land past the 600 s mark (this box carries background tenants; boots crawl)
# — the recovery prompt must not be declared missing while the guest is still
# crawling. The hook's read has no timeout, so prompt-synchronized feeding is
# unaffected.
if uki_wait_hook_prompt 1 900 "$RUN/boot1"; then
    PROMPT_OK=1
    feed_line "$RUN/boot1/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
fi
assert_eq "boot 1: the hook arms the recovery loop (token-less disk)" "1" "$PROMPT_OK"
# Feed the CORRECT passphrase at EVERY prompt (repro 2026-09-24: a feed line
# lost to the serial layer made the hook's read return EOF — three fast
# strikes — and the guest fail-closed-powered off before UNSEALED, so the
# UNSEALED wait died with QEMU-DIED). A repeat feed of the correct passphrase
# is harmless; whichever landing is good unlocks. Liveness per iteration.
for n in 2 3; do
    _i=0
    while (( _i < 45 )); do
        grep -q "alpine-fde: UNSEALED" "$RUN/boot1/console.log" 2>/dev/null && break 2
        grep -cE "$(sentinel_of unseal_prompt_re)" "$RUN/boot1/console.log" 2>/dev/null \
            | grep -q "^$n$" && break
        _qpid=$(cat "$RUN/boot1/qemu.pid" 2>/dev/null || true)
        [[ -z "$_qpid" ]] || ! kill -0 "$_qpid" 2>/dev/null && break 2
        sleep 1
        _i=$((_i + 1))
    done
    grep -q "alpine-fde: UNSEALED" "$RUN/boot1/console.log" 2>/dev/null && break 2
    feed_line "$RUN/boot1/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
done
wait_console "$RUN/boot1" "alpine-fde: UNSEALED" 300
run_stage qemu_wait-boot1 "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/boot1" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_B1=$(cat "$RUN/boot1/console.log" 2>/dev/null || true)
assert_contains "[boot 1] init ran" "$LOG_B1" "alpine-fde-harness: init started"
assert_contains "[boot 1] hook ran the enter-initrd extend" "$LOG_B1" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[boot 1] hook found NO token (pre-step-6 shape)" "$LOG_B1" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[boot 1] keyslot-0 recovery passphrase unsealed the volume (from-install way out)" \
    "$LOG_B1" "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[boot 1] UNSEALED" "$LOG_B1" "alpine-fde: UNSEALED"
assert_not_contains "[boot 1] never unlocked via a token" "$LOG_B1" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[boot 1] no interactive prompt ever appeared" "$LOG_B1" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot 1] no emergency shell" "$LOG_B1" "$(sentinel_of emergency_forbidden)"

# the postphase PCR 11 == the build's enter-initrd prediction (G-T13) — the
# value the provisional seal will bind
D11_BOOT1=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$RUN/boot1/console.log" \
    | head -1 | cut -d= -f2)
assert_eq "boot 1: postphase PCR 11 == the ukify enter-initrd prediction (G-T13)" "$D11_PRED" "$D11_BOOT1"

# ============================================================================
# HOST — the Stage-1 step 6 provisional enrollment (the amended window shape):
# the {11}-selection release-key-signed policy over the LIVE booted PCR 11,
# then seal_provisional + keyslot + token import (the installer's recipe).
# ============================================================================
# the fixture died at boot 1's clean qemu exit; re-extend the booted register
# from the console facts. The readback pins the ZERO-ON-RESTART contract: the
# live register after a reseed is the EXTEND-FROM-ZERO of the seeded digest,
#     live = sha256(0^32 || d11)  (never d11 itself)
# which is exactly why the provisional G-B6 gate must be digest-anchored (the
# entry carries d11; lib/seal.sh computes seal_digest_11 over the COMPONENT,
# no live read) — a live-PCR oracle can never see the booted value here.
_zero_extend22() {
    printf '%064d%s' 0 "$1" | tr -d ' \n' | xxd -r -p | sha256sum | awk '{print $1}'
}
swtpm_ensure "$RUN/tpm" >/dev/null 2>&1 || true
D11_SEEDED=$(_reseed_from_console "$RUN/boot1/console.log") \
    || { echo "s22: boot 1 console missing PCR prints — cannot reseed the fixture"; exit 1; }
D11_LIVE=$(_pcrread "$RUN/tpm" 11)
if [[ "$D11_LIVE" == "$(_zero_extend22 "$D11_SEEDED")" ]]; then
    _assert_result ok "fixture: the register re-seeded to boot 1's values (extend-from-zero contract, seal-time input)" ""
else
    _assert_result not-ok "fixture: the register re-seeded to boot 1's values" \
        "live=$D11_LIVE expected-extend-from-zero=$(_zero_extend22 "$D11_SEEDED") (console d11=$D11_BOOT1)"
    echo "s22: swtpm PCR 11 is not the reseeded register before the provisional seal — aborting"; exit 1
fi
mkdir -p "$RUN/tmp"
# compose over the BOOTED d11 (assertion 15 pinned postphase == prediction);
# D11_LIVE above is only the reseed contract readback
POL11=$(seal_digest_11 "$D11_BOOT1")
printf '%s' "$POL11" | policy_hex_to_bin >"$RUN/msg11.bin"
openssl dgst -sha256 -sign "$RUN/keys/db.key" -out "$RUN/sig11.bin" "$RUN/msg11.bin" \
    || { echo "s22: {11} policy signature failed"; exit 1; }
PKFP=$(policy_pubkey_fp "$RUN/keys/release.pub")
# the d11 digest-anchor (the s00b/Option-A pattern): the provisional G-B6 gate
# verifies the signed pol against the ENTRY'S OWN component — a pure data
# check. The fixture's live register here is a reseed (extend-from-zero), so a
# live-PCR oracle can never equal the booted digest; the boot-time PolicyPCR
# session against the guest's re-derived register is the real verification.
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$RUN/sig11.bin")" \
    --arg pkfp "$PKFP" --arg d11 "$D11_BOOT1" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig, "d11": $d11}]}' >"$RUN/pcrsig-11.json"
assert_eq "S-22: the {11}-selection .pcrsig pol == seal_digest_11(booted d11), anchored" "$POL11" \
    "$(jq -r '.sha256[0].pol' "$RUN/pcrsig-11.json")"
assert_eq "S-22: the {11}-selection entry carries the d11 anchor (digest-anchored G-B6)" "$D11_BOOT1" \
    "$(jq -r '.sha256[0].d11' "$RUN/pcrsig-11.json")"
run_stage pcrsig_disk-11 60 uki_pcrsig_disk "$RUN/pcrsig-11.img" "$RUN/pcrsig-11.json"
# seal_provisional runs INLINE (never via run_stage): it stages SEAL_PASS_FILE
# and SEAL_SLOT for the caller, and a run_stage subshell would lose them
_budget_check seal-provisional
echo "# s22: stage seal-provisional (the installer's step-6 recipe, host-side)"
_PROV_TOK="$RUN/token-prov.json"
rm -f "$_PROV_TOK"
SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE=''
# NB: SWTPM_TCTI is NOT inherited — swtpm_start ran inside run_stage subshells,
# so its export never reached this shell (registry 2026-09-23:
# "SWTPM_TCTI: unbound variable" at the seal-provisional stage). Derive it.
ALPINE_FDE_TMPDIR="$RUN/tmp" \
ALPINE_FDE_SEAL_STAGE="$RUN/tmp" \
ALPINE_FDE_TCTI="$(_swtpm_tcti_for "$RUN/tpm")" \
    seal_provisional "$RUN/keys" "$RUN/disk.img" "$RUN/pcrsig-11.json" "$_PROV_TOK" \
    || { echo "s22: seal_provisional failed"; exit 1; }
[[ -s "$_PROV_TOK" && -n "${SEAL_PASS_FILE:-}" && -f "$SEAL_PASS_FILE" && -n "${SEAL_SLOT:-}" ]] || {
    echo "s22: seal_provisional did not stage a token + passphrase"; exit 1; }
_budget_check token-commit
token_add_keyslot "$RUN/disk.img" "$SEAL_PASS_FILE" "$SEAL_SLOT" "$RUN/kf-slot0" \
    || { echo "s22: token_add_keyslot failed"; exit 1; }
token_import "$RUN/disk.img" "$_PROV_TOK" "$(token_next_id "$RUN/disk.img")" \
    || { echo "s22: token_import failed"; exit 1; }
keys_scrub "$SEAL_PASS_FILE"
unset SEAL_PASS_FILE SEAL_SLOT
# THE AMENDED WINDOW SHAPE (host asserts of record)
METAP=$(disk_metadata "$RUN/disk.img")
TOKP=$(disk_token_json "$RUN/disk.img")
assert_eq "S-22 window shape: keyslots == {0,1}" '["0","1"]' "$(jq -c '.keyslots | keys' <<<"$METAP")"
assert_eq "S-22 window shape: keyslot 0 still argon2id recovery" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$METAP")"
assert_eq "S-22 window shape: EXACTLY ONE token" "1" \
    "$(jq '[.[] | select(.type == "systemd-tpm2")] | length' <<<"$TOKP")"
assert_eq "S-22 window shape: the token binds PCR 11 ONLY (provisional)" "[11]" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKP")"
assert_eq "S-22 window shape: the token sits on keyslot 1" "1" \
    "$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKP")"
assert_contains "S-22 window shape: the token carries the release-key signature (§7.2)" "$TOKP" \
    '"tpm2-signature"'
# stop the swtpm: every later boot must re-derive PCRs from zero (startup-clear)
run_stage swtpm-cycle 60 swtpm_stop "$RUN/tpm"

# ============================================================================
# BOOT 2 — the STANDING SIGNED UKI auto-unseals (zero console input)
# ============================================================================
echo "# boot 2: the standing provisional token unseals with ZERO console input"
_boot_hook "$RUN/boot2" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" \
    "$RUN/pcrsig-11.img"
i=0
until grep -q "alpine-fde: UNSEALED" "$RUN/boot2/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$RUN/boot2" "console-wait:boot2-UNSEALED"
    _budget_check "console-wait:boot2-UNSEALED"
    (( i < QEMU_TIMEOUT )) || _hang_fail CONSOLE-WAIT "boot2 UNSEALED" \
        "the standing provisional token never auto-unsealed"
    sleep 1
    i=$((i + 1))
done
wait_console "$RUN/boot2" "alpine-fde: POWEROFF" "$QEMU_TIMEOUT"
run_stage qemu_wait-boot2 "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/boot2" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_B2=$(cat "$RUN/boot2/console.log" 2>/dev/null || true)
assert_contains "[boot 2] init ran" "$LOG_B2" "alpine-fde-harness: init started"
assert_contains "[boot 2] hook discovered the provisional token" "$LOG_B2" \
    "$(sentinel_of unseal_token_info)11]"
assert_contains "[boot 2] the standing signed UKI auto-unsealed via the TPM token" "$LOG_B2" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[boot 2] UNSEALED with ZERO console input" "$LOG_B2" "alpine-fde: UNSEALED"
assert_eq "[boot 2] the recovery loop NEVER armed (zero-input invariant)" "0" \
    "$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG_B2" || true)"
assert_not_contains "[boot 2] the tampered-word UKI is not what booted" "$LOG_B2" \
    "alpine-fde-tampered"
assert_not_contains "[boot 2] no interactive prompt ever appeared" "$LOG_B2" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot 2] no emergency shell" "$LOG_B2" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot2/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot2/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[boot 2] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[boot 2] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# ============================================================================
# HOST — THE COMPLETION LEG: the window exits into the {7,11} binding
# (fin_completion_steps — the chain shared verbatim by the guided command and
# the first-boot service; §9.1 Stage 2 == Stage 3, ADR-20 amended).
# Runs NOW because the swtpm still holds BOOT 2's live PCRs — the audit and
# the upgrade's G-B6 gate must read exactly the boot-2 register.
# ============================================================================
echo "# completion: the guided finalize drives audit --init + the {7,11} upgrade host-side"
D7_BOOT2=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/boot2/console.log" | head -1 | cut -d= -f2)
D11_BOOT2=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$RUN/boot2/console.log" | head -1 | cut -d= -f2)
[[ -n "$D7_BOOT2" && -n "$D11_BOOT2" ]] || { echo "s22: boot 2 console missing PCR prints"; exit 1; }
# boot 2's clean exit killed the fixture swtpm; re-extend the booted register
# before audit --init finalizes the baseline from the live PCRs. Readback pins
# the zero-on-restart contract (live == extend-from-zero of the seeded d11 —
# never the booted digest itself; see the boot-1 gate above).
swtpm_ensure "$RUN/tpm" >/dev/null 2>&1 || true
swtpm_seed_pcrs "$RUN/tpm" "$D7_BOOT2" "$D11_BOOT2" \
    || { echo "s22: completion-leg fixture reseed failed"; exit 1; }
D11_LIVE2=$(_pcrread "$RUN/tpm" 11)
if [[ "$D11_LIVE2" == "$(_zero_extend22 "$D11_BOOT2")" ]]; then
    _assert_result ok "completion fixture: live PCR 11 == the reseeded boot-2 register (extend-from-zero contract)" ""
else
    _assert_result not-ok "completion fixture: live PCR 11 == the reseeded boot-2 register" \
        "live=$D11_LIVE2 expected-extend-from-zero=$(_zero_extend22 "$D11_BOOT2") (console d11=$D11_BOOT2)"
    echo "s22: swtpm PCR 11 is not the reseeded register before the completion — aborting"; exit 1
fi
# the combined {7,11} release-key-signed policy for the upgrade (s19/s20's
# pcrsign shape, composed host-side with the harness helper)
run_stage pcrsig-combined 120 \
    uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-711.json" \
    "$D7_BOOT2" "$D11_BOOT2" "$RUN/keys" \
    || { echo "s22: combined pcrsig composition failed"; exit 1; }
assert_eq "completion: combined .pcrsig pol == policy_digest(boot-2 d7, enter-initrd d11)" \
    "$(policy_digest "$D7_BOOT2" "$D11_BOOT2")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-pcrsig-711.json")"
run_stage pcrsig_disk-711 60 uki_pcrsig_disk "$RUN/uki-pcrsig-711.img" "$RUN/uki-pcrsig-711.json"
# the CLI state root: pending baseline + `installed` state doc + release.pem
# + /etc/crypttab (the finalize member walk reads every LUKS member UUID from
# it — repro 2026-09-24: without the file the completion died rc 64 "no LUKS
# member UUIDs found", before the recovery-passphrase authorization)
mkdir -p "$RUN/cli-state/etc/alpine-fde/keys"
mkdir -p "$RUN/cli-state/etc"
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$DISK_UUID" \
    >"$RUN/cli-state/etc/crypttab"
cp "$RUN/keys/release.pub" "$RUN/cli-state/etc/alpine-fde/keys/release.pub"
cp "$RUN/keys/db.key" "$RUN/cli-state/etc/alpine-fde/keys/release.pem"
cat >"$RUN/cli-state/etc/alpine-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
cat >"$RUN/cli-state/etc/alpine-fde/baseline.json" <<JSON
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
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
    "release_pub_path": "/etc/alpine-fde/keys/release.pub",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "$DISK_UUID",
    "esp_partuuid": ""
  }
}
JSON
# fixture efivars (SB on, setup mode 0) — the audit + guard read these
EFIVARS="$RUN/cli-state/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
# the by-uuid seam + the Stage-1 stand-in rekey (floor: the well-known slot-0
# passphrase is blocklisted at fin_read_recovery_passphrase)
mkdir -p "$RUN/by-uuid"
ln -sfn "$RUN/disk.img" "$RUN/by-uuid/$DISK_UUID"
# the completion's KEYDIR is $RUN/keys — stage the ADR-18 release.pem there
# (finalize STEP 2 encrypts it in place; repro 2026-09-24: without it the
# completion died rc 64 "release.pem not found in …/keys" right after the
# passphrase authorization)
cp "$RUN/keys/db.key" "$RUN/keys/release.pem"
CRYPTSETUP_BIN=$(command -v cryptsetup)
timeout 120 "$CRYPTSETUP_BIN" luksChangeKey --key-slot 0 "$RUN/disk.img" \
    <(printf '%s' "$S22_RECOVERY") --key-file "$RUN/kf-slot0" 2>/dev/null \
    || { echo "s22: host-side keyslot-0 rekey failed"; exit 1; }
# THE COMPLETION (guided Stage 3 host-side; the DISK mutates through by-uuid)
# (derive the TCTI — SWTPM_TCTI was never exported into this shell, see above)
ALPINE_FDE_TCTI="$(_swtpm_tcti_for "$RUN/tpm")" \
ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
ALPINE_FDE_EVENTLOG="$RUN/cli-state/eventlog-absent" \
ALPINE_FDE_ROOT="$RUN/cli-state" \
ALPINE_FDE_KEYDIR="$RUN/keys" \
ALPINE_FDE_KEY_PASSPHRASE="$S22_KEYPASS" \
ALPINE_FDE_RECOVERY_PASSPHRASE="$S22_RECOVERY" \
ALPINE_FDE_PCRSIG="$RUN/uki-pcrsig-711.json" \
ALPINE_FDE_BY_UUID_DIR="$RUN/by-uuid" \
ALPINE_FDE_TMPDIR="$RUN/tmp" \
ALPINE_FDE_NO_INSTALL=1 \
    timeout 600 "$REPO/bin/alpine-fde" finalize >"$RUN/completion.out" 2>&1
COMPLETION_RC=$?
assert_eq "completion: production finalize rc 0" "0" "$COMPLETION_RC"
grep -q "recovery passphrase verified against keyslot 0 (attempt 1)" "$RUN/completion.out" \
    && _assert_result ok "completion: recovery passphrase authorized the chain (keyslot 0)" "" \
    || _assert_result not-ok "completion: recovery passphrase authorized the chain (keyslot 0)" \
        "no verify marker in completion.out"
grep -q "finalizing the baseline from live values (audit --init" "$RUN/completion.out" \
    && _assert_result ok "completion: audit --init finalized the pending baseline from live values" "" \
    || _assert_result not-ok "completion: audit --init finalized the pending baseline" \
        "no audit marker in completion.out"
grep -q "token upgraded to Mechanism B {PCR 7, PCR 11}" "$RUN/completion.out" \
    && _assert_result ok "completion: the provisional token upgraded to Mechanism B {PCR 7, PCR 11}" "" \
    || _assert_result not-ok "completion: the provisional token upgraded to Mechanism B" \
        "no upgrade marker in completion.out"
grep -q "alpine-fde: install finalized" "$RUN/completion.out" \
    && _assert_result ok "completion: install finalized (state written LAST)" "" \
    || _assert_result not-ok "completion: install finalized (state written LAST)" \
        "no finalized marker in completion.out"
assert_contains "completion: the state doc reads finalized" "finalized" \
    "$(jq -r '.state' "$RUN/cli-state/etc/alpine-fde/install-state.json")"
assert_eq "completion: the ADR-8 marker is CLEAR" "absent" \
    "$([[ -e "$RUN/cli-state/etc/alpine-fde/finalize-attempt.txt" ]] && echo present || echo absent)"
# THE WINDOW-EXIT ASSERT OF RECORD: {7,11} on a non-zero keyslot, recovery at
# slot 0 intact. The slot NUMBER is not pinned: seal_upgrade_token's crash-safe
# choreography stands the fresh seal in the NEXT FREE slot and only then
# retires the provisional one — after a provisional token at slot 1 the
# finalized token lands on slot 2 and the retired slot disappears (keyslots
# {0,2}); the lib contract is "exactly one token, new slot != 0" (I1 two-
# keyslot at-rest holds either way).
METAF=$(disk_metadata "$RUN/disk.img")
TOKF=$(disk_token_json "$RUN/disk.img")
EXIT_SLOT=$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKF")
assert_eq "S-22 window exit: EXACTLY ONE token" "1" \
    "$(jq '[.[] | select(.type == "systemd-tpm2")] | length' <<<"$TOKF")"
assert_eq "S-22 window exit: the token binds {PCR 7, PCR 11}" "[7,11]" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKF")"
assert_ne "S-22 window exit: the token sits on a NON-ZERO keyslot" "0" "$EXIT_SLOT"
assert_eq "S-22 window exit: keyslots == {0, token slot} (I1 two-keyslot at-rest)" \
    "[\"0\",\"$EXIT_SLOT\"]" "$(jq -c '.keyslots | keys' <<<"$METAF")"
assert_eq "S-22 window exit: recovery keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$METAF")"

# ============================================================================
# BOOT 3 — TAMPERED UKI, after the window exit: the finalized {7,11} token is
# equally image-bound (the immunity claim holds past the window too) — the
# PolicyPCR(7,11) digest of the tampered boot misses -> refused -> the bounded
# recovery loop takes 3 wrong passphrases -> 3-strike fail-closed
# ============================================================================
echo "# boot 3: tampered-UKI variant — the sealed blob must refuse (T2c immunity)"
# stop + start (NOT just ensure): the tampered boot must re-derive its PCRs
# from zero, never stack extends on the completion leg's register
swtpm_stop "$RUN/tpm" 2>/dev/null || true
run_stage swtpm-cycle-3 90 swtpm_start "$RUN/tpm"
_rearm_trap
_boot_hook "$RUN/boot3" "$RUN/esp-tampered.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" \
    "$RUN/uki-pcrsig-711.img" "$RUN/harness-tampered.efi"
for n in 1 2 3; do
    # 600 s per prompt: this box's boots crawl under background tenants
    # (live-seen 2026-09-22 — prompts past the 300 s mark); the hook's read
    # has no timeout, so prompt-synchronized feeding is unaffected.
    if uki_wait_hook_prompt "$n" 600 "$RUN/boot3"; then
        feed_line "$RUN/boot3/serial.sock" "alpine-fde-wrong-passphrase-$n"
    else
        _hang_fail CONSOLE-WAIT "tampered recovery prompt $n" "never appeared"
    fi
done
wait_console "$RUN/boot3" "$(sentinel_of unseal_poweroff)" 300
run_stage qemu_wait-boot3 "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/boot3" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_B3=$(cat "$RUN/boot3/console.log" 2>/dev/null || true)
assert_contains "[boot 3] init ran (the tampered UKI boots — SB-on firmware trusts our key)" \
    "$LOG_B3" "alpine-fde-harness: init started"
assert_contains "[boot 3] the tampered cmdline word reached the kernel (the primitive is real)" \
    "$LOG_B3" "alpine-fde-tampered"
assert_contains "[boot 3] hook discovered the standing token" "$LOG_B3" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "[boot 3] the TPM refused the sealed blob under the tampered PCR state" "$LOG_B3" \
    "$(sentinel_of unseal_seal_refused)"
assert_eq "[boot 3] exactly 3 recovery-passphrase prompts (bounded loop)" "3" \
    "$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG_B3" || true)"
assert_contains "[boot 3] 3-strike give-up (§8.2 fail-closed)" "$LOG_B3" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[boot 3] fail-closed poweroff (no shell is offered)" "$LOG_B3" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[boot 3] NEVER unlocked via the token" "$LOG_B3" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[boot 3] NEVER unlocked via the recovery passphrase" "$LOG_B3" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[boot 3] never UNSEALED" "$LOG_B3" "alpine-fde: UNSEALED"
assert_not_contains "[boot 3] no emergency shell" "$LOG_B3" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot3/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot3/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[boot 3] guest exited (hook 3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[boot 3] guest exited (hook 3-strike poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
# the tampered boot mutated NOTHING: the finalized shape is intact (slot
# number not pinned — see the window-exit note above; {0, EXIT_SLOT} holds)
METAB3=$(disk_metadata "$RUN/boot3/disk.img")
B3_SLOT=$(disk_token_json "$RUN/boot3/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "[boot 3] host(booted img): finalized shape intact — keyslots == {0, token slot}" \
    "[\"0\",\"$B3_SLOT\"]" "$(jq -c '.keyslots | keys' <<<"$METAB3")"
assert_eq "[boot 3] host(booted img): finalized shape intact — token pcrs [7,11]" "[7,11]" \
    "$(disk_token_json "$RUN/boot3/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')"

# NOTE: boot 3's payload drive carries the VALID {7,11} signature — the
# refusal is the PCR session digest, never the signature gate

# keep run dirs small
rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/harness-tampered.efi" 2>/dev/null

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s22-handoff-immunity: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s22-handoff-immunity: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
