#!/usr/bin/env bash
# tests/e2e/s15-recovery-chain.sh — §12 Disaster Recovery & Drift Pipeline
# (Wave-2 task 5b; tests/README.md "Scenario Consolidation & Lifecycle
# Pipelining (Approach 1)", pipeline 2). ONE progressive scenario covering,
# in 5 physical launches (4 in the skip modes), what s15 + s17 cover
# standalone:
#
#   b0-producer (full mode only)  baseline (token-less disk) -> fed slot-0
#                                 recovery unlock; host-side finalized
#                                 {7,11} enroll   (absorbs s15/s17 boot 1)
#   b1-pcr7-drift                 dbx-updated vars -> stale-seal refusal ->
#                                 3-strike fail-closed poweroff
#                                                   (absorbs s15 boot 2)
#   b2-rebaselined                zero-input passwordless boot under the
#                                 re-sealed {drifted d7, d11} token
#                                                 (absorbs s15 boot 3)
#   b3-tpm-clear                  swtpm_reset (fresh SRK) -> sealed blob
#                                 refuses -> 3-strike fail-closed poweroff
#                                                 (absorbs s17 boot 2)
#   b4-restored                   zero-input passwordless boot on the fresh
#                                 SRK (unseal restored)
#                                                 (absorbs s17 boot 3)
#
# Between the boots the recovery is the §9.4 HOST-side operator drill, exactly
# as in the absorbed scenarios: wipe the stale enrollment (token + keyslot),
# re-stamp the baseline to the register the machine actually reproduces, and
# re-enroll via the REAL production CLI (digest-anchored: the fresh seal
# composes over the UNCHANGED enter-initrd d11 and the new d7 — no volume-key
# re-encryption, no re-signing ceremony beyond the release key the CLI
# already holds). The §9.4 DETECTION leg (real `alpine-fde audit` over a
# live synthesized drift: exit 1 + pcr7 DRIFT -> `audit --accept --yes` ->
# clean) runs host-side before b1.
#
# RECOVERY-DRILL SHAPE (deliberate, per the absorbed scenarios): the in-guest
# recovery loop is FAIL-CLOSED — the drift/clear boots feed 3 WRONG answers
# prompt-synchronized and assert the 3-strike `poweroff -f` (never an
# emergency shell, never a token/passphrase unlock). The CORRECT-passphrase
# recovery unlock is exercised on the b0-producer boot (token-less volume ->
# the hook's own prompt -> fed slot-0 -> UNSEALED), which is exactly where
# s15/s17 exercise it. The approved 3-boot sketch collapsed the two refusal
# legs into one in-guest recovery unlock; that would drop the 3-strike /
# fail-closed assertions, so the implemented plan keeps both refusal boots.
#
# PERSISTENT-MUTATION MAP (R1/R3):
#   * b0 producer, b2, b4 are positive legs — their overlays are COMMITTED
#     into the canonical disk (R1 in-place advance; the boots themselves
#     change nothing on the LUKS volume, so the commit is idempotent).
#   * b1 and b3 are refusal legs — their overlays are DISCARDED even on a
#     clean run (a fail-closed boot must not advance anything).
#   * the §9.4 host drill's pcrextend mutates ONLY the fixture TPM's volatile
#     PCR state — every boot re-anchors the TPM to a zeroed register first
#     (_reanchor_tpm), so nothing of it leaks into any boot.
#   * swtpm_reset (the b3 drill) is a DELIBERATE persistent mutation of the
#     canonical TPM state (it IS the scenario's subject): the fresh SRK kills
#     the standing seal, and the recovery-reseal-2 stage restores a working
#     enrollment under the new SRK before b4.
#
# R2 (from-cache fast path): mode resolution, in order:
#     1. ALPINE_FDE_PIPELINE_FULL=1  -> full-from-install (explicit opt)
#     2. ALPINE_FDE_E2E_STATE (run-e2e.sh chain: a valid s00b run dir)
#                                     -> state-consume (producer legs skipped)
#     3. tests/e2e/.cache/pristine-s00b (SHA-verified)
#                                     -> cache-reuse (producer legs skipped)
#     4. otherwise                    -> full-from-install (cold path)
# The mode is on the record twice: a "# pipeline mode: <mode>" log line and
# the stage labels (`producer-leg` + `finalize-baseline` exist ONLY in full
# mode; `cache-reuse` covers both skip modes). In the skip modes the cached
# ENROLLED base is consumed read-only (snapshot first): the b1 drift refusal
# replays against the STANDING cached seal (its combined entry rides the
# payload drive verbatim), and the seam-free release UKI the later legs boot
# is built host-side in recovery-reseal-1 — the cached release UKI carries
# the fed-session DEBUG SHELL seam, so it can only serve the refusal leg
# (whose hook powers off inside its own invocation) and never a
# default-stage clean-poweroff boot.
#
# R3 (overlay / LOCK_SH discipline): every boot of every leg runs on a fresh
# QCOW2 overlay over the canonical disk (tests/lib/overlay-disk.sh — LOCK_SH
# on the whole backing chain for the boot's lifetime). Positive legs COMMIT;
# refusal legs and failed attempts DISCARD. Bounded at 2 attempts; a wedged
# attempt is discarded and re-run, never waited out.
#
# Tamper-scoping evidence (the s15/s17 G-T13 NBs, kept): the refusal boots
# fail closed INSIDE the hook's invocation, so no postphase PCR 11 reading
# appears and NO assert_pcr11_prediction runs there — the early console PCR
# 11 equality (b3 vs b2, and b1 vs the producer console in full mode) is the
# "the drift is PCR 7 only" scoping. The unsealing legs (b0, b2, b4) carry
# the signed prediction assert.
#
# Superseded scenarios (s15, s17) STAY in the tree and in the default
# selection; this pipeline is a CHAIN member and runs in the runner's
# SEQUENTIAL hoist phase (s00 -> s00b -> s01c -> s15c), see tests/run-e2e.sh.

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
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13)
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # R3: per-boot QCOW2 overlays + base locking
# shellcheck source=../lib/stage-timing.sh
source "$TESTS/lib/stage-timing.sh"   # Step timing: # stage <label>: begin/done lines
# shellcheck source=../../lib/firmware.sh
source "$REPO/lib/firmware.sh"     # fw_sb_state (the G-R1 efivars seam sanity)

CACHE_DIR="$TESTS/e2e/.cache/pristine-s00b"
PIPELINE_FULL="${ALPINE_FDE_PIPELINE_FULL:-0}"
export QEMU_TIMEOUT="${ALPINE_FDE_PIPELINE_TIMEOUT:-900}"
export SWTPM_FIXTURE_VERBOSE=1    # tpm-cmd.log on disk for EVERY boot (s14 pattern)

# --- hardening: bounded legs, loud failures, overall budget (s01c pattern) -------
# The outer SCENARIO_BUDGET must exceed this; recommend
# ALPINE_FDE_SCENARIO_BUDGET=2700 for full-from-install registry runs —
# from-cache/state-consume runs finish well inside the default budget.
OVERALL_BUDGET="${ALPINE_FDE_PIPELINE_BUDGET:-2400}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {   # _hang_fail <kind> <stage> <detail> — loud, greppable, fatal
    printf '\ns15c: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's15c: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    # 125, NOT timeout(1)'s 124: an internal watchdog fire must never be
    # misread by run-e2e as "exceeded the outer scenario budget".
    exit 125
}
_budget_check() {   # _budget_check <where>
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
_stage_open() {   # _stage_open <label> — leaf-only stage timer (loud on misuse)
    stage_begin "$1" || _hang_fail STAGE-TIMING "$1" "stage_begin refused"
}
_stage_close() {
    stage_end "$1" || _hang_fail STAGE-TIMING "$1" "stage_end refused"
}
# _step <label> — a plain (lib-function) host step: budget-checked, echoed
_step() {
    _budget_check "step:$1"
    echo "# s15c: step $1"
}
_qemu_alive() {   # <run-dir> — fail LOUDLY on a qemu that died at startup
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s15c: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s15c: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}
_qemu_alive_check() { kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; }

# _reanchor_tpm <dir> — before EVERY guest boot the fixture TPM must be a
# FRESH, ZEROED instance (the s01c/s15/s17 hardening: a restored volatilestate
# makes the next boot CUMULATIVE and the {7,11} policy refuses its own
# enrollment). Zeroed-pre-boot is ASSERTED, not assumed. The SRK persists in
# tpm2-00.permall across this (seals survive); swtpm_reset is the ONE leg that
# deliberately discards it (b3's drill).
_reanchor_tpm() {
    local dir="$1" d0 d7 k
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    # swtpm_start is internally bounded (10 s socket/ready loop, per-probe
    # timeouts) — called plainly: it is a sourced FUNCTION, not an executable
    _SWTPM_CLEANUP_TRAP_SET=1 swtpm_start "$dir" \
        || { echo "s15c: swtpm_start (re-anchor) failed"; exit 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    d7=$(swtpm_pcrread "$dir" 7)
    if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ ]]; then
        _assert_result ok "fixture: TPM re-anchored (PCRs 0 and 7 zero before the boot)" ""
    else
        _assert_result not-ok "fixture: TPM re-anchored (PCRs 0 and 7 zero before the boot)" \
            "pcr0=$d0 pcr7=$d7 — refusing to spend the boot on a cumulative register"
        echo "s15c: TPM not zeroed before a boot — aborting"
        exit 1
    fi
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
}

# _wedge_wait <dir> <timeout-s> — the swtpm data-loop WEDGE guard (s02/s16
# mitigation; swtpm 0.10.2 de-registers the data client on ctrl EOF and never
# re-adds it: Recv-Q > 0, console idle > 60 s). Recovery: qemu_kill + fresh
# swtpm start; return 43 so the caller's bounded retry re-runs the boot;
# 44 = recovery restart failed; 0 = qemu exited on its own; 124 = timeout.
_wedge_wait() {
    local dir="$1" timeout="$2" pid
    pid=$(cat "$dir/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout)) sz last_sz last_chg
    last_sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
    last_chg=$SECONDS
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            pkill -9 -f "python3 - $dir/qmp.sock" 2>/dev/null
            serial_bridge_stop "$dir"
            return 0
        fi
        _qmp_kicker_start "$dir"
        sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
        if ((sz != last_sz)); then last_sz=$sz; last_chg=$SECONDS; fi
        if ((SECONDS - last_chg > 60)); then
            if ss -xn 2>/dev/null | awk -v s="$dir/tpm/sock" '$0 ~ s && ($3 + 0) > 0 { found = 1 } END { exit !found }'; then
                echo "WEDGE-RECOVERED: swtpm data-loop stall (console idle >60 s, Recv-Q>0 on $dir/tpm/sock) — killing qemu, restarting swtpm fresh"
                qemu_kill "$dir"
                swtpm_stop "$dir" >/dev/null 2>&1
                if ! swtpm_start "$dir" >/dev/null 2>&1; then
                    echo "WEDGE-RECOVERED: swtpm restart FAILED — caller must abort"
                    return 44
                fi
                return 43
            fi
        fi
        _budget_check "wedge-wait"
        sleep 5
    done
    qemu_kill "$dir"
    return 124
}

# --- ESP helpers (mtools on the file-backed image) --------------------------------
_esp_add_uki() { # <esp.img> <uki.efi> <name.efi>
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name" || return 1
}
_esp_set_default() { # <esp.img> <uki.efi> — swap the removable-path default
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI || return 1
}

# --- the boot driver (R1+R3): overlay boot, COMMIT or DISCARD ---------------------
# _pipeline_boot <label> <esp> <vars> <payload-drive> <commit|discard> [feed]
# Stage label: boot-<label> (leaf). Every attempt: fresh QCOW2 overlay over
# the CANONICAL disk (LOCK_SH on the backing chain via overlay_create),
# qemu_run, the swtpm data-loop wedge guard as the wait, then COMMIT (R1
# in-place advance) or DISCARD. feed="feed": the recovery-passphrase prompt
# is fed ONCE with the CORRECT slot-0 passphrase (the b0 recovery unlock);
# feed="feed3": THREE WRONG answers are fed prompt-synchronized on prompts
# 1..3 (the fail-closed refusal drill). Bounded at 2 attempts.
_pipeline_boot() {
    local label="$1" esp="$2" vars="$3" payload="$4" mode="$5" feed="${6:-}"
    local att wrc overlay n
    _stage_open "boot-$label"
    for att in 1 2; do
        _budget_check "boot:$label:att$att"
        _reanchor_tpm "$RUN/tpm"
        rm -f "$RUN/console.log"
        overlay="$RUN/disk-$label-$att.qcow2"
        overlay_create "$CANON_DISK" "$overlay" || {
            echo "s15c: overlay create failed for $label"; exit 1; }
        echo "# boot $label (attempt $att/2, overlay $mode; up to $QEMU_TIMEOUT s) ..."
        CURRENT_QEMU_DIR="$RUN"
        if ! qemu_run "$RUN" "$esp" "$overlay" "$vars" "$RUN/tpm" "$payload"; then
            echo "s15c: qemu_run FAILED for $label; qemu.stderr:"
            tail -5 "$RUN/qemu.stderr" 2>/dev/null
            overlay_discard "$overlay"
            exit 1
        fi
        _qemu_alive "$RUN"
        if [[ "$feed" == "feed" ]]; then
            if uki_wait_hook_prompt 1 300 "$RUN"; then
                feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
            else
                echo "s15c: [$label] no recovery-passphrase prompt within 300 s (qemu $(if _qemu_alive_check; then echo alive; else echo DEAD; fi))"
            fi
        elif [[ "$feed" == "feed3" ]]; then
            for n in 1 2 3; do
                _budget_check "feed3:$label:$n"
                if uki_wait_hook_prompt "$n" 300 "$RUN"; then
                    feed_line "$RUN/serial.sock" "alpine-fde-wrong-passphrase-$n"
                else
                    echo "s15c: [$label] no recovery-passphrase prompt $n/3 within 300 s (the assertions judge the console)"
                    break
                fi
            done
        fi
        wrc=0
        _wedge_wait "$RUN" "$QEMU_TIMEOUT" || wrc=$?
        if ((wrc == 43)); then
            echo "s15c: $label wedged mid-boot (swtpm data-loop stall) — discarding the attempt, retrying"
            overlay_discard "$overlay"
            (( att < 2 )) && continue
            echo "s15c: $label still wedged after recovery + retry — aborting"
            exit 1
        fi
        if ((wrc == 44 || wrc == 124)); then
            overlay_discard "$overlay"
            echo "s15c: $label wait rc=$wrc (timeout-kill / wedge-recovery failure) — aborting"
            exit 1
        fi
        if [[ "$mode" == "commit" ]]; then
            _bounded_commit qemu-img commit -f qcow2 -- "$overlay"
        fi
        overlay_discard "$overlay"
        cp "$RUN/console.log" "$RUN/console-$label.log"   # THIS boot's evidence
        CURRENT_QEMU_DIR=""
        _stage_close "boot-$label"
        return 0
    done
}
_bounded_commit() {   # timeout-bounded overlay commit (external command)
    _budget_check "overlay-commit"
    timeout 900 "$@" || { echo "s15c: overlay commit FAILED: $*"; exit 1; }
}

# _cache_verify <dir> — rc 0 iff the pristine cache exists AND every recorded
# SHA256 matches (fail-closed; the s00b verifier verbatim: FORMAT btrfs-3 +
# the enrolled-state file set).
_cache_verify() {
    local dir="$1"
    [[ -f "$dir/FORMAT" ]] && grep -q '^btrfs-3$' "$dir/FORMAT" || return 1
    [[ -f "$dir/MANIFEST.sha256" && -f "$dir/disk.img" && -f "$dir/tpm/tpm2-00.permall" \
        && -f "$dir/harness.efi" && -f "$dir/pcrsig.img" && -f "$dir/vars-enrolled.fd" \
        && -f "$dir/baseline.json" && -f "$dir/uki-pcrsig.json" \
        && -f "$dir/uki-pcrsig-combined.json" ]] || return 1
    (cd "$dir" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1
}
# _state_shape_ok <dir> — the s00b RUN DIR contract subset the skip modes need.
_state_shape_ok() {
    local dir="$1"
    [[ -f "$dir/disk.img" && -d "$dir/tpm" && -f "$dir/tpm/tpm2-00.permall" \
        && -f "$dir/harness.efi" && -f "$dir/keys/release.pub" \
        && -f "$dir/vars-enrolled.fd" && -f "$dir/baseline.json" \
        && -f "$dir/uki-pcrsig.json" && -f "$dir/uki-pcrsig-combined.json" ]]
}
# _restore_base <src> — snapshot the (skip-mode) base into THIS run dir. The
# canonical state is ALWAYS the run dir's own copy (R1): the shared cache /
# state dir is never mutated (consumers snapshot their inputs).
_restore_base() {
    local src="$1"
    _bounded_cp 900 cache-restore-disk "$src/disk.img" "$RUN/disk.img"
    _bounded_cp 120 cache-restore-uki "$src/harness.efi" "$RUN/uki-cached.efi"
    _bounded_cp 60 cache-restore-pcrsig "$src/uki-pcrsig.json" "$RUN/uki-cached.pcrsig.json"
    _bounded_cp 60 cache-restore-combined "$src/uki-pcrsig-combined.json" "$RUN/uki-cached-combined.json"
    [[ -d "$src/keys" ]] && cp -a "$src/keys" "$RUN/keys"
    _bounded_cp 60 cache-restore-vars "$src/vars-enrolled.fd" "$RUN/vars-enrolled.fd"
    mkdir -p "$RUN/tpm"
    # LOUD, never a silent skip: a missing permall would boot every leg
    # against a VIRGIN TPM whose seed cannot unseal the standing token
    # (the s00b from-cache breakage class).
    if [[ -f "$src/tpm/tpm2-00.permall" ]]; then
        _bounded_cp 60 cache-restore-permall "$src/tpm/tpm2-00.permall" "$RUN/tpm/"
    else
        echo "s15c: FATAL: no TPM state at $src/tpm/tpm2-00.permall — the sealing SRK cannot be reproduced"
        exit 1
    fi
    mkdir -p "$RUN/rootfs/etc/alpine-fde"
    _bounded_cp 60 cache-restore-baseline "$src/baseline.json" "$RUN/baseline.json"
    _bounded_cp 60 cache-restore-baseline-rootfs "$src/baseline.json" "$RUN/rootfs/etc/alpine-fde/baseline.json"
    _track_swtpm "$RUN/tpm"
}
_bounded_cp() {   # <timeout-s> <label> <src> <dst>
    local tmo="$1" label="$2"; shift 2
    _budget_check "cp:$label"
    timeout "$tmo" cp "$@" || { echo "s15c: STEP-FAILED [cp:$label]"; exit 1; }
}
_track_swtpm() { SWTPM_DIRS+=("$1"); }

# --- shared assertion helpers -------------------------------------------------
console_pcr() { # <label> <idx>
    grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2
}
# _assert_token <img> <label> — the standing-enrollment shape asserts
_assert_token() {
    local img="$1" label="$2" ntok tokpcrs
    ntok=$(disk_token_json "$img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
    assert_eq "[$label] exactly ONE standing systemd-tpm2 token (no dead-slot accumulation)" "1" "$ntok"
    tokpcrs=$(disk_token_json "$img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
    assert_eq "[$label] standing token pins the finalized {PCR 7, PCR 11}" "[7,11]" "$tokpcrs"
}
# _assert_recovery_unlock <log> <label> — the b0 fed-recovery core (s15/s17
# boot 1: token-less volume -> the hook's OWN prompt -> the CORRECT slot-0
# passphrase -> UNSEALED, default-stage clean poweroff)
_assert_recovery_unlock() {
    local log="$1" label="$2"
    assert_contains "[$label] init ran" "$log" "$(sentinel_of harness_init_started)"
    assert_contains "[$label] hook recovery loop opened (no token on the fresh volume)" "$log" \
        "$(sentinel_of unseal_token_missing)"
    assert_contains "[$label] fed slot-0 passphrase unsealed via the recovery path" "$log" \
        "$(sentinel_of unseal_pass_unlocked)"
    assert_contains "[$label] UNSEALED" "$log" "$(sentinel_of harness_unsealed)"
    assert_contains "[$label] clean poweroff" "$log" "$(sentinel_of harness_poweroff)"
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
}
# _assert_unsealed <log> <label> — the zero-input passwordless core (b2/b4;
# every re-baselined/restored leg re-expresses it for the progressive state)
_assert_unsealed() {
    local log="$1" label="$2"
    assert_contains "[$label] init ran" "$log" "$(sentinel_of harness_init_started)"
    assert_contains "[$label] the §8.2 unseal hook owns the unlock (default mechanism)" "$log" \
        "alpine-fde-harness: unlock mechanism: hook"
    assert_not_contains "[$label] the 257.13 oracle stayed out (opt-in only)" "$log" \
        "alpine-fde-harness: unlock mechanism: oracle"
    assert_contains "[$label] hook ran the enter-initrd extend (single phase word)" "$log" \
        "$(sentinel_of unseal_pcrextend_ok)"
    assert_contains "[$label] standing finalized token discovered (pcrs [7,11])" "$log" \
        "$(sentinel_of unseal_token_info)7,11]"
    assert_not_contains "[$label] no recovery-passphrase prompt ever opened (zero-input path)" "$log" \
        "$(sentinel_of unseal_prompt_re)"
    assert_contains "[$label] token unlocked via the TPM (zero-input §8.2 path — recovery complete)" "$log" \
        "$(sentinel_of unseal_unlocked)"
    assert_contains "[$label] volume UNSEALED" "$log" "$(sentinel_of harness_unsealed)"
    assert_contains "[$label] clean poweroff" "$log" "$(sentinel_of harness_poweroff)"
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    assert_not_contains "[$label] no new enrollment in-guest (Mechanism B seal)" "$log" \
        "$(sentinel_of cli_seal_slot)"
    assert_not_contains "[$label] no cryptenroll anywhere" "$log" \
        "$(sentinel_of cryptenroll_enrolled)"
}
# _assert_refused <log> <label> — the fail-closed refusal core (b1 drift +
# b3 tpm-clear): I3 gate passes, the SEAL refuses, the bounded loop reads 3
# WRONG answers, 3-strike fail-closed poweroff, never unlocked.
_assert_refused() {
    local log="$1" label="$2" nprompts _ref_line _p1_line
    assert_contains "[$label] init ran (still boots — the firmware re-measures the fresh/drifted TPM)" "$log" \
        "$(sentinel_of harness_init_started)"
    assert_contains "[$label] hook ran the enter-initrd extend" "$log" \
        "$(sentinel_of unseal_pcrextend_ok)"
    assert_contains "[$label] hook discovered the {7,11} token" "$log" \
        "$(sentinel_of unseal_token_info)7,11]"
    assert_not_contains "[$label] I3 gate passed (the signature is NOT the defect)" "$log" \
        "$(sentinel_of unseal_sig_refused)"
    assert_contains "[$label] hook refused the stale seal (static PCR 7 term / fresh SRK)" "$log" \
        "$(sentinel_of unseal_seal_refused)"
    _ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$RUN/console-$label.log" 2>/dev/null | cut -d: -f1)
    _p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console-$label.log" 2>/dev/null | cut -d: -f1)
    if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
        _assert_result ok "[$label] hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
    else
        _assert_result not-ok "[$label] hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
    fi
    nprompts=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$log" || true)
    assert_eq "[$label] exactly 3 recovery-passphrase prompts (bounded loop, 3 WRONG answers fed)" \
        "3" "$nprompts"
    assert_contains "[$label] 3-strike give-up (§8.2 fail-closed)" "$log" "$(sentinel_of unseal_3strike)"
    assert_contains "[$label] fail-closed poweroff (no shell is offered)" "$log" \
        "$(sentinel_of unseal_poweroff)"
    assert_not_contains "[$label] never unlocked (token)" "$log" "$(sentinel_of unseal_unlocked)"
    assert_not_contains "[$label] never unlocked (recovery passphrase)" "$log" \
        "$(sentinel_of unseal_pass_unlocked)"
    assert_not_contains "[$label] never UNSEALED" "$log" "$(sentinel_of harness_unsealed)"
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    # IN-08: honest in both directions (missing pid file is not a clean exit)
    if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "[$label] guest exited (hook poweroff -f, not timeout-kill)" ""
    else
        _assert_result not-ok "[$label] guest exited (hook poweroff -f, not timeout-kill)" \
            "qemu still running or qemu.pid missing"
    fi
}
# _host_wipe_enrollment <img> — the §9.4 operator step (token remove +
# luksKillSlot; --key-file: the wipe needs to authenticate against the
# remaining keyslot, an unattended stdin blocks FOREVER otherwise).
_host_wipe_enrollment() {
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        timeout 120 cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue
        timeout 120 cryptsetup luksKillSlot --batch-mode --key-file "$RUN/kf-slot0" \
            "$img" "$slot" </dev/null || return 1
    done
}
# _enroll_finalized <pcrsig.json> <logfile> — the REAL production CLI
# enroll-tpm host-side (digest-anchored: the entry's recorded d7/d11 are
# compared against the baseline as pure data; no live TPM PCR read; the TPM
# must be serving for the SRK seal). rc asserted by the caller.
_enroll_finalized() {
    local pcrsig="$1" logfile="$2"
    uki_host_enroll_finalized "$EFIVARS" "$pcrsig" "$CANON_DISK" "$RUN/keys" \
        "$RUN/kf-slot0" "$RUN/rootfs" >"$logfile" 2>&1
}
# _audit_cli — the real CLI `audit` against the fixture swtpm (s15 verbatim)
_audit_cli() {
    swtpm_ensure "$RUN/tpm" || { echo "s15c: swtpm not serving (audit)"; return 64; }
    ALPINE_FDE_ROOT="$RUN/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
        ALPINE_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
        ALPINE_FDE_NO_INSTALL=1 \
        "$REPO/bin/alpine-fde" audit "$@"
}
_mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }

RUN="$TESTS/e2e/.runs/s15-recovery-chain-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
CONSOLE_SAVED="$CONSOLE"
CANON_DISK="$RUN/disk.img"
CANON_ESP="$RUN/esp.img"

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

_exit_cleanup() {
    [[ -n "$CURRENT_QEMU_DIR" ]] && qemu_kill "$CURRENT_QEMU_DIR" 2>/dev/null
    local d
    for d in "${SWTPM_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d" 2>/dev/null
    done
    overlay_lock_release 2>/dev/null
    kill "$REFRESHER" 2>/dev/null
}
trap _exit_cleanup EXIT
_exit_on_int() { _exit_cleanup; exit 130; }
_exit_on_term() { _exit_cleanup; exit 143; }
trap _exit_on_int INT
trap _exit_on_term TERM

# =================================================================================
# Mode resolution (R2) — the mode is on the record BEFORE any fixture work.
# =================================================================================
MODE="full"
BASE_SRC=""
STATE="${ALPINE_FDE_E2E_STATE:-}"
if [[ "$PIPELINE_FULL" == "1" ]]; then
    MODE="full"
    echo "# pipeline mode: full-from-install (explicit opt ALPINE_FDE_PIPELINE_FULL=1)"
elif _state_shape_ok "$STATE"; then
    MODE="skip"
    BASE_SRC="$STATE"
    echo "# pipeline mode: state-consume from $STATE (run-e2e chain; producer legs skipped)"
elif _cache_verify "$CACHE_DIR"; then
    MODE="skip"
    BASE_SRC="$CACHE_DIR"
    echo "# pipeline mode: cache-reuse from $CACHE_DIR (SHA-verified pristine base; producer legs skipped)"
else
    MODE="full"
    echo "# pipeline mode: full-from-install (cold: no state chain, no valid pristine cache)"
fi

# =================================================================================
# b0 producer (full mode) / base restore (skip mode)
# =================================================================================
if [[ "$MODE" == "full" ]]; then
    # ---- producer-leg: fixtures + the seam-free release UKI ----------------------
    _stage_open "producer-leg"
    _SWTPM_CLEANUP_TRAP_SET=1 _step swtpm_start-producer; swtpm_start "$RUN/tpm" \
        || { echo "s15c: swtpm_start (producer) failed"; exit 1; }
    _track_swtpm "$RUN/tpm"
    _step keys_create; keys_create "$RUN/keys" || exit 1
    # ADR-16 floor BEFORE anything signs with the release identity
    _step release-key-floor; uki_release_key_floor "$RUN/keys" || exit 1
    _step keys_vars_enrolled; keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
    assert_contains "enrolled vars: SecureBootEnable ON" \
        "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
    _step uki_build-release
    # the RELEASE UKI, default stage, NO debug-shell seam: b2/b4 must end in a
    # clean default-stage poweroff (s15/s17's own builds carry no seam either)
    uki_build "$RUN" "$RUN/keys" "$RUN/uki.efi" \
        || { echo "s15c: uki_build (release) failed"; exit 1; }
    cp "$RUN/uki-pcrsig.json" "$RUN/uki.pcrsig.json"
    cp "$RUN/pcr11-enter-initrd.txt" "$RUN/pcr11.txt"
    assert_rc "release UKI is SB-valid (release-cert signature)" 0 \
        sbverify --cert "$RUN/keys/db.crt" "$RUN/uki.efi"
    D11=$(cat "$RUN/pcr11.txt")
    [[ -n "$D11" ]] || { echo "s15c: no enter-initrd d11 prediction from the build"; exit 1; }
    UKI_MIB=$(( ($(stat -c%s "$RUN/uki.efi") + 1048575) / 1048576 ))
    _step esp_make-producer
    # default UKI + room to spare (skip mode installs a second ::/EFI/Linux
    # copy in recovery-reseal-1; keep one formula for both modes)
    esp_make "$CANON_ESP" $(( UKI_MIB * 3 + 64 )) "$RUN/uki.efi" || exit 1
    _step disk_make_luks
    disk_make_luks "$CANON_DISK" 128 || exit 1
    # efivars seam for the enroll/audit I5+G-R1 guards (mkvar pattern from
    # tests/unit/baseline_finalize_guard.sh: attrs u32le 0x7 + payload byte)
    EFIVARS="$RUN/rootfs/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    _mkcertvar PK pk-cert-v1
    _mkcertvar KEK kek-cert-v1
    _mkcertvar db db-cert-v1
    _mkcertvar dbx dbx-cert-v1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN/kf-slot0"
    _stage_close "producer-leg"

    # ---- boot b0-producer: token-less disk -> fed slot-0 recovery unlock --------
    # The token-less disk puts the hook's BOUNDED recovery loop in control; the
    # feed is prompt-synchronized (the hook has NO read timeout). The SUCCESSFUL
    # overlay is committed (R1); the disk itself is unchanged by the unlock.
    _pipeline_boot "b0-producer" "$CANON_ESP" "$RUN/vars-enrolled.fd" "$RUN/pcrsig.img" commit feed
    LOG=$(cat "$RUN/console-b0-producer.log")
    _assert_recovery_unlock "$LOG" "b0-producer"
    # G-T13: the signed enter-initrd prediction on the unsealing boot
    CONSOLE="$RUN/console-b0-producer.log"
    assert_pcr11_prediction "G-T13 [b0-producer]"
    CONSOLE="$CONSOLE_SAVED"
    D7_ANCHOR=$(console_pcr b0-producer 7)
    PCR0_B0=$(console_pcr b0-producer 0)
    if [[ -n "$D7_ANCHOR" ]]; then
        _assert_result ok "b0 console records the enrolled PCR 7" ""
    else
        _assert_result not-ok "b0 console records the enrolled PCR 7" "no alpine-fde-pcr sha256:7 line"
    fi
    PCR11_B0=$(console_pcr b0-producer 11)

    # ---- finalize-baseline: stamp + the production-CLI enroll --------------------
    _stage_open "finalize-baseline"
    assert_contains "efivars fixture: SB on, SetupMode=0 (the seam really reads the fixture)" \
        "$(ALPINE_FDE_EFIVARS_DIR="$EFIVARS" fw_sb_state)" \
        "secureboot=1 setup_mode=0"
    # the finalized baseline the enroll preconditions read (uki_baseline_stamp
    # shape; the OPERATOR-meaningful d7 is the BOOTED machine's PCR 7)
    _step baseline_stamp
    uki_baseline_stamp "$RUN/rootfs" "$D7_ANCHOR" || { echo "s15c: baseline stamp failed"; exit 1; }
    sed -i "s|\"pcr0\": \"pending\"|\"pcr0\": \"$PCR0_B0\"|" "$RUN/rootfs/etc/alpine-fde/baseline.json"
    assert_eq "baseline carries the enrolled d7" "$D7_ANCHOR" \
        "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
    cp "$RUN/rootfs/etc/alpine-fde/baseline.json" "$RUN/baseline.json"
    _step pcrsig-combined
    uki_pcrsig_append_combined "$RUN/uki.pcrsig.json" "$RUN/combined-a.json" \
        "$D7_ANCHOR" "$D11" "$RUN/keys" || exit 1
    assert_eq "combined .pcrsig entry pol == policy_digest(enrolled d7, enter-initrd d11) (G-B6 shape)" \
        "$(policy_digest "$D7_ANCHOR" "$D11")" \
        "$(jq -r '.sha256[-1].pol' "$RUN/combined-a.json")"
    assert_contains "combined .pcrsig entry pins {PCR 7, PCR 11}" \
        "$(jq -c '.sha256[-1].pcrs' "$RUN/combined-a.json")" "[7,11]"
    uki_pcrsig_disk "$RUN/pcrsig-a.img" "$RUN/combined-a.json" || exit 1
    swtpm_ensure "$RUN/tpm" || { echo "s15c: swtpm restart (enroll) failed"; exit 1; }
    ENROLL_LOG="$RUN/enroll-a.log"
    if _enroll_finalized "$RUN/combined-a.json" "$ENROLL_LOG"; then
        _assert_result ok "enroll: the production CLI sealed the finalized {7,11} token (rc 0)" ""
    else
        _assert_result not-ok "enroll: the production CLI sealed the finalized {7,11} token (rc 0)" \
            "output: $(tail -3 "$ENROLL_LOG" 2>/dev/null | tr '\n' ' ')"
    fi
    _assert_token "$CANON_DISK" "enroll"
    TOKSLOT=$(disk_token_json "$CANON_DISK" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
    assert_eq "enroll: token on a fresh keyslot (recovery slot 0 untouched)" "1" "$TOKSLOT"
    _stage_close "finalize-baseline"
else
    # ---- skip mode: cache-reuse / state-consume (R2) -----------------------------
    _stage_open "cache-reuse"
    _restore_base "$BASE_SRC"
    # identity anchors of the STANDING cached enrollment: d7 from the
    # finalized baseline, d11 from the cached combined entry's digest anchor
    D7_ANCHOR=$(jq -r '.expected_pcr7 // empty' "$RUN/baseline.json")
    [[ "$D7_ANCHOR" =~ ^[0-9a-f]{64}$ ]] || { echo "s15c: baseline expected_pcr7 not finalized ($D7_ANCHOR)"; exit 1; }
    D11=$(jq -r '.sha256[-1].d11 // empty' "$RUN/uki-cached-combined.json")
    [[ "$D11" =~ ^[0-9a-f]{64}$ ]] || { echo "s15c: cached combined entry carries no d11 anchor"; exit 1; }
    assert_file_exists "cache-reuse: cached enrolled release UKI present" "$RUN/uki-cached.efi"
    UKI_MIB=$(( ($(stat -c%s "$RUN/uki-cached.efi") + 1048575) / 1048576 ))
    _step esp_make-cached
    # the ESP carries THREE UKI copies: the removable-path default (BOOTX64),
    # the cached ::/EFI/Linux entry, and the seam-free rebuild
    # recovery-reseal-1 installs — generous headroom (a too-tight ESP fails
    # the mcopy with "Disk full", loudly since the failure paths name it)
    esp_make "$CANON_ESP" $(( UKI_MIB * 3 + 64 )) "$RUN/uki-cached.efi" || exit 1
    _esp_add_uki "$CANON_ESP" "$RUN/uki-cached.efi" alpine-fde-cached.efi \
        || { echo "s15c: esp_add_uki (cached) FAILED"; exit 1; }
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"
    chmod 600 "$RUN/kf-slot0"
    EFIVARS="$RUN/rootfs/efivars-sb-on"
    mkdir -p "$EFIVARS"
    printf '\007\000\000\000\001' >"$EFIVARS/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    printf '\007\000\000\000\000' >"$EFIVARS/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    # the standing enrollment is VERIFIED, never redone (re-enrolling over the
    # standing token is exactly the work the cache exists to skip)
    _assert_token "$CANON_DISK" "cache-reuse"
    TOKSLOT=$(disk_token_json "$CANON_DISK" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
    assert_eq "cache-reuse: standing token on keyslot 1 (recovery slot 0 untouched)" "1" "$TOKSLOT"
    # the payload drive for the b1 replay: the cached combined entry VERBATIM
    # (its pol anchors the standing seal — the refusal must be the PCR 7 drift,
    # nothing else)
    uki_pcrsig_disk "$RUN/pcrsig-cached.img" "$RUN/uki-cached-combined.json" || exit 1
    echo "# cache-reuse: standing enrollment verified (1 systemd-tpm2 token, keyslot 1, pcrs 7,11) — producer legs skipped"
    _stage_close "cache-reuse"
fi

# =================================================================================
# §9.4 DETECTION drill (host-side, s15 verbatim): real `alpine-fde audit` over
# a live synthesized PCR 7 drift. Read-only for the disk; the pcrextend
# mutates only the fixture TPM's volatile PCRs (every boot re-anchors to a
# zeroed register first — nothing leaks into any boot).
# =================================================================================
_stage_open "drift-detect"
swtpm_ensure "$RUN/tpm" || { echo "s15c: swtpm not serving (drift)"; exit 1; }
DRIFT_HEX=$(printf 'dbx-update-sim' | sha256sum | awk '{print $1}')
swtpm_pcrextend "$RUN/tpm" 7 "$DRIFT_HEX"
D7_DRIFT=$(swtpm_pcrread "$RUN/tpm" 7)
assert_ne "§9.4: live PCR 7 drifted off the enrolled value" "$D7_ANCHOR" "$D7_DRIFT"
AUDOUT=$(mktemp)
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "§9.4: audit detects the drift (exit 1)" "1" "$_audit_rc"
assert_contains "§9.4: audit report: pcr7 DRIFT line" "$(grep '^pcr7' "$AUDOUT")" "DRIFT"
grep -E '^pcr' "$AUDOUT" | sed 's/^/# audit: /'
assert_rc "§9.4: audit --accept --yes re-baselines (real CLI)" 0 _audit_cli --accept --yes
BL7=$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")
assert_ne "§9.4: baseline re-baselined AWAY from the enrolled d7" "$D7_ANCHOR" "$BL7"
if _audit_cli >"$AUDOUT" 2>&1; then _audit_rc=0; else _audit_rc=$?; fi
assert_eq "§9.4: audit clean after re-baseline (exit 0)" "0" "$_audit_rc"
assert_contains "§9.4: last-audit.json records the clean post-accept audit" \
    "$(cat "$RUN/rootfs/etc/alpine-fde/last-audit.json")" '"result": "ok"'
# NB: exact-value equality with $D7_DRIFT is asserted only opportunistically —
# the fixture swtpm can restart between the two CLI invocations (the probe is
# conservative), re-zeroing PCRs; the re-baseline SEMANTICS above are the proof.
rm -f "$AUDOUT"
_stage_close "drift-detect"

# =================================================================================
# b1-pcr7-drift — dbx-updated VARS (the boot-layer drift, firmware-measured):
# the stale seal refuses, the bounded loop reads 3 WRONG answers, 3-strike
# fail-closed poweroff. Refusal leg: overlay DISCARDED. (Full mode replays
# against the just-landed {D7_ANCHOR, D11} seal; skip mode replays against
# the STANDING cached seal with its combined entry verbatim.)
# =================================================================================
echo "# ==== b1: PCR 7 drift (dbx update) -> stale-seal refusal ===="
_step vars-drifted
cp "$RUN/vars-enrolled.fd" "$RUN/vars-drifted.fd"
assert_rc "virt-fw-vars: dbx += throwaway cert" 0 \
    virt-fw-vars -i "$RUN/vars-drifted.fd" -o "$RUN/vars-drifted.fd" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$RUN/keys/KEK.crt"
if [[ "$MODE" == "full" ]]; then
    PAYLOAD_B1="$RUN/pcrsig-a.img"
else
    PAYLOAD_B1="$RUN/pcrsig-cached.img"
fi
_pipeline_boot "b1-pcr7-drift" "$CANON_ESP" "$RUN/vars-drifted.fd" "$PAYLOAD_B1" discard feed3
LOG=$(cat "$RUN/console-b1-pcr7-drift.log")
_assert_refused "$LOG" "b1-pcr7-drift"
D7_DRIFT_BOOT=$(console_pcr b1-pcr7-drift 7)
[[ -n "$D7_DRIFT_BOOT" ]] || { echo "s15c: b1 console has no PCR 7 print — nothing to re-seal over"; exit 1; }
assert_ne "the dbx update moved PCR 7 off the enrolled value (firmware-measured)" \
    "$D7_ANCHOR" "$D7_DRIFT_BOOT"
# tamper scoping: PCR 11 is untouched by the dbx change (the refusal is purely
# the PCR 7 drift). Full mode: equality with the producer boot's console
# (same UKI). Skip mode: the refusal boot is the CACHED UKI with no baseline
# console — the equality is carried by the b3-vs-b2 pair below instead, and
# here the early PCR 11 reading is asserted present + non-zero.
if [[ "$MODE" == "full" ]]; then
    assert_eq "PCR 11 unchanged vs the producer boot (drift is PCR 7 only)" \
        "$PCR11_B0" "$(console_pcr b1-pcr7-drift 11)"
else
    P11_B1=$(console_pcr b1-pcr7-drift 11)
    if [[ -n "$P11_B1" && "$P11_B1" != "$(printf '0%.0s' {1..64})" ]]; then
        _assert_result ok "PCR 11 present on the refusal console (skip mode: equality carried by b3-vs-b2)" ""
    else
        _assert_result not-ok "PCR 11 present on the refusal console" "pcr11=$P11_B1"
    fi
fi

# =================================================================================
# recovery-reseal-1 (host): wipe the stale enrollment, re-stamp the baseline
# to the DRIFTED (boot-layer) d7, re-seal over (drifted d7, UNCHANGED d11) —
# no volume-key re-encryption. Skip mode builds the seam-free release UKI
# here (the cached UKI's debug-shell seam bars it from the clean-poweroff
# legs) and swaps the ESP default to it.
# =================================================================================
echo "# ==== recovery 1: wipe + re-stamp + re-seal over the drifted d7 ===="
_stage_open "recovery-reseal-1"
if [[ "$MODE" == "skip" ]]; then
    _step uki_build-recovery
    uki_build "$RUN" "$RUN/keys" "$RUN/uki.efi" \
        || { echo "s15c: uki_build (recovery release) failed"; exit 1; }
    cp "$RUN/uki-pcrsig.json" "$RUN/uki.pcrsig.json"
    cp "$RUN/pcr11-enter-initrd.txt" "$RUN/pcr11.txt"
    assert_rc "recovery release UKI is SB-valid (release-cert signature)" 0 \
        sbverify --cert "$RUN/keys/db.crt" "$RUN/uki.efi"
    D11=$(cat "$RUN/pcr11.txt")
    [[ -n "$D11" ]] || { echo "s15c: no enter-initrd d11 prediction from the recovery build"; exit 1; }
    _esp_add_uki "$CANON_ESP" "$RUN/uki.efi" alpine-fde-recovery.efi \
        || { echo "s15c: esp_add_uki (recovery) FAILED"; exit 1; }
    _esp_set_default "$CANON_ESP" "$RUN/uki.efi" \
        || { echo "s15c: esp_set_default (recovery) FAILED"; exit 1; }
fi
echo "# wiping the stale enrollment (token + slot) — the §9.4 operator step"
_host_wipe_enrollment "$CANON_DISK" || { echo "s15c: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$CANON_DISK" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"
sed -i "s|\"expected_pcr7\": \".*\"|\"expected_pcr7\": \"$D7_DRIFT_BOOT\"|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline re-stamped to the drifted d7" "$D7_DRIFT_BOOT" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
swtpm_ensure "$RUN/tpm" || { echo "s15c: swtpm not serving (re-seal 1)"; exit 1; }
_step pcrsig-combined-drifted
uki_pcrsig_append_combined "$RUN/uki.pcrsig.json" "$RUN/combined-drift.json" \
    "$D7_DRIFT_BOOT" "$D11" "$RUN/keys" || exit 1
assert_eq "re-sealed combined entry pol == policy_digest(drifted d7, same d11)" \
    "$(policy_digest "$D7_DRIFT_BOOT" "$D11")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/combined-drift.json")"
uki_pcrsig_disk "$RUN/pcrsig-drift.img" "$RUN/combined-drift.json" || exit 1
RESEAL1_LOG="$RUN/enroll-drift.log"
if _enroll_finalized "$RUN/combined-drift.json" "$RESEAL1_LOG"; then
    _assert_result ok "re-seal 1: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" ""
else
    _assert_result not-ok "re-seal 1: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" \
        "output: $(tail -3 "$RESEAL1_LOG" 2>/dev/null | tr '\n' ' ')"
fi
NTOK=$(disk_token_json "$CANON_DISK" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "re-sealed: exactly ONE standing systemd-tpm2 token" "1" "$NTOK"
_stage_close "recovery-reseal-1"

# =================================================================================
# b2-rebaselined — the verified passwordless boot: zero-input token unlock
# under the re-sealed {drifted d7, d11} token. Positive leg: overlay COMMITTED.
# =================================================================================
echo "# ==== b2: verified passwordless boot under the re-baselined seal ===="
_pipeline_boot "b2-rebaselined" "$CANON_ESP" "$RUN/vars-drifted.fd" "$RUN/pcrsig-drift.img" commit
LOG=$(cat "$RUN/console-b2-rebaselined.log")
_assert_unsealed "$LOG" "b2-rebaselined"
assert_eq "[b2] sealed against the drifted (boot-layer) PCR 7" "$D7_DRIFT_BOOT" \
    "$(console_pcr b2-rebaselined 7)"
CONSOLE="$RUN/console-b2-rebaselined.log"
assert_pcr11_prediction "G-T13 [b2-rebaselined]"
CONSOLE="$CONSOLE_SAVED"
PCR11_B2=$(console_pcr b2-rebaselined 11)

# =================================================================================
# b3-tpm-clear — the motherboard-replacement drill: swtpm_reset wipes ALL TPM
# state (fresh SRK); the sealed blob cannot load under it. DELIBERATE
# persistent mutation of the canonical TPM state (the scenario's subject);
# recovery-reseal-2 restores a working enrollment before b4. Refusal leg:
# overlay DISCARDED.
# =================================================================================
echo "# ==== b3: TPM cleared (fresh SRK) -> seal refusal ===="
_stage_open "tpm-clear"
echo "# swtpm_reset: wiping ALL TPM state (fresh SRK, PCRs reset)"
swtpm_reset "$RUN/tpm"
swtpm_start "$RUN/tpm" || { echo "s15c: swtpm restart after reset failed"; exit 1; }
ZERO7=$(printf '0%.0s' {1..64})
assert_eq "fresh TPM: PCR 7 is zero" "$ZERO7" "$(swtpm_pcrread "$RUN/tpm" 7)"
_stage_close "tpm-clear"
_pipeline_boot "b3-tpm-clear" "$CANON_ESP" "$RUN/vars-drifted.fd" "$RUN/pcrsig-drift.img" discard feed3
LOG=$(cat "$RUN/console-b3-tpm-clear.log")
_assert_refused "$LOG" "b3-tpm-clear"
D7_FRESH=$(console_pcr b3-tpm-clear 7)
[[ -n "$D7_FRESH" ]] || { echo "s15c: b3 console has no PCR 7 print — nothing to re-seal over"; exit 1; }
assert_eq "[b3] PCR 7 re-measured to the same value (console evidence: the fresh TPM re-measures the same vars)" \
    "$D7_DRIFT_BOOT" "$D7_FRESH"
assert_eq "[b3] PCR 11 unchanged vs the re-baselined boot (same UKI, same phase extend)" \
    "$PCR11_B2" "$(console_pcr b3-tpm-clear 11)"

# =================================================================================
# recovery-reseal-2 (host): wipe the dead seal, re-stamp the baseline to the
# fresh TPM's d7, re-seal — fresh SRK, same d11, no volume-key re-encryption.
# =================================================================================
echo "# ==== recovery 2: wipe + re-stamp + re-seal on the fresh SRK ===="
_stage_open "recovery-reseal-2"
echo "# wiping the stale enrollment (token + slot) — the §9.4 operator step"
_host_wipe_enrollment "$CANON_DISK" || { echo "s15c: enrollment wipe (2) failed"; exit 1; }
NTOK=$(disk_token_json "$CANON_DISK" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"
sed -i "s|\"expected_pcr7\": \".*\"|\"expected_pcr7\": \"$D7_FRESH\"|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline re-stamped to the fresh TPM's d7" "$D7_FRESH" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
swtpm_ensure "$RUN/tpm" || { echo "s15c: swtpm not serving (re-seal 2)"; exit 1; }
_step pcrsig-combined-fresh
uki_pcrsig_append_combined "$RUN/uki.pcrsig.json" "$RUN/combined-fresh.json" \
    "$D7_FRESH" "$D11" "$RUN/keys" || exit 1
assert_eq "re-sealed combined entry pol == policy_digest(fresh d7, same d11)" \
    "$(policy_digest "$D7_FRESH" "$D11")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/combined-fresh.json")"
uki_pcrsig_disk "$RUN/pcrsig-fresh.img" "$RUN/combined-fresh.json" || exit 1
RESEAL2_LOG="$RUN/enroll-fresh.log"
if _enroll_finalized "$RUN/combined-fresh.json" "$RESEAL2_LOG"; then
    _assert_result ok "re-seal 2: enroll-tpm rc 0 (fresh-SRK seal stood)" ""
else
    _assert_result not-ok "re-seal 2: enroll-tpm rc 0 (fresh-SRK seal stood)" \
        "output: $(tail -3 "$RESEAL2_LOG" 2>/dev/null | tr '\n' ' ')"
fi
NTOK=$(disk_token_json "$CANON_DISK" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "re-sealed: exactly ONE standing systemd-tpm2 token" "1" "$NTOK"
_stage_close "recovery-reseal-2"

# =================================================================================
# b4-restored — passwordless unseal restored on the fresh SRK. Positive leg:
# overlay COMMITTED (the pipeline ends on a healthy, re-enrolled state).
# =================================================================================
echo "# ==== b4: passwordless unseal restored on the fresh SRK ===="
_pipeline_boot "b4-restored" "$CANON_ESP" "$RUN/vars-drifted.fd" "$RUN/pcrsig-fresh.img" commit
LOG=$(cat "$RUN/console-b4-restored.log")
_assert_unsealed "$LOG" "b4-restored"
assert_eq "[b4] passwordless: sealed against the re-measured (fresh-TPM) PCR 7" "$D7_FRESH" \
    "$(console_pcr b4-restored 7)"
CONSOLE="$RUN/console-b4-restored.log"
assert_pcr11_prediction "G-T13 [b4-restored]"
CONSOLE="$CONSOLE_SAVED"

# --- verdict --------------------------------------------------------------------
rm -rf "$RUN/guest-tree"
# Run-dir footprint discipline (registry headroom): on SUCCESS the heavy
# binary artifacts are shed — the durable evidence is the per-leg console log
# (kept) plus the results JSON the runner aggregates. On FAILURE everything
# is kept for diagnosis. kf-slot0/kf0 are SECRET material: always shed.
rm -f "$RUN/kf-slot0" "$RUN/rootfs/kf0" 2>/dev/null
if (( TESTS_FAIL == 0 )); then
    rm -rf "$RUN/disk.img" "$RUN/esp.img" "$RUN/tpm" "$RUN/keys" "$RUN/rootfs"
    rm -f "$RUN"/uki*.efi "$RUN"/pcrsig*.img "$RUN"/vars-*.fd "$RUN"/initrd.cpio \
          "$RUN"/disk-b*.qcow2 2>/dev/null
fi
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
echo "# RECOVERY-CHAIN VERDICT: mode=$MODE — ONE canonical disk advanced in place"
echo "# (R1) across $([[ "$MODE" == "full" ]] && echo 5 || echo 4) launches: the PCR 7 drift refusal stayed fail-closed"
echo "# (3-strike poweroff), the §9.4 audit drill detected + re-baselined the drift,"
echo "# both recoveries re-sealed via the production CLI (no volume-key"
echo "# re-encryption), and the TPM-clear drill ended passwordless on the fresh SRK."
if (( TESTS_FAIL == 0 )); then
    echo "# s15-recovery-chain: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s15-recovery-chain: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
