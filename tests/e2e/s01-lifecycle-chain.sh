#!/usr/bin/env bash
# tests/e2e/s01-lifecycle-chain.sh — §12 Core Lifecycle Pipeline (Wave-2 task 5b
# pilot; tests/README.md "Scenario Consolidation & Lifecycle Pipelining
# (Approach 1)", pipeline 1). ONE progressive scenario covering, in 4 logical
# boots, what s00 + s00b + s01 + s14 + s02 + s16 cover standalone:
#
#   Boot 1  install + enroll + zero-input login   (absorbs s00 + s00b + s01)
#   Boot 2  kernel update + re-seal, passwordless (absorbs s14's core)
#   Boot 3  rollback to the retained previous UKI (absorbs s02's core)
#   Boot 4  release-key rotation K1 -> K2         (absorbs s16's core)
#
# R1 (progressive state): ONE install at Boot 1; every later stage advances
# THE SAME canonical disk in place — never a reinstall, never a re-enroll from
# scratch. Concretely the canonical state lives in THIS run dir
# ($RUN/disk.img + $RUN/esp.img + $RUN/tpm + $RUN/vars-enrolled.fd) and each
# positive leg boots a QCOW2 overlay that is COMMITTED back into the canonical
# disk on success (qemu-img commit — the R1 in-place advance), so the next leg
# boots exactly the state the previous leg produced.
#
# R2 (from-cache fast path): when a valid pristine base exists, the
# install+enroll legs are SKIPPED and the pipeline starts from the cached
# ENROLLED base (boots 2-4 + boot 1's login half). Mode resolution, in order:
#     1. ALPINE_FDE_PIPELINE_FULL=1  -> full-from-install (explicit opt)
#     2. ALPINE_FDE_E2E_STATE (run-e2e.sh chain: a valid s00b run dir)
#                                     -> state-consume (install legs skipped)
#     3. tests/e2e/.cache/pristine-s00b (SHA-verified, FORMAT btrfs-3)
#                                     -> cache-reuse (install legs skipped)
#     4. otherwise                    -> full-from-install (cold path)
# The mode is on the record twice: a "# pipeline mode: <mode>" log line and
# the stage labels (`install-leg` exists ONLY in full mode; `cache-reuse`
# covers both skip modes — the log line names the source dir).
#
# R3 (overlay / LOCK_SH discipline): every boot of every leg runs on a fresh
# QCOW2 overlay over the canonical disk (tests/lib/overlay-disk.sh — LOCK_SH
# on the whole backing chain for the boot's lifetime, the task-2b idiom).
# Positive legs COMMIT the overlay into the canonical disk after a successful
# boot (R1); failed attempts and the legs that must not persist anything
# (boot 3 rollback — LUKS2 metadata identity; boot 4's rotation-recovery leg)
# DISCARD the overlay instead.
#
# Boot map (as implemented — 4 logical stages, 6 physical launches; every
# extra launch is forced by a pinned production contract, see the leg
# comments):
#   Boot 1 (full mode only: installer launch)  Stage-1 unattended install:
#           embedded-kf0 passphrase unlock (zero console input), pinned-
#           artifact rootfs populate, §9.1 btrfs @/@home/@snapshots, §3.3
#           size budget, G-T11b scans. Host: `audit --init` finalizes the
#           baseline (real CLI, G-R1-guarded efivars fixture). Host: the
#           production CLI enrolls the finalized {7,11} Mechanism B token
#           (single seal, keyslot 1, recovery slot 0 untouched). Then the
#           login launch: the SAME release UKI bytes, stage=login on the
#           payload drive (the unmeasured channel), zero-input token unlock
#           -> switch_root -> `login:` — ZERO console keystrokes.
#   Boot 2  kernel update: UKI 6.4.0 built (the §8.3 apk-trigger/kernel-hook
#           stand-in), combined {7,11} entry re-signed over (same d7, new
#           d11), `enroll-tpm` RETIRES the stale enrollment and stands the
#           fresh seal in the same run; the new UKI boots and unseals
#           PASSWORDLESSLY under the updated {7,11}. Plus the §10 row
#           "kernel update build failed": a keyless rebuild fails loudly,
#           ships nothing.
#   Boot 3  rollback: the retained previous UKI (v1) is selected (the mtools
#           default swap — the harness stand-in for bootnext), its OWN
#           release-signed combined {7,11} entry rides the payload drive;
#           the older UKI boots and unseals passwordlessly with ZERO new
#           enrollment; LUKS2 metadata is byte-identical across the boot.
#   Boot 4  rotation: K2 generated at the ADR-16 floor, dual-sign append
#           verified (both signatures), NVRAM db += K2 AND dbx += K1 in ONE
#           vars edit. The K2-built UKI boots under the rotated vars with the
#           STANDING K1-signed entry -> the I3 gate refuses it (K1-signed
#           entry vs the initrd's K2 rel.pub) -> bounded recovery loop (fed
#           slot-0) -> the recovery boot LANDS the rotated PCR 7 (the
#           digest-anchored seal must be composed over the register the
#           machine actually reproduces — s16's 2026-09-24 lesson). Host:
#           baseline re-anchored (the §9.4 accept analog), K2 combined entry,
#           `enroll-tpm` under K2 (retire + stand), token pins the K2 public
#           key. Final launch: passwordless boot + unseal under K2 on the
#           rotated register.
#
# Step timing: stage labels are LEAF-ONLY (tests/lib/stage-timing.sh refuses
# nested stages): full mode emits install-leg / finalize-baseline / enroll-leg,
# skip mode emits cache-reuse, and every boot emits boot-<leg>; host-side
# build steps are bounded by `timeout` + the overall budget instead of their
# own stage labels.
#
# Superseded scenarios (s01 s14 s02 s16) are REMOVED (2026-09-26 removal
# sweep: files AND registry rows gone) — this pipeline is their only home.
# This pipeline is a CHAIN member and
# runs in the runner's SEQUENTIAL hoist phase (s00 -> s00b -> this scenario),
# see tests/run-e2e.sh.

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
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # R3: per-boot QCOW2 overlays + base locking
# shellcheck source=../lib/stage-timing.sh
source "$TESTS/lib/stage-timing.sh"   # Step timing: # stage <label>: begin/done lines

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=16               # three retained UKIs (v1 + v2 + K2)
CACHE_DIR="$TESTS/e2e/.cache/pristine-s00b"
PIPELINE_FULL="${ALPINE_FDE_PIPELINE_FULL:-0}"
export QEMU_TIMEOUT="${ALPINE_FDE_PIPELINE_TIMEOUT:-900}"
export SWTPM_FIXTURE_VERBOSE=1    # tpm-cmd.log on disk for EVERY boot (s14 pattern)

# --- hardening: bounded legs, loud failures, overall budget (s00b pattern) -------
# The outer SCENARIO_BUDGET must exceed this; recommend
# ALPINE_FDE_SCENARIO_BUDGET=5400 for full-from-install registry runs —
# from-cache/state-consume runs finish well inside the default budget.
OVERALL_BUDGET="${ALPINE_FDE_PIPELINE_BUDGET:-5100}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {   # _hang_fail <kind> <stage> <detail> — loud, greppable, fatal
    printf '\ns01c: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's01c: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
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
# _bounded <timeout-s> <label> <cmd...> — an EXTERNAL command with its own
# bound (the run_stage watchdog of s00b, without a nested stage label; lib
# FUNCTIONS are not timeout(1)-runnable — call those plainly under
# _step/_budget_check, the overall budget bounds them).
_bounded() {
    local tmo="$1" label="$2"; shift 2
    _budget_check "bounded:$label"
    echo "# s01c: step $label (timeout ${tmo}s)"
    timeout "$tmo" "$@" || {
        printf 's01c: STEP-FAILED [%s] (rc=%s)\n' "$label" "$?"
        exit 1
    }
}
# _step <label> — a plain (lib-function) host step: budget-checked, echoed
_step() {
    _budget_check "step:$1"
    echo "# s01c: step $1"
}
_qemu_alive() {   # <run-dir> — fail LOUDLY on a qemu that died at startup
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s01c: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s01c: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}
# _boot_wedge_gate <dir> <label> — rc 0 = healthy start (serial output) or a
# normal early qemu death; rc 1 = SILENT WEDGE (0-byte console after 180 s,
# vCPU spin — the 2026-09-22 pre-BdsDxe class). Wedged boots are discarded,
# never waited out.
_boot_wedge_gate() {
    local dir="$1" label="$2" i=0
    while ((i < 180)); do
        [[ -s "$dir/console.log" ]] && return 0
        kill -0 "$(cat "$dir/qemu.pid" 2>/dev/null)" 2>/dev/null || return 0
        _budget_check "wedge-gate:$label"
        sleep 2
        i=$((i + 2))
    done
    return 1
}

RUN="$TESTS/e2e/.runs/s01-lifecycle-chain-$(date +%s)"
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

# _reanchor_tpm <dir> — before EVERY guest boot the fixture TPM must be a
# FRESH, ZEROED instance (the s00b/s16/s18/s22 hardening; defect s15-4: a
# restored volatilestate makes the next boot CUMULATIVE and the {7,11} policy
# refuses its own enrollment). Zeroed-pre-boot is ASSERTED, not assumed; the
# proxy/setup path is settled with real commands before the boot is spent.
# (Leaf-stage discipline: plain swtpm_start under timeout, no stage labels.)
_reanchor_tpm() {
    local dir="$1" d0 d7 k
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    # swtpm_start is internally bounded (10 s socket/ready loop, per-probe
    # timeouts) — called plainly: it is a sourced FUNCTION, not an executable
    _SWTPM_CLEANUP_TRAP_SET=1 swtpm_start "$dir" \
        || { echo "s01c: swtpm_start (re-anchor) failed"; exit 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    d7=$(swtpm_pcrread "$dir" 7)
    if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ ]]; then
        _assert_result ok "fixture: TPM re-anchored (PCRs 0 and 7 zero before the boot)" ""
    else
        _assert_result not-ok "fixture: TPM re-anchored (PCRs 0 and 7 zero before the boot)" \
            "pcr0=$d0 pcr7=$d7 — refusing to spend the boot on a cumulative register"
        echo "s01c: TPM not zeroed before a boot — aborting"
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

# --- ESP helpers (mtools on the file-backed image; no systemd-boot this wave) ----
_esp_add_uki() { # <esp.img> <uki.efi> <name.efi> — conventional ::/EFI/Linux/ entry
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name" || return 1
}
_esp_set_default() { # <esp.img> <uki.efi> — swap the removable-path default
    # (the harness stand-in for the boot-next/boot-order selection of §9.3:
    # the retained UKI stays in ::/EFI/Linux, the swap picks WHAT BOOTS)
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI || return 1
}
_meta_snapshot() { # <disk.img> <out.json> — canonical LUKS2 metadata dump
    disk_metadata "$1" | jq -S . >"$2"
}

# --- the boot driver (R1+R3): overlay boot, COMMIT or DISCARD ---------------------
# _pipeline_boot <label> <esp> <vars> <payload-drive> <commit|discard> [feed]
# Stage label: boot-<label> (leaf; everything inside is plain/timeout-bounded).
# Every attempt: fresh QCOW2 overlay over the CANONICAL disk (LOCK_SH on the
# backing chain via overlay_create), qemu_run, the swtpm data-loop wedge
# guard as the wait, then either COMMIT the overlay into the canonical disk
# (positive leg — R1 in-place advance) or DISCARD it (failed attempt, or a
# leg that must not persist: rollback, rotation recovery). Bounded at 2
# attempts; a wedged attempt is discarded and re-run, never waited out.
# feed="feed": the recovery-passphrase prompt is fed ONCE
# (prompt-synchronized — the hook has NO read timeout) before the wait.
_pipeline_boot() {
    local label="$1" esp="$2" vars="$3" payload="$4" mode="$5" feed="${6:-}"
    local att wrc overlay
    _stage_open "boot-$label"
    for att in 1 2; do
        _budget_check "boot:$label:att$att"
        _reanchor_tpm "$RUN/tpm"
        rm -f "$RUN/console.log"
        overlay="$RUN/disk-$label-$att.qcow2"
        overlay_create "$CANON_DISK" "$overlay" || {
            echo "s01c: overlay create failed for $label"; exit 1; }
        echo "# boot $label (attempt $att/2, overlay $mode; up to $QEMU_TIMEOUT s) ..."
        CURRENT_QEMU_DIR="$RUN"
        if ! qemu_run "$RUN" "$esp" "$overlay" "$vars" "$RUN/tpm" "$payload"; then
            echo "s01c: qemu_run FAILED for $label; qemu.stderr:"
            tail -5 "$RUN/qemu.stderr" 2>/dev/null
            overlay_discard "$overlay"
            exit 1
        fi
        _qemu_alive "$RUN"
        if [[ "$feed" == "feed" ]]; then
            if uki_wait_hook_prompt 1 300 "$RUN"; then
                feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
            else
                echo "s01c: [$label] no recovery-passphrase prompt within 300 s (qemu $(if _qemu_alive_check; then echo alive; else echo DEAD; fi))"
            fi
        fi
        wrc=0
        _wedge_wait "$RUN" "$QEMU_TIMEOUT" || wrc=$?
        if ((wrc == 43)); then
            echo "s01c: $label wedged mid-boot (swtpm data-loop stall) — discarding the attempt, retrying"
            overlay_discard "$overlay"
            (( att < 2 )) && continue
            echo "s01c: $label still wedged after recovery + retry — aborting"
            exit 1
        fi
        if ((wrc == 44 || wrc == 124)); then
            overlay_discard "$overlay"
            echo "s01c: $label wait rc=$wrc (timeout-kill / wedge-recovery failure) — aborting"
            exit 1
        fi
        if [[ "$mode" == "commit" ]]; then
            _bounded 900 "overlay-commit:$label" qemu-img commit -f qcow2 -- "$overlay"
        fi
        overlay_discard "$overlay"
        cp "$RUN/console.log" "$RUN/console-$label.log"   # THIS boot's evidence
        CURRENT_QEMU_DIR=""
        _stage_close "boot-$label"
        return 0
    done
}
_qemu_alive_check() { kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; }

# _wait_login <dir> <timeout-s> — bounded login: wait with qemu-liveness and a
# console-idle wedge discriminator (the login boot never exits on its own).
_wait_login() {
    local dir="$1" tmo="$2" i=0 sz last_sz last_chg
    last_sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
    last_chg=$SECONDS
    while ((i < tmo)); do
        if grep -qE 'login: ?$' "$dir/console.log" 2>/dev/null \
            && grep -q 'Welcome to Alpine Linux' "$dir/console.log" 2>/dev/null; then
            return 0
        fi
        kill -0 "$(cat "$dir/qemu.pid" 2>/dev/null)" 2>/dev/null || return 1
        sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
        if ((sz != last_sz)); then last_sz=$sz; last_chg=$SECONDS; fi
        ((SECONDS - last_chg > 120)) && return 42   # wedged (console idle)
        _budget_check "wait-login"
        sleep 1
        i=$((i + 1))
    done
    return 1
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

# _state_shape_ok <dir> — the s00b RUN DIR contract subset the skip modes need
# (superset of the cache: a fresh s00b run dir also carries
# pcr11-enter-initrd.txt and the tooling-era artifacts).
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
    _bounded 900 cache-restore-disk cp "$src/disk.img" "$RUN/disk.img"
    _bounded 120 cache-restore-uki cp "$src/harness.efi" "$RUN/uki-v1.efi"
    _bounded 60 cache-restore-pcrsig cp "$src/uki-pcrsig.json" "$RUN/uki-v1.pcrsig.json"
    _bounded 60 cache-restore-combined cp "$src/uki-pcrsig-combined.json" "$RUN/uki-v1-combined.json"
    [[ -d "$src/keys" ]] && cp -a "$src/keys" "$RUN/keys"
    _bounded 60 cache-restore-vars cp "$src/vars-enrolled.fd" "$RUN/vars-enrolled.fd"
    mkdir -p "$RUN/tpm"
    # LOUD, never a silent skip: a missing permall would boot every leg
    # against a VIRGIN TPM whose seed cannot unseal the standing token
    # (the s00b from-cache breakage class).
    if [[ -f "$src/tpm/tpm2-00.permall" ]]; then
        _bounded 60 cache-restore-permall cp "$src/tpm/tpm2-00.permall" "$RUN/tpm/"
    else
        echo "s01c: FATAL: no TPM state at $src/tpm/tpm2-00.permall — the sealing SRK cannot be reproduced"
        exit 1
    fi
    mkdir -p "$RUN/rootfs/etc/alpine-fde"
    _bounded 60 cache-restore-baseline cp "$src/baseline.json" "$RUN/baseline.json"
    _bounded 60 cache-restore-baseline-rootfs cp "$src/baseline.json" "$RUN/rootfs/etc/alpine-fde/baseline.json"
    _track_swtpm "$RUN/tpm"
}
_track_swtpm() { SWTPM_DIRS+=("$1"); }

# _vuki_build <stage-dir> <guest-tree> <keys-dir> <uname> <marker> <out.efi>
#             [pcr-priv pcr-pub sign-key sign-cert relpub]
# Variant UKI builder (the s02/s16 pattern): genuinely different measured
# content (init marker line + .osrel VERSION_ID + --uname -> different PCR 11
# section chain), the SHIPPED §8.2 hook staged at the pinned features.d
# destination, enter-initrd d11 prediction beside <out>, .pcrsig extracted.
_vuki_build() {
    local st="$1" tree="$2" kd="$3" un="$4" mk="$5" out="$6"
    local ppriv="${7:-$kd/db.key}" ppub="${8:-$kd/release.pub}"
    local skey="${9:-$kd/db.key}" scert="${10:-$kd/db.crt}" relpub="${11:-$kd/release.pub}"
    mkdir -p "$st"
    local item
    for item in usr modules opt; do
        cp -al "$tree/$item" "$st/$item" || return 1
    done
    ln -sfn usr/bin "$st/bin"
    ln -sfn usr/sbin "$st/sbin"
    _uki_link_busybox "$tree"   # the hook's busybox PATH surface (idempotent)
    uki_initrd_write_init "$st"
    printf '# alpine-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$relpub" "$st/rel.pub"
    local hook_dst="$st/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    mkdir -p "${hook_dst%/*}"
    cp "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" "$hook_dst" || return 1
    chmod 755 "$hook_dst"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=alpine-fde-harness\nVERSION_ID=%s\nNAME=Alpine FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    # the enter-initrd PCR 11 prediction for THIS exact build (ukify --measure;
    # the §8.2 hook's single phase extend re-derives exactly this value)
    if ! ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
            --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
            --uname="$un" \
            --measure --phases enter-initrd --pcr-banks=sha256 \
            --pcr-private-key="$ppriv" >"$st.measure.txt" 2>&1; then
        echo "s01c: ukify --measure (variant $un) failed:" >&2
        cat "$st.measure.txt" >&2
        return 1
    fi
    sed -n 's/^11:sha256=\([0-9a-f]\{64\}\)$/\1/p' "$st.measure.txt" | head -1 >"$out.pcr11.txt"
    [[ -s "$out.pcr11.txt" ]] || { echo "s01c: no enter-initrd d11 prediction (variant $un)" >&2; return 1; }
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --pcr-banks=sha256 --pcr-private-key="$ppriv" --pcr-public-key="$ppub" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s01c: ukify (variant $un) failed" >&2
        return 1
    }
    objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
    sbsign --key "$skey" --cert "$scert" --output "$out" "$st.pcrsigned.efi" >/dev/null
}
# _vuki_build_try <args...> — the bounded bridge for variant builds (the
# bridge carries _vuki_build's OWN lib closure + the globals it reads; the
# paths arrive pre-expanded in "$@"). Returns the build's rc (the keyless
# negative EXPECTS a nonzero rc — the caller asserts it).
_vuki_build_try() {
    _budget_check "vuki-build:$1"
    echo "# s01c: step vuki-build:$1 (timeout 1800s)"
    timeout 1800 bash -c \
        "$(declare -f _vuki_build _uki_link_busybox uki_initrd_write_init uki_initrd_pack); \
         $(declare -p UKI_MODULES ALPINE_FDE_SLOT0_PASSPHRASE ALPINE_FDE_DEBUG_SHELL REPO 2>/dev/null); \
         _vuki_build $*"
}
# _vuki_build_checked <args...> — _vuki_build_try, fatal on failure
_vuki_build_checked() {
    local rc=0
    _vuki_build_try "$@" || rc=$?
    if (( rc != 0 )); then
        printf 's01c: STEP-FAILED [vuki-build] (rc=%s)\n' "$rc"
        exit 1
    fi
}

# _assert_token <img> <label> [pubfile] — the standing-enrollment shape asserts
_assert_token() {
    local img="$1" label="$2" pub="${3:-}" ntok tokpcrs
    ntok=$(disk_token_json "$img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
    assert_eq "[$label] exactly ONE standing systemd-tpm2 token (no dead-slot accumulation)" "1" "$ntok"
    tokpcrs=$(disk_token_json "$img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
    assert_eq "[$label] standing token pins the finalized {PCR 7, PCR 11}" "[7,11]" "$tokpcrs"
    if [[ -n "$pub" ]]; then
        # the token's tpm2-pubkey is the b64 DER SubjectPublicKeyInfo of the
        # release key (lib/token.sh schema pin) — compare DER-to-DER (s16)
        assert_eq "[$label] token pins the rotated release public key" \
            "$(disk_token_json "$img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pubkey"]' | base64 -d | sha256sum | awk '{print $1}')" \
            "$(openssl pkey -pubin -in "$pub" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
    fi
}

# _assert_unsealed <log> <label> [no-poweroff] — the zero-input hook-unlock
# core (every passwordless leg re-expresses it for the progressive state).
# "no-poweroff": the login leg is qemu-killed after `login:` (the installed
# system never powers off) — the clean-poweroff assert is skipped there.
_assert_unsealed() {
    local log="$1" label="$2" no_poweroff="${3:-}"
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
    assert_contains "[$label] token unlocked via the TPM (zero-input §8.2 path)" "$log" \
        "$(sentinel_of unseal_unlocked)"
    assert_contains "[$label] volume UNSEALED" "$log" "$(sentinel_of harness_unsealed)"
    if [[ "$no_poweroff" != "no-poweroff" ]]; then
        assert_contains "[$label] clean poweroff" "$log" "$(sentinel_of harness_poweroff)"
    fi
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    assert_not_contains "[$label] no new enrollment in-guest (Mechanism B seal)" "$log" \
        "$(sentinel_of cli_seal_slot)"
    assert_not_contains "[$label] no cryptenroll anywhere" "$log" \
        "$(sentinel_of cryptenroll_enrolled)"
}

# _assert_polluted <log> <label> [nfeeds] — the fed recovery-path core (the
# s01/s14/s16 recovery-mode invariants, re-expressed for the progressive state)
_assert_polluted() {
    local log="$1" label="$2" nfeeds="${3:-1}" nprompts
    assert_contains "[$label] init ran" "$log" "$(sentinel_of harness_init_started)"
    assert_contains "[$label] hook ran the enter-initrd extend" "$log" \
        "$(sentinel_of unseal_pcrextend_ok)"
    assert_contains "[$label] volume UNSEALED (recovery path)" "$log" \
        "$(sentinel_of harness_unsealed)"
    assert_contains "[$label] fed slot-0 passphrase unsealed via the recovery path" "$log" \
        "$(sentinel_of unseal_pass_unlocked)"
    assert_contains "[$label] clean poweroff" "$log" "$(sentinel_of harness_poweroff)"
    assert_not_contains "[$label] never unlocked via the TPM token" "$log" \
        "$(sentinel_of unseal_unlocked)"
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    nprompts=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$log" || true)
    assert_eq "[$label] exactly $nfeeds recovery-passphrase prompt(s) (bounded loop, fed on attempt 1)" \
        "$nfeeds" "$nprompts"
}

# _enroll_cli <label> <pcrsig.json> <keydir> <logfile> — the production CLI
# enroll-tpm host-side (uki_host_enroll_finalized's environment, explicit for
# the pipeline's canonical disk); rc asserted by the caller.
_enroll_cli() {
    local label="$1" pcrsig="$2" keydir="$3" logfile="$4"
    ALPINE_FDE_ROOT="$RUN/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
        ALPINE_FDE_KEYDIR="$keydir" \
        ALPINE_FDE_LUKS_KEYFILE="$RUN/kf-slot0" \
        ALPINE_FDE_NO_INSTALL=1 \
        timeout 600 "$REPO/bin/alpine-fde" enroll-tpm --uuid "$CANON_DISK" --pcrsig "$pcrsig" \
        >"$logfile" 2>&1
}

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
    echo "# pipeline mode: state-consume from $STATE (run-e2e chain; install legs skipped)"
elif _cache_verify "$CACHE_DIR"; then
    MODE="skip"
    BASE_SRC="$CACHE_DIR"
    echo "# pipeline mode: cache-reuse from $CACHE_DIR (SHA-verified pristine base; install legs skipped)"
else
    MODE="full"
    echo "# pipeline mode: full-from-install (cold: no state chain, no valid pristine cache)"
fi

# =================================================================================
# Boot 1 — install + enroll + auto-finalize (full mode) / base restore (skip mode)
# =================================================================================
if [[ "$MODE" == "full" ]]; then
    # ---- Stage-1 unattended install (the s00 chain, compact) ---------------------
    _stage_open "install-leg"
    _SWTPM_CLEANUP_TRAP_SET=1 _step swtpm_start-boot1; swtpm_start "$RUN/tpm" \
        || { echo "s01c: swtpm_start (boot1) failed"; exit 1; }
    _track_swtpm "$RUN/tpm"
    _step keys_create; keys_create "$RUN/keys" || exit 1
    # ADR-16 floor BEFORE the varstore embeds db (the s00b/s14 pattern): the
    # production CLI refuses to enroll below RSA-3072, and a reissue AFTER the
    # varstore exists would shift PCR 7 away from the booted register.
    _step release-key-floor; uki_release_key_floor "$RUN/keys" || exit 1
    _step keys_vars_enrolled; keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
    assert_contains "enrolled vars: SecureBootEnable ON" \
        "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
    # pristine varstore: each attempt restores an IDENTICAL copy before qemu_run
    # (a -9-killed attempt mutates the pflash vars — Boot#### renumbering class)
    cp "$RUN/vars-enrolled.fd" "$RUN/vars-pristine.fd"
    # the rootfs payload derivation may fetch the pinned artifact (the
    # overnight-hang window) — hard-bounded; the derived payload is cached.
    _bounded 1800 rootfs-payload bash -c \
        "$(declare -f rootfs_payload_image alpine_artifact_ensure \
              alpine_artifact_extract alpine_artifact_path alpine_artifact_cache_dir \
              _uki_payload_stub); \
         $(declare -p ALPINE_ARTIFACT_CACHE_DIR ALPINE_MINI_ROOTFS_VERSION \
              ALPINE_MINI_ROOTFS_ARCH ALPINE_MINI_ROOTFS_URL \
              ALPINE_MINI_ROOTFS_SHA256 ALPINE_MINI_ROOTFS_BYTES _HERE 2>/dev/null); \
         rootfs_payload_image '$RUN/rootfs-payload.img' >'$RUN/payload.out'"
    read -r ROOTFS_SHA ROOTFS_BYTES <"$RUN/payload.out"
    [[ -n "$ROOTFS_SHA" ]] || { echo "s01c: rootfs payload build failed"; exit 1; }
    echo "# artifact pin: $ROOTFS_SHA ($ROOTFS_BYTES bytes)"
    assert_file_exists "S-00: rootfs payload drive built" "$RUN/rootfs-payload.img"
    _step uki_build-installer
    ALPINE_FDE_ROOTFS_SHA="$ROOTFS_SHA" ALPINE_FDE_ROOTFS_BYTES="$ROOTFS_BYTES" \
        uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "alpine-fde-stage=install" \
        || { echo "s01c: uki_build (installer) failed"; exit 1; }
    assert_file_exists "S-00: installer UKI built" "$RUN/harness.efi"
    assert_rc "S-00: installer UKI is SB-valid (release-cert signature)" 0 \
        sbverify --cert "$RUN/keys/db.crt" "$RUN/harness.efi"
    # the passphrase (kf0) is EMBEDDED in the initramfs — verify, do not trust
    if cpio -it --quiet <"$RUN/initrd.cpio" 2>/dev/null | grep -qx "kf0"; then
        _assert_result ok "installer initrd embeds the LUKS passphrase (kf0)" ""
    else
        _assert_result not-ok "installer initrd embeds the LUKS passphrase (kf0)" "kf0 not in cpio listing"
    fi
    UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
    _step esp_make-installer
    esp_make "$CANON_ESP" \
        $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi" || exit 1
    ESP_ACTUAL_MIB=$(( ($(stat -c%s "$CANON_ESP") + 1048575) / 1048576 ))
    assert_eq "§13 ESP-size assertion: actual ESP == UKI × retention + headroom" \
        "$(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB ))" "$ESP_ACTUAL_MIB"
    _step disk_make_luks; disk_make_luks "$CANON_DISK" 1600 || exit 1

    # the installer boot (bounded attempts; wedged attempts are discarded; the
    # SUCCESSFUL overlay is COMMITTED — the populated rootfs is the R1 state)
    for _a_attempt in 1 2 3; do
        _budget_check "boot1-install-attempt:$_a_attempt"
        cp "$RUN/vars-pristine.fd" "$RUN/vars-enrolled.fd"
        rm -f "$RUN/console.log"
        _a_overlay="$RUN/disk-b1-install-$_a_attempt.qcow2"
        overlay_create "$CANON_DISK" "$_a_overlay" || { echo "s01c: overlay create failed"; exit 1; }
        echo "# boot 1 (install): Stage-1 unattended install — passphrase unlock, rootfs populate (zero console input)"
        CURRENT_QEMU_DIR="$RUN"
        qemu_run "$RUN" "$CANON_ESP" "$_a_overlay" "$RUN/vars-enrolled.fd" "$RUN/tpm" \
            "$RUN/rootfs-payload.img" || {
            echo "s01c: qemu_run FAILED (install); qemu.stderr:"
            tail -5 "$RUN/qemu.stderr" 2>/dev/null
            overlay_discard "$_a_overlay"; exit 1; }
        _qemu_alive "$RUN"
        if _boot_wedge_gate "$RUN" "b1-install:$_a_attempt"; then
            qemu_wait "$RUN" "$QEMU_TIMEOUT"
            CURRENT_QEMU_DIR=""
            if grep -q "alpine-fde: POWEROFF" "$RUN/console.log" 2>/dev/null; then
                _bounded 900 overlay-commit-b1-install qemu-img commit -f qcow2 -- "$_a_overlay"
                overlay_discard "$_a_overlay"
                break
            fi
            echo "s01c: install boot attempt $_a_attempt failed (no POWEROFF)"
            overlay_discard "$_a_overlay"
        else
            echo "s01c: install boot attempt $_a_attempt WEDGED (silent pre-BdsDxe)"
            qemu_kill "$RUN"
            CURRENT_QEMU_DIR=""
            overlay_discard "$_a_overlay"
        fi
        ((_a_attempt < 3)) || { echo "s01c: install boot failed after 3 attempts"; exit 1; }
    done
    cp "$RUN/console.log" "$RUN/console-b1-install.log"
    LOG=$(cat "$RUN/console-b1-install.log")
    assert_contains "[install] init ran" "$LOG" "alpine-fde-harness: init started"
    assert_contains "[install] TPM char device appeared" "$LOG" "/dev/tpmrm0 present"
    for pcr in 0 7 11; do
        if grep -qE "alpine-fde-pcr sha256:$pcr=[0-9a-f]{64}" "$RUN/console-b1-install.log" 2>/dev/null; then
            _assert_result ok "[install] PCR $pcr printed (sha256 hex)" ""
        else
            _assert_result not-ok "[install] PCR $pcr printed (sha256 hex)" "no alpine-fde-pcr line"
        fi
    done
    PCR7=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-b1-install.log" | head -1 | cut -d= -f2)
    ZERO7=$(printf '0%.0s' {1..64})
    if [[ -n "$PCR7" && "$PCR7" != "$ZERO7" ]]; then
        _assert_result ok "[install] PCR 7 non-zero (enrolled SB state measured)" ""
    else
        _assert_result not-ok "[install] PCR 7 non-zero (enrolled SB state measured)" "PCR7=${PCR7:-absent}"
    fi
    assert_contains "[install] passphrase unlock (one-time, documented; zero console input)" "$LOG" \
        "alpine-fde-install: root volume unlocked via passphrase"
    assert_not_contains "[install] no fallback prompt on the install path" "$LOG" "awaiting console line"
    assert_contains "[install] rootfs payload hash-verified in-guest" "$LOG" \
        "alpine-fde-install: rootfs payload verified"
    assert_contains "[install] rootfs populated (§3.3)" "$LOG" \
        "alpine-fde-install: populating rootfs from the pinned Alpine artifact"
    assert_contains "[install] getty/openrc configured (§3.3)" "$LOG" \
        "alpine-fde-install: getty/openrc configured"
    assert_contains "[install] §9.1 btrfs rootfs created on the LUKS volume" "$LOG" \
        "alpine-fde-install: btrfs rootfs created (uuid="
    assert_contains "[install] §9.1 subvolumes created (@ @home @snapshots)" "$LOG" \
        "alpine-fde-install: subvolumes created (@ @home @snapshots)"
    assert_contains "[install] root mounted rw with subvol=@" "$LOG" \
        "alpine-fde-install: root mounted (btrfs subvol=@)"
    for sv in '@' '@home' '@snapshots'; do
        if grep -qE "path ${sv}[[:space:]]" "$RUN/console-b1-install.log" 2>/dev/null; then
            _assert_result ok "[install] btrfs subvolume ${sv} present on disk (subvolume list)" ""
        else
            _assert_result not-ok "[install] btrfs subvolume ${sv} present on disk" "no 'path ${sv}' line"
        fi
    done
    assert_not_contains "[install] install stage never failed" "$LOG" "alpine-fde: INSTALL-FAILED"
    assert_not_contains "[install] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
    assert_contains "[install] clean poweroff sentinel" "$LOG" "alpine-fde: POWEROFF"
    # G-T13 prediction for the installer UKI
    CONSOLE="$RUN/console-b1-install.log"
    assert_pcr11_prediction "G-T13 [install]"
    CONSOLE="$CONSOLE_SAVED"
    _stage_close "install-leg"

    # ---- audit --init finalizes the baseline (real CLI, BEFORE any UKI chain) ----
    _stage_open "finalize-baseline"
    EFIVARS="$RUN/rootfs/efivars-sb-on"
    mkdir -p "$EFIVARS" "$RUN/rootfs/etc/alpine-fde"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    _mkcertvar PK pk-cert-v1
    _mkcertvar KEK kek-cert-v1
    _mkcertvar db db-cert-v1
    _mkcertvar dbx dbx-cert-v1
    cat >"$RUN/rootfs/etc/alpine-fde/baseline.json" <<'JSON'
{
  "schema_version": "1",
  "created_at": "PENDING-BY-SCENARIO",
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
    "release_pub_path": "",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "",
    "esp_partuuid": ""
  }
}
JSON
    # the fixture swtpm restarts after the boot; the OPERATOR-meaningful PCR
    # values are stamped from the boot console afterwards (s00/s16 precedent)
    swtpm_ensure "$RUN/tpm" || { echo "s01c: swtpm restart (audit) failed"; exit 1; }
    if AUDIT_OUT=$(ALPINE_FDE_ROOT="$RUN/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
        ALPINE_FDE_EVENTLOG="$RUN/rootfs/eventlog-absent" \
        ALPINE_FDE_NO_INSTALL=1 \
        timeout 300 "$REPO/bin/alpine-fde" audit --init 2>&1); then
        _assert_result ok "audit --init finalizes the baseline (real CLI, rc 0)" ""
    else
        _assert_result not-ok "audit --init finalizes the baseline (real CLI, rc 0)" \
            "output: $(tail -2 <<<"$AUDIT_OUT")"
    fi
    assert_contains "finalized baseline records secure_boot=1" \
        "$(cat "$RUN/rootfs/etc/alpine-fde/baseline.json")" '"secure_boot": "1"'
    sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'alpine-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/console-b1-install.log" | head -1 | cut -d= -f2)\",|" \
        "$RUN/rootfs/etc/alpine-fde/baseline.json"
    assert_eq "baseline expected_pcr7 == the booted machine's PCR 7" "$PCR7" \
        "$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
    if grep -q '"expected_pcr7": "pending"' "$RUN/rootfs/etc/alpine-fde/baseline.json"; then
        _assert_result not-ok "baseline is FINAL (no pending PCR 7)" "still pending"
    else
        _assert_result ok "baseline is FINAL (no pending PCR 7)" ""
    fi
    cp "$RUN/rootfs/etc/alpine-fde/baseline.json" "$RUN/baseline.json"
    _stage_close "finalize-baseline"

    # ---- the enroll leg: production CLI, single finalized {7,11} Mechanism B -----
    _stage_open "enroll-leg"
    # the RELEASE UKI (the ENROLLED one — the s00b boot-B product analog, built
    # without the stage=install word; uki_guest_tree reuses the cached tree)
    _step uki_build-v1
    uki_build "$RUN" "$RUN/keys" "$RUN/uki-v1.efi" \
        || { echo "s01c: uki_build (v1 release) failed"; exit 1; }
    cp "$RUN/uki-pcrsig.json" "$RUN/uki-v1.pcrsig.json"
    cp "$RUN/pcr11-enter-initrd.txt" "$RUN/uki-v1.pcr11.txt"
    assert_rc "release UKI (v1) is SB-valid (release-cert signature)" 0 \
        sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-v1.efi"
    D7="$PCR7"
    D11_V1=$(cat "$RUN/uki-v1.pcr11.txt")
    [[ -n "$D11_V1" ]] || { echo "s01c: no enter-initrd d11 prediction from the v1 build"; exit 1; }
    _step pcrsig-combined-v1
    uki_pcrsig_append_combined "$RUN/uki-v1.pcrsig.json" "$RUN/uki-v1-combined.json" \
            "$D7" "$D11_V1" "$RUN/keys" || exit 1
    assert_eq "combined .pcrsig entry pol == policy_digest(finalized d7, enter-initrd d11) (G-B6 shape)" \
        "$(policy_digest "$D7" "$D11_V1")" \
        "$(jq -r '.sha256[-1].pol' "$RUN/uki-v1-combined.json")"
    assert_contains "combined .pcrsig entry pins {PCR 7, PCR 11}" \
        "$(jq -c '.sha256[-1].pcrs' "$RUN/uki-v1-combined.json")" "[7,11]"
    UKI_MIB=$(( ($(stat -c%s "$RUN/uki-v1.efi") + 1048575) / 1048576 ))
    # the pipeline ESP carries the removable-path default + FOUR retained UKIs
    # (v1 enrolled, v2 update, v0 rollback target, k2 rotated) — retention + 2
    ESP_MIB=$(( UKI_MIB * (ROOTFS_RETENTION + 2) + 2 * ESP_HEADROOM_MIB ))
    _step esp_make-v1
    esp_make "$CANON_ESP" "$ESP_MIB" "$RUN/uki-v1.efi" || exit 1
    _esp_add_uki "$CANON_ESP" "$RUN/uki-v1.efi" alpine-fde-v1.efi || exit 1   # RETAINED for boot 3
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN/kf-slot0"
    swtpm_ensure "$RUN/tpm" || { echo "s01c: swtpm restart (enroll) failed"; exit 1; }
    ENROLL_LOG="$RUN/enroll-v1.log"
    if _enroll_cli "enroll-v1" "$RUN/uki-v1-combined.json" "$RUN/keys" "$ENROLL_LOG"; then
        _assert_result ok "enroll: the production CLI sealed the finalized {7,11} token (rc 0)" ""
    else
        _assert_result not-ok "enroll: the production CLI sealed the finalized {7,11} token (rc 0)" \
            "output: $(tail -3 "$ENROLL_LOG" 2>/dev/null | tr '\n' ' ')"
    fi
    assert_contains "enroll: the CLI's Mechanism B seal marker" \
        "$(cat "$ENROLL_LOG")" "$(sentinel_of cli_seal_slot)"
    assert_not_contains "enroll: NO cryptenroll anywhere (Mechanism B never invokes it)" \
        "$(cat "$ENROLL_LOG")" "$(sentinel_of cryptenroll_enrolled)"
    _assert_token "$CANON_DISK" "enroll"
    TOKSLOT=$(disk_token_json "$CANON_DISK" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
    assert_eq "enroll: token on a fresh keyslot (recovery slot 0 untouched)" "1" "$TOKSLOT"
    _stage_close "enroll-leg"
else
    # ---- skip mode: cache-reuse / state-consume (R2) -----------------------------
    _stage_open "cache-reuse"
    _restore_base "$BASE_SRC"
    # v1 identity from the cached ENROLLED artifacts: the release UKI IS v1;
    # its enter-initrd d11 is the d11 the standing seal was composed over
    # (recorded in the combined entry's digest-anchor fields)
    D7=$(jq -r '.expected_pcr7 // empty' "$RUN/baseline.json")
    [[ "$D7" =~ ^[0-9a-f]{64}$ ]] || { echo "s01c: baseline expected_pcr7 not finalized ($D7)"; exit 1; }
    D11_V1=$(jq -r '.sha256[-1].d11 // empty' "$RUN/uki-v1-combined.json")
    [[ "$D11_V1" =~ ^[0-9a-f]{64}$ ]] || { echo "s01c: combined entry carries no d11 anchor"; exit 1; }
    assert_file_exists "cache-reuse: cached enrolled release UKI present" "$RUN/uki-v1.efi"
    # §13: the run-dir ESP is a deterministic function of the cached release UKI
    UKI_MIB=$(( ($(stat -c%s "$RUN/uki-v1.efi") + 1048575) / 1048576 ))
    # the pipeline ESP carries the removable-path default + FOUR retained UKIs
    # (v1 enrolled, v2 update, v0 rollback target, k2 rotated) — retention + 2
    ESP_MIB=$(( UKI_MIB * (ROOTFS_RETENTION + 2) + 2 * ESP_HEADROOM_MIB ))
    _step esp_make-cached
    esp_make "$CANON_ESP" "$ESP_MIB" "$RUN/uki-v1.efi" || exit 1
    assert_eq "§13 ESP-size assertion [cache-reuse]: actual ESP == UKI × (retention + 2) + headroom" \
        "$ESP_MIB" \
        "$(( ($(stat -c%s "$CANON_ESP") + 1048575) / 1048576 ))"
    _esp_add_uki "$CANON_ESP" "$RUN/uki-v1.efi" alpine-fde-v1.efi || exit 1   # RETAINED for boot 3
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
    echo "# cache-reuse: standing enrollment verified (1 systemd-tpm2 token, keyslot 1, pcrs 7,11) — install legs skipped"
    _stage_close "cache-reuse"
fi

# --- in-guest LIVE-OPS suite (user directive: status / audit / doctor /
# rotate / pre-upgrade executed DURING a live boot, riding boot 1's login
# session — ZERO additional boots) --------------------------------------------
#
# The installed Alpine root ships the tooling tree + the glibc-closure stubs
# (tpm2/jq/flock) but NOT cryptsetup or btrfs userspace (the §3.3 additions
# set arrives via apk in the production flow; the initrd's pinned Debian
# binaries cannot execute on the musl root un-wrapped). The session therefore
# ships BOTH tools as payload-tail stubs — the PROVEN _uki_payload_stub
# pattern (own loader + library closure + wrapper), built from the guest
# tree's OWN Debian binaries and libraries (the exact closure the initrd
# runs) — plus the finalized baseline.json, all in one tarball appended AFTER
# the login marker on the payload drive (offset 128 KiB; the pcrsig region
# and the marker stay untouched).
#
# Console discipline (the s20 lossy-serial lesson): every long output lands
# in a FILE in-guest and is corroborated IN-GUEST (grep over the unwrapped
# file); only short, computed markers (LIV*-RC=0 / LIV*-OK) travel back over
# the serial console. Host-side assertions then pin those markers.

_closure_stage() { # <tree> <bin-path-in-tree> <optdir> <wrapper-abs-path>
    local tree="$1" bin="$2" optdir="$3" wrapper="$4"
    local src="$tree$bin"
    [[ -f "$src" ]] || { echo "s01c: liveops closure: $src missing in the guest tree"; exit 1; }
    mkdir -p "$RUN/liveops/$optdir/bin" "$RUN/liveops/$optdir/lib"         "$RUN/liveops$(dirname "$wrapper")"
    cp -L "$src" "$RUN/liveops/$optdir/bin/$(basename "$bin")"
    local -a queue=("$src")
    local -A seen=()
    local cur needed cand ld
    while ((${#queue[@]} > 0)); do
        cur=${queue[0]}
        queue=("${queue[@]:1}")
        [[ -z "${seen[$cur]:-}" ]] || continue
        seen[$cur]=1
        while IFS= read -r needed; do
            [[ -n "$needed" ]] || continue
            cand=""
            for _ld in "$tree/usr/lib/x86_64-linux-gnu/$needed"                 "$tree/lib/x86_64-linux-gnu/$needed"                 "$tree/usr/lib/$needed" "$tree/lib/$needed"; do
                [[ -f "$_ld" ]] && { cand="$_ld"; break; }
            done
            [[ -n "$cand" ]] || {
                echo "s01c: liveops closure: NEEDED $needed (of $(basename "$cur")) is not in the guest tree"
                exit 1
            }
            cp -L "$cand" "$RUN/liveops/$optdir/lib/"
            queue+=("$cand")
        done < <(objdump -p "$cur" 2>/dev/null | awk '/NEEDED/ {print $2}')
    done
    ld=$(find "$tree" -name 'ld-linux-x86-64.so.2' 2>/dev/null | head -1)
    [[ -n "$ld" ]] || { echo "s01c: liveops closure: no ld-linux in the guest tree"; exit 1; }
    cp -L "$ld" "$RUN/liveops/$optdir/lib/ld-linux-x86-64.so.2"
    printf '#!/bin/sh
exec %s/lib/ld-linux-x86-64.so.2 --library-path %s/lib %s/bin/%s "$@"
' \
        "$optdir" "$optdir" "$optdir" "$(basename "$bin")" >"$RUN/liveops$wrapper"
    chmod 755 "$RUN/liveops$wrapper"
}

# _liveops_build <login-payload-drive> — stage the tail tarball + assert its
# contents BEFORE the boot is spent (fail-closed staging, never a silent
# no-op session).
_liveops_build() {
    local drive="$1"
    _step liveops-closures
    uki_guest_tree "$RUN/guest-tree" || { echo "s01c: uki_guest_tree (liveops) failed"; exit 1; }
    rm -rf "$RUN/liveops"
    mkdir -p "$RUN/liveops/etc/alpine-fde"
    # The in-guest audit copy is the OPERATOR's re-baseline target:
    #   * expected_pcr7 keeps the ENROLLED d7 (the live register re-proves it
    #     every faithful boot — the match IS the assertion);
    #   * pcr0-3 are left "pending": the state baseline's recorded values come
    #     from a DIFFERENT boot of the bimodal-PCR-0 register class, so
    #     comparing them live would report fixture noise as drift (audit's
    #     DRIFT-detecting behavior is pinned host-side and by s15c);
    #   * the SB fingerprints are blanked: the canonical values were captured
    #     from the G-R1 efivars FIXTURE files (raw cert blobs), whose encoding
    #     differs from the guest's real efivarfs NVRAM bytes (signature lists)
    #     — a harness encoding artifact, not product drift;
    #   * target.luks_uuid is injected so the LUKS2 token section resolves.
    _liv_uuid=$(cryptsetup luksUUID "$CANON_DISK" 2>/dev/null)
    [[ -n "$_liv_uuid" ]] || { echo "s01c: no LUKS UUID for the liveops baseline"; exit 1; }
    jq --arg u "$_liv_uuid" \
        '.pcr0 = "pending" | .pcr1 = "pending" | .pcr2 = "pending" | .pcr3 = "pending" |
         .sb_state = {secure_boot: "", setup_mode: "", pk_fp: "", kek_fp: "", db_fp: "", dbx_fp: ""} |
         .target = {luks_uuid: $u, esp_partuuid: ""}' \
        "$RUN/baseline.json" >"$RUN/liveops/etc/alpine-fde/baseline.json"
    unset _liv_uuid
    _closure_stage "$RUN/guest-tree" /usr/sbin/cryptsetup /opt/csbin /usr/local/bin/cryptsetup
    _closure_stage "$RUN/guest-tree" /usr/bin/btrfs /opt/btrfsbin /usr/local/bin/btrfs
    # the payload's tpm2 stub loads its TCTI by DLOPEN (never a NEEDED entry),
    # so the closure omits it — ship the DEVICE module under the exact name
    # dlopen() looks up (live-diagnosed: audit/status died 64 "no TPM
    # reachable" in-guest before this)
    mkdir -p "$RUN/liveops/opt/tpm/bin/lib"
    cp -L "$RUN/guest-tree/usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0" \
        "$RUN/liveops/opt/tpm/bin/lib/libtss2-tcti-device.so" \
        || { echo "s01c: cannot stage the device TCTI module"; exit 1; }
    _bounded 60 liveops-tar tar -C "$RUN/liveops" -czf "$RUN/liveops.tgz" etc opt usr
    local listing
    listing=$(tar -tzf "$RUN/liveops.tgz")
    for _member in etc/alpine-fde/baseline.json opt/csbin/bin/cryptsetup \
        opt/btrfsbin/bin/btrfs usr/local/bin/cryptsetup usr/local/bin/btrfs \
        opt/csbin/lib/ld-linux-x86-64.so.2 opt/btrfsbin/lib/ld-linux-x86-64.so.2 \
        opt/tpm/bin/lib/libtss2-tcti-device.so; do
        if grep -qx "$_member" <<<"$listing"; then
            _assert_result ok "liveops payload ships $_member" ""
        else
            _assert_result not-ok "liveops payload ships $_member" "missing from liveops.tgz"
        fi
    done
    unset _member
    # append AFTER the login marker (offset 128 KiB): the pcrsig region (the
    # first 64 KiB) and the stage marker (64 KiB) are untouched
    _bounded 60 liveops-append \
        dd if="$RUN/liveops.tgz" of="$drive" bs=65536 seek=2 conv=notrunc status=none
}

# _liveops_inject_login — ONE host-side mutation of the canonical disk's
# rootfs BEFORE the login boot: unlock root on the serial getty (the pinned
# Alpine artifact ships root with the `*` LOCKED shadow field — busybox login
# denies every attempt, live-evidenced: the first liveops run died 125 at
# `login:`). Empty field = busybox login authenticates WITHOUT a password
# prompt. Requires sudo -n + loop devices (this harness's sandbox contract);
# anything missing is a loud env-class failure, never a silent skip.
_liveops_inject_login() {
    local loop mp=/mnt/alpine-fde-liveops
    sudo -n true 2>/dev/null || { echo "s01c: liveops login injection needs sudo -n (sandbox contract)"; exit 1; }
    _step liveops-inject-login
    loop=$(sudo -n losetup --find --show -- "$CANON_DISK") \
        || { echo "s01c: losetup --find --show failed for the canonical disk"; exit 1; }
    # $RUN/kf-slot0 is the verbatim (newline-free) slot-0 keyfile both modes
    # write before this point
    if ! sudo -n cryptsetup open --type luks --key-file "$RUN/kf-slot0" \
            --key-slot 0 "$loop" alpine-fde-liveops; then
        echo "s01c: cannot open the canonical disk for the login injection"
        sudo -n losetup -d "$loop" 2>/dev/null
        exit 1
    fi
    sudo -n mkdir -p "$mp"
    if ! sudo -n mount -t btrfs -o subvol=@ /dev/mapper/alpine-fde-liveops "$mp"; then
        echo "s01c: cannot mount the @ rootfs for the login injection"
        sudo -n cryptsetup close alpine-fde-liveops 2>/dev/null
        sudo -n losetup -d "$loop" 2>/dev/null
        exit 1
    fi
    sudo -n sed -i 's/^root:\*:/root::/' "$mp/etc/shadow"
    if sudo -n grep -q '^root::' "$mp/etc/shadow"; then
        _assert_result ok "liveops: root getty unlocked in the installed rootfs (shadow field emptied)" ""
    else
        _assert_result not-ok "liveops: root getty unlocked in the installed rootfs" \
            "shadow root entry not emptied"
    fi
    sudo -n umount "$mp"
    sudo -n cryptsetup close alpine-fde-liveops
    sudo -n losetup -d "$loop"
}

# _liv_feed <dir> <line> <marker-ERE> — feed ONE session line and wait for its
# computed marker with qemu liveness + the overall budget (a lost marker is a
# LOUD hang, never a timeout-kill guess).
_liv_feed() {
    local dir="$1" line="$2" marker="$3" i=0
    feed_line "$dir/serial.sock" "$line"
    while ((i < 600)); do
        grep -qE -- "$marker" "$dir/console.log" 2>/dev/null && return 0
        if ! _qemu_alive_check; then
            # qemu died: the marker may have landed in the same moment as the
            # exit (the session's own poweroff) — one final look before dying
            grep -qE -- "$marker" "$dir/console.log" 2>/dev/null && return 0
            _hang_fail CONSOLE-WAIT "liveops:$marker" "qemu died mid-session"
        fi
        _budget_check "liveops:$marker"
        sleep 1
        i=$((i + 1))
    done
    _hang_fail CONSOLE-WAIT "liveops:$marker" "not seen in 600s; tail: $(tail -3 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
}

# _liveops_session <dir> — the fed operator session (runs ONCE, on the
# successful login attempt's live console; the boot ends in its own
# `poweroff -f`).
_liveops_session() {
    local dir="$1" luks_uuid
    luks_uuid=$(cryptsetup luksUUID "$CANON_DISK" 2>/dev/null)
    [[ -n "$luks_uuid" ]] || { echo "s01c: no LUKS UUID on the canonical disk (liveops)"; exit 1; }
    echo "# live session: logging in on the serial console (one keystroke: the username)"
    _liv_feed "$dir" "root" '~# '
    _liv_feed "$dir" \
        'dd if=/dev/vdc bs=65536 skip=2 | gzip -dc > /liveops.tgz; echo LIV1-RC=$?' \
        'LIV1-RC=0'
    _liv_feed "$dir" 'tar -xf /liveops.tgz -C / && echo LIV1B-$((43+2))-OK' \
        'LIV1B-45-OK'
    # the operator environment: the stub wrappers on PATH, the device TCTI,
    # the by-uuid seam (no udev in the guest for the container — the s00b
    # idiom), and a writable tmp dir for the CLI's temp-key files
    _liv_feed "$dir" \
        "mkdir -p /run/bu && ln -sf /dev/vdb /run/bu/$luks_uuid && export PATH=/usr/local/bin:\$PATH ALPINE_FDE_TCTI=device:/dev/tpmrm0 ALPINE_FDE_BY_UUID_DIR=/run/bu ALPINE_FDE_TMPDIR=/tmp && echo LIV2-\$((40+2))-OK" \
        'LIV2-42-OK'
    # --- status: the read-only live snapshot (§8.1 C-G14) ---------------------
    _liv_feed "$dir" '/opt/alpine-fde/bin/alpine-fde status >/tmp/liv-st.out 2>&1; echo LIV3-RC=$?' \
        'LIV3-RC=0'
    _liv_feed "$dir" \
        'grep -Eq "systemd-tpm2 tokens: 1" /tmp/liv-st.out && grep -Eq "token pcrs: 7,11" /tmp/liv-st.out && echo LIV3B-OK || { cut -c1-72 /tmp/liv-st.out | head -24; echo LIV3B-DIAG; }' \
        'LIV3B-OK'
    _liv_feed "$dir" \
        'grep -Eq "pcr7[[:space:]]+live=[0-9a-f]{64} base=[0-9a-f]{64}[[:space:]]+match" /tmp/liv-st.out && echo LIV3C-OK || { grep -a pcr7 /tmp/liv-st.out | cut -c1-72; echo LIV3C-DIAG; }' \
        'LIV3C-OK'
    # --- audit: live PCRs + SB state vs the baseline (§8.4; rc 0 = match) ------
    # efivarfs is not mounted by the musl init — mount it so the Secure Boot
    # section reads the REAL NVRAM the firmware measured into PCR 7.
    _liv_feed "$dir" \
        'mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null; /opt/alpine-fde/bin/alpine-fde audit >/tmp/liv-aud.out 2>&1; echo LIV4-RC=$?' \
        'LIV4-RC=0'
    _liv_feed "$dir" \
        'grep -F "all checked values match the baseline" /tmp/liv-aud.out && grep -Fq "\"result\"" /etc/alpine-fde/last-audit.json && echo LIV4B-OK || { cut -c1-72 /tmp/liv-aud.out | head -24; echo LIV4B-DIAG; }' \
        'LIV4B-OK'
    # --- doctor: the readiness report (read-only; verdict may be NOT READY) ----
    _liv_feed "$dir" '/opt/alpine-fde/bin/alpine-fde doctor >/tmp/liv-doc.out 2>&1; echo LIV5-RC=$?' \
        'LIV5-RC=[01]'
    _liv_feed "$dir" \
        'grep -F "readiness report" /tmp/liv-doc.out && grep -Eq "TPM 2.0 reachable" /tmp/liv-doc.out && echo LIV5B-OK || { cut -c1-72 /tmp/liv-doc.out | head -16; echo LIV5B-DIAG; }' \
        'LIV5B-(OK|DIAG)'
    # --- rotate: the keyslot-0 passphrase change, there AND BACK (§9.4) --------
    # net-zero: the canonical disk keeps the standing slot-0 passphrase for
    # the later legs even though this boot's overlay is committed (R1).
    _liv_feed "$dir" \
        "ALPINE_FDE_OLD_PASSPHRASE=$ALPINE_FDE_SLOT0_PASSPHRASE ALPINE_FDE_NEW_PASSPHRASE=w2-Live0ps-Rotate9zkq /opt/alpine-fde/bin/alpine-fde rotate >/tmp/liv-rot1.out 2>&1; echo LIV6-RC=\$?" \
        'LIV6-RC=0'
    _liv_feed "$dir" \
        'grep -F "keyslot-0 passphrase changed" /tmp/liv-rot1.out && echo LIV6B-OK' \
        'LIV6B-OK'
    # the rotated state is verified IN-GUEST (the NEW passphrase unlocks slot
    # 0); the rotation BACK is impossible via the CLI BY DESIGN — the §13
    # floor (correctly) refuses the fixture passphrase ("alpine-fde-*" is on
    # the common-password blocklist) — so the scenario performs the
    # restoration host-side once this boot's overlay is committed.
    _liv_feed "$dir" \
        'printf %s w2-Live0ps-Rotate9zkq | cryptsetup open --test-passphrase --key-slot 0 /dev/vdb >/dev/null 2>&1 && echo LIV7B-OK || echo LIV7B-DIAG' \
        'LIV7B-(OK|DIAG)'
    # --- pre-upgrade: the btrfs snapshot op (§8.1 C-G16), then cleaned up ------
    # The CLI snapshots the root subvolume at its MOUNT POINT (the live-found
    # mountinfo fs-root defect — the §9.1 layout mounts subvol=@ as / and
    # "/@" does not exist inside its own namespace — fixed in
    # lib/cmd/pre-upgrade.sh _pu_snapshot_src; unit pin
    # tests/unit/pre_upgrade_snapshot_src.sh). The CLI prints the snapshot
    # path on stdout; the leg asserts rc 0 + the read-only snapshot exists,
    # then deletes it (no residual state rides the committed overlay).
    _liv_feed "$dir" \
        'SNAP=$(/opt/alpine-fde/bin/alpine-fde pre-upgrade 2>/tmp/liv-pu.err | tail -n 1); echo LIV8-RC=$?' \
        'LIV8-RC=0'
    _liv_feed "$dir" \
        '[ -n "$SNAP" ] && /usr/local/bin/btrfs subvolume show "$SNAP" 2>/dev/null | grep -F "Read-only" >/dev/null && echo LIV8B-OK || { cat /tmp/liv-pu.err | cut -c1-72 | head -3; echo LIV8B-DIAG; }' \
        'LIV8B-OK'
    _liv_feed "$dir" \
        '/usr/local/bin/btrfs subvolume delete "$SNAP" 2>/tmp/liv-del.err; echo LIV9-RC=$?; ls -ld "$SNAP" 2>&1 | cut -c1-60; cut -c1-72 /tmp/liv-del.err | head -2' \
        'LIV9-RC=[0-9]+'
    _liv_feed "$dir" 'sync; poweroff -f' 'reboot: Power down|Power down|acpi_power_off'
}

# =================================================================================
# Boot 1 (login half) — zero-input token unlock -> login: -> the LIVE-OPS
# session (status / audit / doctor / rotate / pre-upgrade in-guest)
# =================================================================================
_stage_open "boot1-login"
B1="$RUN/boot1-login"
mkdir -p "$B1"
cp "$RUN/uki-v1.efi" "$B1/harness.efi"
uki_pcrsig_disk "$B1/pcrsig.img" "$RUN/uki-v1-combined.json" || exit 1
uki_stage_login_drive "$B1/pcrsig.img" || exit 1
_liveops_inject_login
_liveops_build "$B1/pcrsig.img"
LOGIN_SEEN=0
for _c_attempt in 1 2; do
    _budget_check "boot1-login-attempt:$_c_attempt"
    _reanchor_tpm "$RUN/tpm"
    rm -f "$RUN/console.log"
    _c_overlay="$RUN/disk-b1-login-$_c_attempt.qcow2"
    overlay_create "$CANON_DISK" "$_c_overlay" || { echo "s01c: overlay create failed"; exit 1; }
    echo "# boot 1 (login): release UKI + login stage on the payload drive — zero-input token unlock (ZERO console input)"
    CURRENT_QEMU_DIR="$RUN"
    qemu_run "$RUN" "$CANON_ESP" "$_c_overlay" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$B1/pcrsig.img" \
        || { echo "s01c: qemu_run FAILED (login); discarding"; qemu_kill "$RUN"; CURRENT_QEMU_DIR=""; \
             overlay_discard "$_c_overlay"; exit 1; }
    _qemu_alive "$RUN"
    _lrc=0
    _wait_login "$RUN" "$QEMU_TIMEOUT" || _lrc=$?
    if ((_lrc == 0)); then
        LOGIN_SEEN=1
        CURRENT_QEMU_DIR="$RUN"
        _liveops_session "$RUN"
        # the session's last feed was `sync; poweroff -f` — the guest exits
        # itself; a stale guest is killed loudly (never a silent timeout)
        _wedge_wait "$RUN" "$QEMU_TIMEOUT" || _hang_fail LIVEOPS-EXIT "b1-login" \
            "the live session's poweroff never landed (wait rc=$?)"
        CURRENT_QEMU_DIR=""
        sleep 1
        _bounded 900 overlay-commit-b1-login qemu-img commit -f qcow2 -- "$_c_overlay"
        overlay_discard "$_c_overlay"
        break
    fi
    qemu_kill "$RUN"
    CURRENT_QEMU_DIR=""
    overlay_discard "$_c_overlay"   # a failed attempt never advances the state
    echo "s01c: login boot attempt $_c_attempt failed (rc=$_lrc) — discarded"
    ((_c_attempt < 2)) || { echo "s01c: login boot failed after 2 attempts"; exit 1; }
done
# the live session rotated keyslot 0 to the in-session passphrase (§9.4
# rotate) — restore the STANDING slot-0 passphrase host-side now that the
# boot's overlay is committed (the CLI cannot do this step: the §13 floor
# rightly refuses the fixture passphrase, which is on the common-password
# blocklist). Net-zero proof below: the standing credential unlocks slot 0
# again AND the rotated one no longer does.
if printf '%s' "w2-Live0ps-Rotate9zkq" | timeout 60 cryptsetup open --test-passphrase \
    --key-slot 0 "$CANON_DISK" >/dev/null 2>&1; then
    printf '%s' "w2-Live0ps-Rotate9zkq" >"$RUN/kf-rot.tmp"
    chmod 600 "$RUN/kf-rot.tmp"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-rot2.tmp"
    chmod 600 "$RUN/kf-rot2.tmp"
    _bounded 600 liveops-rotate-restore cryptsetup luksChangeKey --batch-mode \
        --key-slot 0 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
        --key-file "$RUN/kf-rot.tmp" "$CANON_DISK" "$RUN/kf-rot2.tmp"
    shred -u "$RUN/kf-rot.tmp" "$RUN/kf-rot2.tmp" 2>/dev/null \
        || rm -f "$RUN/kf-rot.tmp" "$RUN/kf-rot2.tmp"
else
    echo "# liveops: slot 0 did not take the in-session passphrase (rotate did not land?)"
fi

cp "$RUN/console.log" "$RUN/console-b1-login.log"
LOG_C=$(cat "$RUN/console-b1-login.log")
if ((LOGIN_SEEN == 1)); then
    _assert_result ok "Boot 1: \`login:\` reached with ZERO console keystrokes" ""
else
    _assert_result not-ok "Boot 1: \`login:\` reached with ZERO console keystrokes" \
        "never matched; console tail: $(tail -3 "$RUN/console-b1-login.log" 2>/dev/null | tr '\n' ' ')"
fi
_assert_unsealed "$LOG_C" "boot1-login" no-poweroff
assert_contains "[boot1-login] stage selected on the payload drive (release UKI bytes preserved)" "$LOG_C" \
    "payload drive selects stage=login"
assert_contains "[boot1-login] switch_root into the populated installed system" "$LOG_C" \
    "alpine-fde-harness: switching to the installed system"
assert_contains "[boot1-login] root mount is the §9.1 @ subvolume (G-HW5 btrfs default)" "$LOG_C" \
    "alpine-fde-btrfs: root mounted subvol=@ (login stage)"
assert_contains "[boot1-login] the installed system's getty banner (real Alpine userspace)" "$LOG_C" \
    "Welcome to Alpine Linux"
# --- the in-guest LIVE-OPS suite (every marker corroborated in-console) ------
for _liv in 'LIV1-RC=0' 'LIV1B-45-OK' 'LIV2-42-OK' 'LIV3-RC=0' 'LIV3B-OK' \
    'LIV3C-OK' 'LIV4-RC=0' 'LIV4B-OK' 'LIV5-RC=' 'LIV5B-OK' 'LIV6-RC=0' \
    'LIV6B-OK' 'LIV7B-OK' 'LIV8-RC=0' 'LIV8B-OK' 'LIV9-RC=0'; do
    assert_contains "[liveops] session marker $_liv" "$LOG_C" "$_liv"
done
unset _liv
if grep -qE 'LIV5-RC=[01]' <<<"$LOG_C"; then
    _assert_result ok "[liveops] doctor completed (readiness report produced, verdict not gated)" ""
else
    _assert_result not-ok "[liveops] doctor completed" "no LIV5-RC marker"
fi
assert_contains "[liveops] the session ended in the guest's own poweroff (not a timeout-kill)" \
    "$LOG_C" "reboot: Power down"
# the disk-level net-zero proof (the session rotated slot 0 to the in-session
# passphrase; the scenario restored the standing one host-side after the
# commit): the standing credential unlocks slot 0 AND the rotated one no
# longer does, and the TPM enrollment survived a no-reseat rotate untouched
assert_eq "liveops: rotate was NET-ZERO (the standing slot-0 passphrase unlocks slot 0)" "0" \
    "$(printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" | timeout 300 cryptsetup open --test-passphrase --key-slot 0 "$CANON_DISK" >/dev/null 2>&1; echo $?)"
assert_ne "liveops: the in-session passphrase no longer unlocks slot 0 (the restore was real)" "0" \
    "$(printf '%s' "w2-Live0ps-Rotate9zkq" | timeout 300 cryptsetup open --test-passphrase --key-slot 0 "$CANON_DISK" >/dev/null 2>&1; echo $?)"
NTOK_LIV=$(disk_token_json "$CANON_DISK" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "liveops: the standing TPM enrollment survived the session (rotate without reseat)" "1" "$NTOK_LIV"
# G-T13 prediction for the ENROLLED release UKI on its own console
CONSOLE="$RUN/console-b1-login.log"
cp "$RUN/uki-v1.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "G-T13 [boot1-login]"
CONSOLE="$CONSOLE_SAVED"
_stage_close "boot1-login"

# =================================================================================
# Boot 2 — kernel update + re-seal, passwordless under the updated {7,11} (s14)
# =================================================================================
echo "# ==== boot 2: kernel update (s14's core, progressive) ===="
# §8.3 Alpine kernel-update delivery contract (the apk trigger + kernel-hooks.d
# stand-in): the update boots carry the tooling payload on their pcrsig drive
# tail and the scenario asserts the shipped hooks invoke `alpine-fde ukictl build`.
_step tooling-payload
rm -rf "$RUN/tooling" "$RUN/tooling.tar.gz"
mkdir -p "$RUN/tooling/opt/alpine-fde"
for _d in bin lib hooks; do
    cp -r "$REPO/$_d" "$RUN/tooling/opt/alpine-fde/$_d" || exit 1
done
_bounded 300 tooling-tar tar -C "$RUN/tooling" -czf "$RUN/tooling.tar.gz" opt
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/alpine-fde/hooks/kernel-hooks.d/alpine-fde-build.hook" "$RUN/tooling.listing" \
    && grep -qx "opt/alpine-fde/hooks/apk/triggers/alpine-fde.trigger" "$RUN/tooling.listing" \
    && grep -qx "opt/alpine-fde/hooks/mkinitfs/alpine-fde-unseal.sh" "$RUN/tooling.listing" \
    && grep -qx "opt/alpine-fde/bin/alpine-fde" "$RUN/tooling.listing"; then
    _assert_result ok "S-14 payload: kernel hook + apk trigger + mkinitfs hook ship in the tooling payload" ""
else
    _assert_result not-ok "S-14 payload: kernel hook + apk trigger + mkinitfs hook ship in the tooling payload" \
        "required entries missing from $RUN/tooling.listing"
fi
assert_contains "S-14 contract: the kernel hook invokes alpine-fde ukictl build (§8.3 marker)" \
    "$(cat "$REPO/hooks/kernel-hooks.d/alpine-fde-build.hook")" "ukictl build"
assert_contains "S-14 contract: the apk trigger invokes alpine-fde ukictl build (§8.3 marker)" \
    "$(cat "$REPO/hooks/apk/triggers/alpine-fde.trigger")" "ukictl build"
assert_contains "S-14 contract: the apk trigger watches the kernel module tree" \
    "$(cat "$REPO/hooks/apk/triggers/alpine-fde.trigger")" "/lib/modules"
# the guest tree for the variant builds (cached via .closure-ok; in skip mode
# uki_build never ran, so derive it explicitly). The variant initrds pack the
# DECOMPRESSED module set ($tree/modules) uki_build otherwise creates from the
# modules-tree — replicate that derivation here (idempotent in full mode).
_step guest-tree
uki_guest_tree "$RUN/guest-tree" || { echo "s01c: uki_guest_tree failed"; exit 1; }
if [[ ! -d "$RUN/guest-tree/modules" ]]; then
    mkdir -p "$RUN/guest-tree/modules"
    for _mod in $UKI_MODULES; do
        _src=$(find "$RUN/guest-tree/modules-tree" -name "$_mod.ko.xz" 2>/dev/null | head -1)
        if [[ -n "$_src" ]]; then
            xz -dc "$_src" >"$RUN/guest-tree/modules/$_mod.ko"
        else
            echo "s01c: module not found in kernel tree (builtin?): $_mod"
        fi
    done
fi
# §10 row "kernel update build failed": the rebuild WITHOUT the release signing
# key fails LOUDLY and ships NOTHING (ADR-8: the CLI's keys_check precedes any
# ESP mutation; the observable outcome is pinned, not the internal rc).
KEYLESS_DIR="$RUN/keys-keyless"   # no db.key/release material inside
mkdir -p "$KEYLESS_DIR"
if _vuki_build_try "$RUN/stage-keyless" "$RUN/guest-tree" "$KEYLESS_DIR" \
        6.3.0-broken v630 "$RUN/uki-keyless.efi" 2>"$RUN/keyless.log"; then
    _assert_result not-ok "failed rebuild: build WITHOUT the signing key fails non-zero (loud)" "unexpected rc 0"
else
    _assert_result ok "failed rebuild: build WITHOUT the signing key fails non-zero (loud)" ""
fi
assert_contains "failed rebuild names tool + variant (not a silent failure)" \
    "$(cat "$RUN/keyless.log")" "ukify --measure (variant 6.3.0-broken) failed"
if [[ -e "$RUN/uki-keyless.efi" ]]; then
    _assert_result not-ok "failed rebuild ships NO UKI artifact" "uki-keyless.efi exists"
else
    _assert_result ok "failed rebuild ships NO UKI artifact" ""
fi
# the kernel update: build 6.4.0 (the §8.3 ukictl-build stand-in), touch NOTHING
# in the TPM world until the re-seal below
_vuki_build_checked "$RUN/stage-v2" "$RUN/guest-tree" "$RUN/keys" 6.4.0 v640 "$RUN/uki-v2.efi"
cp "$RUN/uki-v2.efi.pcrsig.json" "$RUN/uki-v2.pcrsig.json"
assert_rc "uki 6.4.0: sbverify clean" 0 sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-v2.efi"
D11_V2=$(cat "$RUN/uki-v2.efi.pcr11.txt")
[[ -n "$D11_V2" ]] || { echo "s01c: no enter-initrd d11 prediction from the v2 build"; exit 1; }
POLS_V1=$(jq -r '.sha256[].pol' "$RUN/uki-v1.pcrsig.json" | sort)
POLS_V2=$(jq -r '.sha256[].pol' "$RUN/uki-v2.pcrsig.json" | sort)
assert_ne "new kernel -> new signed pols (distinct PCR 11 prediction)" "$POLS_V1" "$POLS_V2"
# the re-seal (§8.3 production answer): enroll-tpm RETIRES the stale enrollment
# and stands the fresh seal in the same run — the {7,11} policy re-composed
# over the UNCHANGED static d7 and the NEW UKI's signed prediction; the volume
# key is never re-encrypted. Digest-anchored: no reseeding needed.
_step pcrsig-combined-v2
uki_pcrsig_append_combined "$RUN/uki-v2.pcrsig.json" "$RUN/uki-v2-combined.json" \
        "$D7" "$D11_V2" "$RUN/keys" || exit 1
assert_eq "re-sealed combined entry pol == policy_digest(same d7, 6.4.0 enter-initrd d11)" \
    "$(policy_digest "$D7" "$D11_V2")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-v2-combined.json")"
uki_pcrsig_disk "$RUN/pcrsig-v2.img" "$RUN/uki-v2-combined.json" || exit 1
cat "$RUN/pcrsig-v2.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-v2-tooling.img"
swtpm_ensure "$RUN/tpm" || { echo "s01c: swtpm restart (re-seal) failed"; exit 1; }
RETIRE_LOG="$RUN/enroll-v2.log"
if _enroll_cli "reseal-v2" "$RUN/uki-v2-combined.json" "$RUN/keys" "$RETIRE_LOG"; then
    _assert_result ok "re-seal: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" ""
else
    _assert_result not-ok "re-seal: enroll-tpm rc 0 (stale retired + fresh seal stood, one run)" \
        "output: $(tail -3 "$RETIRE_LOG" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "re-seal: the CLI RETIRED the stale enrollment in the same run" \
    "$(cat "$RETIRE_LOG")" "$(sentinel_of cli_enroll_retire)"
_assert_token "$CANON_DISK" "re-seal"
# install the update on the ESP: new default, old kernel RETAINED for rollback
_esp_add_uki "$CANON_ESP" "$RUN/uki-v2.efi" alpine-fde-v2.efi || exit 1
_esp_set_default "$CANON_ESP" "$RUN/uki-v2.efi" || exit 1
ESPLS=$(mdir -i "$CANON_ESP" ::/EFI/BOOT ::/EFI/Linux 2>/dev/null)
assert_contains "ESP retains v1 (old kernel kept for rollback)" "$ESPLS" "alpine-fde-v1.efi"
assert_contains "ESP has 6.4.0 as new default" "$ESPLS" "alpine-fde-v2.efi"

_pipeline_boot "b2-kernel-update" "$CANON_ESP" "$RUN/vars-enrolled.fd" "$RUN/pcrsig-v2-tooling.img" commit
LOG=$(cat "$RUN/console-b2-kernel-update.log")
_assert_unsealed "$LOG" "b2-kernel-update"
assert_not_contains "[b2-kernel-update] the I3 gate passed (the signature is NOT the defect)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
CONSOLE="$RUN/console-b2-kernel-update.log"
cp "$RUN/uki-v2.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "G-T13 [b2-kernel-update]"
CONSOLE="$CONSOLE_SAVED"

# =================================================================================
# Boot 3 — rollback to an OLDER RETAINED UKI, passwordless, ZERO enrollment
# (s02's core, exactly the s02 model: the rollback target 6.1.0 is an older
# release-signed UKI that was NEVER enrolled, delivered with its OWN combined
# {7,11} entry over (enrolled d7, its enter-initrd d11)). NB: the ENROLLED v1
# release UKI cannot serve as the rollback target in the skip mode — the
# cached s00b release UKI carries the fed-session DEBUG SHELL seam baked in,
# and a non-login boot of it ends at the debug shell instead of a clean
# poweroff (v0 is this scenario's own build, seam-free). The boot MUST NOT
# persist anything: overlay discarded even on success (the metadata-identity
# invariant + the state for boot 4).
# =================================================================================
echo "# ==== boot 3: rollback (s02's core, progressive) ===="
# the older retained UKI 6.1.0 (genuinely different measured content: own
# uname + .osrel -> own PCR 11 prediction); K1-signed, never enrolled
_vuki_build_checked "$RUN/stage-v0" "$RUN/guest-tree" "$RUN/keys" 6.1.0 v610 "$RUN/uki-v0.efi"
cp "$RUN/uki-v0.efi.pcrsig.json" "$RUN/uki-v0.pcrsig.json"
D11_V0=$(cat "$RUN/uki-v0.efi.pcr11.txt")
[[ -n "$D11_V0" ]] || { echo "s01c: no enter-initrd d11 prediction from the v0 build"; exit 1; }
assert_ne "6.1.0's enter-initrd d11 differs from v1's (genuinely different measured content)" \
    "$D11_V0" "$D11_V1"
assert_rc "uki 6.1.0: sbverify clean (release cert)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-v0.efi"
POLS_V0=$(jq -r '.sha256[].pol' "$RUN/uki-v0.pcrsig.json" | sort)
assert_ne "pcrsig pols differ across UKIs (distinct PCR 11 predictions)" "$POLS_V1" "$POLS_V0"
PKFP_V1=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-v1.pcrsig.json" | sort)
PKFP_V0=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-v0.pcrsig.json" | sort)
assert_eq "pcrsig pkfp identical across UKIs (same release key)" "$PKFP_V1" "$PKFP_V0"
# the vendor's rollback delivery: 6.1.0's OWN release-signed combined {7,11}
# entry over (enrolled d7, 6.1.0's enter-initrd d11) — no enrollment, a
# payload-drive signature only
_step pcrsig-combined-v0-rollback
uki_pcrsig_append_combined "$RUN/uki-v0.pcrsig.json" "$RUN/uki-v0-combined.json" \
        "$D7" "$D11_V0" "$RUN/keys" || exit 1
assert_eq "rollback combined entry pol == policy_digest(enrolled d7, 6.1.0 enter-initrd d11)" \
    "$(policy_digest "$D7" "$D11_V0")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-v0-combined.json")"
uki_pcrsig_disk "$RUN/pcrsig-v0-rb.img" "$RUN/uki-v0-combined.json" || exit 1
# the rollback ACTION: retain the older UKI and select it (the mtools default
# swap — the harness stand-in for bootnext; the retained entries stay in
# ::/EFI/Linux)
_esp_add_uki "$CANON_ESP" "$RUN/uki-v0.efi" alpine-fde-v0.efi || exit 1
_esp_set_default "$CANON_ESP" "$RUN/uki-v0.efi" || exit 1
ESPLS=$(mdir -i "$CANON_ESP" ::/EFI/Linux 2>/dev/null)
assert_contains "ESP retains the enrolled v1 entry" "$ESPLS" "alpine-fde-v1.efi"
assert_contains "ESP retains the 6.4.0 entry (rollback is a selection, not a removal)" "$ESPLS" "alpine-fde-v2.efi"
assert_contains "ESP carries the 6.1.0 rollback target" "$ESPLS" "alpine-fde-v0.efi"
assert_rc "current v2 UKI is sbverify-clean (release cert)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-v2.efi"
# metadata identity baseline: snapshot AFTER the boot-2 re-seal — the rollback
# boot must leave it byte-identical
_meta_snapshot "$CANON_DISK" "$RUN/meta-pre-rollback.json"
_pipeline_boot "b3-rollback" "$CANON_ESP" "$RUN/vars-enrolled.fd" "$RUN/pcrsig-v0-rb.img" discard
LOG=$(cat "$RUN/console-b3-rollback.log")
_assert_unsealed "$LOG" "b3-rollback"
_meta_snapshot "$CANON_DISK" "$RUN/meta-post-rollback.json"
assert_rc "rollback boot changed NO LUKS2 metadata (no enrollment)" 0 \
    cmp -s "$RUN/meta-pre-rollback.json" "$RUN/meta-post-rollback.json"
CONSOLE="$RUN/console-b3-rollback.log"
cp "$RUN/uki-v0.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "G-T13 [b3-rollback]"
CONSOLE="$CONSOLE_SAVED"

# =================================================================================
# Boot 4 — release-key rotation K1 -> K2 (s16's core).
#   launch 1 (recovery): the K2-built UKI under the ROTATED vars (db += K2,
#           dbx += K1) with the STANDING K1-signed entry on the drive: the I3
#           gate refuses (K1-signed entry vs the initrd's K2 rel.pub) -> the
#           bounded recovery loop (fed slot-0) -> the boot LANDS the rotated
#           PCR 7. Overlay discarded (the enrollment is still the K1 world).
#   host:  baseline re-anchored to the rotated register (the §9.4 accept
#           analog), K2 combined entry, enroll-tpm under K2 (retire + stand).
#   launch 2: passwordless boot + unseal under K2 on the rotated register.
# =================================================================================
echo "# ==== boot 4: release-key rotation (s16's core, progressive) ===="
mkdir -p "$RUN/keys2"
# ADR-16 floor applies to ANY key the seal path signs with — K2 at 3072 directly
_bounded 300 k2-keygen openssl req -x509 -newkey rsa:3072 \
    -keyout "$RUN/keys2/db.key" -out "$RUN/keys2/db.crt" -days 30 -nodes \
    -subj "/CN=alpine-fde-test-release-v2"
_bounded 60 k2-release-pub openssl x509 -in "$RUN/keys2/db.crt" -pubkey -noout \
    -out "$RUN/keys2/release.pub"
assert_file_exists "K2 keypair generated (offline-medium stand-in)" "$RUN/keys2/db.key"
# §9.6 step 2: dual-sign (append the K2 signature to the CURRENT UKI) — the
# appended PE signature table is NOT a measured section (verified host-side)
_bounded 300 dual-sign sbsign --key "$RUN/keys2/db.key" --cert "$RUN/keys2/db.crt" \
    --output "$RUN/uki-v2-dual.efi" "$RUN/uki-v2.efi"
SIGLIST=$(sbverify --list "$RUN/uki-v2-dual.efi" 2>&1)
assert_contains "dual-signed: signature 1 present" "$SIGLIST" "signature 1"
assert_contains "dual-signed: signature 2 present" "$SIGLIST" "signature 2"
assert_rc "dual-signed: K1 signature still verifies" 0 sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-v2-dual.efi"
assert_rc "dual-signed: K2 signature verifies" 0 sbverify --cert "$RUN/keys2/db.crt" "$RUN/uki-v2-dual.efi"
# §9.6 step 4: db += K2 AND dbx += K1 in ONE vars edit
cp "$RUN/vars-enrolled.fd" "$RUN/vars-rotated.fd"
assert_rc "virt-fw-vars: db += K2, dbx += K1 (one step)" 0 \
    virt-fw-vars -i "$RUN/vars-rotated.fd" -o "$RUN/vars-rotated.fd" \
        --add-db "$ALPINE_FDE_TEST_GUID" "$RUN/keys2/db.crt" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$RUN/keys/db.crt"
VARSDBG=$(virt-fw-vars -i "$RUN/vars-rotated.fd" -p 2>/dev/null | grep -cE '^(db|dbx)[[:space:]]*:')
assert_eq "rotated vars carry db and dbx blobs" "2" "$VARSDBG"
# the K2-built UKI (pcrsig + PE sig + initrd rel.pub = K2; genuinely different
# measured content via its own uname)
_vuki_build_checked "$RUN/stage-k2" "$RUN/guest-tree" "$RUN/keys2" 6.6.0-k2 v660k2 \
    "$RUN/uki-k2.efi" "$RUN/keys2/db.key" "$RUN/keys2/release.pub" \
    "$RUN/keys2/db.key" "$RUN/keys2/db.crt" "$RUN/keys2/release.pub"
cp "$RUN/uki-k2.efi.pcrsig.json" "$RUN/uki-k2.pcrsig.json"
D11_K2=$(cat "$RUN/uki-k2.efi.pcr11.txt")
[[ -n "$D11_K2" ]] || { echo "s01c: no enter-initrd d11 prediction from the K2 build"; exit 1; }
K1PKFP=$(jq -r '.sha256[].pkfp' "$RUN/uki-v1.pcrsig.json" 2>/dev/null | sort -u | head -1)
K2PKFP=$(jq -r '.sha256[].pkfp' "$RUN/uki-k2.pcrsig.json" | sort -u | head -1)
assert_ne "new .pcrsig is signed by a DIFFERENT key (pkfp K1 != K2)" "$K1PKFP" "$K2PKFP"
_esp_add_uki "$CANON_ESP" "$RUN/uki-k2.efi" alpine-fde-k2.efi || exit 1
_esp_set_default "$CANON_ESP" "$RUN/uki-k2.efi" || exit 1

_pipeline_boot "b4-rotate-recovery" "$CANON_ESP" "$RUN/vars-rotated.fd" "$RUN/pcrsig-v2.img" discard feed
LOG=$(cat "$RUN/console-b4-rotate-recovery.log")
# the firmware ACCEPTED the K2-only UKI under the rotated policy (it carries no
# K1 signature — dbx += K1 revokes nothing on it); the STANDING K1-signed entry
# is refused by the I3 gate, and the bounded recovery loop is the way in
_assert_polluted "$LOG" "b4-rotate-recovery" 1
assert_contains "[b4-rotate-recovery] the I3 gate refused the STANDING K1-signed entry under the K2 initrd" \
    "$LOG" "$(sentinel_of unseal_sig_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_sig_refused)" "$RUN/console-b4-rotate-recovery.log" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console-b4-rotate-recovery.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "[b4-rotate-recovery] refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "[b4-rotate-recovery] refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
# the recovery boot IS the post-rotation measurement: the rotated vars moved
# PCR 7 off the pre-rotation value, and the K2 seal must be composed over the
# register the machine actually reproduces (digest-anchored, the s16 lesson)
D7_ROT=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-b4-rotate-recovery.log" | head -1 | cut -d= -f2)
[[ -n "$D7_ROT" ]] || { echo "s01c: recovery console has no PCR 7 print — nothing to compose over"; exit 1; }
assert_ne "the rotated vars moved PCR 7 off the pre-rotation value" "$D7" "$D7_ROT"
PCR11_V2=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$RUN/console-b2-kernel-update.log" | head -1 | cut -d= -f2)
PCR11_K2REC=$(grep -oE 'alpine-fde-pcr sha256:11=[0-9a-f]{64}' "$RUN/console-b4-rotate-recovery.log" | head -1 | cut -d= -f2)
assert_ne "the K2 kernel moved PCR 11 (distinct measured content)" "$PCR11_V2" "$PCR11_K2REC"
CONSOLE="$RUN/console-b4-rotate-recovery.log"
cp "$RUN/uki-k2.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "G-T13 [b4-rotate-recovery]"
CONSOLE="$CONSOLE_SAVED"

# §9.4 accept analog: the baseline is re-anchored to the register the machine
# actually reproduces under the rotated policy (the CLI's precondition
# compares the entry's recorded d7 against THIS value)
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$D7_ROT\",|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline re-anchored to the rotated register" "$D7_ROT" \
    "$(sed -n 's/^  "expected_pcr7": "\(.*\)",\{0,1\}$/\1/p' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
_step pcrsig-combined-k2
uki_pcrsig_append_combined "$RUN/uki-k2.pcrsig.json" "$RUN/uki-k2-combined.json" \
        "$D7_ROT" "$D11_K2" "$RUN/keys2" || exit 1
assert_eq "K2 combined entry pol == policy_digest(rotated d7, K2 enter-initrd d11)" \
    "$(policy_digest "$D7_ROT" "$D11_K2")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-k2-combined.json")"
uki_pcrsig_disk "$RUN/pcrsig-k2.img" "$RUN/uki-k2-combined.json" || exit 1
swtpm_ensure "$RUN/tpm" || { echo "s01c: swtpm restart (K2 enroll) failed"; exit 1; }
K2LOG="$RUN/enroll-k2.log"
if _enroll_cli "rotate-enroll-k2" "$RUN/uki-k2-combined.json" "$RUN/keys2" "$K2LOG"; then
    _assert_result ok "K2 re-seal: enroll-tpm rc 0 (K1 retired + K2 seal stood, one run)" ""
else
    _assert_result not-ok "K2 re-seal: enroll-tpm rc 0 (K1 retired + K2 seal stood, one run)" \
        "output: $(tail -3 "$K2LOG" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "K2 re-seal: the CLI RETIRED the stale enrollment in the same run" \
    "$(cat "$K2LOG")" "$(sentinel_of cli_enroll_retire)"
_assert_token "$CANON_DISK" "K2 re-seal" "$RUN/keys2/release.pub"

_pipeline_boot "b4-rotate-k2" "$CANON_ESP" "$RUN/vars-rotated.fd" "$RUN/pcrsig-k2.img" commit
LOG=$(cat "$RUN/console-b4-rotate-k2.log")
_assert_unsealed "$LOG" "b4-rotate-k2"
assert_eq "the booted PCR 7 IS the rotated value the K2 seal was composed over (no fixture drift confound)" \
    "$D7_ROT" "$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-b4-rotate-k2.log" | head -1 | cut -d= -f2)"
CONSOLE="$RUN/console-b4-rotate-k2.log"
cp "$RUN/uki-k2.pcrsig.json" "$RUN/uki-pcrsig.json"
assert_pcr11_prediction "G-T13 [b4-rotate-k2]"
CONSOLE="$CONSOLE_SAVED"

# --- verdict --------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-v0" "$RUN/stage-v2" "$RUN/stage-k2" "$RUN/stage-keyless"
# Run-dir footprint discipline (registry headroom): on SUCCESS the heavy
# binary artifacts are shed — the durable evidence is the per-leg console log
# (kept) plus the results JSON the runner aggregates. On FAILURE everything
# is kept for diagnosis. (This scenario's dir is the largest in the suite:
# the post-install canonical disk is genuinely dense ~1.5 GB.)
if (( TESTS_FAIL == 0 )); then
    rm -rf "$RUN/disk.img" "$RUN/esp.img" "$RUN/boot1-login" "$RUN/tpm" \
           "$RUN/tooling" "$RUN/tooling.tar.gz" "$RUN/keys" "$RUN/keys2" \
           "$RUN/rootfs" "$RUN/rootfs-payload.img"
    rm -f "$RUN"/uki-*.efi "$RUN"/harness.efi "$RUN"/pcrsig*.img \
          "$RUN"/vars-*.fd "$RUN"/vars-pristine.fd "$RUN"/initrd.cpio \
          "$RUN"/disk-b1-*.qcow2 "$RUN"/disk-b*.qcow2 2>/dev/null
fi
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
echo "# PIPELINE VERDICT: mode=$MODE — 4 logical boots advanced ONE canonical disk in"
echo "# place (R1): the install leg $([[ "$MODE" == "full" ]] && echo "RAN (full-from-install)" || echo "SKIPPED (valid pristine base)");"
echo "# every passwordless leg re-proved the §8.2 zero-input {7,11} unlock, the kernel"
echo "# update re-sealed via the production CLI (retire+stand), the rollback enrolled"
echo "# nothing (LUKS2 metadata byte-identical), and the rotation ended passwordless"
echo "# under K2 on the rotated register."
if (( TESTS_FAIL == 0 )); then
    echo "# s01-lifecycle-chain: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s01-lifecycle-chain: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
