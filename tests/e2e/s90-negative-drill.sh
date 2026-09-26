#!/usr/bin/env bash
# tests/e2e/s90-negative-drill.sh — the UNIFIED EARLY-BOOT NEGATIVE DRILL
# (queue item 30, move 2). ONE progressive scenario covering, in 6 staged
# fail-closed boot legs over ONE shared enrolled base, the early-boot negative
# surface of the seven standalone scenarios it absorbs:
#
#   leg1-drift        SB-on PCR 7 drift (dbx update) -> PolicyPCR refusal ->
#                     3-strike fail-closed          (absorbs s12 boot B neg.,
#                                                     s15's refusal vector)
#   leg2-loader-opt   release-signed UKI VARIANT with a tampered .cmdline +
#                     the STALE clean .pcrsig payload -> the stub measures the
#                     tampered cmdline into PCR 11 -> the policy session
#                     refuses -> 3-strike            (absorbs s07)
#   leg3-nopcrsig     UKI built WITHOUT the PCR-signing step -> no signed
#                     policy anywhere, "pcrsig payload MISSING", the token
#                     path never arms -> 3-strike   (absorbs s03 flavor 1)
#   leg4-wiped        standing enrollment wiped host-side (token + its
#                     keyslots) -> unseal_token_missing, NO self-heal (I6) ->
#                     3-strike                      (absorbs s03 flavor 2)
#   leg5-foreign-sig  .pcrsig re-signed by a FOREIGN key (same pol bytes, only
#                     the signer moved) -> the I3 openssl gate refuses BEFORE
#                     any TPM session -> 3-strike   (absorbs s18 control 1 —
#                                                     the gate-refusal class
#                                                     representative; the
#                                                     seal-refusal controls
#                                                     remap to leg1/leg2)
#   leg6-sboff-da     SB-off vars -> the ADR-20 PRE-UNSEAL GUARD blocks at the
#                     hook's FIRST step (no TPM op at all) + the DA-locked
#                     TPM drilled host-side (armed -> enforced before -> STILL
#                     enforced after; G-T15: the guest consumed nothing)
#                                                   (absorbs s05, s09, s12
#                                                     boot A)
#
# Every leg ends in the fail-closed terminal action of its class: the refusal
# legs in the §8.2 3-strike `poweroff -f`, the guard leg in the parked
# "Press Enter" reboot prompt (qemu killed BY PID). NEVER unlocked, NEVER
# UNSEALED, NEVER an emergency shell, on any leg.
#
# Artifact-level verdicts of the absorbed scenarios are pinned ZERO-BOOT by
# the wt-bootmin host suites (tests/unit/s03_stale_enrollment_host.sh,
# s13_token_tamper_host.sh, s18_foreign_pcrsig_host.sh) — the drill boots only
# what a console can still teach. Full disposition table:
# tests/unit/s90_negative_drill_contract.sh (COVERAGE_TABLE) — in particular
# s13's token-tamper variants contribute NO boot leg (the refusal/unlock
# verdicts are pinned host-side at the real TPM; the console semantics they
# shared are the GENERIC hook behaviors every leg above pins).
#
# R1/R3 (the pipeline discipline, tests/README.md "Scenario Consolidation"):
# the enrolled base is snapshotted ONCE into $RUN/base (master; NEVER booted),
# every read-mostly leg boots a fresh QCOW2 overlay over the master (discarded
# after the leg — the guest persists nothing), and the one leg that needs a
# host-side disk mutation (leg4's enrollment wipe) runs on a raw COPY of the
# master that is deleted after the boot (cryptsetup cannot write a QCOW2
# overlay — the s18 tok11 decision rule). The TPM is re-anchored (fresh,
# zeroed, settled) before EVERY leg.
#
# R2 (from-state fast path): the base is resolved, in order, from
#     1. ALPINE_FDE_E2E_STATE (run-e2e.sh chain: a valid enrolled state dir)
#     2. tests/e2e/.cache/pristine-s00b (the SHA-verified pristine base)
#     3. self-bootstrap: baseline boot + host-side production enroll (1 boot)
# The mode is on the record ("# drill base: <mode>").
#
# Step timing: one leaf stage per leg (`stage leg1-drift: done <s>s`); the
# runner's additive `stages` object carries them. Registry headroom: 6 legs +
# variant builds want ALPINE_FDE_SCENARIO_BUDGET >= 2700 for default-set runs
# (the default 1500 s outer budget is calibrated for the single-boot
# scenarios; a state-consume drill run fits comfortably in 2700 s).

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
source "$TESTS/lib/stage-timing.sh"   # leaf stage timers per leg

export QEMU_TIMEOUT="${ALPINE_FDE_DRILL_TIMEOUT:-900}"
T0=$SECONDS
CACHE_DIR="$TESTS/e2e/.cache/pristine-s00b"

RUN="$TESTS/e2e/.runs/s90-negative-drill-$(date +%s)"
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
_SWTPM_CLEANUP_TRAP_SET=1
trap 'kill "$REFRESHER" 2>/dev/null; swtpm_cleanup_all 2>/dev/null' EXIT INT TERM

# --- shared mechanics (the absorbed scenarios' proven guards, verbatim) -----------

# _wedge_wait <dir> <timeout-s> — the swtpm data-loop WEDGE guard (s02/s03
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
        sleep 5
    done
    qemu_kill "$dir"
    return 124
}

# _reanchor_tpm <dir> — before EVERY leg the fixture TPM must be a FRESH,
# ZEROED instance (the s18 hardening; a restored volatilestate makes the next
# boot CUMULATIVE and the {7,11} policy refuses its own enrollment — the
# refusal would then be a fixture artifact, not the leg's negative). Zeroed
# pre-boot is ASSERTED with a bounded recycle-retry; the proxy/setup path is
# settled with real commands before the boot is spent.
_reanchor_tpm() {
    local dir="$1" d0 d7 attempt k
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    swtpm_start "$dir" || { echo "s90: swtpm restart failed before a leg"; exit 1; }
    for attempt in 1 2 3; do
        d0=$(swtpm_pcrread "$dir" 0)
        d7=$(swtpm_pcrread "$dir" 7)
        if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ ]]; then
            break
        fi
        echo "s90: re-anchor readback attempt $attempt not zero (pcr0=${d0:-<empty>} pcr7=${d7:-<empty>}) — recycling the fixture"
        if (( attempt == 3 )); then
            echo "s90: TPM not zeroed before a leg — refusing to spend the boot"; exit 1
        fi
        swtpm_stop "$dir" 2>/dev/null || true
        swtpm_start "$dir" || { echo "s90: swtpm restart (re-anchor retry) failed"; exit 1; }
    done
    # settle: a guest TPM command arriving mid-setup times out and the
    # firmware DROPS the measurement (the degraded-boot register — s18's
    # evidence); warm the whole path through the proxy first.
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
}

# _feed_3_strike <dir> <label> — feed 3 WRONG answers through the hook's OWN
# prompt (the bounded loop's read has NO timeout: without the synchronized
# feed the boot could only end in a timeout-kill instead of the 3-strike
# poweroff). Prompt arrivals are RECORDED and asserted by the caller after the
# boot, so a retried leg never double-counts assertions. 900 s per prompt: a
# late prompt is a slow boot, never a missing one (the s18 lesson).
FED_1=0 FED_2=0 FED_3=0
_feed_3_strike() {
    local d="$1" n
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 900 "$d"; then
            eval "FED_$n=1"
            feed_line "$d/serial.sock" "alpine-fde-s90-wrong-passphrase-$n"
        else
            break
        fi
    done
}
_assert_fed() { # <label>
    local label="$1" n
    for n in 1 2 3; do
        if [[ "$(eval "echo \$FED_$n")" == "1" ]]; then
            _assert_result ok "[$label] hook awaiting recovery passphrase $n/3 (hook read path)" ""
        else
            _assert_result not-ok "[$label] hook awaiting recovery passphrase $n/3 (hook read path)" \
                "no prompt $n in console"
            break
        fi
    done
}

# _boot_leg <label> <disk-mode: overlay|raw> <raw-disk> <esp> <vars> <pcrsig-img>
# Boot ONE drill leg with the full guard set (re-anchor, fresh overlay or the
# raw mutated copy, wedge-guarded wait), bounded at 2 attempts; archives the
# console as console-<label>.log. The caller does the leg's host-side staging
# BEFORE the call and the assertions AFTER it.
_boot_leg() {
    local label="$1" mode="$2" rawdisk="$3" esp="$4" vars="$5" pcrsig="$6"
    local att wrc disk overlay=""
    stage_begin "$label"
    for att in 1 2; do
        _reanchor_tpm "$BASE/tpm"
        FED_1=0 FED_2=0 FED_3=0
        overlay=""
        rm -f "$RUN/console.log"
        disk="$rawdisk"
        if [[ "$mode" == "overlay" ]]; then
            overlay="$RUN/disk-$label-$att.qcow2"
            overlay_create "$BASE/disk.img" "$overlay" || {
                echo "s90: overlay create failed ($label attempt $att)"; exit 1; }
            disk="$overlay"
        fi
        echo "# boot leg-$label (attempt $att/2, $mode disk; up to $QEMU_TIMEOUT s) ..."
        if ! qemu_run "$RUN" "$esp" "$disk" "$vars" "$BASE/tpm" "$pcrsig"; then
            echo "s90: qemu_run FAILED ($label); qemu.stderr: $(tail -3 "$RUN/qemu.stderr" 2>/dev/null | tr '\n' ' ')"
            [[ -n "${overlay:-}" ]] && overlay_discard "$overlay"
            exit 1
        fi
        if [[ "${DRILL_LEG_FEED:-}" == "3strike" ]]; then
            _feed_3_strike "$RUN" "$label"
        elif [[ "${DRILL_LEG_FEED:-}" == "guard" ]]; then
            _guard_enter_and_kill "$RUN" "$label"
        fi
        _wedge_wait "$RUN" "$QEMU_TIMEOUT"; wrc=$?
        [[ -n "${overlay:-}" ]] && overlay_discard "$overlay"   # R3: ephemeral
        if ((wrc == 43)); then
            echo "s90: leg-$label wedged mid-boot — swtpm restarted fresh, retrying (attempt $att/2)"
            continue
        fi
        if ((wrc == 44 || wrc == 124)); then
            echo "s90: leg-$label wait rc=$wrc — aborting"
            exit 1
        fi
        break
    done
    cp "$RUN/console.log" "$RUN/console-$label.log"
    stage_end "$label"
    return 0
}

# _guard_enter_and_kill <dir> <label> — the pre-unseal guard BLOCKS and parks
# on its "Press Enter" read (the only input is the Enter confirmation). Wait
# for the guard sentinel with a qemu-liveness poll, feed the Enter, wait for
# the reboot sentinel, then hard-kill qemu BY PID (a reboot loop would
# otherwise run to the timeout).
_guard_enter_and_kill() {
    local d="$1" label="$2" i=0 qpid
    until grep -qF "$(sentinel_of unseal_sb_guard_enter)" "$d/console.log" 2>/dev/null; do
        qpid=$(cat "$d/qemu.pid" 2>/dev/null || true)
        [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break   # self-exited
        (( i < 300 )) || { echo "s90: [$label] the pre-unseal guard never armed"; exit 1; }
        sleep 1
        i=$((i + 1))
    done
    feed_line "$d/serial.sock" ""   # the operator's Enter confirmation
    i=0
    until grep -qF "$(sentinel_of unseal_sb_guard_reboot)" "$d/console.log" 2>/dev/null; do
        qpid=$(cat "$d/qemu.pid" 2>/dev/null || true)
        [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null && break
        (( i < 60 )) || { echo "s90: [$label] the guard never rebooted after Enter"; exit 1; }
        sleep 1
        i=$((i + 1))
    done
    qemu_kill "$d"   # BY PID (tests/lib/qemu.sh); the guest cannot exit itself here
}

# _assert_refusal_tail <label> — the fail-closed terminal shape every refusal
# leg must share (fed wrong answers -> 3-strike -> poweroff; never unlocked,
# never UNSEALED, no emergency shell; guest exited by its own poweroff).
_assert_refusal_tail() {
    local label="$1" log prompts
    log=$(cat "$RUN/console-$label.log" 2>/dev/null || true)
    prompts=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$log" || true)
    assert_eq "[$label] exactly 3 recovery-passphrase prompts (bounded loop, no 4th)" "3" "$prompts"
    assert_contains "[$label] 3-strike give-up (§8.2 fail-closed)" "$log" \
        "$(sentinel_of unseal_3strike)"
    assert_contains "[$label] fail-closed poweroff (no shell is offered)" "$log" \
        "$(sentinel_of unseal_poweroff)"
    assert_not_contains "[$label] never unlocked via the TPM token" "$log" \
        "$(sentinel_of unseal_unlocked)"
    assert_not_contains "[$label] never unlocked via the recovery passphrase" "$log" \
        "$(sentinel_of unseal_pass_unlocked)"
    assert_not_contains "[$label] never UNSEALED (harness sentinel)" "$log" \
        "$(sentinel_of harness_unsealed)"
    assert_not_contains "[$label] no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    # IN-08: honest in both directions (a missing pid file is not a clean exit)
    if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "[$label] guest exited (hook poweroff -f, not timeout-kill — no hang)" ""
    else
        _assert_result not-ok "[$label] guest exited (hook poweroff -f, not timeout-kill — no hang)" \
            "qemu still running or qemu.pid missing"
    fi
}

# _refusal_line_before_first_prompt <label> <sentinel> — the leg's refusal
# must strictly precede the first passphrase prompt (the recovery loop may
# only arm AFTER the token path failed)
_refusal_line_before_first_prompt() {
    local label="$1" sentinel="$2" console="$RUN/console-$label.log"
    local ref p1
    ref=$(grep -nm1 -F "$sentinel" "$console" 2>/dev/null | cut -d: -f1)
    p1=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$console" 2>/dev/null | cut -d: -f1)
    if [[ -n "${ref:-}" && -n "${p1:-}" ]] && (( ref < p1 )); then
        _assert_result ok "[$label] refusal FIRST (line $ref < first prompt line $p1)" ""
    else
        _assert_result not-ok "[$label] refusal FIRST" "ref=$ref prompt1=$p1"
    fi
}

pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }

# _host_wipe_enrollment <disk.img> — remove every systemd-tpm2 token + its
# keyslots (the host-side stand-in for a wiped enrollment; keeps the slot-0
# recovery passphrase).
_host_wipe_enrollment() {
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue   # keep the slot-0 passphrase (recovery slot)
        cryptsetup luksKillSlot --batch-mode "$img" "$slot" || return 1
    done
}

# _vuki_build_no_pcrsig <stage-dir> <guest-tree> <keys-dir> <out.efi> — the
# s03 flavor-1 variant builder: a genuinely bootable, release-signed UKI whose
# build SKIPPED the ukify PCR-signing pass (the ADR-8 "signing key absent"
# mistake) — no .pcrsig section, zero payload drive.
_vuki_build_no_pcrsig() {
    local st="$1" tree="$2" kd="$3" out="$4"
    mkdir -p "$st"
    local item
    for item in usr modules opt; do
        cp -al "$tree/$item" "$st/$item" || return 1
    done
    ln -sfn usr/bin "$st/bin"
    ln -sfn usr/sbin "$st/sbin"
    _uki_link_busybox "$tree"
    uki_initrd_write_init "$st"
    printf '# alpine-fde variant: nopcrsig\n' >>"$st/init"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$kd/release.pub" "$st/rel.pub"
    local hook_dst="$st/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    mkdir -p "${hook_dst%/*}"
    cp "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" "$hook_dst" || return 1
    chmod 755 "$hook_dst"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=alpine-fde-harness\nVERSION_ID=6.3.0\nNAME=Alpine FDE harness UKI\n' >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname=6.3.0 \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s90: ukify (nopcrsig variant) failed" >&2
        return 1
    }
    truncate -s 64K "$out.pcrsig.img"   # zero payload: /init reads an empty .pcrsig
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" "$st.pcrsigned.efi" >/dev/null || return 1
    return 0
}

# =================================================================================
# R2: base resolution — state chain -> pristine cache -> self-bootstrap
# =================================================================================
BASE=""
STATE="${ALPINE_FDE_E2E_STATE:-}"
_state_ok() {
    local dir="$1"
    [[ -f "$dir/disk.img" && -d "$dir/tpm" && -f "$dir/tpm/tpm2-00.permall" \
        && -f "$dir/harness.efi" && -f "$dir/pcrsig.img" && -f "$dir/console.log" \
        && -f "$dir/vars-enrolled.fd" && -d "$dir/keys" ]]
}
if [[ -n "$STATE" ]] && _state_ok "$STATE"; then
    MODE="state-consume"
    BASE_SRC="$STATE"
    echo "# drill base: state-consume from $STATE"
elif _state_ok "$CACHE_DIR"; then
    MODE="cache-reuse"
    BASE_SRC="$CACHE_DIR"
    echo "# drill base: cache-reuse from $CACHE_DIR"
else
    MODE="self-bootstrap"
    BASE_SRC=""
    echo "# drill base: self-bootstrap (baseline boot + host-side enroll; 1 boot)"
fi

if [[ "$MODE" != "self-bootstrap" ]]; then
    # Snapshot the shared base into OUR run dir (sibling prunes; the permall
    # copy seals to the same SRK).
    mkdir -p "$RUN/base/tpm"
    cp "$BASE_SRC/harness.efi" "$RUN/base/"
    cp "$BASE_SRC/pcrsig.img" "$RUN/base/"
    cp "$BASE_SRC/disk.img" "$RUN/base/"
    cp "$BASE_SRC/console.log" "$RUN/base/"
    cp -a "$BASE_SRC/keys" "$RUN/base/keys"
    cp "$BASE_SRC/vars-enrolled.fd" "$RUN/base/"
    cp "$BASE_SRC/tpm/tpm2-00.permall" "$RUN/base/tpm/" 2>/dev/null \
        || { echo "s90: no permall in the base — the SRK cannot be reproduced"; exit 1; }
    [[ -f "$BASE_SRC/uki-pcrsig.json" ]] && cp "$BASE_SRC/uki-pcrsig.json" "$RUN/base/"
    [[ -f "$BASE_SRC/uki-pcrsig-combined.json" ]] && cp "$BASE_SRC/uki-pcrsig-combined.json" "$RUN/base/"
    # REBUILD the payload drive from the COMBINED pcrsig json when it exists
    # (the s12/s13 lesson: the stored pcrsig.img can lag the finalized combined
    # json — the combined json is the seal-time G-B6 authority).
    if [[ -f "$RUN/base/uki-pcrsig-combined.json" ]]; then
        uki_pcrsig_disk "$RUN/base/pcrsig.img" "$RUN/base/uki-pcrsig-combined.json" || {
            echo "s90: cannot rebuild the base payload drive from the combined pcrsig"; exit 1; }
    fi
    BASE="$RUN/base"
else
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s90: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || {
        echo "s90: uki_build (bootstrap) failed"; exit 1; }
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    esp_make "$RUN_ENROLLED/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # ---- baseline boot: token-less disk -> the hook's recovery-passphrase path
    for _attempt in 1 2; do
        OVERLAY_B="$RUN_ENROLLED/disk-baseline-$_attempt.qcow2"
        overlay_create "$RUN_ENROLLED/disk.img" "$OVERLAY_B" || {
            echo "s90: overlay create failed (baseline attempt $_attempt)"; exit 1; }
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$OVERLAY_B" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 900 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
        fi
        _wedge_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT" || true
        overlay_discard "$OVERLAY_B"
        grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s90: baseline boot attempt $_attempt failed"
        ((_attempt < 2)) && { swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1; }
        rm -f "$RUN_ENROLLED/console.log"
    done
    grep -q "alpine-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s90: baseline boot did not reach UNSEALED — state unusable"; exit 1; }
    # ---- host-side finalized enrollment (the production CLI, digest-anchored)
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s90: swtpm restart (enroll) failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s90: no PCR 7 in the baseline console"; exit 1; }
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s90: no enter-initrd d11 prediction from the build"; exit 1; }
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    EFIVARS="$RUN_ENROLLED/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || { echo "s90: production enroll-tpm FAILED"; exit 1; }
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    swtpm_stop "$RUN_ENROLLED/tpm"
    mkdir -p "$RUN/base"
    cp "$RUN_ENROLLED/harness.efi" "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/disk.img" \
       "$RUN_ENROLLED/console.log" "$RUN_ENROLLED/vars-enrolled.fd" \
       "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" "$RUN/base/"
    cp -a "$RUN_ENROLLED/keys" "$RUN/base/keys"
    mkdir -p "$RUN/base/tpm"
    cp "$RUN_ENROLLED/tpm/tpm2-00.permall" "$RUN/base/tpm/"
    BASE="$RUN/base"
fi

[[ -f "$BASE/uki-pcrsig.json" ]] || {
    echo "s90: the base carries no uki-pcrsig.json (leg2/leg5 compose over it)"; exit 1; }
D7_ENROLLED=$(pcr_of "$BASE/console.log" 7)
[[ -n "$D7_ENROLLED" ]] || { echo "s90: the base console carries no PCR 7 print"; exit 1; }
PCR11_ENROLLED=$(pcr_of "$BASE/console.log" 11)
[[ -n "$PCR11_ENROLLED" ]] || { echo "s90: the base console carries no PCR 11 print"; exit 1; }

# --- shared leg fixtures -----------------------------------------------------------
# the ENROLLED release UKI's ESP (legs 1, 4, 5, 6); variant legs (2, 3) build
# their own ESPs around their variant UKIs
mkdir -p "$RUN/fix"
cp "$BASE/harness.efi" "$RUN/fix/harness.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/fix/harness.efi") + 1048575) / 1048576 ))
esp_make "$RUN/fix/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/fix/harness.efi" || exit 1
# the CLEAN payload drive (legs 1, 2 ships it STALE-on-purpose, 4, 6)
cp "$BASE/pcrsig.img" "$RUN/fix/pcrsig.img"
# leg-1 drift vars: the enrolled vars + a dbx update (s12/s15's idiom) —
# SecureBoot stays 1, the firmware measures a NEW PCR 7
cp "$BASE/vars-enrolled.fd" "$RUN/fix/vars-drifted.fd"
assert_rc "leg1: virt-fw-vars dbx += throwaway cert (SB stays ON, PCR 7 will drift)" 0 \
    virt-fw-vars -i "$RUN/fix/vars-drifted.fd" -o "$RUN/fix/vars-drifted.fd" \
        --add-dbx-cert "$ALPINE_FDE_TEST_GUID" "$BASE/keys/KEK.crt"
# leg-6 SB-off vars: stock vars copy (no PK, SecureBoot off)
keys_vars_unenrolled "$BASE/keys" "$RUN/fix/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/fix/vars-unenrolled.fd" SecureBootEnable)" "ON"

# =================================================================================
# leg1-drift — SB-on PCR 7 drift -> PolicyPCR refusal -> 3-strike (s12 boot B)
# =================================================================================
echo "# ==== leg1-drift: dbx-drifted vars (SB stays on), 3 wrong passphrases ===="
DRILL_LEG_FEED=3strike _boot_leg leg1-drift overlay "" "$RUN/fix/esp.img" \
    "$RUN/fix/vars-drifted.fd" "$RUN/fix/pcrsig.img"
LOG=$(cat "$RUN/console-leg1-drift.log")
D7_LEG1=$(pcr_of "$RUN/console-leg1-drift.log" 7)
assert_contains "[leg1] init ran (the guard PASSED — SB on, verified boot)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[leg1] TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
if [[ -n "$D7_LEG1" ]]; then
    _assert_result ok "[leg1] PCR 7 printed by the boot (drift evidence exists)" ""
else
    _assert_result not-ok "[leg1] PCR 7 printed by the boot (drift evidence exists)" "no alpine-fde-pcr sha256:7 line in console"
fi
assert_ne "[leg1] PCR 7 drifted vs the enrolled boot (the dbx update was measured)" \
    "$D7_ENROLLED" "${D7_LEG1:-}"
assert_contains "[leg1] hook ran the enter-initrd extend (the guard let the boot proceed)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[leg1] hook discovered the {7,11} token (still valid LUKS2 metadata)" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "[leg1] hook seal refusal on the stale PCR 7 term (the drift, not the signature)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
assert_not_contains "[leg1] the I3 gate passed (the signature is NOT the defect)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
_refusal_line_before_first_prompt leg1-drift "$(sentinel_of unseal_seal_refused)"
_assert_fed leg1-drift
_assert_refusal_tail leg1-drift

# =================================================================================
# leg2-loader-opt — tampered-cmdline UKI + STALE clean payload -> refusal (s07)
# =================================================================================
echo "# ==== leg2-loader-opt: release-signed UKI variant, cmdline + 1 word, stale payload ===="
TAMPER_WORD="alpine-fde-loader-tamper"
uki_build "$RUN" "$BASE/keys" "$RUN/fix/harness-tampered.efi" "$TAMPER_WORD" || {
    echo "s90: uki_build (tampered cmdline) failed"; exit 1; }
assert_rc "leg2: tampered-cmdline UKI is SB-valid (signed with the release key)" 0 \
    sbverify --cert "$BASE/keys/db.crt" "$RUN/fix/harness-tampered.efi"
# the tampered UKI carries its OWN (matching) prediction — the attacker would
# ship the STALE clean one; prove the predictions diverge host-side BEFORE the
# boot (a false refusal would otherwise be indistinguishable from the tamper)
if python3 - "$RUN/uki-pcrsig.json" "$BASE/uki-pcrsig.json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
sys.exit(0 if a["sha256"][0]["pol"] != b["sha256"][0]["pol"] else 1)
PYEOF
then
    _assert_result ok "leg2: tampered prediction diverges from the shipped (clean) .pcrsig" ""
else
    _assert_result not-ok "leg2: tampered prediction diverges from the shipped (clean) .pcrsig" \
        "pol digests identical — the tamper would not drift PCR 11"
fi
UKI_MIB=$(( ($(stat -c%s "$RUN/fix/harness-tampered.efi") + 1048575) / 1048576 ))
esp_make "$RUN/fix/esp-tampered.img" $(( UKI_MIB * 2 + 8 )) "$RUN/fix/harness-tampered.efi" || exit 1
DRILL_LEG_FEED=3strike _boot_leg leg2-loader-opt overlay "" "$RUN/fix/esp-tampered.img" \
    "$BASE/vars-enrolled.fd" "$RUN/fix/pcrsig.img"
LOG=$(cat "$RUN/console-leg2-loader-opt.log")
PCR11_LEG2=$(pcr_of "$RUN/console-leg2-loader-opt.log" 11)
assert_contains "[leg2] init ran (UKI started via the tampered boot entry)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[leg2] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[leg2] hook discovered the {7,11} token (still valid LUKS2 metadata)" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
if grep -aqE 'alpine-fde-cmdline2? .*alpine-fde-loader-tamper' "$RUN/console-leg2-loader-opt.log" 2>/dev/null; then
    _assert_result ok "leg2: tamper word reached the kernel (stub measured the effective cmdline)" ""
else
    _assert_result not-ok "leg2: tamper word reached the kernel (stub measured the effective cmdline)" \
        "no whole alpine-fde-cmdline line carries the tamper word"
fi
assert_ne "[leg2] PCR 11 drifted (stub measured the tampered cmdline)" \
    "$PCR11_ENROLLED" "${PCR11_LEG2:-}"
assert_contains "[leg2] unseal refused (drifted PCR 11 matches NO signed .pcrsig entry)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
_refusal_line_before_first_prompt leg2-loader-opt "$(sentinel_of unseal_seal_refused)"
_assert_fed leg2-loader-opt
_assert_refusal_tail leg2-loader-opt

# =================================================================================
# leg3-nopcrsig — UKI built WITHOUT the PCR-signing step (s03 flavor 1)
# =================================================================================
echo "# ==== leg3-nopcrsig: release-signed UKI with NO .pcrsig section ===="
_step_guest_tree() {
    uki_guest_tree "$RUN/guest-tree" || { echo "s90: uki_guest_tree failed"; exit 1; }
    if [[ ! -d "$RUN/guest-tree/modules" ]]; then
        mkdir -p "$RUN/guest-tree/modules"
        local _mod _src
        for _mod in $UKI_MODULES; do
            _src=$(find "$RUN/guest-tree/modules-tree" -name "$_mod.ko.xz" 2>/dev/null | head -1)
            if [[ -n "$_src" ]]; then
                xz -dc "$_src" >"$RUN/guest-tree/modules/$_mod.ko"
            fi
        done
    fi
}
_step_guest_tree
_vuki_build_no_pcrsig "$RUN/stage-nopcrsig" "$RUN/guest-tree" "$BASE/keys" \
    "$RUN/fix/harness-nopcrsig.efi" || { echo "s90: nopcrsig variant build failed"; exit 1; }
SEC63=$(objdump -h "$RUN/fix/harness-nopcrsig.efi" | awk '{print $2}')
assert_not_contains "leg3: the nopcrsig UKI has NO .pcrsig section (the defect under test)" "$SEC63" ".pcrsig"
assert_rc "leg3: nopcrsig UKI is sbverify-clean (the firmware WILL boot it)" 0 \
    sbverify --cert "$BASE/keys/db.crt" "$RUN/fix/harness-nopcrsig.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/fix/harness-nopcrsig.efi") + 1048575) / 1048576 ))
esp_make "$RUN/fix/esp-nopcrsig.img" $(( UKI_MIB * 2 + 8 )) "$RUN/fix/harness-nopcrsig.efi" || exit 1
DRILL_LEG_FEED=3strike _boot_leg leg3-nopcrsig overlay "" "$RUN/fix/esp-nopcrsig.img" \
    "$BASE/vars-enrolled.fd" "$RUN/fix/harness-nopcrsig.efi.pcrsig.img"
LOG=$(cat "$RUN/console-leg3-nopcrsig.log")
assert_contains "[leg3] init ran (firmware booted the UKI: SB signature valid)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[leg3] pcrsig payload missing (no policy to satisfy)" "$LOG" \
    "pcrsig payload MISSING"
assert_not_contains "[leg3] no signed policy anywhere: the hook's token path never armed" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "[leg3] no unlock of any kind" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg3] no recovery unlock (wrong answers only)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
_assert_fed leg3-nopcrsig
_assert_refusal_tail leg3-nopcrsig

# =================================================================================
# leg4-wiped — standing enrollment wiped host-side; no self-heal (I6) (s03 f2)
# =================================================================================
echo "# ==== leg4-wiped: token + keyslots removed host-side (raw disk copy) ===="
cp "$BASE/disk.img" "$RUN/leg4-disk.img"
_host_wipe_enrollment "$RUN/leg4-disk.img" || { echo "s90: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/leg4-disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "leg4: token removed from LUKS2 metadata" "0" "$NTOK"
KSLOTS=$(disk_metadata "$RUN/leg4-disk.img" | jq -c '.keyslots | keys')
assert_eq "leg4: only the slot-0 passphrase remains" '["0"]' "$KSLOTS"
DRILL_LEG_FEED=3strike _boot_leg leg4-wiped raw "$RUN/leg4-disk.img" "$RUN/fix/esp.img" \
    "$BASE/vars-enrolled.fd" "$RUN/fix/pcrsig.img"
LOG=$(cat "$RUN/console-leg4-wiped.log")
assert_contains "[leg4] init ran (still boots)" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[leg4] hook ran the enter-initrd extend (complete .pcrsig + key material)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[leg4] no token found on any crypttab member (wiped enrollment, no self-heal)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_not_contains "[leg4] no token policy session ever armed" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "[leg4] no unlock of any kind" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg4] no recovery unlock (wrong answers only)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
_assert_fed leg4-wiped
_assert_refusal_tail leg4-wiped
rm -f "$RUN/leg4-disk.img"   # the mutated copy is dead weight after its boot

# =================================================================================
# leg5-foreign-sig — .pcrsig re-signed by a FOREIGN key -> I3 gate refusal (s18)
# =================================================================================
echo "# ==== leg5-foreign-sig: same pol bytes, every signature moved to a foreign key ===="
openssl genrsa -out "$RUN/fix/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/fix/foreign.key" -pubout -out "$RUN/fix/foreign.pub" 2>/dev/null
assert_rc "leg5: foreign key is NOT the release key (distinct key material)" 1 \
    cmp -s "$RUN/fix/foreign.pub" "$BASE/keys/release.pub"
# _forge_foreign over the ENROLLED combined json: same pol entries, EVERY sig
# re-signed by the foreign key (the value is right, the SIGNER is wrong)
FOR_JSON="$RUN/fix/pcrsig-foreign.json"
cp "$BASE/uki-pcrsig-combined.json" "$FOR_JSON"
N_ENTRIES=$(jq '.sha256 | length' "$FOR_JSON")
for ((e = 0; e < N_ENTRIES; e++)); do
    jq -r ".sha256[$e].pol" "$FOR_JSON" | xxd -r -p >"$RUN/fix/pol.bin"
    openssl dgst -sha256 -sign "$RUN/fix/foreign.key" -out "$RUN/fix/pol.sig" "$RUN/fix/pol.bin"
    sig=$(openssl base64 -A -in "$RUN/fix/pol.sig")
    jq --arg sig "$sig" ".sha256[$e].sig = \$sig" "$FOR_JSON" >"$FOR_JSON.tmp"
    mv "$FOR_JSON.tmp" "$FOR_JSON"
done
assert_eq "leg5: forged .pcrsig keeps the SAME pol entries (only the signer moved)" \
    "$(jq -c '[.sha256[].pol]' "$BASE/uki-pcrsig-combined.json")" "$(jq -c '[.sha256[].pol]' "$FOR_JSON")"
# the hook-side verification recipe, host-side (the s18 idiom): release.pub
# verifies the release sig over pol, and REFUSES the foreign sig over the SAME pol
_sig_verifies() {
    local json="$1" e="$2" pub="$3"
    jq -r ".sha256[$e].pol" "$json" | xxd -r -p >"$RUN/fix/vpol.bin"
    jq -r ".sha256[$e].sig" "$json" | openssl base64 -d -A >"$RUN/fix/vpol.sig" 2>/dev/null
    openssl dgst -sha256 -verify "$pub" -signature "$RUN/fix/vpol.sig" "$RUN/fix/vpol.bin" >/dev/null 2>&1
}
assert_rc "leg5: positive control [0]: release.pub verifies the RELEASE sig over pol" 0 \
    _sig_verifies "$BASE/uki-pcrsig-combined.json" 0 "$BASE/keys/release.pub"
assert_rc "leg5: NEGATIVE control [0]: release.pub REFUSES the foreign sig over the same pol" 1 \
    _sig_verifies "$FOR_JSON" 0 "$BASE/keys/release.pub"
assert_rc "leg5: sanity [0]: foreign.pub verifies the foreign sig (well-formed, foreign-signed)" 0 \
    _sig_verifies "$FOR_JSON" 0 "$RUN/fix/foreign.pub"
uki_pcrsig_disk "$RUN/fix/pcrsig-foreign.img" "$FOR_JSON" || exit 1
DRILL_LEG_FEED=3strike _boot_leg leg5-foreign-sig overlay "" "$RUN/fix/esp.img" \
    "$BASE/vars-enrolled.fd" "$RUN/fix/pcrsig-foreign.img"
LOG=$(cat "$RUN/console-leg5-foreign-sig.log")
D7_LEG5=$(pcr_of "$RUN/console-leg5-foreign-sig.log" 7)
assert_contains "[leg5] init ran (firmware booted our release signature — SB saw no tamper)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[leg5] TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
assert_contains "[leg5] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[leg5] hook discovered the token (selection: 7,11])" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_eq "[leg5] PCR 7 unchanged vs the enrolled boot (no drift confound — only the drive moved)" \
    "$D7_ENROLLED" "${D7_LEG5:-}"
assert_contains "[leg5] hook REFUSED the forgery at the I3 openssl gate (BEFORE any TPM session)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
_refusal_line_before_first_prompt leg5-foreign-sig "$(sentinel_of unseal_sig_refused)"
_assert_fed leg5-foreign-sig
_assert_refusal_tail leg5-foreign-sig

# =================================================================================
# leg6-sboff-da — SB-off vars -> the ADR-20 pre-unseal guard blocks BEFORE any
# TPM op; the DA-locked TPM is drilled host-side (s05 + s09 + s12 boot A)
# =================================================================================
echo "# ==== leg6-sboff-da: SB-off vars + DA-locked TPM -> the guard blocks ===="
# G-T15 arming: "other tooling" locks the TPM out BEFORE the boot; the
# enforcement probe is positive before the boot and must STAY positive after
# it (the guard-blocked guest never reached a single TPM op — it consumed
# nothing, changed nothing).
swtpm_ensure "$BASE/tpm" || { echo "s90: swtpm not serving (DA arming)"; exit 1; }
swtpm_da_lockout "$BASE/tpm" || {
    echo "s90: DA lockout did not arm/engage — scenario precondition failed"; exit 1; }
DA_BEFORE=$(swtpm_da_state "$BASE/tpm")
assert_rc "leg6: DA locked: enforcement probe positive BEFORE the boot" 0 \
    swtpm_da_locked_probe "$BASE/tpm"
echo "# leg6 DA state before boot: $DA_BEFORE (counter readout quirk: see s09)"
DRILL_LEG_FEED=guard _boot_leg leg6-sboff-da overlay "" "$RUN/fix/esp.img" \
    "$RUN/fix/vars-unenrolled.fd" "$RUN/fix/pcrsig.img"
LOG=$(cat "$RUN/console-leg6-sboff-da.log")
D7_LEG6=$(pcr_of "$RUN/console-leg6-sboff-da.log" 7)
PCR11_LEG6=$(pcr_of "$RUN/console-leg6-sboff-da.log" 11)
ZERO=$(printf '0%.0s' {1..64})
assert_contains "[leg6] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[leg6] TPM char device appeared" "$LOG" "$(sentinel_of harness_tpm_present)"
if [[ -n "$D7_LEG6" && "$D7_LEG6" != "$ZERO" ]]; then
    _assert_result ok "[leg6] PCR 7 non-zero (SB-off state measured by firmware)" ""
else
    _assert_result not-ok "[leg6] PCR 7 non-zero (SB-off state measured by firmware)" "PCR7=${D7_LEG6:-absent}"
fi
if [[ -n "$D7_LEG6" ]]; then
    _assert_result ok "[leg6] PCR 7 printed while SB off (SB-off state is measured too)" ""
else
    _assert_result not-ok "[leg6] PCR 7 printed while SB off (SB-off state is measured too)" \
        "no alpine-fde-pcr sha256:7 line in console"
fi
assert_ne "[leg6] PCR 7 drifted vs enrolled boot (7=${D7_LEG6:-?})" "$D7_ENROLLED" "${D7_LEG6:-}"
assert_eq "[leg6] PCR 11 unchanged (the guard blocked before ANY measurement work)" \
    "$PCR11_ENROLLED" "${PCR11_LEG6:-}"
# the guard fired BEFORE any TPM work — no enter-initrd extend, no token, no prompt
_guard_line=$(grep -nm1 -F "$(sentinel_of unseal_sb_guard)" "$RUN/console-leg6-sboff-da.log" 2>/dev/null | cut -d: -f1)
_ext_line=$(grep -nm1 -F "$(sentinel_of unseal_pcrextend_ok)" "$RUN/console-leg6-sboff-da.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_guard_line:-}" && -z "${_ext_line:-}" ]]; then
    _assert_result ok "[leg6] the guard fired BEFORE any TPM work (no enter-initrd extend, line $_guard_line)" ""
else
    _assert_result not-ok "[leg6] the guard fired BEFORE any TPM work" \
        "guard=$_guard_line pcrextend=$_ext_line"
fi
assert_contains "[leg6] guard: the blocking refusal names the pre-unseal guard" "$LOG" \
    "$(sentinel_of unseal_sb_guard)"
assert_contains "[leg6] guard: the refusal carries the LIVE secureboot=0 reading" "$LOG" "secureboot=0"
assert_contains "[leg6] guard: Press-Enter confirmation prompt" "$LOG" \
    "$(sentinel_of unseal_sb_guard_enter)"
assert_contains "[leg6] guard: OsIndications boot-to-firmware-setup requested" "$LOG" \
    "$(sentinel_of unseal_sb_guard_osind)"
assert_contains "[leg6] guard: reboot into the firmware setup" "$LOG" \
    "$(sentinel_of unseal_sb_guard_reboot)"
assert_not_contains "[leg6] NO enter-initrd extend (the guard precedes §8.2 step 2)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_not_contains "[leg6] NO token discovery (the container is NEVER unsealed with SB off)" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "[leg6] NO recovery-passphrase prompt (the fallback is RETRACTED under SB off)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[leg6] NO 3-strike path (nothing to strike — the guard blocked first)" "$LOG" \
    "$(sentinel_of unseal_3strike)"
assert_not_contains "[leg6] NO fail-closed poweroff (the terminal action is the REBOOT)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[leg6] never unlocked via the TPM token" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg6] never unlocked via the recovery passphrase" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[leg6] never UNSEALED (harness sentinel)" "$LOG" \
    "$(sentinel_of harness_unsealed)"
assert_not_contains "[leg6] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# the scenario hard-killed the parked guest (BY PID)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[leg6] guest torn down (qemu_kill BY PID after the guard sentinel)" ""
else
    _assert_result not-ok "[leg6] guest torn down (qemu_kill BY PID after the guard sentinel)" \
        "qemu still running or qemu.pid missing"
fi
# G-T15: the boot consumed no DA budget (§7.1) — the lockout we armed must
# STILL be enforced after the boot + fixture restart
swtpm_ensure "$BASE/tpm" || { echo "s90: swtpm not serving (G-T15 probe)"; exit 1; }
DA_AFTER=$(swtpm_da_state "$BASE/tpm")
assert_eq "leg6: G-T15 DA budget readout unchanged across the guest boot (quirked readout)" \
    "$DA_BEFORE" "$DA_AFTER"
assert_rc "leg6: G-T15 lockout STILL enforced after the boot (guest consumed nothing, changed nothing)" 0 \
    swtpm_da_locked_probe "$BASE/tpm"

# --- wrap up -----------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-nopcrsig" "$RUN/fix/pol.bin" "$RUN/fix/pol.sig" \
    "$RUN/fix/vpol.bin" "$RUN/fix/vpol.sig"
kill "$REFRESHER" 2>/dev/null
echo "# drill verdict: 6 fail-closed legs over ONE enrolled base (mode=$MODE, wall $((SECONDS - T0)) s):"
echo "#   drift / loader-options / nopcrsig / wiped-enrollment / foreign-pcrsig -> 3-strike poweroff;"
echo "#   SB-off (+ DA-locked TPM) -> the pre-unseal guard blocks; NEVER unlocked on any leg."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s90-negative-drill: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s90-negative-drill: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
