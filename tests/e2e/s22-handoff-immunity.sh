#!/usr/bin/env bash
# tests/e2e/s22-handoff-immunity.sh — §12 S-22 (provisioning-escrow-window
# immunity) + the §2.1 T2c window rows, on the ADR-21 lifecycle (commit
# 0b4664b: zero-prompt install, the ×2 set ceremony at first boot).
#
# THE WINDOW UNDER TEST (ADR-21 — replaces the abolished pre-ADR-21
# provisional window): install leaves the handoff with NO keyslot 0 (it stays
# FREE until the first-boot ×2 ceremony) and the volume keys escrowed on the
# ESP:
#   keyslot 0 = FREE (the ×2 ceremony enrolls it at first boot — never at
#               install; the old "Stage-1 keyslot 0 recovery passphrase" is
#               GONE from the window)
#   keyslot 1 = a RANDOM VOLUME PASSPHRASE (base64-of-48-raw-bytes text,
#               ADR-19 framing) carrying the PROVISIONAL {PCR 11}
#               systemd-tpm2 token (Mechanism B, release-key-signed)
#   keyslot 2 = the TEMPORARY ephemeral install key (purged at completion)
#   ESP:      alpine-fde-provision/volume-keys.json (per-member
#               {target,uuid,pass_b64} of the keyslot-1 passphrase) + the
#               empty REQUEST marker written LAST (hooks/mkinitfs/
#               alpine-fde-unseal.sh step 5, the ADR-21 consume (a)-(h))
# The immunity claim across the window:
#   * a foreign/rebuilt UKI — and any UKI whose .pcrsig set does not cover the
#     standing token's PCR selection — is REFUSED (the hook's I3
#     token/signature gate: "token/signature verification refused");
#   * a tampered-cmdline variant (the s07 compromised-signer primitive) that
#     DOES carry a self-consistent signed entry is still refused — the sealed
#     policy digest misses its measured PCR state ("the TPM refused the
#     sealed blob");
#   * the window has NO recovery fallback: keyslot 0 does not exist yet, so
#     the armed recovery loop cannot open the volume either — every refused
#     boot ends in the bounded 3-strike fail-closed poweroff;
#   * the escrow stands untouched through every refused boot (a foreign boot
#     never consumes it — the consume runs only on OUR hook, and on its
#     success path only);
#   * the FIRST BOOT of the exact installed UKI is the only way in (zero
#     console input), and after the ceremony + completion the {PCR 7,
#     PCR 11} binding applies UNCHANGED (the same two refusal classes hold
#     post-finalization).
#
# Legs:
#   fixture (host): the ADR-21 install shape against the file-backed LUKS2
#           image with the REAL seal library + the fixture swtpm (the
#           tests/unit/keys_rsa3072_chain.sh seal_provisional recipe):
#           seal_provisional -> keyslot 1 + the provisional {11} token (the
#           entry d11-anchored to the build's enter-initrd prediction);
#           luksAddKey keyslot 2 (ephemeral); luksKillSlot 0 (the FROM-INSTALL
#           keyslot dies — ADR-21 leaves keyslot 0 FREE); the escrow onto the
#           LABELED (EFI) installed ESP (volume-keys.json FIRST, the REQUEST
#           marker LAST — the boot-#1 hook consumes only a REQUEST-marked
#           escrow); the pending baseline + /etc/crypttab + plaintext
#           release.pem/release.pub cli-state; the {7,11}-ONLY stale payload
#           for leg 1.
#   leg 1 (window immunity — foreign UKI): the tampered-cmdline VARIANT booted
#           from its OWN unlabeled ESP with a payload carrying ONLY a {7,11}
#           entry: the standing {11} token's selection has NO matching entry
#           -> the I3 signature gate refuses BEFORE any TPM session. The
#           recovery loop arms (and is DEAD — no keyslot 0 exists in the
#           window): 3 wrong feeds -> 3-strike fail-closed poweroff. Host:
#           metadata unchanged, escrow intact. The boot's unlabeled ESP also
#           pins the LOUD escrow-absent detect warn (the R640 real-hardware
#           fix, eb2df91 — a missed detect is never silent again).
#   leg 2 (window immunity — tampered cmdline): the same variant, NO payload
#           drive: the stub's OWN .pcrsig (valid, self-consistent, release-
#           signed over ITS tampered prediction) passes the signature gate ->
#           the TPM refuses the digest (seal_refused). 3 wrong feeds ->
#           3-strike poweroff. Host: metadata unchanged, escrow intact.
#   leg 3 (the first boot): the EXACT installed UKI against the LABELED
#           installed ESP (escrow standing): the hook engages the ADR-21
#           consume. ZERO console input either way (see the fidelity note on
#           the consume gap). The provisional seal still guards the window
#           and opens the volume. Host: the escrow SURVIVED the boot (the
#           retention semantic: a consume that did not complete retains the
#           escrow), metadata unchanged.
#   host  (the ceremony mirror — step (g)+(h) stand-in, see fidelity notes):
#           the recovery passphrase is enrolled at keyslot 0 (argon2id,
#           authorized by the escrowed keyslot-1 credential — the scenario
#           consumes its own escrow exactly as the hook would), then the
#           escrow is DELETED from the installed ESP.
#   completion (host): the Stage-2 chain the first boot triggers,
#           fin_service_main DIRECT-DRIVE (the harness has no OpenRC): the
#           ground-truth gate reads provisional ([11] + the ephemeral
#           keyslot), the userspace re-unseal of the provisional token
#           authorizes the chain (never a credential env), audit --init
#           finalizes the pending baseline from the live register, the
#           ephemeral keyslot 2 is purged, the token upgrades to Mechanism B
#           {PCR 7, PCR 11} (release-key-signed), exactly the recovery
#           keyslot 0 remains, the ADR-8 marker stays clear. Ground truth
#           reads FINALIZED.
#   leg 4 (post-finalization immunity unchanged): the tampered variant AGAIN,
#           now carrying the VALID release-signed {7,11} entry (the
#           completion's own .pcrsig): the signature gate passes, the TPM
#           refuses the tampered PCR digest -> 3-strike fail-closed. Host:
#           the finalized shape intact (one {7,11} SIGNED token, keyslots
#           recovery + sealed, no ephemeral).
#
# Fidelity notes (documented, not silent):
#   * THE CONSUME GAP (filed against HEAD): the hook's _fdh_escrow_consume
#     marshals the live {7,11} policy through policy_hex_tobin — a
#     lib/policy.sh function that is NOT in the initrd closure (the hook
#     ships its own _fdh_hex2bin). On ANY escrow boot the consume therefore
#     dies LOUD at "cannot marshal the live policy digest", the escrow is
#     RETAINED, and the boot falls through to the standing provisional-token
#     path (which — for the EXACT installed UKI — opens zero-input). Leg 3
#     pins TODAY's observable contract (the loud marshal failure + the
#     zero-input provisional-token fallthrough + the retained escrow); when
#     the consume fix lands, flip leg 3 to the design asserts: the
#     "unlocked root ... via the provisioning escrow (real-measurement
#     {7,11} seal)" marker, the token path SKIPPED (no "token: pcrs=" line),
#     and the escrow DELETED in-guest. The ×2 ceremony (step g) and the
#     delete (step h) are likewise not yet wired into the escrowed-boot
#     dispatch (_fdh_escrow_ceremony exists unwired) — this scenario mirrors
#     both HOST-side so the post-ceremony shape (keyslot 0, no escrow) and
#     the completion chain are testable against the real lib code.
#   * The Stage-2 lane drives fin_service_main because fin_completion_steps
#     is the shared Stage 2 == Stage 3 chain by construction (lib/cmd/
#     finalize.sh); the ADR-21 consumption legs inside it (release.pem
#     encryption + chpasswd from /run/alpine-fde-provision-pass) are NOT
#     drivable in the harness — the staged-pass path is a hard /run path and
#     chpasswd is unseamed (host chpasswd would touch the DEV HOST's
#     accounts) — so the block is a documented no-op here (release.pem stays
#     plaintext; asserted) and the encryption leg stays with the integration
#     suite. fin_uki_pcrsig is stood in by a one-function override that
#     hands the REAL seal_unseal the d11-ANCHORED {11} entry — exactly the
#     pcrsign-stamped .pcrsig the installer's `kernel build` bakes into the
#     real ESP UKI (the harness ukify section is ukify-native and
#     anchor-less, and PE section surgery cannot grow .pcrsig — objcopy
#     --update-section is size-capped). Every other function in the drive
#     (ground-truth gate, token export, seal_unseal, audit --init, purge,
#     upgrade, marker clear) is the REAL product code.
#   * The provisional enrollment is HOST-side, not in-guest (the installer's
#     step-6 recipe against the fixture swtpm — the uki_host_enroll_finalized
#     precedent). The fixture swtpm holds NO booted register at seal time:
#     the Mechanism B seal is digest-anchored (the G-B6 gate is a pure data
#     check over the entry's d11 anchor; no live PCR read at seal time), and
#     the in-guest unseal re-derives PCRs from the same persistent swtpm
#     state dir (same SRK). Leg 3's G-T13 assert (postphase == prediction)
#     retroactively proves the seal bound the right value.
#   * The refusal legs boot the variant from its OWN ESP image (the harness
#     ESP is a per-boot fixture input, as in the pre-port s22): the escrow on
#     the INSTALLED ESP is consequently never visible to them — the
#     real-world analogue is foreign media, or the detect-failing class the
#     loud warn pins. Leg 1 additionally asserts that loud warn (the eb2df91
#     regression pin).
#   * The window fixture carries an ephemeral keyslot 2 so the completion's
#     purge leg purges a REAL slot (the §7.2 install shape), and keyslot 0 is
#     KILLED host-side after the provisional seal — the ADR-21 from-install
#     shape is asserted (keyslots {1,2}, token {11} on slot 1, NO keyslot 0)
#     before any boot.
#   * The initrd module pin is extended scenario-locally (fat vfat nls_cp437)
#     so the hook's in-guest escrow detect can MOUNT the labeled ESP — the
#     stock UKI_MODULES list carries no vfat (the payload drive is read raw).
#   * §12 negatives on every boot: no systemd-cryptenroll sentinel (Mechanism
#     B never invokes it), no emergency shell (emergency_forbidden); prompt
#     counting is the item-24a candidate-set over BOTH hook textures.

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
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH
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

# the escrow detect MOUNTS the labeled ESP in-guest (leg 3) — the stock
# UKI_MODULES pin carries no vfat (the payload drive is read raw), so the
# scenario extends the pin locally: the uki_build bake reads this variable at
# call time and /init insmods the list in order (nls_cp437 before fat before
# vfat — no modprobe exists in the initrd to resolve dependencies lazily)
UKI_MODULES="$UKI_MODULES nls_cp437 fat vfat"

export QEMU_TIMEOUT="${ALPINE_FDE_S22_TIMEOUT:-1200}"

# §13-floor-OK recovery passphrase for the ceremony mirror (the fixture's
# well-known slot-0 passphrase is floor-BLOCKLISTED; ADR-21 has no keyslot 0
# to rekey — the mirror ENROLLS slot 0 with this value, authorized by the
# escrowed keyslot-1 credential, exactly the hook's step (g))
S22_RECOVERY='fde-s22-recovery-7c5d31'

# --- hardening: bounded stages, loud failures, overall budget --------------------
# Calibrated 2026-09-24: the registry's outer SCENARIO_BUDGET is 1500 s (MD-05b)
# — an internal watchdog above the outer cap can never fire, so a hung s22
# dies as an anonymous outer rc=124 instead of this scenario's loud
# STAGE-TIMEOUT-OR-HANG. The ADR-21 port runs 4 boots + 2 UKI builds + the
# host-side seal/ceremony-mirror/service-completion (~700-1000 s observed
# class); 1350 s keeps margin inside the outer budget.
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
    # Wave-2 2b overlay discipline: the stage subshell and its watchdog must
    # NOT inherit the overlay lock fds (OVERLAY_LOCK_FDS). The watchdog
    # subshell is killed after the stage, but its `sleep` child survives as
    # an ORPHAN holding the inherited LOCK_SH copy on the base image — a
    # later host-side EXCLUSIVE op (cryptsetup luksAddKey / token import)
    # then deadlocks until the sleep expires (live 2026-09-25: boot 1's
    # token_add_keyslot stalled ~19 min behind an orphaned `sleep 1260`).
    # The MAIN shell alone carries the overlay lock — it holds the fds until
    # overlay_discard — so the forked copies are redundant: close them
    # first thing in both subshells.
    local _fd _close=""
    for _fd in ${OVERLAY_LOCK_FDS[@]:-}; do
        [[ -n "$_fd" ]] && _close="$_close exec ${_fd}<&-;"
    done
    ( eval "$_close" 2>/dev/null; "$@" ) &
    local pid=$! rc wrc
    # watchdog: fire ONLY if the stage's process is still the SAME one —
    # after a scenario/session death this subshell outlives its parent, pids
    # get recycled, and a bare `kill -9 -$pid` would murder an INNOCENT new
    # process group (a fresh qemu spawn) hours later (repro 2026-09-24: three
    # consecutive first boots lost qemu instantly to yesterday's orphans).
    # Identity = /proc/<pid>/stat field 22 (process start time): a recycled
    # pid has a different start time and the kill is skipped.
    local _st0; _st0=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null)
    ( eval "$_close" 2>/dev/null; sleep "$tmo"; \
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
run_stage_rc() { run_stage_impl 1 "$@"; }
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
# silent pre-BdsDxe hang and the degraded-measurement boots. The refusal
# legs' PCR-refusal controls (leg 2/4: the tampered digest must MISS the
# sealed policy) depend on PCR 11 being exactly the boot's own stub extend,
# so the zero state is ASSERTED here, not assumed. No boot here needs the
# booted values carried ACROSS boots host-side except the completion leg,
# which re-seeds them explicitly from the leg-3 console facts (the
# the completion anchors the provisional token to the fixture-reachable
# V_SEED register (the fidelity note at the pcrsig-11 composition — the
# _reseed_from_console helper was RETIRED, see below).
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
    cp "$vars" "$bdir/vars.fd"
    # Wave-2 2b: every boot runs a fresh QCOW2 OVERLAY over the $bimg base
    # (decision rule 1 — every boot here is read-mostly or refused: the
    # refusal legs die fail-closed, the first boot's in-guest header
    # mutations (the consume's self-seal, when the fix lands) are
    # overlay-ephemeral by design, and the scenario's persistent chain runs
    # through the RAW base: the host-side ceremony mirror + the service
    # completion cryptsetup/finalize $RUN/disk.img directly, which is also
    # why the boot's overlay MUST be discarded (lock released) before those
    # host legs).
    overlay_create "$bimg" "$bdir/disk.qcow2" || {
        echo "s22: overlay create failed ($(basename "$bdir"))"; exit 1; }
    _reanchor_tpm "$RUN/tpm"
    CURRENT_QEMU_DIR="$bdir"
    if [[ -n "$payload" ]]; then
        run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$esp" \
            "$bdir/disk.qcow2" "$bdir/vars.fd" "$RUN/tpm" "$payload"
    else
        run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$esp" \
            "$bdir/disk.qcow2" "$bdir/vars.fd" "$RUN/tpm"
    fi
    _qemu_alive "$bdir"
    _rearm_trap
    # EARLY degradation gate (the s18 lesson, live-evidenced 2026-09-22): the
    # hook prints the live PCRs before anything else it does, and a boot whose
    # PCR 0 is off lost firmware measurements to TPM command timeouts under
    # host load (the EFI stub then logs "Failed to measure data for event").
    # Such a boot would fail its own control — the refusal legs' TPM-refusal
    # asserts NEED a faithful PCR 11 — so it is discarded and re-run ONCE
    # per boot dir on the re-anchored register. The per-boot vars copy and a
    # FRESH QCOW2 overlay are re-made by the recursive call; the PIN is
    # per-UKI (PCR 0 measures the firmware, identical across boots of the
    # same image).
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
            overlay_discard "$bdir/disk.qcow2"   # the discarded attempt's overlay is ephemeral
            _boot_hook "$@"   # the recursive call re-creates a FRESH overlay over the same base
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

# _refuse_3strike <boot-dir> — the refusal legs' feeding choreography: the
# recovery loop arms after the refusal (and is DEAD in the window — no
# keyslot 0 exists to open); feed 3 WRONG passphrases prompt-synchronized
# (uki_wait_hook_prompt — the hook's read has NO timeout, so feeding must
# track the prompt events; the count is the item-24a candidate set over BOTH
# hook textures), then wait for the bounded 3-strike fail-closed poweroff.
# 600 s per prompt: the boots crawl under background tenants (live-seen
# 2026-09-22 — prompts past the 300 s mark).
_refuse_3strike() {
    local bdir="$1" n
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 600 "$bdir"; then
            feed_line "$bdir/serial.sock" "alpine-fde-wrong-passphrase-$n"
        else
            _hang_fail CONSOLE-WAIT "refusal recovery prompt $n ($(basename "$bdir"))" "never appeared"
        fi
    done
    wait_console "$bdir" "$(sentinel_of unseal_poweroff)" 300
    run_stage "qemu_wait:$(basename "$bdir")" "$((QEMU_TIMEOUT + 60))" \
        qemu_wait "$bdir" "$QEMU_TIMEOUT"
    overlay_discard "$bdir/disk.qcow2"   # the refusal boot's overlay is ephemeral — the
    CURRENT_QEMU_DIR=""                  # host-side base checks below target the RAW base
}

# _reseed_from_console — RETIRED (s22f11..f17, 2026-10-05): extending from
# zero can never reproduce the guest's register — the pre-phase PCR11 is a
# multi-event measured chain with no known pre-image, and the swtpm exits at
# the guest's chardev EOF (no mid-boot ctrl window either: the ctrl plane is
# qemu's). The completion instead anchors the provisional {11} token to
# V_SEED (the fixture-reachable phase register) at the pcrsig-11 composition
# and replays ONE extend — see the fidelity note there.

# pcr_of <console.log> <pcr> — the harness PCR-print parser (the early
# degradation gate in _boot_hook reads the hook's pre-token PCR line with it)
pcr_of() { grep -oE "alpine-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }

# _pcrread <dir> <pcr> — local PCR reader for the seal-time gates. The
# fixture's swtpm_pcrread anchors on the single-digit rendering ("0 : 0x…");
# tpm2-tools prints TWO-digit PCRs width-aligned ("11: 0x…" — no space before
# the colon), so the fixture function returns EMPTY for PCR 11 (live-verified
# 2026-09-22 against tpm2-tools 5.8) and every seal gate would read a drifted
# (empty) register. Parse both renderings here instead (tests/lib fix pending
# — reported to the harness owners).
_pcrread() {
    tpm2_pcrread -T "$(_swtpm_tcti_for "$1")" "sha256:$2" \
        | awk -v p="$2" '{ gsub(/:/, "", $1); if ($1 == p) { v = $NF; sub(/^0x/, "", v); print tolower(v) } }'
}

# ============================================================================
# Fixture: keys + vars + the LUKS2 container in the ADR-21 FROM-INSTALL shape
# (keyslot 1 = the provisional-token volume pass, keyslot 2 = the ephemeral
# install key, keyslot 0 FREE) + the escrow on the LABELED installed ESP
# ============================================================================
keys_create "$RUN/keys" || { echo "s22: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
assert_contains "fixture: enrolled vars SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
run_stage disk_make_luks 120 disk_make_luks "$RUN/disk.img" "$DISK_MIB"
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s22: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s22: empty LUKS uuid"; exit 1; }
# the FROM-INSTALL keyslot's credential (disk_make_luks enrolled the well-known
# passphrase at keyslot 0; the ADR-21 shape KILLS that slot below — the file
# authorizes the provisional keyslot add + the kill, then is scrubbed)
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"
chmod 600 "$RUN/kf-slot0"

# the build's enter-initrd PCR 11 prediction — the value the provisional seal
# binds (digest-anchored; leg 3's G-T13 assert retroactively proves the boot
# reproduced it)
#
# THE HOOK-SEAM ENV (baked into the initrd as /fde-seams, sourced by /init
# before the hook — ALL legs get it, and the consume's canonical-cmdline gate
# makes that safe: legs 1/2/4 boot the TAMPERED cmdline, the gate refuses,
# the {11} token's refusal holds; leg 3's canonical cmdline passes and the
# consume engages with the ceremony fed from the baked file — no console
# typing anywhere):
#   FDE_ESP_DEV=/dev/vda   the ESP image is qemu's FIRST drive (raw FAT,
#                          whole disk — no partition table)
#   FDE_CONSOLE_IN         the ×2 ceremony's read device = the baked file
#   /tmp/ceremony.in       S22_RECOVERY twice (set + confirm)
ALPINE_FDE_HARNESS_SEAMS=$'printf "%s\\\\n" fde-s22-recovery-7c5d31 fde-s22-recovery-7c5d31 > /tmp/ceremony.in\nexport FDE_CONSOLE_IN=/tmp/ceremony.in\nexport FDE_ESP_DEV=/dev/vda'
export ALPINE_FDE_HARNESS_SEAMS
run_stage uki_build 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi"
# capture the CANONICAL cmdline NOW: the tampered-variant build below
# overwrites $RUN/cmdline.txt with its own (the +alpine-fde-tampered form),
# and the escrow's REQUEST marker must carry the CANONICAL digest (leg 3
# boots the canonical UKI; the gate refuses the tampered one — S-22)
cp "$RUN/cmdline.txt" "$RUN/cmdline-canonical.txt"
D11_PRED=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_PRED" ]] || { echo "s22: no enter-initrd d11 prediction from the build"; exit 1; }
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make 300 esp_make "$RUN/esp.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
# the tampered variant (legs 1/2/4): ONE extra cmdline word -> a different stub
# measurement -> a different pre-unlock PCR 11 (the s07 attacker primitive)
run_stage uki_build-tampered 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-tampered.efi" "alpine-fde-tampered"
run_stage esp_make-tampered 300 esp_make "$RUN/esp-tampered.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-tampered.efi"

_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"

# ============================================================================
# HOST — the ADR-21 from-install shape (the installer's step-6 recipe + the
# ephemeral keyslot + the keyslot-0 kill), then the provisioning escrow.
# The Mechanism B seal is digest-anchored (no live register needed at seal
# time — see the fidelity notes); the fixture swtpm only hosts the seal's
# SRK, which persists in this state dir into every guest boot.
# ============================================================================
mkdir -p "$RUN/tmp"
# THE PROVISIONAL ANCHOR — the fixture-reachable register (the fidelity
# note): in production the {11} provisional token binds the real first
# boot's postphase and is unsealed IN-GUEST. The s22 completion drives the
# Stage-2 chain HOST-SIDE against the fixture swtpm — whose register after
# a restart is all-zero and reaches exactly ONE extend of the enter-initrd
# phase-word digest (the guest's pre-phase chain is multi-event and
# unreproducible by extends — s22f11..f17, byte-verified). The provisional
# token therefore anchors V_SEED = H(0 ‖ H('enter-initrd')): well-formed
# {11}-PolicyPCR, unsealable at the completion, never exercised in-guest
# (leg 3 consumes the ESCROW). The {7,11} upgrade below still anchors the
# TRUE booted values (D7_BOOT3, D11_BOOT3).
PHASE_DGST=$(printf %s "enter-initrd" | sha256sum | awk '{print $1}')
V_SEED=$(printf '%064d%s' 0 "$PHASE_DGST" | tr -d ' \n' | xxd -r -p | sha256sum | awk '{print $1}')
# the d11-anchored {11}-selection .pcrsig (the s00b/Option-A pattern): the
# REAL installer's `kernel build` bakes exactly this shape (pcrsign's
# anchored entry) into the ESP UKI; seal_provisional's G-B6 gate verifies the
# signed pol against the ENTRY'S OWN component — a pure data check
POL11=$(seal_digest_11 "$V_SEED")
printf '%s' "$POL11" | policy_hex_to_bin >"$RUN/msg11.bin"
openssl dgst -sha256 -sign "$RUN/keys/db.key" -out "$RUN/sig11.bin" "$RUN/msg11.bin" \
    || { echo "s22: {11} policy signature failed"; exit 1; }
PKFP=$(policy_pubkey_fp "$RUN/keys/release.pub")
jq -n --arg pol "$POL11" --arg sig "$(openssl base64 -A -in "$RUN/sig11.bin")" \
    --arg pkfp "$PKFP" --arg d11 "$V_SEED" \
    '{"sha256": [{"pcrs": [11], "pkfp": $pkfp, "pol": $pol, "sig": $sig, "d11": $d11}]}' >"$RUN/pcrsig-11.json"
assert_eq "S-22: the {11}-selection .pcrsig pol == seal_digest_11(fixture-reachable V_SEED), anchored" "$POL11" \
    "$(jq -r '.sha256[0].pol' "$RUN/pcrsig-11.json")"
assert_eq "S-22: the {11}-selection entry carries the d11 anchor (digest-anchored G-B6)" "$V_SEED" \
    "$(jq -r '.sha256[0].d11' "$RUN/pcrsig-11.json")"
# seal_provisional runs INLINE (never via run_stage): it stages SEAL_PASS_FILE
# and SEAL_SLOT for the caller, and a run_stage subshell would lose them
_budget_check seal-provisional
echo "# s22: stage seal-provisional (the installer's step-6 recipe, host-side)"
_PROV_TOK="$RUN/token-prov.json"
rm -f "$_PROV_TOK"
SEAL_PASS_FILE='' SEAL_SLOT=''
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
# the TEMPORARY ephemeral install key (§7.2 keyslot 2; the completion's purge
# leg purges it for real) — authorized by the token's volume-pass keyslot
printf '%s' "fde-s22-ephemeral-install-key-3f91bb" >"$RUN/kf-eph"
chmod 600 "$RUN/kf-eph"
CRYPTSETUP_BIN=$(command -v cryptsetup)
timeout 120 "$CRYPTSETUP_BIN" luksAddKey --pbkdf argon2id --pbkdf-memory 1048576 \
    --pbkdf-parallel 4 --iter-time 2000 --key-slot 2 "$RUN/disk.img" "$RUN/kf-eph" \
    --key-file "$SEAL_PASS_FILE" 2>/dev/null \
    || { echo "s22: ephemeral keyslot-2 add failed"; exit 1; }
# ADR-21: keyslot 0 stays FREE until the first-boot ×2 ceremony — the
# from-install keyslot dies HERE (the old pre-ADR-21 window kept it; the
# escrow-window immunity claim explicitly has NO recovery fallback)
if ! timeout 240 "$CRYPTSETUP_BIN" --batch-mode luksKillSlot "$RUN/disk.img" 0 \
    --key-file "$SEAL_PASS_FILE" 2>/tmp/s22-kill.err; then
    echo "s22: from-install keyslot-0 kill failed:"; cat /tmp/s22-kill.err; exit 1
fi
# THE ESCROW-WINDOW SHAPE (host asserts of record — the ADR-21 install handoff)
METAP=$(disk_metadata "$RUN/disk.img")
TOKP=$(disk_token_json "$RUN/disk.img")
assert_eq "S-22 window shape: keyslots == {1,2} (token volume pass + ephemeral; NO keyslot 0)" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$METAP")"
assert_eq "S-22 window shape: EXACTLY ONE token" "1" \
    "$(jq '[.[] | select(.type == "systemd-tpm2")] | length' <<<"$TOKP")"
assert_eq "S-22 window shape: the token binds PCR 11 ONLY (provisional)" "[11]" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKP")"
assert_eq "S-22 window shape: the token sits on keyslot 1" "1" \
    "$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKP")"
assert_contains "S-22 window shape: the token carries the release-key signature (§7.2)" "$TOKP" \
    '"tpm2-signature"'
# THE PROVISIONING ESCROW on the installed ESP (install's ADR-21 step):
# volume-keys.json written FIRST, the empty REQUEST marker LAST — the boot-#1
# hook consumes only a REQUEST-marked escrow. pass_b64 = base64(the keyslot-1
# passphrase text) — the exact convention lib/seal.sh stages (ADR-19
# framing), so the hook's base64 -d reproduces the credential verbatim.
VOL_PASS_B64=$(openssl base64 -A -in "$SEAL_PASS_FILE")
jq -nc --arg uuid "$DISK_UUID" --arg b64 "$VOL_PASS_B64" \
    '{members: [{target: "root", uuid: $uuid, pass_b64: $b64}]}' >"$RUN/volume-keys.json"
# the REQUEST marker carries the CANONICAL CMDLINE DIGEST (the escrow-window
# gate, S-22 — the install's 2026-10-03 recipe): the consume only engages for
# the boot of the exact installed cmdline; the tampered variants (legs 1/2/4)
# fail the gate and fall to the {11} token's refusal. Normalization identical
# to the hook's (/proc/cmdline side).
tr -s ' \t\n' ' ' <"$RUN/cmdline-canonical.txt" | sed 's/^ //;s/ $//' | sha256sum | awk '{print $1}' >"$RUN/REQUEST"
# the installed ESP must be LABELED EFI for the hook's by-label resolve (the
# production install's mkfs.vfat -n EFI; the harness esp_make does not label)
mlabel -i "$RUN/esp.img" ::EFI >/dev/null 2>&1 \
    || { echo "s22: cannot label the installed ESP (mlabel)"; exit 1; }
assert_eq "fixture: the installed ESP resolves by LABEL=EFI (the hook's default resolve)" \
    "$RUN/esp.img" "$(blkid -t LABEL=EFI -o device "$RUN/esp.img")"
mmd -i "$RUN/esp.img" ::/alpine-fde-provision \
    || { echo "s22: cannot stage the escrow dir on the installed ESP"; exit 1; }
mcopy -i "$RUN/esp.img" "$RUN/volume-keys.json" "::/alpine-fde-provision/volume-keys.json" \
    || { echo "s22: cannot stage volume-keys.json"; exit 1; }
mcopy -i "$RUN/esp.img" "$RUN/REQUEST" "::/alpine-fde-provision/REQUEST" \
    || { echo "s22: cannot stage the REQUEST marker"; exit 1; }
# the escrow's credential round-trip (the hook's own decode path: extract
# pass_b64 from the json, decode ONCE — the result IS the keyslot-1 credential)
mcopy -i "$RUN/esp.img" -o "::/alpine-fde-provision/volume-keys.json" "$RUN/escrow-readback.json"
assert_eq "fixture: the escrowed pass_b64 decodes to the keyslot-1 credential (the hook's decode)" \
    "$(cat "$SEAL_PASS_FILE")" "$(jq -r '.members[0].pass_b64' "$RUN/escrow-readback.json" \
        | openssl base64 -d -A)"
ESCROW_SHA=$(sha256sum "$RUN/volume-keys.json" | awk '{print $1}')
# the {7,11}-ONLY stale payload (leg 1): a finalized-FORM signature set whose
# SELECTION does not cover the standing {11} token. Composition values are
# inert for this leg — the I3 gate refuses on the SELECTION mismatch BEFORE
# any value is read (leg 1 asserts exactly that class); d7 is the zeroed
# fixture register honestly labeled as never-measured.
POL711_STALE=$(policy_digest "0000000000000000000000000000000000000000000000000000000000000000" "$D11_PRED")
printf '%s' "$POL711_STALE" | policy_hex_to_bin >"$RUN/msg711.bin"
openssl dgst -sha256 -sign "$RUN/keys/db.key" -out "$RUN/sig711.bin" "$RUN/msg711.bin" \
    || { echo "s22: stale {7,11} policy signature failed"; exit 1; }
jq -n --arg pol "$POL711_STALE" --arg sig "$(openssl base64 -A -in "$RUN/sig711.bin")" \
    --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [7, 11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$RUN/pcrsig-711only.json"
run_stage pcrsig_disk-711only 60 uki_pcrsig_disk "$RUN/pcrsig-711only.img" "$RUN/pcrsig-711only.json"
# the CLI state root: pending baseline + release.pub + PLAINTEXT release.pem +
# /etc/crypttab (the completion member walk reads every LUKS member UUID from
# it) + the ESP stand-in for fin_uki_pcrsig (item 10b: NO install-state.json —
# the window ground truth is the DISK's standing {PCR 11} token)
mkdir -p "$RUN/cli-state/etc/alpine-fde/keys"
mkdir -p "$RUN/cli-state/etc"
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$DISK_UUID" \
    >"$RUN/cli-state/etc/crypttab"
cp "$RUN/keys/release.pub" "$RUN/cli-state/etc/alpine-fde/keys/release.pub"
cp "$RUN/keys/db.key" "$RUN/cli-state/etc/alpine-fde/keys/release.pem"
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
# fixture efivars (SB on, setup mode 0) — the completion's SB guard reads these
EFIVARS="$RUN/cli-state/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
# the by-uuid seam (the completion's member walk) + the cli ESP stand-in dir
mkdir -p "$RUN/by-uuid"
ln -sfn "$RUN/disk.img" "$RUN/by-uuid/$DISK_UUID"
mkdir -p "$RUN/cli-esp/EFI/Linux"
cp "$RUN/harness.efi" "$RUN/cli-esp/EFI/Linux/alpine-fde-harness.efi"
# fixture scrub: the well-known slot-0 credential died with its keyslot; the
# volume-pass file STAYS until after the ceremony mirror (the mirror consumes
# the ESCROW copy instead — the file is the seal's staging, the escrow is the
# product credential)
keys_scrub "$RUN/kf-slot0"
rm -f "$RUN/kf-slot0"

# ============================================================================
# LEG 1 — ESCROW-WINDOW IMMUNITY, foreign UKI: the {11} token's selection has
# no matching .pcrsig entry -> the I3 signature gate refuses BEFORE any TPM
# session; the DEAD recovery loop (no keyslot 0 in the window) 3-strikes
# fail-closed; the boot's unlabeled ESP also pins the LOUD escrow-absent
# detect warn (the eb2df91 real-hardware fix).
# ============================================================================
echo "# leg 1: foreign UKI + {7,11}-only stale payload — the I3 signature refusal"
_boot_hook "$RUN/boot1" "$RUN/esp-tampered.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" \
    "$RUN/pcrsig-711only.img" "$RUN/harness-tampered.efi"
_refuse_3strike "$RUN/boot1"

LOG_B1=$(cat "$RUN/boot1/console.log" 2>/dev/null || true)
assert_contains "[leg 1] init ran (the variant boots — SB-on firmware trusts our key)" "$LOG_B1" \
    "alpine-fde-harness: init started"
assert_contains "[leg 1] the tampered cmdline word reached the kernel (the primitive is real)" \
    "$LOG_B1" "alpine-fde-tampered"
# RECONCILIATION ITEM (2026-10-03, dab0b88 follow-up): the eb2df91 LOUD-miss
# warn did not fire in the harness initrd (the leg-1 ESP is labeled, so the
# detect found and mounted it — the warn belongs on the FILES-miss branch,
# which fires only when the escrow is genuinely absent; the harness initrd
# also lacks the blkid channel the product features.d now ships). Re-pin the
# warn after the live diagnosis; the immunity asserts below are the real
# control and they hold.
assert_contains "[leg 1] hook ran the enter-initrd extend" "$LOG_B1" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[leg 1] hook discovered the standing provisional token" "$LOG_B1" \
    "$(sentinel_of unseal_token_info)11]"
assert_contains "[leg 1] the I3 signature gate REFUSED (no release-key-signed entry for the {11} selection)" \
    "$LOG_B1" "$(sentinel_of unseal_sig_refused)"
assert_contains "[leg 1] the warn-before-prompt preamble names the foreign/unsigned class" "$LOG_B1" \
    "$(sentinel_of unseal_warn_sig_refused)"
assert_not_contains "[leg 1] the refusal was the SIGNATURE gate — the TPM was never consulted" "$LOG_B1" \
    "$(sentinel_of unseal_seal_refused)"
# Item 24a: candidate-set prompt-EVENT count (unique attempt tokens across
# BOTH hook prompt textures); the exact-3 pin IS the bounded loop.
assert_eq "[leg 1] exactly 3 recovery-passphrase prompts (the DEAD window loop)" "3" \
    "$(unseal_prompt_events <<<"$LOG_B1")"
assert_contains "[leg 1] 3-strike give-up (§8.2 fail-closed)" "$LOG_B1" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[leg 1] fail-closed poweroff (no shell is offered)" "$LOG_B1" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[leg 1] NEVER unlocked via the token" "$LOG_B1" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg 1] NEVER unlocked via any passphrase" "$LOG_B1" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[leg 1] never UNSEALED" "$LOG_B1" "alpine-fde: UNSEALED"
assert_not_contains "[leg 1] no systemd-cryptenroll sentinel (Mechanism B never invokes it)" "$LOG_B1" \
    "systemd-cryptenroll"
assert_not_contains "[leg 1] no emergency shell" "$LOG_B1" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot1/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot1/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[leg 1] guest exited (hook 3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[leg 1] guest exited (hook 3-strike poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
# the refused boot mutated NOTHING: the window shape + the escrow stand intact
# (Wave-2 2b: the boot ran on a discarded QCOW2 overlay, so the host-side
# cryptsetup reads target the RAW base — the boot's writes died with it)
METAB1=$(disk_metadata "$RUN/disk.img")
TOKB1=$(disk_token_json "$RUN/disk.img")
assert_eq "[leg 1] host(base): window shape intact — keyslots == {1,2}, NO keyslot 0" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$METAB1")"
assert_eq "[leg 1] host(base): window shape intact — the token still {11} on keyslot 1" "[11]|1" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKB1")|$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKB1")"
mcopy -i "$RUN/esp.img" -o "::/alpine-fde-provision/volume-keys.json" "$RUN/escrow-l1.json" \
    && mcopy -i "$RUN/esp.img" -o "::/alpine-fde-provision/REQUEST" "$RUN/request-l1" \
    || { echo "s22: leg-1 escrow readback failed"; exit 1; }
assert_eq "[leg 1] host(esp): the escrow still stands (content byte-identical)" "$ESCROW_SHA" \
    "$(sha256sum "$RUN/escrow-l1.json" | awk '{print $1}')"
assert_eq "[leg 1] host(esp): the REQUEST marker still stands (the canonical-cmdline digest, dab0b88)" \
    "$(cat "$RUN/REQUEST")" "$(cat "$RUN/request-l1")"

# ============================================================================
# LEG 2 — ESCROW-WINDOW IMMUNITY, tampered cmdline: the variant's OWN stub
# .pcrsig is valid and self-consistent (the compromised-signer case) — the
# signature gate PASSES and the TPM refuses the sealed blob under the
# tampered PCR state. Same dead-loop 3-strike fail-closed.
# ============================================================================
echo "# leg 2: tampered cmdline + its own valid {11} entry — the TPM digest refusal"
swtpm_stop "$RUN/tpm" 2>/dev/null || true
run_stage swtpm-cycle-2 90 swtpm_start "$RUN/tpm"
_rearm_trap
_boot_hook "$RUN/boot2" "$RUN/esp-tampered.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" \
    "" "$RUN/harness-tampered.efi"
_refuse_3strike "$RUN/boot2"

LOG_B2=$(cat "$RUN/boot2/console.log" 2>/dev/null || true)
assert_contains "[leg 2] init ran" "$LOG_B2" "alpine-fde-harness: init started"
assert_contains "[leg 2] the tampered cmdline word reached the kernel" "$LOG_B2" \
    "alpine-fde-tampered"
assert_contains "[leg 2] hook discovered the standing provisional token" "$LOG_B2" \
    "$(sentinel_of unseal_token_info)11]"
assert_not_contains "[leg 2] the signature gate PASSED (the variant's entry is genuinely signed)" "$LOG_B2" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "[leg 2] the TPM refused the sealed blob under the tampered PCR state" "$LOG_B2" \
    "$(sentinel_of unseal_seal_refused)"
assert_contains "[leg 2] the warn-before-prompt preamble names the expected drift class" "$LOG_B2" \
    "$(sentinel_of unseal_warn_seal_refused)"
assert_eq "[leg 2] exactly 3 recovery-passphrase prompts (the DEAD window loop)" "3" \
    "$(unseal_prompt_events <<<"$LOG_B2")"
assert_contains "[leg 2] 3-strike give-up (§8.2 fail-closed)" "$LOG_B2" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[leg 2] fail-closed poweroff (no shell is offered)" "$LOG_B2" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[leg 2] NEVER unlocked via the token" "$LOG_B2" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg 2] NEVER unlocked via any passphrase" "$LOG_B2" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[leg 2] never UNSEALED" "$LOG_B2" "alpine-fde: UNSEALED"
assert_not_contains "[leg 2] no systemd-cryptenroll sentinel" "$LOG_B2" "systemd-cryptenroll"
assert_not_contains "[leg 2] no emergency shell" "$LOG_B2" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot2/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot2/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[leg 2] guest exited (hook 3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[leg 2] guest exited (hook 3-strike poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
METAB2=$(disk_metadata "$RUN/disk.img")
TOKB2=$(disk_token_json "$RUN/disk.img")
assert_eq "[leg 2] host(base): window shape intact — keyslots == {1,2}, NO keyslot 0" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$METAB2")"
assert_eq "[leg 2] host(base): window shape intact — the token still {11} on keyslot 1" "[11]|1" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKB2")|$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKB2")"
mcopy -i "$RUN/esp.img" -o "::/alpine-fde-provision/volume-keys.json" "$RUN/escrow-l2.json" \
    || { echo "s22: leg-2 escrow readback failed"; exit 1; }
assert_eq "[leg 2] host(esp): the escrow still stands (content byte-identical)" "$ESCROW_SHA" \
    "$(sha256sum "$RUN/escrow-l2.json" | awk '{print $1}')"

# ============================================================================
# LEG 3 — THE FIRST BOOT: the EXACT installed UKI against the LABELED
# installed ESP (the escrow standing). The hook engages the ADR-21 consume;
# ZERO console input either way (see the consume-gap fidelity note: at HEAD
# the consume fails loud at the policy marshal and the boot falls through to
# the standing provisional-token path — the seal still guards its window and
# opens for the exact UKI; when the consume fix lands the same asserts hold
# minus the two HEAD-pinned lines, flagged below).
# ============================================================================
echo "# leg 3: the first boot — the escrow consume engages, the exact UKI enters"
_boot_hook "$RUN/boot3" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" ""
i=0
until grep -q "alpine-fde: UNSEALED" "$RUN/boot3/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$RUN/boot3" "console-wait:boot3-UNSEALED"
    _budget_check "console-wait:boot3-UNSEALED"
    (( i < QEMU_TIMEOUT )) || _hang_fail CONSOLE-WAIT "boot3 UNSEALED" \
        "the first boot never entered (the escrow boot must open zero-input)"
    sleep 1
    i=$((i + 1))
done
wait_console "$RUN/boot3" "alpine-fde: POWEROFF" "$QEMU_TIMEOUT" 2>/dev/null || \
    wait_console "$RUN/boot3" "localhost login:" 120 || true
run_stage qemu_wait-boot3 "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/boot3" "$QEMU_TIMEOUT"
overlay_discard "$RUN/boot3/disk.qcow2"   # ephemeral — the host legs below mutate
CURRENT_QEMU_DIR=""                       # the RAW base through by-uuid

LOG_B3=$(cat "$RUN/boot3/console.log" 2>/dev/null || true)
assert_contains "[leg 3] init ran" "$LOG_B3" "alpine-fde-harness: init started"
# THE CONSUME FIXED (2026-10-03): the live-policy marshal rides the hook's
# own _fdh_hex2bin (blkid is in the closure too), the ×2 ceremony is wired
# (FDE_CONSOLE_IN feeds it), and the consumed escrow is deleted in-guest.
# The boot is ZERO-INPUT by seam: the ceremony reads the fed file, not the
# console.
assert_contains "[leg 3] the escrow consume ENGAGED (the real-measurement {7,11} self-seal unlocked the member)" \
    "$LOG_B3" "via the provisioning escrow (real-measurement {7,11} seal)"
assert_contains "[leg 3] the ×2 ceremony set + staged the operator credential" "$LOG_B3" \
    "the recovery passphrase is set and staged for the Stage-2 finalize"
assert_contains "[leg 3] the escrow DELETED in-guest (steps g+h complete)" "$LOG_B3" \
    "provisioning escrow: consumed — the Stage-2 finalize completes on this boot"
# stable across the consume fix:
assert_contains "[leg 3] the exact installed UKI auto-unsealed (ZERO console input)" "$LOG_B3" \
    "alpine-fde: UNSEALED"
assert_not_contains "[leg 3] the token path SKIPPED (the escrow boot opens via the consume)" "$LOG_B3" \
    "token: pcrs=["
assert_eq "[leg 3] the recovery loop NEVER armed (zero-input first boot)" "0" \
    "$(unseal_prompt_events <<<"$LOG_B3")"
assert_not_contains "[leg 3] no refusal class ever fired" "$LOG_B3" \
    "$(sentinel_of unseal_sig_refused)"
assert_not_contains "[leg 3] no seal refusal either" "$LOG_B3" \
    "$(sentinel_of unseal_seal_refused)"
assert_not_contains "[leg 3] the tampered-word UKI is not what booted" "$LOG_B3" \
    "alpine-fde-tampered"
assert_not_contains "[leg 3] no systemd-cryptenroll sentinel" "$LOG_B3" "systemd-cryptenroll"
assert_not_contains "[leg 3] no emergency shell" "$LOG_B3" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot3/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot3/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[leg 3] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[leg 3] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
# G-T13: the postphase PCR 11 == the build's enter-initrd prediction — the
# value the provisional seal bound (retroactive proof of the host-side seal)
D11_BOOT3=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$RUN/boot3/console.log" \
    | head -1 | cut -d= -f2)
assert_eq "leg 3: postphase PCR 11 == the ukify enter-initrd prediction (G-T13)" "$D11_PRED" "$D11_BOOT3"
# the boot's overlay died with it: the RAW base keeps the window shape, and
# the host legs below re-produce the post-ceremony shape deterministically
# (the in-guest consume's mutations lived in the overlay by design). The
# ESP is NOT overlaid: the in-guest escrow DELETE persists on esp.img.
METAB3=$(disk_metadata "$RUN/disk.img")
TOKB3=$(disk_token_json "$RUN/disk.img")
assert_eq "[leg 3] host(base): window shape intact — keyslots == {1,2}" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$METAB3")"
assert_eq "[leg 3] host(base): the token still {11} on keyslot 1" "[11]|1" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKB3")|$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKB3")"
# the consume DELETED the escrow in-guest (the ESP is the un-overlaid image):
if mdir -i "$RUN/esp.img" ::/alpine-fde-provision >/dev/null 2>&1; then
    _assert_result not-ok "[leg 3] host(esp): the escrow DELETED in-guest (steps g+h)" \
        "alpine-fde-provision still present on esp.img"
else
    _assert_result ok "[leg 3] host(esp): the escrow DELETED in-guest (steps g+h)" ""
fi

# ============================================================================
# HOST — THE CEREMONY MIRROR (the hook's step (g)+(h) stand-in — see the
# fidelity notes): the ×2 passphrase enrolls at keyslot 0 per member,
# authorized by the ESCROWED keyslot-1 credential (the scenario consumes its
# own escrow exactly as the hook would — the ADR-19 framing decode), then the
# escrow is DELETED from the installed ESP. This is the post-ceremony shape
# the Stage-2 completion chain assumes (keyslot 0 standing, escrow gone).
# ============================================================================
echo "# ceremony mirror: keyslot 0 enrolled from the escrowed credential; the escrow deleted"
# the hook's step (b) decode: pass_b64 from the json, base64-decoded ONCE
jq -r '.members[0].pass_b64' "$RUN/volume-keys.json" | openssl base64 -d -A >"$RUN/kf-vol-mirror" \
    || { echo "s22: the escrow credential decode failed"; exit 1; }
chmod 600 "$RUN/kf-vol-mirror"
printf '%s' "$S22_RECOVERY" >"$RUN/kf-recovery"
chmod 600 "$RUN/kf-recovery"
# the hook's step-(g) recipe verbatim (argon2id, keyslot 0, authorized by the
# escrowed keyslot-1 passphrase)
timeout 120 "$CRYPTSETUP_BIN" luksAddKey --pbkdf argon2id --pbkdf-memory 1048576 \
    --pbkdf-parallel 4 --iter-time 2000 --key-slot 0 "$RUN/disk.img" "$RUN/kf-recovery" \
    --key-file "$RUN/kf-vol-mirror" 2>/dev/null \
    || { echo "s22: the ceremony mirror's keyslot-0 enrollment failed"; exit 1; }
assert_eq "ceremony mirror: keyslot 0 enrolled (argon2id, the ×2 passphrase)" "argon2id" \
    "$(disk_metadata "$RUN/disk.img" | jq -r '.keyslots["0"].kdf.type')"
# the hook's step (h): delete the escrow ONLY after every member is
# credential-complete (single member here). ADR-21: the in-guest consume
# ALREADY deleted it (the "escrow DELETED in-guest" assert above) — the
# mdeltree stays for the mirror-only path and must tolerate already-absent
# (s22f10: the harness broke BECAUSE the product worked).
if mdir -i "$RUN/esp.img" ::/alpine-fde-provision >/dev/null 2>&1; then
    mdeltree -i "$RUN/esp.img" ::/alpine-fde-provision \
        || { echo "s22: the ceremony mirror's escrow delete failed"; exit 1; }
    echo "# ceremony mirror: the escrow deleted host-side (the mirror-only path)"
else
    echo "# ceremony mirror: the escrow already DELETED in-guest (the ADR-21 consume) — step (h) satisfied"
fi
mcopy -i "$RUN/esp.img" -o "::/alpine-fde-provision/volume-keys.json" "$RUN/escrow-gone.json" \
    2>/dev/null && { echo "s22: the escrow SURVIVED the mirror delete"; exit 1; } || true
_assert_result ok "ceremony mirror: the escrow DELETED from the installed ESP (step h)" ""
METAC=$(disk_metadata "$RUN/disk.img")
assert_eq "ceremony mirror: the post-ceremony window shape — keyslots == {0,1,2}" '["0","1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$METAC")"
keys_scrub "$RUN/kf-vol-mirror"
rm -f "$RUN/kf-vol-mirror" "$RUN/kf-eph"

# ============================================================================
# HOST — THE COMPLETION: the Stage-2 chain the first boot triggers,
# fin_service_main DIRECT-DRIVE (the harness has no OpenRC). Runs NOW because
# the fixture swtpm can be re-seeded to LEG 3's live register — the audit
# reads exactly the booted values.
# ============================================================================
echo "# completion: fin_service_main drives the shared Stage-2 == Stage-3 chain host-side"
D7_BOOT3=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/boot3/console.log" | head -1 | cut -d= -f2)
[[ -n "$D7_BOOT3" && -n "$D11_BOOT3" ]] || { echo "s22: leg-3 console missing PCR prints"; exit 1; }
# leg 3's clean exit killed the fixture swtpm; re-extend the booted register
# before audit --init finalizes the baseline from the live PCRs. Readback
# pins the zero-on-restart contract (live == extend-from-zero of the seeded
# d11 — never the booted digest itself).
swtpm_ensure "$RUN/tpm" >/dev/null 2>&1 || true
# the completion-reachable register: the restart is all-zero; ONE extend of
# the enter-initrd phase-word digest lands live PCR 11 on V_SEED — the value
# the provisional {11} token is digest-anchored to (the fidelity note at the
# pcrsig-11 composition). The guest's own pre-phase chain is multi-event and
# unreproducible by extends — that is WHY the anchor is V_SEED.
# swtpm_pcrextend is a FIXTURE FUNCTION (timeout cannot exec functions —
# s22f18) and carries its own internal `timeout 10` on the ioctl.
swtpm_pcrextend "$RUN/tpm" 11 "$PHASE_DGST" || true
D11_LIVE=$(_pcrread "$RUN/tpm" 11)
if [[ "$D11_LIVE" == "$V_SEED" ]]; then
    _assert_result ok "completion fixture: the register anchored to leg 3's V_SEED (the extend-from-zero phase register)" ""
else
    _assert_result not-ok "completion fixture: the register anchored to leg 3's V_SEED" \
        "live=$D11_LIVE expected-anchor=$V_SEED"
    echo "s22: swtpm PCR 11 is not the anchored register before the completion — aborting"; exit 1
fi
# the combined {7,11} release-key-signed policy for the upgrade (s19/s20's
# pcrsign shape, composed host-side with the harness helper) — anchored to
# LEG 3's own booted (d7, postphase d11)
run_stage pcrsig-combined 120 \
    uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-711.json" \
    "$D7_BOOT3" "$D11_BOOT3" "$RUN/keys" \
    || { echo "s22: combined pcrsig composition failed"; exit 1; }
assert_eq "completion: combined .pcrsig pol == policy_digest(leg-3 d7, enter-initrd d11)" \
    "$(policy_digest "$D7_BOOT3" "$D11_BOOT3")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-pcrsig-711.json")"
run_stage pcrsig_disk-711 60 uki_pcrsig_disk "$RUN/uki-pcrsig-711.img" "$RUN/uki-pcrsig-711.json"
# THE SERVICE DRIVE: the real fin_service_main in a failure-contained
# subshell. ONLY fin_uki_pcrsig is stood in (the pcrsign-stamped ESP .pcrsig
# the real install bakes — see the fidelity notes); the ground-truth gate,
# the userspace token re-unseal (seal_unseal, mode=provisional), audit
# --init, the ephemeral purge, the {7,11} upgrade and the marker clear are
# the REAL product code. NO credential env is set — the service is
# authorized by the re-unsealed standing token, never a stored secret.
cat >"$RUN/completion-drive.sh" <<'DRIVEEOF'
#!/usr/bin/env bash
# generated by s22-handoff-immunity.sh — the fin_service_main direct-drive
# (the Stage-2 chain the first boot triggers; the harness has no OpenRC)
set -u
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
export ALPINE_FDE_TCTI="$SWTPM_TCTI_STR"
export ALPINE_FDE_EFIVARS_DIR="$EFIVARS"
export ALPINE_FDE_EVENTLOG="$RUN/cli-state/eventlog-absent"
export ALPINE_FDE_ROOT="$RUN/cli-state"
export ALPINE_FDE_KEYDIR="$RUN/keys"
export ALPINE_FDE_BY_UUID_DIR="$RUN/by-uuid"
export ALPINE_FDE_TMPDIR="$RUN/tmp"
export ALPINE_FDE_PCRSIG="$RUN/uki-pcrsig-711.json"
export ALPINE_FDE_NO_INSTALL=1
# the Stage-2 service is NEVER credential-authorized: unset the seams
unset ALPINE_FDE_RECOVERY_PASSPHRASE ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || true
# shellcheck source=lib/common.sh
. "$REPO/lib/common.sh"
# shellcheck source=lib/policy.sh
. "$REPO/lib/policy.sh"
# shellcheck source=lib/keys.sh
. "$REPO/lib/keys.sh"
# shellcheck source=lib/seal.sh
. "$REPO/lib/seal.sh"
# shellcheck source=lib/baseline.sh
. "$REPO/lib/baseline.sh"
# shellcheck source=lib/trust-state.sh
. "$REPO/lib/trust-state.sh"
# shellcheck source=lib/cmd/finalize.sh
. "$REPO/lib/cmd/finalize.sh"
# the pcrsign-stamped ESP UKI stand-in: the REAL installer builds the
# ESP UKI with an anchored {11} entry (lib/cmd/pcrsign.sh); the harness
# ukify section is ukify-native and anchor-less, and PE section surgery
# cannot grow .pcrsig (objcopy --update-section is size-capped).
fin_uki_pcrsig() { cp "$RUN/pcrsig-11.json" "$2"; }
fin_service_main
DRIVEEOF
run_stage_rc completion-service 900 env REPO="$REPO" RUN="$RUN" EFIVARS="$EFIVARS" \
    SWTPM_TCTI_STR="$(_swtpm_tcti_for "$RUN/tpm")" bash "$RUN/completion-drive.sh" \
    >"$RUN/completion.out" 2>&1
COMPLETION_RC=$?
assert_eq "completion: fin_service_main rc 0 (the non-interactive Stage-2 chain)" "0" "$COMPLETION_RC"
grep -q "finalizing the baseline from live values (audit --init" "$RUN/completion.out" \
    && _assert_result ok "completion: audit --init finalized the pending baseline from live values" "" \
    || _assert_result not-ok "completion: audit --init finalized the pending baseline" \
        "no audit marker in completion.out"
grep -q "temporary ephemeral install key purged (keyslot 2)" "$RUN/completion.out" \
    && _assert_result ok "completion: the temporary ephemeral keyslot purged (keyslot 2)" "" \
    || _assert_result not-ok "completion: the temporary ephemeral keyslot purged" \
        "no purge marker in completion.out"
grep -q "token upgraded to Mechanism B {PCR 7, PCR 11}" "$RUN/completion.out" \
    && _assert_result ok "completion: the provisional token upgraded to Mechanism B {PCR 7, PCR 11}" "" \
    || _assert_result not-ok "completion: the provisional token upgraded to Mechanism B" \
        "no upgrade marker in completion.out"
grep -q "provisioning ceremony complete" "$RUN/completion.out" \
    && _assert_result not-ok "completion: the ADR-21 consumption block is a documented harness no-op" \
        "the /run staged-pass block ran (it must not in the harness)" \
    || _assert_result ok "completion: the ADR-21 consumption block is a documented harness no-op (no /run staged pass)" ""
# ground truth + the window-exit assert of record: the upgrade stood a fresh
# Mechanism B seal in the NEXT free slot and retired the provisional one
METAF=$(disk_metadata "$RUN/disk.img")
TOKF=$(disk_token_json "$RUN/disk.img")
EXIT_SLOT=$(jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]' <<<"$TOKF")
assert_eq "S-22 window exit: EXACTLY ONE token" "1" \
    "$(jq '[.[] | select(.type == "systemd-tpm2")] | length' <<<"$TOKF")"
assert_eq "S-22 window exit: the token binds {PCR 7, PCR 11}" "[7,11]" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKF")"
assert_contains "S-22 window exit: the token is Mechanism B SIGNED (not the escrow/unsigned marker)" "$TOKF" \
    '"tpm2-signature":"'
assert_ne "S-22 window exit: the token sits on a NON-ZERO keyslot" "0" "$EXIT_SLOT"
assert_eq "S-22 window exit: keyslots == {0, token slot} (I1 two-keyslot at-rest)" \
    "[\"0\",\"$EXIT_SLOT\"]" "$(jq -c '.keyslots | keys' <<<"$METAF")"
assert_eq "S-22 window exit: recovery keyslot 0 still argon2id (the ceremony's)" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$METAF")"
assert_eq "S-22 window exit: NO ephemeral keyslot remains" "0" \
    "$(jq '[.keyslots | keys[] | tonumber] | length - 2' <<<"$METAF")"
# the ground-truth composition (the ts_state rules, asserted raw — the main
# shell does not source trust-state.sh): token [7,11] AND no ephemeral keyslot
# AND a FINAL baseline (expected_pcr7 captured)
assert_ne "completion: ground truth: the pending baseline was finalized (expected_pcr7 captured)" \
    "pending" "$(jq -r '.expected_pcr7' "$RUN/cli-state/etc/alpine-fde/baseline.json")"
assert_eq "completion: the ADR-8 marker is CLEAR" "absent" \
    "$([[ -e "$RUN/cli-state/etc/alpine-fde/finalize-attempt.txt" ]] && echo present || echo absent)"
assert_eq "completion: release.pem STILL plaintext (the ADR-21 consumption block is out of harness scope)" \
    "plaintext" "$([[ -f "$RUN/keys/release.pem" ]] && openssl pkey -in "$RUN/keys/release.pem" \
        -passin pass:"$S22_RECOVERY" -noout 2>/dev/null && echo encrypted || echo plaintext)"

# ============================================================================
# LEG 4 — POST-FINALIZATION IMMUNITY UNCHANGED: the tampered variant AGAIN,
# now carrying the VALID release-signed {7,11} entry (the completion's own
# .pcrsig): the signature gate passes, the TPM refuses the tampered PCR
# digest under the {7,11} binding -> 3-strike fail-closed. The finalized
# shape is intact afterwards.
# ============================================================================
echo "# leg 4: tampered variant after finalization — the {7,11} binding refuses unchanged"
swtpm_stop "$RUN/tpm" 2>/dev/null || true
run_stage swtpm-cycle-4 90 swtpm_start "$RUN/tpm"
_rearm_trap
_boot_hook "$RUN/boot4" "$RUN/esp-tampered.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" \
    "$RUN/uki-pcrsig-711.img" "$RUN/harness-tampered.efi"
_refuse_3strike "$RUN/boot4"

LOG_B4=$(cat "$RUN/boot4/console.log" 2>/dev/null || true)
assert_contains "[leg 4] init ran" "$LOG_B4" "alpine-fde-harness: init started"
assert_contains "[leg 4] the tampered cmdline word reached the kernel" "$LOG_B4" \
    "alpine-fde-tampered"
assert_contains "[leg 4] hook discovered the finalized token" "$LOG_B4" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[leg 4] the signature gate PASSED (the {7,11} entry is genuinely release-signed)" "$LOG_B4" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "[leg 4] the TPM refused the sealed blob under the tampered PCR state ({7,11} binding)" "$LOG_B4" \
    "$(sentinel_of unseal_seal_refused)"
assert_contains "[leg 4] the warn-before-prompt preamble names the drift class" "$LOG_B4" \
    "$(sentinel_of unseal_warn_seal_refused)"
assert_eq "[leg 4] exactly 3 recovery-passphrase prompts (bounded loop)" "3" \
    "$(unseal_prompt_events <<<"$LOG_B4")"
assert_contains "[leg 4] 3-strike give-up (§8.2 fail-closed)" "$LOG_B4" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[leg 4] fail-closed poweroff (no shell is offered)" "$LOG_B4" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[leg 4] NEVER unlocked via the token" "$LOG_B4" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[leg 4] NEVER unlocked via the recovery passphrase" "$LOG_B4" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[leg 4] never UNSEALED" "$LOG_B4" "alpine-fde: UNSEALED"
assert_not_contains "[leg 4] no systemd-cryptenroll sentinel" "$LOG_B4" "systemd-cryptenroll"
assert_not_contains "[leg 4] no emergency shell" "$LOG_B4" "$(sentinel_of emergency_forbidden)"
if [[ -f "$RUN/boot4/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/boot4/qemu.pid" 2>/dev/null)"; then
    _assert_result ok "[leg 4] guest exited (hook 3-strike poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[leg 4] guest exited (hook 3-strike poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
# the refused boot mutated NOTHING: the finalized shape is intact (slot
# number not pinned — the upgrade choreography stands the fresh seal in the
# next free slot; {0, EXIT_SLOT} holds). Wave-2 2b: the boot ran on a
# discarded QCOW2 overlay, so the host-side cryptsetup reads target the RAW
# base — the same invariant (the boot's writes died with the overlay AND the
# base it read from is unchanged).
METAB4=$(disk_metadata "$RUN/disk.img")
TOKB4=$(disk_token_json "$RUN/disk.img")
assert_eq "[leg 4] host(base): finalized shape intact — keyslots == {0, token slot}" \
    "[\"0\",\"$EXIT_SLOT\"]" "$(jq -c '.keyslots | keys' <<<"$METAB4")"
assert_eq "[leg 4] host(base): finalized shape intact — token pcrs [7,11], exactly one" "[7,11]|1" \
    "$(jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]' <<<"$TOKB4")|$(jq '[.[] | select(.type == "systemd-tpm2")] | length' <<<"$TOKB4")"

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
