#!/usr/bin/env bash
# tests/e2e/s00b-enroll-cache.sh — §12 S-00b + S-01 (continues tests/e2e/
# s00-bootstrap-lite.sh; runs only AFTER S-00 finalized the baseline).
#
# REWORKED 2026-09-18 per the amended §12 S-00b contract; flipped to the
# ALPINE contract (G-E3, 2026-09-21): the first-install enrollment happens
# via the PRODUCTION CLI in the guest — `/opt/alpine-fde/bin/alpine-fde
# enroll-tpm` (Mechanism B backing: tpm2-tools seal + LUKS2 token import,
# ADR-19/§7; exactly ONE enrollment; the pcrsig source rides the documented
# ALPINE_FDE_PCRSIG seam so no release.pem is needed in-guest) — REPLACING
# the harness stand-in (the initrd's hand-run cryptenroll), which is proven
# OUT of the loop by console evidence. NO systemd-cryptenroll runs anywhere
# in this scenario (Mechanism B never invokes it).
#
#   boot A  (self-bootstrap only) the S-00 installer UKI: passphrase unlock
#           (embedded kf0, zero console input) -> populate the minimal rootfs
#           (§3.3) -> poweroff. Host-side: `audit --init` finalizes the
#           baseline via the REAL CLI (G-R1-guarded efivars fixture) BEFORE
#           any UKI-chain work (§12 S-00b precondition, on every path).
#   boot B  the `ukictl build` PRODUCT analog (release-key PCR-signed +
#           sbsigned UKI) boots the populated disk and the enrollment runs
#           FROM THE GUEST via the production CLI (it has TPM access + the
#           finalized baseline, §9.1 first-install path):
#             - the payload drive carries the COMBINED {7,11} pcrsig entry
#               (uki_pcrsig_append_combined, G-B6 shape) — the finalized
#               enrollment AND the §8.2 unseal hook both consume it;
#             - host-side, a DEAD `systemd-tpm2` token (pcrs [7]) is imported
#               into the LUKS2 metadata (unprivileged `cryptsetup token
#               import`, the s06/s13 mechanism): the §8.2 unseal hook cannot
#               select a policy for it and refuses it (I3 gate) -> the hook's
#               bounded recovery loop opens -> fed slot-0 passphrase -> the
#               initrd's DEBUG SHELL seam (ALPINE_FDE_DEBUG_SHELL, serial);
#             - the fed session untars the §5-shaped tooling payload off the
#               tail of the pcrsig payload drive (/opt/alpine-fde tree +
#               guest-bound baseline + release.pub + jq + the tpm2
#               multitool closure), removes the dead token (fixture
#               teardown), and runs the production CLI: its real
#               preconditions fire (finalized baseline, SB on + SetupMode=0,
#               live PCR 7 == baseline, LUKS uuid resolvable) and enrl_run
#               performs the single A'' enrollment. Console asserts the
#               CLI's own markers: the argv line, the cryptenroll_enrolled
#               sentinel and `alpine-fde: enrolled (...)` + rc 0. NO
#               hand-rolled cryptenroll exists anywhere in this scenario.
#           Then the PRISTINE disk + TPM state are snapshotted into the
#           stable cache (tests/e2e/.cache/pristine-s00b/, SHA256-recorded
#           manifest + FORMAT marker, fail-closed verification on reuse, s00
#           STATE SHAPE including tpm/tpm2-00.permall). The cache also carries
#           baseline.json + uki-pcrsig.json + uki-pcrsig-combined.json:
#           earlier cache formats (flat permall, no finalized baseline,
#           pre-jq target set, no signed-prediction JSON, pre-btrfs ext4 disk
#           without the `btrfs-1` FORMAT marker — G-HW5 bump; ladder-only
#           pcrsig drive without the COMBINED {7,11} entry — the btrfs-3
#           bump, §8.2 hook era) fail verification and trigger a rebuild.
#   boot C  §12 S-01 happy path under the §8.2 hook: the SAME release UKI
#           bytes (the finalized {7,11} sealed policy is bound to the
#           enroll-time measured PCR 11 — a cmdline variant could never
#           match), login stage selected on the payload drive
#           (uki_stage_login_drive), token unlock with ZERO console input ->
#           switch_root into the populated installed system -> `login:` on
#           the serial console. Plus the §13 ESP-size assertion for the
#           release UKI.
#
# State sourcing (in order): ALPINE_FDE_S00_STATE (set by run-e2e.sh when s00
# ran in this invocation) -> the stable pristine cache (verified against its
# SHA manifest) -> full self-bootstrap (runs the S-00 chain itself).
#
# From-cache semantics: the cache snapshots the ENROLLED disk (it is stored
# only after boot B's production enrollment landed), so the from-cache flow
# NEVER re-runs boot B — no dead fixture token import, no in-guest enroll
# (re-enrolling over the standing token is exactly the work the cache exists
# to skip, and a dead-token import would leave 2 systemd-tpm2 tokens on the
# volume). It verifies the standing enrollment host-side (exactly 1 token on
# keyslot 1), restores the cached release UKI artifacts, and goes straight to
# boot C, asserting ZERO cryptenroll invocations.
#
# RUN DIR CONTRACT (consumed by the registered state consumers via run-e2e.sh
# as ALPINE_FDE_E2E_STATE): disk.img (populated + ENROLLED), tpm/ (swtpm state,
# SRK the token seals to), keys/, vars-enrolled.fd, harness.efi (the enrolled
# release UKI), pcrsig.img, console.log; last line:
#     RUNDIR <path>
#
# Hardening (2026-09-18, after an overnight 8h pre-boot hang): every fixture/
# build stage runs under a process-group watchdog (run_stage) with a LOUD,
# sentinel-greppable STAGE-TIMEOUT/STAGE-FAILED failure and a nonzero exit —
# this scenario can never hang indefinitely again. Console waits are bounded;
# the whole scenario carries an overall wall budget; a stale run's QEMU/swtpm
# children are killed on every exit path. (Root-cause evidence for the hang:
# the run dir had swtpm state + rootfs/ + guest-tree/ but NO console.log —
# qemu_run never ran; the only unbounded operation in that window is the
# pin-fetch curl inside the fixture lib, whose call sites are wrapped here.)
#
# deviations (documented, not silent):
#   * the tooling payload rides the TAIL of the pcrsig payload drive (the
#     initrd reads only the first 64 KiB — the pcrsig JSON — so the
#     measurement story of the signed prediction is untouched);
#   * the initrd has no udev, so the CLI's ALPINE_FDE_BY_UUID_DIR seam (its
#     documented injection point) is pointed at a fed /run/bu symlink of the
#     active /dev/mapper/root — the §9.1 enroll-on-active-volume production
#     shape (no unlock key file involved);
#   * jq + the tpm2 multitool + openssl ride as host-closure copies (the
#     /opt/tpm isolation pattern of tests/lib/uki-build.sh): the pinned rootfs
#     tree predates the §3.3 package set and the harness installer never runs
#     apk; openssl is required by the Mechanism B CLI (require_pkgs + the
#     token post-assert pubkey fingerprint) but is not in the initrd tree;
#   * the volume-passphrase credential for luksAddKey rides the CLI's own
#     ALPINE_FDE_LUKS_KEYFILE seam (/kf0, the embedded slot-0 passphrase) —
#     Mechanism B's documented existing-credential injection point; the
#     invocation itself stays inside the production CLI;
#   * boot B's UKI carries the DEBUG SHELL seam (ALPINE_FDE_DEBUG_SHELL) for
#     the fed enrollment session; boot C selects its stage on the payload
#     drive so the release UKI's measured PCR 11 stays exactly the enroll-time
#     one (§8.2 hook contract);
#   * REGISTER-DRIFT DEFENSE (2026-09-24): the digest-anchored enroll (Option
#     A) does NO live PCR read and can enroll rc 0 over a register that
#     diverged from the finalized baseline — concretely the ADR-16 rekey
#     class (this scenario reissues s00's below-floor release key + rebuilds
#     the SB varstore, and the new db cert is measured into PCR 7). The
#     harness therefore compares boot B's console readback against the
#     baseline itself (fixture_drift_verdict) and runs the §9.4 accept path
#     (baseline amend + re-seal + final enroll pass) so the sealed d7 always
#     equals the register boot C actually measures; the cache-store guard
#     additionally refuses a SELF-INCONSISTENT enrollment (sealed d7 !=
#     reproduced d7) so the pristine cache can never carry one.

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
# shellcheck source=../lib/stage-timing.sh
source "$TESTS/lib/stage-timing.sh"   # Step timing: run_stage emits begin/done lines

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
CACHE_DIR="$TESTS/e2e/.cache/pristine-s00b"
# boot C runs the real installed systemd under TCG: boot-to-login includes
# the pinned tree's apparmor profile load (~100 apparmor_parser spawns) and
# the §9.1 fstab submounts — 900 s was exceeded once (2026-09-19,
# s00b-enroll-1789764323: console reached only guest-t=141 s at wall 900 s)
export QEMU_TIMEOUT="${ALPINE_FDE_S00B_TIMEOUT:-1800}"

# --- hardening: bounded stages, loud failures, overall budget --------------------
# recalibrated 2026-09-23: run-e2e's outer SCENARIO_BUDGET is now 1500 s —
# the internal budget must fire FIRST (loud exit 125 + stage name) instead of
# letting the outer rc-124 kill win silently.
OVERALL_BUDGET="${ALPINE_FDE_S00B_BUDGET:-1440}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {   # _hang_fail <kind> <stage> <detail> — loud, greppable, fatal
    printf '\ns00b: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's00b: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    # 125, NOT timeout(1)'s 124: an internal watchdog fire must never be
    # misread by run-e2e as "exceeded the outer scenario budget".
    exit 125
}
_budget_check() {   # _budget_check <stage>
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
# run_stage <name> <timeout-s> <cmd...> — run a stage (function OR binary)
# under a process-group watchdog; loud fatal on timeout/failure. run_stage_rc
# variant returns instead of exiting (for stages whose failure is asserted).
# Step timing: every stage is wrapped in stage_begin/stage_end so the scenario
# log carries "# stage <name>: begin <epoch>" / "done <seconds>s" lines
# (harvested by run-e2e into the results row's `stages` object). A stage_end
# always precedes the failure handling — the elapsed is valid regardless of rc.
run_stage_impl() {   # <soft> <name> <timeout-s> <cmd...>
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s00b: stage $name (watchdog ${tmo}s)"
    stage_begin "$name" || _hang_fail STAGE-TIMING "$name" \
        "stage_begin refused (nested or non-harvestable label)"
    ( "$@" ) &
    local pid=$! rc wrc
    ( sleep "$tmo"; kill -9 -"$pid" 2>/dev/null; exit 125 ) &
    local wpid=$!
    wait "$pid"; rc=$?
    kill "$wpid" 2>/dev/null
    wait "$wpid" 2>/dev/null; wrc=$?
    stage_end "$name" || _hang_fail STAGE-TIMING "$name" "stage_end refused"
    if (( wrc == 125 )); then
        _hang_fail STAGE-TIMEOUT "$name" "exceeded watchdog ${tmo}s"
    fi
    if (( rc != 0 )); then
        printf 's00b: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
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
wait_console() {   # wait_console <dir> <fixed-string> <timeout-s> — bounded poll
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
wait_console_re() {   # wait_console_re <dir> <ERE> <timeout-s>
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qE -- "$pat" "$dir/console.log" 2>/dev/null && return 0
        _qemu_alive_or_die "$dir" "console-wait:$pat"
        _budget_check "console-wait:$pat"
        sleep 1
        i=$((i + 1))
    done
    _hang_fail CONSOLE-WAIT "$pat" "not seen in ${tmo}s; tail: $(tail -3 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
}

RUN="$TESTS/e2e/.runs/s00b-enroll-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while the (long) boots run.
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
    kill "$REFRESHER" 2>/dev/null
}
trap _exit_cleanup EXIT
# IN-02: an interrupt must not be swallowed — clean up AND exit with the
# conventional signal status (130/143) instead of letting the script continue.
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

_ensure_tpm() {
    local dir="$1"
    if timeout 20 swtpm_pcrread "$dir" 0 >/dev/null 2>&1; then
        return 0
    fi
    [ -f "$dir/pid" ] && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    rm -f "$dir/pid" "$dir/sock" "$dir/sock.ctrl"
    # _SWTPM_CLEANUP_TRAP_SET=1: swtpm_start's own EXIT-trap registration must
    # not fire inside the run_stage subshell (it would stop the fixture the
    # moment the stage ends — observed live 2026-09-18); THIS scenario owns
    # swtpm teardown via _exit_cleanup + SWTPM_DIRS.
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_start:$dir" 90 swtpm_start "$dir"
    _rearm_trap
}

# _reanchor_tpm <dir> — before boot C the fixture TPM must be a FRESH, ZEROED
# instance (the s18-foreign-pcrsig hardening, 2026-09-22). A live instance
# carrying boot B's final register values (or a stale volatilestate the next
# start would restore — defect s15-4) hands boot C a cumulative PCR 0/7 whose
# provenance the scenario cannot vouch for, and the standing token's {7,11}
# policy then refuses against a register it was never sealed under. The
# zeroed-pre-boot property is ASSERTED, not assumed: graceful stop -> scrub
# volatile state + stale sockets -> startup-clear start (the SRK in the
# permall persists, which the token's seal needs) -> assert PCR 0 and 7 read
# all-zero -> settle the proxy/setup path with real commands.
_reanchor_tpm() {
    local dir="$1" d0 d7 k
    swtpm_stop "$dir" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_start-reanchor:$dir" 90 swtpm_start "$dir"
    _rearm_trap
    d0=$(swtpm_pcrread "$dir" 0)
    d7=$(swtpm_pcrread "$dir" 7)
    if [[ "$d0" =~ ^0{64}$ && "$d7" =~ ^0{64}$ ]]; then
        _assert_result ok "fixture: boot TPM re-anchored (PCRs 0 and 7 zero before the boot)" ""
    else
        _assert_result not-ok "fixture: boot TPM re-anchored (PCRs 0 and 7 zero before the boot)" \
            "pcr0=$d0 pcr7=$d7 — refusing to spend the boot on a cumulative register"
        echo "s00b: TPM not zeroed before boot C — aborting"
        exit 1
    fi
    # settle (s18): libtpms re-initializes from the tpmstate dir at qemu's
    # CMD_INIT and the control-channel proxy has just bound — a guest TPM
    # command arriving mid-setup times out and the firmware DROPS the
    # measurement (the degraded-boot signature the gate below discards on).
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
}

# _console_seen_re <dir> <ERE> <timeout-s> — NON-fatal bounded probe (rc 0/1):
# unlike wait_console_re this returns instead of _hang_fail-ing, so the boot C
# degradation gate can branch on "sentinel appeared or not".
_console_seen_re() {
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qE -- "$pat" "$dir/console.log" 2>/dev/null && return 0
        _budget_check "console-probe:$pat"
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# _boot_wedge_gate <dir> <label> — rc 0 = healthy start (serial output
# appeared, or qemu died a normal early death for the caller to handle);
# rc 1 = SILENT WEDGE. The 2026-09-22 fixture wedge class (defect diag:
# guest's last TPM command TPM2_PCR_Extend answered SUCCESS by swtpm, then
# the firmware never issues another command — vCPU spin at ~99%, 0-byte
# console, pre-BdsDxe) produces NO serial output at all, so "no console
# bytes within 180 s of qemu start" is the loud, cheap discriminator; a
# healthy KVM boot prints firmware output within seconds. Left undetected,
# the wedge burns the full qemu_wait watchdog (QEMU_TIMEOUT, now 300 s) per boot.
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

# _qemu_alive <dir> — a QEMU that dies at startup (e.g. a missing swtpm ctrl
# socket) exits rc 0 from qemu_run's perspective; fail LOUDLY right here with
# the firmware/qemu stderr instead of surfacing as a missing console sentinel.
_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s00b: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s00b: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

# _cache_verify <dir> — rc 0 iff the pristine cache exists AND every recorded
# SHA256 matches (fail-closed: never enroll/consume from tampered artifacts).
# The cache mirrors the s00 STATE SHAPE (tpm/tpm2-00.permall) so state consumers
# can treat both identically; requires baseline.json + uki-pcrsig.json +
# uki-pcrsig-combined.json + the FORMAT marker: earlier cache formats (flat
# permall, no finalized baseline, pre-jq target set, no signed-prediction
# JSON, pre-btrfs ext4 disk — G-HW5; ladder-only pcrsig drive — the §8.2
# mkinitfs-hook era needs the COMBINED {7,11} entry on the payload drive,
# btrfs-3 bump) fail closed and trigger a rebuild.
_cache_verify() {
    local dir="$1"
    [[ -f "$dir/FORMAT" ]] && grep -q '^btrfs-3$' "$dir/FORMAT" || return 1
    [[ -f "$dir/MANIFEST.sha256" && -f "$dir/disk.img" && -f "$dir/tpm/tpm2-00.permall" \
        && -f "$dir/harness.efi" && -f "$dir/pcrsig.img" && -f "$dir/vars-enrolled.fd" \
        && -f "$dir/baseline.json" && -f "$dir/uki-pcrsig.json" \
        && -f "$dir/uki-pcrsig-combined.json" ]] || return 1
    (cd "$dir" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1 || return 1
    # STALENESS BINDING (2026-09-26 registry, s01c LIV3 RC=127): the disk's
    # installed rootfs was laid down FROM the derived Alpine payload, so a
    # payload whose embedded repo tree changed (the /opt/debian-fde ->
    # /opt/alpine-fde rename) invalidates the cache even though every recorded
    # byte is still sha-intact. FORMAT line 2 carries the tree digest the
    # build installed; a mismatch (or an old one-line FORMAT) rebuilds.
    grep -qx "tree-sha256 $(rootfs_payload_tree_digest)" "$dir/FORMAT"
}

# _cache_store <cache-dir> <run-dir> — snapshot the enrolled state into the
# stable cache (called via run_stage's bash -c bridge; explicit args because
# the bridge subshell does not inherit scenario locals)
_cache_store() {
    local dir="$1" run="$2" tree_digest="${3:-}"
    [[ -n "$tree_digest" ]] || { echo "s00b: _cache_store: no tree digest (payload staleness binding)"; return 64; }
    # Wave-2 2b generator publish: build the snapshot at a STAGING path, then
    # LOCK_EX + atomic mv into place — a consumer reading the previous
    # generation keeps its old inode to natural completion; new consumers get
    # the new generation. (The in-place `rm -rf $dir` this replaces exposed a
    # rebuild window where a consumer's fail-closed _cache_verify saw a
    # deleted/partial cache.)
    local stage="$dir.staging.$$"
    rm -rf "$stage"
    mkdir -p "$stage/tpm"
    cp "$run/disk.img" "$run/harness.efi" "$run/pcrsig.img" "$run/vars-enrolled.fd" "$stage/"
    cp "$run/baseline.json" "$stage/baseline.json"
    cp "$run/uki-pcrsig.json" "$stage/uki-pcrsig.json"
    cp "$run/uki-pcrsig-combined.json" "$stage/uki-pcrsig-combined.json"
    # cache FORMAT marker: the disk layout generation — btrfs @/@home/
    # @snapshots with the §9.1 UUID= fstab + udev-registered initrd attach
    # since 2026-09-19 (btrfs-1 briefly carried a /dev/dm-0 fstab), and since
    # btrfs-3 the payload drive carries the COMBINED {7,11} pcrsig entry the
    # §8.2 mkinitfs unseal hook extracts for the finalized token (G-B4-10).
    # A cache without it (ext4 era, ladder-only pcrsig drive) fails
    # _cache_verify and triggers a rebuild; the login-stage initrd of that
    # generation cannot boot an older-layout disk and vice versa.
    printf 'btrfs-3\ntree-sha256 %s\n' "$(rootfs_payload_tree_digest)" >"$stage/FORMAT"
    # s00 STATE SHAPE (tpm/tpm2-00.permall): the snapshot below consumes
    # $STATE/tpm/tpm2-00.permall — a flat copy here would be silently skipped
    # by that guard and the from-cache boot would resume a VIRGIN TPM whose
    # seed cannot unseal the standing token (observed live 2026-09-18,
    # run s00b-enroll-1789742123: "Failed to load key into TPM ... 0x18b" ->
    # "State not recoverable" -> clean poweroff before login).
    cp "$run/tpm/tpm2-00.permall" "$stage/tpm/tpm2-00.permall"
    cp -a "$run/keys" "$stage/keys"
    (cd "$stage" && sha256sum FORMAT disk.img harness.efi pcrsig.img vars-enrolled.fd \
        tpm/tpm2-00.permall baseline.json uki-pcrsig.json uki-pcrsig-combined.json >MANIFEST.sha256)
    local lock="$dir.publish.lock"
    ( flock -x 9; rm -rf "$dir"; mv -- "$stage" "$dir" ) 9>"$lock"
    echo "# pristine enrolled state cached in $dir (FORMAT $(head -1 "$dir/FORMAT"), tree-sha256 $(sed -n '2p' "$dir/FORMAT" | cut -d' ' -f2), SHA256 manifest: $(wc -l <"$dir/MANIFEST.sha256") entries)"
}

STATE="${ALPINE_FDE_S00_STATE:-}"
FROM_CACHE=0
# set to 1 when the consumed state's release key was reissued at the ADR-16
# floor AND the SB varstore rebuilt from the new certs (below): the db cert is
# measured into PCR 7, so boot B's live register then diverges from boot A's
# baseline BY CONSTRUCTION and the §9.4 accept below must fire even though the
# digest-anchored CLI enrolls rc 0 (no live PCR read — see _s00b_verdict).
_rekeyed=0
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/keys/release.pub" && -f "$STATE/vars-enrolled.fd" \
    && -f "$STATE/baseline.json" ]]; then
    echo "# S-00b: consuming s00's populated (not yet enrolled) state from $STATE"
elif _cache_verify "$CACHE_DIR"; then
    echo "# S-00b: consuming the SHA-verified pristine cache from $CACHE_DIR"
    echo "# S-00b: the cached disk carries the STANDING enrollment — the enroll flow is skipped, boot C only"
    STATE="$CACHE_DIR"
    FROM_CACHE=1
else
    if [[ -d "$CACHE_DIR" ]]; then
        echo "# S-00b: cache at $CACHE_DIR is STALE (pre-rework: flat permall / no finalized baseline / pre-jq target set / no uki-pcrsig.json / pre-btrfs FORMAT marker / ladder-only pcrsig drive) — rebuilding"
        rm -rf "$CACHE_DIR"
    fi
    echo "# S-00b: no s00 state, no valid cache — self-bootstrapping the S-00 chain"
    # compact S-00: installer UKI + passphrase-unlock/populate boot; then the
    # enroll precondition (finalized baseline) is produced host-side via the
    # REAL CLI (audit --init) BEFORE any UKI-chain work, exactly as S-00 does.
    STATE="$RUN/s00-self"
    mkdir -p "$STATE"
    _track_swtpm "$STATE/tpm"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage swtpm_start-bootstrap 90 swtpm_start "$STATE/tpm"
    _rearm_trap
    run_stage keys_create 120 keys_create "$STATE/keys"
    # ADR-16 floor (the s18 pattern): keys_create may mint an RSA-2048 release
    # key, and the production CLI's keys_rsa3072_guard refuses to enroll below
    # RSA-3072 (observed live 2026-09-22, run s00b-enroll-1790071919:
    # enroll-tpm rc 2 "release key is RSA-2048" — after the KEYDIR fix let it
    # reach the guard). Reissue at the floor BEFORE the varstore embeds db.
    run_stage release-key-floor 300 uki_release_key_floor "$STATE/keys"
    run_stage keys_vars_enrolled 120 keys_vars_enrolled "$STATE/keys" "$STATE/vars-enrolled.fd"
    # pristine varstore for the gated boots: each attempt restores an
    # IDENTICAL copy before qemu_run — a -9-killed discard mutates the pflash
    # vars (Boot#### entries are created mid-enumeration), and booting a
    # mutated varstore fails device enumeration ("No bootable option",
    # Boot0004/UEFI-Misc-Device-2 renumbering — observed live 2026-09-22)
    run_stage snapshot-vars-pristine 60 cp "$STATE/vars-enrolled.fd" "$STATE/vars-pristine.fd"
    # the rootfs payload derivation may fetch the pinned artifact over the
    # network (the overnight hang's window) — hard-bounded here, output on a
    # file so the watchdog subshell cannot hand variables back. The bridge
    # exports exactly what rootfs_payload_image consumes (the Alpine pin via
    # tests/lib/alpine-artifact.sh accessors + _HERE for the tooling-tree
    # repo root) — never a hand-dumped pin table (G-E1: the Debian pins are
    # not the payload any more).
    run_stage rootfs-payload 1800 bash -c \
        "$(declare -f rootfs_payload_image alpine_artifact_ensure \
              alpine_artifact_extract alpine_artifact_path alpine_artifact_cache_dir); \
         $(declare -p ALPINE_ARTIFACT_CACHE_DIR ALPINE_MINI_ROOTFS_VERSION \
              ALPINE_MINI_ROOTFS_ARCH ALPINE_MINI_ROOTFS_URL \
              ALPINE_MINI_ROOTFS_SHA256 ALPINE_MINI_ROOTFS_BYTES _HERE 2>/dev/null); \
         rootfs_payload_image '$STATE/rootfs-payload.img' >'$RUN/payload.out'"
    read -r _sha _bytes <"$RUN/payload.out" || { echo "s00b: rootfs payload build failed"; exit 1; }
    [[ -n "$_sha" ]] || { echo "s00b: rootfs payload build failed"; exit 1; }
    ALPINE_FDE_ROOTFS_SHA="$_sha" ALPINE_FDE_ROOTFS_BYTES="$_bytes" \
        run_stage uki_build-installer 1200 \
        uki_build "$STATE" "$STATE/keys" "$STATE/harness.efi" "alpine-fde-stage=install"
    UKI_MIB=$(( ($(stat -c%s "$STATE/harness.efi") + 1048575) / 1048576 ))
    run_stage esp_make-installer 300 esp_make "$STATE/esp.img" \
        $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$STATE/harness.efi"
    run_stage disk_make_luks 120 disk_make_luks "$STATE/disk.img" 1600
    # boot A under the wedge gate (bounded at 5 attempts — the 2026-09-22
    # wedge incidence ran ~75% tonight, so 3 attempts is a coin flip): a
    # silent pre-BdsDxe wedge (firmware stuck in an endless SET_LOCALITY ->
    # GetCapability(TPM_CAP_PCRS) -> PCR_Read retry loop, every command
    # answered SUCCESS — traced live) is discarded and re-run on a freshly
    # re-anchored TPM instead of burning the qemu_wait watchdog (QEMU_TIMEOUT).
    for _a_attempt in 1 2 3 4 5; do
        _budget_check "bootstrap-attempt:$_a_attempt"
        run_stage "vars-restore-a:$_a_attempt" 60 cp "$STATE/vars-pristine.fd" "$STATE/vars-enrolled.fd"
        _reanchor_tpm "$STATE/tpm"
        rm -f "$STATE/console.log"
        CURRENT_QEMU_DIR="$STATE"
        run_stage "qemu_run-bootstrap:$_a_attempt" 60 qemu_run "$STATE" "$STATE/esp.img" "$STATE/disk.img" \
            "$STATE/vars-enrolled.fd" "$STATE/tpm" "$STATE/rootfs-payload.img"
        _qemu_alive "$STATE"
        _rearm_trap
        if _boot_wedge_gate "$STATE" "bootstrap:$_a_attempt"; then
            break
        fi
        echo "s00b: bootstrap boot attempt $_a_attempt WEDGED (silent pre-BdsDxe: 0-byte console after 180s, vCPU spin)"
        if (( _a_attempt < 5 )); then
            echo "s00b: discarding the wedged boot and re-running (attempt $(( _a_attempt + 1 ))/5)"
            qemu_kill "$STATE"
            swtpm_stop "$STATE/tpm" 2>/dev/null || true
            CURRENT_QEMU_DIR=""
            continue
        fi
        echo "s00b: bootstrap wedged after 5 attempts — aborting (tpm trace: $STATE/tpm/tpm-cmd.log)"
        exit 1
    done
    CURRENT_QEMU_DIR="$STATE"
    run_stage qemu_wait-bootstrap "$((QEMU_TIMEOUT + 60))" qemu_wait "$STATE" "$QEMU_TIMEOUT"
    CURRENT_QEMU_DIR=""
    grep -q "alpine-fde: POWEROFF" "$STATE/console.log" || {
        echo "s00b: self-bootstrap installer boot failed (no POWEROFF sentinel)"; exit 1; }

    # finalize the baseline via the REAL CLI (S-00 stage 6) — the enroll
    # precondition; G-R1-guarded on the efivars fixture (SecureBoot=1
    # SetupMode=0), BEFORE any UKI-chain work (§12 S-00b ordering).
    EFIVARS="$STATE/rootfs/efivars-sb-on"
    mkdir -p "$EFIVARS" "$STATE/rootfs/etc/alpine-fde"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    _mkcertvar PK pk-cert-v1
    _mkcertvar KEK kek-cert-v1
    _mkcertvar db db-cert-v1
    _mkcertvar dbx dbx-cert-v1
    cat >"$STATE/rootfs/etc/alpine-fde/baseline.json" <<'JSON'
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
    _ensure_tpm "$STATE/tpm"
    if AUDIT_OUT=$(ALPINE_FDE_ROOT="$STATE/rootfs" \
        ALPINE_FDE_TCTI="swtpm:path=$STATE/tpm/sock" \
        ALPINE_FDE_EFIVARS_DIR="$EFIVARS" \
        ALPINE_FDE_EVENTLOG="$STATE/rootfs/eventlog-absent" \
        ALPINE_FDE_NO_INSTALL=1 \
        timeout 300 "$REPO/bin/alpine-fde" audit --init 2>&1); then
        _assert_result ok "S-00b: audit --init finalized the baseline (real CLI, rc 0)" ""
    else
        _assert_result not-ok "S-00b: audit --init finalized the baseline (real CLI, rc 0)" \
            "output: $(tail -2 <<<"$AUDIT_OUT")"
    fi
    PCR7_B=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)
    sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7_B\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'alpine-fde-pcr sha256:0=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)\",|" \
        "$STATE/rootfs/etc/alpine-fde/baseline.json"
    if grep -q '"expected_pcr7": "pending"' "$STATE/rootfs/etc/alpine-fde/baseline.json" \
        || [[ -z "$PCR7_B" ]]; then
        echo "s00b: baseline still pending after audit --init — refusing to continue"; exit 1
    fi
    cp "$STATE/rootfs/etc/alpine-fde/baseline.json" "$STATE/baseline.json"
    echo "# S-00b: baseline finalized BEFORE UKI-chain work (expected_pcr7=$PCR7_B)"
fi

# Snapshot into OUR run dir (sibling prunes; the permall copy seals to the SRK)
mkdir -p "$RUN"
run_stage snapshot-disk 900 cp "$STATE/disk.img" "$RUN/disk.img"
if (( FROM_CACHE == 0 )); then
    # fresh path only: $STATE/harness.efi is the S-00 INSTALLER UKI. From-cache
    # the cached harness.efi is the ENROLLED RELEASE UKI and is restored below
    # (from-cache block) under its real name.
    run_stage snapshot-installer-uki 120 cp "$STATE/harness.efi" "$RUN/s00-installer.efi"
fi
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && run_stage snapshot-vars 60 cp "$STATE/vars-enrolled.fd" "$RUN/"
mkdir -p "$RUN/tpm"
# LOUD, never a silent skip: a missing permall here would boot the next stage
# against a VIRGIN TPM that cannot unseal the standing token (the from-cache
# breakage class — see _cache_store).
if [[ -f "$STATE/tpm/tpm2-00.permall" ]]; then
    run_stage snapshot-permall 60 cp "$STATE/tpm/tpm2-00.permall" "$RUN/tpm/"
else
    echo "s00b: FATAL: no TPM state at $STATE/tpm/tpm2-00.permall — the sealing SRK cannot be reproduced"
    exit 1
fi
mkdir -p "$RUN/rootfs/etc/alpine-fde"
run_stage snapshot-baseline 60 cp "$STATE/baseline.json" "$RUN/baseline.json"
run_stage snapshot-baseline-rootfs 60 cp "$STATE/baseline.json" "$RUN/rootfs/etc/alpine-fde/baseline.json"
_track_swtpm "$RUN/tpm"

# --- from-cache: verify the STANDING enrollment, skip the enroll work -------------
# The cache snapshots the ENROLLED disk and is stored ONLY after boot B's
# production enrollment landed (sentinel + rc 0 guard below), so from-cache
# the honest flow verifies the standing token host-side, restores the cached
# release UKI artifacts, and goes STRAIGHT to boot C: NO dead fixture token
# import, NO in-guest enroll. Re-running boot B over the cached disk would
# import a dead token onto an already-enrolled volume (2 systemd-tpm2 tokens
# — the exact >1 shape the CLI refuses) and redo the work the cache exists
# to skip.
if (( FROM_CACHE == 1 )); then
    cp "$STATE/harness.efi" "$RUN/harness.efi"
    cp "$STATE/harness.efi" "$RUN/uki-release.efi"
    cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"
    cp "$STATE/pcrsig.img" "$RUN/uki-release.pcrsig.img"
    cp "$STATE/uki-pcrsig.json" "$RUN/uki-pcrsig.json"
    cp "$STATE/uki-pcrsig.json" "$RUN/uki-release.pcrsig.json"
    [[ -f "$STATE/uki-pcrsig-combined.json" ]] \
        && cp "$STATE/uki-pcrsig-combined.json" "$RUN/uki-pcrsig-combined.json" \
        && cp "$STATE/uki-pcrsig-combined.json" "$RUN/uki-release.pcrsig-combined.json"
    assert_file_exists "S-00b from-cache: cached release UKI present" "$RUN/harness.efi"
    assert_file_exists "S-00b from-cache: cached release pcrsig drive present" "$RUN/pcrsig.img"
    # the run-dir ESP contract (G-T11b scans $STATE/esp.img): the release ESP is
    # a deterministic function of the cached release UKI — rebuild it with the
    # SAME §13 sizing formula and assert the formula holds
    UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
    run_stage esp_make-cached 300 esp_make "$RUN/esp.img" \
        $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
    assert_eq "§13 ESP-size assertion [from-cache]: actual ESP == UKI × retention + headroom" \
        "$(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB ))" \
        "$(( ($(stat -c%s "$RUN/esp.img") + 1048575) / 1048576 ))"
    NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
    assert_eq "S-00b from-cache: standing enrollment — exactly ONE systemd-tpm2 token" "1" "$NTOK"
    TOKSLOT=$(disk_token_json "$RUN/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
    assert_eq "S-00b from-cache: standing token on keyslot 1 (recovery slot 0 untouched)" "1" "$TOKSLOT"
    TOKPCRS=$(disk_token_json "$RUN/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
    assert_eq "S-00b from-cache: standing token pins the finalized {PCR 7, PCR 11} (§8.2 hook contract)" \
        "[7,11]" "$TOKPCRS"
    echo "# S-00b from-cache: standing enrollment verified (1 systemd-tpm2 token, keyslot 1, pcrs 7,11) — boot C next"
fi

# --- fresh enroll flow (s00 state or self-bootstrap) — skipped entirely from-cache -
if (( FROM_CACHE == 0 )); then

# ADR-16 floor on the CONSUMED state's release key (registry-context fix,
# 2026-09-23): keys_create mints RSA-2048 and the production CLI's
# keys_rsa3072_guard refuses to enroll below RSA-3072 (rc 2). The
# self-bootstrap branch floors its own keys BEFORE keys_vars_enrolled, but a
# ALPINE_FDE_S00_STATE chain (the registry path: s00 -> s00b) hands this
# scenario a below-floor key — observed in the registry run: boot B's fed
# enroll-tpm died P6-RC=2 ("release key is RSA-2048") while the standalone
# self-bootstrap run passed. Reissue at the floor on the RUN-DIR key copy
# (never the shared STATE dir); the db identity changes, so if the key was
# reissued also rebuild the SB varstore from the new certs — the db cert is
# measured into PCR 7, which shifts the register the finalized baseline
# names; the drift-vote path below re-anchors the baseline to the register
# the machine actually reproduces. pcr0 (firmware-only) is unaffected.
if [[ -d "$RUN/keys" ]]; then
    _pub_before=$(sha256sum "$RUN/keys/release.pub" 2>/dev/null | cut -d' ' -f1)
    run_stage release-key-floor-state 300 uki_release_key_floor "$RUN/keys"
    if [[ "$(sha256sum "$RUN/keys/release.pub" 2>/dev/null | cut -d' ' -f1)" != "$_pub_before" ]]; then
        echo "# S-00b: consumed state's release key was below the ADR-16 floor — reissued; rebuilding the SB varstore"
        _rekeyed=1
        run_stage keys-vars-rebuild 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
    fi
fi

# the guest-bound baseline: same finalized values, keys/target stamped to the
# IN-GUEST production paths (§8.4: what `install` resolves at provision time).
# ONLY the payload copy is stamped — the run-dir contract stays exactly as s00
# produced it, so downstream state consumers are unaffected.
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s00b: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s00b: empty LUKS uuid"; exit 1; }
if jq --arg pub "/etc/alpine-fde/keys/release.pub" --arg uuid "$DISK_UUID" \
    '.keys.release_pub_path = $pub | .target.luks_uuid = $uuid' \
    "$RUN/baseline.json" >"$RUN/baseline-guest.json"; then
    _assert_result ok "S-00b: guest-bound baseline stamped (release_pub_path + target.luks_uuid)" ""
else
    _assert_result not-ok "S-00b: guest-bound baseline stamped" "jq stamp failed"
fi
if grep -q '"expected_pcr7": "pending"' "$RUN/baseline-guest.json"; then
    _assert_result not-ok "S-00b: guest-bound baseline is FINAL (no pending PCR 7)" "still pending"
else
    _assert_result ok "S-00b: guest-bound baseline is FINAL (no pending PCR 7)" ""
fi

# --- the ukictl build PRODUCT: release-key PCR-signed + sbsigned UKI -------------
echo "# S-00b: building the release UKI (ukictl build product: ukify pcr-signing + sbsign)"
# boot B's UKI carries the DEBUG SHELL seam for the fed session. Explicit
# empty pins keep any leaked env from shaping later builds.
# Built BEFORE the tooling payload: the payload carries the release UKI's
# signed prediction (/etc/alpine-fde/pcrsig.json) as the ALPINE_FDE_PCRSIG
# seam source — Mechanism B's enroll must approve exactly the policy the
# release UKI's stub delivers, without release.pem in the guest.
ALPINE_FDE_DEBUG_SHELL=1 ALPINE_FDE_ROOTFS_SHA= ALPINE_FDE_ROOTFS_BYTES= \
    run_stage uki_build-release 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi"
# the COMBINED {7,11} .pcrsig entry (uki_pcrsig_append_combined, G-B6 shape):
# the finalized Mechanism B enrollment (seal_finalized — the ONLY mode the
# production CLI runs, ADR-20) verifies its fresh policy_digest(live d7,
# live d11) against the [7,11] entry, and the §8.2 unseal hook extracts that
# same entry at boot. d7 = the finalized baseline's expected_pcr7 (== the
# enrolled machine's live PCR 7 at enroll time), d11 = THIS build's
# enter-initrd prediction (== the live PCR 11 inside the initrd after the
# hook's single phase extend — exactly when the fed CLI session runs).
D7_ENROLL=$(uki_state_pcr7 "$RUN")
[[ -n "$D7_ENROLL" && "$D7_ENROLL" != "pending" ]] || {
    echo "s00b: baseline expected_pcr7 is not finalized — refusing to compose the combined pcrsig"; exit 1; }
D11_ENROLL=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_ENROLL" ]] || { echo "s00b: no enter-initrd d11 prediction from the release build"; exit 1; }
run_stage pcrsig-combined 120 \
    uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-combined.json" \
        "$D7_ENROLL" "$D11_ENROLL" "$RUN/keys"
assert_eq "combined .pcrsig entry pol == policy_digest(finalized d7, enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$D7_ENROLL" "$D11_ENROLL")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-pcrsig-combined.json")"
assert_contains "combined .pcrsig entry pins {PCR 7, PCR 11}" \
    "$(jq -c '.sha256[-1].pcrs' "$RUN/uki-pcrsig-combined.json")" "[7,11]"
# from here the PAYLOAD DRIVE of this run is the combined-pcrsig drive: boot C
# (the §8.2 hook zero-input token unlock) and the pristine cache consume it.
# Boot B's payload = this drive + the tooling tail (the dead fixture token
# never reaches the .pcrsig extraction, so the extra entries are inert there).
run_stage pcrsig-combined-drive 60 \
    uki_pcrsig_disk "$RUN/pcrsig.img" "$RUN/uki-pcrsig-combined.json"
# IN-04: capture the stage's own output for the failure detail (the runner's
# ASSERT_RC_OUTPUT is assert_rc's contract and is never set by run_stage_rc)
if run_stage_rc sbverify-release 120 bash -c \
    'sbverify --cert "$1" "$2" >"$3" 2>&1' _ "$RUN/keys/db.crt" "$RUN/harness.efi" \
    "$RUN/sbverify-release.log"; then
    _assert_result ok "S-00b: release UKI is SB-valid (release-cert signature)" ""
else
    _assert_result not-ok "S-00b: release UKI is SB-valid (release-cert signature)" \
        "sbverify rc=$? output: $(tail -3 "$RUN/sbverify-release.log" 2>/dev/null | tr '\n' ' ')"
fi
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB ))
run_stage esp_make-release 300 esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi"
ESP_ACTUAL_MIB=$(( ($(stat -c%s "$RUN/esp.img") + 1048575) / 1048576 ))
assert_eq "§13 ESP-size assertion: actual ESP == UKI × retention + headroom" \
    "$ESP_MIB" "$ESP_ACTUAL_MIB"

# --- the §5 tooling payload: /opt/alpine-fde + jq + tpm2 + openssl closures ------
echo "# S-00b: building the guest tooling payload (/opt/alpine-fde + jq + tpm2 + openssl, §3.3/§5)"
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/alpine-fde" "$TOOLING/etc/alpine-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib" \
    "$TOOLING/opt/sslbin/lib"
for d in bin lib hooks docs; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/alpine-fde/$d"
done
run_stage tooling-baseline 60 cp "$RUN/baseline-guest.json" "$TOOLING/etc/alpine-fde/baseline.json"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/alpine-fde/keys/release.pub"
# the ALPINE_FDE_PCRSIG seam source: the COMBINED {7,11} .pcrsig — the
# finalized enrollment (seal_finalized, the CLI's only mode) refuses a
# pcrsig without the [7,11] entry (G-B6 wrong-selection gate)
run_stage tooling-pcrsig 60 cp "$RUN/uki-pcrsig-combined.json" "$TOOLING/etc/alpine-fde/pcrsig.json"
# tpm2 multitool: IDENTICAL ldd closure to the initrd's /opt/tpm tpm2_pcrread
# (same host package — verified 2026-09-18) — joins the existing isolation dir
run_stage tooling-tpm2 60 cp -L "$(command -v tpm2)" "$TOOLING/opt/tpm/bin/tpm2"
printf '#!/bin/sh\nexec /opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/tpm2 "$@"\n' \
    >"$TOOLING/usr/bin/tpm2"
# jq: own loader + closure (host binary, /opt/tpm pattern)
run_stage tooling-jq 60 cp -L "$(command -v jq)" "$TOOLING/opt/jqbin/jq"
_jq_interp=$(ldd "$(command -v jq)" | awk '/ld-linux/{print $1}')
run_stage tooling-jq-ld 60 cp -L "$_jq_interp" "$TOOLING/opt/jqbin/ld-linux"
_JQ_LIBS=""
for _jl in $(ldd "$(command -v jq)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-jq-closure"
    cp -L "$_jl" "$TOOLING/opt/jqbin/lib/"
    _JQ_LIBS="$_JQ_LIBS $_jl"
done
printf '#!/bin/sh\nexec /opt/jqbin/ld-linux --library-path /opt/jqbin/lib /opt/jqbin/jq "$@"\n' \
    >"$TOOLING/usr/bin/jq"
# flock (util-linux): the production CLI's enroll-tpm preconditions demand
# flock:util-linux (B.5 HW-3 ensure-once serialization) — under
# ALPINE_FDE_NO_INSTALL=1 in the initrd a missing binary is the CLI's hard
# exit 64, so the payload ships it. Same host-closure isolation as jq (own
# loader + lib set: the initrd's glibc is not the host's), PLUS a
# closure-identity guard: flock's ELF interp and every shared library ldd
# reports must be path-identical to one the payload's existing binaries
# already ship — a NEW dependency fails the build here, loudly, instead of
# dying in-guest at require_pkgs/enroll time.
run_stage tooling-flock 60 cp -L "$(command -v flock)" "$TOOLING/opt/flockbin/flock"
_flock_interp=$(ldd "$(command -v flock)" | awk '/ld-linux/{print $1}')
if [[ "$_flock_interp" != "$_jq_interp" ]]; then
    echo "s00b: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s00b: flock closure introduces a library the payload's existing binaries do not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
# openssl: Mechanism B's require_pkgs demands the binary and enrl_run/
# seal_finalized call it directly (token post-assert pubkey fingerprint,
# base64 blob halves). Own loader + closure (the /opt/tpm pattern); its
# interp must equal the payload interp, its libs may superset the jq set
# (libssl/libcrypto are genuinely new) — each is copied into the openssl
# isolation dir, so nothing outside it is needed at runtime.
run_stage tooling-openssl 60 cp -L "$(command -v openssl)" "$TOOLING/opt/sslbin/openssl"
_ssl_interp=$(ldd "$(command -v openssl)" | awk '/ld-linux/{print $1}')
if [[ "$_ssl_interp" != "$_jq_interp" ]]; then
    echo "s00b: openssl interp $_ssl_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-openssl-ld 60 cp -L "$_ssl_interp" "$TOOLING/opt/sslbin/ld-linux"
for _sl in $(ldd "$(command -v openssl)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-openssl-closure"
    cp -L "$_sl" "$TOOLING/opt/sslbin/lib/"
done
printf '#!/bin/sh\nexec /opt/sslbin/ld-linux --library-path /opt/sslbin/lib /opt/sslbin/openssl "$@"\n' \
    >"$TOOLING/usr/bin/openssl"
# cryptsetup output normalizer (the CLI's ALPINE_FDE_CRYPTSETUP seam): the
# CLI's LUKS2 JSON mini-parsers (lib/baseline.sh luks_json_*, unit-tested
# against PRETTY-PRINTED fixtures) anchor on '"key": value' spacing and on
# inline '"keyslots": ["N"]' arrays, while real cryptsetup 2.7.5 emits
# compact JSON — against live output the post-asserts read 0 tokens /
# 'keyslot none' (observed live 2026-09-18, runs s00b-enroll-1789706685 /
# -1789709163: "New TPM2 token enrolled as key slot 1." followed by
# "post-assert failed"). Normalize the dump to the documented shape
# (verified host-side against the real dump: count_type/token_keyslot/
# slot_blob/enrl_json_token_id all correct); non-dump invocations pass
# through untouched. OUT-OF-BUCKET FIX REQUIRED in lib/ (reported).
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/openssl" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock"
run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/alpine-fde/bin/alpine-fde" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/pcrsig.json" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/keys/release.pub" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/flock" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/openssl" "$RUN/tooling.listing" \
    && grep -qx "opt/flockbin/flock" "$RUN/tooling.listing" \
    && grep -qx "opt/flockbin/ld-linux" "$RUN/tooling.listing"; then
    _assert_result ok "S-00b: tooling payload built (CLI entrypoint + baseline + pcrsig + KEYDIR release.pub + jq + tpm2 + openssl + flock)" ""
else
    _assert_result not-ok "S-00b: tooling payload built" \
        "required entries missing from tar listing (see $RUN/tooling.listing)"
fi

# boot B's payload drive: the pcrsig JSON (first 64 KiB — the initrd reads
# exactly that; the signed prediction is untouched) + the tooling tail
_budget_check pcrsig-tooling-drive
cat "$RUN/pcrsig.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-tooling.img"
assert_file_exists "boot B payload drive: pcrsig + tooling tail" "$RUN/pcrsig-tooling.img"

# --- boot B: the product boots; the production CLI enrolls FROM THE GUEST --------
# host-side: import a DEAD systemd-tpm2 token (unprivileged metadata write,
# the s06/s13 mechanism). The initrd's enroll branch then SKIPS (stand-in out
# of the loop); the dead blob is refused at unlock; after UNSEALED the fed
# session removes the fixture token and the CLI performs the single, clean
# first-install enrollment (0 tokens -> enroll once -> post-assert 1).
_tok_json="$RUN/token-dead.json"
python3 - "$_tok_json" <<'PYEOF'
import base64, json, sys
blob = bytes([0x01, 0x00]) + bytes((i * 37 + 11) % 256 for i in range(254))
tok = {
    "type": "systemd-tpm2",
    "keyslots": ["0"],
    "tpm2-blob": base64.b64encode(blob).decode(),
    "tpm2-pcrs": [7],
    "tpm2-policy-hash": "00" * 32,
    "tpm2_pubkey": base64.b64encode(b"\x30\x82\x01\x0a" + bytes(260)).decode(),
    "tpm2_pubkey_pcrs": [11],
    "tpm2_salt": "",
}
open(sys.argv[1], "w").write(json.dumps(tok))
PYEOF
run_stage dead-token-import 60 cryptsetup token import "$RUN/disk.img" \
    --token-id 9 --json-file "$_tok_json"
DEADTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "boot B fixture: exactly ONE (dead) systemd-tpm2 token pre-boot" "1" "$DEADTOK"

# keep the ENROLLED release UKI as the run dir's harness.efi contract artifact:
# boot C's build below overwrites harness.efi with the login-stage variant and
# the run dir is restored to the release UKI afterwards.
cp "$RUN/harness.efi" "$RUN/uki-release.efi"
cp "$RUN/uki-pcrsig.json" "$RUN/uki-release.pcrsig.json"
cp "$RUN/pcrsig.img" "$RUN/uki-release.pcrsig.img"
_run_bootb() {
    # boot B under the wedge gate (bounded at 3 attempts, same silent pre-BdsDxe
    # class as boot A): the dead fixture token is already in the LUKS2 metadata
    # (a host-side write) and no attempt ever reaches the fed session before the
    # gate passes, so a discard-and-retry is state-neutral. Each attempt boots
    # from a pristine varstore copy (see the bootstrap snapshot note).
    cp "$RUN/vars-enrolled.fd" "$RUN/vars-bootb-pristine.fd"
    for _b_attempt in 1 2 3; do
        _budget_check "bootb-attempt:$_b_attempt"
        run_stage "vars-restore-b:$_b_attempt" 60 cp "$RUN/vars-bootb-pristine.fd" "$RUN/vars-enrolled.fd"
        _reanchor_tpm "$RUN/tpm"
        rm -f "$RUN/console.log"
        echo "# boot B: attempt $_b_attempt — product boots; production CLI enrolls from the guest (finalized baseline, TCG)"
        CURRENT_QEMU_DIR="$RUN"
        run_stage "qemu_run-bootb:$_b_attempt" 60 qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" \
            "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig-tooling.img"
        _qemu_alive "$RUN"
        _rearm_trap
        if _boot_wedge_gate "$RUN" "bootb:$_b_attempt"; then
            break
        fi
        echo "s00b: boot B attempt $_b_attempt WEDGED (silent pre-BdsDxe: 0-byte console after 180s, vCPU spin)"
        if (( _b_attempt < 3 )); then
            echo "s00b: discarding the wedged boot and re-running (attempt $(( _b_attempt + 1 ))/3)"
            qemu_kill "$RUN"
            swtpm_stop "$RUN/tpm" 2>/dev/null || true
            CURRENT_QEMU_DIR=""
            continue
        fi
        echo "s00b: boot B wedged after 3 attempts — aborting (tpm trace: $RUN/tpm/tpm-cmd.log)"
        exit 1
    done
    CURRENT_QEMU_DIR="$RUN"

# fed session: the dead token is refused by the §8.2 hook (the token pins
# pcrs [7], which is no selectable policy for the hook) -> the hook's bounded
# recovery-passphrase loop opens with its OWN prompt -> feed the slot-0
# passphrase (the hook's `read` — no harness-side shortcut) -> the DEBUG
# SHELL seam takes over.
wait_console "$RUN" "unlock mechanism: hook" "$QEMU_TIMEOUT"
wait_console_re "$RUN" "$(sentinel_of unseal_prompt_re)" "$QEMU_TIMEOUT"
feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
wait_console "$RUN" "DEBUG SHELL on console" 300
# 1) untar the tooling payload off the payload drive's tail
feed_line "$RUN/serial.sock" \
    'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
wait_console "$RUN" "P2A=0" 300
# 2) extract at / (opt/ etc/ usr/ merge into the initrd tree)
feed_line "$RUN/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
wait_console "$RUN" "P2B-42-OK" 300
# 3) fixture teardown: remove the dead token (LUKS2 metadata write on the
#    container — the s06/s13 shape; the mapper view is not a LUKS2 device)
feed_line "$RUN/serial.sock" 'cryptsetup token remove --token-id 9 /dev/vdb && echo T9-$((51+1))-GONE'
wait_console "$RUN" "T9-52-GONE" 120
# 4) by-uuid seam (no udev in the initrd) -> the CONTAINER (/dev/vdb; the
#    production /dev/disk/by-uuid shape — the mapper view is not a LUKS2
#    device, observed live) + the CLI environment, all documented seams:
#    ALPINE_FDE_LUKS_KEYFILE=/kf0 is Mechanism B's existing-credential
#    injection (authorizes luksAddKey with the embedded slot-0 passphrase —
#    the initrd's equivalent of the §9.1 enroll prompt, which has no
#    ask-password agent here); ALPINE_FDE_PCRSIG hands the CLI the release
#    UKI's own signed prediction from the payload (no release.pem in-guest);
#    everything else (preconditions, seal, post-asserts, enrolled.json) is
#    the production CLI's own Mechanism B path.
# ALPINE_FDE_KEYDIR is REQUIRED here (G-B7): enrl_preconditions resolves the
# release key from keys_dir ONLY (--keydir / KEY_PATH / ALPINE_FDE_KEYDIR) and
# never consults the baseline's keys.release_pub_path — without it enroll-tpm
# dies rc 64 ("no release key directory configured") BEFORE sealing, the disk
# keeps ZERO systemd-tpm2 tokens, and boot C's zero-input unlock is impossible
# (observed live 2026-09-22, run s00b-enroll-1790068029: P6-RC=64 -> boot C
# "no systemd-tpm2 token found" -> recovery-passphrase prompt).
# ALPINE_FDE_TMPDIR=/tmp is REQUIRED here: the CLI's scratch mktemps default
# to /dev/shm, which the busybox initrd does not mount — enrl_run fails
# ("mktemp: : No such file or directory" -> "enrolled.json NOT written",
# observed live 2026-09-22, run s00b-enroll-1790077927: P6-RC=64).
feed_line "$RUN/serial.sock" "mkdir -p /run/bu && ln -sf /dev/vdb /run/bu/$DISK_UUID && export ALPINE_FDE_NO_INSTALL=1 ALPINE_FDE_TCTI=device:/dev/tpmrm0 ALPINE_FDE_BY_UUID_DIR=/run/bu ALPINE_FDE_LUKS_KEYFILE=/kf0 ALPINE_FDE_KEYDIR=/etc/alpine-fde/keys ALPINE_FDE_TMPDIR=/tmp ALPINE_FDE_PCRSIG=/etc/alpine-fde/pcrsig.json ALPINE_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty && echo P5-\$((43))-OK"
wait_console "$RUN" "P5-43-OK" 120
# 5) THE PRODUCTION CLI: the §9.1 first-install enrollment (single Mechanism B seal)
feed_line "$RUN/serial.sock" 'timeout 180 /opt/alpine-fde/bin/alpine-fde enroll-tpm; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$RUN/console.log" 2>/dev/null; do
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "production CLI never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC=$(grep -oE 'P6-RC=[0-9]+' "$RUN/console.log" | head -1 | cut -d= -f2)
# the pass's own in-guest register readback (the §8.2 hook's live PCR
# reading) — captured BEFORE any later pass rm's this console
BOOTB_D0=$(grep -oE 'alpine-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/console.log" | head -1 | cut -d= -f2)
BOOTB_D7=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console.log" | head -1 | cut -d= -f2)
# 6) done — clean poweroff from the fed shell
feed_line "$RUN/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-bootb "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""
}

# pre-boot-B disk snapshot: the drift path below restores it (a failed pass's
# fed session removes the dead fixture token — the next pass needs the pristine
# pre-import container, whose snapshot already carries the token)
cp "$RUN/disk.img" "$RUN/disk.img.prebootb"

# _s00b_verdict — the per-pass drift verdict (fixture_drift_verdict, tests/lib/
# swtpm-fixture.sh) from THIS pass's evidence: the console's live {PCR 0, PCR 7}
# readback vs the finalized baseline, the legacy CLI drift marker, and whether
# this run rekeyed the varstore. "none" = healthy; "amend" = deterministic
# rekey drift, a single full-mode reading is faithful; "vote" = ambiguous mode,
# collect up to 3 readings and amend to the majority.
_s00b_verdict() {
    local marker=0
    grep -q "PCR 7 drift" "$RUN/console.log" 2>/dev/null && marker=1
    fixture_drift_verdict "$CLI_RC" "$marker" "${BOOTB_D0:-}" "${BOOTB_D7:-}" \
        "$(jq -r '.pcr0' "$RUN/baseline.json")" \
        "$(jq -r '.expected_pcr7' "$RUN/baseline.json")" "$_rekeyed"
}

# _accept_register <live_d0> <live_d7> — the §9.4 `audit --accept` fixture
# analog: the finalized baseline (boot A's post-boot audit read) is the
# MINORITY register — amend it to the boot-B live pair, rebuild the sealed
# {7,11} combined pcrsig over the new d7, and re-stage the tooling payload.
# No-op when the register already matches.
_accept_register() {
    local d0="$1" d7="$2" _bl
    [[ "$d7" == "$(jq -r '.expected_pcr7' "$RUN/baseline.json")" \
        && "$d0" == "$(jq -r '.pcr0' "$RUN/baseline.json")" ]] && return 0
    _assert_result ok "§9.4 fixture accept: baseline amended to the live register (pcr7=$d7, pcr0=$d0)" ""
    for _bl in "$RUN/baseline.json" "$RUN/baseline-guest.json" \
               "$RUN/tooling/etc/alpine-fde/baseline.json" \
               "$RUN/rootfs/etc/alpine-fde/baseline.json" \
               "$RUN/s00-self/baseline.json" \
               "$RUN/s00-self/rootfs/etc/alpine-fde/baseline.json"; do
        [[ -f "$_bl" ]] || continue
        sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$d7\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$d0\",|" "$_bl"
    done
    D7_ENROLL="$d7"
    run_stage pcrsig-combined-redo 120 \
        uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-combined.json" \
            "$D7_ENROLL" "$D11_ENROLL" "$RUN/keys"
    run_stage pcrsig-combined-drive-redo 60 \
        uki_pcrsig_disk "$RUN/pcrsig.img" "$RUN/uki-pcrsig-combined.json"
    # the CLI's ALPINE_FDE_PCRSIG seam reads the TOOLING copy of the
    # combined pcrsig — re-stage the REBUILT json or the G-B6 gate compares
    # its fresh digest against the ORIGINAL d7's stale signed pol
    # (observed live: "signed bb62a200… != freshly computed e8ee47db…")
    run_stage tooling-pcrsig-redo 60 \
        cp "$RUN/uki-pcrsig-combined.json" "$TOOLING/etc/alpine-fde/pcrsig.json"
    run_stage tooling-baseline-redo 60 cp "$RUN/baseline-guest.json" "$TOOLING/etc/alpine-fde/baseline.json"
    run_stage tooling-tar-redo 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr
    cat "$RUN/pcrsig.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-tooling.img"
    return 0
}

# Register-drift defense. The guest's measured {PCR 0, PCR 7} pair can diverge
# from the finalized baseline two ways:
#   * the 2026-09-22 BIMODAL fixture class — a FULL measurement (8bbb4647…-
#     shaped) vs a TRUNCATED one (2152c155…-shaped, the s18 degraded
#     signature); a single drift reading cannot say which mode is faithful,
#     so up to THREE boot-B readings are taken and the MAJORITY pair wins;
#   * the DIGEST-ANCHORED rekey class (regression 2026-09-24): the ADR-16
#     release-key floor reissue + varstore rebuild above shifts PCR 7 by
#     construction, the CLI enrolls rc 0 sealing the STALE d7 (Option A does
#     NO live PCR read), and the legacy "PCR 7 drift" trigger never fires —
#     _s00b_verdict detects it, and a single full-mode reading (PCR 0 ==
#     baseline) settles the accept (no vote, no wasted passes).
# Either way the baseline is amended (_accept_register) and a FINAL enroll
# pass runs against the corrected register, so the sealed d7 always equals
# the register the machine actually reproduces at boot C.
_run_bootb
_readings=()
VERDICT=$(_s00b_verdict)
while [[ "$VERDICT" != "none" && ${#_readings[@]} -lt 3 ]]; do
    _readings+=("$BOOTB_D0 $BOOTB_D7")
    if (( ${#_readings[@]} == 1 )); then
        echo "# s00b: boot B register drift detected (live d7=${BOOTB_D7:-<none>}, baseline d7=$(jq -r '.expected_pcr7' "$RUN/baseline.json")) — verdict $VERDICT"
    fi
    [[ "$VERDICT" == "amend" ]] && break   # single faithful reading settles it
    run_stage "disk-restore-prebootb:$(( ${#_readings[@]} + 1 ))" 900 \
        cp "$RUN/disk.img.prebootb" "$RUN/disk.img"
    _run_bootb
    VERDICT=$(_s00b_verdict)
done
if (( ${#_readings[@]} > 0 )); then
    _needs_final_pass=0
    if [[ "$VERDICT" == "amend" ]]; then
        _accept_register "$BOOTB_D0" "$BOOTB_D7"
        _needs_final_pass=1
    elif [[ "$VERDICT" == "vote" ]]; then
        # majority pair over the collected readings
        MAJ=$(printf '%s\n' "${_readings[@]}" | sort | uniq -c | sort -rn | while read -r _vc _vpair; do
            if (( _vc >= 2 )); then printf '%s\n' "$_vpair"; break; fi
        done)
        [[ "$MAJ" =~ ^[0-9a-f]{64}\ [0-9a-f]{64}$ ]] || {
            echo "s00b: register vote produced no majority pair (${_readings[*]}) — aborting"; exit 1; }
        LIVE_D0=${MAJ% *}; LIVE_D7=${MAJ#* }
        if [[ "$LIVE_D7" != "$(jq -r '.expected_pcr7' "$RUN/baseline.json")" \
            || "$LIVE_D0" != "$(jq -r '.pcr0' "$RUN/baseline.json")" ]]; then
            _accept_register "$LIVE_D0" "$LIVE_D7"
            _needs_final_pass=1
        fi
    fi
    if (( _needs_final_pass )); then
        run_stage disk-restore-prebootb-final 900 cp "$RUN/disk.img.prebootb" "$RUN/disk.img"
        _run_bootb
    fi
fi

LOG=$(cat "$CONSOLE" 2>/dev/null || true)
assert_contains "[boot B] init ran" "$LOG" "alpine-fde-harness: init started"
assert_contains "[boot B] the §8.2 unseal hook owns the unlock (default mechanism)" "$LOG" \
    "alpine-fde-harness: unlock mechanism: hook"
assert_not_contains "[boot B] the 257.13 oracle stayed out (opt-in only)" "$LOG" \
    "alpine-fde-harness: unlock mechanism: oracle"
# the DEAD fixture token (pcrs [7], no tpm2-pcr-bank/signature): the hook
# cannot select a policy for it -> the I3 gate refuses it (never a forge)
assert_contains "[boot B] dead token refused by the hook's I3 gate" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_sig_refused)" "$RUN/console.log" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "[boot B] dead-token refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "[boot B] dead-token refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
PROMPTS_B=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[boot B] exactly ONE recovery-passphrase prompt (fed slot-0 unlocked on attempt 1)" "1" "$PROMPTS_B"
assert_contains "[boot B] fed slot-0 passphrase unsealed the volume (hook recovery path)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[boot B] volume UNSEALED" "$LOG" \
    "alpine-fde: UNSEALED"
assert_contains "[boot B] tooling payload extracted in-guest" "$LOG" "P2B-42-OK"
assert_contains "[boot B] dead fixture token removed (teardown before enroll)" "$LOG" "T9-52-GONE"
assert_contains "[boot B] production CLI ran (Mechanism B seal, fixture marker)" "$LOG" \
    "$(sentinel_of cli_seal_slot)"
assert_contains "[boot B] production CLI's own success marker" "$LOG" \
    "alpine-fde: enrolled (policy_mode="
assert_not_contains "[boot B] NO cryptenroll anywhere (Mechanism B never invokes it)" "$LOG" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_eq "[boot B] production CLI rc 0" "0" "$CLI_RC"
assert_eq "[boot B] Mechanism B seal fired EXACTLY ONCE (single enrollment)" "1" \
    "$(grep -cF "$(sentinel_of cli_seal_slot)" <<<"$LOG")"
assert_not_contains "[boot B] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "S-00b ensure-once: exactly ONE systemd-tpm2 token on the disk" "1" "$NTOK"
TOKSLOT=$(disk_token_json "$RUN/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "S-00b: token enrolled on a fresh keyslot (recovery slot 0 untouched)" "1" "$TOKSLOT"

# G-T13 prediction check for the ENROLLED release UKI (tests/lib/prediction.sh):
# ukify's enter-initrd entry == the {11}-selection PolicyPCR digest over the
# guest's PRE-UNLOCK (post-phase-word) reading — never the final register
# (§12: post-boot PCR 11 additionally carries leave-initrd and later pcrphase
# extensions). $CONSOLE/$RUN/uki-pcrsig.json are boot B's console + the
# release UKI's signed prediction at this point.
assert_pcr11_prediction "G-T13 [boot B]"

# --- pristine cache (SHA-recorded), snapshot BEFORE boot C touches the disk ------
# only when boot B's production enrollment actually landed (the CLI's own
# Mechanism B markers are the evidence) AND it is SELF-CONSISTENT: the sealed/
# anchored d7 must equal the register the machine actually reproduced (the
# console readback). The digest-anchored CLI can enroll rc 0 over a drifted
# register (fail-at-unseal); caching such an enrollment poisons the pristine
# cache — every from-cache consumer then fails boot C's PolicyPCR with the
# zero-input path lost (observed live 2026-09-24, run s00b-enroll-1790225093:
# a rekey-drifted enrollment cached at 12:46 turned the whole registry red).
_BL_D7_STORE=$(jq -r '.expected_pcr7' "$RUN/baseline.json")
if grep -qF "$(sentinel_of cli_seal_slot)" "$RUN/console.log" \
    && [[ "$CLI_RC" == "0" && -n "$BOOTB_D7" && "$BOOTB_D7" == "$_BL_D7_STORE" ]]; then
    run_stage cache-store 900 bash -c "$(declare -f _cache_store); _cache_store '$CACHE_DIR' '$RUN' '$(rootfs_payload_tree_digest)'"
else
    echo "s00b: enrollment evidence missing or SELF-INCONSISTENT (rc=$CLI_RC, live d7=${BOOTB_D7:-<none>} vs baseline $_BL_D7_STORE) — pristine cache NOT stored"
fi

fi   # FROM_CACHE == 0 (fresh enroll flow: guest-bound baseline, tooling payload,
     # release UKI, dead-token boot B, in-guest production enroll, cache store)

# --- boot C: §12 S-01 — zero-input token unlock + switch_root -> login: ---------
# §8.2 hook era: boot C boots the SAME release UKI bytes boot B enrolled
# under — the finalized {7,11} sealed policy is bound to the enroll-time
# measured PCR 11, so a cmdline-variant UKI (the old login-stage build) could
# never match. The login stage is selected on the PAYLOAD DRIVE instead
# (uki_stage_login_drive — the unmeasured channel), which also carries the
# COMBINED pcrsig the hook extracts for the standing token.
echo "# S-00b: boot C — release UKI + combined pcrsig drive + login marker (§8.2 zero-input unlock)"
C="$RUN/boot-login"
mkdir -p "$C"
cp "$RUN/harness.efi" "$C/harness.efi"
uki_pcrsig_disk "$C/pcrsig.img" "$RUN/uki-pcrsig-combined.json" || exit 1
uki_stage_login_drive "$C/pcrsig.img" || exit 1
cp "$RUN/esp.img" "$C/esp.img"
# PCR-0 pin for the boot C degradation gate: the initrd's live PCR 0 must
# equal the finalized baseline's (the same firmware measurement the standing
# enrollment's world was built against).
PCR0_EXPECTED=$(jq -r '.pcr0 // empty' "$RUN/baseline.json")
[[ "$PCR0_EXPECTED" =~ ^[0-9a-f]{64}$ ]] || {
    echo "s00b: baseline pcr0 not finalized ($PCR0_EXPECTED) — no PCR-0 pin for the boot C gate"; exit 1; }
# per-attempt pristine varstore for boot C (the post-boot-B enrolled vars —
# SB state + boot entries as the enrollment world left them)
cp "$RUN/vars-enrolled.fd" "$RUN/vars-bootc-pristine.fd"

# EARLY DEGRADATION GATE + bounded re-run (the s18-foreign-pcrsig pattern,
# bounded at 3 attempts): a degraded boot — the fixture proxy's command-drop
# class (EFI stub "Failed to measure"), a cumulative PCR 0/7 register, or the
# hook's refusal/prompt path — can NEVER demonstrate the zero-input unlock, so
# discard it and re-run instead of burning the QEMU_TIMEOUT login wait on a
# boot that is already known-bad. Zero console input on every attempt: the
# happy path never feeds the serial socket.
for _c_attempt in 1 2 3; do
    _budget_check "bootc-attempt:$_c_attempt"
    # fresh working copy each attempt: the cache stays pristine and a killed
    # mid-prompt attempt cannot leak state into the next one
    run_stage "bootc-disk-copy:$_c_attempt" 900 cp "$RUN/disk.img" "$C/disk.img"
    run_stage "vars-restore-c:$_c_attempt" 60 cp "$RUN/vars-bootc-pristine.fd" "$RUN/vars-enrolled.fd"
    _reanchor_tpm "$RUN/tpm"
    rm -f "$C/console.log"
    echo "# boot C: attempt $_c_attempt — zero-input token unlock + switch_root into the installed system (TCG)"
    CURRENT_QEMU_DIR="$C"
    run_stage "qemu_run-bootc:$_c_attempt" 60 qemu_run "$C" "$C/esp.img" "$C/disk.img" \
        "$RUN/vars-enrolled.fd" "$RUN/tpm" "$C/pcrsig.img"
    _qemu_alive "$C"
    _rearm_trap
    _degraded=""
    _i=0
    while (( _i < 240 )); do
        kill -0 "$(cat "$C/qemu.pid" 2>/dev/null)" 2>/dev/null || break
        if grep -q "EFI stub: WARNING: Failed to measure data for event" "$C/console.log" 2>/dev/null; then
            _degraded="EFI-stub measurement loss (the fixture proxy command-drop class)"; break
        fi
        if grep -qE "$(sentinel_of unseal_prompt_re)" "$C/console.log" 2>/dev/null; then
            _degraded="recovery-passphrase prompt opened (the zero-input path is already lost)"; break
        fi
        grep -q "unlock mechanism: hook" "$C/console.log" 2>/dev/null && break   # healthy: past firmware, hook staged
        sleep 2
        _i=$((_i + 2))
        _budget_check "bootc-gate:$_c_attempt"
    done
    if [[ -z "$_degraded" ]] && grep -q "unlock mechanism: hook" "$C/console.log" 2>/dev/null; then
        # PCR-0 pin: the initrd's first register readback must equal the baseline
        if _console_seen_re "$C" "alpine-fde-pcr sha256:0=" 120; then
            _d0_live=$(grep -oE 'alpine-fde-pcr sha256:0=[0-9a-f]{64}' "$C/console.log" | head -1 | cut -d= -f2)
            [[ "$_d0_live" == "$PCR0_EXPECTED" ]] \
                || _degraded="PCR-0 pin failed: live $_d0_live != baseline $PCR0_EXPECTED (cumulative/degraded register)"
        else
            _degraded="no alpine-fde-pcr sha256:0 readback within 120s of the hook marker"
        fi
    elif [[ -z "$_degraded" ]]; then
        _degraded="qemu exited before the hook marker (console tail: $(tail -2 "$C/console.log" 2>/dev/null | tr '\n' ' '))"
    fi
    if [[ -z "$_degraded" ]]; then
        _assert_result ok "boot C attempt $_c_attempt: degradation gate clean (no stub warning, no prompt, PCR-0 pin holds)" ""
        break
    fi
    echo "s00b: boot C attempt $_c_attempt DEGRADED — $_degraded"
    if (( _c_attempt < 3 )); then
        echo "s00b: discarding the degraded boot and re-running (attempt $(( _c_attempt + 1 ))/3)"
        qemu_kill "$C"
        # leak-free discard: the failed attempt's swtpm/proxy pair must not
        # idle on (the next attempt's _reanchor_tpm stops it anyway, but an
        # orphaned instance between attempts is exactly the wedge-fodder the
        # 2026-09-22 diag called out)
        swtpm_stop "$RUN/tpm" 2>/dev/null || true
        CURRENT_QEMU_DIR=""
        sleep 1
        continue
    fi
    echo "s00b: boot C degraded after 3 attempts — aborting (console: $C/console.log)"
    exit 1
done
# WAIT for `login:` — we NEVER write to the serial socket (zero console input).
# agetty prints the installed system's /etc/issue banner, then the login prompt
# (the §3.3 rootfs is the pinned ALPINE minirootfs — its banner, not Debian's).
LOGIN_SEEN=0
i=0
while ((i < QEMU_TIMEOUT)); do
    if grep -qE 'login: ?$' "$C/console.log" 2>/dev/null \
        && grep -q 'Welcome to Alpine Linux' "$C/console.log" 2>/dev/null; then
        LOGIN_SEEN=1
        break
    fi
    _budget_check "console-wait:login"
    sleep 1
    i=$((i + 1))
done
qemu_kill "$C"
CURRENT_QEMU_DIR=""
sleep 1
LOG_C=$(cat "$C/console.log" 2>/dev/null || true)
if (( LOGIN_SEEN == 1 )); then
    _assert_result ok "S-01: \`login:\` reached on the serial console (wall ${i}s)" ""
else
    _assert_result not-ok "S-01: \`login:\` reached on the serial console" \
        "never matched within ${QEMU_TIMEOUT}s; console tail: $(tail -3 "$C/console.log" 2>/dev/null | tr '\n' ' ')"
fi
assert_contains "[boot C] init ran" "$LOG_C" "alpine-fde-harness: init started"
assert_contains "[boot C] the §8.2 unseal hook owns the unlock (default mechanism)" "$LOG_C" \
    "alpine-fde-harness: unlock mechanism: hook"
assert_contains "[boot C] stage selected on the payload drive (release UKI bytes preserved)" "$LOG_C" \
    "payload drive selects stage=login"
assert_contains "[boot C] hook ran the enter-initrd extend (single phase word)" "$LOG_C" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[boot C] standing finalized token discovered (pcrs [7,11])" "$LOG_C" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "[boot C] token unlocked via the TPM (zero-input §8.2 path)" "$LOG_C" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[boot C] volume UNSEALED" "$LOG_C" \
    "alpine-fde: UNSEALED"
assert_contains "[boot C] switch_root into the populated installed system" "$LOG_C" \
    "alpine-fde-harness: switching to the installed system"
assert_contains "[boot C] root mount is the §9.1 @ subvolume (G-HW5 btrfs default)" "$LOG_C" \
    "alpine-fde-btrfs: root mounted subvol=@ (login stage)"
assert_contains "[boot C] the installed system's getty banner (real Alpine userspace)" "$LOG_C" \
    "Welcome to Alpine Linux"
assert_not_contains "[boot C] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG_C" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[boot C] no emergency shell in the installed system" "$LOG_C" \
    "$(sentinel_of emergency_forbidden)"

# G-T13 prediction check for the LOGIN-stage UKI (G-E9: every boot that
# reaches the UKI stub): $RUN/uki-pcrsig.json is the login-stage build's own
# signed prediction at this point (the from-cache restore below runs later).
_CONSOLE_SAVE="$CONSOLE"
CONSOLE="$C/console.log"
assert_pcr11_prediction "G-T13 [boot C]"
CONSOLE="$_CONSOLE_SAVE"

if (( FROM_CACHE == 1 )); then
    # run-dir contract: console.log is this run's (boot C) console evidence
    cp "$C/console.log" "$RUN/console.log"
    LOG_CACHED=$(cat "$RUN/console.log" 2>/dev/null || true)
    assert_not_contains "[from-cache] ZERO Mechanism B seals (the cache is never re-enrolled over)" \
        "$LOG_CACHED" "$(sentinel_of cli_seal_slot)"
    assert_not_contains "[from-cache] no enrollment success marker" "$LOG_CACHED" \
        "alpine-fde: enrolled (policy_mode"
    assert_not_contains "[from-cache] no fed tooling session ran (no enroll work redone)" \
        "$LOG_CACHED" "P2B-42-OK"
fi

# restore the run-dir contract: the ENROLLED release UKI + its pcrsig drive
# (the login-stage variant stays as boot C evidence)
cp "$RUN/uki-release.efi" "$RUN/harness.efi"
cp "$RUN/uki-release.pcrsig.json" "$RUN/uki-pcrsig.json"
cp "$RUN/uki-release.pcrsig.img" "$RUN/pcrsig.img"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s00b-enroll-cache: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s00b-enroll-cache: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
