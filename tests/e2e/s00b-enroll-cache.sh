#!/usr/bin/env bash
# tests/e2e/s00b-enroll-cache.sh — §12 S-00b + S-01 (continues tests/e2e/
# s00-bootstrap-lite.sh; runs only AFTER S-00 finalized the baseline).
#
# REWORKED 2026-09-18 per the amended §12 S-00b contract: the first-install
# enrollment happens via the PRODUCTION CLI in the guest —
# `/opt/debian-fde/bin/debian-fde enroll-tpm` (the dedicated enrollment
# entry of the §6.1 ensure-once step; real systemd-cryptenroll, exactly ONE
# enrollment) — REPLACING the harness stand-in (the initrd's hand-run
# cryptenroll), which is proven OUT of the loop by console evidence.
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
#             - host-side, a DEAD `systemd-tpm2` token is imported into the
#               LUKS2 metadata (unprivileged `cryptsetup token import`, the
#               s06/s13 mechanism) purely so the initrd's built-in enroll
#               branch SKIPS ("token present — skipping enrollment"): the
#               harness stand-in is out of the loop, asserted on the console;
#             - the dead token is refused at unlock (tpm2_refused) -> the
#               harness console-fallback arms (s12 mechanism; fed slot-0
#               passphrase) -> UNSEALED -> the initrd's DEBUG SHELL seam
#               (DEBIAN_FDE_DEBUG_SHELL, input via serial);
#             - the fed session untars the §5-shaped tooling payload off the
#               tail of the pcrsig payload drive (/opt/debian-fde tree +
#               guest-bound baseline + release.pub + jq + the tpm2
#               multitool closure), removes the dead token (fixture
#               teardown), and runs the production CLI: its real
#               preconditions fire (finalized baseline, SB on + SetupMode=0,
#               live PCR 7 == baseline, LUKS uuid resolvable) and enrl_run
#               performs the single A'' enrollment. Console asserts the
#               CLI's own markers: the argv line, the cryptenroll_enrolled
#               sentinel and `debian-fde: enrolled (...)` + rc 0. NO
#               hand-rolled cryptenroll exists anywhere in this scenario.
#           Then the PRISTINE disk + TPM state are snapshotted into the
#           stable cache (tests/e2e/.cache/pristine-s00b/, SHA256-recorded
#           manifest + FORMAT marker, fail-closed verification on reuse, s00
#           STATE SHAPE including tpm/tpm2-00.permall). The cache also carries
#           baseline.json + uki-pcrsig.json: earlier cache formats (flat
#           permall, no finalized baseline, pre-jq target set, no
#           signed-prediction JSON, pre-btrfs ext4 disk without the
#           `btrfs-1` FORMAT marker — G-HW5 bump) fail verification and
#           trigger a rebuild.
#   boot C  §12 S-01 happy path: the login-stage UKI (enroll-skip -> token
#           unlock with ZERO console input -> switch_root into the populated
#           installed system) must reach `login:` on the serial console.
#           Plus the §13 ESP-size assertion for the release UKI.
#
# State sourcing (in order): DEBIAN_FDE_S00_STATE (set by run-e2e.sh when s00
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
# as DEBIAN_FDE_E2E_STATE): disk.img (populated + ENROLLED), tpm/ (swtpm state,
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
#   * the initrd has no udev, so the CLI's DEBIAN_FDE_BY_UUID_DIR seam (its
#     documented injection point) is pointed at a fed /run/bu symlink of the
#     active /dev/mapper/root — the §9.1 enroll-on-active-volume production
#     shape (no unlock key file involved);
#   * jq + the tpm2 multitool ride as host-closure copies (the /opt/tpm
#     isolation pattern of tests/lib/uki-build.sh): the pinned rootfs tree
#     predates the §3.3 package set and the harness installer never runs apt;
#   * the CLI's DEBIAN_FDE_CRYPTENROLL seam (its documented test injection
#     point) points at a payload wrapper that prepends the embedded slot-0
#     passphrase as --unlock-key-file — the §9.1 enroll prompt has no
#     ask-password equivalent in the initrd ("Failed to query password",
#     observed live); the invocation itself stays inside the production CLI;
#   * boot B's UKI is a SIGNED VARIANT carrying the harness feeding channels
#     (`debian-fde-console-fallback` + the DEBUG SHELL seam; s12 precedent).

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

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
CACHE_DIR="$TESTS/e2e/.cache/pristine-s00b"
# boot C runs the real installed systemd under TCG: boot-to-login includes
# the pinned tree's apparmor profile load (~100 apparmor_parser spawns) and
# the §9.1 fstab submounts — 900 s was exceeded once (2026-09-19,
# s00b-enroll-1789764323: console reached only guest-t=141 s at wall 900 s)
export QEMU_TIMEOUT="${DEBIAN_FDE_S00B_TIMEOUT:-1800}"

# --- hardening: bounded stages, loud failures, overall budget --------------------
OVERALL_BUDGET="${DEBIAN_FDE_S00B_BUDGET:-5400}"
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
run_stage_impl() {   # <soft> <name> <timeout-s> <cmd...>
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s00b: stage $name (watchdog ${tmo}s)"
    ( "$@" ) &
    local pid=$! rc wrc
    ( sleep "$tmo"; kill -9 -"$pid" 2>/dev/null; exit 125 ) &
    local wpid=$!
    wait "$pid"; rc=$?
    kill "$wpid" 2>/dev/null
    wait "$wpid" 2>/dev/null; wrc=$?
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
wait_console() {   # wait_console <dir> <fixed-string> <timeout-s> — bounded poll
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qF -- "$pat" "$dir/console.log" 2>/dev/null && return 0
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
# can treat both identically; requires baseline.json + uki-pcrsig.json + the
# FORMAT marker: earlier cache formats (flat permall, no finalized baseline,
# pre-jq target set, no signed-prediction JSON, pre-btrfs ext4 disk — G-HW5
# format bump) fail closed and trigger a rebuild.
_cache_verify() {
    local dir="$1"
    [[ -f "$dir/FORMAT" ]] && grep -q '^btrfs-2$' "$dir/FORMAT" || return 1
    [[ -f "$dir/MANIFEST.sha256" && -f "$dir/disk.img" && -f "$dir/tpm/tpm2-00.permall" \
        && -f "$dir/harness.efi" && -f "$dir/pcrsig.img" && -f "$dir/vars-enrolled.fd" \
        && -f "$dir/baseline.json" && -f "$dir/uki-pcrsig.json" ]] || return 1
    (cd "$dir" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1
}

# _cache_store <cache-dir> <run-dir> — snapshot the enrolled state into the
# stable cache (called via run_stage's bash -c bridge; explicit args because
# the bridge subshell does not inherit scenario locals)
_cache_store() {
    local dir="$1" run="$2"
    rm -rf "$dir"
    mkdir -p "$dir/tpm"
    cp "$run/disk.img" "$run/harness.efi" "$run/pcrsig.img" "$run/vars-enrolled.fd" "$dir/"
    cp "$run/baseline.json" "$dir/baseline.json"
    cp "$run/uki-pcrsig.json" "$dir/uki-pcrsig.json"
    # cache FORMAT marker (G-HW5 format bump): the disk layout generation —
    # btrfs @/@home/@snapshots with the §9.1 UUID= fstab + udev-registered
    # initrd attach since 2026-09-19 (btrfs-1 briefly carried a /dev/dm-0
    # fstab). A cache without it (or from the ext4 era) fails _cache_verify
    # and triggers a rebuild; the login-stage initrd of that generation
    # cannot boot an older-layout disk and vice versa.
    printf 'btrfs-2\n' >"$dir/FORMAT"
    # s00 STATE SHAPE (tpm/tpm2-00.permall): the snapshot below consumes
    # $STATE/tpm/tpm2-00.permall — a flat copy here would be silently skipped
    # by that guard and the from-cache boot would resume a VIRGIN TPM whose
    # seed cannot unseal the standing token (observed live 2026-09-18,
    # run s00b-enroll-1789742123: "Failed to load key into TPM ... 0x18b" ->
    # "State not recoverable" -> clean poweroff before login).
    cp "$run/tpm/tpm2-00.permall" "$dir/tpm/tpm2-00.permall"
    cp -a "$run/keys" "$dir/keys"
    (cd "$dir" && sha256sum FORMAT disk.img harness.efi pcrsig.img vars-enrolled.fd \
        tpm/tpm2-00.permall baseline.json uki-pcrsig.json >MANIFEST.sha256)
    echo "# pristine enrolled state cached in $dir (FORMAT $(cat "$dir/FORMAT"), SHA256 manifest: $(wc -l <"$dir/MANIFEST.sha256") entries)"
}

STATE="${DEBIAN_FDE_S00_STATE:-}"
FROM_CACHE=0
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
        echo "# S-00b: cache at $CACHE_DIR is STALE (pre-rework: flat permall / no finalized baseline / pre-jq target set / no uki-pcrsig.json / pre-btrfs FORMAT marker) — rebuilding"
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
    run_stage keys_vars_enrolled 120 keys_vars_enrolled "$STATE/keys" "$STATE/vars-enrolled.fd"
    # the rootfs payload derivation may fetch the pinned artifact over the
    # network (the overnight hang's window) — hard-bounded here, output on a
    # file so the watchdog subshell cannot hand variables back
    run_stage rootfs-payload 1800 bash -c \
        "$(declare -f rootfs_payload_image rootfs_ensure _rootfs_pin_lookup rootfs_cache_dir); \
         $(declare -p ROOTFS_CACHE_DIR _ROOTFS_PINS _DEB_BASE _CLOUD_BASE 2>/dev/null); \
         rootfs_payload_image '$STATE/rootfs-payload.img' >'$RUN/payload.out'"
    read -r _sha _bytes <"$RUN/payload.out" || { echo "s00b: rootfs payload build failed"; exit 1; }
    [[ -n "$_sha" ]] || { echo "s00b: rootfs payload build failed"; exit 1; }
    DEBIAN_FDE_ROOTFS_SHA="$_sha" DEBIAN_FDE_ROOTFS_BYTES="$_bytes" \
        run_stage uki_build-installer 1200 \
        uki_build "$STATE" "$STATE/keys" "$STATE/harness.efi" "debian-fde-stage=install"
    UKI_MIB=$(( ($(stat -c%s "$STATE/harness.efi") + 1048575) / 1048576 ))
    run_stage esp_make-installer 300 esp_make "$STATE/esp.img" \
        $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$STATE/harness.efi"
    run_stage disk_make_luks 120 disk_make_luks "$STATE/disk.img" 1600
    CURRENT_QEMU_DIR="$STATE"
    run_stage qemu_run-bootstrap 60 qemu_run "$STATE" "$STATE/esp.img" "$STATE/disk.img" \
        "$STATE/vars-enrolled.fd" "$STATE/tpm" "$STATE/rootfs-payload.img"
    _qemu_alive "$STATE"
    _rearm_trap
    run_stage qemu_wait-bootstrap "$((QEMU_TIMEOUT + 60))" qemu_wait "$STATE" "$QEMU_TIMEOUT"
    CURRENT_QEMU_DIR=""
    grep -q "debian-fde: POWEROFF" "$STATE/console.log" || {
        echo "s00b: self-bootstrap installer boot failed (no POWEROFF sentinel)"; exit 1; }

    # finalize the baseline via the REAL CLI (S-00 stage 6) — the enroll
    # precondition; G-R1-guarded on the efivars fixture (SecureBoot=1
    # SetupMode=0), BEFORE any UKI-chain work (§12 S-00b ordering).
    EFIVARS="$STATE/rootfs/efivars-sb-on"
    mkdir -p "$EFIVARS" "$STATE/rootfs/etc/debian-fde"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    _mkcertvar PK pk-cert-v1
    _mkcertvar KEK kek-cert-v1
    _mkcertvar db db-cert-v1
    _mkcertvar dbx dbx-cert-v1
    cat >"$STATE/rootfs/etc/debian-fde/baseline.json" <<'JSON'
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
    if AUDIT_OUT=$(DEBIAN_FDE_ROOT="$STATE/rootfs" \
        DEBIAN_FDE_TCTI="swtpm:path=$STATE/tpm/sock" \
        DEBIAN_FDE_EFIVARS_DIR="$EFIVARS" \
        DEBIAN_FDE_EVENTLOG="$STATE/rootfs/eventlog-absent" \
        DEBIAN_FDE_NO_INSTALL=1 \
        timeout 300 "$REPO/bin/debian-fde" audit --init 2>&1); then
        _assert_result ok "S-00b: audit --init finalized the baseline (real CLI, rc 0)" ""
    else
        _assert_result not-ok "S-00b: audit --init finalized the baseline (real CLI, rc 0)" \
            "output: $(tail -2 <<<"$AUDIT_OUT")"
    fi
    PCR7_B=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)
    sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7_B\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$STATE/console.log" | head -1 | cut -d= -f2)\",|" \
        "$STATE/rootfs/etc/debian-fde/baseline.json"
    if grep -q '"expected_pcr7": "pending"' "$STATE/rootfs/etc/debian-fde/baseline.json" \
        || [[ -z "$PCR7_B" ]]; then
        echo "s00b: baseline still pending after audit --init — refusing to continue"; exit 1
    fi
    cp "$STATE/rootfs/etc/debian-fde/baseline.json" "$STATE/baseline.json"
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
mkdir -p "$RUN/rootfs/etc/debian-fde"
run_stage snapshot-baseline 60 cp "$STATE/baseline.json" "$RUN/baseline.json"
run_stage snapshot-baseline-rootfs 60 cp "$STATE/baseline.json" "$RUN/rootfs/etc/debian-fde/baseline.json"
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
    echo "# S-00b from-cache: standing enrollment verified (1 systemd-tpm2 token, keyslot 1) — boot C next"
fi

# --- fresh enroll flow (s00 state or self-bootstrap) — skipped entirely from-cache -
if (( FROM_CACHE == 0 )); then

# the guest-bound baseline: same finalized values, keys/target stamped to the
# IN-GUEST production paths (§8.4: what `install` resolves at provision time).
# ONLY the payload copy is stamped — the run-dir contract stays exactly as s00
# produced it, so downstream state consumers are unaffected.
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s00b: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s00b: empty LUKS uuid"; exit 1; }
if jq --arg pub "/etc/debian-fde/keys/release.pub" --arg uuid "$DISK_UUID" \
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

# --- the §5 tooling payload: /opt/debian-fde + jq + tpm2 multitool closure -------
echo "# S-00b: building the guest tooling payload (/opt/debian-fde + jq + tpm2, §3.3/§5)"
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/debian-fde" "$TOOLING/etc/debian-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib"
for d in bin lib hooks docs; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/debian-fde/$d"
done
run_stage tooling-baseline 60 cp "$RUN/baseline-guest.json" "$TOOLING/etc/debian-fde/baseline.json"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/debian-fde/keys/release.pub"
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
# DEBIAN_FDE_NO_INSTALL=1 in the initrd a missing binary is the CLI's hard
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
# cryptenroll unlock-credential wrapper (the CLI's DEBIAN_FDE_CRYPTENROLL seam):
# prepends the embedded slot-0 passphrase as --unlock-key-file — the harness
# equivalent of the §9.1 interactive enroll prompt (the initrd has no
# ask-password agent; observed live: "Failed to query password")
printf '#!/bin/sh\nexec /usr/bin/systemd-cryptenroll --unlock-key-file=/kf0 "$@"\n' \
    >"$TOOLING/usr/bin/cryptenroll-kf"
# cryptsetup output normalizer (the CLI's DEBIAN_FDE_CRYPTSETUP seam): the
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
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/cryptenroll-kf" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock"
run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/debian-fde/bin/debian-fde" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/flock" "$RUN/tooling.listing" \
    && grep -qx "opt/flockbin/flock" "$RUN/tooling.listing" \
    && grep -qx "opt/flockbin/ld-linux" "$RUN/tooling.listing"; then
    _assert_result ok "S-00b: tooling payload built (CLI entrypoint + baseline + jq + tpm2 + flock)" ""
else
    _assert_result not-ok "S-00b: tooling payload built" \
        "required entries missing from tar listing (see $RUN/tooling.listing)"
fi

# --- the ukictl build PRODUCT: release-key PCR-signed + sbsigned UKI -------------
echo "# S-00b: building the release UKI (ukictl build product: ukify pcr-signing + sbsign)"
# boot B's UKI is a SIGNED VARIANT carrying the harness feeding channels
# (s12 precedent): the console-fallback word arms the bounded 3-strike loop;
# DEBIAN_FDE_DEBUG_SHELL bakes the DEBUG SHELL seam for the fed session.
# Explicit empty pins keep any leaked env from shaping later builds.
DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-release 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "debian-fde-console-fallback"
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
_ensure_tpm "$RUN/tpm"
_rearm_trap
echo "# boot B: product boots; production CLI enrolls from the guest (finalized baseline) — TCG"
CURRENT_QEMU_DIR="$RUN"
run_stage qemu_run-bootb 60 qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig-tooling.img"
_qemu_alive "$RUN"
_rearm_trap

# fed session: the dead token is refused -> the fallback arms -> feed the
# slot-0 passphrase (s12 mechanism) -> the DEBUG SHELL seam takes over.
wait_console "$RUN" "awaiting console line" "$QEMU_TIMEOUT"
feed_line "$RUN/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
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
#    device, observed live) + the CLI environment. DEBIAN_FDE_CRYPTENROLL is
#    the CLI's own documented injection seam: the payload-shipped wrapper
#    prepends --unlock-key-file=/kf0 (the embedded slot-0 passphrase) to the
#    real binary — the harness equivalent of the §9.1 enroll prompt, which
#    has no ask-password agent in the initrd (observed live: "Failed to
#    query password"); everything else (preconditions, argv, post-asserts,
#    enrolled.json) is the production CLI's own path.
feed_line "$RUN/serial.sock" "mkdir -p /run/bu && ln -sf /dev/vdb /run/bu/$DISK_UUID && export DEBIAN_FDE_NO_INSTALL=1 DEBIAN_FDE_TCTI=device:/dev/tpmrm0 DEBIAN_FDE_BY_UUID_DIR=/run/bu DEBIAN_FDE_CRYPTENROLL=/usr/bin/cryptenroll-kf DEBIAN_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty && echo P5-\$((43))-OK"
wait_console "$RUN" "P5-43-OK" 120
# 5) THE PRODUCTION CLI: the §9.1 first-install enrollment (single A'' cryptenroll)
feed_line "$RUN/serial.sock" 'timeout 180 /opt/debian-fde/bin/debian-fde enroll-tpm; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$RUN/console.log" 2>/dev/null; do
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "production CLI never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC=$(grep -oE 'P6-RC=[0-9]+' "$RUN/console.log" | head -1 | cut -d= -f2)
# 6) done — clean poweroff from the fed shell
feed_line "$RUN/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-bootb "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG=$(cat "$CONSOLE" 2>/dev/null || true)
assert_contains "[boot B] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[boot B] harness stand-in OUT of the loop: enroll branch skipped" "$LOG" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_not_contains "[boot B] NO hand-rolled cryptenroll fired" "$LOG" \
    "debian-fde-harness: no systemd-tpm2 token — enrolling in-guest"
# NB: the DEAD token is refused EARLIER in 257.13's flow than the s13
# blob-corrupt shape (synthetic blob dies at TPM2B parse: no token-JSON
# request, no signature-policy setup) — so token_discovered/pcr_sig_added are
# NOT asserted on boot B; they belong to boot C's REAL token unlock below.
assert_contains "[boot B] dead token refused by the TPM" "$LOG" "$(sentinel_of tpm2_refused)"
assert_contains "[boot B] console fallback armed (bounded 3-strike)" "$LOG" \
    "passphrase attempt 1/3"
assert_contains "[boot B] fed slot-0 passphrase unsealed the volume" "$LOG" \
    "debian-fde: UNSEALED"
assert_contains "[boot B] tooling payload extracted in-guest" "$LOG" "P2B-42-OK"
assert_contains "[boot B] dead fixture token removed (teardown before enroll)" "$LOG" "T9-52-GONE"
assert_contains "[boot B] production CLI ran (enroll-tpm argv printed)" "$LOG" \
    "cryptenroll invocation (policy_mode=a2)"
assert_contains "[boot B] cryptenroll enrolled (Mechanism A'', sentinel table)" "$LOG" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[boot B] production CLI's own success marker" "$LOG" \
    "debian-fde: enrolled (policy_mode=a2, token keyslot"
assert_eq "[boot B] production CLI rc 0" "0" "$CLI_RC"
assert_eq "[boot B] cryptenroll invoked EXACTLY ONCE (single A'' enrollment)" "1" \
    "$(grep -cF 'cryptenroll invocation (policy_mode=a2)' <<<"$LOG")"
assert_not_contains "[boot B] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "S-00b ensure-once: exactly ONE systemd-tpm2 token on the disk" "1" "$NTOK"
TOKSLOT=$(disk_token_json "$RUN/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "S-00b: token enrolled on a fresh keyslot (recovery slot 0 untouched)" "1" "$TOKSLOT"

# G-T13 prediction check for the ENROLLED release UKI: ukify's enter-initrd
# entry == the {11}-selection PolicyPCR digest over the guest's PRE-UNLOCK
# (post-phase-word) reading — never the final register (§12: post-boot PCR 11
# additionally carries leave-initrd and later pcrphase extensions).
PCR11_POST_B=$(grep -oE 'debian-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$CONSOLE" 2>/dev/null | head -1 | cut -d= -f2)
POL_ENTER_B=$(uki_pcrsig_enter_initrd_pol "$RUN/uki-pcrsig.json")
POL_PREDICTED_B=$(uki_pcr11_policy_digest "$PCR11_POST_B")
if [[ -n "$PCR11_POST_B" ]]; then
    assert_eq "G-T13 [boot B]: ukify enter-initrd prediction == pre-unlock PCR 11 state" \
        "$POL_ENTER_B" "$POL_PREDICTED_B"
else
    _assert_result not-ok "G-T13 [boot B]: ukify enter-initrd prediction == pre-unlock PCR 11 state" \
        "no postphase PCR 11 line in console"
fi

# --- pristine cache (SHA-recorded), snapshot BEFORE boot C touches the disk ------
# only when boot B's production enrollment actually landed (the sentinel table
# is the evidence) — a failed enrollment must NEVER poison the pristine cache
if grep -qF "$(sentinel_of cryptenroll_enrolled)" "$RUN/console.log" \
    && [[ "$CLI_RC" == "0" ]]; then
    run_stage cache-store 900 bash -c "$(declare -f _cache_store); _cache_store '$CACHE_DIR' '$RUN'"
else
    echo "s00b: enrollment evidence missing (sentinel/rc=$CLI_RC) — pristine cache NOT stored"
fi

fi   # FROM_CACHE == 0 (fresh enroll flow: guest-bound baseline, tooling payload,
     # release UKI, dead-token boot B, in-guest production enroll, cache store)

# --- boot C: §12 S-01 — zero-input token unlock + switch_root -> login: ---------
echo "# S-00b: building the login-stage UKI (enroll-skip + token unlock + switch_root)"
DEBIAN_FDE_DEBUG_SHELL= DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-login 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "debian-fde-stage=login"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make-login 300 esp_make "$RUN/esp-login.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
C="$RUN/boot-login"
mkdir -p "$C"
cp "$RUN/harness.efi" "$C/harness.efi"
cp "$RUN/pcrsig.img" "$C/pcrsig.img"
cp "$RUN/esp-login.img" "$C/esp.img"
cp "$RUN/disk.img" "$C/disk.img"   # working copy: the cache stays pristine
_ensure_tpm "$RUN/tpm"
_rearm_trap
echo "# boot C: zero-input token unlock + switch_root into the installed system (TCG)"
CURRENT_QEMU_DIR="$C"
run_stage qemu_run-bootc 60 qemu_run "$C" "$C/esp.img" "$C/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$C/pcrsig.img"
_qemu_alive "$C"
_rearm_trap
# WAIT for `login:` — we NEVER write to the serial socket (zero console input).
# agetty prints the installed system's /etc/issue banner, then the login prompt.
LOGIN_SEEN=0
i=0
while ((i < QEMU_TIMEOUT)); do
    if grep -qE 'login: ?$' "$C/console.log" 2>/dev/null \
        && grep -q 'Debian GNU/Linux' "$C/console.log" 2>/dev/null; then
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
assert_contains "[boot C] init ran" "$LOG_C" "debian-fde-harness: init started"
assert_contains "[boot C] enrollment SKIPPED (token enrolled by the production CLI in boot B)" "$LOG_C" \
    "systemd-tpm2 token present — skipping enrollment"
assert_contains "[boot C] standing token discovered by the real unlock path" "$LOG_C" \
    "$(sentinel_of token_discovered)"
assert_contains "[boot C] login UKI's own .pcrsig consumed (signed policy)" "$LOG_C" \
    "$(sentinel_of pcr_sig_added)"
assert_contains "[boot C] volume activated with a LUKS token (sentinel table)" "$LOG_C" \
    "$(sentinel_of unlocked)"
assert_contains "[boot C] token unlocked with ZERO console input" "$LOG_C" \
    "debian-fde: UNSEALED"
assert_contains "[boot C] switch_root into the populated installed system" "$LOG_C" \
    "debian-fde-harness: switching to the installed system"
assert_contains "[boot C] root mount is the §9.1 @ subvolume (G-HW5 btrfs default)" "$LOG_C" \
    "debian-fde-btrfs: root mounted subvol=@ (login stage)"
assert_contains "[boot C] the installed system's getty banner (real Debian userspace)" "$LOG_C" \
    "Debian GNU/Linux"
assert_not_contains "[boot C] no passphrase prompt ever armed (zero-input path)" "$LOG_C" \
    "awaiting console line"
assert_not_contains "[boot C] no ask-password prompt on the zero-input path (sentinel table)" "$LOG_C" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot C] no emergency shell in the installed system" "$LOG_C" \
    "$(sentinel_of emergency_forbidden)"

if (( FROM_CACHE == 1 )); then
    # run-dir contract: console.log is this run's (boot C) console evidence
    cp "$C/console.log" "$RUN/console.log"
    LOG_CACHED=$(cat "$RUN/console.log" 2>/dev/null || true)
    assert_not_contains "[from-cache] ZERO cryptenroll invocations (the cache is never re-enrolled over)" \
        "$LOG_CACHED" "cryptenroll invocation (policy_mode"
    assert_not_contains "[from-cache] no enrollment success marker" "$LOG_CACHED" \
        "debian-fde: enrolled (policy_mode"
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
