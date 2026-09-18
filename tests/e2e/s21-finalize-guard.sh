#!/usr/bin/env bash
# tests/e2e/s21-finalize-guard.sh — §10 row "First boot with Secure Boot OFF"
# + §12 S-21 (Stage-3 Secure Boot verification guard) + the Stage-3 happy proof
# (§9.1 finalize: fw_sb_state guard -> audit --init -> per-member enroll ->
# install-state `finalized` LAST).
#
# Fixture (host-side, s00b patterns — NO guest writes after the installer boot):
# an `installed`-state disk image built by ONE installer-stage boot:
#   * LUKS2 container, keyslot 0 only (argon2id, the well-known CI passphrase),
#     NO token — the §8.4 handoff-window shape;
#   * Btrfs rootfs with the §9.1 @/@home/@snapshots subvolumes, populated from
#     the pinned Debian root tree ENRICHED scenario-locally with the Stage-1
#     payload: /etc/debian-fde/{install-state.json=installed, baseline.json
#     PENDING, debian-fde.conf}, /etc/crypttab (member UUID), the REAL
#     debian-fde-finalize.service copied from hooks/systemd/ + the
#     multi-user.target.wants enable symlink, /usr/local/bin/debian-fde and
#     the /opt/debian-fde tooling tree (the §5 payload the unit drives).
#     (The rootfs payload is a concatenated ustar: pinned base tree + the
#     scenario's additions — the installer's sha256 pin covers the WHOLE
#     enriched artifact, so nothing can ride in unstated.)
#
#   boot A (§10 first-boot row / S-21 negative): SB-OFF vars (stock vars
#           copy) -> the initramfs unlock path: the harness stand-in is kept
#           OUT of the loop by a DEAD fixture token (s00b mechanism) -> token
#           refused -> console fallback armed -> FED slot-0 recovery
#           passphrase -> UNSEALED -> the fed session runs the PRODUCTION CLI
#           (`debian-fde finalize`, the service's ExecStart verbatim) against
#           the DISK rootfs (DEBIAN_FDE_ROOT=/mnt): the fw_sb_state guard must
#           HALT fail-closed (rc 64) with the §9.1 instruction text, ZERO
#           enrollment, ZERO baseline finalization, install state still
#           `installed`. Post-boot host: LUKS metadata UNCHANGED (1 argon2id
#           keyslot, 0 tokens).
#   boot B (Stage-3 happy proof): same image fresh copy, SB-ON enrolled vars
#           -> same fed unlock -> the production finalize PROCEEDS: in-guest
#           `audit --init` finalizes the pending baseline from live values,
#           enrl_ensure_once performs the SINGLE A'' enrollment (real
#           systemd-cryptenroll), istate_write lands `finalized` ON DISK
#           (LAST mutation, §9.1). Console: the cryptenroll sentinel + the
#           finalize per-member/summary markers + rc 0. Post-boot host:
#           exactly 1 systemd-tpm2 token (keyslot 1; recovery slot 0
#           untouched), state/baseline finalized read back from the mounted
#           disk BEFORE poweroff.
#
# Fidelity notes (documented, not silent):
#   * The finalize CODE path runs under the harness busybox initrd via the
#     fed session (the s00b production-CLI pattern) because the harness
#     initrd has no systemd; the UNIT itself (hooks/systemd/
#     debian-fde-finalize.service + its enable symlink) is shipped on the
#     disk and asserted there (tar listing + in-guest ls). ExecStart target
#     == the CLI invocation exercised here.
#   * Boot B's dead fixture token exists ONLY to keep the harness initrd's
#     own stand-in enroll branch out of the loop (s00b precedent: "token
#     present — skipping enrollment") so the PRODUCTION CLI performs the one
#     enrollment; the fed session removes it before finalize (teardown,
#     asserted) — the enrolled token is cryptenroll's, on a fresh keyslot.
#   * The guest needs jq/tpm2/flock/cryptsetup: the s00b tooling-payload
#     closures (host-closure copies + wrapper scripts) ride the TAIL of the
#     pcrsig payload drive.
#
# Every boot carries the §12 negatives: the interactive passphrase prompt
# never appears (prompt_re), no emergency shell (emergency_forbidden), and
# every upstream-drifting grep goes through the sentinel table (sentinel_of).

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
DISK_MIB=1600

export QEMU_TIMEOUT="${DEBIAN_FDE_S21_TIMEOUT:-1200}"

# --- hardening: bounded stages, loud failures, overall budget --------------------
OVERALL_BUDGET="${DEBIAN_FDE_S21_BUDGET:-7200}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {   # _hang_fail <kind> <stage> <detail> — loud, greppable, fatal
    printf '\ns21: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's21: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    # 125, NOT timeout(1)'s 124: an internal watchdog fire must never be
    # misread by run-e2e as "exceeded the outer scenario budget".
    exit 125
}
_budget_check() {   # _budget_check <stage>
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
run_stage_impl() {   # <soft> <name> <timeout-s> <cmd...>
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s21: stage $name (watchdog ${tmo}s)"
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
        printf 's21: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
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

RUN="$TESTS/e2e/.runs/s21-finalize-guard-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while the (long) boots run; prune our OWN superseded runs,
# never the dirs run-e2e protects (CR-02/MD-03: DEBIAN_FDE_PROTECT_DIRS).
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's21-finalize-guard-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
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

# _ensure_tpm — the swtpm dies at qemu disconnect (observed, s00 note);
# relaunch on the SAME state dir (permall/SRK persists, PCRs reset).
_ensure_tpm() {
    local dir="$1"
    if timeout 20 swtpm_pcrread "$dir" 0 >/dev/null 2>&1; then
        return 0
    fi
    [ -f "$dir/pid" ] && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    rm -f "$dir/pid" "$dir/sock" "$dir/sock.ctrl"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_start:$dir" 90 swtpm_start "$dir"
    _rearm_trap
}

# _qemu_alive <dir> — a QEMU that dies at startup exits rc 0 from qemu_run's
# perspective; fail LOUDLY here with the qemu stderr instead of surfacing as
# a missing console sentinel.
_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s21: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s21: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

# ============================================================================
# Fixture stage 1: keys + vars + the LUKS2 container (keyslot 0 only, NO token)
# ============================================================================
keys_create "$RUN/keys" || { echo "s21: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
assert_contains "fixture: enrolled vars SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
run_stage disk_make_luks 120 disk_make_luks "$RUN/disk.img" "$DISK_MIB"
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s21: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s21: empty LUKS uuid"; exit 1; }

META0=$(disk_metadata "$RUN/disk.img")
assert_eq "fixture: handoff shape — exactly 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META0")"
assert_eq "fixture: keyslot 0 pbkdf is argon2id (§13)" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META0")"
assert_eq "fixture: handoff shape — ZERO tokens (no TPM enrollment yet)" "{}" \
    "$(disk_token_json "$RUN/disk.img")"

# ============================================================================
# Fixture stage 2: the §5 tooling staging tree (s00b closures, replicated
# scenario-locally per the W2b file-ownership split) + the Stage-1 payload
# files the `installed`-state disk must carry.
# ============================================================================
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz" "$RUN/tooling.tar"
mkdir -p "$TOOLING/opt/debian-fde" "$TOOLING/etc/debian-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/usr/local/bin" "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" \
    "$TOOLING/opt/flockbin/lib" "$TOOLING/etc/systemd/system/multi-user.target.wants"
for d in bin lib hooks; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/debian-fde/$d"
done
# tpm2 multitool + jq + flock: host-closure copies with their own loader
# (the /opt isolation pattern of tests/lib/uki-build.sh; s00b precedent)
run_stage tooling-tpm2 60 cp -L "$(command -v tpm2)" "$TOOLING/opt/tpm/bin/tpm2"
printf '#!/bin/sh\nexec /opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/tpm2 "$@"\n' \
    >"$TOOLING/usr/bin/tpm2"
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
run_stage tooling-flock 60 cp -L "$(command -v flock)" "$TOOLING/opt/flockbin/flock"
_flock_interp=$(ldd "$(command -v flock)" | awk '/ld-linux/{print $1}')
if [[ "$_flock_interp" != "$_jq_interp" ]]; then
    echo "s21: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s21: flock closure introduces a library the payload does not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
# cryptenroll unlock-credential wrapper (the CLI's DEBIAN_FDE_CRYPTENROLL
# seam): prepends the embedded slot-0 passphrase — the harness equivalent of
# the §9.1 enroll prompt (no ask-password agent in the initrd, observed live)
printf '#!/bin/sh\nexec /usr/bin/systemd-cryptenroll --unlock-key-file=/kf0 "$@"\n' \
    >"$TOOLING/usr/bin/cryptenroll-kf"
# cryptsetup output normalizer (the CLI's DEBIAN_FDE_CRYPTSETUP seam; the
# LUKS2 JSON mini-parsers anchor on the pretty-printed shape — s00b evidence)
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
# /usr/local/bin/debian-fde: the debian-fde-finalize.service ExecStart target —
# a launcher for the shipped tooling tree (the production install layout shape)
printf '#!/bin/sh\nexec /opt/debian-fde/bin/debian-fde "$@"\n' >"$TOOLING/usr/local/bin/debian-fde"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/cryptenroll-kf" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock" "$TOOLING/usr/local/bin/debian-fde"

# Stage-1 payload documents (the §8.4 `installed` handoff state)
cat >"$TOOLING/etc/debian-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
# pending baseline (the s00 pending shape), guest-stamped: the pub path is
# where the DISK rootfs carries it (finalize runs with DEBIAN_FDE_ROOT=/mnt)
cat >"$TOOLING/etc/debian-fde/baseline.json" <<JSON
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
    "release_pub_path": "/mnt/etc/debian-fde/keys/release.pub",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "$DISK_UUID",
    "esp_partuuid": ""
  }
}
JSON
printf '# debian-fde.conf — harness fixture (comment-only: the environment wins)\n' \
    >"$TOOLING/etc/debian-fde/debian-fde.conf"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/debian-fde/keys/release.pub"
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$DISK_UUID" >"$TOOLING/etc/crypttab"
# the REAL Stage-3 unit + its enable symlink (§9.1: shipped enabled)
run_stage tooling-unit 60 cp "$REPO/hooks/systemd/debian-fde-finalize.service" \
    "$TOOLING/etc/systemd/system/debian-fde-finalize.service"
ln -sfn /etc/systemd/system/debian-fde-finalize.service \
    "$TOOLING/etc/systemd/system/multi-user.target.wants/debian-fde-finalize.service"

run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr
# an UNCOMPRESSED copy of the same tree for the payload concatenation below
run_stage tooling-tar-plain 300 tar -C "$TOOLING" -cf "$RUN/tooling.tar" opt etc usr
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/debian-fde/bin/debian-fde" "$RUN/tooling.listing" \
    && grep -qx "etc/debian-fde/install-state.json" "$RUN/tooling.listing" \
    && grep -qx "etc/debian-fde/baseline.json" "$RUN/tooling.listing" \
    && grep -qx "etc/crypttab" "$RUN/tooling.listing" \
    && grep -qx "etc/systemd/system/debian-fde-finalize.service" "$RUN/tooling.listing" \
    && grep -qx "etc/systemd/system/multi-user.target.wants/debian-fde-finalize.service" "$RUN/tooling.listing" \
    && grep -qx "usr/local/bin/debian-fde" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/flock" "$RUN/tooling.listing"; then
    _assert_result ok "S-21 fixture: tooling payload built (CLI + Stage-1 docs + REAL unit + enable symlink + closures)" ""
else
    _assert_result not-ok "S-21 fixture: tooling payload built" \
        "required entries missing from tar listing (see $RUN/tooling.listing)"
fi

# ============================================================================
# Fixture stage 3: the enriched rootfs payload + the ONE installer boot.
# Concatenated ustar: pinned base tree + this scenario's additions; the
# installer's @@ROOTFS_SHA@@ pin covers the WHOLE enriched artifact.
# ============================================================================
_PAYLOAD_TARBASE="$ROOTFS_CACHE_DIR/debian-13-generic-amd64-rootustar.tar.gz"
if [[ ! -f "$_PAYLOAD_TARBASE" ]]; then
    # force the (cached) derivation via the harness builder, then discard
    run_stage payload-derive 2400 bash -c \
        "$(declare -f rootfs_payload_image rootfs_ensure _rootfs_pin_lookup rootfs_cache_dir); \
         $(declare -p ROOTFS_CACHE_DIR _ROOTFS_PINS _DEB_BASE _CLOUD_BASE 2>/dev/null); \
         rootfs_payload_image '$RUN/payload-derive-scratch.img' >/dev/null"
fi
[[ -f "$_PAYLOAD_TARBASE" ]] || { echo "s21: derived rootfs payload missing after derivation"; exit 1; }
_budget_check payload-enrich
echo "# s21: enriching the rootfs payload (base tree + Stage-1 additions, ONE tar)"
# NOT a concatenated archive: busybox tar (the installer's extractor) stops at
# the first stream's end-of-archive marker, silently dropping the second
# stream (observed live 2026-09-19: the sha pin verified the whole file while
# the additions never extracted). Merge into ONE tree, then re-tar.
run_stage payload-build 1800 bash -c '
    set -eu
    mkdir -p "$2/basetree"
    tar -xf "$1" -C "$2/basetree"
    cp -a "$3"/. "$2/basetree"/
    tar -C "$2/basetree" --format=ustar --owner=0 --group=0 --numeric-owner -cf "$2/combined.tar" .
    gzip -n < "$2/combined.tar" > "$2/enriched.tar.gz"
' _ "$_PAYLOAD_TARBASE" "$RUN" "$TOOLING"
ROOTFS_SHA=$(sha256sum "$RUN/enriched.tar.gz" | awk '{print $1}')
ROOTFS_BYTES=$(stat -c%s "$RUN/enriched.tar.gz")
_aligned=$(((ROOTFS_BYTES + 1048575) / 1048576 * 1048576))
truncate -s "$_aligned" "$RUN/payload.img"
dd if="$RUN/enriched.tar.gz" of="$RUN/payload.img" conv=notrunc status=none
assert_file_exists "S-21 fixture: enriched payload drive (installer input)" "$RUN/payload.img"
tar -tzf "$RUN/enriched.tar.gz" | grep -qxE '\./?etc/debian-fde/install-state.json' \
    || { echo "s21: additions missing from the enriched payload"; exit 1; }
_assert_result ok "S-21 fixture: Stage-1 additions present in the enriched payload tar" ""

DEBIAN_FDE_ROOTFS_SHA="$ROOTFS_SHA" DEBIAN_FDE_ROOTFS_BYTES="$ROOTFS_BYTES" \
    run_stage uki_build-installer 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "debian-fde-stage=install"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make-installer 300 esp_make "$RUN/esp-installer.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
echo "# s21: installer boot — populate the installed-state disk (TCG)"
CURRENT_QEMU_DIR="$RUN"
run_stage qemu_run-installer 60 qemu_run "$RUN" "$RUN/esp-installer.img" "$RUN/disk.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/payload.img"
_qemu_alive "$RUN"
_rearm_trap
run_stage qemu_wait-installer "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""
grep -q "debian-fde: POWEROFF" "$RUN/console.log" || {
    echo "s21: installer boot failed (no POWEROFF sentinel)"; exit 1; }
LOG_INST=$(cat "$RUN/console.log" 2>/dev/null || true)
assert_contains "installer boot: install stage completed" "$LOG_INST" \
    "debian-fde-harness: install stage complete"
# the installed-state handoff shape survived the populate: keyslot 0 only, no token
META1=$(disk_metadata "$RUN/disk.img")
assert_eq "installer boot: disk still exactly 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META1")"
assert_eq "installer boot: disk still ZERO tokens" "{}" "$(disk_token_json "$RUN/disk.img")"

# ============================================================================
# Fixture stage 4: the feeding UKI (console-fallback + DEBUG SHELL seam,
# s00b boot-B pattern) and the dead-token suppressor fixture.
# ============================================================================
DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-feed 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-feed.efi" "debian-fde-console-fallback"
run_stage esp_make-feed 300 esp_make "$RUN/esp-feed.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-feed.efi"

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
_import_dead_token() {   # _import_dead_token <disk-image> — s00b suppressor
    run_stage "dead-token-import:$1" 60 cryptsetup token import "$1" \
        --token-id 9 --json-file "$_tok_json"
}

# _run_fed_boot <boot-dir> <disk-img> <vars.fd> — boot with the feeding UKI,
# feed the slot-0 recovery passphrase through the console fallback, then hand
# over to the fed session (the DEBUG SHELL seam). Returns after the guest
# powered off cleanly. The CALLER owns the fed-session commands.
_run_fed_boot() {
    local bdir="$1" bimg="$2" vars="$3"
    mkdir -p "$bdir"
    cp "$RUN/harness-feed.efi" "$bdir/harness.efi"
    cp "$RUN/esp-feed.img" "$bdir/esp.img"
    cp "$bimg" "$bdir/disk.img"
    _ensure_tpm "$RUN/tpm"
    _rearm_trap
    CURRENT_QEMU_DIR="$bdir"
    run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$bdir/esp.img" \
        "$bdir/disk.img" "$vars" "$RUN/tpm" "$RUN/pcrsig-feed-tooling.img"
    _qemu_alive "$bdir"
    _rearm_trap
    wait_console "$bdir" "awaiting console line" "$QEMU_TIMEOUT"
    feed_line "$bdir/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    wait_console "$bdir" "DEBUG SHELL on console" 300
}

# the pcrsig drive for the fed boots: the JSON (first 64 KiB, unchanged) +
# the tooling tail (s00b mechanism — the initrd reads only the JSON)
run_stage pcrsig_disk-feed 60 uki_pcrsig_disk "$RUN/pcrsig-feed.img" "$RUN/uki-pcrsig.json"
_budget_check pcrsig-tooling-drive
cat "$RUN/pcrsig-feed.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-feed-tooling.img"

# _feed_common <boot-dir> — the shared fed-session prefix: tooling untar,
# dead-token teardown, on-disk fixture proof, CLI seams.
# P4 asserts the `installed`-state fixture ON THE DISK (mount subvol=@).
_feed_common() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
    wait_console "$bdir" "P2A=0" 300
    feed_line "$bdir/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
    wait_console "$bdir" "P2B-42-OK" 300
    # fixture teardown BEFORE any finalize work: the dead suppressor token is
    # removed so the volume is genuinely token-free for the CLI
    feed_line "$bdir/serial.sock" 'cryptsetup token remove --token-id 9 /dev/vdb && echo T9-$((51+1))-GONE'
    wait_console "$bdir" "T9-52-GONE" 120
    # the `installed`-state fixture on disk: state doc, REAL unit + enable
    # symlink, crypttab (the finalize inputs — §9.1 Stage-1 shape). Markers
    # are arithmetic so the tty echo of the fed line can never satisfy the
    # wait (the s00b convention — a literal marker matches its own echo).
    feed_line "$bdir/serial.sock" \
        'mkdir -p /mnt && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && cat /mnt/etc/debian-fde/install-state.json && ls -l /mnt/etc/systemd/system/multi-user.target.wants/ && cat /mnt/etc/crypttab && echo P4-$((41+3))-OK'
    wait_console "$bdir" "P4-44-OK" 300
    # the CLI environment: by-uuid seam (no udev reliance), payload wrappers,
    # and DEBIAN_FDE_ROOT=/mnt — finalize mutates the DISK documents
    feed_line "$bdir/serial.sock" "mkdir -p /run/bu && ln -sf /dev/vdb /run/bu/$DISK_UUID && export DEBIAN_FDE_NO_INSTALL=1 DEBIAN_FDE_TCTI=device:/dev/tpmrm0 DEBIAN_FDE_BY_UUID_DIR=/run/bu DEBIAN_FDE_CRYPTENROLL=/usr/bin/cryptenroll-kf DEBIAN_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty DEBIAN_FDE_ROOT=/mnt DEBIAN_FDE_EVENTLOG=/evtlog-absent && echo P5-\$((43))-OK"
    wait_console "$bdir" "P5-43-OK" 120
}

# _feed_postcheck <boot-dir> — the on-disk post-state evidence (console-borne:
# the LUKS/btrfs container is not host-mountable unprivileged)
_feed_postcheck() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'echo "P7STATE $(grep -o "\"state\": \"[a-z]*\"" /mnt/etc/debian-fde/install-state.json | head -1)"; echo "P7TOK $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq "[.tokens[] | select(.type==\"systemd-tpm2\")] | length")"; echo "P7SLOTS $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c ".keyslots | keys")"; grep expected_pcr7 /mnt/etc/debian-fde/baseline.json; echo P7-$((41+4))-DONE'
    wait_console "$bdir" "P7-45-DONE" 300
    feed_line "$bdir/serial.sock" 'sync; poweroff -f'
    run_stage "qemu_wait:$(basename "$bdir")" "$((QEMU_TIMEOUT + 60))" qemu_wait "$bdir" "$QEMU_TIMEOUT"
    CURRENT_QEMU_DIR=""
}

# ============================================================================
# BOOT A — §10 first-boot row: SB OFF -> the guard HALTS fail-closed (64),
# zero enrollment, state stays `installed`.
# ============================================================================
A="$RUN/boot-a"
cp "$RUN/disk.img" "$RUN/disk-a.img"
_import_dead_token "$RUN/disk-a.img"
keys_vars_unenrolled "$RUN/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "boot A fixture: unenrolled vars carry no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
echo "# boot A: SB-off vars — finalize must halt (exit 64) with ZERO enrollment"
_run_fed_boot "$A" "$RUN/disk-a.img" "$RUN/vars-unenrolled.fd"
_feed_common "$A"
feed_line "$A/serial.sock" 'timeout 300 /opt/debian-fde/bin/debian-fde finalize; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$A/console.log" 2>/dev/null; do
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "finalize never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC_A=$(grep -oE 'P6-RC=[0-9]+' "$A/console.log" | head -1 | cut -d= -f2)
_feed_postcheck "$A"

LOG_A=$(cat "$A/console.log" 2>/dev/null || true)
assert_contains "[boot A] init ran" "$LOG_A" "debian-fde-harness: init started"
assert_contains "[boot A] harness stand-in OUT of the loop (dead suppressor token)" "$LOG_A" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[boot A] dead token refused by the TPM (the only token attempt)" "$LOG_A" \
    "$(sentinel_of tpm2_refused)"
assert_contains "[boot A] fed slot-0 recovery passphrase unsealed the volume (§10 way out)" "$LOG_A" \
    "debian-fde: UNSEALED"
assert_contains "[boot A] tooling extracted in-guest" "$LOG_A" "P2B-42-OK"
assert_contains "[boot A] dead suppressor token removed (token-free for finalize)" "$LOG_A" "T9-52-GONE"
assert_contains "[boot A] installed-state fixture on disk: state=installed" "$LOG_A" '"state": "installed"'
assert_contains "[boot A] the REAL finalize unit is enabled (wants symlink)" "$LOG_A" \
    "debian-fde-finalize.service -> /etc/systemd/system/debian-fde-finalize.service"
assert_contains "[boot A] crypttab member resolved (root UUID= line, not the seam echo)" "$LOG_A" \
    "root UUID=$DISK_UUID none luks"
# THE GUARD (§12 S-21): fw_sb_state fails -> die 64 with the §9.1 instruction
# text; NO enrollment, NO baseline finalization, state unchanged.
assert_eq "[boot A] finalize halted fail-closed (rc 64)" "64" "$CLI_RC_A"
assert_contains "[boot A] fw_sb_state guard saw Secure Boot OFF" "$LOG_A" \
    "fw_sb_state: secureboot=0"
assert_contains "[boot A] the §9.1 instruction text (enable SB in BIOS setup)" "$LOG_A" \
    "Secure Boot is not enabled with your custom keys"
assert_contains "[boot A] the volume remains locked by keyslot 0 (instruction text)" "$LOG_A" \
    "remains safely locked by the keyslot 0 recovery passphrase"
# ordering: the guard halt PRECEDES every mutation — assert by line numbers
_guard_line=$(grep -nm1 -F "Secure Boot is not enabled with your custom keys" "$A/console.log" | cut -d: -f1)
_enroll_line=$(grep -nm1 -F "cryptenroll invocation (policy_mode=" "$A/console.log" | cut -d: -f1)
if [[ -n "$_guard_line" && -z "$_enroll_line" ]]; then
    _assert_result ok "[boot A] ZERO enrollment attempts (no cryptenroll invocation anywhere)" ""
else
    _assert_result not-ok "[boot A] ZERO enrollment attempts (no cryptenroll invocation anywhere)" \
        "guard=$_guard_line enroll=$_enroll_line"
fi
assert_not_contains "[boot A] no baseline finalization before the guard" "$LOG_A" \
    "finalizing pending baseline from live values"
_p7a_line=$(grep -nm1 -F "P7STATE" "$A/console.log" | cut -d: -f1)
if [[ -n "$_guard_line" && -n "$_p7a_line" ]] && (( _guard_line < _p7a_line )); then
    _assert_result ok "[boot A] state evidence printed AFTER the halt (halt really stopped the flow)" ""
else
    _assert_result not-ok "[boot A] state evidence printed AFTER the halt" "guard=$_guard_line p7=$_p7a_line"
fi
assert_contains "[boot A] post: install state STILL installed (istate_write never ran)" "$LOG_A" \
    "P7STATE \"state\": \"installed\""
assert_contains "[boot A] post: baseline STILL pending (audit --init never ran)" "$LOG_A" \
    '"expected_pcr7": "pending"'
assert_contains "[boot A] post: ZERO tokens in the LUKS2 metadata" "$LOG_A" "P7TOK 0"
assert_contains "[boot A] post: keyslots unchanged ([\"0\"] only)" "$LOG_A" 'P7SLOTS ["0"]'
assert_not_contains "[boot A] no interactive prompt ever appeared (sentinel table)" "$LOG_A" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot A] no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
# post-boot HOST: the BOOTED image's LUKS metadata is unchanged NET of the
# suppressor cycle (dead token imported pre-boot, removed in-guest): 1
# keyslot, 0 tokens. The pristine fixture copy never changed at all.
META_A=$(disk_metadata "$A/disk.img")
assert_eq "[boot A] host(booted img): metadata unchanged — 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META_A")"
assert_eq "[boot A] host(booted img): metadata unchanged — ZERO tokens (teardown canceled the import)" "{}" \
    "$(disk_token_json "$A/disk.img")"
assert_eq "[boot A] host(booted img): keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_A")"
assert_eq "[boot A] host(fixture img): untouched — ZERO tokens" "{}" \
    "$(disk_token_json "$RUN/disk.img")"

# ============================================================================
# BOOT B — Stage-3 happy proof: SB ON -> finalize proceeds end-to-end.
# ============================================================================
B="$RUN/boot-b"
cp "$RUN/disk.img" "$RUN/disk-b.img"
_import_dead_token "$RUN/disk-b.img"   # stand-in suppressor ONLY (s00b); the
                                       # fed session removes it before finalize
echo "# boot B: SB-on vars — production finalize (audit --init + ONE A'' enroll + state finalized)"
_run_fed_boot "$B" "$RUN/disk-b.img" "$RUN/vars-enrolled.fd"
_feed_common "$B"
feed_line "$B/serial.sock" 'timeout 300 /opt/debian-fde/bin/debian-fde finalize; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$B/console.log" 2>/dev/null; do
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "finalize never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC_B=$(grep -oE 'P6-RC=[0-9]+' "$B/console.log" | head -1 | cut -d= -f2)
_feed_postcheck "$B"

LOG_B=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] init ran" "$LOG_B" "debian-fde-harness: init started"
assert_contains "[boot B] stand-in OUT of the loop (dead suppressor token)" "$LOG_B" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[boot B] fed slot-0 recovery passphrase unsealed the volume" "$LOG_B" \
    "debian-fde: UNSEALED"
assert_contains "[boot B] dead suppressor token removed before finalize" "$LOG_B" "T9-52-GONE"
assert_contains "[boot B] pre-state: installed (on disk)" "$LOG_B" '"state": "installed"'
# the finalize flow, in order: audit --init -> ONE enrollment -> state LAST
assert_contains "[boot B] audit --init finalized the pending baseline from live values" "$LOG_B" \
    "finalizing pending baseline from live values (first boot in the final SB state)"
assert_contains "[boot B] baseline finalized marker" "$LOG_B" \
    "debian-fde: baseline finalized: /mnt/etc/debian-fde/baseline.json"
assert_contains "[boot B] the production enroll argv (policy_mode=a2)" "$LOG_B" \
    "cryptenroll invocation (policy_mode=a2)"
assert_contains "[boot B] cryptenroll enrolled (Mechanism A'', sentinel table)" "$LOG_B" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[boot B] finalize per-member marker (member enrolled, keyslot/token recorded)" "$LOG_B" \
    "debian-fde: member $DISK_UUID: enrolled (keyslot 1, token 0)"
assert_contains "[boot B] install finalized marker (§9.1 Stage 3)" "$LOG_B" \
    "debian-fde: install finalized"
assert_contains "[boot B] the §9.1 off-machine backup prompt" "$LOG_B" \
    "back up the key material off-machine now"
assert_eq "[boot B] production finalize rc 0" "0" "$CLI_RC_B"
assert_eq "[boot B] cryptenroll invoked EXACTLY ONCE (single A'' enrollment)" "1" \
    "$(grep -cF 'cryptenroll invocation (policy_mode=a2)' <<<"$LOG_B")"
# ordering: state transition is the LAST mutation (§9.1) — the finalized state
# doc is only written after the enrollment marker
_enrlb_line=$(grep -nm1 -F "debian-fde: member $DISK_UUID: enrolled" "$B/console.log" | cut -d: -f1)
_finb_line=$(grep -nm1 -F "debian-fde: install finalized" "$B/console.log" | cut -d: -f1)
if [[ -n "$_enrlb_line" && -n "$_finb_line" ]] && (( _enrlb_line < _finb_line )); then
    _assert_result ok "[boot B] enrollment precedes the finalized transition (state written LAST, §9.1)" ""
else
    _assert_result not-ok "[boot B] enrollment precedes the finalized transition" \
        "enroll=$_enrlb_line finalized=$_finb_line"
fi
assert_contains "[boot B] post: install state NOW finalized (written to the DISK doc)" "$LOG_B" \
    "P7STATE \"state\": \"finalized\""
assert_not_contains "[boot B] post: baseline no longer pending" "$LOG_B" \
    '"expected_pcr7": "pending"'
assert_contains "[boot B] post: baseline expected_pcr7 is a live PCR 7 digest" "$LOG_B" \
    "P7-45-DONE"
if grep -qE '"expected_pcr7": "[0-9a-f]{64}"' "$B/console.log"; then
    _assert_result ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" ""
else
    _assert_result not-ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" \
        "no finalized expected_pcr7 line on the console"
fi
assert_contains "[boot B] post: exactly ONE systemd-tpm2 token" "$LOG_B" "P7TOK 1"
assert_contains "[boot B] post: token on a fresh keyslot (0+1)" "$LOG_B" 'P7SLOTS ["0","1"]'
assert_not_contains "[boot B] no interactive prompt ever appeared (sentinel table)" "$LOG_B" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot B] no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
# post-boot HOST: the enrolled metadata — read the BOOTED image (the VM
# mutated its vdb copy; the pre-boot copies stay pristine by design)
META_B=$(disk_metadata "$B/disk.img")
NTOK=$(disk_token_json "$B/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[boot B] host(booted img): exactly ONE systemd-tpm2 token" "1" "$NTOK"
TOKSLOT=$(disk_token_json "$B/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "[boot B] host(booted img): token on keyslot 1 (recovery slot 0 untouched)" "1" "$TOKSLOT"
assert_eq "[boot B] host(booted img): 2 keyslots (passphrase + token)" "2" \
    "$(jq -r '.keyslots | length' <<<"$META_B")"
assert_eq "[boot B] host(booted img): recovery keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_B")"
# and the ORIGINAL fixture copy is untouched by the boot (suppressor cycle
# happened on the copy; the fixture stays token-free)
assert_eq "[boot B] host(fixture img): still ZERO tokens (boot isolated)" "{}" \
    "$(disk_token_json "$RUN/disk.img")"

# keep run dirs small
rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/enriched.tar.gz" "$RUN/payload-derive-scratch.img"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s21-finalize-guard: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s21-finalize-guard: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
