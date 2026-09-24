#!/usr/bin/env bash
# tests/e2e/s21-finalize-guard.sh — §10 row "First boot with Secure Boot OFF"
# + §12 S-21 (Stage-3 Secure Boot verification guard) + the amended Stage-3
# happy proof, on the ALPINE contract (ADR-20 amended §9.1; hooks/openrc/
# alpine-fde-finalize; lib/cmd/finalize.sh fin_completion_steps).
#
# Fixture (host-side, s19/s20 payload patterns — NO guest writes after the
# installer boot): an `installed`-state disk image built by ONE installer-stage
# boot:
#   * LUKS2 container, keyslot 0 only (argon2id, the well-known CI passphrase),
#     NO token — the §8.4 handoff-window shape (the amended §7.2 provisional
#     token slot is the installer's step 6, out of this scenario's scope: the
#     guided completion chain under test seals the {7,11} token itself);
#   * Btrfs rootfs with the §9.1 @/@home/@snapshots subvolumes, populated from
#     the pinned rootfs base tree ENRICHED scenario-locally with the Stage-1
#     payload: /etc/alpine-fde/{install-state.json=installed, baseline.json
#     PENDING, alpine-fde.conf, keys/{release.pub,release.pem}}, /etc/crypttab
#     (member UUID), the REAL advisory oneshot hooks/openrc/alpine-fde-finalize
#     at /etc/init.d/alpine-fde-finalize + the rc-update enable symlink
#     /etc/runlevels/default/alpine-fde-finalize (byte-for-byte the installer's
#     Stage-1 step 7 record, lib/cmd/install.sh), an unfinalized /etc/motd
#     carrying the fde_motd_banner line, and the /opt/alpine-fde tooling tree.
#     NO systemd unit, NO /etc/systemd — the residue guard hard-denies those
#     patterns and the amended ADR-20 lifecycle has no such artifact.
#
# Both boots are FED sessions on the SHIPPED §8.2 mkinitfs unseal hook (the
# unlock of record): the disk carries NO token, so the hook reports
# unseal_token_missing and arms its bounded keyslot-0 recovery loop; the fed
# slot-0 passphrase unseals the volume and the DEBUG SHELL seam hosts the legs.
#
#   boot A (§10 first-boot row / S-21 negative): SB-OFF vars (stock vars
#           copy). Three legs, in order, all advisory-or-fail-closed:
#             a) the ADVISORY oneshot: start() sourced from
#                /etc/init.d/alpine-fde-finalize — rc 0 ALWAYS, prints the
#                not-finalized WARNING + the SB-off fw_sb_state reading + the
#                finalize guidance, mutates NOTHING;
#             b) the SERVICE completion (fin_service_main — the guarded steps
#                the oneshot family owns): the provisional token re-unseal
#                cannot stand (no token, no ESP .pcrsig) -> failure-contained
#                nonzero + the ADR-8 retry-next-boot marker on the DISK; ZERO
#                baseline capture, ZERO token operations, ZERO state flip;
#             c) the GUIDED CLI (`alpine-fde finalize`, recovery-passphrase
#                seam): step 1 verifies the floored recovery passphrase against
#                keyslot 0 (the Stage-1 stand-in rekey), step 2 encrypts
#                release.pem, step 3 the fw_sb_state gate HALTS fail-closed
#                (rc 64) with the §9.1 instruction text — no enrollment, no
#                baseline capture, no token upgrade, state still `installed`.
#           Post-boot host: LUKS metadata UNCHANGED (1 argon2id keyslot, 0
#           tokens).
#   boot B (Stage-3 happy proof / positive control): same image fresh copy,
#           SB-ON enrolled vars -> the guided finalize PROCEEDS through the
#           shared completion chain: recovery passphrase verified -> release.pem
#           encrypted (ADR-18) -> audit --init finalizes the pending baseline
#           from live values -> seal_upgrade_token binds {PCR 7, PCR 11} (the
#           release-key-signed policy rides the payload drive) -> the temporary
#           ephemeral keyslot purge crash-skips -> the unfinalized MOTD banner
#           is stripped line-exactly -> the ADR-8 marker stays clear -> state
#           `finalized` written LAST. Console: the per-member upgrade marker +
#           rc 0. Post-boot host: exactly 1 systemd-tpm2 token bound to
#           {PCR 7, PCR 11} on keyslot 1 (recovery slot 0 untouched),
#           state/baseline finalized read back from the mounted disk BEFORE
#           poweroff.
#
# Fidelity notes (documented, not silent):
#   * The finalize CODE path runs under the harness busybox initrd via the
#     fed session (the s19/s20 production-CLI pattern) because the harness
#     initrd has no OpenRC; the SERVICE legs (a)/(b) therefore drive the
#     staged oneshot and fin_service_main DIRECTLY — the exact code the
#     boot-time service would run (the oneshot's start() body and the
#     failure-contained completion), with the rc/warning/marker surfaces the
#     amended ADR-20 contract pins on them.
#   * The §13 entropy floor refuses the fixture's well-known slot-0
#     passphrase at fin_read_recovery_passphrase, so BOTH boots first rekey
#     keyslot 0 in-guest to the scenario's floored recovery passphrase
#     (cryptsetup luksChangeKey --key-slot 0, /kf0 = the embedded slot-0
#     credential) — the Stage-1 credential-ceremony stand-in (§9.1 step 4;
#     recovery at keyslot 0 authorizes Stage 3).
#   * The guest needs jq/tpm2/flock/openssl/cryptsetup: the s19/s20
#     tooling-payload closures (host-closure copies + wrapper scripts) ride
#     the TAIL of the pcrsig payload drive.
#   * The {7,11} policy signature for boot B's token upgrade is composed
#     HOST-side (uki_pcrsig_append_combined): d7 = the installer boot's
#     console PCR 7 (SB-on enrolled vars are deterministic across boots),
#     d11 = the feed UKI build's enter-initrd prediction — the same
#     composition s19/s20 host-side `pcrsign` legs stand for.
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

# §13-floor-OK credentials for the in-guest finalize (the *debian-fde*
# substring is blocklisted by the entropy floor; >=16 chars passes). The
# recovery passphrase is REKEYED into keyslot 0 in-guest (the Stage-1
# credential-ceremony stand-in); the key passphrase encrypts release.pem at
# finalize STEP 2 (ADR-18).
S21_RECOVERY='alpine-fde-s21-recovery-4e8b20'
S21_KEYPASS='alpine-fde-s21-release-pbkdf2-m5'

# --- hardening: bounded stages, loud failures, overall budget --------------------
# Calibrated 2026-09-24: the registry's outer SCENARIO_BUDGET is 1500 s (MD-05b)
# — an internal watchdog ABOVE the outer cap can never fire and only masks
# hangs (a hung s21 then dies as an anonymous outer rc=124 instead of a loud
# STAGE-TIMEOUT-OR-HANG). Registry evidence: a full s21 pass takes ~400-600 s;
# 1350 s = ~2.2x margin while still fitting inside the outer budget.
OVERALL_BUDGET="${DEBIAN_FDE_S21_BUDGET:-1350}"
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
run_stage vars-unenrolled 60 keys_vars_unenrolled "$RUN/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "fixture: SB-off vars carry no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
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
# Fixture stage 2: the tooling staging tree (s19/s20 closures) + the Stage-1
# payload files the `installed`-state disk must carry — under the ALPINE
# contract paths, with the advisory oneshot + rc-update record and NO systemd.
# ============================================================================
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/alpine-fde" "$TOOLING/etc/alpine-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib" \
    "$TOOLING/opt/sslbin/lib" "$TOOLING/etc/init.d" "$TOOLING/etc/runlevels/default"
for d in bin lib hooks; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/alpine-fde/$d"
done
# tpm2 multitool + jq + flock + openssl: host-closure copies with their own
# loader (the /opt isolation pattern of tests/lib/uki-build.sh; s19/s20
# precedent). openssl: finalize STEP 2's ADR-18 release.pem encryption.
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
run_stage tooling-openssl 60 cp -L "$(command -v openssl)" "$TOOLING/opt/sslbin/openssl"
_ssl_interp=$(ldd "$(command -v openssl)" | awk '/ld-linux/{print $1}')
if [[ "$_ssl_interp" != "$_jq_interp" ]]; then
    echo "s21: openssl interp $_ssl_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-openssl-ld 60 cp -L "$_ssl_interp" "$TOOLING/opt/sslbin/ld-linux"
for _sl in $(ldd "$(command -v openssl)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-openssl-closure"
    cp -L "$_sl" "$TOOLING/opt/sslbin/lib/"
done
printf '#!/bin/sh\nexec /opt/sslbin/ld-linux --library-path /opt/sslbin/lib /opt/sslbin/openssl "$@"\n' \
    >"$TOOLING/usr/bin/openssl"
# cryptsetup output normalizer (the CLI's DEBIAN_FDE_CRYPTSETUP seam; the
# LUKS2 JSON mini-parsers anchor on the pretty-printed shape — s00b evidence)
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock" "$TOOLING/usr/bin/openssl"

# The REAL advisory oneshot + its rc-update enable record (the installer's
# Stage-1 step 7 verbatim: cp to /etc/init.d + `rc-update add ... default`).
# NO systemd unit anywhere — the amended ADR-20 lifecycle has no such artifact.
run_stage tooling-oneshot 60 cp "$REPO/hooks/openrc/alpine-fde-finalize" \
    "$TOOLING/etc/init.d/alpine-fde-finalize"
chmod 755 "$TOOLING/etc/init.d/alpine-fde-finalize"
ln -sfn /etc/init.d/alpine-fde-finalize \
    "$TOOLING/etc/runlevels/default/alpine-fde-finalize"

# Stage-1 payload documents (the §8.4 `installed` handoff state)
cat >"$TOOLING/etc/alpine-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
# pending baseline: the pub path is where the DISK rootfs carries it (finalize
# runs with DEBIAN_FDE_ROOT=/mnt); boot B's in-guest audit --init finalizes it
cat >"$TOOLING/etc/alpine-fde/baseline.json" <<JSON
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
printf '# alpine-fde.conf — harness fixture (comment-only: the environment wins)\n' \
    >"$TOOLING/etc/alpine-fde/alpine-fde.conf"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/alpine-fde/keys/release.pub"
# release.pem: the release key in the ADR-18 PLAINTEXT staging form (finalize
# STEP 2 encrypts it in-guest under DEBIAN_FDE_KEY_PASSPHRASE; the fixture's
# db/release identity is ONE key, ADR-11)
run_stage tooling-release-pem 60 cp "$RUN/keys/db.key" "$TOOLING/etc/alpine-fde/keys/release.pem"
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$DISK_UUID" >"$TOOLING/etc/crypttab"
# an unfinalized /etc/motd: one operator line + the EXACT banner line from the
# product's single source (fde_motd_banner) — boot B's completion chain strips
# the banner line-exactly and must preserve the operator line
_BANNER=$(DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd" . "$REPO/lib/install-state.sh" 2>/dev/null; fde_motd_banner)
{ printf 'Welcome to the Alpine FDE harness fixture — operator content stays.\n'; printf '%s\n' "$_BANNER"; } \
    >"$TOOLING/etc/motd"
grep -c "NOT finalized" "$TOOLING/etc/motd" >/dev/null || {
    echo "s21: fixture motd banner missing — fde_motd_banner source failed"; exit 1; }

run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/alpine-fde/bin/alpine-fde" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/install-state.json" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/baseline.json" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/keys/release.pub" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/keys/release.pem" "$RUN/tooling.listing" \
    && grep -qx "etc/crypttab" "$RUN/tooling.listing" \
    && grep -qx "etc/init.d/alpine-fde-finalize" "$RUN/tooling.listing" \
    && grep -qx "etc/runlevels/default/alpine-fde-finalize" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/flock" "$RUN/tooling.listing" \
    && ! grep -E '^(etc|usr)/' "$RUN/tooling.listing" | grep -qE 'systemd|debian-fde'; then
    _assert_result ok "S-21 fixture: tooling payload built (CLI + Stage-1 docs + advisory oneshot + rc-update record + closures, NO systemd)" ""
else
    _assert_result not-ok "S-21 fixture: tooling payload built" \
        "required entries missing from (or forbidden entries in) the tar listing (see $RUN/tooling.listing)"
fi

# ============================================================================
# Fixture stage 3: the enriched rootfs payload + the ONE installer boot.
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
tar -tzf "$RUN/enriched.tar.gz" | grep -qxE '\./?etc/alpine-fde/install-state.json' \
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
# the SB-on booted PCR 7 (enrolled vars are deterministic across boots) — the
# d7 input of boot B's host-composed {7,11} policy signature
PCR7_SBON=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_SBON" ]] || { echo "s21: no PCR 7 print in the installer console"; exit 1; }
# the installed-state handoff shape survived the populate: keyslot 0 only, no token
META1=$(disk_metadata "$RUN/disk.img")
assert_eq "installer boot: disk still exactly 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META1")"
assert_eq "installer boot: disk still ZERO tokens" "{}" "$(disk_token_json "$RUN/disk.img")"

# ============================================================================
# Fixture stage 4: the feeding UKI (§8.2 hook unlock + DEBUG SHELL seam) and
# the {7,11} policy signature for boot B's token upgrade.
# ============================================================================
DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-feed 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-feed.efi"
D11_PRED=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_PRED" ]] || { echo "s21: no enter-initrd d11 prediction from the feed build"; exit 1; }
run_stage esp_make-feed 300 esp_make "$RUN/esp-feed.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-feed.efi"

# the {7,11} release-key-signed policy entry (s19/s20's pcrsign leg, composed
# host-side with the harness helper): d7 = the installer boot's SB-on PCR 7,
# d11 = the feed UKI's enter-initrd prediction — exactly what the upgraded
# token's G-B6 gate verifies against the LIVE boot B PCRs
run_stage pcrsig-combined 120 \
    uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-711.json" \
    "$PCR7_SBON" "$D11_PRED" "$RUN/keys" || { echo "s21: combined pcrsig composition failed"; exit 1; }
assert_eq "S-21: combined .pcrsig entry pol == policy_digest(SB-on d7, enter-initrd d11)" \
    "$(policy_digest "$PCR7_SBON" "$D11_PRED")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-pcrsig-711.json")"

# the payload drive for the fed boots: the .pcrsig (first 64 KiB) + tooling tail
run_stage pcrsig_disk-feed 60 uki_pcrsig_disk "$RUN/pcrsig-feed.img" "$RUN/uki-pcrsig-711.json"
_budget_check pcrsig-tooling-drive
cat "$RUN/pcrsig-feed.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-feed-tooling.img"

# _run_fed_boot <boot-dir> <disk-img> <vars.fd> — boot with the feeding UKI on
# the SHIPPED §8.2 hook unlock: the disk carries NO token, so the hook reports
# unseal_token_missing and arms its bounded keyslot-0 recovery loop; feed the
# slot-0 passphrase (prompt-synchronized — the hook's read has NO timeout) and
# hand over to the fed session at the DEBUG SHELL. Re-feeds on TCG console
# corruption: a shredded feed line earns the NEXT prompt (arithmetic markers
# are useless here — the hook owns the prompt text).
_run_fed_boot() {
    local bdir="$1" bimg="$2" vars="$3" n
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
    for n in 1 2 3; do
        # 600 s (was 300): this box's boots crawl under background tenants
        # (live-seen 2026-09-22 — hook prompts past the 300 s mark); the
        # hook's read has no timeout, so the feed stays prompt-synchronized.
        if uki_wait_hook_prompt "$n" 600 "$bdir"; then
            feed_line "$bdir/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
        else
            _hang_fail CONSOLE-WAIT "hook recovery prompt $n" "never appeared"
        fi
        grep -q "debian-fde: UNSEALED" "$bdir/console.log" 2>/dev/null && break
    done
    wait_console "$bdir" "debian-fde: UNSEALED" 120
    wait_console "$bdir" "DEBUG SHELL on console" 300
}

# _feed_common <boot-dir> — the shared fed-session prefix: tooling untar,
# on-disk fixture proof, CLI environment.
# P4 asserts the `installed`-state fixture ON THE DISK (mount subvol=@),
# including the advisory oneshot + its rc-update enable record.
_feed_common() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
    wait_console "$bdir" "P2A=0" 300
    feed_line "$bdir/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
    wait_console "$bdir" "P2B-42-OK" 300
    feed_line "$bdir/serial.sock" \
        'mkdir -p /mnt /run/bu && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && cat /mnt/etc/alpine-fde/install-state.json && ls -l /mnt/etc/init.d/alpine-fde-finalize /mnt/etc/runlevels/default/ && cat /mnt/etc/crypttab && ln -sf /dev/vdb /run/bu/'"$DISK_UUID"' && echo P4-$((41+3))-OK'
    wait_console "$bdir" "P4-44-OK" 300
    # the CLI/service environment: by-uuid seam (no udev reliance), payload
    # wrappers, and DEBIAN_FDE_ROOT=/mnt — the legs mutate the DISK documents.
    # DEBIAN_FDE_CMD_DIR points at the shipped lib staged under /opt/alpine-fde
    # (what the oneshot's own default and the openrc-run service resolve);
    # DEBIAN_FDE_PCRSIG is the host-composed {7,11} policy on the payload drive
    # (boot B's token-upgrade input; s19/s20's DEBIAN_FDE_PCRSIG seam).
    feed_line "$bdir/serial.sock" \
        "export DEBIAN_FDE_NO_INSTALL=1 DEBIAN_FDE_TCTI=device:/dev/tpmrm0 DEBIAN_FDE_BY_UUID_DIR=/run/bu DEBIAN_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd DEBIAN_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty DEBIAN_FDE_ROOT=/mnt DEBIAN_FDE_EVENTLOG=/evtlog-absent DEBIAN_FDE_TMPDIR=/tmp DEBIAN_FDE_KEYDIR=/etc/alpine-fde/keys DEBIAN_FDE_KEY_PASSPHRASE=$S21_KEYPASS DEBIAN_FDE_RECOVERY_PASSPHRASE=$S21_RECOVERY DEBIAN_FDE_PCRSIG=/pcrsig.json && echo P5-\$((43))-OK"
    wait_console "$bdir" "P5-43-OK" 120
}

# _rekey_slot0 <boot-dir> — the Stage-1 credential-ceremony stand-in (§9.1
# step 4, amended): the fixture's well-known slot-0 passphrase is §13-floor-
# BLOCKLISTED, so keyslot 0 is rekeyed in-guest to the floored recovery
# passphrase that authorizes the guided Stage 3 (/kf0 = the embedded slot-0
# credential the UKI carries).
_rekey_slot0() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        "printf %s $S21_RECOVERY > /rp && cryptsetup luksChangeKey --key-slot 0 /dev/vdb /rp --key-file /kf0 && echo RK-\$((44+1))-OK"
    wait_console "$bdir" "RK-45-OK" 600
}

# _feed_postcheck <boot-dir> — the on-disk post-state evidence (console-borne:
# the LUKS/btrfs container is not host-mountable unprivileged)
_feed_postcheck() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'echo "P7STATE $(grep -o "\"state\": \"[a-z-]*\"" /mnt/etc/alpine-fde/install-state.json | head -1)"; echo "P7TOK $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq "[.tokens[] | select(.type==\"systemd-tpm2\")] | length")"; echo "P7SLOTS $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c ".keyslots | keys")"; grep expected_pcr7 /mnt/etc/alpine-fde/baseline.json; echo "P7ATT $(cat /mnt/etc/alpine-fde/finalize-attempt.txt 2>/dev/null | grep -o "will retry next boot" || echo none)"; echo "P7BANNER $(grep -c "NOT finalized" /mnt/etc/motd)"; echo P7-$((41+4))-DONE'
    wait_console "$bdir" "P7-45-DONE" 300
    feed_line "$bdir/serial.sock" 'sync; poweroff -f'
    run_stage "qemu_wait:$(basename "$bdir")" "$((QEMU_TIMEOUT + 60))" qemu_wait "$bdir" "$QEMU_TIMEOUT"
    CURRENT_QEMU_DIR=""
}

# _await_rc <boot-dir> — wait out a `... ; echo P6-RC=$?` leg
_await_rc() {
    local bdir="$1" i=0
    until grep -qE 'P6-RC=[0-9]+' "$bdir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$bdir" "console-wait:P6-RC"
        _budget_check "console-wait:P6-RC"
        (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "the leg never returned"
        sleep 1
        i=$((i + 1))
    done
    grep -oE 'P6-RC=[0-9]+' "$bdir/console.log" | head -1 | cut -d= -f2
}

# ============================================================================
# BOOT A — §10 first-boot row: SB OFF -> advisory stays advisory, the service
# failure is contained to the retry marker, the guided guard HALTS (64).
# ============================================================================
A="$RUN/boot-a"
cp "$RUN/disk.img" "$RUN/disk-a.img"
echo "# boot A: SB-off vars — advisory oneshot + contained service failure + fail-closed guard"
_run_fed_boot "$A" "$RUN/disk-a.img" "$RUN/vars-unenrolled.fd"
_feed_common "$A"
_rekey_slot0 "$A"
# leg (a): the ADVISORY oneshot — start() driven exactly as openrc-run would.
# Every leg captures the rc through a tested list (`|| RC=$?`): fin_service_main
# arms the lib's strict_mode inside the shell it is sourced into, and a bare
# failing command under `set -e` would kill the fed shell before the echo.
feed_line "$A/serial.sock" \
    'RC=0; . /etc/init.d/alpine-fde-finalize; start || RC=$?; echo ADVRC=$RC'
i=0
until grep -q "ADVRC=" "$A/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$A" "console-wait:ADVRC"; _budget_check "console-wait:ADVRC"; (( i < 120 )) || _hang_fail CONSOLE-WAIT ADVRC advisory; sleep 1; i=$((i + 1))
done
# leg (b): the SERVICE completion — fin_service_main, failure-contained; the
# subshell keeps strict_mode (set -eu) from leaking into the fed shell
feed_line "$A/serial.sock" \
    'RC=0; ( . /opt/alpine-fde/lib/cmd/finalize.sh; fin_service_main ) || RC=$?; echo SVCRC=$RC'
i=0
until grep -q "SVCRC=" "$A/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$A" "console-wait:SVCRC"; _budget_check "console-wait:SVCRC"; (( i < 300 )) || _hang_fail CONSOLE-WAIT SVCRC service; sleep 1; i=$((i + 1))
done
# leg (c): the GUIDED CLI — the fw_sb_state gate must halt fail-closed (64)
feed_line "$A/serial.sock" \
    'RC=0; timeout 300 /opt/alpine-fde/bin/alpine-fde finalize || RC=$?; echo P6-RC=$RC'
CLI_RC_A=$(_await_rc "$A")
_feed_postcheck "$A"

LOG_A=$(cat "$A/console.log" 2>/dev/null || true)
assert_contains "[boot A] init ran" "$LOG_A" "debian-fde-harness: init started"
assert_contains "[boot A] the shipped §8.2 hook ran the enter-initrd extend" "$LOG_A" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[boot A] hook found NO token (handoff window shape)" "$LOG_A" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[boot A] fed slot-0 recovery passphrase unsealed the volume (§10 way out)" "$LOG_A" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[boot A] UNSEALED" "$LOG_A" "debian-fde: UNSEALED"
assert_contains "[boot A] tooling extracted in-guest" "$LOG_A" "P2B-42-OK"
assert_contains "[boot A] installed-state fixture on disk: state=installed" "$LOG_A" '"state": "installed"'
assert_contains "[boot A] the advisory oneshot is staged + enabled (init.d + runlevels/default)" "$LOG_A" \
    "alpine-fde-finalize -> /etc/init.d/alpine-fde-finalize"
assert_contains "[boot A] crypttab member resolved (root UUID= line, not the seam echo)" "$LOG_A" \
    "root UUID=$DISK_UUID none luks"
assert_contains "[boot A] Stage-1 stand-in: recovery passphrase rekeyed into keyslot 0" "$LOG_A" "RK-45-OK"
# --- leg (a): the advisory oneshot stays ADVISORY under SB-off ---------------
assert_eq "[boot A] advisory oneshot rc 0 (NEVER blocks boot, ADR-20 amended)" "0" \
    "$(grep -oE 'ADVRC=[0-9]+' "$A/console.log" | head -1 | cut -d= -f2)"
assert_contains "[boot A] advisory: the not-finalized WARNING with the live state" "$LOG_A" \
    "WARNING: Alpine FDE trust is NOT finalized (install state: installed)."
assert_contains "[boot A] advisory: the SB-off fw_sb_state reading (the amended guard text)" "$LOG_A" \
    "Secure Boot guard failed: secureboot=0 setup_mode=1 pk=0"
assert_contains "[boot A] advisory: the finalize guidance (the amended manual-completion line)" "$LOG_A" \
    "or complete it manually with: alpine-fde finalize"
# --- leg (b): the service failure is contained (marker, no mutations) --------
assert_ne "[boot A] service completion FAILED contained (rc != 0, never an OpenRC failure)" "0" \
    "$(grep -oE 'SVCRC=[0-9]+' "$A/console.log" | head -1 | cut -d= -f2)"
assert_contains "[boot A] ADR-8 marker: retry-next-boot reason on the DISK doc" "$LOG_A" \
    "will retry next boot"
# --- leg (c): the guided guard halts fail-closed ------------------------------
assert_eq "[boot A] guided finalize halted fail-closed (rc 64)" "64" "$CLI_RC_A"
assert_contains "[boot A] recovery passphrase VERIFIED first (guard is step 3, not step 1)" "$LOG_A" \
    "recovery passphrase verified against keyslot 0 (attempt 1)"
assert_contains "[boot A] fw_sb_state guard saw Secure Boot OFF" "$LOG_A" \
    "fw_sb_state: secureboot=0"
assert_contains "[boot A] the §9.1 instruction text (enable SB in BIOS setup)" "$LOG_A" \
    "Secure Boot is not enabled with your custom keys"
# Needle note (registry 2026-09-23): the guard's die() text reached the serial
# console with ONE DUPLICATED byte ("the volume rremains safely locked") — a
# UART burst artifact under registry load, in exactly this flood-phase line.
# Match the corruption-surviving tail of the sentence instead of the full
# phrase (the ordering proof below still pins the guard text itself).
assert_contains "[boot A] the volume remains safely locked (no enrollment, no purge)" "$LOG_A" \
    "safely locked"
# ordering: the guard halt PRECEDES every completion mutation — the audit and
# the token upgrade never run (line-number proof against the post-state)
_guard_line=$(grep -nm1 -F "Secure Boot is not enabled with your custom keys" "$A/console.log" | cut -d: -f1)
_audit_line=$(grep -nm1 -F "finalizing the baseline from live values" "$A/console.log" | cut -d: -f1)
_upgr_line=$(grep -nm1 -F "token upgraded to Mechanism B" "$A/console.log" | cut -d: -f1)
if [[ -n "$_guard_line" && -z "$_audit_line" && -z "$_upgr_line" ]]; then
    _assert_result ok "[boot A] ZERO baseline capture, ZERO token upgrade after the guard" ""
else
    _assert_result not-ok "[boot A] ZERO baseline capture, ZERO token upgrade after the guard" \
        "guard=$_guard_line audit=$_audit_line upgrade=$_upgr_line"
fi
assert_not_contains "[boot A] no baseline finalization anywhere (SB-off)" "$LOG_A" \
    "finalizing the baseline from live values"
assert_not_contains "[boot A] NO cryptenroll anywhere (Mechanism B never invokes it)" "$LOG_A" \
    "$(sentinel_of cryptenroll_enrolled)"
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
assert_contains "[boot A] post: the retry-next-boot marker is ON DISK (service leg)" "$LOG_A" \
    "P7ATT will retry next boot"
assert_not_contains "[boot A] no interactive prompt ever appeared (sentinel table)" "$LOG_A" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot A] no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
# post-boot HOST: the BOOTED image's LUKS metadata is unchanged: 1 keyslot,
# 0 tokens. The pristine fixture copy never changed at all.
META_A=$(disk_metadata "$A/disk.img")
assert_eq "[boot A] host(booted img): metadata unchanged — 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META_A")"
assert_eq "[boot A] host(booted img): metadata unchanged — ZERO tokens" "{}" \
    "$(disk_token_json "$A/disk.img")"
assert_eq "[boot A] host(booted img): keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_A")"
assert_eq "[boot A] host(fixture img): untouched — ZERO tokens" "{}" \
    "$(disk_token_json "$RUN/disk.img")"

# ============================================================================
# BOOT B — Stage-3 happy proof: SB ON -> the completion chain runs end-to-end.
# ============================================================================
B="$RUN/boot-b"
cp "$RUN/disk.img" "$RUN/disk-b.img"
echo "# boot B: SB-on vars — the shared completion chain (audit --init + {7,11} upgrade + state finalized LAST)"
_run_fed_boot "$B" "$RUN/disk-b.img" "$RUN/vars-enrolled.fd"
_feed_common "$B"
_rekey_slot0 "$B"
feed_line "$B/serial.sock" \
    'RC=0; timeout 300 /opt/alpine-fde/bin/alpine-fde finalize || RC=$?; echo P6-RC=$RC'
CLI_RC_B=$(_await_rc "$B")
_feed_postcheck "$B"

LOG_B=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] init ran" "$LOG_B" "debian-fde-harness: init started"
assert_contains "[boot B] hook found NO token before the completion (window shape)" "$LOG_B" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[boot B] fed slot-0 recovery passphrase unsealed the volume" "$LOG_B" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[boot B] UNSEALED" "$LOG_B" "debian-fde: UNSEALED"
assert_contains "[boot B] pre-state: installed (on disk)" "$LOG_B" '"state": "installed"'
assert_contains "[boot B] Stage-1 stand-in: recovery rekeyed into keyslot 0" "$LOG_B" "RK-45-OK"
# the completion flow, in order: passphrase verify -> release.pem -> audit
# --init -> ONE token upgrade -> purge crash-skip -> banner clear -> state LAST
assert_contains "[boot B] recovery passphrase VERIFIED against keyslot 0 (§9.1 amended)" "$LOG_B" \
    "recovery passphrase verified against keyslot 0 (attempt 1)"
assert_contains "[boot B] release.pem encrypted in place (ADR-18)" "$LOG_B" \
    "release.pem encrypted (AES-256 PBKDF2, ADR-18)"
assert_contains "[boot B] audit --init finalized the pending baseline from live values" "$LOG_B" \
    "finalizing the baseline from live values (audit --init"
assert_contains "[boot B] the member upgraded to Mechanism B {PCR 7, PCR 11}" "$LOG_B" \
    "debian-fde: member $DISK_UUID: token upgraded to Mechanism B {PCR 7, PCR 11}"
assert_contains "[boot B] no ephemeral keyslot remained (crash-skip of the purge)" "$LOG_B" \
    "no temporary ephemeral keyslot remains — skipping the purge"
assert_contains "[boot B] the unfinalized MOTD banner cleared" "$LOG_B" \
    "unfinalized MOTD/issue banner cleared"
assert_contains "[boot B] install finalized marker (§9.1 Stage 3)" "$LOG_B" \
    "debian-fde: install finalized"
assert_contains "[boot B] the §9.1 off-machine backup prompt" "$LOG_B" \
    "back up the key material off-machine now"
assert_contains "[boot B] audit summary names the finalized baseline" "$LOG_B" \
    "debian-fde: audit summary: baseline /mnt/etc/alpine-fde/baseline.json"
assert_eq "[boot B] production finalize rc 0" "0" "$CLI_RC_B"
assert_eq "[boot B] token upgraded EXACTLY ONCE (single-member seal)" "1" \
    "$(grep -cF "token upgraded to Mechanism B" <<<"$LOG_B")"
assert_not_contains "[boot B] NO cryptenroll anywhere (Mechanism B never invokes it)" "$LOG_B" \
    "$(sentinel_of cryptenroll_enrolled)"
# ordering: the upgrade precedes the finalized transition (state written LAST)
_upgrb_line=$(grep -nm1 -F "debian-fde: member $DISK_UUID: token upgraded" "$B/console.log" | cut -d: -f1)
_finb_line=$(grep -nm1 -F "debian-fde: install finalized" "$B/console.log" | cut -d: -f1)
if [[ -n "$_upgrb_line" && -n "$_finb_line" ]] && (( _upgrb_line < _finb_line )); then
    _assert_result ok "[boot B] token upgrade precedes the finalized transition (state written LAST, §9.1)" ""
else
    _assert_result not-ok "[boot B] token upgrade precedes the finalized transition" \
        "upgrade=$_upgrb_line finalized=$_finb_line"
fi
assert_contains "[boot B] post: install state NOW finalized (written to the DISK doc)" "$LOG_B" \
    "P7STATE \"state\": \"finalized\""
assert_not_contains "[boot B] post: baseline no longer pending" "$LOG_B" \
    '"expected_pcr7": "pending"'
if grep -qE '"expected_pcr7": "[0-9a-f]{64}"' "$B/console.log"; then
    _assert_result ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" ""
else
    _assert_result not-ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" \
        "no finalized expected_pcr7 line on the console"
fi
assert_contains "[boot B] post: exactly ONE systemd-tpm2 token" "$LOG_B" "P7TOK 1"
assert_contains "[boot B] post: token on a fresh keyslot (0+1)" "$LOG_B" 'P7SLOTS ["0","1"]'
assert_contains "[boot B] post: NO attempt marker stands after the completion (clean exit, istate_attempt_clear)" "$LOG_B" \
    "P7ATT none"
assert_contains "[boot B] post: the motd banner line is GONE (stripped line-exactly)" "$LOG_B" \
    "P7BANNER 0"
assert_not_contains "[boot B] no interactive prompt ever appeared (sentinel table)" "$LOG_B" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot B] no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
# post-boot HOST: the upgraded metadata — read the BOOTED image (the VM
# mutated its vdb copy; the pre-boot copies stay pristine by design)
META_B=$(disk_metadata "$B/disk.img")
NTOK=$(disk_token_json "$B/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[boot B] host(booted img): exactly ONE systemd-tpm2 token" "1" "$NTOK"
TOKPCRS=$(disk_token_json "$B/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')
assert_eq "[boot B] host(booted img): the token binds {PCR 7, PCR 11}" "[7,11]" "$TOKPCRS"
TOKSLOT=$(disk_token_json "$B/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "[boot B] host(booted img): token on keyslot 1 (recovery slot 0 untouched)" "1" "$TOKSLOT"
assert_eq "[boot B] host(booted img): 2 keyslots (recovery + token, I1 at-rest)" "2" \
    "$(jq -r '.keyslots | length' <<<"$META_B")"
assert_eq "[boot B] host(booted img): recovery keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_B")"
# and the ORIGINAL fixture copy is untouched by the boot (boot isolated)
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
