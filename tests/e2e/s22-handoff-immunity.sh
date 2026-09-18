#!/usr/bin/env bash
# tests/e2e/s22-handoff-immunity.sh — §12 S-22 (handoff window immunity).
#
# The handoff window (§8.4/§9.1): Stage 1 `install` is done (keyslot 0
# recovery passphrase only, NO TPM enrollment yet) and the machine is
# rebooting into BIOS setup for the Secure Boot ceremony. In that window the
# volume key exists ONLY passphrase-wrapped in the argon2id keyslot 0 — there
# is no token ANY tool could consume, so a foreign OS / live USB booted
# against the disk cannot do better than brute-force the passphrase floor.
#
# Fixture (host-side, the s21 `installed`-state builder replicated
# scenario-locally per the W2b file-ownership split — no shared helper file):
# ONE installer-stage boot lays a LUKS2 container (keyslot 0 argon2id, ZERO
# tokens) with a §9.1 Btrfs @-subvol rootfs carrying the Stage-1 documents
# (/etc/debian-fde/{install-state.json=installed, baseline.json PENDING,
# debian-fde.conf}, crypttab, the REAL debian-fde-finalize.service + enable
# symlink, /usr/local/bin/debian-fde + the /opt/debian-fde tooling tree).
# Host-side, BEFORE any boot: tokens == {} && keyslots == {"0"} argon2id.
#
#   boot A (same machine — SB vars carry the custom keys; enrollment has not
#           happened, which is the point): the harness stand-in enroll branch
#           is kept OUT of the loop by a DEAD fixture token (s00b mechanism);
#           the token path is attempted and REFUSED -> console fallback armed
#           -> FED slot-0 recovery passphrase -> UNSEALED. In the fed session
#           the dead suppressor is removed (teardown) and the §12 S-22
#           primitive is exercised on the then-token-free volume:
#             `cryptsetup open --type luks --token-only /dev/vdb x`
#           must FAIL (rc != 0, no mapper node) — no token exists to try.
#   boot B (foreign machine): the SAME disk against a FRESH swtpm state
#           (different storage seed = different SRK, the s11 pattern). The
#           passphrase unlock still WORKS (keyslot 0 is TPM-independent — the
#           documented recovery way out) but the token path stays impossible:
#           the token-only open fails again. Never unlocked-by-token anywhere.
#
# Post-boot host (both boots): tokens == {} && keyslots == {"0"} argon2id —
# the volume key was exclusively behind keyslot 0 Argon2id for the whole
# window; nothing in either boot mutated the LUKS2 metadata.
#
# Fidelity notes (documented, not silent):
#   * The dead fixture token exists ONLY to keep the harness initrd's own
#     stand-in enroll branch out of the loop (s00b precedent) — without it a
#     REAL token would be enrolled against the live PCRs and the S-22
#     premise (token-free window) would be destroyed. It is removed in the
#     fed session BEFORE the token-only attempt; the refusal SENTINEL
#     asserted on the console is the real token-path refusal of the boot's
#     unlock phase.
#   * `cryptsetup open --token-only` is the consumer primitive a foreign OS
#     would run; in this harness it runs inside the fed initrd session (the
#     guest userspace closure — cryptsetup + the systemd-tpm2 token plugin +
#     libtss2 — is the same pinned trixie set every scenario uses).
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

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
DISK_MIB=1600

export QEMU_TIMEOUT="${DEBIAN_FDE_S22_TIMEOUT:-1200}"

# --- hardening: bounded stages, loud failures, overall budget --------------------
OVERALL_BUDGET="${DEBIAN_FDE_S22_BUDGET:-7200}"
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
    ( sleep "$tmo"; kill -9 -"$pid" 2>/dev/null; exit 125 ) &
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
wait_console() {
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qF -- "$pat" "$dir/console.log" 2>/dev/null && return 0
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

# ============================================================================
# Fixture: the `installed`-state image (the s21 builder, embedded here)
# ============================================================================
keys_create "$RUN/keys" || { echo "s22: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
assert_contains "fixture: enrolled vars SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
run_stage disk_make_luks 120 disk_make_luks "$RUN/disk.img" "$DISK_MIB"
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s22: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s22: empty LUKS uuid"; exit 1; }

# THE S-22 HOST ASSERT OF RECORD: the handoff window opens with the volume
# key exclusively behind keyslot 0 (argon2id) and NO token anywhere.
META0=$(disk_metadata "$RUN/disk.img")
assert_eq "S-22 handoff shape: keyslots == {0}" '["0"]' "$(jq -c '.keyslots | keys' <<<"$META0")"
assert_eq "S-22 handoff shape: keyslot 0 is argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META0")"
assert_eq "S-22 handoff shape: tokens == {}" "{}" "$(disk_token_json "$RUN/disk.img")"

# --- tooling staging (s00b closures, embedded) + Stage-1 documents --------------
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar"
mkdir -p "$TOOLING/opt/debian-fde" "$TOOLING/etc/debian-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/usr/local/bin" "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" \
    "$TOOLING/opt/flockbin/lib" "$TOOLING/etc/systemd/system/multi-user.target.wants"
for d in bin lib hooks; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/debian-fde/$d"
done
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
    echo "s22: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s22: flock closure introduces a library the payload does not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
printf '#!/bin/sh\nexec /usr/bin/systemd-cryptenroll --unlock-key-file=/kf0 "$@"\n' \
    >"$TOOLING/usr/bin/cryptenroll-kf"
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
printf '#!/bin/sh\nexec /opt/debian-fde/bin/debian-fde "$@"\n' >"$TOOLING/usr/local/bin/debian-fde"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/cryptenroll-kf" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock" "$TOOLING/usr/local/bin/debian-fde"

cat >"$TOOLING/etc/debian-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
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
run_stage tooling-unit 60 cp "$REPO/hooks/systemd/debian-fde-finalize.service" \
    "$TOOLING/etc/systemd/system/debian-fde-finalize.service"
ln -sfn /etc/systemd/system/debian-fde-finalize.service \
    "$TOOLING/etc/systemd/system/multi-user.target.wants/debian-fde-finalize.service"
run_stage tooling-tar 300 tar -C "$TOOLING" -cf "$RUN/tooling.tar" opt etc usr
tar -tf "$RUN/tooling.tar" >"$RUN/tooling.listing"
if grep -qx "etc/debian-fde/install-state.json" "$RUN/tooling.listing" \
    && grep -qx "etc/systemd/system/debian-fde-finalize.service" "$RUN/tooling.listing" \
    && grep -qx "etc/systemd/system/multi-user.target.wants/debian-fde-finalize.service" "$RUN/tooling.listing" \
    && grep -qx "usr/local/bin/debian-fde" "$RUN/tooling.listing"; then
    _assert_result ok "S-22 fixture: Stage-1 payload assembled (state doc + REAL unit + enable symlink)" ""
else
    _assert_result not-ok "S-22 fixture: Stage-1 payload assembled" \
        "required entries missing from tar listing (see $RUN/tooling.listing)"
fi

# --- enriched rootfs payload + the ONE installer boot ----------------------------
_PAYLOAD_TARBASE="$ROOTFS_CACHE_DIR/debian-13-generic-amd64-rootustar.tar.gz"
if [[ ! -f "$_PAYLOAD_TARBASE" ]]; then
    run_stage payload-derive 2400 bash -c \
        "$(declare -f rootfs_payload_image rootfs_ensure _rootfs_pin_lookup rootfs_cache_dir); \
         $(declare -p ROOTFS_CACHE_DIR _ROOTFS_PINS _DEB_BASE _CLOUD_BASE 2>/dev/null); \
         rootfs_payload_image '$RUN/payload-derive-scratch.img' >/dev/null"
fi
[[ -f "$_PAYLOAD_TARBASE" ]] || { echo "s22: derived rootfs payload missing after derivation"; exit 1; }
_budget_check payload-enrich
echo "# s22: enriching the rootfs payload (base tree + Stage-1 additions, ONE tar)"
# NOT a concatenated archive: busybox tar stops at the first stream's
# end-of-archive marker (observed live 2026-09-19 in s21) — merge and re-tar.
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
tar -tzf "$RUN/enriched.tar.gz" | grep -qxE '\./?etc/debian-fde/install-state.json' \
    || { echo "s22: additions missing from the enriched payload"; exit 1; }
_assert_result ok "S-22 fixture: enriched payload carries the Stage-1 additions" ""

DEBIAN_FDE_ROOTFS_SHA="$ROOTFS_SHA" DEBIAN_FDE_ROOTFS_BYTES="$ROOTFS_BYTES" \
    run_stage uki_build-installer 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "debian-fde-stage=install"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make-installer 300 esp_make "$RUN/esp-installer.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
echo "# s22: installer boot — lay the installed-state disk (TCG)"
CURRENT_QEMU_DIR="$RUN"
run_stage qemu_run-installer 60 qemu_run "$RUN" "$RUN/esp-installer.img" "$RUN/disk.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/payload.img"
_qemu_alive "$RUN"
_rearm_trap
run_stage qemu_wait-installer "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""
grep -q "debian-fde: POWEROFF" "$RUN/console.log" || {
    echo "s22: installer boot failed (no POWEROFF sentinel)"; exit 1; }
META1=$(disk_metadata "$RUN/disk.img")
assert_eq "installer boot: disk still exactly 1 keyslot" "1" \
    "$(jq -r '.keyslots | length' <<<"$META1")"
assert_eq "installer boot: disk still ZERO tokens (window intact)" "{}" \
    "$(disk_token_json "$RUN/disk.img")"

# --- the feeding UKI + fixtures ---------------------------------------------------
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
_import_dead_token() {
    run_stage "dead-token-import:$1" 60 cryptsetup token import "$1" \
        --token-id 9 --json-file "$_tok_json"
}

# _run_fed_boot <boot-dir> <disk-img> <swtpm-dir> <vars.fd> — boot, feed the
# slot-0 passphrase through the console fallback, hand over to the fed session.
_run_fed_boot() {
    local bdir="$1" bimg="$2" tpmdir="$3" vars="$4"
    mkdir -p "$bdir"
    cp "$RUN/harness-feed.efi" "$bdir/harness.efi"
    cp "$RUN/esp-feed.img" "$bdir/esp.img"
    cp "$bimg" "$bdir/disk.img"
    _ensure_tpm "$tpmdir"
    _rearm_trap
    CURRENT_QEMU_DIR="$bdir"
    run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$bdir/esp.img" \
        "$bdir/disk.img" "$vars" "$tpmdir"
    _qemu_alive "$bdir"
    _rearm_trap
    wait_console "$bdir" "awaiting console line" "$QEMU_TIMEOUT"
    feed_line "$bdir/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    wait_console "$bdir" "DEBUG SHELL on console" 300
}

# _s22_probe <boot-dir> — the fed-session S-22 primitive: after the dead
# suppressor is removed, the volume is token-free; `cryptsetup open
# --token-only` must FAIL CLOSED (the §12 S-22 consumer primitive). The rc
# value is captured and asserted NONZERO (the exact cryptsetup rc is not
# pinned here — host-side probing cannot exercise the token path without
# device-mapper; the honest in-guest observable is rc != 0 + no mapper node,
# with the failure output itself on the console as evidence).
_s22_probe() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" 'cryptsetup token remove --token-id 9 /dev/vdb && echo T9-$((51+1))-GONE'
    wait_console "$bdir" "T9-52-GONE" 120
    # the on-disk handoff-window state doc (console-borne: LUKS/btrfs is not
    # host-mountable unprivileged); arithmetic markers (s00b convention — a
    # literal marker would match its own tty echo)
    feed_line "$bdir/serial.sock" \
        'mkdir -p /mnt && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && grep -o "\"state\": \"[a-z]*\"" /mnt/etc/debian-fde/install-state.json && echo P4-$((41+3))-OK'
    wait_console "$bdir" "P4-44-OK" 300
    # THE S-22 PRIMITIVE: token-only open with ZERO tokens -> fail closed
    feed_line "$bdir/serial.sock" \
        'cryptsetup open --type luks --token-only /dev/vdb s22probe 2>/tmp/s22.out; echo S22RC=$?; head -3 /tmp/s22.out; [ -e /dev/mapper/s22probe ] && echo S22MAP-$((46+2))-PRESENT || echo S22NOM-$((46+1))-OK; echo S22P-$((46+0))-DONE'
    wait_console "$bdir" "S22P-46-DONE" 300
    feed_line "$bdir/serial.sock" 'sync; poweroff -f'
    run_stage "qemu_wait:$(basename "$bdir")" "$((QEMU_TIMEOUT + 60))" qemu_wait "$bdir" "$QEMU_TIMEOUT"
    CURRENT_QEMU_DIR=""
}

# _s22_rc <boot-dir> — the guest-captured token-only open rc
_s22_rc() {
    grep -oE 'S22RC=[0-9]+' "$1/console.log" 2>/dev/null | head -1 | cut -d= -f2
}

# ============================================================================
# BOOT A — the handoff window on the machine itself: no token exists to try
# ============================================================================
A="$RUN/boot-a"
cp "$RUN/disk.img" "$RUN/disk-a.img"
_import_dead_token "$RUN/disk-a.img"
echo "# boot A: same machine, SB vars irrelevant (no enrollment) — token path impossible"
_run_fed_boot "$A" "$RUN/disk-a.img" "$RUN/tpm" "$RUN/vars-enrolled.fd"
_s22_probe "$A"

LOG_A=$(cat "$A/console.log" 2>/dev/null || true)
assert_contains "[boot A] init ran" "$LOG_A" "debian-fde-harness: init started"
assert_contains "[boot A] harness stand-in OUT of the loop (dead suppressor token)" "$LOG_A" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[boot A] token path attempted and REFUSED (the boot's only token)" "$LOG_A" \
    "$(sentinel_of token_unusable)"
assert_contains "[boot A] fed slot-0 recovery passphrase unsealed the volume" "$LOG_A" \
    "debian-fde: UNSEALED"
assert_contains "[boot A] suppressor removed — volume token-free again" "$LOG_A" "T9-52-GONE"
assert_contains "[boot A] on-disk install state: installed (window)" "$LOG_A" '"state": "installed"'
assert_contains "[boot A] token-only open FAILED closed (rc captured, nonzero)" "$LOG_A" \
    "S22RC="
assert_ne "[boot A] token-only open rc != 0 (no token to try)" "0" "$(_s22_rc "$A")"
assert_not_contains "[boot A] token-only open produced NO mapper node" "$LOG_A" \
    "S22MAP-48-PRESENT"
assert_contains "[boot A] token-only open produced NO mapper node" "$LOG_A" "S22NOM-47-OK"
assert_not_contains "[boot A] NEVER unlocked by a token (sentinel table)" "$LOG_A" \
    "$(sentinel_of unlocked)"
assert_not_contains "[boot A] no interactive prompt ever appeared" "$LOG_A" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot A] no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
if [[ -f "$A/qemu.pid" ]] && ! kill -0 "$(cat "$A/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[boot A] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[boot A] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
# post-boot HOST: the BOOTED image, net of the suppressor cycle (imported
# pre-boot, removed in-guest): keyslots == {"0"}, ZERO tokens
META_A=$(disk_metadata "$A/disk.img")
assert_eq "[boot A] host(booted img): metadata unchanged — ZERO tokens" "{}" "$(disk_token_json "$A/disk.img")"
assert_eq "[boot A] host(booted img): metadata unchanged — keyslots == {0}" '["0"]' \
    "$(jq -c '.keyslots | keys' <<<"$META_A")"

# ============================================================================
# BOOT B — foreign machine: fresh swtpm state (different SRK, s11 pattern);
# the passphrase way out still works, the token path stays impossible
# ============================================================================
B="$RUN/boot-b"
cp "$RUN/disk.img" "$RUN/disk-b.img"
_import_dead_token "$RUN/disk-b.img"
_track_swtpm "$RUN/tpm-foreign"
echo "# boot B: FOREIGN TPM (fresh swtpm state) — fed unlock works, token path impossible"
_run_fed_boot "$B" "$RUN/disk-b.img" "$RUN/tpm-foreign" "$RUN/vars-enrolled.fd"
_s22_probe "$B"

LOG_B=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] init ran (foreign TPM booted the same disk)" "$LOG_B" \
    "debian-fde-harness: init started"
assert_contains "[boot B] stand-in OUT of the loop (dead suppressor token)" "$LOG_B" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[boot B] token path attempted and REFUSED (foreign TPM)" "$LOG_B" \
    "$(sentinel_of token_unusable)"
assert_contains "[boot B] slot-0 recovery passphrase STILL unlocks (keyslot 0 is TPM-independent)" \
    "$LOG_B" "debian-fde: UNSEALED"
assert_contains "[boot B] suppressor removed — volume token-free again" "$LOG_B" "T9-52-GONE"
assert_contains "[boot B] on-disk install state: installed (window)" "$LOG_B" '"state": "installed"'
assert_contains "[boot B] token-only open FAILED closed on the foreign machine too (rc nonzero)" "$LOG_B" \
    "S22RC="
assert_ne "[boot B] token-only open rc != 0 (no token to try)" "0" "$(_s22_rc "$B")"
assert_contains "[boot B] token-only open produced NO mapper node" "$LOG_B" "S22NOM-47-OK"
assert_not_contains "[boot B] NEVER unlocked by a token (sentinel table)" "$LOG_B" \
    "$(sentinel_of unlocked)"
assert_not_contains "[boot B] no interactive prompt ever appeared" "$LOG_B" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot B] no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
if [[ -f "$B/qemu.pid" ]] && ! kill -0 "$(cat "$B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[boot B] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[boot B] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi
META_B=$(disk_metadata "$B/disk.img")
assert_eq "[boot B] host(booted img): metadata unchanged — ZERO tokens" "{}" "$(disk_token_json "$B/disk.img")"
assert_eq "[boot B] host(booted img): metadata unchanged — keyslots == {0}" '["0"]' \
    "$(jq -c '.keyslots | keys' <<<"$META_B")"
assert_eq "[boot B] host(booted img): keyslot 0 still argon2id (the only guard in the window)" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_B")"

rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/enriched.tar.gz" "$RUN/payload-derive-scratch.img"

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
