#!/usr/bin/env bash
# tests/e2e/s20-raid1-member-loss.sh — §10 row "Single drive failure (Btrfs
# RAID1)" + §12 S-20 (member loss & degraded recovery).
#
# IN-SCENARIO bootstrap (fed session — a btrfs raid1 pool must be laid INSIDE
# the LUKS containers, which an unprivileged host cannot open):
#   vda = ESP (primary only — §4.1: secondaries carry no ESP)
#   vdb = LUKS2 member 1 (root1, keyslot 0 argon2id, well-known passphrase)
#   vdc = pcrsig+tooling payload drive (harness contract slot)
#   vdd = LUKS2 member 2 (root2, same passphrase) — extra-drives slot
#   in-guest: both members unlocked, `mkfs.btrfs -d raid1 -m raid1`, the §9.1
#   @ subvolume + a canary file, both container UUIDs printed for the host.
# Host-side: the production crypttab (root1/root2, password-cache=yes, §8.2)
# and the FINAL baseline via the REAL CLI (s00 pattern: fixture efivars +
# boot-console PCR stamping) ride the tooling tail.
#
#   Phase 1 (member loss, fail-closed): member 2's image MOVED AWAY; the fed
#           session unlocks the surviving root1 (the dead suppressor token
#           from the bootstrap keeps the harness stand-in out of the loop;
#           s00b mechanism) and runs the harness initrd's login-stage mount
#           line BYTE-IDENTICALLY (`mount -t btrfs -o subvol=@
#           /dev/mapper/root /newroot`): it MUST FAIL — btrfs refuses a
#           raid1 pool with a missing member without an explicit `degraded`
#           option. The mount error lands on the console; clean poweroff.
#   Phase 2 (rescue, the runbook's live-media leg): fed session on a working
#           copy: `mount -o degraded,subvol=@` — the ONLY way a
#           missing-member pool mounts — asserts the degraded mount option
#           in /proc/mounts + `btrfs filesystem show` state + the canary,
#           clean poweroff.
#   Phase 3a (restore + production finalization): member 2 restored (the
#           PRE-BUILT second-member image back at its path); fed session on
#           the CANONICAL member images unlocks BOTH and runs the PRODUCTION
#           `alpine-fde finalize`: the per-member loop upgrades BOTH
#           containers to the Mechanism B {PCR 7, PCR 11} token
#           (seal_upgrade_token — each member enters finalize with ZERO
#           standing tokens, so the upgrade takes the seal branch exactly
#           once per member, authorized by the operator recovery passphrase
#           verified at keyslot 0), install state finalized (the §8.4 state
#           doc is scenario-ephemeral here — the DURABLE evidence is the
#           standing {7,11} tokens, asserted host-side post-boot).
#   Phase 3b (full pool, zero-input): both members boot with their standing
#           tokens: the harness unlock of root1 is the ZERO-INPUT token path
#           (token_discovered/pcr_sig_added/unlocked sentinels, UNSEALED, no
#           console line ever awaited); the fed session then opens member 2
#           via the SAME production primitive (`cryptsetup open
#           --token-only`) and mounts the COMPLETE pool non-degraded over
#           the §9.1 @ subvolume — canary intact.
#
# FIDELITY NOTES (documented, not silent):
#   * The §4.1 production fail-closed trio for a missing RAID1 member is
#     "systemd-cryptsetup@root2 fails -> sysroot.mount stalls -> initrd
#     poweroff (rd.emergency=poweroff)". The HARNESS initrd is a busybox
#     prototype, and its login-stage dispatch is reachable only after the
#     zero-input token unlock — the fed path cannot drive it. Phase 1
#     therefore runs the login-stage mount line BYTE-IDENTICALLY in the fed
#     session and asserts the same semantics the initrd would hit: plain
#     mount of a missing-member pool FAILS, explicit `-o degraded` is
#     required, and no emergency shell exists to fall into (none is in this
#     initrd). The production dracut sysroot.mount stall semantics remain a
#     documented deferred gap (S-20 scope note, §12).
#   * Member restoration uses the PRE-BUILT second-member image restored to
#     its path (the runbook's `btrfs replace` rebuild is impractical under
#     TCG: a full device replace over an emulated raid1 pool exceeds every
#     budget tried); the restored pool is accepted by the runbook's own
#     check — a non-degraded full-pool mount with the canary intact.
#   * The dead suppressor token (s00b mechanism) exists only to keep the
#     harness stand-in enroll branch out of the loop on the ROOT member;
#     member 1's is removed in the fed session before finalize. Member 2
#     carries NO token into finalize: seal_upgrade_token seals the fresh
#     volume passphrase under the {7,11} policy and adds token + keyslot with
#     no old enrollment to retire — exactly the "first finalization" shape.
#   * UNLOCK PATH PIN (documented, not silent): the feeding UKI pins
#     `debian-fde-unlock=oracle`. The §8.2 hook is the shipped unlock of
#     record, but this scenario's fed sessions are built on the oracle's
#     console-fallback seam ("awaiting console line" -> fed line -> DEBUG
#     SHELL) and its stand-in-enrollment suppressor contract; the shipped
#     hook's bounded recovery loop has no read timeout and 3-strikes to a
#     fail-closed poweroff, which cannot host a multi-command fed session.
#     The oracle is the harness-documented opt-in for exactly this
#     (uki-build.sh: "opt-in, for scenarios that explicitly document it").
#   * The Stage-1 credential ceremony stand-in (§9.1 step 4): the fixture's
#     well-known slot-0 passphrase is §13-floor-BLOCKLISTED (*debian-fde*),
#     so BOTH members are rekeyed in-guest (cryptsetup luksChangeKey
#     --key-slot 0) to the scenario's floored recovery passphrase — the
#     amended contract's at-rest shape (operator recovery at keyslot 0
#     authorizes the guided Stage 3; no key handoff to finalize exists).
#
# §12 negatives on every boot: no interactive passphrase prompt (prompt_re),
# no emergency shell (emergency_forbidden), sentinels via the table only.

set -u
set -m

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
source "$TESTS/lib/sentinels.sh"
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
MEMBER_MIB=1024

# §13-floor-OK credentials for the in-guest finalize (the *debian-fde*
# substring is blocklisted by the entropy floor; >=16 chars passes). The
# recovery passphrase is REKEYED into keyslot 0 of BOTH members in-guest
# (the Stage-1 credential-ceremony stand-in); the key passphrase encrypts
# release.pem at finalize STEP 2 (ADR-18).
S20_RECOVERY='alpine-fde-s20-recovery-6c31a9'
S20_KEYPASS='alpine-fde-s20-release-pbkdf2-j2'

export QEMU_TIMEOUT="${DEBIAN_FDE_S20_TIMEOUT:-900}"

# recalibrated 2026-09-23: run-e2e's outer SCENARIO_BUDGET is now 1500 s —
# the internal budget must fire FIRST (loud exit 125 + stage name) instead of
# letting the outer rc-124 kill win silently.
OVERALL_BUDGET="${DEBIAN_FDE_S20_BUDGET:-1440}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {
    printf '\ns20: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's20: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    exit 125
}
_budget_check() {
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
run_stage_impl() {
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s20: stage $name (watchdog ${tmo}s)"
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
        printf 's20: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
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
# wait_console_soft — wait_console without the hang-fail: rc 1 when the
# pattern never lands, so a caller may re-derive the sentinel from live
# guest state. Needed because the TCG 16550 emulation DROPS/DUPLICATES
# console bytes under kernel-printk load (observed: B2-42-OPEN captured as
# "B2-42-OPEEN" in run 1789845714) — an exact-match wait can starve on a
# sentinel the guest genuinely emitted.
wait_console_soft() {
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qF -- "$pat" "$dir/console.log" 2>/dev/null && return 0
        _budget_check "console-wait:$pat"
        sleep 1
        i=$((i + 1))
    done
    return 1
}

RUN="$TESTS/e2e/.runs/s20-raid1-member-loss-$(date +%s)"
mkdir -p "$RUN"

(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's20-raid1-member-loss-*' | sort -r |
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

# _fresh_pcrs — force ZEROED PCRs for the NEXT qemu boot (repro-proven
# 2026-09-24): after a fed boot exits CLEANLY the swtpm proxy stores the
# volatile state and the fixture's restart RESTORES it into RAM; a boot
# served by that restored instance EXTENDS OVER the previous boot's final
# values (PCR 0/7/11 all shift — "register instability") and the phase-3a
# finalize's fresh-policy gate dies rc 64. swtpm_stop + swtpm_start (the
# second start finds no volatile file) restores the documented per-boot
# zeroed-PCR semantics. The bootstrap's post-boot audit window reads the
# booted register on purpose — this guard is called only at BOOT boundaries.
_fresh_pcrs() {
    local dir="$RUN/tpm" d0 k
    if timeout 20 swtpm_pcrread "$dir" 0 >/dev/null 2>&1; then
        d0=$(swtpm_pcrread "$dir" 0)
        [[ "$d0" =~ ^0{64}$ ]] && return 0
        run_stage "swtpm_stop:$dir" 60 swtpm_stop "$dir"
    fi
    pkill -9 -f "swtpm socket .*$dir/" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/.lock" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl" "$dir/swtpm.sock"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_start:$dir" 90 swtpm_start "$dir"
    _rearm_trap
    d0=$(swtpm_pcrread "$dir" 0)
    [[ "$d0" =~ ^0{64}$ ]] || { echo "s20: TPM not zeroed before a boot (pcr0=$d0)"; exit 1; }
    # settle: a guest TPM command arriving mid-setup times out and the
    # firmware DROPS the measurement (the degraded-boot register — s18's
    # _reanchor_tpm evidence); warm the whole path through the proxy first.
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    return 0
}

_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s20: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s20: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

# _boot_fed <boot-dir> <member1-img> [member2-img] — boot the feeding UKI
# (vdb = <member1-img> used VERBATIM — the caller decides copies vs canonical
# images; vdd = <member2-img> when present), feed the slot-0 passphrase
# through the console fallback, hand over to the DEBUG SHELL.
_boot_fed() {
    local bdir="$1" m1="$2" m2="${3:-}"
    mkdir -p "$bdir"
    cp "$RUN/harness-feed.efi" "$bdir/harness.efi"
    cp "$RUN/esp.img" "$bdir/esp.img"
    cp "$RUN/pcrsig-tooling.img" "$bdir/pcrsig.img"
    _ensure_tpm "$RUN/tpm"
    _fresh_pcrs
    _rearm_trap
    CURRENT_QEMU_DIR="$bdir"
    run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$bdir/esp.img" \
        "$m1" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$bdir/pcrsig.img" "$m2"
    _qemu_alive "$bdir"
    _rearm_trap
    wait_console "$bdir" "awaiting console line" "$QEMU_TIMEOUT"
    feed_line "$bdir/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    wait_console "$bdir" "DEBUG SHELL on console" 300
}

# ============================================================================
# Host-side bootstrap: keys, both members, ONE feeding UKI (debug + fallback)
# ============================================================================
keys_create "$RUN/keys" || { echo "s20: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
run_stage disk_make_luks-1 120 disk_make_luks "$RUN/disk-root1.img" "$MEMBER_MIB"
run_stage disk_make_luks-2 120 disk_make_luks "$RUN/disk-root2.img" "$MEMBER_MIB"
UUID1=$(timeout 60 cryptsetup luksUUID "$RUN/disk-root1.img") || exit 1
UUID2=$(timeout 60 cryptsetup luksUUID "$RUN/disk-root2.img") || exit 1
[[ -n "$UUID1" && -n "$UUID2" && "$UUID1" != "$UUID2" ]] || { echo "s20: bad member uuids"; exit 1; }

DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-feed 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-feed.efi" \
        "debian-fde-console-fallback debian-fde-unlock=oracle"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness-feed.efi") + 1048575) / 1048576 ))
run_stage esp_make 300 esp_make "$RUN/esp.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-feed.efi"

# dead suppressor token on member 1 (s00b mechanism): keeps the harness
# stand-in enroll branch out of the loop for THIS and every working-copy boot
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
_import_dead_token() {   # _import_dead_token <img> <token-id>
    run_stage "dead-token-import:$1" 60 cryptsetup token import "$1" \
        --token-id "$2" --json-file "$_tok_json"
}

# ============================================================================
# BOOTSTRAP boot: lay the raid1 pool in-guest (fed session, SB-on vars)
# ============================================================================
echo "# bootstrap: two LUKS members -> mkfs.btrfs -d raid1 -m raid1 (fed session)"
_import_dead_token "$RUN/disk-root1.img" 9
_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
mkdir -p "$RUN/bootstrap"
cp "$RUN/harness-feed.efi" "$RUN/bootstrap/harness.efi"
cp "$RUN/esp.img" "$RUN/bootstrap/esp.img"
CURRENT_QEMU_DIR="$RUN/bootstrap"
run_stage qemu_run-bootstrap 60 qemu_run "$RUN/bootstrap" "$RUN/bootstrap/esp.img" \
    "$RUN/disk-root1.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "" "$RUN/disk-root2.img"
_qemu_alive "$RUN/bootstrap"
_rearm_trap
wait_console "$RUN/bootstrap" "awaiting console line" "$QEMU_TIMEOUT"
feed_line "$RUN/bootstrap/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
wait_console "$RUN/bootstrap" "DEBUG SHELL on console" 300
# unlock member 2, lay the pool, create @ + canary, print every uuid
# (bootstrap passes NO pcrsig drive -> the extra member lands on /dev/vdc;
# later phases add the pcrsig drive, shifting member 2 to /dev/vdd)
feed_line "$RUN/bootstrap/serial.sock" \
    "printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" | cryptsetup open --type luks --key-file - /dev/vdc root2 && echo B2-\$((40+2))-OPEN"
# TCG serial corruption guard: re-derive the sentinel from live guest state
# (mapper existence) — never a blind replay — then wait hard
wait_console_soft "$RUN/bootstrap" "B2-42-OPEN" 60 || \
    feed_line "$RUN/bootstrap/serial.sock" \
        'cryptsetup status root2 >/dev/null 2>&1 && echo B2-$((40+2))-OPEN'
wait_console "$RUN/bootstrap" "B2-42-OPEN" 300
feed_line "$RUN/bootstrap/serial.sock" \
    'mkfs.btrfs -f -d raid1 -m raid1 /dev/mapper/root /dev/mapper/root2 >/tmp/mkfs.log 2>&1; echo B3RC=$?'
wait_console "$RUN/bootstrap" "B3RC=0" 300
feed_line "$RUN/bootstrap/serial.sock" \
    'mkdir -p /btop && mount -t btrfs /dev/mapper/root /btop && btrfs subvolume create /btop/@ && echo B4-$((41+3))-OK'
wait_console "$RUN/bootstrap" "B4-44-OK" 300
feed_line "$RUN/bootstrap/serial.sock" \
    'printf "s20-canary raid1 member-loss\n" > /btop/@/canary.txt && echo "CANARY-SHA $(sha256sum /btop/@/canary.txt | cut -d" " -f1)" && echo "FSID $(btrfs filesystem show /dev/mapper/root 2>/dev/null | grep -m1 -o "uuid: [0-9a-f-]*")" && echo "UUID1 $(cryptsetup luksUUID /dev/vdb)" && echo "UUID2 $(cryptsetup luksUUID /dev/vdc)" && umount /btop && echo B5-$((44+1))-OK'
wait_console "$RUN/bootstrap" "B5-45-OK" 300
feed_line "$RUN/bootstrap/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-bootstrap "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/bootstrap" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

CANARY_SHA=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | awk '{print $2}')
FSID=$(grep -oE 'FSID uuid: [0-9a-f-]{36}' "$RUN/bootstrap/console.log" | head -1 | awk '{print $3}')
[[ -n "$CANARY_SHA" ]] || { echo "s20: canary sha missing from bootstrap console"; exit 1; }
[[ -n "$FSID" ]] || { echo "s20: btrfs fsid missing from bootstrap console"; exit 1; }
# Console-UUID evidence (re-pinned 2026-09-24): the registry's first pass lost
# this assertion to a serial burst artifact — the guest's "UUID2 6d604a4d-…"
# line reached the console garbled AND truncated ("66d604a4d-7"), so the
# labeled-extraction equality compared garbage. Assert containment of the
# EXACT host UUIDs among the console's well-formed UUID tokens instead: the
# invariant (the guest sees the same member UUIDs the host formatted) is what
# matters, not the label prefix, and a full 36-char token match tolerates a
# garbled label or a truncated neighbor token.
CON_UUIDS=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$RUN/bootstrap/console.log" | sort -u)
assert_contains "bootstrap: member 1 console UUID == host LUKS UUID" "$CON_UUIDS" "$UUID1"
assert_contains "bootstrap: member 2 console UUID == host LUKS UUID" "$CON_UUIDS" "$UUID2"
assert_eq "bootstrap: member 1 tokens == 1 (the dead suppressor only)" "1" \
    "$(disk_token_json "$RUN/disk-root1.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')"
assert_eq "bootstrap: member 2 still ZERO tokens (pool built pre-finalization)" "0" \
    "$(disk_token_json "$RUN/disk-root2.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')"

# ============================================================================
# Host-side: production crypttab + FINAL baseline (real CLI, s00 pattern)
# ============================================================================
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/alpine-fde" "$TOOLING/etc/alpine-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib" \
    "$TOOLING/opt/sslbin/lib"
for d in bin lib hooks; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/alpine-fde/$d"
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
    echo "s20: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s20: flock closure introduces a library the payload does not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
# openssl closure (s00b pattern): finalize STEP 2 shells out to openssl for
# the ADR-18 release.pem encryption/inspection (enc / asn1parse)
run_stage tooling-openssl 60 cp -L "$(command -v openssl)" "$TOOLING/opt/sslbin/openssl"
_ossl_interp=$(ldd "$(command -v openssl)" | awk '/ld-linux/{print $1}')
if [[ "$_ossl_interp" != "$_jq_interp" ]]; then
    echo "s20: openssl interp $_ossl_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-openssl-ld 60 cp -L "$_ossl_interp" "$TOOLING/opt/sslbin/ld-linux"
for _ol in $(ldd "$(command -v openssl)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-openssl-closure"
    cp -L "$_ol" "$TOOLING/opt/sslbin/lib/"
done
printf '#!/bin/sh\nexec /opt/sslbin/ld-linux --library-path /opt/sslbin/lib /opt/sslbin/openssl "$@"\n' \
    >"$TOOLING/usr/bin/openssl"
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/openssl" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock"

# production crypttab (§4.1/§8.2 multi-disk shape: password-cache=yes)
printf 'root1 UUID=%s none luks,tpm2-device=auto,password-cache=yes,discard\nroot2 UUID=%s none luks,tpm2-device=auto,password-cache=yes,discard\n' \
    "$UUID1" "$UUID2" >"$TOOLING/etc/crypttab"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/alpine-fde/keys/release.pub"
# release.pem = the PLAINTEXT release key (the fixture db.key): finalize STEP 2
# encrypts it in place (ADR-18) under DEBIAN_FDE_KEY_PASSPHRASE
run_stage tooling-release-pem 60 cp "$RUN/keys/db.key" "$TOOLING/etc/alpine-fde/keys/release.pem"

# the FINAL baseline via the REAL CLI (audit --init), PCRs stamped from the
# bootstrap boot console (s00b pattern: fixture efivars + swtpm TCTI)
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS" "$RUN/rootfs-etc/etc/alpine-fde"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
_mkcertvar PK pk-cert-v1
_mkcertvar KEK kek-cert-v1
_mkcertvar db db-cert-v1
_mkcertvar dbx dbx-cert-v1
cat >"$RUN/rootfs-etc/etc/alpine-fde/baseline.json" <<'JSON'
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
    "release_pub_path": "/etc/alpine-fde/keys/release.pub",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "",
    "esp_partuuid": ""
  }
}
JSON
_ensure_tpm "$RUN/tpm"
if AUDIT_OUT=$(DEBIAN_FDE_ROOT="$RUN/rootfs-etc" \
    DEBIAN_FDE_TCTI="swtpm:path=$RUN/tpm/sock" \
    DEBIAN_FDE_EFIVARS_DIR="$EFIVARS" \
    DEBIAN_FDE_EVENTLOG="$RUN/rootfs-etc/eventlog-absent" \
    DEBIAN_FDE_NO_INSTALL=1 \
    timeout 300 "$REPO/bin/alpine-fde" audit --init 2>&1); then
    _assert_result ok "S-20: audit --init finalized the baseline (real CLI, rc 0)" ""
else
    _assert_result not-ok "S-20: audit --init finalized the baseline (real CLI, rc 0)" \
        "output: $(tail -2 <<<"$AUDIT_OUT")"
fi
PCR7_B=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | cut -d= -f2)
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7_B\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | cut -d= -f2)\",|" \
    "$RUN/rootfs-etc/etc/alpine-fde/baseline.json"
if grep -q '"expected_pcr7": "pending"' "$RUN/rootfs-etc/etc/alpine-fde/baseline.json" \
    || [[ -z "$PCR7_B" ]]; then
    echo "s20: baseline still pending after audit --init — refusing to continue"; exit 1
fi
run_stage baseline-copy 60 cp "$RUN/rootfs-etc/etc/alpine-fde/baseline.json" "$TOOLING/etc/alpine-fde/baseline.json"
# §8.4 state doc at `installed` — finalize's state gate requires it (a missing
# doc is a loud no-op); the `finalized` write stays scenario-ephemeral in-guest
cat >"$TOOLING/etc/alpine-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" opt etc usr

# the {7,11} policy signature for the FINALIZED token (§6.1.1 pcrsign): the
# ukify .pcrsig carries ONLY pcrs:[11] entries, and seal_enroll's finalized
# verify REQUIRES a pcrs=[7,11] entry — so the payload's .pcrsig is produced
# by `pcrsign` over the feed-UKI components (d11 = the enter-initrd prediction
# the guest reaches post-phase-word) + the FINAL baseline's expected_pcr7.
mkdir -p "$RUN/relkey"
run_stage relkey-pem 60 cp "$RUN/keys/db.key" "$RUN/relkey/release.pem"
run_stage relkey-crt 60 cp "$RUN/keys/db.crt" "$RUN/relkey/release.crt"
run_stage relkey-pub 60 cp "$RUN/keys/release.pub" "$RUN/relkey/release.pub"
DEBIAN_FDE_KEYDIR="$RUN/relkey" run_stage pcrsign-711 600 \
    "$REPO/bin/alpine-fde" pcrsign \
    --linux "$RUN/guest-tree/vmlinuz" --initrd "$RUN/initrd.cpio" \
    --cmdline "$RUN/cmdline.txt" --os-release "$RUN/os-release.txt" \
    --baseline "$RUN/rootfs-etc/etc/alpine-fde/baseline.json" \
    --out "$RUN/pcrsign-711.json"
assert_eq "S-20: pcrsign produced the {7,11} policy signature (§6.1.1)" '[[7,11]]' \
    "$(jq -c '[.sha256[].pcrs]' "$RUN/pcrsign-711.json")"

# pcrsig drive + tooling tail (s00b mechanism)
run_stage pcrsig_disk-711 60 uki_pcrsig_disk "$RUN/pcrsig-711.img" "$RUN/pcrsign-711.json"
_budget_check pcrsig-tooling-drive
cat "$RUN/pcrsig-711.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-tooling.img"
assert_file_exists "S-20: payload drive (pcrsig + crypttab/baseline/keys tail)" "$RUN/pcrsig-tooling.img"

# _feed_env <boot-dir> — the CLI seams for the fed sessions (amended §9.1:
# the recovery passphrase + keydir + key passphrase + {7,11} .pcrsig; the old
# DEBIAN_FDE_CRYPTENROLL / _LUKS_KEYFILE seams are retired by Mechanism B).
# SPLIT into three short feeds with per-line markers + ONE retry each (repro
# 2026-09-24): a single ~470-char line loses whole sentences to the 16550
# byte-duplication/drop artifact under kernel-printk load — the guest echoed
# "P5-443-OK" for `echo P5-$((43))-OK` and one run lost the marker entirely.
# Every feed is idempotent (mkdir/ln/export/echo), so a retry is safe.
_feed_line_retry() { # <boot-dir> <line> <marker-fixed> <marker-ERE> <label>
    local bdir="$1" line="$2" pat="$3" ere="$4" label="$5" try
    for try in 1 2; do
        feed_line "$bdir/serial.sock" "$line"
        if wait_console_soft "$bdir" "$pat" 60; then return 0; fi
        grep -qE "$ere" "$bdir/console.log" 2>/dev/null && {
            echo "s20: $label landed byte-garbled (16550 duplication) — accepted on the tolerant match"
            return 0
        }
        echo "s20: $label not seen (try $try/2) — re-feeding (idempotent line)"
    done
    _hang_fail CONSOLE-WAIT "$label" "not seen after 2 feeds (tolerant match included)"
}
_feed_env() {
    local bdir="$1"
    _feed_line_retry "$bdir" \
        "mkdir -p /run/bu /tmp && ln -sf /dev/vdb /run/bu/$UUID1 && ln -sf /dev/vdd /run/bu/$UUID2 && echo P5-40-OK" \
        "P5-40-OK" 'P5-4{1,2}0-OK' "P5-40-OK (by-uuid seams)"
    _feed_line_retry "$bdir" \
        "export DEBIAN_FDE_NO_INSTALL=1 DEBIAN_FDE_TCTI=device:/dev/tpmrm0 DEBIAN_FDE_BY_UUID_DIR=/run/bu DEBIAN_FDE_RECOVERY_PASSPHRASE=$S20_RECOVERY DEBIAN_FDE_KEYDIR=/etc/alpine-fde/keys DEBIAN_FDE_KEY_PASSPHRASE=$S20_KEYPASS DEBIAN_FDE_TMPDIR=/tmp DEBIAN_FDE_PCRSIG=/pcrsig.json DEBIAN_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty && echo P5-41-OK" \
        "P5-41-OK" 'P5-4{1,2}1-OK' "P5-41-OK (CLI env)"
    _feed_line_retry "$bdir" 'echo P5-43-OK' "P5-43-OK" 'P5-4{1,2}3-OK' "P5-43-OK (env ready)"
}

# ============================================================================
# PHASE 1 — member lost: the harness initrd's login-stage mount FAILS CLOSED
# ============================================================================
P1="$RUN/phase1"
cp "$RUN/disk-root1.img" "$RUN/p1-root1.img"   # carries the dead suppressor
run_stage phase1-move-member 60 mv "$RUN/disk-root2.img" "$RUN/root2.lost.img"
echo "# phase 1: member 2 MOVED AWAY — plain mount of the degraded pool must fail"
_boot_fed "$P1" "$RUN/p1-root1.img"
# byte-identical to the harness /init login_stage mount line (uki-build.sh)
feed_line "$P1/serial.sock" \
    'mkdir -p /newroot && mount -t btrfs -o subvol=@ /dev/mapper/root /newroot 2>/tmp/p1.log; echo P1PLAIN=$?; head -3 /tmp/p1.log; echo P1-$((44+6))-DONE'
wait_console "$P1" "P1-50-DONE" 300
feed_line "$P1/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-phase1 "$((QEMU_TIMEOUT + 60))" qemu_wait "$P1" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_P1=$(cat "$P1/console.log" 2>/dev/null || true)
P1_RC=$(grep -oE 'P1PLAIN=[0-9]+' "$P1/console.log" | head -1 | cut -d= -f2)
assert_contains "[phase 1] init ran" "$LOG_P1" "debian-fde-harness: init started"
assert_contains "[phase 1] stand-in OUT of the loop (dead suppressor token)" "$LOG_P1" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[phase 1] fed unlock of the SURVIVING member root1 succeeded" "$LOG_P1" \
    "debian-fde: UNSEALED"
# THE FAIL-CLOSED HINGE: the login-stage plain mount of a missing-member
# raid1 pool fails (btrfs requires an explicit `degraded`)
assert_contains "[phase 1] login-stage mount command ran (byte-identical line)" "$LOG_P1" \
    "P1PLAIN="
assert_ne "[phase 1] plain mount of the degraded pool FAILED (rc != 0)" "0" "$P1_RC"
assert_not_contains "[phase 1] no /newroot mount materialized" "$LOG_P1" "P1PLAIN=0"
# busybox 1.37.0 (pinned) mount error format — harness-owned wording, stable
assert_contains "[phase 1] the kernel/busybox refusal is on the console (evidence)" "$LOG_P1" \
    "mounting /dev/mapper/root on /newroot failed"
assert_not_contains "[phase 1] never unlocked by a token (no standing token)" "$LOG_P1" \
    "$(sentinel_of unlocked)"
assert_not_contains "[phase 1] no interactive prompt ever appeared" "$LOG_P1" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[phase 1] no emergency shell (H-G1)" "$LOG_P1" \
    "$(sentinel_of emergency_forbidden)"
if [[ -f "$P1/qemu.pid" ]] && ! kill -0 "$(cat "$P1/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[phase 1] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[phase 1] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# ============================================================================
# PHASE 2 — rescue: the ONLY way in is `mount -o degraded` (runbook leg 1)
# ============================================================================
P2="$RUN/phase2"
cp "$RUN/disk-root1.img" "$RUN/p2-root1.img"   # carries the dead suppressor
# member 2 is STILL away (root2.lost.img from phase 1)
echo "# phase 2: rescue session — degraded mount of the surviving member"
_boot_fed "$P2" "$RUN/p2-root1.img"
feed_line "$P2/serial.sock" \
    'mkdir -p /mnt && mount -t btrfs -o degraded,subvol=@ /dev/mapper/root /mnt 2>/tmp/p2m.log; echo P2MRC=$?; grep -qw degraded /proc/mounts && echo DEG-$((44+5))-OK || echo DEG-ABSENT-$((44+5))'
wait_console "$P2" "P2MRC=0" 300
wait_console "$P2" "DEG-49-OK" 120
feed_line "$P2/serial.sock" \
    'cat /mnt/canary.txt >/dev/null && echo "CANARY-SHA $(sha256sum /mnt/canary.txt | cut -d" " -f1)" && btrfs filesystem show /dev/mapper/root; echo P2S-$((44+7))-DONE'
wait_console "$P2" "P2S-51-DONE" 300
feed_line "$P2/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-phase2 "$((QEMU_TIMEOUT + 60))" qemu_wait "$P2" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_P2=$(cat "$P2/console.log" 2>/dev/null || true)
P2_CANARY=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$P2/console.log" | head -1 | awk '{print $2}')
assert_contains "[phase 2] stand-in OUT of the loop" "$LOG_P2" \
    "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
assert_contains "[phase 2] fed unlock of the surviving member" "$LOG_P2" "debian-fde: UNSEALED"
assert_contains "[phase 2] degraded mount SUCCEEDED (the explicit -o degraded runbook leg)" \
    "$LOG_P2" "P2MRC=0"
assert_contains "[phase 2] the mount option degraded is IN EFFECT (/proc/mounts)" "$LOG_P2" \
    "DEG-49-OK"
assert_eq "[phase 2] canary intact on the degraded pool (raid1 data readable)" \
    "$CANARY_SHA" "$P2_CANARY"
assert_contains "[phase 2] btrfs filesystem show reports the pool fsid" "$LOG_P2" "$FSID"
assert_contains "[phase 2] btrfs filesystem show reports total devices 2" "$LOG_P2" \
    "Total devices 2"
assert_not_contains "[phase 2] no interactive prompt ever appeared" "$LOG_P2" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[phase 2] no emergency shell" "$LOG_P2" "$(sentinel_of emergency_forbidden)"
if [[ -f "$P2/qemu.pid" ]] && ! kill -0 "$(cat "$P2/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[phase 2] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[phase 2] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# ============================================================================
# PHASE 3a — member restored: production finalize enrolls BOTH members
# (CANONICAL member images: the enrollment must persist)
# ============================================================================
P3A="$RUN/phase3a"
run_stage phase3a-restore-member 60 mv "$RUN/root2.lost.img" "$RUN/disk-root2.img"
echo "# phase 3a: member restored — production finalize (both members, Mechanism B)"
_boot_fed "$P3A" "$RUN/disk-root1.img" "$RUN/disk-root2.img"
# tooling off the payload tail + member 1 suppressor teardown (member 2
# carries no token at all — seal_upgrade_token takes the first-seal branch)
feed_line "$P3A/serial.sock" \
    'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
wait_console "$P3A" "P2A=0" 300
feed_line "$P3A/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
wait_console "$P3A" "P2B-42-OK" 300
feed_line "$P3A/serial.sock" 'cryptsetup token remove --token-id 9 /dev/vdb && echo T9-$((51+1))-GONE'
wait_console "$P3A" "T9-52-GONE" 120
# unlock member 2 (fed passphrase — its token comes only from finalize below)
feed_line "$P3A/serial.sock" \
    "printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" | cryptsetup open --type luks --key-file - /dev/vdd root2 && echo B2-\$((40+2))-OPEN"
# TCG serial corruption guard (same as the bootstrap unlock sentinel)
wait_console_soft "$P3A" "B2-42-OPEN" 60 || \
    feed_line "$P3A/serial.sock" \
        'cryptsetup status root2 >/dev/null 2>&1 && echo B2-$((40+2))-OPEN'
wait_console "$P3A" "B2-42-OPEN" 300
# Stage-1 credential-ceremony stand-in (§9.1 step 4, amended): rekey BOTH
# members' keyslot 0 to the §13-floored recovery passphrase — the fixture's
# well-known slot-0 passphrase is floor-BLOCKLISTED, and the amended contract
# verifies the operator recovery passphrase against keyslot 0 (no key handoff
# to finalize exists; ADR-20 amended)
feed_line "$P3A/serial.sock" \
    "printf %s $S20_RECOVERY > /rp && cryptsetup luksChangeKey --key-slot 0 /dev/vdb /rp --key-file /kf0 && cryptsetup luksChangeKey --key-slot 0 /dev/vdd /rp --key-file /kf0 && echo RK-\$((44+1))-OK"
wait_console "$P3A" "RK-45-OK" 600
_feed_env "$P3A"
feed_line "$P3A/serial.sock" 'timeout 300 /opt/alpine-fde/bin/alpine-fde finalize; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$P3A/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$P3A" "console-wait:P6-RC"
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "finalize never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC_3A=$(grep -oE 'P6-RC=[0-9]+' "$P3A/console.log" | head -1 | cut -d= -f2)
feed_line "$P3A/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-phase3a "$((QEMU_TIMEOUT + 60))" qemu_wait "$P3A" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_3A=$(cat "$P3A/console.log" 2>/dev/null || true)
assert_contains "[phase 3a] tooling extracted" "$LOG_3A" "P2B-42-OK"
assert_contains "[phase 3a] Stage-1 stand-in: recovery rekeyed into keyslot 0 on BOTH members" "$LOG_3A" \
    "RK-45-OK"
assert_contains "[phase 3a] finalize: recovery passphrase VERIFIED against keyslot 0 (§9.1 amended)" "$LOG_3A" \
    "recovery passphrase verified against keyslot 0 (attempt 1) — authorizing the completion"
assert_contains "[phase 3a] baseline already final (audit skipped, §9.1 idempotency)" "$LOG_3A" \
    "baseline already final — skipping audit --init"
assert_contains "[phase 3a] finalize: release.pem encrypted in place (ADR-18)" "$LOG_3A" \
    "release.pem encrypted (AES-256 PBKDF2, ADR-18)"
assert_contains "[phase 3a] member 1 upgraded to Mechanism B {PCR 7, PCR 11}" "$LOG_3A" \
    "debian-fde: member $UUID1: token upgraded to Mechanism B {PCR 7, PCR 11}"
assert_contains "[phase 3a] member 2 upgraded to Mechanism B {PCR 7, PCR 11}" "$LOG_3A" \
    "debian-fde: member $UUID2: token upgraded to Mechanism B {PCR 7, PCR 11}"
assert_eq "[phase 3a] exactly TWO finalized seals (one per member)" "2" \
    "$(grep -cF "$(sentinel_of cli_seal_slot)" "$P3A/console.log")"
assert_contains "[phase 3a] no ephemeral keyslot remained (crash-skip of the purge)" "$LOG_3A" \
    "no temporary ephemeral keyslot remains — skipping the purge"
assert_contains "[phase 3a] install finalized marker" "$LOG_3A" "debian-fde: install finalized"
assert_eq "[phase 3a] production finalize rc 0" "0" "$CLI_RC_3A"
assert_not_contains "[phase 3a] NO cryptenroll anywhere (Mechanism B never invokes it)" "$LOG_3A" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_not_contains "[phase 3a] no emergency shell" "$LOG_3A" "$(sentinel_of emergency_forbidden)"
NTOK1=$(disk_token_json "$RUN/disk-root1.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
NTOK2=$(disk_token_json "$RUN/disk-root2.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[phase 3a] host: member 1 carries exactly ONE standing token" "1" "$NTOK1"
assert_eq "[phase 3a] host: member 2 carries exactly ONE standing token" "1" "$NTOK2"
TOKSLOT1=$(disk_token_json "$RUN/disk-root1.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
TOKSLOT2=$(disk_token_json "$RUN/disk-root2.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
TOKPCRS1=$(disk_token_json "$RUN/disk-root1.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')
TOKPCRS2=$(disk_token_json "$RUN/disk-root2.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')
assert_eq "[phase 3a] host: member 1 token on keyslot 1 (recovery at keyslot 0, amended §7.2)" "1" "$TOKSLOT1"
assert_eq "[phase 3a] host: member 2 token on keyslot 1 (recovery at keyslot 0, amended §7.2)" "1" "$TOKSLOT2"
assert_eq "[phase 3a] host: member 1 token binds {PCR 7, PCR 11}" "[7,11]" "$TOKPCRS1"
assert_eq "[phase 3a] host: member 2 token binds {PCR 7, PCR 11}" "[7,11]" "$TOKPCRS2"
SLOTS1=$(timeout 60 cryptsetup luksDump --dump-json-metadata "$RUN/disk-root1.img" | jq -r '.keyslots | keys | sort | join(",")')
SLOTS2=$(timeout 60 cryptsetup luksDump --dump-json-metadata "$RUN/disk-root2.img" | jq -r '.keyslots | keys | sort | join(",")')
assert_eq "[phase 3a] host: member 1 keyslots = recovery 0 + token 1 (I1 two-keyslot)" "0,1" "$SLOTS1"
assert_eq "[phase 3a] host: member 2 keyslots = recovery 0 + token 1 (I1 two-keyslot)" "0,1" "$SLOTS2"

# ============================================================================
# PHASE 3b — full pool: zero-input token unlock + non-degraded assembly
# ============================================================================
# Upstream-257 token projection (ADR-19; tests/lib/interop-oracle.sh): the raw
# §7.2 token lacks 'tpm2-policy-hash', and 257's token validation refuses it
# BEFORE any policy work ("TPM2 token data lacks 'tpm2-policy-hash' field" —
# live 2026-09-24: the phase-3b zero-input unlock fell to the console
# fallback and the leg hung). Project the standing token + the {7,11}
# .pcrsig into the upstream-consumable form and install the projection on
# member 1 alongside the raw token; the production attach then validates,
# authorizes over the live {7,11} PCR digest and unseals.
if ! source "$REPO/lib/policy.sh" 2>/dev/null; then source "$TESTS/../lib/policy.sh"; fi
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"   # BEFORE seal.sh (sibling resolution)
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"
# shellcheck source=../lib/interop-oracle.sh
source "$TESTS/lib/interop-oracle.sh"
mkdir -p "$RUN/proj"
timeout 60 cryptsetup luksDump --dump-json-metadata "$RUN/disk-root1.img" \
    | jq -c '[.tokens[] | select(.type == "systemd-tpm2")][0]' >"$RUN/standing-token.json"
[[ -s "$RUN/standing-token.json" ]] || { echo "s20: no standing token on member 1"; exit 1; }
_ensure_tpm "$RUN/tpm"
ORACLE_TOKEN="$RUN/standing-token.json" \
ORACLE_PCRSIG="$RUN/pcrsign-711.json" \
DEBIAN_FDE_TCTI="$(_swtpm_tcti_for "$RUN/tpm")" \
    interop_oracle_project "$RUN/proj" "$RUN/relkey" || {
    echo "s20: upstream-257 token projection failed"; exit 1; }
assert_eq "S-20 phase 3b: projected token carries tpm2-policy-hash (upstream schema)" "64" \
    "$(jq -r '.["tpm2-policy-hash"]' "$ORACLE_TOKEN_UP" | tr -d '\n' | wc -c)"
assert_eq "S-20 phase 3b: STANDING token itself carries tpm2-policy-hash (product fix)" "64" \
    "$(jq -r '.["tpm2-policy-hash"]' "$RUN/standing-token.json" | tr -d '\n' | wc -c)"

P3B="$RUN/phase3b"
cp "$RUN/disk-root1.img" "$RUN/p3b-root1.img"   # carries the STANDING token
PROJ_TID=$(token_next_id "$RUN/p3b-root1.img")
token_import "$RUN/p3b-root1.img" "$ORACLE_TOKEN_UP" "$PROJ_TID" || {
    echo "s20: projected token import failed"; exit 1; }
# member 2 carries the SAME standing §7.2 token shape — and since it is only
# opened via the production primitive, the same CI-only projection rides on
# it too, derived from MEMBER 2's OWN standing token (the blob seals that
# member's volume passphrase — member 1's projected token unseals member 1's
# secret only). RESIDUAL ADR-19 DELTA (pinned, not silent —
# tests/lib/interop-oracle.sh SCHEMA DELTA): the raw token now VALIDATES
# (tpm2-policy-hash present, product-side) but its policy work is still
# refused by 257 because the raw token pins tpm2-pcrs [7,11] while a
# G4-conformant (kernel-update-immune, policy-authorized) seal is only
# consumable with tpm2-pcrs [] + tpm2_pubkey/tpm2_pubkey_pcrs + the pcrsign
# pkfp form — product changes that collide with the tpm2-pcrs assertions
# pinned in s16/s18/s21/s22 and are out of this scenario's bucket.
mkdir -p "$RUN/proj2"
timeout 60 cryptsetup luksDump --dump-json-metadata "$RUN/disk-root2.img" \
    | jq -c '[.tokens[] | select(.type == "systemd-tpm2")][0]' >"$RUN/standing-token2.json"
[[ -s "$RUN/standing-token2.json" ]] || { echo "s20: no standing token on member 2"; exit 1; }
assert_eq "S-20 phase 3b: member 2 STANDING token carries tpm2-policy-hash (product fix)" "64" \
    "$(jq -r '.["tpm2-policy-hash"]' "$RUN/standing-token2.json" | tr -d '\n' | wc -c)"
ORACLE_TOKEN="$RUN/standing-token2.json" \
ORACLE_PCRSIG="$RUN/pcrsign-711.json" \
DEBIAN_FDE_TCTI="$(_swtpm_tcti_for "$RUN/tpm")" \
    interop_oracle_project "$RUN/proj2" "$RUN/relkey" || {
    echo "s20: upstream-257 token projection (member 2) failed"; exit 1; }
PROJ_TID2=$(token_next_id "$RUN/disk-root2.img")
token_import "$RUN/disk-root2.img" "$ORACLE_TOKEN_UP" "$PROJ_TID2" || {
    echo "s20: projected token import (member 2) failed"; exit 1; }
echo "# phase 3b: both members present — ZERO-INPUT unlock, full non-degraded pool"
mkdir -p "$P3B"
cp "$RUN/harness-feed.efi" "$P3B/harness.efi"
cp "$RUN/esp.img" "$P3B/esp.img"
run_stage pcrsig_disk-711-up 60 uki_pcrsig_disk "$RUN/pcrsig-711-up.img" "$ORACLE_PCRSIG_UP"
cat "$RUN/pcrsig-711-up.img" "$RUN/tooling.tar.gz" >"$RUN/pcrsig-tooling-up.img"
cp "$RUN/pcrsig-tooling-up.img" "$P3B/pcrsig.img"
_ensure_tpm "$RUN/tpm"
_fresh_pcrs
_rearm_trap
CURRENT_QEMU_DIR="$P3B"
run_stage qemu_run-phase3b 60 qemu_run "$P3B" "$P3B/esp.img" "$RUN/p3b-root1.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$P3B/pcrsig.img" "$RUN/disk-root2.img"
_qemu_alive "$P3B"
_rearm_trap
# ZERO console input: the standing token must unseal root1 unaided (the
# fallback never arms on success — asserted below by marker absence)
i=0
until grep -q "debian-fde: UNSEALED" "$P3B/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$P3B" "console-wait:UNSEALED"
    _budget_check "console-wait:UNSEALED"
    (( i < QEMU_TIMEOUT )) || _hang_fail CONSOLE-WAIT "UNSEALED" "zero-input token unlock never completed"
    sleep 1
    i=$((i + 1))
done
wait_console "$P3B" "DEBUG SHELL on console" 300
# the production token-only primitive assembles member 2 (zero PASSPHRASE
# input). systemd-cryptsetup is THE unlock primitive the boot path runs (the
# s19 phase-3 shape): it ITERATES the volume's systemd-tpm2 tokens — the raw
# standing token is refused at the pinned ADR-19 residual delta, the
# projected token unseals. (`cryptsetup --token-only` aborts on the first
# plugin refusal instead of iterating.)
feed_line "$P3B/serial.sock" \
    'SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-cryptsetup attach root2 /dev/vdd "" "luks,tpm2-device=auto,tpm2-signature=/pcrsig.json,tries=1" 2>/tmp/p3b.out; echo R2RC=$?; head -3 /tmp/p3b.out; echo R2-$((44+8))-DONE'
wait_console "$P3B" "R2-52-DONE" 300
# TCG serial corruption guard: R2RC=<n> IS the payload and one lossy TX burst
# must not decide it (run 1789847363 captured "R2RC==0" — doubled '='). The
# guest re-derives the rc from the live mapper; the grep reads whichever
# well-formed emission landed first (both state-grounded, never a replay).
feed_line "$P3B/serial.sock" 'cryptsetup status root2 >/dev/null 2>&1; echo R2RC=$?'
wait_console_soft "$P3B" "R2RC=0" 120 || true
# TCG serial corruption guard (runs 1790248563/1790249187: the mount leg's
# non-degraded sentinel landed shredded as "NODDEG-45-OK" — doubled-byte class,
# twice at the same offset right after a kernel printk burst). The re-derivation
# emits a COMPACT payload (tiny interleave window) from the LIVE /proc/mounts;
# the assertion reads whichever well-formed emission landed (state-grounded,
# never a replay).
feed_line "$P3B/serial.sock" \
    'grep -qs " /mnt btrfs" /proc/mounts && { grep -qw degraded /proc/mounts || echo NG-$((45))-OK; }; echo RDG-$((45+2))-DONE'
wait_console_soft "$P3B" "RDG-47-DONE" 120 || true
feed_line "$P3B/serial.sock" \
    'mkdir -p /mnt && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && echo MNT-$((44+2))-OK && (grep -qw degraded /proc/mounts && echo DEG-STILL-$((44+9)) || echo NG-$((45))-OK); echo "CANARY-SHA $(sha256sum /mnt/canary.txt | cut -d" " -f1)"; echo P3B-$((45+1))-DONE'
wait_console "$P3B" "P3B-46-DONE" 300
feed_line "$P3B/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-phase3b "$((QEMU_TIMEOUT + 60))" qemu_wait "$P3B" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_3B=$(cat "$P3B/console.log" 2>/dev/null || true)
R2_RC=$(grep -oE 'R2RC=[0-9]+' "$P3B/console.log" | head -1 | cut -d= -f2)
P3B_CANARY=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$P3B/console.log" | tail -1 | awk '{print $2}')
assert_contains "[phase 3b] standing token discovered by the real unlock path" "$LOG_3B" \
    "$(sentinel_of token_discovered)"
assert_contains "[phase 3b] the UKI's own .pcrsig consumed (signed policy)" "$LOG_3B" \
    "$(sentinel_of pcr_sig_added)"
assert_contains "[phase 3b] volume activated with a LUKS token (sentinel table)" "$LOG_3B" \
    "$(sentinel_of unlocked)"
assert_contains "[phase 3b] ZERO-INPUT unlock of member 1 (UNSEALED)" "$LOG_3B" \
    "debian-fde: UNSEALED"
assert_not_contains "[phase 3b] console fallback NEVER armed (zero-input invariant)" "$LOG_3B" \
    "awaiting console line"
assert_not_contains "[phase 3b] no interactive prompt ever appeared" "$LOG_3B" \
    "$(sentinel_of prompt_re)"
assert_eq "[phase 3b] member 2 token-only open rc 0 (production primitive)" "0" "$R2_RC"
assert_contains "[phase 3b] full pool assembled + @ mounted" "$LOG_3B" "MNT-46-OK"
# compact payload (see the corruption guard above): either the mount leg's or
# the re-derivation leg's emission proves the LIVE pool mounted non-degraded
assert_contains "[phase 3b] pool is NOT degraded (both members live)" "$LOG_3B" "NG-45-OK"
assert_not_contains "[phase 3b] no degraded mount option anywhere" "$LOG_3B" "DEG-STILL-53"
assert_eq "[phase 3b] canary intact end-to-end (raid1 rebuild acceptance check)" \
    "$CANARY_SHA" "$P3B_CANARY"
assert_not_contains "[phase 3b] no emergency shell" "$LOG_3B" "$(sentinel_of emergency_forbidden)"
if [[ -f "$P3B/qemu.pid" ]] && ! kill -0 "$(cat "$P3B/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[phase 3b] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[phase 3b] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s20-raid1-member-loss: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s20-raid1-member-loss: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
