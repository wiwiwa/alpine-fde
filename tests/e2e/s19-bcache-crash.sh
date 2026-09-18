#!/usr/bin/env bash
# tests/e2e/s19-bcache-crash.sh — §10 row "Cache SSD physical failure (Hybrid
# bcache)" + §12 S-19 (hybrid bcache crash consistency) on the §4.1 topology.
#
# Topology (§4.1 accelerated hybrid, harness drive map):
#   vda = CACHE drive image: p1 = ESP (FAT, signed UKI), p2 = bcache cache set
#   vdb = BACKING drive image: p1 = bcache backing device
#   vdc = pcrsig(+tooling) payload drive (harness contract slot)
#   in-guest: `make-bcache -C /dev/vda2` + `make-bcache -B /dev/vdb1` (pinned
#   bcache-tools, host-closure payload), manual register + explicit sysfs
#   attach, WRITETHROUGH (§4.1 cache-mode invariant, asserted from sysfs),
#   LUKS2 ON /dev/bcache0 (ciphertext-only caching), Btrfs @ + canary.
#
#   Bootstrap (fed session): lay the bcache stack + the LUKS/Btrfs payload,
#   print the container UUID + canary sha. Host-side: the production crypttab
#   (§4.1 hybrid shape) + the FINAL baseline via the REAL CLI (s00 pattern)
#   ride the tooling tail.
#   Phase 1 (cache SSD lost): the cache image MOVED AWAY; a rescue-ESP boot
#           (the runbook's live-media leg) registers the BACKING — the kernel
#           FAIL-CLOSED-refuses to fabricate a bcache0 for a CLEAN backing
#           without its set (register_bdev runs NONE/STALE only) — and the
#           rescue opens the LUKS container on the RAW member AT THE BCACHE
#           DATA OFFSET (16 sectors: BDEV_DATA_START_DEFAULT, sb version 1;
#           writethrough means the backing is 100% consistent) and mounts
#           the rootfs READ-ONLY: canary intact, ro mount option asserted,
#           LUKS uuid unchanged.
#   Phase 2 (replacement SSD, writethrough re-attach): a NEW cache image is
#           attached (`make-bcache -C` + explicit sysfs attach); sysfs asserts
#           state=clean + [writethrough]; /dev/bcache0 is consistent (canary +
#           container uuid unchanged). Then the PRODUCTION `debian-fde
#           finalize` enrolls the bcache0 container (Mechanism A'', real
#           systemd-cryptenroll) — the §4.1 single-token invariant for the
#           hybrid layout.
#   Phase 3 (ESP rebuilt + zero-input): the ESP is rebuilt HOST-side (fresh
#           uki_build + esp_make from the SAME release key — the runbook's
#           "rebuild ESP in chroot" leg, host-side stand-in, ratified scope)
#           onto a fresh cache image; the boot is the PRODUCTION shape again
#           (ESP on the cache drive): the bcache stack reassembles, the
#           standing token unseals /dev/bcache0 with ZERO input (real
#           systemd-cryptsetup attach + the fresh .pcrsig — the A'' pubkey
#           pivot makes the rebuilt UKI TPM-free, s14 semantics), the pool
#           mounts clean and the canary survives end-to-end.
#
# FIDELITY NOTES (documented, not silent):
#   * The harness /init unlocks /dev/vdb by contract; in this topology vdb is
#     the RAW backing member (the LUKS container sits on /dev/bcache0), so
#     every boot's built-in attach for vdb fails by construction and the
#     DEBUG SHELL seam drives the real sequence (the expected
#     PROMPT-FAILED-for-vdb lines are harness-map noise, not scenario
#     failures). The real unlock path (systemd-cryptsetup attach with
#     tpm2-device=auto + the .pcrsig) is exercised VERBATIM in phase 3
#     against /dev/bcache0.
#   * No dead suppressor tokens are needed: the stand-in enroll branch fires
#     on /dev/vdb (not a LUKS2 container) and fails LOUDLY without creating
#     anything — asserted via the cryptenroll-sentinel absence.
#   * bcache assembly is driven manually (echo > /sys/fs/bcache/register +
#     explicit attach): the initrd carries the bcache KERNEL module (G-HW3)
#     but not the bcache udev rules, so the rules-based auto-registration
#     production path is out of scope for the harness initrd.
#   * Host-side LUKS metadata asserts (the s21/s22 pattern) are NOT possible
#     here: the container lives at the bcache data offset BEHIND the backing
#     member's superblock. The enrollment evidence is therefore console-borne
#     (the finalize markers + a post-enroll metadata dump echoed in-guest).
#
#   * Phase 1's rescue leg reads the RAW backing member at the bcache data
#     offset (16 sectors — BDEV_DATA_START_DEFAULT; the pinned make-bcache
#     1.0.8 writes version-1 BDEV superblocks) via a linear dm map, instead
#     of a standalone bcache0: the kernel only runs a backing device
#     standalone in states NONE/STALE, and the bootstrap legitimately leaves
#     it CLEAN — a cache-less bcache0 is refused by design (asserted).
#     Writethrough makes the backing 100% consistent, so the raw-offset open
#     IS the runbook's live-media read. Phases 2/3 re-attach the pending
#     backing through /sys/block/vdb/vdb1/bcache/attach (the cached_dev
#     kobject hangs under the PARTITION device in /sys/block; bcache0 does
#     not exist until the attach lands), the canonical replacement-cache
#     path — a CLEAN backing binds to a new set fine.
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

ROOTFS_RETENTION=2
ESP_HEADROOM_MIB=8
# 512 MiB: the 6.12 kernel's cache_alloc() requires
# roundup_pow_of_two(nbuckets) >> 10 != 0 — nbuckets > 512 (super.c); at
# make-bcache's 512 KiB default bucket a 200 MiB cache yields 400 buckets
# and is refused ("ca->sb.nbuckets is too small"). 512 MiB => ~1020 buckets.
CACHE_MIB=512
BACKING_MIB=796

export QEMU_TIMEOUT="${DEBIAN_FDE_S19_TIMEOUT:-900}"

OVERALL_BUDGET="${DEBIAN_FDE_S19_BUDGET:-7200}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {
    printf '\ns19: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's19: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
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
    echo "# s19: stage $name (watchdog ${tmo}s)"
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
        printf 's19: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
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
# wait_console_soft — wait_console without the hang-fail: rc 1 when the
# pattern never lands, so a caller may re-derive the sentinel from live
# guest state. Needed because the TCG 16550 emulation DROPS/DUPLICATES
# console bytes under kernel-printk load (observed: REGC-48-OK shredded to
# "REGGwd_nsec: ..." in run 1789853012) — an exact-match wait can starve on
# a sentinel the guest genuinely emitted.
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

RUN="$TESTS/e2e/.runs/s19-bcache-crash-$(date +%s)"
mkdir -p "$RUN"

(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's19-bcache-crash-*' | sort -r |
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
    [[ -f "$dir/qemu.pid" ]] || { echo "s19: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s19: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

# ============================================================================
# Host-side bootstrap: keys, partitioned drive images, ONE debug-shell UKI
# (NO fallback word: the built-in attach targets vdb = raw backing and must
# fail fast; the fed session owns every real unlock)
# ============================================================================
keys_create "$RUN/keys" || { echo "s19: keys_create failed"; exit 1; }

DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB ))

# cache drive image: p1 = ESP (the §4.1 cache-SSD shape), p2 = cache member
run_stage esp-standalone 300 esp_make "$RUN/esp.fat" "$ESP_MIB" "$RUN/harness.efi"
run_stage mkfs-cache-img 60 truncate -s "$(( ESP_MIB + CACHE_MIB + 2 ))M" "$RUN/cache.img"
printf 'label: gpt\nname=ESP, size=%d, type=uefi\nname=CACHE, type=linux\n' \
    "$(( ESP_MIB * 2048 ))" >"$RUN/cache.sfdisk"
run_stage sfdisk-cache 120 bash -c 'sfdisk --quiet "$1" < "$2"' _ "$RUN/cache.img" "$RUN/cache.sfdisk"
run_stage esp-into-p1 120 bash -c \
    'dd if="$1" of="$2" bs=512 seek=2048 conv=notrunc status=none' _ \
    "$RUN/esp.fat" "$RUN/cache.img"
# backing drive image: p1 = backing member
run_stage mkfs-backing-img 60 truncate -s "${BACKING_MIB}M" "$RUN/backing.img"
printf 'label: gpt\nname=BACK, type=linux\n' >"$RUN/backing.sfdisk"
run_stage sfdisk-backing 120 bash -c 'sfdisk --quiet "$1" < "$2"' _ "$RUN/backing.img" "$RUN/backing.sfdisk"
PART_CHECK=$(sfdisk -d "$RUN/cache.img" 2>/dev/null | grep -c 'start=')
assert_eq "S-19 topology: cache image carries 2 partitions (ESP + cache set)" "2" "$PART_CHECK"
PART_CHECK=$(sfdisk -d "$RUN/backing.img" 2>/dev/null | grep -c 'start=')
assert_eq "S-19 topology: backing image carries 1 partition (backing member)" "1" "$PART_CHECK"

# --- tooling staging: CLI + closures + make-bcache (pinned bcache-tools) --------
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling-core.tar"
mkdir -p "$TOOLING/opt/debian-fde" "$TOOLING/etc/debian-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib" \
    "$TOOLING/opt/bcachebin/lib"
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
    echo "s19: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s19: flock closure introduces a library the payload does not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
printf '#!/bin/sh\nexec /usr/bin/systemd-cryptenroll --unlock-key-file=/kf0 "$@"\n' \
    >"$TOOLING/usr/bin/cryptenroll-kf"
{ printf '#!/bin/sh\n_dump=0\nfor _a in "$@"; do\n    [ "$_a" = "--dump-json-metadata" ] && _dump=1\ndone\nif [ "$_dump" = 1 ]; then\n    /usr/sbin/cryptsetup "$@" | /usr/bin/jq -c . | sed '"'"'s/":"/": "/g; s/":{/": {/g; s/":\\[/": [/g'"'"'\nelse\n    exec /usr/sbin/cryptsetup "$@"\nfi\n'; } \
    >"$TOOLING/usr/bin/cryptsetup-pretty"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" "$TOOLING/usr/bin/cryptenroll-kf" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock"
# make-bcache from the PINNED bcache-tools deb, closure-walked into the payload
_BCACHE_STAGE="$RUN/bcache-deb"
rm -rf "$_BCACHE_STAGE"
mkdir -p "$_BCACHE_STAGE"
run_stage bcache-deb-extract 300 rootfs_deb_extract "bcache-tools_1.0.8_amd64.deb" "$_BCACHE_STAGE"
MAKE_BCACHE=$(find "$_BCACHE_STAGE" -name make-bcache | head -1)
[[ -n "$MAKE_BCACHE" ]] || { echo "s19: make-bcache not found in the pinned bcache-tools deb"; exit 1; }
run_stage tooling-make-bcache 60 cp -L "$MAKE_BCACHE" "$TOOLING/opt/bcachebin/make-bcache"
_MB_LIBS=""
for _bl in $(ldd "$MAKE_BCACHE" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-make-bcache-closure"
    cp -L "$_bl" "$TOOLING/opt/bcachebin/lib/"
    _MB_LIBS="$_MB_LIBS $_bl"
done
# closure gate: make-bcache's NEEDED closure must be fully in the payload
_MISS=$(_uki_closure_check "$TOOLING" "$TOOLING/opt/bcachebin/make-bcache" 2>/dev/null | grep -v '/opt/' || true)
if [[ -n "$_MISS" ]]; then
    echo "s19: make-bcache closure incomplete outside the payload: $_MISS"
    exit 1
fi
_B_INTERP=$(ldd "$MAKE_BCACHE" | awk '/ld-linux/{print $1}')
if [[ "$_B_INTERP" != "$_jq_interp" ]]; then
    echo "s19: make-bcache interp $_B_INTERP != payload interp $_jq_interp"
    exit 1
fi
cp -L "$_B_INTERP" "$TOOLING/opt/bcachebin/ld-linux"
printf '#!/bin/sh\nexec /opt/bcachebin/ld-linux --library-path /opt/bcachebin/lib /opt/bcachebin/make-bcache "$@"\n' \
    >"$TOOLING/usr/bin/make-bcache"
chmod 755 "$TOOLING/usr/bin/make-bcache"
run_stage tooling-tar-core 300 tar -C "$TOOLING" -czf "$RUN/tooling-core.tar.gz" opt usr

_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
run_stage pcrsig_disk 60 uki_pcrsig_disk "$RUN/pcrsig.img" "$RUN/uki-pcrsig.json"
_budget_check pcrsig-core-drive
cat "$RUN/pcrsig.img" "$RUN/tooling-core.tar.gz" >"$RUN/pcrsig-core.img"

# _boot_s19 <boot-dir> <esp-img> <payload-img> [extra-cache-img] —
#   vda = <esp-img> (whole-ESP rescue media OR the partitioned cache drive),
#   vdb = backing.img, vdc = <payload-img> (pcrsig + tooling tail),
#   vdd = optional extra cache image.
#   Boots the debug-shell UKI; NO feeding before the DEBUG SHELL (the built-in
#   vdb attach fails by construction — see the fidelity notes).
_boot_s19() {
    local bdir="$1" esp="$2" payload="$3" extra="${4:-}"
    mkdir -p "$bdir"
    cp "$RUN/harness.efi" "$bdir/harness.efi"
    cp "$payload" "$bdir/pcrsig.img"
    _ensure_tpm "$RUN/tpm"
    _rearm_trap
    CURRENT_QEMU_DIR="$bdir"
    run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$esp" \
        "$RUN/backing.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$bdir/pcrsig.img" "$extra"
    _qemu_alive "$bdir"
    _rearm_trap
    wait_console "$bdir" "DEBUG SHELL on console" "$QEMU_TIMEOUT"
}

# _untar_tooling <boot-dir> — tooling off the payload tail
_untar_tooling() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
    wait_console "$bdir" "P2A=0" 300
    feed_line "$bdir/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
    wait_console "$bdir" "P2B-42-OK" 300
}

# ============================================================================
# BOOTSTRAP boot: make-bcache -C/-B, register+attach writethrough, LUKS on
# /dev/bcache0, Btrfs @ + canary
# ============================================================================
echo "# bootstrap: bcache stack + LUKS2 on bcache0 + Btrfs @ (fed session)"
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
mkdir -p "$RUN/bootstrap"
_boot_s19 "$RUN/bootstrap" "$RUN/cache.img" "$RUN/pcrsig-core.img"
_untar_tooling "$RUN/bootstrap"
feed_line "$RUN/bootstrap/serial.sock" \
    'make-bcache -C /dev/vda2 >/tmp/mbc.log 2>&1 && make-bcache -B /dev/vdb1 >>/tmp/mbc.log 2>&1 && echo MB-$((31+11))-OK'
wait_console "$RUN/bootstrap" "MB-42-OK" 300
feed_line "$RUN/bootstrap/serial.sock" \
    'echo /dev/vda2 > /sys/fs/bcache/register && echo REGC-$((45+3))-OK; echo /dev/vdb1 > /sys/fs/bcache/register && echo REGB-$((45+4))-OK'
# TCG serial corruption guard: re-derive the sentinel from live sysfs (the
# cache-set dir materializes only on a successful registration) — never a
# blind replay — then wait hard
wait_console_soft "$RUN/bootstrap" "REGC-48-OK" 60 || \
    feed_line "$RUN/bootstrap/serial.sock" \
        'ls /sys/fs/bcache | grep -qE "^[0-9a-f]{8}-" && echo REGC-$((45+3))-OK'
wait_console "$RUN/bootstrap" "REGC-48-OK" 120
wait_console "$RUN/bootstrap" "REGB-49-OK" 120
feed_line "$RUN/bootstrap/serial.sock" \
    'CSET=$(ls /sys/fs/bcache | head -1); echo "CSET $CSET"; echo "$CSET" > /sys/block/bcache0/bcache/attach && echo ATT-$((45+5))-OK'
wait_console "$RUN/bootstrap" "ATT-50-OK" 120
feed_line "$RUN/bootstrap/serial.sock" \
    'i=0; while [ ! -b /dev/bcache0 ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; [ -b /dev/bcache0 ] && echo BC0-$((45+6))-OK || echo BC0-ABSENT-$((45+6)); grep -o "\[writethrough\]" /sys/block/bcache0/bcache/cache_mode && echo WT-$((45+7))-OK; echo "STATE $(cat /sys/block/bcache0/bcache/state)"'
wait_console "$RUN/bootstrap" "BC0-51-OK" 120
feed_line "$RUN/bootstrap/serial.sock" \
    "printf %s $DEBIAN_FDE_SLOT0_PASSPHRASE | cryptsetup luksFormat --type luks2 --pbkdf=argon2id --pbkdf-memory=16000 --pbkdf-parallel=1 --pbkdf-force-iterations=4 --batch-mode /dev/bcache0 && echo LKF-$((45+8))-OK"
wait_console "$RUN/bootstrap" "LKF-53-OK" 300
feed_line "$RUN/bootstrap/serial.sock" \
    "printf %s $DEBIAN_FDE_SLOT0_PASSPHRASE | cryptsetup open --type luks --key-file - /dev/bcache0 root && echo LKO-$((45+9))-OK"
wait_console "$RUN/bootstrap" "LKO-54-OK" 300
feed_line "$RUN/bootstrap/serial.sock" \
    'mkfs.btrfs -f /dev/mapper/root >/tmp/mk.log 2>&1 && mkdir -p /btop && mount -t btrfs /dev/mapper/root /btop && btrfs subvolume create /btop/@ && printf "s19-canary bcache writethrough\n" > /btop/@/canary.txt && echo "CANARY-SHA $(sha256sum /btop/@/canary.txt | cut -d" " -f1)" && echo "LUKSUUID $(cryptsetup luksUUID /dev/bcache0)" && umount /btop && cryptsetup close root && echo BOOT-$((46+0))-DONE'
wait_console "$RUN/bootstrap" "BOOT-46-DONE" 300
feed_line "$RUN/bootstrap/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-bootstrap "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN/bootstrap" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

CANARY_SHA=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | awk '{print $2}')
LUKS_UUID=$(grep -oE 'LUKSUUID [0-9a-f-]{36}' "$RUN/bootstrap/console.log" | head -1 | awk '{print $2}')
[[ -n "$CANARY_SHA" && -n "$LUKS_UUID" ]] || { echo "s19: canary/uuid missing from bootstrap console"; exit 1; }
assert_contains "bootstrap: cache mode is WRITETHROUGH (§4.1 invariant, sysfs)" \
    "$(grep -oE 'WT-[0-9]+-OK' "$RUN/bootstrap/console.log" | head -1)" "WT-52-OK"
assert_contains "bootstrap: bcache state clean after attach" \
    "$(grep -oE 'STATE [a-z0-9]+' "$RUN/bootstrap/console.log" | head -1)" "STATE clean"

# ============================================================================
# Host-side: production crypttab + FINAL baseline (real CLI) + finalize payload
# ============================================================================
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$LUKS_UUID" >"$TOOLING/etc/crypttab"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/debian-fde/keys/release.pub"
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS" "$RUN/rootfs-etc/etc/debian-fde"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkcertvar() { printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
_mkcertvar PK pk-cert-v1
_mkcertvar KEK kek-cert-v1
_mkcertvar db db-cert-v1
_mkcertvar dbx dbx-cert-v1
cat >"$RUN/rootfs-etc/etc/debian-fde/baseline.json" <<'JSON'
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
    "release_pub_path": "/etc/debian-fde/keys/release.pub",
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
    timeout 300 "$REPO/bin/debian-fde" audit --init 2>&1); then
    _assert_result ok "S-19: audit --init finalized the baseline (real CLI, rc 0)" ""
else
    _assert_result not-ok "S-19: audit --init finalized the baseline (real CLI, rc 0)" \
        "output: $(tail -2 <<<"$AUDIT_OUT")"
fi
PCR7_B=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | cut -d= -f2)
sed -i "s|^  \"expected_pcr7\": \".*\",\{0,1\}$|  \"expected_pcr7\": \"$PCR7_B\",|; s|^  \"pcr0\": \".*\",\{0,1\}$|  \"pcr0\": \"$(grep -oE 'debian-fde-pcr sha256:0=[0-9a-f]{64}' "$RUN/bootstrap/console.log" | head -1 | cut -d= -f2)\",|" \
    "$RUN/rootfs-etc/etc/debian-fde/baseline.json"
if grep -q '"expected_pcr7": "pending"' "$RUN/rootfs-etc/etc/debian-fde/baseline.json" \
    || [[ -z "$PCR7_B" ]]; then
    echo "s19: baseline still pending after audit --init — refusing to continue"; exit 1
fi
run_stage baseline-copy 60 cp "$RUN/rootfs-etc/etc/debian-fde/baseline.json" "$TOOLING/etc/debian-fde/baseline.json"
# §8.4 state doc at `installed` — finalize's state gate requires it (a missing
# doc is a loud no-op); the `finalized` write stays scenario-ephemeral in-guest
cat >"$TOOLING/etc/debian-fde/install-state.json" <<JSON
{
  "schema_version": 1,
  "state": "installed",
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
run_stage tooling-tar-full 300 tar -C "$TOOLING" -czf "$RUN/tooling-full.tar.gz" opt etc usr
_budget_check pcrsig-full-drive
cat "$RUN/pcrsig.img" "$RUN/tooling-full.tar.gz" >"$RUN/pcrsig-full.img"

# ============================================================================
# PHASE 1 — cache SSD lost: kernel refuses a cache-less bcache0 (fail-closed);
# the RAW member at the bcache data offset IS the writethrough rescue read
# ============================================================================
P1="$RUN/phase1"
run_stage phase1-move-cache 60 mv "$RUN/cache.img" "$RUN/cache.lost.img"
echo "# phase 1: cache drive MOVED AWAY — backing registered; raw-offset rescue read"
# the rescue ESP (whole-image esp.fat) is the runbook's live-media leg: the
# §4.1 ESP lived on the LOST cache drive
_boot_s19 "$P1" "$RUN/esp.fat" "$RUN/pcrsig-core.img"
feed_line "$P1/serial.sock" \
    'echo /dev/vdb1 > /sys/fs/bcache/register && echo REGB-$((45+4))-OK; i=0; while [ ! -b /dev/bcache0 ] && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done; [ -b /dev/bcache0 ] && echo BC0-$((45+6))-PRESENT || echo BC0-$((45+6))-ABSENT'
wait_console "$P1" "REGB-49-OK" 120
i=0
until grep -qE 'BC0-51-(PRESENT|ABSENT)' "$P1/console.log" 2>/dev/null; do
    _budget_check "console-wait:BC0-51"
    (( i < 120 )) || _hang_fail CONSOLE-WAIT "BC0-51" "not seen in 120s"
    sleep 1
    i=$((i + 1))
done
# writethrough rescue read: the container lives at the bcache data offset
# (16 sectors) on the RAW member. The pending registration holds the member
# exclusively (EBUSY for foreign tables), so the operator first releases it
# from the dead set (bcache stop), then shifts it into view with a linear dm
# map (dmsetup ships in the harness initrd, G-HW5) and opens the LUKS
# normally. Markers stay arithmetic so the tty echo of the fed line can
# never satisfy a wait (the BC0 literals above cost a run: the echo raced
# the poll).
feed_line "$P1/serial.sock" \
    'echo 1 > /sys/block/vdb/vdb1/bcache/stop && echo STP-$((44+9))-OK; i=0; until dmsetup create rootraw --table "0 $(( $(cat /sys/class/block/vdb1/size) - 16 )) linear /dev/vdb1 16" 2>/dev/null; do sleep 1; i=$((i+1)); [ $i -lt 20 ] && continue; echo DM-$((44+8))-FAIL; break; done; [ -b /dev/mapper/rootraw ] && echo DM-$((44+8))-OK'
wait_console "$P1" "STP-53-OK" 60
wait_console "$P1" "DM-52" 120
feed_line "$P1/serial.sock" \
    "printf %s $DEBIAN_FDE_SLOT0_PASSPHRASE | cryptsetup open --type luks --key-file - /dev/mapper/rootraw root && echo LKO-$((45+9))-OK"
wait_console "$P1" "LKO-54-OK" 300
feed_line "$P1/serial.sock" \
    'mkdir -p /mnt && mount -t btrfs -o ro,subvol=@ /dev/mapper/root /mnt && echo MNT-$((44+2))-OK && grep " /mnt btrfs" /proc/mounts | grep -qw ro && echo RO-$((44+3))-OK; echo "CANARY-SHA $(sha256sum /mnt/canary.txt | cut -d" " -f1)"; echo "LUKSUUID $(cryptsetup luksUUID /dev/mapper/rootraw)"; umount /mnt; cryptsetup close root; dmsetup remove rootraw; echo P1-$((44+6))-DONE'
wait_console "$P1" "P1-50-DONE" 300
feed_line "$P1/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-phase1 "$((QEMU_TIMEOUT + 60))" qemu_wait "$P1" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_P1=$(cat "$P1/console.log" 2>/dev/null || true)
P1_CANARY=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$P1/console.log" | head -1 | awk '{print $2}')
P1_UUID=$(grep -oE 'LUKSUUID [0-9a-f-]{36}' "$P1/console.log" | head -1 | awk '{print $2}')
assert_contains "[phase 1] backing registered standalone (no cache set present)" "$LOG_P1" "REGB-49-OK"
# §4.1 kernel semantics, asserted as fail-closed: a CLEAN backing NEVER
# fabricates a bcache0 without its cache set (register_bdev runs NONE/STALE
# only) — the rescue reads the raw member at the data offset instead
assert_contains "[phase 1] kernel refuses a cache-less bcache0 for the CLEAN backing" "$LOG_P1" \
    "BC0-51-ABSENT"
assert_contains "[phase 1] LUKS container opened on the RAW member at the bcache data offset" "$LOG_P1" \
    "LKO-54-OK"
assert_contains "[phase 1] rootfs mounted READ-ONLY (consistency posture)" "$LOG_P1" "MNT-46-OK"
assert_contains "[phase 1] the ro mount option is IN EFFECT (/proc/mounts)" "$LOG_P1" "RO-47-OK"
assert_eq "[phase 1] canary intact on the standalone backing (writethrough ⇒ clean)" \
    "$CANARY_SHA" "$P1_CANARY"
assert_eq "[phase 1] LUKS container uuid unchanged" "$LUKS_UUID" "$P1_UUID"
assert_not_contains "[phase 1] no interactive prompt ever appeared" "$LOG_P1" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[phase 1] no emergency shell" "$LOG_P1" "$(sentinel_of emergency_forbidden)"
if [[ -f "$P1/qemu.pid" ]] && ! kill -0 "$(cat "$P1/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[phase 1] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[phase 1] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# ============================================================================
# PHASE 2 — replacement SSD: new cache image attached writethrough + finalize
# ============================================================================
P2="$RUN/phase2"
run_stage mkfs-cache2-img 60 truncate -s "$(( ESP_MIB + CACHE_MIB + 2 ))M" "$RUN/cache2.img"
printf 'label: gpt\nname=ESP, size=%d, type=uefi\nname=CACHE, type=linux\n' \
    "$(( ESP_MIB * 2048 ))" >"$RUN/cache2.sfdisk"
run_stage sfdisk-cache2 120 bash -c 'sfdisk --quiet "$1" < "$2"' _ "$RUN/cache2.img" "$RUN/cache2.sfdisk"
echo "# phase 2: NEW cache image attached writethrough; production finalize enrolls bcache0"
# the payload carries the tooling-FULL tail (crypttab + baseline + keys)
_boot_s19 "$P2" "$RUN/esp.fat" "$RUN/pcrsig-full.img" "$RUN/cache2.img"   # vdd = new cache image
_untar_tooling "$P2"
feed_line "$P2/serial.sock" \
    'make-bcache -C /dev/vdd2 >/tmp/mbc2.log 2>&1 && echo MB-$((31+11))-OK'
wait_console "$P2" "MB-42-OK" 300
feed_line "$P2/serial.sock" \
    'echo /dev/vdd2 > /sys/fs/bcache/register && echo REGC-$((45+3))-OK; echo /dev/vdb1 > /sys/fs/bcache/register && echo REGB-$((45+4))-OK'
# TCG serial corruption guard (same as the bootstrap registration sentinel)
wait_console_soft "$P2" "REGC-48-OK" 60 || \
    feed_line "$P2/serial.sock" \
        'ls /sys/fs/bcache | grep -qE "^[0-9a-f]{8}-" && echo REGC-$((45+3))-OK'
wait_console "$P2" "REGC-48-OK" 120
wait_console "$P2" "REGB-49-OK" 120
feed_line "$P2/serial.sock" \
    'CSET=$(ls /sys/fs/bcache | grep -E "^[0-9a-f]{8}-" | head -1); echo "$CSET" > /sys/block/vdb/vdb1/bcache/attach && echo ATT-$((45+5))-OK; i=0; until [ "$(cat /sys/block/bcache0/bcache/state 2>/dev/null)" = "clean" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; echo "STATE $(cat /sys/block/bcache0/bcache/state)"; grep -o "\[writethrough\]" /sys/block/bcache0/bcache/cache_mode && echo WT-$((45+7))-OK'
wait_console "$P2" "ATT-50-OK" 120
feed_line "$P2/serial.sock" \
    "printf %s $DEBIAN_FDE_SLOT0_PASSPHRASE | cryptsetup open --type luks --key-file - /dev/bcache0 root && echo LKO-$((45+9))-OK"
wait_console "$P2" "LKO-54-OK" 300
feed_line "$P2/serial.sock" \
    'mkdir -p /mnt && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && echo MNT-OK && echo "CANARY-SHA $(sha256sum /mnt/canary.txt | cut -d" " -f1)" && echo "LUKSUUID $(cryptsetup luksUUID /dev/bcache0)" && umount /mnt && echo P2C-$((46+1))-DONE'
wait_console "$P2" "P2C-47-DONE" 300
# production finalize: crypttab + final baseline came on the tooling tail
feed_line "$P2/serial.sock" \
    "mkdir -p /run/bu && ln -sf /dev/bcache0 /run/bu/$LUKS_UUID && export DEBIAN_FDE_NO_INSTALL=1 DEBIAN_FDE_TCTI=device:/dev/tpmrm0 DEBIAN_FDE_BY_UUID_DIR=/run/bu DEBIAN_FDE_CRYPTENROLL=/usr/bin/cryptenroll-kf DEBIAN_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty DEBIAN_FDE_EVENTLOG=/evtlog-absent && echo P5-\$((43))-OK"
wait_console "$P2" "P5-43-OK" 120
feed_line "$P2/serial.sock" 'timeout 300 /opt/debian-fde/bin/debian-fde finalize; echo P6-RC=$?'
i=0
until grep -qE 'P6-RC=[0-9]+' "$P2/console.log" 2>/dev/null; do
    _budget_check "console-wait:P6-RC"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "finalize never returned"
    sleep 1
    i=$((i + 1))
done
CLI_RC_P2=$(grep -oE 'P6-RC=[0-9]+' "$P2/console.log" | head -1 | cut -d= -f2)
feed_line "$P2/serial.sock" \
    'cryptsetup luksDump --dump-json-metadata /dev/bcache0 | jq "[.tokens[] | select(.type==\"systemd-tpm2\")] | length" | xargs echo ENROLLTOK; sync; poweroff -f'
run_stage qemu_wait-phase2 "$((QEMU_TIMEOUT + 60))" qemu_wait "$P2" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_P2=$(cat "$P2/console.log" 2>/dev/null || true)
P2_CANARY=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$P2/console.log" | head -1 | awk '{print $2}')
P2_UUID=$(grep -oE 'LUKSUUID [0-9a-f-]{36}' "$P2/console.log" | head -1 | awk '{print $2}')
assert_contains "[phase 2] new cache set created + registered" "$LOG_P2" "MB-42-OK"
assert_contains "[phase 2] explicit sysfs attach of the new cache set" "$LOG_P2" "ATT-50-OK"
assert_contains "[phase 2] bcache state CLEAN after re-attach (writethrough, no dirty data)" \
    "$LOG_P2" "STATE clean"
assert_contains "[phase 2] cache mode WRITETHROUGH after re-attach (§4.1)" "$LOG_P2" "WT-52-OK"
assert_contains "[phase 2] /dev/bcache0 consistent: container opened" "$LOG_P2" "LKO-54-OK"
assert_eq "[phase 2] canary intact across the re-attach" "$CANARY_SHA" "$P2_CANARY"
assert_eq "[phase 2] container uuid unchanged across the re-attach" "$LUKS_UUID" "$P2_UUID"
assert_contains "[phase 2] baseline already final (audit skipped, §9.1 idempotency)" "$LOG_P2" \
    "baseline already final — skipping audit --init"
assert_contains "[phase 2] production CLI enrolled the bcache0 container" "$LOG_P2" \
    "debian-fde: member $LUKS_UUID: enrolled (keyslot 1, token 0)"
assert_contains "[phase 2] cryptenroll enrolled sentinel (Mechanism A'')" "$LOG_P2" \
    "$(sentinel_of cryptenroll_enrolled)"
assert_contains "[phase 2] install finalized marker" "$LOG_P2" "debian-fde: install finalized"
assert_eq "[phase 2] production finalize rc 0" "0" "$CLI_RC_P2"
assert_contains "[phase 2] post-enroll metadata: exactly ONE systemd-tpm2 token" "$LOG_P2" \
    "ENROLLTOK 1"
assert_not_contains "[phase 2] no interactive prompt ever appeared" "$LOG_P2" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[phase 2] no emergency shell" "$LOG_P2" "$(sentinel_of emergency_forbidden)"

# ============================================================================
# PHASE 3 — ESP rebuilt HOST-side (same release key) + zero-input UNSEALED
# ============================================================================
P3="$RUN/phase3"
run_stage mv-lost-cache-aside 60 mv "$RUN/cache.lost.img" "$RUN/cache-dead.img"
echo "# phase 3: ESP rebuilt host-side (esp_make + uki_build, same release key) — production boot shape"
DEBIAN_FDE_DEBUG_SHELL=1 DEBIAN_FDE_ROOTFS_SHA= DEBIAN_FDE_ROOTFS_BYTES= \
    run_stage uki_build-rebuild 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-rebuild.efi"
run_stage esp-rebuild 300 esp_make "$RUN/esp-rebuilt.fat" "$ESP_MIB" "$RUN/harness-rebuild.efi"
run_stage mkfs-cache3-img 60 truncate -s "$(( ESP_MIB + CACHE_MIB + 2 ))M" "$RUN/cache3.img"
printf 'label: gpt\nname=ESP, size=%d, type=uefi\nname=CACHE, type=linux\n' \
    "$(( ESP_MIB * 2048 ))" >"$RUN/cache3.sfdisk"
run_stage sfdisk-cache3 120 bash -c 'sfdisk --quiet "$1" < "$2"' _ "$RUN/cache3.img" "$RUN/cache3.sfdisk"
run_stage esp-into-p1-rebuild 120 bash -c \
    'dd if="$1" of="$2" bs=512 seek=2048 conv=notrunc status=none' _ \
    "$RUN/esp-rebuilt.fat" "$RUN/cache3.img"
# the payload drive must pair the REBUILT UKI's fresh .pcrsig with the tooling
run_stage pcrsig_disk-rebuild 60 uki_pcrsig_disk "$RUN/pcrsig-rebuild.img" "$RUN/uki-pcrsig.json"
_budget_check pcrsig-rebuild-drive
cat "$RUN/pcrsig-rebuild.img" "$RUN/tooling-full.tar.gz" >"$RUN/pcrsig-rebuild-full.img"
mkdir -p "$P3"
cp "$RUN/harness-rebuild.efi" "$P3/harness.efi"
cp "$RUN/pcrsig-rebuild-full.img" "$P3/pcrsig.img"
_ensure_tpm "$RUN/tpm"
_rearm_trap
CURRENT_QEMU_DIR="$P3"
run_stage qemu_run-phase3 60 qemu_run "$P3" "$RUN/cache3.img" "$RUN/backing.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$P3/pcrsig.img"
_qemu_alive "$P3"
_rearm_trap
wait_console "$P3" "DEBUG SHELL on console" "$QEMU_TIMEOUT"
_untar_tooling "$P3"
feed_line "$P3/serial.sock" \
    'make-bcache -C /dev/vda2 >/tmp/mbc3.log 2>&1 && echo MB-$((31+11))-OK'
wait_console "$P3" "MB-42-OK" 300
feed_line "$P3/serial.sock" \
    'echo /dev/vda2 > /sys/fs/bcache/register && echo REGC-$((45+3))-OK; echo /dev/vdb1 > /sys/fs/bcache/register && echo REGB-$((45+4))-OK'
# TCG serial corruption guard (same as the bootstrap registration sentinel)
wait_console_soft "$P3" "REGC-48-OK" 60 || \
    feed_line "$P3/serial.sock" \
        'ls /sys/fs/bcache | grep -qE "^[0-9a-f]{8}-" && echo REGC-$((45+3))-OK'
wait_console "$P3" "REGC-48-OK" 120
wait_console "$P3" "REGB-49-OK" 120
feed_line "$P3/serial.sock" \
    'CSET=$(ls /sys/fs/bcache | grep -E "^[0-9a-f]{8}-" | head -1); echo "$CSET" > /sys/block/vdb/vdb1/bcache/attach && echo ATT-$((45+5))-OK; i=0; until [ "$(cat /sys/block/bcache0/bcache/state 2>/dev/null)" = "clean" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; echo "STATE $(cat /sys/block/bcache0/bcache/state)"'
wait_console "$P3" "ATT-50-OK" 120
# THE ZERO-INPUT PROOF: the production unlock primitive against /dev/bcache0
# with the standing token + the rebuilt UKI's own .pcrsig — no passphrase, no
# fed credential of any kind.
feed_line "$P3/serial.sock" \
    'SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-cryptsetup attach root /dev/bcache0 "" "tpm2-device=auto,tpm2-signature=/pcrsig.json,tries=1" 2>/tmp/p3u.log; echo P3ATTACH=$?; grep -cE "Requesting JSON|activated with a LUKS token" /tmp/p3u.log | xargs echo SENTINELHITS; grep -F "Requesting JSON for token 0." /tmp/p3u.log; grep -F "Adding PCR signature policy." /tmp/p3u.log; grep -F "activated with a LUKS token." /tmp/p3u.log; echo P3U-$((46+2))-DONE'
wait_console "$P3" "P3U-48-DONE" 300
feed_line "$P3/serial.sock" \
    '[ -e /dev/mapper/root ] && echo MAP-$((44+4))-OK; mkdir -p /mnt && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && echo MNT-$((44+2))-OK && echo "CANARY-SHA $(sha256sum /mnt/canary.txt | cut -d" " -f1)"; sync; poweroff -f'
run_stage qemu_wait-phase3 "$((QEMU_TIMEOUT + 60))" qemu_wait "$P3" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_P3=$(cat "$P3/console.log" 2>/dev/null || true)
P3_RC=$(grep -oE 'P3ATTACH=[0-9]+' "$P3/console.log" | head -1 | cut -d= -f2)
P3_CANARY=$(grep -oE 'CANARY-SHA [0-9a-f]{64}' "$P3/console.log" | tail -1 | awk '{print $2}')
assert_contains "[phase 3] rebuilt UKI is in the fresh ESP (rebuild ran)" "$LOG_P3" \
    "debian-fde-harness: init started"
assert_contains "[phase 3] bcache stack reassembled (new cache + backing, attached)" "$LOG_P3" \
    "ATT-50-OK"
assert_contains "[phase 3] bcache state clean" "$LOG_P3" "STATE clean"
assert_eq "[phase 3] zero-input production attach rc 0 (standing token + fresh .pcrsig)" "0" \
    "$P3_RC"
assert_contains "[phase 3] standing token discovered by the real unlock path" "$LOG_P3" \
    "$(sentinel_of token_discovered)"
assert_contains "[phase 3] the rebuilt UKI's .pcrsig consumed (signed policy)" "$LOG_P3" \
    "$(sentinel_of pcr_sig_added)"
assert_contains "[phase 3] volume activated with a LUKS token (sentinel table)" "$LOG_P3" \
    "$(sentinel_of unlocked)"
assert_contains "[phase 3] mapper node materialized" "$LOG_P3" "MAP-48-OK"
assert_eq "[phase 3] canary intact end-to-end (crash-consistency acceptance)" \
    "$CANARY_SHA" "$P3_CANARY"
assert_not_contains "[phase 3] no passphrase was ever fed or prompted (zero-input)" "$LOG_P3" \
    "awaiting console line"
assert_not_contains "[phase 3] no interactive prompt ever appeared" "$LOG_P3" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[phase 3] no emergency shell" "$LOG_P3" "$(sentinel_of emergency_forbidden)"
if [[ -f "$P3/qemu.pid" ]] && ! kill -0 "$(cat "$P3/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[phase 3] guest exited (clean poweroff, not timeout-kill)" ""
else
    _assert_result not-ok "[phase 3] guest exited (clean poweroff, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/cache-dead.img"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s19-bcache-crash: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s19-bcache-crash: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
