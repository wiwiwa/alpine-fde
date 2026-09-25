#!/usr/bin/env bash
# tests/lib/qemu.sh — guest runner for the Alpine FDE e2e harness (TCG by
# default in this sandbox — no /dev/kvm; KVM is used when available, see the
# accelerator selection below; budget ~2-4 min per TCG boot, so keep boots
# minimal and always hard-timeout).
#
# Usage (source, then):
#   qemu_run <run-dir> <esp.img> <disk.img> <vars.fd> <swtpm-dir> [pcrsig.img] \
#            [extra-drives]
#     * boots q35 + OVMF secboot (code readonly, per-scenario VARS copy),
#       swtpm passthrough (tpm-tis), ESP+LUKS(+payload) virtio drives,
#       serial on a unix socket with EVERYTHING teed to <run-dir>/console.log
#       (chardev logfile=), hard timeout kill, PID in <run-dir>/qemu.pid.
#       The chardev socket is INTERNAL (<run-dir>/serial-qemu.sock): a
#       persistent console bridge (serial_bridge_start, tests/lib/serial.sh)
#       owns the client side and fronts the public <run-dir>/serial.sock —
#       feed_line/serial.py callers connect there, never to qemu directly.
#     * <extra-drives> (G-HW1, opt-in): newline-separated image paths appended
#       as virtio drives AFTER the pcrsig payload slot — the N-disk mechanism
#       for multi-drive scenarios. Empty/absent (every current caller) keeps
#       the historical 2+1-positional argv byte-identical.
#   qemu_argv <run-dir> <esp.img> <disk.img> <vars.fd> <swtpm-dir> [pcrsig.img] \
#             [extra-drives]
#     * pure-argv seam: prints (one per line) exactly the argv qemu_run execs.
#       No pin checks, no sockets, no accelerator probe — unit-testable (the
#       once-per-process accelerator choice applies: unset => TCG, no -accel).
#       ALPINE_FDE_QEMU_NO_TPM=1 omits the tpmdev trio (chardev chrtpm /
#       tpmdev tpm0 / device tpm-tis) for the TPM-less-machine scenarios
#       (s10): the guest then has NO TPM character device at all, while the
#       rest of the shared path (pins, accelerator, console bridge, pid file)
#       is exactly qemu_run's. Unset (the default) emits the trio unchanged.
#   qemu_wait <run-dir> <timeout-s>   wait for exit (0 = powered off cleanly)
#   qemu_kill <run-dir>               hard kill (timeout path)
#
# Boot timing (Step timing, tests/README.md): qemu_run records the boot's
# launch epoch and qemu_wait emits to the SCENARIO stdout (which run-e2e
# captures per scenario — NEVER to console.log, whose format the sentinel
# asserts own):
#   # boot <basename-of-run-dir>: powered down after <seconds>s   (clean exit)
#   # boot <basename-of-run-dir>: killed after <seconds>s         (timeout path)
#
# Drive map (fixed contract with the harness /init): vda=ESP, vdb=LUKS disk,
# vdc=optional pcrsig payload, vdd, vde, … = extra-drives list order.
#
# EMPIRICAL (verified this sandbox): the tpmdev-emulator chardev must point at
# swtpm's CONTROL socket (<state-dir>/sock.ctrl — QEMU speaks the swtpm ctrl
# protocol on it). Pointing it at the server socket ("sock") deadlocks the
# firmware in its TPM handshake before ANY console output — 0 serial bytes,
# silent hang. (unixio equivalent of the control-port=server+1 TCP quirk.)

if [[ -n "${_ALPINE_FDE_QEMU_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_QEMU_SOURCED=1

QEMU_TIMEOUT="${QEMU_TIMEOUT:-300}"

# Boot-timing state: launch epoch per run dir (recorded by qemu_run, consumed
# by qemu_wait's clean/timeout emission). A run dir whose boot was launched by
# a PREVIOUS process (e.g. a re-sourced library) falls back to the qemu.pid
# mtime — see _qemu_boot_note.
declare -A _QEMU_BOOT_T0=()

# qemu_now_epoch — current unix epoch without a fork (bash >= 5 builtin
# variable; date(1) only as a pre-bash-5 fallback). Shared by the boot-timing
# recorder and the stage-timing library's own epoch logic.
qemu_now_epoch() {
    if [[ -n "${EPOCHREALTIME:-}" ]]; then
        printf '%s' "${EPOCHREALTIME%.*}"
    else
        date +%s
    fi
}

# _qemu_boot_note <run-dir> <powered|killed> — emit the boot's wall time to
# scenario stdout. No recorded epoch AND no pid file: emit nothing (rc 0) —
# a missing measurement is never a fabricated one.
_qemu_boot_note() {
    local run="$1" outcome="$2" t0 now
    t0=${_QEMU_BOOT_T0[$run]:-}
    if [[ -z "$t0" && -f "$run/qemu.pid" ]]; then
        t0=$(stat -c %Y "$run/qemu.pid" 2>/dev/null || true)
    fi
    [[ -n "$t0" ]] || return 0
    now=$(qemu_now_epoch)
    if [[ "$outcome" == "killed" ]]; then
        printf '# boot %s: killed after %ds\n' "${run##*/}" "$((now - t0))"
    else
        printf '# boot %s: powered down after %ds\n' "${run##*/}" "$((now - t0))"
    fi
    return 0
}

# --- guest console wiring (persistent bridge, see tests/lib/serial.sh) ------------
# The serial chardev points at the INTERNAL socket <run>/serial-qemu.sock; the
# console bridge started below owns that client connection for the whole boot
# and fronts the PUBLIC <run>/serial.sock every scenario feeds/reads.
# ROOT CAUSE (live-evidenced 2026-09-22, tests/unit/serial_feed_race.sh): the
# historical direct wiring (feeder connects straight to the chardev socket,
# sends, holds ~5s, closes) loses in-flight input whenever the guest's UART is
# backpressured (vCPU descheduled under host load) at the moment the feeder
# closes — only the bytes already in the UART FIFO (~8) survive, the
# passphrase line arrives truncated/unterminated and the hook's prompt hangs
# until the 420s timeout kill. With the bridge, the qemu-side connection never
# closes during a boot, so queued input is delivered whenever the guest
# drains, regardless of load.
_QEMU_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/serial.sh
source "$_QEMU_LIB_DIR/serial.sh"

# --- accelerator selection (/dev/kvm is REQUIRED) ---------------------------------
# ALPINE_FDE_ACCEL: kvm (default) | tcg. KVM is a hard requirement for e2e
# (§12): an unusable /dev/kvm is a loud fail-closed error — never a silent TCG
# downgrade (TCG boots blow the per-scenario time budget and corrupt the serial
# console; the explicit escape hatch below exists for exactly that reason).
# ALPINE_FDE_ACCEL=tcg is honored verbatim as the explicitly-requested dev
# opt-out; any other value (including the old silent 'auto') is rejected. The
# decision is made once per process and logged with a greppable `qemu-accel:`
# marker; every qemu_run in the process then uses the chosen accelerator (the
# `-accel kvm` flag is added ONLY for KVM, so TCG invocations stay
# byte-identical). OVMF + swtpm need no accel-specific flags and work
# identically under both.
# ALPINE_FDE_KVM_PROBE_TIMEOUT (seconds, default 10) bounds the KVM probe guest
# below: the probe is SELF-TERMINATING (QMP `quit` over stdio), so the bound is
# only a hang guard — a refusal costs ~0.1s on a broken-KVM host, never a
# 30s idle-kill.
ALPINE_FDE_ACCEL="${ALPINE_FDE_ACCEL:-kvm}"
ALPINE_FDE_KVM_PROBE_TIMEOUT="${ALPINE_FDE_KVM_PROBE_TIMEOUT:-10}"

_qemu_accel=""

# _qemu_kvm_probe_run — self-terminating probe guest. Drives QMP over stdio:
# `qmp_capabilities` then `quit` make qemu exit as soon as KVM init is proven,
# instead of idling until an external killer arrives (the old `timeout 30 …`
# form paid a 30s hang on every refusal). Success ONLY = KVM-accelerated qemu
# (a lone `-accel kvm` never falls back to TCG) starts AND exits cleanly within
# the ALPINE_FDE_KVM_PROBE_TIMEOUT bound; timeout-kill, nonzero exit, or a
# missing binary are all "not working". VERIFIED on this sandbox: 0.115s, rc 0,
# query-kvm -> {"enabled": true}; with stdin at EOF qemu would idle, hence the
# piped quit AND the timeout guard (belt and braces).
_qemu_kvm_probe_run() {
    printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}' \
        | timeout "${ALPINE_FDE_KVM_PROBE_TIMEOUT}" \
            qemu-system-x86_64 -accel kvm -machine none -display none \
            -qmp stdio >/dev/null 2>&1
}

# _qemu_kvm_ok — /dev/kvm present, writable, and a -machine none probe guest
# actually starts under KVM and exits cleanly (the kernel module can be loaded
# but broken). The cheap /dev/kvm check stays the first gate; the qemu probe
# (_qemu_kvm_probe_run) is the authoritative one.
_qemu_kvm_ok() {
    [[ -e /dev/kvm && -w /dev/kvm ]] || return 1
    _qemu_kvm_probe_run
}

# _qemu_accel_choose — decide the accelerator ONCE PER PROCESS and log the
# choice (loud, greppable `qemu-accel:` marker); sets $_qemu_accel, rc 0.
# Nonzero = KVM required but unusable (default and explicit kvm), explicit tcg
# is always honored, invalid env value. This is the entry point qemu_run uses
# — NOT via command substitution, whose subshell would defeat the
# once-per-process cache.
_qemu_accel_choose() {
    [[ -n "$_qemu_accel" ]] && return 0
    local mode="${ALPINE_FDE_ACCEL:-kvm}" why
    case "$mode" in
        tcg)
            _qemu_accel="tcg"; why="requested (ALPINE_FDE_ACCEL=tcg)" ;;
        kvm)
            if _qemu_kvm_ok; then
                _qemu_accel="kvm"; why="requested (ALPINE_FDE_ACCEL=kvm)"
            else
                echo "qemu-accel: KVM is REQUIRED for e2e but /dev/kvm is unusable here" >&2
                echo "  (need /dev/kvm, writable, and a working probe:" >&2
                echo "   qemu-system-x86_64 -accel kvm -machine none -display none" >&2
                echo "   -qmp stdio, bounded by ALPINE_FDE_KVM_PROBE_TIMEOUT" >&2
                echo "   =${ALPINE_FDE_KVM_PROBE_TIMEOUT}s: success only on a clean exit)" >&2
                echo "  enable KVM (modprobe kvm_intel / kvm_amd) or run on KVM-capable" >&2
                echo "  hardware; explicitly set ALPINE_FDE_ACCEL=tcg to opt out anyway" >&2
                return 1
            fi
            ;;
        auto)
            echo "qemu-accel: ALPINE_FDE_ACCEL=auto removed — KVM is required by default;" >&2
            echo "  set ALPINE_FDE_ACCEL=tcg explicitly to request software emulation" >&2
            return 1
            ;;
        *)
            echo "qemu-accel: invalid ALPINE_FDE_ACCEL='$mode' (want kvm|tcg)" >&2
            return 1
            ;;
    esac
    echo "qemu-accel: using $_qemu_accel ($why)" >&2
    return 0
}

# qemu_accel — reporter form for `$( )` callers (the runner logs the choice
# once per run this way). Re-derives the same deterministic decision in the
# subshell; qemu_run's own first use logs the same line inside the scenario
# process.
qemu_accel() {
    _qemu_accel_choose || return 1
    printf '%s\n' "$_qemu_accel"
}

# --- OVMF fixture pins (§3.1: the harness, not the doc, is the pin of record) -----
# The repo's fixture set is pinned below. CI pinning its own OVMF artifacts
# overrides the pins via env (hashes must cover whichever files the path vars
# select):
#   OVMF_CODE / OVMF_VARS_STOCK          path overrides (same vars as the boot
#                                        code pflash / keys-fixture enrollment)
#   ALPINE_FDE_OVMF_CODE_SHA256          expected sha256 of the code image
#   ALPINE_FDE_OVMF_VARS_SHA256          expected sha256 of the vars template
ALPINE_FDE_OVMF_CODE_SHA256_DEFAULT="cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f"
ALPINE_FDE_OVMF_VARS_SHA256_DEFAULT="5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"

_qemu_ovmf_code() { printf '%s\n' "${OVMF_CODE:-/usr/share/ovmf/x64/OVMF_CODE.secboot.4m.fd}"; }
_qemu_ovmf_vars() { printf '%s\n' "${OVMF_VARS_STOCK:-/usr/share/ovmf/x64/OVMF_VARS.4m.fd}"; }

# _ovmf_pin_one <path> <override-var> <default-pin> — loud failure naming the
# mismatch when <path>'s sha256 differs from the active pin.
_ovmf_pin_one() {
    local path="$1" var="$2" default="$3" expected actual
    if [[ ! -f "$path" ]]; then
        echo "ovmf-pin: MISSING fixture: $path" >&2
        return 1
    fi
    expected="${!var:-$default}"
    actual=$(sha256sum "$path" | awk '{print $1}')
    if [[ "$actual" != "$expected" ]]; then
        echo "ovmf-pin: SHA256 MISMATCH for $path" >&2
        echo "  expected: $expected   (from ${var:-the harness default pin})" >&2
        echo "  actual:   $actual" >&2
        echo "  (CI pinning its own artifacts: export $var=<sha256 of your $path>)" >&2
        return 1
    fi
    return 0
}

# ovmf_pin_check — verify both OVMF fixture files against the active pins
# (env override wins, else the recorded default). Nonzero = loud mismatch.
ovmf_pin_check() {
    local rc=0
    _ovmf_pin_one "$(_qemu_ovmf_code)" ALPINE_FDE_OVMF_CODE_SHA256 \
        "$ALPINE_FDE_OVMF_CODE_SHA256_DEFAULT" || rc=1
    _ovmf_pin_one "$(_qemu_ovmf_vars)" ALPINE_FDE_OVMF_VARS_SHA256 \
        "$ALPINE_FDE_OVMF_VARS_SHA256_DEFAULT" || rc=1
    return "$rc"
}

# _qemu_disk_format <img> — the -drive format for the DISK: raw for every
# fixture/base image, qcow2 for the Wave-2 2b EPHEMERAL OVERLAYS
# (tests/lib/overlay-disk.sh names every overlay *.qcow2). Strictly
# extension-keyed: no existing raw caller changes behavior.
_qemu_disk_format() {
    case $1 in
        *.qcow2) printf 'qcow2' ;;
        *) printf 'raw' ;;
    esac
}

# --- disk-image locking (Wave-2 2b) -------------------------------------------
# Every boot holds LOCK_SH on the DISK's whole backing chain (base first) for
# the boot's lifetime: acquired in qemu_run, released via serial_bridge_stop
# (the single choke point qemu_wait, qemu_kill and every scenario-local wait
# guard already call on every exit path — release is therefore idempotent and
# leak-free even on wedge-recovery paths). A chain-less raw disk locks itself;
# an overlay locks every parent, so a pristine base cannot be mutated by a
# generator while any consumer boots it. Crash-safe: SIGKILL drops flocks.
QEMU_DISK_LOCK_FDS=()

_disk_lock_shared() {
    local img=$1 parent fd f
    img=$(readlink -f -- "$img" 2>/dev/null) || return 0
    local -a chain=("$img") guard=0
    while ((guard < 8)); do
        guard=$((guard + 1))
        parent=$(qemu-img info --output=json -- "${chain[${#chain[@]} - 1]}" 2>/dev/null |
            jq -r '."backing-filename" // empty') || parent=""
        [[ -z "$parent" ]] && break
        parent=$(readlink -f -- "$parent" 2>/dev/null) || break
        [[ " ${chain[*]} " == *" $parent "* ]] && break   # cycle guard
        chain+=("$parent")
    done
    for f in "${chain[@]}"; do
        exec {fd}<"$f" 2>/dev/null || continue
        if flock -s "$fd" 2>/dev/null; then
            QEMU_DISK_LOCK_FDS+=("$fd")
        else
            eval "exec ${fd}<&-" 2>/dev/null
        fi
    done
}

_disk_lock_release() {
    local fd
    for fd in "${QEMU_DISK_LOCK_FDS[@]}"; do
        eval "exec ${fd}<&-" 2>/dev/null
    done
    QEMU_DISK_LOCK_FDS=()
}

# qemu_argv <run-dir> <esp.img> <disk.img> <vars.fd> <swtpm-dir> [pcrsig.img] \
#           [extra-drives] — the qemu_run argv, one argument per line on
# stdout. Pure function: the pin check, accelerator choice and socket cleanup
# stay in qemu_run (here $_qemu_accel is read as-is; unset => TCG argv, the
# deterministic form the unit assertions pin). The optional 7th argument is
# the newline-separated extra-drives list (G-HW1): every entry becomes one
# virtio drive appended after the optional pcrsig payload drive (vdd, vde, …
# in list order).
qemu_argv() {
    local run="$1" esp="$2" disk="$3" vars="$4" swtpmdir="$5" pcrsig="${6:-}" extra="${7:-}"
    # INTERNAL socket: the console bridge (tests/lib/serial.sh) owns the client
    # side; scenarios only ever see the public <run>/serial.sock.
    local sock; sock=$(_qemu_serial_sock "$run")
    printf '%s\n' \
        -machine q35 -m 2048 \
        -smp "${ALPINE_FDE_GUEST_SMP:-2}"
    if [[ "$_qemu_accel" == "kvm" ]]; then
        printf '%s\n' -accel kvm
    fi
    printf '%s\n' \
        -display none -nodefaults \
        -drive "if=pflash,format=raw,readonly=on,file=$(_qemu_ovmf_code)" \
        -drive "if=pflash,format=raw,file=$vars" \
        -drive "file=$esp,format=raw,if=virtio" \
        -drive "file=$disk,format=$(_qemu_disk_format "$disk"),if=virtio"
    if [[ "${ALPINE_FDE_QEMU_NO_TPM:-}" == "1" ]]; then
        :   # TPM-less machine (s10): no chardev/tpmdev/tpm-tis trio at all
    else
        # DEVICE INTERFACE: tpm-crb, not tpm-tis. ROOT CAUSE (2026-09-22,
        # docs/research/tpm-init-timing.md): qemu's async TPM completions are
        # dispatched via bottom-halves, but aio_notify() misses waking the
        # main loop from ppoll() (glib poll path) — completions only dispatch
        # when a periodic timer fires. On tpm-tis, OVMF's driver waits out a
        # ~1.2 s interrupt-completion timeout PER COMMAND (minutes of silent
        # pre-BdsDxe bring-up per boot); on tpm-crb the guest's tight
        # CRB_CTRL_START poll instead wedges the whole boot. The -qmp socket
        # below + the QMP kicker process spawned in qemu_run (query-status
        # every 15 ms) wakes the main loop so completion BHs retire
        # immediately: verified 112/112 TPM commands, firmware phase
        # ~8 min → ~10-15 s (docs/research/tpm-init-timing.md, mitigation 1).
        printf '%s\n' \
            -chardev "socket,id=chrtpm,path=$swtpmdir/sock.ctrl" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-crb,tpmdev=tpm0
    fi
    printf '%s\n' \
        -chardev "socket,id=ser0,path=$sock,server=on,wait=off,logfile=$run/console.log" \
        -qmp "unix:path=$run/qmp.sock,server=on,wait=off" \
        -serial chardev:ser0
    if [[ -n "$pcrsig" ]]; then
        printf '%s\n' "-drive" "file=$pcrsig,format=$(_qemu_disk_format "$pcrsig"),if=virtio"
    fi
    local d
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        # per-extension format (Wave-2 2b): extra drives may be qcow2 overlays
        # (e.g. raid member-2 legs in s19/s21/s22), not only raw images
        printf '%s\n' "-drive" "file=$d,format=$(_qemu_disk_format "$d"),if=virtio"
    done <<<"$extra"
    return 0
}

qemu_run() {
    local run="$1" esp="$2" disk="$3" vars="$4" swtpmdir="$5" pcrsig="${6:-}" extra="${7:-}"
    ovmf_pin_check || return 1
    _qemu_accel_choose || return 1
    # kill any bridge from a previous boot on this run dir FIRST: it owns the
    # stale <run>/serial.sock that qemu_run must recreate cleanly
    serial_bridge_stop "$run"
    rm -f "$(_qemu_serial_sock "$run")" "$run/console.log" "$run/qemu.pid" \
        "$(serial_bridge_log "$run")"
    serial_bridge_start "$run" || return 1
    # Wave-2 2b disk locking: LOCK_SH on the disk's whole backing chain for
    # the boot's lifetime (released by serial_bridge_stop on every exit path
    # of every wait flavor — see _disk_lock_shared above)
    _disk_lock_shared "$disk"
    local -a args=()
    mapfile -t args < <(qemu_argv "$run" "$esp" "$disk" "$vars" "$swtpmdir" \
        "$pcrsig" "$extra")
    _QEMU_BOOT_T0["$run"]=$(qemu_now_epoch)   # boot-timing start (qemu_wait emits the elapsed)
    qemu-system-x86_64 "${args[@]}" >"$run/qemu.stdout" 2>"$run/qemu.stderr" &
    echo $! >"$run/qemu.pid"
    # QMP kicker (tpm-crb companion, docs/research/tpm-init-timing.md): a
    # 15 ms query-status poll on $run/qmp.sock wakes qemu's main loop out of
    # ppoll() so TPM completion bottom-halves retire immediately — without
    # it the guest's firmware TPM phase stalls minutes (tpm-tis) or wedges
    # outright (tpm-crb). Idempotent; re-armed by qemu_wait if it dies.
    _qmp_kicker_start "$run"
    return 0
}

# _qmp_kicker_start <run-dir> — spawn the QMP kicker unless one is already
# alive for this run (recorded in <run>/qmp-kicker.pid). Idempotent.
_qmp_kicker_start() {
    local run="$1" kpid
    kpid=$(cat "$run/qmp-kicker.pid" 2>/dev/null) || kpid=""
    [[ -n "$kpid" ]] && kill -0 "$kpid" 2>/dev/null && return 0
    setsid python3 - "$run/qmp.sock" "$run/console.log" >>"$run/qmp-kicker.log" 2>&1 <<'PYEOF' &
import json, os, socket, sys, time
qmp_path, console_path = sys.argv[1], sys.argv[2]
deadline = time.time() + 900   # 15 min max lifetime; qemu reap is authoritative
# Two-phase lifetime: DENSE (15 ms) while the firmware phase is silent
# (console.log 0 bytes — the window where a stranded completion BH wedges
# the guest), then LIGHT (1 Hz) once OVMF reaches BdsDxe and the console
# starts emitting — the guard stays up until qemu exits, at throwaway cost.
def console_started():
    try:
        return os.path.getsize(console_path) > 0
    except OSError:
        return False
while time.time() < deadline:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(qmp_path)
        f = s.makefile("rw")
        f.readline()                       # qmp greeting
        while True:
            f.write('{"execute":"query-status"}\n'); f.flush()
            line = f.readline()
            if not line:
                raise ConnectionError       # qemu gone: kicker is done
            time.sleep(0.015 if not console_started() else 1.0)
    except OSError:
        pass
    time.sleep(0.05)
PYEOF
    echo $! >"$run/qmp-kicker.pid"
    return 0
}

qemu_wait() {
    local run="$1" timeout="$2" pid
    pid=$(cat "$run/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            # clean guest exit: time on the record, then reap bridge + kicker
            _qemu_boot_note "$run" powered
            pkill -9 -f "python3 - $run/qmp.sock" 2>/dev/null
            serial_bridge_stop "$run"
            return 0
        fi
        # WEDGE GUARD: if the QMP kicker dies while the guest lives, TPM
        # completion BHs strand again and the boot wedges silently (live
        # evidence 2026-09-22). Respawn it.
        _qmp_kicker_start "$run"
        sleep 1
    done
    # timeout path: the elapsed lands on the record too (the kill below is
    # the wedge-recovery sweep, not a clean exit — the line says "killed")
    _qemu_boot_note "$run" killed
    qemu_kill "$run"
    return 124   # timeout
}

qemu_kill() {
    local run="$1" pid
    pid=$(cat "$run/qemu.pid" 2>/dev/null) || pid=""
    if [[ -n "$pid" ]]; then
        kill -9 "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    fi
    # pidfile-independent fallback: the run dir path is unique in qemu's argv,
    # so a lost/stale pid file can never leak a spinning KVM guest (a leaked
    # vCPU starves every later boot on this box — observed live 2026-09-22).
    # Scoped to THIS run dir, so a concurrent scenario's guest is never
    # touched; pkill never matches its own argv.
    pkill -9 -f "qemu-system-x86_64 .*$run/" 2>/dev/null
    # the QMP kicker's only reason to live was this qemu
    pkill -9 -f "python3 - $run/qmp.sock" 2>/dev/null
    serial_bridge_stop "$run"   # the bridge's only reason to live was qemu
    return 0
}

# qemu_console <run-dir> — path of the captured console log
qemu_console() { printf '%s\n' "$1/console.log"; }
