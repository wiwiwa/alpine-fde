#!/usr/bin/env bash
# tests/lib/qemu.sh — guest runner for the Debian FDE e2e harness (TCG by
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
#     * <extra-drives> (G-HW1, opt-in): newline-separated image paths appended
#       as virtio drives AFTER the pcrsig payload slot — the N-disk mechanism
#       for multi-drive scenarios. Empty/absent (every current caller) keeps
#       the historical 2+1-positional argv byte-identical.
#   qemu_argv <run-dir> <esp.img> <disk.img> <vars.fd> <swtpm-dir> [pcrsig.img] \
#             [extra-drives]
#     * pure-argv seam: prints (one per line) exactly the argv qemu_run execs.
#       No pin checks, no sockets, no accelerator probe — unit-testable (the
#       once-per-process accelerator choice applies: unset => TCG, no -accel).
#   qemu_wait <run-dir> <timeout-s>   wait for exit (0 = powered off cleanly)
#   qemu_kill <run-dir>               hard kill (timeout path)
#
# Drive map (fixed contract with the harness /init): vda=ESP, vdb=LUKS disk,
# vdc=optional pcrsig payload, vdd, vde, … = extra-drives list order.
#
# EMPIRICAL (verified this sandbox): the tpmdev-emulator chardev must point at
# swtpm's CONTROL socket (<state-dir>/sock.ctrl — QEMU speaks the swtpm ctrl
# protocol on it). Pointing it at the server socket ("sock") deadlocks the
# firmware in its TPM handshake before ANY console output — 0 serial bytes,
# silent hang. (unixio equivalent of the control-port=server+1 TCP quirk.)

if [[ -n "${_DEBIAN_FDE_QEMU_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_QEMU_SOURCED=1

QEMU_TIMEOUT="${QEMU_TIMEOUT:-420}"

# --- accelerator selection (/dev/kvm is REQUIRED) ---------------------------------
# DEBIAN_FDE_ACCEL: kvm (default) | tcg. KVM is a hard requirement for e2e
# (§12): an unusable /dev/kvm is a loud fail-closed error — never a silent TCG
# downgrade (TCG boots blow the per-scenario time budget and corrupt the serial
# console; the explicit escape hatch below exists for exactly that reason).
# DEBIAN_FDE_ACCEL=tcg is honored verbatim as the explicitly-requested dev
# opt-out; any other value (including the old silent 'auto') is rejected. The
# decision is made once per process and logged with a greppable `qemu-accel:`
# marker; every qemu_run in the process then uses the chosen accelerator (the
# `-accel kvm` flag is added ONLY for KVM, so TCG invocations stay
# byte-identical). OVMF + swtpm need no accel-specific flags and work
# identically under both.
# DEBIAN_FDE_KVM_PROBE_TIMEOUT (seconds, default 10) bounds the KVM probe guest
# below: the probe is SELF-TERMINATING (QMP `quit` over stdio), so the bound is
# only a hang guard — a refusal costs ~0.1s on a broken-KVM host, never a
# 30s idle-kill.
DEBIAN_FDE_ACCEL="${DEBIAN_FDE_ACCEL:-kvm}"
DEBIAN_FDE_KVM_PROBE_TIMEOUT="${DEBIAN_FDE_KVM_PROBE_TIMEOUT:-10}"

_qemu_accel=""

# _qemu_kvm_probe_run — self-terminating probe guest. Drives QMP over stdio:
# `qmp_capabilities` then `quit` make qemu exit as soon as KVM init is proven,
# instead of idling until an external killer arrives (the old `timeout 30 …`
# form paid a 30s hang on every refusal). Success ONLY = KVM-accelerated qemu
# (a lone `-accel kvm` never falls back to TCG) starts AND exits cleanly within
# the DEBIAN_FDE_KVM_PROBE_TIMEOUT bound; timeout-kill, nonzero exit, or a
# missing binary are all "not working". VERIFIED on this sandbox: 0.115s, rc 0,
# query-kvm -> {"enabled": true}; with stdin at EOF qemu would idle, hence the
# piped quit AND the timeout guard (belt and braces).
_qemu_kvm_probe_run() {
    printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}' \
        | timeout "${DEBIAN_FDE_KVM_PROBE_TIMEOUT}" \
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
    local mode="${DEBIAN_FDE_ACCEL:-kvm}" why
    case "$mode" in
        tcg)
            _qemu_accel="tcg"; why="requested (DEBIAN_FDE_ACCEL=tcg)" ;;
        kvm)
            if _qemu_kvm_ok; then
                _qemu_accel="kvm"; why="requested (DEBIAN_FDE_ACCEL=kvm)"
            else
                echo "qemu-accel: KVM is REQUIRED for e2e but /dev/kvm is unusable here" >&2
                echo "  (need /dev/kvm, writable, and a working probe:" >&2
                echo "   qemu-system-x86_64 -accel kvm -machine none -display none" >&2
                echo "   -qmp stdio, bounded by DEBIAN_FDE_KVM_PROBE_TIMEOUT" >&2
                echo "   =${DEBIAN_FDE_KVM_PROBE_TIMEOUT}s: success only on a clean exit)" >&2
                echo "  enable KVM (modprobe kvm_intel / kvm_amd) or run on KVM-capable" >&2
                echo "  hardware; explicitly set DEBIAN_FDE_ACCEL=tcg to opt out anyway" >&2
                return 1
            fi
            ;;
        auto)
            echo "qemu-accel: DEBIAN_FDE_ACCEL=auto removed — KVM is required by default;" >&2
            echo "  set DEBIAN_FDE_ACCEL=tcg explicitly to request software emulation" >&2
            return 1
            ;;
        *)
            echo "qemu-accel: invalid DEBIAN_FDE_ACCEL='$mode' (want kvm|tcg)" >&2
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
#   DEBIAN_FDE_OVMF_CODE_SHA256          expected sha256 of the code image
#   DEBIAN_FDE_OVMF_VARS_SHA256          expected sha256 of the vars template
DEBIAN_FDE_OVMF_CODE_SHA256_DEFAULT="cc150d941d4f1d39e596dedc545384a66ccfb3c9ba5cf9bc3a54d8d427d4d88f"
DEBIAN_FDE_OVMF_VARS_SHA256_DEFAULT="5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"

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
    _ovmf_pin_one "$(_qemu_ovmf_code)" DEBIAN_FDE_OVMF_CODE_SHA256 \
        "$DEBIAN_FDE_OVMF_CODE_SHA256_DEFAULT" || rc=1
    _ovmf_pin_one "$(_qemu_ovmf_vars)" DEBIAN_FDE_OVMF_VARS_SHA256 \
        "$DEBIAN_FDE_OVMF_VARS_SHA256_DEFAULT" || rc=1
    return "$rc"
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
    local sock="$run/serial.sock"
    printf '%s\n' \
        -machine q35 -m 2048
    if [[ "$_qemu_accel" == "kvm" ]]; then
        printf '%s\n' -accel kvm
    fi
    printf '%s\n' \
        -display none -nodefaults \
        -drive "if=pflash,format=raw,readonly=on,file=$(_qemu_ovmf_code)" \
        -drive "if=pflash,format=raw,file=$vars" \
        -drive "file=$esp,format=raw,if=virtio" \
        -drive "file=$disk,format=raw,if=virtio" \
        -chardev "socket,id=chrtpm,path=$swtpmdir/sock.ctrl" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -chardev "socket,id=ser0,path=$sock,server=on,wait=off,logfile=$run/console.log" \
        -serial chardev:ser0
    if [[ -n "$pcrsig" ]]; then
        printf '%s\n' "-drive" "file=$pcrsig,format=raw,if=virtio"
    fi
    local d
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        printf '%s\n' "-drive" "file=$d,format=raw,if=virtio"
    done <<<"$extra"
    return 0
}

qemu_run() {
    local run="$1" esp="$2" disk="$3" vars="$4" swtpmdir="$5" pcrsig="${6:-}" extra="${7:-}"
    local sock="$run/serial.sock"
    ovmf_pin_check || return 1
    _qemu_accel_choose || return 1
    rm -f "$sock" "$run/console.log" "$run/qemu.pid"
    local -a args=()
    mapfile -t args < <(qemu_argv "$run" "$esp" "$disk" "$vars" "$swtpmdir" \
        "$pcrsig" "$extra")
    qemu-system-x86_64 "${args[@]}" >"$run/qemu.stdout" 2>"$run/qemu.stderr" &
    echo $! >"$run/qemu.pid"
    return 0
}

qemu_wait() {
    local run="$1" timeout="$2" pid
    pid=$(cat "$run/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout))
    while ((SECONDS < deadline)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 1
    done
    qemu_kill "$run"
    return 124   # timeout
}

qemu_kill() {
    local run="$1" pid
    pid=$(cat "$run/qemu.pid" 2>/dev/null) || return 0
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    return 0
}

# qemu_console <run-dir> — path of the captured console log
qemu_console() { printf '%s\n' "$1/console.log"; }
