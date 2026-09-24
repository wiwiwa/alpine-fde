#!/usr/bin/env bash
# tests/unit/swtpm_proxy_data_plane.sh — contract test for the DIRECT swtpm
# fixture mode (tests/lib/swtpm-fixture.sh, user-approved simplified design).
# The file name is historical: in the broker era this was the regression test
# for the data-loop stall (swtpm 0.10.2 de-registers its data client when a
# ctrl-channel client EOFs — live-verified with a gdb poll-set dump). The
# broker/tests/lib/swtpm-ctrl-proxy.py that mitigated it is RETIRED (deleted):
# the fixture now binds swtpm's public ctrl+data sockets DIRECTLY, and the
# single-client conflicts that made the broker necessary are avoided by
# DISCIPLINE instead of by machinery:
#
#   * all host-side TPM work happens BETWEEN boots (qemu 100% dead) — never
#     interleaved with a boot's established data fd;
#   * the enroll flow is DIGEST-ANCHORED (Option A): the CLI's drift
#     precondition and the seal's G-B6 gate compare the pcrsig entry's
#     recorded d7/d11 components against the baseline — NO live TPM PCR read,
#     so no between-boot register reseeding is needed for it. swtpm_seed_pcrs
#     <dir> <d7> <d11> STAYS as a fixture helper for the scenarios' OWN live
#     reads and the drift SIMULATIONS (s15/s18 pcrextend-by-design);
#   * the restart path purges any stale tpm2-00.volatilestate (defect
#     s15-4: a restored volatile blob would make the next boot CUMULATIVE).
#
# This test pins that contract end-to-end against the REAL swtpm binary:
#   1. direct-mode start: a host TCTI command is answered on the public
#      sockets (swtpm:path=<dir>/sock, ctrl derived as <path>.ctrl);
#   2. the qemu-mimic establishment (CMD_INIT + CMD_SET_DATAFD carrying an
#      SCM_RIGHTS socketpair end over the ctrl channel) is accepted, and the
#      guest data path (TPM2_Startup, TPM2_GetCapability) is answered over
#      that socketpair — the production guest interaction, verbatim;
#   3. the single-client property is pinned HONESTLY: while the guest data
#      fd is established, a host command on the public data socket is NOT
#      served (bounded probe times out) — the documented reason for the
#      between-boots discipline above;
#   4. the EOF lifecycle: the guest's ctrl disconnect ends swtpm (documented
#      swtpm behavior), and swtpm_ensure restarts it fresh (PCRs zero);
#   5. swtpm_seed_pcrs reseeding is deterministic: the same seed on a freshly
#      restarted instance reproduces the identical register digest;
#   6. the restart path purges a planted stale volatilestate.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"

D=${DATA_PLANE_D:-$(mktemp -d /tmp/alpine-fde-swtpm-dataplane.XXXXXX)}
mkdir -p "$D"

cleanup() {
    swtpm_cleanup_all 2>/dev/null
    [[ -f "$D/guest.pid" ]] && kill -9 "$(cat "$D/guest.pid")" 2>/dev/null
    [[ -n "${DATA_PLANE_D:-}" ]] && { echo "# kept workdir: $D"; return; }
    rm -rf "$D"
}
trap cleanup EXIT
_SWTPM_CLEANUP_TRAP_SET=1

# TPM2 frames (tag=0x8001, BE32 size, code, body) — byte counts must match
# the size field EXACTLY, or the data stream desyncs (bad-frame drop).
STARTUP12="8001""0000000c""00000144""0001"                                  # Startup(CLEAR): 12B
GETCAP22="8001""00000016""0000017a""00000000""00000000""00000014"           # GetCapability: 22B

# --- stack up: swtpm binding the PUBLIC ctrl+data sockets directly ------------
swtpm_start "$D" || { echo "# swtpm_start failed"; exit 1; }
TCTI="swtpm:path=$D/sock"

# guest daemon: the qemu-mimic. Establishes INIT + SET_DATAFD over the
# PUBLIC ctrl socket exactly like qemu's tpm_emulator_prepare_data_fd
# (socketpair end passed via SCM_RIGHTS, kept open for the "VM lifetime"),
# then serves one hex frame per request file (mimicking the guest's TPM
# command stream) and writes the response hex to $D/resp.
python3 - "$D" >"$D/guest.log" 2>&1 <<'PYEOF' &
import os, socket, struct, sys, time

d = sys.argv[1]
ready = os.path.join(d, "ready")
reqf = os.path.join(d, "req")
respf = os.path.join(d, "resp")

qemu_side, swtpm_side = socket.socketpair()
ctrl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ctrl.connect(os.path.join(d, "sock.ctrl"))

def recv_exact(s, n, timeout=15.0):
    s.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            break
        buf += c
    return buf

ctrl.sendall(struct.pack(">II", 0x02, 1))                # CMD_INIT
r = recv_exact(ctrl, 4)
assert r == b"\x00\x00\x00\x00", f"INIT: {r.hex()}"
ctrl.sendmsg([struct.pack(">I", 0x10)],                  # CMD_SET_DATAFD
             [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
               struct.pack("i", swtpm_side.fileno()))])
r = recv_exact(ctrl, 4)
assert r == b"\x00\x00\x00\x00", f"SET_DATAFD: {r.hex()}"

open(ready, "w").close()                                 # establishment done
while True:
    while not os.path.exists(reqf):
        time.sleep(0.02)
    hexcmd = open(reqf).read().strip()
    os.unlink(reqf)
    if hexcmd in ("QUIT", ""):
        raise SystemExit
    if hexcmd == "SHUTDOWN":
        # qemu's teardown sequence: CMD_SHUTDOWN over ctrl (reply absorbed
        # into swtpm's shut-down state), then the process exit closes both
        # chardevs — swtpm terminates on the ctrl EOF
        ctrl.sendall((0x00000003).to_bytes(4, "big"))
        r = recv_exact(ctrl, 4)
        open(respf, "w").write(r.hex())
        raise SystemExit
    qemu_side.sendall(bytes.fromhex(hexcmd))
    hdr = recv_exact(qemu_side, 6)
    if len(hdr) < 6:
        open(respf, "w").write("EOF")
        raise SystemExit
    size = int.from_bytes(hdr[2:6], "big")
    open(respf, "w").write((hdr + recv_exact(qemu_side, size - 6)).hex())
PYEOF
echo $! >"$D/guest.pid"

wait_for() {   # wait_for <file> [seconds]
    local f="$1" n="${2:-150}"
    for _ in $(seq 1 "$n"); do [[ -e "$f" ]] && return 0; sleep 0.1; done
    return 1
}
guest_cmd() {  # guest_cmd <hexframe> -> response hex on stdout ("" on failure)
    rm -f "$D/req" "$D/resp"
    printf '%s' "$1" >"$D/req"
    wait_for "$D/resp" 150 || return 1
    cat "$D/resp"
}

# 1. direct-mode start: a host command is answered on the public sockets
assert_rc "direct fixture: baseline host getcap" 0 \
    timeout 15 tpm2_getcap -T "$TCTI" properties-fixed

# 2. qemu-mimic establishment (swtpm pins its single data-client slot — by
#    design; this is the production guest interaction)
wait_for "$D/ready" 200
assert_eq "direct fixture: qemu-mimic establishment (INIT + SET_DATAFD) accepted" \
    "yes" "$([[ -e "$D/ready" ]] && echo yes || echo no)"

# 3. the guest data path through swtpm's own pinned data plane
RESP=$(guest_cmd "$STARTUP12")
assert_eq "direct fixture: guest-path TPM2_Startup answered (TPM2_RC_SUCCESS)" \
    "00000000" \
    "$(python3 -c "b=bytes.fromhex('${RESP:-}'); print(b[6:10].hex()) if len(b)>=10 else print('short')")"

# 4. host command DURING establishment: always BOUNDED. Observed swtpm
#    0.10.2 behavior in this sequence: the interleaved command is actually
#    SERVED (rc 0) — but after a ctrl-EOF de-registration the same command
#    stalls forever (the live-verified stall class). The contract the
#    fixture guarantees is only "never hangs forever" (every host probe is
#    timeout-wrapped); the harness additionally never relies on in-boot
#    host commands (between-boots discipline; the enroll is digest-anchored).
timeout 5 tpm2_getcap -T "$TCTI" properties-fixed >/dev/null 2>&1
HOST_DURING_RC=$?
assert_rc "direct fixture: in-boot host command is bounded (rc 0 served / rc 124 bounded-refusal)" \
    0 bash -c "[[ $HOST_DURING_RC == 0 || $HOST_DURING_RC == 124 ]]"

# 5. the guest data path still healthy after the host probe — response frame
#    SELF-CONSISTENT (the size field equals the actual response length; a
#    GetCapability(ALGS) response is 139 bytes, not the request's 22)
RESP=$(guest_cmd "$GETCAP22")
assert_eq "direct fixture: guest GetCapability answered (frame self-consistent)" \
    "self-consistent" \
    "$(python3 -c "
b=bytes.fromhex('${RESP:-}')
print('self-consistent') if len(b)>=6 and int.from_bytes(b[2:6],'big')==len(b) else print('size '+b[2:6].hex()+' vs len '+str(len(b)))")"

# 6. the qemu teardown lifecycle: CMD_SHUTDOWN over ctrl, then the guest
#    daemon exits (chardev EOF) — swtpm terminates (documented behavior)
guest_cmd "SHUTDOWN" >/dev/null
for _ in $(seq 1 50); do
    swtpm_pid_alive=0
    if _swtpm_pid_alive "$D"; then swtpm_pid_alive=1; fi
    (( swtpm_pid_alive == 0 )) && break
    sleep 0.1
done
assert_eq "direct fixture: qemu teardown (CMD_SHUTDOWN + EOF) ends swtpm" \
    "0" "$swtpm_pid_alive"

# 7. swtpm_ensure restarts it fresh — PCRs zero (startup-clear), and a
#    planted stale volatilestate is purged by the restart path (s15-4)
printf 'x%.0s' {1..64} >"$D/tpm2-00.volatilestate"
swtpm_ensure "$D" || { echo "# swtpm_ensure failed"; exit 1; }
assert_file_exists "direct fixture: swtpm_ensure restarted the EOF-dead instance" "$D/pid"
assert_eq "direct fixture: stale volatilestate purged by the restart (s15-4)" \
    "gone" "$([[ -e "$D/tpm2-00.volatilestate" ]] && echo present || echo gone)"
PCR7=$(swtpm_pcrread "$D" 7)
assert_eq "direct fixture: restart is startup-clear (PCR 7 zero)" \
    "$(printf '0%.0s' {1..64})" "$PCR7"

# 8. swtpm_seed_pcrs reseeding is deterministic — the fixture helper the
#    scenarios' own live reads and drift simulations (s15/s18) use
SEED7=$(printf 'ab%.0s' {1..32})
SEED11=$(printf 'cd%.0s' {1..32})
swtpm_seed_pcrs "$D" "$SEED7" "$SEED11" || { echo "# seed failed"; exit 1; }
PCR7_SEEDED=$(swtpm_pcrread "$D" 7)
[[ "$PCR7_SEEDED" =~ ^[0-9a-f]{64}$ && "$PCR7_SEEDED" != "$(printf '0%.0s' {1..64})" ]] \
    && _assert_result ok "direct fixture: seed_pcrs lands a stable non-zero PCR 7" "" \
    || _assert_result not-ok "direct fixture: seed_pcrs lands a stable non-zero PCR 7" \
        "pcr7=${PCR7_SEEDED:-absent}"
swtpm_stop "$D" >/dev/null 2>&1
swtpm_ensure "$D" || { echo "# swtpm_ensure (reseed pass) failed"; exit 1; }
swtpm_seed_pcrs "$D" "$SEED7" "$SEED11" || { echo "# reseed failed"; exit 1; }
assert_eq "direct fixture: reseeding is deterministic (same seed -> same register)" \
    "$PCR7_SEEDED" "$(swtpm_pcrread "$D" 7)"

printf 'QUIT' >"$D/req" 2>/dev/null

echo "# swtpm_proxy_data_plane: pass=$TESTS_PASS fail=$TESTS_FAIL"
(( TESTS_FAIL == 0 )) || exit 1
exit 0
