# Bug Report: QEMU tpm-crb Hangs in OVMF Firmware During Command Completion

**Title:** `tpm-crb` event loop notification miss / BQL starvation causes indefinite firmware boot wedge under KVM
**Component:** QEMU (`hw/tpm/tpm_crb.c`, `backends/tpm/tpm_emulator.c`, `util/async.c`, `util/main-loop.c`)
**Environment:**
- QEMU: `11.1.1` (x86_64)
- Firmware: OVMF `edk2-ovmf 202608-1` (`OVMF_CODE.secboot.4m.fd`)
- TPM Emulator: `swtpm 0.10.2`
- Host OS: Linux (KVM enabled)

---

## 1. Summary

When booting a virtual machine with `-device tpm-crb,tpmdev=tpm0` under KVM and OVMF, the firmware boot intermittently wedges prior to BDS (Boot Device Selection) with a 0-byte console.

During the wedge:
- The guest vCPU is trapped in an infinite polling loop reading physical address `0xFED4004C` (`CRB_CTRL_START`) returning `0x1` millions of times.
- `swtpm` has already received, processed, and replied to the TPM command in ~1 ms.
- The QEMU background worker thread (`tpm_backend_worker_thread`) has finished executing the request, returned `ret = 0`, marked the thread-pool request `THREAD_DONE`, and enqueued a completion Bottom-Half (`pool->completion_bh`).
- However, QEMU's main event-loop thread remains asleep in `ppoll()` (`os_host_main_loop_wait()`). The completion callback `tpm_crb_request_completed` is never executed, and `CRB_CTRL_START` bit 0 (`Start`) is never cleared to `0`.

---

## 2. Minimal Reproduction (No OS / Disk Image Required)

The bug can be reproduced using only stock `qemu-system-x86_64`, `swtpm`, and the standard distribution OVMF firmware:

### Shell Script (`repro.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail

WORKDIR="/tmp/qemu-crb-repro"
rm -rf "$WORKDIR" && mkdir -p "$WORKDIR"
cd "$WORKDIR"

# Copy standard OVMF variable template
cp /usr/share/ovmf/x64/OVMF_VARS.4m.fd vars.fd

# 1. Start clean swtpm instance on unix control socket
swtpm socket \
    --tpm2 \
    --tpmstate dir="$WORKDIR" \
    --ctrl type=unixio,path="$WORKDIR/swtpm.ctrl" \
    --flags not-need-init,startup-clear &
SWTPM_PID=$!
sleep 0.5

# 2. Launch minimal QEMU with tpm-crb and trace MMIO accesses
timeout 20 qemu-system-x86_64 \
    -machine q35 -accel kvm -m 2048 -display none -nodefaults \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/ovmf/x64/OVMF_CODE.secboot.4m.fd \
    -drive if=pflash,format=raw,file="$WORKDIR/vars.fd" \
    -chardev socket,id=chrtpm,path="$WORKDIR/swtpm.ctrl" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-crb,tpmdev=tpm0 \
    -d trace:tpm_crb_mmio_write,trace:tpm_crb_mmio_read \
    -D "$WORKDIR/trace.log" || true

kill -9 "$SWTPM_PID" 2>/dev/null || true

echo "Total MMIO trace lines captured in 20 seconds:"
wc -l "$WORKDIR/trace.log"
echo "Last 10 MMIO trace entries (showing stuck polling loop):"
tail -n 10 "$WORKDIR/trace.log"
```

### Observed Output:
```text
Total MMIO trace lines captured in 20 seconds:
120606 /tmp/qemu-crb-repro/trace.log
tpm_crb_mmio_read CRB read 0x000000000000004c len:4 val: 0x1
tpm_crb_mmio_read CRB read 0x000000000000004c len:4 val: 0x1
tpm_crb_mmio_read CRB read 0x000000000000004c len:4 val: 0x1
...
```

---

## 3. Root Cause Analysis

### A. EDK2 Guest Polling (`SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2Ptp.c`)
When dispatching a TPM command in CRB mode:
1. `PtpCrbTpmCommand` writes `1` to `CRB_CTRL_START` (offset `0x4C`):
   ```c
   MmioWrite32 ((UINTN)&CrbReg->CrbControlStart, PTP_CRB_CONTROL_START);
   Status = PtpCrbWaitRegisterBits (
              &CrbReg->CrbControlStart,
              0,
              PTP_CRB_CONTROL_START,
              PTP_TIMEOUT_MAX  // 90 seconds
              );
   ```
2. `PtpCrbWaitRegisterBits` polls `MmioRead32(0xFED4004C)` in a tight loop with `MicroSecondDelay(30)`, waiting for bit 0 to clear to 0.

### B. QEMU Asynchronous Offloading (`hw/tpm/tpm_crb.c`)
1. On the write of `1` to `CRB_CTRL_START`, `tpm_crb_mmio_write` calls `tpm_backend_deliver_request()`.
2. `tpm_backend_deliver_request` enqueues the request into QEMU's AIO thread pool via `thread_pool_submit_aio(tpm_backend_worker_thread, s, tpm_backend_request_completed, s)`.
3. The background worker thread executes `tpm_backend_worker_thread()`, communicates with `swtpm` over the unix socket, and receives the response.

### C. The Deadlock: Missed AioContext Notification & BQL Contention
1. In `util/thread-pool.c`, when the worker thread finishes, it updates the request:
   ```c
   qatomic_set(&req->ret, ret);
   qatomic_store_release(&req->state, THREAD_DONE);
   qemu_bh_schedule(pool->completion_bh);
   ```
2. `qemu_bh_schedule()` calls `aio_bh_enqueue()` -> `aio_notify(ctx)` in `util/async.c`.
3. In `aio_notify(AioContext *ctx)`:
   ```c
   void aio_notify(AioContext *ctx) {
       qatomic_set(&ctx->notified, true);
       smp_mb();
       if (qatomic_read(&ctx->notify_me)) {
           event_notifier_set(&ctx->notifier);
       }
   }
   ```
4. **The Fault:** When QEMU's main thread is waiting in `os_host_main_loop_wait()` -> `qemu_poll_ns()` -> `ppoll()`, `ctx->notify_me` is **0** (because it is polled via GLib's `GSource` rather than `aio_poll()`). `aio_notify()` therefore **skips `event_notifier_set(&ctx->notifier)`**.
5. The main thread remains asleep in `ppoll()`.
6. Meanwhile, the guest vCPU spins in `PtpCrbWaitRegisterBits`, executing ~30,000 `KVM_EXIT_MMIO` exits per second. Every exit acquires and releases the Big QEMU Lock (BQL), starving any chance of asynchronous wakeups.
7. GDB inspection of the wedged QEMU process (`ThreadPoolElementAio` at `pool->head`) proves:
   - `state = 2` (`THREAD_DONE`)
   - `ret = 0` (`SUCCESS`)
   - The completion callback `tpm_backend_request_completed` -> `tpm_crb_request_completed` is stranded waiting for the main thread to wake up and dispatch `pool->completion_bh`.

---

## 4. Verification & Workarounds

### Workaround 1: Host-Side QMP Event Loop Kicker (Zero guest/QEMU code change)
Because the deadlock is purely caused by the main loop sleeping in `ppoll()`, sending any event/query to a chardev handled by the main loop wakes `ppoll()`, immediately flushing `pool->completion_bh`.

Adding a background helper that queries QMP (e.g. `query-status`) every 10–20 ms completely resolves the issue:
- **Result:** 112/112 TPM commands complete in ~1 ms each.
- Pre-BdsDxe boot completes cleanly in **under 15 seconds** with 0 wedges.

```python
# Minimal Python QMP kicker
import socket, json, time, sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
f = s.makefile("rw")
f.readline()
f.write(json.dumps({"execute": "qmp_capabilities"}) + "\n")
f.flush()
f.readline()

while True:
    f.write(json.dumps({"execute": "query-status"}) + "\n")
    f.flush()
    f.readline()
    time.sleep(0.02)
```

### Workaround 2: Use `tpm-tis`
`tpm-tis` does not experience permanent deadlock because its polling intervals are longer and periodic internal QEMU timers eventually wake `ppoll()`, though it suffers from high per-command latency (~1.2 s per command).
