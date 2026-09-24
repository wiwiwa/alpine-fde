# tests/ — Alpine FDE test harness

Everything in `docs/Architecture.md` §10 (failure matrix) becomes an automated
scenario here (§12): QEMU/OVMF guests on a software TPM (swtpm), asserted via
serial-console sentinels pinned in `tests/sentinels-257.13.txt`. This tree is
the harness; `lib/` and `bin/` (repo root) hold the Alpine FDE tooling itself.

## Running

```sh
tests/env-check.sh          # exit 1 + MISSING list if a prereq is absent
tests/run-unit.sh           # runs tests/unit/*.sh in parallel (default: nproc), TAP-ish output
tests/run-unit.sh -j 2      # explicit concurrency (or ALPINE_FDE_TEST_JOBS)
tests/run-unit.sh 'pattern' # subset by filename glob, e.g. the swtpm smoke test
tests/run-e2e.sh            # harness self-test, then every registered scenario
tests/run-e2e.sh s01        # one scenario (runs the self-test first either way)
tests/run-e2e.sh -j 2 s01 s05   # up to 2 scenarios concurrently (see below)
```

`run-unit.sh` aggregates `ok` / `not ok` lines from each unit test; a test file
that exits nonzero without emitting a `not ok` counts as one failure (crash
detection). The contract is fail-closed on vacuous results: a file that exits
0 while emitting **zero assertions** is a failure (silent test rot), and a run
that observes no assertions at all (`1..0`) fails.

`run-e2e.sh` failure classes are distinct (§12):

- **exit 64** — environment/prerequisite failure (env-check, missing tools).
- **exit 65** — *harness-failure*: the infra self-test
  (`tests/unit/e2e_infra_smoke.sh`) runs BEFORE any scenario; if the fixtures,
  UKI builder, serial client or registry contract are broken, the run stops
  there. Infra breakage is never reported as a scenario failure.
- **exit 1** — scenario-class failures. A registered scenario id whose
  `tests/e2e/<id>-*.sh` file is absent is a FAILURE (status `missing`), not a
  pending pass, and a run in which zero scenarios execute is a failure — a
  harness that exits 0 on nothing is lying.

Runner contract details:

- **Accelerator (KVM autodetect)**: `tests/lib/qemu.sh` picks the QEMU
  accelerator from `ALPINE_FDE_ACCEL` (`kvm` | `tcg` | `auto`, default
  `auto`). `auto` uses KVM when `/dev/kvm` exists, is writable, AND a probe
  guest (`qemu-system-x86_64 -accel kvm -machine none -display none`) starts;
  otherwise TCG exactly as before (TCG argv is byte-identical — the
  `-accel kvm` flag is added only for KVM). OVMF + swtpm need no
  accel-specific flags and behave identically under both; numbers (seconds
  per scenario) will differ between the two. The choice is logged once per
  run with the greppable marker `qemu-accel: using <kvm|tcg> (...)` — the
  runner logs it before any scenario boots and lands it in the results JSON
  (`"accel"`); an explicit `ALPINE_FDE_ACCEL=kvm` that cannot be honored is a
  loud failure (env-class), never a silent TCG downgrade.
- **Parallel matrix (`-j N`)**: `-j N` / `-jN` / `--jobs=N` (or env
  `ALPINE_FDE_E2E_JOBS`, default 1 = sequential) runs up to N scenarios
  concurrently. Dependency phases: the state chain `s00 -> s00b` always runs
  FIRST and always sequentially, whatever the requested order; the remaining
  scenarios are independent state consumers (each snapshots its inputs into
  its own run dir at start) and share up to N worker slots. Failure
  semantics are unchanged: any scenario failure fails the run; budget,
  vacuous guard and exit-code classes apply per scenario exactly as in
  sequential mode.
- **Prune safety under `-j`**: with jobs > 1 the runner feeds EVERY existing
  `.runs` dir to the prune filter scenarios already honor
  (`ALPINE_FDE_PROTECT_DIRS`) — re-collected before each worker fork, so
  later workers also protect dirs earlier peers created. Peer run dirs are
  therefore never pruned mid-run without any scenario-side flag. (Dirs
  created after a peer's last fork are still safe: each scenario keeps its
  own dir the freshest via its touch loop and prunes only target dirs beyond
  the 2 newest by mtime.)
- **Results aggregation under `-j`**: each scenario result is written by its
  worker as a mktemp-unique JSON fragment (plus its captured output beside
  it); the runner aggregates the fragments into one `results-<ts>.json`
  preserving the sequential schema (`id`/`status`/`seconds`, plus the
  top-level `accel`/`jobs`). Row order is deterministic — registry order in
  the default selection, invocation order for named scenarios — never
  completion order. Console logs stay per-scenario in each run dir; the
  runner prints each scenario's output + completion line as workers finish
  (completion order), so lines never interleave.
- **Per-scenario budget**: every scenario runs under a wall-clock `timeout`
  (`ALPINE_FDE_SCENARIO_BUDGET`, default 7200 s). A killed scenario is
  recorded with the distinct status `timeout`, never as a plain failure.
  rc 124 is reported generically ("timeout-class status") — the runner never
  asserts the outer budget was exceeded, because a scenario's own internal
  timeout machinery can also end 124 (scenario-internal watchdogs exit 125
  to stay distinct).
- **Budget `--kill-after` caveat**: if the scenario's bash is stuck
  uninterruptible (D-state) for more than 30 s at kill time, the budget's
  `--kill-after=30` SIGKILL can orphan a `setsid`'d swtpm the scenario had
  started. The blast radius is bounded and environment-local: the fixture
  binds unixio sockets inside its own run dir, and a stale fixture is
  reclaimed by the next `swtpm_start`/`swtpm_cleanup_all`.
- **Vacuous guard**: a scenario that exits 0 without emitting at least one
  `ok` assertion line is recorded as `fail` (same silent-rot rule as
  `run-unit.sh`).
- **Protected run dirs**: run-e2e exports `ALPINE_FDE_PROTECT_DIRS` (colon-
  separated, the s00/s00b state dirs this invocation chains on — and, under
  `-j`, every existing `.runs` dir, see the parallel bullet above); every
  scenario's `.runs` prune filters those dirs out. The end-of-run G-T11b
  artifact scan reports rc-64 ("nothing to scan") as an explicit **SKIP** —
  it is never conflated with a key-material scan failure.

## Fixture pins (§3.1)

Fixture artifacts are SHA256-pinned in the harness; the harness, not the docs,
is the pin of record. The OVMF Secure Boot firmware is pinned in
`lib/qemu.sh` (checked by `env-check.sh` and again at every `qemu_run`):
CI building its own artifacts overrides with `ALPINE_FDE_OVMF_CODE_SHA256` /
`ALPINE_FDE_OVMF_VARS_SHA256` (path overrides: `OVMF_CODE` /
`OVMF_VARS_STOCK`). A local file matching neither pin is a loud failure naming
the mismatch.

## Files

| File | Purpose |
|---|---|
| `lib/assert.sh` | `assert_eq` `assert_ne` `assert_rc` `assert_contains` `assert_not_contains` `assert_file_exists`; TAP-ish lines; tallies in `$TESTS_PASS`/`$TESTS_FAIL` |
| `lib/swtpm-fixture.sh` | swtpm lifecycle: `swtpm_start`/`swtpm_stop`/`swtpm_reset`/`swtpm_ensure`/`swtpm_seed_pcrs`/`swtpm_pcrextend`/`swtpm_pcrread`/`swtpm_cleanup_all` |
| `run-unit.sh` | unit test runner |
| `env-check.sh` | prerequisite check (commands + SHA256-pinned OVMF secboot files) |
| `unit/swtpm_fixture_smoke.sh` | the fixture's own test |
| `unit/swtpm_proxy_data_plane.sh` | the SIMPLIFIED direct-socket wiring: host commands, a live qemu-style `SET_DATAFD` establishment straight into stock swtpm, and the between-boots EOF-exit + restart + zeroed-PCR discipline |
| `sentinels-257.13.txt` | versioned console-sentinel table (see below) |

## swtpm fixture: TCTI decision (verified empirically)

The fixture runs swtpm with **unixio sockets** and tpm2-tools 5.8 consumes it
with:

```
SWTPM_TCTI="swtpm:path=<state-dir>/sock"
```

Three details make this work — each one was hit and verified by hand:

1. **Control socket is `<server-path>.ctrl`.** tpm2-tss's swtpm TCTI derives
   the control-channel path by appending `.ctrl` to the configured path
   (literal `%s.ctrl` format string in `libtss2-tcti-swtpm.so`). The fixture
   therefore starts swtpm with `--server type=unixio,path=<dir>/sock` and
   `--ctrl type=unixio,path=<dir>/sock.ctrl`. (Naming the ctrl socket anything
   else fails with `Failed to connect to ... .ctrl`.)
2. **`--flags not-need-init,startup-clear` is required.** Without
   `startup-clear` the TPM never starts: every command fails with
   `TPM not initialized by TPM2_Startup or already initialized` and an explicit
   `tpm2_startup` is rejected (0x1c4). `startup-clear` makes swtpm issue
   TPM2_Startup itself; `not-need-init` covers the ctrl-channel INIT that
   tpm2-tools never sends.
3. **Fresh state = zeroed PCRs.** A wiped state dir (or `swtpm_reset`) gives
   `sha256:7 = 0x000…0`; `swtpm_pcrextend` mutates it for drift simulation.

No TCP fallback was needed — unixio works with the `.ctrl` naming. (For
reference: `swtpm:port=N` requires `--server type=tcp,port=N`.)

## swtpm 0.10.2 data-loop stall: root cause + harness avoidance (2026-09-23)

**Symptom.** Host-side tpm2 commands (fixture readiness probe, pcrread,
enroll steps) intermittently hung forever in `read()` on their data-socket
fd; `ss -xp` showed the client↔swtpm data connection ESTABLISHED with the
command (a 22-byte `TPM2_GetCapability`) sitting UNREAD in swtpm's receive
queue while swtpm idled in `poll()` at 0% CPU.

**Root cause (swtpm 0.10.2 design, gdb/poll-set-verified — swtpm mainloop.c
+ ctrlchannel.c, NOT a proxy bug):** swtpm serves exactly ONE client per
channel, and qemu's tpm-emulator realize sends `CMD_SET_DATAFD` carrying a
socketpair end (`tpm_emulator_prepare_data_fd`). swtpm's handler sets
`mlp->fd` + `MAIN_LOOP_FLAG_USE_FD`, after which `mainloop.c`:

1. polls the public data listener ONLY while `connection_fd.fd < 0` — so the
   public data socket is never accepted/serviced again while the SET_DATAFD
   fd is open (i.e. for the whole VM lifetime);
2. silently ORPHANS any already-accepted data client when SET_DATAFD lands:
   `connection_fd.fd` is overwritten by `mlp->fd` at the top of the next
   iteration — the old fd stays open, unread and unclosed forever (exactly
   the "ESTABLISHED, Recv-Q = 22 bytes unread" capture);

and the ctrl channel has the SAME single-client shape (`ctrlclntfd`;
`CTRL_SERVER_FD` is polled only while `ctrlclntfd < 0`). With the pre-v4
wiring, qemu's ctrl chardev held that slot for the whole VM lifetime, so the
TCTI's 5-byte `CMD_SET_LOCALITY` (sent before every host command) from any
other client was never accepted or answered — an identical-looking hang.

**Avoidance (harness-side; swtpm is unpatched):** the SIMPLIFIED (current)
design avoids the conflict structurally: swtpm binds the public sockets
DIRECTLY and the harness issues host TPM commands only BETWEEN boots (qemu
100% dead) — after each clean qemu exit (CMD_SHUTDOWN + chardev EOF, which
kills swtpm) `swtpm_ensure` restarts a fresh startup-clear instance. The
enroll flow is DIGEST-ANCHORED (the CLI compares the pcrsig entry's recorded
d7/d11 components against the baseline — no live TPM PCR read), so the
between-boot register reseeding is GONE; `swtpm_seed_pcrs <dir> <d7> <d11>`
stays as a fixture helper for the scenarios' own live reads and the drift
SIMULATIONS (s15/s18 pcrextend-by-design). The historical
broker — `swtpm-ctrl-proxy.py` (v4), which fronted BOTH planes and owned
swtpm's two single-client slots — is RETIRED AND DELETED; its design, for
reference:

- swtpm's real listeners move to the private `<dir>/swtpm.ctrl` and
  `<dir>/swtpm.sock`; the proxy binds the public `<dir>/sock.ctrl` and
  `<dir>/sock` that the TCTI and qemu_argv derive.
- **ctrl mux**: one upstream ctrl session; every client's request is
  serialized over it (FIFO) and answered by each command's fixed reply size
  (from swtpm's `ctrlchannel.c` / `tpm_ioctl.h`). `CMD_SHUTDOWN` stays
  absorbed (store-volatile, then success); `CMD_SET_DATAFD` is absorbed —
  the received fd becomes a guest data source and is NEVER forwarded, so
  swtpm never leaves listener mode and never orphans a client.
- **data broker**: one upstream data connection; every TPM frame (guest
  socketpair + host clients, framed by the BE32 size at `[2:6]`) is
  serialized over it.

Broker-era property (the broker is deleted): guest and host TPM traffic
interleaved safely, including during a live boot. Known broker limits:
state-blob migration
commands (`CMD_GET/SET_STATEBLOB`) are refused through the public paths.

Regression test: `tests/unit/swtpm_proxy_data_plane.sh` (the SIMPLIFIED
direct-socket wiring: host commands before a guest establishment; INIT +
SET_DATAFD DIRECT to stock swtpm; the guest data path; the between-boots
EOF-exit + restart discipline with zeroed PCRs).

Other fixture facts: swtpm is started detached via `setsid` (it dies with its
parent shell otherwise) with the pid in `<dir>/pid`; stop is graceful via
`swtpm_ioctl -s --unix <dir>/sock.ctrl` with SIGTERM/SIGKILL escalation;
`swtpm_reset` wipes the state dir so the next start is a brand-new TPM; a
trap-based `swtpm_cleanup_all` stops every fixture on exit. `swtpm_start`
blocks until a real TPM command (`tpm2_getcap`) succeeds, so tests start from
a deterministically ready TPM.

## Sentinel pinning

All e2e console greps consume `tests/sentinels-257.13.txt`
(`name<TAB>string`). Sentinel strings drift across systemd releases — the
policy-mismatch wording differs between 257.13 and 261 — so the table is
extracted from the exact pinned Debian artifacts, not transcribed from docs:

- `systemd-cryptsetup_257.13-1~deb13u1_amd64.deb`
- `libsystemd-shared_257.13-1~deb13u1_amd64.deb` (most policy/token messages
  live in `libsystemd-shared-257.so`, not the cryptsetup binary)
- `dracut_106-6_all.deb` + `dracut-core_106-6_amd64.deb`
  (`Entering emergency mode.` is echoed by dracut's
  `98dracut-systemd/dracut-emergency.sh`, not by systemd)

Each deb's sha256 and the binary where every string was byte-verified are
recorded in the table header. Regenerate by re-running the extraction
(`ar x` + tar + `strings`) against a new version and writing a new
`sentinels-<version>.txt`. The "reference the table, never inline" rule
scopes to UPSTREAM-drifting strings — anything printed by systemd,
cryptsetup, dracut or the OVMF firmware, whose wording changes between
releases. Harness-owned markers (`alpine-fde: UNSEALED`, `awaiting console
line`, `passphrase attempt 1/3`, …) are versioned by this harness itself and
stay inline by design.

## TPM device interface & firmware bring-up timing (tpm-crb, not tpm-tis)

The harness boots guests with **`-device tpm-crb,tpmdev=tpm0`** and a per-boot
**QMP kicker** process (`-qmp unix:<run>/qmp.sock` + a 15 ms `query-status`
poller, spawned and reaped by `qemu_run`/`qemu_kill`). This is a deliberate
workaround for a QEMU 11.1 event-loop defect, measured and verified
2026-09-22 (112/112 TPM commands, firmware phase ~8 min → ~10–15 s):

- **Root cause:** qemu dispatches async TPM completions via bottom-halves, but
  `aio_notify()` fails to wake the main loop out of `ppoll()` (glib poll
  path) — completions sit stranded until a periodic timer fires. The guest's
  firmware makes it worse: OVMF's TIS/CRB drivers poll status registers on a
  ~30 µs loop, and the resulting flood of KVM MMIO exits monopolizes the Big
  QEMU Lock.
- **Observed cost on tpm-tis:** ~1.2 s per firmware TPM command (completion
  waits out the timer), i.e. minutes of silent pre-BdsDxe bring-up per boot —
  `console.log` stays 0 bytes during it because OVMF's serial console only
  starts at BdsDxe. On tpm-crb without the kicker, the guest instead wedges
  forever polling `CRB_CTRL_START`. With tpm-crb + kicker: boots reach BdsDxe
  in ~10–15 s, deterministically.
- **What the firmware is doing in that phase** (edk2 `Tcg2Pei`/`Tcg2Dxe`):
  `TPM2_Startup`, self-test, FV/variable/image measurements into PCR 0/1/7,
  event-log creation — hundreds of small TPM operations, each paying the
  per-command penalty above. It recurs every boot by design: each boot uses
  fresh swtpm state (`startup-clear`) for per-boot zeroed PCRs.
- **Do not "fix" this by switching back to tpm-tis** or by removing the
  kicker/-qmp trio — that reinstates the minutes-long silent phase (tpm-tis)
  or the CRB wedge. The e2e_infra_smoke argv pin enforces the device choice.
- Measured command mix (3-boot window): GetCapability ×147, PCR_Extend ×97,
  PCR_Read ×85, GetRandom ×30, SelfTest ×4, CreatePrimary ×4; swtpm's own
  processing is 0.1–25 ms/op — the stalls are the host event loop, not swtpm.
  Raw traces: `tests/e2e/.runs/*/…/tpm/tpm-cmd.log`
  (`SWTPM_TIMED_LOG=1` adds per-line timestamps).

## Design: Scenario Consolidation & Lifecycle Pipelining (Approach 1)

### Motivation & Problem
In the original standalone scenario suite, over 50 QEMU/OVMF boots are executed because many independent test scripts (`s02`, `s08`, `s10`, `s11`, `s14`, `s15`, `s16`, `s17`) repeat an identical "Boot 1: baseline setup/enrollment" step before running their specific verification boot. Furthermore, positive lifecycle workflows (Install → Happy Boot → Kernel Upgrade → Rollback → Key Rotation) are fragmented across disparate scenarios that reconstruct disk and EFI state from scratch.

### Architectural Strategy
Approach 1 consolidates sequential, non-destructive lifecycle stages into unified, progressive pipelines while keeping destructive / fail-closed negative tamper tests isolated:

1. **Multi-Stage Positive Pipelines:** Each stage advances the system state in place, allowing the next stage to boot directly against the mutated disk, ESP, and TPM state without intermediate re-installations or redundant baseline boots.
2. **Fail-Closed Negatives Kept Standalone:** Negative tamper scenarios (`s03`-`s07`, `s09`-`s13`, `s18`) intentionally terminate in `poweroff -f` or firmware refusal, and continue to execute as standalone single-boot checks against a cached pristine image.

---

### Pipeline Specifications

#### 1. Core Lifecycle Pipeline (`s01-lifecycle-chain`)
Consolidates **`s00`**, **`s00b`**, **`s01`**, **`s14`**, **`s02`**, and **`s16`** into a continuous 4-boot end-to-end journey (reduced from 12+ boots):

* **Boot 1: Installation & Auto-Finalization (s00 + s00b + s01)**
  - Execute Stage-1 unattended install.
  - Reboot to disk; unseal via provisional TPM token (PCR 11).
  - OpenRC service `alpine-fde-finalize` executes: captures `audit --init` baseline, upgrades token to `{PCR 7, PCR 11}`, purges ephemeral install keyslot 2, and cleans up service.
  - Assert serial reaches `login:` with zero console keystrokes.
* **Boot 2: In-Guest Kernel Upgrade (s14)**
  - Inside the booted guest, run kernel upgrade trigger (`apk upgrade` / `alpine-fde ukictl build`).
  - Enter release key passphrase to sign new UKI (`linux-lts` newer version) and update the TPM seal.
  - Reboot to new kernel.
  - Assert new UKI unseals passwordlessly under the updated `{PCR 7, PCR 11}` measurement.
* **Boot 3: Kernel Rollback (s02)**
  - Inside the guest, select the previous retained kernel (`alpine-fde bootnext <old-entry>`).
  - Reboot to disk.
  - Assert the older retained UKI boots and unseals passwordlessly via its own release-signed `.pcrsig` without re-enrollment.
* **Boot 4: Release Key Rotation (s16)**
  - Rotate release signing key to K2 (`alpine-fde rotate` / re-sign retained UKIs).
  - Update UEFI NVRAM keys (`db += K2`, `dbx += K1`).
  - Reboot to disk.
  - Assert system boots and unseals cleanly under K2, confirming revocation of K1.

---

#### 2. Disaster Recovery & Drift Pipeline (`s15-recovery-chain`)
Consolidates **`s15`** (PCR 7 drift) and **`s17`** (TPM cleared) into a 3-boot recovery drill (reduced from 6 boots):

* **Boot 1: PCR 7 Drift Detection & Recovery**
  - Update firmware variables (`dbx` update) to induce PCR 7 drift.
  - Boot guest: assert TPM unseal is refused and drops to bounded recovery prompt.
  - Enter recovery passphrase (keyslot 0) to unlock volume.
  - In-guest: run `alpine-fde audit --accept` and `alpine-fde enroll-tpm` to re-baseline and update the token.
* **Boot 2: Verified Passwordless Recovery Boot**
  - Reboot system.
  - Assert disk unlocks automatically with zero keystrokes under the re-baselined PCR 7 state.
* **Boot 3: TPM Reset / Motherboard Replacement Drill**
  - Trigger `swtpm_reset` (simulate hardware TPM replacement/clear).
  - Boot guest: assert unseal refused under foreign/empty SRK → enter recovery passphrase → re-enroll TPM token.
  - Reboot: assert passwordless unseal restored.

---

### Expected Impact
* **Boot Reduction:** Cuts total QEMU boots across positive lifecycle scenarios by ~60% (saving 15–20 boots overall).
* **Test Fidelity:** Exercises real-world state transitions (upgrading an already-running system, rolling back, and recovering) rather than synthetic isolated boots.
* **Execution Time:** Decreases total e2e test suite runtime significantly while maintaining all invariant assertions (I1–I6).
