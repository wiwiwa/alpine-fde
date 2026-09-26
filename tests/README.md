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
tests/run-e2e.sh            # harness self-test, then the default scenario set (see below)
tests/run-e2e.sh s05        # one scenario (runs the self-test first either way)
tests/run-e2e.sh -j 2 s03 s05   # up to 2 scenarios concurrently (see below)
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

- **Default selection**: with no ids on the command line, the runner selects
  every registered scenario whose registry status is `ready`, in registry
  order — currently 14 rows (the state chain `s00 -> s00b -> s01c -> s15c`,
  the surviving standalone scenarios, and the `s19`-`s22` multi-drive rows).
  The six pipeline-absorbed scenarios (`s01`, `s02`, `s14`, `s15`, `s16`,
  `s17`) and the seven drill-absorbed early-boot negatives (`s03`, `s05`,
  `s07`, `s09`, `s12`, `s13`, `s18`) are REMOVED: their files are deleted
  from `tests/e2e/` AND their registry rows are gone, so they cannot be
  selected or invoked — naming one is a loud `unknown` row. Their invariants
  are covered by the merged pipelines, the unified negative drill `s90`, and
  the zero-boot host suites (see "Retirement of the absorbed scenarios"
  below).
- **Guest shape**: every guest is `-machine q35 -m 2048 -smp $ALPINE_FDE_GUEST_SMP` (default 2): the in-guest phases under test (systemd, finalize, recovery drills) are multi-process, and a single vCPU serializes them on a multi-core host. Set `ALPINE_FDE_GUEST_SMP=1` for the historical shape.
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
  concurrently. Dependency phases: the state chain
  `s00 -> s00b -> s01c -> s15c` always runs FIRST and always sequentially,
  whatever the requested order (the two merged pipelines are chain members);
  the remaining
  scenarios are independent state consumers (each snapshots its inputs into
  its own run dir at start) and share up to N worker slots. Failure
  semantics are unchanged: any scenario failure fails the run; budget,
  vacuous guard and exit-code classes apply per scenario exactly as in
  sequential mode. (See "Base Image Sharing & Parallel Worker Isolation Architecture"
  below for how workers safely share the base image without mutation).
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
- **Step timing**: per-step cost is on the record, not just the per-scenario
  total. `tests/lib/stage-timing.sh` emits `# stage <label>: begin <epoch>`
  and `# stage <label>: done <seconds>s` lines into the scenario log (s00b's
  `run_stage` stages, s00's build/install/finalize legs); `tests/lib/qemu.sh`
  emits `# boot <run-dir-basename>: powered down after <seconds>s` on a clean
  guest exit, and `... killed after <seconds>s` on the timeout path (scenario
  stdout only — `console.log`'s format is the assertion substrate and never
  changes). Each bridge boot also mirrors the console into
  `<run>/console-timed.log`: the same lines, each prefixed with an epoch
  timestamp, for boot-phase hot-spot analysis. The runner parses the `done`
  lines (never an env var) into an OPTIONAL additive `stages` object
  (`{label: seconds}`) on each results row; rows without stage lines keep
  the exact previous schema. Hot-spot triage:
  `jq '.scenarios[] | {id, seconds, stages}' tests/e2e/.runs/results-<ts>.json`.
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

## Base Image Sharing & Parallel Worker Isolation Architecture

When running scenarios concurrently via `-j N`, multiple QEMU/OVMF guests execute simultaneously on the host. The test runner ensures deterministic isolation and fast startup by sharing a single golden enrolled base image without in-place mutation or cross-test interference:

```
[ s00 -> s00b ] (sequential bootstrap & enrollment)
       │
       ▼
[ tests/e2e/.cache/pristine-s00b/ ] ──(read-only golden state)──┐
       │ (exports ALPINE_FDE_E2E_STATE)                         │
       ├──────────────────────────┬─────────────────────────────┤
       ▼                          ▼                             ▼
Worker 1 (s01c)            Worker 2 (s05)                Worker N (s06)
- .runs/s01c-<ts>/         - .runs/s05-<ts>/             - .runs/s06-<ts>/
- private disk copy        - private disk copy           - private disk copy / tamper
- private swtpm sockets    - private swtpm sockets       - private swtpm sockets
- ephemeral QCOW2 overlay  - ephemeral QCOW2 overlay     - ephemeral QCOW2 overlay
```

### 1. Golden Base Image Generation (`s00b-enroll-cache.sh`)
- `s00b` completes the full in-guest enrollment under UEFI Secure Boot and writes the canonical state to `tests/e2e/.cache/pristine-s00b/`:
  - `disk.img`: The fully provisioned and enrolled LUKS2 root disk.
  - `vars-enrolled.fd`: Enrolled UEFI Secure Boot NVRAM variables (`PK`, `KEK`, `db`, `dbx`).
  - `tpm/tpm2-00.permall`: The non-volatile TPM state containing the Storage Root Key (SRK) seed.
  - `baseline.json`, `harness.efi`, and signing keys.
- The directory is verified against a SHA-256 manifest (`SHA256SUMS`).

### 2. State Propagation via `ALPINE_FDE_E2E_STATE`
- In `tests/run-e2e.sh`, the state chain `s00 -> s00b -> s01c -> s15c` runs first sequentially.
- Upon completion of `s00b`, the runner exports `ALPINE_FDE_E2E_STATE="$S00B_RUNDIR"`.
- When background worker subshells launch concurrently `( _run_one "$_i" "$_id" ) &`, each scenario inherits `$ALPINE_FDE_E2E_STATE` (or falls back to the SHA-verified `.cache/pristine-s00b/` directory).

### 3. Disk Sharing & Ephemeral QCOW2 Overlays (`tests/lib/overlay-disk.sh`)
To guarantee that parallel workers and repeated attempts never corrupt the base image or collide:
- **Private Working Directory:** Every worker operates inside its own timestamped directory (`tests/e2e/.runs/<scenario>-<ts>/`).
- **Read-Only Locking (`flock -s` / `LOCK_SH`):** `overlay_lock_acquire` opens every file in the backing chain with shared locks, preventing races against generator rebuilds.
- **Per-Boot Ephemeral Overlays:** Instead of booting raw disk files directly, QEMU boots a fresh QCOW2 overlay:
  ```sh
  qemu-img create -f qcow2 -b "$CANON_DISK" -F raw "$OVERLAY_BOOT"
  ```
- **Commit vs. Discard Discipline:**
  - *Positive lifecycle legs (e.g. `s01c` kernel upgrade / key rotation):* On success, changes are committed into the worker's private canonical disk (`qemu-img commit`), advancing the state for subsequent boots.
  - *Negative refusal/tamper/fail-closed legs (e.g. `s03`, `s06`, `s15c` drift refusal):* The overlay is discarded (`rm -f "$OVERLAY_BOOT"`), returning the disk state to pristine instantaneously.

### 4. TPM & Socket Concurrency Isolation
- **Hardware NV Seed Sharing (`tpm2-00.permall`):** Only `tpm2-00.permall` is copied into `$RUN/tpm/`. Because it preserves the NV seed, each worker's `swtpm` instance independently reproduces the exact same Storage Root Key (SRK) required to unseal the LUKS token.
- **Zero Volatile State (`_reanchor_tpm`):** Before every boot, `tpm2-00.volatilestate` is deleted and `swtpm` is started fresh with `startup-clear`, ensuring PCR 0 and PCR 7 start strictly at 0.
- **Private Sockets:** Each worker binds its own Unix domain sockets inside `$RUN/` (`tpm/sock`, `tpm/sock.ctrl`, `serial.sock`, `qmp.sock`), completely eliminating host port contention or inter-process interference.

## Design: Scenario Consolidation & Lifecycle Pipelining (Approach 1)

### Motivation & Problem
In the original standalone scenario suite, over 50 QEMU/OVMF boots are executed because many independent test scripts (`s02`, `s08`, `s10`, `s11`, `s14`, `s15`, `s16`, `s17`) repeat an identical "Boot 1: baseline setup/enrollment" step before running their specific verification boot. Furthermore, positive lifecycle workflows (Install → Happy Boot → Kernel Upgrade → Rollback → Key Rotation) are fragmented across disparate scenarios that reconstruct disk and EFI state from scratch.

### Architectural Strategy
Approach 1 consolidates sequential, non-destructive lifecycle stages into unified, progressive pipelines while keeping destructive / fail-closed negative tamper tests isolated:

1. **Multi-Stage Positive Pipelines:** Each stage advances the system state in place, allowing the next stage to boot directly against the mutated disk, ESP, and TPM state without intermediate re-installations or redundant baseline boots.
2. **Fail-Closed Negatives Consolidated Into One Drill (updated 2026-09-26):** the negative scenarios (`s03`-`s07`, `s09`-`s13`, `s18`) terminate in `poweroff -f` or firmware refusal. They now execute as ONE unified fail-closed drill (`s90`, 6 staged boot legs over a single shared enrolled base — see pipeline 3 below); their artifact-level verdicts moved into the zero-boot wt-bootmin host unit suites (`tests/unit/s0{3,13,18}_*_host.sh`), so the default registry no longer pays 7 scenarios' worth of duplicated bootstrap+refusal boots.

---

### Pipeline Specifications

#### 1. Core Lifecycle Pipeline — **IMPLEMENTED** (Wave-2 task 5b pilot)

**Status:** implemented and verified standalone in BOTH modes (2026-09-25,
KVM, 2 vCPUs): full-from-install `s01c` PASS (157 assertions, 6 launches,
~400 s wall) and from-cache PASS (122 assertions, 5 launches, ~275 s wall),
plus the full `-j 2` registry with the pipeline hoisted (results in
`tests/e2e/.runs/results-<ts>.json`).

**Id / file:** registry id **`s01c`** -> `tests/e2e/s01-lifecycle-chain.sh`
(resolved via the registry's script-name column). It consolidates the core of
**`s00`**, **`s00b`**, **`s01`**, **`s14`**, **`s02`**, and **`s16`** into one
progressive journey. Runner integration: `s01c` is a **chain member** — the
`-j` hoist list is `s00 -> s00b -> s01c` (sequential phase; later extended
to `s00 -> s00b -> s01c -> s15c` by pipeline 2), and `s01c` is
also a state consumer (`ALPINE_FDE_E2E_STATE`): when the s00 -> s00b chain
ran in the same invocation, the pipeline consumes that enrolled state and
skips its install legs. The superseded scenarios are REMOVED — files and
registry rows gone (see "Retirement of the absorbed scenarios" below).

**Boot map (as implemented — 4 logical stages, 6 physical launches):**

* **Boot 1 (full mode: installer launch + login launch; skip mode: login
  launch only)** — Stage-1 unattended install (embedded-kf0 passphrase
  unlock, pinned-artifact rootfs populate, §9.1 btrfs subvolumes, §3.3 size
  budget, G-T11b scans); host-side `audit --init` finalizes the baseline
  (real CLI, G-R1-guarded efivars fixture); the production CLI
  (`enroll-tpm`) seals the single finalized `{PCR 7, PCR 11}` Mechanism B
  token (keyslot 1, recovery slot 0 untouched); then the release UKI boots
  with stage=login on the payload drive and reaches `login:` with ZERO
  console keystrokes.
* **Boot 2 — kernel update (s14)** — UKI 6.4.0 built (the §8.3
  apk-trigger/kernel-hook stand-in), combined `{7,11}` entry re-signed over
  (same d7, new d11), `enroll-tpm` RETIRES the stale enrollment and stands
  the fresh seal in one run, and the new UKI boots + unseals PASSWORDLESSLY
  under the updated `{7,11}`. Plus the §10 "kernel update build failed" row:
  a keyless rebuild fails loudly and ships nothing.
* **Boot 3 — rollback (s02)** — an OLDER retained UKI (6.1.0, K1-signed,
  never enrolled) is selected (mtools default swap = the harness stand-in
  for bootnext) and boots + unseals passwordlessly via its OWN
  release-signed combined `.pcrsig` with zero enrollment and zero prompts;
  LUKS2 metadata is byte-identical across the boot. (The rollback target is
  a scenario-built older variant rather than the enrolled release UKI
  itself: the cached s00b release UKI carries the fed-session DEBUG SHELL
  seam, so a non-login boot of it ends at the debug shell, not a clean
  poweroff.)
* **Boot 4 — release-key rotation (s16)** — K2 at the ADR-16 floor,
  dual-sign append verified, NVRAM `db += K2` AND `dbx += K1` in one vars
  edit; the K2-built UKI boots under the rotated vars with the standing
  K1-signed entry -> the I3 gate refuses it -> bounded recovery loop (fed
  slot-0) -> the recovery boot LANDS the rotated PCR 7 (the digest-anchored
  K2 seal must be composed over the register the machine actually
  reproduces); after the K2 re-seal (retire + stand, token pins the K2
  public key) the final launch boots + unseals PASSWORDLESSLY under K2.

**R1/R2/R3 semantics (user-confirmed, binding):**

* **R1 progressive state** — ONE install at boot 1; the canonical state is
  the run dir's own `disk.img`/`esp.img`/`tpm/`/`vars-enrolled.fd`, and each
  positive leg boots a QCOW2 overlay that is COMMITTED back into the
  canonical disk on success (`qemu-img commit`), so every leg advances THE
  SAME disk in place.
* **R2 from-cache fast path** — mode resolution, in order:
  `ALPINE_FDE_PIPELINE_FULL=1` -> full-from-install (explicit opt);
  else a valid `ALPINE_FDE_E2E_STATE` -> state-consume (install legs
  skipped); else the SHA-verified `tests/e2e/.cache/pristine-s00b` ->
  cache-reuse (install legs skipped); else cold full-from-install. The mode
  is on the record in the log (`# pipeline mode: ...`) AND in the results
  row's `stages` object: `install-leg` exists ONLY in full mode; skip mode
  emits `cache-reuse`. The cache/state are consumed read-only (the base is
  snapshotted into the run dir first).
* **R3 overlay/LOCK_SH discipline** — every boot of every leg runs on a
  fresh QCOW2 overlay over the canonical disk (`tests/lib/overlay-disk.sh`:
  LOCK_SH on the whole backing chain for the boot's lifetime). Positive legs
  commit; failed attempts and the legs that must not persist anything
  (boot 3 rollback, boot 4's rotation-recovery) DISCARD the overlay.

**Not merged (intentionally, with the superseded scenario still covering
them):** s00b's dead-token I3-refusal fed-enroll session and drift-vote
fixture mechanics (the pipeline enrolls via the same production CLI
host-side; the dead-token recovery-path negative stays with s06/s13/s00b),
s01-as-in-tree's SB-off 3-strike tamper boot and s16's post-revoke
firmware-rejection boot (negative single-boot checks; the boot map has no
negative launch slot — s01/s16 are removed, s04 remains a default-set
scenario), and
s14's stale-seal refusal boot (the pipeline re-seals BEFORE first boot of
the new kernel; the refusal-mode invariant is exercised by b4's
recovery-rejection leg instead).

**Step timing:** leaf stage labels (the timing lib refuses nesting):
`install-leg`, `finalize-baseline`, `enroll-leg` (full mode only),
`cache-reuse` (skip modes), and `boot-<leg>` for every launch; host-side
build steps are `timeout`-bounded under the scenario's overall budget
(`ALPINE_FDE_PIPELINE_BUDGET`, default 5100 — set
`ALPINE_FDE_SCENARIO_BUDGET` above it for registry runs).

#### 2. Disaster Recovery & Drift Pipeline — **IMPLEMENTED** (Wave-2 task 5b)

**Id / file:** registry id **`s15c`** -> `tests/e2e/s15-recovery-chain.sh`
(the registry's script-name column resolves it; the `s15-` prefix itself
still resolves to `s15`'s own scenario). It consolidates **`s15`** (PCR 7
drift) and **`s17`** (TPM cleared) into one progressive recovery drill.
Runner integration: `s15c` is a **chain member** — the `-j` hoist list is
`s00 -> s00b -> s01c -> s15c` (sequential phase), and `s15c` is also a state
consumer (`ALPINE_FDE_E2E_STATE`): when the chain ran in the same invocation
(or the SHA-verified `pristine-s00b` cache is valid), the producer legs are
skipped and the drill replays against the standing enrolled seal. The
superseded scenarios STAY in the tree and invocable by name, but are RETIRED
from the default selection (see "Retirement of the absorbed scenarios"
below). Contract suite:
`tests/unit/s15c_recovery_chain_contract.sh` (coverage table + wiring +
structure pins); the runner-side phase pins live in
`tests/unit/run_e2e_parallel_contract.sh`.

**Boot map (as implemented — 5 physical launches, 4 in the skip modes):**

* **b0-producer (full mode only)** — baseline boot against a token-less
  volume: the §8.2 hook's bounded recovery loop is the only way in, the
  CORRECT slot-0 passphrase is fed prompt-synchronized -> UNSEALED
  (s15/s17's boot 1); host-side the finalized baseline is stamped and the
  production CLI (`enroll-tpm`) seals the combined `{PCR 7, PCR 11}` token
  (keyslot 1, recovery slot 0 untouched).
* **host: §9.4 detection drill** — live PCR 7 drift synthesized host-side
  (`swtpm_pcrextend`); the real CLI `audit` exits 1 with a `pcr7 DRIFT`
  line, `audit --accept --yes` re-baselines, a follow-up audit is clean and
  `last-audit.json` records `result: ok`.
* **b1-pcr7-drift (refusal; overlay discarded)** — dbx-updated vars
  (`virt-fw-vars --add-dbx-cert`, the §9.4 boot-layer drift): the firmware
  measures a different PCR 7, the stale seal refuses (`unseal_seal_refused`,
  I3 gate passes — the signature is NOT the defect), the bounded loop reads
  3 WRONG answers -> 3-strike fail-closed `poweroff -f`, never unlocked, no
  emergency shell, PCR 11 untouched (tamper scoping), guest exits by hook
  poweroff (IN-08). Tamper scoping remap: in the skip modes the refusal boot
  is the CACHED UKI (no baseline console exists), so the full mode's
  producer-console PCR 11 equality is carried by the b3-vs-b2 pair instead,
  and b1 asserts the early PCR 11 reading present + non-zero.
* **host: recovery-reseal-1** — wipe the stale enrollment (token +
  luksKillSlot), re-stamp the baseline to the DRIFTED boot-layer d7, re-seal
  over (drifted d7, UNCHANGED enter-initrd d11) via the production CLI — no
  volume-key re-encryption. Skip mode builds the seam-free release UKI here
  (the cached release UKI carries the fed-session DEBUG SHELL seam, so it
  can only serve the refusal leg, whose hook powers off inside its own
  invocation) and swaps the ESP default to it.
* **b2-rebaselined (passwordless; overlay committed)** — zero-input token
  unlock under the re-sealed token on the drifted-but-real PCR 7; the
  booted PCR 7 equals the drifted d7 the seal was composed over; G-T13
  signed prediction asserted.
* **b3-tpm-clear (refusal; overlay discarded)** — `swtpm_reset` wipes ALL
  TPM state (fresh SRK, PCR 7 asserted zero): the firmware re-measures the
  same vars, the I3 gate passes, but the sealed blob cannot load under the
  fresh SRK -> the same fail-closed 3-strike refusal drill; PCR 7
  re-measured to the same value and PCR 11 unchanged vs b2 (same UKI, same
  phase extend). The reset is the pipeline's ONE deliberate persistent TPM
  mutation (it is the scenario's subject); recovery-reseal-2 restores a
  working enrollment under the new SRK (fresh SRK, same d11, no
  re-encryption) before the final leg.
* **b4-restored (passwordless; overlay committed)** — zero-input unseal
  restored on the fresh SRK under the re-measured PCR 7; G-T13 prediction
  asserted; the pipeline ends on a healthy re-enrolled state.

**Recovery-drill shape (deliberate deviation from the 3-boot sketch):** the
sketch collapsed the two refusal legs into one in-guest recovery unlock
("enter recovery passphrase, run `audit --accept` + `enroll-tpm` in-guest").
The absorbed scenarios' recovery drill is FAIL-CLOSED in-guest (3 WRONG
answers -> 3-strike `poweroff -f`) with the recovery as a HOST-side operator
step, and collapsing the refusal legs would drop the 3-strike / fail-closed
assertions — so the implemented plan keeps both refusal boots and folds the
in-guest correct-passphrase recovery unlock into b0-producer (exactly where
s15/s17 exercise it). Cost: 5 launches (4 from-cache) vs the standalone
s15 + s17's 6 boots + duplicated fixture/enroll/audit work.

**R1/R2/R3 semantics:** as pipeline 1 (one canonical disk advanced in place
via committed overlays; refusal legs and failed attempts discard their
overlays; `ALPINE_FDE_PIPELINE_FULL=1` / `ALPINE_FDE_E2E_STATE` /
`pristine-s00b` / cold mode resolution recorded in the log and the `stages`
object). The §9.4 drill's `pcrextend` mutates only the fixture TPM's
volatile PCRs — every boot re-anchors to a zeroed register first
(`_reanchor_tpm`), so nothing of it leaks into any boot.

**Step timing:** leaf stage labels — full mode emits `producer-leg`,
`finalize-baseline`, `drift-detect`, `recovery-reseal-1`, `tpm-clear`,
`recovery-reseal-2`; skip mode emits `cache-reuse` instead of the first two;
every launch emits `boot-<leg>`; `ALPINE_FDE_PIPELINE_BUDGET` (default
2400) bounds the scenario internally — set `ALPINE_FDE_SCENARIO_BUDGET`
above it (recommend 2700) for full-from-install registry runs.

---

#### 3. Unified Early-Boot Negative Drill — **IMPLEMENTED** (queue item 30, 2026-09-26)

**Id / file:** registry id **`s90`** -> `tests/e2e/s90-negative-drill.sh`
(appended at runtime, NOT a literal table row — the literal table stays the
pure §10/§12 matrix). It consolidates the VM-only console residuals of the
seven early-boot negative scenarios into 6 staged fail-closed boot legs over
ONE shared enrolled base:

* **leg1-drift** — SB-on PCR 7 drift (dbx update, SB stays 1): the guard
  passes, the `{7,11}` token's PolicyPCR refuses the stale seal term,
  refusal-first ordering, 3 wrong answers -> 3-strike fail-closed `poweroff
  -f` (s12 boot B's negative; s15's refusal vector).
* **leg2-loader-opt** — a release-signed UKI VARIANT whose `.cmdline` carries
  one extra word, booted with the STALE clean `.pcrsig` payload: the stub
  measures the tampered cmdline into PCR 11, the policy session refuses,
  3-strike (s07; the host-side divergence proof rides along).
* **leg3-nopcrsig** — a release-signed UKI built WITHOUT the PCR-signing step
  (ADR-8 signing-key-absent): "pcrsig payload MISSING", the token path never
  arms, 3-strike (s03 flavor 1).
* **leg4-wiped** — the standing enrollment wiped host-side (token + its
  keyslots, raw disk copy): `unseal_token_missing`, NO self-heal (I6),
  3-strike (s03 flavor 2).
* **leg5-foreign-sig** — the `.pcrsig` re-signed by a FOREIGN key (same pol
  bytes, only the signer moved): the I3 openssl gate refuses BEFORE any TPM
  session, 3-strike (s18 control 1 — the gate-refusal class representative).
* **leg6-sboff-da** — SB-off vars: the ADR-20 PRE-UNSEAL GUARD blocks at the
  hook's first step (no TPM op, no prompt; parked on Enter -> qemu killed BY
  PID), with the DA-locked TPM drilled host-side (armed -> enforced before ->
  STILL enforced after; G-T15: the guest consumed nothing) (s05 + s09 + s12
  boot A).

**Absorption bookkeeping:** every absorbed assertion is either in the drill
(leg-pinned), covered ZERO-BOOT by a wt-bootmin host suite
(`tests/unit/s03_stale_enrollment_host.sh`, `s13_token_tamper_host.sh`,
`s18_foreign_pcrsig_host.sh` — the artifact-level verdicts: G-B6 gate
refusals, token-tamper primitives, foreign-signer recipe controls), or
DROPPED WITH THE REASON NAMED. The disposition table lives in
`tests/unit/s90_negative_drill_contract.sh` (the s15c-pattern contract suite,
which also pins the boot plan and the runner wiring). Net effect: the seven
absorbed scenarios' ~16–23 boots (standalone, each with its own
bootstrap/enroll tail) become 6 drill legs (+1 bootstrap boot only when no
state chain/cache exists).

**R1/R2/R3 semantics:** as the pipelines (the enrolled base is snapshotted
once into a master dir that is never booted; read-mostly legs run discarded
QCOW2 overlays; the one mutating leg runs a raw copy; `ALPINE_FDE_E2E_STATE`
-> the SHA-verified `pristine-s00b` cache -> self-bootstrap, with the mode on
the record as `# drill base:`); the TPM is re-anchored (fresh, zeroed,
settled) before every leg; one leaf stage per leg for the Step timing.

---

### Retirement of the absorbed scenarios

With both pipelines merged and registry-proven green (the lifecycle
pipeline `s01c` and the recovery pipeline `s15c` each verified standalone in
full-from-install and from-cache modes, plus in the `-j` registry with the
chain hoisted), the six standalone scenarios whose boots they absorbed are
REMOVED: `s01`, `s02`, `s14`, `s16` (absorbed by `s01c`) and `s15`, `s17`
(absorbed by `s15c`). The 2026-09-26 drill consolidation removed seven more:
`s03`, `s05`, `s07`, `s09`, `s12`, `s13`, `s18` (absorbed by the `s90`
unified negative drill + the zero-boot wt-bootmin host suites). REMOVED means the scenario FILES are deleted from
`tests/e2e/` and the registry ROWS are dropped from `tests/run-e2e.sh` —
not merely deselected. The no-args default run stops paying their duplicated
fixture/enroll/audit boots — the pipelines assert the same invariants
progressively against one advancing disk state — and a targeted run of a
removed id is no longer possible: naming one yields a loud `unknown` row
(a removed id is unregistered, never silently skipped). Registry bookkeeping
stays honest by the same token: the removed ids left the runner's
state-consumer set (`s01` was the only one in it — the other five bootstrap
in-scenario), the registry-completeness pins in
`tests/unit/e2e_infra_smoke.sh` cover every SURVIVING row (16-row literal
floor), and the default-set pins (contents, count, removed-ids-absent) live
in `tests/unit/run_e2e_parallel_contract.sh`.

---

### Expected Impact
* **Boot Reduction:** Cuts total QEMU boots across positive lifecycle scenarios by ~60% (saving 15–20 boots overall).
* **Test Fidelity:** Exercises real-world state transitions (upgrading an already-running system, rolling back, and recovering) rather than synthetic isolated boots.
* **Execution Time:** Decreases total e2e test suite runtime significantly while maintaining all invariant assertions (I1–I6).
