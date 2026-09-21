# tests/ — Debian FDE test harness

Everything in `docs/Architecture.md` §10 (failure matrix) becomes an automated
scenario here (§12): QEMU/OVMF guests on a software TPM (swtpm), asserted via
serial-console sentinels pinned in `tests/sentinels-257.13.txt`. This tree is
the harness; `lib/` and `bin/` (repo root) hold the Debian FDE tooling itself.

## Running

```sh
tests/env-check.sh          # exit 1 + MISSING list if a prereq is absent
tests/run-unit.sh           # runs tests/unit/*.sh in parallel (default: nproc), TAP-ish output
tests/run-unit.sh -j 2      # explicit concurrency (or DEBIAN_FDE_TEST_JOBS)
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
  accelerator from `DEBIAN_FDE_ACCEL` (`kvm` | `tcg` | `auto`, default
  `auto`). `auto` uses KVM when `/dev/kvm` exists, is writable, AND a probe
  guest (`qemu-system-x86_64 -accel kvm -machine none -display none`) starts;
  otherwise TCG exactly as before (TCG argv is byte-identical — the
  `-accel kvm` flag is added only for KVM). OVMF + swtpm need no
  accel-specific flags and behave identically under both; numbers (seconds
  per scenario) will differ between the two. The choice is logged once per
  run with the greppable marker `qemu-accel: using <kvm|tcg> (...)` — the
  runner logs it before any scenario boots and lands it in the results JSON
  (`"accel"`); an explicit `DEBIAN_FDE_ACCEL=kvm` that cannot be honored is a
  loud failure (env-class), never a silent TCG downgrade.
- **Parallel matrix (`-j N`)**: `-j N` / `-jN` / `--jobs=N` (or env
  `DEBIAN_FDE_E2E_JOBS`, default 1 = sequential) runs up to N scenarios
  concurrently. Dependency phases: the state chain `s00 -> s00b` always runs
  FIRST and always sequentially, whatever the requested order; the remaining
  scenarios are independent state consumers (each snapshots its inputs into
  its own run dir at start) and share up to N worker slots. Failure
  semantics are unchanged: any scenario failure fails the run; budget,
  vacuous guard and exit-code classes apply per scenario exactly as in
  sequential mode.
- **Prune safety under `-j`**: with jobs > 1 the runner feeds EVERY existing
  `.runs` dir to the prune filter scenarios already honor
  (`DEBIAN_FDE_PROTECT_DIRS`) — re-collected before each worker fork, so
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
  (`DEBIAN_FDE_SCENARIO_BUDGET`, default 7200 s). A killed scenario is
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
- **Protected run dirs**: run-e2e exports `DEBIAN_FDE_PROTECT_DIRS` (colon-
  separated, the s00/s00b state dirs this invocation chains on — and, under
  `-j`, every existing `.runs` dir, see the parallel bullet above); every
  scenario's `.runs` prune filters those dirs out. The end-of-run G-T11b
  artifact scan reports rc-64 ("nothing to scan") as an explicit **SKIP** —
  it is never conflated with a key-material scan failure.

## Fixture pins (§3.1)

Fixture artifacts are SHA256-pinned in the harness; the harness, not the docs,
is the pin of record. The OVMF Secure Boot firmware is pinned in
`lib/qemu.sh` (checked by `env-check.sh` and again at every `qemu_run`):
CI building its own artifacts overrides with `DEBIAN_FDE_OVMF_CODE_SHA256` /
`DEBIAN_FDE_OVMF_VARS_SHA256` (path overrides: `OVMF_CODE` /
`OVMF_VARS_STOCK`). A local file matching neither pin is a loud failure naming
the mismatch.

## Files

| File | Purpose |
|---|---|
| `lib/assert.sh` | `assert_eq` `assert_ne` `assert_rc` `assert_contains` `assert_not_contains` `assert_file_exists`; TAP-ish lines; tallies in `$TESTS_PASS`/`$TESTS_FAIL` |
| `lib/swtpm-fixture.sh` | swtpm lifecycle: `swtpm_start`/`swtpm_stop`/`swtpm_reset`/`swtpm_pcrextend`/`swtpm_pcrread`/`swtpm_cleanup_all` |
| `run-unit.sh` | unit test runner |
| `env-check.sh` | prerequisite check (commands + SHA256-pinned OVMF secboot files) |
| `unit/swtpm_fixture_smoke.sh` | the fixture's own test |
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
releases. Harness-owned markers (`debian-fde: UNSEALED`, `awaiting console
line`, `passphrase attempt 1/3`, …) are versioned by this harness itself and
stay inline by design.
