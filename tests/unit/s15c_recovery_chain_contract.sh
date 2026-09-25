#!/usr/bin/env bash
# tests/unit/s15c_recovery_chain_contract.sh — contract suite for the merged
# recovery pipeline (registry id **s15c** -> tests/e2e/s15-recovery-chain.sh,
# Wave-2 task 5b; tests/README.md "Scenario Consolidation & Lifecycle
# Pipelining (Approach 1)", pipeline 2). HERMETIC: no qemu, no swtpm, no
# boots — the scenario artifact and the runner wiring are pinned by content.
#
# Pinned (mirrors the s01c pilot's contract shape — the runner-side phase pins
# live in tests/unit/run_e2e_parallel_contract.sh, the scenario-side pins here):
#   1. Scenario artifact: present, bash -n clean, wired for R1/R2/R3 and the
#      Step-timing instrumentation (stage-timing + overlay-disk sourced).
#   2. R2 mode resolution: ALPINE_FDE_PIPELINE_FULL=1 -> full; a valid
#      ALPINE_FDE_E2E_STATE -> state-consume; the SHA-verified pristine-s00b
#      cache -> cache-reuse; else cold full. The mode is on the record
#      ("# pipeline mode:" line + the stages object: producer-leg exists ONLY
#      in full mode; cache-reuse only in the skip modes).
#   3. R3 overlay/LOCK_SH discipline: every boot runs _pipeline_boot on a
#      fresh QCOW2 overlay (overlay_create); positive legs COMMIT
#      (qemu-img commit), refusal legs DISCARD (overlay_discard); the exit
#      path releases the locks (overlay_lock_release).
#   4. Boot plan: 5 physical launches (4 in the skip modes) — b0-producer
#      (full only), b1-pcr7-drift (refusal), b2-rebaselined (passwordless),
#      b3-tpm-clear (refusal), b4-restored (passwordless).
#   5. COVERAGE TABLE — every assertion made by the absorbed scenarios
#      (s15-pcr7-drift.sh, s17-tpm-clear.sh) is absorbed here or explicitly
#      re-mapped (remaps named in the row). NONE silently dropped. The
#      superseded scenarios STAY in the tree and in the registry (status
#      `retired` since the 2026-09-25 retirement sweep: NOT in the default
#      selection, still invocable by name).
#   6. Runner wiring: s15c is a CHAIN MEMBER — the -j hoist list is
#      s00 -> s00b -> s01c -> s15c, s15c is a state consumer
#      (_STATE_CONSUMERS), and the registry resolves id s15c to
#      s15-recovery-chain.sh via the script-name column.
#
# RED-first: with the scenario file or any wiring piece missing, the
# corresponding assertions fail (the file greps, never executes, the runner).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

SCENARIO="$TESTS/e2e/s15-recovery-chain.sh"
RUNNER="$TESTS/run-e2e.sh"
PAR_CONTRACT="$TESTS/unit/run_e2e_parallel_contract.sh"

# --- part 0: artifacts present and parseable --------------------------------------
assert_file_exists "s15c scenario present (tests/e2e/s15-recovery-chain.sh)" "$SCENARIO"
assert_file_exists "runner present" "$RUNNER"
assert_file_exists "parallel-matrix contract present" "$PAR_CONTRACT"
assert_rc "s15c scenario: bash -n clean" 0 bash -n "$SCENARIO"
assert_rc "runner: bash -n clean" 0 bash -n "$RUNNER"

# --- part 1: R1/R2/R3 + timing instrumentation structure ---------------------------
SC=$(cat "$SCENARIO")
assert_contains "R3: boots run on fresh QCOW2 overlays over the canonical disk" "$SC" \
    "overlay_create"
assert_contains "R1: positive legs commit the overlay (in-place advance)" "$SC" \
    "qemu-img commit"
assert_contains "R3: refusal/failed legs discard the overlay" "$SC" "overlay_discard"
assert_contains "R3: the exit path releases the overlay locks" "$SC" "overlay_lock_release"
assert_contains "R2: ALPINE_FDE_PIPELINE_FULL=1 forces full-from-install" "$SC" \
    "ALPINE_FDE_PIPELINE_FULL"
assert_contains "R2: chain state consumed via ALPINE_FDE_E2E_STATE" "$SC" \
    "ALPINE_FDE_E2E_STATE"
assert_contains "R2: SHA-verified pristine-s00b cache fast path" "$SC" "pristine-s00b"
assert_contains "R2: mode on the record in the log" "$SC" '# pipeline mode:'
assert_contains "R2: skip-mode base snapshot, never mutated in place" "$SC" "_restore_base"
assert_contains "timing: stage-timing instrumentation sourced" "$SC" "lib/stage-timing.sh"
assert_contains "timing: cache-reuse stage emitted in the skip modes" "$SC" "cache-reuse"
assert_contains "timing: full-mode producer stage emitted" "$SC" "producer-leg"
assert_contains "timing: finalize-baseline stage emitted (full mode)" "$SC" \
    "finalize-baseline"
assert_contains "timing: drift-detect stage emitted (§9.4 host drill)" "$SC" "drift-detect"
assert_contains "timing: recovery re-seal stages emitted" "$SC" "recovery-reseal-1"
assert_contains "timing: tpm-clear stage emitted" "$SC" "tpm-clear"
assert_contains "boot plan: b0-producer (fed recovery unlock, full mode only)" "$SC" \
    "b0-producer"
assert_contains "boot plan: b1-pcr7-drift (PCR 7 drift refusal)" "$SC" "b1-pcr7-drift"
assert_contains "boot plan: b2-rebaselined (verified passwordless boot)" "$SC" \
    "b2-rebaselined"
assert_contains "boot plan: b3-tpm-clear (foreign-SRK refusal)" "$SC" "b3-tpm-clear"
assert_contains "boot plan: b4-restored (passwordless unseal restored)" "$SC" \
    "b4-restored"
assert_contains "safety: overall pipeline budget with loud hang failure" "$SC" \
    "OVERALL-BUDGET"
assert_contains "safety: per-boot qemu timeout bound" "$SC" "QEMU_TIMEOUT"

# --- part 2: coverage table (absorbed assertions; none dropped) --------------------
# row = source-scenario <TAB> assertion <TAB> fixed pattern that MUST appear in
# s15-recovery-chain.sh. Remaps are named in the assertion text (the s15c
# header documents the full reasoning).
COVERAGE_TABLE=(
    "s15	b1 producer: hook recovery loop opened (token-less volume)	sentinel_of unseal_token_missing"
    "s15	b1 producer: fed slot-0 passphrase unsealed via the recovery path	sentinel_of unseal_pass_unlocked"
    "s15	b1 producer: volume UNSEALED	sentinel_of harness_unsealed"
    "s15	b1 producer: init ran	sentinel_of harness_init_started"
    "s15	b1 producer: G-T13 signed PCR 11 prediction on the unsealing boot	assert_pcr11_prediction"
    "s15	host: efivars seam reads SB on / SetupMode 0 (G-R1 finalize guard)	fw_sb_state"
    "s15	host: boot console records the enrolled PCR 7	console_pcr"
    "s15	host: finalized baseline carries expected_pcr7	expected_pcr7"
    "s15	host: combined .pcrsig pol == policy_digest(enrolled d7, d11) (G-B6)	policy_digest"
    "s15	host: standing token is systemd-tpm2 pinning {PCR 7, PCR 11}	tpm2-pcrs"
    "s15	host: standing token on a fresh keyslot (recovery slot 0 untouched)	keyslot"
    "s15	host: production CLI enroll-tpm host-side (digest-anchored)	uki_host_enroll_finalized"
    "s15	§9.4: live PCR 7 drift synthesized host-side (pcrextend)	swtpm_pcrextend"
    "s15	§9.4: audit detects the drift (exit 1, pcr7 DRIFT line)	DRIFT"
    "s15	§9.4: audit --accept --yes re-baselines (real CLI)	--accept --yes"
    "s15	§9.4: audit clean after re-baseline (exit 0)	last-audit.json"
    "s15	drift: dbx update via virt-fw-vars (boot-layer drift injection)	--add-dbx-cert"
    "s15	drift: hook ran the enter-initrd extend	sentinel_of unseal_pcrextend_ok"
    "s15	drift: hook discovered the {7,11} token	sentinel_of unseal_token_info"
    "s15	drift: hook refused the stale seal (static PCR 7 term)	sentinel_of unseal_seal_refused"
    "s15	drift: I3 gate passed (the signature is NOT the defect)	sentinel_of unseal_sig_refused"
    "s15	drift: refusal precedes the first recovery prompt	refusal FIRST"
    "s15	drift: exactly 3 recovery-passphrase prompts (bounded loop)	sentinel_of unseal_prompt_re"
    "s15	drift: 3-strike give-up (§8.2 fail-closed)	sentinel_of unseal_3strike"
    "s15	drift: fail-closed poweroff (no shell offered)	sentinel_of unseal_poweroff"
    "s15	drift: never unlocked via the TPM token	sentinel_of unseal_unlocked"
    "s15	drift: no emergency shell	sentinel_of emergency_forbidden"
    "s15	drift: PCR 11 tamper scoping (the drift is PCR 7 only; skip mode remapped to the b3-vs-b2 pair)	PCR 11"
    "s15	drift: guest exited via hook poweroff, not timeout-kill (IN-08)	not timeout-kill"
    "s15	recovery: wipe enrollment (token remove + luksKillSlot, --key-file)	luksKillSlot"
    "s15	recovery: stale token removed (0 standing tokens)	stale token removed"
    "s15	recovery: baseline re-stamped to the drifted d7	re-stamped"
    "s15	recovery: re-sealed exactly ONE standing systemd-tpm2 token	exactly ONE standing"
    "s15	recovery boot: zero-input token unlock (no prompt ever opened)	zero-input"
    "s15	recovery boot: unlocked via the TPM token (recovery complete)	recovery complete"
    "s15	recovery boot: clean poweroff	sentinel_of harness_poweroff"
    "s15	recovery boot: sealed against the drifted (boot-layer) PCR 7	boot-layer"
    "s17	drill: swtpm_reset wipes ALL TPM state (fresh SRK)	swtpm_reset"
    "s17	drill: fresh TPM has PCR 7 zero before the refusal boot	ZERO7"
    "s17	cleared: the sealed blob refuses under the fresh SRK	fresh SRK"
    "s17	cleared: still boots — the firmware re-measures the fresh TPM	re-measures"
    "s17	cleared: PCR 7 re-measured to the same value (console evidence)	re-measured"
    "s17	recovery: re-seal against the fresh TPM (new SRK, same d11, no re-encryption)	no volume-key re-encryption"
    "s17	recovery boot: passwordless unseal restored	passwordless"
)
_coverage_seen=0
for _row in "${COVERAGE_TABLE[@]}"; do
    IFS=$'\t' read -r _src _assert _pat <<<"$_row"
    assert_contains "coverage [$_src] $_assert" "$SC" "$_pat"
    _coverage_seen=$((_coverage_seen + 1))
done
unset _row _src _assert _pat
assert_rc "coverage table carries the full absorbed set (>= 43 rows)" 0 \
    test "$_coverage_seen" -ge 43

# --- part 3: runner wiring (chain member) ------------------------------------------
RN=$(cat "$RUNNER")
assert_contains "wiring: registry row s15c -> s15-recovery-chain.sh" "$RN" \
    "s15c	s15-recovery-chain.sh"
assert_contains "wiring: hoist list is s00 -> s00b -> s01c -> s15c" "$RN" \
    'for _canon in s00 s00b s01c s15c; do'
assert_contains "wiring: parallel-wave skip covers s15c" "$RN" \
    's00|s00b|s01c|s15c'
assert_contains "wiring: s15c is a state consumer (_STATE_CONSUMERS)" "$RN" \
    ' s01c s15c '
assert_contains "wiring: chain-phase order puts s15c after s01c" "$RN" "s00b -> s01c -> s15c"
assert_contains "wiring: usage header names the s15c chain member" "$RN" "s15-recovery-chain.sh"
assert_contains "parallel contract: s15c phase pin present" "$(cat "$PAR_CONTRACT")" "s15c"

# --- part 4: absorbed scenarios retained -------------------------------------------
# (retired 2026-09-25: the pipelines absorbed their boots — the files stay in
# the tree and the ids stay registered, invocable by name, but the retired
# rows are NOT in the default selection; see tests/run-e2e.sh REGISTRY)
assert_file_exists "s15 stays in the tree (retired: absorbed by s15c)" \
    "$TESTS/e2e/s15-pcr7-drift.sh"
assert_file_exists "s17 stays in the tree (retired: absorbed by s15c)" \
    "$TESTS/e2e/s17-tpm-clear.sh"
assert_contains "s15 stays registered (retired — absent from the default selection)" "$RN" \
    "s15	s15-pcr7-drift.sh"
assert_contains "s17 stays registered (retired — absent from the default selection)" "$RN" \
    "s17	s17-tpm-clear.sh"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# s15c_recovery_chain_contract: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
