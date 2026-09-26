#!/usr/bin/env bash
# tests/unit/s90_negative_drill_contract.sh — contract suite for the unified
# early-boot NEGATIVE drill (registry id **s90** -> tests/e2e/s90-negative-drill.sh,
# queue item 30 move 2). HERMETIC: no qemu, no swtpm, no boots — the scenario
# artifact, the absorption bookkeeping and the runner wiring are pinned by
# content (the s15c contract-suite pattern).
#
# Pinned:
#   1. Scenario artifact: present, bash -n clean, wired for the R1/R3
#      discipline (overlay-disk sourced; read-mostly legs on discarded QCOW2
#      overlays; the one mutating leg on a raw copy) and the Step-timing
#      instrumentation (stage-timing sourced; one leaf stage per leg).
#   2. Boot plan: exactly 6 fail-closed legs — leg1-drift, leg2-loader-opt,
#      leg3-nopcrsig, leg4-wiped, leg5-foreign-sig (each ending in the §8.2
#      3-strike `poweroff -f`) and leg6-sboff-da (the ADR-20 pre-unseal guard
#      block + the host-side DA-lockout drill, qemu killed BY PID).
#   3. COVERAGE / DISPOSITION TABLE — every VM-only assertion class of the
#      seven absorbed scenarios (s03, s05, s07, s09, s12, s13, s18) is either
#      (a) covered by a drill leg (pattern pinned in the scenario), (b) covered
#      ZERO-BOOT by a wt-bootmin host suite (suite file pinned present), or
#      (c) dropped WITH the reason named in the row. NONE silently lost.
#   4. Runner wiring: the s90 row resolves via the runtime append (the literal
#      table stays the pure §10/§12 matrix), s90 is a state consumer
#      (_STATE_CONSUMERS), and the seven absorbed ids are REMOVED — files and
#      registry rows gone; naming one is a loud `unknown` row (the runner-side
#      behavior is pinned by run D of run_e2e_parallel_contract.sh).
#
# RED-first: with the scenario file or any wiring piece missing, the
# corresponding assertions fail (the file greps, never executes, the runner).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

SCENARIO="$TESTS/e2e/s90-negative-drill.sh"
RUNNER="$TESTS/run-e2e.sh"
PAR_CONTRACT="$TESTS/unit/run_e2e_parallel_contract.sh"
HOST_S03="$TESTS/unit/s03_stale_enrollment_host.sh"
HOST_S13="$TESTS/unit/s13_token_tamper_host.sh"
HOST_S18="$TESTS/unit/s18_foreign_pcrsig_host.sh"

# --- part 0: artifacts present and parseable --------------------------------------
assert_file_exists "s90 scenario present (tests/e2e/s90-negative-drill.sh)" "$SCENARIO"
assert_file_exists "runner present" "$RUNNER"
assert_file_exists "parallel-matrix contract present" "$PAR_CONTRACT"
assert_rc "s90 scenario: bash -n clean" 0 bash -n "$SCENARIO"
assert_rc "runner: bash -n clean" 0 bash -n "$RUNNER"

# --- part 1: structure — R1/R3 + timing + shared-mechanics sourcing ---------------
SC=$(cat "$SCENARIO")
assert_contains "R3: read-mostly legs boot fresh QCOW2 overlays over the master base" "$SC" \
    "overlay_create"
assert_contains "R3: leg overlays are discarded (the guest persists nothing)" "$SC" \
    "overlay_discard"
assert_contains "R1: the enrolled base is snapshotted once into a master dir" "$SC" \
    'mkdir -p "$RUN/base"'
assert_contains "R1: the master base disk is NEVER booted (mutation legs use raw copies)" "$SC" \
    'cp "$BASE/disk.img" "$RUN/leg4-disk.img"'
assert_contains "R2: state-consume fast path via ALPINE_FDE_E2E_STATE" "$SC" \
    "ALPINE_FDE_E2E_STATE"
assert_contains "R2: pristine-s00b cache fallback" "$SC" "pristine-s00b"
assert_contains "R2: the resolved mode is on the record in the log" "$SC" '# drill base:'
assert_contains "timing: stage-timing instrumentation sourced" "$SC" "lib/stage-timing.sh"
assert_contains "mechanics: the swtpm data-loop wedge guard is present" "$SC" "_wedge_wait"
assert_contains "mechanics: the TPM is re-anchored (zeroed, settled) before every leg" "$SC" \
    "_reanchor_tpm"
assert_contains "mechanics: sentinel lookups go through the promoted table" "$SC" \
    "lib/sentinels.sh"
assert_contains "safety: per-boot qemu timeout bound" "$SC" "QEMU_TIMEOUT"

# --- part 2: boot plan -------------------------------------------------------------
assert_contains "boot plan: leg1-drift (SB-on PCR 7 drift refusal)" "$SC" "leg1-drift"
assert_contains "boot plan: leg2-loader-opt (tampered-cmdline UKI + stale payload)" "$SC" \
    "leg2-loader-opt"
assert_contains "boot plan: leg3-nopcrsig (UKI built without PCR signing)" "$SC" "leg3-nopcrsig"
assert_contains "boot plan: leg4-wiped (standing enrollment wiped host-side)" "$SC" "leg4-wiped"
assert_contains "boot plan: leg5-foreign-sig (foreign-signed .pcrsig, I3 gate refusal)" "$SC" \
    "leg5-foreign-sig"
assert_contains "boot plan: leg6-sboff-da (pre-unseal guard block + DA lockout)" "$SC" \
    "leg6-sboff-da"
assert_contains "refusal legs: 3-strike fail-closed poweroff (no shell is offered)" "$SC" \
    "fail-closed poweroff (no shell is offered)"
assert_contains "guard leg: qemu killed BY PID after the reboot sentinel" "$SC" \
    "_guard_enter_and_kill"
assert_contains "G-T15: the DA-lockout boot consumed no budget (probe before + after)" "$SC" \
    "swtpm_da_locked_probe"

# --- part 3: coverage / disposition table ------------------------------------------
# row = source <TAB> assertion class <TAB> disposition <TAB> pin
#   disposition "drill"    -> _pat is a pattern that MUST appear in the scenario
#   disposition "host"     -> _pat is a pattern that MUST appear in the named
#                             host suite (checked against HOST_<SRC>_FILE)
#   disposition "dropped"  -> _pat names the REASON (asserted as the row's
#                             documentation; nothing greps it)
# s13 contributes its VM-only rows here too: its artifact-level verdicts moved
# to the host suite; its console semantics were GENERIC hook behaviors the
# drill legs pin (documented in the drill header).
COVERAGE_TABLE=(
    "s05	guard: blocking refusal names the pre-unseal guard (live secureboot=0)	drill	unseal_sb_guard"
    "s05	guard: Press-Enter confirmation + OsIndications + firmware-setup reboot	drill	unseal_sb_guard_reboot"
    "s05	guard fires BEFORE any TPM work (no extend, no token, no prompt)	drill	the guard fired BEFORE any TPM work"
    "s05	PCR 7 non-zero + drifted vs enrolled; PCR 11 unchanged	drill	PCR 7 non-zero (SB-off state measured by firmware)"
    "s05	never unlocked / never UNSEALED / no emergency shell on the guard boot	drill	never UNSEALED (harness sentinel)"
    "s07	tampered cmdline reaches the kernel (stub measured the effective cmdline)	drill	tamper word reached the kernel"
    "s07	tampered prediction diverges from the shipped clean .pcrsig (host-side)	drill	tampered prediction diverges from the shipped"
    "s07	PCR 11 drifted -> policy session refuses (I3 admits the stale entry)	drill	drifted PCR 11 matches NO signed .pcrsig entry"
    "s07	refusal BEFORE the first prompt; exactly 3 prompts; 3-strike; poweroff	drill	refusal FIRST"
    "s03	f1: UKI built without PCR signing -> no .pcrsig section, sbverify-clean	drill	NO .pcrsig section (the defect under test)"
    "s03	f1: 'pcrsig payload MISSING'; token path never armed	drill	pcrsig payload MISSING"
    "s03	f2: token removed from LUKS2 metadata; only slot-0 remains	drill	token removed from LUKS2 metadata"
    "s03	f2: unseal_token_missing; NO self-heal (I6)	drill	wiped enrollment, no self-heal"
    "s03	3 prompts + 3-strike + poweroff + never unlocked (every refusal leg)	drill	_assert_refusal_tail"
    "s12	boot A: SB-off guard block (see s05 rows) + BY-PID teardown	drill	qemu_kill BY PID after the guard sentinel"
    "s12	boot B neg: SB-on drift -> seal refusal -> refusal-first ordering	drill	[leg1] hook seal refusal on the stale PCR 7 term"
    "s09	DA lockout armed -> enforced before the boot -> STILL enforced after (G-T15)	drill	G-T15 lockout STILL enforced after the boot"
    "s09	locked TPM still boots (auth-less ops serve; PCR 7 printed)	drill	PCR 7 non-zero (SB-off state measured by firmware)"
    "s18	foreign: pols identical, only the signer moved (host-side recipe)	drill	only the signer moved"
    "s18	foreign: release.pub REFUSES the foreign sig over the same pol (negative)	drill	REFUSES the foreign sig over the same pol"
    "s18	foreign: the I3 gate refuses BEFORE any TPM session (unseal_sig_refused)	drill	BEFORE any TPM session"
    "s18	PCR 7 unchanged vs enrolled (no drift confound — only the drive moved)	drill	no drift confound — only the drive moved"
    "s03	standing-token shape + G-B6 gate refusals + wipe detection	host	token_post_assert"
    "s03	stale d7 re-sign -> gate dies 64 'stale/tampered'; unseal oracle refuses	host	seal_unseal"
    "s13	pubkey-swap inert / re-export moved + enroll post-assert refuses	host	token_import"
    "s13	blob-corrupt: sealed object FAILS TO LOAD at the live swtpm	host	tpm2_load"
    "s13	sig-corrupt + version-99 inert under the entry-sig I3 semantic	host	entry-sig"
    "s13	bad descriptor: cryptsetup refuses the dangling keyslots descriptor	host	dangling keyslots"
    "s18	wrongsel/staled7/pcrsig11only/tok11: gate + recipe verdicts	host	seal_verify_pcrsig"
    "s18	missing .pcrsig: gate dies 64 (ADR-8 signing-key-absent)	host	G-B6"
    "s13	inert-variant UNLOCK boots (pubkey-swap/sig-corrupt/version-99)	dropped	dropped-with-reason: the unlock-proceeds verdict is pinned host-side (s13_token_tamper_host) and the positive token unlock is exercised by the s01c/s15c pipelines; a fourth unlock boot would re-pay the fixture cycle for zero new console semantics"
    "s18	wrongsel/staled7/tok11 control BOOTS	dropped	dropped-with-reason: their artifact-level verdicts are pinned host-side (s18_foreign_pcrsig_host: gate dies-64 + recipe negatives) and their console refusal class (unseal_seal_refused) is the generic policy-session refusal leg1/leg2 pin; leg5 boots the OTHER refusal class (gate refusal) so both classes stay live"
    "s13	all token-tamper variant BOOTS	dropped	dropped-with-reason: refusal/unlock verdicts pinned host-side at the real TPM (s13_token_tamper_host); the console semantics the variants shared (token discovery, refusal class, 3-strike, poweroff) are the GENERIC behaviors every drill leg pins"
    "s03	bootstrap/baseline boot positive controls	dropped	dropped-with-reason: only needed for self-bootstrap; the positive baseline boot is owned by the s00 -> s00b chain (and s01c boot 1), not by a negative drill"
)
_coverage_seen=0
for _row in "${COVERAGE_TABLE[@]}"; do
    IFS=$'\t' read -r _src _assert _disp _pat <<<"$_row"
    case "$_disp" in
        drill)
            assert_contains "coverage [$_src] $_assert" "$SC" "$_pat"
            ;;
        host)
            eval "_host_file=\$HOST_${_src^^}"
            assert_file_exists "coverage [$_src] $_assert (host suite present)" "$_host_file"
            assert_contains "coverage [$_src] $_assert (host pin)" "$(cat "$_host_file")" "$_pat"
            ;;
        dropped)
            assert_contains "coverage [$_src] $_assert (dropped: reason on record)" "$_pat" "dropped-with-reason:"
            ;;
    esac
    _coverage_seen=$((_coverage_seen + 1))
done
unset _row _src _assert _disp _pat _host_file
assert_rc "coverage table carries the full disposition set (>= 33 rows)" 0 \
    test "$_coverage_seen" -ge 33

# --- part 4: absorbed scenarios removed (files AND registry rows) ------------------
for _f in s03-stale-enrollment.sh s05-sb-off.sh s07-loader-options.sh \
    s09-tpm-da-locked.sh s12-wrong-passphrase.sh s13-token-tamper.sh \
    s18-foreign-pcrsig.sh; do
    assert_rc "absorbed file removed: tests/e2e/$_f" 1 test -e "$TESTS/e2e/$_f"
done
unset _f
RN=$(cat "$RUNNER")
for _id in s03 s05 s07 s09 s12 s13; do
    assert_not_contains "registry row removed: $_id" "$RN" "$_id	$_id"
done
unset _id
assert_not_contains "registry row removed: s18 (runtime append gone with its file)" "$RN" \
    '"s18" "s18-foreign-pcrsig.sh"'


# --- part 5: runner wiring ----------------------------------------------------------
assert_contains "wiring: s90 row resolves to s90-negative-drill.sh (runtime append)" "$RN" \
    '"s90" "s90-negative-drill.sh" "ready"'
assert_contains "wiring: s90 is a state consumer (_STATE_CONSUMERS)" "$RN" \
    '_STATE_CONSUMERS=" s01c s15c s06 s90 "'
assert_contains "wiring: s90 not chain-hoisted (it is an independent consumer)" "$RN" \
    'for _canon in s00 s00b s01c s15c; do'
assert_contains "parallel contract: s90 phase/default pins present" "$(cat "$PAR_CONTRACT")" \
    "s90"
assert_contains "parallel contract: run D pins the removed-id `unknown` rows" "$(cat "$PAR_CONTRACT")" \
    '"unknown","pass","unknown"'

# --- summary ------------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# s90_negative_drill_contract: pass=$TESTS_PASS fail=$TESTS_FAIL"
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
