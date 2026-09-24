#!/usr/bin/env bash
# tests/e2e/s17-tpm-clear.sh — §10 row "TPM cleared" + §9.4 recovery (Wave 3),
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock).
#
#   boot 1  baseline (token-less disk): the hook's bounded recovery loop is
#           the only way in; the slot-0 passphrase is fed through the hook's
#           OWN prompt -> UNSEALED (healthy baseline). Host: the REAL
#           production CLI enrolls the finalized {7,11} Mechanism B token
#           against the fixture swtpm.
#   host    swtpm_reset — wipe ALL TPM state (fresh SRK, PCRs 0)
#   boot 2  the hook's I3 gate PASSES (the token + .pcrsig are untouched —
#           the defect is the TPM state), the fresh primary is created, but
#           the sealed blob FAILS TO LOAD under it (it was sealed to the
#           pre-clear SRK) -> "the TPM refused the sealed blob under the
#           current PCR state (drift / foreign TPM / DA lock)" ->
#           the hook's BOUNDED recovery loop (3 fed WRONG answers) ->
#           3-strike fail-closed `poweroff -f`. NEVER an emergency shell.
#   host    wipe the stale enrollment (token + keyslot) — the §9.4
#           operator step; re-stamp the baseline to the fresh TPM's
#           firmware-measured d7 and re-enroll (fresh SRK, same d11).
#   boot 3  zero-input token unlock against the re-sealed token (new SRK,
#           firmware re-measured PCR 7)                        UNSEALED
#
# §10 expectations: TPM cleared -> Boots ✅ / Auto-unlock ❌ (fail-closed
# bounded loop) / re-enroll.
#
# NB (G-T13): NO assert_pcr11_prediction on boot 2 — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading; the PCR 11 unchanged-equality vs the enrolled boot's
# console is the equivalent tamper-scoping evidence (a cleared TPM re-measures
# the SAME section chain + phase word from zero). Boot 1 and boot 3 UNSEAL,
# so the postphase reading appears there and the signed prediction IS
# asserted.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/assert.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/keys-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/disk-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/prediction.sh
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13, §12)
# shellcheck disable=SC1091
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck disable=SC1091
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

RUN="$TESTS/e2e/.runs/s17-tpm-clear-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# CR-02/MD-03: prunes must spare the invocation's chained state dirs
# (DEBIAN_FDE_PROTECT_DIRS, exported by run-e2e.sh)
while IFS= read -r _d; do
    case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$_d:"*) continue ;; esac
    rm -rf "$_d"
done < <(find "$TESTS/e2e/.runs" -mindepth 1 -maxdepth 1 -type d -printf "%T@\t%p\n" 2>/dev/null | sort -rn | tail -n +3 | cut -f2-)

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The SRK persists in tpm2-00.permall (seals survive); PCRs reset to zero on
# the restart and are re-measured by the firmware at the next boot.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }
# _fresh_pcrs — force ZEROED PCRs for the NEXT qemu boot (repro-proven
# 2026-09-24, registry s02/s15/s17): after a boot exits CLEANLY the proxy
# stores the volatile state and the fixture's restart RESTORES it into RAM;
# a boot served by that restored instance EXTENDS OVER the previous boot's
# final values (PCR 0/7/11 all shift — the "register instability" consoles)
# and the re-sealed token can never match. swtpm_stop + swtpm_start (the
# second start finds no volatile file) restores the documented per-boot
# zeroed-PCR semantics. The re-seal's host-side window reads the booted
# values BEFORE this guard runs (boot_and_wait is only called for boot 3).
_fresh_pcrs() {
    local dir="$RUN/tpm" d0 k
    swtpm_stop "$dir" 2>/dev/null || true
    # a HALF-STARTED instance (readiness probe failed) still holds the state
    # dir's .lock and would make the restart below fail — kill it scoped to
    # this run dir and clear every socket/lock file it left behind
    pkill -9 -f "swtpm socket .*$dir/" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/.lock" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl" "$dir/swtpm.sock"
    swtpm_start "$dir" || { echo "s17: swtpm restart failed"; return 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    if [[ ! "$d0" =~ ^0{64}$ ]]; then
        echo "s17: TPM not zeroed before a boot (pcr0=$d0) — refusing a cumulative register"; return 1
    fi
    # settle: a guest TPM command arriving mid-setup times out and the
    # firmware DROPS the measurement (the degraded-boot register — s18's
    # _reanchor_tpm evidence); warm the whole path through the proxy first.
    for k in 1 2 3 4 5; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    return 0
}

_host_wipe_enrollment() {
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue
        # --key-file: the wipe needs to authenticate against the remaining
        # keyslot; an unattended stdin blocks FOREVER otherwise (repro 2026-09-24:
        # luksKillSlot sat 36 min waiting to read a passphrase)
        timeout 120 cryptsetup luksKillSlot --batch-mode --key-file "$RUN/kf-slot0" \
            "$img" "$slot" </dev/null || return 1
    done
}

boot_and_wait() {
    local label="$1"
    _ensure_tpm || { echo "s17: swtpm not serving"; return 1; }
    _fresh_pcrs || { echo "s17: cannot zero the TPM PCRs for the boot"; return 1; }
    echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
    qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5"
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-$label.log"
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }
console_pcr() { # <label> <idx>
    grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$RUN/console-$1.log" 2>/dev/null | head -1 | cut -d= -f2
}

# --- fixtures ------------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s17: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s17: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
esp_make "$RUN/esp.img" $(( UKI_MIB * 2 + 8 )) "$RUN/uki-6.2.0.efi" || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1
printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"

# efivars seam for the enroll-tpm I5 guard (mkvar pattern from
# tests/unit/baseline_finalize_guard.sh)
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0

# --- boot 1: baseline (token-less disk) -> hook recovery loop -------------------
_ensure_tpm || { echo "s17: swtpm not serving (boot 1)"; exit 1; }
echo "# boot v1-baseline (token-less disk -> hook recovery loop, TCG, up to $QEMU_TIMEOUT s) ..."
for _attempt in 1 2; do
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig.img"
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    fi
    qemu_wait "$RUN" "$QEMU_TIMEOUT"
    cp "$CONSOLE" "$RUN/console-v1-baseline.log"
    grep -q "$(sentinel_of harness_unsealed)" "$RUN/console-v1-baseline.log" && break
    echo "# baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_reset "$RUN/tpm" && swtpm_start "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
done
LOG=$(log_of "v1-baseline")
assert_contains "[v1] init ran" "$LOG" "$(sentinel_of harness_init_started)"
assert_contains "[v1] hook recovery loop opened (no token on the fresh volume)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[v1] fed slot-0 passphrase unsealed via the recovery path" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[v1] UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_pcr11_prediction "S-17 v1-baseline"
D7_PRE=$(console_pcr "v1-baseline" 7)
assert_ne "boot 1 console records a non-zero PCR 7" "$D7_PRE" ""

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted
# console's PCR 7, d11 = the build's enter-initrd prediction; the combined
# {7,11} entry is what the hook extracts for the finalized token.
D11=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11" ]] || { echo "s17: no enter-initrd d11 prediction from the build"; exit 1; }
swtpm_ensure "$RUN/tpm" || { echo "s17: swtpm restart (enroll) failed"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0-combined.json" \
    "$D7_PRE" "$D11" "$RUN/keys" || exit 1
assert_eq "combined .pcrsig entry pol == policy_digest(enrolled d7, enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$D7_PRE" "$D11")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.2.0-combined.json")"
uki_pcrsig_disk "$RUN/pcrsig-combined.img" "$RUN/uki-6.2.0-combined.json" || exit 1
# the finalized baseline the enroll preconditions read (sp_etc_dir shape)
mkdir -p "$RUN/rootfs/etc/alpine-fde"
cat >"$RUN/rootfs/etc/alpine-fde/baseline.json" <<EOF
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcr0": "pending",
  "pcr1": "pending",
  "pcr2": "pending",
  "pcr3": "pending",
  "expected_pcr7": "$D7_PRE",
  "sb_state": {
    "secure_boot": "1",
    "setup_mode": "0",
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
    "release_pub_path": "",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "",
    "esp_partuuid": ""
  }
}
EOF
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.2.0-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s17: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

# --- clear the TPM (§9.4 "cleared TPM") ------------------------------------------
echo "# swtpm_reset: wiping ALL TPM state (fresh SRK, PCRs reset)"
swtpm_reset "$RUN/tpm"
swtpm_start "$RUN/tpm" || { echo "s17: swtpm restart after reset failed"; exit 1; }
ZERO7=$(printf '0%.0s' {1..64})
assert_eq "fresh TPM: PCR 7 is zero" "$ZERO7" "$(swtpm_pcrread "$RUN/tpm" 7)"

# --- boot 2: seal is dead — fail closed -------------------------------------------
# ONE boot: the hook refuses (the sealed blob cannot load under the fresh
# SRK) and its bounded loop reads 3 WRONG answers fed prompt-synchronized.
_ensure_tpm || { echo "s17: swtpm not serving (boot 2)"; exit 1; }
echo "# boot cleared: fresh SRK, stale sealed blob (TCG, up to $QEMU_TIMEOUT s)"
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/pcrsig-combined.img"
for n in 1 2 3; do
    if uki_wait_hook_prompt "$n" 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "debian-fde-cleared-wrong-passphrase-$n"
    else
        _assert_result not-ok "[clr] hook awaiting recovery passphrase $n/3" \
            "no prompt $n in console"
        break
    fi
done
qemu_wait "$RUN" "$QEMU_TIMEOUT"
cp "$CONSOLE" "$RUN/console-cleared.log"
LOG=$(log_of "cleared")
assert_contains "[clr] init ran (still boots — firmware re-measures the fresh TPM)" "$LOG" \
    "$(sentinel_of harness_init_started)"
assert_contains "[clr] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[clr] hook discovered the {7,11} token" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[clr] I3 gate passed (the signature is NOT the defect)" "$LOG" \
    "$(sentinel_of unseal_sig_refused)"
assert_contains "[clr] TPM refused the sealed blob (sealed to the pre-clear SRK)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$RUN/console-cleared.log" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$RUN/console-cleared.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "[clr] hook refusal FIRST (line $_ref_line < first prompt line $_p1_line)" ""
else
    _assert_result not-ok "[clr] hook refusal FIRST" "ref=$_ref_line prompt1=$_p1_line"
fi
PROMPTS_CLR=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[clr] exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS_CLR"
assert_contains "[clr] 3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "[clr] fail-closed poweroff (no shell is offered)" "$LOG" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[clr] never unlocked (token)" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[clr] never unlocked (recovery passphrase)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[clr] never UNSEALED" "$LOG" "$(sentinel_of harness_unsealed)"
assert_not_contains "[clr] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# tamper scoping: a cleared TPM re-measures the SAME section chain + phase word
# from zero — PCR 7 AND PCR 11 are unchanged vs the enrolled boot
assert_eq "[clr] PCR 7 re-measured to the same value (console evidence)" "$D7_PRE" \
    "$(console_pcr "cleared" 7)"
assert_eq "[clr] PCR 11 unchanged vs the enrolled boot (same UKI, same phase extend)" \
    "$(console_pcr "v1-baseline" 11)" "$(console_pcr "cleared" 11)"
# IN-08: honest in both directions (missing pid file is not a clean exit)
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[clr] guest exited (hook poweroff -f, not timeout-kill)" ""
else
    _assert_result not-ok "[clr] guest exited (hook poweroff -f, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

# --- recovery: wipe the dead seal; re-seal against the fresh TPM -------------------
echo "# wiping the stale enrollment (token + slot) — the §9.4 operator step"
_host_wipe_enrollment "$RUN/disk.img" || { echo "s17: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "stale token removed" "0" "$NTOK"

# re-stamp the baseline to the fresh TPM's firmware-measured d7 (boot 2's
# console) and re-enroll: fresh SRK, same d11, no volume-key re-encryption
D7_RE=$(console_pcr "cleared" 7)
swtpm_ensure "$RUN/tpm" || { echo "s17: swtpm not serving (re-seal)"; exit 1; }
# digest-anchored re-seal (Option A): no reseeding — the CLI compares the
# re-signed entry's recorded d7/d11 against the re-stamped baseline (pure
# data, no live TPM read).
sed -i "s|\"expected_pcr7\": \".*\"|\"expected_pcr7\": \"$D7_RE\"|" \
    "$RUN/rootfs/etc/alpine-fde/baseline.json"
assert_eq "baseline re-stamped to the fresh TPM's d7" "$D7_RE" \
    "$(jq -r '.expected_pcr7' "$RUN/rootfs/etc/alpine-fde/baseline.json")"
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-cleared-combined.json" \
    "$D7_RE" "$D11" "$RUN/keys" || exit 1
uki_pcrsig_disk "$RUN/pcrsig-cleared.img" "$RUN/uki-cleared-combined.json" || exit 1
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-cleared-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/rootfs" || {
    echo "s17: re-seal enroll-tpm FAILED"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "re-sealed: exactly ONE standing systemd-tpm2 token" "1" "$NTOK"

# --- boot 3: re-sealed token on the fresh TPM -> UNSEALED ---------------------------
boot_and_wait "re-enroll" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/pcrsig-cleared.img"
LOG=$(log_of "re-enroll")
assert_pcr11_prediction "S-17 re-enroll"
assert_contains "[re] hook ran the enter-initrd extend" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[re] re-sealed {7,11} token discovered" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_not_contains "[re] no recovery-passphrase prompt ever opened (zero-input path)" "$LOG" \
    "$(sentinel_of unseal_prompt_re)"
assert_contains "[re] unlocked via the TPM token (recovery complete)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_contains "[re] UNSEALED (recovery complete)" "$LOG" "$(sentinel_of harness_unsealed)"
assert_contains "[re] clean poweroff" "$LOG" "$(sentinel_of harness_poweroff)"
assert_eq "PCR 7 re-measured to the same enrolled state (console evidence)" "$D7_PRE" \
    "$(console_pcr "re-enroll" 7)"

rm -rf "$RUN/guest-tree"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s17-tpm-clear: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s17-tpm-clear: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
