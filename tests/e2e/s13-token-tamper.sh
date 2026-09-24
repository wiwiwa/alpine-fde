#!/usr/bin/env bash
# tests/e2e/s13-token-tamper.sh — §10/§12 token-tamper family (invariant I3:
# "Token JSON is untrusted: tampering with it can only break unseal, never
# forge it"), against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the
# harness DEFAULT unlock). Parametrized over cryptsetup token import
# fixtures, all under SB-ENROLLED vars (pure metadata attack, trusted boot
# intact). OBSERVED HOOK BEHAVIOR per variant — the hook consumes ONLY
# type / tpm2-pcrs / tpm2-pcr-bank / tpm2-blob / tpm2-signature from the
# token JSON (its policy anchor is the signed /.extra .pcrsig + public key,
# NOT any token field — I3 by construction):
#   pubkey-swap     — tpm2-pubkey swapped for a VALID foreign RSA key:
#                     INERT for the hook (it never reads tpm2-pubkey — the
#                     PolicyAuthorize anchor is loadexternal of the /.extra
#                     release key). Documented deviation from the 257.13
#                     oracle, which pivoted on this field: unlock proceeds.
#   blob-corrupt    — tpm2-blob corrupted (first byte flipped): the sealed
#                     object fails to load/unseal in the TPM -> refusal ->
#                     the hook's bounded recovery-passphrase loop -> 3
#                     wrong answers -> 3-strike fail-closed `poweroff -f`.
#   sig-corrupt     — tpm2-signature corrupted: INERT under the entry-sig
#                     I3 semantic (the hook verifies the DRIVE ENTRY's own
#                     release-key signature against /.extra/tpm2-pcr-
#                     public-key.pem, never the token's signature) ->
#                     unlock proceeds. Entry-level forgeries (forged entry
#                     sig, swapped /.extra key, relabeled pcrs) still fail
#                     closed — unit-pinned in hooks_mkinitfs_unseal.sh.
#   version-99      — unknown "version": 99 field: inert metadata -> unlock.
#
# Each variant boots the enrolled disk with its tampered token; refusal
# variants must END in the hook's 3-strike fail-closed poweroff (fed via the
# hook's OWN prompt), never unlocked, no emergency shell. Host-side pre-boot
# assertions prove every tamper actually landed (token remove + import is
# the attacker's unprivileged write primitive; an "in use" token cannot be
# overwritten directly).
#
# Reuses s00 state when DEBIAN_FDE_E2E_STATE points at the s00 run dir
# (run-e2e.sh sets it); otherwise builds + boots the enrolled state itself
# (bootstrap boot + one boot per variant).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/disk-fixture.sh
source "$TESTS/lib/disk-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
source "$TESTS/lib/prediction.sh"  # assert_pcr11_prediction (G-T13/G-E9)

RUN="$TESTS/e2e/.runs/s13-lite-$(date +%s)"
mkdir -p "$RUN"
# the G-T13 prediction helper reads $CONSOLE (prediction.sh); the variant
# boots re-point it at each variant's own console. Default it to the
# scenario-level console so the save/restore can never trip `set -u` with an
# unbound variable (registry 2026-09-23: "CONSOLE: unbound variable" aborted
# the scenario after every assertion had passed — same defect class as s12).
CONSOLE="$RUN/console.log"

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while boots run, else a mid-boot prune unlinks console.log.
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!
# HI-02: the refresher must die on EVERY exit path (early `exit 1`s leak it
# forever and it poisons later prunes). Chain with swtpm cleanup; pre-set the
# flag so swtpm_start does not overwrite this trap.
_SWTPM_CLEANUP_TRAP_SET=1
trap 'kill "$REFRESHER" 2>/dev/null; swtpm_cleanup_all 2>/dev/null' EXIT INT TERM

# _wedge_wait <dir> <timeout-s> — the swtpm data-loop WEDGE guard (s02/s04
# mitigation, 2026-09-23; gdb poll-dump root cause: swtpm 0.10.2 de-registers
# the data client when a ctrl-channel client EOFs and never re-adds it — the
# data connection sits with Recv-Q > 0, absent from swtpm's poll set, and the
# guest stalls forever). Wedge signature, sampled every 5 s: qemu alive +
# console.log size unchanged for >60 s + Recv-Q > 0 on <dir>/tpm/sock.
# Recovery: qemu_kill + swtpm_stop + swtpm_start (fresh startup-clear), loud
# WEDGE-RECOVERED line, return 43 (caller retries) / 44 (restart failed);
# 0 = qemu exited on its own.
_wedge_wait() {
    local dir="$1" timeout="$2" pid
    pid=$(cat "$dir/qemu.pid" 2>/dev/null) || return 64
    local deadline=$((SECONDS + timeout)) sz last_sz last_chg
    last_sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
    last_chg=$SECONDS
    while ((SECONDS < deadline)); do
        if ! kill -0 "$pid" 2>/dev/null; then
            pkill -9 -f "python3 - $dir/qmp.sock" 2>/dev/null
            serial_bridge_stop "$dir"
            return 0
        fi
        _qmp_kicker_start "$dir"
        sz=$(stat -c%s "$dir/console.log" 2>/dev/null || echo 0)
        if ((sz != last_sz)); then last_sz=$sz; last_chg=$SECONDS; fi
        if ((SECONDS - last_chg > 60)); then
            if ss -xn 2>/dev/null | awk -v s="$dir/tpm/sock" '$0 ~ s && ($3 + 0) > 0 { found = 1 } END { exit !found }'; then
                echo "WEDGE-RECOVERED: swtpm data-loop stall (console idle >60 s, Recv-Q>0 on $dir/tpm/sock) — killing qemu, restarting swtpm fresh"
                qemu_kill "$dir"
                swtpm_stop "$dir" >/dev/null 2>&1
                if ! swtpm_start "$dir" >/dev/null 2>&1; then
                    echo "WEDGE-RECOVERED: swtpm restart FAILED — caller must abort"
                    return 44
                fi
                return 43
            fi
        fi
        sleep 5
    done
    qemu_kill "$dir"
    return 124
}

STATE="${DEBIAN_FDE_E2E_STATE:-}"
if [[ -n "$STATE" && -f "$STATE/disk.img" && -d "$STATE/tpm" && -f "$STATE/harness.efi" \
    && -f "$STATE/pcrsig.img" && -d "$STATE/keys" && -f "$STATE/vars-enrolled.fd" ]]; then
    echo "# reusing enrolled state from $STATE"
    RUN_ENROLLED="$STATE"
else
    echo "# no s00 state — building + booting it (bootstrap: enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s13: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # bootstrap boot: token-less disk -> the hook's recovery-passphrase path
    # (prompt-synchronized feed: the hook has NO read timeout)
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
        fi
        _wedge_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s13: bootstrap boot attempt $_attempt failed"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s13: bootstrap boot did not reach UNSEALED — state unusable"
        exit 1
    }
    # host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = booted PCR 7, d11 = the build's
    # enter-initrd prediction; the combined {7,11} entry is what the hook
    # extracts for the finalized token.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s13: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s13: no PCR 7 in the bootstrap console"; exit 1; }
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s13: no enter-initrd d11 prediction from the build"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    uki_pcrsig_disk "$RUN_ENROLLED/pcrsig.img" "$RUN_ENROLLED/uki-pcrsig-combined.json" || exit 1
    printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$RUN_ENROLLED/kf-slot0"   # verbatim kf0 (no newline)
    chmod 600 "$RUN_ENROLLED/kf-slot0"
    EFIVARS="$RUN_ENROLLED/efivars-sb-on"
    mkdir -p "$EFIVARS"
    _mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
    _mkvar SecureBoot 1
    _mkvar SetupMode 0
    uki_host_enroll_finalized "$EFIVARS" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$RUN_ENROLLED/disk.img" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/kf-slot0" \
        "$RUN_ENROLLED/cli-state" || {
        echo "s13: production enroll-tpm FAILED"; exit 1; }
    TOK=$(disk_token_json "$RUN_ENROLLED/disk.img")
    assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
    assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'
    swtpm_stop "$RUN_ENROLLED/tpm"
    STATE="$RUN_ENROLLED"
fi

# Snapshot the shared state into OUR run dir: sibling prunes may remove the
# state dir mid-run; from here on this scenario only touches the local copy
# (the swtpm permall carries the seed -> the copy seals to the same SRK).
mkdir -p "$RUN/state"
cp "$STATE/harness.efi" "$RUN/state/"
cp "$STATE/pcrsig.img" "$RUN/state/"
cp "$STATE/disk.img" "$RUN/state/"
cp "$STATE/console.log" "$RUN/state/"
[[ -d "$STATE/keys" ]] && cp -a "$STATE/keys" "$RUN/state/keys"
[[ -f "$STATE/vars-enrolled.fd" ]] && cp "$STATE/vars-enrolled.fd" "$RUN/state/"
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/state/"
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
# REBUILD the payload drive from the state's COMBINED pcrsig json when it
# exists (registry 2026-09-23/24, three runs): the stored pcrsig.img lags the
# finalized combined json (s00b rewrites the json during its majority-vote
# enroll passes), so the drive's {7,11} entry pol != policy_digest(live d7,
# postphase d11) and EVERY zero-input token unlock dies at policyauthorize
# ("the TPM refused the sealed blob") with nothing wrong in the tamper under
# test. The combined json is the seal-time G-B6 authority — rebuild from it.
if [[ -f "$STATE/uki-pcrsig-combined.json" ]]; then
    cp "$STATE/uki-pcrsig-combined.json" "$RUN/state/"
    uki_pcrsig_disk "$RUN/state/pcrsig.img" "$RUN/state/uki-pcrsig-combined.json" || {
        echo "s13: cannot rebuild the state payload drive from the combined pcrsig"; exit 1; }
fi
STATE="$RUN/state"

UKI_MIB=$(( ($(stat -c%s "$STATE/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$STATE/harness.efi" || exit 1
cp "$STATE/vars-enrolled.fd" "$RUN/vars-enrolled.fd"
[[ -f "$STATE/uki-pcrsig.json" ]] && cp "$STATE/uki-pcrsig.json" "$RUN/uki-pcrsig.json"

# --- token fixtures from the REAL enrolled token -------------------------------
cryptsetup token export "$STATE/disk.img" --token-id 0 --json-file "$RUN/token-orig.json" 2>/dev/null \
    || cryptsetup token export "$STATE/disk.img" --json-file "$RUN/token-orig.json"
assert_file_exists "original token exported" "$RUN/token-orig.json"

openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -outform DER -out "$RUN/foreign.der" 2>/dev/null
# DER SPKI, base64 — the token's tpm2-pubkey field is base64(DER), never PEM text
# (a PEM-in-base64 swap is rejected by cryptsetup's token validation)
FOREIGN_PUB_B64=$(base64 -w0 "$RUN/foreign.der")
python3 - "$RUN/token-orig.json" "$FOREIGN_PUB_B64" "$RUN" <<'PYEOF'
import base64, json, os, sys
t = json.load(open(sys.argv[1]))
out = lambda name: os.path.join(sys.argv[3], "tok-" + name + ".json")
# pubkey-swap: ONLY the pubkey replaced by a valid foreign RSA key (the hook
# never reads it — inert by construction, asserted honestly below)
a = dict(t); a["tpm2-pubkey"] = sys.argv[2]
json.dump(a, open(out("pubkey-swap"), "w"))
# blob-corrupt: ONLY the sealed blob corrupted (first byte flipped)
b = base64.b64decode(t["tpm2-blob"])
c = dict(t); c["tpm2-blob"] = base64.b64encode(bytes([b[0] ^ 0xFF]) + b[1:]).decode()
json.dump(c, open(out("blob-corrupt"), "w"))
# sig-corrupt: ONLY the token's tpm2-signature corrupted (inert under the
# entry-sig I3 semantic — first base64 char flipped)
s = dict(t); sig = t["tpm2-signature"]
s["tpm2-signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
json.dump(s, open(out("sig-corrupt"), "w"))
# version-99: otherwise-valid token + unknown field
v = dict(t); v["version"] = 99
json.dump(v, open(out("version-99"), "w"))
print("fixtures written", file=sys.stderr)
PYEOF

# tamper_disk <variant> <disk-copy> — swap in the tampered token (host-side
# attacker primitive; verified unprivileged on a LUKS2 file). The import goes
# through the SAME seam the production enrollment uses (lib/token.sh
# token_import): --disable-external-tokens, because cryptsetup otherwise
# hands the token to the host's systemd-tpm2 PLUGIN for validation — the
# plugin demands the upstream token field set and dies "wrong or missing
# parameters" on the pinned §7.2 dash-form schema BEFORE the metadata ever
# lands (registry 2026-09-23: all four variants failed the import this way).
tamper_disk() {
    local variant="$1" disk="$2"
    cryptsetup token remove --token-id 0 "$disk" 2>/dev/null
    cryptsetup token import "$disk" --token-id 0 --json-file "$RUN/tok-$variant.json" \
        --disable-external-tokens
}

# assert_tamper_landed <variant> — re-export and prove the right field moved
assert_tamper_landed() {
    local variant="$1" disk="$2"
    cryptsetup token export "$disk" --token-id 0 --json-file "$RUN/chk-$variant.json" 2>/dev/null \
        || cryptsetup token export "$disk" --json-file "$RUN/chk-$variant.json"
    python3 - "$RUN/token-orig.json" "$RUN/chk-$variant.json" "$variant" <<'PYEOF'
import base64, json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
v = sys.argv[3]
if v == "pubkey-swap":
    ok = a["tpm2-pubkey"] != b["tpm2-pubkey"] and a["tpm2-blob"] == b["tpm2-blob"] \
         and a["tpm2-signature"] == b["tpm2-signature"]
elif v == "blob-corrupt":
    ok = base64.b64decode(a["tpm2-blob"]) != base64.b64decode(b["tpm2-blob"]) \
         and a["tpm2-pubkey"] == b["tpm2-pubkey"]
elif v == "sig-corrupt":
    ok = a["tpm2-signature"] != b["tpm2-signature"] and a["tpm2-blob"] == b["tpm2-blob"]
elif v == "version-99":
    ok = b.get("version") == 99 and a["tpm2-blob"] == b["tpm2-blob"] \
         and a["tpm2-signature"] == b["tpm2-signature"] \
         and a["tpm2-pubkey"] == b["tpm2-pubkey"]
else:
    ok = False
sys.exit(0 if ok else 1)
PYEOF
}

# refusal classes per variant (observed hook behavior):
#   refused   — the hook refuses the tampered token, then runs its bounded
#               recovery loop to a 3-strike fail-closed poweroff
#   unlock    — the tamper is inert metadata for the hook: the token path
#               proceeds unchanged (documented deviation, see header)
run_variant() {
    local variant="$1" expect="${2:-}"
    local V="$RUN/boot-$variant"
    mkdir -p "$V"
    cp "$STATE/disk.img" "$V/disk.img"
    tamper_disk "$variant" "$V/disk.img" >/dev/null || {
        _assert_result not-ok "$variant: token import (host-side tamper)" "cryptsetup token import failed"
        return 0
    }
    _assert_result ok "$variant: token import (host-side tamper landed)" ""
    if assert_tamper_landed "$variant" "$V/disk.img"; then
        _assert_result ok "$variant: re-export proves the intended field moved" ""
    else
        _assert_result not-ok "$variant: re-export proves the intended field moved" \
            "token JSON after import does not match the fixture intent"
    fi

    swtpm_start "$STATE/tpm" || { echo "s13: swtpm restart ($variant) failed"; exit 1; }
    # _fresh_pcrs — force ZEROED PCRs for this variant's boot (repro-proven
    # 2026-09-24): a preceding variant's CLEAN exit (3-strike poweroff) makes
    # the proxy store the volatile state and this restart RESTORES it into
    # RAM; the boot then EXTENDS OVER the carried values (PCR 0/7/11 all
    # shift) and the token unseal refuses on a PCRs-vs-policy mismatch that
    # has nothing to do with the tamper. Full re-anchor shape (s18's
    # _reanchor_tpm): scrub volatile + sockets, restart, verify zero, warm
    # the proxy path so the guest's first TPM command cannot arrive mid-setup
    # (a dropped measurement is exactly the degraded-register signature).
    swtpm_stop "$STATE/tpm" 2>/dev/null || true
    pkill -9 -f "swtpm socket .*$STATE/tpm/" 2>/dev/null || true
    rm -f "$STATE/tpm/tpm2-00.volatilestate" "$STATE/tpm/.lock" "$STATE/tpm/pid" \
        "$STATE/tpm/proxypid" "$STATE/tpm/sock" "$STATE/tpm/sock.ctrl" \
        "$STATE/tpm/swtpm.ctrl" "$STATE/tpm/swtpm.sock"
    swtpm_start "$STATE/tpm" || { echo "s13: swtpm restart ($variant) failed"; exit 1; }
    _zero=$(printf '0%.0s' {1..64})
    if [[ "$(swtpm_pcrread "$STATE/tpm" 0)" != "$_zero" ]]; then
        echo "s13: TPM not zeroed before the $variant boot — refusing a cumulative register"; exit 1
    fi
    for _rk in 1 2 3 4 5; do
        swtpm_pcrread "$STATE/tpm" 0 >/dev/null 2>&1 || true
        sleep 1
    done
    echo "# booting variant $variant (SB-enrolled vars, TCG, up to $QEMU_TIMEOUT s)"
    qemu_run "$V" "$RUN/esp.img" "$V/disk.img" "$RUN/vars-enrolled.fd" "$STATE/tpm" "$STATE/pcrsig.img"
    if [[ "$expect" == "refused" ]]; then
        # the hook's bounded loop has NO read timeout: feed 3 WRONG answers
        # through the hook's OWN prompt, else the boot could only end in a
        # timeout-kill instead of the 3-strike poweroff
        local n
        for n in 1 2 3; do
            if uki_wait_hook_prompt "$n" 300 "$V"; then
                feed_line "$V/serial.sock" "debian-fde-$variant-wrong-passphrase-$n"
            else
                _assert_result not-ok "$variant: hook awaiting recovery passphrase $n/3" \
                    "no prompt $n in console"
                break
            fi
        done
    fi
    # Consumer-context UKIs (s00b) bake the debug-shell seam: an unlocked boot
    # reaches UNSEALED and then hands the console to the harness DEBUG SHELL
    # instead of powering off (STAGE=boot, no login marker on the snapshot
    # payload). Feed a clean poweroff there instead of burning the whole
    # budget to a timeout-kill. QEMU-LIVENESS: every poll iteration checks
    # the boot's qemu pid.
    if [[ "$expect" != "refused" ]]; then
        local _si=0 _qpid
        while ((_si < 90)); do
            if grep -q "DEBUG SHELL on console" "$V/console.log" 2>/dev/null; then
                feed_line "$V/serial.sock" 'poweroff -f'
                break
            fi
            grep -q "debian-fde: POWEROFF" "$V/console.log" 2>/dev/null && break
            _qpid=$(cat "$V/qemu.pid" 2>/dev/null || true)
            [[ -z "$_qpid" ]] || ! kill -0 "$_qpid" 2>/dev/null && break
            sleep 1
            _si=$((_si + 1))
        done
    fi
    _wedge_wait "$V" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
    local log
    log=$(cat "$V/console.log" 2>/dev/null || true)

    assert_contains "$variant: init ran" "$log" "debian-fde-harness: init started"
    assert_contains "$variant: hook ran the enter-initrd extend" "$log" \
        "$(sentinel_of unseal_pcrextend_ok)"
    assert_contains "$variant: hook discovered the {7,11} token (still valid LUKS2 metadata)" "$log" \
        "$(sentinel_of unseal_token_info)7,11]"
    if [[ "$expect" == "refused" ]]; then
        # the tamper only ever BREAKS unseal — refused fail-closed, never forged
        if grep -qF "$(sentinel_of unseal_sig_refused)" "$V/console.log" 2>/dev/null \
            || grep -qF "$(sentinel_of unseal_seal_refused)" "$V/console.log" 2>/dev/null; then
            _assert_result ok "$variant: hook refused the tampered token (breaks, never forges)" ""
        else
            _assert_result not-ok "$variant: hook refused the tampered token (breaks, never forges)" \
                "neither the I3 signature refusal nor the seal refusal in console"
        fi
        local prompts
        prompts=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$log" || true)
        assert_eq "$variant: exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$prompts"
        assert_contains "$variant: 3-strike give-up (§8.2 fail-closed)" "$log" \
            "$(sentinel_of unseal_3strike)"
        assert_contains "$variant: fail-closed poweroff (no shell is offered)" "$log" \
            "$(sentinel_of unseal_poweroff)"
        assert_not_contains "$variant: never unlocked (token)" "$log" \
            "$(sentinel_of unseal_unlocked)"
        assert_not_contains "$variant: never unlocked (recovery passphrase)" "$log" \
            "$(sentinel_of unseal_pass_unlocked)"
        assert_not_contains "$variant: never UNSEALED" "$log" "debian-fde: UNSEALED"
    else
        # inert-metadata variant: the OBSERVED hook behavior is an unchanged
        # token unlock (documented deviation, see header) — asserted honestly
        assert_contains "$variant: tamper is INERT for the hook (token unlock proceeded)" "$log" \
            "$(sentinel_of unseal_unlocked)"
        assert_contains "$variant: harness UNSEALED sentinel" "$log" "debian-fde: UNSEALED"
        # G-T13/G-E9: boot UNSEALED -> post-hook postphase PCR 11 must equal
        # the booted UKI's signed prediction
        _CONSOLE_SAVE="$CONSOLE"
        CONSOLE="$V/console.log"
        assert_pcr11_prediction "S-13 [$variant]"
        CONSOLE="$_CONSOLE_SAVE"
    fi
    assert_not_contains "$variant: no emergency shell" "$log" "$(sentinel_of emergency_forbidden)"
    # IN-08: honest in both directions (missing pid file is not a clean exit)
    if [[ -f "$V/qemu.pid" ]] && ! kill -0 "$(cat "$V/qemu.pid" 2>/dev/null)" 2>/dev/null; then
        _assert_result ok "$variant: guest exited (own poweroff, not timeout-kill)" ""
    else
        _assert_result not-ok "$variant: guest exited (own poweroff, not timeout-kill)" \
            "qemu still running or qemu.pid missing"
    fi
    swtpm_stop "$STATE/tpm"   # free the state dir for the next variant
    return 0
}

run_variant pubkey-swap unlock   # hook never reads tpm2-pubkey (I3 anchor is /.extra)
run_variant blob-corrupt refused # sealed object dead in the TPM -> bounded loop -> 3-strike
run_variant sig-corrupt unlock   # token-sig inert under the entry-sig I3 semantic (hook
                                 # verifies the DRIVE ENTRY's own release-key signature;
                                 # token-level sig corruption cannot forge or refuse)
run_variant version-99 unlock    # unknown field is inert metadata

# keep run dirs small
rm -rf "$RUN/enroll-boot/guest-tree" "$RUN/enroll-boot/initrd.cpio" \
    "$RUN/enroll-boot/uki-unsigned.efi" "$RUN/enroll-boot/uki-pcrsigned.efi"

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s13-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s13-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
