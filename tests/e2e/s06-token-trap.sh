#!/usr/bin/env bash
# tests/e2e/s06-token-trap.sh — §12 trap case (invariant I3):
#   "SB off + tampered token metadata + otherwise-legitimate PCR 11 signature
#    => unseal must still fail".
#
# The LUKS2 header travels with the disk, so an attacker can flip Secure Boot
# off AND rewrite the token JSON (host-side: cryptsetup token remove + token
# import) while the release-key-signed .pcrsig stays perfectly valid. The
# token's `tpm2-pubkey` here is swapped for a VALID foreign RSA public key —
# the most plausible-looking tamper. It cannot grant: the PolicyAuthorize
# keyName anchor lives INSIDE the sealed blob, so a substituted key can only
# break the policy (I3: token JSON is untrusted).
#
# Against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock) the pubkey swap itself is INERT (documented deviation from the
# 257.13 oracle, first pinned by s13: the hook never reads tpm2-pubkey — its
# policy anchor is the signed /.extra .pcrsig + public key). The trap still
# fails closed, on its OTHER leg: SB off drifts PCR 7 away from the value the
# finalized {7,11} token was enrolled under -> the hook's PolicyPCR({7,11})
# session digest no longer matches the signed combined .pcrsig entry ->
# tpm2_unseal refuses (unseal_seal_refused) -> the hook's BOUNDED keyslot-0
# recovery-passphrase loop -> three wrong answers -> 3-strike fail-closed
# `poweroff -f`. NO shell is ever offered.
#
# REQUIRED (hook sentinels, tests/sentinels-260.2.txt Section 1): tampered
#           token verified host-side (pubkey swapped, blob/policy-hash/srk
#           intact), unseal_token_info (the tampered token is still valid
#           LUKS2 metadata: pcrs=[7,11]), unseal_seal_refused BEFORE the
#           first prompt, exactly 3 prompts fed, unseal_3strike,
#           unseal_poweroff; unseal_unlocked / unseal_pass_unlocked /
#           UNSEALED NEVER; PCR 7 drifted + PCR 11 unchanged (scoping: the
#           refusal is the SB-off drift, never a grant); no emergency shell;
#           guest exited by its own poweroff.
#
# NB (G-T13): NO assert_pcr11_prediction on this boot — the hook fails closed
# INSIDE its own invocation, so /init never reaches its post-hook postphase
# PCR 11 reading; the PCR 11 unchanged-equality vs the enrolled console is
# the equivalent tamper-scoping evidence.
#
# Reuses the enrolled s00b state when DEBIAN_FDE_E2E_STATE points at the s00b
# run dir (run-e2e.sh sets it); otherwise builds + enrolls it itself
# (bootstrap boot + host-side production enroll, then the trap boot).

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

RUN="$TESTS/e2e/.runs/s06-lite-$(date +%s)"
mkdir -p "$RUN"
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
# WEDGE-RECOVERED line, return 43 so the caller's bounded retry re-runs the
# boot; 44 = recovery restart failed; 0 = qemu exited on its own.
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
    && -f "$STATE/pcrsig.img" && -f "$STATE/console.log" && -d "$STATE/keys" \
    && -f "$STATE/vars-enrolled.fd" ]]; then
    echo "# reusing enrolled state from $STATE"
else
    echo "# no state — self-bootstrapping (boot 1 of 2: baseline boot + host-side enroll under SB-on vars)"
    RUN_ENROLLED="$RUN/enroll-boot"
    mkdir -p "$RUN_ENROLLED"
    swtpm_start "$RUN_ENROLLED/tpm" || { echo "s06: swtpm failed"; exit 1; }
    keys_create "$RUN_ENROLLED/keys"
    uki_release_key_floor "$RUN_ENROLLED/keys" || exit 1   # ADR-16 floor for enroll
    keys_vars_enrolled "$RUN_ENROLLED/keys" "$RUN_ENROLLED/vars-enrolled.fd" || exit 1
    uki_build "$RUN_ENROLLED" "$RUN_ENROLLED/keys" "$RUN_ENROLLED/harness.efi" || exit 1
    UKI_MIB=$(( ($(stat -c%s "$RUN_ENROLLED/harness.efi") + 1048575) / 1048576 ))
    ESP_MIB=$(( UKI_MIB * 2 + 8 ))
    esp_make "$RUN_ENROLLED/esp.img" "$ESP_MIB" "$RUN_ENROLLED/harness.efi" || exit 1
    disk_make_luks "$RUN_ENROLLED/disk.img" 128 || exit 1
    # ---- baseline boot: token-less disk -> the hook's recovery-passphrase
    # path is the ONLY way in (prompt-synchronized feed: the hook has NO read
    # timeout). The disk restarts blank on retry and /init re-runs the same
    # flow; the TPM must be RESET so PCR 11 carries only one phase extension,
    # else the .pcrsig never matches the later token unlock.
    for _attempt in 1 2; do
        qemu_run "$RUN_ENROLLED" "$RUN_ENROLLED/esp.img" "$RUN_ENROLLED/disk.img" \
            "$RUN_ENROLLED/vars-enrolled.fd" "$RUN_ENROLLED/tpm" "$RUN_ENROLLED/pcrsig.img"
        if uki_wait_hook_prompt 1 300 "$RUN_ENROLLED"; then
            feed_line "$RUN_ENROLLED/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
        fi
        _wedge_wait "$RUN_ENROLLED" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
        grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" && break
        echo "s06: baseline boot attempt $_attempt failed"
        echo "--- console bytes: $(stat -c%s "$RUN_ENROLLED/console.log" 2>/dev/null || echo missing)"
        echo "--- qemu.stderr (tail):"
        tail -10 "$RUN_ENROLLED/qemu.stderr" 2>/dev/null
        if ((_attempt < 2)); then
            swtpm_reset "$RUN_ENROLLED/tpm" && swtpm_start "$RUN_ENROLLED/tpm" || exit 1
            rm -f "$RUN_ENROLLED/console.log"
        fi
    done
    grep -q "debian-fde: UNSEALED" "$RUN_ENROLLED/console.log" || {
        echo "s06: baseline boot did not reach UNSEALED — state unusable"
        exit 1
    }

    # ---- host-side finalized enrollment (the production CLI;
    # digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted
    # console's PCR 7, d11 = the build's enter-initrd prediction; the combined
    # {7,11} entry is what the hook extracts for the finalized token.
    swtpm_ensure "$RUN_ENROLLED/tpm" || { echo "s06: swtpm restart failed"; exit 1; }
    PCR7_ENROLLED=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN_ENROLLED/console.log" | head -1 | cut -d= -f2)
    [[ -n "$PCR7_ENROLLED" ]] || { echo "s06: no PCR 7 in the baseline console"; exit 1; }
    uki_baseline_stamp "$RUN_ENROLLED/cli-state" "$PCR7_ENROLLED"
    D11=$(cat "$RUN_ENROLLED/pcr11-enter-initrd.txt" 2>/dev/null)
    [[ -n "$D11" ]] || { echo "s06: no enter-initrd d11 prediction from the build"; exit 1; }
# digest-anchored enroll (Option A): no reseeding — the CLI compares the
# entry's recorded d7/d11 against the baseline (pure data, no live TPM read).
    uki_pcrsig_append_combined "$RUN_ENROLLED/uki-pcrsig.json" "$RUN_ENROLLED/uki-pcrsig-combined.json" \
        "$PCR7_ENROLLED" "$D11" "$RUN_ENROLLED/keys" || exit 1
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
        echo "s06: production enroll-tpm FAILED"; exit 1; }
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
mkdir -p "$RUN/state/tpm"
cp "$STATE/tpm/tpm2-00.permall" "$RUN/state/tpm/" 2>/dev/null || true
STATE="$RUN/state"

# --- host-side tamper: swap the token's tpm2-pubkey for a foreign RSA key -----
# (verified empirically: a token assigned to an active keyslot is "in use" —
# remove + re-import at the same id is the attacker's write primitive; both
# are unprivileged metadata ops on a LUKS2 file.)
cp "$STATE/disk.img" "$RUN/disk.img"
cryptsetup token export "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-orig.json"
assert_file_exists "token exported (original)" "$RUN/token-orig.json"

openssl genrsa -out "$RUN/foreign.key" 2048 2>/dev/null
openssl pkey -in "$RUN/foreign.key" -pubout -outform DER -out "$RUN/foreign.der" 2>/dev/null
# DER SPKI, base64 — the token's tpm2-pubkey field is base64(DER), never PEM text
# (a PEM-in-base64 swap is rejected by cryptsetup's token validation)
FOREIGN_B64=$(base64 -w0 "$RUN/foreign.der")
python3 - "$RUN/token-orig.json" "$RUN/token-trap.json" "$FOREIGN_B64" <<'PYEOF'
import json, sys
t = json.load(open(sys.argv[1]))
# NB: cryptsetup's token export uses the DASH form (tpm2-pubkey etc.) — the
# lib/token.sh schema. (An earlier revision read t["tpm2-pubkey"] and
# KeyError'd, so the tamper never landed and the trap booted with NO token.)
orig = t["tpm2-pubkey"]
assert orig != sys.argv[3], "foreign pubkey must differ from the enrolled one"
t["tpm2-pubkey"] = sys.argv[3]  # ONLY the pubkey is swapped
json.dump(t, open(sys.argv[2], "w"))
PYEOF
cryptsetup token remove --token-id 0 "$RUN/disk.img" 2>/dev/null
assert_rc "tampered token imported at id 0" 0 \
    cryptsetup token import "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-trap.json" --disable-external-tokens
cryptsetup token export "$RUN/disk.img" --token-id 0 --json-file "$RUN/token-check.json"
if python3 - "$RUN/token-orig.json" "$RUN/token-check.json" <<'PYEOF'
import json, sys
a = json.load(open(sys.argv[1]))
b = json.load(open(sys.argv[2]))
ok = (a["tpm2-pubkey"] != b["tpm2-pubkey"]
      and a["tpm2-blob"] == b["tpm2-blob"]
      and a["tpm2-pcrs"] == b["tpm2-pcrs"]
      and a["tpm2-pcr-bank"] == b["tpm2-pcr-bank"]
      and a["tpm2-signature"] == b["tpm2-signature"])
sys.exit(0 if ok else 1)
PYEOF
then
    _assert_result ok "host-side tamper landed: ONLY tpm2-pubkey swapped (blob/policy-hash/srk intact)" ""
else
    _assert_result not-ok "host-side tamper landed: ONLY tpm2-pubkey swapped" "unexpected token JSON after re-import"
fi

# swtpm: the SRK must be the one the token is sealed to -> reuse the state dir
swtpm_start "$STATE/tpm" || { echo "s06: swtpm restart failed"; exit 1; }
cp "$STATE/harness.efi" "$RUN/harness.efi"
cp "$STATE/pcrsig.img" "$RUN/pcrsig.img"   # the .pcrsig remains perfectly VALID
# SB off: the trap combines a firmware-level downgrade with the metadata tamper
keys_vars_unenrolled "$STATE/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "unenrolled vars: no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 2 + 8 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/harness.efi" || exit 1

# --- boot the trap: SB off + tampered token + valid .pcrsig ---------------------
echo "# booting the trap: SB-off vars + pubkey-swapped token + valid .pcrsig, feeding 3 WRONG passphrases (TCG, up to $QEMU_TIMEOUT s) ..."
TRAP_OK=0
for _att in 1 2; do
    swtpm_ensure "$STATE/tpm" || { echo "s06: swtpm not serving (trap boot attempt $_att)"; exit 1; }
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-unenrolled.fd" "$STATE/tpm" "$RUN/pcrsig.img" || {
        echo "s06: qemu_run FAILED for the trap boot (rc=$?)" >&2
        exit 1; }
    # the hook's bounded loop has NO read timeout: feed 3 WRONG answers through
    # the hook's OWN prompt (uki_wait_hook_prompt), else the boot could only end
    # in a timeout-kill instead of the 3-strike poweroff
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 300 "$RUN"; then
            _assert_result ok "hook awaiting recovery passphrase $n/3 (hook read path)" ""
            feed_line "$RUN/serial.sock" "debian-fde-wrong-passphrase-$n"
        else
            _assert_result not-ok "hook awaiting recovery passphrase $n/3 (hook read path)" \
                "no prompt $n in console"
            break
        fi
    done
    wrc=0
    _wedge_wait "$RUN" "$QEMU_TIMEOUT" || wrc=$?
    if ((wrc == 43)); then
        echo "s06: trap boot wedged mid-boot (swtpm data-loop stall) — swtpm restarted fresh, retrying (attempt $_att/2)"
        continue
    fi
    TRAP_OK=1
    break
done
if ((TRAP_OK != 1)); then
    echo "s06: trap boot still wedged after 1 recovery + retry — console kept: $CONSOLE"
    exit 1
fi
LOG=$(cat "$CONSOLE" 2>/dev/null || true)

# --- PCR forensics -------------------------------------------------------------
pcr_of() { grep -oE "debian-fde-pcr sha256:$2=[0-9a-f]{64}" "$1" 2>/dev/null | head -1 | cut -d= -f2; }
PCR7=$(pcr_of "$CONSOLE" 7)
PCR7_ENROLLED=$(pcr_of "$STATE/console.log" 7)
PCR11=$(pcr_of "$CONSOLE" 11)
PCR11_ENROLLED=$(pcr_of "$STATE/console.log" 11)

# --- assertions ---------------------------------------------------------------
assert_contains "init ran (SB off boots the UKI)" "$LOG" "debian-fde-harness: init started"
assert_contains "hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "token discovered by the hook (tampered token is still valid LUKS2 metadata)" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
if [[ -n "$PCR7" && "$PCR7" != "$PCR7_ENROLLED" ]]; then
    _assert_result ok "PCR 7 drifted vs enrolled boot (the SB-off leg of the trap)" ""
else
    _assert_result not-ok "PCR 7 drifted vs enrolled boot (the SB-off leg of the trap)" \
        "PCR7=$PCR7 enrolled=$PCR7_ENROLLED"
fi
assert_eq "PCR 11 unchanged (the refusal is purely the SB-off PCR 7 drift)" "$PCR11_ENROLLED" "$PCR11"
# ordering proof: the hook's refusal strictly precedes its first passphrase
# prompt (the recovery loop may only arm AFTER the token path failed)
_ref_line=$(grep -nm1 -F "$(sentinel_of unseal_seal_refused)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
_p1_line=$(grep -nm1 -E "$(sentinel_of unseal_prompt_re)" "$CONSOLE" 2>/dev/null | cut -d: -f1)
if [[ -n "${_ref_line:-}" && -n "${_p1_line:-}" ]] && (( _ref_line < _p1_line )); then
    _assert_result ok "hook refused the sealed blob BEFORE any passphrase prompt (line $_ref_line < $_p1_line)" ""
else
    _assert_result not-ok "hook refused the sealed blob BEFORE any passphrase prompt" \
        "ref=$_ref_line prompt1=$_p1_line"
fi
assert_contains "unseal refused (swapped pubkey cannot grant; the {7,11} session refuses on the PCR 7 drift)" "$LOG" \
    "$(sentinel_of unseal_seal_refused)"
PROMPTS=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS"
assert_contains "3-strike give-up (§8.2 fail-closed)" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "fail-closed poweroff (no shell is offered)" "$LOG" "$(sentinel_of unseal_poweroff)"
assert_not_contains "never unlocked via the TPM token" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "never unlocked via the recovery passphrase" "$LOG" "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "never UNSEALED (harness sentinel)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# IN-08: an absent pid file (qemu_run failed outright) must not read as a
# clean "guest exited" — the check is honest in both directions
if [[ -f "$RUN/qemu.pid" ]] && ! kill -0 "$(cat "$RUN/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "guest exited (hook poweroff -f, not timeout-kill)" ""
else
    _assert_result not-ok "guest exited (hook poweroff -f, not timeout-kill)" \
        "qemu still running or qemu.pid missing"
fi

echo "# run dir: $RUN"
kill "$REFRESHER" 2>/dev/null
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s06-lite: PASS ($TESTS_PASS assertions)"
    exit 0
fi
echo "# s06-lite: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)))"
exit 1
