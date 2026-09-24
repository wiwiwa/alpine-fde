#!/usr/bin/env bash
# tests/e2e/s03-stale-enrollment.sh — §10 row "enrollment missing/stale",
# against the SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT
# unlock). "Stale enrollment" collapses to two concrete fail-closed flavors,
# BOTH proven here:
#
#   flavor 1 — a NEW UKI (6.3.0) built WITHOUT the PCR-signing step (no
#     .pcrsig section: the ADR-8 "signing key absent" mistake). Firmware still
#     boots it (PE signature valid), but NO signed policy exists anywhere —
#     the payload drive is empty and the stub carries no synthetic /.extra
#     sections, so the hook has no /.extra signature/key material at all: the
#     token path never arms and the BOUNDED keyslot-0 recovery loop is the
#     only way forward -> 3 wrong answers -> 3-strike fail-closed poweroff.
#
#   flavor 2 — a VALID UKI + valid .pcrsig, but the token was REMOVED
#     (cryptsetup token remove + luksKillSlot — the host-side stand-in for a
#     wiped enrollment). The hook finds no systemd-tpm2 token on any crypttab
#     member (unseal_token_missing) and CANNOT self-heal — no enrollment
#     machinery exists in the initrd (I6) — so the bounded recovery loop is
#     again the only way forward -> 3 wrong answers -> 3-strike fail-closed
#     poweroff.
#
# §10 expectations both rows: Boots ✅ / Auto-unlock ❌ / fail-closed, never
# unlocked, never an emergency shell. The hook's bounded recovery loop has NO
# read timeout: every refusal boot's 3 wrong answers are fed over serial,
# prompt-synchronized (uki_wait_hook_prompt).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/assert.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/keys-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/disk-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/uki-build.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/prediction.sh"   # assert_pcr11_prediction (G-T13/G-E9)
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck disable=SC1091  # fixtures resolved at runtime via $TESTS
source "$TESTS/lib/qemu.sh"
# shellcheck disable=SC1091
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck disable=SC1091
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)

RUN="$TESTS/e2e/.runs/s03-stale-enrollment-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# CR-02/MD-03: prunes must spare the invocation's chained state dirs
# (ALPINE_FDE_PROTECT_DIRS, exported by run-e2e.sh)
while IFS= read -r _d; do
    case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$_d:"*) continue ;; esac
    rm -rf "$_d"
done < <(find "$TESTS/e2e/.runs" -mindepth 1 -maxdepth 1 -type d -printf "%T@\t%p\n" 2>/dev/null | sort -rn | tail -n +3 | cut -f2-)

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The SRK (storage primary seed) persists in tpm2-00.permall, so seals made by
# a previous boot still unseal after the restart (s01 precedent); PCRs reset
# and are re-measured by the firmware at the next boot — physically faithful.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }

# _wedge_wait <dir> <timeout-s> — qemu_wait + the swtpm data-loop WEDGE guard
# (mitigation 2026-09-23; gdb poll-dump root cause: swtpm 0.10.2 de-registers
# the data client when a ctrl-channel client EOFs and never re-adds it — the
# data connection sits with Recv-Q > 0, absent from swtpm's poll set, and the
# guest stalls forever; s03's 1212 s stall was this class). Wedge signature,
# sampled every 5 s: qemu alive + console.log size unchanged for >60 s +
# Recv-Q > 0 on <dir>/tpm/sock. Recovery: qemu_kill + swtpm_stop + swtpm_start
# (fresh startup-clear), loud WEDGE-RECOVERED line, return 43 (distinct from
# qemu_wait's 0/64/124) so the caller's bounded retry re-runs the boot.
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

# _archive_console <label> — archive THIS boot's own console (qemu_run
# truncates $RUN/console.log at every start, so it is always the boot's own
# bytes) and point CONSOLE at the archive. Never copy a stale $CONSOLE.
_archive_console() {
    cp "$RUN/console.log" "$RUN/console-$1.log"
    CONSOLE="$RUN/console.log"
}

# _pcr7_majority <dir> <console-d7> — bimodal-register defense (the s00b
# class, 2026-09-22): the guest's measured PCR 7 is BIMODAL across boots
# (full vs truncated measurement — deterministic per mode), and a single
# reading cannot say which mode is faithful. Vote 3 LIVE readings from the
# fixture (bounded probes, settled per s18) and print the majority digest;
# abort when no majority exists. The sealed {7,11} policy must anchor the
# register later boots will actually measure, so the majority LIVE value —
# not a possibly-truncated single console print — is the enrollment anchor.
_pcr7_majority() {
    local dir="$1" console_d7="$2" k d7
    local -a readings=()
    for k in 1 2 3; do
        swtpm_pcrread "$dir" 0 >/dev/null 2>&1 || true   # settle probe (s18)
        d7=$(swtpm_pcrread "$dir" 7) && readings+=("$d7")
        sleep 1
    done
    local count pair
    read -r count pair < <(printf '%s\n' "${readings[@]}" | sort | uniq -c | sort -rn | head -1)
    if (( ${count:-0} < 2 )); then
        echo "s03: PCR 7 register vote produced no majority (${readings[*]}) — refusing to seal against an unstable register"
        return 1
    fi
    if [[ "$pair" != "$console_d7" ]]; then
        echo "s03: NOTE console PCR 7 was a minority/truncated reading ($console_d7) — anchoring the enrollment on the majority live register ($pair)"
    fi
    printf '%s\n' "$pair"
}

_esp_set_default() {
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}
_esp_add_uki() {
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name"
}
_host_wipe_enrollment() { # <disk.img> — remove every systemd-tpm2 token + its keyslots
    local img="$1" id slot
    for id in $(disk_token_json "$img" | jq -r 'to_entries[] | select(.value.type == "systemd-tpm2") | .key'); do
        cryptsetup token remove --token-id "$id" --batch-mode "$img" || return 1
    done
    for slot in $(disk_metadata "$img" | jq -r '.keyslots | keys[]'); do
        [ "$slot" = "0" ] && continue   # keep the slot-0 passphrase (recovery slot)
        cryptsetup luksKillSlot --batch-mode "$img" "$slot" || return 1
    done
}

# _feed_3_strike <dir> — feed 3 WRONG answers through the hook's OWN prompt
# (the bounded loop's read has NO timeout: without the synchronized feed the
# boot could only end in a timeout-kill instead of the 3-strike poweroff)
_feed_3_strike() {
    local d="$1" n
    for n in 1 2 3; do
        if uki_wait_hook_prompt "$n" 300 "$d"; then
            _assert_result ok "hook awaiting recovery passphrase $n/3 (hook read path)" ""
            feed_line "$d/serial.sock" "alpine-fde-wrong-passphrase-$n"
        else
            _assert_result not-ok "hook awaiting recovery passphrase $n/3 (hook read path)" \
                "no prompt $n in console"
            break
        fi
    done
}

# _vuki_build <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
# Variant UKI builder. VUKI_NO_PCRSIG=1 skips the ukify PCR-signing pass and
# the .pcrsig extraction (simulates a UKI built with the signing key absent —
# ADR-8's loud-failure condition, here proven fail-closed AT BOOT instead).
# The SHIPPED §8.2 unseal hook is staged at the pinned features.d destination
# (the default unlock path runs exactly this file — ADR-13).
_vuki_build() {
    local st="$1" tree="$2" kd="$3" un="$4" mk="$5" out="$6"
    mkdir -p "$st"
    local item
    for item in usr modules opt; do
        cp -al "$tree/$item" "$st/$item" || return 1
    done
    ln -sfn usr/bin "$st/bin"
    ln -sfn usr/sbin "$st/sbin"
    _uki_link_busybox "$tree"   # the hook's busybox PATH surface (idempotent)
    uki_initrd_write_init "$st"
    printf '# alpine-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$kd/release.pub" "$st/rel.pub"
    local hook_dst="$st/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    mkdir -p "${hook_dst%/*}"
    cp "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" "$hook_dst" || return 1
    chmod 755 "$hook_dst"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=alpine-fde-harness\nVERSION_ID=%s\nNAME=Alpine FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    local -a pcrargs=()
    if [[ -z "${VUKI_NO_PCRSIG:-}" ]]; then
        pcrargs=(--pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub")
    fi
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" "${pcrargs[@]}" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s03: ukify (variant $un) failed" >&2
        return 1
    }
    if [[ -z "${VUKI_NO_PCRSIG:-}" ]]; then
        objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
        uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
    else
        truncate -s 64K "$out.pcrsig.img"   # zero payload: /init reads an empty .pcrsig
    fi
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" "$st.pcrsigned.efi" >/dev/null
}

boot_and_wait() { # <label> <esp> <disk> <vars> <pcrsig-img>
    local label="$1" att wrc
    for att in 1 2; do
        _ensure_tpm || { echo "swtpm not serving"; return 1; }
        echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
        qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5" || {
            echo "s03: qemu_run FAILED for $label; qemu.stderr: $(tail -3 "$RUN/qemu.stderr" 2>/dev/null | tr '\n' ' ')"
            return 1
        }
        _wedge_wait "$RUN" "$QEMU_TIMEOUT"; wrc=$?
        if ((wrc == 43)); then
            echo "s03: $label wedged mid-boot — swtpm restarted fresh, retrying (attempt $att/2)"
            continue
        fi
        _archive_console "$label"
        return 0
    done
    echo "s03: $label still wedged after 1 recovery + retry"
    return 1
}
boot_feed_and_wait() { # <label> <esp> <disk> <vars> <pcrsig-img> — boot + feed
                       # the hook's bounded recovery loop 3 WRONG answers
    local label="$1" att wrc
    for att in 1 2; do
        _ensure_tpm || { echo "swtpm not serving"; return 1; }
        echo "# boot $label: feeding 3 WRONG recovery passphrases (TCG, up to $QEMU_TIMEOUT s) ..."
        qemu_run "$RUN" "$2" "$3" "$4" "$RUN/tpm" "$5" || {
            echo "s03: qemu_run FAILED for $label; qemu.stderr: $(tail -3 "$RUN/qemu.stderr" 2>/dev/null | tr '\n' ' ')"
            return 1
        }
        _feed_3_strike "$RUN"
        _wedge_wait "$RUN" "$QEMU_TIMEOUT"; wrc=$?
        if ((wrc == 43)); then
            echo "s03: $label wedged mid-boot — swtpm restarted fresh, retrying (attempt $att/2)"
            continue
        fi
        _archive_console "$label"
        return 0
    done
    echo "s03: $label still wedged after 1 recovery + retry"
    return 1
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures -----------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s03: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
echo "# building UKI 6.2.0 (enrolled baseline) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s03: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" alpine-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: healthy baseline (token-less disk -> hook recovery path, then
# the HOST-SIDE finalized enrollment) -------------------------------------------
_ensure_tpm || { echo "s03: swtpm not serving"; exit 1; }
echo "# boot v1-enroll: token-less disk, feeding the slot-0 recovery passphrase (TCG, up to $QEMU_TIMEOUT s) ..."
qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/uki-6.2.0.efi.pcrsig.img"
for _attempt in 1 2; do
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$ALPINE_FDE_SLOT0_PASSPHRASE"
    fi
    _wedge_wait "$RUN" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
    grep -q "alpine-fde: UNSEALED" "$CONSOLE" && break
    echo "s03: baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_ensure "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
    _ensure_tpm || { echo "s03: swtpm restart (retry) failed"; exit 1; }
    qemu_run "$RUN" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/uki-6.2.0.efi.pcrsig.img"
done
grep -q "alpine-fde: UNSEALED" "$CONSOLE" || { echo "s03: baseline boot did not reach UNSEALED"; exit 1; }
cp "$CONSOLE" "$RUN/console-v1-enroll.log"
LOG=$(log_of "v1-enroll")
assert_contains "[v1] init ran" "$LOG" "alpine-fde-harness: init started"
assert_contains "[v1] hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[v1] no token yet (fresh disk) — recovery path armed" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[v1] unlocked via the recovery passphrase" "$LOG" "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[v1] UNSEALED" "$LOG" "alpine-fde: UNSEALED"
assert_contains "[v1] clean poweroff" "$LOG" "alpine-fde: POWEROFF"
# G-T13/G-E9 (boot reaches the UKI stub): $RUN/uki-pcrsig.json is 6.2.0's
# signed prediction, the console is this boot's — the hook UNSEALED, so /init
# printed the post-hook postphase PCR 11 reading.
CONSOLE="$RUN/console-v1-enroll.log"
assert_pcr11_prediction "S-03 [v1]"
CONSOLE="$RUN/console.log"

# host-side finalized enrollment (the production CLI): d7 = the boot's PCR 7
# as the console witnessed it (the guest's own measurement IS the machine
# anchor — digest-anchored enroll, Option A: the CLI's drift precondition and
# G-B6 gate are pure data comparisons over the entry's recorded d7/d11, no
# live TPM read), d11 = the build's enter-initrd prediction; the combined
# {7,11} entry is what the hook extracts. The re-anchor first (2026-09-23): a
# boot can leave the fixture wedged for NEW data clients, and an unbounded
# host tpm2 command would hang forever (observed in s02); swtpm_ensure's
# bounded probe + restart keeps the fixture SERVING for the seal's getcap
# probe + SRK operations.
_ensure_tpm || { echo "s03: swtpm re-anchor before enroll failed"; exit 1; }
D11_620=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_620" ]] || { echo "s03: no enter-initrd d11 prediction from the build"; exit 1; }
PCR7_CONSOLE=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-v1-enroll.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_CONSOLE" ]] || { echo "s03: no PCR 7 in the baseline console"; exit 1; }
PCR7_ENROLLED=$PCR7_CONSOLE
uki_baseline_stamp "$RUN/cli-state" "$PCR7_ENROLLED"
uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-combined.json" \
    "$PCR7_ENROLLED" "$D11_620" "$RUN/keys" || exit 1
uki_pcrsig_disk "$RUN/pcrsig.img" "$RUN/uki-pcrsig-combined.json" || exit 1
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-pcrsig-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/cli-state" || {
    echo "s03: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

# --- flavor 1: new UKI with NO .pcrsig -----------------------------------------
echo "# building UKI 6.3.0 WITHOUT PCR signing (no .pcrsig section) ..."
VUKI_NO_PCRSIG=1 _vuki_build "$RUN/stage-6.3.0" "$RUN/guest-tree" "$RUN/keys" 6.3.0 v630 "$RUN/uki-6.3.0.efi" || {
    echo "s03: variant build failed"; exit 1; }
SEC63=$(objdump -h "$RUN/uki-6.3.0.efi" | awk '{print $2}')
assert_not_contains "uki 6.3.0 has NO .pcrsig section (the defect under test)" "$SEC63" ".pcrsig"
assert_rc "uki 6.3.0: sbverify clean (firmware WILL boot it)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.3.0.efi"
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.3.0.efi" alpine-fde-6.3.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.3.0.efi" || exit 1

boot_feed_and_wait "v3-nopcrsig" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.3.0.efi.pcrsig.img"
LOG=$(log_of "v3-nopcrsig")
assert_contains "[v3] init ran (firmware booted the UKI: SB signature valid)" "$LOG" \
    "alpine-fde-harness: init started"
assert_contains "[v3] pcrsig payload missing (no policy to satisfy)" "$LOG" \
    "pcrsig payload MISSING"
assert_not_contains "[v3] no signed policy anywhere: the hook's token path never armed" "$LOG" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "[v3] no unlock of any kind" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[v3] no recovery unlock (wrong answers only)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
PROMPTS_V3=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[v3] exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS_V3"
assert_contains "[v3] 3-strike fail-closed (no standing enrollment to satisfy, no self-heal)" "$LOG" \
    "$(sentinel_of unseal_3strike)"
assert_contains "[v3] fail-closed poweroff (no shell is offered)" "$LOG" "$(sentinel_of unseal_poweroff)"
assert_not_contains "[v3] never unlocked (harness)" "$LOG" "alpine-fde: UNSEALED"
assert_not_contains "[v3] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# NB: NO assert_pcr11_prediction for this boot — the defect under test is the
# ABSENT .pcrsig (no signed prediction exists to compare G-T13 against), and
# the hook fails closed INSIDE its own invocation (no postphase reading).

# --- flavor 2: valid UKI + valid .pcrsig, token removed -------------------------
# The hook CANNOT self-heal: no enrollment machinery exists in the initrd
# (I6) — a wiped enrollment is unrecoverable at boot, and the bounded
# recovery loop is the only way in. The plain 6.2.0 UKI boots (its .pcrsig
# and /.extra key material are complete); the hook simply finds no
# systemd-tpm2 token on any crypttab member.
echo "# removing the enrollment host-side (token + its keyslots) ..."
_host_wipe_enrollment "$RUN/disk.img" || { echo "s03: enrollment wipe failed"; exit 1; }
NTOK=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "token removed from LUKS2 metadata" "0" "$NTOK"
KSLOTS=$(disk_metadata "$RUN/disk.img" | jq -c '.keyslots | keys')
assert_eq "only the slot-0 passphrase remains" '["0"]' "$KSLOTS"

_esp_set_default "$RUN/esp.img" "$RUN/uki-6.2.0.efi" || exit 1
boot_feed_and_wait "v1-notoken" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.2.0.efi.pcrsig.img"
LOG=$(log_of "v1-notoken")
assert_contains "[v1'] init ran (still boots)" "$LOG" "alpine-fde-harness: init started"
assert_contains "[v1'] hook ran the enter-initrd extend (complete .pcrsig + key material)" "$LOG" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[v1'] no token found on any crypttab member (wiped enrollment, no self-heal)" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_not_contains "[v1'] no token policy session ever armed" "$LOG" "$(sentinel_of unseal_token_info)"
assert_not_contains "[v1'] no unlock of any kind" "$LOG" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[v1'] no recovery unlock (wrong answers only)" "$LOG" \
    "$(sentinel_of unseal_pass_unlocked)"
PROMPTS_V1N=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[v1'] exactly 3 recovery-passphrase prompts (bounded loop)" "3" "$PROMPTS_V1N"
assert_contains "[v1'] 3-strike fail-closed" "$LOG" "$(sentinel_of unseal_3strike)"
assert_contains "[v1'] fail-closed poweroff (no shell is offered)" "$LOG" "$(sentinel_of unseal_poweroff)"
assert_not_contains "[v1'] never unlocked (harness)" "$LOG" "alpine-fde: UNSEALED"
assert_not_contains "[v1'] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
# NB: NO assert_pcr11_prediction for this boot — the hook fails closed INSIDE
# its own invocation, so /init never reaches its post-hook postphase reading.

# --- wrap up -------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.3.0"
echo "# flavor verdicts: missing-.pcrsig -> fail-closed; removed-token (the hook cannot"
echo "# self-heal — no enrollment machinery in the initrd, I6) -> fail-closed; the recovery"
echo "# loop stays the ONLY way in, 3-strike fail-closed on wrong answers."
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s03-stale-enrollment: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s03-stale-enrollment: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
