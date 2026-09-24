#!/usr/bin/env bash
# tests/e2e/s02-rollback.sh — §9.3 rollback after failed upgrade, against the
# SHIPPED mkinitfs unseal hook (§8.2; ADR-13 — the harness DEFAULT unlock).
#
# ESP holds TWO release-key-signed UKIs:
#   * 6.2.0 — built first, booted, enrolled HOST-SIDE via the production CLI
#     (finalized {PCR 7, PCR 11} Mechanism B token; the sealed blob anchors
#     the release keyName, so the PCR constraint comes from the release-signed
#     combined .pcrsig entry, §6.1.1);
#   * 6.1.0 — an OLDER UKI rebuilt with ukify afterwards (different .initrd
#     marker line + .osrel VERSION_ID + .uname -> genuinely different PCR 11
#     section chain -> different signed pols), NEVER enrolled.
# Rollback action = make the older UKI the boot default (mtools default swap —
# the LITE stand-in for systemd-boot loader.conf/bootnext) + ship 6.1.0's OWN
# release-signed combined {7,11} entry over (booted d7, 6.1.0's enter-initrd
# d11) on the payload drive — the vendor's rollback signature, computed
# host-side with uki_pcrsig_append_combined (the same recipe pcrsign uses;
# a ladder-only drive would leave the hook no {7,11} entry to admit).
#
# Boot 2 (6.1.0) must reach `debian-fde: UNSEALED` with ZERO new enrollment
# and ZERO console input: the hook's PolicyAuthorize pivots on the release
# keyName and admits 6.1.0's freshly delivered combined entry, whose pol
# covers the LIVE PCR state under the older kernel. §10 row "old retained
# kernel (rollback)": rollback remains passwordless, TPM-free.
#
# Assertions (host side, after each boot): both UKI files present on the ESP
# and sbverify-clean; LUKS2 metadata (tokens + keyslots) byte-identical across
# boot 2 — rollback enrolled nothing.
#
# Artifacts: <rundir>/console-{6.2.0-enroll,6.1.0-rollback}.log + images.

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
# shellcheck disable=SC1091
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base locking

RUN="$TESTS/e2e/.runs/s02-rollback-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
T0=$SECONDS

# prune .runs aggressively (disk ~90%): keep the 2 newest run dirs overall —
# but NEVER the invocation's chained state dirs (CR-02/MD-03: run-e2e exports
# DEBIAN_FDE_PROTECT_DIRS; deleting them defeated §12 chaining and made the
# final artifact scan report "nothing to scan" on a green run)
while IFS= read -r _d; do
    case ":${DEBIAN_FDE_PROTECT_DIRS:-}:" in *":$_d:"*) continue ;; esac
    rm -rf "$_d"
done < <(find "$TESTS/e2e/.runs" -mindepth 1 -maxdepth 1 -type d -printf "%T@\t%p\n" 2>/dev/null | sort -rn | tail -n +3 | cut -f2-)

# The swtpm fixture TERMINATES when a boot's qemu exits cleanly (ctrl-channel
# disconnect) — restart it on the same state dir before every TPM touch/boot.
# The SRK (storage primary seed) persists in tpm2-00.permall, so seals made by
# a previous boot still unseal after the restart (s01 precedent); PCRs reset
# and are re-measured by the firmware at the next boot — physically faithful.
# IN-03: the restart path itself lives in the fixture (swtpm_ensure).
_ensure_tpm() { swtpm_ensure "$RUN/tpm"; }
# _fresh_pcrs — force ZEROED PCRs for the NEXT qemu boot (repro-proven
# 2026-09-24): after a boot exits CLEANLY the swtpm proxy stores the volatile
# state and the fixture's restart RESTORES it into RAM; a boot served by that
# restored instance EXTENDS OVER the previous boot's final values (PCR
# 0/7/11 all shift — "register instability") and the rollback boot's {7,11}
# policy can never match the enrollment. swtpm_stop + swtpm_start (the
# second start finds no volatile file) restores the documented per-boot
# zeroed-PCR semantics. The host-side enroll window reads the booted values
# BEFORE this guard runs.
_fresh_pcrs() {
    local dir="$RUN/tpm" d0 k
    swtpm_stop "$dir" 2>/dev/null || true
    # a HALF-STARTED instance (readiness probe failed) still holds the state
    # dir's .lock and would make the restart below fail — kill it scoped to
    # this run dir and clear every socket/lock file it left behind
    pkill -9 -f "swtpm socket .*$dir/" 2>/dev/null || true
    rm -f "$dir/tpm2-00.volatilestate" "$dir/.lock" "$dir/pid" "$dir/proxypid" \
        "$dir/sock" "$dir/sock.ctrl" "$dir/swtpm.ctrl" "$dir/swtpm.sock"
    swtpm_start "$dir" || { echo "s02: swtpm restart failed"; return 1; }
    d0=$(swtpm_pcrread "$dir" 0)
    if [[ ! "$d0" =~ ^0{64}$ ]]; then
        echo "s02: TPM not zeroed before a boot (pcr0=$d0) — refusing a cumulative register"; return 1
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

# _wedge_wait <dir> <timeout-s> — qemu_wait + the swtpm data-loop WEDGE guard
# (mitigation 2026-09-23; gdb poll-dump root cause: swtpm 0.10.2 de-registers
# the data client when a ctrl-channel client EOFs and never re-adds it — the
# data connection sits with Recv-Q > 0, absent from swtpm's poll set, and the
# guest stalls forever). Wedge signature, sampled every 5 s: qemu alive +
# console.log size unchanged for >60 s + Recv-Q > 0 on <dir>/tpm/sock.
# Recovery: qemu_kill + swtpm_stop + swtpm_start (fresh startup-clear), loud
# WEDGE-RECOVERED line, return 43 (distinct from qemu_wait's 0/64/124) so the
# caller's bounded retry re-runs the boot; 44 = recovery restart failed.
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

# --- ESP helpers (mtools on the file-backed image; no systemd-boot this wave) --
_esp_add_uki() { # <esp.img> <uki.efi> <name.efi> — conventional ::/EFI/Linux/ entry
    local esp="$1" uki="$2" name="$3"
    mmd -i "$esp" ::/EFI/Linux 2>/dev/null
    mdel -i "$esp" "::/EFI/Linux/$name" 2>/dev/null
    mcopy -i "$esp" "$uki" "::/EFI/Linux/$name"
}
_esp_set_default() { # <esp.img> <uki.efi> — swap the removable-path default
    local esp="$1" uki="$2"
    mdel -i "$esp" ::/EFI/BOOT/BOOTX64.EFI 2>/dev/null
    mcopy -i "$esp" "$uki" ::/EFI/BOOT/BOOTX64.EFI
}
_esp_ls() { mdir -i "$1" -/ :: ::/EFI 2>/dev/null; }
_meta_snapshot() { # <disk.img> <out.json> — canonical metadata dump (identity asserts)
    disk_metadata "$1" | jq -S . >"$2"
}

# _vuki_measure <st> <tree> <kd> — the variant initrd's enter-initrd PCR 11
# prediction (ukify --measure over the SAME inputs the signed build uses;
# the §8.2 hook's single phase extend re-derives exactly this value at boot).
# The kernel is the SHARED guest-tree one (the variant differs only in
# initrd/cmdline/uname). (Was "$st-tree/vmlinuz" — a literal
# "<stage-dir>-tree" path that never exists; caught live 2026-09-23.)
_vuki_measure() { # <stage-dir> <guest-tree> <keys-dir> <uname> -> writes <stage-dir>.pcr11.txt
    local st="$1" tree="$2" kd="$3" un="$4"
    # --uname MUST match the signed build exactly: systemd-stub measures the
    # .uname section into PCR 11, so a measure over the autodetected uname
    # predicts a DIFFERENT d11 than the 6.1.0 UKI actually produces (observed
    # live 2026-09-23: hook refusal + recovery prompt on the rollback boot).
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --measure --phases enter-initrd --pcr-banks=sha256 \
        --pcr-private-key="$kd/db.key" >"$st.measure.txt" 2>&1 || {
        echo "s02: ukify --measure (variant enter-initrd prediction) failed:" >&2
        cat "$st.measure.txt" >&2
        return 1
    }
    sed -n 's/^11:sha256=\([0-9a-f]\{64\}\)$/\1/p' "$st.measure.txt" | head -1 >"$st.pcr11.txt"
    [[ -s "$st.pcr11.txt" ]] || { echo "s02: cannot parse the variant --measure output" >&2; return 1; }
}

# _vuki_build <stage-dir> <v1-tree> <keys-dir> <uname> <marker> <out.efi>
# Variant UKI builder (replicates uki_build's pack+ukify+objcopy+sbsign steps
# with a DIFFERENT measured content: init marker line, real .osrel, --uname —
# task-mandated because tests/lib/ is outside this scenario's ownership).
# The SHIPPED §8.2 unseal hook is staged at the pinned features.d destination
# (the default unlock path runs exactly this file — ADR-13), and the variant's
# own enter-initrd d11 prediction lands next to <out> as
# <out>.pcr11-enter-initrd.txt. Convention: <out>.pcrsig.img / <out>.pcrsig.json
# sit next to <out>.
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
    printf '# debian-fde variant: %s\n' "$mk" >>"$st/init"
    printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$st/kf0"
    chmod 600 "$st/kf0"
    cp "$kd/release.pub" "$st/rel.pub"
    # THE SHIPPED HOOK (§8.2/ADR-13 staging contract) — without it the variant
    # initrd has no unlock machinery at all
    local hook_dst="$st/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    mkdir -p "${hook_dst%/*}"
    cp "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" "$hook_dst" || return 1
    chmod 755 "$hook_dst"
    uki_initrd_pack "$st" "$st.cpio" || return 1
    printf 'ID=debian-fde-harness\nVERSION_ID=%s\nNAME=Debian FDE harness UKI\n' "$un" >"$st/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE" >"$st/cmdline.txt"
    _vuki_measure "$st" "$tree" "$kd" "$un" || return 1
    cp "$st.pcr11.txt" "$out.pcr11-enter-initrd.txt"
    ukify build --linux="$tree/vmlinuz" --initrd="$st.cpio" \
        --cmdline="@$st/cmdline.txt" --os-release="@$st/os-release.txt" \
        --uname="$un" \
        --pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub" \
        --output="$st.pcrsigned.efi" >/dev/null || {
        echo "s02: ukify (variant $un) failed" >&2
        return 1
    }
    objcopy -O binary --only-section=.pcrsig "$st.pcrsigned.efi" "$out.pcrsig.json" || return 1
    uki_pcrsig_disk "$out.pcrsig.img" "$out.pcrsig.json" || return 1
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" "$st.pcrsigned.efi" >/dev/null
}

boot_and_wait() { # <label> <esp> <disk> <vars> <pcrsig-img> — zero-input boot
    local label="$1"
    local att wrc
    for att in 1 2; do
        _ensure_tpm || { echo "swtpm not serving"; return 1; }
        _fresh_pcrs || { echo "cannot zero the TPM PCRs for $label"; return 1; }
        # Wave-2 2b: the boot runs on a fresh QCOW2 overlay over the enrolled
        # base ($3, LOCK_SH via overlay_create) — discarded after the attempt,
        # so the rollback can never persist anything to the shared base (the
        # metadata identity asserts below pin that).
        OVERLAY_RW="$RUN/disk-$label-$att.qcow2"
        overlay_create "$3" "$OVERLAY_RW" || {
            echo "s02: overlay create failed for $label"; return 1
        }
        echo "# boot $label (TCG, up to $QEMU_TIMEOUT s) ..."
        # QEMU-LIVENESS (2026-09-23): a silent qemu_run failure (or a qemu_wait
        # timeout/kill) used to fall through to `cp` — copying the PREVIOUS boot's
        # console as this label's evidence (observed: console-6.1.0-rollback.log
        # was byte-identical to the enroll console, so every [6.1.0] assert ran
        # against the WRONG boot). Fail loudly instead, never assert stale bytes.
        if ! qemu_run "$RUN" "$2" "$OVERLAY_RW" "$4" "$RUN/tpm" "$5"; then
            echo "s02: qemu_run FAILED for $label (rc=$?); qemu.stderr:" >&2
            tail -5 "$RUN/qemu.stderr" 2>/dev/null >&2
            overlay_discard "$OVERLAY_RW"
            return 1
        fi
        wrc=0
        _wedge_wait "$RUN" "$QEMU_TIMEOUT" || wrc=$?
        overlay_discard "$OVERLAY_RW"   # the attempt's overlay is ephemeral
        if ((wrc == 0)); then
            # archive THIS boot's own console (always the canonical $RUN/console.log
            # that qemu_run truncates at start) and leave CONSOLE pointing at it.
            # NEVER `cp "$CONSOLE"`: the prediction asserts below re-point CONSOLE at
            # an ARCHIVED log, and a stale CONSOLE here silently re-archived the
            # PREVIOUS boot's console as this label's evidence (observed live
            # 2026-09-23: console-6.1.0-rollback.log was byte-identical to the enroll
            # console, so every [6.1.0] assert ran against the WRONG boot).
            cp "$RUN/console.log" "$RUN/console-$label.log"
            CONSOLE="$RUN/console.log"
            return 0
        fi
        if ((wrc == 43)); then
            echo "s02: $label wedged mid-boot (swtpm data-loop stall) — swtpm restarted fresh, retrying (attempt $att/2)"
            continue
        fi
        echo "s02: qemu_wait rc=$wrc for $label (timeout-kill, early qemu death, or wedge-recovery restart failure); console tail:" >&2
        tail -3 "$CONSOLE" 2>/dev/null >&2
        return 1
    done
    echo "s02: $label still wedged after 1 recovery + retry"
    return 1
}
log_of() { cat "$RUN/console-$1.log" 2>/dev/null || true; }

# --- fixtures -----------------------------------------------------------------
swtpm_start "$RUN/tpm" || { echo "s02: swtpm failed"; exit 1; }
keys_create "$RUN/keys"
uki_release_key_floor "$RUN/keys" || exit 1   # ADR-16 floor for enroll
keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd" || exit 1
assert_contains "enrolled vars: SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"

echo "# building UKI 6.2.0 (current, will be enrolled host-side) ..."
uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" || { echo "s02: uki_build failed"; exit 1; }
cp "$RUN/harness.efi" "$RUN/uki-6.2.0.efi"
cp "$RUN/uki-pcrsig.json" "$RUN/uki-6.2.0.efi.pcrsig.json"   # unify the naming convention
cp "$RUN/pcrsig.img" "$RUN/uki-6.2.0.efi.pcrsig.img"
assert_file_exists "uki 6.2.0: .pcrsig extracted" "$RUN/uki-6.2.0.efi.pcrsig.json"

UKI_MIB=$(( ($(stat -c%s "$RUN/uki-6.2.0.efi") + 1048575) / 1048576 ))
ESP_MIB=$(( UKI_MIB * 3 + 12 ))   # two UKIs + headroom
esp_make "$RUN/esp.img" "$ESP_MIB" "$RUN/uki-6.2.0.efi" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.2.0.efi" debian-fde-6.2.0.efi || exit 1
disk_make_luks "$RUN/disk.img" 128 || exit 1

# --- boot 1: 6.2.0 baseline (token-less disk -> the hook's recovery path) ------
_ensure_tpm || { echo "s02: swtpm not serving"; exit 1; }
echo "# boot 6.2.0-enroll: token-less disk, feeding the slot-0 recovery passphrase (TCG, up to $QEMU_TIMEOUT s) ..."
# Wave-2 2b: every attempt boots a fresh QCOW2 overlay over the pristine base
# (base LOCK_SH via overlay_create; the overlay is discarded after the
# attempt — a retry is free and the base stays pristine for the enrollment)
OVERLAY_B1="$RUN/disk-enroll-1.qcow2"
overlay_create "$RUN/disk.img" "$OVERLAY_B1" || { echo "s02: overlay create failed"; exit 1; }
qemu_run "$RUN" "$RUN/esp.img" "$OVERLAY_B1" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/uki-6.2.0.efi.pcrsig.img"
# the hook's read has NO timeout: prompt-synchronized feed (positive control
# for the recovery path; the token enrollment happens HOST-SIDE afterwards)
for _attempt in 1 2; do
    if uki_wait_hook_prompt 1 300 "$RUN"; then
        feed_line "$RUN/serial.sock" "$DEBIAN_FDE_SLOT0_PASSPHRASE"
    fi
    _wedge_wait "$RUN" "$QEMU_TIMEOUT" || true   # 43: swtpm already restarted fresh
    overlay_discard "$OVERLAY_B1"   # the attempt's overlay is ephemeral
    grep -q "debian-fde: UNSEALED" "$CONSOLE" && break
    echo "s02: baseline boot attempt $_attempt failed"
    ((_attempt < 2)) && { swtpm_ensure "$RUN/tpm" || exit 1; }
    rm -f "$CONSOLE"
    _ensure_tpm || { echo "s02: swtpm restart (retry) failed"; exit 1; }
    OVERLAY_B1="$RUN/disk-enroll-$_attempt.qcow2"
    overlay_create "$RUN/disk.img" "$OVERLAY_B1" || { echo "s02: overlay create failed"; exit 1; }
    qemu_run "$RUN" "$RUN/esp.img" "$OVERLAY_B1" "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/uki-6.2.0.efi.pcrsig.img"
done
grep -q "debian-fde: UNSEALED" "$CONSOLE" || { echo "s02: baseline boot did not reach UNSEALED"; exit 1; }
cp "$CONSOLE" "$RUN/console-6.2.0-enroll.log"
LOG=$(log_of "6.2.0-enroll")
assert_contains "[6.2.0] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[6.2.0] TPM present" "$LOG" "/dev/tpmrm0 present"
assert_contains "[6.2.0] hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[6.2.0] no token yet (fresh disk) — recovery path armed" "$LOG" \
    "$(sentinel_of unseal_token_missing)"
assert_contains "[6.2.0] unlocked via the recovery passphrase" "$LOG" "$(sentinel_of unseal_pass_unlocked)"
assert_contains "[6.2.0] UNSEALED" "$LOG" "debian-fde: UNSEALED"
assert_contains "[6.2.0] clean poweroff" "$LOG" "debian-fde: POWEROFF"
# G-T13/G-E9 (boot reaches the UKI stub): $RUN/uki-pcrsig.json is 6.2.0's
# signed prediction (uki_build wrote it), the console is this boot's — the
# hook UNSEALED, so /init printed the post-hook postphase PCR 11 reading.
CONSOLE="$RUN/console-6.2.0-enroll.log"
assert_pcr11_prediction "S-02 [6.2.0]"

# --- host-side finalized enrollment (the production CLI;
# digest-anchored enroll (Option A — no between-boot reseeding — the CLI compares the entry's recorded d7/d11 against the baseline (pure data): d7 = the booted console's PCR 7, d11 = 6.2.0's
# enter-initrd prediction; the combined {7,11} entry is what the hook extracts.
PCR7_ENROLLED=$(grep -oE 'debian-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console-6.2.0-enroll.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_ENROLLED" ]] || { echo "s02: no PCR 7 in the baseline console"; exit 1; }
D11_620=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_620" ]] || { echo "s02: no enter-initrd d11 prediction from the build"; exit 1; }
uki_baseline_stamp "$RUN/cli-state" "$PCR7_ENROLLED"
uki_pcrsig_append_combined "$RUN/uki-6.2.0.efi.pcrsig.json" "$RUN/uki-6.2.0-combined.json" \
    "$PCR7_ENROLLED" "$D11_620" "$RUN/keys" || exit 1
assert_eq "combined .pcrsig entry pol == policy_digest(booted d7, 6.2.0 enter-initrd d11) (G-B6 shape)" \
    "$(policy_digest "$PCR7_ENROLLED" "$D11_620")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.2.0-combined.json")"
uki_pcrsig_disk "$RUN/pcrsig.img" "$RUN/uki-6.2.0-combined.json" || exit 1
# QEMU-LIVENESS / TPM re-anchor (2026-09-23): after a guest boot the fixture
# swtpm can be wedged for NEW data clients (the guest's disconnect leaves the
# unixio server refusing fresh connections — observed live: a host tpm2
# command hung on the data socket for 15+ min, and an independent probe hung
# identically). swtpm_ensure is the promoted recovery: bounded probe ->
# restart (a fresh startup-clear). DIGEST-ANCHORED enroll (Option A): no
# reseeding — the drift precondition and seal_finalized's G-B6 gate compare
# the entry's recorded d7/d11 components against the baseline (pure data);
# only the seal's getcap probe + SRK operations touch the TPM.
_ensure_tpm || { echo "s02: swtpm re-anchor after boot 6.2.0 failed"; exit 1; }
printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$RUN/kf-slot0"   # verbatim kf0 (no newline)
chmod 600 "$RUN/kf-slot0"
EFIVARS="$RUN/efivars-sb-on"
mkdir -p "$EFIVARS"
_mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
_mkvar SecureBoot 1
_mkvar SetupMode 0
uki_host_enroll_finalized "$EFIVARS" "$RUN/uki-6.2.0-combined.json" \
    "$RUN/disk.img" "$RUN/keys" "$RUN/kf-slot0" "$RUN/cli-state" || {
    echo "s02: production enroll-tpm FAILED"; exit 1; }
TOK=$(disk_token_json "$RUN/disk.img")
assert_contains "standing token is systemd-tpm2 (Mechanism B)" "$TOK" '"type":"systemd-tpm2"'
assert_contains "standing token pins {PCR 7, PCR 11}" "$TOK" '"tpm2-pcrs":[7,11]'

# metadata identity baseline: snapshot AFTER the (one-time) enrollment — the
# ROLLBACK boot below must leave it byte-identical
_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-6.2.0.json"

# --- build the OLDER 6.1.0 UKI (own .pcrsig, never enrolled) -------------------
echo "# building UKI 6.1.0 (older, rollback target; no enrollment will exist for it) ..."
_vuki_build "$RUN/stage-6.1.0" "$RUN/guest-tree" "$RUN/keys" 6.1.0 v610 "$RUN/uki-6.1.0.efi" || {
    echo "s02: variant build failed"; exit 1; }
assert_file_exists "uki 6.1.0: .pcrsig extracted" "$RUN/uki-6.1.0.efi.pcrsig.json"
D11_610=$(cat "$RUN/uki-6.1.0.efi.pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_610" ]] || { echo "s02: no variant enter-initrd d11 prediction"; exit 1; }
assert_ne "6.1.0's enter-initrd d11 differs from 6.2.0's (genuinely different measured content)" \
    "$D11_610" "$D11_620"
assert_rc "uki 6.1.0: sbverify clean (release cert)" 0 \
    sbverify --cert "$RUN/keys/db.crt" "$RUN/uki-6.1.0.efi"
SEC61=$(objdump -h "$RUN/uki-6.1.0.efi" | awk '{print $2}')
for sec in .linux .initrd .cmdline .osrel .uname .pcrpkey .pcrsig; do
    assert_contains "uki 6.1.0: section $sec present" "$SEC61" "$sec"
done
# genuinely different measured content -> different signed pols, same release key
POLS62=$(jq -r '.sha256[].pol' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
POLS61=$(jq -r '.sha256[].pol' "$RUN/uki-6.1.0.efi.pcrsig.json" | sort)
assert_ne "pcrsig pols differ across UKIs (distinct PCR 11 predictions)" "$POLS62" "$POLS61"
PKFP62=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-6.2.0.efi.pcrsig.json" | sort)
PKFP61=$(jq -r -S '.sha256[].pkfp' "$RUN/uki-6.1.0.efi.pcrsig.json" | sort)
assert_eq "pcrsig pkfp identical across UKIs (same release key)" "$PKFP62" "$PKFP61"

# --- rollback signature + action -----------------------------------------------
# the vendor's rollback delivery: 6.1.0's OWN release-signed combined {7,11}
# entry over (booted d7, 6.1.0's enter-initrd d11) — the entry the hook
# extracts for the standing token's selection under the OLDER kernel
uki_pcrsig_append_combined "$RUN/uki-6.1.0.efi.pcrsig.json" "$RUN/uki-6.1.0-combined.json" \
    "$PCR7_ENROLLED" "$D11_610" "$RUN/keys" || exit 1
assert_eq "6.1.0 combined entry pol == policy_digest(booted d7, 6.1.0 enter-initrd d11)" \
    "$(policy_digest "$PCR7_ENROLLED" "$D11_610")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-6.1.0-combined.json")"
uki_pcrsig_disk "$RUN/uki-6.1.0-combined.img" "$RUN/uki-6.1.0-combined.json" || exit 1
_esp_add_uki "$RUN/esp.img" "$RUN/uki-6.1.0.efi" debian-fde-6.1.0.efi || exit 1
_esp_set_default "$RUN/esp.img" "$RUN/uki-6.1.0.efi" || exit 1
ESPLS=$(_esp_ls "$RUN/esp.img")
assert_contains "ESP retains 6.2.0 entry" "$ESPLS" "debian-fde-6.2.0.efi"
assert_contains "ESP retains 6.1.0 entry" "$ESPLS" "debian-fde-6.1.0.efi"

# --- boot 2: 6.1.0 rollback must unlock passwordless (zero console input) ------
if ! boot_and_wait "6.1.0-rollback" "$RUN/esp.img" "$RUN/disk.img" "$RUN/vars-enrolled.fd" "$RUN/uki-6.1.0-combined.img"; then
    echo "s02: rollback boot failed (qemu_run/qemu_wait) — console kept for evidence: $RUN/console.log" >&2
    exit 1
fi
LOG=$(log_of "6.1.0-rollback")
assert_contains "[6.1.0] init ran" "$LOG" "debian-fde-harness: init started"
assert_contains "[6.1.0] hook ran the enter-initrd extend" "$LOG" "$(sentinel_of unseal_pcrextend_ok)"
assert_contains "[6.1.0] hook discovered the standing {7,11} token" "$LOG" \
    "$(sentinel_of unseal_token_info)7,11]"
assert_contains "[6.1.0] unlocked via the TPM token (rollback passwordless)" "$LOG" \
    "$(sentinel_of unseal_unlocked)"
assert_not_contains "[6.1.0] no new enrollment (Mechanism B seal)" "$LOG" "$(sentinel_of cli_seal_slot)"
assert_not_contains "[6.1.0] no new enrollment (cryptenroll)" "$LOG" "$(sentinel_of cryptenroll_enrolled)"
PROMPTS_RB=$(grep -cE "$(sentinel_of unseal_prompt_re)" <<<"$LOG" || true)
assert_eq "[6.1.0] zero recovery-passphrase prompts (zero-input rollback)" "0" "$PROMPTS_RB"
assert_contains "[6.1.0] UNSEALED (rollback passwordless)" "$LOG" "debian-fde: UNSEALED"
assert_not_contains "[6.1.0] no emergency shell" "$LOG" "$(sentinel_of emergency_forbidden)"
assert_contains "[6.1.0] clean poweroff" "$LOG" "debian-fde: POWEROFF"
# G-T13/G-E9 for the ROLLBACK boot: pair the helper with 6.1.0's OWN signed
# prediction (the older UKI's pols differ — asserted above) — the post-hook
# PCR 11 reading under 6.1.0 must match 6.1.0's per-kernel signed policy.
cp "$RUN/uki-6.1.0.efi.pcrsig.json" "$RUN/uki-pcrsig.json"
CONSOLE="$RUN/console-6.1.0-rollback.log"
assert_pcr11_prediction "S-02 [6.1.0]"
CONSOLE="$RUN/console.log"

_meta_snapshot "$RUN/disk.img" "$RUN/meta-post-6.1.0.json"
assert_rc "rollback boot changed NO LUKS2 metadata (no enrollment)" 0 \
    cmp -s "$RUN/meta-post-6.2.0.json" "$RUN/meta-post-6.1.0.json"

# --- wrap up -------------------------------------------------------------------
rm -rf "$RUN/guest-tree" "$RUN/stage-6.1.0"
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s02-rollback: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s02-rollback: FAIL ($TESTS_FAIL failing assertions of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
