#!/usr/bin/env bash
# tests/e2e/s21-finalize-guard.sh — §10 row "First boot with Secure Boot OFF"
# + §12 S-21 on the ADR-21 PROVISIONING-ESCROW FIRST-BOOT LIFECYCLE (§9.1
# Stage 2; commit 0b4664b's design): the pre-ADR-21 fixture this scenario used
# to stage (keyslot 0 only, NO token, the GUIDED finalize verifying the
# recovery passphrase against keyslot 0) is an ABOLISHED shape —
# lib/trust-state.sh derives "unknown" for it and the guided entry dies 64
# ("unrecognized ground-truth state"). This rewrite stages EXACTLY what the
# real ADR-21 installer leaves behind and drives the Stage-2 oneshot entry
# (fin_service_main) the way hooks/openrc/alpine-fde-finalize does.
#
# Fixture (host-side, s19/s20 payload patterns — NO guest writes after the
# installer boot): the ADR-21 post-install container shape, built with the
# PRODUCTION libs host-side (the blessed "harness's host-side Stage-1 step-6
# seal" pattern — lib/seal.sh's own G-B6 comment; probed the same way s19
# sources seal.sh/token.sh for its interop legs):
#   * LUKS2 container: keyslot 0 = the CI layup passphrase (the installer
#     boot's /kf0 unlock; KILLED after the populate — keyslot 0 LEFT FREE,
#     the escrow install's defining property), keyslot 1 = the RANDOM VOLUME
#     PASSPHRASE (seal_provisional's 64-char base64(48 raw bytes), ADR-19
#     framing) bound to a REAL PROVISIONAL {PCR 11} systemd-tpm2 token (a
#     full §7.2 seal_provisional token: release-key-signed tpm2-signature,
#     tpm2-policy-hash, SRK blob — the real install's seal_provisional
#     shape), keyslot 2 = the TEMPORARY ephemeral install key. The
#     provisional token's G-B6 gate is DIGEST-ANCHORED: the scenario
#     composes the {11} .pcrsig entry host-side (pol = seal_digest_11 over
#     the feed UKI's enter-initrd prediction d11, signed by release.pem,
#     d11 anchor carried) — the anchored-provisional form seal_enroll
#     explicitly supports for fixture swtpms ("extend-from-zero, never the
#     booted value"). The token is imported with lib/token.sh at token id 0.
#   * The ESP carries the ADR-21 provisioning escrow (mtools, no mount):
#     alpine-fde-provision/REQUEST (empty marker, copied LAST) +
#     alpine-fde-provision/volume-keys.json =
#     {"members":[{"target":"root","uuid":<luks>,"pass_b64":base64(the
#     keyslot-1 volume passphrase)}]} — byte-identical to the golden
#     install's ADR-21 step and to the escrow the consume sed-parses.
#   * The PENDING baseline (expected_pcr7 "pending"), /etc/crypttab, the
#     REAL advisory oneshot /etc/init.d/alpine-fde-finalize + its
#     rc-update default-runlevel symlink, the PLAINTEXT release.pem +
#     release.pub (ADR-18 deferral — the Stage-2 consumption encrypts it),
#     a plain operator /etc/motd, and an ADMIN ACCOUNT (uid 1000, home
#     /home/admin, LOCKED shadow "!") appended to the disk rootfs — the
#     Stage-2 chpasswd needs the account to exist.
#
#   boot A (§10 first-boot row / S-21 negative): SB-OFF vars (stock vars
#           copy). The ADR-20 amended PRE-UNSEAL SECURE BOOT GUARD blocks at
#           the hook's FIRST step — BEFORE any escrow detection: the refusal
#           notice + "Press Enter to reboot" + OsIndications + reboot. The
#           container is NEVER unsealed and the ESCROW IS NEVER CONSUMED:
#           post-kill host asserts pin the metadata unchanged (keyslot 0
#           free, the {11} token + the ephemeral intact) AND the escrow
#           still standing on the ESP image (mtools read). The hook parks on
#           its Enter read; the scenario waits for the guard sentinel and
#           hard-kills qemu BY PID.
#   boot B (SB-ON enrolled vars): the provisional {11} token unlocks the
#           volume PASSWORDLESSLY in-initrd (the shipped hook's token path —
#           exactly the "falls to the {11}-token path" behavior the ADR-21
#           escrow boot converges from; the escrow ITSELF is NOT consumed
#           in-initrd — see the fidelity notes). The fed DEBUG SHELL then
#           hosts, in order:
#             (1) THE ESCROW BOOT — the SHIPPED hook is re-run as a DIRECT
#                 drive with the escrow seams (FDE_ESP_DEV, FDE_ESP_MNT,
#                 FDE_NEWROOT=/, FDE_CONSOLE_IN) after closing the mapper:
#                 detect mounts the ESP (see the mount seam below), SELF-
#                 SEALS the real-measurement {PCR 7, PCR 11} token with the
#                 EMPTY tpm2-signature escrow-provenance marker, trial-
#                 unseals it, imports it at token id 1, UNLOCKS the member
#                 with the escrowed keyslot-1 passphrase, runs the REAL ×2
#                 SET CEREMONY on the console (BOTH prompts — the scenario
#                 feeds the recovery passphrase at each prompt, exactly the
#                 operator's typing) — keyslot 0 enrolled BY THE HOOK,
#                 the passphrase staged for Stage 2, and the ESCROW DELETED
#                 ("provisioning escrow: consumed"). Every TPM, LUKS and
#                 ceremony step is the shipped code driven for real.
#             (2) THE STAGE-2 SERVICE — the oneshot's start() body:
#                 source trust-state.sh + finalize.sh, fin_service_main.
#                 Asserts the completion chain: the provisional re-unseal
#                 authorization, the pending baseline finalized (audit
#                 --init from live values), the TEMPORARY ephemeral keyslot
#                 purged, the {7,11} token upgrade, the ADR-8 marker
#                 cleared, and the ADR-21 CONSUMPTION LEGS: release.pem
#                 encrypted (ADR-18), root+admin passwords set from the
#                 staged passphrase, the staged file scrubbed.
#
# Fidelity notes (documented, not silent — the product/harness gaps this
# scenario pins instead of papering over):
#   * THE IN-INITRD ESCROW PATH CANNOT FIRE IN THIS HARNESS: the harness
#     initrd has no blkid binary, no vfat/nls modules (UKI_MODULES), and no
#     env channel to set FDE_ESP_DEV. The escrow boot therefore runs as a
#     DIRECT hook drive in the fed session with two PATH shims: `mount`
#     translates the hook's `mount -t vfat DEV MNT` into a BIND mount of
#     the payload escrow dir (no vfat module exists in the initrd), and
#     `tpm2_pcrextend` REFUSES so the hook's unconditional step-1 extend
#     cannot DOUBLE-extend PCR 11 past the signed enter-initrd value (the
#     in-initrd hook already extended once; the service's live-PCR unseal
#     and the self-seal both depend on the single-extend value).
#   * THE CEREMONY READ STAYS ON /dev/console: the documented FDE_CONSOLE_IN
#     seam exists only in the hook header — _fdh_read_pass hard-reads the
#     console. That is exactly the fed session's stdin here, so the
#     scenario feeds the ×2 prompts through the console (prompt-
#     synchronized, the passphrase itself never echoed — the ceremony's
#     stty -echo holds) and asserts BOTH prompt texts verbatim.
#   * FDE_NEWROOT=/ in the fed drive: the ceremony stages the passphrase at
#     $FDE_NEWROOT/run/alpine-fde-provision-pass; on a real boot NEWROOT is
#     the booted system's root so the file IS /run/alpine-fde-provision-
#     pass after switch_root — in the fed session the equivalent of the
#     booted root is /, which is where fin_completion_steps reads it.
#   * THE ESCROW SELF-SEAL'S PROVISIONAL SIBLING: the shipped consume
#     imports the {7,11} token at a FREE id and leaves the provisional {11}
#     token standing (the header's step-e "takes its id" is not
#     implemented). The scenario performs that retirement as a stand-in,
#     which is ALSO what lets the Stage-2 chain see the standing seal — and
#     the "token already {PCR 7, PCR 11} — skipping" upgrade-skip branch is
#     consequently unreachable here: with the provisional kept, the
#     seal_unseal authorization (policyauthorize-only session) can only
#     re-unseal the PROVISIONAL seal, so fin_provisional_unseal requires
#     the provisional first-in-line and the chain UPGRADES (the skip branch
#     would need the escrow token first, whose PolicyPCR-only binding the
#     authorize-only session refuses). The end state is identical either
#     way: exactly ONE {7,11} token, keyslots 0 + the sealed slot.
#   * The finalize CODE path runs under the harness busybox initrd via the
#     fed session (the harness initrd has no OpenRC): the service legs drive
#     the staged oneshot's body DIRECTLY — the exact functions the boot-time
#     service runs, with the rc/marker surfaces the contract pins.
#   * The chpasswd consumption leg runs in the INITRD environment (no
#     chroot): the fed session appends the same admin account to the
#     initrd's /etc/passwd+shadow (the DISK rootfs carries the fixture's
#     admin account per the fixture spec; chpasswd edits the running
#     system's account db, which in the real boot IS the disk's).
#   * The guest needs jq/tpm2/flock/openssl/OBJCOPY/cryptsetup: the s19/s20
#     tooling-payload closures (host-closure copies + wrapper scripts) ride
#     the payload drive; objcopy is new (fin_uki_pcrsig extracts the {11}
#     .pcrsig from the ALPINE_FDE_ESP UKI — a 2-section mini-PE fixture file
#     carrying the composed {11} entry, built host-side with objcopy
#     --add-section and verified by a section roundtrip; the real UKI's own
#     stub would carry the same entry).
#   * The {7,11} policy signature for the token upgrade is composed
#     HOST-side (uki_pcrsig_append_combined): d7 = the installer boot's
#     console PCR 7 (SB-on enrolled vars are deterministic across boots),
#     d11 = the feed UKI build's enter-initrd prediction — the same
#     composition s19/s20 host-side `pcrsign` legs stand for.
#
# Every boot carries the §12 negatives: the interactive passphrase prompt
# never appears (prompt_re), no emergency shell (emergency_forbidden), no
# systemd-cryptenroll anywhere (cryptenroll_enrolled), and every
# upstream-drifting grep goes through the sentinel table (sentinel_of).

set -u
set -m   # each background job gets its own process group: the watchdog can
         # kill the whole stage tree, not just the subshell leader

HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
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
# shellcheck source=../lib/overlay-disk.sh
source "$TESTS/lib/overlay-disk.sh"   # Wave-2 2b: per-boot QCOW2 overlays + base LOCK_SH

ROOTFS_RETENTION=3
ESP_HEADROOM_MIB=8
DISK_MIB=1600

export QEMU_TIMEOUT="${ALPINE_FDE_S21_TIMEOUT:-1200}"

# §13-floor-OK credentials (>=16 chars; the *alpine-fde* substring is
# blocklisted by the entropy floor). S21_RECOVERY is the ×2 set ceremony's
# passphrase (keyslot 0 + the admin/root login + the release.pem encryption
# passphrase at the Stage-2 consumption); S21_KEYPASS encrypts release.pem.
S21_RECOVERY='fde-s21-recovery-4e8b20'
S21_KEYPASS='fde-s21-release-pbkdf2-m5'
# The temporary ephemeral install key (keyslot 2; purged by the Stage-2
# completion chain — the value never matters beyond the layup).
S21_EPHKEY='s21-ephemeral-install-key-9f27'

# --- hardening: bounded stages, loud failures, overall budget --------------------
# Calibrated 2026-09-24: the registry's outer SCENARIO_BUDGET is 1500 s (MD-05b)
# — an internal watchdog ABOVE the outer cap can never fire and only masks
# hangs (a hung s21 then dies as an anonymous outer rc=124 instead of a loud
# STAGE-TIMEOUT-OR-HANG). 1350 s = ~2.2x the observed full-pass wall while
# still fitting inside the outer budget.
OVERALL_BUDGET="${ALPINE_FDE_S21_BUDGET:-1350}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

_hang_fail() {   # _hang_fail <kind> <stage> <detail> — loud, greppable, fatal
    printf '\ns21: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's21: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    # 125, NOT timeout(1)'s 124: an internal watchdog fire must never be
    # misread by run-e2e as "exceeded the outer scenario budget".
    exit 125
}
_budget_check() {   # _budget_check <stage>
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
run_stage_impl() {   # <soft> <name> <timeout-s> <cmd...>
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s21: stage $name (watchdog ${tmo}s)"
    # Wave-2 2b overlay discipline: the stage subshell and its watchdog must
    # NOT inherit the overlay lock fds (OVERLAY_LOCK_FDS) — the watchdog's
    # `sleep` child survives run_stage's kill as an ORPHAN holding the
    # inherited LOCK_SH copy on the base image, deadlocking any later
    # host-side EXCLUSIVE op until the sleep expires (the s22 live repro
    # 2026-09-25). The MAIN shell alone carries the overlay lock (fds held
    # until overlay_discard), so the forked copies are redundant: close them.
    local _fd _close=""
    for _fd in ${OVERLAY_LOCK_FDS[@]:-}; do
        [[ -n "$_fd" ]] && _close="$_close exec ${_fd}<&-;"
    done
    ( eval "$_close" 2>/dev/null; "$@" ) &
    local pid=$! rc wrc
    ( eval "$_close" 2>/dev/null; sleep "$tmo"; kill -9 -"$pid" 2>/dev/null; exit 125 ) &
    local wpid=$!
    wait "$pid"; rc=$?
    kill "$wpid" 2>/dev/null
    wait "$wpid" 2>/dev/null; wrc=$?
    if (( wrc == 125 )); then
        _hang_fail STAGE-TIMEOUT "$name" "exceeded watchdog ${tmo}s"
    fi
    if (( rc != 0 )); then
        printf 's21: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
        (( soft == 1 )) && return "$rc"
        exit 1
    fi
    return 0
}
run_stage() { run_stage_impl 0 "$@"; }
run_stage_rc() { run_stage_impl 1 "$@"; }
_qemu_alive_or_die() {   # _qemu_alive_or_die <dir> <stage> — QEMU-LIVENESS guard
    local dir="$1" stage="$2" qpid
    qpid=$(cat "$dir/qemu.pid" 2>/dev/null || true)
    if [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null; then
        _hang_fail QEMU-DIED "$stage" \
            "qemu (pid ${qpid:-<none>}) is gone — sentinel can never appear; tail: $(tail -5 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
    fi
}
wait_console() {   # wait_console <dir> <fixed-string> <timeout-s> — bounded poll
    local dir="$1" pat="$2" tmo="$3" i=0
    while ((i < tmo)); do
        grep -qF -- "$pat" "$dir/console.log" 2>/dev/null && return 0
        _qemu_alive_or_die "$dir" "console-wait:$pat"
        _budget_check "console-wait:$pat"
        sleep 1
        i=$((i + 1))
    done
    _hang_fail CONSOLE-WAIT "$pat" "not seen in ${tmo}s; tail: $(tail -3 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
}

RUN="$TESTS/e2e/.runs/s21-finalize-guard-$(date +%s)"
mkdir -p "$RUN"

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while the (long) boots run; prune our OWN superseded runs,
# never the dirs run-e2e protects (CR-02/MD-03: ALPINE_FDE_PROTECT_DIRS).
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

find "$TESTS/e2e/.runs" -maxdepth 1 -type d -name 's21-finalize-guard-*' | sort -r |
    tail -n +3 | while IFS= read -r d; do
        case ":${ALPINE_FDE_PROTECT_DIRS:-}:" in *":$d:"*) continue ;; esac
        rm -rf "$d"
    done

_exit_cleanup() {
    [[ -n "$CURRENT_QEMU_DIR" ]] && qemu_kill "$CURRENT_QEMU_DIR" 2>/dev/null
    local d
    for d in "${SWTPM_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d" 2>/dev/null
    done
    kill "$REFRESHER" 2>/dev/null
}
trap _exit_cleanup EXIT
_exit_on_int() { _exit_cleanup; exit 130; }
_exit_on_term() { _exit_cleanup; exit 143; }
trap _exit_on_int INT
trap _exit_on_term TERM
_rearm_trap() {
    trap _exit_cleanup EXIT
    trap _exit_on_int INT
    trap _exit_on_term TERM
}
_track_swtpm() { SWTPM_DIRS+=("$1"); }

# _ensure_tpm — the swtpm dies at qemu disconnect (observed, s00 note);
# relaunch on the SAME state dir (permall/SRK persists, PCRs reset — the
# reset is LOAD-BEARING here: every boot re-derives PCR 11 from zero, so the
# enter-initrd extend lands on exactly the signed prediction every time).
_ensure_tpm() {
    local dir="$1"
    if timeout 20 swtpm_pcrread "$dir" 0 >/dev/null 2>&1; then
        return 0
    fi
    [ -f "$dir/pid" ] && kill -9 "$(cat "$dir/pid")" 2>/dev/null
    rm -f "$dir/pid" "$dir/sock" "$dir/sock.ctrl"
    _SWTPM_CLEANUP_TRAP_SET=1 run_stage "swtpm_start:$dir" 90 swtpm_start "$dir"
    _rearm_trap
}

# _qemu_alive <dir> — a QEMU that dies at startup exits rc 0 from qemu_run's
# perspective; fail LOUDLY here with the qemu stderr instead of surfacing as
# a missing console sentinel.
_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s21: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s21: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

# ============================================================================
# Fixture stage 1: keys + vars + the LUKS2 container layup
# (keyslot 0 = the CI layup passphrase, keyslot 2 = the ephemeral install key)
# ============================================================================
keys_create "$RUN/keys" || { echo "s21: keys_create failed"; exit 1; }
run_stage vars-enrolled 120 keys_vars_enrolled "$RUN/keys" "$RUN/vars-enrolled.fd"
assert_contains "fixture: enrolled vars SecureBootEnable ON" \
    "$(keys_vars_get "$RUN/vars-enrolled.fd" SecureBootEnable)" "ON"
run_stage vars-unenrolled 60 keys_vars_unenrolled "$RUN/keys" "$RUN/vars-unenrolled.fd"
assert_not_contains "fixture: SB-off vars carry no SecureBootEnable" \
    "$(keys_vars_get "$RUN/vars-unenrolled.fd" SecureBootEnable)" "ON"
run_stage disk_make_luks 120 disk_make_luks "$RUN/disk.img" "$DISK_MIB"
DISK_UUID=$(timeout 60 cryptsetup luksUUID "$RUN/disk.img") || { echo "s21: luksUUID failed"; exit 1; }
[[ -n "$DISK_UUID" ]] || { echo "s21: empty LUKS uuid"; exit 1; }
# the layup credentials as keyfiles (byte-identical to disk_make_luks's feed)
printf '%s' "$ALPINE_FDE_SLOT0_PASSPHRASE" >"$RUN/slot0pw" && chmod 600 "$RUN/slot0pw"
printf '%s' "$S21_EPHKEY" >"$RUN/ephkey" && chmod 600 "$RUN/ephkey"
run_stage ephkey-slot2 120 cryptsetup luksAddKey --batch-mode --key-slot 2 \
    --key-file "$RUN/slot0pw" "$RUN/disk.img" "$RUN/ephkey"
META0=$(disk_metadata "$RUN/disk.img")
assert_eq "fixture: layup shape — keyslots 0 (layup) + 2 (ephemeral)" '["0","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$META0")"
assert_eq "fixture: ephemeral keyslot 2 pbkdf is argon2id (§13)" "argon2id" \
    "$(jq -r '.keyslots["2"].kdf.type' <<<"$META0")"

# ============================================================================
# Fixture stage 2: the FEED UKI FIRST (its enter-initrd d11 prediction is the
# {11} seal's G-B6 anchor) — §8.2 hook unlock + DEBUG SHELL seam.
# ============================================================================
ALPINE_FDE_DEBUG_SHELL=1 ALPINE_FDE_ROOTFS_SHA= ALPINE_FDE_ROOTFS_BYTES= \
    run_stage uki_build-feed 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness-feed.efi"
D11_PRED=$(cat "$RUN/pcr11-enter-initrd.txt" 2>/dev/null)
[[ -n "$D11_PRED" ]] || { echo "s21: no enter-initrd d11 prediction from the feed build"; exit 1; }
FEED_MIB=$(( ($(stat -c%s "$RUN/harness-feed.efi") + 1048575) / 1048576 ))
run_stage esp_make-feed 300 esp_make "$RUN/esp-feed.img" \
    $(( FEED_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness-feed.efi"

# ============================================================================
# Fixture stage 3: the host-side ADR-21 seal — the anchored {11} .pcrsig entry
# (composed + G-B6-validated), then seal_provisional + the keyslot/token/
# escrow choreography with the PRODUCTION libs against the fixture swtpm.
# ============================================================================
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"   # BEFORE the seal libs (siblings)
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/token.sh
source "$REPO/lib/token.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"

# the anchored {11} entry: pol = seal_digest_11(d11 prediction), release-signed
POL11=$(seal_digest_11 "$D11_PRED")
[[ -n "$POL11" ]] || { echo "s21: seal_digest_11 produced nothing"; exit 1; }
printf '%s' "$POL11" | policy_hex_to_bin >"$RUN/pol11.bin"
run_stage pcrsig11-sign 120 openssl dgst -sha256 -sign "$RUN/keys/db.key" \
    -out "$RUN/pol11.sig" "$RUN/pol11.bin"
POL11_SIG=$(openssl base64 -A -in "$RUN/pol11.sig")
POL11_PKFP=$(openssl pkey -pubin -in "$RUN/keys/release.pub" -outform DER 2>/dev/null |
    openssl base64 -A)
printf '{"sha256":[{"pcrs":[11],"pkfp":"%s","pol":"%s","sig":"%s","d11":"%s"}]}\n' \
    "$POL11_PKFP" "$POL11" "$POL11_SIG" "$D11_PRED" >"$RUN/uki-pcrsig-11.json"
# pre-boot loud validation: the entry must pass the seal's own G-B6 gate and
# the HOOK's sed extraction (both consumers of the drive-head .pcrsig)
seal_verify_pcrsig "$RUN/keys" "$RUN/uki-pcrsig-11.json" 11 "$POL11" ||
    { echo "s21: the composed {11} entry failed the G-B6 gate"; exit 1; }
POL11_HOOK=$(sed -n "s/^.*\"pcrs\":\[11\],[^{]*\"pol\":\"\([0-9a-fA-F]\{64\}\)\".*$/\1/p" \
    "$RUN/uki-pcrsig-11.json")
[[ "$POL11_HOOK" == "$POL11" ]] ||
    { echo "s21: the composed {11} entry fails the hook's pol extraction"; exit 1; }
_assert_result ok "fixture: anchored {11} .pcrsig entry composed (G-B6 + hook-extraction valid)" ""

# the mini-PE UKI fixture file: fin_uki_pcrsig objcopies .pcrsig out of
# $ALPINE_FDE_ESP/EFI/Linux/alpine-fde-*.efi — a 2-section object carrying
# EXACTLY this entry stands in for the real UKI (roundtrip-verified here)
printf 'x' >"$RUN/one-byte.bin"
run_stage minipe-build 120 objcopy -I binary -O elf64-x86-64 \
    --add-section ".pcrsig=$RUN/uki-pcrsig-11.json" \
    --set-section-flags .pcrsig=contents,alloc,load,data \
    "$RUN/one-byte.bin" "$RUN/alpine-fde-fixture.efi"
run_stage minipe-roundtrip 120 bash -c \
    'objcopy -O binary --only-section=.pcrsig "$1" "$2" && cmp "$3" "$2"' \
    _ "$RUN/alpine-fde-fixture.efi" "$RUN/pcrsig-extracted.json" "$RUN/uki-pcrsig-11.json" ||
    { echo "s21: the mini-PE .pcrsig roundtrip failed"; exit 1; }

# the REAL provisional seal against the fixture swtpm (deterministic SRK — the
# same state dir the guest boots share), then the keyslot/token/escrow chain:
# token_free_slot skips keyslot 0 by design and lands on 1 (the §7.2 token slot)
_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
if ! ALPINE_FDE_TCTI="$(_swtpm_tcti_for "$RUN/tpm")" ALPINE_FDE_KEYDIR="$RUN/keys" \
    seal_provisional "$RUN/keys" "$RUN/disk.img" "$RUN/uki-pcrsig-11.json" \
    "$RUN/token0.json"; then
    echo "s21: host-side seal_provisional failed"; exit 1
fi
[[ -n "$SEAL_PASS_FILE" && -s "$SEAL_PASS_FILE" ]] || { echo "s21: no volume passphrase staged"; exit 1; }
assert_eq "fixture: the provisional seal bound keyslot 1 (token_free_slot skips 0)" \
    "1" "$SEAL_SLOT"
run_stage volume-pass-stage 60 cp "$SEAL_PASS_FILE" "$RUN/volume-pass"
chmod 600 "$RUN/volume-pass"
run_stage token-add-keyslot1 300 token_add_keyslot "$RUN/disk.img" \
    "$RUN/volume-pass" "1" "$RUN/slot0pw"
run_stage token-import-0 300 token_import "$RUN/disk.img" "$RUN/token0.json" \
    "$(token_next_id "$RUN/disk.img")"
# the ADR-21 escrow: pass_b64 = base64(the keyslot-1 passphrase text) — the
# SAME double-framing the golden install printf's and the hook sed-parses
PASS_B64=$(openssl base64 -A <"$RUN/volume-pass")
printf '{"members":[{"target":"root","uuid":"%s","pass_b64":"%s"}]}\n' \
    "$DISK_UUID" "$PASS_B64" >"$RUN/volume-keys.json"
jq -e '.members[0].target == "root" and (.members[0].pass_b64 | length > 0)' \
    "$RUN/volume-keys.json" >/dev/null ||
    { echo "s21: escrow volume-keys.json malformed"; exit 1; }
# bake the escrow onto the ESP image (mtools — volume-keys FIRST, the empty
# REQUEST marker LAST: only a REQUEST-marked escrow is a live one)
: >"$RUN/request.marker"
run_stage esp-escrow-bake 120 bash -c '
    mmd -i "$1" ::/alpine-fde-provision &&
    mcopy -i "$1" "$2" "::/alpine-fde-provision/volume-keys.json" &&
    mcopy -i "$1" "$3" "::/alpine-fde-provision/REQUEST" &&
    mtype -i "$1" "::/alpine-fde-provision/REQUEST" >/dev/null' \
    _ "$RUN/esp-feed.img" "$RUN/volume-keys.json" "$RUN/request.marker"
run_stage seal-scrub 60 seal_scrub
# post-seal fixture shape: keyslots 0/1/2, ONE {11} token on slot 1
METAS=$(disk_metadata "$RUN/disk.img")
assert_eq "fixture: post-seal shape — 3 keyslots" "3" "$(jq -r '.keyslots | length' <<<"$METAS")"
assert_eq "fixture: exactly ONE systemd-tpm2 token" "1" \
    "$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')"
TOK0PCRS=$(disk_token_json "$RUN/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')
assert_eq "fixture: the provisional token pins PCR 11 ONLY (ADR-21 install shape)" "[11]" "$TOK0PCRS"
TOK0SLOT=$(disk_token_json "$RUN/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "fixture: the provisional token binds the volume-pass keyslot 1" "1" "$TOK0SLOT"
TOK0SIGLEN=$(disk_token_json "$RUN/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-signature"] | length')
if (( TOK0SIGLEN > 0 )); then
    _assert_result ok "fixture: the provisional token carries a REAL release-key signature" ""
else
    _assert_result not-ok "fixture: the provisional token carries a REAL release-key signature" \
        "empty tpm2-signature (the escrow marker leaked into the provisional seal)"
fi

# ============================================================================
# Fixture stage 4: the tooling staging tree (s19/s20 closures + objcopy) and
# the Stage-1 payload the installed disk must carry.
# ============================================================================
TOOLING="$RUN/tooling"
rm -rf "$TOOLING" "$RUN/tooling.tar.gz"
mkdir -p "$TOOLING/opt/alpine-fde" "$TOOLING/etc/alpine-fde/keys" "$TOOLING/usr/bin" \
    "$TOOLING/opt/jqbin/lib" "$TOOLING/opt/tpm/bin" "$TOOLING/opt/flockbin/lib" \
    "$TOOLING/opt/sslbin/lib" "$TOOLING/opt/objcopybin/lib" \
    "$TOOLING/etc/init.d" "$TOOLING/etc/runlevels/default" \
    "$TOOLING/escrow/esp/alpine-fde-provision" "$TOOLING/efi/EFI/Linux"
for d in bin lib hooks; do
    run_stage "tooling-copy:$d" 120 cp -r "$REPO/$d" "$TOOLING/opt/alpine-fde/$d"
done
# tpm2 multitool + jq + flock + openssl + objcopy: host-closure copies with
# their own loader (the /opt isolation pattern; s19/s20 precedent). openssl:
# the ADR-18 release.pem encryption + the post-state PBES2 check. objcopy:
# fin_uki_pcrsig's .pcrsig extraction from the mini-PE fixture.
run_stage tooling-tpm2 60 cp -L "$(command -v tpm2)" "$TOOLING/opt/tpm/bin/tpm2"
printf '#!/bin/sh\nexec /opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/tpm2 "$@"\n' \
    >"$TOOLING/usr/bin/tpm2"
run_stage tooling-jq 60 cp -L "$(command -v jq)" "$TOOLING/opt/jqbin/jq"
_jq_interp=$(ldd "$(command -v jq)" | awk '/ld-linux/{print $1}')
run_stage tooling-jq-ld 60 cp -L "$_jq_interp" "$TOOLING/opt/jqbin/ld-linux"
_JQ_LIBS=""
for _jl in $(ldd "$(command -v jq)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-jq-closure"
    cp -L "$_jl" "$TOOLING/opt/jqbin/lib/"
    _JQ_LIBS="$_JQ_LIBS $_jl"
done
printf '#!/bin/sh\nexec /opt/jqbin/ld-linux --library-path /opt/jqbin/lib /opt/jqbin/jq "$@"\n' \
    >"$TOOLING/usr/bin/jq"
run_stage tooling-flock 60 cp -L "$(command -v flock)" "$TOOLING/opt/flockbin/flock"
_flock_interp=$(ldd "$(command -v flock)" | awk '/ld-linux/{print $1}')
if [[ "$_flock_interp" != "$_jq_interp" ]]; then
    echo "s21: flock interp $_flock_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-flock-ld 60 cp -L "$_flock_interp" "$TOOLING/opt/flockbin/ld-linux"
for _fl in $(ldd "$(command -v flock)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-flock-closure"
    case "$_JQ_LIBS" in
        *"$_fl"*) : ;;
        *) echo "s21: flock closure introduces a library the payload does not ship: $_fl"; exit 1 ;;
    esac
    cp -L "$_fl" "$TOOLING/opt/flockbin/lib/"
done
printf '#!/bin/sh\nexec /opt/flockbin/ld-linux --library-path /opt/flockbin/lib /opt/flockbin/flock "$@"\n' \
    >"$TOOLING/usr/bin/flock"
run_stage tooling-openssl 60 cp -L "$(command -v openssl)" "$TOOLING/opt/sslbin/openssl"
_ssl_interp=$(ldd "$(command -v openssl)" | awk '/ld-linux/{print $1}')
if [[ "$_ssl_interp" != "$_jq_interp" ]]; then
    echo "s21: openssl interp $_ssl_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-openssl-ld 60 cp -L "$_ssl_interp" "$TOOLING/opt/sslbin/ld-linux"
for _sl in $(ldd "$(command -v openssl)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-openssl-closure"
    cp -L "$_sl" "$TOOLING/opt/sslbin/lib/"
done
printf '#!/bin/sh\nexec /opt/sslbin/ld-linux --library-path /opt/sslbin/lib /opt/sslbin/openssl "$@"\n' \
    >"$TOOLING/usr/bin/openssl"
run_stage tooling-objcopy 60 cp -L "$(command -v objcopy)" "$TOOLING/opt/objcopybin/objcopy"
_obj_interp=$(ldd "$(command -v objcopy)" | awk '/ld-linux/{print $1}')
if [[ "$_obj_interp" != "$_jq_interp" ]]; then
    echo "s21: objcopy interp $_obj_interp != payload interp $_jq_interp — closure not identical"
    exit 1
fi
run_stage tooling-objcopy-ld 60 cp -L "$_obj_interp" "$TOOLING/opt/objcopybin/ld-linux"
for _ol in $(ldd "$(command -v objcopy)" | awk '$3 ~ /^\// {print $3}'); do
    _budget_check "tooling-objcopy-closure"
    cp -L "$_ol" "$TOOLING/opt/objcopybin/lib/"
done
printf '#!/bin/sh\nexec /opt/objcopybin/ld-linux --library-path /opt/objcopybin/lib /opt/objcopybin/objcopy "$@"\n' \
    >"$TOOLING/usr/bin/objcopy"
chmod 755 "$TOOLING/usr/bin/tpm2" "$TOOLING/usr/bin/jq" \
    "$TOOLING/usr/bin/cryptsetup-pretty" "$TOOLING/usr/bin/flock" \
    "$TOOLING/usr/bin/openssl" "$TOOLING/usr/bin/objcopy"

# The REAL advisory oneshot + its rc-update enable record (the installer's
# Stage-1 step 7 verbatim). NO systemd unit anywhere.
run_stage tooling-oneshot 60 cp "$REPO/hooks/openrc/alpine-fde-finalize" \
    "$TOOLING/etc/init.d/alpine-fde-finalize"
chmod 755 "$TOOLING/etc/init.d/alpine-fde-finalize"
ln -sfn /etc/init.d/alpine-fde-finalize \
    "$TOOLING/etc/runlevels/default/alpine-fde-finalize"

# pending baseline: the pub path is where the DISK rootfs carries it (finalize
# runs with ALPINE_FDE_ROOT=/mnt); boot B's audit --init finalizes it
cat >"$TOOLING/etc/alpine-fde/baseline.json" <<JSON
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcr0": "pending",
  "pcr1": "pending",
  "pcr2": "pending",
  "pcr3": "pending",
  "expected_pcr7": "pending",
  "sb_state": {
    "secure_boot": "",
    "setup_mode": "",
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
    "release_pub_path": "/etc/alpine-fde/keys/release.pub",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "$DISK_UUID",
    "esp_partuuid": ""
  }
}
JSON
printf '# alpine-fde.conf — harness fixture (comment-only: the environment wins)\n' \
    >"$TOOLING/etc/alpine-fde/alpine-fde.conf"
run_stage tooling-release-pub 60 cp "$RUN/keys/release.pub" "$TOOLING/etc/alpine-fde/keys/release.pub"
# release.pem: the release key in the ADR-18 PLAINTEXT staging form (the
# Stage-2 consumption encrypts it with the ceremony passphrase)
run_stage tooling-release-pem 60 cp "$RUN/keys/db.key" "$TOOLING/etc/alpine-fde/keys/release.pem"
printf 'root UUID=%s none luks,tpm2-device=auto,discard\n' "$DISK_UUID" >"$TOOLING/etc/crypttab"
# /etc/motd: ONE operator line (ADR-20 #4: no banner is ever written, and the
# completion chain must never touch motd)
printf 'Welcome to the Alpine FDE harness fixture — operator content stays.\n' \
    >"$TOOLING/etc/motd"
# the ADR-21 pieces of the fed-session drive: the ESCROW COPY (what the
# consume bind-mounts — the ESP copy is baked separately above), the mini-PE
# UKI fixture (fin_uki_pcrsig's ALPINE_FDE_ESP resident), and the scenario's
# own tpm2_pcrextend-refusing + vfat-to-bind mount shims (see the header)
run_stage tooling-escrow-copy 60 cp "$RUN/volume-keys.json" \
    "$TOOLING/escrow/esp/alpine-fde-provision/volume-keys.json"
# the REQUEST marker carries the CANONICAL CMDLINE DIGEST (the consume gate,
# S-22/2026-10-03): the consume only engages when /proc/cmdline matches the
# installed cmdline — the fed drive's booted cmdline IS $RUN/cmdline.txt
# (uki_build-feed wrote it), so the fixture stages its normalized digest.
tr -s ' \t\n' ' ' <"$RUN/cmdline.txt" | sed 's/^ //;s/ $//' | sha256sum | awk '{print $1}' \
    >"$TOOLING/escrow/esp/alpine-fde-provision/REQUEST"
run_stage tooling-minipe 60 cp "$RUN/alpine-fde-fixture.efi" \
    "$TOOLING/efi/EFI/Linux/alpine-fde-fixture.efi"
mkdir -p "$TOOLING/s21shims"
printf '#!/bin/sh\n# s21 shim: refuse the PCR 11 extend (the fed-session hook drive must not\n# double-extend past the signed enter-initrd value the in-initrd hook set)\nexit 1\n' \
    >"$TOOLING/s21shims/tpm2_pcrextend"
printf '#!/bin/sh\n# s21 shim: the harness initrd has no vfat module — translate the hook'"'"'s\n# `mount -t vfat DEV MNT` (the escrow-detect ESP mount) into a BIND mount of\n# the payload escrow dir; every other mount shape passes through. /bin/mount\n# is the initrd'"'"'s busybox mount link — NEVER bare `mount` (that would\n# recurse into this shim through the prepended PATH).\n[ "$1" = "-t" ] && [ "$2" = "vfat" ] && { shift 2; mkdir -p "$2" && exec /bin/mount -o bind "$S21_ESP_BIND" "$2"; }\nexec /bin/mount "$@"\n' \
    >"$TOOLING/s21shims/mount"
chmod 755 "$TOOLING/s21shims/tpm2_pcrextend" "$TOOLING/s21shims/mount"

run_stage tooling-tar 300 tar -C "$TOOLING" -czf "$RUN/tooling.tar.gz" \
    opt etc usr escrow efi s21shims
tar -tzf "$RUN/tooling.tar.gz" >"$RUN/tooling.listing"
if grep -qx "opt/alpine-fde/bin/alpine-fde" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/baseline.json" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/keys/release.pub" "$RUN/tooling.listing" \
    && grep -qx "etc/alpine-fde/keys/release.pem" "$RUN/tooling.listing" \
    && grep -qx "etc/crypttab" "$RUN/tooling.listing" \
    && grep -qx "etc/init.d/alpine-fde-finalize" "$RUN/tooling.listing" \
    && grep -qx "etc/runlevels/default/alpine-fde-finalize" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/flock" "$RUN/tooling.listing" \
    && grep -qx "usr/bin/objcopy" "$RUN/tooling.listing" \
    && grep -qx "escrow/esp/alpine-fde-provision/volume-keys.json" "$RUN/tooling.listing" \
    && grep -qx "escrow/esp/alpine-fde-provision/REQUEST" "$RUN/tooling.listing" \
    && grep -qx "efi/EFI/Linux/alpine-fde-fixture.efi" "$RUN/tooling.listing" \
    && grep -qx "s21shims/mount" "$RUN/tooling.listing" \
    && ! grep -E '^(etc|usr)/' "$RUN/tooling.listing" | grep -qE 'systemd|debian-fde'; then
    _assert_result ok "S-21 fixture: tooling payload built (CLI + Stage-1 docs + advisory oneshot + rc-update record + closures + escrow copy + mini-PE + shims, NO systemd)" ""
else
    _assert_result not-ok "S-21 fixture: tooling payload built" \
        "required entries missing from (or forbidden entries in) the tar listing (see $RUN/tooling.listing)"
fi

# ============================================================================
# Fixture stage 5: the enriched rootfs payload + the ONE installer boot.
# ============================================================================
_PAYLOAD_TARBASE="$ROOTFS_CACHE_DIR/debian-13-generic-amd64-rootustar.tar.gz"
if [[ ! -f "$_PAYLOAD_TARBASE" ]]; then
    # force the (cached) derivation via the harness builder, then discard
    run_stage payload-derive 2400 bash -c \
        "$(declare -f rootfs_payload_image rootfs_ensure _rootfs_pin_lookup rootfs_cache_dir); \
         $(declare -p ROOTFS_CACHE_DIR _ROOTFS_PINS _DEB_BASE _CLOUD_BASE 2>/dev/null); \
         rootfs_payload_image '$RUN/payload-derive-scratch.img' >/dev/null"
fi
[[ -f "$_PAYLOAD_TARBASE" ]] || { echo "s21: derived rootfs payload missing after derivation"; exit 1; }
_budget_check payload-enrich
echo "# s21: enriching the rootfs payload (base tree + Stage-1 additions + admin account, ONE tar)"
# NOT a concatenated archive: busybox tar (the installer's extractor) stops at
# the first stream's end-of-archive marker, silently dropping the second
# stream (observed live 2026-09-19). Merge into ONE tree, then re-tar.
# The ADMIN ACCOUNT (uid 1000, home /home/admin, LOCKED shadow) is appended
# to the BASE tree's passwd/shadow — never overlaid (a tooling etc/passwd
# would clobber the rootfs account db wholesale).
run_stage payload-build 1800 bash -c '
    set -eu
    mkdir -p "$2/basetree"
    tar -xf "$1" -C "$2/basetree"
    cp -a "$3"/. "$2/basetree"/
    printf "admin:x:1000:1000:operator:/home/admin:/bin/sh\n" >> "$2/basetree/etc/passwd"
    printf "admin:!::0:::::\n" >> "$2/basetree/etc/shadow"
    mkdir -p "$2/basetree/home/admin"
    tar -C "$2/basetree" --format=ustar --owner=0 --group=0 --numeric-owner -cf "$2/combined.tar" .
    gzip -n < "$2/combined.tar" > "$2/enriched.tar.gz"
' _ "$_PAYLOAD_TARBASE" "$RUN" "$TOOLING"
ROOTFS_SHA=$(sha256sum "$RUN/enriched.tar.gz" | awk '{print $1}')
ROOTFS_BYTES=$(stat -c%s "$RUN/enriched.tar.gz")
_aligned=$(((ROOTFS_BYTES + 1048575) / 1048576 * 1048576))
truncate -s "$_aligned" "$RUN/payload.img"
dd if="$RUN/enriched.tar.gz" of="$RUN/payload.img" conv=notrunc status=none
assert_file_exists "S-21 fixture: enriched payload drive (installer input)" "$RUN/payload.img"
tar -tzf "$RUN/enriched.tar.gz" | grep -qxE '\./?etc/alpine-fde/baseline.json' \
    || { echo "s21: additions missing from the enriched payload"; exit 1; }
_assert_result ok "S-21 fixture: Stage-1 additions present in the enriched payload tar" ""

ALPINE_FDE_ROOTFS_SHA="$ROOTFS_SHA" ALPINE_FDE_ROOTFS_BYTES="$ROOTFS_BYTES" \
    run_stage uki_build-installer 1200 \
    uki_build "$RUN" "$RUN/keys" "$RUN/harness.efi" "alpine-fde-stage=install"
UKI_MIB=$(( ($(stat -c%s "$RUN/harness.efi") + 1048575) / 1048576 ))
run_stage esp_make-installer 300 esp_make "$RUN/esp-installer.img" \
    $(( UKI_MIB * ROOTFS_RETENTION + ESP_HEADROOM_MIB )) "$RUN/harness.efi"
_ensure_tpm "$RUN/tpm"
_track_swtpm "$RUN/tpm"
echo "# s21: installer boot — populate the installed-state disk (TCG; unlock via /kf0 = the layup keyslot 0)"
CURRENT_QEMU_DIR="$RUN"
run_stage qemu_run-installer 60 qemu_run "$RUN" "$RUN/esp-installer.img" "$RUN/disk.img" \
    "$RUN/vars-enrolled.fd" "$RUN/tpm" "$RUN/payload.img"
_qemu_alive "$RUN"
_rearm_trap
run_stage qemu_wait-installer "$((QEMU_TIMEOUT + 60))" qemu_wait "$RUN" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""
grep -q "alpine-fde: POWEROFF" "$RUN/console.log" || {
    echo "s21: installer boot failed (no POWEROFF sentinel)"; exit 1; }
LOG_INST=$(cat "$RUN/console.log" 2>/dev/null || true)
assert_contains "installer boot: install stage completed" "$LOG_INST" \
    "alpine-fde-harness: install stage complete"
# the SB-on booted PCR 7 (enrolled vars are deterministic across boots) — the
# d7 input of the Stage-2 upgrade's host-composed {7,11} policy signature
PCR7_SBON=$(grep -oE 'alpine-fde-pcr sha256:7=[0-9a-f]{64}' "$RUN/console.log" | head -1 | cut -d= -f2)
[[ -n "$PCR7_SBON" ]] || { echo "s21: no PCR 7 print in the installer console"; exit 1; }
# the populate boot mutated no LUKS structure: 3 keyslots, the ONE provisional token
META1=$(disk_metadata "$RUN/disk.img")
assert_eq "installer boot: disk still exactly 3 keyslots" "3" \
    "$(jq -r '.keyslots | length' <<<"$META1")"
assert_eq "installer boot: disk still exactly ONE token" "1" "$(disk_token_json "$RUN/disk.img" | jq length)"

# ============================================================================
# Fixture stage 6: the {7,11} policy signature for the Stage-2 upgrade, the
# fed tar (#2 = #1 + pcrsig-711), the fed payload drive, and the ADR-21 shape
# completion: keyslot 0 KILLED (free), the layup credential retired.
# ============================================================================
run_stage pcrsig-combined 120 \
    uki_pcrsig_append_combined "$RUN/uki-pcrsig.json" "$RUN/uki-pcrsig-711.json" \
    "$PCR7_SBON" "$D11_PRED" "$RUN/keys" || { echo "s21: combined pcrsig composition failed"; exit 1; }
assert_eq "S-21: combined .pcrsig entry pol == policy_digest(SB-on d7, enter-initrd d11)" \
    "$(policy_digest "$PCR7_SBON" "$D11_PRED")" \
    "$(jq -r '.sha256[-1].pol' "$RUN/uki-pcrsig-711.json")"
run_stage pcrsig711-into-tar 60 cp "$RUN/uki-pcrsig-711.json" "$TOOLING/pcrsig-711.json"
run_stage tooling-tar-fed 300 tar -C "$TOOLING" -czf "$RUN/tooling-fed.tar.gz" \
    opt etc usr escrow efi s21shims pcrsig-711.json
# the fed payload drive: the {11} .pcrsig on the 64 KiB head (the harness /init
# stages it as the hook's FDE_EXTRA_DIR/tpm2-pcr-signature.json) + the fed tar
run_stage pcrsig_disk-feed 60 uki_pcrsig_disk "$RUN/pcrsig-feed.img" "$RUN/uki-pcrsig-11.json"
_budget_check pcrsig-tooling-drive
cat "$RUN/pcrsig-feed.img" "$RUN/tooling-fed.tar.gz" >"$RUN/pcrsig-feed-tooling.img"

# kill the layup keyslot 0 (authorized by the escrowed volume passphrase) —
# the ADR-21 defining shape: keyslot 0 FREE until the ×2 set ceremony
run_stage kill-slot0 300 cryptsetup luksKillSlot --batch-mode \
    --key-file "$RUN/volume-pass" "$RUN/disk.img" 0
META2=$(disk_metadata "$RUN/disk.img")
assert_eq "fixture: ADR-21 shape — keyslot 0 FREE, volume-pass slot 1 + ephemeral slot 2" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$META2")"
if cryptsetup open --test-passphrase "$RUN/disk.img" --key-file "$RUN/volume-pass" 2>/dev/null; then
    _assert_result ok "fixture: the escrowed volume passphrase opens the container" ""
else
    _assert_result not-ok "fixture: the escrowed volume passphrase opens the container" "test-passphrase refused"
fi
if cryptsetup open --test-passphrase "$RUN/disk.img" --key-file "$RUN/ephkey" 2>/dev/null; then
    _assert_result ok "fixture: the ephemeral install key opens the container" ""
else
    _assert_result not-ok "fixture: the ephemeral install key opens the container" "test-passphrase refused"
fi
# host-side secret hygiene: the volume passphrase is consumed — the escrow on
# the ESP and the tooling copy are its only holders (the real install scrubs
# it the same way; I1)
run_stage volume-pass-scrub 60 rm -f "$RUN/volume-pass"
rm -f "$RUN/slot0pw" "$RUN/ephkey"

# _run_fed_boot <boot-dir> <disk-img> <vars.fd> — boot with the feeding UKI on
# the SHIPPED §8.2 hook: the container's PROVISIONAL {11} token unlocks the
# volume passwordlessly in-initrd (the escrow is NOT consumed in-initrd — the
# harness initrd has no blkid/vfat/FDE_ESP_DEV channel; see the header), then
# hands over to the fed DEBUG SHELL. A failure of the composed seal falls into
# the hook's recovery loop (prompts) and the UNSEALED wait fails LOUDLY with
# the console tail — the scenario never feeds a passphrase it staged.
_run_fed_boot() {
    local bdir="$1" bimg="$2" vars="$3"
    mkdir -p "$bdir"
    cp "$RUN/harness-feed.efi" "$bdir/harness.efi"
    cp "$RUN/esp-feed.img" "$bdir/esp.img"
    # Wave-2 2b: the caller either hands us a prepared QCOW2 OVERLAY (a
    # read-mostly base boot, decision rule 1 — used as-is) or a raw image that
    # must be copied per boot (the persistent-mutation leg, decision rule 2 —
    # boot B's writes MUST land in the bootable copy and are read back
    # host-side with cryptsetup, which cannot operate on qcow2).
    local DISKIMG
    case "$bimg" in
        *.qcow2) DISKIMG="$bimg" ;;
        *) cp "$bimg" "$bdir/disk.img"; DISKIMG="$bdir/disk.img" ;;
    esac
    _ensure_tpm "$RUN/tpm"
    _rearm_trap
    CURRENT_QEMU_DIR="$bdir"
    run_stage "qemu_run:$(basename "$bdir")" 60 qemu_run "$bdir" "$bdir/esp.img" \
        "$DISKIMG" "$vars" "$RUN/tpm" "$RUN/pcrsig-feed-tooling.img"
    _qemu_alive "$bdir"
    _rearm_trap
    # the token path's own console record ("token: pcrs=[11] ...") proves the
    # provisional seal fired BEFORE the UNSEALED/DEBUG-SHELL handover
    wait_console "$bdir" "$(sentinel_of unseal_token_info)" 600
    wait_console "$bdir" "alpine-fde: UNSEALED" 300
    wait_console "$bdir" "DEBUG SHELL on console" 300
}

# _feed_common <boot-dir> — the shared fed-session prefix: tooling untar,
# on-disk fixture proof, the account-db stand-in, the shims, the CLI env.
_feed_common() {
    local bdir="$1"
    feed_line "$bdir/serial.sock" \
        'dd if=/dev/vdc bs=65536 skip=1 | gzip -dc > /tooling.tgz; echo P2A=$?'
    wait_console "$bdir" "P2A=0" 300
    feed_line "$bdir/serial.sock" 'tar -xf /tooling.tgz -C / && echo P2B-$((40+2))-OK'
    wait_console "$bdir" "P2B-42-OK" 300
    feed_line "$bdir/serial.sock" \
        'mkdir -p /mnt /run/bu && mount -t btrfs -o subvol=@ /dev/mapper/root /mnt && ls -l /mnt/etc/init.d/alpine-fde-finalize /mnt/etc/runlevels/default/ && grep -c "^admin:x:1000:1000" /mnt/etc/passwd && cat /mnt/etc/crypttab && ln -sf /dev/vdb /run/bu/'"$DISK_UUID"' && echo P4-$((41+3))-OK'
    wait_console "$bdir" "P4-44-OK" 300
    # the chpasswd consumption leg edits the RUNNING account db — in this
    # initrd env that is the initrd's passwd/shadow (the disk rootfs carries
    # the fixture's admin account, pinned by P4 above); stage the same admin
    # here so the leg behaves exactly as on the real first boot.
    feed_line "$bdir/serial.sock" \
        'printf "admin:x:1000:1000:operator:/home/admin:/bin/sh\n" >> /etc/passwd; printf "admin:!::0:::::\n" >> /etc/shadow; mkdir -p /newroot/run /tmp /escrow && echo P4B-$((40+7))-OK'
    wait_console "$bdir" "P4B-47-OK" 120
    # the CLI/service environment: by-uuid seam (no udev reliance), payload
    # wrappers, ALPINE_FDE_ROOT=/mnt — the legs mutate the DISK documents;
    # ALPINE_FDE_ESP=/efi (the mini-PE fixture) is fin_uki_pcrsig's resident;
    # ALPINE_FDE_PCRSIG is the host-composed {7,11} policy (the upgrade input).
    feed_line "$bdir/serial.sock" \
        "export ALPINE_FDE_NO_INSTALL=1 ALPINE_FDE_TCTI=device:/dev/tpmrm0 ALPINE_FDE_BY_UUID_DIR=/run/bu ALPINE_FDE_CMD_DIR=/opt/alpine-fde/lib/cmd ALPINE_FDE_CRYPTSETUP=/usr/bin/cryptsetup-pretty ALPINE_FDE_ROOT=/mnt ALPINE_FDE_EVENTLOG=/evtlog-absent ALPINE_FDE_TMPDIR=/tmp ALPINE_FDE_KEYDIR=/mnt/etc/alpine-fde/keys ALPINE_FDE_KEY_PASSPHRASE=$S21_KEYPASS ALPINE_FDE_ESP=/efi ALPINE_FDE_PCRSIG=/pcrsig-711.json && echo P5-\$((43))-OK"
    wait_console "$bdir" "P5-43-OK" 120
}

# _await_rc <boot-dir> — wait out a `... ; echo P6-RC=$RC` leg.
# TCG serial corruption guard (the doubled-byte class — live 2026-09-25): the
# value is RE-DERIVED from the LIVE variable in two short re-emissions and
# the majority of {first, re1, re2} wins — state-grounded, never a replay.
_await_rc() {
    local bdir="$1" i=0 rc re1 re2
    until grep -qE 'P6-RC=[0-9]+' "$bdir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$bdir" "console-wait:P6-RC"
        _budget_check "console-wait:P6-RC"
        (( i < 300 )) || _hang_fail CONSOLE-WAIT "P6-RC" "the leg never returned"
        sleep 1
        i=$((i + 1))
    done
    rc=$(grep -oE 'P6-RC=[0-9]+' "$bdir/console.log" | head -1 | cut -d= -f2)
    feed_line "$bdir/serial.sock" 'echo "P6RC2=$RC"'
    i=0
    until grep -qE 'P6RC2=[0-9]+' "$bdir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$bdir" "console-wait:P6RC2"
        _budget_check "console-wait:P6RC2"
        (( i < 60 )) || break
        sleep 1
        i=$((i + 1))
    done
    re1=$(grep -oE 'P6RC2=[0-9]+' "$bdir/console.log" | head -1 | cut -d= -f2)
    feed_line "$bdir/serial.sock" 'echo "P6RC3=$RC"'
    i=0
    until grep -qE 'P6RC3=[0-9]+' "$bdir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$bdir" "console-wait:P6RC3"
        _budget_check "console-wait:P6RC3"
        (( i < 60 )) || break
        sleep 1
        i=$((i + 1))
    done
    re2=$(grep -oE 'P6RC3=[0-9]+' "$bdir/console.log" | head -1 | cut -d= -f2)
    if [[ "$re1" == "$rc" || "$re2" == "$rc" ]]; then
        printf '%s\n' "$rc"
    elif [[ -n "$re1" && "$re1" == "$re2" ]]; then
        printf '%s\n' "$re1"   # both fresh emissions agree against one stale burst
    else
        printf '%s\n' "${re1:-$rc}"
    fi
}

# ============================================================================
# BOOT A — §10 first-boot row: SB OFF -> the ADR-20 amended PRE-UNSEAL GUARD
# blocks at the hook's FIRST step — BEFORE any escrow detection/consumption.
# The disk is NEVER unlocked and the ESCROW IS NEVER CONSUMED; the fed legs
# are UNREACHABLE under SB off. The hook parks on its Enter read; the
# scenario waits for the guard sentinel and hard-kills qemu BY PID.
# ============================================================================
A="$RUN/boot-a"
# Wave-2 2b (decision rule 1): boot A is a READ-MOSTLY base boot — the guard
# blocks before ANY mutation, and the boot runs on a fresh QCOW2 overlay over
# the pristine fixture disk; the overlay is discarded right after the kill.
mkdir -p "$A"
overlay_create "$RUN/disk.img" "$A/disk.qcow2" || {
    echo "s21: overlay create failed (boot A)"; exit 1; }
echo "# boot A: SB-off vars — the initramfs pre-unseal guard must BLOCK (no unlock, no escrow consumption, no fed session)"
_ensure_tpm "$RUN/tpm"
_rearm_trap
CURRENT_QEMU_DIR="$A"
run_stage "qemu_run:boot-a" 60 qemu_run "$A" "$RUN/esp-feed.img" "$A/disk.qcow2" \
    "$RUN/vars-unenrolled.fd" "$RUN/tpm" "$RUN/pcrsig-feed-tooling.img"
_qemu_alive "$A"
_rearm_trap
# wait for the guard sentinel with a qemu-liveness poll, feed the operator's
# Enter confirmation, wait for the reboot sentinel, then kill BY PID
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_enter)" "$A/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$A" "console-wait:guard"
    _budget_check "console-wait:guard"
    (( i < 300 )) || _hang_fail CONSOLE-WAIT "pre-unseal guard" "never armed"
    sleep 1
    i=$((i + 1))
done
feed_line "$A/serial.sock" ""   # the operator's Enter confirmation
i=0
until grep -qF "$(sentinel_of unseal_sb_guard_reboot)" "$A/console.log" 2>/dev/null; do
    _qemu_alive_or_die "$A" "console-wait:guard-reboot"
    _budget_check "console-wait:guard-reboot"
    (( i < 60 )) || _hang_fail CONSOLE-WAIT "pre-unseal guard reboot" "never rebooted after Enter"
    sleep 1
    i=$((i + 1))
done
qemu_kill "$A"   # BY PID (tests/lib/qemu.sh); the guest cannot exit itself here
CURRENT_QEMU_DIR=""
overlay_discard "$A/disk.qcow2"   # boot A's overlay is ephemeral (console + base asserts below)

LOG_A=$(cat "$A/console.log" 2>/dev/null || true)
assert_contains "[boot A] init ran" "$LOG_A" "alpine-fde-harness: init started"
assert_contains "[boot A] the shipped §8.2 hook executed (guard context)" "$LOG_A" \
    "invoking /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
# ordering proof: the guard fired BEFORE any TPM work — no enter-initrd extend
_guard_line=$(grep -nm1 -F "$(sentinel_of unseal_sb_guard)" "$A/console.log" 2>/dev/null | cut -d: -f1)
_exta_line=$(grep -nm1 -F "$(sentinel_of unseal_pcrextend_ok)" "$A/console.log" 2>/dev/null | cut -d: -f1)
if [[ -n "${_guard_line:-}" && -z "${_exta_line:-}" ]]; then
    _assert_result ok "[boot A] the guard fired BEFORE any TPM work (line $_guard_line, no extend)" ""
else
    _assert_result not-ok "[boot A] the guard fired BEFORE any TPM work" \
        "guard=$_guard_line pcrextend=$_exta_line"
fi
assert_contains "[boot A] guard: the blocking refusal names the pre-unseal guard" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard)"
assert_contains "[boot A] guard: the refusal carries the LIVE secureboot=0 reading" "$LOG_A" \
    "secureboot=0"
assert_contains "[boot A] guard: Press-Enter confirmation prompt" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_enter)"
assert_contains "[boot A] guard: OsIndications boot-to-firmware-setup requested" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_osind)"
assert_contains "[boot A] guard: reboot into the firmware setup" "$LOG_A" \
    "$(sentinel_of unseal_sb_guard_reboot)"
assert_not_contains "[boot A] NO enter-initrd extend (the guard precedes §8.2 step 2)" "$LOG_A" \
    "$(sentinel_of unseal_pcrextend_ok)"
assert_not_contains "[boot A] NO escrow consumption (the guard precedes ADR-21 step 5)" "$LOG_A" \
    "via the provisioning escrow"
assert_not_contains "[boot A] NO token discovery (NEVER unsealed with SB off)" "$LOG_A" \
    "$(sentinel_of unseal_token_info)"
assert_not_contains "[boot A] NO recovery-passphrase prompt (the fallback is RETRACTED under SB off)" "$LOG_A" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[boot A] NO 3-strike path" "$LOG_A" "$(sentinel_of unseal_3strike)"
assert_not_contains "[boot A] NO fail-closed poweroff (the terminal action is the REBOOT)" "$LOG_A" \
    "$(sentinel_of unseal_poweroff)"
assert_not_contains "[boot A] never unlocked (token)" "$LOG_A" "$(sentinel_of unseal_unlocked)"
assert_not_contains "[boot A] never unlocked (recovery passphrase)" "$LOG_A" \
    "$(sentinel_of unseal_pass_unlocked)"
assert_not_contains "[boot A] never UNSEALED (the fed session is unreachable under SB off)" "$LOG_A" \
    "alpine-fde: UNSEALED"
assert_not_contains "[boot A] no emergency shell" "$LOG_A" "$(sentinel_of emergency_forbidden)"
# the scenario hard-killed the parked guest (BY PID)
if [[ -f "$A/qemu.pid" ]] && ! kill -0 "$(cat "$A/qemu.pid" 2>/dev/null)" 2>/dev/null; then
    _assert_result ok "[boot A] guest torn down (qemu_kill BY PID after the guard sentinel)" ""
else
    _assert_result not-ok "[boot A] guest torn down (qemu_kill BY PID after the guard sentinel)" \
        "qemu still running or qemu.pid missing"
fi
# post-boot HOST (Wave-2 2b: boot A ran on a discarded QCOW2 overlay, so the
# host-side cryptsetup reads target the RAW fixture disk — the invariant they
# pin — "the boot mutated no LUKS metadata structure" — holds structurally AND
# on the base the overlay backs onto): keyslot 0 FREE, the {11} token + the
# ephemeral intact.
META_A=$(disk_metadata "$RUN/disk.img")
assert_eq "[boot A] host(base): metadata unchanged — keyslots 1+2 (keyslot 0 FREE)" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$META_A")"
assert_eq "[boot A] host(base): metadata unchanged — exactly ONE token (the {11} seal)" "1" \
    "$(disk_token_json "$RUN/disk.img" | jq length)"
assert_eq "[boot A] host(base): keyslot 1 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["1"].kdf.type' <<<"$META_A")"
# the ADR-21 escrow STILL STANDING on the ESP image (mtools, no mount)
if mtype -i "$RUN/esp-feed.img" "::/alpine-fde-provision/REQUEST" >/dev/null 2>&1 \
    && mtype -i "$RUN/esp-feed.img" "::/alpine-fde-provision/volume-keys.json" 2>/dev/null |
    jq -e '.members[0].uuid == "'"$DISK_UUID"'"' >/dev/null 2>&1; then
    _assert_result ok "[boot A] host: the provisioning escrow STILL STANDING on the ESP (REQUEST + volume-keys.json, SB off consumed nothing)" ""
else
    _assert_result not-ok "[boot A] host: the provisioning escrow STILL STANDING on the ESP" \
        "REQUEST or volume-keys.json missing/mangled after the SB-off boot"
fi

# ============================================================================
# BOOT B — SB ON: the provisional-token unlock, then the fed ADR-21 legs:
# the ESCROW CONSUME (shipped hook, seams), the ×2 SET STAND-IN, and the
# STAGE-2 SERVICE (fin_service_main) through the ADR-21 consumption legs.
# ============================================================================
B="$RUN/boot-b"
cp "$RUN/disk.img" "$RUN/disk-b.img"
echo "# boot B: SB-on vars — the provisional {11} unlock in-initrd, then the escrow consume + the Stage-2 service in the fed session"
_run_fed_boot "$B" "$RUN/disk-b.img" "$RUN/vars-enrolled.fd"
_feed_common "$B"

# --- leg E1: THE ESCROW BOOT — the shipped hook re-run as a direct drive.
# The mapper is closed first (the in-initrd token path already holds it — the
# R640-observed race this drive resolves); the shims keep PCR 11 at the
# single-extend signed value and give the detect a mountable ESP. The hook
# BLOCKS in the ×2 ceremony after the unlock: the two passphrase reads are
# fed prompt-synchronized through the console (the operator's typing; the
# ceremony's stty -echo keeps the value out of the capture).
feed_line "$B/serial.sock" \
    'cryptsetup close root; if [ ! -e /dev/mapper/root ]; then echo ESC-CLOSE-$((40+2))-OK; else echo ESC-CLOSE-42-FAIL; fi'
wait_console "$B" "ESC-CLOSE-42" 120
assert_not_contains "[boot B] escrow boot: the mapper close SUCCEEDED (the token unlock released the hold)" \
    "$(cat "$B/console.log" 2>/dev/null || true)" "ESC-CLOSE-42-FAIL"
feed_line "$B/serial.sock" \
    'OLDPATH=$PATH; export PATH=/s21shims:$PATH S21_ESP_BIND=/escrow/esp FDE_ESP_DEV=/dev/vda FDE_ESP_MNT=/run/alpine-fde-esp FDE_NEWROOT=/ FDE_CONSOLE_IN=/tmp/ceremony.in ALPINE_FDE_TCTI=device:/dev/tpmrm0; sh /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh; echo ESC-HOOK-RC=$?; export PATH=$OLDPATH; echo ESC-DONE-$((44+3))-OK'
# the ×2 SET ceremony: BOTH prompts verbatim, each fed at its own prompt
wait_console "$B" "set the recovery passphrase (it is also your admin login): " 600
feed_line "$B/serial.sock" "$S21_RECOVERY"
wait_console "$B" "confirm the recovery passphrase: " 120
feed_line "$B/serial.sock" "$S21_RECOVERY"
wait_console "$B" "ESC-DONE-47-OK" 600

LOG_B=$(cat "$B/console.log" 2>/dev/null || true)
# the in-initrd phase: the provisional {11} token unlocked passwordlessly
assert_contains "[boot B] init ran" "$LOG_B" "alpine-fde-harness: init started"
assert_contains "[boot B] the provisional {11} token was discovered (the ADR-21 pre-convergence unlock)" "$LOG_B" \
    "$(sentinel_of unseal_token_info)"
assert_contains "[boot B] the provisional token pins PCR 11 ONLY" "$LOG_B" "token: pcrs=[11]"
assert_contains "[boot B] unlocked via the TPM token (passwordless, keyslot 1)" "$LOG_B" \
    "$(sentinel_of unseal_unlocked)"
_postphase=$(grep -oE 'alpine-fde-pcr-postphase sha256:11=[0-9a-f]{64}' "$B/console.log" 2>/dev/null | head -1 | cut -d= -f2)
assert_eq "[boot B] post-extend PCR 11 == the signed enter-initrd prediction (single extend)" \
    "alpine-fde-pcr-postphase sha256:11=$D11_PRED" \
    "alpine-fde-pcr-postphase sha256:11=$_postphase"
assert_contains "[boot B] UNSEALED" "$LOG_B" "alpine-fde: UNSEALED"
assert_not_contains "[boot B] NO token_missing (the provisional seal stands)" "$LOG_B" \
    "$(sentinel_of unseal_token_missing)"
assert_not_contains "[boot B] NO recovery-passphrase prompt (the {11} seal unlocks)" "$LOG_B" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[boot B] NO recovery-passphrase unlock" "$LOG_B" \
    "$(sentinel_of unseal_pass_unlocked)"
# the escrow boot: the shipped hook's REAL markers (dual-emission: the
# harness runs the hook with FDE_SERIAL_ECHO=1 — live + [serial-echo] copy;
# the CEREMONY prompts are single-emission by design — they render through
# the raw emit fan-out, not _msg)
assert_contains "[boot B] escrow boot: unlocked via the provisioning escrow (real-measurement {7,11} seal)" "$LOG_B" \
    "via the provisioning escrow (real-measurement {7,11} seal)"
assert_eq "[boot B] escrow boot: the unlock marker dual-emitted (live + serial-echo)" "2" \
    "$(grep -cF 'via the provisioning escrow (real-measurement {7,11} seal)' <<<"$LOG_B")"
assert_contains "[boot B] escrow boot: the ×2 ceremony SET prompt rendered" "$LOG_B" \
    "set the recovery passphrase (it is also your admin login): "
assert_contains "[boot B] escrow boot: the ×2 ceremony CONFIRM prompt rendered" "$LOG_B" \
    "confirm the recovery passphrase: "
assert_contains "[boot B] escrow boot: the passphrase set + staged for the Stage-2 finalize (hook _msg)" "$LOG_B" \
    "the recovery passphrase is set and staged for the Stage-2 finalize (your admin login is the same passphrase)"
assert_eq "[boot B] escrow boot: the staged marker dual-emitted (live + serial-echo)" "2" \
    "$(grep -cF 'the recovery passphrase is set and staged for the Stage-2 finalize' <<<"$LOG_B")"
assert_contains "[boot B] escrow boot: the escrow DELETED after the ceremony (step h — consumed)" "$LOG_B" \
    "provisioning escrow: consumed — the Stage-2 finalize completes on this boot"
assert_eq "[boot B] escrow boot: the consumed marker dual-emitted (live + serial-echo)" "2" \
    "$(grep -cF 'provisioning escrow: consumed — the Stage-2 finalize completes on this boot' <<<"$LOG_B")"
assert_not_contains "[boot B] escrow boot: NO recovery prompt in the boot either" "$LOG_B" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[boot B] escrow boot: the ceremony passphrase is NEVER echoed into the capture" "$LOG_B" \
    "$S21_RECOVERY"
assert_not_contains "[boot B] no interactive recovery prompt ever appeared (sentinel table)" "$LOG_B" \
    "$(sentinel_of prompt_re)"
assert_not_contains "[boot B] no emergency shell" "$LOG_B" "$(sentinel_of emergency_forbidden)"
assert_not_contains "[boot B] NO cryptenroll anywhere (Mechanism B never invokes it)" "$LOG_B" \
    "$(sentinel_of cryptenroll_enrolled)"

# --- leg E2: post-boot metadata — the self-sealed {7,11} token with the
# EMPTY signature marker; the provisional sibling STILL standing (the shipped
# consume leaves it; the design's step-e retirement is leg E3's stand-in);
# keyslot 0 now holds the ceremony passphrase; the bind-source escrow GONE.
feed_line "$B/serial.sock" \
    'echo "ESCTOK $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c "[.tokens | to_entries[] | {id: .key, pcrs: .value[\"tpm2-pcrs\"], siglen: (.value[\"tpm2-signature\"] | length)}]")"; echo "ESCSLOTS $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c ".keyslots | keys")"; echo "ESCKS0 $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -r ".keyslots[\"0\"].kdf.type")"; echo "ESCFILES $(ls /escrow/esp/alpine-fde-provision/ 2>/dev/null | tr "\n" ",")dir=$([ -d /escrow/esp/alpine-fde-provision ] && echo present || echo gone)"; echo "ESCSTAGE $(stat -c %a /run/alpine-fde-provision-pass 2>/dev/null || echo absent)"; echo ESC-META-$((40+7))-DONE'
wait_console "$B" "ESC-META-47-DONE" 300
LOG_E2=$(cat "$B/console.log" 2>/dev/null || true)
ESCTOK=$(grep -oE 'ESCTOK \[.*\]' <<<"$LOG_E2" | head -1 | cut -d' ' -f2-)
assert_eq "[boot B] post-boot: TWO tokens — the {11} provisional (id 0) + the escrow self-seal (id 1)" \
    '[{"id":"0","pcrs":[11],"siglen":344},{"id":"1","pcrs":[7,11],"siglen":0}]' \
    "$ESCTOK"
ESCSLOTS=$(grep -oE 'ESCSLOTS \[.*\]' <<<"$LOG_E2" | head -1 | cut -d' ' -f2-)
assert_eq "[boot B] post-boot: keyslots 0 (the ceremony's enrollment) + the volume-pass slot 1 + the ephemeral 2" \
    '["0","1","2"]' "$ESCSLOTS"
ESCKS0=$(grep -oE 'ESCKS0 [a-z0-9]+' <<<"$LOG_E2" | head -1 | cut -d' ' -f2)
assert_eq "[boot B] post-boot: keyslot 0 is argon2id (enrolled by the ×2 ceremony, §13)" \
    "argon2id" "$ESCKS0"
ESCSTAGE=$(grep -oE 'ESCSTAGE [a-z0-9]+' <<<"$LOG_E2" | head -1 | cut -d' ' -f2)
assert_eq "[boot B] post-boot: the staged ceremony passphrase is 0600 at /run/alpine-fde-provision-pass" \
    "600" "$ESCSTAGE"
if grep -qF 'ESCFILES dir=gone' <<<"$LOG_E2"; then
    _assert_result ok "[boot B] post-boot: the escrow DELETED from the consumed ESP (REQUEST + volume-keys.json gone, step h)" ""
else
    _assert_result not-ok "[boot B] post-boot: the escrow DELETED from the consumed ESP (REQUEST + volume-keys.json gone, step h)" \
        "$(grep -oE 'ESCFILES [^;]*' <<<"$LOG_E2" | head -1)"
fi
# the scenario's baked ESP IMAGE copy is a fixture artifact (the guest boots a
# per-boot COPY and never writes the baked image) — the delete is pinned on
# the consumed bind source above; the baked copy proves the fixture was live.
if mtype -i "$RUN/esp-feed.img" "::/alpine-fde-provision/REQUEST" >/dev/null 2>&1; then
    _assert_result ok "[boot B] host: the fixture's baked ESP escrow intact (the guest booted a per-boot copy; boot isolation)" ""
else
    _assert_result not-ok "[boot B] host: the fixture's baked ESP escrow intact (boot isolation)" \
        "the baked image was mutated — the boot was NOT isolated"
fi

# --- leg E3: the STEP-(e) RETIREMENT STAND-IN — the shipped consume imports
# the {7,11} token at a free id and leaves the provisional {11} token
# standing (the header's "takes its id" is not implemented); the Stage-2
# chain needs the provisional first-in-line (its policyauthorize-only
# re-unseal is the service authorization) and the upgrade's post-assert
# refuses a second standing token — so the scenario retires the ESCROW
# self-seal token AFTER its metadata was pinned by E2.
feed_line "$B/serial.sock" \
    'cryptsetup token remove --token-id 1 /dev/vdb && echo X2-RETIRE-$((45+4))-OK'
wait_console "$B" "X2-RETIRE-49-OK" 120
LOG_E3=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] ×2 stand-in: the escrow self-seal token retired (the design's step-e takeover)" "$LOG_E3" \
    "X2-RETIRE-49-OK"

# --- leg E4: THE STAGE-2 SERVICE — the oneshot's start() body (the same
# sourcing + fin_service_main call hooks/openrc/alpine-fde-finalize runs).
# A subshell contains strict_mode; the completion log is catted to the
# console so every completion marker is asserted from the console stream.
feed_line "$B/serial.sock" \
    '( . /opt/alpine-fde/lib/trust-state.sh && . /opt/alpine-fde/lib/cmd/finalize.sh && echo "SVC-STATE=$(ts_label 2>/dev/null)"; RC=0; fin_service_main >/tmp/svc.log 2>&1 || RC=$?; cat /tmp/svc.log; echo P6-RC=$RC; echo SVC-DONE-$((40+10)) )'
wait_console "$B" "SVC-DONE-50" 600
SVC_RC_B=$(_await_rc "$B")

# --- leg E5: the on-disk post-state evidence (console-borne: the LUKS/btrfs
# container is not host-mountable unprivileged)
feed_line "$B/serial.sock" \
    'echo "P7PCRS $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c "first(.tokens // {} | to_entries[] | select(.value.type? == \"systemd-tpm2\") | .value[\"tpm2-pcrs\"] // empty)")"; echo "P7TOK $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq "[.tokens[] | select(.type==\"systemd-tpm2\")] | length")"; echo "P7SLOTS $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -c ".keyslots | keys")"; echo "P7SIGLEN $(cryptsetup luksDump --dump-json-metadata /dev/vdb | jq -r "first(.tokens // {} | .[] | select(.type? == \"systemd-tpm2\") | .\"tpm2-signature\" | length")"; echo "P7STAGE $([ -e /run/alpine-fde-provision-pass ] && echo present || echo gone)"; echo "P7PBES2 $(openssl asn1parse -in /mnt/etc/alpine-fde/keys/release.pem 2>/dev/null | grep -c PBES2)"; echo "P7TS $( (. /opt/alpine-fde/lib/trust-state.sh && ts_label) 2>/dev/null )"; echo "P7ATT $(cat /mnt/etc/alpine-fde/finalize-attempt.txt 2>/dev/null | grep -o "will retry next boot" || echo none)"; echo "P7MOTD $(cat /mnt/etc/motd)"; echo P7-$((41+4))-DONE'
wait_console "$B" "P7-45-DONE" 300
feed_line "$B/serial.sock" 'sync; poweroff -f'
run_stage "qemu_wait:boot-b" "$((QEMU_TIMEOUT + 60))" qemu_wait "$B" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

# --- the Stage-2 chain, asserted from the console stream --------------------
LOG_SVC=$(sed -n '/SVC-STATE/,$p' "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] service: the ground-truth state was PROVISIONAL ({11} + the ephemeral slot)" "$LOG_SVC" \
    "SVC-STATE=provisional"
assert_contains "[boot B] service: the pending baseline finalized from live values (audit --init)" "$LOG_SVC" \
    "finalizing the baseline from live values (audit --init"
assert_contains "[boot B] service: the TEMPORARY ephemeral install key purged (keyslot 2)" "$LOG_SVC" \
    "temporary ephemeral install key purged (keyslot 2)"
assert_contains "[boot B] service: the member upgraded to Mechanism B {PCR 7, PCR 11}" "$LOG_SVC" \
    "alpine-fde: member $DISK_UUID: token upgraded to Mechanism B {PCR 7, PCR 11}"
assert_contains "[boot B] service: the ADR-21 consumption — the ceremony marker (keyslot 0 + release.pem + the account passwords)" "$LOG_SVC" \
    "provisioning ceremony complete: keyslot 0 enrolled, release.pem encrypted, the admin + root passwords set from your passphrase"
assert_not_contains "[boot B] service: NO banner step in the completion (ADR-20 #4: the banner path is removed)" "$LOG_SVC" \
    "unfinalized MOTD/issue banner cleared"
assert_eq "[boot B] service: production fin_service_main rc 0" "0" "$SVC_RC_B"
assert_eq "[boot B] service: the token upgrade ran EXACTLY ONCE (single-member chain)" "1" \
    "$(grep -cF "token upgraded to Mechanism B" <<<"$LOG_SVC")"
assert_not_contains "[boot B] service: NO guided-finalize residual (fin_service_main never prompts)" "$LOG_SVC" \
    "recovery passphrase verified against keyslot 0 (attempt"

# --- the on-disk post-state, asserted from the console stream ----------------
LOG_P7=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] post: ground truth NOW finalized (the standing token binds {PCR 7, PCR 11})" "$LOG_P7" \
    "P7PCRS [7,11]"
assert_contains "[boot B] post: exactly ONE systemd-tpm2 token (the I1 at-rest shape)" "$LOG_P7" \
    "P7TOK 1"
assert_contains "[boot B] post: token on the sealed slot, keyslots 0 (recovery) + sealed" "$LOG_P7" \
    'P7SLOTS ["0","3"]'
assert_contains "[boot B] post: the standing token carries a REAL release-key signature (the upgrade's, not the escrow's empty marker)" \
    "$LOG_P7" "P7SIGLEN 344"
assert_contains "[boot B] post: the staged ceremony passphrase GONE (scrubbed by the consumption legs)" "$LOG_P7" \
    "P7STAGE gone"
assert_contains "[boot B] post: release.pem is ENCRYPTED (PBES2 in the asn1parse, ADR-18 via the ceremony passphrase)" "$LOG_P7" \
    "P7PBES2 1"
assert_contains "[boot B] post: trust state reads FINALIZED (ground truth: {7,11}, no ephemeral, baseline final)" "$LOG_P7" \
    "P7TS finalized"
assert_contains "[boot B] post: NO attempt marker stands after the completion (clean exit, fde_attempt_clear)" "$LOG_P7" \
    "P7ATT none"
assert_contains "[boot B] post: motd carries the operator line byte-exactly (finalize never touches it, ADR-20 #4)" "$LOG_P7" \
    "P7MOTD Welcome to the Alpine FDE harness fixture — operator content stays."
assert_not_contains "[boot B] post: baseline no longer pending" "$LOG_P7" \
    '"expected_pcr7": "pending"'
if grep -qE '"expected_pcr7": "[0-9a-f]{64}"' <<<"$LOG_P7"; then
    _assert_result ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" ""
else
    _assert_result not-ok "[boot B] post: on-disk baseline expected_pcr7 == 64-hex live value" \
        "no finalized expected_pcr7 line on the console"
fi

# --- post-boot HOST: the finalized metadata, read from the BOOTED image ------
META_B=$(disk_metadata "$B/disk.img")
NTOK=$(disk_token_json "$B/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[boot B] host(booted img): exactly ONE systemd-tpm2 token" "1" "$NTOK"
TOKPCRS=$(disk_token_json "$B/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]["tpm2-pcrs"]')
assert_eq "[boot B] host(booted img): the token binds {PCR 7, PCR 11}" "[7,11]" "$TOKPCRS"
TOKSLOT=$(disk_token_json "$B/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "[boot B] host(booted img): the token on the sealed slot 3 (recovery slot 0 untouched)" "3" "$TOKSLOT"
assert_eq "[boot B] host(booted img): 2 keyslots (recovery + token, I1 at-rest)" "2" \
    "$(jq -r '.keyslots | length' <<<"$META_B")"
assert_eq "[boot B] host(booted img): recovery keyslot 0 argon2id (the ceremony's enrollment)" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_B")"
printf '%s' "$S21_RECOVERY" >"$RUN/recovery-verify.pw" && chmod 600 "$RUN/recovery-verify.pw"
if cryptsetup open --test-passphrase "$B/disk.img" --key-file "$RUN/recovery-verify.pw" 2>/dev/null; then
    _assert_result ok "[boot B] host: the ×2 ceremony passphrase (set in the fed stand-in) OPENS the container via keyslot 0" ""
else
    _assert_result not-ok "[boot B] host: the ×2 ceremony passphrase OPENS the container via keyslot 0" \
        "test-passphrase refused for the recovery credential"
fi
rm -f "$RUN/recovery-verify.pw"
# and the ORIGINAL fixture copy is untouched by the boot (boot isolated)
assert_eq "[boot B] host(fixture img): still the ADR-21 install shape — keyslot 0 FREE" '["1","2"]' \
    "$(jq -c '.keyslots | keys' <<<"$(disk_metadata "$RUN/disk.img")")"

# keep run dirs small
rm -rf "$RUN/guest-tree" "$RUN/initrd.cpio" "$RUN/uki-unsigned.efi" "$RUN/uki-pcrsigned.efi" \
    "$RUN/enriched.tar.gz" "$RUN/payload-derive-scratch.img" "$RUN/tooling"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s21-finalize-guard: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s21-finalize-guard: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
