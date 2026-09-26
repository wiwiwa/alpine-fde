#!/usr/bin/env bash
# tests/e2e/s23-install-e2e.sh — THE true end-to-end install canary (§9.1/
# ADR-20; queue item 32 = item 25 concretized): the REAL `alpine-fde install`
# runs inside a REAL Alpine live environment booted from the PINNED ISO, with
# the apk phase served from the PINNED local mirror, followed by a reboot
# into the installed disk asserting the passwordless unseal + auto-finalize
# + a sane `alpine-fde status` — and finally snapshots the installed disk as
# the registry's GOLDEN BASE (cache slot tests/e2e/.cache/pristine-install-e2e/).
#
# ============================================================================
# VERIFIED vs AUTHORED-UNTESTED (the honest split, 2026-09-26)
#
#   VERIFIED (executed on this host, evidence /var/tmp/evidence/w2-canary/):
#     * the local pinned mirror: tests/lib/local-mirror.sh's REAL chain ran —
#       APKINDEX fetch + pin check, apk-tools-static bootstrap, `apk fetch
#       --recursive` closure (212 apks, 928 MB), main/community
#       classification, MANIFEST.sha256 (214 entries) + mirror.json;
#       second mirror_ensure call is a verified no-op; index drift check
#       runs on the no-op path. The ISO pin downloaded + hash-verified.
#     * pins: tests/unit/canary_e2e_contract.sh (hermetic, GREEN).
#     * bash -n on this file.
#   AUTHORED-UNTESTED (every GUEST leg + every qemu boot below — the boot
#   verification lane owns them):
#     * boot A (ISO live env), every fed console leg, the credential-ceremony
#       feed, boot B (installed disk), the golden-base snapshot machinery.
#     * Known risk knobs the boot lane should expect to calibrate:
#       - the ISO boot uses qemu DIRECT KERNEL BOOT (-kernel/-initrd from the
#         ISO, extracted host-side with bsdtar) instead of El Torito: this
#         keeps console=ttyS0,115200 under OUR control, so the WHOLE install
#         leg is sentinel-corroborable. The -cdrom GRUB path cannot promise a
#         serial console (the ISO's grub.cfg terminal settings are upstream's).
#       - the in-guest /etc/hosts mapping that makes the
#         installer's DNS preflight (inst_preflight nslookup of the mirror
#         host) pass with NO external network.
#       - all watchdogs/budgets (marked CALIBRATE below).
#
# ============================================================================
# WHY the mirror is served by the HOST loopback over qemu slirp (PIVOTED
# 2026-09-26, boot lane; was: a read-only vfat disk + a GUEST-LOCAL httpd):
#   * the guest-local design's premise is FALSE on the pinned set: the
#     alpine-virt ISO's busybox carries NO httpd applet (httpd lives in
#     busybox-extras — absent from the ISO's apks/ repo AND from the pinned
#     mirror closure). Observed live: "-sh: httpd: not found" at the P1 leg
#     (attempt 2, run ...-1790420269). No server package exists in either
#     pinned set, and staging one would change the mirror pins.
#   * file:// / bind-mount repositories CANNOT work under the chroot runner:
#     the in-chroot `apk add` resolves repository paths against the TARGET
#     root, and the installer binds only /proc /sys /dev (+ efivars) — there
#     is no seam to bind the mirror into <mnt>. Any local-mirror design that
#     needs a path inside the target root would require lib/ changes. So the
#     live-env populate and the in-chroot transaction MUST meet over HTTP
#     one way or another.
#   * the pivot uses the fixture's OWN optional seam — mirror_serve_start
#     (tests/lib/local-mirror.sh, HOST loopback httpd: busybox if present,
#     else python3 http.server) — plus a qemu slirp netdev. The guest
#     addresses the host as 10.0.2.2 (slirp's host IP); NO external network
#     is involved at any point.
#   * ALPINE_FDE_MIRROR=http://mirror.fde.internal:8123/mirror/<release>/main
#     (inst_repo_lines derives the community twin automatically). The name is
#     /etc/hosts-backed (-> 10.0.2.2), which reconciles the installer's DNS
#     preflight with the network-free design. The busybox on the ISO has NO
#     dnsd applet either (attempt 7: dnsd -> Done(127)), and nslookup is
#     hosts-blind — but the real consumer (apk's fetcher over musl
#     getaddrinfo) honors /etc/hosts, and the installer's preflight accepts a
#     hosts-file match (boot-lane finding #7) and seeds the TARGET's
#     /etc/hosts so the in-chroot transaction resolves the same name.
#   * the tooling tree rides the SAME server (docroot/tooling), fetched with
#     busybox wget; the docroot is a HARD-LINK tree of the pinned cache
#     (cp -al, no data copy) under the run dir, so the shared cache is never
#     touched and the manifest re-verification leg keeps its meaning.
#
# ============================================================================
# CHOREOGRAPHY (per stage; every stage boundary sentinel/marker-corroborated
# — the s20 lossy-serial lesson: arithmetic markers, bounded waits, rc
# re-read majority, re-feed on corruption):
#
#   stage mirror+iso     host: local_mirror_ensure (no-op on the verified
#                        cache, index pins re-checked) + iso_ensure. Asserts
#                        the manifest pins.
#   stage fixture        host: setup-mode vars (keys_vars_unenrolled: SB OFF,
#                        SetupMode=1 — the installer's preflight gate + its
#                        own NVRAM enrollment complete the world), a sparse
#                        20 GiB target disk (the installer partitions it —
#                        NO fixture LUKS/btrfs anywhere), a blank ESP-slot
#                        placeholder (the positional qemu contract), a blank
#                        export vfat, and the MIRROR DOCROOT (host-side):
#                        a HARD-LINK tree of tests/.cache/local-mirror/
#                        <release> + the tooling tarball, served on
#                        127.0.0.1:$MIRROR_PORT by mirror_serve_start
#                        (MANIFEST.sha256 + APKINDEXes + apks + tooling).
#   boot A (ISO)         qemu DIRECT KERNEL BOOT: q35 + OVMF(secboot) + the
#                        ISO's own vmlinuz-lts/initramfs-lts (-kernel/
#                        -initrd/-append console=ttyS0,115200) + the ISO as
#                        AHCI CD (modloop source) + slirp (guest 10.0.2.15,
#                        host 10.0.2.2) + target=vdb, export=vdc, swtpm
#                        tpm-crb. In-guest legs:
#                        P1 slirp route + resolver+hosts -> P2 wget the
#                        manifest + BOTH APKINDEXes and `sha256sum -c` them
#                        (the mirror is tamper-evident end-to-end; the whole
#                        closure is hash-checked by apk against the signed
#                        index at install time) -> P3 tooling fetch +
#                        extract -> P4 THE REAL INSTALLER:
#                            ./bin/alpine-fde install --disk /dev/vdb
#                              --user admin --yes --no-reboot
#                        with ALPINE_FDE_MIRROR pointed at the loopback
#                        mirror. The credential ceremony is fed on its OWN
#                        prompt sentinels (§9.1 step 4 contract): the
#                        recovery passphrase TWICE (set + repeat), then two
#                        bare ENTERs (account password + release-key
#                        passphrase both default to the recovery value).
#                        INSTALL-RC re-read three ways, majority wins
#                        (the s20 doubled-byte lesson). --no-reboot +
#                        explicit `poweroff -f` (P5) replaces the plan's
#                        reboot tail under OUR control (the documented CI
#                        seam; fidelity note: the deferred/OsIndications
#                        tail records are not exercised — NVRAM enrollment
#                        SUCCEEDS under SetupMode=1 OVMF, so the deferred
#                        path is unreachable here anyway).
#                        Post-boot host: the freshly installed LUKS2 shape
#                        (keyslots 0+1+2, ONE provisional token pcrs [11]).
#   boot B (installed)   qemu_run (the standard harness path, no ISO) on a
#                        COPY of the installed disk + the SAME OVMF vars
#                        (the installer's NVRAM enrollment lives in them) +
#                        the SAME swtpm state dir (the provisional token's
#                        SRK — NEVER re-anchored between the boots, the s00b
#                        permall lesson). Asserts: firmware hands to
#                        systemd-boot (sdboot sentinels), secure boot: on,
#                        ZERO console input during unlock (the passwordless
#                        proof: no unseal_prompt_re, no emergency shell),
#                        getty banner + `login:` reached, then a FED login
#                        (admin) whose legs corroborate in-guest: install
#                        state `finalized`, `alpine-fde status` sane, the
#                        {PCR 7, PCR 11} token on keyslot 1, keyslot 2
#                        PURGED (I1 at-rest shape), evidence exported to
#                        vdd. Serial observability of boot B is provided by
#                        the PLAN-TIME extra-cmdline seam: the P4 feed runs
#                        the installer with ALPINE_FDE_CMDLINE_EXTRA=
#                        'console=ttyS0,115200' (lib/cmd/install.sh
#                        inst_cmdline_extra_check / inst_cmdline_extra) —
#                        the words land in cmdline.txt BEFORE the ukictl
#                        build + provisional seal, so the PCR-11 measurement
#                        and the seal agree (a post-hoc append would break
#                        the seal). Alpine's mkinitfs setup_inittab_console
#                        then spawns the serial getty on the installed
#                        system from the same console= word.
#   stage esp+i2         host: extract the installed ESP (partition 1) from
#                        the booted disk, assert BOOTX64.EFI +
#                        EFI/systemd/systemd-bootx64.efi + UKIs present, and
#                        run the I2 no-secrets scan (no PEM private keys, no
#                        release.pem, NO alpine-fde-keys fallback dir — the
#                        NVRAM enrollment succeeded).
#   stage golden-base    snapshot the finalized disk into
#                        tests/e2e/.cache/pristine-install-e2e/ (staging +
#                        flock + atomic mv, the s00b _cache_store
#                        discipline): disk.img, vars-enrolled.fd,
#                        tpm/tpm2-00.permall, the on-target alpine-fde
#                        config tarball, baseline.json, install-state.json,
#                        FORMAT marker `install-e2e-1`, MANIFEST.sha256,
#                        PINS.json (mirror.json + ISO sha), CACHE-LAYOUT.txt
#                        (the consumer boot shape + compat notes). The
#                        orchestrator decides the consumer cutover; this
#                        scenario only produces the artifact.
#
# REGISTRY: intentionally NOT registered (the orchestrator gates the default
# selection on boot verification). The row to add (named invocation works as
# soon as the file exists; `pinned` keeps it out of the default set):
#     s23	s23-install-e2e.sh	pinned
# BUDGET: this is the designated deep-check — it EXCEEDS run-e2e's outer
# SCENARIO_BUDGET (1500 s) by design. When it is registered the runner needs
# a per-id budget exception (or a raised ALPINE_FDE_SCENARIO_BUDGET) of
# >= 7200 s under TCG.

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
# shellcheck source=../lib/swtpm-fixture.sh
source "$TESTS/lib/swtpm-fixture.sh"
# shellcheck source=../lib/qemu.sh
source "$TESTS/lib/qemu.sh"
# shellcheck source=../lib/sentinels.sh
source "$TESTS/lib/sentinels.sh"   # sentinel_of (MD-02: fails loudly on unknown names)
# shellcheck source=../lib/serial.sh
source "$TESTS/lib/serial.sh"      # feed_line (IN-03: single promoted copy)
# shellcheck source=../lib/stage-timing.sh
source "$TESTS/lib/stage-timing.sh"   # Step timing: run_stage emits begin/done lines
# shellcheck source=../lib/local-mirror.sh
source "$TESTS/lib/local-mirror.sh"   # the pinned local mirror + ISO cache
# boot-lane finding #19 (s23 attempt 17c): drive the install from the
# alpine-standard ISO, NOT alpine-virt — the virt kernel's modloop carries NO
# TPM driver modules (verified: modloop-virt xz blocks contain no char/tpm
# entries), so /dev/tpmrm0 can never exist in the live env and the step-6
# provisional seal dies "no usable TPM" no matter what. The standard ISO's
# lts kernel + modloop-lts carry the TPM drivers, and the lts VERSION matches
# the linux-lts the plan installs. The sha pin is the release index's.
ISO_FLAVOR=alpine-standard
ISO_SHA256_DEFAULT="20c026e3a788bfb75fc8b50a54bcc12aee85e3c75909740bba6a6f4563d63296"
export ALPINE_FDE_ISO_CACHE="$TESTS/e2e/.cache/isos-s23"

# --- credentials (well-known CI credentials, the s21/s00b convention; the
# §13 floor requires >=16 chars or >=12 across 3 classes; the substring
# `alpine-fde` is floor-blocklisted) -----------------------------------------
S23_RECOVERY='fde-s23-recovery-9d41c2'
S23_USER='admin'

DISK_MIB=$((20 * 1024))    # the real install sizes its own ESP + LUKS inside
MIRROR_PORT=8123
MIRROR_HOSTNAME="mirror.fde.internal"
# the slirp host IP the guest addresses the host-side server at (NO external
# network: slirp routes 10.0.2.2:<port> to the host's loopback)
SLIRP_HOST_IP="10.0.2.2"
SLIRP_GUEST_IP="10.0.2.15"
# served under docroot/mirror (a hard-link tree of the pinned cache)
MIRROR_URL="http://$MIRROR_HOSTNAME:$MIRROR_PORT/mirror/$(mirror_release)/main"
CACHE_DIR="$TESTS/e2e/.cache/pristine-install-e2e"

# Deep-check budgets (CALIBRATE — authored-untested; TCG-dominated).
export QEMU_TIMEOUT="${ALPINE_FDE_S23_TIMEOUT:-3600}"
OVERALL_BUDGET="${ALPINE_FDE_S23_BUDGET:-7200}"
T0=$SECONDS
CURRENT_QEMU_DIR=""
SWTPM_DIRS=()

# --- hardening: bounded stages, loud failures (the s00b/s21 idiom) ------------
_hang_fail() {
    printf '\ns23: %s at stage [%s] — %s\n' "$1" "$2" "$3"
    printf 's23: STAGE-TIMEOUT-OR-HANG [%s] (this scenario must never hang)\n' "$2"
    [[ -n "$CURRENT_QEMU_DIR" ]] && tail -5 "$CURRENT_QEMU_DIR/qemu.stderr" 2>/dev/null
    exit 125   # NOT timeout(1)'s 124 (never misread as the outer budget)
}
_budget_check() {
    (( SECONDS - T0 < OVERALL_BUDGET )) || _hang_fail OVERALL-BUDGET "$1" \
        "wall $((SECONDS - T0))s >= budget ${OVERALL_BUDGET}s"
}
run_stage_impl() {
    local soft="$1" name="$2" tmo="$3"; shift 3
    _budget_check "$name"
    echo "# s23: stage $name (watchdog ${tmo}s)"
    stage_begin "$name" || _hang_fail STAGE-TIMING "$name" "stage_begin refused"
    ( "$@" ) &
    local pid=$! rc wrc
    ( sleep "$tmo"; kill -9 -"$pid" 2>/dev/null; exit 125 ) &
    local wpid=$!
    wait "$pid"; rc=$?
    kill "$wpid" 2>/dev/null
    wait "$wpid" 2>/dev/null; wrc=$?
    stage_end "$name" || _hang_fail STAGE-TIMING "$name" "stage_end refused"
    if (( wrc == 125 )); then
        _hang_fail STAGE-TIMEOUT "$name" "exceeded watchdog ${tmo}s"
    fi
    if (( rc != 0 )); then
        printf 's23: STAGE-FAILED [%s] (rc=%s)\n' "$name" "$rc"
        (( soft == 1 )) && return "$rc"
        exit 1
    fi
    return 0
}
run_stage() { run_stage_impl 0 "$@"; }
run_stage_rc() { run_stage_impl 1 "$@"; }

_qemu_alive_or_die() {
    local dir="$1" stage="$2" qpid
    qpid=$(cat "$dir/qemu.pid" 2>/dev/null || true)
    if [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null; then
        _hang_fail QEMU-DIED "$stage" \
            "qemu (pid ${qpid:-<none>}) is gone — sentinel can never appear; tail: $(tail -5 "$dir/console.log" 2>/dev/null | tr '\n' ' ')"
    fi
}
wait_console() {   # wait_console <dir> <fixed-string> <timeout-s>
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
_qemu_alive() {
    local dir="$1" pid
    [[ -f "$dir/qemu.pid" ]] || { echo "s23: qemu pid file missing in $dir"; exit 1; }
    pid=$(cat "$dir/qemu.pid")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "s23: QEMU died at startup in $dir; qemu.stderr:"
        tail -5 "$dir/qemu.stderr" 2>/dev/null
        exit 1
    fi
}

RUN="$TESTS/e2e/.runs/s23-install-e2e-$(date +%s)"
mkdir -p "$RUN"
CONSOLE="$RUN/console.log"
DOCROOT="$RUN/docroot"   # the HOST-side mirror+tooling docroot (see the WHY header)

# Sibling scenarios prune .runs to the 2 newest dirs GLOBALLY — keep THIS run
# dir the newest while the (very long) boots run.
(
    while :; do
        sleep 5
        [[ -d "$RUN" ]] || break
        touch "$RUN"
    done
) &
REFRESHER=$!

_exit_cleanup() {
    [[ -n "$CURRENT_QEMU_DIR" ]] && qemu_kill "$CURRENT_QEMU_DIR" 2>/dev/null
    local d
    for d in "${SWTPM_DIRS[@]:-}"; do
        [[ -n "$d" ]] && swtpm_stop "$d" 2>/dev/null
    done
    kill "$REFRESHER" 2>/dev/null
    mirror_serve_stop "$DOCROOT" 2>/dev/null || true
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

# _ensure_tpm — the swtpm dies at qemu disconnect; relaunch on the SAME state
# dir (permall/SRK persists — the provisional token's seal must survive into
# boot B; NEVER re-anchor between the two boots).
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

# ============================================================================
# STAGE 0 — the pinned mirror + ISO (VERIFIED machinery; local-mirror.sh)
# ============================================================================
run_stage mirror-ensure 1800 mirror_ensure
MIRROR_DIR=$(mirror_cache_dir)
run_stage iso-ensure 1800 iso_ensure
assert_file_exists "mirror: MANIFEST.sha256 present" "$MIRROR_DIR/MANIFEST.sha256"
assert_file_exists "mirror: mirror.json provenance present" "$MIRROR_DIR/mirror.json"
assert_file_exists "mirror: pinned main APKINDEX cached" "$MIRROR_DIR/main/x86_64/APKINDEX.tar.gz"
assert_file_exists "mirror: pinned community APKINDEX cached" "$MIRROR_DIR/community/x86_64/APKINDEX.tar.gz"
# the mirror package universe must cover the REAL installer's list (the
# derivation is the lib's, asserted here against the product lib directly)
MIRROR_PKGS=$(mirror_package_list)
for p in cryptsetup systemd-boot systemd-efistub ukify ukify-kernel-hook py3-pefile \
    mkinitfs linux-lts tpm2-tools sbsigntool openssl jq doas btrfs-progs alpine-base; do
    case " $MIRROR_PKGS " in
        *" $p "*) : ;;
        *) assert_contains "mirror package list covers $p" "MISSING" "$p" ;;
    esac
done
_assert_result ok "mirror package list derivation covers install_package_list (+topology union)" ""
# end-to-end tamper-evidence: the cached manifest verifies RIGHT NOW
run_stage manifest-verify-host 600 bash -c "cd '$MIRROR_DIR' && sha256sum --check --quiet MANIFEST.sha256"
assert_file_exists "iso: pinned $(iso_filename) cached" "$(iso_path)"

# ============================================================================
# STAGE 1 — fixtures: setup-mode vars, blank target, MIRROR DISK, export drive
# ============================================================================
run_stage vars-unenrolled 120 keys_vars_unenrolled "$RUN/keys" "$RUN/vars.fd"
assert_not_contains "fixture: setup-mode vars carry no SecureBootEnable (SB off pre-install)" \
    "$(keys_vars_get "$RUN/vars.fd" SecureBootEnable)" "ON"

run_stage target-disk 120 truncate -s "${DISK_MIB}M" "$RUN/disk.img"
run_stage esp-slot-blank 60 truncate -s 1M "$RUN/esp-blank.img"   # positional placeholder only

# the export drive (blank vfat — boot B copies the on-target evidence out)
run_stage export-drive 120 bash -c "truncate -s 64M '$RUN/export.img' && mkfs.vfat -F 32 '$RUN/export.img' >/dev/null"

# the tooling tarball (repo product tree only — the installer's own copy
# contract, inst_tooling_copy_cmd)
run_stage tooling-tar 600 tar -C "$REPO" -czf "$RUN/alpine-fde.tar.gz" bin lib hooks docs

# THE MIRROR DOCROOT (host-side; served by mirror_serve_start — see the WHY
# header): a HARD-LINK tree of the pinned cache (cp -al — no data copy, the
# shared cache is never written) + the tooling tarball. The guest reaches it
# as http://10.0.2.2:$MIRROR_PORT/... via slirp, and as
# http://mirror.fde.internal:$MIRROR_PORT/mirror/... through /etc/hosts.
build_docroot() {
    local docroot="$1" rel
    rel=$(mirror_release)
    rm -rf "$docroot"
    # the manifest pins paths RELATIVE to <cache>/<release>/ — serve the
    # release dir one level below docroot/mirror so the URLs line up
    mkdir -p "$docroot/mirror/$rel" "$docroot/tooling"
    cp -al "$MIRROR_DIR/." "$docroot/mirror/$rel/"
    cp "$RUN/alpine-fde.tar.gz" "$docroot/tooling/alpine-fde.tar.gz"
}
run_stage mirror-docroot 600 build_docroot "$DOCROOT"
run_stage mirror-serve 60 mirror_serve_start "$MIRROR_PORT" "$DOCROOT"
_rearm_trap
assert_file_exists "fixture: mirror docroot manifest" "$DOCROOT/mirror/$(mirror_release)/MANIFEST.sha256"
# the server must answer before any guest leg runs
run_stage mirror-selfcheck 60 bash -c "curl -fsS -o /dev/null 'http://127.0.0.1:$MIRROR_PORT/mirror/$(mirror_release)/MANIFEST.sha256'"

# ============================================================================
# STAGE 2 — BOOT A: the Alpine ISO live env (qemu DIRECT KERNEL BOOT from the
# pinned ISO's own kernel/initramfs — full serial-cmdline control)
# ============================================================================
run_stage iso-extract 600 bash -c "
    mkdir -p '$RUN/iso' && bsdtar -xf '$(iso_path)' -C '$RUN/iso' \
        boot/vmlinuz-lts boot/initramfs-lts boot/modloop-lts"

A="$RUN/boot-a"
mkdir -p "$A"
# _track_swtpm — the s15/s21 idiom: register the fixture dir so the scenario's
# own _exit_cleanup stops the daemon (the fixture's trap-based
# swtpm_cleanup_all must stay DISARMED here — see the run_stage guard below).
_track_swtpm() { SWTPM_DIRS+=("$1"); }
_track_swtpm "$RUN/tpm"
# _SWTPM_CLEANUP_TRAP_SET=1: swtpm_start arms `trap swtpm_cleanup_all EXIT` by
# default — inside the run_stage stage subshell that fires at STAGE EXIT and
# stops the healthy daemon before qemu can connect (attempt-1 live failure).
_SWTPM_CLEANUP_TRAP_SET=1 run_stage swtpm_start-a 90 swtpm_start "$RUN/tpm"
_rearm_trap
CURRENT_QEMU_DIR="$A"

# _qemu_run_iso — qemu_run + the ISO legs: the scenario-local wrapper keeps
# the harness pins (accel choice, OVMF pins, console bridge, QMP kicker,
# tpm-crb trio) byte-for-byte and adds ONLY -kernel/-initrd/-append (the
# ISO's own kernel) + -cdrom (its modloop source) + guest memory (the live
# env needs headroom for the in-guest argon2id KDF + ukify build).
_qemu_run_iso() {
    local dir="$1" esp="$2" disk="$3" vars="$4" swtpmdir="$5" pcrsig="$6" extra="$7"
    local isoargs mem
    ovmf_pin_check || return 1
    _qemu_accel_choose || return 1
    serial_bridge_stop "$dir"
    rm -f "$(_qemu_serial_sock "$dir")" "$dir/console.log" "$dir/qemu.pid" \
        "$(serial_bridge_log "$dir")"
    serial_bridge_start "$dir" || return 1
    local -a args=()
    mapfile -t args < <(qemu_argv "$dir" "$esp" "$disk" "$vars" "$swtpmdir" "$pcrsig" "$extra")
    # memory: the live install env wants > 2 GiB (argon2id --pbkdf-memory 1G
    # + the in-chroot ukify build); swap -m 2048 for -m ${S23_GUEST_MEM}
    mem="${S23_GUEST_MEM:-4096}"
    local i
    for i in "${!args[@]}"; do
        [[ "${args[$i]}" == "-m" ]] && args[$((i + 1))]="$mem"
    done
    args+=(-drive "file=$(iso_path),media=cdrom,readonly=on")
    args+=(-kernel "$RUN/iso/boot/vmlinuz-lts")
    args+=(-initrd "$RUN/iso/boot/initramfs-lts")
    # the slirp netdev: the guest reaches the HOST-side mirror server at
    # 10.0.2.2:$MIRROR_PORT (see the WHY header — the guest-local httpd is
    # unachievable on the pinned ISO); NO external network is involved
    args+=(-netdev user,id=mirror0 -device virtio-net-pci,netdev=mirror0)
    # Alpine's own virt-ISO append + our serial console (the kernel console is
    # what makes the WHOLE install leg sentinel-corroborable)
    args+=(-append "modules=loop,squashfs,sd-mod,usb-storage console=ttyS0,115200")
    _QEMU_BOOT_T0["$dir"]=$(qemu_now_epoch)
    qemu-system-x86_64 "${args[@]}" >"$dir/qemu.stdout" 2>"$dir/qemu.stderr" &
    echo $! >"$dir/qemu.pid"
    _qmp_kicker_start "$dir"
    return 0
}

run_stage qemu_run-iso 120 _qemu_run_iso "$A" "$RUN/esp-blank.img" "$RUN/disk.img" \
    "$RUN/vars.fd" "$RUN/tpm" "" "$RUN/export.img"
_qemu_alive "$A"
_rearm_trap

# wait for the live env's getty (AUTHORED-UNTESTED: TCG boot of the virt
# kernel; the direct-kernel boot skips the bootloader entirely)
wait_console "$A" "Welcome to Alpine Linux" 900
wait_console "$A" "login:" 300
feed_line "$A/serial.sock" "root"     # the live ISO logs root in with NO password
wait_console "$A" "localhost:~#" 120

# --- P1: the slirp route + the DNS-preflight reconciliation ------------------
# The mirror name resolves WITHOUT any external network: /etc/hosts maps it
# to 10.0.2.2 (slirp's host IP = the host loopback where mirror_serve_start
# listens); the NAME-based wget leg below proves /etc/hosts resolution works
# for the real consumer (musl getaddrinfo), and the installer's preflight
# in-chroot transaction reuses the same resolver through the seeded
# resolv.conf. busybox wget fetches the mirror + tooling over that route.
feed_line "$A/serial.sock" \
    "ip link set eth0 up && ip addr add $SLIRP_GUEST_IP/24 dev eth0 && ip route add default via $SLIRP_HOST_IP && printf '127.0.0.1 localhost\\n$SLIRP_HOST_IP $MIRROR_HOSTNAME\\n' > /etc/hosts && printf 'nameserver 127.0.0.1\\n' > /etc/resolv.conf && echo P1-\$((40+1))-HOSTS"
wait_console "$A" "P1-41-HOSTS" 120
feed_line "$A/serial.sock" \
    "wget -q -O /dev/null http://$MIRROR_HOSTNAME:$MIRROR_PORT/mirror/$(mirror_release)/MANIFEST.sha256 && echo P1-\$((40+2))-DNS-OK || echo P1-\$((40+2))-DNS-FAIL"
# EXACT marker: the loose 'P1-42-DNS-' prefix also matched DNS-FAIL and
# masked the dead-dnsd finding (attempt 7)
wait_console "$A" "P1-42-DNS-OK" 120
feed_line "$A/serial.sock" \
    "wget -q -O /dev/null http://$SLIRP_HOST_IP:$MIRROR_PORT/mirror/$(mirror_release)/MANIFEST.sha256 && echo P1-\$((40+3))-FETCH-OK || echo P1-\$((40+3))-FETCH-FAIL"
wait_console "$A" "P1-43-FETCH-OK" 120

# --- P2: the guest re-verifies the mirror manifest (tamper-evident e2e) ------
# over the wire: fetch the manifest + BOTH pinned APKINDEXes, check the
# pinned hashes (the full closure is hash-checked by apk itself on install —
# every .apk is verified against this signed index)
feed_line "$A/serial.sock" \
    "mkdir -p /tmp/mchk/main/x86_64 /tmp/mchk/community/x86_64 && cd /tmp/mchk && wget -q http://$SLIRP_HOST_IP:$MIRROR_PORT/mirror/$(mirror_release)/MANIFEST.sha256 && wget -q -O main/x86_64/APKINDEX.tar.gz http://$SLIRP_HOST_IP:$MIRROR_PORT/mirror/$(mirror_release)/main/x86_64/APKINDEX.tar.gz && wget -q -O community/x86_64/APKINDEX.tar.gz http://$SLIRP_HOST_IP:$MIRROR_PORT/mirror/$(mirror_release)/community/x86_64/APKINDEX.tar.gz && grep APKINDEX MANIFEST.sha256 > check.txt && sha256sum -c check.txt >/dev/null 2>&1 && echo P2-\$((40+5))-MANIFEST-OK || echo P2-\$((40+5))-MANIFEST-FAIL"
wait_console "$A" "P2-45-MANIFEST-OK" 300

# --- P3: the tooling tree -----------------------------------------------------
feed_line "$A/serial.sock" \
    "mkdir -p /root/alpine-fde && wget -q -O /root/tooling.tar.gz http://$SLIRP_HOST_IP:$MIRROR_PORT/tooling/alpine-fde.tar.gz && tar -xzf /root/tooling.tar.gz -C /root/alpine-fde && test -x /root/alpine-fde/bin/alpine-fde && echo P3-\$((40+6))-TOOLING-OK"
wait_console "$A" "P3-46-TOOLING-OK" 300

# --- P4: THE REAL INSTALLER + the credential ceremony feed --------------------
# The installer runs in the FOREGROUND of the serial shell: every marker and
# every ceremony prompt lands on the console (inst_prompt_secret reads THIS
# tty), and RC stays in the shell for the majority re-reads (the s20
# doubled-byte lesson). Ceremony feed order per the §9.1 step 4 contract
# (item 12 AMENDED):
#   1/3 recovery passphrase  -> typed TWICE (set + repeat)
#   2/3 account password     -> ONE bare Enter (reuses the recovery value)
#   3/3 release-key passphrase -> ONE bare Enter (same)
# --no-reboot + the explicit P5 poweroff replaces the plan's reboot tail
# under our control (fidelity note in the header).
feed_line "$A/serial.sock" \
    "cd /root/alpine-fde && ALPINE_FDE_MIRROR='$MIRROR_URL' ALPINE_FDE_CMDLINE_EXTRA='console=ttyS0,115200' ./bin/alpine-fde install --disk /dev/vdb --user $S23_USER --yes --no-reboot; RC=\$?; echo INSTALL-RC=\$RC"

# the DNS preflight is the FIRST installer action — corroborate it
wait_console "$A" "install: live env resolves the mirror host $MIRROR_HOSTNAME" 300
# the Setup Mode gate + the keyring seed corroborate the plan started
wait_console "$A" "install: firmware Setup Mode confirmed" 300

# THE CEREMONY FEED: recovery twice, then two bare Enters (prompt-synchronized
# — the prompts are read from THIS tty by inst_prompt_secret)
wait_console "$A" "set the LUKS2 recovery passphrase" 3600
feed_line "$A/serial.sock" "$S23_RECOVERY"
wait_console "$A" "repeat the recovery passphrase" 300
feed_line "$A/serial.sock" "$S23_RECOVERY"
wait_console "$A" "set the password for account '$S23_USER'" 1800
feed_line "$A/serial.sock" ""          # bare Enter: reuse the recovery passphrase
wait_console "$A" "set the release-key passphrase" 600
feed_line "$A/serial.sock" ""          # bare Enter: reuse the recovery passphrase
# the secret-dependent tail: signed UKI build + provisional seal
wait_console "$A" "$(sentinel_of cli_seal_slot)" 3600
wait_console "$A" "install complete" 3600

# INSTALL-RC: re-derive from the LIVE shell three times, majority wins
_await_rc() {
    local dir="$1" i=0 rc re1 re2
    until grep -qE 'INSTALL-RC=[0-9]+' "$dir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$dir" "console-wait:INSTALL-RC"
        _budget_check "console-wait:INSTALL-RC"
        (( i < 120 )) || _hang_fail CONSOLE-WAIT "INSTALL-RC" "never returned"
        sleep 1; i=$((i + 1))
    done
    rc=$(grep -oE 'INSTALL-RC=[0-9]+' "$dir/console.log" | head -1 | cut -d= -f2)
    feed_line "$dir/serial.sock" 'echo "RC2=$RC"'
    i=0
    until grep -qE 'RC2=[0-9]+' "$dir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$dir" "console-wait:RC2"; (( i < 60 )) || break; sleep 1; i=$((i + 1))
    done
    re1=$(grep -oE 'RC2=[0-9]+' "$dir/console.log" | head -1 | cut -d= -f2)
    feed_line "$dir/serial.sock" 'echo "RC3=$RC"'
    i=0
    until grep -qE 'RC3=[0-9]+' "$dir/console.log" 2>/dev/null; do
        _qemu_alive_or_die "$dir" "console-wait:RC3"; (( i < 60 )) || break; sleep 1; i=$((i + 1))
    done
    re2=$(grep -oE 'RC3=[0-9]+' "$dir/console.log" | head -1 | cut -d= -f2)
    if [[ "$re1" == "$rc" || "$re2" == "$rc" ]]; then
        printf '%s\n' "$rc"
    elif [[ -n "$re1" && "$re1" == "$re2" ]]; then
        printf '%s\n' "$re1"
    else
        printf '%s\n' "${re1:-$rc}"
    fi
}
INSTALL_RC=$(_await_rc "$A")
assert_eq "install: the REAL installer exited rc 0" "0" "$INSTALL_RC"
if [ "$INSTALL_RC" != "0" ]; then
    echo "s23: the REAL installer failed (rc=$INSTALL_RC) — aborting: boot B cannot proceed; feeding poweroff so the guest exits"
    feed_line "$A/serial.sock" "poweroff -f" 2>/dev/null
    sleep 5
    qemu_kill "$A" 2>/dev/null
    exit 1
fi

# --- P5: controlled poweroff (the boot B handoff) ------------------------------
feed_line "$A/serial.sock" \
    "sync; poweroff -f; echo P5-\$((40+8))-BYE"
run_stage qemu_wait-a "$((QEMU_TIMEOUT + 120))" qemu_wait "$A" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_A=$(cat "$A/console.log" 2>/dev/null || true)
assert_contains "[boot A] installer: DNS preflight resolved the mirror host" "$LOG_A" \
    "live env resolves the mirror host $MIRROR_HOSTNAME"
assert_contains "[boot A] installer: Setup Mode gate passed" "$LOG_A" \
    "install: firmware Setup Mode confirmed"
assert_contains "[boot A] installer: the apk populate consumed the LOCAL mirror" "$LOG_A" \
    "alpine-fde: info: apk keyring seeded"
assert_contains "[boot A] installer: NVRAM enrollment SUCCEEDED (SetupMode=1 OVMF)" "$LOG_A" \
    "install: credential ceremony (1/3): recovery passphrase enrolled in keyslot 0"
assert_contains "[boot A] provisional Mechanism B seal (PCR 11) fired" "$LOG_A" \
    "$(sentinel_of cli_seal_slot)"
assert_contains "[boot A] install completed" "$LOG_A" "install complete"
assert_contains "[boot A] P5 controlled poweroff" "$LOG_A" "P5-48-BYE"

# post-install HOST: the freshly installed LUKS2 shape — keyslots 0 (recovery)
# + 1 (provisional token) + 2 (ephemeral, purged at first-boot finalization);
# ONE provisional token pinning PCR 11 ONLY.
META_A=$(disk_metadata "$RUN/disk.img")
assert_eq "[boot A host] 3 keyslots after install (recovery + provisional + ephemeral)" "3" \
    "$(jq -r '.keyslots | length' <<<"$META_A")"
NTOK_A=$(disk_token_json "$RUN/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[boot A host] exactly ONE systemd-tpm2 token (the provisional seal)" "1" "$NTOK_A"
TOKPCRS_A=$(disk_token_json "$RUN/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
assert_eq "[boot A host] the provisional token pins PCR 11 ONLY (ADR-20 step 6)" "[11]" "$TOKPCRS_A"

# ============================================================================
# STAGE 3 — BOOT B: the installed disk (no ISO; same vars + same TPM state)
# ============================================================================
B="$RUN/boot-b"
mkdir -p "$B"
run_stage disk-copy-b 900 cp "$RUN/disk.img" "$B/disk.img"
cp "$RUN/vars.fd" "$B/vars.fd"   # boot A's enrollment mutated the pflash vars
_ensure_tpm "$RUN/tpm"
_rearm_trap
CURRENT_QEMU_DIR="$B"
echo "# boot B: the installed system boots via its OWN ESP (BOOTX64.EFI fallback), SB on, zero console input"
run_stage qemu_run-b 60 qemu_run "$B" "$RUN/esp-blank.img" "$B/disk.img" \
    "$B/vars.fd" "$RUN/tpm" ""
_qemu_alive "$B"
_rearm_trap
# export drive rides the pcrsig slot this boot (vdc): the evidence channel
# console=ttyS0,115200 rides the installed UKI cmdline (plan-time
# ALPINE_FDE_CMDLINE_EXTRA seam, header) -> kernel + initrd-phase output IS
# serial-visible; the passwordless proof is zero-input-to-login + the
# host-side LUKS shape.
LOGIN_SEEN=0
i=0
while ((i < QEMU_TIMEOUT)); do
    if grep -qE 'login: ?$' "$B/console.log" 2>/dev/null \
        && grep -q 'Welcome to Alpine Linux' "$B/console.log" 2>/dev/null; then
        LOGIN_SEEN=1
        break
    fi
    _qemu_alive_or_die "$B" "console-wait:login-b"
    _budget_check "console-wait:login-b"
    sleep 1
    i=$((i + 1))
done
if (( LOGIN_SEEN == 1 )); then
    _assert_result ok "[boot B] \`login:\` reached with ZERO console input (the passwordless unseal proof, wall ${i}s)" ""
else
    _assert_result not-ok "[boot B] \`login:\` reached with ZERO console input" \
        "never matched within ${QEMU_TIMEOUT}s; tail: $(tail -3 "$B/console.log" 2>/dev/null | tr '\n' ' ')"
fi
assert_not_contains "[boot B] NO recovery-passphrase prompt ever opened" "$B/console.log" \
    "$(sentinel_of unseal_prompt_re)"
assert_not_contains "[boot B] no emergency shell" "$B/console.log" "$(sentinel_of emergency_forbidden)"
assert_contains "[boot B] systemd-boot owns the boot (the guarded file copy installed it)" "$B/console.log" \
    "$(sentinel_of sdboot_loaderinfo)"

# fed login (admin; the account password was ceremony 2/3 = the recovery value)
feed_line "$B/serial.sock" "$S23_USER"
sleep 5
feed_line "$B/serial.sock" "$S23_RECOVERY"
wait_console "$B" "localhost:~#" 300

# in-guest corroboration legs (console-visible arithmetic markers)
feed_line "$B/serial.sock" \
    'cat /etc/alpine-fde/install-state.json; cat /proc/cmdline; alpine-fde status; echo P7STATUS-RC=$?'
wait_console "$B" '"state": "finalized"' 300
feed_line "$B/serial.sock" \
    'cryptsetup luksDump --dump-json-metadata /dev/vdb > /tmp/luks.json && jq -c "[.keyslots|keys, [.tokens[]|select(.type==\"systemd-tpm2\")|.tpm2-pcrs]]" /tmp/luks.json; echo P7-\$((50+1))-OK'
wait_console "$B" "P7-51-OK" 300
# export the evidence to the vfat drive (vdc this boot)
feed_line "$B/serial.sock" \
    'mkdir -p /mnt/export && mount -t vfat /dev/vdc /mnt/export && cp /tmp/luks.json /mnt/export/ && tar -czf /mnt/export/alpine-fde-etc.tar.gz -C / etc/alpine-fde && dmesg > /mnt/export/dmesg-bootb.txt && cat /proc/cmdline > /mnt/export/cmdline.txt && sync && echo P7-\$((50+2))-EXPORTED'
wait_console "$B" "P7-52-EXPORTED" 300
feed_line "$B/serial.sock" 'sync; poweroff -f'
run_stage qemu_wait-b "$((QEMU_TIMEOUT + 120))" qemu_wait "$B" "$QEMU_TIMEOUT"
CURRENT_QEMU_DIR=""

LOG_B=$(cat "$B/console.log" 2>/dev/null || true)
assert_contains "[boot B] install state finalized (the auto-finalizer completed Stage 2)" "$LOG_B" \
    '"state": "finalized"'

# post-boot HOST: the I1 at-rest shape — exactly 2 keyslots (recovery + token;
# the ephemeral keyslot 2 is PURGED at first-boot finalization), one {7,11} token
META_B=$(disk_metadata "$B/disk.img")
assert_eq "[boot B host] 2 keyslots at rest (ephemeral keyslot PURGED, I1)" "2" \
    "$(jq -r '.keyslots | length' <<<"$META_B")"
NTOK_B=$(disk_token_json "$B/disk.img" | jq '[.[] | select(.type == "systemd-tpm2")] | length')
assert_eq "[boot B host] exactly ONE systemd-tpm2 token" "1" "$NTOK_B"
TOKPCRS_B=$(disk_token_json "$B/disk.img" | jq -c '[.[] | select(.type == "systemd-tpm2")][0]."tpm2-pcrs"')
assert_eq "[boot B host] the token was UPGRADED to {PCR 7, PCR 11} (Stage 2 completion)" "[7,11]" "$TOKPCRS_B"
TOKSLOT_B=$(disk_token_json "$B/disk.img" | jq -r '[.[] | select(.type == "systemd-tpm2")][0].keyslots[0]')
assert_eq "[boot B host] token on keyslot 1 (recovery slot 0 untouched)" "1" "$TOKSLOT_B"
assert_eq "[boot B host] recovery keyslot 0 still argon2id" "argon2id" \
    "$(jq -r '.keyslots["0"].kdf.type' <<<"$META_B")"

# ============================================================================
# STAGE 4 — ESP content + the I2 no-secrets scan (host-side, unprivileged)
# ============================================================================
ESP_IMG="$RUN/esp-extract.img"
extract_esp() {
    local start
    start=$(sfdisk -d "$1" 2>/dev/null | awk '
    /start=/ && (/UEFI/ || /C12A7328/ || /EFI System/ || /type: uefi/) {
        if (match($0, /start=[0-9]+/)) { print substr($0, RSTART + 6, RLENGTH - 6); exit }
    }')
    [[ -n "$start" ]] || { echo "s23: cannot resolve the ESP start sector"; return 1; }
    dd if="$1" of="$2" bs=512 skip="$start" status=none
    mdir -i "$2" ::/ >/dev/null
}
run_stage esp-extract 300 extract_esp "$B/disk.img" "$ESP_IMG"
ESP_LIST="$RUN/esp.listing"
mdir -i "$ESP_IMG" -/ ::/ >"$ESP_LIST" 2>/dev/null
if grep -qE 'EFI/BOOT/BOOTX64\.EFI' "$ESP_LIST" \
    && grep -qE 'EFI/systemd/systemd-bootx64\.efi' "$ESP_LIST" \
    && grep -qE 'EFI/Linux/.*\.efi' "$ESP_LIST"; then
    _assert_result ok "[esp] BOOTX64.EFI + the canonical loader + UKI(s) present on the installed ESP" ""
else
    _assert_result not-ok "[esp] BOOTX64.EFI + loader + UKIs present" \
        "listing: $(grep -E '\.efi' "$ESP_LIST" | tr '\n' ' ')"
fi
# I2: NO secrets on the ESP — no PEM private keys anywhere in the extracted
# files, no release.pem, and NO alpine-fde-keys fallback staging dir (the
# NVRAM enrollment succeeded, so the deferred-import staging never ran)
ESP_SCAN="$RUN/esp-scan"
rm -rf "$ESP_SCAN"; mkdir -p "$ESP_SCAN"
mcopy -i "$ESP_IMG" -s ::/ "$ESP_SCAN/" >/dev/null 2>&1
if grep -rqlE -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$ESP_SCAN" 2>/dev/null \
    || find "$ESP_SCAN" -name 'release.pem' | grep -q . \
    || [[ -d "$ESP_SCAN/alpine-fde-keys" ]]; then
    _assert_result not-ok "[i2] NO secrets on the ESP (no private keys, no release.pem, no alpine-fde-keys staging)" \
        "hits in $ESP_SCAN"
else
    _assert_result ok "[i2] NO secrets on the ESP (no private keys, no release.pem, no alpine-fde-keys staging)" ""
fi

# ============================================================================
# STAGE 5 — the GOLDEN BASE snapshot (scope addition: this canary's OUTPUT is
# the registry's next base image). Staging + flock + atomic mv (the s00b
# _cache_store discipline); consumers boot it via the disk's OWN ESP.
# ============================================================================
golden_base_store() {
    local dir="$1" run="$2"
    local stage="$dir.staging.$$"
    rm -rf "$stage"
    mkdir -p "$stage/tpm"
    cp "$run/boot-b/disk.img" "$stage/disk.img"
    cp "$run/boot-b/vars.fd" "$stage/vars-enrolled.fd"
    cp "$run/tpm/tpm2-00.permall" "$stage/tpm/tpm2-00.permall"
    # the on-target evidence the export drive carried out of the guest
    cp "$run/baseline.json" "$stage/baseline.json"
    cp "$run/install-state.json" "$stage/install-state.json"
    mkdir -p "$stage/export"
    mcopy -i "$run/export.img" -s ::/ "$stage/export/" 2>/dev/null || true
    printf 'install-e2e-1\n' >"$stage/FORMAT"
    # the pins this base is a function of (mirror.json + ISO pin)
    cp "$(mirror_cache_dir)/mirror.json" "$stage/PINS.json"
    printf '{\n  "iso": "%s",\n  "iso_sha256": "%s",\n  "recovery_passphrase": "%s",\n  "user": "%s",\n  "mirror_url": "%s"\n}\n' \
        "$(iso_filename)" "$(iso_expected_sha256)" "$S23_RECOVERY" "$S23_USER" "$MIRROR_URL" \
        >>"$stage/PINS.json"
    cat >"$stage/CACHE-LAYOUT.txt" <<'EOF'
pristine-install-e2e — the GOLDEN BASE produced by the REAL installer
(tests/e2e/s23-install-e2e.sh; NOT the stamped-rootfs s00b fixture).

Consumer boot shape (differs from pristine-s00b by design):
  qemu_run <run> <any blank/ignored esp slot> <this disk.img> <vars-enrolled.fd> <tpm-dir>
  * NO harness.efi / esp.img / pcrsig.img: the disk's OWN ESP boots via
    EFI/BOOT/BOOTX64.EFI (removable-media path, no NVRAM dependency);
    zero console input reaches `login:` (standing {7,11} token).
  * tpm/tpm2-00.permall MUST pair with disk.img (the token's SRK) — never
    re-anchor the TPM between consumers.
  * vars-enrolled.fd carries the keys the INSTALLER enrolled (not a
    fixture varstore): SB on, SetupMode 0.
  * the well-known credentials + the exact ISO/mirror pins are in PINS.json.
  * login: <user from PINS.json>, password = the recovery passphrase.
EOF
    (cd "$stage" && sha256sum FORMAT disk.img vars-enrolled.fd tpm/tpm2-00.permall \
        baseline.json install-state.json PINS.json >MANIFEST.sha256)
    local lock="$dir.publish.lock"
    ( flock -x 9; rm -rf "$dir"; mv -- "$stage" "$dir" ) 9>"$lock"
    echo "# golden base cached in $dir (FORMAT $(cat "$dir/FORMAT"))"
}
# pull the exported documents back out of the export vfat first
EXPORT_X="$RUN/export-extract"
rm -rf "$EXPORT_X"; mkdir -p "$EXPORT_X"
run_stage export-pull 300 bash -c "mcopy -i '$RUN/export.img' -s ::/ '$EXPORT_X/' 2>/dev/null; ls '$EXPORT_X'"
[[ -f "$EXPORT_X/alpine-fde-etc.tar.gz" ]] || { echo "s23: the export drive came back empty — boot B's evidence legs failed"; exit 1; }
run_stage export-untar 300 tar -xzf "$EXPORT_X/alpine-fde-etc.tar.gz" -C "$RUN"
cp "$RUN/etc/alpine-fde/baseline.json" "$RUN/baseline.json"
cp "$RUN/etc/alpine-fde/install-state.json" "$RUN/install-state.json"
assert_eq "[golden-base] exported install-state is finalized" "finalized" \
    "$(jq -r .state "$RUN/install-state.json")"
run_stage golden-base-store 1800 bash -c "$(declare -f golden_base_store); golden_base_store '$CACHE_DIR' '$RUN'"
if [[ -f "$CACHE_DIR/MANIFEST.sha256" ]] && (cd "$CACHE_DIR" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1; then
    _assert_result ok "[golden-base] cache stored + SHA-manifest verifies ($CACHE_DIR)" ""
else
    _assert_result not-ok "[golden-base] cache stored + SHA-manifest verifies" "$CACHE_DIR"
fi

# keep run dirs small
rm -rf "$RUN/iso" "$RUN/esp-scan" "$RUN/alpine-fde.tar.gz"

_exit_cleanup
trap - EXIT INT TERM
echo "# run dir: $RUN (wall $((SECONDS - T0)) s)"
echo "RUNDIR $RUN"
if (( TESTS_FAIL == 0 )); then
    echo "# s23-install-e2e: PASS ($TESTS_PASS assertions, wall $((SECONDS - T0)) s)"
    exit 0
fi
echo "# s23-install-e2e: FAIL ($TESTS_FAIL failing of $((TESTS_PASS + TESTS_FAIL)), wall $((SECONDS - T0)) s)"
exit 1
