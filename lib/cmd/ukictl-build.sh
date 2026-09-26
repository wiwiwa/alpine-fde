#!/bin/sh
# cmd/ukictl-build.sh — `alpine-fde ukictl build` (docs/Architecture.md §8.1, §9.2;
# gap report B-G1/G3/G4/G5/G10/G11/G12; mechanism ladder resolved by ADR-19/
# ADR-20: Mechanism B (rung b) is the normative Alpine seal path — a2 remains
# an accepted alias; documented-absent rungs fail closed at the
# policy_mode_normalize boundary).
#
# Sequence (no partial ESP state survives a failure; ADR-8 loud failure):
#   0. config + loud-fail precondition: release key material checked BEFORE any
#      ESP mutation; failure persists the /etc/alpine-fde/build-failed marker
#   1. initramfs via the lib/initramfs.sh seam (default dracut --hostonly)
#   2. ukify build: assemble + offline PCR 11 prediction in one pass
#      (--measure --json=short --pcr-banks=sha256 --phases=enter-initrd) and
#      ukify-native .pcrsig/.pcrpkey embedding for Mechanism A'' (static-7 +
#      signed-11)
#   3. combined {7,11} policy digest via lib/policy.sh (audit/display data;
#      the A'' token pins only the release pubkey — no pcrsign under A'')
#   4. sbsign (Secure Boot) + sbverify assertion
#   5. atomic ESP install (lib/esp.sh)
#   6. manifest upsert + meta
#   6b. ENSURE-ONCE A'' enrollment: token present → metadata read only
#      (s14: kernel updates are TPM-free) and the standing enrollment's
#      keyslot/token_id stamped onto every manifest entry (§8.4, incl. the
#      NEW kver — upsert carry-over is same-kver only); token absent →
#      exactly ONE cryptenroll, then keyslot/token_id recorded (§8.4);
#      volume unreachable → warn + empty bookkeeping (documented escape)
#   7. manifest + ESP prune to the single keep set (current + retention)
#      (only reached after 5, 6 and 6b succeeded)
#   8. predictions.json (B-G11: pcr11 enter-initrd, policy_digest, signature,
#      sizes, section digests, tool versions) — machine-readable handoff for the
#      harness prediction checks (§12)
#   9. clear the failure marker
#
# --re-sign-all (B-G12): recompute every retained entry's policy_digest from its
# stored pcr11_digest + the CURRENT baseline PCR 7 and re-sign — no UKI rebuild.
# This is the §9.4/§9.6 bookkeeping layer ONLY: it performs neither the ESP UKI
# re-install nor the re-enrollment that §9.6 step 6 names. Full runbook after a
# key rotation: `ukictl build <kver>` per retained kernel + `enroll-tpm`.

cmd_ukictl_build_usage() {
    cat >&2 <<EOF
Usage: $PROG ukictl build [--re-sign-all] [kver]

  kver            kernel release to build (default: the running kernel)
  --re-sign-all   re-sign every retained manifest entry against the current
                  baseline PCR 7 (and current key); no UKI rebuild
EOF
}

# _ukictl_lib NAME — source a sibling library next to this command file
_ukictl_lib() {
    # shellcheck disable=SC1090  # resolved next to this file
    . "${ALPINE_FDE_CMD_DIR:?}/../$1"
}

# _ukictl_marker_write <marker> <etc-dir> <kver> <reason> — persist the loud
# failure marker (consumed by `alpine-fde status`), best effort
_ukictl_marker_write() {
    _mk_file=$1
    _mk_etc=$2
    _mk_kver=$3
    _mk_reason=$4
    mkdir -p "$_mk_etc" 2>/dev/null || true
    {
        printf 'ukictl build failed for kernel %s\n' "$_mk_kver"
        printf 'time: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'reason: %s\n' "$_mk_reason"
    } >"$_mk_file" 2>/dev/null \
        || warn "ukictl build: cannot persist failure marker at $_mk_file"
}

# _uk_kernel_resolve ROOT KVER — real-server blocker #9b: resolve the kernel
# image for KVER. The verbatim <root>/boot/vmlinuz-<kver> path only exists in
# fixture sandboxes (which is why every local test passed); real Alpine kernel
# packages ship the UNVERSIONED FLAVOR image (/boot/vmlinuz-lts for linux-lts
# — the live run died on "required build input missing:
# /boot/vmlinuz-6.18.35-0-lts"). Priority order:
#   1. <root>/boot/vmlinuz-<kver>    (previous verbatim path — still first)
#   2. <root>/boot/vmlinuz-<flavor>  (the flavor suffix of the kver,
#      e.g. 6.18.35-0-lts -> lts — the linux-<flavor> package's image)
#   3. glob <root>/boot/vmlinuz-*    (last resort, already-probed skipped)
# Every candidate must be a regular NON-EMPTY file (a 0-byte image is a
# broken install, not a resolvable kernel). On success sets _uk_kernel and
# returns 0. On a total miss returns 1 with _uk_kernel_cands holding the
# probed list (newline-separated, in probe order) for the loud failure.
_uk_kernel_resolve() {
    _ukr_root=$1
    _ukr_kver=$2
    _uk_kernel=''
    _uk_kernel_cands="$_ukr_root/boot/vmlinuz-$_ukr_kver"
    # flavor = the kver's trailing package suffix (6.18.35-0-lts -> lts);
    # empty when the kver carries no flavor (plain <version>) — then only the
    # versioned path and the glob are probed.
    _ukr_flavor=$(printf '%s' "$_ukr_kver" | sed -n 's/^[0-9][0-9.]*-[0-9][0-9]*-//p')
    _ukr_try() { # <candidate> — record it, first regular non-empty file wins
        case "
$_uk_kernel_cands
" in
        *"
$1
"*) : ;; # already probed — never listed twice
        *) _uk_kernel_cands="$_uk_kernel_cands
$1" ;;
        esac
        [ -f "$1" ] && [ -s "$1" ] && {
            _uk_kernel=$1
            return 0
        }
        return 1
    }
    if _ukr_try "$_ukr_root/boot/vmlinuz-$_ukr_kver"; then
        return 0
    fi
    if [ -n "$_ukr_flavor" ] && _ukr_try "$_ukr_root/boot/vmlinuz-$_ukr_flavor"; then
        return 0
    fi
    for _ukr_g in "$_ukr_root"/boot/vmlinuz-*; do
        [ -e "$_ukr_g" ] || continue # unmatched glob
        if _ukr_try "$_ukr_g"; then
            return 0
        fi
    done
    return 1
}

cmd_ukictl_build_main() {
    strict_mode

    _uk_sign_all=0
    while [ $# -gt 0 ]; do
        case $1 in
            --re-sign-all)
                _uk_sign_all=1
                ;;
            -h | --help)
                cmd_ukictl_build_usage
                exit 0
                ;;
            -*)
                err "ukictl build: unknown option: $1"
                cmd_ukictl_build_usage
                exit "$ALPINE_FDE_USAGE"
                ;;
            *)
                break
                ;;
        esac
        shift
    done
    if [ $# -ge 1 ]; then
        _uk_kver=$1
    elif [ "$_uk_sign_all" -eq 1 ]; then
        # --re-sign-all consumes NO kernel image: it re-signs every retained
        # manifest entry against the CURRENT baseline — no kver to resolve
        # (blocker #11's strict no-arg resolution applies to real builds only)
        _uk_kver=''
    else
        # REAL-SERVER BLOCKER #11: NO-ARG invocation. `uname -r` is the LIVE
        # ISO's kernel on install media while the TARGET's installed linux-lts
        # is a different version (/lib/modules/<live-kver> does not exist in
        # the target — the live run built for the wrong kernel). Resolution
        # order: exactly ONE directory under <root>/lib/modules -> use it
        # (the in-chroot invocation sanity case); else `uname -r` ONLY when
        # its module dir actually exists in the target (back-compat for a
        # booted target); else fail closed LISTING the available dirs.
        _uk_mods="${ALPINE_FDE_ROOT:-}/lib/modules"
        _uk_cands=''
        for _uk_d in "$_uk_mods"/*/; do
            [ -d "$_uk_d" ] || continue # unmatched glob / non-dir: skipped
            _uk_b=${_uk_d%/} # the glob's trailing slash would empty ##*/
            _uk_cands="$_uk_cands ${_uk_b##*/}"
        done
        _uk_n=${_uk_cands//[^ ]/}
        _uk_run=$(uname -r 2>/dev/null)
        if [ ${#_uk_n} -eq 1 ]; then
            _uk_kver=${_uk_cands# }
            _uk_kver=${_uk_kver% }
        elif [ -n "$_uk_run" ] && [ -d "${_uk_mods}/$_uk_run" ]; then
            _uk_kver=$_uk_run
        else
            err "ukictl build: no kver given and no resolvable kernel module tree under $_uk_mods (found:${_uk_cands:- none}; the running kernel '${_uk_run:-unknown}' is not installed there) — pass the target kernel version explicitly (real-server blocker #11)"
            exit 64
        fi
        unset _uk_mods _uk_cands _uk_d _uk_b _uk_n _uk_run
    fi
    [ $# -le 1 ] || {
        err "ukictl build: too many arguments"
        cmd_ukictl_build_usage
        exit "$ALPINE_FDE_USAGE"
    }

    _ukictl_lib common.sh
    _ukictl_lib policy.sh
    _ukictl_lib manifest.sh
    _ukictl_lib keys.sh
    _ukictl_lib esp.sh
    _ukictl_lib initramfs.sh
    # G-R3: the build's ensure-once enroll step IS enroll-tpm's enrollment
    # (enrl_run/enrl_ensure_once shared core); sourced next to this command.
    # shellcheck disable=SC1091  # sibling in the same command directory
    . "${ALPINE_FDE_CMD_DIR:?}/enroll-tpm.sh"
    load_config

    # --- paths / config ---------------------------------------------------------
    _uk_root=${ALPINE_FDE_ROOT:-}
    _uk_etc="${_uk_root}/etc/alpine-fde"
    _uk_marker="$_uk_etc/build-failed"
    _uk_manifest="$_uk_etc/digests.json"
    _uk_predictions="$_uk_etc/predictions.json"
    _uk_baseline="$_uk_etc/baseline.json"
    _uk_cmdline=${CMDLINE_PATH:-"$_uk_etc/cmdline.txt"}
    _uk_kernel="${_uk_root}/boot/vmlinuz-$_uk_kver"
    _uk_osrelease="${_uk_root}/etc/os-release"
    # LO-01: the kver interpolates into UKI paths, manifest keys and the keep-set
    # JSON — validate once at the boundary (usage error, not a build failure)
    # blocker #11: --re-sign-all carries NO kver (nothing to validate) — it
    # exits at the re-sign-all branch below before any kver consumption
    if [ "$_uk_sign_all" -eq 0 ] && ! esp_validate_kver "$_uk_kver"; then
        err "ukictl build: invalid kernel version: '$_uk_kver' (alphanumerics, '.', '_', '-' only)"
        cmd_ukictl_build_usage
        exit "$ALPINE_FDE_USAGE"
    fi
    # G-B3/ADR-19/ADR-20: the ladder is resolved — Mechanism B (rung b) is the
    # normative Alpine seal path; a2 / a-prime-prime / native remain accepted
    # aliases. Documented-absent rungs fail closed (64) WITH the ADR-8 marker
    # (a build context exists here); unknown garbage stays an invalid
    # policy_mode error.
    _uk_pm_rc=0
    _uk_policy_mode=$(policy_mode_normalize "${POLICY_MODE:-${policy_mode:-a2}}") || _uk_pm_rc=$?
    if [ "$_uk_pm_rc" -ne 0 ]; then
        if [ "$_uk_pm_rc" -eq "$ALPINE_FDE_FAIL_CLOSED" ]; then
            _ukictl_marker_write "$_uk_marker" "$_uk_etc" "$_uk_kver" \
                "POLICY_MODE documented-absent (ADR-19/ADR-20): Mechanism B (rung b) is the normative seal path; refusing to build"
            err "ukictl build: refusing to build — see the POLICY_MODE error above (ADR-19/ADR-20)"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
        die "ukictl build: invalid policy_mode (expected: b — a2 / a-prime-prime / native accepted as aliases; ADR-19/ADR-20)"
    fi
    _uk_retention=${RETENTION:-2}
    case $_uk_retention in
        '' | *[!0-9]*)
            die "ukictl build: invalid retention '$_uk_retention' (expected a non-negative integer)"
            ;;
    esac

    require_pkgs jq:jq openssl:openssl ukify:systemd-ukify sbsign:sbsigntool sbverify:sbsigntool

    # --- 0. loud-fail preconditions BEFORE any ESP mutation (ADR-8) --------------
    if ! _uk_key_reason=$(keys_check); then
        _ukictl_marker_write "$_uk_marker" "$_uk_etc" "$_uk_kver" "$_uk_key_reason"
        err "ukictl build: $_uk_key_reason"
        err "ukictl build: refusing to touch the ESP — restore the scp backup or attach the signing medium and re-run (ADR-8/ADR-18)"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi

    # baseline PCR 7 (pending until `audit --init` finalizes it, §8.4) — under
    # A'' this is display/audit data only; a pending baseline never blocks a build
    _uk_d7=''
    if [ -f "$_uk_baseline" ]; then
        _uk_d7=$(jq -r '.expected_pcr7 // empty' "$_uk_baseline" 2>/dev/null || true)
    fi

    # --- ADR-8 failure net (review HW-1) --------------------------------------------
    # Every failure past this point — including `die` from a lib helper inside
    # the build body (ESP install, manifest, policy), SIGINT and SIGTERM — must
    # (a) wipe the build workdir and (b) persist the ADR-8 marker for `status`.
    # _uk_fail_reason carries a precise reason where the failing site knows it;
    # the trap is the SINGLE marker writer from here on. Lib code installs no
    # traps of its own (policy.sh rule); only this cmd owns the handler.
    _uk_work=''
    _uk_rs_tmp=''
    _uk_rs_sig_tmp=''
    _uk_rs_pred_tmp=''
    _uk_unlock_tmp=''
    _uk_fail_reason=''
    _uk_cleanup() {
        _uk_rc=$?
        # WR-02: every cleanup rm is guarded — strict_mode's errexit is
        # inherited by this trap, and a failing rm (EROFS/EIO) must never
        # abort the trap BEFORE the ADR-8 marker write nor replace the
        # original exit status. Cleanup is best effort; marker + rc are not.
        if [ -n "$_uk_work" ]; then
            rm -rf "$_uk_work" 2>/dev/null || :
        fi
        if [ -n "$_uk_rs_tmp" ]; then
            rm -f "$_uk_rs_tmp" 2>/dev/null || :
            [ -z "${_uk_rs_sig_tmp:-}" ] || rm -f "$_uk_rs_sig_tmp" 2>/dev/null || :
            [ -z "${_uk_rs_pred_tmp:-}" ] || rm -f "$_uk_rs_pred_tmp" 2>/dev/null || :
        fi
        # G-KC4/ADR-18: the decrypted release.pem copy exists only for this
        # build — zeroize+unlink it on EVERY exit path (tmpfs already, but the
        # scrub keeps the no-plaintext-left-behind invariant uniform)
        if [ -n "${_uk_unlock_tmp:-}" ]; then
            keys_scrub "${_uk_unlock_tmp}" 2>/dev/null || :
        fi
        if [ "$_uk_rc" -ne 0 ]; then
            _ukictl_marker_write "$_uk_marker" "$_uk_etc" "$_uk_kver" \
                "${_uk_fail_reason:-build failed (rc=$_uk_rc); full output above}"
        fi
        exit "$_uk_rc"
    }
    trap _uk_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    # --- G-KC4/ADR-18: release-key unlock seam (ONCE, before any signer) ---------
    # keys_check proved release.pem EXISTS. When it is the ADR-18 encrypted
    # form, decrypt it ONCE via keys_unlock (ALPINE_FDE_KEY_PASSPHRASE env ->
    # no-echo TTY prompt -> loud 64) and hand the UNLOCKED tmpfs path to every
    # signer below (ukify --pcr-private-key, sbsign --key, policy_sign). A
    # plaintext release.pem (offline medium / legacy) keeps the previous
    # behavior with ZERO passphrase interaction. The decrypted copy is scrubbed
    # by the EXIT-trap net above.
    _uk_keydir=$(keys_dir)
    _uk_keyfile="$_uk_keydir/release.pem"
    if keys_is_encrypted "$_uk_keyfile"; then
        _uk_unlock_tmp=$(keys_unlock "$_uk_keydir") || {
            if [ -n "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
                _uk_fail_reason="release.pem unlock failed: wrong passphrase (ALPINE_FDE_KEY_PASSPHRASE rejected) — release key stays locked (ADR-18)"
            else
                _uk_fail_reason="release.pem is encrypted: passphrase required; provide ALPINE_FDE_KEY_PASSPHRASE or run interactively (ADR-18)"
            fi
            err "ukictl build: $_uk_fail_reason"
            err "ukictl build: refusing to touch the ESP (ADR-8/ADR-18)"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        }
        chmod 600 "$_uk_unlock_tmp" 2>/dev/null || :
        _uk_keyfile=$_uk_unlock_tmp
        info "ukictl build: unlocked encrypted release.pem -> $_uk_keyfile (scrubbed at exit)"
    fi

    # --- re-sign-all path (B-G12; no UKI rebuild, no ESP writes) ------------------
    if [ "$_uk_sign_all" -eq 1 ]; then
        _ukictl_re_sign_all "$_uk_manifest" "$_uk_d7" "$_uk_marker"
        exit 0 # re-sign-all returns; this exit fires the cleanup trap with rc 0
    fi

    # blocker #9b: resolve the kernel image (versioned path -> flavor image ->
    # glob) BEFORE the input check; a total miss is the loud fail-closed
    # failure with the candidates probed + the remedy (never a bare
    # "<root>/boot/vmlinuz-<kver>" that only fixture sandboxes can satisfy).
    if ! _uk_kernel_resolve "$_uk_root" "$_uk_kver"; then
        _uk_fail_reason="required build input missing: kernel image for $_uk_kver"
        err "ukictl build: required build input missing: kernel image for $_uk_kver"
        err "ukictl build: probed (first regular non-empty file wins): $(printf '%s' "$_uk_kernel_cands" | tr '\n' ' ')"
        err "ukictl build: remedy: install the matching kernel package (e.g. apk add linux-lts) and check: ls ${_uk_root:-}/boot"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi

    for _uk_f in "$_uk_kernel" "$_uk_cmdline" "$_uk_osrelease"; do
        if [ ! -f "$_uk_f" ]; then
            _uk_fail_reason="required build input missing: $_uk_f"
            err "ukictl build: $_uk_fail_reason"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
    done

    # --- cmdline pins guard (G-U6; §8.2 H-G1) — the pins are build inputs ---------
    if ! _uk_pins_reason=$(cmdline_pins_check "$_uk_cmdline"); then
        _uk_fail_reason=$_uk_pins_reason
        err "ukictl build: $_uk_pins_reason"
        err "ukictl build: refusing to embed an unpinned cmdline (emergency-shell escape) — restore rd.shell=0 rd.emergency=poweroff"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi

    # --- crypttab guard (G-U4; §8.2 verified coupling) — BEFORE the initramfs -----
    # systemd-cryptsetup adds tpm2-tss only when /etc/crypttab carries
    # tpm2-device= AT BUILD TIME; a build without it silently ships an initrd
    # that can never TPM-unlock (ADR-8: loud failure instead).
    if ! _uk_ct_reason=$(crypttab_tpm2_check "${_uk_root}/etc/crypttab"); then
        _uk_fail_reason=$_uk_ct_reason
        err "ukictl build: $_uk_ct_reason"
        err "ukictl build: refusing to build the initramfs — fix /etc/crypttab first (§8.2)"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi

    # --- workdir + guarded build body ----------------------------------------------
    _uk_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-build.XXXXXX") || {
        _uk_fail_reason="mktemp for the build workdir failed"
        err "ukictl build: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    }
    _uk_uki="$_uk_work/uki.efi"
    _uk_uki_signed="$_uk_work/uki.signed.efi"
    _uk_measure="$_uk_work/measure.json"

    # _uk_body runs inside a `||` context, which SUPPRESES errexit for its whole
    # duration — strict_mode is dead in here. The contract is therefore explicit
    # guards at every fragile step: each failing site sets _uk_fail_reason,
    # reports, and `return 1` (review MD-01); `die` from a lib helper exits and
    # lands in the EXIT trap (workdir wipe + marker) either way. The previous
    # default UKI is never touched on the failure paths — ESP writes happen only
    # in step 5, atomically, after every fragile step succeeded.
    _uk_rc=0
    _uk_body || _uk_rc=$?
    if [ "$_uk_rc" -ne 0 ]; then
        _uk_fail_reason="${_uk_fail_reason:-build step failed (rc=$_uk_rc); full output above}"
        err "ukictl build: failed — $_uk_fail_reason"
        err "ukictl build: previous UKI left untouched; marker: $_uk_marker"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi

    exit 0 # EXIT trap wipes the (already removed) workdir; rc 0 writes no marker
}

# _uk_body — the build pipeline proper (run in the guarded context of
# cmd_ukictl_build_main; all _uk_* variables are process globals of this cmd)
_uk_body() {
    _uk_keydir=$(keys_dir)

    # --- 1. initramfs (seam; default dracut --hostonly) ---------------------------
    initramfs_build "$_uk_work/initrd.img" "$_uk_kver"

    # --- 1b. initrd inventory audit (§8.2/§12/I6; loud ADR-8 failure) --------------
    if ! initrd_audit "$_uk_work/initrd.img" "$_uk_kver" "$_uk_root"; then
        _uk_fail_reason="initrd audit failed: ${_initrd_audit_reason:-<no reason>}"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi

    # --- 2. ukify: assemble + measure + Mechanism A'' .pcrsig ----------------------
    # Verified flag surface (ukify 261): .pcrsig embedding happens via
    # --pcr-private-key/--pcr-public-key/--phases; there is no --pcr-signature
    # option in this release (manual .pcrsig content injection is --pcrsig=).
    # The argv accumulates in "$@" (POSIX set --) — config-derived paths with
    # spaces/globs stay single arguments (review MD-02; the old newline template
    # was deliberately word-split).
    set -- \
        "--linux=$_uk_kernel" \
        "--initrd=$_uk_work/initrd.img" \
        "--cmdline=@$_uk_cmdline" \
        "--os-release=@$_uk_osrelease" \
        "--uname=$_uk_kver" \
        --pcr-banks=sha256 \
        --phases=enter-initrd \
        "--pcr-private-key=$_uk_keyfile" \
        "--pcr-public-key=$_uk_keydir/release.pub" \
        --measure --json=short \
        "--output=$_uk_uki"
    if [ -n "${STUB_PATH:-}" ]; then
        set -- "$@" "--stub=$STUB_PATH"
    fi
    if ! ukify build "$@" >"$_uk_measure"; then
        _uk_fail_reason="ukify build failed (kernel $_uk_kver)"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi
    _uk_pcr11=$(jq -r '.sha256[] | select(.phase == "enter-initrd") | .hash' "$_uk_measure")
    if [ "${#_uk_pcr11}" -ne 64 ] || ! policy_check_digest "$_uk_pcr11"; then
        _uk_fail_reason="ukify did not predict an enter-initrd PCR 11 digest"
        err "ukictl build: ukify did not predict an enter-initrd PCR 11 digest (got '${_uk_pcr11:-<none>}')"
        return 1
    fi

    # --- 3. combined policy digest (audit/display data; A'' never pcrsigns) --------
    _uk_policy_digest=''
    _uk_signature=''
    if policy_check_digest "$_uk_d7"; then
        _uk_policy_digest=$(policy_digest "$_uk_d7" "$_uk_pcr11")
    else
        warn "ukictl build: baseline PCR 7 pending — policy_digest/signature recorded as empty (run 'alpine-fde audit --init')"
    fi

    # --- 4. Secure Boot signing + verification --------------------------------------
    # MD-01: explicit guards — sbsign failing must not fall through into sbverify
    # and get misreported as "sbverify rejected the signed UKI".
    if ! sbsign --key "$_uk_keyfile" --cert "$_uk_keydir/release.crt" \
        --output "$_uk_uki_signed" "$_uk_uki" >/dev/null; then
        _uk_fail_reason="sbsign failed (key/cert: $_uk_keydir)"
        err "ukictl build: sbsign failed — check the signing key (key: $_uk_keyfile)"
        return 1
    fi
    sbverify --cert "$_uk_keydir/release.crt" "$_uk_uki_signed" >/dev/null || {
        _uk_fail_reason="sbverify rejected the signed UKI"
        err "ukictl build: sbverify rejected the signed UKI"
        return 1
    }

    # --- 5. atomic ESP install -------------------------------------------------------
    esp_install_uki "$_uk_uki_signed" "$_uk_kver"

    # --- 6. manifest upsert + meta ----------------------------------------------------
    # MD-01: the signing-bucket contract for policy_pubkey_fp is "empty stdout +
    # rc 1 on failure" — consume defensively, never record a silent empty fp.
    if ! _uk_pubkey_fp=$(policy_pubkey_fp "$_uk_keydir/release.pub") || [ -z "$_uk_pubkey_fp" ]; then
        _uk_fail_reason="cannot fingerprint the release public key ($_uk_keydir/release.pub)"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi
    manifest_upsert "$_uk_manifest" "$_uk_kver" "$_uk_pcr11" "$_uk_policy_digest" "$_uk_signature"
    manifest_set_meta "$_uk_manifest" "$_uk_kver" "$_uk_pubkey_fp"

    # --- 6b. ENSURE-ONCE TPM enrollment (Mechanism B; §6.1/§8.1, s14 semantics,
    # ADR-19/ADR-20, G-U1) --------------------------------------------
    # Kernel updates are TPM-free: when the LUKS2 volume already carries a
    # systemd-tpm2 token this step is a metadata read only (ZERO TPM operations)
    # and the standing enrollment's keyslot/token_id are stamped onto every
    # manifest entry (§8.4: repeated per entry — the NEW kver's upserted entry
    # starts empty). A fresh volume gets exactly ONE Mechanism B enrollment
    # (seal under static PCR 7 + release-pubkey-signed PCR 11; §6.1/§7.2), then
    # enrolled.json is written and the manifest records the enrollment's
    # keyslot/token_id (§8.4).
    # An unreachable volume is the documented precondition escape (warn + empty
    # bookkeeping). Prune (6c/7) runs only after this succeeded — an enroll
    # failure lands on the ADR-8 marker path with the pre-enroll ESP/manifest
    # state (UKI install may stand).
    _uk_luks_uuid=$(enrl_crypttab_uuid "${_uk_root}/etc/crypttab" || true)
    _uk_luks_dev=''
    if [ -n "$_uk_luks_uuid" ]; then
        _uk_luks_dev="$(enrl_by_uuid_dir)/$_uk_luks_uuid"
    fi
    ENRL_ENROLLED=0
    if ! enrl_ensure_once "$_uk_luks_dev" "$_uk_keydir/release.pub"; then
        _uk_fail_reason="TPM enrollment failed (Mechanism B ensure-once; device: ${_uk_luks_dev:-<none>})${ENRL_FAIL_REASON:+: $ENRL_FAIL_REASON}"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi
    if [ "$ENRL_ENROLLED" -eq 1 ]; then
        # LO-02/MD-01: the enrolled.json write is guarded — a silent empty-write
        # would leave the §8.4 record missing while the build reports success
        if ! enrl_record "$_uk_luks_uuid" "$_uk_policy_mode" "$ENRL_WIPE" "$ENRL_SLOT" \
            "$_uk_keydir/release.pub"; then
            _uk_fail_reason="writing enrolled.json failed after enrollment"
            err "ukictl build: $_uk_fail_reason"
            return 1
        fi
        manifest_set_enrollment "$_uk_manifest" "$ENRL_SLOT" "$ENRL_TOKEN_ID"
    elif [ -n "$_uk_luks_dev" ] && [ -e "$_uk_luks_dev" ]; then
        # Token standing (the s14 zero-TPM-op path): §8.4 stamps the standing
        # enrollment's keyslot/token_id onto EVERY manifest entry — incl. the
        # NEW kver just upserted (upsert carry-over covers same-kver rebuilds
        # only). Source: the token introspection ensure-once already read —
        # a luksDump metadata read only, still ZERO TPM operations.
        _uk_standing=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-standing.XXXXXX") ||
            die "ukictl build: mktemp failed"
        if enrl_cryptsetup luksDump --dump-json-metadata "$_uk_luks_dev" \
            >"$_uk_standing" 2>/dev/null; then
            _uk_slot=$(luks_json_token_keyslot "$_uk_standing" systemd-tpm2 || true)
            _uk_tok=$(enrl_json_token_id "$_uk_standing" systemd-tpm2)
            if [ -n "$_uk_slot" ] && [ -n "$_uk_tok" ]; then
                manifest_set_enrollment "$_uk_manifest" "$_uk_slot" "$_uk_tok"
            else
                warn "ukictl build: cannot parse the standing token's keyslot/token_id on $_uk_luks_dev — manifest enrollment bookkeeping left unstamped (§8.4); re-run the build with the volume attached"
            fi
        else
            warn "ukictl build: cannot re-read LUKS2 metadata of $_uk_luks_dev — manifest enrollment bookkeeping left unstamped (§8.4); re-run the build with the volume attached"
        fi
        rm -f "$_uk_standing"
    fi
    # Volume unreachable (dev empty or unresolvable) is the documented
    # precondition escape: enrl_ensure_once warned; the entries keep empty
    # keyslot/token_id bookkeeping until a build that can reach the volume.

    # --- 6c. manifest prune to the keep set --------------------------------------------
    _uk_keep=$(esp_compute_keep "$_uk_kver" "$_uk_retention")
    # shellcheck disable=SC2086  # word split intended: one kver per line
    manifest_prune_to "$_uk_manifest" $_uk_keep

    # --- 7. ESP prune (only after successful install + manifest update, B-G5) -------
    # LO-04: a prune rm failure would silently diverge ESP from manifest (§9.2);
    # the build treats it as a marked failure instead.
    # shellcheck disable=SC2086  # word split intended: one kver per line
    if ! esp_prune_ukis $_uk_keep; then
        _uk_fail_reason="ESP prune failed — ESP and manifest would diverge (§9.2); marker set, UKI install stands"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi

    # --- 8. predictions.json (B-G11/B-G15) -------------------------------------------
    if ! _uk_sections=$(ukify inspect "$_uk_uki_signed" --json=short); then
        _uk_fail_reason="ukify inspect failed on the installed UKI"
        err "ukictl build: $_uk_fail_reason"
        return 1
    fi
    _uk_uki_size=$(wc -c <"$_uk_uki_signed" | tr -d '[:space:]')
    _uk_ukify_ver=$(ukify --version 2>/dev/null | head -n1)
    _uk_sbsign_ver=$(sbsign --version 2>/dev/null | head -n1)
    _uk_openssl_ver=$(openssl version 2>/dev/null | head -n1)
    _uk_predictions_tmp="$_uk_work/predictions.json"
    if ! jq -n \
        --arg kver "$_uk_kver" \
        --arg pcr11 "$_uk_pcr11" \
        --arg pd "$_uk_policy_digest" \
        --arg sig "$_uk_signature" \
        --arg mode "$_uk_policy_mode" \
        --arg fp "$_uk_pubkey_fp" \
        --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg uki_size "$_uk_uki_size" \
        --arg ukify_ver "$_uk_ukify_ver" \
        --arg sbsign_ver "$_uk_sbsign_ver" \
        --arg openssl_ver "$_uk_openssl_ver" \
        --argjson retention "$_uk_retention" \
        --argjson sections "$_uk_sections" \
        '{kernel_version: $kver, pcr_bank: "sha256", phase: "enter-initrd",
          pcr11_digest: $pcr11, policy_digest: $pd, signature: $sig,
          policy_mode: $mode, pubkey_fp: $fp,
          uki_size: ($uki_size | tonumber), retention: $retention,
          sections: ($sections | with_entries(.value |= {size: .size, sha256: .sha256})),
          tools: {ukify: $ukify_ver, sbsign: $sbsign_ver, openssl: $openssl_ver},
          updated_at: $now}' >"$_uk_predictions_tmp"; then
        err "ukictl build: assembling predictions.json failed"
        return 1
    fi
    manifest_atomic_write "$_uk_predictions" <"$_uk_predictions_tmp"

    # --- 9. success: clear the failure marker -----------------------------------------
    rm -f "$_uk_marker"
    info "ukictl build: kernel $_uk_kver installed and recorded (pcr11=$_uk_pcr11 policy=${_uk_policy_digest:-<pending>})"
    return 0
}

# _ukictl_re_sign_all <manifest> <d7hex> <marker> — B-G12: recompute every
# retained entry's policy_digest from its stored pcr11_digest + current d7,
# re-sign with the current key, atomically rewrite the manifest, print a diff.
#
# §9.4/§9.6 bookkeeping layer ONLY (review MD-03 header fix): no ESP UKI
# re-install and no re-enrollment happen here — for the full §9.6 step-6
# runbook run `ukictl build <kver>` per retained kernel + `enroll-tpm`.
#
# Failure contract (review MD-03 + HW-1):
#   * a pending baseline d7 is refused by a PRECHECK before the loop (the old
#     die-inside-the-loop tore the manifest: some entries re-signed, others not)
#   * the loop mutates a COPY; the live manifest is replaced by ONE atomic
#     write at the end — a mid-loop die rewrites nothing
#   * predictions.json is refreshed (policy_digest/signature/updated_at) in the
#     same pass, so the harness prediction checks (§12) never see divergence
#   * any failure exits non-zero → the cmd's EXIT trap wipes temps and
#     persists the ADR-8 marker
_ukictl_re_sign_all() {
    _uk_manifest=$1
    _uk_d7=$2
    _uk_marker=$3
    manifest_load "$_uk_manifest" >/dev/null 2>&1 \
        || die "ukictl build --re-sign-all: no manifest at $_uk_manifest (nothing to re-sign)"
    # precheck: a pending baseline PCR 7 makes every policy_digest computation
    # impossible — refuse BEFORE any transformation (torn-manifest prevention)
    if ! policy_check_digest "$_uk_d7"; then
        _uk_fail_reason="re-sign-all: baseline PCR 7 pending — run 'alpine-fde audit --init' first; nothing re-signed"
        err "ukictl build --re-sign-all: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi
    _uk_keydir=$(keys_dir)
    _uk_rs_tmp=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-resign.XXXXXX") || {
        _uk_fail_reason="mktemp failed (re-sign-all manifest copy)"
        err "ukictl build: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    }
    _uk_rs_sig_tmp=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-resign.XXXXXX") || {
        _uk_fail_reason="mktemp failed (re-sign-all signature)"
        err "ukictl build: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    }
    # transactional: all re-signs land in the COPY; the live manifest is
    # replaced once, atomically, after the last entry succeeded
    # (IN-01: the cp is guarded — a truncated copy would only fail later with
    # a misattributed schema error)
    cp "$_uk_manifest" "$_uk_rs_tmp" || {
        _uk_fail_reason="cannot copy the manifest for re-signing ($_uk_manifest -> $_uk_rs_tmp)"
        err "ukictl build --re-sign-all: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    }
    for _uk_kver in $(manifest_kvers "$_uk_manifest"); do
        _uk_pcr11=$(jq -r --arg kver "$_uk_kver" \
            '.digests[] | select(.kernel_version == $kver) | .pcr11_digest' "$_uk_manifest")
        if ! policy_check_digest "$_uk_pcr11"; then
            _uk_fail_reason="re-sign-all: entry $_uk_kver has no/invalid stored pcr11_digest"
            err "ukictl build --re-sign-all: entry $_uk_kver has no stored pcr11_digest"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
        if ! _uk_pd=$(policy_digest "$_uk_d7" "$_uk_pcr11"); then
            _uk_fail_reason="re-sign-all: policy digest computation failed for $_uk_kver"
            err "ukictl build --re-sign-all: $_uk_fail_reason"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
        if ! policy_sign "$_uk_d7" "$_uk_pcr11" "$_uk_keyfile" "$_uk_rs_sig_tmp"; then
            _uk_fail_reason="re-sign-all: signing the policy digest failed for $_uk_kver (key: $_uk_keyfile)"
            err "ukictl build --re-sign-all: $_uk_fail_reason"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
        if ! _uk_sig=$(openssl base64 -A -in "$_uk_rs_sig_tmp"); then
            _uk_fail_reason="re-sign-all: base64 encoding the signature failed for $_uk_kver"
            err "ukictl build --re-sign-all: $_uk_fail_reason"
            exit "$ALPINE_FDE_FAIL_CLOSED"
        fi
        manifest_upsert "$_uk_rs_tmp" "$_uk_kver" "$_uk_pcr11" "$_uk_pd" "$_uk_sig"
        _uk_old=$(jq -r --arg kver "$_uk_kver" \
            '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$_uk_manifest")
        if [ "$_uk_old" != "$_uk_pd" ]; then
            info "re-sign-all: $_uk_kver policy_digest $_uk_old -> $_uk_pd"
        else
            info "re-sign-all: $_uk_kver unchanged ($_uk_pd)"
        fi
    done
    if ! _uk_fp=$(policy_pubkey_fp "$_uk_keydir/release.pub") || [ -z "$_uk_fp" ]; then
        _uk_fail_reason="re-sign-all: cannot fingerprint the release public key ($_uk_keydir/release.pub)"
        err "ukictl build --re-sign-all: $_uk_fail_reason"
        exit "$ALPINE_FDE_FAIL_CLOSED"
    fi
    manifest_set_meta "$_uk_rs_tmp" "$(jq -r '.current_kernel // empty' "$_uk_rs_tmp")" "$_uk_fp"

    # predictions.json refresh (same pass; §12 prediction checks stay coherent)
    _uk_pred="$(dirname "$_uk_manifest")/predictions.json"
    _uk_cur=$(jq -r '.current_kernel // empty' "$_uk_rs_tmp")
    if [ -f "$_uk_pred" ] && [ -n "$_uk_cur" ] \
        && _uk_cur_pd=$(jq -r --arg kver "$_uk_cur" \
            '.digests[] | select(.kernel_version == $kver) | .policy_digest // empty' "$_uk_rs_tmp") \
        && _uk_cur_sig=$(jq -r --arg kver "$_uk_cur" \
            '.digests[] | select(.kernel_version == $kver) | .signature // empty' "$_uk_rs_tmp"); then
        if [ -n "$_uk_cur_pd" ]; then
            _uk_rs_pred_tmp=$(mktemp "${TMPDIR:-/tmp}/alpine-fde-resign.XXXXXX") || {
                _uk_fail_reason="mktemp failed (re-sign-all predictions)"
                err "ukictl build: $_uk_fail_reason"
                exit "$ALPINE_FDE_FAIL_CLOSED"
            }
            if ! jq --arg pd "$_uk_cur_pd" --arg sig "$_uk_cur_sig" \
                --arg now "$(manifest_now)" \
                '.policy_digest = $pd | .signature = $sig | .updated_at = $now' \
                "$_uk_pred" >"$_uk_rs_pred_tmp"; then
                _uk_fail_reason="re-sign-all: refreshing predictions.json failed"
                err "ukictl build --re-sign-all: $_uk_fail_reason"
                exit "$ALPINE_FDE_FAIL_CLOSED"
            fi
            manifest_atomic_write "$_uk_pred" <"$_uk_rs_pred_tmp"
            rm -f "$_uk_rs_pred_tmp"
            _uk_rs_pred_tmp=''
        fi
    fi

    # the single transactional write — everything before this could die freely
    manifest_atomic_write "$_uk_manifest" <"$_uk_rs_tmp"
    _uk_rs_tmp=''
    rm -f "$_uk_rs_sig_tmp"
    _uk_rs_sig_tmp=''
    rm -f "$_uk_marker"
    info "ukictl build --re-sign-all: $_uk_manifest re-signed over baseline d7 ($_uk_d7)"
}
