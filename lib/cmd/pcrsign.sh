#!/bin/sh
# cmd/pcrsign.sh — `debian-fde pcrsign` (docs/Architecture.md §8.1 row pcrsign;
# normative signer contract §6.1.1, gap G-B4).
#
# Standalone signer: combined {7,11} PolicyPCR policy digest -> release-key
# PolicyAuthorize signature JSON (systemd-measure sign output shape, existing
# fields only). All signing math lives in lib/policy.sh (golden-vector pinned +
# live-TPM cross-checked); key material handling in lib/keys.sh — the keydir
# release.pem is routed through keys_unlock (ADR-18 encrypted-at-rest form is
# decrypted to a scrubbed tmpfs copy; §11 I4), the same seam enrl_sign_pcrsig
# and the ukictl hook use.
#
# Sequence (§6.1.1 steps 1–5):
#   1. expected PCR 11 digest: `ukify build --measure`, phase pinned
#      enter-initrd (systemd-measure calculate fallback when ukify is absent).
#      Input is either --uki <file> (measurable sections extracted via
#      objcopy — .linux/.initrd/.cmdline/.osrel; UKIs carrying other measured
#      sections (.ucode/.dtb/.splash/.pcrpkey) are REFUSED fail-closed —
#      S-M3: sign from component inputs instead) or explicit component files.
#   2. expected PCR 7 digest from the FINALIZED baseline (§8.4); pending or
#      missing baseline is a loud fail-closed 64.
#   3. combined {7,11} trial digest via lib/policy.sh (formula with the
#      PolicyPCR command-code bytes; the live-TPM trial session remains the
#      normative cross-check — policy_digest_tpm_crosscheck.sh).
#   4. release-key RSASSA-PKCS1-v1_5/SHA256 signature over the raw 32-byte
#      policyDigest (policyRef empty; keyName is NOT signed — it enters only
#      the sealed-object policy digest, §6.1.1 step 4b).
#   5. emit the systemd-measure sign-format JSON with pcrs [7,11] — no
#      invented fields (policy_sign_json).
#
# Errors exit 64 fail-closed (missing tools, missing/pending baseline, missing
# keys, bad measurements, release-key unlock failure); CLI-shape errors exit 2
# with usage (§8.1 contract).

_pcrsign_lib() {
    # shellcheck disable=SC1090  # resolved next to this command file
    . "$DEBIAN_FDE_CMD_DIR/../$1"
}

# _pcrsign_marker_write REASON — persist the ADR-8 failure marker for a
# release-key UNLOCK failure (ADR-18: the keydir release.pem is the
# encrypted-at-rest form and could not be decrypted), best effort, same shape
# as ukictl-build's _ukictl_marker_write (consumed next to
# <etc>/build-failed). Only the unlock path writes it: this command is a
# standalone signer with no ESP/build state of its own.
_pcrsign_marker_write() {
    _pm_etc="${DEBIAN_FDE_ROOT:-}/etc/alpine-fde"
    mkdir -p "$_pm_etc" 2>/dev/null || true
    {
        printf 'pcrsign failed (release key unlock, ADR-18)\n'
        printf 'time: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'reason: %s\n' "$1"
    } >"$_pm_etc/pcrsign-failed" 2>/dev/null \
        || warn "pcrsign: cannot persist failure marker at $_pm_etc/pcrsign-failed"
    return 0
}

cmd_pcrsign_usage() {
    cat >&2 <<EOF
Usage: $PROG pcrsign (--uki <file> | --linux <file> [--initrd <file>] [--cmdline <file>] [--os-release <file>])
                     [--baseline <file>] [--out <file>]

  --uki <file>        measure an existing UKI (extracts .linux/.initrd/
                      .cmdline/.osrel; UKIs carrying other measured sections
                      (.ucode/.dtb/.splash/.pcrpkey) are refused — sign from
                      component inputs instead)
  --linux <file>      kernel image component
  --initrd <file>     initrd component
  --cmdline <file>    kernel command line component
  --os-release <file> os-release component
  --baseline <file>   baseline.json override (default: <root>/etc/alpine-fde/)
  --out <file>        write the signature JSON here (default: stdout)

The baseline PCR 7 must be finalized ('debian-fde audit --init'); release key
material must be available (--keydir / KEY_PATH / DEBIAN_FDE_KEYDIR).
EOF
}

cmd_pcrsign_main() {
    strict_mode

    _ps_uki=''
    _ps_linux=''
    _ps_initrd=''
    _ps_cmdline=''
    _ps_osrelease=''
    _ps_baseline=''
    _ps_out=''
    while [ $# -gt 0 ]; do
        case $1 in
            --uki | --linux | --initrd | --cmdline | --os-release | --baseline | --out)
                [ $# -ge 2 ] || {
                    err "pcrsign: option $1 requires an argument"
                    cmd_pcrsign_usage
                    exit "$DEBIAN_FDE_USAGE"
                }
                _ps_opt=$1
                [ "$1" = --uki ] && _ps_uki=$2
                [ "$1" = --linux ] && _ps_linux=$2
                [ "$1" = --initrd ] && _ps_initrd=$2
                [ "$1" = --cmdline ] && _ps_cmdline=$2
                [ "$1" = --os-release ] && _ps_osrelease=$2
                [ "$1" = --baseline ] && _ps_baseline=$2
                [ "$1" = --out ] && _ps_out=$2
                shift
                ;;
            -h | --help)
                cmd_pcrsign_usage
                exit 0
                ;;
            -*)
                err "pcrsign: unknown option: $1"
                cmd_pcrsign_usage
                exit "$DEBIAN_FDE_USAGE"
                ;;
            *)
                err "pcrsign: unexpected argument: $1"
                cmd_pcrsign_usage
                exit "$DEBIAN_FDE_USAGE"
                ;;
        esac
        shift
    done

    # --- CLI-shape validation (usage = 2) ---------------------------------------
    if [ -n "$_ps_uki" ] && [ -n "$_ps_linux" ]; then
        err "pcrsign: --uki and --linux are mutually exclusive"
        cmd_pcrsign_usage
        exit "$DEBIAN_FDE_USAGE"
    fi
    if [ -z "$_ps_uki" ] && [ -z "$_ps_linux" ]; then
        err "pcrsign: need a measurement input: --uki <file> or --linux <file>"
        cmd_pcrsign_usage
        exit "$DEBIAN_FDE_USAGE"
    fi
    # S-L3: --initrd/--cmdline/--os-release would be silently ignored next to
    # --uki (the UKI's own components are what gets measured)
    if [ -n "$_ps_uki" ]; then
        for _ps_c in "$_ps_initrd" "$_ps_cmdline" "$_ps_osrelease"; do
            if [ -n "$_ps_c" ]; then
                err "pcrsign: component inputs cannot be combined with --uki (drop them, or sign from components without --uki)"
                cmd_pcrsign_usage
                exit "$DEBIAN_FDE_USAGE"
            fi
        done
    fi

    _pcrsign_lib common.sh
    _pcrsign_lib policy.sh
    _pcrsign_lib keys.sh
    require_pkgs jq:jq openssl:openssl

    # §6.1.1 step 1: ukify primary, systemd-measure fallback; loud 64 if neither
    if ! command -v ukify >/dev/null 2>&1 && ! command -v systemd-measure >/dev/null 2>&1; then
        require_pkgs ukify:systemd-ukify
    fi

    # --- fail-closed preconditions (ADR-8: keys before any artifact) -------------
    keys_require

    # --- §6.1.1 step 2: finalized baseline PCR 7 (§8.4) ---------------------------
    if [ -z "$_ps_baseline" ]; then
        _ps_root=${DEBIAN_FDE_ROOT:-}
        _ps_baseline="$_ps_root/etc/alpine-fde/baseline.json"
    fi
    if [ ! -f "$_ps_baseline" ]; then
        die "pcrsign: baseline file not found: $_ps_baseline (expected the finalized baseline.json — run 'debian-fde audit --init' after the first boot into the final SB state)"
    fi
    _ps_d7=$(jq -r '.expected_pcr7 // empty' "$_ps_baseline" 2>/dev/null || true)
    if [ "$_ps_d7" = "pending" ]; then
        die "pcrsign: baseline PCR 7 is still pending — boot once into the final SB state and run 'debian-fde audit --init' (§8.4); refusing to sign against an unknown PCR 7"
    fi
    policy_check_digest "$_ps_d7" || die "pcrsign: baseline has no usable expected_pcr7 digest (got '${_ps_d7:-<none>}' in $_ps_baseline) — run 'debian-fde audit --init' (§8.4)"

    # --- §6.1.1 step 1: expected PCR 11 digest (enter-initrd) ----------------------
    _ps_work=$(mktemp -d "${TMPDIR:-/tmp}/debian-fde-pcrsign.XXXXXX") || die "pcrsign: mktemp failed"
    _ps_d11=''
    if [ -n "$_ps_uki" ]; then
        [ -f "$_ps_uki" ] || {
            rm -rf "$_ps_work"
            die "pcrsign: UKI input missing: $_ps_uki"
        }
        command -v objcopy >/dev/null 2>&1 || require_pkgs objcopy:binutils
        _ps_args=''
        for _ps_sec in osrel cmdline linux initrd; do
            if objcopy -O binary --only-section=."$_ps_sec" "$_ps_uki" \
                "$_ps_work/sec-$_ps_sec.bin" 2>/dev/null && [ -s "$_ps_work/sec-$_ps_sec.bin" ]; then
                case $_ps_sec in
                    osrel) _ps_args="$_ps_args --os-release=@$_ps_work/sec-$_ps_sec.bin" ;;
                    cmdline) _ps_args="$_ps_args --cmdline=@$_ps_work/sec-$_ps_sec.bin" ;;
                    linux) _ps_args="$_ps_args --linux=$_ps_work/sec-$_ps_sec.bin" ;;
                    initrd) _ps_args="$_ps_args --initrd=$_ps_work/sec-$_ps_sec.bin" ;;
                esac
            fi
        done
        [ -n "$_ps_args" ] || {
            rm -rf "$_ps_work"
            die "pcrsign: no measurable sections found in UKI: $_ps_uki"
        }
        # S-M3: systemd-stub also measures .ucode/.dtb/.splash/.pcrpkey into
        # PCR 11. If any is present but not extracted above, the prediction
        # would be silently wrong — refuse loudly instead (fail-loud, ADR-8).
        _ps_extra=''
        for _ps_meas in ucode dtb splash pcrpkey; do
            if objcopy -O binary --only-section=."$_ps_meas" "$_ps_uki" \
                "$_ps_work/unmeasured-$_ps_meas.bin" 2>/dev/null &&
                [ -s "$_ps_work/unmeasured-$_ps_meas.bin" ]; then
                _ps_extra="$_ps_extra .$_ps_meas"
            fi
        done
        [ -z "$_ps_extra" ] || {
            rm -rf "$_ps_work"
            die "pcrsign: UKI contains measured sections that pcrsign does not extract:$_ps_extra — the PCR 11 digest would be silently wrong; sign from the component inputs instead (§6.1.1 step 1)"
        }
    else
        [ -f "$_ps_linux" ] || {
            rm -rf "$_ps_work"
            die "pcrsign: --linux component missing: $_ps_linux"
        }
        _ps_args="--linux=$_ps_linux"
        for _ps_pair in "initrd:$_ps_initrd" "cmdline:$_ps_cmdline" "osrelease:$_ps_osrelease"; do
            _ps_name=${_ps_pair%%:*}
            _ps_file=${_ps_pair#*:}
            [ -n "$_ps_file" ] || continue
            [ -f "$_ps_file" ] || {
                rm -rf "$_ps_work"
                die "pcrsign: --$_ps_name component missing: $_ps_file"
            }
            case $_ps_name in
                initrd) _ps_args="$_ps_args --initrd=$_ps_file" ;;
                cmdline) _ps_args="$_ps_args --cmdline=@$_ps_file" ;;
                osrelease) _ps_args="$_ps_args --os-release=@$_ps_file" ;;
            esac
        done
    fi

    # --- key unlock BEFORE the measure step (ukify >= 261 requires a
    # --pcr-private-key for every --phases= specification, even for a pure
    # prediction: "ValueError: --phases= specifications must match
    # --pcr-private-key="). The prediction .hash is key-independent, but the
    # key must be a VALID private key (ukify runs systemd-keyutil on it) — so
    # this is the SAME unlocked release key the signature step uses below
    # (unlocked once, here; registry 2026-09-23: s19/s20 pcrsign-711 died on
    # the ValueError before ever signing).
    _ps_tmp=''
    _ps_keydir=$(keys_dir)
    # ADR-18 + §11 I4: route the private key through the SAME unlock seam as
    # enrl_sign_pcrsig (lib/cmd/enroll-tpm.sh) and the ukictl hook — the keydir
    # release.pem may be the encrypted-at-rest form, and signing with the raw
    # ciphertext would simply fail (or worse, bypass custody). ALPINE_FDE_KEY_
    # PASSPHRASE is the canonical credential-agent env spelling (§8.1); keys_
    # unlock consumes DEBIAN_FDE_KEY_PASSPHRASE (the finalize.sh mapping).
    if [ -z "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ] && [ -n "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
        DEBIAN_FDE_KEY_PASSPHRASE=$ALPINE_FDE_KEY_PASSPHRASE
    fi
    _ps_had_pass=0
    [ -n "${DEBIAN_FDE_KEY_PASSPHRASE:-}" ] && _ps_had_pass=1
    # command substitution: a die inside keys_unlock (missing/wrong passphrase)
    # exits THAT subshell 64 — its stderr is already loud; persist the ADR-8
    # marker, leave NO signature artifact and scrub _ps_work/_ps_tmp (S-L1).
    # The env-provided vs. absent passphrase distinguishes wrong-passphrase
    # from missing-passphrase in the marker.
    _ps_priv=$(keys_unlock "$_ps_keydir") || {
        rm -rf "$_ps_work"
        rm -f "${_ps_tmp:-}"
        if [ "$_ps_had_pass" = 1 ]; then
            _pcrsign_marker_write "release.pem unlock FAILED: wrong passphrase — no signature written (ADR-8/ADR-18/I4)"
            die "pcrsign: wrong passphrase for $_ps_keydir/release.pem (unlock failed) — no signature written (ADR-8/ADR-18)"
        fi
        _pcrsign_marker_write "release.pem is encrypted and no passphrase is available (ADR-18) — no signature written (ADR-8)"
        die "pcrsign: release.pem is encrypted: passphrase required; provide ALPINE_FDE_KEY_PASSPHRASE / DEBIAN_FDE_KEY_PASSPHRASE or run interactively — no signature written (ADR-8/ADR-18)"
    }

    if command -v ukify >/dev/null 2>&1; then
        # shellcheck disable=SC2086  # deliberate word split over the arg list
        if ! ukify build --measure --json=short --pcr-banks=sha256 --phases=enter-initrd \
            --pcr-private-key="$_ps_priv" \
            $_ps_args >"$_ps_work/measure.json" 2>"$_ps_work/measure.err"; then
            _ps_err=$(tail -n 2 "$_ps_work/measure.err" 2>/dev/null || true)
            rm -rf "$_ps_work"
            die "pcrsign: ukify --measure failed: $_ps_err"
        fi
        _ps_d11=$(jq -r '.sha256[] | select(.phase == "enter-initrd") | .hash' "$_ps_work/measure.json" 2>/dev/null || true)
    else
        # systemd-measure fallback (§6.1.1): hex digest on stdout
        # shellcheck disable=SC2086
        if ! systemd-measure calculate --pcr-bank=sha256 --phase=enter-initrd \
            $_ps_args >"$_ps_work/measure.out" 2>"$_ps_work/measure.err"; then
            _ps_err=$(tail -n 2 "$_ps_work/measure.err" 2>/dev/null || true)
            rm -rf "$_ps_work"
            die "pcrsign: systemd-measure calculate failed: $_ps_err"
        fi
        _ps_d11=$(awk '{ v = $NF } END { gsub(/^.*[:=-]/, "", v); print v }' "$_ps_work/measure.out")
    fi
    policy_check_digest "$_ps_d11" || {
        _ps_got=''
        [ -s "$_ps_work/measure.err" ] && _ps_got=$(tail -n 2 "$_ps_work/measure.err")
        rm -rf "$_ps_work"
        die "pcrsign: measurement did not yield an enter-initrd PCR 11 sha256 digest (got '${_ps_d11:-<none>}' $_ps_got)"
    }

    # --- §6.1.1 steps 3–5: combined digest + release-key signature JSON -------------
    _ps_tmp=$(mktemp "${TMPDIR:-/tmp}/debian-fde-pcrsig.XXXXXX") || {
        rm -rf "$_ps_work"
        die "pcrsign: mktemp failed"
    }
    # (_ps_keydir/_ps_priv: unlocked above, before the measure step — ukify >= 261
    # needs a valid --pcr-private-key alongside --phases= even for a prediction)
    # subshell: a die inside policy_sign_json (corrupt key material) must not
    # strand the decrypted key copy (I4) nor _ps_work/_ps_tmp (S-L1)
    if ! (policy_sign_json "$_ps_d7" "$_ps_d11" "$_ps_priv" \
        "$_ps_keydir/release.pub" "$_ps_tmp"); then
        [ "$_ps_priv" != "$_ps_keydir/release.pem" ] && keys_scrub "$_ps_priv"
        rm -rf "$_ps_work"
        rm -f "$_ps_tmp"
        die "pcrsign: policy signature emission failed (keydir: $_ps_keydir)"
    fi
    # I4 hygiene: scrub the DECRYPTED copy only — for a plaintext (offline
    # medium) keydir keys_unlock returned the input path itself
    [ "$_ps_priv" != "$_ps_keydir/release.pem" ] && keys_scrub "$_ps_priv"
    rm -rf "$_ps_work"
    unset DEBIAN_FDE_KEY_PASSPHRASE ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || :

    if [ -n "$_ps_out" ]; then
        # atomic: same-directory temp + rename (S-M1: a slash-less relative
        # --out is a plain filename — its directory is the CWD)
        _ps_outdir=.
        case $_ps_out in
            */*) _ps_outdir=${_ps_out%/*} ;;
        esac
        [ -d "$_ps_outdir" ] || mkdir -p "$_ps_outdir" || {
            rm -f "$_ps_tmp"
            die "pcrsign: cannot create output directory: $_ps_outdir"
        }
        _ps_atom=$(mktemp "${_ps_outdir:-.}/.pcrsign.XXXXXX") || {
            rm -f "$_ps_tmp"
            die "pcrsign: mktemp for output failed"
        }
        cat "$_ps_tmp" >"$_ps_atom" && mv "$_ps_atom" "$_ps_out" || {
            rm -f "$_ps_atom" "$_ps_tmp"
            die "pcrsign: writing output failed: $_ps_out"
        }
        rm -f "$_ps_tmp"
        info "pcrsign: signed combined {7,11} policy digest for PCR11=$_ps_d11 (artifact: $_ps_out)"
    else
        cat "$_ps_tmp"
        rm -f "$_ps_tmp"
        info "pcrsign: signed combined {7,11} policy digest for PCR11=$_ps_d11"
    fi
    exit 0
}

return 0
