#!/bin/sh
# measure.sh — self-contained `systemd-measure sign`/`calculate` replacement for
# the Alpine guest (real-server blocker #16; docs/Architecture.md §6.1/§8.3).
#
# Alpine does NOT package systemd-measure in ANY branch or repo (verified via
# pkgs.alpinelinux.org contents filename-search for v3.24 AND edge — zero hits;
# the only systemd packages are systemd-boot, systemd-efistub, ukify + hooks).
# ukify's find_tool() falls back to the hardcoded /usr/lib/systemd/systemd-measure
# path, so ukify's PCR-signing leg is dead on a stock guest:
#
#   File "/usr/sbin/ukify", line 839, in call_systemd_measure
#   FileNotFoundError: [Errno 21] ... '/usr/lib/systemd/systemd-measure'
#   alpine-fde: error: ukictl build: ukify build failed (kernel 6.18.53-0-lts)
#
# This module reproduces the REAL binary's contract (systemd 261.3 oracle,
# byte-for-byte differential-pinned by tests/integration/measure_shim_oracle.sh)
# for EXACTLY the option surface `ukify build` generates:
#   calculate --json short --linux=… --osrel=… --cmdline=… --initrd=… --uname=…
#             --sbat=… --pcrpkey=… --bank=sha256 --phase=enter-initrd
#   sign      --linux=… … --bank=sha256 --private-key=… --public-key=…
#             --phase=enter-initrd
# Everything else is refused fail-closed (a silent option-ordering guesswork
# bug would mint UKIs whose .pcrsig cannot verify at boot — never acceptable).
#
# Verified algorithm (v261.3 src/measure/measure-tool.c, src/fundamental/uki.c,
# src/shared/tpm2-util.c tpm2_calculate_policy_pcr; ALL steps cross-checked
# against the live oracle, not from memory):
#
#   PCR11 = 32 zero bytes
#   for each supplied UKI section, CANONICAL order (linux osrel cmdline initrd
#     ucode splash dtb uname sbat pcrpkey profile dtbauto hwids efifw — the
#     UnifiedSection enum order; .pcrsig is never measured):
#       empty files are skipped (the stub does so too — measure_kernel `m == 0`)
#       PCR11 = SHA256( PCR11 || SHA256("<section-name-with-dot>\0") )
#       PCR11 = SHA256( PCR11 || SHA256(section content) )       (raw file bytes)
#   for each phase word (phase split at ":"):
#       PCR11 = SHA256( PCR11 || SHA256(word) )                  (no NUL)
#
#   calculate → {"sha256":[{"phase":"enter-initrd","pcr":11,"hash":"<hex>"}]}
#   pol       = SHA256( zero32 || 00 00 01 7f || TPML{11} || SHA256(PCR11) )
#       CC_PolicyPCR = 00 00 01 7f (IS part of the policy hash, TPM 2.0 Part 3)
#       TPML{11}     = 00 00 00 01 00 0b 03 00 08 00 (count=1, sha256,
#                      sizeofSelect=3, PCR 11 = byte1 bit3)
#   pkfp      = SHA256(DER PKCS#1 RSAPublicKey of the public key)
#               (openssl i2d_PublicKey — NOT the SPKI encoding)
#   sig       = RSASSA-PKCS1-v1_5/SHA256 over the RAW 32-byte pol
#               (plain `openssl dgst -sha256 -sign`, deterministic)
#   sign      → {"sha256":[{"pcrs":[11],"pkfp":"<hex>","pol":"<hex>","sig":"<b64>"}]}
#
# ukify (260.2 call_systemd_measure) json.loads() this output per call and
# embeds combine_signatures() of it as the UKI .pcrsig section; systemd-stub
# verifies the same fields at boot. A --public-key that does not match the
# private key is NOT rejected (the oracle signs with the private key and
# fingerprints the given public key verbatim — pinned behavior).
#
# Wiring (lib/cmd/ukictl-build.sh): a REAL systemd-measure (e2e-host/CI shape)
# always wins; only when absent does measure_probe stage an executable
# `systemd-measure` shim next to this module's libs and hand it to ukify via
# --tools=<dir>; neither available → loud fail-closed 64 naming both.
#
# Depends on: lib/common.sh (info/warn/die), openssl, busybox/coreutils
# (cat, mv, head, cut, tr). POSIX sh; no python, no tpm2-tools, no TPM device —
# the whole point is that the signing path is TPM-free.

if [ -n "${ALPINE_FDE_MEASURE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_MEASURE_LOADED=1

# --- constants (marshaled TPM 2.0 structures, sha256 bank, PCR 11) --------------
MEASURE_CC_PCR='0000017f'                  # TPM_CC_PolicyPCR (4-byte big-endian)
MEASURE_TPML_PCR11='00000001000b03000800'  # count=1, sha256, sizeofSelect=3,
                                           # select 00 08 00 (PCR 11 = byte1 bit3)
MEASURE_ZERO32='0000000000000000000000000000000000000000000000000000000000000000'

# --- binary helpers ---------------------------------------------------------------

# measure_hex_to_bin — hex string (stdin, even length, no whitespace) -> raw
# bytes. POSIX awk; LC_ALL=C pins byte semantics (gawk otherwise UTF-8-encodes
# %c > 127 — same shape as policy_hex_to_bin, kept independent so this module
# never pulls the policy/seal machinery into the signing path).
measure_hex_to_bin() {
    LC_ALL=C awk '{
        hex = "0123456789abcdef"
        for (i = 1; i <= length($0); i += 2) {
            hi = index(hex, tolower(substr($0, i, 1))) - 1
            lo = index(hex, tolower(substr($0, i + 1, 1))) - 1
            printf "%c", hi * 16 + lo
        }
    }'
}

# measure_sha256_bin — raw SHA256 of stdin to stdout (binary)
measure_sha256_bin() {
    openssl dgst -sha256 -binary
}

# measure_extend PCRFILE DATAFILE — PCR = SHA256(PCR || DATA), in place
measure_extend() {
    cat "$1" "$2" | measure_sha256_bin >"$1.next" ||
        die "measure: sha256 extend failed (openssl dgst)"
    mv "$1.next" "$1"
}

# measure_extend_section PCRFILE PATH NAME — model measure_kernel for ONE
# section: skip when not supplied; loud 64 when supplied but missing; skip
# empty files (the stub does so too — measure_kernel `m == 0`); extend with
# SHA256("<dotted name>\0") then SHA256(content).
measure_extend_section() {
    _mes_pcr=$1
    _mes_path=$2
    _mes_name=$3
    [ -n "$_mes_path" ] || return 0
    if [ ! -f "$_mes_path" ]; then
        die "measure: section $_mes_name: cannot open '$_mes_path': No such file"
    fi
    [ -s "$_mes_path" ] || return 0
    # the section NAME is hashed WITH its leading dot and its NUL terminator
    # (EVP_Digest(unified_sections[c], strlen + 1)) — differential-pinned
    printf '%s\0' "$_mes_name" | measure_sha256_bin >"$_mes_pcr.in" ||
        die "measure: sha256 of section name failed"
    measure_extend "$_mes_pcr" "$_mes_pcr.in"
    openssl dgst -sha256 -binary -- "$_mes_path" >"$_mes_pcr.in" ||
        die "measure: sha256 of section content failed ($_mes_name)"
    measure_extend "$_mes_pcr" "$_mes_pcr.in"
}

# measure_extend_phase PCRFILE PHASE — model measure_phase: split at ":", extend
# with SHA256(word) per word (no NUL), skipping empty words
measure_extend_phase() {
    _mep_pcr=$1
    _mep_phase=$2
    # the `|| [ -n ... ]` guard: read returns FALSE at EOF-without-newline even
    # though it populated the variable — the last word of an unterminated split
    # must still be measured (the oracle measures EVERY word)
    printf '%s' "$_mep_phase" | tr ':' '\n' |
        while IFS= read -r _mep_word || [ -n "$_mep_word" ]; do
            [ -n "$_mep_word" ] || continue
            printf '%s' "$_mep_word" | measure_sha256_bin >"$_mep_pcr.in" ||
                die "measure: sha256 of phase word failed"
            measure_extend "$_mep_pcr" "$_mep_pcr.in"
        done
}

# measure_sections_value WORKDIR — run the SECTION measurement (kernel
# equivalent); prints nothing, leaves <WORKDIR>/pcrsec.bin holding the expected
# PCR 11 value BEFORE any phase extension (32 raw bytes). Globals in:
# _me_sections_* (paths).
measure_sections_value() {
    _mpv_work=$1
    _mpv_pcr="$_mpv_work/pcrsec.bin"
    printf '%s' "$MEASURE_ZERO32" | measure_hex_to_bin >"$_mpv_pcr" ||
        die "measure: cannot seed the zero PCR state"
    # canonical measurement order = the UnifiedSection enum order
    # (uki.h: PLEASE DO NOT REORDER); .pcrsig is never measured
    measure_extend_section "$_mpv_pcr" "${_me_sections_linux:-}" '.linux'
    measure_extend_section "$_mpv_pcr" "${_me_sections_osrel:-}" '.osrel'
    measure_extend_section "$_mpv_pcr" "${_me_sections_cmdline:-}" '.cmdline'
    measure_extend_section "$_mpv_pcr" "${_me_sections_initrd:-}" '.initrd'
    measure_extend_section "$_mpv_pcr" "${_me_sections_ucode:-}" '.ucode'
    measure_extend_section "$_mpv_pcr" "${_me_sections_splash:-}" '.splash'
    measure_extend_section "$_mpv_pcr" "${_me_sections_dtb:-}" '.dtb'
    measure_extend_section "$_mpv_pcr" "${_me_sections_uname:-}" '.uname'
    measure_extend_section "$_mpv_pcr" "${_me_sections_sbat:-}" '.sbat'
    measure_extend_section "$_mpv_pcr" "${_me_sections_pcrpkey:-}" '.pcrpkey'
    measure_extend_section "$_mpv_pcr" "${_me_sections_profile:-}" '.profile'
    measure_extend_section "$_mpv_pcr" "${_me_sections_dtbauto:-}" '.dtbauto'
    measure_extend_section "$_mpv_pcr" "${_me_sections_hwids:-}" '.hwids'
    measure_extend_section "$_mpv_pcr" "${_me_sections_efifw:-}" '.efifw'
}

# measure_phase_value WORKDIR PHASE — the oracle saves the section value and
# RESTORES it before each phase (pcr_states_save/restore): every phase's
# expected PCR is measured from the SAME post-section state. Prints nothing,
# leaves <WORKDIR>/pcr11.bin holding the per-phase value.
measure_phase_value() {
    _mph_work=$1
    _mph_phase=$2
    cp "$_mph_work/pcrsec.bin" "$_mph_work/pcr11.bin" ||
        die "measure: cannot restore the PCR state"
    measure_extend_phase "$_mph_work/pcr11.bin" "$_mph_phase"
}

# measure_policy WORKDIR — {11} PolicyPCR policy digest over the CURRENT
# <WORKDIR>/pcr11.bin; prints nothing, leaves <WORKDIR>/pol.bin (32 raw bytes):
#
#   pol = SHA256( zero32 || CC_PolicyPCR || TPML{11} || SHA256(PCR11) )
measure_policy() {
    _mpol_work=$1
    {
        printf '%s%s%s' "$MEASURE_ZERO32" "$MEASURE_CC_PCR" "$MEASURE_TPML_PCR11" |
            measure_hex_to_bin
        measure_sha256_bin <"$_mpol_work/pcr11.bin"
    } >"$_mpol_work/pol.in"
    measure_sha256_bin <"$_mpol_work/pol.in" >"$_mpol_work/pol.bin" ||
        die "measure: policy digest failed"
}

# measure_bin_to_hex FILE — print the file's bytes as lowercase hex. The JSON
# "hash"/"pol" fields are hexdumps of the VALUE (sd_json SD_JSON_BUILD_HEX =
# hexmem of the digest bytes), NOT a digest of the file — this distinction is
# exactly what a from-memory reimplementation gets wrong.
measure_bin_to_hex() {
    od -An -v -tx1 -- "$1" | tr -d ' \n'
    printf '\n'
}

# measure_hexdigest FILE — hex sha256 of FILE (lowercase, no decoration); the
# digest is the LAST field regardless of the openssl digest label spelling
measure_hexdigest() {
    openssl dgst -sha256 -hex -- "$1" | awk '{print $NF}'
}

# --- option surface ----------------------------------------------------------------

# _measure_parse VERB ARGV... — strict parser for exactly the surface ukify
# generates. Sets: _me_sections_<name>, _me_banks, _me_phases, _me_priv,
# _me_pub, _me_json ('' | short | pretty). Unknown/unsupported -> loud 64.
_measure_parse() {
    _me_verb=$1
    shift
    _me_sections_linux=''
    _me_sections_osrel=''
    _me_sections_cmdline=''
    _me_sections_initrd=''
    _me_sections_ucode=''
    _me_sections_splash=''
    _me_sections_dtb=''
    _me_sections_uname=''
    _me_sections_sbat=''
    _me_sections_pcrpkey=''
    _me_sections_profile=''
    _me_sections_dtbauto=''
    _me_sections_hwids=''
    _me_sections_efifw=''
    _me_banks=''
    _me_phases=''
    _me_priv=''
    _me_pub=''
    _me_json=''
    _me_opt=''
    while [ $# -gt 0 ]; do
        case $_me_opt in
            --bank | --pcr-bank | --phase | --json | --private-key | --public-key)
                # consume the value of a previous "--opt value" spelling
                case $1 in
                    -*) die "measure: $_me_verb: option $_me_opt requires a value" ;;
                esac
                case $_me_opt in
                    --bank | --pcr-bank) _me_banks="$_me_banks$1
" ;;
                    --phase) _me_phases="$_me_phases$1
" ;;
                    --json) _me_json=$1 ;;
                    --private-key) _me_priv=$1 ;;
                    --public-key) _me_pub=$1 ;;
                esac
                _me_opt=''
                shift
                continue
                ;;
        esac
        case $1 in
            --linux=*) _me_sections_linux=${1#--linux=} ;;
            --osrel=*) _me_sections_osrel=${1#--osrel=} ;;
            --os-release=*) _me_sections_osrel=${1#--os-release=} ;;
            --cmdline=*) _me_sections_cmdline=${1#--cmdline=} ;;
            --initrd=*) _me_sections_initrd=${1#--initrd=} ;;
            --ucode=*) _me_sections_ucode=${1#--ucode=} ;;
            --splash=*) _me_sections_splash=${1#--splash=} ;;
            --dtb=*) _me_sections_dtb=${1#--dtb=} ;;
            --uname=*) _me_sections_uname=${1#--uname=} ;;
            --sbat=*) _me_sections_sbat=${1#--sbat=} ;;
            --pcrpkey=*) _me_sections_pcrpkey=${1#--pcrpkey=} ;;
            --profile=*) _me_sections_profile=${1#--profile=} ;;
            --dtbauto=*) _me_sections_dtbauto=${1#--dtbauto=} ;;
            --hwids=*) _me_sections_hwids=${1#--hwids=} ;;
            --efifw=*) _me_sections_efifw=${1#--efifw=} ;;
            --bank=* | --pcr-bank=*)
                _me_banks="$_me_banks${1#*=}
"
                ;;
            --phase=*) _me_phases="$_me_phases${1#--phase=}
" ;;
            --json=*) _me_json=${1#--json=} ;;
            --json | --bank | --pcr-bank | --phase | --private-key | --public-key)
                _me_opt=$1
                ;;
            --private-key=*) _me_priv=${1#--private-key=} ;;
            --public-key=*) _me_pub=${1#--public-key=} ;;
            --current)
                die "measure: --current needs a TPM/TPM-state sysfs — not supported by the bundled shim (real-server blocker #16)"
                ;;
            -j)
                _me_json=short
                ;;
            *)
                die "measure: $_me_verb: unsupported option or argument: $1 (the shim implements exactly the ukify-generated surface — real-server blocker #16)"
                ;;
        esac
        shift
    done
    [ -n "$_me_opt" ] && die "measure: $_me_verb: option $_me_opt requires a value"
    # the real tool refuses without --linux (measure-tool.c verb_calculate guard)
    [ -n "$_me_sections_linux" ] || die "measure: Either --linux= or --current must be specified, refusing."
    case $_me_verb in
        sign)
            [ -n "$_me_priv" ] ||
                die "measure: No private key specified, use --private-key=."
            ;;
    esac
    # normalize the accumulated value lists (command substitution strips the
    # trailing record separator; inner separators survive for multi-value)
    _me_banks=$(printf '%s' "$_me_banks")
    _me_phases=$(printf '%s' "$_me_phases")
    # bank surface: the product pins sha256 everywhere (--pcr-banks=sha256);
    # anything else would silently change the .pcrsig bank — refuse loudly
    _me_b=${_me_banks:-sha256}
    case $_me_b in
        sha256) : ;;
        *)
            die "measure: unsupported bank(s): $(printf '%s' "$_me_b" | tr '\n' ' ')(the product pins --pcr-banks=sha256)"
            ;;
    esac
    _me_banks=sha256
    # phase default = the tool's own default surface (measure-tool.c): the
    # initrd phases; the product always passes --phase=enter-initrd explicitly
    if [ -z "$_me_phases" ]; then
        _me_phases='enter-initrd
enter:sysroot
enter:machine-id
enter:newroot
leave:final
'
    fi
    return 0
}

# --- verbs --------------------------------------------------------------------------

# fde_measure_main VERB ARGV... — dispatch (used by the staged executable shim)
fde_measure_main() {
    _me_verb=$1
    shift
    case $_me_verb in
        sign) fde_measure_sign "$@" ;;
        calculate | policy-digest) fde_measure_calculate "$@" ;;
        *)
            die "measure: unknown command '$_me_verb' (expected sign or calculate)"
            ;;
    esac
}

# fde_measure_calculate ARGV... — `systemd-measure calculate` for the ukify
# surface: expected PCR 11 value per phase. --json -> short JSON (the only
# spelling ukictl-build's jq parse accepts); no --json -> the human format
# ("11:sha256=<hex>" lines; lib/cmd/pcrsign.sh's awk fallback parses this).
fde_measure_calculate() {
    _measure_parse calculate "$@" || exit "$ALPINE_FDE_FAIL_CLOSED"
    _me_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-measure.XXXXXX") ||
        die "measure: mktemp failed"
    measure_sections_value "$_me_work"
    _me_out=''
    for _me_phase in $_me_phases; do
        measure_phase_value "$_me_work" "$_me_phase"
        _me_hash=$(measure_bin_to_hex "$_me_work/pcr11.bin")
        if [ -n "$_me_json" ]; then
            _me_entry="{"
            if [ -n "$_me_phase" ]; then
                _me_entry="$_me_entry\"phase\":\"$_me_phase\","
            fi
            _me_entry="$_me_entry\"pcr\":11,\"hash\":\"$_me_hash\"}"
            _me_out="$_me_out,$_me_entry"
        else
            if [ -z "$_me_out" ]; then
                printf '%s\n' "# PCR[11] Phase <${_me_phase:-:}>" >&2
            fi
            printf '11:sha256=%s\n' "$_me_hash"
        fi
    done
    rm -rf "$_me_work"
    if [ -n "$_me_json" ]; then
        printf '{"sha256":[%s]}\n' "${_me_out#,}"
    fi
    return 0
}

# fde_measure_sign ARGV... — `systemd-measure sign` for the ukify surface:
# RSASSA-PKCS1-v1_5/SHA256 signature over the {11} PolicyPCR policy digest,
# emitted in the exact short-JSON shape the oracle (and therefore ukify 260.2's
# combine_signatures + systemd-stub's verifier) consumes:
#   {"sha256":[{"pcrs":[11],"pkfp":"<hex>","pol":"<hex>","sig":"<b64>"}]}
fde_measure_sign() {
    _measure_parse sign "$@" || exit "$ALPINE_FDE_FAIL_CLOSED"
    _me_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-measure.XXXXXX") ||
        die "measure: mktemp failed"
    measure_sections_value "$_me_work"

    # pkfp = SHA256(DER PKCS#1 RSAPublicKey) of --public-key, else of the key
    # derived from --private-key (measure-tool.c: derive when none given)
    if [ -n "$_me_pub" ]; then
        _me_fp_key="$_me_pub"
        _me_fp_args="-pubin"
    else
        _me_fp_key="$_me_priv"
        _me_fp_args=''
    fi
    _me_pkfp=$(openssl rsa $_me_fp_args -in "$_me_fp_key" -RSAPublicKey_out \
        -outform DER 2>/dev/null |
        openssl dgst -sha256 -hex | awk '{print $NF}')
    [ -n "$_me_pkfp" ] || die "measure: cannot fingerprint the public key ($_me_fp_key)"

    _me_out=''
    for _me_phase in $_me_phases; do
        measure_phase_value "$_me_work" "$_me_phase"
        measure_policy "$_me_work"
        _me_pol=$(measure_bin_to_hex "$_me_work/pol.bin")
        # sig = RSASSA-PKCS1-v1_5/SHA256 over the RAW 32-byte pol (deterministic —
        # this is what makes byte-for-byte oracle parity achievable at all)
        _me_sig=$(openssl dgst -sha256 -sign "$_me_priv" "$_me_work/pol.bin" |
            openssl base64 -A) || die "measure: RSA sign failed (openssl dgst -sign)"
        if [ -z "$_me_sig" ]; then
            die "measure: RSA sign produced no signature"
        fi
        _me_entry="{\"pcrs\":[11],\"pkfp\":\"$_me_pkfp\","
        _me_entry="$_me_entry\"pol\":\"$_me_pol\",\"sig\":\"$_me_sig\"}"
        _me_out="$_me_out,$_me_entry"
    done
    rm -rf "$_me_work"
    printf '{"sha256":[%s]}\n' "${_me_out#,}"
    return 0
}

# --- wiring probe --------------------------------------------------------------------

# measure_system_bin — print the system systemd-measure candidate path, or
# nothing. ALPINE_FDE_MEASURE_BIN is the test seam (mirrors INITRAMFS_CMD):
# when SET — even empty — it REPLACES the probe entirely (empty = simulate
# absence, so the shim path is exercisable on hosts that carry a real binary).
# Unset: ukify's own find_tool order — `command -v`, then the hardcoded
# /usr/lib/systemd/systemd-measure fallback.
measure_system_bin() {
    if [ "${ALPINE_FDE_MEASURE_BIN+set}" = set ]; then
        [ -n "$ALPINE_FDE_MEASURE_BIN" ] && [ -x "$ALPINE_FDE_MEASURE_BIN" ] &&
            printf '%s\n' "$ALPINE_FDE_MEASURE_BIN"
        return 0
    fi
    _msb=$(command -v systemd-measure 2>/dev/null || true)
    if [ -z "$_msb" ]; then
        [ -x /usr/lib/systemd/systemd-measure ] && _msb=/usr/lib/systemd/systemd-measure
    fi
    [ -n "$_msb" ] && printf '%s\n' "$_msb"
    return 0
}

# measure_lib_candidates — newline list of measure.sh locations to probe
# (CLI context first, then the installed guest tree — same shape as keys.sh)
measure_lib_candidates() {
    if [ -n "${ALPINE_FDE_CMD_DIR:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_CMD_DIR/../measure.sh"
    fi
    printf '%s\n' /opt/alpine-fde/lib/measure.sh
}

# measure_stage_shim STAGING_DIR MEASURE_SH — write the executable
# `systemd-measure` shim ukify will find via --tools=<STAGING_DIR>
measure_stage_shim() {
    _mss_dir=$1
    _mss_sh=$2
    mkdir -p "$_mss_dir" || die "measure: cannot create the shim staging dir $_mss_dir"
    _mss_lib=$(CDPATH='' cd -- "$(dirname -- "$_mss_sh")" && pwd) ||
        die "measure: cannot resolve the measure.sh directory"
    cat >"$_mss_dir/systemd-measure" <<EOF
#!/bin/sh
# systemd-measure shim staged by alpine-fde ukictl build (real-server blocker
# #16: Alpine ships no systemd-measure package). Dispatches to the bundled
# POSIX sh + openssl implementation; differential-pinned byte-for-byte against
# the real systemd-measure by tests/integration/measure_shim_oracle.sh.
. '$_mss_lib/common.sh' || exit 64
. '$_mss_lib/measure.sh' || exit 64
fde_measure_main "\$@"
EOF
    chmod 755 "$_mss_dir/systemd-measure" ||
        die "measure: cannot chmod the staged shim"
    return 0
}

# measure_probe STAGING_DIR — resolve the measure implementation ukify will use.
#   1. a REAL systemd-measure (system/seam probe) wins — prints nothing, the
#      caller leaves ukify on its own find_tool path (e2e-host/CI shape);
#   2. else the bundled lib/measure.sh — stages the shim and prints
#      "--tools=<STAGING_DIR>" for the ukify argv;
#   3. else loud fail-closed 64 NAMING BOTH candidates (never a silent fall-
#      through into ukify's FileNotFoundError — that is the blocker-#16 crash).
measure_probe() {
    _mpr_dir=$1
    if [ -n "$(measure_system_bin)" ]; then
        info "ukictl build: PCR signing via system systemd-measure ($(measure_system_bin))"
        return 0
    fi
    for _mpr_sh in $(measure_lib_candidates); do
        [ -f "$_mpr_sh" ] || continue
        measure_stage_shim "$_mpr_dir" "$_mpr_sh"
        info "ukictl build: no system systemd-measure — PCR signing via the bundled shim ($_mpr_sh, --tools=$_mpr_dir)"
        printf '%s\n' "--tools=$_mpr_dir"
        return 0
    done
    die "ukictl build: no PCR-signing implementation available: probed the system systemd-measure (command -v, ALPINE_FDE_MEASURE_BIN, /usr/lib/systemd/systemd-measure) AND the bundled lib/measure.sh (ALPINE_FDE_CMD_DIR, /opt/alpine-fde/lib) — Alpine ships no systemd-measure package (real-server blocker #16), so the bundled shim is the only guest-side implementation; repair the alpine-fde install tree"
}

# --- product-wide resolution (real-server blocker #17) ------------------------------

# measure_stage_root — the STABLE staged-shim location. The ukictl workdir
# tools dir dies with the workdir; every other consumer (seal.sh's G-B6
# recomputation) must resolve the SAME implementation from a stable path.
# ALPINE_FDE_MEASURE_STAGE wins when set (test seam).
measure_stage_root() {
    printf '%s\n' "${ALPINE_FDE_MEASURE_STAGE:-/opt/alpine-fde/.measure-tools}"
}

# measure_resolve [STAGING_DIR] — THE product-wide entry point: print the
# path of the measure implementation (real binary, else the staged shim);
# loud fail-closed 64 naming both candidates when neither exists. Every
# consumer routes through here — never probe independently.
measure_resolve() {
    _mrv_dir=${1:-$(measure_stage_root)}
    if [ -n "$(measure_system_bin)" ]; then
        measure_system_bin
        return 0
    fi
    for _mrv_sh in $(measure_lib_candidates); do
        [ -f "$_mrv_sh" ] || continue
        measure_stage_shim "$_mrv_dir" "$_mrv_sh"
        printf '%s\n' "$_mrv_dir/systemd-measure"
        return 0
    done
    die "measure: no PCR-signing implementation available: probed the system systemd-measure (command -v, ALPINE_FDE_MEASURE_BIN, /usr/lib/systemd/systemd-measure) AND the bundled lib/measure.sh (ALPINE_FDE_CMD_DIR, /opt/alpine-fde/lib) — Alpine ships no systemd-measure package (real-server blocker #16); repair the alpine-fde install tree"
}

# measure_tools_arg IMPL_PATH — the ukify argv addition for IMPL_PATH: empty
# for the system binary (ukify's own find_tool finds it), --tools=<dir> for a
# staged shim (ukify must not fall through to the hardcoded path).
measure_tools_arg() {
    case $1 in
        */.measure-tools/* | */tools/*)
            printf '%s\n' "--tools=$(dirname -- "$1")"
            ;;
        *)
            : # system binary — no argv addition
            ;;
    esac
}

# measure_pcr11_from_uki UKI — recompute the expected enter-initrd PCR 11
# value from a BUILT UKI: extract every measured section with objcopy (the
# same faithful extraction lib/cmd/pcrsign.sh's --uki path is pinned on) and
# run the oracle-verified measurement math over them in canonical order.
# Prints the 64-hex digest; dies 64 loud+specific when it cannot run. This is
# the G-B6 recomputation source for anchor-less .pcrsig entries built by the
# shim (real-server blocker #17): the seal must never confuse "cannot
# recompute" with "stale/tampered".
measure_pcr11_from_uki() {
    [ $# -eq 1 ] || die "measure_pcr11_from_uki: usage: measure_pcr11_from_uki <uki>"
    _mpu_uki=$1
    [ -f "$_mpu_uki" ] || die "measure_pcr11_from_uki: UKI not found: $_mpu_uki"
    command -v objcopy >/dev/null 2>&1 ||
        die "measure_pcr11_from_uki: objcopy not found (binutils) — cannot recompute the anchored PCR-11 digest from the UKI"
    command -v measure_sha256_bin >/dev/null 2>&1 ||
        die "measure_pcr11_from_uki: measure implementation not loaded (lib/measure.sh missing) — cannot recompute the anchored PCR-11 digest"
    _mpu_work=$(mktemp -d "${TMPDIR:-/tmp}/alpine-fde-measure-uki.XXXXXX") ||
        die "measure_pcr11_from_uki: mktemp failed"
    _mpu_supplied=0
    for _mpu_sec in linux osrel cmdline initrd ucode splash dtb uname sbat pcrpkey profile dtbauto hwids efifw; do
        _mpu_out="$_mpu_work/$_mpu_sec"
        # absent sections fail objcopy — skipped, exactly like the builder's
        # measure pass skipped sections it was never given
        if objcopy -O binary --only-section=".$_mpu_sec" -- "$_mpu_uki" "$_mpu_out" 2>/dev/null && [ -s "$_mpu_out" ]; then
            eval "_me_sections_$_mpu_sec=\$_mpu_out"
            _mpu_supplied=1
        else
            rm -f "$_mpu_out"
        fi
    done
    if [ "$_mpu_supplied" -eq 0 ]; then
        rm -rf "$_mpu_work"
        die "measure_pcr11_from_uki: no measured sections found in $_mpu_uki (not a UKI?) — cannot recompute the anchored PCR-11 digest"
    fi
    _me_phases='enter-initrd'
    measure_sections_value "$_mpu_work"
    measure_phase_value "$_mpu_work" enter-initrd
    measure_bin_to_hex "$_mpu_work/pcr11.bin"
    rm -rf "$_mpu_work"
    return 0
}
