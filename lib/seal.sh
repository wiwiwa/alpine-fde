#!/bin/sh
# seal.sh — Mechanism B sealing (docs/Architecture.md §6.1/§7.1/§9.1 step 6;
# ADR-19/ADR-20; G-B3). Alpine-normative seal path: tpm2-tools only, no
# systemd-cryptenroll (not packaged on Alpine, ADR-19).
#
# Policy construction (§6.1.1 — the pcrsign_policyauthorize_accept.sh chain,
# reproduced programmatically):
#   keyName          = keys_keyname_verifying(release.pub)   (VERIFYING area —
#                      the area that verifies at session time; §6.1.1 step 4b)
#   sealed digest    = policy_sealed_digest(keyName)          (PINNED double
#                      hash; the tpm2_create -L argument — identical for both
#                      modes; the MODE decides which approved policy the
#                      session's PolicyAuthorize checks)
#   approved digest:
#     provisional    = seal_digest_11(d11_live)   — the PCR-11-only selection
#                      digest the UKI's .pcrsig signs (ADR-20 Stage-1 token)
#     finalized      = policy_digest(d7, d11) — the combined {7,11}
#                      construction over the entry's DIGEST-ANCHORED
#                      components (Option A): the entry records the `d7`/`d11`
#                      the composing flow signed it over (d7 = the
#                      console-measured PCR 7 stamped into the baseline, d11 =
#                      the build's enter-initrd prediction) and the seal-time
#                      G-B6 gate recomputes the policy digest from THOSE — no
#                      live TPM read. Entries predating the anchor fields fall
#                      back to the live-PCR oracle (the production advisory
#                      path). PolicyPCR embeds the provided digests into the
#                      policy structure; the TPM evaluates them only at
#                      UNSEAL, against the guest's firmware-measured PCRs —
#                      fail-at-unseal replaces fail-at-seal, the cryptographic
#                      enforcement is unchanged.
#   The .pcrsig is verified BEFORE anything is embedded or staged (G-B6): the
#   entry selected by its pcrs field must exist, its signature must verify
#   openssl-level over the embedded `pol` bytes against keydir/release.pub,
#   and `pol` must equal the freshly computed digest over the anchored (or,
#   legacy, live) PCR digest components.
#
# SRK (§7.1): `tpm2 createprimary -C o -g sha256 -G rsa` — the tpm2-tools
# DEFAULT owner-hierarchy primary template (restricted|decrypt|fixedTPM|
# fixedParent|sensitiveDataOrigin|userWithAuth, sha256, RSA with NULL
# scheme/symmetric default), i.e. the TCG Storage Root Key profile. The
# template is deterministic: re-running the command reproduces the same
# primary on an untouched TPM (verified on swtpm: identical readpublic Name).
#
# Random volume passphrase (I1): 48 random raw bytes (384-bit entropy) staged
# BASE64-FRAMED at $(seal_stage_dir)/alpine-fde-seal-pass.XXXXXX — i.e. ALWAYS
# under the tmpfs root ${ALPINE_FDE_TMPDIR:-/dev/shm}, never /tmp — mode 600.
# FRAMING (ADR-19): the LUKS2 credential is base64(unsealed secret) — upstream
# systemd's token plugin base64-encodes the TPM-unsealed bytes before using
# them as the passphrase. The staged file IS that credential; the RAW bytes
# are what seal_create feeds to tpm2_create -i (decoded inside the work dir)
# and what the TPM yields at unseal (seal_unseal re-encodes). Callers scrub
# via seal_scrub, which zeroizes + unlinks the passphrase and removes the
# work dir.
#
# tpm2 object-context discipline: swtpm/libtpms exposes ~2 transient object
# slots, and context files are SAVED contexts (each tool invocation re-loads
# them). Every helper below therefore flushes its own contexts and never holds
# more than two objects; seal_unseal flushes ALL transients between `tpm2 load`
# and the policy session so the final ContextLoad has a free slot (the exact
# pattern proven by tests/unit/pcrsign_policyauthorize_accept.sh).
#
# Globals set on success (enroll ops): SEAL_MODE, SEAL_SLOT, SEAL_PASS_FILE,
# SEAL_POL (approved digest hex), SEAL_KEYNAME (hex), SEAL_TOKEN_FILE,
# SEAL_WORK_DIR (the staging dir holding the blob halves — scrub both with
# seal_scrub once the choreography no longer needs them).
#
# Depends on: lib/common.sh, lib/policy.sh, lib/keys.sh, lib/token.sh,
# openssl, tpm2-tools via the tpm() TCTI wrapper.

if [ -n "${ALPINE_FDE_SEAL_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_SEAL_LOADED=1

_sl_cmd_dir=${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_sl_lib_dir=${_sl_cmd_dir%/*}
if [ -z "${ALPINE_FDE_COMMON_LOADED:-}" ]; then
    if [ -r "$_sl_lib_dir/common.sh" ]; then
        # shellcheck disable=SC1090
        . "$_sl_lib_dir/common.sh"
    fi
fi
if [ -z "${ALPINE_FDE_POLICY_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "$_sl_lib_dir/policy.sh"
fi
if [ -z "${ALPINE_FDE_KEYS_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "$_sl_lib_dir/keys.sh"
fi
if [ -z "${ALPINE_FDE_TOKEN_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "$_sl_lib_dir/token.sh"
fi

# --- constants (marshaled TPM 2.0 structures, sha256 bank) ----------------------
# TPML_PCR_SELECTION for PCR 11 only: count=1, alg sha256(000b),
# sizeofSelect=3, select bytes 00 08 00 (byte 1, bit 3).
SEAL_CC_PCR='0000017f'
SEAL_TPML_11='00000001000b03000800'

# seal_digest_11 <d11hex> — the {11}-only PolicyPCR trial digest:
#   SHA256( zero32 || CC_PolicyPCR || TPML{11} || SHA256(d11_raw) )
# Cross-checked against a live TPM trial session by
# tests/unit/seal_mechanism_b.sh (the normative oracle).
seal_digest_11() {
    case ${1:-} in
        '' | *[!0-9a-fA-F]*)
            die "seal_digest_11: PCR 11 digest is not a sha256 hex digest: '${1:-}'" ;;
    esac
    [ ${#1} -eq 64 ] || die "seal_digest_11: PCR 11 digest is not 64 hex chars: $1"
    _sd11_pcrd=$(printf '%s' "$1" | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')
    printf '%s%s%s%s' "$POLICY_ZERO32" "$SEAL_CC_PCR" "$SEAL_TPML_11" "$_sd11_pcrd" |
        policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}'
}

# seal_stage_dir — the I1 staging root. ALWAYS tmpfs: ${ALPINE_FDE_TMPDIR:-/dev/shm}
# (the repo-wide tmpfs seam convention; rotate.sh/keys.sh/finalize.sh agree).
# NEVER default to /tmp: every staging site below may hold the RANDOM VOLUME
# PASSPHRASE or key material in flight (§11 I1 — no plaintext secret on a
# persistent filesystem), and /tmp is not guaranteed to be a tmpfs. ALPINE_FDE_TMPDIR
# (tests / exotic setups) wins; /dev/shm is the fail-safe default.
seal_stage_dir() {
    printf '%s\n' "${ALPINE_FDE_TMPDIR:-/dev/shm}"
}

# seal_pcrread <idx> — live sha256 PCR digest as bare lowercase hex (the -o +
# od form: format-independent, unlike pcrread's aligned text output).
seal_pcrread() {
    [ $# -eq 1 ] || die "seal_pcrread: usage: seal_pcrread <idx>"
    _spr_f=$(mktemp "$(seal_stage_dir)/alpine-fde-seal-pcr.XXXXXX") || die "seal: mktemp failed"
    if ! tpm pcrread -Q -o "$_spr_f" "sha256:$1" >/dev/null 2>&1; then
        rm -f "$_spr_f"
        die "seal: cannot read live PCR $1 (TCTI: ${ALPINE_FDE_TCTI:-<default>})"
    fi
    _spr_hex=$(od -An -v -tx1 "$_spr_f" | tr -d ' \n')
    rm -f "$_spr_f"
    printf '%s\n' "$_spr_hex"
}

# seal_require_env — tpm2 tools present AND the configured TCTI answers (the
# §6.1 preconditions; fail-closed 64).
seal_require_env() {
    command -v tpm2 >/dev/null 2>&1 ||
        die "seal: tpm2-tools not found (tpm2 binary) — Mechanism B sealing requires tpm2-tools"
    if ! tpm getcap properties-fixed >/dev/null 2>&1; then
        die "seal: no usable TPM via TCTI '${ALPINE_FDE_TCTI:-<default>}' — cannot seal"
    fi
}

# seal_keydir_check <keydir> — the keydir exists and holds release.pub (the
# policy anchor; release.pem is NOT needed on the seal path — the .pcrsig is
# signed upstream by pcrsign/ukify).
seal_keydir_check() {
    [ -n "$1" ] || die "seal: no release key directory configured (KEYDIR)"
    [ -d "$1" ] || die "seal: release key directory not found: $1"
    [ -f "$1/release.pub" ] || die "seal: release public key not found: $1/release.pub"
}

# seal_pcrsig_field <pcrsig.json> <pcrs_csv> <field> — extract <field> of the
# .pcrsig entry whose pcrs list matches (e.g. "11" or "7,11"). Empty output =
# no matching entry (wrong selection).
seal_pcrsig_field() {
    jq -r --arg sel "$2" --arg f "$3" \
        'first(.sha256 // [] | .[] | select((.pcrs | join(",")) == $sel) | .[$f]) // empty' \
        "$1" 2>/dev/null
}

# seal_verify_pcrsig <keydir> <pcrsig.json> <pcrs_csv> <expected_digest> — the
# G-B6 gate. Sets SEAL_SIG_B64 and SEAL_POL on success; dies 64 (before ANY
# embedding or staging) on:
#   * no .pcrsig entry for the expected selection (wrong-selection signature)
#   * the signature does not verify over the embedded pol bytes (tampered or
#     foreign-key signature — openssl-level per the swtpm-leniency caveat)
#   * pol != the expected digest (tampered/stale; the caller computes it over
#     the entry's anchored d7/d11 components — or, legacy entries, the live
#     PCRs)
seal_verify_pcrsig() {
    [ $# -eq 4 ] || die "seal_verify_pcrsig: usage: <keydir> <pcrsig> <pcrs_csv> <fresh>"
    _svp_keydir=$1 _svp_sig=$2 _svp_sel=$3 _svp_fresh=$4
    _svp_pol=$(seal_pcrsig_field "$_svp_sig" "$_svp_sel" pol)
    if [ -z "$_svp_pol" ]; then
        die "seal: the .pcrsig carries no pcrs=[$_svp_sel] entry — wrong-selection signature for this mode (refusing to embed)"
    fi
    _svp_sigb64=$(seal_pcrsig_field "$_svp_sig" "$_svp_sel" sig)
    [ -n "$_svp_sigb64" ] ||
        die "seal: the .pcrsig [$_svp_sel] entry carries no signature"
    _svp_work=$(mktemp -d "$(seal_stage_dir)/alpine-fde-seal-verify.XXXXXX") ||
        die "seal: mktemp failed"
    chmod 700 "$_svp_work"
    printf '%s' "$_svp_pol" | policy_hex_to_bin >"$_svp_work/pol.bin"
    printf '%s' "$_svp_sigb64" | openssl base64 -d -A >"$_svp_work/sig.bin" 2>/dev/null
    if ! openssl dgst -sha256 -verify "$_svp_keydir/release.pub" \
        -signature "$_svp_work/sig.bin" "$_svp_work/pol.bin" >/dev/null 2>&1; then
        rm -rf "$_svp_work"
        die "seal: the .pcrsig signature does NOT verify against the release public key (tampered or foreign-key signature) — refusing to embed"
    fi
    rm -rf "$_svp_work"
    if [ "$_svp_pol" != "$_svp_fresh" ]; then
        die "seal: the .pcrsig policy digest is stale/tampered: signed $_svp_pol != computed $_svp_fresh over the anchored digest components — refusing to embed"
    fi
    SEAL_POL=$_svp_pol
    SEAL_SIG_B64=$_svp_sigb64
    return 0
}

# seal_gen_passphrase — stage the random volume passphrase (I1) under
# ${ALPINE_FDE_SEAL_STAGE:-$(seal_stage_dir)}, mode 600.
# FRAMING (ADR-19): the staged file is base64(48 random raw bytes) — 64
# canonical base64 chars, no padding, no trailing newline (384-bit secret).
# Upstream systemd's TPM2 token plugin base64-encodes the unsealed secret
# before handing it to cryptsetup as the LUKS2 passphrase ("Before using this
# key as passphrase we base64 encode it, for compat with homed"), so the
# keyslot credential AND this staged file must be in exactly that form; the
# RAW bytes go into the TPM sealed object only (seal_create decodes).
# BYTE-EXACT: no trailing newline — every consumer (luksAddKey --key-file,
# the mkinitfs hook's stdin feed) must see identical bytes.
# ALPINE_FDE_SEAL_STAGE (enroll-tpm's choreography staging dir) wins when set
# so the whole staging tree is scrubbed with one rm by the caller; the default
# is the seal_stage_dir tmpfs root — NEVER /tmp (I1).
seal_gen_passphrase() {
    _sgp_dir=${ALPINE_FDE_SEAL_STAGE:-$(seal_stage_dir)}
    SEAL_PASS_FILE=$(mktemp "$_sgp_dir/alpine-fde-seal-pass.XXXXXX") ||
        die "seal: cannot stage the volume passphrase ($_sgp_dir usable?)"
    chmod 600 "$SEAL_PASS_FILE"
    if ! openssl rand 48 | openssl base64 -A >"$SEAL_PASS_FILE"; then
        keys_scrub "$SEAL_PASS_FILE"
        die "seal: generating the random volume passphrase failed"
    fi
    [ "$(wc -c <"$SEAL_PASS_FILE")" -eq 64 ] || {
        keys_scrub "$SEAL_PASS_FILE"
        die "seal: staged passphrase has unexpected length — refusing"
    }
    return 0
}

# seal_scrub [DIR...] — the seal-owned I1 staging scrub (invariant (c)):
# ZEROIZE then unlink the staged random volume passphrase (SEAL_PASS_FILE,
# via keys_scrub's dd-zeroize + rm) and remove the seal work dir
# (SEAL_WORK_DIR, holding the blob halves), plus any extra directories given.
# Idempotent and best-effort — safe as a trap handler and on success AND
# failure paths; never fails the caller (strict-mode safe).
seal_scrub() {
    if [ -n "${SEAL_PASS_FILE:-}" ]; then
        keys_scrub "$SEAL_PASS_FILE"
    fi
    SEAL_PASS_FILE=''
    if [ -n "${SEAL_WORK_DIR:-}" ] && [ -d "$SEAL_WORK_DIR" ]; then
        rm -rf "$SEAL_WORK_DIR"
    fi
    SEAL_WORK_DIR=''
    for _ss_d in "$@"; do
        if [ -n "$_ss_d" ] && [ -d "$_ss_d" ]; then
            rm -rf "$_ss_d"
        fi
    done
    return 0
}

# seal_blob_pack <priv> <pub> — base64(priv || pub) on stdout: the exact
# systemd tpm2-blob encoding.
seal_blob_pack() {
    cat "$1" "$2" | openssl base64 -A
}

# seal_blob_split <priv_out> <pub_out> — split a packed tpm2-blob (stdin,
# base64) into its TPM2B halves. The private half KEEPS its 2-byte length
# prefix (tpm2_load -r consumes the TPM2B form — the prefix is what declares
# the structure size).
seal_blob_split() {
    _sbs_priv=$1 _sbs_pub=$2
    _sbs_tmp=$(mktemp "$(seal_stage_dir)/alpine-fde-seal-blob.XXXXXX") || die "seal: mktemp failed"
    openssl base64 -d -A >"$_sbs_tmp"
    _sbs_plen=$((0x$(xxd -p -l 2 "$_sbs_tmp")))
    dd if="$_sbs_tmp" of="$_sbs_priv" bs=1 count=$((2 + _sbs_plen)) status=none
    dd if="$_sbs_tmp" of="$_sbs_pub" bs=1 skip=$((2 + _sbs_plen)) status=none
    rm -f "$_sbs_tmp"
}

# seal_create <workdir> <pass_file> <sealed_hex> — seal the passphrase under
# the SRK: primary (pinned template) + tpm2_create -L <sealed digest>. The
# blob halves land in <workdir>/seal.priv and <workdir>/seal.pub. <pass_file>
# carries the base64-framed passphrase (ADR-19); the RAW secret bytes are
# decoded into the work dir (scrubbed with it) and fed to tpm2_create -i —
# the TPM seals the raw secret, every LUKS-facing consumer sees base64(raw).
seal_create() {
    [ $# -eq 3 ] || die "seal_create: usage: <workdir> <pass_file> <sealed_hex>"
    _sc_w=$1 _sc_pass=$2 _sc_sealed=$3
    if ! openssl base64 -d -A -in "$_sc_pass" >"$_sc_w/secret.bin" 2>/dev/null ||
        [ "$(wc -c <"$_sc_w/secret.bin")" -ne 48 ]; then
        seal_scrub "$_sc_w" # I1: zeroize the staged passphrase, drop the work dir
        die "seal: staged passphrase is not 64-char base64 of 48 raw bytes — refusing"
    fi
    if ! tpm createprimary -C o -g sha256 -G rsa -c "$_sc_w/primary.ctx" >/dev/null 2>&1; then
        seal_scrub "$_sc_w" # I1: zeroize the staged passphrase, drop the work dir
        die "seal: tpm2_createprimary failed (SRK; TCTI: ${ALPINE_FDE_TCTI:-default})"
    fi
    if ! tpm create -C "$_sc_w/primary.ctx" -g sha256 -i "$_sc_w/secret.bin" \
        -L "$_sc_sealed" -u "$_sc_w/seal.pub" -r "$_sc_w/seal.priv" >/dev/null 2>&1; then
        tpm flushcontext -t >/dev/null 2>&1 || true
        seal_scrub "$_sc_w" # I1: zeroize the staged passphrase, drop the work dir
        die "seal: tpm2_create failed — could not seal the volume passphrase under the SRK policy"
    fi
    tpm flushcontext -t >/dev/null 2>&1 || true
    if [ ! -s "$_sc_w/seal.priv" ] || [ ! -s "$_sc_w/seal.pub" ]; then
        seal_scrub "$_sc_w" # I1
        die "seal: tpm2_create produced an empty blob — refusing"
    fi
    return 0
}

# seal_unseal <keydir> <pcrsig.json> <mode> <token_json> <out_file> — unseal
# the token's blob under a policy session over the LIVE PCRs with the .pcrsig
# signature. rc 0 and the base64-framed passphrase (base64 of the raw unsealed
# secret — the LUKS2 keyslot credential, ADR-19 framing) in <out_file> on
# success; nonzero (loud die for verify failures) on any refusal. Also the
# oracle path for the ADR-20 Stage-3 upgrade choreography.
seal_unseal() {
    [ $# -eq 5 ] || die "seal_unseal: usage: <keydir> <pcrsig> <mode> <token_json> <out_file>"
    _su_keydir=$1 _su_sig=$2 _su_mode=$3 _su_tok=$4 _su_out=$5
    case $_su_mode in
        provisional) _su_sel=11 ;;
        finalized) _su_sel=7,11 ;;
        *) die "seal_unseal: unknown mode '$_su_mode' (provisional|finalized)" ;;
    esac
    seal_require_env
    _su_d11=$(seal_pcrread 11)
    if [ "$_su_mode" = finalized ]; then
        _su_d7=$(seal_pcrread 7)
        _su_fresh=$(policy_digest "$_su_d7" "$_su_d11")
    else
        _su_fresh=$(seal_digest_11 "$_su_d11")
    fi
    # the approved policy must be release-key-signed AND match the live PCRs
    seal_verify_pcrsig "$_su_keydir" "$_su_sig" "$_su_sel" "$_su_fresh"
    _su_w=$(mktemp -d "$(seal_stage_dir)/alpine-fde-seal-unseal.XXXXXX") ||
        die "seal: mktemp failed"
    chmod 700 "$_su_w"
    keys_keyname_verifying "$_su_keydir/release.pub" "$_su_w/name.hex"
    _su_name_hex=$(tr -d ' \n' <"$_su_w/name.hex")
    printf '%s' "$_su_name_hex" | policy_hex_to_bin >"$_su_w/name.bin"
    printf '%s' "$SEAL_SIG_B64" | openssl base64 -d -A >"$_su_w/sig.bin"
    printf '%s' "$SEAL_POL" | policy_hex_to_bin >"$_su_w/msg.bin"
    jq -r '.["tpm2-blob"] // empty' "$_su_tok" | seal_blob_split "$_su_w/priv.bin" "$_su_w/pub.bin"
    if [ ! -s "$_su_w/priv.bin" ] || [ ! -s "$_su_w/pub.bin" ]; then
        rm -rf "$_su_w"
        die "seal_unseal: the token carries no tpm2-blob"
    fi
    # ticket: verify-key loaded ALONE (2-slot budget), then flush
    if ! tpm loadexternal -C o -G rsa -u "$_su_keydir/release.pub" -c "$_su_w/ro.ctx" >/dev/null 2>&1 ||
        ! tpm verifysignature -c "$_su_w/ro.ctx" -m "$_su_w/msg.bin" -s "$_su_w/sig.bin" \
            -f rsassa -g sha256 -t "$_su_w/ticket.bin" >/dev/null 2>&1; then
        tpm flushcontext -t >/dev/null 2>&1 || true
        rm -rf "$_su_w"
        die "seal_unseal: TPM2_VerifySignature refused the .pcrsig signature"
    fi
    tpm flushcontext -t >/dev/null 2>&1 || true
    # reload the sealed object, then flush ALL transients: the saved context
    # re-loads into the freed slot at unseal time (object-budget discipline)
    if ! tpm createprimary -C o -g sha256 -G rsa -c "$_su_w/primary.ctx" >/dev/null 2>&1 ||
        ! tpm load -C "$_su_w/primary.ctx" -u "$_su_w/pub.bin" -r "$_su_w/priv.bin" \
            -c "$_su_w/seal.ctx" >/dev/null 2>&1; then
        tpm flushcontext -t >/dev/null 2>&1 || true
        rm -rf "$_su_w"
        die "seal_unseal: tpm2_load refused the sealed blob (wrong TPM or corrupt token?)"
    fi
    tpm flushcontext -t >/dev/null 2>&1 || true
    _su_rc=0
    tpm startauthsession --policy-session -S "$_su_w/sess.ctx" >/dev/null 2>&1 &&
        tpm policypcr -S "$_su_w/sess.ctx" -l "sha256:$_su_sel" >/dev/null 2>&1 &&
        tpm policyauthorize -S "$_su_w/sess.ctx" -i "$_su_w/msg.bin" \
            -n "$_su_w/name.bin" -t "$_su_w/ticket.bin" >/dev/null 2>&1 &&
        tpm unseal -c "$_su_w/seal.ctx" -p "session:$_su_w/sess.ctx" \
            -o "$_su_w/secret.raw" >/dev/null 2>&1 ||
        _su_rc=1
    # FRAMING (ADR-19): the TPM yields the RAW secret; every LUKS-facing
    # consumer (cryptsetup keyslot, the mkinitfs hook) gets base64(raw) — the
    # exact form upstream's token plugin hands over and seal_gen_passphrase
    # staged at enroll time.
    if [ "$_su_rc" -eq 0 ]; then
        openssl base64 -A -in "$_su_w/secret.raw" >"$_su_out" 2>/dev/null &&
            [ -s "$_su_out" ] || _su_rc=1
    fi
    tpm flushcontext -t >/dev/null 2>&1 || true
    rm -rf "$_su_w"
    [ "$_su_rc" -eq 0 ] ||
        err "seal_unseal: the TPM refused to unseal under the current PCR state (drift?)"
    return "$_su_rc"
}

# seal_enroll <keydir> <luks_dev> <pcrsig.json> <out_token.json> <mode> — the
# shared Mechanism B enrollment core. Order is fail-closed first: keydir,
# .pcrsig presence, environment, signature verification (G-B6) — and only then
# LUKS metadata reads and TPM operations.
seal_enroll() {
    [ $# -eq 5 ] || die "seal_enroll: usage: <keydir> <luks_dev> <pcrsig> <out_token> <mode>"
    _se_keydir=$1 _se_dev=$2 _se_sig=$3 _se_out=$4 _se_mode=$5
    case $_se_mode in
        provisional) _se_sel=11 ;;
        finalized) _se_sel=7,11 ;;
        *) die "seal_enroll: unknown mode '$_se_mode' (provisional|finalized)" ;;
    esac
    seal_keydir_check "$_se_keydir"
    [ -f "$_se_sig" ] || die "seal: UKI .pcrsig not found: $_se_sig"
    seal_require_env

    # G-B6 gate BEFORE anything else is touched. Finalized mode is DIGEST-
    # ANCHORED (Option A): recompute the policy digest from the entry's own
    # recorded anchor components (d7/d11 — the composing flow's console-
    # measured PCR 7 + the build's enter-initrd prediction) and compare to the
    # signed pol — a pure data check, NO live TPM read. The PROVISIONAL {11}
    # selection is anchored the same way when the entry carries a d11
    # component (2026-09-24: the harness's host-side Stage-1 step-6 seal runs
    # against a fixture swtpm whose live register is a designated RESEED —
    # extend-from-zero, never the booted value — so the live oracle refused
    # the seal's own correctly-signed policy; the real verification stays the
    # token's boot-time PolicyPCR session). Entries predating the anchor
    # fields keep the live-PCR oracle: the in-guest installer seals against
    # the very TPM the machine booted with, where live d11 IS the postphase
    # value.
    _se_fresh=''
    if [ "$_se_mode" = finalized ]; then
        _se_ad7=$(seal_pcrsig_field "$_se_sig" "$_se_sel" d7)
        _se_ad11=$(seal_pcrsig_field "$_se_sig" "$_se_sel" d11)
        if [ -n "$_se_ad7" ] && [ -n "$_se_ad11" ]; then
            _se_fresh=$(policy_digest "$_se_ad7" "$_se_ad11")
            info "seal: G-B6 digest-anchored over the entry's d7/d11 components (no live PCR read)"
        fi
    elif [ "$_se_mode" = provisional ]; then
        _se_ad11=$(seal_pcrsig_field "$_se_sig" "$_se_sel" d11)
        if [ -n "$_se_ad11" ]; then
            _se_fresh=$(seal_digest_11 "$_se_ad11")
            info "seal: G-B6 digest-anchored over the entry's d11 component (no live PCR read)"
        fi
    fi
    if [ -z "$_se_fresh" ]; then
        _se_d11=$(seal_pcrread 11)
        if [ "$_se_mode" = finalized ]; then
            _se_d7=$(seal_pcrread 7)
            _se_fresh=$(policy_digest "$_se_d7" "$_se_d11")
        else
            _se_fresh=$(seal_digest_11 "$_se_d11")
        fi
    fi
    seal_verify_pcrsig "$_se_keydir" "$_se_sig" "$_se_sel" "$_se_fresh"

    # keyslot choice from the REAL volume (token.sh owns LUKS2 reads)
    [ -e "$_se_dev" ] || die "seal: LUKS device not resolvable: $_se_dev"
    if ! SEAL_SLOT=$(token_free_slot "$_se_dev"); then
        die "seal: cannot determine a free LUKS2 keyslot on $_se_dev"
    fi

    # seal under the pinned sealed-object digest (§6.1.1 step 4b); all staging
    # (work dir + passphrase) lands in ALPINE_FDE_SEAL_STAGE when the caller
    # set it, so the choreography driver can scrub everything with one rm.
    # Default: the seal_stage_dir TMPFS root — NEVER /tmp (I1).
    _se_stage=${ALPINE_FDE_SEAL_STAGE:-$(seal_stage_dir)}
    _se_w=$(mktemp -d "$_se_stage/alpine-fde-seal.XXXXXX") ||
        die "seal: mktemp failed"
    chmod 700 "$_se_w"
    # SEAL_WORK_DIR: the caller's scrub handle (seal_scrub removes it with the
    # passphrase) — the blob halves staged here are secret-adjacent material
    SEAL_WORK_DIR=$_se_w
    keys_keyname_verifying "$_se_keydir/release.pub" "$_se_w/name.hex"
    SEAL_KEYNAME=$(tr -d ' \n' <"$_se_w/name.hex")
    _se_sealed=$(policy_sealed_digest "$SEAL_KEYNAME")
    seal_gen_passphrase
    seal_create "$_se_w" "$SEAL_PASS_FILE" "$_se_sealed"

    # emit the §7.2 token payload
    _se_blob=$(seal_blob_pack "$_se_w/seal.priv" "$_se_w/seal.pub")
    _se_pub=$(openssl pkey -pubin -in "$_se_keydir/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
    [ -n "$_se_pub" ] || {
        seal_scrub # I1: zeroize the passphrase, remove the work dir
        die "seal: cannot DER-encode the release public key (corrupt release.pub?)"
    }
    token_build_json "[$_se_sel]" "$_se_pub" "$SEAL_SIG_B64" "$_se_blob" "$SEAL_SLOT" \
        "$_se_sealed" "$_se_out"
    rm -f "$_se_w/name.hex" "$_se_w/primary.ctx"
    # Caller-facing seam: consumed by the sourcing caller (token.sh
    # choreography) and the seal_* unit suites after seal returns.
    # shellcheck disable=SC2034
    SEAL_TOKEN_FILE=$_se_out
    # shellcheck disable=SC2034
    SEAL_MODE=$_se_mode
    # NOTE: SEAL_PASS_FILE and the blob halves under $_se_w remain staged for
    # the caller (token.sh choreography / post-asserts) — the caller scrubs
    # them with seal_scrub (seal_upgrade_token does so itself; enrl_run's
    # choreography stage holds them and scrubs on every exit path).
    info "seal: sealed the random volume passphrase ($_se_mode, PCR $_se_sel) into keyslot $SEAL_SLOT of $_se_dev"
    return 0
}

# seal_provisional <keydir> <luks_dev> <uki_pcrsig_json> <out.token.json> —
# ADR-20 Stage 1 step 6: PolicyAuthorize over the PCR-11-only signed policy.
seal_provisional() {
    seal_enroll "${1:-}" "${2:-}" "${3:-}" "${4:-}" provisional
}

# seal_finalized <keydir> <luks_dev> <uki_pcrsig_json> <out.token.json> — the
# finalized {PCR 7, PCR 11} construction; the static d7 comes from the entry's
# recorded anchor components (digest-anchored G-B6, Option A) — no live TPM
# PCR read at seal time.
seal_finalized() {
    seal_enroll "${1:-}" "${2:-}" "${3:-}" "${4:-}" finalized
}

# seal_upgrade_token <keydir> <luks_dev> <uki_pcrsig_json> <out.token.json> \
#                    [auth_key_file] — ADR-20 Stage 3: replace the provisional
# keyslot-1 token with the finalized {7,11} token. Choreography (crash-safe
# order — the provisional seal stays standing until the finalized one does):
#   1. seal_finalized: fresh random passphrase sealed under the {7,11} policy
#   2. luksAddKey the new passphrase into a FRESH keyslot (never reuse the
#      provisional slot; auth_key_file — any current passphrase, e.g. the
#      recovery keyslot 0 — authorizes; without it cryptsetup prompts)
#   3. atomic token import of the finalized token (fresh token id)
#   4. swap: remove the OLD token, kill the OLD keyslot (the NEW passphrase
#      authorizes the kill — it is now a valid volume credential)
#   5. post-asserts: exactly one systemd-tpm2 token (the new one), bound to the
#      new slot != 0, recovery slot 0 byte-identical
# I1 staging hygiene: this function scrubs its OWN staging on EVERY exit path —
# steps 1-4 run in a subshell whose EXIT trap calls seal_scrub (zeroize +
# unlink the random volume passphrase, remove the seal work dir), so even the
# fail-closed dies inside the seal/token libs cannot strand the passphrase on
# disk. The choreography result (the new slot) crosses to the post-asserts via
# a scratch env file, also under the tmpfs root and also scrubbed.
seal_upgrade_token() {
    [ $# -ge 4 ] || die "seal_upgrade_token: usage: <keydir> <luks_dev> <pcrsig> <out_token> [auth_key_file]"
    _sut_keydir=$1 _sut_dev=$2 _sut_sig=$3 _sut_out=$4 _sut_auth=${5:-}
    [ -e "$_sut_dev" ] || die "seal: LUKS device not resolvable: $_sut_dev"
    _sut_stage=$(mktemp -d "$(seal_stage_dir)/alpine-fde-seal-upg.XXXXXX") ||
        die "seal: mktemp failed"
    chmod 700 "$_sut_stage"
    _sut_env=$(mktemp "$(seal_stage_dir)/alpine-fde-seal-upg-env.XXXXXX") ||
        {
            rm -rf "$_sut_stage"
            die "seal: mktemp failed"
        }
    # pre-state: find the standing enrollment (token id + keyslot), if any
    _sut_pre=$(mktemp "$(seal_stage_dir)/alpine-fde-seal-upg.XXXXXX") ||
        {
            rm -rf "$_sut_stage" "$_sut_env"
            die "seal: mktemp failed"
        }
    if ! token_dump "$_sut_dev" "$_sut_pre"; then
        rm -rf "$_sut_stage" "$_sut_env" "$_sut_pre"
        die "seal: cannot read LUKS2 metadata of $_sut_dev"
    fi
    _sut_old_tok=$(jq -r 'first(.tokens // {} | to_entries[] |
        select(.value.type? == "systemd-tpm2") | .key) // empty' "$_sut_pre" 2>/dev/null)
    _sut_old_slot=$(jq -r 'first(.tokens // {} | to_entries[] |
        select(.value.type? == "systemd-tpm2") | .value.keyslots[0]) // empty' \
        "$_sut_pre" 2>/dev/null)

    # 1+2+3+4: seal fresh under {7,11}, add the new keyslot + token, retire the
    # old enrollment — in a subshell with the seal_scrub EXIT net (I1)
    _sut_rc=0
    (
        trap 'seal_scrub' EXIT # zeroize the passphrase, remove the work dir
        export ALPINE_FDE_SEAL_STAGE="$_sut_stage"
        seal_finalized "$_sut_keydir" "$_sut_dev" "$_sut_sig" "$_sut_out" || exit 1
        if [ -n "$_sut_old_slot" ] && [ "$SEAL_SLOT" = "$_sut_old_slot" ]; then
            err "seal_upgrade_token: the fresh keyslot collides with the standing slot $_sut_old_slot — refusing"
            exit 1
        fi
        token_add_keyslot "$_sut_dev" "$SEAL_PASS_FILE" "$SEAL_SLOT" "$_sut_auth" || exit 1
        _sut_tid=$(token_next_id "$_sut_dev") || exit 1
        token_import "$_sut_dev" "$_sut_out" "$_sut_tid" || exit 1
        # 4: swap — retire the old enrollment under the NEW passphrase (it is a
        # valid volume credential the moment the new keyslot exists)
        if [ -n "$_sut_old_tok" ]; then
            token_remove "$_sut_dev" "$_sut_old_tok" || exit 1
            token_kill_slot "$_sut_dev" "$_sut_old_slot" "$SEAL_PASS_FILE" || exit 1
        fi
        printf 'SUT_SLOT=%s\n' "$SEAL_SLOT" >"$_sut_env"
    ) 2>"$_sut_stage/sub.err" || _sut_rc=1
    if [ -s "$_sut_stage/sub.err" ]; then
        cat "$_sut_stage/sub.err" >&2
    fi
    seal_scrub # belt-and-braces: the trap already ran INSIDE the subshell
    rm -rf "$_sut_stage"

    # 5: post-assert on the real metadata (no passphrase needed from here on)
    _sut_post=$(mktemp "$(seal_stage_dir)/alpine-fde-seal-upg.XXXXXX") ||
        {
            rm -f "$_sut_env" "$_sut_pre"
            return 1
        }
    token_dump "$_sut_dev" "$_sut_post" ||
        {
            rm -f "$_sut_env" "$_sut_pre" "$_sut_post"
            return 1
        }
    _sut_pub=$(jq -r '.["tpm2-pubkey"] // empty' "$_sut_out")
    _sut_new_slot=$(sed -n 's/^SUT_SLOT=//p' "$_sut_env" 2>/dev/null)
    rm -f "$_sut_env"
    if [ "$_sut_rc" -eq 0 ]; then
        token_post_assert "$_sut_pre" "$_sut_post" "$_sut_pub" '[7,11]' "$_sut_new_slot" || _sut_rc=1
        if [ "$_sut_rc" -ne 0 ]; then
            err "seal_upgrade_token: post-assertions failed — the finalized token is NOT standing as expected; manual intervention required (§8.3)"
        fi
    fi
    rm -f "$_sut_pre" "$_sut_post"
    return "$_sut_rc"
}

return 0
