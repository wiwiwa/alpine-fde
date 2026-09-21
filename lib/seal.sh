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
#     finalized      = policy_digest(d7_live, d11_live) — the combined {7,11}
#                      construction; the static d7 is re-captured from the
#                      live TPM at seal time
#   The .pcrsig is verified BEFORE anything is embedded or staged (G-B6): the
#   entry selected by its pcrs field must exist, its signature must verify
#   openssl-level over the embedded `pol` bytes against keydir/release.pub,
#   and `pol` must equal the freshly computed digest over the live PCRs.
#
# SRK (§7.1): `tpm2 createprimary -C o -g sha256 -G rsa` — the tpm2-tools
# DEFAULT owner-hierarchy primary template (restricted|decrypt|fixedTPM|
# fixedParent|sensitiveDataOrigin|userWithAuth, sha256, RSA with NULL
# scheme/symmetric default), i.e. the TCG Storage Root Key profile. The
# template is deterministic: re-running the command reproduces the same
# primary on an untouched TPM (verified on swtpm: identical readpublic Name).
#
# Random volume passphrase (I1): openssl rand -hex 32 (>= 256-bit), staged at
# ${DEBIAN_FDE_TMPDIR:-/dev/shm}/debian-fde-seal-pass.XXXXXX, mode 600 — never
# plaintext on a persistent filesystem. The passphrase is sealed INTO the TPM
# blob and added as the new LUKS2 keyslot's credential (token.sh choreography;
# callers scrub via keys_scrub after use).
#
# tpm2 object-context discipline: swtpm/libtpms exposes ~2 transient object
# slots, and context files are SAVED contexts (each tool invocation re-loads
# them). Every helper below therefore flushes its own contexts and never holds
# more than two objects; seal_unseal flushes ALL transients between `tpm2 load`
# and the policy session so the final ContextLoad has a free slot (the exact
# pattern proven by tests/unit/pcrsign_policyauthorize_accept.sh).
#
# Globals set on success (enroll ops): SEAL_MODE, SEAL_SLOT, SEAL_PASS_FILE,
# SEAL_POL (approved digest hex), SEAL_KEYNAME (hex), SEAL_TOKEN_FILE.
#
# Depends on: lib/common.sh, lib/policy.sh, lib/keys.sh, lib/token.sh,
# openssl, tpm2-tools via the tpm() TCTI wrapper.

if [ -n "${DEBIAN_FDE_SEAL_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_SEAL_LOADED=1

_sl_cmd_dir=${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_sl_lib_dir=${_sl_cmd_dir%/*}
if [ -z "${DEBIAN_FDE_COMMON_LOADED:-}" ]; then
    if [ -r "$_sl_lib_dir/common.sh" ]; then
        # shellcheck disable=SC1090
        . "$_sl_lib_dir/common.sh"
    fi
fi
if [ -z "${DEBIAN_FDE_POLICY_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "$_sl_lib_dir/policy.sh"
fi
if [ -z "${DEBIAN_FDE_KEYS_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "$_sl_lib_dir/keys.sh"
fi
if [ -z "${DEBIAN_FDE_TOKEN_LOADED:-}" ]; then
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

# seal_pcrread <idx> — live sha256 PCR digest as bare lowercase hex (the -o +
# od form: format-independent, unlike pcrread's aligned text output).
seal_pcrread() {
    [ $# -eq 1 ] || die "seal_pcrread: usage: seal_pcrread <idx>"
    _spr_f=$(mktemp "${TMPDIR:-/tmp}/debian-fde-seal-pcr.XXXXXX") || die "seal: mktemp failed"
    if ! tpm pcrread -Q -o "$_spr_f" "sha256:$1" >/dev/null 2>&1; then
        rm -f "$_spr_f"
        die "seal: cannot read live PCR $1 (TCTI: ${DEBIAN_FDE_TCTI:-<default>})"
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
        die "seal: no usable TPM via TCTI '${DEBIAN_FDE_TCTI:-<default>}' — cannot seal"
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

# seal_verify_pcrsig <keydir> <pcrsig.json> <pcrs_csv> <fresh_digest> — the
# G-B6 gate. Sets SEAL_SIG_B64 and SEAL_POL on success; dies 64 (before ANY
# embedding or staging) on:
#   * no .pcrsig entry for the expected selection (wrong-selection signature)
#   * the signature does not verify over the embedded pol bytes (tampered or
#     foreign-key signature — openssl-level per the swtpm-leniency caveat)
#   * pol != the freshly computed digest over the live PCRs (tampered/stale)
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
    _svp_work=$(mktemp -d "${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}/debian-fde-seal-verify.XXXXXX") ||
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
        die "seal: the .pcrsig policy digest is stale/tampered: signed $_svp_pol != freshly computed $_svp_fresh over the live PCRs — refusing to embed"
    fi
    SEAL_POL=$_svp_pol
    SEAL_SIG_B64=$_svp_sigb64
    return 0
}

# seal_gen_passphrase — stage the random volume passphrase (I1): 256-bit hex
# under ${DEBIAN_FDE_SEAL_STAGE:-${DEBIAN_FDE_TMPDIR:-/dev/shm}}, mode 600.
# BYTE-EXACT: no trailing newline (the file is fed verbatim to tpm2_create -i
# and luksAddKey --key-file — every consumer must see identical bytes).
# DEBIAN_FDE_SEAL_STAGE (enroll-tpm's choreography staging dir) wins when set
# so the whole staging tree is scrubbed with one rm by the caller.
seal_gen_passphrase() {
    _sgp_dir=${DEBIAN_FDE_SEAL_STAGE:-${DEBIAN_FDE_TMPDIR:-/dev/shm}}
    SEAL_PASS_FILE=$(mktemp "$_sgp_dir/debian-fde-seal-pass.XXXXXX") ||
        die "seal: cannot stage the volume passphrase ($_sgp_dir usable?)"
    chmod 600 "$SEAL_PASS_FILE"
    if ! openssl rand -hex 32 | tr -d '\n' >"$SEAL_PASS_FILE"; then
        keys_scrub "$SEAL_PASS_FILE"
        die "seal: generating the random volume passphrase failed"
    fi
    [ "$(wc -c <"$SEAL_PASS_FILE")" -eq 64 ] || {
        keys_scrub "$SEAL_PASS_FILE"
        die "seal: staged passphrase has unexpected length — refusing"
    }
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
    _sbs_tmp=$(mktemp "${TMPDIR:-/tmp}/debian-fde-seal-blob.XXXXXX") || die "seal: mktemp failed"
    openssl base64 -d -A >"$_sbs_tmp"
    _sbs_plen=$((0x$(xxd -p -l 2 "$_sbs_tmp")))
    dd if="$_sbs_tmp" of="$_sbs_priv" bs=1 count=$((2 + _sbs_plen)) status=none
    dd if="$_sbs_tmp" of="$_sbs_pub" bs=1 skip=$((2 + _sbs_plen)) status=none
    rm -f "$_sbs_tmp"
}

# seal_create <workdir> <pass_file> <sealed_hex> — seal the passphrase under
# the SRK: primary (pinned template) + tpm2_create -L <sealed digest>. The
# blob halves land in <workdir>/seal.priv and <workdir>/seal.pub.
seal_create() {
    [ $# -eq 3 ] || die "seal_create: usage: <workdir> <pass_file> <sealed_hex>"
    _sc_w=$1 _sc_pass=$2 _sc_sealed=$3
    if ! tpm createprimary -C o -g sha256 -G rsa -c "$_sc_w/primary.ctx" >/dev/null 2>&1; then
        die "seal: tpm2_createprimary failed (SRK; TCTI: ${DEBIAN_FDE_TCTI:-default})"
    fi
    if ! tpm create -C "$_sc_w/primary.ctx" -g sha256 -i "$_sc_pass" \
        -L "$_sc_sealed" -u "$_sc_w/seal.pub" -r "$_sc_w/seal.priv" >/dev/null 2>&1; then
        tpm flushcontext -t >/dev/null 2>&1 || true
        die "seal: tpm2_create failed — could not seal the volume passphrase under the SRK policy"
    fi
    tpm flushcontext -t >/dev/null 2>&1 || true
    if [ ! -s "$_sc_w/seal.priv" ] || [ ! -s "$_sc_w/seal.pub" ]; then
        die "seal: tpm2_create produced an empty blob — refusing"
    fi
    return 0
}

# seal_unseal <keydir> <pcrsig.json> <mode> <token_json> <out_file> — unseal
# the token's blob under a policy session over the LIVE PCRs with the .pcrsig
# signature. rc 0 and the passphrase bytes in <out_file> on success; nonzero
# (loud die for verify failures) on any refusal. Also the oracle path for the
# ADR-20 Stage-3 upgrade choreography.
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
    _su_w=$(mktemp -d "${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}/debian-fde-seal-unseal.XXXXXX") ||
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
        tpm unseal -c "$_su_w/seal.ctx" -p "session:$_su_w/sess.ctx" -o "$_su_out" >/dev/null 2>&1 ||
        _su_rc=1
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

    # G-B6 gate BEFORE anything else is touched
    _se_d11=$(seal_pcrread 11)
    if [ "$_se_mode" = finalized ]; then
        _se_d7=$(seal_pcrread 7)
        _se_fresh=$(policy_digest "$_se_d7" "$_se_d11")
    else
        _se_fresh=$(seal_digest_11 "$_se_d11")
    fi
    seal_verify_pcrsig "$_se_keydir" "$_se_sig" "$_se_sel" "$_se_fresh"

    # keyslot choice from the REAL volume (token.sh owns LUKS2 reads)
    [ -e "$_se_dev" ] || die "seal: LUKS device not resolvable: $_se_dev"
    if ! SEAL_SLOT=$(token_free_slot "$_se_dev"); then
        die "seal: cannot determine a free LUKS2 keyslot on $_se_dev"
    fi

    # seal under the pinned sealed-object digest (§6.1.1 step 4b); all staging
    # (work dir + passphrase) lands in DEBIAN_FDE_SEAL_STAGE when the caller
    # set it, so the choreography driver can scrub everything with one rm
    _se_stage=${DEBIAN_FDE_SEAL_STAGE:-${DEBIAN_FDE_TMPDIR:-${TMPDIR:-/tmp}}}
    _se_w=$(mktemp -d "$_se_stage/debian-fde-seal.XXXXXX") ||
        die "seal: mktemp failed"
    chmod 700 "$_se_w"
    keys_keyname_verifying "$_se_keydir/release.pub" "$_se_w/name.hex"
    SEAL_KEYNAME=$(tr -d ' \n' <"$_se_w/name.hex")
    _se_sealed=$(policy_sealed_digest "$SEAL_KEYNAME")
    seal_gen_passphrase
    seal_create "$_se_w" "$SEAL_PASS_FILE" "$_se_sealed"

    # emit the §7.2 token payload
    _se_blob=$(seal_blob_pack "$_se_w/seal.priv" "$_se_w/seal.pub")
    _se_pub=$(openssl pkey -pubin -in "$_se_keydir/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
    [ -n "$_se_pub" ] || {
        keys_scrub "$SEAL_PASS_FILE"
        rm -rf "$_se_w"
        die "seal: cannot DER-encode the release public key (corrupt release.pub?)"
    }
    token_build_json "[$_se_sel]" "$_se_pub" "$SEAL_SIG_B64" "$_se_blob" "$SEAL_SLOT" "$_se_out"
    rm -f "$_se_w/name.hex" "$_se_w/primary.ctx"
    SEAL_TOKEN_FILE=$_se_out
    SEAL_MODE=$_se_mode
    # NOTE: SEAL_PASS_FILE and the blob halves under $_se_w remain staged for
    # the caller (token.sh choreography / post-asserts / scrub).
    info "seal: sealed the random volume passphrase ($_se_mode, PCR $_se_sel) into keyslot $SEAL_SLOT of $_se_dev"
    return 0
}

# seal_provisional <keydir> <luks_dev> <uki_pcrsig_json> <out.token.json> —
# ADR-20 Stage 1 step 6: PolicyAuthorize over the PCR-11-only signed policy.
seal_provisional() {
    seal_enroll "${1:-}" "${2:-}" "${3:-}" "${4:-}" provisional
}

# seal_finalized <keydir> <luks_dev> <uki_pcrsig_json> <out.token.json> — the
# finalized {PCR 7, PCR 11} construction; static d7 re-captured from the live
# TPM.
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
seal_upgrade_token() {
    [ $# -ge 4 ] || die "seal_upgrade_token: usage: <keydir> <luks_dev> <pcrsig> <out_token> [auth_key_file]"
    _sut_keydir=$1 _sut_dev=$2 _sut_sig=$3 _sut_out=$4 _sut_auth=${5:-}
    [ -e "$_sut_dev" ] || die "seal: LUKS device not resolvable: $_sut_dev"
    # pre-state: find the standing enrollment (token id + keyslot), if any
    _sut_pre=$(mktemp "${TMPDIR:-/tmp}/debian-fde-seal-upg.XXXXXX") || die "seal: mktemp failed"
    token_dump "$_sut_dev" "$_sut_pre"
    _sut_old_tok=$(jq -r 'first(.tokens // {} | to_entries[] |
        select(.value.type? == "systemd-tpm2") | .key) // empty' "$_sut_pre" 2>/dev/null)
    _sut_old_slot=$(jq -r 'first(.tokens // {} | to_entries[] |
        select(.value.type? == "systemd-tpm2") | .value.keyslots[0]) // empty' \
        "$_sut_pre" 2>/dev/null)

    # 1+2+3: seal fresh under {7,11} and add the new keyslot + token
    seal_finalized "$_sut_keydir" "$_sut_dev" "$_sut_sig" "$_sut_out"
    _sut_new_slot=$SEAL_SLOT
    if [ -n "$_sut_old_slot" ] && [ "$_sut_new_slot" = "$_sut_old_slot" ]; then
        keys_scrub "$SEAL_PASS_FILE"
        rm -rf "${_se_w:-}"
        die "seal_upgrade_token: the fresh keyslot collides with the standing slot $_sut_old_slot — refusing"
    fi
    token_add_keyslot "$_sut_dev" "$SEAL_PASS_FILE" "$_sut_new_slot" "$_sut_auth"
    _sut_tid=$(token_next_id "$_sut_dev")
    token_import "$_sut_dev" "$_sut_out" "$_sut_tid"

    # 4: swap — retire the old enrollment under the NEW passphrase (it is a
    # valid volume credential the moment the new keyslot exists)
    if [ -n "$_sut_old_tok" ]; then
        token_remove "$_sut_dev" "$_sut_old_tok"
        token_kill_slot "$_sut_dev" "$_sut_old_slot" "$SEAL_PASS_FILE"
    fi

    # 5: post-assert on the real metadata
    _sut_post=$(mktemp "${TMPDIR:-/tmp}/debian-fde-seal-upg.XXXXXX") || die "seal: mktemp failed"
    token_dump "$_sut_dev" "$_sut_post"
    _sut_pub=$(jq -r '.["tpm2-pubkey"] // empty' "$_sut_out")
    _sut_rc=0
    token_post_assert "$_sut_pre" "$_sut_post" "$_sut_pub" '[7,11]' "$_sut_new_slot" || _sut_rc=1
    if [ "$_sut_rc" -ne 0 ]; then
        err "seal_upgrade_token: post-assertions failed — the finalized token is NOT standing as expected; manual intervention required (§8.3)"
    fi
    rm -f "$_sut_pre" "$_sut_post"
    return "$_sut_rc"
}

return 0
