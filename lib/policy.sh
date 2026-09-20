#!/bin/sh
# policy.sh — combined {7,11} PolicyPCR policy-digest math and release-key policy
# signature emission (`pcrsign`, docs/Architecture.md §6.1.1). TPM-free by design
# (B-G2: never shell out to tpm2_createpolicy — it requires a live TCTI).
#
# Verified serialization (golden vector fixtures/policy-digest/golden.json and two
# independent live-TPM trial-session cross-checks, tpm2-tools 5.8 / swtpm):
#
#   pcrDigest    = SHA256(pcr7_raw || pcr11_raw)                  (raw PCR bytes, index order)
#   policyDigest = SHA256( zero32 || CC_PolicyPCR || TPML{7,11} || pcrDigest )
#     CC_PolicyPCR = 00 00 01 7f                       (TPM_CC_PolicyPCR; IS part of the
#                                                   policy hash per TPM 2.0 Part 3)
#     TPML{7,11}   = 00 00 00 01 00 0b 03 80 08 00     (count=1, sha256, sizeofSelect=3,
#                                                   select: bit7 in byte0, bit11 in byte1)
#     zero32       = 32 zero bytes                    (initial session policy digest)
#
# The signed message for PolicyAuthorize is the RAW 32-byte policyDigest
# (policyRef empty; keyName is NOT signed — §6.1.1 step 4). Signature: RSASSA-
# PKCS1-v1_5 over SHA256(message) — plain `openssl dgst -sha256 -sign`, matching
# what `tpm2_verifysignature -f rsassa -g sha256` accepts.
#
# The sealed-object policy digest PolicyAuthorize leaves in the session
# (§6.1.1 step 4b) is policy_sealed_digest below — a DOUBLE hash over
# zero32 || CC_PolicyAuthorize || keyName, policyRef empty.
#
# Depends on: lib/common.sh (info/warn/die/require_cmds), openssl, awk (LC_ALL=C),
# jq only for the signature JSON emitter (policy_sign_json).

if [ -n "${DEBIAN_FDE_POLICY_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_POLICY_LOADED=1

# --- constants (marshaled TPM 2.0 structures, sha256 bank, PCRs 7+11) ----------
POLICY_CC_PCR='0000017f'
POLICY_CC_AUTHORIZE='0000016a'
POLICY_TPML_7_11='00000001000b03800800'
POLICY_ZERO32='0000000000000000000000000000000000000000000000000000000000000000'

# policy_hex_to_bin — hex string (stdin, even length, no whitespace) -> raw bytes.
# POSIX awk; LC_ALL=C pins byte semantics (gawk otherwise UTF-8-encodes %c > 127).
policy_hex_to_bin() {
    LC_ALL=C awk '{
        hex = "0123456789abcdef"
        for (i = 1; i <= length($0); i += 2) {
            hi = index(hex, tolower(substr($0, i, 1))) - 1
            lo = index(hex, tolower(substr($0, i + 1, 1))) - 1
            printf "%c", hi * 16 + lo
        }
    }'
}

# policy_check_digest HEX — rc 0 iff HEX is exactly 64 hex chars (sha256 digest)
policy_check_digest() {
    case $1 in
        '' | *[!0-9a-fA-F]*) return 1 ;;
    esac
    [ ${#1} -eq 64 ]
}

# policy_pcr_digest <d7hex> <d11hex> — print pcrDigest = SHA256(d7||d11)
policy_pcr_digest() {
    policy_check_digest "$1" || die "policy: pcr7 digest is not a sha256 hex digest: $1"
    policy_check_digest "$2" || die "policy: pcr11 digest is not a sha256 hex digest: $2"
    printf '%s%s' "$1" "$2" | policy_hex_to_bin \
        | openssl dgst -sha256 -hex | awk '{print $NF}'
}

# policy_sealed_digest <keyNameHex> — print the sealed-object policy digest
# a TPM2_PolicyAuthorize session leaves behind (docs/Architecture.md §6.1.1
# step 4b — formula PINNED; matches libtpms PolicyAuthorize.c/Policy_spt.c and
# live swtpm sessions; offline golden: fixtures/policy-digest/sealed-digest.golden,
# live oracle: tests/unit/policy_digest_tpm_crosscheck.sh case 3 +
# tests/unit/pcrsign_policyauthorize_accept.sh):
#
#   sealed = SHA256( SHA256( zero32 || CC_PolicyAuthorize || keyName ) || policyRef )
#     zero32            = 32 zero bytes    (PolicyAuthorize CLEARS the session digest)
#     CC_PolicyAuthorize = 00 00 01 6a     (4-byte big-endian command code — part of
#                                          the hash per TPM 2.0 Part 3 PolicyContextUpdate)
#     keyName           = TPM Name (hex) of the area that will VERIFY at session time
#     policyRef         = EMPTY — the second hash round STILL runs (DOUBLE hash)
#
# The earlier single-hash form H(policyDigest || keyName || policyRef) is WRONG.
# keyName is NOT signed (§6.1.1 step 4); it enters only this digest update.
# Fails closed (die 64) on non-hex or odd-length keyName hex.
policy_sealed_digest() {
    case ${1:-} in
        '' | *[!0-9a-fA-F]*)
            die "policy_sealed_digest: keyName is not a hex string: '${1:-}'" ;;
    esac
    [ $((${#1} % 2)) -eq 0 ] || die "policy_sealed_digest: keyName hex has odd length: $1"
    _pol_d1=$(printf '%s%s%s' "$POLICY_ZERO32" "$POLICY_CC_AUTHORIZE" "$1" \
        | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}')
    printf '%s' "$_pol_d1" | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}'
}

# policy_digest <d7hex> <d11hex> — print the combined {7,11} PolicyPCR policy digest.
# This is the value the TPM's policy session computes for
#   tpm2_policypcr -l sha256:7,11
# and therefore the value `pcrsign` signs (A'/A/B) and the manifest records.
# The digests are re-checked HERE: policy_pcr_digest's die would be swallowed
# by this function's command substitution in non-strict contexts (fail-open).
policy_digest() {
    policy_check_digest "$1" || die "policy: pcr7 digest is not a sha256 hex digest: ${1:-<empty>}"
    policy_check_digest "$2" || die "policy: pcr11 digest is not a sha256 hex digest: ${2:-<empty>}"
    _pol_pcrd=$(policy_pcr_digest "$1" "$2")
    printf '%s%s%s%s' "$POLICY_ZERO32" "$POLICY_CC_PCR" "$POLICY_TPML_7_11" "$_pol_pcrd" \
        | policy_hex_to_bin | openssl dgst -sha256 -hex | awk '{print $NF}'
}

# policy_digest_bin <d7hex> <d11hex> — raw 32-byte policyDigest on stdout
# (the exact PolicyAuthorize message bytes to sign).
# Input is validated HERE, in this function's own frame: policy_digest dies
# inside the pipeline below, and a pipeline's rc is its LAST component's —
# the die would be swallowed (fail-open) in non-strict contexts.
policy_digest_bin() {
    policy_check_digest "$1" || die "policy: pcr7 digest is not a sha256 hex digest: ${1:-<empty>}"
    policy_check_digest "$2" || die "policy: pcr11 digest is not a sha256 hex digest: ${2:-<empty>}"
    policy_digest "$1" "$2" | policy_hex_to_bin
}

# policy_sign <d7hex> <d11hex> <privkey.pem> <out.sig> — RSASSA-PKCS1-v1_5/SHA256
# signature over the raw policyDigest bytes.
# NOTE: deliberately NO trap here — lib code must not clobber the caller's EXIT
# trap (POSIX sh has exactly one handler per signal); every path cleans up itself.
policy_sign() {
    [ $# -eq 4 ] || die "policy_sign: usage: policy_sign <d7hex> <d11hex> <privkey.pem> <out.sig>"
    _pol_msg=$(mktemp "${TMPDIR:-/tmp}/debian-fde-policy.XXXXXX") || die "policy_sign: mktemp failed"
    # subshell: a die inside policy_digest_bin (invalid hex) must not strand
    # _pol_msg (S-L1)
    if ! (policy_digest_bin "$1" "$2") >"$_pol_msg"; then
        rm -f "$_pol_msg"
        die "policy_sign: PCR digests are not sha256 hex digests: '${1:-}' '${2:-}'"
    fi
    if ! openssl dgst -sha256 -sign "$3" -out "$4" "$_pol_msg"; then
        rm -f "$_pol_msg"
        die "policy_sign: release-key signature over policy digest failed (key: $3)"
    fi
    rm -f "$_pol_msg"
}

# policy_verify <sig-file> <d7hex> <d11hex> <pubkey.pem> — rc 0 iff the signature
# verifies over the policyDigest recomputed from the given PCR values.
policy_verify() {
    [ $# -eq 4 ] || return 2
    _pol_msg=$(mktemp "${TMPDIR:-/tmp}/debian-fde-policy.XXXXXX") || return 2
    # subshell: a die inside policy_digest_bin (invalid hex) must not strand
    # _pol_msg (S-L1); invalid digests are a verify failure here
    if ! (policy_digest_bin "$2" "$3") >"$_pol_msg"; then
        rm -f "$_pol_msg"
        return 1
    fi
    _pol_rc=0
    openssl dgst -sha256 -verify "$4" -signature "$1" "$_pol_msg" >/dev/null 2>&1 || _pol_rc=1
    rm -f "$_pol_msg"
    return "$_pol_rc"
}

# policy_pubkey_fp <pubkey.pem> — SHA256 over the DER-encoded SubjectPublicKeyInfo
# (the `pkfp`/`pubkey_fp` fingerprint format used by systemd-measure output and
# recorded in the manifest and predictions.json).
# CONTRACT (S-M4): on ANY failure (absent/unparseable key) return rc 1 with
# EMPTY stdout — never a fingerprint of the empty string. Consumers guard on
# this (policy_sign_json here; `ukictl build` in lib/cmd/ukictl-build.sh).
policy_pubkey_fp() {
    _ppf_tmp=$(mktemp "${TMPDIR:-/tmp}/debian-fde-pkfp.XXXXXX") || return 1
    if ! openssl pkey -pubin -in "$1" -outform DER 2>/dev/null >"$_ppf_tmp"; then
        rm -f "$_ppf_tmp"
        return 1
    fi
    if [ ! -s "$_ppf_tmp" ]; then
        rm -f "$_ppf_tmp"
        return 1
    fi
    _ppf_fp=$(sha256sum "$_ppf_tmp") || { rm -f "$_ppf_tmp"; return 1; }
    rm -f "$_ppf_tmp"
    printf '%s\n' "${_ppf_fp%% *}"
}

# policy_sign_json <d7hex> <d11hex> <privkey.pem> <pubkey.pem> <out.json>
# Emit the pcrsign artifact: release-key signature over the combined policy digest,
# wrapped in the `systemd-measure sign` output shape (§6.1.1 step 5 — existing
# fields only, with pcrs [7,11] in the same field). This JSON is what the
# Mechanism A'/A enrollment steps consume (exact .pcrsig embedding is pinned by
# the cryptenroll-acceptance spike, B-G3).
policy_sign_json() {
    [ $# -eq 5 ] || die "policy_sign_json: usage: <d7hex> <d11hex> <privkey.pem> <pubkey.pem> <out.json>"
    require_cmds jq
    _pol_tmp=$(mktemp -d "${TMPDIR:-/tmp}/debian-fde-pcrsig.XXXXXX") || die "policy_sign_json: mktemp failed"
    # subshell: a die inside policy_sign (unusable private key) must not
    # strand _pol_tmp (S-L1)
    if ! (policy_sign "$1" "$2" "$3" "$_pol_tmp/sig.bin"); then
        rm -rf "$_pol_tmp"
        die "policy_sign_json: release-key signature failed (key: $3)"
    fi
    _pol_b64=$(openssl base64 -A -in "$_pol_tmp/sig.bin") || {
        rm -rf "$_pol_tmp"
        die "policy_sign_json: base64 failed"
    }
    # S-M4: an unparseable release.pub must fail closed — never record the
    # well-known SHA256("") fingerprint as the key's pkfp
    _pol_fp=$(policy_pubkey_fp "$4") || {
        rm -rf "$_pol_tmp"
        die "policy_sign_json: cannot parse the release public key: $4 (corrupt release.pub?)"
    }
    _pol_pd=$(policy_digest "$1" "$2")
    if ! jq -n --arg sig "$_pol_b64" --arg pkfp "$_pol_fp" --arg pol "$_pol_pd" \
        '{"sha256": [{"pcrs": [7, 11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' \
        >"$5"; then
        rm -rf "$_pol_tmp"
        die "policy_sign_json: jq failed"
    fi
    rm -rf "$_pol_tmp"
}

return 0
