#!/bin/sh
# token.sh — LUKS2 systemd-tpm2 token writer + keyslot/token choreography
# (§7.2; G-B5). Owns the exact token JSON the §12 interop oracle consumes.
#
# TOKEN SCHEMA PIN (dash-form, upstream systemd names — lib/cmd/status.sh and
# the existing fixtures read these):
#   {"type": "systemd-tpm2",
#    "keyslots": ["<slot>"],
#    "tpm2-blob":        <b64 of TPM2B_PRIVATE || TPM2B_PUBLIC>,
#    "tpm2-pcrs":        [11] provisional / [7, 11] finalized,
#    "tpm2-pcr-bank":    "sha256",
#    "tpm2-pubkey":      <b64 DER SubjectPublicKeyInfo of release.pub>,
#    "tpm2-signature":   <b64 of the .pcrsig release-key signature>}
#
# Choreography primitives (all cryptsetup calls go through the
# DEBIAN_FDE_CRYPTSETUP seam — the same env override enroll-tpm/ukictl-build
# and their tests use):
#   token_free_slot <dev>       smallest free keyslot >= 1 (slot 0 is recovery)
#   token_next_id   <dev>       smallest free LUKS2 token id
#   token_add_keyslot <dev> <pass_file> <slot> [auth_file]
#                               luksAddKey: pass_file becomes the new keyslot's
#                               passphrase; auth_file (any existing passphrase)
#                               authorizes — omitted, cryptsetup prompts
#   token_import <dev> <token_json> <id>
#                               atomic token import: same-dir temp (chmod 600)
#                               + `cryptsetup token import --json-file`, then
#                               the temp is unlinked
#   token_remove <dev> <id>, token_kill_slot <dev> <slot> [auth_file]
#   token_dump <dev> <outfile>  luksDump --dump-json-metadata wrapper (die 64)
#   token_post_assert <pre_json> <post_json> <pub_b64> <pcrs_json> <slot>
#                               the enroll post-assert skeleton (exactly one
#                               systemd-tpm2 token, pubkey equality, pcrs for
#                               mode, slot != 0, recovery slot 0 byte-identical)
#
# Depends on: lib/common.sh (die/info), lib/baseline.sh parsers are NOT needed
# here (own jq one-liners); jq; cryptsetup via the seam.

if [ -n "${DEBIAN_FDE_TOKEN_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_TOKEN_LOADED=1

if [ -z "${DEBIAN_FDE_COMMON_LOADED:-}" ]; then
    _tk_cmd_dir=${DEBIAN_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
    _tk_lib_dir=${_tk_cmd_dir%/*}
    if [ -r "$_tk_lib_dir/common.sh" ]; then
        # shellcheck disable=SC1090
        . "$_tk_lib_dir/common.sh"
    fi
fi

token_cryptsetup() { "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }

# token_dump <dev> <outfile> — LUKS2 metadata snapshot (fail-closed 64).
token_dump() {
    [ $# -eq 2 ] || die "token_dump: usage: token_dump <dev> <outfile>"
    if ! token_cryptsetup luksDump --dump-json-metadata "$1" >"$2" 2>/dev/null; then
        die "token: cannot read LUKS2 metadata of $1"
    fi
}

# token_free_slot <dev> — smallest free keyslot index in [1..31] (slot 0 is the
# recovery slot and is never proposed; LUKS2 caps at 32 slots). Prints the
# index; dies 64 when the metadata is unreadable or no slot is free.
token_free_slot() {
    [ $# -eq 1 ] || die "token_free_slot: usage: token_free_slot <dev>"
    _tfs_tmp=$(mktemp "${TMPDIR:-/tmp}/debian-fde-token.XXXXXX") || die "token: mktemp failed"
    token_dump "$1" "$_tfs_tmp"
    _tfs_slot=$(jq -r '[.keyslots // {} | keys[] | tonumber] as $u |
        [range(1; 32)] | map(select(. as $i | $u | index($i) | not)) | first // empty' \
        "$_tfs_tmp" 2>/dev/null)
    rm -f "$_tfs_tmp"
    [ -n "$_tfs_slot" ] || die "token: no free LUKS2 keyslot on $1 (slots 1..31 exhausted)"
    printf '%s\n' "$_tfs_slot"
}

# token_next_id <dev> — smallest free LUKS2 token id (>= 0).
token_next_id() {
    [ $# -eq 1 ] || die "token_next_id: usage: token_next_id <dev>"
    _tni_tmp=$(mktemp "${TMPDIR:-/tmp}/debian-fde-token.XXXXXX") || die "token: mktemp failed"
    token_dump "$1" "$_tni_tmp"
    _tni_id=$(jq -r '[.tokens // {} | keys[] | tonumber] as $u |
        [range(0; 64)] | map(select(. as $i | $u | index($i) | not)) | first // empty' \
        "$_tni_tmp" 2>/dev/null)
    rm -f "$_tni_tmp"
    [ -n "$_tni_id" ] || die "token: no free LUKS2 token id on $1"
    printf '%s\n' "$_tni_id"
}

# token_build_json <pcrs_json> <pub_b64> <sig_b64> <blob_b64> <slot> <out_file>
# The §7.2 token, jq-built (values can never mangle the JSON).
token_build_json() {
    [ $# -eq 6 ] || die "token_build_json: usage: <pcrs_json> <pub_b64> <sig_b64> <blob_b64> <slot> <out>"
    if ! jq -n \
        --argjson pcrs "$1" --arg pub "$2" --arg sig "$3" --arg blob "$4" --arg slot "$5" \
        '{type: "systemd-tpm2",
          keyslots: [$slot],
          "tpm2-blob": $blob,
          "tpm2-pcrs": $pcrs,
          "tpm2-pcr-bank": "sha256",
          "tpm2-pubkey": $pub,
          "tpm2-signature": $sig}' >"$6"; then
        die "token: building the systemd-tpm2 token JSON failed"
    fi
}

# token_add_keyslot <dev> <pass_file> <slot> [auth_file] — luksAddKey with the
# staged passphrase as the NEW keyslot's credential. Without auth_file,
# cryptsetup prompts for an existing passphrase (guided recovery/finalize path).
token_add_keyslot() {
    [ $# -ge 3 ] || die "token_add_keyslot: usage: <dev> <pass_file> <slot> [auth_file]"
    _tak_dev=$1 _tak_pass=$2 _tak_slot=$3 _tak_auth=${4:-}
    if [ -n "$_tak_auth" ]; then
        token_cryptsetup luksAddKey "$_tak_dev" "$_tak_pass" --key-slot "$_tak_slot" \
            --key-file "$_tak_auth" 2>/dev/null
    else
        token_cryptsetup luksAddKey "$_tak_dev" "$_tak_pass" --key-slot "$_tak_slot" 2>/dev/null
    fi
    _tak_rc=$?
    [ "$_tak_rc" -eq 0 ] ||
        die "token: luksAddKey failed on $_tak_dev (keyslot $_tak_slot) — no changes recorded"
    return 0
}

# token_import <dev> <token_json> <id> — atomic token import: the JSON is
# staged same-directory (chmod 600 BEFORE the cryptsetup call — no
# default-umask window) and unlinked afterwards; cryptsetup reads it via
# --json-file. External-token plugins are disabled for the import: validation
# belongs to the pinned schema (§12 interop oracle), not to whatever plugin
# version the host happens to carry.
token_import() {
    [ $# -eq 3 ] || die "token_import: usage: <dev> <token_json> <id>"
    _tim_dev=$1 _tim_json=$2 _tim_id=$3
    _tim_dir=${_tim_json%/*}
    [ -d "$_tim_dir" ] || _tim_dir=${TMPDIR:-/tmp}
    _tim_tmp=$(mktemp "$_tim_dir/.debian-fde-token-import.XXXXXX") ||
        die "token: cannot stage the token import"
    chmod 600 "$_tim_tmp"
    cat "$_tim_json" >"$_tim_tmp"
    if ! token_cryptsetup token import "$_tim_dev" --token-id "$_tim_id" \
        --json-file "$_tim_tmp" --disable-external-tokens 2>/dev/null; then
        rm -f "$_tim_tmp"
        die "token: cryptsetup token import failed on $_tim_dev (token id $_tim_id) — the keyslot was added but the token is NOT standing (re-run enrollment; §8.3)"
    fi
    rm -f "$_tim_tmp"
    return 0
}

# token_remove <dev> <id> — remove a LUKS2 token (best-effort semantics are the
# CALLER's decision: this function fails loudly).
token_remove() {
    [ $# -eq 2 ] || die "token_remove: usage: <dev> <id>"
    token_cryptsetup token remove "$1" --token-id "$2" 2>/dev/null ||
        die "token: removing token id $2 from $1 failed"
}

# token_kill_slot <dev> <slot> [auth_file] — wipe a keyslot (retire path of the
# ADR-20 Stage-3 upgrade). Authorization: auth_file, else cryptsetup prompts.
token_kill_slot() {
    [ $# -ge 2 ] || die "token_kill_slot: usage: <dev> <slot> [auth_file]"
    _tks_dev=$1 _tks_slot=$2 _tks_auth=${3:-}
    if [ -n "$_tks_auth" ]; then
        token_cryptsetup luksKillSlot "$_tks_dev" "$_tks_slot" --key-file "$_tks_auth" 2>/dev/null
    else
        token_cryptsetup luksKillSlot "$_tks_dev" "$_tks_slot" 2>/dev/null
    fi
    _tks_rc=$?
    [ "$_tks_rc" -eq 0 ] ||
        die "token: luksKillSlot failed on $_tks_dev (keyslot $_tks_slot) — the retired slot still holds its passphrase"
    return 0
}

# token_post_assert <pre_json> <post_json> <pub_b64> <pcrs_json> <slot> —
# the enroll post-assert skeleton (reused from lib/cmd/enroll-tpm.sh's
# assertions, generalized over the mode):
#   * exactly one systemd-tpm2 token
#   * its tpm2-pubkey == <pub_b64> (the pinned release key)
#   * its tpm2-pcrs == <pcrs_json> for the mode ([11] / [7,11])
#   * the referenced keyslot == <slot> and is != 0 (recovery slot)
#   * recovery keyslot 0 byte-identical to the pre-state (when it existed)
token_post_assert() {
    [ $# -eq 5 ] || die "token_post_assert: usage: <pre_json> <post_json> <pub_b64> <pcrs_json> <slot>"
    _tpa_pre=$1 _tpa_post=$2 _tpa_pub=$3 _tpa_pcrs=$4 _tpa_slot=$5
    _tpa_pre0=$(jq -rS '.keyslots["0"] // empty' "$_tpa_pre" 2>/dev/null)
    _tpa_fail=''
    _tpa_n=$(jq -r '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' \
        "$_tpa_post" 2>/dev/null)
    [ "$_tpa_n" = "1" ] || _tpa_fail="expected exactly 1 systemd-tpm2 token, found ${_tpa_n:-0}"
    if [ -z "$_tpa_fail" ]; then
        _tpa_tok=$(jq -c 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value)' \
            "$_tpa_post" 2>/dev/null)
        _tpa_got_slot=$(printf '%s' "$_tpa_tok" | jq -r '.keyslots[0] // empty')
        _tpa_got_pub=$(printf '%s' "$_tpa_tok" | jq -r '.["tpm2-pubkey"] // empty')
        _tpa_got_pcrs=$(printf '%s' "$_tpa_tok" | jq -c '.["tpm2-pcrs"] // empty')
        [ "$_tpa_got_slot" = "$_tpa_slot" ] ||
            _tpa_fail="token keyslot is '${_tpa_got_slot:-none}', want $_tpa_slot"
        [ -z "$_tpa_fail" ] && [ "$_tpa_got_slot" = "0" ] &&
            _tpa_fail="token must reference a keyslot != 0 (recovery slot)"
        [ -z "$_tpa_fail" ] && [ "$_tpa_got_pub" != "$_tpa_pub" ] &&
            _tpa_fail="token pubkey mismatch (not the pinned release key)"
        [ -z "$_tpa_fail" ] && [ "$_tpa_got_pcrs" != "$_tpa_pcrs" ] &&
            _tpa_fail="token pcrs are $_tpa_got_pcrs, want $_tpa_pcrs for this mode"
    fi
    if [ -z "$_tpa_fail" ] && [ -n "$_tpa_pre0" ]; then
        _tpa_post0=$(jq -rS '.keyslots["0"] // empty' "$_tpa_post" 2>/dev/null)
        [ "$_tpa_pre0" = "$_tpa_post0" ] ||
            _tpa_fail="recovery keyslot 0 changed — enrollment aborted (slot intact?)"
    fi
    if [ -n "$_tpa_fail" ]; then
        err "token: post-assert failed: $_tpa_fail"
        return 1
    fi
    return 0
}

return 0
