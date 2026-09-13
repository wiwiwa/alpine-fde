#!/bin/sh
# manifest.sh — /etc/debian-fde/digests.json (docs/Architecture.md §8.4, gap B-G4):
# the signed combined-policy digest set for all retained UKIs. Written by
# `ukictl build`, consumed by enroll-tpm / audit / the test harness; bridges the
# build→enroll hand-off including on first install.
#
# Schema v1 (normative for this library):
# {
#   "version": 1, "pcr_bank": "sha256", "pcrs": [7, 11],
#   "current_kernel": "<kver>", "updated_at": "<iso8601z>",
#   "pubkey_fp": "<sha256 of DER SPKI>",
#   "digests": [ { "kernel_version", "pcr11_digest", "policy_digest", "signature",
#                  "keyslot", "token_id" } ]
# }
#  * upsert by kernel_version — rebuilding a kernel REPLACES its entry
#  * keyslot/token_id (§8.4, G-U2): the single A'' enrollment's bookkeeping.
#    OPTIONAL on read (legacy v1 documents without them stay valid — fail-open
#    on read), always WRITTEN by this library (write-always; "" until enrolled).
#    Under A'' every entry repeats the standing enrollment's values (consumed
#    by status/audit/recovery).
#  * all writes are atomic: temp file in the target directory + fsync + rename
#  * reading a document with an unknown `version` fails closed (exit 64)
#
# Depends on: lib/common.sh, jq, openssl (base64 not needed here), sync (GNU).

if [ -n "${DEBIAN_FDE_MANIFEST_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_MANIFEST_LOADED=1

MANIFEST_SCHEMA_VERSION=1

# manifest_now — ISO 8601 UTC timestamp for `updated_at`
manifest_now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

# manifest_atomic_write <file> — replace <file> with stdin contents atomically:
# write to a temp file in the SAME directory, fsync it, rename over the target,
# then best-effort fsync the directory. Never leaves partial state at <file>.
manifest_atomic_write() {
    _man_dst=$1
    _man_dir=$(dirname "$_man_dst")
    [ -d "$_man_dir" ] || die "manifest: target directory does not exist: $_man_dir"
    _man_tmp=$(mktemp "$_man_dir/.debian-fde-manifest.XXXXXX") \
        || die "manifest: cannot create temp file in $_man_dir"
    cat >"$_man_tmp" || {
        rm -f "$_man_tmp"
        die "manifest: writing temp file failed: $_man_tmp"
    }
    sync -f "$_man_tmp" 2>/dev/null || true
    if ! mv -f "$_man_tmp" "$_man_dst"; then
        rm -f "$_man_tmp"
        die "manifest: atomic rename failed: $_man_tmp -> $_man_dst"
    fi
    sync -d "$_man_dir" 2>/dev/null || warn "manifest: directory fsync not supported ($_man_dir)"
}

# manifest_load <file> — validate and print the manifest. Fails closed (64) when
# the file exists but is not a schema-v1 document (unknown `version`, or a
# digests[] whose elements are not all objects — a stray scalar would print as
# `null` from manifest_kvers; review IN-01). rc 1 (non-fatal) when absent.
manifest_load() {
    [ -f "$1" ] || return 1
    if ! jq -e ".version == $MANIFEST_SCHEMA_VERSION and (.digests | type == \"array\") and all(.digests[]; type == \"object\")" "$1" >/dev/null 2>&1; then
        die "manifest: unknown or invalid schema in $1 (expected version=$MANIFEST_SCHEMA_VERSION with object digests[] entries) — refusing to touch it"
    fi
    cat "$1"
}

# manifest_entry <kver> <pcr11hex> <policy_digest> <signature> [keyslot] [token_id]
# — print one digests[] entry as JSON (keyslot/token_id default "")
manifest_entry() {
    jq -n --arg kver "$1" --arg p11 "$2" --arg pd "$3" --arg sig "$4" \
        --arg slot "${5:-}" --arg tok "${6:-}" \
        '{kernel_version: $kver, pcr11_digest: $p11, policy_digest: $pd, signature: $sig,
          keyslot: $slot, token_id: $tok}'
}

# manifest_new <current_kernel> <pubkey_fp> — print a fresh schema-v1 document
manifest_new() {
    jq -n --arg kver "$1" --arg fp "$2" --arg now "$(manifest_now)" --argjson v "$MANIFEST_SCHEMA_VERSION" \
        '{version: $v, pcr_bank: "sha256", pcrs: [7, 11], current_kernel: $kver,
          updated_at: $now, pubkey_fp: $fp, digests: []}'
}

# manifest_transform <file> <jq-filter> [args...] — apply a jq filter (with the
# given --arg style args passed through verbatim) and atomically rewrite <file>.
# The filter receives the parsed document on stdin; rc!=0 from jq fails closed.
manifest_transform() {
    _man_file=$1
    _man_filter=$2
    shift 2
    _man_out=$(mktemp "${TMPDIR:-/tmp}/debian-fde-manifest.XXXXXX") \
        || die "manifest: mktemp failed"
    if ! jq "$@" "$_man_filter" <"$_man_file" >"$_man_out"; then
        rm -f "$_man_out"
        die "manifest: transform failed for $_man_file"
    fi
    manifest_atomic_write "$_man_file" <"$_man_out"
    rm -f "$_man_out"
}

# manifest_upsert <file> <kver> <pcr11hex> <policy_digest> <signature> [keyslot] [token_id]
# Insert-or-replace the entry for <kver>; bumps updated_at. Auto-creates a
# schema-v1 document when <file> does not exist yet. keyslot/token_id default
# to "" = carry over the replaced entry's enrollment bookkeeping (rebuilding a
# kernel does not change its standing A'' enrollment); explicit values override.
manifest_upsert() {
    _man_file=$1
    if ! manifest_load "$_man_file" >/dev/null 2>&1; then
        manifest_new "" "" | manifest_atomic_write "$_man_file"
    fi
    manifest_transform "$_man_file" '
        (.digests // []) as $old
        | .updated_at = $now
        | .digests = ($old | map(select(.kernel_version != $kver))
            + [($old | map(select(.kernel_version == $kver)) | .[0] // {}
                | {kernel_version: $kver, pcr11_digest: $p11, policy_digest: $pd,
                   signature: $sig,
                   keyslot: (if $slot != "" then $slot else (.keyslot // "") end),
                   token_id: (if $tok != "" then $tok else (.token_id // "") end)})])' \
        --arg kver "$2" --arg p11 "$3" --arg pd "$4" --arg sig "$5" \
        --arg slot "${6:-}" --arg tok "${7:-}" --arg now "$(manifest_now)"
}

# manifest_set_enrollment <file> <keyslot> <token_id> — record the single A''
# enrollment's bookkeeping onto EVERY digests[] entry (§8.4: under A'' there is
# one enrollment; the values repeat per entry for status/audit/recovery).
# Atomically re-serializes; bumps updated_at. No-op (rc 0) without a manifest.
manifest_set_enrollment() {
    _man_file=$1
    manifest_load "$_man_file" >/dev/null 2>&1 || return 0
    manifest_transform "$_man_file" '
        .updated_at = $now
        | .digests = (.digests | map(. + {keyslot: $slot, token_id: $tok}))' \
        --arg slot "$2" --arg tok "$3" --arg now "$(manifest_now)"
}

# manifest_set_meta <file> <current_kernel> <pubkey_fp> — record the build-time
# header fields (current_kernel, pubkey_fp, updated_at)
manifest_set_meta() {
    _man_file=$1
    manifest_load "$_man_file" >/dev/null 2>&1 || {
        manifest_new "$2" "$3" | manifest_atomic_write "$_man_file"
        return 0
    }
    manifest_transform "$_man_file" '
        .current_kernel = $kver | .pubkey_fp = $fp | .updated_at = $now' \
        --arg kver "$2" --arg fp "$3" --arg now "$(manifest_now)"
}

# manifest_get <file> <kver> — print the entry for <kver> or rc 1
manifest_get() {
    manifest_load "$1" >/dev/null 2>&1 || return 1
    jq -e --arg kver "$2" '.digests[] | select(.kernel_version == $kver)' "$1"
}

# manifest_kvers <file> — print kernel_version values, one per line
manifest_kvers() {
    manifest_load "$1" >/dev/null 2>&1 || return 0
    jq -r '.digests[].kernel_version' "$1"
}

# manifest_prune_to <file> <kver>... — keep ONLY entries whose kernel_version is
# in the argument list (the keep set is computed by lib/esp.sh so ESP files and
# manifest entries are pruned from ONE decision, §9.2). Bumps updated_at.
# The keep set is built BY JQ (never string concatenation): a kver is one opaque
# string, so quotes/commas/backslashes in a user-supplied version can neither
# inject phantom keep entries nor mangle the JSON (review MD-05).
manifest_prune_to() {
    _man_file=$1
    shift
    manifest_load "$_man_file" >/dev/null 2>&1 || return 0
    _man_keep=$(mktemp "${TMPDIR:-/tmp}/debian-fde-keep.XXXXXX") \
        || die "manifest: mktemp failed"
    if [ $# -eq 0 ]; then
        printf '[]\n' >"$_man_keep" # empty keep set -> [] (keeps nothing)
    else
        printf '%s\n' "$@" | jq -R . | jq -s . >"$_man_keep"
    fi
    manifest_transform "$_man_file" '
        .updated_at = $now
        | .digests = (.digests | map(select(.kernel_version as $k | $keep[0] | index($k))))' \
        --slurpfile keep "$_man_keep" --arg now "$(manifest_now)"
    _man_rc=$?
    rm -f "$_man_keep"
    return "$_man_rc"
}

return 0
