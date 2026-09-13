#!/usr/bin/env bash
# tests/unit/manifest_roundtrip.sh — digests.json manifest contract (§8.4, B-G4):
# schema v1, upsert-by-kernel_version (rebuild replaces), prune, fail-closed
# reads of unknown schema versions.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/manifest.sh
source "$REPO/lib/manifest.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
M="$TMP/digests.json"

# --- fresh document --------------------------------------------------------------
manifest_new "6.12.8-1-amd64" "fp0" | manifest_atomic_write "$M"
assert_eq "manifest_new: schema version" 1 "$(jq -r .version "$M")"
assert_eq "manifest_new: pcr_bank" "sha256" "$(jq -r .pcr_bank "$M")"
assert_eq "manifest_new: pcrs" "[7,11]" "$(jq -c .pcrs "$M")"
assert_eq "manifest_new: current_kernel" "6.12.8-1-amd64" "$(jq -r .current_kernel "$M")"

# --- load + upsert ----------------------------------------------------------------
manifest_load "$M" >/dev/null
assert_rc "manifest_load: valid v1 document loads" 0 $?
manifest_upsert "$M" "6.12.8-1-amd64" "<p11-a>" "<pd-a>" "<sig-a>"
n=$(jq '.digests | length' "$M")
assert_eq "upsert: one entry after first build" 1 "$n"
e=$(manifest_get "$M" "6.12.8-1-amd64")
assert_eq "upsert: entry fields intact (keyslot/token_id write-always, empty until enrolled)" \
    '{"kernel_version":"6.12.8-1-amd64","keyslot":"","pcr11_digest":"<p11-a>","policy_digest":"<pd-a>","signature":"<sig-a>","token_id":""}' \
    "$(printf '%s' "$e" | jq -cS .)"

# rebuild of the SAME kernel replaces (B-G4: upsert, never duplicate)
manifest_upsert "$M" "6.12.8-1-amd64" "<p11-b>" "<pd-b>" "<sig-b>"
n=$(jq '.digests | length' "$M")
assert_eq "upsert: rebuild of same kver replaces, count still 1" 1 "$n"
assert_eq "upsert: replaced values visible" "<pd-b>" "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .policy_digest)"

# --- enrollment bookkeeping (§8.4, G-U2): keyslot + token_id -----------------------
# An old manifest WITHOUT the fields still loads and validates (optional-on-read)
M0="$TMP/v1-nofields.json"
jq -n '{version: 1, pcr_bank: "sha256", pcrs: [7, 11], current_kernel: "k",
        updated_at: "t", pubkey_fp: "fp",
        digests: [{kernel_version: "k", pcr11_digest: "p", policy_digest: "d", signature: "s"}]}' \
    | manifest_atomic_write "$M0"
manifest_load "$M0" >/dev/null
assert_rc "keyslot/token_id optional-on-read: legacy v1 manifest loads" 0 $?
rc=0; manifest_set_enrollment "$M0" "3" "2" || rc=1
assert_rc "set_enrollment on a legacy manifest succeeds" 0 $rc
assert_eq "set_enrollment: fields added to the legacy entry" '{"keyslot":"3","token_id":"2"}' \
    "$(manifest_get "$M0" k | jq -c '{keyslot, token_id}')"

# set_enrollment records onto EVERY entry (repeated per entry — bookkeeping)
manifest_upsert "$M" "6.12.5-1-amd64" "<p11-c>" "<pd-c>" "<sig-c>"
assert_eq "upsert: second kernel added" 2 "$(jq '.digests | length' "$M")"
assert_eq "manifest_kvers lists both" \
    "$(printf '6.12.8-1-amd64\n6.12.5-1-amd64')" "$(manifest_kvers "$M")"
rc=0; manifest_set_enrollment "$M" "3" "2" || rc=1
assert_rc "manifest_set_enrollment succeeds" 0 $rc
assert_eq "set_enrollment: keyslot on entry 1" "3" "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .keyslot)"
assert_eq "set_enrollment: token_id on entry 1" "2" "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .token_id)"
assert_eq "set_enrollment: keyslot repeated on entry 2" "3" "$(manifest_get "$M" "6.12.5-1-amd64" | jq -r .keyslot)"
assert_eq "set_enrollment: token_id repeated on entry 2" "2" "$(manifest_get "$M" "6.12.5-1-amd64" | jq -r .token_id)"
manifest_load "$M" >/dev/null
assert_rc "set_enrollment: rewritten document still schema-valid" 0 $?

# a rebuild (upsert WITHOUT explicit values) preserves the standing enrollment
manifest_upsert "$M" "6.12.8-1-amd64" "<p11-d>" "<pd-d>" "<sig-d>"
assert_eq "upsert: rebuild preserves keyslot (enrollment unchanged)" "3" \
    "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .keyslot)"
assert_eq "upsert: rebuild preserves token_id" "2" \
    "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .token_id)"
# an explicit upsert value overrides
manifest_upsert "$M" "6.12.5-1-amd64" "<p11-c>" "<pd-c>" "<sig-c>" "5" "7"
assert_eq "upsert: explicit keyslot overrides" "5" "$(manifest_get "$M" "6.12.5-1-amd64" | jq -r .keyslot)"
assert_eq "upsert: explicit token_id overrides" "7" "$(manifest_get "$M" "6.12.5-1-amd64" | jq -r .token_id)"
# prune keeps the bookkeeping on surviving entries
manifest_prune_to "$M" "6.12.8-1-amd64"
assert_eq "prune: keeps only listed kver" "6.12.8-1-amd64" "$(manifest_kvers "$M")"
assert_eq "prune: bookkeeping survives on the kept entry" "3" \
    "$(manifest_get "$M" "6.12.8-1-amd64" | jq -r .keyslot)"

# --- meta -------------------------------------------------------------------------
manifest_set_meta "$M" "6.12.8-1-amd64" "deadbeef"
assert_eq "manifest_set_meta: pubkey_fp recorded" "deadbeef" "$(jq -r .pubkey_fp "$M")"

# --- prune to an explicit keep set (same decision drives the ESP prune) -----------
manifest_prune_to "$M" "6.12.8-1-amd64"
assert_eq "manifest_prune_to: keeps only listed kver" "6.12.8-1-amd64" "$(manifest_kvers "$M")"
manifest_upsert "$M" "6.12.5-1-amd64" "<p11-c>" "<pd-c>" "<sig-c>"
manifest_prune_to "$M" "6.12.8-1-amd64" "6.12.5-1-amd64"
assert_eq "manifest_prune_to: multi-kver keep set" \
    "$(printf '6.12.8-1-amd64\n6.12.5-1-amd64')" "$(manifest_kvers "$M")"
rc=0; manifest_get "$M" "6.0.0-old" >/dev/null 2>&1 || rc=1
assert_rc "manifest_get: unknown kver fails" 1 $rc

# --- prune keeps ONLY the named kvers — kver content can never mangle the JSON -----
# MD-05: the keep set is built by jq itself; a kver carrying '"'/','/'\'' must be
# treated as ONE opaque string (the old string-concat keep-set turned `x","y`
# into two phantom keep entries and a backslash into invalid JSON -> die).
MK="$TMP/mangle.json"
manifest_new "6.1.0-1-amd64" "fp" | manifest_atomic_write "$MK"
manifest_upsert "$MK" "6.1.0-1-amd64" "p11" "pd" "sig"
manifest_upsert "$MK" "x" "p11" "pd" "sig"
manifest_upsert "$MK" "y" "p11" "pd" "sig"
rc=0; ( manifest_prune_to "$MK" 'x","y' >/dev/null 2>&1 ) || rc=1
assert_rc "prune_to: quote/comma kver does not corrupt the keep-set JSON (rc 0)" 0 "$rc"
assert_eq "prune_to: phantom keep strings never match real entries (all dropped)" "" \
    "$(manifest_kvers "$MK")"
manifest_new "6.1.0-1-amd64" "fp" | manifest_atomic_write "$MK"
manifest_upsert "$MK" "6.1.0-1-amd64" "p11" "pd" "sig"
rc=0; ( manifest_prune_to "$MK" 'back\slash' >/dev/null 2>&1 ) || rc=1
assert_rc "prune_to: backslash kver stays valid JSON (no die after mutation)" 0 "$rc"
assert_eq "prune_to: backslash kver matched nothing (digests emptied)" "[]" "$(jq -c .digests "$MK")"
# positive control: normal keep sets still behave (multi + none)
manifest_upsert "$MK" "keep-a" "p11" "pd" "sig"
manifest_upsert "$MK" "keep-b" "p11" "pd" "sig"
manifest_prune_to "$MK" "keep-a" "keep-b"
assert_eq "prune_to: ordinary keep set intact" "$(printf 'keep-a\nkeep-b')" "$(manifest_kvers "$MK" | sort)"

# --- fail closed on unknown / broken schema ---------------------------------------
M2="$TMP/bad.json"
manifest_new "x" "y" | jq '.version = 2' | manifest_atomic_write "$M2"
out=$(manifest_load "$M2" 2>&1); rc=$?
assert_rc "manifest_load: unknown schema version rejected (exit 64)" 64 $rc
assert_contains "rejection names the version field (not a phantom schema_version)" "$out" "version=$MANIFEST_SCHEMA_VERSION"

printf 'not json at all' >"$M2"
out=$(manifest_load "$M2" 2>&1); rc=$?
assert_rc "manifest_load: broken JSON rejected (exit 64)" 64 $rc

# version missing entirely
printf '{"digests": []}' >"$M2"
out=$(manifest_load "$M2" 2>&1); rc=$?
assert_rc "manifest_load: version field required" 64 $rc

# IN-01: digests[] elements must be objects — string/scalar entries are schema
# garbage that would print `null` from manifest_kvers; fail closed instead.
printf '{"version": 1, "pcr_bank": "sha256", "pcrs": [7, 11], "current_kernel": "k",
         "updated_at": "t", "pubkey_fp": "fp", "digests": ["not-an-object"]}' >"$M2"
out=$(manifest_load "$M2" 2>&1); rc=$?
assert_rc "manifest_load: non-object digests[] element rejected (exit 64)" 64 $rc
printf '{"version": 1, "digests": [{"kernel_version": "ok"}, "stray"]}' >"$M2"
out=$(manifest_load "$M2" 2>&1); rc=$?
assert_rc "manifest_load: one stray element poisons the whole document (64)" 64 $rc
manifest_load "$M" >/dev/null 2>&1
rc=$?
assert_rc "manifest_load: object-only digests[] still loads" 0 $rc

finish
