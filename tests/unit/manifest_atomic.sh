#!/usr/bin/env bash
# tests/unit/manifest_atomic.sh — atomic-write contract (§8.4, B-G4): the
# manifest is replaced by temp-file + fsync + rename, so a reader never observes
# partial state and failures leave the previous document intact.
# NOTE: manifest mutators fail closed via die (exit 64) — failure paths are
# sampled inside command substitutions (subshells) here.
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

# --- happy path: full document replaced, no temp files left -----------------------
manifest_new "6.12.8-1-amd64" "fp" | manifest_atomic_write "$M"
manifest_upsert "$M" "6.12.8-1-amd64" "11" "22" "33"
jq -e '.version == 1 and (.digests | length == 1)' "$M" >/dev/null
assert_rc "document valid after upsert (complete rename, not in-place edit)" 0 $?
leftovers=$(find "$TMP" -maxdepth 1 -name '.debian-fde-manifest.*' | wc -l | tr -d '[:space:]')
assert_eq "no temp files left in the manifest directory" 0 "$leftovers"

# --- failed transform leaves the previous document byte-identical -----------------
before=$(cat "$M")
out=$(manifest_transform "$M" 'this is not valid jq' 2>&1)
rc=$?
assert_rc "failed transform fails closed (64)" 64 $rc
assert_eq "failed transform left the document byte-identical" "$before" "$(cat "$M")"

# --- missing target directory fails loudly, nothing written -----------------------
out=$(manifest_new "x" "y" | manifest_atomic_write "$TMP/no/such/dir/m.json" 2>&1)
rc=$?
assert_rc "atomic_write into a missing directory fails (64)" 64 $rc
assert_contains "failure explains the missing directory" "$out" "does not exist"
[ -e "$TMP/no" ]
assert_rc "no partial directory structure was created" 1 $?

# --- empty keep set is a legal, complete rewrite -----------------------------------
manifest_prune_to "$M"
assert_eq "empty keep set empties digests (legal operation)" "[]" "$(jq -c .digests "$M")"

# --- concurrent reader sees either old or new, never partial (sampling) ------------
manifest_upsert "$M" "6.12.8-1-amd64" "p11-init" "pd-init" "sig-init"
torn=0
for i in $(seq 1 40); do
    manifest_upsert "$M" "6.12.8-1-amd64" "p11-$i" "pd-$i" "sig-$i" &
    # concurrent reader on the same path: every observation must be complete
    if ! jq -e '.version == 1 and (.digests | length == 1)
                and (.digests[0].signature | startswith("sig-"))
                and (.digests[0].pcr11_digest | startswith("p11-"))' "$M" >/dev/null 2>&1; then
        torn=1
        wait
        break
    fi
    wait
done
assert_eq "40 concurrent upsert/read cycles: no torn document ever observed" 0 "$torn"

finish
