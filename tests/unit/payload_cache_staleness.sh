#!/usr/bin/env bash
# tests/unit/payload_cache_staleness.sh — the derived Alpine payload's cache
# reuse must be bound to the CURRENT repo tree, not only to its own bytes.
#
# Bug this pins (2026-09-26 registry results-20260926T093432Z.nZzWyQ.json,
# s01c LIV3 RC=127, run dir pruned; stale payload verified by read-only mount
# of the s00b disk cache: /opt/alpine-fde absent, /opt/debian-fde present):
# rootfs_payload_image cached its derived payload tar with a SIDECAR SHA of
# the tar itself. That proves the cached bytes intact — never that they are
# CURRENT. The payload cached 2026-09-21 (pre-rename repo state) kept being
# reused after the tree moved to /opt/alpine-fde, so EVERY installed guest
# rooted at /opt/debian-fde (a residue-guard-BANNED spelling: the shipped
# tree contains no such path), /usr/local/bin/alpine-fde dangled into it, and
# the first in-guest CLI invocation died 127. The disk cache (pristine-s00b)
# was sha-clean too — installed FROM the same stale payload — so its verify
# must bind FORMAT line 2 to the current tree digest as well.
#
# Pinned invariants:
#   P1  a repo-tree content digest helper exists and digests the exact dirs
#       the payload embeds (bin lib hooks docs);
#   P2  the helper is stable + well-formed (functional: 64-hex, repeatable);
#   P3  the payload sidecar carries BOTH digests (payload sha + tree digest);
#   P4  reuse is gated on the tree digest matching, and a stale cache is
#       announced loudly before re-derivation (never silent reuse);
#   P5  _cache_verify refuses a disk cache whose FORMAT tree digest is absent
#       or stale (installed rootfs came FROM the payload);
#   P6  _cache_store records the binding and refuses to store without it.
#
# RED-first: before the fix, P1/P3/P4/P5/P6 fail against the unguarded lib.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

LIB="$TESTS/lib/uki-build.sh"
S00B="$TESTS/e2e/s00b-enroll-cache.sh"
assert_file_exists "uki-build lib present" "$LIB"
assert_file_exists "s00b cache builder present" "$S00B"
assert_rc "uki-build: bash -n clean" 0 bash -n "$LIB"
assert_rc "s00b: bash -n clean" 0 bash -n "$S00B"
LIBC=$(cat "$LIB")
SC=$(cat "$S00B")

# --- P1: the tree-digest helper exists and digests the embedded dirs ---------
assert_contains "P1: rootfs_payload_tree_digest defined" "$LIBC" "rootfs_payload_tree_digest() {"
assert_contains "P1: digest covers exactly the embedded tree (bin lib hooks docs)" "$LIBC" \
    "find bin lib hooks docs -type f -print0"

# --- P2: functional — stable, 64-hex (isolated cache dir, no downloads) ------
DIGEST_A=$(ALPINE_FDE_ARTIFACT_CACHE_DIR="$(mktemp -d)" bash -c \
    'source "$1/lib/uki-build.sh" && rootfs_payload_tree_digest' _ "$TESTS")
DIGEST_B=$(ALPINE_FDE_ARTIFACT_CACHE_DIR="$(mktemp -d)" bash -c \
    'source "$1/lib/uki-build.sh" && rootfs_payload_tree_digest' _ "$TESTS")
if [[ "$DIGEST_A" =~ ^[0-9a-f]{64}$ ]] && [[ "$DIGEST_A" == "$DIGEST_B" ]]; then
    _assert_result ok "P2: tree digest is 64-hex and stable across invocations" ""
else
    _assert_result not-ok "P2: tree digest is 64-hex and stable across invocations" \
        "A=$DIGEST_A B=$DIGEST_B"
fi

# --- P3: the sidecar carries BOTH digests ------------------------------------
assert_contains "P3: sidecar line 2 = the tree digest (staleness half)" "$LIBC" \
    "printf '%s\n' \"\$tree_digest\" >>\"\$tmpout.sha\""

# --- P4: reuse gated on the tree digest + loud stale announcement ------------
assert_contains "P4: reuse requires the cached tree digest to match the current tree" "$LIBC" \
    '[[ -n "$cached_tree_digest" && "$tree_digest" == "$cached_tree_digest" ]]'
assert_contains "P4: a sha-intact but stale cache is announced before re-derivation" "$LIBC" \
    "derived payload cache is STALE (embedded repo tree changed) — re-deriving"

# --- P5: the s00b disk cache is bound to the tree it was installed from ------
assert_contains "P5: _cache_verify compares FORMAT line 2 against the CURRENT tree digest" "$SC" \
    'grep -qx "tree-sha256 $(rootfs_payload_tree_digest)" "$dir/FORMAT"'

# --- P6: _cache_store records the binding, refuses to store without it -------
assert_contains "P6: _cache_store writes FORMAT line 2 from the passed digest" "$SC" \
    "printf 'btrfs-3\\ntree-sha256 %s\\n' \"\$tree_digest\" >\"\$stage/FORMAT\""
# the cache-store stage runs _cache_store inside `bash -c "$(declare -f ...)"`:
# only DECLARED functions exist there, so the body must take the digest as an
# argument (live-failed 2026-09-26: a body-side `$(rootfs_payload_tree_digest)`
# died "command not found" and cached an EMPTY binding).
_SCS_BODY=$(sed -n '/^_cache_store() {/,/^}/p' "$S00B")
assert_not_contains "P6: _cache_store body never calls the lib helper (undecleared in its subshell)" \
    "$_SCS_BODY" "rootfs_payload_tree_digest"
assert_contains "P6: the rootfs-payload stage declares the digest helper + stub builder alongside rootfs_payload_image" "$SC" \
    "declare -f rootfs_payload_image rootfs_payload_tree_digest"
assert_contains "P6: _cache_store refuses a digest-less store (loud rc 64)" "$SC" \
    "no tree digest (payload staleness binding)"
assert_contains "P6: the cache-store stage passes the digest into the subshell" "$SC" \
    "_cache_store '\$CACHE_DIR' '\$RUN' '\$(rootfs_payload_tree_digest)'"

# --- summary -----------------------------------------------------------------------
TOTAL=$((TESTS_PASS + TESTS_FAIL))
echo "1..$TOTAL"
echo "# payload_cache_staleness: pass=$TESTS_PASS fail=$TESTS_FAIL"
if ((TESTS_FAIL == 0)); then exit 0; fi
exit 1
