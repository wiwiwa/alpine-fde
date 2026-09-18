#!/usr/bin/env bash
# tests/unit/build_no_key_loud_fail.sh — ADR-8/I4 loud failure: with the release
# key material absent, `ukictl build` exits fail-closed (64), persists the
# build-failed marker, and does NOT mutate the ESP or the manifest — the previous
# default UKI stays bootable and unlockable (§10 failure-matrix row).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# helpers beyond W0's lib.sh set (assert.sh's assert_rc has a different
# signature, so define the two missing ones here instead of mixing libraries)
assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/manifest.sh
source "$REPO/lib/manifest.sh"

KVER=6.12.8-1-amd64
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/debian-fde" "$ESP/EFI/Linux" "$TMP/empty-keydir"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/debian-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
# G-U4 (§8.2): the crypttab guard requires the tpm2-device= option at build time
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{pcr7_digest: $d7, status: "finalized"}' >"$ROOT/etc/debian-fde/baseline.json"

# prior good state: an old UKI and a manifest the build must not touch
printf 'pre-existing-uki' >"$ESP/EFI/Linux/debian-fde-6.1.0-1-amd64.efi"
M="$ROOT/etc/debian-fde/digests.json"
manifest_new "6.1.0-1-amd64" "fp" | manifest_atomic_write "$M"
manifest_upsert "$M" "6.1.0-1-amd64" "p11" "pd" "sig"
BEFORE_ESP=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
BEFORE_MANIFEST=$(cat "$M")

debian-fde() {
    DEBIAN_FDE_ROOT="$ROOT" \
        DEBIAN_FDE_ESP="$ESP" \
        DEBIAN_FDE_KEYDIR="$1" \
        DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        "$REPO/bin/debian-fde" "${@:2}"
}

# --- case 1: keydir not configured at all --------------------------------------------
out=$(debian-fde "" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "unconfigured keydir -> fail-closed exit 64" 64 $rc
assert_contains "error names the missing configuration" "$out" "release key directory not configured"

# --- case 2: keydir exists but is empty (USB not attached / backup not restored) ------
out=$(debian-fde "$TMP/empty-keydir" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "empty keydir -> fail-closed exit 64" 64 $rc
assert_contains "error explains what is missing" "$out" "release.pem is missing"
assert_contains "error points at the encrypted key location (ADR-18 semantics, G-KC8)" "$out" \
    "release.pem is missing (encrypted key expected at $TMP/empty-keydir/release.pem"
assert_contains "error cites ADR-18" "$out" "ADR-18"
assert_contains "error tells the operator the ESP was not touched" "$out" "refusing to touch the ESP"
assert_contains "recovery copy offers the scp backup + medium paths (ADR-18)" "$out" "scp backup"

# --- case 3: keydir has the public key but the private key is offline ------------------
mkdir -p "$TMP/pubonly"
cp "$REPO/fixtures/keys/release.pub" "$TMP/pubonly/"
out=$(debian-fde "$TMP/pubonly" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "public-key-only keydir -> fail-closed exit 64 (I4)" 64 $rc
assert_contains "error names the absent private key" "$out" "release.pem is missing"

# --- invariants across all cases --------------------------------------------------------
AFTER_ESP=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
assert_eq "ESP byte-identical after failed builds (no UKI installed, nothing pruned)" \
    "$BEFORE_ESP" "$AFTER_ESP"
assert_eq "manifest untouched by failed builds" "$BEFORE_MANIFEST" "$(cat "$M")"
[ ! -e "$ROOT/etc/debian-fde/predictions.json" ]
rc=$?
assert_rc "no predictions.json emitted on failure" 0 "$rc"

marker="$ROOT/etc/debian-fde/build-failed"
assert_file_exists "failure marker persisted for debian-fde status" "$marker"
assert_contains "marker names the kernel" "$(cat "$marker")" "$KVER"
assert_contains "marker records the reason" "$(cat "$marker")" "reason:"

# recovery: attach the key (fixture stands in for the signing medium) -> build
# succeeds and the marker is cleared (§8.3 operator recovery)
out=$(debian-fde "$REPO/fixtures/keys" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "recovery build with the key attached succeeds" 0 $rc
[ ! -e "$marker" ]
rc=$?
assert_rc "successful build cleared the failure marker" 0 "$rc"
assert_file_exists "UKI now installed" "$ESP/EFI/Linux/debian-fde-$KVER.efi"

finish
