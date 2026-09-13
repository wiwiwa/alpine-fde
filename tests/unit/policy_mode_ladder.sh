#!/usr/bin/env bash
# tests/unit/policy_mode_ladder.sh — G-B3/ADR-14: the mechanism ladder is
# RESOLVED — Mechanism A'' (mode a2) is the ONLY pipeline mode. Modes a / ap /
# b are documented-absent and fail closed (64) at every entry point:
#   * policy_mode_normalize — the common.sh boundary (unit level)
#   * `ukictl build` — rc 64 + ADR-8 build-failed marker + ESP byte-identical
#   * `enroll-tpm` — rc 64
# Every rejection cites ADR-14: "Mechanism A'' is the proven path".
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

assert_ne() {
    if [ "$2" != "$3" ]; then _pass "$1"; else _fail "$1 (both values are [$2])"; fi
}
assert_not_contains() {
    case $2 in
        *"$3"*) _fail "$1 ([$2] must not contain [$3])" ;;
        *) _pass "$1" ;;
    esac
}
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (missing: $2)"; fi
}

# --- unit level: the common.sh boundary -------------------------------------------
# shellcheck source=../../lib/common.sh
. "$REPO/lib/common.sh"

for m in a ap b a-prime combined; do
    out=$(policy_mode_normalize "$m" 2>&1)
    rc=$?
    assert_rc "normalize: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "normalize: $m message cites ADR-14" "$out" "ADR-14"
    assert_contains "normalize: $m message names the proven path" "$out" "Mechanism A'' is the proven path"
    assert_ne "normalize: $m emits no canonical mode on the rejected path" "$out" "a2"
done

assert_eq "normalize: canonical a2 still accepted" "a2" "$(policy_mode_normalize a2)"
assert_eq "normalize: verbose a2 alias accepted" "a2" "$(policy_mode_normalize a-prime-prime)"
assert_eq "normalize: native alias accepted" "a2" "$(policy_mode_normalize native)"
policy_mode_normalize definitely-not-a-mode >/dev/null 2>&1
assert_rc "normalize: unknown mode stays a plain reject (rc 1)" 1 $?

# --- entry points: ukictl build + enroll-tpm ---------------------------------------
KVER=6.12.8-1-amd64
KEYDIR="$REPO/fixtures/keys"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/debian-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/debian-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/debian-fde/baseline.json"
printf 'pre-existing-uki' >"$ESP/EFI/Linux/debian-fde-6.1.0-1-amd64.efi"

debian-fde() {
    DEBIAN_FDE_BIN_TEST=1 \
        DEBIAN_FDE_ROOT="$ROOT" \
        DEBIAN_FDE_ESP="$ESP" \
        DEBIAN_FDE_KEYDIR="$KEYDIR" \
        DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        "$REPO/bin/debian-fde" "$@"
}

ESP_BEFORE=$(find "$ESP" -type f -exec sha256sum {} + | sort)
for m in a ap b; do
    out=$(POLICY_MODE=$m debian-fde ukictl build "$KVER" 2>&1)
    rc=$?
    assert_rc "build: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "build: $m message cites ADR-14" "$out" "ADR-14"
    assert_contains "build: $m message names the proven path" "$out" "Mechanism A'' is the proven path"
    assert_file_exists "build: $m persists the ADR-8 failure marker" "$ROOT/etc/debian-fde/build-failed"
    assert_contains "build: $m marker cites ADR-14" "$(cat "$ROOT/etc/debian-fde/build-failed")" "ADR-14"
    assert_eq "build: $m leaves the ESP byte-identical" "$ESP_BEFORE" \
        "$(find "$ESP" -type f -exec sha256sum {} + | sort)"
done

for m in a ap b; do
    out=$(POLICY_MODE=$m debian-fde enroll-tpm 2>&1)
    rc=$?
    assert_rc "enroll-tpm: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "enroll-tpm: $m message cites ADR-14" "$out" "ADR-14"
    assert_contains "enroll-tpm: $m message names the proven path" "$out" "Mechanism A'' is the proven path"
done

finish
