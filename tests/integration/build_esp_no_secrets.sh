#!/usr/bin/env bash
# tests/integration/build_esp_no_secrets.sh — G-U11 (§11 I2): the ESP contains no
# secrets, guarded after a REAL `ukictl build` over the stub inputs:
#   * `find ESP -type f` == exactly the retained UKI set (current + retention)
#   * no "BEGIN ... PRIVATE KEY" material anywhere on the ESP
#   * no .pem/.pub/.crt/.json artifacts on the ESP
# The build env mirrors tests/unit/ukictl_build_stub.sh (stub initramfs, real
# ukify/sbsign, seeded retained UKIs so prune is exercised against real state).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"

KVER=6.12.8-1-amd64
KEYDIR="$REPO/fixtures/keys"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
# §8.2 crypttab contract (G-U4 guard requires it at build time)
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/alpine-fde/baseline.json"

# pre-existing retained UKIs + manifest entries (prune must drop 5.15.0)
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    printf 'pre-existing-uki-%s' "$k" >"$ESP/EFI/Linux/alpine-fde-$k.efi"
done
. "$REPO/lib/common.sh"
. "$REPO/lib/manifest.sh"
M="$ROOT/etc/alpine-fde/digests.json"
manifest_new "6.2.0-1-amd64" "fp-old" | manifest_atomic_write "$M"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    manifest_upsert "$M" "$k" "p11-old-$k" "pd-old-$k" "sig-old-$k"
done

ALPINE_FDE_BIN_TEST=1 \
    ALPINE_FDE_ROOT="$ROOT" \
    ALPINE_FDE_ESP="$ESP" \
    ALPINE_FDE_KEYDIR="$KEYDIR" \
    ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
assert_rc "ukictl build succeeds over the stub inputs" 0 $?

# --- exactly the retained UKI set -----------------------------------------------------
EXPECTED=$(printf '%s\n' \
    "$ESP/EFI/Linux/alpine-fde-6.1.0-1-amd64.efi" \
    "$ESP/EFI/Linux/alpine-fde-6.2.0-1-amd64.efi" \
    "$ESP/EFI/Linux/alpine-fde-$KVER.efi" | sort)
ACTUAL=$(find "$ESP" -type f | sort)
assert_eq "ESP holds exactly the retained UKI set (current + 2)" "$EXPECTED" "$ACTUAL"

# --- I2: no secrets on the ESP ---------------------------------------------------------
if grep -r "BEGIN.*PRIVATE KEY" "$ESP" >/dev/null 2>&1; then
    _fail "ESP carries no private key material (I2) (matched BEGIN ... PRIVATE KEY)"
else
    _pass "ESP carries no private key material (I2)"
fi
assert_eq "ESP holds no .pem/.pub/.crt/.json artifacts (I2)" "" \
    "$(find "$ESP" -type f \( -name '*.pem' -o -name '*.pub' -o -name '*.crt' -o -name '*.json' \) -print)"

# --- CR fix (review B-CR1): a build with NO env ESP resolves the ESP from the
# persisted conf (ESP_PATH=...) — exactly how `install` records the real mount.
# Before the fix this build fell back to /boot/efi (created on the encrypted
# root, exit 0) — the installed system's kernel updates never reached the boot
# menu. ALPINE_FDE_ESP is deliberately NOT set here.
ESP3="$TMP/esp-from-conf"
printf '%s\n' "ESP_PATH=$ESP3" >"$TMP/esp.conf"
env -u ALPINE_FDE_ESP \
    ALPINE_FDE_BIN_TEST=1 \
    ALPINE_FDE_ROOT="$ROOT" \
    ALPINE_FDE_CONF="$TMP/esp.conf" \
    ALPINE_FDE_KEYDIR="$KEYDIR" \
    ALPINE_FDE_NO_INSTALL=1 \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
assert_rc "build with conf-persisted ESP_PATH (no env) succeeds" 0 $?
assert_file_exists "UKI landed on the conf-recorded ESP" "$ESP3/EFI/Linux/alpine-fde-$KVER.efi"

finish
