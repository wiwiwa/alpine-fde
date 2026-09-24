#!/usr/bin/env bash
# tests/unit/policy_mode_ladder.sh — G-B4/ADR-19/ADR-20: on Alpine the sealing
# pipeline is Mechanism B (rung b) — systemd-cryptenroll is not packaged on
# Alpine (ADR-19), so rung b is the only implementable mechanism and is the
# canonical mode. A″ (a2 / a-prime-prime / native) remains ACCEPTED as an alias
# of the same policy construction. Rungs a / ap (and the combined-signature
# spelling a-prime/combined) stay documented-absent and fail closed (64) at
# every entry point:
#   * policy_mode_normalize — the common.sh boundary (unit level)
#   * `ukictl build` — rc 64 + ADR-8 build-failed marker + ESP byte-identical
#   * `enroll-tpm` — rc 64
# Every rejection cites ADR-19 ("Mechanism B (rung b) is the normative path").
# b's ACCEPTANCE at the entry points is asserted as the gate-passing observed
# effect (enroll-tpm proceeds past the mode gate into its baseline precondition).
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

for m in b a2 a-prime-prime native; do
    out=$(policy_mode_normalize "$m" 2>&1)
    rc=$?
    assert_rc "normalize: POLICY_MODE=$m accepted" 0 $rc
    assert_eq "normalize: $m canonicalizes to b" "b" "$out"
done

for m in a ap a-prime combined; do
    out=$(policy_mode_normalize "$m" 2>&1)
    rc=$?
    assert_rc "normalize: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "normalize: $m message cites ADR-19" "$out" "ADR-19"
    assert_contains "normalize: $m message names the normative Mechanism B path" "$out" "Mechanism B"
    assert_ne "normalize: $m emits no canonical mode on the rejected path" "$out" "b"
done

policy_mode_normalize definitely-not-a-mode >/dev/null 2>&1
assert_rc "normalize: unknown mode stays a plain reject (rc 1)" 1 $?

# --- entry points: ukictl build + enroll-tpm ---------------------------------------
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
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/alpine-fde/baseline.json"
printf 'pre-existing-uki' >"$ESP/EFI/Linux/alpine-fde-6.1.0-1-amd64.efi"

alpine-fde() {
    ALPINE_FDE_BIN_TEST=1 \
        ALPINE_FDE_ROOT="$ROOT" \
        ALPINE_FDE_ESP="$ESP" \
        ALPINE_FDE_KEYDIR="$KEYDIR" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        "$REPO/bin/alpine-fde" "$@"
}

ESP_BEFORE=$(find "$ESP" -type f -exec sha256sum {} + | sort)
for m in a ap; do
    out=$(POLICY_MODE=$m alpine-fde ukictl build "$KVER" 2>&1)
    rc=$?
    assert_rc "build: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "build: $m message cites ADR-19 (normalize boundary)" "$out" "ADR-19"
    assert_contains "build: $m message names the normative Mechanism B path" "$out" "Mechanism B"
    assert_file_exists "build: $m persists the ADR-8 failure marker" "$ROOT/etc/alpine-fde/build-failed"
    assert_eq "build: $m leaves the ESP byte-identical" "$ESP_BEFORE" \
        "$(find "$ESP" -type f -exec sha256sum {} + | sort)"
done

for m in a ap; do
    out=$(POLICY_MODE=$m alpine-fde enroll-tpm 2>&1)
    rc=$?
    assert_rc "enroll-tpm: POLICY_MODE=$m exits 64" 64 $rc
    assert_contains "enroll-tpm: $m message cites ADR-19" "$out" "ADR-19"
    assert_contains "enroll-tpm: $m message names the normative Mechanism B path" "$out" "Mechanism B"
done

# b is ACCEPTED at the entry points: the mode gate passes and the command moves
# on to its next precondition (absent baseline -> the "no baseline" failure, NOT
# a policy_mode rejection).
rm -f "$ROOT/etc/alpine-fde/baseline.json"
out=$(POLICY_MODE=b alpine-fde enroll-tpm 2>&1)
rc=$?
assert_rc "enroll-tpm: POLICY_MODE=b passes the mode gate (fails later on baseline)" 64 $rc
assert_not_contains "enroll-tpm: b rejection is not a mode rejection" "$out" "policy_mode"
assert_contains "enroll-tpm: b reached the baseline precondition" "$out" "no baseline"

finish
