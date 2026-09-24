#!/usr/bin/env bash
# tests/e2e/e2e_infra_smoke.sh — G-T11b artifact scans over the BUILT s00/s00b
# state (the s00-side disk scans; the unit-side fixture scans live in
# tests/unit/e2e_infra_smoke.sh, which also runs as run-e2e.sh's harness
# self-test gate BEFORE any scenario).
#
# What this scans (I2/I4): the artifacts the bootstrap scenarios actually
# built — the ESP image, the UKI binaries, the .pcrsig payload drive, the
# rootfs payload drive and the LUKS header — for PRIVATE key material:
# PEM "PRIVATE KEY" headers and .pem/.key filenames (public trust-store
# certs excluded; binaries and indented doc samples accounted for — see the
# init-side in-guest scan in tests/lib/uki-build.sh installer_stage, whose
# console line is cross-checked here).
#
# State selection (first match wins):
#   $ALPINE_FDE_E2E_STATE | $ALPINE_FDE_S00_STATE | the newest
#   s00b-enroll-* run dir | the newest s00-bootstrap-* run dir (under
#   tests/e2e/.runs/).
#
# Exit codes: 0 clean, 1 scan failure (key material / broken state),
# 64 nothing to scan (no state dir — fail-closed: an empty scan is not a
# pass). run-e2e.sh calls this after the scenario loop over the run dirs
# produced in that invocation.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"

PRIKEY_RE='^-----BEGIN [A-Z ]*PRIVATE KEY-----'

_state_dir() {
    local d
    for d in "${ALPINE_FDE_E2E_STATE:-}" "${ALPINE_FDE_S00_STATE:-}"; do
        [[ -n "$d" && -d "$d" ]] && { printf '%s\n' "$d"; return 0; }
    done
    # newest first (glob expansion is sorted): s00b (enrolled, newest state)
    # before s00 (populated only)
    for d in "$TESTS"/e2e/.runs/s00b-enroll-* "$TESTS"/e2e/.runs/s00-bootstrap-*; do
        [[ -d "$d" ]] || continue
        printf '%s\n' "$d"
        return 0
    done
    return 1
}

STATE=$(_state_dir) || {
    echo "e2e_infra_smoke: nothing to scan — no s00/s00b state dir (run s00/s00b first, or set ALPINE_FDE_E2E_STATE / ALPINE_FDE_S00_STATE)" >&2
    exit 64
}
echo "# e2e_infra_smoke: scanning state dir $STATE"

# --- the state must be complete enough to scan -----------------------------------
for f in disk.img esp.img harness.efi; do
    assert_file_exists "artifact present: $f" "$STATE/$f"
done

# --- ESP: no .pem/.key listed, no PRIVATE KEY block in the boot binary -----------
if [[ -f "$STATE/esp.img" ]]; then
    ESPLIST=$(mdir -i "$STATE/esp.img" -/ :: 2>/dev/null | grep -Ei '\.(pem|key)' || true)
    assert_eq "ESP lists no .pem/.key files" "" "$ESPLIST"
    if mcopy -i "$STATE/esp.img" ::/EFI/BOOT/BOOTX64.EFI "$STATE/.smoke-bootx64.efi" 2>/dev/null; then
        HITS=$(grep -alE "$PRIKEY_RE" "$STATE/.smoke-bootx64.efi" 2>/dev/null || true)
        assert_eq "ESP boot binary carries no PRIVATE KEY PEM block" "" "$HITS"
        rm -f "$STATE/.smoke-bootx64.efi"
    else
        _assert_result not-ok "ESP boot binary carries no PRIVATE KEY PEM block" \
            "could not extract BOOTX64.EFI from $STATE/esp.img"
    fi
fi

# --- UKI binaries: no PRIVATE KEY block --------------------------------------------
for uki in "$STATE"/harness.efi "$STATE"/uki-release.efi; do
    [[ -f "$uki" ]] || continue
    HITS=$(grep -alE "$PRIKEY_RE" "$uki" 2>/dev/null || true)
    assert_eq "$(basename "$uki") carries no PRIVATE KEY PEM block" "" "$HITS"
done

# --- .pcrsig payload drive: signature material only, no keys -----------------------
if [[ -f "$STATE/pcrsig.img" ]]; then
    PCRSIG_TXT=$(dd if="$STATE/pcrsig.img" bs=4096 count=16 2>/dev/null | tr -d '\000')
    HITS=$(grep -aE "$PRIKEY_RE" <<<"$PCRSIG_TXT" || true)
    assert_eq ".pcrsig payload carries no PRIVATE KEY PEM block" "" "$HITS"
    assert_contains ".pcrsig payload is the signed-policy JSON (pol entries)" \
        "$PCRSIG_TXT" '"pol"'
fi

# --- rootfs payload drive: the pinned/derived artifact is scanned DECOMPRESSED -----
# (PEM headers inside the gzip stream are invisible to a raw grep)
if [[ -f "$STATE/rootfs-payload.img" ]]; then
    # trim the MiB padding back to the artifact, then decompress-scan.
    # HI-03: decompression failure must FAIL the scan — never scan-vacuously.
    cp "$STATE/rootfs-payload.img" "$STATE/.smoke-rootfs.gz" 2>/dev/null
    if gzip -dc "$STATE/.smoke-rootfs.gz" 2>/dev/null >"$STATE/.smoke-rootfs.tar"; then
        ART_BYTES=$(grep -acE "$PRIKEY_RE" "$STATE/.smoke-rootfs.tar" || true)
        assert_eq "rootfs payload (decompressed) carries no PRIVATE KEY PEM headers" "0" "$ART_BYTES"
    else
        _assert_result not-ok "rootfs payload (decompressed) carries no PRIVATE KEY PEM headers" \
            "decompression failed"
    fi
    rm -f "$STATE/.smoke-rootfs.gz" "$STATE/.smoke-rootfs.tar"
fi

# --- LUKS header area: metadata JSON only, no key material --------------------------
if [[ -f "$STATE/disk.img" ]]; then
    HITS=$(head -c 4194304 "$STATE/disk.img" | grep -acE "$PRIKEY_RE" || true)
    assert_eq "LUKS header area carries no PRIVATE KEY PEM block" "0" "$HITS"
fi

# --- cross-check the guest's own in-guest scan (s00 console evidence) ---------------
if [[ -f "$STATE/console.log" ]]; then
    SCAN_LINE=$(grep -oE 'alpine-fde-scan: keyfiles=[0-9]+ pem=[0-9]+' "$STATE/console.log" | head -1)
    if [[ -n "$SCAN_LINE" ]]; then
        assert_eq "in-guest scan (console evidence) reports no key material" \
            "alpine-fde-scan: keyfiles=0 pem=0" "$SCAN_LINE"
    else
        echo "# e2e_infra_smoke: NOTE no in-guest scan line in $STATE/console.log (pre-s00 state?) — skipped"
    fi
fi

echo "# e2e_infra_smoke: pass=$TESTS_PASS fail=$TESTS_FAIL"
if (( TESTS_FAIL > 0 )); then
    exit 1
fi
exit 0
