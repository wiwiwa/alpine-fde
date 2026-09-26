#!/usr/bin/env bash
# tests/integration/ukictl_build_stub.sh — end-to-end `ukictl build` over stub inputs
# with the REAL ukify/sbsign/sbverify binaries (ukify 261 present) and the stub
# initramfs builder. Asserts the full contract: .pcrsig embedding (Mechanism
# A''), SB signature validity, manifest upsert/prune, predictions.json, marker
# cleared, idempotent rebuild (B-G1/G4/G5/G11; ladder §6.1).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"

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

KVER=6.12.8-1-amd64
KEYDIR="$REPO/fixtures/keys"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- fixture environment: stub root tree + ESP with retained old UKIs -------------
ROOT="$TMP/root"
ESP="$TMP/esp"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux"
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
# G-U4 (§8.2): the crypttab guard requires the tpm2-device= option at build time
printf '%s\n' 'root UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,discard' \
    >"$ROOT/etc/crypttab"
# finalized baseline: golden PCR 7 (the value paired with the golden vector)
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/alpine-fde/baseline.json"

# pre-existing retained UKIs (older kernels) + matching manifest entries,
# so prune + upsert behavior is exercised against real prior state
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    printf 'pre-existing-uki-%s' "$k" >"$ESP/EFI/Linux/alpine-fde-$k.efi"
done
. "$REPO/lib/common.sh"
. "$REPO/lib/manifest.sh"
. "$REPO/lib/keys.sh"
M="$ROOT/etc/alpine-fde/digests.json"
manifest_new "6.2.0-1-amd64" "fp-old" | manifest_atomic_write "$M"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    manifest_upsert "$M" "$k" "p11-old-$k" "pd-old-$k" "sig-old-$k"
done

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

# --- build -------------------------------------------------------------------------
out=$(alpine-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "ukictl build succeeds over stub inputs" 0 $rc

# --- ESP: canonical layout, .pcrsig/.pcrpkey embedded, SB signature valid ----------
UKI="$ESP/EFI/Linux/alpine-fde-$KVER.efi"
assert_file_exists "UKI installed at ESP:/EFI/Linux/alpine-fde-<kver>.efi" "$UKI"

ukify_inspect=$(ukify inspect "$UKI" 2>/dev/null || objdump -h "$UKI")
assert_contains "UKI carries a .pcrsig section (Mechanism A'' signed PCR 11)" "$ukify_inspect" ".pcrsig"
assert_contains "UKI carries a .pcrpkey section" "$ukify_inspect" ".pcrpkey"
sbverify --cert "$KEYDIR/release.crt" "$UKI" >/dev/null 2>&1
assert_rc "sbverify validates the installed UKI against the release cert" 0 $?

# --- manifest: schema v1, upsert replaced, prune matched the ESP keep set ----------
assert_eq "manifest schema version" "1" "$(jq -r .version "$M")"
assert_eq "manifest current_kernel" "$KVER" "$(jq -r .current_kernel "$M")"
entry=$(manifest_get "$M" "$KVER")
[ -n "$entry" ]
assert_rc "manifest has the built kernel's entry" 0 $?
assert_contains "manifest entry: signature recorded (a2 default)" "$entry" '"signature": "'
assert_eq "manifest: rebuilt entry replaced the seeded one (single entry for kver)" "1" \
    "$(jq --arg kver "$KVER" '[.digests[] | select(.kernel_version == $kver)] | length' "$M")"
assert_eq "prune: ESP keeps current + 2 (5.15.0 dropped)" "absent" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-5.15.0-3-amd64.efi" ] && echo present || echo absent)"
assert_eq "prune: kept 6.2.0" "present" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-6.2.0-1-amd64.efi" ] && echo present || echo absent)"
assert_eq "prune: manifest matches ESP (5.15.0 entry dropped)" "absent" \
    "$(jq -r 'if any(.digests[]; .kernel_version == "5.15.0-3-amd64") then "present" else "absent" end' "$M")"

# --- ladder fail-closed (ADR-19/ADR-20/G-B3): ap is documented-absent ---------------
# ADR-19/ADR-20: Mechanism B (rung b) is the normative pipeline; a2 is an
# accepted alias; ap/a exit 64 with an ADR-8 marker and never touch the ESP or
# the manifest (the combined-signature path is unreachable).
M="$ROOT/etc/alpine-fde/digests.json"
BEFORE_ESP_AP=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
BEFORE_MANIFEST_AP=$(cat "$M")
POLICY_MODE=ap alpine-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?; assert_rc "ap-mode rebuild fails closed (64, documented-absent)" 64 $rc
assert_file_exists "ap mode: ADR-8 failure marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "ap mode: marker cites ADR-19/ADR-20" "$(cat "$ROOT/etc/alpine-fde/build-failed")" "ADR-19"
assert_eq "ap mode: ESP byte-identical (refusing to touch the ESP)" \
    "$BEFORE_ESP_AP" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"
assert_eq "ap mode: manifest untouched" "$BEFORE_MANIFEST_AP" "$(cat "$M")"
# restore the default (a2) build so later sections see the canonical state
# (and verify a successful build clears the failure marker, §8.3 recovery)
POLICY_MODE=a2 alpine-fde ukictl build "$KVER" >/dev/null 2>&1
assert_rc "a2-mode rebuild restores canonical state" 0 $?
[ ! -e "$ROOT/etc/alpine-fde/build-failed" ]
assert_rc "a2 rebuild cleared the failure marker" 0 $?
M="$ROOT/etc/alpine-fde/digests.json"

# --- policy_digest correctness: golden d7 paired with the REAL predicted pcr11 -----
P11=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .pcr11_digest' "$M")
. "$REPO/lib/policy.sh"
D7=$(jq -r .expected_pcr7 "$ROOT/etc/alpine-fde/baseline.json")
assert_eq "manifest pcr11 is a 64-hex sha256 digest (ukify prediction)" "64" "${#P11}"
assert_eq "manifest policy_digest == golden formula(d7, pcr11)" \
    "$(policy_digest "$D7" "$P11")" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")"

# a2 contract: manifest signature field is EMPTY (pcrsign skipped; §6.1 ladder)
SIG=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .signature' "$M")
assert_eq "a2: manifest signature empty (pcrsign skipped)" "" "$SIG"

# --- predictions.json (B-G11) --------------------------------------------------------
P="$ROOT/etc/alpine-fde/predictions.json"
assert_file_exists "predictions.json emitted" "$P"
assert_eq "predictions: phase pinned to enter-initrd" "enter-initrd" "$(jq -r .phase "$P")"
assert_eq "predictions: pcr11 matches manifest" "$P11" "$(jq -r .pcr11_digest "$P")"
assert_eq "predictions: policy_digest matches manifest" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")" \
    "$(jq -r .policy_digest "$P")"
assert_eq "predictions: uki_size == installed UKI size" \
    "$(wc -c <"$UKI" | tr -d '[:space:]')" "$(jq -r .uki_size "$P")"
assert_contains "predictions: section digests include .pcrsig" "$(jq -r '.sections | keys | join(" ")' "$P")" "pcrsig"
[ -n "$(jq -r .tools.ukify "$P")" ]
assert_rc "predictions: tool versions recorded (ukify non-empty)" 0 $?
assert_eq "predictions: policy_mode recorded (normalized b; a2 is an alias)" "b" \
    "$(jq -r .policy_mode "$P")"

# --- failure marker cleared on success ------------------------------------------------
[ ! -e "$ROOT/etc/alpine-fde/build-failed" ]
rc=$?
assert_rc "no failure marker after a successful build" 0 "$rc"

# --- idempotent rebuild: same inputs -> same pcr11/policy_digest, count stable --------
out=$(alpine-fde ukictl build "$KVER" 2>&1)
assert_rc "rebuild of the same kernel succeeds (idempotent)" 0 $?
assert_eq "rebuild: entry count unchanged" "3" "$(jq '.digests | length' "$M")"
assert_eq "rebuild: pcr11 unchanged (deterministic stub inputs)" "$P11" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .pcr11_digest' "$M")"
assert_eq "rebuild: policy_digest unchanged" "$(policy_digest "$D7" "$P11")" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")"

# --- a2 mode: pcrsign skipped, policy_digest still recorded ---------------------------
POLICY_MODE=a2 alpine-fde ukictl build "$KVER" >/dev/null 2>&1
assert_rc "a2-mode build succeeds" 0 $?
a2sig=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .signature' "$M")
a2pd=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")
[ -z "$a2sig" ]
assert_rc "a2: signature field empty (pcrsign not invoked)" 0 $?
assert_eq "a2: policy_digest still computed (audit/display data)" "$(policy_digest "$D7" "$P11")" "$a2pd"

# --- remove verb (postrm wire) ----------------------------------------------------------
alpine-fde ukictl remove "6.2.0-1-amd64" >/dev/null 2>&1
assert_rc "ukictl remove succeeds" 0 $?
assert_eq "remove: ESP file gone" "absent" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-6.2.0-1-amd64.efi" ] && echo present || echo absent)"
assert_eq "remove: manifest entry gone" "absent" \
    "$(jq -r 'if any(.digests[]; .kernel_version == "6.2.0-1-amd64") then "present" else "absent" end' "$M")"

# --- re-sign-all (B-G8; §9.6 step 6): baseline d7 change re-signs everything -------
# After a d7 rotation: every retained entry's policy_digest is recomputed over the
# NEW d7, every stored signature re-verifies (policy_verify), the failure marker
# is cleared, and the ESP UKI bytes (incl. the A'' .pcrsig section) are unchanged —
# re-sign-all never rebuilds UKIs (.pcrsig is d7-independent under A'').
# The retained 6.1.0 entry models a real prior build: it needs a valid stored
# pcr11 (the earlier seed used placeholder strings that policy_check_digest
# rejects — re-sign-all must die 64 on those, which is its own contract).
P11_610=$(printf 'ukictl-build-stub: retained 6.1.0 pcr11' | sha256sum | awk '{print $1}')
D7_GOLDEN=$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")
manifest_upsert "$M" "6.1.0-1-amd64" "$P11_610" "$(policy_digest "$D7_GOLDEN" "$P11_610")" ""

ESP_BEFORE=$(find "$ESP" -type f -name '*.efi' -exec sha256sum {} + | sort)
UKI_CUR="$ESP/EFI/Linux/alpine-fde-$KVER.efi"
objcopy -O binary --only-section=.pcrsig "$UKI_CUR" "$TMP/pcrsig.before" 2>/dev/null
PCRSIG_BEFORE=$(sha256sum "$TMP/pcrsig.before" | awk '{print $1}')
: >"$ROOT/etc/alpine-fde/build-failed" # stale marker must be cleared by re-sign-all
D7OLD=$(jq -r .expected_pcr7 "$ROOT/etc/alpine-fde/baseline.json")
D7NEW=$(printf 'ukictl-build-stub: rotated baseline pcr7' | sha256sum | awk '{print $1}')
assert_ne "re-sign-all: sanity — rotated d7 differs from the seeded one" "$D7NEW" "$D7OLD"
jq -n --arg d7 "$D7NEW" '{expected_pcr7: $d7, status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"

alpine-fde ukictl build --re-sign-all >/dev/null 2>&1
assert_rc "ukictl build --re-sign-all succeeds" 0 $?

[ ! -e "$ROOT/etc/alpine-fde/build-failed" ]
assert_rc "re-sign-all: failure marker cleared" 0 $?

# MD-03: predictions.json is refreshed in the SAME pass — a stale policy_digest
# would trip the harness prediction checks (§12) after every re-sign-all.
assert_eq "re-sign-all: predictions.json policy_digest refreshed over the new d7" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")" \
    "$(jq -r .policy_digest "$ROOT/etc/alpine-fde/predictions.json")"

assert_eq "re-sign-all: ESP UKI bytes unchanged (no rebuild)" "$ESP_BEFORE" \
    "$(find "$ESP" -type f -name '*.efi' -exec sha256sum {} + | sort)"
objcopy -O binary --only-section=.pcrsig "$UKI_CUR" "$TMP/pcrsig.after" 2>/dev/null
assert_eq "re-sign-all: .pcrsig section unchanged (A'': d7-independent)" \
    "$PCRSIG_BEFORE" "$(sha256sum "$TMP/pcrsig.after" | awk '{print $1}')"

. "$REPO/lib/policy.sh"
for k in $(manifest_kvers "$M"); do
    k_p11=$(jq -r --arg kver "$k" '.digests[] | select(.kernel_version == $kver) | .pcr11_digest' "$M")
    k_pd=$(jq -r --arg kver "$k" '.digests[] | select(.kernel_version == $kver) | .policy_digest' "$M")
    k_sig=$(jq -r --arg kver "$k" '.digests[] | select(.kernel_version == $kver) | .signature' "$M")
    assert_eq "re-sign-all: $k policy_digest recomputed over the NEW d7" \
        "$(policy_digest "$D7NEW" "$k_p11")" "$k_pd"
    printf '%s' "$k_sig" | openssl base64 -d -A >"$TMP/$k.sig"
    policy_verify "$TMP/$k.sig" "$D7NEW" "$k_p11" "$KEYDIR/release.pub"
    assert_rc "re-sign-all: $k signature verifies over (new d7, pcr11) via policy_verify" 0 $?
done

# --- re-sign-all negative branches: fail closed, touch NOTHING (signing F-3) ----------
# The comment on the positive section names this contract without testing it:
# a stored pcr11_digest that policy_check_digest rejects must kill re-sign-all
# with 64 (ukictl-build.sh), leave the manifest and the ESP byte-identical, and
# persist/refresh the ADR-8 failure marker naming the corrupt entry (ADR-8:
# every failing signing flow leaves the marker visible to `status`); a MISSING
# manifest is likewise a loud 64.
cp "$M" "$TMP/man.canonical"
ESP_BEFORE_NEG=$(find "$ESP" -type f -exec sha256sum {} \; | sort)

# (a) invalid stored pcr11 in the manifest -> die 64, marker written, rest untouched
rm -f "$ROOT/etc/alpine-fde/build-failed"
jq '.digests |= map(.pcr11_digest = "zz-invalid-pcr11-placeholder")' "$M" >"$TMP/man.bad" \
    && mv "$TMP/man.bad" "$M"
cp "$M" "$TMP/man.bad.snapshot"   # the comparison baseline: corrupt-but-untouched
out=$(alpine-fde ukictl build --re-sign-all 2>&1)
rc=$?
assert_rc "re-sign-all: invalid stored pcr11 -> exit 64" 64 $rc
assert_contains "re-sign-all: message names the corrupt entry" "$out" "has no stored pcr11_digest"
assert_file_exists "re-sign-all: ADR-8 marker persisted by the failing flow" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "re-sign-all: marker names the kernel" "$(cat "$ROOT/etc/alpine-fde/build-failed")" "$KVER"
assert_contains "re-sign-all: marker records the reason" "$(cat "$ROOT/etc/alpine-fde/build-failed")" "re-sign-all"
assert_eq "re-sign-all: manifest byte-identical (die precedes any upsert)" \
    "$(cat "$TMP/man.bad.snapshot")" "$(cat "$M")"
assert_eq "re-sign-all: ESP byte-identical (no rebuild, no writes)" \
    "$ESP_BEFORE_NEG" "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"

# (b) missing manifest -> die 64
mv "$M" "$TMP/man.hold"
out=$(alpine-fde ukictl build --re-sign-all 2>&1)
rc=$?
assert_rc "re-sign-all: missing manifest -> exit 64" 64 $rc
assert_contains "re-sign-all: missing-manifest message" "$out" "no manifest"
mv "$TMP/man.hold" "$M"

# restore the canonical manifest and prove it: re-sign-all succeeds again and
# clears the stale marker (later sections, if any, see the pre-negative state)
cp "$TMP/man.canonical" "$M"
alpine-fde ukictl build --re-sign-all >/dev/null 2>&1
assert_rc "re-sign-all: canonical manifest restored (re-sign succeeds)" 0 $?
[ ! -e "$ROOT/etc/alpine-fde/build-failed" ]
assert_rc "re-sign-all: restored success clears the stale marker" 0 $?

# --- MD-03: pending baseline d7 -> the precheck refuses BEFORE the loop -------------
# (a pending d7 used to die inside the FIRST policy_digest call — after earlier
# entries had already been upserted: a torn manifest + leaked temps + marker gap)
PRED_P="$ROOT/etc/alpine-fde/predictions.json"
jq '.expected_pcr7 = ""' "$ROOT/etc/alpine-fde/baseline.json" >"$TMP/bl.pending" \
    && mv "$TMP/bl.pending" "$ROOT/etc/alpine-fde/baseline.json"
cp "$M" "$TMP/man.pre-pending"
rm -f "$ROOT/etc/alpine-fde/build-failed"
PRED_BEFORE=$(cat "$PRED_P")
out=$(TMPDIR="$TMP" alpine-fde ukictl build --re-sign-all 2>&1)
rc=$?
assert_rc "re-sign-all: pending baseline PCR 7 -> exit 64" 64 $rc
assert_contains "re-sign-all: precheck points at audit --init" "$out" "audit --init"
assert_file_exists "re-sign-all: pending precheck persists the ADR-8 marker" "$ROOT/etc/alpine-fde/build-failed"
assert_eq "re-sign-all: manifest NOT torn by the refused loop" \
    "$(cat "$TMP/man.pre-pending")" "$(cat "$M")"
assert_eq "re-sign-all: predictions.json untouched by the refusal" "$PRED_BEFORE" "$(cat "$PRED_P")"
assert_eq "re-sign-all: no resign temp files leaked" "" \
    "$(find "$TMP" -maxdepth 1 -name 'alpine-fde-resign.*' -print)"
# restore the finalized baseline
jq -n --arg d7 "$D7NEW" '{expected_pcr7: $d7, status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"

# --- MD-03: transactional re-sign — a MID-LOOP failure rewrites NOTHING --------------
# corrupt ONLY the second entry: the first is processable, so a non-transactional
# loop would upsert it into the live manifest before dying on the second.
jq '(.digests[] | select(.kernel_version == "6.1.0-1-amd64") | .pcr11_digest) = "zz-invalid-midloop"' \
    "$M" >"$TMP/man.mid" && mv "$TMP/man.mid" "$M"
cp "$M" "$TMP/man.mid.snapshot"
rm -f "$ROOT/etc/alpine-fde/build-failed"
out=$(alpine-fde ukictl build --re-sign-all 2>&1)
rc=$?
assert_rc "re-sign-all: mid-loop invalid pcr11 -> exit 64" 64 $rc
assert_eq "re-sign-all: live manifest byte-identical across the mid-loop die" \
    "$(cat "$TMP/man.mid.snapshot")" "$(cat "$M")"
assert_file_exists "re-sign-all: mid-loop failure persists the marker" "$ROOT/etc/alpine-fde/build-failed"
# restore canonical state for the remaining legs
cp "$TMP/man.canonical" "$M"
alpine-fde ukictl build --re-sign-all >/dev/null 2>&1
assert_rc "re-sign-all: state restored again" 0 $?

# --- LO-01: kver is validated on the CLI surface (traversal / spaces -> usage 2) -----
out=$(alpine-fde ukictl remove '../../../evil' 2>&1)
rc=$?
assert_rc "ukictl remove: traversal kver rejected as usage (2)" 2 "$rc"
out=$(alpine-fde ukictl build 'bad kver' 2>&1)
rc=$?
assert_rc "ukictl build: spaced kver rejected as usage (2)" 2 "$rc"
out=$(alpine-fde ukictl build $'semi;colon' 2>&1)
rc=$?
assert_rc "ukictl build: shell-meta kver rejected as usage (2)" 2 "$rc"
assert_eq "remove: traversal kver touched no ESP path outside the UKI dir" "" \
    "$(find "$ROOT" -name '*evil*' -print 2>/dev/null)"

# --- MD-02: config-derived paths with spaces survive argv construction ---------------
KEYDIR_SP="$TMP/my keys"
ln -s "$REPO/fixtures/keys" "$KEYDIR_SP"
ALPINE_FDE_BIN_TEST=1 \
    ALPINE_FDE_ROOT="$ROOT" \
    ALPINE_FDE_ESP="$ESP" \
    ALPINE_FDE_KEYDIR="$KEYDIR_SP" \
    ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
assert_rc "build with a SPACED keydir succeeds (ukify argv intact)" 0 $?
sbverify --cert "$KEYDIR_SP/release.crt" "$ESP/EFI/Linux/alpine-fde-$KVER.efi" >/dev/null 2>&1
assert_rc "spaced-keydir build still ships a validly signed UKI" 0 $?
# restore the canonical keydir build (marker cleared)
alpine-fde ukictl build "$KVER" >/dev/null 2>&1
assert_rc "canonical build after the spaced-keydir leg" 0 $?

# --- HW-1: a die inside the body (ESP install) persists the marker AND wipes the
# workdir — no leak of the unsigned UKI/initrd on ^C-style or lib-die failures.
ESP_BAD="$TMP/esp-bad"
mkdir -p "$ESP_BAD"
printf 'not-a-directory' >"$ESP_BAD/EFI" # ESP/EFI is a FILE -> mkdir ESP/EFI/Linux fails -> esp_install_uki dies
rm -f "$ROOT/etc/alpine-fde/build-failed"
out=$(env -u ALPINE_FDE_ESP TMPDIR="$TMP" \
    ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP_BAD" \
    ALPINE_FDE_KEYDIR="$KEYDIR" ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 "$REPO/bin/alpine-fde" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "ESP-install die fails the build closed (64)" 64 "$rc"
assert_file_exists "ESP-install die persists the ADR-8 marker (HW-1)" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "marker records the failure" "$(cat "$ROOT/etc/alpine-fde/build-failed")" "ukictl build failed"
assert_eq "build workdir wiped on the die path (no leak)" "" \
    "$(find "$TMP" -maxdepth 1 -name 'alpine-fde-build.*' -print)"
assert_file_exists "previously installed UKI untouched by the failed build" \
    "$ESP/EFI/Linux/alpine-fde-$KVER.efi"

# --- LO-04: ESP-prune failure is a MARKED build failure (no silent divergence) -------
FAKEBIN2="$TMP/bin2"
ESP2="$TMP/esp-prunefail"
mkdir -p "$FAKEBIN2" "$ESP2/EFI/Linux"
VICTIM="$ESP2/EFI/Linux/alpine-fde-5.15.0-3-amd64.efi"
cat >"$FAKEBIN2/rm" <<EOF
#!/bin/sh
for a in "\$@"; do
    [ "\$a" = "$VICTIM" ] && { echo "rm: cannot remove '$VICTIM': simulated EROFS" >&2; exit 1; }
done
exec /bin/rm "\$@"
EOF
chmod +x "$FAKEBIN2/rm"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    printf 'seed-%s' "$k" >"$ESP2/EFI/Linux/alpine-fde-$k.efi"
done
rm -f "$ROOT/etc/alpine-fde/build-failed"
env PATH="$FAKEBIN2:$PATH" TMPDIR="$TMP" \
    ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP2" \
    ALPINE_FDE_KEYDIR="$KEYDIR" ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "prune failure fails the build loudly (64)" 64 "$rc"
assert_file_exists "prune failure persists the ADR-8 marker" "$ROOT/etc/alpine-fde/build-failed"
assert_file_exists "failed prune left the victim file on the ESP (fail-safe)" "$VICTIM"
assert_eq "prune-failure build wiped its workdir" "" \
    "$(find "$TMP" -maxdepth 1 -name 'alpine-fde-build.*' -print)"

# --- WR-02: a failing rm in the EXIT trap must not eat the marker or the rc ---
# strict_mode (set -eu) is inherited by _uk_cleanup; an unguarded rm that fails
# (EROFS/EIO) aborts the trap BEFORE the ADR-8 marker write and replaces the
# exit status with the rm's. The PATH stub fails ONLY the build-workdir rm;
# everything else delegates to /bin/rm. Failure point: the initrd audit (a
# failing lister) — past workdir creation, so the trap runs with _uk_work set
# and rc 64. Post-fix, the workdir residue is EXPECTED (cleanup is best effort
# when the medium fights back); the marker and the original rc must survive.
FAKEBIN3="$TMP/bin3"
mkdir -p "$FAKEBIN3"
cat >"$FAKEBIN3/rm" <<EOF
#!/bin/sh
for a in "\$@"; do
    case \$a in */alpine-fde-build.*)
        echo "rm: cannot remove '\$a': simulated EROFS" >&2; exit 1 ;;
    esac
done
exec /bin/rm "\$@"
EOF
chmod +x "$FAKEBIN3/rm"
rm -f "$ROOT/etc/alpine-fde/build-failed"
env PATH="$FAKEBIN3:$PATH" TMPDIR="$TMP" \
    INITRD_LISTER_CMD=/bin/false \
    ALPINE_FDE_BIN_TEST=1 ALPINE_FDE_ROOT="$ROOT" ALPINE_FDE_ESP="$ESP" \
    ALPINE_FDE_KEYDIR="$KEYDIR" ALPINE_FDE_NO_INSTALL=1 \
    ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
    INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
    RETENTION=2 \
    "$REPO/bin/alpine-fde" ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "WR-02: audit-failed build still exits 64 when the workdir rm fails" 64 "$rc"
assert_file_exists "WR-02: ADR-8 marker written even though the workdir rm failed" \
    "$ROOT/etc/alpine-fde/build-failed"
assert_contains "WR-02: marker records the audit failure" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "initrd audit"
[ -n "$(find "$TMP" -maxdepth 1 -name 'alpine-fde-build.*' -print)" ]
assert_rc "WR-02: rm stub actually fired (workdir residue proves the leg is live)" 0 $?

# --- ADR-18/G-KC4: encrypted release.pem unlock seam --------------------------------
# keys_check only proves release.pem EXISTS. When it is the ADR-18 encrypted
# form, `ukictl build` must unlock it ONCE via keys_unlock (ALPINE_FDE_KEY_
# PASSPHRASE env -> TTY prompt -> loud 64) and hand the UNLOCKED tmpfs path to
# ukify --pcr-private-key, sbsign --key and policy_sign; the decrypted copy is
# scrubbed by the build's EXIT-trap net. A plaintext release.pem (offline
# medium, legacy) keeps the previous behavior with zero passphrase interaction.
. "$REPO/lib/keys.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
ENC_PASS='ci-unlock-passphrase-600000'

mkdir -p "$TMP/shm"
ENC_KEYDIR="$TMP/enc-keys"
mkdir -p "$ENC_KEYDIR"
cp "$REPO/fixtures/keys/release.pem" "$ENC_KEYDIR/release.pem"
cp "$REPO/fixtures/keys/release.crt" "$ENC_KEYDIR/release.crt"
cp "$REPO/fixtures/keys/release.pub" "$ENC_KEYDIR/release.pub"
ALPINE_FDE_KEY_PASSPHRASE=$ENC_PASS ALPINE_FDE_TMPDIR="$TMP/shm" \
    keys_encrypt_release "$ENC_KEYDIR" >/dev/null 2>&1
[ "$?" -eq 0 ] || { echo "fixture: encrypting release.pem failed" >&2; exit 1; }

# argv-recording wrappers: log the invocation, then exec the REAL binary
WRAPBIN="$TMP/wrapbin"
mkdir -p "$WRAPBIN"
ARGVLOG="$TMP/signer-argv.log"
for b in ukify sbsign sbverify; do
    real=$(command -v "$b")
    cat >"$WRAPBIN/$b" <<EOF
#!/bin/sh
printf '%s %s\n' "$b" "\$*" >>'$ARGVLOG'
exec $real "\$@"
EOF
    chmod +x "$WRAPBIN/$b"
done
: >"$ARGVLOG"

enc_alpine_fde() { # PASSPHRASE(possibly empty string = unset) args...
    _enc_pass=$1
    shift
    if [ -n "$_enc_pass" ]; then
        export ALPINE_FDE_KEY_PASSPHRASE=$_enc_pass
    else
        unset ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || :
    fi
    ALPINE_FDE_BIN_TEST=1 \
        ALPINE_FDE_ROOT="$ROOT" \
        ALPINE_FDE_ESP="$ESP" \
        ALPINE_FDE_KEYDIR="$ENC_KEYDIR" \
        ALPINE_FDE_TMPDIR="$TMP/shm" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/alpine-fde.conf" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        PATH="$WRAPBIN:$PATH" \
        "$REPO/bin/alpine-fde" "$@" </dev/null
}

# leg A: encrypted key + NO passphrase env + NO tty -> 64 + ADR-8 marker
BEFORE_ESP_A=$(find "$ESP" -type f -exec sha256sum {} \; | sort)
rm -f "$ROOT/etc/alpine-fde/build-failed"
out=$(enc_alpine_fde "" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "unlock: encrypted key, no env, no tty -> exit 64" 64 $rc
assert_contains "unlock: loud message demands a passphrase (env or interactive)" "$out" \
    "passphrase required; provide ALPINE_FDE_KEY_PASSPHRASE or run interactively"
assert_file_exists "unlock: ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "unlock: marker names the missing credential" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "passphrase required"
assert_eq "unlock: ESP byte-identical (refusal before any signing)" "$BEFORE_ESP_A" \
    "$(find "$ESP" -type f -exec sha256sum {} \; | sort)"
assert_eq "unlock: no signer ever saw the encrypted file" "0" \
    "$(grep -c "$ENC_KEYDIR/release.pem" "$ARGVLOG" 2>/dev/null; true)"

# leg B: WRONG passphrase via the env seam -> 64 + marker naming wrong-passphrase
rm -f "$ROOT/etc/alpine-fde/build-failed"
out=$(enc_alpine_fde "definitely-not-the-passphrase" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "unlock: wrong env passphrase -> exit 64" 64 $rc
assert_contains "unlock: wrong-passphrase message is distinct" "$out" "wrong passphrase"
assert_file_exists "unlock: wrong-passphrase ADR-8 marker persisted" "$ROOT/etc/alpine-fde/build-failed"
assert_contains "unlock: marker names wrong-passphrase" \
    "$(cat "$ROOT/etc/alpine-fde/build-failed")" "wrong passphrase"

# leg C: correct env passphrase -> build proceeds over the UNLOCKED tmpfs path
rm -f "$ROOT/etc/alpine-fde/build-failed" "$ARGVLOG"
out=$(enc_alpine_fde "$ENC_PASS" ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "unlock: correct env passphrase -> build succeeds" 0 $rc
assert_eq "unlock: no failure marker after the successful build" "0" \
    "$([ -e "$ROOT/etc/alpine-fde/build-failed" ] && echo 1 || echo 0)"
ARGV_CONTENT=$(cat "$ARGVLOG")
assert_contains "unlock: ukify got the UNLOCKED tmpfs key (--pcr-private-key)" "$ARGV_CONTENT" \
    "--pcr-private-key=$TMP/shm/"
assert_contains "unlock: sbsign got the UNLOCKED tmpfs key (--key)" "$ARGV_CONTENT" \
    "sbsign --key $TMP/shm/"
assert_eq "unlock: no signer ever saw the encrypted path" "0" \
    "$(grep -c "$ENC_KEYDIR/release.pem" "$ARGVLOG"; true)"
assert_eq "unlock: decrypted copy scrubbed after the build (tmpfs clean)" "" \
    "$(find "$TMP/shm" -maxdepth 1 -name 'alpine-fde-unlock.*' -print 2>/dev/null)"
sbverify --cert "$ENC_KEYDIR/release.crt" "$ESP/EFI/Linux/alpine-fde-$KVER.efi" >/dev/null 2>&1
assert_rc "unlock: installed UKI verifies against the release cert" 0 $?

# leg D: plaintext keydir -> unchanged behavior (no unlock, keydir path used)
rm -f "$ARGVLOG"
PATH="$WRAPBIN:$PATH" alpine-fde ukictl build "$KVER" >/dev/null 2>&1
assert_rc "unlock: plaintext release.pem build unchanged (rc 0)" 0 $?
ARGV_CONTENT=$(cat "$ARGVLOG")
assert_contains "unlock: plaintext build hands the KEYDIR path to ukify" "$ARGV_CONTENT" \
    "--pcr-private-key=$KEYDIR/release.pem"
assert_eq "unlock: plaintext build touched no tmpfs unlock file" "" \
    "$(find "$TMP/shm" -maxdepth 1 -name 'alpine-fde-unlock.*' -print 2>/dev/null)"

# kept LAST: this second build mutates manifest current_kernel/keep-set state
# that the earlier sections pin against
# --- boot-lane finding #9 (s23 attempt 9): Alpine ships FLAVOR-named kernels
# (/boot/vmlinuz-lts, modules at /lib/modules/<kver>), NOT vmlinuz-<kver>.
# A real install resolves the target kver (6.18.53-0-lts) but the kernel file
# is vmlinuz-lts — the build must fall back to the flavor name or every real
# install dies at step 5 ("required build input missing").
KVER2=6.18.53-0-lts
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-lts"
out2=$(alpine-fde ukictl build "$KVER2" 2>&1)
rc2=$?
assert_rc "ukictl build: Alpine flavor-named kernel (/boot/vmlinuz-lts) resolves" 0 $rc2
assert_file_exists "ukictl build: UKI produced for the flavor-named kernel kver" \
    "$ESP/EFI/Linux/alpine-fde-$KVER2.efi"

finish


