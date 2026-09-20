#!/usr/bin/env bash
# tests/unit/ukictl_build_enroll_wire.sh — G-U1/G-U2/G-R3/G-D12: `ukictl build`
# carries the ENSURE-ONCE Mechanism B enrollment step (ADR-19/ADR-20; after the
# manifest update, BEFORE prune; wired to the ADR-8 marker path). Exercised
# END-TO-END: REAL swtpm (the seal ops are the production lib/seal.sh path),
# REAL file-backed LUKS2 container (the keyslot/token choreography mutates real
# metadata), a DEBIAN_FDE_CRYPTSETUP logging wrapper around the REAL cryptsetup
# (argv observability), and a PATH systemd-cryptenroll TRIPWIRE (must NEVER be
# invoked — ADR-19). Pinned contract:
#   T1. no systemd-tpm2 token → exactly ONE Mechanism B enrollment (fresh
#       keyslot via luksAddKey, systemd-tpm2 token {PCR 7, PCR 11} imported;
#       release-key-signed policy, G-B6); enrolled.json (policy_mode b) +
#       manifest keyslot/token_id recorded; marker cleared; prune ran
#   T2. token already standing → metadata read ONLY (zero mutating cryptsetup
#       calls, s14: kernel updates are TPM-free), rc 0, info line
#   T3. manifest entries carry keyslot + token_id matching enrolled.json
#       (repeated per entry — bookkeeping, §8.4)
#   T4. enroll failure → rc 64 + marker + prune did NOT run
#   T5. recovery build succeeds and clears the marker (prune runs)
#   T6. NEW kver built while the token STANDS → the standing enrollment's
#       keyslot/token_id stamped onto the NEW kver's manifest entry too
#       (§8.4) — metadata read only, zero mutating calls
#   T7. volume unreachable → rc 0, warning names the volume, ZERO contact,
#       no marker, NEW entry with EMPTY keyslot/token_id (documented escape)
#   T8. >1 standing tokens → LOUD refusal (manual intervention), marker,
#       zero mutating calls
#   T9. the enrollment holds the ensure-once lock while luksAddKey runs (HW-3)
#   T10. two sequential builds → still exactly ONE enrollment (REAL state:
#        the second build observes the first build's token in the metadata)
#   T11/T12 (G-IL7): install state `installed` / baseline pending → the
#        ensure-once gate SKIPS (warn + rc 0, zero mutating calls, empty
#        bookkeeping) — the Stage-1 trap (§8.1 build row)
#   T13/T14 (G-IL7): state `finalized` / ABSENT state file → the enrollment
#        proceeds exactly as in T1
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/manifest.sh
source "$REPO/lib/manifest.sh"

assert_not_contains() {
    case $2 in
        *"$3"*) _fail "$1 ([$2] must not contain [$3])" ;;
        *) _pass "$1" ;;
    esac
}
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (missing: $2)"; fi
}
assert_file_absent() {
    if [ -e "$2" ]; then _fail "$1 (unexpectedly present: $2)"; else _pass "$1"; fi
}

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

KVER=6.12.8-1-amd64
UUID=22222222-2222-2222-2222-222222222222
TMP=$(mktemp -d)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT

ROOT="$TMP/root"
ESP="$TMP/esp"
FAKEBIN="$TMP/bin"
BYUUID="$TMP/by-uuid"
LUKS="$TMP/luks.img"
CE_LOG="$TMP/cryptenroll.log"
CS_LOG="$TMP/cs.log"
MARKER="$ROOT/etc/alpine-fde/build-failed"
ENROLLED="$ROOT/etc/alpine-fde/enrolled.json"
KEYDIR="$TMP/keys"
ISTATE="$ROOT/etc/alpine-fde/install-state.json"
mkdir -p "$ROOT/boot" "$ROOT/etc/alpine-fde" "$ESP/EFI/Linux" "$FAKEBIN" "$BYUUID" \
    "$KEYDIR" "$TMP/shm" "$TMP/swtpm"

# --- hermetic release keys (shared fixtures tree is mutated by parallel suites)
openssl genrsa -out "$KEYDIR/release.pem" 2048 2>/dev/null
openssl pkey -in "$KEYDIR/release.pem" -pubout -out "$KEYDIR/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEYDIR/release.pem" -out "$KEYDIR/release.crt" \
    -subj /CN=debian-fde-enroll-wire-ci 2>/dev/null

# --- swtpm: deterministic live PCRs (the seal anchors d7 statically) -----------
TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
tpm flushcontext -t >/dev/null 2>&1 || true
swtpm_pcrextend "$TPMDIR" 7 0123456701234567012345670123456701234567012345670123456701234567
swtpm_pcrextend "$TPMDIR" 11 fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98

# --- tripwire: cryptenroll must NEVER be invoked (ADR-19) ----------------------
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL \$*" >>'$CE_LOG'
exit 1
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll"

# --- cryptsetup wrapper: log argv, exec the REAL cryptsetup --------------------
REAL_CS=$(command -v cryptsetup)
cat >"$FAKEBIN/cs-wrapper" <<EOF
#!/bin/sh
printf 'CALL %s\\n' "\$*" >>'$CS_LOG'
# T9 probe: the ensure-once enrollment must hold the lock while luksAddKey runs
if [ "\$1" = luksAddKey ] && flock -n '$TMP/enroll.lock' true 2>/dev/null; then
    echo "LOCK-NOT-HELD" >>'$CS_LOG'
fi
exec $REAL_CS "\$@"
EOF
chmod +x "$FAKEBIN/cs-wrapper"

# --- REAL file-backed LUKS2 member (small CI KDF; token choreography is real) --
KDFARGS=(--pbkdf argon2id --pbkdf-memory 16000 --pbkdf-parallel 1 --pbkdf-force-iterations 4)
printf '%s' 'enroll-wire-slot0-passphrase-0123456789' >"$TMP/slot0.bin"
truncate -s 32M "$LUKS"
cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/slot0.bin" \
    "${KDFARGS[@]}" "$LUKS"
ln -sfn "$LUKS" "$BYUUID/$UUID"
reset_volume() { # — fresh container WITHOUT any token (smallest free slot = 1)
    rm -f "$LUKS" "$BYUUID/$UUID"
    truncate -s 32M "$LUKS"
    cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/slot0.bin" \
        "${KDFARGS[@]}" "$LUKS"
    ln -sfn "$LUKS" "$BYUUID/$UUID"
}
fresh_container() { # — container with slot 0 only (no token); alias of reset
    reset_volume
}

cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/alpine-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
printf '%s\n' "root UUID=$UUID none luks,tpm2-device=auto,discard" >"$ROOT/etc/crypttab"
jq -n '{expected_pcr7: "a5f90c8c5a73ade2323ba70d2c1a8a4a5a1e6e46e08c8ad3f3c5d7c9e2f0a1b3", status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"

for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    printf 'pre-existing-uki-%s' "$k" >"$ESP/EFI/Linux/alpine-fde-$k.efi"
done
M="$ROOT/etc/alpine-fde/digests.json"
manifest_new "6.2.0-1-amd64" "fp-seed" | manifest_atomic_write "$M"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    manifest_upsert "$M" "$k" "p11-seed-$k" "pd-seed-$k" "sig-seed-$k"
    printf 'pre-existing-uki-%s' "$k" >"$ESP/EFI/Linux/alpine-fde-$k.efi"
done

debian-fde() {
    DEBIAN_FDE_BIN_TEST=1 \
        DEBIAN_FDE_ROOT="$ROOT" \
        DEBIAN_FDE_ESP="$ESP" \
        DEBIAN_FDE_KEYDIR="$KEYDIR" \
        DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/debian-fde.conf" \
        DEBIAN_FDE_BY_UUID_DIR="$BYUUID" \
        DEBIAN_FDE_ENROLL_LOCK="$TMP/enroll.lock" \
        DEBIAN_FDE_CRYPTSETUP="$FAKEBIN/cs-wrapper" \
        DEBIAN_FDE_TCTI="$SWTPM_TCTI" \
        DEBIAN_FDE_TMPDIR="$TMP/shm" \
        DEBIAN_FDE_LUKS_KEYFILE="$TMP/slot0.bin" \
        PATH="$FAKEBIN:$PATH" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        "$REPO/bin/debian-fde" "$@"
}
reset_wire() {
    : >"$CE_LOG"
    : >"$CS_LOG"
}
cs_count() { # NEEDLE — fixed-substring count over the logged cryptsetup argv
    grep -cF "$1" "$CS_LOG" 2>/dev/null || true
}
tok_meta() { # jq FILTER over the REAL metadata (-c: compact — arrays compare textually)
    cryptsetup luksDump --dump-json-metadata "$LUKS" 2>/dev/null | jq -c "$1"
}

# --- T1: no token → ONE Mechanism B enrollment, records, marker cleared, prune --
reset_volume
reset_wire
: >"$MARKER" # stale marker must be cleared by the successful build
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T1: build with no token succeeds (enroll once)" 0 $rc
assert_eq "T1: exactly one luksAddKey (the fresh keyslot)" "1" "$(cs_count 'CALL luksAddKey')"
assert_eq "T1: exactly one token import" "1" "$(cs_count 'CALL token import')"
assert_eq "T1: ZERO cryptenroll invocations anywhere (ADR-19 tripwire)" "0" \
    "$(grep -c . "$CE_LOG")"
assert_contains "T1: build reports the ensure-once enrollment" "$out" "enrolling once"
assert_eq "T1: metadata now carries exactly one systemd-tpm2 token" "1" \
    "$(tok_meta '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length')"
assert_eq "T1: the standing token is bound to {PCR 7, PCR 11}" "[7,11]" \
    "$(tok_meta 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pcrs"] // empty) // empty')"
assert_eq "T1: the token references the keyslot luksAddKey created (slot 1)" '"1"' \
    "$(tok_meta 'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value.keyslots[0]) // empty')"
assert_file_exists "T1: enrolled.json recorded by the build enroll step" "$ENROLLED"
assert_eq "T1: enrolled.json policy_mode is b (ADR-19)" "b" "$(jq -r .policy_mode "$ENROLLED")"
assert_eq "T1: enrolled.json token keyslot matches the REAL metadata" "1" \
    "$(jq -r .token_keyslot "$ENROLLED")"
assert_file_absent "T1: success cleared the failure marker" "$MARKER"
assert_eq "T1: prune ran on success (5.15.0 dropped)" "absent" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-5.15.0-3-amd64.efi" ] && echo present || echo absent)"

# --- T3: manifest carries keyslot + token_id matching enrolled.json (per entry) --
E=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver)' "$M")
assert_eq "T3: current entry keyslot matches enrolled.json" "1" \
    "$(printf '%s' "$E" | jq -r .keyslot)"
assert_eq "T3: current entry token_id matches the LUKS2 token id" "0" \
    "$(printf '%s' "$E" | jq -r .token_id)"
assert_eq "T3: keyslot repeated on a retained entry (bookkeeping)" "1" \
    "$(jq -r --arg k 6.1.0-1-amd64 '.digests[] | select(.kernel_version == $k) | .keyslot' "$M")"
assert_eq "T3: token_id repeated on a retained entry (bookkeeping)" "0" \
    "$(jq -r --arg k 6.1.0-1-amd64 '.digests[] | select(.kernel_version == $k) | .token_id' "$M")"

# --- T2: token standing → metadata read ONLY, zero mutating calls ----------------
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T2: build with token standing succeeds" 0 $rc
assert_contains "T2: info line says the enrollment stands" "$out" "already present"
assert_contains "T2: info line says no TPM operations" "$out" "no TPM operations"
assert_eq "T2: ZERO mutating cryptsetup calls (metadata read only, s14)" "0" \
    "$(( $(cs_count 'CALL luksAddKey') + $(cs_count 'CALL token') + $(cs_count 'CALL luksKillSlot') ))"
assert_eq "T2: keyslot preserved across the rebuild" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T2: token_id preserved across the rebuild" "0" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T4: enroll failure → rc 64 + marker + prune did NOT run ----------------------
reset_volume
printf 'not a LUKS container' >"$LUKS" # the volume cannot even be read
reset_wire
printf 'old-4.9.0' >"$ESP/EFI/Linux/alpine-fde-4.9.0-1-amd64.efi" # prune bait beyond retention
manifest_upsert "$M" "4.9.0-1-amd64" "p11-old" "pd-old" "sig-old"
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T4: enroll failure fails the build closed (64)" 64 $rc
assert_contains "T4: failure names the ensure-once enroll step" "$out" "TPM enrollment failed"
assert_file_exists "T4: ADR-8 marker persisted" "$MARKER"
assert_contains "T4: marker cites the enroll failure" "$(cat "$MARKER")" "enroll"
assert_eq "T4: prune did NOT run (beyond-retention UKI still on ESP)" "present" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-4.9.0-1-amd64.efi" ] && echo present || echo absent)"
assert_eq "T4: prune did NOT run (manifest entry still present)" "present" \
    "$(jq -r 'if any(.digests[]; .kernel_version == "4.9.0-1-amd64") then "present" else "absent" end' "$M")"

# --- T5: recovery — the enrollment works again, marker cleared, prune runs --------
reset_volume
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T5: recovery build succeeds" 0 $rc
assert_file_absent "T5: success cleared the failure marker" "$MARKER"
assert_eq "T5: prune ran after recovery" "absent" \
    "$([ -f "$ESP/EFI/Linux/alpine-fde-4.9.0-1-amd64.efi" ] && echo present || echo absent)"

# --- T6: NEW kver + token STANDING (zero-TPM-op path) → §8.4 stamping -------------
# Building a NEW kernel version upserts an entry with EMPTY keyslot/token_id
# (manifest_upsert carries bookkeeping over same-kver rebuilds only); the
# standing token's values must be stamped onto every entry (incl. the NEW
# kver's) from the REAL metadata introspection — still zero mutating calls.
KVER_B=6.13.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_B"
reset_wire
out=$(debian-fde ukictl build "$KVER_B" 2>&1)
rc=$?
assert_rc "T6: new-kver build with token standing succeeds" 0 $rc
assert_contains "T6: info line says the enrollment stands" "$out" "already present"
assert_eq "T6: ZERO mutating cryptsetup calls (standing token; s14)" "0" \
    "$(( $(cs_count 'CALL luksAddKey') + $(cs_count 'CALL token') + $(cs_count 'CALL luksKillSlot') ))"
assert_eq "T6: NEW kver's entry carries the standing keyslot" "1" \
    "$(jq -r --arg kver "$KVER_B" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T6: NEW kver's entry carries the standing token_id" "0" \
    "$(jq -r --arg kver "$KVER_B" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"
assert_eq "T6: standing keyslot still repeated on the enrolled kver" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T6: standing token_id still repeated on the enrolled kver" "0" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T7: volume unreachable → documented precondition escape (warn + rc 0) ---------
KVER_C=6.14.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_C"
rm -f "$BYUUID/$UUID" # the volume is not resolvable in this build context
reset_wire
out=$(debian-fde ukictl build "$KVER_C" 2>&1)
rc=$?
assert_rc "T7: build succeeds with the volume unreachable (escape, rc 0)" 0 $rc
assert_contains "T7: warning names the unreachable volume" "$out" "not reachable"
assert_contains "T7: warning carries the by-uuid device path" "$out" "$BYUUID/$UUID"
assert_eq "T7: ZERO cryptsetup calls at all (volume never touched)" "0" "$(cs_count CALL)"
assert_file_absent "T7: no ADR-8 marker (loud, not fatal)" "$MARKER"
assert_eq "T7: NEW kver's entry written with EMPTY keyslot (escape)" "" \
    "$(jq -r --arg kver "$KVER_C" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T7: NEW kver's entry written with EMPTY token_id (escape)" "" \
    "$(jq -r --arg kver "$KVER_C" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"
assert_eq "T7: standing keyslot on the enrolled kver NOT wiped by the escape" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
ln -sfn "$LUKS" "$BYUUID/$UUID" # restore the device for any later legs

# --- T8: >1 standing tokens → LOUD refusal from the ensure-once path (HW-3) --------
# The standing path must refuse ANY token count >= 2 — a post-race state of 2
# tokens + 2 burned keyslots was silently permanent once. Import a SECOND real
# token (bound to a fresh keyslot) to build that state, then expect the loud
# refusal: build fails closed (64) with a marker citing manual intervention and
# zero mutating calls.
cryptsetup luksAddKey "${KDFARGS[@]}" --key-slot 2 --key-file "$TMP/slot0.bin" \
    "$LUKS" "$TMP/slot0.bin"
jq -n '{type: "systemd-tpm2", keyslots: ["2"], "tpm2-blob": "AAEAC0RhdGE=", "tpm2-pcrs": [7, 11], "tpm2-pcr-bank": "sha256"}' \
    >"$TMP/tok2.json"
cryptsetup token import "$LUKS" --token-id 1 --json-file "$TMP/tok2.json" \
    --disable-external-tokens
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T8: >1 standing tokens fails the build closed (64)" 64 $rc
assert_contains "T8: message cites manual intervention" "$out" "manual intervention"
assert_file_exists "T8: ADR-8 marker persisted" "$MARKER"
assert_contains "T8: marker names the token-count reason" "$(cat "$MARKER")" "tokens"
assert_eq "T8: ZERO mutating calls (refusal, not re-enroll)" "0" \
    "$(( $(cs_count 'CALL luksAddKey') + $(cs_count 'CALL token') + $(cs_count 'CALL luksKillSlot') ))"

# --- T9: the enrollment holds the ensure-once lock while luksAddKey runs ----------
# The cs-wrapper probes the lock (flock -n) AT luksAddKey time; the holder must
# LOSE the probe (HW-3 TOCTOU race: concurrent builds/postinst serialize).
reset_volume
reset_wire
rm -f "$MARKER" "$ENROLLED"
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T9: build with the lock wire succeeds" 0 $rc
assert_eq "T9: luksAddKey ran exactly once" "1" "$(cs_count 'CALL luksAddKey')"
assert_eq "T9: the lock was HELD at luksAddKey time (probe lost)" "0" \
    "$(grep -c 'LOCK-NOT-HELD' "$CS_LOG" || true)"

# --- T10: two sequential builds → still exactly ONE enrollment (REAL state) --------
# After T9's build the REAL metadata carries the token; the second build must
# observe it (standing path) rather than enroll again. The CS log is NOT reset:
# it spans both builds, so the count pins the one-enrollment invariant.
out2=$(debian-fde ukictl build "$KVER" 2>&1)
rc2=$?
assert_rc "T10: second build sees the standing token (rc 0)" 0 "$rc2"
assert_contains "T10: second build took the standing path" "$out2" "already present"
assert_eq "T10: exactly ONE luksAddKey across both builds" "1" \
    "$(cs_count 'CALL luksAddKey')"

# --- T11 (G-IL7): install state 'installed' → ensure-once SKIPS (§8.1 build row) ---
# Stage-1 in-chroot provisioning presents the exact trap: reachable volume,
# ZERO tokens, SB off. The install-state gate must skip the enrollment BEFORE
# token inspection: warn + rc 0, zero mutating calls, no enrolled.json, no
# marker, manifest entries carrying EMPTY keyslot/token_id (bookkeeping
# deferred to a build under a finalized install state).
KVER_D=6.15.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_D"
printf '{\n  "schema_version": "1",\n  "state": "installed"\n}\n' >"$ISTATE"
reset_volume
rm -f "$ENROLLED" "$MARKER"
reset_wire
out=$(debian-fde ukictl build "$KVER_D" 2>&1)
rc=$?
assert_rc "T11: stage-1 build (state=installed, reachable volume, 0 tokens) rc 0" 0 $rc
assert_eq "T11: ZERO mutating calls (gate fired before token inspection)" "0" \
    "$(( $(cs_count 'CALL luksAddKey') + $(cs_count 'CALL token') ))"
assert_contains "T11: warn names the unfinalized install state" "$out" "not finalized"
assert_file_absent "T11: no enrolled.json (nothing enrolled)" "$ENROLLED"
assert_file_absent "T11: no ADR-8 marker (skip is loud, not fatal)" "$MARKER"
assert_eq "T11: NEW kver entry carries EMPTY keyslot (bookkeeping deferred)" "" \
    "$(jq -r --arg kver "$KVER_D" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T11: NEW kver entry carries EMPTY token_id" "" \
    "$(jq -r --arg kver "$KVER_D" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T12 (G-IL7): pending baseline → the same skip ----------------------------------
# No install-state file (legacy shape): the BASELINE half of the gate must
# still fire when expected_pcr7 is pending (§8.1 "install state is not
# finalized / baseline is pending").
KVER_E=6.16.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_E"
rm -f "$ISTATE"
jq -n '{expected_pcr7: "pending", status: "pending"}' >"$ROOT/etc/alpine-fde/baseline.json"
reset_volume
rm -f "$ENROLLED" "$MARKER"
reset_wire
out=$(debian-fde ukictl build "$KVER_E" 2>&1)
rc=$?
assert_rc "T12: pending-baseline build rc 0 (gate skip)" 0 $rc
assert_eq "T12: ZERO mutating calls" "0" \
    "$(( $(cs_count 'CALL luksAddKey') + $(cs_count 'CALL token') ))"
assert_contains "T12: warn names the pending baseline" "$out" "expected_pcr7 is pending"
assert_file_absent "T12: no enrolled.json" "$ENROLLED"
assert_eq "T12: NEW kver entry carries EMPTY keyslot" "" \
    "$(jq -r --arg kver "$KVER_E" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T12: NEW kver entry carries EMPTY token_id" "" \
    "$(jq -r --arg kver "$KVER_E" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T13 (G-IL7): state=finalized + 0 tokens ⇒ exactly ONE enrollment ---------------
printf '{\n  "schema_version": "1",\n  "state": "finalized"\n}\n' >"$ISTATE"
jq -n '{expected_pcr7: "a5f90c8c5a73ade2323ba70d2c1a8a4a5a1e6e46e08c8ad3f3c5d7c9e2f0a1b3", status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"
reset_volume
rm -f "$ENROLLED" "$MARKER"
reset_wire
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T13: finalized install state build enrolls (rc 0)" 0 $rc
assert_eq "T13: exactly ONE enrollment under a finalized install state" "1" \
    "$(cs_count 'CALL luksAddKey')"
assert_file_exists "T13: enrolled.json recorded" "$ENROLLED"

# --- T14 (G-IL7): ABSENT install-state file ⇒ legacy behavior unchanged (T1) --------
rm -f "$ISTATE" "$ENROLLED" "$MARKER"
reset_volume
reset_wire
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T14: absent install-state file ⇒ legacy gate passes (enrolls)" 0 $rc
assert_eq "T14: exactly ONE enrollment without any install-state file" "1" \
    "$(cs_count 'CALL luksAddKey')"

finish
