#!/usr/bin/env bash
# tests/unit/ukictl_build_enroll_wire.sh — G-U1/G-U2/G-R3: `ukictl build`
# carries the ENSURE-ONCE A'' enrollment step (after the manifest update,
# BEFORE prune; wired to the ADR-8 marker path):
#   T1. no systemd-tpm2 token on the LUKS2 volume → exactly ONE cryptenroll
#       invocation with the A'' flag set (--tpm2-pcrs=7 AND
#       --tpm2-public-key-pcrs=11; never a signed selection on --tpm2-pcrs);
#       enrolled.json + manifest keyslot/token_id recorded; marker cleared
#   T2. token already present → ZERO cryptenroll calls (s14: kernel updates
#       are TPM-free), rc 0, info line; enrollment bookkeeping preserved
#   T3. manifest entries carry keyslot + token_id matching enrolled.json
#       (repeated per entry — bookkeeping, §8.4)
#   T4. enroll failure → rc 64 + marker + prune did NOT run
#   T5. recovery build succeeds and clears the marker (prune runs)
#   T6. NEW kver built while the token STANDS (zero-TPM-op path) → the standing
#       enrollment's keyslot/token_id are stamped onto the NEW kver's manifest
#       entry too (§8.4: repeated per entry; upsert carry-over is same-kver
#       only) — sourced from the token introspection, ZERO cryptenroll calls
#   T7. volume unreachable (no by-uuid device) → rc 0, warning names the
#       volume, ZERO TPM contact, no marker, NEW entry written with EMPTY
#       keyslot/token_id (documented precondition escape — pinned)
#   T11/T12 (G-IL7): install state `installed` / baseline pending → the
#       ensure-once gate SKIPS (warn + rc 0, ZERO cryptenroll, empty
#       keyslot/token_id bookkeeping) — the Stage-1 trap (§8.1 build row)
#   T13/T14 (G-IL7): state `finalized` / ABSENT state file (legacy) → the
#       enrollment proceeds exactly as before (1 call)
# cryptenroll/cryptsetup are stubs recording argv / serving LUKS2 metadata;
# fake /dev/disk/by-uuid + compliant crypttab/cmdline pins per the stub pattern.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

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

KVER=6.12.8-1-amd64
KEYDIR="$REPO/fixtures/keys"
UUID=22222222-2222-2222-2222-222222222222
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ROOT="$TMP/root"
ESP="$TMP/esp"
FAKEBIN="$TMP/bin"
BYUUID="$TMP/by-uuid"
CR_LOG="$TMP/cryptenroll.log"
CR_FAIL="$TMP/cryptenroll-fail"
CS_COUNTER="$TMP/cs-counter"
CS_PRE="$TMP/luks-pre.json"
CS_POST="$TMP/luks-post.json"
MARKER="$ROOT/etc/debian-fde/build-failed"
ENROLLED="$ROOT/etc/debian-fde/enrolled.json"
mkdir -p "$ROOT/boot" "$ROOT/etc/debian-fde" "$ESP/EFI/Linux" "$FAKEBIN" "$BYUUID"

cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER"
cp "$REPO/fixtures/uki/cmdline.txt" "$ROOT/etc/debian-fde/cmdline.txt"
cp "$REPO/fixtures/uki/os-release" "$ROOT/etc/os-release"
printf '%s\n' "root UUID=$UUID none luks,tpm2-device=auto,discard" >"$ROOT/etc/crypttab"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/debian-fde/baseline.json"
: >"$BYUUID/$UUID"

# cryptenroll stub: records every invocation; the --tpm2-device=list probe
# always answers; the enroll call fails iff CR_FAIL holds 1
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL: \$*" >>'$CR_LOG'
for a in "\$@"; do
    [ "\$a" = "--tpm2-device=list" ] && exit 0
done
[ "\$(cat '$CR_FAIL' 2>/dev/null || echo 0)" = "1" ] && exit 1
exit 0
EOF
# cryptsetup stub: 1st luksDump serves PRE, later calls serve POST
cat >"$FAKEBIN/cryptsetup" <<EOF
#!/bin/sh
if [ "\$1" = "luksDump" ] && [ "\$2" = "--dump-json-metadata" ]; then
    n=\$(cat '$CS_COUNTER' 2>/dev/null || echo 0)
    n=\$((n + 1))
    echo "\$n" >'$CS_COUNTER'
    if [ "\$n" -ge 2 ]; then cat '$CS_POST'; else cat '$CS_PRE'; fi
    exit 0
fi
exit 0
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll" "$FAKEBIN/cryptsetup"
printf 0 >"$CR_FAIL"

# LUKS2 metadata fixtures (cryptsetup --dump-json-metadata pretty shape)
luks_json() { # WITH-TOKEN(yes|no|two) — token id "0" bound to keyslot "1"
    if [ "$1" = two ]; then
        TOKS='"tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"], "tpm2_blob": "AAEAC0RhdGE=" },
        "1": { "type": "systemd-tpm2", "keyslots": ["1"], "tpm2_blob": "AAEAC0RhdGE=" }
    }'
    elif [ "$1" = yes ]; then
        TOKS='"tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"], "tpm2_blob": "AAEAC0RhdGE=" }
    }'
    else
        TOKS='"tokens": {}'
    fi
    printf '{\n    "keyslots": {\n        "0": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id" } },\n        "1": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id" } }\n    },\n    %s\n}\n' "$TOKS"
}

. "$REPO/lib/common.sh"
. "$REPO/lib/manifest.sh"
M="$ROOT/etc/debian-fde/digests.json"
manifest_new "6.2.0-1-amd64" "fp-seed" | manifest_atomic_write "$M"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 5.15.0-3-amd64; do
    manifest_upsert "$M" "$k" "p11-seed-$k" "pd-seed-$k" "sig-seed-$k"
    printf 'pre-existing-uki-%s' "$k" >"$ESP/EFI/Linux/debian-fde-$k.efi"
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
        PATH="$FAKEBIN:$PATH" \
        INITRAMFS_CMD="$REPO/fixtures/initramfs/stub-generate.sh {out} {kver}" \
        RETENTION=2 \
        "$REPO/bin/debian-fde" "$@"
}
reset_wire() {
    : >"$CR_LOG"
    echo 0 >"$CS_COUNTER"
}

# --- T1: a2 + NO token → enroll exactly once, A'' argv, records, marker cleared ---
luks_json no >"$CS_PRE"
luks_json yes >"$CS_POST"
reset_wire
: >"$MARKER" # stale marker must be cleared by the successful build
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T1: a2 build with no token succeeds (enroll once)" 0 $rc
CALLS=$(grep -v 'tpm2-device=list' "$CR_LOG")
assert_eq "T1: cryptenroll invoked exactly once (beyond probes)" "1" \
    "$(printf '%s\n' "$CALLS" | grep -c .)"
assert_contains "T1: argv has static --tpm2-pcrs=7" "$CALLS" "--tpm2-pcrs=7"
assert_contains "T1: argv has signed --tpm2-public-key-pcrs=11" "$CALLS" "--tpm2-public-key-pcrs=11"
assert_contains "T1: argv pins the release public key" "$CALLS" \
    "--tpm2-public-key=$KEYDIR/release.pub"
assert_not_contains "T1: never a combined 7+11 signed selection under A''" "$CALLS" "7+11"
assert_not_contains "T1: no --tpm2-signature under A''" "$CALLS" "--tpm2-signature"
assert_eq "T1: the only --tpm2-pcrs selection is the static 7" "--tpm2-pcrs=7 " \
    "$(printf '%s\n' "$CALLS" | grep -o -- '--tpm2-pcrs=[0-9+]*' | sort -u | tr '\n' ' ')"
assert_contains "T1: build reports the ensure-once enrollment" "$out" "enrolling once"
assert_file_exists "T1: enrolled.json recorded by the build enroll step" "$ENROLLED"
assert_eq "T1: enrolled.json token keyslot matches the served metadata" "1" \
    "$(jq -r .token_keyslot "$ENROLLED")"
assert_eq "T1: enrolled.json policy_mode" "a2" "$(jq -r .policy_mode "$ENROLLED")"
assert_file_absent "T1: success cleared the failure marker" "$MARKER"
assert_eq "T1: prune ran on success (5.15.0 dropped)" "absent" \
    "$([ -f "$ESP/EFI/Linux/debian-fde-5.15.0-3-amd64.efi" ] && echo present || echo absent)"

# --- T3: manifest carries keyslot + token_id matching enrolled.json (per entry) ----
E=$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver)' "$M")
assert_eq "T3: current entry keyslot matches enrolled.json" "1" \
    "$(printf '%s' "$E" | jq -r .keyslot)"
assert_eq "T3: current entry token_id matches the LUKS2 token id" "0" \
    "$(printf '%s' "$E" | jq -r .token_id)"
assert_eq "T3: keyslot repeated on a retained entry (bookkeeping)" "1" \
    "$(jq -r --arg k 6.1.0-1-amd64 '.digests[] | select(.kernel_version == $k) | .keyslot' "$M")"
assert_eq "T3: token_id repeated on a retained entry (bookkeeping)" "0" \
    "$(jq -r --arg k 6.1.0-1-amd64 '.digests[] | select(.kernel_version == $k) | .token_id' "$M")"

# --- T2: a2 + token present → ZERO TPM operations, info line, bookkeeping kept ------
luks_json yes >"$CS_PRE"
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T2: a2 build with token present succeeds" 0 $rc
assert_eq "T2: ZERO cryptenroll calls (s14: TPM-free kernel update)" "0" \
    "$(grep -c . "$CR_LOG" || true)"
assert_contains "T2: info line says the enrollment stands" "$out" "already present"
assert_contains "T2: info line says no TPM operations" "$out" "no TPM operations"
assert_eq "T2: keyslot preserved across the rebuild" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T2: token_id preserved across the rebuild" "0" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T4: enroll failure → rc 64 + marker + prune did NOT run ------------------------
printf 1 >"$CR_FAIL"
luks_json no >"$CS_PRE" # no token → the ensure-once step must attempt and fail
reset_wire
printf 'old-4.9.0' >"$ESP/EFI/Linux/debian-fde-4.9.0-1-amd64.efi" # prune bait beyond retention
manifest_upsert "$M" "4.9.0-1-amd64" "p11-old" "pd-old" "sig-old"
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T4: enroll failure fails the build closed (64)" 64 $rc
assert_contains "T4: failure names the ensure-once enroll step" "$out" "TPM enrollment failed"
assert_file_exists "T4: ADR-8 marker persisted" "$MARKER"
assert_contains "T4: marker cites the enroll failure" "$(cat "$MARKER")" "enroll"
assert_eq "T4: prune did NOT run (beyond-retention UKI still on ESP)" "present" \
    "$([ -f "$ESP/EFI/Linux/debian-fde-4.9.0-1-amd64.efi" ] && echo present || echo absent)"
assert_eq "T4: prune did NOT run (manifest entry still present)" "present" \
    "$(jq -r 'if any(.digests[]; .kernel_version == "4.9.0-1-amd64") then "present" else "absent" end' "$M")"

# --- T5: recovery — the enrollment works again, marker cleared, prune runs ----------
printf 0 >"$CR_FAIL"
luks_json no >"$CS_PRE"
luks_json yes >"$CS_POST"
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T5: recovery build succeeds" 0 $rc
assert_file_absent "T5: success cleared the failure marker" "$MARKER"
assert_eq "T5: prune ran after recovery" "absent" \
    "$([ -f "$ESP/EFI/Linux/debian-fde-4.9.0-1-amd64.efi" ] && echo present || echo absent)"

# --- T6: NEW kver + token STANDING (zero-TPM-op path) → §8.4 stamping --------------
# Building a NEW kernel version upserts an entry with EMPTY keyslot/token_id
# (manifest_upsert carries bookkeeping over same-kver rebuilds only); the
# standing token's values must be stamped onto every entry (incl. the NEW
# kver's) from the token introspection — still ZERO cryptenroll calls (s14).
KVER_B=6.13.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_B"
luks_json yes >"$CS_PRE"
luks_json yes >"$CS_POST"
reset_wire
out=$(debian-fde ukictl build "$KVER_B" 2>&1)
rc=$?
assert_rc "T6: new-kver build with token standing succeeds" 0 $rc
assert_contains "T6: info line says the enrollment stands" "$out" "already present"
assert_eq "T6: ZERO cryptenroll calls (standing token; s14)" "0" \
    "$(grep -c . "$CR_LOG" || true)"
assert_eq "T6: NEW kver's entry carries the standing keyslot" "1" \
    "$(jq -r --arg kver "$KVER_B" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T6: NEW kver's entry carries the standing token_id" "0" \
    "$(jq -r --arg kver "$KVER_B" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"
assert_eq "T6: standing keyslot still repeated on the enrolled kver" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T6: standing token_id still repeated on the enrolled kver" "0" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T7: volume unreachable → documented precondition escape (warn + rc 0) ---------
# No by-uuid device in this build context: the ensure-once step warns (naming
# the volume), touches NOTHING (zero cryptenroll AND zero luksDump), the build
# still succeeds (no ADR-8 marker) and the NEW kver's entry is written with
# EMPTY keyslot/token_id — pinned so the escape cannot silently change; the
# standing bookkeeping on already-enrolled entries is NOT wiped by it.
KVER_C=6.14.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_C"
rm -f "$BYUUID/$UUID" # the volume is not resolvable in this build context
reset_wire
out=$(debian-fde ukictl build "$KVER_C" 2>&1)
rc=$?
assert_rc "T7: build succeeds with the volume unreachable (escape, rc 0)" 0 $rc
assert_contains "T7: warning names the unreachable volume" "$out" "not reachable"
assert_contains "T7: warning carries the by-uuid device path" "$out" "$BYUUID/$UUID"
assert_eq "T7: ZERO cryptenroll calls" "0" "$(grep -c . "$CR_LOG" || true)"
assert_eq "T7: no LUKS metadata read at all (volume never touched)" "0" \
    "$(cat "$CS_COUNTER")"
assert_file_absent "T7: no ADR-8 marker (loud, not fatal)" "$MARKER"
assert_eq "T7: NEW kver's entry written with EMPTY keyslot (escape)" "" \
    "$(jq -r --arg kver "$KVER_C" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T7: NEW kver's entry written with EMPTY token_id (escape)" "" \
    "$(jq -r --arg kver "$KVER_C" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"
assert_eq "T7: standing keyslot on the enrolled kver NOT wiped by the escape" "1" \
    "$(jq -r --arg kver "$KVER" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
: >"$BYUUID/$UUID" # restore the device for any later legs

# --- T8: >1 standing tokens → LOUD refusal from the ensure-once path (HW-3) ---------
# The standing path used to treat ANY token count >= 1 as "stands, zero ops" —
# a post-race / post-partial-failure state of 2 tokens + 2 burned keyslots was
# silently permanent (the designed loud refusal lived only inside enrl_run,
# unreachable from the standing path). The build must fail closed (64) with a
# marker citing manual intervention, and cryptenroll must never be touched.
luks_json two >"$CS_PRE"
luks_json two >"$CS_POST"
reset_wire
out=$(debian-fde ukictl build "$KVER" 2>&1)
rc=$?
assert_rc "T8: >1 standing tokens fails the build closed (64)" 64 $rc
assert_contains "T8: message cites manual intervention" "$out" "manual intervention"
assert_file_exists "T8: ADR-8 marker persisted" "$MARKER"
assert_contains "T8: marker names the token-count reason" "$(cat "$MARKER")" "tokens"
assert_eq "T8: ZERO cryptenroll calls (refusal, not re-enroll)" "0" \
    "$(grep -c . "$CR_LOG" || true)"

# --- T9: the enrollment holds the ensure-once lock while cryptenroll runs -----------
# The stub probes the lock (flock -n) at enroll time; the holder must LOSE the
# probe. Serializes concurrent builds/postinst passes (HW-3 TOCTOU race).
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL: \$*" >>'$CR_LOG'
for a in "\$@"; do
    [ "\$a" = "--tpm2-device=list" ] && exit 0
done
if flock -n '$TMP/enroll.lock' true 2>/dev/null; then
    echo "LOCK-NOT-HELD" >>'$CR_LOG'
else
    echo "LOCK-HELD" >>'$CR_LOG'
fi
[ "\$(cat '$CR_FAIL' 2>/dev/null || echo 0)" = "1" ] && exit 1
exit 0
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll"
luks_json no >"$CS_PRE"
luks_json yes >"$CS_POST"
reset_wire
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T9: build with the lock wire succeeds" 0 $rc
assert_eq "T9: enroll ran under the held lock (probe lost)" "1" \
    "$(grep -c 'LOCK-HELD' "$CR_LOG" || true)"
assert_eq "T9: no enrollment ever ran without the lock" "0" \
    "$(grep -c 'LOCK-NOT-HELD' "$CR_LOG" || true)"

# --- T10: two sequential builds → still exactly ONE enrollment (no accumulation) ----
# State-driven stubs: cryptenroll (enroll call) flips a token-state file; the
# cryptsetup stub serves no-token until it exists, with-token after — so the
# second build must observe the FIRST build's standing token, not enroll again.
: >"$CR_LOG"
mkdir -p "$TMP/state"
rm -f "$TMP/state/token"
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
for a in "\$@"; do
    [ "\$a" = "--tpm2-device=list" ] && exit 0
done
echo "CALL: \$*" >>'$CR_LOG'
: >'$TMP/state/token'
exit 0
EOF
cat >"$FAKEBIN/cryptsetup" <<EOF
#!/bin/sh
if [ "\$1" = "luksDump" ] && [ "\$2" = "--dump-json-metadata" ]; then
    if [ -f '$TMP/state/token' ]; then cat '$CS_POST'; else cat '$CS_PRE'; fi
    exit 0
fi
exit 0
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll" "$FAKEBIN/cryptsetup"
luks_json no >"$CS_PRE"
luks_json yes >"$CS_POST"
printf 0 >"$CR_FAIL"
out1=$(debian-fde ukictl build "$KVER" 2>&1); rc1=$?
out2=$(debian-fde ukictl build "$KVER" 2>&1); rc2=$?
assert_rc "T10: first build enrolls once" 0 "$rc1"
assert_rc "T10: second build sees the standing token (rc 0)" 0 "$rc2"
assert_eq "T10: exactly ONE enrollment across both builds" "1" \
    "$(grep -c 'CALL:' "$CR_LOG" || true)"
assert_contains "T10: second build took the standing path" "$out2" "already present"

# --- T11 (G-IL7): install state 'installed' → ensure-once SKIPS (§8.1 build row) ----
# Stage-1 in-chroot provisioning presents the exact trap: reachable volume,
# ZERO tokens, SB off. The install-state gate must skip the enrollment BEFORE
# token inspection: warn + rc 0, ZERO cryptenroll calls, no enrolled.json, no
# marker, manifest entries carrying EMPTY keyslot/token_id (bookkeeping
# deferred to a build under a finalized install state).
KVER_D=6.15.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_D"
ISTATE="$ROOT/etc/debian-fde/install-state.json"
printf '{\n  "schema_version": "1",\n  "state": "installed"\n}\n' >"$ISTATE"
rm -f "$TMP/state/token" "$ENROLLED" "$MARKER"
luks_json no >"$CS_PRE" # 0 tokens behind the reachable volume
luks_json yes >"$CS_POST"
reset_wire
out=$(debian-fde ukictl build "$KVER_D" 2>&1)
rc=$?
assert_rc "T11: stage-1 build (state=installed, reachable volume, 0 tokens) rc 0" 0 $rc
assert_eq "T11: ZERO cryptenroll calls (gate fired before token inspection)" "0" \
    "$(grep -c 'CALL:' "$CR_LOG" || true)"
assert_contains "T11: warn names the unfinalized install state" "$out" "not finalized"
assert_file_absent "T11: no enrolled.json (nothing enrolled)" "$ENROLLED"
assert_file_absent "T11: no ADR-8 marker (skip is loud, not fatal)" "$MARKER"
assert_eq "T11: NEW kver entry carries EMPTY keyslot (bookkeeping deferred)" "" \
    "$(jq -r --arg kver "$KVER_D" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T11: NEW kver entry carries EMPTY token_id" "" \
    "$(jq -r --arg kver "$KVER_D" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T12 (G-IL7): pending baseline → the same skip -----------------------------------
# No install-state file (legacy shape): the BASELINE half of the gate must
# still fire when expected_pcr7 is pending (§8.1 "install state is not
# finalized / baseline is pending").
KVER_E=6.16.0-1-amd64
cp "$REPO/fixtures/uki/vmlinuz" "$ROOT/boot/vmlinuz-$KVER_E"
rm -f "$ISTATE" "$TMP/state/token" "$ENROLLED" "$MARKER"
jq -n '{expected_pcr7: "pending", status: "pending"}' >"$ROOT/etc/debian-fde/baseline.json"
reset_wire
out=$(debian-fde ukictl build "$KVER_E" 2>&1)
rc=$?
assert_rc "T12: pending-baseline build rc 0 (gate skip)" 0 $rc
assert_eq "T12: ZERO cryptenroll calls" "0" "$(grep -c 'CALL:' "$CR_LOG" || true)"
assert_contains "T12: warn names the pending baseline" "$out" "expected_pcr7 is pending"
assert_file_absent "T12: no enrolled.json" "$ENROLLED"
assert_eq "T12: NEW kver entry carries EMPTY keyslot" "" \
    "$(jq -r --arg kver "$KVER_E" '.digests[] | select(.kernel_version == $kver) | .keyslot' "$M")"
assert_eq "T12: NEW kver entry carries EMPTY token_id" "" \
    "$(jq -r --arg kver "$KVER_E" '.digests[] | select(.kernel_version == $kver) | .token_id' "$M")"

# --- T13 (G-IL7): state=finalized + 0 tokens ⇒ exactly ONE enrollment (unchanged) ----
printf '{\n  "schema_version": "1",\n  "state": "finalized"\n}\n' >"$ISTATE"
jq -n --arg d7 "$(jq -r .pcr7_digest "$REPO/fixtures/policy-digest/golden.json")" \
    '{expected_pcr7: $d7, status: "finalized"}' >"$ROOT/etc/debian-fde/baseline.json"
rm -f "$TMP/state/token" "$ENROLLED" "$MARKER"
luks_json no >"$CS_PRE"
luks_json yes >"$CS_POST"
reset_wire
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T13: finalized install state build enrolls (rc 0)" 0 $rc
assert_eq "T13: exactly ONE enrollment under a finalized install state" "1" \
    "$(grep -c 'CALL:' "$CR_LOG" || true)"
assert_file_exists "T13: enrolled.json recorded" "$ENROLLED"

# --- T14 (G-IL7): ABSENT install-state file ⇒ legacy behavior unchanged (T1) ---------
rm -f "$ISTATE" "$TMP/state/token" "$ENROLLED" "$MARKER"
luks_json no >"$CS_PRE"
reset_wire
debian-fde ukictl build "$KVER" >/dev/null 2>&1
rc=$?
assert_rc "T14: absent install-state file ⇒ legacy gate passes (enrolls)" 0 $rc
assert_eq "T14: exactly ONE enrollment without any install-state file" "1" \
    "$(grep -c 'CALL:' "$CR_LOG" || true)"

finish
