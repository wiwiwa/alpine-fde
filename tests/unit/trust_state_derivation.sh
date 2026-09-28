#!/usr/bin/env bash
# tests/unit/trust_state_derivation.sh — item 10b ("install-state.json is DEAD
# in the design"): the GROUND-TRUTH trust state, lib/trust-state.sh.
#
#   * derivation primitives over fixture LUKS2 metadata JSON (PRETTY 4-space
#     and COMPACT single-line cryptsetup 2.7.5 shapes, the
#     tests/unit/luks_json_parsers.sh fixture patterns):
#       ts_token_pcrs      [11] provisional / [7,11] finalized / '' no token
#       ts_sealed_slots    the token-referenced keyslot inventory
#       ts_ephemeral_slots the temporary install keyslot (keyslot 2 normative)
#       ts_recovery_slot_ok exactly keyslot 0 beyond the sealed slots (I1)
#   * ts_state classification:
#       provisional  token [11] — AND the mid-completion crash shape
#                    (token [7,11] + ephemeral slot still present, §9.1)
#       finalized    token [7,11] + NO ephemeral slot + baseline expected_pcr7
#                    a real digest (pending baseline ⇒ unknown, fail-closed)
#       unknown      no token / exotic pcrs / contradictory baseline
#   * ts_first_member + ts_label: the degrade-safe top-level read (empty —
#     never a die — when no member resolves or metadata is unreadable)
#   * the ADR-8 attempt marker (fde_attempt_*): write/read/present/clear,
#     mode 600, atomic replace, ALPINE_FDE_ATTEMPT_MARKER override, root scoping
#   * RESIDUE PINS: no shipped path references the retired machinery
#     (install-state.json / istate_* / ALPINE_FDE_INSTALL_STATE /
#     ALPINE_FDE_INSTALL_ATTEMPT) and the unseal hook persists NOTHING

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/trust-state.sh
source "$REPO/lib/trust-state.sh"

T=$(mktemp -d /tmp/alpine-fde-tstate.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_ROOT=$T/root
ETC=$(sp_etc_dir)
BYUUID=$T/by-uuid
FAKEBIN=$T/bin
mkdir -p "$ETC" "$BYUUID" "$FAKEBIN"

DIG7=$(printf '7%.0s' {1..64})

bl_write() { # PCR7-VALUE — a 2-field baseline fixture (the parser's shape)
    printf '{\n  "schema_version": 1,\n  "expected_pcr7": "%s"\n}\n' "$1" \
        >"$(sp_baseline_file)"
}

# --- LUKS2 metadata fixtures (both real-world shapes) -----------------------------
# PRETTY: the hand-written stub shape (4-space indent, ": " separators)
MD_PROV=$T/prov.json
cat >"$MD_PROV" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "AAA" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "BBB" } },
        "2": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "CCC" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": [11],
               "tpm2-blob": "AAEAC0RhdGE=", "tpm2-pcr-bank": "sha256" }
    }
}
EOF
# COMPACT: the cryptsetup 2.7.5 single-line form (format-tolerance pin)
MD_FIN=$T/fin.json
printf '%s' '{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7,11],"tpm2-pcr-bank":"sha256","tpm2-blob":"AAEAC0RhdGE="}}}' >"$MD_FIN"
# the mid-completion crash shape: upgraded token, ephemeral keyslot SURVIVES
MD_CRASH=$T/crash.json
printf '%s' '{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"},"2":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7,11]}}}' >"$MD_CRASH"
# exotic/missing token shapes
MD_PCR7=$T/pcr7.json
printf '%s' '{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-pcrs":[7]}}}' >"$MD_PCR7"
MD_NOTOKEN=$T/notoken.json
printf '%s' '{"keyslots":{"0":{"type":"luks2"}},"tokens":{}}' >"$MD_NOTOKEN"
MD_GARBAGE=$T/garbage.json
printf 'this is not LUKS2 metadata\n' >"$MD_GARBAGE"

# =================================================================================
# 1. derivation primitives ----------------------------------------------------------
assert_eq "token pcrs: provisional reads [11]" "[11]" "$(ts_token_pcrs "$MD_PROV")"
assert_eq "token pcrs: finalized reads [7,11] (compact shape)" "[7,11]" "$(ts_token_pcrs "$MD_FIN")"
assert_eq "token pcrs: no token -> empty" "" "$(ts_token_pcrs "$MD_NOTOKEN")"
assert_eq "token pcrs: garbage metadata -> empty (never a crash)" "" "$(ts_token_pcrs "$MD_GARBAGE")"

assert_eq "sealed inventory: the token's keyslot" "1" "$(ts_sealed_slots "$MD_PROV")"
assert_eq "ephemeral inventory: the temporary install keyslot (keyslot 2, §7.2)" "2" \
    "$(ts_ephemeral_slots "$MD_PROV")"
assert_eq "ephemeral inventory: purged at finalization -> empty" "" \
    "$(ts_ephemeral_slots "$MD_FIN")"
assert_rc "ephemeral present: rc 0 in the install-time shape" 0 ts_ephemeral_present "$MD_PROV"
assert_rc "ephemeral present: rc 1 in the at-rest shape (I1)" 1 ts_ephemeral_present "$MD_FIN"
assert_rc "recovery slot ok: exactly keyslot 0 beyond the sealed slots" 0 \
    ts_recovery_slot_ok "$MD_FIN"
assert_rc "recovery slot ok: the ephemeral slot breaks the at-rest shape" 1 \
    ts_recovery_slot_ok "$MD_PROV"

# =================================================================================
# 2. ts_state classification ----------------------------------------------------------
bl_write pending
assert_eq "ts_state: provisional token -> provisional (pending baseline)" "provisional" \
    "$(ts_state "$MD_PROV" "$(sp_baseline_file)")"
assert_eq "ts_state: mid-completion crash shape (token [7,11] + ephemeral) stays provisional" \
    "provisional" "$(ts_state "$MD_CRASH" "$(sp_baseline_file)")"
assert_eq "ts_state: finalized token + PENDING baseline -> unknown (fail-closed)" "unknown" \
    "$(ts_state "$MD_FIN" "$(sp_baseline_file)")"
bl_write "$DIG7"
assert_eq "ts_state: token [7,11] + no ephemeral + final baseline -> finalized" "finalized" \
    "$(ts_state "$MD_FIN" "$(sp_baseline_file)")"
assert_eq "ts_state: crash shape + final baseline -> still provisional (purge pending)" \
    "provisional" "$(ts_state "$MD_CRASH" "$(sp_baseline_file)")"
assert_eq "ts_state: exotic token pcrs [7] -> unknown" "unknown" \
    "$(ts_state "$MD_PCR7" "$(sp_baseline_file)")"
assert_eq "ts_state: no token -> unknown" "unknown" \
    "$(ts_state "$MD_NOTOKEN" "$(sp_baseline_file)")"
assert_eq "ts_state: garbage metadata -> unknown" "unknown" \
    "$(ts_state "$MD_GARBAGE" "$(sp_baseline_file)")"
assert_eq "ts_state: absent baseline file -> unknown even at token [7,11]" "unknown" \
    "$(ts_state "$MD_FIN" "$T/no-such-baseline.json")"

# =================================================================================
# 3. ts_first_member + ts_label (the degrade-safe top-level read) ----------------------
UUID=55555555-5555-5555-8555-555555555555
cat >"$T/root/etc/crypttab" <<EOF
root UUID=$UUID none luks,tpm2-device=auto
EOF
# cryptsetup stub: serve the fixture the by-uuid link points at
cat >"$FAKEBIN/cryptsetup" <<'EOF'
#!/bin/sh
# a real luksDump fails on non-LUKS2 input — mirror that (an unreadable
# container must be EMPTY from ts_label, never a classification)
grep -q '"keyslots"' "$(readlink -f "$3")" 2>/dev/null || exit 1
[ "$1" = "luksDump" ] && cat "$(readlink -f "$3")"
exit 0
EOF
chmod +x "$FAKEBIN/cryptsetup"
export ALPINE_FDE_CRYPTSETUP=$FAKEBIN/cryptsetup
export ALPINE_FDE_BY_UUID_DIR=$BYUUID

assert_eq "ts_first_member: no link -> empty, rc 1 (never dies)" "" "$(ts_first_member)"
ln -sfn "$MD_PROV" "$BYUUID/$UUID"
assert_eq "ts_first_member: resolves the crypttab member" "$BYUUID/$UUID" "$(ts_first_member)"
bl_write pending
assert_eq "ts_label: provisional container -> provisional" "provisional" "$(ts_label)"
ln -sfn "$MD_FIN" "$BYUUID/$UUID"
bl_write "$DIG7"
assert_eq "ts_label: finalized container + final baseline -> finalized" "finalized" "$(ts_label)"
rm -f "$BYUUID/$UUID"
assert_eq "ts_label: unreachable container -> EMPTY (report-only, never a die)" "" "$(ts_label)"
ln -sfn "$MD_GARBAGE" "$BYUUID/$UUID"
assert_eq "ts_label: unreadable metadata -> EMPTY" "" "$(ts_label)"
rm -f "$BYUUID/$UUID"
assert_eq "ts_label: no crypttab at all -> EMPTY" "" "$(ts_label)"

# =================================================================================
# 4. the ADR-8 attempt marker (fde_attempt_*) ------------------------------------------
assert_eq "attempt: absent initially" "" "$(fde_attempt_read)"
assert_rc "attempt: not present initially" 1 fde_attempt_present
A_RC=0
(fde_attempt_write "guard-failed: secureboot=0 setup_mode=0") || A_RC=$?
assert_eq "attempt: write rc 0" "0" "$A_RC"
assert_rc "attempt: present after write" 0 fde_attempt_present
assert_contains "attempt: read-back carries the reason" "$(fde_attempt_read)" "guard-failed"
assert_file_exists "attempt: marker at the etc dir" "$ETC/finalize-attempt.txt"
assert_eq "attempt: marker mode pinned 600" "600" "$(stat -c %a "$ETC/finalize-attempt.txt")"
fde_attempt_write "step-failed: token upgrade"
assert_contains "attempt: rewrite replaces (latest reason wins)" "$(fde_attempt_read)" \
    "step-failed"
assert_eq "attempt: rewrite leaves exactly ONE line" "1" \
    "$(wc -l <"$ETC/finalize-attempt.txt" | tr -d ' ')"
assert_rc "attempt: clear succeeds" 0 fde_attempt_clear
assert_rc "attempt: not present after clear" 1 fde_attempt_present
assert_eq "attempt: read empty after clear" "" "$(fde_attempt_read)"
fde_attempt_clear
assert_rc "attempt: clear is idempotent (absent file)" 0 fde_attempt_clear

# ALPINE_FDE_ATTEMPT_MARKER override (test seam)
OV=$T/custom-attempt.txt
export ALPINE_FDE_ATTEMPT_MARKER=$OV
fde_attempt_write "override-reason"
assert_file_exists "attempt: override write landed" "$OV"
assert_contains "attempt: override read-back" "$(fde_attempt_read)" "override-reason"
unset ALPINE_FDE_ATTEMPT_MARKER
assert_rc "attempt: override removed -> default path empty again" 1 fde_attempt_present

# atomicity: a failed rename leaves the previous marker intact
mkdir -p "$T/bin-mv"
printf '#!/bin/sh\necho "mv fault injection" >&2\nexit 1\n' >"$T/bin-mv/mv"
chmod +x "$T/bin-mv/mv"
export ALPINE_FDE_ATTEMPT_MARKER=$OV
fde_attempt_write "before-fault"
OLD_PATH=$PATH
export PATH="$T/bin-mv:$PATH"
ARC=0
(fde_attempt_write "after-fault") || ARC=$?
assert_ne "attempt: rename fault -> nonzero" "0" "$ARC"
assert_contains "attempt: previous marker intact after the fault" "$(fde_attempt_read)" \
    "before-fault"
assert_eq "attempt: no temp litter after the failed write" "" \
    "$(find "$(dirname "$OV")" -maxdepth 1 -name '.finalize-attempt.*' -print -quit)"
export PATH="$OLD_PATH"
unset ALPINE_FDE_ATTEMPT_MARKER

# root scoping: the marker follows the root-scoped etc dir
fde_attempt_write "step-failed"
ROOT2=$T/root2
export ALPINE_FDE_ROOT=$ROOT2
mkdir -p "$(sp_etc_dir)"
assert_rc "attempt: scoped root has no marker" 1 fde_attempt_present
fde_attempt_write "scoped-reason"
assert_contains "attempt: scoped write lands in the scoped root" "$(fde_attempt_read)" \
    "scoped-reason"
export ALPINE_FDE_ROOT=$T/root
assert_contains "attempt: root1 marker unaffected" "$(fde_attempt_read)" "step-failed"
fde_attempt_clear

# =================================================================================
# 5. RESIDUE PINS: the retired machinery is gone everywhere shipped (item 10b) ----------
for p in 'install-state' 'istate_' 'ALPINE_FDE_INSTALL_STATE' 'ALPINE_FDE_INSTALL_ATTEMPT' 'FDE_STATE_ONLY'; do
    assert_eq "residue: '$p' zero in lib/ hooks/ bin/ (beyond the item-10b design notes)" "0" \
        "$(grep -rF -- "$p" "$REPO/lib" "$REPO/hooks" "$REPO/bin" 2>/dev/null | grep -vF 'item 10b' | wc -l)"
done
assert_eq "residue: the unseal hook persists NOTHING (no write primitives beyond msg/err)" "0" \
    "$(grep -cE '(mktemp|mv -f|>[[:space:]]*["]?[$]?[A-Za-z_]*(file|path))' "$REPO/hooks/mkinitfs/alpine-fde-unseal.sh" | grep -x 0 || echo 0)"
assert_eq "residue: lib/install-state.sh deleted" "0" \
    "$([ -e "$REPO/lib/install-state.sh" ] && echo 1 || echo 0)"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
