#!/usr/bin/env bash
# tests/unit/finalize_service_guard.sh — G-IL9/G-IL10 (§9.1 Stage 3, §10): the
# first-boot finalization cmd (`debian-fde finalize`, driven at boot by
# hooks/systemd/debian-fde-finalize.service), exercised END-TO-END with the
# real command and stubbed seams (DEBIAN_FDE_EFIVARS_DIR, DEBIAN_FDE_CRYPTENROLL,
# DEBIAN_FDE_CRYPTSETUP, DEBIAN_FDE_ROOT, DEBIAN_FDE_BY_UUID_DIR, PATH tpm2):
#   * SB-off  ⇒ 64 + the §9.1 instruction text, state stays `installed`,
#     ZERO enrollment attempts, baseline untouched
#   * SB-on fresh ⇒ audit --init once + exactly ONE enrollment per crypttab
#     member, state `finalized` written LAST
#   * crash matrix (§9.1/§10): baseline-final-no-tokens, token-standing, and
#     interrupted-mid-members each converge under an immediate re-run
#   * member-2 failure ⇒ state stays installed, member-1 token stands, resume
#     enrolls ONLY member 2

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"

T=$(mktemp -d /tmp/debian-fde-final.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
LUKS_DIR=$T/luks
BYUUID=$T/by-uuid
U1=11111111-1111-4111-8111-111111111111
U2=22222222-2222-4222-8222-222222222222
D7=$(printf '7%.0s' {1..64})
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
export DEBIAN_FDE_BY_UUID_DIR=$BYUUID
export DEBIAN_FDE_CRYPTENROLL=$FAKEBIN/cryptenroll-stub
export DEBIAN_FDE_CRYPTSETUP=$FAKEBIN/cryptsetup-stub
export DEBIAN_FDE_ENROLL_LOCK=$T/enroll.lock
export DEBIAN_FDE_NO_INSTALL=1
export CE_LOG=$T/cryptenroll.log TPM2_LOG=$T/tpm2.log
export LUKS_DIR FAIL_MEMBER=''

cleanup() { rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "$LUKS_DIR" "$BYUUID" "$(sp_etc_dir)" "$T/keys"

# --- seams ---------------------------------------------------------------------
# tpm2: getcap answers (tpm_available), fixed PCR digests in the real
# tpm2-tools pcrread list format (lib/baseline.sh tpm_pcr_read parses
# "    <idx> : 0x<hex>" lines)
cat >"$FAKEBIN/tpm2" <<EOF
#!/bin/sh
echo "CALL \$*" >>'$TPM2_LOG'
[ "\$1" = getcap ] && { echo 'TPM2_PT_FIXED:'; exit 0; }
if [ "\$1" = pcrread ]; then
    case \$2 in
        sha256:0) echo '  sha256:'; echo '    0 : 0x$(printf 'a%.0s' {1..64})'; exit 0 ;;
        sha256:1) echo '  sha256:'; echo '    1 : 0x$(printf 'b%.0s' {1..64})'; exit 0 ;;
        sha256:2) echo '  sha256:'; echo '    2 : 0x$(printf 'c%.0s' {1..64})'; exit 0 ;;
        sha256:3) echo '  sha256:'; echo '    3 : 0x$(printf 'd%.0s' {1..64})'; exit 0 ;;
        sha256:7) echo '  sha256:'; echo '    7 : 0x$D7'; exit 0 ;;
    esac
fi
exit 1
EOF
# cryptsetup: serve the CURRENT per-member LUKS2 metadata document
cat >"$FAKEBIN/cryptsetup-stub" <<'EOF'
#!/bin/sh
if [ "$1" = "luksDump" ]; then
    f="$LUKS_DIR/$(basename "$3").json"
    [ -f "$f" ] || { echo "cryptsetup stub: no metadata fixture for $3" >&2; exit 1; }
    cat "$f"
    exit 0
fi
exit 1
EOF
# systemd-cryptenroll: enroll = mutate the member's metadata (fresh keyslot 1 +
# one systemd-tpm2 token); FAIL_MEMBER injects a per-member enrollment failure
cat >"$FAKEBIN/cryptenroll-stub" <<'EOF'
#!/bin/sh
echo "CALL $*" >>"$CE_LOG"
dev=''
for a in "$@"; do dev=$a; done   # the device is the LAST argv element
b=$(basename "$dev")
if [ -n "$FAIL_MEMBER" ] && [ "$b" = "$FAIL_MEMBER" ]; then
    echo "cryptenroll stub: injected enrollment failure for $b" >&2
    exit 1
fi
f="$LUKS_DIR/$b.json"
[ -f "$f" ] || { echo "cryptenroll stub: no metadata fixture for $dev" >&2; exit 1; }
jq '.keyslots["1"] = {"type":"luks2"}
   | .tokens["0"] = {"type":"systemd-tpm2","keyslots":["1"]}' "$f" >"$f.tmp" \
    && mv "$f.tmp" "$f" || exit 1
exit 0
EOF
chmod +x "$FAKEBIN/tpm2" "$FAKEBIN/cryptsetup-stub" "$FAKEBIN/cryptenroll-stub"
export PATH="$FAKEBIN:$PATH"

# --- fixtures --------------------------------------------------------------------
mkvar() { # NAME BYTE — efivars fixture (attrs header + payload byte)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkcertvar() { # NAME CONTENT
    printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_state() { # SECUREBOOT SETUPMODE — full key tree (the §8.4 guard state)
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
    mkcertvar PK pk-cert-v1
    mkcertvar KEK kek-cert-v1
    mkcertvar db db-cert-v1
    mkcertvar dbx dbx-cert-v1
}

EMPTY_JSON='{"keyslots": {"0": {"type": "luks2", "kdf": {"type": "argon2id", "salt": "AAA"}}}, "tokens": {}}'
printf '%s' "$EMPTY_JSON" >"$LUKS_DIR/$U1.json"
printf '%s' "$EMPTY_JSON" >"$LUKS_DIR/$U2.json"
cp "$LUKS_DIR/$U1.json" "$LUKS_DIR/$U1.empty"
cp "$LUKS_DIR/$U2.json" "$LUKS_DIR/$U2.empty"
: >"$BYUUID/$U1"
: >"$BYUUID/$U2"
printf 'root1 UUID=%s none luks,tpm2-device=auto,password-cache=yes,discard\nroot2 UUID=%s none luks,tpm2-device=auto,password-cache=yes,discard\n' \
    "$U1" "$U2" >"$T/root/etc/crypttab"
printf 'RELEASE-PUB-MATERIAL' >"$T/keys/release.pub"
BL_PCR0=pending BL_PCR1=pending BL_PCR2=pending BL_PCR3=pending BL_PCR7=pending \
    BL_KEYS_RELEASE_PUB_PATH="$T/keys/release.pub" BL_TARGET_LUKS_UUID="$U1" \
    baseline_write "$(sp_baseline_file)"

run_finalize() {
    FIN_OUT=$("$REPO/bin/debian-fde" finalize "$@" 2>&1)
    FIN_RC=$?
}
wipe_tokens() {
    cp "$LUKS_DIR/$U1.empty" "$LUKS_DIR/$U1.json"
    cp "$LUKS_DIR/$U2.empty" "$LUKS_DIR/$U2.json"
}

# --- 1. SB off ⇒ 64 + §9.1 instruction, state installed, ZERO enroll attempts ---
sb_state 0 0
istate_write installed
: >"$CE_LOG"
: >"$TPM2_LOG"
run_finalize
assert_eq "SB off: rc 64" "64" "$FIN_RC"
assert_contains "SB off: §9.1 instruction text" "$FIN_OUT" \
    "Secure Boot is not enabled with your custom keys"
assert_contains "SB off: instruction names the BIOS action" "$FIN_OUT" \
    "Reboot into BIOS setup and toggle Secure Boot ON"
assert_eq "SB off: install state stays installed" "installed" "$(istate_state)"
assert_eq "SB off: ZERO enrollment attempts" "" "$(cat "$CE_LOG")"
assert_rc "SB off: baseline still pending (no audit --init)" 0 \
    baseline_is_pending "$(sp_baseline_file)"
assert_eq "SB off: no last-audit written" "absent" \
    "$([ -f "$(sp_last_audit_file)" ] && echo present || echo absent)"

# --- 1b. SetupMode=1 is equally refused (keys not in the final state) ------------
sb_state 1 1
run_finalize
assert_eq "SetupMode=1: rc 64" "64" "$FIN_RC"
assert_contains "SetupMode=1: refusal names Secure Boot" "$FIN_OUT" "Secure Boot"
assert_eq "SetupMode=1: state stays installed" "installed" "$(istate_state)"

# --- 2. SB on, fresh install ⇒ audit once + one enrollment per member ------------
sb_state 1 0
: >"$CE_LOG"
: >"$TPM2_LOG"
run_finalize
assert_eq "SB on fresh: rc 0" "0" "$FIN_RC"
assert_eq "SB on fresh: state finalized" "finalized" "$(istate_state)"
assert_rc "SB on fresh: baseline final" 0 baseline_is_final "$(sp_baseline_file)"
assert_eq "SB on fresh: expected_pcr7 recorded from live" "$D7" \
    "$(baseline_get "$(sp_baseline_file)" expected_pcr7)"
assert_file_exists "SB on fresh: last-audit written" "$(sp_last_audit_file)"
assert_contains "SB on fresh: audit summary printed" "$FIN_OUT" "audit summary"
assert_contains "SB on fresh: summary carries the recorded PCR 7" "$FIN_OUT" "$D7"
assert_contains "SB on fresh: scp backup reminder (§9.1)" "$FIN_OUT" \
    "scp -r $(sp_etc_dir)/keys/"
assert_eq "SB on fresh: exactly one cryptenroll per member" "2" "$(grep -c '^CALL' "$CE_LOG")"
assert_eq "member 1 enrolled exactly once" "1" "$(grep -c -- "$BYUUID/$U1\$" "$CE_LOG")"
assert_eq "member 2 enrolled exactly once" "1" "$(grep -c -- "$BYUUID/$U2\$" "$CE_LOG")"
assert_contains "the audit step ran (tpm2 consulted)" "$(cat "$TPM2_LOG")" "pcrread"
assert_eq "member 1 metadata carries the token" "1" \
    "$(luks_json_count_type "$LUKS_DIR/$U1.json" systemd-tpm2)"
assert_eq "member 2 metadata carries the token" "1" \
    "$(luks_json_count_type "$LUKS_DIR/$U2.json" systemd-tpm2)"
TPM2_AFTER_AUDIT=$(md5sum "$TPM2_LOG" | cut -d' ' -f1)

# --- 3. re-run after success ⇒ loud no-op ----------------------------------------
CP_CE=$(cat "$CE_LOG")
run_finalize
assert_eq "already finalized: rc 0" "0" "$FIN_RC"
assert_contains "already finalized: loud no-op message" "$FIN_OUT" "already finalized"
assert_eq "already finalized: zero additional enrollments" "$CP_CE" "$(cat "$CE_LOG")"
assert_eq "already finalized: no re-audit (tpm2 untouched)" "$TPM2_AFTER_AUDIT" \
    "$(md5sum "$TPM2_LOG" | cut -d' ' -f1)"

# --- 4. crash matrix A: baseline final + state installed + no tokens --------------
# (crash between audit --init and enrollment) ⇒ skips audit, enrolls, finalizes
istate_write installed
wipe_tokens
: >"$CE_LOG"
LA_BEFORE=$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)
run_finalize
assert_eq "crash A: rc 0" "0" "$FIN_RC"
assert_eq "crash A: state finalized" "finalized" "$(istate_state)"
assert_eq "crash A: audit --init SKIPPED (tpm2 untouched)" "$TPM2_AFTER_AUDIT" \
    "$(md5sum "$TPM2_LOG" | cut -d' ' -f1)"
assert_eq "crash A: last-audit not re-written" "$LA_BEFORE" \
    "$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)"
assert_eq "crash A: both members enrolled once each" "2" "$(grep -c '^CALL' "$CE_LOG")"

# --- 5. crash matrix B: token already standing on member 1 only -------------------
# (crash between member enrollments) ⇒ member 1 skipped with zero TPM ops,
# member 2 enrolled, state finalized
istate_write installed
cp "$LUKS_DIR/$U1.empty" "$LUKS_DIR/$U1.json"
cp "$LUKS_DIR/$U2.empty" "$LUKS_DIR/$U2.json"
FAIL_MEMBER='' "$DEBIAN_FDE_CRYPTENROLL" --tpm2-device=auto --tpm2-pcrs=7 \
    --tpm2-public-key="$T/keys/release.pub" --tpm2-public-key-pcrs=11 "$BYUUID/$U1" \
    >/dev/null 2>&1
cp "$LUKS_DIR/$U1.json" "$LUKS_DIR/$U1.standing"
: >"$CE_LOG"
run_finalize
assert_eq "crash B: rc 0" "0" "$FIN_RC"
assert_eq "crash B: state finalized" "finalized" "$(istate_state)"
assert_eq "crash B: exactly ONE enrollment (member 2 only)" "1" "$(grep -c '^CALL' "$CE_LOG")"
assert_eq "crash B: the enrollment targeted member 2" "1" "$(grep -c -- "$BYUUID/$U2\$" "$CE_LOG")"
assert_not_contains "crash B: member 1 untouched (token stands, zero TPM ops)" \
    "$(cat "$CE_LOG")" "$BYUUID/$U1"
assert_eq "crash B: member 1 token count still exactly 1" "1" \
    "$(luks_json_count_type "$LUKS_DIR/$U1.json" systemd-tpm2)"

# --- 6. member-2 enrollment fails ⇒ state installed, member-1 stands, resume -----
istate_write installed
wipe_tokens
: >"$CE_LOG"
FAIL_MEMBER=$U2 run_finalize
assert_eq "member-2 failure: rc 64" "64" "$FIN_RC"
assert_eq "member-2 failure: state stays installed" "installed" "$(istate_state)"
assert_contains "member-2 failure: message names the member" "$FIN_OUT" "$U2"
assert_eq "member-2 failure: member 1 enrolled before the failure" "1" \
    "$(luks_json_count_type "$LUKS_DIR/$U1.json" systemd-tpm2)"
assert_eq "member-2 failure: member 2 has NO token" "0" \
    "$(luks_json_count_type "$LUKS_DIR/$U2.json" systemd-tpm2)"
assert_file_exists "member-2 failure: audit had succeeded" "$(sp_last_audit_file)"
FAIL_MEMBER=''
: >"$CE_LOG"
TPM2_SNAP=$(md5sum "$TPM2_LOG" | cut -d' ' -f1)
run_finalize
assert_eq "resume: rc 0" "0" "$FIN_RC"
assert_eq "resume: state finalized" "finalized" "$(istate_state)"
assert_eq "resume: exactly one more enrollment" "1" "$(grep -c '^CALL' "$CE_LOG")"
assert_eq "resume: targeted member 2 ONLY" "1" "$(grep -c -- "$BYUUID/$U2\$" "$CE_LOG")"
assert_not_contains "resume: member 1 not re-enrolled" "$(cat "$CE_LOG")" "$BYUUID/$U1"
assert_eq "resume: audit skipped (baseline already final)" "$TPM2_SNAP" \
    "$(md5sum "$TPM2_LOG" | cut -d' ' -f1)"

# --- 7. garbage / unexpected state fails closed ------------------------------------
printf '{"schema_version": 1, "state": "weird", "updated_at": "2026-09-19T00:00:00Z"}' \
    >"$(sp_etc_dir)/install-state.json"
run_finalize
assert_eq "garbage state: rc 64" "64" "$FIN_RC"
assert_contains "garbage state: message names the state" "$FIN_OUT" "unexpected install state"

# --- 8. absent state file ⇒ loud no-op rc 0 (pre-state-machine install) -----------
rm -f "$(sp_etc_dir)/install-state.json"
: >"$CE_LOG"
run_finalize
assert_eq "absent state: rc 0" "0" "$FIN_RC"
assert_contains "absent state: loud no-op" "$FIN_OUT" "nothing to finalize"
assert_eq "absent state: zero enrollments" "" "$(cat "$CE_LOG")"

# --- 9. CLI surface: help + unknown arg -------------------------------------------
run_finalize --help
assert_eq "finalize --help: rc 0" "0" "$FIN_RC"
assert_contains "finalize --help: usage" "$FIN_OUT" "Usage: debian-fde finalize"
FIN_OUT=$("$REPO/bin/debian-fde" finalize --bogus 2>&1)
FIN_RC=$?
assert_eq "finalize --bogus: usage rc 2" "2" "$FIN_RC"
assert_contains "finalize --bogus: named in the error" "$FIN_OUT" "unknown argument"

# --- 10. the boot unit: ordering + oneshot + state-aware (no path condition) ------
UNIT=$REPO/hooks/systemd/debian-fde-finalize.service
assert_file_exists "finalize unit exists" "$UNIT"
UNIT_TXT=$(cat "$UNIT")
assert_contains "unit: Type=oneshot" "$UNIT_TXT" "Type=oneshot"
assert_contains "unit: ExecStart targets the tooling copy" "$UNIT_TXT" \
    "ExecStart=/usr/local/bin/debian-fde finalize"
assert_contains "unit: After=local-fs.target (all local mounts up)" "$UNIT_TXT" \
    "local-fs.target"
assert_contains "unit: After=cryptsetup.target (all LUKS members unlocked)" "$UNIT_TXT" \
    "cryptsetup.target"
assert_contains "unit: After=tpm2.target (TPM device accessible)" "$UNIT_TXT" "tpm2.target"
assert_contains "unit: enabled via multi-user.target" "$UNIT_TXT" "WantedBy=multi-user.target"
assert_not_contains "unit: no ConditionPathExists — the cmd is state-aware" "$UNIT_TXT" \
    "ConditionPathExists"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
