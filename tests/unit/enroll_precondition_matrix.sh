#!/usr/bin/env bash
# tests/unit/enroll_precondition_matrix.sh — `debian-fde enroll-tpm` after the
# Mechanism B rewire (ADR-19/ADR-20: systemd-cryptenroll is GONE — lib/seal.sh
# + lib/token.sh do the sealing; cryptsetup stays the LUKS2 seam):
#   * precondition matrix: SB off / SetupMode=1 / PCR7 drift / pending
#     baseline / missing baseline / invalid baseline / unresolvable LUKS uuid /
#     missing release.pub in KEYDIR — all fail-closed 64, NO TPM contact before
#     the documented precondition (tpm2 recorder wrapper), no enrolled.json
#   * KEYDIR-explicit key source (G-B7): the enrollment anchors the release key
#     from DEBIAN_FDE_KEYDIR, NEVER from baseline keys.release_pub_path (the
#     baseline pins a DECOY path throughout)
#   * policy_mode: b canonical (a2/native aliases); a / ap / a-prime / combined
#     fail closed 64 citing ADR-19 BEFORE any package/precondition work
#   * CLI-level happy path with the REAL seal against swtpm (cryptsetup
#     stubbed): explicit --pcrsig AND the in-process re-sign fallback
#     (DEBIAN_FDE_PCRSIG unset — release.pem from the keydir via keys_unlock);
#     tampered .pcrsig -> 64, no keyslot, no token, no record (G-B6)
#   * compact LUKS2 wire shape (real cryptsetup dumps): parsers + reseat work
#   * dry-run prints the plan, touches nothing; `ukictl enroll` alias: same
#     surface
#   * function-level (enrl_run, seal ops stubbed): choreography order, retire
#     on reseat, >1 standing tokens refuse loudly, post-assert failures record
#     nothing, passphrase scrubbed, G-IL7/HW-3 ensure-once contract intact

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"

T=$(mktemp -d /tmp/debian-fde-enroll-matrix.XXXXXX)
STATE=$T/swtpm
FAKEBIN=$T/bin
EFIVARS=$T/efivars
BYUUID=$T/by-uuid
CS_LOG=$T/cryptsetup.log
TPM_LOG=$T/tpm2.log
UUID=12345678-90ab-cdef-1234-567890abcdef
KEYDIR=$REPO/fixtures/keys
DER=$(openssl pkey -pubin -in "$KEYDIR/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
export DEBIAN_FDE_BY_UUID_DIR=$BYUUID
export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_ENROLL_LOCK=$T/enroll.lock
export DEBIAN_FDE_KEYDIR=$KEYDIR
export DEBIAN_FDE_CRYPTSETUP=$FAKEBIN/cryptsetup

REAL_TPM2=$(command -v tpm2)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "$BYUUID" "$T/keys" "$(sp_etc_dir 2>/dev/null || echo "$T/root/etc/debian-fde")"

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_vars() { # SB SETUPMODE
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
}

# --- cryptsetup stub: serve pre/post metadata, record mutations --------------------
cat >"$FAKEBIN/cryptsetup" <<EOF
#!/bin/sh
case "\$1" in
    luksDump)
        echo "CALL luksDump \$3" >>'$CS_LOG'
        n=\$(cat "$T/counter" 2>/dev/null || echo 0)
        n=\$((n + 1))
        echo "\$n" >"$T/counter"
        if [ "\$n" = "1" ]; then cat "$T/luks-pre.json"; else cat "$T/luks-post.json"; fi
        exit 0
        ;;
    luksAddKey|token|luksKillSlot)
        echo "CALL \$*" >>'$CS_LOG'
        exit 0
        ;;
esac
exit 0
EOF
# --- tpm2 recorder wrapper: log + exec the real binary (TPM-contact observability) --
cat >"$FAKEBIN/tpm2" <<EOF
#!/bin/sh
echo "CALL \$1 \$2" >>'$TPM_LOG'
exec "$REAL_TPM2" "\$@"
EOF
chmod +x "$FAKEBIN/cryptsetup" "$FAKEBIN/tpm2"

# LUKS2 metadata fixtures. POST_OK mirrors what the REAL runtime must produce:
# free slot 2 (0 recovery + 1 taken in pre), token id 0, the REAL release-pub
# DER b64, pcrs [7,11] — so the real token_post_assert can pass against it.
write_pre_notoken() {
    cat >"$T/luks-pre.json" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "AAA" } },
        "1": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "BBB" } }
    },
    "tokens": {}
}
EOF
}
write_pre_token() {
    cat >"$T/luks-pre.json" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "AAA" } },
        "1": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "BBB" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"], "tpm2-blob": "AAEAC0RhdGE=" }
    }
}
EOF
}
write_post_ok() { # SLOT(=2)
    jq -n --arg der "$DER" '{
        "keyslots": {
            "0": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "AAA" } },
            "1": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "BBB" } },
            "2": { "type": "luks2", "key_size": 64, "kdf": { "type": "argon2id", "salt": "CCC" } }
        },
        "tokens": {
            "0": { "type": "systemd-tpm2", "keyslots": ["3"],
                   "tpm2-blob": "AAEAC0RhdGE=", "tpm2-pcrs": [7, 11],
                   "tpm2-pcr-bank": "sha256", "tpm2-pubkey": $der,
                   "tpm2-signature": "U0lH" }
        }
    }' >"$T/luks-post.json"
}
write_post_two() {
    jq -n --arg der "$DER" '{
        "keyslots": { "0": { "type": "luks2" }, "1": { "type": "luks2" } },
        "tokens": {
            "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
            "7": { "type": "systemd-tpm2", "keyslots": ["1"] }
        }
    }' >"$T/luks-post.json"
}
# compact single-line documents (the shape REAL cryptsetup 2.7.x emits) for the
# standing-token reseat leg: slot 0 byte-identical, new slot 2, old slot 1 gone
write_compact_pre_token() {
    printf '%s\n' '{"keyslots":{"0":{"type":"luks2","key_size":64,"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000}},"1":{"type":"luks2","key_size":64,"kdf":{"type":"argon2id"}}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}}' >"$T/luks-pre.json"
}
write_compact_post_reseat() {
    printf '%s\n' "{\"keyslots\":{\"0\":{\"type\":\"luks2\",\"key_size\":64,\"kdf\":{\"type\":\"pbkdf2\",\"hash\":\"sha256\",\"iterations\":1000}},\"1\":{\"type\":\"luks2\",\"key_size\":64,\"kdf\":{\"type\":\"argon2id\"}},\"2\":{\"type\":\"luks2\",\"key_size\":64,\"kdf\":{\"type\":\"argon2id\"}}},\"tokens\":{\"0\":{\"type\":\"systemd-tpm2\",\"keyslots\":[\"3\"],\"tpm2-blob\":\"AAEAC0RhdGE=\",\"tpm2-pcrs\":[7,11],\"tpm2-pcr-bank\":\"sha256\",\"tpm2-pubkey\":\"$DER\",\"tpm2-signature\":\"U0lH\"}}}" >"$T/luks-post.json"
}

reset_state() { # counters + logs + record only — fixture files are the caller's
    : >"$CS_LOG"
    : >"$TPM_LOG"
    echo 0 >"$T/counter"
    rm -f "$(sp_enrolled_file)"
}
restore_state() { # the default pre/post pair (0 tokens pre; consistent post)
    reset_state
    write_pre_notoken
    write_post_ok
}

assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export DEBIAN_FDE_TCTI=$SWTPM_TCTI

LIVE_PCR7=$(swtpm_pcrread "$STATE" 7)
# swtpm_pcrread's field parser mis-splits two-digit indices ("11:" glues the
# colon) — read PCR 11 format-independently (the seal_pcrread method)
tpm pcrread -Q -o "$T/pcr11.bin" sha256:11 2>/dev/null
LIVE_PCR11=$(od -An -v -tx1 "$T/pcr11.bin" | tr -d ' \n')
HEX_AB=$(printf 'ab%.0s' {1..32})

make_baseline() { # PENDING|FINAL — release_pub_path deliberately points at a
    # DECOY: the enrollment must use DEBIAN_FDE_KEYDIR, never the baseline (G-B7)
    case $1 in
        pending) BL_PCR7='pending' ;;
        final) BL_PCR7="$LIVE_PCR7" ;;
    esac
    BL_PCR0="$LIVE_PCR7"
    BL_PCR1="$LIVE_PCR7"
    BL_PCR2="$LIVE_PCR7"
    BL_PCR3="$LIVE_PCR7"
    BL_KEYS_RELEASE_PUB_PATH="$T/keys/DECOY-never-use.pub"
    BL_TARGET_LUKS_UUID="$UUID"
    baseline_write "$(sp_baseline_file)"
}
BL=$(sp_baseline_file)

assert_absent() { # DESC PATH
    if [ -e "$2" ]; then assert_eq "$1" "absent" "present"; else assert_eq "$1" "absent" "absent"; fi
}

run_enroll() { # args...
    restore_state
    ENROLL_OUT=$("$REPO/bin/debian-fde" enroll-tpm "$@" 2>&1)
    ENROLL_RC=$?
}

# --- 1. missing baseline ----------------------------------------------------------
make_baseline final
rm -f "$BL"
run_enroll
assert_eq "no baseline -> fail-closed" "64" "$ENROLL_RC"
assert_eq "no baseline: NO tpm2 contact" "0" "$(grep -c . "$TPM_LOG")"

# --- 2. invalid baseline (schema 2) -------------------------------------------------
make_baseline final
sed -i 's/"schema_version": "1"/"schema_version": "2"/' "$BL"
run_enroll
assert_eq "invalid baseline -> fail-closed" "64" "$ENROLL_RC"
assert_eq "invalid baseline: NO tpm2 contact" "0" "$(grep -c . "$TPM_LOG")"

# --- 3. pending baseline --------------------------------------------------------------
make_baseline pending
run_enroll
assert_eq "pending baseline -> fail-closed" "64" "$ENROLL_RC"
assert_contains "pending message points to audit --init" "$ENROLL_OUT" "audit --init"
assert_eq "pending: NO tpm2 contact" "0" "$(grep -c . "$TPM_LOG")"

# --- 4. Secure Boot off -----------------------------------------------------------------
make_baseline final
sb_vars 0 0
run_enroll
assert_eq "SB off -> fail-closed" "64" "$ENROLL_RC"
assert_contains "SB off message cites I5" "$ENROLL_OUT" "I5"
assert_eq "SB off: NO tpm2 contact" "0" "$(grep -c . "$TPM_LOG")"

# --- 5. SetupMode=1 -----------------------------------------------------------------------
sb_vars 1 1
run_enroll
assert_eq "SetupMode=1 -> fail-closed" "64" "$ENROLL_RC"
assert_eq "SetupMode: NO tpm2 contact" "0" "$(grep -c . "$TPM_LOG")"

# --- 6. PCR 7 drift --------------------------------------------------------------------------
sb_vars 1 0
make_baseline final
BL_PCR7="$HEX_AB" baseline_write "$BL"
run_enroll
assert_eq "PCR7 drift -> fail-closed" "64" "$ENROLL_RC"
assert_contains "drift message shows both digests" "$ENROLL_OUT" "$HEX_AB"

# --- 7. missing release.pub in KEYDIR (G-B7: the keydir is the key source) --------------------
sb_vars 1 0
make_baseline final
KEYDIR_SAVED=$DEBIAN_FDE_KEYDIR
DEBIAN_FDE_KEYDIR=$T/empty-keydir
run_enroll
DEBIAN_FDE_KEYDIR=$KEYDIR_SAVED
assert_eq "missing keydir release.pub -> fail-closed" "64" "$ENROLL_RC"

# --- 8. LUKS uuid unresolvable -----------------------------------------------------------------
sb_vars 1 0
make_baseline final
run_enroll
assert_eq "unresolvable uuid -> fail-closed" "64" "$ENROLL_RC"
assert_contains "uuid message names the device" "$ENROLL_OUT" "$DEBIAN_FDE_BY_UUID_DIR/$UUID"
: >"$BYUUID/$UUID" # resolvable from here on

# --- 9. policy_mode ladder at the CLI (b accepted; documented-absent rungs -> 64 ADR-19) --------
make_baseline final
run_enroll_mode() { # MODE
    reset_state
    sb_vars 1 0
    MODE_OUT=$(policy_mode="$1" "$REPO/bin/debian-fde" enroll-tpm 2>&1)
    MODE_RC=$?
}
for m in a ap a-prime combined; do
    run_enroll_mode "$m"
    assert_eq "mode $m: documented-absent -> fail-closed 64" "64" "$MODE_RC"
    assert_contains "mode $m: message cites ADR-19" "$MODE_OUT" "ADR-19"
    assert_contains "mode $m: message names the normative Mechanism B path" "$MODE_OUT" "Mechanism B"
    assert_absent "mode $m: no enrolled.json" "$(sp_enrolled_file)"
done
run_enroll_mode definitely-not-a-mode
assert_eq "mode garbage: rc 64 (usage-class die)" "64" "$MODE_RC"
assert_contains "mode garbage message" "$MODE_OUT" "invalid policy_mode"

# b passes the gate: the FULL CLI happy path (real seal vs swtpm; in-process
# re-sign fallback — no --pcrsig given, release.pem from the keydir) succeeds.
run_enroll_mode b
assert_eq "mode b: enroll rc 0 via in-process re-sign" "0" "$MODE_RC"
assert_eq "enrolled.json policy_mode is b (canonical)" "b" "$(baseline_get "$(sp_enrolled_file)" policy_mode)"
assert_eq "enrolled.json token keyslot (free slot on the fixture)" "3" "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"
assert_contains "luksAddKey went through the cryptsetup seam" "$(grep CALL "$CS_LOG")" "luksAddKey"
assert_contains "token import went through the cryptsetup seam" "$(grep CALL "$CS_LOG")" "token import"
run_enroll_mode a2
assert_eq "a2 alias reaches the same path" "0" "$MODE_RC"
run_enroll_mode native
assert_eq "native alias reaches the same path" "0" "$MODE_RC"

# --- 10. --pcrsig: explicit source + G-B6 CLI negatives -------------------------------------------
sb_vars 1 0
PSIG=$T/pcrsig.json
policy_sign_json "$LIVE_PCR7" "$LIVE_PCR11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$PSIG"
run_enroll --pcrsig "$PSIG"
assert_eq "explicit --pcrsig: enroll rc 0" "0" "$ENROLL_RC"

sed 's/"sig": "./"sig": "B/' "$PSIG" >"$T/pcrsig-tampered.json"
run_enroll --pcrsig "$T/pcrsig-tampered.json"
assert_eq "tampered .pcrsig -> fail-closed 64" "64" "$ENROLL_RC"
assert_eq "tampered: NO luksAddKey" "0" "$(grep -c luksAddKey "$CS_LOG")"
assert_eq "tampered: NO token import" "0" "$(grep -c 'token import' "$CS_LOG")"
assert_absent "tampered: no enrolled.json" "$(sp_enrolled_file)"

# wrong-selection: a {7,11}-expecting CLI fed an 11-only .pcrsig -> 64
jq -c '.sha256[0].pcrs = [11]' "$PSIG" >"$T/pcrsig-11only.json"
run_enroll --pcrsig "$T/pcrsig-11only.json"
assert_eq "wrong-selection .pcrsig -> fail-closed 64" "64" "$ENROLL_RC"
assert_eq "wrong-selection: NO luksAddKey" "0" "$(grep -c luksAddKey "$CS_LOG")"

# --- 11. compact LUKS2 wire shape: standing token reseat --------------------------------------------
sb_vars 1 0
make_baseline final
reset_state
write_compact_pre_token
write_compact_post_reseat
ENROLL_OUT=$("$REPO/bin/debian-fde" enroll-tpm --reseat 2>&1)
ENROLL_RC=$?
assert_eq "compact standing token: reseat rc 0" "0" "$ENROLL_RC"
assert_eq "compact reseat: old slot retired via luksKillSlot" "1" "$(grep -c luksKillSlot "$CS_LOG")"

# --- 12. dry-run: prints the plan, runs nothing ------------------------------------------------------
make_baseline final
sb_vars 1 0
run_enroll --dry-run
assert_eq "dry-run rc 0" "0" "$ENROLL_RC"
assert_contains "dry-run names the mode" "$ENROLL_OUT" "policy_mode=b"
assert_contains "dry-run names the device" "$ENROLL_OUT" "$DEBIAN_FDE_BY_UUID_DIR/$UUID"
assert_eq "dry-run: no keyslot mutation" "0" "$(grep -c luksAddKey "$CS_LOG")"
assert_eq "dry-run: no token import" "0" "$(grep -c 'token import' "$CS_LOG")"
assert_absent "dry-run writes no enrolled.json" "$(sp_enrolled_file)"

# --- 13. `ukictl enroll` alias: identical surface ------------------------------------------------------
sb_vars 1 0
run_enroll --dry-run
PLAN=$(printf '%s\n' "$ENROLL_OUT" | grep 'policy_mode=b')
reset_state # fresh metadata counter — the alias must see the SAME pre-state
ALIAS_OUT=$("$REPO/bin/debian-fde" ukictl enroll --dry-run 2>&1)
ALIAS_RC=$?
assert_eq "ukictl enroll alias: same rc" "0" "$ALIAS_RC"
assert_contains "ukictl enroll alias: same plan line" "$ALIAS_OUT" "$PLAN"

# --- 14. function level: enrl_run with STUBBED seal ops -------------------------------------------------
# shellcheck source=../../lib/token.sh
. "$REPO/lib/token.sh"
# shellcheck source=../../lib/cmd/enroll-tpm.sh
. "$REPO/lib/cmd/enroll-tpm.sh"

FNLOG=$T/fn.log
# snapshot the REAL token_post_assert before the stubs replace it (rename the
# function in its own definition — declare -f emits the "name ()" header)
eval "$(declare -f token_post_assert | sed 's/^token_post_assert/token_post_assert_real/')"
stub_seal() { # OUTFILE — pretend seal_finalized ran
    SEAL_SLOT=2
    SEAL_PASS_FILE=$T/staged-pass
    printf 'staged-passphrase-0123456789abcdef' >"$SEAL_PASS_FILE"
    chmod 600 "$SEAL_PASS_FILE"
    token_build_json '[7, 11]' "$DER" "U0lH" "AAJhYg==" 2 "$1"
}
wire_stubs() {
    seal_finalized() { echo "CALL seal_finalized $*" >>"$FNLOG"; stub_seal "$4"; }
    token_free_slot() { echo "CALL token_free_slot" >>"$FNLOG"; printf '%s\n' 2; }
    token_add_keyslot() { echo "CALL token_add_keyslot $*" >>"$FNLOG"; return 0; }
    token_next_id() { printf '%s\n' 0; }
    token_import() { echo "CALL token_import $*" >>"$FNLOG"; return 0; }
    token_remove() { echo "CALL token_remove $*" >>"$FNLOG"; return 0; }
    token_kill_slot() { echo "CALL token_kill_slot $*" >>"$FNLOG"; return 0; }
    token_dump() { enrl_cryptsetup luksDump --dump-json-metadata "$1" >"$2" 2>/dev/null; }
    token_post_assert() { return 0; }
}
wire_real_post_assert() {
    token_post_assert() { token_post_assert_real "$@"; }
}

# happy: choreography order, ENRL_* globals, passphrase scrubbed
restore_state
: >"$FNLOG"
rm -f "$T/staged-pass"
ENRL_RC=0
wire_stubs
enrl_run b "$KEYDIR/release.pub" "$DEBIAN_FDE_BY_UUID_DIR/$UUID" 0 || ENRL_RC=1
assert_eq "fn: enrl_run(b) rc 0" "0" "$ENRL_RC"
assert_eq "fn: seal op invoked once" "1" "$(grep -c seal_finalized "$FNLOG")"
assert_eq "fn: keyslot added" "1" "$(grep -c token_add_keyslot "$FNLOG")"
assert_eq "fn: token imported" "1" "$(grep -c token_import "$FNLOG")"
assert_eq "fn: NO retire on a fresh volume" "0" "$(grep -c -e token_remove -e token_kill_slot "$FNLOG")"
assert_eq "fn: ENRL_SLOT" "2" "$ENRL_SLOT"
assert_eq "fn: ENRL_TOKEN_ID" "0" "$ENRL_TOKEN_ID"
assert_eq "fn: ENRL_WIPE" "no" "$ENRL_WIPE"
assert_eq "fn: staged passphrase SCRUBBED after the run" "absent" \
    "$([ -e "$T/staged-pass" ] && echo present || echo absent)"

# reseat: standing token -> retire calls IN THE SAME RUN
reset_state
write_pre_token
write_post_ok
: >"$FNLOG"
ENRL_RC=0
enrl_run b "$KEYDIR/release.pub" "$DEBIAN_FDE_BY_UUID_DIR/$UUID" 0 || ENRL_RC=1
assert_eq "fn reseat: rc 0" "0" "$ENRL_RC"
assert_eq "fn reseat: ENRL_WIPE=yes" "yes" "$ENRL_WIPE"
assert_eq "fn reseat: old token removed" "1" "$(grep -c token_remove "$FNLOG")"
assert_eq "fn reseat: old slot killed" "1" "$(grep -c token_kill_slot "$FNLOG")"

# >1 standing tokens: loud refusal, nothing enrolled
reset_state
cat >"$T/luks-pre.json" <<'EOF'
{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"},"2":{"type":"luks2"}},
 "tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"]},"1":{"type":"systemd-tpm2","keyslots":["2"]}}}
EOF
: >"$FNLOG"
ENRL_RC=0
EE_REASON=$(enrl_run b "$KEYDIR/release.pub" "$DEBIAN_FDE_BY_UUID_DIR/$UUID" 0 2>&1) || ENRL_RC=1
assert_eq "fn >1 tokens: rc 1" "1" "$ENRL_RC"
assert_contains "fn >1 tokens: message names the count" "$EE_REASON" "2 systemd-tpm2 tokens"
assert_eq "fn >1 tokens: NO seal op" "0" "$(grep -c seal_finalized "$FNLOG")"

# post-assert failure with the REAL token_post_assert: rc 1, nothing recorded
wire_real_post_assert
reset_state
write_pre_notoken
write_post_two
ENRL_RC=0
PA_REASON=$(enrl_run b "$KEYDIR/release.pub" "$DEBIAN_FDE_BY_UUID_DIR/$UUID" 0 2>&1) || ENRL_RC=1
assert_eq "fn post-assert failure: rc 1" "1" "$ENRL_RC"
assert_contains "fn post-assert failure: names the assert" "$PA_REASON" "exactly 1 systemd-tpm2 token"
assert_absent "fn post-assert failure: no enrolled.json (caller records only on rc 0)" "$(sp_enrolled_file)"

# G-IL7/HW-3: the ensure-once contract survives the rewire
reset_state
write_pre_token
: >"$FNLOG"
ENRL_SKIPPED=0
EO_RC=0
enrl_ensure_once "$DEBIAN_FDE_BY_UUID_DIR/$UUID" "$KEYDIR/release.pub" || EO_RC=1
assert_eq "ensure-once: standing token stands (rc 0)" "0" "$EO_RC"
assert_eq "ensure-once: NO seal op (zero TPM ops, s14)" "0" "$(grep -c seal_finalized "$FNLOG")"
assert_eq "ensure-once: ENRL_ENROLLED stays 0" "0" "$ENRL_ENROLLED"

swtpm_stop "$STATE" || true
exit $((TESTS_FAIL > 0 ? 1 : 0))
