#!/usr/bin/env bash
# tests/unit/enroll_precondition_matrix.sh — `debian-fde enroll-tpm` wrapper
# logic with STUBBED systemd-cryptenroll/cryptsetup (cryptenroll itself is a
# guest tool — e2e belongs to the QEMU wave):
#   * precondition matrix: SB off / SetupMode=1 / PCR7 drift / pending
#     baseline / missing baseline / invalid baseline / unresolvable LUKS uuid /
#     missing release pubkey — all fail-closed 64 with NO cryptenroll invocation
#   * happy path: Mechanism A'' argv shape (static --tpm2-pcrs=7 + signed
#     --tpm2-public-key-pcrs=11), device addressed via /dev/disk/by-uuid
#   * idempotence: existing token → --wipe-slot=tpm2 inside the SAME invocation
#   * policy_mode: A''-only (ADR-14) — a / ap / b fail closed 64, no TPM contact
#   * post-assertions: exactly one systemd-tpm2 token, slot != 0, keyslot 0
#     byte-identical; enrolled.json recorded on success only
#   * --dry-run prints the argv, runs nothing
#   * recovery: token wiped -> fresh slot + fresh token, no keydir/release key
#   * `ukictl enroll` alias: argv-identical surface of enroll-tpm (same
#     cmd_enroll_tpm_main through the same recording stub — same rc, same argv)

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

T=$(mktemp -d /tmp/debian-fde-enroll-matrix.XXXXXX)
STATE=$T/swtpm
FAKEBIN=$T/bin
EFIVARS=$T/efivars
BYUUID=$T/by-uuid
LOG=$T/cryptenroll.log
UUID=12345678-90ab-cdef-1234-567890abcdef
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
export DEBIAN_FDE_BY_UUID_DIR=$BYUUID
export DEBIAN_FDE_NO_INSTALL=1
export DEBIAN_FDE_ENROLL_LOCK=$T/enroll.lock
export PATH="$FAKEBIN:$PATH"

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "$BYUUID" "$T/keys" "$(sp_etc_dir 2>/dev/null || echo "$T/root/etc/debian-fde")"

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
setvar() { # NAME BYTE
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}

# --- stubs ---------------------------------------------------------------------
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL: \$*" >>'$LOG'
for a in "\$@"; do
    [ "\$a" = "--tpm2-device=list" ] && { echo "TPM devices are listed."; exit 0; }
done
exit 0
EOF
cat >"$FAKEBIN/cryptsetup" <<'EOF'
#!/bin/sh
# luksDump: serve pre-json on 1st call of a run, post-json on 2nd (counter file)
case "$1" in
    luksDump)
        n=$(cat "$COUNTER" 2>/dev/null || echo 0)
        n=$((n + 1))
        echo "$n" >"$COUNTER"
        if [ "$n" = "1" ]; then cat "$PRE_JSON"; else cat "$POST_JSON"; fi
        exit 0
        ;;
esac
exit 0
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll" "$FAKEBIN/cryptsetup"
export COUNTER=$T/counter PRE_JSON=$T/luks-pre.json POST_JSON=$T/luks-post.json

json_slots() { # EXTRA-POST?
    cat <<EOF
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        }
    },
    "tokens": {
    }
}
EOF
}
write_pre() { json_slots >"$PRE_JSON"; }
write_post_happy() {
    cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        }
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2_blob": "AAEAC0RhdGE="
        }
    }
}
EOF
}
write_post_happy # default post fixture

# --- shared fixture state -------------------------------------------------------
reset_state() {
    : >"$LOG"
    echo 0 >"$COUNTER"
    rm -f "$(sp_enrolled_file)"
}
# sb_vars SB SETUPMODE — every case sets its own Secure Boot state explicitly
sb_vars() {
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
}
assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export DEBIAN_FDE_TCTI=$SWTPM_TCTI

HEX_AB=$(printf 'ab%.0s' {1..32})
LIVE_PCR7=$(swtpm_pcrread "$STATE" 7)

make_baseline() { # PENDING|FINAL|SCHEMA2
    case $1 in
        pending) BL_PCR7='pending' ;;
        final) BL_PCR7="$LIVE_PCR7" ;;
        schema2) BL_PCR7="$LIVE_PCR7" ;;
    esac
    BL_PCR0="$LIVE_PCR7"
    BL_PCR1="$LIVE_PCR7"
    BL_PCR2="$LIVE_PCR7"
    BL_PCR3="$LIVE_PCR7"
    BL_KEYS_RELEASE_PUB_PATH="$T/keys/release.pub.pem"
    BL_KEYS_RELEASE_CERT_PATH="$T/keys/release.cert.pem"
    BL_TARGET_LUKS_UUID="$UUID"
    baseline_write "$(sp_baseline_file)"
    if [ "$1" = "schema2" ]; then
        sed -i 's/"schema_version": "1"/"schema_version": "2"/' "$(sp_baseline_file)"
    fi
    rm -f "$T/keys/release.pub.pem" 2>/dev/null
    case $1 in
        *) printf 'PUBKEY' >"$T/keys/release.pub.pem" ;;
    esac
}
BL=$(sp_baseline_file)

run_enroll() { # args...
    reset_state
    ENROLL_OUT=$("$REPO/bin/debian-fde" enroll-tpm "$@" 2>&1)
    ENROLL_RC=$?
}

# --- 1. missing baseline ---------------------------------------------------------
reset_state
rm -f "$BL"
run_enroll
assert_eq "no baseline -> fail-closed" "64" "$ENROLL_RC"
assert_eq "no baseline: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 2. invalid baseline (schema 2) ------------------------------------------------
make_baseline schema2
run_enroll
assert_eq "invalid baseline -> fail-closed" "64" "$ENROLL_RC"
assert_eq "invalid baseline: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 3. pending baseline -----------------------------------------------------------
make_baseline pending
run_enroll
assert_eq "pending baseline -> fail-closed" "64" "$ENROLL_RC"
assert_contains "pending message points to audit --init" "$ENROLL_OUT" "audit --init"
assert_eq "pending: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 4. Secure Boot off --------------------------------------------------------------
make_baseline final
sb_vars 0 0
run_enroll
assert_eq "SB off -> fail-closed" "64" "$ENROLL_RC"
assert_contains "SB off message cites I5" "$ENROLL_OUT" "I5"
assert_eq "SB off: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 5. SetupMode=1 -------------------------------------------------------------------
sb_vars 1 1
run_enroll
assert_eq "SetupMode=1 -> fail-closed" "64" "$ENROLL_RC"
assert_eq "SetupMode: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 6. PCR 7 drift --------------------------------------------------------------------
sb_vars 1 0
BL_PCR0="$LIVE_PCR7" BL_PCR1="$LIVE_PCR7" BL_PCR2="$LIVE_PCR7" BL_PCR3="$LIVE_PCR7" \
    BL_PCR7="$HEX_AB" BL_KEYS_RELEASE_PUB_PATH="$T/keys/release.pub.pem" \
    BL_TARGET_LUKS_UUID="$UUID" baseline_write "$BL"
printf 'PUBKEY' >"$T/keys/release.pub.pem"
run_enroll
assert_eq "PCR7 drift -> fail-closed" "64" "$ENROLL_RC"
assert_contains "drift message shows both digests" "$ENROLL_OUT" "$HEX_AB"
assert_eq "PCR7 drift: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"

# --- 7. missing release pub key ----------------------------------------------------------
sb_vars 1 0
BL_PCR7="$LIVE_PCR7" baseline_write "$BL"
rm -f "$T/keys/release.pub.pem"
run_enroll
assert_eq "missing pubkey -> fail-closed" "64" "$ENROLL_RC"
assert_eq "missing pubkey: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"
printf 'PUBKEY' >"$T/keys/release.pub.pem"

# --- 8. LUKS uuid unresolvable -------------------------------------------------------------
sb_vars 1 0
BL_PCR7="$LIVE_PCR7" baseline_write "$BL"
run_enroll
assert_eq "unresolvable uuid -> fail-closed" "64" "$ENROLL_RC"
assert_eq "no uuid device: cryptenroll never invoked" "0" "$(wc -l <"$LOG")"
: >"$BYUUID/$UUID"

# --- 9. happy path first enrollment (Mechanism A'') -------------------------------------------
make_baseline final
sb_vars 1 0
write_pre
write_post_happy
run_enroll
assert_eq "happy first enroll rc 0" "0" "$ENROLL_RC"
CALLS=$(grep -v 'tpm2-device=list' "$LOG")
assert_contains "argv: --tpm2-device=auto" "$CALLS" "--tpm2-device=auto"
assert_contains "argv: static --tpm2-pcrs=7" "$CALLS" "--tpm2-pcrs=7"
assert_contains "argv: signed --tpm2-public-key-pcrs=11" "$CALLS" "--tpm2-public-key-pcrs=11"
assert_contains "argv: --tpm2-public-key=<baseline path>" "$CALLS" "--tpm2-public-key=$T/keys/release.pub.pem"
assert_contains "argv: device addressed via by-uuid dir + uuid LAST" "$CALLS" "$DEBIAN_FDE_BY_UUID_DIR/$UUID"
assert_not_contains "first enroll: NO --wipe-slot" "$CALLS" "--wipe-slot"
assert_not_contains "never mixed: no --tpm2-public-key-pcrs=7+11 under A''" "$CALLS" "7+11"
assert_file_exists "enrolled.json recorded" "$(sp_enrolled_file)"
assert_eq "enrolled.json token keyslot" "1" "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"
assert_eq "enrolled.json policy_mode" "a2" "$(baseline_get "$(sp_enrolled_file)" policy_mode)"
assert_eq "enrolled.json luks_uuid" "$UUID" "$(baseline_get "$(sp_enrolled_file)" luks_uuid)"

# --- 10. reseat: pre-state already has a token -> wipe+enroll in ONE invocation ---------------
write_pre_with_token() {
    cat >"$PRE_JSON" <<'EOF'
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id" }
        }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] }
    }
}
EOF
}
sb_vars 1 0
write_pre_with_token
run_enroll --reseat
assert_eq "reseat rc 0" "0" "$ENROLL_RC"
CALLS=$(grep -v 'tpm2-device=list' "$LOG")
assert_contains "reseat: --wipe-slot=tpm2 in same invocation" "$CALLS" "--wipe-slot=tpm2"
assert_eq "wipe and enroll co-occur (single cryptenroll call)" "1" "$(grep -c -v 'tpm2-device=list' "$LOG")"
# --reseat forces the wipe even without a pre-existing token
reset_state
sb_vars 1 0
write_pre
run_enroll --reseat
assert_eq "forced reseat rc 0" "0" "$ENROLL_RC"
assert_contains "forced reseat wipes (one invocation)" "$(grep -v 'tpm2-device=list' "$LOG")" "--wipe-slot=tpm2"

# --- 11. policy_mode: A''-only (G-B3/G-R2/ADR-14) — documented-absent rungs --------
# fail closed (64) BEFORE any package/precondition work; cryptenroll is never
# touched; the rejection cites ADR-14 ("Mechanism A'' is the proven path")
run_enroll_mode() { # MODE — sets MODE_RC / MODE_OUT / MODE_CALLS (globals)
    reset_state
    sb_vars 1 0
    write_pre
    MODE_OUT=$(policy_mode="$1" "$REPO/bin/debian-fde" enroll-tpm 2>&1)
    MODE_RC=$?
    MODE_CALLS=$(grep -v 'tpm2-device=list' "$LOG")
}
assert_rc "swtpm still up" 0 swtpm_pcrread "$STATE" 7 >/dev/null
for m in a-prime a b ap combined; do
    run_enroll_mode "$m"
    assert_eq "mode $m: documented-absent -> fail-closed 64" "64" "$MODE_RC"
    assert_contains "mode $m: message cites ADR-14" "$MODE_OUT" "ADR-14"
    assert_contains "mode $m: message names the proven path" "$MODE_OUT" "Mechanism A'' is the proven path"
    assert_eq "mode $m: cryptenroll never invoked" "0" "$(printf '%s\n' "$MODE_CALLS" | grep -c .)"
done
run_enroll_mode a2
assert_eq "mode a2: still enrolled" "0" "$MODE_RC"

# --- 12. post-assert: two tokens -> fail-closed, no record ----------------------------------------
reset_state
make_baseline final
sb_vars 1 0
write_pre
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": { "0": { "type": "luks2" }, "1": { "type": "luks2" } },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
        "1": { "type": "systemd-tpm2", "keyslots": ["1"] }
    }
}
EOF
run_enroll
assert_eq "two tpm2 tokens -> fail-closed" "64" "$ENROLL_RC"
assert_contains "post-assert message" "$ENROLL_OUT" "exactly 1 systemd-tpm2 token"
if [ -e "$(sp_enrolled_file)" ]; then
    assert_eq "enrolled.json NOT written on failed assert" "absent" "present"
else
    assert_eq "enrolled.json NOT written on failed assert" "absent" "absent"
fi

# --- 13. post-assert: recovery slot 0 modified -> fail-closed --------------------------------------
reset_state
sb_vars 1 0
make_baseline final
write_pre_with_token
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "pbkdf2" }, "tampered": true },
        "1": { "type": "luks2", "kdf": { "type": "argon2id" } }
    },
    "tokens": { "0": { "type": "systemd-tpm2", "keyslots": ["1"] } }
}
EOF
run_enroll
assert_eq "recovery slot 0 changed -> fail-closed" "64" "$ENROLL_RC"
assert_contains "slot-0 message" "$ENROLL_OUT" "recovery keyslot 0"

# --- 14. post-assert: token bound to slot 0 -> fail-closed ------------------------------------------
reset_state
sb_vars 1 0
make_baseline final
write_pre
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id" } }
    },
    "tokens": { "0": { "type": "systemd-tpm2", "keyslots": ["0"] } }
}
EOF
run_enroll
assert_eq "token on slot 0 -> fail-closed" "64" "$ENROLL_RC"
assert_contains "slot-0 binding message" "$ENROLL_OUT" "keyslot != 0"

# --- 15. --dry-run: prints argv, runs nothing --------------------------------------------------------
reset_state
make_baseline final
sb_vars 1 0
write_pre
run_enroll --dry-run
assert_eq "dry-run rc 0" "0" "$ENROLL_RC"
assert_contains "dry-run prints the cryptenroll argv" "$ENROLL_OUT" "--tpm2-pcrs=7"
assert_eq "dry-run: cryptenroll not invoked (beyond probe)" "1" "$(grep -c 'tpm2-device=list' "$LOG")"
assert_eq "dry-run: no enroll call at all" "0" "$(grep -c -v 'tpm2-device=list' "$LOG")"
if [ -e "$(sp_enrolled_file)" ]; then
    assert_eq "dry-run writes no enrolled.json" "absent" "present"
else
    assert_eq "dry-run writes no enrolled.json" "absent" "absent"
fi

# --- 16. recovery (§9.4, RESOLVED-4): token wiped -> enroll-tpm re-enrolls ----------
# TPM-clear recovery: fresh keyslot + fresh cryptenroll token in ONE invocation;
# cryptenroll re-captures the CURRENT PCR 7 (static selection only — no digest
# value is passed); NO release private key / keydir is required and NO
# --tpm2-signature is needed: the token pins only the pubkey (§7.2).
reset_state
make_baseline final
sb_vars 1 0
write_pre # token wiped: no systemd-tpm2 token in the pre-state
write_post_happy
unset DEBIAN_FDE_KEYDIR
unset KEY_PATH
run_enroll
assert_eq "recovery: re-enroll after TPM-clear succeeds (no keydir/release key)" "0" "$ENROLL_RC"
CALLS=$(grep -v 'tpm2-device=list' "$LOG")
assert_contains "recovery: static --tpm2-pcrs=7 re-captures the current PCR 7" "$CALLS" "--tpm2-pcrs=7"
assert_not_contains "recovery: NO --tpm2-signature under A''" "$CALLS" "--tpm2-signature"
assert_not_contains "recovery: NO combined 7+11 selection" "$CALLS" "7+11"
assert_not_contains "recovery: fresh slot — no wipe of a (nonexistent) prior enrollment" "$CALLS" "--wipe-slot"
assert_eq "recovery: fresh token keyslot recorded (!= recovery slot 0)" "1" \
    "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"

# --- 16b. COMPACT LUKS2 wire shape (real cryptsetup 2.7.5 form: ONE line, no
# space after colons) — the parsers must be shape-tolerant: standing-token
# detection, --reseat slot-0 guard, post-assertions and recording all work on
# the metadata shape a REAL machine emits.
write_compact_pre() { # NO-TOKEN|TOKEN — compact single-line dumps
    if [ "${1:-}" = "TOKEN" ]; then
        printf '%s\n' '{"keyslots":{"0":{"type":"luks2","key_size":64,"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000}},"1":{"type":"luks2","key_size":64,"kdf":{"type":"argon2id"}}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}}' >"$PRE_JSON"
    else
        printf '%s\n' '{"keyslots":{"0":{"type":"luks2","key_size":64,"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000}},"1":{"type":"luks2","key_size":64,"kdf":{"type":"argon2id"}}},"tokens":{}}' >"$PRE_JSON"
    fi
}
write_compact_post_standing() { # slot 0 untouched (reseat guard passes)
    write_compact_pre TOKEN
    cp "$PRE_JSON" "$POST_JSON"
}
write_compact_post_tampered() { # recovery slot 0 modified under the compact form
    printf '%s\n' '{"keyslots":{"0":{"type":"luks2","key_size":64,"area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},"kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"VEFNUEVSRUQ="},"tampered":true},"1":{"type":"luks2","key_size":64,"kdf":{"type":"argon2id"}}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}}' >"$POST_JSON"
}
write_compact_post_two_tokens() {
    printf '%s\n' '{"keyslots":{"0":{"type":"luks2"},"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"]},"1":{"type":"systemd-tpm2","keyslots":["1"]}}}' >"$POST_JSON"
}

# compact: standing token detected on the PRE-count -> wipe issued WITHOUT
# --reseat (the pre-count-0 bug made enroll-tpm skip the wipe on real dumps)
reset_state
make_baseline final
sb_vars 1 0
write_compact_pre TOKEN
write_compact_post_standing
run_enroll
assert_eq "compact standing token: enroll rc 0" "0" "$ENROLL_RC"
assert_contains "compact standing token: wipe issued without --reseat" \
    "$(grep -v 'tpm2-device=list' "$LOG")" "--wipe-slot=tpm2"
assert_eq "compact standing token: keyslot recorded" "1" \
    "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"

# compact: --reseat with standing token — recovery slot 0 untouched -> passes
reset_state
sb_vars 1 0
write_compact_pre TOKEN
write_compact_post_standing
run_enroll --reseat
assert_eq "compact reseat: rc 0 (slot-0 byte-identical guard passes)" "0" "$ENROLL_RC"
assert_contains "compact reseat: wipe+enroll in one invocation" \
    "$(grep -v 'tpm2-device=list' "$LOG")" "--wipe-slot=tpm2"

# compact: recovery slot 0 modified -> fail-closed (the silent-skip bug)
reset_state
sb_vars 1 0
write_compact_pre TOKEN
write_compact_post_tampered
run_enroll
assert_eq "compact tampered slot 0 -> fail-closed" "64" "$ENROLL_RC"
assert_contains "compact tampered slot 0: message" "$ENROLL_OUT" "recovery keyslot 0"

# compact: first enrollment (no token) — post-assertions pass on the compact
# post-state and the fresh keyslot is recorded
reset_state
sb_vars 1 0
write_compact_pre TOKEN
mv "$PRE_JSON" "$POST_JSON" # that document IS the fresh post-state
write_compact_pre # pre: no token yet
run_enroll
assert_eq "compact first enroll: rc 0" "0" "$ENROLL_RC"
assert_not_contains "compact first enroll: no wipe" \
    "$(grep -v 'tpm2-device=list' "$LOG")" "--wipe-slot"
assert_eq "compact first enroll: token keyslot recorded" "1" \
    "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"

# compact: two tokens -> fail-closed "exactly 1" (was found-0 on real dumps)
reset_state
sb_vars 1 0
write_compact_pre
write_compact_post_two_tokens
run_enroll
assert_eq "compact two tokens -> fail-closed" "64" "$ENROLL_RC"
assert_contains "compact two tokens: post-assert message" "$ENROLL_OUT" "exactly 1 systemd-tpm2 token"

# --- 17. `ukictl enroll` alias (G-R3/F3): argv-identical surface of enroll-tpm -----
# `ukictl enroll` must drive the SAME cmd_enroll_tpm_main through the SAME
# recording stub: identical rc and IDENTICAL cryptenroll argv (the invocation
# line enroll-tpm prints). --dry-run semantics carry through the alias: the
# argv is printed, no enroll call happens, nothing is recorded.
reset_state
make_baseline final
sb_vars 1 0
write_pre
run_enroll --dry-run
TPM_ARGV=$(printf '%s\n' "$ENROLL_OUT" | sed -n '/cryptenroll invocation/{n;p}')
reset_state # fresh cryptsetup counter — the alias must see the SAME pre-state
ALIAS_OUT=$("$REPO/bin/debian-fde" ukictl enroll --dry-run 2>&1)
ALIAS_RC=$?
assert_eq "ukictl enroll alias: same rc as enroll-tpm --dry-run" "$ENROLL_RC" "$ALIAS_RC"
TPM_ARGV=$(printf '%s\n' "$ENROLL_OUT" | sed -n '/cryptenroll invocation/{n;p}')
ALIAS_ARGV=$(printf '%s\n' "$ALIAS_OUT" | sed -n '/cryptenroll invocation/{n;p}')
assert_eq "ukictl enroll alias: cryptenroll argv identical to enroll-tpm" "$TPM_ARGV" "$ALIAS_ARGV"
assert_contains "alias argv pins static --tpm2-pcrs=7" "$ALIAS_ARGV" "--tpm2-pcrs=7"
assert_contains "alias argv pins signed --tpm2-public-key-pcrs=11" "$ALIAS_ARGV" "--tpm2-public-key-pcrs=11"
assert_contains "alias argv addresses the same by-uuid device" "$ALIAS_ARGV" "$DEBIAN_FDE_BY_UUID_DIR/$UUID"
assert_eq "alias --dry-run: no enroll call through the stub" "0" \
    "$(grep -c -v 'tpm2-device=list' "$LOG")"

# --- 18. MD-02: argv construction is word-split-free -------------------------------
# A pubkey path (or uuid / device path) containing spaces/globs must arrive at
# cryptenroll as ONE argv element each. The shared stub logs "$*" (space-joined,
# ambiguous), so this leg swaps in a per-argument recorder, calls the shared
# enrl_run core directly, then restores the stub.
# shellcheck source=../../lib/cmd/enroll-tpm.sh
. "$REPO/lib/cmd/enroll-tpm.sh"
SP_PUB="$T/keys/my release.pub"
printf 'PUBKEY' >"$SP_PUB"
SP_DEV="$BYUUID/spaced uuid"
: >"$SP_DEV"
mv "$FAKEBIN/systemd-cryptenroll" "$FAKEBIN/systemd-cryptenroll.shared"
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
for a in "\$@"; do
    [ "\$a" = "--tpm2-device=list" ] && exit 0
    printf 'ARG:%s\n' "\$a" >>'$LOG'
done
exit 0
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll"
reset_state
write_pre
write_post_happy
SP_RC=0
enrl_run a2 "$SP_PUB" "$SP_DEV" 0 || SP_RC=1
assert_eq "spaced paths: enrl_run succeeds (no word-split corruption)" "0" "$SP_RC"
assert_contains "spaced pubkey: ONE argv element carries the full path" \
    "$(grep '^ARG:' "$LOG")" "ARG:--tpm2-public-key=$SP_PUB"
assert_contains "spaced device: ONE argv element, addressed last" \
    "$(grep '^ARG:' "$LOG")" "ARG:$SP_DEV"
assert_contains "argv shape preserved: static pcrs 7" "$(grep '^ARG:' "$LOG")" "ARG:--tpm2-pcrs=7"
assert_contains "argv shape preserved: signed pcrs 11" "$(grep '^ARG:' "$LOG")" "ARG:--tpm2-public-key-pcrs=11"
mv -f "$FAKEBIN/systemd-cryptenroll.shared" "$FAKEBIN/systemd-cryptenroll"
chmod +x "$FAKEBIN/systemd-cryptenroll"

# --- 19. HW-3: >1 standing tokens → the ensure-once path REFUSES loudly -------------
# (the standing path used to accept any token count >= 1 as "stands" forever)
write_pre_two_tokens() {
    cat >"$PRE_JSON" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id" } },
        "2": { "type": "luks2", "kdf": { "type": "argon2id" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
        "1": { "type": "systemd-tpm2", "keyslots": ["2"] }
    }
}
EOF
}
reset_state
write_pre_two_tokens
: >"$LOG"
EE_RC=0
EE_OUT=$(enrl_ensure_once "$SP_DEV" "$T/keys/release.pub.pem" 2>&1) || EE_RC=1
assert_eq "ensure_once: 2 standing tokens -> rc 1 (loud refusal)" "1" "$EE_RC"
assert_contains "ensure_once: refusal cites manual intervention" "$EE_OUT" "manual intervention"
assert_contains "ensure_once: refusal states the token count" "$EE_OUT" "2 systemd-tpm2 tokens"
assert_eq "ensure_once: ZERO cryptenroll contact on refusal" "0" "$(wc -l <"$LOG")"

# --- 20. LO-02: enrolled.json is jq-built, atomic, mode 600, quote-safe -------------
# A luks uuid containing a double quote must survive verbatim as valid JSON.
QUOTED_UUID='a"b'
: >"$BYUUID/$QUOTED_UUID"
reset_state
sb_vars 1 0
make_baseline final
write_pre
write_post_happy
run_enroll --uuid "$QUOTED_UUID"
assert_eq "quoted uuid enroll rc 0" "0" "$ENROLL_RC"
assert_file_exists "enrolled.json written" "$(sp_enrolled_file)"
assert_rc "enrolled.json is valid JSON (quote in uuid did not mangle it)" 0 \
    jq -e . "$(sp_enrolled_file)"
assert_eq "enrolled.json luks_uuid verbatim" "$QUOTED_UUID" \
    "$(jq -r .luks_uuid "$(sp_enrolled_file)")"
assert_eq "enrolled.json mode 600 (no default-umask window)" "600" \
    "$(stat -c %a "$(sp_enrolled_file)")"
ETC_DIR=$(dirname "$(sp_enrolled_file)")
TMP_PAT='.debian-fde-enrolled.*'
assert_eq "no temp files left behind in the state dir" "" \
    "$(find "$ETC_DIR" -maxdepth 1 -name "$TMP_PAT" -print)"
rm -f "$BYUUID/$QUOTED_UUID"

# --- 21. G-XC12: --uuid accepts a block-device path (§8.1 "(or target block device)") ---
# In addition to /dev/disk/by-uuid/<uuid>, an explicit /dev/... block-device
# path must be accepted and passed to cryptenroll verbatim as the target.
reset_state
make_baseline final
sb_vars 1 0
write_pre
write_post_happy
mkdir -p "$T/dev"
BLKDEV="$T/dev/nvme0n1p2"
: >"$BLKDEV"
run_enroll --uuid "$BLKDEV"
assert_eq "block-device --uuid: enroll rc 0" "0" "$ENROLL_RC"
assert_contains "block-device --uuid: passed verbatim as the cryptenroll target" \
    "$(grep -v 'tpm2-device=list' "$LOG")" "$BLKDEV"
assert_eq "block-device --uuid: enrolled.json records the device target" "$BLKDEV" \
    "$(baseline_get "$(sp_enrolled_file)" luks_uuid)"
rm -f "$BLKDEV"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
