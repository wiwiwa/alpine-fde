#!/usr/bin/env bash
# tests/integration/rotate_slot_assertions.sh — `alpine-fde rotate`:
#   * §13 entropy floor enforced (weak passphrase -> fail-closed, no cryptsetup)
#   * device resolution via baseline target.luks_uuid -> by-uuid dir
#   * luksChangeKey argv: --key-slot 0 + Argon2id KDF pins
#   * post-assertions: token count unchanged, keyslots != 0 byte-identical,
#     keyslot 0 changed (stubbed luksDump pre/post)
#   * --reseat-tpm delegates to enroll-tpm: the Mechanism B seal (fresh
#     keyslot + token, standing enrollment retired in the same run; ADR-19 —
#     no systemd-cryptenroll anywhere)
#   * passphrase temp files live on tmpfs (/dev/shm, §11 I1 — never plaintext
#     on disk), mode 0600 at call time, removed after the run

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/cmd/rotate.sh
source "$REPO/lib/cmd/rotate.sh"

T=$(mktemp -d /tmp/alpine-fde-rotate.XXXXXX)
FAKEBIN=$T/bin
UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_EFIVARS_DIR=$T/efivars
export ALPINE_FDE_BY_UUID_DIR=$T/by-uuid
export ALPINE_FDE_NO_INSTALL=1
export PATH="$FAKEBIN:$PATH"
export COUNTER=$T/counter PRE_JSON=$T/luks-pre.json POST_JSON=$T/luks-post.json
export CS_STAT=$T/cs-stat.log CS_SLOW=$T/cs-slow POSTFAIL=$T/postfail PRE_AT3=$T/pre-at3 PRE3_JSON=$T/luks-pre3.json
export ALPINE_FDE_OLD_PASSPHRASE='old-passphrase-here'
export ALPINE_FDE_NEW_PASSPHRASE='new-pass-V4l1d!here'

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$T/efivars" "$T/by-uuid" "$T/keys"

# --- stubs -----------------------------------------------------------------------
cat >"$FAKEBIN/cryptsetup" <<'EOF'
#!/bin/sh
case "$1" in
    luksDump)
        n=$(cat "$COUNTER")
        n=$((n + 1))
        echo "$n" >"$COUNTER"
        echo "DUMP$n" >>"$CS_LOG"
        if [ -e "$POSTFAIL" ] && [ "$n" = "2" ]; then exit 1; fi
        if [ "$n" = "1" ]; then
            cat "$PRE_JSON"                       # rotate pre-view (slot0 OLD)
        elif [ -e "$PRE_AT3" ] && [ "$n" = "3" ]; then
            cat "$PRE3_JSON"                      # enroll pre-view: standing old token, slot0 NEW
        else
            cat "$POST_JSON"                      # everything after the change
        fi
        exit 0
        ;;
    luksChangeKey)
        echo "CALL: $*" >>"$CS_LOG"
        # record path + mode of the passphrase key files AT CALL TIME (they are
        # removed right after, so this is the only observable moment)
        _prev='' _old='' _last=''
        for _a in "$@"; do
            [ "$_prev" = "--key-file" ] && _old=$_a
            _prev=$_a
        done
        _last=$_prev
        stat -c 'MODE %a %n' "$_old" >>"$CS_STAT" 2>/dev/null
        stat -c 'MODE %a %n' "$_last" >>"$CS_STAT" 2>/dev/null
        # M-2 test seam: linger so the driver can SIGINT mid-luksChangeKey
        [ -e "$CS_SLOW" ] && sleep 3
        exit 0
        ;;
    *)
        echo "CALL $*" >>"$CS_LOG"
        exit 0
        ;;
esac
exit 0
EOF
chmod +x "$FAKEBIN/cryptsetup"
export CS_LOG=$T/cs.log

# canonical pre/post fixtures: post differs from pre ONLY in keyslot 0 (the
# rotated one — new KDF salt), exactly what luksChangeKey does
write_pre() {
    cat >"$PRE_JSON" <<'EOF'
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id", "salt": "AAA" }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id", "salt": "BBB" }
        }
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"]
        }
    }
}
EOF
}
write_post() {
    cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id", "salt": "CCC" }
        },
        "1": {
            "type": "luks2",
            "key_size": 64,
            "kdf": { "type": "argon2id", "salt": "BBB" }
        }
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"]
        }
    }
}
EOF
}

reset_state() {
    : >"$CS_LOG"
    : >"$CS_STAT"
    echo 0 >"$COUNTER"
    write_pre
    write_post
}

make_baseline() { # luks_uuid-value
    BL_PCR0="pending"
    BL_KEYS_RELEASE_PUB_PATH="$T/keys/release.pub.pem"
    BL_TARGET_LUKS_UUID="$1"
    baseline_write "$(sp_baseline_file)"
}

run_rotate() { # args...
    ROT_OUT=$("$REPO/bin/alpine-fde" rotate "$@" 2>&1)
    ROT_RC=$?
}

# --- 0. M-4: passphrase_floor_ok rejects control characters (unit-level) ---------
assert_rc "floor accepts a 16+ char passphrase" 0 passphrase_floor_ok 'Val1d-Pass phrase-x'
assert_rc "floor rejects embedded newline (control char)" 1 \
    passphrase_floor_ok "$(printf 'Val1d-Pass\nline-two')"
assert_rc "floor rejects embedded TAB (control char)" 1 \
    passphrase_floor_ok "$(printf 'Val1d-Pass\tline-two')"

# --- 1. no baseline ------------------------------------------------------------------
reset_state
rm -f "$(sp_baseline_file)"
run_rotate
assert_eq "no baseline -> fail-closed" "64" "$ROT_RC"

# --- 2. baseline without luks_uuid ----------------------------------------------------
make_baseline ''
run_rotate
assert_eq "empty target.luks_uuid -> fail-closed" "64" "$ROT_RC"
assert_contains "message names target.luks_uuid" "$ROT_OUT" "target.luks_uuid"

# --- 3. device unresolvable ------------------------------------------------------------
make_baseline "$UUID"
run_rotate
assert_eq "unresolvable device -> fail-closed" "64" "$ROT_RC"

# --- 4. weak passphrase -> fail-closed, cryptsetup NOT invoked ---------------------------
: >"$T/by-uuid/$UUID"
reset_state
export ALPINE_FDE_NEW_PASSPHRASE='short1!'
run_rotate
assert_eq "weak passphrase -> fail-closed" "64" "$ROT_RC"
assert_contains "floor message present" "$ROT_OUT" "entropy floor"
assert_eq "cryptsetup never invoked on weak passphrase" "0" "$(wc -l <"$CS_LOG")"
export ALPINE_FDE_NEW_PASSPHRASE='new-pass-V4l1d!here'

# --- 5. blocklisted passphrase -------------------------------------------------------------
export ALPINE_FDE_NEW_PASSPHRASE='correct-horse-battery-password'
run_rotate
assert_eq "blocklisted passphrase -> fail-closed" "64" "$ROT_RC"
export ALPINE_FDE_NEW_PASSPHRASE='new-pass-V4l1d!here'

# --- 5b. §11 I1 fail-closed chain: unwritable ALPINE_FDE_TMPDIR -> 64, no leak ----
# rotate must fail closed (64) when the passphrase temp files cannot be created
# (rotate.sh mktemp chain) — and no passphrase file may be left behind anywhere
# under the requested tmpdir.
reset_state
ROT_TMPDIR=$T/rot-tmp
mkdir -p "$ROT_TMPDIR"
chmod 500 "$ROT_TMPDIR"   # r-x: traversable, not writable (uid!=root)
ALPINE_FDE_TMPDIR="$ROT_TMPDIR" run_rotate
assert_eq "unwritable ALPINE_FDE_TMPDIR -> fail-closed 64" "64" "$ROT_RC"
assert_contains "fail-closed message names the temp-file failure" "$ROT_OUT" "cannot create temp file"
assert_eq "no passphrase/temp file leaked under the unwritable tmpdir" "" \
    "$(find "$ROT_TMPDIR" -type f -name 'alpine-fde-rot-*' -print -quit)"
assert_eq "cryptsetup never invoked (mktemp chain precedes it)" "0" "$(wc -l <"$CS_LOG")"
chmod 700 "$ROT_TMPDIR"   # restore so the EXIT cleanup can remove it

# --- 5c. M-4: env passphrase with embedded newline -> floor reject, no cryptsetup -
reset_state
ALPINE_FDE_NEW_PASSPHRASE="$(printf 'Val1d-Pass\nline-two')" run_rotate
assert_eq "newline passphrase -> fail-closed" "64" "$ROT_RC"
assert_contains "floor message names control characters" "$ROT_OUT" "control characters"
assert_eq "cryptsetup never invoked for newline passphrase" "0" "$(wc -l <"$CS_LOG")"

# --- 6. happy path ---------------------------------------------------------------------------
reset_state
run_rotate
assert_eq "happy rotate rc 0" "0" "$ROT_RC"
CALLS=$(grep -v '^CALL:' -d skip "$CS_LOG" 2>/dev/null || sed -n 's/^CALL: //p' "$CS_LOG")
CALLS=$(sed -n 's/^CALL: //p' "$CS_LOG")
assert_contains "luksChangeKey argv: --key-slot 0" "$CALLS" "--key-slot 0"
assert_contains "luksChangeKey argv: argon2id" "$CALLS" "--pbkdf argon2id"
assert_contains "luksChangeKey argv: memory pin" "$CALLS" "--pbkdf-memory 1048576"
assert_contains "luksChangeKey argv: iter pin" "$CALLS" "--iter-time 2000"
assert_eq "exactly one luksChangeKey invocation" "1" "$(grep -c luksChangeKey "$CS_LOG")"

# --- 6b. §11 I1: passphrase temp files on tmpfs, 0600, removed after ----------------
TMP_PATHS=$(sed -n 's/^MODE [0-9]* //p' "$CS_STAT")
OLD_TMP=$(printf '%s\n' "$TMP_PATHS" | head -n1)
NEW_TMP=$(printf '%s\n' "$TMP_PATHS" | sed -n '2p')
assert_contains "old passphrase temp under /dev/shm (tmpfs, I1)" "$OLD_TMP" "/dev/shm/alpine-fde-rot-old."
assert_contains "new passphrase temp under /dev/shm (tmpfs, I1)" "$NEW_TMP" "/dev/shm/alpine-fde-rot-new."
assert_eq "passphrase temp files mode 0600 at call time" "600
600" "$(sed -n 's/^MODE \([0-9]*\) .*/\1/p' "$CS_STAT")"
if [ -e "$OLD_TMP" ] || [ -e "$NEW_TMP" ]; then
    assert_eq "passphrase temp files removed after the run" "gone" "present"
else
    assert_eq "passphrase temp files removed after the run" "gone" "gone"
fi

# --- 7. post-assert: token count changed -> fail-closed ---------------------------------------
reset_state
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "CCC" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "BBB" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] },
        "1": { "type": "systemd-tpm2", "keyslots": ["1"] }
    }
}
EOF
run_rotate
assert_eq "token count changed -> fail-closed" "64" "$ROT_RC"
assert_contains "token assertion message" "$ROT_OUT" "token count changed"
assert_contains "H-1: re-keyed warning on token-count failure (slot 0 WAS changed)" "$ROT_OUT" "WAS re-keyed"

# --- 8. post-assert: keyslot 1 modified -> fail-closed ------------------------------------------
reset_state
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "CCC" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "ZZZ" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] }
    }
}
EOF
run_rotate
assert_eq "keyslot 1 changed -> fail-closed" "64" "$ROT_RC"
assert_contains "slot-1 assertion message" "$ROT_OUT" "keyslot 1 changed"
assert_contains "H-1: re-keyed warning on slot-1 failure (slot 0 WAS changed)" "$ROT_OUT" "WAS re-keyed"

# --- 9. post-assert: keyslot 0 unchanged -> fail-closed -------------------------------------------
reset_state
cp "$PRE_JSON" "$POST_JSON"
run_rotate
assert_eq "keyslot 0 unchanged -> fail-closed" "64" "$ROT_RC"
assert_contains "slot-0 assertion message" "$ROT_OUT" "keyslot 0 unchanged"
assert_not_contains "H-1: unchanged slot 0 means old passphrase valid — no re-keyed claim" \
    "$ROT_OUT" "WAS re-keyed"

# --- 9b. post-assert: keyslot 0 vanished -> fail-closed, no re-keyed claim ----------
reset_state
cat >"$POST_JSON" <<'EOF'
{
    "keyslots": {
        "1": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "BBB" } }
    },
    "tokens": {
        "0": { "type": "systemd-tpm2", "keyslots": ["1"] }
    }
}
EOF
run_rotate
assert_eq "keyslot 0 vanished -> fail-closed" "64" "$ROT_RC"
assert_contains "slot-0 vanished message" "$ROT_OUT" "keyslot 0 vanished"
assert_not_contains "vanished: old passphrase still valid — no re-keyed claim" "$ROT_OUT" "WAS re-keyed"

# --- 9c. H-1: post-luksDump re-read fails after a successful luksChangeKey -----------
reset_state
touch "$POSTFAIL"
run_rotate
rm -f "$POSTFAIL"
assert_eq "post-metadata re-read failure -> fail-closed" "64" "$ROT_RC"
assert_contains "re-read failure message" "$ROT_OUT" "cannot re-read LUKS2 metadata"
assert_contains "H-1: re-keyed warning on re-read failure" "$ROT_OUT" "WAS re-keyed"

# --- 10. removed: user-facing --dry-run (task 8 — the flag is gone; rc 2 usage) ---------------------
reset_state
run_rotate --dry-run
assert_eq "--dry-run is no longer a rotate option -> usage rc 2" "2" "$ROT_RC"
assert_eq "--dry-run: cryptsetup not invoked" "0" "$(wc -l <"$CS_LOG")"

# --- 11. --reseat-tpm delegates to enroll-tpm (swtpm + stub cryptsetup: the
# Mechanism B seal path, ADR-19/ADR-20 — no systemd-cryptenroll anywhere) ------
assert_rc "swtpm fixture starts" 0 swtpm_start "$T/swtpm"
export ALPINE_FDE_TCTI=$SWTPM_TCTI
LIVE=$(swtpm_pcrread "$T/swtpm" 7)
mkvar() { printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$ALPINE_FDE_EFIVARS_DIR/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"; }
mkvar SecureBoot 1
mkvar SetupMode 0
# the enrollment anchors the release key from the KEYDIR (G-B7) — a REAL key so
# the token pubkey post-assert can DER-encode it. ADR-16: --reseat-tpm delegates
# to enroll-tpm, which fails closed on any release key < RSA-3072, so the KEYDIR
# is a hermetic suite-generated RSA-3072 keydir (same release.pem/.pub/.crt
# shaping as keys_rsa3072_chain.sh), not the shared RSA-2048 fixtures/keys dir
openssl genrsa -out "$T/keys/release.pem" 3072 2>/dev/null
openssl pkey -in "$T/keys/release.pem" -pubout -out "$T/keys/release.pub" 2>/dev/null
openssl req -new -x509 -key "$T/keys/release.pem" -out "$T/keys/release.crt" \
    -subj /CN=alpine-fde-rotate-reseat 2>/dev/null
[ -s "$T/keys/release.pub" ] && [ -s "$T/keys/release.crt" ] || {
    echo "FAIL: cannot generate the RSA-3072 reseat keydir" >&2
    exit 1
}
ALPINE_FDE_KEYDIR="$T/keys"
export ALPINE_FDE_KEYDIR
cp "$T/keys/release.pub" "$T/keys/release.pub.pem"
BL_PCR0="$LIVE" BL_PCR1="$LIVE" BL_PCR2="$LIVE" BL_PCR3="$LIVE" BL_PCR7="$LIVE" \
    BL_KEYS_RELEASE_PUB_PATH="$T/keys/release.pub.pem" BL_TARGET_LUKS_UUID="$UUID" \
    baseline_write "$(sp_baseline_file)"
# LUKS metadata for the enrollment path: PRE carries ONE standing token (the
# reseat retires it in the same run); POST mirrors what the fresh enrollment
# produces — token on the free slot 2, pubkey = the keydir release key
DER_B64=$(openssl pkey -pubin -in "$T/keys/release.pub" -outform DER 2>/dev/null | openssl base64 -A)
reset_state
# PRE (rotate's own pre-view, n=1): slot-0 with the OLD salt - rotate asserts
#   the change took effect (slot0 differs pre/post)
# PRE3 (the enroll's pre-view, n=3): slot-0 ALREADY the new salt (rotate ran
#   first) + the STANDING old-keyslot-1 token the reseat must retire
# POST (n>=2): the fresh enrollment - token on the FREE slot over {0,1,2} = 3,
#   slot-0 identical to the enroll's pre-view (the enroll must not touch it)
cat >"$PRE_JSON" <<'PRE11'
{"keyslots":{"0":{"type":"luks2","kdf":{"type":"argon2id","salt":"AAA"}},"1":{"type":"luks2","kdf":{"type":"argon2id","salt":"BBB"}}},
 "tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}}
PRE11
cat >"$PRE3_JSON" <<'PRE311'
{"keyslots":{"0":{"type":"luks2","kdf":{"type":"argon2id","salt":"ZZZ"}},"1":{"type":"luks2","kdf":{"type":"argon2id","salt":"BBB"}}},
 "tokens":{"0":{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"AAEAC0RhdGE="}}}
PRE311
cat >"$POST_JSON" <<POST11
{"keyslots":{"0":{"type":"luks2","kdf":{"type":"argon2id","salt":"ZZZ"}},"1":{"type":"luks2","kdf":{"type":"argon2id","salt":"BBB"}},"2":{"type":"luks2","kdf":{"type":"argon2id","salt":"CCC"}}},
 "tokens":{"0":{"type":"systemd-tpm2","keyslots":["3"],"tpm2-blob":"AAEAC0RhdGE=","tpm2-pcrs":[7,11],"tpm2-pcr-bank":"sha256","tpm2-policy-hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tpm2-primary-alg":"rsa","tpm2-pubkey":"$DER_B64","tpm2-signature":"U0lH"}}}
POST11
touch "$PRE_AT3"
run_rotate --reseat-tpm
rm -f "$PRE_AT3"
assert_eq "rotate --reseat-tpm rc 0" "0" "$ROT_RC"
assert_eq "luksChangeKey ran" "1" "$(grep -c luksChangeKey "$CS_LOG")"
assert_contains "reseat: the Mechanism B enrollment added a fresh keyslot" "$(cat "$CS_LOG")" "luksAddKey"
assert_contains "reseat: the fresh token was imported" "$(cat "$CS_LOG")" "token import"
assert_contains "reseat: the standing enrollment was retired (token)" "$(cat "$CS_LOG")" "token remove"
assert_contains "reseat: the standing enrollment was retired (slot)" "$(cat "$CS_LOG")" "luksKillSlot"
assert_eq "reseat: NO cryptenroll anywhere (ADR-19)" "" \
    "$(find "$FAKEBIN" -name 'systemd-cryptenroll' -print -quit)"
assert_file_exists "reseat: enrolled.json recorded" "$(sp_enrolled_file)"
assert_eq "reseat: enrolled.json policy_mode is b" "b" "$(baseline_get "$(sp_enrolled_file)" policy_mode)"
assert_eq "reseat: enrolled.json token keyslot (free slot)" "3" "$(baseline_get "$(sp_enrolled_file)" token_keyslot)"

# --- 12. M-2: SIGINT mid-luksChangeKey -> zeroized + removed, rotation aborted ------
# The stubbed luksChangeKey lingers (CS_SLOW); the driver backgrounds rotate under
# job control (set -m keeps SIGINT trappable for async children), signals INT once
# the passphrase files exist, and requires: rotation NOT completed, and no
# alpine-fde-rot-* file left anywhere under the requested tmpdir.
reset_state
mkdir -p "$T/rottmp"
touch "$CS_SLOW"
: >"$CS_LOG"
INT_RC_FILE=$T/int-rc
(
    set -m
    ALPINE_FDE_TMPDIR="$T/rottmp" "$REPO/bin/alpine-fde" rotate >"$T/int-out" 2>&1 &
    ROT_PID=$!
    for _i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        [ -s "$CS_LOG" ] && break
        sleep 0.2
    done
    kill -INT "$ROT_PID" 2>/dev/null
    wait "$ROT_PID"
    echo $? >"$INT_RC_FILE"
)
rm -f "$CS_SLOW"
ROT_INT_RC=$(cat "$INT_RC_FILE")
ROT_OUT=$(cat "$T/int-out")
assert_eq "SIGINT: rotate interrupted (rc 130), not run to completion" "130" "$ROT_INT_RC"
assert_not_contains "SIGINT: rotation must not complete" "$ROT_OUT" "keyslot-0 passphrase changed"
assert_eq "SIGINT: no passphrase/temp file left under the tmpdir (M-2)" "" \
    "$(find "$T/rottmp" -type f -name 'alpine-fde-rot-*' -print -quit)"

# --- 13. L-4: jq missing -> ADR-15 loud refusal before any cryptsetup call -----------
# Every post-assertion parser is jq-based with fail-vacuous fallbacks; without jq
# the assertions degrade and rotate dies claiming "keyslot 0 vanished". ADR-15:
# the command must declare the dependency and refuse loudly instead.
NOJQ=$T/bin-nojq
mkdir -p "$NOJQ"
OLD_PATH=$PATH
IFS=':'
for _d in "$FAKEBIN" $OLD_PATH; do
    [ -d "$_d" ] || continue
    for _f in "$_d"/*; do
        [ -x "$_f" ] || continue
        _n=${_f##*/}
        [ "$_n" = jq ] && continue
        [ -e "$NOJQ/$_n" ] || ln -s "$_f" "$NOJQ/$_n"
    done
done
unset IFS
export PATH="$NOJQ"
reset_state
run_rotate
export PATH="$OLD_PATH"
assert_eq "jq absent -> fail-closed" "64" "$ROT_RC"
assert_contains "ADR-15 message names jq" "$ROT_OUT" "jq"
assert_eq "cryptsetup never invoked when jq is missing" "0" "$(wc -l <"$CS_LOG")"

swtpm_stop "$T/swtpm" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
