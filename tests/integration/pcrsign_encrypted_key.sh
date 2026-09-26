#!/usr/bin/env bash
# tests/integration/pcrsign_encrypted_key.sh — §8.4 + §11 invariant I4 + ADR-18:
# `pcrsign` must route the keydir release.pem through the SAME unlock seam the
# other signing callers use (keys_unlock, like enrl_sign_pcrsig in
# lib/cmd/enroll-tpm.sh) instead of signing with the raw (possibly
# encrypted-at-rest) file. Asserts OBSERVED effects, driving the REAL
# cmd_pcrsign dispatcher with a stubbed ukify (canned enter-initrd measure
# JSON, tests/unit/pcrsign_cli.sh idiom):
#   * ENCRYPTED release.pem (produced by the REAL keys_encrypt_release) +
#     correct ALPINE_FDE_KEY_PASSPHRASE (the only spelling, §8.1) -> rc 0,
#     openssl-verifiable signature over the
#     combined policyDigest, the unlock staging file (alpine-fde-unlock.*) is
#     SCRUBBED afterwards, and the keydir key stays encrypted on disk
#   * missing passphrase (no env, no tty)  -> rc 64, loud message, NO artifact,
#     ADR-8 failure marker persisted
#   * wrong env passphrase                 -> rc 64, distinct wrong-passphrase
#     message, the marker NAMES it, staging scrubbed, NO artifact
#   * PLAINTEXT keydir -> unchanged behavior (rc 0 + verifiable artifact, no
#     passphrase needed, no unlock staging file ever created)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"

# helper beyond lib.sh (same shape as pcrsign_cli.sh's)
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}

KEYDIR_SRC="$REPO/fixtures/keys"
GOLDEN="$REPO/fixtures/policy-digest/golden.json"
D7=$(jq -r .pcr7_digest "$GOLDEN")
D11=$(jq -r .pcr11_digest "$GOLDEN")
POL=$(jq -r .policy_digest "$GOLDEN")
PASS='ci-pcrsign-unlock-passphrase-ADR18'

TMP=$(mktemp -d)
# Deterministic fixture initrd, generated IN-SUITE (the former shared
# fixtures/uki/initrd.img was a git-ignored untracked artifact that a fresh
# checkout lacked). ukify measures the bytes; it never parses them.
INITRD="$TMP/initrd.img"
printf 'alpine-fde pcrsign fixture initrd: fixed bytes for ukify to measure\n' >"$INITRD"
SHM="$TMP/shm"
mkdir -p "$SHM"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

STUBBIN="$TMP/stubbin"
mkdir -p "$STUBBIN"
# Canned ukify: only the measure invocation matters — pinned to the enter-initrd
# phase (§6.1.1 step 1) and emitting the golden d11, so the expected combined
# digest equals the golden policy digest (pcrsign_cli.sh idiom).
UKIFY_LOG="$TMP/ukify.log"
cat >"$STUBBIN/ukify" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$UKIFY_LOG"
case \$* in
    *--measure*)
        printf '{"sha256":[{"pcrbank":"sha256","phase":"enter-initrd","hash":"%s"}]}\n' "$D11"
        ;;
esac
EOF
chmod +x "$STUBBIN/ukify"

# --- fixture: ENCRYPTED keydir produced by the REAL keys_encrypt_release ---------
ENC_KEYS="$TMP/enc-keys"
mkdir -p "$ENC_KEYS"
cp "$KEYDIR_SRC/release.pem" "$KEYDIR_SRC/release.crt" "$KEYDIR_SRC/release.pub" "$ENC_KEYS/"
ALPINE_FDE_KEY_PASSPHRASE=$PASS ALPINE_FDE_TMPDIR="$SHM" keys_encrypt_release "$ENC_KEYS" ||
    { echo "FAIL: fixture: keys_encrypt_release failed" >&2; exit 1; }
enc_rc() { (keys_is_encrypted "$1") >/dev/null 2>&1; echo $?; }
assert_eq "fixture: release.pem is now the ADR-18 encrypted form" "0" "$(enc_rc "$ENC_KEYS/release.pem")"

# --- fixture tree: finalized baseline (golden d7, §8.4) ---------------------------
ROOT="$TMP/root"
mkdir -p "$ROOT/etc/alpine-fde"
jq -n --arg d7 "$D7" '{schema_version: "1", expected_pcr7: $d7, status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"

# pcrsign — the REAL dispatcher with stubbed measure + fixture env (stdin is
# /dev/null: the no-tty half of the credential ladder must be the one exercised)
# pcrsign KEYDIR [--out F] — the REAL dispatcher with stubbed measure + fixture
# env (stdin is /dev/null: the no-tty half of the credential ladder must be the
# one exercised)
pcrsign() {
    _kd=$1
    shift
    env -u ALPINE_FDE_TCTI PATH="$STUBBIN:$PATH" \
        ALPINE_FDE_ROOT="$ROOT" \
        ALPINE_FDE_KEYDIR="$_kd" \
        ALPINE_FDE_TMPDIR="$SHM" \
        ALPINE_FDE_NO_INSTALL=1 \
        ALPINE_FDE_CONF="$TMP/absent.conf" \
        "$REPO/bin/alpine-fde" pcrsign --linux "$REPO/fixtures/uki/vmlinuz" \
        --initrd "$INITRD" \
        --cmdline "$REPO/fixtures/uki/cmdline.txt" \
        --os-release "$REPO/fixtures/uki/os-release" "$@" </dev/null
}

# unlock_leaks — count of leftover keys_unlock staging files (must be 0: I4
# hygiene — no decrypted key material survives the run, success OR failure)
unlock_leaks() { find "$SHM" -name 'alpine-fde-unlock.*' 2>/dev/null | wc -l | tr -d '[:space:]'; }

# verify_sig <json> — decode .sha256[0].sig and openssl-verify it over the
# policyDigest recomputed from the golden d7/d11 (independent of policy_verify)
verify_sig() {
    jq -r '.sha256[0].sig' "$1" | openssl base64 -d -A >"$TMP/ver.sig" 2>/dev/null
    policy_digest_bin "$D7" "$D11" >"$TMP/ver.msg"
    openssl dgst -sha256 -verify "$KEYDIR_SRC/release.pub" \
        -signature "$TMP/ver.sig" "$TMP/ver.msg" >/dev/null 2>&1
}

# =============================================================================
# 1. ENCRYPTED release.pem + correct env passphrase -> signed AND scrubbed
# =============================================================================
OUT="$TMP/pcrsig-enc.json"
rc=0
out=$(ALPINE_FDE_KEY_PASSPHRASE=$PASS pcrsign "$ENC_KEYS" --out "$OUT" 2>&1) || rc=$?
assert_rc "encrypted key + correct passphrase: pcrsign exits 0" 0 $rc
assert_file_exists "encrypted key: artifact written" "$OUT"
assert_eq "encrypted key: pcrs are [7,11]" "true" "$(jq '.sha256[0].pcrs == [7, 11]' "$OUT" 2>/dev/null)"
assert_eq "encrypted key: pol == golden combined policyDigest" "$POL" "$(jq -r '.sha256[0].pol' "$OUT" 2>/dev/null)"
verify_sig "$OUT"
assert_rc "encrypted key: openssl verifies the release signature over the policyDigest" 0 $?
assert_eq "encrypted key: unlock staging file scrubbed after signing" "0" "$(unlock_leaks)"
assert_eq "encrypted key: keydir release.pem still encrypted on disk" "0" "$(enc_rc "$ENC_KEYS/release.pem")"

# --- ...same, via the canonical ALPINE_FDE_KEY_PASSPHRASE spelling (§8.1) ---------
OUT_A="$TMP/pcrsig-enc-alpine.json"
rc=0
out=$(ALPINE_FDE_KEY_PASSPHRASE=$PASS pcrsign "$ENC_KEYS" --out "$OUT_A" 2>&1) || rc=$?
assert_rc "ALPINE_FDE_KEY_PASSPHRASE seam: pcrsign exits 0" 0 $rc
assert_eq "ALPINE_FDE_KEY_PASSPHRASE seam: identical artifact to the DEBIAN_ spelling" \
    "$(jq -c '.sha256[0]' "$OUT")" "$(jq -c '.sha256[0]' "$OUT_A" 2>/dev/null)"
assert_eq "ALPINE_FDE_KEY_PASSPHRASE seam: staging scrubbed" "0" "$(unlock_leaks)"

# =============================================================================
# 2. missing passphrase (no env, no tty) -> rc 64, loud, marker, NO artifact
# =============================================================================
OUT_M="$TMP/nope-missing.json"
rm -f "$ROOT/etc/alpine-fde/pcrsign-failed"
rc=0
out=$(pcrsign "$ENC_KEYS" --out "$OUT_M" 2>&1) || rc=$?
assert_rc "missing passphrase -> exit 64 (fail-closed, ADR-8/ADR-18)" 64 $rc
assert_contains "missing passphrase: loud message names the credential seam" "$out" "passphrase"
[ ! -e "$OUT_M" ]
assert_rc "missing passphrase: NO signature artifact written" 0 $?
assert_file_exists "missing passphrase: ADR-8 failure marker persisted" "$ROOT/etc/alpine-fde/pcrsign-failed"
assert_contains "missing passphrase: marker says the passphrase is missing" \
    "$(cat "$ROOT/etc/alpine-fde/pcrsign-failed")" "no passphrase"
assert_eq "missing passphrase: unlock staging scrubbed" "0" "$(unlock_leaks)"

# =============================================================================
# 3. WRONG env passphrase -> rc 64, DISTINCT message, marker names it, no artifact
# =============================================================================
OUT_W="$TMP/nope-wrong.json"
rm -f "$ROOT/etc/alpine-fde/pcrsign-failed"
rc=0
out=$(ALPINE_FDE_KEY_PASSPHRASE=definitely-not-the-passphrase pcrsign "$ENC_KEYS" --out "$OUT_W" 2>&1) || rc=$?
assert_rc "wrong passphrase -> exit 64 (fail-closed)" 64 $rc
assert_contains "wrong passphrase: DISTINCT message says decryption failed" "$out" "wrong passphrase"
[ ! -e "$OUT_W" ]
assert_rc "wrong passphrase: NO signature artifact written" 0 $?
assert_file_exists "wrong passphrase: ADR-8 failure marker persisted" "$ROOT/etc/alpine-fde/pcrsign-failed"
assert_contains "wrong passphrase: marker NAMES the wrong passphrase" \
    "$(cat "$ROOT/etc/alpine-fde/pcrsign-failed")" "wrong passphrase"
assert_eq "wrong passphrase: unlock staging scrubbed on the failure path" "0" "$(unlock_leaks)"
assert_eq "wrong passphrase: keydir release.pem untouched (still encrypted)" "0" "$(enc_rc "$ENC_KEYS/release.pem")"

# =============================================================================
# 4. PLAINTEXT keydir -> unchanged behavior (offline medium, no passphrase)
# =============================================================================
PLAIN_KEYS="$TMP/plain-keys"
mkdir -p "$PLAIN_KEYS"
cp "$KEYDIR_SRC/release.pem" "$KEYDIR_SRC/release.crt" "$KEYDIR_SRC/release.pub" "$PLAIN_KEYS/"
OUT_P="$TMP/pcrsig-plain.json"
rc=0
out=$(pcrsign "$PLAIN_KEYS" --out "$OUT_P" 2>&1) || rc=$?
assert_rc "plaintext keydir (no passphrase env): pcrsign exits 0 unchanged" 0 $rc
assert_eq "plaintext keydir: identical artifact to the unlocked-encrypted path" \
    "$(jq -c '.sha256[0]' "$OUT")" "$(jq -c '.sha256[0]' "$OUT_P" 2>/dev/null)"
assert_eq "plaintext keydir: plaintext release.pem NOT scrubbed/modified (still on the medium)" "1" \
    "$(enc_rc "$PLAIN_KEYS/release.pem")"
assert_eq "plaintext keydir: no unlock staging file ever created" "0" "$(unlock_leaks)"

finish
