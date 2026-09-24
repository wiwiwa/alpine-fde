#!/usr/bin/env bash
# tests/unit/keys_tpmt_public.sh — release-key handling (B-G7): TPMT_PUBLIC
# construction (task-pinned attrs 0x00020012, NULL scheme, 65537 exponent,
# 2-byte TPM2B prefix) must load in a real TPM and its Name must match both the
# committed fixture and the name-computation formula (§6.1.1 step 4b).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"

KEYDIR="$REPO/fixtures/keys"
TMP=$(mktemp -d)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT

# --- keys_check: loud-fail precondition surfaces (no TPM needed) --------------------
out=$(keys_check "$TMP/absent" 2>&1)
rc=$?
assert_rc "keys_check: missing directory fails" 1 $rc
assert_contains "keys_check: explains the missing directory" "$out" "not found"
mkdir -p "$TMP/incomplete"
printf x >"$TMP/incomplete/release.pem"
out=$(keys_check "$TMP/incomplete" 2>&1)
assert_contains "keys_check: detects incomplete key material" "$out" "key material incomplete"
keys_check "$KEYDIR"
assert_rc "keys_check: complete fixture keydir passes" 0 $?

# --- TPMT_PUBLIC bytes: our builder == committed fixture -----------------------------
keys_tpmt_public "$KEYDIR/release.pub" "$TMP/release.tpm2b"
cmp -s "$TMP/release.tpm2b" "$KEYDIR/release.tpm2b"
assert_rc "TPMT_PUBLIC bytes identical to the committed fixture" 0 $?
facts_keyname=$(jq -r .keyname_hex "$KEYDIR/release-facts.json")
facts_inner=$(jq -r .tpmt_public_inner_sha256 "$KEYDIR/release-facts.json")
inner_sha=$(tail -c +3 "$TMP/release.tpm2b" | sha256sum | awk '{print $1}')
assert_eq "TPMT_PUBLIC inner area matches the fixture hash" "$facts_inner" "$inner_sha"

# --- S-L2: the marshaled exponent must come from the key (die 64 if != 65537) --------
openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_pubexp:3 -pkeyopt rsa_keygen_bits:2048 \
    -out "$TMP/exp3.pem" 2>/dev/null
openssl rsa -in "$TMP/exp3.pem" -pubout -out "$TMP/exp3.pub" 2>/dev/null
openssl rsa -pubin -in "$TMP/exp3.pub" -noout -text 2>/dev/null | grep -q 'Exponent: 3 '
assert_rc "S-L2 sanity: fixture key really has exponent 3" 0 $?
rc=0
(keys_tpmt_public "$TMP/exp3.pub" "$TMP/exp3.tpm2b") >/dev/null 2>&1 || rc=$?
assert_rc "keys_tpmt_public: exponent != 65537 -> die 64 (S-L2)" 64 $rc
[ ! -e "$TMP/exp3.tpm2b" ]
assert_rc "keys_tpmt_public: exponent!=65537 -> no output file" 0 $?

# --- S-L1: keys_keyname must not leak its temp dir when the key is unparseable -------
printf 'deliberately not a key' >"$TMP/garbage.pub"
LEAK=$(mktemp -d)
rc=0
( export TMPDIR="$LEAK"
  keys_keyname "$TMP/garbage.pub" "$LEAK/out.name" ) >/dev/null 2>&1 || rc=$?
assert_rc "keys_keyname: unparseable key -> die 64" 64 $rc
assert_eq "keys_keyname: no temp leak on the die path (S-L1)" "0" \
    "$(find "$LEAK" -name 'alpine-fde-keyname.*' 2>/dev/null | wc -l | tr -d '[:space:]')"
rm -rf "$LEAK"

# --- live TPM: loadexternal accepts the construction; Name == fixture == formula ----
command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}
TPMDIR="$TMP/swtpm"
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI

keys_keyname "$KEYDIR/release.pub" "$TMP/release.name"
[ -s "$TMP/release.name" ]
rc=$?
assert_rc "keys_keyname produced the TPM name via loadexternal+readpublic" 0 "$rc"
name_hex=$(xxd -p "$TMP/release.name" | tr -d '\n')
assert_eq "TPM keyName == committed fixture keyName" "$facts_keyname" "$name_hex"

# name formula: 000b || SHA256(TPMT_PUBLIC bytes) — computed independently
computed="000b$(sha256sum "$TMP/release.tpm2b" | awk '{print $1}')"
# note: name hashes the inner TPMT_PUBLIC (without the 2-byte TPM2B prefix)
computed="000b$inner_sha"
assert_eq "keyName == 000b || SHA256(TPMT_PUBLIC inner)" "$facts_keyname" "$computed"

# the same public area also loads through a direct tpm2 call (no lib wrapper)
tpm loadexternal -C n -u "$TMP/release.tpm2b" -c "$TMP/ctx" -n "$TMP/name2" >/dev/null
tpm flushcontext "$TMP/ctx" >/dev/null 2>&1 || tpm flushcontext -t >/dev/null 2>&1 || true
assert_eq "direct tpm2_loadexternal name matches" "$name_hex" "$(xxd -p "$TMP/name2" | tr -d '\n')"

# --- G-B1 §6.1.1 step 4b: keys_keyname_verifying — the VERIFYING-area keyName --------
# The sealed policy pins the keyName of the area that will VERIFY at session
# time: the tpm2-tools PEM conversion (attrs 0x00060040), NOT the task-pinned
# 0x00020012 recording area above (keys.sh header NOTE — different Names).
rm -f "$TMP/verifying.name"
keys_keyname_verifying "$KEYDIR/release.pub" "$TMP/verifying.name"
[ -s "$TMP/verifying.name" ]
assert_rc "keys_keyname_verifying produced an output file" 0 $?
verifying_hex=$(tr -d '[:space:]' <"$TMP/verifying.name")
[ ${#verifying_hex} -eq 68 ] && case $verifying_hex in *[!0-9a-f]* | '') false ;; esac
assert_rc "verifying keyName output contract: pure lowercase hex, 68 chars (000b || SHA256)" 0 $?

# TPM-authoritative equality: the name the TPM itself reports, via two
# independent commands, for the object tpm2-tools converts the PEM into
tpm loadexternal -C n -G rsa -u "$KEYDIR/release.pub" -c "$TMP/verifying.ctx" \
    -n "$TMP/verifying-lo.name" >/dev/null 2>&1
tpm readpublic -c "$TMP/verifying.ctx" -n "$TMP/verifying-rp.name" >/dev/null 2>&1
assert_eq "verifying keyName == tpm2_loadexternal -n (TPM-authoritative)" \
    "$(xxd -p "$TMP/verifying-lo.name" | tr -d '\n')" "$verifying_hex"
assert_eq "verifying keyName == tpm2_readpublic -n (TPM-authoritative)" \
    "$(xxd -p "$TMP/verifying-rp.name" | tr -d '\n')" "$verifying_hex"
tpm flushcontext "$TMP/verifying.ctx" >/dev/null 2>&1 || tpm flushcontext -t >/dev/null 2>&1 || true

# the two areas MUST differ (recording-area name_hex captured above, line ~89)
[ "$verifying_hex" != "$name_hex" ]
assert_rc "verifying-area keyName DIFFERS from the recording-area keys_keyname name" 0 $?

# rc contract: missing PEM file -> loud die 64, no output file written
rc=0
out_missing=$(keys_keyname_verifying "$TMP/no-such.pub" "$TMP/missing.name" 2>&1) || rc=$?
assert_rc "keys_keyname_verifying: missing PEM -> die 64" 64 $rc
assert_contains "keys_keyname_verifying: missing PEM dies LOUD" "$out_missing" "keys_keyname_verifying"
[ ! -e "$TMP/missing.name" ]
assert_rc "keys_keyname_verifying: missing PEM -> no output file written" 0 $?

finish
