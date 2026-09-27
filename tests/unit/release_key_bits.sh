#!/usr/bin/env bash
# tests/unit/release_key_bits.sh — real-server blocker #26: a REAL TPM refused
# tpm2_loadexternal of the RSA-3072 release pubkey (Esys 0x2C4 parameter out
# of range — many TPM2s LoadExternal only RSA-2048), killing the provisional
# seal. ADR-11 AMENDED: the release key is generated at RSA-2048 (the portable
# bound; Microsoft PK/KEK/db are RSA-2048) and the ADR-16 floor follows.
#   (a) prov_keygen release keydir -> release.pub is exactly 2048 bits
#       (RED on main: 3072);
#   (b) keys_rsa3072_guard ACCEPTS the generated 2048 keydir (RED on main);
#   (c) the guard still refuses a sub-2048 key (1024) citing the floor;
#   (d) keys_keyname_verifying surfaces the tpm2 stderr in its die message
#       (blocker #26's invisible 0x2C4 diagnosis).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# tests/unit/lib.sh has no assert_file_exists; local definition
assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (file does not exist: $2)"; fi
}
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/cmd/provision.sh
. "$ALPINE_FDE_CMD_DIR/provision.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
KD=$TMP/keys
mkdir -p "$KD"

# --- (a) generated release key is RSA-2048 -----------------------------------------
prov_keygen "$KD" release 2048 TestRelease >/dev/null 2>&1
# the keys.sh release.pub convention (as provision stage1 shapes it)
cp "$KD/release.pub.pem" "$KD/release.pub"
cp "$KD/release.cert.pem" "$KD/release.crt"
assert_file_exists "release key generated" "$KD/release.pub"
BITS=$(keys_rsa_bits "$KD/release.pub")
assert_eq "blocker #26: the generated release key is RSA-2048 (portable TPM LoadExternal bound)" \
    "2048" "$BITS"

# --- (b) the ADR-16 guard accepts the generated 2048 keydir ------------------------
out=$(keys_rsa3072_guard "$KD" 2>&1); rc=$?
assert_rc "keys_rsa3072_guard accepts the amended 2048 release key" 0 "$rc"
[ -z "$out" ] && _pass "guard is silent on acceptance" || _pass "guard notes: $out"

# --- (c) the guard still refuses a sub-2048 key (1024) -----------------------------
SUB=$TMP/sub2048
mkdir -p "$SUB"
openssl genrsa -out "$SUB/release.pub" 1024 2>/dev/null
out=$(keys_rsa3072_guard "$SUB" 2>&1); rc=$?
assert_rc "guard refuses a 1024-bit release key (rc 2)" 2 "$rc"
assert_contains "the refusal cites the floor" "$out" "2048"

# --- (d) keys_keyname_verifying surfaces the tpm2 stderr ---------------------------
STUB="$TMP/stub"
mkdir -p "$STUB"
cat >"$STUB/tpm2" <<'STUB'
#!/bin/sh
echo "Esys 0x2C4 tpm:parameter(2): value is out of range or is not correct for the context" >&2
exit 1
STUB
chmod +x "$STUB/tpm2"
out=$(PATH="$STUB" ALPINE_FDE_TCTI='' tpm_tcti_resolve >/dev/null 2>&1; true)
ERR=$(ALPINE_FDE_TCTI='device:/dev/null' PATH="$STUB" /bin/bash -c '
    set -u
    . '"$REPO"'/lib/common.sh
    . '"$REPO"'/lib/keys.sh
    keys_keyname_verifying '"$KD"'/release.pub /dev/null
' >/dev/null 2>&1); RC=$?
ERR=$(ALPINE_FDE_TCTI='device:/dev/null' PATH="$STUB:$PATH" /bin/bash -c '
    set -u
    . '"$REPO"'/lib/common.sh
    . '"$REPO"'/lib/keys.sh
    keys_keyname_verifying '"$KD"'/release.pub /dev/null
' 2>&1 >/dev/null)
assert_rc "keys_keyname_verifying fails closed when the TPM refuses" 64 "$RC"
assert_contains "the die message surfaces the tpm2 stderr (blocker #26 diagnosis)" \
    "$ERR" "Esys 0x2C4"

finish
