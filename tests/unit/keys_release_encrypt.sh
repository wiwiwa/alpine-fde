#!/usr/bin/env bash
# tests/unit/keys_release_encrypt.sh — ADR-18 encrypted release.pem custody
# (docs/Architecture.md ADR-18, §9.1 steps 3+6, I4; gap G-KC2):
#   * keys_encrypt_release KEYDIR — encrypts release.pem in place to standard
#     OpenSSL PKCS#8 interoperability form: PBES2 / PBKDF2-hmacWithSHA256 /
#     aes-256-cbc / iter >= 600000 (pinned argv + asn1parse structure)
#   * passphrase credential mechanism (RESOLVED-4): ALPINE_FDE_KEY_PASSPHRASE
#     env seam -> interactive no-echo TTY prompt -> loud 64; §13 entropy floor
#     enforced (rc 2) BEFORE any ciphertext is written
#   * ALL plaintext copies scrubbed after success (release.priv.pem, tmp
#     staging — zeroize+rm); post-assert keys_is_encrypted or loud die
#   * keys_is_encrypted FILE — asn1parse-based rc 0/1 verdict pinning the exact
#     ADR-18 parameters (PBES2 + PBKDF2 + hmacWithSHA256 + aes-256-cbc +
#     iter >= 600000); wrong PRF/cipher/iteration counts are NOT conformant
#   * decrypt round-trip interoperability: right passphrase re-derives the
#     key, wrong passphrase fails loudly

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
export ALPINE_FDE_NO_INSTALL=1
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"

T=$(mktemp -d /tmp/alpine-fde-keys-enc.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT
export ALPINE_FDE_TMPDIR="$T/shm"
mkdir -p "$ALPINE_FDE_TMPDIR"

PASS_OK='ci-release-passphrase-600000-x'   # §13 floor OK (>=16 chars)
PASS_SHORT='short'                          # floor violation

# call_rc ARGS... — run in an inner subshell (die exits THAT subshell)
call_rc() { ( "$@" ) >/dev/null 2>&1; echo $?; }

# call_rc_notty KEYDIR — same, with ALPINE_FDE_KEY_PASSPHRASE unset and stdin
# detached from any tty (the loud no-credential leg)
call_rc_notty() {
    ( unset ALPINE_FDE_KEY_PASSPHRASE; keys_encrypt_release "$1" ) >/dev/null 2>&1 </dev/null
    echo $?
}

# wrap_openssl LOG — interpose a logging wrapper (pins the exact argv)
wrap_openssl() {
    mkdir -p "$T/wrapbin"
    local real; real=$(command -v openssl)
    cat >"$T/wrapbin/openssl" <<EOF
#!/bin/sh
printf 'openssl %s\n' "\$*" >>'$1'
exec $real "\$@"
EOF
    chmod +x "$T/wrapbin/openssl"
}

# new_plaintext_keydir DIR — fixture: plaintext release.pem (+ duplicate
# release.priv.pem the way stage1 leaves it) + public material
new_plaintext_keydir() {
    mkdir -p "$1"
    cp "$REPO/fixtures/keys/release.pem" "$1/release.pem"
    cp "$REPO/fixtures/keys/release.pem" "$1/release.priv.pem"
    cp "$REPO/fixtures/keys/release.crt" "$1/release.crt"
    cp "$REPO/fixtures/keys/release.pub" "$1/release.pub"
}

# =============================================================================
# keys_is_encrypted: rc 0/1 verdict before anything else exists
# =============================================================================
KP=$T/keys-plain
new_plaintext_keydir "$KP"
assert_eq "is_encrypted: plaintext PEM -> 1" "1" "$(call_rc keys_is_encrypted "$KP/release.pem")"
assert_eq "is_encrypted: garbage file -> 1" "1" \
    "$(printf 'not a pem\n' >"$T/garbage.pem"; call_rc keys_is_encrypted "$T/garbage.pem")"
assert_eq "is_encrypted: missing file -> 1" "1" "$(call_rc keys_is_encrypted "$T/absent.pem")"
assert_eq "is_encrypted: empty file -> 1" "1" \
    "$( : >"$T/empty.pem"; call_rc keys_is_encrypted "$T/empty.pem")"

# =============================================================================
# keys_encrypt_release: loud usage errors
# =============================================================================
assert_eq "encrypt: no argv -> 64" "64" "$(ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK call_rc keys_encrypt_release)"
assert_eq "encrypt: two argv -> 64" "64" \
    "$(ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK call_rc keys_encrypt_release "$KP" extra)"
assert_eq "encrypt: missing keydir -> 64" "64" \
    "$(ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK call_rc keys_encrypt_release "$T/nokeys")"

# =============================================================================
# floor violation: rc 2 BEFORE any ciphertext is written
# =============================================================================
KF=$T/keys-floor
new_plaintext_keydir "$KF"
assert_eq "encrypt: floor-violating passphrase -> rc 2" "2" \
    "$(ALPINE_FDE_KEY_PASSPHRASE=$PASS_SHORT call_rc keys_encrypt_release "$KF")"
assert_eq "encrypt: floor violation wrote NO ciphertext (release.pem still plaintext)" "1" \
    "$(call_rc keys_is_encrypted "$KF/release.pem")"
assert_eq "encrypt: floor violation left no staging ciphertext in tmpfs" "" \
    "$(find "$ALPINE_FDE_TMPDIR" -maxdepth 1 -name 'alpine-fde-enc.*' -print 2>/dev/null)"

# no passphrase available (no env, no tty) -> loud 64
KN=$T/keys-noenv
new_plaintext_keydir "$KN"
assert_eq "encrypt: no env + no tty -> 64" "64" "$(call_rc_notty "$KN")"

# =============================================================================
# happy path: encrypt with the env seam; pin the exact openssl argv + format
# =============================================================================
KE=$T/keys-enc
new_plaintext_keydir "$KE"
ARGVLOG=$T/openssl-argv.log
wrap_openssl "$ARGVLOG"
OUT=$(PATH="$T/wrapbin:$PATH" ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK keys_encrypt_release "$KE" 2>&1)
assert_eq "encrypt: env passphrase -> rc 0" "0" "$?"
ARGVLOG_CONTENT=$(cat "$ARGVLOG" 2>/dev/null)
assert_contains "encrypt: pinned argv (-topk8)" "$ARGVLOG_CONTENT" "-topk8"
assert_contains "encrypt: pinned argv (PBES2 aes-256-cbc)" "$ARGVLOG_CONTENT" "-v2 aes-256-cbc"
assert_contains "encrypt: pinned argv (hmacWithSHA256 PRF)" "$ARGVLOG_CONTENT" "-v2prf hmacWithSHA256"
assert_contains "encrypt: pinned argv (iter 600000)" "$ARGVLOG_CONTENT" "-iter 600000"

# ASN.1 structure pins (asn1parse, PEM input)
ASN=$(openssl asn1parse -in "$KE/release.pem" 2>/dev/null)
assert_contains "format: PBES2" "$ASN" ":PBES2"
assert_contains "format: PBKDF2" "$ASN" ":PBKDF2"
assert_contains "format: hmacWithSHA256 PRF" "$ASN" ":hmacWithSHA256"
assert_contains "format: aes-256-cbc" "$ASN" ":aes-256-cbc"
# iteration count 600000: asn1parse renders INTEGERs >2^24 in HEX (:0927C0);
# accept either rendering (older/newer asn1parse print decimal)
ITER_HEX=$(printf '%06X' 600000)
case "$ASN" in
    *":600000"* | *":$ITER_HEX"*)
        assert_eq "format: iteration count 600000 pinned" "ok" "ok"
        ;;
    *)
        assert_eq "format: iteration count 600000 pinned" ":600000|:$ITER_HEX in [$ASN]" "missing"
        ;;
esac

# keys_is_encrypted now accepts it
assert_eq "is_encrypted: ADR-18-conformant encrypted release.pem -> 0" "0" \
    "$(call_rc keys_is_encrypted "$KE/release.pem")"

# decrypt round-trip: interoperable PKCS#8 (right pass parses as a key)
openssl pkcs8 -in "$KE/release.pem" -passin pass:"$PASS_OK" -out /dev/null 2>/dev/null
assert_eq "decrypt: correct passphrase round-trips (standard PKCS#8)" "0" "$?"
openssl pkcs8 -in "$KE/release.pem" -passin pass:"definitely-wrong-pass" -out /dev/null 2>/dev/null
assert_ne "decrypt: WRONG passphrase fails loudly (rc != 0)" "0" "$?"

# plaintext remnants scrubbed: release.priv.pem + tmp staging gone
assert_eq "scrub: release.priv.pem zeroized+removed" "0" "$([ -e "$KE/release.priv.pem" ] && echo 1 || echo 0)"
assert_eq "scrub: no staging ciphertext left in tmpfs" "" \
    "$(find "$ALPINE_FDE_TMPDIR" -maxdepth 1 -name 'alpine-fde-enc.*' -print 2>/dev/null)"
assert_eq "scrub: public material kept (release.crt)" "1" "$([ -f "$KE/release.crt" ] && echo 1 || echo 0)"
assert_eq "scrub: public material kept (release.pub)" "1" "$([ -f "$KE/release.pub" ] && echo 1 || echo 0)"
PERM=$(stat -c %a "$KE/release.pem")
assert_eq "encrypted release.pem mode 600" "600" "$PERM"

# idempotency (crash-resume): re-encrypting an already-encrypted key is a no-op
OUT2=$(ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK keys_encrypt_release "$KE" 2>&1)
assert_eq "encrypt: already-encrypted keydir -> rc 0 (idempotent no-op)" "0" "$?"
assert_eq "idempotent: still decryptable with the ORIGINAL passphrase" "0" \
    "$(openssl pkcs8 -in "$KE/release.pem" -passin pass:"$PASS_OK" -out /dev/null 2>/dev/null; echo $?)"

# =============================================================================
# keys_is_encrypted: parameter pins — wrong PRF / wrong cipher / low iter are
# NOT ADR-18-conformant (rc 1) even though they are valid encrypted PKCS#8
# =============================================================================
BAD1=$T/bad-prf.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$T/bad-src.pem" 2>/dev/null
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA1 -iter 600000 \
    -in "$T/bad-src.pem" -passout pass:"$PASS_OK" -out "$BAD1" 2>/dev/null
assert_eq "is_encrypted: hmacWithSHA1 PRF (iter ok) -> 1 (PRF pinned)" "1" "$(call_rc keys_is_encrypted "$BAD1")"
BAD2=$T/bad-cipher.pem
openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA256 -iter 600000 \
    -in "$T/bad-src.pem" -passout pass:"$PASS_OK" -out "$BAD2" 2>/dev/null
assert_eq "is_encrypted: aes-128-cbc (PRF ok) -> 1 (cipher pinned)" "1" "$(call_rc keys_is_encrypted "$BAD2")"
BAD3=$T/bad-iter.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 1000 \
    -in "$T/bad-src.pem" -passout pass:"$PASS_OK" -out "$BAD3" 2>/dev/null
assert_eq "is_encrypted: iter=1000 -> 1 (600000 floor pinned)" "1" "$(call_rc keys_is_encrypted "$BAD3")"

# F1 (cycle-2 gate): the §9.1 step-6 guest one-liner runs in a FRESH shell
# sourcing ONLY keys.sh — common.sh must be self-loaded (die/info), and the
# keydir argument is mandatory. Reproduce the exact install.sh:980 shape.
_clean_shell_rc() { # <keydir> — env-clean subshell mirroring install.sh's
    # guest one-liner: the line exports the cmd dir, then sources common.sh +
    # keys.sh (a fresh chroot shell preloads nothing — die/info and the §13
    # floor's rotate.sh must all resolve from the payload tree)
    (
        unset ALPINE_FDE_KEYS_LOADED ALPINE_FDE_COMMON_LOADED
        unset ALPINE_FDE_KEY_PASSPHRASE ALPINE_FDE_CMD_DIR
        mkdir -p "$T/opt/alpine-fde/lib/cmd"
        cp "$REPO/lib/common.sh" "$REPO/lib/keys.sh" "$T/opt/alpine-fde/lib/"
        cp "$REPO/lib/cmd/rotate.sh" "$T/opt/alpine-fde/lib/cmd/"
        export ALPINE_FDE_CMD_DIR="$T/opt/alpine-fde/lib/cmd"
        . "$T/opt/alpine-fde/lib/common.sh"
        . "$T/opt/alpine-fde/lib/keys.sh"
        ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK keys_encrypt_release "$1" >/dev/null 2>&1
        echo $?
    )
}
_kp_fresh="$T/freshkeys"
mkdir -p "$_kp_fresh"
openssl genrsa -out "$_kp_fresh/release.pem" 2048 2>/dev/null
assert_eq "fresh-shell: keys.sh-only encrypt rc 0 (self-load + keydir arg)" "0" \
    "$(_clean_shell_rc "$_kp_fresh")"
# in-place ADR-18 form: release.pem exists but is now PKCS#8-encrypted
assert_contains "fresh-shell: release.pem is the encrypted artifact" \
    "$(head -2 "$_kp_fresh/release.pem")" "ENCRYPTED PRIVATE KEY"
assert_eq "fresh-shell: artifact is encrypted (standalone keys.sh)" "0" \
    "$( keys_is_encrypted "$_kp_fresh/release.pem"; echo $? )"
# no-argv usage: die exits the ( subshell ) — capture its rc from outside
assert_eq "fresh-shell: no-argv usage still dies 64" "64" \
    "$( ( . "$REPO/lib/keys.sh" >/dev/null 2>&1; ALPINE_FDE_KEY_PASSPHRASE=$PASS_OK keys_encrypt_release >/dev/null 2>&1 ); echo $? )"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
