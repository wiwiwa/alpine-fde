#!/usr/bin/env bash
# tests/unit/hooks_custody_copy.sh — ADR-18 custody copy + unlock seam in the
# NEW Alpine kernel build hook (docs/Architecture.md §9.2, ADR-18/ADR-8;
# G-C16 rewrite):
#   * the hook carries the new recovery copy: re-run the flow (enter the
#     release-key passphrase when prompted); unattended: provide
#     ALPINE_FDE_KEY_PASSPHRASE (canonical) or DEBIAN_FDE_KEY_PASSPHRASE
#     (compat) via your credential agent, then `apk fix` — the stale
#     dpkg-era lines are GONE
#   * the boot-manager re-sign routes its sbsign --key through keys_unlock:
#     an ENCRYPTED release.pem is decrypted ONCE to tmpfs and the UNLOCKED
#     path is signed with; plaintext keys keep the old behavior;
#     missing/wrong passphrase = loud 64 + build-failed marker (ADR-8)
#   * the decrypted copy is scrubbed after the hook exits
#   * the canonical seam wins when both spellings are set (§8.1)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

BUILD=$REPO/hooks/kernel-hooks.d/alpine-fde-build.hook
assert_file_exists "build hook template exists" "$BUILD"
assert_eq "build hook template is executable" "1" "$([ -x "$BUILD" ] && echo 1 || echo 0)"

# =============================================================================
# recovery copy pins (ADR-18 wording; Alpine conventions; NO dpkg anywhere)
# =============================================================================
C=$(cat "$BUILD")
assert_contains "hook: names the canonical credential-agent env seam" "$C" "ALPINE_FDE_KEY_PASSPHRASE"
assert_contains "hook: names the compat credential-agent env seam" "$C" "DEBIAN_FDE_KEY_PASSPHRASE"
assert_contains "hook: copy tells the operator the passphrase prompt is expected" "$C" \
    "enter the release-key passphrase when prompted"
assert_contains "hook: copy ends with the apk recovery step" "$C" "apk fix"
assert_not_contains "hook: no dpkg reconfigure step" "$C" "dpkg --configure -a"
assert_not_contains "hook: stale 'attach the signing medium' recovery line removed" "$C" \
    "attach the signing medium"
assert_contains "hook: wires the keys_unlock seam" "$C" "keys_unlock"
assert_contains "hook: prechecks the encrypted form" "$C" "keys_is_encrypted"
assert_not_contains "hook: no /etc/debian-fde marker path" "$C" "etc/debian-fde"

# =============================================================================
# functional: build hook + ENCRYPTED release.pem (unlock seam honored)
# =============================================================================
T=$(mktemp -d /tmp/alpine-fde-hooks-custody.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export ALPINE_FDE_ESP=$T/esp
export ALPINE_FDE_KEYDIR=$T/keys
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_TMPDIR=$T/shm
# keys_unlock stages under its DEBIAN_FDE_TMPDIR spelling (lib/keys.sh)
export DEBIAN_FDE_TMPDIR=$T/shm
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_LIB_DIR=$REPO/lib
KVER=6.6.63-0-lts
mkdir -p "$ALPINE_FDE_ESP/EFI/systemd" "$ALPINE_FDE_ESP/EFI/BOOT" \
    "$ALPINE_FDE_KEYDIR" "$ALPINE_FDE_ROOT/etc/alpine-fde" "$T/stub" "$T/shm"
printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
MARKER=$ALPINE_FDE_ROOT/etc/alpine-fde/build-failed

# recording alpine-fde stub (the ukictl build child — always "succeeds" here;
# the hook-level contract under test is the boot-manager re-sign custody)
FAKE=$T/stub/alpine-fde
cat >"$FAKE" <<'EOF'
#!/bin/sh
printf 'alpine-fde %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
exit 0
EOF
# sbsign/sbverify stubs: sbsign records argv and writes signed(output);
# sbverify accepts only signed content
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$ALPINE_FDE_TEST_LOG"
out=''
prev=''
for a in "$@"; do
    [ "$prev" = "--output" ] && out=$a
    prev=$a
done
last=''
for a in "$@"; do last=$a; done
if [ -n "$out" ]; then
    printf 'signed' >"$out"
fi
exit 0
EOF
cat >"$T/stub/sbverify" <<'EOF'
#!/bin/sh
f=''
for a in "$@"; do f=$a; done
[ "$(tail -c 6 "$f")" = "signed" ]
EOF
chmod +x "$FAKE" "$T/stub/sbsign" "$T/stub/sbverify"
export ALPINE_FDE_BIN=$FAKE
export PATH="$T/stub:$PATH"

run_hook() { sh "$BUILD" add "$KVER" </dev/null >"$T/out.log" 2>&1; echo $?; }
reset_stubs() { : >"$ALPINE_FDE_TEST_LOG"; }

# fixture: a REAL encrypted release.pem (ADR-18 form) + public material
HOOK_PASS='ci-hook-passphrase-600000'
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
    -in "$REPO/fixtures/keys/release.pem" -passout pass:"$HOOK_PASS" \
    -out "$ALPINE_FDE_KEYDIR/release.pem" 2>/dev/null
cp "$REPO/fixtures/keys/release.crt" "$ALPINE_FDE_KEYDIR/release.crt"
[ -s "$ALPINE_FDE_KEYDIR/release.pem" ] || { echo "fixture: encrypted PEM failed" >&2; exit 1; }

# leg 1: encrypted key + NO passphrase env + NO tty -> 64 + marker, no signing
reset_stubs
unset ALPINE_FDE_KEY_PASSPHRASE DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
assert_eq "hook: encrypted key, no credential -> rc 64" "64" "$(run_hook)"
assert_file_exists "hook: ADR-8 marker persisted" "$MARKER"
assert_contains "hook: marker demands the passphrase (env or interactive)" \
    "$(cat "$MARKER")" "passphrase required"
assert_eq "hook: nothing signed without a credential" "0" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG"; true)"

# leg 2: WRONG compat env passphrase -> 64 + marker naming wrong-passphrase
reset_stubs
export DEBIAN_FDE_KEY_PASSPHRASE=definitely-not-it
assert_eq "hook: wrong compat env passphrase -> rc 64" "64" "$(run_hook)"
assert_contains "hook: wrong-passphrase marker is distinct" \
    "$(cat "$MARKER")" "wrong passphrase"
unset DEBIAN_FDE_KEY_PASSPHRASE

# leg 3: correct CANONICAL env passphrase -> re-signs via the UNLOCKED tmpfs key
reset_stubs
export ALPINE_FDE_KEY_PASSPHRASE=$HOOK_PASS
assert_eq "hook: correct canonical passphrase -> rc 0" "0" "$(run_hook)"
LOG_CONTENT=$(cat "$ALPINE_FDE_TEST_LOG")
assert_contains "hook: sbsign signed with the UNLOCKED tmpfs key" "$LOG_CONTENT" \
    "sbsign --key $T/shm/"
assert_eq "hook: the encrypted path was never handed to sbsign" "0" \
    "$(grep -c "$ALPINE_FDE_KEYDIR/release.pem" "$ALPINE_FDE_TEST_LOG"; true)"
assert_eq "hook: boot manager replaced by the signed binary" "signed" \
    "$(cat "$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: decrypted copy scrubbed after the hook" "" \
    "$(find "$T/shm" -maxdepth 1 -name '*-fde-unlock.*' -print 2>/dev/null)"
assert_eq "hook: success cleared the marker" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"
unset ALPINE_FDE_KEY_PASSPHRASE

# leg 4: CANONICAL wins when both spellings are set (canonical correct,
# compat wrong -> rc 0 proves ALPINE_FDE_* precedence, §8.1)
reset_stubs
export ALPINE_FDE_KEY_PASSPHRASE=$HOOK_PASS
export DEBIAN_FDE_KEY_PASSPHRASE=definitely-not-it
assert_eq "hook: canonical seam wins over a wrong compat value -> rc 0" "0" "$(run_hook)"
unset ALPINE_FDE_KEY_PASSPHRASE DEBIAN_FDE_KEY_PASSPHRASE

# leg 5: PLAINTEXT release.pem -> unchanged behavior (keydir path, no unlock).
# Reset the ESP fixture first: the verify-first re-sign skipped already-signed
# binaries in legs 3-4 (idempotence), so nothing would run otherwise.
reset_stubs
printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
printf 'plaintext-key-material' >"$ALPINE_FDE_KEYDIR/release.pem"
assert_eq "hook: plaintext key -> rc 0 (unchanged)" "0" "$(run_hook)"
assert_contains "hook: plaintext key signed straight from the keydir" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "sbsign --key $ALPINE_FDE_KEYDIR/release.pem"
assert_eq "hook: plaintext run left no tmpfs unlock file" "" \
    "$(find "$T/shm" -maxdepth 1 -name '*-fde-unlock.*' -print 2>/dev/null)"

# leg 6: the lib seam is overridable (ALPINE_FDE_LIB_DIR) — a WRONG override
# fails loud (the guard_fail channel is the marker file, ADR-8)
reset_stubs
export ALPINE_FDE_LIB_DIR=$T/no-such-lib
assert_eq "hook: unusable lib seam -> fail-closed 64" "64" "$(run_hook)"
assert_contains "hook: unusable lib seam is loud in the marker" \
    "$(cat "$MARKER")" "runtime"
unset ALPINE_FDE_LIB_DIR

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
