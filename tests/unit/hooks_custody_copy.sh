#!/usr/bin/env bash
# tests/unit/hooks_custody_copy.sh — ADR-18 custody copy + unlock seam in the
# kernel hooks (docs/Architecture.md §9.2, ADR-18/ADR-8; gap G-KC5):
#   * BOTH hook templates carry the new recovery copy: re-run the flow (enter
#     the release-key passphrase when prompted); unattended: provide
#     DEBIAN_FDE_KEY_PASSPHRASE via your credential agent, then
#     `dpkg --configure -a` — the stale "attach the signing medium" line is
#     GONE (release.pem may live encrypted on the target, ADR-18)
#   * the boot-manager re-sign hook routes its sbsign --key through
#     keys_unlock: an ENCRYPTED release.pem is decrypted ONCE to tmpfs and the
#     UNLOCKED path is signed with; plaintext keys keep the old behavior;
#     missing/wrong passphrase = loud 64 + build-failed marker (ADR-8)
#   * the decrypted copy is scrubbed after the hook exits

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

POSTINST=$REPO/hooks/postinst.d-zz-debian-fde
BOOTMGR=$REPO/hooks/systemd-boot-upgrade-zz-debian-fde
assert_file_exists "postinst hook template exists" "$POSTINST"
assert_file_exists "boot-manager re-sign hook template exists" "$BOOTMGR"
assert_eq "postinst template is executable" "1" "$([ -x "$POSTINST" ] && echo 1 || echo 0)"
assert_eq "boot-manager template is executable" "1" "$([ -x "$BOOTMGR" ] && echo 1 || echo 0)"

# =============================================================================
# G-KC5: recovery copy pins (ADR-18 wording replaces "attach the signing
# medium" in BOTH templates — marker text and header guidance)
# =============================================================================
for f in "$POSTINST" "$BOOTMGR"; do
    C=$(cat "$f")
    assert_contains "$(basename "$f"): names the credential-agent env seam" "$C" "DEBIAN_FDE_KEY_PASSPHRASE"
    assert_contains "$(basename "$f"): copy tells the operator the passphrase prompt is expected" "$C" \
        "enter the release-key passphrase when prompted"
    assert_contains "$(basename "$f"): copy ends with the dpkg reconfigure step" "$C" "dpkg --configure -a"
    assert_not_contains "$(basename "$f"): stale 'attach the signing medium' recovery line removed" "$C" \
        "attach the signing medium"
done
BM_C=$(cat "$BOOTMGR")
assert_contains "boot-manager hook wires the keys_unlock seam" "$BM_C" "keys_unlock"
assert_contains "boot-manager hook prechecks the encrypted form" "$BM_C" "keys_is_encrypted"

# =============================================================================
# functional: boot-manager hook + ENCRYPTED release.pem (unlock seam honored)
# =============================================================================
T=$(mktemp -d /tmp/debian-fde-hooks-custody.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

export DEBIAN_FDE_ESP=$T/esp
export DEBIAN_FDE_KEYDIR=$T/keys
export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_TMPDIR=$T/shm
export DEBIAN_FDE_TEST_LOG=$T/cmd.log
export DEBIAN_FDE_TEST_SBV_STATE=$T/sbv-state
export DEBIAN_FDE_LIB_DIR=$REPO/lib
mkdir -p "$DEBIAN_FDE_ESP/EFI/systemd" "$DEBIAN_FDE_ESP/EFI/BOOT" \
    "$DEBIAN_FDE_KEYDIR" "$DEBIAN_FDE_ROOT/etc/debian-fde" "$T/stub" "$T/shm"
printf 'unsigned-systemd-boot' >"$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$DEBIAN_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
MARKER=$DEBIAN_FDE_ROOT/etc/debian-fde/build-failed

# sbsign/sbverify stubs (same discipline as boot_manager_resign_guard):
# sbsign records argv and writes signed(output); sbverify behaves per
# DEBIAN_FDE_TEST_SBV_MODE and records argv
cat >"$T/stub/sbsign" <<'EOF'
#!/bin/sh
printf 'sbsign %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
out=''
prev=''
for a in "$@"; do
    [ "$prev" = "--output" ] && out=$a
    prev=$a
done
last=''
for a in "$@"; do last=$a; done
if [ -n "$out" ]; then
    printf 'signed(%s)' "$last" >"$out"
fi
exit 0
EOF
cat >"$T/stub/sbverify" <<'EOF'
#!/bin/sh
printf 'sbverify %s\n' "$*" >>"$DEBIAN_FDE_TEST_LOG"
n=$(cat "$DEBIAN_FDE_TEST_SBV_STATE" 2>/dev/null || echo 0)
n=$((n + 1))
printf '%s' "$n" >"$DEBIAN_FDE_TEST_SBV_STATE"
case "${DEBIAN_FDE_TEST_SBV_MODE:-failonce}" in
    fail) exit 1 ;;
    failonce) [ "$n" -le 1 ] && exit 1 ;;
esac
exit 0
EOF
chmod +x "$T/stub/sbsign" "$T/stub/sbverify"
export PATH="$T/stub:$PATH"

run_hook() { sh "$BOOTMGR" </dev/null >/dev/null 2>&1; echo $?; }
reset_stubs() { : >"$DEBIAN_FDE_TEST_LOG"; printf '0' >"$DEBIAN_FDE_TEST_SBV_STATE"; }

# fixture: a REAL encrypted release.pem (ADR-18 form) + public material
HOOK_PASS='ci-hook-passphrase-600000'
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
    -in "$REPO/fixtures/keys/release.pem" -passout pass:"$HOOK_PASS" \
    -out "$DEBIAN_FDE_KEYDIR/release.pem" 2>/dev/null
cp "$REPO/fixtures/keys/release.crt" "$DEBIAN_FDE_KEYDIR/release.crt"
[ -s "$DEBIAN_FDE_KEYDIR/release.pem" ] || { echo "fixture: encrypted PEM failed" >&2; exit 1; }

# leg 1: encrypted key + NO passphrase env + NO tty -> 64 + marker, no signing
reset_stubs
unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :
assert_eq "hook: encrypted key, no credential -> rc 64" "64" "$(run_hook)"
assert_file_exists "hook: ADR-8 marker persisted" "$MARKER"
assert_contains "hook: marker demands the passphrase (env or interactive)" \
    "$(cat "$MARKER")" "passphrase required"
assert_eq "hook: nothing signed without a credential" "0" \
    "$(grep -c '^sbsign' "$DEBIAN_FDE_TEST_LOG"; true)"

# leg 2: WRONG env passphrase -> 64 + marker naming wrong-passphrase
reset_stubs
export DEBIAN_FDE_KEY_PASSPHRASE=definitely-not-it
assert_eq "hook: wrong env passphrase -> rc 64" "64" "$(run_hook)"
assert_contains "hook: wrong-passphrase marker is distinct" \
    "$(cat "$MARKER")" "wrong passphrase"
unset DEBIAN_FDE_KEY_PASSPHRASE

# leg 3: correct env passphrase -> hook re-signs via the UNLOCKED tmpfs key
reset_stubs
export DEBIAN_FDE_KEY_PASSPHRASE=$HOOK_PASS
assert_eq "hook: correct passphrase -> rc 0" "0" "$(run_hook)"
LOG_CONTENT=$(cat "$DEBIAN_FDE_TEST_LOG")
assert_contains "hook: sbsign signed with the UNLOCKED tmpfs key" "$LOG_CONTENT" \
    "sbsign --key $T/shm/"
assert_eq "hook: the encrypted path was never handed to sbsign" "0" \
    "$(grep -c "$DEBIAN_FDE_KEYDIR/release.pem" "$DEBIAN_FDE_TEST_LOG"; true)"
assert_eq "hook: boot manager replaced by the signed binary" \
    "signed($DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi)" \
    "$(cat "$DEBIAN_FDE_ESP/EFI/systemd/systemd-bootx64.efi")"
assert_eq "hook: decrypted copy scrubbed after the hook" "" \
    "$(find "$T/shm" -maxdepth 1 -name 'debian-fde-unlock.*' -print 2>/dev/null)"
assert_eq "hook: success cleared the marker" "0" "$([ -e "$MARKER" ] && echo 1 || echo 0)"
unset DEBIAN_FDE_KEY_PASSPHRASE

# leg 4: PLAINTEXT release.pem -> unchanged behavior (keydir path, no unlock)
reset_stubs
printf 'plaintext-key-material' >"$DEBIAN_FDE_KEYDIR/release.pem"
assert_eq "hook: plaintext key -> rc 0 (unchanged)" "0" "$(run_hook)"
assert_contains "hook: plaintext key signed straight from the keydir" \
    "$(cat "$DEBIAN_FDE_TEST_LOG")" "sbsign --key $DEBIAN_FDE_KEYDIR/release.pem"
assert_eq "hook: plaintext run left no tmpfs unlock file" "" \
    "$(find "$T/shm" -maxdepth 1 -name 'debian-fde-unlock.*' -print 2>/dev/null)"

# leg 5: the lib seam is overridable (DEBIAN_FDE_LIB_DIR) — default derivation
# (hooks/../lib) already proven by the legs above; a WRONG override fails loud
# (guard_fail's channel is the marker file, ADR-8)
reset_stubs
export DEBIAN_FDE_LIB_DIR=$T/no-such-lib
assert_eq "hook: unusable lib seam -> fail-closed 64" "64" "$(run_hook)"
assert_contains "hook: unusable lib seam is loud in the marker" \
    "$(cat "$MARKER")" "runtime"
unset DEBIAN_FDE_LIB_DIR

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
