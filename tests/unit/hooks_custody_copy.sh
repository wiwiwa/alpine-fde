#!/usr/bin/env bash
# tests/unit/hooks_custody_copy.sh — ADR-18 custody copy + unlock seam in the
# NEW Alpine kernel build hook (docs/Architecture.md §9.2, ADR-18/ADR-8;
# G-C16 rewrite):
#   * the hook carries the new recovery copy: re-run the flow (enter the
#     release-key passphrase when prompted); unattended: provide
#     ALPINE_FDE_KEY_PASSPHRASE via your credential agent, then `apk fix`
#     — the stale
#     dpkg-era lines are GONE
#   * the boot-manager re-sign routes its sbsign --key through keys_unlock:
#     an ENCRYPTED release.pem is decrypted ONCE to tmpfs and the UNLOCKED
#     path is signed with; plaintext keys keep the old behavior;
#     missing/wrong passphrase = loud 64 + build-failed marker (ADR-8)
#   * §9.2/ADR-18 single-unlock: ONE hook run unlocks EXACTLY ONCE — the
#     hook unlocks BEFORE `ukictl build` and hands the ALREADY-UNLOCKED
#     staged path to the child (staged keydir seam), so the build child and
#     the boot-manager re-sign leg never unlock/prompt again
#   * ADR-8 loud failure stays SINGLE: no env + no tty -> one rc 64, one
#     marker report, zero prompts
#   * the decrypted copy is scrubbed after the hook exits — on success AND
#     on failure (single EXIT-trap scrub site)
#   * the env namespace is ALPINE_FDE_* only — the retired DEBIAN_FDE_*
#     spellings grant no credential (§8.1)

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
assert_contains "hook: names the credential-agent env seam" "$C" "ALPINE_FDE_KEY_PASSPHRASE"
assert_not_contains "hook: no retired DEBIAN_FDE_* compat spelling" "$C" "DEBIAN_FDE_"
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
# keys_unlock stages under ALPINE_FDE_TMPDIR (lib/keys.sh)
export ALPINE_FDE_TMPDIR=$T/shm
export ALPINE_FDE_TEST_LOG=$T/cmd.log
export ALPINE_FDE_LIB_DIR=$REPO/lib
KVER=6.6.63-0-lts
mkdir -p "$ALPINE_FDE_ESP/EFI/systemd" "$ALPINE_FDE_ESP/EFI/BOOT" \
    "$ALPINE_FDE_KEYDIR" "$ALPINE_FDE_ROOT/etc/alpine-fde" "$T/stub" "$T/shm"
printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
printf 'unsigned-fallback' >"$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
MARKER=$ALPINE_FDE_ROOT/etc/alpine-fde/build-failed

# recording alpine-fde stub (the ukictl build child — "succeeds" unless
# ALPINE_FDE_TEST_FAIL is set; records the ALPINE_FDE_KEYDIR seam it was
# handed so the single-unlock handoff is assertable)
FAKE=$T/stub/alpine-fde
cat >"$FAKE" <<'EOF'
#!/bin/sh
printf 'alpine-fde %s ALPINE_FDE_KEYDIR=%s\n' "$*" "${ALPINE_FDE_KEYDIR:-}" >>"$ALPINE_FDE_TEST_LOG"
# record WHAT the child saw at its keydir seam (mid-run: the hook scrubs the
# staging on exit, so this is the only vantage point)
if [ -n "${ALPINE_FDE_KEYDIR:-}" ] && [ -f "$ALPINE_FDE_KEYDIR/release.pem" ]; then
    printf 'child-release.pem=%s\n' "$(cat "$ALPINE_FDE_KEYDIR/release.pem")" \
        >>"$ALPINE_FDE_TEST_LOG"
fi
[ -n "${ALPINE_FDE_TEST_FAIL:-}" ] && exit "${ALPINE_FDE_TEST_FAIL}"
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

# the hook-run passphrase (fixtures + stub tty prompt seam below)
HOOK_PASS='ci-hook-passphrase-600000'

# =============================================================================
# keys_unlock stub lib (plugged in through the ALPINE_FDE_LIB_DIR seam, cf.
# leg 6): a contract-shaped stand-in for lib/keys.sh that COUNTS unlock
# invocations and passphrase prompts, so the §9.2/ADR-18 single-unlock
# contract is observable. The stub tty seam (ALPINE_FDE_TEST_TTY) stands in
# for `[ -t 0 ]` because run_hook feeds the hook </dev/null.
# =============================================================================
STUBLIB=$T/stub-lib
mkdir -p "$STUBLIB"
: >"$STUBLIB/common.sh"
cat >"$STUBLIB/keys.sh" <<'EOF'
# stub keys.sh — unit-test double for lib/keys.sh (ADR-18 custody surface only)
keys_is_encrypted() {
    [ -n "$1" ] && [ -f "$1" ] || return 1
    case $(head -n 1 "$1") in
        *ENCRYPTED*) return 0 ;;
        *) return 1 ;;
    esac
}
keys_unlock() {
    printf 'keys_unlock %s\n' "$1" >>"$ALPINE_FDE_UNLOCK_LOG"
    [ $# -eq 1 ] && [ -f "$1/release.pem" ] || return 64
    if [ -z "${ALPINE_FDE_KEY_PASSPHRASE:-}" ]; then
        if [ -z "${ALPINE_FDE_TEST_TTY:-}" ]; then
            printf 'keys_unlock: release.pem is encrypted: passphrase required\n' >&2
            return 64
        fi
        # stub tty prompt: no-echo read stand-in, counted in the log
        printf 'prompt\n' >>"$ALPINE_FDE_UNLOCK_LOG"
        ALPINE_FDE_KEY_PASSPHRASE=$ALPINE_FDE_TEST_HOOK_PASS
    fi
    if [ "$ALPINE_FDE_KEY_PASSPHRASE" != "$ALPINE_FDE_TEST_HOOK_PASS" ]; then
        # mirror lib/keys.sh: a wrong passphrase stages + scrubs, then fails
        _su_bad=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-unlock.XXXXXX")
        printf 'x' >"$_su_bad"
        rm -f "$_su_bad"
        return 65
    fi
    _su_out=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-unlock.XXXXXX") || return 64
    printf 'unlocked-release-key' >"$_su_out"
    chmod 600 "$_su_out"
    printf '%s\n' "$_su_out"
}
keys_scrub() {
    for _ss_f in "$@"; do
        [ -n "$_ss_f" ] || continue
        rm -f "$_ss_f"
    done
}
EOF
export ALPINE_FDE_LIB_DIR=$STUBLIB
export ALPINE_FDE_TEST_HOOK_PASS=$HOOK_PASS
export ALPINE_FDE_UNLOCK_LOG=$T/unlock.log

run_hook() { sh "$BUILD" add "$KVER" </dev/null >"$T/out.log" 2>&1; echo $?; }
reset_stubs() { : >"$ALPINE_FDE_TEST_LOG"; : >"$ALPINE_FDE_UNLOCK_LOG"; }
# unlock-count helpers over the stub log
unlock_count() { grep -c '^keys_unlock ' "$ALPINE_FDE_UNLOCK_LOG"; }
prompt_count() { grep -c '^prompt$' "$ALPINE_FDE_UNLOCK_LOG"; }
staged_left() { find "$T/shm" -maxdepth 1 \( -name '*-fde-unlock.*' -o -name '*-fde-hook-keys.*' \) -print 2>/dev/null; }

# fixture: a REAL encrypted release.pem (ADR-18 form) + public material
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
    -in "$REPO/fixtures/keys/release.pem" -passout pass:"$HOOK_PASS" \
    -out "$ALPINE_FDE_KEYDIR/release.pem" 2>/dev/null
cp "$REPO/fixtures/keys/release.crt" "$ALPINE_FDE_KEYDIR/release.crt"
[ -s "$ALPINE_FDE_KEYDIR/release.pem" ] || { echo "fixture: encrypted PEM failed" >&2; exit 1; }

# leg 1: encrypted key + NO passphrase env + NO tty -> 64 + marker, no signing
reset_stubs
unset ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || :
assert_eq "hook: encrypted key, no credential -> rc 64" "64" "$(run_hook)"
assert_file_exists "hook: ADR-8 marker persisted" "$MARKER"
assert_contains "hook: marker demands the passphrase (env or interactive)" \
    "$(cat "$MARKER")" "passphrase required"
assert_eq "hook: nothing signed without a credential" "0" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG"; true)"
assert_eq "hook: impossible unlock is attempted ONCE (single-unlock, §9.2/ADR-18)" \
    "1" "$(unlock_count; true)"
assert_eq "hook: impossible unlock never prompts (no tty -> loud, ADR-8)" \
    "0" "$(prompt_count; true)"
assert_eq "hook: loud failure reported ONCE (no double marker write)" \
    "1" "$(grep -c 'passphrase required' "$MARKER"; true)"
assert_eq "hook: failure path left no staging behind" "" "$(staged_left)"

# leg 2: WRONG env passphrase -> 64 + marker naming wrong-passphrase
reset_stubs
export ALPINE_FDE_KEY_PASSPHRASE=definitely-not-it
assert_eq "hook: wrong env passphrase -> rc 64" "64" "$(run_hook)"
assert_contains "hook: wrong-passphrase marker is distinct" \
    "$(cat "$MARKER")" "wrong passphrase"
assert_eq "hook: wrong-passphrase run is a single unlock attempt" \
    "1" "$(unlock_count; true)"
assert_eq "hook: wrong-passphrase failure path left no staging behind" "" "$(staged_left)"
unset ALPINE_FDE_KEY_PASSPHRASE

# leg 3: correct env passphrase -> re-signs via the UNLOCKED tmpfs key
reset_stubs
export ALPINE_FDE_KEY_PASSPHRASE=$HOOK_PASS
assert_eq "hook: correct env passphrase -> rc 0" "0" "$(run_hook)"
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
assert_eq "hook: env path unlocks EXACTLY ONCE per hook run" \
    "1" "$(unlock_count; true)"
assert_eq "hook: env path performs ZERO passphrase prompts" \
    "0" "$(prompt_count; true)"
assert_contains "hook: build child received the staged keydir (single-unlock handoff)" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "ALPINE_FDE_KEYDIR=$T/shm/alpine-fde-hook-keys."
assert_eq "hook: build child never saw the encrypted keydir" "0" \
    "$(grep -c "ALPINE_FDE_KEYDIR=$ALPINE_FDE_KEYDIR\b" "$ALPINE_FDE_TEST_LOG"; true)"
assert_contains "hook: staged keydir serves the ALREADY-UNLOCKED key (not the encrypted PEM)" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "child-release.pem=unlocked-release-key"
unset ALPINE_FDE_KEY_PASSPHRASE

# leg 4: the RETIRED DEBIAN_FDE_* spelling grants NO credential — a set
# retired var must not unlock (falls through to no-tty loud failure, §8.1)
reset_stubs
export DEBIAN_FDE_KEY_PASSPHRASE=$HOOK_PASS
assert_eq "hook: retired DEBIAN_FDE_KEY_PASSPHRASE is ignored -> rc 64" "64" "$(run_hook)"
unset DEBIAN_FDE_KEY_PASSPHRASE 2>/dev/null || :

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
export ALPINE_FDE_LIB_DIR=$STUBLIB

# =============================================================================
# §9.2/ADR-18 single-unlock across BOTH stages (build child + re-sign leg)
# =============================================================================
# re-encrypt the fixture (legs 5+ replaced it with plaintext) and reset the
# ESP so both signing stages actually run
refit_encrypted() {
    openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter 600000 \
        -in "$REPO/fixtures/keys/release.pem" -passout pass:"$HOOK_PASS" \
        -out "$ALPINE_FDE_KEYDIR/release.pem" 2>/dev/null
    printf 'unsigned-systemd-boot' >"$ALPINE_FDE_ESP/EFI/systemd/systemd-bootx64.efi"
    printf 'unsigned-fallback' >"$ALPINE_FDE_ESP/EFI/BOOT/BOOTX64.EFI"
}

# leg 7: encrypted key + NO env + STUB TTY prompt -> the prompt is hit EXACTLY
# ONCE per hook run and BOTH stages (ukictl build + boot-manager re-sign)
# succeed on the single unlocked copy
refit_encrypted
reset_stubs
unset ALPINE_FDE_KEY_PASSPHRASE 2>/dev/null || :
export ALPINE_FDE_TEST_TTY=1
assert_eq "hook: tty prompt path -> rc 0" "0" "$(run_hook)"
assert_eq "hook: tty path unlocks EXACTLY ONCE per hook run" \
    "1" "$(unlock_count; true)"
assert_eq "hook: tty path prompts EXACTLY ONCE (no second unlock in the re-sign leg)" \
    "1" "$(prompt_count; true)"
assert_eq "hook: both stages signed (build child + 2 ESP binaries)" "2" \
    "$(grep -c '^sbsign' "$ALPINE_FDE_TEST_LOG"; true)"
assert_contains "hook: build child signed with the single staged unlock" \
    "$(cat "$ALPINE_FDE_TEST_LOG")" "ALPINE_FDE_KEYDIR=$T/shm/alpine-fde-hook-keys."
assert_eq "hook: tty path scrubbed the staged copy after the run" "" "$(staged_left)"
unset ALPINE_FDE_TEST_TTY

# leg 8: unlock SUCCEEDS but the build child fails -> rc propagates (ADR-8)
# and the EXIT trap still scrubs the decrypted copy exactly once
refit_encrypted
reset_stubs
export ALPINE_FDE_TEST_TTY=1
export ALPINE_FDE_TEST_FAIL=7
assert_eq "hook: failing build child -> rc propagates" "7" "$(run_hook)"
assert_contains "hook: build failure marker appended" \
    "$(cat "$MARKER")" "kernel hook: ukictl build failed"
assert_eq "hook: child-failure path unlocked ONCE" "1" "$(unlock_count; true)"
assert_eq "hook: child-failure path scrubbed the staged copy on the exit path" "" \
    "$(staged_left)"
unset ALPINE_FDE_TEST_TTY ALPINE_FDE_TEST_FAIL

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
