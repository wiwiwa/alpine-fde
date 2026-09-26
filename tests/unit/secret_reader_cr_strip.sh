#!/usr/bin/env bash
# tests/unit/secret_reader_cr_strip.sh — console-CR tolerance of the secret
# readers (real-server blocker #15). On a serial / management console, Enter
# sends CR (\r) before the line-terminating LF; `IFS= read -r` keeps the
# trailing CR in the value, so every reader's [:cntrl:] guard refuses EVERY
# entry — the credential ceremony could never complete on such a console
# (server evidence: "the entered secret contains control characters — refusing"
# on the very first LUKS recovery-passphrase prompt).
# Contract:
#   * the shared strip idiom (lib/common.sh fde_strip_trailing_cr) removes one
#     trailing CR and leaves LF-only values untouched
#   * inst_prompt_secret (install) accepts a CRLF-terminated secret and the
#     value it stores is CR-free
#   * genuine embedded control characters (TAB) are still refused — the strip
#     must not become a blanket cntrl bypass
#   * rotate's rot_prompt strips CR on both reads; the mismatch check still
#     compares the stripped values
# Driven END-TO-END through the real readers with CRLF/LF stdin (the documented
# non-tty test seam) — never by re-implementing the reader in the test.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/install.sh
source "$REPO/lib/cmd/install.sh"

T=$(mktemp -d /tmp/alpine-fde-cr-strip.XXXXXX)
trap 'rm -rf "$T"' EXIT

# --- 1. the shared strip idiom ------------------------------------------------
V=$'S3cret-p4ss\r'
fde_strip_trailing_cr V
assert_eq "strip idiom: trailing CR removed" "S3cret-p4ss" "$V"

V=$'S3cret-p4ss\n'
fde_strip_trailing_cr V
assert_eq "strip idiom: LF-only value untouched" $'S3cret-p4ss\n' "$V"

V=$'ab\r\r'
fde_strip_trailing_cr V
assert_eq "strip idiom: only ONE trailing CR removed" $'ab\r' "$V"

# --- 2. install: inst_prompt_secret end-to-end over the stdin seam ------------
# run in the CURRENT shell (file redirect, never a pipe) so the eval-stored
# var is observable — the var placement is part of the reader's contract.
printf 'S3cret-p4ss\r\n' >"$T/crlf.in"
inst_prompt_secret 'pass: ' _V <"$T/crlf.in" 2>/dev/null
assert_eq "install reader: CRLF secret accepted, stored CR-free" "S3cret-p4ss" "$_V"

printf 'bad\tchar\n' >"$T/tab.in"
out=$(inst_prompt_secret 'pass: ' _V2 <"$T/tab.in" 2>&1); rc=$?
assert_eq "install reader: embedded TAB still refused (rc 64)" "64" "$rc"
assert_contains "install reader: TAB diagnostic names control characters" \
    "$out" "control characters"

: >"$T/eof.in"
out=$(inst_prompt_secret 'pass: ' _V3 <"$T/eof.in" 2>&1); rc=$?
assert_eq "install reader: EOF still fail-closed (blocker-hardened behavior)" "64" "$rc"
assert_contains "install reader: EOF diagnostic present" "$out" "end of input"

# --- 3. rotate: rot_prompt strips CR on both reads ----------------------------
# rot_prompt reads </dev/tty verbatim, so allocate a pty via script(1) and
# feed the CRLF secrets through it (the real interactive shape).
sed -n '/^rot_prompt()/,/^}/p' "$REPO/lib/cmd/rotate.sh" >"$T/rot_prompt.sh"
assert_file_exists "rot_prompt extracted from rotate.sh" "$T/rot_prompt.sh"
cat >"$T/rot_drive.sh" <<'DRIVE'
source "$_fde_lib/common.sh"
source "$_fde_dir/rot_prompt.sh"
# the server shape: the console line discipline does NOT translate CR->NL
# (icrnl off), so the CR Enter sends SURVIVES into the read — the exact
# condition that fired the blocker on the real server.
stty -icrnl 2>/dev/null || true
rot_prompt P "new: " 2>&1
printf 'GOT=[%s]' "$P"
DRIVE
# script(1) wires its stdin into the driven session's /dev/tty; the feed must
# be PACED (input only after the drive applied -icrnl), or the pty buffers the
# bytes under the wrong line discipline.
out=$(cd "$T" && _fde_lib="$REPO/lib" _fde_dir="$T" bash -c \
    '(sleep 1; printf "R3ally-good\r\nR3ally-good\r\n"; sleep 2) | script -qec "bash \"$_fde_dir/rot_drive.sh\"" /dev/null' 2>&1 | tr -d '\r')
assert_contains "rotate reader: CRLF secrets accepted (CR stripped on both reads)" \
    "$out" 'GOT=[R3ally-good]'

out=$(cd "$T" && _fde_lib="$REPO/lib" _fde_dir="$T" bash -c \
    '(sleep 1; printf "R3ally-good\r\nOther-secret\n"; sleep 2) | script -qec "bash \"$_fde_dir/rot_drive.sh\"" /dev/null' 2>&1 | tr -d '\r')
assert_contains "rotate reader: mismatched confirm still refuses" "$out" "do not match"

# --- 4. finalize: the recovery re-prompt reads use the shared strip -----------
assert_contains "finalize re-prompt: reads routed through the shared strip idiom" \
    "$(grep -c 'fde_strip_trailing_cr' "$REPO/lib/cmd/finalize.sh")" "2"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
