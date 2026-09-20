#!/usr/bin/env bash
# tests/unit/hooks_mkinitfs_unseal.sh — G-C8 (§8.2 Early-Boot Unseal Hook +
# Fail-Closed Security Guarantee; ADR-13): drives the REAL
# hooks/mkinitfs/alpine-fde-unseal.sh inside a busybox-shaped sandbox.
#
# The hook's collaborators are PATH stubs that RECORD their full argv:
#   tpm2_pcrextend/startauthsession/policypcr/policyauthorize/loadexternal/
#   verifysignature/createprimary/load/unseal/flushcontext, cryptsetup,
#   poweroff. openssl/sha256sum/awk/sed/dd/od stay REAL (they exist in the
#   initramfs per hooks/mkinitfs/features.d/alpine-fde.files).
#
# Pinned behavior (docs/Architecture.md §8.2, §9.1 Stage 2, ADR-20):
#   1. extends sha256("enter-initrd") into PCR 11 (ukify --measure phase
#      string, lib/cmd/pcrsign.sh --phases=enter-initrd)
#   2. consumes the §7.2 dash-form systemd-tpm2 token (lib/token.sh schema)
#      via `cryptsetup token export` + the UKI stub's /.extra/ files
#   3. PolicyAuthorize session: policypcr(sha256:11|7,11) + policyauthorize
#      over the release-key-signed approved policy (openssl-verified against
#      /.extra/tpm2-pcr-public-key.pem), tpm2_unseal, cryptsetup open per
#      /etc/crypttab (UUID mapping)
#   4. fail-closed: TPM absent/refused/tampered/empty-unseal -> bounded
#      keyslot-0 prompt (3 strikes) -> poweroff -f; NEVER a shell
#   5. RAID1: one prompt, passphrase cached across members
#   6. writes the provisional-booted install-state marker on the mounted
#      NEWROOT when the state file says `installed` (atomic tmp+mv)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

assert_not_contains() {
    if [ -z "$3" ]; then
        _fail "$1 (empty needle — vacuous pass refused)"
    elif [[ "$2" != *"$3"* ]]; then
        _pass "$1"
    else
        _fail "$1 (haystack must not contain [$3])"
    fi
}

assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}

HOOK=$REPO/hooks/mkinitfs/alpine-fde-unseal.sh
FILES=$REPO/hooks/mkinitfs/features.d/alpine-fde.files

TMP=$(mktemp -d /tmp/debian-fde-unseal.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

BIN=$TMP/bin
LOG=$TMP/argv.log
: >"$LOG"
mkdir -p "$BIN" "$TMP/extra" "$TMP/tmp" "$TMP/newroot/etc/alpine-fde"

# --- fixtures -------------------------------------------------------------------
KEYDIR=$REPO/fixtures/keys

hex2bin() {
    printf '%s' "$1" | LC_ALL=C awk '{
        h = "0123456789abcdef"
        for (i = 1; i <= length($0); i += 2)
            printf "%c", (index(h, tolower(substr($0, i, 1))) - 1) * 16 + (index(h, tolower(substr($0, i + 1, 1))) - 1)
    }'
}

# the approved policy digest the .pcrsig signs (any 64-hex value works: the
# TPM chain is stubbed; openssl verification is REAL)
POL=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf '%s' "$POL" | hex2bin >"$TMP/pol.bin"
SIGB64=$(openssl dgst -sha256 -sign "$KEYDIR/release.pem" "$TMP/pol.bin" | openssl base64 -A)
# a REAL signature over the WRONG message (the token-tampering class)
BADSIGB64=$(printf 'tampered' | openssl dgst -sha256 -sign "$KEYDIR/release.pem" | openssl base64 -A)
# sha256 of the ukify --measure phase string (what pcrextend must feed)
PHASH=$(printf 'enter-initrd' | sha256sum | awk '{print $1}')

cp "$KEYDIR/release.pub" "$TMP/extra/tpm2-pcr-public-key.pem"
cat >"$TMP/extra/tpm2-pcr-signature.json" <<EOF
{
  "sha256": [
    {"pcrs": [11], "pkfp": "deadbeefcafe", "pol": "$POL", "sig": "$SIGB64"}
  ]
}
EOF
cat >"$TMP/extra/tpm2-pcr-signature-7-11.json" <<EOF
{
  "sha256": [
    {"pcrs": [7, 11], "pkfp": "deadbeefcafe", "pol": "$POL", "sig": "$SIGB64"}
  ]
}
EOF

make_token() { # <outfile> <pcrs-json> <sigb64>
    cat >"$1" <<EOF
{
  "type": "systemd-tpm2",
  "keyslots": ["1"],
  "tpm2-blob": "AAJhYg==",
  "tpm2-pcrs": $2,
  "tpm2-pcr-bank": "sha256",
  "tpm2-pubkey": "cHVi",
  "tpm2-signature": "$3"
}
EOF
}
make_token "$TMP/token.json" '[11]' "$SIGB64"
make_token "$TMP/token-7-11.json" '[7, 11]' "$SIGB64"
make_token "$TMP/token-tampered.json" '[11]' "$BADSIGB64"

UUID1=22222222-2222-2222-2222-222222222222
UUID2=33333333-3333-3333-3333-333333333333
printf '%s\n' "root UUID=$UUID1 none luks,tpm2-device=auto,discard" >"$TMP/crypttab"
printf '%s\n' \
    "root1 UUID=$UUID1 none luks,tpm2-device=auto,password-cache=yes" \
    "root2 UUID=$UUID2 none luks,tpm2-device=auto,password-cache=yes" >"$TMP/crypttab-raid1"

write_state() { # <state>
    printf '{\n  "schema_version": 1,\n  "state": "%s",\n  "updated_at": "2026-01-01T00:00:00Z"\n}\n' \
        "$1" >"$TMP/newroot/etc/alpine-fde/install-state.json"
}

# --- stubs (record full argv) ------------------------------------------------------
for v in tpm2_pcrextend tpm2_startauthsession tpm2_policypcr tpm2_policyauthorize \
    tpm2_loadexternal tpm2_verifysignature tpm2_createprimary tpm2_load \
    tpm2_unseal tpm2_flushcontext; do
    cat >"$BIN/$v" <<EOF
#!/bin/sh
printf '$v %s\n' "\$*" >>'$LOG'
[ "\${FDE_TPM_FAIL:-0}" = 1 ] && exit 1
prev=
for a in "\$@"; do
    case "\$prev" in
        -o) [ "\${FDE_UNSEAL_EMPTY:-0}" = 1 ] && : >"\$a" ||
            printf '1111111111111111111111111111111111111111111111111111111111111111' >"\$a" ;;
        -t | -n | -S | -c) : >"\$a" ;;
    esac
    prev=\$a
done
exit 0
EOF
    chmod +x "$BIN/$v"
done

cat >"$BIN/cryptsetup" <<EOF
#!/bin/sh
printf 'cryptsetup %s\n' "\$*" >>'$LOG'
if [ "\$1" = "token" ]; then
    cat "\${FDE_TEST_TOKEN_FILE:-$TMP/token.json}"
    exit 0
fi
if [ "\$1" = "open" ]; then
    IFS= read -r _p || :
    printf 'cryptsetup-pass %s\n' "\$_p" >>'$LOG'
    [ "\${FDE_OPEN_FAIL:-0}" = 1 ] && exit 1
    exit 0
fi
exit 1
EOF
chmod +x "$BIN/cryptsetup"

cat >"$BIN/poweroff" <<EOF
#!/bin/sh
printf 'poweroff %s\n' "\$*" >>'$LOG'
exit 0
EOF
chmod +x "$BIN/poweroff"

# --- driver --------------------------------------------------------------------
run_hook() { # <stdin-file> [VAR=VAL ...]
    local stdin=$1
    shift
    env PATH="$BIN:$PATH" FDE_NEWROOT="$TMP/newroot" FDE_EXTRA_DIR="$TMP/extra" \
        FDE_CRYPTTAB="$TMP/crypttab" FDE_TMPDIR="$TMP/tmp" \
        FDE_TEST_TOKEN_FILE="$TMP/token.json" "$@" \
        sh "$HOOK" <"$stdin" >"$TMP/out.log" 2>&1
    echo $?
}

argv_count() { # <pattern>
    grep -c "$1" "$LOG" 2>/dev/null || :
}
reset_leg() {
    : >"$LOG"
    rm -f "$TMP/out.log"
}

# =============================================================================
# 0. artifact shape
# =============================================================================
assert_file_exists "unseal hook exists" "$HOOK"
assert_eq "hook is executable" "1" "$([ -x "$HOOK" ] && echo 1 || echo 0)"
sh -n "$HOOK" >/dev/null 2>&1
assert_eq "hook parses under POSIX sh (busybox ash)" "0" "$?"
assert_eq "hook source never spawns a shell or rescue path" "" \
    "$(grep -nE '(^|[^a-zA-Z_-])(exec|rescue)([^a-zA-Z_-]|$)|sh +-c|ash +-c' "$HOOK" || true)"
assert_file_exists "features.d/alpine-fde.files exists" "$FILES"
for need in \
    usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh \
    usr/bin/cryptsetup usr/bin/openssl \
    usr/bin/tpm2_pcrextend usr/bin/tpm2_startauthsession usr/bin/tpm2_policypcr \
    usr/bin/tpm2_policyauthorize usr/bin/tpm2_loadexternal usr/bin/tpm2_verifysignature \
    usr/bin/tpm2_createprimary usr/bin/tpm2_load usr/bin/tpm2_unseal usr/bin/tpm2_flushcontext \
    libtss2-esys libtss2-tcti-device \
    kernel/drivers/char/tpm/tpm_tis.ko \
    btrfs/btrfs.ko ext4/ext4.ko \
    drivers/md/bcache/bcache.ko 69-bcache.rules; do
    assert_contains "features.d file lists $need" "$(cat "$FILES" 2>/dev/null)" "$need"
done

# =============================================================================
# 1. SUCCESS — token path, provisional token {PCR 11} (§9.1 Stage 2)
# =============================================================================
reset_leg
write_state installed
printf 'unused\n' >"$TMP/stdin1"
rc=$(run_hook "$TMP/stdin1")
assert_rc "token success: hook rc 0" 0 "$rc"
assert_eq "token success: pcrextend feeds sha256(enter-initrd) into PCR 11" \
    "tpm2_pcrextend 11:sha256=$PHASH" "$(grep '^tpm2_pcrextend' "$LOG")"
assert_contains "token success: verify key loaded from /.extra pubkey" \
    "$(grep '^tpm2_loadexternal' "$LOG")" "$TMP/extra/tpm2-pcr-public-key.pem"
assert_contains "token success: verifysignature covers pol+sig over rsassa/sha256" \
    "$(grep '^tpm2_verifysignature' "$LOG")" "-f rsassa -g sha256"
assert_contains "token success: PolicyAuthorize carries the approved policy file" \
    "$(grep '^tpm2_policyauthorize' "$LOG")" "pol.bin"
assert_contains "token success: PolicyAuthorize carries the pubkey Name file" \
    "$(grep '^tpm2_policyauthorize' "$LOG")" "pub.name"
assert_contains "token success: PolicyAuthorize carries the verification ticket" \
    "$(grep '^tpm2_policyauthorize' "$LOG")" "ticket.bin"
assert_contains "token success: PolicyPCR over the token's pcrs (sha256:11)" \
    "$(grep '^tpm2_policypcr' "$LOG")" "-l sha256:11"
assert_contains "token success: unseal under the policy session" \
    "$(grep '^tpm2_unseal' "$LOG")" "session:"
assert_eq "token success: opens via the UUID resolved from crypttab" \
    "cryptsetup open --type luks --key-file - /dev/disk/by-uuid/$UUID1 root" \
    "$(grep '^cryptsetup open' "$LOG")"
assert_eq "token success: exactly one open (no prompt needed)" "1" "$(argv_count '^cryptsetup open')"
assert_eq "token success: no poweroff" "0" "$(argv_count '^poweroff')"
assert_contains "token success: marker moved to provisional-booted" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "provisional-booted"'
assert_eq "token success: no leftover temp state documents" "" \
    "$(find "$TMP/newroot/etc/alpine-fde" -name '.*' -print)"
assert_eq "token success: success path never runs a shell (recorded argv)" "" \
    "$(grep -nE 'sh +-c|(^| )exec |rescue|ash +-c' "$LOG" || true)"

# =============================================================================
# 2. FINALIZED token {PCR 7, 11} — policy PCR selection follows the token;
#    finalized state is NOT re-marked
# =============================================================================
mkdir -p "$TMP/extra-7-11"
cp "$KEYDIR/release.pub" "$TMP/extra-7-11/tpm2-pcr-public-key.pem"
cp "$TMP/extra/tpm2-pcr-signature-7-11.json" "$TMP/extra-7-11/tpm2-pcr-signature.json"
reset_leg
write_state finalized
rc=$(run_hook "$TMP/stdin1" FDE_TEST_TOKEN_FILE="$TMP/token-7-11.json" FDE_EXTRA_DIR="$TMP/extra-7-11")
assert_rc "finalized token: hook rc 0" 0 "$rc"
assert_contains "finalized token: PolicyPCR over {7,11}" \
    "$(grep '^tpm2_policypcr' "$LOG")" "-l sha256:7,11"
assert_contains "finalized: state file NOT rewritten" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "finalized"'

# =============================================================================
# 3. TPM absent/refused -> bounded recovery prompt path (§8.2 step 4)
# =============================================================================
reset_leg
write_state installed
printf 'recovery-pass\n' >"$TMP/stdin-rec"
rc=$(run_hook "$TMP/stdin-rec" FDE_TPM_FAIL=1)
assert_rc "tpm absent: unlocked via keyslot-0 recovery passphrase" 0 "$rc"
assert_eq "tpm absent: no unseal attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "tpm absent: exactly one open with the prompted passphrase" "1" "$(argv_count '^cryptsetup open')"
assert_contains "tpm absent: open used the prompted passphrase" \
    "$(cat "$LOG")" "cryptsetup-pass recovery-pass"
assert_eq "tpm absent: no poweroff on first-correct passphrase" "0" "$(argv_count '^poweroff')"
assert_contains "tpm absent: marker still written (unlock succeeded)" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "provisional-booted"'

# =============================================================================
# 4. 3-STRIKE -> poweroff -f exactly once, rc != 0 (§8.2 fail-closed)
# =============================================================================
reset_leg
write_state installed
printf 'wrong1\nwrong2\nwrong3\n' >"$TMP/stdin-3bad"
rc=$(run_hook "$TMP/stdin-3bad" FDE_TPM_FAIL=1 FDE_OPEN_FAIL=1)
assert_ne "3-strike: hook rc nonzero" "0" "$rc"
assert_eq "3-strike: poweroff -f called exactly once" "1" "$(argv_count '^poweroff')"
assert_contains "3-strike: poweroff is forced" "$(grep '^poweroff' "$LOG")" "-f"
assert_eq "3-strike: attempts bounded to exactly 3 opens" "3" "$(argv_count '^cryptsetup open')"
assert_eq "3-strike: no state write after failing" "installed" \
    "$(sed -n 's/^  "state": "\(.*\)",\{0,1\}$/\1/p' "$TMP/newroot/etc/alpine-fde/install-state.json")"

# =============================================================================
# 5. TAMPERED token (signature over a foreign digest) -> fail-closed prompt
#    path; TPM chain refused BEFORE unseal (I3)
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_TEST_TOKEN_FILE="$TMP/token-tampered.json" FDE_OPEN_FAIL=1)
assert_ne "tampered token: hook rc nonzero" "0" "$rc"
assert_eq "tampered token: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "tampered token: bounded to 3 prompt attempts then poweroff once" \
    "3 1" "$(argv_count '^cryptsetup open') $(argv_count '^poweroff')"

# =============================================================================
# 6. /.extra artifacts missing -> fail-closed prompt path (no TPM ops)
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-rec" FDE_EXTRA_DIR="$TMP/no-such-extra")
assert_rc "missing /.extra: recovery passphrase still unlocks" 0 "$rc"
assert_eq "missing /.extra: no unseal attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "missing /.extra: one open" "1" "$(argv_count '^cryptsetup open')"

# =============================================================================
# 7. unseal produced EMPTY secret -> fail-closed prompt path
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-rec" FDE_UNSEAL_EMPTY=1)
assert_rc "empty unseal: recovery passphrase unlocks" 0 "$rc"
assert_contains "empty unseal: open used the prompted passphrase (not empty)" \
    "$(cat "$LOG")" "cryptsetup-pass recovery-pass"
assert_eq "empty unseal: no poweroff" "0" "$(argv_count '^poweroff')"

# =============================================================================
# 8. RAID1 — token path: ONE unseal, EVERY member opened; prompt path: ONE
#    prompt, passphrase reused across members
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1" FDE_CRYPTTAB="$TMP/crypttab-raid1")
assert_rc "raid1 token: hook rc 0" 0 "$rc"
assert_eq "raid1 token: single unseal" "1" "$(argv_count '^tpm2_unseal')"
assert_eq "raid1 token: both members opened" "2" "$(argv_count '^cryptsetup open')"
assert_contains "raid1 token: member 1 via by-uuid" "$(grep '^cryptsetup open' "$LOG")" "/dev/disk/by-uuid/$UUID1"
assert_contains "raid1 token: member 2 via by-uuid" "$(grep '^cryptsetup open' "$LOG")" "/dev/disk/by-uuid/$UUID2"

reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-rec" FDE_TPM_FAIL=1 FDE_CRYPTTAB="$TMP/crypttab-raid1")
assert_rc "raid1 prompt: hook rc 0" 0 "$rc"
assert_eq "raid1 prompt: exactly one passphrase entry, reused (2 identical passes)" \
    "2" "$(argv_count '^cryptsetup-pass recovery-pass')"
assert_eq "raid1 prompt: both members opened" "2" "$(argv_count '^cryptsetup open')"
assert_eq "raid1 prompt: no poweroff" "0" "$(argv_count '^poweroff')"

# =============================================================================
# 9. no crypttab root entry -> fatal fail-closed (poweroff, no prompt loop)
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_CRYPTTAB="$TMP/no-such-crypttab")
assert_ne "no crypttab: hook rc nonzero" "0" "$rc"
assert_eq "no crypttab: poweroff exactly once" "1" "$(argv_count '^poweroff')"

# =============================================================================
# 10. state file absent -> no marker written, boot still proceeds
# =============================================================================
reset_leg
rm -f "$TMP/newroot/etc/alpine-fde/install-state.json"
rc=$(run_hook "$TMP/stdin1")
assert_rc "no state file: hook rc 0" 0 "$rc"
if [ -e "$TMP/newroot/etc/alpine-fde/install-state.json" ]; then
    _fail "no state file: absent file must not be created"
else
    _pass "no state file: absent file must not be created"
fi

finish
