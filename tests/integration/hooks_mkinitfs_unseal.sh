#!/usr/bin/env bash
# tests/integration/hooks_mkinitfs_unseal.sh — G-C8 (§8.2 Early-Boot Unseal Hook +
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
#   0. ADR-20 amended PRE-UNSEAL SECURE BOOT GUARD — the hook's FIRST action:
#      reads SecureBoot/SetupMode from efivarfs (canonical EFI_GLOBAL_VARIABLE
#      namespace; fail-closed on unreadable/missing). SB off (secureboot != 1
#      || setup_mode != 0) is a HARD refusal: notice + "Press Enter to reboot"
#      + OsIndications boot-to-firmware-setup (best-effort) + `reboot -f`. The
#      container is NEVER unsealed with SB off — no token path, NO recovery
#      passphrase fallback, no pcrextend, no cryptsetup, no poweroff prompt
#      loop. The provisional PCR-11-only token is only ever usable with SB on.
#   1. extends sha256("enter-initrd") into PCR 11 (ukify --measure phase
#      string, lib/cmd/pcrsign.sh --phases=enter-initrd)
#   2. consumes the §7.2 dash-form systemd-tpm2 token (lib/token.sh schema)
#      via `cryptsetup token export` + the UKI stub's /.extra/ files
#   3. PolicyAuthorize session: policypcr(sha256:11|7,11) + policyauthorize
#      over the approved policy digest carried by the DRIVE .pcrsig ENTRY,
#      whose OWN release-key signature is openssl-verified against
#      /.extra/tpm2-pcr-public-key.pem BEFORE any TPM session, tpm2_unseal,
#      cryptsetup open per /etc/crypttab (UUID mapping)
#   4. fail-closed: TPM absent/refused/tampered/empty-unseal -> bounded
#      keyslot-0 prompt (3 strikes) -> poweroff -f; NEVER a shell
#   5. RAID1: one prompt, passphrase cached across members; a PARTIAL token
#      unlock (one member's token open failed) still routes that member into
#      the same bounded prompt loop — never a silently incomplete pool
#   6. writes the provisional-booted install-state marker on the mounted
#      NEWROOT when the state file says `installed` (atomic tmp+mv)
#   7. token scan covers the full LUKS2 token-id range 0..31
#   8. G4 rollback (§9.3): a token whose tpm2-signature covers UKI-A's
#      ENROLL-time pol + a drive .pcrsig entry for UKI-B (same release key)
#      PASSES the I3 gate and unseals — the gate verifies the ENTRY's own
#      signature over the entry's pol, never the token's signature (which
#      covers only the enroll-time pol; requiring it to cover the entry made
#      every retained-kernel boot prompt). The policyauthorize input pin
#      proves the ENTRY's pol (not the token's enroll pol) is what the TPM
#      session admits, so PolicyPCR still fail-closes a pol ≠ live digest.
#   9. §6.1/§12 signing negative controls, ALL fail-closed at the I3 gate
#      (no verifysignature, no unseal, bounded prompt -> 3-strike poweroff):
#      token/.pcrsig PCR-selection mismatch in BOTH directions (no matching
#      entry -> no pol extraction), forged entry signature (unknown/foreign
#      key), swapped /.extra public key (keyName mismatch), missing .pcrsig
#      entry. The token's tpm2-signature is INERT metadata under this
#      semantic: corrupting it can only fail closed elsewhere (the entry's
#      own signature is what the gate verifies), never grant unseal.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
# shellcheck source=../lib/sentinels.sh
source "$HERE/../lib/sentinels.sh"   # sentinel_of (MD-02: single promoted table)

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

TMP=$(mktemp -d /tmp/alpine-fde-unseal.XXXXXX)
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
hex2bin "$POL" >"$TMP/pol.bin"
SIGB64=$(openssl dgst -sha256 -sign "$KEYDIR/release.pem" "$TMP/pol.bin" | openssl base64 -A)
# a REAL signature over the WRONG message (the token-tampering class)
BADSIGB64=$(printf 'tampered' | openssl dgst -sha256 -sign "$KEYDIR/release.pem" | openssl base64 -A)
# sha256 of the ukify --measure phase string (what pcrextend must feed)
PHASH=$(printf 'enter-initrd' | sha256sum | awk '{print $1}')
# the sentinel secret the tpm2_unseal stub writes (the "TPM-unsealed" keyslot-1
# passphrase the token path feeds to `cryptsetup open`)
TOKEN_PASS=1111111111111111111111111111111111111111111111111111111111111111
# the tpm2_unseal stub emits the RAW secret; the hook feeds cryptsetup the
# base64-framed credential (ADR-19 framing — lib/seal.sh staged base64(raw))
TOKEN_PASS_B64=$(printf '%s' "$TOKEN_PASS" | openssl base64 -A)

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
# sig-corrupt class (s13 parity): the token's tpm2-signature with its first
# base64 char flipped — under the entry-sig semantic this is INERT metadata
BADSIG_CORRUPT="A${SIGB64#?}"
[ "$BADSIG_CORRUPT" = "$SIGB64" ] && BADSIG_CORRUPT="B${SIGB64#?}"
make_token "$TMP/token-sig-corrupt.json" '[11]' "$BADSIG_CORRUPT"

# --- G4 rollback fixtures: a SECOND (retained-kernel) pol, signed by the SAME
# release key. The standing token above carries tpm2-signature=$SIGB64 (over
# the ENROLL-time POL); the rollback drive entry carries pol=POL_B with its
# OWN release-key signature. The design-conformant I3 gate must admit it.
POL_B=feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
hex2bin "$POL_B" >"$TMP/pol-b.bin"
SIGB64_B=$(openssl dgst -sha256 -sign "$KEYDIR/release.pem" "$TMP/pol-b.bin" | openssl base64 -A)
# a FOREIGN key (unknown to the release authority) — the forged-entry class
openssl genrsa -out "$TMP/foreign.key" 2048 2>/dev/null
openssl rsa -in "$TMP/foreign.key" -pubout -out "$TMP/foreign.pub" 2>/dev/null
SIGB64_FOREIGN=$(openssl dgst -sha256 -sign "$TMP/foreign.key" "$TMP/pol.bin" | openssl base64 -A)

# extra-dir variants: <dir> <pol> <sig> — one [11] entry each
make_extra() {
    mkdir -p "$1"
    cp "$KEYDIR/release.pub" "$1/tpm2-pcr-public-key.pem"
    printf '{"sha256":[{"pcrs":[11],"pkfp":"deadbeefcafe","pol":"%s","sig":"%s"}]}\n' \
        "$2" "$3" >"$1/tpm2-pcr-signature.json"
}
make_extra "$TMP/extra-rollback" "$POL_B" "$SIGB64_B"        # UKI-B entry, same release key
make_extra "$TMP/extra-forged-sig" "$POL" "$SIGB64_FOREIGN"  # entry sig from an UNKNOWN key
# swapped /.extra public key: a VALID foreign key replaces the release key
# (the keyName the sealed policy pins would mismatch — user-space refuses too)
mkdir -p "$TMP/extra-swapped-key"
cp "$TMP/foreign.pub" "$TMP/extra-swapped-key/tpm2-pcr-public-key.pem"
printf '{"sha256":[{"pcrs":[11],"pkfp":"cafebabe","pol":"%s","sig":"%s"}]}\n' \
    "$POL" "$SIGB64" >"$TMP/extra-swapped-key/tpm2-pcr-signature.json"
# missing entry: well-formed .pcrsig with NO entry for the token's selection
mkdir -p "$TMP/extra-missing-entry"
cp "$KEYDIR/release.pub" "$TMP/extra-missing-entry/tpm2-pcr-public-key.pem"
printf '{"sha256":[]}\n' >"$TMP/extra-missing-entry/tpm2-pcr-signature.json"

# --- efivarfs fixtures (the ADR-20 pre-unseal SB guard's input; the canonical
# EFI_GLOBAL_VARIABLE namespace, 4-byte attrs header + payload byte, the same
# shape lib/firmware.sh fw_var_u8 reads) -----------------------------------------
FW_GUID='8be4df61-93ca-11d2-aa0d-00e098032b8c'
mk_efivars() { # <dir> <secureboot-byte> <setupmode-byte>
    mkdir -p "$1"
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$1/SecureBoot-$FW_GUID"
    printf '\007\000\000\000'"$(printf '\%03o' "$3")" >"$1/SetupMode-$FW_GUID"
}
mk_efivars "$TMP/efivars" 1 0        # DEFAULT: SB on, keys final (guard passes)
mk_efivars "$TMP/efivars-sb-off" 0 0 # SecureBoot=0 -> guard blocks
mk_efivars "$TMP/efivars-setupmode" 1 1 # SetupMode=1 -> guard blocks (keys not final)
mkdir -p "$TMP/efivars-empty"        # no variables -> unreadable -> guard blocks

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
            printf '$TOKEN_PASS' >"\$a" ;;
        -t | -n | -S | -c) : >"\$a" ;;
        # G4 pin: WHICH policy digest the TPM session admits (sha256 of the
        # -i file's bytes) — the rollback leg asserts the ENTRY's pol is
        # authorized, never the token's enroll-time pol
        -i) printf 'policyauthorize-pol %s\n' "\$(sha256sum "\$a" | cut -d' ' -f1)" >>'$LOG' ;;
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
    # FDE_TEST_TOKEN_MIN_ID seam: token export fails (no token) for every
    # token-id below the floor — used to place the token at a HIGH id
    _fdt_tid=0
    _fdt_prev=
    for _fdt_a in "\$@"; do
        [ "\$_fdt_prev" = "--token-id" ] && _fdt_tid=\$_fdt_a
        _fdt_prev=\$_fdt_a
    done
    if [ "\$_fdt_tid" -lt "\${FDE_TEST_TOKEN_MIN_ID:-0}" ]; then
        exit 1
    fi
    cat "\${FDE_TEST_TOKEN_FILE:-$TMP/token.json}"
    exit 0
fi
if [ "\$1" = "open" ]; then
    IFS= read -r _p || :
    printf 'cryptsetup-pass %s\n' "\$_p" >>'$LOG'
    # the mapper target is the last positional argv word
    _fdt_tgt=
    for _fdt_a in "\$@"; do
        _fdt_tgt=\$_fdt_a
    done
    [ "\${FDE_OPEN_FAIL:-0}" = 1 ] && exit 1
    # FDE_OPEN_FAIL_TARGET: EVERY open of that member fails (token + passphrase)
    [ -n "\${FDE_OPEN_FAIL_TARGET:-}" ] && [ "\$_fdt_tgt" = "\${FDE_OPEN_FAIL_TARGET}" ] && exit 1
    # FDE_OPEN_FAIL_TOKEN_TARGET: only the TOKEN unlock (the TPM-unsealed
    # sentinel passphrase) fails for that member — the keyslot-0 recovery
    # passphrase still succeeds (partial RAID1 unlock scenario)
    [ -n "\${FDE_OPEN_FAIL_TOKEN_TARGET:-}" ] && [ "\$_fdt_tgt" = "\${FDE_OPEN_FAIL_TOKEN_TARGET}" ] &&
        [ "\$_p" = "$TOKEN_PASS_B64" ] && exit 1
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

# ADR-20 guard terminal action: `reboot -f` into the firmware setup. The stub
# RECORDS argv and exits 0 (the hook must `exit 0` after an accepted reboot —
# on real firmware the machine resets and the hook never returns).
cat >"$BIN/reboot" <<EOF
#!/bin/sh
printf 'reboot %s\n' "\$*" >>'$LOG'
exit 0
EOF
chmod +x "$BIN/reboot"
# only attempted when the efivars dir is absent (best-effort mount); fails in
# the sandbox so the fail-closed guard path stays the one under test
cat >"$BIN/mount" <<EOF
#!/bin/sh
printf 'mount %s\n' "\$*" >>'$LOG'
exit 1
EOF
chmod +x "$BIN/mount"

# --- driver --------------------------------------------------------------------
run_hook() { # <stdin-file> [VAR=VAL ...]
    local stdin=$1
    shift
    env PATH="$BIN:$PATH" FDE_NEWROOT="$TMP/newroot" FDE_EXTRA_DIR="$TMP/extra" \
        FDE_CRYPTTAB="$TMP/crypttab" FDE_TMPDIR="$TMP/tmp" \
        FDE_EFIVARS_DIR="$TMP/efivars" \
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
# 0. artifact shape — the hook's initramfs staging path is pinned to a SINGLE
#    canonical constant, derived from the path hooks/mkinitfs/features.d/
#    alpine-fde.files actually lists (that file is the mkinitfs contract the
#    installer stages against; §8.2/ADR-13)
# =============================================================================
assert_file_exists() { # <desc> <path>
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (no such file: $2)"
    fi
}
# the canonical staging path: the one alpine-fde-unseal.sh line in the
# features.d list (absolute target-root path, no inline comment)
HOOK_INITRAMFS_PATH=$(grep -E '^[[:space:]]*/.*alpine-fde-unseal\.sh[[:space:]]*$' "$FILES" | head -n 1 | tr -d '[:space:]')
assert_file_exists "unseal hook exists" "$HOOK"
assert_eq "hook is executable" "1" "$([ -x "$HOOK" ] && echo 1 || echo 0)"
sh -n "$HOOK" >/dev/null 2>&1
assert_eq "hook parses under POSIX sh (busybox ash)" "0" "$?"
assert_eq "hook source never spawns a shell or rescue path" "" \
    "$(grep -nE '(^|[^a-zA-Z_-])(exec|rescue)([^a-zA-Z_-]|$)|sh +-c|ash +-c' "$HOOK" || true)"
assert_file_exists "features.d/alpine-fde.files exists" "$FILES"
assert_ne "features.d lists the hook staging path (canonical constant non-empty)" \
    "$HOOK_INITRAMFS_PATH" ""
assert_eq "features.d lists exactly one unseal-hook artifact path" "1" \
    "$(grep -cE '^[[:space:]]*/.*alpine-fde-unseal\.sh[[:space:]]*$' "$FILES")"
assert_not_contains "canonical staging path is the features.d-listed path (not the /etc/mkinitfs config dir)" \
    "$HOOK_INITRAMFS_PATH" "etc/mkinitfs"
for need in \
    "$HOOK_INITRAMFS_PATH" \
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
assert_eq "token success: policyauthorize admits the .pcrsig entry's pol" \
    "$(hex2bin "$POL" | sha256sum | awk '{print $1}')" "$(grep '^policyauthorize-pol' "$LOG" | awk '{print $2}')"
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
# 1b. token parked at a HIGH token-id (17) — the scan must cover the full
#     LUKS2 valid range 0..31 (§8.2 step 2); a token at id >=16 must still
#     unseal, not silently fall through to the passphrase prompt
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1" FDE_TEST_TOKEN_MIN_ID=17)
assert_rc "high token-id: hook rc 0" 0 "$rc"
assert_eq "high token-id: scan reaches id 17 and exports the token" "1" \
    "$(argv_count 'token export --token-id 17')"
assert_eq "high token-id: unseal still happens" "1" "$(argv_count '^tpm2_unseal')"
assert_eq "high token-id: exactly one open (no prompt fallback)" "1" "$(argv_count '^cryptsetup open')"
assert_eq "high token-id: no poweroff" "0" "$(argv_count '^poweroff')"
assert_contains "high token-id: marker moved to provisional-booted" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "provisional-booted"'

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
# 5. G4 ROLLBACK (§9.3, THE contract change): standing token sealed at UKI-A
#    enroll time (tpm2-signature covers ENROLL-time POL) + a drive .pcrsig
#    entry for retained UKI-B (entry pol=POL_B with its OWN release-key
#    signature, same authority). The I3 gate verifies the ENTRY's own
#    signature over the ENTRY's pol — NOT the token's signature — so the
#    rollback must PASS the gate, reach tpm2_unseal, and unlock with ZERO
#    prompts. The policyauthorize -i pin proves the TPM session admits the
#    ENTRY's pol (so a pol ≠ live digest still fail-closes in a real TPM via
#    PolicyPCR), and the openssl verify anchors the entry to the same
#    release authority whose keyName the sealed policy pins.
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1" FDE_TEST_TOKEN_FILE="$TMP/token.json" FDE_EXTRA_DIR="$TMP/extra-rollback")
assert_rc "rollback: hook rc 0 (entry-sig gate admits UKI-B's entry)" 0 "$rc"
assert_eq "rollback: unseal reached" "1" "$(argv_count '^tpm2_unseal')"
assert_eq "rollback: verifysignature ran on the ENTRY's sig+pol" "1" "$(argv_count '^tpm2_verifysignature')"
assert_eq "rollback: policyauthorize admits the ENTRY's pol (POL_B), not the enroll pol" \
    "$(hex2bin "$POL_B" | sha256sum | awk '{print $1}')" "$(grep '^policyauthorize-pol' "$LOG" | awk '{print $2}')"
assert_ne "rollback: admitted pol differs from the token's enroll pol (genuinely a different UKI)" \
    "$(hex2bin "$POL" | sha256sum | awk '{print $1}')" "$(grep '^policyauthorize-pol' "$LOG" | awk '{print $2}')"
assert_eq "rollback: exactly one open, zero prompts" "1" "$(argv_count '^cryptsetup open')"
assert_eq "rollback: no poweroff" "0" "$(argv_count '^poweroff')"
assert_contains "rollback: marker moved to provisional-booted" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "provisional-booted"'

# =============================================================================
# 5a. token tpm2-signature tamper (s13 sig-corrupt class) — INERT under the
#     entry-sig semantic: the gate consumes the DRIVE ENTRY's signature, so a
#     corrupted/foreign token signature cannot grant OR block unseal. The
#     valid entry (release-signed, matching live PCRs) still unlocks.
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1" FDE_TEST_TOKEN_FILE="$TMP/token-tampered.json")
assert_rc "token-sig tamper: hook rc 0 (inert metadata, unlock proceeds)" 0 "$rc"
assert_eq "token-sig tamper: unseal reached" "1" "$(argv_count '^tpm2_unseal')"
reset_leg
rc=$(run_hook "$TMP/stdin1" FDE_TEST_TOKEN_FILE="$TMP/token-sig-corrupt.json")
assert_rc "sig-corrupt: hook rc 0 (inert metadata, unlock proceeds)" 0 "$rc"
assert_eq "sig-corrupt: unseal reached" "1" "$(argv_count '^tpm2_unseal')"
assert_eq "sig-corrupt: no poweroff" "0" "$(argv_count '^poweroff')"

# =============================================================================
# 5b/5c. §6.1/§12 signing NEGATIVE CONTROL — PCR-selection mismatch between
#     the token's pinned selection and the /.extra .pcrsig entries, BOTH
#     directions. The approved policy digest must come from the .pcrsig entry
#     for EXACTLY the token's selection: a mismatch leaves `pol` unextracted,
#     the openssl gate refuses, and the TPM chain (incl. tpm2_unseal) is
#     never entered — bounded prompt path (fail-closed).
# =============================================================================
# 5b: token pins {7,11} but .pcrsig carries only [11]
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_TEST_TOKEN_FILE="$TMP/token-7-11.json" FDE_OPEN_FAIL=1)
assert_ne "selection mismatch {7,11}vs[11]: hook rc nonzero" "0" "$rc"
assert_eq "selection mismatch {7,11}vs[11]: pol extraction failed -> no verifysignature" "0" \
    "$(argv_count '^tpm2_verifysignature')"
assert_eq "selection mismatch {7,11}vs[11]: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "selection mismatch {7,11}vs[11]: bounded to 3 prompt attempts then poweroff once" \
    "3 1" "$(argv_count '^cryptsetup open') $(argv_count '^poweroff')"

# 5c (inverse): token pins {11} but .pcrsig carries only [7,11]
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_TEST_TOKEN_FILE="$TMP/token.json" FDE_EXTRA_DIR="$TMP/extra-7-11" FDE_OPEN_FAIL=1)
assert_ne "selection mismatch {11}vs[7,11]: hook rc nonzero" "0" "$rc"
assert_eq "selection mismatch {11}vs[7,11]: pol extraction failed -> no verifysignature" "0" \
    "$(argv_count '^tpm2_verifysignature')"
assert_eq "selection mismatch {11}vs[7,11]: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "selection mismatch {11}vs[7,11]: bounded to 3 prompt attempts then poweroff once" \
    "3 1" "$(argv_count '^cryptsetup open') $(argv_count '^poweroff')"

# =============================================================================
# 5d/5e/5f. §6.1/§12 signing NEGATIVE CONTROLS under the entry-sig semantic —
#     every entry-level tamper must STILL fail closed at the I3 gate (no
#     verifysignature, no unseal, bounded 3-strike prompt path):
#       5d forged entry signature (signed by an UNKNOWN/foreign key)
#       5e swapped /.extra public key (the keyName the sealed policy pins
#          would mismatch — user-space refuses the same entry too)
#       5f missing entry (well-formed .pcrsig, no entry for the selection)
# =============================================================================
# 5d: forged entry.sig
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_EXTRA_DIR="$TMP/extra-forged-sig" FDE_OPEN_FAIL=1)
assert_ne "forged entry sig: hook rc nonzero" "0" "$rc"
assert_eq "forged entry sig: openssl gate refused -> no verifysignature" "0" \
    "$(argv_count '^tpm2_verifysignature')"
assert_eq "forged entry sig: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "forged entry sig: bounded to 3 prompt attempts then poweroff once" \
    "3 1" "$(argv_count '^cryptsetup open') $(argv_count '^poweroff')"

# 5e: swapped /.extra pubkey (valid foreign key)
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_EXTRA_DIR="$TMP/extra-swapped-key" FDE_OPEN_FAIL=1)
assert_ne "swapped /.extra pubkey: hook rc nonzero" "0" "$rc"
assert_eq "swapped /.extra pubkey: entry sig refuses under the foreign key -> no verifysignature" "0" \
    "$(argv_count '^tpm2_verifysignature')"
assert_eq "swapped /.extra pubkey: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "swapped /.extra pubkey: bounded to 3 prompt attempts then poweroff once" \
    "3 1" "$(argv_count '^cryptsetup open') $(argv_count '^poweroff')"

# 5f: missing entry
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_EXTRA_DIR="$TMP/extra-missing-entry" FDE_OPEN_FAIL=1)
assert_ne "missing entry: hook rc nonzero" "0" "$rc"
assert_eq "missing entry: no verifysignature" "0" "$(argv_count '^tpm2_verifysignature')"
assert_eq "missing entry: tpm2_unseal never attempted" "0" "$(argv_count '^tpm2_unseal')"
assert_eq "missing entry: bounded to 3 prompt attempts then poweroff once" \
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
# 8b. RAID1 PARTIAL token unlock — the token open fails for member 2 only
#     (§10 "kernel re-signed, its enrollment missing/stale"): the failing
#     member MUST fall back into the same bounded 3-strike prompt loop (one
#     prompt shared across the remaining members) — never a silently
#     incomplete pool, never an interactive shell
# =============================================================================
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-rec" FDE_CRYPTTAB="$TMP/crypttab-raid1" FDE_OPEN_FAIL_TOKEN_TARGET=root2)
assert_rc "raid1 partial token: hook rc 0" 0 "$rc"
assert_contains "raid1 partial token: member 1 opened via the TPM token" \
    "$(grep '^cryptsetup open' "$LOG")" "/dev/disk/by-uuid/$UUID1"
assert_eq "raid1 partial token: member 2 recovered by ONE prompt" "1" \
    "$(argv_count '^cryptsetup-pass recovery-pass')"
assert_eq "raid1 partial token: member 2 attempted exactly twice (failed token + prompt)" "2" \
    "$(grep -c '^cryptsetup open --type luks --key-file - .* root2$' "$LOG" || true)"
assert_eq "raid1 partial token: 3 opens total (2 token attempts + 1 prompt)" "3" \
    "$(argv_count '^cryptsetup open')"
assert_eq "raid1 partial token: no poweroff" "0" "$(argv_count '^poweroff')"
assert_contains "raid1 partial token: marker written (pool complete)" \
    "$(cat "$TMP/newroot/etc/alpine-fde/install-state.json")" '"state": "provisional-booted"'

# --- 8c. same partial failure, but the passphrase never works: the bounded
#     strikes still end in exactly one forced poweroff (fail-closed, §8.2)
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-3bad" FDE_CRYPTTAB="$TMP/crypttab-raid1" FDE_OPEN_FAIL_TARGET=root2)
assert_ne "raid1 partial hard-fail: hook rc nonzero" "0" "$rc"
assert_eq "raid1 partial hard-fail: poweroff -f exactly once" "1" "$(argv_count '^poweroff')"
assert_contains "raid1 partial hard-fail: poweroff is forced" "$(grep '^poweroff' "$LOG")" "-f"
assert_eq "raid1 partial hard-fail: opens bounded (1 member token + 1 fail + 3 strikes)" "5" \
    "$(argv_count '^cryptsetup open')"
assert_eq "raid1 partial hard-fail: no state write after failing" "installed" \
    "$(sed -n 's/^  "state": "\(.*\)",\{0,1\}$/\1/p' "$TMP/newroot/etc/alpine-fde/install-state.json")"

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

# =============================================================================
# 10b. ADR-20 amended PRE-UNSEAL SECURE BOOT GUARD (§8.2 step 1) — the guard
#      runs FIRST: SB off / SetupMode=1 / unreadable efivarfs each BLOCK the
#      boot before ANY TPM op, ANY token work, ANY passphrase prompt. The
#      container is NEVER unsealed with Secure Boot off. The refusal prints
#      the notice + "Press Enter to reboot", requests boot-to-firmware-setup
#      via OsIndications (best-effort), and reboots (reboot -f exactly once,
#      NO poweroff, NO state write). Every other leg below runs under the
#      SB-on default fixture — the provisional PCR-11-only token is only ever
#      usable with Secure Boot on.
# =============================================================================

# --- 10b-1. SecureBoot=0 -> guard block + reboot into firmware setup ---------
reset_leg
write_state installed
printf 'unused\n' >"$TMP/stdin-guard"
rc=$(run_hook "$TMP/stdin-guard" FDE_EFIVARS_DIR="$TMP/efivars-sb-off")
assert_rc "SB guard: hook exits 0 after the accepted reboot" 0 "$rc"
assert_contains "SB guard: refusal sentinel names the pre-unseal guard" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard)"
assert_contains "SB guard: the live efivarfs reading is printed" \
    "$(cat "$TMP/out.log")" "secureboot=0"
assert_contains "SB guard: Press-Enter confirmation prompt" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard_enter)"
assert_contains "SB guard: the container was NOT unlocked (no passphrase requested)" \
    "$(cat "$TMP/out.log")" "the container was NOT unlocked"
assert_contains "SB guard: reboot sentinel" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard_reboot)"
assert_eq "SB guard: reboot -f exactly once (into the firmware setup)" "1" \
    "$(argv_count '^reboot ')"
assert_contains "SB guard: reboot is forced" "$(grep '^reboot ' "$LOG")" "-f"
assert_eq "SB guard: OsIndications boot-to-firmware-setup requested" "1" \
    "$(grep -c 'OsIndications: boot-to-firmware-setup requested' "$TMP/out.log" || true)"
assert_eq "SB guard: OsIndications var written (u64 LE bit-1 payload)" "02" \
    "$(dd if="$TMP/efivars-sb-off/OsIndications-8be4df61-93ca-11d2-aa0d-00e098032b8c" \
        bs=1 skip=4 count=1 2>/dev/null | od -An -v -tx1 | tr -d ' \n')"
assert_eq "SB guard: NO pcrextend (the guard precedes §8.2 step 2)" "0" \
    "$(argv_count '^tpm2_pcrextend')"
assert_eq "SB guard: NO token export, NO open, NO unseal — the container is NEVER unsealed" \
    "0 0 0" "$(argv_count 'token export') $(argv_count '^cryptsetup open') $(argv_count '^tpm2_unseal')"
assert_eq "SB guard: NO poweroff (the terminal action is the reboot)" "0" \
    "$(argv_count '^poweroff')"
assert_eq "SB guard: NO passphrase prompt (the fallback is RETRACTED under SB off)" \
    "0" "$(grep -c 'enter the recovery passphrase' "$TMP/out.log" || true)"
assert_eq "SB guard: state file NOT rewritten" "installed" \
    "$(sed -n 's/^  "state": "\(.*\)",\{0,1\}$/\1/p' "$TMP/newroot/etc/alpine-fde/install-state.json")"

# --- 10b-2. SecureBoot=1 but SetupMode=1 (keys not in final state) -> block ---
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-guard" FDE_EFIVARS_DIR="$TMP/efivars-setupmode")
assert_rc "SB guard (setup mode): hook exits 0 after the accepted reboot" 0 "$rc"
assert_contains "SB guard (setup mode): refusal sentinel" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard)"
assert_contains "SB guard (setup mode): the live reading names setup_mode=1" \
    "$(cat "$TMP/out.log")" "setup_mode=1"
assert_eq "SB guard (setup mode): reboot -f exactly once" "1" "$(argv_count '^reboot ')"
assert_eq "SB guard (setup mode): NO unseal work" "0" "$(argv_count '^tpm2_pcrextend')"

# --- 10b-3. unreadable efivarfs (no variables) -> fail CLOSED ----------------
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-guard" FDE_EFIVARS_DIR="$TMP/efivars-empty")
assert_rc "SB guard (unreadable): hook exits 0 after the accepted reboot" 0 "$rc"
assert_contains "SB guard (unreadable): refusal sentinel (fail-closed)" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard)"
assert_contains "SB guard (unreadable): the reading is reported unreadable" \
    "$(cat "$TMP/out.log")" "unreadable"
assert_eq "SB guard (unreadable): NO unseal work" "0" "$(argv_count '^tpm2_pcrextend')"

# --- 10b-4. efivars dir absent entirely -> best-effort mount, still closed ---
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin-guard" FDE_EFIVARS_DIR="$TMP/efivars-absent")
assert_rc "SB guard (absent dir): hook exits 0 after the accepted reboot" 0 "$rc"
assert_contains "SB guard (absent dir): the efivarfs mount was attempted (best-effort)" \
    "$(cat "$LOG")" "mount -t efivarfs"
assert_contains "SB guard (absent dir): refusal sentinel (fail-closed)" \
    "$(cat "$TMP/out.log")" "$(sentinel_of unseal_sb_guard)"
assert_eq "SB guard (absent dir): NO unseal work" "0" "$(argv_count '^tpm2_pcrextend')"

# --- 10b-5. SecureBoot=1 + SetupMode=0 -> the guard PASSES and boot proceeds --
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1")
assert_rc "SB guard pass: hook rc 0 (verified boot confirmed)" 0 "$rc"
assert_contains "SB guard pass: the pass line is printed" \
    "$(cat "$TMP/out.log")" "secureboot=1 setup_mode=0"
assert_eq "SB guard pass: NO reboot" "0" "$(argv_count '^reboot ')"
assert_eq "SB guard pass: the pcrextend (§8.2 step 2) runs after the guard" "1" \
    "$(argv_count '^tpm2_pcrextend')"
assert_eq "SB guard pass: the token path unseals" "1" "$(argv_count '^tpm2_unseal')"

# =============================================================================
# 11. REAL-TPM regression: the unseal session chain must complete against a
#     REAL TPM (tpm2-tools 5.8 / swtpm). Root cause of the s15 boot-3 token
#     unlock failure: `tpm2_loadexternal -C n` loaded the verifying key into
#     the NULL hierarchy, where TPM2_VerifySignature succeeds but issues NO
#     validation ticket ("The NULL hierarchy doesn't produce a validation
#     ticket"). Without the ticket `tpm2_policyauthorize` aborts CLIENT-SIDE
#     ("Could not load verification ticket file") before TPM2_PolicyAuthorize
#     is ever sent, `tpm2_unseal` never runs, and the hook falls to the
#     bounded passphrase path on EVERY boot — deterministic, PCR-state
#     independent (the swtpm command trace shows PolicyPCR rc=0, then
#     session save/load teardown including ContextSave 0x910
#     TPM_RC_REFERENCE_H0 from the aborted tools, and NO TPM2_PolicyAuthorize
#     at all). The hook now pins -C o (lib/seal.sh seal_unseal parity): the
#     owner hierarchy issues the ticket, PolicyAuthorize admits the approved
#     policy, and the unseal completes.
# =============================================================================

# --- 11a. hermetic argv pin: the verifying key rides the OWNER hierarchy ----
reset_leg
write_state installed
rc=$(run_hook "$TMP/stdin1")
assert_rc "owner-hierarchy pin: hook rc 0" 0 "$rc"
assert_contains "owner-hierarchy pin: loadexternal uses -C o" \
    "$(grep '^tpm2_loadexternal' "$LOG")" "-C o"
assert_not_contains "owner-hierarchy pin: loadexternal never uses NULL (-C n)" \
    "$(grep '^tpm2_loadexternal' "$LOG")" "-C n"
assert_eq "owner-hierarchy pin: unseal still reached" "1" "$(argv_count '^tpm2_unseal')"

# --- 11b. live leg: real swtpm + real tpm2-tools (skipped without swtpm) -----
run_live_leg() {
    # shellcheck source=../lib/swtpm-fixture.sh
    source "$HERE/../lib/swtpm-fixture.sh"
    # shellcheck source=../../lib/common.sh
    source "$REPO/lib/common.sh"
    # shellcheck source=../../lib/policy.sh
    source "$REPO/lib/policy.sh"

    LIVE=$TMP/live
    LIVEBIN=$LIVE/bin
    mkdir -p "$LIVEBIN" "$LIVE/extra" "$LIVE/tmp" "$LIVE/newroot/etc/alpine-fde"
    TPMDIR=$TMP/live-swtpm
    if ! swtpm_start "$TPMDIR"; then
        _fail "live leg: swtpm did not start"
        return 0
    fi
    tpm() { TPM2TOOLS_TCTI="$SWTPM_TCTI" tpm2 "$@"; }
    hex2bin() { # stdin hex -> raw bytes (busybox-safe, mirrors the hook)
        LC_ALL=C awk '{
            h = "0123456789abcdef"
            for (i = 1; i <= length($0); i += 2)
                printf "%c", (index(h, tolower(substr($0, i, 1))) - 1) * 16 + (index(h, tolower(substr($0, i + 1, 1))) - 1)
        }'
    }
    # boot-shape PCR state: PCR 7 carries a firmware digest; PCR 11 is ZERO
    # here (fresh boot) — the seal must predict the POST-enter-initrd value
    # the hook's step-1 extend produces, exactly like lib/cmd/pcrsign does.
    tpm pcrextend "7:sha256=1111111111111111111111111111111111111111111111111111111111111111" >/dev/null
    tpm pcrread -Q -o "$LIVE/d7.bin" sha256:7
    D7=$(od -An -v -tx1 "$LIVE/d7.bin" | tr -d ' \n')
    PH11=$(printf 'enter-initrd' | sha256sum | awk '{print $1}')
    D11=$(printf '%064d%s' 0 "$PH11" | hex2bin | openssl dgst -sha256 -hex | awk '{print $NF}')
    POLHEX=$(policy_digest "$D7" "$D11")
    printf '%s' "$POLHEX" | hex2bin >"$LIVE/pol.bin"

    # release-key signature over the approved policy digest (the .pcrsig `pol`)
    openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$LIVE/sig.bin" "$LIVE/pol.bin"
    SIGB64LIVE=$(openssl base64 -A <"$LIVE/sig.bin")

    # release-key Name + the PolicyAuthorize sealed-object policy digest
    tpm loadexternal -C n -G rsa -u "$KEYDIR/release.pub" -c "$LIVE/kn.ctx" -n "$LIVE/kn.name" >/dev/null
    tpm flushcontext "$LIVE/kn.ctx" >/dev/null 2>&1 || tpm flushcontext -t >/dev/null 2>&1 || :
    KNHEX=$(od -An -v -tx1 "$LIVE/kn.name" | tr -d ' \n')
    SEALEDHEX=$(policy_sealed_digest "$KNHEX")
    printf '%s' "$SEALEDHEX" | hex2bin >"$LIVE/sealedpol.bin"

    # seal a secret under the authorized policy (mirrors seal_create)
    printf 'live-tpm-volume-secret\n' >"$LIVE/secret"
    tpm flushcontext -t >/dev/null 2>&1 || :
    tpm createprimary -C o -g sha256 -G rsa -c "$LIVE/primary.ctx" >/dev/null
    tpm create -C "$LIVE/primary.ctx" -g sha256 -i "$LIVE/secret" \
        -L "$LIVE/sealedpol.bin" -u "$LIVE/seal.pub" -r "$LIVE/seal.priv" >/dev/null
    tpm flushcontext -t >/dev/null 2>&1 || :
    BLOBB64=$(cat "$LIVE/seal.priv" "$LIVE/seal.pub" | openssl base64 -A)

    cp "$KEYDIR/release.pub" "$LIVE/extra/tpm2-pcr-public-key.pem"
    # the guard's efivarfs seam is pinned to the SB-on fixture — the HOST's
    # real efivarfs state must never decide a unit leg's outcome
    mk_efivars "$LIVE/efivars" 1 0
    printf '{"sha256":[{"pcrs":[7,11],"pkfp":"live","pol":"%s","sig":"%s"}]}\n' \
        "$POLHEX" "$SIGB64LIVE" >"$LIVE/extra/tpm2-pcr-signature.json"
    printf '{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":"%s","tpm2-pcrs":[7,11],"tpm2-pcr-bank":"sha256","tpm2-signature":"%s"}' \
        "$BLOBB64" "$SIGB64LIVE" >"$LIVE/token.json"
    printf '%s\n' "root UUID=$UUID1 none luks,tpm2-device=auto" >"$LIVE/crypttab"
    write_state installed
    mv "$TMP/newroot/etc/alpine-fde/install-state.json" "$LIVE/newroot/etc/alpine-fde/install-state.json"

    # cryptsetup stub (LUKS itself is out of scope; the TPM chain is what is
    # under test) + a poweroff that FAILS the leg if ever reached
    cat >"$LIVEBIN/cryptsetup" <<EOF
#!/bin/sh
if [ "\$1" = "token" ]; then cat "$LIVE/token.json"; exit 0; fi
if [ "\$1" = "open" ]; then printf 'opened\n' >"$LIVE/opened"; exit 0; fi
exit 1
EOF
    cat >"$LIVEBIN/poweroff" <<EOF
#!/bin/sh
printf 'poweroff reached\n' >"$LIVE/poweroff"; exit 1
EOF
    chmod +x "$LIVEBIN/cryptsetup" "$LIVEBIN/poweroff"

    env PATH="$LIVEBIN:$PATH" TPM2TOOLS_TCTI="$SWTPM_TCTI" \
        FDE_NEWROOT="$LIVE/newroot" FDE_EXTRA_DIR="$LIVE/extra" \
        FDE_CRYPTTAB="$LIVE/crypttab" FDE_TMPDIR="$LIVE/tmp" \
        FDE_EFIVARS_DIR="$LIVE/efivars" \
        sh "$HOOK" </dev/null >"$LIVE/hook.out" 2>&1
    LIVE_RC=$?
    assert_rc "live swtpm: hook rc 0" 0 "$LIVE_RC"
    assert_contains "live swtpm: phase extend ran" \
        "$(cat "$LIVE/hook.out")" "extended 'enter-initrd' into PCR 11"
    assert_not_contains "live swtpm: NO TPM-refusal fallback sentinel" \
        "$(cat "$LIVE/hook.out")" "the TPM refused the sealed blob"
    assert_not_contains "live swtpm: NO recovery-passphrase fallback" \
        "$(cat "$LIVE/hook.out")" "recovery passphrase"
    assert_file_exists "live swtpm: cryptsetup open ran (token unlock)" "$LIVE/opened"
    if [ -e "$LIVE/poweroff" ]; then
        _fail "live swtpm: poweroff reached (fail-closed triggered — chain failed)"
    else
        _pass "live swtpm: fail-closed poweroff never reached (negative control)"
    fi
    swtpm_stop "$TPMDIR" >/dev/null 2>&1 || :
}
if command -v swtpm >/dev/null 2>&1 && command -v tpm2_startauthsession >/dev/null 2>&1; then
    run_live_leg
else
    _pass "live leg skipped (swtpm/tpm2-tools not available on this host)"
fi

finish
