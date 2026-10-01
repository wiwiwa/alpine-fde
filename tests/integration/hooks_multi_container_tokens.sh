#!/usr/bin/env bash
# tests/integration/hooks_multi_container_tokens.sh — bcache-multi per-member
# token unseal (R640 2026-10-01). The §8.2 token path was built on the RAID1
# sharing assumption: ONE token unsealed, its secret replayed across EVERY
# crypttab member ("RAID1: the unsealed passphrase is reused across all
# members"). The bcache-multi topology (two INDEPENDENT LUKS2 containers, each
# with its OWN random volume passphrase sealed under its OWN token) breaks
# that: root1's unsealed secret legitimately fails to open root2, and root2
# falls into the recovery-prompt loop on EVERY boot — the R640 2026-10-01
# first-boot finding (root1 passwordless via the TPM token, root2 prompting).
#
# This test pins the FIXED semantics: per-member token scan + unseal. Each
# member's OWN token is exported, gated (I3), unsealed, and opened with ITS
# OWN secret; members whose token JSON is byte-identical to an
# already-unsealed member (true RAID1 sharing) still reuse the first unseal.
# The recovery-prompt path keeps its shared-credential semantics (keyslot 0
# passphrase IS common across members — the §9.1 ceremony types it once).
#
# Harness parity with hooks_mkinitfs_unseal.sh: real hook, stubbed TPM/cryptsetup
# collaborators recording argv; openssl/sha256sum/awk stay real.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../unit/lib.sh
source "$HERE/../unit/lib.sh"

HOOK=$REPO/hooks/mkinitfs/alpine-fde-unseal.sh

TMP=$(mktemp -d /tmp/alpine-fde-multitok.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

BIN=$TMP/bin
LOG=$TMP/argv.log
: >"$LOG"
mkdir -p "$BIN" "$TMP/extra" "$TMP/tmp" "$TMP/newroot/etc/alpine-fde" "$TMP/dev"

# --- fixtures -------------------------------------------------------------------
KEYDIR=$REPO/fixtures/keys

hex2bin() {
    printf '%s' "$1" | LC_ALL=C awk '{
        h = "0123456789abcdef"
        for (i = 1; i <= length($0); i += 2)
            printf "%c", (index(h, tolower(substr($0, i, 1))) - 1) * 16 + (index(h, tolower(substr($0, i + 1, 1))) - 1)
    }'
}

POL=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
hex2bin "$POL" >"$TMP/pol.bin"
SIGB64=$(openssl dgst -sha256 -sign "$KEYDIR/release.pem" "$TMP/pol.bin" | openssl base64 -A)
PHASH=$(printf 'enter-initrd' | sha256sum | awk '{print $1}')

# per-member secrets: distinct per-container volume passphrases (the R640
# post-reseal reality — each container's token seals its own random)
SECRET_A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SECRET_B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
SECRET_A_B64=$(printf '%s' "$SECRET_A" | openssl base64 -A)
SECRET_B_B64=$(printf '%s' "$SECRET_B" | openssl base64 -A)
# the shared keyslot-0 recovery credential (the one legitimately common secret)
RECOVERY=7265636f766572792d70617373
RECOVERY_TXT=recovery-pass

# the drive .pcrsig entry: ONE [7,11] entry (both reseals pin the same policy)
cp "$KEYDIR/release.pub" "$TMP/extra/tpm2-pcr-public-key.pem"
cat >"$TMP/extra/tpm2-pcr-signature.json" <<EOF
{
  "sha256": [
    {"pcrs": [7, 11], "pkfp": "deadbeefcafe", "pol": "$POL", "sig": "$SIGB64"}
  ]
}
EOF

# per-member tokens: same schema, same policy, DIFFERENT sealed blobs (each
# container's own secret lives behind its own token)
make_token() { # <outfile> <blob-b64>
    cat >"$1" <<EOF
{
  "type": "systemd-tpm2",
  "keyslots": ["1"],
  "tpm2-blob": "$2",
  "tpm2-pcrs": [7, 11],
  "tpm2-pcr-bank": "sha256",
  "tpm2-pubkey": "cHVi",
  "tpm2-signature": "$SIGB64"
}
EOF
}
make_token "$TMP/token-a.json" "AAJhYg=="
make_token "$TMP/token-b.json" "AAJhYw=="

UUID1=22222222-2222-2222-2222-222222222222
UUID2=33333333-3333-3333-3333-333333333333
printf '%s\n' \
    "root1 UUID=$UUID1 none luks,tpm2-device=auto,password-cache=yes" \
    "root2 UUID=$UUID2 none luks,tpm2-device=auto,password-cache=yes" >"$TMP/crypttab-2"

# efivarfs: SB on, keys final (ADR-20 guard passes)
FW_GUID='8be4df61-93ca-11d2-aa0d-00e098032b8c'
mkdir -p "$TMP/efivars"
printf '\007\000\000\000\001' >"$TMP/efivars/SecureBoot-$FW_GUID"
printf '\007\000\000\000\000' >"$TMP/efivars/SetupMode-$FW_GUID"

# the prompt loop's stdin: the recovery passphrase (fed once; the loop's
# cached-reuse covers any second prompt in the CURRENT shared semantics)
printf '%s\n' "$RECOVERY_TXT" >"$TMP/stdin-rec"

# --- stubs (record full argv) ------------------------------------------------------
# tpm2 verbs: record; unseal emits secrets from a FIFO seq (1st -> A, 2nd -> B)
for v in tpm2_pcrextend tpm2_startauthsession tpm2_policypcr tpm2_policyauthorize \
    tpm2_loadexternal tpm2_verifysignature tpm2_createprimary tpm2_load \
    tpm2_flushcontext; do
    cat >"$BIN/$v" <<EOF
#!/bin/sh
printf '$v %s\n' "\$*" >>'$LOG'
prev=
for a in "\$@"; do
    case "\$prev" in
        -t | -n | -S | -c) : >"\$a" ;;
        -i) : >"\$a" ;;
    esac
    prev=\$a
done
exit 0
EOF
    chmod +x "$BIN/$v"
done

printf '%s\n%s\n' "$SECRET_A" "$SECRET_B" >"$TMP/unseal.seq"
cat >"$BIN/tpm2_unseal" <<EOF
#!/bin/sh
printf 'tpm2_unseal %s\n' "\$*" >>'$LOG'
prev=
for a in "\$@"; do
    case "\$prev" in
        -o)
            # pop the next secret from the seq file (1st unseal -> A, 2nd -> B)
            s=\$(head -n 1 '$TMP/unseal.seq' 2>/dev/null)
            [ -n "\$s" ] && sed -i '1d' '$TMP/unseal.seq'
            printf '%s' "\${s:-$SECRET_A}" >"\$a"
            ;;
    esac
    prev="\$a"
done
exit 0
EOF
chmod +x "$BIN/tpm2_unseal"

cat >"$BIN/cryptsetup" <<EOF
#!/bin/sh
printf 'cryptsetup %s\n' "\$*" >>'$LOG'
if [ "\$1" = "token" ]; then
    # per-member enrollment: the device path decides WHICH token stands
    case "\$*" in
        *$UUID1*) cat "$TMP/token-a.json" ;;
        *$UUID2*) cat "$TMP/token-b.json" ;;
        *) exit 1 ;;
    esac
    exit 0
fi
if [ "\$1" = "open" ]; then
    IFS= read -r _p || :
    printf 'cryptsetup-pass %s\n' "\$_p" >>'$LOG'
    _fdt_tgt=
    for _fdt_a in "\$@"; do _fdt_tgt=\$_fdt_a; done
    # per-member volume passphrase: each container opens ONLY with its own
    # secret (the bcache-multi reality the RAID1 sharing assumption missed) —
    # except the keyslot-0 recovery passphrase, which IS shared (raw on the
    # prompt path per the main harness's 'cryptsetup-pass recovery-pass' idiom)
    case "\$_fdt_tgt" in
        root1) [ "\$_p" = "$SECRET_A_B64" ] && exit 0
               [ "\$_p" = "$RECOVERY_TXT" ] && exit 0 ;;
        root2) [ "\$_p" = "$SECRET_B_B64" ] && exit 0
               [ "\$_p" = "$RECOVERY_TXT" ] && exit 0
               # L3 seam: identical tokens seal the SAME secret (true RAID1)
               [ "\${FDE_TEST_RAID1_SHARED:-0}" = 1 ] && [ "\$_p" = "$SECRET_A_B64" ] && exit 0 ;;
    esac
    # L4 seam: the TOKEN-secret open fails for that member — the keyslot-0
    # recovery passphrase still succeeds (partial-unlock scenario)
    [ -n "\${FDE_OPEN_FAIL_TOKEN_TARGET:-}" ] && [ "\$_fdt_tgt" = "\${FDE_OPEN_FAIL_TOKEN_TARGET:-}" ] &&
        [ "\$_p" != "$RECOVERY_TXT" ] && exit 1
    printf 'cryptsetup-secret-mismatch %s\\n' "\$_fdt_tgt" >>'$LOG'
    exit 1
fi
exit 1
EOF
chmod +x "$BIN/cryptsetup"

cat >"$BIN/poweroff" <<'EOF'
#!/bin/sh
printf 'poweroff %s\n' "$*" >>"$LOG"
exit 0
EOF
chmod +x "$BIN/poweroff"

cat >"$BIN/nlplug-findfs" <<'EOF'
#!/bin/sh
printf 'nlplug-findfs %s\n' "$*" >>"$LOG"
_spec=
for _a in "$@"; do
    case $_a in UUID=*) _spec=${_a#UUID=} ;; esac
done
[ -n "$_spec" ] || exit 1
_dir="${FDE_DISK_BY_UUID_DIR:-/dev/disk/by-uuid}"
mkdir -p "$_dir" 2>/dev/null || :
_node="$_dir/$_spec"
: >"$_node" 2>/dev/null || :
printf '%s\n' "$_node"
exit 0
EOF
chmod +x "$BIN/nlplug-findfs"

run_hook() { # <stdin-file> [VAR=VAL ...]
    local stdin=$1
    shift
    env PATH="$BIN:$PATH" FDE_NEWROOT="$TMP/newroot" FDE_EXTRA_DIR="$TMP/extra" \
        FDE_CRYPTTAB="$TMP/crypttab-2" FDE_TMPDIR="$TMP/tmp" \
        FDE_EFIVARS_DIR="$TMP/efivars" \
        FDE_NLPLUG_FINDFS="$BIN/nlplug-findfs" \
        FDE_DEV_DIR="$TMP/dev" \
        "$@" \
        sh "$HOOK" <"$stdin" >"$TMP/out.log" 2>&1
    echo $?
}

argv_count() { # <pattern>
    grep -c "$1" "$LOG" 2>/dev/null || :
}

reset_leg() {
    : >"$LOG"
    printf '%s\n%s\n' "$SECRET_A" "$SECRET_B" >"$TMP/unseal.seq"
    mkdir -p "$TMP/newroot/etc/alpine-fde"
}

# =============================================================================
# L1 — bcache-multi DISTINCT tokens: per-member token scan + unseal. Each
# member's own token is exported, gated (I3), unsealed, and opened with its
# own secret; NO prompt loop is entered. (This is the R640 2026-10-01 fix:
# the pre-fix shared-secret hook replayed root1's secret at root2 and fell
# into the 3-strike prompt loop on every boot.)
# =============================================================================
reset_leg
rc=$(run_hook /dev/null)
assert_rc "multi: hook rc 0" 0 "$rc"
assert_eq "multi: TWO unseals (one per member)" "2" "$(argv_count '^tpm2_unseal')"
assert_eq "multi: both members opened" "2" "$(argv_count '^cryptsetup open')"
assert_contains "multi: root1 opened with SECRET_A" \
    "$(grep '^cryptsetup-pass' "$LOG")" "$SECRET_A_B64"
assert_contains "multi: root2 opened with SECRET_B" \
    "$(grep '^cryptsetup-pass' "$LOG")" "$SECRET_B_B64"
assert_eq "multi: NO secret mismatch" "0" \
    "$(grep -c 'cryptsetup-secret-mismatch' "$LOG" || true)"
assert_eq "multi: NO passphrase prompt (stdin untouched)" "0" \
    "$(argv_count "^cryptsetup-pass $RECOVERY_TXT")"
assert_eq "multi: no poweroff" "0" "$(argv_count '^poweroff')"

# =============================================================================
# L2 — true-RAID1 fast path: byte-identical tokens on both members reuse the
# FIRST unseal (no second TPM round-trip), both members still opened.
# =============================================================================
reset_leg
cp "$TMP/token-a.json" "$TMP/token-b.json"
rc=$(run_hook /dev/null FDE_TEST_RAID1_SHARED=1)
assert_rc "raid1-identical: hook rc 0" 0 "$rc"
assert_eq "raid1-identical: ONE unseal (identical-token reuse)" "1" "$(argv_count '^tpm2_unseal')"
assert_eq "raid1-identical: both members opened" "2" "$(argv_count '^cryptsetup open')"
assert_eq "raid1-identical: no poweroff" "0" "$(argv_count '^poweroff')"

# =============================================================================
# L3 — partial token unlock in the multi-container world: root2's token-
# secret open fails (§10 "kernel re-signed, its enrollment missing/stale") —
# root2 recovers via the shared keyslot-0 passphrase; root1 stays on its
# token. Never a silently incomplete pool.
# =============================================================================
reset_leg
rc=$(run_hook "$TMP/stdin-rec" FDE_OPEN_FAIL_TOKEN_TARGET=root2)
assert_rc "partial: hook rc 0" 0 "$rc"
assert_eq "partial: root1 token + root2 token attempt + root2 prompt" "3" \
    "$(argv_count '^cryptsetup open')"
assert_eq "partial: root2 recovered by ONE prompt" "1" \
    "$(argv_count "^cryptsetup-pass $RECOVERY_TXT")"
assert_eq "partial: no poweroff" "0" "$(argv_count '^poweroff')"

finish
