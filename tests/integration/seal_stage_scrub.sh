#!/usr/bin/env bash
# tests/integration/seal_stage_scrub.sh — §11 I1 seal/enroll staging hygiene:
#   * the staging root is TMPFS by construction: with ALPINE_FDE_TMPDIR unset
#     the seal staging default resolves under /dev/shm (the repo convention) —
#     NEVER /tmp, because the staging may hold the random volume passphrase
#   * seal_scrub is the seal-owned scrub helper: zeroize + unlink the staged
#     passphrase, remove the seal work dir
#   * after the REAL enroll flow (enrl_run with real seal ops vs swtpm,
#     file-backed LUKS2) the whole test tree holds ZERO leftover staging
#     artifacts (alpine-fde-seal-pass.* / alpine-fde-seal* / alpine-fde-enroll.*)
#   * seal_upgrade_token scrubs its OWN staging (passphrase + blob halves +
#     work dir) as soon as the caller's post-asserts no longer need it — on
#     SUCCESS and on injected-failure paths (choreography refusal included)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"
# shellcheck source=../../lib/cmd/enroll-tpm.sh
source "$REPO/lib/cmd/enroll-tpm.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

# TMP is the TEST TREE scanned for leftovers; ALPINE_FDE_TMPDIR binds every
# staging root to it so the scan is complete (nothing escapes to /tmp or /dev/shm)
TMP=$(mktemp -d /tmp/alpine-fde-stage-scrub.XXXXXX)
cleanup() {
    swtpm_cleanup_all
    rm -rf "$TMP"
}
trap cleanup EXIT
mkdir -p "$TMP/tmp"
ALPINE_FDE_TMPDIR=$TMP/tmp

# hermetic ADR-16-conformant release key (the enroll path refuses RSA < 3072)
KEYDIR=$TMP/keys3072
mkdir -p "$KEYDIR"
openssl genrsa -out "$KEYDIR/release.pem" 3072 2>/dev/null
openssl pkey -in "$KEYDIR/release.pem" -pubout -out "$KEYDIR/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEYDIR/release.pem" -out "$KEYDIR/release.crt" \
    -subj /CN=alpine-fde-stage-scrub 2>/dev/null
[ -s "$KEYDIR/release.pem" ] && [ -s "$KEYDIR/release.pub" ] || {
    echo "FAIL: release key fixture did not generate" >&2
    exit 1
}

TPMDIR=$TMP/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
ALPINE_FDE_TCTI=$SWTPM_TCTI
export ALPINE_FDE_TCTI
swtpm_pcrextend "$TPMDIR" 7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
swtpm_pcrextend "$TPMDIR" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc
pcr_hex() {
    tpm pcrread -Q -o "$TMP/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$TMP/pcr.bin" | tr -d ' \n'
}
D7=$(pcr_hex 7)
D11=$(pcr_hex 11)
[ ${#D7} -eq 64 ] && [ ${#D11} -eq 64 ] || {
    echo "FAIL: could not read live PCR values" >&2
    exit 1
}

# signed .pcrsig fixtures over the live PCRs (reused by every leg; each seal
# re-verifies the signature against the FRESH live-PCR digest)
policy_sign_json "$D7" "$D11" "$KEYDIR/release.pem" "$KEYDIR/release.pub" "$TMP/pcrsig711.json"
[ -s "$TMP/pcrsig711.json" ] || {
    echo "FAIL: {7,11} .pcrsig fixture did not sign" >&2
    exit 1
}

mk_luks() { # PATH — fresh file-backed LUKS2 container, recovery slot 0
    truncate -s 24M "$1"
    printf 'slot0-recovery-passphrase-0123456789ab' >"$TMP/k0"
    cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$TMP/k0" "$1" 2>/dev/null
}
# the enroll flow authorizes luksAddKey with the recovery slot 0 passphrase
export ALPINE_FDE_LUKS_KEYFILE=$TMP/k0

# leftover-staging scan: the whole test tree must hold ZERO seal/enroll
# staging artifacts (the random volume passphrase above all)
leftovers() {
    find "$TMP" \( -name 'alpine-fde-seal-pass.*' -o -name 'alpine-fde-seal*' \
        -o -name 'alpine-fde-enroll.*' \) -print 2>/dev/null
}
assert_no_leftovers() { # DESC
    assert_eq "$1 (zero leftover staging artifacts in the test tree)" "" "$(leftovers)"
}

# --- 1. staging root: tmpfs by construction -------------------------------------------
assert_eq "staging root with ALPINE_FDE_TMPDIR unset -> /dev/shm (tmpfs, never /tmp)" \
    "/dev/shm" "$(unset ALPINE_FDE_TMPDIR; seal_stage_dir 2>/dev/null)"
assert_eq "staging root honors ALPINE_FDE_TMPDIR" "$TMP/tmp" "$(seal_stage_dir)"
# the /tmp default is BANNED from the seal/enroll staging sites (I1: the
# staging may hold the random volume passphrase) — no "${TMPDIR:-/tmp}"
# default may remain in the seal/enroll staging code
assert_eq "no /tmp-defaulted staging left in seal.sh / enroll-tpm.sh" "0" \
    "$(grep -c 'TMPDIR:-/tmp' "$REPO/lib/seal.sh" "$REPO/lib/cmd/enroll-tpm.sh" | awk -F: '{ s += $NF } END { print s+0 }')"

# --- 2. the REAL enroll flow (enrl_run, real seal ops) scrubs on success ---------------
LUKS1=$TMP/luks-enroll.img
mk_luks "$LUKS1"
ENRL_RC=0
ENRL_OUT=$(enrl_run b "$KEYDIR/release.pub" "$LUKS1" 0 "$TMP/pcrsig711.json" 2>&1) || ENRL_RC=$?
assert_eq "real enroll flow rc 0" "0" "$ENRL_RC"
assert_no_leftovers "enroll flow success"

# --- 3. enroll flow with an INJECTED FAILURE (luksAddKey refuses) ----------------------
REAL_CS=$(command -v cryptsetup)
cat >"$TMP/cs-no-addkey" <<EOF
#!/bin/sh
[ "\$1" = "luksAddKey" ] && exit 1
exec "$REAL_CS" "\$@"
EOF
chmod +x "$TMP/cs-no-addkey"
LUKS2=$TMP/luks-enroll-fail.img
mk_luks "$LUKS2"
ALPINE_FDE_CRYPTSETUP=$TMP/cs-no-addkey
ENRL2_RC=0
ENRL2_OUT=$(enrl_run b "$KEYDIR/release.pub" "$LUKS2" 0 "$TMP/pcrsig711.json" 2>&1) || ENRL2_RC=$?
assert_eq "injected luksAddKey failure -> enroll flow rc 1" "1" "$ENRL2_RC"
unset ALPINE_FDE_CRYPTSETUP
assert_no_leftovers "enroll flow failure"

# --- 4. seal_upgrade_token scrubs its OWN staging on success ---------------------------
# (before the fix the staged random volume passphrase and the seal work dir
# with the blob halves SURVIVED the upgrade — the caller had to glob-scrub)
LUKS3=$TMP/luks-upgrade.img
mk_luks "$LUKS3"
UPG=$TMP/upg-token.json
rm -f "$UPG"
UPG_RC=0
( seal_upgrade_token "$KEYDIR" "$LUKS3" "$TMP/pcrsig711.json" "$UPG" "$TMP/k0" ) >"$TMP/upg.out" 2>&1 ||
    UPG_RC=$?
assert_rc "seal_upgrade_token rc 0" 0 "$UPG_RC"
UPGPOST=$TMP/upg-post.json
token_dump "$LUKS3" "$UPGPOST"
assert_eq "upgrade: exactly ONE systemd-tpm2 token stands" "1" \
    "$(jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length' "$UPGPOST")"
assert_no_leftovers "upgrade success"

# --- 5. seal_upgrade_token scrubs on an INJECTED FAILURE (token import refuses) --------
cat >"$TMP/cs-no-import" <<EOF
#!/bin/sh
[ "\$1" = "token" ] && [ "\$2" = "import" ] && exit 1
exec "$REAL_CS" "\$@"
EOF
chmod +x "$TMP/cs-no-import"
LUKS4=$TMP/luks-upgrade-fail.img
mk_luks "$LUKS4"
ALPINE_FDE_CRYPTSETUP=$TMP/cs-no-import
UPG2_RC=0
( seal_upgrade_token "$KEYDIR" "$LUKS4" "$TMP/pcrsig711.json" "$TMP/upg2-token.json" "$TMP/k0" ) \
    >"$TMP/upg2.out" 2>&1 || UPG2_RC=$?
assert_eq "injected token-import failure -> upgrade rc 1" "1" "$UPG2_RC"
unset ALPINE_FDE_CRYPTSETUP
assert_no_leftovers "upgrade failure"

swtpm_stop "$TPMDIR" || true
finish
