#!/usr/bin/env bash
# tests/unit/status_report.sh — `alpine-fde status` report row (G-R4, §8.1):
#   * per-kernel manifest-vs-ESP diff: OK / MISSING / EXTRA, rc stays 0
#   * systemd-tpm2 token display: pcrs + pubkey fingerprint (display-only, I3)
#   * Secure Boot state line, build-failed marker visibility (ADR-8), last audit
#   * §8.3: sbverify run over BOTH ESP boot binaries (stub records argv);
#     sbverify failures are REPORTED, never fatal (status is report-only)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"

T=$(mktemp -d /tmp/alpine-fde-status.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
ESP=$T/esp
UUID=11112222-3333-4444-5555-666677778888
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS
export ALPINE_FDE_ESP=$ESP
export ALPINE_FDE_BY_UUID_DIR=$T/by-uuid
export ALPINE_FDE_KEYDIR=$T/keys
export ALPINE_FDE_NO_INSTALL=1
export ALPINE_FDE_TCTI='device:/nonexistent-tpmrm0'   # PCRs print <unreadable>, fast
export PATH="$FAKEBIN:$PATH"
export SBV_LOG=$T/sbverify.log SBV_RC=$T/sbverify.rc

cleanup() { rm -rf "$T"; }
trap cleanup EXIT

mkvar() { # NAME BYTE
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}

# --- fixtures -----------------------------------------------------------------
mkdir -p "$FAKEBIN" "$EFIVARS" "$(sp_etc_dir)" "$T/keys" "$T/by-uuid"
mkvar SecureBoot 1
mkvar SetupMode 0
printf 'PUBKEY' >"$T/keys/release.crt"

BL_PCR0=$(printf 'a%.0s' {1..64}) BL_PCR1=$(printf 'b%.0s' {1..64}) \
    BL_PCR2=$(printf 'c%.0s' {1..64}) BL_PCR3=$(printf 'd%.0s' {1..64}) \
    BL_PCR7=$(printf '7%.0s' {1..64}) BL_TARGET_LUKS_UUID="$UUID" \
    baseline_write "$(sp_baseline_file)"

# ESP: one UKI with a manifest entry (OK), one orphane UKI (EXTRA),
# plus the two boot binaries §8.3 requires sbverify over
mkdir -p "$ESP/EFI/Linux" "$ESP/EFI/systemd" "$ESP/EFI/BOOT"
: >"$ESP/EFI/Linux/alpine-fde-6.1.0-1-amd64.efi"
: >"$ESP/EFI/Linux/alpine-fde-9.9.9-local.efi"
: >"$ESP/EFI/systemd/systemd-bootx64.efi"
: >"$ESP/EFI/BOOT/BOOTX64.EFI"

# manifest: entry for the present UKI + one whose UKI is MISSING from the ESP
cat >"$(sp_manifest_file)" <<'EOF'
{
  "version": 1,
  "pcr_bank": "sha256",
  "pcrs": [7, 11],
  "current_kernel": "6.1.0-1-amd64",
  "updated_at": "2026-09-17T00:00:00Z",
  "pubkey_fp": "aa11",
  "digests": [
    {
      "kernel_version": "6.1.0-1-amd64",
      "pcr11_digest": "11",
      "policy_digest": "pd1",
      "signature": "sig1"
    },
    {
      "kernel_version": "6.1.0-2-amd64",
      "pcr11_digest": "22",
      "policy_digest": "pd2",
      "signature": "sig2"
    }
  ]
}
EOF

# LUKS2 metadata served by the cryptsetup stub: recovery slot 0, token on 1,
# token JSON carrying pcrs + base64 DER pubkey (display fields, I3)
TOK_B64='MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE'
TOK_FP=$(printf '%s' "$TOK_B64" | base64 -d | sha256sum | cut -d' ' -f1)
LUKS_JSON=$T/luks.json
cat >"$LUKS_JSON" <<EOF
{
    "keyslots": {
        "0": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "AAA" } },
        "1": { "type": "luks2", "kdf": { "type": "argon2id", "salt": "BBB" } }
    },
    "tokens": {
        "0": {
            "type": "systemd-tpm2",
            "keyslots": ["1"],
            "tpm2-blob": "AAEAC0RhdGE=",
            "tpm2-pcrs": [7],
            "tpm2-public-key": "$TOK_B64",
            "tpm2-public-key-pcrs": [11]
        }
    }
}
EOF
: >"$T/by-uuid/$UUID"

cat >"$FAKEBIN/cryptsetup" <<EOF
#!/bin/sh
[ "\$1" = "luksDump" ] && cat '$LUKS_JSON'
exit 0
EOF
cat >"$FAKEBIN/sbverify" <<EOF
#!/bin/sh
echo "CALL: \$*" >>'$SBV_LOG'
exit \$(cat '$SBV_RC' 2>/dev/null || echo 0)
EOF
chmod +x "$FAKEBIN/cryptsetup" "$FAKEBIN/sbverify"

# last audit + build-failed marker fixtures
cat >"$(sp_last_audit_file)" <<'EOF'
{
  "schema_version": 1,
  "audited_at": "2026-09-17T01:02:03Z",
  "result": "drift",
  "accepted": "no"
}
EOF
printf 'ukictl build failed for kernel 6.1.0-3\nreason: signing key absent\n' >"$(sp_etc_dir)/build-failed"

run_status() {
    ST_OUT=$("$REPO/bin/alpine-fde" status 2>&1)
    ST_RC=$?
}

# --- 1. the report row: manifest diff, token fields, rc stays 0 -----------------
run_status
assert_eq "status rc 0 with diff findings" "0" "$ST_RC"
assert_contains "manifest kver present on ESP -> OK" "$ST_OUT" "6.1.0-1-amd64  OK"
assert_contains "manifest kver missing from ESP -> MISSING" "$ST_OUT" "6.1.0-2-amd64  MISSING"
assert_contains "ESP UKI without manifest entry -> EXTRA" "$ST_OUT" "9.9.9-local  EXTRA"
assert_contains "token pcrs echoed (I3 display-only)" "$ST_OUT" "token pcrs: 7"
assert_contains "token pubkey fingerprint echoed" "$ST_OUT" "token pubkey fp: sha256:$TOK_FP"

# --- 2. SB state, build-failed marker, last audit --------------------------------
assert_contains "SB state line (on, no setup mode)" "$ST_OUT" "secureboot=1 setup_mode=0"
assert_contains "build-failed marker shown prominently (ADR-8)" "$ST_OUT" "FAILED BUILD MARKER PRESENT"
assert_contains "marker reason quoted" "$ST_OUT" "signing key absent"
assert_contains "marker points at the recovery flow" "$ST_OUT" "ukictl build"
assert_contains "last-audit result + accepted echoed" "$ST_OUT" "result: drift accepted: no"

# --- 3. §8.3 sbverify over BOTH boot binaries -------------------------------------
assert_contains "sbverify pass: systemd-bootx64.efi" "$ST_OUT" "systemd-bootx64.efi"
assert_contains "sbverify pass: fallback loader" "$ST_OUT" "BOOTX64.EFI"
SBV_CALLS=$(sed -n 's/^CALL: //p' "$SBV_LOG")
assert_contains "sbverify invoked on the boot manager" "$SBV_CALLS" "$ESP/EFI/systemd/systemd-bootx64.efi"
assert_contains "sbverify invoked on the fallback loader" "$SBV_CALLS" "$ESP/EFI/BOOT/BOOTX64.EFI"
assert_contains "sbverify called with --cert <release cert>" "$SBV_CALLS" "--cert $T/keys/release.crt"

# --- 4. sbverify FAIL is reported, never fatal -------------------------------------
echo 1 >"$SBV_RC"
run_status
assert_eq "status stays rc 0 when sbverify fails" "0" "$ST_RC"
assert_contains "sbverify failure reported in output" "$ST_OUT" "FAIL"
echo 0 >"$SBV_RC"

# --- 4b. sbverify binary absent from PATH -> "skipped" line, rc stays 0 -----------
# RR-OPS-1: status is report-only; a machine without sbsigntool must still get
# its report (§8.3 loud-skip, never a crash or a nonzero rc).
NOBV=$T/bin-nosbverify
mkdir -p "$NOBV"
OLD_PATH=$PATH
IFS=':'
for d in $OLD_PATH; do
    [ -d "$d" ] || continue
    for f in "$d"/*; do
        [ -x "$f" ] || continue
        n=${f##*/}
        [ "$n" = sbverify ] && continue
        [ -e "$NOBV/$n" ] || ln -s "$f" "$NOBV/$n"
    done
done
unset IFS
ln -s "$FAKEBIN/cryptsetup" "$NOBV/cryptsetup"   # FAKEBIN mirrored by hand (minus sbverify)
assert_eq "probe setup: sbverify truly absent from the restricted PATH" "missing" \
    "$(env PATH="$NOBV" sh -c 'command -v sbverify >/dev/null 2>&1 && echo found || echo missing')"
export PATH="$NOBV"
run_status
assert_eq "sbverify absent: status rc 0" "0" "$ST_RC"
assert_contains "sbverify absent: loud skipped line" "$ST_OUT" "sbverify: not installed"
export PATH="$OLD_PATH"

# --- 4c. release cert absent -> per-binary "no release cert" lines, rc stays 0 ----
mv "$T/keys/release.crt" "$T/keys/release.crt.bak"
run_status
assert_eq "no release cert: status rc 0" "0" "$ST_RC"
assert_eq "no release cert: BOTH boot binaries reported skipped" "2" \
    "$(printf '%s\n' "$ST_OUT" | grep -c 'no release cert')"
mv "$T/keys/release.crt.bak" "$T/keys/release.crt"

# --- 4d. M-1: cert resolution falls back to baseline keys.release_cert_path ---------
# On the installed target the signing medium is offline (I4) and install writes no
# conf — the recorded cert path is the only pointer, so the §8.3 check must not be
# dormant there.
printf 'BASE-CERT' >"$T/keys/base-release.crt"
BL_PCR0=$(printf 'a%.0s' {1..64}) BL_PCR1=$(printf 'b%.0s' {1..64}) \
    BL_PCR2=$(printf 'c%.0s' {1..64}) BL_PCR3=$(printf 'd%.0s' {1..64}) \
    BL_PCR7=$(printf '7%.0s' {1..64}) BL_TARGET_LUKS_UUID="$UUID" \
    BL_KEYS_RELEASE_CERT_PATH="$T/keys/base-release.crt" \
    baseline_write "$(sp_baseline_file)"
unset BL_KEYS_RELEASE_CERT_PATH
: >"$SBV_LOG"
ALPINE_FDE_KEYDIR= KEY_PATH= run_status
assert_eq "M-1: status rc 0" "0" "$ST_RC"
SBV_CALLS=$(sed -n 's/^CALL: //p' "$SBV_LOG")
assert_contains "M-1: sbverify used the baseline-recorded release cert" "$SBV_CALLS" \
    "--cert $T/keys/base-release.crt"
export ALPINE_FDE_KEYDIR=$T/keys

# --- 4e. CR-02: the recorded path is the SIGNING MEDIUM (offline on the booted
# target — I4), so a live baseline record resolves a dead path there. The §8.4
# target copy ($(sp_etc_dir)/keys/release.crt, where install puts the real
# cert) must be the next tier of the resolution chain.
rm -f "$T/keys/base-release.crt"
BL_PCR0=$(printf 'a%.0s' {1..64}) BL_PCR1=$(printf 'b%.0s' {1..64}) \
    BL_PCR2=$(printf 'c%.0s' {1..64}) BL_PCR3=$(printf 'd%.0s' {1..64}) \
    BL_PCR7=$(printf '7%.0s' {1..64}) BL_TARGET_LUKS_UUID="$UUID" \
    BL_KEYS_RELEASE_CERT_PATH="$T/keys/base-release.crt" \
    baseline_write "$(sp_baseline_file)"
unset BL_KEYS_RELEASE_CERT_PATH
mkdir -p "$(sp_etc_dir)/keys"
printf 'TARGET-CERT' >"$(sp_etc_dir)/keys/release.crt"
: >"$SBV_LOG"
ALPINE_FDE_KEYDIR= KEY_PATH= run_status
assert_eq "CR-02: status rc 0" "0" "$ST_RC"
SBV_CALLS=$(sed -n 's/^CALL: //p' "$SBV_LOG")
assert_contains "CR-02: sbverify used the §8.4 target cert" "$SBV_CALLS" \
    "--cert $(sp_etc_dir)/keys/release.crt"
assert_not_contains "CR-02: dead baseline-recorded path never invoked" "$SBV_CALLS" \
    "$T/keys/base-release.crt"
assert_not_contains "CR-02: check not dormant (no no-cert skip)" "$ST_OUT" \
    "no release cert"
export ALPINE_FDE_KEYDIR=$T/keys

# --- 5. ESP absent -> reported skipped, rc stays 0 -----------------------------------
mv "$ESP" "$ESP.bak"
run_status
assert_eq "status rc 0 without an ESP" "0" "$ST_RC"
assert_contains "ESP absence reported" "$ST_OUT" "ESP not mounted"
mv "$ESP.bak" "$ESP"

# --- N. token display parsers are format-tolerant (real 2.7.5 = compact JSON) -----
# Same bug family as the LUKS2 metadata parsers (see tests/unit/luks_json_parsers.sh):
# cryptsetup emits single-line compact JSON; the parsers must not anchor on the
# pretty-printed '"type": "systemd-tpm2"' colon-space form.
. "$REPO/lib/cmd/status.sh"
COMPACT_TOKEN='{"keyslots":{"1":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","tpm2-pcrs":[7,11],"tpm2-public-key":"'"$TOK_B64"'"},"1":{"type":"clevis"}}}'
printf '%s' "$COMPACT_TOKEN" >"$T/compact-token.json"
assert_eq "compact token: pcrs parsed" "7,11" "$(st_token_pcrs "$T/compact-token.json")"
assert_eq "compact token: pubkey fp parsed" "sha256:$TOK_FP" "$(st_token_pubkey_fp "$T/compact-token.json")"
printf '%s' '{"tokens":{"tpm2":{"type":"systemd-tpm2","tpm2-pcrs":[7]}}}' >"$T/nopk-token.json"
assert_rc "compact token: no pubkey -> rc 1" 1 st_token_pubkey_fp "$T/nopk-token.json"

# --- 6. L-3: undecodable token pubkey -> <undecodable>, never a fake fingerprint ----
printf '%s' '{"tokens":{"0":{"type":"systemd-tpm2","tpm2-public-key":"!!!not-base64!!!"}}}' \
    >"$T/bad-token.json"
assert_rc "L-3: undecodable pubkey -> rc 1" 1 st_token_pubkey_fp "$T/bad-token.json"
assert_contains "L-3: <undecodable> marker printed" "$ASSERT_RC_OUTPUT" "<undecodable>"
cp "$LUKS_JSON" "$T/luks.json.good"
printf '%s' '{"keyslots":{"0":{"type":"luks2"}},"tokens":{"0":{"type":"systemd-tpm2","tpm2-public-key":"@@@corrupt@@@"}}}' >"$LUKS_JSON"
run_status
assert_eq "L-3 e2e: status rc stays 0 (display-only, I3)" "0" "$ST_RC"
assert_contains "L-3 e2e: report shows token pubkey fp: <undecodable>" "$ST_OUT" \
    "token pubkey fp: <undecodable>"
mv "$T/luks.json.good" "$LUKS_JSON"

# --- 7. L-5: mktemp failure -> loud skip line, report-only rc stays 0 ---------------
TMPDIR=$T/nosuch-tmp run_status
unset TMPDIR
assert_eq "L-5: mktemp failure: status rc stays 0 (report-only contract)" "0" "$ST_RC"
assert_contains "L-5: loud skip line for the LUKS2 token section" "$ST_OUT" \
    "token section skipped"

# --- 8. G-IL12 (§8.1/§9.1): install-state row — PROMINENT warning while the
# ceremony is unfinished (state: installed + resume hint at the advisory
# alpine-fde-finalize OpenRC service), quiet line when finalized, SILENT when the
# state file is absent (pre-state-machine installs). Report-only: rc stays 0.
rm -f "$(istate_file)"
run_status
assert_eq "install state absent: rc 0" "0" "$ST_RC"
assert_not_contains "install state absent: no Install state section (silent)" \
    "$ST_OUT" "== Install state"

istate_write installed
run_status
assert_eq "install state installed: rc stays 0" "0" "$ST_RC"
assert_contains "installed: prominent warning" "$ST_OUT" \
    "WARNING: installation is NOT finalized"
assert_contains "installed: names the state" "$ST_OUT" "install state: installed"
assert_contains "installed: resume hint at the first-boot service" "$ST_OUT" \
    "alpine-fde-finalize"
assert_contains "installed: resume hint at the CLI" "$ST_OUT" "alpine-fde finalize"

istate_write finalized
run_status
assert_eq "install state finalized: rc stays 0" "0" "$ST_RC"
assert_contains "finalized: quiet line" "$ST_OUT" "install state: finalized"
assert_not_contains "finalized: no warning" "$ST_OUT" "WARNING"

printf '{"schema_version": 1, "state": "garbage", "updated_at": "x"}' >"$(istate_file)"
run_status
assert_eq "install state garbage: rc stays 0" "0" "$ST_RC"
assert_contains "garbage: loud unreadable-state line" "$ST_OUT" "unreadable install state"

rm -f "$(istate_file)"
run_status
assert_not_contains "absent again: section gone" "$ST_OUT" "== Install state"

# --- 9. ADR-20 provisional window (§8.4 vocabulary, §10 mid-finalization row):
# state=provisional-booted is FIRST-CLASS (installed → provisional-booted →
# finalized) — Stage 2 done (first boot unlocked via the provisional PCR-11-only
# token), finalize pending. status must flag the active provisional window
# PROMINENTLY (token provisional PCR-11-only, recovery passphrase not yet set)
# with the `alpine-fde finalize` resume hint — never fall through to the
# unreadable-state branch. Exercised through the ALPINE_FDE_INSTALL_STATE seam
# against the REAL cmd_status_main (same seam install-state.sh documents).
ISTATE_FIX=$T/install-state-fixture.json
export ALPINE_FDE_INSTALL_STATE=$ISTATE_FIX

printf '{\n  "schema_version": 1,\n  "state": "provisional-booted",\n  "updated_at": "2026-09-21T00:00:00Z"\n}\n' \
    >"$ISTATE_FIX"
run_status
assert_eq "provisional-booted: rc stays 0 (report-only)" "0" "$ST_RC"
assert_contains "provisional-booted: prominent ADR-20 provisional-window warning" \
    "$ST_OUT" "WARNING"
assert_contains "provisional-booted: names the state" "$ST_OUT" "provisional-booted"
assert_contains "provisional-booted: token is provisional PCR-11-only" "$ST_OUT" "PCR 11"
assert_contains "provisional-booted: recovery passphrase not yet set" "$ST_OUT" \
    "recovery passphrase"
assert_contains "provisional-booted: resume hint (§10 mid-finalization row)" "$ST_OUT" \
    "alpine-fde finalize"
assert_not_contains "provisional-booted: never the unreadable fallthrough" \
    "$ST_OUT" "unreadable install state"

# genuinely corrupt state file (not the documented schema at all) → the
# fallthrough unreadable warning must KEEP working for real garbage
printf 'garbage\x01\x02 not a state document' >"$ISTATE_FIX"
run_status
assert_eq "corrupt state file: rc stays 0" "0" "$ST_RC"
assert_contains "corrupt state file: unreadable fallthrough intact" "$ST_OUT" \
    "unreadable install state"

# regression through the SAME seam: the other two first-class states unchanged
printf '{\n  "schema_version": 1,\n  "state": "installed",\n  "updated_at": "x"\n}\n' \
    >"$ISTATE_FIX"
run_status
assert_eq "installed (fixture seam): rc stays 0" "0" "$ST_RC"
assert_contains "installed (fixture seam): prominent warning unchanged" "$ST_OUT" \
    "WARNING: installation is NOT finalized"
assert_contains "installed (fixture seam): resume hint unchanged" "$ST_OUT" \
    "alpine-fde finalize"

printf '{\n  "schema_version": 1,\n  "state": "finalized",\n  "updated_at": "x"\n}\n' \
    >"$ISTATE_FIX"
run_status
assert_eq "finalized (fixture seam): rc stays 0" "0" "$ST_RC"
assert_contains "finalized (fixture seam): quiet line unchanged" "$ST_OUT" \
    "install state: finalized"
assert_not_contains "finalized (fixture seam): no warning" "$ST_OUT" "WARNING"

unset ALPINE_FDE_INSTALL_STATE

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
