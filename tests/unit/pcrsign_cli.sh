#!/usr/bin/env bash
# tests/unit/pcrsign_cli.sh — G-B4: `debian-fde pcrsign` (§6.1.1 signer contract)
# end-to-end through the REAL dispatcher with fixture keys, fixture baseline and
# a stubbed ukify (canned enter-initrd measure JSON). Asserts OBSERVED effects:
# the sign-format JSON artifact, pcrs [7,11], and an openssl-verifiable release
# signature over the combined policyDigest; fail-closed 64 on pending baseline /
# missing key material / missing inputs; usage 2 on CLI-shape errors.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"

# helper beyond lib.sh's set (same shape as policy_digest_golden.sh's)
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}

KEYDIR="$REPO/fixtures/keys"
GOLDEN="$REPO/fixtures/policy-digest/golden.json"
D7=$(jq -r .pcr7_digest "$GOLDEN")
D11=$(jq -r .pcr11_digest "$GOLDEN")
POL=$(jq -r .policy_digest "$GOLDEN")
KVER=6.12.8-1-amd64

TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

STUBBIN="$TMP/stubbin"
mkdir -p "$STUBBIN"

# Canned ukify: only the measure invocation matters — it must be pinned to the
# enter-initrd phase (§6.1.1 step 1) and emit the parseable JSON. We hand it the
# golden d11 so the expected combined digest equals the golden policy digest.
UKIFY_LOG="$TMP/ukify.log"
cat >"$STUBBIN/ukify" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$UKIFY_LOG"
case \$* in
    *--measure*)
        printf '{"sha256":[{"pcrbank":"sha256","phase":"enter-initrd","hash":"%s"}]}\n' "$D11"
        ;;
esac
EOF
chmod +x "$STUBBIN/ukify"

# --- fixture tree: finalized baseline (golden d7) + a REAL minimal UKI ------------
ROOT="$TMP/root"
mkdir -p "$ROOT/etc/alpine-fde"
jq -n --arg d7 "$D7" '{schema_version: "1", expected_pcr7: $d7, status: "finalized"}' \
    >"$ROOT/etc/alpine-fde/baseline.json"

UKI="$TMP/uki.efi"
ukify build \
    --linux="$REPO/fixtures/uki/vmlinuz" \
    --initrd="$REPO/fixtures/uki/initrd.img" \
    --cmdline=@"$REPO/fixtures/uki/cmdline.txt" \
    --os-release=@"$REPO/fixtures/uki/os-release" \
    --uname="$KVER" \
    --output="$UKI" >/dev/null 2>&1
[ -s "$UKI" ] || { echo "FAIL: could not build the fixture UKI (real ukify)" >&2; exit 1; }

# pcrsign — the REAL dispatcher with stubbed measure + fixture env
pcrsign() {
    env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR -u DEBIAN_FDE_ESP -u DEBIAN_FDE_DISK \
        PATH="$STUBBIN:$PATH" \
        DEBIAN_FDE_ROOT="$ROOT" \
        DEBIAN_FDE_KEYDIR="$KEYDIR" \
        DEBIAN_FDE_NO_INSTALL=1 \
        DEBIAN_FDE_CONF="$TMP/absent.conf" \
        "$REPO/bin/debian-fde" pcrsign "$@"
}

# verify_sig <json> — decode .sha256[0].sig and openssl-verify it over the
# policyDigest recomputed from the golden d7/d11 (independent of policy_verify)
verify_sig() {
    jq -r '.sha256[0].sig' "$1" | openssl base64 -d -A >"$TMP/ver.sig" 2>/dev/null
    policy_digest_bin "$D7" "$D11" >"$TMP/ver.msg"
    openssl dgst -sha256 -verify "$KEYDIR/release.pub" \
        -signature "$TMP/ver.sig" "$TMP/ver.msg" >/dev/null 2>&1
}

# --- happy path: measure from an existing UKI --------------------------------------
OUT="$TMP/pcrsig-uki.json"
out=$(pcrsign --uki "$UKI" --out "$OUT" 2>&1)
rc=$?
assert_rc "pcrsign --uki exits 0" 0 $rc
assert_file_exists "pcrsign --uki wrote the artifact" "$OUT"
assert_eq "artifact: pcrs are [7,11]" "true" "$(jq '.sha256[0].pcrs == [7, 11]' "$OUT")"
assert_eq "artifact: pol == golden combined policyDigest" "$POL" "$(jq -r '.sha256[0].pol' "$OUT")"
assert_eq "artifact: pkfp == DER-SPKI sha256 of release.pub" \
    "$(policy_pubkey_fp "$KEYDIR/release.pub")" "$(jq -r '.sha256[0].pkfp' "$OUT")"
assert_eq "artifact: sha256 is the only bank" "sha256" "$(jq -r 'keys | join(",")' "$OUT")"
verify_sig "$OUT"
assert_rc "artifact: openssl verifies the release signature over the policyDigest" 0 $?
assert_contains "measure was pinned to --phases=enter-initrd" "$(cat "$UKIFY_LOG")" "--phases=enter-initrd"
assert_contains "measure ran in --measure mode" "$(cat "$UKIFY_LOG")" "--measure"
# systemd-measure sign output shape: no invented fields BEYOND the Option A
# digest anchors (d7/d11 — the components the signature was computed over,
# consumed by the seal-time digest-anchored G-B6/precondition checks)
assert_eq "artifact: fields are exactly pcrs|pkfp|pol|sig|d7|d11" \
    "pcrs,pkfp,pol,sig,d7,d11" "$(jq -r '.sha256[0] | keys_unsorted | join(",")' "$OUT")"

# --- happy path: explicit component inputs ------------------------------------------
OUT2="$TMP/pcrsig-comp.json"
pcrsign --linux "$REPO/fixtures/uki/vmlinuz" \
    --initrd "$REPO/fixtures/uki/initrd.img" \
    --cmdline "$REPO/fixtures/uki/cmdline.txt" \
    --os-release "$REPO/fixtures/uki/os-release" \
    --out "$OUT2" >/dev/null 2>&1
assert_rc "pcrsign with component inputs exits 0" 0 $?
assert_eq "component path: identical policyDigest (same canned d11)" \
    "$(jq -c '.sha256[0]' "$OUT")" "$(jq -c '.sha256[0]' "$OUT2")"

# --- systemd-measure FALLBACK branch (§6.1.1 step 1): no ukify on PATH --------------
# lib/cmd/pcrsign.sh routes through `systemd-measure calculate` (awk digest
# parse) when ukify is absent. Restricted PATH with a canned systemd-measure
# stub and NO ukify — the artifact must be IDENTICAL to the ukify-path artifact
# (same canned d11 -> same policyDigest -> same signature) and the invocation
# must be pinned to the enter-initrd phase.
FB="$TMP/fallbackbin"
mkdir -p "$FB"
for t in bash sh jq openssl awk mktemp cat rm mv mkdir chmod date sed grep head tail \
    tr od xxd sha256sum cut env uname dirname basename readlink id sleep sort uniq cp; do
    p=$(command -v "$t" 2>/dev/null) && ln -s "$p" "$FB/$t"
done
SDM_LOG="$TMP/systemd-measure.log"
cat >"$FB/systemd-measure" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >>"$SDM_LOG"
# real-shape calculate line: ':', '=' and '-' all appear BEFORE the digest, so
# the awk gsub(/^.*[:=-]/) strip is exercised greedily
printf '11:sha256(9f2a:44cc-be01)=%s\n' "$D11"
EOF
chmod +x "$FB/systemd-measure"
assert_eq "fallback env: ukify genuinely absent" "missing" \
    "$(env PATH="$FB" sh -c 'command -v ukify >/dev/null 2>&1 && echo found || echo missing')"
: >"$SDM_LOG"
OUT3="$TMP/pcrsig-fallback.json"
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR -u DEBIAN_FDE_ESP -u DEBIAN_FDE_DISK \
    PATH="$FB" \
    DEBIAN_FDE_ROOT="$ROOT" \
    DEBIAN_FDE_KEYDIR="$KEYDIR" \
    DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --linux "$REPO/fixtures/uki/vmlinuz" \
        --initrd "$REPO/fixtures/uki/initrd.img" \
        --cmdline "$REPO/fixtures/uki/cmdline.txt" \
        --os-release "$REPO/fixtures/uki/os-release" \
        --out "$OUT3" 2>&1)
rc=$?
assert_rc "systemd-measure fallback: pcrsign exits 0" 0 $rc
assert_file_exists "systemd-measure fallback: artifact written" "$OUT3"
assert_contains "fallback: systemd-measure calculate was the measurer" "$(cat "$SDM_LOG")" "calculate"
assert_contains "fallback: phase pinned to enter-initrd" "$(cat "$SDM_LOG")" "--phase=enter-initrd"
assert_eq "fallback: identical artifact to the ukify path (same canned d11)" \
    "$(jq -c '.sha256[0]' "$OUT")" "$(jq -c '.sha256[0]' "$OUT3")"

# --- fail-closed: pending baseline (§8.4 — refuse until finalized) -------------------
ROOT_PEND="$TMP/root-pending"
mkdir -p "$ROOT_PEND/etc/alpine-fde"
jq -n '{schema_version: "1", expected_pcr7: "pending", status: "pending"}' \
    >"$ROOT_PEND/etc/alpine-fde/baseline.json"
rc=0
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR PATH="$STUBBIN:$PATH" \
    DEBIAN_FDE_ROOT="$ROOT_PEND" DEBIAN_FDE_KEYDIR="$KEYDIR" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --uki "$UKI" --out "$TMP/nope.json" 2>&1) || rc=$?
assert_rc "pending baseline -> exit 64 (fail-closed)" 64 $rc
assert_contains "pending baseline message names the audit --init cure" "$out" "audit --init"
[ ! -e "$TMP/nope.json" ]
assert_rc "pending baseline: no artifact written" 0 $?

# --- fail-closed: baseline file missing entirely --------------------------------------
ROOT_NOBL="$TMP/root-nobaseline"
mkdir -p "$ROOT_NOBL/etc/alpine-fde"
rc=0
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR PATH="$STUBBIN:$PATH" \
    DEBIAN_FDE_ROOT="$ROOT_NOBL" DEBIAN_FDE_KEYDIR="$KEYDIR" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --uki "$UKI" 2>&1 >/dev/null) || rc=$?
assert_rc "missing baseline -> exit 64" 64 $rc
assert_contains "missing baseline message names the file" "$out" "baseline.json"

# --- fail-closed: missing release key material ------------------------------------------
rc=0
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR PATH="$STUBBIN:$PATH" \
    DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_KEYDIR="$TMP/absent-keys" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --uki "$UKI" 2>&1 >/dev/null) || rc=$?
assert_rc "missing key material -> exit 64 (loud, I4/ADR-8)" 64 $rc
assert_contains "missing key message explains the keydir" "$out" "release key"

# --- fail-closed: input UKI file missing --------------------------------------------------
rc=0
out=$(pcrsign --uki "$TMP/does-not-exist.efi" 2>&1 >/dev/null) || rc=$?
assert_rc "missing UKI input -> exit 64" 64 $rc
assert_contains "missing UKI message names the file" "$out" "does-not-exist.efi"

# --- S-M3: UKI carrying measured-but-unextracted sections is REFUSED (64) ------------
# systemd-stub measures .ucode/.dtb/.splash/.pcrpkey into PCR 11; pcrsign extracts
# only .linux/.initrd/.cmdline/.osrel, so a signature over such a UKI would be
# silently dead. Fixture: a real ukify build with --pcr-private-key (embeds
# .pcrpkey — exactly what every A'' `ukictl build` UKI carries); a throwaway
# systemd-measure stub satisfies ukify's sign step during the fixture build only.
SMBIN="$TMP/smbin"
mkdir -p "$SMBIN"
cat >"$SMBIN/systemd-measure" <<'EOF'
#!/bin/sh
printf '{"sha256":[{"pcrbank":"sha256","phase":"enter-initrd","hash":"0000000000000000000000000000000000000000000000000000000000000000"}]}\n'
EOF
chmod +x "$SMBIN/systemd-measure"
UKI_PK="$TMP/uki-pcrpkey.efi"
PATH="$SMBIN:$PATH" ukify build \
    --linux="$REPO/fixtures/uki/vmlinuz" \
    --initrd="$REPO/fixtures/uki/initrd.img" \
    --cmdline=@"$REPO/fixtures/uki/cmdline.txt" \
    --os-release=@"$REPO/fixtures/uki/os-release" \
    --uname="$KVER" \
    --pcr-private-key="$KEYDIR/release.pem" \
    --pcr-public-key="$KEYDIR/release.pub" \
    --pcr-banks=sha256 \
    --output="$UKI_PK" >/dev/null 2>&1
objcopy -O binary --only-section=.pcrpkey "$UKI_PK" "$TMP/pk.bin" 2>/dev/null && [ -s "$TMP/pk.bin" ]
assert_rc "S-M3 sanity: fixture UKI really carries .pcrpkey" 0 $?
rc=0
out=$(pcrsign --uki "$UKI_PK" --out "$TMP/nope-m3.json" 2>&1) || rc=$?
assert_rc "UKI with .pcrpkey -> exit 64 (unextracted measured section, S-M3)" 64 $rc
assert_contains "S-M3 message names the offending section" "$out" ".pcrpkey"
[ ! -e "$TMP/nope-m3.json" ]
assert_rc "S-M3: no artifact written" 0 $?

# --- S-M1: relative --out (no slash) — artifact in the CWD, no stray directory -------
RELOUT="$TMP/relout"
mkdir -p "$RELOUT"
rc=0
out=$(cd "$RELOUT" && pcrsign --uki "$UKI" --out pcrsig.json 2>&1) || rc=$?
assert_rc "relative --out pcrsig.json exits 0 (S-M1)" 0 $rc
[ -f "$RELOUT/pcrsig.json" ]
assert_rc "relative --out: artifact file created in cwd" 0 $?
[ -s "$RELOUT/pcrsig.json" ]
assert_rc "relative --out: artifact is non-empty" 0 $?
jq -e . "$RELOUT/pcrsig.json" >/dev/null 2>&1
assert_rc "relative --out: artifact is valid JSON" 0 $?
[ -d "$RELOUT/pcrsig.json" ]
assert_rc "relative --out: no stray directory named after the artifact" 1 $?

# --- S-L3: component flags combined with --uki are a usage error (exit 2) ------------
for _l3flag in --initrd --cmdline --os-release; do
    rc=0
    out=$(pcrsign --uki "$UKI" "$_l3flag" "$REPO/fixtures/uki/cmdline.txt" 2>&1 >/dev/null) || rc=$?
    assert_rc "--uki with $_l3flag -> exit 2 (usage, S-L3)" 2 $rc
done
assert_contains "S-L3 message names the conflicting option" "$out" "--uki"

# --- S-M4: corrupt release.pub -> fail-closed 64, no artifact (never SHA256('')) -----
CORRUPT="$TMP/corrupt-keys"
mkdir -p "$CORRUPT"
cp "$KEYDIR/release.pem" "$CORRUPT/release.pem"
cp "$KEYDIR/release.crt" "$CORRUPT/release.crt"
printf 'deliberately not a key' >"$CORRUPT/release.pub"
rc=0
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR PATH="$STUBBIN:$PATH" \
    DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_KEYDIR="$CORRUPT" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --uki "$UKI" --out "$TMP/nope-m4.json" 2>&1) || rc=$?
assert_rc "corrupt release.pub -> exit 64 (fail-closed, S-M4)" 64 $rc
assert_contains "S-M4 message names the unusable public key" "$out" "release.pub"
[ ! -e "$TMP/nope-m4.json" ]
assert_rc "S-M4: no artifact written" 0 $?

# --- S-L1: pcrsign temps must not leak when policy_sign_json dies ---------------------
# (truncated release.pem: keys_require passes the -f check, policy_sign dies inside
# policy_sign_json — _ps_work/_ps_tmp used to leak with it)
TRUNC="$TMP/trunc-keys"
mkdir -p "$TRUNC"
cp "$KEYDIR/release.pub" "$TRUNC/release.pub"
cp "$KEYDIR/release.crt" "$TRUNC/release.crt"
head -c 120 "$KEYDIR/release.pem" >"$TRUNC/release.pem"
PSTEMP="$TMP/pstemp"
mkdir -p "$PSTEMP"
rc=0
out=$(env -u DEBIAN_FDE_TCTI -u DEBIAN_FDE_CMD_DIR PATH="$STUBBIN:$PATH" \
    TMPDIR="$PSTEMP" \
    DEBIAN_FDE_ROOT="$ROOT" DEBIAN_FDE_KEYDIR="$TRUNC" DEBIAN_FDE_NO_INSTALL=1 \
    DEBIAN_FDE_CONF="$TMP/absent.conf" \
    "$REPO/bin/debian-fde" pcrsign --uki "$UKI" 2>&1 >/dev/null) || rc=$?
assert_rc "truncated release.pem -> exit 64 (fail-closed)" 64 $rc
assert_eq "S-L1: no pcrsign temp leak on the policy_sign_json die path" "0" \
    "$(find "$PSTEMP" -name 'debian-fde-pcrsig*' 2>/dev/null | wc -l | tr -d '[:space:]')"

# --- usage errors: exit 2 (CLI-shape), never silently proceeded ---------------------------
rc=0
out=$(pcrsign --bogus "$UKI" 2>&1 >/dev/null) || rc=$?
assert_rc "unknown option -> exit 2 (usage)" 2 $rc
rc=0
out=$(pcrsign 2>&1 >/dev/null) || rc=$?
assert_rc "no input selection -> exit 2 (usage)" 2 $rc
assert_contains "no-input message tells the user what to give" "$out" "--uki"

finish
