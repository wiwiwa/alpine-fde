#!/usr/bin/env bash
# tests/integration/measure_shim_oracle.sh — real-server blocker #16: the
# bundled lib/measure.sh `systemd-measure` replacement must reproduce the REAL
# binary's output BYTE-FOR-BYTE for the exact option surface `ukify build`
# generates (--pcr-banks=sha256 --phases=enter-initrd --pcr-private-key/
# --pcr-public-key), because the .pcrsig JSON it emits is embedded in the UKI
# and verified by systemd-stub at boot.
#
# Oracle: the real /usr/lib/systemd/systemd-measure (systemd 261.3 on this
# host). Every positive pin is differential: oracle stdout == shim stdout,
# byte-for-byte. Pins:
#   1. sign, single phase enter-initrd (product shape) — byte parity
#   2. calculate --json=short (ukify's PCR-11 prediction leg) — byte parity
#   3. ukify argv shape incl. --sbat/--uname-as-file — byte parity
#   4. wrong-key negative: the sig verifies under the SIGNING key's public key
#      and MUST FAIL under a different key (what systemd-stub enforces at boot)
#   5. malformed input (missing section file): BOTH the oracle and the shim
#      fail with empty stdout — never a silent half-signature
#   6. MUTATION CONTROL: perturbing one TPML byte in a scratch copy of
#      lib/measure.sh MUST be caught by pin 1 (proves the pins have teeth)
#   7. WIRING: measure_probe — system binary wins (empty argv addition); with
#      the system binary seam-forced absent it stages an executable
#      `systemd-measure` shim and prints --tools=<dir>; with the shim also
#      absent it fails closed rc 64 NAMING BOTH candidates
#   8. END-TO-END: the real ukify, given --tools=<staged shim dir>, embeds a
#      .pcrsig section whose content starts with the shim's JSON (ukify 260.2
#      combine_signatures + 1024-space padding)
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../unit/lib.sh
source "$HERE/../unit/lib.sh"

ORACLE=/usr/lib/systemd/systemd-measure
if [ ! -x "$ORACLE" ]; then
    echo "SKIP: no oracle at $ORACLE — differential pins need the real systemd-measure (e2e-host shape); run where systemd exists"
    exit 0
fi
command -v openssl >/dev/null 2>&1 || { echo "FAIL: openssl required" >&2; exit 1; }

# unit/lib.sh has no file helper; define locally (do NOT mix in tests/lib/assert.sh)
assert_file_exists() { # <desc> <path>
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (file does not exist: $2)"; fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- fixture: throwaway RSA keys + tiny section files (in the suite's tmp) ------
KEYA="$TMP/keyA.pem"
PUBA="$TMP/pubA.pem"
KEYB="$TMP/keyB.pem"
PUBB="$TMP/pubB.pem"
openssl genrsa -out "$KEYA" 2048 2>/dev/null
openssl rsa -in "$KEYA" -pubout -out "$PUBA" 2>/dev/null
openssl genrsa -out "$KEYB" 2048 2>/dev/null
openssl rsa -in "$KEYB" -pubout -out "$PUBB" 2>/dev/null

KVER=6.18.53-0-lts
printf 'root=UUID=22222222-2222-2222-2222-222222222222 ro rd.shell=0' >"$TMP/cmdline.txt"
printf 'ID=alpine\nNAME="Alpine Linux"\n' >"$TMP/os-release"
printf '%s\n' "$KVER" >"$TMP/uname.txt"           # ukify writes uname WITHOUT trailing NL
printf '%s' "$KVER" >"$TMP/uname_nonl.txt"
head -c 1024 /dev/urandom >"$TMP/linux.bin"
head -c 512 /dev/urandom >"$TMP/initrd.img"
printf 'ALPINE-FDE$$1:alpine-fde:1\n' >"$TMP/sbat.txt"

# the shim under test: fresh shell, common.sh + measure.sh
shim_run() { # <outfile> ARGV...
    local out=$1
    shift
    printf '%s\n' \
        ". '$REPO/lib/common.sh' 2>/dev/null" \
        ". '$REPO/lib/measure.sh'" \
        "fde_measure_main \"\$@\"" >"$TMP/shimentry.sh"
    bash "$TMP/shimentry.sh" "$@" >"$out" 2>"$TMP/shim.err"
}

# --- 1/2. product shape: sign + calculate byte parity ----------------------------
ARGV=(--linux="$TMP/linux.bin" --osrel="$TMP/os-release" --cmdline="$TMP/cmdline.txt"
    --initrd="$TMP/initrd.img" --uname="$TMP/uname_nonl.txt" --pcrpkey="$PUBA"
    --bank=sha256 --phase=enter-initrd)

"$ORACLE" sign "${ARGV[@]}" --private-key="$KEYA" --public-key="$PUBA" >"$TMP/oracle.sign.json" 2>/dev/null
shim_run "$TMP/shim.sign.json" sign "${ARGV[@]}" --private-key="$KEYA" --public-key="$PUBA"
assert_rc "shim sign exits 0" 0 $?
if cmp -s "$TMP/oracle.sign.json" "$TMP/shim.sign.json"; then
    _pass "sign JSON byte-for-byte identical to the oracle"
else
    _fail "sign JSON differs from oracle: $(cat "$TMP/oracle.sign.json") vs $(cat "$TMP/shim.sign.json")"
fi

"$ORACLE" calculate --json short "${ARGV[@]}" >"$TMP/oracle.calc.json" 2>/dev/null
shim_run "$TMP/shim.calc.json" calculate --json short "${ARGV[@]}"
assert_rc "shim calculate exits 0" 0 $?
if cmp -s "$TMP/oracle.calc.json" "$TMP/shim.calc.json"; then
    _pass "calculate --json short byte-for-byte identical to the oracle"
else
    _fail "calculate JSON differs from oracle: $(cat "$TMP/oracle.calc.json") vs $(cat "$TMP/shim.calc.json")"
fi

# --- 3. ukify argv shape (sections incl. .sbat, --uname as file) ------------------
ARGV3=(--osrel="$TMP/os-release" --cmdline="$TMP/cmdline.txt" --uname="$TMP/uname_nonl.txt"
    --pcrpkey="$PUBA" --linux="$TMP/linux.bin" --initrd="$TMP/initrd.img" --sbat="$TMP/sbat.txt"
    --bank=sha256 --private-key="$KEYA" --public-key="$PUBA" --phase=enter-initrd)
"$ORACLE" sign "${ARGV3[@]}" >"$TMP/oracle.sbat.json" 2>/dev/null
shim_run "$TMP/shim.sbat.json" sign "${ARGV3[@]}"
assert_rc "shim sign (ukify argv order + .sbat) exits 0" 0 $?
if cmp -s "$TMP/oracle.sbat.json" "$TMP/shim.sbat.json"; then
    _pass "sign (ukify argv order, .sbat measured) byte-for-byte identical"
else
    _fail "sign (.sbat shape) differs from oracle"
fi

# --- 4. wrong-key negative --------------------------------------------------------
"$ORACLE" sign "${ARGV[@]}" --private-key="$KEYA" --public-key="$PUBB" >"$TMP/oracle.wrongkey.json" 2>/dev/null
shim_run "$TMP/shim.wrongkey.json" sign "${ARGV[@]}" --private-key="$KEYA" --public-key="$PUBB"
if cmp -s "$TMP/oracle.wrongkey.json" "$TMP/shim.wrongkey.json"; then
    _pass "mismatched pub/priv output byte-for-byte identical to the oracle (pkfp of the GIVEN key)"
else
    _fail "mismatched pub/priv output differs from oracle"
fi
assert_rc "shim sign with mismatched --public-key exits 0 (oracle-pinned behavior)" 0 $?
assert_contains "pkfp fingerprints the GIVEN --public-key (pubB), not the signer" \
    "$(cat "$TMP/shim.wrongkey.json")" \
    "$(jq -r '.sha256[0].pkfp' "$TMP/oracle.wrongkey.json" 2>/dev/null || true)"
# the real check: openssl verification semantics — sig(A) verifies under pubA,
# MUST fail under pubB (this is what systemd-stub enforces against .pcrpkey)
jq -r '.sha256[0].sig' "$TMP/shim.sign.json" >"$TMP/sigA.b64"
openssl base64 -d -A -in "$TMP/sigA.b64" -out "$TMP/sigA.raw" 2>/dev/null
# independent recomputation of the pol digest from the shim's own JSON
POL=$(jq -r '.sha256[0].pol' "$TMP/shim.sign.json")
printf '%s' "$POL" | LC_ALL=C awk '{
    hex = "0123456789abcdef"
    for (i = 1; i <= length($0); i += 2) {
        hi = index(hex, tolower(substr($0, i, 1))) - 1
        lo = index(hex, tolower(substr($0, i + 1, 1))) - 1
        printf "%c", hi * 16 + lo
    }
}' >"$TMP/polA.bin"
openssl dgst -sha256 -verify "$PUBA" -signature "$TMP/sigA.raw" "$TMP/polA.bin" >/dev/null 2>&1
assert_rc "sig verifies under the signing key's public key (pubA)" 0 $?
openssl dgst -sha256 -verify "$PUBB" -signature "$TMP/sigA.raw" "$TMP/polA.bin" >/dev/null 2>&1
if [ $? -eq 0 ]; then
    _fail "wrong-key negative FAILED: sig(A) verified under pubB — the pin is vacuous"
else
    _pass "wrong-key negative: sig(A) rejected under pubB (rc!=0)"
fi

# --- 5. malformed input shape ------------------------------------------------------
"$ORACLE" sign --linux="$TMP/does-not-exist" --bank=sha256 --private-key="$KEYA" \
    --public-key="$PUBA" --phase=enter-initrd >"$TMP/oracle.bad.out" 2>/dev/null
assert_rc "oracle fails on a missing section file" 1 $?
[ -s "$TMP/oracle.bad.out" ] && _fail "oracle produced stdout on failure" ||
    _pass "oracle stdout empty on failure"
shim_run "$TMP/shim.bad.out" sign --linux="$TMP/does-not-exist" --bank=sha256 \
    --private-key="$KEYA" --public-key="$PUBA" --phase=enter-initrd
assert_rc "shim fails loud (64) on a missing section file" 64 $?
[ -s "$TMP/shim.bad.out" ] && _fail "shim produced stdout on failure" ||
    _pass "shim stdout empty on failure (no half-signature)"

# --- 6. MUTATION CONTROL: one TPML byte must be caught -----------------------------
mkdir -p "$TMP/mutant"
sed 's/MEASURE_TPML_PCR11=.00000001000b03000800./MEASURE_TPML_PCR11=00000001000b03000900/' \
    "$REPO/lib/measure.sh" >"$TMP/mutant/measure.sh"
grep -q 'MEASURE_TPML_PCR11=00000001000b03000900' "$TMP/mutant/measure.sh" ||
    _fail "mutation control could not apply the byte perturbation (sed pattern drifted)"
printf '%s\n' \
    ". '$REPO/lib/common.sh' 2>/dev/null" \
    ". '$TMP/mutant/measure.sh'" \
    "fde_measure_main \"\$@\"" >"$TMP/mutant/entry.sh"
bash "$TMP/mutant/entry.sh" sign "${ARGV[@]}" --private-key="$KEYA" --public-key="$PUBA" \
    >"$TMP/mutant.sign.json" 2>/dev/null
if cmp -s "$TMP/oracle.sign.json" "$TMP/mutant.sign.json"; then
    _fail "MUTATION CONTROL FAILED: perturbed TPML byte still reproduced the oracle — pin 1 has no teeth"
else
    _pass "mutation control: one perturbed TPML byte is caught (output differs from oracle)"
fi

# --- 7. WIRING: measure_probe -------------------------------------------------------
. "$REPO/lib/common.sh"
. "$REPO/lib/measure.sh"

# 7a. real system binary present (this host) -> system impl, no argv addition
ALPINE_FDE_MEASURE_BIN="$ORACLE" measure_probe "$TMP/stage-a" >"$TMP/probe.a.out" 2>/dev/null
assert_rc "probe: system binary -> rc 0" 0 $?
assert_eq "probe: system binary -> no ukify argv addition" "" "$(cat "$TMP/probe.a.out")"

# 7b. system binary seam-forced ABSENT -> staged shim + --tools=<dir>
# (ALPINE_FDE_CMD_DIR pinned to the REPO so the bundled measure.sh is the
# discovered candidate — the same shape as the installed guest, where
# /opt/alpine-fde/lib/measure.sh resolves)
rm -rf "$TMP/stage-b"
ALPINE_FDE_CMD_DIR="$REPO/lib/cmd" ALPINE_FDE_MEASURE_BIN= measure_probe "$TMP/stage-b" \
    >"$TMP/probe.b.out" 2>/dev/null
assert_rc "probe: shim path -> rc 0" 0 $?
assert_eq "probe: shim path -> --tools=<staging dir>" \
    "--tools=$TMP/stage-b" "$(cat "$TMP/probe.b.out")"
assert_file_exists "probe: staged an executable systemd-measure shim" "$TMP/stage-b/systemd-measure"
test -x "$TMP/stage-b/systemd-measure"
assert_rc "staged shim is executable" 0 $?
# the staged shim itself must reproduce the oracle
ALPINE_FDE_MEASURE_BIN= "$TMP/stage-b/systemd-measure" sign "${ARGV[@]}" \
    --private-key="$KEYA" --public-key="$PUBA" >"$TMP/staged.sign.json" 2>/dev/null
if cmp -s "$TMP/oracle.sign.json" "$TMP/staged.sign.json"; then
    _pass "staged shim reproduces the oracle byte-for-byte through the executable path"
else
    _fail "staged shim output differs from oracle"
fi

# 7c. NEITHER available -> loud fail-closed 64 naming both candidates
# (ALPINE_FDE_CMD_DIR forced to an empty dir so the bundled measure.sh is
# unreachable AND the system binary is seam-absent — a true double absence)
/bin/bash -c ". '$REPO/lib/common.sh'; . '$REPO/lib/measure.sh';
             ALPINE_FDE_CMD_DIR='$TMP/nothing' ALPINE_FDE_MEASURE_BIN= measure_probe '$TMP/stage-c'" \
    >"$TMP/probe.c.out" 2>"$TMP/probe.c.err"
_rc=$?
assert_rc "probe: neither implementation -> fail-closed 64" 64 "$_rc"
assert_contains "fail-closed message names /usr/lib/systemd/systemd-measure" \
    "$(cat "$TMP/probe.c.err")" "/usr/lib/systemd/systemd-measure"
assert_contains "fail-closed message names lib/measure.sh" \
    "$(cat "$TMP/probe.c.err")" "measure.sh"

# --- 8. END-TO-END: real ukify embeds the shim's .pcrsig -----------------------------
if command -v ukify >/dev/null 2>&1 && command -v objcopy >/dev/null 2>&1 &&
    [ -f /usr/lib/systemd/boot/efi/linuxx64.efi.stub ]; then
    ALPINE_FDE_MEASURE_BIN= ukify build \
        "--linux=$TMP/linux.bin" "--initrd=$TMP/initrd.img" "--cmdline=@$TMP/cmdline.txt" \
        "--os-release=@$TMP/os-release" "--uname=$KVER" \
        --pcr-banks=sha256 --phases=enter-initrd \
        "--pcr-private-key=$KEYA" "--pcr-public-key=$PUBA" \
        "--tools=$TMP/stage-b" --measure --json=short \
        "--output=$TMP/uki.efi" >/dev/null 2>"$TMP/ukify.err"
    assert_rc "ukify build completes against the staged shim (no FileNotFoundError)" 0 $?
    objcopy -O binary --only-section=.pcrsig "$TMP/uki.efi" "$TMP/ukicrsig.bin" 2>/dev/null
    assert_file_exists ".pcrsig section extracted from the UKI" "$TMP/ukicrsig.bin"
    # airtight differential: extract the sections ukify ACTUALLY measured
    # (.cmdline came in as a literal, .sbat is ukify's merged STUB_SBAT) and
    # require the embedded .pcrsig to start with the ORACLE's output over those
    # exact bytes
    objcopy -O binary --only-section=.cmdline "$TMP/uki.efi" "$TMP/cmdline.extracted" 2>/dev/null
    objcopy -O binary --only-section=.sbat "$TMP/uki.efi" "$TMP/sbat.extracted" 2>/dev/null
    "$ORACLE" sign --linux="$TMP/linux.bin" --initrd="$TMP/initrd.img" \
        "--cmdline=$TMP/cmdline.extracted" "--osrel=$TMP/os-release" "--uname=$TMP/uname_nonl.txt" \
        "--pcrpkey=$PUBA" "--sbat=$TMP/sbat.extracted" \
        --bank=sha256 --private-key="$KEYA" --public-key="$PUBA" --phase=enter-initrd \
        >"$TMP/oracle.e2e.json" 2>/dev/null
    assert_rc "oracle re-sign over the UKI's own sections exits 0" 0 $?
    # ukify combine_signatures() re-dumps the JSON then pads with spaces — the
    # oracle's (== shim's) JSON must be a space-trimmed prefix of the section
    ACTUAL=$(head -c "$(stat -c %s "$TMP/oracle.e2e.json")" "$TMP/ukicrsig.bin" | tr -d ' \n')
    EXPECTED=$(tr -d ' \n' <"$TMP/oracle.e2e.json")
    assert_contains ".pcrsig starts with the oracle(-shim) signature JSON" \
        "$ACTUAL" "${EXPECTED:0:120}"
else
    _pass "end-to-end ukify leg skipped (ukify or EFI stub absent on this host)"
fi

finish
