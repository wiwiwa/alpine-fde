#!/usr/bin/env bash
# tests/unit/finalize_service_guard.sh — G-D10/G-D12 (§9.1 Stage 3, §10, ADR-20):
# the GUIDED finalization cmd (`debian-fde finalize`; at boot only the OpenRC
# ADVISORY oneshot hooks/openrc/alpine-fde-finalize exists — it never runs this
# command), exercised END-TO-END with the REAL command handler against REAL
# collaborators: a swtpm-backed TPM (the Mechanism B seal ops are the
# production code path), REAL file-backed LUKS2 containers (the
# keyslot/token choreography mutates real metadata), the real audit --init,
# and the real ADR-18 release.pem encryption. Only the seams are stubbed:
# DEBIAN_FDE_EFIVARS_DIR (firmware state), a PATH systemd-cryptenroll
# TRIPWIRE (ADR-19: cryptenroll must never be invoked anywhere), and a
# DEBIAN_FDE_CRYPTSETUP logging/fail-injection wrapper around the REAL
# cryptsetup (observability + per-member failure injection).
#
# Pinned invariants:
#   * state gate: installed | provisional-booted proceed; finalized loud
#     no-op; absent loud no-op; anything else fail-closed 64
#   * §9.1 Stage-3 order: recovery passphrase (next free keyslot + ephemeral
#     purge) -> release.pem encryption -> Secure Boot gate -> audit --init ->
#     token upgrade to {PCR 7, PCR 11} via seal_upgrade_token (per RAID1
#     member) -> MOTD/issue banner strip -> state `finalized` LAST
#   * SB-off / SetupMode=1 => 64 + the §9.1 instruction text; NO audit, NO
#     enrollment, NO token mutation, NO MOTD clear, state stays unfinalized
#     (the LOCAL step-1 keyslot work legitimately precedes the gate, §12 S-21)
#   * crash idempotency (§9.1): interrupted runs converge — the passphrase
#     step skips when the recovery passphrase already verifies in ANY slot;
#     the token upgrade skips when the standing token is already {7,11};
#     release.pem encryption skips when already encrypted (keys_is_encrypted)
#   * wrong existing-passphrase key => loud 64, NO keyslot touched
#   * §13 entropy floor enforced before ANY cryptsetup call
#   * zero systemd-cryptenroll invocations anywhere (ADR-19)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"
# shellcheck source=../../lib/install-state.sh
source "$REPO/lib/install-state.sh"

command -v swtpm >/dev/null 2>&1 || {
    echo "FAIL: swtpm not available — this test is normative and must run where swtpm exists" >&2
    exit 1
}

assert_file_exists() {
    if [ -e "$2" ]; then _pass "$1"; else _fail "$1 (missing: $2)"; fi
}
assert_not_contains() {
    case $2 in
        *"$3"*) _fail "$1 ([$2] must not contain [$3])" ;;
        *) _pass "$1" ;;
    esac
}

T=$(mktemp -d /tmp/debian-fde-final.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
LUKS_DIR=$T/luks
BYUUID=$T/by-uuid
SHM=$T/shm
KEYDIR=$T/keys
U1=11111111-1111-4111-8111-111111111111
U2=22222222-2222-4222-8222-222222222222

RECOVERY_PASS='Fin4l-Rec0very-X9k2-!qmwjpz'
KEY_PASS='R3lease-K3ypass-X7!qmz'
EPH_SECRET='ephemeral-install-key-DO-NOT-PERSIST'
PROV_SECRET='provisional-sealed-secret-0123456789'

export DEBIAN_FDE_ROOT=$T/root
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
export DEBIAN_FDE_BY_UUID_DIR=$BYUUID
export DEBIAN_FDE_KEYDIR=$KEYDIR
export DEBIAN_FDE_TMPDIR=$SHM
export DEBIAN_FDE_CRYPTSETUP=$FAKEBIN/cs-wrapper
export DEBIAN_FDE_LUKS_KEYFILE=$T/eph.bin
export DEBIAN_FDE_RECOVERY_PASSPHRASE=$RECOVERY_PASS
export DEBIAN_FDE_KEY_PASSPHRASE=$KEY_PASS
export DEBIAN_FDE_PCRSIG=$T/pcrsig-711.json
export DEBIAN_FDE_CONF=$T/none.conf
export DEBIAN_FDE_NO_INSTALL=1
export CE_LOG=$T/cryptenroll.log CS_LOG=$T/cs.log
export LUKS_DIR FAIL_MEMBER=''

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "$LUKS_DIR" "$BYUUID" "$SHM" "$KEYDIR" "$(sp_etc_dir)" \
    "$T/root/etc" "$T/swtpm"

# --- seams ---------------------------------------------------------------------
# ADR-19 tripwire: systemd-cryptenroll must NEVER be invoked by anything in the
# finalize flow (Mechanism B is the only seal path). Record and fail.
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL $*" >>'$CE_LOG'
exit 1
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll"
# cryptsetup wrapper: LOG every invocation, optionally fail (exit 1) every
# MUTATING call for one member (FAIL_MEMBER = uuid substring), then exec the
# REAL cryptsetup — the metadata effects are always real. FAIL_MEMBER is read
# at RUNTIME so each finalize invocation can inject a different failure. The
# uuid only ever appears in the DEVICE argument.
REAL_CS=$(command -v cryptsetup)
cat >"$FAKEBIN/cs-wrapper" <<EOF
#!/bin/sh
printf 'CALL %s\\n' "\$*" >>'$CS_LOG'
if [ -n "\$FAIL_MEMBER" ]; then
    case "\$*" in
        *\$FAIL_MEMBER*)
            case \$1 in
                luksAddKey | luksKillSlot) exit 1 ;;
            esac ;;
    esac
fi
exec $REAL_CS "\$@"
EOF
chmod +x "$FAKEBIN/cs-wrapper"
export PATH="$FAKEBIN:$PATH"

# --- TPM fixture: deterministic live PCRs ---------------------------------------
TPMDIR=$T/swtpm
swtpm_start "$TPMDIR" || {
    echo "FAIL: swtpm did not start" >&2
    exit 1
}
export DEBIAN_FDE_TCTI=$SWTPM_TCTI
tpm flushcontext -t >/dev/null 2>&1 || true
swtpm_pcrextend "$TPMDIR" 7 0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c
swtpm_pcrextend "$TPMDIR" 11 9a8b7c6d9a8b7c6d9a8b7c6d9a8b7c6d9a8b7c6d9a8b7c6d9a8b7c6d9a8b7c6d
pcr_hex() {
    tpm pcrread -Q -o "$T/pcr.bin" "sha256:$1" >/dev/null 2>&1
    od -An -v -tx1 "$T/pcr.bin" | tr -d ' \n'
}
D7=$(pcr_hex 7)
D11=$(pcr_hex 11)
[ ${#D7} -eq 64 ] && [ ${#D11} -eq 64 ] || {
    echo "FAIL: could not read live PCR values" >&2
    exit 1
}

# --- release keys (copy: the flow ENCRYPTS release.pem in place, ADR-18) --------
# --- release keys (HERMETIC: generated here — the shared fixtures/keys tree is
# mutated by other suites running in parallel; the flow ENCRYPTS release.pem in
# place, ADR-18, so finalize needs its own plaintext copy) ------------------------
openssl genrsa -out "$KEYDIR/release.pem" 2048 2>/dev/null
openssl pkey -in "$KEYDIR/release.pem" -pubout -out "$KEYDIR/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEYDIR/release.pem" -out "$KEYDIR/release.crt" \
    -subj /CN=debian-fde-finalize-ci 2>/dev/null
[ -s "$KEYDIR/release.pem" ] && [ -s "$KEYDIR/release.pub" ] || {
    echo "FAIL: hermetic release key generation failed" >&2
    exit 1
}
# The finalized {7,11} .pcrsig, signed ONCE by the plaintext release.pem over
# the live swtpm PCRs (the G-B6 gate inside seal_upgrade_token re-verifies it
# against the SAME live values — they never drift in this test).
POL711=$(policy_digest "$D7" "$D11")
printf '%s' "$POL711" | policy_hex_to_bin >"$T/pol711.bin"
openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$T/pol711.sig" "$T/pol711.bin"
SIG711=$(openssl base64 -A -in "$T/pol711.sig")
PKFP=$(policy_pubkey_fp "$KEYDIR/release.pub")
jq -n --arg pol "$POL711" --arg sig "$SIG711" --arg pkfp "$PKFP" \
    '{"sha256": [{"pcrs": [7, 11], "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' \
    >"$DEBIAN_FDE_PCRSIG"

# --- LUKS2 member fixture: the REAL ADR-20 `install` handoff topology -----------
# (SLOT CONTRACT, install.sh header): keyslot 0 = the ephemeral install key
# (luksFormat --key-slot 0), keyslot 1 = the provisional token slot (token
# keyslots references 1). finalize must discover the ephemeral slot as the
# passphrase slot NOT referenced by any systemd-tpm2 token (works for ANY
# index), add the recovery passphrase to the NEXT FREE slot, then kill the
# ephemeral slot (authorized by the just-added recovery passphrase).
KDFARGS=(--pbkdf argon2id --pbkdf-memory 16000 --pbkdf-parallel 1 --pbkdf-force-iterations 4)
printf '%s' "$EPH_SECRET" >"$T/eph.bin"
printf '%s' "$PROV_SECRET" >"$T/prov.bin"
mk_member() { # IMG — real file-backed LUKS2 container in the handoff topology
    truncate -s 24M "$1"
    cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$T/eph.bin" \
        "${KDFARGS[@]}" "$1"
    cryptsetup luksAddKey "${KDFARGS[@]}" --key-slot 1 --key-file "$T/eph.bin" \
        "$1" "$T/prov.bin"
    jq -n '{type: "systemd-tpm2", keyslots: ["1"], "tpm2-blob": "AAEAC0RhdGE=",
        "tpm2-pcrs": [11], "tpm2-pcr-bank": "sha256"}' >"$T/tok-prov.json"
    cryptsetup token import "$1" --token-id 0 --json-file "$T/tok-prov.json" \
        --disable-external-tokens
}
fresh_members() {
    rm -f "$LUKS_DIR/$U1.img" "$LUKS_DIR/$U2.img"
    mk_member "$LUKS_DIR/$U1.img"
    mk_member "$LUKS_DIR/$U2.img"
    ln -sfn "$LUKS_DIR/$U1.img" "$BYUUID/$U1"
    ln -sfn "$LUKS_DIR/$U2.img" "$BYUUID/$U2"
}
fresh_members

# --- firmware / state / baseline fixtures ----------------------------------------
mkvar() { # NAME BYTE — efivars fixture (attrs header + payload byte)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" \
        >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkcertvar() { # NAME CONTENT
    printf '\007\000\000\000%s' "$2" \
        >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_state() { # SECUREBOOT SETUPMODE — full key tree (the §8.4 guard state)
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
    mkcertvar PK pk-cert-v1
    mkcertvar KEK kek-cert-v1
    mkcertvar db db-cert-v1
    mkcertvar dbx dbx-cert-v1
}
BL_PCR0=pending BL_PCR1=pending BL_PCR2=pending BL_PCR3=pending BL_PCR7=pending \
    BL_KEYS_RELEASE_PUB_PATH="$KEYDIR/release.pub" BL_TARGET_LUKS_UUID="$U1" \
    baseline_write "$(sp_baseline_file)"
printf 'root1 UUID=%s none luks,tpm2-device=auto,discard\nroot2 UUID=%s none luks,tpm2-device=auto,discard\n' \
    "$U1" "$U2" >"$T/root/etc/crypttab"
BANNER_LINE='rootfs is ready — keep this line'
{ fde_motd_banner; printf '%s\n' "$BANNER_LINE"; } >"$T/root/etc/motd"
{ fde_motd_banner; printf '%s\n' "$BANNER_LINE"; } >"$T/root/etc/issue"

# --- drivers ---------------------------------------------------------------------
run_finalize() {
    FIN_OUT=$("$REPO/bin/debian-fde" finalize "$@" 2>&1)
    FIN_RC=$?
}
reset_logs() {
    : >"$CE_LOG"
    : >"$CS_LOG"
}
dump_md5() { # DEV — byte-stable LUKS2 metadata fingerprint
    cryptsetup luksDump --dump-json-metadata "$1" | md5sum | cut -d' ' -f1
}
tok_pcrs() { # DEV — the standing systemd-tpm2 token's pcrs (jq -c)
    cryptsetup luksDump --dump-json-metadata "$1" 2>/dev/null | jq -c \
        'first(.tokens // {} | to_entries[] | select(.value.type? == "systemd-tpm2") | .value["tpm2-pcrs"] // empty) // empty'
}
tok_count() {
    cryptsetup luksDump --dump-json-metadata "$1" 2>/dev/null |
        jq '[.tokens // {} | .[] | select(.type? == "systemd-tpm2")] | length'
}
slots_of() {
    cryptsetup luksDump --dump-json-metadata "$1" 2>/dev/null | jq -c '[.keyslots // {} | keys[] | tonumber] | sort'
}
nontok_slots() { # DEV — keyslot indexes NOT referenced by any systemd-tpm2 token
    cryptsetup luksDump --dump-json-metadata "$1" 2>/dev/null | jq -c \
        '[.keyslots // {} | keys[] | tonumber] as $slots
         | ([.tokens // {} | .[] | select(.type? == "systemd-tpm2")
             | .keyslots[]? | tonumber]) as $sealed
         | [$slots[] | select(. as $s | $sealed | index($s) | not)] | sort'
}
pass_verifies() { # DEV PASS — rc 0 iff PASS opens ANY keyslot
    cryptsetup open --test-passphrase --key-file <(printf '%s' "$2") "$1" >/dev/null 2>&1
    echo $?
}
cs_for() { # DEV-SUBSTRING VERB-NEEDLE — count of logged calls touching DEV
    local needle="$1" verb="$2" n=0 line
    while IFS= read -r line; do
        case $line in *"$needle"*) n=$((n + 1)) ;; esac
    done < <(grep -F "CALL $verb" "$CS_LOG" 2>/dev/null)
    echo "$n"
}

# =================================================================================
# 1. SB off ⇒ 64 + §9.1 instruction, ZERO enrollment/audit/token mutation ---------
# (§9.1 Stage-3 order puts the LOCAL steps first: the recovery passphrase +
# ephemeral purge run BEFORE the gate — §12 S-21 forbids only the TPM
# ENROLLMENT — so the pinned invariants here are: no audit, no token/enrollment
# mutation, no MOTD clear, state stays unfinalized; the local keyslot choreography
# DID run and is asserted as such.)
sb_state 0 0
istate_write installed
reset_logs
run_finalize
assert_eq "SB off: rc 64" "64" "$FIN_RC"
assert_contains "SB off: §9.1 instruction text" "$FIN_OUT" \
    "Secure Boot is not enabled with your custom keys"
assert_contains "SB off: instruction names the BIOS action" "$FIN_OUT" \
    "Reboot into BIOS setup and toggle Secure Boot ON"
assert_eq "SB off: install state stays installed" "installed" "$(istate_state)"
baseline_is_pending "$(sp_baseline_file)"
assert_rc "SB off: baseline still pending (no audit --init)" 0 $?
assert_eq "SB off: no last-audit written" "absent" \
    "$([ -f "$(sp_last_audit_file)" ] && echo present || echo absent)"
assert_eq "SB off: ZERO cryptenroll invocations (ADR-19 tripwire)" "0" \
    "$(grep -c . "$CE_LOG")"
assert_eq "SB off: member 1 token untouched (still provisional [11])" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"
assert_eq "SB off: member 2 token untouched" "[11]" "$(tok_pcrs "$LUKS_DIR/$U2.img")"
assert_eq "SB off: exactly one token per member (nothing enrolled)" "1" \
    "$(tok_count "$LUKS_DIR/$U1.img")"
assert_eq "SB off: member 1 LOCAL step ran before the gate (recovery slot 2)" "[2]" \
    "$(nontok_slots "$LUKS_DIR/$U1.img")"
assert_eq "SB off: member 1 ephemeral keyslot 0 purged (local step; rc 2 = wrong passphrase)" "2" \
    "$(pass_verifies "$LUKS_DIR/$U1.img" "$EPH_SECRET")"
assert_contains "SB off: MOTD banner NOT cleared" "$(cat "$T/root/etc/motd")" \
    "$(fde_motd_banner)"

# --- 1b. SetupMode=1 is equally refused (keys not in the final state) ------------
sb_state 1 1
run_finalize
assert_eq "SetupMode=1: rc 64" "64" "$FIN_RC"
assert_contains "SetupMode=1: refusal names Secure Boot" "$FIN_OUT" "Secure Boot"
assert_eq "SetupMode=1: state stays installed" "installed" "$(istate_state)"

# =================================================================================
# 2. Happy path (state installed, Secure Boot on) ⇒ full §9.1 Stage-3 choreography
sb_state 1 0
fresh_members
istate_write installed
reset_logs
: >"$T/root/etc/motd"
{ fde_motd_banner; printf '%s\n' "$BANNER_LINE"; } >"$T/root/etc/motd"
{ fde_motd_banner; printf '%s\n' "$BANNER_LINE"; } >"$T/root/etc/issue"
run_finalize
assert_eq "happy: rc 0" "0" "$FIN_RC"
assert_eq "happy: state finalized" "finalized" "$(istate_state)"
baseline_is_final "$(sp_baseline_file)"
assert_rc "happy: baseline final" 0 $?
assert_eq "happy: expected_pcr7 recorded from live" "$D7" \
    "$(baseline_get "$(sp_baseline_file)" expected_pcr7)"
assert_file_exists "happy: last-audit written (audit --init ran)" "$(sp_last_audit_file)"
assert_contains "happy: audit summary printed" "$FIN_OUT" "audit summary"
assert_contains "happy: summary carries the recorded PCR 7" "$FIN_OUT" "$D7"
assert_contains "happy: scp backup reminder (§9.1)" "$FIN_OUT" \
    "scp -r $(sp_etc_dir)/keys/"
assert_eq "happy: ZERO cryptenroll invocations anywhere (ADR-19)" "0" \
    "$(grep -c . "$CE_LOG")"
for _m in "$U1" "$U2"; do
    assert_eq "happy: member $_m recovery passphrase verifies (any slot)" "0" \
        "$(pass_verifies "$LUKS_DIR/$_m.img" "$RECOVERY_PASS")"
    assert_eq "happy: member $_m recovery passphrase sits in keyslot 2 (next free at handoff)" "0" \
        "$(cryptsetup open --test-passphrase --key-slot 2 --key-file <(printf '%s' "$RECOVERY_PASS") "$LUKS_DIR/$_m.img" >/dev/null 2>&1; echo $?)"
    assert_eq "happy: member $_m exactly ONE passphrase slot beyond the token (the recovery slot)" "[2]" \
        "$(nontok_slots "$LUKS_DIR/$_m.img")"
    assert_eq "happy: member $_m ephemeral install key verifies NOWHERE (purged; rc 2)" "2" \
        "$(pass_verifies "$LUKS_DIR/$_m.img" "$EPH_SECRET")"
    assert_eq "happy: member $_m provisional secret retired by the upgrade (rc 2)" "2" \
        "$(pass_verifies "$LUKS_DIR/$_m.img" "$PROV_SECRET")"
    assert_eq "happy: member $_m exactly two keyslots remain (recovery + sealed)" \
        "2" "$(slots_of "$LUKS_DIR/$_m.img" | jq 'length')"
    assert_eq "happy: member $_m token upgraded to {PCR 7, PCR 11}" "[7,11]" \
        "$(tok_pcrs "$LUKS_DIR/$_m.img")"
    assert_eq "happy: member $_m exactly ONE systemd-tpm2 token" "1" \
        "$(tok_count "$LUKS_DIR/$_m.img")"
    assert_eq "happy: member $_m two luksAddKey (recovery slot + finalized seal slot)" "2" \
        "$(cs_for "$_m" luksAddKey)"
    assert_eq "happy: member $_m two luksKillSlot (ephemeral 0 + provisional 1)" "2" \
        "$(cs_for "$_m" luksKillSlot)"
    assert_eq "happy: member $_m token imported once" "1" \
        "$(cs_for "$_m" "token import")"
done
keys_is_encrypted "$KEYDIR/release.pem"
assert_rc "happy: release.pem is ADR-18-encrypted" 0 $?
assert_eq "happy: release.pem tightened to 0400" "400" "$(stat -c %a "$KEYDIR/release.pem")"
assert_not_contains "happy: MOTD banner cleared" "$(cat "$T/root/etc/motd")" \
    "$(fde_motd_banner)"
assert_not_contains "happy: issue banner cleared" "$(cat "$T/root/etc/issue")" \
    "$(fde_motd_banner)"
assert_eq "happy: MOTD operator content preserved" "$BANNER_LINE" "$(cat "$T/root/etc/motd")"
assert_eq "happy: issue operator content preserved" "$BANNER_LINE" "$(cat "$T/root/etc/issue")"

# --- 2b. provisional-booted state ⇒ full convergence WITHOUT double-apply --------
# Stage-2 wrote the new vocabulary, everything else already stands: the
# passphrase step skips (user slot verifies), the encryption skips (already
# ADR-18), audit --init skips (baseline final), the token upgrade skips
# (standing {7,11}) — observable as byte-identical metadata.
istate_write provisional-booted
reset_logs
LA_SNAP=$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)
M1_MD5=$(dump_md5 "$LUKS_DIR/$U1.img")
M2_MD5=$(dump_md5 "$LUKS_DIR/$U2.img")
run_finalize
assert_eq "provisional resume: rc 0" "0" "$FIN_RC"
assert_eq "provisional resume: state finalized" "finalized" "$(istate_state)"
assert_eq "provisional resume: member 1 metadata byte-identical (no double-apply)" \
    "$M1_MD5" "$(dump_md5 "$LUKS_DIR/$U1.img")"
assert_eq "provisional resume: member 2 metadata byte-identical" \
    "$M2_MD5" "$(dump_md5 "$LUKS_DIR/$U2.img")"
assert_eq "provisional resume: audit NOT re-run" "$LA_SNAP" \
    "$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)"
assert_eq "provisional resume: zero mutations on member 1" "0" \
    "$(( $(cs_for "$U1" luksAddKey) + $(cs_for "$U1" luksKillSlot) + $(cs_for "$U1" import) ))"
assert_eq "provisional resume: zero mutations on member 2" "0" \
    "$(( $(cs_for "$U2" luksAddKey) + $(cs_for "$U2" luksKillSlot) + $(cs_for "$U2" import) ))"

# --- 2c. re-run after success ⇒ loud no-op ----------------------------------------
CP_CS=$(cat "$CS_LOG")
run_finalize
assert_eq "already finalized: rc 0" "0" "$FIN_RC"
assert_contains "already finalized: loud no-op message" "$FIN_OUT" "already finalized"
assert_eq "already finalized: zero additional work" "$CP_CS" "$(cat "$CS_LOG")"

# =================================================================================
# 3. Crash matrix: interrupted mid-members ⇒ resume completes, no double-apply -----
# (§9.1 crash idempotency / §10 mid-finalization row): member 1 fails during the
# passphrase step (fail injection on its mutating cryptsetup calls) ⇒ die 64 with
# the member named, member 2 untouched, state NOT finalized, baseline still
# pending (the SB gate / audit sit AFTER the local steps). Resume (state
# provisional-booted) applies ONLY what is missing and converges.
sb_state 1 0
fresh_members
BL_PCR0=pending BL_PCR1=pending BL_PCR2=pending BL_PCR3=pending BL_PCR7=pending \
    BL_KEYS_RELEASE_PUB_PATH="$KEYDIR/release.pub" BL_TARGET_LUKS_UUID="$U1" \
    baseline_write "$(sp_baseline_file)"
istate_write installed
reset_logs
FAIL_MEMBER=$U1 run_finalize
FAIL_MEMBER=''
assert_eq "crash: rc 64" "64" "$FIN_RC"
assert_contains "crash: message names the failed member" "$FIN_OUT" "$U1"
assert_eq "crash: state stays installed" "installed" "$(istate_state)"
assert_eq "crash: member 2 untouched (still provisional [11])" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U2.img")"
assert_eq "crash: member 2 never reached (still at handoff: only the ephemeral slot 0)" "[0]" \
    "$(nontok_slots "$LUKS_DIR/$U2.img")"
assert_eq "crash: member 2 handoff intact (ephemeral verifies in slot 0)" "0" \
    "$(pass_verifies "$LUKS_DIR/$U2.img" "$EPH_SECRET")"
baseline_is_pending "$(sp_baseline_file)"
assert_rc "crash: baseline still pending (audit never ran)" 0 $?
reset_logs
rm -f "$(sp_last_audit_file)"
istate_write provisional-booted
run_finalize
assert_eq "crash resume: rc 0" "0" "$FIN_RC"
assert_eq "crash resume: state finalized" "finalized" "$(istate_state)"
assert_eq "crash resume: member 1 token {7,11}" "[7,11]" "$(tok_pcrs "$LUKS_DIR/$U1.img")"
assert_eq "crash resume: member 2 token {7,11}" "[7,11]" "$(tok_pcrs "$LUKS_DIR/$U2.img")"
baseline_is_final "$(sp_baseline_file)"
assert_rc "crash resume: baseline finalized (audit --init)" 0 $?
assert_file_exists "crash resume: last-audit written" "$(sp_last_audit_file)"
assert_eq "crash resume: member 2 passphrase opens = recovery skip-check + eph discovery (no re-apply)" "2" \
    "$(cs_for "$U2" open)"
assert_eq "crash resume: member 2 luksAddKey = recovery add + finalized seal add (each once)" "2" \
    "$(cs_for "$U2" luksAddKey)"
assert_eq "crash resume: member 2 token imported once" "1" \
    "$(cs_for "$U2" "token import")"
assert_eq "crash resume: member 1 passphrase + seal adds only (no third mutation)" \
    "2" "$(cs_for "$U1" luksAddKey)"

# =================================================================================
# 4. Wrong existing-passphrase key ⇒ loud 64, keyslot 0 NOT touched ----------------
sb_state 1 0
fresh_members
printf '%s' 'definitely-the-wrong-ephemeral-passphrase' >"$T/eph-wrong.bin"
rm -f "$KEYDIR/release.pem" # the happy path left it 0400 — genrsa cannot truncate it
openssl genrsa -out "$KEYDIR/release.pem" 2048 2>/dev/null # plaintext again
istate_write installed
reset_logs
DEBIAN_FDE_LUKS_KEYFILE=$T/eph-wrong.bin run_finalize
export DEBIAN_FDE_LUKS_KEYFILE=$T/eph.bin
assert_eq "wrong key: rc 64" "64" "$FIN_RC"
assert_contains "wrong key: loud message names the recovery passphrase add" "$FIN_OUT" \
    "recovery passphrase"
assert_eq "wrong key: state stays installed" "installed" "$(istate_state)"
assert_eq "wrong key: recovery passphrase added NOWHERE (step 1 died; rc 2)" "2" \
    "$(pass_verifies "$LUKS_DIR/$U1.img" "$RECOVERY_PASS")"
assert_eq "wrong key: handoff intact (ephemeral keyslot 0 still verifies)" "0" \
    "$(pass_verifies "$LUKS_DIR/$U1.img" "$EPH_SECRET")"
assert_eq "wrong key: token still provisional" "[11]" "$(tok_pcrs "$LUKS_DIR/$U1.img")"
assert_eq "wrong key: release.pem NOT yet encrypted (died in step 1)" "1" \
    "$(keys_is_encrypted "$KEYDIR/release.pem"; echo $?)"
assert_eq "wrong key: ZERO cryptenroll invocations" "0" "$(grep -c . "$CE_LOG")"

# --- 4b. §13 entropy floor enforced BEFORE any cryptsetup call --------------------
reset_logs
DEBIAN_FDE_RECOVERY_PASSPHRASE='short1!' run_finalize
assert_eq "weak passphrase: rc 64" "64" "$FIN_RC"
assert_contains "weak passphrase: floor named" "$FIN_OUT" "entropy floor"
assert_eq "weak passphrase: zero cryptsetup invocations" "0" "$(grep -c . "$CS_LOG")"
assert_eq "weak passphrase: state stays installed" "installed" "$(istate_state)"
export DEBIAN_FDE_RECOVERY_PASSPHRASE=$RECOVERY_PASS

# =================================================================================
# 5. state gate: garbage / absent --------------------------------------------------
printf '{"schema_version": 1, "state": "weird", "updated_at": "2026-09-19T00:00:00Z"}' \
    >"$(sp_etc_dir)/install-state.json"
run_finalize
assert_eq "garbage state: rc 64" "64" "$FIN_RC"
assert_contains "garbage state: message names the state" "$FIN_OUT" "unexpected install state"
rm -f "$(sp_etc_dir)/install-state.json"
reset_logs
run_finalize
assert_eq "absent state: rc 0" "0" "$FIN_RC"
assert_contains "absent state: loud no-op" "$FIN_OUT" "nothing to finalize"
assert_eq "absent state: zero cryptsetup calls" "0" "$(grep -c . "$CS_LOG")"

# --- 5b. CLI surface: help + unknown arg -------------------------------------------
run_finalize --help
assert_eq "finalize --help: rc 0" "0" "$FIN_RC"
assert_contains "finalize --help: usage" "$FIN_OUT" "Usage: debian-fde finalize"
FIN_OUT=$("$REPO/bin/debian-fde" finalize --bogus 2>&1)
FIN_RC=$?
assert_eq "finalize --bogus: usage rc 2" "2" "$FIN_RC"
assert_contains "finalize --bogus: named in the error" "$FIN_OUT" "unknown argument"

# --- 5c. the boot-time artifact: OpenRC ADVISORY oneshot (ADR-20 Stage 3;
# §9.1 step 7 ships /etc/init.d/alpine-fde-finalize). It NEVER runs the guided
# command: state != finalized ⇒ print the read-only SB state + guidance, rc 0
# ALWAYS (never blocks boot); finalized ⇒ quiet; zero cryptsetup/cryptenroll
# calls at runtime; no LUKS mutation vocabulary anywhere in the file. ----------
HOOK=$REPO/hooks/openrc/alpine-fde-finalize
assert_file_exists "finalize advisory hook exists" "$HOOK"
assert_eq "advisory: openrc-run shebang" "#!/sbin/openrc-run" "$(head -n1 "$HOOK")"
assert_eq "advisory: systemd unit deleted (ADR-20 Stage 3: finalize is GUIDED)" "0" \
    "$([ -e "$REPO/hooks/systemd/debian-fde-finalize.service" ] && echo 1 || echo 0)"
HOOK_TXT=$(cat "$HOOK")
assert_contains "advisory: depend() needs localmount" "$HOOK_TXT" "need localmount"
assert_not_contains "advisory: NEVER enrolls or wipes (no cryptsetup vocabulary)" "$HOOK_TXT" \
    "cryptsetup"
assert_not_contains "advisory: NEVER enrolls (no cryptenroll)" "$HOOK_TXT" "cryptenroll"
case $HOOK_TXT in
    *"$REPO/bin/debian-fde"* | *"cmd/finalize.sh"*)
        _fail "advisory: must not invoke the finalize command" ;;
    *) _pass "advisory: must not invoke the finalize command" ;;
esac
assert_contains "advisory: state-aware (finalized check)" "$HOOK_TXT" \
    "istate_is_finalized"
reset_logs
run_advisory() { # — source the hook in a subshell, call start(), print output
    (
        export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
        export DEBIAN_FDE_INSTALL_STATE="$T/advisory-state.json"
        export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
        # shellcheck disable=SC1090
        . "$REPO/hooks/openrc/alpine-fde-finalize"
        start
    ) 2>&1
}
printf '{\n  "schema_version": 1,\n  "state": "installed",\n  "updated_at": "x"\n}\n' \
    >"$T/advisory-state.json"
ADV_OUT=$(run_advisory)
ADV_RC=$?
assert_eq "advisory (installed): rc 0 (never blocks boot)" "0" "$ADV_RC"
assert_contains "advisory (installed): names the install state" "$ADV_OUT" "installed"
assert_contains "advisory (installed): carries the read-only SB state" "$ADV_OUT" \
    "secureboot="
assert_contains "advisory (installed): directs to the guided command" "$ADV_OUT" \
    "Run: alpine-fde finalize"
assert_eq "advisory (installed): ZERO cryptsetup invocations (advisory only)" "0" \
    "$(grep -c . "$CS_LOG")"
printf '{\n  "schema_version": 1,\n  "state": "finalized",\n  "updated_at": "x"\n}\n' \
    >"$T/advisory-state.json"
ADV_OUT=$(run_advisory)
ADV_RC=$?
assert_eq "advisory (finalized): rc 0" "0" "$ADV_RC"
assert_eq "advisory (finalized): quiet" "" "$ADV_OUT"
assert_eq "advisory (finalized): ZERO cryptsetup invocations" "0" "$(grep -c . "$CS_LOG")"

finish
