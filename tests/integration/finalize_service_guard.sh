#!/usr/bin/env bash
# tests/integration/finalize_service_guard.sh — AMENDED ADR-20 (§9.1 Stage 2/3, §7.2
# keyslot table, §12 S-25): the completion of trust finalization, exercised
# END-TO-END with the REAL command code against REAL collaborators: a
# swtpm-backed TPM (the Mechanism B seal ops are the production code path),
# REAL file-backed LUKS2 containers (the keyslot/token choreography mutates
# real metadata), the real audit --init, and the real ADR-18 release.pem
# encryption. Only the seams are stubbed: ALPINE_FDE_EFIVARS_DIR (firmware
# state), the ESP UKI .pcrsig carrier for the Stage-2 userspace re-unseal, a
# PATH systemd-cryptenroll TRIPWIRE (ADR-19: cryptenroll must never be invoked
# anywhere), a ALPINE_FDE_CRYPTSETUP logging/fail-injection wrapper around the
# REAL cryptsetup, and — ONLY in the Stage-2 service legs — seal_unseal
# (the fixture's provisional token is metadata-level, not a real TPM blob; the
# stub records the userspace re-unseal and hands back the provisional
# passphrase exactly as the real seal would).
#
# AMENDED KEYSLOT HANDOFF SHAPE (§7.2 / install.sh SLOT CONTRACT; the fixture
# mirrors what the §9.1 step-4 credential ceremony leaves behind):
#   keyslot 0 = the OPERATOR'S RECOVERY PASSPHRASE (Argon2id)
#   keyslot 1 = the provisional token slot (Mechanism B, PCR 11 only)
#   keyslot 2 = the TEMPORARY ephemeral install key — purged at completion
# ALPINE_FDE_LUKS_KEYFILE is RETIRED: NO leg sets it; the guided Stage 3 is
# authorized by the recovery passphrase (ALPINE_FDE_RECOVERY_PASSPHRASE seam
# — the interactive no-echo prompt is the default path), the Stage-2 service
# by re-unsealing the standing provisional token.
#
# Pinned invariants:
#   * state gate: installed | provisional-booted proceed; finalized loud
#     no-op; absent loud no-op; anything else fail-closed 64
#   * completion chain (Stage 2 == Stage 3, fin_completion_steps): SB guard
#     -> audit --init -> token upgrade {PCR 7, PCR 11} per member -> TEMPORARY
#     ephemeral keyslot purge per member -> state `finalized` LAST (ADR-8
#     attempt marker cleared, §8.4). ADR-20 amendment #4: the MOTD/issue
#     provisional banner path is REMOVED — no banner is ever written and
#     finalize never touches /etc/motd or /etc/issue.
#   * SB-off / SetupMode=1 => 64 + the §9.1 instruction text; NO audit, NO
#     token mutation, NO purge, state stays provisional (§12 S-21: nothing at
#     all happens under an unverified boot). ADR-20 amendment #3: this guard
#     is the SECOND blocking layer — the first is the initramfs pre-unseal
#     guard (§8.2 step 1); both refuse the same contract: the volume is never
#     finalized (nor unsealed) while Secure Boot is off.
#   * guided Stage 3: recovery passphrase verified against keyslot 0; a WRONG
#     passphrase is a BOUNDED retry (3 attempts) then die 64 + the ADR-8
#     attempt marker; the §13 floor is enforced before ANY cryptsetup call
#   * crash idempotency (§9.1): interrupted runs converge — audit skips when
#     the baseline is final, the upgrade skips when a standing token is
#     already {7,11}, the purge skips when the ephemeral slot is gone;
#     exactly keyslot 0 (recovery) remains beyond the sealed slot after
#     completion (I1 two-keyslot at-rest state)
#   * Stage-2 service (fin_service_main): NON-INTERACTIVE — rc 0 + finalized
#     when provisional + SB final; on ANY failure the ADR-8 attempt marker is
#     written and a NONZERO rc is returned (the OpenRC wrapper maps it to the
#     advisory + exit 0; boot is never blocked); finalized / missing /
#     corrupt state are silent degrade-safe no-ops
#   * zero systemd-cryptenroll invocations anywhere (ADR-19)

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/../unit/lib.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/policy.sh
source "$REPO/lib/policy.sh"
# shellcheck source=../../lib/keys.sh
source "$REPO/lib/keys.sh"
# shellcheck source=../../lib/seal.sh
source "$REPO/lib/seal.sh"
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

T=$(mktemp -d /tmp/alpine-fde-final.XXXXXX)
FAKEBIN=$T/bin
EFIVARS=$T/efivars
LUKS_DIR=$T/luks
BYUUID=$T/by-uuid
SHM=$T/shm
KEYDIR=$T/keys
ESP=$T/esp
U1=11111111-1111-4111-8111-111111111111
U2=22222222-2222-4222-8222-222222222222

RECOVERY_PASS='Fin4l-Rec0very-X9k2-!qmwjpz'
KEY_PASS='R3lease-K3ypass-X7!qmz'
EPH_SECRET='ephemeral-install-key-DO-NOT-PERSIST'
PROV_SECRET='provisional-sealed-secret-0123456789'

export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS
export ALPINE_FDE_BY_UUID_DIR=$BYUUID
export ALPINE_FDE_KEYDIR=$KEYDIR
export ALPINE_FDE_TMPDIR=$SHM
export ALPINE_FDE_CRYPTSETUP=$FAKEBIN/cs-wrapper
export ALPINE_FDE_RECOVERY_PASSPHRASE=$RECOVERY_PASS
export ALPINE_FDE_KEY_PASSPHRASE=$KEY_PASS
export ALPINE_FDE_PCRSIG=$T/pcrsig-711.json
export ALPINE_FDE_CONF=$T/none.conf
export ALPINE_FDE_NO_INSTALL=1
export CE_LOG=$T/cryptenroll.log CS_LOG=$T/cs.log SVC_LOG=$T/svc.log
export LUKS_DIR FAIL_ADD_MEMBER='' FAIL_KILL_MEMBER=''
# ALPINE_FDE_LUKS_KEYFILE is RETIRED (§9.1 Stage 3) — deliberately NOT set;
# the static leg below pins it out of the implementation.

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$FAKEBIN" "$EFIVARS" "$LUKS_DIR" "$BYUUID" "$SHM" "$KEYDIR" \
    "$(sp_etc_dir)" "$T/root/etc" "$T/swtpm" "$ESP/EFI/Linux"

# --- static contract: the ephemeral-key handoff seam is RETIRED ------------------
assert_eq "static: ALPINE_FDE_LUKS_KEYFILE retired from all CODE (comment-only mentions)" "0" \
    "$(grep -c '^[^#]*ALPINE_FDE_LUKS_KEYFILE' "$REPO/lib/cmd/finalize.sh")"
assert_contains "static: guided usage documents the recovery-passphrase seam" \
    "$(cat "$REPO/lib/cmd/finalize.sh")" "ALPINE_FDE_RECOVERY_PASSPHRASE"
assert_contains "static: Stage-2 service entry point exists" \
    "$(cat "$REPO/lib/cmd/finalize.sh")" "fin_service_main()"

# --- seams -----------------------------------------------------------------------
# ADR-19 tripwire: systemd-cryptenroll must NEVER be invoked by anything in the
# finalize flow (Mechanism B is the only seal path). Record and fail.
cat >"$FAKEBIN/systemd-cryptenroll" <<EOF
#!/bin/sh
echo "CALL $*" >>'$CE_LOG'
exit 1
EOF
chmod +x "$FAKEBIN/systemd-cryptenroll"
# cryptsetup wrapper: LOG every invocation, optionally fail every call of one
# member (FAIL_ADD_MEMBER: mutating adds; FAIL_KILL_MEMBER: keyslot kills; both
# read at RUNTIME so each finalize invocation injects a different failure),
# then exec the REAL cryptsetup — the metadata effects are always real.
REAL_CS=$(command -v cryptsetup)
cat >"$FAKEBIN/cs-wrapper" <<EOF
#!/bin/sh
printf 'CALL %s\\n' "\$*" >>'$CS_LOG'
if [ -n "\$FAIL_ADD_MEMBER" ]; then
    case "\$*" in
        *\$FAIL_ADD_MEMBER*)
            [ "\$1" = luksAddKey ] && exit 1 ;;
    esac
fi
if [ -n "\$FAIL_KILL_MEMBER" ]; then
    case "\$*" in
        *\$FAIL_KILL_MEMBER*)
            [ "\$1" = luksKillSlot ] && exit 1 ;;
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
export ALPINE_FDE_TCTI=$SWTPM_TCTI
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

# --- release keys (HERMETIC: generated here; the flow CONSUMES them — the
# Stage-1 credential ceremony already encrypted release.pem per the amended
# ADR-18/ADR-20, mirrored below) ---------------------------------------------------
openssl genrsa -out "$KEYDIR/release.pem" 2048 2>/dev/null
openssl pkey -in "$KEYDIR/release.pem" -pubout -out "$KEYDIR/release.pub" 2>/dev/null
openssl req -new -x509 -key "$KEYDIR/release.pem" -out "$KEYDIR/release.crt" \
    -subj /CN=alpine-fde-finalize-ci 2>/dev/null
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
    >"$ALPINE_FDE_PCRSIG"

# Option A digest-ANCHOR fixtures (same composition + the d7/d11 anchor fields
# policy_sign_json now records). ANCH-FOREIGN is self-consistent
# (policy_digest(d7', d11') == its signed pol) but its anchors deliberately
# DIFFER from the live swtpm PCRs — the digest-anchored G-B6 must accept it
# WITHOUT a live read (fail-at-unseal replaces fail-at-seal). ANCH-BROKEN
# records anchors that do NOT recompute to its signed pol — the gate must
# refuse. Signed here, BEFORE the ADR-18 encryption mirrors the ceremony.
HEX_AB=$(printf 'ab%.0s' {1..32})
HEX_CD=$(printf 'cd%.0s' {1..32})
mk_anch_pcrsig() { # OUT D7 D11
    local _out=$1 _d7=$2 _d11=$3 _pol _sig _pkfp
    _pol=$(policy_digest "$_d7" "$_d11")
    printf '%s' "$_pol" | policy_hex_to_bin >"$T/anch.bin"
    openssl dgst -sha256 -sign "$KEYDIR/release.pem" -out "$T/anch.sig" "$T/anch.bin" 2>/dev/null
    _sig=$(openssl base64 -A -in "$T/anch.sig")
    _pkfp=$(policy_pubkey_fp "$KEYDIR/release.pub")
    jq -n --arg pol "$_pol" --arg sig "$_sig" --arg pkfp "$_pkfp" \
        --arg d7 "$_d7" --arg d11 "$_d11" \
        '{"sha256": [{pcrs: [7, 11], pkfp: $pkfp, pol: $pol, sig: $sig,
                      d7: $d7, d11: $d11}]}' >"$_out"
}
mk_anch_pcrsig "$T/pcrsig-anch-foreign.json" "$HEX_AB" "$HEX_CD"
mk_anch_pcrsig "$T/pcrsig-anch-broken.json" "$HEX_AB" "$HEX_CD"
jq --arg ee "$(printf 'ee%.0s' {1..32})" '.sha256[0].d7 = $ee' \
    "$T/pcrsig-anch-broken.json" >"$T/pcrsig-anch-broken2.json" &&
    mv "$T/pcrsig-anch-broken2.json" "$T/pcrsig-anch-broken.json"

# --- Stage-1 ceremony mirror: release.pem encrypted (ADR-18), ESP UKI .pcrsig ---
ALPINE_FDE_KEY_PASSPHRASE=$KEY_PASS keys_encrypt_release "$KEYDIR"
keys_is_encrypted "$KEYDIR/release.pem"
assert_rc "stage-1 mirror: release.pem ADR-18-encrypted (ceremony 3/3 output)" 0 $?
# the ESP UKI carrier: the .pcrsig section the Stage-2 userspace re-unseal
# reads from the just-booted UKI (fin_uki_pcrsig). Content is irrelevant here —
# the service legs stub seal_unseal — but the extraction must succeed.
printf 'fake-uki-stub-body' >"$T/uki-body.bin"
printf '{"sha256":[{"pcrs":[11],"pol":"stub"}]}' >"$T/uki-pcrsig.json"
objcopy -I binary -O elf64-x86-64 -B i386 \
    --add-section .pcrsig="$T/uki-pcrsig.json" --set-section-flags .pcrsig=alloc,readonly \
    "$T/uki-body.bin" "$ESP/EFI/Linux/alpine-fde-6.12.efi" 2>/dev/null
[ -s "$ESP/EFI/Linux/alpine-fde-6.12.efi" ] || {
    echo "FAIL: could not build the ESP UKI .pcrsig fixture" >&2
    exit 1
}

# --- LUKS2 member fixture: the AMENDED ADR-20 handoff topology (§7.2) ------------
# keyslot 2 = temporary ephemeral install key (luksFormat), keyslot 0 = the
# operator's recovery passphrase (the §9.1 step-4 ceremony's luksAddKey,
# authorized by the ephemeral key), keyslot 1 = provisional token slot.
KDFARGS=(--pbkdf argon2id --pbkdf-memory 16000 --pbkdf-parallel 1 --pbkdf-force-iterations 4)
printf '%s' "$EPH_SECRET" >"$T/eph.bin"
printf '%s' "$PROV_SECRET" >"$T/prov.bin"
printf '%s' "$RECOVERY_PASS" >"$T/rec.bin"
mk_member() { # IMG — real file-backed LUKS2 container in the amended handoff shape
    truncate -s 24M "$1"
    cryptsetup luksFormat -q --type luks2 --key-slot 2 --key-file "$T/eph.bin" \
        "${KDFARGS[@]}" "$1"
    cryptsetup luksAddKey "${KDFARGS[@]}" --key-slot 0 --key-file "$T/eph.bin" \
        "$1" "$T/rec.bin"
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
pending_baseline() {
    BL_PCR0=pending BL_PCR1=pending BL_PCR2=pending BL_PCR3=pending BL_PCR7=pending \
        BL_KEYS_RELEASE_PUB_PATH="$KEYDIR/release.pub" BL_TARGET_LUKS_UUID="$U1" \
        baseline_write "$(sp_baseline_file)"
}
printf 'root1 UUID=%s none luks,tpm2-device=auto,discard\nroot2 UUID=%s none luks,tpm2-device=auto,discard\n' \
    "$U1" "$U2" >"$T/root/etc/crypttab"
BANNER_LINE='rootfs is ready — keep this line'
fresh_banners() {
    # ADR-20 amendment #4: NO unfinalized banner exists anymore — the fixture
    # carries operator content only, and the completion must never touch it
    printf '%s\n' "$BANNER_LINE" >"$T/root/etc/motd"
    printf '%s\n' "$BANNER_LINE" >"$T/root/etc/issue"
}
fresh_stage() { # — full amended first-boot state: members + pending baseline + motd/issue
    fresh_members
    pending_baseline
    rm -f "$(sp_last_audit_file)" 2>/dev/null || :
    istate_attempt_clear
    fresh_banners
}

# --- drivers ----------------------------------------------------------------------
run_finalize() { # — the GUIDED Stage 3 (bin entrypoint; env supplies the
    # recovery passphrase — the interactive no-echo prompt is the tty default)
    FIN_OUT=$("$REPO/bin/alpine-fde" finalize "$@" 2>&1)
    FIN_RC=$?
}
run_service() { # $1 — optional ALPINE_FDE_ESP override (unseal-failure legs).
    # — the Stage-2 auto-finalizer (fin_service_main) with ONLY the
    # userspace re-unseal stubbed: the stub RECORDS the invocation (proof the
    # authorization is the standing provisional token, never a credential env)
    # and hands back the provisional passphrase exactly as the real seal would.
    : >"$SVC_LOG"
    SVC_OUT=$(
        exec 2>&1
        unset ALPINE_FDE_RECOVERY_PASSPHRASE ALPINE_FDE_LUKS_KEYFILE
        unset ALPINE_FDE_KEY_PASSPHRASE
        export ALPINE_FDE_ESP=${1:-$ESP}
        (
            # shellcheck source=../../lib/cmd/finalize.sh
            . "$REPO/lib/cmd/finalize.sh"
            seal_unseal() { # <keydir> <pcrsig> <mode> <token.json> <out>
                printf 'seal_unseal mode=%s\n' "$3" >>"$SVC_LOG"
                [ "$3" = "provisional" ] || return 1
                printf '%s' "$PROV_SECRET" >"$5"
                chmod 600 "$5"
            }
            fin_service_main
        )
    )
    SVC_RC=$?
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
marker_rc() { # — rc of the attempt-marker presence check, captured for assert_rc
    istate_attempt_present >/dev/null 2>&1
    echo $?
}
assert_member_final() { # DESC UUID — the I1 at-rest shape after completion
    local d="$1" m="$LUKS_DIR/$2.img"
    assert_eq "$d: token upgraded to Mechanism B {PCR 7, PCR 11}" "[7,11]" \
        "$(tok_pcrs "$m")"
    assert_eq "$d: exactly ONE systemd-tpm2 token" "1" "$(tok_count "$m")"
    assert_eq "$d: exactly the recovery keyslot 0 remains beyond the token (I1)" \
        "[0]" "$(nontok_slots "$m")"
    assert_eq "$d: exactly two keyslots remain (recovery + sealed)" "2" \
        "$(slots_of "$m" | jq 'length')"
    assert_eq "$d: recovery passphrase verifies in keyslot 0" "0" \
        "$(cryptsetup open --test-passphrase --key-slot 0 --key-file <(printf '%s' "$RECOVERY_PASS") "$m" >/dev/null 2>&1; echo $?)"
    assert_eq "$d: temporary ephemeral install key verifies NOWHERE (purged; rc 2)" "2" \
        "$(pass_verifies "$m" "$EPH_SECRET")"
    assert_eq "$d: provisional secret retired by the completion (rc 2)" "2" \
        "$(pass_verifies "$m" "$PROV_SECRET")"
}

# =================================================================================
# 1. state gate: absent / finalized / garbage (§8.4) -------------------------------
rm -f "$(sp_etc_dir)/install-state.json"
reset_logs
run_finalize
assert_eq "absent state: rc 0" "0" "$FIN_RC"
assert_contains "absent state: loud no-op" "$FIN_OUT" "nothing to finalize"
assert_eq "absent state: zero cryptsetup calls" "0" "$(grep -c . "$CS_LOG")"

istate_write finalized
run_finalize
assert_eq "already finalized: rc 0" "0" "$FIN_RC"
assert_contains "already finalized: loud no-op message" "$FIN_OUT" "already finalized"
assert_eq "already finalized: zero cryptsetup calls" "0" "$(grep -c . "$CS_LOG")"

printf '{"schema_version": 1, "state": "weird", "updated_at": "2026-09-19T00:00:00Z"}' \
    >"$(sp_etc_dir)/install-state.json"
run_finalize
assert_eq "garbage state: rc 64" "64" "$FIN_RC"
assert_contains "garbage state: message names the state" "$FIN_OUT" "unexpected install state"

# --- 1b. CLI surface: help + unknown arg -------------------------------------------
run_finalize --help
assert_eq "finalize --help: rc 0" "0" "$FIN_RC"
assert_contains "finalize --help: usage" "$FIN_OUT" "Usage: alpine-fde finalize"
assert_contains "finalize --help: names the recovery-passphrase authorization" "$FIN_OUT" \
    "recovery passphrase"
FIN_OUT=$("$REPO/bin/alpine-fde" finalize --bogus 2>&1)
FIN_RC=$?
assert_eq "finalize --bogus: usage rc 2" "2" "$FIN_RC"
assert_contains "finalize --bogus: named in the error" "$FIN_OUT" "unknown argument"

# =================================================================================
# 2. SB off ⇒ 64 + §9.1 instruction, NOTHING mutated (§12 S-21 amended: the
# guard is the FIRST completion step — no local keyslot work precedes it) ----------
sb_state 0 0
fresh_stage
istate_write provisional-booted
reset_logs
run_finalize
assert_eq "SB off: rc 64" "64" "$FIN_RC"
assert_contains "SB off: §9.1 instruction text" "$FIN_OUT" \
    "Secure Boot is not enabled with your custom keys"
assert_contains "SB off: instruction names the BIOS action" "$FIN_OUT" \
    "Reboot into BIOS setup and toggle Secure Boot ON"
assert_eq "SB off: install state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"
baseline_is_pending "$(sp_baseline_file)"
assert_rc "SB off: baseline still pending (no audit --init)" 0 $?
assert_eq "SB off: no last-audit written" "absent" \
    "$([ -f "$(sp_last_audit_file)" ] && echo present || echo absent)"
assert_eq "SB off: ZERO cryptenroll invocations (ADR-19 tripwire)" "0" \
    "$(grep -c . "$CE_LOG")"
for _m in "$U1" "$U2"; do
    assert_eq "SB off: member $_m token untouched (still provisional [11])" "[11]" \
        "$(tok_pcrs "$LUKS_DIR/$_m.img")"
    assert_eq "SB off: member $_m handoff intact (ephemeral slot still present)" "0" \
        "$(pass_verifies "$LUKS_DIR/$_m.img" "$EPH_SECRET")"
    assert_eq "SB off: member $_m recovery slot 0 intact" "0" \
        "$(pass_verifies "$LUKS_DIR/$_m.img" "$RECOVERY_PASS")"
done
assert_contains "SB off: motd untouched (no banner was ever written; the banner path is removed)" \
    "$(cat "$T/root/etc/motd")" "$BANNER_LINE"
assert_rc "SB off: NO attempt marker (the guided path dies loud instead)" 1 "$(marker_rc)"
keys_is_encrypted "$KEYDIR/release.pem"
assert_rc "SB off: release.pem already encrypted (the Stage-1 ceremony did it)" 0 $?

# --- 2b. SetupMode=1 is equally refused (keys not in the final state) ------------
sb_state 1 1
run_finalize
assert_eq "SetupMode=1: rc 64" "64" "$FIN_RC"
assert_contains "SetupMode=1: refusal names Secure Boot" "$FIN_OUT" "Secure Boot"
assert_eq "SetupMode=1: state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"

# =================================================================================
# 3. Guided happy path (state provisional-booted, Secure Boot on) ⇒ the full
# AMENDED Stage-3 completion — authorized by the recovery passphrase, with NO
# keyfile env set anywhere ----------------------------------------------------------
sb_state 1 0
fresh_stage
istate_write provisional-booted
reset_logs
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
assert_rc "happy: ADR-8 attempt marker cleared on success" 1 "$(marker_rc)"
for _m in "$U1" "$U2"; do
    assert_member_final "happy: member $_m" "$_m"
    assert_eq "happy: member $_m ONE luksAddKey (the finalized seal slot only — recovery was the ceremony's)" "1" \
        "$(cs_for "$_m" luksAddKey)"
    assert_eq "happy: member $_m TWO luksKillSlot (provisional slot 1 + temporary ephemeral slot 2)" "2" \
        "$(cs_for "$_m" luksKillSlot)"
    assert_eq "happy: member $_m token imported once" "1" \
        "$(cs_for "$_m" "token import")"
done
keys_is_encrypted "$KEYDIR/release.pem"
assert_rc "happy: release.pem still ADR-18-encrypted (crash-skip, ceremony already did it)" 0 $?
assert_not_contains "happy: NO banner writeback (the ADR-20 #4 banner path is removed; motd untouched)" \
    "$(cat "$T/root/etc/motd")" "fde_motd_banner"
assert_eq "happy: motd operator content preserved byte-exactly (finalize never touches it)" \
    "$BANNER_LINE" "$(cat "$T/root/etc/motd")"
assert_eq "happy: issue operator content preserved byte-exactly" \
    "$BANNER_LINE" "$(cat "$T/root/etc/issue")"

# --- 3b. re-run after success ⇒ loud no-op -----------------------------------------
CP_CS=$(cat "$CS_LOG")
run_finalize
assert_eq "already finalized (post-run): rc 0" "0" "$FIN_RC"
assert_contains "already finalized (post-run): loud no-op message" "$FIN_OUT" \
    "already finalized"
assert_eq "already finalized (post-run): zero additional work" "$CP_CS" "$(cat "$CS_LOG")"

# =================================================================================
# 4. Crash matrix A: interrupted DURING the token upgrade ⇒ die 64 with the
# member named; resume applies ONLY what is missing (§9.1 crash idempotency) -------
sb_state 1 0
fresh_stage
istate_write provisional-booted
reset_logs
FAIL_ADD_MEMBER=$U1 run_finalize
FAIL_ADD_MEMBER=''
assert_eq "crash A: rc 64" "64" "$FIN_RC"
assert_contains "crash A: message names the failed member" "$FIN_OUT" "$U1"
assert_eq "crash A: state stays provisional-booted" "provisional-booted" "$(istate_state)"
assert_eq "crash A: member 2 untouched (still provisional [11])" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U2.img")"
assert_eq "crash A: member 2 ephemeral slot intact" "0" \
    "$(pass_verifies "$LUKS_DIR/$U2.img" "$EPH_SECRET")"
baseline_is_final "$(sp_baseline_file)"
assert_rc "crash A: baseline ALREADY finalized (audit ran before the upgrade died)" 0 $?
LA_SNAP=$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)
reset_logs
run_finalize
assert_eq "crash A resume: rc 0" "0" "$FIN_RC"
assert_eq "crash A resume: state finalized" "finalized" "$(istate_state)"
assert_eq "crash A resume: audit NOT re-run" "$LA_SNAP" \
    "$(md5sum "$(sp_last_audit_file)" | cut -d' ' -f1)"
for _m in "$U1" "$U2"; do
    assert_member_final "crash A resume: member $_m" "$_m"
done
assert_eq "crash A resume: member 2 needed exactly ONE add + TWO kills (no re-apply)" "3" \
    "$(( $(cs_for "$U2" luksAddKey) + $(cs_for "$U2" luksKillSlot) ))"

# =================================================================================
# 4b. Crash matrix B: interrupted BETWEEN the upgrade and the purge (the
# upgrade already stands; the ephemeral slot survives) ⇒ resume purges only ------
sb_state 1 0
fresh_stage
istate_write provisional-booted
# simulate the crash: perform the upgrade step by hand for BOTH members, then
# stop — exactly the post-upgrade pre-purge state (§9.1 Stage 2 step 3 done)
printf '%s' "$RECOVERY_PASS" >"$T/auth.bin"
chmod 600 "$T/auth.bin"
for _m in "$U1" "$U2"; do
    seal_upgrade_token "$KEYDIR" "$LUKS_DIR/$_m.img" "$ALPINE_FDE_PCRSIG" \
        "$T/token-crash-$_m.json" "$T/auth.bin" || {
        echo "FAIL: crash-B fixture upgrade failed for $_m" >&2
        exit 1
    }
done
reset_logs
FAIL_KILL_MEMBER=$U1 run_finalize
FAIL_KILL_MEMBER=''
assert_eq "crash B: rc 64" "64" "$FIN_RC"
assert_contains "crash B: message names the failed member + the purge" "$FIN_OUT" \
    "$U1"
assert_contains "crash B: message names the ephemeral purge" "$FIN_OUT" \
    "ephemeral"
assert_eq "crash B: state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"
assert_eq "crash B: member 1 token already {7,11} (the upgrade HAD completed)" "[7,11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"
assert_eq "crash B: member 1 ephemeral slot STILL present (the purge died)" "0" \
    "$(pass_verifies "$LUKS_DIR/$U1.img" "$EPH_SECRET")"
reset_logs
run_finalize
assert_eq "crash B resume: rc 0" "0" "$FIN_RC"
assert_eq "crash B resume: state finalized" "finalized" "$(istate_state)"
for _m in "$U1" "$U2"; do
    assert_member_final "crash B resume: member $_m" "$_m"
done
assert_eq "crash B resume: member 1 re-ran ZERO luksAddKey (upgrade crash-skipped)" "0" \
    "$(cs_for "$U1" luksAddKey)"
assert_eq "crash B resume: member 1 ran exactly ONE luksKillSlot (the missed purge)" "1" \
    "$(cs_for "$U1" luksKillSlot)"

# =================================================================================
# 4c. Digest-anchored G-B6 (Option A): the upgrade's .pcrsig gate recomputes the
# policy digest from the entry's OWN recorded d7/d11 components — a pure data
# check, NO live TPM PCR read ----------------------------------------------
sb_state 1 0
fresh_stage
istate_write provisional-booted
printf '%s' "$RECOVERY_PASS" >"$T/auth-anch.bin"
chmod 600 "$T/auth-anch.bin"
ANCH_RC=0
seal_upgrade_token "$KEYDIR" "$LUKS_DIR/$U1.img" "$T/pcrsig-anch-foreign.json" \
    "$T/token-anch.json" "$T/auth-anch.bin" 2>>"$T/anch.err" || ANCH_RC=$?
assert_rc "anchored G-B6: upgrade rc 0 with anchors != live PCRs (no live read)" 0 "$ANCH_RC"
assert_eq "anchored G-B6: member 1 token is the finalized {7,11}" "[7,11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"
# INCONSISTENT anchors (recorded d7 does not recompute to the signed pol):
# the gate refuses BEFORE any LUKS2 mutation
fresh_stage
istate_write provisional-booted
BROKEN_RC=0
seal_upgrade_token "$KEYDIR" "$LUKS_DIR/$U1.img" "$T/pcrsig-anch-broken.json" \
    "$T/token-anch-broken.json" "$T/auth-anch.bin" 2>>"$T/anch.err" || BROKEN_RC=$?
assert_rc "anchored G-B6: inconsistent d7/d11 vs signed pol -> refuse" 1 "$BROKEN_RC"
assert_contains "anchored G-B6: refusal names the stale/tampered digest" \
    "$(cat "$T/anch.err")" "stale/tampered"
assert_eq "anchored G-B6: refusal left the token provisional" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"

# =================================================================================
# 5. Wrong recovery passphrase ⇒ BOUNDED retry (3) then die 64 + the ADR-8
# attempt marker; NO keyslot mutation at all (§9.1 Stage 3 authorization) ----------
sb_state 1 0
fresh_stage
istate_write provisional-booted
reset_logs
ALPINE_FDE_RECOVERY_PASSPHRASE='definitely-not-it-X9k2-!qmwjpz' run_finalize
assert_eq "wrong passphrase: rc 64" "64" "$FIN_RC"
assert_contains "wrong passphrase: loud message names keyslot 0" "$FIN_OUT" \
    "keyslot 0"
assert_contains "wrong passphrase: message names the bounded retry" "$FIN_OUT" \
    "after 3 attempts"
assert_eq "wrong passphrase: state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"
assert_rc "wrong passphrase: ADR-8 attempt marker WRITTEN (§8.4)" 0 "$(marker_rc)"
assert_contains "wrong passphrase: marker carries the guided reason" \
    "$(istate_attempt_read)" "recovery passphrase rejected"
assert_eq "wrong passphrase: exactly THREE verify attempts (bounded)" "3" \
    "$(grep -c 'CALL open --test-passphrase' "$CS_LOG")"
assert_eq "wrong passphrase: ZERO mutations (no add, no kill, no import)" "0" \
    "$(( $(grep -cE 'CALL (luksAddKey|luksKillSlot|token import)' "$CS_LOG") ))"
assert_eq "wrong passphrase: token still provisional" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"

# --- 5b. §13 entropy floor enforced BEFORE any cryptsetup call --------------------
reset_logs
ALPINE_FDE_RECOVERY_PASSPHRASE='short1!' run_finalize
assert_eq "weak passphrase: rc 64" "64" "$FIN_RC"
assert_contains "weak passphrase: floor named" "$FIN_OUT" "entropy floor"
assert_eq "weak passphrase: zero cryptsetup invocations" "0" "$(grep -c . "$CS_LOG")"
assert_eq "weak passphrase: state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"

# =================================================================================
# 6. Stage-2 SERVICE (fin_service_main): non-interactive completion authorized
# by re-unsealing the standing provisional token — NEVER a credential env -------
sb_state 1 0
fresh_stage
istate_write provisional-booted
reset_logs
run_service
assert_eq "service: rc 0" "0" "$SVC_RC"
assert_eq "service: state finalized" "finalized" "$(istate_state)"
assert_contains "service: the provisional token WAS re-unsealed in userspace" \
    "$(cat "$SVC_LOG")" "seal_unseal mode=provisional"
assert_eq "service: re-unseal happened exactly once" "1" "$(grep -c . "$SVC_LOG")"
baseline_is_final "$(sp_baseline_file)"
assert_rc "service: baseline captured (audit --init)" 0 $?
assert_rc "service: ADR-8 attempt marker cleared on success" 1 "$(marker_rc)"
for _m in "$U1" "$U2"; do
    assert_member_final "service: member $_m" "$_m"
done
assert_not_contains "service: NO banner writeback (motd untouched)" \
    "$(cat "$T/root/etc/motd")" "fde_motd_banner"
assert_eq "service: MOTD operator content preserved" "$BANNER_LINE" \
    "$(cat "$T/root/etc/motd")"
assert_eq "service: ZERO cryptenroll invocations (ADR-19)" "0" "$(grep -c . "$CE_LOG")"
assert_eq "service: motd untouched (no banner path, ADR-20 #4)" "$BANNER_LINE" \
    "$(cat "$T/root/etc/motd")"

# --- 6b. service: re-run with state finalized ⇒ silent rc 0 (idempotent) ---------
reset_logs
run_service
assert_eq "service (finalized): rc 0" "0" "$SVC_RC"
assert_eq "service (finalized): quiet" "" "$SVC_OUT"
assert_eq "service (finalized): ZERO invocations" "0" "$(grep -c . "$CS_LOG")"
assert_eq "service (finalized): no re-unseal" "0" "$(grep -c . "$SVC_LOG")"

# --- 6c. service: SB guard failure ⇒ nonzero rc + attempt marker + NO mutation;
# the OpenRC wrapper maps this to the advisory + exit 0 (never blocks boot) -----
sb_state 0 0
fresh_stage
istate_write provisional-booted
reset_logs
run_service
assert_eq "service (SB off): rc NONZERO (wrapper maps to advisory + exit 0)" "1" "$SVC_RC"
assert_eq "service (SB off): state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"
assert_rc "service (SB off): ADR-8 attempt marker WRITTEN" 0 "$(marker_rc)"
assert_contains "service (SB off): marker names the completion failure" \
    "$(istate_attempt_read)" "completion step failed"
assert_eq "service (SB off): token untouched" "[11]" \
    "$(tok_pcrs "$LUKS_DIR/$U1.img")"
assert_eq "service (SB off): ephemeral slot untouched" "0" \
    "$(pass_verifies "$LUKS_DIR/$U1.img" "$EPH_SECRET")"
baseline_is_pending "$(sp_baseline_file)"
assert_rc "service (SB off): baseline still pending" 0 $?
assert_contains "service (SB off): the blocking guard refusal names Secure Boot (second blocking layer, ADR-20 #3)" \
    "$SVC_OUT" "Secure Boot is not enabled with your custom keys"
assert_contains "service (SB off): the refusal names the BIOS remedy" "$SVC_OUT" \
    "Reboot into BIOS setup and toggle Secure Boot ON"
assert_eq "service (SB off): motd untouched (no banner path, ADR-20 #4)" "$BANNER_LINE" \
    "$(cat "$T/root/etc/motd")"

# --- 6d. service: unseal failure (PCR drift / no .pcrsig) ⇒ marker + retry ------
sb_state 1 0
fresh_stage
istate_write provisional-booted
reset_logs
run_service "$T/no-such-esp"
assert_eq "service (unseal fail): rc NONZERO" "1" "$SVC_RC"
assert_eq "service (unseal fail): state stays provisional-booted" "provisional-booted" \
    "$(istate_state)"
assert_rc "service (unseal fail): ADR-8 attempt marker WRITTEN" 0 "$(marker_rc)"
assert_contains "service (unseal fail): marker names the re-unseal" \
    "$(istate_attempt_read)" "re-unseal"
assert_eq "service (unseal fail): ZERO cryptsetup mutations" "0" \
    "$(( $(grep -cE 'CALL (luksAddKey|luksKillSlot|token import)' "$CS_LOG") ))"

# --- 6e. service: missing / corrupt state ⇒ silent degrade, rc 0 -----------------
sb_state 1 0
reset_logs
rm -f "$(sp_etc_dir)/install-state.json"
run_service
assert_eq "service (absent state): rc 0" "0" "$SVC_RC"
assert_eq "service (absent state): quiet" "" "$SVC_OUT"
assert_eq "service (absent state): zero cryptsetup calls" "0" "$(grep -c . "$CS_LOG")"
printf 'not json {{\n' >"$(sp_etc_dir)/install-state.json"
run_service
assert_eq "service (corrupt state): rc 0" "0" "$SVC_RC"
assert_eq "service (corrupt state): quiet" "" "$SVC_OUT"
assert_eq "service (corrupt state): zero cryptsetup calls" "0" "$(grep -c . "$CS_LOG")"

finish
