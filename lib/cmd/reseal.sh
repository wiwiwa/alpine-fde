#!/bin/sh
# reseal.sh — `alpine-fde reseal`: Mechanism B TPM-seal enrollment
# (§6.1/§7.1/§9.1/§9.4; ADR-19/ADR-20; gaps G-B3/G-B5/G-B6/G-B7). Alpine has
# NO systemd-cryptenroll (ADR-19): the seal is lib/seal.sh (tpm2-tools) and the
# LUKS2 choreography is lib/token.sh — cryptsetup stays the only LUKS2 seam.
# A guest/installed-system tool (needs the TPM via the configured TCTI); unit
# tests exercise the logic via stubs + the swtpm fixture. Also the shared
# enrollment core of `kernel build`: reseal_run / reseal_ensure_once are the
# callable seam the build's ensure-once step reuses (§8.1: the enrollment is
# internal to the build; `reseal` is the operator-facing spelling).
#
# Preconditions (fail-closed, in order):
#   1. policy_mode gate (ADR-19: b canonical; a2/native aliases; a / ap exit 64)
#   2. finalized baseline (expected_pcr7 != pending — finalize via audit --init)
#   3. Secure Boot on AND SetupMode=0 (efivarfs seam)
#   4. PCR 7 digest-anchored baseline: when a .pcrsig with anchor fields is
#      supplied, the entry the seal will use must carry d7 ==
#      baseline.expected_pcr7 (PURE data comparison — no live TPM read,
#      Option A: the guest's console-measured PCR 7 IS the machine state and
#      PolicyPCR enforces it fail-closed at UNSEAL). Legacy anchor-less
#      .pcrsig / the in-process re-sign path keep the live-PCR-7 oracle
#      (tpm() pcrread) as the production advisory refusal.
#   5. release public key present in the KEYDIR (keys_dir; NEVER the baseline's
#      keys.release_pub_path — G-B7: keydir-explicit so K1->K2 rotation +
#      re-enroll anchors under the keydir the operator selected) AND RSA >=
#      3072 bits (ADR-16 fail-closed rc 2, keys_rsa3072_guard)
#   6. LUKS device resolvable via /dev/disk/by-uuid/<baseline target.luks_uuid>
#   7. a usable TPM via TCTI (tpm2 getcap probe; seal_require_env)
# Then reseal_run: the Mechanism B enrollment (seal under the finalized {7,11}
# policy + keyslot + token + retire-on-reseat), post-asserted via
# `cryptsetup luksDump --dump-json-metadata` (exactly one systemd-tpm2 token,
# pubkey == the keydir release key, pcrs [7,11], keyslot != 0, recovery
# keyslot 0 byte-identical), then enrolled.json.
#
# Signed-policy source (§9.1 step 6): --pcrsig FILE (or ALPINE_FDE_PCRSIG env)
# supplies the release-key-signed .pcrsig JSON the seal embeds; its entry is
# verified openssl-level against the policy digest recomputed from the entry's
# own anchored d7/d11 components BEFORE anything is embedded (G-B6, digest-
# anchored — no live PCR read). Without one, reseal re-signs in-process
# from the keydir's release.pem (keys_unlock; ADR-18) over the CURRENT PCR 7/11
# — the §9.4 re-enroll path (re-captures the new current PCR 7; live-read
# precondition kept).
#
# Recovery semantics (§9.4): an existing TPM enrollment is retired in the SAME
# run as the fresh one is standing (add new keyslot + token FIRST, then remove
# the old token + kill the old slot) — never a bare wipe (brick risk).

if [ -n "${ALPINE_FDE_RESEAL_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_RESEAL_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi
if [ -z "${ALPINE_FDE_TRUST_STATE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../trust-state.sh"
fi
if [ -z "${ALPINE_FDE_SEAL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../seal.sh"
fi

# Seams (test injection points):
#   ALPINE_FDE_CRYPTSETUP      cryptsetup binary override (LUKS2 choreography)
#   ALPINE_FDE_BY_UUID_DIR     /dev/disk/by-uuid override
#   ALPINE_FDE_ENROLL_LOCK     ensure-once lockfile override (tests; default below)
#   ALPINE_FDE_PCRSIG          .pcrsig JSON source (default variant) for the
#                              ensure-once path
#   ALPINE_FDE_PCRSIG_SERIAL   .pcrsig JSON source (serial variant) — the
#                              two-UKI serial token pins its DISTINCT policy
#                              digest when supplied
#   ALPINE_FDE_LUKS_KEYFILE    existing-passphrase key file authorizing luksAddKey
reseal_cryptsetup() { "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }
reseal_by_uuid_dir() { printf '%s\n' "${ALPINE_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}"; }

# --- ensure-once serialization (§8.3 one-enrollment invariant; review HW-3) -----
# The inspect+enroll decision must be atomic: two concurrent `kernel build`s
# (operator + kernel hook, two racing postinst passes) must never both see
# "zero tokens" and both enroll. flock (util-linux, base dep) on a lockfile in
# /run (tmpfs), /var/lock fallback, overridable for tests.
reseal_lockfile() {
    if [ -n "${ALPINE_FDE_ENROLL_LOCK:-}" ]; then
        printf '%s\n' "$ALPINE_FDE_ENROLL_LOCK"
        return 0
    fi
    if mkdir -p /run/alpine-fde 2>/dev/null && [ -w /run/alpine-fde ]; then
        printf '%s\n' /run/alpine-fde/enroll.lock
        return 0
    fi
    printf '%s\n' /var/lock/alpine-fde-enroll.lock
}

# reseal_lock_acquire — take the exclusive enrollment lock on fd 9 (bounded wait).
# rc 0 = held; rc 1 = cannot serialize (caller decides fatality). Release with
# reseal_lock_release. RESEAL_LOCKED is 1 while held (diagnostics).
reseal_lock_acquire() {
    RESEAL_LOCKED=0
    if ! command -v flock >/dev/null 2>&1; then
        err "enroll: flock not available (util-linux) — cannot serialize the enrollment (§8.3)"
        return 1
    fi
    _ela_f=$(reseal_lockfile)
    _ela_dir=${_ela_f%/*}
    if [ ! -d "$_ela_dir" ] && ! mkdir -p "$_ela_dir" 2>/dev/null; then
        err "enroll: cannot create lock directory $_ela_dir"
        return 1
    fi
    if ! touch "$_ela_f" 2>/dev/null; then
        err "enroll: cannot create lockfile $_ela_f"
        return 1
    fi
    exec 9>>"$_ela_f"
    # blocking with a generous bound: a racing postinst pass WAITS rather than
    # fails; a wedged holder fails loudly instead of hanging forever
    if ! flock -w 120 9; then
        err "enroll: another enrollment holds the lock ($_ela_f) — timed out after 120s"
        exec 9>&-
        return 1
    fi
    RESEAL_LOCKED=1
    return 0
}

# reseal_lock_release — drop the enrollment lock (idempotent). NOTE: plain
# `exec 9>&-` only — an extra `2>/dev/null` on the exec would be applied
# PERSISTENTLY (POSIX exec-without-command semantics) and silence the rest of
# the process's stderr.
reseal_lock_release() {
    if [ "${RESEAL_LOCKED:-0}" -eq 1 ]; then
        exec 9>&-
        RESEAL_LOCKED=0
    fi
    return 0
}

# reseal_policy_mode — config key `policy_mode` (env wins). ADR-19/ADR-20: the
# ladder is resolved — Mechanism B (rung b) is the normative Alpine pipeline;
# a2 / a-prime-prime / native are accepted aliases of the same construction;
# rungs a / ap fail closed at the policy_mode_normalize boundary (64, cites
# ADR-19).
reseal_policy_mode() {
    policy_mode_normalize "${policy_mode:-${POLICY_MODE:-b}}" ||
        die "reseal: invalid policy_mode '${policy_mode:-${POLICY_MODE:-}}' (ADR-19: Mechanism B (rung b) is the normative path; want b — a2 accepted as an alias)"
}

enroll_usage() {
    cat >&2 <<'EOF'
Usage: alpine-fde reseal [--uuid LUKS-UUID|BLOCK-DEV] [--pcrsig FILE]
                             [--pcrsig-serial FILE] [--reseat]

Enroll the TPM seal (Mechanism B: tpm2-tools seal + systemd-tpm2 tokens;
ADR-19). Preconditions: finalized baseline, Secure Boot on + SetupMode=0,
PCR 7 digest-anchor (the .pcrsig entry's d7 == baseline.expected_pcr7 — a
pure data check; legacy anchor-less .pcrsig keeps the live-PCR-7 read),
release key in KEYDIR (--keydir / KEY_PATH / ALPINE_FDE_KEYDIR), LUKS device
resolvable (--uuid takes a LUKS uuid or a /dev/... block-device path). A
standing enrollment is retired in the SAME run the fresh one is standing
(--reseat forces it).

TWO-UKI TOKEN PAIR (one policy per console variant): the run stands TWO
tokens — the DEFAULT console variant's first, the SERIAL/RECOVERY variant's
second (distinct keyslots + token ids; the unseal hook scans ids 0..31 and
uses the booting UKI's own .pcrsig either way). --pcrsig-serial supplies the
serial UKI's .pcrsig so the serial token pins the DISTINCT serial policy
digest; without it the serial token falls back to the live/default policy
(warned).

Signed-policy source: --pcrsig FILE (the release-key-signed .pcrsig JSON,
verified against the fresh live-PCR digest before anything is embedded); when
absent, the policy is re-signed in-process from the keydir's release.pem over
the CURRENT PCR 7/11 (the §9.4 re-enroll path; ADR-18 passphrase seam
applies). ALPINE_FDE_PCRSIG / ALPINE_FDE_PCRSIG_SERIAL /
ALPINE_FDE_LUKS_KEYFILE are the env seams.

Policy mechanism (ADR-19/ADR-20, ladder resolved):
  b              Mechanism B — the normative Alpine pipeline: seal the random
                 volume passphrase under PolicyAuthorize over the {PCR 7,
                 PCR 11} signed policy (static d7 re-captured live), write the
                 systemd-tpm2 token (§7.2)
  a2             accepted ALIAS of b (same policy construction — the proven
                 A″ construction, now executed by our own sealer)
Never mix a fixed-digest term with a signed selection: both together AND and
break passwordless kernel updates (ADR-14 precision note). Modes a / ap are
documented-absent (fail closed, 64, ADR-19).
EOF
}

# reseal_preconditions UUID-OVERRIDE [PCRSIG] — on success rc 0 with the resolved
# triple in the RESEAL_PRE_UUID / RESEAL_PRE_PUB / RESEAL_PRE_DEV globals (review
# MD-02: a flat space-joined stdout cannot round-trip paths containing spaces);
# dies fail-closed otherwise. KEYDIR-explicit (G-B7): the release key comes from
# keys_dir — the baseline's keys.release_pub_path is never consulted.
reseal_preconditions() {
    RESEAL_PRE_UUID=''
    RESEAL_PRE_PUB=''
    RESEAL_PRE_DEV=''
    _ep_override=${1:-}
    _ep_pcrsig=${2:-${ALPINE_FDE_PCRSIG:-}}
    _ep_bl=$(sp_baseline_file)
    [ -f "$_ep_bl" ] || die "reseal: no baseline at $_ep_bl (run 'alpine-fde provision stage1')"
    baseline_validate "$_ep_bl" || die "reseal: baseline invalid: $_ep_bl"
    if ! baseline_is_final "$_ep_bl"; then
        die "reseal: baseline expected_pcr7 is pending — finalize after first boot: alpine-fde audit --init"
    fi

    _ep_sb=$(fw_sb_state) || true
    case $_ep_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "reseal: precondition failed: Secure Boot must be on with SetupMode=0, got: $_ep_sb (I5)"
            ;;
    esac

    _ep_expected=$(baseline_get "$_ep_bl" expected_pcr7)
    # PCR 7 drift gate (Option A digest anchoring): when the .pcrsig source the
    # seal will consume carries the entry's anchor components, the comparison
    # is PURE DATA — entry.d7 == baseline.expected_pcr7 (both digests the
    # composing flow provides: d7 is the console-measured PCR 7 the baseline
    # stamps; the guest's own measurement IS the machine state). No TPM read:
    # a machine whose real state diverged fails CLOSED at unseal (PolicyPCR) —
    # fail-at-unseal replaces fail-at-seal. Legacy anchor-less entries and the
    # in-process re-sign path keep the live-read oracle.
    _ep_anchor=''
    if [ -n "$_ep_pcrsig" ] && [ -f "$_ep_pcrsig" ]; then
        _ep_anchor=$(seal_pcrsig_field "$_ep_pcrsig" "7,11" d7)
    fi
    if [ -n "$_ep_anchor" ]; then
        if [ "$_ep_anchor" != "$_ep_expected" ]; then
            die "reseal: PCR 7 digest-anchor drift: pcrsig entry d7 $_ep_anchor != baseline expected_pcr7 $_ep_expected — audit, then audit --accept + re-enroll (§9.4)"
        fi
    else
        if ! _ep_live=$(tpm_pcr_read 7) || [ -z "$_ep_live" ]; then
            die "reseal: cannot read live PCR 7 (TCTI: ${ALPINE_FDE_TCTI:-<default>})"
        fi
        if [ "$_ep_live" != "$_ep_expected" ]; then
            die "reseal: PCR 7 drift: live $_ep_live != baseline $_ep_expected — audit, then audit --accept + re-enroll (§9.4)"
        fi
    fi

    _ep_keydir=$(keys_dir)
    [ -n "$_ep_keydir" ] || die "reseal: no release key directory configured (set --keydir / KEY_PATH / ALPINE_FDE_KEYDIR)"
    [ -d "$_ep_keydir" ] || die "reseal: release key directory not found: $_ep_keydir"
    _ep_pub="$_ep_keydir/release.pub"
    [ -f "$_ep_pub" ] || die "reseal: release public key not found: $_ep_pub"
    # ADR-16: the release key must be RSA >= 3072 — fail-closed rc 2 at the
    # enroll path entry, BEFORE any TPM/LUKS2 state is touched
    keys_rsa3072_guard "$_ep_keydir"

    _ep_uuid=${_ep_override:-$(baseline_get_in "$_ep_bl" target luks_uuid)}
    [ -n "$_ep_uuid" ] || die "reseal: no LUKS uuid (baseline target.luks_uuid empty; set it in install or pass --uuid)"
    case $_ep_uuid in
        /*)
            # G-XC12 (§8.1 "(or target block device)"): an explicit
            # block-device path (/dev/nvme0n1p2, /dev/mapper/root1, …) is
            # addressed verbatim — not looked up under by-uuid
            _ep_dev=$_ep_uuid
            ;;
        *)
            _ep_dev="$(reseal_by_uuid_dir)/$_ep_uuid"
            ;;
    esac
    [ -e "$_ep_dev" ] || die "reseal: LUKS device not resolvable: $_ep_dev"

    # a usable TPM via the configured TCTI (Mechanism B precondition, §6.1)
    seal_require_env

    RESEAL_PRE_UUID=$_ep_uuid
    RESEAL_PRE_PUB=$_ep_pub
    RESEAL_PRE_DEV=$_ep_dev
    return 0
}

# reseal_record FILE(UUID) MODE WIPE KEYSLOT PUBKEY [KEYSLOT_SERIAL] [TOKEN_ID_SERIAL]
# — write enrolled.json. Built with jq -n (field values can never mangle the
# JSON) and installed atomically (temp in the same directory + chmod 600 BEFORE
# the rename — no default-umask window, no partial document; review LO-02).
# two-UKI design: the serial variant's token bookkeeping rides the SAME record
# as additive token_keyslot_serial / token_id_serial fields (empty until a
# serial token stands). rc 1 on failure.
reseal_record() {
    _er_uuid=$1 _er_mode=$2 _er_wipe=$3 _er_slot=$4 _er_pub=$5
    _er_slot_serial=${6:-} _er_tok_serial=${7:-}
    _er_f=$(sp_enrolled_file)
    _er_dir=${_er_f%/*}
    mkdir -p "$_er_dir"
    _er_tmp=$(mktemp "$_er_dir/.alpine-fde-enrolled.XXXXXX") || {
        err "reseal: cannot create temp file for enrolled.json in $_er_dir"
        return 1
    }
    if ! jq -n \
        --arg uuid "$_er_uuid" --arg mode "$_er_mode" --arg wipe "$_er_wipe" \
        --arg slot "$_er_slot" --arg pub "$_er_pub" \
        --arg slot_serial "$_er_slot_serial" --arg tok_serial "$_er_tok_serial" \
        --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schema_version: 1, enrolled_at: $now, luks_uuid: $uuid,
          policy_mode: $mode, wipe_slot: $wipe, token_keyslot: $slot,
          token_keyslot_serial: $slot_serial, token_id_serial: $tok_serial,
          pubkey: $pub, pcr_bank: "sha256"}' >"$_er_tmp"; then
        rm -f "$_er_tmp"
        err "reseal: serializing enrolled.json failed"
        return 1
    fi
    chmod 600 "$_er_tmp"
    if ! mv -f "$_er_tmp" "$_er_f"; then
        rm -f "$_er_tmp"
        err "reseal: installing enrolled.json failed: $_er_f"
        return 1
    fi
    return 0
}

# reseal_json_token_id FILE TYPE — the JSON key (token id) of the first token of
# TYPE in `cryptsetup luksDump --dump-json-metadata` output (numeric "0"… or
# any string key). jq-parsed like baseline.sh's luks_json_* parsers —
# cryptsetup's dump layout varies by version (compact single-line on 2.7.x)
# and must never be text-anchored.
reseal_json_token_id() {
    jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == $t) | .key) // empty' \
        --arg t "$2" "$1" 2>/dev/null || :
}

# reseal_sign_pcrsig <staging_dir> <keydir> [out_file] — the in-process
# re-sign fallback (§9.4): sign the {7,11} policy over the CURRENT live PCR
# 7/11 with the keydir's release.pem (keys_unlock handles the ADR-18 encrypted
# form; the decrypted copy is scrubbed HERE, before this function returns).
# OUT_FILE defaults to <staging_dir>/pcrsig.json (the two-UKI serial token
# signs into its own file so the two variants never share a staged .pcrsig).
reseal_sign_pcrsig() {
    _esp_stage=$1 _esp_keydir=$2
    _esp_out=${3:-$_esp_stage/pcrsig.json}
    seal_require_env
    _esp_d7=$(seal_pcrread 7)
    _esp_d11=$(seal_pcrread 11)
    if command -v keys_unlock >/dev/null 2>&1; then
        _esp_priv=$(keys_unlock "$_esp_keydir") || {
            die "reseal: release.pem unlock failed — cannot re-sign the policy (ADR-18)"
        }
    else
        _esp_priv="$_esp_keydir/release.pem"
        [ -f "$_esp_priv" ] || die "reseal: no release.pem in $_esp_keydir — cannot re-sign the policy"
    fi
    # subshell: a die inside policy_sign_json must not strand the decrypted key
    if ! (policy_sign_json "$_esp_d7" "$_esp_d11" "$_esp_priv" \
        "$_esp_keydir/release.pub" "$_esp_out"); then
        [ -n "${_esp_priv}" ] && [ "$_esp_priv" != "$_esp_keydir/release.pem" ] &&
            keys_scrub "$_esp_priv"
        die "reseal: in-process policy re-sign failed (keydir: $_esp_keydir)"
    fi
    [ "$_esp_priv" != "$_esp_keydir/release.pem" ] && keys_scrub "$_esp_priv"
    printf '%s\n' "$_esp_out"
}

# reseal_run MODE PUBKEY DEVSPEC FORCE-WIPE(0|1) [PCRSIG] [PCRSIG_SERIAL] —
# the enrollment core shared by `reseal` and the `kernel build` ensure-once
# step (G-R3). two-UKI design: ONE run stands the WHOLE TOKEN PAIR (one token
# policy per console variant — the DEFAULT token first, the SERIAL token
# second; distinct seals under the same release-key PolicyAuthorize, and with
# per-variant .pcrsigs supplied the embedded policy digests differ too):
#   * pre-dump LUKS2 metadata; >1 existing systemd-tpm2 tokens → loud refusal
#     (a full reseat runs only on a clean or single-standing state)
#   * a standing enrollment is retired in the SAME run the fresh pair stands
#     (add the new keyslots + tokens, import the tokens, THEN remove the old
#     token + kill the old slot); FORCE-WIPE forces that (--reseat semantics)
#   * PCRSIG (default variant) / PCRSIG_SERIAL: per-variant .pcrsig sources;
#     a missing source falls back to the in-process re-sign over the CURRENT
#     live PCRs (the serial token then carries the default's policy digest —
#     the signature is inert at unseal; a later build with both UKIs re-runs
#     reseal to stamp the distinct serial policy — loud warn below)
#   * post-assertions: exactly TWO systemd-tpm2 tokens (the pair), pubkey ==
#     the keydir release key, pcrs [7,11], keyslots = the two fresh slots
#     (never 0, never shared), recovery keyslot 0 byte-identical
#   * the whole seal+choreography runs in a SUBSHELL (the seal functions die
#     fail-closed; this function translates that to rc 1 — the CALLER owns
#     fatal handling) with ALL staging under one directory scrubbed on every
#     exit path (I1: the random volume passphrase never survives on disk)
# On success: rc 0 with RESEAL_SLOT / RESEAL_TOKEN_ID (default variant),
# RESEAL_SLOT_SERIAL / RESEAL_TOKEN_ID_SERIAL, RESEAL_WIPE set. Any failure:
# rc 1 with the reason on stderr.
reseal_run() {
    _er_mode=$1 _er_pub=$2 _er_dev=$3 _er_force=$4
    _er_sig_arg=${5:-${ALPINE_FDE_PCRSIG:-}}
    _er_sig_serial_arg=${6:-${ALPINE_FDE_PCRSIG_SERIAL:-}}
    # ADR-16: same release-key floor as reseal_preconditions — this shared core
    # is also the `kernel build` ensure-once entry, which never passes through
    # the CLI precondition gate
    keys_rsa3072_guard "${_er_pub%/*}"
    RESEAL_SLOT=''
    RESEAL_TOKEN_ID=''
    RESEAL_SLOT_SERIAL=''
    RESEAL_TOKEN_ID_SERIAL=''
    RESEAL_WIPE=no
    # I1: every enroll-owned scratch/staging root is TMPFS — the enrollment
    # stage holds the RANDOM VOLUME PASSPHRASE, so the default is /dev/shm
    # (the repo tmpfs seam; cf. seal_stage_dir), never /tmp. The same root
    # pins the LUKS2 metadata dumps (not secret, scrubbed anyway).
    _er_pre=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-lukspre.XXXXXX") || return 1
    if ! reseal_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_pre" 2>/dev/null; then
        rm -f "$_er_pre"
        err "reseal: cannot read LUKS2 metadata of $_er_dev"
        return 1
    fi
    _er_tok_pre=$(luks_json_count_type "$_er_pre" systemd-tpm2)
    if [ "$_er_tok_pre" -gt 2 ]; then
        rm -f "$_er_pre"
        err "reseal: $_er_tok_pre systemd-tpm2 tokens found (expected <= 2: the two-UKI token pair) — manual intervention required"
        return 1
    fi
    if [ "$_er_tok_pre" -gt 0 ]; then
        if [ "$_er_force" != "1" ]; then
            info "existing TPM enrollment found — retiring it in the same run the fresh token pair stands"
        fi
        RESEAL_WIPE=yes
    fi
    if [ "$_er_force" = "1" ]; then
        RESEAL_WIPE=yes # explicit --reseat forces retire+re-enroll in ONE run
    fi
    # ALL standing tokens retire (a legacy single enrollment OR the pair) —
    # "SLOT TOKENID" lines, ascending token id
    _er_old=$(token_pair_bookkeeping "$_er_pre")
    # shellcheck disable=SC2086  # four '-'-padded fields
    set -- $_er_old
    _er_old_list=''
    if [ "$2" != "-" ]; then
        _er_old_list="$_er_old_list $1:$2"
    fi
    if [ "${3:-}" != "-" ] && [ "${4:-}" != "-" ] && [ -n "${4:-}" ]; then
        _er_old_list="$_er_old_list $3:$4"
    fi
    _er_slot0_pre=$(luks_json_slot_blob "$_er_pre" 0)

    # staging: ONE directory holding the two .pcrsigs, the sealed blob halves,
    # the random volume passphrases and the token JSON — scrubbed on every exit
    # (I1). The stage root is TMPFS by construction
    # (${ALPINE_FDE_TMPDIR:-/dev/shm}; cf. seal_stage_dir) — the /tmp default
    # is BANNED for this directory.
    _er_stage=$(mktemp -d "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-enroll.XXXXXX") || {
        rm -f "$_er_pre"
        return 1
    }
    chmod 700 "$_er_stage"
    if [ -n "$_er_sig_arg" ]; then
        if ! cp "$_er_sig_arg" "$_er_stage/pcrsig.json" 2>/dev/null; then
            rm -rf "$_er_stage" "$_er_pre"
            err "reseal: cannot read the .pcrsig source: $_er_sig_arg"
            return 1
        fi
    fi
    if [ -n "$_er_sig_serial_arg" ]; then
        if ! cp "$_er_sig_serial_arg" "$_er_stage/pcrsig-serial.json" 2>/dev/null; then
            rm -rf "$_er_stage" "$_er_pre"
            err "reseal: cannot read the serial .pcrsig source: $_er_sig_serial_arg"
            return 1
        fi
    fi

    # the seal + LUKS2 choreography: subshell so a fail-closed die inside the
    # seal/token libs becomes rc 1 HERE (caller-owned fatal handling), with the
    # staging dir seam pointing every secret at the scrubbed directory
    _er_keydir=${_er_pub%/*}
    _er_rc=0
    (
        export ALPINE_FDE_SEAL_STAGE="$_er_stage"
        # --- DEFAULT-variant token (the boot-priority first slot) ------------
        if [ ! -f "$_er_stage/pcrsig.json" ]; then
            reseal_sign_pcrsig "$_er_stage" "$_er_keydir" || exit 1
        fi
        seal_finalized "$_er_keydir" "$_er_dev" "$_er_stage/pcrsig.json" \
            "$_er_stage/token-default.json" || exit 1
        _er_slot_d=$SEAL_SLOT
        _er_pass_d=$SEAL_PASS_FILE
        token_add_keyslot "$_er_dev" "$SEAL_PASS_FILE" "$_er_slot_d" \
            "${ALPINE_FDE_LUKS_KEYFILE:-}" || exit 1
        _er_tid_d=$(token_next_id "$_er_dev") || exit 1
        token_import "$_er_dev" "$_er_stage/token-default.json" "$_er_tid_d" || exit 1
        # --- SERIAL-variant token (the recovery lane's second slot) ----------
        # With the serial .pcrsig supplied, the token pins the SERIAL policy
        # digest (the serial cmdline measures to a different PCR 11 — the
        # expected digest is read from the serial .pcrsig itself and handed to
        # seal_finalized explicitly, since no anchor/live recomputation can
        # produce the OTHER variant's prediction). Without one, the in-process
        # re-sign covers the live PCRs — the same pol as the default token
        # (documented fallback; the signature is inert at unseal).
        if [ ! -f "$_er_stage/pcrsig-serial.json" ]; then
            reseal_sign_pcrsig "$_er_stage" "$_er_keydir" \
                "$_er_stage/pcrsig-serial.json" || exit 1
            warn "reseal: no serial .pcrsig supplied — the serial token carries the live/default policy digest (re-run reseal with both UKIs' .pcrsigs to pin the distinct serial policy)"
        fi
        _er_pol_s=$(seal_pcrsig_field "$_er_stage/pcrsig-serial.json" "7,11" pol)
        seal_finalized "$_er_keydir" "$_er_dev" "$_er_stage/pcrsig-serial.json" \
            "$_er_stage/token-serial.json" "$_er_pol_s" || exit 1
        _er_slot_s=$SEAL_SLOT
        token_add_keyslot "$_er_dev" "$SEAL_PASS_FILE" "$_er_slot_s" \
            "$_er_pass_d" || exit 1
        _er_tid_s=$(token_next_id "$_er_dev") || exit 1
        token_import "$_er_dev" "$_er_stage/token-serial.json" "$_er_tid_s" || exit 1
        # --- retire ALL standing enrollments (same-run swap) -----------------
        if [ "$RESEAL_WIPE" = "yes" ] && [ -n "$_er_old_list" ]; then
            for _er_old_pair in $_er_old_list; do
                _er_o_slot=${_er_old_pair%:*}
                _er_o_tok=${_er_old_pair#*:}
                token_remove "$_er_dev" "$_er_o_tok" || exit 1
                token_kill_slot "$_er_dev" "$_er_o_slot" "$_er_pass_d" || exit 1
            done
        fi
        printf '%s\n' \
            "RESEAL_SLOT=$_er_slot_d" "RESEAL_TOKEN_ID=$_er_tid_d" \
            "RESEAL_SLOT_SERIAL=$_er_slot_s" "RESEAL_TOKEN_ID_SERIAL=$_er_tid_s" \
            "RESEAL_PASS=$_er_pass_d" >"$_er_stage/env"
    ) 2>>"$_er_stage/sub.err" || _er_rc=1
    if [ -s "$_er_stage/sub.err" ]; then
        cat "$_er_stage/sub.err" >&2
    fi
    if [ "$_er_rc" -eq 0 ] && [ -f "$_er_stage/env" ]; then
        # shellcheck disable=SC1090
        . "$_er_stage/env"
        keys_scrub "$RESEAL_PASS"
    fi
    if [ "$_er_rc" -ne 0 ]; then
        # I1 invariant (c): the staged passphrases are ZEROIZED, not merely
        # unlinked, on the failure path too
        for _er_p in "$_er_stage"/alpine-fde-seal-pass.*; do
            [ -f "$_er_p" ] && keys_scrub "$_er_p" || :
        done
        rm -rf "$_er_stage"
        rm -f "$_er_pre"
        err "reseal: the Mechanism B enrollment failed — LUKS2 state may hold fresh keyslots without their tokens (re-run enrollment; §8.3)"
        return 1
    fi

    # Post-assertions on the fresh metadata (rc-based: the caller decides)
    _er_post=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-lukspost.XXXXXX") || {
        rm -rf "$_er_stage" "$_er_pre"
        return 1
    }
    if ! reseal_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_post" 2>/dev/null; then
        rm -rf "$_er_stage"
        rm -f "$_er_pre" "$_er_post"
        err "reseal: cannot re-read LUKS2 metadata after enrollment"
        return 1
    fi
    _er_pub_b64=$(openssl pkey -pubin -in "$_er_pub" -outform DER 2>/dev/null | openssl base64 -A)
    if ! token_post_assert_multi "$_er_pre" "$_er_post" "$_er_pub_b64" '[7,11]' \
        "$RESEAL_SLOT" "$RESEAL_SLOT_SERIAL"; then
        rm -rf "$_er_stage"
        rm -f "$_er_pre" "$_er_post"
        err "reseal: post-assertions failed — enrollment NOT recorded"
        return 1
    fi
    rm -rf "$_er_stage"
    rm -f "$_er_pre" "$_er_post"
    return 0
}

# reseal_pair_bookkeeping META_JSON — print the standing token pair's
# keyslot/token-id bookkeeping as ONE line "SLOT_D TOK_D SLOT_S TOK_S"
# (lower token id = the DEFAULT variant — the pair is enrolled in that order;
# fields are '-' when fewer than two tokens stand).
reseal_pair_bookkeeping() {
    token_pair_bookkeeping "$@"
}

# reseal_ensure_gate_skip — G-IL7 (§8.1 kernel-build row): the build's ensure-once
# enrollment must NEVER fire while the installation is unfinalized — Stage-1
# in-chroot provisioning presents the exact trap (reachable volume, zero
# tokens, SB off). Ground-truth gate (item 10b: no install-state.json —
# lib/trust-state.sh): SKIP (warn; caller returns rc 0, bookkeeping stays
# empty) when the baseline expected_pcr7 is still pending, or when a standing
# token is NOT the finalized {PCR 7, PCR 11} (a provisional {11} seal — or any
# unrecognized shape — means the ceremony has not completed). No baseline ⇒
# no anchoring evidence either way ⇒ proceed (the legacy context; the
# ensure-once inspection below owns the zero-token case). rc 0 ⇒ SKIP,
# rc 1 ⇒ run the enrollment path.
reseal_ensure_gate_skip() {
    _eg_bl=$(sp_baseline_file)
    if [ -f "$_eg_bl" ] && ! baseline_is_final "$_eg_bl"; then
        warn "enroll: baseline expected_pcr7 is pending — skipping the ensure-once enrollment (finalize via 'alpine-fde audit --init', §8.1)"
        return 0
    fi
    if [ -f "$_eg_bl" ] && _eg_dev=$(ts_first_member); then
        _eg_meta=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-gate.XXXXXX") || return 0
        if ts_read_meta "$_eg_dev" "$_eg_meta"; then
            _eg_pcrs=$(ts_token_pcrs "$_eg_meta")
            if [ -n "$_eg_pcrs" ] && [ "$_eg_pcrs" != "[7,11]" ]; then
                warn "enroll: trust state is not finalized (standing token pcrs: $_eg_pcrs) — skipping the ensure-once enrollment; finalize after first boot ('alpine-fde finalize') and rebuild (§8.1)"
                rm -f "$_eg_meta"
                return 0
            fi
        fi
        rm -f "$_eg_meta"
    fi
    return 1
}

# reseal_ensure_once DEVSPEC PUBKEY [PCRSIG_SERIAL] — the `kernel build`
# ensure-once step (G-U1), two-UKI aware (the standing state is the TOKEN PAIR):
#   * volume unreachable → warn + rc 0 (a build context may not have the target
#     volume attached; under the pinned pubkey+signed-policy construction
#     kernel updates are TPM-free either way, s14)
#   * G-IL7: unfinalized ground truth (baseline pending / a non-{7,11}
#     standing token) → warn + rc 0
#     (Stage-1 builds must never enroll; RESEAL_SKIPPED=1 signals the skip)
#   * inspect + enroll run UNDER the enrollment lock (§8.3: concurrent builds /
#     postinst passes must serialize on the enrollment decision, HW-3)
#   * exactly the 2-token PAIR standing → info line, ZERO TPM operations (s14)
#   * 0 tokens → exactly ONE pair enrollment via reseal_run (RESEAL_ENROLLED=1)
#   * 1 token (a PARTIAL state: a pre-two-UKI legacy enrollment, or a crash
#     between the pair's two seals) → STANDS (rc 0, s14 — kernel updates are
#     TPM-free on legacy single-token volumes too) with an ADVISORY info naming
#     `reseal` as the pair-completion verb; a build must never grow TPM
#     operations the operator did not ask for
#   * >2 tokens → LOUD refusal rc 1 citing manual intervention (never silently
#     "stands" — the dead-slot accumulation the invariant exists to prevent)
# PCRSIG_SERIAL: the SERIAL variant's .pcrsig (the -serial UKI's own section) —
# when supplied, the serial token pins the DISTINCT serial policy digest;
# without it the serial token falls back to the live/default policy (warned).
# Globals on return: RESEAL_ENROLLED (1 = enrolled here), RESEAL_SKIPPED (1 = a
# documented precondition escape fired: unreachable volume or unfinalized
# install), RESEAL_FAIL_REASON. rc 1 only on enrollment failure (caller: marker
# + fail-closed pipeline).
reseal_ensure_once() {
    _ee_dev=$1 _ee_pub=$2
    RESEAL_PCRSIG_SERIAL_ARG=${3:-}
    RESEAL_ENROLLED=0
    # shellcheck disable=SC2034  # consumed by the caller (kernel build, §8.4)
    RESEAL_SKIPPED=0
    RESEAL_FAIL_REASON=''
    if [ -z "$_ee_dev" ] || [ ! -e "$_ee_dev" ]; then
        # shellcheck disable=SC2034  # consumed by the caller (kernel build)
        RESEAL_SKIPPED=1
        warn "enroll: LUKS2 volume not reachable (${_ee_dev:-<none>}) — skipping the ensure-once enrollment check (kernel updates are TPM-free under the pinned-token construction, s14)"
        return 0
    fi
    if reseal_ensure_gate_skip; then
        # shellcheck disable=SC2034  # consumed by the caller (kernel build)
        RESEAL_SKIPPED=1
        return 0
    fi
    if ! reseal_lock_acquire; then
        err "enroll: refusing an unserialized ensure-once check on $_ee_dev (§8.3)"
        return 1
    fi
    _ee_rc=0
    reseal_ensure_once_locked "$_ee_dev" "$_ee_pub" || _ee_rc=1
    reseal_lock_release
    return "$_ee_rc"
}

# reseal_ensure_once_locked DEVSPEC PUBKEY — the inspect+enroll body; caller holds
# the enrollment lock
reseal_ensure_once_locked() {
    _ee_dev=$1 _ee_pub=$2
    _ee_pre=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-enroll-ensure.XXXXXX") || return 1
    if ! reseal_cryptsetup luksDump --dump-json-metadata "$_ee_dev" >"$_ee_pre" 2>/dev/null; then
        rm -f "$_ee_pre"
        err "enroll: cannot read LUKS2 metadata of $_ee_dev"
        return 1
    fi
    _ee_tok=$(luks_json_count_type "$_ee_pre" systemd-tpm2)
    if [ "$_ee_tok" -eq 2 ]; then
        info "enroll: the systemd-tpm2 token PAIR already stands on $_ee_dev — enrollment stands, no TPM operations (s14)"
        rm -f "$_ee_pre"
        return 0
    fi
    if [ "$_ee_tok" -gt 2 ]; then
        # §7.2 fact check: LUKS2 provides 32 keyslots (0..31); this tool's
        # enrollment allocates from 1..31 (token_free_slot; slot 0 is recovery)
        RESEAL_FAIL_REASON="$_ee_tok systemd-tpm2 tokens found on $_ee_dev (expected <= 2: the two-UKI token pair) — manual intervention required (§8.3; LUKS2 provides 32 keyslots, this tool enrolls into 1..31)"
        err "enroll: $RESEAL_FAIL_REASON — clean up the surplus tokens/slots before any further enrollment"
        rm -f "$_ee_pre"
        return 1
    fi
    if [ "$_ee_tok" -eq 1 ]; then
        info "enroll: ONE systemd-tpm2 token stands on $_ee_dev (a pre-two-UKI enrollment or a partial pair) — kernel updates stay TPM-free (s14); run 'alpine-fde reseal' to stand the full two-UKI token pair"
        rm -f "$_ee_pre"
        return 0
    fi
    info "enroll: no TPM token on $_ee_dev — enrolling the token pair once (Mechanism B, one policy per UKI variant)"
    if ! reseal_run b "$_ee_pub" "$_ee_dev" 0 '' "$RESEAL_PCRSIG_SERIAL_ARG"; then
        rm -f "$_ee_pre"
        return 1
    fi
    rm -f "$_ee_pre"
    # shellcheck disable=SC2034  # caller-facing seam (unit suites assert it)
    RESEAL_ENROLLED=1
    return 0
}

# reseal_crypttab_uuid FILE — the LUKS2 target UUID of the first crypttab line
# with luks options (the volume the build's enroll step addresses, §8.2
# verified coupling); empty output when absent
reseal_crypttab_uuid() {
    [ -f "$1" ] || return 0
    awk '
        /^[[:space:]]*#/ { next }
        NF >= 4 && $4 ~ /(^|,)luks(,|$)/ {
            if (match($2, /^UUID=[^,]*/)) {
                print substr($2, 6)
                exit
            }
        }
    ' "$1"
}

cmd_reseal_main() {
    strict_mode

    _em_uuid='' _em_reseat=0 _em_pcrsig=${ALPINE_FDE_PCRSIG:-}
    _em_pcrsig_serial=${ALPINE_FDE_PCRSIG_SERIAL:-}
    while [ $# -gt 0 ]; do
        case $1 in
            --uuid)
                [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "reseal: --uuid requires an argument"
                _em_uuid=$2
                shift
                ;;
            --pcrsig)
                [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "reseal: --pcrsig requires an argument"
                _em_pcrsig=$2
                shift
                ;;
            --pcrsig-serial)
                [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "reseal: --pcrsig-serial requires an argument"
                _em_pcrsig_serial=$2
                shift
                ;;
            --reseat) _em_reseat=1 ;;
            -h | --help)
                enroll_usage
                return 0
                ;;
            *) die -r "$ALPINE_FDE_USAGE" "reseal: unknown argument: $1" ;;
        esac
        shift
    done

    # G-B4/ADR-19: the ladder gate fires BEFORE any package or precondition
    # work — a documented-absent mode fails closed regardless of environment.
    _em_mode=$(reseal_policy_mode)

    require_pkgs cryptsetup:cryptsetup tpm2:tpm2-tools jq:jq openssl:openssl flock:util-linux

    reseal_preconditions "$_em_uuid" "$_em_pcrsig"
    _em_uuid=$RESEAL_PRE_UUID
    _em_pub=$RESEAL_PRE_PUB
    _em_dev=$RESEAL_PRE_DEV

    # The Mechanism B TOKEN-PAIR enrollment (shared core, G-R3; two-UKI design:
    # one policy per console variant) under the enrollment lock (§8.3
    # serialization, HW-3); failures die fail-closed 64
    if ! reseal_lock_acquire; then
        die "reseal: cannot take the enrollment lock — refusing an unserialized enrollment"
    fi
    _em_rc=0
    reseal_run "$_em_mode" "$_em_pub" "$_em_dev" "$_em_reseat" "$_em_pcrsig" \
        "$_em_pcrsig_serial" || _em_rc=1
    reseal_lock_release
    if [ "$_em_rc" -ne 0 ]; then
        die "reseal: enrollment failed — enrolled.json NOT written"
    fi

    if ! reseal_record "$_em_uuid" "$_em_mode" "$RESEAL_WIPE" "$RESEAL_SLOT" "$_em_pub" \
        "$RESEAL_SLOT_SERIAL" "$RESEAL_TOKEN_ID_SERIAL"; then
        die "reseal: enrollment succeeded but enrolled.json could NOT be written — fix the state directory and re-run (loud failure, ADR-8)"
    fi
    printf 'alpine-fde: enrolled (policy_mode=%s, token pair: default keyslot %s + serial keyslot %s, wipe=%s); record: %s\n' \
        "$_em_mode" "$RESEAL_SLOT" "${RESEAL_SLOT_SERIAL:-<none>}" "$RESEAL_WIPE" "$(sp_enrolled_file)" >&2
    return 0
}
