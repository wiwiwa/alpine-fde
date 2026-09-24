#!/bin/sh
# enroll-tpm.sh — `alpine-fde enroll-tpm`: Mechanism B TPM-seal enrollment
# (§6.1/§7.1/§9.1/§9.4; ADR-19/ADR-20; gaps G-B3/G-B5/G-B6/G-B7). Alpine has
# NO systemd-cryptenroll (ADR-19): the seal is lib/seal.sh (tpm2-tools) and the
# LUKS2 choreography is lib/token.sh — cryptsetup stays the only LUKS2 seam.
# A guest/installed-system tool (needs the TPM via the configured TCTI); unit
# tests exercise the logic via stubs + the swtpm fixture. Also the shared
# enrollment core of `ukictl build`: enrl_run / enrl_ensure_once are the
# callable seam the build's ensure-once step reuses (`enroll`/`enroll-tpm` are
# the alias surface of that step, §8.1).
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
# Then enrl_run: the Mechanism B enrollment (seal under the finalized {7,11}
# policy + keyslot + token + retire-on-reseat), post-asserted via
# `cryptsetup luksDump --dump-json-metadata` (exactly one systemd-tpm2 token,
# pubkey == the keydir release key, pcrs [7,11], keyslot != 0, recovery
# keyslot 0 byte-identical), then enrolled.json.
#
# Signed-policy source (§9.1 step 6): --pcrsig FILE (or ALPINE_FDE_PCRSIG env)
# supplies the release-key-signed .pcrsig JSON the seal embeds; its entry is
# verified openssl-level against the policy digest recomputed from the entry's
# own anchored d7/d11 components BEFORE anything is embedded (G-B6, digest-
# anchored — no live PCR read). Without one, enroll-tpm re-signs in-process
# from the keydir's release.pem (keys_unlock; ADR-18) over the CURRENT PCR 7/11
# — the §9.4 re-enroll path (re-captures the new current PCR 7; live-read
# precondition kept).
#
# Recovery semantics (§9.4): an existing TPM enrollment is retired in the SAME
# run as the fresh one is standing (add new keyslot + token FIRST, then remove
# the old token + kill the old slot) — never a bare wipe (brick risk).

if [ -n "${ALPINE_FDE_ENROLL_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_ENROLL_LOADED=1

if [ -z "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../baseline.sh"
fi
if [ -z "${ALPINE_FDE_SEAL_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}/../seal.sh"
fi

# Seams (test injection points):
#   ALPINE_FDE_CRYPTSETUP    cryptsetup binary override (LUKS2 choreography)
#   ALPINE_FDE_BY_UUID_DIR   /dev/disk/by-uuid override
#   ALPINE_FDE_ENROLL_LOCK   ensure-once lockfile override (tests; default below)
#   ALPINE_FDE_PCRSIG        .pcrsig JSON source for the ensure-once path
#   ALPINE_FDE_LUKS_KEYFILE  existing-passphrase key file authorizing luksAddKey
enrl_cryptsetup() { "${ALPINE_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }
enrl_by_uuid_dir() { printf '%s\n' "${ALPINE_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}"; }

# --- ensure-once serialization (§8.3 one-enrollment invariant; review HW-3) -----
# The inspect+enroll decision must be atomic: two concurrent `ukictl build`s
# (operator + kernel hook, two racing postinst passes) must never both see
# "zero tokens" and both enroll. flock (util-linux, base dep) on a lockfile in
# /run (tmpfs), /var/lock fallback, overridable for tests.
enrl_lockfile() {
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

# enrl_lock_acquire — take the exclusive enrollment lock on fd 9 (bounded wait).
# rc 0 = held; rc 1 = cannot serialize (caller decides fatality). Release with
# enrl_lock_release. ENRL_LOCKED is 1 while held (diagnostics).
enrl_lock_acquire() {
    ENRL_LOCKED=0
    if ! command -v flock >/dev/null 2>&1; then
        err "enroll: flock not available (util-linux) — cannot serialize the enrollment (§8.3)"
        return 1
    fi
    _ela_f=$(enrl_lockfile)
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
    ENRL_LOCKED=1
    return 0
}

# enrl_lock_release — drop the enrollment lock (idempotent). NOTE: plain
# `exec 9>&-` only — an extra `2>/dev/null` on the exec would be applied
# PERSISTENTLY (POSIX exec-without-command semantics) and silence the rest of
# the process's stderr.
enrl_lock_release() {
    if [ "${ENRL_LOCKED:-0}" -eq 1 ]; then
        exec 9>&-
        ENRL_LOCKED=0
    fi
    return 0
}

# enrl_policy_mode — config key `policy_mode` (env wins). ADR-19/ADR-20: the
# ladder is resolved — Mechanism B (rung b) is the normative Alpine pipeline;
# a2 / a-prime-prime / native are accepted aliases of the same construction;
# rungs a / ap fail closed at the policy_mode_normalize boundary (64, cites
# ADR-19).
enrl_policy_mode() {
    policy_mode_normalize "${policy_mode:-${POLICY_MODE:-b}}" ||
        die "enroll-tpm: invalid policy_mode '${policy_mode:-${POLICY_MODE:-}}' (ADR-19: Mechanism B (rung b) is the normative path; want b — a2 accepted as an alias)"
}

enroll_usage() {
    cat >&2 <<'EOF'
Usage: alpine-fde enroll-tpm [--uuid LUKS-UUID|BLOCK-DEV] [--pcrsig FILE]
                             [--reseat] [--dry-run]

Enroll the TPM seal (Mechanism B: tpm2-tools seal + systemd-tpm2 token;
ADR-19). Preconditions: finalized baseline, Secure Boot on + SetupMode=0,
PCR 7 digest-anchor (the .pcrsig entry's d7 == baseline.expected_pcr7 — a
pure data check; legacy anchor-less .pcrsig keeps the live-PCR-7 read),
release key in KEYDIR (--keydir / KEY_PATH / ALPINE_FDE_KEYDIR), LUKS device
resolvable (--uuid takes a LUKS uuid or a /dev/... block-device path). A
standing enrollment is retired in the SAME run the fresh one is standing
(--reseat forces it).

Signed-policy source: --pcrsig FILE (the release-key-signed .pcrsig JSON,
verified against the fresh live-PCR digest before anything is embedded); when
absent, the policy is re-signed in-process from the keydir's release.pem over
the CURRENT PCR 7/11 (the §9.4 re-enroll path; ADR-18 passphrase seam
applies). ALPINE_FDE_PCRSIG / ALPINE_FDE_LUKS_KEYFILE are the env seams.

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

# enrl_preconditions UUID-OVERRIDE [PCRSIG] — on success rc 0 with the resolved
# triple in the ENRL_PRE_UUID / ENRL_PRE_PUB / ENRL_PRE_DEV globals (review
# MD-02: a flat space-joined stdout cannot round-trip paths containing spaces);
# dies fail-closed otherwise. KEYDIR-explicit (G-B7): the release key comes from
# keys_dir — the baseline's keys.release_pub_path is never consulted.
enrl_preconditions() {
    ENRL_PRE_UUID=''
    ENRL_PRE_PUB=''
    ENRL_PRE_DEV=''
    _ep_override=${1:-}
    _ep_pcrsig=${2:-${ALPINE_FDE_PCRSIG:-}}
    _ep_bl=$(sp_baseline_file)
    [ -f "$_ep_bl" ] || die "enroll-tpm: no baseline at $_ep_bl (run 'alpine-fde provision stage1')"
    baseline_validate "$_ep_bl" || die "enroll-tpm: baseline invalid: $_ep_bl"
    if ! baseline_is_final "$_ep_bl"; then
        die "enroll-tpm: baseline expected_pcr7 is pending — finalize after first boot: alpine-fde audit --init"
    fi

    _ep_sb=$(fw_sb_state) || true
    case $_ep_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "enroll-tpm: precondition failed: Secure Boot must be on with SetupMode=0, got: $_ep_sb (I5)"
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
            die "enroll-tpm: PCR 7 digest-anchor drift: pcrsig entry d7 $_ep_anchor != baseline expected_pcr7 $_ep_expected — audit, then audit --accept + re-enroll (§9.4)"
        fi
    else
        if ! _ep_live=$(tpm_pcr_read 7) || [ -z "$_ep_live" ]; then
            die "enroll-tpm: cannot read live PCR 7 (TCTI: ${ALPINE_FDE_TCTI:-<default>})"
        fi
        if [ "$_ep_live" != "$_ep_expected" ]; then
            die "enroll-tpm: PCR 7 drift: live $_ep_live != baseline $_ep_expected — audit, then audit --accept + re-enroll (§9.4)"
        fi
    fi

    _ep_keydir=$(keys_dir)
    [ -n "$_ep_keydir" ] || die "enroll-tpm: no release key directory configured (set --keydir / KEY_PATH / ALPINE_FDE_KEYDIR)"
    [ -d "$_ep_keydir" ] || die "enroll-tpm: release key directory not found: $_ep_keydir"
    _ep_pub="$_ep_keydir/release.pub"
    [ -f "$_ep_pub" ] || die "enroll-tpm: release public key not found: $_ep_pub"
    # ADR-16: the release key must be RSA >= 3072 — fail-closed rc 2 at the
    # enroll path entry, BEFORE any TPM/LUKS2 state is touched
    keys_rsa3072_guard "$_ep_keydir"

    _ep_uuid=${_ep_override:-$(baseline_get_in "$_ep_bl" target luks_uuid)}
    [ -n "$_ep_uuid" ] || die "enroll-tpm: no LUKS uuid (baseline target.luks_uuid empty; set it in install or pass --uuid)"
    case $_ep_uuid in
        /*)
            # G-XC12 (§8.1 "(or target block device)"): an explicit
            # block-device path (/dev/nvme0n1p2, /dev/mapper/root1, …) is
            # addressed verbatim — not looked up under by-uuid
            _ep_dev=$_ep_uuid
            ;;
        *)
            _ep_dev="$(enrl_by_uuid_dir)/$_ep_uuid"
            ;;
    esac
    [ -e "$_ep_dev" ] || die "enroll-tpm: LUKS device not resolvable: $_ep_dev"

    # a usable TPM via the configured TCTI (Mechanism B precondition, §6.1)
    seal_require_env

    ENRL_PRE_UUID=$_ep_uuid
    ENRL_PRE_PUB=$_ep_pub
    ENRL_PRE_DEV=$_ep_dev
    return 0
}

# enrl_record FILE(UUID) MODE WIPE KEYSLOT PUBKEY — write enrolled.json.
# Built with jq -n (field values can never mangle the JSON) and installed
# atomically (temp in the same directory + chmod 600 BEFORE the rename — no
# default-umask window, no partial document; review LO-02). rc 1 on failure.
enrl_record() {
    _er_uuid=$1 _er_mode=$2 _er_wipe=$3 _er_slot=$4 _er_pub=$5
    _er_f=$(sp_enrolled_file)
    _er_dir=${_er_f%/*}
    mkdir -p "$_er_dir"
    _er_tmp=$(mktemp "$_er_dir/.alpine-fde-enrolled.XXXXXX") || {
        err "enroll-tpm: cannot create temp file for enrolled.json in $_er_dir"
        return 1
    }
    if ! jq -n \
        --arg uuid "$_er_uuid" --arg mode "$_er_mode" --arg wipe "$_er_wipe" \
        --arg slot "$_er_slot" --arg pub "$_er_pub" \
        --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{schema_version: 1, enrolled_at: $now, luks_uuid: $uuid,
          policy_mode: $mode, wipe_slot: $wipe, token_keyslot: $slot,
          pubkey: $pub, pcr_bank: "sha256"}' >"$_er_tmp"; then
        rm -f "$_er_tmp"
        err "enroll-tpm: serializing enrolled.json failed"
        return 1
    fi
    chmod 600 "$_er_tmp"
    if ! mv -f "$_er_tmp" "$_er_f"; then
        rm -f "$_er_tmp"
        err "enroll-tpm: installing enrolled.json failed: $_er_f"
        return 1
    fi
    return 0
}

# enrl_json_token_id FILE TYPE — the JSON key (token id) of the first token of
# TYPE in `cryptsetup luksDump --dump-json-metadata` output (numeric "0"… or
# any string key). jq-parsed like baseline.sh's luks_json_* parsers —
# cryptsetup's dump layout varies by version (compact single-line on 2.7.x)
# and must never be text-anchored.
enrl_json_token_id() {
    jq -r 'first(.tokens // {} | to_entries[] | select(.value.type? == $t) | .key) // empty' \
        --arg t "$2" "$1" 2>/dev/null || :
}

# enrl_sign_pcrsig <staging_dir> <keydir> — the in-process re-sign fallback
# (§9.4): sign the {7,11} policy over the CURRENT live PCR 7/11 with the
# keydir's release.pem (keys_unlock handles the ADR-18 encrypted form; the
# decrypted copy is scrubbed HERE, before this function returns).
enrl_sign_pcrsig() {
    _esp_stage=$1 _esp_keydir=$2
    seal_require_env
    _esp_d7=$(seal_pcrread 7)
    _esp_d11=$(seal_pcrread 11)
    if command -v keys_unlock >/dev/null 2>&1; then
        _esp_priv=$(keys_unlock "$_esp_keydir") || {
            die "enroll-tpm: release.pem unlock failed — cannot re-sign the policy (ADR-18)"
        }
    else
        _esp_priv="$_esp_keydir/release.pem"
        [ -f "$_esp_priv" ] || die "enroll-tpm: no release.pem in $_esp_keydir — cannot re-sign the policy"
    fi
    # subshell: a die inside policy_sign_json must not strand the decrypted key
    if ! (policy_sign_json "$_esp_d7" "$_esp_d11" "$_esp_priv" \
        "$_esp_keydir/release.pub" "$_esp_stage/pcrsig.json"); then
        [ -n "${_esp_priv}" ] && [ "$_esp_priv" != "$_esp_keydir/release.pem" ] &&
            keys_scrub "$_esp_priv"
        die "enroll-tpm: in-process policy re-sign failed (keydir: $_esp_keydir)"
    fi
    [ "$_esp_priv" != "$_esp_keydir/release.pem" ] && keys_scrub "$_esp_priv"
    printf '%s\n' "$_esp_stage/pcrsig.json"
}

# enrl_run MODE PUBKEY DEVSPEC FORCE-WIPE(0|1) [PCRSIG] — the single-enrollment
# core shared by `enroll-tpm` and the `ukictl build` ensure-once step (G-R3):
#   * pre-dump LUKS2 metadata; >1 existing systemd-tpm2 tokens → loud refusal
#   * a standing enrollment is retired in the SAME run the fresh one stands
#     (add new keyslot + token, import token, THEN remove old token + kill old
#     slot); FORCE-WIPE forces that (--reseat semantics)
#   * post-assertions: exactly one systemd-tpm2 token, pubkey == the keydir
#     release key, pcrs [7,11], referenced keyslot != 0, recovery keyslot 0
#     byte-identical to the pre-state
#   * the whole seal+choreography runs in a SUBSHELL (the seal functions die
#     fail-closed; this function translates that to rc 1 — the CALLER owns
#     fatal handling) with ALL staging under one directory scrubbed on every
#     exit path (I1: the random volume passphrase never survives on disk)
# On success: rc 0 with ENRL_SLOT / ENRL_TOKEN_ID / ENRL_WIPE set. Any failure:
# rc 1 with the reason on stderr.
enrl_run() {
    _er_mode=$1 _er_pub=$2 _er_dev=$3 _er_force=$4 _er_sig_arg=${5:-${ALPINE_FDE_PCRSIG:-}}
    # ADR-16: same release-key floor as enrl_preconditions — this shared core
    # is also the `ukictl build` ensure-once entry, which never passes through
    # the CLI precondition gate
    keys_rsa3072_guard "${_er_pub%/*}"
    ENRL_SLOT=''
    ENRL_TOKEN_ID=''
    ENRL_WIPE=no
    # I1: every enroll-owned scratch/staging root is TMPFS — the enrollment
    # stage holds the RANDOM VOLUME PASSPHRASE, so the default is /dev/shm
    # (the repo tmpfs seam; cf. seal_stage_dir), never /tmp. The same root
    # pins the LUKS2 metadata dumps (not secret, scrubbed anyway).
    _er_pre=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-lukspre.XXXXXX") || return 1
    if ! enrl_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_pre" 2>/dev/null; then
        rm -f "$_er_pre"
        err "enroll-tpm: cannot read LUKS2 metadata of $_er_dev"
        return 1
    fi
    _er_tok_pre=$(luks_json_count_type "$_er_pre" systemd-tpm2)
    if [ "$_er_tok_pre" -gt 1 ]; then
        rm -f "$_er_pre"
        err "enroll-tpm: $_er_tok_pre systemd-tpm2 tokens found (expected <= 1) — manual intervention required"
        return 1
    fi
    if [ "$_er_tok_pre" -gt 0 ]; then
        if [ "$_er_force" != "1" ]; then
            info "existing TPM enrollment found — retiring it in the same run the fresh seal stands"
        fi
        ENRL_WIPE=yes
    fi
    if [ "$_er_force" = "1" ]; then
        ENRL_WIPE=yes # explicit --reseat forces retire+re-enroll in ONE run
    fi
    _er_old_tok=$(enrl_json_token_id "$_er_pre" systemd-tpm2)
    _er_old_slot=$(luks_json_token_keyslot "$_er_pre" systemd-tpm2 2>/dev/null || true)
    _er_slot0_pre=$(luks_json_slot_blob "$_er_pre" 0)

    # staging: ONE directory holding the .pcrsig, the sealed blob halves, the
    # random volume passphrase and the token JSON — scrubbed on every exit (I1).
    # The stage root is TMPFS by construction (${ALPINE_FDE_TMPDIR:-/dev/shm};
    # cf. seal_stage_dir) — the /tmp default is BANNED for this directory.
    _er_stage=$(mktemp -d "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-enroll.XXXXXX") || {
        rm -f "$_er_pre"
        return 1
    }
    chmod 700 "$_er_stage"
    if [ -n "$_er_sig_arg" ]; then
        if ! cp "$_er_sig_arg" "$_er_stage/pcrsig.json" 2>/dev/null; then
            rm -rf "$_er_stage" "$_er_pre"
            err "enroll-tpm: cannot read the .pcrsig source: $_er_sig_arg"
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
        if [ ! -f "$_er_stage/pcrsig.json" ]; then
            enrl_sign_pcrsig "$_er_stage" "$_er_keydir" || exit 1
        fi
        seal_finalized "$_er_keydir" "$_er_dev" "$_er_stage/pcrsig.json" \
            "$_er_stage/token.json" || exit 1
        token_add_keyslot "$_er_dev" "$SEAL_PASS_FILE" "$SEAL_SLOT" \
            "${ALPINE_FDE_LUKS_KEYFILE:-}" || exit 1
        _er_tid=$(token_next_id "$_er_dev") || exit 1
        token_import "$_er_dev" "$_er_stage/token.json" "$_er_tid" || exit 1
        if [ "$ENRL_WIPE" = "yes" ] && [ -n "$_er_old_tok" ]; then
            token_remove "$_er_dev" "$_er_old_tok" || exit 1
            token_kill_slot "$_er_dev" "$_er_old_slot" "$SEAL_PASS_FILE" || exit 1
        fi
        printf '%s\n' "ENRL_SLOT=$SEAL_SLOT" "ENRL_TOKEN_ID=$_er_tid" \
            "ENRL_PASS=$SEAL_PASS_FILE" >"$_er_stage/env"
    ) 2>>"$_er_stage/sub.err" || _er_rc=1
    if [ -s "$_er_stage/sub.err" ]; then
        cat "$_er_stage/sub.err" >&2
    fi
    if [ "$_er_rc" -eq 0 ] && [ -f "$_er_stage/env" ]; then
        # shellcheck disable=SC1090
        . "$_er_stage/env"
        keys_scrub "$ENRL_PASS"
    fi
    if [ "$_er_rc" -ne 0 ]; then
        # I1 invariant (c): the staged passphrase is ZEROIZED, not merely
        # unlinked, on the failure path too
        for _er_p in "$_er_stage"/alpine-fde-seal-pass.*; do
            [ -f "$_er_p" ] && keys_scrub "$_er_p" || :
        done
        rm -rf "$_er_stage"
        rm -f "$_er_pre"
        err "enroll-tpm: the Mechanism B enrollment failed — LUKS2 state may hold a fresh keyslot without its token (re-run enrollment; §8.3)"
        return 1
    fi

    # Post-assertions on the fresh metadata (rc-based: the caller decides)
    _er_post=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-lukspost.XXXXXX") || {
        rm -rf "$_er_stage" "$_er_pre"
        return 1
    }
    if ! enrl_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_post" 2>/dev/null; then
        rm -rf "$_er_stage"
        rm -f "$_er_pre" "$_er_post"
        err "enroll-tpm: cannot re-read LUKS2 metadata after enrollment"
        return 1
    fi
    _er_pub_b64=$(openssl pkey -pubin -in "$_er_pub" -outform DER 2>/dev/null | openssl base64 -A)
    if ! token_post_assert "$_er_pre" "$_er_post" "$_er_pub_b64" '[7,11]' "$ENRL_SLOT"; then
        rm -rf "$_er_stage"
        rm -f "$_er_pre" "$_er_post"
        err "enroll-tpm: post-assertions failed — enrollment NOT recorded"
        return 1
    fi
    ENRL_TOKEN_ID=$(enrl_json_token_id "$_er_post" systemd-tpm2)
    rm -rf "$_er_stage"
    rm -f "$_er_pre" "$_er_post"
    return 0
}

# enrl_install_state — the persisted installation state (state sibling's API:
# lib/install-state.sh; the state file is resolved by istate_file() —
# $ALPINE_FDE_INSTALL_STATE test override, else $(sp_etc_dir)/install-state.json).
# Empty output ⇒ no state file (legacy / not-installed build context — the
# G-IL7 gate PASSES, backward compat with pre-install-state builds and the
# existing unit tests) or an unreadable document (istate_state reports empty;
# the sibling owns the file contract and decides warn semantics). The lib is
# sourced when present; until it lands, a local jq fallback reads .state
# (same schema contract: {"state": "installed"|"finalized", ...}).
enrl_install_state() {
    if [ -z "${ALPINE_FDE_INSTALL_STATE_LOADED:-}" ]; then
        _eis_lib="$(sp_cmd_dir)/../install-state.sh"
        if [ -r "$_eis_lib" ]; then
            # shellcheck disable=SC1090
            . "$_eis_lib"
        fi
    fi
    if command -v istate_state >/dev/null 2>&1; then
        # landed state sibling API: existence is checked here first so the
        # legacy absent-file case stays silent (istate_state warns on absence)
        _eis_file=$(istate_file)
        [ -f "$_eis_file" ] || return 0
        istate_state 2>/dev/null || :
    else
        _eis_file="$(sp_etc_dir)/install-state.json"
        [ -f "$_eis_file" ] || return 0
        jq -r '.state // empty' "$_eis_file" 2>/dev/null || :
    fi
}

# enrl_ensure_gate_skip — G-IL7 (§8.1 ukictl-build row): the build's ensure-once
# enrollment must NEVER fire while the installation is unfinalized — Stage-1
# in-chroot provisioning presents the exact trap (reachable volume, zero
# tokens, SB off). SKIP (warn; caller returns rc 0, bookkeeping stays empty)
# when the persisted install state exists and is not `finalized`, or when the
# baseline expected_pcr7 is still pending. Absent install-state file ⇒ legacy
# context ⇒ proceed. rc 0 ⇒ SKIP, rc 1 ⇒ run the enrollment path.
enrl_ensure_gate_skip() {
    _eg_state=$(enrl_install_state)
    if [ -n "$_eg_state" ] && [ "$_eg_state" != "finalized" ]; then
        warn "enroll: install state is '$_eg_state' (not finalized) — skipping the ensure-once enrollment; finalize after first boot ('alpine-fde audit --init') and rebuild (§8.1)"
        return 0
    fi
    _eg_bl=$(sp_baseline_file)
    if [ -f "$_eg_bl" ] && ! baseline_is_final "$_eg_bl"; then
        warn "enroll: baseline expected_pcr7 is pending — skipping the ensure-once enrollment (finalize via 'alpine-fde audit --init', §8.1)"
        return 0
    fi
    return 1
}

# enrl_ensure_once DEVSPEC PUBKEY — the `ukictl build` ensure-once step (G-U1):
#   * volume unreachable → warn + rc 0 (a build context may not have the target
#     volume attached; under the pinned pubkey+signed-policy construction
#     kernel updates are TPM-free either way, s14)
#   * G-IL7: install state not finalized / baseline pending → warn + rc 0
#     (Stage-1 builds must never enroll; ENRL_SKIPPED=1 signals the skip)
#   * inspect + enroll run UNDER the enrollment lock (§8.3: concurrent builds /
#     postinst passes must serialize on the one-enrollment decision, HW-3)
#   * exactly 1 systemd-tpm2 token → info line, ZERO TPM operations (s14)
#   * 0 tokens → exactly ONE enrollment via enrl_run (ENRL_ENROLLED=1)
#   * >1 tokens → LOUD refusal rc 1 citing manual intervention (never silently
#     "stands" — the dead-slot accumulation the invariant exists to prevent)
# Globals on return: ENRL_ENROLLED (1 = enrolled here), ENRL_SKIPPED (1 = a
# documented precondition escape fired: unreachable volume or unfinalized
# install), ENRL_FAIL_REASON. rc 1 only on enrollment failure (caller: marker
# + fail-closed pipeline).
enrl_ensure_once() {
    _ee_dev=$1 _ee_pub=$2
    ENRL_ENROLLED=0
    # shellcheck disable=SC2034  # consumed by the caller (ukictl build, §8.4)
    ENRL_SKIPPED=0
    ENRL_FAIL_REASON=''
    if [ -z "$_ee_dev" ] || [ ! -e "$_ee_dev" ]; then
        # shellcheck disable=SC2034  # consumed by the caller (ukictl build)
        ENRL_SKIPPED=1
        warn "enroll: LUKS2 volume not reachable (${_ee_dev:-<none>}) — skipping the ensure-once enrollment check (kernel updates are TPM-free under the pinned-token construction, s14)"
        return 0
    fi
    if enrl_ensure_gate_skip; then
        # shellcheck disable=SC2034  # consumed by the caller (ukictl build)
        ENRL_SKIPPED=1
        return 0
    fi
    if ! enrl_lock_acquire; then
        err "enroll: refusing an unserialized ensure-once check on $_ee_dev (§8.3)"
        return 1
    fi
    _ee_rc=0
    enrl_ensure_once_locked "$_ee_dev" "$_ee_pub" || _ee_rc=1
    enrl_lock_release
    return "$_ee_rc"
}

# enrl_ensure_once_locked DEVSPEC PUBKEY — the inspect+enroll body; caller holds
# the enrollment lock
enrl_ensure_once_locked() {
    _ee_dev=$1 _ee_pub=$2
    _ee_pre=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-enroll-ensure.XXXXXX") || return 1
    if ! enrl_cryptsetup luksDump --dump-json-metadata "$_ee_dev" >"$_ee_pre" 2>/dev/null; then
        rm -f "$_ee_pre"
        err "enroll: cannot read LUKS2 metadata of $_ee_dev"
        return 1
    fi
    _ee_tok=$(luks_json_count_type "$_ee_pre" systemd-tpm2)
    rm -f "$_ee_pre"
    if [ "$_ee_tok" -eq 1 ]; then
        info "enroll: systemd-tpm2 token already present on $_ee_dev — enrollment stands, no TPM operations (s14)"
        return 0
    fi
    if [ "$_ee_tok" -gt 1 ]; then
        # §7.2 fact check: LUKS2 provides 32 keyslots (0..31); this tool's
        # enrollment allocates from 1..31 (token_free_slot; slot 0 is recovery)
        ENRL_FAIL_REASON="$_ee_tok systemd-tpm2 tokens found on $_ee_dev (expected <= 1) — manual intervention required (§8.3 one-enrollment invariant; LUKS2 provides 32 keyslots, this tool enrolls into 1..31)"
        err "enroll: $ENRL_FAIL_REASON — clean up the surplus tokens/slots before any further enrollment"
        return 1
    fi
    info "enroll: no TPM token on $_ee_dev — enrolling once (Mechanism B)"
    if ! enrl_run b "$_ee_pub" "$_ee_dev" 0; then
        return 1
    fi
    ENRL_ENROLLED=1
    return 0
}

# enrl_crypttab_uuid FILE — the LUKS2 target UUID of the first crypttab line
# with luks options (the volume the build's enroll step addresses, §8.2
# verified coupling); empty output when absent
enrl_crypttab_uuid() {
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

cmd_enroll_tpm_main() {
    strict_mode

    _em_uuid='' _em_reseat=0 _em_pcrsig=${ALPINE_FDE_PCRSIG:-}
    while [ $# -gt 0 ]; do
        case $1 in
            --uuid)
                [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "enroll-tpm: --uuid requires an argument"
                _em_uuid=$2
                shift
                ;;
            --pcrsig)
                [ $# -ge 2 ] || die -r "$ALPINE_FDE_USAGE" "enroll-tpm: --pcrsig requires an argument"
                _em_pcrsig=$2
                shift
                ;;
            --reseat) _em_reseat=1 ;;
            --dry-run) ALPINE_FDE_DRY_RUN=1 ;;
            -h | --help)
                enroll_usage
                return 0
                ;;
            *) die -r "$ALPINE_FDE_USAGE" "enroll-tpm: unknown argument: $1" ;;
        esac
        shift
    done

    # G-B4/ADR-19: the ladder gate fires BEFORE any package or precondition
    # work — a documented-absent mode fails closed regardless of environment.
    _em_mode=$(enrl_policy_mode)

    require_pkgs cryptsetup:cryptsetup tpm2:tpm2-tools jq:jq openssl:openssl flock:util-linux

    enrl_preconditions "$_em_uuid" "$_em_pcrsig"
    _em_uuid=$ENRL_PRE_UUID
    _em_pub=$ENRL_PRE_PUB
    _em_dev=$ENRL_PRE_DEV

    # --dry-run: plan only — read the pre-state for the retire decision and the
    # free slot, print the plan, touch nothing (no seal, no enrollment, no
    # enrolled.json)
    if [ -n "${ALPINE_FDE_DRY_RUN:-}" ]; then
        _em_prej=$(mktemp "${ALPINE_FDE_TMPDIR:-/dev/shm}/alpine-fde-lukspre.XXXXXX") || die "enroll-tpm: mktemp failed"
        enrl_cryptsetup luksDump --dump-json-metadata "$_em_dev" >"$_em_prej" 2>/dev/null ||
            {
                rm -f "$_em_prej"
                die "enroll-tpm: cannot read LUKS2 metadata of $_em_dev"
            }
        _em_tok=$(luks_json_count_type "$_em_prej" systemd-tpm2)
        _em_slot=$(token_free_slot "$_em_dev")
        rm -f "$_em_prej"
        _em_wipe=no
        if [ "$_em_tok" -gt 0 ] || [ "$_em_reseat" -eq 1 ]; then
            _em_wipe=yes
        fi
        _em_src=explicit
        [ -n "$_em_pcrsig" ] || _em_src="in-process re-sign from the keydir release.pem"
        info "enroll plan (policy_mode=$_em_mode): device=$_em_dev keydir_pub=$_em_pub pcrs=7,11 slot=$_em_slot retire=$_em_wipe pcrsig=$_em_src"
        info "dry-run: enrollment not performed; enrolled.json not written"
        return 0
    fi

    # The single Mechanism B enrollment (shared core, G-R3) under the
    # enrollment lock (§8.3 serialization, HW-3); failures die fail-closed 64
    if ! enrl_lock_acquire; then
        die "enroll-tpm: cannot take the enrollment lock — refusing an unserialized enrollment"
    fi
    _em_rc=0
    enrl_run "$_em_mode" "$_em_pub" "$_em_dev" "$_em_reseat" "$_em_pcrsig" || _em_rc=1
    enrl_lock_release
    if [ "$_em_rc" -ne 0 ]; then
        die "enroll-tpm: enrollment failed — enrolled.json NOT written"
    fi

    if ! enrl_record "$_em_uuid" "$_em_mode" "$ENRL_WIPE" "$ENRL_SLOT" "$_em_pub"; then
        die "enroll-tpm: enrollment succeeded but enrolled.json could NOT be written — fix the state directory and re-run (loud failure, ADR-8)"
    fi
    printf 'alpine-fde: enrolled (policy_mode=%s, token keyslot %s, wipe=%s); record: %s\n' \
        "$_em_mode" "$ENRL_SLOT" "$ENRL_WIPE" "$(sp_enrolled_file)" >&2
    return 0
}
