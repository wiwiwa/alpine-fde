#!/bin/sh
# enroll-tpm.sh — `debian-fde enroll-tpm`: TPM-seal enrollment wrapper around
# systemd-cryptenroll (§8.1; gaps C-G4/C-G8; G-R2/G-R3 A''-only). A guest/
# installed-system tool (needs /dev/tpmrm0); unit tests exercise the logic via
# stubs. Also the shared enrollment core of `ukictl build`: enrl_run /
# enrl_ensure_once are the callable seam the build's ensure-once step reuses
# (`enroll`/`enroll-tpm` are the alias surface of that step, §8.1).
#
# Preconditions (fail-closed, in order):
#   1. A''-only mode gate (ADR-14: a / ap / b exit 64 at the normalize boundary)
#   2. finalized baseline (expected_pcr7 != pending — finalize via audit --init)
#   3. Secure Boot on AND SetupMode=0 (efivarfs seam)
#   4. live PCR 7 == baseline.expected_pcr7 (tpm() pcrread)
#   5. release public key present (baseline keys.release_pub_path)
#   6. LUKS device resolvable via /dev/disk/by-uuid/<baseline target.luks_uuid>
#   7. cryptenroll probe --tpm2-device=list answers
# Then enrl_run: the SINGLE cryptenroll invocation, post-asserted via
# `cryptsetup luksDump --dump-json-metadata` (exactly one systemd-tpm2 token,
# keyslot != 0, recovery keyslot 0 byte-identical), then enrolled.json.
#
# Recovery semantics (§9.4, ADR-14): an existing TPM enrollment is wiped and
# re-created in ONE cryptenroll invocation (--wipe-slot=tpm2) — never a bare
# wipe (brick risk). cryptenroll re-captures the CURRENT PCR 7 into the static
# policy; no release private key is needed — the token pins only the pubkey.

if [ -n "${DEBIAN_FDE_ENROLL_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_ENROLL_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

# Seams (test injection points):
#   DEBIAN_FDE_CRYPTENROLL   systemd-cryptenroll binary override
#   DEBIAN_FDE_CRYPTSETUP    cryptsetup binary override (luksDump post-assertions)
#   DEBIAN_FDE_BY_UUID_DIR   /dev/disk/by-uuid override
#   DEBIAN_FDE_ENROLL_LOCK   ensure-once lockfile override (tests; default below)
enrl_cryptenroll() { "${DEBIAN_FDE_CRYPTENROLL:-systemd-cryptenroll}" "$@"; }
enrl_cryptsetup() { "${DEBIAN_FDE_CRYPTSETUP:-cryptsetup}" "$@"; }
enrl_by_uuid_dir() { printf '%s\n' "${DEBIAN_FDE_BY_UUID_DIR:-/dev/disk/by-uuid}"; }

# --- ensure-once serialization (§8.3 one-enrollment invariant; review HW-3) -----
# The inspect+enroll decision must be atomic: two concurrent `ukictl build`s
# (operator + kernel hook, two racing postinst passes) must never both see
# "zero tokens" and both enroll. flock (util-linux, base dep) on a lockfile in
# /run (tmpfs), /var/lock fallback, overridable for tests.
enrl_lockfile() {
    if [ -n "${DEBIAN_FDE_ENROLL_LOCK:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_ENROLL_LOCK"
        return 0
    fi
    if mkdir -p /run/debian-fde 2>/dev/null && [ -w /run/debian-fde ]; then
        printf '%s\n' /run/debian-fde/enroll.lock
        return 0
    fi
    printf '%s\n' /var/lock/debian-fde-enroll.lock
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

# enrl_policy_mode — config key `policy_mode` (env wins). ADR-14: the ladder is
# resolved — only A″ (a2; aliases a-prime-prime, native) is implemented; rungs
# a / ap / b fail closed at the policy_mode_normalize boundary (64, cites ADR-14).
enrl_policy_mode() {
    policy_mode_normalize "${policy_mode:-${POLICY_MODE:-a2}}" ||
        die "enroll-tpm: invalid policy_mode '${policy_mode:-${POLICY_MODE:-}}' (ADR-14: Mechanism A'' only; want a2|a-prime-prime, native)"
}

enroll_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde enroll-tpm [--uuid LUKS-UUID] [--reseat] [--dry-run]

Enroll the TPM seal (systemd-cryptenroll wrapper). Preconditions: finalized
baseline, Secure Boot on + SetupMode=0, live PCR 7 == baseline, LUKS uuid
resolvable. An existing tpm2 slot is wiped and re-created in ONE invocation.

Policy mechanism (ADR-14: resolved — Mechanism A'' is the ONLY mode):
  a2             systemd-native static PCR 7 + release-key-signed PCR 11;
                 signatures ride in each UKI's .pcrsig/.pcrpkey:
                   --tpm2-pcrs=7 --tpm2-public-key=<pub> --tpm2-public-key-pcrs=11
                 cryptenroll re-captures the CURRENT PCR 7; no release private
                 key is required — the token pins only the pubkey (§7.2).
Never pass --tpm2-pcrs together with a signed selection: fixed-digest AND
signed modes AND together and break passwordless kernel updates (ADR-14
precision note). Modes a / ap / b are documented-absent (fail closed, 64).
EOF
}

# enrl_cryptenroll_argv PUBKEY WIPE(yes|no) DEVSPEC — print the single A''
# cryptenroll argv, one argument per line (device last)
enrl_cryptenroll_argv() {
    _eca_pub=$1 _eca_wipe=$2 _eca_dev=$3
    if [ "$_eca_wipe" = "yes" ]; then
        printf '%s\n' --wipe-slot=tpm2
    fi
    printf '%s\n' --tpm2-device=auto
    printf '%s\n' --tpm2-pcrs=7
    printf '%s\n' "--tpm2-public-key=$_eca_pub"
    printf '%s\n' --tpm2-public-key-pcrs=11
    printf '%s\n' "$_eca_dev"
}

# enrl_preconditions UUID-OVERRIDE — on success rc 0 with the resolved triple in
# the ENRL_PRE_UUID / ENRL_PRE_PUB / ENRL_PRE_DEV globals (review MD-02: a flat
# space-joined stdout cannot round-trip paths containing spaces); dies
# fail-closed otherwise
enrl_preconditions() {
    ENRL_PRE_UUID=''
    ENRL_PRE_PUB=''
    ENRL_PRE_DEV=''
    _ep_override=${1:-}
    _ep_bl=$(sp_baseline_file)
    [ -f "$_ep_bl" ] || die "enroll-tpm: no baseline at $_ep_bl (run 'debian-fde provision stage1')"
    baseline_validate "$_ep_bl" || die "enroll-tpm: baseline invalid: $_ep_bl"
    if ! baseline_is_final "$_ep_bl"; then
        die "enroll-tpm: baseline expected_pcr7 is pending — finalize after first boot: debian-fde audit --init"
    fi

    _ep_sb=$(fw_sb_state) || true
    case $_ep_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "enroll-tpm: precondition failed: Secure Boot must be on with SetupMode=0, got: $_ep_sb (I5)"
            ;;
    esac

    _ep_expected=$(baseline_get "$_ep_bl" expected_pcr7)
    if ! _ep_live=$(tpm_pcr_read 7) || [ -z "$_ep_live" ]; then
        die "enroll-tpm: cannot read live PCR 7 (TCTI: ${DEBIAN_FDE_TCTI:-<default>})"
    fi
    if [ "$_ep_live" != "$_ep_expected" ]; then
        die "enroll-tpm: PCR 7 drift: live $_ep_live != baseline $_ep_expected — audit, then audit --accept + re-enroll (§9.4)"
    fi

    _ep_pub=$(baseline_get_in "$_ep_bl" keys release_pub_path)
    [ -n "$_ep_pub" ] || die "enroll-tpm: baseline keys.release_pub_path is empty"
    [ -f "$_ep_pub" ] || die "enroll-tpm: release public key not found: $_ep_pub"

    _ep_uuid=${_ep_override:-$(baseline_get_in "$_ep_bl" target luks_uuid)}
    [ -n "$_ep_uuid" ] || die "enroll-tpm: no LUKS uuid (baseline target.luks_uuid empty; set it in install or pass --uuid)"
    _ep_dev="$(enrl_by_uuid_dir)/$_ep_uuid"
    [ -e "$_ep_dev" ] || die "enroll-tpm: LUKS device not resolvable: $_ep_dev"

    if ! enrl_cryptenroll --tpm2-device=list >/dev/null 2>&1; then
        die "enroll-tpm: systemd-cryptenroll probe failed (--tpm2-device=list) — no TPM usable by systemd?"
    fi

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
    _er_tmp=$(mktemp "$_er_dir/.debian-fde-enrolled.XXXXXX") || {
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

# enrl_run MODE PUBKEY DEVSPEC FORCE-WIPE(0|1) — the single-enrollment core
# shared by `enroll-tpm` and the `ukictl build` ensure-once step (G-R3):
#   * pre-dump LUKS2 metadata; >1 existing systemd-tpm2 tokens → loud refusal
#   * an existing tpm2 enrollment is wiped and re-created in the SAME cryptenroll
#     invocation (--wipe-slot=tpm2); FORCE-WIPE forces it (--reseat semantics)
#   * post-assertions: exactly one systemd-tpm2 token, referenced keyslot != 0,
#     recovery keyslot 0 byte-identical to the pre-state
# On success: rc 0 with ENRL_SLOT / ENRL_TOKEN_ID / ENRL_WIPE set. Any failure:
# rc 1 with the reason on stderr — the CALLER owns fatal handling (enroll-tpm
# dies 64; ukictl build writes the ADR-8 marker and fails its pipeline).
enrl_run() {
    _er_mode=$1 _er_pub=$2 _er_dev=$3 _er_force=$4
    ENRL_SLOT=''
    ENRL_TOKEN_ID=''
    ENRL_WIPE=no
    _er_pre=$(mktemp "${TMPDIR:-/tmp}/debian-fde-lukspre.XXXXXX") || return 1
    if ! enrl_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_pre" 2>/dev/null; then
        rm -f "$_er_pre"
        err "enroll-tpm: cannot read LUKS2 metadata of $_er_dev"
        return 1
    fi
    _er_tok_pre=$(luks_json_count_type "$_er_pre" systemd-tpm2)
    if [ "$_er_tok_pre" -gt 0 ]; then
        if [ "$_er_force" != "1" ]; then
            info "existing TPM enrollment found — re-seating (wipe+enroll in one invocation)"
        fi
        ENRL_WIPE=yes
    fi
    if [ "$_er_force" = "1" ]; then
        ENRL_WIPE=yes # explicit --reseat forces wipe+re-enroll in ONE invocation
    fi
    if [ "$_er_tok_pre" -gt 1 ]; then
        rm -f "$_er_pre"
        err "enroll-tpm: $_er_tok_pre systemd-tpm2 tokens found (expected <= 1) — manual intervention required"
        return 1
    fi
    if [ "$_er_tok_pre" -gt 0 ]; then
        _er_slot0_pre=$(luks_json_slot_blob "$_er_pre" 0)
    else
        _er_slot0_pre=''
    fi

    # Build + run the single cryptenroll invocation. The argv is materialized
    # one-argument-per-line into "$@" (POSIX set -- accumulation) — never a
    # word-split flat string, so spaces/globs in paths survive verbatim (MD-02).
    _er_argvf=$(mktemp "${TMPDIR:-/tmp}/debian-fde-argv.XXXXXX") || {
        rm -f "$_er_pre"
        return 1
    }
    enrl_cryptenroll_argv "$_er_pub" "$ENRL_WIPE" "$_er_dev" >"$_er_argvf"
    set --
    while IFS= read -r _er_a || [ -n "$_er_a" ]; do
        set -- "$@" "$_er_a"
    done <"$_er_argvf"
    rm -f "$_er_argvf"
    info "cryptenroll invocation (policy_mode=$_er_mode):"
    printf '  systemd-cryptenroll' >&2
    for _er_a in "$@"; do
        printf ' %s' "$_er_a" >&2
    done
    printf '\n' >&2
    if ! enrl_cryptenroll "$@"; then
        rm -f "$_er_pre"
        err "enroll-tpm: systemd-cryptenroll failed"
        return 1
    fi

    # Post-assertions on the fresh metadata
    _er_post=$(mktemp "${TMPDIR:-/tmp}/debian-fde-lukspost.XXXXXX") || {
        rm -f "$_er_pre"
        return 1
    }
    if ! enrl_cryptsetup luksDump --dump-json-metadata "$_er_dev" >"$_er_post" 2>/dev/null; then
        rm -f "$_er_pre" "$_er_post"
        err "enroll-tpm: cannot re-read LUKS2 metadata after enrollment"
        return 1
    fi
    _er_rc=0
    _er_tok_post=$(luks_json_count_type "$_er_post" systemd-tpm2)
    if [ "$_er_tok_post" -ne 1 ]; then
        err "enroll-tpm: post-assert failed: expected exactly 1 systemd-tpm2 token, found $_er_tok_post"
        if [ "$_er_tok_post" -gt "$_er_tok_pre" ]; then
            err "enroll-tpm: the failed attempt left an EXTRA token behind — manual intervention required: wipe the surplus tpm2 token (cryptsetup luksKillSlot / token export) before retrying, or slots accumulate (§8.3)"
        fi
        _er_rc=1
    fi
    _er_slot=$(luks_json_token_keyslot "$_er_post" systemd-tpm2)
    if [ "$_er_rc" -eq 0 ] && { [ -z "$_er_slot" ] || [ "$_er_slot" = "0" ]; }; then
        err "enroll-tpm: post-assert failed: token must reference a keyslot != 0 (recovery slot), got '${_er_slot:-none}'"
        _er_rc=1
    fi
    if [ "$_er_rc" -eq 0 ] && [ -n "$_er_slot0_pre" ]; then
        _er_slot0_post=$(luks_json_slot_blob "$_er_post" 0)
        if [ "$_er_slot0_pre" != "$_er_slot0_post" ]; then
            err "enroll-tpm: post-assert failed: recovery keyslot 0 changed — enrollment aborted (slot intact?)"
            _er_rc=1
        fi
    fi
    if [ "$_er_rc" -eq 0 ]; then
        ENRL_SLOT=$_er_slot
        ENRL_TOKEN_ID=$(enrl_json_token_id "$_er_post" systemd-tpm2)
    else
        err "enroll-tpm: post-assertions failed — enrollment NOT recorded"
    fi
    rm -f "$_er_pre" "$_er_post"
    return "$_er_rc"
}

# enrl_ensure_once DEVSPEC PUBKEY — the `ukictl build` ensure-once step (G-U1):
#   * volume unreachable → warn + rc 0 (a build context may not have the target
#     volume attached; under A'' kernel updates are TPM-free either way, s14)
#   * inspect + enroll run UNDER the enrollment lock (§8.3: concurrent builds /
#     postinst passes must serialize on the one-enrollment decision, HW-3)
#   * exactly 1 systemd-tpm2 token → info line, ZERO TPM operations (s14)
#   * 0 tokens → exactly ONE enrollment via enrl_run (ENRL_ENROLLED=1)
#   * >1 tokens → LOUD refusal rc 1 citing manual intervention (never silently
#     "stands" — the dead-slot accumulation the invariant exists to prevent)
# rc 1 only on enrollment failure (caller: marker + fail-closed pipeline).
enrl_ensure_once() {
    _ee_dev=$1 _ee_pub=$2
    ENRL_ENROLLED=0
    ENRL_FAIL_REASON=''
    if [ -z "$_ee_dev" ] || [ ! -e "$_ee_dev" ]; then
        warn "enroll: LUKS2 volume not reachable (${_ee_dev:-<none>}) — skipping the ensure-once enrollment check (kernel updates are TPM-free under A'', s14)"
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
    _ee_pre=$(mktemp "${TMPDIR:-/tmp}/debian-fde-enroll-ensure.XXXXXX") || return 1
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
        ENRL_FAIL_REASON="$_ee_tok systemd-tpm2 tokens found on $_ee_dev (expected <= 1) — manual intervention required (§8.3 one-enrollment invariant)"
        err "enroll: $ENRL_FAIL_REASON — clean up the surplus tokens/slots before any further enrollment (LUKS2 slots are capped at 8)"
        return 1
    fi
    info "enroll: no TPM token on $_ee_dev — enrolling once (A'')"
    if ! enrl_run a2 "$_ee_pub" "$_ee_dev" 0; then
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

    _em_uuid='' _em_reseat=0
    while [ $# -gt 0 ]; do
        case $1 in
            --uuid)
                [ $# -ge 2 ] || die -r "$DEBIAN_FDE_USAGE" "enroll-tpm: --uuid requires an argument"
                _em_uuid=$2
                shift
                ;;
            --reseat) _em_reseat=1 ;;
            --dry-run) DEBIAN_FDE_DRY_RUN=1 ;;
            -h | --help)
                enroll_usage
                return 0
                ;;
            *) die -r "$DEBIAN_FDE_USAGE" "enroll-tpm: unknown argument: $1" ;;
        esac
        shift
    done

    # G-B3/ADR-14: the ladder gate fires BEFORE any package or precondition
    # work — a documented-absent mode fails closed regardless of environment.
    _em_mode=$(enrl_policy_mode)

    require_pkgs systemd-cryptenroll:systemd-cryptsetup cryptsetup:cryptsetup tpm2:tpm2-tools flock:util-linux

    enrl_preconditions "$_em_uuid"
    _em_uuid=$ENRL_PRE_UUID
    _em_pub=$ENRL_PRE_PUB
    _em_dev=$ENRL_PRE_DEV

    # --dry-run: plan only — read the pre-state for the wipe decision, print the
    # argv, touch nothing (no enrollment, no enrolled.json)
    if [ -n "${DEBIAN_FDE_DRY_RUN:-}" ]; then
        _em_prej=$(mktemp "${TMPDIR:-/tmp}/debian-fde-lukspre.XXXXXX") || die "enroll-tpm: mktemp failed"
        enrl_cryptsetup luksDump --dump-json-metadata "$_em_dev" >"$_em_prej" 2>/dev/null \
            || {
                rm -f "$_em_prej"
                die "enroll-tpm: cannot read LUKS2 metadata of $_em_dev"
            }
        _em_tok=$(luks_json_count_type "$_em_prej" systemd-tpm2)
        rm -f "$_em_prej"
        _em_wipe=no
        if [ "$_em_tok" -gt 0 ] || [ "$_em_reseat" -eq 1 ]; then
            _em_wipe=yes
        fi
        _em_argvf=$(mktemp "${TMPDIR:-/tmp}/debian-fde-argv.XXXXXX") || die "enroll-tpm: mktemp failed"
        enrl_cryptenroll_argv "$_em_pub" "$_em_wipe" "$_em_dev" >"$_em_argvf"
        set --
        while IFS= read -r _em_a || [ -n "$_em_a" ]; do
            set -- "$@" "$_em_a"
        done <"$_em_argvf"
        rm -f "$_em_argvf"
        info "cryptenroll invocation (policy_mode=$_em_mode, dry-run):"
        printf '  systemd-cryptenroll' >&2
        for _em_a in "$@"; do
            printf ' %s' "$_em_a" >&2
        done
        printf '\n' >&2
        info "dry-run: enrollment not performed; enrolled.json not written"
        return 0
    fi

    # The single A'' enrollment (shared core, G-R3) under the enrollment lock
    # (§8.3 serialization, HW-3); failures die fail-closed 64
    if ! enrl_lock_acquire; then
        die "enroll-tpm: cannot take the enrollment lock — refusing an unserialized enrollment"
    fi
    _em_rc=0
    enrl_run "$_em_mode" "$_em_pub" "$_em_dev" "$_em_reseat" || _em_rc=1
    enrl_lock_release
    if [ "$_em_rc" -ne 0 ]; then
        die "enroll-tpm: enrollment failed — enrolled.json NOT written"
    fi

    if ! enrl_record "$_em_uuid" "$_em_mode" "$ENRL_WIPE" "$ENRL_SLOT" "$_em_pub"; then
        die "enroll-tpm: enrollment succeeded but enrolled.json could NOT be written — fix the state directory and re-run (loud failure, ADR-8)"
    fi
    printf 'debian-fde: enrolled (policy_mode=%s, token keyslot %s, wipe=%s); record: %s\n' \
        "$_em_mode" "$ENRL_SLOT" "$ENRL_WIPE" "$(sp_enrolled_file)" >&2
    return 0
}
