#!/bin/sh
# install-state.sh — /etc/debian-fde/install-state.json: the install ceremony
# state machine (§8.4, §9.1, gap G-IL1). The vocabulary is exactly
# `installed` → `finalized` — no provisional token/state anywhere:
#
#   `installed`  Stage 1 done (chroot provisioning + reboot-to-BIOS pending);
#                volume protected by the keyslot 0 recovery passphrase only
#   `finalized`  Stage 3 done (Secure Boot verified, baseline final, TPM
#                enrollment standing for every crypttab member)
#
# Document schema v1 (every value quoted except schema_version):
#   { "schema_version": 1, "state": "installed|finalized", "updated_at": "<ISO8601 UTC>" }
#
# Writes are ATOMIC (temp document next to the target + mv) so a crash
# mid-write leaves the previous state readable — the §9.1 crash idempotency
# depends on it. Library only: sourcing has no side effects.

if [ -n "${DEBIAN_FDE_INSTALL_STATE_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_INSTALL_STATE_LOADED=1

# Pull in common.sh (exit codes, logging) and baseline.sh (sp_etc_dir) the
# same way the cmd files resolve their siblings. When this file lives at
# <tree>/lib/install-state.sh, the cmd dir is <tree>/lib/cmd.
_is_cmd_dir=${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}
_is_lib_dir=${_is_cmd_dir%/*}
if [ -z "${DEBIAN_FDE_COMMON_LOADED:-}" ] && [ -r "$_is_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from DEBIAN_FDE_CMD_DIR / install tree
    . "$_is_lib_dir/common.sh"
fi
if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ] && [ -r "$_is_lib_dir/baseline.sh" ]; then
    # shellcheck disable=SC1090
    . "$_is_lib_dir/baseline.sh"
fi

# istate_file — $(sp_etc_dir)/install-state.json; DEBIAN_FDE_INSTALL_STATE
# overrides the path wholesale (tests).
istate_file() {
    if [ -n "${DEBIAN_FDE_INSTALL_STATE:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_INSTALL_STATE"
        return 0
    fi
    printf '%s/install-state.json\n' "$(sp_etc_dir)"
}

# istate_get FILE KEY — top-level scalar value (fixed 2-space layout, same
# parser style as baseline_get); empty when absent
istate_get() {
    sed -n "s/^  \"$2\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1"
}

# istate_state [FILE] — print the state value; empty + warn when the document
# is absent (pre-state-machine installs) or carries no readable state. An
# explicit FILE argument is read as-is (consumed by enroll-tpm.sh's G-IL7
# install-state reader); without one the path resolves via istate_file.
# Report only: rc 0, the CALLER decides what empty/garbage means.
# shellcheck disable=SC2120  # the FILE arg is passed by external consumers (enroll-tpm.sh G-IL7 reader, tests)
istate_state() {
    if [ -n "${1:-}" ]; then
        _is_f=$1
    else
        _is_f=$(istate_file)
    fi
    if [ ! -f "$_is_f" ]; then
        warn "install-state: no state file at $_is_f (pre-state-machine install?)"
        return 0
    fi
    _is_s=$(istate_get "$_is_f" state)
    if [ -z "$_is_s" ]; then
        warn "install-state: no readable state in $_is_f"
        return 0
    fi
    printf '%s\n' "$_is_s"
}

# istate_is_finalized — rc 0 iff the state reads exactly `finalized`
istate_is_finalized() {
    [ "$(istate_state 2>/dev/null)" = "finalized" ]
}

# istate_write STATE — validate (installed|finalized, fail-closed 64 on
# anything else) and atomically install the state document (temp next to the
# target + chmod 600 BEFORE the rename — no partial document, no umask window;
# same pattern as enrl_record / baseline finalize).
istate_write() {
    _is_new=$1
    case $_is_new in
        installed | finalized) : ;;
        *)
            die "istate_write: unknown install state '$_is_new' (want: installed|finalized)"
            ;;
    esac
    _is_f=$(istate_file)
    _is_dir=${_is_f%/*}
    if ! mkdir -p "$_is_dir"; then
        die "istate_write: cannot create state directory $_is_dir"
    fi
    _is_tmp=$(mktemp "$_is_dir/.install-state.XXXXXX") || {
        die "istate_write: cannot create temp document in $_is_dir"
    }
    {
        printf '{\n'
        printf '  "schema_version": 1,\n'
        printf '  "state": "%s",\n' "$_is_new"
        printf '  "updated_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '}\n'
    } >"$_is_tmp" || {
        rm -f "$_is_tmp"
        die "istate_write: cannot write temp document in $_is_dir"
    }
    chmod 600 "$_is_tmp"
    if ! mv -f "$_is_tmp" "$_is_f"; then
        rm -f "$_is_tmp"
        die "istate_write: atomic replace of $_is_f failed"
    fi
    return 0
}

return 0
