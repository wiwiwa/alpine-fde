#!/bin/sh
# common.sh — Debian FDE shared runtime: exit-code contract, strict-mode helper,
# logging, config loader, TCTI wrapper for tpm2-tools, command preconditions.
# Library only: sourcing has no side effects and never enables strict mode by itself.

# --- exit-code contract (docs/Architecture.md §8.1) ---------------------------
# shellcheck disable=SC2034  # exit-code API consumed by cmd implementations and tests
DEBIAN_FDE_OK=0              # success
# shellcheck disable=SC2034
DEBIAN_FDE_DRIFT=1           # drift detected / check failed (a result, not a crash)
DEBIAN_FDE_USAGE=2           # bad CLI usage — print usage and exit
# shellcheck disable=SC2034
DEBIAN_FDE_NOT_IMPLEMENTED=3 # known subcommand whose implementation has not landed yet
DEBIAN_FDE_FAIL_CLOSED=64    # fail-closed error (missing tools, violated precondition, ...)

if [ -n "${DEBIAN_FDE_COMMON_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_COMMON_LOADED=1

# --- strict mode ---------------------------------------------------------------
# strict_mode — enable errexit + unset-variable errors. Scripts opt in explicitly;
# the library must stay sourceable from loose shells (e.g. unit tests).
strict_mode() {
    set -eu
}

# --- logging (all to stderr; stdout stays clean for data) ----------------------
info() { printf 'debian-fde: info: %s\n' "$*" >&2; }
warn() { printf 'debian-fde: warn: %s\n' "$*" >&2; }
err() { printf 'debian-fde: error: %s\n' "$*" >&2; }

# die [-r RC] message... — log an error and exit; default exit code: fail-closed
die() {
    _sp_rc=$DEBIAN_FDE_FAIL_CLOSED
    if [ "${1:-}" = "-r" ]; then
        _sp_rc=$2
        shift 2
    fi
    err "$*"
    exit "$_sp_rc"
}

# --- config ---------------------------------------------------------------------
# config_path — effective config file path ($DEBIAN_FDE_CONF overrides the default)
config_path() {
    printf '%s\n' "${DEBIAN_FDE_CONF:-/etc/debian-fde/debian-fde.conf}"
}

# load_config — parse the KEY=VALUE config into the environment.
#   * missing file is fine (no-op, rc 0)
#   * '#' comments and blank lines ignored
#   * keys must match [A-Za-z_][A-Za-z0-9_]* after trimming spaces/tabs
#   * one matching pair of surrounding quotes on a value is stripped; inner text verbatim
#   * the environment wins: an already-set variable is never clobbered by the file
load_config() {
    _sp_conf=$(config_path)
    if [ ! -f "$_sp_conf" ]; then
        return 0
    fi
    _sp_cr=$(printf '\r')
    while IFS= read -r _sp_line || [ -n "$_sp_line" ]; do
        _sp_line=${_sp_line%"$_sp_cr"}
        case $_sp_line in
            '' | '#'*)
                continue
                ;;
        esac
        case $_sp_line in
            *=*) _sp_val=${_sp_line#*=} ;;
            *)
                warn "config: line without '=' skipped: $_sp_line"
                continue
                ;;
        esac
        _sp_key=$(printf '%s' "${_sp_line%%=*}" | tr -d ' \t')
        _sp_val=$(printf '%s' "$_sp_val" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        case $_sp_val in
            '"'*)
                case $_sp_val in
                    '"'*'"')
                        _sp_val=${_sp_val#\"}
                        _sp_val=${_sp_val%\"}
                        ;;
                esac
                ;;
            "'"*)
                case $_sp_val in
                    "'"*"'")
                        _sp_val=${_sp_val%\'}
                        _sp_val=${_sp_val#\'}
                        ;;
                esac
                ;;
        esac
        case $_sp_key in
            '')
                continue
                ;;
            [0-9]* | *[!A-Za-z0-9_]*)
                warn "config: invalid key skipped: $_sp_key"
                continue
                ;;
        esac
        # environment wins over the config file
        if eval "test \"\${${_sp_key}+x}\""; then
            continue
        fi
        # shellcheck disable=SC2086  # key is validated above
        eval "${_sp_key}=\$_sp_val"
        # shellcheck disable=SC2163  # deliberate dynamic export; key validated above
        export "$_sp_key"
    done <"$_sp_conf"
    return 0
}

# --- TPM access ------------------------------------------------------------------
# tpm — run tpm2-tools with the configured TCTI.
# DEBIAN_FDE_TCTI empty/unset → TPM2TOOLS_TCTI set to empty → tctildr default discovery.
# `command` bypasses any shell function named tpm2 (no recursion, real binary only).
tpm() {
    TPM2TOOLS_TCTI="${DEBIAN_FDE_TCTI:-}" command tpm2 "$@"
}

# --- preconditions -----------------------------------------------------------------
# require_cmds cmd... — die (fail-closed) unless every named command is on PATH
require_cmds() {
    _sp_missing=''
    for _sp_c in "$@"; do
        if ! command -v "$_sp_c" >/dev/null 2>&1; then
            _sp_missing="$_sp_missing $_sp_c"
        fi
    done
    if [ -n "$_sp_missing" ]; then
        die "missing required commands:$_sp_missing"
    fi
}

# require_pkgs binary:debian-package ... — require_cmds plus on-demand install of the
# corresponding Debian package (debian-fde must run from a Debian live ISO).
#   * binary already on PATH → satisfied, no package manager touched
#   * else, if apt-get exists and DEBIAN_FDE_NO_INSTALL is unset: `apt-get update`
#     (once per process), then `DEBIAN_FRONTEND=noninteractive apt-get install -y
#     --no-install-recommends <pkg>` per missing pair; binary re-checked after install
#   * any failure (no apt-get / non-Debian, DEBIAN_FDE_NO_INSTALL set, apt error, or
#     binary still absent after install) ⇒ die(64, fail-closed) with the exact manual
#     install line (ADR-8: fail loudly, never degrade silently). Only apt-get is ever
#     attempted. Environment failures are NOT usage errors: 64 = missing tools, 2 =
#     bad CLI usage (G-I7).
require_pkgs() {
    _sp_missing=''
    for _sp_pair in "$@"; do
        _sp_bin=${_sp_pair%%:*}
        if command -v "$_sp_bin" >/dev/null 2>&1; then
            continue
        fi
        _sp_missing="$_sp_missing $_sp_pair"
    done
    if [ -z "$_sp_missing" ]; then
        return 0
    fi

    _sp_pkgs=''
    # shellcheck disable=SC2086  # pairs never contain spaces
    for _sp_pair in $_sp_missing; do
        _sp_pkgs="$_sp_pkgs ${_sp_pair#*:}"
    done

    if [ -n "${DEBIAN_FDE_NO_INSTALL:-}" ]; then
        die \
            "missing packages but DEBIAN_FDE_NO_INSTALL is set — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        die \
            "apt-get not found (non-Debian system?) — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
    fi

    if [ -z "${_SP_APT_UPDATED:-}" ]; then
        info "apt-get update ..."
        apt-get update || die \
            "apt-get update failed (no network?) — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
        _SP_APT_UPDATED=1
    fi
    # shellcheck disable=SC2086  # package names never contain spaces
    for _sp_pkg in $_sp_pkgs; do
        info "installing missing package: $_sp_pkg"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$_sp_pkg" || \
            die \
                "apt-get install $_sp_pkg failed — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
    done

    # install claims success — the binary must now exist (catches wrong/missing pairs)
    _sp_still=''
    # shellcheck disable=SC2086
    for _sp_pair in $_sp_missing; do
        _sp_bin=${_sp_pair%%:*}
        if ! command -v "$_sp_bin" >/dev/null 2>&1; then
            _sp_still="$_sp_still $_sp_pair"
        fi
    done
    if [ -n "$_sp_still" ]; then
        _sp_still_pkgs=''
        # shellcheck disable=SC2086
        for _sp_pair in $_sp_still; do
            _sp_still_pkgs="$_sp_still_pkgs ${_sp_pair#*:}"
        done
        die \
            "package install did not provide the expected binary (for:$_sp_still) — install manually: apt-get install -y --no-install-recommends$_sp_still_pkgs"
    fi
}

# policy_mode_normalize MODE — canonicalize the ladder naming across commands.
# ADR-14: the ladder is RESOLVED — Mechanism A″ (a2) is the proven pipeline
# mode; rungs a / ap / b are documented-absent and fail closed HERE (rc 64)
# so every entry point (ukictl build, enroll-tpm, ...) inherits the same loud
# rejection citing ADR-14. Canonical: a2 (aliases: a-prime-prime, native).
# Unknown garbage → rc 1 (caller decides usage vs fail-closed).
policy_mode_normalize() {
    case ${1:-} in
        a2 | a-prime-prime | native)  printf '%s\n' a2 ;;
        ap | a-prime | combined | a | b)
            err "POLICY_MODE=${1:-} is documented-absent (ADR-14): Mechanism A'' is the proven path"
            return "$DEBIAN_FDE_FAIL_CLOSED"
            ;;
        *) return 1 ;;
    esac
}

return 0
