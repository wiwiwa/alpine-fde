#!/bin/sh
# common.sh — Debian FDE shared runtime: exit-code contract, strict-mode helper,
# logging, config loader, TCTI wrapper for tpm2-tools, command preconditions.
# Library only: sourcing has no side effects and never enables strict mode by itself.

# --- exit-code contract (docs/Architecture.md §8.1) ---------------------------
# shellcheck disable=SC2034  # exit-code API consumed by cmd implementations and tests
DEBIAN_FDE_OK=0 # success
# shellcheck disable=SC2034
DEBIAN_FDE_DRIFT=1 # drift detected / check failed (a result, not a crash)
DEBIAN_FDE_USAGE=2 # bad CLI usage — print usage and exit
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
# The prefix carries the INVOKED program name: bin/alpine-fde signals
# DEBIAN_FDE_PROG=alpine-fde (§8.1); unset → historical "debian-fde".
info() { printf '%s: info: %s\n' "${DEBIAN_FDE_PROG:-debian-fde}" "$*" >&2; }
warn() { printf '%s: warn: %s\n' "${DEBIAN_FDE_PROG:-debian-fde}" "$*" >&2; }
err() { printf '%s: error: %s\n' "${DEBIAN_FDE_PROG:-debian-fde}" "$*" >&2; }

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
# config_path — effective config file path (§8.4). $DEBIAN_FDE_CONF (typically
# via the ALPINE_FDE_CONF alias, §8.1) overrides the default; clean rename to
# the Alpine path — no legacy Debian-era fallback.
config_path() {
  printf '%s\n' "${DEBIAN_FDE_CONF:-/etc/alpine-fde/alpine-fde.conf}"
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

# --- environment aliases (§8.1, ADR-15) -------------------------------------------
# env_alias_apply — ALPINE_FDE_* is the canonical spelling of the DEBIAN_FDE_*
# environment surface (Debian→Alpine pivot). Copies every set ALPINE_FDE_<NAME>
# onto its DEBIAN_FDE_<NAME> twin, so ALPINE_FDE_* WINS over a co-set
# DEBIAN_FDE_* twin; CLI flags are parsed later and beat both. Sourcing this
# library stays side-effect-free: entry points call this explicitly BEFORE
# load_config. Resolution order: CLI flags > ALPINE_FDE_* > DEBIAN_FDE_* > conf.
env_alias_apply() {
  # shellcheck disable=SC2046  # deliberate word split over the alias table
  for _sp_a in NO_INSTALL ROOT ESP DISK DISKS BCACHE FS TCTI KEYDIR CONF; do
    eval "test \"\${ALPINE_FDE_${_sp_a}+x}\"" || continue
    eval "DEBIAN_FDE_${_sp_a}=\$ALPINE_FDE_${_sp_a}"
    # shellcheck disable=SC2163  # deliberate dynamic export
    eval "export DEBIAN_FDE_${_sp_a}"
  done
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

# require_pkgs binary:package ... — require_cmds plus on-demand install of the
# corresponding package on the live host (ADR-15: runs from an Alpine live ISO,
# with a Debian live launcher as fallback).
#   * binary already on PATH → satisfied, no package manager touched
#   * else, if a backend exists and *_FDE_NO_INSTALL unset: `apk update` or
#     `apt-get update` (once per process), then `apk add <pkg>` or
#     `DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends
#     <pkg>` per missing pair; binary re-checked after install
#   * any failure (no backend, DEBIAN_FDE_NO_INSTALL set, backend error, or
#     binary still absent after install) ⇒ die(64, fail-closed) with the exact
#     manual install line for the backend that ran (ADR-8: fail loudly, never
#     degrade silently). Environment failures are NOT usage errors: 64 = missing
#     tools, 2 = bad CLI usage (G-I7).
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
      "missing packages but DEBIAN_FDE_NO_INSTALL is set — install manually:$_sp_pkgs (apk add$_sp_pkgs | apt-get install -y --no-install-recommends$_sp_pkgs)"
  fi

  # dual backend: apk (Alpine live host) or apt-get (Debian) — whichever the
  # host actually has; NEITHER must fail closed 64 naming the packages, never
  # an accidental 127 from invoking an absent manager (ADR-15: loud failures)
  if command -v apk >/dev/null 2>&1; then
    _SP_PKGS_BACKEND=apk
    if [ -z "${_SP_PKGS_UPDATED:-}" ]; then
      info "apk update ..."
      apk update || die \
        "apk update failed (no network?) — install manually: apk add$_sp_pkgs"
      _SP_PKGS_UPDATED=1
    fi
    # shellcheck disable=SC2086  # package names never contain spaces
    for _sp_pkg in $_sp_pkgs; do
      info "installing missing package: $_sp_pkg"
      apk add "$_sp_pkg" || \
        die \
          "apk add $_sp_pkg failed — install manually: apk add$_sp_pkgs"
    done
  else
    if ! command -v apt-get >/dev/null 2>&1; then
      die \
        "no package manager (apk|apt-get) found (non-Debian system?) for missing:$_sp_pkgs — install manually: apk add$_sp_pkgs | apt-get install -y --no-install-recommends$_sp_pkgs"
    fi
    _SP_PKGS_BACKEND=apt-get
    if [ -z "${_SP_PKGS_UPDATED:-}" ]; then
      info "apt-get update ..."
      apt-get update || die \
        "apt-get update failed (no network?) — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
      _SP_PKGS_UPDATED=1
    fi
    # shellcheck disable=SC2086  # package names never contain spaces
    for _sp_pkg in $_sp_pkgs; do
      info "installing missing package: $_sp_pkg"
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$_sp_pkg" || \
        die \
          "apt-get install $_sp_pkg failed — install manually: apt-get install -y --no-install-recommends$_sp_pkgs"
    done
  fi

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
    if [ "$_SP_PKGS_BACKEND" = apk ]; then
      die \
        "package install did not provide the expected binary (for:$_sp_still) — install manually: apk add$_sp_still_pkgs"
    fi
    die \
      "package install did not provide the expected binary (for:$_sp_still) — install manually: apt-get install -y --no-install-recommends$_sp_still_pkgs"
  fi
}

# policy_mode_normalize MODE — canonicalize the ladder naming across commands.
# ADR-19/ADR-20: on Alpine, Mechanism B (rung b) is the NORMATIVE sealing
# pipeline — systemd-cryptenroll is not packaged on Alpine, so Mechanism A is
# unavailable and rung b is the only implementable mechanism. b is canonical;
# the A″ spellings (a2 / a-prime-prime / native) remain accepted as aliases —
# same policy construction (static-PCR7 + release-key-signed PCR11 under
# PolicyAuthorize). Rungs a / ap / a-prime / combined stay documented-absent
# and fail closed HERE (rc 64) so every entry point (ukictl build, enroll-tpm,
# ...) inherits the same loud rejection citing ADR-19.
# Unknown garbage → rc 1 (caller decides usage vs fail-closed).
policy_mode_normalize() {
  case ${1:-} in
  b | a2 | a-prime-prime | native) printf '%s\n' b ;;
  a | ap | a-prime | combined)
    err "POLICY_MODE=${1:-} is documented-absent (ADR-19): Mechanism B (rung b) is the normative path on Alpine"
    return "$DEBIAN_FDE_FAIL_CLOSED"
    ;;
  *) return 1 ;;
  esac
}

return 0
