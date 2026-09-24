#!/bin/sh
# common_env_namespace.sh — the ALPINE_FDE_* environment namespace (§8.1):
#   * ALPINE_FDE_* is the ONLY accepted spelling — the retired DEBIAN_FDE_*
#     compat spellings are no longer honored anywhere (alpine-fde rename)
#   * the env_alias_apply alias layer is GONE; variables are read directly
#     (precedence: CLI flags > ALPINE_FDE_* > config file)
#   * sourcing common.sh stays side-effect-free (contract: common_exitcodes.sh)
#   * ALPINE_FDE_NO_INSTALL=1 alone disables auto-install (rc 64 + manual list)

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/common.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- the alias layer is retired -----------------------------------------------------
assert_eq "env_alias_apply is gone (retired with the DEBIAN_FDE_* spellings)" "no" \
    "$(command -v env_alias_apply >/dev/null 2>&1 && echo yes || echo no)"

# --- ALPINE_FDE_* read directly: nothing rewrites or conjures variables -------------
out=$(
    unset ALPINE_FDE_ROOT
    ALPINE_FDE_ROOT=/t/root
    export ALPINE_FDE_ROOT
    sh -c '. "$1/lib/common.sh"; printf "%s" "${ALPINE_FDE_ROOT-UNSET}"' sh "$REPO_ROOT"
)
assert_eq "ALPINE_FDE_* visible verbatim in a fresh consumer process" "/t/root" "$out"

# --- the retired DEBIAN_FDE_* spelling is NOT honored --------------------------------
out=$(
    unset ALPINE_FDE_ROOT
    DEBIAN_FDE_ROOT=/retired-spelling
    export DEBIAN_FDE_ROOT
    sh -c '. "$1/lib/common.sh"; printf "%s" "${ALPINE_FDE_ROOT-UNSET}"' sh "$REPO_ROOT"
)
assert_eq "retired DEBIAN_FDE_ROOT does not conjure ALPINE_FDE_ROOT" "UNSET" "$out"

# --- sourcing stays side-effect-free --------------------------------------------------
out=$(
    unset ALPINE_FDE_ROOT
    ALPINE_FDE_ROOT=/source-must-not-export
    export ALPINE_FDE_ROOT
    sh -c '. "$1/lib/common.sh"; printf "%s" "${ALPINE_FDE_ROOT-UNSET}"' sh "$REPO_ROOT"
)
assert_eq "sourcing common.sh applies no aliases (fresh process)" "/source-must-not-export" "$out"

# --- ALPINE_FDE_CONF override honored by config_path ----------------------------------
out=$(
    unset ALPINE_FDE_CONF
    ALPINE_FDE_CONF=/t/from-alpine.conf
    export ALPINE_FDE_CONF
    config_path
)
assert_eq "ALPINE_FDE_CONF override honored by config_path" "/t/from-alpine.conf" "$out"

# --- ALPINE_FDE_NO_INSTALL=1 alone disables auto-install (rc 64 + manual list) --------
# fake apk on PATH: any invocation is logged and "succeeds", so the ONLY way this
# call may fail is the NO_INSTALL escape hatch firing before a backend is touched.
fakebin="$tmp/fakebin"
mkdir -p "$fakebin"
pkmgr_log="$tmp/pkmgr.log"
: >"$pkmgr_log"
printf '#!/bin/sh\nprintf "CALLED %%s\\n" "$*" >>"%s"\nexit 0\n' "$pkmgr_log" >"$fakebin/apk"
chmod +x "$fakebin/apk"
rc=0
msg=$(
    unset ALPINE_FDE_NO_INSTALL
    ALPINE_FDE_NO_INSTALL=1
    export ALPINE_FDE_NO_INSTALL
    PATH="$fakebin"
    export PATH
    require_pkgs absent-a:pkg-a 2>&1
) || rc=$?
assert_rc "ALPINE_FDE_NO_INSTALL=1 alone -> exit 64 (fail-closed)" "64" "$rc"
assert_contains "ALPINE_FDE_NO_INSTALL message names the escape hatch" \
    "$msg" "NO_INSTALL is set"
assert_eq "ALPINE_FDE_NO_INSTALL=1 -> package manager never invoked" "" "$(cat "$pkmgr_log")"

finish
