#!/bin/sh
# common_env_aliases.sh — ALPINE_FDE_* environment alias layer (§8.1, ADR-15;
# Debian→Alpine pivot rev C): ALPINE_FDE_* is the canonical spelling of the
# DEBIAN_FDE_* environment surface.
#   * env_alias_apply maps every ALPINE_FDE_{...} onto its DEBIAN_FDE_{...} twin
#   * precedence: ALPINE_FDE_* WINS over a co-set DEBIAN_FDE_* twin (canonical);
#     CLI flags are parsed later and beat both
#   * sourcing common.sh stays side-effect-free — aliases apply only when
#     env_alias_apply is explicitly called (contract: common_exitcodes.sh)
#   * ALPINE_FDE_NO_INSTALL=1 alone disables auto-install (rc 64 + manual list)

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/common.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- env_alias_apply maps every ALPINE_FDE_* twin ---------------------------------
out=$(
    for _v in DEBIAN_FDE_NO_INSTALL DEBIAN_FDE_ROOT DEBIAN_FDE_ESP \
              DEBIAN_FDE_DISK DEBIAN_FDE_DISKS DEBIAN_FDE_BCACHE DEBIAN_FDE_FS \
              DEBIAN_FDE_TCTI DEBIAN_FDE_KEYDIR DEBIAN_FDE_CONF; do
        unset "$_v"
    done
    ALPINE_FDE_NO_INSTALL=1
    ALPINE_FDE_ROOT=/t/root
    ALPINE_FDE_ESP=/t/esp
    ALPINE_FDE_DISK=/t/disk
    ALPINE_FDE_DISKS=/t/d1
    ALPINE_FDE_BCACHE=/t/bcache
    ALPINE_FDE_FS=ext4
    ALPINE_FDE_TCTI=/t/tcti
    ALPINE_FDE_KEYDIR=/t/keys
    ALPINE_FDE_CONF=/t/alpine-fde.conf
    export ALPINE_FDE_NO_INSTALL ALPINE_FDE_ROOT ALPINE_FDE_ESP ALPINE_FDE_DISK \
        ALPINE_FDE_DISKS ALPINE_FDE_BCACHE ALPINE_FDE_FS ALPINE_FDE_TCTI \
        ALPINE_FDE_KEYDIR ALPINE_FDE_CONF
    env_alias_apply
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
        "${DEBIAN_FDE_NO_INSTALL-}" "${DEBIAN_FDE_ROOT-}" "${DEBIAN_FDE_ESP-}" \
        "${DEBIAN_FDE_DISK-}" "${DEBIAN_FDE_DISKS-}" "${DEBIAN_FDE_BCACHE-}" \
        "${DEBIAN_FDE_FS-}" "${DEBIAN_FDE_TCTI-}" "${DEBIAN_FDE_KEYDIR-}" \
        "${DEBIAN_FDE_CONF-}"
)
assert_eq "env_alias_apply maps all ALPINE_FDE_* twins onto DEBIAN_FDE_*" \
    "1|/t/root|/t/esp|/t/disk|/t/d1|/t/bcache|ext4|/t/tcti|/t/keys|/t/alpine-fde.conf" "$out"

# --- precedence: ALPINE_FDE_* wins over a co-set DEBIAN_FDE_* twin ------------------
out=$(
    unset DEBIAN_FDE_ROOT
    ALPINE_FDE_ROOT=/alpine-wins
    DEBIAN_FDE_ROOT=/debian-loses
    export ALPINE_FDE_ROOT DEBIAN_FDE_ROOT
    env_alias_apply
    printf '%s' "${DEBIAN_FDE_ROOT-}"
)
assert_eq "ALPINE_FDE_* wins when both spellings are set" "/alpine-wins" "$out"

# --- DEBIAN_FDE_* kept untouched when ALPINE_FDE_* unset ----------------------------
out=$(
    unset ALPINE_FDE_ROOT
    DEBIAN_FDE_ROOT=/debian-kept
    export DEBIAN_FDE_ROOT
    env_alias_apply
    printf '%s' "${DEBIAN_FDE_ROOT-}"
)
assert_eq "DEBIAN_FDE_* untouched when ALPINE_FDE_* unset" "/debian-kept" "$out"

# --- nothing conjured when neither spelling is set -----------------------------------
out=$(
    unset ALPINE_FDE_ROOT DEBIAN_FDE_ROOT
    env_alias_apply
    printf '%s' "${DEBIAN_FDE_ROOT+conjured}"
)
assert_eq "env_alias_apply conjures nothing when neither is set" "" "$out"

# --- sourcing stays side-effect-free: no aliases applied at source time --------------
out=$(
    unset DEBIAN_FDE_ROOT
    ALPINE_FDE_ROOT=/source-must-not-alias
    export ALPINE_FDE_ROOT
    sh -c '. "$1/lib/common.sh"; printf "%s" "${DEBIAN_FDE_ROOT-UNSET}"' sh "$REPO_ROOT"
)
assert_eq "sourcing common.sh applies no aliases (fresh process)" "UNSET" "$out"

# --- ALPINE_FDE_CONF override honored by config_path ---------------------------------
out=$(
    unset DEBIAN_FDE_CONF
    ALPINE_FDE_CONF=/t/from-alpine.conf
    export ALPINE_FDE_CONF
    env_alias_apply
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
    unset DEBIAN_FDE_NO_INSTALL
    ALPINE_FDE_NO_INSTALL=1
    export ALPINE_FDE_NO_INSTALL
    env_alias_apply
    PATH="$fakebin"
    export PATH
    require_pkgs absent-a:pkg-a 2>&1
) || rc=$?
assert_rc "ALPINE_FDE_NO_INSTALL=1 alone -> exit 64 (fail-closed)" "64" "$rc"
assert_contains "ALPINE_FDE_NO_INSTALL message names the escape hatch" \
    "$msg" "NO_INSTALL is set"
assert_eq "ALPINE_FDE_NO_INSTALL=1 -> package manager never invoked" "" "$(cat "$pkmgr_log")"

finish
