#!/bin/sh
# common_require_pkgs.sh — unit tests for lib/common.sh require_pkgs() using a
# stubbed apt-get on PATH (no network, no real package manager, no root).

TEST_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$TEST_DIR/../.." && pwd)

# shellcheck disable=SC1091
. "$REPO_ROOT/tests/unit/lib.sh"
# shellcheck disable=SC1091
. "$REPO_ROOT/lib/common.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

tmpbin="$tmp/bin"
mkdir -p "$tmpbin"
FAKE_APT_LOG="$tmp/apt.log"
FAKE_BIN_DIR="$tmpbin"
export FAKE_APT_LOG FAKE_BIN_DIR
: >"$FAKE_APT_LOG"

cat >"$tmpbin/apt-get" <<'EOF'
#!/bin/sh
# fake apt-get stub: log actions; on install, create the binary mapped to each
# installed package via $FAKE_INSTALL_MAKES (pkg:binary pairs); failure simulated
# via $FAKE_APT_FAIL.
if [ "${1:-}" = update ]; then
    printf 'update\n' >>"$FAKE_APT_LOG"
    exit "${FAKE_APT_UPDATE_RC:-0}"
fi
if [ "${1:-}" = install ]; then
    printf 'frontend=%s %s\n' "${DEBIAN_FRONTEND-}" "$*" >>"$FAKE_APT_LOG"
    if [ "${FAKE_APT_FAIL:-0}" = 1 ]; then
        printf 'E: Unable to locate package\n' >&2
        exit 100
    fi
    shift
    for a in "$@"; do
        for entry in ${FAKE_INSTALL_MAKES:-}; do
            if [ "${entry%%:*}" = "$a" ]; then
                printf '#!/bin/sh\n' >"$FAKE_BIN_DIR/${entry#*:}"
                chmod +x "$FAKE_BIN_DIR/${entry#*:}"
            fi
        done
    done
    exit 0
fi
printf 'E: bogus operation\n' >&2
exit 2
EOF
chmod +x "$tmpbin/apt-get"

: >"$tmpbin/present-tool"
chmod +x "$tmpbin/present-tool"

PATH="$tmpbin:$PATH"
export PATH

reset_log() {
    : >"$FAKE_APT_LOG"
}

# --- all binaries present: no package manager touched ---
rc=0
require_pkgs sh:coreutils present-tool:present-pkg >/dev/null 2>&1 || rc=$?
assert_rc "require_pkgs: all present -> rc 0" "0" "$rc"
assert_eq "require_pkgs: all present -> no apt-get calls" "" "$(cat "$FAKE_APT_LOG")"

# --- missing binaries + apt available: update once, install requested pkgs, binary found;
# --- a second require_pkgs call in the SAME process must not re-run apt-get update ---
FAKE_INSTALL_MAKES="pkg-one:newtool1 pkg-two:newtool2 pkg-three:newtool3"
export FAKE_INSTALL_MAKES
out=$(
    require_pkgs newtool1:pkg-one newtool2:pkg-two 2>&1 || echo CALL1-FAILED
    require_pkgs newtool3:pkg-three 2>&1 || echo CALL2-FAILED
    command -v newtool1 >/dev/null 2>&1 && echo HAS-TOOL1
    command -v newtool3 >/dev/null 2>&1 && echo HAS-TOOL3
)
assert_contains "require_pkgs: install path succeeds (call 1)" "$out" "HAS-TOOL1"
assert_contains "require_pkgs: later call succeeds (call 2)" "$out" "HAS-TOOL3"
assert_contains "require_pkgs: logs what it installs" "$out" "installing missing package: pkg-one"
assert_eq "require_pkgs: no call failed" \
    "0" "$(printf '%s\n' "$out" | grep -c FAILED)"
assert_eq "require_pkgs: apt-get update ran once per process" \
    "1" "$(grep -c '^update$' "$FAKE_APT_LOG")"
assert_eq "require_pkgs: install uses noninteractive frontend" \
    "1" "$(grep -c '^frontend=noninteractive install -y --no-install-recommends pkg-one$' "$FAKE_APT_LOG")"
assert_eq "require_pkgs: second requested pkg installed too" \
    "1" "$(grep -c 'install -y --no-install-recommends pkg-two$' "$FAKE_APT_LOG")"
assert_eq "require_pkgs: third call installed its pkg without re-update" \
    "1" "$(grep -c 'install -y --no-install-recommends pkg-three$' "$FAKE_APT_LOG")"

# --- DEBIAN_FDE_NO_INSTALL=1: loud failure with manual instructions, apt untouched ---
# exit contract: environment failures are FAIL-CLOSED (64), not usage (2) — G-I7
reset_log
lines_before=$(wc -l <"$FAKE_APT_LOG")
rc=0
msg=$(DEBIAN_FDE_NO_INSTALL=1 require_pkgs absent-a:pkg-a 2>&1) || rc=$?
assert_rc "require_pkgs: DEBIAN_FDE_NO_INSTALL -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: manual install line listed" \
    "$msg" "apt-get install -y --no-install-recommends pkg-a"
assert_eq "require_pkgs: DEBIAN_FDE_NO_INSTALL -> apt untouched" \
    "$lines_before" "$(wc -l <"$FAKE_APT_LOG")"

# --- apt-get absent (non-Debian / stripped PATH): loud failure, manual instructions ---
rc=0
msg=$(PATH="$tmp/void" require_pkgs absent-b:pkg-b 2>&1) || rc=$?
assert_rc "require_pkgs: no apt-get -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: no-apt message lists the package" \
    "$msg" "apt-get install -y --no-install-recommends pkg-b"
assert_contains "require_pkgs: no-apt message mentions non-Debian" "$msg" "non-Debian"

# --- apt-get install fails: loud failure with the manual line ---
reset_log
FAKE_APT_FAIL=1
export FAKE_APT_FAIL
FAKE_INSTALL_MAKES="irrelevant-thing"
rc=0
msg=$(require_pkgs absent-c:pkg-c 2>&1 >/dev/null) || rc=$?
assert_rc "require_pkgs: apt install failure -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: apt failure names the package" \
    "$msg" "apt-get install pkg-c failed"
unset FAKE_APT_FAIL

# --- install "succeeds" but binary still absent (bad pair): loud failure ---
reset_log
FAKE_INSTALL_MAKES="pkg-e:wrong-thing"
rc=0
msg=$(require_pkgs ghostbin:pkg-d 2>&1 >/dev/null) || rc=$?
assert_rc "require_pkgs: binary missing after install -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: post-install recheck lists manual line" \
    "$msg" "apt-get install -y --no-install-recommends pkg-d"

# --- explicit exit-code contract: every require_pkgs failure mode is 64 (G-I7) ---
# 64 = fail-closed "missing tools"; 2 stays reserved for bad CLI usage. Pin both
# halves so a future regression in either direction is caught.
reset_log
rc=0
msg=$(DEBIAN_FDE_NO_INSTALL=1 require_pkgs absent-x:pkg-x 2>&1) || rc=$?
assert_rc "require_pkgs: rc 64 == missing tools (fail-closed environment failure)" "64" "$rc"
assert_eq "require_pkgs: rc 2 stays reserved for usage, never environment" "2" "$DEBIAN_FDE_USAGE"

finish
