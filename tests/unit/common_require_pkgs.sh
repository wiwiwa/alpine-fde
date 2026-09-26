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

# --- ALPINE_FDE_NO_INSTALL=1: loud failure with manual instructions, apt untouched ---
# exit contract: environment failures are FAIL-CLOSED (64), not usage (2) — G-I7
reset_log
lines_before=$(wc -l <"$FAKE_APT_LOG")
rc=0
msg=$(ALPINE_FDE_NO_INSTALL=1 require_pkgs absent-a:pkg-a 2>&1) || rc=$?
assert_rc "require_pkgs: ALPINE_FDE_NO_INSTALL -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: manual install line listed" \
    "$msg" "apt-get install -y --no-install-recommends pkg-a"
assert_eq "require_pkgs: ALPINE_FDE_NO_INSTALL -> apt untouched" \
    "$lines_before" "$(wc -l <"$FAKE_APT_LOG")"

# --- apt-get absent (non-Debian / stripped PATH): loud failure, manual instructions ---
rc=0
msg=$(PATH="$tmp/void" require_pkgs absent-b:pkg-b 2>&1) || rc=$?
assert_rc "require_pkgs: no apt-get -> exit 64 (missing tools, fail-closed)" "64" "$rc"
assert_contains "require_pkgs: no-apt message lists the package" \
    "$msg" "apt-get install -y --no-install-recommends pkg-b"
assert_contains "require_pkgs: no-apt message mentions non-Debian" "$msg" "non-Debian"
assert_eq "require_pkgs: absent manager never leaks rc 127 (loud 64, ADR-15)" \
    "" "$(printf '%s\n' "$rc" | grep -x 127)"

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

# --- apk backend (ADR-15: Alpine live ISO host) ------------------------------------
# Stubbed apk in its OWN dir, prepended to PATH only for these cases: apk wins the
# backend choice while the apt-get stub above stays present (dual-manager host).
tmpapk="$tmp/apkbin"
mkdir -p "$tmpapk"
FAKE_APK_LOG="$tmp/apk.log"
export FAKE_APK_LOG
: >"$FAKE_APK_LOG"

cat >"$tmpapk/apk" <<'EOF'
#!/bin/sh
# fake apk stub: log actions; on add, create the binary mapped to each installed
# package via $FAKE_INSTALL_MAKES (pkg:binary pairs); failure simulated via
# $FAKE_APK_FAIL / $FAKE_APK_UPDATE_RC.
if [ "${1:-}" = update ]; then
    printf 'update\n' >>"$FAKE_APK_LOG"
    exit "${FAKE_APK_UPDATE_RC:-0}"
fi
if [ "${1:-}" = add ]; then
    shift
    printf 'add %s\n' "$*" >>"$FAKE_APK_LOG"
    if [ "${FAKE_APK_FAIL:-0}" = 1 ]; then
        printf 'ERROR: unable to select packages\n' >&2
        exit 99
    fi
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
printf 'apk: bogus operation\n' >&2
exit 2
EOF
chmod +x "$tmpapk/apk"

APKPATH="$tmpapk:$tmpbin:$PATH"

reset_apk_log() {
    : >"$FAKE_APK_LOG"
}

# apk preferred over apt-get when both managers are present
reset_log
reset_apk_log
FAKE_INSTALL_MAKES="pkg-apk1:apktool1"
export FAKE_INSTALL_MAKES
rc=0
out=$(
    PATH="$APKPATH"
    export PATH
    require_pkgs apktool1:pkg-apk1 2>&1
) || rc=$?
assert_rc "require_pkgs: apk backend succeeds" "0" "$rc"
assert_contains "require_pkgs: apk logs what it installs" "$out" "installing missing package: pkg-apk1"
assert_eq "require_pkgs: apk preferred over apt-get when both present" \
    "1" "$(grep -c '^add pkg-apk1$' "$FAKE_APK_LOG")"
assert_eq "require_pkgs: apt-get untouched when apk ran" "" "$(cat "$FAKE_APT_LOG")"

# apk update runs once per process, even across require_pkgs calls
reset_log
reset_apk_log
FAKE_INSTALL_MAKES="pkg-apk2:apktool2 pkg-apk3:apktool3"
out=$(
    PATH="$APKPATH"
    export PATH
    export FAKE_INSTALL_MAKES
    require_pkgs apktool2:pkg-apk2 2>&1 || echo CALL1-FAILED
    require_pkgs apktool3:pkg-apk3 2>&1 || echo CALL2-FAILED
)
assert_eq "require_pkgs: no apk call failed" "0" "$(printf '%s\n' "$out" | grep -c FAILED)"
assert_eq "require_pkgs: apk update ran once per process" "1" "$(grep -c '^update$' "$FAKE_APK_LOG")"
assert_eq "require_pkgs: apk add per package (first)" "1" "$(grep -c '^add pkg-apk2$' "$FAKE_APK_LOG")"
assert_eq "require_pkgs: apk add per package (second)" "1" "$(grep -c '^add pkg-apk3$' "$FAKE_APK_LOG")"

# apk update failure -> 64 with the apk manual line; add never attempted
reset_log
reset_apk_log
FAKE_APK_UPDATE_RC=100
export FAKE_APK_UPDATE_RC
rc=0
out=$(
    PATH="$APKPATH"
    export PATH
    require_pkgs apktool4:pkg-apk4 2>&1
) || rc=$?
assert_rc "require_pkgs: apk update failure -> exit 64 (fail-closed)" "64" "$rc"
assert_contains "require_pkgs: apk update failure names the apk manual line" \
    "$out" "install manually: apk add pkg-apk4"
assert_eq "require_pkgs: apk update failure -> no add attempted" "0" "$(grep -c '^add ' "$FAKE_APK_LOG")"
unset FAKE_APK_UPDATE_RC

# apk add failure -> 64 naming the package
reset_log
reset_apk_log
FAKE_APK_FAIL=1
export FAKE_APK_FAIL
rc=0
out=$(
    PATH="$APKPATH"
    export PATH
    require_pkgs apktool5:pkg-apk5 2>&1
) || rc=$?
assert_rc "require_pkgs: apk add failure -> exit 64 (fail-closed)" "64" "$rc"
assert_contains "require_pkgs: apk add failure names the package" "$out" "apk add pkg-apk5 failed"
unset FAKE_APK_FAIL

# install "succeeds" but binary still absent: the recheck manual line names the
# backend that actually ran (apk), never apt-get
reset_log
reset_apk_log
FAKE_INSTALL_MAKES="pkg-apk6:wrong-thing"
rc=0
out=$(
    PATH="$APKPATH"
    export PATH
    require_pkgs ghostapk:pkg-apk6 2>&1
) || rc=$?
assert_rc "require_pkgs: apk recheck failure -> exit 64 (fail-closed)" "64" "$rc"
assert_contains "require_pkgs: apk recheck failure names apk add" "$out" "apk add pkg-apk6"
assert_eq "require_pkgs: apk recheck failure never suggests apt-get" \
    "0" "$(printf '%s\n' "$out" | grep -c apt-get)"

# --- e2e-mock: real bin/alpine-fde dispatches into the real require_pkgs -------------
e2e_cmd="$tmp/e2e-cmd"
mkdir -p "$e2e_cmd"
cat >"$e2e_cmd/status.sh" <<'EOF'
cmd_status_main() {
    require_pkgs "$@"
}
EOF
reset_log
reset_apk_log
FAKE_INSTALL_MAKES="pkg-e2e:e2etool"
export FAKE_INSTALL_MAKES
rc=0
out=$(
    PATH="$APKPATH"
    export PATH
    ALPINE_FDE_CMD_DIR="$e2e_cmd"
    ALPINE_FDE_CONF="$tmp/absent.conf"
    export ALPINE_FDE_CMD_DIR ALPINE_FDE_CONF
    "$REPO_ROOT/bin/alpine-fde" status e2etool:pkg-e2e 2>&1
) || rc=$?
assert_rc "e2e: dispatcher -> real require_pkgs -> apk install succeeds" "0" "$rc"
assert_contains "e2e: apk update announced" "$out" "apk update ..."
assert_contains "e2e: apk add announced per package" "$out" "installing missing package: pkg-e2e"
assert_eq "e2e: apk log recorded exactly one add" "1" "$(grep -c '^add pkg-e2e$' "$FAKE_APK_LOG")"
assert_eq "e2e: apt-get never touched" "" "$(cat "$FAKE_APT_LOG")"

# --- explicit exit-code contract: every require_pkgs failure mode is 64 (G-I7) ---
# 64 = fail-closed "missing tools". (The "rc 2 stays reserved for usage" half of
# this contract is pinned where it is OBSERVED — dispatch_and_exitcodes.sh's
# usage-path pins — not by re-asserting a constant against its own literal.)
reset_log
rc=0
msg=$(ALPINE_FDE_NO_INSTALL=1 require_pkgs absent-x:pkg-x 2>&1) || rc=$?
assert_rc "require_pkgs: rc 64 == missing tools (fail-closed environment failure)" "64" "$rc"

finish
