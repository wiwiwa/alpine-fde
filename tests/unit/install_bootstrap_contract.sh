#!/usr/bin/env bash
# tests/unit/install_bootstrap_contract.sh — curl|sh bootstrap `install` script
# (README Quick start: `curl -sSfL .../raw/main/install | sh -s -- install --disk ...`).
# The script is driven END-TO-END with mocked collaborators (E2E-mock rule: real
# dispatcher, stubbed fetchers/payload, asserted argv/stdin/exit codes — never
# source it and poke internal functions):
#   * args forwarding: piped through `sh -s --`, the payload sees the full CLI
#     verbatim and the payload's exit code propagates (both 0 and nonzero)
#   * stdin reconnect: payload stdin is the ALPINE_FDE_BOOTSTRAP_TTY target, not
#     the exhausted pipe that carried the script
#   * unreadable tty -> fail-loud 64 naming the tty, no fetch attempted
#   * non-root -> fail-loud 64 naming root, no fetch attempted (EUID seam:
#     ALPINE_FDE_BOOTSTRAP_EUID, so the contract is testable unprivileged)
#   * cleanup: payload dir (mktemp pattern alpine-fde-bootstrap.*) is removed on
#     success, kept+printed on failure
#   * hygiene: `sh -n` clean, executable, tracked as 100755 once committed

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
INSTALL="$REPO/install"

T=$(mktemp -d /tmp/alpine-fde-boot-contract.XXXXXX)
trap 'rm -rf "$T"' EXIT

# Hermetic sandbox for the script's `mktemp -d` payload dir: the cleanup pins
# glob THIS tmpdir, never the machine's real /tmp.
export TMPDIR="$T/tmp"
mkdir -p "$TMPDIR"

# Scrub every seam so an inherited developer env cannot steer the run.
unset ALPINE_FDE_BOOTSTRAP_TTY ALPINE_FDE_BOOTSTRAP_REF \
    ALPINE_FDE_BOOTSTRAP_TARBALL_URL ALPINE_FDE_BOOTSTRAP_EUID \
    ALPINE_FDE_BOOTSTRAP_KEEP_ON_FAIL || true

TTY="$T/tty"
TARBALL="$T/fake.tar.gz"
FETCH_LOG="$T/fetch.log"
: >"$FETCH_LOG"

# --- stub fetchers: log the attempt, serve file:// URLs by copying ---------------
mkdir -p "$T/bin"
cat >"$T/bin/curl" <<EOF
#!/bin/sh
printf 'curl %s\n' "\$*" >>"$FETCH_LOG"
out=
url=
while [ \$# -gt 0 ]; do
    case \$1 in
        -o) out=\$2; shift 2 ;;
        -*) shift ;;
        *) url=\$1; shift ;;
    esac
done
[ -n "\$out" ] || exit 3
cp "\${url#file://}" "\$out"
EOF
chmod +x "$T/bin/curl"
cat >"$T/bin/wget" <<EOF
#!/bin/sh
printf 'wget %s\n' "\$*" >>"$FETCH_LOG"
out=
url=
while [ \$# -gt 0 ]; do
    case \$1 in
        -O) out=\$2; shift 2 ;;
        -*) shift ;;
        *) url=\$1; shift ;;
    esac
done
[ -n "\$out" ] || exit 3
cp "\${url#file://}" "\$out"
EOF
chmod +x "$T/bin/wget"

# --- fake payload tarball: codeload layout (top-level dir, bin/, lib/) -----------
payload_src="$T/src/alpine-fde-main"
mkdir -p "$payload_src/bin" "$payload_src/lib"
printf 'ALPINE_FDE_PAYLOAD_LIB_LOADED=1\n' >"$payload_src/lib/common.sh"
cat >"$payload_src/bin/alpine-fde" <<'EOF'
#!/bin/sh
. "$(dirname "$0")/../lib/common.sh"
printf 'PAYLOAD-LIB-LOADED=%s\n' "${ALPINE_FDE_PAYLOAD_LIB_LOADED-UNSET}"
printf 'PAYLOAD-ARGS=%s\n' "$*"
printf 'PAYLOAD-STDIN-BEGIN\n'
cat
printf 'PAYLOAD-STDIN-END\n'
exit "${PAYLOAD_RC:-0}"
EOF
chmod +x "$payload_src/bin/alpine-fde"
tar -czf "$TARBALL" -C "$T/src" alpine-fde-main

# curl|sh shape: the script TEXT arrives on stdin, args after `-s --`.
# Combined output is kept in BOOT_OUT, exit code in BOOT_RC.
run_piped() {
    BOOT_RC=0
    BOOT_OUT=$(cat "$INSTALL" | env \
        ALPINE_FDE_BOOTSTRAP_EUID=0 \
        ALPINE_FDE_BOOTSTRAP_TTY="$TTY" \
        ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$TARBALL" \
        PATH="$T/bin:$PATH" \
        PAYLOAD_RC="${PAYLOAD_RC:-0}" \
        sh -s -- "$@" 2>&1
    ) || BOOT_RC=$?
}

# --- 1a. happy path: args forwarded, payload tree intact, rc 0 --------------------
printf 'TTY-SECRET-PASSPHRASE\n' >"$TTY"
run_piped install --disk /dev/nvme0n1
assert_eq "happy path: payload exit code 0 propagates" "0" "$BOOT_RC"
assert_contains "payload receives the forwarded args verbatim" \
    "$BOOT_OUT" "PAYLOAD-ARGS=install --disk /dev/nvme0n1"
assert_contains "payload's lib/ tree is present in the unpacked tarball" \
    "$BOOT_OUT" "PAYLOAD-LIB-LOADED=1"
leftovers=$(find "$TMPDIR" -maxdepth 1 -name 'alpine-fde-bootstrap.*' | wc -l)
assert_eq "success removes the alpine-fde-bootstrap.* payload dir" "0" "$leftovers"

# --- 1b. nonzero payload exit code propagates verbatim, payload dir KEPT ------------
PAYLOAD_RC=7 run_piped install --disk /dev/nvme0n1
assert_eq "payload exit code 7 propagates verbatim" "7" "$BOOT_RC"
kept=$(find "$TMPDIR" -maxdepth 1 -name 'alpine-fde-bootstrap.*' -type d)
kept_bin=$(find "$kept" -type f -path '*/bin/alpine-fde' | head -n 1)
assert_file_exists "failure keeps the unpacked payload (bin/alpine-fde present)" "$kept_bin"
assert_contains "failure prints the kept payload path" "$BOOT_OUT" "$kept"
rm -rf "$kept"

# --- 2. stdin reconnect: the payload read the TTY target, not the pipe -------------
run_piped install --disk /dev/nvme0n1
stdin_block=${BOOT_OUT#*PAYLOAD-STDIN-BEGIN}
stdin_block=${stdin_block%%PAYLOAD-STDIN-END*}
assert_contains "payload stdin carries the tty content" \
    "$stdin_block" "TTY-SECRET-PASSPHRASE"

# --- 3. unreadable tty: fail loud, name the tty, never fetch -----------------------
: >"$FETCH_LOG"
BOOT_RC=0
BOOT_OUT=$(cat "$INSTALL" | env \
    ALPINE_FDE_BOOTSTRAP_EUID=0 \
    ALPINE_FDE_BOOTSTRAP_TTY="$T/does-not-exist" \
    ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$TARBALL" \
    PATH="$T/bin:$PATH" \
    sh -s -- install --disk /dev/nvme0n1 2>&1
) || BOOT_RC=$?
assert_eq "missing tty -> fail-closed 64" "64" "$BOOT_RC"
assert_contains "missing tty diagnostic names the tty" "$BOOT_OUT" "tty"
assert_not_contains "missing tty: payload never runs" "$BOOT_OUT" "PAYLOAD-ARGS"
assert_eq "missing tty: nothing fetched" "" "$(cat "$FETCH_LOG")"

# --- 4. non-root refusal: fail loud before any fetch -------------------------------
: >"$FETCH_LOG"
BOOT_RC=0
BOOT_OUT=$(cat "$INSTALL" | env \
    ALPINE_FDE_BOOTSTRAP_EUID=1000 \
    ALPINE_FDE_BOOTSTRAP_TTY="$TTY" \
    ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$TARBALL" \
    PATH="$T/bin:$PATH" \
    sh -s -- install --disk /dev/nvme0n1 2>&1
) || BOOT_RC=$?
assert_eq "non-root -> fail-closed 64" "64" "$BOOT_RC"
assert_contains "non-root diagnostic names root/uid" "$BOOT_OUT" "root"
assert_not_contains "non-root: payload never runs" "$BOOT_OUT" "PAYLOAD-ARGS"
assert_eq "non-root: nothing fetched" "" "$(cat "$FETCH_LOG")"

# --- 5. script hygiene pins ---------------------------------------------------------
rc=0; sh -n "$INSTALL" 2>"$T/shn.err" || rc=$?
assert_eq "sh -n install parses clean" "0" "$rc"
rc=0; bash -n "$INSTALL" 2>>"$T/shn.err" || rc=$?
assert_eq "bash -n install parses clean" "0" "$rc"
assert_eq "install is executable on disk" "yes" \
    "$([ -x "$INSTALL" ] && echo yes || echo no)"
if git -C "$REPO" ls-files --error-unmatch install >/dev/null 2>&1; then
    assert_eq "install tracked in git as 100755" "100755" \
        "$(git -C "$REPO" ls-files -s install | awk '{print $1}')"
else
    assert_eq "install exists (tracked-mode pin applies once committed)" "yes" \
        "$([ -f "$INSTALL" ] && echo yes || echo no)"
fi

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
