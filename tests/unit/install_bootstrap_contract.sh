#!/usr/bin/env bash
# tests/unit/install_bootstrap_contract.sh — wget|sh bootstrap `alpine-fde` script
# (README Quick start: `wget -qO- .../raw/main/alpine-fde | sh -s -- install --disk ...`).
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
#   * local-tree detection: invoked as a FILE from a checkout (bin/alpine-fde +
#     lib/ beside the script, possibly via a symlink to it), the LOCAL product
#     runs with the same tty-seam stdin and args/exit-code forwarding, and NO
#     fetch is attempted — network is only for the piped wget|sh shape, which
#     can never have a $0 file (a stdin-piped script has no script file, so the
#     detection no-ops there). The local path runs unprivileged on purpose: the
#     root precondition is NOT duplicated (`./alpine-fde doctor` from a clone
#     must work as non-root); the tty reconnect IS kept (ceremony prompts)
#   * hygiene: `sh -n` clean, executable, tracked as 100755 once committed

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
INSTALL="$REPO/alpine-fde"

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

# --- 4b. fetch preference: wget first (Alpine live ISO ships busybox wget, not curl)
: >"$FETCH_LOG"
run_piped install --disk /dev/nvme0n1
assert_eq "wget-first happy path exits 0" "0" "$BOOT_RC"
assert_contains "fetcher log records the wget attempt" "$(cat "$FETCH_LOG")" "wget"
assert_not_contains "curl untouched when wget is available" "$(cat "$FETCH_LOG")" "curl"

# --- 6. local-tree detection: ./alpine-fde from a checkout runs the LOCAL product ---
# Sandbox mirrors a checkout: this dispatcher copied beside a STUB product
# (bin/alpine-fde + lib/). Invoked as a FILE, never piped — $0 is real.
local_sandbox=$T/local
mkdir -p "$local_sandbox/bin" "$local_sandbox/lib"
cp "$INSTALL" "$local_sandbox/alpine-fde"
cat >"$local_sandbox/bin/alpine-fde" <<'EOF'
#!/bin/sh
printf 'LOCAL-STUB-RAN=1\n'
printf 'LOCAL-STUB-ARGS=%s\n' "$*"
printf 'LOCAL-STUB-STDIN-BEGIN\n'
cat
printf 'LOCAL-STUB-STDIN-END\n'
exit "${LOCAL_RC:-0}"
EOF
chmod +x "$local_sandbox/bin/alpine-fde"

run_local() { # SCRIPT ARGS... — invoke a dispatcher copy as a plain file
    BOOT_RC=0
    BOOT_OUT=$(env \
        ALPINE_FDE_BOOTSTRAP_EUID=1000 \
        ALPINE_FDE_BOOTSTRAP_TTY="$TTY" \
        ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$T/no-such-tarball.tar.gz" \
        PATH="$T/bin:$PATH" \
        LOCAL_RC="${LOCAL_RC:-0}" \
        "$@" 2>&1
    ) || BOOT_RC=$?
}

# 6a. local tree wins: stub runs (unprivileged — no root refusal duplicated),
#     args forwarded verbatim, and NO fetch is attempted (fetch log stays empty
#     even though the tarball URL points at a file that does not exist).
: >"$FETCH_LOG"
printf 'TTY-SECRET-PASSPHRASE\n' >"$TTY"
run_local "$local_sandbox/alpine-fde" doctor --verbose
assert_eq "local tree: stub product exit code 0 propagates" "0" "$BOOT_RC"
assert_contains "local tree: the LOCAL stub runs, not a fetched payload" \
    "$BOOT_OUT" "LOCAL-STUB-RAN=1"
assert_contains "local tree: args forwarded verbatim to the local product" \
    "$BOOT_OUT" "LOCAL-STUB-ARGS=doctor --verbose"
assert_not_contains "local tree: no fetch/payload path taken" \
    "$BOOT_OUT" "PAYLOAD-ARGS"
assert_eq "local tree: nothing fetched (no network from a checkout)" \
    "" "$(cat "$FETCH_LOG")"

# 6b. stdin seam on the local path: same reconnect contract as the fetch path.
stdin_block=${BOOT_OUT#*LOCAL-STUB-STDIN-BEGIN}
stdin_block=${stdin_block%%LOCAL-STUB-STDIN-END*}
assert_contains "local tree: product stdin is the tty-seam target" \
    "$stdin_block" "TTY-SECRET-PASSPHRASE"

# 6c. nonzero exit of the local product propagates verbatim.
: >"$FETCH_LOG"
LOCAL_RC=7 run_local "$local_sandbox/alpine-fde" install --disk /dev/nvme0n1
assert_eq "local tree: stub exit code 7 propagates verbatim" "7" "$BOOT_RC"
assert_eq "local tree: failure still fetched nothing" "" "$(cat "$FETCH_LOG")"

# 6d. the script may be reached through a symlink (PATH install); $0 must be
#     resolved to the copy that HAS the product tree beside it.
ln -sf "$local_sandbox/alpine-fde" "$T/fde-link"
: >"$FETCH_LOG"
run_local "$T/fde-link" doctor
assert_eq "symlinked dispatcher: local product runs through the link" "0" "$BOOT_RC"
assert_contains "symlinked dispatcher: LOCAL stub reached" "$BOOT_OUT" "LOCAL-STUB-RAN=1"
assert_eq "symlinked dispatcher: nothing fetched" "" "$(cat "$FETCH_LOG")"

# 6e. invoked as a FILE but with NO local tree beside it -> the download path
#     still runs (local detection is additive; the fetch shape is unchanged).
nolocal=$T/nolocal
mkdir -p "$nolocal"
cp "$INSTALL" "$nolocal/alpine-fde"
: >"$FETCH_LOG"
printf 'TTY-SECRET-PASSPHRASE\n' >"$TTY"
BOOT_RC=0
BOOT_OUT=$(env \
    ALPINE_FDE_BOOTSTRAP_EUID=0 \
    ALPINE_FDE_BOOTSTRAP_TTY="$TTY" \
    ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$TARBALL" \
    PATH="$T/bin:$PATH" \
    PAYLOAD_RC=0 \
    "$nolocal/alpine-fde" install --disk /dev/nvme0n1 2>&1
) || BOOT_RC=$?
assert_eq "no local tree: download path still boots the payload" "0" "$BOOT_RC"
assert_contains "no local tree: fetched payload runs with forwarded args" \
    "$BOOT_OUT" "PAYLOAD-ARGS=install --disk /dev/nvme0n1"
assert_not_contains "no local tree: local stub never runs" "$BOOT_OUT" "LOCAL-STUB-RAN"
assert_contains "no local tree: fetch was attempted" "$(cat "$FETCH_LOG")" "wget"

# 6f. the piped `wget|sh` shape can NEVER take the local branch, even with the
#     shell's cwd inside a checkout that has a product tree: a stdin-piped
#     script has no $0 file ($0 is 'sh', naming no real file), so detection
#     must no-op and the fetch path must run.
: >"$FETCH_LOG"
printf 'TTY-SECRET-PASSPHRASE\n' >"$TTY"
BOOT_RC=0
BOOT_OUT=$(cd "$local_sandbox" && cat "$INSTALL" | env \
    ALPINE_FDE_BOOTSTRAP_EUID=0 \
    ALPINE_FDE_BOOTSTRAP_TTY="$TTY" \
    ALPINE_FDE_BOOTSTRAP_TARBALL_URL="file://$TARBALL" \
    PATH="$T/bin:$PATH" \
    PAYLOAD_RC=0 \
    sh -s -- install --disk /dev/nvme0n1 2>&1
) || BOOT_RC=$?
assert_eq "piped shape inside a checkout dir: fetch path still wins" "0" "$BOOT_RC"
assert_contains "piped shape: fetched payload ran (local branch no-ops)" \
    "$BOOT_OUT" "PAYLOAD-ARGS=install --disk /dev/nvme0n1"
assert_not_contains "piped shape: local stub never runs" "$BOOT_OUT" "LOCAL-STUB-RAN"
assert_contains "piped shape: fetch was attempted" "$(cat "$FETCH_LOG")" "wget"

# --- 5. script hygiene pins ---------------------------------------------------------
rc=0; sh -n "$INSTALL" 2>"$T/shn.err" || rc=$?
assert_eq "sh -n install parses clean" "0" "$rc"
rc=0; bash -n "$INSTALL" 2>>"$T/shn.err" || rc=$?
assert_eq "bash -n install parses clean" "0" "$rc"
assert_eq "bootstrap script is executable on disk" "yes" \
    "$([ -x "$INSTALL" ] && echo yes || echo no)"
if git -C "$REPO" ls-files --error-unmatch alpine-fde >/dev/null 2>&1; then
    assert_eq "bootstrap script tracked in git as 100755" "100755" \
        "$(git -C "$REPO" ls-files -s alpine-fde | awk '{print $1}')"
else
    assert_eq "bootstrap script exists (tracked-mode pin applies once committed)" "yes" \
        "$([ -f "$INSTALL" ] && echo yes || echo no)"
fi

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
