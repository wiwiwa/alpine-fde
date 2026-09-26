#!/bin/sh
# common_tcti_wrapper.sh — unit tests for the lib/common.sh tpm() TCTI wrapper,
# using a fake `tpm2` stub on PATH (no real TPM required).

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

FAKE_TPM2_LOG="$tmp/tpm2.log"
export FAKE_TPM2_LOG

cat >"$tmpbin/tpm2" <<'EOF'
#!/bin/sh
# fake tpm2 stub: record TPM2TOOLS_TCTI and argv into $FAKE_TPM2_LOG,
# emit canned output, propagate FAKE_TPM2_RC as exit status.
printf 'tcti=[%s] args=' "${TPM2TOOLS_TCTI-<UNSET>}" >>"$FAKE_TPM2_LOG"
for a in "$@"; do
    printf '[%s]' "$a" >>"$FAKE_TPM2_LOG"
done
printf '\n' >>"$FAKE_TPM2_LOG"
printf 'canned-tpm2-output\n'
exit "${FAKE_TPM2_RC:-0}"
EOF
chmod +x "$tmpbin/tpm2"

PATH="$tmpbin:$PATH"
export PATH

# --- ALPINE_FDE_TCTI unset/empty: the wrapper RESOLVES the TCTI itself ----------
# (real-server blocker #18: the old set-but-empty value fed tctildr default
# discovery, which fails on the installer env). With a dev-dir seam holding a
# tpmrm0 file the resolved value is device:<dir>/tpmrm0.
DEVDIR="$tmp/dev"
mkdir -p "$DEVDIR"
: >"$DEVDIR/tpmrm0"
export ALPINE_FDE_TPM_DEV_DIR="$DEVDIR" # ambient seam for the later cases
out=$(ALPINE_FDE_TCTI='' ALPINE_FDE_TPM_DEV_DIR="$DEVDIR" tpm getcap -l)
assert_eq "wrapper returns the tool's stdout" "canned-tpm2-output" "$out"
line=$(tail -n 1 "$FAKE_TPM2_LOG")
assert_eq "empty ALPINE_FDE_TCTI -> resolved device TCTI, argv forwarded" \
    "tcti=[device:$DEVDIR/tpmrm0] args=[getcap][-l]" "$line"

# --- ALPINE_FDE_TCTI unset AND no device node: loud specific rc 64 ---------------
out=$(ALPINE_FDE_TCTI='' ALPINE_FDE_TPM_DEV_DIR="$tmp/no-dev" tpm getcap -l 2>&1)
rc=$?
assert_rc "blocker #18: unset TCTI + no TPM node -> fail-closed 64" "64" "$rc"
assert_contains "blocker #18: the refusal names the probed nodes and modules" "$out" \
    "probed $tmp/no-dev/tpmrm0, $tmp/no-dev/tpm0; modules tpm_crb/tpm_tis load attempted"

# --- ALPINE_FDE_TCTI propagated ---
out=$(ALPINE_FDE_TCTI=swtpm tpm pcrread sha256 0)
assert_eq "wrapper returns the tool's stdout (tcti set)" "canned-tpm2-output" "$out"
line=$(tail -n 1 "$FAKE_TPM2_LOG")
assert_eq "ALPINE_FDE_TCTI propagated to TPM2TOOLS_TCTI" \
    "tcti=[swtpm] args=[pcrread][sha256][0]" "$line"

# --- argument quoting preserved ---
tpm getcap --option 'value with spaces' >/dev/null
line=$(tail -n 1 "$FAKE_TPM2_LOG")
assert_contains "arguments with spaces survive intact" "$line" "[value with spaces]"

# --- exit status propagation ---
FAKE_TPM2_RC=7
export FAKE_TPM2_RC
rc=0
out=$(tpm status 2>/dev/null) || rc=$?
assert_rc "wrapper propagates the tpm2 exit status" "7" "$rc"
unset FAKE_TPM2_RC

# --- wrapper must bypass shell functions named tpm2 (uses `command`) ---
# shellcheck disable=SC2317  # invoked via the tpm() wrapper, not directly
out=$(tpm2() { echo HIJACKED; }; tpm status)
assert_eq "wrapper bypasses a shell function named tpm2" "canned-tpm2-output" "$out"

finish
