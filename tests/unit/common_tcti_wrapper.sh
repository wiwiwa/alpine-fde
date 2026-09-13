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

# --- DEBIAN_FDE_TCTI unset/empty: TPM2TOOLS_TCTI must be set-but-empty (tctildr default) ---
out=$(DEBIAN_FDE_TCTI='' tpm getcap -l)
assert_eq "wrapper returns the tool's stdout" "canned-tpm2-output" "$out"
line=$(tail -n 1 "$FAKE_TPM2_LOG")
assert_eq "empty DEBIAN_FDE_TCTI -> set-but-empty TPM2TOOLS_TCTI, argv forwarded" \
    "tcti=[] args=[getcap][-l]" "$line"

# --- DEBIAN_FDE_TCTI propagated ---
out=$(DEBIAN_FDE_TCTI=swtpm tpm pcrread sha256 0)
assert_eq "wrapper returns the tool's stdout (tcti set)" "canned-tpm2-output" "$out"
line=$(tail -n 1 "$FAKE_TPM2_LOG")
assert_eq "DEBIAN_FDE_TCTI propagated to TPM2TOOLS_TCTI" \
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
