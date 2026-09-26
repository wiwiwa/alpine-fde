#!/usr/bin/env bash
# tests/unit/tpm_tcti_resolution.sh — real-server blocker #18: with
# ALPINE_FDE_TCTI unset, tpm() used to hand tpm2 an EMPTY TPM2TOOLS_TCTI and
# let tctildr do DEFAULT DISCOVERY (tabrmd daemon first) — which fails on the
# installer env, so the seal path's first TPM touch died as
#   keys_keyname_verifying: tpm2_loadexternal failed for .../release.pub
# Contract pinned here:
#   (a) unset ALPINE_FDE_TCTI + a probed dev-dir seam (ALPINE_FDE_TPM_DEV_DIR,
#       mirroring ALPINE_FDE_MAPPER_DIR) holding tpmrm0 -> device:<...tpmrm0>
#   (b) tpm0-only dir -> device:<...tpm0>
#   (c) neither node, modprobe unavailable -> loud SPECIFIC rc 64 naming the
#       probes AND the attempted modules (never a bare tool failure downstream)
#   (d) RED control: main's tpm() yields an EMPTY TPM2TOOLS_TCTI when unset
#       (pinned against the resolved value, which must never be empty)
#   (e) explicit ALPINE_FDE_TCTI still wins verbatim (the e2e swtpm seam)
# No tpm2 binary is needed: these pins exercise tpm_tcti_resolve and capture
# TPM2TOOLS_TCTI through a stubbed tpm2.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# a stub modprobe that is ABSENT unless the pin creates it (PATH is scrubbed
# per-case so "modprobe unavailable" is the honest shape)
SCRUB_PATH="$TMP/bin"
mkdir -p "$SCRUB_PATH"

# capture what the wrapper would hand to the real tpm2: a PATH STUB BINARY —
# tpm() invokes `command tpm2`, which deliberately BYPASSES shell functions
cat >"$SCRUB_PATH/tpm2" <<'EOF'
#!/bin/sh
printf '%s\n' "${TPM2TOOLS_TCTI-<UNSET>}"
EOF
chmod +x "$SCRUB_PATH/tpm2"

# capture_tcti [dev-dir] — scrub PATH to the stub dir (no modprobe unless a
# later pin installs one) and print the TCTI the wrapper resolved
capture_tcti() {
    ALPINE_FDE_TPM_DEV_DIR=${1:-} PATH="$SCRUB_PATH" /bin/bash -c '
        . "'"$REPO"'/lib/common.sh"
        tpm getcap properties-fixed
    '
}

# --- (a) unset ALPINE_FDE_TCTI, tpmrm0 present -------------------------------------
mkdir -p "$TMP/deva"
: >"$TMP/deva/tpmrm0"
RES=$(capture_tcti "$TMP/deva")
assert_eq "unset TCTI + tpmrm0 -> device:<dir>/tpmrm0" "device:$TMP/deva/tpmrm0" "$RES"

# --- (b) tpm0-only dir ---------------------------------------------------------------
mkdir -p "$TMP/devb"
: >"$TMP/devb/tpm0"
RES=$(capture_tcti "$TMP/devb")
assert_eq "unset TCTI + tpm0 only -> device:<dir>/tpm0" "device:$TMP/devb/tpm0" "$RES"

# --- (c) neither node, modprobe unavailable -> loud specific rc 64 --------------------
mkdir -p "$TMP/devc"
OUT=$(capture_tcti "$TMP/devc" 2>&1)
RC=$?
assert_rc "no TPM node + no modprobe -> fail-closed 64" 64 "$RC"
assert_contains "refusal names the probed nodes" "$OUT" "probed $TMP/devc/tpmrm0, $TMP/devc/tpm0"
assert_contains "refusal names the attempted modules" "$OUT" "tpm_crb/tpm_tis"
assert_contains "refusal names the diagnosis" "$OUT" "the TPM is absent or its driver is not loaded"

# --- (c2) modprobe present but ineffective: retried once, then the same refusal --
mkdir -p "$SCRUB_PATH"
cat >"$SCRUB_PATH/modprobe" <<'EOF'
#!/bin/sh
exit 0 # pretends to load, creates no node
EOF
chmod +x "$SCRUB_PATH/modprobe"
MODPROBE_CALLS="$TMP/modprobe.log"
cat >"$SCRUB_PATH/modprobe" <<EOF
#!/bin/sh
echo "\$*" >>"$MODPROBE_CALLS"
exit 0
EOF
chmod +x "$SCRUB_PATH/modprobe"
OUT=$(capture_tcti "$TMP/devc" 2>&1)
RC=$?
assert_rc "ineffective modprobe -> still fail-closed 64" 64 "$RC"
assert_eq "modprobe attempted exactly tpm_crb + tpm_tis, once" \
    "tpm_crb
tpm_tis" "$(cat "$MODPROBE_CALLS")"

# --- (d) RED control: the resolved value is NEVER empty --------------------------
RES=$(ALPINE_FDE_TPM_DEV_DIR="$TMP/deva" PATH="$SCRUB_PATH" \
    /bin/bash -c '
        . "'"$REPO"'/lib/common.sh"
        tpm getcap properties-fixed
    ')
[ -n "$RES" ] &&
    _pass "RED control: unset ALPINE_FDE_TCTI no longer yields an EMPTY TPM2TOOLS_TCTI (blocker #18 fixed)" ||
    _fail "RED control FAILED: TPM2TOOLS_TCTI is empty on the unset path (tctildr default discovery again)"

# --- (e) explicit ALPINE_FDE_TCTI wins verbatim ------------------------------------
RES=$(ALPINE_FDE_TCTI='device:/dev/swtpm-fixture' PATH="$SCRUB_PATH" \
    /bin/bash -c '
        . "'"$REPO"'/lib/common.sh"
        tpm getcap properties-fixed
    ')
assert_eq "explicit ALPINE_FDE_TCTI wins verbatim (e2e seam preserved)" \
    "device:/dev/swtpm-fixture" "$RES"

finish
