#!/usr/bin/env bash
# tests/unit/baseline_finalize_guard.sh — G-R1 (§8.1, §9.1): baseline
# finalization (`audit --init` / `audit --accept`, and `provision stage2` via
# the shared helper) refuses fail-closed (64) unless Secure Boot is ON with
# SetupMode=0. An SB-off finalized baseline would become the trust root that
# `audit` reports "clean" against. No override: an SB-off machine must fix
# Secure Boot first (enroll-tpm refuses likewise).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../lib/swtpm-fixture.sh
source "$HERE/../lib/swtpm-fixture.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

T=$(mktemp -d /tmp/alpine-fde-blfinal.XXXXXX)
STATE=$T/swtpm
EFIVARS=$T/efivars
EVENTLOG=$T/eventlog
export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_EFIVARS_DIR=$EFIVARS
export ALPINE_FDE_EVENTLOG=$EVENTLOG
export ALPINE_FDE_NO_INSTALL=1

cleanup() {
    swtpm_cleanup_all
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$EFIVARS" "$(sp_etc_dir)"
head -c 1024 /dev/urandom >"$EVENTLOG"

mkvar() { # NAME BYTE — attrs u32le 0x7 + payload byte (efivars fixture)
    printf '\007\000\000\000'"$(printf '\%03o' "$2")" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
mkcertvar() { # NAME CONTENT — payload after the 4-byte attrs header
    printf '\007\000\000\000%s' "$2" >"$EFIVARS/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
}
sb_state() { # SECUREBOOT SETUPMODE — set the full PK/KEK/db/dbx tree too
    mkvar SecureBoot "$1"
    mkvar SetupMode "$2"
    mkcertvar PK pk-cert-v1
    mkcertvar KEK kek-cert-v1
    mkcertvar db db-cert-v1
    mkcertvar dbx dbx-cert-v1
}

run_audit() { # args...
    AUD_OUT=$("$REPO/bin/alpine-fde" audit "$@" 2>&1)
    AUD_RC=$?
}

BL=$(sp_baseline_file)
pending_baseline() { BL_PCR0='pending' BL_PCR7='pending' baseline_write "$BL"; }

assert_rc "swtpm fixture starts" 0 swtpm_start "$STATE"
export ALPINE_FDE_TCTI=$SWTPM_TCTI

# --- 1. SB off -> --init refuses 64, baseline stays pending, no last-audit ------
sb_state 0 0
pending_baseline
run_audit --init
assert_eq "SB off: audit --init -> 64" "64" "$AUD_RC"
assert_rc "SB off: baseline still pending" 0 baseline_is_pending "$BL"
if [ -e "$(sp_last_audit_file)" ]; then
    assert_eq "SB off: no last-audit ok written" "absent" "present"
else
    assert_eq "SB off: no last-audit ok written" "absent" "absent"
fi
assert_contains "refusal names Secure Boot" "$AUD_OUT" "Secure Boot"

# --- 2. SetupMode=1 -> refuse 64 (keys not in the final state) -------------------
sb_state 1 1
pending_baseline
run_audit --init
assert_eq "SetupMode=1: audit --init -> 64" "64" "$AUD_RC"
assert_rc "SetupMode=1: baseline still pending" 0 baseline_is_pending "$BL"

# --- 3. efivars absent entirely -> refuse 64 ---------------------------------------
mv "$EFIVARS" "$EFIVARS.bak"
pending_baseline
run_audit --init
assert_eq "efivars absent: audit --init -> 64" "64" "$AUD_RC"
assert_rc "efivars absent: baseline still pending" 0 baseline_is_pending "$BL"
mv "$EFIVARS.bak" "$EFIVARS"

# --- 4. SB on + SetupMode=0 -> finalizes --------------------------------------------
sb_state 1 0
pending_baseline
run_audit --init
assert_eq "SB on: audit --init rc 0" "0" "$AUD_RC"
assert_rc "SB on: baseline final" 0 baseline_is_final "$BL"
assert_eq "baseline records secure_boot=1" "1" "$(baseline_get_in "$BL" sb_state secure_boot)"
assert_eq "baseline records setup_mode=0" "0" "$(baseline_get_in "$BL" sb_state setup_mode)"
assert_eq "expected_pcr7 == live swtpm PCR7" "$(swtpm_pcrread "$STATE" 7)" "$(baseline_get "$BL" expected_pcr7)"

# --- 5. shared helper seam: direct finalize refuses too (provision stage2) ----------
sb_state 0 0
pending_baseline
BL_RC=0
( baseline_finalize_from_live ) >/dev/null 2>&1 || BL_RC=$?
assert_eq "direct baseline_finalize_from_live: SB off -> 64" "64" "$BL_RC"
assert_rc "direct: baseline still pending" 0 baseline_is_pending "$BL"

# --- 6. --accept --yes inherits the guard -------------------------------------------
sb_state 0 0
pending_baseline
LA_BEFORE=$(md5sum "$(sp_last_audit_file)" 2>/dev/null | cut -d' ' -f1)
run_audit --accept --yes
assert_eq "SB off: --accept --yes -> 64" "64" "$AUD_RC"
assert_rc "SB off: baseline still pending after --accept" 0 baseline_is_pending "$BL"
assert_eq "SB off: --accept leaves last-audit untouched" \
    "$LA_BEFORE" "$(md5sum "$(sp_last_audit_file)" 2>/dev/null | cut -d' ' -f1)"

# --- 7. SetupMode=1 x --accept --yes -> refuse 64 (the SB-on cell of the matrix) ----
# §9.1: keys are not in the final state until SetupMode=0; re-baselining (--accept)
# inherits the exact same guard as --init (SB-off-for-both-flags is already
# covered above; this closes the SetupMode=1-via---accept cell).
sb_state 1 1
pending_baseline
LA_BEFORE=$(md5sum "$(sp_last_audit_file)" 2>/dev/null | cut -d' ' -f1)
run_audit --accept --yes
assert_eq "SetupMode=1: --accept --yes -> 64" "64" "$AUD_RC"
assert_rc "SetupMode=1: baseline still pending after --accept" 0 baseline_is_pending "$BL"
assert_contains "SetupMode=1: refusal names the SB guard (not a drift/prompt error)" \
    "$AUD_OUT" "SetupMode=0"
assert_eq "SetupMode=1: --accept leaves last-audit untouched" \
    "$LA_BEFORE" "$(md5sum "$(sp_last_audit_file)" 2>/dev/null | cut -d' ' -f1)"

# --- 8. M-3: mid-capture failure leaves the baseline untouched (atomic finalize) -----
# PCR 1 is made unreadable AFTER PCR 0 would have been captured: with in-place
# mutation the baseline ends up torn (real pcr0 + pending pcr7); the finalized
# document must be built next to the target and moved into place atomically.
FAKEBIN=$T/bin
mkdir -p "$FAKEBIN"
REAL_TPM2=$(command -v tpm2)
cat >"$FAKEBIN/tpm2" <<EOF
#!/bin/sh
if [ "\$1" = "pcrread" ] && [ "\$2" = "sha256:1" ]; then
    exit 1
fi
exec "$REAL_TPM2" "\$@"
EOF
chmod +x "$FAKEBIN/tpm2"
OLD_PATH=$PATH
export PATH="$FAKEBIN:$PATH"
sb_state 1 0
pending_baseline
run_audit --init
assert_eq "PCR 1 unreadable mid-finalize -> 64" "64" "$AUD_RC"
# CR-01: exec-without-command applies BOTH redirects persistently, so a stray
# `2>/dev/null` on the lock release silenced stderr BEFORE die printed — every
# fail-closed finalize path became invisible. The diagnostic must be loud.
assert_contains "CR-01: failed finalize prints the real diagnostic" "$AUD_OUT" \
    "cannot read PCR 1"
assert_not_contains "CR-01: stderr not swallowed by the lock release" "$AUD_OUT" \
    "alpine-fde: error: alpine-fde: error:"
assert_rc "baseline still pending (no torn finalize, M-3)" 0 baseline_is_pending "$BL"
assert_eq "pcr0 not partially written into the live baseline" "pending" "$(baseline_get "$BL" pcr0)"
assert_eq "no .tmp litter next to the baseline" "" \
    "$(find "$(sp_etc_dir)" -maxdepth 1 -name '*.tmp' -print -quit)"
assert_eq "no abandoned finalize temp documents" "" \
    "$(find "$(sp_etc_dir)" -maxdepth 1 -name '.baseline-finalize.*' -print -quit)"
export PATH="$OLD_PATH"

# --- 8b. IN-01: a SETTER dying inside finalize (I/O fault) must not leak the
# staged document nor blame "key not found". The awk fault fires only when awk
# is invoked ON the staged `.baseline-finalize.*` document (the setters are the
# only finalize step that does), so PCR reads / validation are unaffected.
cat >"$FAKEBIN/awk" <<EOF
#!/bin/sh
for _a in "\$@"; do
    case \$_a in
        $T/root/etc/alpine-fde/.baseline-finalize.*)
            echo 'awk fault injection: staged document unwritable' >&2
            exit 2
            ;;
    esac
done
exec "$(command -v awk)" "\$@"
EOF
chmod +x "$FAKEBIN/awk"
export PATH="$FAKEBIN:$PATH"
sb_state 1 0
pending_baseline
run_audit --init
assert_eq "setter I/O fault mid-finalize -> 64" "64" "$AUD_RC"
assert_contains "IN-01: reports the real setter-fault reason" "$AUD_OUT" \
    "awk fault injection"
assert_not_contains "IN-01: no misleading key-not-found blame" "$AUD_OUT" \
    "key not found"
assert_rc "baseline still pending after setter fault" 0 baseline_is_pending "$BL"
assert_eq "IN-01: no abandoned finalize temp documents" "" \
    "$(find "$(sp_etc_dir)" -maxdepth 1 -name '.baseline-finalize.*' -print -quit)"
assert_eq "IN-01: no .tmp litter next to the baseline" "" \
    "$(find "$(sp_etc_dir)" -maxdepth 1 -name '*.tmp' -print -quit)"
rm "$FAKEBIN/awk"
export PATH="$OLD_PATH"

# --- 9. L-6: concurrent finalizations serialize on <etc>/.baseline.lock -------------
sb_state 1 0
pending_baseline
LOCK=$(sp_etc_dir)/.baseline.lock
flock "$LOCK" -c 'sleep 5' &
HOLD=$!
sleep 0.3
timeout 2 "$REPO/bin/alpine-fde" audit --init >/dev/null 2>&1
TMO_RC=$?
assert_eq "finalize blocked while another ceremony holds the lock (timeout 124)" "124" "$TMO_RC"
assert_rc "baseline still pending after the blocked attempt" 0 baseline_is_pending "$BL"
wait "$HOLD"
run_audit --init
assert_eq "finalize succeeds once the lock is free" "0" "$AUD_RC"

swtpm_stop "$STATE" || true
exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
