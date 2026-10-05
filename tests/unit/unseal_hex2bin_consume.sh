#!/usr/bin/env bash
# tests/unit/unseal_hex2bin_consume.sh — the escrow-consume pol.bin marshal
# regression (s22 leg-3, 2026-10-05): _fdh_hex2bin reads ONLY its argument —
# it never consumes stdin. The consume's write site used the stdin-pipe form
# (printf '%s' "$_fec_pol" | _fdh_hex2bin >pol.bin), so $1 was empty, awk
# transformed zero bytes, and pol.bin was created EMPTY with exit 0 — the ||
# "cannot marshal" branch never fired. The self-seal then sealed under an
# empty policy and the trial unseal refused 0x99d ("a policy check failed")
# despite startauthsession/policypcr/load all passing.
# Pins:
#   (a) behavioral: the ARG form round-trips known hex → exact bytes, and a
#       64-hex-char policy digest → exactly 32 bytes;
#   (b) behavioral: the pipe form yields 0 bytes with rc=0 — the silent-empty
#       trap that made this bug invisible (documented so the pin's reason
#       stays observable);
#   (c) structural: the hook's consume write site is the ARG form
#       (`_fdh_hex2bin "$_fec_pol" >"$_fec_w/pol.bin"`), never a pipe form;
#   (d) structural: no `| _fdh_hex2bin` stdin pipe remains anywhere in the
#       hook;
#   (e) structural: the loud empty-file guard (the 32-byte check) sits behind
#       the write — a silent-empty marshal can never ride into a seal;
#   (f) closure discipline (the blkid lesson): the consume body uses NO wc —
#       wc is NOT in the initrd closure — and counts bytes via od|tr|awk;
#   (g) wedge discipline (the s22f1 18-min hang): every tpm2 verb in the
#       consume body runs under `busybox timeout` (bare timeout is NOT in the
#       closure either), and the step traces (srk created / pol.bin marshaled /
#       trial step lines) are present so a future wedge names its own step.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

HOOK=$REPO/hooks/mkinitfs/alpine-fde-unseal.sh
[ -f "$HOOK" ] || { echo "FAIL: hook missing: $HOOK" >&2; exit 1; }

# (a) behavioral — extract the function and round-trip it
eval "$(sed -n '/^_fdh_hex2bin() {/,/^}/p' "$HOOK")"
[ "$(type _fdh_hex2bin >/dev/null 2>&1; echo $?)" = "0" ] || {
    echo "FAIL: could not extract _fdh_hex2bin from $HOOK" >&2
    exit 1
}

TD=$(mktemp -d)
trap 'rm -rf "$TD"' EXIT

# known bytes, incl. >0x7f values (the LC_ALL=C %c encoding hazard)
_fdh_hex2bin "00ff10417f80" >"$TD/a.bin"
assert_eq "arg form: known hex -> exact bytes" "00 ff 10 41 7f 80" \
    "$(od -An -tx1 "$TD/a.bin" | tr -s ' \n' ' ' | sed 's/^ //;s/ $//')"

# the policy-digest shape: 64 hex chars -> exactly 32 bytes
_fdh_hex2bin "e70aadd55b1e0f7a3f2c9d8b6a5e4c3d2b1a0918273645546372819a0bccdef0" >"$TD/pol.bin"
assert_eq "arg form: 64 hex chars -> 32-byte pol.bin" "32" "$(wc -c <"$TD/pol.bin")"

# (b) behavioral — the pipe form is the documented silent-empty trap
printf '%s' "e70aadd5" | _fdh_hex2bin >"$TD/pipe.bin" 2>/dev/null
assert_eq "pipe form: 0 bytes (the trap, documented)" "0" "$(wc -c <"$TD/pipe.bin")"

# (c) structural — the consume write site is the ARG form
HOOK_TXT=$(cat "$HOOK")
assert_contains "consume write site is the arg form" "$HOOK_TXT" \
    '_fdh_hex2bin "$_fec_pol" >"$_fec_w/pol.bin"'

# (d) structural — no stdin-pipe form remains anywhere in the hook
assert_not_contains "no stdin-pipe call of _fdh_hex2bin in the hook" "$HOOK_TXT" \
    '| _fdh_hex2bin'

# (e) structural — the loud 32-byte guard behind the write
assert_contains "the 32-byte empty-marshal guard is present" "$HOOK_TXT" \
    'the marshaled policy digest is not 32 bytes'

# (f) closure discipline — the guard counts via od|tr|awk, never wc
CONSUME_BODY=$(sed -n '/^_fdh_escrow_consume() {/,/^}/p' "$HOOK")
assert_contains "the guard counts bytes via od+awk (closure-safe)" "$CONSUME_BODY" \
    "od -An -tx1 \"\$_fec_w/pol.bin\" 2>/dev/null | tr -d ' \\n' | awk '{print length(\$0)}'"
assert_not_contains "the consume body never uses wc (not in the closure)" \
    "$(printf '%s\n' "$CONSUME_BODY" | grep -v '^[[:space:]]*#')" 'wc '

# (g) wedge discipline — every tpm2 verb in the consume body is busybox-timeout-
# wrapped; a bare tpm2 invocation at command position is a boot-killer
# (lines with `command -v tpm2_` are existence probes, not invocations)
UNWRAPPED=$(printf '%s\n' "$CONSUME_BODY" | sed 's/#.*//' | grep -v 'command -v' | grep -E '(^|[|;& (])tpm2_[a-z]+' | grep -v 'busybox timeout' || true)
assert_eq "no unwrapped tpm2 verb in the consume body" "" "$UNWRAPPED"
assert_contains "createprimary runs under busybox timeout" "$CONSUME_BODY" \
    'busybox timeout 90 tpm2_createprimary'
assert_contains "the self-seal runs under busybox timeout" "$CONSUME_BODY" \
    'busybox timeout 60 tpm2_create '
for verb in startauthsession policypcr load unseal; do
    assert_contains "trial $verb runs under busybox timeout" "$CONSUME_BODY" \
        "busybox timeout 30 tpm2_$verb"
done

# (g2) the step traces — a future wedge names its own step
for trace in 'srk createprimary starting' 'the SRK created' \
    'pol.bin marshaled 32 bytes' 'self-seal starting for' \
    'trial $(_fec_elapsed)s' '_fec_elapsed() { echo'; do
    assert_contains "trace present: $trace" "$CONSUME_BODY" "$trace"
done

finish
