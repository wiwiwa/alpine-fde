#!/usr/bin/env bash
# tests/unit/unseal_warn_preamble.sh — warn-before-prompt (§8.2 step 5; user
# decision queue item 8): the mkinitfs unseal hook prints a REASON preamble,
# mapped from the refusal class, BEFORE the bounded keyslot-0 recovery
# passphrase fallback, plus a closing remediation line naming the NEW CLI
# verbs (audit/reseal). This suite pins the CONTRACT CHEAPLY (grep-only; the
# behavioral pins — each class's preamble observed on real hook console output
# before the prompt — live in tests/integration/hooks_mkinitfs_unseal.sh):
#   (a) wording identity: each canonical sentence is byte-identical across the
#       hook, docs/UserGuide.md §5 and docs/Architecture.md §8.2 step 5 (the
#       operator reads the docs and meets the same sentence on the console);
#   (b) class → branch mapping: each _fdh_warn call sits in the hook's ACTUAL
#       refusal branch (structurally: after the branch's refusal sentinel
#       line), never on a branch that cannot detect that class;
#   (c) the (attempt N of 3) counter prefixes the pinned prompt shape, so the
#       unseal_prompt_re sentinel stays valid for the scenario greps;
#   (d) the honest caveat (anti-footgun, NOT anti-tamper) is present in BOTH
#       docs files with identical wording;
#   (e) the unseal_warn_* sentinels carry the exact sentences.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"
# shellcheck source=../lib/sentinels.sh
source "$HERE/../lib/sentinels.sh"   # sentinel_of (MD-02: single promoted table)

HOOK=$REPO/hooks/mkinitfs/alpine-fde-unseal.sh
UGUIDE=$REPO/docs/UserGuide.md
ARCH=$REPO/docs/Architecture.md
for f in "$HOOK" "$UGUIDE" "$ARCH" "$REPO/tests/sentinels-260.2.txt"; do
    [ -f "$f" ] || { echo "FAIL: required file missing: $f" >&2; exit 1; }
done

HOOK_TXT=$(cat "$HOOK")
UG_TXT=$(cat "$UGUIDE")
ARCH_TXT=$(cat "$ARCH")

# --- (a) wording identity: hook == UserGuide == Architecture ----------------------
for name in unseal_warn_seal_refused unseal_warn_sig_refused \
    unseal_warn_token_missing unseal_warn_reclose; do
    s=$(sentinel_of "$name")
    assert_contains "warn preamble [$name]: sentinel value present in the HOOK" "$HOOK_TXT" "$s"
    assert_contains "warn preamble [$name]: SAME sentence in docs/UserGuide.md" "$UG_TXT" "$s"
    assert_contains "warn preamble [$name]: SAME sentence in docs/Architecture.md" "$ARCH_TXT" "$s"
done

# the closing line names the NEW verbs (audit/reseal — the decided rename) and
# never the old ones
CLOSING=$(sentinel_of unseal_warn_reclose)
assert_contains "closing line names the audit verb" "$CLOSING" "audit"
assert_contains "closing line names the reseal verb" "$CLOSING" "reseal"
assert_not_contains() {
    if [ -z "$3" ]; then
        _fail "$1 (empty needle — vacuous pass refused)"
    elif [[ "$2" != *"$3"* ]]; then
        _pass "$1"
    else
        _fail "$1 (haystack must not contain [$3])"
    fi
}
assert_not_contains "closing line carries NO retired verb (enroll-tpm)" "$CLOSING" "enroll-tpm"
assert_not_contains "closing line carries NO retired verb (rotate)" "$CLOSING" "rotate"

# --- (b) class → branch mapping (structural, line-ordered in the hook) ------------
lineno() { # <needle> — first line number of <needle> in the hook (0 = absent)
    grep -nF "$1" "$HOOK" | head -n 1 | cut -d: -f1
}
warn_line() { # <warn-var> — the _fdh_warn call site for a class variable
    grep -nF "_fdh_warn \"\$FDE_WARN_$1\"" "$HOOK" | head -n 1 | cut -d: -f1
}

# sig_refused sits in the I3 gate-refusal branch (BEFORE any TPM session)
SIG_BR=$(lineno "token/signature verification refused")
SIG_WARN=$(warn_line SIG_REFUSED)
assert_eq "sig_refused preamble: branch exists (I3 gate refusal line)" "1" \
    "$([ -n "$SIG_BR" ] && [ "$SIG_BR" -gt 0 ] && echo 1 || echo 0)"
assert_eq "sig_refused preamble: emitted by the I3 gate-refusal branch (after its refusal line)" "1" \
    "$([ -n "$SIG_WARN" ] && [ "$SIG_BR" -gt 0 ] && [ "$SIG_WARN" -gt "$SIG_BR" ] && echo 1 || echo 0)"

# seal_refused sits in the sealed-blob/policy refusal branch (the PCR 7 drift case)
SEAL_BR=$(lineno "the TPM refused the sealed blob under the current PCR state")
SEAL_WARN=$(warn_line SEAL_REFUSED)
assert_eq "seal_refused preamble: branch exists (sealed-blob refusal line)" "1" \
    "$([ -n "$SEAL_BR" ] && [ "$SEAL_BR" -gt 0 ] && echo 1 || echo 0)"
assert_eq "seal_refused preamble: emitted by the sealed-blob refusal branch (after its refusal line)" "1" \
    "$([ -n "$SEAL_WARN" ] && [ "$SEAL_BR" -gt 0 ] && [ "$SEAL_WARN" -gt "$SEAL_BR" ] && echo 1 || echo 0)"

# token_missing sits in BOTH no-token-path branches: no systemd-tpm2 token on
# any member, and TPM absent/refused at the §8.2 step-1 extend
TOK_BR=$(lineno "no systemd-tpm2 token found on any crypttab member")
TOK_WARN_CNT=$(grep -cF '_fdh_warn "$FDE_WARN_TOKEN_MISSING"' "$HOOK")
TPM_BR=$(lineno "TPM absent or refused the PCR 11 extend")
# the emission in EACH branch must sit AFTER that branch's refusal line (the
# TPM-absent branch precedes the token path in the hook, so order matters)
WARN_AFTER() { # <branch-line> — first token_missing emission line AFTER <branch-line>
    grep -nF '_fdh_warn "$FDE_WARN_TOKEN_MISSING"' "$HOOK" | cut -d: -f1 | sort -n |
        awk -v b="$1" '$1 > b { print; exit }'
}
TOK_WARN_AT_TOKBR=$(WARN_AFTER "$TOK_BR")
TOK_WARN_AT_TPMBR=$(WARN_AFTER "$TPM_BR")
assert_eq "token_missing preamble: emitted by BOTH no-token-path branches" "2" "$TOK_WARN_CNT"
assert_eq "token_missing preamble: emission after the no-token-found line" "1" \
    "$([ -n "$TOK_WARN_AT_TOKBR" ] && [ "$TOK_BR" -gt 0 ] && echo 1 || echo 0)"
assert_eq "token_missing preamble: emission after the TPM-absent line" "1" \
    "$([ -n "$TOK_WARN_AT_TPMBR" ] && [ "$TPM_BR" -gt 0 ] && echo 1 || echo 0)"

# every _fdh_warn call prints the closing line (the helper is the only emitter)
assert_eq "exactly one _fdh_warn helper definition" "1" "$(grep -cF '_fdh_warn() {' "$HOOK")"
assert_eq "the closing line is emitted ONLY via FDE_WARN_CLOSING inside the helper" "1" \
    "$(grep -cF '_msg "$FDE_WARN_CLOSING"' "$HOOK")"

# --- (c) (attempt N of 3) counter, prefixed on the pinned prompt shape ------------
assert_contains "prompt line carries the (attempt N of FDE_MAX_ATTEMPTS) counter prefix" "$HOOK_TXT" \
    '(attempt $2 of $FDE_MAX_ATTEMPTS) enter the recovery passphrase for $1 (keyslot 0): '
assert_contains "FDE_MAX_ATTEMPTS is pinned to 3 (§8.2 bounded loop)" "$HOOK_TXT" "FDE_MAX_ATTEMPTS=3"
assert_contains "prompt call site passes the 1-based attempt (tries+1 shape)" "$HOOK_TXT" \
    '_fdh_prompt_pass "$_fdh_target" "$((_fdh_tries + 1))"'
# the counter is a PREFIX: the pre-existing unseal_prompt_re sentinel suffix
# must still match the prompt line (the e2e prompt-synchronization greps count it)
PROMPT_RE=$(sentinel_of unseal_prompt_re)
PROMPT_LINE=$(grep -F 'enter the recovery passphrase for $1' "$HOOK")
if printf '%s\n' "$PROMPT_LINE" | grep -qE "$PROMPT_RE"; then
    _pass "the countered prompt line still matches the unseal_prompt_re sentinel"
else
    _fail "the countered prompt line no longer matches unseal_prompt_re (scenario prompt greps would strand)"
fi

# --- (d) the honest caveat, identical wording in BOTH docs ------------------------
CAVEAT='anti-footgun for the legitimate operator, not anti-tamper'
assert_contains "docs/UserGuide.md carries the anti-footgun-not-anti-tamper caveat" "$UG_TXT" "$CAVEAT"
assert_contains "docs/Architecture.md carries the anti-footgun-not-anti-tamper caveat" "$ARCH_TXT" "$CAVEAT"

# --- (e) hook parses (the grep pins above mean nothing on a broken script) --------
sh -n "$HOOK" >/dev/null 2>&1
assert_eq "hook parses under POSIX sh (busybox ash)" "0" "$?"

finish
