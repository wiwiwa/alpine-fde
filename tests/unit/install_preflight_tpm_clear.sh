#!/bin/bash
# install_preflight_tpm_clear.sh — the preflight's TPM clean-slate clear
# (R640 2026-10-08): inst_preflight runs tpm2_clear (platform hierarchy)
# BEFORE any disk mutation; a refusal dies loud with the racadm/F2 remedy;
# a missing TPM degrades to a warn (the reseal/finalize still gates).
# Verified tonight: EVERY real-TPM failure (the boot-1 escrow createprimary
# death, the boot-2 rc=127 sibling) traced to undefined leftover TPM state;
# the e2e never sees the class because swtpm is wiped per scenario.
set -u
cd "$(dirname "$0")/../.." || exit 1

pass=0; fail=0
t() {
    if [ "$2" = 0 ]; then
        echo "ok - $1"; pass=$((pass + 1))
    else
        echo "not ok - $1"; fail=$((fail + 1))
    fi
}

grep -q 'inst_preflight()' lib/cmd/install.sh
t "inst_preflight exists" $?

grep -q 'tpm clear -c lockout' lib/cmd/install.sh
t "preflight clears the TPM (lockout-first, shared tpm() wrapper)" $?

# the clear sits BEFORE the first partition/disk mutation record
cl=$(grep -n 'tpm clear -c lockout' lib/cmd/install.sh | head -1 | cut -d: -f1)
p1=$(grep -n 'sfdisk --force' lib/cmd/install.sh | head -1 | cut -d: -f1)
[ -n "$cl" ] && [ -n "$p1" ] && [ "$cl" -lt "$p1" ]
t "clear runs before the first partition write" $?

# the refusal dies loud with the firmware/racadm remedy
grep -q 'Tpm2Hierarchy Clear' lib/cmd/install.sh
t "refusal names the racadm Tpm2Hierarchy remedy" $?
grep -q 'Clear TPM' lib/cmd/install.sh
t "refusal names the F2 Clear TPM remedy" $?

# the missing-TPM path degrades to a warn (never a die — unit/TPM-less hosts)
grep -q 'no TPM device present' lib/cmd/install.sh
t "absent TPM degrades to warn (reseal still gates)" $?

# the clear is idempotent-safe to re-run (a die only on a FAILED clear)
grep -q 'factory-fresh' lib/cmd/install.sh
t "success prints the clean-slate confirmation" $?

echo "1..$((pass + fail))"
[ "$fail" = 0 ]

# the SRK probe: the clear is verified by an actual createprimary, not a hope
grep -q 'post-clear createprimary probe failed' lib/cmd/install.sh
t "clear verified by a live createprimary probe" $?
