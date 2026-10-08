#!/bin/bash
# initrd_closure_tpm2_verbs.sh — every tpm2_* verb the unseal hook invokes
# MUST be packed by the mkinitfs alpine-fde.files closure list. The R640
# 2026-10-08 boot-2: the escrow self-seal died rc=127 (tpm2_create invoked
# but never packed) — the x2 ceremony never ran on ANY real boot, while the
# e2e stayed green (4d61efa had fixed the HARNESS wrapper list only; the
# PRODUCT features.d list was never updated). This test pins the closure to
# the hook's actual verb usage so the class cannot recur.
set -u
cd "$(dirname "$0")/../.." || exit 1

HOOK=hooks/mkinitfs/alpine-fde-unseal.sh
FILES=hooks/mkinitfs/features.d/alpine-fde.files

pass=0; fail=0
t() { # t DESC CONDITION
    if [ "$2" = 0 ]; then
        echo "ok - $1"; pass=$((pass + 1))
    else
        echo "not ok - $1"; fail=$((fail + 1))
    fi
}

[ -f "$HOOK" ] && t "hook exists" 0 || t "hook exists" 1
[ -f "$FILES" ] && t "closure list exists" 0 || t "closure list exists" 1

# every tpm2_* token in the hook (comments included — a verb named in a
# comment is a verb the maintainer expects to exist; over-packing one extra
# /usr/bin/tpm2_* costs ~1MB, a missing one costs the whole ceremony)
verbs=$(grep -oE 'tpm2_[a-z]+' "$HOOK" | sort -u)
[ -n "$verbs" ] && t "hook names at least one tpm2 verb" 0 || t "hook names at least one tpm2 verb" 1

for v in $verbs; do
    grep -q "/usr/bin/$v\$" "$FILES"
    t "closure packs /usr/bin/$v" $?
done

# and the closure list carries nothing tpm2-ish that the hook never uses
# (drift guard: an entry nobody calls is dead weight — flag it, not fatal)
for f in $(grep -oE '^/usr/bin/tpm2_[a-z]+' "$FILES"); do
    v=${f#/usr/bin/}
    grep -q "$v" "$HOOK" || echo "# note: $v packed but not referenced by the hook"
done

echo "1..$((pass + fail))"
[ "$fail" = 0 ]
