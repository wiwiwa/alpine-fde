#!/usr/bin/env bash
# tests/unit/reseal_crypttab_multi.sh — the reseal target selection for the
# bcache-multi topology (R640 2026-10-01): reseal with no --uuid seals EVERY
# crypttab LUKS member (each container carries an INDEPENDENT volume
# passphrase + its own token pair), while the single-member accessor keeps
# serving kernel-build's ensure-once (first member, §8.2 verified coupling).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
source "$HERE/lib.sh"

. "$REPO/lib/common.sh"
. "$REPO/lib/cmd/reseal.sh"

T=$(mktemp -d /tmp/alpine-fde-ctmulti.XXXXXX)
trap 'rm -rf "$T"' EXIT

# the bcache-multi crypttab shape (R640 first install): root1 + root2, both
# luks, plus noise lines the grammar must skip
cat >"$T/crypttab" <<'EOF'
root1 UUID=11111111-1111-1111-1111-111111111111 none luks,tpm2-device=auto,password-cache=yes,discard
root2 UUID=22222222-2222-2222-2222-222222222222 none luks,tpm2-device=auto,password-cache=yes,discard
# a commented-out former member is skipped
#root3 UUID=33333333-3333-3333-3333-333333333333 none luks
swap UUID=aaaaaaaa-0000-0000-0000-000000000000 none swap,discard
EOF

assert_eq "multi: BOTH members, first-seen order" \
    "11111111-1111-1111-1111-111111111111
22222222-2222-2222-2222-222222222222" "$(reseal_crypttab_uuids "$T/crypttab")"
assert_eq "multi: the single-member accessor keeps serving the FIRST (kernel-build ensure-once)" \
    "11111111-1111-1111-1111-111111111111" "$(reseal_crypttab_uuid "$T/crypttab")"

# duplicate collapse (a re-run appended the same member)
cat "$T/crypttab" "$T/crypttab" >"$T/crypttab.dup"
assert_eq "multi: duplicates collapsed" "2" "$(reseal_crypttab_uuids "$T/crypttab.dup" | wc -l)"

# single-volume legacy crypttab: the multi accessor returns exactly one
printf 'root UUID=db66f53d-ef0d-4fe9-a2d2-30a5cbf3471b none luks\n' >"$T/crypttab.single"
assert_eq "legacy single-volume: exactly one member" "1" "$(reseal_crypttab_uuids "$T/crypttab.single" | wc -l)"
assert_eq "legacy single-volume: accessor agrees" \
    "db66f53d-ef0d-4fe9-a2d2-30a5cbf3471b" "$(reseal_crypttab_uuid "$T/crypttab.single")"

# missing file: quiet empty (the caller falls back to the baseline target)
assert_eq "missing crypttab: quiet empty" "" "$(reseal_crypttab_uuids "$T/absent")"
assert_eq "missing crypttab: accessor quiet empty" "" "$(reseal_crypttab_uuid "$T/absent")"

finish
