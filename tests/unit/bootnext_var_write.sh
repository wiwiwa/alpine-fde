#!/usr/bin/env bash
# tests/unit/bootnext_var_write.sh — `debian-fde bootnext` LoaderEntryOneShot
# mechanics (C-G11): var file = u32le attrs 0x7 + UTF-16LE entry id; write is
# delete-then-write; no-arg prints current; dry-run writes nothing; invalid
# entry ids -> usage rc 2.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
export DEBIAN_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/baseline.sh
source "$REPO/lib/baseline.sh"

T=$(mktemp -d /tmp/debian-fde-bootnext.XXXXXX)
EFIVARS=$T/efivars
export DEBIAN_FDE_EFIVARS_DIR=$EFIVARS
VARFILE=$EFIVARS/LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
ENTRY='alpine-fde-6.6.0-0-lts.conf'

run_bootnext() { # args...
    BN_OUT=$("$REPO/bin/debian-fde" bootnext "$@" 2>&1)
    BN_RC=$?
}

mkdir -p "$EFIVARS"

# --- 1. write a one-shot entry ---------------------------------------------------
run_bootnext "$ENTRY"
assert_eq "bootnext write rc 0" "0" "$BN_RC"
assert_file_exists "var file created" "$VARFILE"
assert_eq "file size = 4 (attrs) + 2*len(entry)" "$((4 + 2 * ${#ENTRY}))" "$(wc -c <"$VARFILE" | tr -d ' ')"
assert_eq "attrs u32le 0x7 prefix" "07000000" "$(od -An -v -tx1 -N4 "$VARFILE" | tr -d ' \n')"
assert_eq "payload starts with UTF-16LE('al')" "61006c00" \
    "$(tail -c +5 "$VARFILE" | od -An -v -tx1 | tr -d ' \n' | cut -c 1-8)"
# precise: full body hex (attrs + UTF-16LE of $ENTRY, no trailing NUL)
EXPECT_HEX='07000000'
EXPECT_HEX+=$(printf '%s' "$ENTRY" | od -An -v -tx1 | tr -d ' \n' | sed 's/../&00/g')
assert_eq "full var body golden" "$EXPECT_HEX" "$(od -An -v -tx1 "$VARFILE" | tr -d ' \n')"

# --- 2. delete-then-write: stale longer var replaced exactly ------------------------
python3 - "$VARFILE" <<'EOF'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
b += b'\x00' * 60   # stale variable with a longer payload
open(sys.argv[1], 'wb').write(bytes(b))
EOF
run_bootnext 'other-entry'
assert_eq "delete-then-write rc 0" "0" "$BN_RC"
assert_eq "stale var fully replaced (exact new size)" "$((4 + 2 * 11))" "$(wc -c <"$VARFILE" | tr -d ' ')"

# --- 3. no argument prints the current entry ------------------------------------------
run_bootnext
assert_eq "display rc 0" "0" "$BN_RC"
assert_eq "displays current entry (UTF-16LE decoded)" "other-entry" "$BN_OUT"

# --- 4. unset variable -> "(unset)" ----------------------------------------------------
rm -f "$VARFILE"
run_bootnext
assert_eq "unset display rc 0" "0" "$BN_RC"
assert_eq "unset prints (unset)" "(unset)" "$BN_OUT"

# --- 5. validation: bad entry ids -> usage rc 2 ------------------------------------------
run_bootnext ''
assert_eq "empty entry -> rc 2" "2" "$BN_RC"
run_bootnext $'with\nnewline'
assert_eq "newline injection -> rc 2" "2" "$BN_RC"
run_bootnext 'has space'
assert_eq "space in entry -> rc 2" "2" "$BN_RC"
run_bootnext "$(printf 'x%.0s' {1..201})"
assert_eq "entry > 200 chars -> rc 2" "2" "$BN_RC"
if [ -e "$VARFILE" ]; then
    assert_eq "invalid ids wrote nothing" "absent" "present"
else
    assert_eq "invalid ids wrote nothing" "absent" "absent"
fi

# --- 6. extra args -> usage rc 2 ------------------------------------------------------------
run_bootnext a b
assert_eq "two args -> rc 2" "2" "$BN_RC"

# --- 7. dry-run: prints plan, writes nothing ---------------------------------------------------
run_bootnext --dry-run "$ENTRY"
assert_eq "dry-run rc 0" "0" "$BN_RC"
assert_contains "dry-run prints the entry" "$BN_OUT" "$ENTRY"
if [ -e "$VARFILE" ]; then
    assert_eq "dry-run wrote nothing" "absent" "present"
else
    assert_eq "dry-run wrote nothing" "absent" "absent"
fi

# --- 8. no efivars dir on real write -> fail-closed ----------------------------------------------
export DEBIAN_FDE_EFIVARS_DIR=$T/nonexistent-efivars
run_bootnext "$ENTRY"
assert_eq "missing efivarfs -> fail-closed" "64" "$BN_RC"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
