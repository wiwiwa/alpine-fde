#!/usr/bin/env bash
# tests/unit/residue_guard.sh — G-E13 tree-level Debian-contract residue guard.
#
# The tree-level safety net against Debian-contract regressions: the shipped
# product must not reference the retired Debian tooling contract (paths,
# unit names, package-manager/debian-tool invocations) anywhere a user, the
# guest, or a maintainer would trip over it.
#
# SCANNED (shipped paths): bin/ lib/ hooks/ docs/Architecture.md
# docs/UserGuide.md README.md.
# EXCLUDED: tests/, .git, Debian-era provenance records
# (tests/sentinels-257.13.txt). The former compat seams (the bin/debian-fde
# alias wrapper + the DEBIAN_FDE_* env spellings) were RETIRED in the
# alpine-fde rename — the debian-fde spellings below are BANNED patterns, not
# accepted seams.
#
# PATTERNS: /opt/debian-fde  /etc/debian-fde  debian-fde-finalize.service
#           debootstrap  apt-get install  dpkg  systemd-cryptenroll
#           dracut.conf.d  omit_dracutmodules   (ADR-13: mkinitfs, not dracut)
#
# WHITELIST MECHANISM (exact): in docs/Architecture.md ONLY, a line carrying
# the literal marker `ADR-` is exempt (today: the §14 decision-table rows and
# the §6.1 Mechanism A record — historical/rationale mentions of the Debian
# tools). Every other docs line, all of docs/UserGuide.md and README.md, and
# ALL code paths (bin/, lib/, hooks/) have NO whitelist.
#
# ENFORCEMENT TIERS:
#   * HARD (count must be 0): `/opt/debian-fde` and
#     `debian-fde-finalize.service` anywhere shipped; every pattern in
#     hooks/ and bin/; every pattern in docs beyond the ADR whitelist.
#   * LEDGER ratchet (count must stay <= pin): the known in-flight residue in
#     lib/ — the historical comments / host require_pkgs apt-get fallback. The
#     /etc/debian-fde -> /etc/alpine-fde target-path migration is COMPLETE
#     (R4: no legacy fallback; the last lib hit, the audit.sh usage-comment
#     mention, is gone): pin 0 — ANY /etc/debian-fde regression in lib/ now
#     fails. A NEW hit breaks the pin; landing the owning gap LOWERS the pin.
#     Ledger pinned at G-E13 time, /etc landed at 1 and now ratcheted to 0:
#       lib /etc/debian-fde=0  debootstrap=1  apt-get install=9  dpkg=2
#       systemd-cryptenroll=5
#     (counts = lines matched by grep -rF over lib/ — same command as below).
#
# Also pins the G-C7 seam agreement: lib/keys.sh's cmd-dir candidate list and
# lib/firmware.sh's documented guest one-liner name /opt/alpine-fde (never
# /opt/debian-fde), and the shipped finalize advisory's default cmd-dir
# (/opt/alpine-fde/lib/cmd) agreeing with the installer's emitted guest lines.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"

PATTERNS=(
    '/opt/debian-fde'
    '/etc/debian-fde'
    'debian-fde-finalize.service'
    'debootstrap'
    'apt-get install'
    'dpkg'
    'systemd-cryptenroll'
    'dracut.conf.d'
    'omit_dracutmodules'
)
DOCS_FILES="$REPO/docs/Architecture.md $REPO/docs/UserGuide.md $REPO/README.md"
SHIPPED_DIRS="$REPO/bin $REPO/lib $REPO/hooks"

# count_in DIRS PATTERN — lines matching a fixed string across dirs/files
count_in() {
    grep -rF -- "$2" "$1" 2>/dev/null | wc -l
}

# =============================================================================
# HARD: the retired tooling PATHS must be gone everywhere shipped (G-C7/G-E13)
# =============================================================================
for p in '/opt/debian-fde' 'debian-fde-finalize.service'; do
    assert_eq "residue guard: '$p' zero anywhere shipped (bin lib hooks docs README)" "0" \
        "$(count_in "$SHIPPED_DIRS $DOCS_FILES" "$p")"
done

# =============================================================================
# HARD: hooks/ and bin/ are fully clean of every Debian-contract pattern
# (behavior-level Debian-isms in shipped code paths are never whitelisted)
# =============================================================================
for p in "${PATTERNS[@]}"; do
    assert_eq "residue guard: hooks/ clean of '$p'" "0" "$(count_in "$REPO/hooks" "$p")"
    assert_eq "residue guard: bin/ clean of '$p'" "0" "$(count_in "$REPO/bin" "$p")"
done

# =============================================================================
# HARD: docs clean beyond the ADR whitelist (UserGuide + README: no whitelist)
# =============================================================================
for f in $DOCS_FILES; do
    for p in "${PATTERNS[@]}"; do
        # whitelist: Architecture.md lines carrying the literal 'ADR-' marker
        [ "$f" = "$REPO/docs/Architecture.md" ] && WL=(grep -v 'ADR-') || WL=(cat)
        n=$(grep -F -- "$p" "$f" 2>/dev/null | "${WL[@]}" | wc -l)
        assert_eq "residue guard: $(basename "$f") clean of '$p' beyond the ADR whitelist" "0" "$n"
    done
done

# =============================================================================
# LEDGER ratchet: known in-flight lib/ residue (see header for the pins and
# the ownership of each entry). Any NEW hit fails; fixes must LOWER the pin.
# =============================================================================
ledger() { # PATTERN PIN
    local n
    n=$(count_in "$REPO/lib" "$1")
    assert_rc "residue ledger: lib/ '$1' <= $2 (ratchet; regression if it grows)" 0 \
        bash -c "[ $n -le $2 ]"
}
ledger '/etc/debian-fde' 0
ledger 'debootstrap' 1
ledger 'apt-get install' 9
ledger 'dpkg' 2
ledger 'systemd-cryptenroll' 5
# ADR-13 ratchet: the dracut-contract writes are removed from the install
# plan — any dracut conf residue re-appearing in lib/ fails the guard
ledger 'dracut.conf.d' 0
ledger 'omit_dracutmodules' 0

# =============================================================================
# G-C7 seam agreement: the cmd-dir resolution candidates and the shipped
# advisory default name /opt/alpine-fde — agreeing with the installer's
# emitted guest lines (pinned exactly in install_qemu_emit.sh)
# =============================================================================
KEYS_SH=$(cat "$REPO/lib/keys.sh")
FIRMWARE_SH=$(cat "$REPO/lib/firmware.sh")
ADVISORY=$(cat "$REPO/hooks/openrc/alpine-fde-finalize")
assert_contains "G-C7: lib/keys.sh cmd-dir candidate list names /opt/alpine-fde/lib/cmd" \
    "$KEYS_SH" "/opt/alpine-fde/lib/cmd"
assert_not_contains "G-C7: lib/keys.sh candidates free of /opt/debian-fde" \
    "$KEYS_SH" "/opt/debian-fde"
assert_contains "G-C7: lib/firmware.sh documents the /opt/alpine-fde guest one-liner" \
    "$FIRMWARE_SH" "/opt/alpine-fde"
assert_not_contains "G-C7: lib/firmware.sh free of /opt/debian-fde" \
    "$FIRMWARE_SH" "/opt/debian-fde"
assert_contains "G-C7: shipped finalize advisory default cmd-dir = /opt/alpine-fde/lib/cmd (guest-line seam agreement)" \
    "$ADVISORY" "/opt/alpine-fde/lib/cmd"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
