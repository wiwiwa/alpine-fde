#!/usr/bin/env bash
# tests/unit/live_tool_pairs_shape.sh — real-server blocker #19: the LIVE-HOST
# preflight tool set (lib/cmd/install.sh inst_live_tool_pairs) died as
#   package install did not provide the expected binary (for: bcache-tools-udev)
# because a TARGET-only package (bcache-tools-udev ships only udev rules +
# helpers — no binary) was emitted as a BARE pair; require_pkgs parsed it as
# binary=bcache-tools-udev, probed, apk-added, re-probed, died 64. Contract:
#   1. SHAPE: every inst_live_tool_pairs line is `binary:package` — a
#      colon-less pair is a build-system bug and fails this pin (RED control
#      below replays the old emission and shows the check catching it);
#   2. RESOLUTION: every left side is a real command the named package ships
#      (checked against the local mirror spool's apk listings when available,
#      mirroring the guest_tool_inventory idiom; skipped when no spool);
#   3. CLOSURE: bcache-tools-udev stays in mirror_package_list — it MUST be in
#      the mirror/spool even though it is not a live pair (the in-chroot apk
#      txn installs it; offline/local installs fetch it from the mirror);
#   4. the bcache-tools-udev apk bytes match the pin in tests/lib/local-mirror.sh
#      when the apk is present in the spool.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/install.sh
. "$ALPINE_FDE_CMD_DIR/install.sh"
# shellcheck source=../lib/local-mirror.sh
source "$HERE/../lib/local-mirror.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- 1. shape: every emitted line is binary:package -------------------------------
# captured at the MAXIMAL topology (bcache on) — the bcache branch is where
# blocker #19's bare pair lived
PAIRS=$(INST_BCACHE=1 INST_ROOT_FS=btrfs inst_live_tool_pairs)
[ -n "$PAIRS" ] || { echo "FAIL: inst_live_tool_pairs emitted nothing" >&2; exit 1; }
BAD=$(printf '%s\n' "$PAIRS" | grep -cvE '^[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+$')
assert_eq "every inst_live_tool_pairs line is binary:package (no bare pairs)" "0" "$BAD"

# RED control: replay the OLD emission (the bare bcache-tools-udev pair from
# blocker #14b) and show the shape check catches it — the pin has teeth.
OLD_PAIRS=$(printf '%s\n' "$PAIRS" "bcache-tools-udev")
OLD_BAD=$(printf '%s\n' "$OLD_PAIRS" | grep -cvE '^[A-Za-z0-9_.+-]+:[A-Za-z0-9_.+-]+$')
[ "$OLD_BAD" -ge 1 ] &&
    _pass "RED control: the old bare 'bcache-tools-udev' pair violates the shape check" ||
    _fail "RED control FAILED: the shape check cannot catch the old bare pair"

# --- 2. closure: bcache-tools-udev stays in the mirror package list ---------------
for bc in 0 1; do
    INST_BCACHE=$bc INST_ROOT_FS=btrfs mirror_package_list >"$TMP/mirror-b$bc.txt"
    assert_contains "mirror closure (INST_BCACHE=$bc) contains bcache-tools-udev" \
        "$(tr ' ' '\n' <"$TMP/mirror-b$bc.txt" | sort -u | tr '\n' ' ')" "bcache-tools-udev"
done
# and it is NOT derivable from the live pairs anymore (so the closure union is
# what pins it — the union must keep carrying it)
printf '%s\n' "$PAIRS" | grep -q "bcache-tools-udev" &&
    _fail "bcache-tools-udev is still emitted as a LIVE pair" ||
    _pass "bcache-tools-udev is no longer a live pair (target-side only, closure-pinned)"

# --- 3. resolution: each left side is a command the named package ships -----------
SPOOL=${ALPINE_FDE_SPOOL:-/tmp/mirror-work/spool}
if [ -d "$SPOOL" ] && ls "$SPOOL"/*.apk >/dev/null 2>&1; then
    IDX="$TMP/spool-index.txt"
    : >"$IDX"
    for apk in "$SPOOL"/*.apk; do
        pkg=$(basename "$apk" .apk)
        pkg=$(printf '%s' "$pkg" | sed -E 's/-[0-9][^-]*-r[0-9]+$//')
        case $pkg in
            linux-firmware* | linux-lts*) continue ;;
        esac
        tar -tzf "$apk" 2>/dev/null |
            grep -E '^(usr/)?(bin|sbin)/[^/]+$' |
            sed 's#.*/##' |
            awk -v p="$pkg" '{ print $1 "\t" p }' >>"$IDX"
    done
    sort -u -o "$IDX" "$IDX"
    while IFS= read -r pair; do
        bin=${pair%%:*}
        pkg=${pair#*:}
        if ! grep -qF "$pkg" "$IDX"; then
            # the spool subset does not carry the package at all (mirror_ensure
            # fetches it on demand; util-linux/dosfstools are split metas) —
            # nothing verifiable locally, the closure pin carries the guarantee
            _pass "live pair $pair: package '$pkg' not in this spool subset (closure-pinned, fetched on demand)"
            continue
        fi
        if awk -F'\t' -v t="$bin" -v p="$pkg" '$1 == t && $2 == p { found = 1 } END { exit !found }' "$IDX"; then
            _pass "live pair $pair: '$bin' is shipped by the pinned '$pkg' apk"
        else
            # blocker #19 class inside a pair: the package exists but does not
            # ship the probed binary (the bcache-tools-udev mistake, paired form)
            _fail "live pair $pair: '$pkg' does not ship '$bin' (blocker-#19 class)"
        fi
    done < <(printf '%s\n' "$PAIRS" | sort -u)
else
    _pass "resolution check skipped (no spool at $SPOOL) — shape + closure pins still apply"
fi

# --- 4. the bcache-tools-udev apk bytes match the pin ------------------------------
UDEV_APK=$(ls "$SPOOL"/bcache-tools-udev-*.apk 2>/dev/null | head -n 1)
if [ -n "$UDEV_APK" ]; then
    got=$(sha256sum "$UDEV_APK" | cut -d' ' -f1)
    assert_eq "spool bcache-tools-udev apk matches the pinned sha256 ($MIRROR_PIN_BCACHE_TOOLS_UDEV_SHA256)" \
        "$MIRROR_PIN_BCACHE_TOOLS_UDEV_SHA256" "$got"
    assert_contains "spool bcache-tools-udev apk is the pinned version ($MIRROR_PIN_BCACHE_TOOLS_UDEV_VERSION)" \
        "$(basename "$UDEV_APK")" "-$MIRROR_PIN_BCACHE_TOOLS_UDEV_VERSION.apk"
else
    _pass "bcache-tools-udev apk not yet in this spool — mirror_ensure fetches it (closure carries it); pin MIRROR_PIN_BCACHE_TOOLS_UDEV_SHA256 holds the bytes of record"
fi

finish
