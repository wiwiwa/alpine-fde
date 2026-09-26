#!/usr/bin/env bash
# tests/unit/guest_tool_inventory.sh — TARGET-TOOL INVENTORY pin (real-server
# blocker #16 is the founding member of its failure class): every external
# command the GUEST-side build invokes must be PROVIDED by the pinned Alpine
# package set — 'works on the host, missing in the guest' must fail locally,
# forever, before an install dies mid-flight on the target.
#
# Hermetic + fast: pure apk listings (tar -tzf) over the LOCAL mirror spool
# (ALPINE_FDE_SPOOL, default /tmp/mirror-work/spool) — no network, no chroot,
# no boots. The guest's OWN busybox (extracted from its apk, run through the
# guest's OWN musl loader, also from the spool) is the applet authority.
#
# What is checked:
#   1. TOOL EXTRACTION (mechanical, command-position approximated) over
#      - lib/cmd/ukictl-build.sh (the guest UKI build script, wholesale) and
#      - every GUEST RECORD emitted by lib/cmd/install.sh
#        (inst_plan_run guest '...' / printf '%s\n' "..." lines).
#   2. PROVISION: each extracted command word must come from
#      (a) a binary entry in some spool apk (usr/bin, usr/sbin, bin, sbin),
#      (b) a busybox applet, or
#      (c) the product tree itself (/opt/alpine-fde/bin/alpine-fde).
#   3. require_pkgs MAPPINGS: every `require_pkgs binary:package` pair across
#      lib/ must name a package present in the spool AND carried by it —
#      EXCEPT the documented known-gap list below.
#   4. RED CONTROL (the founding fact): NO apk in the spool provides
#      systemd-measure — the product must keep providing it (lib/measure.sh
#      + the ukictl-build --tools=<dir> shim staging), or this pin fails.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

SPOOL=${ALPINE_FDE_SPOOL:-/tmp/mirror-work/spool}
if [ ! -d "$SPOOL" ] || ! ls "$SPOOL"/*.apk >/dev/null 2>&1; then
    echo "SKIP: no apk spool at $SPOOL — the inventory pin needs the pinned mirror; run where the mirror is staged"
    exit 0
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- 1. provision index: tool -> providing packages (spool listings) ------------
# linux-firmware* and linux-lts* are excluded from the listing scan for speed:
# they carry no system tools (firmware blobs / kernel modules only) and
# dominate the spool's byte count.
INDEX="$TMP/index.txt"
: >"$INDEX"
PKGSET="$TMP/pkgs.txt"
: >"$PKGSET"
for apk in "$SPOOL"/*.apk; do
    pkg=$(basename "$apk" .apk)
    pkg=$(printf '%s' "$pkg" | sed -E 's/-[0-9][^-]*-r[0-9]+$//')
    printf '%s\n' "$pkg" >>"$PKGSET"
    case $pkg in
        linux-firmware* | linux-lts*) continue ;;
    esac
    tar -tzf "$apk" 2>/dev/null |
        grep -E '^(usr/)?(bin|sbin)/[^/]+$' |
        sed 's#.*/##' |
        awk -v p="$pkg" '{ print $1 "\t" p }' >>"$INDEX"
done
sort -u -o "$INDEX" "$INDEX"
sort -u -o "$PKGSET" "$PKGSET"

provided_by() { # <tool> — print the spool packages providing it
    awk -F'\t' -v t="$1" '$1 == t { print $2 }' "$INDEX"
}

# --- 2. busybox applet set: the guest's OWN busybox is the authority -------------
APPLETS="$TMP/applets.txt"
: >"$APPLETS"
BUSYBOX_APK=$(ls "$SPOOL"/busybox-[0-9]*.apk 2>/dev/null | head -n 1)
MUSL_APK=$(ls "$SPOOL"/musl-[0-9]*.apk 2>/dev/null | head -n 1)
if [ -n "$BUSYBOX_APK" ] && [ -n "$MUSL_APK" ]; then
    mkdir -p "$TMP/bb"
    # the guest binaries are musl-linked; run the guest busybox through the
    # guest musl loader — both straight out of the spool, still no chroot
    if tar -xzf "$BUSYBOX_APK" -C "$TMP/bb" bin/busybox 2>/dev/null &&
        tar -xzf "$MUSL_APK" -C "$TMP/bb" lib/ld-musl-x86_64.so.1 2>/dev/null &&
        [ -x "$TMP/bb/bin/busybox" ] &&
        "$TMP/bb/lib/ld-musl-x86_64.so.1" "$TMP/bb/bin/busybox" --list >"$APPLETS" 2>/dev/null; then
        : # applet list extracted
    else
        : >"$APPLETS" # loader/arch mismatch — applets unchecked on this host
    fi
fi
is_applet() {
    [ -s "$APPLETS" ] && awk -v t="$1" '$0 == t { found = 1 } END { exit !found }' "$APPLETS"
}

# --- 3. tool extraction (command-position approximated) ---------------------------
FUNCS=$(grep -hEo '^[a-zA-Z_][a-zA-Z0-9_]*\(\)' \
    "$REPO"/lib/*.sh "$REPO"/lib/cmd/*.sh 2>/dev/null | sed 's/()//' | sort -u)
is_repo_function() {
    printf '%s\n' "$FUNCS" | awk -v t="$1" '$0 == t { found = 1 } END { exit !found }'
}

# extract_commands — stdin: shell text; stdout: candidate command words.
# A candidate is the FIRST word of each approximated simple command that is
# not a shell keyword, assignment, option, repo-private (_-prefixed) name, or
# a path/variable reference (a leading path IS the command — and never an
# apk-provided bare name anyway). Comment lines, trailing comments, heredoc
# bodies and single-quoted spans (jq/sed programs) are suppressed first:
# usage prose must never become a "tool". No single quotes are used inside
# the awk programs (q = CHR 39) so the shell quoting stays trivial.
extract_commands() {
    awk '
        BEGIN { q = sprintf("%c", 39); d = sprintf("%c", 34); insq = 0; indq = 0 }
        # NOTE: insq/indq (quote state) are PERSISTENT across lines on purpose:
        # multi-line quoted strings (jq programs in ukictl-build.sh) must not
        # leak their bodies as fake command words.
        {
            line = $0
            if (inh != "") {                       # inside a heredoc body
                if (index(line, inh) == 1) inh = ""
                next
            }
            if (match(line, /<<-?[A-Za-z_][A-Za-z0-9_]*/)) {
                hd = substr(line, RSTART + 2, RLENGTH - 2)
                while (index(hd, q) == 1) hd = substr(hd, 2, length(hd) - 1)
                while (length(hd) > 0 && substr(hd, length(hd), 1) == q)
                    hd = substr(hd, 1, length(hd) - 1)
                pre = substr(line, 1, RSTART - 1)
                rest = substr(line, RSTART + RLENGTH)
                inh = hd                           # body always starts on the NEXT line
                line = pre rest                    # keep same-line code, drop the marker
            }
            if (line ~ /^[[:space:]]*#/) next      # whole-line comment: DROPPED
            gsub(/\\"/, "\"", line)                # unfold \" and \$ escapes FIRST
            gsub(/\\[$]/, "$", line)
            # single scan: strip QUOTED SPANS (single- AND double-quoted) and
            # comments. Command words are never quoted in this codebase, while
            # strings carry prose, jq/sed programs and variable references that
            # would otherwise leak in as fake command positions. The comment
            # check (# at line start or after whitespace) MUST run inside this
            # scan — a per-line regexp strip would also eat "#..." INSIDE a
            # quote span and corrupt the quote parity for the whole file.
            out = ""
            prev = " "
            L = length(line)
            for (c = 1; c <= L; c++) {
                ch = substr(line, c, 1)
                if (insq == 0 && indq == 0 && ch == "#" && prev ~ /[[:space:]]/) break
                if (ch == q && indq == 0) {
                    insq = 1 - insq
                    out = out " "
                } else if (ch == d && insq == 0) {
                    indq = 1 - indq
                    out = out " "
                } else if (insq == 0 && indq == 0) {
                    out = out ch
                    prev = ch
                }
            }
            line = out
            gsub(/[|&;()]/, "\n", line)            # split simple commands
            print line
        }
    ' |
        awk '
            {
                n = split($0, w, /[[:space:]]+/)
                for (i = 1; i <= n; i++) {
                    t = w[i]
                    if (t == "") continue
                    sub(/^[([{]+/, "", t)
                    if (t == "") continue
                    if (t ~ /^[A-Za-z_][A-Za-z0-9_]*=/) continue   # assignment (NAME=…)
                    if (t !~ /^[A-Za-z_][A-Za-z0-9_.-]*$/) break   # pattern/redirection/etc
                    if (t ~ /^(if|then|else|elif|fi|for|while|until|do|done|case|esac|in|!|break|continue|cd|export|readonly|set|unset|shift|return|exit|eval|exec|trap|umask|local|source|read|INT|TERM|EXIT|HUP|ERR|:|\.)$/) break   # these own the rest of the line (var names, not commands)
                    if (t ~ /^_/) break                            # repo-private name
                    print t
                    break
                }
            }
        '
}

# UKI build script: wholesale (it IS the guest build program)
extract_commands <"$REPO/lib/cmd/ukictl-build.sh" >"$TMP/tools-build.txt"
# install.sh: only the GUEST RECORD strings (the in-chroot steps)
{
    grep -h "inst_plan_run guest " "$REPO/lib/cmd/install.sh" | sed -E 's/^[^"'"'"']*["'"'"']//; s/["'"'"'].*$//'
    grep -h "printf '%s..n' \"" "$REPO/lib/cmd/install.sh" | sed -E 's/^[^"]*"//; s/".*$//'
} | extract_commands >"$TMP/tools-records.txt"
sort -u "$TMP/tools-build.txt" "$TMP/tools-records.txt" -o "$TMP/tools.txt"

# --- 4. the pin: every extracted command word must be provided ---------------------
FAILS=0
while IFS= read -r tool; do
    [ -n "$tool" ] || continue
    case $tool in
        alpine-fde | fde_* | measure_probe)
            provided="product"
            ;;
        *)
            if [ -n "$(provided_by "$tool")" ]; then
                provided="apk:$(provided_by "$tool" | tr '\n' ',')"
            elif is_applet "$tool"; then
                provided="busybox"
            elif is_repo_function "$tool"; then
                continue # shell function from the sourced product libs
            else
                provided=""
            fi
            ;;
    esac
    if [ -z "$provided" ]; then
        _fail "guest tool NOT PROVIDED by the pinned package set: '$tool'"
        FAILS=$((FAILS + 1))
    else
        _pass "provided: $tool ($provided)"
    fi
done <"$TMP/tools.txt"

# --- 5. require_pkgs mappings must resolve against the spool -----------------------
# KNOWN GAPS (pinned, must not grow): these binaries are declared against
# util-linux, which the spool subset does not carry (present in Alpine main;
# the on-demand install fails closed at run time if ever reached — a separate
# mirror decision, NOT silently waved through here).
KNOWN_GAP_RE='^(flock:util-linux|sfdisk:util-linux)$'
grep -hEo 'require_pkgs [A-Za-z0-9_:-]+([[:space:]]+[A-Za-z0-9_:-]+)*' \
    "$REPO"/lib/*.sh "$REPO"/lib/cmd/*.sh 2>/dev/null |
    sed 's/^require_pkgs //' | tr ' ' '\n' |
    grep -E '^[A-Za-z0-9_]+:[A-Za-z0-9_]+' | grep -vE '^(binary|package):' | sort -u >"$TMP/require.txt"
while IFS= read -r pair; do
    bin=${pair%%:*}
    pkg=${pair#*:}
    if printf '%s' "$pair" | grep -qE "$KNOWN_GAP_RE"; then
        _pass "require_pkgs $pair: documented known-gap (spool subset omits $pkg)"
        continue
    fi
    if ! awk -v p="$pkg" '$0 == p { found = 1 } END { exit !found }' "$PKGSET"; then
        _fail "require_pkgs $pair: package '$pkg' is NOT in the pinned spool (Alpine package name drift — blocker-#16 class)"
        FAILS=$((FAILS + 1))
        continue
    fi
    if [ -z "$(provided_by "$bin")" ]; then
        _fail "require_pkgs $pair: no spool package provides '$bin'"
        FAILS=$((FAILS + 1))
    elif ! provided_by "$bin" | grep -qx "$pkg"; then
        _fail "require_pkgs $pair: '$bin' is provided by ($(provided_by "$bin" | tr '\n' ',')) — not by '$pkg'"
        FAILS=$((FAILS + 1))
    else
        _pass "require_pkgs $pair resolves in the spool"
    fi
done <"$TMP/require.txt"

# --- 6. RED CONTROL: systemd-measure is the founding member -------------------------
if [ -n "$(provided_by systemd-measure)" ]; then
    _fail "RED CONTROL inverted: an apk now provides systemd-measure ($(provided_by systemd-measure)) — switch the ukictl-build probe to prefer the package and retire the shim"
else
    _pass "RED CONTROL: NO apk in the spool provides systemd-measure (blocker #16 founding fact holds)"
fi
grep -q "fde_measure_main" "$REPO/lib/measure.sh" &&
    grep -q -- "--tools=" "$REPO/lib/cmd/ukictl-build.sh" &&
    grep -q "measure_resolve" "$REPO/lib/cmd/ukictl-build.sh"
assert_rc "product provides the measure implementation (lib/measure.sh shim + measure_resolve/--tools wiring, blocker #17 centralization)" 0 $?

# coverage guard: the extraction actually saw the guest build surface (a silent
# extractor regression must not vacuate the pin)
grep -q '^ukify$' "$TMP/tools-build.txt"
assert_rc "extractor saw ukify in ukictl-build.sh (extraction not vacuous)" 0 $?
grep -q '^apk$' "$TMP/tools-records.txt" || grep -q '^echo$' "$TMP/tools-records.txt"
assert_rc "extractor saw guest-record command words (extraction not vacuous)" 0 $?

finish
