#!/usr/bin/env bash
# shellcheck shell=bash  # [[ ]], arrays, _MIRROR_CURL array — bash test lib
# tests/lib/local-mirror.sh — pinned LOCAL Alpine apk mirror + ISO cache for
# the install canary (tests/e2e/s23-install-e2e.sh, queue item 32/25) and any
# other lane that needs a drift-detectable, download-once Alpine package
# source.
#
# WHY: the real `alpine-fde install` (lib/cmd/install.sh) apk-populates the
# target from a live apk repository (ALPINE_FDE_MIRROR, default
# https://dl-cdn.alpinelinux.org/alpine/v3.24/main). A true end-to-end canary
# must consume the REAL installer's apk phase, but against a PINNED snapshot:
# upstream v3.24 is a moving branch (index entries change weekly), so a canary
# that fetches from upstream at run time is not reproducible. This lib
# materializes the installer's exact dependency closure ONCE into
# tests/.cache/local-mirror/<release>/ (download-once, SHA256-manifested),
# verified against the index pins below on EVERY call — upstream drift vs the
# pins is loud even on the cached no-op path.
#
# CACHE LAYOUT (upstream shape — inst_repo_lines resolves the main/community
# twin by stripping /main, so the layout must mirror dl-cdn's):
#   <cache>/<release>/main/x86_64/APKINDEX.tar.gz + *.apk
#   <cache>/<release>/community/x86_64/APKINDEX.tar.gz + *.apk
#   <cache>/<release>/MANIFEST.sha256   (indexes + every apk)
#   <cache>/<release>/mirror.json       (pins + provenance, human-readable)
# Default cache root tests/.cache/local-mirror (gitignored via the repo `.*`
# rule); ALPINE_FDE_LOCAL_MIRROR_CACHE relocates it.
#
# HOW the closure is computed (host-side, boot-free): the pinned
# apk-tools-static binary (bootstrapped below, itself SHA-pinned) runs
#   apk fetch --recursive --output <spool>  <package list>
# against the UPSTREAM http repositories — apk resolves the full dependency
# closure (including so:/cmd: provider deps) so the mirror can never
# under-approximate. Every spooled apk is then classified into main/community
# by (name, version) lookup against the CACHED (pinned) indexes; an apk whose
# (name, version) pair is absent from the pinned indexes means upstream moved
# between the index download and the fetch — fail-closed re-pin error, never a
# silent mixed snapshot.
#
# PACKAGE LIST DERIVATION (no drift by construction): mirror_package_list
# sources the REAL lib/cmd/install.sh and prints alpine-base + the output of
# its install_package_list (the §3.3 additions set, topology-conditional)
# UNION the other topology's conditional packages (e2fsprogs, btrfs-progs,
# bcache-tools), so ONE mirror serves any --fs/--bcache combination. Extra
# packages in the mirror are harmless; a missing one would kill the install.
#
# SERVING (decision + rationale, see the canary header): the guest consumes
# the mirror from a READ-ONLY VFAT DISK image (built with mkfs.vfat + mtools,
# the esp_make idiom) mounted in the live ISO and served by the GUEST's own
# busybox httpd on its loopback:
#     ALPINE_FDE_MIRROR=http://mirror.fde.internal:<port>/<release>/main
# This is the robust option because (a) it needs NO slirp/hostname networking
# in the guest — the only "network" apk ever touches is 127.0.0.1; (b) a
# file:// or bind-mounted repository cannot work under the chroot runner (the
# in-chroot `apk add` resolves repository paths against the TARGET root, and
# the installer mounts only /proc /sys /dev — there is no seam to bind the
# mirror into <mnt>); (c) the installer's DNS preflight (inst_preflight
# nslookup of the mirror host) trivially passes on a /etc/hosts-backed name
# with a stub resolver, which the canary stages in-guest. mirror_serve_start/
# stop is ALSO provided for lanes that prefer a HOST loopback httpd (the
# guest wget's the tree via slirp at http://10.0.2.2:<port>/) — the canary
# does not use it (the disk design avoids a ~1 GB slirp transfer), it exists
# so both documented options have a working implementation.
#
# ISO PIN: the installer boots the real Alpine ISO. Flavor alpine-virt
# (linux-virt kernel: virtio + serial console built in — the q35/UEFI/virtio
# harness shape), version aligned with the minirootfs pin in
# tests/lib/alpine-artifact.sh (3.24.2). Cached download-once under
# tests/.cache/isos/ (ALPINE_FDE_ISO_CACHE relocates), SHA256-pinned with an
# env override (ALPINE_FDE_ISO_SHA256) following the OVMF pin idiom
# (tests/lib/qemu.sh ovmf_pin_check).
#
# Pins provenance (byte-verified in this sandbox, 2026-09-26):
#   * ISO version/size/sha256 from the release index
#     https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/latest-releases.yaml
#     (flavor alpine-virt, version 3.24.2, dated 2026-09-17).
#   * APKINDEX sha256s: hashed from the downloaded dl-cdn v3.24 indexes on
#     the same day; the mirror manifest re-records them and mirror_ensure
#     re-verifies on every call.
#   * apk-tools-static / alpine-keys: exact versions + sha256s hashed from
#     the downloaded apks (dl-cdn v3.24/main).
# A mismatch anywhere FAILS CLOSED (nothing replaced, nothing half-written):
# unverified bytes never become an install source.

if [[ -n "${_ALPINE_FDE_LOCAL_MIRROR_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_LOCAL_MIRROR_SOURCED=1

_LOCAL_MIRROR_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
_TESTS_DIR=$(cd "$_LOCAL_MIRROR_HERE/.." && pwd)

# --- pins (the pin of record is THIS table, like alpine-artifact.sh) -----------
MIRROR_RELEASE_DEFAULT="v3.24"   # MUST match lib/cmd/install.sh inst_mirror's version segment
MIRROR_UPSTREAM_DEFAULT="https://dl-cdn.alpinelinux.org/alpine"

MIRROR_PIN_MAIN_APKINDEX_SHA256="${ALPINE_FDE_MIRROR_MAIN_APKINDEX_SHA256:-093ced7b6d94907be046454322f91d63d474670f32686ad0f89ceab4ba190d00}"
MIRROR_PIN_COMMUNITY_APKINDEX_SHA256="${ALPINE_FDE_MIRROR_COMMUNITY_APKINDEX_SHA256:-6d82ae4bbb2e2266f8e6211240d5d0e12baf973778f12f3d9303ae806ced1882}"

# bootstrap: the pinned apk binary that computes the closure + its keyring
MIRROR_PIN_APK_TOOLS_STATIC_VERSION="3.0.8-r0"
MIRROR_PIN_APK_TOOLS_STATIC_SHA256="c8e2c88c13ba12a12269b79a3543e1190ff8c0ab0beb32b58cadfd5881c619e3"
MIRROR_PIN_ALPINE_KEYS_VERSION="2.6-r0"
MIRROR_PIN_ALPINE_KEYS_SHA256="dd211936d544f4050924ce8aec078d24e7b1b036ae70b30bd07867349587c708"

# ISO pin (flavor alpine-virt; see header)
ISO_FLAVOR="alpine-virt"
ISO_VERSION="3.24.2"
ISO_ARCH="x86_64"
# shellcheck disable=SC2034  # pin of record (docs: byte size of the pinned ISO)
ISO_SIZE_BYTES=69206016
ISO_SHA256_DEFAULT="3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b"

# CR-01 curl policy (a mid-body stall must time out, never hang)
_MIRROR_CURL=(curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 30 --max-time 1800)

# --- accessors -------------------------------------------------------------------
mirror_release()   { printf '%s\n' "${ALPINE_FDE_MIRROR_RELEASE:-$MIRROR_RELEASE_DEFAULT}"; }
mirror_upstream()  { printf '%s\n' "${ALPINE_FDE_MIRROR_UPSTREAM:-$MIRROR_UPSTREAM_DEFAULT}"; }
mirror_cache_root() { printf '%s\n' "${ALPINE_FDE_LOCAL_MIRROR_CACHE:-$_TESTS_DIR/.cache/local-mirror}"; }
mirror_cache_dir() { printf '%s\n' "$(mirror_cache_root)/$(mirror_release)"; }
# mirror_repo_dir <component> — the repository ROOT apk consumes (apk appends
# the arch segment itself; upstream shape <release>/<component>/x86_64)
mirror_repo_dir()  { printf '%s\n' "$(mirror_cache_dir)/$1/x86_64"; }

mirror_iso_cache_dir() { printf '%s\n' "${ALPINE_FDE_ISO_CACHE:-$_TESTS_DIR/.cache/isos}"; }
iso_filename()     { printf '%s\n' "$ISO_FLAVOR-$ISO_VERSION-$ISO_ARCH.iso"; }
iso_path()         { printf '%s\n' "$(mirror_iso_cache_dir)/$(iso_filename)"; }
iso_url()          { printf '%s\n' "$(mirror_upstream)/$(mirror_release)/releases/$ISO_ARCH/$(iso_filename)"; }
iso_expected_sha256() { printf '%s\n' "${ALPINE_FDE_ISO_SHA256:-$ISO_SHA256_DEFAULT}"; }

# mirror_package_list — the REAL installer's apk universe (derivation, not a
# hand-copied table): alpine-base (the §3.3 populate) + install_package_list
# (the §3.3 in-chroot additions, topology-conditional) + the full topology
# union so one mirror serves every --fs/--bcache run. Sources the product lib;
# overrides ALPINE_FDE_MIRROR are NOT consumed here (the mirror is the
# UPSTREAM source we snapshot, not the serving URL).
mirror_package_list() {
    if ! command -v install_package_list >/dev/null 2>&1; then
        # shellcheck disable=SC1090,SC1091
        [[ -n "${ALPINE_FDE_CMD_DIR:-}" ]] || export ALPINE_FDE_CMD_DIR="$_TESTS_DIR/../lib/cmd"
        # shellcheck source=../../lib/common.sh
        . "$_TESTS_DIR/../lib/common.sh"
        # shellcheck source=../../lib/cmd/install.sh
        . "$ALPINE_FDE_CMD_DIR/install.sh"
    fi
    INST_ROOT_FS=${INST_ROOT_FS:-btrfs}
    INST_BCACHE=${INST_BCACHE:-0}
    local list
    list=$(install_package_list)
    # LIVE-env tool union (dedup): the §9.1 preflight's require_pkgs pairs —
    # the installer apk-adds any of these from the mirror when the live ISO
    # lacks the tool (the virt ISO lacks sfdisk/lsblk/mkfs.vfat). Without
    # this union a real install dies at the FIRST preflight probe
    # (boot-lane finding #4: "apk add util-linux failed ... no such
    # packaage", INSTALL-RC=64).
    local pair
    for pair in $(inst_live_tool_pairs); do
        list="$list ${pair#*:}"
    done
    # topology union (dedup): whatever install_package_list's --fs/--bcache
    # conditionals left out is appended, so one mirror serves every topology
    local p
    for p in btrfs-progs e2fsprogs bcache-tools; do
        case " $list " in
            *" $p "*) : ;;
            *) list="$list $p" ;;
        esac
    done
    printf '%s\n' "alpine-base $list"
}

# --- fail-closed download helpers --------------------------------------------------
_mirror_fetch() {   # _mirror_fetch <dest> <url> — tmp file + hash-verify is the
                    # CALLER's job (each pin knows its expected hash)
    local dest="$1" url="$2" tmp
    tmp="${dest}.part"
    "${_MIRROR_CURL[@]}" -o "$tmp" "$url" || {
        rm -f "$tmp"
        echo "local-mirror: download failed: $url" >&2
        return 1
    }
    mv "$tmp" "$dest"
}

_mirror_hash() { sha256sum "$1" | awk '{print $1}'; }

# --- the ensure chain ---------------------------------------------------------------
# mirror_index_ensure <main|community> — pinned APKINDEX into the repo dir.
# Fail-closed on hash mismatch (upstream moved => re-pin loudly, never mix).
mirror_index_ensure() {
    local comp="$1" dir url want have
    dir=$(mirror_repo_dir "$comp")
    mkdir -p "$dir"
    url="$(mirror_upstream)/$(mirror_release)/$comp/x86_64/APKINDEX.tar.gz"
    case "$comp" in
        main)      want="$MIRROR_PIN_MAIN_APKINDEX_SHA256" ;;
        community) want="$MIRROR_PIN_COMMUNITY_APKINDEX_SHA256" ;;
        *) echo "local-mirror: unknown component: $comp" >&2; return 64 ;;
    esac
    local dest="$dir/APKINDEX.tar.gz"
    if [[ -f "$dest" ]] && [[ "$(_mirror_hash "$dest")" == "$want" ]]; then
        return 0
    fi
    echo "local-mirror: fetching $comp APKINDEX ($url)" >&2
    _mirror_fetch "$dest" "$url" || return 1
    have=$(_mirror_hash "$dest")
    if [[ "$have" != "$want" ]]; then
        echo "local-mirror: APKINDEX PIN MISMATCH ($comp): expected $want got $have" >&2
        echo "  upstream $([ "$(mirror_release)" ])/$comp moved since the pin was recorded —" >&2
        echo "  re-pin MIRROR_PIN_${comp^^}_APKINDEX_SHA256 in tests/lib/local-mirror.sh and rebuild the mirror" >&2
        rm -f "$dest"
        return 1
    fi
    return 0
}

# mirror_bootstrap_ensure — the pinned apk-tools-static binary + the Alpine
# keyring (from the alpine-keys apk), extracted under <cache>/bootstrap/.
# The keyring lets apk verify the upstream APKINDEX signatures during the
# closure fetch (no --allow-untrusted anywhere).
mirror_bootstrap_ensure() {
    local bdir url base
    bdir="$(mirror_cache_root)/bootstrap"
    mkdir -p "$bdir"
    base="$(mirror_upstream)/$(mirror_release)/main/x86_64"
    local apk_apk="$bdir/apk-tools-static-${MIRROR_PIN_APK_TOOLS_STATIC_VERSION}.apk"
    local keys_apk="$bdir/alpine-keys-${MIRROR_PIN_ALPINE_KEYS_VERSION}.apk"
    if [[ ! -f "$apk_apk" ]]; then
        url="$base/apk-tools-static-${MIRROR_PIN_APK_TOOLS_STATIC_VERSION}.apk"
        echo "local-mirror: fetching $(basename "$apk_apk")" >&2
        _mirror_fetch "$apk_apk" "$url" || return 1
    fi
    if [[ ! -f "$keys_apk" ]]; then
        url="$base/alpine-keys-${MIRROR_PIN_ALPINE_KEYS_VERSION}.apk"
        echo "local-mirror: fetching $(basename "$keys_apk")" >&2
        _mirror_fetch "$keys_apk" "$url" || return 1
    fi
    local have
    have=$(_mirror_hash "$apk_apk")
    [[ "$have" == "$MIRROR_PIN_APK_TOOLS_STATIC_SHA256" ]] || {
        echo "local-mirror: apk-tools-static SHA MISMATCH: expected $MIRROR_PIN_APK_TOOLS_STATIC_SHA256 got $have" >&2
        return 1
    }
    have=$(_mirror_hash "$keys_apk")
    [[ "$have" == "$MIRROR_PIN_ALPINE_KEYS_SHA256" ]] || {
        echo "local-mirror: alpine-keys SHA MISMATCH: expected $MIRROR_PIN_ALPINE_KEYS_SHA256 got $have" >&2
        return 1
    }
    if [[ ! -x "$bdir/apk.static" ]]; then
        tar -xzf "$apk_apk" -C "$bdir" sbin/apk.static 2>/dev/null ||
            tar -xzf "$apk_apk" -C "$bdir" ./sbin/apk.static 2>/dev/null || {
            echo "local-mirror: cannot extract sbin/apk.static from $apk_apk" >&2
            return 1
        }
        mv "$bdir/sbin/apk.static" "$bdir/apk.static"
        rmdir "$bdir/sbin" 2>/dev/null || true
        chmod +x "$bdir/apk.static"
    fi
    if [[ ! -d "$bdir/keys" ]]; then
        mkdir -p "$bdir/keys"
        tar -xzf "$keys_apk" -C "$bdir/keys" etc/apk/keys 2>/dev/null || {
            echo "local-mirror: cannot extract etc/apk/keys from $keys_apk" >&2
            return 1
        }
    fi
    printf '%s\n' "$bdir"
}

# _mirror_index_namemap <component> <out-file> — (name version) pairs from the
# CACHED pinned index (line-based awk: portable across gawk/mawk/busybox).
_mirror_index_namemap() {
    local comp="$1" out="$2" index
    index="$(mirror_repo_dir "$comp")/APKINDEX.tar.gz"
    tar -xzOf "$index" APKINDEX 2>/dev/null | awk '
        /^P:/ { n = substr($0, 3) }
        /^V:/ { if (n != "") { print n, substr($0, 3); n = "" } }
    ' >"$out"
}

# mirror_closure_fetch — apk fetch --recursive from the UPSTREAM repos into a
# scratch spool, then classify each apk into main/community by (name, version)
# against the CACHED pinned indexes. Fail-closed on any unclassified apk
# (upstream moved between the index fetch and the closure fetch) or on any
# pinned package that came back unresolvable (renamed/vanished => re-pin).
mirror_closure_fetch() {
    local cdir bdir work spool root pkgs name
    cdir=$(mirror_cache_dir)
    bdir=$(mirror_bootstrap_ensure) || return 1
    work="$cdir/.work"
    spool="$work/spool"
    root="$work/root"
    rm -rf "$work"
    mkdir -p "$spool" "$root/etc/apk"

    pkgs=$(mirror_package_list)
    echo "local-mirror: resolving the closure of [$(echo "$pkgs" | tr '\n' ' ' | tr -s ' ')]" >&2
    if ! "$bdir/apk.static" --arch x86_64 --root "$root" \
            --keys-dir "$bdir/keys/etc/apk/keys" \
            --repository "$(mirror_upstream)/$(mirror_release)/main" \
            --repository "$(mirror_upstream)/$(mirror_release)/community" \
            fetch --recursive --output "$spool" $pkgs; then
        echo "local-mirror: apk fetch --recursive FAILED (a pinned package is unresolvable upstream — re-pin or fix mirror_package_list)" >&2
        rm -rf "$work"
        return 1
    fi

    _mirror_index_namemap main "$work/main.map"
    _mirror_index_namemap community "$work/community.map"
    local f b nver ver comp found=0 missing='' n_main=0 n_comm=0
    for f in "$spool"/*.apk; do
        b=$(basename "$f")
        nver=${b%.apk}
        # name = strip the trailing -<version>-<revision>; version = the rest
        name=${nver%-*-*}
        ver=${nver#"$name"-}
        comp=''
        if awk -v n="$name" -v v="$ver" '$1==n && $2==v { found=1 } END { exit !found }' "$work/main.map"; then
            comp=main
        elif awk -v n="$name" -v v="$ver" '$1==n && $2==v { found=1 } END { exit !found }' "$work/community.map"; then
            comp=community
        fi
        if [[ -z "$comp" ]]; then
            missing="$missing $nver"
            continue
        fi
        mkdir -p "$(mirror_repo_dir "$comp")"
        # shellcheck disable=SC2086  # deliberate single-move
        mv "$f" "$(mirror_repo_dir "$comp")/$b"
        found=$((found + 1))
    done
    # count per component for the report
    n_main=$(find "$(mirror_repo_dir main)" -maxdepth 1 -name '*.apk' 2>/dev/null | wc -l)
    n_comm=$(find "$(mirror_repo_dir community)" -maxdepth 1 -name '*.apk' 2>/dev/null | wc -l)
    rm -rf "$work"
    if [[ -n "$missing" ]]; then
        echo "local-mirror: CLOSURE/INDEX DRIFT — $missing resolved upstream but (name,version) is absent from the PINNED indexes:" >&2
        echo "  upstream moved between the index download and the closure fetch; re-pin the APKINDEX hashes and rebuild" >&2
        return 1
    fi
    echo "local-mirror: closure materialized: $found new apks (mirror now: main=$n_main community=$n_comm)" >&2
    return 0
}

# mirror_manifest_write — MANIFEST.sha256 (indexes + every apk, relative paths
# so `sha256sum --check` runs from the cache dir) + mirror.json provenance.
mirror_manifest_write() {
    local cdir
    cdir=$(mirror_cache_dir)
    {
        cd "$cdir" || return 1
        sha256sum main/x86_64/APKINDEX.tar.gz community/x86_64/APKINDEX.tar.gz
        find main/x86_64 community/x86_64 -name '*.apk' | sort | xargs sha256sum
    } >"$cdir/MANIFEST.sha256"
    local n_main n_comm
    n_main=$(find "$(mirror_repo_dir main)" -maxdepth 1 -name '*.apk' | wc -l)
    n_comm=$(find "$(mirror_repo_dir community)" -maxdepth 1 -name '*.apk' | wc -l)
    cat >"$cdir/mirror.json" <<JSON
{
  "schema_version": 1,
  "release": "$(mirror_release)",
  "upstream": "$(mirror_upstream)",
  "generated": "$(date -u +%Y-%m-%d)",
  "layout": "<release>/<component>/x86_64/APKINDEX.tar.gz + *.apk (upstream shape; inst_repo_lines' main/community twin resolves)",
  "package_list_basis": "alpine-base + lib/cmd/install.sh install_package_list + inst_live_tool_pairs union + topology union (e2fsprogs btrfs-progs bcache-tools)",
  "package_list_sha256": "$(mirror_package_list | tr ' ' '\n' | sort | sha256sum | cut -d' ' -f1)",
  "pins": {
    "apkindex_main_sha256": "$MIRROR_PIN_MAIN_APKINDEX_SHA256",
    "apkindex_community_sha256": "$MIRROR_PIN_COMMUNITY_APKINDEX_SHA256",
    "apk_tools_static": "${MIRROR_PIN_APK_TOOLS_STATIC_VERSION} $MIRROR_PIN_APK_TOOLS_STATIC_SHA256",
    "alpine_keys": "${MIRROR_PIN_ALPINE_KEYS_VERSION} $MIRROR_PIN_ALPINE_KEYS_SHA256"
  },
  "packages": {
    "main": $n_main,
    "community": $n_comm
  },
  "serving": "HOST loopback mirror_serve_start (busybox httpd / python3 http.server) reached via qemu slirp at 10.0.2.2; ALPINE_FDE_MIRROR=http://mirror.fde.internal:<port>/mirror/<release>/main"
}
JSON
}

# mirror_manifest_verify — rc 0 iff the manifest exists, every listed hash
# matches, AND every apk on disk is listed (no unmanifested strays).
mirror_manifest_verify() {
    local cdir
    cdir=$(mirror_cache_dir)
    [[ -f "$cdir/MANIFEST.sha256" && -f "$cdir/mirror.json" ]] || return 1
    (cd "$cdir" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1 || return 1
    local listed ondisk
    listed=$(grep -c '\.apk$' "$cdir/MANIFEST.sha256" || true)
    ondisk=$(find "$cdir/main/x86_64" "$cdir/community/x86_64" -name '*.apk' 2>/dev/null | wc -l)
    [[ "$listed" == "$ondisk" ]] || return 1
    return 0
}

# _mirror_index_drift_check — cached indexes vs the LIB pins (runs on EVERY
# mirror_ensure, including the cached no-op path: drift must be detectable
# without a rebuild). rc 1 = the cache is self-consistent but upstream moved
# past the pins (the cache itself is still the pinned snapshot — with
# ALPINE_FDE_MIRROR_ALLOW_DRIFT=1 this downgrades to a loud warning).
_mirror_index_drift_check() {
    local want have comp rc=0
    for comp in main community; do
        case "$comp" in
            main)      want="$MIRROR_PIN_MAIN_APKINDEX_SHA256" ;;
            community) want="$MIRROR_PIN_COMMUNITY_APKINDEX_SHA256" ;;
        esac
        have=$(_mirror_hash "$(mirror_repo_dir "$comp")/APKINDEX.tar.gz" 2>/dev/null) || have=''
        if [[ "$have" != "$want" ]]; then
            if [[ "${ALPINE_FDE_MIRROR_ALLOW_DRIFT:-0}" == "1" ]]; then
                echo "local-mirror: WARNING: cached $comp APKINDEX drifted from the lib pin (have ${have:-<none>}, want $want) — continuing (ALPINE_FDE_MIRROR_ALLOW_DRIFT=1)" >&2
            else
                echo "local-mirror: DRIFT: cached $comp APKINDEX != lib pin (have ${have:-<none>}, want $want)" >&2
                rc=1
            fi
        fi
    done
    return "$rc"
}

# _mirror_list_basis_matches — rc 0 iff mirror.json's recorded
# package_list_sha256 equals the CURRENT derivation. The manifest alone can
# NOT detect a derivation change (it covers exactly what was fetched — a
# smaller, older closure verifies perfectly), which is how the cache kept
# missing the live tool set after install.sh's list grew (boot-lane finding
# #4 tail). rc 1 with a loud reason = rebuild required.
_mirror_list_basis_matches() {
    local cdir want have
    cdir=$(mirror_cache_dir)
    want=$(mirror_package_list | tr ' ' '\n' | sort | sha256sum | cut -d' ' -f1)
    have=$(jq -r '.package_list_sha256 // empty' "$cdir/mirror.json" 2>/dev/null) || have=''
    if [[ -z "$have" ]]; then
        echo "local-mirror: mirror.json records no package_list_sha256 (pre-basis cache) — rebuilding" >&2
        return 1
    fi
    if [[ "$have" != "$want" ]]; then
        echo "local-mirror: closure derivation CHANGED (package_list_sha256 $have -> $want) — rebuilding" >&2
        return 1
    fi
    return 0
}

# mirror_ensure — the public entry point. Second call with an intact cache is
# a NO-OP (manifest verify + index drift check only); a missing/tampered
# cache triggers a full rebuild under a cache-wide lock (concurrent lanes
# serialize; a reader either sees the old complete generation or the new one
# — mirrors s00b's staging+publish discipline).
mirror_ensure() {
    local cdir
    cdir=$(mirror_cache_dir)
    mkdir -p "$cdir"
    if mirror_manifest_verify && _mirror_list_basis_matches; then
        echo "local-mirror: cache verified (no-op): $cdir ($(grep -c '\.apk$' "$cdir/MANIFEST.sha256") apks, release $(mirror_release))" >&2
        _mirror_index_drift_check || {
            [[ "${ALPINE_FDE_MIRROR_ALLOW_DRIFT:-0}" == "1" ]] && return 0
            echo "local-mirror: refusing the cached snapshot as a pin source (drift above); set ALPINE_FDE_MIRROR_ALLOW_DRIFT=1 to accept the existing cache anyway" >&2
            return 1
        }
        return 0
    fi
    echo "local-mirror: cache missing/incomplete/unmanifested — rebuilding $cdir" >&2
    (
        flock -x 9
        # double-checked under the lock: a concurrent builder may have won
        if mirror_manifest_verify && _mirror_list_basis_matches; then
            echo "local-mirror: cache appeared under the lock (another lane built it) — no-op" >&2
            exit 0
        fi
        mirror_index_ensure main || exit 1
        mirror_index_ensure community || exit 1
        mirror_closure_fetch || exit 1
        mirror_manifest_write || exit 1
        mirror_manifest_verify || { echo "local-mirror: rebuilt cache failed manifest verification" >&2; exit 1; }
        echo "local-mirror: mirror built: $cdir (release $(mirror_release))" >&2
        exit 0
    ) 9>"$cdir/.lock"
}

# --- serving -------------------------------------------------------------------------
# mirror_serve_start <port> [docroot] — HOST loopback httpd (the OPTIONAL
# transfer channel; the canary serves the mirror guest-locally off the vfat
# disk instead — see the header). Uses busybox httpd when present, else
# python3 http.server. PID in <docroot>/.httpd.pid.
mirror_serve_start() {
    # NB: one assignment per local WORD that references a sibling — `local
    # a=x b=$a/y` expands ALL words before ANY assignment sticks, so $docroot
    # was unbound here under set -u (fatal to the caller; boot-lane finding).
    local port="${1:-}" docroot="${2:-$(mirror_cache_root)}"
    local pidfile="$docroot/.httpd.pid"
    mkdir -p "$docroot"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null; then
        return 0   # already serving
    fi
    # boot-lane finding #12: spawn INSIDE a job-control-free ( ) subshell (the
    # swtpm_start idiom). Under a set -m caller, bash makes a background job a
    # process-group leader — setsid(2) fails and util-linux setsid auto-forks,
    # so the recorded $! (the setsid parent) died instantly and the pidfile
    # held a DEAD pid: mirror_serve_stop killed nothing and the httpd leaked
    # into the next run's port.
    (
        if command -v busybox >/dev/null 2>&1 && busybox httpd --help >/dev/null 2>&1; then
            setsid busybox httpd -f -p "127.0.0.1:$port" -h "$docroot" &
        else
            setsid python3 -m http.server "$port" --bind 127.0.0.1 --directory "$docroot" >/dev/null 2>&1 &
        fi
        echo $! >"$pidfile"
    )
    sleep 1
    kill -0 "$(cat "$pidfile")" 2>/dev/null || {
        echo "local-mirror: httpd did not stay up on 127.0.0.1:$port" >&2
        return 1
    }
    echo "local-mirror: serving $docroot on http://127.0.0.1:$port (pid $(cat "$pidfile"))" >&2
    return 0
}

mirror_serve_stop() {
    local docroot="${1:-$(mirror_cache_root)}"
    local pidfile="$docroot/.httpd.pid" pid
    [[ -f "$pidfile" ]] || return 0
    pid=$(cat "$pidfile" 2>/dev/null) || pid=""
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    rm -f "$pidfile"
    return 0
}

# --- ISO (download once, SHA-pinned, fail-closed) -------------------------------------
iso_ensure() {
    local path want have
    path=$(iso_path)
    mkdir -p "$(mirror_iso_cache_dir)"
    want=$(iso_expected_sha256)
    if [[ -f "$path" ]]; then
        have=$(_mirror_hash "$path")
        if [[ "$have" == "$want" ]]; then
            return 0
        fi
        echo "local-mirror: cached ISO hash mismatch — re-downloading" >&2
        rm -f "$path"
    fi
    echo "local-mirror: fetching $(iso_filename) ($(iso_url))" >&2
    _mirror_fetch "$path" "$(iso_url)" || return 1
    have=$(_mirror_hash "$path")
    if [[ "$have" != "$want" ]]; then
        echo "local-mirror: ISO SHA256 MISMATCH: expected $want got $have" >&2
        echo "  (CI pinning its own artifact: export ALPINE_FDE_ISO_SHA256=<sha256 of your $(iso_filename)>)" >&2
        rm -f "$path"
        return 1
    fi
    return 0
}
