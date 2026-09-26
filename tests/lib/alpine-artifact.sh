#!/usr/bin/env bash
# tests/lib/alpine-artifact.sh — pinned Alpine minirootfs artifact cache for
# the e2e harness (docs/Architecture.md §12: "Guest userspace is a pinned
# Alpine rootfs artifact (downloaded once, SHA256-pinned)"; ADR-12 platform
# baseline). Replaces the Debian cloud-tarball pin (G-E1).
#
# The cache IS the rootfs fixture: nothing is "apk installed" at test time.
#
# Usage (source, then):
#   alpine_artifact_cache_dir   -> print the cache dir (tests/e2e/.cache)
#   alpine_artifact_path        -> print the pinned artifact's cached path
#   alpine_artifact_sha256      -> print the pinned SHA256
#   alpine_artifact_ensure      -> download once + SHA256 verify (fail-closed)
#   alpine_artifact_extract <dest> -> verify, then tar-extract into <dest>
#
# Pin provenance (byte-verified in this sandbox, 2026-09-21):
#   * URL/version taken from the release index
#     https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/latest-releases.yaml
#     (flavor alpine-minirootfs, version 3.24.2, dated 2026-09-17).
#   * SHA256 recorded from that SAME index entry and re-verified by hashing
#     the downloaded bytes (curl -o tmp -> sha256sum -> compare -> atomic mv).
#   * A mismatch FAILS CLOSED (exit nonzero, nothing exported, nothing
#     extracted): unverified bytes must never become a UKI payload.

if [[ -n "${_ALPINE_FDE_ALPINE_ARTIFACT_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_ALPINE_ARTIFACT_SOURCED=1

_ALPINE_ARTIFACT_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Download-once cache: tests/e2e/.cache (gitignored via the repo's `.*` rule);
# ALPINE_FDE_CACHE_DIR (or ALPINE_FDE_ARTIFACT_CACHE_DIR) relocates it.
# shellcheck disable=SC2034  # caller-facing seam (sibling libs + suites read it)
ALPINE_ARTIFACT_CACHE_DIR="${ALPINE_FDE_ARTIFACT_CACHE_DIR:-${ALPINE_FDE_CACHE_DIR:-$(cd "$_ALPINE_ARTIFACT_HERE/../e2e" && pwd)/.cache}}"
mkdir -p "$ALPINE_ARTIFACT_CACHE_DIR"

# --- the pin (ADR-12/§12) ---------------------------------------------------------
ALPINE_MINI_ROOTFS_VERSION="3.24.2"
ALPINE_MINI_ROOTFS_ARCH="x86_64"
_ALPINE_CDN="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64"
ALPINE_MINI_ROOTFS_URL="$_ALPINE_CDN/alpine-minirootfs-${ALPINE_MINI_ROOTFS_VERSION}-${ALPINE_MINI_ROOTFS_ARCH}.tar.gz"
ALPINE_MINI_ROOTFS_SHA256="c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677"
# shellcheck disable=SC2034  # pinned size constant (consumed by suites/helpers)
ALPINE_MINI_ROOTFS_BYTES=3701382

alpine_artifact_cache_dir() { printf '%s\n' "$ALPINE_ARTIFACT_CACHE_DIR"; }
alpine_artifact_path() {
    printf '%s\n' "$ALPINE_ARTIFACT_CACHE_DIR/alpine-minirootfs-${ALPINE_MINI_ROOTFS_VERSION}-${ALPINE_MINI_ROOTFS_ARCH}.tar.gz"
}
alpine_artifact_sha256() { printf '%s\n' "$ALPINE_MINI_ROOTFS_SHA256"; }

# alpine_artifact_ensure — download once + SHA256 verify. Fail-closed: a hash
# mismatch removes the temp file and returns nonzero; the cached artifact is
# only ever the byte-verified pin. curl bounds match the harness default
# (CR-01: a mid-body stall must time out, never hang).
alpine_artifact_ensure() {
    local path sha tmp
    path=$(alpine_artifact_path)
    if [[ -f "$path" ]]; then
        sha=$(sha256sum "$path" | awk '{print $1}')
        if [[ "$sha" == "$ALPINE_MINI_ROOTFS_SHA256" ]]; then
            return 0
        fi
        echo "alpine-artifact: cached artifact hash mismatch — re-downloading" >&2
        rm -f "$path"
    fi
    tmp=$(mktemp "$ALPINE_ARTIFACT_CACHE_DIR/.alpine.part.XXXXXX") || return 1
    echo "alpine-artifact: fetching alpine-minirootfs-${ALPINE_MINI_ROOTFS_VERSION}-${ALPINE_MINI_ROOTFS_ARCH}" >&2
    if ! curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 30 --max-time 1800 \
            -o "$tmp" "$ALPINE_MINI_ROOTFS_URL"; then
        rm -f "$tmp"
        echo "alpine-artifact: download failed: $ALPINE_MINI_ROOTFS_URL" >&2
        return 1
    fi
    sha=$(sha256sum "$tmp" | awk '{print $1}')
    if [[ "$sha" != "$ALPINE_MINI_ROOTFS_SHA256" ]]; then
        echo "alpine-artifact: sha256 MISMATCH: expected $ALPINE_MINI_ROOTFS_SHA256 got $sha" >&2
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$path"
    return 0
}

# alpine_artifact_extract <dest-dir> — hash-verify the cached artifact, then
# extract. Never extracts unverified bytes.
alpine_artifact_extract() {
    local dest="$1" path sha
    alpine_artifact_ensure || return $?
    path=$(alpine_artifact_path)
    sha=$(sha256sum "$path" | awk '{print $1}')
    if [[ "$sha" != "$ALPINE_MINI_ROOTFS_SHA256" ]]; then
        echo "alpine-artifact: refusing extraction — cached hash mismatch ($sha)" >&2
        return 1
    fi
    mkdir -p "$dest"
    tar -xzf "$path" -C "$dest" || {
        echo "alpine-artifact: extraction failed: $path" >&2
        return 1
    }
    return 0
}
