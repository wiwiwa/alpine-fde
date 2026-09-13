#!/usr/bin/env bash
# tests/lib/rootfs-fixture.sh — pinned Debian (trixie) artifact cache for the
# Debian FDE e2e harness (Wave 1 agent C).
#
# Every guest-side binary in the harness UKI comes from the SHA256-pinned debs
# below + the pinned Debian cloud rootfs tarball (used by Wave 2 scenarios to
# populate the LUKS image in-guest). Nothing is "apt-get installed" at test
# time: the cache IS the rootfs fixture.
#
# Usage (source, then):
#   rootfs_cache_dir                      -> print the cache dir (tests/.cache)
#   rootfs_ensure <cache-name>            -> download+verify if absent/stale
#   rootfs_ensure_all                     -> fetch every pinned artifact
#   rootfs_deb_extract <cache-name> <dest>-> ar x + tar a deb into <dest>
#   rootfs_tarball_extract <cache-name> <dest>
#
# Pin provenance (empirical, this sandbox):
#   * systemd-cryptsetup / libsystemd-shared debs: same bytes as the debs
#     hash-pinned in tests/sentinels-257.13.txt (the sentinel pin of record).
#   * debian-13-generic-amd64.tar.xz: SHA512 verified against upstream
#     SHA512SUMS of https://cloud.debian.org/images/cloud/trixie/latest/
#   * all others: sha256 computed at pin time from deb.debian.org's
#     dists/trixie index filenames (see docs in tests/e2e/README.md).
#
# NOTE (task-spec deviation, documented): the task suggested
# "debian-13-generic-amd64-root.tar.xz" — that filename does not exist in the
# trixie/latest listing; the actual artifact is "debian-13-generic-amd64.tar.xz".

if [[ -n "${_DEBIAN_FDE_ROOTFS_FIXTURE_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_ROOTFS_FIXTURE_SOURCED=1

ROOTFS_CACHE_DIR="${DEBIAN_FDE_CACHE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.cache}"
mkdir -p "$ROOTFS_CACHE_DIR"

_DEB_BASE="http://deb.debian.org/debian"
# Pin-of-record discipline (§3.1): dated upstream dir, never the moving `latest`
# symlink — latest/ drifted under us once already (20260914 build ≠ pinned bytes).
_CLOUD_BASE="https://cloud.debian.org/images/cloud/trixie"

# cache-name <TAB> sha256 <TAB> url
_ROOTFS_PINS="
busybox-static_1.37.0_amd64.deb	598a3fd92bdafc34cd81196b2952ad36e910e47a4ecf162f8ce5e8e262598e53	$_DEB_BASE/pool/main/b/busybox/busybox-static_1.37.0-6+b9_amd64.deb
systemd_257.13_amd64.deb	ee81302a1d5b7434762b6e784a572854d4b6cf6235e33e2d104ad4e1cae71ab4	$_DEB_BASE/pool/main/s/systemd/systemd_257.13-1~deb13u1_amd64.deb
systemd-cryptsetup_257.13_amd64.deb	08ec2063867d0e5861b01340f9705dfe0ef4c4612dc5bdfeae29e5d8e7370034	$_DEB_BASE/pool/main/s/systemd/systemd-cryptsetup_257.13-1~deb13u1_amd64.deb
libsystemd-shared_257.13_amd64.deb	2d349824e57f88507e2a33360610d8afc143a4ad5e80ee4bf8f37b826d6f37f9	$_DEB_BASE/pool/main/s/systemd/libsystemd-shared_257.13-1~deb13u1_amd64.deb
linux-image-6.12.107+deb13-amd64-unsigned.deb	7d13cd82a1d377e40826c313f5dbbdb2edf1b48c713a375e4cfe5e207749cb4e	$_DEB_BASE/pool/main/l/linux/linux-image-6.12.107+deb13-amd64-unsigned_6.12.107-1_amd64.deb
cryptsetup-bin.deb	b77b192cf1c35f96da02134300bb227ab92c49eec2444268049fa1ce84fb9bc7	$_DEB_BASE/pool/main/c/cryptsetup/cryptsetup-bin_2.7.5-2_amd64.deb
libcryptsetup12.deb	84f6596296c346c1c8f6bb16b0d4d485215b7a23a23ff21e9c28e35822d45a7b	$_DEB_BASE/pool/main/c/cryptsetup/libcryptsetup12_2.7.5-2_amd64.deb
libargon2-1.deb	a54a6640be69c29c1e43b14ee464484a6f20e33fe73200c02949cfeb03228547	$_DEB_BASE/pool/main/a/argon2/libargon2-1_0~20190702+dfsg-4+b2_amd64.deb
libdevmapper.deb	e924e0df8823987f271b7d3a375dc2f8adcd76db66f09d0273043c885edb0af0	$_DEB_BASE/pool/main/l/lvm2/libdevmapper1.02.1_1.02.205-2_amd64.deb
libjson-c5.deb	4fbd5fb4d54c626f05d68abf38a31533fbf1bf4a87068696abe041ee9c974fe0	$_DEB_BASE/pool/main/j/json-c/libjson-c5_0.18+ds-1_amd64.deb
libpopt0.deb	07f649b706852af937654295697dcfc7858f3295718ec18681dce1704663e4f2	$_DEB_BASE/pool/main/p/popt/libpopt0_1.19+dfsg-2_amd64.deb
libssl3t64.deb	916f7f40b34a06e6ebfaefcdab331bff458328411da672598f126a760472467d	$_DEB_BASE/pool/main/o/openssl/libssl3t64_3.5.7-1~deb13u2_amd64.deb
libc6.deb	967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9	$_DEB_BASE/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb
libtss2-esys.deb	87c0747c54e12be29c149145830385f5c6816b0fd962391858d63d70c921859e	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-esys-3.0.2-0t64_4.1.3-1.2_amd64.deb
libtss2-mu.deb	b7e1b9a05623f304aa82b4a577f8948e967f9212e5871c76bd88dd8e96b3e4ea	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-mu-4.0.1-0t64_4.1.3-1.2_amd64.deb
libtss2-rc.deb	e04baea4ffaf6f49011dd42d34b19cfd9f81abe518c24357b1ffa72e7ca74b84	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-rc0t64_4.1.3-1.2_amd64.deb
libtss2-sys.deb	ffd806325106fb22cf479e65c6c74ef6c5db598a943dfd3b6a38b1edbdd55e99	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-sys1t64_4.1.3-1.2_amd64.deb
libtss2-tctildr.deb	90a301083c38ae92c16fab7d5bfc2d1f3874a09a33f500d289308bdbb12e135d	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-tctildr0t64_4.1.3-1.2_amd64.deb
libtss2-tcti-device.deb	e2c07f7258f52b611edb96945049dfc5dd0f066b9464cd2338716d73f78fc495	$_DEB_BASE/pool/main/t/tpm2-tss/libtss2-tcti-device0t64_4.1.3-1.2_amd64.deb
libacl1.deb	08074f01e384bc07c0c2d79a58cf4a6523f71cf75d1808101c79617656c9a39d	$_DEB_BASE/pool/main/a/acl/libacl1_2.3.2-2+b1_amd64.deb
libblkid1.deb	81535f3c2c0efc732965907c8749103a0a26377c761622c9ce39b4c92dcde52f	$_DEB_BASE/pool/main/u/util-linux/libblkid1_2.41.5-0+deb13u1_amd64.deb
libmount1.deb	6d00f45f2e80e078e906e3eedecd3ba6913e39fef49bff361ee583f17f00ec05	$_DEB_BASE/pool/main/u/util-linux/libmount1_2.41.5-0+deb13u1_amd64.deb
libuuid1.deb	c1bf4c4c3ff48c57fabf93307dfb56996b60cfa33927afc4158b5db36fb2721e	$_DEB_BASE/pool/main/u/util-linux/libuuid1_2.41.5-0+deb13u1_amd64.deb
libcap2.deb	89fc4d34fc7a28ad6f0fcd0c561ab253b9dedf6f77f5a000b47c276c8295bf67	$_DEB_BASE/pool/main/libc/libcap2/libcap2_2.75-10+deb13u1+b3_amd64.deb
libcap-ng0.deb	20a9e4b0619a3eb2566338223bed135dde5a601eaa2f8fdd5f20b94506addcac	$_DEB_BASE/pool/main/libc/libcap-ng/libcap-ng0_0.8.5-4+b1_amd64.deb
libcrypt1.deb	0ebc144d662e3197982d1bf3a7b8b35ca845e54c68811de0328b1f0d7c67585c	$_DEB_BASE/pool/main/libx/libxcrypt/libcrypt1_4.4.38-1_amd64.deb
libpam0g.deb	4f5bde27d8df2de6ea8990319b42d9974f56a3ba9907ce7296fd0f8964fc9fb1	$_DEB_BASE/pool/main/p/pam/libpam0g_1.7.0-5_amd64.deb
libseccomp2.deb	89d5138e05fb6a86b9afd8b54dc0fb4b14f4c27c05e6c5f767c2132bdf808531	$_DEB_BASE/pool/main/libs/libseccomp/libseccomp2_2.6.0-2_amd64.deb
libselinux1.deb	68bb8d32bd8d6d7d2f5952a169db03d1484b46ae1e52abccdec42a19dccea5d5	$_DEB_BASE/pool/main/libs/libselinux/libselinux1_3.8.1-1_amd64.deb
libsepol2.deb	3595d2d3a6d24695e7953f4f00cdfe6974c9242d9a8dfee8998e77fbf7b2ba09	$_DEB_BASE/pool/main/libs/libsepol/libsepol2_3.8.1-1_amd64.deb
libpcre2-8-0.deb	1252b96a5bc44bb5db982bef8eb18e54f5047cede2aff641bce4f8e1edb91c3e	$_DEB_BASE/pool/main/p/pcre2/libpcre2-8-0_10.46-1~deb13u2_amd64.deb
libudev1.deb	5d41c284f5a93b05bc7d648b61a02dd2bb9ff05b2261ad1a8b7d96044a0cfa88	$_DEB_BASE/pool/main/s/systemd/libudev1_257.13-1~deb13u1_amd64.deb
libz1.deb	015be740d6236ad114582dea500c1d907f29e16d6db00566ca32fb68d71ac90d	$_DEB_BASE/pool/main/z/zlib/zlib1g_1.3.dfsg+really1.3.1-1+b1_amd64.deb
libzstd1.deb	2f6a2aeacfc925eba8b00ac9139bc4bfccf8cacb09eb93de067074b26948eef9	$_DEB_BASE/pool/main/libz/libzstd/libzstd1_1.5.7+dfsg-1_amd64.deb
libaudit1.deb	3d1dd3f031a56f01b747e2acc0e14575212580e6fa63d800c44cb0a31f1edfd7	$_DEB_BASE/pool/main/a/audit/libaudit1_4.0.2-2+deb13u1_amd64.deb
debian-13-generic-amd64.tar.xz	700067e09ac7059f556eb8cf041575828b4f9a3c35d1544463fb600c08c70bf1	$_CLOUD_BASE/20260831-2587/debian-13-generic-amd64-20260831-2587.tar.xz
"

# rootfs_cache_dir — print the cache directory
rootfs_cache_dir() {
    printf '%s\n' "$ROOTFS_CACHE_DIR"
}

# _rootfs_pin_lookup <cache-name> — set _PIN_SHA and _PIN_URL
_rootfs_pin_lookup() {
    _PIN_SHA=""
    _PIN_URL=""
    local line name sha url
    while IFS=$'\t' read -r name sha url; do
        [[ -z "$name" ]] && continue
        if [[ "$name" == "$1" ]]; then
            _PIN_SHA="$sha"
            _PIN_URL="$url"
            return 0
        fi
    done <<<"$_ROOTFS_PINS"
    echo "rootfs-fixture: no pin for artifact: $1" >&2
    return 64
}

# rootfs_ensure <cache-name> — download + verify if absent or hash-mismatched.
# A partial download goes to a UNIQUE temp file first (concurrent invocations
# must never interleave into one shared .part path — MD-07); a hash mismatch
# is fatal (fail-closed: never build a UKI from unverified bytes). The curl
# bounds are the harness default (CR-01: a mid-body stall must time out, not
# hang — the 8h-hang window).
rootfs_ensure() {
    local name="$1" path="$ROOTFS_CACHE_DIR/$1"
    _rootfs_pin_lookup "$name" || return $?
    if [[ -f "$path" ]]; then
        if [[ "$(sha256sum "$path" | awk '{print $1}')" == "$_PIN_SHA" ]]; then
            return 0
        fi
        echo "rootfs-fixture: $name hash mismatch — re-downloading" >&2
        rm -f "$path"
    fi
    local tmp
    tmp=$(mktemp "$ROOTFS_CACHE_DIR/.part.XXXXXX") || return 1
    echo "rootfs-fixture: fetching $name" >&2
    # CR-01: connect/stall/total bounds — -f alone does not cover a stalled body
    if ! curl -fsSL --connect-timeout 15 --speed-limit 1024 --speed-time 30 --max-time 1800 \
            -o "$tmp" "$_PIN_URL"; then
        rm -f "$tmp"
        echo "rootfs-fixture: download failed: $_PIN_URL" >&2
        return 1
    fi
    local got
    got=$(sha256sum "$tmp" | awk '{print $1}')
    if [[ "$got" != "$_PIN_SHA" ]]; then
        echo "rootfs-fixture: sha256 mismatch for $name: expected $_PIN_SHA got $got" >&2
        rm -f "$tmp"
        return 1
    fi
    mv "$tmp" "$path"
    return 0
}

rootfs_ensure_all() {
    local line name
    while IFS=$'\t' read -r name _sha _url; do
        [[ -z "$name" ]] && continue
        rootfs_ensure "$name" || return $?
    done <<<"$_ROOTFS_PINS"
}

# rootfs_deb_extract <cache-name> <dest-dir> — extract a pinned deb (ar + tar).
rootfs_deb_extract() {
    local name="$1" dest="$2" tmp
    rootfs_ensure "$name" || return $?
    tmp=$(mktemp -d)
    (cd "$tmp" && ar x "$ROOTFS_CACHE_DIR/$name" && tar -xf data.tar.* -C "$dest") || {
        rm -rf "$tmp"
        echo "rootfs-fixture: deb extraction failed: $name" >&2
        return 1
    }
    rm -rf "$tmp"
    return 0
}

# rootfs_tarball_extract <cache-name> <dest-dir> — extract the pinned rootfs
# tarball (Debian cloud "root" tarball = an unpacked root tree, no /boot).
rootfs_tarball_extract() {
    local name="$1" dest="$2"
    rootfs_ensure "$name" || return $?
    mkdir -p "$dest"
    tar -xf "$ROOTFS_CACHE_DIR/$name" -C "$dest" || {
        echo "rootfs-fixture: tarball extraction failed: $name" >&2
        return 1
    }
    return 0
}
