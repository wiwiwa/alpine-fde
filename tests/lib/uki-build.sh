#!/usr/bin/env bash
# tests/lib/uki-build.sh — minimal harness UKI builder for the FDE e2e
# harness (Wave 1 agent C).
#
# Builds a Unified Kernel Image whose initramfs is a small busybox-based
# harness that:
#   * mounts proc/sys/dev(run,tmpfs), loads the disk/dm modules,
#   * waits for /dev/tpmrm0 and prints `debian-fde-pcr sha256:<idx>=<hex>`
#     for PCRs 0, 7, 11 (machine-readable, consumed by scenarios),
#   * enrolls a systemd-tpm2 token IN-GUEST on an unenrolled LUKS volume
#     (the §12 S-00b "enroll from the guest" pattern, miniaturized),
#   * runs the real systemd-cryptsetup (trixie 257.13, from the pinned deb)
#     with the signed-PCR policy (tpm2-signature= + .pcrsig),
#   * prints `debian-fde: UNSEALED` / `debian-fde: PROMPT-FAILED`, powers off.
#
# GUEST ROOTFS (G-E1, ADR-12/§12): the S-00 payload populated into the LUKS
# image is the SHA256-pinned ALPINE minirootfs artifact
# (tests/lib/alpine-artifact.sh) + the alpine-fde tooling tree + host-closure
# stub binaries (see rootfs_payload_image) — not the Debian cloud image. The
# INITRD's own unlock machinery below still comes from the pinned Debian debs
# (the harness-contract unlock path; its console sentinels live in
# tests/sentinels-257.13.txt until the mkinitfs-hook unlock lands here).
#
# Provenance decisions (see tests/e2e/README.md for the full write-up):
#   * Kernel: pinned Debian trixie linux-image deb (vmlinuz + module tree).
#     The host /boot/vmlinuz-linux-lts was REJECTED: this host ships it
#     without a matching /usr/lib/modules tree (running kernel is -virt),
#     so no virtio_blk/dm-crypt closure exists for it.
#   * Guest userspace: binaries + libraries copied from the pinned trixie
#     debs (systemd-cryptsetup, libsystemd-shared, busybox-static, ...),
#     closure-resolved with objdump NEEDED walking, laid out in the deb's
#     natural paths with Debian's own ld.so + glibc.
#   * tpm2_pcrread: copied from the HOST with its ldd closure, isolated under
#     /opt/tpm and invoked via its own ld-linux (avoids clashing the host
#     glibc closure with the Debian one).
#   * .pcrsig: ukify build signs the enter-initrd prediction with the release
#     key (--pcr-private-key/--pcr-public-key/--pcr-banks=sha256); the JSON is
#     extracted from the .pcrsig PE section (objcopy) and delivered to the
#     guest on a small raw payload DRIVE (/dev/vdc), not inside the initramfs.
#     (Chicken-and-egg: the stub's PCR 11 prediction covers the .initrd bytes;
#     embedding the signature that covers those bytes would change them.
#     The .pcrsig/.pcrpkey PE sections are excluded from measurement upstream,
#     and a payload drive keeps the measurement self-consistent.)
#
# WAVE-2 UNLOCK RESOLUTION (empirically pinned, see tests/e2e/README.md):
# ukify's `.pcrsig` predicts PCR 11 as stub-section extends PLUS the
# `enter-initrd` PHASE WORD (H("enter-initrd")) that a production initrd
# extends via `systemd-pcrextend enter-initrd` (systemd-pcrphase-initrd.
# service, Before=cryptsetup.target) before unlocking. The harness initrd
# therefore runs the real 257.13 systemd-pcrextend (from the pinned deb;
# tpm2_pcrextend as fallback) BEFORE the unlock attempt — without it, the
# consumer's find_signature() can never match the .pcrsig `pol` entries:
#   observed-session pol = H(0|CC_PolicyPCR|TPML{sha256,pcr11}|H(pcr11))
# over the PCR value WITHOUT the phase word, while the signed entry covers
# the value WITH it (calibrated against swtpm + guest evidence; every 257/261
# prediction formula is otherwise identical, so the version-skew hypothesis
# is dead). The unlock line also passes a deliberately WRONG key file as the
# fallback credential: on the happy boot the token unlocks at attempt 0 and
# the key file is never read; on tampered boots (PCR 7 drift) both fail and
# with tries=2 systemd-cryptsetup hits "Too many attempts to activate;
# giving up." — no ask-password agent needed (there is none in this initrd
# and the fallback prompt cannot read the serial console).

if [[ -n "${_DEBIAN_FDE_UKI_BUILD_SOURCED:-}" ]]; then
    return 0
fi
_DEBIAN_FDE_UKI_BUILD_SOURCED=1

_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
_UKI_REPO_ROOT=$(cd "$_HERE/../.." && pwd)
# shellcheck source=lib/rootfs-fixture.sh
source "$_HERE/rootfs-fixture.sh"
# shellcheck source=lib/alpine-artifact.sh
source "$_HERE/alpine-artifact.sh"
# shellcheck source=lib/disk-fixture.sh
source "$_HERE/disk-fixture.sh"
# shellcheck source=../../lib/policy.sh
source "$_UKI_REPO_ROOT/lib/common.sh"
source "$_UKI_REPO_ROOT/lib/policy.sh"

UKI_KERNEL_RELEASE="6.12.107+deb13-amd64"
UKI_KERNEL_CMDLINE="console=ttyS0,115200 rdinit=/init loglevel=7"
# G-HW3: the btrfs-default BASE matrix closure. Dependency-ordered for the
# bare-insmod loop in /init (no modprobe): btrfs needs xor + raid6_pq +
# libcrc32c (already listed above); zstd (crypto scomp, btrfs compression)
# and bcache (§8.2 topology driver, no deps) load standalone. Every entry is
# verified present as a .ko.xz in the pinned kernel deb AND packed into the
# initrd (tests/unit/e2e_infra_smoke.sh asserts both).
UKI_MODULES="gf128mul cryptd crypto_simd aesni-intel aes_x86_64 xts dm-mod dm-crypt crc16 mbcache crc32c_generic libcrc32c jbd2 ext4 virtio_blk efivarfs zstd xor raid6_pq btrfs bcache"

# _uki_closure_check <root> <binary>... — objdump NEEDED walk; echo MISSING lines
_uki_closure_check() {
    local root="$1"; shift
    declare -A seen=()
    local queue=("$@") f lib hit
    while ((${#queue[@]} > 0)); do
        f="${queue[0]}"; queue=("${queue[@]:1}")
        [[ -n "${seen[$f]:-}" ]] && continue
        seen[$f]=1
        while IFS= read -r lib; do
            [[ -z "$lib" ]] && continue
            [[ -n "${seen[$lib]:-}" ]] && continue
            hit=$(find "$root" -name "$lib" 2>/dev/null | head -1)
            if [[ -n "$hit" ]]; then
                queue+=("$hit")
            else
                echo "MISSING: $lib (needed by $f)"
            fi
        done < <(objdump -p "$f" 2>/dev/null | awk '/NEEDED/{print $2}')
    done
    return 0
}

# uki_guest_tree <dest> — assemble the Debian guest userspace from pinned debs.
# Idempotent; asserts the dynamic-linker closure at the end (fail-closed).
uki_guest_tree() {
    local dest="$1"
    if [[ -f "$dest/.closure-ok" ]]; then
        return 0
    fi
    mkdir -p "$dest"
    local d
    # systemd_257.13 provides /usr/lib/systemd/systemd-pcrextend (the real
    # enter-initrd phase-word extension a production initrd runs before
    # unlocking — see the WAVE-2 UNLOCK RESOLUTION note above). btrfs-progs
    # 6.14 (G-HW5): mkfs.btrfs + the subvolume tooling for the §9.1 Btrfs
    # installer stage (lib closure: only liblzo2 is new — pinned above).
    # udev + dmsetup (G-HW5): systemd-udevd/udevadm + the dm rules so the
    # LUKS attach is udev-registered (the §9.1 fstab UUID= submounts resolve
    # only via the udev db; same pinned systemd version).
    for d in systemd-cryptsetup_257.13_amd64.deb libsystemd-shared_257.13_amd64.deb \
             systemd_257.13_amd64.deb busybox-static_1.37.0_amd64.deb cryptsetup-bin.deb \
             btrfs-progs_6.14_amd64.deb udev_257.13_amd64.deb dmsetup.deb; do
        rootfs_deb_extract "$d" "$dest" || return 1
    done
    for d in libc6.deb libssl3t64.deb libargon2-1.deb libcryptsetup12.deb libdevmapper.deb libjson-c5.deb \
             libpopt0.deb libtss2-esys.deb libtss2-mu.deb libtss2-rc.deb libtss2-sys.deb \
             libtss2-tctildr.deb libtss2-tcti-device.deb libacl1.deb libblkid1.deb \
             libmount1.deb libuuid1.deb libcap2.deb libcap-ng0.deb libcrypt1.deb \
             libpam0g.deb libseccomp2.deb libselinux1.deb libsepol2.deb libpcre2-8-0.deb \
             libudev1.deb libz1.deb libzstd1.deb libaudit1.deb liblzo2-2.deb; do
        rootfs_deb_extract "$d" "$dest" || return 1
    done
    # strip non-runtime payload (docs/man/completions) — keeps the initramfs
    # (and thus boot time under TCG) small
    rm -rf "$dest"/usr/share/doc "$dest"/usr/share/man "$dest"/usr/share/lintian \
           "$dest"/usr/share/bug "$dest"/usr/share/bash-completion "$dest"/usr/share/zsh \
           "$dest"/usr/share/fish "$dest"/etc/dhcp "$dest"/usr/lib/systemd/system \
           2>/dev/null
    find "$dest" -name '*.mo' -delete 2>/dev/null
    # btrfs-progs trim: /init needs only the `btrfs` multitool (subvolume
    # create/list) + mkfs.btrfs; the recovery/editor helpers (~2.8 MiB) would
    # bloat the initramfs for nothing. udev trim: the hwdb sources (~2 MiB)
    # are only consulted for net/usb device naming — nothing this initrd
    # attaches needs them.
    rm -f "$dest/usr/bin/btrfs-convert" "$dest/usr/bin/btrfs-find-root" \
          "$dest/usr/bin/btrfs-image" "$dest/usr/bin/btrfs-map-logical" \
          "$dest/usr/bin/btrfs-select-super" "$dest/usr/bin/btrfstune" \
          "$dest/usr/sbin/btrfs-convert" "$dest/usr/sbin/btrfs-image" \
          "$dest/usr/sbin/btrfstune" 2>/dev/null
    rm -rf "$dest/usr/lib/udev/hwdb.d" "$dest/etc/udev/hwdb.d" 2>/dev/null
    true
    # kernel + modules
    local ktmp
    ktmp=$(mktemp -d)
    rootfs_deb_extract linux-image-6.12.107+deb13-amd64-unsigned.deb "$ktmp" || return 1
    mv "$ktmp/usr/lib/modules/$UKI_KERNEL_RELEASE" "$dest/modules-tree" 2>/dev/null ||
        mv "$ktmp/lib/modules/$UKI_KERNEL_RELEASE" "$dest/modules-tree"
    cp "$ktmp/boot/vmlinuz-$UKI_KERNEL_RELEASE" "$dest/vmlinuz"
    rm -rf "$ktmp"
    # merged-usr symlinks (debs assume /bin,/sbin -> /usr/...)
    ln -sfn usr/bin "$dest/bin"
    ln -sfn usr/sbin "$dest/sbin"
    # host tpm2 closure, isolated under /opt/tpm with its own loader.
    # THE FULL HOOK VERB SET (hooks/mkinitfs/features.d/alpine-fde.files):
    # the mkinitfs unseal hook (§8.2) runs exactly these ten verbs — pcrread
    # is kept for the console PCR prints, pcrextend doubles as the enter-
    # initrd fallback on the 257.13 oracle path. Same lib set for all verbs,
    # one loader walk over the union.
    mkdir -p "$dest/opt/tpm/bin" "$dest/opt/tpm/lib"
    local v
    for v in tpm2_pcrread tpm2_pcrextend tpm2_startauthsession tpm2_policypcr \
             tpm2_policyauthorize tpm2_loadexternal tpm2_verifysignature \
             tpm2_createprimary tpm2_load tpm2_unseal tpm2_flushcontext; do
        cp -L "$(command -v "$v")" "$dest/opt/tpm/bin/$v"
    done
    local interp
    interp=$(ldd "$dest/opt/tpm/bin/tpm2_pcrread" | awk '/ld-linux/{print $1}')
    cp -L "$interp" "$dest/opt/tpm/ld-linux-x86-64.so.2"
    local l
    for l in $(
        for v in tpm2_pcrread tpm2_verifysignature tpm2_unseal tpm2_load; do
            ldd "$dest/opt/tpm/bin/$v" 2>/dev/null
        done | awk '$3 ~ /^\// {print $3}' | sort -u); do
        cp -L "$l" "$dest/opt/tpm/lib/"
    done
    # the device TCTI is dlopen'd (with its VERSIONED soname), ldd does not
    # show it — keep the .0 filename or tctildr's dlopen fails
    for l in /usr/lib/libtss2-tcti-device.so.0 /usr/lib/libtss2-tcti-swtpm.so.0; do
        [[ -f "$l" ]] && cp -L "$l" "$dest/opt/tpm/lib/"
    done
    # host openssl closure under /opt/ssl (own loader — the host glibc/libcrypto
    # must not clash with the Debian guest's). The hook (§8.2) shells out to
    # `openssl base64` / `openssl dgst -verify` for the I3 signature gate;
    # features.d/alpine-fde.files lists /usr/bin/openssl — satisfied here by
    # the wrapper script below (same PATH name, same argv surface).
    mkdir -p "$dest/opt/ssl/bin" "$dest/opt/ssl/lib"
    cp -L "$(command -v openssl)" "$dest/opt/ssl/bin/openssl"
    interp=$(ldd "$dest/opt/ssl/bin/openssl" | awk '/ld-linux/{print $1}')
    cp -L "$interp" "$dest/opt/ssl/ld-linux-x86-64.so.2"
    for l in $(ldd "$dest/opt/ssl/bin/openssl" | awk '$3 ~ /^\// {print $3}'); do
        cp -L "$l" "$dest/opt/ssl/lib/"
    done
    # PATH-name wrappers for the SHIPPED hook (features.d/alpine-fde.files
    # contract): the hook calls bare `tpm2_*` verbs and bare `openssl`, while
    # the host-closure copies live under /opt/{tpm,ssl} behind their own
    # loaders — so each PATH name is a two-line sh wrapper pinning that loader
    # (the rootfs_payload_image /opt-isolation pattern). The TCTI crosses the
    # wrapper as the TPM2TOOLS_TCTI env (/init exports device:/dev/tpmrm0);
    # argv surface is passed through verbatim.
    local w
    for w in tpm2_pcrextend tpm2_startauthsession tpm2_policypcr \
             tpm2_policyauthorize tpm2_loadexternal tpm2_verifysignature \
             tpm2_createprimary tpm2_load tpm2_unseal tpm2_flushcontext; do
        printf '#!/bin/sh\nexec /opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/%s "$@"\n' \
            "$w" >"$dest/usr/bin/$w"
        chmod 755 "$dest/usr/bin/$w"
    done
    printf '#!/bin/sh\nexec /opt/ssl/ld-linux-x86-64.so.2 --library-path /opt/ssl/lib /opt/ssl/bin/openssl "$@"\n' \
        >"$dest/usr/bin/openssl"
    chmod 755 "$dest/usr/bin/openssl"
    # closure gate (guest binaries only; /opt/* resolve via their own loader)
    local miss
    miss=$(_uki_closure_check "$dest" \
        "$dest/usr/lib/systemd/systemd-cryptsetup" \
        "$dest/usr/lib/systemd/systemd-pcrextend" \
        "$dest/usr/bin/systemd-cryptenroll" \
        "$dest/usr/sbin/cryptsetup" \
        "$dest/usr/lib/x86_64-linux-gnu/cryptsetup/libcryptsetup-token-systemd-tpm2.so" \
        "$dest/usr/bin/btrfs" \
        "$dest/usr/sbin/mkfs.btrfs" \
        "$dest/usr/lib/systemd/systemd-udevd" \
        "$dest/usr/bin/udevadm" \
        "$dest/opt/tpm/bin/tpm2_pcrread" \
        "$dest/opt/tpm/bin/tpm2_pcrextend" 2>/dev/null | grep -v '/opt/' || true)
    if [[ -n "$miss" ]]; then
        echo "uki-build: guest closure incomplete:" >&2
        echo "$miss" >&2
        return 1
    fi
    touch "$dest/.closure-ok"
    return 0
}

# uki_initrd_write_init <tree> — write /init into the guest-tree staging dir.
uki_initrd_write_init() {
    local tree="$1"
    cat >"$tree/init" <<'INIT'
#!/bin/sh
# Debian FDE harness initramfs /init (busybox). See tests/lib/uki-build.sh.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu/systemd
/bin/busybox mkdir -p /proc /sys /dev /run /tmp /etc /opt/tpm
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs dev /dev
/bin/busybox mount -t tmpfs tmpfs /run
/bin/busybox mount -t tmpfs tmpfs /tmp
# make sure our output reaches the console even if the kernel could not open
# the initial console from a node-less cpio
[ -c /dev/console ] && exec >/dev/console 2>&1 </dev/console
echo "debian-fde-harness: init started"

# modules: crypto for LUKS2 aes-xts, device-mapper, virtio disk
for m in @@MODULES@@; do
    if [ -f "/modules/$m.ko" ]; then
        busybox insmod "/modules/$m.ko" 2>/dev/null || echo "debian-fde-harness: insmod $m failed (maybe builtin)"
    fi
done

# machine-readable effective-kernel-commandline prints (s07 asserts the
# cmdline tamper actually reached the kernel). Printed TWICE: kernel printk
# can interleave into userspace console writes (observed live, lines split
# mid-print), so scenarios match the first line that survived whole.
echo "debian-fde-cmdline $(cat /proc/cmdline)"
busybox sleep 0.3
echo "debian-fde-cmdline2 $(cat /proc/cmdline)"

# efivarfs: systemd-pcrextend checks the stub's EFI variables (StubPcrKernelImage)
# to decide whether to extend PCR 11 — without the mount it logs "Kernel stub
# did not measure kernel image into PCR 11, skipping userspace measurement"
# and exits 0 WITHOUT extending (pre==post). Best effort: if the mount fails,
# the tpm2_pcrextend fallback below still applies the identical extend.
busybox mkdir -p /sys/firmware/efi/efivars
busybox mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null \
    || echo "debian-fde-harness: efivarfs not mounted (pcrextend fallback will be used)"

# udev in the initrd (the dracut pattern): systemd-cryptsetup's dm attach must
# happen with udev sync so 55-dm.rules registers /dev/mapper/root and the
# persistent by-uuid links — systemd's device units (and therefore the §9.1
# fstab UUID= submounts after switch_root) NEVER activate for a dm device
# created udev-unregistered (observed live 2026-09-19: dev-disk-by...device
# timed out even for the raw /dev/dm-0 node → local-fs failed → emergency
# sulogin instead of login:). login_stage stops udevd again before
# switch_root so the installed system's own udevd starts cleanly; /run/udev
# (the device db with our by-uuid entries) moves into the real system with
# switch_root. A failed start is logged LOUDLY (rc + stderr on the console),
# never silent and never fatal.
mkdir -p /run/udev
udev_err=$(/usr/lib/systemd/systemd-udevd --daemon 2>&1)
udev_rc=$?
if [ "$udev_rc" = "0" ] && [ -e /run/udev/control ]; then
    echo "debian-fde-harness: udevd running (dm attach will be udev-registered)"
else
    echo "debian-fde-harness: udevd NOT started (rc=$udev_rc): $udev_err"
fi

# coldplug (the dracut pattern): udevd started AFTER the kernel already
# registered every device, so no uevent ever reached the udev device db —
# /dev/disk/by-uuid for the payload disk NEVER appeared and the unseal hook's
# crypttab UUID= resolution found nothing on any member ("no systemd-tpm2
# token found" -> recovery prompt -> 3-strike poweroff; observed live in the
# s15 boot of 2026-09-21). Replay the add uevents for everything the kernel
# registered before udevd came up, then wait (BOUNDED) for the event queue to
# drain so the persistent links exist before the unlock machinery runs.
if [ "$udev_rc" = "0" ] && [ -e /run/udev/control ]; then
    if udevadm trigger --type=devices --action=add 2>&1; then
        udevadm settle --timeout=15 \
            || echo "debian-fde-harness: WARNING udevadm settle timed out (by-uuid links may be incomplete)"
        echo "debian-fde-harness: coldplug settled; by-uuid: $(ls /dev/disk/by-uuid 2>/dev/null | tr '\n' ' ')"
    else
        echo "debian-fde-harness: WARNING udevadm trigger FAILED — /dev/disk/by-uuid will not resolve"
    fi
fi

# signed-PCR-policy JSON: delivered on the raw payload drive (/dev/vdc)
if [ -b /dev/vdc ]; then
    busybox dd if=/dev/vdc bs=4096 count=16 2>/dev/null | busybox tr -d '\000' > /pcrsig.json
fi
[ -s /pcrsig.json ] && echo "debian-fde-harness: pcrsig payload loaded ($(busybox wc -c < /pcrsig.json) bytes): $(head -c 60 /pcrsig.json)" || echo "debian-fde-harness: pcrsig payload MISSING"
# stage selector via the PAYLOAD DRIVE (uki_stage_login_drive): the word
# "login" at offset 64 KiB (the pcrsig region is the first 64 KiB; the tooling
# tail rides after it). The cmdline word debian-fde-stage= keeps working; the
# drive marker exists because the §8.2 unseal hook's {7,11} policy is bound to
# THIS UKI's measured PCR 11 — a cmdline-variant UKI changes the stub
# measurement and the zero-input token unlock can never match (s00b boot C).
if [ -b /dev/vdc ]; then
    busybox dd if=/dev/vdc bs=1 skip=65536 count=8 2>/dev/null | busybox tr -d '\000' > /fde-stage
    [ "$(cat /fde-stage 2>/dev/null)" = "login" ] \
        && echo "debian-fde-harness: payload drive selects stage=login (unmeasured channel)"
fi
# ALSO install it at the token plugin's auto-search location (CONF_PATHS("systemd")
# + tpm2-pcr-signature.json — the dracut/trixie initrd production pattern). The
# cryptsetup-tokens plugin gets a NULL signature_path on this systemd/libcryptsetup
# pair (tpm2-signature= option value never reaches the plugin), so the direct
# /pcrsig.json path would die at the default-name lookup; with the file installed
# the sanctioned plugin path activates the volume. The internal fallback retry
# (tpm2-signature=/pcrsig.json) remains as the safety net.
busybox mkdir -p /etc/systemd
busybox cp /pcrsig.json /etc/systemd/tpm2-pcr-signature.json 2>/dev/null || true

# wait for the TPM character device (devtmpfs + built-in tpm_tis)
i=0
while [ ! -c /dev/tpmrm0 ] && [ "$i" -lt 50 ]; do
    i=$((i + 1))
    busybox sleep 0.1
done
if [ -c /dev/tpmrm0 ]; then
    echo "debian-fde-harness: /dev/tpmrm0 present"
else
    echo "debian-fde-harness: /dev/tpmrm0 ABSENT after timeout"
fi

# print PCRs (host-closure tpm2-tools under /opt/tpm, own loader)
TPM2="/opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/tpm2_pcrread"
# tpm2_pcrread output aligns the colon by index width: `  0 : 0x…` but
# ` 11: 0x…`. Parse format-agnostically: strip colons, then take the field
# after the PCR index that is a 64-hex-char digest. (Field-position checks
# break one format or the other: single-digit PCRs have the colon as a
# SEPARATE field, two-digit ones glue it to the index.)
pcr_hex() {
    $TPM2 -T device:/dev/tpmrm0 "sha256:$1" 2>/dev/null | awk -v p="$1" '
        {
            line = $0
            gsub(/:/, " ", line)
            n = split(line, f, /[ \t]+/)   # NB: a leading separator yields an EMPTY f[1]
            for (k = 1; k <= n; k++) {
                if (f[k] != p) continue
                for (j = k + 1; j <= n; j++) {
                    h = f[j]
                    if (substr(h, 1, 2) == "0x" || substr(h, 1, 2) == "0X")
                        h = substr(h, 3)
                    if (length(h) == 64 && h !~ /[^0-9a-fA-F]/) { print tolower(h); exit }
                }
            }
        }'
}
for pcr in 0 7 11; do
    hex=$(pcr_hex "$pcr")
    if [ -z "$hex" ]; then
        echo "debian-fde-harness: pcrread $pcr RAW OUTPUT:"
        $TPM2 -T device:/dev/tpmrm0 sha256:$pcr 2>&1 | head -4
    fi
    echo "debian-fde-pcr sha256:$pcr=$hex"
done

# pcrextend_enter_initrd — extend PCR 11 with the enter-initrd PHASE WORD
# before any unlock attempt — exactly what a production initrd does
# (systemd-pcrphase-initrd.service: `systemd-pcrextend --graceful
# enter-initrd`, Before=cryptsetup.target). Called on the INSTALLER stage
# (passphrase unlock, no hook — without it the G-T13 postphase line never
# exists for S-00: regression, 2026-09-22 registry run) and on the ORACLE
# unlock path. NOT called on the hook path: the SHIPPED hook performs its own
# enter-initrd pcrextend (a second extension here would push PCR 11 past the
# signed prediction). ukify's phase=enter-initrd .pcrsig prediction INCLUDES
# this extension, so without it the consumer's find_signature() can never
# match (Wave-2 root cause; see tests/e2e/README.md). Primary: real 257.13
# systemd-pcrextend (needs efivarfs for the stub-measured check). The PCR
# VALUE decides, not the rc: if PCR 11 did not change, fall back to extending
# H("enter-initrd") via the host tpm2-tools closure — the extend value is
# identical (the PCR does not care which tool computed it).
pcrextend_enter_initrd() {
    echo "debian-fde-harness: extending PCR 11 (enter-initrd phase word)"
    pcr11_pre=$(pcr_hex 11)
    if /usr/lib/systemd/systemd-pcrextend enter-initrd \
            && [ "$(pcr_hex 11)" != "$pcr11_pre" ]; then
        echo "debian-fde-harness: pcrextend ok (systemd-pcrextend)"
    else
        echo "debian-fde-harness: systemd-pcrextend skipped/failed — trying tpm2_pcrextend"
        word_digest=$(printf 'enter-initrd' | sha256sum | awk '{print $1}')
        if /opt/tpm/ld-linux-x86-64.so.2 --library-path /opt/tpm/lib /opt/tpm/bin/tpm2_pcrextend \
                -T device:/dev/tpmrm0 "11:sha256=$word_digest" \
                && [ "$(pcr_hex 11)" != "$pcr11_pre" ]; then
            echo "debian-fde-harness: pcrextend ok (tpm2_pcrextend)"
        else
            echo "debian-fde-harness: pcrextend FAILED — unlock cannot match the signed policy"
        fi
    fi
    echo "debian-fde-pcr-postphase sha256:11=$(pcr_hex 11)"
}

# ---- unlock mechanism selection (§8.2 fixture, Architecture.md §12) ----------
# DEFAULT: the SHIPPED mkinitfs unseal hook (hooks/mkinitfs/alpine-fde-unseal.
# sh) — the Alpine-contract unlock of record (ADR-13). The 257.13
# systemd-cryptsetup unlock oracle remains available, opt-in, for scenarios
# that explicitly document it: boot with `debian-fde-unlock=oracle`.
UNLOCK=hook
for _w in $(cat /proc/cmdline); do
    case "$_w" in debian-fde-unlock=oracle) UNLOCK=oracle ;;
    esac
done
echo "debian-fde-harness: unlock mechanism: $UNLOCK"

if [ "$UNLOCK" = "oracle" ]; then
pcrextend_enter_initrd
fi  # UNLOCK=oracle phase extension

DISK=/dev/vdb

# ---- §12 S-00 installer stage (cmdline: debian-fde-stage=install) -------------
# The one-time PASSPHRASE unlock of the freshly laid LUKS2 volume (the only
# documented first-boot prompt; here fed from the embedded /kf0, ZERO console
# input — no enrollment exists yet), then populate the minimal rootfs (§3.3)
# from the SHA256-pinned Alpine rootfs payload and power off. NO enrollment and
# NO token unlock in this stage: `audit --init` finalizes the baseline first
# (S-00, host side) and the S-00b boot enrolls from the guest afterwards.
# The pinned payload travels on a raw payload drive (vdc for this stage — the
# token unlock never runs here, so the .pcrsig drive slot is free; embedding
# the artifact in the initramfs is infeasible: a 171MiB UKI already proved
# beyond the firmware's TCG budget, see uki_initrd_pack).
installer_stage() {
    # the enter-initrd phase-word extension is not hook/oracle-exclusive: the
    # G-T13 prediction check needs the postphase PCR 11 reading on EVERY boot
    # of the pcrsig-carrying UKI, including this passphrase-only one (the
    # hook never runs here and the oracle branch is never reached — the
    # stage dispatch powers off before either).
    pcrextend_enter_initrd
    echo "debian-fde-install: one-time passphrase unlock (slot 0, documented first-boot prompt)"
    /usr/sbin/cryptsetup open --type luks --key-file /kf0 "$DISK" root
    cs_rc=$?
    if [ "$cs_rc" -ne 0 ] || [ ! -e /dev/mapper/root ]; then
        echo "debian-fde-install: passphrase unlock FAILED (cryptsetup rc=$cs_rc)"
        return 1
    fi
    echo "debian-fde-install: root volume unlocked via passphrase (no enrollment yet)"
    if [ ! -b /dev/vdc ]; then
        echo "debian-fde-install: rootfs payload drive /dev/vdc MISSING"
        return 1
    fi
    busybox dd if=/dev/vdc of=/rootfs.tar bs=1M 2>/dev/null
    # the payload image is MiB-aligned (virtio-blk capacity is 512-byte
    # granular; an unaligned image would be silently rounded DOWN and truncate
    # the artifact) — trim the device read back to the artifact size, then
    # hash-verify against the build-time pin.
    busybox truncate -s @@ROOTFS_BYTES@@ /rootfs.tar
    echo "@@ROOTFS_SHA@@  /rootfs.tar" | sha256sum -c - || {
        echo "debian-fde-install: pinned rootfs artifact hash MISMATCH"; return 1; }
    echo "debian-fde-install: rootfs payload verified ($(du -k /rootfs.tar | cut -f1) KiB)"
    # §9.1 default filesystem (G-HW5, revised-design BASE matrix): Btrfs with
    # the @/@home/@snapshots subvolume layout. mkfs.btrfs + the `btrfs`
    # multitool come from the pinned btrfs-progs deb (packed into this
    # initrd). The legacy flat fs stays production-only (`install --fs ext4`);
    # no harness scenario exercises it, so there is no ext4 seam here.
    mkfs.btrfs -f /dev/mapper/root >/tmp/mkfs.log 2>&1 || {
        echo "debian-fde-install: mkfs.btrfs FAILED"; busybox tail -5 /tmp/mkfs.log; return 1; }
    ROOTFS_UUID=$(awk '/^UUID:/ {print $2; exit}' /tmp/mkfs.log)
    if [ -z "$ROOTFS_UUID" ]; then
        ROOTFS_UUID=$(btrfs filesystem show /dev/mapper/root 2>/dev/null | awk '/uuid:/ {print $NF; exit}')
    fi
    if [ -z "$ROOTFS_UUID" ]; then
        echo "debian-fde-install: no btrfs UUID — cannot write the §9.1 fstab"; return 1
    fi
    echo "debian-fde-install: btrfs rootfs created (uuid=$ROOTFS_UUID)"
    mkdir -p /btop
    busybox mount -t btrfs /dev/mapper/root /btop || {
        echo "debian-fde-install: btrfs top-level mount FAILED"; return 1; }
    SVOK=1
    btrfs subvolume create /btop/@ >/dev/null 2>&1 || SVOK=0
    btrfs subvolume create /btop/@home >/dev/null 2>&1 || SVOK=0
    btrfs subvolume create /btop/@snapshots >/dev/null 2>&1 || SVOK=0
    busybox umount /btop
    if [ "$SVOK" != "1" ]; then
        echo "debian-fde-install: btrfs subvolume create FAILED"; return 1
    fi
    echo "debian-fde-install: subvolumes created (@ @home @snapshots)"
    mkdir -p /newroot
    busybox mount -t btrfs -o subvol=@ /dev/mapper/root /newroot || {
        echo "debian-fde-install: root mount FAILED (btrfs subvol=@)"; return 1; }
    echo "debian-fde-install: root mounted (btrfs subvol=@)"
    echo "debian-fde-install: populating rootfs from the pinned Alpine artifact (§3.3)"
    gzip -dc /rootfs.tar | tar -xf - -C /newroot || {
        echo "debian-fde-install: rootfs untar FAILED"; return 1; }
    # §3.3/§9.1 config drops — mirror what production install writes
    # (lib/cmd/install.sh): /etc/apk/repositories = inst_repo_lines (the
    # mirror's main + community), /etc/network/interfaces = the OpenRC
    # ifupdown-ng drop, `rc-update add networking boot` = the boot-runlevel
    # symlink, and the serial getty = Alpine's own inittab line (commented
    # upstream; enabled here for the harness console). No apk transaction runs
    # in-guest: the payload ships the tooling + stubs pre-placed instead.
    mkdir -p /newroot/etc/apk /newroot/etc/network /newroot/etc/runlevels/boot \
             /newroot/usr/local/bin
    printf '%s\n' '@@APK_MIRROR@@' '@@APK_MIRROR_COMMUNITY@@' >/newroot/etc/apk/repositories
    printf 'auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet dhcp\n' \
        >/newroot/etc/network/interfaces
    ln -sfn /etc/init.d/networking /newroot/etc/runlevels/boot/networking
    if grep -q '^ttyS0::' /newroot/etc/inittab 2>/dev/null; then
        :
    else
        printf '%s\n' 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' >>/newroot/etc/inittab
    fi
    echo "debian-fde-install: getty/openrc configured (§3.3)"
    # §9.1 mountpoints inside @ — the fstab entries below mount @home and
    # @snapshots here at boot. (No btrfs userspace copy: the initrd's pinned
    # btrfs-progs binaries are glibc builds and cannot execute on the musl
    # root; the §3.3 additions set arrives via apk in the production flow.)
    mkdir -p /newroot/home /newroot/.snapshots
    # fstab: the §9.1 Btrfs subvolume forms (verbatim production shapes,
    # lib/cmd/install.sh: UUID=<rootfs-uuid> /|/home|/.snapshots btrfs
    # subvol=@…). Root is hand-mounted rw by the boot initrd before
    # switch_root; /home and /.snapshots resolve via the udev-registered
    # by-uuid links (the initrd udevd above). The source-image PARTUUID
    # entries do not exist on this hardware; the harness ESP is not
    # fstab-mounted (production adds `PARTUUID=<esp> /efi vfat umask=0077 0 2`).
    printf '%s\n' \
        '# /etc/fstab — §9.1 Btrfs subvolume layout; root is mounted rw by' \
        '# the boot initrd before switch_root (LUKS volume unlocked there).' \
        "UUID=$ROOTFS_UUID / btrfs subvol=@,defaults 0 1" \
        "UUID=$ROOTFS_UUID /home btrfs subvol=@home,defaults 0 2" \
        "UUID=$ROOTFS_UUID /.snapshots btrfs subvol=@snapshots,defaults 0 2" \
        > /newroot/etc/fstab
    echo "debian-fde-install: fstab (§9.1 subvol=@/@home/@snapshots) written"
    # §9.1 step 10 / ADR-20 amended: the install-state marker, schema v1 in
    # the lib/install-state.sh shape (two-space indent, quoted values). The
    # unseal hook's Stage-2 transition and the first-boot finalization
    # service both key off this file.
    mkdir -p /newroot/etc/alpine-fde
    {
        printf '{\n'
        printf '  "schema_version": 1,\n'
        printf '  "state": "installed",\n'
        printf '  "updated_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        printf '}\n'
    } > /newroot/etc/alpine-fde/install-state.json
    echo "debian-fde-install: install-state marked installed (§9.1 step 10)"
    # console proof of the on-disk fstab forms (asserted verbatim by S-00)
    while read -r _fl; do
        case "$_fl" in \#*) continue ;; esac
        echo "debian-fde-btrfs: fstab| $_fl"
    done < /newroot/etc/fstab
    # machine-readable installed size + package count (§3.3/ADR-12 budget,
    # asserted by S-00). Package marker = the apk world/db: /lib/apk/db/
    # installed, one leading `P:` line per installed package.
    _pkgdb=/newroot/lib/apk/db/installed
    if [ -f "$_pkgdb" ]; then
        packages=$(grep -c '^P:' "$_pkgdb")
    else
        packages=0
    fi
    echo "debian-fde-rootfs: kib=$(du -sk /newroot | cut -f1) packages=$packages"
    # §9.1 subvolume presence — the on-disk evidence S-00 asserts (the mounted
    # root IS the @ subvolume; the list shows every subvolume on the volume)
    echo "debian-fde-btrfs: subvolume list (on-disk evidence):"
    btrfs subvolume list /newroot || {
        echo "debian-fde-install: btrfs subvolume list FAILED"; return 1; }
    # I2/I4 disk-side scan: no private key material anywhere on the LUKS payload.
    #   keyfiles: .pem/.key OUTSIDE the public trust store (the Debian CA
    #     bundle ships hundreds of PUBLIC .pem certs — /etc/ssl/certs,
    #     /usr/lib/ssl/certs{,/cert.pem} — those are not key material; the
    #     ALPINE trust store layout differs: the merged CA bundle lives at
    #     /etc/ssl/cert.pem plus the legacy /etc/ssl1.1/cert.pem copy — both
    #     PUBLIC bundles, observed as keyfiles=2 in the 2026-09-22 registry
    #     run until pruned here);
    #   pem: PRIVATE-KEY PEM headers at LINE START (real PEM files open the
    #     header at column 1) in TEXT files only (grep -I) — unanchored greps
    #     false-positive on openssh/gnutls BINARIES (the header string as a
    #     code literal), on a python cryptography constant and on INDENTED
    #     sample keys in cloud-init doc examples (all observed live
    #     2026-09-17 against this exact tree).
    echo "debian-fde-scan: keyfiles=$(find /newroot \( -path /newroot/etc/ssl/certs -o -path /newroot/usr/lib/ssl/certs -o -path /newroot/usr/lib/ssl/cert.pem -o -path /newroot/etc/ssl/cert.pem -o -path /newroot/etc/ssl1.1/cert.pem \) -prune -o \( -name '*.pem' -o -name '*.key' \) -print | wc -l) pem=$(grep -rIlE '^-----BEGIN [A-Z ]*PRIVATE KEY-----' /newroot 2>/dev/null | wc -l)"
    busybox umount /newroot
    /usr/sbin/cryptsetup close root
    return 0
}

STAGE=boot
for _w in $(cat /proc/cmdline); do
    case "$_w" in debian-fde-stage=*) STAGE=${_w#debian-fde-stage=} ;;
    esac
done
# the payload-drive marker OVERRIDES the (measured) cmdline word — the login
# stage of the §8.2 hook era must boot the SAME UKI bytes the enrollment
# measured (see the marker read above)
[ "$(cat /fde-stage 2>/dev/null)" = "login" ] && STAGE=login
if [ "$STAGE" = "install" ]; then
    if installer_stage; then
        echo "debian-fde-harness: install stage complete"
        echo "debian-fde: POWEROFF"
        sync
        busybox poweroff -f
    else
        echo "debian-fde: INSTALL-FAILED"
        sync
        busybox poweroff -f
    fi
fi

# ---- §12 S-01 login stage (cmdline: debian-fde-stage=login) -------------------
# After the TOKEN unlock succeeded (zero console input — the §12 S-01 happy
# path), hand the machine to the populated installed system: switch_root into
# the real Debian root; systemd + getty-generator put `login:` on the serial
# console. No passphrase loop exists on this cmdline (no fallback word) — the
# boot reaches login or it does not reach login.
#
# ORDERING (fixed 2026-09-17): the dispatch runs AFTER the unlock below —
# /dev/mapper/root only exists once the token path has unsealed the volume, so
# an early dispatch could never fire (a login-stage boot silently powered off
# after UNSEALED instead of switching root).
login_stage() {
    mkdir -p /newroot
    # §9.1: the installed root is the @ subvolume of the LUKS volume (G-HW5)
    busybox mount -t btrfs -o subvol=@ /dev/mapper/root /newroot || {
        echo "debian-fde-login: root mount FAILED (btrfs subvol=@)"; return 1; }
    busybox grep -Eq 'subvol=/?@(,| )' /proc/mounts \
        && echo "debian-fde-btrfs: root mounted subvol=@ (login stage)"
    # settle: give the udev event pipeline a bounded window to finish the
    # persistent by-uuid links for the dm volume (they are what the installed
    # system's fstab resolves). Loud on timeout, never fatal.
    i=0
    while [ -z "$(ls /dev/disk/by-uuid 2>/dev/null)" ]; do
        [ "$i" -lt 20 ] && { i=$((i + 1)); busybox sleep 0.5; continue; }
        echo "debian-fde-harness: WARNING no /dev/disk/by-uuid links after 10s (fstab submounts will not resolve)"
        break
    done
    if [ -n "$(ls /dev/disk/by-uuid 2>/dev/null)" ]; then
        echo "debian-fde-harness: udev by-uuid links present: $(ls /dev/disk/by-uuid | tr '\n' ' ')"
    fi
    # stop the initrd udevd so the installed system's own udevd starts
    # cleanly; the /run/udev device db (by-uuid entries for the dm volume)
    # must survive the switch
    udevadm control --exit 2>/dev/null || busybox killall systemd-udevd 2>/dev/null
    busybox sleep 0.3
    # busybox switch_root does NOT carry the initrd's api-fs mounts over: it
    # overmounts / with the new root, and the initrd-only mounts (devtmpfs on
    # /dev — the mapper node + the udev by-uuid links — and the /run tmpfs
    # WITH the udev device db) would be buried; the installed systemd then
    # mounts a FRESH /dev and /run and its fstab UUID= device units can never
    # resolve (observed live 2026-09-19: 90 s device timeout → emergency).
    # Move them onto the new root first — exactly what dracut/systemd's
    # switch_root does internally.
    busybox mount -o move /dev /newroot/dev \
        || echo "debian-fde-harness: /dev move FAILED (mapper node + by-uuid links lost)"
    busybox mount -o move /proc /newroot/proc || echo "debian-fde-harness: /proc move FAILED"
    busybox mount -o move /sys /newroot/sys || echo "debian-fde-harness: /sys move FAILED"
    busybox mount -o move /run /newroot/run \
        || echo "debian-fde-harness: /run move FAILED (udev device db lost)"
    echo "debian-fde-harness: switching to the installed system (zero console input so far)"
    echo "debian-fde: SWITCH-ROOT"
    exec busybox switch_root /newroot /sbin/init
}

# ---- console passphrase fallback loop (HARNESS-ONLY; s12) -------------------
# Production recovers via systemd's ask-password machinery inside the dracut
# initramfs (systemd-tty-ask-password-agent ships in dracut). This raw busybox
# initrd has no agent socket and no controlling TTY, so ask_password_auto()
# returns ENOENT and serial-fed input is never consumed (see s01 history) —
# hence this minimal harness equivalent, gated behind the
# `debian-fde-console-fallback` kernel cmdline flag: without the flag the token
# refusal path stays exactly as s01 proved it (deterministic lockout, no read).
#
# Ordering contract (257.13 semantics): the TOKEN path is always attempted
# FIRST and without any key file (a key file in the attach position DISPLACES
# the token path entirely -> acquire_tpm2_key with hardcoded defaults ->
# segfault in tpm2_unseal). Only after the token is REFUSED do we fall through
# to reading the passphrase slot, one line at a time, feeding a PLAIN
# `cryptsetup open --key-file` attach (NO tpm2-device= — passphrase attempts
# never touch the TPM2 token path).
#
# Termios note (why no stty): the kernel serial console (ttyS0) comes up in
# canonical mode with echo and ICRNL by default, so a plain `read` from stdin
# (already redirected from /dev/console) returns exactly one fed line and the
# tty echo doubles as console evidence of what the feeder sent. Raw mode would
# need explicit termios repair (busybox stty exists in the guest tree) — not
# needed here because nothing in this initrd puts the console in raw mode.
console_passphrase_loop() {
    n=0
    while [ "$n" -lt 3 ]; do
        n=$((n + 1))
        echo "debian-fde-harness: passphrase attempt $n/3 (awaiting console line)"
        line=
        read -t 20 -r line
        read_rc=$?
        echo "debian-fde-harness: read done (rc=$read_rc len=${#line})"
        if [ "$read_rc" -ne 0 ] || [ -z "$line" ]; then
            echo "debian-fde-harness: passphrase attempt $n rejected (read rc=$read_rc: timeout/empty)"
            continue
        fi
        printf '%s' "$line" > /tmp/kf-try
        chmod 600 /tmp/kf-try
        /usr/sbin/cryptsetup open --type luks --key-file /tmp/kf-try "$DISK" root >/tmp/cs.log 2>&1
        cs_rc=$?
        cat /tmp/cs.log
        if [ "$cs_rc" -eq 0 ] && [ -e /dev/mapper/root ]; then
            echo "debian-fde-harness: passphrase unlock ok (attempt $n)"
            echo "debian-fde: UNSEALED"
            return 0
        fi
        echo "debian-fde-harness: passphrase attempt $n rejected (cryptsetup rc=$cs_rc)"
    done
    echo "debian-fde-harness: passphrase attempts exhausted (3 failures)"
    return 1
}

if [ "$UNLOCK" = "oracle" ]; then
# ---- 257.13 unlock ORACLE (opt-in: debian-fde-unlock=oracle) -----------------
# Kept verbatim as the Debian-era provenance record; its sentinels live in
# tests/sentinels-257.13.txt. The DEFAULT path is the §8.2 hook branch below.
#
# enroll a systemd-tpm2 token in-guest when the volume has none yet
# (the S-00b pattern: enrollment from the guest, against live PCRs)
if ! /usr/sbin/cryptsetup luksDump --dump-json-metadata "$DISK" 2>/dev/null | grep -q '"systemd-tpm2"'; then
    echo "debian-fde-harness: no systemd-tpm2 token — enrolling in-guest"
    systemd-cryptenroll \
        --unlock-key-file=/kf0 \
        --tpm2-device=auto --wipe-slot=tpm2 \
        --tpm2-pcrs=7 \
        --tpm2-public-key=/rel.pub --tpm2-public-key-pcrs=11 \
        "$DISK" || echo "debian-fde-harness: cryptenroll failed rc=$?"
else
    echo "debian-fde-harness: systemd-tpm2 token present — skipping enrollment"
fi

# unlock with the signed-PCR policy: real trixie 257.13 systemd-cryptsetup.
# NO key-file argument: in 257.13 the attach KEY-FILE position DISPLACES the
# LUKS2-token path entirely (acquire_tpm2_key is then called with hardcoded
# no-signature/no-SRK/no-bank defaults, which cannot unlock a token-sealed
# volume and crashes tpm2_unseal on the incompatible primary). The fallback
# prompt needs an ask-password agent / controlling TTY (absent here), so on
# tampered boots we run with tries=1: the single token attempt is refused
# (PCR 7 drift) and systemd-cryptsetup ends in "Too many attempts to
# activate; giving up." — deterministic lockout, no prompt involved.
# SYSTEMD_LOG_LEVEL=debug stays ON: the s00 assertion surface includes the
# log_debug-only sentinel "Adding PCR signature policy.".
# WAVE-2 DEBUG (kept through the spike): prove the payload is visible at
# unlock time (the ls line below).
echo "debian-fde-harness: starting unlock attempt"
ls -la /pcrsig.json 2>&1
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-cryptsetup attach root "$DISK" "" \
    "tpm2-device=auto,tpm2-signature=/pcrsig.json,tries=1" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && [ -e /dev/mapper/root ]; then
    echo "debian-fde: UNSEALED"
    if [ "$STAGE" = "login" ]; then
        login_stage   # exec switch_root — never returns on success
        echo "debian-fde: LOGIN-STAGE-FAILED"
        sync
        busybox poweroff -f
    fi
elif grep -q debian-fde-console-fallback /proc/cmdline; then
    echo "debian-fde-harness: token refused (rc=$rc) — console passphrase fallback armed"
    if console_passphrase_loop; then
        :  # UNSEALED printed inside the loop
    else
        echo "debian-fde: PROMPT-FAILED rc=3"
    fi
else
    echo "debian-fde: PROMPT-FAILED rc=$rc"
fi

else
# ---- §8.2 mkinitfs unseal hook (the DEFAULT unlock; ADR-13) ------------------
# /init plays the mkinitfs init role: stage the hook's expected environment,
# then hand the console to the SHIPPED hook. The hook owns the whole unlock
# contract — the enter-initrd PCR 11 extend, the cryptsetup token export
# scan, the I3 openssl signature gate against FDE_EXTRA_DIR, the TPM
# PolicyPCR/PolicyAuthorize session, `cryptsetup open`, the bounded
# recovery-passphrase loop (its OWN prompt read, keyslot 0) and the 3-strike
# fail-closed `poweroff -f`. /init does NOT extend PCR 11 on this path (the
# hook does; a second extend would overshoot the signed enter-initrd
# prediction).
echo "debian-fde-harness: staging the unseal hook environment (§8.2)"
# the hook calls bare tpm2_* verbs (PATH names) and bare openssl under the
# ambient TCTI — the /usr/bin wrappers pin the /opt loaders, and here we pin
# the device TCTI the way a production mkinitfs image does.
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
# FDE_NEWROOT stays the production default (/sysroot). DEVIATION (documented):
# the harness mounts the unlocked root only later, in login_stage — the
# volume is still sealed while the hook runs — so the hook's Stage-2
# installed->provisional-booted marker flip cannot fire in-guest (it is
# unit-pinned in tests/unit/hooks_mkinitfs_unseal.sh; no e2e scenario asserts
# unseal_state_flip).
mkdir -p /sysroot /run/cryptsetup
if ! LUKS_UUID=$(cryptsetup luksUUID "$DISK" 2>/dev/null) || [ -z "$LUKS_UUID" ]; then
    echo "debian-fde-harness: cryptsetup luksUUID FAILED — cannot stage crypttab"
    echo "debian-fde: PROMPT-FAILED rc=1"
    sync
    busybox poweroff -f
fi
# /etc/crypttab in the production shape (lib/cmd/install.sh): the hook scans
# it for root/root<N> members and resolves the UUID= via /dev/disk/by-uuid
# (the initrd udevd above registered the links).
printf '%s\n' "root UUID=$LUKS_UUID none" > /etc/crypttab
echo "debian-fde-harness: crypttab staged: $(cat /etc/crypttab)"
# FDE_EXTRA_DIR: the signed .pcrsig travels on the payload drive
# (uki_pcrsig_disk) — stage it with the release public key at the hook's
# seam path. When the drive is missing, fall back to the UKI stub's
# synthetic /.extra sections (ukify bakes .pcrsig/.pcrpkey into the PE).
if [ -s /pcrsig.json ]; then
    mkdir -p /fde-extra
    cp /pcrsig.json /fde-extra/tpm2-pcr-signature.json
    cp /rel.pub /fde-extra/tpm2-pcr-public-key.pem
    FDE_EXTRA_DIR=/fde-extra
else
    FDE_EXTRA_DIR=/.extra
    echo "debian-fde-harness: payload pcrsig MISSING — FDE_EXTRA_DIR falls back to the stub /.extra"
fi
export FDE_EXTRA_DIR
echo "debian-fde-harness: invoking /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
sh /usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh
hook_rc=$?
if [ -e /dev/mapper/root ]; then
    echo "debian-fde: UNSEALED"
    # this reading is POST hook-extend: exactly the value the ukify
    # enter-initrd .pcrsig prediction covers (G-T13; the hook printed
    # unseal_pcrextend_ok above)
    echo "debian-fde-pcr-postphase sha256:11=$(pcr_hex 11)"
    if [ "$STAGE" = "login" ]; then
        login_stage   # exec switch_root — never returns on success
        echo "debian-fde: LOGIN-STAGE-FAILED"
        sync
        busybox poweroff -f
    fi
else
    # the hook NEVER leaves the volume open on refusal: it already ran its
    # 3-strike fail-closed poweroff (§8.2, no shell offered). This branch is
    # the belt for a nonzero hook exit that somehow returned — it must not
    # fall through to any shell.
    echo "debian-fde: PROMPT-FAILED rc=$hook_rc"
    sync
    busybox poweroff -f
fi
fi  # UNLOCK=hook / oracle
if [ -n "@@DEBUG_SHELL@@" ]; then
    echo "debian-fde-harness: DEBUG SHELL on console (input via serial)"
    exec /bin/sh </dev/console >/dev/console 2>&1
fi
echo "debian-fde-harness: powering off"
echo "debian-fde: POWEROFF"
sync
busybox poweroff -f
INIT
    # bake the module list (ordered, from modules.dep analysis at pin time)
    # and the rootfs artifact pins consumed by the S-00 installer stage
    sed -i "s/@@MODULES@@/$UKI_MODULES/" "$tree/init"
    sed -i "s/@@ROOTFS_SHA@@/${DEBIAN_FDE_ROOTFS_SHA:-none}/" "$tree/init"
    sed -i "s/@@ROOTFS_BYTES@@/${DEBIAN_FDE_ROOTFS_BYTES:-0}/" "$tree/init"
    # apk repositories drop (inst_repo_lines shape): DEBIAN_FDE_MIRROR is the
    # production mirror env (lib/cmd/install.sh), community = the sibling URL
    local apk_mirror="${DEBIAN_FDE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine/v3.24/main}"
    sed -i "s|@@APK_MIRROR@@|$apk_mirror|" "$tree/init"
    sed -i "s|@@APK_MIRROR_COMMUNITY@@|${apk_mirror%/main}/community|" "$tree/init"
    if [[ -n "${DEBIAN_FDE_DEBUG_SHELL:-}" ]]; then
        sed -i 's/@@DEBUG_SHELL@@/1/' "$tree/init"
    else
        sed -i 's/@@DEBUG_SHELL@@//' "$tree/init"
    fi
    chmod 755 "$tree/init"
}

# _uki_link_busybox <tree> — busybox lives at usr/bin/busybox in the deb;
# provide the /bin symlink + the tool names /init and the unseal hook use.
# (Debian's busybox-static also resolves applets from ash directly, but the
# explicit links keep the hook's PATH surface identical to a production
# mkinitfs image — features.d/alpine-fde.files has no busybox wildcard.)
_uki_link_busybox() {
    local tree="$1" a
    for a in sh mount insmod sleep poweroff grep awk mkdir \
             sed tr dd od head sha256sum mktemp chmod rm mv date stty cat; do
        ln -sfn busybox "$tree/usr/bin/$a"
    done
}

# uki_pcrsig_disk <out.img> <pcrsig.json> — raw payload drive carrying the
# signed PCR-policy JSON (read back by /init from /dev/vdc, see above).
uki_pcrsig_disk() {
    local out="$1" json="$2"
    truncate -s 64K "$out"
    dd if="$json" of="$out" conv=notrunc status=none
}

# uki_stage_login_drive <pcrsig-drive> — append the login-stage selector at
# offset 64 KiB of a pcrsig payload drive (the unmeasured stage channel /init
# reads, see uki_initrd_write_init). The drive grows to 128 KiB; the pcrsig
# region (first 64 KiB) and the hook's .pcrsig extraction are untouched, and
# s00b's tooling tail (offset 64 KiB, boot B only) is never combined with the
# marker — the two channels are mutually exclusive by construction.
uki_stage_login_drive() {
    local img="$1"
    truncate -s 128K "$img"
    printf 'login\n' | dd of="$img" bs=1 seek=65536 conv=notrunc status=none
}

# uki_initrd_inventory <initrd.cpio> — the initrd listing (I6 audit seam,
# G-E10): emit the cpio file list so the infra smoke can assert the inventory
# policy (no compilers, no package tools, no interactive shells beyond the
# busybox init shell) and print it as a machine-greppable line.
uki_initrd_inventory() {
    cpio -it --quiet <"$1"
}

# uki_initrd_pack <tree> <out.cpio> — pack the staging tree as newc cpio.
# Only the RUNTIME subset is packed (init, usr/{bin,lib,sbin}, opt/tpm,
# modules, payload files) — NOT the whole guest tree (which also holds the
# kernel image + the full modules tree + vmlinuz; packing it wholesale made a
# 171MiB UKI that the firmware could not chew through in TCG budget).
# /dev/console is included when the sandbox allows mknod (sudo); without it the
# init's exec-redirection fallback covers the missing node.
uki_initrd_pack() {
    local tree="$1" out="$2"
    local root="$tree/initrd-root"
    rm -rf "$root"
    mkdir -p "$root"
    # hardlink the runtime subtrees (cheap, same filesystem)
    for item in usr init kf0 rel.pub modules opt; do
        cp -al "$tree/$item" "$root/$item"
    done
    ln -sfn usr/bin "$root/bin"
    ln -sfn usr/sbin "$root/sbin"
    # ELF interpreter path baked into Debian binaries: /lib64/ld-linux-x86-64.so.2
    ln -sfn usr/lib/x86_64-linux-gnu "$root/lib64"
    mkdir -p "$root/proc" "$root/sys" "$root/run" "$root/tmp" "$root/etc"
    mkdir -p "$root/dev"
    if sudo -n mknod "$root/dev/console" c 5 1 2>/dev/null; then
        sudo -n chmod 600 "$root/dev/console"
    else
        rm -f "$root/dev/console"
        echo "uki-build: no mknod permission — /dev/console node omitted (init has fallback)" >&2
    fi
    (cd "$root" && find . -print0 | cpio -0 -o -H newc --quiet >"$out")
}

# uki_build <run-dir> <keys-dir> <out.efi> [extra-cmdline ...] — full pipeline:
#   guest tree -> initramfs -> ukify (pcr-signed) -> sbsign -> .pcrsig extract.
# Writes <run-dir>/uki-pcrsig.json (the signed prediction) on success.
# Optional extra args are APPENDED to the kernel cmdline (s12's
# `debian-fde-console-fallback` flag). They change the .cmdline section bytes,
# hence the PCR 11 prediction — ukify signs the new prediction, so the extra
# cmdline is not a tamper, it is a (signed) UKI variant.
uki_build() {
    local run="$1" kd="$2" out="$3"
    shift 3
    local extra_cmdline="${*:-}"
    local tree="$run/guest-tree"
    # Scope mktemp/ukify tempfiles to the RUN DIR (disk-backed), never /tmp:
    # the kernel-deb + guest-tree extractions peak near ~1 GB each, and /tmp
    # (tmpfs) has filled the machine mid-build (ENOSPC in pefile.write).
    # Cleaned with the run dir by the registry's run-dir pruning.
    export TMPDIR="$run/tmp"
    mkdir -p "$TMPDIR"
    uki_guest_tree "$tree" || return 1
    _uki_link_busybox "$tree"
    uki_initrd_write_init "$tree" || return 1
    # THE SHIPPED HOOK, at the ONE pinned features.d destination
    # (hooks/mkinitfs/features.d/alpine-fde.files — §8.2/ADR-13 staging
    # contract): the default unlock path runs exactly this file.
    local hook_dst="$tree/usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh"
    mkdir -p "${hook_dst%/*}"
    cp "$_UKI_REPO_ROOT/hooks/mkinitfs/alpine-fde-unseal.sh" "$hook_dst" || return 1
    chmod 755 "$hook_dst"
    # payload: slot-0 passphrase (verbatim, no trailing newline; used by
    # in-guest cryptenroll), release key, decompressed modules (the .pcrsig
    # JSON travels on its own drive, see uki_pcrsig_disk — NOT in the
    # initramfs, it would change its own prediction)
    printf '%s' "$DEBIAN_FDE_SLOT0_PASSPHRASE" >"$tree/kf0"
    chmod 600 "$tree/kf0"
    cp "$kd/release.pub" "$tree/rel.pub"
    local mdir="$tree/modules"
    mkdir -p "$mdir"
    local m src
    for m in $UKI_MODULES; do
        src=$(find "$tree/modules-tree" -name "$m.ko.xz" 2>/dev/null | head -1)
        if [[ -n "$src" ]]; then
            xz -dc "$src" >"$mdir/$m.ko"
        else
            echo "uki-build: module not found in kernel tree (builtin?): $m" >&2
        fi
    done
    uki_initrd_pack "$tree" "$run/initrd.cpio" || return 1
    # unseal-hook closure pin (§8.2 fixture): the packed initrd must carry the
    # hook, the features.d PATH names (/usr/bin/tpm2_* wrappers + /usr/bin/
    # openssl + cryptsetup), the /opt closures behind them and the device
    # TCTI — cross-checked against hooks/mkinitfs/features.d/alpine-fde.files.
    local inv need
    inv=$(uki_initrd_inventory "$run/initrd.cpio")
    for need in usr/share/alpine-fde/mkinitfs/alpine-fde-unseal.sh \
                usr/bin/openssl opt/ssl/bin/openssl opt/ssl/ld-linux-x86-64.so.2 \
                usr/sbin/cryptsetup \
                usr/bin/tpm2_pcrextend usr/bin/tpm2_startauthsession \
                usr/bin/tpm2_policypcr usr/bin/tpm2_policyauthorize \
                usr/bin/tpm2_loadexternal usr/bin/tpm2_verifysignature \
                usr/bin/tpm2_createprimary usr/bin/tpm2_load \
                usr/bin/tpm2_unseal usr/bin/tpm2_flushcontext \
                opt/tpm/bin/tpm2_pcrextend opt/tpm/bin/tpm2_startauthsession \
                opt/tpm/bin/tpm2_policypcr opt/tpm/bin/tpm2_policyauthorize \
                opt/tpm/bin/tpm2_loadexternal opt/tpm/bin/tpm2_verifysignature \
                opt/tpm/bin/tpm2_createprimary opt/tpm/bin/tpm2_load \
                opt/tpm/bin/tpm2_unseal opt/tpm/bin/tpm2_flushcontext \
                opt/tpm/lib/libtss2-tcti-device.so.0; do
        if ! grep -qx "$need" <<<"$inv"; then
            echo "uki-build: initrd closure pin FAILED — missing: $need" >&2
            return 1
        fi
    done
    echo "uki-build: unseal-hook closure pinned (hook + 10 tpm2 verbs + openssl + cryptsetup); initrd $(du -k "$run/initrd.cpio" | cut -f1) KiB"
    # cmdline + os-release inputs
    printf 'ID=debian-fde-harness\nVERSION_ID=1\nNAME=Debian FDE harness UKI\n' >"$run/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE${extra_cmdline:+ $extra_cmdline}" >"$run/cmdline.txt"
    # enter-initrd PCR 11 prediction for THIS exact build (ukify --measure,
    # the same inputs the .pcrsig pol entries are derived from). Consumed by
    # the finalized {7,11} enrollment composition (uki_pcrsig_append_combined)
    # — policypcr{7,11} at unlock time must see exactly this value.
    if ! ukify build --linux="$tree/vmlinuz" --initrd="$run/initrd.cpio" \
            --cmdline="@$run/cmdline.txt" --os-release="@$run/os-release.txt" \
            --measure --phases enter-initrd --pcr-banks=sha256 \
            --pcr-private-key="$kd/db.key" \
            --output="$run/measure-throwaway.efi" >"$run/pcr11-measure.txt" 2>&1; then
        echo "uki-build: ukify --measure (enter-initrd prediction) failed:" >&2
        cat "$run/pcr11-measure.txt" >&2
        return 1
    fi
    local d11
    d11=$(sed -n 's/^11:sha256=\([0-9a-f]\{64\}\)$/\1/p' "$run/pcr11-measure.txt" | head -1)
    if [[ -z "$d11" ]]; then
        echo "uki-build: cannot parse the ukify --measure output:" >&2
        cat "$run/pcr11-measure.txt" >&2
        return 1
    fi
    printf '%s\n' "$d11" >"$run/pcr11-enter-initrd.txt"
    # 1) unsigned build (structure sanity)
    ukify build --linux="$tree/vmlinuz" --initrd="$run/initrd.cpio" \
        --cmdline="@$run/cmdline.txt" --os-release="@$run/os-release.txt" \
        --output="$run/uki-unsigned.efi" >/dev/null || {
        echo "uki-build: ukify (unsigned) failed" >&2
        return 1
    }
    # 2) signed UKI: PCR prediction signed by the release key (.pcrsig/.pcrpkey)
    ukify build --linux="$tree/vmlinuz" --initrd="$run/initrd.cpio" \
        --cmdline="@$run/cmdline.txt" --os-release="@$run/os-release.txt" \
        --pcr-banks=sha256 --pcr-private-key="$kd/db.key" --pcr-public-key="$kd/release.pub" \
        --output="$run/uki-pcrsigned.efi" >/dev/null || {
        echo "uki-build: ukify (pcr-signed) failed" >&2
        return 1
    }
    # 3) extract .pcrsig JSON (the signed enter-initrd prediction) -> payload drive
    objcopy -O binary --only-section=.pcrsig "$run/uki-pcrsigned.efi" "$run/uki-pcrsig.json" || {
        echo "uki-build: .pcrsig extraction failed" >&2
        return 1
    }
    uki_pcrsig_disk "$run/pcrsig.img" "$run/uki-pcrsig.json" || return 1
    # 4) outer Secure Boot signature (same release identity, ADR-11)
    sbsign --key "$kd/db.key" --cert "$kd/db.crt" --output "$out" \
        "$run/uki-pcrsigned.efi" >/dev/null || {
        echo "uki-build: sbsign failed" >&2
        return 1
    }
    return 0
}

# vars_set_boot_entry_optdata <vars.fd> <efi-path> <optdata> — replace OVMF's
# fallback boot entries with ONE full-device-path entry for <efi-path> whose
# OptionalData carries <optdata>. The firmware hands OptionalData to the
# loaded image as LoadOptions; systemd-stub appends them to the embedded
# .cmdline and MEASURES THE COMBINED STRING into PCR 11 — the §12 "tampered
# loader options" vector (the evil maid editing boot options in firmware
# setup). A FULL device path is required: OVMF's BDS drops OptionalData when
# it EXPANDS short-form (media-file-path-only) entries — observed live
# (2026-09-14): the base path is therefore reused from OVMF's own Boot0002.
# Used by s07 with the TAMPERED cmdline.
vars_set_boot_entry_optdata() {
    local vars="$1" efi="$2" optdata="$3"
    python3 - "$vars" "$efi" "$optdata" <<'VEOF'
import sys
from virt.firmware.varstore import autodetect
from virt.firmware.efi import devpath

fd, efi, optdata = sys.argv[1], sys.argv[2], sys.argv[3]
store = autodetect.open_varstore(fd)
varlist = store.get_varlist()

base = varlist["Boot0002"].data          # OVMF's own fallback entry
fpl = int.from_bytes(base[4:6], "little")
i = 6
while base[i:i + 2] != b"\x00\x00":
    i += 2
i += 2
dp = devpath.DevicePath(base[i:i + fpl])  # ctor stops at the END node
elem = devpath.DevicePathElem()
elem.set_filepath(efi)
dp.append(elem)

for name in ("Boot0002", "Boot0003", "Boot0004"):
    varlist.delete(name)

title = "Debian FDE harness (tampered options)"
varlist.set_boot_entry(0x0002, title, dp, optdata.encode("utf-16-le"))
store.write_varstore(fd, varlist)
VEOF
    local rc=$?
    ((rc != 0)) && echo "uki-build: boot-entry OptionalData edit failed (rc=$rc)" >&2
    return $rc
}

# esp_make <out.img> <mib> <uki.efi> — file-backed FAT32 ESP with the UKI at
# the firmware's removable-media path (\EFI\BOOT\BOOTX64.EFI). No systemd-boot
# this wave (Wave 2 installs it for loader/rollback scenarios).
esp_make() {
    local out="$1" mib="$2" uki="$3"
    truncate -s "${mib}M" "$out"
    mkfs.vfat -F32 "$out" >/dev/null || {
        echo "uki-build: mkfs.vfat failed" >&2
        return 1
    }
    mmd -i "$out" ::/EFI ::/EFI/BOOT 2>/dev/null
    mcopy -i "$out" "$uki" "::/EFI/BOOT/BOOTX64.EFI" || {
        echo "uki-build: mcopy failed" >&2
        return 1
    }
    return 0
}

# rootfs_payload_image <out.img> — build the §12 S-00 rootfs payload drive: a
# raw image whose LEADING bytes ARE the SHA256-pinned Alpine rootfs payload
# (MiB-aligned with zero padding — virtio-blk capacity is 512-byte granular and
# an unaligned image would be rounded DOWN, truncating the payload; /init dd's
# the device whole, trims back to the payload size and hash-verifies against
# the @@ROOTFS_SHA@@ pin baked at build time). Prints "<sha256> <bytes>"; the
# S-00 scenario passes both back via DEBIAN_FDE_ROOTFS_SHA / DEBIAN_FDE_ROOTFS_
# BYTES before calling uki_build with the `debian-fde-stage=install` word.
#
# DERIVED PAYLOAD (G-E1, ADR-12/§12): the PINNED upstream artifact is the
# Alpine minirootfs (tests/lib/alpine-artifact.sh — downloaded once,
# SHA256-verified, fail-closed). The §3.3 additions set cannot be pre-installed
# without apk transactions, so the harness payload = mini rootfs + the
# alpine-fde tooling tree (production inst_tooling_copy_cmd shape:
# bin/lib/hooks/docs -> /opt/debian-fde + /usr/local/bin symlinks) + the
# host-closure stub binaries (the s00b "/opt" pattern: tpm2 multitool, jq,
# flock — each with its own ld-linux + ldd closure, wrapped from
# /usr/local/bin; a musl guest cannot execute the host's glibc builds
# directly). Assembled HOST-side, ONCE (cached): alpine_artifact_extract
# (hash-verified) -> tooling copy -> stub closures -> mtime normalization ->
# root-owned ustar re-tar -> `gzip -n` (no mtime/name => byte-stable). The
# derived payload carries a sidecar sha256 verified on every reuse (MD-07: a
# corrupted cached payload must never propagate into a UKI silently).
# Cache: <alpine-artifact cache>/alpine-fde-payload-rootustar.tar.gz.
rootfs_payload_image() {
    local out="$1"
    local derived="$ALPINE_ARTIFACT_CACHE_DIR/alpine-fde-payload-rootustar.tar.gz"
    local derived_sha="$derived.sha256"
    local sha bytes aligned
    if [[ -f "$derived" && -f "$derived_sha" ]] \
        && [[ "$(sha256sum "$derived" | awk '{print $1}')" == "$(awk '{print $1}' "$derived_sha")" ]]; then
        :
    else
        if [[ -f "$derived" ]]; then
            echo "uki-build: derived payload cache failed its sidecar-sha check — re-deriving" >&2
        fi
        rm -f "$derived" "$derived_sha"
        echo "uki-build: deriving the Alpine payload (pinned minirootfs + tooling + stubs; one-time, cached) ..." >&2
        local tmp
        tmp=$(mktemp -d) || return 1
        # 1. the pinned, hash-verified mini rootfs
        if ! alpine_artifact_extract "$tmp/tree"; then
            rm -rf "$tmp"
            return 1
        fi
        # 2. the alpine-fde tooling tree — the production inst_tooling_copy_cmd
        #    shape (explicit per-dir copies: bin lib hooks docs; never descends
        #    into VCS/harness residue)
        local tree="$tmp/tree" d repo_root
        repo_root=$(cd "$_HERE/../.." && pwd)
        mkdir -p "$tree/opt/debian-fde" "$tree/usr/local/bin"
        for d in bin lib hooks docs; do
            mkdir -p "$tree/opt/debian-fde/$d"
            if ! cp -r "$repo_root/$d/." "$tree/opt/debian-fde/$d/"; then
                rm -rf "$tmp"
                echo "uki-build: tooling copy failed: $d" >&2
                return 1
            fi
        done
        ln -sfn /opt/debian-fde/bin/debian-fde "$tree/usr/local/bin/debian-fde"
        ln -sfn /opt/debian-fde/bin/alpine-fde "$tree/usr/local/bin/alpine-fde"
        # 3. stub binaries — the s00b /opt host-closure pattern
        if ! _uki_payload_stub "$tree" tpm2 /opt/tpm/bin /usr/local/bin/tpm2 \
            || ! _uki_payload_stub "$tree" jq /opt/jqbin /usr/local/bin/jq \
            || ! _uki_payload_stub "$tree" flock /opt/flockbin /usr/local/bin/flock; then
            rm -rf "$tmp"
            return 1
        fi
        # 4. deterministic root-owned ustar + gzip -n payload artifact.
        #    Normalize every mtime to epoch or the derived artifact (and the
        #    @@ROOTFS_SHA@@ baked into the S-00 UKI) changes on every
        #    regeneration.
        find "$tree" -exec touch -h -d @0 {} +
        # MD-07: unique temp (concurrent invocations never share a .part path)
        local tmpout
        tmpout=$(mktemp "$ALPINE_ARTIFACT_CACHE_DIR/.alpinepayload.part.XXXXXX") || { rm -rf "$tmp"; return 1; }
        if ! (cd "$tree" && tar --format=ustar --owner=0 --group=0 --numeric-owner \
            -cf - . | gzip -n >"$tmpout"); then
            rm -rf "$tmp" "$tmpout"
            echo "uki-build: alpine payload re-containerization failed" >&2
            return 1
        fi
        rm -rf "$tmp"
        sha256sum "$tmpout" | awk '{print $1}' >"$tmpout.sha"
        mv "$tmpout" "$derived"
        mv "$tmpout.sha" "$derived_sha"
    fi
    sha=$(sha256sum "$derived" | awk '{print $1}')
    bytes=$(stat -c%s "$derived")
    aligned=$(((bytes + 1048575) / 1048576 * 1048576))
    cp -f "$derived" "$out" || {
        echo "uki-build: rootfs payload image build failed" >&2
        return 1
    }
    truncate -s "$aligned" "$out"
    printf '%s %s\n' "$sha" "$bytes"
}

# _uki_payload_stub <tree> <tool> <optdir> <wrapper-path> — copy one HOST
# binary into the payload with its own loader + full ldd closure (the s00b
# "/opt" pattern): a musl guest cannot run the host's glibc-linked build
# directly, so the stub is invoked via the wrapper which pins the isolated
# loader and library path.
_uki_payload_stub() {
    local tree="$1" tool="$2" optdir="$3" wrapper="$4"
    local src interp l
    src=$(command -v "$tool") || {
        echo "uki-build: stub tool not found on host: $tool" >&2
        return 1
    }
    mkdir -p "$tree/$optdir/lib" "$tree$(dirname "$wrapper")"
    cp -L "$src" "$tree/$optdir/$(basename "$src")" || return 1
    interp=$(ldd "$src" | awk '/ld-linux/{print $1}')
    cp -L "$interp" "$tree/$optdir/ld-linux" || return 1
    for l in $(ldd "$src" | awk '$3 ~ /^\// {print $3}'); do
        cp -L "$l" "$tree/$optdir/lib/" || return 1
    done
    printf '#!/bin/sh\nexec %s/ld-linux --library-path %s/lib %s/%s "$@"\n' \
        "$optdir" "$optdir" "$optdir" "$(basename "$src")" >"$tree$wrapper"
    chmod 755 "$tree$wrapper"
}

# uki_pcrsig_enter_initrd_pol <pcrsig.json> — the .pcrsig entry the unlock
# consumes: ukify's default 4-phase ladder signs `enter-initrd` FIRST (entries
# carry no phase field; index 0 == enter-initrd — pinned empirically,
# tests/e2e/README.md "Wave-2 unlock resolution").
uki_pcrsig_enter_initrd_pol() { jq -r '.sha256[0].pol' "$1"; }

# uki_pcr11_policy_digest <pcr11-hex> — the {11}-selection PolicyPCR policy
# digest over a PCR 11 VALUE (the consumer's session-digest formula, TPM 2.0
# marshaling per tests/unit/policy_digest_golden.sh: zero32 ‖ CC_PolicyPCR ‖
# TPML{sha256, pcr 11 -> 00 08 00} ‖ SHA256(pcrValue); live-TPM cross-checked
# there). G-T13: this over the guest's PRE-UNLOCK (post-phase-word) reading
# must equal uki_pcrsig_enter_initrd_pol of the booted UKI's .pcrsig.
uki_pcr11_policy_digest() {
    python3 - "$1" <<'PYEOF'
import hashlib, sys
d11 = bytes.fromhex(sys.argv[1])
zero32 = bytes(32)
cc_pcr = (0x17F).to_bytes(4, "big")
tpml_11 = bytes.fromhex("00000001000b03000800")
print(hashlib.sha256(zero32 + cc_pcr + tpml_11 + hashlib.sha256(d11).digest()).hexdigest())
PYEOF
}

# uki_pcrsig_append_combined <in.json> <out.json> <d7hex> <d11hex> <keydir> —
# append the §6.1.1 COMBINED {PCR 7, PCR 11} entry to a ukify .pcrsig: the
# policy_digest over (d7, d11) release-signed exactly the way `pcrsign`
# (lib/cmd/pcrsign.sh) signs a finalized enrollment — policy_digest_bin |
# openssl dgst -sha256 -sign. This is the entry a finalized Mechanism B token
# (enrl_run -> seal_finalized, G-B6) requires in DEBIAN_FDE_PCRSIG, and the
# entry the §8.2 hook extracts for a {7,11}-selection token. NOT a fantasy
# shape: identical fields (pcrs/pkfp/pol/sig — plus the digest-anchor fields
# d7/d11 the shipped CLI's policy_sign_json also records) and signing recipe
# as the shipped CLI, composed host-side because the harness UKI build never
# runs pcrsign (no release.pem in the fixture keydir — db.key IS the release
# key, ADR-11; s18's staled7 control already signs with it).
uki_pcrsig_append_combined() {
    local in=$1 out=$2 d7=$3 d11=$4 kd=$5
    local pol sig pkfp bin
    pol=$(policy_digest "$d7" "$d11") || return 1
    bin=$(mktemp "${TMPDIR:-/tmp}/uki-pcrsig-pol.XXXXXX") || return 1
    sig=$(mktemp "${TMPDIR:-/tmp}/uki-pcrsig-sig.XXXXXX") || { rm -f "$bin"; return 1; }
    policy_digest_bin "$d7" "$d11" >"$bin" || { rm -f "$bin" "$sig"; return 1; }
    openssl dgst -sha256 -sign "$kd/db.key" -out "$sig" "$bin" 2>/dev/null || {
        rm -f "$bin" "$sig"; return 1; }
    sig=$(openssl base64 -A -in "$sig") || { rm -f "$bin" "$sig"; return 1; }
    rm -f "$bin" "$sig"
    # pkfp = SHA256 over the PKCS#1 RSAPublicKey DER — the exact form
    # systemd-measure fingerprints (matches the ukify-built entries' pkfp)
    pkfp=$(openssl rsa -pubin -in "$kd/release.pub" -RSAPublicKey_out -outform DER 2>/dev/null \
        | sha256sum | cut -d' ' -f1)
    local entry
    entry=$(jq -n --arg pol "$pol" --arg sig "$sig" --arg pkfp "$pkfp" \
        --arg d7 "$d7" --arg d11 "$d11" \
        '{pcrs: [7, 11], pkfp: $pkfp, pol: $pol, sig: $sig, d7: $d7, d11: $d11}') || return 1
    jq --argjson entry "$entry" '.sha256 += [$entry]' "$in" >"$out" || return 1
}

# uki_state_pcr7 <state-dir> — the ENROLLED PCR 7 reading for a state contract
# directory: baseline.json's finalized expected_pcr7 (written by `audit
# --init` after the first enrolled boot). Never consults live TPM state.
uki_state_pcr7() {
    jq -r '.expected_pcr7 // empty' "$1/baseline.json" 2>/dev/null
}

# uki_release_key_floor <keydir> — pin the fixture release identity to the
# ADR-16 RSA floor (lib/keys.sh keys_rsa3072_guard refuses to enroll anything
# smaller). Regenerates db.key/db.crt/release.pub AT 3072 when the fixture
# came up smaller — the SAME one identity (ADR-11), re-issued before
# keys_vars_enrolled / sbsign / ukify ever see it. No-op once the fixture
# itself generates >= 3072.
uki_release_key_floor() {
    local kd=$1 bits
    [[ -f "$kd/release.pub" ]] || { echo "uki-build: no release.pub under $kd" >&2; return 1; }
    bits=$(openssl pkey -pubin -in "$kd/release.pub" -text -noout 2>/dev/null \
        | sed -n 's/^Public-Key: (\([0-9]*\) bit)/\1/p')
    [[ "$bits" =~ ^[0-9]+$ ]] || { echo "uki-build: cannot read RSA modulus size from $kd/release.pub" >&2; return 1; }
    ((bits >= 3072)) && return 0
    (
        umask 077
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
            -out "$kd/db.key" 2>/dev/null &&
            openssl req -x509 -new -key "$kd/db.key" -days 30 \
                -subj "/CN=debian-fde-test-release" -out "$kd/db.crt" 2>/dev/null &&
            openssl x509 -in "$kd/db.crt" -pubkey -noout >"$kd/release.pub"
    ) || { echo "uki-build: release-key floor reissue FAILED" >&2; return 1; }
}

# uki_wait_hook_prompt <n> <timeout-s> <dir> — wait until the unseal hook has
# printed its nth recovery-passphrase prompt (the hook's `read` has NO
# timeout, so serial feeding must be prompt-synchronized). Counts occurrences
# of the pinned unseal_prompt_re shape instead of digit matching (kernel
# printk can split console lines mid-print).
# QEMU-LIVENESS (s02/s04 registry stalls, 2026-09-22): every iteration checks
# the boot's qemu pid — if qemu died the prompt can NEVER appear, so the loop
# fails LOUDLY and immediately (QEMU-DIED + console tail) instead of silently
# burning the full budget. rc contract unchanged (1 = prompt not seen).
uki_wait_hook_prompt() {
    local n=$1 tmo=$2 dir=$3 i=0 c re qpid
    re=$(sentinel_of unseal_prompt_re)
    while ((i < tmo)); do
        c=$(grep -cE "$re" "$dir/console.log" 2>/dev/null || true)
        [[ -n "$c" ]] && ((c >= n)) && return 0
        qpid=$(cat "$dir/qemu.pid" 2>/dev/null || true)
        if [[ -z "$qpid" ]] || ! kill -0 "$qpid" 2>/dev/null; then
            echo "QEMU-DIED: qemu (pid ${qpid:-<none>}) is gone before prompt $n/$n" >&2
            echo "QEMU-DIED console tail: $(tail -5 "$dir/console.log" 2>/dev/null | tr '\n' ' ')" >&2
            return 1
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# uki_host_enroll_finalized <efivars-dir> <pcrsig.json> <luks-dev-or-uuid>
#                           <keydir> <slot0-keyfile> [state-root] — run the
# REAL production CLI enroll-tpm host-side against the fixture swtpm
# (DEBIAN_FDE_TCTI=SWTPM_TCTI, exported by swtpm_start), producing the
# finalized {7,11} Mechanism B token the §8.2 hook consumes. The caller must
# have: a finalized baseline expected_pcr7 (uki_baseline_stamp — the booted
# console's PCR 7) and composed <pcrsig.json> via uki_pcrsig_append_combined.
# DIGEST-ANCHORED (Option A): the drift precondition and seal_finalized's
# G-B6 gate are pure data comparisons over the entry's recorded d7/d11
# components — NO live TPM PCR state is consulted, so the swtpm may have been
# restarted (swtpm_ensure) before this runs; no swtpm_seed_pcrs reseed is
# needed. The TPM itself must still be serving (getcap probe + SRK seal).
uki_host_enroll_finalized() {
    local efivars=$1 pcrsig=$2 dev=$3 keydir=$4 keyfile=$5 root=${6:-}
    DEBIAN_FDE_ROOT="$root" \
        DEBIAN_FDE_TCTI="${SWTPM_TCTI:?uki_host_enroll_finalized: swtpm not started}" \
        DEBIAN_FDE_EFIVARS_DIR="$efivars" \
        DEBIAN_FDE_KEYDIR="$keydir" \
        DEBIAN_FDE_LUKS_KEYFILE="$keyfile" \
        DEBIAN_FDE_NO_INSTALL=1 \
        "$_UKI_REPO_ROOT/bin/debian-fde" enroll-tpm --uuid "$dev" --pcrsig "$pcrsig"
}

# uki_baseline_stamp <root> <pcr7hex> — write the finalized baseline.json
# (schema v1, s00 shape) with expected_pcr7 stamped from the booted console —
# the OPERATOR-meaningful value is the BOOTED machine's PCR 7, never the
# restarted fixture's. enrl_preconditions compares live-vs-this at enroll.
uki_baseline_stamp() {
    local root=$1 pcr7=$2 dir
    dir="$root/etc/alpine-fde"
    mkdir -p "$dir"
    cat >"$dir/baseline.json" <<JSON
{
  "schema_version": "1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pcr0": "pending",
  "pcr1": "pending",
  "pcr2": "pending",
  "pcr3": "pending",
  "expected_pcr7": "$pcr7",
  "sb_state": {
    "secure_boot": "1",
    "setup_mode": "0",
    "pk_fp": "",
    "kek_fp": "",
    "db_fp": "",
    "dbx_fp": ""
  },
  "fw": {
    "vendor": "Bochs",
    "version": "Bochs",
    "eventlog_sha256": "",
    "eventlog_size": ""
  },
  "keys": {
    "release_pub_path": "",
    "release_cert_path": ""
  },
  "target": {
    "luks_uuid": "",
    "esp_partuuid": ""
  }
}
JSON
}
