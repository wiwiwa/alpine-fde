#!/usr/bin/env bash
# tests/lib/uki-build.sh — minimal harness UKI builder for the Debian FDE e2e
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
# shellcheck source=lib/rootfs-fixture.sh
source "$_HERE/rootfs-fixture.sh"
# shellcheck source=lib/disk-fixture.sh
source "$_HERE/disk-fixture.sh"

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
    # host tpm2 closure, isolated under /opt/tpm with its own loader
    # (pcrread for the console PCR prints; pcrextend as the enter-initrd
    # fallback when systemd-pcrextend fails — same lib set, one walk)
    mkdir -p "$dest/opt/tpm/bin" "$dest/opt/tpm/lib"
    cp -L "$(command -v tpm2_pcrread)" "$dest/opt/tpm/bin/tpm2_pcrread"
    cp -L "$(command -v tpm2_pcrextend)" "$dest/opt/tpm/bin/tpm2_pcrextend"
    local interp
    interp=$(ldd "$dest/opt/tpm/bin/tpm2_pcrread" | awk '/ld-linux/{print $1}')
    cp -L "$interp" "$dest/opt/tpm/ld-linux-x86-64.so.2"
    local l
    for l in $(ldd "$dest/opt/tpm/bin/tpm2_pcrread" | awk '$3 ~ /^\// {print $3}'); do
        cp -L "$l" "$dest/opt/tpm/lib/"
    done
    # the device TCTI is dlopen'd (with its VERSIONED soname), ldd does not
    # show it — keep the .0 filename or tctildr's dlopen fails
    for l in /usr/lib/libtss2-tcti-device.so.0 /usr/lib/libtss2-tcti-swtpm.so.0; do
        [[ -f "$l" ]] && cp -L "$l" "$dest/opt/tpm/lib/"
    done
    # closure gate (guest binaries only; /opt/tpm resolves via its own loader)
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
        "$dest/opt/tpm/bin/tpm2_pcrextend" 2>/dev/null | grep -v '/opt/tpm' || true)
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

# signed-PCR-policy JSON: delivered on the raw payload drive (/dev/vdc)
if [ -b /dev/vdc ]; then
    busybox dd if=/dev/vdc bs=4096 count=16 2>/dev/null | busybox tr -d '\000' > /pcrsig.json
fi
[ -s /pcrsig.json ] && echo "debian-fde-harness: pcrsig payload loaded ($(busybox wc -c < /pcrsig.json) bytes): $(head -c 60 /pcrsig.json)" || echo "debian-fde-harness: pcrsig payload MISSING"
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

# extend PCR 11 with the enter-initrd PHASE WORD before any unlock attempt —
# exactly what a production initrd does (systemd-pcrphase-initrd.service:
# `systemd-pcrextend --graceful enter-initrd`, Before=cryptsetup.target).
# ukify's phase=enter-initrd .pcrsig prediction INCLUDES this extension, so
# without it the consumer's find_signature() can never match (Wave-2 root
# cause; see tests/e2e/README.md). Primary: real 257.13 systemd-pcrextend
# (needs efivarfs for the stub-measured check). The PCR VALUE decides, not
# the rc: if PCR 11 did not change, fall back to extending H("enter-initrd")
# via the host tpm2-tools closure — the extend value is identical (the PCR
# does not care which tool computed it).
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

DISK=/dev/vdb

# ---- §12 S-00 installer stage (cmdline: debian-fde-stage=install) -------------
# The one-time PASSPHRASE unlock of the freshly laid LUKS2 volume (the only
# documented first-boot prompt; here fed from the embedded /kf0, ZERO console
# input — no enrollment exists yet), then populate the minimal rootfs (§3.3)
# from the SHA256-pinned Debian rootfs artifact and power off. NO enrollment and
# NO token unlock in this stage: `audit --init` finalizes the baseline first
# (S-00, host side) and the S-00b boot enrolls from the guest afterwards.
# The pinned artifact travels on a raw payload drive (vdc for this stage — the
# token unlock never runs here, so the .pcrsig drive slot is free; embedding
# the artifact in the initramfs is infeasible: a 171MiB UKI already proved
# beyond the firmware's TCG budget, see uki_initrd_pack).
installer_stage() {
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
    echo "debian-fde-install: populating rootfs from the pinned Debian artifact (§3.3)"
    gzip -dc /rootfs.tar | tar -xf - -C /newroot || {
        echo "debian-fde-install: rootfs untar FAILED"; return 1; }
    # §3.3: apt policy + dpkg trims + networkd/resolved + serial getty
    mkdir -p /newroot/etc/systemd/network /newroot/etc/systemd/system/multi-user.target.wants \
             /newroot/etc/apt/apt.conf.d /newroot/etc/dpkg/dpkg.cfg.d
    printf 'APT::Install-Recommends "false";\nAPT::Install-Suggests "false";\nAcquire::Languages "none";\n' \
        >/newroot/etc/apt/apt.conf.d/99debian-fde-minimal
    printf 'path-exclude=/usr/share/doc/*\npath-exclude=/usr/share/man/*\n' \
        >/newroot/etc/dpkg/dpkg.cfg.d/99debian-fde-minimal
    printf '[Match]\nName=en* eth*\n\n[Network]\nDHCP=yes\n' \
        >/newroot/etc/systemd/network/20-debian-fde.network
    ln -sfn /usr/lib/systemd/system/systemd-networkd.service \
        /newroot/etc/systemd/system/multi-user.target.wants/systemd-networkd.service
    ln -sfn /usr/lib/systemd/system/systemd-resolved.service \
        /newroot/etc/systemd/system/multi-user.target.wants/systemd-resolved.service
    ln -sfn /usr/lib/systemd/system/serial-getty@.service \
        /newroot/etc/systemd/system/multi-user.target.wants/serial-getty@ttyS0.service
    echo "debian-fde-install: getty/networkd configured (§3.3)"
    # §9.1 mountpoints inside @ — the fstab entries below mount @home and
    # @snapshots here at boot. Plus the btrfs userspace: production §9.1
    # apt-installs btrfs-progs in-chroot for btrfs roots; the harness ships
    # the pinned binaries instead (fsck.btrfs satisfies the fstab passno-2
    # entries at boot, `btrfs` powers the pre-upgrade snapshots §9.3).
    mkdir -p /newroot/home /newroot/.snapshots
    mkdir -p /newroot/usr/bin /newroot/usr/sbin /newroot/usr/lib/x86_64-linux-gnu
    cp /usr/bin/btrfs /newroot/usr/bin/btrfs
    cp /usr/sbin/mkfs.btrfs /newroot/usr/sbin/mkfs.btrfs
    cp -P /usr/sbin/fsck.btrfs /newroot/usr/sbin/fsck.btrfs 2>/dev/null \
        || busybox ln -sf ../bin/btrfs /newroot/usr/sbin/fsck.btrfs
    for _l in /usr/lib/x86_64-linux-gnu/liblzo2.so.2*; do
        cp -a "$_l" /newroot/usr/lib/x86_64-linux-gnu/
    done
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
    # cloud-init probes DHCP before multi-user.target (minutes under TCG,
    # degraded boots) — the official kill switch:
    mkdir -p /newroot/etc/cloud
    : > /newroot/etc/cloud/cloud-init.disabled
    echo "debian-fde-install: fstab (§9.1 subvol=@/@home/@snapshots) + cloud-init.disabled written"
    # console proof of the on-disk fstab forms (asserted verbatim by S-00)
    while read -r _fl; do
        case "$_fl" in \#*) continue ;; esac
        echo "debian-fde-btrfs: fstab| $_fl"
    done < /newroot/etc/fstab
    # machine-readable installed size + package count (§3.3 budget, asserted by S-00)
    echo "debian-fde-rootfs: kib=$(du -sk /newroot | cut -f1) packages=$(grep -c '^Package: ' /newroot/var/lib/dpkg/status)"
    # §9.1 subvolume presence — the on-disk evidence S-00 asserts (the mounted
    # root IS the @ subvolume; the list shows every subvolume on the volume)
    echo "debian-fde-btrfs: subvolume list (on-disk evidence):"
    btrfs subvolume list /newroot || {
        echo "debian-fde-install: btrfs subvolume list FAILED"; return 1; }
    # I2/I4 disk-side scan: no private key material anywhere on the LUKS payload.
    #   keyfiles: .pem/.key OUTSIDE the public trust store (the Debian CA
    #     bundle ships hundreds of PUBLIC .pem certs — /etc/ssl/certs,
    #     /usr/lib/ssl/certs{,/cert.pem} — those are not key material);
    #   pem: PRIVATE-KEY PEM headers at LINE START (real PEM files open the
    #     header at column 1) in TEXT files only (grep -I) — unanchored greps
    #     false-positive on openssh/gnutls BINARIES (the header string as a
    #     code literal), on a python cryptography constant and on INDENTED
    #     sample keys in cloud-init doc examples (all observed live
    #     2026-09-17 against this exact tree).
    echo "debian-fde-scan: keyfiles=$(find /newroot \( -path /newroot/etc/ssl/certs -o -path /newroot/usr/lib/ssl/certs -o -path /newroot/usr/lib/ssl/cert.pem \) -prune -o \( -name '*.pem' -o -name '*.key' \) -print | wc -l) pem=$(grep -rIlE '^-----BEGIN [A-Z ]*PRIVATE KEY-----' /newroot 2>/dev/null | wc -l)"
    busybox umount /newroot
    /usr/sbin/cryptsetup close root
    return 0
}

STAGE=boot
for _w in $(cat /proc/cmdline); do
    case "$_w" in debian-fde-stage=*) STAGE=${_w#debian-fde-stage=} ;;
    esac
done
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
    if [[ -n "${DEBIAN_FDE_DEBUG_SHELL:-}" ]]; then
        sed -i 's/@@DEBUG_SHELL@@/1/' "$tree/init"
    else
        sed -i 's/@@DEBUG_SHELL@@//' "$tree/init"
    fi
    chmod 755 "$tree/init"
}

# _uki_link_busybox <tree> — busybox lives at usr/bin/busybox in the deb;
# provide the /bin symlink + the tool names /init uses.
_uki_link_busybox() {
    local tree="$1"
    ln -sfn busybox "$tree/usr/bin/sh"
    ln -sfn busybox "$tree/usr/bin/mount"
    ln -sfn busybox "$tree/usr/bin/insmod"
    ln -sfn busybox "$tree/usr/bin/sleep"
    ln -sfn busybox "$tree/usr/bin/poweroff"
    ln -sfn busybox "$tree/usr/bin/grep"
    ln -sfn busybox "$tree/usr/bin/awk"
    ln -sfn busybox "$tree/usr/bin/mkdir"
}

# uki_pcrsig_disk <out.img> <pcrsig.json> — raw payload drive carrying the
# signed PCR-policy JSON (read back by /init from /dev/vdc, see above).
uki_pcrsig_disk() {
    local out="$1" json="$2"
    truncate -s 64K "$out"
    dd if="$json" of="$out" conv=notrunc status=none
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
    uki_guest_tree "$tree" || return 1
    _uki_link_busybox "$tree"
    uki_initrd_write_init "$tree" || return 1
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
    # cmdline + os-release inputs
    printf 'ID=debian-fde-harness\nVERSION_ID=1\nNAME=Debian FDE harness UKI\n' >"$run/os-release.txt"
    printf '%s\n' "$UKI_KERNEL_CMDLINE${extra_cmdline:+ $extra_cmdline}" >"$run/cmdline.txt"
    # 1) unsigned build (structure sanity)
    ukify build --linux="$tree/vmlinuz" --initrd="$run/initrd.cpio" \
        --cmdline="@$run/cmdline.txt" --os-release="$run/os-release.txt" \
        --output="$run/uki-unsigned.efi" >/dev/null || {
        echo "uki-build: ukify (unsigned) failed" >&2
        return 1
    }
    # 2) signed UKI: PCR prediction signed by the release key (.pcrsig/.pcrpkey)
    ukify build --linux="$tree/vmlinuz" --initrd="$run/initrd.cpio" \
        --cmdline="@$run/cmdline.txt" --os-release="$run/os-release.txt" \
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
# raw image whose LEADING bytes ARE the SHA256-pinned Debian rootfs artifact
# (MiB-aligned with zero padding — virtio-blk capacity is 512-byte granular and
# an unaligned image would be rounded DOWN, truncating the artifact; /init dd's
# the device whole, trims back to the artifact size and hash-verifies against
# the @@ROOTFS_SHA@@ pin baked at build time). Prints "<sha256> <bytes>"; the
# S-00 scenario passes both back via DEBIAN_FDE_ROOTFS_SHA / DEBIAN_FDE_ROOTFS_
# BYTES before calling uki_build with the `debian-fde-stage=install` word.
#
# DERIVED ARTIFACT (documented, deterministic — byte-identical across runs,
# verified 2026-09-17): the PINNED upstream artifact is the Debian CLOUD IMAGE
# tarball (20260831-2587) whose single member is a 3 GiB sparse `disk.raw`
# (GPT: p15 ESP, p14 BIOS-boot, p1 = the ext4 root partition). No upstream
# root-TREE tarball exists in that dated snapshot (checked; the in-guest
# installer needs a TREE — and extracting a 3 GiB disk image in the guest
# cannot fit any TCG budget or the LUKS volume anyway). The payload therefore
# carves the root TREE out of the pinned image, unprivileged, HOST-side, ONCE
# (cached): `tar -x --sparse` → `sfdisk -d` partition probe → `dd` the root
# partition (largest, type Linux/x86-64) → `debugfs -R 'rdump /'` (e2fsprogs,
# no root needed) → mtime normalization (rdump leaves directory mtimes at
# dump time) → ustar re-tar with `--owner=0 --group=0` (rdump cannot
# preserve ownership; in-guest extraction runs as root and restores uid/gid
# from the archive) → `gzip -n` (no mtime/name ⇒ byte-stable). Derived ONLY
# after rootfs_ensure hash-verified the pinned source. Cache:
# <cache-dir>/debian-13-generic-amd64-rootustar.tar.gz.
rootfs_payload_image() {
    local out="$1" name="debian-13-generic-amd64.tar.xz"
    local src="$ROOTFS_CACHE_DIR/$name"
    local derived="$ROOTFS_CACHE_DIR/debian-13-generic-amd64-rootustar.tar.gz"
    # MD-07: the derived artifact carries a sidecar sha256 — verified on every
    # reuse (there is no upstream pin for this artifact, so the sidecar IS the
    # pin; a corrupted cached payload must never propagate into a UKI silently)
    local derived_sha="$derived.sha256"
    local sha bytes aligned
    rootfs_ensure "$name" || return 1
    if [[ -f "$derived" && -f "$derived_sha" ]] \
        && [[ "$(sha256sum "$derived" | awk '{print $1}')" == "$(awk '{print $1}' "$derived_sha")" ]]; then
        :
    else
        if [[ -f "$derived" ]]; then
            echo "uki-build: derived payload cache failed its sidecar-sha check — re-deriving" >&2
        fi
        rm -f "$derived" "$derived_sha"
        echo "uki-build: deriving the root tree payload from the pinned cloud image (one-time, cached) ..." >&2
        local tmp
        tmp=$(mktemp -d) || return 1
        # 1. materialize the sparse disk image from the pinned tarball
        if ! tar -x --sparse -f "$src" -C "$tmp"; then
            rm -rf "$tmp"
            echo "uki-build: pinned cloud-image tarball extraction failed" >&2
            return 1
        fi
        local diskimg="$tmp/disk.raw"
        # 2. partition probe: the root partition = largest (Debian cloud GPT:
        #    p15 ESP, p14 BIOS-boot, p1 root ext4). sfdisk -d emits
        #    `name : start= N, size= M, type= ..., uuid= ...` — values carry
        #    trailing commas; strip them (portable awk: no gawk 3-arg match).
        local part_line start size
        part_line=$(sfdisk -d "$diskimg" 2>/dev/null | awk '
            /start=/ {
                gsub(/=[ \t]+/, "=", $0)   # sfdisk pads AFTER the = sign
                n = split($0, f, /[ \t]+/)
                s = ""; z = ""
                for (i = 1; i <= n; i++) {
                    if (f[i] ~ /^start=/) { s = f[i]; sub(/^start=/, "", s); sub(/,$/, "", s) }
                    if (f[i] ~ /^size=/)  { z = f[i]; sub(/^size=/, "", z); sub(/,$/, "", z) }
                }
                if ((z + 0) > (max + 0)) { max = z + 0; rs = s; rz = z }
            }
            END { print rs, rz }')
        start=${part_line% *}
        size=${part_line#* }
        if [[ -z "$start" || -z "$size" ]]; then
            rm -rf "$tmp"
            echo "uki-build: partition probe failed on the pinned cloud image (sfdisk)" >&2
            return 1
        fi
        # 3. carve the root partition
        dd if="$diskimg" of="$tmp/root-part.img" bs=512 skip="$start" count="$size" \
            conv=sparse status=none || {
            rm -rf "$tmp"
            echo "uki-build: root partition carve failed (start=$start size=$size)" >&2
            return 1
        }
        # 4. dump the tree (debugfs is unprivileged; target dir must pre-exist
        #    and the rdump paths are resolved from THIS process's CWD — use
        #    absolute paths)
        mkdir -p "$tmp/tree"
        if ! debugfs -R "rdump / $tmp/tree" "$tmp/root-part.img" >/dev/null 2>&1 \
            || [[ ! -f "$tmp/tree/usr/lib/systemd/systemd" ]]; then
            rm -rf "$tmp"
            echo "uki-build: debugfs rdump of the root partition failed (or no systemd in tree)" >&2
            return 1
        fi
        # 5. deterministic root-owned ustar + gzip -n payload artifact.
        #    rdump restores FILE mtimes from the fs but leaves DIRECTORY
        #    mtimes at dump time — normalize every mtime to epoch or the
        #    derived artifact (and the @@ROOTFS_SHA@@ baked into the S-00
        #    UKI) changes on every regeneration. (Verified: two dumps then
        #    differ; normalized, byte-identical.)
        find "$tmp/tree" -exec touch -h -d @0 {} +
        # MD-07: unique temp (concurrent invocations never share a .part path)
        local tmpout
        tmpout=$(mktemp "$ROOTFS_CACHE_DIR/.rootustar.part.XXXXXX") || { rm -rf "$tmp"; return 1; }
        if ! (cd "$tmp/tree" && tar --format=ustar --owner=0 --group=0 --numeric-owner \
            -cf - . | gzip -n >"$tmpout"); then
            rm -rf "$tmp" "$tmpout"
            echo "uki-build: root tree re-containerization failed" >&2
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
