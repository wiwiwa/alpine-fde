#!/usr/bin/env bash
# tests/unit/initramfs_platform_drivers.sh — boot-lane finding #22 (s23
# attempt 22, run ...-1790451796): boot B died "Mounting root: failed" with
# /dev/vdb ABSENT from /sys/class/block (only loop/ram) — the installer's
# pinned mkinitfs feature set ("base cryptsetup btrfs alpine-fde") carries NO
# platform storage drivers, so the initramfs cannot see the target disk on
# ANY machine (qemu virtio, SATA, NVMe alike). mkinitfs's own stock default
# set (ata base cdrom ext4 keymap kms mmc nvme raid scsi usb virtio) carries
# exactly these; the alpine-fde set must keep the storage families.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
source "$HERE/lib.sh"

. "$REPO/lib/common.sh"
. "$REPO/lib/initramfs.sh"

feat=$(initramfs_features)
for want in virtio ata nvme scsi; do
    case " $feat " in
        *" $want "*) _pass "pinned feature set carries the platform storage driver family: $want" ;;
        *) _fail "pinned feature set is missing the storage driver family: $want (got: $feat)" ;;
    esac
done
for want in base cryptsetup btrfs alpine-fde; do
    case " $feat " in
        *" $want "*) _pass "pinned feature set keeps: $want" ;;
        *) _fail "pinned feature set lost: $want" ;;
    esac
done

finish
