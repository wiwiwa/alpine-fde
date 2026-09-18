#!/usr/bin/env bash
# tests/unit/e2e_infra_smoke.sh — harness self-test for the e2e infrastructure
# (Wave 1 agent C): keys fixture, disk fixture, UKI builder, serial client.
# No QEMU boot here — boots are covered by tests/e2e/*-lite.sh. Infra breakage
# must report HERE as harness-failure, not scenario-failure (§12).

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
# shellcheck source=../lib/keys-fixture.sh
source "$TESTS/lib/keys-fixture.sh"
# shellcheck source=../lib/disk-fixture.sh
source "$TESTS/lib/disk-fixture.sh"
# shellcheck source=../lib/uki-build.sh
source "$TESTS/lib/uki-build.sh"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- keys fixture: ceremony + virt-fw-vars roundtrip -----------------------------
keys_create "$WORK/keys"
assert_file_exists "keys: release cert" "$WORK/keys/db.crt"
assert_file_exists "keys: release public key" "$WORK/keys/release.pub"
keys_vars_enrolled "$WORK/keys" "$WORK/enrolled.fd"
assert_contains "vars: enrolled has SecureBootEnable ON" \
    "$(keys_vars_get "$WORK/enrolled.fd" SecureBootEnable)" "ON"
assert_contains "vars: enrolled has PK" "$(keys_vars_get "$WORK/enrolled.fd" PK)" "blob"
assert_contains "vars: enrolled has db" "$(keys_vars_get "$WORK/enrolled.fd" db)" "blob"
keys_vars_unenrolled "$WORK/keys" "$WORK/unenrolled.fd"
assert_not_contains "vars: unenrolled has no PK" "$(keys_vars_get "$WORK/unenrolled.fd" PK)" "blob"
assert_not_contains "vars: unenrolled has no SecureBootEnable" \
    "$(keys_vars_get "$WORK/unenrolled.fd" SecureBootEnable)" "ON"

# --- disk fixture: unprivileged LUKS2 on a file ----------------------------------
disk_make_luks "$WORK/disk.img" 64
META=$(disk_metadata "$WORK/disk.img")
assert_contains "disk: LUKS2 json metadata readable" "$META" '"keyslots"'
SLOTS=$(printf '%s' "$META" | jq -r '.keyslots | keys | length')
assert_eq "disk: 1 keyslot after luksFormat" "1" "$SLOTS"
PBKDF=$(printf '%s' "$META" | jq -r '.keyslots["0"].kdf.type')
assert_eq "disk: keyslot 0 pbkdf is argon2id" "argon2id" "$PBKDF"
disk_add_slot1 "$WORK/disk.img"
SLOTS=$(disk_metadata "$WORK/disk.img" | jq -r '.keyslots | keys | length')
assert_eq "disk: 2 keyslots after luksAddKey" "2" "$SLOTS"
TOKENS=$(disk_token_json "$WORK/disk.img")
assert_eq "disk: no tokens before enrollment" "{}" "$TOKENS"

# --- qemu argv contract (G-HW1): N-disk attachment + documented drive map --------
# qemu_argv is the pure-argv seam of qemu_run (no sockets/pins/processes): the
# drive map is vda=ESP, vdb=LUKS, vdc=optional pcrsig payload, vdd… = the
# opt-in 7th argument (newline-separated images appended in list order).
source "$TESTS/lib/qemu.sh"
mkdir -p "$WORK/argv"
ARGV=$(qemu_argv "$WORK/argv" "$WORK/argv/esp.img" "$WORK/argv/disk.img" \
    "$WORK/argv/vars.fd" "$WORK/argv/tpm" "$WORK/argv/pcrsig.img" \
    "$(printf '%s\n%s\n' "$WORK/argv/x1.img" "$WORK/argv/x2.img")")
assert_contains "qemu_argv: OVMF code pflash (readonly)" "$ARGV" \
    "if=pflash,format=raw,readonly=on"
assert_contains "qemu_argv: per-scenario vars pflash" "$ARGV" \
    "if=pflash,format=raw,file=$WORK/argv/vars.fd"
assert_contains "qemu_argv: swtpm ctrl-socket tpmdev" "$ARGV" \
    "socket,id=chrtpm,path=$WORK/argv/tpm/sock.ctrl"
assert_contains "qemu_argv: tpm-tis device" "$ARGV" "tpm-tis,tpmdev=tpm0"
assert_not_contains "qemu_argv: TCG argv carries no -accel flag" "$ARGV" "-accel"
DRIVES=$(sed -n 's/^file=\(.*\),format=raw,if=virtio$/\1/p' <<<"$ARGV" | tr '\n' ' ')
assert_eq "qemu_argv: virtio drive order == documented map vda..vde (2 extra drives)" \
    "$WORK/argv/esp.img $WORK/argv/disk.img $WORK/argv/pcrsig.img $WORK/argv/x1.img $WORK/argv/x2.img " \
    "$DRIVES"
ARGV5=$(qemu_argv "$WORK/argv" "$WORK/argv/esp.img" "$WORK/argv/disk.img" \
    "$WORK/argv/vars.fd" "$WORK/argv/tpm")
DRIVES5=$(sed -n 's/^file=\(.*\),format=raw,if=virtio$/\1/p' <<<"$ARGV5" | tr '\n' ' ')
assert_eq "qemu_argv: legacy 5-arg contract == vda+vdb only" \
    "$WORK/argv/esp.img $WORK/argv/disk.img " "$DRIVES5"

# --- UKI builder: guest tree, initramfs, ukify sections, pcrsig ------------------
keys_create "$WORK/uki-keys"
echo "# building guest tree + UKI (first run extracts pinned debs; cached) ..."
# CR-01: the build stage (which may trigger deb extraction) is bounded — the
# unit smoke runs UNBOUNDED inside run-e2e's harness self-test gate
if timeout 3600 bash -c 'set -u; source "$1/lib/uki-build.sh"; uki_build "$2" "$3" "$4"' \
    _ "$TESTS" "$WORK/run" "$WORK/uki-keys" "$WORK/run/harness.efi"; then
    _assert_result ok "uki_build pipeline" ""
else
    _assert_result not-ok "uki_build pipeline" "failed or exceeded the 3600s bound — see output above"
fi
assert_file_exists "uki: signed output" "$WORK/run/harness.efi"
SECTIONS=$(objdump -h "$WORK/run/uki-unsigned.efi" 2>/dev/null)
assert_contains "uki: .linux section" "$SECTIONS" ".linux"
assert_contains "uki: .initrd section" "$SECTIONS" ".initrd"
assert_contains "uki: .cmdline section" "$SECTIONS" ".cmdline"
PCRSIGNED=$(objdump -h "$WORK/run/uki-pcrsigned.efi" 2>/dev/null)
assert_contains "uki: .pcrsig section present when signed" "$PCRSIGNED" ".pcrsig"
assert_contains "uki: .pcrpkey section present when signed" "$PCRSIGNED" ".pcrpkey"
# signed prediction JSON: pcrs 11, signature material, bank sha256
PCRSIG=$(cat "$WORK/run/uki-pcrsig.json" 2>/dev/null)
assert_contains "uki: pcrsig covers bank sha256" "$PCRSIG" '"sha256"'
assert_contains "uki: pcrsig covers PCR 11" "$PCRSIG" '"pcrs": [11]'
assert_contains "uki: pcrsig carries signature" "$PCRSIG" '"sig"'
# sbverify: the outer signature validates against our release cert
if sbverify --list "$WORK/run/harness.efi" 2>&1 | grep -q "debian-fde-test-release"; then
    _assert_result ok "uki: sbverify shows release-cert signature" ""
else
    _assert_result not-ok "uki: sbverify shows release-cert signature" "signature subject not found"
fi
# initramfs: busybox + cryptsetup payload + modules present (list the cpio)
CPIO=$(cpio -it --quiet <"$WORK/run/initrd.cpio" 2>/dev/null)
assert_contains "initrd: busybox present" "$CPIO" "usr/bin/busybox"
assert_contains "initrd: init script present" "$CPIO" "init"
assert_contains "initrd: systemd-cryptsetup present" "$CPIO" "usr/lib/systemd/systemd-cryptsetup"
assert_contains "initrd: cryptenroll present" "$CPIO" "usr/bin/systemd-cryptenroll"
assert_contains "initrd: tpm2 helper present" "$CPIO" "opt/tpm/bin/tpm2_pcrread"
assert_contains "initrd: dm-crypt module present" "$CPIO" "modules/dm-crypt.ko"
# G-HW3: the btrfs+bcache module closure (deps first in UKI_MODULES; every
# member verified present as a .ko.xz in the PINNED kernel deb — see the
# modules-tree asserts below — and packed decompressed into the initrd)
for m in btrfs bcache zstd xor raid6_pq; do
    assert_contains "initrd: $m module present (G-HW3 btrfs/bcache closure)" "$CPIO" "modules/$m.ko"
done
# G-HW4: the pinned kernel carries the btrfs/bcache modules (gap-review fact,
# re-asserted here against the extracted deb so a kernel re-pin cannot drop
# the driver silently)
for m in btrfs bcache zstd xor raid6_pq; do
    KMOD=$(find "$WORK/run/guest-tree/modules-tree" -name "$m.ko.xz" 2>/dev/null | head -1)
    if [[ -n "$KMOD" ]]; then
        _assert_result ok "pinned kernel deb carries $m.ko.xz" ""
    else
        _assert_result not-ok "pinned kernel deb carries $m.ko.xz" \
            "no $m.ko.xz under guest-tree/modules-tree"
    fi
done
# G-HW5: the btrfs userspace closure rides the initrd (mkfs.btrfs + subvolume
# tooling for the §9.1 installer stage). The udev pieces ride with it: without
# systemd-udevd + the dm rules in the initrd, the LUKS attach is udev-
# unregistered and the installed system's §9.1 fstab UUID= submounts can
# never resolve (device units require the udev db — observed live 2026-09-19)
assert_contains "initrd: btrfs tool present" "$CPIO" "usr/bin/btrfs"
assert_contains "initrd: mkfs.btrfs present" "$CPIO" "usr/sbin/mkfs.btrfs"
assert_contains "initrd: systemd-udevd present (fstab UUID= resolution)" "$CPIO" \
    "usr/lib/systemd/systemd-udevd"
assert_contains "initrd: udevadm present" "$CPIO" "usr/bin/udevadm"
assert_contains "initrd: 55-dm.rules present" "$CPIO" "usr/lib/udev/rules.d/55-dm.rules"
assert_contains "initrd: 60-persistent-storage.rules present" "$CPIO" \
    "usr/lib/udev/rules.d/60-persistent-storage.rules"
assert_contains "initrd: release pub present" "$CPIO" "rel.pub"
# NOTE: pcrsig.json deliberately NOT in the initrd (would change its own
# PCR prediction) — travels on the payload drive instead.
assert_not_contains "initrd: no pcrsig.json (payload-drive design)" "$CPIO" "pcrsig.json"
assert_file_exists "uki: pcrsig payload drive" "$WORK/run/pcrsig.img"

# --- rootfs fixture: pins verify (downloads cached from the earlier run) ---------
# CR-01: the fetch stage is the 8h-hang window — bound it (curl itself is
# bounded in rootfs-fixture.sh; this is the stage-level defense in depth)
if timeout 2400 bash -c 'set -u; source "$1/lib/rootfs-fixture.sh"; rootfs_ensure_all' \
    _ "$TESTS" >/dev/null 2>&1; then
    _assert_result ok "rootfs: all pinned artifacts verify" ""
else
    _assert_result not-ok "rootfs: all pinned artifacts verify" "pin/hash/download failure or timeout"
fi

# --- serial.py loopback -----------------------------------------------------------
SERIAL_PY="$TESTS/lib/serial.py"
python3 - "$WORK" "$SERIAL_PY" <<'PYEOF'
import socket, subprocess, sys, threading, time, os
work, script = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = os.path.join(work, "serial-test.sock")
srv.bind(path); srv.listen(1)
def echo():
    conn, _ = srv.accept()
    conn.settimeout(5)
    try:
        data = conn.recv(256)
        conn.sendall(b"echo:" + data)
    except (BrokenPipeError, ConnectionResetError, socket.timeout):
        pass
    finally:
        conn.close()
t = threading.Thread(target=echo); t.start()
time.sleep(0.2)
r = subprocess.run([sys.executable, script, path, "write_line", "ping"],
                   capture_output=True)
t.join(timeout=5)
sys.exit(r.returncode)
PYEOF
if (( $? == 0 )); then
    _assert_result ok "serial: loopback write_line" ""
else
    _assert_result not-ok "serial: loopback write_line" "python loopback failed"
fi
# read_until against a canned socket stream
python3 - "$WORK" "$SERIAL_PY" <<'PYEOF'
import socket, subprocess, sys, threading, time, os
work, script = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = os.path.join(work, "serial-test2.sock")
srv.bind(path); srv.listen(1)
def feed():
    conn, _ = srv.accept()
    try:
        time.sleep(0.3)
        conn.sendall(b"debian-fde: UNSEALED\r\n")
        time.sleep(1.5)   # keep the socket open while the client matches
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        conn.close()
t = threading.Thread(target=feed); t.start()
time.sleep(0.2)
r = subprocess.run([sys.executable, script, path, "read_until", "debian-fde: UNSEALED", "5"],
                   capture_output=True)
t.join(timeout=5)
sys.exit(r.returncode)
PYEOF
if (( $? == 0 )); then
    _assert_result ok "serial: read_until matches sentinel" ""
else
    _assert_result not-ok "serial: read_until matches sentinel" "python read_until failed"
fi

# --- scenario registry completeness vs the §10/§12 matrix -------------------------
# The registry in run-e2e.sh must declare the FULL §10/§12 matrix: a dropped
# row would silently shrink the failure matrix. Assert every matrix id is
# covered — s00–s17 (the original 18-row matrix) PLUS the W2b multi-drive
# rows s19–s22 (now LITERAL table rows, per run-e2e.sh's registry notes).
# The pinned invariants are (a) the per-id coverage below, (b) no duplicate
# rows and (c) the 18-row floor (now 22 rows with W2b landed).
REGISTRY_IDS=$(awk -F '\t' '$1 ~ /^s[0-9][0-9]$/ {print $1}' "$TESTS/run-e2e.sh")
for s in s00 s01 s02 s03 s04 s05 s06 s07 s08 s09 s10 s11 s12 s13 s14 s15 s16 s17 \
    s19 s20 s21 s22; do
    assert_contains "registry covers $s" "$REGISTRY_IDS" "$s"
done
N_ROWS=$(grep -c . <<<"$REGISTRY_IDS")
N_UNIQ=$(sort -u <<<"$REGISTRY_IDS" | wc -l)
assert_eq "registry: no duplicate matrix rows (dynamic count)" "$N_UNIQ" "$N_ROWS"
if (( N_UNIQ >= 18 )); then
    _assert_result ok "registry: >= 18 rows (§10/§12 matrix floor; 22 with the W2b rows)" ""
else
    _assert_result not-ok "registry: >= 18 rows (§10/§12 matrix floor)" \
        "only $N_UNIQ distinct ids in the literal table"
fi

# --- I1/I2/I4 artifact scans: no private key material in build artifacts ----------
# I4: the release signing private key never ships on/in the protected machine;
# I2: the ESP contains no secrets. Host-side scans over the fixtures this smoke
# builds (UKI binaries, initrd cpio, guest tree, ESP fixture image): no
# "-----BEGIN … PRIVATE KEY-----" PEM block, no .pem/.key files. (The s00
# disk-side extension of this scan belongs to the scenario task.)
PRIKEY_RE='-----BEGIN [A-Z ]*PRIVATE KEY-----'
# keep the scans non-vacuous: assert the scanned artifacts exist first
for f in "$WORK/run/uki-unsigned.efi" "$WORK/run/uki-pcrsigned.efi" \
         "$WORK/run/harness.efi" "$WORK/run/initrd.cpio"; do
    assert_file_exists "I4-scan: artifact present ($(basename "$f"))" "$f"
done
PEM_HITS=$(grep -al "$PRIKEY_RE" "$WORK/run/uki-unsigned.efi" \
    "$WORK/run/uki-pcrsigned.efi" "$WORK/run/harness.efi" \
    "$WORK/run/initrd.cpio" 2>/dev/null || true)
assert_eq "I4: UKI + initrd binaries carry no private-key PEM block" "" "$PEM_HITS"
KEYNAMES=$(cpio -it --quiet <"$WORK/run/initrd.cpio" 2>/dev/null | grep -Ei '\.(pem|key)$' || true)
assert_eq "I4: initrd ships no .pem/.key files" "" "$KEYNAMES"
KEYNAMES=$(find "$WORK/run/guest-tree" \( -name '*.pem' -o -name '*.key' \) 2>/dev/null || true)
assert_eq "I4: guest tree ships no .pem/.key files" "" "$KEYNAMES"
# ESP fixture: build it, then scan the image listing and the binary that ships
# at the firmware's removable-media path
esp_make "$WORK/esp-scan.img" 128 "$WORK/run/harness.efi" || {
    _assert_result not-ok "I2: ESP fixture build (scan prerequisite)" "esp_make failed"
}
if [[ -f "$WORK/esp-scan.img" ]]; then
    ESP_LIST=$(mdir -i "$WORK/esp-scan.img" -/ :: 2>/dev/null | grep -Ei '\.(pem|key)' || true)
    assert_eq "I2: ESP fixture lists no .pem/.key files" "" "$ESP_LIST"
    if mcopy -i "$WORK/esp-scan.img" ::/EFI/BOOT/BOOTX64.EFI "$WORK/esp-scan-bootx64.efi" 2>/dev/null; then
        ESP_HITS=$(grep -al "$PRIKEY_RE" "$WORK/esp-scan-bootx64.efi" 2>/dev/null || true)
        assert_eq "I2: ESP fixture binary carries no private-key PEM block" "" "$ESP_HITS"
    else
        _assert_result not-ok "I2: ESP fixture binary carries no private-key PEM block" \
            "could not extract BOOTX64.EFI from ESP fixture"
    fi
fi

echo "# e2e_infra_smoke: pass=$TESTS_PASS fail=$TESTS_FAIL"
(( TESTS_FAIL == 0 )) || exit 1
exit 0
