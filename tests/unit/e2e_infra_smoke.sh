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
# Wave-2 speed lever: guests default to 2 vCPUs (ALPINE_FDE_GUEST_SMP) — the
# in-guest phases under test (systemd, finalize, recovery) are multi-process
# and a single vCPU left them serial on a multi-core host. qemu_argv emits
# one token per line, so the value is the line AFTER the -smp token.
SMPV=$(awk '/^-smp$/{getline; print; exit}' <<<"$ARGV")
assert_eq "qemu_argv: guest vCPU count defaults to 2 (ALPINE_FDE_GUEST_SMP)" \
    "$SMPV" "2"
assert_contains "qemu_argv: per-scenario vars pflash" "$ARGV" \
    "if=pflash,format=raw,file=$WORK/argv/vars.fd"
assert_contains "qemu_argv: swtpm ctrl-socket tpmdev" "$ARGV" \
    "socket,id=chrtpm,path=$WORK/argv/tpm/sock.ctrl"
assert_contains "qemu_argv: tpm-crb device (tpm-tis hits qemu 11.1 completion-BH stranding: ~1.2s/command firmware phase)" "$ARGV" "tpm-crb,tpmdev=tpm0"
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
# Wave-2 2b: extra drives are per-extension format — a .qcow2 overlay leg
# (raid member-2 rows in s19/s21/s22) must carry format=qcow2, raw names
# stay format=raw
ARGVQ=$(qemu_argv "$WORK/argv" "$WORK/argv/esp.img" "$WORK/argv/disk.img" \
    "$WORK/argv/vars.fd" "$WORK/argv/tpm" "" \
    "$(printf '%s\n%s\n' "$WORK/argv/x1.img" "$WORK/argv/x3.qcow2")")
assert_contains "qemu_argv: qcow2 extra drive carries format=qcow2" "$ARGVQ" \
    "file=$WORK/argv/x3.qcow2,format=qcow2,if=virtio"
assert_contains "qemu_argv: raw extra drive stays format=raw" "$ARGVQ" \
    "file=$WORK/argv/x1.img,format=raw,if=virtio"

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
# G-B6 self-consistency (2026-09-24, s19/s20 registry red): the build's
# enter-initrd prediction must equal a pcrsign-style re-measure of the SAME
# components it leaves on disk. ukify needs the @file form for --os-release:
# a bare value is embedded/measured as the LITERAL PATH STRING, so the
# prediction diverged from every @-form consumer (pcrsign, the hook) by one
# section. Also pins the embedded .osrel to the real file content.
if [ -s "$WORK/run/pcr11-enter-initrd.txt" ]; then
    _smoke_pred=$(cat "$WORK/run/pcr11-enter-initrd.txt")
    _smoke_re=$(ukify build --measure --json=short --pcr-banks=sha256 --phases=enter-initrd \
        --pcr-private-key="$WORK/uki-keys/db.key" \
        --linux="$WORK/run/guest-tree/vmlinuz" --initrd="$WORK/run/initrd.cpio" \
        --cmdline="@$WORK/run/cmdline.txt" --os-release="@$WORK/run/os-release.txt" 2>/dev/null \
        | jq -r '.sha256[] | select(.phase == "enter-initrd") | .hash')
    assert_eq "uki: build prediction == pcrsign-style re-measure (@-form inputs)" \
        "$_smoke_pred" "$_smoke_re"
else
    assert_eq "uki: build prediction == pcrsign-style re-measure (@-form inputs)" \
        "prediction-file" "missing"
fi
objcopy -O binary --only-section=.osrel "$WORK/run/uki-pcrsigned.efi" \
    "$WORK/run/osrel.bin" 2>/dev/null
assert_eq "uki: embedded .osrel is the real os-release content (not a literal path)" \
    "$(cat "$WORK/run/os-release.txt")" "$(cat "$WORK/run/osrel.bin" 2>/dev/null)"
# sbverify: the outer signature validates against our release cert
if sbverify --list "$WORK/run/harness.efi" 2>&1 | grep -q "alpine-fde-test-release"; then
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
# Defect s15-1 (live boot 2026-09-21): /init started udevd but never ran the
# coldplug replay, so no uevent ever reached the udev db AFTER boot —
# /dev/disk/by-uuid for the payload disk never appeared, the unseal hook's
# crypttab UUID= resolution found nothing on any member ("no systemd-tpm2
# token found"), and every boot funneled into the recovery prompt / 3-strike.
# The dracut pattern (trigger + settle) must be baked into the generated /init.
INIT_TEXT=$(cat "$WORK/run/guest-tree/init")
assert_contains "init: udev coldplug trigger (by-uuid resolution, dracut pattern)" \
    "$INIT_TEXT" "udevadm trigger --type=devices --action=add"
assert_contains "init: coldplug wait bounded (udevadm settle --timeout)" \
    "$INIT_TEXT" "udevadm settle --timeout="
# NOTE: pcrsig.json deliberately NOT in the initrd (would change its own
# PCR prediction) — travels on the payload drive instead.
assert_not_contains "initrd: no pcrsig.json (payload-drive design)" "$CPIO" "pcrsig.json"
assert_file_exists "uki: pcrsig payload drive" "$WORK/run/pcrsig.img"

# --- I6/G-E10: initrd inventory audit ---------------------------------------------
# uki_initrd_inventory is the cpio listing emitter; the DEFAULT build's initrd
# must satisfy the I6 allowlist policy: no compilers/linkers, no package tools
# (apk/apt/dpkg), and no interactive shell — the debug-shell seam is proven
# absent in the default build and armed only under ALPINE_FDE_DEBUG_SHELL.
INV=$(uki_initrd_inventory "$WORK/run/initrd.cpio" 2>/dev/null)
if [[ -n "$INV" ]]; then
    _assert_result ok "inventory: uki_initrd_inventory emits the cpio listing" ""
else
    _assert_result not-ok "inventory: uki_initrd_inventory emits the cpio listing" "empty listing"
fi
N_ENTRIES=$(grep -c . <<<"$INV")
echo "# initrd inventory: $N_ENTRIES entries (uki_initrd_inventory)"
INV_BASENAMES=$(awk -F/ '{print $NF}' <<<"$INV" | sort -u)
INV_HIT=$(grep -Fx -e gcc -e cc1 -e g++ -e cpp -e as -e ld -e ld.gold -e make -e gas \
    <<<"$INV_BASENAMES" | tr '\n' ' ' || true)
assert_eq "inventory: no compilers/linkers (gcc/cc1/g++/cpp/as/ld/make)" "" "$INV_HIT"
INV_HIT=$(grep -Fx -e apk -e apk-static -e apt -e apt-get -e dpkg -e dpkg-deb -e dpkg-query \
    <<<"$INV_BASENAMES" | tr '\n' ' ' || true)
assert_eq "inventory: no package tools (apk/apt/dpkg)" "" "$INV_HIT"
INV_HIT=$(grep -Fx -e bash -e dash -e zsh -e ksh -e csh -e tcsh -e sulogin -e nulogin \
    -e login -e getty -e agetty \
    <<<"$INV_BASENAMES" | tr '\n' ' ' || true)
assert_eq "inventory: no interactive shells/login/getty beyond the busybox init shell" "" "$INV_HIT"
# debug-shell seam: the default build bakes the guard EMPTY (substituted, no
# placeholder residue); with ALPINE_FDE_DEBUG_SHELL=1 the same seam arms it.
if grep -q '@@DEBUG_SHELL@@' "$WORK/run/guest-tree/init"; then
    _assert_result not-ok "default build: @@DEBUG_SHELL@@ placeholder substituted" "placeholder residue in init"
else
    _assert_result ok "default build: @@DEBUG_SHELL@@ placeholder substituted" ""
fi
DISABLED=$(grep -cF 'if [ -n "" ]; then' "$WORK/run/guest-tree/init")
assert_eq "default build: debug-shell seam DISABLED (empty -n guard)" "1" "$DISABLED"
mkdir -p "$WORK/debug-tree"
if bash -c 'set -u; source "$1/lib/uki-build.sh"; ALPINE_FDE_DEBUG_SHELL=1 uki_initrd_write_init "$2"' \
    _ "$TESTS" "$WORK/debug-tree" 2>/dev/null; then
    ENABLED=$(grep -cF 'if [ -n "1" ]; then' "$WORK/debug-tree/init")
    assert_eq "ALPINE_FDE_DEBUG_SHELL=1: debug-shell seam ARMED (guard 1)" "1" "$ENABLED"
else
    assert_eq "ALPINE_FDE_DEBUG_SHELL=1: debug-shell seam ARMED (guard 1)" "init written" "uki_initrd_write_init failed"
fi

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
        conn.sendall(b"alpine-fde: UNSEALED\r\n")
        time.sleep(1.5)   # keep the socket open while the client matches
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        conn.close()
t = threading.Thread(target=feed); t.start()
time.sleep(0.2)
r = subprocess.run([sys.executable, script, path, "read_until", "alpine-fde: UNSEALED", "5"],
                   capture_output=True)
t.join(timeout=5)
sys.exit(r.returncode)
PYEOF
if (( $? == 0 )); then
    _assert_result ok "serial: read_until matches sentinel" ""
else
    _assert_result not-ok "serial: read_until matches sentinel" "python read_until failed"
fi

# --- swtpm fixture: simplified (proxy-less) between-boots design ------------------
# swtpm binds the PUBLIC sockets DIRECTLY (no ctrl/data proxy — retired and
# deleted; see tests/README.md's data-loop-stall section). qemu's tpm-emulator
# sends CMD_SHUTDOWN over the CONTROL socket at its clean exit (swtpm answers
# success and marks itself shut-down) and then closes both chardevs; swtpm
# exits on the EOF. swtpm_ensure restarts the stack FRESH (startup-clear, all
# PCRs zero) and the scenarios reseed the booted registers with
# swtpm_seed_pcrs (d7 from the console, d11 from the build prediction) —
# digest-anchored sealing needs no stored live state.
source "$TESTS/lib/swtpm-fixture.sh"
if swtpm_start "$WORK/tpm-u"; then
    _assert_result ok "swtpm: fixture start (direct sockets, no proxy)" ""
else
    _assert_result not-ok "swtpm: fixture start (direct sockets, no proxy)" \
        "swtpm_start failed"
fi
MARKER=$(printf 's15-2-marker' | sha256sum | awk '{print $1}')
MARKER11=$(printf 's15-2-d11' | sha256sum | awk '{print $1}')
swtpm_pcrextend "$WORK/tpm-u" 7 "$MARKER"
PCR_BEFORE=$(swtpm_pcrread "$WORK/tpm-u" 7)
assert_ne "swtpm: pcrextend changed PCR 7 (on the direct sockets)" \
    "0000000000000000000000000000000000000000000000000000000000000000" "$PCR_BEFORE"
# fake-qemu client: send CMD_SHUTDOWN over the ctrl socket exactly the way
# qemu's clean exit does; stock swtpm must answer success itself.
python3 - "$WORK/tpm-u/sock.ctrl" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall((0x00000003).to_bytes(4, "big"))
reply = s.recv(4)
s.close()
sys.exit(0 if reply == b"\x00\x00\x00\x00" else 1)
PYEOF
assert_eq "swtpm: swtpm answers the fake-qemu CMD_SHUTDOWN with success" "0" "$?"
# the real qemu exit then closes the chardevs and swtpm exits on the EOF;
# terminate it directly here — same dead-stack precondition for swtpm_ensure
for _ in $(seq 1 50); do
    kill -0 "$(cat "$WORK/tpm-u/pid" 2>/dev/null)" 2>/dev/null || break
    sleep 0.1
done
kill -9 "$(cat "$WORK/tpm-u/pid" 2>/dev/null)" 2>/dev/null
rm -f "$WORK/tpm-u/pid"
if swtpm_ensure "$WORK/tpm-u"; then
    _assert_result ok "swtpm: swtpm_ensure restarts the stack after the EOF-exit" ""
else
    _assert_result not-ok "swtpm: swtpm_ensure restarts the stack after the EOF-exit" \
        "restart failed"
fi
assert_eq "swtpm: restart left PCRs ZEROED (scenarios reseed via swtpm_seed_pcrs)" \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "$(swtpm_pcrread "$WORK/tpm-u" 7)"
swtpm_seed_pcrs "$WORK/tpm-u" "$MARKER" "$MARKER11"
# pcrextend CONCATENATES: a zeroed PCR becomes sha256(0x00*32 || digest)
assert_eq "swtpm: swtpm_seed_pcrs reseeds the booted registers (d7 + d11)" \
    "$(python3 -c "
import hashlib
for m in ('$MARKER', '$MARKER11'):
    print(hashlib.sha256(bytes(32) + bytes.fromhex(m)).hexdigest())" | paste -sd'|')" \
    "$(swtpm_pcrread "$WORK/tpm-u" 7)|$(swtpm_pcrread "$WORK/tpm-u" 11)"
swtpm_stop "$WORK/tpm-u"
RC=$(swtpm_pcrread "$WORK/tpm-u" 7 >/dev/null 2>&1; echo $?)
assert_ne "swtpm: swtpm_stop really stopped the stack" "0" "$RC"

# --- scenario registry completeness vs the §10/§12 matrix -------------------------
# The registry in run-e2e.sh must declare the SURVIVING §10/§12 matrix: a
# dropped row would silently shrink the failure matrix. Assert every
# surviving matrix id is covered — s00 + the surviving standalone negatives
# (the §10/§12 matrix after the 2026-09-26 removals: the six pipeline-absorbed
# scenarios s01/s02/s14/s15/s16/s17, then the seven early-boot negatives
# s03/s05/s07/s09/s12/s13/s18 absorbed by the s90 drill) PLUS the W2b
# multi-drive rows s19–s22 (LITERAL table rows, per run-e2e.sh's registry
# notes). s90 (the unified fail-closed drill) is appended at runtime, not
# literal; s18's artifacts are pinned zero-boot by
# tests/unit/s18_foreign_pcrsig_host.sh (its row went with the drill
# consolidation).
# The pinned invariants are (a) the per-id coverage below, (b) no duplicate
# rows and (c) the post-removal 10-row literal floor.
REGISTRY_IDS=$(awk -F '\t' '$1 ~ /^s[0-9][0-9]$/ {print $1}' "$TESTS/run-e2e.sh")
for s in s00 s04 s06 s08 s10 s11 \
    s19 s20 s21 s22; do
    assert_contains "registry covers $s" "$REGISTRY_IDS" "$s"
done
N_ROWS=$(grep -c . <<<"$REGISTRY_IDS")
N_UNIQ=$(sort -u <<<"$REGISTRY_IDS" | wc -l)
assert_eq "registry: no duplicate matrix rows (dynamic count)" "$N_UNIQ" "$N_ROWS"
if (( N_UNIQ >= 10 )); then
    _assert_result ok "registry: >= 10 rows (post-removal §10/§12 literal floor)" ""
else
    _assert_result not-ok "registry: >= 10 rows (post-removal §10/§12 literal floor)" \
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

# --- accelerator contract (§12): /dev/kvm is REQUIRED for e2e --------------------
# Default ALPINE_FDE_ACCEL=kvm: an unusable KVM is a LOUD failure (rc!=0, the
# message names /dev/kvm) — never a silent TCG downgrade. ALPINE_FDE_ACCEL=tcg
# is the explicit dev escape hatch, honored verbatim; every other value
# (including the old silent 'auto') is rejected. Decision is once-per-process,
# so every case runs _qemu_accel_choose in a fresh subshell.
ACC=$( ( _qemu_accel=''; ALPINE_FDE_ACCEL=kvm; _qemu_kvm_ok() { return 0; }; \
    _qemu_accel_choose 2>/dev/null && printf '%s' "$_qemu_accel" ) )
assert_eq "accel: explicit kvm + working KVM -> kvm" "kvm" "$ACC"
ACC=$( ( _qemu_accel=''; unset ALPINE_FDE_ACCEL; _qemu_kvm_ok() { return 0; }; \
    _qemu_accel_choose 2>/dev/null && printf '%s' "$_qemu_accel" ) )
assert_eq "accel: DEFAULT is kvm (working KVM -> kvm, never tcg)" "kvm" "$ACC"
ACC_RC=$( ( _qemu_accel=''; unset ALPINE_FDE_ACCEL; _qemu_kvm_ok() { return 1; }; \
    _qemu_accel_choose >/dev/null 2>&1; echo $? ) )
assert_eq "accel: default + unusable /dev/kvm -> fail closed (rc!=0)" "1" "$ACC_RC"
MSG=$( ( _qemu_accel=''; unset ALPINE_FDE_ACCEL; _qemu_kvm_ok() { return 1; }; \
    _qemu_accel_choose 2>&1 >/dev/null ) )
assert_contains "accel: failure message names /dev/kvm" "$MSG" "/dev/kvm"
assert_not_contains "accel: unusable KVM never downgrades to tcg" "$MSG" "using tcg"
TCG=$( ( _qemu_accel=''; ALPINE_FDE_ACCEL=tcg; _qemu_accel_choose 2>/dev/null \
    && printf '%s' "$_qemu_accel" ) )
assert_eq "accel: explicit ALPINE_FDE_ACCEL=tcg honored verbatim" "tcg" "$TCG"
INV=$( ( _qemu_accel=''; ALPINE_FDE_ACCEL=auto; _qemu_accel_choose >/dev/null 2>&1; echo $? ) )
assert_eq "accel: 'auto' (silent-decision mode) rejected" "1" "$INV"

# --- KVM probe hardening (G-K1): the probe guest must be SELF-TERMINATING --------
# A `-machine none` guest with no QMP `quit` idles forever, so the historical
# `timeout 30 qemu …` probe paid a ~30s hang on EVERY refusal. The probe now
# drives QMP over stdio (qmp_capabilities + quit) under `timeout` with the
# ALPINE_FDE_KVM_PROBE_TIMEOUT bound (default 10): success ONLY = KVM-accelerated
# qemu starts AND exits cleanly within the bound. Unit tests exercise the
# _qemu_kvm_probe_run helper seam through a PATH-stubbed qemu (the /dev/kvm
# existence+writability gate cannot be forced here); every case runs in a fresh
# subshell, resetting PATH after each so later sections keep the real qemu.
PROBE_STUB="$WORK/kvm-probe-stub"
mkdir -p "$PROBE_STUB/bin"

assert_eq "kvm-probe: _qemu_kvm_probe_run helper seam exists" "function" \
    "$(declare -F _qemu_kvm_probe_run >/dev/null && echo function || echo missing)"

# (a) stub qemu exits 0 immediately -> probe run succeeds
cat >"$PROBE_STUB/bin/qemu-system-x86_64" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$PROBE_STUB/bin/qemu-system-x86_64"
RC=$( ( PATH="$PROBE_STUB/bin:$PATH"; _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
assert_eq "kvm-probe: clean fast qemu exit 0 -> probe run succeeds" "0" "$RC"

# (b) stub exits 1 (broken KVM init) -> probe run fails
cat >"$PROBE_STUB/bin/qemu-system-x86_64" <<'EOF'
#!/bin/sh
echo "qemu-system-x86_64: -accel kvm: failed to initialize kvm" >&2
exit 1
EOF
chmod +x "$PROBE_STUB/bin/qemu-system-x86_64"
RC=$( ( PATH="$PROBE_STUB/bin:$PATH"; _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
assert_eq "kvm-probe: nonzero qemu exit -> probe run fails (rc 1 propagates)" "1" "$RC"

# (c) stub hangs; the default bound kills it -> nonzero, FAST, SIGTERM marker
cat >"$PROBE_STUB/bin/qemu-system-x86_64" <<EOF
#!/bin/sh
trap 'echo sigterm > "$PROBE_STUB/sigterm.marker"; exit 99' TERM
sleep 30
EOF
chmod +x "$PROBE_STUB/bin/qemu-system-x86_64"
rm -f "$PROBE_STUB/sigterm.marker"
T0=$SECONDS
RC=$( ( PATH="$PROBE_STUB/bin:$PATH"; _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
ELAPSED=$((SECONDS - T0))
assert_eq "kvm-probe: hung guest killed by bound -> rc 124" "124" "$RC"
if (( ELAPSED < 20 )); then
    _assert_result ok "kvm-probe: hung guest refuses fast (elapsed=${ELAPSED}s < 20s)" ""
else
    _assert_result not-ok "kvm-probe: hung guest refuses fast" "elapsed=${ELAPSED}s >= 20s"
fi
assert_file_exists "kvm-probe: bound SIGTERMed the hung guest (stub marker)" \
    "$PROBE_STUB/sigterm.marker"

# (d) qemu missing from PATH (timeout still resolvable) -> probe run fails
mkdir -p "$PROBE_STUB/only-timeout"
ln -sf "$(command -v timeout)" "$PROBE_STUB/only-timeout/timeout"
RC=$( ( PATH="$PROBE_STUB/only-timeout"; _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
assert_ne "kvm-probe: missing qemu -> probe run fails" "0" "$RC"

# (e) ALPINE_FDE_KVM_PROBE_TIMEOUT=1 with the hanging stub -> refuses in < 6s
rm -f "$PROBE_STUB/sigterm.marker"
T0=$SECONDS
RC=$( ( PATH="$PROBE_STUB/bin:$PATH"; ALPINE_FDE_KVM_PROBE_TIMEOUT=1; \
    _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
ELAPSED=$((SECONDS - T0))
assert_eq "kvm-probe: bound=1 expiry -> rc 124" "124" "$RC"
if (( ELAPSED < 6 )); then
    _assert_result ok "kvm-probe: ALPINE_FDE_KVM_PROBE_TIMEOUT=1 honored (elapsed=${ELAPSED}s < 6s)" ""
else
    _assert_result not-ok "kvm-probe: ALPINE_FDE_KVM_PROBE_TIMEOUT=1 honored" "elapsed=${ELAPSED}s >= 6s"
fi

# (f) argv pin: the probe cannot silently degrade into a non-KVM check
cat >"$PROBE_STUB/bin/qemu-system-x86_64" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$PROBE_STUB/argv.log"
exit 0
EOF
chmod +x "$PROBE_STUB/bin/qemu-system-x86_64"
( PATH="$PROBE_STUB/bin:$PATH"; _qemu_kvm_probe_run >/dev/null 2>&1 )
ARGV=$(tr '\n' ' ' <"$PROBE_STUB/argv.log" 2>/dev/null)
assert_contains "kvm-probe: argv pins -accel kvm" "$ARGV" "-accel kvm"
assert_contains "kvm-probe: argv pins -machine none" "$ARGV" "-machine none"
assert_contains "kvm-probe: argv pins -qmp stdio (self-terminating QMP quit)" "$ARGV" \
    "-qmp stdio"
RC=$( ( PATH="$PROBE_STUB/bin:$PATH"; ALPINE_FDE_KVM_PROBE_TIMEOUT=notaseconds; \
    _qemu_kvm_probe_run >/dev/null 2>&1; echo $? ) )
assert_ne "kvm-probe: invalid ALPINE_FDE_KVM_PROBE_TIMEOUT fails closed" "0" "$RC"

# --- G-E2: sentinel fixtures — parse, cross-fixture collisions, consumers --------
# Every versioned fixture must parse (name<TAB>string rows only, no duplicate
# names within a file); a NAME defined in more than one fixture must carry the
# IDENTICAL value everywhere (a value-drifting name is a collision and must be
# renamed); and every sentinel_of name referenced by existing scenarios must
# resolve against the DEFAULT table (260.2, the Alpine contract).
SENT_DEFAULT=$(bash -c 'source "$1/lib/sentinels.sh"; printf "%s" "$SENTINELS"' _ "$TESTS")
assert_contains "sentinels: default table is the Alpine fixture (sentinels-260.2.txt)" \
    "$SENT_DEFAULT" "sentinels-260.2.txt"
LEGACY_TABLE=$(bash -c 'source "$1/lib/sentinels.sh"; printf "%s" "$SENTINELS"' \
    _ "$TESTS" 2>/dev/null) # env-pin seam re-checked below with SENTINELS_FILE
LEGACY_TABLE=$(SENTINELS_VER=257.13 bash -c 'source "$1/lib/sentinels.sh"; printf "%s" "$SENTINELS"' _ "$TESTS")
assert_contains "sentinels: SENTINELS_VER=257.13 loads the Debian-era record" \
    "$LEGACY_TABLE" "sentinels-257.13.txt"
for f in "$TESTS"/sentinels-*.txt; do
    BAD=$(awk -F '\t' '
        /^[[:space:]]*$/ {next}
        /^#/ {next}
        $1 !~ /^[A-Za-z_][A-Za-z0-9_]*$/ || $2 == "" {print "row: " $0}
        ' "$f")
    assert_eq "sentinels: $(basename "$f") parses (name<TAB>string data rows only)" "" "$BAD"
    DUPS=$(awk -F '\t' '
        /^[[:space:]]*$/ {next}
        /^#/ {next}
        {c[$1]++}
        END {for (n in c) if (c[n] > 1) print n}' "$f")
    assert_eq "sentinels: $(basename "$f") has no duplicate names" "" "$DUPS"
done
SENT_COLLISIONS=$(awk -F '\t' '
    /^[[:space:]]*$/ {next}
    /^#/ {next}
    ($1 in seen) && seen[$1] != $2 {print $1 " (conflicting values across fixtures)"}
    {seen[$1] = $2}' "$TESTS"/sentinels-*.txt)
assert_eq "sentinels: no name collides across fixtures (value conflicts)" "" "$SENT_COLLISIONS"
SENT_NAMES=$(grep -hEo 'sentinel_of +[A-Za-z_0-9]+' \
    "$TESTS"/e2e/*.sh 2>/dev/null | awk '{print $2}' | sort -u)
if [[ -n "$SENT_NAMES" ]]; then
    _assert_result ok "sentinels: consumer grep found referenced names ($(grep -c . <<<"$SENT_NAMES"))" ""
else
    _assert_result not-ok "sentinels: consumer grep found referenced names" \
        "no sentinel_of consumers found — non-vacuous check required"
fi
SENT_MISSING=""
for n in $SENT_NAMES; do
    bash -c 'source "$1/lib/sentinels.sh"; sentinel_of "$2" >/dev/null' _ "$TESTS" "$n" 2>/dev/null \
        || SENT_MISSING="$SENT_MISSING $n"
done
assert_eq "sentinels: every referenced name resolves in the default (260.2) table" "" "$SENT_MISSING"

# --- G-E11: ADR-19 interop oracle scaffold — fail-closed + scope guards ----------
# The oracle is CI-only and gated: without ALPINE_FDE_INTEROP_ORACLE=1, or
# without bwrap on PATH, everything about it refuses (rc 64). The scope guard
# must pass on the CURRENT tree: shipped bin/+lib/+hooks carry no bwrap /
# Debian-runtime references. The oracle BODY is intentionally absent (scaffold).
source "$TESTS/lib/interop-oracle.sh"
assert_eq "interop-oracle: rootfs assembly seam exists (scaffold)" "function" \
    "$(declare -F interop_oracle_rootfs >/dev/null && echo function || echo missing)"
RC=$( ( unset ALPINE_FDE_INTEROP_ORACLE; interop_oracle_assert_ready >/dev/null 2>&1; echo $? ) )
assert_eq "interop-oracle: gate env unset -> fail closed (rc 64)" "64" "$RC"
RC=$( ( ALPINE_FDE_INTEROP_ORACLE=0 interop_oracle_assert_ready >/dev/null 2>&1; echo $? ) )
assert_eq "interop-oracle: gate env not exactly 1 -> fail closed (rc 64)" "64" "$RC"
mkdir -p "$WORK/no-bwrap"
RC=$( ( ALPINE_FDE_INTEROP_ORACLE=1 PATH="$WORK/no-bwrap" interop_oracle_assert_ready >/dev/null 2>&1; echo $? ) )
assert_eq "interop-oracle: gate set but bwrap absent -> fail closed (rc 64)" "64" "$RC"
RC=$( ( ALPINE_FDE_INTEROP_ORACLE=1 interop_oracle_assert_ready >/dev/null 2>&1; echo $? ) )
assert_eq "interop-oracle: gate set + bwrap present -> ready (rc 0)" "0" "$RC"
if interop_scope_check "$TESTS/.." >/dev/null 2>&1; then
    _assert_result ok "interop-oracle: scope guard passes on the current tree (bin/lib/hooks clean)" ""
else
    _assert_result not-ok "interop-oracle: scope guard passes on the current tree" \
        "bwrap/Debian-runtime references in shipped bin/lib/hooks (see stderr above)"
fi

echo "# e2e_infra_smoke: pass=$TESTS_PASS fail=$TESTS_FAIL"
(( TESTS_FAIL == 0 )) || exit 1
exit 0
