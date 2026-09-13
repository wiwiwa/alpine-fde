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
# The registry in run-e2e.sh must declare the FULL S-00..S-17 matrix: a dropped
# row would silently shrink the §10 failure matrix. Assert every matrix id is
# covered AND that the registry carries exactly 18 rows (duplicates inflate the
# count and fail here too).
REGISTRY_IDS=$(awk -F '\t' '$1 ~ /^s[0-9][0-9]$/ {print $1}' "$TESTS/run-e2e.sh")
for s in s00 s01 s02 s03 s04 s05 s06 s07 s08 s09 s10 s11 s12 s13 s14 s15 s16 s17; do
    assert_contains "registry covers $s" "$REGISTRY_IDS" "$s"
done
assert_eq "registry declares exactly the 18-row §10/§12 matrix" "18" \
    "$(grep -c . <<<"$REGISTRY_IDS")"

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
