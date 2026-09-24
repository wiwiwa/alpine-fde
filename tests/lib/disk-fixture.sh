#!/usr/bin/env bash
# tests/lib/disk-fixture.sh — file-backed LUKS2 disk fixture for the Alpine FDE
# e2e harness (no root, no loop devices: cryptsetup works unprivileged on a
# plain file for FORMAT + METADATA ops; device-mapper open happens in-guest).
#
# CI-cost divergence (documented, tests/e2e/README.md): Argon2id is pinned with
# deliberately SMALL cost params so luksFormat stays fast in CI. Production
# uses generous costs (docs/Architecture.md §13) — the fixture only proves the
# mechanics, not the KDF hardness.
#
# Usage (source, then):
#   disk_make_luks <file> <size-mib>     fresh LUKS2, keyslot 0 = passphrase
#   disk_slot0_passphrase                print the well-known slot-0 passphrase
#   disk_add_slot1 <file>                add keyslot 1 (multi-slot proof)
#   disk_metadata <file>                 print LUKS2 JSON metadata (jq-able)
#   disk_token_json <file>               print LUKS2 tokens JSON

if [[ -n "${_ALPINE_FDE_DISK_FIXTURE_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_DISK_FIXTURE_SOURCED=1

ALPINE_FDE_SLOT0_PASSPHRASE="alpine-fde-ci-slot0-passphrase"
ALPINE_FDE_SLOT1_PASSPHRASE="alpine-fde-ci-slot1-passphrase"

disk_slot0_passphrase() {
    printf '%s\n' "$ALPINE_FDE_SLOT0_PASSPHRASE"
}

# Internal: CI argon2id cost params (SMALL on purpose)
_disk_kdf_args() {
    printf '%s\n' "--pbkdf=argon2id --pbkdf-memory=16000 --pbkdf-parallel=1 --pbkdf-force-iterations=4"
}

# disk_make_luks <file> <size-mib> — whole-disk LUKS2 (no partition table;
# per the design simplification used by the harness, §12 S-00 note).
disk_make_luks() {
    local file="$1" mib="$2"
    truncate -s "${mib}M" "$file"
    disk_slot0_passphrase | cryptsetup luksFormat --type luks2 \
        $(_disk_kdf_args) --batch-mode --label alpine-fde-ci "$file" || {
        echo "disk-fixture: luksFormat failed on $file" >&2
        return 1
    }
    return 0
}

# disk_add_slot1 <file> — add a second passphrase slot (both passphrases via
# stdin lines: existing key first, then the new one).
disk_add_slot1() {
    local file="$1"
    { disk_slot0_passphrase; printf '%s\n' "$ALPINE_FDE_SLOT1_PASSPHRASE"; } |
        cryptsetup luksAddKey $(_disk_kdf_args) "$file" || {
        echo "disk-fixture: luksAddKey failed on $file" >&2
        return 1
    }
    return 0
}

disk_metadata() {
    cryptsetup luksDump --dump-json-metadata "$1"
}

disk_token_json() {
    disk_metadata "$1" | jq -c '.tokens'
}
