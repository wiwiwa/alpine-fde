#!/usr/bin/env bash
# tests/lib/keys-fixture.sh — throwaway Secure Boot + release key ceremony for
# the Alpine FDE e2e harness (docs/Architecture.md §12, ADR-11).
#
# Generates, per harness run (keys are throwaway, re-created per run):
#   <dir>/PK.key/.crt        PK (platform key) — self-signed throwaway cert
#   <dir>/KEK.key/.crt       KEK — self-signed throwaway cert
#   <dir>/db.key/.crt        db signing key = THE release key (ADR-11: one
#                            identity signs UKIs, pcr policies, and lives in db)
#   <dir>/release.pub        db/release PUBLIC key PEM (SPKI) for pcr policies
# and builds OVMF vars images offline with virt-fw-vars (empirically verified
# CLI: --set-pk GUID FILE / --add-kek GUID FILE / --add-db GUID FILE take PEM
# certs; --sb sets SecureBootEnable; -p prints the varstore):
#   keys_vars_enrolled  <keys-dir> <out.fd>   -> custom PK/KEK/db, SB enabled
#   keys_vars_unenrolled <keys-dir> <out.fd>  -> stock copy, SB off (negative)
#
# The enrolled vars are applied OFFLINE to a copy of the host OVMF_VARS —
# no firmware UI, fully deterministic.

if [[ -n "${_ALPINE_FDE_KEYS_FIXTURE_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_KEYS_FIXTURE_SOURCED=1

# Throwaway owner GUID for the custom key entries (random-generated once).
ALPINE_FDE_TEST_GUID="{0fb75ec8-8c55-4c0c-9d6b-6c272f4ac4bb}"

# _cert_common <key> <crt> <CN> — self-signed RSA cert (throwaway, 2048 is fine)
_keys_cert() {
    local key="$1" crt="$2" cn="$3"
    openssl req -x509 -newkey rsa:2048 -keyout "$key" -out "$crt" \
        -days 30 -nodes -subj "/CN=$cn" 2>/dev/null
}

# keys_create <dir> — generate the full throwaway ceremony
# (IN-06: private keys are created under umask 077, never an inherited one)
keys_create() {
    local dir="$1"
    mkdir -p "$dir"
    (
        umask 077
        _keys_cert "$dir/PK.key" "$dir/PK.crt" "alpine-fde-test-PK"
        _keys_cert "$dir/KEK.key" "$dir/KEK.crt" "alpine-fde-test-KEK"
        # release/db key: one identity (ADR-11)
        _keys_cert "$dir/db.key" "$dir/db.crt" "alpine-fde-test-release"
        openssl x509 -in "$dir/db.crt" -pubkey -noout >"$dir/release.pub"
    )
}

# keys_vars_enrolled <keys-dir> <out.fd> — copy stock vars + enroll custom keys,
# Secure Boot ON. Fails closed if virt-fw-vars rejects anything.
keys_vars_enrolled() {
    local kd="$1" out="$2" stock="${OVMF_VARS_STOCK:-/usr/share/ovmf/x64/OVMF_VARS.4m.fd}"
    cp "$stock" "$out"
    virt-fw-vars -i "$out" -o "$out" \
        --set-pk "$ALPINE_FDE_TEST_GUID" "$kd/PK.crt" \
        --add-kek "$ALPINE_FDE_TEST_GUID" "$kd/KEK.crt" \
        --add-db "$ALPINE_FDE_TEST_GUID" "$kd/db.crt" \
        --sb >/dev/null || {
        echo "keys-fixture: virt-fw-vars enrollment failed" >&2
        return 1
    }
    return 0
}

# keys_vars_unenrolled <keys-dir> <out.fd> — negative fixture: stock vars copy
# (no PK, SecureBoot off). The keys-dir argument is accepted for symmetry.
keys_vars_unenrolled() {
    local kd="$1" out="$2" stock="${OVMF_VARS_STOCK:-/usr/share/ovmf/x64/OVMF_VARS.4m.fd}"
    cp "$stock" "$out"
}

# keys_vars_print <vars.fd> — human-readable varstore dump (test assertions use
# `keys_vars_get` instead; this is for logs).
keys_vars_print() {
    virt-fw-vars -i "$1" -p
}

# keys_vars_get <vars.fd> <name> — print "name : <value>" line for <name>
# (empty + rc 1 when absent). grep-able assertion surface.
keys_vars_get() {
    keys_vars_print "$1" 2>/dev/null | grep -E "^$2[[:space:]]*:"
}

# keys_vars_secureboot_on <vars.fd> — rc 0 iff SecureBootEnable is ON
keys_vars_secureboot_on() {
    keys_vars_get "$1" SecureBootEnable | grep -q "ON"
}
