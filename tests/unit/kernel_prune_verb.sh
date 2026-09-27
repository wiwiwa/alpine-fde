#!/usr/bin/env bash
# tests/unit/kernel_prune_verb.sh — the `alpine-fde kernel prune [kver]`
# sub-verb (§8.1): the build's step-7 keep-set prune, exposed standalone.
# Contract:
#   * explicit kver: prunes ESP UKIs AND the manifest to keep current +
#     RETENTION newest others (one keep-set decision, §9.2)
#   * no kver: resolves the current kernel from the manifest's
#     .current_kernel
#   * invalid retention / missing manifest fail closed or loud, never a
#     silent partial prune
# Hermetic: fixture ESP + manifest, no TPM, no real kernel images.

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

SP="$REPO/bin/alpine-fde"
T=$(mktemp -d /tmp/alpine-fde-kernel-prune.XXXXXX)
trap 'rm -rf "$T"' EXIT

export ALPINE_FDE_ROOT=$T/root
export ALPINE_FDE_ESP=$T/esp
export ALPINE_FDE_KEYDIR=$REPO/fixtures/keys
export ALPINE_FDE_CONF=$T/absent.conf
mkdir -p "$ALPINE_FDE_ROOT/etc/alpine-fde" "$ALPINE_FDE_ESP/EFI/Linux"
MANIFEST=$ALPINE_FDE_ROOT/etc/alpine-fde/digests.json

# schema-v1 manifest shape (manifest_new / manifest_load contract: version is
# a NUMBER, every digests[] entry carries the full field set)
mk_fixture() { # <current-kver> <kver>...
    local cur=$1
    shift
    local kvers="$*"
    {
        printf '{\n  "version": 1,\n  "pcr_bank": "sha256",\n  "pcrs": [7, 11],\n  "current_kernel": "%s",\n  "updated_at": "2026-09-28T00:00:00Z",\n  "pubkey_fp": "",\n  "digests": [\n' "$cur"
        local first=1
        local k
        for k in $kvers; do
            [ $first -eq 1 ] || printf ',\n'
            first=0
            printf '    {"kernel_version": "%s", "pcr11_digest": "%064d", "policy_digest": "", "signature": "", "keyslot": "", "token_id": ""}' \
                "$k" 0
        done
        printf '\n  ]\n}\n'
    } >"$MANIFEST"
    for k in $kvers; do
        printf 'dummy-uki-%s' "$k" >"$ALPINE_FDE_ESP/EFI/Linux/alpine-fde-$k.efi"
    done
}

run_prune() { # <args...>
    "$SP" kernel prune "$@" >"$T/out.log" 2>&1
    echo $?
}

# --- explicit kver: ESP + manifest pruned to current + 2 --------------------------
mk_fixture 6.12.10-1-lts 6.12.10-1-lts 6.12.9-1-lts 6.12.8-1-lts 6.1.0-1-lts
assert_rc "kernel prune: explicit kver rc 0" 0 "$(run_prune 6.12.10-1-lts)"
assert_eq "kernel prune: kept current 6.12.10" "1" \
    "$([ -f "$ALPINE_FDE_ESP/EFI/Linux/alpine-fde-6.12.10-1-lts.efi" ] && echo 1 || echo 0)"
assert_eq "kernel prune: kept retained 6.12.9" "1" \
    "$([ -f "$ALPINE_FDE_ESP/EFI/Linux/alpine-fde-6.12.9-1-lts.efi" ] && echo 1 || echo 0)"
assert_eq "kernel prune: kept retained 6.12.8" "1" \
    "$([ -f "$ALPINE_FDE_ESP/EFI/Linux/alpine-fde-6.12.8-1-lts.efi" ] && echo 1 || echo 0)"
assert_eq "kernel prune: pruned 6.1.0 from the ESP" "0" \
    "$([ -f "$ALPINE_FDE_ESP/EFI/Linux/alpine-fde-6.1.0-1-lts.efi" ] && echo 1 || echo 0)"
assert_eq "kernel prune: pruned 6.1.0 from the manifest" "0" \
    "$(jq '[.digests[] | select(.kernel_version == "6.1.0-1-lts")] | length' "$MANIFEST")"
assert_eq "kernel prune: manifest keeps exactly the keep set" "3" \
    "$(jq '.digests | length' "$MANIFEST")"

# --- no kver: resolved from the manifest's .current_kernel ------------------------
mk_fixture 6.2.0-1-lts 6.2.0-1-lts 6.1.0-1-lts 6.0.0-1-lts
assert_rc "kernel prune: no kver -> manifest .current_kernel resolves rc 0" 0 "$(run_prune)"
assert_eq "kernel prune (default kver): kept 6.2.0 / 6.1.0 / 6.0.0" "3" \
    "$(ls "$ALPINE_FDE_ESP/EFI/Linux" | wc -l | tr -d ' ')"

# --- failure shapes ----------------------------------------------------------------
mk_fixture 6.2.0-1-lts 6.2.0-1-lts
assert_rc "kernel prune: invalid kver -> usage rc 2" 2 "$(run_prune '../traversal')"
rm -f "$MANIFEST"
assert_rc "kernel prune: no manifest -> fail-closed 64" 64 "$(run_prune 6.2.0-1-lts 2>/dev/null)"

# retired-verb spot check: the enrollment alias surface is NOT a kernel verb
rc=0
out=$("$SP" kernel enroll 2>&1 >/dev/null) || rc=$?
assert_rc "kernel: retired enroll sub-verb -> usage rc 2" 2 "$rc"
assert_contains "kernel: retired enroll named as unknown verb" "$out" "unknown verb: enroll"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
