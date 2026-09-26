#!/usr/bin/env bash
# tests/lib/interop-oracle.sh — ADR-19 interop oracle BODY (gap G-E11).
#
# Scope (ADR-19/§12): upstream systemd-cryptsetup/cryptenroll 257 runs under
# bwrap against a swtpm-backed TPM and asserts the REVERSE direction of
# Mechanism B — a token produced by our sealer is enrolled/unsealed by
# upstream systemd code, and tampered/schema-drifted tokens are refused. The
# oracle is CI-ONLY: it never runs in `install`, the initramfs, or any shipped
# path; the Alpine target carries zero bwrap/Debian footprint.
#
# Call graph (our seal -> upstream import -> upstream unseal):
#   interop_oracle_seal      swtpm fixture + real lib/seal.sh seal_finalized
#                            against a file-backed LUKS2 image; token imported
#                            with lib/token.sh choreography
#   interop_oracle_project   derive the UPSTREAM-257-consumable projection of
#                            our token (see SCHEMA DELTA below)
#   interop_oracle_attach    run the ROOTFS's own /usr/lib/systemd/
#                            systemd-cryptsetup under bwrap: `attach` with the
#                            crypttab option tpm2-device=swtpm:path=... (the
#                            pinned TCTI seam); upstream loads our token via
#                            libcryptsetup-token-systemd-tpm2, verifies the
#                            release-key .pcrsig signature, drives the TPM
#                            policy session and unseals — or refuses
#   interop_oracle_log_*     assert the upstream verdict from ITS OWN debug log
#                            (refusals are upstream refusals, never our gates)
#
# SCHEMA DELTA (pinned empirically against systemd 257.13 — the regression net
# this oracle keeps taut): our §7.2 token
#   {type, keyslots, tpm2-blob, tpm2-pcrs, tpm2-pcr-bank, tpm2-pubkey (b64 DER
#    SPKI), tpm2-signature}
# is NOT consumable verbatim. Upstream additionally requires/reinterprets:
#   * tpm2-policy-hash  (hex)  — mandatory since forever; validation refuses
#     the token without it ("TPM2 token data lacks 'tpm2-policy-hash' field").
#   * tpm2_pubkey (UNDERSCORE, b64 PEM — not our dash/b64-DER spelling) +
#     tpm2_pubkey_pcrs  — the signed-PCR-policy key. Our tpm2-signature is
#     never read by 257; the signature arrives via the .pcrsig file.
#   * tpm2-primary-alg "rsa" — upstream defaults to an ECC SRK; our seal
#     creates the RSA SRK, so the parent key would not match.
#   * the .pcrsig "pkfp" must be SHA256 over the PKCS#1 RSAPublicKey DER
#     (i2d_PublicKey), NOT over the SPKI DER our pcrsign pins.
#   * tpm2-pcrs must project to [] for our seal shape: upstream 257 ALWAYS
#     re-applies PolicyPCR AFTER PolicyAuthorize, so its session digest is
#     H(auth_digest || pcr-data) and can never equal the digest our blob is
#     sealed under (the bare authorized digest, lib/policy.sh
#     policy_sealed_digest). With tpm2-pcrs=[] the PCR binding is carried by
#     tpm2_pubkey_pcrs + the .pcrsig selection (PolicyAuthorize refuses unless
#     the live PCR digest equals the signed pol), and upstream unseals.
# Every one of those deltas is a loud ADR-19 finding against lib/seal.sh +
# lib/token.sh + pcrsign (out of this file's bucket).
#
# Usage (source, then):
#   interop_oracle_gate_ok        -> rc 0 iff ALPINE_FDE_INTEROP_ORACLE=1
#   interop_oracle_assert_ready   -> fail-closed rc 64 without the gate env
#                                    or without bwrap on PATH
#   interop_oracle_rootfs <dest>  -> assemble the fixture rootfs from the
#                                    ALREADY-PINNED 257 debs (rootfs-fixture.sh
#                                    table), record the tree SHA256; requires
#                                    interop_oracle_assert_ready first
#   interop_oracle_bootstrap <dir>    -> rootfs + sandbox mountpoints + the
#                                        host swtpm-TCTI shim staging
#   interop_oracle_seal <dir> <keydir> -> real Mechanism B finalized seal into
#                                        <dir>/luks.img (swtpm fixture); sets
#                                        ORACLE_SLOT / ORACLE_TOKEN /
#                                        ORACLE_PASS_FILE / ORACLE_PCRSIG
#   interop_oracle_project <dir> <keydir> -> upstream-257 token projection
#                                        (sets ORACLE_TOKEN_UP / ORACLE_PCRSIG_UP)
#   interop_oracle_attach <dir> <img> <token> <pcrsig> <log> -> upstream
#                                        systemd-cryptsetup attach; prints rc
#   interop_oracle_log_unsealed <log> <slot> -> rc 0 iff upstream unsealed
#   interop_oracle_log_refused <log>          -> rc 0 iff upstream refused
#   interop_scope_check [tree]    -> rc 1 when the SHIPPED bin/+lib/+hooks
#                                    under <tree> (default: this repo) carry
#                                    bwrap/Debian-runtime references

# shellcheck disable=SC2034
# ORACLE_*/ALPINE_FDE_TMPDIR are caller-facing seams: the sourcing oracle
# suite reads them after interop_oracle_* returns.
if [[ -n "${_ALPINE_FDE_INTEROP_ORACLE_SOURCED:-}" ]]; then
    return 0
fi
_ALPINE_FDE_INTEROP_ORACLE_SOURCED=1

_INTEROP_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
_INTEROP_REPO=$(cd "$_INTEROP_HERE/../.." && pwd)
# shellcheck source=lib/rootfs-fixture.sh
source "$_INTEROP_HERE/rootfs-fixture.sh"

# interop_oracle_gate_ok — the explicit opt-in gate. ANY other value ( unset,
# 0, yes, …) means the oracle does not run.
interop_oracle_gate_ok() {
    [[ "${ALPINE_FDE_INTEROP_ORACLE:-}" == "1" ]]
}

# interop_oracle_assert_ready — fail-closed preconditions: gate env AND bwrap.
# Every refusal is rc 64 (the harness usage/prerequisite class) with the
# reason on stderr — the oracle must never degrade into "best effort".
interop_oracle_assert_ready() {
    if ! interop_oracle_gate_ok; then
        echo "interop-oracle: gate ALPINE_FDE_INTEROP_ORACLE=1 not set — oracle does not run (ADR-19 scope guard)" >&2
        return 64
    fi
    if ! command -v bwrap >/dev/null 2>&1; then
        echo "interop-oracle: bwrap not available — refusing (ADR-19: CI-only interop oracle)" >&2
        return 64
    fi
    return 0
}

# interop_oracle_rootfs <dest-dir> — assemble the oracle fixture rootfs from
# the ALREADY-PINNED 257 deb table (rootfs-fixture.sh; every artifact
# SHA256-verified at fetch, rootfs_ensure). The assembled tree is recorded by
# a SHA256 manifest digest (sorted per-file sha256s, then one digest over
# that manifest) written to <dest>/.oracle-sha256 and printed on stdout.
# The digest makes the oracle's userspace input reproducible: a drift in ANY
# pinned deb changes the recorded digest and is visible.
interop_oracle_rootfs() {
    local dest="$1" name
    interop_oracle_assert_ready || return $?
    [[ -n "$dest" ]] || { echo "interop-oracle: rootfs dest required" >&2; return 64; }
    mkdir -p "$dest"
    for name in $(rootfs_pin_names); do
        rootfs_deb_extract "$name" "$dest" || {
            echo "interop-oracle: pinned deb extraction failed: $name" >&2
            return 1
        }
    done
    # Sandbox mountpoints the pinned tree does not carry (no ld.so.cache, no
    # /lib64 symlink, no /run|/tmp|/proc|/sys|/dev in the runtime debs). The
    # tree digest covers FILES only, so this is invisible to .oracle-sha256.
    mkdir -p "$dest/run" "$dest/tmp" "$dest/var/tmp" "$dest/proc" "$dest/sys" \
        "$dest/dev" "$dest/etc/systemd"
    local manifest digest
    manifest=$(mktemp) || return 1
    (cd "$dest" && find . -type f -print0 | sort -z \
        | xargs -0 sha256sum >"$manifest") || { rm -f "$manifest"; return 1; }
    digest=$(sha256sum "$manifest" | awk '{print $1}')
    rm -f "$manifest"
    printf '%s\n' "$digest" >"$dest/.oracle-sha256"
    printf '%s\n' "$digest"
    return 0
}

# interop_scope_check [tree] — the ADR-19 scope guard: the SHIPPED paths
# (bin/, lib/, hooks/ under <tree>) must carry NO bwrap footprint and NO
# references to the Debian runtime fixture (the pinned-deb cache machinery,
# the Debian archive hosts/images). This is what keeps the oracle "CI-only":
# if any of these strings appear in shipped code, the oracle (or its Debian
# fixture) has leaked into the Alpine product. rc 0 = clean, rc 1 = leaks
# (printed). Text files only (-I); hits name file + line.
interop_scope_check() {
    local tree="${1:-$(cd "$_INTEROP_HERE/.." && pwd)/..}"
    tree=$(cd "$tree" 2>/dev/null && pwd) || {
        echo "interop-scope: tree not found: $1" >&2
        return 64
    }
    local leaks
    leaks=$(grep -rInE 'bwrap|bubblewrap|rootfs-fixture|interop-oracle|deb\.debian\.org|cloud\.debian\.org|debian-13' \
        "$tree/bin" "$tree/lib" "$tree/hooks" 2>/dev/null || true)
    if [[ -n "$leaks" ]]; then
        echo "interop-scope: SHIPPED paths carry oracle/Debian-runtime references (ADR-19 violation):" >&2
        printf '%s\n' "$leaks" >&2
        return 1
    fi
    return 0
}

# --- oracle BODY (ADR-19/§12) ------------------------------------------------
#
# Lazy product-lib sourcing: the seal path (lib/seal.sh + siblings) is only
# needed once the oracle actually runs; e2e_infra_smoke sources this file for
# the gate/scope guards and must not drag the product libs in.
_interop_product_libs_sourced=0
_interop_source_product_libs() {
    ((_interop_product_libs_sourced == 1)) && return 0
    # seal.sh resolves its siblings (token.sh) through ALPINE_FDE_CMD_DIR
    export ALPINE_FDE_CMD_DIR="${ALPINE_FDE_CMD_DIR:-$_INTEROP_REPO/lib/cmd}"
    # shellcheck source=../lib/common.sh disable=SC1091
    source "$_INTEROP_REPO/lib/common.sh"
    # shellcheck source=../lib/policy.sh disable=SC1091
    source "$_INTEROP_REPO/lib/policy.sh"
    # shellcheck source=../lib/keys.sh disable=SC1091
    source "$_INTEROP_REPO/lib/keys.sh"
    # shellcheck source=../lib/seal.sh disable=SC1091
    source "$_INTEROP_REPO/lib/seal.sh"
    _interop_product_libs_sourced=1
}

# interop_oracle_bootstrap <dir> — assemble EVERYTHING the sandboxed upstream
# run needs: (a) the pinned fixture rootfs (+ sandbox mountpoints), (b) the
# host swtpm-TCTI shim staged as libtss2-tcti-swtpm.so.0 (the pinned tpm2-tss
# table carries NO swtpm TCTI; the host one is ABI-compatible: it needs only
# libtss2-mu + libc). Fail loud (64) when a prerequisite is missing — the
# oracle never degrades to best-effort.
interop_oracle_bootstrap() {
    local dest="$1" tcti_lib
    interop_oracle_assert_ready || return $?
    [[ -n "$dest" ]] || { echo "interop-oracle: bootstrap dir required" >&2; return 64; }
    mkdir -p "$dest"
    if ! interop_oracle_rootfs "$dest/rootfs" >/dev/null; then
        echo "interop-oracle: fixture rootfs assembly failed" >&2
        return 1
    fi
    # the pinned userspace must be complete — a drifted pin is fatal, not a skip
    for f in usr/lib/systemd/systemd-cryptsetup \
             usr/lib/x86_64-linux-gnu/cryptsetup/libcryptsetup-token-systemd-tpm2.so \
             usr/sbin/cryptsetup usr/lib64/ld-linux-x86-64.so.2 \
             usr/lib/x86_64-linux-gnu/libcryptsetup.so.12 \
             usr/lib/x86_64-linux-gnu/libargon2.so.1; do
        [[ -e "$dest/rootfs/$f" ]] || {
            echo "interop-oracle: pinned rootfs is incomplete (missing $f) — refusing" >&2
            return 64
        }
    done
    tcti_lib="$(command -v libtss2-tcti-swtpm.so 2>/dev/null || \
        { for d in /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib64 /lib; do
              [[ -e "$d/libtss2-tcti-swtpm.so" ]] && { echo "$d/libtss2-tcti-swtpm.so"; break; }
          done; })"
    [[ -n "$tcti_lib" ]] || {
        echo "interop-oracle: host libtss2-tcti-swtpm.so not found — cannot feed swtpm to the pinned TSS" >&2
        return 64
    }
    mkdir -p "$dest/tcti"
    cp -f "$tcti_lib" "$dest/tcti/libtss2-tcti-swtpm.so.0" || return 1
    mkdir -p "$dest/tmp"
    # the upstream .pcrsig search-path mountpoint (per-attach --ro-bind target;
    # created here so bwrap can mount over it — the digest above predates it)
    : >"$dest/rootfs/etc/systemd/tpm2-pcr-signature.json"
    return 0
}

# interop_oracle_seal <dir> <keydir> — the REAL Mechanism B finalized seal:
# swtpm fixture with the §6.1 deterministic PCR 7/11 extends, a file-backed
# LUKS2 container (recovery slot 0), seal_finalized over a freshly signed
# {7,11} .pcrsig, and the lib/token.sh keyslot+import choreography. Sets:
#   ORACLE_SLOT        the enrolled keyslot (!= 0)
#   ORACLE_TOKEN       our §7.2 token JSON
#   ORACLE_PASS_FILE   the staged random volume passphrase (tmpfs; caller scrubs)
#   ORACLE_PCRSIG      the {7,11} .pcrsig JSON the seal was driven by
# Also exports ALPINE_FDE_TCTI for the caller. rc != 0 on any failure.
interop_oracle_seal() {
    local dir="$1" keydir="$2" d7 d11 pol fp sig_b64
    interop_oracle_assert_ready || return $?
    _interop_source_product_libs
    # shellcheck source=swtpm-fixture.sh disable=SC1091
    source "$_INTEROP_HERE/swtpm-fixture.sh"
    [[ -d "$dir" && -d "$keydir" && -f "$keydir/release.pem" ]] || {
        echo "interop-oracle: seal requires <dir> and a <keydir> with release.pem" >&2
        return 64
    }
    local tpmdir="$dir/swtpm"
    swtpm_stop "$tpmdir" 2>/dev/null
    swtpm_start "$tpmdir" || return 1
    ALPINE_FDE_TCTI=$SWTPM_TCTI
    export ALPINE_FDE_TCTI
    # deterministic PCR state (§6.1: fixed extends, sha256)
    swtpm_pcrextend "$tpmdir" 7 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef || return 1
    swtpm_pcrextend "$tpmdir" 11 fedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedcbafedc || return 1
    tpm flushcontext -t >/dev/null 2>&1 || true
    # live PCR digests, format-independent (swtpm_pcrread's awk expects the
    # old tpm2-tools "  7 : 0x" spacing; current tpm2-tools prints "  7: 0x")
    pcr_hex() { # <dir> <pcr> -> bare lowercase hex
        tpm pcrread -Q -o "$1/pcr$2.bin" "sha256:$2" >/dev/null 2>&1 || return 1
        od -An -v -tx1 "$1/pcr$2.bin" | tr -d ' \n'
    }
    d7=$(pcr_hex "$dir" 7) || return 1
    d11=$(pcr_hex "$dir" 11) || return 1
    [[ ${#d7} -eq 64 && ${#d11} -eq 64 ]] || {
        echo "interop-oracle: cannot read live PCR 7/11 from the swtpm fixture" >&2
        return 1
    }
    # the {7,11} .pcrsig in the systemd-measure sign shape (pcrsign's artifact)
    pol=$(policy_digest "$d7" "$d11") || return 1
    printf '%s' "$pol" | policy_hex_to_bin >"$dir/pol711.bin"
    openssl dgst -sha256 -sign "$keydir/release.pem" -out "$dir/sig711.bin" "$dir/pol711.bin" 2>/dev/null || return 1
    fp=$(policy_pubkey_fp "$keydir/release.pub") || return 1
    sig_b64=$(openssl base64 -A -in "$dir/sig711.bin") || return 1
    jq -n --arg pol "$pol" --arg sig "$sig_b64" --argjson pcrs '[7, 11]' --arg pkfp "$fp" \
        '{"sha256": [{"pcrs": $pcrs, "pkfp": $pkfp, "pol": $pol, "sig": $sig}]}' >"$dir/pcrsig711.json" || return 1

    # the real container + the real sealer + the real token choreography
    truncate -s 24M "$dir/luks.img" || return 1
    printf 'slot0-recovery-passphrase-0123456789ab' >"$dir/k0"
    chmod 600 "$dir/k0"
    cryptsetup luksFormat -q --type luks2 --key-slot 0 --key-file "$dir/k0" "$dir/luks.img" 2>/dev/null || return 1
    mkdir -p "$dir/tmp"
    ALPINE_FDE_TMPDIR=$dir/tmp
    SEAL_PASS_FILE='' SEAL_SLOT='' SEAL_POL='' SEAL_MODE=''
    seal_finalized "$keydir" "$dir/luks.img" "$dir/pcrsig711.json" "$dir/token.json" || return 1
    ORACLE_SLOT=$(token_free_slot "$dir/luks.img") || return 1
    token_add_keyslot "$dir/luks.img" "$SEAL_PASS_FILE" "$ORACLE_SLOT" "$dir/k0" || return 1
    token_import "$dir/luks.img" "$dir/token.json" "$(token_next_id "$dir/luks.img")" || return 1
    ORACLE_TOKEN=$dir/token.json
    ORACLE_PASS_FILE=$SEAL_PASS_FILE
    ORACLE_PCRSIG=$dir/pcrsig711.json
    return 0
}

# interop_oracle_project <dir> <keydir> — derive the upstream-257-consumable
# token + signature projection from ORACLE_TOKEN/ORACLE_PCRSIG (see the SCHEMA
# DELTA note at the top of this file for every rewrite, each one a pinned ADR-19
# finding). Sets ORACLE_TOKEN_UP / ORACLE_PCRSIG_UP.
interop_oracle_project() {
    local dir="$1" keydir="$2" name_hex sealed b64_pem fp_up
    [[ -s "${ORACLE_TOKEN:-}" && -s "${ORACLE_PCRSIG:-}" ]] || {
        echo "interop-oracle: project requires a prior interop_oracle_seal" >&2
        return 64
    }
    # the digest our blob is sealed under: the authorized policy digest over
    # the verifying key's TPM Name (lib/policy.sh policy_sealed_digest)
    tpm loadexternal -C o -G rsa -u "$keydir/release.pub" -c "$dir/proj-name.ctx" -n "$dir/proj-name.bin" >/dev/null 2>&1 || return 1
    name_hex=$(xxd -p -c 256 "$dir/proj-name.bin" | tr -d ' \n')
    [[ -n "$name_hex" ]] || { echo "interop-oracle: cannot read the verifying key TPM Name" >&2; return 1; }
    # free the transient slot again — the sandboxed upstream unseal needs every
    # object context the fixture TPM has (primary + pubkey + sealed blob)
    tpm flushcontext -t >/dev/null 2>&1 || true
    sealed=$(policy_sealed_digest "$name_hex") || return 1
    # upstream tpm2_pubkey = base64(PEM); ours is base64(DER SPKI)
    b64_pem=$(openssl pkey -pubin -in "$keydir/release.pub" -outform PEM 2>/dev/null | openssl base64 -A) || return 1
    [[ -n "$b64_pem" ]] || { echo "interop-oracle: cannot PEM-encode the release public key" >&2; return 1; }
    jq --arg d "$sealed" --arg p "$b64_pem" \
        '. + {"tpm2-policy-hash": $d, "tpm2_pubkey": $p, "tpm2_pubkey_pcrs": [7, 11],
              "tpm2-primary-alg": "rsa", "tpm2-pcrs": []}' \
        "$ORACLE_TOKEN" >"$dir/token-up.json" || return 1
    # upstream pkfp = SHA256 over the PKCS#1 RSAPublicKey DER (i2d_PublicKey),
    # not over the SPKI DER our pcrsign pins
    fp_up=$(openssl rsa -pubin -in "$keydir/release.pub" -RSAPublicKey_out -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
    [[ -n "$fp_up" ]] || { echo "interop-oracle: cannot fingerprint the RSA public key (upstream form)" >&2; return 1; }
    jq --arg f "$fp_up" '."sha256"[0].pkfp = $f' "$ORACLE_PCRSIG" >"$dir/pcrsig-up.json" || return 1
    ORACLE_TOKEN_UP=$dir/token-up.json
    ORACLE_PCRSIG_UP=$dir/pcrsig-up.json
    return 0
}

# interop_oracle_attach <dir> <img-basename> <token-json> <pcrsig-json> <log> —
# clone <dir>/luks.img to <dir>/<img-basename> with <token-json> installed as
# token 0, then run the ROOTFS's own systemd-cryptsetup `attach` under bwrap
# (tpm2-device= crypttab option carries the swtpm TCTI config; the release-key
# signature comes from the upstream search path /etc/systemd/
# tpm2-pcr-signature.json). Prints the upstream rc; the full upstream debug log
# lands in <log> — verdicts are asserted from THERE (upstream words, not ours).
interop_oracle_attach() {
    local dir="$1" img="$2" token="$3" pcrsig="$4" log="$5"
    local ld="/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:/tmp/work/tcti"
    [[ -d "$dir/rootfs" && -d "$dir/tcti" && -d "$dir/swtpm" && -s "$dir/luks.img" ]] || {
        echo "interop-oracle: attach requires bootstrap + seal first" >&2
        return 64
    }
    cp "$dir/luks.img" "$dir/$img" || return 1
    cryptsetup token remove "$dir/$img" --token-id 0 >/dev/null 2>&1 || true
    cryptsetup token import "$dir/$img" --token-id 0 --json-file "$token" --disable-external-tokens >/dev/null || return 1
    timeout 120 bwrap \
        --ro-bind "$dir/rootfs" / \
        --tmpfs /run --tmpfs /tmp --tmpfs /var \
        --bind "$dir/swtpm" /run/swtpm \
        --bind "$dir" /tmp/work \
        --dev-bind /dev /dev \
        --proc /proc \
        --ro-bind "$pcrsig" /etc/systemd/tpm2-pcr-signature.json \
        --setenv LD_LIBS "$ld" \
        --setenv CRYPTSETUP_TOKENS_PATH /usr/lib/x86_64-linux-gnu/cryptsetup \
        --setenv SYSTEMD_LOG_LEVEL debug \
        /usr/lib64/ld-linux-x86-64.so.2 --library-path "$ld" \
        /usr/lib/systemd/systemd-cryptsetup attach oraclevol "/tmp/work/$img" - \
        "luks,tpm2-device=swtpm:path=/run/swtpm/sock,headless=no" \
        >"$log" 2>&1
    echo $?
}

# interop_oracle_log_unsealed <log> <slot> — rc 0 iff the UPSTREAM log proves
# the token was consumed: the TPM unseal completed AND the unsealed key
# verified against our enrolled keyslot.
interop_oracle_log_unsealed() {
    grep -q 'Unsealing HMAC key for shard 0\.' "$1" \
        && grep -qE "Activating volume oraclevol \[keyslot $2\] using passphrase" "$1" \
        && ! grep -q 'does not match stored policy digest' "$1"
}

# interop_oracle_log_refused <log> — rc 0 iff the UPSTREAM log proves the
# token was REFUSED (no unseal attempt ever completed).
interop_oracle_log_refused() {
    ! grep -q 'Unsealing HMAC key for shard 0\.' "$1"
}

# interop_oracle_log_reason <log> — print the upstream refusal line (the
# reason), for loud diagnostics.
interop_oracle_log_reason() {
    grep -iE "lacks 'tpm2-|validation failed|Couldn't find signature|does not match stored|integrity check|Failed to load key|Received TPM Error" "$1" | head -3
}
