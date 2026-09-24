#!/bin/sh
# alpine-fde-unseal.sh — mkinitfs Early-Boot Unseal Hook (docs/Architecture.md
# §8.2 + §9.1 Stage 2; ADR-13/ADR-20, gap G-C8). ONE POSIX-sh script, shipped
# into the initramfs via hooks/mkinitfs/features.d/alpine-fde.files.
#
# Boot-time flow (§8.2 steps 1-4):
#   1. tpm2_pcrextend the ukify --measure phase string ("enter-initrd", the
#      exact value lib/cmd/pcrsign.sh pins via --phases=enter-initrd) into
#      PCR 11, aligning the live PCR state with the signed prediction.
#   2. Read the LUKS2 systemd-tpm2 token (§7.2 dash-form schema, lib/token.sh)
#      via `cryptsetup token export` and the UKI stub's synthetic initrd
#      files /.extra/tpm2-pcr-signature.json + /.extra/tpm2-pcr-public-key.pem.
#   3. Policy session over the token's PCRs (policypcr) + PolicyAuthorize of
#      the approved policy digest: the DRIVE ENTRY's OWN .pcrsig signature is
#      verified (openssl) over the entry's `pol` digest against the /.extra
#      public key, then re-verified in-TPM (tpm2_verifysignature) before
#      tpm2_policyauthorize admits it — the keyName anchor lives INSIDE the
#      sealed blob, so a swapped /.extra key still fails the unseal (I3).
#      The token's tpm2-signature covers the ENROLL-time policy only and is
#      deliberately NOT required to cover the booting kernel's entry (G4:
#      any retained kernel unseals passwordless off its own .pcrsig entry,
#      §9.3). tpm2_unseal feeds `cryptsetup open --key-file -` per
#      /etc/crypttab (UUID= resolved via /dev/disk/by-uuid). Mirrors
#      lib/seal.sh seal_unseal argv-for-argv.
#   4. Fail-closed: TPM absent/refused, tampered token, missing /.extra
#      artifacts, or an empty unsealed secret fall back to a BOUNDED keyslot-0
#      recovery-passphrase prompt — 3 strikes total (shared across RAID1
#      members) end in `poweroff -f`. This hook NEVER spawns an interactive
#      shell; no interactive fallback of any kind exists here by construction.
#   5. After a successful unlock, flips the ADR-20 install-state marker on the
#      mounted NEWROOT from `installed` to `provisional-booted` (direct JSON
#      write, atomic tmp+mv, only when the state file says `installed`).
#
# Test seams (the real boot path uses the defaults): FDE_NEWROOT, FDE_CRYPTTAB,
# FDE_EXTRA_DIR, FDE_TMPDIR.
#
# Busybox mkinitfs environment only: no bashisms, no GNU tools beyond busybox
# (sha256sum/od/dd/sed/awk/tr/mktemp/date), openssl + cryptsetup + tpm2-tools
# binaries per the features.d file list.

set -u

FDE_NEWROOT=${FDE_NEWROOT:-/sysroot}
FDE_CRYPTTAB=${FDE_CRYPTTAB:-/etc/crypttab}
FDE_EXTRA_DIR=${FDE_EXTRA_DIR:-/.extra}
FDE_TMPDIR=${FDE_TMPDIR:-/tmp}
FDE_MAX_ATTEMPTS=3
FDE_PCR_PHASE=enter-initrd

_msg() { printf 'alpine-fde-unseal: %s\n' "$1" >&2; }
_err() { _msg "error: $1"; }

# _fdh_poweroff REASON — the terminal fail-closed action (§8.2): loud reason,
# forced poweroff, nonzero exit. The ONLY interactive-adjacent state this hook
# can end in.
_fdh_poweroff() {
    _err "$1"
    _msg "fail-closed: forcing poweroff (no shell is offered, §8.2)"
    poweroff -f
    exit 1
}

# _fdh_hex2bin HEX — hex string -> raw bytes on stdout. Pure busybox awk (no
# xxd in the initramfs).
# shellcheck disable=SC2120  # stdin consumer by design
_fdh_hex2bin() {
    printf '%s' "$1" | LC_ALL=C awk '{
        h = "0123456789abcdef"
        for (i = 1; i <= length($0); i += 2)
            printf "%c", (index(h, tolower(substr($0, i, 1))) - 1) * 16 + (index(h, tolower(substr($0, i + 1, 1))) - 1)
    }'
}

# _fdh_json_field FLATJSON FIELD — the "FIELD":"value" string value of a
# flattened §7.2 token (values are base64/hex: no quotes inside).
_fdh_json_field() {
    printf '%s\n' "$1" | sed -n "s/^.*\"$2\":\"\([A-Za-z0-9+/=]*\)\".*$/\1/p"
}

# _fdh_json_array FLATJSON FIELD — the element list inside "FIELD":[...].
_fdh_json_array() {
    printf '%s\n' "$1" | sed -n "s/^.*\"$2\":\[\([^]]*\)\].*$/\1/p"
}

# _fdh_members — "target device" pairs for every root/root<N> crypttab entry
# (§8.2: single target `root`, RAID1 members root1 root2, ...).
_fdh_members=$(sed -n 's/^[[:space:]]*\(root[0-9]*\)[[:space:]][[:space:]]*\([^[:space:]][^[:space:]]*\).*/\1 \2/p' \
    "$FDE_CRYPTTAB" 2>/dev/null)
if [ -z "$_fdh_members" ]; then
    # nothing to unlock and nothing to prompt for: configuration is broken —
    # fail closed instead of stumbling into an unauthenticated boot attempt
    _fdh_poweroff "no root/root<N> entry in $FDE_CRYPTTAB — cannot resolve the root container (§8.2)"
fi

# _fdh_resolve_dev DEVICE-FIELD — crypttab device field -> block device path.
# shellcheck disable=SC2120  # returns 1 on an unusable field
_fdh_resolve_dev() {
    case $1 in
        UUID=*)
            case ${1#UUID=} in
                *[!0-9a-fA-F-]*) return 1 ;;
            esac
            printf '/dev/disk/by-uuid/%s\n' "${1#UUID=}"
            ;;
        /dev/*) printf '%s\n' "$1" ;;
        *) return 1 ;;
    esac
}

# _fdh_prompt_pass TARGET — read the keyslot-0 recovery passphrase from the
# console (echo off when the console tty allows it; best-effort).
_fdh_prompt_pass() {
    _msg "enter the recovery passphrase for $1 (keyslot 0): "
    _fdh_echo_off=0
    if [ -t 0 ] && command -v stty >/dev/null 2>&1; then
        stty -echo 2>/dev/null && _fdh_echo_off=1
    fi
    IFS= read -r _fdh_pass || _fdh_pass=''
    if [ "$_fdh_echo_off" = 1 ]; then
        stty echo 2>/dev/null || :
        printf '\n' >&2
    fi
    printf '%s' "$_fdh_pass"
}

# --- §8.2 step 1: extend the ukify phase string into PCR 11 ---------------------
_fdh_tpm_ok=1
_fdh_phase_dgst=$(printf '%s' "$FDE_PCR_PHASE" | sha256sum | awk '{print $1}')
tpm2_pcrextend "11:sha256=$_fdh_phase_dgst" >/dev/null 2>&1 || _fdh_tpm_ok=0
if [ "$_fdh_tpm_ok" = 1 ]; then
    _msg "extended '$FDE_PCR_PHASE' into PCR 11 (ukify --measure phase alignment)"
else
    _msg "TPM absent or refused the PCR 11 extend — recovery passphrase path (§8.2)"
fi

# --- §8.2 steps 2+3: token path -------------------------------------------------
_fdh_pass_file=''
_fdh_w=''
if [ "$_fdh_tpm_ok" = 1 ]; then
    _fdh_w=$(mktemp -d "$FDE_TMPDIR/alpine-fde-unseal.XXXXXX") 2>/dev/null || _fdh_w=''
    [ -n "$_fdh_w" ] && chmod 700 "$_fdh_w" 2>/dev/null || :
fi
if [ -n "$_fdh_w" ] && [ -r "$FDE_EXTRA_DIR/tpm2-pcr-signature.json" ] &&
    [ -r "$FDE_EXTRA_DIR/tpm2-pcr-public-key.pem" ]; then
    # the first member carrying a systemd-tpm2 token pins policy + blob
    # (§8.2: all RAID1 members are enrolled with matching parameters).
    # Member pairing walks the whitespace-split word list (crypttab root
    # target/device fields are whitespace-free by grammar): odd word = target,
    # even word = device.
    _fdh_tok=''
    _fdh_exp_err=''
    _fdh_pos=0
    for _fdh_wd in $_fdh_members; do
        _fdh_pos=$((_fdh_pos + 1))
        if [ $((_fdh_pos % 2)) -eq 1 ]; then
            _fdh_target=$_fdh_wd
            continue
        fi
        _fdh_dev=$(_fdh_resolve_dev "$_fdh_wd") || continue
        _fdh_tid=0
        # LUKS2 allows up to 32 tokens (ids 0..31): scan the FULL valid range —
        # a token parked at id >=16 must still be found, never silently
        # dropped into the passphrase fallback (§8.2 step 2)
        while [ "$_fdh_tid" -le 31 ]; do
            _fdh_out=$(cryptsetup token export --token-id "$_fdh_tid" "$_fdh_dev" 2>"$_fdh_w/exp.err")
            if [ $? -ne 0 ]; then
                # fail VISIBLE: keep the FIRST line of WHY an export was
                # refused, so the recovery path is diagnosable from console
                if [ -s "$_fdh_w/exp.err" ] && [ -z "$_fdh_exp_err" ]; then
                    _fdh_exp_err=$(head -n 1 "$_fdh_w/exp.err" | tr -d '\r')
                fi
            else
                _fdh_tokflat=$(printf '%s' "$_fdh_out" | tr -d ' \t\n\r')
                case $_fdh_tokflat in
                    *'"type":"systemd-tpm2"'*) _fdh_tok=$_fdh_out ;;
                esac
                if [ -z "$_fdh_tok" ] && [ -z "$_fdh_exp_err" ]; then
                    # a successful export the type filter rejected: keep a
                    # fingerprint of the payload for the console record
                    _fdh_exp_err="token id $_fdh_tid exported, no systemd-tpm2 type in [$(printf '%s' \
                        "$_fdh_tokflat" | cut -c 1-60)]"
                fi
            fi
            [ -n "$_fdh_tok" ] && break
            _fdh_tid=$((_fdh_tid + 1))
        done
        [ -n "$_fdh_tok" ] && break
    done

    if [ -n "$_fdh_tok" ]; then
        # §7.2 dash-form token (lib/token.sh schema): tpm2-blob, tpm2-pcrs,
        # tpm2-pcr-bank, tpm2-signature (+ type checked above, keyslots logged)
        _fdh_tokflat=$(printf '%s' "$_fdh_tok" | tr -d ' \t\n\r')
        _fdh_pcrs=$(_fdh_json_array "$_fdh_tokflat" tpm2-pcrs)
        _fdh_bank=$(_fdh_json_field "$_fdh_tokflat" tpm2-pcr-bank)
        _fdh_blob=$(_fdh_json_field "$_fdh_tokflat" tpm2-blob)
        case $_fdh_pcrs in
            11 | 7,11) _fdh_sel=$_fdh_pcrs ;;
            *) _fdh_sel='' ;;
        esac
        _msg "token: pcrs=[$_fdh_pcrs] bank=$_fdh_bank keyslots=[$(_fdh_json_array "$_fdh_tokflat" keyslots)]"

        # the approved policy digest AND the drive entry's own release-key
        # signature come from the UKI stub's .pcrsig entry for EXACTLY the
        # PCR selection the token pins
        _fdh_pol=''
        _fdh_entsig=''
        if [ -n "$_fdh_sel" ] && [ "$_fdh_bank" = "sha256" ] && [ -n "$_fdh_blob" ]; then
            _fdh_sigflat=$(tr -d ' \t\n\r' <"$FDE_EXTRA_DIR/tpm2-pcr-signature.json")
            _fdh_pol=$(printf '%s\n' "$_fdh_sigflat" |
                sed -n "s/^.*\"pcrs\":\\[$_fdh_sel\\],[^{]*\"pol\":\"\([0-9a-fA-F]\{64\}\)\".*$/\1/p")
            _fdh_entsig=$(printf '%s\n' "$_fdh_sigflat" |
                sed -n "s/^.*\"pcrs\":\\[$_fdh_sel\\],[^{]*\"sig\":\"\([A-Za-z0-9+/=]*\)\".*$/\1/p")
        fi

        # openssl-level gate (I3, G4 rollback semantics): the DRIVE ENTRY's
        # OWN release-key signature must cover the entry's approved policy
        # digest and verify against the /.extra public key BEFORE any TPM
        # session — i.e. the entry was signed by the same authority whose
        # keyName the sealed policy's PolicyAuthorize pins. The token's
        # tpm2-signature covers the ENROLL-time policy only and is NOT
        # required to cover the booting kernel's entry (G4: retained kernels
        # unseal passwordless off their own .pcrsig entries, §9.3); it is
        # inert metadata here. The remaining anchors stay in the TPM and
        # fail closed: keyName via PolicyAuthorize (a swapped /.extra key or
        # a forged entry from an unknown key cannot rebuild the enrollment
        # policy) and live PCRs via PolicyPCR (a pol that does not match the
        # measured boot refuses).
        _fdh_rc=1
        if [ -n "$_fdh_pol" ] && [ -n "$_fdh_entsig" ]; then
            if printf '%s' "$_fdh_entsig" | openssl base64 -d -A >"$_fdh_w/sig.bin" 2>/dev/null; then
                _fdh_hex2bin "$_fdh_pol" >"$_fdh_w/pol.bin"
                if openssl dgst -sha256 -verify "$FDE_EXTRA_DIR/tpm2-pcr-public-key.pem" \
                    -signature "$_fdh_w/sig.bin" "$_fdh_w/pol.bin" >/dev/null 2>&1; then
                    _fdh_rc=0
                fi
            fi
        fi

        if [ "$_fdh_rc" -ne 0 ]; then
            _msg "token/signature verification refused (no release-key-signed .pcrsig entry for the token's PCR selection) — recovery passphrase path (I3)"
        else
            # in-TPM signature verification -> ticket for PolicyAuthorize.
            # The verifying key MUST be loaded into the OWNER hierarchy (-C o,
            # lib/seal.sh seal_unseal parity): TPM2_VerifySignature under the
            # NULL hierarchy (-C n) succeeds but issues NO validation ticket,
            # and without the ticket tpm2_policyauthorize aborts client-side
            # ("Could not load verification ticket file") before it ever sends
            # TPM2_PolicyAuthorize — the unseal then dies with a policy-check
            # failure on EVERY boot regardless of PCR state (0x910-style
            # session teardown noise in the swtpm trace is downstream of this).
            _fdh_rc=1
            if tpm2_loadexternal -C o -G rsa -u "$FDE_EXTRA_DIR/tpm2-pcr-public-key.pem" \
                -c "$_fdh_w/pub.ctx" -n "$_fdh_w/pub.name" >/dev/null 2>&1 &&
                tpm2_verifysignature -c "$_fdh_w/pub.ctx" -m "$_fdh_w/pol.bin" \
                    -s "$_fdh_w/sig.bin" -f rsassa -g sha256 -t "$_fdh_w/ticket.bin" >/dev/null 2>&1; then
                tpm2_flushcontext -t >/dev/null 2>&1 || :
                # split the packed tpm2-blob: TPM2B_PRIVATE (2-byte length
                # prefix KEPT) || TPM2B_PUBLIC — same encoding as seal_blob_split
                printf '%s' "$_fdh_blob" | openssl base64 -d -A >"$_fdh_w/blob.bin" 2>/dev/null
                _fdh_plen=$(dd if="$_fdh_w/blob.bin" bs=1 count=2 2>/dev/null | od -An -v -tx1 | head -n 1 |
                    awk '{ h = "0123456789abcdef"
                        b1 = (index(h, tolower(substr($1, 1, 1))) - 1) * 16 + (index(h, tolower(substr($1, 2, 1))) - 1)
                        b2 = (index(h, tolower(substr($2, 1, 1))) - 1) * 16 + (index(h, tolower(substr($2, 2, 1))) - 1)
                        print b1 * 256 + b2 }')
                if [ -n "$_fdh_plen" ] && [ "$_fdh_plen" -gt 0 ] 2>/dev/null; then
                    dd if="$_fdh_w/blob.bin" of="$_fdh_w/priv.bin" bs=1 count=$((2 + _fdh_plen)) 2>/dev/null
                    dd if="$_fdh_w/blob.bin" of="$_fdh_w/pub.bin" bs=1 skip=$((2 + _fdh_plen)) 2>/dev/null
                    # sealed object under the SRK (pinned template, seal.sh)
                    if tpm2_createprimary -C o -g sha256 -G rsa -c "$_fdh_w/primary.ctx" >/dev/null 2>&1 &&
                        tpm2_load -C "$_fdh_w/primary.ctx" -u "$_fdh_w/pub.bin" -r "$_fdh_w/priv.bin" \
                            -c "$_fdh_w/seal.ctx" >/dev/null 2>&1; then
                        tpm2_flushcontext -t >/dev/null 2>&1 || :
                        if tpm2_startauthsession --policy-session -S "$_fdh_w/sess.ctx" >/dev/null 2>&1 &&
                            tpm2_policypcr -S "$_fdh_w/sess.ctx" -l "sha256:$_fdh_sel" >/dev/null 2>&1 &&
                            tpm2_policyauthorize -S "$_fdh_w/sess.ctx" -i "$_fdh_w/pol.bin" \
                                -n "$_fdh_w/pub.name" -t "$_fdh_w/ticket.bin" >/dev/null 2>&1 &&
                            tpm2_unseal -c "$_fdh_w/seal.ctx" -p "session:$_fdh_w/sess.ctx" \
                                -o "$_fdh_w/pass.raw" >/dev/null 2>&1; then
                            tpm2_flushcontext -t >/dev/null 2>&1 || :
                            # FRAMING (ADR-19): the keyslot credential is
                            # base64(unsealed secret) — upstream's token plugin
                            # hands cryptsetup base64mem(secret), and
                            # lib/seal.sh staged exactly that at enroll time.
                            if openssl base64 -A -in "$_fdh_w/pass.raw" \
                                -out "$_fdh_w/pass.bin" >/dev/null 2>&1 && [ -s "$_fdh_w/pass.bin" ]; then
                                _fdh_rc=0
                            fi
                        fi
                    fi
                    tpm2_flushcontext -t >/dev/null 2>&1 || :
                fi
            fi
            if [ "$_fdh_rc" -eq 0 ]; then
                _fdh_pass_file=$_fdh_w/pass.bin
            else
                _msg "the TPM refused the sealed blob under the current PCR state (drift / foreign TPM / DA lock) — recovery passphrase path (§8.2)"
            fi
        fi
    else
        _msg "no systemd-tpm2 token found on any crypttab member — recovery passphrase path (§8.2)${_fdh_exp_err:+ [last export refusal: $_fdh_exp_err]}"
    fi
fi

# --- open every member with the unsealed secret (§8.2 step 3; RAID1: the
# unsealed passphrase is reused across all members without re-prompting) -------
_fdh_opened=0
_fdh_opened_list=''
if [ -n "$_fdh_pass_file" ]; then
    _fdh_pos=0
    for _fdh_wd in $_fdh_members; do
        _fdh_pos=$((_fdh_pos + 1))
        if [ $((_fdh_pos % 2)) -eq 1 ]; then
            _fdh_target=$_fdh_wd
            continue
        fi
        _fdh_dev=$(_fdh_resolve_dev "$_fdh_wd") || continue
        if cryptsetup open --type luks --key-file - "$_fdh_dev" "$_fdh_target" <"$_fdh_pass_file" >/dev/null 2>&1; then
            _fdh_opened=$((_fdh_opened + 1))
            _fdh_opened_list="$_fdh_opened_list $_fdh_target "
            _msg "unlocked $_fdh_target ($_fdh_dev) via the TPM token"
        else
            _msg "token unlock failed for $_fdh_target — recovery passphrase path (§8.2)"
        fi
    done
    rm -rf "$_fdh_w"
    _fdh_w=''
    _fdh_pass_file=''
fi

# --- §8.2 step 4: BOUNDED recovery-passphrase path (keyslot 0, 3 strikes
# TOTAL across all members), then poweroff -f. NO shell is ever offered.
# EVERY member not yet unlocked enters this loop — a partial RAID1 token
# unlock (one member's token open failed, §10 "kernel re-signed, its
# enrollment missing/stale") must never leave the pool silently incomplete.
_fdh_cached=''
_fdh_tries=0
_fdh_pos=0
for _fdh_wd in $_fdh_members; do
    _fdh_pos=$((_fdh_pos + 1))
    if [ $((_fdh_pos % 2)) -eq 1 ]; then
        _fdh_target=$_fdh_wd
        continue
    fi
    case $_fdh_opened_list in
        *" $_fdh_target "*) continue ;; # already unlocked via the TPM token
    esac
    _fdh_dev=$(_fdh_resolve_dev "$_fdh_wd") || continue
    _fdh_done=0
    while [ "$_fdh_done" -eq 0 ]; do
        if [ -n "$_fdh_cached" ]; then
            if printf '%s' "$_fdh_cached" | cryptsetup open --type luks --key-file - \
                "$_fdh_dev" "$_fdh_target" >/dev/null 2>&1; then
                _fdh_opened=$((_fdh_opened + 1))
                _fdh_done=1
                _msg "unlocked $_fdh_target ($_fdh_dev) via the recovery passphrase"
                continue
            fi
            _fdh_cached=''
        fi
        if [ "$_fdh_tries" -ge "$FDE_MAX_ATTEMPTS" ]; then
            _fdh_poweroff "$FDE_MAX_ATTEMPTS failed recovery passphrase attempts — giving up (§8.2 fail-closed)"
        fi
        _fdh_cached=$(_fdh_prompt_pass "$_fdh_target")
        _fdh_tries=$((_fdh_tries + 1))
    done
done

# --- §9.1 Stage 2 / ADR-20: flip installed -> provisional-booted on the
# mounted NEWROOT (atomic tmp+mv; only when the state file says installed) ------
if [ "$_fdh_opened" -gt 0 ]; then
    _fdh_state_dir="$FDE_NEWROOT/etc/alpine-fde"
    _fdh_state_file="$_fdh_state_dir/install-state.json"
    if [ -f "$_fdh_state_file" ]; then
        _fdh_cur=$(sed -n 's/^  "state": "\(.*\)",\{0,1\}$/\1/p' "$_fdh_state_file" | head -n 1)
        if [ "$_fdh_cur" = "installed" ]; then
            _fdh_tmp=$(mktemp "$_fdh_state_dir/.install-state.XXXXXX") || _fdh_tmp=''
            if [ -n "$_fdh_tmp" ]; then
                {
                    printf '{\n'
                    printf '  "schema_version": 1,\n'
                    printf '  "state": "provisional-booted",\n'
                    printf '  "updated_at": "%s"\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
                    printf '}\n'
                } >"$_fdh_tmp" 2>/dev/null &&
                    chmod 600 "$_fdh_tmp" 2>/dev/null || :
                if mv -f "$_fdh_tmp" "$_fdh_state_file" 2>/dev/null; then
                    _msg "install-state: installed -> provisional-booted"
                else
                    rm -f "$_fdh_tmp" 2>/dev/null || :
                    _msg "warning: could not update the install-state marker (finalize resumes on the next boot)"
                fi
            else
                _msg "warning: could not stage the install-state marker (finalize resumes on the next boot)"
            fi
        fi
    fi
fi

exit 0
