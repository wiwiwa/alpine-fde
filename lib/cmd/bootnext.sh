#!/bin/sh
# bootnext.sh — `debian-fde bootnext <entry>`: one-shot boot entry for rollback
# (§8.1, §9.3; C-G11). Writes the EFI variable LoaderEntryOneShot under the
# systemd loader GUID directly to efivarfs (no bootctl/systemd round-trip):
#   file: <efivars>/LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
#   body: u32 attributes (0x7 NV+BS+RT, little-endian) + UTF-16LE entry id
# Delete-then-write (a stale var may exist with a different size). No argument
# prints the current value. The firmware hands the entry to the boot manager
# for the NEXT boot only, then clears the variable.

if [ -n "${DEBIAN_FDE_BOOTNEXT_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_BOOTNEXT_LOADED=1

if [ -z "${DEBIAN_FDE_BASELINE_LOADED:-}" ]; then
    # shellcheck disable=SC1090
    . "${DEBIAN_FDE_CMD_DIR:-/usr/share/debian-fde/lib/cmd}/../baseline.sh"
fi

BN_VAR_NAME='LoaderEntryOneShot'
BN_VAR_GUID='4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'

bootnext_usage() {
    cat >&2 <<'EOF'
Usage: debian-fde bootnext [<entry-id>]

Set the one-shot boot entry (UEFI LoaderEntryOneShot; consumed by
systemd-boot on the NEXT boot only, then cleared by the firmware). <entry-id>
is the loader entry id as listed by `bootctl list`, e.g.
alpine-fde-6.6.0-0-lts.conf. Without argument: print the current value.
EOF
}

# bn_var_path — full efivarfs path of the LoaderEntryOneShot variable
bn_var_path() {
    _bp_dir=$(fw_efivars_dir)
    printf '%s/%s-%s\n' "$_bp_dir" "$BN_VAR_NAME" "$BN_VAR_GUID"
}

# bn_validate_entry ENTRY — rc 0 iff usable as an entry id
bn_validate_entry() {
    _bv_e=$1
    [ -n "$_bv_e" ] || return 1
    case $_bv_e in
        *[![:alnum:]_.-]*) return 1 ;;
    esac
    [ "${#_bv_e}" -le 200 ] || return 1
    return 0
}

# bn_encode ENTRY — var file body on stdout (u32le attrs 0x7 + UTF-16LE id);
# self-contained (no provision.sh helpers): awk emits char + NUL pairs
bn_encode() {
    {
        printf '\007\000\000\000'
        printf '%s\n' "$1" | awk '{
            for (i = 1; i <= length($0); i++)
                printf "%c%c", substr($0, i, 1), 0
        }'
    }
}

cmd_bootnext_main() {
    strict_mode

    _bm_dry=0
    _bm_entry=''
    _bm_given=0
    while [ $# -gt 0 ]; do
        case $1 in
            -h | --help)
                bootnext_usage
                return 0
                ;;
            --dry-run) _bm_dry=1 ;;
            --)
                shift
                break
                ;;
            -*) die -r "$DEBIAN_FDE_USAGE" "bootnext: unknown option: $1" ;;
            *)
                [ "$_bm_given" -eq 0 ] || die -r "$DEBIAN_FDE_USAGE" "bootnext: unexpected arguments: $*"
                _bm_entry=$1
                _bm_given=1
                ;;
        esac
        shift
    done

    _bm_path=$(bn_var_path)
    _bm_dir=${_bm_path%/*}
    if [ "$_bm_given" -eq 0 ]; then
        # display current value
        if [ ! -f "$_bm_path" ]; then
            printf '(unset)\n'
            return 0
        fi
        _bm_val=$(tail -c +5 "$_bm_path" | tr -d '\000')
        if [ -z "$_bm_val" ]; then
            printf '(unset)\n'
        else
            printf '%s\n' "$_bm_val"
        fi
        return 0
    fi

    _bm_entry_set=$_bm_entry
    if ! bn_validate_entry "$_bm_entry"; then
        die -r "$DEBIAN_FDE_USAGE" "bootnext: invalid entry id: '$_bm_entry' (alphanumerics, '.', '_', '-' only, <= 200 chars)"
    fi
    if [ "$_bm_dry" -eq 1 ]; then
        info "dry-run: would write LoaderEntryOneShot = '$_bm_entry_set' (attrs 0x7) to $_bm_path"
        return 0
    fi
    [ -d "$_bm_dir" ] || die "bootnext: efivarfs directory not found: $_bm_dir (booted without UEFI?)"
    [ -w "$_bm_dir" ] || die "bootnext: efivarfs not writable (need root?) — try sudo"
    # delete-then-write: a stale variable may hold a longer payload
    rm -f "$_bm_path"
    bn_encode "$_bm_entry" >"$_bm_path" || die "bootnext: writing $_bm_path failed"
    printf 'debian-fde: one-shot boot entry set: %s (next boot only)\n' "$_bm_entry" >&2
    return 0
}
