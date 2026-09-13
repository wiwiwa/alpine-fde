#!/bin/sh
# cmd/ukictl-remove.sh — `debian-fde ukictl remove <kver>` (gap B-G6 postrm wire):
# remove one kernel's UKI from the ESP and its entry from the digest manifest.
# Wire: /etc/kernel/postrm.d/zz-debian-fde (postrm passes the removed ABI version).
# Safe without the signing key — removal cannot create an unsigned-ESP state; a
# retained manifest entry without a file is harmless (fail-closed at boot, §10).
#
# TPM keyslot/token cleanup for the removed kernel is the enrollment bucket's
# concern (one enrollment per retained UKI, §7.2): it keys off the manifest
# diff, which this command updates — see docs/Architecture.md §8.3.

cmd_ukictl_remove_main() {
    strict_mode

    _ukrm_kver=${1:-}
    if [ -z "$_ukrm_kver" ] || [ $# -gt 1 ]; then
        err "ukictl remove: usage: debian-fde ukictl remove <kver>"
        exit "$DEBIAN_FDE_USAGE"
    fi

    _ukrm_lib_dir=$DEBIAN_FDE_CMD_DIR/../
    # shellcheck disable=SC1090  # resolved next to the command directory
    . "$_ukrm_lib_dir/common.sh"
    # shellcheck disable=SC1090
    . "$_ukrm_lib_dir/manifest.sh"
    # shellcheck disable=SC1090
    . "$_ukrm_lib_dir/esp.sh"
    load_config

    # LO-01: the kver interpolates into the ESP UKI path and the manifest prune
    # keep-set — validate at the boundary (usage error; `../traversal`, spaces,
    # shell/JSON metacharacters never reach path composition)
    if ! esp_validate_kver "$_ukrm_kver"; then
        err "ukictl remove: invalid kernel version: '$_ukrm_kver' (alphanumerics, '.', '_', '-' only)"
        exit "$DEBIAN_FDE_USAGE"
    fi

    _ukrm_etc="${DEBIAN_FDE_ROOT:-}/etc/debian-fde"
    _ukrm_manifest="$_ukrm_etc/digests.json"

    _ukrm_path=$(esp_uki_path "$_ukrm_kver")
    if [ -f "$_ukrm_path" ]; then
        rm -f "$_ukrm_path"
        info "ukictl remove: deleted $_ukrm_path"
    else
        info "ukictl remove: no UKI on the ESP for $_ukrm_kver ($_ukrm_path)"
    fi

    if [ -f "$_ukrm_manifest" ]; then
        if manifest_get "$_ukrm_manifest" "$_ukrm_kver" >/dev/null 2>&1; then
            _ukrm_keep=$(manifest_kvers "$_ukrm_manifest" | grep -Fxv -- "$_ukrm_kver")
            # shellcheck disable=SC2086  # word split intended: one kver per line
            manifest_prune_to "$_ukrm_manifest" $_ukrm_keep
            info "ukictl remove: manifest entry for $_ukrm_kver removed"
        else
            info "ukictl remove: no manifest entry for $_ukrm_kver"
        fi
    fi
    exit 0
}
