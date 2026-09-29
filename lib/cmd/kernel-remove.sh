#!/bin/sh
# cmd/kernel-remove.sh — `alpine-fde kernel remove <kver>` (gap B-G6 wire):
# remove one kernel's UKI from the ESP and its entry from the digest manifest.
# Wire: hooks/kernel-hooks.d/alpine-fde-remove.hook (invoked by the Alpine
# kernel hook on remove; the APK trigger at hooks/apk/triggers/alpine-fde.trigger
# fans kernel add/update/remove out to this toolchain).
# Safe without the signing key — removal cannot create an unsigned-ESP state; a
# retained manifest entry without a file is harmless (fail-closed at boot, §10).
#
# TPM keyslot/token cleanup for the removed kernel is the enrollment bucket's
# concern (one enrollment per retained UKI, §7.2): it keys off the manifest
# diff, which this command updates — see docs/Architecture.md §8.3.

cmd_kernel_remove_main() {
    strict_mode

    _ukrm_kver=${1:-}
    if [ -z "$_ukrm_kver" ] || [ $# -gt 1 ]; then
        err "kernel remove: usage: alpine-fde kernel remove <kver>"
        exit "$ALPINE_FDE_USAGE"
    fi

    _ukrm_lib_dir=$ALPINE_FDE_CMD_DIR/../
    # shellcheck disable=SC1090  # resolved next to the command directory
    . "$_ukrm_lib_dir/common.sh"
    # shellcheck disable=SC1090
    . "$_ukrm_lib_dir/manifest.sh"
    # shellcheck disable=SC1090
    . "$_ukrm_lib_dir/esp.sh"
    # the NVRAM boot-entry sweep (inst_bootentry_prune) lives next door in the
    # install lane; sourcing keeps ONE efibootmgr implementation
    # shellcheck disable=SC1091  # sibling in the same command directory
    . "$ALPINE_FDE_CMD_DIR/install.sh"
    load_config

    # LO-01: the kver interpolates into the ESP UKI path and the manifest prune
    # keep-set — validate at the boundary (usage error; `../traversal`, spaces,
    # shell/JSON metacharacters never reach path composition)
    if ! esp_validate_kver "$_ukrm_kver"; then
        err "kernel remove: invalid kernel version: '$_ukrm_kver' (alphanumerics, '.', '_', '-' only)"
        exit "$ALPINE_FDE_USAGE"
    fi

    _ukrm_etc="${ALPINE_FDE_ROOT:-}/etc/alpine-fde"
    _ukrm_manifest="$_ukrm_etc/digests.json"

    # two-UKI design: BOTH console variants of the kver go together (the
    # -serial sibling is never left behind — an orphaned sibling would keep a
    # pruned kernel bootable via its firmware menu item).
    for _ukrm_variant in default serial; do
        _ukrm_path=$(esp_uki_path "$_ukrm_kver" "$_ukrm_variant")
        if [ -f "$_ukrm_path" ]; then
            rm -f "$_ukrm_path"
            info "kernel remove: deleted $_ukrm_path"
        else
            info "kernel remove: no $_ukrm_variant UKI on the ESP for $_ukrm_kver ($_ukrm_path)"
        fi
    done
    # the firmware NVRAM entries ride along: the pair's boot entries must not
    # outlive the UKIs they point at (best-effort — a build/remove context
    # without efivars skips with a warn; the next ESP prune also sweeps)
    inst_bootentry_prune "$_ukrm_kver"

    if [ -f "$_ukrm_manifest" ]; then
        if manifest_get "$_ukrm_manifest" "$_ukrm_kver" >/dev/null 2>&1; then
            _ukrm_keep=$(manifest_kvers "$_ukrm_manifest" | grep -Fxv -- "$_ukrm_kver")
            # shellcheck disable=SC2086  # word split intended: one kver per line
            manifest_prune_to "$_ukrm_manifest" $_ukrm_keep
            info "kernel remove: manifest entry for $_ukrm_kver removed"
        else
            info "kernel remove: no manifest entry for $_ukrm_kver"
        fi
    fi
    exit 0
}
