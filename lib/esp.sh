#!/bin/sh
# esp.sh — ESP file operations for Alpine FDE UKIs (docs/Architecture.md §8.4, §9.2,
# gap B-G5). Layout convention: ESP:/EFI/Linux/alpine-fde-<kernel-version>.efi
# (one UKI per kernel).
#
# Ordering contract (ADR-8, B-G5): a UKI is installed atomically (temp + fsync +
# rename) and PRUNING happens only after a successful install + manifest update —
# a failed build must leave the previous default UKI bootable and unlockable.
# The retention decision (keep current + N newest by version sort) is
# computed ONCE here and drives both the ESP prune and the manifest prune so the
# two can never diverge (§9.2: "pruned together").
#
# The ESP is a directory mount point (DEBIAN_FDE_ESP flag / ESP_PATH config /
# /efi). ESP image files are mounted by the caller (install / CI harness).
#
# Depends on: lib/common.sh. esp_version_sort is busybox-safe (no `sort -V`,
# ADR-20 §3.1).

if [ -n "${DEBIAN_FDE_ESP_LOADED:-}" ]; then
    return 0
fi
DEBIAN_FDE_ESP_LOADED=1

# esp_dir — effective ESP mount point. Resolution order: $DEBIAN_FDE_ESP (flag)
# > $ESP_PATH (config/env) > the ESP_PATH persisted at install time in
# /etc/alpine-fde/alpine-fde.conf (single source of truth for the actual mount,
# §8.1) > /efi (the layout install sets up — same default as the boot-manager
# hook, so library-only consumers can never drift back to a created-on-root
# /boot/efi; review B-CR1).
esp_dir() {
    if [ -n "${DEBIAN_FDE_ESP:-}" ]; then
        printf '%s\n' "$DEBIAN_FDE_ESP"
        return 0
    fi
    if [ -n "${ESP_PATH:-}" ]; then
        printf '%s\n' "$ESP_PATH"
        return 0
    fi
    if command -v config_path >/dev/null 2>&1; then
        _esp_conf=$(config_path)
    else
        _esp_conf=/etc/alpine-fde/alpine-fde.conf
    fi
    if [ -n "$_esp_conf" ] && [ -f "$_esp_conf" ]; then
        # targeted parse (load_config parity): last-writer-wins would be
        # surprising here — first ESP_PATH= line, surrounding quotes stripped
        _esp_val=$(sed -n 's/^[[:space:]]*ESP_PATH[[:space:]]*=[[:space:]]*//p' \
            "$_esp_conf" 2>/dev/null | head -n 1 | sed 's/[[:space:]]*$//')
        case $_esp_val in
            '"'*)
                case $_esp_val in
                    '"'*'"') _esp_val=${_esp_val#\"}; _esp_val=${_esp_val%\"} ;;
                esac
                ;;
            "'"*)
                case $_esp_val in
                    "'"*"'") _esp_val=${_esp_val%\'}; _esp_val=${_esp_val#\'} ;;
                esac
                ;;
        esac
        if [ -n "$_esp_val" ]; then
            printf '%s\n' "$_esp_val"
            return 0
        fi
    fi
    printf '%s\n' /efi
}

# esp_uki_dir — directory holding Debian FDE UKIs on the ESP
esp_uki_dir() {
    printf '%s/EFI/Linux\n' "$(esp_dir)"
}

# esp_validate_kver KVER — rc 0 iff KVER is safe to interpolate into UKI paths
# and manifest keys (defense-in-depth, review LO-01: `../` traversal and
# shell/JSON metacharacters never reach path composition or the keep-set JSON)
esp_validate_kver() {
    case ${1:-} in
        '' | *[!A-Za-z0-9._-]*) return 1 ;;
    esac
    return 0
}

# esp_uki_path <kver> — canonical UKI path for a kernel version
esp_uki_path() {
    printf '%s/alpine-fde-%s.efi\n' "$(esp_uki_dir)" "$1"
}

# esp_list_kvers — kernel versions of the UKIs currently on the ESP,
# one per line, unsorted. Empty output when none.
esp_list_kvers() {
    _esp_d=$(esp_uki_dir)
    [ -d "$_esp_d" ] || return 0
    for _esp_f in "$_esp_d"/alpine-fde-*.efi; do
        [ -f "$_esp_f" ] || continue
        _esp_b=$(basename "$_esp_f")
        printf '%s\n' "${_esp_b#alpine-fde-}" | sed 's/\.efi$//'
    done
}

# esp_version_sort — kernel versions on stdin, ascending version order.
# Busybox-safe (ADR-20, §3.1: the host is an Alpine live system — coreutils is
# NOT in the package set, and busybox sort has no -V): a GNU `sort -V` here
# would make esp_compute_keep silently degrade to "current only" on Alpine and
# prune the rollback UKIs. Instead each line gets a byte-sortable key — every
# dot/dash-separated field zero-padded to a fixed width when numeric, absent
# fields padded below any real field (shorter versions sort first) — which is
# then ordered by PLAIN `sort` (present in busybox), keys stripped afterwards.
# Usage: esp_version_sort [-r]
esp_version_sort() {
    _evs_rev=''
    if [ "${1:-}" = "-r" ]; then
        _evs_rev="-r"
    fi
    # shellcheck disable=SC2086  # $_evs_rev is "-r" or empty
    awk '{
        n = split($1, f, /[.-]/)
        key = ""
        for (i = 1; i <= n; i++) {
            if (f[i] ~ /^[0-9]+$/) key = key sprintf("%010d", f[i]) "/"
            else key = key f[i] "/"
        }
        for (i = n + 1; i <= 12; i++) key = key sprintf("%c", 1) "/"
        printf "%s\t%s\n", key, $1
    }' | LC_ALL=C sort $_evs_rev | sed 's/^[^\t]*\t//'
}

# esp_compute_keep <current_kver> <retention> — print the keep set (one kver per
# line): the current kernel plus the <retention> newest OTHER versions. Current
# is always kept even if an older version sorts higher (should not happen; the
# running kernel wins).
esp_compute_keep() {
    _esp_cur=$1
    _esp_ret=$2
    printf '%s\n' "$_esp_cur"
    esp_list_kvers | esp_version_sort -r | grep -Fxv -- "$_esp_cur" | head -n "$_esp_ret"
}

# esp_install_uki <src-file> <kver> — atomically install a UKI:
# copy to "<dst>.new" in the same directory, fsync the data, rename over the
# destination, best-effort fsync of the directory. The rename is atomic within
# the filesystem, so the ESP never holds a partial UKI under the final name.
esp_install_uki() {
    _esp_src=$1
    _esp_kver=$2
    [ -f "$_esp_src" ] || die "esp: UKI source not found: $_esp_src"
    _esp_d=$(esp_uki_dir)
    if ! mkdir -p "$_esp_d"; then
        die "esp: cannot create UKI directory $_esp_d"
    fi
    _esp_dst="$_esp_d/alpine-fde-$_esp_kver.efi"
    _esp_tmp="$_esp_dst.new.$$"
    if ! cat "$_esp_src" >"$_esp_tmp"; then
        rm -f "$_esp_tmp"
        die "esp: staging UKI failed: $_esp_tmp"
    fi
    sync -f "$_esp_tmp" 2>/dev/null || true
    if ! mv -f "$_esp_tmp" "$_esp_dst"; then
        rm -f "$_esp_tmp"
        die "esp: atomic UKI rename failed: $_esp_tmp -> $_esp_dst"
    fi
    sync -d "$_esp_d" 2>/dev/null || warn "esp: directory fsync not supported ($_esp_d)"
    info "esp: installed UKI $_esp_dst ($(wc -c <"$_esp_dst" | tr -d '[:space:]') bytes)"
}

# esp_prune_ukis <kver>... — remove every alpine-fde-*.efi whose kernel version is
# NOT in the keep-set arguments. Callers MUST pass the set computed by
# esp_compute_keep after a successful install (prune is never run on a failed
# build; the caller owns the ordering).
esp_prune_ukis() {
    _esp_d=$(esp_uki_dir)
    [ -d "$_esp_d" ] || return 0
    for _esp_f in "$_esp_d"/alpine-fde-*.efi; do
        [ -f "$_esp_f" ] || continue
        _esp_b=$(basename "$_esp_f")
        _esp_k=${_esp_b#alpine-fde-}
        _esp_k=${_esp_k%.efi}
        _esp_keep=0
        for _esp_want in "$@"; do
            if [ "$_esp_k" = "$_esp_want" ]; then
                _esp_keep=1
                break
            fi
        done
        if [ "$_esp_keep" -eq 0 ]; then
            # LO-04: a failed rm means ESP and manifest would silently diverge
            # (§9.2 "pruned together" becomes unverifiable) — propagate loudly;
            # the caller (`ukictl build`) treats this as a marked failure.
            if ! rm -f "$_esp_f"; then
                err "esp: prune failed: $_esp_f"
                return 1
            fi
            info "esp: pruned $_esp_f"
        fi
    done
}

return 0
