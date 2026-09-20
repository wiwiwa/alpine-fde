#!/usr/bin/env bash
# tests/unit/esp_prune_policy.sh — ESP install/prune contract (§9.2/§9.3, B-G5):
# keep current + 2 newest by Debian version sort; prune files+manifest from ONE
# keep-set decision; pruning only ever runs after a successful install (the
# end-to-end ordering lives in ukictl_build_stub / build_no_key_loud_fail).
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

# helpers beyond W0's lib.sh set (assert.sh's assert_rc has a different
# signature, so define the two missing ones here instead of mixing libraries)
assert_ne() {
    if [ "$2" != "$3" ]; then
        _pass "$1"
    else
        _fail "$1 (both values are [$2])"
    fi
}
assert_file_exists() {
    if [ -e "$2" ]; then
        _pass "$1"
    else
        _fail "$1 (file does not exist: $2)"
    fi
}
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/esp.sh
source "$REPO/lib/esp.sh"
# shellcheck source=../../lib/manifest.sh
source "$REPO/lib/manifest.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- CR fix (review B-CR1): esp_dir resolution order — env DEBIAN_FDE_ESP > env
# ESP_PATH > persisted conf ESP_PATH (install records the real mount in
# /etc/debian-fde/debian-fde.conf) > /efi default (install + boot-hook parity).
# All legs run in subshells so the ambient test env stays untouched.
mkdir -p "$TMP/cr1"
printf '%s\n' 'ESP_PATH=/efi-from-conf' >"$TMP/cr1/debian-fde.conf"
cr1=$(unset DEBIAN_FDE_ESP ESP_PATH; DEBIAN_FDE_CONF="$TMP/cr1/debian-fde.conf" esp_dir)
assert_eq "esp_dir: persisted conf ESP_PATH honored (env unset)" "/efi-from-conf" "$cr1"
cr2=$(unset DEBIAN_FDE_ESP ESP_PATH DEBIAN_FDE_CONF; esp_dir)
assert_eq "esp_dir: no conf + no env falls back to /efi (matches install/boot hook)" "/efi" "$cr2"
cr3=$(unset DEBIAN_FDE_ESP; ESP_PATH=/env-esp-path DEBIAN_FDE_CONF="$TMP/cr1/debian-fde.conf" esp_dir)
assert_eq "esp_dir: ESP_PATH env still wins over the conf" "/env-esp-path" "$cr3"
cr4=$(unset ESP_PATH; DEBIAN_FDE_ESP=/env-top DEBIAN_FDE_CONF="$TMP/cr1/debian-fde.conf" esp_dir)
assert_eq "esp_dir: DEBIAN_FDE_ESP wins over everything" "/env-top" "$cr4"
cr5=$(unset DEBIAN_FDE_ESP ESP_PATH; printf 'ESP_PATH="/efi quoted"\n' >"$TMP/cr1/q.conf"; DEBIAN_FDE_CONF="$TMP/cr1/q.conf" esp_dir)
assert_eq "esp_dir: conf value quotes are stripped (load_config parity)" "/efi quoted" "$cr5"

# --- keep-set math: Debian version sort (6.12.8-1 vs 6.12.10-1 vs 6.9.x) ----------
export DEBIAN_FDE_ESP="$TMP/esp"
mkdir -p "$(esp_uki_dir)"
for k in 6.12.8-1-amd64 6.12.10-1-amd64 6.1.0-1-amd64 5.15.0-2-amd64 6.12.9-1-amd64; do
    printf 'dummy-uki-%s' "$k" >"$(esp_uki_dir)/alpine-fde-$k.efi"
done
keep=$(esp_compute_keep "6.12.10-1-amd64" 2)
assert_eq "keep set = current first, then 2 newest others by Debian version sort" \
    "$(printf '6.12.10-1-amd64\n6.12.9-1-amd64\n6.12.8-1-amd64')" "$keep"

# --- G-C22: busybox-safe version sort (no `sort -V`; ADR-20 §3.1) -------------------
# busybox sort (the Alpine host toolchain, §3.1) has NO -V. If the comparator
# still shells out to `sort -V`, a busybox PATH silently degrades esp_compute_keep
# to "current only" and prune deletes the rollback UKIs. Pin: with a busybox-
# shaped `sort` stub on PATH (refuses -V, delegates everything else), both the
# comparator and the keep-set math stay correct.
SORT_FAKEBIN="$TMP/bin-busybox-sort"
mkdir -p "$SORT_FAKEBIN"
REAL_SORT=$(command -v sort)
cat >"$SORT_FAKEBIN/sort" <<EOF
#!/bin/sh
for a in "\$@"; do
    [ "\$a" = "-V" ] && { echo "sort: unrecognized option: -V (busybox shape)" >&2; exit 1; }
done
exec "$REAL_SORT" "\$@"
EOF
chmod +x "$SORT_FAKEBIN/sort"
SORTED=$(printf '6.12.9-1-amd64\n6.1.0-0-amd64\n6.12.10-1-amd64\n' \
    | PATH="$SORT_FAKEBIN:$PATH" esp_version_sort)
assert_eq "comparator: 6.12.10 > 6.12.9 > 6.1.0 without sort -V" \
    "$(printf '6.1.0-0-amd64\n6.12.9-1-amd64\n6.12.10-1-amd64')" "$SORTED"
SORTED2=$(printf '6.6.0-10-lts\n6.6.0-9-lts\n' | PATH="$SORT_FAKEBIN:$PATH" esp_version_sort)
assert_eq "comparator: numeric fields compare as numbers (9 < 10, 3- vs 2-digit)" \
    "$(printf '6.6.0-9-lts\n6.6.0-10-lts')" "$SORTED2"
STUB_KEEP=$(PATH="$SORT_FAKEBIN:$PATH" esp_compute_keep "6.12.10-1-amd64" 2)
assert_eq "keep set under a sort-without--V PATH: current + 2 newest others" \
    "$(printf '6.12.10-1-amd64\n6.12.9-1-amd64\n6.12.8-1-amd64')" "$STUB_KEEP"

# --- prune removes exactly the non-keep files --------------------------------------
# shellcheck disable=SC2046  # word split intended: one kver per line
esp_prune_ukis $(esp_compute_keep "6.12.10-1-amd64" 2)
assert_eq "prune: kept 6.12.10" "1" "$([ -f "$(esp_uki_dir)/alpine-fde-6.12.10-1-amd64.efi" ] && echo 1 || echo 0)"
assert_eq "prune: kept 6.12.9" "1" "$([ -f "$(esp_uki_dir)/alpine-fde-6.12.9-1-amd64.efi" ] && echo 1 || echo 0)"
assert_eq "prune: kept 6.12.8" "1" "$([ -f "$(esp_uki_dir)/alpine-fde-6.12.8-1-amd64.efi" ] && echo 1 || echo 0)"
assert_eq "prune: removed 6.1.0" "0" "$([ -f "$(esp_uki_dir)/alpine-fde-6.1.0-1-amd64.efi" ] && echo 1 || echo 0)"
assert_eq "prune: removed 5.15.0" "0" "$([ -f "$(esp_uki_dir)/alpine-fde-5.15.0-2-amd64.efi" ] && echo 1 || echo 0)"

# --- current kernel always kept even when an older version sorts lowest ------------
export DEBIAN_FDE_ESP="$TMP/esp2"
mkdir -p "$(esp_uki_dir)"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 6.3.0-1-amd64 6.4.0-1-amd64; do
    printf 'dummy-%s' "$k" >"$(esp_uki_dir)/alpine-fde-$k.efi"
done
# running kernel is 6.1.0 (rollback to it): it must survive despite sorting oldest;
# the retained others fill newest-first
keep=$(esp_compute_keep "6.1.0-1-amd64" 2)
assert_eq "rollback keep: current oldest still kept + 2 newest" \
    "$(printf '6.1.0-1-amd64\n6.4.0-1-amd64\n6.3.0-1-amd64')" "$keep"

# --- retention=0 keeps only the current kernel --------------------------------------
keep=$(esp_compute_keep "6.1.0-1-amd64" 0 | sort)
assert_eq "retention 0 keeps only current" "6.1.0-1-amd64" "$keep"

# --- install is atomic: replaces in place, leaves no staging files -------------------
export DEBIAN_FDE_ESP="$TMP/esp3"
printf 'uki-v1' >"$TMP/uki1"
printf 'uki-v2-longer-content' >"$TMP/uki2"
esp_install_uki "$TMP/uki1" "6.12.8-1-amd64"
assert_file_exists "install placed the UKI at the canonical path" \
    "$(esp_uki_path 6.12.8-1-amd64)"
esp_install_uki "$TMP/uki2" "6.12.8-1-amd64"
assert_eq "reinstall replaced the content" "uki-v2-longer-content" \
    "$(cat "$(esp_uki_path 6.12.8-1-amd64)")"
leftovers=$(find "$(esp_uki_dir)" -name '*.new.*' | wc -l | tr -d '[:space:]')
assert_eq "no staging (.new.PID) files left after install" 0 "$leftovers"

# --- install failure does not touch the previous UKI ---------------------------------
before=$(cat "$(esp_uki_path 6.12.8-1-amd64)")
out=$(esp_install_uki "$TMP/does-not-exist" "6.12.8-1-amd64" 2>&1)
rc=$?
assert_rc "installing a missing source fails loudly (64)" 64 $rc
assert_eq "failed install left the previous UKI intact" "uki-v2-longer-content" \
    "$(cat "$(esp_uki_path 6.12.8-1-amd64)")"

# --- prune helper refuses nothing silently: unknown kver -> file stays ---------------
esp_prune_ukis "6.12.8-1-amd64" # keep set containing the only file
assert_file_exists "prune keeps files in the keep set" "$(esp_uki_path 6.12.8-1-amd64)"

# --- LO-04: a failing rm propagates — prune never reports silent success --------------
export DEBIAN_FDE_ESP="$TMP/esp-ro"
mkdir -p "$(esp_uki_dir)"
for k in 6.12.8-1-amd64 6.0.0-1-amd64; do
    printf 'dummy-%s' "$k" >"$(esp_uki_path "$k")"
done
chmod 555 "$(esp_uki_dir)" # uid!=root: rm inside now fails with EACCES
ro_out=$(esp_prune_ukis "6.12.8-1-amd64" 2>&1)
ro_rc=$?
chmod 755 "$(esp_uki_dir)" # restore before asserts (cleanup trap needs it)
assert_rc "prune: rm failure propagates (rc 1, not silent success)" 1 "$ro_rc"
assert_contains "prune: failure names the file" "$ro_out" "6.0.0-1-amd64"
assert_file_exists "prune: failed rm left the file in place (fail-safe divergence)" \
    "$(esp_uki_path 6.0.0-1-amd64)"
esp_prune_ukis "6.12.8-1-amd64" "6.0.0-1-amd64" # clean up the seeded file

# --- manifest co-prune from the SAME keep-set decision (§9.2) ------------------------
M="$TMP/digests.json"
manifest_new "6.1.0-1-amd64" "fp" | manifest_atomic_write "$M"
for k in 6.1.0-1-amd64 6.2.0-1-amd64 6.3.0-1-amd64 6.4.0-1-amd64; do
    manifest_upsert "$M" "$k" "p11-$k" "pd-$k" "sig-$k"
done
export DEBIAN_FDE_ESP="$TMP/esp2" # restore for the shared decision
# shellcheck disable=SC2046
manifest_prune_to "$M" $(esp_compute_keep "6.1.0-1-amd64" 2)
assert_eq "manifest pruned from the same keep set as the ESP" \
    "$(printf '6.1.0-1-amd64\n6.3.0-1-amd64\n6.4.0-1-amd64')" "$(manifest_kvers "$M" | sort)"

finish
