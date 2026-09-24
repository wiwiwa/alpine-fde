#!/usr/bin/env bash
# tests/unit/dispatch_flags.sh — dispatcher global-flag surface for the Wave 2
# topologies (README quick start; Architecture.md §8.1 flags):
#   * --disk repeatable: values accumulate newline-separated into
#     ALPINE_FDE_DISKS; ALPINE_FDE_DISK stays the LAST value (backward compat)
#   * --bcache <dev> forwards ALPINE_FDE_BCACHE
#   * --fs <btrfs|ext4> validated — anything else is usage (rc 2)
#   * global flags must precede the subcommand; later flags pass through
#   * `finalize` is a registered subcommand

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=../lib/assert.sh
source "$HERE/../lib/assert.sh"
SP="$REPO/bin/alpine-fde"

T=$(mktemp -d /tmp/alpine-fde-dflags.XXXXXX)
trap 'rm -rf "$T"' EXIT
CMD=$T/cmd
mkdir -p "$CMD"

# stub: report which flag variables the dispatcher forwarded
cat >"$CMD/status.sh" <<'EOF'
cmd_status_main() {
    printf 'STUB|DISK=%s|DISKS=%s|BCACHE=%s|FS=%s|ARGS=%s\n' \
        "${ALPINE_FDE_DISK-}" \
        "$(printf '%s' "${ALPINE_FDE_DISKS-}" | tr '\n' ',')" \
        "${ALPINE_FDE_BCACHE-}" "${ALPINE_FDE_FS-}" "$*"
}
EOF

sp() {
    env -u ALPINE_FDE_DISK -u ALPINE_FDE_DISKS -u ALPINE_FDE_BCACHE -u ALPINE_FDE_FS \
        -u ALPINE_FDE_ROOT -u ALPINE_FDE_ESP -u ALPINE_FDE_KEYDIR -u ALPINE_FDE_TCTI \
        -u ALPINE_FDE_YES -u ALPINE_FDE_DRY_RUN \
        ALPINE_FDE_CONF="$T/absent.conf" \
        ALPINE_FDE_CMD_DIR="$CMD" \
        "$SP" "$@"
}

# --- --disk: single value --------------------------------------------------------
out=$(sp --disk /dev/nvme0n1 status)
assert_eq "single --disk sets DISK and DISKS" \
    "STUB|DISK=/dev/nvme0n1|DISKS=/dev/nvme0n1|BCACHE=|FS=|ARGS=" "$out"

# --- --disk: repeatable (RAID1) — DISK = last value, DISKS accumulates in order --
out=$(sp --disk /dev/sda --disk /dev/nvme1n1 status)
assert_eq "repeatable --disk: DISK = last value (backward compat), DISKS in order" \
    "STUB|DISK=/dev/nvme1n1|DISKS=/dev/sda,/dev/nvme1n1|BCACHE=|FS=|ARGS=" "$out"

out=$(sp --disk /dev/sda --fs btrfs --disk /dev/nvme1n1 --bcache /dev/nvme0n1 status)
assert_eq "interleaved flags: all accumulated, last --disk wins DISK" \
    "STUB|DISK=/dev/nvme1n1|DISKS=/dev/sda,/dev/nvme1n1|BCACHE=/dev/nvme0n1|FS=btrfs|ARGS=" "$out"

# --- --fs validation --------------------------------------------------------------
out=$(sp --fs ext4 status)
assert_eq "--fs ext4 accepted" \
    "STUB|DISK=|DISKS=|BCACHE=|FS=ext4|ARGS=" "$out"

rc=0
out=$(sp --fs xfs status 2>&1 >/dev/null) || rc=$?
assert_eq "invalid --fs -> usage rc 2" "2" "$rc"
assert_contains "invalid --fs named in the error" "$out" "--fs"
assert_contains "invalid --fs prints usage" "$out" "Usage:"

rc=0
out=$(sp --fs 2>&1 >/dev/null) || rc=$?
assert_eq "--fs at end of argv (no value) -> usage rc 2" "2" "$rc"
assert_contains "--fs missing value named" "$out" "requires an argument"

# --- global flags precede the subcommand ------------------------------------------
out=$(sp status --fs btrfs --disk /dev/sda)
assert_eq "flags after the subcommand pass through untouched" \
    "STUB|DISK=|DISKS=|BCACHE=|FS=|ARGS=--fs btrfs --disk /dev/sda" "$out"

# --- ALPINE_FDE_* env namespace read directly (§8.1; alias layer retired) -----------
# One representative flag env: ALPINE_FDE_DISK must reach the cmd verbatim
# (no alias rewrite). sp strips it deliberately, so set it downstream of the -u list.
out=$(env -u ALPINE_FDE_DISKS -u ALPINE_FDE_BCACHE -u ALPINE_FDE_FS \
    -u ALPINE_FDE_ROOT -u ALPINE_FDE_ESP -u ALPINE_FDE_KEYDIR -u ALPINE_FDE_TCTI \
    -u ALPINE_FDE_YES -u ALPINE_FDE_DRY_RUN \
    ALPINE_FDE_CONF="$T/absent.conf" ALPINE_FDE_CMD_DIR="$CMD" \
    ALPINE_FDE_DISK=/dev/alpine-live-disk "$SP" status)
assert_eq "ALPINE_FDE_DISK env reaches the cmd as ALPINE_FDE_DISK" \
    "STUB|DISK=/dev/alpine-live-disk|DISKS=|BCACHE=|FS=|ARGS=" "$out"

# --- finalize is a registered subcommand ------------------------------------------
rc=0
out=$(sp finalize 2>&1 >/dev/null) || rc=$?
assert_eq "finalize is registered (no stub cmd file -> not-implemented 3, not usage 2)" "3" "$rc"
assert_contains "finalize missing cmd file says not implemented" "$out" "not implemented"

out=$(sp --help 2>&1)
assert_contains "--help lists finalize" "$out" "finalize"
assert_contains "--help documents --bcache" "$out" "--bcache"
assert_contains "--help documents --fs" "$out" "--fs"
assert_contains "--help documents repeatable --disk" "$out" "repeatable"

exit $(( TESTS_FAIL > 0 ? 1 : 0 ))
