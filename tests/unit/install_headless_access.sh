#!/usr/bin/env bash
# tests/unit/install_headless_access.sh — REAL-SERVER BLOCKER (headless,
# Dell PowerEdge R640 first verified boot 2026-09-28): the guest shipped
# NEITHER a serial getty NOR sshd — on a headless server the operator was
# locked out of the booted system. Contract over the lib/cmd/install.sh
# headless-access emitters:
#   1. inst_inittab_getty_cmd emits a guarded, IDEMPOTENT busybox getty
#      record for ttyS0 (`ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100`)
#      — running the emitted record against a fixture inittab appends the
#      line + marker; running it TWICE appends exactly once; a fixture that
#      already carries ANY ttyS0 line (operator's own) is left untouched;
#   2. inst_sshd_config_cmd emits a guarded, IDEMPOTENT policy record:
#      PermitRootLogin no (root SSH stays DISABLED by design — the §9.1
#      step 4 ceremony account is the login path) + PasswordAuthentication
#      yes, with the 'alpine-fde headless access' marker the guard greps;
#      double-run appends exactly once;
#   3. the §3.3 additions set carries `openssh` (the package the in-chroot
#      apk transaction installs so the sshd records + `rc-update add sshd
#      default` never die "service does not exist" — real-server failure #2
#      discipline).
# Plan-level placement (records AFTER the apk transaction) is pinned by
# tests/integration/install_dryrun.sh; in-guest execution by
# tests/integration/install_chroot_plan.sh.
set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
# shellcheck source=lib.sh
source "$HERE/lib.sh"

export ALPINE_FDE_CMD_DIR="$REPO/lib/cmd"
# shellcheck source=../../lib/common.sh
source "$REPO/lib/common.sh"
# shellcheck source=../../lib/cmd/install.sh
. "$ALPINE_FDE_CMD_DIR/install.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- 1. inittab getty: the record appends the pinned line + marker -------------
INITTAB=$TMP/inittab
printf '# /etc/inittab\n::sysinit:/sbin/openrc sysinit\ntty1::respawn:/sbin/getty 38400 tty1\n' >"$INITTAB"
GETTY_CMD=$(inst_inittab_getty_cmd "$INITTAB")
assert_contains "getty record greps for an existing ttyS0 line (idempotence guard)" \
    "$GETTY_CMD" "grep -q '^ttyS0:'"
assert_contains "getty record carries the pinned busybox serial getty line" \
    "$GETTY_CMD" "ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100"
assert_contains "getty record carries the alpine-fde marker comment" \
    "$GETTY_CMD" "alpine-fde: serial console getty"
sh -c "$GETTY_CMD"
assert_rc "getty record: rc 0 on a fixture inittab" 0 "$?"
grep -q '^ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100$' "$INITTAB"
assert_rc "getty record: the ttyS0 line landed in the fixture inittab" 0 "$?"
assert_eq "getty record: exactly ONE ttyS0 line after the first run" "1" \
    "$(grep -c '^ttyS0:' "$INITTAB")"

# --- 2. inittab getty: IDEMPOTENT (crash-resume re-run appends nothing) --------
sh -c "$GETTY_CMD"
assert_rc "getty idempotency: re-run rc 0" 0 "$?"
assert_eq "getty idempotency: still exactly ONE ttyS0 line after the re-run" "1" \
    "$(grep -c '^ttyS0:' "$INITTAB")"

# --- 3. inittab getty: an operator's OWN ttyS0 line wins (no append) ----------
INITTAB2=$TMP/inittab-own
printf '::sysinit:/sbin/openrc sysinit\nttyS0::respawn:/sbin/getty -L 9600 ttyS0 vt100\n' >"$INITTAB2"
sh -c "$(inst_inittab_getty_cmd "$INITTAB2")"
assert_rc "getty guard: rc 0 when a ttyS0 line already exists" 0 "$?"
assert_eq "getty guard: the operator's own ttyS0 line is untouched" "1" \
    "$(grep -c '^ttyS0:' "$INITTAB2")"
assert_eq "getty guard: the pinned 115200 line was NOT appended" "0" \
    "$(grep -c '115200' "$INITTAB2")"

# --- 4. sshd config: the record appends PermitRootLogin no + PasswordAuth yes --
SSHD=$TMP/sshd_config
printf '#\t$OpenBSD: sshd_config\n# forbid root login by default\n#PermitRootLogin prohibit-password\nSubsystem sftp internal-sftp\n' >"$SSHD"
SSHD_CMD=$(inst_sshd_config_cmd "$SSHD")
assert_contains "sshd record greps the alpine-fde marker (idempotence guard)" \
    "$SSHD_CMD" "grep -q 'alpine-fde: headless access'"
assert_contains "sshd record pins PermitRootLogin no" "$SSHD_CMD" "'PermitRootLogin no'"
assert_contains "sshd record pins PasswordAuthentication yes" "$SSHD_CMD" "'PasswordAuthentication yes'"
sh -c "$SSHD_CMD"
assert_rc "sshd record: rc 0 on a fixture sshd_config" 0 "$?"
grep -q '^PermitRootLogin no$' "$SSHD"
assert_rc "sshd record: 'PermitRootLogin no' landed" 0 "$?"
grep -q '^PasswordAuthentication yes$' "$SSHD"
assert_rc "sshd record: 'PasswordAuthentication yes' landed" 0 "$?"
assert_eq "sshd record: the marker comment landed exactly once" "1" \
    "$(grep -c 'alpine-fde: headless access' "$SSHD")"

# --- 5. sshd config: IDEMPOTENT -----------------------------------------------
sh -c "$SSHD_CMD"
assert_rc "sshd idempotency: re-run rc 0" 0 "$?"
assert_eq "sshd idempotency: still exactly ONE 'PermitRootLogin no' after the re-run" "1" \
    "$(grep -c '^PermitRootLogin no$' "$SSHD")"
assert_eq "sshd idempotency: still exactly ONE marker block" "1" \
    "$(grep -c 'alpine-fde: headless access' "$SSHD")"

# --- 6. the §3.3 additions set ships openssh -----------------------------------
PKG_LIST=$(install_package_list)
case " $PKG_LIST " in
    *" openssh "*) assert_eq "package list contains openssh (headless access)" "1" "1" ;;
    *) assert_eq "package list contains openssh (headless access)" "1" "0" ;;
esac

finish
