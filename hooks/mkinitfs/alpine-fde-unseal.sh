#!/bin/sh
# alpine-fde-unseal.sh — mkinitfs Early-Boot Unseal Hook (docs/Architecture.md
# §8.2 + §9.1 Stage 2; ADR-13/ADR-20, gap G-C8). ONE POSIX-sh script, shipped
# into the initramfs via hooks/mkinitfs/features.d/alpine-fde.files.
#
# Boot-time flow (§8.2 steps 1-5; ADR-20 amended):
#   0. PRE-UNSEAL SECURE BOOT GUARD — the FIRST action (ADR-20 amendments
#      #3+#4): read SecureBoot/SetupMode from efivarfs (initrd-safe form of
#      lib/firmware.sh fw_sb_state). Secure Boot OFF (`secureboot != 1 ||
#      setup_mode != 0`, or unreadable — fail closed) is a HARD refusal:
#      blocking notice + "Press Enter to reboot" + OsIndications
#      boot-to-firmware-setup (best-effort) + `reboot -f`. The container is
#      NEVER unsealed with Secure Boot off — NO token path, NO recovery
#      passphrase fallback. The provisional PCR-11-only token is only ever
#      usable with Secure Boot on (the OpenRC finalize guard is the SECOND
#      blocking layer, §9.1 Stage 2).
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
#      recovery-passphrase prompt — each refusal class first prints its
#      warn-before-prompt REASON preamble + the audit/reseal remediation line
#      (§8.2 step 5; the SAME sentences docs/UserGuide.md §5 quotes), the
#      prompt carries the "(attempt N of 3)" counter, and 3 strikes total
#      (shared across RAID1 members) end in `poweroff -f`. This hook NEVER
#      spawns an interactive shell; no interactive fallback of any kind exists
#      here by construction.
#   5. (RETIRED with install-state.json — item 10b) There is NO post-unlock
#      marker write: the lifecycle is GROUND TRUTH (lib/trust-state.sh
#      derives provisional vs finalized from the token pcrs + keyslot
#      inventory + baseline expected_pcr7); the hook persists nothing.
#
# Test seams (the real boot path uses the defaults): FDE_CRYPTTAB,
# FDE_EXTRA_DIR, FDE_TMPDIR, FDE_DISK_BY_UUID_DIR, FDE_ATTACH_WAIT_SECS,
# FDE_NLPLUG_FINDFS, FDE_DEV_DIR, FDE_PROC_CONSOLES. (FDE_NEWROOT retired
# with the state flip, item 10b.)
#   DUAL-CONSOLE FAN-OUT (REAL-SERVER R640, 2026-09-29): the target cmdline
#   ends with console=ttyS0,115200 and LAST-CONSOLE-WINS makes /dev/console
#   SERIAL-ONLY — kernel printk fans out to every console= device, but the
#   hook's userspace writes (stderr) reached the serial port ALONE: on the
#   R640 the operator's SCREEN froze at the kernel disk-attach line while the
#   hook sat invisible at the recovery prompt. Every user-visible emission
#   (_msg, _err, _fdh_warn, the prompt text + attempt counter) therefore fans
#   out via _fdh_console_emit: /dev/console (stderr, ALWAYS — the read side;
#   the PASSPHRASE READ itself stays on /dev/console, only the text fans out)
#   PLUS the video console (/dev/tty0, falling back to /dev/tty1) and
#   /dev/ttyS0, each probed present+openable ONCE at hook start (FDE_DEV_DIR
#   is the device dir, default /dev) — a device that is absent or unwritable
#   is dropped from the fan-out and can never fail a message or the hook.
#   /dev/ttyS0 joins the fan-out only when the kernel's preferred console
#   (/dev/console, CON_CONSDEV in FDE_PROC_CONSOLES, default /proc/consoles)
#   is NOT already ttyS0 — the stderr write already reaches that UART, and an
#   explicit second write would double every production serial line.
#   FDE_SERIAL_ECHO (default 0; the e2e initrd splice turns it ON — decision
#   queue item 24a): every console line is emitted TWICE — the live line, then
#   an "[serial-echo]" copy a breath later — so one lost/corrupted 16550 burst
#   under parallel (-j) load no longer false-fails an assertion that reads a
#   single-emission marker (live evidence: "one lost serial marker" on s00; a
#   doubled-byte "B2-42-OPEEN" in run 1789845714; "CANARY-SHAA" in
#   1790321112). The pinned TEXT is still required verbatim from at least one
#   emission — nothing is weakened. The recovery-passphrase PROMPT is echoed
#   in a COMPACT texture (counter + target only; sentinel
#   unseal_prompt_echo_re) instead of repeating the pinned prompt sentence, so
#   the sentence stays countable-exact for the bounded-loop pins ("exactly N
#   prompt events") while each prompt EVENT is corroborated from either
#   emission (candidate-set unique attempt counting in the scenarios). OFF in
#   production: an operator's console is not a capture pipe; single emission
#   is the shipped UX. COMPOSITION with the fan-out (no triple serial): while
#   the seam is ON the explicit /dev/ttyS0 fan-out member is SUPPRESSED — the
#   echo copy already owns serial duplication (live + echo, both via
#   /dev/console = 2 per sentence, exactly what the e2e counts pin), while the
#   video console still receives every live line.
#
# Busybox mkinitfs environment only: no bashisms, no GNU tools beyond busybox
# (sha256sum/od/dd/sed/awk/tr/mktemp/date), openssl + cryptsetup + tpm2-tools
# binaries per the features.d file list.

set -u

FDE_CRYPTTAB=${FDE_CRYPTTAB:-/etc/crypttab}
FDE_EXTRA_DIR=${FDE_EXTRA_DIR:-/.extra}
FDE_TMPDIR=${FDE_TMPDIR:-/tmp}
FDE_MAX_ATTEMPTS=3
FDE_PCR_PHASE=enter-initrd
# REAL-SERVER RACE (Dell PowerEdge R640, first verified boot 2026-09-28): the
# token scan resolved crypttab members via /dev/disk/by-uuid/ and gave up the
# moment one member was not yet visible — the LAST kernel line before the
# token_missing verdict was a disk still attaching ("sd 14:2:5:0: [sdb]
# Attached SCSI disk"), i.e. the seal/token was intact and the verdict was a
# FALSE token_missing. FDE_DISK_BY_UUID_DIR is the directory the UUID= fields
# resolve against (the SAME paths the token lookup opens); FDE_ATTACH_WAIT_SECS
# bounds the wait for every member to appear before the token_missing verdict
# is taken (§8.2 step 2). A timeout after the bound is a GENUINE token_missing;
# the race path itself never prints the warn-before-prompt preamble.
FDE_DISK_BY_UUID_DIR=${FDE_DISK_BY_UUID_DIR:-/dev/disk/by-uuid}
FDE_ATTACH_WAIT_SECS=${FDE_ATTACH_WAIT_SECS:-30}
# The UUID=* resolver's device-attachment source: nlplug-findfs (the uevent
# waiter the initramfs's own /init uses — this image runs nlplug + mdev, NO
# udevd, so /dev/disk/by-uuid entries are never created and by-uuid can only
# ever be the fallback for udev-equipped images). When the binary is absent
# the resolver goes straight to the by-uuid path.
FDE_NLPLUG_FINDFS=${FDE_NLPLUG_FINDFS:-nlplug-findfs}
# Item 24a corroboration seam (see the header comment): 0 = single emission
# (production default), 1 = dual emission (live line + "[serial-echo]" copy).
FDE_SERIAL_ECHO=${FDE_SERIAL_ECHO:-0}
# Dual-console fan-out seams (see the header comment; the real boot path uses
# the defaults /dev and /proc/consoles).
FDE_DEV_DIR=${FDE_DEV_DIR:-/dev}
FDE_PROC_CONSOLES=${FDE_PROC_CONSOLES:-/proc/consoles}

# Console device resolution — O(1), ONCE at hook start (never per message):
#   _fdh_console_video  the video console to ALSO write ('' when none)
#   _fdh_console_serial the serial device to ALSO write ('' when redundant)
# Each candidate must EXIST and be OPENABLE (`: >dev` in a subshell — a
# redirection failure on a special builtin could abort the hook, so the probe
# is isolated) or it is dropped from the fan-out: a missing device never
# fails a message and never fails the hook.
_fdh_console_video=''
for _fdh_c in "$FDE_DEV_DIR/tty0" "$FDE_DEV_DIR/tty1"; do
    if [ -e "$_fdh_c" ] && ( : >"$_fdh_c" ) 2>/dev/null; then
        _fdh_console_video=$_fdh_c
        break
    fi
done
# /dev/ttyS0 joins the fan-out ONLY when (a) the e2e echo seam is OFF — under
# FDE_SERIAL_ECHO=1 the "[serial-echo]" copy already duplicates every line on
# the console path and an explicit UART write would TRIPLE the serial traffic
# the e2e counts pin at live+echo — and (b) the kernel's preferred console
# (CON_CONSDEV, the 'C' flag in /proc/consoles) is NOT already ttyS0 — then
# /dev/console (stderr) already reaches the UART and a second write would
# double every production serial line ("single emission is the shipped UX").
# An unreadable /proc/consoles falls safe to INCLUDE (a redundant line beats
# a swallowed one; /dev/tty0-then-tty1 above still carries the video).
_fdh_console_serial=''
if [ "$FDE_SERIAL_ECHO" != 1 ] && [ -e "$FDE_DEV_DIR/ttyS0" ] &&
    ( : >"$FDE_DEV_DIR/ttyS0" ) 2>/dev/null; then
    if ! grep -q '^ttyS0 .*(.*C' "$FDE_PROC_CONSOLES" 2>/dev/null; then
        _fdh_console_serial=$FDE_DEV_DIR/ttyS0
    fi
fi

# _fdh_console_emit FMT [ARG] — ONE user-visible emission to EVERY console:
# /dev/console (stderr) always, plus the video and serial devices resolved
# above (APPEND opens — a tty ignores O_APPEND, a regular-file test stub
# accumulates). Per-device write failures are guarded (`|| :`); the
# resolution-time probes make them the rare case. FMT is an internal literal.
_fdh_console_emit() {
    printf "$1" "${2-}" >&2
    if [ -n "$_fdh_console_video" ]; then
        printf "$1" "${2-}" >>"$_fdh_console_video" 2>/dev/null || :
    fi
    if [ -n "$_fdh_console_serial" ]; then
        printf "$1" "${2-}" >>"$_fdh_console_serial" 2>/dev/null || :
    fi
    return 0
}

# Warn-before-prompt REASON preambles (user decision queue item 8, §8.2 step
# 5): ONE canonical sentence per refusal class, printed verbatim by the branch
# that detects that class, immediately BEFORE the bounded keyslot-0 recovery
# passphrase fallback. docs/UserGuide.md §5 ("The Console Experience When
# Something Is Wrong") and docs/Architecture.md §8.2 step 5 quote the SAME
# sentences — the hook↔docs wording identity is pinned by
# tests/unit/unseal_warn_preamble.sh and the unseal_warn_* sentinels
# (tests/sentinels-260.2.txt). The closing line names the audit/reseal CLI
# verbs (the decided rename — new names even while the rename lane is in
# flight).
FDE_WARN_SEAL_REFUSED='the expected firmware/Secure Boot configuration changed — if this was you (firmware update, SB toggle), this is expected'
FDE_WARN_SIG_REFUSED='the booted kernel image failed signature/PCR policy — likely a foreign or unsigned UKI'
FDE_WARN_TOKEN_MISSING='the TPM seal is absent — the TPM may have been cleared'
FDE_WARN_CLOSING='after boot, run: audit, then reseal to restore passwordless unlock'

# _msg LINE — the console emission, fanned out to BOTH consoles via
# _fdh_console_emit (/dev/console + video + serial per the resolution above).
# With FDE_SERIAL_ECHO=1 (item 24a) the line is immediately re-emitted as an
# "[serial-echo]" copy: a SECOND, independent burst a breath after the first,
# so one lost/corrupted burst under parallel load leaves the other intact.
# The echo copy stays on the console stream only (stderr): the seam OWNS
# serial duplication, the fan-out owns device coverage — together they never
# triple-emit on serial. Both copies carry the pinned sentence VERBATIM —
# asserts that require the text are corroborated, never weakened.
_msg() {
    _fdh_console_emit 'alpine-fde-unseal: %s\n' "$1"
    [ "$FDE_SERIAL_ECHO" = 1 ] || return 0
    printf 'alpine-fde-unseal: [serial-echo] %s\n' "$1" >&2
}
_err() { _msg "error: $1"; }

# _fdh_warn REASON — the warn-before-prompt preamble: the refusal class's
# reason sentence, then the remediation closing line, both BEFORE the
# recovery-passphrase prompt (§8.2 step 5). ANTI-FOOTGUN, NOT ANTI-TAMPER:
# the sentence is the hook's own classification of a refusal it genuinely
# detected — guidance for the legitimate operator, not a trusted statement
# (an attacker who controls the boot chain controls the console too).
_fdh_warn() {
    _msg "$1"
    _msg "$FDE_WARN_CLOSING"
}

# _fdh_poweroff REASON — the terminal fail-closed action (§8.2): loud reason,
# forced poweroff, nonzero exit. The ONLY interactive-adjacent state this hook
# can end in.
_fdh_poweroff() {
    _err "$1"
    _msg "fail-closed: forcing poweroff (no shell is offered, §8.2)"
    poweroff -f
    exit 1
}

# _fdh_state_flip — RETIRED with install-state.json (item 10b). The hook used
# to flip a persisted `installed` -> `provisional-booted` marker on the
# mounted NEWROOT after a successful unlock; nothing reads such a document
# any more (the trust state is derived from the LUKS2 metadata, lib/
# trust-state.sh), and a boot-time hook persisting lifecycle state was the
# one write path this design removes. The hook now persists NOTHING, ever —
# it is a pure unlock path.
#
# blocker #23: the stock-init splice's post-mount STATE-ONLY mode
# (FDE_STATE_ONLY=1) is RETIRED with the marker flip (item 10b) — no post-mount
# work left, so the splice carries exactly ONE hook invocation (pre-mount,
# splice A).


# --- §8.2 step 0: PRE-UNSEAL SECURE BOOT GUARD (ADR-20 amended, FIRST) --------
# efivarfs read in the initrd-safe form of lib/firmware.sh fw_sb_state: the
# canonical EFI_GLOBAL_VARIABLE namespace only (a same-named variable in any
# other namespace is NOT the firmware's SB state, S-M5), 4-byte u32 attrs
# header + payload byte 0. Fail CLOSED: unreadable == not a verified boot.
FDE_EFIVARS_DIR=${FDE_EFIVARS_DIR:-/sys/firmware/efi/efivars}
FW_GUID_GLOBAL='8be4df61-93ca-11d2-aa0d-00e098032b8c'

# _fdh_efivar_u8 NAME — print the variable's payload byte 0 as od hex, rc 1
# when absent/unreadable (the caller maps that to "unreadable" and blocks).
# shellcheck disable=SC2120  # stdin consumer by design
_fdh_efivar_u8() {
    _fde_f="$FDE_EFIVARS_DIR/$1-$FW_GUID_GLOBAL"
    [ -f "$_fde_f" ] || return 1
    _fde_h=$(dd if="$_fde_f" bs=1 skip=4 count=1 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
    [ -n "$_fde_h" ] || return 1
    printf '%s\n' "$_fde_h"
}

# best-effort efivarfs mount (the real initrd usually mounts it in /init;
# a bare environment may not have it yet — never fatal, the read decides)
if [ ! -d "$FDE_EFIVARS_DIR" ]; then
    mkdir -p "$FDE_EFIVARS_DIR" 2>/dev/null || :
    mount -t efivarfs efivarfs "$FDE_EFIVARS_DIR" >/dev/null 2>&1 || :
fi

# operator debug gate: `fde_hook_debug` on the kernel cmdline turns on sh -x
# tracing for the whole main flow (console-visible; normal boots stay quiet)
case " $(cat /proc/cmdline 2>/dev/null) " in
    *" fde_hook_debug"*) set -x ;;
esac

_fdh_sb=$(_fdh_efivar_u8 SecureBoot) || _fdh_sb=''
_fdh_sm=$(_fdh_efivar_u8 SetupMode) || _fdh_sm=''
case $_fdh_sb in
    01) _fdh_sb=1 ;;
    00) _fdh_sb=0 ;;
    *) _fdh_sb=unreadable ;;
esac
case $_fdh_sm in
    00) _fdh_sm=0 ;;
    01) _fdh_sm=1 ;;
    *) _fdh_sm=unreadable ;;
esac

if [ "$_fdh_sb" != "1" ] || [ "$_fdh_sm" != "0" ]; then
    # ADR-20 amendments #3+#4: the container is NEVER unsealed with Secure
    # Boot off — no token path, no passphrase fallback. Block, ask for the
    # operator's confirmation, request the next boot into the firmware setup
    # (OsIndications bit 1, EFI_OS_INDICATIONS_BOOT_TO_FW_UI, best-effort
    # because some firmware refuses plain SetVariable), and reboot.
    _msg "Secure Boot guard: secureboot=$_fdh_sb setup_mode=$_fdh_sm — Secure Boot is OFF — refusing to unlock (pre-unseal guard, ADR-20)"
    _msg "the container will NOT be unlocked: no token path, no recovery passphrase — enable Secure Boot with this machine's platform keys in the firmware setup (UEFI)"
    _fdh_osind="$FDE_EFIVARS_DIR/OsIndications-$FW_GUID_GLOBAL"
    rm -f "$_fdh_osind" 2>/dev/null || :
    if printf '\007\000\000\000\002\000\000\000\000\000\000\000' >"$_fdh_osind" 2>/dev/null; then
        # OsIndications accepted — spec-compliant firmware: Enter-prompt +
        # reboot-into-setup works (the operator can reach the firmware UI)
        _msg "OsIndications: boot-to-firmware-setup requested"
        _msg "Press Enter to reboot into the firmware setup (the container was NOT unlocked; no passphrase was requested)"
        IFS= read -r _fdh_enter || _fdh_enter=''
        _msg "rebooting into the firmware setup (Secure Boot must be enabled)"
        if reboot -f; then
            # not reached on real firmware: the machine resets under the hook
            exit 0
        fi
        # a refused reboot must never fall through into an unauthenticated boot
        _fdh_poweroff "reboot refused — fail-closed poweroff (Secure Boot is OFF; §8.2)"
    else
        # REAL-SERVER blocker (Samuel's Dell): OsIndications is NOT supported
        # (some firmwares lack the capability entirely — SetupMode=1 but the
        # OsIndications SetVariable is refused or silently ignored). Print the
        # FULL manual instructions, then STILL reboot: the reboot is useful
        # (the operator catches F2 during the next POST to enter the firmware
        # setup manually) while a bare poweroff strands the machine.
        _msg "OsIndications not supported by this firmware — at the next boot, press F2 during POST to enter the firmware setup and:"
        _msg "  1. import the keys from the ESP partition (alpine-fde-keys: db.auth, kek.auth, pk.auth — in that order, or the .cer certificates) or verify they are present"
        _msg "  2. enable Secure Boot"
        _msg "  3. save and exit"
        _msg "Press Enter to reboot (press F2 during POST to enter the firmware setup)"
        IFS= read -r _fdh_enter || _fdh_enter=''
        _msg "rebooting — press F2 during POST to enter the firmware setup"
        if reboot -f; then
            exit 0
        fi
        _fdh_poweroff "reboot refused — fail-closed poweroff (Secure Boot is OFF; §8.2)"
    fi
fi
_msg "Secure Boot guard: secureboot=1 setup_mode=0 — verified boot confirmed (pre-unseal guard, ADR-20)"

# --- bcache self-registration (R640 2026-09-29) ---------------------------------
# The initramfs may have NO udevd (stock mdev hotplug never runs
# 69-bcache.rules), so the bcache backing set would never assemble and every
# member resolve below starves. Register every visible disk/partition
# directly: non-bcache devices just fail the sysfs write harmlessly; the
# kernel then emits the bcacheN uevents nlplug-findfs resolves members by
# (no udevd required — it rides the kernel netlink socket).
if modprobe bcache 2>/dev/null; then
    _fdh_bcreg=0
    for _fdh_bc in /dev/sd[a-z] /dev/sd[a-z][0-9] /dev/nvme[0-9]n[0-9] \
        /dev/nvme[0-9]n[0-9]p[0-9] /dev/vd[a-z] /dev/vd[a-z][0-9]; do
        [ -e "$_fdh_bc" ] || continue
        echo "$_fdh_bc" > /sys/fs/bcache/register 2>/dev/null && _fdh_bcreg=$((_fdh_bcreg + 1))
    done
    [ "$_fdh_bcreg" -gt 0 ] && _msg "bcache: registered $_fdh_bcreg device(s) from the initramfs (mdev hotplug lane)"
    unset _fdh_bc _fdh_bcreg
fi


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
            # R640 2026-09-29: nlplug-findfs can exit 0 with NO output in the
        # packed initramfs (empty device -> cryptsetup fails instantly, every
        # attempt burns). Resolve bcache members DIRECTLY instead: cryptsetup
        # is guaranteed in the initramfs and luksUUID only reads the header.
        for _fdh_bcd in /dev/bcache[0-9]*; do
            [ -e "$_fdh_bcd" ] || continue
            if [ "$(cryptsetup luksUUID "$_fdh_bcd" 2>/dev/null)" = "${1#UUID=}" ]; then
                printf '%s\n' "$_fdh_bcd"
                return 0
            fi
        done
        if command -v "$FDE_NLPLUG_FINDFS" >/dev/null 2>&1; then
                # REAL-SERVER R640 (verified boot 2026-09-28): this initramfs's
                # /init runs nlplug-findfs + mdev — NO udevd — so NOTHING ever
                # creates /dev/disk/by-uuid entries; a bare by-uuid print
                # starves the whole FDE_ATTACH_WAIT_SECS bound on a path mdev
                # never makes (30s wait, then token_missing on an INTACT seal).
                # nlplug-findfs is the same resolver init uses: it waits for
                # the uevent matching the spec (-t: ms of uevent silence) and
                # prints the /dev node. by-uuid stays the fallback for
                # udev-equipped images, keeping FDE_DISK_BY_UUID_DIR meaningful.
                # REAL-SERVER R640 (verified boot 2026-09-29): -t only bounds
                # UEVENT SILENCE — every straggler uevent (PERC/NIC attach
                # tail) resets it, so the resolver blocked ~5.5 min on a
                # member that could never appear (no udevd -> bcache never
                # assembled) and starved FDE_ATTACH_WAIT_SECS from the
                # outside. busybox timeout gives the call a HARD ceiling so
                # the §8.2 bound stays the bound.
                _fdh_nf=$(timeout 10 "$FDE_NLPLUG_FINDFS" -t 5000 "$1" 2>/dev/null) && {
                    printf '%s\n' "$_fdh_nf"
                    return 0
                }
            fi
            printf '%s/%s\n' "$FDE_DISK_BY_UUID_DIR" "${1#UUID=}"
            ;;
        /dev/*) printf '%s\n' "$1" ;;
        *) return 1 ;;
    esac
}

# _fdh_prompt_pass TARGET ATTEMPT — read the keyslot-0 recovery passphrase from
# the console (echo off when the console tty allows it; best-effort). The
# prompt carries the bounded-loop counter "(attempt N of 3)" (§8.2 step 5,
# status-spec decision 10b): N is 1-based and counted across ALL members
# (3 strikes TOTAL). The counter PREFIXES the pinned prompt shape (sentinel
# unseal_prompt_re still matches the "enter the recovery passphrase …(keyslot
# 0):" suffix). The PROMPT TEXT (sentence + counter + the after-read newline)
# renders on BOTH consoles via _fdh_console_emit (R640: the prompt must be
# VISIBLE on the screen, not only on serial); the READ itself stays on
# /dev/console (stdin — the input device is never split).
_fdh_prompt_pass() {
    # Item 24a: the prompt's LIVE emission is byte-identical to the pinned
    # shape (sentinel unseal_prompt_re) and stays SINGLE — the bounded-loop
    # pins count prompt events via this exact sentence ("exactly N prompts").
    # Its ECHO copy is the COMPACT texture (counter + target, sentinel
    # unseal_prompt_echo_re): a second independent burst corroborating the
    # prompt EVENT (a lost live prompt line no longer starves a feed that is
    # prompt-synchronized) WITHOUT duplicating the countable sentence.
    _fdh_console_emit 'alpine-fde-unseal: %s\n' \
        "(attempt $2 of $FDE_MAX_ATTEMPTS) enter the recovery passphrase for $1 (keyslot 0): "
    if [ "$FDE_SERIAL_ECHO" = 1 ]; then
        printf 'alpine-fde-unseal: [serial-echo] (attempt %s of %s) recovery-passphrase prompt opened for %s (keyslot 0)\n' \
            "$2" "$FDE_MAX_ATTEMPTS" "$1" >&2
    fi
    _fdh_echo_off=0
    if [ -t 0 ] && command -v stty >/dev/null 2>&1; then
        stty -echo 2>/dev/null && _fdh_echo_off=1
    fi
    # R640 2026-09-29: fd 0 in the spliced-init context is NOT the console —
    # read returned EOF instantly and burned all attempts in ~1s. Read the
    # passphrase from /dev/console explicitly (the one channel both the video
    # and serial lanes land on, and where the prompt itself went).
    IFS= read -r _fdh_pass < /dev/console || _fdh_pass=''
    if [ "$_fdh_echo_off" = 1 ]; then
        stty echo 2>/dev/null || :
        _fdh_console_emit '\n'
    fi
    printf '%s' "$_fdh_pass"
}

# _fdh_scan_token — walk the crypttab members and export the FIRST
# systemd-tpm2 token found (full LUKS2 token-id range 0..31). Sets:
#   _fdh_tok          the raw token JSON ('' when none found)
#   _fdh_exp_err      first export-refusal line (console diagnosability)
#   _fdh_attach_missing  1 when ANY resolved member device path did not exist
#                     at probe time — the device-attach race signal (R640)
# re-scan-safe: callable twice (the bounded attach wait re-invokes it).
_fdh_scan_token() {
    _fdh_tok=''
    _fdh_exp_err=''
    _fdh_attach_missing=0
    _fdh_pos=0
    for _fdh_wd in $_fdh_members; do
        _fdh_pos=$((_fdh_pos + 1))
        if [ $((_fdh_pos % 2)) -eq 1 ]; then
            _fdh_target=$_fdh_wd
            continue
        fi
        _fdh_dev=$(_fdh_resolve_dev "$_fdh_wd") || continue
        if [ ! -e "$_fdh_dev" ]; then
            # member not attached (yet): remember the race signal — the
            # export below still runs so the refusal stays VISIBLE
            _fdh_attach_missing=1
        fi
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
    return 0
}

# _fdh_wait_members — bounded wait for EVERY crypttab member device to appear
# (the R640 device-attach race, §8.2 step 2). Probes the SAME by-uuid paths
# the token lookup opens, plain POSIX loop, `sleep 1` between probes (no
# busy-spin), total bound FDE_ATTACH_WAIT_SECS. Returns 0 the moment all
# members exist (caller re-runs the token scan — the normal flow continues);
# returns 1 only after the bound expires — from THERE a token_missing verdict
# is genuine, and ONLY that timeout path may take it (the race path itself
# never prints the warn-before-prompt preamble).
_fdh_wait_members() {
    _fdh_left=$FDE_ATTACH_WAIT_SECS
    while [ "$_fdh_left" -gt 0 ]; do
        _fdh_all=1
        _fdh_pos=0
        for _fdh_wd in $_fdh_members; do
            _fdh_pos=$((_fdh_pos + 1))
            [ $((_fdh_pos % 2)) -eq 1 ] && continue # odd word = target
            _fdh_dev=$(_fdh_resolve_dev "$_fdh_wd") || continue
            [ -e "$_fdh_dev" ] || _fdh_all=0
        done
        [ "$_fdh_all" = 1 ] && return 0
        _fdh_left=$((_fdh_left - 1))
        [ "$_fdh_left" -gt 0 ] && sleep 1
    done
    return 1
}

# --- §8.2 step 1: extend the ukify phase string into PCR 11 ---------------------
_fdh_tpm_ok=1
_fdh_phase_dgst=$(printf '%s' "$FDE_PCR_PHASE" | sha256sum | awk '{print $1}')
tpm2_pcrextend "11:sha256=$_fdh_phase_dgst" >/dev/null 2>&1 || _fdh_tpm_ok=0
if [ "$_fdh_tpm_ok" = 1 ]; then
    _msg "extended '$FDE_PCR_PHASE' into PCR 11 (ukify --measure phase alignment)"
else
    _msg "TPM absent or refused the PCR 11 extend — recovery passphrase path (§8.2)"
    # token_missing class: no TPM path exists at all (§8.2 step 5)
    _fdh_warn "$FDE_WARN_TOKEN_MISSING"
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
    _fdh_scan_token
    if [ -z "$_fdh_tok" ] && [ "$_fdh_attach_missing" = 1 ]; then
        # R640 device-attach race: a member device was not visible during the
        # scan — WAIT (bounded) for the crypttab members before ANY verdict.
        # A member that appears here continues the NORMAL flow (re-scan); the
        # warn-before-prompt preamble is NOT printed on this path — only an
        # exhausted bound below reaches the genuine token_missing verdict.
        _msg "crypttab member device(s) not attached yet — waiting up to ${FDE_ATTACH_WAIT_SECS}s for /dev/disk/by-uuid to settle (device-attach race)"
        if _fdh_wait_members; then
            _msg "crypttab member(s) attached — retrying the token scan"
            _fdh_scan_token
        fi
    fi

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
            # sig_refused class: the entry signature/PCR policy gate refused
            # BEFORE any TPM session (I3) — a foreign or unsigned UKI
            _fdh_warn "$FDE_WARN_SIG_REFUSED"
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
                # seal_refused class: the live PCR state no longer matches the
                # sealed policy (PCR 7 firmware/SB drift — the expected,
                # anti-footgun case after a firmware update or SB toggle)
                _fdh_warn "$FDE_WARN_SEAL_REFUSED"
            fi
        fi
    else
        _msg "no systemd-tpm2 token found on any crypttab member — recovery passphrase path (§8.2)${_fdh_exp_err:+ [last export refusal: $_fdh_exp_err]}"
        # token_missing class: the seal is gone from the containers (§8.2 step 2)
        _fdh_warn "$FDE_WARN_TOKEN_MISSING"
    fi
fi

# --- open every member with the unsealed secret (§8.2 step 3; RAID1: the
# unsealed passphrase is reused across all members without re-prompting) -------
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
                _fdh_done=1
                _msg "unlocked $_fdh_target ($_fdh_dev) via the recovery passphrase"
                continue
            fi
            _fdh_cached=''
        fi
        if [ "$_fdh_tries" -ge "$FDE_MAX_ATTEMPTS" ]; then
            _fdh_poweroff "$FDE_MAX_ATTEMPTS failed recovery passphrase attempts — giving up (§8.2 fail-closed)"
        fi
        _fdh_cached=$(_fdh_prompt_pass "$_fdh_target" "$((_fdh_tries + 1))")
        _fdh_tries=$((_fdh_tries + 1))
    done
done

# (item 10b) NO post-unlock marker write: the unlock itself is the only fact
# this hook produces; the trust state stays derivable from the container.

exit 0
