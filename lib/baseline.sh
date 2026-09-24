#!/bin/sh
# baseline.sh — baseline.json v1 schema + shared helpers for the Alpine FDE
# ceremony/lifecycle commands (bucket C: provision/install/enroll/rotate/
# audit/status/bootnext/doctor).
#
# baseline.json v1 (docs/Architecture.md §8.4, gap C-G5) — emitted layout is
# fixed (2-space top level, 4-space nested, every value a JSON string):
#   {
#     "schema_version": "1",
#     "created_at": "<ISO8601 UTC>",
#     "pcr0": "<64-hex|pending>", ... "pcr3": ...,
#     "expected_pcr7": "<64-hex|pending>",
#     "sb_state": { "secure_boot","setup_mode","pk_fp","kek_fp","db_fp","dbx_fp" },
#     "fw":       { "vendor","version","eventlog_sha256","eventlog_size" },
#     "keys":     { "release_pub_path","release_cert_path" },   (paths, not material — I4)
#     "target":   { "luks_uuid","esp_partuuid" }
#   }
# "pending" pcr fields are finalized by `audit --init` / `provision stage2`
# (PCR 7 only updates on the next boot after firmware key enrollment — §9.1).
#
# Library only: sourcing has no side effects.

if [ -n "${ALPINE_FDE_BASELINE_LOADED:-}" ]; then
    return 0
fi
ALPINE_FDE_BASELINE_LOADED=1

# Pull in common.sh (exit codes, logging, tpm()) and firmware.sh (efivarfs
# seam) if they are reachable next to us and not loaded yet. When this file
# lives at <tree>/lib/baseline.sh, the cmd dir is <tree>/lib/cmd.
_bl_cmd_dir=${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}
_bl_lib_dir=${_bl_cmd_dir%/*}
if [ -z "${ALPINE_FDE_COMMON_LOADED:-}" ] && [ -r "$_bl_lib_dir/common.sh" ]; then
    # shellcheck disable=SC1090  # resolved from ALPINE_FDE_CMD_DIR / install tree
    . "$_bl_lib_dir/common.sh"
fi
if [ -z "${ALPINE_FDE_FIRMWARE_LOADED:-}" ] && [ -r "$_bl_lib_dir/firmware.sh" ]; then
    # shellcheck disable=SC1090
    . "$_bl_lib_dir/firmware.sh"
fi
if [ -z "${ALPINE_FDE_ESP_LOADED:-}" ] && [ -r "$_bl_lib_dir/esp.sh" ]; then
    # shellcheck disable=SC1090
    . "$_bl_lib_dir/esp.sh"
fi

# --- path helpers (all overridable for tests via ALPINE_FDE_ROOT etc.) ---------
sp_cmd_dir() {
    printf '%s\n' "${ALPINE_FDE_CMD_DIR:-/usr/share/alpine-fde/lib/cmd}"
}

# sp_etc_dir — <root>/etc/alpine-fde (root empty → absolute /etc/alpine-fde;
# ADR-20 §8.4 clean rename — no legacy fallback)
sp_etc_dir() {
    printf '%s/etc/alpine-fde\n' "${ALPINE_FDE_ROOT:-}"
}

sp_baseline_file() { printf '%s/baseline.json\n' "$(sp_etc_dir)"; }
sp_enrolled_file() { printf '%s/enrolled.json\n' "$(sp_etc_dir)"; }
sp_last_audit_file() { printf '%s/last-audit.json\n' "$(sp_etc_dir)"; }
sp_manifest_file() { printf '%s/digests.json\n' "$(sp_etc_dir)"; }

# --- live capture helpers -----------------------------------------------------
# tpm_pcr_read IDX — print the live sha256 PCR <IDX> digest (bare lowercase hex)
tpm_pcr_read() {
    _pr_out=$(tpm pcrread "sha256:$1") || return 1
    printf '%s\n' "$_pr_out" | awk -v p="$1" '$1 == p && $2 == ":" { sub(/^0x/, "", $3); print tolower($3) }'
}

# tpm_available — rc 0 iff a TPM answers through the configured TCTI
tpm_available() {
    tpm getcap properties-fixed >/dev/null 2>&1
}

# fw_var_sha256 NAME — sha256 of an EFI variable payload (after the 4-byte
# attrs header); rc 1 if the variable is absent, rc 64 on ambiguity (NEW-2:
# fw_find_var's fail-closed die rc is PROPAGATED, not collapsed into rc 1 —
# `|| _fp=''` consumers then degrade with the loud ambiguity diagnostic on
# stderr instead of recording a silently-empty fingerprint)
fw_var_sha256() {
    _fvs_rc=0
    _fvs_file=$(fw_find_var "$(fw_efivars_dir)" "$1") || _fvs_rc=$?
    [ "$_fvs_rc" -eq 0 ] || return "$_fvs_rc"
    tail -c +5 "$_fvs_file" | sha256sum | cut -d' ' -f1
}

# eventlog_path — TCG event log location ($ALPINE_FDE_EVENTLOG overrides)
eventlog_path() {
    printf '%s\n' "${ALPINE_FDE_EVENTLOG:-/sys/kernel/security/tpm0/binary_bios_measurements}"
}

# eventlog_info — print "<sha256> <size>"; rc 1 if the log is absent.
# v1 audit scope: existence + size + sha256 only (no replay — C-G10).
eventlog_info() {
    _el_f=$(eventlog_path)
    [ -f "$_el_f" ] || return 1
    _el_sz=$(wc -c <"$_el_f" | tr -d '[:space:]')
    _el_sha=$(sha256sum <"$_el_f" | cut -d' ' -f1)
    printf '%s %s\n' "$_el_sha" "$_el_sz"
}

# dmi_field NAME — print a DMI id field (vendor/version), "" if unavailable
dmi_field() {
    _dm_d=${ALPINE_FDE_DMI_DIR:-/sys/devices/virtual/dmi/id}
    if [ -r "$_dm_d/$1" ]; then
        tr -d '\n' <"$_dm_d/$1"
    fi
}

# sbverify_boot_binaries [CERT] — §8.3: `status` and `audit` run sbverify over
# the ESP boot-manager binaries (systemd-bootx64.efi + firmware fallback
# loader). Prints one verdict line per binary; sets SBVERIFY_FAILED to the
# number of PRESENT binaries that failed verification. Absent ESP / binaries /
# tooling / cert are reported as skipped, never failed (status is report-only;
# audit drifts only on a binary that exists and does not verify).
sbverify_boot_binaries() {
    _sv_cert=${1:-"${ALPINE_FDE_KEYDIR:-${KEY_PATH:-}}/release.crt"}
    # M-1: on the installed target the signing medium is offline (I4) and
    # `install` writes no alpine-fde.conf — without this fallback the §8.3
    # boot-manager check would be permanently dormant exactly where it matters
    # most. The cert path recorded at provision (§8.4, /etc/alpine-fde/keys/)
    # is read back when the env-based resolution points at nothing.
    if [ ! -f "$_sv_cert" ] && [ -r "$(sp_baseline_file)" ]; then
        _sv_bl_cert=$(baseline_get_in "$(sp_baseline_file)" keys release_cert_path)
        if [ -n "$_sv_bl_cert" ]; then
            _sv_cert=$_sv_bl_cert
        fi
    fi
    # CR-02: the recorded path points at the SIGNING MEDIUM (offline on the
    # booted target — I4), so the read-back above still resolves a dead path
    # there. The §8.4 target copy — where install puts the real cert — is the
    # next tier, keeping the §8.3 check alive on the machine that runs it.
    if [ ! -f "$_sv_cert" ]; then
        _sv_etc_cert=$(sp_etc_dir)/keys/release.crt
        if [ -f "$_sv_etc_cert" ]; then
            _sv_cert=$_sv_etc_cert
        fi
    fi
    SBVERIFY_FAILED=0
    _sv_esp=$(esp_dir)
    if [ ! -d "$_sv_esp" ]; then
        printf 'sbverify: ESP not mounted at %s — skipped\n' "$_sv_esp"
        return 0
    fi
    if ! command -v sbverify >/dev/null 2>&1; then
        printf 'sbverify: not installed (apk add sbsigntool) — skipped\n'
        return 0
    fi
    for _sv_pair in \
        "systemd-bootx64.efi:EFI/systemd/systemd-bootx64.efi" \
        "BOOTX64.EFI (fallback):EFI/BOOT/BOOTX64.EFI"; do
        _sv_name=${_sv_pair%%:*}
        _sv_bin="$_sv_esp/${_sv_pair#*:}"
        if [ ! -f "$_sv_bin" ]; then
            printf 'sbverify %-30s absent on ESP (%s)\n' "$_sv_name" "$_sv_bin"
            continue
        fi
        if [ ! -f "$_sv_cert" ]; then
            printf 'sbverify %-30s skipped (no release cert: %s)\n' "$_sv_name" "$_sv_cert"
            continue
        fi
        if sbverify --cert "$_sv_cert" "$_sv_bin" >/dev/null 2>&1; then
            printf 'sbverify %-30s pass\n' "$_sv_name"
        else
            printf 'sbverify %-30s FAIL (unsigned or wrong key)\n' "$_sv_name"
            SBVERIFY_FAILED=$((SBVERIFY_FAILED + 1))
        fi
    done
    return 0
}

# --- baseline.json v1 writer ---------------------------------------------------
# baseline_write FILE — emit a v1 baseline from the BL_* environment:
#   BL_CREATED_AT, BL_PCR0..3, BL_PCR7 (expected_pcr7),
#   BL_SB_SECURE_BOOT, BL_SB_SETUP_MODE, BL_SB_PK_FP, BL_SB_KEK_FP, BL_SB_DB_FP,
#   BL_SB_DBX_FP, BL_FW_VENDOR, BL_FW_VERSION, BL_FW_EVENTLOG_SHA256,
#   BL_FW_EVENTLOG_SIZE, BL_KEYS_RELEASE_PUB_PATH, BL_KEYS_RELEASE_CERT_PATH,
#   BL_TARGET_LUKS_UUID, BL_TARGET_ESP_PARTUUID
# Missing vars default to "pending"/"" sensibly. Values containing a double
# quote or backslash are rejected (would corrupt the fixed JSON layout).
# lib/sane() helper: values containing a double quote or backslash are rejected
# (would corrupt the fixed JSON layout)
_bl_sane() {
    printf '%s' "$1" | grep -q '["\\]' && return 1
    return 0
}

baseline_write() {
    _bw_f=$1
    for _bw_v in \
        "${BL_CREATED_AT:-}" "${BL_PCR0:-}" "${BL_PCR1:-}" "${BL_PCR2:-}" \
        "${BL_PCR3:-}" "${BL_PCR7:-}" "${BL_SB_SECURE_BOOT:-}" \
        "${BL_SB_SETUP_MODE:-}" "${BL_SB_PK_FP:-}" "${BL_SB_KEK_FP:-}" \
        "${BL_SB_DB_FP:-}" "${BL_SB_DBX_FP:-}" "${BL_FW_VENDOR:-}" \
        "${BL_FW_VERSION:-}" "${BL_FW_EVENTLOG_SHA256:-}" \
        "${BL_FW_EVENTLOG_SIZE:-}" "${BL_KEYS_RELEASE_PUB_PATH:-}" \
        "${BL_KEYS_RELEASE_CERT_PATH:-}" "${BL_TARGET_LUKS_UUID:-}" \
        "${BL_TARGET_ESP_PARTUUID:-}"; do
        _bl_sane "$_bw_v" || die "baseline_write: value would break JSON layout: $_bw_v"
    done
    _bw_dir=${_bw_f%/*}
    [ -n "$_bw_dir" ] && [ "$_bw_dir" != "$_bw_f" ] && mkdir -p "$_bw_dir"
    _bw_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    cat >"$_bw_f" <<EOF
{
  "schema_version": "1",
  "created_at": "${BL_CREATED_AT:-$_bw_now}",
  "pcr0": "${BL_PCR0:-pending}",
  "pcr1": "${BL_PCR1:-pending}",
  "pcr2": "${BL_PCR2:-pending}",
  "pcr3": "${BL_PCR3:-pending}",
  "expected_pcr7": "${BL_PCR7:-pending}",
  "sb_state": {
    "secure_boot": "${BL_SB_SECURE_BOOT:-}",
    "setup_mode": "${BL_SB_SETUP_MODE:-}",
    "pk_fp": "${BL_SB_PK_FP:-}",
    "kek_fp": "${BL_SB_KEK_FP:-}",
    "db_fp": "${BL_SB_DB_FP:-}",
    "dbx_fp": "${BL_SB_DBX_FP:-}"
  },
  "fw": {
    "vendor": "${BL_FW_VENDOR:-}",
    "version": "${BL_FW_VERSION:-}",
    "eventlog_sha256": "${BL_FW_EVENTLOG_SHA256:-}",
    "eventlog_size": "${BL_FW_EVENTLOG_SIZE:-}"
  },
  "keys": {
    "release_pub_path": "${BL_KEYS_RELEASE_PUB_PATH:-}",
    "release_cert_path": "${BL_KEYS_RELEASE_CERT_PATH:-}"
  },
  "target": {
    "luks_uuid": "${BL_TARGET_LUKS_UUID:-}",
    "esp_partuuid": "${BL_TARGET_ESP_PARTUUID:-}"
  }
}
EOF
    # I-2: pin the trust-root record's mode explicitly — 0600 regardless of the
    # caller's ambient umask (direct sourcing, tests, future callers), matching
    # aud_write_last_audit/enrl_record.
    chmod 600 "$_bw_f"
}

# baseline_load_env FILE — read a baseline back into the BL_* environment
baseline_load_env() {
    _ble_f=$1
    BL_CREATED_AT=$(baseline_get "$_ble_f" created_at)
    BL_PCR0=$(baseline_get "$_ble_f" pcr0)
    BL_PCR1=$(baseline_get "$_ble_f" pcr1)
    BL_PCR2=$(baseline_get "$_ble_f" pcr2)
    BL_PCR3=$(baseline_get "$_ble_f" pcr3)
    BL_PCR7=$(baseline_get "$_ble_f" expected_pcr7)
    BL_SB_SECURE_BOOT=$(baseline_get_in "$_ble_f" sb_state secure_boot)
    BL_SB_SETUP_MODE=$(baseline_get_in "$_ble_f" sb_state setup_mode)
    BL_SB_PK_FP=$(baseline_get_in "$_ble_f" sb_state pk_fp)
    BL_SB_KEK_FP=$(baseline_get_in "$_ble_f" sb_state kek_fp)
    BL_SB_DB_FP=$(baseline_get_in "$_ble_f" sb_state db_fp)
    BL_SB_DBX_FP=$(baseline_get_in "$_ble_f" sb_state dbx_fp)
    BL_FW_VENDOR=$(baseline_get_in "$_ble_f" fw vendor)
    BL_FW_VERSION=$(baseline_get_in "$_ble_f" fw version)
    BL_FW_EVENTLOG_SHA256=$(baseline_get_in "$_ble_f" fw eventlog_sha256)
    BL_FW_EVENTLOG_SIZE=$(baseline_get_in "$_ble_f" fw eventlog_size)
    BL_KEYS_RELEASE_PUB_PATH=$(baseline_get_in "$_ble_f" keys release_pub_path)
    BL_KEYS_RELEASE_CERT_PATH=$(baseline_get_in "$_ble_f" keys release_cert_path)
    BL_TARGET_LUKS_UUID=$(baseline_get_in "$_ble_f" target luks_uuid)
    BL_TARGET_ESP_PARTUUID=$(baseline_get_in "$_ble_f" target esp_partuuid)
}

# --- baseline.json v1 reader / validator ---------------------------------------
# baseline_get FILE KEY — top-level scalar value (empty if absent)
baseline_get() {
    sed -n "s/^  \"$2\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1"
}

# baseline_get_in FILE OBJ KEY — nested (4-space indent) scalar value
baseline_get_in() {
    sed -n "s/^    \"$3\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1"
}

baseline_has_key() { grep -q "^  \"$2\":" "$1"; }
baseline_has_key_in() { grep -q "^    \"$3\":" "$1"; }

# _bl_pcr_ok V — rc 0 iff V is "pending" or a 64-char lowercase hex digest
_bl_pcr_ok() {
    [ "$1" = "pending" ] && return 0
    printf '%s' "$1" | grep -qE '^[0-9a-f]{64}$'
}

# baseline_validate FILE — structural v1 validation; rc 0 iff the file parses,
# schema_version is exactly 1 and every required key is present with a sane value
baseline_validate() {
    _bv_f=$1
    if [ ! -r "$_bv_f" ]; then
        warn "baseline: not readable: $_bv_f"
        return 1
    fi
    _bv_ver=$(baseline_get "$_bv_f" schema_version)
    if [ "$_bv_ver" != "1" ]; then
        warn "baseline: unsupported schema_version '$_bv_ver' (want 1)"
        return 1
    fi
    for _bv_k in created_at pcr0 pcr1 pcr2 pcr3 expected_pcr7; do
        if ! baseline_has_key "$_bv_f" "$_bv_k"; then
            warn "baseline: missing key: $_bv_k"
            return 1
        fi
    done
    for _bv_k in pcr0 pcr1 pcr2 pcr3 expected_pcr7; do
        _bv_v=$(baseline_get "$_bv_f" "$_bv_k")
        if ! _bl_pcr_ok "$_bv_v"; then
            warn "baseline: $_bv_k: not 'pending' nor a 64-hex sha256 digest: '$_bv_v'"
            return 1
        fi
    done
    if [ -z "$(baseline_get "$_bv_f" created_at)" ]; then
        warn "baseline: empty created_at"
        return 1
    fi
    for _bv_k in secure_boot setup_mode pk_fp kek_fp db_fp dbx_fp; do
        if ! baseline_has_key_in "$_bv_f" sb_state "$_bv_k"; then
            warn "baseline: missing sb_state.$_bv_k"
            return 1
        fi
    done
    for _bv_k in vendor version eventlog_sha256 eventlog_size; do
        if ! baseline_has_key_in "$_bv_f" fw "$_bv_k"; then
            warn "baseline: missing fw.$_bv_k"
            return 1
        fi
    done
    for _bv_k in release_pub_path release_cert_path; do
        if ! baseline_has_key_in "$_bv_f" keys "$_bv_k"; then
            warn "baseline: missing keys.$_bv_k"
            return 1
        fi
    done
    for _bv_k in luks_uuid esp_partuuid; do
        if ! baseline_has_key_in "$_bv_f" target "$_bv_k"; then
            warn "baseline: missing target.$_bv_k"
            return 1
        fi
    done
    return 0
}

# baseline_is_pending FILE — rc 0 iff expected_pcr7 is still "pending"
baseline_is_pending() {
    [ "$(baseline_get "$1" expected_pcr7)" = "pending" ]
}

# baseline_is_final FILE — rc 0 iff the baseline is finalized (has a real PCR 7)
baseline_is_final() {
    _bif_v=$(baseline_get "$1" expected_pcr7)
    [ -n "$_bif_v" ] && [ "$_bif_v" != "pending" ]
}

# baseline_set_pcr FILE KEY VALUE — surgically replace a pending/known pcr
# value ("pcr0".."pcr3", "expected_pcr7"); VALUE must be 'pending' or 64-hex
baseline_set_pcr() {
    _bsp_f=$1 _bsp_k=$2 _bsp_v=$3
    _bl_pcr_ok "$_bsp_v" || die "baseline_set_pcr: bad value for $_bsp_k: $_bsp_v"
    # IN-01: `2>&1 >tmp` captures awk's stderr (and any tmp-file open failure)
    # so an I/O fault dies with the REAL reason; a clean nonzero awk exit
    # (empty stderr, END { exit !done }) is the genuine key-not-found case.
    _bsp_err=$(awk -v k="\"$_bsp_k\":" -v v="$_bsp_v" '
        !done && index($0, "  " k " \"") == 1 {
            printf "  %s \"%s\",\n", k, v
            done = 1
            next
        }
        { print }
        END { exit !done }
    ' "$_bsp_f" 2>&1 >"$_bsp_f.tmp") || {
        rm -f "$_bsp_f.tmp" 2>/dev/null
        die "baseline_set_pcr: ${_bsp_err:-key not found: $_bsp_k}"
    }
    mv "$_bsp_f.tmp" "$_bsp_f"
}

# baseline_set_field FILE INDENT OBJ KEY VALUE — replace any nested field
baseline_set_field() {
    _bsf_f=$1 _bsf_pad=$2 _bsf_obj=$3 _bsf_k=$4 _bsf_v=$5
    _bl_sane "$_bsf_v" || die "baseline_set_field: value would break JSON: $_bsf_v"
    # IN-01: same real-reason capture as baseline_set_pcr
    _bsf_err=$(awk -v pad="$_bsf_pad" -v obj="\"$_bsf_obj\"" -v k="\"$_bsf_k\":" -v v="$_bsf_v" '
        {
            if (index($0, "  " obj ": {") == 1) {
                inobj = 1
            } else if (inobj && substr($0, 1, 4) == "  \"") {
                inobj = 0
            }
            if (inobj && index($0, pad k " \"") == 1) {
                # preserve whether the original line ended with a comma:
                # replacing the final field of an object must not add one
                hascomma = ($0 ~ /,[[:space:]]*$/)
                printf "%s%s \"%s\"%s\n", pad, k, v, (hascomma ? "," : "")
                done = 1
                next
            }
            print
        }
        END { exit !done }
    ' "$_bsf_f" 2>&1 >"$_bsf_f.tmp") || {
        rm -f "$_bsf_f.tmp" 2>/dev/null
        die "baseline_set_field: ${_bsf_err:-key not found: $_bsf_obj.$_bsf_k}"
    }
    mv "$_bsf_f.tmp" "$_bsf_f"
}

# baseline_finalize_from_live — finalize a pending baseline from the live
# machine (used by `audit --init`/`audit --accept` and `provision stage2`):
# PCR 0..3+7, Secure Boot state + key fingerprints, firmware identity, event
# log v1 record. Requires a working TPM + baseline on disk; dies fail-closed
# otherwise.
#
# M-3: the finalized document is built in a temp file NEXT TO the target,
# validated, then moved into place atomically — a mid-capture failure
# (unreadable PCR, invalid result) leaves the on-disk trust root untouched
# instead of torn. L-6: the read-modify-write ceremony is serialized with an
# exclusive flock on <etc>/alpine-fde/.baseline.lock so concurrent
# finalizations (audit --accept + provision stage2) cannot interleave
# field-by-field into a mixed baseline that still validates.
baseline_finalize_from_live() {
    _bff_f=$(sp_baseline_file)
    [ -f "$_bff_f" ] || die "baseline_finalize: no baseline at $_bff_f (run 'alpine-fde provision stage1' first)"
    baseline_validate "$_bff_f" || die "baseline_finalize: existing baseline invalid"
    tpm_available || die "no TPM reachable via TCTI '${ALPINE_FDE_TCTI:-<default>}' — cannot finalize baseline"
    # Guard (§8.1/§9.1): the finalized baseline is the trust root every later
    # `audit` is measured against, so it may only be captured in the machine's
    # FINAL Secure Boot state. Fail-closed 64 before ANY mutation (the baseline
    # stays pending); no override — an SB-off machine must fix Secure Boot
    # first ('enroll-tpm' refuses on the same precondition).
    _bff_sb=$(fw_sb_state) || true
    case $_bff_sb in
        secureboot=1\ setup_mode=0\ *) : ;;
        *)
            die "baseline_finalize: refusing to finalize: Secure Boot must be on with SetupMode=0, got: $_bff_sb — fix Secure Boot first (no override)"
            ;;
    esac
    # L-6: serialize concurrent ceremonies (probe-then-open: a redirect error
    # under `exec` would abort a strict-mode caller without our die message).
    _bff_lock="${_bff_f%/*}/.baseline.lock"
    if ! : >"$_bff_lock"; then
        die "baseline_finalize: cannot create lock file $_bff_lock"
    fi
    exec 9>"$_bff_lock"
    if ! flock -x 9; then
        exec 9>&-
        die "baseline_finalize: cannot acquire $_bff_lock (another ceremony running?)"
    fi
    # _bff_fail — staged-document die path: discard the temp doc, drop the lock.
    # CR-01: plain `exec 9>&-` ONLY (same pattern as enrl_lock_release) — a
    # second redirect on the same exec (e.g. 2>/dev/null) is applied
    # PERSISTENTLY (POSIX exec-without-command semantics) and would silence
    # stderr BEFORE die prints, making every fail-closed path invisible.
    _bff_tmp=''
    _bff_fail() {
        [ -z "$_bff_tmp" ] || rm -f "$_bff_tmp"
        exec 9>&-
        die "$@"
    }
    # IN-01: a setter dying on an I/O fault bypasses _bff_fail (leaking the
    # staged document). Run each setter in a subshell — its die only exits that
    # subshell — and route the real reason through _bff_fail. The die prefix is
    # stripped so the composed message does not stutter.
    _bff_set() {
        _bff_err=$(baseline_set_pcr "$@" 2>&1) || _bff_fail \
            "baseline_finalize: $(printf '%s' "$_bff_err" | sed 's/^alpine-fde: error: //')"
    }
    _bff_set_field() {
        _bff_err=$(baseline_set_field "$@" 2>&1) || _bff_fail \
            "baseline_finalize: $(printf '%s' "$_bff_err" | sed 's/^alpine-fde: error: //')"
    }
    # M-3: stage the finalized document next to the target
    _bff_tmp=$(mktemp "${_bff_f%/*}/.baseline-finalize.XXXXXX") ||
        _bff_fail "baseline_finalize: cannot create temp document next to $_bff_f"
    if ! cp "$_bff_f" "$_bff_tmp"; then
        _bff_fail "baseline_finalize: cannot stage temp document from $_bff_f"
    fi
    for _bff_i in 0 1 2 3 7; do
        if ! _bff_v=$(tpm_pcr_read "$_bff_i") || [ -z "$_bff_v" ]; then
            _bff_fail "baseline_finalize: cannot read PCR $_bff_i"
        fi
        if [ "$_bff_i" = "7" ]; then
            _bff_set "$_bff_tmp" expected_pcr7 "$_bff_v"
        else
            _bff_set "$_bff_tmp" "pcr$_bff_i" "$_bff_v"
        fi
    done
    # _bff_sb: "secureboot=N setup_mode=N pk=N" (captured by the guard above)
    _bff_set_field "$_bff_tmp" '    ' sb_state secure_boot "$(printf '%s' "$_bff_sb" | sed -n 's/.*secureboot=\([01]\).*/\1/p')"
    _bff_set_field "$_bff_tmp" '    ' sb_state setup_mode "$(printf '%s' "$_bff_sb" | sed -n 's/.*setup_mode=\([01]\).*/\1/p')"
    for _bff_pair in PK:pk_fp KEK:kek_fp db:db_fp dbx:dbx_fp; do
        _bff_var=${_bff_pair%%:*}
        _bff_fp=$(fw_var_sha256 "$_bff_var") || _bff_fp=''
        _bff_set_field "$_bff_tmp" '    ' sb_state "${_bff_pair#*:}" "$_bff_fp"
    done
    _bff_set_field "$_bff_tmp" '    ' fw vendor "$(dmi_field sys_vendor)"
    _bff_set_field "$_bff_tmp" '    ' fw version "$(dmi_field bios_version)"
    if _bff_el=$(eventlog_info); then
        _bff_set_field "$_bff_tmp" '    ' fw eventlog_sha256 "$(printf '%s' "$_bff_el" | cut -d' ' -f1)"
        _bff_set_field "$_bff_tmp" '    ' fw eventlog_size "$(printf '%s' "$_bff_el" | cut -d' ' -f2)"
    else
        warn "baseline_finalize: TCG event log not found at $(eventlog_path) — recorded empty"
    fi
    baseline_validate "$_bff_tmp" ||
        _bff_fail "baseline_finalize: finalization produced an invalid baseline"
    if ! mv "$_bff_tmp" "$_bff_f"; then
        _bff_fail "baseline_finalize: atomic replace of $_bff_f failed"
    fi
    exec 9>&-
}

# --- LUKS2 metadata JSON parsers (jq) -------------------------------------------
# These consume `cryptsetup luksDump --dump-json-metadata` output. cryptsetup's
# emitted layout VARIES BY VERSION: pretty-printed with/without spaces after
# colons across releases, and single-line COMPACT on 2.7.x (observed live, e2e
# runs 1789706685/-9163). The parsers are therefore shape-tolerant: every
# function parses the document with jq (a §3.3 target dependency) instead of
# anchoring on a text layout. Output conventions unchanged: counts print a
# number (0 when the document is unparseable), lookups print the value or
# nothing, rc 0.

# luks_json_count_type FILE TYPE — number of objects with "type": "<TYPE>"
luks_json_count_type() {
    jq '[.. | objects | select(.type? == $t)] | length' --arg t "$2" "$1" 2>/dev/null || echo 0
}

# luks_json_token_keyslot FILE TYPE — first "keyslots": ["N"] ref of the first
# token of TYPE; empty output when absent
luks_json_token_keyslot() {
    jq -r 'first(.tokens[]? | select(.type? == $t) | .keyslots[0]?) // empty' \
        --arg t "$2" "$1" 2>/dev/null || :
}

# luks_json_slot_blob FILE SLOT — the canonical single-line JSON of
# keyslots.<SLOT> (object value only); deterministic for identical content, so
# before/after equality comparisons remain byte-identical
luks_json_slot_blob() {
    jq -c --arg s "$2" '.keyslots // {} | .[$s] // empty' "$1" 2>/dev/null || :
}
