#!/usr/bin/env bash
# tests/unit/canary_e2e_contract.sh — hermetic contract pins for the install
# canary (queue item 32: tests/e2e/s23-install-e2e.sh + tests/lib/
# local-mirror.sh). NOTHING here boots a VM or touches the network:
#   * local mirror tooling: the cache no-op second call, the manifest pin,
#     index drift detection (fail-closed + the explicit allow-drift escape),
#     rebuild-on-corruption, the release/upstream/cache accessors, the
#     inst_repo_lines main/community twin layout, and the package-list
#     derivation covering the REAL lib/cmd/install.sh install_package_list
#   * ISO pin convention: flavor-version-arch filename under .cache/isos,
#     SHA256 env override idiom
#   * scenario structure: the local-mirror seam, the ALPINE_FDE_MIRROR seam
#     pointed at the guest loopback, the credentials ceremony feed (recovery
#     twice + two bare Enters), the sentinel-corroborated assertions
#     (BOOTX64.EFI + loader + UKIs on the ESP, the I2 no-secrets scan, the
#     finalized baseline, the provisional {11} -> final {7,11} shape), the
#     golden-base snapshot, and the s20 lesson (bounded waits, rc majority)
#   * registration gate: s23 is NOT yet in run-e2e.sh's REGISTRY (the
#     orchestrator registers it after boot verification)
#   * bash -n on everything authored

set -u
HERE=$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)
TESTS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$TESTS/.." && pwd)
# shellcheck source=../lib/assert.sh
source "$TESTS/lib/assert.sh"
_pass() { _assert_result ok "$1" ""; }
_fail() { _assert_result not-ok "$1" "${2:-}"; }

T=$(mktemp -d /tmp/alpine-fde-canary-contract.XXXXXX)
cleanup() { rm -rf "$T"; }
trap cleanup EXIT

SCENARIO="$TESTS/e2e/s23-install-e2e.sh"
MIRROR_LIB="$TESTS/lib/local-mirror.sh"

# --- 0. syntax gates ------------------------------------------------------------
for f in "$SCENARIO" "$MIRROR_LIB" "$HERE/canary_e2e_contract.sh"; do
    if bash -n "$f" 2>"$T/syn.err"; then
        _pass "bash -n: $(basename "$f")"
    else
        _fail "bash -n: $(basename "$f") ($(cat "$T/syn.err"))"
    fi
done

# --- 1. hermetic fake mirror: env-pinned indexes, isolated cache ------------------
mkdir -p "$T/fake-index" "$T/isos"
printf 'FAKE-APKINDEX-MAIN\n' >"$T/fake-index/main-APKINDEX.tar.gz"
printf 'FAKE-APKINDEX-COMMUNITY\n' >"$T/fake-index/community-APKINDEX.tar.gz"
PIN_MAIN=$(sha256sum "$T/fake-index/main-APKINDEX.tar.gz" | awk '{print $1}')
PIN_COMM=$(sha256sum "$T/fake-index/community-APKINDEX.tar.gz" | awk '{print $1}')

export ALPINE_FDE_LOCAL_MIRROR_CACHE="$T/cache"
export ALPINE_FDE_MIRROR_RELEASE="v9test"
export ALPINE_FDE_ISO_CACHE="$T/isos"
export ALPINE_FDE_MIRROR_MAIN_APKINDEX_SHA256="$PIN_MAIN"
export ALPINE_FDE_MIRROR_COMMUNITY_APKINDEX_SHA256="$PIN_COMM"
# the fake-upstream URL is never fetched (the fetchers are stubbed below)
export ALPINE_FDE_MIRROR_UPSTREAM="http://fake.invalid/alpine"

# shellcheck source=../lib/local-mirror.sh
source "$MIRROR_LIB"

# stub the three network-touching chain links; each appends to a call log so
# the no-op second call can be PROVEN (a silent rebuild would double the log)
NL=$'\n'
CALLLOG="$T/calls.log"
mirror_index_ensure() {
    local comp="$1"
    echo "index:$comp" >>"$CALLLOG"
    mkdir -p "$(mirror_repo_dir "$comp")"
    cp "$T/fake-index/$comp-APKINDEX.tar.gz" "$(mirror_repo_dir "$comp")/APKINDEX.tar.gz"
    return 0
}
mirror_bootstrap_ensure() { echo "bootstrap" >>"$CALLLOG"; mkdir -p "$(mirror_cache_root)/bootstrap"; return 0; }
mirror_closure_fetch() {
    echo "closure" >>"$CALLLOG"
    mkdir -p "$(mirror_repo_dir main)" "$(mirror_repo_dir community)"
    printf 'fake-apk-main\n' >"$(mirror_repo_dir main)/fake-pkg-1.0-r0.apk"
    printf 'fake-apk-comm\n' >"$(mirror_repo_dir community)/fake-pkg-2.0-r1.apk"
    return 0
}

# --- 2. accessors + the inst_repo_lines twin layout -------------------------------
assert_eq "mirror_release honors the env override" "v9test" "$(mirror_release)"
assert_eq "mirror_cache_dir is <cache>/<release>" "$T/cache/v9test" "$(mirror_cache_dir)"
assert_eq "mirror_repo_dir layout (upstream shape: <release>/<comp>/x86_64)" \
    "$T/cache/v9test/main/x86_64" "$(mirror_repo_dir main)"

# the SERVING contract: inst_repo_lines (the installer's repositories drop)
# derives the community twin by stripping /main — the mirror layout must
# resolve under exactly those two URLs. Source the product lib for real.
if bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    base='$(mirror_upstream)/$(mirror_release)'
    ALPINE_FDE_MIRROR=\"\$base/main\"
    lines=\$(inst_repo_lines)
    want=\"\$base/main
\$base/community\"
    [ \"\$lines\" = \"\$want\" ]"; then
    _pass "inst_repo_lines twin resolves against the mirror layout ($T/win-twin)"
else
    _fail "inst_repo_lines twin does not resolve against the mirror layout"
fi

# --- 3. package-list derivation covers the REAL install_package_list --------------
PROD_PKGS=$(bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    INST_ROOT_FS=btrfs INST_BCACHE=0 install_package_list")
MIRROR_PKGS=$(mirror_package_list)
_missing=''
for p in alpine-base $PROD_PKGS; do
    case " $MIRROR_PKGS " in
        *" $p "*) : ;;
        *) _missing="$_missing $p" ;;
    esac
done
if [ -z "$_missing" ]; then
    _pass "mirror_package_list covers install_package_list + alpine-base (btrfs topology)"
else
    _fail "mirror_package_list is missing:$_missing"
fi
case " $MIRROR_PKGS " in
    *" e2fsprogs "*)
        case " $MIRROR_PKGS " in
            *" bcache-tools "*) _pass "topology union present (e2fsprogs + bcache-tools)" ;;
            *) _fail "topology union incomplete: [$MIRROR_PKGS]" ;;
        esac ;;
    *) _fail "topology union incomplete: [$MIRROR_PKGS]" ;;
esac

# --- 4. cache lifecycle: build -> no-op second call -> drift -> rebuild -----------
mirror_ensure >/dev/null 2>&1
if mirror_ensure 2>"$T/noop.err"; then
    _pass "mirror_ensure (built cache) rc 0"
else
    _fail "mirror_ensure (built cache) rc nonzero"
fi
assert_contains "second call is a NO-OP (log says so)" "$(cat "$T/noop.err")" "no-op"
assert_eq "second call made ZERO network/stub calls" \
    "index:main${NL}index:community${NL}closure" \
    "$(cat "$CALLLOG")"
assert_file_exists "manifest pin written (MANIFEST.sha256)" "$T/cache/v9test/MANIFEST.sha256"
assert_file_exists "mirror.json provenance written" "$T/cache/v9test/mirror.json"
grep -q '^.*main/x86_64/APKINDEX.tar.gz$' "$T/cache/v9test/MANIFEST.sha256" &&
    grep -q '^.*community/x86_64/APKINDEX.tar.gz$' "$T/cache/v9test/MANIFEST.sha256" &&
    _pass "manifest pins BOTH indexes" || _fail "manifest does not pin both indexes"

# drift detection: cached index no longer matching the pins fails CLOSED...
MIRROR_PIN_MAIN_APKINDEX_SHA256="0000000000000000000000000000000000000000000000000000000000000000"
if mirror_ensure >/dev/null 2>&1; then
    _fail "index drift was NOT detected (mirror_ensure rc 0 with a mismatched pin)"
else
    _pass "index drift detected: mirror_ensure fails closed on a pin mismatch"
fi
# ...unless explicitly allowed (the loud-warning escape)
if ALPINE_FDE_MIRROR_ALLOW_DRIFT=1 mirror_ensure >/dev/null 2>&1; then
    _pass "ALPINE_FDE_MIRROR_ALLOW_DRIFT=1 downgrades drift to a loud warning (rc 0)"
else
    _fail "ALPINE_FDE_MIRROR_ALLOW_DRIFT=1 still failed"
fi
MIRROR_PIN_MAIN_APKINDEX_SHA256="$PIN_MAIN"

# rebuild-on-corruption: a byte-flipped apk must trigger (and survive) a rebuild
printf 'CORRUPTED' >"$T/cache/v9test/main/x86_64/fake-pkg-1.0-r0.apk"
if mirror_ensure >/dev/null 2>&1; then
    _pass "corrupted cache triggers a rebuild (rc 0 after)"
else
    _fail "corrupted cache did not rebuild cleanly"
fi
assert_eq "rebuild path re-ran the fetch chain" \
    "index:main${NL}index:community${NL}closure${NL}index:main${NL}index:community${NL}closure" \
    "$(cat "$CALLLOG")"
(cd "$T/cache/v9test" && sha256sum --check --quiet MANIFEST.sha256) >/dev/null 2>&1 &&
    _pass "rebuilt cache re-verifies against its manifest" ||
    _fail "rebuilt cache manifest does not verify"

# the cache must be BOUND to the derivation that built it (the boot lane's
# live finding #4 tail: the no-op path can't be "manifest verifies" alone —
# a DERIVATION change (e.g. the live tool union) would never be fetched and
# the cache would silently keep missing packages). mirror.json records
# package_list_sha256; a basis mismatch forces a rebuild.
if [ -n "$(jq -r '.package_list_sha256 // empty' "$T/cache/v9test/mirror.json" 2>/dev/null)" ]; then
    _pass "mirror.json records the closure basis (package_list_sha256)"
else
    _fail "mirror.json does not record package_list_sha256 (the no-op path cannot detect a derivation change)"
fi
N_BEFORE=$(grep -c closure "$CALLLOG" || true)
INST_ROOT_FS=ext4 mirror_ensure >/dev/null 2>&1
N_AFTER=$(grep -c closure "$CALLLOG" || true)
if [ "$N_AFTER" -gt "$N_BEFORE" ]; then
    _pass "a derivation change forces a rebuild (topology flip is NOT a no-op)"
else
    _fail "derivation change was a NO-OP (the cache silently keeps missing packages)"
fi

# --- 4b. the REAL bootstrap chain (the boot lane's live finding #5) ----------
# mirror_bootstrap_ensure was never executed hermetically (the section-1
# stubs replace it) and its rebuild path is broken: the version pins are
# shell VARIABLES referenced with COMMAND-substitution syntax
# ($(MIRROR_PIN_APK_TOOLS_STATIC_VERSION) -> "command not found", empty
# interpolation -> apk-tools-static-.apk -> upstream 404; observed live,
# attempt 5, the first real rebuild). Execute the REAL function here in a
# fresh shell (stub-free) with a stubbed _mirror_fetch and pins matching the
# fixture: it must fetch, verify both hashes, extract apk.static and leave it
# executable.
BOOT_OUT=$(bash -c "
    set -u
    export ALPINE_FDE_LOCAL_MIRROR_CACHE='$T/bootfix-cache'
    export ALPINE_FDE_MIRROR_RELEASE='v9test'
    export ALPINE_FDE_MIRROR_UPSTREAM='http://fake.invalid/alpine'
    . '$REPO/tests/lib/local-mirror.sh'
    d='$T/bootfix'
    mkdir -p \"\$d/src/sbin\"
    printf '#!/bin/sh\necho apk-static-stub\n' >\"\$d/src/sbin/apk.static\"
    chmod +x \"\$d/src/sbin/apk.static\"
    tar -czf \"\$d/apk-tools-static-3.0.8-r0.apk\" -C \"\$d/src\" sbin
    mkdir -p \"\$d/src2/etc/apk/keys\"
    printf 'DUMMY-KEY\n' >\"\$d/src2/etc/apk/keys/alpine-devel@example.test.rsa\"
    tar -czf \"\$d/alpine-keys-2.6-r0.apk\" -C \"\$d/src2\" etc/apk/keys
    MIRROR_PIN_APK_TOOLS_STATIC_SHA256=\$(sha256sum \"\$d/apk-tools-static-3.0.8-r0.apk\" | awk '{print \$1}')
    MIRROR_PIN_ALPINE_KEYS_SHA256=\$(sha256sum \"\$d/alpine-keys-2.6-r0.apk\" | awk '{print \$1}')
    _mirror_fetch() { # stub the wire: serve the fixtures by basename
        dest=\$1; base=\$(basename \"\$2\")
        case \"\$base\" in
            apk-tools-static-*) cp \"\$d/apk-tools-static-3.0.8-r0.apk\" \"\$dest\" ;;
            alpine-keys-*) cp \"\$d/alpine-keys-2.6-r0.apk\" \"\$dest\" ;;
            *) return 1 ;;
        esac
    }
    mirror_bootstrap_ensure; echo \"A-RC=\$?\"
    test -x \"\$ALPINE_FDE_LOCAL_MIRROR_CACHE/bootstrap/apk.static\"; echo \"B-RC=\$?\"
    \"\$ALPINE_FDE_LOCAL_MIRROR_CACHE/bootstrap/apk.static\" | grep -q apk-static-stub; echo \"C-RC=\$?\"
" 2>&1)
if printf '%s' "$BOOT_OUT" | grep -q '^A-RC=0$' \
    && printf '%s' "$BOOT_OUT" | grep -q '^B-RC=0$' \
    && printf '%s' "$BOOT_OUT" | grep -q '^C-RC=0$'; then
    _pass "mirror_bootstrap_ensure (REAL run): fetch + hash pins + apk.static extraction"
else
    _fail "mirror_bootstrap_ensure broken on the rebuild path ($(printf '%s' "$BOOT_OUT" | grep -E 'A-RC|B-RC|C-RC|local-mirror' | tr '\n' ' '))"
fi
rm -rf "$T/bootfix" "$T/bootfix-cache"

# --- 5. ISO pin convention ----------------------------------------------------------
assert_eq "iso filename convention (flavor-version-arch under the ISO cache)" \
    "$T/isos/alpine-virt-3.24.2-x86_64.iso" "$(iso_path)"
case "$(iso_url)" in
    */releases/x86_64/alpine-virt-3.24.2-x86_64.iso)
        _pass "iso URL follows the dl-cdn releases convention" ;;
    *) _fail "iso URL convention: $(iso_url)" ;;
esac
assert_eq "ISO sha pin honors the env override idiom (ALPINE_FDE_ISO_SHA256)" \
    "custom" "$(ALPINE_FDE_ISO_SHA256=custom iso_expected_sha256)"

# --- 6. scenario structure (the authored canary, grep-pinned) -----------------------
assert_file_exists "canary scenario present" "$SCENARIO"
_s23() { cat "$SCENARIO"; }
assert_contains "scenario sources the local-mirror lib" "$(_s23)" "lib/local-mirror.sh"
assert_contains "scenario runs the mirror ensure (the pinned apk source)" "$(_s23)" "mirror_ensure"
assert_contains "scenario runs the ISO ensure (the pinned boot media)" "$(_s23)" "iso_ensure"
assert_contains "scenario points ALPINE_FDE_MIRROR at the guest loopback mirror" "$(_s23)" \
    "ALPINE_FDE_MIRROR='"'$MIRROR_URL'"'"
assert_contains "the mirror URL is the guest-local httpd host (loopback seam)" "$(_s23)" \
    "mirror.fde.internal"
# the credentials ceremony seam: recovery typed TWICE + two bare Enters
n_recovery=$(grep -c 'feed_line "$A/serial.sock" "$S23_RECOVERY"' "$SCENARIO" || true)
assert_eq "ceremony feed: the recovery passphrase is typed TWICE" "2" "$n_recovery"
n_enters=$(grep -c 'feed_line "$A/serial.sock" ""' "$SCENARIO" || true)
if [ "$n_enters" -ge 2 ]; then
    _pass "ceremony feed: two bare ENTERs (account password + release-key reuse)"
else
    _fail "ceremony feed: expected >= 2 bare Enters, got $n_enters"
fi
assert_contains "ceremony synchronized on the REAL prompt text (recovery 1/3)" "$(_s23)" \
    "set the LUKS2 recovery passphrase"
assert_contains "ceremony synchronized on the REAL prompt text (account 2/3)" "$(_s23)" \
    "set the password for account"
assert_contains "ceremony synchronized on the REAL prompt text (release key 3/3)" "$(_s23)" \
    "set the release-key passphrase"
# the real installer invocation
assert_contains "scenario runs the REAL installer with --yes" "$(_s23)" "--yes"
assert_contains "scenario runs the REAL installer against a blank target disk" "$(_s23)" \
    "--disk /dev/vdb"
# assertion sentinels (every stage boundary corroborated; s20 lesson)
for s in sentinel_of unseal_prompt_re emergency_forbidden cli_seal_slot; do
    assert_contains "scenario pins the sentinel seam: $s" "$(_s23)" "$s"
done
assert_contains "scenario: bounded rc re-read majority (the s20 doubled-byte lesson)" "$(_s23)" "_await_rc"
assert_contains "scenario asserts BOOTX64.EFI on the installed ESP" "$(_s23)" "BOOTX64.EFI"
assert_contains "scenario asserts the canonical loader (systemd-bootx64.efi)" "$(_s23)" \
    "systemd-bootx64.efi"
assert_contains "scenario asserts UKIs on the ESP (EFI/Linux)" "$(_s23)" "EFI/Linux"
assert_contains "scenario runs the I2 no-secrets scan (PEM private keys)" "$(_s23)" \
    "PRIVATE KEY"
assert_contains "scenario asserts NO alpine-fde-keys fallback staging on the ESP (I2)" "$(_s23)" \
    "alpine-fde-keys"
assert_contains "scenario asserts the LUKS2 at-rest shape (ephemeral keyslot purged, I1)" "$(_s23)" \
    "PURGED"
assert_contains "scenario asserts the provisional -> final token upgrade ({7,11})" "$(_s23)" \
    '"[7,11]"'
assert_contains "scenario asserts the finalized install state" "$(_s23)" '"state": "finalized"'
assert_contains "scenario asserts \`alpine-fde status\` runs in the installed system" "$(_s23)" \
    "alpine-fde status"
# golden-base snapshot (the registry's next base image)
assert_contains "scenario snapshots the golden base (.cache/pristine-install-e2e)" "$(_s23)" \
    "pristine-install-e2e"
assert_contains "golden base carries a FORMAT generation marker" "$(_s23)" "install-e2e-1"
assert_contains "golden base is SHA-manifested" "$(_s23)" "MANIFEST.sha256"
assert_contains "golden base records the mirror/ISO pins (PINS.json)" "$(_s23)" "PINS.json"

# --- 6b. the swtpm fixture handoff (the boot lane's live finding #1) ----------
# swtpm_start arms `trap swtpm_cleanup_all EXIT INT TERM` when
# _SWTPM_CLEANUP_TRAP_SET==0 (tests/lib/swtpm-fixture.sh); inside a run_stage
# stage subshell that trap fires at STAGE EXIT and stops the freshly-started,
# healthy daemon — observed live: s23 attempt 1 lost boot A in the first
# console wait, qemu.stderr "Failed to connect .../tpm/sock.ctrl: No such
# file or directory". The established idiom (s15/s21) is the
# _SWTPM_CLEANUP_TRAP_SET=1 call prefix + a local _track_swtpm definition.
# every `run_stage ... swtpm_start` invocation must carry the guard prefix;
# unguarded = a line whose command word IS run_stage (guarded lines start
# with the _SWTPM_CLEANUP_TRAP_SET=1 prefix)
if [ "$(grep -cE '^[[:space:]]*run_stage[[:space:]].*swtpm_start' "$SCENARIO")" -eq 0 ] \
    && [ "$(grep -c '_SWTPM_CLEANUP_TRAP_SET=1 run_stage' "$SCENARIO")" -ge 1 ]; then
    _pass "s23 guards the boot-A swtpm_start stage with _SWTPM_CLEANUP_TRAP_SET=1"
else
    _fail "s23 boot-A swtpm_start stage lacks the _SWTPM_CLEANUP_TRAP_SET=1 guard (the fixture's EXIT trap kills the daemon at stage exit)"
fi
assert_contains "s23 defines _track_swtpm (SWTPM_DIRS registration — no phantom call)" "$(_s23)" \
    '_track_swtpm() { SWTPM_DIRS+=("$1"); }'

# --- 6c. the mirror serving seam (the boot lane's live finding #2) ------------
# The authored guest-local busybox-httpd design is UNACHIEVABLE with the
# pinned sets: the alpine-virt ISO's busybox has NO httpd applet (it lives in
# busybox-extras, absent from both the ISO's apks/ repo and the pinned
# mirror closure) — observed live: "-sh: httpd: not found" at the P1 leg
# (attempt 2). The pivot: the fixture's OWN host-server seam
# (mirror_serve_start, tests/lib/local-mirror.sh) + qemu slirp; the guest
# reaches the host server at 10.0.2.2 (slirp's host IP), the
# mirror.fde.internal name stays /etc/hosts + dnsd-backed for the installer's
# DNS preflight.
if grep -qE '"httpd -p|\| httpd ' "$SCENARIO"; then
    _fail "s23 still feeds a guest httpd invocation (unachievable: no httpd applet on the pinned ISO)"
else
    _pass "s23 feeds NO guest httpd invocation (host-server seam instead)"
fi
assert_contains "s23 starts the HOST loopback mirror server (mirror_serve_start)" "$(_s23)" \
    "mirror_serve_start"
assert_contains "s23 attaches the slirp netdev for the mirror route" "$(_s23)" \
    '-netdev user,id=mirror0'
assert_contains "s23 maps the mirror name at the slirp host IP (10.0.2.2)" "$(_s23)" \
    "10.0.2.2"

# --- 6d. mirror_serve_start/stop: the HOST transfer channel must WORK under
# set -u (the boot lane's live finding #3, attempt 3) --------------------------
# `local a="x" b="$a/y"` under set -u fails: `local` expands ALL of its words
# BEFORE any assignment sticks, so $docroot in the same local line was
# unbound ("local-mirror.sh: line 449: docroot: unbound variable"). The seam
# is execution-pinned here: serve a file over 127.0.0.1 and stop cleanly.
SRV_PORT=$(( 18000 + $$ % 20000 ))
mkdir -p "$T/serve"
printf 'SERVE-PROBE-OK\n' >"$T/serve/probe.txt"
# the call runs in a set -u SUBSHELL deliberately: the defect this pin guards
# (unbound $docroot inside the same `local` line) is FATAL to the caller —
# as sourced here it would abort this whole suite, which is exactly how the
# scenario's mirror-serve stage died (attempt 3)
if ( set -u; mirror_serve_start "$SRV_PORT" "$T/serve" ) 2>"$T/serve.err" \
    && [ "$(curl -fsS "http://127.0.0.1:$SRV_PORT/probe.txt")" = "SERVE-PROBE-OK" ]; then
    _pass "mirror_serve_start serves the docroot over 127.0.0.1 under set -u"
else
    _fail "mirror_serve_start unusable under set -u ($(head -1 "$T/serve.err"))"
fi
# stop is only meaningful against a RUNNING server (else the check is
# vacuous): require the pidfile the start above leaves, then stop, then
# require BOTH the pidfile gone and the port closed. A failed start makes
# this pin FAIL (the lifecycle is one contract).
STOP_WAS_RUNNING=0
[ -f "$T/serve/.httpd.pid" ] && STOP_WAS_RUNNING=1
( set -u; mirror_serve_stop "$T/serve" ) 2>"$T/serve-stop.err"
if [ "$STOP_WAS_RUNNING" = 1 ] && [ ! -f "$T/serve/.httpd.pid" ] \
    && ! curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:$SRV_PORT/probe.txt"; then
    _pass "mirror_serve_stop kills the server and clears the pidfile"
else
    _fail "mirror_serve_stop lifecycle broken (running=$STOP_WAS_RUNNING; $(head -1 "$T/serve-stop.err"))"
fi

# --- 6e. the mirror closure must cover the LIVE-env tool set (the boot
# lane's live finding #4, attempt 4) -------------------------------------------
# The real installer's FIRST mirror consumption is the preflight's
# require_pkgs: the virt ISO lacks sfdisk/lsblk (util-linux), mkfs.vfat
# (dosfstools) and the cryptsetup CLI, and the installer `apk add`s them from
# ALPINE_FDE_MIRROR — observed live: "apk add util-linux failed ... (no such
# packaage)" (INSTALL-RC=64). The closure derivation covered ONLY
# install_package_list (the in-chroot txn), not the live tool pairs.
# The fix seam: install.sh exposes the pairs ONCE (inst_live_tool_pairs), the
# preflight consumes them, mirror_package_list derives the pkg-name union —
# so the two lists cannot drift again.
PROD_LIVE=$(bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    inst_live_tool_pairs" 2>&1)
if [ "$?" -eq 0 ] && [ -n "$PROD_LIVE" ]; then
    _pass "install.sh exposes inst_live_tool_pairs (the preflight require_pkgs pairs)"
else
    _fail "install.sh has no inst_live_tool_pairs seam (got: $(printf '%s' "$PROD_LIVE" | head -1))"
fi
MIRROR_COVER=$(bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    . '$REPO/tests/lib/local-mirror.sh'
    INST_ROOT_FS=btrfs INST_BCACHE=0 install_package_list
    mirror_package_list" 2>/dev/null || true)
_miss=''
for p in util-linux dosfstools apk-tools cryptsetup openssl btrfs-progs e2fsprogs; do
    case " $MIRROR_COVER " in
        *" $p "*) : ;;
        *) _miss="$_miss $p" ;;
    esac
done
if [ -z "$_miss" ]; then
    _pass "mirror_package_list covers the live tool union (util-linux dosfstools apk-tools ...)"
else
    _fail "mirror_package_list is missing the live tool set:$_miss"
fi
if grep -q 'require_pkgs \$(inst_live_tool_pairs)' "$REPO/lib/cmd/install.sh" \
    && ! grep -q 'require_pkgs apk:apk-tools sfdisk:util-linux' "$REPO/lib/cmd/install.sh"; then
    _pass "the preflight consumes inst_live_tool_pairs (single source — no drift)"
else
    _fail "the preflight still hardcodes the require_pkgs pairs (drifts from the mirror derivation)"
fi
# the EXECUTED record: with every tool absent, require_pkgs consuming
# inst_live_tool_pairs must fail closed 64 naming the operand packages —
# exactly the record the real installer printed when the mirror lacked them
LIVE_ERR=$(bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    PATH=/nonexistent require_pkgs \$(inst_live_tool_pairs)" 2>&1 >/dev/null)
bash -c "
    set -u
    export ALPINE_FDE_CMD_DIR='$REPO/lib/cmd'
    . '$REPO/lib/common.sh'
    . '$REPO/lib/cmd/install.sh'
    PATH=/nonexistent require_pkgs \$(inst_live_tool_pairs)" >/dev/null 2>&1
LIVE_RC=$?
if [ "$LIVE_RC" = "64" ] && printf '%s' "$LIVE_ERR" | grep -q "util-linux" \
    && printf '%s' "$LIVE_ERR" | grep -q "dosfstools"; then
    _pass "executed record: require_pkgs(inst_live_tool_pairs) fails closed 64 naming the operands"
else
    _fail "executed record wrong: rc=$LIVE_RC err=$(printf '%s' "$LIVE_ERR" | head -1)"
fi

# --- 7. registration gate: NOT in the default selection yet -------------------------
if grep -qE $'^s23\t' "$TESTS/run-e2e.sh"; then
    _fail "s23 is registered in run-e2e.sh — the orchestrator gates registration (boot verification first)"
else
    _pass "s23 NOT registered in run-e2e.sh (orchestrator gate honored)"
fi
if [ -f "$TESTS/e2e/results-final.json" ] && grep -q '"s23"' "$TESTS/e2e/results-final.json"; then
    _fail "s23 already has a results-final.json row (nothing was executed yet)"
else
    _pass "no results-final.json row for s23 (authored-untested is honest)"
fi

if [ "$TESTS_FAIL" -gt 0 ]; then
    printf -- '---- %d passed, %d FAILED ----\n' "$TESTS_PASS" "$TESTS_FAIL"
    exit 1
fi
printf -- '---- %d passed, %d failed ----\n' "$TESTS_PASS" "$TESTS_FAIL"
exit 0
