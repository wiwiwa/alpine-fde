# tests/e2e — QEMU/OVMF end-to-end scenarios (docs/Architecture.md §12)

Status after Wave 3 (2026-09-14) + wave-3b revalidation (2026-09-18): **the
§6.1 mechanism ladder rung A″ is
PROVEN end-to-end** — `s00-bootstrap-lite` boots an enrolled OVMF+swtpm guest,
enrolls in-guest (Mechanism A″ flags), consumes the release-key-signed
`.pcrsig` and reaches the `unlocked` sentinel (`Volume … activated with a LUKS
token.` — table key `unlocked` in `tests/sentinels-257.13.txt`; console keys
are referenced by NAME throughout this README — the strings drift across
systemd releases, the table is the pin) + `debian-fde: UNSEALED`;
`s01-happy-lite` proves the tamper side (SB-off → PCR 7 drift → unseal
refused → retry cap → locked out, no prompt). Wave 3 adds the §10 fail-closed
scenario family: `s05` (SB-off row + PCR forensics), `s06` (the §12 trap:
SB-off + tampered token metadata + valid `.pcrsig`), `s07` (cmdline-tamper
UKI + stale `.pcrsig` → PCR 11 drift → refusal), `s12` (console-fed
passphrase fallback: 3 strikes → poweroff + recovery positive control) and
`s13` (token-tamper suite: pubkey-swap / blob-corrupt / policy-corrupt /
unknown-field). Evidence runs preserved under `.runs/` (gitignored). Wave 3b
(2026-09-18) re-observed s00/s00b and re-executed s14/s15/s16 for real (s14
including its first-ever run of the §10 build-failed leg); s01–s08, s10–s13,
s17 still carry their 2026-09-14 statuses (see follow-ups below).

## Full-bootstrap wave (S-00 per §12 + s00b + s09 + s18)

The bootstrap chain now follows §12 S-00/S-00b exactly (wave of 2026-09-17):

- **`s00-bootstrap-lite.sh`** — the full §12 S-00: installer UKI (passphrase
  unlock from the embedded kf0, ZERO console input) → populate the minimal
  rootfs (§3.3) from the SHA256-pinned artifact → §3.3 size-budget assertion
  (budget var `DEBIAN_FDE_ROOTFS_BUDGET_MIB` is the pin of record; planning
  target ≤1.4 GB) + package count → G-T11b disk-side key-material scans →
  `audit --init` finalizes the baseline via the REAL CLI (fail-closed unless
  the efivars seam reports SecureBoot=1 SetupMode=0 — the Wave-1 guard) →
  G-T13 prediction check (ukify's enter-initrd pol == the pre-unlock PCR 11
  state, never the final register) → ESP-size assertion (§13). Prints
  `RUNDIR <path>` for s00b.
- **G-HW5 wave (2026-09-19, btrfs-default BASE matrix)**: the populated
  rootfs follows the revised-design default — Btrfs on the LUKS volume with
  the §9.1 subvolume layout `@` / `@home` / `@snapshots` (mkfs.btrfs +
  `btrfs` from the pinned btrfs-progs deb; verified on-console via
  `btrfs subvolume list` and the verbatim fstab echo). The installer writes
  the §9.1 fstab forms (`UUID=<fs-uuid> /|/home|/.snapshots btrfs
  subvol=@…`) — production-exact. Making them RESOLVE required the dracut
  initrd pattern in the harness initrd: systemd-udevd runs from init start
  so the LUKS attach is udev-registered, and login_stage moves
  /dev + /proc + /sys + /run onto the new root before switch_root (busybox
  switch_root buries them otherwise — the /run udev db is what the installed
  system's fstab device units resolve through; both observed live, console
  evidence in the run dirs). Measured size under btrfs-default:
  **680 MiB / 322 packages** (du of `@` incl. the shipped btrfs-progs
  binaries) — the budget pin stays the §3.3 planning target with the
  measurement recorded at `DEBIAN_FDE_ROOTFS_BUDGET_MIB` (s00). The legacy
  flat fs remains production-only (`install --fs ext4`); no scenario
  exercises it, so the harness carries no ext4 seam. The pristine s00b
  cache is generation-marked (`FORMAT: btrfs-2`): pre-btrfs disks (ext4
  era) fail verification and trigger a rebuild.
- **`s00b-enroll-cache.sh`** — §12 S-00b (+S-01): boot B enrolls FROM THE
  GUEST via the production enroll CLI path (real `systemd-cryptenroll`,
  Mechanism A″, approved D3), asserts ensure-once (exactly ONE systemd-tpm2
  token), snapshot the pristine enrolled state into
  `.cache/pristine-s00b/` (SHA256 manifest, fail-closed verification on
  reuse); boot C is §12 S-01: login-stage UKI (enroll-skip → token unlock
  with zero input → switch_root into the installed system) must reach
  `login:` on the serial console; §13 ESP-size assertion; G-T13 prediction
  check for the enrolled release UKI.
- **`s09-tpm-da-locked.sh`** — §10 DA-locked row (G-T15): `swtpm_da_lockout`
  (tpm2_dictionarylockout) arms and ENGAGES dictionary-attack lockout
  (enforcement probe positive before AND after the boot — §7.1: the guest's
  refused policy sessions consumed no budget; the GetCapability counter
  readout is quirked on libtpms and is NOT faked into evidence). The pinned
  `da_locked` sentinel is documented as UNREACHABLE in-guest on swtpm
  (libtpms does not gate policy-session unseals on lockout — header note in
  the scenario): the refusal/fallback chain is driven via the PCR 7 drift
  vector instead: refusal → bounded fallback (3 strikes) → PROMPT-FAILED →
  poweroff, never emergency.
- **`s18-foreign-pcrsig.sh`** — §6.1 signing negative control, foreign key
  (G-T5): the payload `.pcrsig` carries the SAME (correct!) pol entries
  re-signed by a FOREIGN RSA key; the outer sbsign signature is ours so the
  firmware boots it (SB cannot see the payload drive). Host-side, the
  verification recipe itself is pinned: release.pub verifies the release sig
  over pol, REFUSES the foreign sig, foreign.pub verifies the foreign sig.
  In-guest: PCR 7 equal to the enrolled boot and post-phase PCR 11 equal to
  the signed pol (the pol MATCHED — the refusal is exactly the foreign
  signer), then token refusal → bounded fallback → poweroff, never
  emergency.
- **`tests/e2e/e2e_infra_smoke.sh`** — G-T11b artifact scans over the BUILT
  state (ESP listing + boot binary, UKI binaries, `.pcrsig` payload, the
  rootfs payload artifact decompressed, LUKS header area, plus a cross-check
  of the in-guest scan's console line). Exit 64 when there is nothing to
  scan. run-e2e.sh runs it after the scenario loop over the run dirs of that
  invocation (a hit is a harness-detected invariant violation); the
  unit-side fixture scans remain in `tests/unit/e2e_infra_smoke.sh` (the
  pre-scenario harness self-test).

## What exists

| File | Purpose |
|---|---|
| `../run-e2e.sh` | Orchestrator: env-check → harness self-test (infra smoke) → named/default scenarios (sequential by default; `-j N` runs up to N concurrent workers, with the s00→s00b chain always first and alone — see tests/README.md "Runner contract details") → per-scenario TAP output → G-T11b artifact scan → aggregated results JSON (`e2e/.runs/results-<ts>.json`) → nonzero exit on failure. Registry inside maps `s00, s00b, s01..s17` (the original §10/§12 matrix rows) PLUS the literal W2b rows `s19..s22` (§10 BASE matrix + §12 S-19..S-22) plus `s18` (appended at runtime so the literal table stays §10/§12-matrix-only). A registered id with NO scenario file is a FAILURE (`missing`), never a pending pass. The W2b scenarios bootstrap IN-SCENARIO (each builds its own fixtures and consumes no s00/s00b state — they are not in `_STATE_CONSUMERS`), so the `-j` s00/s00b hoist cannot misorder them and they run as ordinary independent workers. |
| `s00-bootstrap-lite.sh` | Full §12 S-00 (see "Full-bootstrap wave" above): installer UKI boot → passphrase unlock (one documented prompt, zero console input) → pinned-artifact rootfs populate (§3.3) → size budget + package count → disk-side scans → real-CLI `audit --init` baseline finalize (SB-state-guarded) → G-T13 prediction check → ESP-size assertion. Prints `RUNDIR <path>`. |
| `s00b-enroll-cache.sh` | §12 S-00b + S-01 (continues s00): in-guest production-CLI enroll (ensure-once), pristine-state cache with SHA manifest, then the zero-input `login:` happy path. Consumes `DEBIAN_FDE_S00_STATE` (set by run-e2e.sh when s00 ran in the same invocation), else the verified cache, else self-bootstraps. Prints `RUNDIR <path>` (the ENROLLED state consumed by s01/s05/s06/s07/s09/s12/s13/s18). |
| `s09-tpm-da-locked.sh` | §10 DA-locked row (G-T15): armed + enforced dictionary-attack lockout on swtpm; boots, refuses, bounded 3-strike fallback, clean poweroff; §7.1 budget-preservation asserted via the enforcement probe (see "Full-bootstrap wave" for the swtpm-leniency caveat). |
| `s18-foreign-pcrsig.sh` | §6.1 foreign-signer negative control (G-T5): correct pol entries, foreign signature → firmware boots (outer sig ours) → policy refuses → bounded fallback → poweroff (see "Full-bootstrap wave"). |
| `s19-bcache-crash.sh` | §10 cache-SSD-failure row + §12 S-19 (hybrid bcache crash consistency) on the Alpine contract: writethrough bcache stack laid in-guest, raw-offset rescue read on member loss (a CLEAN backing never fabricates a cache-less bcache0 — asserted), replacement-cache re-attach, production `alpine-fde finalize` (recovery-passphrase authorized, Mechanism B {PCR 7, PCR 11} token upgrade, ADR-18 release.pem), host `pcrsign` {7,11} re-sign over the rebuilt ESP, zero-input token unlock end-to-end. Pins `debian-fde-unlock=oracle`: the raw-backing topology cannot host the §8.2 hook's crypttab resolution (documented in the header). |
| `s20-raid1-member-loss.sh` | §10 RAID1 rows + §12 S-20: btrfs raid1 across two LUKS members; plain mount of a missing-member pool FAILS closed and `-o degraded` is the only rescue; production finalize upgrades BOTH members to the Mechanism B {7,11} token (recovery rekeyed to a §13-floored passphrase first — the Stage-1 stand-in); zero-input token unlock + non-degraded full-pool reassembly, canary intact. Pins `debian-fde-unlock=oracle` for the fed sessions (documented). |
| `s21-finalize-guard.sh` | §10 "first boot with Secure Boot OFF" + §12 S-21, ADR-20 AMENDED: an `installed`-state disk staged with the REAL advisory oneshot (`/etc/init.d/alpine-fde-finalize` + the rc-update `default` record — byte-for-byte the installer's Stage-1 step 7; NO systemd anywhere). Boot A (SB-off, fed boots ride the SHIPPED §8.2 hook unlock): the oneshot stays ADVISORY (rc 0 + the not-finalized warning + the SB-off reading), the service completion (fin_service_main) fails CONTAINED to the ADR-8 retry-next-boot marker — no baseline capture, no token upgrade, no state flip — and the guided `alpine-fde finalize` halts fail-closed (rc 64) at the fw_sb_state gate. Boot B (SB-on, positive control): the shared completion chain runs end-to-end (passphrase verify → release.pem ADR-18 → audit --init → {7,11} upgrade → ephemeral-purge crash-skip → MOTD banner stripped line-exactly → state `finalized` LAST); host asserts the token binds [7,11] on keyslot 1. |
| `s22-handoff-immunity.sh` | §12 S-22 + §2.1 T2c provisional-window rows, ADR-20 AMENDED: the window carries a REAL PCR-11-only provisional token beside recovery keyslot 0 (host-side `seal_provisional` + token commit — the installer's step-6 recipe against the fixture swtpm). Boot 1: recovery-at-keyslot-0 is the only way in from install. Boot 2: the STANDING signed UKI auto-unseals with ZERO console input. Host completion leg: the guided finalize drives the shared Stage-2==Stage-3 chain into the {7,11} binding (token on keyslot 1, I1 two-keyslot at-rest). Boot 3: a tampered-cmdline UKI is REFUSED (the PolicyPCR digest misses) → 3 wrong passphrases → 3-strike fail-closed, metadata untouched. |
| `s01-happy-lite.sh` | LITE tamper variant: boots the s00-enrolled disk under SB-OFF (stock) vars → PCR 7 drift → policy must refuse → fallback prompt → 3 wrong passphrases. Reuses s00 artifacts via `DEBIAN_FDE_E2E_STATE` (set by run-e2e.sh). |
| `s05-sb-off.sh` | §10 row "SB disabled": SB-off boot of the enrolled disk, PCR 7 drift asserted against the enrolled boot's console (and PCR 11 asserted UNCHANGED — the refusal is purely PCR 7), refused → retry cap → poweroff. |
| `s06-token-trap.sh` | §12 trap case / I3: SB-off vars + `tpm2_pubkey` swapped for a VALID foreign RSA key via host-side `cryptsetup token remove` + `token import` + otherwise-valid `.pcrsig` → unseal must STILL fail. |
| `s07-loader-options.sh` | §12 cmdline-tamper row (I5): a release-key-signed UKI VARIANT whose `.cmdline` carries one extra word is booted with the STALE (clean-cmdline) `.pcrsig` payload — the attacker's primitive, since the payload drive is unsigned on the wire. The stub measures the tampered effective cmdline into PCR 11 → the trial digest matches NO signed entry → refused. Guest `debian-fde-cmdline` prints (twice, printk-interleave-robust) prove the word reached the kernel. See the deviation note in the scenario header for why the literal loader-entry vector is not exercisable on trixie. |
| `s12-wrong-passphrase.sh` | §10 passphrase way out: token refused first (SB-off, PCR 7 drift, no key file), then the harness-only console passphrase loop reads 3 lines from `/dev/console` into plain `cryptsetup open --key-file` attaches. Boot A: 3 wrong → exhausted → poweroff. Boot B (recovery positive control): wrong, wrong, correct slot-0 passphrase → UNSEALED. |
| `s13-token-tamper.sh` | Token-tamper suite (I3), SB-enrolled vars, one boot per variant: `pubkey-swap` / `blob-corrupt` / `policy-corrupt` / `version-99` (unknown field) — each host-tampered via `cryptsetup token import`, each must fail closed. |
| `../lib/keys-fixture.sh` | Throwaway PK/KEK/db ceremony + offline OVMF var enrollment via `virt-fw-vars` (`keys_vars_enrolled/unenrolled/get/secureboot_on`). |
| `../lib/disk-fixture.sh` | Unprivileged file-backed LUKS2: `disk_make_luks` (slot 0 passphrase, CI-cheap argon2id), `disk_add_slot1`, `disk_metadata`, `disk_token_json`. |
| `../lib/rootfs-fixture.sh` | SHA256-pinned Debian trixie deb/tarball cache (`tests/.cache/`, 41 pins incl. the 257.13 systemd-cryptsetup, the sentinel-pinned artifacts, and the G-HW4/G-HW5 btrfs + udev suite: btrfs-progs, liblzo2, bcache-tools, udev, dmsetup). `rootfs_ensure/deb_extract/tarball_extract`. |
| `../lib/uki-build.sh` | Harness UKI builder: guest userspace tree from pinned debs (objdump NEEDED-walk closure gate), busybox `/init` (TPM wait, PCR print, **enter-initrd PCR 11 phase extension**, cmdline print, §S-00 `stage=install` passphrase-unlock + pinned-rootfs populate + §3.3 trims + in-guest key scan, §S-01 `stage=login` switch_root handoff, in-guest enroll, real 257.13 unlock, gated console-passphrase fallback loop, sentinels). G-HW3/G-HW5: the module closure now covers the btrfs-default matrix (btrfs + zstd/xor/raid6_pq deps + bcache, dependency-ordered for the bare-insmod loop) and the initrd carries the §9.1 Btrfs installer pieces (mkfs.btrfs + `btrfs`) plus the udev pieces (systemd-udevd/udevadm + 55-dm.rules — the LUKS attach must be udev-registered for the fstab UUID= submounts to resolve; see the G-HW5 wave note above), ukify PCR-signing (`.pcrsig`/`.pcrpkey`; optional extra-cmdline args for signed UKI variants), sbsign, `.pcrsig` JSON → raw payload drive (`/dev/vdc`), `rootfs_payload_image` (deterministic root-tree payload derived from the pinned cloud image — see its header), plus `vars_set_boot_entry_optdata` (virt-fw-vars-based firmware boot-entry editing, kept for future loader-tamper work) and the G-T13 policy-digest helpers. |
| `../lib/qemu.sh` | q35 + OVMF secboot (per-scenario VARS copy) + swtpm passthrough (`-tpmdev emulator` on the swtpm **ctrl** socket) + serial chardev socket with full console logfile. Drive contract (G-HW1): vda=ESP, vdb=LUKS disk, vdc=pcrsig payload, vdd… = the opt-in 7th `qemu_run` argument (newline-separated images appended as virtio drives in list order; `qemu_argv` is the pure-argv seam the unit smoke pins — every current caller passes ≤6 positional args). Hard timeout, PID file. |
| `../lib/serial.py` / `serial.sh` | stdlib-only serial-socket client (`read_until`, `write_line`, `drain`). No pexpect/expect on this sandbox. |
| `../unit/e2e_infra_smoke.sh` | Host-side harness self-test (keys roundtrip, disk fixture, full UKI build + section/pcrsig assertions, serial loopback, rootfs pins, registry completeness). Runs as part of `tests/run-unit.sh`. |

## Verification status (all green unless noted)

Verified by direct execution, 2026-09-14:

- **env-check**: all prerequisites present (incl. `virt-fw-vars`, `mkfs.vfat`,
  `mcopy`, OVMF secboot firmware).
- **keys-fixture**: `keys_create` + `keys_vars_enrolled` → `virt-fw-vars
  --print` shows `PK`/`KEK`/`db`/`dbx` blobs and `SecureBootEnable : ON`;
  unenrolled vars show none (rc=1 from `keys_vars_get`).
- **disk-fixture**: LUKS2 on a plain file, argon2id, slot 0 + slot 1, JSON
  metadata readable unprivileged. Covered by `e2e_infra_smoke.sh` assertions.
- **rootfs-fixture**: cache warm (423 MiB); `rootfs_ensure_all` hash-verifies
  all 37 pins.
- **uki-build**: full pipeline runs; `objdump -h` shows `.linux/.initrd/
  .cmdline/.osrel/.sbat/.pcrpkey/.pcrsig`; `.pcrsig` JSON carries 4 entries
  (ukify 261 default 4-phase ladder), `sbverify` validates the release-cert
  signature. Guest closure gate passes.
- **qemu.sh + serial**: s00-lite boots to `debian-fde-harness: init started` …
  clean poweroff in ~134 s TCG wall time; console fully captured to
  `<rundir>/console.log`; PCR 0/7/11 all print (after the PCR-parse fix, see
  below); OVMF+TPM passthrough works; the `cryptenroll_enrolled` sentinel
  (`New TPM2 token enrolled as key slot %i.`, observed with %i = 1) —
  **in-guest enrollment (Mechanism A″) works live**.
- **Unit suite**: `tests/run-unit.sh` → **616 pass / 0 fail** (includes
  `e2e_infra_smoke.sh`).
- **run-e2e.sh**: env gate, registry, selection, results JSON, exit codes —
  `run-e2e.sh s00 s01` → both pass (s00 148 s, s01 109 s TCG; aggregated JSON
  in `.runs/results-*.json`).
- **s00-lite assertions**: **16/16 pass** — including the STRONG tier:
  `.pcrsig` consumed by the real 257.13 cryptsetup, `Volume root activated
  with a LUKS token.`, `debian-fde: UNSEALED`, clean poweroff.
- **s01-lite assertions**: **11/11 pass** — SB-off boot: TPM2 unseal refused
  (PCR 7 drift), retry cap reached, interactive prompt never appears, never
  unlocked, clean poweroff.
- **s05-lite (Wave 3)**: **18/18 pass** — SB-off boot of the enrolled disk;
  PCR 7 drift asserted against the enrolled boot's console while PCR 11 is
  asserted UNCHANGED (the refusal is purely PCR 7); refused → retry cap →
  poweroff; no prompt, no emergency shell.
- **s06-lite (Wave 3)**: **13/13 pass** — the §12 trap: SB-off vars + the
  token's `tpm2_pubkey` swapped for a VALID foreign RSA key (host-side
  `cryptsetup token remove` + `token import`; re-export proves only the
  pubkey moved) + otherwise-valid `.pcrsig` → unseal refused, fail closed.
- **s07-lite (Wave 3)**: **15/15 pass** — release-key-signed UKI variant with
  one extra cmdline word + the STALE (clean-cmdline) `.pcrsig` payload:
  `debian-fde-cmdline` shows the tamper word reached the kernel, PCR 11
  drifted, the trial digest matched NO signed entry (the `pcr_sig_missing`
  sentinel), refused → poweroff. Host-side assertions prove the shipped
  `.pcrsig` is the stale one (pol divergence).
- **s12-lite (Wave 3)**: **31/31 pass** — boot A: token attempted FIRST and
  refused (line-order asserted), console fallback reads 3 fed lines (each
  `read done rc=0 len=27`, tty echo visible), cryptsetup rejects each
  (the `cryptsetup_nokey` sentinel, rc=2), exhausted →
  PROMPT-FAILED → poweroff. Boot B (recovery positive): wrong, wrong,
  correct slot-0 passphrase → the passphrase slot UNSEALS the volume.
- **s13-lite (Wave 3)**: **45/45 pass** — `pubkey-swap` / `blob-corrupt` /
  `policy-corrupt` all fail closed (refused, never unlocked, clean
  poweroff); `version-99` documented as INERT (unlock unchanged — 257.13's
  token validate has no version check; deviation pinned in the scenario
  header).

### Fixed during the completion pass

- **PCR print parser** (`uki-build.sh` `/init`): `tpm2_pcrread` aligns the
  colon by index width — `  0 : 0x…` (single-digit, colon is a separate
  field) vs ` 11: 0x…` (two-digit, colon glued to the index). The old parser
  handled only one shape → the PCR 11 line printed EMPTY. The new parser is
  format-agnostic (strip colons, scan fields for the index, take the first
  64-hex field after it; handles the `0x` prefix; busybox-awk-safe). Note:
  `awk split()` with a regex separator keeps a leading EMPTY field when the
  line starts with whitespace — field[1] is not reliably the index.
- **Wave-2 diagnostics baked into `/init`** (kept: still the assertion
  surface): `ls -la /pcrsig.json` at unlock time + `SYSTEMD_LOG_LEVEL=debug`
  on the `systemd-cryptsetup attach` call — several sentinels
  (`pcr_sig_added`, `unlocked`, `tpm2_refused`) are `log_debug`-level and
  invisible without it.
- Busybox note: Debian's busybox-static ash runs applets standalone (works
  even with `PATH=/nonexistent`), so bare `head`/`sync`/`ls`/`wc` in `/init`
  resolve without per-applet symlinks.

## The Wave-2 unlock failures — ROOT-CAUSED AND RESOLVED (2026-09-14)

Evidence for the history below:
`tests/e2e/.runs/s00-lite-1789351958/console.log` (instrumented rerun),
`tests/e2e/.runs/s00-lite-1789319655/` (preserved original failure) and the
converging runs `s00-lite-1789358395/1789358691/1789359060` +
`s01-lite-1789358875/1789359208`.

### Root cause of the signature↔policy mismatch — the missing `enter-initrd` PHASE WORD

The `.pcrsig` was correct all along, and there is **no 257↔261 skew**: the
trixie 257.13 `systemd-measure` (extracted from the pinned deb, run on the
host against the guest tree) and the host 261 binary predict **bit-identically**
for identical inputs. The mismatch decomposes exactly:

1. ukify's phase `enter-initrd` prediction = the sd-stub's PCR 11 section
   extends **PLUS the phase word**: `pcr11 += H(H("enter-initrd"))`. A
   production initrd performs precisely that extension via
   `systemd-pcrextend enter-initrd` (257 `systemd-pcrphase-initrd.service`,
   `Before=cryptsetup.target`) before unlocking. The busybox harness initrd
   never did — so the observed PCR 11 (section chain only) could never match
   any signed `pol`.
2. The consumer's value is a pure TPM calculation, calibrated against swtpm
   and confirmed against the live guest:
   `policyDigest = SHA256(zero32 ‖ BE32(TPM_CC_PolicyPCR = 0x17F) ‖
   BE-marshaled TPML_PCR_SELECTION{sha256, pcr 11 → pcrSelect bytes
   00 08 00} ‖ SHA256(pcrValue))` (reference implementation:
   TPM2_PolicyPCR in libtpms `src/tpm2/TPMCmd/tpm/src/command/EA/PolicyPCR.c`).
   The guest session digest `4106fea1…` = this formula over the phase-less
   PCR value; the signed entry `pol = ba71967e…` = the same formula over the
   predicted (phase-included) value. `find_signature()` (257.13
   tpm2-util.c) compares entry `pol` to the session digest — the ONLY
   difference was the missing phase word.
3. 257.13's unlock flow (`tpm2_build_sealing_policy`) applies the signed
   PolicyPCR over `pubkey_pcr_mask` (PCR 11) **only**, and the static PCR 7
   term separately afterwards — the A″ construction composes as documented.
   The `pol` match at unlock depends on nothing but the observed PCR 11 +
   the `.pcrsig`; enrollment pins nothing about PCR 11 (PolicyAuthorize
   pivots on the release keyName).

Empirical cross-check (run `s00-lite-1789358691`): in-guest PCR 11 printed
`6eeb57c1…` (sections only), `pcrextend ok` → `8e6fd90d…` (post-phase);
formula over `8e6fd90d…` = `aafbc3cf…` = the session policy digest the guest
printed = the signed entry's `pol`. Unseal completed ("Completed TPM2 key
unsealing in 802 ms"), the `unlocked` sentinel (`Volume … activated with a
LUKS token.`, table key `unlocked`),
`debian-fde: UNSEALED`.

For completeness, the PCR 11 section-chain model that both measure versions
implement (and the sd-stub executes, in `unified_sections[]` enumeration
order, `.pcrsig` excluded): per present section, extend with
`SHA256(section-name ‖ NUL)` then `SHA256(section data, VirtualSize bytes
read at file offset)` — verified to reproduce the observed pre-phase value
bit-exactly by simulating the PE section table of the preserved UKI.

### Fixes implemented (all in tests/lib/uki-build.sh)

1. **`/init` extends PCR 11 with the enter-initrd phase word before the
   unlock** — primary: the real 257.13 `systemd-pcrextend enter-initrd` (from
   the pinned `systemd` deb, now part of the guest tree). It needs
   **efivarfs** (new module in `UKI_MODULES` + mount): without it the tool
   cannot see the stub's `StubPcrKernelImage` EFI variable, logs "Kernel stub
   did not measure kernel image into PCR 11, skipping userspace measurement,
   too." and exits 0 WITHOUT extending. The harness verifies the extend by
   VALUE (pre/post PCR comparison) and falls back to
   `tpm2_pcrextend 11:sha256=H("enter-initrd")` (host closure under
   `/opt/tpm`) — identical extend value, the PCR does not care which tool
   computed it. New assertion surface: `debian-fde-pcr-postphase sha256:11=…`.
2. **The signature is ALSO installed as `/etc/systemd/tpm2-pcr-signature.json`**
   (`CONF_PATHS("systemd")` + default name — the dracut/trixie initrd
   pattern): the cryptsetup-tokens plugin still receives
   `signature_path = NULL` (the `tpm2-signature=` usrdata bug on
   257.13 + libcryptsetup 2.7.5 persists), but now finds the signature at the
    default location and takes the **sanctioned plugin activation path** —
    which is what prints the `unlocked` sentinel (table key `unlocked`; the
    underlying `log_debug` printf `Volume %s activated with a LUKS token.`
    lives in the plugin branch of the 257.13 tries loop). The internal
    fallback retry (`tpm2-signature=/pcrsig.json`, table key `pcr_sig_added`)
    remains as the safety net.
3. **Never pass a key file in the attach position alongside the token**: in
   257.13, `attach NAME DEVICE KEY-FILE OPTIONS` with a non-empty key file
   DISPLACES the token path entirely — `acquire_tpm2_key` is then called with
   hardcoded defaults (no signature, no SRK, no bank:
   `cryptsetup.c` attach_luks_or_plain_or_bitlk_by_tpm2), which produced a
   best-bank scan + legacy-primary creation and a **segfault inside
   `tpm2_unseal`** (observed at offset `+0x1a46de` in
   libsystemd-shared-257.so) on token-sealed volumes. The unlock line is
   `attach root $DISK "" tpm2-device=auto,tpm2-signature=/pcrsig.json,tries=1`.

### Fallback feeding (s01 design; superseded for feeding by the s12 console loop)

(s01 keeps the deterministic `tries=1` lockout.) The interactive prompt cannot
be used in this initrd and serial-fed input is NOT consumed by systemd:
`ask_password_auto()` needs either the ask-password agent socket (absent → the
historical `Failed to query password: No such file or directory`) or
`isatty(STDIN)` + a controlling TTY for `ask_password_tty` (/dev/console via
devtmpfs is not enough; /dev/tty has no controlling terminal in a raw initrd).
Since a key file would displace the token (fix 3), s01 runs the unlock with
`tries=1`: the single token attempt is REFUSED (SB-off → PCR 7 drift → the
static `PolicyPCR(7)` term of the sealed object no longer matches; console:
the `tpm2_refused` sentinel) → the `retry_cap` sentinel →
`debian-fde: PROMPT-FAILED` → clean poweroff.

**s12's harness-only console passphrase loop** (gated behind the
`debian-fde-console-fallback` cmdline word on a signed UKI variant): after a
REFUSED token attempt, `/init` reads up to 3 lines from `/dev/console`
(busybox `read -t 20 -r`; the kernel console comes up canonical+echo, ICRNL
folds the serial NL, so no `stty` repair is needed — nothing in this initrd
puts the console in raw mode — and the tty echo doubles as console evidence)
and feeds each line to a PLAIN `cryptsetup open --type luks --key-file`
attach with NO `tpm2-device=` (passphrase attempts never touch the token
path). Production instead runs `systemd-tty-ask-password-agent` inside the
dracut initramfs (dracut ships it) — the loop is a harness equivalent, not a
production pattern. Boot B of s12 proves the positive direction (2 wrong +
the correct slot-0 passphrase → UNSEALED), closing the §10 passphrase
recovery way out end-to-end.

### Loader-level cmdline injection on trixie — empirically dead ends (Wave 3, s07)

Six instrumented boots pinned WHY the literal "tampered loader-entry options"
vector cannot be exercised on this stack (each observed live, not inferred):

- **sd-boot type1 entry `options` are dropped for UKI entries**: trixie
  sd-boot 257.13 recognizes and boots a `loader/entries/*.conf` entry whose
  `linux` line points at a UKI (menu shows it, boots after timeout), but the
  stub logs `EFI stub: command line: <embedded cmdline only>` — the options
  never reach the image.
- **Debian's sd-boot build has no `\EFI\Linux` UKI auto-entry scan**: the
  binary contains no such path string (checked UTF-16); UKIs placed there are
  invisible to it.
- **Firmware `Boot####` OptionalData is dropped**: a full-device-path boot
  entry with OptionalData (built via virt-fw-vars' python API; short-form
  entries get expanded by OVMF's BDS, losing OptionalData) boots the UKI, but
  the stub ignores the LoadOptions — with Secure Boot ON *and* OFF.
- **UKI addons are not picked up by this stub build**: signed addons (ukify
  `-stub=addonx64.efi.stub`, sbsigned with db) placed in `\EFI\BOOT\
  BOOTX64.addon.efi` and `\loader\addons` were both ignored. A raw objcopy
  `--add-section .cmdline` build is additionally ignored due to section
  placement ("section below image base") — use ukify for addon PEs.

Consequence: any cmdline that actually reaches the kernel through this stack
is either the signed one inside a UKI, or one a compromised signer shipped —
and systemd-stub measures the effective cmdline into PCR 11 either way, so
s07 exercises the invariant with a signed tampered-cmdline UKI + stale
`.pcrsig` (fail closed). Related: the s12 console loop's plain
`cryptsetup open --key-file` attempts also probe the TPM2 keyslot through the
token plugin (as a PIN attempt — properly refused, no segfault; the 257.13
segfault hazard is specific to the attach-position key file WITH
`tpm2-device=` options).

### Sentinel table changes (tests/sentinels-257.13.txt)

- `token_discovered` re-pinned to `Requesting JSON for token 0.` (observed in
  every run; the previously pinned "Automatically discovered security TPM2
  token unlocks volume." exists in libsystemd-shared but is never printed by
  257.13's attach flow with `tpm2-device=auto`).
- `tpm2_refused` added: `Failed to unseal secret using TPM2`.
- `pcr_sig_added` (`Adding PCR signature policy.`) and the `unlocked`
  literal are `log_debug`-level — the harness keeps `SYSTEMD_LOG_LEVEL=debug`
  on the attach call so the assertion surface stays available.

### §6.1 ladder verdict

**Mechanism A″ PROVEN** (guest-side enrollment + signed-11 policy unlock +
tamper refusal + lockout). Signer↔consumer version skew is a non-issue for
the PCR-11 model (257 ≡ 261, bit-exact); production keeps signing on-target
per §6.1.1 (the PCR-11-only signing limitation stands).

### Non-issues (verified so Wave 2 doesn't chase them)

- **tpmrm0 udev**: not needed. `/dev/tpmrm0` appears via devtmpfs alone (no
  udevd in the initrd); both tpm2-tools (`-T device:/dev/tpmrm0`) and
  systemd's TCTI (`Using TPM2 TCTI driver 'device' with device
  '/dev/tpmrm0'.`) work.
- **QEMU↔swtpm wiring**: the tpmdev-emulator chardev must point at the swtpm
  **ctrl** socket (`<state-dir>/sock.ctrl`) — verified; pointing it at the
  server socket deadlocks the firmware before any console output.
- **Enrollment in-guest** (Mechanism A″ with live PCRs): works end to end
  (`cryptenroll_enrolled` sentinel; token on disk shows
  `tpm2-pcrs:[7]`, `tpm2_pubkey_pcrs:[11]`, `tpm2_pubkey`, `tpm2-policy-hash`).

## Scenario registry

`tests/run-e2e.sh` maps `s00, s00b, s01..s17` (the §10/§12 matrix — the
letter-suffixed `s00b` continues S-00 and does not inflate the literal
18-row table the infra smoke pins) plus `s18` (a §6.1 extension row,
appended at runtime). W2b will append the s19–s22 multi-drive rows (§10
BASE matrix) to the literal table; the infra smoke's count pin went dynamic
for that (per-id §10/§12 coverage + no-duplicates + an 18-row floor), so
the appended rows keep the smoke green. Registration is by FILENAME
CONVENTION: an id is
runnable iff `tests/e2e/s<nn>[b]-*.sh` matches (glob, lowest name wins); a
REGISTERED id with no file is a FAILURE (`missing`), never a pending pass —
a run with zero scenarios executed is also a failure. The literal table in
`run-e2e.sh` (grep'd by `tests/unit/e2e_infra_smoke.sh`) keeps one row per
matrix id with the current script name as documentation. Scenario scripts
that consume the ENROLLED s00b artifacts (`s01 s05 s06 s07 s09 s12 s13
s18`) honor `DEBIAN_FDE_E2E_STATE`; **each snapshots the shared state into
its own run dir at start** and keeps the dir's mtime fresh — sibling
scenarios prune `.runs` to the 2 newest dirs globally (never the dirs listed
in `DEBIAN_FDE_PROTECT_DIRS`, which `run-e2e.sh` exports for the state dirs
its own invocation chains on), and a mid-boot prune
of the shared state dir or of an actively-written run dir otherwise unlinks
`console.log` mid-boot (observed live 2026-09-14, s07 first attempt).
Artifacts per run live in `e2e/.runs/<scenario>-<ts>/` (gitignored):
console.log, qemu.{stdout,stderr}, vars, keys, disk.img, UKI, swtpm state.
Keep big artifacts out of git and out of the repo root. Under a parallel
`-j` invocation the runner protects ALL existing `.runs` dirs from these
prunes for the whole run (via the same `DEBIAN_FDE_PROTECT_DIRS` filter) —
a peer's rundir is never pruned mid-run; see tests/README.md.

## Results provenance (assembly convention)

Every run writes its own `e2e/.runs/results-<ts>.json` (one row per executed
scenario: `id` / `status` / `seconds`; a `status` of `timeout` means the
per-scenario wall budget killed it). The tracked `results-final.json` is an
ASSEMBLY of those artifacts, not one run's output — its top-level
`rows_recorded` counts the rows in the file (never "scenarios executed in one
invocation"), and each row carries its real provenance: `observed` when that
scenario was executed in a tracked run, `pinned_from` when the row was carried
over unchanged from an earlier verified run. A row with `pinned_from` is a
pinned historical status, not a fresh measurement.

## W2b multi-drive rows (s19–s22) — validation fidelity notes

Validated green under TCG against the PRIOR (Debian-era) contract: s20
2026-09-19 (54 asserts, wall 912 s), s19 2026-09-20 (43 asserts, wall 992 s;
first-ever validation), s21/s22 in the prior same-day pass (28/30 asserts).
The 2026-09-21 Alpine-contract migration (s19/s20 path re-pin + the documented
`debian-fde-unlock=oracle` pin; s21 re-written to the amended ADR-20 semantics
— advisory oneshot + contained service failure + fail-closed SB gate; s22
re-written to the amended T2c provisional-window shape with a real PCR-11
token) is static-verified (`bash -n`, product-message cross-checks against
lib/cmd/finalize.sh, seal.sh, token.sh, install-state.sh, hooks/openrc/
alpine-fde-finalize, hooks/mkinitfs/alpine-fde-unseal.sh) and PENDING the
consolidated QEMU re-run. The validation surfaced these kernel/tooling
realities the scenarios encode (all documented in the scenario headers, none
silent):

- **§8.4 state gate is real** (both s19/s20): `finalize` without
  `<root>/etc/alpine-fde/install-state.json` is a LOUD NO-OP (rc 0, "nothing
  to finalize") — the scenarios stage the state doc at `installed` in the
  tooling tail; the `finalized` write stays scenario-ephemeral in-guest.
  `sp_etc_dir` resolves `<root>/etc/alpine-fde/` with NO legacy fallback
  (lib/baseline.sh), so the host-side baseline stub must live THERE (the
  retired `/etc/debian-fde` path is denied by tests/unit/residue_guard.sh in
  shipped paths).
- **Mechanism B entry shape** (s20/s21/s22): finalize upgrades tokens via
  `seal_upgrade_token` and NEVER invokes cryptenroll; members enter finalize
  with ZERO standing tokens (s20: both members; s21/s22: the handoff shape),
  so the upgrade takes the first-seal branch exactly once per member, and the
  fixture's well-known slot-0 passphrase is §13-floor-BLOCKLISTED — the
  scenarios rekey keyslot 0 in-guest (cryptsetup luksChangeKey) to a floored
  recovery passphrase first, the Stage-1 credential-ceremony stand-in.
- **bcache recovery is raw-offset, not standalone-bcache0** (s19): a CLEAN
  backing device never runs without its cache set (register_bdev runs
  NONE/STALE only — asserted as a fail-closed negative), the registered
  member is held exclusively (foreign dm tables get EBUSY — release it
  with `bcache/stop` first), and the cache partition must exceed the
  kernel's `nbuckets > 512` floor (512 MiB at make-bcache's 512 KiB
  default bucket). Replacement-cache re-attach goes through the pending
  device's own kobject: `/sys/block/vdb/vdb1/bcache/attach` (bcache0 does
  not exist until the attach lands). TCG's 16550 emulation can
  drop/duplicate console bytes under printk load, so sentinel waits
  re-derive from live guest state instead of replaying markers, and fed
  markers stay arithmetic (`$((..))`) so the tty echo can never satisfy a
  wait.
- **Fed sessions and the §8.2 hook** (s21/s22, post-wave-0): the shipped
  hook is the unlock of record and its bounded recovery loop feeds
  prompt-synchronized via `uki_wait_hook_prompt` (the hook's read has NO
  timeout); s19/s20's multi-command fed sessions instead pin the opt-in
  `debian-fde-unlock=oracle` unlock, whose console-fallback + DEBUG SHELL
  seams they were built on (documented in both headers).

## Remaining gaps / follow-ups

- **Pinned 2026-09-14 statuses pending a full-matrix re-run**: s01–s08,
  s10–s13, s17 carry their 2026-09-14 pinned statuses (`pinned_from` in
  `results-final.json`); wave 3b (2026-09-18) re-observed only s00, s00b,
  s14, s15, s16. The W2b multi-drive rows s19–s22 are validated as of
  2026-09-19/20 against the prior contract (see the W2b section above and
  `results-final.json`); the 2026-09-21 Alpine-contract migration of all four
  rows awaits the consolidated re-run.
- **s18 sentinel-table follow-up (deb byte-check)**: the foreign-signer
  refusal logs `Failed to validate signature in TPM` — a refusal class
  distinct from the stale-pol `pcr_sig_missing` shape — which needs a
  dedicated table key byte-checked against the pinned 257.13 debs. The
  table is not scenario-owned; until then s18 records the observation in a
  comment and never inlines the string.
- **Done in the full-bootstrap wave**: dictionary-attack lockout (s09),
  the foreign-signer signing negative control (s18), the S-00/S-00b split
  with in-guest enrollment + pristine cache, the §3.3 budget + G-T13
  prediction checks + ESP-size assertions (s00/s00b), the
  build-failed-but-still-boots row (s14), and the efivars SB-state guard
  fixtures for the Wave-1 baseline finalize (s00/s15/s16).
- **Full S-02+ matrix** (§10/§12): dbx rotation + re-baseline-after-reboot,
  PCR 7 re-enrollment drill, rollback to retained UKIs, missing/absent TPM
  (s10/s17 cover these — rewritten as full scenarios in wave 1, not LITE
  stand-ins).
- **H-G7 kernel-update-without-re-enroll**: covered by `s14` (build 6.2.0 →
  enroll once → 6.4.0 with ZERO TPM operations → old default survives a
  failed keyless rebuild → boots + auto-unlocks).
- **Later phase entries of the `.pcrsig` ladder**: only the `enter-initrd`
  entry is consumed at unlock; `leave-initrd`/`sysinit`/`ready` pols become
  relevant when scenarios boot the full rootfs (production pcrphase extends
  at those transitions).
- pcrlock sharding (`n_shards = 2`) path is untested (no pcrlock token).
- The plugin `tpm2-signature=` usrdata bug is worked around, not fixed: if a
  future systemd/libcryptsetup pair fixes the plumbing, the explicit
  `/pcrsig.json` path remains authoritative and `/etc/systemd/
  tpm2-pcr-signature.json` is simply redundant.
- The `systemd-boot-efi` deb (addonx64 stub source) is fetched + hash-pinned
  inside `tests/lib/uki-build.sh`, NOT in rootfs-fixture.sh's pin table (it
  is not a guest-tree component). If rootfs-fixture gains generic pin
  support, move it there.
- The rootfs payload derivation (`rootfs_payload_image`) is documented and
  deterministic but its SWTPM/QEMU timing under the s00 installer boot
  (untar of the ~670 MiB tree under TCG) needs CI-grade soak: the
  QEMU_TIMEOUT for s00 defaults to 1200 s for this reason (the btrfs-default
  scan varies ~±40% between runs; 900 s was exceeded once — see the s00
  timeout comment).

## Budget / accelerator

The accelerator is autodetected (`DEBIAN_FDE_ACCEL=kvm|tcg|auto`, default
auto — see tests/README.md "Runner contract details"): on a host with a
working `/dev/kvm` every guest boots under KVM; otherwise TCG exactly as
before. Every run logs the choice once (`qemu-accel: using <accel> …`) and
records it in the results JSON (`"accel"`). The two accelerators are NOT
comparable numerically — all wall times below are TCG numbers, and any
expectation-setting should name the accelerator it was measured under.

TCG reference (this sandbox, no `/dev/kvm`): one s00 full bootstrap (payload
build + UKI build + installer boot + asserts) ≈ 870 s; one s00b fresh chain
(boot B enroll + boot C login) ≈ 2060 s; a from-cache s00b (boot C only)
boot ≈ 265 s + UKI build; s01 ≈ 300 s. Hard timeouts: s00
`QEMU_TIMEOUT=1200`, s00b `QEMU_TIMEOUT=1800`. Scenario scripts must always
hard-timeout and always leave a run dir for post-mortem.
Parallel `-j` runs shrink WALL time but each concurrent guest runs slower
than solo (shared cores); per-scenario `seconds` under `-j` therefore reads
higher than the solo baseline — compare walls, not per-row seconds, across
different `-j`.
