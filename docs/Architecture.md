# Debian FDE — TPM 2.0-Backed Verified Boot & Disk Encryption

**Platform:** Debian 13 "trixie" (x86_64, systemd) · **Status:** revision B — approved design; **implementation in progress** (unit suite: 1095 assertions green at commit aa6cdd8; e2e: 17/17 pass on the pinned run of 2026-09-14, `tests/e2e/results-final.json` — scenario rework in flight)

Debian FDE makes a Linux machine that protects its data against physical theft:

1. **The root filesystem is fully encrypted** (LUKS2) and **minimal** (§3.3).
2. **The key unseals automatically in the initramfs — but only if the boot process verifies as untampered** (Secure Boot + measured kernel, enforced by a TPM 2.0 signed-PCR policy).
3. **Booting requires no password** in the happy path.

Revision B note: the original design targeted Alpine Linux with fully custom enrollment + initramfs tooling. It was revised to Debian to adopt the maintained `systemd-cryptenroll` / `systemd-cryptsetup` unlock path (same security semantics, battle-tested code) — see ADR-1. Debian FDE remains the glue Debian lacks out of the box: the signing ceremony, minimal-image installer, firmware key provisioning, manifest/token lifecycle, and the audit + recovery tooling.

---

## 1. Goals

- G1 — Root (and therefore `/home`) at rest on a LUKS2 volume; no plaintext secrets on unencrypted storage.
- G2 — Automatic unseal at boot; no interactive prompt unless verification fails.
- G3 — "Verified" is *enforced*: an evil maid cannot boot a modified OS and still get the key.
- G4 — Kernel updates and rollback boots remain passwordless (no re-seal of existing enrollments, no passphrase).
- G5 — One clearly documented recovery path when verification fails.
- G6 — Everything reproducible in CI with a software TPM.
- G7 — The installed system is **minimal** (§3.3): only what boot, unlock, audit, and admin need.

## 2. Threat model

### 2.1 In scope

| Threat | Mitigation |
|---|---|
| **T1 — Offline theft**: machine stolen powered off (suspended: RAM-extraction attacks remain out of scope, §2.2) | LUKS2 + key material sealed to this TPM; unsealed only after verified boot, in RAM only from then on |
| **T2 — Evil maid**: brief physical access; boots USB/modified boot files to install a backdoored kernel, then steals the machine | Firmware (Secure Boot, custom keys) refuses unsigned bootloaders/kernels; TPM policy (PCR 7 bound + release-key-authorized PCR 11) refuses to unseal otherwise. Two independent mechanisms |
| **T2b — Brute force** | Sealed blob and volume key are high-entropy and unguessable; the one guessable secret is the keyslot-0 passphrase. `install` enforces a passphrase entropy floor + Argon2id KDF (§3.3, §13); systemd's passphrase prompt retries are bounded before boot fails. Note: TPM dictionary-attack lockout does **not** increment on policy-session failures (only authValue failures) — it's an availability consideration, not a confidentiality control |

### 2.2 Out of scope (non-goals)

- Malicious or reflashed **firmware** (SMM implants, SPI-flash reflash, Boot Guard defeat). The UEFI firmware is this design's **trust anchor, not a verified component** — nothing user-installable can verify it. Detection is partially possible (see `audit`, §9.5); prevention is the OEM's fused hardware (Intel Boot Guard / AMD PSP), outside user control.
- Cold-boot / RAM extraction, DMA attacks, hardware implants/loggers.
- **Hibernation** (a hibernate image is unencrypted volume-key state on disk). Swap is RAM-only (zram); suspend-to-RAM is fine.
- Multi-disk / RAID / dual-boot-with-other-OS setups.

## 3. Platform baseline (Debian 13 "trixie")

### 3.1 Package dependencies

Verified present in the trixie `main` component (Packages/Contents indexes checked at revision time):

| Purpose | Debian package | Note |
|---|---|---|
| systemd init, journal, networkd/resolved, getty | `systemd` | base |
| LUKS2 unlock (initramfs + running system) and **`systemd-cryptenroll`** | `systemd-cryptsetup` | cryptenroll ships here (verified via Contents) |
| Boot manager + `bootctl` | `systemd-boot`, `systemd-boot-tools` | both in main |
| UKI assembly + PCR measurement/signing | `systemd-ukify` | `ukify`, includes measure support |
| Initramfs generator | `dracut` | hostonly mode (§8.2) |
| Kernel | `linux-image-amd64` | cloud variant `linux-image-cloud-amd64` is a smaller option **only if** its config has TCG_TIS/TPM built in — verify before adopting |
| TPM audit/ceremony ops | `tpm2-tools` | pulls TSS libs; host-side and in-guest |
| EFI binary signing | `sbsigntool` | `sbctl` is **not** in Debian main — key handling via our openssl-based scripts |
| Firmware key enrollment fallback | `efitools` | KeyTool, for machines whose setup UI can't enroll db entries; **verify presence in trixie at implementation** (efitools has churned in Debian) — else firmware-UI-only, documented |
| Minimal rootfs bootstrap | `debootstrap` | `--variant=minbase`; `mmdebstrap` exists as an unprivileged alternative (§3.3) |
| Swap on zram | `zram-tools` | hibernation unsupported (§2.2) |
| Admin | `sudo`, `openssh-server` (optional) | the one interactive service |

CI **host** (test sandbox, Arch Linux) additionally uses: `qemu-system-x86_64`, `edk2-ovmf`, `swtpm`, `tpm2-tools`, `sbsigntools`, `virt-firmware` (offline OVMF vars enrollment), `dosfstools`+`mtools` (ESP image tooling, no root needed), `jq`, `python3`.

Version-pin policy: fixture artifacts (rootfs tarball, OVMF binaries) are SHA256-pinned in the harness; doc-cited versions may drift — the harness, not this doc, is the pin of record.

### 3.2 Why not clevis / why systemd-cryptenroll

Debian ships clevis, but its `tpm2` pin supports only *static PCR digest* policies — it cannot express the **signed PCR policy** this design requires (§6), and it would re-introduce a custom JWE token format. `systemd-cryptenroll` + `systemd-cryptsetup` implement exactly the required semantics natively: signed PCR policies (`--tpm2-public-key` / `--tpm2-signature`), `systemd-tpm2` LUKS2 tokens, initramfs unlock with passphrase fallback. Adopting them deletes the riskiest custom code (an initramfs unlock script) in exchange for systemd's battle-tested path (ADR-1).

### 3.3 Minimal root filesystem composition

The installed system is deliberately minimal — only what boot, unlock, audit, and administration require:

- **Bootstrap:** `debootstrap --variant=minbase trixie <mnt> http://deb.debian.org/debian` onto the mounted LUKS2 root. minbase installs only `Priority: required` (apt, dpkg, coreutils, systemd, libc, …).
- **Apt policy** (written by `install` before first apt use): `APT::Install-Recommends "false"`, `APT::Install-Suggests "false"`, `Acquire::Languages "none"`; sources include `main` + `non-free-firmware` (microcode). Optional trims recorded in the image config: `path-exclude=/usr/share/doc/*`, man pages, non-C.UTF-8 locales.
- **Explicit additions** (all `--no-install-recommends`, installed in one transaction so `linux-image-amd64`'s `linux-initramfs-tool` dependency resolves to **dracut**, not initramfs-tools): the §3.1 boot/unlock/audit set (`systemd-cryptsetup`, `systemd-boot`, `systemd-boot-tools`, `systemd-ukify`, `dracut`, `linux-image-amd64`, `tpm2-tools`), **plus the tools our own flows need on-target**: `cryptsetup` (CLI: `luksAddKey`/`luksKillSlot`/`luksDump` for enroll/rotate/status), `sbsigntool` + `openssl` (UKI/boot-manager signing + pcrsign helpers — without these every kernel update fails loudly, ADR-8), `zram-tools`, `jq` (dependency of the `debian-fde` CLI itself — manifest/enrollment JSON bookkeeping; the `/opt/debian-fde` tooling copy must be runnable in-guest for §9.1's enroll-from-the-booted-system path; ~1 MB installed), `sudo`, and optionally `openssh-server`. CPU microcode (`intel-microcode` / `amd64-microcode`) is included — security-relevant. `systemd-ukify`'s signing dependencies are `Depends`-verified at implementation (no-recommends must not break them).
- **Explicit exclusions:** no bootloader packages (firmware → systemd-boot → UKI; no GRUB, no shim — our own db key signs the boot manager), no editor, no cron (systemd timers), no rsyslog (journald), no ifupdown (systemd-networkd + resolved), no man/docs/locales beyond C.UTF-8.
- **What must NOT be cut:** `systemd-cryptsetup`, `cryptsetup`, `tpm2-tools`, `sbsigntool`, `openssl` (in-guest recovery, re-enroll, audit, re-sign), microcode, and the kernel modules the target hardware needs (dracut hostonly collects them — §8.2).
- **User account:** `install` creates the admin user (name, password, sudo grant) interactively — §5's "login as usual" needs it.
- **Size budget (asserted in CI, scenario S-00):** the pin of record lives in the harness config, not this doc; initial planning target ≤ 1.4 GB installed (kernel modules dominate), revised to the measured value at S-00. Package count tracked alongside.

## 4. Disk layout

```
p1  ESP     FAT32, sized from measured UKI size × retention + headroom (§13), NOT encrypted
p2  LUKS2   rest of disk → root fs (ext4), includes /home; btrfs optional (then pre-upgrade snapshots)
swap        zram (RAM only; hibernation unsupported, §2.2)
```

The ESP is unencrypted **by design**: it contains only signature-verified artifacts (boot manager, UKIs). An evil maid replacing ESP contents either breaks boot (invalid signature) or boots our own signed content — and PCR 11 measurement still binds the LUKS key to the exact expected image. Zero secrets on the ESP. `/boot` stays on the encrypted root (dracut staging area); UKIs are assembled from it and written to the ESP.

## 5. Trust chain — what "boot verified" concretely means

```
1. UEFI firmware  ──verifies signature──▶  UKI  (kernel + initramfs + cmdline, one EFI binary)
2. UKI EFI stub   ──measures components──▶ PCR 11 (sha256)
3. Firmware       ──records SB state/keys─▶ PCR 7
4. initramfs      ──systemd-cryptsetup +──▶ unseal ⇔ running PCRs satisfy a release-key-signed
                    systemd-tpm2 token        policy digest over PolicyPCR, selection {7,11}, ascending
5. cryptsetup open ──▶ root mounted ──▶ systemd ──▶ login (user password as usual)
```

- **PCR 7** pins the Secure Boot configuration (enabled, *our* keys active). Disabling SB or swapping firmware keys breaks unsealing.
- **PCR 11** pins the exact kernel+initramfs+cmdline. Booting anything not signed by the release key breaks unsealing.
- The two gates are independent *mechanisms* — firmware signature check, TPM policy check — sharing one root of trust: the offline release key (I4, ADR-11). Compromising that key defeats both, which is why its custody is the strictest requirement in this design. Either gate failing ⇒ TPM refuses ⇒ the LUKS passphrase slot is the only way in (§10).
- "Passwordless boot" refers to *disk* unlock; user login authentication is unchanged.

## 6. PCR strategy

| PCR | Role | In seal policy? | Notes |
|---|---|---|---|
| 7 | Secure Boot state (vars, keys) | **Yes — static digest policy** (`--tpm2-pcrs=7` at enroll) | Exact-match binding against the enrollment-time value. Mostly stable, but dbx/UEFI-variable changes break it *by design* → re-enroll (§9.4). `provision` removes vendor certs from db so the expected value is fully ours |
| 11 | Measured UKI components | **Yes — release-key-signed policy** (`--tpm2-public-key-pcrs=11`), signatures delivered via each UKI's `.pcrsig` | Kernel updates are TPM-free: each UKI carries its own signature (§9.2) |
| 0–3 | Firmware code/config | **No** | Changes on every firmware update/settings change; enforcing on PCR 0 makes the machine permanently fragile. Covered instead by the `audit` detective control (§9.5) |

The policy is the design's core trick — **resolved (empirically against trixie 257.13) to a systemd-native construction with zero custom crypto:**

- **PCR 7 — static binding:** `--tpm2-pcrs=7` seals an exact-digest check into the policy at enroll time. SB-off or firmware-key changes break the static match ⇒ fallback. Non-bypassable: it lives in the sealed object's policy, not in metadata.
- **PCR 11 — release-key-signed policy:** `--tpm2-public-key=<release.pub> --tpm2-public-key-pcrs=11`; signatures ride in each UKI's `.pcrsig`/`.pcrpkey` sections, produced natively by `ukify build --pcr-public-key=… --pcr-private-key=…` (phase `enter-initrd`), handed to systemd-cryptsetup by the stub at unlock. Kernel updates are TPM-free (§9.2).
- The two policies are **ANDed** by the TPM. An evil maid must defeat *both* the firmware signature check *and* the TPM policy; dropping either term recreates the SB-off-unseal flaw, which the harness asserts cannot happen (§12 negative controls).
- Signatures are precomputed offline (no TPM-generated nonce) — `PolicyAuthorize`, not `PolicySigned`.
- Enrollment happens once per SB-state (§9.4); kernel updates need no TPM operation at all.

### 6.1 Mechanism decision ladder (spike, first implementation task)

**Status (resolved, ADR-14):** Mechanism A″ is PROVEN and is the **only pipeline mode** — in code, `policy_mode_normalize` (lib/common.sh) rejects rungs a/ap/b fail-closed (exit 64, "documented-absent") at every entry point (`ukictl build`, `enroll-tpm`, …). `pcrsign` ships as a standalone, fully unit-tested CLI with **no pipeline consumer** under A″ (ukify embeds each UKI's `.pcrsig` natively); it is kept for the §6.1.1 contract tests, manual re-sign tooling, and future deliberate rung work. The rung descriptions below are retained as design documentation.

**Mechanism A″ (preferred — systemd-native, zero custom crypto):** the static-7 + signed-11 construction above. Spike on a swtpm guest running trixie 257.x: enroll → happy boot shows `Adding PCR signature policy.` sentinel → SB-off boot falls back to prompt → **kernel update with zero TPM operations boots passwordless** (H-G7: token-digest gating is release-sensitive — if 257.13 gates on the token's stored digest list, the postinst hook falls back to conditional re-enroll while the signing key is mounted).

**Fallback rungs** (resolved in order; each keeps the same §12 scenario matrix):

- **Mechanism A′ (single enrollment, combined-digest `.pcrsig`):** if the native `.pcrsig` can carry our combined-digest signature for a {7,11}-selection policy (handoff verified on 257), one TPM enrollment total suffices: the token pins the release pubkey, each UKI carries its own combined signature, rollback needs no extra keyslots. Gate: `kernel_update_no_reenroll_passwordless` e2e plus cryptenroll/chroot acceptance of the exact JSON.
- **Mechanism A (cryptenroll multi-enrollment, combined signature):** `systemd-cryptenroll --tpm2-public-key=… --tpm2-public-key-pcrs=7+11 --tpm2-signature=<combined JSON>`. **Flag precision:** the signed selection is `--tpm2-public-key-pcrs=`; do **not** also pass `--tpm2-pcrs=` — that is the fixed-digest mode, and both together yield an ANDed policy that defeats kernel-update-without-re-enroll; never rely on defaults. Spike must also prove **multi-enrollment coexistence** (enroll kernel A then B — cryptenroll supersession semantics could wipe the first; if so, per-kernel tokens are written directly even if sealing stays cryptenroll-based).
- **Mechanism B (last resort):** Debian FDE seals with `tpm2-tools` (~200 LOC: primary key → `tpm2_create` under the §6 policy → blob) and writes the `systemd-tpm2` token JSON itself, while **unlock stays systemd's**.

#### 6.1.1 Fallback signer contract (`pcrsign`) — required by A′/A/B, not by A″

**Verified toolchain limitation (empirical, systemd 261):** `systemd-measure`/`ukify sign` predict and sign **PCR 11 only** (per `--phase` path); no flag folds PCR 7 into the signed policy. When a rung needs a combined {7,11} signature, `debian-fde pcrsign` follows this normative contract:

1. Compute the expected PCR 11 digest for the UKI via `ukify build --measure` (phase path pinned to `enter-initrd`).
2. Take the **expected PCR 7 digest** from the finalized baseline (§8.4).
3. Compute the combined trial digest exactly as TPM2_PolicyPCR does for selection {7, 11} — **verified formula with golden vector** (`8764f34f…` fixture reproduces it): `pcrDigest = H(d7_raw ‖ d11_raw)`; `policyDigest = H(zero32 ‖ TPM_CC_PolicyPCR(0x17f, 4 bytes) ‖ marshaled-TPML_PCR_SELECTION{7,11} ‖ pcrDigest)` — the command-code bytes are required. The live TPM trial session (`tpm2_startauthsession --policy-session` + `tpm2_policypcr` on swtpm) remains the normative cross-check.
4. Sign the combined `policyDigest` bytes (32 bytes, policyRef empty — RSASSA-SHA256 signs the raw bytes and hashes once via the scheme). **The approved `policyDigest` is CHECKED by `TPM2_PolicyAuthorize`, not hashed into the sealed policy**: the TPM verifies `H(approvedPolicy ‖ policyRef)` — with an empty policyRef, exactly the signed 32 bytes — against its running session digest before clearing it. **`keyName` is not signed**: it enters only the sealed policy's digest update (step 4b), per TPM2 Part 3. Under A′ the same bytes ride in the UKI `.pcrsig` section.
   4b. Sealed-object policy digest — **empirically corrected formula** (pinned by `tests/unit/pcrsign_policyauthorize_accept.sh`; matches libtpms `PolicyAuthorize.c`/`Policy_spt.c`): `PolicyAuthorize` CLEARS the session digest, then `sealed = H( H(zero32 ‖ TPM_CC_PolicyAuthorize(0x0000016a, 4 bytes) ‖ keyName) ‖ policyRef(empty) )` — a **double hash** (the second round runs even for the empty policyRef). The earlier single-hash form `H(policyDigest ‖ keyName ‖ policyRef)` is wrong. `keyName` is the TPM Name of the release public area (obtained via `tpm2_loadexternal` + `tpm2_readpublic`; an openssl key has no Name until loaded external) — **the sealed policy pins the keyName of the area that will VERIFY at session time**, so keys must be registered consistently (recording-area and verifying-area attributes differ — see the `lib/keys.sh` header).
5. Emit the signature JSON in the `systemd-measure sign` output format — `pcrs: [7, 11]` in the existing field, no invented fields.

The live-TPM unit test (`tests/unit/pcrsign_policyauthorize_accept.sh`) covers the **whole chain**: digest trial session (step 3), keyName capture, sealing under the 4b digest, and real in-session `tpm2_policyauthorize` acceptance of the signature — the session digest equal to the sealed-object policy digest, proven by successful session use (`tpm2_unseal`) — each against swtpm, not our own math. The live TPM trial session remains the normative oracle for this contract. The spike also confirms `ukify build --measure` exists on trixie's ukify, else `systemd-measure` is invoked directly.

Negative controls (all mechanisms): a signature over pcrs ≠ {7,11}, or over a stale d7, must be rejected at enroll/unlock — asserted in §12. **swtpm leniency caveat (verified):** swtpm accepted a wrong-digest PolicyAuthorize ticket, so signature-rejection negative tests must run against real systemd-cryptenroll (trixie chroot) or a real TPM — never swtpm alone. The chroot acceptance test pins the accepted format as a fixture before any signing code ships.

## 7. TPM objects and LUKS2 token model

### 7.1 TPM side (systemd-owned)

- **SRK:** systemd creates/uses its own primary key under the owner hierarchy per its documented policy; Debian FDE does not manage it. This is what binds the disk to *this machine's chip*.
- **Sealed object:** systemd seals the target keyslot's **passphrase** (not the volume key — same rationale as ADR-9) under the §6 policy.
- **Auth model:** policy-based authorization with no user-supplied authValue on the seal path — policy-session failures do not consume TPM dictionary-attack budget (§2.2).

### 7.2 LUKS2 metadata (travels with the disk, in the header)

- **Keyslot 0:** user-chosen passphrase (recovery path, decision ADR-3; entropy floor per §13).
- **Keyslot 1 — single enrollment (Mechanism A″, proven live):** one machine-generated random passphrase (≥ 256-bit entropy), sealed under static-PCR7 + pubkey-anchored signed-PCR11 (§6). Per-kernel signatures ride in each UKI's `.pcrsig` — the single token pins only the release pubkey, so kernel updates and rollback need **no TPM operations** (verified: s14, H-G7). The per-kernel multi-slot model survives only in the §6.1 fallback rungs.
- **Token** (type `systemd-tpm2`; field names per the systemd schema — `tpm2_blob`, `tpm2_pcrs`, `tpm2_pcr_bank`, `tpm2_pubkey`, `tpm2_signature`, … — schema owned by systemd, not normative here): `pcrs: [7, 11]`, `pcrbank: sha256`, `pubkey: <b64 release public key>`, `signature: <b64 release-key signature over the PolicyAuthorize verification structure>`, `keyslots: [<slot>]`.
- **Trust posture (I3):** the token is untrusted input. The pubkey in the token is *used* for signature verification but anchored by the keyName pinned inside the sealed object's policy — swapping it fails the policy. Tampering can only *break* unseal, never forge it. Unknown token format/version fields are ignored or rejected by systemd (fail-closed).

## 8. Components

### 8.1 `debian-fde` CLI — the only user-facing tool

Ceremony and lifecycle orchestration around systemd/Debian primitives, **designed to run from a Debian live ISO** (the provisioning environment): the script tree is self-contained, and every command declares its binary dependencies — missing packages are installed **on demand** via apt (`--no-install-recommends`), or the command fails loudly with the exact manual-install list (ADR-15). `DEBIAN_FDE_NO_INSTALL=1` disables the auto-install. `debian-fde doctor` reports environment readiness without changing anything. All commands accept overrides for scripting/tests: `--root <dir>` (target root/`/etc/debian-fde`), `--esp <dir|file>`, `--disk <dev|file>`, `--tcti <conf>` (TPM access for tpm2-tools), `--keydir <dir>`.

| Command | Purpose |
|---|---|
| `doctor` | Environment readiness check: missing binaries/packages, apt reachability, TPM presence, SB state readout, OVMF/QEMU prereqs (CI) — no changes, exit 0/1 |
| `provision` | Two stages. **stage1**: generate release keypair **on the offline signing medium** (openssl; never on the target, I4); create PK/KEK/db certificates; repeatable `--revoke-cert <cert>` builds dbx `EFI_CERT_X509_SHA256` revocation entries (KEK-signed) so removed vendor certs can't verify — after stage1, PCR 7 is **fully ours** (§6); enroll into firmware (KeyTool/efitools or firmware UI on real hardware; `virt-fw-vars` in CI); record baseline **marked pending**. **stage2** (= `--capture-baseline`): the same guarded baseline capture as `audit --init` — refuses any non-final SB state (§8.4 guard). No SRK step — systemd owns it |
| `install` | Guided: partition, `luksFormat` (Argon2id, passphrase slot 0 + entropy floor), mkfs.ext4, `debootstrap --variant=minbase` (§3.3), apt policy, minimal package set, user account, kernel hook install, systemd-networkd config, `bootctl install` to ESP **followed by signing the boot manager** (sbsign, key from the signing medium; ESP writes happen only via signed flows). Before first reboot, copy `/etc/debian-fde/` (baseline, manifest, key metadata) into the encrypted root |
| `ukictl build` | Per kernel (A″ only — the whole pipeline, §6.1): dracut hostonly initrd → `ukify build --measure` (phase `enter-initrd`) with the release key (ukify natively embeds the UKI's own `.pcrsig`/`.pcrpkey`) → combined {7,11} policy digest computed for manifest/audit display → `sbsign` + `sbverify` → atomic UKI install to ESP → manifest upsert → **ensure-once enroll**: a `systemd-tpm2` token already standing ⇒ metadata read only, **zero TPM operations** (verified in s14), and the build stamps **every** manifest entry — including the new kernel's — with the standing `keyslot`/`token_id` via one `luksDump` metadata read (still zero TPM operations; unit-pinned: `tests/unit/ukictl_build_enroll_wire.sh` T6); volume unreachable in the build context (chroot/kernel-hook builds without the target volume attached) ⇒ warn and skip, rc 0 — kernel updates are TPM-free either way (s14) — with manifest entries written in that state carrying empty `keyslot`/`token_id` until a build that can reach the volume stamps them (unit-pinned: `tests/unit/ukictl_build_enroll_wire.sh` T7); token absent ⇒ exactly ONE cryptenroll (static PCR 7 + release-pubkey-signed PCR 11), and the manifest records the enrollment's **`keyslot`/`token_id`** (§8.4) → prune beyond current + 2 old (ESP file + manifest entry together; the standing enrollment is untouched) |
| `pcrsign` | The §6.1 signer: combined {7,11} policy digest → PolicyAuthorize verification structure → release-key signature JSON. Standalone, fully unit-tested against live TPM trial sessions — **no pipeline consumer under A″** (ukify signs natively); kept for the §6.1.1 contract tests, manual re-sign tooling, and future rung work |
| `enroll-tpm` | The enrollment step of `ukictl build` (shared `enrl_run`/`enrl_ensure_once` core). Under A″ there is ONE enrollment per volume: one fresh keyslot + one cryptenroll token pinning only the release pubkey — each UKI's `.pcrsig` already rides on the ESP, so **no release key and no re-signing** are needed. An existing enrollment is wiped and re-created in ONE cryptenroll invocation (`--reseat` forces it); TPM-clear recovery (§9.4) uses the same path |
| `rotate` | Change the keyslot-0 passphrase (`cryptsetup`/`luksChangeKey`; volume key and TPM seals untouched — no re-encryption, no re-seal) |
| `audit` | Compare PCR 0..3 + SB state against baseline; warn on firmware drift (§9.5). `--init` records the first finalized baseline (post-first-boot into the final SB state); `--accept` re-baselines after explicit operator confirmation (required before PCR 7 drift recovery, §9.4) |
| `status` | SB state, PCR readings vs baseline/token, enrolled slots (`cryptsetup luksDump`), manifest vs ESP diff, last audit |
| `bootnext <entry>` | One-shot boot entry (EFI LoaderEntryOneShot) for rollback (§9.3) |
| `pre-upgrade` | Optional: filesystem snapshot before upgrades (btrfs-backed roots only; plain ext4 installs skip) |

### 8.2 Unlock path (systemd-native, no custom code)

- dracut **hostonly** initramfs with modules: `systemd`, `systemd-cryptsetup`, `tpm2-tss`, `kernel-modules`; the legacy `crypt`/`90crypt` module is **omitted** (competing non-systemd prompt path). Verified coupling (trixie dracut 106): `systemd-cryptsetup` auto-adds `tpm2-tss` only when `/etc/crypttab` contains `tpm2-device=` **at build time**, and `91tpm2-tss` requires `tpm2` binaries (installs `systemd-tpm2-generator`, tpm udev rules, TPM driver modules). Hostonly inputs are explicit, not ambient: kernel cmdline comes from `/etc/debian-fde/cmdline.txt` (canonical, embedded into the UKI via ukify `--cmdline`), extra drivers via a `dracut.conf.d` snippet `force_drivers` list — CI builds for the q35/TPM guest use these explicitly.
- **Fail-closed cmdline pins (verified, H-G1):** systemd's passphrase loop is bounded (attempt pacing sentinels → `Too many attempts to activate; giving up.`) but exhaustion then drops to the initrd **emergency shell**. The UKI cmdline therefore pins `rd.shell=0 rd.emergency=poweroff` (dracut 106 honors both) — three strikes ends in poweroff, never an unauthenticated shell; the e2e asserts `Entering emergency mode.` NEVER appears.
- **crypttab contract (verified 257.13 option table):** `root UUID=<luks-uuid> none luks,tpm2-device=auto,discard` — the `tpm2-device=` option is **mandatory** (omitting it silently disables all TPM unlock); no `tpm2-pin=`, no `try-empty-password=`, prompts reachable (`headless=no`), `tpm2-signature=` reserved for non-UKI debug.
- **Required unlock artifacts asserted present in the initrd** (their absence = tokens silently ignored → every boot prompts, G2 lost): `libcryptsetup-token-systemd-tpm2.so`, the libtss2 libraries, TPM kernel modules + udev rules (`tpmrm0`; multiarch paths — `/usr/lib/x86_64-linux-gnu/systemd/…`). Asserted by the `lsinitrd` audit and in S-01.
- `/etc/crypttab` populated before initramfs generation; initramfs regenerates per kernel inside `ukictl build` itself (`dracut --force`, §8.3); UKI assembly consumes the initrd that same build produced (dracut-hook ordering is convention only, §8.3).
- Behavior contract: token policy satisfied → unseal, zero input; policy/TPM failure → **passphrase fallback prompt** (bounded attempt pacing per systemd; the exact try-count is confirmed on target to match the T2b cap) → retries exhausted ⇒ poweroff (no shell).
- Honesty note: loader entries are unsigned by design, so an attacker with ESP write access can append `rd.break`/`rd.shell` to the effective cmdline — unseal then **fails** (PCR 11 mismatch); with `rd.shell=0` no shell spawns, and even where one would, it yields **no secrets** (key never unsealed, no /etc/shadow in the initrd).
- Initrd contents are audited in CI (`lsinitrd` inventory: required-artifact presence per above + deny-rules: no compilers, package tools, unnecessary shells — I6).

### 8.3 Kernel hook — `/etc/kernel/postinst.d/zz-debian-fde`

Debian's dpkg kernel-hook convention: `/etc/kernel/postinst.d/zz-debian-fde` runs after every kernel install/upgrade and calls `ukictl build` for the new kernel; `/etc/kernel/postrm.d/zz-debian-fde` prunes that kernel's UKI + manifest entry **ONLY** (`ukictl remove`) — under A″ the volume's single keyslot/token is shared by all retained UKIs and is **never killed on kernel removal**. **One enrollment per volume (A″ ensure-once)**: rebuilding the same version (microcode, dracut config, cmdline change) finds the standing `systemd-tpm2` token and skips — zero TPM operations (a new kernel built while the token stands is likewise stamped with the standing `keyslot`/`token_id` bookkeeping — still zero TPM operations, `tests/unit/ukictl_build_enroll_wire.sh` T6); a fresh volume gets exactly one enrollment — either way dead slots never accumulate toward LUKS2's 8-slot ceiling. Ordering: the `zz-` placement after dracut's own postinst hook is retained by convention, but Debian FDE's build does not depend on it — `ukictl build` does not consume dracut-hook output; it (re)generates the initrd itself, unconditionally, via `dracut --force` under the pinned §8.2 module set (`initramfs_build`, lib/initramfs.sh). Dracut is never given an ESP/UKI output, and its own ESP-sync (if any) is disabled because **all ESP writes go through Debian FDE's signed flow**. The same guard covers the boot manager: a `systemd-boot` package upgrade re-runs `bootctl install` + re-signs (masked `systemd-boot-update.service`; a dpkg path hook re-signs ESP boot-manager binaries on package upgrade), and `status`/`audit` run `sbverify` over ESP binaries. Microcode and other initrd-affecting updates trigger a `ukictl build` for the running kernel too (same hook family). Release signing key unavailable ⇒ **fail loudly** (non-zero exit + persisted marker visible in `status`); silently shipping a UKI that boots but cannot unseal, or an unsigned binary on the ESP, is treated as a bug.

### 8.4 Interfaces between components

- **`systemd-tpm2` LUKS2 token** (§7.2) — written by the enroll step (`systemd-cryptenroll`; under ADR-14 the only writer — Mechanism B's own writer is documented-absent), read by systemd-cryptsetup in the initramfs. Schema owned by systemd; Debian FDE only orchestrates.
- **Digest manifest** `/etc/debian-fde/digests.json` — written by `ukictl build`; per retained UKI: `kernel_version`, `pcr11_digest` (enter-initrd phase), `policy_digest` (combined {7,11}), `signature`, plus its **`keyslot` and `token id`** — the standing A″ enrollment's bookkeeping, repeated per entry (one enrollment per volume, §7.2). Consumed by `enroll-tpm`/`audit`/harness; bridges build→enroll, including on first install.
- **Baseline file** `/etc/debian-fde/baseline.json` — written at `provision` with `pcr7: "pending"`, **finalized by `audit --init`** after the first boot into the final SB state (PCR 7 changes only on the next boot after firmware key enrollment) — finalization is guarded (`baseline_finalize_from_live`, lib/baseline.sh): requires `secureboot=1 setup_mode=0`, else fail-closed 64 **before any mutation** (baseline stays pending), no override: PCR 0..3 values, expected PCR 7 digest for the custom-key state (what every "PCR 7 matches baseline" check means), release public key path + its TPM name/hash alg, SB state, firmware version, creation date. Read by `audit` and `enroll-tpm`.
- **ESP layout convention:**
  ```
  ESP:/EFI/systemd/systemd-bootx64.efi
  ESP:/EFI/Linux/debian-fde-<kernel-version>.efi     (one UKI per kernel)
  ```

  The resolved ESP mount is persisted at install as `ESP_PATH` in `/etc/debian-fde/debian-fde.conf`; the CLI default is `/efi`.

  (Also the firmware fallback loader `/EFI/BOOT/BOOTX64.EFI`. `loader/` config and entry files are unsigned and unmeasured themselves — acceptable, because security does not rest on them: the boot manager and UKIs are SB-signed, and systemd-stub measures the embedded command line into PCR 11. Empirical note (s07, trixie 257.13): the loader-level cmdline-injection vector is structurally dead — sd-boot drops a type1 UKI entry's `options` line, Boot#### OptionalData is dropped by the stub, and UKI addons are not picked up — so the live tamper vector is a signed-UKI variant with a tampered `.cmdline`, which still breaks unseal via the PCR 11 mismatch. A tampered `loader.conf` default can at most choose *which* signed UKI boots — all retained UKIs are unlock-capable, so there is no privilege gain. `sbverify` + CI assert the signing of `systemd-bootx64.efi` and the fallback loader.)
- **Key material** `/etc/debian-fde/keys/` — release public key, db/KEK/PK certs; private keys stay on the offline medium (I4).

## 9. Lifecycle flows

### 9.1 Provision & install (from the Debian live ISO)
`debian-fde` runs from the live environment (USB/ISO — script tree plus signing medium). Boot live ISO → `debian-fde doctor` (**read-only readiness check** — verifies TPM + disk, installs nothing; the commands that need missing binaries install them on demand, ADR-15) → `provision` (keys, firmware enrollment, **pending** baseline) → `install` (disk + minimal rootfs + boot chain) → first boot (one documented passphrase prompt; `audit --init` finalizes the baseline — guarded on the final SB state: `secureboot=1 setup_mode=0`, fail-closed 64, no override) → `ukictl build` + ensure-once enrollment **from the booted system** (it has the finalized baseline and TPM access — the only first-install enrollment path; the installer environment lacks both) → subsequent boots passwordless. Re-installs with an already-finalized matching baseline may enroll from the installer environment. `enroll-tpm`/`enroll` refuse to run if SB is off or PCR 7 doesn't match the finalized baseline.

### 9.2 Kernel update (the common case)
`linux-image` upgrade → `/etc/kernel/postinst.d/zz-debian-fde` → `ukictl build`: dracut → `ukify build` with the release key as `--pcr-private-key/--pcr-public-key` (embeds this kernel's own `.pcrsig` — the single token pins only the pubkey, so **no TPM operation and no re-enrollment occur**; verified in s14) → `sbsign` → install UKI to ESP → append to manifest → prune the oldest retained kernel (ESP file + manifest entry together). **No prompts.** Release private key required (I4) — e.g. plugged-in signing USB; absence = loud failure.

### 9.3 Rollback after failed upgrade
Up to 3 UKIs stay on the ESP, each carrying its own release-key `.pcrsig`; the ONE A″ enrollment (§7.2) serves them all — the single token pins only the release pubkey, and each retained UKI's signature covers exactly its own measurement ⇒ booting any retained kernel (boot menu, `bootnext`, or loader.conf default) is fully passwordless: the token's policy is satisfied by whichever retained kernel's `.pcrsig` the stub presents (verified in s02/s14). Signatures are release-key-signed, so an attacker cannot add entries — but note the deliberate tradeoff: retained old kernels *remain bootable and auto-unlocking*, including ones with known CVEs. The current + 2 retention window bounds that exposure; extend or prune deliberately. Complement: `pre-upgrade` snapshots (btrfs roots only), since an old *kernel* doesn't undo a bad *userspace* upgrade.

### 9.4 Recovery & rotation
Unseal fails ⇒ passphrase prompt (keyslot 0) ⇒ fix the cause. Which step is stale depends on the failure (§10):

- **Missing/stale enrollment** (UKI re-signed with no standing token, or the token was removed): `ukictl build`'s ensure-once enroll (or `enroll-tpm`) re-enrolls. No broader ceremony.
- **PCR 7 drift** (dbx/UEFI-variable change, SB config change): confirm the drift is benign (`audit` output) → `debian-fde audit --accept` re-baselines → **`enroll-tpm` re-enrolls** (cryptenroll re-captures the *new* current PCR 7 into the static policy; verified in s15). `.pcrsig` re-signing is **not** involved under A″ — the signed policy covers PCR 11 + phase only and encodes no PCR 7 state. The volume key is never re-encrypted.
- **Cleared TPM / lost sealed blobs**: one re-enrollment covers all retained kernels (`enroll-tpm`/`ukictl build` ensure-once; ONE fresh cryptenroll — new keyslot + token sealed to the fresh TPM's SRK; the per-UKI `.pcrsig` files and their signatures are unchanged — verified in s17).

`rotate` changes the keyslot-0 passphrase only; run it whenever the passphrase may have been exposed.

### 9.5 Firmware audit (detective control, not preventive)
`audit` re-reads PCR 0..3 + the TCG event log and compares against the baseline. Event-log check, **v1 scope (ratified): presence + size + whole-file sha256** vs the baseline record — a tripwire, not a parser: any post-baseline change, including a benign append, flips the sha256 and reports as drift. Refinement (parsing pre-OS events, structured comparison) is future work. Drift ⇒ warn with details (firmware update? settings change? or tampering?). This cannot *prevent* firmware attacks (§2.2) but converts silent reflashes into visible alerts.

### 9.6 Release-key rotation (compromise or scheduled)
Two ordering constraints drive the sequence: db/dbx changes reach PCR 7 only after a reboot, **and** binaries the firmware verifies must remain verifiable across the transition — PE binaries can carry **multiple signatures**, so new-key signatures are **appended** while the old ones stay until final revocation.

1. On the offline medium: generate the new release keypair (it never touches the target, I4).
2. Re-sign (K2 only) and install: **all retained UKIs** + boot manager + fallback loader → ESP. (Empirical correction, s16: dual-signing does NOT survive revocation — with K1 in dbx, OVMF rejects a dual-signed image outright; K2-only signatures are required *before* the revoke step.)
3. Reboot — firmware verifies via the K2 signature; PCR 7 unchanged yet, so auto-unseal **still works**.
4. Apply the db change (new cert) **and** the old key's dbx revocation in one firmware/KeyTool step (takes effect next boot).
5. Reboot — firmware verifies via the new signature (old one is now revoked and ignored by firmware policy). PCR 7 has shifted ⇒ **one-time passphrase event**; `debian-fde audit --accept` re-baselines (records the final PCR 7 value).
6. `ukictl build` re-signs **all retained UKIs** over the new d7 with K2 (old signatures already stripped at step 2); rewrites manifest; re-enrolls under the K2-anchored token (cryptenroll re-captures the new PCR 7).
7. Verify passwordless boot. The old key is now revoked and unused.

## 10. Failure matrix — fail-closed by construction

| Condition | Boots? | Auto-unlock | Way out |
|---|---|---|---|
| Current kernel | ✅ | ✅ | — |
| Old retained kernel (rollback) | ✅ | ✅ | its own `.pcrsig`; the single token pins the release pubkey (§7.2) |
| Kernel update build failed | ✅ | ✅ | old signed UKI remains default; fix build (`dpkg --configure -a` after attaching signing key) |
| Kernel re-signed, its enrollment missing/stale | ✅ | ❌ | passphrase → `ukictl build` (re-sign + enroll) |
| Kernel updated, unsigned UKI | ❌ (SB refuses) | ❌ | re-sign via `ukictl build` |
| SB disabled / firmware keys changed | ✅ (SB off → firmware boots unsigned loaders) | ❌ (PCR 7 mismatch) | passphrase; fix SB; re-baseline + re-sign via `ukictl build` (§9.4) |
| Firmware updated | ✅ | ✅ usually (PCR 0 not in policy) — but a dbx/UEFI-variable update can drift PCR 7 ⇒ ❌ | `audit` warns; `audit --accept` + `ukictl build` re-signs over the new PCR 7 (§9.4) |
| TPM cleared / absent / DA-locked by other tooling | ✅ | ❌ | passphrase; one re-enrollment covers all retained kernels (§9.4) |
| Disk moved to another machine | — | ❌ | sealed to *this* TPM's SRK (systemd-owned) — unseals nowhere else |
| Passphrase forgotten + TPM refuses | — | ❌ | **data loss** (documented) |

## 11. Invariants

- **I1** — At rest, the volume key exists only passphrase-wrapped inside LUKS2 keyslots 0 and 1 (one A″ TPM enrollment per volume, §7.2); the TPM-sealed passphrase exists only inside that single token's blob. Neither secret is ever plaintext on disk.
- **I2** — The ESP contains no secrets.
- **I3** — Token JSON is untrusted: tampering with it can only *break* unseal, never forge it. The PCR digests are display data; `pubkey` is *used* for verification but anchored by the keyName pinned inside the sealed object's `PolicyAuthorize` policy — a swapped key fails the policy. Every tampering outcome fails closed.
- **I4** — The release signing **private** key is never stored on the protected machine; custody is offline (signing USB / separate workstation). It is the single identity for db cert, UKI signatures, and PCR policy signatures (ADR-11).
- **I5** — A UKI unseals iff it is signature-valid (firmware gate) **and** the trial digest over the *current* PCR 7 + PCR 11 values is release-key-signed and present in the token (TPM gate). Everything else fails closed.
- **I6** — The unlock path is systemd's, inside a dracut **hostonly** initramfs; CI audits the initrd inventory (`lsinitrd`) against an allowlist policy: no compilers, package tools, or unnecessary shells.

## 12. Testing strategy (swtpm + QEMU/OVMF)

Every row of §10 is an automated scenario on a software TPM (swtpm) under QEMU with OVMF Secure Boot (custom keys enrolled offline via `virt-fw-vars`). Guest userspace is a **pinned Debian rootfs artifact** (downloaded once, SHA256-pinned; populated into the LUKS image in-guest by scenario S-00). Results are asserted from serial-console sentinels.

- **S-00 (bootstrap):** first boot of the freshly installed disk from a **harness installer UKI** (its initrd embeds the pinned rootfs artifact and the LUKS passphrase) — **passphrase unlock** (documented one-time; no enrollment exists yet) → populate minimal rootfs (§3.3) + configure getty/networkd → `audit --init` finalizes the baseline (**before** any UKI chain work — pcrsign needs the finalized d7) → poweroff. Produces the pristine disk cached **at end of S-00b** (post-enrollment) and reused by every scenario; asserts the §3.3 size budget. The artifact itself is produced by a **CI artifact-build job that runs `install` end-to-end in QEMU** (so the installer, debootstrap transaction, apt policy and trims are exercised, not bypassed) and emits the SHA256-pinned artifact. S-00b: the `ukictl build` product boots, then enrollment runs **from the guest** (has TPM access + finalized baseline) via the **production CLI in the guest** — `/opt/debian-fde/bin/debian-fde` (`ukictl build`'s ensure-once enroll / `enroll-tpm`, real systemd-cryptenroll) — replacing the previous harness stand-in (hand-run cryptenroll); the unit-side argv-parity pins (`tests/unit/ukictl_build_enroll_wire.sh` T1) remain as the mechanism-level guard; then cache. Stated as the contract the reworked scenario implements; observed green 2026-09-18 (s00b 35/35, `tests/e2e/results-final.json`).
- **S-01 happy path (headline):** enrolled vars, signed UKI, enrolled TPM → boots to `login:` with **zero input**; no fallback prompt; PCR 11 at the unlock point == ukify's enter-initrd prediction (compared via event log / pre-unlock reading — the final register additionally contains later pcrphase extensions); ESP-size assertion.
- **Tamper rows:** unsigned UKI (SB refusal asserted); SB-off boot (unseal refusal + fallback prompt asserted); stale enrollment (under A″: a UKI whose `.pcrsig` is missing/stale for the standing token, or the token removed — s03); token tampering (I3: refusal, never grant) — including the trap case: **SB off + tampered token metadata + otherwise-legitimate PCR 11 signature ⇒ unseal must still fail**; tampered cmdline on an otherwise-signed UKI (the compromised-signer vector, **as implemented in s07**: a release-key-signed UKI variant whose `.cmdline` carries one extra word — the stub measures the tampered cmdline into PCR 11, the trial digest drifts away from every signed `.pcrsig`, unseal refused; **empirical correction**: the literal "tampered loader-entry `options`" vector is dead on trixie — sd-boot 257.13 drops a type1 UKI entry's `options` line, Boot#### OptionalData is dropped by the stub, addons are not picked up); cleared/absent TPM; disk moved to foreign TPM.
- **Sentinel pinning:** all console greps consume `tests/sentinels-257.13.txt`, extracted and hash-pinned from the exact trixie debs, with per-line provenance kept in sections: systemd sentinels from `systemd-cryptsetup_257.13-1~deb13u1`, cryptsetup sentinels from `cryptsetup-bin_2.7.5-2`, and a separate **firmware/host-tool section** (OVMF, sbsigntool) — provenance classes stay distinct so a break reports its own class. Sentinel strings drift across systemd releases (verified: the policy-mismatch wording differs between 257.13 and 261). Key anchors: success `Volume … activated with a LUKS token.`; happy-path proof `Adding PCR signature policy.`; fallback prompt regex `^Please enter .* for disk`; retry cap `Too many attempts to activate; giving up.`; TPM-absent and DA-locked sentinels (both must fall back, never hang; DA simulated via `tpm2_dictionarylockout` on swtpm); **`Entering emergency mode.` must NEVER appear** (H-G1). Unknown token `version` (s13, verified): 257.13 validates required fields only and **ignores** the field — unlock is unchanged (crypto intact; an inert field cannot forge, I3 unaffected); the scenario asserts the *observed* semantics.
- **Recovery drills:** PCR 7 drift runbook end-to-end (drift → `audit --accept` → re-sign → passwordless boot); release-key rotation (§9.6; s16 pins the corrected outcome — **dual-signing does NOT survive revocation**: with K1 in dbx, OVMF rejects any image carrying a revoked signature outright, so K2-only signatures are required *before* the revoke step; the wrong-order negative control asserts the dual-signed + revoked boot fails closed); TPM-clear re-enroll.
- **Prediction checks:** ukify's predicted PCR 11 (enter-initrd phase) asserted equal to the PCR 11 state at the unlock point in every scenario that reaches the UKI stub — compared against the TCG event log / the guest's pre-unlock reading, **not** the final register (post-boot PCR 11 additionally contains leave-initrd and later pcrphase extensions). The outer `sbsign` signature does not alter stub-measured sections.
- **Signing negative controls (§6.1):** signature over pcrs ≠ {7,11}; signature over a stale d7; signature from a foreign key — every variant must be rejected at enrollment or fail closed at unlock.
- **Initrd inventory audit** on every build (I6). Harness self-tests (swtpm fixture, vars enrollment, disk fixture) run before e2e so infra breakage reports as harness-failure, not scenario-failure.

## 13. Prerequisites (checked by `debian-fde doctor` — a **read-only** check, no installs; the commands that need missing packages auto-install them on demand, §8.1/ADR-15)

- x86_64 UEFI machine with **TPM 2.0** (SHA-256 PCRs) and custom-key Secure Boot enrollment possible (firmware UI or KeyTool).
- **Firmware admin password set** (manual step; keeps the evil maid out of firmware setup).
- Offline custody plan for the release signing key.
- Keyslot-0 passphrase: minimum **heuristic entropy estimate** (zxcvbn-class, threshold-blocked) enforced interactively by `install`/`rotate`; LUKS2 KDF pinned to **Argon2id** with generous memory/time cost (the passphrase is the one offline-guessable secret, T2b).
- ESP sized from **measured UKI size × retention + headroom** (verified in CI, §12).
- Debian 13 (trixie) target; root on ext4 (btrfs optional, enables `pre-upgrade` snapshots).

## 14. Decision record

| # | Decision | Rationale |
|---|---|---|
| ADR-1 | **Platform: Debian 13 "trixie"** (rev. B; supersedes Alpine) | systemd-cryptenroll/cryptsetup provide the signed-PCR unlock path as maintained code; custom Alpine initramfs tooling was the original premise and is consciously traded away for a battle-tested unlock path and simpler validation. Debian FDE keeps the ceremony, installer, audit, and lifecycle tooling |
| ADR-2 | Threat model: offline theft + evil maid; firmware attacks out of scope | Hardware-rooted firmware verification (Boot Guard/PSP) is OEM-fused, not user-installable |
| ADR-3 | Recovery: TPM slot + user-chosen passphrase slot | User decision; recovery-key option declined |
| ADR-4 | Boot chain: SB(custom keys) → systemd-boot → signed UKI; policy = PCR 7 + PCR 11 combined, release-key-signed | Only option satisfying G3 + G4 simultaneously |
| ADR-5 | ESP stays unencrypted | Holds only verified artifacts; encrypting it adds complexity and no security (I2) |
| ADR-6 | PCR 0..3 excluded from seal policy; covered by `audit` | Firmware updates would permanently break sealing; detection beats brittle prevention |
| ADR-7 | Hibernation unsupported; swap = zram | Hibernate image would leak volume-key state to disk |
| ADR-8 | Missing signing key during kernel update = loud failure | Silent passphrase-prompt degradation would erode the security property |
| ADR-9 | TPM seals a keyslot passphrase, not the volume key | LUKS2 keyslots wrap passphrases; systemd's model is exactly this — conventional and validated |
| ADR-10 | Release-key signature covers the combined policy digest — single PolicyPCR call, selection {7,11}, ascending | Signing only the PCR 11 digest would leave PCR 7 unbindable — the evil-maid gate could silently vanish |
| ADR-11 | One signing identity: the release key's certificate lives in db and signs both UKIs and policy digests | Fewer keys, one custody story; PK/KEK/db keys are enrollment-only |
| ADR-12 | Minimal rootfs: debootstrap `--variant=minbase`, no-recommends policy, explicit ~15-package addition set, size budget asserted in CI | User requirement; §3.3 is the normative recipe |
| ADR-13 | dracut hostonly initramfs; ext4 default root (btrfs optional) | Hostonly = smallest initrd + only-needed drivers for a single-machine image; ext4 keeps the minimal footprint, at the cost of optional snapshots |
| ADR-14 | Mechanism ladder resolved empirically: **A″ PROVEN in e2e (s00/s01/s14/s16)** — systemd-native static PCR 7 + signed PCR 11 delivered via per-UKI `.pcrsig`; single enrollment; kernel updates and rollback TPM-free | Verified live on trixie 257.13: no signer/consumer skew (257≡261 bit-exact); the unlock blocker was the harness initrd missing `systemd-pcrextend enter-initrd` (production dracut does this via systemd-pcrphase-initrd). In code the ladder is A″-only: rungs a/ap/b fail closed (exit 64, "documented-absent") at the `policy_mode_normalize` boundary (lib/common.sh) inherited by every pipeline entry point; `pcrsign` (§6.1.1) ships as a standalone fully-tested CLI with no pipeline consumer; rungs retained as design documentation |
| ADR-15 | Runs from the Debian live ISO; missing packages installed on demand via apt (`--no-install-recommends`), `DEBIAN_FDE_NO_INSTALL=1` escape hatch, loud failure with manual list otherwise | The provisioning environment is a live system without the toolchain preinstalled; silent degradation is unacceptable (ADR-8 spirit) |
