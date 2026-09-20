# Alpine FDE — TPM 2.0-Backed Verified Boot & Disk Encryption

**Platform:** Alpine Linux (x86_64, OpenRC, musl) · **Status:** revision C — approved design [Alpine Architecture]; (supersedes Revision B Debian 13 baseline)

Alpine FDE makes a Linux machine that protects its data against physical theft:

1. **The root filesystem is fully encrypted** (LUKS2) and **minimal** (~200 MB installed, §3.3).
2. **The key unseals automatically in the initramfs — but only if the boot process verifies as untampered** (Secure Boot + measured kernel, enforced by a TPM 2.0 signed-PCR policy).
3. **Booting requires no password** in the happy path.

Revision C note: the architecture targets Alpine Linux as the installed target operating system. While Revision B evaluated Debian for its systemd-cryptenroll/cryptsetup unlock path, Alpine FDE leverages Alpine's ultra-compact footprint (~200 MB rootfs vs ~1.4 GB on Debian) by utilizing standalone upstream packages available on Alpine (`ukify`, `systemd-boot`, `systemd-efistub`, `tpm2-tools`, `libtss2-policy`). Unified Kernel Images (UKIs) assembled via `ukify` embed the `.pcrsig` and `.pcrpkey` sections, which `systemd-stub` injects into the synthetic initramfs at `/.extra/`. Early-boot unseal is executed by a dedicated initramfs hook with strict fail-closed poweroff guards (`poweroff -f`), and post-install lifecycle events are managed via OpenRC trust finalization and APK upgrade triggers.

---

## 1. Goals

- G1 — Root (and therefore `/home`) at rest on a LUKS2 volume; no plaintext secrets on unencrypted storage.
- G2 — Automatic unseal at boot; no interactive prompt unless verification fails.
- G3 — "Verified" is *enforced*: an evil maid cannot boot a modified OS and still get the key.
- G4 — Kernel updates and rollback boots remain passwordless (no re-seal of existing enrollments, no passphrase).
- G5 — One clearly documented recovery path when verification fails.
- G6 — Everything reproducible in CI with a software TPM.
- G7 — The installed system is **minimal** (§3.3): only what boot, unlock, audit, and admin need (~200 MB budget).

## 2. Threat model

### 2.1 In scope

| Threat | Mitigation |
|---|---|
| **T1 — Offline theft**: machine stolen powered off (suspended: RAM-extraction attacks remain out of scope, §2.2) | LUKS2 + key material sealed to this TPM; unsealed only after verified boot, in RAM only from then on |
| **T1b — Cache SSD theft (Hybrid bcache)** | An attacker extracts the caching SSD. Because LUKS2 sits on top of `/dev/bcache0`, the cache SSD holds solely AES-XTS ciphertext (no plaintext user data or key material on SSD, ADR-17). Yields no decrypted data or keys |
| **T1c — Single RAID member theft (Btrfs RAID1)** | An attacker extracts one drive from a multi-disk RAID1 array. Each member is independently wrapped in a LUKS2 container sealed to the machine's TPM; protected by the same verified-boot policy and Argon2id passphrase floor |
| **T2 — Evil maid**: brief physical access; boots USB/modified boot files to install a backdoored kernel, then steals the machine | Firmware (Secure Boot, custom keys) refuses unsigned bootloaders/kernels; TPM policy (PCR 7 bound + release-key-authorized PCR 11) refuses to unseal otherwise. Two independent mechanisms |
| **T2b — Brute force** | Sealed blob and volume key are high-entropy and unguessable; the one guessable secret is the keyslot-0 passphrase. Enforced by a passphrase entropy floor + Argon2id KDF (§3.3, §13); unlock attempts are bounded, and failure triggers immediate fail-closed poweroff (no rescue shell). Note: TPM dictionary-attack lockout does **not** increment on policy-session failures (only authValue failures) — it's an availability consideration, not a confidentiality control |
| **T2c — Bootstrap handoff window** | Between Stage 1 in-chroot provisioning and Stage 3 trust finalization, the volume is protected exclusively by the operator's permanent recovery passphrase in keyslot 0 (Argon2id + high entropy floor). No TPM token exists during the reboot window, completely eliminating PCR-replay vulnerabilities while Secure Boot is transitioning. `release.pem` is encrypted with AES-256 PBKDF2 in Stage 1 before reboot (ADR-18). On first boot under verified Secure Boot, the operator enters the recovery passphrase once, whereupon the system validates the firmware state and establishes the permanent {PCR 7, PCR 11} TPM token |

### 2.2 Out of scope (non-goals)

- Malicious or reflashed **firmware** (SMM implants, SPI-flash reflash, Boot Guard defeat). The UEFI firmware is this design's **trust anchor, not a verified component** — nothing user-installable can verify it. Detection is partially possible (see `audit`, §9.5); prevention is the OEM's fused hardware (Intel Boot Guard / AMD PSP), outside user control.
- Cold-boot / RAM extraction, DMA attacks, hardware implants/loggers.
- **Hibernation** (a hibernate image is unencrypted volume-key state on disk). Swap is RAM-only (zram); suspend-to-RAM is fine.
- Dual-booting with foreign operating systems (multi-disk Btrfs RAID1 and bcache hybrid acceleration are in-scope per §4.1; foreign OS dual-boot is unsupported).

## 3. Platform baseline (Alpine Linux)

### 3.1 Package dependencies

Verified present in the Alpine Linux `main` and `community` components:

| Purpose | Alpine package | Note |
|---|---|---|
| Init system, service manager, getty | `openrc`, `busybox` | base |
| LUKS2 volume manipulation | `cryptsetup` | standard upstream tool |
| Boot manager + `bootctl` | `systemd-boot` | available in Alpine main (`apk add systemd-boot`) |
| EFI Boot Stub | `systemd-efistub` | measures UKI into PCR 11, injects `/.extra/` signatures |
| UKI assembly + PCR measurement/signing | `ukify`, `py3-pefile` | available in Alpine (`apk add ukify`) |
| Initramfs generator | `mkinitfs` / `dracut` | modular initramfs with early-boot unlock hook (§8.2) |
| Kernel | `linux-lts` | default stable LTS kernel (or `linux-virt`) |
| TPM audit, ceremony, and policy ops | `tpm2-tools`, `tpm2-tss`, `tpm2-tss-policy`, `tpm2-tss-tcti-device` | full TSS2 and policy stack |
| EFI binary signing | `sbsigntool`, `openssl` | UKI and bootloader signing via openssl-based ceremony |
| Minimal rootfs bootstrap | `apk-tools-static` / `apk` | `apk add --root` onto mounted LUKS2 root |
| Filesystem utilities | `btrfs-progs` (default) / `e2fsprogs` (if ext4) | Btrfs tools for subvolume management; e2fsprogs if `--fs ext4` |
| Hybrid storage acceleration | `bcache-tools` | Optional; required when `--bcache` is enabled |
| Swap on zram | `zram-init` | hibernation unsupported (§2.2) |
| Admin | `doas` or `sudo`, `openssh-server` (optional) | interactive service |

CI **host** (test sandbox) additionally uses: `qemu-system-x86_64`, `edk2-ovmf`, `swtpm`, `tpm2-tools`, `sbsigntool`, `virt-firmware` (offline OVMF vars enrollment), `dosfstools`+`mtools` (ESP image tooling, no root needed), `jq`, `python3`.

### 3.2 Why `ukify` + Authorized Policy over Clevis

Clevis's `tpm2` pin supports only *static PCR digest* policies — it cannot evaluate digital signatures over PCR 11 (`PolicyAuthorize`). Binding statically to PCR 11 causes every legitimate kernel update to break passwordless boot, while omitting PCR 11 leaves the boot chain completely unverified against evil-maid kernel replacement.

Alpine FDE uses `ukify` to predict and sign PCR 11 measurements into `.pcrsig` files, which `systemd-efistub` measures into PCR 11 and places at `/.extra/tpm2-pcr-signature.json`. The early-boot initramfs hook evaluates the `PolicyAuthorize` session against the release public key, enabling **fully passwordless kernel updates and rollbacks** without sacrificing evil-maid protection (ADR-1, ADR-14).

### 3.3 Minimal root filesystem composition

The installed system is deliberately minimal — only what boot, unlock, audit, and administration require:

- **Bootstrap:** `apk add --root <mnt> --initdb alpine-base` onto the mounted LUKS2 root.
- **Package policy:** explicit minimal additions installed with `--no-cache`.
- **Explicit additions:** the §3.1 boot/unlock/audit set (`cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `linux-lts`, `tpm2-tools`, `tpm2-tss-policy`, `tpm2-tss-tcti-device`, `sbsigntool`, `openssl`, `jq`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`).
- **Explicit exclusions:** no heavy display managers, no GRUB/shim (direct UEFI handover to `systemd-boot`), no documentation/man pages.
- **Fail-closed guard:** The initramfs hook enforces `poweroff -f` after failed unseal / passphrase retries, preventing drops into an interactive BusyBox emergency shell.
- **Size budget:** Initial planning target ≤ 250 MB installed (an 80%+ reduction compared to Debian).

## 4. Disk layout

The default filesystem for the encrypted root is **Btrfs**, configured with standard subvolumes (`@` for root, `@home` for user data, and `@snapshots` for atomic `debian-fde pre-upgrade` snapshots). `ext4` is available via `--fs ext4`.

### 4.1 Topology Variants [Wave 2 Architecture — Design Approved, Implementation In Progress]

```
1. Default Single-Disk (NVMe or SATA):
   p1  ESP     FAT32, sized from measured UKI size × retention + headroom (§13), NOT encrypted
   p2  LUKS2   dm-crypt container (Argon2id + TPM 2.0 token)
       └── Btrfs root filesystem (subvolumes: @ -> /, @home -> /home, @snapshots -> /.snapshots)
   swap        zram (RAM only; hibernation unsupported, §2.2)

2. Accelerated Hybrid Layout (--disk <backing> --bcache <cache_dev>):
   Fast Caching Drive (e.g. NVMe CACHE_DEV, /dev/nvme0n1):
   p1  ESP     FAT32, holds signed systemd-boot & UKIs (firmware accessible)
   p2  Cache   bcache caching set (make-bcache -C)
   Backing Drive (e.g. HDD --disk, /dev/sda):
   p1  Backing bcache backing device (make-bcache -B)
   Virtual Device:
   /dev/bcache0 ───▶ LUKS2 dm-crypt (single TPM 2.0 token Mechanism A″)
                     └── Btrfs root filesystem (@, @home, @snapshots)
   * Cache Mode: Always "writethrough" (crash-safe; backing drive is always 100% consistent).
   * Key Invariant: LUKS2 sits ON TOP of bcache (ciphertext-only caching; no plaintext user data or key material on SSD cache).

3. Multi-Disk Btrfs RAID1 Layout (multiple --disk):
   Primary Disk (--disk #1): p1 ESP (FAT32) + p2 LUKS2 (/dev/mapper/root1)
   Secondary Disk(s) (--disk #2..): p1 LUKS2 (/dev/mapper/root2)
   All LUKS2 containers enrolled to TPM 2.0 with identical {PCR 7, PCR 11} policy;
   crypttab uses password-cache=yes so recovery passphrase prompts only once.
   Multi-device RAID1 pool: mkfs.btrfs -d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2.
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
- The two gates are independent *mechanisms* — firmware signature check, TPM policy check — sharing one root of trust: the release key (I4, ADR-11). Compromising that key defeats both, which is why its custody is the strictest requirement in this design. Either gate failing ⇒ TPM refuses ⇒ the LUKS passphrase slot is the only way in (§10).
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

- **Keyslot 0:** user-chosen recovery passphrase (decision ADR-3; entropy floor per §13). Created at `luksFormat` during host bootstrap (pre-reboot).
- **Keyslot 1 — single enrollment (Mechanism A″, proven live):** one machine-generated random passphrase (≥ 256-bit entropy), sealed under static-PCR7 + pubkey-anchored signed-PCR11 (§6). Per-kernel signatures ride in each UKI's `.pcrsig` — the single token pins only the release pubkey, so kernel updates and rollback need **no TPM operations** (verified: s14, H-G7). (Enrolled at Stage 3 after the operator unlocks via recovery passphrase and the Secure Boot state is verified).
- **Token** (type `systemd-tpm2`; field names per the systemd schema — `tpm2_blob`, `tpm2_pcrs`, `tpm2_pcr_bank`, `tpm2_pubkey`, `tpm2_signature`, … — schema owned by systemd, not normative here): `pcrs: [7, 11]`, `pcrbank: sha256`, `pubkey: <b64 release public key>`, `signature: <b64 release-key signature over the PolicyAuthorize verification structure>`, `keyslots: [<slot>]`.
- **Trust posture (I3):** the token is untrusted input. The pubkey in the token is *used* for signature verification but anchored by the keyName pinned inside the sealed object's policy — swapping it fails the policy. Tampering can only *break* unseal, never forge it. Unknown token format/version fields are ignored or rejected by systemd (fail-closed).

### 8. Components

### 8.1 `alpine-fde` CLI — the user-facing tool

Ceremony and lifecycle orchestration around verified boot and storage primitives (`bin/alpine-fde`, with `bin/debian-fde` provided as a backwards-compatible alias). Missing host packages are installed on demand via `apk` (or the command fails loudly with the manual install list, ADR-15). `DEBIAN_FDE_NO_INSTALL=1` / `ALPINE_FDE_NO_INSTALL=1` disables auto-install. `alpine-fde doctor` reports environment readiness without changing anything. All commands accept overrides for scripting/tests: `--root <dir>` (target root/`/etc/alpine-fde`), `--esp <dir|file>`, `--disk <dev|file>` (repeatable for RAID1), `--bcache <dev>` (for hybrid acceleration), `--fs <btrfs|ext4>`, `--tcti <conf>`, `--keydir <dir>`.

| Command | Purpose |
|---|---|
| `doctor` | Environment readiness check: missing binaries/packages, apk/network reachability, TPM presence, SB state readout (including `SetupMode` detection), OVMF/QEMU prereqs (CI) — no changes, exit 0/1 |
| `provision` | Two stages. **stage1**: generate release keypair (in-chroot or on offline signing medium, ADR-18); create PK/KEK/db certificates; repeatable `--revoke-cert <cert>` builds dbx `EFI_CERT_X509_SHA256` revocation entries (KEK-signed) so removed vendor certs can't verify — after stage1, PCR 7 is **fully ours** (§6); enroll into firmware via efivarfs in strict order `db → KEK → PK (last)` (requires `SetupMode=1`) or KeyTool/efitools; record baseline **marked pending**. **stage2** (= `--capture-baseline`): guarded baseline capture — refuses any non-final SB state (§8.4 guard). (In Wave 2, `install` runs these steps integrated in-chroot; `provision` remains available for standalone/offline key ceremonies) |
| `install` | Guided: partition, block layer setup (single-disk, `--bcache`, or RAID1), format LUKS2 keyslot 0 with recovery passphrase (Argon2id + entropy floor), format root filesystem (Btrfs default or ext4), `apk add --root` minimal base system (§3.3), minimal package set, user account, OpenRC network config, `bootctl install` to ESP **followed by signing the boot manager** (sbsign; ESP writes happen only via signed flows). Stage 1 in-chroot sets `OsIndications` bit 0 to signal firmware setup on next reboot |
| `finalize` | First-boot trust-finalization entry point (shipped as `/etc/init.d/alpine-fde-finalize` OpenRC service, §9.1 Stage 3): install-state guard (runs only in state `installed`), `fw_sb_state` guard (halts exit 64 with **no enrollment and no wiping** when Secure Boot is off), crash-idempotent `audit --init` + per-member enroll (RAID1), writes state `finalized` |
| `ukictl build` | Per kernel: initramfs generation → `ukify build --measure` (phase `enter-initrd`) with the release key (ukify natively embeds the UKI's own `.pcrsig`/`.pcrpkey`) → combined {7,11} policy digest computed for manifest/audit display → `sbsign` + `sbverify` → atomic UKI install to ESP → manifest upsert → **ensure-once enroll**: an active token already standing ⇒ metadata read only, **zero TPM operations**; token absent and state finalized ⇒ enrolls static PCR 7 + release-pubkey-signed PCR 11 → prune beyond current + 2 old (ESP file + manifest entry together) |
| `pcrsign` | Standalone signer: combined {7,11} policy digest → PolicyAuthorize verification structure → release-key signature JSON (§6.1.1) |
| `enroll-tpm` | The enrollment step of `ukictl build` (shared core). Binds keyslot 1 to static PCR 7 + release-pubkey-signed PCR 11 via TPM 2.0 authorized policy. Takes `--uuid <LUKS_UUID>` (or target block device). TPM-clear recovery (§9.4) uses the same path |
| `rotate` | Change the keyslot-0 passphrase (`cryptsetup`/`luksChangeKey`; volume key and TPM seals untouched — no re-encryption, no re-seal) |
| `audit` | Compare PCR 0..3 + SB state against baseline; warn on firmware drift (§9.5). `--init` records the first finalized baseline; `--accept` re-baselines after explicit operator confirmation (required before PCR 7 drift recovery, §9.4) |
| `status` | SB state, PCR readings vs baseline/token, enrolled slots (`cryptsetup luksDump`), manifest vs ESP diff, last audit; warns prominently if installation state is `installed` |
| `bootnext <entry>` | One-shot boot entry (`bootctl` / EFI LoaderEntryOneShot) for rollback (§9.3) |
| `pre-upgrade` | Optional: filesystem snapshot before upgrades (btrfs-backed roots only; plain ext4 installs skip) |

### 8.2 Unlock path & Initramfs Hook

- **Early-Boot Unseal Hook:**
  - When `systemd-efistub` boots the UKI, it measures the UKI sections into PCR 11 and places `.pcrsig` and `.pcrpkey` into the synthetic initrd at `/.extra/tpm2-pcr-signature.json` and `/.extra/tpm2-pcr-public-key.pem`.
  - In the initramfs, the early-boot unlock hook executes:
    1. Extends `"enter-initrd"` into PCR 11 via `tpm2_pcrextend` to align with `ukify`'s phase measurement prediction.
    2. Starts a TPM policy session evaluating `PolicyPCR` (PCR 7 + PCR 11) and `PolicyAuthorize` (matching `/.extra/tpm2-pcr-signature.json`).
    3. Unseals the keyslot-1 secret and unlocks the container via `cryptsetup open`.
    4. If the TPM policy fails, prompts for the keyslot 0 recovery passphrase.
- **Fail-Closed Security Guarantee (Anti Evil-Maid):**
  - If passphrase attempts fail (bounded to 3 strikes), the hook executes **`poweroff -f` immediately**.
  - Dropping into an interactive BusyBox ash rescue shell is **strictly prevented**, eliminating local dictionary attacks, kernel memory inspection, and ESP tampering vectors.
- **crypttab & RAID1:**
  - Each container is mapped in `/etc/crypttab`. For multi-disk RAID1 arrays, all member containers are enrolled with matching policy parameters.

### 8.3 Kernel upgrade hooks — APK Triggers

- **APK Trigger Integration:**
  - Alpine packages use `apk`. An APK trigger script (e.g., `/etc/apk/triggers/alpine-fde.trigger` watching `/boot/vmlinuz-*`) intercepts kernel installations and upgrades.
  - The trigger prompts the operator for the `release.pem` passphrase and calls `alpine-fde ukictl build` for the new kernel version.
  - Pruning retains the current plus 2 older UKIs on the ESP; rollback remains 100% passwordless via each retained UKI's `.pcrsig`.

### 8.4 Interfaces between components

- **LUKS2 Token Metadata:** Keyslot 0 holds the recovery passphrase (Argon2id). Keyslot 1 holds the TPM-sealed passphrase bound to {PCR 7, PCR 11}.
- **Digest manifest** `/etc/alpine-fde/digests.json` — written by `ukictl build`; per retained UKI: `kernel_version`, `pcr11_digest` (enter-initrd phase), `policy_digest` (combined {7,11}), `signature`, plus `keyslot` and `token_id`.
- **Baseline file** `/etc/alpine-fde/baseline.json` — written at `provision` with `pcr7: "pending"`, finalized by `audit --init` after the first boot into the verified custom Secure Boot state (`secureboot=1 setup_mode=0`).
- **Installation state file** `/etc/alpine-fde/install-state.json` — tracks the install ceremony state machine: `installed` → `[reboot to BIOS]` → `finalized`. Prevents premature enrollment and guarantees crash recovery across the first-boot reboot.
- **ESP layout convention:**
  ```
  ESP:/EFI/systemd/systemd-bootx64.efi
  ESP:/EFI/Linux/alpine-fde-<kernel-version>.efi     (one UKI per kernel)
  ```
  Persisted as `ESP_PATH` in `/etc/alpine-fde/alpine-fde.conf` (default `/efi`).
- **Key material** `/etc/alpine-fde/keys/` — release public key, db/KEK/PK certs; private release key (`release.pem`) is encrypted at rest (AES-256 PBKDF2) and backed up off-machine (I4, ADR-18).

## 9. Lifecycle flows

### 9.1 Provision & install lifecycle (chroot provisioning + single-reboot finalization) [Wave 2 Architecture — Design Approved, Implementation In Progress]

The lifecycle is modeled as an explicit, crash-safe state machine: `installed` → `[reboot to BIOS]` → `finalized`, recorded in `/etc/debian-fde/install-state.json`.

#### Keyslot Choreography by Lifecycle State
| State | Keyslot 0 | Keyslot 1 | Token 0 | Notes |
|---|---|---|---|---|
| `installed` | Permanent Recovery Passphrase | (Empty) | (None) | Recovery passphrase only; immune to PCR-replay; ESP has no secrets |
| `finalized` | Permanent Recovery Passphrase | Finalized Sealed TPM Passphrase | `systemd-tpm2` (bound to PCR 7 + PCR 11) | Mechanism A″ active; passwordless happy path |

1. **Stage 1: Host Bootstrap & In-Chroot Provisioning (from live USB; Secure Boot OFF, Setup Mode ON):**
   * **Host preflight check:**
     - Asserts firmware is in **Setup Mode** (`SetupMode=1`, vendor PK cleared). If `SetupMode != 1`, fails closed (`exit 64`) with instructions to clear vendor PK in BIOS before disk partitioning (preventing NVRAM write failures, §9.1 preflight).
     - Asserts presence of required host utilities (`debootstrap` or `mmdebstrap`, `sfdisk`, `cryptsetup`, `mkfs.vfat`, filesystem utilities `btrfs-progs` or `e2fsprogs`, optional `bcache-tools` if `--bcache`, and `lsblk`) **before any disk mutation**. On Debian live hosts, missing packages are installed on demand via `apt-get` (unless `DEBIAN_FDE_NO_INSTALL=1`); on non-Debian live hosts, missing tools trigger an immediate fail-closed abort (`exit 64`) instructing the operator to install them.
   * **Host bootstrap:**
      - **Partitioning & block layer setup:**
        - *Single-disk topology:* Partitions target disk into ESP (`p1`) and LUKS2 container (`p2`).
        - *Accelerated hybrid topology (`--bcache CACHE_DEV`):* Partitions fast caching SSD (`CACHE_DEV`) into ESP (`p1`) and bcache caching set (`p2`, `make-bcache -C`); partitions backing disk (`--disk`) into backing set (`p1`, `make-bcache -B`); registers and attaches `/dev/bcache0` in `writethrough` mode (ensuring backing disk is always crash-safe and consistent). LUKS2 container is created directly on `/dev/bcache0`.
        - *Multi-disk Btrfs RAID1 (multiple `--disk`):* Partitions primary disk into ESP (`p1`) and LUKS2 container (`p2`), and all secondary disks into LUKS2 containers (`p1`). Formats root pool with `mkfs.btrfs -d raid1 -m raid1`.
      - **LUKS2 creation:** Formats target LUKS container(s) directly with the operator's **permanent recovery passphrase** in keyslot 0 (`luksFormat --key-slot 0`, enforcing Argon2id and §13 entropy floor). No provisional TPM token is created during Stage 1.
      - **Filesystem setup:** Formats root container(s) with Btrfs (`mkfs.btrfs`) and creates standard subvolumes (`@`, `@home`, `@snapshots`); mounts `@` to `<mnt>`, `@home` to `<mnt>/home`, `@snapshots` to `<mnt>/.snapshots`, and ESP to `<mnt>/efi`. (If `--fs ext4` is passed, formats ext4 and mounts flat).
     - Runs `debootstrap --variant=minbase trixie <mnt>` to install base Debian (including `apt-get`).
     - Drops initial system configurations (`apt`, `fstab`, `crypttab`).
     - Bind-mounts `/dev`, `/proc`, `/sys`, and `/sys/firmware/efi/efivars` into `<mnt>`.
   * **In-chroot provisioning (strictly ordered sequence):**
      1. `apt-get` installs the §3.3 explicit-additions set (topology-conditional items per `--fs`/`--bcache`: `linux-image-amd64`, `dracut`, `systemd-cryptsetup`, `cryptsetup`, `systemd-boot`, `systemd-boot-tools`, `systemd-ukify`, `sbsigntool`, `openssl`, `tpm2-tools`, `jq`, `sudo`, `zram-tools`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`, CPU microcode), user account, and network services.
      2. Writes initial baseline with `pcr7: "pending"` (following `provision stage1` semantics).
      3. Provisions platform keys: generates `PK`, `KEK`, `db`, and `release.pem` on the encrypted root volume (ADR-18).
      4. Enrolls authenticated variable update packets (`.auth`) into UEFI NVRAM via `efivarfs` in **strict order**: `db → KEK → PK (last)` (writing PK last cleanly transitions firmware out of Setup Mode, I-3).
      5. Builds signed `systemd-bootx64.efi` and initial signed UKI with `.pcrsig` via `ukictl build`.
      6. Encrypts `release.pem` with AES-256 (PBKDF2 HMAC-SHA256, ≥ 600,000 iterations; enforces §13 entropy floor on passphrase, ADR-18), eliminating plaintext signing keys on disk before reboot.
      7. Installs `/etc/kernel/postinst.d/zz-debian-fde` and `/etc/kernel/postrm.d/zz-debian-fde` hooks.
      8. Writes state `installed` to `/etc/debian-fde/install-state.json`.
   * **Teardown & Reboot:** Unmounts targets, signals firmware to enter setup on next boot (setting `OsIndications` bit 0), and executes reboot.

2. **Stage 2: BIOS Setup (One-Time Toggle):**
   * Machine reboots directly into the BIOS/UEFI setup interface.
   * Operator toggles **Secure Boot: ON** (activating the enrolled custom keys; firmware transitions to User Mode) and exits BIOS.

3. **Stage 3: First Boot from Disk (Trust Finalization):**
   * Machine boots into the target system under verified Secure Boot. Initramfs prompts the operator for the keyslot 0 recovery passphrase (the single documented manual passphrase unlock during provisioning).
   * **Secure Boot verification guard & TPM sealing:**
     - The first-boot service (`debian-fde-finalize.service`) reads `install-state.json` and evaluates firmware Secure Boot state (`fw_sb_state`).
     - **If Secure Boot is NOT active (`secureboot != 1` or `setup_mode != 0`):**
       - Halts (`exit 64`) with actionable instructions: *"Secure Boot is not enabled with your custom keys. Reboot into BIOS setup and toggle Secure Boot ON to complete TPM enrollment."* Volume remains safely locked by the keyslot 0 recovery passphrase.
     - **If Secure Boot is ON (`secureboot == 1` and `setup_mode == 0`):**
       - Captures the finalized baseline (`audit --init` records the verified custom Secure Boot PCR 7).
       - Performs the single Mechanism A″ enrollment into keyslot 1 bound to **{PCR 7, PCR 11}** (`enroll-tpm`, for each member container in RAID1 topologies).
       - Writes state `finalized` to `/etc/debian-fde/install-state.json`, displays audit status, and prompts operator to back up `/etc/debian-fde/keys/` off-machine via `scp`.
       - *Crash idempotency:* If interrupted before completion, the oneshot service resumes on next boot after recovery passphrase entry.

4. **Stage 4: Normal Operation:**
   * **Subsequent boots:** 100% passwordless automatic unlock bound to PCR 7 and PCR 11.

### 9.2 Kernel update (the common case)
`linux-image` upgrade → `/etc/kernel/postinst.d/zz-debian-fde` → `ukictl build`: dracut → `ukify build` with the release key as `--pcr-private-key/--pcr-public-key` (embeds this kernel's own `.pcrsig` — the single token pins only the pubkey, so **no TPM operation and no re-enrollment occur**; verified in s14) → `sbsign` → install UKI to ESP → append to manifest → prune the oldest retained kernel (ESP file + manifest entry together). Release private key required (I4, ADR-18): prompts operator interactively for `release.pem` passphrase (or non-interactively via the `DEBIAN_FDE_KEY_PASSPHRASE` credential seam) during `apt upgrade` (or loaded from an offline signing workstation); absence or wrong passphrase = loud failure. Next boot remains 100% passwordless.

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

1. Generate new release keypair (on offline medium or secure environment).
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
| Kernel update build failed | ✅ | ✅ | old signed UKI remains default; fix build (`dpkg --configure -a` after entering release key passphrase) |
| Kernel re-signed, its enrollment missing/stale | ✅ | ❌ | passphrase → `ukictl build` (re-sign + enroll) |
| Kernel updated, unsigned UKI | ❌ (SB refuses) | ❌ | re-sign via `ukictl build` |
| SB disabled / firmware keys changed | ✅ (SB off → firmware boots unsigned loaders) | ❌ (PCR 7 mismatch) | passphrase; fix SB; `audit --accept` + `enroll-tpm` re-enrolls (§9.4) |
| Firmware updated | ✅ | ✅ usually (PCR 0 not in policy) — but a dbx/UEFI-variable update can drift PCR 7 ⇒ ❌ | `audit` warns; `audit --accept` + `enroll-tpm` re-enrolls over the new PCR 7 (§9.4) |
| TPM cleared / absent / DA-locked by other tooling | ✅ | ❌ | passphrase; one re-enrollment covers all retained kernels (§9.4) |
| Disk moved to another machine | — | ❌ | sealed to *this* TPM's SRK (systemd-owned) — unseals nowhere else |
| Passphrase forgotten + TPM refuses | — | ❌ | **data loss** (documented) |
| Cache SSD physical failure (Hybrid bcache) | ❌ (ESP lost on dead SSD) | ❌ | Data intact on backing drive under writethrough. Boot live media → assemble backing device standalone → attach replacement SSD in writethrough mode → rebuild ESP in chroot (Runbook 1) |
| Single drive failure (Btrfs RAID1) | ❌ (sysroot stalls fail-closed) | ❌ | Boot live media with recovery passphrase (or signed rescue UKI) → mount degraded → `btrfs replace` (Runbook 2) |
| First boot with Secure Boot OFF | ✅ (firmware loads bootloader) | ❌ (no TPM token exists yet; prompts for recovery passphrase) | Unlock via keyslot 0 recovery passphrase → guard detects Secure Boot OFF, halts (exit 64) with instructions to enable Secure Boot in BIOS |
| Mid-finalization crash / power loss | ✅ | ❌ (keyslot 0 established) | `install-state.json` detects unfinished state → resume wizard with recovery passphrase |

## 11. Invariants

- **I1** — At rest, the volume key exists only passphrase-wrapped inside LUKS2 keyslots 0 (recovery passphrase) and 1 (single A″ TPM enrollment per volume, §7.2); the TPM-sealed passphrase exists only inside that single token's blob. Neither secret is ever plaintext on disk.
- **I2** — The ESP contains no secrets.
- **I3** — Token JSON is untrusted: tampering with it can only *break* unseal, never forge it. The PCR digests are display data; `pubkey` is *used* for verification but anchored by the keyName pinned inside the sealed object's `PolicyAuthorize` policy — a swapped key fails the policy. Every tampering outcome fails closed.
- **I4** — The release signing **private** key (`release.pem`) is encrypted at rest with AES-256 PBKDF2 (≥ 600,000 iterations, entropy floor enforced) and backed up off-machine via `scp` (ADR-18). It is the single identity for db cert, UKI signatures, and PCR policy signatures (ADR-11). Post-install signing operations (`ukictl build`, `apt upgrade`) require entering the passphrase to unlock `release.pem`.
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
- **Wave 2 scenario extensions (planned for wave 2 test harness):**
  - **S-19 (Hybrid bcache crash consistency):** simulate cache SSD detachment; assert backing drive mounts standalone in read-only/clean state; verify ESP reconstruction and writethrough re-attachment.
  - **S-20 (RAID1 member loss & degraded recovery):** simulate member detachment; assert `sysroot.mount` stalls fail-closed (no emergency shell, powers off per H-G1); assert recovery via live media / signed rescue UKI mounts degraded and rebuilds pool.
  - **S-21 (Stage 3 Secure Boot verification guard):** simulate first boot with Secure Boot OFF; assert user unlocks via keyslot 0 recovery passphrase, and first-boot service detects `secureboot != 1`, halts fail-closed (exit 64), and prevents TPM enrollment until Secure Boot is enabled in BIOS.
  - **S-22 (Handoff window immunity):** assert that no TPM token exists during the handoff window; foreign OS/USB media cannot unseal the volume, and volume key remains exclusively protected by keyslot 0 Argon2id passphrase.

## 13. Prerequisites (checked by `debian-fde doctor` — a **read-only** check, no installs; the commands that need missing packages auto-install them on demand, §8.1/ADR-15)

- x86_64 UEFI machine with **TPM 2.0** (SHA-256 PCRs) and custom-key Secure Boot enrollment possible (firmware UI or KeyTool).
- **Firmware admin password set** (manual step; keeps the evil maid out of firmware setup).
- **Firmware in Setup Mode prior to install** (`SetupMode=1`, vendor PK cleared; verified by `doctor` and `install` preflight, §9.1 preflight).
- Offline custody / off-machine backup plan for the release signing key.
- Keyslot-0 passphrase: minimum **heuristic entropy estimate** (zxcvbn-class, threshold-blocked) enforced interactively by `install` (both Wave 1 and Wave 2 paths) and by `rotate`; LUKS2 KDF pinned to **Argon2id** (`--pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000`, matching Runbook 2; the passphrase is the one offline-guessable secret, T2b). The same entropy floor applies to the `release.pem` encryption passphrase.
- ESP sized from **measured UKI size × retention + headroom** (verified in CI, §12; minimum 128 MB, recommended 512 MB for multi-kernel retention).
- Alpine Linux target; root on **Btrfs** with subvolumes (`@`, `@home`, `@snapshots`), enabling atomic `alpine-fde pre-upgrade` snapshots (ext4 optional via `--fs ext4`).
- **Host installer tools** (verified by `install` preflight before disk mutation): `apk`, `sfdisk` (`util-linux`), `cryptsetup`, `btrfs-progs` (or `e2fsprogs`), `mkfs.vfat` (`dosfstools`), optional `bcache-tools` (if `--bcache` enabled), `lsblk`.
- **Target chroot tools** (installed into rootfs via `apk`): the §3.1 additions set (`cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `linux-lts`, `tpm2-tools`, `tpm2-tss-policy`, `tpm2-tss-tcti-device`, `sbsigntool`, `openssl`, `jq`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`).

## 14. Decision record

| # | Decision | Rationale |
|---|---|---|
| ADR-1 | **Platform: Alpine Linux** (rev. C; supersedes Debian 13) | Re-adopts Alpine Linux as the primary target operating system to achieve an ultra-compact footprint (~200 MB installed vs ~1.4 GB on Debian) and minimal attack surface. Leverages standalone upstream `ukify`, `systemd-boot`, `systemd-efistub`, and `tpm2-tools`/`libtss2-policy` packages available on Alpine, coupled with a custom early-boot initramfs hook and fail-closed poweroff guards. |
| ADR-2 | Threat model: offline theft + evil maid; firmware attacks out of scope | Hardware-rooted firmware verification (Boot Guard/PSP) is OEM-fused, not user-installable |
| ADR-3 | Recovery: TPM slot + user-chosen passphrase slot | User decision; recovery-key option declined |
| ADR-4 | Boot chain: SB(custom keys) → systemd-boot → signed UKI; policy = PCR 7 + PCR 11 combined, release-key-signed | Only option satisfying G3 + G4 simultaneously |
| ADR-5 | ESP stays unencrypted | Holds only verified artifacts; encrypting it adds complexity and no security (I2) |
| ADR-6 | PCR 0..3 excluded from seal policy; covered by `audit` | Firmware updates would permanently break sealing; detection beats brittle prevention |
| ADR-7 | Hibernation unsupported; swap = zram | Hibernate image would leak volume-key state to disk |
| ADR-8 | Missing signing key during kernel update = loud failure | Silent passphrase-prompt degradation would erode the security property |
| ADR-9 | TPM seals a keyslot passphrase, not the volume key | LUKS2 keyslots wrap passphrases; conventional and validated |
| ADR-10 | Release-key signature covers the combined policy digest — single PolicyPCR call, selection {7,11}, ascending | Signing only the PCR 11 digest would leave PCR 7 unbindable — the evil-maid gate could silently vanish |
| ADR-11 | One signing identity: the release key's certificate lives in db and signs both UKIs and policy digests | Fewer keys, one custody story; PK/KEK/db keys are enrollment-only |
| ADR-12 | Minimal rootfs: `apk add --root`, explicit additions set, size budget ≤ 250 MB asserted in CI | User requirement; §3.3 is the normative recipe |
| ADR-13 | **mkinitfs / dracut initramfs with early-boot hook; Btrfs default rootfs with subvolumes (ext4 optional)** | Btrfs subvolumes (`@`, `@home`, `@snapshots`) provide native userspace rollback matching `pre-upgrade` snapshot flows. ext4 remains supported for minimal single-partition simplicity |
| ADR-14 | Signed PCR 11 via per-UKI `.pcrsig` + static PCR 7; single enrollment; kernel updates and rollback TPM-free | Unified Kernel Images assembled via `ukify` embed `.pcrsig` into synthetic initrd `/.extra/`; initramfs unseal hook verifies against release public key |
| ADR-15 | Runs from Alpine live ISO (or Debian live launcher); missing host packages installed on demand via apk, `ALPINE_FDE_NO_INSTALL=1` escape hatch, loud failure with manual list otherwise | The host provisioning environment only needs partitioning, LUKS formatting, and apk-tools; all Alpine-specific packages, kernel assembly, and EFI signing run in the target chroot |
| ADR-16 | **Key algorithms: RSA (RSA-3072 release key, RSA-2048 PK/KEK/db) over ECC** | While TPM 2.0 and Linux userspace (`systemd-cryptenroll`, `ukify`, `openssl`) support NIST P-256/P-384 ECDSA, UEFI Secure Boot firmware support for ECC certificates in NVRAM (`db`) and ECDSA Authenticode PE/COFF verification is notoriously incomplete or broken across commodity x86_64 PC motherboards. Because ADR-11 binds the release-key identity to both UEFI Secure Boot and TPM policy authorization, RSA is mandatory for universal firmware compatibility. |
| ADR-17 | **Accelerated hybrid storage: bcache under LUKS2 (LUKS over bcache, writethrough)** [Wave 2 Architecture — Design Approved, Implementation In Progress] | When `--bcache <cache_dev>` is specified to cache backing storage (`--disk`), LUKS2 dm-crypt sits on top of `/dev/bcache0`. The cache mode is pinned to `writethrough` for strict crash safety and data integrity (backing storage remains 100% consistent if cache SSD fails). All blocks written to the caching SSD are ciphertext (zero plaintext leakage, I2), and `/dev/bcache0` presents a single LUKS2 header so Mechanism A″ single-token TPM 2.0 unsealing and single-passphrase recovery apply cleanly without multi-device coordination complexity. |
| ADR-18 | **Key custody: on-target encrypted `release.pem` (AES-256 PBKDF2) with interactive upgrade passphrase** | To support single-machine autonomy without requiring an offline host during installation while preventing unencrypted private key material on disk, `release.pem` is generated in-chroot on the encrypted root volume and encrypted with AES-256 (PBKDF2 HMAC-SHA256, ≥ 600,000 iterations, entropy floor enforced; PBKDF2 conforms to standard OpenSSL PKCS#8 interoperability while Argon2id is pinned for LUKS2) in Stage 1 before reboot, with mandatory off-machine backup via `scp`. Consequently, post-install signing operations (`apt upgrade`, `ukictl build`) prompt the operator interactively for the release key passphrase. Non-interactive updates fail loudly (ADR-8) unless unlocked via a credential agent. |
