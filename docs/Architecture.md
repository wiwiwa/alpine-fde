# Alpine FDE — TPM 2.0-Backed Verified Boot & Disk Encryption

Alpine FDE makes a Linux machine that protects its data against physical theft:

1. **The root filesystem is fully encrypted** (LUKS2) and **lean** (~200 MB installed, §3.2).
2. **The key unseals automatically in the initramfs — but only if the boot process verifies as untampered** (Secure Boot + measured kernel, enforced by a TPM 2.0 signed-PCR policy).
3. **Booting requires no password** in the happy path.

---

## 1. Architectural Goals & Functional Requirements

The architecture realizes the eight core functional requirements specified in the [User Guide](UserGuide.md#functional-requirements--security-guarantees) through these technical design goals:

- G1 (Full-Disk Encryption, FR-1) — Root (and therefore `/home`) at rest on a LUKS2 volume; no plaintext secrets on unencrypted storage.
- G2 (Passwordless Verified Boot, FR-2) — Automatic unseal at boot; no interactive prompt unless verification fails.
- G3 (Anti Evil-Maid, FR-3) — "Verified" is *enforced*: an evil maid cannot boot a modified OS and still get the key.
- G4 (TPM-Free Maintenance, FR-4) — Kernel updates and rollback boots remain passwordless (no re-seal of existing enrollments, no passphrase).
- G5 (Reliable Recovery, FR-8) — One clearly documented recovery path when verification fails.
- G6 (Deterministic Testing) — Everything reproducible in CI with a software TPM.
- G7 (Lean Footprint) — The installed system is lean (§3.2): only what boot, unlock, audit, and admin need, naturally benefiting from Alpine's compact architecture without artificial bloat.

## 2. Threat model

### 2.1 In scope

| Threat | Mitigation |
|---|---|
| **T1 — Offline theft**: machine stolen powered off (suspended: RAM-extraction attacks remain out of scope, §2.2) | LUKS2 + key material sealed to this TPM; unsealed only after verified boot, in RAM only from then on |
| **T1b — Cache SSD theft (Hybrid bcache)** | An attacker extracts the caching SSD. Because LUKS2 sits on top of `/dev/bcache0`, the cache SSD holds solely AES-XTS ciphertext (no plaintext user data or key material on SSD, ADR-17). Yields no decrypted data or keys |
| **T1c — Single RAID member theft (Btrfs RAID1)** | An attacker extracts one drive from a multi-disk RAID1 array. Each member is independently wrapped in a LUKS2 container sealed to the machine's TPM; protected by the same verified-boot policy and Argon2id passphrase floor |
| **T2 — Evil maid**: brief physical access; boots USB/modified boot files to install a backdoored kernel, then steals the machine | Firmware (Secure Boot, custom keys) refuses unsigned bootloaders/kernels; TPM policy (PCR 7 bound + release-key-authorized PCR 11) refuses to unseal otherwise. Two independent mechanisms |
| **T2b — Brute force** | Sealed blob and volume key are high-entropy and unguessable; the one guessable secret is the keyslot-0 passphrase. Enforced by a passphrase entropy floor + Argon2id KDF (§3.2, §13); unlock attempts are bounded, and failure triggers immediate fail-closed poweroff (no rescue shell). Note: TPM dictionary-attack lockout does **not** increment on policy-session failures (only authValue failures) — it's an availability consideration, not a confidentiality control |
| **T2c — Provisional window** | The provisional window (prior to first-boot finalization) is minutes long and auto-closed by the first-boot finalization service (ADR-20, amended). From Stage 1 the volume is protected by the operator's own recovery passphrase in keyslot 0 (Argon2id + high entropy floor, §13), set interactively in-chroot; `release.pem` is encrypted with AES-256 PBKDF2 in Stage 1 before reboot (ADR-18). Within the window a **provisional PCR-11-only token** exists so the first boot can auto-unlock; however, the early-boot initramfs hook executes a **pre-unseal Secure Boot guard** before attempting any TPM unseal: if Secure Boot is OFF, it **blocks boot with an error** and reboots into UEFI setup after user confirmation (§8.2, §9.1 Stage 2, §10) without unsealing the volume. The disk is therefore never decrypted with Secure Boot disabled. A tampered or foreign UKI never unseals (PCR 11 moves). After finalization under verified Secure Boot, the hardware-enforced {PCR 7, PCR 11} binding applies unchanged |

### 2.2 Out of scope (non-goals)

- Malicious or reflashed **firmware** (SMM implants, SPI-flash reflash, Boot Guard defeat). The UEFI firmware is this design's **trust anchor, not a verified component** — nothing user-installable can verify it. Detection is partially possible (see `audit`, §9.5); prevention is the OEM's fused hardware (Intel Boot Guard / AMD PSP), outside user control.
- Cold-boot / RAM extraction, DMA attacks, hardware implants/loggers.
- **Hibernation & unencrypted disk swap** (a hibernate image or plaintext disk swap leaks volume-key state and decrypted memory to disk; hibernation is strictly unsupported. Ephemeral encrypted swap is supported ONLY via `--swap [size]` as an optional partition using a random key from `/dev/urandom` wiped on poweroff, Approach A). Suspend-to-RAM is fine.
- Dual-booting with foreign operating systems (multi-disk Btrfs RAID1 and bcache hybrid acceleration are in-scope per §4.1; foreign OS dual-boot is unsupported).

## 3. Platform baseline (Alpine Linux)

### 3.1 Package dependencies

Verified present in the Alpine Linux `main` and `community` components:

| Purpose | Alpine package | Note |
|---|---|---|
| Init system, service manager, getty | `openrc`, `busybox` | base |
| LUKS2 volume manipulation | `cryptsetup` | standard upstream tool |
| Boot manager + `bootctl` | `systemd-boot` | Alpine ≥ 3.24 ships 260.2 in main (`apk add systemd-boot`; subpackages `systemd-efistub`, `ukify`, `ukify-kernel-hook`) |
| EFI Boot Stub | `systemd-efistub` | measures UKI into PCR 11, injects `/.extra/` signatures |
| UKI assembly + PCR measurement/signing | `ukify`, `py3-pefile` | available in Alpine (`apk add ukify`) |
| Initramfs generator | `mkinitfs` | Alpine-native default for `linux-lts`; early-boot unlock hook is a POSIX-sh script + features.d entry (§8.2). dracut rejected: its module framework buys nothing when the unlock hook is custom, and it drags an unnecessary second init framework into the system |
| Kernel | `linux-lts` | default stable LTS kernel (or `linux-virt`) |
| TPM audit, ceremony, and policy ops | `tpm2-tools`, `tpm2-tss`, `tpm2-tss-policy`, `tpm2-tss-tcti-device` | full TSS2 and policy stack |
| EFI binary signing | `sbsigntool`, `openssl` | UKI and bootloader signing via openssl-based ceremony |
| Minimal rootfs bootstrap | `apk-tools-static` / `apk` | `apk add --root` onto mounted LUKS2 root |
| Filesystem utilities | `btrfs-progs` (default) / `e2fsprogs` (if ext4) | Btrfs tools for subvolume management; e2fsprogs if `--fs ext4` |
| Hybrid storage acceleration | `bcache-tools` | Optional; required when `--bcache` is enabled (`bcache-tools` 1.1-r5 is in Alpine ≥ 3.24 **main**) |
| Admin | `doas` or `sudo`, `openssh-server` (optional) | interactive service |

CI **host** (test sandbox) additionally uses: `qemu-system-x86_64`, `edk2-ovmf`, `swtpm`, `tpm2-tools`, `sbsigntool`, `virt-firmware` (offline OVMF vars enrollment), `dosfstools`+`mtools` (ESP image tooling, no root needed), `jq`, `python3`.

### 3.2 Minimal root filesystem composition

The installed system is deliberately minimal — only what boot, unlock, audit, and administration require:

- **Bootstrap:** `apk add --root <mnt> --initdb alpine-base` onto the mounted LUKS2 root.
- **Package policy:** explicit minimal additions installed with `--no-cache`.
- **Explicit additions:** the §3.1 boot/unlock/audit set (`cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `linux-lts`, `tpm2-tools`, `tpm2-tss-policy`, `tpm2-tss-tcti-device`, `sbsigntool`, `openssl`, `jq`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`).
- **Explicit exclusions:** no heavy display managers, no GRUB/shim (direct UEFI handover to `systemd-boot`), no documentation/man pages.
- **Fail-closed guard:** The initramfs hook enforces `poweroff -f` after failed unseal / passphrase retries, preventing drops into an interactive BusyBox emergency shell.
- **Lean footprint:** Switching to Alpine Linux naturally yields an exceptionally lean installation footprint (~200 MB); this is an inherent benefit of Alpine's musl/BusyBox base rather than an artificial requirement or architectural constraint.

## 4. Disk layout

The default filesystem for the encrypted root is **Btrfs**, configured with standard subvolumes (`@` for root, `@home` for user data, and `@snapshots` for atomic `alpine-fde pre-upgrade` snapshots). `ext4` is available via `--fs ext4`.

### 4.1 Topology Variants

```
1. Default Single-Disk (NVMe or SATA):
   p1  ESP     FAT32, sized from measured UKI size × retention + headroom (§13), NOT encrypted
   p2  LUKS2   dm-crypt container (Argon2id + TPM 2.0 token)
       └── Btrfs root filesystem (subvolumes: @ -> /, @home -> /home, @snapshots -> /.snapshots)
   [p3 Swap]   (Optional, only if installed with --swap [size]):
               Ephemeral encrypted swap partition (Approach A: random key from /dev/urandom via /etc/crypttab; wiped on poweroff)

2. Accelerated Hybrid Layout (--disk <backing> --bcache <cache_dev>):
   Fast Caching Drive (e.g. NVMe CACHE_DEV, /dev/nvme0n1):
   p1  ESP     FAT32, holds signed systemd-boot & UKIs (firmware accessible)
   p2  Cache   bcache caching set (make-bcache -C)
   Backing Drive (e.g. HDD --disk, /dev/sda):
   p1  Backing bcache backing device (make-bcache -B)
    Virtual Device:
    /dev/bcache0 ───▶ LUKS2 dm-crypt (single TPM 2.0 token)
                      └── Btrfs root filesystem (@, @home, @snapshots)
    * Cache Mode: Always "writethrough" (crash-safe; backing drive is always 100% consistent).
    * Key Invariant: LUKS2 sits ON TOP of bcache (ciphertext-only caching; no plaintext user data or key material on SSD cache).

3. Multi-Disk Btrfs RAID1 Layout (multiple --disk):
   Primary Disk (--disk #1): p1 ESP (FAT32) + p2 LUKS2 (/dev/mapper/root1)
   Secondary Disk(s) (--disk #2..): p1 LUKS2 (/dev/mapper/root2)
   All LUKS2 containers enrolled to TPM 2.0 with identical {PCR 7, PCR 11} policy;
   crypttab uses password-cache=yes so recovery passphrase prompts only once.
   Multi-device RAID1 pool: mkfs.btrfs -d raid1 -m raid1 /dev/mapper/root1 /dev/mapper/root2.

4. Accelerated Multi-Disk Hybrid Layout (--bcache <cache_dev> multiple --disk):
   Fast Caching Drive (e.g. NVMe CACHE_DEV, /dev/nvme0n1):
   p1  ESP     FAT32, holds signed systemd-boot & UKIs (firmware accessible)
   p2  Cache   bcache caching set (make-bcache -C) shared by all backing drives
   Backing Drives (e.g. HDDs /dev/sda, /dev/sdb):
   p1  Backing bcache backing device for each disk (make-bcache -B /dev/sda1, make-bcache -B /dev/sdb1)
   Virtual Devices & Encryption:
   /dev/bcache0 (backing sda1) ───▶ LUKS2 dm-crypt (/dev/mapper/root1) ┐
   /dev/bcache1 (backing sdb1) ───▶ LUKS2 dm-crypt (/dev/mapper/root2) ┴──▶ Btrfs RAID1 pool
                                                                             (@, @home, @snapshots)
   * Cache Mode: Always "writethrough" for all attached backing devices (crash-safe; backing drives remain 100% consistent).
   * Key Invariant: LUKS2 sits ON TOP of bcache on each device (ciphertext-only caching; zero plaintext on cache SSD).
   * Multi-Device TPM Binding: All member LUKS2 containers enrolled to TPM 2.0 with matching {PCR 7, PCR 11} policy; single recovery passphrase unlocks all members via crypttab caching.
```

The ESP is unencrypted **by design**: it contains only signature-verified artifacts (boot manager, UKIs). An evil maid replacing ESP contents either breaks boot (invalid signature) or boots our own signed content — and PCR 11 measurement still binds the LUKS key to the exact expected image. Zero secrets on the ESP. `/boot` stays on the encrypted root (staging area); UKIs are assembled from it and written to the ESP.

## 5. Trust chain — what "boot verified" concretely means

```
1. UEFI firmware  ──verifies signature──▶  UKI  (kernel + initramfs + cmdline, one EFI binary)
2. UKI EFI stub   ──measures components──▶ PCR 11 (sha256) + injects /.extra/.pcrsig into initrd
3. Firmware       ──records SB state/keys─▶ PCR 7
4. initramfs      ──early-boot hook──────▶ extends enter-initrd via tpm2_pcrextend,
                                            unseals ⇔ running PCRs satisfy release-key-signed
                                            PolicyAuthorize over {7,11}
5. cryptsetup open ──▶ root mounted ──▶ OpenRC ──▶ login (user password as usual)
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

The policy is the design's core trick — **resolved to a systemd/ukify-native construction with zero custom crypto (empirically proven on systemd-stub / ukify 257.x and preserved under Alpine):**

- **PCR 7 — static binding:** `--tpm2-pcrs=7` seals an exact-digest check into the policy at enroll time. SB-off or firmware-key changes break the static match ⇒ fallback. Non-bypassable: it lives in the sealed object's policy, not in metadata.
- **PCR 11 — release-key-signed policy:** `--tpm2-public-key=<release.pub> --tpm2-public-key-pcrs=11`; signatures ride in each UKI's `.pcrsig`/`.pcrpkey` sections, produced natively by `ukify build --pcr-public-key=… --pcr-private-key=…` (phase `enter-initrd`), injected into `/.extra/` by the stub at unlock and verified before `cryptsetup open`. Kernel updates are TPM-free (§9.2).
- The two policies are **ANDed** by the TPM. An evil maid must defeat *both* the firmware signature check *and* the TPM policy; dropping either term recreates the SB-off-unseal flaw, which the harness asserts cannot happen (§12 negative controls).
- Signatures are precomputed offline (no TPM-generated nonce) — `PolicyAuthorize`, not `PolicySigned`.
- Enrollment happens once per SB-state (§9.4); kernel updates need no TPM operation at all.

### 6.1 Native TPM 2.0 Sealing & Policy Signing Architecture (ADR-19)

On Alpine Linux, `systemd-cryptenroll` is not packaged. Sealing is executed natively via `tpm2-tools` (ADR-19), storing the sealed passphrase blob and policy metadata in the LUKS2 header as a standard `systemd-tpm2` token JSON.

#### 6.1.1 Policy Construction

The unseal policy is an authorized policy evaluated via a single TPM policy session:
1. **Static PCR 7 match:** Bound to the machine's custom Secure Boot baseline (`secureboot=1, setup_mode=0`, with custom `PK`/`KEK`/`db` keys).
2. **Authorized PCR 11 match (`PolicyAuthorize`):** Evaluates `systemd-efistub`'s measurement of the UKI components (kernel + initramfs + cmdline) at the `enter-initrd` phase, authorized against the release public key (`release.pub`).

Because the sealed object pins only the authority's `keyName` rather than transient kernel digests, **kernel upgrades and rollback boots require zero TPM operations** (ADR-14).

#### 6.1.2 Policy Signer (`pcrsign`)

Standard `ukify` and `systemd-measure` sign PCR 11 in isolation and cannot fold PCR 7 into a combined authorized policy. Alpine FDE provides `pcrsign` (`lib/cmd/pcrsign.sh`) to compute and sign the combined `{7, 11}` policy digest:

1. **Measure UKI components:** Predicts the expected PCR 11 digest for the UKI via `ukify build --measure` (phase path pinned to `enter-initrd`).
2. **Read PCR 7 baseline:** Retrieves the expected PCR 7 digest from the finalized baseline (`/etc/alpine-fde/baseline.json`).
3. **Compute combined trial digest:** Replicates the TPM2 `PolicyPCR` calculation for selection `{7, 11}`:
   ```text
   pcrDigest = H(d7_raw ‖ d11_raw)
   policyDigest = H(zero32 ‖ TPM_CC_PolicyPCR(0x17f, 4 bytes) ‖ marshaled-TPML_PCR_SELECTION{7,11} ‖ pcrDigest)
   ```
4. **Sign combined policy digest:** Signs `policyDigest` (32 bytes, empty `policyRef`) with `release.pem` using RSASSA-SHA256. The signed digest is validated by `TPM2_PolicyAuthorize` against the running session digest before the digest is cleared.
5. **Sealed-object policy digest:** The sealed object pins the authority's `keyName` under the double-hash `PolicyAuthorize` formula:
   ```text
   sealed = H( H(zero32 ‖ TPM_CC_PolicyAuthorize(0x0000016a, 4 bytes) ‖ keyName) ‖ policyRef(empty) )
   ```
   where `keyName` is the TPM Name of the external release public key (`tpm2_loadexternal` + `tpm2_readpublic`).
6. **Emit signature JSON:** Formats the signature into standard `systemd-measure` JSON (`pcrs: [7, 11]`), which `ukify` embeds into the UKI's `.pcrsig` PE section.

#### 6.1.3 Negative Controls & Invariants

A signature over PCRs ≠ `{7, 11}`, a signature over a stale PCR 7 digest, or a signature generated with an untrusted private key is rejected at enrollment and fails closed at boot unlock. Testing validates the complete chain against both software TPM (`swtpm`) and verified chroot acceptance test fixtures.

## 7. TPM objects and LUKS2 token model

### 7.1 TPM side (standard Storage Root Key hierarchy)

- **SRK:** Alpine FDE creates/uses a standard primary key under the owner hierarchy (Storage Root Key, SRK); Alpine FDE does not invent custom hierarchies. This is what binds the disk to *this machine's chip*.
- **Sealed object:** Alpine FDE seals the target keyslot's **passphrase** (not the volume key — same rationale as ADR-9) under the §6 policy.
- **Auth model:** policy-based authorization with no user-supplied authValue on the seal path — policy-session failures do not consume TPM dictionary-attack budget (§2.2).

### 7.2 LUKS2 metadata (travels with the disk, in the header)

- **Keyslot 0:** user-chosen recovery passphrase (decision ADR-3; entropy floor per §13). Set by the operator during the Stage 1 in-chroot credential ceremony (pre-reboot; ADR-20 amended) into the keyslot created at `luksFormat`.
- **Keyslot 1 — single enrollment (ADR-19):** one machine-generated random passphrase (≥ 256-bit entropy), sealed under static-PCR7 + pubkey-anchored signed-PCR11 (§6). Per-kernel signatures ride in each UKI's `.pcrsig` — the single token pins only the release pubkey, so kernel updates and rollback need **no TPM operations** (verified: s14, G4). (Provisional PCR-11-only enrollment happens in Stage 1; upgraded to {PCR 7, PCR 11} by the first-boot finalization service — or `alpine-fde finalize` as a manual recovery fallback — once the Secure Boot state is verified).
- **Token** (type `systemd-tpm2`; field names per the systemd schema — `tpm2_blob`, `tpm2_pcrs`, `tpm2_pcr_bank`, `tpm2_pubkey`, `tpm2_signature`, … — schema owned by systemd, not normative here): finalized tokens carry `pcrs: [7, 11]`, `pcrbank: sha256`, `pubkey: <b64 release public key>`, `signature: <b64 release-key signature over the PolicyAuthorize verification structure>`, `keyslots: [<slot>]`; during the provisional window the token carries `pcrs: [11]` only (§9.1).
- **Trust posture (I3):** the token is untrusted input. The pubkey in the token is *used* for signature verification but anchored by the keyName pinned inside the sealed object's policy — swapping it fails the policy. Tampering can only *break* unseal, never forge it. Unknown token format/version fields are ignored or rejected fail-closed.

### 8. Components

### 8.1 `alpine-fde` CLI — the user-facing tool

Ceremony and lifecycle orchestration around verified boot and storage primitives (`bin/alpine-fde`). Missing host packages are installed on demand via `apk` (or the command fails loudly with the manual install list, ADR-15). `DEBIAN_FDE_NO_INSTALL=1` / `ALPINE_FDE_NO_INSTALL=1` disables auto-install. When both spellings of a variable are set, the `ALPINE_FDE_*` name wins (canonical); CLI flags override both. `alpine-fde doctor` reports environment readiness without changing anything. All commands accept overrides for scripting/tests: `--root <dir>` (target root/`/etc/alpine-fde`), `--esp <dir|file>`, `--disk <dev|file>` (repeatable for RAID1), `--bcache <dev>` (for hybrid acceleration), `--fs <btrfs|ext4>`, `--keydir <dir>` (and test harness seam `--tcti <conf>`).

> [!IMPORTANT]
> **Strict Separation: User-Facing CLI vs. Script Entry Points:**
> `alpine-fde` is strictly the user-facing operator CLI. End users should **not** invoke internal lifecycle tasks like `finalize`. Any script-called tool or daemon (such as the first-boot OpenRC finalization service, APK triggers, or initramfs unseal hooks) must **never** use `alpine-fde` as its entry point. Instead, scripts source or invoke internal library modules directly (e.g. `lib/cmd/finalize.sh` via `fin_service_main`), preserving a clean decoupling between the user CLI and internal automation.

#### Public CLI Boundary

The `alpine-fde` executable is the single entry point reserved exclusively for manual operator actions (`install`, `doctor`, `status`, `audit`, `rotate`, `ukictl`, `bootnext`, `pre-upgrade`, `finalize`, and disaster recovery `enroll-tpm`). Full subcommand syntax, options (e.g. `--disk`, `--bcache`, `--swap`), and operational runbooks are documented in [docs/UserGuide.md §4](UserGuide.md#4-daily-operations).

#### Internal Automation & Background Components (Not for Daily Operator Use)

The following components are invoked strictly by internal scripts, hooks, or system services and do not use `alpine-fde` as their entry point:
- **`finalize` (`lib/cmd/finalize.sh` / `/etc/init.d/alpine-fde-finalize`):** Standalone one-shot first-boot trust finalization service (`alpine-fde-finalize`) in `default` runlevel. Executes `audit --init`, token upgrade to {7, 11}, and temporary Keyslot 2 purge, auto-removing itself upon completion. Also exposed via `alpine-fde finalize` as an emergency manual recovery command. End users do not normally run this.
- **`alpine-fde-audit` (`/etc/init.d/alpine-fde-audit`):** Lightweight oneshot OpenRC service in `default` runlevel scheduled with `after *` to run last immediately before the login prompt. Compares live measurements (PCR 0..3, PCR 7, event log) against `/etc/alpine-fde/baseline.json` on every boot, logs anomalies to syslog/dmesg, updates `/etc/issue` / `/etc/motd`, and exits immediately (0 MB resident RAM, 0 background CPU). Running last ensures warnings are not scrolled off-screen by other daemon startup logs.
- **`alpine-fde.sh` (`/etc/profile.d/alpine-fde.sh`):** Interactive shell login hook that checks the audit status upon user login and prints a security alert banner if firmware drift is detected.
- **`pcrsign` (`lib/cmd/pcrsign.sh`):** Standalone signer routine invoked internally during UKI builds to compute release-key signatures over combined {7,11} policy digests.
- **`enroll-tpm` (`lib/cmd/enroll-tpm.sh`):** Core enrollment routine called internally by `ukictl build`, and exposed to operators during specific disaster recovery runbooks.
- **`provision` (`lib/cmd/provision.sh`):** Platform key generation and baseline initialization routines used by `install`.

### 8.2 Unlock path & Initramfs Hook

- **Early-Boot Unseal Hook:**
  - When `systemd-efistub` boots the UKI, it measures the UKI sections into PCR 11 and places `.pcrsig` and `.pcrpkey` into the synthetic initrd at `/.extra/tpm2-pcr-signature.json` and `/.extra/tpm2-pcr-public-key.pem`.
  - In the initramfs, the early-boot unlock hook executes:
    1. **Pre-Unseal Secure Boot Guard:** Mounts `efivarfs` and inspects `SecureBoot` and `SetupMode`. If Secure Boot is disabled (`secureboot != 1 || setup_mode != 0`), the initramfs/initrd **strictly refuses to boot**: halts with a fatal error, displays an explicit notice that Secure Boot must be enabled in UEFI setup, waits for user confirmation (e.g. *Press Enter to reboot*), and executes immediate reboot into UEFI firmware setup. The container is **never unsealed** while Secure Boot is OFF.
    2. Extends `"enter-initrd"` into PCR 11 via `tpm2_pcrextend` to align with `ukify`'s phase measurement prediction.
    3. Starts a TPM policy session evaluating `PolicyPCR` (PCR 7 + PCR 11) and `PolicyAuthorize` (matching `/.extra/tpm2-pcr-signature.json`).
    4. Unseals the keyslot-1 secret and unlocks the container via `cryptsetup open`.
    5. If the TPM policy fails:
       - Displays the exact **diagnostic failure reason** (e.g. `PCR 7 / PCR 11 mismatch` or communication fault).
       - Prints the **security warning** alerting the operator that boot integrity verification failed and unexpected prompts may indicate an evil-maid attack.
       - Prompts for the keyslot 0 recovery passphrase with a bounded retry counter (`attempt 1 of 3`).
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
- **Trust state & finalization observability:** Finalization status is derived directly from ground-truth storage state rather than a synthetic tracking file: the LUKS2 header token (`pcrs: [7, 11]` vs `pcrs: [11]`), Keyslot 2 presence (purged at finalization), and `/etc/alpine-fde/baseline.json` (`expected_pcr7` contains the final SHA-256 digest vs `"pending"`).
- **ESP layout convention:**
  ```
  ESP:/EFI/systemd/systemd-bootx64.efi
  ESP:/EFI/Linux/alpine-fde-<kernel-version>.efi     (one UKI per kernel)
  ```
  Persisted as `ESP_PATH` in `/etc/alpine-fde/alpine-fde.conf` (default `/efi`).
- **Key material** `/etc/alpine-fde/keys/` — release public key, db/KEK/PK certs; private release key (`release.pem`) is encrypted at rest (AES-256 PBKDF2) in Stage 1 before reboot and follows a Zero-Exfiltration posture (never exported or backed up off-machine; I4, ADR-18).

## 9. Lifecycle flows

### 9.1 Provision & install lifecycle (unattended-until-reboot install + in-chroot credential ceremony + first-boot auto-finalization, ADR-20 amended)

The lifecycle transitions from **provisional** to **finalized**, determined directly from ground-truth storage state (LUKS2 token PCR binding `{7, 11}` vs `{11}`, and `baseline.json`'s `expected_pcr7`). "Unattended" means unattended **until reboot** (ADR-20 amended): Stage 1 ends with an interactive in-chroot credential ceremony, and the first reboot unseals automatically and runs trust finalization in the background before the login prompt, with zero console input between power-on and finalization.

#### Keyslot & Trust Choreography by Lifecycle State
| State | Keyslot 0 | Keyslot 1 | Token & Baseline | Service & Observability |
|---|---|---|---|---|
| **Provisional** (post-install / first boot) | **Operator's Recovery Passphrase** (set in-chroot; Argon2id) | Sealed Provisional Secret (temporary Keyslot 2 exists) | **Provisional Token**: `PolicyAuthorize` over **PCR 11 only**; `expected_pcr7: "pending"` | `alpine-fde-finalize` service active in runlevel; `status` reports provisional |
| **Finalized** (permanent operation) | Permanent Recovery Passphrase | Finalized Sealed TPM Passphrase (Keyslot 2 purged) | **TPM 2.0 Token**: Bound to **PCR 7 + PCR 11**; `expected_pcr7` finalized digest | `alpine-fde-finalize` unregistered and deleted; `status` reports finalized |

1. **Stage 1: Interactive Credential Ceremony + Unattended Host Bootstrap & In-Chroot Provisioning (from live USB; Secure Boot OFF, Setup Mode ON):**
   * **Host preflight check:**
     - Asserts firmware is in **Setup Mode** (`SetupMode=1`, vendor PK cleared). If `SetupMode != 1`, fails closed (`exit 64`) with instructions to clear vendor PK in BIOS before disk partitioning (preventing NVRAM write failures, §9.1 preflight).
     - Asserts presence of required host utilities (`apk`, `sfdisk`, `cryptsetup`, `mkfs.vfat`, filesystem utilities `btrfs-progs` or `e2fsprogs`, optional `bcache-tools` if `--bcache`, and `lsblk`) **before any disk mutation**. On Alpine live hosts, missing packages are installed on demand via `apk` (unless `ALPINE_FDE_NO_INSTALL=1`); missing tools trigger an immediate fail-closed abort (`exit 64`) instructing the operator to install them.
   * **Host bootstrap:**
      - **Partitioning & block layer setup:** Partitions disk(s) and initializes the block layer according to the target topology variant defined in [§4.1](#41-topology-variants) (single-disk, `--bcache` accelerated hybrid, or multi-disk Btrfs RAID1; optional `--swap` partition if requested).
      - **LUKS2 creation:** Formats target LUKS container(s) with an **internal ephemeral installation key** generated in `/dev/shm` (mode `0600`) into a temporary keyslot (Argon2id). This key authorizes the keyslot mutations of the credential ceremony below and is purged at finalization (Stage 2); it is never persisted beyond the provisional window.
      - **Filesystem setup:** Formats root container(s) with Btrfs (`mkfs.btrfs`) and creates standard subvolumes (`@`, `@home`, `@snapshots`); mounts `@` to `<mnt>`, `@home` to `<mnt>/home`, `@snapshots` to `<mnt>/.snapshots`, and ESP to `<mnt>/efi`. (If `--fs ext4` is passed, formats ext4 and mounts flat).
     - Runs `apk add --root <mnt> --initdb alpine-base` to install minimal base Alpine.
     - Drops initial system configurations (`repositories`, `fstab`, `crypttab`).
     - Bind-mounts `/dev`, `/proc`, `/sys`, and `/sys/firmware/efi/efivars` into `<mnt>`.
   * **In-chroot provisioning (strictly ordered sequence):**
      1. `apk add --no-cache` installs the §3.1 explicit-additions set (`cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `linux-lts`, `tpm2-tools`, `tpm2-tss-policy`, `tpm2-tss-tcti-device`, `sbsigntool`, `openssl`, `jq`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`), user account, `doas` (wheel `doas.conf`), and OpenRC networking.
      2. Writes initial baseline with `pcr7: "pending"` (following `provision stage1` semantics).
      3. Provisions platform keys: generates `PK`, `KEK`, `db`, and `release.pem` on the encrypted root volume (mode `0600`).
      4. Enrolls authenticated variable update packets (`.auth`) into UEFI NVRAM via `efivarfs` in **strict order**: `db → KEK → PK (last)` (writing PK last cleanly transitions firmware out of Setup Mode, I-3).
      5. Builds signed `systemd-bootx64.efi` and initial signed UKI with `.pcrsig` via `ukictl build`.
      6. **Provisional TPM enrollment:** Derives `PolicyAuthorize` policy digest over **PCR 11 only** matching the UKI signature. Uses `tpm2_create` under the PCR 11 policy to seal keyslot 1 with a random volume passphrase, enabling automatic passwordless unlock on first boot.
      7. Installs `/etc/apk/triggers/alpine-fde.trigger`, `/etc/init.d/alpine-fde-finalize`, `/etc/init.d/alpine-fde-audit` (oneshot boot service), and `/etc/profile.d/alpine-fde.sh` (login audit).
      8. **Credential ceremony (interactive, final step before reboot):** Run while the ephemeral install key is still staged. By executing all disk formatting, package downloads, NVRAM writes, and UKI compilation first, any system or firmware failure aborts immediately, keeping the fail-debug loop fast without prompting for passwords:
          - **User account password** — the account becomes loginable.
          - **LUKS2 recovery passphrase** — enrolled into keyslot 0 (Argon2id, §13 entropy floor), the mutation authorized by the ephemeral install key while staged.
          - **Release-key passphrase** — `release.pem` encrypted with AES-256 PBKDF2 ($\ge$ 600,000 iterations, ADR-18), permissions tightened to `0400`.
   * **Teardown & Direct Reboot:** Unmounts targets, securely scrubs ephemeral key from `/dev/shm`, and executes direct reboot to disk.

2. **Stage 2: First Boot — Automatic Trust Finalization (OpenRC service `/etc/init.d/alpine-fde-finalize`):**
   * Machine powers on under custom Secure Boot keys. Firmware verifies `systemd-boot` and the UKI.
   * `systemd-efistub` measures UKI sections into **PCR 11**.
   * In the initramfs, the early-boot hook executes the **Pre-Unseal Secure Boot Guard**:
     - Evaluates `secureboot == 1 && setup_mode == 0`. If Secure Boot is OFF, the initrd **strictly refuses to boot**: halts with a fatal error, displays an explicit notice that Secure Boot must be enabled in UEFI setup, waits for user confirmation (e.g. *Press Enter to reboot*), and executes immediate reboot into UEFI firmware setup. The container is **never unsealed** while Secure Boot is OFF.
     - If Secure Boot is ON, the hook evaluates the **Provisional Token** in keyslot 1 against PCR 11 and unseals the root container **100% automatically with zero password prompts**.
   * Finalization is **auto-called before login on first boot, never by the user** (ADR-20 amended). The OpenRC service `/etc/init.d/alpine-fde-finalize` runs automatically before reaching the login prompt:
     1. **Detects provisional state:** Inspects ground-truth storage state (LUKS2 token carries PCR 11 only, or `baseline.json` has `expected_pcr7: "pending"`).
     2. **Baseline:** captures the verified PCR 7 baseline (`audit --init`), writing the final digest to `/etc/alpine-fde/baseline.json`.
     3. **Purge:** removes the ephemeral install keyslot (Keyslot 2) while authorized by the standing provisional token.
     4. **Token upgrade:** provisional {PCR 11} → **{PCR 7, PCR 11}** (for each member container in RAID1 topologies), retiring the provisional token.
     5. **Self-removal:** upon successful completion, removes itself from OpenRC runlevels (`rc-update del alpine-fde-finalize default`) and deletes its service script (`rm -f /etc/init.d/alpine-fde-finalize`), leaving zero residual services or background overhead on future boots.
   * Any step failure ⇒ leaves the provisional token and pending baseline in place, leaves the service script installed, logs the warning, and automatically retries on the next boot.
   * Key custody follows the Zero-Exfiltration posture (I4): key material remains strictly confined to the encrypted root volume and is never exported off-machine.

3. **Stage 3: Normal Operation:**
   * **Subsequent boots:** 100% passwordless automatic unlock bound to PCR 7 and PCR 11. The oneshot `alpine-fde-audit` OpenRC service runs in `default` runlevel scheduled with `after *` to run last immediately before the login prompt, verifying static PCR 0–3, PCR 7, and the TCG event log against `/etc/alpine-fde/baseline.json`. It logs anomalies to syslog/dmesg and updates `/etc/issue` / `/etc/motd` before exiting (0 MB resident RAM, 0 background CPU), ensuring warnings remain visible on screen.
   * **Login checks:** Interactive logins (`/etc/profile.d/alpine-fde.sh`) check audit status upon shell startup and display immediate security alert banners if firmware drift is detected.
   * **Drift Recovery:** If PCR 7 drifts (BIOS update) or PCR 11 drifts (kernel update anomaly), initramfs prompts for the keyslot 0 **recovery passphrase** with diagnostic reasons and security warnings. If entered correctly, system unlocks and allows re-baselining (`audit --accept && enroll-tpm`). After 3 failed attempts, system executes immediate `poweroff -f`.

### 9.2 Kernel update (the common case)
`linux-lts` upgrade → `/etc/apk/triggers/alpine-fde.trigger` → `ukictl build`: initramfs → `ukify build` with the release key as `--pcr-private-key/--pcr-public-key` (embeds this kernel's own `.pcrsig` — the single token pins only the pubkey, so **no TPM operation and no re-enrollment occur**; verified in s14) → `sbsign` → install UKI to ESP → append to manifest → prune the oldest retained kernel (ESP file + manifest entry together). Release private key required (I4, ADR-18): prompts operator interactively for `release.pem` passphrase (or non-interactively via the `ALPINE_FDE_KEY_PASSPHRASE` credential seam) during `apk upgrade`; absence or wrong passphrase = loud failure. Next boot remains 100% passwordless.

### 9.3 Rollback after failed upgrade
Up to 3 UKIs stay on the ESP, each carrying its own release-key `.pcrsig`; the single TPM 2.0 enrollment (§7.2) serves them all — the single token pins only the release pubkey, and each retained UKI's signature covers exactly its own measurement ⇒ booting any retained kernel (boot menu, `bootnext`, or loader.conf default) is fully passwordless: the token's policy is satisfied by whichever retained kernel's `.pcrsig` the stub presents (verified in s02/s14). Signatures are release-key-signed, so an attacker cannot add entries — but note the deliberate tradeoff: retained old kernels *remain bootable and auto-unlocking*, including ones with known CVEs. The current + 2 retention window bounds that exposure; extend or prune deliberately. Complement: `pre-upgrade` snapshots (btrfs roots only), since an old *kernel* doesn't undo a bad *userspace* upgrade.

### 9.4 Recovery & rotation
Unseal fails ⇒ passphrase prompt (keyslot 0) ⇒ fix the cause. Which step is stale depends on the failure (§10):

- **Missing/stale enrollment** (UKI re-signed with no standing token, or the token was removed): `ukictl build`'s ensure-once enroll (or `enroll-tpm`) re-enrolls. No broader ceremony.
- **PCR 7 drift** (dbx/UEFI-variable change, SB config change): confirm the drift is benign (`audit` output) → `alpine-fde audit --accept` re-baselines → re-sign retained UKIs with the updated PCR 7 baseline (or re-enroll; [Runbook 3](UserGuide.md#runbook-3-pcr-7-drift-after-firmwarebios-update)). The volume key is never re-encrypted.
- **Cleared TPM / lost sealed blobs**: one re-enrollment covers all retained kernels (`enroll-tpm`/`ukictl build` ensure-once; ONE fresh enrollment — new keyslot + token sealed to the fresh TPM's SRK; the per-UKI `.pcrsig` files and their signatures are unchanged — verified in s17).

`rotate` changes the keyslot-0 passphrase only; run it whenever the passphrase may have been exposed.

### 9.5 Firmware audit (detective control, not preventive)
`alpine-fde audit` re-reads PCR 0..3 + the TCG event log and compares them against the baseline recorded in `/etc/alpine-fde/baseline.json`. Event-log check, **v1 scope (ratified): presence + size + whole-file sha256** vs the baseline record — a tripwire, not a parser: any post-baseline change, including a benign append, flips the sha256 and reports as drift. Refinement (parsing pre-OS events, structured comparison) is future work. Drift ⇒ reports detailed diffs to console and syslog (firmware update? settings change? or tampering?). This cannot *prevent* firmware attacks (§2.2) but converts silent reflashes into visible alerts.
- **Automated Boot Audit (Oneshot):** The `alpine-fde-audit` OpenRC service runs in `default` runlevel scheduled with `after *` as a lightweight oneshot script, evaluating static boot-time PCRs and event log against the baseline last before the login prompt. It updates `/etc/issue` and `/etc/motd` if drift is detected, logs to syslog, and immediately terminates (0 MB resident RAM, zero background daemons).
- **Login Visibility (Oneshot):** `/etc/profile.d/alpine-fde.sh` runs once when an interactive shell starts, printing a security alert banner if firmware drift is detected, and exits.
- **Manual / Runbook Inspection:** Executed directly by the operator via `alpine-fde audit` to inspect firmware integrity or accept updates via `alpine-fde audit --accept`.
- **Zero Resident Overhead:** Operates strictly via oneshot triggers; no background monitoring daemons or persistent processes.

### 9.6 Release-key rotation (compromise or scheduled)
Two ordering constraints drive the sequence: db/dbx changes reach PCR 7 only after a reboot, **and** binaries the firmware verifies must remain verifiable across the transition — PE binaries can carry **multiple signatures**, so new-key signatures are **appended** while the old ones stay until final revocation.

1. Generate new release keypair on the target machine.
2. Re-sign (K2 only) and install: **all retained UKIs** + boot manager + fallback loader → ESP. (Empirical correction, s16: dual-signing does NOT survive revocation — with K1 in dbx, OVMF rejects a dual-signed image outright; K2-only signatures are required *before* the revoke step.)
3. Reboot — firmware verifies via the K2 signature; PCR 7 unchanged yet, so auto-unseal **still works**.
4. Apply the db change (new cert) **and** the old key's dbx revocation in one firmware/KeyTool step (takes effect next boot).
5. Reboot — firmware verifies via the new signature (old one is now revoked and ignored by firmware policy). PCR 7 has shifted ⇒ **one-time passphrase event**; `alpine-fde audit --accept` re-baselines (records the final PCR 7 value).
6. `ukictl build` re-signs **all retained UKIs** over the new d7 with K2 (old signatures already stripped at step 2); rewrites manifest; re-enrolls under the K2-anchored token (re-captures the new PCR 7).
7. Verify passwordless boot. The old key is now revoked and unused.

## 10. Failure matrix — fail-closed by construction

| Condition | Boots? | Auto-unlock | Way out |
|---|---|---|---|
| Current kernel | ✅ | ✅ | — |
| Old retained kernel (rollback) | ✅ | ✅ | its own `.pcrsig`; the single token pins the release pubkey (§7.2) |
| Kernel update build failed | ✅ | ✅ | old signed UKI remains default; fix build (`apk fix` after entering release key passphrase) |
| Kernel re-signed, its enrollment missing/stale | ✅ | ❌ | passphrase → `ukictl build` (re-sign + enroll) |
| Kernel updated, unsigned UKI | ❌ (SB refuses) | ❌ | re-sign via `ukictl build` |
| SB disabled (post-install / normal boot) | ✅ (firmware loads bootloader) | ❌ (initrd strictly refuses to boot) | Initramfs pre-unseal guard halts boot, displays notice, and reboots to UEFI setup. Volume is NEVER unsealed with Secure Boot OFF. |
| SB keys changed / BIOS update (SB active) | ✅ | ❌ (PCR 7 mismatch) | passphrase; confirm drift via `audit`; `audit --accept` + `enroll-tpm` re-enrolls (§9.4, [Runbook 3](UserGuide.md#runbook-3-pcr-7-drift-after-firmwarebios-update)) |
| Firmware updated | ✅ | ✅ usually (PCR 0 not in policy) — but a dbx/UEFI-variable update can drift PCR 7 ⇒ ❌ | `audit` warns; `audit --accept` + `enroll-tpm` re-enrolls over the new PCR 7 (§9.4) |
| TPM cleared / absent / DA-locked by other tooling | ✅ | ❌ | passphrase; one re-enrollment covers all retained kernels (§9.4) |
| Disk moved to another machine | — | ❌ | sealed to *this* TPM's SRK — unseals nowhere else |
| Passphrase forgotten + TPM refuses | — | ❌ | **data loss** (documented) |
| Cache SSD physical failure (Hybrid bcache, single or multi-disk) | ❌ (ESP lost on dead SSD) | ❌ | Data intact on all backing drives under writethrough. Boot live media → assemble backing device(s) standalone → attach replacement SSD in writethrough mode → rebuild ESP in chroot ([Runbook 1](UserGuide.md#runbook-1-broken-cache-ssd--esp-rebuild-hybrid-bcache-setup)) |
| First boot under custom Secure Boot | ✅ | ✅ | Unseals via Provisional Token (PCR 11); the OpenRC service `alpine-fde-finalize` auto-finalizes, purges Keyslot 2, and removes itself from runlevels and disk (zero console input) |
| First boot with Secure Boot OFF (provisional window) | ✅ (firmware loads bootloader) | ❌ (initrd strictly refuses to boot) | Initramfs pre-unseal guard detects `secureboot != 1`: the initrd **strictly refuses to boot**, halts with a fatal error, displays an explicit notice that Secure Boot must be enabled in UEFI setup, waits for user confirmation (e.g. *Press Enter to reboot*), and executes immediate reboot into UEFI firmware setup. Volume is NEVER unsealed with Secure Boot OFF. |
| PCR 7 or PCR 11 drift after finalization | ✅ | ❌ | Initramfs displays diagnostic reason + security warning, prompts for recovery passphrase; 3 failed attempts power off immediately (`poweroff -f`); unlock enables `audit --accept` + `enroll-tpm` re-baseline |
| Mid-finalization crash / power loss | ✅ | ✅ | LUKS2 token ({11} vs {7, 11}) and `baseline.json` indicate provisional state; the `alpine-fde-finalize` service retries on next boot until completed and self-removed; zero user intervention needed. |

## 11. Invariants

- **I1** — At rest, the volume key exists only passphrase-wrapped inside LUKS2 keyslots 0 (recovery passphrase) and 1 (single TPM 2.0 enrollment per volume, §7.2); the TPM-sealed passphrase exists only inside that single token's blob. Neither secret is ever plaintext on disk. Scoping: the install-time ephemeral keyslot is a *transient* of the provisional window only (§9.1) — it is purged at first-boot finalization (§9.1 Stage 2), so this two-keyslot at-rest state holds throughout normal operation after finalization.
- **I2** — The ESP contains no secrets.
- **I3** — Token JSON is untrusted: tampering with it can only *break* unseal, never forge it. The PCR digests are display data; `pubkey` is *used* for verification but anchored by the keyName pinned inside the sealed object's `PolicyAuthorize` policy — a swapped key fails the policy. At unlock the hook verifies the booting UKI's **own** `.pcrsig` entry (entry `sig` over entry `pol`) against the release key — not the token's `tpm2-signature`, which covers only the enroll-time policy — so any retained kernel's entry admits the standing token passwordless (G4, §9.3) while forged, foreign-signed, relabeled, or missing entries still fail closed (PolicyAuthorize keyName + PolicyPCR). Every tampering outcome fails closed.
- **I4** — The release signing **private** key (`release.pem`) is encrypted at rest with AES-256 PBKDF2 (≥ 600,000 iterations, entropy floor enforced) and follows a **Zero-Exfiltration** posture (ADR-18): it remains strictly on-target within the encrypted root filesystem and is never exported or backed up off-machine. It is the single identity for db cert, UKI signatures, and PCR policy signatures (ADR-11). Post-install signing operations (`ukictl build`, `apk upgrade`) require entering the passphrase to unlock `release.pem`. If the root volume is permanently destroyed, verified boot is restored by resetting firmware Secure Boot keys to Setup Mode and reinstalling.
- **I5** — After finalization, a UKI unseals iff it is signature-valid (firmware gate) **and** the trial digest over the *current* PCR 7 + PCR 11 values is release-key-signed and present in the token (TPM gate). Everything else fails closed. (The provisional-window exception — PCR 11 only — is a documented, time-bounded carve-out, §9.1 Stage 2 / ADR-20 amended.)
- **I6** — The unlock path is the early-boot initramfs hook with strict fail-closed poweroff guards; CI audits the initrd inventory against an allowlist policy: no compilers, package tools, or interactive shells.

## 12. Testing strategy (swtpm + QEMU/OVMF)

Every row of §10 is an automated scenario on a software TPM (swtpm) under QEMU with OVMF Secure Boot (custom keys enrolled offline via `virt-fw-vars`). Guest userspace is a **pinned Alpine rootfs artifact** (downloaded once, SHA256-pinned; populated into the LUKS image in-guest by scenario S-00). Results are asserted from serial-console sentinels. **Hardware KVM (`/dev/kvm`) is required**: the harness probes KVM up front and fails closed (rc 64) when unusable — TCG software emulation is not a supported execution mode (it blows the per-scenario time budget and corrupts the serial console); the only opt-out is an explicit `ALPINE_FDE_ACCEL=tcg` (or `DEBIAN_FDE_ACCEL=tcg`), never a silent downgrade.

- **S-00 (bootstrap):** first boot of the freshly installed disk from a **harness installer UKI** (its initrd embeds the pinned rootfs artifact and the LUKS passphrase) — **passphrase unlock** (documented one-time; no enrollment exists yet) → populate minimal rootfs (§3.2) + configure OpenRC networking/getty → `audit --init` finalizes the baseline (**before** any UKI chain work — pcrsign needs the finalized d7) → poweroff. Produces the pristine disk cached **at end of S-00b** (post-enrollment) and reused by every scenario; asserts §3.2 minimal package composition and system health. The artifact itself is produced by a **CI artifact-build job that runs `install` end-to-end in QEMU** (credential prompts scripted — they are the only interactive input, ADR-20 amended; so the installer, apk transaction, and trims are exercised, not bypassed) and emits the SHA256-pinned artifact. S-00b: the `ukictl build` product boots, then enrollment runs **from the guest** (has TPM access + finalized baseline) via the **production CLI in the guest** — `/opt/alpine-fde/bin/alpine-fde` (`ukictl build`'s ensure-once enroll / `enroll-tpm`) — replacing the previous harness stand-in; then cache.
- **S-01 happy path (headline):** enrolled vars, signed UKI, enrolled TPM → boots to `login:` with **zero input**; no fallback prompt; PCR 11 at the unlock point == ukify's enter-initrd prediction (compared via event log / pre-unlock reading — the final register additionally contains later pcrphase extensions); ESP-size assertion.
- **Tamper rows:** unsigned UKI (SB refusal asserted); SB-off boot after finalization (unseal refusal + fallback prompt asserted — the {PCR 7, PCR 11} binding; within the provisional window the accepted PCR-11-only behavior is covered by S-21/S-22); stale enrollment (a UKI whose `.pcrsig` is missing/stale for the standing token, or the token removed — s03); token tampering (I3: refusal, never grant) — including the trap case: **SB off + tampered token metadata + otherwise-legitimate PCR 11 signature ⇒ unseal must still fail**; tampered cmdline on an otherwise-signed UKI (the compromised-signer vector, **as implemented in s07**: a release-key-signed UKI variant whose `.cmdline` carries one extra word — the stub measures the tampered cmdline into PCR 11, the trial digest drifts away from every signed `.pcrsig`, unseal refused); cleared/absent TPM; disk moved to foreign TPM.
- **Sentinel pinning:** all console greps consume `tests/sentinels-257.13.txt` (or versioned sentinel fixtures), with per-line provenance kept in sections. On the Alpine platform the unlock-path sentinels change contract: the mkinitfs unseal hook emits its own pinned strings (the upstream systemd-cryptsetup/cryptenroll strings do not exist there), and systemd-boot 260.2 console output needs a versioned fixture — the 257.13 file remains the provenance record for the harness-side sentinels until that fixture lands. Key anchors: success `Volume … activated with a LUKS token.`; happy-path proof `Adding PCR signature policy.`; fallback prompt regex `^Please enter .* for disk`; retry cap `Too many attempts to activate; giving up.`; TPM-absent and DA-locked sentinels (both must fall back, never hang; DA simulated via `tpm2_dictionarylockout` on swtpm); **emergency shell must NEVER appear** (G3: immediate poweroff on failure).
- **Recovery drills:** PCR 7 drift runbook end-to-end (drift → `audit --accept` → re-sign → passwordless boot); release-key rotation (§9.6; s16 pins the corrected outcome — **dual-signing does NOT survive revocation**: with K1 in dbx, OVMF rejects any image carrying a revoked signature outright, so K2-only signatures are required *before* the revoke step; the wrong-order negative control asserts the dual-signed + revoked boot fails closed); TPM-clear re-enroll.
- **Prediction checks:** ukify's predicted PCR 11 (enter-initrd phase) asserted equal to the PCR 11 state at the unlock point in every scenario that reaches the UKI stub — compared against the TCG event log / the guest's pre-unlock reading, **not** the final register (post-boot PCR 11 additionally contains leave-initrd and later pcrphase extensions). The outer `sbsign` signature does not alter stub-measured sections.
- **Signing negative controls (§6.1):** signature over pcrs ≠ {7,11}; signature over a stale d7; signature from a foreign key — every variant must be rejected at enrollment or fail closed at unlock.
- **Initrd inventory audit** on every build (I6). Harness self-tests (swtpm fixture, vars enrollment, disk fixture) run before e2e so infra breakage reports as harness-failure, not scenario-failure.
- **Interop oracle (ADR-19, CI-only):** a unit suite runs upstream `systemd-cryptsetup`/`cryptenroll` (a pinned upstream-systemd 257 mini rootfs) under `bwrap` against a swtpm-backed TPM and asserts reverse interoperability: a token produced by our native sealer is enrolled and unsealed by upstream systemd code, and tampered/schema-drifted tokens are refused. Scope guards: the oracle never runs in `install`, the initramfs, or any shipped path; the Alpine target carries no bwrap/oracle footprint; the oracle exists purely to pin the self-authored token schema and policy construction against upstream behavior.
- **Scenario extensions (planned for the test harness):**
  - **S-19 (Hybrid bcache crash consistency):** simulate cache SSD detachment; assert backing drive mounts standalone in read-only/clean state; verify ESP reconstruction and writethrough re-attachment.
  - **S-20 (RAID1 member loss & degraded recovery):** simulate member detachment; assert `sysroot.mount` stalls fail-closed (no emergency shell, powers off per G3); assert recovery via live media / signed rescue UKI mounts degraded and rebuilds pool.
  - **S-21 (First-boot Secure Boot verification guard):** simulate first boot with Secure Boot OFF; assert the initramfs pre-unseal guard detects `secureboot != 1` before unsealing, halts boot with an error, prompts for user confirmation, and reboots to UEFI setup without unsealing the disk or proceeding to multi-user login — asserting that the volume is never decrypted and no TPM enrollment occurs until Secure Boot is enabled in BIOS.
   - **S-22 (Provisional-window immunity):** during the provisional window, foreign OS/USB media — and any UKI other than the exact signed one — cannot unseal the volume (PCR 11 moves); the operator's keyslot 0 Argon2id recovery passphrase (set in Stage 1) remains the only fallback. After finalization, the {PCR 7, PCR 11} binding applies unchanged.
   - **S-23 (Accelerated multi-disk hybrid crash consistency & degraded recovery):** simulate cache SSD detachment in a multi-backing-disk hybrid setup; assert both backing drives mount standalone in clean state; assert single backing drive detachment retains bootability/mountability under surviving backing drive and bcache cache.
   - **S-24 (Install credential ceremony & provisional UKI unseal):** run `alpine-fde install --disk ...` with the three credential prompts scripted at the end of Stage 1 (user password, recovery passphrase, release passphrase — the only interactive input; ADR-20 amended); assert zero further input until the reboot, keyslot 0 holds the Argon2id recovery passphrase, `release.pem` is encrypted, provisional token is enrolled pre-reboot, and the install reboots directly to disk; assert first boot unlocks automatically with zero keystrokes.
   - **S-25 (First-boot auto-finalization & PCR 7 upgrade):** under verified Secure Boot with provisional token, assert the OpenRC service completes with **zero console input**: `audit --init` baseline captured; keyslot 1 upgraded to {PCR 7, PCR 11} (authorized by re-unsealing the standing provisional token, no persisted credential); ephemeral install keyslot purged; service unregisters and deletes itself; subsequent reboot unseals passwordlessly under {PCR 7, PCR 11}.
   - **S-26 (Provisional tamper negative control):** boot tampered UKI; assert provisional unseal fails and system halts fail-closed without interactive shell.

## 13. Prerequisites (checked by `alpine-fde doctor` — a **read-only** check, no installs; the commands that need missing packages auto-install them on demand, §8.1/ADR-15)

- x86_64 UEFI machine with **TPM 2.0** (SHA-256 PCRs) and custom-key Secure Boot enrollment possible (firmware UI or KeyTool).
- **Firmware admin password set** (manual step; keeps the evil maid out of firmware setup).
- **Firmware in Setup Mode prior to install** (`SetupMode=1`, vendor PK cleared; verified by `doctor` and `install` preflight, §9.1 preflight).
- Recovery passphrase safely stored off-machine (the sole required offline credential).
- Keyslot-0 passphrase: minimum **heuristic entropy estimate** (zxcvbn-class, threshold-blocked) enforced interactively by `install` (all install paths) and by `rotate`; LUKS2 KDF pinned to **Argon2id** (`--pbkdf-memory 1048576 --pbkdf-parallel 4 --iter-time 2000`, matching [Runbook 2](UserGuide.md#runbook-2-multi-disk-raid1-member-replacement--re-sync); the passphrase is the one offline-guessable secret, T2b). The same entropy floor applies to the `release.pem` encryption passphrase.
- ESP sized from **measured UKI size × retention + headroom** (verified in CI, §12; minimum 128 MB, recommended 512 MB for multi-kernel retention).
- Alpine Linux target; root on **Btrfs** with subvolumes (`@`, `@home`, `@snapshots`), enabling atomic `alpine-fde pre-upgrade` snapshots (ext4 optional via `--fs ext4`).
- **Host installer tools** (verified by `install` preflight before disk mutation): `apk`, `sfdisk` (`util-linux`), `cryptsetup`, `btrfs-progs` (or `e2fsprogs`), `mkfs.vfat` (`dosfstools`), optional `bcache-tools` (if `--bcache` enabled), `lsblk`.
- **Target chroot tools** (installed into rootfs via `apk`): the §3.1 additions set (`cryptsetup`, `systemd-boot`, `systemd-efistub`, `ukify`, `linux-lts`, `tpm2-tools`, `tpm2-tss-policy`, `tpm2-tss-tcti-device`, `sbsigntool`, `openssl`, `jq`, `btrfs-progs` or `e2fsprogs`, optional `bcache-tools`).

## 14. Decision record

| # | Decision | Rationale |
|---|---|---|
| ADR-1 | **Platform: Alpine Linux ≥ 3.24** (rev. C) | Adopts Alpine Linux as the primary target operating system to achieve an ultra-compact footprint (~200 MB installed) and minimal attack surface. The minimum supported release is **v3.24** (ships `systemd-boot` 260.2 with `systemd-efistub`/`ukify`/`ukify-kernel-hook` subpackages in main; `bcache-tools` 1.1-r5 in main), verified against the Alpine package index 2026-09-20. Leverages standalone upstream `ukify`, `systemd-boot`, `systemd-efistub`, and `tpm2-tools`/`libtss2-policy` packages available on Alpine, coupled with a custom early-boot initramfs hook and fail-closed poweroff guards. |
| ADR-2 | Threat model: offline theft + evil maid; firmware attacks out of scope | Hardware-rooted firmware verification (Boot Guard/PSP) is OEM-fused, not user-installable |
| ADR-3 | Recovery: TPM slot + user-chosen passphrase slot | User decision; recovery-key option declined |
| ADR-4 | Boot chain: SB(custom keys) → systemd-boot → signed UKI; policy = PCR 7 + PCR 11 combined, release-key-signed | Only option satisfying G3 + G4 simultaneously |
| ADR-5 | ESP stays unencrypted | Holds only verified artifacts; encrypting it adds complexity and no security (I2) |
| ADR-6 | PCR 0..3 excluded from seal policy; covered by `audit` | Firmware updates would permanently break sealing; detection beats brittle prevention |
| ADR-7 | **Hibernation unsupported; ephemeral encrypted swap partition only when requested (`--swap`)** | Plaintext disk swap leaks volume-key state and decrypted memory to disk. Hibernation (suspend-to-disk) dumps decrypted kernel memory and compromises verified boot and TPM state invariants. Swap is omitted by default; when explicitly requested via `install --swap [size]`, a dedicated partition is allocated and encrypted with a fresh ephemeral random key (`/dev/urandom` in `/etc/crypttab`) on every boot (Approach A). On shutdown/poweroff, the ephemeral key is wiped from memory, ensuring zero residual swap ciphertext is ever decryptable |
| ADR-8 | Missing signing key during kernel update = loud failure | Silent passphrase-prompt degradation would erode the security property |
| ADR-9 | TPM seals a keyslot passphrase, not the volume key | LUKS2 keyslots wrap passphrases; conventional and validated |
| ADR-10 | Release-key signature covers the combined policy digest — single PolicyPCR call, selection {7,11}, ascending | Signing only the PCR 11 digest would leave PCR 7 unbindable — the evil-maid gate could silently vanish |
| ADR-11 | One signing identity: the release key's certificate lives in db and signs both UKIs and policy digests | Fewer keys, one custody story; PK/KEK/db keys are enrollment-only |
| ADR-13 | **mkinitfs initramfs with early-boot hook; Btrfs default rootfs with subvolumes (ext4 optional)** | Btrfs subvolumes (`@`, `@home`, `@snapshots`) provide native userspace rollback matching `pre-upgrade` snapshot flows. ext4 remains supported for minimal single-partition simplicity. Initramfs generator resolved to **mkinitfs** (Alpine-native `linux-lts` default; hook = one POSIX-sh script + features.d entry). dracut rejected: its module framework adds no value when the unlock hook is custom and would pull an unnecessary second init framework into the initramfs |
| ADR-14 | Signed PCR 11 via per-UKI `.pcrsig` + static PCR 7; single enrollment; kernel updates and rollback TPM-free | Unified Kernel Images assembled via `ukify` embed `.pcrsig` into synthetic initrd `/.extra/`; initramfs unseal hook verifies against release public key |
| ADR-19 | **Native TPM 2.0 sealing (tpm2-tools + tpm2-tss-policy) on Alpine; clevis rejected; bwrap + pinned upstream-systemd rootfs as CI interop oracle only** | `systemd-cryptenroll` is not packaged on Alpine (package-index verified 2026-09-20). clevis is also absent from v3.24 and unsuitable on the merits: it binds static PCR digests, has no `PolicyAuthorize` release-key-signed policy, consumes no `/.extra/.pcrsig`, and would force re-binding on every kernel update — defeating G4. Direct sealing via `tpm2-tools` (~200 LOC: primary key → `tpm2_create` under the §6 policy → `systemd-tpm2`-schema token) is therefore the normative seal path. Kernel-update re-signs hook into Alpine's `/etc/kernel-hooks.d/` via the packaged `ukify-kernel-hook` convention. `bwrap` + a pinned mini rootfs running upstream `systemd-cryptsetup`/`cryptenroll` 257 is sanctioned **as a CI interop oracle only** (§12): it must prove it consumes our self-authored tokens, and reject tampered/schema-drifted ones. It never appears in the install or boot paths, carries zero footprint in the shipped Alpine system, and is not scheduled for removal — it is the standing regression net that keeps the self-authored token schema honest against upstream systemd |
| ADR-15 | Runs from the Alpine live ISO; missing host packages installed on demand via apk, `ALPINE_FDE_NO_INSTALL=1` escape hatch, loud failure with manual list otherwise | The host provisioning environment only needs partitioning, LUKS formatting, and apk-tools; all Alpine-specific packages, kernel assembly, and EFI signing run in the target chroot |
| ADR-16 | **Key algorithms: RSA (RSA-3072 release key, RSA-2048 PK/KEK/db) over ECC** | While TPM 2.0 and Linux userspace (`tpm2-tools`, `ukify`, `openssl`) support NIST P-256/P-384 ECC/ECDSA, UEFI Secure Boot firmware support for ECC certificates in NVRAM (`db`) and ECDSA Authenticode PE/COFF verification is notoriously incomplete or broken across commodity x86_64 PC motherboards. Because ADR-11 binds the release-key identity to both UEFI Secure Boot and TPM policy authorization, RSA is mandatory for universal firmware compatibility. |
| ADR-17 | **Accelerated hybrid storage: bcache under LUKS2 (LUKS over bcache, writethrough)** | When `--bcache <cache_dev>` is specified to cache backing storage (single `--disk` or multiple `--disk` drives), LUKS2 dm-crypt sits on top of each `/dev/bcacheN` device. The cache mode is pinned to `writethrough` for strict crash safety and data integrity (backing storage remains 100% consistent if cache SSD fails). All blocks written to the caching SSD are ciphertext (zero plaintext leakage, I2). In single-disk mode, `/dev/bcache0` presents a single LUKS2 header so single-token TPM 2.0 unsealing and single-passphrase recovery apply cleanly. In multi-disk mode (`--bcache <cache_dev> --disk <dev1> --disk <dev2>`), a single SSD cache set accelerates all backing drives, each backing drive is encrypted as an independent LUKS2 container with matching Argon2id passphrase / TPM 2.0 policy, and Btrfs RAID1 aggregates them into a redundant root pool. |
| ADR-18 | **Key custody: Zero-Exfiltration on-target encrypted `release.pem` (AES-256 PBKDF2); key backups rejected** | Backing up private release keys off-machine expands the attack surface (compromise of the backup server or USB medium compromises the verified boot chain). Alpine FDE enforces a **Zero-Exfiltration** posture: `release.pem` is generated directly in-chroot on the encrypted root volume and encrypted with AES-256 (PBKDF2 HMAC-SHA256, ≥ 600,000 iterations, entropy floor enforced) in Stage 1 before reboot (ADR-20 amended). The private key **never leaves the encrypted root filesystem and is never exported off-machine**. For in-place recovery (ESP rebuild, kernel repair, cache SSD replacement), keys are accessed directly from the unlocked root volume (`/mnt/etc/alpine-fde/keys`). If the root disk suffers catastrophic physical destruction, the single operational penalty is 1 reboot into UEFI firmware setup to clear keys back to Setup Mode and reinstall fresh. Consequently, *post-install* signing operations — kernel upgrades (`apk upgrade`, `ukictl build`) — prompt the operator interactively for the release key passphrase. Non-interactive updates fail loudly (ADR-8) unless unlocked via a credential agent. |
| ADR-20 | **Unattended-until-reboot install: in-chroot credential ceremony at end of Stage 1 + `alpine-fde-finalize` self-removing first-boot service + oneshot boot/login audit** | To support zero-touch automated installations (`alpine-fde install --disk ...`) while keeping fail-debug loops fast, Stage 1 executes all heavy disk formatting, package downloads, NVRAM writes, and UKI compilation first, prompting for credentials (user password, keyslot 0 recovery passphrase, and AES-256 encrypted `release.pem` passphrase) only as the final step before reboot. First boot executes a pre-unseal Secure Boot guard in the early-boot initramfs hook before unlocking: if Secure Boot is OFF, it **blocks boot with an error**, displays an explicit notice, and reboots to UEFI setup upon user confirmation, ensuring the container is never unsealed with Secure Boot disabled. Once booted with Secure Boot active, the container unseals automatically and the standalone OpenRC `alpine-fde-finalize` service automatically finalizes trust (`audit --init`, token upgrade to {PCR 7, PCR 11}, purge of the temporary install key, and self-removal from `rc-update` and `/etc/init.d/`) with zero console input. Finalization state is determined directly from cryptographic ground truth (LUKS2 token {7, 11} vs {11}, Keyslot 2 presence, and `baseline.json` digest) rather than synthetic state tracking files. On all subsequent boots, the oneshot `alpine-fde-audit` service runs once to verify hardware/firmware baselines, exiting immediately (0 MB resident RAM, 0 background daemons), and interactive logins (`/etc/profile.d/alpine-fde.sh`) check audit status to alert the operator of any drift. |

