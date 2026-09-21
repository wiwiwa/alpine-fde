# Alpine FDE

**Passwordless, verified-boot disk encryption for Alpine Linux.**

Alpine FDE encrypts your entire root filesystem (LUKS2) and seals the unlock key
inside your machine's TPM 2.0. The key is released **only if the boot process
verifies as untampered** — Secure Boot with your own keys, booting a signed
Unified Kernel Image (UKI via `ukify` and `systemd-boot`) whose measurement the TPM checks.
In the happy path you type **no password at boot**, ever.

- Steal the disk → useless (key is sealed to *this* machine's TPM).
- Evil maid tampers with the boot chain → it won't boot, and even if it boots,
  the TPM refuses to release the key → you see the recovery passphrase prompt;
  bounded attempts trigger an immediate fail-closed poweroff (no rescue shell).
- Kernel update or rollback → still passwordless.
- Extremely lightweight → minimal footprint (~200 MB installed vs ~1.4 GB on Debian).

---

## For end users

### What you need

- An x86_64 machine with UEFI firmware and TPM 2.0.
- The ability to enter UEFI Setup, clear vendor keys to enter **Setup Mode** (`SetupMode=1`), and set a **firmware admin password**.
- One **recovery passphrase** (chosen during install; the only password you ever type for the disk — stored somewhere safe, not on the machine).
- A remote host to `scp` backup your keys (or an offline USB stick).

### Quick start

#### Option A: Wave 2 Installation (Btrfs default, single-reboot ceremony — Design Preview)
*(Note: Wave 2 features are currently in design preview; see Option B for shipped `main` commands).*
```sh
# 1. From live host (Alpine Linux standard live ISO):
# Standard single-disk installation (Btrfs root with @, @home, @snapshots):
./bin/alpine-fde install --disk /dev/nvme0n1

# Accelerated hybrid storage (fast SSD caching slow HDD; strictly writethrough):
./bin/alpine-fde install --disk /dev/sda --bcache /dev/nvme0n1

# Multi-disk Btrfs RAID1 across two drives:
./bin/alpine-fde install --disk /dev/nvme0n1 --disk /dev/nvme1n1

# Accelerated multi-disk hybrid storage (fast SSD caching multiple HDDs in Btrfs RAID1):
./bin/alpine-fde install --bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb
```

Unattended means unattended **until reboot** (ADR-20, amended): `install` asks you exactly three no-echo questions — your user account password, your **recovery passphrase** (keyslot 0, Argon2id), and your **release signing key passphrase** (encrypts `release.pem` at rest). It then installs Alpine via `apk`, enrolls your custom Secure Boot keys into firmware, seals a provisional PCR-11 TPM token, and reboots directly to disk.
* On first boot: **Zero passwords at boot.** The disk unseals automatically via the provisional TPM token, and the first-boot OpenRC service **completes trust finalization by itself** — baseline capture, permanent {PCR 7, PCR 11} sealing, ephemeral-keyslot purge, banner clear. No login needed to finalize; log in and use the machine.
* `alpine-fde finalize` is only the crash-resume path: run it manually if the first-boot service could not finish (mid-finalization power loss, repeated guard failure).
* From now on: **100% passwordless verified boot.** The disk unseals automatically via the TPM as long as firmware and boot files are untampered.

#### Option B: Shipped Wave 1 Installation (Single-disk ext4, offline signing medium)
```sh
# boot the Alpine live ISO, then run alpine-fde from your USB stick:
./bin/alpine-fde doctor            # checks the environment (read-only — it installs nothing)
./bin/alpine-fde provision stage1   # creates + enrolls Secure Boot keys, generates release key on USB
./bin/alpine-fde install --disk /dev/nvme0n1 --keydir /media/usb/keys # partitions, encrypts, installs
# reboot — you'll be asked ONCE for the recovery passphrase
./bin/alpine-fde audit --init      # record the verified-boot baseline
./bin/alpine-fde ukictl build      # build + sign the kernel image (UKI via ukify)
./bin/alpine-fde enroll-tpm        # seal the disk key into the TPM
# reboot — from now on: zero passwords at boot
```

### Daily life

| You do… | What happens |
|---|---|
| Boot the machine | Unlocks automatically. No password. |
| `apk upgrade` (new kernel) | The APK trigger prompts for your release key passphrase, then rebuilds and re-signs the boot image (`ukify`) and PCR policy. Next boot: still automatic. |
| Before major upgrades / experiments | `alpine-fde pre-upgrade` takes an atomic Btrfs snapshot of `@` to `/.snapshots` for instant rollback. |
| Machine won't unlock after a firmware/BIOS update or a Secure Boot change | You're asked for the **recovery passphrase** — that's by design (the machine noticed boot verification changed). Fix the cause, then `alpine-fde audit --accept` and re-enroll; see `docs/Architecture.md` §9.4. |
| Want to boot the previous kernel | Pick it in the boot menu (`alpine-fde bootnext <entry>`) — still passwordless for the retained kernels. |
| Suspect the passphrase leaked | `alpine-fde rotate` — new passphrase, no re-encryption. |

> [!TIP]
> For complete operational procedures, hardware replacement runbooks (including recovering from a failed cache SSD and rebuilding the ESP), and snapshot rollbacks, see [docs/UserGuide.md](docs/UserGuide.md).

### Honest limits

Alpine FDE defends against **theft of the powered-off machine** and against an
**evil maid** who can briefly boot it with other media. It does **not** protect
against someone who can modify your firmware itself, cold-boot/RAM attacks,
or hardware implants. Hibernation is disabled by design (its sleep image would
leak the key to disk). Firmware settings are not a substitute: still set a
firmware admin password.

### Keep safe

1. Your **signing key backup** (and its passphrase) — whoever holds your decrypted signing key can sign boot images this TPM will trust.
2. The **recovery passphrase** — with it, you can always get back in; without it
   (and with the TPM refusing), the data is gone. That's the point.

---

## For developers

### Repository layout

```
bin/alpine-fde            CLI dispatcher (symlink/alias: bin/debian-fde)
lib/                      core libraries (TCTI/TPM seam, efivarfs seam, baseline,
                          manifest, ESP management, policy/signing, firmware keys,
                          initramfs/crypttab/cmdline build guards)
hooks/                    /etc/apk/triggers + initramfs hooks (post-upgrade build,
                          initramfs early-boot unlock hook, systemd-boot upgrade re-sign,
                          OpenRC first-boot trust finalization service)
fixtures/                 pinned test artifacts (keys, UKI inputs, golden vectors)
tests/                    unit suite + e2e harness (swtpm, QEMU/OVMF, sentinels)
docs/Architecture.md      the design — SOURCE OF TRUTH, implementation-ready
docs/UserGuide.md         operator guide: workflows, RAID1, bcache, and recovery runbooks
```

### How it works

The design — what gets sealed where, why the boot chain verifies, and every
trade-off — is documented in [docs/Architecture.md](docs/Architecture.md).
In short: your machine verifies the boot chain with your own Secure Boot keys,
measures what it verified into the TPM, and the TPM only releases the disk key
when both check out. No boot component added by Alpine FDE ever needs to be
trusted with your passphrase.

### Development environment

- Alpine Linux (x86_64, musl libc, OpenRC) with standard toolchain; CI-style checks run
  with POSIX sh (busybox-ash compatible), `apk`, `jq`, `openssl`, `cryptsetup`, `tpm2-tools` ≥ 5.8,
  `ukify`, `systemd-boot`, `swtpm`, QEMU + OVMF for e2e.
- `tests/env-check.sh` — verifies your environment, prints what's missing.
- `tests/run-unit.sh` — unit suite (TAP output). Fast, no VM; TPM tests run
  against **swtpm**, never your real TPM.

### Conventions (enforced by review)

- **Fail closed**: any abnormal condition ends in the recovery passphrase path
  or poweroff — never in silent degradation or dropping to an interactive emergency shell.
- **Loud failures** beat silent fallbacks everywhere (ADR-8): a kernel build
  without the signing key must fail, not "just prompt for a passphrase".
- The installed system stays **minimal** (§3.3): Alpine base via `apk add --root`,
  targeting ~200 MB installed size budget.
- Everything in `docs/Architecture.md` §14 is decided; if code and doc disagree,
  raise it — never work around silently.

### Build & test

```sh
tests/env-check.sh          # environment ready?
tests/run-unit.sh           # unit suite (swtpm-backed)
```
