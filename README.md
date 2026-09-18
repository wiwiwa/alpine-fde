# Debian FDE

**Passwordless, verified-boot disk encryption for Debian 13.**

Debian FDE encrypts your entire root filesystem (LUKS2) and seals the unlock key
inside your machine's TPM 2.0. The key is released **only if the boot process
verifies as untampered** — Secure Boot with your own keys, booting a signed
Unified Kernel Image whose measurement the TPM checks. In the happy path you
type **no password at boot**, ever.

- Steal the disk → useless (key is sealed to *this* machine's TPM).
- Evil maid tampers with the boot chain → it won't boot, and even if it boots,
  the TPM refuses to release the key → you see the recovery passphrase prompt.
- Kernel update or rollback → still passwordless.

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
# 1. From live host (Debian Live or Alpine):
# Standard single-disk installation (Btrfs root with @, @home, @snapshots):
./bin/debian-fde install --disk /dev/nvme0n1

# Accelerated hybrid storage (fast SSD caching slow HDD; strictly writethrough):
./bin/debian-fde install --disk /dev/sda --bcache /dev/nvme0n1

# Multi-disk Btrfs RAID1 across two drives:
./bin/debian-fde install --disk /dev/nvme0n1 --disk /dev/nvme1n1
```

The installer prompts for your disk recovery passphrase and signing key passphrase, installs Debian, enrolls your custom Secure Boot keys into firmware, and automatically reboots into BIOS.
* In BIOS: Toggle **Secure Boot: ON** and exit BIOS.
* On first boot: Enter your recovery passphrase once. The system verifies Secure Boot, securely seals your disk to the TPM, and prompts you to back up your keys off-machine.
* From now on: **Zero passwords at boot.** The disk unseals automatically via the TPM as long as firmware and boot files are untampered.

#### Option B: Shipped Wave 1 Installation (Single-disk ext4, offline signing medium)
```sh
# boot the Debian installer/live ISO, then run debian-fde from your USB stick:
./bin/debian-fde doctor            # checks the environment (read-only — it installs nothing)
./bin/debian-fde provision stage1   # creates + enrolls Secure Boot keys, generates release key on USB
./bin/debian-fde install --disk /dev/nvme0n1 --keydir /media/usb/keys # partitions, encrypts, installs
# reboot — you'll be asked ONCE for the recovery passphrase
./bin/debian-fde audit --init      # record the verified-boot baseline
./bin/debian-fde ukictl build      # build + sign the kernel image (UKI)
./bin/debian-fde enroll-tpm        # seal the disk key into the TPM
# reboot — from now on: zero passwords at boot
```

### Daily life

| You do… | What happens |
|---|---|
| Boot the machine | Unlocks automatically. No password. |
| `apt upgrade` (new kernel) | The kernel hook prompts for your release key passphrase, then rebuilds and re-signs the boot image and PCR policy. Next boot: still automatic. |
| Before major upgrades / experiments | `debian-fde pre-upgrade` takes an atomic Btrfs snapshot of `@` to `/.snapshots` for instant rollback. |
| Machine won't unlock after a firmware/BIOS update or a Secure Boot change | You're asked for the **recovery passphrase** — that's by design (the machine noticed boot verification changed). Fix the cause, then `debian-fde audit --accept` and re-enroll; see `docs/Architecture.md` §9.4. |
| Want to boot the previous kernel | Pick it in the boot menu (`debian-fde bootnext <entry>`) — still passwordless for the retained kernels. |
| Suspect the passphrase leaked | `debian-fde rotate` — new passphrase, no re-encryption. |

> [!TIP]
> For complete operational procedures, hardware replacement runbooks (including recovering from a failed cache SSD and rebuilding the ESP), and snapshot rollbacks, see [docs/UserGuide.md](docs/UserGuide.md).

### Honest limits

Debian FDE defends against **theft of the powered-off machine** and against an
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
bin/debian-fde            CLI dispatcher (subcommands in lib/cmd/)
lib/                      core libraries (TCTI/TPM seam, efivarfs seam, baseline,
                          manifest, ESP management, policy/signing, firmware keys,
                          initramfs/crypttab/cmdline build guards)
hooks/                    /etc/kernel + initramfs hook templates (postinst build,
                          postrm prune, initramfs post-update, systemd-boot
                          upgrade re-sign)
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
when both check out. No boot component added by Debian FDE ever needs to be
trusted with your passphrase.

### Development environment

- Any Linux with the toolchain; CI-style checks run on Arch in this repo's
  sandbox, production target is Debian 13. POSIX sh only (busybox-ash
  compatible), `jq`, `openssl`, `cryptsetup`, `tpm2-tools` ≥ 5.8, `swtpm`,
  QEMU + OVMF for e2e.
- `tests/env-check.sh` — verifies your environment, prints what's missing.
- `tests/run-unit.sh` — unit suite (TAP output). Fast, no VM; TPM tests run
  against **swtpm**, never your real TPM.
- The e2e scenario matrix (mapping 1:1 to the failure matrix in
  Architecture.md §10) runs on the swtpm + QEMU/OVMF harness
  (`tests/run-e2e.sh`; `tests/e2e/results-final.json` holds the last pinned
  baseline run).

### Conventions (enforced by review)

- **Fail closed**: any abnormal condition ends in the recovery passphrase path
  or poweroff — never in silent degradation. Exit codes are a contract
  (0 ok / 1 check-failed / 2 usage / 3 not-implemented / 64 fail-closed).
- **Loud failures** beat silent fallbacks everywhere (ADR-8): a kernel build
  without the signing key must fail, not "just prompt for a passphrase".
- Sentinel strings for e2e greps are **pinned per systemd release**
  (`tests/sentinels-257.13.txt`) — they drift between versions; don't grep
  from memory.
- swtpm is **lenient** about signature validation — negative crypto tests must
  run against real `systemd-cryptenroll`/TPM, never swtpm alone.
- The installed system stays **minimal** (§3.3): `debootstrap --variant=minbase`,
  no-recommends, an explicit ~15-package addition set; size budget asserted in CI.
- Everything in `docs/Architecture.md` §14 (ADR-1…18) is decided; if code and
  doc disagree, raise it — never work around silently.

### Build & test

```sh
tests/env-check.sh          # environment ready?
tests/run-unit.sh           # unit suite (swtpm-backed)
# e2e: tests/run-e2e.sh — landing with the scenario matrix
```
