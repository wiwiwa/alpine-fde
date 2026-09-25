# Alpine FDE

**Passwordless, verified-boot disk encryption for Alpine Linux.**

Alpine FDE encrypts your entire root filesystem (LUKS2) and seals the unlock key
inside your machine's TPM 2.0. The key is released **only if the boot process
verifies as untampered** — Secure Boot with your own keys, booting a signed
Unified Kernel Image whose measurement the TPM checks.
In the happy path you type **no password at boot**, ever.

- Steal the disk → useless (key is sealed to *this* machine's TPM).
- Evil maid tampers with the boot chain → it won't boot, and even if it boots,
  the TPM refuses to release the key → you see the recovery passphrase prompt;
  bounded attempts trigger an immediate fail-closed poweroff (no rescue shell).
- Kernel update or rollback → still passwordless.
- Extremely lightweight → minimal footprint (~200 MB installed).

No boot component added by Alpine FDE ever needs to be trusted with your
passphrase.

> [!NOTE]
> **This document** is the pitch and quick start — deciding whether Alpine FDE
> is for you, and getting a machine running the first time. The complete
> end-user reference is [docs/UserGuide.md](docs/UserGuide.md); the design is
> [docs/Architecture.md](docs/Architecture.md).

---

## For end users

### Functional Requirements & Guarantees

Alpine FDE delivers eight core functional guarantees (detailed in the [User Guide](docs/UserGuide.md#functional-requirements--security-guarantees)):
1. **Full-Disk Encryption at Rest:** Complete encryption under LUKS2 (Argon2id); zero plaintext data on disk.
2. **Passwordless Verified Boot:** Volume unseals via TPM 2.0 iff custom Secure Boot (`PCR 7`) and signed UKI measurements (`PCR 11`) verify.
3. **Anti Evil-Maid & Fail-Closed Defense:** Tampered kernels, modified cmdlines, or disabled Secure Boot halt unseal, show diagnostic warnings, and enforce a 3-strike fail-closed immediate poweroff (`poweroff -f`).
4. **TPM-Free Kernel Upgrades & Rollbacks:** Unified Kernel Images carry per-kernel `.pcrsig` signatures; upgrades and rollbacks remain 100% passwordless without TPM re-sealing.
5. **Flexible Topologies:** Native support for single-disk, accelerated hybrid storage (`--bcache` in writethrough mode), and multi-disk redundancy (Btrfs RAID1). Optional ephemeral encrypted swap (`--swap`) wipes its key on poweroff.
6. **Automated Firmware Auditing:** On every boot (oneshot `alpine-fde-audit` service) and every interactive login (`/etc/profile.d/alpine-fde.sh`), platform measurements are verified against the baseline, alerting you to firmware drift while `alpine-fde audit` supports manual checks and `--accept` re-baselining.
7. **Unattended-Until-Reboot Installation:** Guided ceremony executes all formatting, bootstrap, and NVRAM enrollment first; credentials are prompted only as the final pre-reboot step.
8. **Zero-Exfiltration Key Custody:** Signing keys remain encrypted on-target; disaster recovery is achieved without off-machine key exports.

### What you need

- An x86_64 machine with UEFI firmware and TPM 2.0.
- The ability to enter UEFI Setup, clear vendor keys to enter **Setup Mode**, and set a **firmware admin password**.
  Recommended, not enforced — the installer cannot verify it. Without that password, an attacker with physical access can enter firmware setup, enroll their own boot keys, and install a bootkit. The disk still cannot be decrypted (the TPM seal fails closed on any Secure Boot key change), but the bootkit can fake the passphrase prompt to phish your recovery passphrase. The firmware admin password closes that first step.
- One **recovery passphrase** (chosen during install; the only password you ever type for the disk — stored somewhere safe, not on the machine).

### Quick start

Boot the standard Alpine live USB, and install:

```sh
# Standard single-disk installation (Btrfs root with @, @home, @snapshots):
curl -sSfL https://github.com/wiwiwa/alpine-fde/raw/main/install | sh -s -- install --disk /dev/nvme0n1

# With optional ephemeral encrypted swap (key wiped on poweroff):
curl -sSfL https://github.com/wiwiwa/alpine-fde/raw/main/install | sh -s -- install --disk /dev/nvme0n1 --swap 4G

# Accelerated hybrid storage (fast SSD caching slow HDD; strictly writethrough):
curl -sSfL https://github.com/wiwiwa/alpine-fde/raw/main/install | sh -s -- install --disk /dev/sda --bcache /dev/nvme0n1

# Multi-disk Btrfs RAID1 across two drives:
curl -sSfL https://github.com/wiwiwa/alpine-fde/raw/main/install | sh -s -- install --disk /dev/nvme0n1 --disk /dev/nvme1n1

# Accelerated multi-disk hybrid storage (fast SSD caching multiple HDDs in Btrfs RAID1):
curl -sSfL https://github.com/wiwiwa/alpine-fde/raw/main/install | sh -s -- install --bcache /dev/nvme0n1 --disk /dev/sda --disk /dev/sdb
```

*(The bootstrap script reconnects `stdin` to `/dev/tty` so interactive passphrase prompts work seamlessly through the pipe. Alternatively, if running from a local git clone or unpacked release tarball, invoke `./bin/alpine-fde install ...` directly).*

`install` is unattended **until reboot**: it executes all disk partitioning, package bootstrap, and firmware key enrollment first, prompting for your three credentials — your user account password, your **recovery passphrase**, and your **release signing key passphrase** — as the final step before rebooting directly to disk.

* On first boot: **zero passwords.** Before unlocking the disk, the early-boot sequence verifies Secure Boot is active — if Secure Boot is disabled, the initrd strictly refuses to boot, prints an error notice, never unseals the root volume, and reboots directly to UEFI setup; if Secure Boot is enabled, the disk unseals automatically via the TPM, and the standalone `alpine-fde-finalize` service runs automatically before the login prompt — capturing the baseline, making the TPM seal permanent ({PCR 7, PCR 11}), purging the temporary install key, and auto-removing itself upon completion.
* From now on: **100% passwordless verified boot with automatic auditing.** The disk unseals automatically via the TPM as long as firmware and boot files are untampered. A lightweight oneshot service audits firmware measurements on every boot, and interactive logins alert you immediately if firmware drift is detected.

For the full step-by-step walkthrough of install and first boot, see the [User Guide, §3](docs/UserGuide.md#3-installation--first-boot-experience).

### Daily life

| You do… | What happens |
|---|---|
| Boot the machine | Unlocks automatically. No password. |
| Normal boot / login | Oneshot `alpine-fde-audit` checks firmware baseline during boot; login profile alerts if drift is detected. |
| `apk upgrade` (new kernel) | The upgrade prompts for your release key passphrase, then rebuilds and re-signs the boot image and updates the TPM policy. Next boot: still automatic. |
| Before major upgrades / experiments | `alpine-fde pre-upgrade` takes an atomic Btrfs snapshot of `@` to `/.snapshots` for instant rollback. |
| Machine won't unlock after a firmware/BIOS update or a Secure Boot key change | You're asked for the **recovery passphrase** — that's by design (the machine noticed boot verification changed). Fix the cause, then `alpine-fde audit --accept` and re-enroll; see the [User Guide, Runbook 3](docs/UserGuide.md#runbook-3-pcr-7-drift-after-firmwarebios-update). |
| Want to boot the previous kernel | Pick it in the boot menu (`alpine-fde bootnext <entry>`) — still passwordless for the retained kernels. |
| Suspect the passphrase leaked | `alpine-fde rotate` — new passphrase, no re-encryption. |

> [!TIP]
> For complete operational procedures, hardware replacement runbooks (including recovering from a failed cache SSD and rebuilding the ESP), and snapshot rollbacks, see [docs/UserGuide.md](docs/UserGuide.md) — the full end-user reference and functional-requirement specification. For the design, security invariants, and architecture decisions, see [docs/Architecture.md](docs/Architecture.md).

### Honest limits

Alpine FDE defends against **theft of the powered-off machine** and against an
**evil maid** who can briefly boot it with other media. It does **not** protect
against someone who can modify your firmware itself, cold-boot/RAM attacks,
or hardware implants. Hibernation is disabled by design (its sleep image would
leak the key to disk). Firmware settings are not a substitute: still set a
firmware admin password.

### Keep safe

1. The **recovery passphrase** — with it, you can always get back in; without it (and with the TPM refusing), the data is gone. Store it safely off-machine.
2. The **release signing key passphrase** — protects `release.pem` at rest on the encrypted disk. The private key never leaves the encrypted container (Zero-Exfiltration).
3. The **firmware admin password** — prevents unauthorized physical tampering with UEFI Secure Boot settings.

---

## For developers

Repository layout, development environment, coding conventions, and how to run
the test suites are documented in [docs/Developer.md](docs/Developer.md).
The design — source of truth, implementation-ready — is
[docs/Architecture.md](docs/Architecture.md).
