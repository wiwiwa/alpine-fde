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

> Status: implementation in progress (docs/Architecture.md is implementation-ready;
> unit suite green; the e2e scenario matrix is being re-validated wave by wave).
> See "For developers".

---

## For end users

### What you need

- A Debian 13 ("trixie") machine, x86_64, UEFI firmware with TPM 2.0.
- The ability to set a **firmware admin password** and enroll custom Secure Boot
  keys (any modern machine; a firmware UI or the bundled KeyTool handles it).
- One **offline USB stick** that holds the signing key (kept in a drawer, used
  only during provisioning and kernel-signing updates).
- One **recovery passphrase** (chosen during install; the only password you ever
  type for the disk — stored somewhere safe, not on the machine).

### Quick start (from the Debian live ISO)

```sh
# boot the Debian installer/live ISO, then run debian-fde from your USB stick:
./bin/debian-fde doctor            # checks the environment (read-only — it
                                 # installs nothing)
./bin/debian-fde provision         # creates + enrolls Secure Boot keys,
                                 # generates the release key on your USB stick
./bin/debian-fde install           # partitions, encrypts (LUKS2), installs a
                                 # minimal Debian, sets up the signed boot chain
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
| `apt upgrade` (new kernel) | The kernel hook rebuilds and re-signs the boot image. Next boot: still automatic. |
| Machine won't unlock after a firmware/BIOS update or a Secure Boot change | You're asked for the **recovery passphrase** — that's by design (the machine noticed boot verification changed). Fix the cause, then `debian-fde audit --accept` and re-enroll; see `docs/Architecture.md` §9.4. |
| Want to boot the previous kernel | Pick it in the boot menu (`debian-fde bootnext <entry>`) — still passwordless for the retained kernels. |
| Suspect the passphrase leaked | `debian-fde rotate` — new passphrase, no re-encryption. |

### Honest limits

Debian FDE defends against **theft of the powered-off machine** and against an
**evil maid** who can briefly boot it with other media. It does **not** protect
against someone who can modify your firmware itself, cold-boot/RAM attacks,
or hardware implants. Hibernation is disabled by design (its sleep image would
leak the key to disk). Firmware settings are not a substitute: still set a
firmware admin password.

### Keep safe

1. The **offline signing USB** — whoever holds it can sign boot images this TPM
   will trust.
2. The **recovery passphrase** — with it, you can always get back in; without it
   (and with the TPM refusing), the data is gone. That's the point.

---

## For developers

### Repository layout

```
bin/debian-fde            CLI dispatcher (subcommands in lib/cmd/)
lib/                      core libraries (TCTI/TPM seam, efivarfs seam, baseline,
                          manifest, ESP management, policy/signing, firmware keys)
hooks/                    /etc/kernel/postinst.d + postrm.d integration
fixtures/                 pinned test artifacts (keys, UKI inputs, golden vectors)
tests/                    unit suite + e2e harness (swtpm, QEMU/OVMF, sentinels)
docs/Architecture.md      the design — SOURCE OF TRUTH, implementation-ready
```

### Design in one paragraph

Debian 13 + systemd-native tooling: `ukify` builds a Unified Kernel Image
(kernel + initramfs + cmdline, one signed EFI binary); `sbctl`-style custom
Secure Boot keys (openssl + sbsigntool — sbctl itself isn't in Debian) make the
firmware verify it; the stub measures it into PCR 11. The LUKS2 key is enrolled
via `systemd-cryptenroll` with **PCR 7 bound statically and PCR 11 covered by a
release-key-signed policy** whose signatures ride inside each UKI (`.pcrsig`).
Unlock is **systemd's own initramfs code** — Debian FDE adds no boot-critical
custom code. A decision ladder (Architecture.md §6.1) spikes the preferred
mechanism first; fallbacks are specified and tested. See ADR-1…ADR-15 for every
decision and its rationale.

### Development environment

- Any Linux with the toolchain; CI-style checks run on Arch in this repo's
  sandbox, production target is Debian 13. POSIX sh only (busybox-ash
  compatible), `jq`, `openssl`, `cryptsetup`, `tpm2-tools` ≥ 5.8, `swtpm`,
  QEMU + OVMF for e2e.
- `tests/env-check.sh` — verifies your environment, prints what's missing.
- `tests/run-unit.sh` — unit suite (TAP output). Fast, no VM; TPM tests run
  against **swtpm**, never your real TPM.
- e2e (scenario matrix S-00…S-18, mapping 1:1 to the failure matrix in
  Architecture.md §10) runs on the swtpm + QEMU/OVMF harness (`tests/run-e2e.sh`);
  the headline assertion is *boots to login with zero input*.

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
- Everything in `docs/Architecture.md` §14 (ADR-1…15) is decided; if code and
  doc disagree, raise it — never work around silently.

### Build & test

```sh
tests/env-check.sh          # environment ready?
tests/run-unit.sh           # unit suite (swtpm-backed)
# e2e: tests/run-e2e.sh — landing with the scenario matrix
```
