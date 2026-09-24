# Alpine FDE — Developer Guide

> [!NOTE]
> **Role of this document:** contributor information — repository layout,
> development environment, coding conventions, and how to run the tests.
> The design source of truth is [Architecture.md](Architecture.md);
> the end-user reference is [UserGuide.md](UserGuide.md); the pitch and
> quick start live in the [README](../README.md).

## Repository layout

```
bin/alpine-fde            CLI dispatcher
lib/                      core libraries (TCTI/TPM seam, efivarfs seam, baseline,
                          manifest, ESP management, policy/signing, firmware keys,
                          initramfs/crypttab/cmdline build guards)
hooks/                    /etc/apk/triggers + initramfs hooks (post-upgrade build,
                          initramfs early-boot unlock hook, systemd-boot upgrade re-sign,
                          OpenRC first-boot trust finalization service, OpenRC oneshot
                          boot audit service, and login auditing profile hook)
fixtures/                 pinned test artifacts (keys, UKI inputs, golden vectors)
tests/                    unit suite + e2e harness (swtpm, QEMU/OVMF, sentinels)
docs/Architecture.md      the design — SOURCE OF TRUTH, implementation-ready
docs/UserGuide.md         operator guide: workflows, RAID1, bcache, and recovery runbooks
```

## Development environment

- Alpine Linux (x86_64, musl libc, OpenRC) with standard toolchain; CI-style checks run
  with POSIX sh (busybox-ash compatible), `apk`, `jq`, `openssl`, `cryptsetup`, `tpm2-tools` ≥ 5.8,
  `ukify`, `systemd-boot`, `swtpm`, QEMU + OVMF for e2e.
- `tests/env-check.sh` — verifies your environment, prints what's missing.
- `tests/run-unit.sh` — unit suite (TAP output). Fast, no VM; TPM tests run
  against **swtpm**, never your real TPM.

## Conventions (enforced by review)

- **Fail closed**: any abnormal condition ends in the recovery passphrase path
  or poweroff — never in silent degradation or dropping to an interactive emergency shell.
- **Loud failures** beat silent fallbacks everywhere: a kernel build
  without the signing key must fail, not "just prompt for a passphrase".
- **Zero-Exfiltration (ADR-18)**: Private keys (`release.pem`) are generated directly in-chroot
  on the encrypted root volume and encrypted at rest with AES-256 PBKDF2; keys must NEVER be
  exported, copied, or backed up off-machine.
- The installed system stays **minimal** ([Architecture.md §3.2](file:///home/user/debian-fde/docs/Architecture.md#32-installed-system-footprint)): Alpine base via `apk add --root`;
  the lean ~200 MB footprint is an inherent benefit of Alpine rather than a formal size requirement.
- Everything in `docs/Architecture.md` §14 is decided; if code and doc disagree,
  raise it — never work around silently.

## Build & test

```sh
tests/env-check.sh          # environment ready?
tests/run-unit.sh           # unit suite (swtpm-backed)
```
