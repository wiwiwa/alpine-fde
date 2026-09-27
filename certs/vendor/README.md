# certs/vendor — vendor certificates for the db rebuild

This directory ships the vendor trust anchors that `provision stage1` embeds
into the combined `db.esl` (release cert + every `*.cer` here, LC_ALL=C sorted
filename order, ONE authenticated write) and that the enrollment flow's ESP
fallback stages to `<ESP>/alpine-fde-keys/` under their basenames.

DECIDED (Samuel, 2026-09-27): db is RESET (authenticated delete) then REBUILT
as release cert + these vendor certs — replacing the former db-replacement-
with-release-cert-only design. Motivation: under a custom-only db with Secure
Boot enforced, the Dell PowerEdge firmware fails UEFI0072 Secure Boot policy
on the NIC PXE option ROMs and the Integrated RAID Controller (PERC) option
ROM, because nothing in the custom db authorizes them.

Knobs (environment / `/etc/alpine-fde/alpine-fde.conf`):

| Knob | Values | Meaning |
|---|---|---|
| `ALPINE_FDE_DB_VENDOR` | `all` (default) / `none` | `none` = minimal db (release cert only, the old behavior) |
| `ALPINE_FDE_DB_VENDOR_DIR` | directory path | alternative vendor-cert directory (default: `certs/vendor` next to the lib tree — repo checkout, `/usr/share/alpine-fde/certs/vendor`, or `/opt/alpine-fde/certs/vendor`) |

Only `*.cer` files (DER) are consumed. Every file is validated as a DER
certificate before it enters the ESL — a malformed file fails the ceremony
loudly (ADR-8), it is never silently skipped.

`dbx` is NEVER touched by this flow — it is the revocation list.

## Shipped certificates

### `microsoft-option-rom-uefi-ca-2023.cer`

- Subject: `C=US, O=Microsoft Corporation, CN=Microsoft Option ROM UEFI CA 2023`
- Issuer: `C=US, O=Microsoft Corporation, CN=Microsoft RSA Devices Root CA 2021`
- Validity: 2023-10-26 .. 2038-10-26
- Serial: `3300000017b3ec4d8f01e27005000000000017`
- SHA-256 (DER file): `e5be3e64c6e66a281457ecdece0d6d0787577aad2a3a0144262c10c14ba8d8f1`
- Official source (Microsoft Learn, "Windows Secure Boot Key Creation and
  Management Guidance" — the Option ROM CA row):
  <https://go.microsoft.com/fwlink/?linkid=2284009>
  (resolves to `https://www.microsoft.com/pkiops/certs/microsoft option rom uefi ca 2023.crt`)
- Purpose: authorizes signed option ROMs (NIC PXE, storage controllers) under
  Secure Boot without trusting third-party bootloaders. Microsoft states
  systems that trust option ROMs can add this CA to db *without* adding trust
  for bootloader CAs — exactly the minimal-vendor-trust posture of the
  decided design.
- Naming note: Microsoft publishes this certificate as "Microsoft Option ROM
  UEFI CA 2023"; the design discussion (and Dell's material) refers to it as
  the "Option ROM UEFI CA 2" trust anchor. It is the same option-ROM CA line —
  the current, 2023-era certificate Microsoft ships for it.
