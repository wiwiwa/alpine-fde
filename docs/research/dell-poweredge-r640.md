# Dell PowerEdge R640 — deployment findings (vendor-specific)

Vendor-specific notes from live Alpine FDE deployments on a Dell PowerEdge R640
(2026-09 through 2026-10). The product docs (UserGuide/Architecture) carry the
hardware-AGNOSTIC statements of the same findings; this note keeps the
vendor-specific detail — iDRAC workflows, exact firmware behaviors, and the
remediation paths — that does not belong in the product manual.

Source sections mirrored from the product docs (kept here verbatim for
operational use):

## Real-hardware findings (Dell PowerEdge R640)


Findings from live Dell PowerEdge installs (2026-09 through 2026-10). The installer and boot hook already adapt to this firmware automatically where they can; the firmware-side prerequisites below **cannot** be automated and must be satisfied by the operator.

1. **No software reboot-to-firmware-setup (`OsIndications` unsupported).** This firmware exposes no `OsIndicationsSupported` variable, so the UEFI-defined software boot-to-setup mechanism is impossible — nothing an OS writes can make it reboot straight into setup. Enter firmware setup with **F2 during POST**. The early-boot Secure Boot guard detects the missing support at boot, prints the full manual steps (import `db.auth`, `kek.auth`, `pk.auth` from the ESP's `alpine-fde-keys` in that order, enable Secure Boot, save and exit), prompts *Press Enter to reboot*, and reboots plainly — press **F2 during the next POST** to reach the firmware UI (see [§3 Step 3](#step-3-first-boot--automated-trust-finalization)).
2. **Key import goes through `efi-updatevar`, not raw efivarfs writes.** This firmware refused `sign-efi-sig-list`-format packets written directly to `efivarfs`, but accepts the native `EFI_VARIABLE_AUTHENTICATION_2` packets the installer emits via `efi-updatevar` (efitools). Authenticated **deletes** additionally need signed-empty packets plus `chattr -i` on the efivarfs node first — efivarfs marks authenticated variables immutable at creation, so any removal attempt dies `EPERM` without it. The installer handles all of this; the operator takeaways are: make sure `efitools` (`efi-updatevar`) and `e2fsprogs` (`chattr`) are available on the live host, and never hand-write the variables with `cat`/`printf` redirection.
3. **Flash SB-capable PERC and NIC firmware BEFORE enabling Secure Boot.** With Secure Boot enforced, out-of-band device firmware — NIC PXE option ROMs and the Integrated RAID Controller (PERC) option ROM — can fail the firmware's UEFI0072 Secure Boot policy checks at POST if the option ROM is stale or unsigned. In the verified failure, the PERC option ROM's refusal blocked the RAID controller from initializing (disks invisible to the installer). **Prerequisite: flash current, SB-capable PERC and NIC firmware via iDRAC before enabling Secure Boot.** If it bites anyway, the POST screen offers **F1 (continue)** / **F2 (setup)**.
4. **db contents: reset + release+vendor rebuild.** The db is no longer custom-only. During enrollment (Setup Mode, before the KEK and PK writes) the installer **resets db** — an authenticated delete of its existing content — and then **rebuilds it in one authenticated write** as the Alpine FDE release certificate **plus the vendor trust anchors** shipped in `certs/vendor/` (default: **Microsoft Option ROM UEFI CA 2023**, the option-ROM CA that authorizes signed NIC PXE / storage option ROMs, which is what fails UEFI0072 when missing). `dbx` is never touched — it stays the revocation list. The rebuild **replaces** the whole variable, so re-installs never accumulate duplicate certificates. Knobs: `ALPINE_FDE_DB_VENDOR=none` restores the minimal release-cert-only db (the old behavior); `ALPINE_FDE_DB_VENDOR_DIR` points at an alternative vendor directory. The vendor `.cer` files are additionally staged to the ESP's `alpine-fde-keys/` directory so an operator can append them via the firmware UI on boards where the NVRAM writes cannot run.
5. **After "Delete All Policy Entries", OS-side NVRAM writes may be refused: recover via the firmware UI and the staged files (observed live 2026-09-28).** On this firmware, OS-side authenticated writes of PK/KEK/db (`efi-updatevar`) that succeeded the day before were refused with `EACCES` ("wrong filesystem permissions") after the operator used the firmware's **Delete All Policy Entries** — the wipe changes the variable-storage state in a way the kernel-visible efivarfs does not explain, and the installer cannot work around it. The install degrades gracefully: it stages the key material to the ESP's `alpine-fde-keys/` directory and continues. That directory now carries everything the firmware UI needs, **no extra LUKS unlock required**: the `.auth` packets (for `KeyTool.efi` / `efi-updatevar` repair only — the setup UI cannot import them), the **import-ready certificates** `db.cer` (the release cert, from `release.crt`), `KEK.cer` (from `kek.cert.der`), `PK.cer` (from `pk.cert.der`), the vendor `microsoft-option-rom-uefi-ca-2023.cer`, and a `README.txt` repeating the runbook below. Documented recovery:
   1. Reboot into firmware setup (**F2 during POST** on Dell PowerEdge) and open Security / Secure Boot / Key Management.
   2. Import **`db.cer`** into the Key Database — **and then the vendor `microsoft-option-rom-uefi-ca-2023.cer` into db as well.** The db holds BOTH the release certificate (it authorizes the signed bootloader/kernel) and the vendor option-ROM CA: under custom keys, without the vendor cert, signed NIC PXE / PERC option ROMs fail the firmware's UEFI0072 Secure Boot policy at POST (the PERC can refuse to initialize and the disks vanish — see item 3).
   3. Import **`KEK.cer`** into the Key Exchange Key.
   4. Import **`PK.cer`** into the Platform Key **last** — enrolling the PK flips the platform to **User Mode** and locks the key database; no further key imports are possible until the PK is removed again.
   5. **Enable Secure Boot** (the platform must show User Mode, Custom mode), set the firmware administrator password, save and exit, and let the install/first boot finish (first boot stays guarded until the keys are imported, ADR-20).

   All the staged `.cer` files are **DER** — Dell PowerEdge firmware imports `.cer` files in DER encoding only (a PEM `.cer` is rejected with "The import operation did not complete successfully"; observed live 2026-09-29). `db.cer` is the DER encoding of the keydir's `release.crt`, converted at staging time.
6. **Boot entries are created for you.** `install` creates a PAIR of firmware boot entries per kernel version — **`Alpine FDE - <kver> (<date>)`** pointing directly at the default UKI `\EFI\Linux\alpine-fde-<kver>.efi` (FIRST in `BootOrder`) and **`Alpine FDE - <kver> serial (<date>)`** pointing at `\EFI\Linux\alpine-fde-<kver>-serial.efi` (the serial/recovery lane) — the firmware loads each UKI directly (systemd-boot stays only the removable-media fallback). Idempotent: re-installs and rebuilds reuse or recreate the pair (no manual `efibootmgr` run is needed), and pruning a kernel removes its entries with it — at most three version-pairs (six entries) stand. **NVRAM commit latency (live-verified):** this firmware commits `efibootmgr -c` writes BEFORE the new entry appears in the listing — the install re-reads the listing up to **24 times, 10 s apart (~240 s bounded)**, and the R640 needed >50 s and up to ~2 min per entry. The retry messages are expected; do not interrupt the step. The ESP's fallback loader (`\EFI\BOOT\BOOTX64.EFI`) boots the UKIs meanwhile even while the named entry is still pending, and a re-run converges idempotently.
7. **TPM restricted to SHA-1 PCRs (observed live 2026-09-29): the firmware ships `Tpm2Algorithm = SHA1`.** On this R640 the BIOS's TPM Advanced Settings limited the TPM to the SHA-1 PCR bank; every SHA-256 PCR read returned an empty selection while the SHA-1 bank looked healthy — the install completed, but the final reseal could not read PCR 0 and the baseline finalize died `cannot read PCR 0`. The preflight now catches exactly this before disk mutation (see Prerequisite 3). **Remedy: iDRAC web GUI → Configuration → BIOS Settings → Security → TPM Advanced Settings → TPM2 Algorithm Selection = SHA256 → Apply (the scheduled `BIOS.Setup.1-1` job reboots the server itself).** iDRAC 8-era `racadm` cannot set BIOS attributes (`set BIOS...` is a syntax error, no SCP import in Redfish), and the TPM's **platform hierarchy may be owned by the firmware** — a user-space `tpm2_pcrallocate` fails `0x9a2 authorization failure` even after a `tpm2_clear` from the lockout locus, so the BIOS setting (or a firmware-level TPM Clear, which resets the bank allocation to the firmware default) is the only working path. Beware the **TPM dictionary-attack lockout** during recovery: repeated failed token-policy unseals across boots max the DA counter (`tpm2_getcap properties-variable` → `inLockout: 1`), which surfaces as bizarre session-creation errors (`Failed TPM2_CC_ECDH_ZGen`) on every auth'ed command; clear it with `tpm2_dictionarylockout -c -p ""` (default empty lockout auth) before diagnosing anything else.
8. **The live ISO lacks `lsblk` and `efibootmgr`, and its apk repo only has the CD.** The stock ISO's repository list points at the CD media alone, so every package fetch fails until a network repo is added. In live-env prep, add the dl-cdn network repo to `/etc/apk/repositories` (`setup-apkrepos` can do this; the installer's live-env preflight apk-adds missing live tools such as `lsblk`/`sfdisk` from exactly this mirror — default `https://dl-cdn.alpinelinux.org/alpine/v3.24/main`), and run `apk add efibootmgr` for the NVRAM boot-entry work.
9. **The iDRAC virtual CD (vCD) attachment can DROP across power cycles.** If the machine suddenly no longer boots from the installer ISO after a power cycle, re-attach the virtual CD in iDRAC before retrying the CD boot.
10. **A forced `reboot -f` from the initrd can wedge the shutdown in the `megaraid_sas` path (observed live 2026-10-02).** The console freezes mid shutdown while iDRAC still reports PowerState On. Recovery is a BMC power cycle (iDRAC power cycle, not a plain power-on) — and the `OsIndications` boot-to-firmware-setup request, once written, SURVIVES the power cycle, so the next boot still enters firmware setup where it was requested.
11. **The firmware setup UI renders on VIDEO only.** While the machine sits in firmware setup, the serial console shows nothing (serial/SOL stays silent for the entire setup UI). Do firmware-UI work (key imports, TPM/BIOS settings) from a video console — a physical head or the iDRAC virtual console.
12. **PCR 1 (BIOS-settings) drift after firmware/NVRAM work is expected.** BIOS-settings changes — including the firmware/NVRAM enrollment work above — move PCR 1, and the boot/login audit reports the drift afterwards. Verify the cause with `alpine-fde audit` and re-baseline with `alpine-fde audit --accept` (then `alpine-fde reseal` to restore passwordless unlock) — the [Runbook 3](#runbook-3-pcr-7-drift-after-firmwarebios-update) sequence.

---

## 2. Installation Ceremonies

Alpine FDE supports two primary storage layouts. Choose the one that matches your hardware:


## iDRAC operational notes (this deployment)

- The vCD attachment can DROP across host power cycles — re-attach
  `alpine-standard-apeioff.iso` in the iDRAC Virtual Media before retrying a
  CD boot (the installer's bootcd phase guards `Inserted: true`).
- The firmware setup UI renders on VIDEO only (iDRAC virtual console); the
  serial console stays silent for the entire setup UI. Do key imports and
  BIOS/TPM settings from the virtual console.
- TPM SHA-256 bank: iDRAC web GUI → Configuration → BIOS Settings → Security →
  TPM Advanced Settings → TPM2 Algorithm Selection = SHA256 → Apply (the
  scheduled `BIOS.Setup.1-1` job reboots the server itself). iDRAC 8-era
  `racadm` cannot set BIOS attributes, and the platform hierarchy may be
  firmware-owned (`tpm2_pcrallocate` fails `0x9a2` even after
  `tpm2_dictionarylockout -c -p ""`).
- A forced `reboot -f` from the initrd can wedge the shutdown in the
  `megaraid_sas` path (console freezes mid `Synchronizing SCSI cache` /
  `megasas_disable_intr_fusion`, iDRAC PowerState stays On). Recovery: iDRAC
  power CYCLE (ForceOff → ForceOn — not a plain power-on). The
  `OsIndications` boot-to-firmware-setup request, once written, SURVIVES the
  wedge, so the next power-on still enters firmware setup.
- PCR 1 (BIOS-settings) drift after firmware/NVRAM work is expected; verify
  with `alpine-fde audit`, re-baseline with `alpine-fde audit --accept`, then
  `alpine-fde reseal` to restore passwordless unlock.
- Live ISO prep checklist (no lsblk/efibootmgr on the ISO; its apk repo only
  has the CD): bring eth0 up + udhcpc, add the dl-cdn network repo to
  `/etc/apk/repositories`, `apk add openssh efibootmgr`, set
  `PermitRootLogin yes` + root password (or stage the operator pubkey), start
  sshd. The firmware setup UI is video-only; serial stays silent there.
