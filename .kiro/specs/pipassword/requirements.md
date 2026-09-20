# pipassword — Requirements

## Introduction

`pipassword` is a new project that replaces `minipassword` with a security-hardened,
TUI-driven password vault targeting Raspberry Pi hardware, including the handheld
Beepy (400×240 Sharp Memory LCD, 50×15 character console).

It is a **new codebase with a new data directory**, not an in-place upgrade. The
existing `minipassword` installation and its data at `~/.minipassword/` remain
untouched and fully functional. `pipassword` imports legacy data **read-only**, so a
failed or abandoned import leaves the original vault intact. This is the primary risk
control for the migration.

### Why a rewrite rather than a patch

The legacy design has one defect that cannot be patched incrementally: there is no
master secret. `Fernet.generate_key()` writes the encryption key in cleartext to
`~/.minipassword/config.ini` (observed on disk as mode `0644`), and the application
reads it back unattended. Every other finding is downstream of that. Introducing a
KDF, a master password, and whole-record encryption changes the on-disk format,
the key hierarchy, and the sync model simultaneously.

### Threat model

In scope:

- **T1** — Device lost, stolen, or powered off. Primary threat. Defended by a
  memory-hard KDF and authenticated encryption.
- **T2** — A vault copy leaks via Syncthing, a backup, or a spare SD card. Same
  defence as T1.
- **T3** — Shoulder-surfing while the vault is open on a handheld in public.
  Defended by masking secrets and a short reveal window.
- **T4** — Accidental data loss: a bad sync, a mistaken delete, a mid-write power
  failure on a battery device. Defended by append-only storage and event history.

Out of scope, and explicitly not claimed:

- Malware running as the user while the vault is unlocked. Unsolvable in a Python
  process; plaintext is in memory by necessity.
- Coercion, and plausible-deniability or decoy vaults.
- Offline brute force throttling. An attacker with the vault file bypasses the
  application entirely; the only real defence is the KDF cost.

---

## 1. Platform

**User story:** As a user with several Raspberry Pi boards, I want one tool that
installs cleanly on all of them without compilation.

1.1. The system SHALL support Raspberry Pi OS on `aarch64`, `armv7l` and `armv6l`,
in both 32-bit and 64-bit variants, from Bullseye onward.

**Corrected after production contact.** This originally specified 64-bit only, on the
basis that the Beepy ran a 64-bit image. It does not: the Beepy's recommended image is
32-bit Raspberry Pi OS Bullseye on `armv7l` with **Python 3.9.2**. Requiring 64-bit
would have meant reinstalling the OS and rebuilding the working sharp-drm, fbterm,
fcitx and Google Pinyin stack, which is a far larger cost than supporting 32-bit.

1.2. No dependency may require compilation from source on a target device. Every
dependency SHALL resolve to a `manylinux aarch64` wheel or a pure-Python wheel.

1.2a. The system SHALL be delivered by a `curl | bash` installer, not published to
PyPI. It is a personal tool for one person's devices, and a shell installer keeps the
door open for non-Python components later without changing how it is installed.

1.2b. The installer SHALL be safe against a truncated download. All logic SHALL live
in a function invoked on the final line, so an incomplete transfer cannot execute a
partial installer.

1.2c. The installer SHALL require no root, SHALL verify the platform before writing
anything, and SHALL NOT place the application inside the vault directory, which is
the directory the user shares with Syncthing.

1.2d. The installer SHALL provide an uninstall path that removes the application and
leaves the vault untouched.

1.3. The system SHALL NOT support macOS, Windows, or 32-bit ARM. 32-bit Raspberry Pi
OS and ARMv6 boards (original Pi Zero / Zero W) are unsupported because the required
`manylinux_2_28_aarch64` wheels do not apply.

1.4. WHEN the system starts on an unsupported architecture THEN it SHALL exit with a
message naming the requirement, rather than failing inside a dependency import.

1.5. The system SHALL operate with no network access at any point. Network is
required only by Syncthing, which is a separate process outside this project's scope.

1.6. The system SHALL require Python 3.9 or later. Raspberry Pi OS Bullseye ships
3.9.2, which is what the Beepy runs.

1.6a. Where a newer-Python feature is worth having, it SHALL be applied conditionally
rather than raising the floor. `dataclass(slots=True)` (3.10+) and `tomllib` (3.11+)
are handled in `compat.py`.

1.7. Dependencies SHALL be expressed as version ranges, not exact pins. Exact pins
were tried first and failed on the real target: piwheels caps `cryptography` at
42.0.8 for `armv7l`, and `prompt_toolkit` 3.0.53 requires Python 3.10. The RFC 8439
known-answer test is what guards against a bad crypto build, not the pin.

---

## 2. Cryptography

**User story:** As a user whose vault may be copied off a lost device, I want the
vault to resist offline attack by anyone who obtains the file.

2.1. The system SHALL derive a key-encryption key (KEK) from the master password
using Argon2id via `argon2-cffi`.

2.2. Default Argon2id parameters SHALL be `time_cost=3`, `memory_cost=65536` (64 MiB),
`parallelism=4`, `hash_len=32`. The 64 MiB ceiling is set by the Pi Zero 2 W's 512 MB
of RAM shared with Syncthing.

2.3. Argon2id parameters SHALL be stored in the vault keyfile so that any device can
open a vault created on any other device.

2.4. The system SHALL provide a `calibrate` command reporting measured unlock time on
the current device.

2.5. WHEN opening a vault whose `memory_cost` exceeds available system memory THEN the
system SHALL refuse with an explanatory error naming the shortfall, rather than
risking an OOM kill.

2.6. The system SHALL generate a random 256-bit data-encryption key (DEK) at vault
creation, independent of the master password.

2.7. The DEK SHALL be wrapped by the KEK. Changing the master password SHALL rewrap
the DEK without re-encrypting vault contents.

2.8. The system SHALL encrypt all record data with ChaCha20-Poly1305 via
`cryptography`. ChaCha20 is chosen over AES because no 64-bit Raspberry Pi except the
Pi 5's BCM2712 has ARMv8 AES instructions.

2.9. Every AEAD operation SHALL bind its file header as associated data, preventing
version or KDF-parameter downgrade.

2.10. The system SHALL encrypt **every** field, including `name`, `url`, and `memo`.
No record metadata may appear in plaintext on disk.

2.11. The system SHALL NOT write any key, key material, or plaintext record data to
any configuration file.

2.12. The system SHALL create its data directory mode `0700` and all vault files mode
`0600`.

2.13. The system SHALL read the master password without terminal echo.

---

## 3. Storage and sync

**User story:** As a user who edits passwords on multiple devices, I want every
device to show one unified vault, and I never want an entry to disappear.

3.1. The vault SHALL be a directory containing a keyfile and one append-only
encrypted log file per device.

3.2. Each device SHALL write only to its own log file, and SHALL NOT modify any other
device's log file. This makes a Syncthing conflict structurally impossible, because
no path ever has two writers.

3.3. The system SHALL derive vault state by reading all log files and folding their
events in deterministic order. All devices holding the same set of files SHALL
compute identical state.

3.4. A device's identity SHALL be stored outside the vault directory so it is never
synced. Two devices sharing an identity would share a log file and reintroduce
conflicts.

3.5. Event timestamps SHALL use a hybrid logical clock:
`timestamp = max(physical_now, highest_timestamp_observed + 1)`. This is mandatory
because no Raspberry Pi before the Pi 5 has a battery-backed RTC, so a Beepy booting
from `fake-hwclock` may report a time days in the past. Without it, a current edit
could sort before an older one and be silently discarded.

3.6. Conflicting edits SHALL resolve per field by last write. Concurrent edits to
different fields of the same record SHALL both survive.

3.7. A superseded value SHALL remain in the event log and be recoverable via history.

3.8. Deletion SHALL be recorded as a tombstone event, never by removing data from a
log.

3.9. WHEN a log frame is truncated or fails authentication THEN the system SHALL skip
it, report it, and load all remaining events. A power failure mid-append SHALL cost
at most the final event.

3.10. Writes SHALL be append-plus-`fsync`. Any whole-file replacement SHALL be atomic
via `os.replace`.

3.11. WHEN a vault is opened THEN the system SHALL report which records changed on
other devices since this device last opened it.

3.12. WHEN a `*.sync-conflict-*` file is present THEN the system SHALL report it as an
anomaly, since requirement 3.2 means one should never occur.

3.13. The system SHALL NOT implement network sync, cloud upload, or cloud restore.
File replication is delegated to Syncthing. The legacy `upload_db`/`restore_db` code
path is deliberately not carried forward.

3.14. The system SHALL support at least 10,000 records with unlock under 3 seconds on
a Pi Zero 2 W, excluding KDF time.

---

## 4. Terminal interface

**User story:** As a Beepy user, I want the vault fully usable on a 50×15 monochrome
console with a thumb keyboard and a Pinyin IME.

4.1. The TUI SHALL be fully functional at 50 columns × 15 rows — the Beepy's geometry
at 400×240 with an 8×16 console font.

4.2. The TUI SHALL NOT convey information by colour alone. The Beepy console runs
`TERM=xterm-mono`.

4.3. The TUI SHALL leave the bottom terminal row free of essential content, because
`fcitx-fbterm` draws its Pinyin candidate bar there.

4.4. The TUI SHALL repaint only in response to input events. No timers, animations,
or periodic refresh. Two reasons: a repaint during IME composition erases the
candidate bar, and the Sharp Memory LCD is driven over SPI where full repaints are
costly.

4.5. The TUI SHALL compute all text width with `wcwidth` and never with `len()`. CJK
characters occupy two columns; the legacy `item[:40]` truncation corrupts the display
on a 50-column screen.

4.6. The TUI SHALL bind single-key commands only. The BBQ20 keyboard has no arrow
keys, no function keys, and awkward modifiers.

4.7. The TUI SHALL NOT bind `Ctrl+Space`, which `fcitx` reserves for IME switching.

4.8. The TUI SHALL accept `j`/`k`, arrow keys, and trackpad scroll for navigation.

4.9. The TUI SHALL detect terminal size and use an expanded layout on larger
terminals.

4.10. Passwords SHALL be masked by default, revealed only on explicit keypress, and
re-masked automatically after 15 seconds.

4.11. The system SHALL clear the screen region containing a revealed secret on exit,
leaving no secret in scrollback.

4.12. Search SHALL match against name, URL, and memo.

4.13. Search SHALL match Chinese entries by **Pinyin initials and full Pinyin**, so
that `qyyx` or `qiyeyouxiang` finds `企业邮箱`. This removes the need to switch IME
merely to locate an entry.

4.14. The Pinyin index SHALL be computed at write time and stored inside the
encrypted log, so `pypinyin` is not a runtime dependency on the Pi and the index does
not leak plaintext.

4.15. The system SHALL provide a non-interactive CLI suitable for scripting, for use
on larger terminals.

4.16. The system SHALL provide a password generator, including a mode that avoids
characters requiring the BBQ20 symbol layer, for passwords that must be typed by hand
on the Beepy.

4.17. The system SHALL NOT auto-lock and SHALL NOT run a background daemon. The key
is held only for the lifetime of one foreground session and discarded on exit.

---

## 5. Legacy import

**User story:** As a user with an existing `minipassword` vault, I want to import it
with certainty that the original is untouched and the copy is complete.

5.1. The system SHALL import from a legacy `minipassword` SQLite database plus its
`config.ini`, decrypting `login_name` and `password` with the legacy Fernet key.

5.2. The system SHALL open all legacy files **read-only** and SHALL NOT write,
modify, move, or delete `~/.minipassword/` or any file within it, under any code
path.

5.3. The system SHALL provide `--dry-run`, reporting record count, records containing
CJK text, records with non-empty memo and url, duplicate names, and any record whose
Fernet decryption fails — without writing anything.

5.4. WHEN a record fails to decrypt THEN the system SHALL record the failure, skip
that record, continue the import, and list all failures in the final report. A single
bad record SHALL NOT abort the import.

5.5. The system SHALL preserve each legacy integer `id` as a `legacy_id` field for
cross-reference.

5.6. AFTER import the system SHALL re-open the new vault from disk and verify every
field of every record against the legacy source by comparison hash.

5.7. WHEN verification fails THEN the system SHALL report the specific mismatches and
exit non-zero. Success SHALL NOT be reported on the basis of the import completing
without an exception.

5.8. The system SHALL also import the plaintext JSON layout used by the legacy
`tests/importfromjsonfile.py`, correcting that script's off-by-one reporting bug.

5.9. The system SHALL be idempotent on re-import: running the same import twice SHALL
NOT create duplicates.

5.10. AFTER a verified import the system SHALL advise that the legacy key was stored
world-readable and that high-value credentials should be rotated, and SHALL advise
securely erasing the legacy files manually once satisfied. It SHALL NOT erase them
itself.

---

## 6. Recoverability

**User story:** As a user, my worst outcome is being locked out of my own vault. I
want that to be impossible even if this software stops working.

6.1. The system SHALL generate a 256-bit recovery key at vault creation, displayed as
transcribable grouped Base32, and SHALL instruct the user to record it on paper.

6.2. The recovery key SHALL unwrap the DEK independently of the master password, so a
forgotten password is not fatal.

6.3. The repository SHALL contain a standalone `recover.py` that dumps the vault to
plaintext JSON given the vault directory and either the master password or the
recovery key. It SHALL depend only on `cryptography` and `argon2-cffi`, and SHALL NOT
import any other module of this project.

6.4. The repository SHALL contain `FORMAT.md` specifying the on-disk format precisely
enough to write an independent decryptor. Only standard primitives are used; no
custom cryptographic construction.

6.5. The system SHALL provide `export --plaintext` to JSON, always available while
unlocked.

6.6. Master password rotation SHALL append a new keyfile generation rather than
rewriting the existing keyfile, preserving the append-only property across the whole
vault directory.

6.7. The system SHALL document that the keyfile is required to open the vault and
SHALL support printing it as transcribable text for offline backup.

---

## 7. TOTP

**User story:** As a user who is sometimes fully offline, I want my TOTP seeds safely
stored, and I never want to be shown a code that is silently wrong.

7.1. The system SHALL store TOTP secrets and `otpauth://` URIs as record fields.
Storage is unconditional; the seed backup is valuable independent of code generation.

7.2. The system SHALL generate TOTP codes locally with no network access. RFC 6238 is
an HMAC over a time counter; the algorithm itself has no connectivity requirement.

7.3. The system SHALL persist a `last_known_good_time` on every vault write.

7.4. WHEN the system clock is earlier than `last_known_good_time` THEN the system
SHALL refuse to display a TOTP code, state that the clock is unreliable, and offer to
set the time. Raspberry Pi boards before the Pi 5 have no battery-backed RTC; the
Beepy's RP2040 RTC exists but its firmware documents that RTC state is lost on
power-switch-off or deep sleep, which is the default auto-off path.

7.5. The system SHALL accept a manual time override so a code can still be produced
when the correct time is known from another source.

7.6. The system SHALL NOT display a TOTP code without a clock-validity check.

---

## 8. Non-goals

- macOS, Windows, 32-bit ARM support
- KDBX / KeePass interoperability
- Built-in network sync, cloud upload, or cloud restore
- Auto-lock, background agent, or resident daemon
- Browser integration or autotype
- Multi-user or shared-team vaults
- Log compaction in v1. Roughly 10,000 records at a few hundred bytes per event is a
  few megabytes, so compaction is a later convenience. The `seq` and coverage fields
  needed to add it are specified now.
