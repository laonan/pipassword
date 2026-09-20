# pipassword

A TUI password vault for Raspberry Pi hardware, including the
[Beepy](https://beepy.sqfmi.com/) handheld.

Successor to [minipassword](https://github.com/laonan/minipassword). It is a **new
codebase with a new data directory**, not an in-place upgrade. Your existing
`~/.minipassword/` vault is opened read-only during import and never modified, so an
abandoned migration costs you nothing.

> **Status: alpha.** The storage format, CLI, and TUI are implemented and tested,
> but this has not yet been run in anger on real hardware. Keep your legacy vault
> until you have verified an import and can open the new one on every device.

---

## Why this exists

The legacy tool had one defect that could not be patched incrementally: **there was
no master secret.** `Fernet.generate_key()` wrote the encryption key in cleartext to
`~/.minipassword/config.ini` — observed on disk at mode `0644`, world-readable — and
the application read it back unattended. Anything that could read your home
directory had the vault.

|  | minipassword | pipassword |
|---|---|---|
| Master password | none | Argon2id, `t=3`, `m=64 MiB`, `p=4` |
| Key at rest | cleartext in `config.ini`, mode `0644` | wrapped by your password; no key in any config file |
| Encrypted fields | `login_name`, `password` | **every** field, including `name`, `url`, `memo` |
| Cipher | Fernet (AES-128-CBC) | ChaCha20-Poly1305 |
| Multi-device | copy the file and hope | per-device append-only logs; conflicts structurally impossible |
| Sync | bespoke HTTP upload/restore | Syncthing |
| Interface | prompts and a menu | full TUI, usable at 50×15 |
| CJK display | `item[:40]`, corrupts the menu | `wcwidth` everywhere |
| Finding CJK entries | switch IME, compose, search | type `qyyx` |
| Recovery | none | paper recovery key, standalone `recover.py`, documented format |

Design rationale, including why SQLCipher was rejected, is in
[`.kiro/specs/pipassword/design.md`](.kiro/specs/pipassword/design.md). The on-disk
format is specified in [`FORMAT.md`](FORMAT.md).

## Requirements

- **64-bit Raspberry Pi OS (aarch64)**, Python 3.11 or later
- 32-bit Raspberry Pi OS and ARMv6 boards (original Pi Zero / Zero W) are **not
  supported**: the required `manylinux aarch64` wheels do not apply, so
  `cryptography` and `argon2` would have to compile from source on the device

Every dependency installs from a wheel. Nothing compiles on the Pi.

## Install

```bash
sudo apt install pipx
pipx install pipassword
```

`pipx` isolates the dependencies from system Python, so the
`break-system-packages` workaround minipassword needed is no longer required.

## Quick start

```bash
pipw gen -p                 # pick a master passphrase
pipw init                   # create the vault, print the recovery key
pipw tui                    # the interface you will actually use
```

`init` prints a recovery key **once**. Write it on paper. It is the only way into
the vault if you forget your master password, and nothing stores it for you.

---

## Commands

```
pipw tui                    full-screen interface
pipw list                   list every entry
pipw get QUERY              show one entry (password masked)
pipw get QUERY --field password     bare value, for piping
pipw add NAME [--login ...] [--password ...] [--url ...] [--memo ...] [--totp ...]
pipw edit QUERY --password ...      change named fields only
pipw delete QUERY
pipw gen [-n 20] [-t] [-p] [-w 6]   password or passphrase
pipw totp QUERY [--at "14:30"]
pipw export --plaintext [--output FILE]
pipw passwd                 change the master password
pipw calibrate              measure unlock time on this device
pipw import-legacy [--dry-run]
pipw import-json PATH [--dry-run]
pipw recovery-script -o recover.py      write out the standalone recovery tool
pipw where                  show vault and config paths
```

Secrets reach stdout only when you ask for them. Prompts, warnings, and the sync
summary go to stderr, so this works:

```bash
pipw get github --field password | wl-copy
```

## Migrating from minipassword

The import is read-only and verified. Nothing in `~/.minipassword/` is written,
moved, or deleted at any point.

```bash
pipw import-legacy --dry-run     # report only, writes nothing
pipw import-legacy               # import, then verify against the source
```

The dry run reports how many rows were found, how many contain CJK, how many have a
memo or url, duplicate names, and any row that will not decrypt. A row that fails is
skipped and listed; it does not abort the rest.

After writing, the vault is **closed and reopened cold from disk**, and every field
of every record is compared against the legacy source by hash. If anything differs,
you get the specific records and a non-zero exit. Completing without an error is not
treated as success.

Once verified, two things are worth doing:

1. **Rotate high-value credentials.** The legacy key lived in cleartext at mode
   `0644` and may exist in old backups. If that machine was never shared the real
   exposure is probably low, so treat this as a prioritised task rather than an
   emergency: banking, email, and anything with payment details first.
2. **Erase the legacy files** once you are satisfied. `pipassword` will not do it
   for you.
   ```bash
   shred -u ~/.minipassword/minipassword.db ~/.minipassword/config.ini
   ```

Until then your passwords exist in two places, one of them weakly protected.

## Syncing with Syncthing

Share the **vault directory**, not individual files:

```
~/.local/share/pipassword/vault/
```

Each device appends only to its own log file, so no path ever has two writers and
Syncthing has nothing to reconcile. A `.sync-conflict-*` file should be impossible;
if one appears, `pipassword` reports it as an anomaly, because the likely cause is
two devices sharing a `device_id`.

Recommended folder settings:

- **File versioning: staggered.** Costs nothing and is your undo of last resort.
- A default `.stignore` is written into new vaults, excluding temp and lock files.
- **Do not** use Syncthing's untrusted-device encryption. The payload is already
  encrypted and that should not be your security layer.

Concurrent edits merge per field. If you change a password on the Beepy while
offline and edit the same entry's memo on a Pi, both survive. Only a change to the
*same field* is superseded, and the old value stays in the log.

Device identity lives in `~/.config/pipassword/device_id`, deliberately **outside**
the vault. Do not sync your config directory — two devices sharing a `device_id`
would share a log file and reintroduce conflicts.

## Beepy notes

The TUI targets **50 columns × 15 rows**, which is what a 400×240 Sharp Memory LCD
gives with fbterm's 8×16 font.

For CJK display and Pinyin input, follow
[CJK support on Beepy](https://gist.github.com/charlestsai1995/54ab65a87e2e063ea25eb3aec4193fe1)
(sharp-drm driver, fbterm, fcitx with Google Pinyin). `pipassword` is built for that
stack specifically:

- The **bottom terminal row is left blank**, because `fcitx-fbterm` draws its
  candidate bar there.
- **Repaints happen only on keypress.** No timers, no animation. A repaint during
  IME composition erases the candidate bar, and the Sharp LCD repaints over SPI.
- **No colour is used.** `TERM=xterm-mono`. Selection is reverse video plus a `»`
  marker, so it stays visible either way.
- **`Ctrl+Space` is never bound**, since fcitx owns it for switching input method.
- All text is measured with `wcwidth`, so double-width CJK never overflows the line.

### Finding Chinese entries without switching IME

Type Pinyin initials or syllables:

```
> qyyx                                         1/2
» 企业邮箱 · alan@corp.cn
  企业邮箱备用 · backup@corp.cn
```

`qyyx`, `qiyeyouxiang`, `youxiang`, and `企业` all match. The index is built when a
record is saved and stored **inside the encrypted log**, so `pypinyin` never loads on
the read path and the index does not leak entry names.

### Keys

In the list, typing searches. Navigation is the trackpad (which emits arrows), or
`Ctrl+N`/`Ctrl+P`, or Tab.

| Key | Action |
|---|---|
| any printable | narrow the search |
| trackpad / `↑` `↓` / `^n` `^p` / Tab | move selection |
| `Enter` | open entry |
| `Esc` | clear search, then quit |
| `^a` | add entry |
| `^g` | generate a password into a new entry |
| `^q` | quit |

In the detail view there is no search box, so single letters are free: `p` reveals
the password for 15 seconds, `e` edits, `d` deletes, `Esc` goes back.

### Generated passwords you have to type

`pipw gen --thumb` omits symbols, which sit behind a modifier layer on the BBQ20
keyboard. Length more than compensates: 20 thumb-typable characters is about 116
bits, against 79 for 12 characters from the full set. The TUI uses thumb mode
automatically on a narrow terminal.

## TOTP

Codes are generated locally; RFC 6238 is an HMAC over a time counter and never
touches the network. The fragile part is the **clock**, not connectivity.

No Raspberry Pi before the Pi 5 has a battery-backed RTC. A board that has been
powered off boots with `fake-hwclock` restoring the time from its last shutdown, so
after a week off every code would be wrong. The Beepy's RP2040 does expose RTC
registers and its keyboard driver pushes NTP time into them when a network is
available, but the firmware documents that RTC state is lost on power-switch-off or
deep sleep — and deep sleep is the default auto-off path.

So `pipassword` splits the feature:

- **Secrets are always stored.** Inert data, and for most people it is the only
  backup of the seed they have.
- **Codes are refused when the clock cannot be trusted**, with an explanation,
  rather than shown wrong. A wrong code looks like the service rejecting you.

If you know the real time from a watch or phone:

```bash
pipw totp corp --at "14:30"
```

## If you are locked out

Four independent paths, so no single failure costs you the data.

**1. The paper recovery key.** Unwraps the vault independently of your master
password.

```bash
pipw list --recovery-key
```

**2. `recover.py`.** About 420 lines, standalone, importing only `cryptography` and
`argon2-cffi` — nothing from this package. It works if the package is broken or
uninstalled.

A copy ships inside the wheel, so you can get it without a git checkout:

```bash
pipw recovery-script -o recover.py
python3 recover.py ~/.local/share/pipassword/vault > vault.json
python3 recover.py /path/to/vault --recovery-key --output vault.json
```

Keep a copy somewhere you can reach **without** this tool — the same place as your
paper recovery key is a reasonable choice.

**3. [`FORMAT.md`](FORMAT.md).** Byte-level specification, standard primitives only.
Enough to write your own decryptor. The test suite requires `recover.py`'s output to
match the package's own export exactly, which is what keeps the document honest.

**4. `pipw export --plaintext`.** Always available while unlocked.

### Back up the keyfile

`keys.N.mpk` is 174 bytes and rarely changes. **Without it the logs cannot be
decrypted, even with the right password.** It lives in the synced vault directory,
so Syncthing already replicates it, but a copy somewhere else is cheap insurance.

### After changing your master password

`pipw passwd` writes a new keyfile generation, verifies it opens, then moves the old
one to `archive/`. Until you delete that file, **someone who finds it can still use
your old password.** Delete `archive/` once you are satisfied.

Your printed recovery key keeps working; it is not changed by a password change.

## Calibrating the KDF

```bash
pipw calibrate
```

Argon2 parameters are stored in the keyfile, so **one setting governs every device**.
Calibrate on the slowest board that will open this vault. A vault created with more
memory than a board has will not open there at all — `pipassword` refuses with an
explanation rather than being OOM-killed, but you still cannot get in.

64 MiB is the default because the Pi Zero 2 W has 512 MB shared with Syncthing.

One honest caveat: an attacker runs the derivation on fast hardware, so the KDF buys
perhaps 10–20 bits of work factor. **Your passphrase entropy is what actually carries
the security.** Use `pipw gen -p`; six words is about 59 bits, and a word sequence is
far easier to thumb-type than a short symbol-heavy string.

## Security summary

In scope and defended:

- Device lost, stolen, or powered off; a vault copy leaking via sync or a spare SD
  card. Argon2id plus ChaCha20-Poly1305, with every field encrypted and all file
  headers authenticated so KDF parameters cannot be downgraded.
- Shoulder-surfing on a handheld. Passwords masked by default, revealed for 15
  seconds, masked during entry, fixed-width mask so length does not leak.
- Accidental loss. Append-only logs, atomic durable writes, a damaged frame costing
  at most one event, deletions as recoverable tombstones.

Out of scope, and not claimed:

- **Malware running as you while the vault is unlocked.** Plaintext is in process
  memory by necessity, and Python cannot reliably erase it. `close()` zeroes what it
  can and that is the honest limit.
- Coercion, and plausible-deniability or decoy vaults.
- Offline brute-force throttling. An attacker with the file bypasses the
  application; the KDF is the only real defence.

## Development

The package targets aarch64 Linux, but the test suite runs anywhere:

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The platform guard runs only at the CLI entry point, never on import, so tests and
`recover.py` work off-target. To run the CLI on a development machine:

```bash
PIPASSWORD_ALLOW_UNSUPPORTED=1 .venv/bin/pipw --help
```

Tests redirect `HOME` and the XDG base directories into a per-test temporary
directory via an autouse fixture, and assert the redirect held before each test body
runs. No test can reach a real vault. This is deliberately heavier than usual,
because the legacy suite did reach real data: `tests/test_manager.py` constructed
`PasswordManager()` with no arguments and `test_delete_password` deleted record id 1.

## Licence

MIT
