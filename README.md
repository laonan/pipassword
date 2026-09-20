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

Linux on ARM with **Python 3.9 or later**. Both 32-bit and 64-bit Raspberry Pi OS
work, from Bullseye onward.

| Platform | Status |
|---|---|
| 64-bit Raspberry Pi OS (aarch64) | everything installs from a wheel |
| 32-bit Raspberry Pi OS (armv7l) | `argon2-cffi` compiles from source, ~1-3 min |
| armv6l (original Pi Zero / Zero W) | works, but slow; warned about |

The Beepy's recommended image is **32-bit Bullseye with Python 3.9**, so that is a
first-class target rather than an afterthought.

On 32-bit ARM you need a C toolchain first, because piwheels has no
`argon2-cffi-bindings` wheel for that architecture:

```bash
sudo apt install python3-venv build-essential python3-dev libffi-dev
```

That build is plain C with cffi and needs **no Rust**. `cryptography` is the
dependency that needs Rust, and [piwheels](https://www.piwheels.org/) already
provides it prebuilt for 32-bit ARM, which is why the dependency floor is
`cryptography>=42.0.8` rather than an exact pin — 42.0.8 is the newest piwheels
builds for `armv7l`.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/laonan/pipassword/main/install.sh | bash
```

Reading it first costs nothing, and for something that holds your passwords that
seems like a fair trade:

```bash
curl -fsSL https://raw.githubusercontent.com/laonan/pipassword/main/install.sh -o install.sh
less install.sh && bash install.sh
```

Pin to a tag rather than tracking `main`:

```bash
curl -fsSL .../install.sh | PIPASSWORD_REF=v0.1.0 bash
```

The installer needs no root and writes to three places:

```
~/.local/lib/pipassword/app     the source tree, including tests
~/.local/lib/pipassword/venv    a private virtualenv with the pinned dependencies
~/.local/bin/pipw               launcher
```

Your vault lives separately at `~/.local/share/pipassword/vault` and the installer
never touches it. That separation matters: you point Syncthing at the vault
directory, and the application must not be inside it.

| Variable | Effect |
|---|---|
| `PIPASSWORD_REF` | git ref to install (default `main`) |
| `PIPASSWORD_SOURCE` | install from a local checkout instead of downloading |
| `PIPASSWORD_PREFIX` | install prefix (default `~/.local`) |
| `PIPASSWORD_ALLOW_UNSUPPORTED` | skip the aarch64 check, for development |

Re-run the installer to update. `pipw-uninstall` removes the application and leaves
the vault alone.

### On piping a script into bash

This is not published to PyPI, so `curl | bash` replaces `pipx install`. Worth being
clear about what that does and does not change.

It is the same trust model as installing from a package index — you are executing
code fetched over HTTPS — except the source is a repository you control, which is
arguably better. What it loses is a signature and a version resolver.

Two mitigations are built in:

- **The whole script is one function, invoked on the final line.** If the transfer is
  cut off mid-download, bash executes whatever arrived. Without the wrapper, a
  truncated file could run half an installer; with it, an incomplete download simply
  never calls `main`.
- **The platform is checked before anything is written.** On 32-bit Raspberry Pi OS
  it refuses with an explanation rather than starting a source build that would take
  an hour and then fail.

What it does not give you is integrity verification. Pin `PIPASSWORD_REF` to a tag
and the content is at least stable; if you want more, clone the repository and run
`bash install.sh` from the checkout.

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
pipw benchmark [-n 10000]   measure the unlock hot path on this device
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

There is no built-in cloud upload. The legacy `minipassword` had one, and it is not
carried forward on purpose: its URL validator accepted `http://` and `ftp://` and
then POSTed the raw database to whatever it was given, and its restore path
overwrote the local database with the response body without validating it or taking
a snapshot first. File replication is a solved problem and Syncthing solves it
better than a bespoke endpoint would.

## Offsite backup

Syncthing is replication, not backup. It keeps machines you own in step, which means
a deletion propagates to all of them. For an offsite copy you want something that
does not follow your mistakes.

Every file in the vault is independently encrypted with a key derived from your
passphrase, so any provider can hold it without being able to read it:

```bash
rclone sync ~/.local/share/pipassword/vault remote:pipassword-backup
```

This is strictly safer than the old upload endpoint, which shipped a database whose
`name`, `url`, and `memo` columns were plaintext. Here the provider sees encrypted
blobs, and the only structure it can infer is how many devices you have and roughly
when each last made an edit, from the log filenames and their sizes.

Two things worth doing deliberately:

**Use `copy`, not `sync`, if you want protection from your own deletions.** `rclone
sync` mirrors, so a record you delete locally disappears from the backup too. Or keep
`sync` and turn on versioning at the provider.

**Back up `keys.N.mpk` separately as well.** It is 174 bytes, it rarely changes, and
**without it the logs cannot be decrypted even with the correct password.** It lives
inside the vault directory so any backup picks it up, but a copy somewhere
independent of that backup — alongside your paper recovery key — costs nothing and
removes a single point of failure. It is small enough to print:

```bash
base64 ~/.local/share/pipassword/vault/keys.1.mpk
```

### Restoring

There is no import step. The files on disk *are* the vault, so a restore is putting
the directory back:

```bash
rclone copy remote:pipassword-backup ~/.local/share/pipassword/vault
pipw list
```

This works on a device that has never seen the vault before. Your `device_id` lives
outside the vault, so a restored copy opened on a new machine simply gains one more
(initially empty) log file for that device. Nothing needs reconciling.

> **Do not restore an old backup over a live vault.** `rclone copy` overwrites, so a
> stale copy of *this* device's log would discard events newer than the backup. The
> append-only design protects you from concurrent edits, not from being overwritten
> by an older file. Restore into an empty directory, check it, then swap.

```bash
rclone copy remote:pipassword-backup /tmp/vault-check
pipw --vault /tmp/vault-check list        # does it have what you expect?
```

### Verifying a backup

Check occasionally rather than assuming. The recovery tool reads a vault directory
directly and writes nothing, so it can inspect a restored copy without touching your
live one:

```bash
pipw recovery-script -o /tmp/recover.py       # if you installed with the script
python3 /tmp/recover.py /tmp/vault-check | head -20
rm -rf /tmp/vault-check /tmp/recover.py
```

Using `recover.py` rather than `pipw` for this is deliberate: it exercises the
independent read path, so a passing check tells you the backup is readable even
without this software.

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

## Performance, and whether to reach for C

Measured, not assumed. `pipw benchmark` builds a throwaway vault and times the
post-unlock hot path; your real vault is never opened.

On an M-series Mac with 10,000 records:

```
  decrypt frames       32.0 ms   (41.7%)  AEAD in C, loop in Python
  decode events        27.4 ms   (35.6%)  json in C, validation in Python
  fold                 17.4 ms   (22.7%)  pure Python
  total                76.8 ms
```

Two things follow from that shape.

**The expensive primitives are already C.** Argon2id comes from `argon2-cffi`,
ChaCha20-Poly1305 from `cryptography`, and JSON parsing from CPython's C scanner.
What is left in Python is loop overhead and dictionary work. Rewriting the vault in C
would target the 77 ms, not the parts that actually cost time.

**Key derivation dominates anyway.** At the default 64 MiB it is ~30 ms here and
plausibly ~1 s on a Pi Zero 2 W — likely more than the entire rest of unlock. Run
`pipw calibrate` for that half.

So before writing any C, the order of leverage is:

1. **Log compaction** (listed as deferred in the task plan). Collapsing N events into
   one snapshot frame removes this work rather than speeding it up: unlock would
   decrypt one frame instead of ten thousand. Pure Python, and the `seq` and coverage
   fields it needs are already specified.
2. **Lower `time_cost`** if `calibrate` says derivation is the bottleneck. This is a
   real security trade, so make it deliberately.
3. **Then** consider a native accelerator.

If it does come to that, the boundary is already clean. The two hot functions are
`format.read_log` and `events.fold`, both of which take bytes and return plain data
structures with no vault state involved. [`FORMAT.md`](FORMAT.md) specifies the
on-disk format independently of any language, so a native implementation needs no
format change and `recover.py` stays as the pure-Python fallback that must always
work. Measure on the Beepy first:

```bash
pipw benchmark -n 10000
pipw calibrate
```

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

The suite is expected to pass on **3.9 as well as 3.11+**, because the Beepy runs
3.9.2. Two shims in `compat.py` make that work: `dataclass(slots=True)` is 3.10+, so
it is applied conditionally, and `tomllib` is 3.11+, so `tomli` is a conditional
dependency below that. If you touch either, check both versions:

```bash
python3.9 -m venv /tmp/v39 && /tmp/v39/bin/pip install -e ".[dev]"
PYTHONPATH=src /tmp/v39/bin/pytest
```

`pyproject.toml` is kept as the dependency manifest and the development entry point,
not as a PyPI package — `install.sh` reads the pins through pip. The tests also ship
with the installed application, so you can verify on the device itself:

```bash
cd ~/.local/lib/pipassword/app
~/.local/lib/pipassword/venv/bin/python -m pip install pytest
~/.local/lib/pipassword/venv/bin/python -m pytest
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
