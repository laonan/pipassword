# pipassword

A TUI password vault for Raspberry Pi hardware, including the
[Beepy](https://beepy.sqfmi.com/) handheld.

> **Status: alpha, under active construction.** The vault format is not yet
> implemented. Do not put real credentials in this yet. See
> `.kiro/specs/pipassword/tasks.md` for progress.

This is the successor to [minipassword](https://github.com/laonan/minipassword).
It is a **new codebase with a new data directory**, not an in-place upgrade. Your
existing `~/.minipassword/` vault is read **read-only** during import and is never
modified or deleted, so an abandoned migration costs you nothing.

## What is different from minipassword

| | minipassword | pipassword |
|---|---|---|
| Master password | none | Argon2id, `t=3`, `m=64 MiB`, `p=4` |
| Key storage | cleartext in `config.ini`, mode `0644` | wrapped by the master password; no key in any config file |
| Encrypted fields | `login_name`, `password` | every field, including `name`, `url`, `memo` |
| Cipher | Fernet (AES-128-CBC) | ChaCha20-Poly1305 |
| Multi-device | copy the file and hope | per-device append-only logs; conflicts are structurally impossible |
| Sync | bespoke HTTP upload/restore | Syncthing |
| Interface | prompts and a menu | full TUI, usable at 50×15 |
| Recovery | none | paper recovery key, standalone `recover.py`, documented format |

The design rationale, including why SQLCipher was rejected, is in
`.kiro/specs/pipassword/design.md`.

## Requirements

- **64-bit Raspberry Pi OS (aarch64)**, Python 3.11 or later
- 32-bit Raspberry Pi OS and ARMv6 boards (original Pi Zero / Zero W) are **not**
  supported: the required `manylinux aarch64` wheels do not apply, so `cryptography`
  and `argon2` would have to compile from source on the device

Verified on Pi Zero 2 W (Beepy), Pi 4, Pi 5.

## Install

```bash
pipx install pipassword
```

`pipx` keeps the vault's dependencies isolated from system Python, so the
`break-system-packages` workaround minipassword needed is no longer required.

## Development

The package targets aarch64 Linux, but the test suite runs anywhere:

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

The platform guard runs only at the command-line entry point, never on import, so
tests and `recover.py` work off-target. To run the CLI itself on a development machine:

```bash
PIPASSWORD_ALLOW_UNSUPPORTED=1 .venv/bin/pipw --help
```

Tests redirect `HOME` and the XDG base directories into a per-test temporary directory
via an autouse fixture, and assert the redirect held before each test body runs. No
test can reach a real vault.

## Licence

MIT
