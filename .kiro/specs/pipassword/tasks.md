# pipassword — Implementation Plan

Sequenced so that each task is independently testable, and so that **recovery tooling
exists before any real data is imported** (tasks 7–8 precede task 10).

---

- [x] 1. Project scaffold
  - Create the `pipassword` package layout, `pyproject.toml` with PEP 621 metadata
    (replacing the legacy `setup.py`), and `requires-python = ">=3.11"`
  - Pin exact versions: `cryptography`, `argon2-cffi`, `prompt_toolkit`, `wcwidth`,
    `pypinyin`, `pyotp`. Drop `requests` and `simple-term-menu`
  - Add an architecture guard that exits with a clear message on non-aarch64 or
    Python < 3.11, before any dependency import
  - Set up pytest with a temporary-vault fixture. No test may touch a real vault path
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.6_

- [x] 2. Crypto primitives (`crypto.py`)
  - `derive_kek(password, salt, params)` via `argon2-cffi` `hash_secret_raw`,
    `Type.ID`, defaults `t=3`, `m=65536`, `p=4`, `hash_len=32`
  - `derive_rkek(recovery_key)` via keyed BLAKE2b with `person=b"pipw-rkey"`
  - `aead_encrypt/decrypt(key, nonce, plaintext, aad)` over ChaCha20-Poly1305
  - `generate_dek()`, `generate_recovery_key()`, Base32 grouped encode/decode
  - `check_memory_available(memory_cost)` reading `MemAvailable` from `/proc/meminfo`
  - Known-answer tests; assert AAD tampering fails
  - _Requirements: 2.1, 2.2, 2.6, 2.8, 2.9, 6.1_

- [x] 3. Keyfile format (`format.py`)
  - Encode/decode `keys.<gen>.mpk` exactly per design §3.1
  - Bind `HDR = bytes[0:54]` as AAD on both wrap slots
  - `create_keyfile` (password + recovery slots), `open_keyfile` trying the highest
    generation and falling back
  - Write mode `0600`; create the data directory mode `0700`
  - Test: mutating `memory_cost` in a keyfile must fail authentication
  - Test: refuse to open when `memory_cost` exceeds available RAM, naming the shortfall
  - _Requirements: 2.3, 2.5, 2.7, 2.9, 2.12_

- [x] 4. Log format (`format.py`)
  - Write the 42-byte log header; `append_frame` with length prefix, 12-byte random
    nonce, AAD = `log_header || frame_len`
  - `read_frames` as a generator, returning valid frames and a list of anomalies
  - Append path: `write` then `fsync`
  - Test: truncate a log at every byte offset; all complete frames recovered, no crash
  - Test: a frame moved between two logs must fail authentication
  - _Requirements: 3.9, 3.10, 2.9_

- [x] 5. Event model and fold (`events.py`)
  - CBOR event encode/decode per design §3.3
  - `next_ts(highest_seen)` hybrid logical clock
  - `fold(events)` sorting on `(ts, device_uuid, seq)`, per-field last-write-wins,
    tombstones, and resurrection by a later `set`
  - Property test: shuffled arrival order and log membership yield identical state
  - Test: a device with a one-week-stale clock still has its new edits sort last
  - Test: concurrent edits to different fields of one record both survive
  - _Requirements: 3.3, 3.5, 3.6, 3.7, 3.8_

- [x] 6. Vault API (`vault.py`)
  - `Vault.create`, `Vault.unlock(password | recovery_key)`, `Vault.close` zeroing
    what can be zeroed
  - `device_id` provisioning in `~/.config/pipassword/device_id`, never inside the
    vault directory
  - Log filename derived from device id; open own log for append, all logs for read
  - `add`, `update`, `delete`, `get`, `search`, `history(record_id)`
  - `changes_since_last_open()` for the unlock summary
  - Detect and report `*.sync-conflict-*` as an anomaly
  - Persist `last_known_good_time` on every write
  - `config.toml` load/save containing no secrets
  - _Requirements: 2.11, 3.1, 3.2, 3.4, 3.11, 3.12, 4.17, 7.3_

- [x] 7. `FORMAT.md`
  - Normative byte-level specification of keyfile and log, including AAD construction,
    the fold ordering rule, and the HLC rule
  - Sufficient to write an independent decryptor with no reference to the source
  - _Requirements: 6.4_

- [x] 8. Standalone `recover.py`
  - Single file outside the package, importing only `cryptography` and `argon2-cffi`
  - Accepts a vault directory plus master password or recovery key; emits plaintext
    JSON on stdout
  - Duplicates the read path deliberately; imports nothing from `pipassword`
  - CI test: output must match `export --plaintext` for a generated vault
  - _Requirements: 6.2, 6.3_

- [x] 9. CLI (`cli.py`)
  - `init` — create vault, display the grouped Base32 recovery key, require
    acknowledgement that it was recorded
  - `get <query> [--field F]`, `add`, `edit`, `delete`, `list`
  - `export --plaintext`, `passwd` (append a new keyfile generation), `calibrate`
  - Password entry without echo via `getpass`
  - _Requirements: 2.4, 2.13, 4.15, 6.1, 6.5, 6.6_

- [x] 10. Legacy import (`importer.py`)
  - Open the legacy SQLite via `file:...?mode=ro`; read `aes_key` from the legacy
    `config.ini`; decrypt `login_name` and `password` with Fernet
  - Module must contain no write-mode `open`, `os.remove`, or `shutil` call targeting
    the legacy directory — assert this in a test
  - `--dry-run`: record count, CJK records, non-empty memo/url counts, duplicate
    names, decryption failures; writes nothing
  - Collect and report `InvalidToken` per record; never abort the run
  - Preserve `legacy_id`; idempotent re-import keyed on it
  - **Verify**: re-open the vault cold and compare every field by hash against the
    source; on mismatch report the specific records and exit non-zero
  - Post-import advisory: rotate high-value credentials (the legacy key was mode
    `0644`), and erase legacy files manually. Never erase them automatically
  - JSON importer for the legacy `importfromjsonfile.py` layout, without its
    off-by-one reporting bug
  - Test with a fixture legacy DB; assert legacy file mtime and content hash unchanged
  - _Requirements: 5.1–5.10_

- [x] 11. Pinyin index (`pinyin.py`)
  - Build initials and full Pinyin per CJK field at write time; store in the event `p`
    map inside the encrypted frame
  - Search matches the union of raw text and index, case-folded
  - Test: `qyyx` and `qiyeyouxiang` both match `企业邮箱`; `pypinyin` is not imported
    on the read path
  - _Requirements: 4.12, 4.13, 4.14_

- [x] 12. TOTP (`totp.py`)
  - Store secret / `otpauth://` URI as a record field, unconditionally
  - Generate via `pyotp`, entirely offline
  - Clock gate: refuse and explain when `now < last_known_good_time`; offer to set time
  - `--at` manual override
  - Test: a backwards clock blocks display rather than emitting a wrong code
  - _Requirements: 7.1, 7.2, 7.4, 7.5, 7.6_

- [x] 13. Password generator
  - Configurable length and character classes
  - "Thumb-typable" mode excluding characters behind the BBQ20 symbol layer
  - Uses `secrets`
  - _Requirements: 4.16_

- [x] 14. TUI core (`tui.py`)
  - `prompt_toolkit` full-screen app; list view per design §6.1 at 50×15
  - Repaint on input events only. No timers, no animation, no periodic refresh
  - All width via `wcwidth`; never `len()`
  - Reverse video plus `»` for selection; no colour dependence
  - Leave the bottom row free for the `fcitx-fbterm` candidate bar
  - Keymap per §6.2; `Ctrl+Space` unbound
  - Bind `j`/`k`, arrows, and trackpad scroll
  - Test at 50×15 with CJK entries: no wrapping, no overflow
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8_

- [x] 15. TUI detail, edit, and reveal
  - Detail view per §6.1; password masked by default
  - `p` reveals for 15 seconds, then re-masks; TOTP countdown updates on keypress
  - Clear the revealed-secret screen region on exit; leave nothing in scrollback
  - Add / edit / delete forms; unlock summary of changes from other devices
  - Clock-skew warning when `physical_now < highest_seen`
  - _Requirements: 4.10, 4.11, 3.11_

- [x] 16. Expanded layout
  - Detect terminal size; two-pane list/detail above 80 columns
  - _Requirements: 4.9_

- [x] 17. Packaging and documentation
  - `curl | bash` installer as the documented path; not published to PyPI.
    `pyproject.toml` is retained as the dependency manifest that pip reads during
    installation, and as the development entry point. The legacy
    `break-system-packages` advice is dropped
  - `pipw benchmark` measures the post-unlock hot path on the real device, so the
    question of native code is settled by measurement
  - README: Syncthing setup (share the directory, staggered versioning, `.stignore`,
    do not use untrusted-device encryption), 64-bit Raspberry Pi OS requirement,
    Beepy fbterm/fcitx notes, recovery key handling, migration walkthrough
  - Ship a default `.stignore` into new vault directories
  - _Requirements: 1.2, 3.13, 6.7_

---

## Deferred

- Log compaction (`mp compact`). The `seq` and coverage fields are specified now; at
  10,000 records the logs total a few megabytes, so this is a convenience rather than a
  requirement.
- Two-pane Textual front-end for desktop use. The layered architecture keeps this
  additive — it would consume `vault.py` without modification.
