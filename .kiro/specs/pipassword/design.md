# pipassword — Design

## 1. Architecture

Three layers, strictly one-directional. The core never imports UI code, which keeps
the storage format testable in isolation and makes the TUI choice reversible.

```
pipassword/
  crypto.py      KDF, key hierarchy, AEAD primitives
  format.py      keyfile and log binary encode/decode
  events.py      event model, hybrid logical clock, fold
  vault.py       Vault: unlock, query, mutate, append      <-- no UI, no argparse
  pinyin.py      index construction (write-time only)
  totp.py        code generation + clock gate
  importer.py    legacy minipassword / JSON import
  cli.py         non-interactive commands
  tui.py         prompt_toolkit interface
  __main__.py    entry point, dispatch
recover.py       standalone, dependency-minimal recovery tool
FORMAT.md        on-disk format specification
```

`vault.py` is the only module the CLI and TUI both depend on. `recover.py` sits
outside the package and duplicates a minimal read path on purpose — it must keep
working if the package does not.

### Dependencies

| Package | Purpose | aarch64 wheel |
|---|---|---|
| `cryptography` | ChaCha20-Poly1305 | yes |
| `argon2-cffi` | Argon2id | yes |
| `prompt_toolkit` | TUI | pure Python |
| `wcwidth` | CJK-correct width | pure Python |
| `pypinyin` | index build (not needed at runtime on Pi) | pure Python |
| `pyotp` | TOTP | pure Python |

`requests` and `simple-term-menu` from the legacy project are both dropped.

### Filesystem layout

```
~/.config/pipassword/
  config.toml            vault path, UI preferences. NO SECRETS.
  device_id              16 random bytes, per-device, NEVER synced

~/.local/share/pipassword/vault/          <-- point Syncthing at this directory
  keys.1.mpk                              keyfile generation 1
  log/beepy-a1b2c3d4.mpl                  written only by the Beepy
  log/pi4-e5f6a7b8.mpl                    written only by the Pi 4
  .stignore                               excludes lock/temp files
```

`device_id` lives in the config directory, deliberately outside the vault. If it were
synced, two devices would share a log filename and requirement 3.2 would break.

The contrast with the legacy design is the point: `config.toml` holds no key material
of any kind. The legacy `config.ini` held the Fernet key in cleartext at mode `0644`.

---

## 2. Key hierarchy

```
master password ──Argon2id(salt, t=3, m=64MiB, p=4)──> KEK ──unwraps──┐
                                                                      ├──> DEK ──> all record data
recovery key (256-bit) ──BLAKE2b(person="pipw-rkey")──> RKEK ──unwraps┘
```

Two independent unwrap paths to one DEK. Consequences:

- Password rotation rewraps 32 bytes; vault contents are never re-encrypted.
- A forgotten password is recoverable from the paper recovery key.
- The recovery key already has full entropy, so it needs only domain separation, not
  a slow KDF. BLAKE2b keyed derivation is sufficient and is in the standard library.

`parallelism=4` is why `argon2-cffi` is used rather than PyNaCl: libsodium implements
Argon2id single-threaded and does not expose the parameter, which would idle three of
the Zero 2 W's four cores during unlock.

`memory_cost=65536` (64 MiB) is bounded by the Zero 2 W's 512 MB shared with
Syncthing, which itself takes 50–100 MB. Because there is one KEK for one vault, the
weakest device sets the parameters for every device. This is an accepted tradeoff:
64 MiB Argon2id is still far stronger than SQLCipher's 256,000-round PBKDF2, which is
not memory-hard at all.

---

## 3. On-disk format

Little-endian throughout. Specified normatively in `FORMAT.md`.

### 3.1 Keyfile — `keys.<generation>.mpk`

```
off  len  field
  0    8  magic          "PIPWKEY\x00"
  8    2  format_version u16 = 1
 10   16  vault_uuid
 26    4  generation     u32
 30    1  kdf_id         u8 = 1 (argon2id)
 31    4  memory_cost    u32, KiB
 35    1  time_cost      u8
 36    1  parallelism    u8
 37   16  argon2_salt
 53    1  slots_present  u8 bitfield: bit0 password, bit1 recovery
 54   12  pw_nonce
 66   48  pw_ct          ChaCha20Poly1305(KEK, pw_nonce, DEK, aad=HDR)
114   12  rec_nonce
126   48  rec_ct         ChaCha20Poly1305(RKEK, rec_nonce, DEK, aad=HDR)
174       end
```

Each slot has its own associated data, because the two slots need to authenticate
different things:

```
pw_aad  = bytes[0:54]                   + b"pipw-kek-slot-v1"
rec_aad = bytes[0:26] || bytes[53:54]   + b"pipw-rkek-slot-v1"
```

`pw_aad` covers the full header, so the version, vault UUID, generation, salt, and all
Argon2 parameters are authenticated — an attacker cannot downgrade `memory_cost` to
1 MiB and still produce a keyfile that opens.

`rec_aad` deliberately covers only the magic, format version, vault UUID, and slot
bitfield. It excludes the generation number, the salt, and the Argon2 parameters, for
two reasons. The principled one: the recovery slot is unwrapped by a BLAKE2b-derived
RKEK and never touches Argon2, so binding it to Argon2 parameters would authenticate
data the slot does not depend on. The practical one: it lets password rotation copy the
recovery slot's 60 bytes verbatim into the new generation, since the DEK is unchanged.
Without this, rotating the master password would require the paper recovery key to be
physically in hand, or would force a new recovery key to be printed every time — both
of which push the user toward not rotating at all.

The trailing per-slot label makes the two slots non-interchangeable, so a `pw_ct` value
cannot be relocated into the `rec_ct` position.

### Old keyfile generations

Requirement 6.6 keeps rotation append-only so a crash cannot destroy the only keyfile.
That has a consequence worth stating plainly: while an old generation remains readable
in the vault directory, **the old master password still opens the vault**.

So rotation is: write the new generation, verify it opens, then move the old generation
into `archive/`. The loader scans only top-level `keys.*.mpk`, so the old password
stops working through the normal path while the file itself survives for recovery. The
CLI tells the user to delete `archive/` once satisfied, and explains why.

Keyfiles are immutable once written. Password rotation writes `keys.2.mpk`; unlock
tries the highest generation and falls back. This preserves append-only semantics for
the whole directory, so rotation cannot produce a Syncthing conflict either.

### 3.2 Log file — `log/<device-name>-<device-id-prefix>.mpl`

Fixed header, then a sequence of independently encrypted frames:

```
header (42 bytes, written once at creation)
  off  len  field
    0    8  magic        "PIPWLOG\x00"
    8    2  format_ver   u16 = 1
   10   16  vault_uuid
   26   16  device_uuid

frame (repeated, appended)
  off  len  field
    0    4  frame_len    u32, length of nonce + ct
    4   12  nonce        random per frame
   16    N  ct           ChaCha20Poly1305(DEK, nonce, event_cbor,
                                          aad = log_header || frame_len)
```

Design consequences:

- **Per-frame encryption** means appending never rewrites earlier bytes. Combined with
  `fsync`, a power cut on a battery handheld can damage at most the trailing frame.
- **Length-prefixed and individually authenticated** means a truncated tail frame is
  detected by either a short read or a tag failure. The loader skips it, reports it,
  and returns every valid preceding event.
- **AAD binds `vault_uuid` and `device_uuid`**, so a frame cannot be transplanted
  between logs or between vaults.
- A 96-bit random nonce per frame is safe here: collision probability stays negligible
  far beyond the 10,000-record target.

### 3.3 Event payload (JSON, UTF-8)

Stdlib `json` rather than CBOR: every field is text, so a binary encoding saves
little at the 10,000-record target, and it avoids a dependency.

```python
{
  "op":  "set" | "del",
  "id":  "<record uuid>",        # stable across devices
  "ts":  <u64 microseconds>,     # hybrid logical clock, NOT raw wall clock
  "seq": <u64>,                  # per-device monotonic; reserved for compaction
  "f":   {                       # "set" only; ONLY changed fields
     "name": str, "login": str, "password": str,
     "url": str, "memo": str, "totp": str, "legacy_id": int
  },
  "p":   {"name": "qyyx qiyeyouxiang"}   # write-time pinyin index
}
```

A `set` carries only the fields that changed. That is what makes field-level merge
fall out of a plain ordered replay.

---

## 4. Event fold

```python
def fold(events):
    events.sort(key=lambda e: (e["ts"], e["device_uuid"], e["seq"]))
    records, tombstones = {}, {}
    for e in events:
        if e["op"] == "del":
            tombstones[e["id"]] = e["ts"]
        else:
            rec = records.setdefault(e["id"], {})
            rec.update(e["f"])            # later event wins, per field
            if tombstones.get(e["id"], 0) < e["ts"]:
                tombstones.pop(e["id"], None)   # a later set resurrects
    return {k: v for k, v in records.items() if k not in tombstones}
```

Sorting on `(ts, device_uuid, seq)` makes the result deterministic: `device_uuid`
breaks timestamp ties identically on every device, so all devices holding the same
files compute byte-identical state.

### Hybrid logical clock

```python
def next_ts(highest_seen: int) -> int:
    return max(time.time_ns() // 1000, highest_seen + 1)
```

`highest_seen` is the maximum `ts` across all loaded events, captured at unlock.

This is not optional on this hardware. No Raspberry Pi before the Pi 5 has a
battery-backed RTC, so a Beepy that has been powered off boots with `fake-hwclock`
restoring the timestamp from its last shutdown — potentially days stale. With raw wall
clock timestamps, an edit made today on the Beepy would sort before last week's
desktop edit and lose the merge. The HLC guarantees that any event written after
observing another device's event sorts after it, whatever the local clock says.

When `physical_now < highest_seen`, the TUI shows a clock-skew warning, which also
drives the TOTP gate (§7).

---

## 5. Sync behaviour

Syncthing is a continuous background replicator, not a pull-on-demand transport. It
watches the filesystem and propagates changes with no involvement from this
application; by the time `pipassword` starts, replication has already happened. There
is no startup hook at which a "is the remote newer?" check could run, which is why the
design places the safety property in the data model instead.

Because each device writes only its own log path, no path has two writers, so
Syncthing has nothing to reconcile and cannot emit a `.sync-conflict-*` file. If one
appears anyway, it indicates a duplicated `device_id` — the loader reports it rather
than silently ignoring it.

Recommended Syncthing configuration, documented in the README:

- Share the vault **directory**, not individual files.
- Enable staggered file versioning as a last-resort undo.
- `.stignore` covering `*.lock`, `*.tmp`, `*.sync-conflict-*`.
- Do not use Syncthing's untrusted-device encryption. The payload is already
  encrypted, and it should not be relied on as a security layer.

What the user sees on unlock: "4 entries added on pi4 since you last opened this."
This is the useful half of a sync prompt — awareness of what changed — with no
overwrite decision to get wrong.

---

## 6. TUI

### 6.1 Compact layout, 50×15

Row 15 is deliberately empty: `fcitx-fbterm` draws its Pinyin candidate bar there and
would otherwise overwrite the status line.

```
 1  > qyyx                                    3/412
 2
 3  » 企业邮箱 · mail.corp.cn                          <- reverse video
 4    企业邮箱备用 · webmail.corp.cn
 5    Google 企业账号 · google.com
 6      (list continues)
 …
12
13
14  ↵ view  a add  e edit  g gen  q quit
15                                                    <- reserved for IME
```

Detail view, same 15 rows, single column, no borders:

```
 1  企业邮箱
 2
 3  user  alan@corp.cn
 4  pass  ••••••••••      p reveal
 5  url   mail.corp.cn
 6  totp  482 913   (28s)
 7
 8  memo  (scrollable)
 …
14  p reveal  c copy  e edit  ␛ back
15
```

### 6.2 Keymap

Single keys only — the BBQ20 has no arrow keys, no function keys, and awkward
modifiers. `Ctrl+Space` is never bound, since `fcitx` owns it for IME switching.

| Key | Action |
|---|---|
| any printable | incremental search |
| `j` / `k` / arrows / trackpad | move selection |
| `Enter` | open detail |
| `Esc` | back / clear search |
| `a` `e` `d` | add / edit / delete |
| `p` | reveal password for 15s |
| `g` | generate password |
| `q` | quit, discard key |

### 6.3 Rendering rules

- Repaint only on input events. No timers, no animation. A repaint during IME
  composition erases the candidate bar, and the Sharp Memory LCD repaints over SPI.
  The TOTP countdown in the detail view therefore updates on keypress, not on a tick.
- All truncation and padding via `wcwidth`. CJK is double-width; the legacy
  `item[:40]` produces 80 display columns on a 50-column screen and corrupts the list.
- Selection shown by reverse video plus a `»` marker. `TERM=xterm-mono` has no colour.
- On terminals wider than 80 columns, switch to a two-pane list/detail layout.

### 6.4 Pinyin search

`pypinyin` runs at **write** time only. When a record is saved, initials and full
Pinyin for each CJK field are computed and stored in the event's `p` map, inside the
encrypted frame.

So `企业邮箱` stores `"qyyx qiyeyouxiang"`, and typing either substring matches. Two
benefits: `pypinyin`'s data tables are never loaded on the Pi, and the index inherits
the vault's encryption rather than leaking a plaintext search key.

Matching is substring over the union of raw text and Pinyin index, case-folded.

---

## 7. TOTP clock gate

```
last_known_good_time  persisted on every vault write

on TOTP display request:
    if now < last_known_good_time:
        refuse; report clock unreliable; offer to set time
    else:
        show code, and remaining seconds in window
```

The algorithm is fully offline — RFC 6238 is an HMAC over a counter derived from the
current time. The fragile input is the clock, not connectivity.

The Beepy's RP2040 does expose RTC registers (`0x26`–`0x2C` in the `i2c_puppet`
firmware) and `beepy-kbd` pushes NTP time into them when a network is available. That
would solve this, except the firmware documentation states RTC state is lost when the
power switch is turned off or the device enters deep sleep — and deep sleep is the
default `CF2_AUTO_OFF` path. So the RTC survives a normal Pi-off but not a real
power-down, and cannot be relied on.

Hence: secrets always stored, codes best-effort with an explicit refusal rather than a
silently wrong number. `--at "14:30"` provides a manual override.

---

## 8. Legacy import

```
~/.minipassword/config.ini   ─ read-only ─┐
~/.minipassword/*.db         ─ read-only ─┴─> decrypt ─> verify ─> append events
```

Opened with SQLite URI mode `file:...?mode=ro`. No code path in `importer.py` opens
any legacy file for writing, and the module contains no `os.remove`, `shutil`, or
write-mode `open` against the legacy directory.

Per record: `name`, `memo`, `url` are already plaintext in the legacy schema;
`login_name` and `password` are Fernet tokens decrypted with the key from the legacy
`config.ini`. A new UUID is assigned and the legacy integer `id` retained as
`legacy_id`.

`InvalidToken` on a record is collected and reported, not raised — one unreadable row
must not abort a 400-record import.

**Verification is the point of the whole feature.** After writing, the vault is closed
and re-opened cold from disk, then every field of every record is compared against the
legacy source by hash. A mismatch reports the specific records and exits non-zero.
Completing without an exception is not treated as success.

Idempotency is by `legacy_id`: re-importing updates rather than duplicating.

The legacy vault is never modified or deleted. After a verified import the tool advises
rotating high-value credentials, because the legacy Fernet key sat world-readable at
mode `0644` and may exist in old backups.

A second importer reads the plaintext JSON layout used by
`tests/importfromjsonfile.py` (a list of `{name, login_name, password, memo, url}`),
without that script's off-by-one reporting bug — it increments its seed before
printing, so it reports the *next* record's name on success.

---

## 9. Recoverability

Four independent guarantees, so that no single failure locks the user out:

1. **Paper recovery key** — second unwrap slot; a forgotten password is not fatal.
2. **`recover.py`** — roughly 100 lines, standalone, importing only `cryptography` and
   `argon2-cffi`. Takes a vault directory plus a password or recovery key, emits
   plaintext JSON. Deliberately duplicates the read path so it survives any breakage
   in the package, and is tested against a real vault in CI.
3. **`FORMAT.md`** — normative byte-level specification. Standard primitives only, so
   an independent implementation is possible from the document alone.
4. **`export --plaintext`** — always available while unlocked.

Worst realistic outcome: the interface is broken and the user runs a script. Never:
the data is gone.

---

## 9a. PIN unlock slot (planned, not yet implemented)

A local, opt-in convenience credential. See requirements section 9 for the
threat-model trade this makes, which is deliberate: it preserves T2 (a leaked vault
copy) and degrades T1 (a stolen device).

### Why a separate file rather than a third keyfile slot

The keyfile lives in the vault directory, so it is synced. A PIN-wrapped slot inside
it would travel to every device and into every backup, which is precisely the copy a
20-bit secret must never protect. Putting the slot in a **non-synced local file**
inverts that: the thing a PIN guards never leaves the device.

It also means the vault format does not change. `keys.N.mpk` stays at version 1,
`FORMAT.md` is untouched, and `recover.py` keeps working with no knowledge of PINs.

```
~/.config/pipassword/          per-device, NEVER synced
  pin.unlock                   <- the slot; mode 0600
~/.local/share/pipassword/vault/
  keys.1.mpk                   <- unchanged, still password + recovery only
```

### File layout — `pin.unlock`, 143 bytes

| Offset | Len | Field | Notes |
|---:|---:|---|---|
| 0 | 8 | `magic` | `"PIPWPIN\0"` |
| 8 | 2 | `format_version` | `1` |
| 10 | 16 | `vault_uuid` | binds the slot to one vault (req 9.6) |
| 26 | 1 | `kdf_id` | `1` = Argon2id |
| 27 | 4 | `memory_cost` | KiB |
| 31 | 1 | `time_cost` | |
| 32 | 1 | `parallelism` | |
| 33 | 16 | `argon2_salt` | |
| 49 | 32 | `device_secret` | 256 random bits (req 9.4) |
| 81 | 12 | `nonce` | |
| 93 | 48 | `ct` | 32-byte DEK + 16-byte tag |
| 141 | 2 | `failure_count` | u16, **outside the AAD** |

`failure_count` sits after the ciphertext and outside the authenticated data
deliberately: it must be updatable in place without re-wrapping the DEK. The cost is
that it is unauthenticated and therefore trivially resettable, which is consistent
with it being a speed bump rather than a control.

### Derivation

```
pin_kek    = Argon2id(UTF8(NFC(pin)), argon2_salt, params)      # 32 bytes
unlock_key = BLAKE2b(pin_kek, key=device_secret,
                     person="pipw-pin", digest_size=32)
aad        = pin.unlock[0:81] + "pipw-pin-slot-v1"
DEK        = ChaCha20Poly1305_Decrypt(unlock_key, nonce, ct, aad)
```

Both inputs are required: the PIN contributes ~20 bits, the device secret 256. An
attacker with the vault but not the file faces 256 bits and stops. An attacker with
both faces 20 and does not.

NFC normalisation matches the master password path, for the same reason — a PIN typed
through an IME must derive the same key on every device.

The same primitives as everywhere else, so no new cryptographic surface: Argon2id,
BLAKE2b keyed derivation as used for the recovery key, ChaCha20-Poly1305 with a
domain-separation label.

### Unlock flow

```
open_vault:
    slot = read pin.unlock if present
    if slot and slot.vault_uuid == keyfile.vault_uuid:
        prompt "PIN (or blank for master password): "
        if blank                  -> master password path
        if correct                -> reset failure_count, return DEK
        if wrong                  -> increment failure_count
                                     if failure_count >= limit: delete slot
                                     re-prompt or fall back
    else:
        master password path
```

Mode is checked before use (req 9.5): a `pin.unlock` readable by others is refused,
because the whole value of the file is that only this device's owner has it.

### Commands

| Command | Credential needed | Effect |
|---|---|---|
| `pipw pin set` | master password or recovery key | generate secret, wrap DEK, write slot |
| `pipw pin remove` | none | delete the local file |
| `pipw pin status` | none | report vault, parameters, failure count |

`pin set` needs the DEK, hence a real credential. `pin remove` needs nothing: it
deletes a local file that only reduces security, and requiring a password to give up
a convenience would be pointless friction.

### What this must not claim

The failure counter is not rate limiting. There is no secure element on a Pi Zero 2 W,
so an offline attack against a copied `pin.unlock` proceeds at the attacker's speed.
Any user-facing wording that implies enforced attempt limits is a defect, and the
warning at `pin set` time states the bit count and approximate cracking time instead.

## 10. Error handling

| Condition | Behaviour |
|---|---|
| Wrong master password | Retry, no lockout. Offline throttling is theatre; the KDF is the defence. |
| `memory_cost` exceeds free RAM | Refuse with the shortfall named, before OOM risk |
| Truncated tail frame | Skip, warn, load all valid events |
| Frame tag failure mid-file | Skip, warn loudly, continue; report count |
| Keyfile missing | Fatal, explain it is required and point at backup instructions |
| Missing log file | Load available logs, warn that the view may be stale |
| `.sync-conflict-*` present | Report as anomaly; likely duplicated `device_id` |
| Clock earlier than last known good | Warn in TUI; block TOTP display |
| Unsupported architecture | Exit with the requirement named, before dependency import |

Secrets never appear in an exception message or traceback.

---

## 11. Testing

- **Crypto** — known-answer tests for Argon2id and ChaCha20-Poly1305; AAD tampering
  must fail; downgrading `memory_cost` in the keyfile must fail authentication.
- **Fold determinism** — property test: shuffling event arrival order and log
  membership yields identical state. This is the core sync correctness claim.
- **HLC** — simulate a device whose wall clock is a week stale; its new edits must
  still sort last. Directly models the Beepy `fake-hwclock` case.
- **Truncation** — truncate a log at every byte offset; loader must recover all
  complete frames and never crash.
- **Multi-device** — simulate two devices editing different fields of one record while
  disconnected; both edits must survive.
- **Import** — fixture legacy DB; assert byte-identical field recovery, and assert via
  file mtime and content hash that the legacy files were not modified.
- **Width** — CJK strings must render within 50 columns.
- **`recover.py`** — run against a vault produced by the main package; output must
  match `export --plaintext`.

Tests SHALL use a temporary vault directory via fixtures. No test may instantiate a
vault at the user's real path — the legacy `tests/test_manager.py` binds to the live
vault and its `test_delete_password` deletes record id 1, which is consistent with the
single surviving row observed in the current database.
