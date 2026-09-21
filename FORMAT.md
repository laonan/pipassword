# pipassword on-disk format, version 1

This is a normative specification. It is detailed enough to write an independent
decryptor without reading the implementation, and that is its purpose: if this
software stops working, your data must still be reachable.

`recover.py` in this repository is such an independent implementation. It imports
only `cryptography` and `argon2-cffi` and nothing from the `pipassword` package.

All integers are **little-endian, unsigned**. All offsets are in bytes. All text is
**UTF-8**.

## Primitives

| Purpose | Algorithm | Parameters |
|---|---|---|
| Password hardening | Argon2id | from the keyfile; type `Argon2id`, tag length 32 |
| Recovery key separation | BLAKE2b, keyed | `person = "pipw-rkey"`, `digest_size = 32`, empty message |
| Authenticated encryption | ChaCha20-Poly1305 (RFC 8439) | 32-byte key, 12-byte nonce, 16-byte tag |

ChaCha20 rather than AES because no 64-bit Raspberry Pi except the Pi 5's BCM2712
provides ARMv8 AES instructions. Argon2id rather than PBKDF2 because it is
memory-hard.

## Directory layout

```
<vault>/
  keys.<generation>.mpk       one or more; highest generation is current
  archive/                    superseded keyfiles; NOT scanned when opening
  log/
    <name>-<uuid8>.mpl        one per device; only that device appends to it
  .stignore
```

A reader MUST scan only top-level `keys.*.mpk`. Files under `archive/` are
superseded and MUST be ignored, because an old generation would accept an old
master password.

A reader MUST read every `log/*.mpl` and fold their events together. Each log is
written by exactly one device.

---

## 1. Keyfile — `keys.<generation>.mpk`

Exactly **174 bytes**.

| Offset | Len | Field | Notes |
|---:|---:|---|---|
| 0 | 8 | `magic` | `50 49 50 57 4B 45 59 00` = `"PIPWKEY\0"` |
| 8 | 2 | `format_version` | `1` |
| 10 | 16 | `vault_uuid` | raw UUID bytes |
| 26 | 4 | `generation` | matches the filename |
| 30 | 1 | `kdf_id` | `1` = Argon2id |
| 31 | 4 | `memory_cost` | KiB |
| 35 | 1 | `time_cost` | Argon2 passes |
| 36 | 1 | `parallelism` | Argon2 lanes |
| 37 | 16 | `argon2_salt` | |
| 53 | 1 | `slots_present` | bit 0 = password, bit 1 = recovery |
| 54 | 12 | `pw_nonce` | |
| 66 | 48 | `pw_ct` | 32-byte DEK + 16-byte tag |
| 114 | 12 | `rec_nonce` | |
| 126 | 48 | `rec_ct` | 32-byte DEK + 16-byte tag |

When a slot's bit is clear, its nonce and ciphertext bytes are present but zero
and MUST be ignored.

### 1.1 Associated data

The two slots use **different** associated data. This is deliberate and is the
one part of the format most likely to surprise a reimplementer.

```
HDR      = keyfile[0:54]

pw_aad   = HDR + "pipw-kek-slot-v1"
rec_aad  = keyfile[0:26] + keyfile[53:54] + "pipw-rkek-slot-v1"
```

Both labels are ASCII, appended with no separator and no terminator.

`pw_aad` covers the entire header, so `format_version`, `vault_uuid`,
`generation`, every Argon2 parameter, and the salt are all authenticated. Editing
`memory_cost` down to a cheap value produces a file that no longer authenticates.

`rec_aad` covers only `magic`, `format_version`, `vault_uuid`, and
`slots_present`. It deliberately **excludes** `generation`, `argon2_salt`, and the
Argon2 parameters, for two reasons:

- The recovery slot is unwrapped with a key derived by BLAKE2b and never touches
  Argon2, so binding it to Argon2 parameters would authenticate data it does not
  depend on.
- It lets a password change copy `rec_nonce` and `rec_ct` verbatim into a new
  generation. Without this, changing the master password would require the paper
  recovery key to be physically in hand.

The trailing per-slot labels make the two slots non-interchangeable: a `pw_ct`
value relocated into the `rec_ct` position will not authenticate.

### 1.2 Unwrapping the DEK

With the master password:

```
password_bytes = UTF8(NFC(password))
KEK = Argon2id(password  = password_bytes,
               salt      = argon2_salt,
               time_cost = time_cost,
               memory    = memory_cost KiB,
               lanes     = parallelism,
               tag_len   = 32)
DEK = ChaCha20Poly1305_Decrypt(KEK, pw_nonce, pw_ct, pw_aad)
```

The **NFC normalisation is mandatory**. Vault text, and possibly the passphrase,
may be typed through a Pinyin input method, and the same visually identical string
can otherwise arrive in different Unicode normalisation forms on different
devices, deriving a different key.

With the recovery key:

```
recovery_key = Base32Decode(strip "-", whitespace; uppercase; re-pad to 8)
RKEK = BLAKE2b(message = "", key = recovery_key,
               person = "pipw-rkey", digest_size = 32)
DEK  = ChaCha20Poly1305_Decrypt(RKEK, rec_nonce, rec_ct, rec_aad)
```

### 1.3 Recovery key presentation

32 random bytes, RFC 4648 Base32, padding stripped, giving 52 characters, written
in 13 groups of 4 separated by `-`:

```
HZ4T-9PQB-...-EO4Q
```

RFC 4648's alphabet is `A-Z` and `2-7`. It contains no `0`, `1`, `8`, or `9`, so
`0`/`O` and `1`/`l` transcription errors cannot occur. A parser MUST accept any
case and ignore `-` and whitespace, and MUST require exactly 52 significant
characters.

---

## 2. Log file — `log/<name>-<uuid8>.mpl`

A 42-byte header, then zero or more frames.

### 2.1 Header

| Offset | Len | Field | Notes |
|---:|---:|---|---|
| 0 | 8 | `magic` | `"PIPWLOG\0"` |
| 8 | 2 | `format_version` | `1` |
| 10 | 16 | `vault_uuid` | must match the keyfile |
| 26 | 16 | `device_uuid` | identifies the sole writer |

A log whose `vault_uuid` differs from the keyfile's MUST be ignored, not merged.

### 2.2 Frames

Repeated to end of file:

| Offset | Len | Field |
|---:|---:|---|
| 0 | 4 | `frame_len` |
| 4 | 12 | `nonce` |
| 16 | `frame_len - 12` | `ciphertext` including the 16-byte tag |

`frame_len = 12 + plaintext_length + 16`. The next frame begins at
`4 + frame_len`.

```
frame_aad = log_header[0:42] + LE_U32(frame_len)
plaintext = ChaCha20Poly1305_Decrypt(DEK, nonce, ciphertext, frame_aad)
```

Binding the header makes a frame non-transplantable into another device's log or
another vault. Binding `frame_len` prevents a frame being re-cut at a different
boundary.

### 2.3 Required reader behaviour

A reader MUST NOT abort on a damaged frame. Specifically:

| Condition | Behaviour |
|---|---|
| Fewer than 4 bytes remain | record a truncation anomaly, stop |
| `frame_len < 28` or `frame_len > 1048576` | record a bad-length anomaly, stop |
| fewer than `frame_len` bytes remain | record a truncation anomaly, stop |
| decryption fails | record an anomaly, **continue at the next frame** |
| payload is not a valid event | record an anomaly, skip that event |

Scanning stops only when a frame boundary itself cannot be trusted. A frame that
fails authentication does not hide the frames after it, because the length prefix
that locates the next boundary was still readable.

This matters on battery-powered hardware: an interrupted append leaves a partial
trailing frame, and it must cost that one frame and nothing more.

---

## 3. Events

Each frame's plaintext is a UTF-8 JSON object.

```json
{
  "op": "set",
  "id": "9f1c...-uuid",
  "ts": 1758000000000000,
  "seq": 12,
  "f":  { "name": "企业邮箱", "password": "..." },
  "p":  { "name": "qyyx qiyeyouxiang" }
}
```

| Key | Type | Notes |
|---|---|---|
| `op` | string | `"set"` or `"del"` |
| `id` | string | record identifier, stable across devices |
| `ts` | integer | microseconds; a hybrid logical clock, **not** a wall clock |
| `seq` | integer | per-device monotonic counter; defaults to `0` if absent |
| `f` | object | present on `set` only; **only the fields that changed** |
| `p` | object | optional Pinyin search index |

Permitted field names in `f` and `p`: `name`, `login`, `password`, `url`, `memo`,
`totp`, `legacy_id`. A reader MUST reject any other name.

A `set` MUST carry at least one field. A `del` MUST NOT carry fields.

`device_uuid` is **not** in the payload. It comes from the log header, so it cannot
be forged independently of the log the event lives in.

### 3.1 Hybrid logical clock

When writing an event:

```
ts = max(wall_clock_micros, highest_ts_observed_in_any_log + 1)
```

This is required, not advisory. No Raspberry Pi before the Pi 5 has a
battery-backed real-time clock. A device that has been powered off boots with
`fake-hwclock` restoring the timestamp saved at its last shutdown, which may be
days stale. With raw wall-clock timestamps, an edit made today on such a device
would sort before a week-old edit from another device and be discarded by the
fold. The rule above guarantees that an event written after observing another
device's event sorts after it, regardless of local clock error.

A reader MAY warn the user when `wall_clock < highest_ts_observed`, which
indicates the clock cannot be trusted.

### 3.2 Fold

State is the ordered replay of every event from every log.

1. Sort all events by `(ts, device_uuid, seq)` ascending. `device_uuid` compares
   as raw bytes. Including it makes ties resolve identically on every device, so
   all devices holding the same files compute identical state.
2. Replay in order. For each record id:
   - `set`: merge `f` over the record's fields, merge `p` over its index, set
     `updated_at = ts`, and clear any tombstone.
   - `del`: set a tombstone at `ts` and set `updated_at = ts`.
   - `created_at` is the `ts` of the first event seen for that id.
3. A record is present iff it has no tombstone after replay.

Because `set` events carry only changed fields, this yields **last-write-wins per
field**. Two devices editing different fields of one record while disconnected
both keep their edit. A `set` ordered after a `del` resurrects the record without
losing previously set fields.

A superseded value is not erased; it remains in the log and is recoverable by
reading the event history for that record.

---

## 4. Worked recovery procedure

1. List top-level `keys.*.mpk`; take the highest generation that parses. Ignore
   `archive/`.
2. Read the 174 bytes, verify the magic, read the Argon2 parameters and salt.
3. Derive `KEK` (or `RKEK`) and decrypt the matching slot with the correct AAD
   from §1.1 to obtain the 32-byte `DEK`.
4. For each `log/*.mpl`: verify the magic and that `vault_uuid` matches; walk the
   frames per §2.2 and §2.3, decrypting each with the `DEK`.
5. Parse each plaintext as an event per §3.
6. Sort and replay per §3.2.

`recover.py --help` performs exactly these steps.

---

## 5. PIN unlock slot — `~/.config/pipassword/pin.unlock` (optional)

This file is **not part of the vault** and is **not required to read it**.
`recover.py` ignores it entirely; the master password and recovery key are the only
paths it and this specification care about. It is documented here only so the format
is complete.

It is an opt-in local convenience: a short PIN that unlocks the vault *on one
device*, backed by a 256-bit secret that never leaves that device. It deliberately
trades theft resistance for typing convenience — see the project's design notes. It
lives in the per-device config directory, never in the synced vault directory, so a
leaked or backed-up vault copy contains nothing it protects.

Exactly **143 bytes**.

| Offset | Len | Field | Notes |
|---:|---:|---|---|
| 0 | 8 | `magic` | `"PIPWPIN\0"` |
| 8 | 2 | `format_version` | `1` |
| 10 | 16 | `vault_uuid` | must match the vault this slot unlocks |
| 26 | 1 | `kdf_id` | `1` = Argon2id |
| 27 | 4 | `memory_cost` | KiB |
| 31 | 1 | `time_cost` | |
| 32 | 1 | `parallelism` | |
| 33 | 16 | `argon2_salt` | |
| 49 | 32 | `device_secret` | 256 random bits |
| 81 | 12 | `nonce` | |
| 93 | 48 | `ct` | 32-byte DEK + 16-byte tag |
| 141 | 2 | `failure_count` | u16, **outside the AAD** |

```
pin_kek    = Argon2id(UTF8(NFC(pin)), argon2_salt, params)
unlock_key = BLAKE2b(pin_kek, key=device_secret, person="pipw-pin", digest_size=32)
aad        = pin.unlock[0:81] + "pipw-pin-slot-v1"
DEK        = ChaCha20Poly1305_Decrypt(unlock_key, nonce, ct, aad)
```

Both the PIN and `device_secret` are required. The AAD covers bytes 0–80 (through the
device secret) plus the label, but **not** `failure_count`: the counter must be
updatable in place without re-wrapping, so it is unauthenticated and trivially
resettable. That is by design. The counter is a speed bump, not rate limiting — no
software on this hardware can throttle an offline attack against a copied file.

A reader MUST refuse a slot whose `vault_uuid` does not match, and SHOULD refuse one
whose file mode is readable by group or other.
