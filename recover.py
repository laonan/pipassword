#!/usr/bin/env python3
"""Standalone pipassword recovery tool.

Reads a pipassword vault and writes every record to stdout as plaintext JSON,
given either the master password or the paper recovery key.

    ./recover.py ~/.local/share/pipassword/vault
    ./recover.py /path/to/vault --recovery-key
    ./recover.py /path/to/vault --output vault.json

This file is deliberately self-contained. It imports **nothing** from the
``pipassword`` package, only the standard library plus ``cryptography`` and
``argon2-cffi``. That is the whole point: if the package breaks, if a dependency
rots, if you come back to this in five years on a different Python, the data still
comes out. It duplicates the read path on purpose, and the test suite checks its
output against the package's own export so the two cannot silently diverge.

It is also an independent implementation of FORMAT.md, which is how that document
is kept honest.

Everything here is read-only. No file in the vault is modified.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import re
import struct
import sys
import unicodedata
import uuid
from pathlib import Path
from typing import Any

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"error: missing dependency: {exc}\n"
        f"install with: pip install cryptography argon2-cffi"
    )

# --- FORMAT.md section 1: keyfile -------------------------------------------
KEYFILE_MAGIC = b"PIPWKEY\x00"
KEYFILE_SIZE = 174
KEYFILE_VERSION = 1
KDF_ID_ARGON2ID = 1
SLOT_PASSWORD = 0b01
SLOT_RECOVERY = 0b10
PW_SLOT_LABEL = b"pipw-kek-slot-v1"
REC_SLOT_LABEL = b"pipw-rkek-slot-v1"
RKEK_PERSON = b"pipw-rkey"

# --- FORMAT.md section 2: log ----------------------------------------------
LOG_MAGIC = b"PIPWLOG\x00"
LOG_HEADER_SIZE = 42
LOG_VERSION = 1
NONCE_SIZE = 12
TAG_SIZE = 16
MIN_FRAME = NONCE_SIZE + TAG_SIZE
MAX_FRAME = 1 << 20

# --- FORMAT.md section 3: events ------------------------------------------
FIELDS = ("name", "login", "password", "url", "memo", "totp", "legacy_id")

KEYFILE_RE = re.compile(r"^keys\.(\d+)\.mpk$")


class RecoveryError(Exception):
    pass


def log(message: str) -> None:
    """Progress goes to stderr so stdout stays pure JSON and stays pipeable."""
    print(message, file=sys.stderr)


# ---------------------------------------------------------------- keyfile


def parse_keyfile(data: bytes) -> dict[str, Any]:
    if len(data) != KEYFILE_SIZE:
        raise RecoveryError(f"keyfile must be {KEYFILE_SIZE} bytes, got {len(data)}")
    if data[0:8] != KEYFILE_MAGIC:
        raise RecoveryError("not a pipassword keyfile (bad magic)")
    (version,) = struct.unpack_from("<H", data, 8)
    if version != KEYFILE_VERSION:
        raise RecoveryError(f"unsupported keyfile version {version}")
    if data[30] != KDF_ID_ARGON2ID:
        raise RecoveryError(f"unsupported KDF id {data[30]}")

    (memory_cost,) = struct.unpack_from("<I", data, 31)
    return {
        "vault_uuid": data[10:26],
        "generation": struct.unpack_from("<I", data, 26)[0],
        "memory_cost": memory_cost,
        "time_cost": data[35],
        "parallelism": data[36],
        "salt": data[37:53],
        "slots": data[53],
        "pw_nonce": data[54:66],
        "pw_ct": data[66:114],
        "rec_nonce": data[114:126],
        "rec_ct": data[126:174],
        # FORMAT.md 1.1: the two slots authenticate different byte ranges.
        "pw_aad": data[0:54] + PW_SLOT_LABEL,
        "rec_aad": data[0:26] + data[53:54] + REC_SLOT_LABEL,
    }


def unwrap_with_password(keyfile: dict[str, Any], password: str) -> bytes:
    if not keyfile["slots"] & SLOT_PASSWORD:
        raise RecoveryError("this keyfile has no password slot")
    # FORMAT.md 1.2: NFC normalisation is mandatory.
    secret = unicodedata.normalize("NFC", password).encode("utf-8")
    kek = hash_secret_raw(
        secret=secret,
        salt=keyfile["salt"],
        time_cost=keyfile["time_cost"],
        memory_cost=keyfile["memory_cost"],
        parallelism=keyfile["parallelism"],
        hash_len=32,
        type=Type.ID,
    )
    try:
        return ChaCha20Poly1305(kek).decrypt(
            keyfile["pw_nonce"], keyfile["pw_ct"], keyfile["pw_aad"]
        )
    except InvalidTag:
        raise RecoveryError(
            "could not unwrap the key: wrong password, or the keyfile was modified"
        ) from None


def parse_recovery_key(text: str) -> bytes:
    cleaned = re.sub(r"[\s\-]", "", text).upper()
    if len(cleaned) != 52:
        raise RecoveryError(
            f"recovery key must have 52 characters excluding separators, "
            f"got {len(cleaned)}"
        )
    try:
        raw = base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except Exception:
        raise RecoveryError("recovery key contains invalid characters") from None
    if len(raw) != 32:
        raise RecoveryError(f"recovery key decoded to {len(raw)} bytes, expected 32")
    return raw


def unwrap_with_recovery_key(keyfile: dict[str, Any], recovery_key: bytes) -> bytes:
    if not keyfile["slots"] & SLOT_RECOVERY:
        raise RecoveryError("this keyfile has no recovery slot")
    rkek = hashlib.blake2b(
        b"", key=recovery_key, person=RKEK_PERSON, digest_size=32
    ).digest()
    try:
        return ChaCha20Poly1305(rkek).decrypt(
            keyfile["rec_nonce"], keyfile["rec_ct"], keyfile["rec_aad"]
        )
    except InvalidTag:
        raise RecoveryError(
            "could not unwrap the key: wrong recovery key, or the keyfile was modified"
        ) from None


def load_keyfile(vault_dir: Path) -> dict[str, Any]:
    """Highest parseable generation. Ignores archive/ per FORMAT.md."""
    candidates = []
    for entry in sorted(vault_dir.iterdir()) if vault_dir.is_dir() else []:
        match = KEYFILE_RE.match(entry.name) if entry.is_file() else None
        if match:
            candidates.append((int(match.group(1)), entry))
    if not candidates:
        raise RecoveryError(f"no keys.N.mpk found in {vault_dir}")

    problems = []
    for generation, path in sorted(candidates, reverse=True):
        try:
            parsed = parse_keyfile(path.read_bytes())
            log(f"using {path.name} (generation {generation})")
            return parsed
        except (RecoveryError, OSError) as exc:
            problems.append(f"  {path.name}: {exc}")
    raise RecoveryError("no readable keyfile:\n" + "\n".join(problems))


# -------------------------------------------------------------------- logs


def read_log(path: Path, dek: bytes, vault_uuid: bytes) -> list[dict[str, Any]]:
    """Decrypt and parse one log. Damaged frames are reported, never fatal."""
    data = path.read_bytes()
    if len(data) < LOG_HEADER_SIZE:
        log(f"warning: {path.name}: shorter than a header; skipped")
        return []
    if data[0:8] != LOG_MAGIC:
        log(f"warning: {path.name}: not a pipassword log; skipped")
        return []
    (version,) = struct.unpack_from("<H", data, 8)
    if version != LOG_VERSION:
        log(f"warning: {path.name}: unsupported log version {version}; skipped")
        return []
    if data[10:26] != vault_uuid:
        log(f"warning: {path.name}: belongs to a different vault; skipped")
        return []

    header = data[:LOG_HEADER_SIZE]
    device_uuid = data[26:42]
    cipher = ChaCha20Poly1305(dek)

    events: list[dict[str, Any]] = []
    offset = LOG_HEADER_SIZE
    total = len(data)

    while offset < total:
        if total - offset < 4:
            log(f"warning: {path.name}: {total - offset} trailing byte(s) at "
                f"{offset}; interrupted write")
            break
        (frame_len,) = struct.unpack_from("<I", data, offset)
        body = offset + 4

        if frame_len < MIN_FRAME or frame_len > MAX_FRAME:
            log(f"warning: {path.name}: implausible frame length {frame_len} at "
                f"{offset}; stopping")
            break
        if total - body < frame_len:
            log(f"warning: {path.name}: frame at {offset} declares {frame_len} "
                f"bytes, only {total - body} remain; interrupted write")
            break

        nonce = data[body : body + NONCE_SIZE]
        ciphertext = data[body + NONCE_SIZE : body + frame_len]
        aad = header + struct.pack("<I", frame_len)
        try:
            payload = cipher.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            log(f"warning: {path.name}: frame at {offset} did not authenticate; "
                f"skipped")
            offset = body + frame_len
            continue

        try:
            event = json.loads(payload.decode("utf-8"))
            if not isinstance(event, dict):
                raise ValueError("not an object")
            event["_device"] = device_uuid
            events.append(event)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            log(f"warning: {path.name}: unreadable event at {offset}: {exc}")

        offset = body + frame_len

    return events


# -------------------------------------------------------------------- fold


def fold(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """FORMAT.md 3.2. Sort by (ts, device_uuid, seq), replay, drop tombstones."""

    def key(event: dict[str, Any]):
        return (
            int(event.get("ts", 0)),
            event.get("_device", b""),
            int(event.get("seq", 0)),
        )

    fields: dict[str, dict[str, Any]] = {}
    created: dict[str, int] = {}
    updated: dict[str, int] = {}
    deleted: dict[str, int] = {}

    for event in sorted(events, key=key):
        rid = event.get("id")
        if not isinstance(rid, str) or not rid:
            continue
        op = event.get("op")
        ts = int(event.get("ts", 0))

        if rid not in fields:
            fields[rid] = {}
            created[rid] = ts

        if op == "del":
            deleted[rid] = ts
            updated[rid] = ts
        elif op == "set":
            payload = event.get("f") or {}
            if isinstance(payload, dict):
                fields[rid].update(
                    {k: v for k, v in payload.items() if k in FIELDS}
                )
            updated[rid] = ts
            deleted.pop(rid, None)

    records = []
    for rid, values in fields.items():
        if rid in deleted:
            continue
        record: dict[str, Any] = {
            "id": rid,
            "created_at": created[rid],
            "updated_at": updated[rid],
        }
        for name in FIELDS:  # stable order, matching the package's export
            if name in values:
                record[name] = values[name]
        records.append(record)

    records.sort(key=lambda r: str(r.get("name", "")).casefold())
    return records


# -------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover a pipassword vault to plaintext JSON.",
        epilog="Reads only. Nothing in the vault is modified.",
    )
    parser.add_argument("vault", type=Path, help="path to the vault directory")
    parser.add_argument(
        "--recovery-key",
        action="store_true",
        help="authenticate with the paper recovery key instead of the password",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write JSON here instead of stdout (created with mode 0600)",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password or recovery key from stdin (for scripting)",
    )
    args = parser.parse_args(argv)

    try:
        keyfile = load_keyfile(args.vault)

        if args.recovery_key:
            prompt = "Recovery key: "
            raw = (
                sys.stdin.readline().rstrip("\n")
                if args.password_stdin
                else getpass.getpass(prompt)
            )
            dek = unwrap_with_recovery_key(keyfile, parse_recovery_key(raw))
        else:
            raw = (
                sys.stdin.readline().rstrip("\n")
                if args.password_stdin
                else getpass.getpass("Master password: ")
            )
            dek = unwrap_with_password(keyfile, raw)

        log("key unwrapped")

        log_dir = args.vault / "log"
        events: list[dict[str, Any]] = []
        logs = (
            sorted(p for p in log_dir.iterdir() if p.is_file() and p.suffix == ".mpl")
            if log_dir.is_dir()
            else []
        )
        if not logs:
            log(f"warning: no log files found in {log_dir}")
        for path in logs:
            found = read_log(path, dek, keyfile["vault_uuid"])
            log(f"{path.name}: {len(found)} event(s)")
            events.extend(found)

        records = fold(events)
        log(f"recovered {len(records)} record(s) from {len(events)} event(s)")

        document = {
            "format": "pipassword-export-v1",
            "vault_uuid": str(uuid.UUID(bytes=keyfile["vault_uuid"])),
            "records": records,
        }
        text = json.dumps(document, ensure_ascii=False, indent=2)

        if args.output:
            # Plaintext secrets: never world-readable, even briefly.
            handle = None
            try:
                import os

                fd = os.open(
                    args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
                )
                handle = os.fdopen(fd, "w", encoding="utf-8")
                handle.write(text + "\n")
            finally:
                if handle is not None:
                    handle.close()
            log(f"wrote {args.output} (mode 0600)")
        else:
            print(text)

    except RecoveryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
