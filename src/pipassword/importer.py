"""Import from a legacy ``minipassword`` vault.

The contract of this module is that **the legacy vault is never touched**. It is
opened through SQLite's read-only URI mode, and this module contains no write-mode
``open``, no ``os.remove``, no ``shutil`` call, and no ``os.replace`` targeting the
legacy directory. A test enforces that by inspecting this file's AST, and another
checks the legacy files' hashes and mtimes are unchanged after a run.

That matters because it is the whole reason ``pipassword`` is a separate project
with a separate data directory: if the migration goes wrong or is abandoned, the
original vault and the original ``mm`` command still work.

The legacy schema, for reference::

    CREATE TABLE passwords (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        name       VARCHAR(200) NOT NULL UNIQUE,
        login_name TEXT NOT NULL,     -- Fernet token
        password   TEXT NOT NULL,     -- Fernet token
        memo       TEXT NULL,         -- PLAINTEXT
        url        VARCHAR(255) NULL  -- PLAINTEXT
    )

Only ``login_name`` and ``password`` were ever encrypted. ``name``, ``memo`` and
``url`` sat in the clear, and the Fernet key sat in ``config.ini`` at mode 0644.
Both facts shape the advice printed after a successful import.

Deliberately **not** copied to a temporary file first: ``name``, ``memo`` and
``url`` are plaintext in that database, so writing a copy into ``/tmp`` would
expose them more widely than leaving the original alone.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field

from .compat import SLOTS
from pathlib import Path
from typing import Any, Iterable, Sequence

from cryptography.fernet import Fernet, InvalidToken

from . import events as ev
from .vault import Vault, VaultError

__all__ = [
    "ImportError_",
    "LegacyRecord",
    "ImportReport",
    "LEGACY_DATA_DIR",
    "find_legacy_paths",
    "read_legacy_key",
    "read_legacy_records",
    "read_json_records",
    "apply_records",
    "verify_against",
    "contains_cjk",
    "ROTATION_ADVICE",
]

LEGACY_DATA_DIR = "~/.minipassword"

_CJK = re.compile(
    r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef]"
)

ROTATION_ADVICE = """\
Two things worth doing now that your data is in pipassword:

1. Rotate high-value credentials. The legacy encryption key lived in cleartext in
   config.ini at mode 0644 (world-readable), and may exist in old backups. If that
   machine was never shared, real exposure is probably low, so treat this as a
   prioritised task rather than an emergency: banking, email, and anything with
   payment details first.

2. Securely erase the legacy files once you are satisfied this vault is complete.
   pipassword will not do it for you, on purpose. Check the data first, then:

       shred -u ~/.minipassword/minipassword.db ~/.minipassword/config.ini

   Until then your passwords exist in two places, one of them weakly protected."""


class ImportError_(Exception):
    """Import could not proceed. Named with a trailing underscore to avoid
    shadowing the builtin."""


def contains_cjk(text: str) -> bool:
    return bool(_CJK.search(text or ""))


@dataclass(frozen=True, **SLOTS)
class LegacyRecord:
    """One decrypted legacy row."""

    legacy_id: int | None
    name: str
    login: str
    password: str
    memo: str = ""
    url: str = ""

    def digest(self) -> str:
        """Stable hash over every field, for import verification.

        Field order and the separator are fixed, and the separator is a NUL byte
        so it cannot occur inside a value and shift the boundaries.
        """
        joined = "\x00".join(
            [self.name, self.login, self.password, self.memo, self.url]
        )
        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    def as_spec(self) -> dict[str, Any]:
        spec: dict[str, Any] = {
            "name": self.name,
            "login": self.login,
            "password": self.password,
            "memo": self.memo,
            "url": self.url,
        }
        if self.legacy_id is not None:
            spec["legacy_id"] = self.legacy_id
        return spec


@dataclass
class ImportReport:
    """What happened, in enough detail to trust or reject the result."""

    source: str
    dry_run: bool = False
    total_rows: int = 0
    added: int = 0
    updated: int = 0
    unchanged: int = 0
    failures: list[tuple[str, str]] = field(default_factory=list)
    duplicate_names: list[str] = field(default_factory=list)
    cjk_records: int = 0
    with_memo: int = 0
    with_url: int = 0
    verified: bool = False
    mismatches: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True only if nothing failed and verification passed.

        Completing without an exception is explicitly not success
        (requirement 5.7).
        """
        if self.dry_run:
            return not self.failures
        return self.verified and not self.mismatches and not self.failures

    def lines(self) -> list[str]:
        out = [
            f"Source: {self.source}",
            f"  rows found         {self.total_rows}",
        ]
        if self.dry_run:
            out.append(f"  would import       {self.total_rows - len(self.failures)}")
        else:
            out += [
                f"  added              {self.added}",
                f"  updated            {self.updated}",
                f"  already current    {self.unchanged}",
            ]
        out += [
            f"  containing CJK     {self.cjk_records}",
            f"  with a memo        {self.with_memo}",
            f"  with a url         {self.with_url}",
        ]
        if self.duplicate_names:
            out.append(f"  duplicate names    {len(self.duplicate_names)}")
            for name in self.duplicate_names[:10]:
                out.append(f"      {name}")
        if self.failures:
            out.append(f"  FAILED to read     {len(self.failures)}")
            for ident, why in self.failures[:20]:
                out.append(f"      {ident}: {why}")
        if not self.dry_run:
            out.append(
                f"  verification       {'PASSED' if self.verified else 'NOT RUN'}"
            )
            if self.mismatches:
                out.append(f"  MISMATCHES         {len(self.mismatches)}")
                for line in self.mismatches[:20]:
                    out.append(f"      {line}")
        return out


# --------------------------------------------------------------- legacy input


def find_legacy_paths(
    data_dir: Path | str = LEGACY_DATA_DIR,
) -> tuple[Path, Path]:
    """Locate the legacy ``config.ini`` and database.

    The database path is read from the config, since the legacy tool allowed it to
    live elsewhere, with a fallback to the conventional location.
    """
    base = Path(data_dir).expanduser()
    config_path = base / "config.ini"
    if not config_path.is_file():
        raise ImportError_(
            f"no legacy config at {config_path}. Pass --legacy-dir if your "
            f"minipassword data is somewhere else."
        )

    parser = configparser.ConfigParser()
    parser.read(config_path)
    try:
        db_path = Path(parser.get("db", "database_file")).expanduser()
    except (configparser.NoSectionError, configparser.NoOptionError):
        db_path = base / "minipassword.db"

    if not db_path.is_file():
        raise ImportError_(f"legacy database not found at {db_path}")
    return config_path, db_path


def read_legacy_key(config_path: Path) -> str:
    """Read the legacy Fernet key from ``config.ini``."""
    parser = configparser.ConfigParser()
    parser.read(config_path)
    try:
        return parser.get("common", "aes_key")
    except (configparser.NoSectionError, configparser.NoOptionError) as exc:
        raise ImportError_(
            f"{config_path} has no [common] aes_key, so the legacy rows cannot be "
            f"decrypted. Without that key the data is unrecoverable; check your "
            f"backups for the original config.ini."
        ) from exc


def read_legacy_records(
    db_path: Path, fernet_key: str
) -> tuple[list[LegacyRecord], list[tuple[str, str]]]:
    """Read and decrypt every legacy row.

    Returns the records plus a list of ``(identifier, reason)`` failures. A row
    that cannot be decrypted is recorded and skipped, never raised: one unreadable
    row must not abort a 400-record import (requirement 5.4).
    """
    try:
        fernet = Fernet(fernet_key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ImportError_(
            f"the legacy aes_key is not a valid Fernet key: {exc}"
        ) from exc

    # Read-only. SQLite will not write to the file, the WAL, or the journal.
    uri = f"file:{db_path}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise ImportError_(f"could not open {db_path} read-only: {exc}") from exc

    try:
        connection.execute("PRAGMA query_only = 1")
        try:
            rows = connection.execute(
                "SELECT id, name, login_name, password, memo, url FROM passwords "
                "ORDER BY id"
            ).fetchall()
        except sqlite3.Error as exc:
            raise ImportError_(
                f"{db_path} does not look like a minipassword database: {exc}"
            ) from exc
    finally:
        connection.close()

    records: list[LegacyRecord] = []
    failures: list[tuple[str, str]] = []

    for legacy_id, name, login_token, password_token, memo, url in rows:
        label = f"id {legacy_id} ({name!r})"
        try:
            login = fernet.decrypt((login_token or "").encode("utf-8")).decode("utf-8")
            password = fernet.decrypt(
                (password_token or "").encode("utf-8")
            ).decode("utf-8")
        except InvalidToken:
            failures.append(
                (
                    label,
                    "could not be decrypted with this key; the row may predate a "
                    "key change, or be corrupt",
                )
            )
            continue
        except (UnicodeDecodeError, ValueError) as exc:
            failures.append((label, f"decrypted to invalid text: {exc}"))
            continue

        records.append(
            LegacyRecord(
                legacy_id=int(legacy_id),
                name=str(name or ""),
                login=login,
                password=password,
                memo=str(memo or ""),
                url=str(url or ""),
            )
        )

    return records, failures


def read_json_records(
    json_path: Path,
) -> tuple[list[LegacyRecord], list[tuple[str, str]]]:
    """Read the plaintext JSON layout used by the legacy ``importfromjsonfile.py``.

    A list of objects with ``name``, ``login_name``, ``password``, ``memo`` and
    ``url``. Records are reported by their own name rather than by the following
    record's, which is what the original script did: it incremented its seed before
    printing, so every success line named the *next* entry.
    """
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportError_(f"could not read {json_path}: {exc}") from exc

    if not isinstance(data, list):
        raise ImportError_(f"{json_path} should contain a JSON list of objects")

    records: list[LegacyRecord] = []
    failures: list[tuple[str, str]] = []

    for index, entry in enumerate(data):
        label = f"entry {index}"
        if not isinstance(entry, dict):
            failures.append((label, "not an object"))
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            failures.append((label, "has no name"))
            continue
        records.append(
            LegacyRecord(
                legacy_id=None,
                name=name,
                login=str(entry.get("login_name") or entry.get("login") or ""),
                password=str(entry.get("password") or ""),
                memo=str(entry.get("memo") or ""),
                url=str(entry.get("url") or ""),
            )
        )

    return records, failures


# ----------------------------------------------------------------- statistics


def _describe(records: Sequence[LegacyRecord], report: ImportReport) -> None:
    report.total_rows = len(records) + len(report.failures)
    report.cjk_records = sum(
        1
        for r in records
        if contains_cjk(r.name) or contains_cjk(r.memo) or contains_cjk(r.login)
    )
    report.with_memo = sum(1 for r in records if r.memo.strip())
    report.with_url = sum(1 for r in records if r.url.strip())

    seen: dict[str, int] = {}
    for record in records:
        key = record.name.casefold()
        seen[key] = seen.get(key, 0) + 1
    report.duplicate_names = sorted(
        name for name, count in seen.items() if count > 1
    )


# --------------------------------------------------------------------- import


def apply_records(
    vault: Vault,
    records: Sequence[LegacyRecord],
    *,
    source: str,
    dry_run: bool = False,
    failures: Iterable[tuple[str, str]] = (),
) -> ImportReport:
    """Write legacy records into an open vault.

    Idempotent. A record with a ``legacy_id`` already present is updated in place
    rather than duplicated; JSON records, which have no ``legacy_id``, match on
    name instead (requirement 5.9).
    """
    report = ImportReport(source=source, dry_run=dry_run)
    report.failures = list(failures)
    _describe(records, report)

    if dry_run:
        return report

    by_legacy_id: dict[int, ev.Record] = {}
    by_name: dict[str, ev.Record] = {}
    for existing in vault.all_records():
        if existing.legacy_id is not None:
            by_legacy_id[existing.legacy_id] = existing
        by_name.setdefault(existing.name.casefold(), existing)

    to_add: list[dict[str, Any]] = []

    for record in records:
        current = None
        if record.legacy_id is not None:
            current = by_legacy_id.get(record.legacy_id)
        if current is None:
            current = by_name.get(record.name.casefold())

        if current is None:
            to_add.append(record.as_spec())
            continue

        changes = {
            key: value
            for key, value in (
                ("name", record.name),
                ("login", record.login),
                ("password", record.password),
                ("memo", record.memo),
                ("url", record.url),
            )
            if current.fields.get(key, "") != value
        }
        if record.legacy_id is not None and current.legacy_id != record.legacy_id:
            changes["legacy_id"] = record.legacy_id

        if changes:
            vault.update(current.id, **changes)
            report.updated += 1
        else:
            report.unchanged += 1

    if to_add:
        # One append and one fold rather than several thousand of each.
        vault.add_many(to_add)
        report.added = len(to_add)

    return report


def verify_against(
    vault: Vault, records: Sequence[LegacyRecord]
) -> list[str]:
    """Compare a freshly reopened vault against the source, field by field.

    Requirement 5.6. The caller must pass a vault that was closed and reopened
    from disk, not the one used for writing: the point is to prove the bytes on
    disk decrypt back to the source data, not that an in-memory dict is
    self-consistent.

    Returns a list of human-readable mismatches; empty means verified.
    """
    mismatches: list[str] = []

    by_legacy_id: dict[int, ev.Record] = {}
    by_name: dict[str, ev.Record] = {}
    for existing in vault.all_records():
        if existing.legacy_id is not None:
            by_legacy_id[existing.legacy_id] = existing
        by_name.setdefault(existing.name.casefold(), existing)

    for record in records:
        found = None
        if record.legacy_id is not None:
            found = by_legacy_id.get(record.legacy_id)
        if found is None:
            found = by_name.get(record.name.casefold())

        if found is None:
            mismatches.append(f"{record.name!r}: missing from the new vault")
            continue

        rebuilt = LegacyRecord(
            legacy_id=found.legacy_id,
            name=found.name,
            login=found.login,
            password=found.password,
            memo=found.memo,
            url=found.url,
        )
        if rebuilt.digest() == record.digest():
            continue

        differing = [
            name
            for name, left, right in (
                ("name", record.name, rebuilt.name),
                ("login", record.login, rebuilt.login),
                ("password", record.password, rebuilt.password),
                ("memo", record.memo, rebuilt.memo),
                ("url", record.url, rebuilt.url),
            )
            if left != right
        ]
        # Field names only. The values are the secrets we are migrating.
        mismatches.append(
            f"{record.name!r}: differs in {', '.join(differing) or 'an unknown field'}"
        )

    return mismatches
