"""The vault: unlock, query, mutate.

This is the only module the CLI and the TUI both depend on, and it contains no
user interface, no argument parsing, and no printing. Everything below the surface
is the storage layer from :mod:`format` and :mod:`events`.

Layout on disk::

    ~/.config/pipassword/           per-device, NEVER synced
      config.toml                   vault path, device name. NO SECRETS.
      device_id                     16 random bytes
      state.json                    last_known_good_time, last_open_ts

    <vault_dir>/                    point Syncthing at this
      keys.1.mpk
      log/beepy-a1b2c3d4.mpl        only this device appends here
      log/pi4-e5f6a7b8.mpl          only the Pi 4 appends there
      .stignore

The device identity deliberately lives outside the vault. If it were synced, two
devices would derive the same log filename and both would append to one path,
which is the only way Syncthing could produce a conflict (requirement 3.4).

Contrast with the legacy project, where ``config.ini`` held the Fernet key in
cleartext at mode 0644: no file under the config directory here ever contains key
material (requirement 2.11).
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from . import events as ev
from . import format as fmt
from .compat import SLOTS, TomlDecodeError, load_toml
from .crypto import KdfParams, wipe

__all__ = [
    "VaultError",
    "RecordNotFoundError",
    "DuplicateNameError",
    "DeviceIdentity",
    "VaultConfig",
    "ChangeSummary",
    "Vault",
    "default_config_dir",
    "default_vault_dir",
    "CONFLICT_GLOB",
    "STIGNORE_CONTENTS",
]


class VaultError(Exception):
    """A vault-level problem."""


class RecordNotFoundError(VaultError):
    """No such record."""


class DuplicateNameError(VaultError):
    """A record with that name already exists."""


CONFLICT_GLOB = "*.sync-conflict-*"

STIGNORE_CONTENTS = """\
// Managed by pipassword. Keep these out of sync.
.tmp-*
*.tmp
*.lock
// Conflict copies should never occur: each device writes only its own log file.
// If one appears it means two devices share a device_id, which needs fixing
// rather than syncing around.
*.sync-conflict-*
"""


# ------------------------------------------------------------------ locations


def default_config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path(os.path.expanduser("~")) / ".config"
    return root / "pipassword"


def default_vault_dir() -> Path:
    override = os.environ.get("PIPASSWORD_VAULT")
    if override:
        return Path(override)
    base = os.environ.get("XDG_DATA_HOME")
    root = Path(base) if base else Path(os.path.expanduser("~")) / ".local" / "share"
    return root / "pipassword" / "vault"


# ------------------------------------------------------------ device identity


@dataclass(frozen=True, **SLOTS)
class DeviceIdentity:
    uuid: bytes
    name: str

    @property
    def uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.uuid))

    @property
    def log_filename(self) -> str:
        return fmt.log_filename(self.name, self.uuid)

    @classmethod
    def load_or_create(
        cls, config_dir: Path | str | None = None, *, name: str | None = None
    ) -> DeviceIdentity:
        """Read this device's identity, generating it on first run.

        Stored outside the vault directory on purpose; see the module docstring.
        """
        config_dir = default_config_dir() if config_dir is None else Path(config_dir)
        fmt.ensure_dir(config_dir)
        id_path = config_dir / "device_id"

        if id_path.exists():
            raw = id_path.read_bytes()
            if len(raw) != 16:
                raise VaultError(
                    f"{id_path} should contain 16 bytes but has {len(raw)}. "
                    f"Delete it to generate a new device identity; this creates a "
                    f"new log file and loses nothing."
                )
        else:
            raw = uuid.uuid4().bytes
            fmt.atomic_write(id_path, raw)

        resolved = name or _read_device_name(config_dir) or _hostname()
        return cls(uuid=raw, name=resolved)


def _hostname() -> str:
    try:
        return socket.gethostname() or "device"
    except OSError:  # pragma: no cover
        return "device"


def _read_device_name(config_dir: Path) -> str | None:
    try:
        return VaultConfig.load(config_dir).device_name
    except (OSError, VaultError):
        return None


# -------------------------------------------------------------------- config


@dataclass(**SLOTS)
class VaultConfig:
    """Non-secret preferences.

    Deliberately incapable of holding key material: :meth:`save` writes only these
    named fields (requirement 2.11).
    """

    vault_path: Path | None = None
    device_name: str | None = None
    reveal_seconds: int = 15

    @classmethod
    def load(cls, config_dir: Path | None = None) -> VaultConfig:
        config_dir = default_config_dir() if config_dir is None else config_dir
        path = config_dir / "config.toml"
        if not path.exists():
            return cls()
        try:
            data = load_toml(path.read_text(encoding="utf-8"))
        except (TomlDecodeError, UnicodeDecodeError) as exc:
            raise VaultError(f"{path} is not valid TOML: {exc}") from exc

        vault = data.get("vault", {})
        ui = data.get("ui", {})
        raw_path = vault.get("path")
        return cls(
            vault_path=Path(raw_path) if raw_path else None,
            device_name=vault.get("device_name"),
            reveal_seconds=int(ui.get("reveal_seconds", 15)),
        )

    def save(self, config_dir: Path | None = None) -> Path:
        config_dir = default_config_dir() if config_dir is None else Path(config_dir)
        fmt.ensure_dir(config_dir)
        path = config_dir / "config.toml"

        lines = [
            "# pipassword configuration.",
            "# This file contains no key material and no passwords. The vault's",
            "# encryption key is derived from your master password and never stored.",
            "",
            "[vault]",
        ]
        if self.vault_path is not None:
            lines.append(f'path = "{self.vault_path}"')
        if self.device_name is not None:
            lines.append(f'device_name = "{self.device_name}"')
        lines += ["", "[ui]", f"reveal_seconds = {self.reveal_seconds}", ""]
        fmt.atomic_write(path, "\n".join(lines).encode("utf-8"))
        return path


@dataclass(**SLOTS)
class DeviceState:
    """Per-device, non-synced bookkeeping.

    ``last_known_good_time`` is the highest timestamp this device has ever
    observed. It is the reference for the TOTP clock gate (requirement 7.3): if
    the system clock is earlier than this, the clock went backwards and any TOTP
    code would be wrong.

    ``last_open_ts`` is where the "what changed since I last looked" summary
    measures from (requirement 3.11).
    """

    last_known_good_time: int = 0
    last_open_ts: int = 0

    @classmethod
    def load(cls, config_dir: Path) -> DeviceState:
        path = config_dir / "state.json"
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            # Corrupt per-device state must never block an unlock; it is a cache,
            # and the worst cost of losing it is a less useful change summary.
            return cls()
        return cls(
            last_known_good_time=int(data.get("last_known_good_time", 0)),
            last_open_ts=int(data.get("last_open_ts", 0)),
        )

    def save(self, config_dir: Path) -> None:
        fmt.ensure_dir(config_dir)
        fmt.atomic_write(
            config_dir / "state.json",
            json.dumps(
                {
                    "last_known_good_time": self.last_known_good_time,
                    "last_open_ts": self.last_open_ts,
                },
                indent=2,
            ).encode("utf-8"),
        )


# ------------------------------------------------------------ change summary


@dataclass(frozen=True, **SLOTS)
class ChangeSummary:
    """What happened in the vault since this device last opened it."""

    since_ts: int
    added: tuple[ev.Record, ...] = ()
    updated: tuple[ev.Record, ...] = ()
    deleted: tuple[str, ...] = ()
    by_device: Mapping[bytes, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.updated) + len(self.deleted)

    @property
    def is_empty(self) -> bool:
        return self.total == 0


# ---------------------------------------------------------------------- vault


class Vault:
    """An unlocked vault.

    There is no auto-lock and no background agent (requirement 4.17). The key
    lives for the lifetime of this object and is dropped by :meth:`close`, which
    makes the safe thing and the simple thing the same thing: unlock, work, exit.

    Use as a context manager so the key is released on the way out.
    """

    def __init__(
        self,
        *,
        vault_dir: Path,
        config_dir: Path,
        device: DeviceIdentity,
        keyfile: fmt.Keyfile,
        dek: bytes,
        events: list[ev.Event],
        anomalies: list[str],
        conflicts: list[Path],
        state: DeviceState,
    ) -> None:
        self.vault_dir = vault_dir
        self.config_dir = config_dir
        self.device = device
        self.keyfile = keyfile
        self._dek = bytearray(dek)
        self._events = events
        self.anomalies = anomalies
        self.conflicts = conflicts
        self._state = state
        self._fold: ev.FoldResult | None = None
        self._closed = False
        self._seq = max(
            (e.seq for e in events if e.device_uuid == device.uuid), default=0
        )
        self._opened_at_ts = self.state_snapshot().highest_ts

    # -------------------------------------------------------------- lifecycle

    @staticmethod
    def _log_dir(vault_dir: Path) -> Path:
        return vault_dir / "log"

    @classmethod
    def create(
        cls,
        vault_dir: Path | str,
        password: str | bytes,
        *,
        params: KdfParams | None = None,
        config_dir: Path | str | None = None,
        device_name: str | None = None,
        check_memory: bool = True,
    ) -> tuple[Vault, bytes]:
        """Create a vault. Returns the open vault and the recovery key.

        The recovery key is returned rather than stored: the caller must show it
        to the user exactly once, and it is never written anywhere by us
        (requirement 6.1).
        """
        vault_dir = Path(vault_dir)
        config_dir = default_config_dir() if config_dir is None else Path(config_dir)
        if fmt.find_keyfile_generations(vault_dir):
            raise VaultError(
                f"{vault_dir} already contains a keyfile; refusing to overwrite it"
            )

        keyfile, recovery_key = fmt.create_keyfile(
            vault_dir, password, params=params, check_memory=check_memory
        )
        fmt.ensure_dir(cls._log_dir(vault_dir))
        stignore = vault_dir / ".stignore"
        if not stignore.exists():
            fmt.atomic_write(stignore, STIGNORE_CONTENTS.encode("utf-8"))

        dek = keyfile.unwrap_with_password(password, check_memory=False)
        vault = cls._open(
            vault_dir=vault_dir,
            config_dir=config_dir,
            keyfile=keyfile,
            dek=dek,
            device_name=device_name,
        )
        return vault, recovery_key

    @classmethod
    def unlock(
        cls,
        vault_dir: Path | str,
        *,
        password: str | bytes | None = None,
        recovery_key: bytes | None = None,
        pin: str | None = None,
        config_dir: Path | str | None = None,
        device_name: str | None = None,
        check_memory: bool = True,
    ) -> Vault:
        """Open an existing vault with a password, the recovery key, or a PIN.

        Exactly one credential. The PIN path (requirement 9) only works if a PIN slot
        exists in the config directory for this vault, and it is a deliberate
        convenience-for-security trade documented in the spec: it protects a leaked
        vault copy but not a stolen device.
        """
        given = [c is not None for c in (password, recovery_key, pin)]
        if sum(given) != 1:
            raise VaultError(
                "supply exactly one of password, recovery_key, or pin"
            )

        vault_dir = Path(vault_dir)
        config_dir = default_config_dir() if config_dir is None else Path(config_dir)
        keyfile = fmt.load_keyfile(vault_dir)

        if password is not None:
            dek = keyfile.unwrap_with_password(password, check_memory=check_memory)
        elif recovery_key is not None:
            dek = keyfile.unwrap_with_recovery_key(recovery_key)
        else:
            assert pin is not None
            dek = cls._unlock_with_pin(vault_dir, config_dir, keyfile, pin)

        return cls._open(
            vault_dir=vault_dir,
            config_dir=config_dir,
            keyfile=keyfile,
            dek=dek,
            device_name=device_name,
        )

    @staticmethod
    def _unlock_with_pin(
        vault_dir: Path, config_dir: Path, keyfile: fmt.Keyfile, pin: str
    ) -> bytes:
        # Imported here, not at module scope: pinslot imports from format, and vault
        # imports both, so a top-level import would be circular.
        from . import pinslot

        slot_file = pinslot.load_pin_slot(config_dir)
        if slot_file is None:
            raise VaultError(
                "no PIN is set on this device. Unlock with your master password, "
                "or run 'pipw pin set' first."
            )
        return slot_file.unlock(pin, keyfile.vault_uuid)

    @staticmethod
    def has_pin(config_dir: Path | str | None = None) -> bool:
        from . import pinslot

        config_dir = default_config_dir() if config_dir is None else Path(config_dir)
        return pinslot.pin_slot_exists(config_dir)

    @classmethod
    def _open(
        cls,
        *,
        vault_dir: Path,
        config_dir: Path,
        keyfile: fmt.Keyfile,
        dek: bytes,
        device_name: str | None,
    ) -> Vault:
        device = DeviceIdentity.load_or_create(config_dir, name=device_name)
        log_dir = fmt.ensure_dir(cls._log_dir(vault_dir))

        own_log = log_dir / device.log_filename
        fmt.create_log(own_log, keyfile.vault_uuid, device.uuid)

        events: list[ev.Event] = []
        anomalies: list[str] = []

        for path in fmt.find_logs(log_dir):
            try:
                result = fmt.read_log(path, dek)
            except fmt.FormatError as exc:
                anomalies.append(f"{path.name}: {exc}")
                continue

            if result.header.vault_uuid != keyfile.vault_uuid:
                anomalies.append(
                    f"{path.name}: belongs to a different vault "
                    f"({result.header.vault_uuid_str}); ignored"
                )
                continue

            for anomaly in result.anomalies:
                anomalies.append(f"{path.name}: {anomaly}")

            for payload in result.payloads:
                try:
                    events.append(
                        ev.decode_event(payload, result.header.device_uuid)
                    )
                except ev.EventError as exc:
                    # One malformed event must not cost the vault.
                    anomalies.append(f"{path.name}: unreadable event: {exc}")

        conflicts = sorted(vault_dir.glob(CONFLICT_GLOB)) + sorted(
            log_dir.glob(CONFLICT_GLOB)
        )
        if conflicts:
            anomalies.append(
                f"{len(conflicts)} Syncthing conflict file(s) present. This should "
                f"be impossible, because each device writes only its own log. The "
                f"likely cause is two devices sharing a device_id."
            )

        state = DeviceState.load(config_dir)
        vault = cls(
            vault_dir=vault_dir,
            config_dir=config_dir,
            device=device,
            keyfile=keyfile,
            dek=dek,
            events=events,
            anomalies=anomalies,
            conflicts=conflicts,
            state=state,
        )
        vault._record_known_good_time()
        return vault

    def close(self) -> None:
        """Release the key and persist per-device state.

        Zeroes the DEK buffer. This is best effort by necessity: Python cannot
        erase the immutable ``bytes`` the key passed through on its way here. The
        threat model excludes an attacker reading process memory while unlocked,
        precisely because that is not solvable in this language.
        """
        if self._closed:
            return
        try:
            self._state.last_open_ts = self.state_snapshot().highest_ts
            self._state.save(self.config_dir)
        finally:
            wipe(self._dek)
            self._events = []
            self._fold = None
            self._closed = True

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise VaultError("vault is closed")

    @property
    def dek(self) -> bytes:
        self._require_open()
        return bytes(self._dek)

    # ------------------------------------------------------------- read side

    def state_snapshot(self) -> ev.FoldResult:
        """Current folded state, computed lazily and cached until the next write."""
        if self._fold is None:
            self._fold = ev.fold(self._events)
        return self._fold

    def all_records(self) -> list[ev.Record]:
        self._require_open()
        return sorted(
            self.state_snapshot().records.values(), key=lambda r: r.name.casefold()
        )

    def get(self, record_id: str) -> ev.Record:
        self._require_open()
        record = self.state_snapshot().records.get(record_id)
        if record is None:
            raise RecordNotFoundError(f"no record with id {record_id}")
        return record

    def get_by_name(self, name: str) -> ev.Record | None:
        self._require_open()
        folded = name.casefold()
        for record in self.state_snapshot().records.values():
            if record.name.casefold() == folded:
                return record
        return None

    def search(self, query: str) -> list[ev.Record]:
        """Substring search over name, url, memo, and the Pinyin index.

        Consulting the Pinyin index here means task 11 only has to populate it:
        typing ``qyyx`` matches ``企业邮箱`` without switching input method
        (requirements 4.12, 4.13).
        """
        self._require_open()
        needle = query.strip().casefold()
        if not needle:
            return self.all_records()

        matches = []
        for record in self.all_records():
            haystack = [
                record.name,
                record.url,
                record.memo,
                *record.pinyin.values(),
            ]
            if any(needle in (value or "").casefold() for value in haystack):
                matches.append(record)
        return matches

    def history(self, record_id: str) -> list[ev.Event]:
        """Every event touching a record, oldest first.

        This is what makes a superseded or deleted value recoverable
        (requirement 3.7) rather than merely gone.
        """
        self._require_open()
        return sorted(
            (e for e in self._events if e.record_id == record_id),
            key=lambda e: e.sort_key,
        )

    def deleted_ids(self) -> dict[str, int]:
        self._require_open()
        return dict(self.state_snapshot().deleted)

    # --------------------------------------------------------------- syncing

    def changes_since_last_open(self) -> ChangeSummary:
        """Requirement 3.11.

        This is the useful half of a sync prompt: it tells the user what arrived
        without asking them to make an overwrite decision, because there is no
        overwrite to make.
        """
        self._require_open()
        since = self._state.last_open_ts
        folded = self.state_snapshot()

        added, updated = [], []
        by_device: dict[bytes, int] = {}

        for record in folded.records.values():
            if record.updated_at <= since:
                continue
            if record.created_at > since:
                added.append(record)
            else:
                updated.append(record)
            if record.last_device:
                by_device[record.last_device] = (
                    by_device.get(record.last_device, 0) + 1
                )

        deleted = tuple(
            rid for rid, ts in folded.deleted.items() if ts > since
        )
        return ChangeSummary(
            since_ts=since,
            added=tuple(sorted(added, key=lambda r: r.name.casefold())),
            updated=tuple(sorted(updated, key=lambda r: r.name.casefold())),
            deleted=deleted,
            by_device=by_device,
        )

    @property
    def clock_is_behind(self) -> bool:
        """True when the system clock predates timestamps already in the vault.

        On a Pi this almost always means the board was powered off and
        ``fake-hwclock`` restored a stale time. Drives the TUI warning and the
        TOTP gate.
        """
        return ev.clock_is_behind(self._state.last_known_good_time)

    @property
    def last_known_good_time(self) -> int:
        return self._state.last_known_good_time

    def _record_known_good_time(self) -> None:
        highest = max(
            self.state_snapshot().highest_ts, self._state.last_known_good_time
        )
        if highest != self._state.last_known_good_time:
            self._state.last_known_good_time = highest
            self._state.save(self.config_dir)

    # -------------------------------------------------------------- write side

    @property
    def own_log(self) -> Path:
        return self._log_dir(self.vault_dir) / self.device.log_filename

    def _next_ts_and_seq(self) -> tuple[int, int]:
        highest = max(
            self.state_snapshot().highest_ts, self._state.last_known_good_time
        )
        self._seq += 1
        return ev.next_ts(highest), self._seq

    def _commit(self, new_events: Sequence[ev.Event]) -> None:
        """Append events to this device's log and fold them into memory.

        Order matters: the log is written first, so an in-memory state that
        reports success always corresponds to bytes that reached the disk.
        """
        if not new_events:
            return
        payloads = [ev.encode_event(e) for e in new_events]
        fmt.append_frames(self.own_log, self.dek, payloads)
        self._events.extend(new_events)
        self._fold = None
        self._state.last_known_good_time = max(
            self._state.last_known_good_time,
            max(e.ts for e in new_events),
        )
        self._state.save(self.config_dir)

    def _index_for(
        self,
        fields: Mapping[str, Any],
        explicit: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Build the Pinyin search index for an event being written.

        Imported here rather than at module scope so that reading a vault never
        pulls in pypinyin and its multi-megabyte tables (requirement 4.14). An
        explicit index always wins, which keeps tests and the importer able to
        control it exactly.
        """
        if explicit is not None:
            return dict(explicit)
        from . import pinyin as pinyin_module

        return pinyin_module.build_index(fields)

    def add(
        self,
        name: str,
        *,
        login: str = "",
        password: str = "",
        url: str = "",
        memo: str = "",
        totp: str = "",
        legacy_id: int | None = None,
        allow_duplicate_name: bool = False,
        pinyin: Mapping[str, str] | None = None,
    ) -> ev.Record:
        """Add a record.

        Duplicate names are rejected by default, matching the legacy schema's
        UNIQUE constraint on ``name``, but the check is overridable rather than
        structural: two devices can legitimately create the same name while
        disconnected, and the fold must not lose either (see requirement 5.10's
        collision reporting).
        """
        self._require_open()
        if not name.strip():
            raise VaultError("name is required")
        if not allow_duplicate_name and self.get_by_name(name) is not None:
            raise DuplicateNameError(f"a record named {name!r} already exists")

        fields: dict[str, Any] = {"name": name}
        for key, value in (
            ("login", login),
            ("password", password),
            ("url", url),
            ("memo", memo),
            ("totp", totp),
        ):
            if value:
                fields[key] = value
        if legacy_id is not None:
            fields["legacy_id"] = int(legacy_id)

        ts, seq = self._next_ts_and_seq()
        record_id = ev.new_record_id()
        self._commit(
            [
                ev.make_set_event(
                    record_id,
                    fields,
                    ts=ts,
                    seq=seq,
                    device_uuid=self.device.uuid,
                    pinyin=self._index_for(fields, pinyin),
                )
            ]
        )
        return self.get(record_id)

    def add_many(self, specs: Iterable[Mapping[str, Any]]) -> list[ev.Record]:
        """Bulk add in a single append and a single fold.

        Exists for the legacy import: adding several thousand records one at a
        time would re-fold the whole event stream on each one.
        """
        self._require_open()
        new_events, ids = [], []
        for spec in specs:
            name = str(spec.get("name", "")).strip()
            if not name:
                raise VaultError("name is required for every record")
            fields: dict[str, Any] = {"name": name}
            for key in ("login", "password", "url", "memo", "totp"):
                value = spec.get(key)
                if value:
                    fields[key] = str(value)
            if spec.get("legacy_id") is not None:
                fields["legacy_id"] = int(spec["legacy_id"])

            ts, seq = self._next_ts_and_seq()
            record_id = ev.new_record_id()
            ids.append(record_id)
            new_events.append(
                ev.make_set_event(
                    record_id,
                    fields,
                    ts=ts,
                    seq=seq,
                    device_uuid=self.device.uuid,
                    pinyin=self._index_for(fields, spec.get("pinyin")),
                )
            )
        self._commit(new_events)
        return [self.get(rid) for rid in ids]

    def update(
        self,
        record_id: str,
        *,
        pinyin: Mapping[str, str] | None = None,
        **changes: Any,
    ) -> ev.Record:
        """Update named fields. Only the fields given are written.

        Writing just the delta is what lets two devices edit different fields of
        one record while disconnected and keep both edits.
        """
        self._require_open()
        record = self.get(record_id)

        unknown = set(changes) - set(ev.FIELDS)
        if unknown:
            raise VaultError(f"unknown field(s): {sorted(unknown)}")
        if "name" in changes and not str(changes["name"]).strip():
            raise VaultError("name cannot be empty")

        delta = {
            key: value
            for key, value in changes.items()
            if record.fields.get(key) != value
        }
        if not delta and not pinyin:
            return record

        merged = {**record.fields, **delta}
        ts, seq = self._next_ts_and_seq()
        self._commit(
            [
                ev.make_set_event(
                    record_id,
                    delta or {"name": record.name},
                    ts=ts,
                    seq=seq,
                    device_uuid=self.device.uuid,
                    pinyin=self._index_for(merged, pinyin),
                )
            ]
        )
        return self.get(record_id)

    def delete(self, record_id: str) -> None:
        """Write a tombstone. The record's history remains in the log."""
        self._require_open()
        self.get(record_id)  # raises if unknown
        ts, seq = self._next_ts_and_seq()
        self._commit(
            [
                ev.make_del_event(
                    record_id, ts=ts, seq=seq, device_uuid=self.device.uuid
                )
            ]
        )

    # ---------------------------------------------------------------- PIN slot

    def set_pin(self, pin: str, *, check_memory: bool = True) -> None:
        """Create or replace this device's PIN slot, wrapping the current DEK.

        Requires an already-unlocked vault, which is how requirement 9.7's "needs the
        master password or recovery key" is enforced in practice: you cannot reach
        this method without having unlocked first.
        """
        self._require_open()
        from . import pinslot

        slot_file = pinslot.PinSlotFile(pinslot.pin_slot_path(self.config_dir))
        slot_file.create(
            vault_uuid=self.keyfile.vault_uuid,
            dek=self.dek,
            pin=pin,
            check_memory=check_memory,
        )

    def remove_pin(self) -> bool:
        """Delete this device's PIN slot. Returns whether one existed.

        Needs no credential (requirement 9.8): it only removes a local convenience
        that reduces security, so gating it behind a password would be theatre.
        """
        from . import pinslot

        existed = pinslot.pin_slot_exists(self.config_dir)
        pinslot.PinSlotFile(pinslot.pin_slot_path(self.config_dir)).delete()
        return existed

    def export_plaintext(self) -> dict[str, Any]:
        """Everything, decrypted, as plain data (requirement 6.5).

        The vault must never be a roach motel. Field order is stable so the
        output diffs cleanly against :file:`recover.py`.
        """
        self._require_open()
        return {
            "format": "pipassword-export-v1",
            "vault_uuid": self.keyfile.vault_uuid_str,
            "records": [
                {
                    "id": record.id,
                    "created_at": record.created_at,
                    "updated_at": record.updated_at,
                    **{
                        key: record.fields[key]
                        for key in ev.FIELDS
                        if key in record.fields
                    },
                }
                for record in self.all_records()
            ],
        }
