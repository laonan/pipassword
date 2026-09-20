"""Event model, hybrid logical clock, and the fold that produces vault state.

The vault is not stored as records; it is stored as an ordered stream of changes,
one append-only log per device. State is the fold of every log's events. That is
what makes multi-device editing safe without a merge algorithm: each device only
ever writes its own file, so there is nothing to reconcile, and the union of the
files is the answer.

Two details carry most of the weight:

**Ordering.** Events sort by ``(ts, device_uuid, seq)``. Including ``device_uuid``
breaks timestamp ties the same way on every device, so all devices holding the
same set of files compute byte-identical state.

**The clock.** ``ts`` is a hybrid logical clock, not a wall clock. No Raspberry
Pi before the Pi 5 has a battery-backed RTC, so a Beepy that has been powered off
boots with ``fake-hwclock`` restoring the time from its last shutdown, which may
be days stale. With raw wall-clock timestamps an edit made today on the Beepy
would sort before last week's desktop edit and lose. See :func:`next_ts`.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "EventError",
    "OP_SET",
    "OP_DEL",
    "FIELDS",
    "REQUIRED_FIELDS",
    "Event",
    "Record",
    "FoldResult",
    "next_ts",
    "now_micros",
    "clock_is_behind",
    "encode_event",
    "decode_event",
    "make_set_event",
    "make_del_event",
    "fold",
    "new_record_id",
]


class EventError(Exception):
    """An event payload is malformed."""


OP_SET = "set"
OP_DEL = "del"
_OPS = frozenset({OP_SET, OP_DEL})

FIELDS = (
    "name",
    "login",
    "password",
    "url",
    "memo",
    "totp",
    "legacy_id",
)
"""Every field a record may carry.

A closed set, validated on decode, so a typo in a field name surfaces as an error
rather than silently creating a field nothing ever reads. ``legacy_id`` preserves
the integer id from a migrated minipassword vault (requirement 5.5).
"""

REQUIRED_FIELDS = ("name",)
"""Fields a record must have to be meaningful. Enforced by the vault, not here:
an individual ``set`` event legitimately carries only what changed."""

_MAX_TS = 2**63 - 1


def now_micros() -> int:
    """Wall clock in microseconds since the epoch."""
    return time.time_ns() // 1000


def next_ts(highest_seen: int, now_us: int | None = None) -> int:
    """Return a timestamp guaranteed to sort after everything already observed.

    This is the hybrid logical clock, and it is not optional on this hardware.
    ``highest_seen`` is the maximum ``ts`` across every event loaded from every
    log. Taking ``max(now, highest_seen + 1)`` means an event written after
    observing another device's event always sorts after it, no matter how wrong
    the local clock is.

    Worked example. The Beepy's clock is stale by a week. The desktop wrote an
    event at a true timestamp of T. The Beepy loads that event, so
    ``highest_seen == T``, and its own next event gets ``T + 1`` rather than
    ``T - one_week``. Causality is preserved and the newer edit wins the fold.
    """
    if highest_seen < 0:
        raise EventError("highest_seen must not be negative")
    now = now_micros() if now_us is None else now_us
    ts = max(now, highest_seen + 1)
    if ts > _MAX_TS:
        raise EventError("timestamp overflow")
    return ts


def clock_is_behind(highest_seen: int, now_us: int | None = None) -> bool:
    """True when the local clock is earlier than events already in the vault.

    Drives the TUI's clock-skew warning and the TOTP gate. A true result means
    the system clock cannot be trusted, which on a Pi almost always means it was
    powered off and ``fake-hwclock`` restored a stale time.
    """
    now = now_micros() if now_us is None else now_us
    return now < highest_seen


def new_record_id() -> str:
    """A stable, device-independent record identifier.

    UUIDs rather than the legacy autoincrement integers: two devices adding a
    record while disconnected must not collide, and there is no coordinator to
    hand out sequence numbers.
    """
    return str(uuid.uuid4())


@dataclass(frozen=True, slots=True)
class Event:
    """A single change.

    ``device_uuid`` is not part of the serialised payload. It comes from the log
    header at read time, which means it cannot be forged independently of the
    log the event lives in, and it costs nothing to store per event.
    """

    op: str
    record_id: str
    ts: int
    seq: int
    device_uuid: bytes
    fields: Mapping[str, Any] = field(default_factory=dict)
    pinyin: Mapping[str, str] = field(default_factory=dict)

    @property
    def sort_key(self) -> tuple[int, bytes, int]:
        return (self.ts, self.device_uuid, self.seq)


@dataclass(frozen=True, slots=True)
class Record:
    """A folded record: the current value of every field."""

    id: str
    fields: Mapping[str, Any]
    pinyin: Mapping[str, str]
    created_at: int
    updated_at: int
    last_device: bytes = b""
    """Device whose event last modified this record.

    Needed for requirement 3.11, the "4 entries added on pi4 since you last
    opened this" summary. Tracked during the fold because the information is only
    available there: it is not a property of any single field.
    """

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    @property
    def name(self) -> str:
        return str(self.fields.get("name", ""))

    @property
    def login(self) -> str:
        return str(self.fields.get("login", ""))

    @property
    def password(self) -> str:
        return str(self.fields.get("password", ""))

    @property
    def url(self) -> str:
        return str(self.fields.get("url", ""))

    @property
    def memo(self) -> str:
        return str(self.fields.get("memo", ""))

    @property
    def totp(self) -> str:
        return str(self.fields.get("totp", ""))

    @property
    def legacy_id(self) -> int | None:
        value = self.fields.get("legacy_id")
        return None if value is None else int(value)


@dataclass(frozen=True, slots=True)
class FoldResult:
    records: dict[str, Record]
    deleted: dict[str, int]
    """Record id to the timestamp of the delete that removed it.

    Kept rather than discarded so the vault can report what a sync brought in,
    and so an accidental deletion is visible instead of just absent.
    """

    highest_ts: int
    """Maximum timestamp observed. Seeds the hybrid logical clock."""

    event_count: int


def _validate_fields(raw: Any, what: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise EventError(f"{what} must be an object")
    unknown = set(raw) - set(FIELDS)
    if unknown:
        raise EventError(f"unknown field(s) in {what}: {sorted(unknown)}")
    return dict(raw)


def encode_event(event: Event) -> bytes:
    """Serialise an event to compact UTF-8 JSON.

    ``sort_keys`` makes the output byte-stable for a given event, which keeps
    tests meaningful and makes a diff of two logs readable when debugging.
    """
    payload: dict[str, Any] = {
        "op": event.op,
        "id": event.record_id,
        "ts": event.ts,
        "seq": event.seq,
    }
    if event.fields:
        payload["f"] = dict(event.fields)
    if event.pinyin:
        payload["p"] = dict(event.pinyin)
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def decode_event(payload: bytes, device_uuid: bytes) -> Event:
    """Parse an event payload, validating structure.

    Raises :class:`EventError` rather than letting a malformed payload through.
    The caller treats that like any other frame anomaly: report it, skip it, keep
    loading. One bad event must not cost the vault.
    """
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EventError(f"event is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise EventError("event must be a JSON object")

    op = raw.get("op")
    if op not in _OPS:
        raise EventError(f"unknown op {op!r}")

    record_id = raw.get("id")
    if not isinstance(record_id, str) or not record_id:
        raise EventError("event has no valid id")

    ts = raw.get("ts")
    seq = raw.get("seq", 0)
    if not isinstance(ts, int) or isinstance(ts, bool) or ts < 0:
        raise EventError("event ts must be a non-negative integer")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise EventError("event seq must be a non-negative integer")

    fields = _validate_fields(raw.get("f"), "f")
    pinyin = _validate_fields(raw.get("p"), "p")

    if op == OP_SET and not fields:
        raise EventError("a set event must carry at least one field")
    if op == OP_DEL and fields:
        raise EventError("a del event must not carry fields")

    return Event(
        op=op,
        record_id=record_id,
        ts=ts,
        seq=seq,
        device_uuid=device_uuid,
        fields=fields,
        pinyin=pinyin,
    )


def make_set_event(
    record_id: str,
    fields: Mapping[str, Any],
    *,
    ts: int,
    seq: int,
    device_uuid: bytes,
    pinyin: Mapping[str, str] | None = None,
) -> Event:
    """Build a ``set`` event carrying only the fields that changed.

    Partial updates are the mechanism behind field-level merge: because an event
    records just what changed, two devices editing different fields of one record
    while disconnected both survive the fold.
    """
    clean = _validate_fields(dict(fields), "fields")
    if not clean:
        raise EventError("a set event must carry at least one field")
    return Event(
        op=OP_SET,
        record_id=record_id,
        ts=ts,
        seq=seq,
        device_uuid=device_uuid,
        fields=clean,
        pinyin=dict(pinyin or {}),
    )


def make_del_event(
    record_id: str, *, ts: int, seq: int, device_uuid: bytes
) -> Event:
    """Build a tombstone.

    Deletion is recorded, never applied by removing bytes from a log
    (requirement 3.8). That keeps logs append-only and leaves the deleted value
    recoverable from history.
    """
    return Event(
        op=OP_DEL, record_id=record_id, ts=ts, seq=seq, device_uuid=device_uuid
    )


def fold(events: Iterable[Event]) -> FoldResult:
    """Reduce an event stream to current state.

    Deterministic: sorting on ``(ts, device_uuid, seq)`` means every device
    holding the same files produces identical output, regardless of the order
    files were read or events arrived.

    Conflict resolution is last-write-wins **per field**, which follows from
    events carrying only changed fields and being applied in order.
    """
    ordered = sorted(events, key=lambda e: e.sort_key)

    fields: dict[str, dict[str, Any]] = {}
    pinyin: dict[str, dict[str, str]] = {}
    created: dict[str, int] = {}
    updated: dict[str, int] = {}
    last_device: dict[str, bytes] = {}
    deleted: dict[str, int] = {}
    highest_ts = 0
    count = 0

    for event in ordered:
        count += 1
        highest_ts = max(highest_ts, event.ts)
        rid = event.record_id

        if rid not in fields:
            fields[rid] = {}
            pinyin[rid] = {}
            created[rid] = event.ts

        if event.op == OP_DEL:
            deleted[rid] = event.ts
            updated[rid] = event.ts
            last_device[rid] = event.device_uuid
            continue

        fields[rid].update(event.fields)
        pinyin[rid].update(event.pinyin)
        updated[rid] = event.ts
        last_device[rid] = event.device_uuid
        # Applying in sorted order means any set reaching here is later than an
        # earlier delete, so it resurrects the record (requirement 3.6).
        deleted.pop(rid, None)

    records = {
        rid: Record(
            id=rid,
            fields=dict(values),
            pinyin=dict(pinyin[rid]),
            created_at=created[rid],
            updated_at=updated[rid],
            last_device=last_device.get(rid, b""),
        )
        for rid, values in fields.items()
        if rid not in deleted
    }

    return FoldResult(
        records=records,
        deleted=dict(deleted),
        highest_ts=highest_ts,
        event_count=count,
    )
