"""Tests for the event model and fold (requirements 3.3, 3.5, 3.6, 3.7, 3.8)."""

from __future__ import annotations

import random
import uuid

import pytest

from pipassword import events as ev

DEV_A = bytes([0xAA] * 16)
DEV_B = bytes([0xBB] * 16)


def sev(rid, fields, ts, *, seq=0, dev=DEV_A, pinyin=None):
    return ev.make_set_event(
        rid, fields, ts=ts, seq=seq, device_uuid=dev, pinyin=pinyin
    )


def dev_(rid, ts, *, seq=0, dev=DEV_A):
    return ev.make_del_event(rid, ts=ts, seq=seq, device_uuid=dev)


# ------------------------------------------------------- hybrid logical clock


class TestHybridLogicalClock:
    """Requirement 3.5. Without this the merge model is unsound on a Pi."""

    def test_uses_wall_clock_when_it_is_ahead(self):
        assert ev.next_ts(highest_seen=1000, now_us=5000) == 5000

    def test_steps_past_highest_seen_when_clock_is_behind(self):
        assert ev.next_ts(highest_seen=5000, now_us=1000) == 5001

    def test_stale_clock_still_sorts_last(self):
        """The Beepy case: powered off for a week, fake-hwclock restores old time.

        The desktop's edit is at T. The Beepy's wall clock reads a week earlier.
        Its new edit must still win, because it happened later in real life.
        """
        one_week_us = 7 * 24 * 3600 * 1_000_000
        desktop_ts = 1_700_000_000_000_000
        beepy_wall_clock = desktop_ts - one_week_us

        desktop_edit = sev("r1", {"password": "from-desktop"}, desktop_ts, dev=DEV_B)

        beepy_ts = ev.next_ts(highest_seen=desktop_ts, now_us=beepy_wall_clock)
        beepy_edit = sev("r1", {"password": "from-beepy"}, beepy_ts, dev=DEV_A)

        assert beepy_ts > desktop_ts
        result = ev.fold([desktop_edit, beepy_edit])
        assert result.records["r1"].password == "from-beepy"

    def test_without_hlc_the_stale_edit_would_lose(self):
        """Demonstrates the bug the HLC prevents, by skipping the HLC."""
        desktop_ts = 1_700_000_000_000_000
        stale_ts = desktop_ts - 7 * 24 * 3600 * 1_000_000

        result = ev.fold(
            [
                sev("r1", {"password": "from-desktop"}, desktop_ts, dev=DEV_B),
                sev("r1", {"password": "from-beepy"}, stale_ts, dev=DEV_A),
            ]
        )
        assert result.records["r1"].password == "from-desktop"  # the wrong answer

    def test_monotonic_across_repeated_calls(self):
        seen = 0
        for _ in range(100):
            ts = ev.next_ts(seen, now_us=1000)
            assert ts > seen
            seen = ts

    def test_real_clock_is_usable(self):
        assert ev.next_ts(0) > 1_600_000_000_000_000

    def test_rejects_negative(self):
        with pytest.raises(ev.EventError):
            ev.next_ts(-1)

    def test_clock_is_behind_detection(self):
        assert ev.clock_is_behind(5000, now_us=1000)
        assert not ev.clock_is_behind(1000, now_us=5000)
        assert not ev.clock_is_behind(1000, now_us=1000)


# --------------------------------------------------------- encode and decode


class TestEncodeDecode:
    def test_roundtrip_set(self):
        original = sev("r1", {"name": "Google", "password": "p"}, 123, seq=7)
        decoded = ev.decode_event(ev.encode_event(original), DEV_A)
        assert decoded == original

    def test_roundtrip_del(self):
        original = dev_("r1", 456, seq=2)
        assert ev.decode_event(ev.encode_event(original), DEV_A) == original

    def test_roundtrip_cjk_and_pinyin(self):
        original = sev(
            "r1",
            {"name": "企业邮箱", "memo": "备用地址"},
            9,
            pinyin={"name": "qyyx qiyeyouxiang"},
        )
        decoded = ev.decode_event(ev.encode_event(original), DEV_A)
        assert decoded.fields["name"] == "企业邮箱"
        assert decoded.pinyin["name"] == "qyyx qiyeyouxiang"

    def test_device_uuid_is_not_in_the_payload(self):
        """It comes from the log header, so it cannot be forged separately."""
        payload = ev.encode_event(sev("r1", {"name": "x"}, 1))
        assert DEV_A.hex() not in payload.decode()
        assert ev.decode_event(payload, DEV_B).device_uuid == DEV_B

    def test_encoding_is_byte_stable(self):
        e = sev("r1", {"name": "a", "password": "b"}, 1)
        assert ev.encode_event(e) == ev.encode_event(e)

    def test_legacy_id_survives(self):
        decoded = ev.decode_event(
            ev.encode_event(sev("r1", {"name": "x", "legacy_id": 42}, 1)), DEV_A
        )
        assert decoded.fields["legacy_id"] == 42

    @pytest.mark.parametrize(
        "payload",
        [
            b"not json",
            b"[]",
            b'{"op":"nope","id":"r","ts":1}',
            b'{"op":"set","ts":1}',
            b'{"op":"set","id":"","ts":1,"f":{"name":"x"}}',
            b'{"op":"set","id":"r","ts":-1,"f":{"name":"x"}}',
            b'{"op":"set","id":"r","ts":"x","f":{"name":"x"}}',
            b'{"op":"set","id":"r","ts":1,"seq":-1,"f":{"name":"x"}}',
            b'{"op":"set","id":"r","ts":1}',
            b'{"op":"set","id":"r","ts":1,"f":{}}',
            b'{"op":"del","id":"r","ts":1,"f":{"name":"x"}}',
            b'{"op":"set","id":"r","ts":1,"f":{"nmae":"typo"}}',
            b'{"op":"set","id":"r","ts":1,"f":"notanobject"}',
        ],
        ids=[
            "not-json",
            "not-object",
            "bad-op",
            "no-id",
            "empty-id",
            "negative-ts",
            "string-ts",
            "negative-seq",
            "set-without-fields",
            "set-with-empty-fields",
            "del-with-fields",
            "unknown-field",
            "fields-not-object",
        ],
    )
    def test_malformed_payloads_rejected(self, payload):
        with pytest.raises(ev.EventError):
            ev.decode_event(payload, DEV_A)

    def test_boolean_is_not_accepted_as_ts(self):
        """bool is a subclass of int; it must not sneak through."""
        with pytest.raises(ev.EventError):
            ev.decode_event(b'{"op":"set","id":"r","ts":true,"f":{"name":"x"}}', DEV_A)

    def test_make_set_rejects_unknown_field(self):
        with pytest.raises(ev.EventError, match="unknown field"):
            sev("r1", {"nonsense": 1}, 1)

    def test_make_set_rejects_empty(self):
        with pytest.raises(ev.EventError, match="at least one field"):
            sev("r1", {}, 1)


# ----------------------------------------------------------------- folding


class TestFoldBasics:
    def test_empty(self):
        result = ev.fold([])
        assert result.records == {}
        assert result.highest_ts == 0
        assert result.event_count == 0

    def test_single_record(self):
        result = ev.fold([sev("r1", {"name": "Google", "password": "p"}, 100)])
        record = result.records["r1"]
        assert record.name == "Google"
        assert record.password == "p"
        assert record.created_at == 100
        assert record.updated_at == 100

    def test_later_event_updates_fields(self):
        result = ev.fold(
            [
                sev("r1", {"name": "Google", "password": "old"}, 100),
                sev("r1", {"password": "new"}, 200),
            ]
        )
        assert result.records["r1"].password == "new"
        assert result.records["r1"].name == "Google"  # untouched field survives
        assert result.records["r1"].created_at == 100
        assert result.records["r1"].updated_at == 200

    def test_highest_ts_is_reported(self):
        result = ev.fold([sev("r1", {"name": "a"}, 5), sev("r2", {"name": "b"}, 99)])
        assert result.highest_ts == 99

    def test_accessors_default_to_empty(self):
        record = ev.fold([sev("r1", {"name": "only"}, 1)]).records["r1"]
        assert record.login == ""
        assert record.memo == ""
        assert record.totp == ""
        assert record.legacy_id is None
        assert record.get("missing", "fallback") == "fallback"


class TestFieldLevelMerge:
    """Requirement 3.6, and the property that makes multi-device editing safe."""

    def test_concurrent_edits_to_different_fields_both_survive(self):
        """The scenario from the design discussion, as a test.

        Beepy changes the password while offline; the Pi edits the memo. Both
        edits must be present after sync.
        """
        result = ev.fold(
            [
                sev("r1", {"name": "Bank", "password": "p1", "memo": "m1"}, 100),
                sev("r1", {"password": "from-beepy"}, 200, dev=DEV_A),
                sev("r1", {"memo": "from-pi"}, 201, dev=DEV_B),
            ]
        )
        record = result.records["r1"]
        assert record.password == "from-beepy"
        assert record.memo == "from-pi"
        assert record.name == "Bank"

    def test_same_field_last_write_wins(self):
        result = ev.fold(
            [
                sev("r1", {"name": "x", "password": "a"}, 100),
                sev("r1", {"password": "b"}, 300, dev=DEV_B),
                sev("r1", {"password": "c"}, 200, dev=DEV_A),
            ]
        )
        assert result.records["r1"].password == "b"

    def test_superseded_value_remains_in_the_event_stream(self):
        """Requirement 3.7: shadowed values stay recoverable from history."""
        stream = [
            sev("r1", {"name": "x", "password": "old"}, 100),
            sev("r1", {"password": "new"}, 200),
        ]
        assert ev.fold(stream).records["r1"].password == "new"
        assert any(e.fields.get("password") == "old" for e in stream)


class TestDeterminism:
    """Requirement 3.3: every device computes identical state."""

    def _stream(self):
        stream = []
        ts = 1000
        for i in range(40):
            ts += 10
            dev = DEV_A if i % 2 else DEV_B
            rid = f"r{i % 7}"
            stream.append(sev(rid, {"name": f"n{i}", "password": f"p{i}"}, ts, dev=dev))
            if i % 11 == 0:
                ts += 1
                stream.append(dev_(rid, ts, dev=dev))
        return stream

    def test_shuffled_arrival_order_yields_identical_state(self):
        stream = self._stream()
        baseline = ev.fold(stream)

        for seed in range(25):
            shuffled = stream[:]
            random.Random(seed).shuffle(shuffled)
            result = ev.fold(shuffled)
            assert result.records.keys() == baseline.records.keys()
            for rid, record in baseline.records.items():
                assert result.records[rid].fields == record.fields
                assert result.records[rid].updated_at == record.updated_at
            assert result.deleted == baseline.deleted

    def test_split_across_logs_yields_identical_state(self):
        """Reading log A then B must equal reading B then A."""
        stream = self._stream()
        a = [e for e in stream if e.device_uuid == DEV_A]
        b = [e for e in stream if e.device_uuid == DEV_B]
        assert ev.fold(a + b).records.keys() == ev.fold(b + a).records.keys()
        for rid, record in ev.fold(a + b).records.items():
            assert ev.fold(b + a).records[rid].fields == record.fields

    def test_timestamp_ties_broken_consistently_by_device(self):
        """Equal timestamps must not make the result depend on input order."""
        forward = ev.fold(
            [
                sev("r1", {"name": "x", "password": "from-a"}, 500, dev=DEV_A),
                sev("r1", {"password": "from-b"}, 500, dev=DEV_B),
            ]
        )
        backward = ev.fold(
            [
                sev("r1", {"password": "from-b"}, 500, dev=DEV_B),
                sev("r1", {"name": "x", "password": "from-a"}, 500, dev=DEV_A),
            ]
        )
        assert forward.records["r1"].password == backward.records["r1"].password
        assert forward.records["r1"].password == "from-b"  # DEV_B > DEV_A

    def test_seq_breaks_ties_within_one_device(self):
        result = ev.fold(
            [
                sev("r1", {"name": "x", "password": "second"}, 500, seq=2),
                sev("r1", {"password": "first"}, 500, seq=1),
            ]
        )
        assert result.records["r1"].password == "second"


class TestTombstones:
    """Requirement 3.8."""

    def test_delete_removes_from_records(self):
        result = ev.fold([sev("r1", {"name": "x"}, 100), dev_("r1", 200)])
        assert "r1" not in result.records
        assert result.deleted["r1"] == 200

    def test_delete_before_set_does_not_remove(self):
        result = ev.fold([dev_("r1", 100), sev("r1", {"name": "x"}, 200)])
        assert "r1" in result.records
        assert "r1" not in result.deleted

    def test_set_after_delete_resurrects(self):
        result = ev.fold(
            [
                sev("r1", {"name": "x", "password": "p"}, 100),
                dev_("r1", 200),
                sev("r1", {"password": "revived"}, 300),
            ]
        )
        assert result.records["r1"].password == "revived"
        assert result.records["r1"].name == "x"  # fields were not lost
        assert "r1" not in result.deleted

    def test_delete_on_one_device_while_other_edits(self):
        """A delete that arrives last wins; the edit is still in history."""
        result = ev.fold(
            [
                sev("r1", {"name": "x", "password": "p"}, 100),
                sev("r1", {"password": "edited"}, 200, dev=DEV_A),
                dev_("r1", 300, dev=DEV_B),
            ]
        )
        assert "r1" not in result.records
        assert result.deleted["r1"] == 300

    def test_edit_after_remote_delete_resurrects(self):
        result = ev.fold(
            [
                sev("r1", {"name": "x"}, 100),
                dev_("r1", 200, dev=DEV_B),
                sev("r1", {"password": "still-want-this"}, 300, dev=DEV_A),
            ]
        )
        assert result.records["r1"].password == "still-want-this"

    def test_delete_of_unknown_record_is_harmless(self):
        result = ev.fold([dev_("never-existed", 100)])
        assert result.records == {}
        assert result.deleted["never-existed"] == 100

    def test_repeated_deletes_are_idempotent(self):
        result = ev.fold(
            [sev("r1", {"name": "x"}, 100), dev_("r1", 200), dev_("r1", 300)]
        )
        assert "r1" not in result.records
        assert result.deleted["r1"] == 300


class TestScale:
    def test_ten_thousand_records_fold(self):
        """Requirement 3.14's data volume, folded."""
        stream = []
        for i in range(10_000):
            stream.append(
                sev(
                    f"r{i}",
                    {"name": f"entry {i}", "password": f"pw{i}"},
                    1000 + i,
                    dev=DEV_A if i % 2 else DEV_B,
                )
            )
        result = ev.fold(stream)
        assert len(result.records) == 10_000
        assert result.event_count == 10_000
        assert result.records["r9999"].name == "entry 9999"


class TestRecordId:
    def test_ids_are_unique_uuids(self):
        ids = {ev.new_record_id() for _ in range(1000)}
        assert len(ids) == 1000
        uuid.UUID(ids.pop())  # parses
