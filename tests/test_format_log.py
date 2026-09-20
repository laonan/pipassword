"""Tests for the log file format (requirements 2.9, 3.9, 3.10)."""

from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path

import pytest

from pipassword import crypto, format as fmt


@pytest.fixture
def dek():
    return crypto.generate_dek()


@pytest.fixture
def ids():
    return uuid.uuid4().bytes, uuid.uuid4().bytes


@pytest.fixture
def log(vault_dir: Path, ids):
    vault_uuid, device_uuid = ids
    path = vault_dir / "log" / fmt.log_filename("beepy", device_uuid)
    fmt.create_log(path, vault_uuid, device_uuid)
    return path


class TestHeader:
    def test_size_and_layout(self, ids):
        vault_uuid, device_uuid = ids
        raw = fmt.encode_log_header(vault_uuid, device_uuid)
        assert len(raw) == fmt.LOG_HEADER_SIZE == 42
        assert raw[0:8] == b"PIPWLOG\x00"
        assert struct.unpack_from("<H", raw, 8)[0] == 1
        assert raw[10:26] == vault_uuid
        assert raw[26:42] == device_uuid

    def test_roundtrip(self, ids):
        vault_uuid, device_uuid = ids
        header = fmt.decode_log_header(
            fmt.encode_log_header(vault_uuid, device_uuid)
        )
        assert header.vault_uuid == vault_uuid
        assert header.device_uuid == device_uuid
        assert header.vault_uuid_str == str(uuid.UUID(bytes=vault_uuid))

    def test_bad_magic(self, ids):
        raw = bytearray(fmt.encode_log_header(*ids))
        raw[0:8] = b"XXXXXXXX"
        with pytest.raises(fmt.LogFormatError, match="bad magic"):
            fmt.decode_log_header(bytes(raw))

    def test_future_version(self, ids):
        raw = bytearray(fmt.encode_log_header(*ids))
        struct.pack_into("<H", raw, 8, 77)
        with pytest.raises(fmt.UnsupportedVersionError, match="upgrade"):
            fmt.decode_log_header(bytes(raw))

    def test_short_data(self):
        with pytest.raises(fmt.LogFormatError, match="42 bytes"):
            fmt.decode_log_header(b"short")

    def test_rejects_bad_uuid_lengths(self):
        with pytest.raises(fmt.LogFormatError, match="vault_uuid"):
            fmt.encode_log_header(b"x", uuid.uuid4().bytes)
        with pytest.raises(fmt.LogFormatError, match="device_uuid"):
            fmt.encode_log_header(uuid.uuid4().bytes, b"x")


class TestFilename:
    def test_includes_device_prefix(self):
        device_uuid = uuid.uuid4().bytes
        name = fmt.log_filename("beepy", device_uuid)
        assert name.endswith(".mpl")
        assert device_uuid.hex()[:8] in name
        assert name.startswith("beepy-")

    def test_sanitises_hostname(self):
        name = fmt.log_filename("Alan's Pi 4!! / prod", uuid.uuid4().bytes)
        stem = name[: name.index(".mpl")]
        assert set(stem) <= set("abcdefghijklmnopqrstuvwxyz0123456789-_")

    def test_empty_name_falls_back(self):
        assert fmt.log_filename("!!!", uuid.uuid4().bytes).startswith("device-")


class TestCreateLog:
    def test_creates_with_header_only(self, log: Path):
        assert log.stat().st_size == fmt.LOG_HEADER_SIZE

    def test_is_idempotent(self, log: Path, ids):
        header = fmt.create_log(log, *ids)
        assert header.device_uuid == ids[1]
        assert log.stat().st_size == fmt.LOG_HEADER_SIZE

    def test_rejects_wrong_vault(self, log: Path, ids):
        with pytest.raises(fmt.LogFormatError, match="belongs to vault"):
            fmt.create_log(log, uuid.uuid4().bytes, ids[1])

    def test_rejects_wrong_device(self, log: Path, ids):
        """Catches a duplicated device id, the one way requirement 3.2 can break."""
        with pytest.raises(fmt.LogFormatError, match="belongs to device"):
            fmt.create_log(log, ids[0], uuid.uuid4().bytes)


class TestAppendAndRead:
    def test_roundtrip_single_frame(self, log: Path, dek):
        fmt.append_frame(log, dek, b"first event")
        result = fmt.read_log(log, dek)
        assert result.payloads == [b"first event"]
        assert result.ok

    def test_roundtrip_many_frames(self, log: Path, dek):
        payloads = [f"event {i}".encode() for i in range(200)]
        for payload in payloads:
            fmt.append_frame(log, dek, payload)
        result = fmt.read_log(log, dek)
        assert result.payloads == payloads
        assert result.ok

    def test_batch_append_matches_individual(self, log: Path, dek):
        payloads = [b"a", b"b", b"c"]
        fmt.append_frames(log, dek, payloads)
        assert fmt.read_log(log, dek).payloads == payloads

    def test_append_is_additive(self, log: Path, dek):
        fmt.append_frame(log, dek, b"one")
        size_after_one = log.stat().st_size
        fmt.append_frame(log, dek, b"two")
        assert log.stat().st_size > size_after_one
        assert fmt.read_log(log, dek).payloads == [b"one", b"two"]

    def test_empty_log_reads_as_empty(self, log: Path, dek):
        result = fmt.read_log(log, dek)
        assert result.payloads == []
        assert result.ok
        assert result.valid_end == fmt.LOG_HEADER_SIZE

    def test_empty_payload_is_allowed(self, log: Path, dek):
        fmt.append_frame(log, dek, b"")
        assert fmt.read_log(log, dek).payloads == [b""]

    def test_appending_nothing_writes_nothing(self, log: Path, dek):
        assert fmt.append_frames(log, dek, []) == 0
        assert log.stat().st_size == fmt.LOG_HEADER_SIZE

    def test_unicode_payload(self, log: Path, dek):
        payload = "企业邮箱 · mail.corp.cn".encode()
        fmt.append_frame(log, dek, payload)
        assert fmt.read_log(log, dek).payloads == [payload]

    def test_oversized_frame_rejected(self, log: Path, dek):
        with pytest.raises(fmt.LogFormatError, match="exceeds"):
            fmt.append_frame(log, dek, b"x" * (fmt.MAX_FRAME_SIZE + 1))

    def test_wrong_key_reports_every_frame(self, log: Path, dek):
        fmt.append_frames(log, dek, [b"a", b"b", b"c"])
        result = fmt.read_log(log, crypto.generate_dek())
        assert result.payloads == []
        assert len(result.anomalies) == 3
        assert all(a.kind == "auth_failed" for a in result.anomalies)


class TestFrameBinding:
    """Requirement 2.9: a frame is bound to its vault, its device, and its length."""

    def test_frame_cannot_be_moved_to_another_device_log(
        self, vault_dir: Path, dek, ids
    ):
        vault_uuid, device_a = ids
        device_b = uuid.uuid4().bytes

        log_a = vault_dir / "log" / fmt.log_filename("a", device_a)
        log_b = vault_dir / "log" / fmt.log_filename("b", device_b)
        fmt.create_log(log_a, vault_uuid, device_a)
        fmt.create_log(log_b, vault_uuid, device_b)

        fmt.append_frame(log_a, dek, b"secret event")
        frame = log_a.read_bytes()[fmt.LOG_HEADER_SIZE :]

        with open(log_b, "ab") as handle:  # transplant it
            handle.write(frame)

        result = fmt.read_log(log_b, dek)
        assert result.payloads == []
        assert result.anomalies[0].kind == "auth_failed"

    def test_frame_cannot_be_moved_to_another_vault(self, vault_dir: Path, dek, ids):
        _, device_uuid = ids
        log_a = vault_dir / "log" / "a.mpl"
        log_b = vault_dir / "log" / "b.mpl"
        fmt.create_log(log_a, uuid.uuid4().bytes, device_uuid)
        fmt.create_log(log_b, uuid.uuid4().bytes, device_uuid)

        fmt.append_frame(log_a, dek, b"event")
        with open(log_b, "ab") as handle:
            handle.write(log_a.read_bytes()[fmt.LOG_HEADER_SIZE :])

        assert fmt.read_log(log_b, dek).anomalies[0].kind == "auth_failed"

    def test_tampering_with_ciphertext_is_detected(self, log: Path, dek):
        fmt.append_frame(log, dek, b"event")
        data = bytearray(log.read_bytes())
        data[-1] ^= 0x01
        log.write_bytes(bytes(data))
        assert fmt.read_log(log, dek).anomalies[0].kind == "auth_failed"

    def test_rewriting_the_length_prefix_is_detected(self, log: Path, dek):
        """The length is in the AAD, so a frame cannot be silently re-cut."""
        fmt.append_frame(log, dek, b"event payload here")
        data = bytearray(log.read_bytes())
        (original,) = struct.unpack_from("<I", data, fmt.LOG_HEADER_SIZE)
        struct.pack_into("<I", data, fmt.LOG_HEADER_SIZE, original - 1)
        log.write_bytes(bytes(data[:-1]))
        result = fmt.read_log(log, dek)
        assert result.payloads == []
        assert result.anomalies

    def test_header_tampering_changes_frame_aad(self, log: Path, dek, ids):
        """Rewriting the device UUID in the header invalidates every frame."""
        fmt.append_frame(log, dek, b"event")
        data = bytearray(log.read_bytes())
        data[26:42] = uuid.uuid4().bytes
        log.write_bytes(bytes(data))
        assert fmt.read_log(log, dek).anomalies[0].kind == "auth_failed"


class TestTruncationRecovery:
    """Requirement 3.9: a power cut on a battery handheld costs one frame."""

    def test_every_truncation_offset_is_survivable(self, log: Path, dek):
        """The headline test: truncate at every byte offset, never crash, never lie.

        At any offset, whatever frames were complete must still load, and the
        count must never exceed what was actually written.
        """
        payloads = [f"event-{i:03d}".encode() for i in range(25)]
        fmt.append_frames(log, dek, payloads)
        full = log.read_bytes()

        for cut in range(fmt.LOG_HEADER_SIZE, len(full) + 1):
            log.write_bytes(full[:cut])
            result = fmt.read_log(log, dek)

            assert result.payloads == payloads[: len(result.payloads)], (
                f"at cut={cut} the recovered prefix does not match what was written"
            )
            assert len(result.payloads) <= len(payloads)
            if cut < len(full):
                assert len(result.payloads) < len(payloads)

    def test_recovers_all_complete_frames_after_partial_append(self, log: Path, dek):
        fmt.append_frames(log, dek, [b"one", b"two"])
        complete = log.read_bytes()
        with open(log, "ab") as handle:  # simulate a half-written third frame
            handle.write(struct.pack("<I", 40) + b"\x00" * 9)

        result = fmt.read_log(log, dek)
        assert result.payloads == [b"one", b"two"]
        assert result.anomalies[0].kind == "truncated"
        assert result.valid_end == len(complete)

    def test_stray_bytes_shorter_than_a_length_prefix(self, log: Path, dek):
        fmt.append_frame(log, dek, b"one")
        with open(log, "ab") as handle:
            handle.write(b"\x01\x02")
        result = fmt.read_log(log, dek)
        assert result.payloads == [b"one"]
        assert result.anomalies[0].kind == "truncated"
        assert "length prefix" in result.anomalies[0].detail

    def test_implausible_length_stops_the_scan(self, log: Path, dek):
        fmt.append_frame(log, dek, b"one")
        with open(log, "ab") as handle:
            handle.write(struct.pack("<I", 0xFFFFFF0) + b"\x00" * 32)
        result = fmt.read_log(log, dek)
        assert result.payloads == [b"one"]
        assert result.anomalies[0].kind == "bad_length"

    def test_zero_length_frame_is_implausible(self, log: Path, dek):
        with open(log, "ab") as handle:
            handle.write(struct.pack("<I", 0))
        assert fmt.read_log(log, dek).anomalies[0].kind == "bad_length"

    def test_corrupt_middle_frame_does_not_hide_later_frames(self, log: Path, dek):
        """Explicit lengths mean one bad frame costs one frame, not the tail."""
        fmt.append_frames(log, dek, [b"first", b"second", b"third"])
        data = bytearray(log.read_bytes())

        first_len = struct.unpack_from("<I", data, fmt.LOG_HEADER_SIZE)[0]
        second_start = fmt.LOG_HEADER_SIZE + 4 + first_len
        data[second_start + 4 + crypto.NONCE_SIZE] ^= 0xFF  # corrupt frame 2's ct
        log.write_bytes(bytes(data))

        result = fmt.read_log(log, dek)
        assert result.payloads == [b"first", b"third"]
        assert len(result.anomalies) == 1
        assert result.anomalies[0].kind == "auth_failed"


class TestRepair:
    def test_clean_log_is_untouched(self, log: Path, dek):
        fmt.append_frames(log, dek, [b"a", b"b"])
        before = log.read_bytes()
        discarded, anomalies = fmt.repair_log(log, dek)
        assert discarded == 0
        assert anomalies == []
        assert log.read_bytes() == before

    def test_truncated_tail_is_discarded(self, log: Path, dek):
        fmt.append_frames(log, dek, [b"a", b"b"])
        good = log.read_bytes()
        with open(log, "ab") as handle:
            handle.write(struct.pack("<I", 100) + b"\x00" * 10)

        discarded, anomalies = fmt.repair_log(log, dek)
        assert discarded == 14
        assert anomalies
        assert log.read_bytes() == good
        assert fmt.read_log(log, dek).ok

    def test_repair_is_idempotent(self, log: Path, dek):
        fmt.append_frame(log, dek, b"a")
        with open(log, "ab") as handle:
            handle.write(b"\x00\x01\x02")
        fmt.repair_log(log, dek)
        assert fmt.repair_log(log, dek) == (0, [])

    def test_refuses_to_discard_valid_data_after_a_bad_frame(self, log: Path, dek):
        """Truncating here would throw away good frames to tidy a corrupt one."""
        fmt.append_frames(log, dek, [b"first", b"second", b"third"])
        data = bytearray(log.read_bytes())
        first_len = struct.unpack_from("<I", data, fmt.LOG_HEADER_SIZE)[0]
        second_start = fmt.LOG_HEADER_SIZE + 4 + first_len
        data[second_start + 4 + crypto.NONCE_SIZE] ^= 0xFF
        log.write_bytes(bytes(data))
        size_before = log.stat().st_size

        discarded, anomalies = fmt.repair_log(log, dek)
        assert discarded == 0
        assert anomalies
        assert log.stat().st_size == size_before
        assert fmt.read_log(log, dek).payloads == [b"first", b"third"]


class TestFindLogs:
    def test_finds_only_mpl_files_sorted(self, vault_dir: Path, ids):
        log_dir = vault_dir / "log"
        for name in ["b.mpl", "a.mpl", "c.txt"]:
            (log_dir / name).write_bytes(b"")
        (log_dir / "sub").mkdir()
        assert [p.name for p in fmt.find_logs(log_dir)] == ["a.mpl", "b.mpl"]

    def test_missing_directory_is_empty(self, vault_dir: Path):
        assert fmt.find_logs(vault_dir / "absent") == []


class TestDurability:
    def test_append_fsyncs(self, log: Path, dek, monkeypatch):
        """An append that is not fsynced can vanish on power loss."""
        synced = []
        real_fsync = os.fsync
        monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd)))
        fmt.append_frame(log, dek, b"durable")
        assert synced, "append_frames did not fsync"
