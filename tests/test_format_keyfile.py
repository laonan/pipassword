"""Tests for the keyfile format (requirements 2.3, 2.5, 2.7, 2.9, 2.12, 6.2, 6.6)."""

from __future__ import annotations

import os
import stat
import struct
import uuid
from pathlib import Path

import pytest

from pipassword import crypto, format as fmt

# Cheap parameters. Key derivation correctness is covered in test_crypto.py; these
# tests are about layout and file handling, so there is no reason to burn 64 MiB.
FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)
PASSWORD = "correct horse battery staple"


@pytest.fixture
def made(vault_dir: Path):
    """A created vault keyfile plus the material needed to assert against it."""
    dek = crypto.generate_dek()
    recovery_key = crypto.generate_recovery_key()
    keyfile, returned_recovery = fmt.create_keyfile(
        vault_dir,
        PASSWORD,
        params=FAST,
        dek=dek,
        recovery_key=recovery_key,
        check_memory=False,
    )
    assert returned_recovery == recovery_key
    return keyfile, dek, recovery_key


# ------------------------------------------------------------------ layout


class TestLayout:
    def test_encoded_size_matches_spec(self):
        encoded = fmt.encode_keyfile(
            vault_uuid=uuid.uuid4().bytes,
            generation=1,
            params=FAST,
            salt=crypto.generate_salt(),
            dek=crypto.generate_dek(),
            password=PASSWORD,
            recovery_key=crypto.generate_recovery_key(),
        )
        assert len(encoded) == fmt.KEYFILE_SIZE == 174

    def test_magic_and_version_at_documented_offsets(self):
        encoded = fmt.encode_keyfile(
            vault_uuid=uuid.uuid4().bytes,
            generation=7,
            params=FAST,
            salt=crypto.generate_salt(),
            dek=crypto.generate_dek(),
            password=PASSWORD,
        )
        assert encoded[0:8] == b"PIPWKEY\x00"
        assert struct.unpack_from("<H", encoded, 8)[0] == 1
        assert struct.unpack_from("<I", encoded, 26)[0] == 7

    def test_roundtrip_preserves_every_field(self):
        vault_uuid = uuid.uuid4().bytes
        salt = crypto.generate_salt()
        params = crypto.KdfParams(time_cost=2, memory_cost_kib=1024, parallelism=3)

        decoded = fmt.decode_keyfile(
            fmt.encode_keyfile(
                vault_uuid=vault_uuid,
                generation=42,
                params=params,
                salt=salt,
                dek=crypto.generate_dek(),
                password=PASSWORD,
                recovery_key=crypto.generate_recovery_key(),
            )
        )
        assert decoded.vault_uuid == vault_uuid
        assert decoded.generation == 42
        assert decoded.params == params
        assert decoded.salt == salt
        assert decoded.has_password_slot
        assert decoded.has_recovery_slot
        assert decoded.vault_uuid_str == str(uuid.UUID(bytes=vault_uuid))

    def test_params_survive_the_round_trip(self):
        """Requirement 2.3: parameters travel with the vault, not with the device."""
        params = crypto.KdfParams(time_cost=5, memory_cost_kib=131072, parallelism=2)
        decoded = fmt.decode_keyfile(
            fmt.encode_keyfile(
                vault_uuid=uuid.uuid4().bytes,
                generation=1,
                params=params,
                salt=crypto.generate_salt(),
                dek=crypto.generate_dek(),
                password=PASSWORD,
            )
        )
        assert decoded.params.time_cost == 5
        assert decoded.params.memory_cost_kib == 131072
        assert decoded.params.memory_cost_mib == 128
        assert decoded.params.parallelism == 2


class TestDecodeRejectsMalformed:
    def _valid(self) -> bytes:
        return fmt.encode_keyfile(
            vault_uuid=uuid.uuid4().bytes,
            generation=1,
            params=FAST,
            salt=crypto.generate_salt(),
            dek=crypto.generate_dek(),
            password=PASSWORD,
            recovery_key=crypto.generate_recovery_key(),
        )

    def test_bad_magic(self):
        data = bytearray(self._valid())
        data[0:8] = b"NOTAKEY\x00"
        with pytest.raises(fmt.MagicMismatchError):
            fmt.decode_keyfile(bytes(data))

    def test_future_version_names_the_problem(self):
        data = bytearray(self._valid())
        struct.pack_into("<H", data, 8, 99)
        with pytest.raises(fmt.UnsupportedVersionError, match="upgrade pipassword"):
            fmt.decode_keyfile(bytes(data))

    def test_unknown_kdf_id(self):
        data = bytearray(self._valid())
        data[30] = 9
        with pytest.raises(fmt.UnsupportedVersionError, match="KDF id"):
            fmt.decode_keyfile(bytes(data))

    @pytest.mark.parametrize("size", [0, 173, 175, 500])
    def test_wrong_length(self, size):
        with pytest.raises(fmt.FormatError, match="174 bytes"):
            fmt.decode_keyfile(bytes(size))

    def test_no_slots_declared(self):
        data = bytearray(self._valid())
        data[53] = 0
        with pytest.raises(fmt.FormatError, match="no usable slots"):
            fmt.decode_keyfile(bytes(data))

    def test_invalid_kdf_params_reported_as_format_error(self):
        """A corrupt time_cost of zero must not surface as a bare ParameterError."""
        data = bytearray(self._valid())
        data[35] = 0
        with pytest.raises(fmt.FormatError, match="invalid KDF parameters"):
            fmt.decode_keyfile(bytes(data))


class TestEncodeValidation:
    def _kwargs(self, **over):
        base = dict(
            vault_uuid=uuid.uuid4().bytes,
            generation=1,
            params=FAST,
            salt=crypto.generate_salt(),
            dek=crypto.generate_dek(),
            password=PASSWORD,
        )
        base.update(over)
        return base

    def test_rejects_short_uuid(self):
        with pytest.raises(fmt.FormatError, match="vault_uuid"):
            fmt.encode_keyfile(**self._kwargs(vault_uuid=b"short"))

    def test_rejects_bad_salt(self):
        with pytest.raises(fmt.FormatError, match="salt"):
            fmt.encode_keyfile(**self._kwargs(salt=bytes(8)))

    def test_rejects_bad_dek(self):
        with pytest.raises(fmt.FormatError, match="dek"):
            fmt.encode_keyfile(**self._kwargs(dek=bytes(16)))

    def test_rejects_time_cost_above_one_byte(self):
        params = crypto.KdfParams(time_cost=256, memory_cost_kib=1024, parallelism=1)
        with pytest.raises(fmt.FormatError, match="one byte"):
            fmt.encode_keyfile(**self._kwargs(params=params))

    def test_rejects_parallelism_above_one_byte(self):
        params = crypto.KdfParams(
            time_cost=1, memory_cost_kib=1024 * 8, parallelism=256
        )
        with pytest.raises(fmt.FormatError, match="one byte"):
            fmt.encode_keyfile(**self._kwargs(params=params))

    def test_rejects_no_slots(self):
        with pytest.raises(fmt.FormatError, match="at least one slot"):
            fmt.encode_keyfile(**self._kwargs(password=None))

    def test_rejects_both_recovery_inputs(self):
        with pytest.raises(fmt.FormatError, match="not both"):
            fmt.encode_keyfile(
                **self._kwargs(
                    recovery_key=crypto.generate_recovery_key(),
                    recovery_slot=(crypto.generate_nonce(), bytes(48)),
                )
            )


# ------------------------------------------------------------- unwrap and AAD


class TestUnwrap:
    def test_password_unwraps_dek(self, made):
        keyfile, dek, _ = made
        assert keyfile.unwrap_with_password(PASSWORD, check_memory=False) == dek

    def test_recovery_key_unwraps_dek(self, made):
        """Requirement 6.2: the paper key reaches the DEK independently."""
        keyfile, dek, recovery_key = made
        assert keyfile.unwrap_with_recovery_key(recovery_key) == dek

    def test_both_slots_yield_the_same_dek(self, made):
        keyfile, _, recovery_key = made
        assert keyfile.unwrap_with_password(
            PASSWORD, check_memory=False
        ) == keyfile.unwrap_with_recovery_key(recovery_key)

    def test_wrong_password_fails(self, made):
        keyfile, _, _ = made
        with pytest.raises(crypto.AuthenticationError):
            keyfile.unwrap_with_password("wrong password", check_memory=False)

    def test_wrong_recovery_key_fails(self, made):
        keyfile, _, _ = made
        with pytest.raises(crypto.AuthenticationError):
            keyfile.unwrap_with_recovery_key(crypto.generate_recovery_key())

    def test_transcribed_recovery_key_works(self, made):
        """The realistic path: read the grouped Base32 off paper and type it back."""
        keyfile, dek, recovery_key = made
        printed = crypto.format_recovery_key(recovery_key)
        typed = printed.lower().replace("-", " ")
        assert keyfile.unwrap_with_recovery_key(crypto.parse_recovery_key(typed)) == dek

    def test_missing_slot_is_reported(self):
        keyfile = fmt.decode_keyfile(
            fmt.encode_keyfile(
                vault_uuid=uuid.uuid4().bytes,
                generation=1,
                params=FAST,
                salt=crypto.generate_salt(),
                dek=crypto.generate_dek(),
                password=PASSWORD,
            )
        )
        assert not keyfile.has_recovery_slot
        with pytest.raises(fmt.FormatError, match="no recovery slot"):
            keyfile.unwrap_with_recovery_key(crypto.generate_recovery_key())


class TestKdfDowngradeIsImpossible:
    """Requirement 2.9. The headline property of the AAD binding.

    Without it, an attacker with write access could rewrite memory_cost to something
    trivial, and the vault would still open — turning a memory-hard KDF into a cheap
    one and making offline brute force far easier.
    """

    @pytest.fixture
    def encoded(self):
        return fmt.encode_keyfile(
            vault_uuid=uuid.uuid4().bytes,
            generation=1,
            params=crypto.KdfParams(
                time_cost=2, memory_cost_kib=1024, parallelism=1
            ),
            salt=crypto.generate_salt(),
            dek=crypto.generate_dek(),
            password=PASSWORD,
            recovery_key=crypto.generate_recovery_key(),
        )

    def test_lowering_memory_cost_fails_authentication(self, encoded):
        data = bytearray(encoded)
        struct.pack_into("<I", data, 31, 8)  # 1 MiB -> 8 KiB
        keyfile = fmt.decode_keyfile(bytes(data))
        assert keyfile.params.memory_cost_kib == 8  # the field did change
        with pytest.raises(crypto.AuthenticationError):
            keyfile.unwrap_with_password(PASSWORD, check_memory=False)

    def test_lowering_time_cost_fails_authentication(self, encoded):
        data = bytearray(encoded)
        data[35] = 1
        with pytest.raises(crypto.AuthenticationError):
            fmt.decode_keyfile(bytes(data)).unwrap_with_password(
                PASSWORD, check_memory=False
            )

    def test_changing_parallelism_fails_authentication(self, encoded):
        data = bytearray(encoded)
        data[36] = 4
        with pytest.raises(crypto.AuthenticationError):
            fmt.decode_keyfile(bytes(data)).unwrap_with_password(
                PASSWORD, check_memory=False
            )

    def test_changing_salt_fails_authentication(self, encoded):
        data = bytearray(encoded)
        data[37:53] = bytes(16)
        with pytest.raises(crypto.AuthenticationError):
            fmt.decode_keyfile(bytes(data)).unwrap_with_password(
                PASSWORD, check_memory=False
            )

    def test_changing_generation_fails_password_slot(self, encoded):
        data = bytearray(encoded)
        struct.pack_into("<I", data, 26, 99)
        with pytest.raises(crypto.AuthenticationError):
            fmt.decode_keyfile(bytes(data)).unwrap_with_password(
                PASSWORD, check_memory=False
            )

    def test_changing_vault_uuid_fails_both_slots(self, encoded):
        data = bytearray(encoded)
        data[10:26] = uuid.uuid4().bytes
        keyfile = fmt.decode_keyfile(bytes(data))
        with pytest.raises(crypto.AuthenticationError):
            keyfile.unwrap_with_password(PASSWORD, check_memory=False)

    def test_slots_bitfield_is_authenticated(self, encoded):
        """Flipping the bitfield must not be a way to strip a slot silently."""
        data = bytearray(encoded)
        data[53] = fmt.SLOT_PASSWORD | fmt.SLOT_RECOVERY | 0b100
        with pytest.raises(crypto.AuthenticationError):
            fmt.decode_keyfile(bytes(data)).unwrap_with_password(
                PASSWORD, check_memory=False
            )

    def test_slots_cannot_be_swapped(self, encoded):
        """Per-slot labels stop a pw ciphertext being relocated into the rec slot."""
        data = bytearray(encoded)
        data[114:126] = data[54:66]  # pw nonce -> rec nonce
        data[126:174] = data[66:114]  # pw ct    -> rec ct
        keyfile = fmt.decode_keyfile(bytes(data))
        with pytest.raises(crypto.AuthenticationError):
            keyfile.unwrap_with_recovery_key(crypto.generate_recovery_key())


class TestRecoverySlotIsIndependentOfKdfFields:
    """The deliberate asymmetry that makes password rotation practical.

    The recovery slot is unwrapped by a BLAKE2b key that never touches Argon2, so its
    AAD excludes the generation, salt, and Argon2 parameters.
    """

    def test_recovery_slot_survives_generation_and_salt_changes(self):
        dek = crypto.generate_dek()
        recovery_key = crypto.generate_recovery_key()
        vault_uuid = uuid.uuid4().bytes

        first = fmt.decode_keyfile(
            fmt.encode_keyfile(
                vault_uuid=vault_uuid,
                generation=1,
                params=FAST,
                salt=crypto.generate_salt(),
                dek=dek,
                password=PASSWORD,
                recovery_key=recovery_key,
            )
        )

        second = fmt.decode_keyfile(
            fmt.encode_keyfile(
                vault_uuid=vault_uuid,
                generation=2,
                params=crypto.KdfParams(
                    time_cost=2, memory_cost_kib=2048, parallelism=2
                ),
                salt=crypto.generate_salt(),  # different salt
                dek=dek,
                password="a different password",
                recovery_slot=(first.rec_nonce, first.rec_ct),  # copied verbatim
            )
        )

        assert second.unwrap_with_recovery_key(recovery_key) == dek
        assert second.unwrap_with_password("a different password", check_memory=False) == dek


# ---------------------------------------------------------------- file handling


class TestCreateKeyfile:
    def test_creates_file_and_directory(self, vault_dir: Path, made):
        keyfile, _, _ = made
        assert fmt.keyfile_path(vault_dir, 1).is_file()
        assert keyfile.generation == 1

    def test_file_mode_is_0600(self, vault_dir: Path, made):
        """Requirement 2.12. The legacy config.ini held a cleartext key at 0644."""
        mode = stat.S_IMODE(fmt.keyfile_path(vault_dir, 1).stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_directory_mode_is_0700(self, isolate_home: Path):
        target = isolate_home / "fresh-vault"
        fmt.create_keyfile(
            target, PASSWORD, params=FAST, check_memory=False
        )
        mode = stat.S_IMODE(target.stat().st_mode)
        assert mode == 0o700, f"expected 0700, got {oct(mode)}"

    def test_ensure_dir_tightens_existing_permissions(self, isolate_home: Path):
        loose = isolate_home / "loose"
        loose.mkdir(mode=0o755)
        fmt.ensure_dir(loose)
        assert stat.S_IMODE(loose.stat().st_mode) == 0o700

    def test_refuses_to_overwrite_a_generation(self, vault_dir: Path, made):
        """Requirement 6.6: keyfiles are immutable; rotation appends."""
        with pytest.raises(fmt.GenerationExistsError, match="immutable"):
            fmt.create_keyfile(vault_dir, "another", params=FAST, check_memory=False)

    def test_returns_a_usable_recovery_key(self, vault_dir: Path):
        keyfile, recovery_key = fmt.create_keyfile(
            vault_dir, PASSWORD, params=FAST, check_memory=False
        )
        assert len(recovery_key) == crypto.RECOVERY_KEY_SIZE
        assert keyfile.has_recovery_slot
        assert keyfile.unwrap_with_recovery_key(recovery_key)

    def test_no_temp_files_left_behind(self, vault_dir: Path, made):
        leftovers = [p.name for p in vault_dir.iterdir() if p.name.startswith(".tmp-")]
        assert leftovers == []

    def test_memory_check_blocks_creation(self, vault_dir: Path, monkeypatch):
        """Requirement 2.5, on the creation path as well as the open path."""
        monkeypatch.setattr(crypto, "read_mem_available_kib", lambda *a, **k: 1000)
        with pytest.raises(crypto.InsufficientMemoryError, match="64 MiB"):
            fmt.create_keyfile(vault_dir, PASSWORD)  # default 64 MiB params


class TestLoadKeyfile:
    def test_loads_the_only_generation(self, vault_dir: Path, made):
        assert fmt.load_keyfile(vault_dir).generation == 1

    def test_prefers_the_highest_generation(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        fmt.rotate_keyfile(vault_dir, keyfile, dek, "second", check_memory=False)
        fmt.rotate_keyfile(
            vault_dir,
            fmt.load_keyfile(vault_dir),
            dek,
            "third",
            check_memory=False,
        )
        assert fmt.load_keyfile(vault_dir).generation == 3

    def test_falls_back_when_newest_is_corrupt(self, vault_dir: Path, made):
        """A truncated newest keyfile must not make the vault unopenable."""
        keyfile, dek, _ = made
        fmt.rotate_keyfile(vault_dir, keyfile, dek, "second", check_memory=False)
        fmt.keyfile_path(vault_dir, 2).write_bytes(b"truncated")

        loaded = fmt.load_keyfile(vault_dir)
        assert loaded.generation == 1
        assert loaded.unwrap_with_password(PASSWORD, check_memory=False) == dek

    def test_missing_keyfile_explains_recovery(self, vault_dir: Path):
        with pytest.raises(fmt.KeyfileNotFoundError, match="backup"):
            fmt.load_keyfile(vault_dir)

    def test_missing_directory_is_reported(self, isolate_home: Path):
        with pytest.raises(fmt.KeyfileNotFoundError):
            fmt.load_keyfile(isolate_home / "nope")

    def test_all_corrupt_reports_each_generation(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        fmt.rotate_keyfile(vault_dir, keyfile, dek, "second", check_memory=False)
        fmt.keyfile_path(vault_dir, 1).write_bytes(b"bad")
        fmt.keyfile_path(vault_dir, 2).write_bytes(b"also bad")

        with pytest.raises(fmt.NoUsableKeyfileError) as excinfo:
            fmt.load_keyfile(vault_dir)
        assert set(excinfo.value.failures) == {1, 2}
        assert "keys.2.mpk" in str(excinfo.value)

    def test_generation_discovery_ignores_other_files(self, vault_dir: Path, made):
        (vault_dir / "keys.mpk").write_bytes(b"x")
        (vault_dir / "keys.1.mpk.bak").write_bytes(b"x")
        (vault_dir / "notes.txt").write_bytes(b"x")
        assert fmt.find_keyfile_generations(vault_dir) == [1]

    def test_archive_subdirectory_is_not_scanned(self, vault_dir: Path, made):
        """Design 3.1: an archived generation means the old password still works,
        so archived files must never be offered for unlocking."""
        archive = vault_dir / "archive"
        archive.mkdir()
        (archive / "keys.9.mpk").write_bytes(fmt.keyfile_path(vault_dir, 1).read_bytes())
        assert fmt.find_keyfile_generations(vault_dir) == [1]


class TestRotate:
    def test_new_password_works_and_dek_is_preserved(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "brand new passphrase", check_memory=False
        )
        assert rotated.generation == 2
        assert rotated.unwrap_with_password(
            "brand new passphrase", check_memory=False
        ) == dek

    def test_old_password_does_not_open_the_new_generation(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "brand new passphrase", check_memory=False
        )
        with pytest.raises(crypto.AuthenticationError):
            rotated.unwrap_with_password(PASSWORD, check_memory=False)

    def test_printed_recovery_key_still_works_after_rotation(
        self, vault_dir: Path, made
    ):
        """The point of the per-slot AAD: rotation does not invalidate paper."""
        keyfile, dek, recovery_key = made
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "brand new passphrase", check_memory=False
        )
        assert rotated.unwrap_with_recovery_key(recovery_key) == dek

    def test_vault_uuid_is_preserved(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "next", check_memory=False
        )
        assert rotated.vault_uuid == keyfile.vault_uuid

    def test_rotation_uses_a_fresh_salt(self, vault_dir: Path, made):
        keyfile, dek, _ = made
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "next", check_memory=False
        )
        assert rotated.salt != keyfile.salt

    def test_old_generation_is_left_on_disk(self, vault_dir: Path, made):
        """Rotation appends; archiving is the caller's job after verification."""
        keyfile, dek, _ = made
        fmt.rotate_keyfile(vault_dir, keyfile, dek, "next", check_memory=False)
        assert fmt.keyfile_path(vault_dir, 1).is_file()
        assert fmt.keyfile_path(vault_dir, 2).is_file()

    def test_can_also_change_kdf_params(self, vault_dir: Path, made):
        """Recalibrating on a faster board should be possible without a new vault."""
        keyfile, dek, _ = made
        stronger = crypto.KdfParams(time_cost=2, memory_cost_kib=2048, parallelism=2)
        rotated = fmt.rotate_keyfile(
            vault_dir, keyfile, dek, "next", params=stronger, check_memory=False
        )
        assert rotated.params == stronger
        assert rotated.unwrap_with_password("next", check_memory=False) == dek


# --------------------------------------------------------------- atomic writes


class TestAtomicWrite:
    def test_writes_content_and_mode(self, tmp_path: Path):
        target = tmp_path / "x.bin"
        fmt.atomic_write(target, b"hello")
        assert target.read_bytes() == b"hello"
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_replaces_existing_file(self, tmp_path: Path):
        target = tmp_path / "x.bin"
        target.write_bytes(b"old")
        fmt.atomic_write(target, b"new")
        assert target.read_bytes() == b"new"

    def test_leaves_no_temp_file_on_success(self, tmp_path: Path):
        fmt.atomic_write(tmp_path / "x.bin", b"data")
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp-")] == []

    def test_cleans_up_temp_file_on_failure(self, tmp_path: Path, monkeypatch):
        """A failure mid-write must not litter, and must not clobber the original."""
        target = tmp_path / "x.bin"
        target.write_bytes(b"original")

        def boom(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", boom)
        with pytest.raises(OSError, match="disk full"):
            fmt.atomic_write(target, b"replacement")

        assert target.read_bytes() == b"original"
        assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".tmp-")] == []

    def test_original_survives_a_failed_keyfile_write(self, vault_dir: Path, made):
        """The legacy failure mode: crash mid-write destroys the only key copy."""
        keyfile, dek, _ = made
        before = fmt.keyfile_path(vault_dir, 1).read_bytes()

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
            with pytest.raises(OSError):
                fmt.rotate_keyfile(vault_dir, keyfile, dek, "next", check_memory=False)

        assert fmt.keyfile_path(vault_dir, 1).read_bytes() == before
        assert fmt.load_keyfile(vault_dir).unwrap_with_password(
            PASSWORD, check_memory=False
        ) == dek
