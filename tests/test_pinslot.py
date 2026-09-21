"""Tests for the PIN unlock slot (requirements 9.1-9.15, task 18).

The load-bearing tests, in order of what would be worst to get wrong:

* :class:`TestLeakedVaultIsSafe` -- a leaked vault directory alone must be unopenable
  with the PIN. This is the entire justification for the feature; if it fails, the
  PIN is protecting nothing.
* :class:`TestSlotNeverEntersVault` -- the slot must never be written into the synced
  vault directory.
* :class:`TestRecoverIgnoresPin` and :class:`TestFormatUnchanged` -- the vault format
  and the independent recovery path must be untouched.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from pipassword import crypto, format as fmt, pinslot
from pipassword.vault import Vault, VaultError

FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)
PW = "correct horse battery staple"
PIN = "135790"


@pytest.fixture
def opened(isolate_home: Path):
    """A created vault plus its paths, still open."""
    vault_dir = isolate_home / "vault"
    config_dir = isolate_home / ".config" / "pipassword"
    vault, recovery = Vault.create(
        vault_dir, PW, params=FAST, config_dir=config_dir, check_memory=False
    )
    vault.add("Google", login="a@g.com", password="p")
    return vault, vault_dir, config_dir, recovery


def _slot_path(config_dir: Path) -> Path:
    return pinslot.pin_slot_path(config_dir)


# ------------------------------------------------------------- format layer


class TestFormat:
    def test_roundtrip(self):
        dek = crypto.generate_dek()
        vault_uuid = crypto.generate_salt()  # any 16 bytes
        encoded = pinslot.encode_pin_slot(
            vault_uuid=vault_uuid,
            dek=dek,
            pin=PIN,
            device_secret=crypto.generate_recovery_key(),
            params=FAST,
            salt=crypto.generate_salt(),
        )
        assert len(encoded) == pinslot.PIN_SLOT_SIZE == 143
        slot = pinslot.decode_pin_slot(encoded)
        assert slot.vault_uuid == vault_uuid
        assert slot.failure_count == 0
        assert slot.unwrap(PIN) == dek

    def test_magic_and_version(self):
        encoded = _make_slot()
        assert encoded[0:8] == b"PIPWPIN\x00"
        assert struct.unpack_from("<H", encoded, 8)[0] == 1

    def test_wrong_pin_fails_authentication(self):
        slot = pinslot.decode_pin_slot(_make_slot())
        with pytest.raises(crypto.AuthenticationError):
            slot.unwrap("000000")

    def test_bad_magic(self):
        data = bytearray(_make_slot())
        data[0] = 0
        with pytest.raises(fmt.MagicMismatchError):
            pinslot.decode_pin_slot(bytes(data))

    def test_future_version(self):
        data = bytearray(_make_slot())
        struct.pack_into("<H", data, 8, 99)
        with pytest.raises(fmt.UnsupportedVersionError):
            pinslot.decode_pin_slot(bytes(data))

    def test_wrong_size(self):
        with pytest.raises(fmt.FormatError, match="143"):
            pinslot.decode_pin_slot(b"too short")

    def test_device_secret_is_required(self):
        """The PIN alone must not unwrap; the file's secret is a second factor."""
        dek = crypto.generate_dek()
        salt = crypto.generate_salt()
        secret = crypto.generate_recovery_key()
        key_with = pinslot.derive_unlock_key(PIN, secret, salt, FAST)
        key_without = pinslot.derive_unlock_key(
            PIN, bytes(pinslot.DEVICE_SECRET_SIZE), salt, FAST
        )
        assert key_with != key_without

    def test_failure_count_is_outside_the_aad(self):
        """Rewriting the counter must not invalidate the ciphertext (design 9a)."""
        dek = crypto.generate_dek()
        encoded = pinslot.encode_pin_slot(
            vault_uuid=crypto.generate_salt(),
            dek=dek,
            pin=PIN,
            device_secret=crypto.generate_recovery_key(),
            params=FAST,
            salt=crypto.generate_salt(),
        )
        bumped = pinslot.rewrite_failure_count(encoded, 3)
        slot = pinslot.decode_pin_slot(bumped)
        assert slot.failure_count == 3
        assert slot.unwrap(PIN) == dek  # still unwraps despite the changed counter

    def test_nfc_normalisation(self):
        """A PIN with combining characters must unwrap the same on every device."""
        dek = crypto.generate_dek()
        secret = crypto.generate_recovery_key()
        salt = crypto.generate_salt()
        composed = pinslot.derive_unlock_key("café", secret, salt, FAST)
        decomposed = pinslot.derive_unlock_key("cafe\u0301", secret, salt, FAST)
        assert composed == decomposed


def _make_slot(pin=PIN, dek=None, vault_uuid=None):
    return pinslot.encode_pin_slot(
        vault_uuid=vault_uuid or crypto.generate_salt(),
        dek=dek or crypto.generate_dek(),
        pin=pin,
        device_secret=crypto.generate_recovery_key(),
        params=FAST,
        salt=crypto.generate_salt(),
    )


# ------------------------------------------------- the security-critical trade


class TestLeakedVaultIsSafe:
    """Requirement 9.3, and the whole reason the feature is acceptable.

    A vault directory that leaks -- via Syncthing, rclone, or a copied SD card --
    carries no PIN slot, because the slot lives in the config directory. So the PIN
    cannot weaken it: the attacker still faces the full-entropy master password.
    """

    def test_leaked_vault_has_no_pin_slot(self, opened, tmp_path):
        import shutil

        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()

        # Simulate exactly what Syncthing/rclone would replicate: the vault dir only.
        leaked = tmp_path / "leaked-copy"
        shutil.copytree(vault_dir, leaked)

        assert not (leaked / "pin.unlock").exists()
        assert list(leaked.rglob("pin.unlock")) == []

        # The attacker cannot even attempt a PIN: there is no slot in what they have.
        assert not Vault.has_pin(leaked)

    def test_pin_alone_is_useless_without_the_device_secret(self, opened):
        """Even knowing the PIN, the vault contents give no shortcut."""
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()

        # Attacker has the vault and guesses the PIN, but not pin.unlock.
        with pytest.raises(VaultError, match="no PIN is set"):
            Vault.unlock(
                vault_dir, pin=PIN, config_dir=vault_dir / "attacker-empty-config",
                check_memory=False,
            )


class TestSlotNeverEntersVault:
    """Requirement 9.3: structural, not incidental."""

    def test_set_pin_writes_only_to_config_dir(self, opened):
        vault, vault_dir, config_dir, _ = opened
        before = {p for p in vault_dir.rglob("*") if p.is_file()}
        vault.set_pin(PIN, check_memory=False)
        after = {p for p in vault_dir.rglob("*") if p.is_file()}
        assert before == after, "set_pin must not add files to the vault directory"
        assert (config_dir / "pin.unlock").is_file()

    def test_slot_path_is_under_config_not_vault(self, opened):
        vault, vault_dir, config_dir, _ = opened
        path = pinslot.pin_slot_path(config_dir)
        assert config_dir in path.parents
        assert vault_dir not in path.parents


class TestRecoverIgnoresPin:
    """Requirement 9.12: recover.py must not know about PINs."""

    def test_recover_tool_has_no_pin_references(self):
        import ast

        root = Path(__file__).resolve().parent.parent
        for name in ("recover.py", "src/pipassword/recovery_tool.py"):
            source = (root / name).read_text()
            assert "pin.unlock" not in source, f"{name} references the PIN slot"
            assert "PIPWPIN" not in source
            tree = ast.parse(source)
            imported = {
                n.module
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
                for n in [node]
            }
            assert "pinslot" not in (imported or set())


class TestFormatUnchanged:
    """Requirement 9.15: the keyfile format and version are untouched."""

    def test_keyfile_still_174_bytes_and_v1(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()
        keyfile = fmt.load_keyfile(vault_dir)
        assert keyfile.generation == 1
        assert fmt.keyfile_path(vault_dir, 1).stat().st_size == fmt.KEYFILE_SIZE

    def test_format_md_pin_slot_size_matches_code(self):
        format_md = (Path(__file__).resolve().parent.parent / "FORMAT.md").read_text()
        # If FORMAT.md documents the slot, its size must agree with the code.
        if "PIPWPIN" in format_md or "pin.unlock" in format_md:
            assert str(pinslot.PIN_SLOT_SIZE) in format_md


# ------------------------------------------------------------- file layer


class TestPinSlotFile:
    def test_create_and_unlock(self, opened):
        vault, vault_dir, config_dir, _ = opened
        dek = vault.dek
        vault_uuid = vault.keyfile.vault_uuid
        vault.close()

        f = pinslot.PinSlotFile(_slot_path(config_dir))
        f.create(vault_uuid=vault_uuid, dek=dek, pin=PIN, check_memory=False)
        assert f.unlock(PIN, vault_uuid) == dek

    def test_mode_is_0600(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        mode = _slot_path(config_dir).stat().st_mode & 0o777
        assert mode == 0o600

    def test_loose_mode_is_refused(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        _slot_path(config_dir).chmod(0o644)
        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError, match="readable by others"):
            f.read()

    def test_short_pin_refused(self, opened):
        vault, vault_dir, config_dir, _ = opened
        dek, uid = vault.dek, vault.keyfile.vault_uuid
        vault.close()
        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError, match="at least"):
            f.create(vault_uuid=uid, dek=dek, pin="12", check_memory=False)

    def test_wrong_vault_uuid_refused(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError, match="belongs to vault"):
            f.unlock(PIN, crypto.generate_salt())  # a different 16-byte uuid


class TestFailureCounter:
    """Requirement 9.11. A speed bump, and the tests treat it as exactly that."""

    def test_wrong_pin_increments(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        uid = vault.keyfile.vault_uuid
        vault.close()

        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError, match="4 attempt"):
            f.unlock("000000", uid)
        assert f.read().failure_count == 1

    def test_correct_pin_resets_the_counter(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        uid = vault.keyfile.vault_uuid
        vault.close()

        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError):
            f.unlock("000000", uid)
        f.unlock(PIN, uid)  # correct
        assert f.read().failure_count == 0

    def test_slot_deleted_after_the_limit(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        uid = vault.keyfile.vault_uuid
        vault.close()

        f = pinslot.PinSlotFile(_slot_path(config_dir), failure_limit=3)
        with pytest.raises(pinslot.PinError):
            f.unlock("000000", uid)  # 1
        with pytest.raises(pinslot.PinError):
            f.unlock("000000", uid)  # 2
        with pytest.raises(pinslot.PinAttemptsExhausted):
            f.unlock("000000", uid)  # 3 -> delete
        assert not _slot_path(config_dir).exists()

    def test_counter_is_a_speed_bump_a_copy_defeats_it(self, opened, tmp_path):
        """Explicit: copying the file before guessing resets the count. Documented
        as the reason this is not rate limiting."""
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        uid = vault.keyfile.vault_uuid
        vault.close()

        pristine = (tmp_path / "copy.unlock")
        pristine.write_bytes(_slot_path(config_dir).read_bytes())

        f = pinslot.PinSlotFile(_slot_path(config_dir))
        with pytest.raises(pinslot.PinError):
            f.unlock("000000", uid)
        assert f.read().failure_count == 1
        # The attacker's untouched copy still reads zero.
        assert pinslot.decode_pin_slot(pristine.read_bytes()).failure_count == 0


class TestRemove:
    def test_remove_needs_no_credential(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        assert _slot_path(config_dir).exists()
        assert vault.remove_pin() is True
        assert not _slot_path(config_dir).exists()

    def test_remove_when_absent_is_harmless(self, opened):
        vault, vault_dir, config_dir, _ = opened
        assert vault.remove_pin() is False


# ------------------------------------------------------------- vault unlock


class TestVaultUnlock:
    def test_unlock_with_pin(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()

        with Vault.unlock(
            vault_dir, pin=PIN, config_dir=config_dir, check_memory=False
        ) as reopened:
            assert reopened.get_by_name("Google").password == "p"

    def test_password_still_works_after_pin_set(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()
        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_dir, check_memory=False
        ) as reopened:
            assert reopened.get_by_name("Google") is not None

    def test_recovery_key_still_works_after_pin_set(self, opened):
        vault, vault_dir, config_dir, recovery = opened
        vault.set_pin(PIN, check_memory=False)
        vault.close()
        with Vault.unlock(
            vault_dir, recovery_key=recovery, config_dir=config_dir
        ) as reopened:
            assert reopened.get_by_name("Google") is not None

    def test_pin_unlock_without_a_slot_is_a_clear_error(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.close()
        with pytest.raises(VaultError, match="no PIN is set"):
            Vault.unlock(vault_dir, pin=PIN, config_dir=config_dir, check_memory=False)

    def test_exactly_one_credential(self, opened):
        vault, vault_dir, config_dir, _ = opened
        vault.close()
        with pytest.raises(VaultError, match="exactly one"):
            Vault.unlock(
                vault_dir, password=PW, pin=PIN, config_dir=config_dir,
                check_memory=False,
            )
        with pytest.raises(VaultError, match="exactly one"):
            Vault.unlock(vault_dir, config_dir=config_dir)

    def test_has_pin(self, opened):
        vault, vault_dir, config_dir, _ = opened
        assert Vault.has_pin(config_dir) is False
        vault.set_pin(PIN, check_memory=False)
        assert Vault.has_pin(config_dir) is True


# ------------------------------------------------------------- entropy notes


class TestEntropyReporting:
    def test_digit_pin_scored_low(self):
        assert pinslot.pin_entropy_bits("123456") == pytest.approx(19.93, abs=0.1)

    def test_longer_pin_more_bits(self):
        assert pinslot.pin_entropy_bits("12345678") > pinslot.pin_entropy_bits("1234")

    def test_crack_estimate_is_human(self):
        assert "minute" in pinslot.crack_time_estimate(20) or "second" in pinslot.crack_time_estimate(20)
        assert "year" in pinslot.crack_time_estimate(60)

    def test_empty_pin_zero_bits(self):
        assert pinslot.pin_entropy_bits("") == 0.0
