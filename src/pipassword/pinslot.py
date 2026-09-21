"""The PIN unlock slot: an opt-in, local, low-entropy convenience credential.

Read requirements section 9 and design section 9a before changing anything here.
This module makes a deliberate security trade, and the trade is the whole point:

* A leaked *vault copy* (Syncthing, rclone, a spare SD card) stays fully protected,
  because this slot never enters the vault directory and is never synced.
* A *stolen device* is degraded to the PIN's entropy, roughly 20 bits for six
  digits, because the thief has both the vault and this file.

That is why the slot lives in ``~/.config/pipassword/`` beside ``device_id`` rather
than as a third slot in the keyfile. The keyfile is synced; this must not be.

Two inputs are required to recover the DEK: the PIN, and a 256-bit ``device_secret``
stored in this file. Neither alone is enough. An attacker with the vault but not the
file faces 256 bits; an attacker with both faces the PIN.

The failure counter is a **speed bump, not rate limiting**. There is no secure
element on a Pi to enforce an attempt limit, so an attacker who copies the file first
resets the count at will. It stops a curious person picking up an unlocked handheld,
nothing more, and the code and docs must never imply otherwise.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

from .compat import SLOTS
from .crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    AuthenticationError,
    KdfParams,
    ParameterError,
    aead_decrypt,
    aead_encrypt,
    derive_kek,
    generate_nonce,
    generate_salt,
    require_memory_available,
)
from .format import FormatError, MagicMismatchError, UnsupportedVersionError, atomic_write

__all__ = [
    "PinError",
    "PinSlot",
    "PIN_MAGIC",
    "PIN_SLOT_SIZE",
    "DEFAULT_FAILURE_LIMIT",
    "MIN_PIN_LENGTH",
    "WARN_PIN_LENGTH",
    "DEVICE_SECRET_SIZE",
    "encode_pin_slot",
    "decode_pin_slot",
    "derive_unlock_key",
    "pin_entropy_bits",
    "crack_time_estimate",
]

PIN_MAGIC = b"PIPWPIN\x00"
PIN_VERSION = 1
PIN_SLOT_SIZE = 143

KDF_ID_ARGON2ID = 1

DEVICE_SECRET_SIZE = 32
PIN_SLOT_LABEL = b"pipw-pin-slot-v1"
PIN_PERSON = b"pipw-pin"

DEFAULT_FAILURE_LIMIT = 5
MIN_PIN_LENGTH = 4
WARN_PIN_LENGTH = 6

#: Argon2 defaults for the PIN slot. Kept identical to the vault default rather than
#: raised: per requirement 9.13, more KDF cost is a rounding error against a PIN's
#: entropy. Each doubling buys one bit; a sixth digit buys 3.3. Spending seconds of a
#: handheld's battery to pretend a PIN is stronger than it is would be dishonest.
DEFAULT_PIN_PARAMS = KdfParams()

# Field offsets, named so this module and design section 9a cannot drift.
_OFF_MAGIC = 0
_OFF_VERSION = 8
_OFF_VAULT_UUID = 10
_OFF_KDF_ID = 26
_OFF_MEMORY_COST = 27
_OFF_TIME_COST = 31
_OFF_PARALLELISM = 32
_OFF_SALT = 33
_OFF_DEVICE_SECRET = 49
_OFF_NONCE = 81
_OFF_CT = 93
_OFF_FAILURE_COUNT = 141

#: Bytes authenticated as associated data: everything up to and including the nonce
#: region's start, i.e. the header and device secret, but NOT the failure counter.
#: The counter must change in place without re-wrapping, so it cannot be authenticated
#: (design 9a). Binding the header stops a slot being retargeted at another vault, and
#: binding the device secret stops it being swapped for a known one.
_AAD_END = _OFF_NONCE


class PinError(Exception):
    """A PIN slot problem. Never carries the PIN or any key material."""


def pin_entropy_bits(pin: str) -> float:
    """A deliberately pessimistic entropy estimate for a numeric or short PIN.

    Assumes the attacker knows the character class, which for a device PIN they do.
    An all-digit PIN is scored as log2(10) per character; anything else as a
    conservative log2(36). This is only used to warn the user, and erring low is the
    honest direction.
    """
    import math

    if not pin:
        return 0.0
    alphabet = 10 if pin.isdigit() else 36
    return len(pin) * math.log2(alphabet)


def crack_time_estimate(bits: float) -> str:
    """Human phrasing of offline cracking time against this vault's KDF.

    Anchored to a high-end GPU at ~2,000 Argon2id guesses/sec at 64 MiB. Order of
    magnitude only, and labelled as such wherever it is shown; the point is to make
    "minutes" versus "centuries" legible, not to be precise.
    """
    import math

    guesses = 2.0 ** bits / 2  # average: half the keyspace
    seconds = guesses / 2000.0
    for unit, span in (
        ("second", 1),
        ("minute", 60),
        ("hour", 3600),
        ("day", 86400),
        ("year", 31557600),
    ):
        if seconds < span * 90 or unit == "year":
            value = seconds / span
            if unit == "year" and value > 1000:
                return f"~{value/1000:,.0f} thousand years"
            return f"~{value:.0f} {unit}{'s' if value >= 2 else ''}"
    return "a long time"  # pragma: no cover


def derive_unlock_key(pin: str, device_secret: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Derive the DEK-wrapping key from the PIN and the device secret together.

    ``derive_kek`` already NFC-normalises and runs Argon2id, so a PIN typed through
    an IME derives the same key on every device, exactly like the master password.
    The Argon2 output is then keyed-BLAKE2b'd with the device secret, so the file is
    a mandatory second factor: the PIN alone yields nothing without it.
    """
    if len(device_secret) != DEVICE_SECRET_SIZE:
        raise ParameterError(
            f"device secret must be {DEVICE_SECRET_SIZE} bytes, got {len(device_secret)}"
        )
    pin_kek = derive_kek(pin, salt, params)
    return hashlib.blake2b(
        pin_kek, key=device_secret, person=PIN_PERSON, digest_size=KEY_SIZE
    ).digest()


@dataclass(**SLOTS)
class PinSlot:
    """A parsed PIN slot.

    ``raw`` is retained because the associated data is defined as a byte range of the
    file itself; recomputing it from fields risks drift that would surface as a
    spurious authentication failure.
    """

    vault_uuid: bytes
    params: KdfParams
    salt: bytes
    device_secret: bytes
    nonce: bytes
    ct: bytes
    failure_count: int
    raw: bytes

    @property
    def vault_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.vault_uuid))

    def unwrap(self, pin: str) -> bytes:
        """Recover the DEK from the PIN. Raises on a wrong PIN.

        Callers own the failure-counter bookkeeping via :func:`bump_failure` and
        :func:`reset_failure`, because whether to increment depends on the outcome
        and the caller has the file path.
        """
        key = derive_unlock_key(pin, self.device_secret, self.salt, self.params)
        return aead_decrypt(key, self.nonce, self.ct, self.raw[:_AAD_END] + PIN_SLOT_LABEL)


def encode_pin_slot(
    *,
    vault_uuid: bytes,
    dek: bytes,
    pin: str,
    device_secret: bytes,
    params: KdfParams,
    salt: bytes,
    failure_count: int = 0,
) -> bytes:
    """Serialise a PIN slot. The header must exist before wrapping, since the AAD is
    a slice of the header bytes."""
    if len(vault_uuid) != 16:
        raise PinError(f"vault_uuid must be 16 bytes, got {len(vault_uuid)}")
    if len(dek) != KEY_SIZE:
        raise PinError(f"dek must be {KEY_SIZE} bytes, got {len(dek)}")
    if len(device_secret) != DEVICE_SECRET_SIZE:
        raise PinError("device secret has the wrong size")
    if len(salt) != SALT_SIZE:
        raise PinError("salt has the wrong size")
    if params.time_cost > 0xFF or params.parallelism > 0xFF:
        raise PinError("KDF parameters do not fit the slot layout")
    if not 0 <= failure_count <= 0xFFFF:
        raise PinError("failure_count out of range")

    header = bytearray(_OFF_NONCE)
    header[_OFF_MAGIC:_OFF_VERSION] = PIN_MAGIC
    struct.pack_into("<H", header, _OFF_VERSION, PIN_VERSION)
    header[_OFF_VAULT_UUID:_OFF_KDF_ID] = vault_uuid
    header[_OFF_KDF_ID] = KDF_ID_ARGON2ID
    struct.pack_into("<I", header, _OFF_MEMORY_COST, params.memory_cost_kib)
    header[_OFF_TIME_COST] = params.time_cost
    header[_OFF_PARALLELISM] = params.parallelism
    header[_OFF_SALT:_OFF_DEVICE_SECRET] = salt
    header[_OFF_DEVICE_SECRET:_OFF_NONCE] = device_secret

    raw_prefix = bytes(header)
    nonce = generate_nonce()
    key = derive_unlock_key(pin, device_secret, salt, params)
    ct = aead_encrypt(key, nonce, dek, raw_prefix + PIN_SLOT_LABEL)

    encoded = raw_prefix + nonce + ct + struct.pack("<H", failure_count)
    if len(encoded) != PIN_SLOT_SIZE:  # pragma: no cover - guards the offsets
        raise PinError(f"encoded slot is {len(encoded)} bytes, expected {PIN_SLOT_SIZE}")
    return encoded


def decode_pin_slot(data: bytes) -> PinSlot:
    """Parse a PIN slot. Raises :class:`FormatError` subclasses on malformed input."""
    if len(data) != PIN_SLOT_SIZE:
        raise FormatError(f"PIN slot must be {PIN_SLOT_SIZE} bytes, got {len(data)}")
    if data[_OFF_MAGIC:_OFF_VERSION] != PIN_MAGIC:
        raise MagicMismatchError("not a pipassword PIN slot (bad magic)")

    (version,) = struct.unpack_from("<H", data, _OFF_VERSION)
    if version != PIN_VERSION:
        raise UnsupportedVersionError(
            f"PIN slot version {version} is not supported (expected {PIN_VERSION})"
        )
    if data[_OFF_KDF_ID] != KDF_ID_ARGON2ID:
        raise UnsupportedVersionError(f"unknown KDF id {data[_OFF_KDF_ID]}")

    (memory_cost,) = struct.unpack_from("<I", data, _OFF_MEMORY_COST)
    try:
        params = KdfParams(
            time_cost=data[_OFF_TIME_COST],
            memory_cost_kib=memory_cost,
            parallelism=data[_OFF_PARALLELISM],
        )
    except Exception as exc:
        raise FormatError(f"PIN slot has invalid KDF parameters: {exc}") from exc

    (failure_count,) = struct.unpack_from("<H", data, _OFF_FAILURE_COUNT)
    return PinSlot(
        vault_uuid=data[_OFF_VAULT_UUID:_OFF_KDF_ID],
        params=params,
        salt=data[_OFF_SALT:_OFF_DEVICE_SECRET],
        device_secret=data[_OFF_DEVICE_SECRET:_OFF_NONCE],
        nonce=data[_OFF_NONCE:_OFF_CT],
        ct=data[_OFF_CT:_OFF_FAILURE_COUNT],
        failure_count=failure_count,
        raw=bytes(data),
    )


def rewrite_failure_count(data: bytes, failure_count: int) -> bytes:
    """Return the slot bytes with a new failure count and nothing else changed.

    Only the trailing two bytes move. The DEK is not re-wrapped, which is the whole
    reason the counter sits outside the AAD.
    """
    if not 0 <= failure_count <= 0xFFFF:
        raise PinError("failure_count out of range")
    return data[:_OFF_FAILURE_COUNT] + struct.pack("<H", failure_count)


# =============================================================================
# On-disk management: the local pin.unlock file
# =============================================================================

import os  # noqa: E402  (kept with the file layer it belongs to)

PIN_FILENAME = "pin.unlock"

__all__ += [
    "PIN_FILENAME",
    "PinSlotFile",
    "pin_slot_path",
    "pin_slot_exists",
    "load_pin_slot",
]


def pin_slot_path(config_dir: Path) -> Path:
    """Location of the slot: beside ``device_id`` in the config directory.

    Never inside the vault directory (requirement 9.3). This is the single fact the
    whole feature's security rests on, so it is computed in exactly one place.
    """
    return config_dir / PIN_FILENAME


def pin_slot_exists(config_dir: Path) -> bool:
    return pin_slot_path(config_dir).is_file()


class PinAttemptsExhausted(PinError):
    """The failure limit was reached and the slot was deleted."""


class PinSlotFile:
    """A PIN slot backed by a file, owning the failure-counter bookkeeping.

    The unlock/increment/delete cycle needs the file path, so it lives here rather
    than on :class:`PinSlot`, which is pure data.
    """

    def __init__(self, path: Path, failure_limit: int = DEFAULT_FAILURE_LIMIT) -> None:
        self.path = path
        self.failure_limit = failure_limit

    # -- reading -----------------------------------------------------------

    def _require_safe_mode(self) -> None:
        """Refuse a world- or group-readable slot (requirement 9.5).

        The file's only value is that no one else has it. If the permissions say
        otherwise, using it would be a false sense of safety, so fail loudly.
        """
        mode = self.path.stat().st_mode & 0o777
        if mode & 0o077:
            raise PinError(
                f"{self.path} is readable by others (mode {mode:04o}). "
                f"Fix it with: chmod 600 {self.path}"
            )

    def read(self) -> PinSlot:
        self._require_safe_mode()
        return decode_pin_slot(self.path.read_bytes())

    def matches_vault(self, vault_uuid: bytes) -> bool:
        try:
            return self.read().vault_uuid == vault_uuid
        except (FormatError, OSError, PinError):
            return False

    # -- the unlock cycle --------------------------------------------------

    def unlock(self, pin: str, expected_vault_uuid: bytes) -> bytes:
        """Recover the DEK, handling the failure counter and vault binding.

        On success the counter is reset. On a wrong PIN it is incremented, and when
        it reaches the limit the slot file is deleted and
        :class:`PinAttemptsExhausted` is raised, so the next unlock must use the
        master password.
        """
        slot = self.read()

        # Requirement 9.6: a slot for a different vault must never be honoured.
        if slot.vault_uuid != expected_vault_uuid:
            raise PinError(
                f"{self.path} belongs to vault {slot.vault_uuid_str}, not the one "
                f"being opened. Remove it with 'pipw pin remove'."
            )

        try:
            dek = slot.unwrap(pin)
        except AuthenticationError:
            remaining = self._register_failure(slot)
            if remaining <= 0:
                raise PinAttemptsExhausted(
                    "too many wrong PINs; the PIN has been removed. Unlock with your "
                    "master password."
                ) from None
            raise PinError(
                f"wrong PIN. {remaining} attempt(s) left before the PIN is removed."
            ) from None

        if slot.failure_count != 0:
            self._write(rewrite_failure_count(slot.raw, 0))
        return dek

    def _register_failure(self, slot: PinSlot) -> int:
        """Increment the on-disk counter; delete the slot if the limit is hit.

        Returns attempts remaining. This is a speed bump: an attacker who copied the
        file beforehand still has an untouched counter. It exists to blunt casual
        shoulder-guessing on a picked-up device, not to withstand an offline attack.
        """
        new_count = slot.failure_count + 1
        if new_count >= self.failure_limit:
            self.delete()
            return 0
        self._write(rewrite_failure_count(slot.raw, new_count))
        return self.failure_limit - new_count

    # -- writing -----------------------------------------------------------

    def _write(self, data: bytes) -> None:
        # atomic_write creates at mode 0600 and never leaves the file briefly
        # world-readable, which matters here as much as for the keyfile.
        atomic_write(self.path, data, mode=0o600)

    def create(
        self,
        *,
        vault_uuid: bytes,
        dek: bytes,
        pin: str,
        params: KdfParams | None = None,
        check_memory: bool = True,
    ) -> PinSlot:
        """Generate a device secret and write a fresh slot wrapping the DEK.

        The caller must already hold the DEK, which is why the CLI requires the
        master password or recovery key for ``pin set`` (requirement 9.7).
        """
        if len(pin) < MIN_PIN_LENGTH:
            raise PinError(f"a PIN must be at least {MIN_PIN_LENGTH} characters")
        params = DEFAULT_PIN_PARAMS if params is None else params
        if check_memory:
            require_memory_available(params)

        device_secret = os.urandom(DEVICE_SECRET_SIZE)
        encoded = encode_pin_slot(
            vault_uuid=vault_uuid,
            dek=dek,
            pin=pin,
            device_secret=device_secret,
            params=params,
            salt=generate_salt(),
        )
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._write(encoded)
        # Verify by reading back, as the keyfile does: a slot that cannot be reopened
        # is worse than no slot, because the user thinks they have a shortcut.
        slot = self.read()
        if slot.unwrap(pin) != dek:  # pragma: no cover - would be a serious bug
            self.delete()
            raise PinError("PIN slot verification failed after writing")
        return slot

    def delete(self) -> None:
        """Remove the slot. Idempotent, and needs no credential (requirement 9.8)."""
        self.path.unlink(missing_ok=True)


def load_pin_slot(
    config_dir: Path, failure_limit: int = DEFAULT_FAILURE_LIMIT
) -> PinSlotFile | None:
    """Return a :class:`PinSlotFile` if one exists, else ``None``."""
    path = pin_slot_path(config_dir)
    return PinSlotFile(path, failure_limit) if path.is_file() else None
