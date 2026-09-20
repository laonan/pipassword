"""On-disk binary formats.

This module owns the keyfile layout. The log layout lands in task 4.

Everything here is little-endian and fixed-width, specified normatively in
:file:`FORMAT.md`. The layout is deliberately boring: fixed offsets, no length-prefixed
optional sections, no nesting. A recovery tool should be able to parse it with
``struct.unpack`` and nothing else.
"""

from __future__ import annotations

import datetime
import os
import re
import struct
import tempfile
import uuid
from dataclasses import dataclass

from .compat import SLOTS
from pathlib import Path

from .crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    TAG_SIZE,
    AuthenticationError,
    KdfParams,
    aead_decrypt,
    aead_encrypt,
    derive_kek,
    derive_rkek,
    generate_dek,
    generate_nonce,
    generate_recovery_key,
    generate_salt,
    require_memory_available,
)

__all__ = [
    "FormatError",
    "MagicMismatchError",
    "UnsupportedVersionError",
    "KeyfileNotFoundError",
    "NoUsableKeyfileError",
    "GenerationExistsError",
    "Keyfile",
    "KEYFILE_MAGIC",
    "KEYFILE_VERSION",
    "KEYFILE_SIZE",
    "KDF_ID_ARGON2ID",
    "SLOT_PASSWORD",
    "SLOT_RECOVERY",
    "encode_keyfile",
    "decode_keyfile",
    "create_keyfile",
    "keyfile_path",
    "find_keyfile_generations",
    "load_keyfile",
    "atomic_write",
    "ensure_dir",
    "DIR_MODE",
    "FILE_MODE",
]

# --------------------------------------------------------------------- constants

KEYFILE_MAGIC = b"PIPWKEY\x00"
KEYFILE_VERSION = 1
KEYFILE_SIZE = 174

KDF_ID_ARGON2ID = 1

SLOT_PASSWORD = 0b01
SLOT_RECOVERY = 0b10

#: Wrapped-DEK length: 32-byte key plus 16-byte Poly1305 tag.
WRAPPED_DEK_SIZE = KEY_SIZE + TAG_SIZE

#: Domain separation labels. Appended to each slot's associated data so a ciphertext
#: cannot be relocated from one slot to the other.
PW_SLOT_LABEL = b"pipw-kek-slot-v1"
REC_SLOT_LABEL = b"pipw-rkek-slot-v1"

DIR_MODE = 0o700
"""Requirement 2.12. The legacy project left its data directory at the umask default,
typically 0755, with a world-readable cleartext key inside it."""

FILE_MODE = 0o600

_KEYFILE_NAME_RE = re.compile(r"^keys\.(\d+)\.mpk$")

# Field offsets. Named rather than inlined so FORMAT.md and this module cannot drift.
_OFF_MAGIC = 0
_OFF_VERSION = 8
_OFF_VAULT_UUID = 10
_OFF_GENERATION = 26
_OFF_KDF_ID = 30
_OFF_MEMORY_COST = 31
_OFF_TIME_COST = 35
_OFF_PARALLELISM = 36
_OFF_SALT = 37
_OFF_SLOTS = 53
_OFF_PW_NONCE = 54
_OFF_PW_CT = 66
_OFF_REC_NONCE = 114
_OFF_REC_CT = 126

_HDR_END = 54
"""End of the authenticated header region used by the password slot."""


# -------------------------------------------------------------------- exceptions


class FormatError(Exception):
    """A file is not a well-formed pipassword container."""


class MagicMismatchError(FormatError):
    """The file does not start with the expected magic bytes."""


class UnsupportedVersionError(FormatError):
    """The format version is newer than this build understands."""


class KeyfileNotFoundError(FormatError):
    """No keyfile exists in the vault directory."""


class NoUsableKeyfileError(FormatError):
    """Keyfiles exist but none could be parsed.

    Carries per-generation detail so the user is told which files were tried and why
    each failed, rather than just being told the vault is broken.
    """

    def __init__(self, message: str, failures: dict[int, str]) -> None:
        super().__init__(message)
        self.failures = failures


class GenerationExistsError(FormatError):
    """Refusing to overwrite an existing keyfile generation.

    Keyfiles are immutable once written (requirement 6.6); rotation appends a new
    generation rather than replacing one.
    """


# ------------------------------------------------------------------ aad helpers


def _password_aad(raw: bytes) -> bytes:
    """Associated data for the password slot: the whole header, plus a label.

    Covers version, vault UUID, generation, salt, and every Argon2 parameter, so a
    downgrade of ``memory_cost`` cannot produce a keyfile that still authenticates
    (requirement 2.9).
    """
    return raw[_OFF_MAGIC:_HDR_END] + PW_SLOT_LABEL


def _recovery_aad(raw: bytes) -> bytes:
    """Associated data for the recovery slot: identity fields only, plus a label.

    Excludes the generation number, salt, and Argon2 parameters. The recovery slot is
    unwrapped by a BLAKE2b-derived key and never touches Argon2, so binding it to
    Argon2 parameters would authenticate data it does not depend on. It also lets
    password rotation copy this slot verbatim into a new generation, which is what
    makes rotation possible without the paper key in hand. See design section 3.1.
    """
    return (
        raw[_OFF_MAGIC:_OFF_GENERATION]
        + raw[_OFF_SLOTS : _OFF_SLOTS + 1]
        + REC_SLOT_LABEL
    )


# ---------------------------------------------------------------------- keyfile


@dataclass(frozen=True, **SLOTS)
class Keyfile:
    """A parsed keyfile.

    ``raw`` is retained because the associated data is defined as byte ranges of the
    file itself. Recomputing it from the parsed fields would risk the two drifting
    apart, and any such drift would show up as an authentication failure that looks
    like a wrong password.
    """

    vault_uuid: bytes
    generation: int
    params: KdfParams
    salt: bytes
    slots: int
    pw_nonce: bytes
    pw_ct: bytes
    rec_nonce: bytes
    rec_ct: bytes
    raw: bytes

    @property
    def has_password_slot(self) -> bool:
        return bool(self.slots & SLOT_PASSWORD)

    @property
    def has_recovery_slot(self) -> bool:
        return bool(self.slots & SLOT_RECOVERY)

    @property
    def vault_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.vault_uuid))

    def unwrap_with_password(
        self, password: str | bytes, *, check_memory: bool = True
    ) -> bytes:
        """Recover the DEK from the master password.

        Raises :class:`~pipassword.crypto.InsufficientMemoryError` before doing any
        work if Argon2 could not allocate (requirement 2.5), and
        :class:`~pipassword.crypto.AuthenticationError` if the password is wrong.
        """
        if not self.has_password_slot:
            raise FormatError("this keyfile has no password slot")
        if check_memory:
            require_memory_available(self.params)
        kek = derive_kek(password, self.salt, self.params)
        return aead_decrypt(kek, self.pw_nonce, self.pw_ct, _password_aad(self.raw))

    def unwrap_with_recovery_key(self, recovery_key: bytes) -> bytes:
        """Recover the DEK from the paper recovery key.

        Needs no memory check: the RKEK comes from BLAKE2b, not Argon2, so this path
        works even on a device that cannot afford the KDF. That is deliberate — it is
        the last-resort path.
        """
        if not self.has_recovery_slot:
            raise FormatError("this keyfile has no recovery slot")
        rkek = derive_rkek(recovery_key)
        return aead_decrypt(rkek, self.rec_nonce, self.rec_ct, _recovery_aad(self.raw))


def encode_keyfile(
    *,
    vault_uuid: bytes,
    generation: int,
    params: KdfParams,
    salt: bytes,
    dek: bytes,
    password: str | bytes | None = None,
    recovery_key: bytes | None = None,
    recovery_slot: tuple[bytes, bytes] | None = None,
) -> bytes:
    """Serialise a keyfile.

    Exactly one of ``recovery_key`` or ``recovery_slot`` may be given.
    ``recovery_slot`` is the ``(nonce, ciphertext)`` pair copied verbatim from a
    previous generation, which is how rotation preserves the printed recovery key.
    """
    if len(vault_uuid) != 16:
        raise FormatError(f"vault_uuid must be 16 bytes, got {len(vault_uuid)}")
    if len(salt) != SALT_SIZE:
        raise FormatError(f"salt must be {SALT_SIZE} bytes, got {len(salt)}")
    if len(dek) != KEY_SIZE:
        raise FormatError(f"dek must be {KEY_SIZE} bytes, got {len(dek)}")
    if not 0 <= generation <= 0xFFFFFFFF:
        raise FormatError(f"generation out of range: {generation}")
    if params.time_cost > 0xFF:
        raise FormatError(f"time_cost must fit in one byte, got {params.time_cost}")
    if params.parallelism > 0xFF:
        raise FormatError(
            f"parallelism must fit in one byte, got {params.parallelism}"
        )
    if params.memory_cost_kib > 0xFFFFFFFF:
        raise FormatError("memory_cost_kib does not fit in four bytes")
    if recovery_key is not None and recovery_slot is not None:
        raise FormatError("give either recovery_key or recovery_slot, not both")

    slots = 0
    if password is not None:
        slots |= SLOT_PASSWORD
    if recovery_key is not None or recovery_slot is not None:
        slots |= SLOT_RECOVERY
    if not slots:
        raise FormatError("a keyfile needs at least one slot")

    # Build the header first: both AADs are slices of the encoded bytes, so the
    # header must exist before anything can be wrapped.
    header = bytearray(_HDR_END)
    header[_OFF_MAGIC:_OFF_VERSION] = KEYFILE_MAGIC
    struct.pack_into("<H", header, _OFF_VERSION, KEYFILE_VERSION)
    header[_OFF_VAULT_UUID:_OFF_GENERATION] = vault_uuid
    struct.pack_into("<I", header, _OFF_GENERATION, generation)
    header[_OFF_KDF_ID] = KDF_ID_ARGON2ID
    struct.pack_into("<I", header, _OFF_MEMORY_COST, params.memory_cost_kib)
    header[_OFF_TIME_COST] = params.time_cost
    header[_OFF_PARALLELISM] = params.parallelism
    header[_OFF_SALT:_OFF_SLOTS] = salt
    header[_OFF_SLOTS] = slots

    raw = bytes(header)

    if password is not None:
        pw_nonce = generate_nonce()
        kek = derive_kek(password, salt, params)
        pw_ct = aead_encrypt(kek, pw_nonce, dek, _password_aad(raw))
    else:
        pw_nonce = bytes(NONCE_SIZE)
        pw_ct = bytes(WRAPPED_DEK_SIZE)

    if recovery_slot is not None:
        rec_nonce, rec_ct = recovery_slot
        if len(rec_nonce) != NONCE_SIZE or len(rec_ct) != WRAPPED_DEK_SIZE:
            raise FormatError("copied recovery slot has the wrong size")
    elif recovery_key is not None:
        rec_nonce = generate_nonce()
        rec_ct = aead_encrypt(
            derive_rkek(recovery_key), rec_nonce, dek, _recovery_aad(raw)
        )
    else:
        rec_nonce = bytes(NONCE_SIZE)
        rec_ct = bytes(WRAPPED_DEK_SIZE)

    encoded = raw + pw_nonce + pw_ct + rec_nonce + rec_ct
    if len(encoded) != KEYFILE_SIZE:  # pragma: no cover - guards the layout constants
        raise FormatError(
            f"encoded keyfile is {len(encoded)} bytes, expected {KEYFILE_SIZE}"
        )
    return encoded


def decode_keyfile(data: bytes) -> Keyfile:
    """Parse a keyfile. Raises :class:`FormatError` on anything malformed."""
    if len(data) != KEYFILE_SIZE:
        raise FormatError(
            f"keyfile must be {KEYFILE_SIZE} bytes, got {len(data)}"
        )
    if data[_OFF_MAGIC:_OFF_VERSION] != KEYFILE_MAGIC:
        raise MagicMismatchError("not a pipassword keyfile (bad magic)")

    (version,) = struct.unpack_from("<H", data, _OFF_VERSION)
    if version != KEYFILE_VERSION:
        raise UnsupportedVersionError(
            f"keyfile format version {version} is not supported by this build "
            f"(expected {KEYFILE_VERSION}); upgrade pipassword"
        )

    kdf_id = data[_OFF_KDF_ID]
    if kdf_id != KDF_ID_ARGON2ID:
        raise UnsupportedVersionError(f"unknown KDF id {kdf_id}")

    (generation,) = struct.unpack_from("<I", data, _OFF_GENERATION)
    (memory_cost,) = struct.unpack_from("<I", data, _OFF_MEMORY_COST)

    # KdfParams validates; surface it as a FormatError since the cause is the file.
    try:
        params = KdfParams(
            time_cost=data[_OFF_TIME_COST],
            memory_cost_kib=memory_cost,
            parallelism=data[_OFF_PARALLELISM],
        )
    except Exception as exc:
        raise FormatError(f"keyfile has invalid KDF parameters: {exc}") from exc

    slots = data[_OFF_SLOTS]
    if not slots & (SLOT_PASSWORD | SLOT_RECOVERY):
        raise FormatError("keyfile declares no usable slots")

    return Keyfile(
        vault_uuid=data[_OFF_VAULT_UUID:_OFF_GENERATION],
        generation=generation,
        params=params,
        salt=data[_OFF_SALT:_OFF_SLOTS],
        slots=slots,
        pw_nonce=data[_OFF_PW_NONCE:_OFF_PW_CT],
        pw_ct=data[_OFF_PW_CT:_OFF_REC_NONCE],
        rec_nonce=data[_OFF_REC_NONCE:_OFF_REC_CT],
        rec_ct=data[_OFF_REC_CT:KEYFILE_SIZE],
        raw=bytes(data),
    )


# ------------------------------------------------------------------- file layer


def ensure_dir(path: Path, mode: int = DIR_MODE) -> Path:
    """Create a directory with restrictive permissions (requirement 2.12).

    ``mkdir`` applies the umask to ``mode``, so permissions are set explicitly
    afterwards. An existing directory is tightened too: a vault directory that was
    created before this was enforced should not stay world-readable.
    """
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - e.g. a read-only mount
        pass
    return path


def atomic_write(path: Path, data: bytes, mode: int = FILE_MODE) -> None:
    """Write a file atomically, durably, and with restrictive permissions.

    Temp file in the same directory, fsync, then ``os.replace``, then fsync the
    directory so the rename itself survives power loss. The legacy project rewrote
    ``config.ini`` in place, so a crash mid-write could destroy the only copy of the
    encryption key.

    Permissions are set on the descriptor before any bytes are written, so the file is
    never briefly world-readable while it contains key material.
    """
    parent = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=parent, prefix=".tmp-", suffix=path.suffix)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise

    dir_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - not supported on every filesystem
        pass
    finally:
        os.close(dir_fd)


def keyfile_path(vault_dir: Path, generation: int) -> Path:
    return vault_dir / f"keys.{generation}.mpk"


def find_keyfile_generations(vault_dir: Path) -> list[int]:
    """Return keyfile generations present at the top level, highest first.

    Deliberately does not recurse. Rotation moves superseded generations into
    ``archive/``, and those must not be offered for unlocking, because an old
    generation means the old master password still works. See design section 3.1.
    """
    if not vault_dir.is_dir():
        return []
    generations = []
    for entry in vault_dir.iterdir():
        if not entry.is_file():
            continue
        match = _KEYFILE_NAME_RE.match(entry.name)
        if match:
            generations.append(int(match.group(1)))
    return sorted(generations, reverse=True)


def load_keyfile(vault_dir: Path) -> Keyfile:
    """Load the newest parseable keyfile.

    Tries generations from highest down, so a partially written or damaged newest
    generation falls back to the previous one rather than making the vault unopenable.
    Failures are collected and reported together.
    """
    generations = find_keyfile_generations(vault_dir)
    if not generations:
        raise KeyfileNotFoundError(
            f"no keyfile found in {vault_dir}. A keyfile is required to open the "
            f"vault; if you have a backup of keys.N.mpk, restore it here."
        )

    failures: dict[int, str] = {}
    for generation in generations:
        path = keyfile_path(vault_dir, generation)
        try:
            return decode_keyfile(path.read_bytes())
        except (FormatError, OSError) as exc:
            failures[generation] = str(exc)

    raise NoUsableKeyfileError(
        f"found {len(generations)} keyfile(s) in {vault_dir} but none could be read: "
        + "; ".join(f"keys.{gen}.mpk: {why}" for gen, why in failures.items()),
        failures=failures,
    )


def create_keyfile(
    vault_dir: Path,
    password: str | bytes,
    *,
    params: KdfParams | None = None,
    vault_uuid: bytes | None = None,
    dek: bytes | None = None,
    recovery_key: bytes | None = None,
    generation: int = 1,
    check_memory: bool = True,
) -> tuple[Keyfile, bytes]:
    """Create and write a new keyfile generation.

    Returns the parsed keyfile and the recovery key, which the caller must show to the
    user exactly once (requirement 6.1).

    Refuses to overwrite an existing generation: keyfiles are immutable, and rotation
    appends (requirement 6.6).
    """
    params = KdfParams() if params is None else params
    if check_memory:
        require_memory_available(params)

    ensure_dir(vault_dir)
    path = keyfile_path(vault_dir, generation)
    if path.exists():
        raise GenerationExistsError(
            f"{path.name} already exists; keyfiles are immutable and rotation "
            f"appends a new generation"
        )

    vault_uuid = uuid.uuid4().bytes if vault_uuid is None else vault_uuid
    dek = generate_dek() if dek is None else dek
    recovery_key = generate_recovery_key() if recovery_key is None else recovery_key

    encoded = encode_keyfile(
        vault_uuid=vault_uuid,
        generation=generation,
        params=params,
        salt=generate_salt(),
        dek=dek,
        password=password,
        recovery_key=recovery_key,
    )
    atomic_write(path, encoded)

    # Verify by reading back from disk rather than trusting the in-memory bytes. A
    # keyfile that cannot be reopened is a total loss, so it is worth the extra read.
    verified = decode_keyfile(path.read_bytes())
    recovered = verified.unwrap_with_password(password, check_memory=False)
    if recovered != dek:  # pragma: no cover - would indicate a serious bug
        raise FormatError("keyfile verification failed immediately after writing")

    return verified, recovery_key


def rotate_keyfile(
    vault_dir: Path,
    keyfile: Keyfile,
    dek: bytes,
    new_password: str | bytes,
    *,
    params: KdfParams | None = None,
    check_memory: bool = True,
) -> Keyfile:
    """Write a new generation wrapping the same DEK under a new password.

    The recovery slot is copied verbatim, so the printed recovery key keeps working and
    the user does not need it in hand to change their password. This is why the
    recovery slot's associated data excludes the generation and salt.

    Does not remove the superseded generation; the caller archives it after confirming
    the new one opens. See design section 3.1.
    """
    params = keyfile.params if params is None else params
    if check_memory:
        require_memory_available(params)

    generation = keyfile.generation + 1
    path = keyfile_path(vault_dir, generation)
    if path.exists():
        raise GenerationExistsError(f"{path.name} already exists")

    recovery_slot = (
        (keyfile.rec_nonce, keyfile.rec_ct) if keyfile.has_recovery_slot else None
    )
    encoded = encode_keyfile(
        vault_uuid=keyfile.vault_uuid,
        generation=generation,
        params=params,
        salt=generate_salt(),
        dek=dek,
        password=new_password,
        recovery_slot=recovery_slot,
    )
    atomic_write(path, encoded)

    verified = decode_keyfile(path.read_bytes())
    if verified.unwrap_with_password(new_password, check_memory=False) != dek:
        raise FormatError("rotated keyfile verification failed")  # pragma: no cover
    return verified


# =============================================================================
# Log files
# =============================================================================
#
# A log is a fixed header followed by independently encrypted, length-prefixed
# frames. Three properties fall out of that shape, and all three matter on a
# battery-powered handheld:
#
#   * Appending never rewrites earlier bytes, so a power cut can damage at most
#     the trailing frame rather than the whole file.
#   * Each frame carries its own length and its own authentication tag, so a
#     truncated tail is detectable and skippable, and a corrupt frame in the
#     middle does not hide the frames after it.
#   * The AAD binds the header, which contains the vault and device UUIDs, so a
#     frame cannot be transplanted into another device's log or another vault.
#
# Only one device ever writes a given log file. That is what makes Syncthing
# conflicts structurally impossible (requirement 3.2), and it is also why append
# is safe without any locking between machines.

LOG_MAGIC = b"PIPWLOG\x00"
LOG_VERSION = 1
LOG_HEADER_SIZE = 42

_LOG_OFF_MAGIC = 0
_LOG_OFF_VERSION = 8
_LOG_OFF_VAULT_UUID = 10
_LOG_OFF_DEVICE_UUID = 26

_FRAME_LEN_SIZE = 4

MAX_FRAME_SIZE = 1 << 20
"""Reject a frame length above 1 MiB.

A corrupted length prefix would otherwise cause a huge allocation, or make the
reader seek far past the end of the file looking for a boundary that is not
there. Real events are a few hundred bytes, so this is generous by three orders
of magnitude while still bounding the damage.
"""

__all__ += [
    "LOG_MAGIC",
    "LOG_VERSION",
    "LOG_HEADER_SIZE",
    "MAX_FRAME_SIZE",
    "LogHeader",
    "LogAnomaly",
    "LogReadResult",
    "encode_log_header",
    "decode_log_header",
    "create_log",
    "append_frame",
    "append_frames",
    "read_log",
    "repair_log",
    "log_filename",
    "find_logs",
]


class LogFormatError(FormatError):
    """A log file's header is not well formed."""


__all__.append("LogFormatError")


@dataclass(frozen=True, **SLOTS)
class LogHeader:
    vault_uuid: bytes
    device_uuid: bytes
    raw: bytes

    @property
    def vault_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.vault_uuid))

    @property
    def device_uuid_str(self) -> str:
        return str(uuid.UUID(bytes=self.device_uuid))


@dataclass(frozen=True, **SLOTS)
class LogAnomaly:
    """Something wrong with a frame, reported rather than raised.

    Requirement 3.9: a damaged frame must not prevent the rest of the log from
    loading. The user is told what happened; they are not handed a dead vault.
    """

    offset: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"offset {self.offset}: {self.kind}: {self.detail}"


@dataclass(frozen=True, **SLOTS)
class LogReadResult:
    header: LogHeader
    payloads: list[bytes]
    anomalies: list[LogAnomaly]
    valid_end: int
    """Byte offset just past the last frame that decrypted successfully.

    :func:`repair_log` truncates to this, which discards a half-written tail
    without touching anything that was complete.
    """

    @property
    def ok(self) -> bool:
        return not self.anomalies


def encode_log_header(vault_uuid: bytes, device_uuid: bytes) -> bytes:
    if len(vault_uuid) != 16:
        raise LogFormatError(f"vault_uuid must be 16 bytes, got {len(vault_uuid)}")
    if len(device_uuid) != 16:
        raise LogFormatError(f"device_uuid must be 16 bytes, got {len(device_uuid)}")
    header = bytearray(LOG_HEADER_SIZE)
    header[_LOG_OFF_MAGIC:_LOG_OFF_VERSION] = LOG_MAGIC
    struct.pack_into("<H", header, _LOG_OFF_VERSION, LOG_VERSION)
    header[_LOG_OFF_VAULT_UUID:_LOG_OFF_DEVICE_UUID] = vault_uuid
    header[_LOG_OFF_DEVICE_UUID:LOG_HEADER_SIZE] = device_uuid
    return bytes(header)


def decode_log_header(data: bytes) -> LogHeader:
    if len(data) < LOG_HEADER_SIZE:
        raise LogFormatError(
            f"log header must be {LOG_HEADER_SIZE} bytes, got {len(data)}"
        )
    raw = bytes(data[:LOG_HEADER_SIZE])
    if raw[_LOG_OFF_MAGIC:_LOG_OFF_VERSION] != LOG_MAGIC:
        raise LogFormatError("not a pipassword log (bad magic)")
    (version,) = struct.unpack_from("<H", raw, _LOG_OFF_VERSION)
    if version != LOG_VERSION:
        raise UnsupportedVersionError(
            f"log format version {version} is not supported by this build "
            f"(expected {LOG_VERSION}); upgrade pipassword"
        )
    return LogHeader(
        vault_uuid=raw[_LOG_OFF_VAULT_UUID:_LOG_OFF_DEVICE_UUID],
        device_uuid=raw[_LOG_OFF_DEVICE_UUID:LOG_HEADER_SIZE],
        raw=raw,
    )


def _frame_aad(header_raw: bytes, frame_len: int) -> bytes:
    """Associated data for a frame: the log header plus this frame's length.

    Including the header binds the frame to its vault and its device, so frames
    cannot be moved between logs. Including the length stops a frame being
    re-cut at a different boundary.
    """
    return header_raw + struct.pack("<I", frame_len)


def log_filename(device_name: str, device_uuid: bytes) -> str:
    """Build a log filename.

    The UUID prefix guarantees uniqueness even if two devices share a hostname;
    the human-readable part exists so that ``ls`` in a synced folder is
    intelligible.
    """
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", device_name).strip("-").lower() or "device"
    return f"{safe}-{device_uuid.hex()[:8]}.mpl"


def find_logs(log_dir: Path) -> list[Path]:
    """All log files, sorted by name for deterministic iteration."""
    if not log_dir.is_dir():
        return []
    return sorted(p for p in log_dir.iterdir() if p.is_file() and p.suffix == ".mpl")


def create_log(path: Path, vault_uuid: bytes, device_uuid: bytes) -> LogHeader:
    """Create a log file with its header, or validate an existing one.

    Idempotent: if the file already exists its header is parsed and checked
    against the expected UUIDs, which catches a device id collision (the one way
    requirement 3.2 could be violated).
    """
    header_bytes = encode_log_header(vault_uuid, device_uuid)
    if path.exists():
        existing = decode_log_header(path.read_bytes()[:LOG_HEADER_SIZE])
        if existing.vault_uuid != vault_uuid:
            raise LogFormatError(
                f"{path.name} belongs to vault {existing.vault_uuid_str}, "
                f"not {uuid.UUID(bytes=vault_uuid)}"
            )
        if existing.device_uuid != device_uuid:
            raise LogFormatError(
                f"{path.name} belongs to device {existing.device_uuid_str}, "
                f"not {uuid.UUID(bytes=device_uuid)}"
            )
        return existing

    ensure_dir(path.parent)
    atomic_write(path, header_bytes)
    return decode_log_header(header_bytes)


def append_frames(path: Path, dek: bytes, payloads: list[bytes]) -> int:
    """Append encrypted frames to a log, durably. Returns bytes written.

    One ``fsync`` covers the whole batch, which matters on an SD card. Writing
    is append-only, so a failure part way through leaves earlier frames intact
    and at worst a partial trailing frame, which the reader skips.
    """
    if not payloads:
        return 0
    header = decode_log_header(path.read_bytes()[:LOG_HEADER_SIZE])

    blob = bytearray()
    for payload in payloads:
        nonce = generate_nonce()
        frame_len = NONCE_SIZE + len(payload) + TAG_SIZE
        if frame_len > MAX_FRAME_SIZE:
            raise LogFormatError(
                f"frame of {frame_len} bytes exceeds the {MAX_FRAME_SIZE} byte limit"
            )
        ciphertext = aead_encrypt(
            dek, nonce, payload, _frame_aad(header.raw, frame_len)
        )
        blob += struct.pack("<I", frame_len) + nonce + ciphertext

    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, bytes(blob))
        os.fsync(fd)
    finally:
        os.close(fd)
    return len(blob)


def append_frame(path: Path, dek: bytes, payload: bytes) -> int:
    return append_frames(path, dek, [payload])


def read_log(path: Path, dek: bytes) -> LogReadResult:
    """Read and decrypt every frame, collecting anomalies instead of raising.

    Requirement 3.9. The scan is driven by each frame's explicit length, so a
    frame that fails authentication does not hide the frames after it: the
    reader records the problem and continues at the next boundary. Scanning
    stops only when a boundary itself cannot be trusted, which is the case for a
    truncated tail or an implausible length.
    """
    data = path.read_bytes()
    header = decode_log_header(data)

    payloads: list[bytes] = []
    anomalies: list[LogAnomaly] = []
    offset = LOG_HEADER_SIZE
    valid_end = LOG_HEADER_SIZE
    total = len(data)

    while offset < total:
        if total - offset < _FRAME_LEN_SIZE:
            anomalies.append(
                LogAnomaly(
                    offset,
                    "truncated",
                    f"{total - offset} trailing byte(s), too short for a length "
                    f"prefix; likely an interrupted write",
                )
            )
            break

        (frame_len,) = struct.unpack_from("<I", data, offset)
        body_start = offset + _FRAME_LEN_SIZE

        if frame_len < NONCE_SIZE + TAG_SIZE or frame_len > MAX_FRAME_SIZE:
            anomalies.append(
                LogAnomaly(
                    offset,
                    "bad_length",
                    f"implausible frame length {frame_len}; cannot locate the next "
                    f"frame boundary, so scanning stopped here",
                )
            )
            break

        if total - body_start < frame_len:
            anomalies.append(
                LogAnomaly(
                    offset,
                    "truncated",
                    f"frame declares {frame_len} bytes but only "
                    f"{total - body_start} remain; likely an interrupted write",
                )
            )
            break

        nonce = data[body_start : body_start + NONCE_SIZE]
        ciphertext = data[body_start + NONCE_SIZE : body_start + frame_len]
        try:
            payloads.append(
                aead_decrypt(
                    dek, nonce, ciphertext, _frame_aad(header.raw, frame_len)
                )
            )
            valid_end = body_start + frame_len
        except AuthenticationError:
            anomalies.append(
                LogAnomaly(
                    offset,
                    "auth_failed",
                    "frame did not authenticate; it was tampered with, or "
                    "encrypted with a different key",
                )
            )

        offset = body_start + frame_len

    return LogReadResult(
        header=header,
        payloads=payloads,
        anomalies=anomalies,
        valid_end=valid_end,
    )


def repair_log(path: Path, dek: bytes) -> tuple[int, list[LogAnomaly]]:
    """Truncate a log to its last fully valid frame.

    Returns the number of bytes discarded and the anomalies that prompted it.

    Only ever removes a damaged *tail*. If the log contains a bad frame with
    good frames after it, nothing is truncated, because discarding valid data to
    tidy up a corrupt frame would be the wrong trade. In that case the anomalies
    are returned for reporting and the file is left alone.
    """
    result = read_log(path, dek)
    if not result.anomalies:
        return 0, []

    tail_only = all(a.offset >= result.valid_end for a in result.anomalies)
    if not tail_only:
        return 0, result.anomalies

    size = path.stat().st_size
    discarded = size - result.valid_end
    if discarded <= 0:
        return 0, result.anomalies

    fd = os.open(path, os.O_WRONLY)
    try:
        os.ftruncate(fd, result.valid_end)
        os.fsync(fd)
    finally:
        os.close(fd)
    return discarded, result.anomalies


def archive_keyfile(vault_dir: Path, generation: int) -> Path:
    """Move a superseded keyfile generation into ``archive/``.

    Called after a rotation has been written and verified. This is the step that
    makes rotation meaningful: while an old generation remains readable at the top
    level, the old master password still opens the vault, because
    :func:`load_keyfile` would fall back to it. Moving rather than deleting keeps
    the file available if something went wrong, and the CLI tells the user to
    delete ``archive/`` once satisfied. See design section 3.1.
    """
    source = keyfile_path(vault_dir, generation)
    if not source.is_file():
        raise KeyfileNotFoundError(f"{source.name} does not exist")

    archive = ensure_dir(vault_dir / "archive")
    target = archive / source.name
    if target.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        target = archive / f"{source.stem}.{stamp}{source.suffix}"
    os.replace(source, target)
    return target


__all__.append("archive_keyfile")
