"""Cryptographic primitives.

This module is the whole trust base of the vault, so it deliberately does very little
and invents nothing. Every construction is a standard primitive used in its intended
mode, and :file:`FORMAT.md` specifies each one precisely enough to reimplement.

Key hierarchy (design section 2)::

    master password --Argon2id(salt, t, m, p)--> KEK  --unwraps--+
                                                                 +--> DEK --> records
    recovery key ----BLAKE2b(keyed, personalised)--> RKEK --unwraps--+

Two independent unwrap paths reach one DEK, so a forgotten master password is not
fatal, and rotating the password rewraps 32 bytes instead of re-encrypting the vault.

Why ``argon2-cffi`` rather than PyNaCl/libsodium: libsodium implements Argon2id
single-threaded and does not expose the parallelism parameter. The Pi Zero 2 W has
four cores, and ``parallelism=4`` buys roughly four times the KDF work at the same
unlock latency.

Why ChaCha20-Poly1305 rather than AES-GCM: no 64-bit Raspberry Pi except the Pi 5's
BCM2712 ships the optional ARMv8 AES instructions, so AES runs in software on the
target hardware while ChaCha20 does not need hardware help.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from dataclasses import dataclass

from .compat import SLOTS
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = [
    "CryptoError",
    "AuthenticationError",
    "ParameterError",
    "InsufficientMemoryError",
    "KdfParams",
    "DEFAULT_KDF_PARAMS",
    "MemoryCheck",
    "SALT_SIZE",
    "NONCE_SIZE",
    "KEY_SIZE",
    "TAG_SIZE",
    "RECOVERY_KEY_SIZE",
    "derive_kek",
    "derive_rkek",
    "aead_encrypt",
    "aead_decrypt",
    "generate_dek",
    "generate_salt",
    "generate_nonce",
    "generate_recovery_key",
    "format_recovery_key",
    "parse_recovery_key",
    "check_memory_available",
    "read_mem_available_kib",
    "constant_time_equal",
    "wipe",
]

# --------------------------------------------------------------------------- sizes

SALT_SIZE = 16
"""Argon2id salt length, matching the keyfile layout in FORMAT.md."""

NONCE_SIZE = 12
"""ChaCha20-Poly1305 nonce length (RFC 8439)."""

KEY_SIZE = 32
"""Length of the KEK, RKEK, and DEK."""

TAG_SIZE = 16
"""Poly1305 authentication tag length."""

RECOVERY_KEY_SIZE = 32
"""Recovery key length. 256 bits, so it needs no stretching, only separation."""

RKEK_PERSON = b"pipw-rkey"
"""BLAKE2b personalisation for recovery-key derivation. Fixed forever; changing it
would make existing recovery keys unusable."""

MEMORY_HEADROOM = 1.25
"""Require 25% more available memory than Argon2id will allocate.

Argon2id allocates ``memory_cost`` KiB in one block, and the interpreter plus
Syncthing also need room. Refusing early with a clear message is much better than
being OOM-killed mid-unlock on a 512 MB Pi Zero 2 W (requirement 2.5).
"""


# ---------------------------------------------------------------------- exceptions


class CryptoError(Exception):
    """Base class. No subclass ever embeds key or plaintext material in its message."""


class AuthenticationError(CryptoError):
    """AEAD authentication failed: wrong key, wrong AAD, or tampered ciphertext.

    Raised instead of ``cryptography.exceptions.InvalidTag`` so that callers, and
    :file:`recover.py`, need not import provider-specific exception types.
    """


class ParameterError(CryptoError):
    """A parameter is structurally invalid, for example a short salt."""


class InsufficientMemoryError(CryptoError):
    """Argon2id would allocate more memory than the machine has available."""


# --------------------------------------------------------------------- kdf params


@dataclass(frozen=True, **SLOTS)
class KdfParams:
    """Argon2id cost parameters.

    Stored in the keyfile so any device can open a vault created on any other
    (requirement 2.3). Because there is one KEK per vault, the weakest device sets
    these for every device.
    """

    time_cost: int = 3
    memory_cost_kib: int = 65536  # 64 MiB
    parallelism: int = 4

    def __post_init__(self) -> None:
        if self.time_cost < 1:
            raise ParameterError("time_cost must be at least 1")
        if self.parallelism < 1:
            raise ParameterError("parallelism must be at least 1")
        # Argon2 requires m >= 8p; below that the reference implementation errors.
        if self.memory_cost_kib < 8 * self.parallelism:
            raise ParameterError(
                f"memory_cost_kib must be at least 8 * parallelism "
                f"({8 * self.parallelism}), got {self.memory_cost_kib}"
            )

    @property
    def memory_cost_mib(self) -> float:
        return self.memory_cost_kib / 1024

    @property
    def memory_human(self) -> str:
        """Human-readable memory size, in KiB below one MiB.

        Test parameters use tiny values like 64 KiB, which would otherwise render
        as a confusing "0 MiB".
        """
        if self.memory_cost_kib < 1024:
            return f"{self.memory_cost_kib} KiB"
        return f"{self.memory_cost_mib:.0f} MiB"


DEFAULT_KDF_PARAMS = KdfParams()
"""Defaults from requirement 2.2.

``memory_cost`` is capped at 64 MiB by the Pi Zero 2 W's 512 MB of RAM, which is
shared with Syncthing (50-100 MB). ``parallelism=4`` matches its four cores.
"""


# ------------------------------------------------------------------ derivations


def _normalise_password(password: str | bytes) -> bytes:
    """Encode a password to bytes, NFC-normalising text first.

    This matters more here than in most projects. Vault entries and quite possibly the
    master passphrase contain Chinese characters entered through Google Pinyin under
    fcitx, and the same visually identical string can be produced in different Unicode
    normalisation forms by different input paths. Without normalisation, a passphrase
    accepted on one device could be rejected on another, with no way to tell why.

    NFC is chosen because it is what IMEs and Linux input stacks emit by default.

    ``bytes`` input is passed through untouched: the caller has already committed to an
    exact byte sequence, and silently reinterpreting it would be worse.
    """
    if isinstance(password, bytes):
        return password
    if not isinstance(password, str):
        raise ParameterError("password must be str or bytes")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_kek(
    password: str | bytes,
    salt: bytes,
    params: KdfParams = DEFAULT_KDF_PARAMS,
) -> bytes:
    """Derive the key-encryption key from the master password via Argon2id.

    Requirements 2.1, 2.2.
    """
    if len(salt) != SALT_SIZE:
        raise ParameterError(f"salt must be {SALT_SIZE} bytes, got {len(salt)}")

    return hash_secret_raw(
        secret=_normalise_password(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_rkek(recovery_key: bytes) -> bytes:
    """Derive the recovery key-encryption key from the recovery key.

    A deliberately fast derivation, not a password hash. The recovery key is 256
    uniformly random bits, so it has nothing to stretch; all that is needed is domain
    separation so it cannot be confused with any other key in the system. Keyed
    BLAKE2b with a fixed personalisation provides exactly that, from the standard
    library, which also keeps :file:`recover.py` minimal.

    Requirement 6.1, 6.2.
    """
    if len(recovery_key) != RECOVERY_KEY_SIZE:
        raise ParameterError(
            f"recovery key must be {RECOVERY_KEY_SIZE} bytes, got {len(recovery_key)}"
        )
    return hashlib.blake2b(
        b"", key=recovery_key, person=RKEK_PERSON, digest_size=KEY_SIZE
    ).digest()


# ------------------------------------------------------------------------- aead


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305 encrypt. Returns ciphertext with the tag appended.

    ``aad`` is never optional anywhere in this project: every ciphertext is bound to
    its file header so that version and KDF parameters are authenticated and cannot be
    downgraded (requirement 2.9).
    """
    _check_key(key)
    _check_nonce(nonce)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305 decrypt and verify.

    Raises :class:`AuthenticationError` on any failure. The message is deliberately
    uninformative: distinguishing "wrong password" from "tampered file" would leak
    more than it helps, and the caller has the context to say something useful.
    """
    _check_key(key)
    _check_nonce(nonce)
    if len(ciphertext) < TAG_SIZE:
        raise AuthenticationError("ciphertext is too short to contain a tag")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("authentication failed") from exc


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ParameterError(f"key must be {KEY_SIZE} bytes, got {len(key)}")


def _check_nonce(nonce: bytes) -> None:
    if len(nonce) != NONCE_SIZE:
        raise ParameterError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")


# --------------------------------------------------------------------- generation


def generate_dek() -> bytes:
    """A fresh random data-encryption key (requirement 2.6)."""
    return secrets.token_bytes(KEY_SIZE)


def generate_salt() -> bytes:
    return secrets.token_bytes(SALT_SIZE)


def generate_nonce() -> bytes:
    """A random 96-bit nonce.

    Random rather than counter-based is safe at this scale: with per-event nonces the
    collision probability stays negligible far beyond the 10,000-record target, and a
    counter would have to be persisted and kept consistent across devices that each
    append to their own log.
    """
    return secrets.token_bytes(NONCE_SIZE)


def generate_recovery_key() -> bytes:
    """A fresh 256-bit recovery key (requirement 6.1)."""
    return secrets.token_bytes(RECOVERY_KEY_SIZE)


# ------------------------------------------------------- recovery key formatting

_GROUP_SIZE = 4
_RECOVERY_KEY_CHARS = 52
"""Base32 characters needed for 32 bytes: ceil(256 / 5) = 52, padding stripped."""


def format_recovery_key(recovery_key: bytes) -> str:
    """Render a recovery key as grouped Base32 for transcription onto paper.

    RFC 4648 Base32 is used because its alphabet is A-Z plus 2-7, which excludes
    ``0``, ``1``, ``8`` and ``9`` and so cannot produce the 0/O or 1/l/I confusions
    that make hand-copied keys fail. Grouping in fours gives the eye somewhere to
    rest::

        HZ4T-9PQB-... (13 groups)
    """
    if len(recovery_key) != RECOVERY_KEY_SIZE:
        raise ParameterError(
            f"recovery key must be {RECOVERY_KEY_SIZE} bytes, got {len(recovery_key)}"
        )
    encoded = base64.b32encode(recovery_key).decode("ascii").rstrip("=")
    groups = [
        encoded[i : i + _GROUP_SIZE] for i in range(0, len(encoded), _GROUP_SIZE)
    ]
    return "-".join(groups)


def parse_recovery_key(text: str) -> bytes:
    """Parse a hand-typed recovery key back to bytes.

    Deliberately forgiving about everything that does not change the value: case,
    grouping, dashes, spaces, and newlines are all ignored, because this string will be
    read off paper and typed on a thumb keyboard. It is strict about the decoded
    length, so a dropped character is an error rather than a mystery.
    """
    cleaned = re.sub(r"[\s\-]", "", text).upper()
    if not cleaned:
        raise ParameterError("recovery key is empty")
    if len(cleaned) != _RECOVERY_KEY_CHARS:
        raise ParameterError(
            f"recovery key must have {_RECOVERY_KEY_CHARS} characters excluding "
            f"separators, got {len(cleaned)}"
        )
    padding = "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(cleaned + padding, casefold=False)
    except Exception as exc:  # binascii.Error and friends
        raise ParameterError("recovery key contains invalid characters") from exc
    if len(raw) != RECOVERY_KEY_SIZE:
        raise ParameterError(
            f"recovery key decoded to {len(raw)} bytes, expected {RECOVERY_KEY_SIZE}"
        )
    return raw


# ------------------------------------------------------------------ memory check


@dataclass(frozen=True, **SLOTS)
class MemoryCheck:
    """Outcome of comparing Argon2id's appetite against available memory."""

    required_kib: int
    available_kib: int | None
    sufficient: bool
    detail: str

    @property
    def determinable(self) -> bool:
        """False when available memory could not be read, as on a non-Linux host."""
        return self.available_kib is not None


def read_mem_available_kib(meminfo: Path | str = "/proc/meminfo") -> int | None:
    """Read ``MemAvailable`` from :file:`/proc/meminfo`, in KiB.

    Returns ``None`` when it cannot be determined, which is the normal case on a
    development machine. ``MemAvailable`` is used rather than ``MemFree`` because the
    kernel's estimate accounts for reclaimable page cache, and ``MemFree`` on a
    long-running Pi is misleadingly small.
    """
    try:
        text = Path(meminfo).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None

    match = re.search(r"^MemAvailable:\s+(\d+)\s*kB", text, re.MULTILINE)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:  # pragma: no cover - regex already constrains this
        return None


def check_memory_available(
    params: KdfParams = DEFAULT_KDF_PARAMS,
    *,
    available_kib: int | None = None,
    meminfo: Path | str = "/proc/meminfo",
) -> MemoryCheck:
    """Report whether Argon2id can run without risking an OOM kill.

    Requirement 2.5. When availability cannot be determined the result is permissive:
    refusing to open a vault because :file:`/proc/meminfo` is absent would be worse
    than attempting it.
    """
    required = params.memory_cost_kib
    if available_kib is None:
        available_kib = read_mem_available_kib(meminfo)

    if available_kib is None:
        return MemoryCheck(
            required_kib=required,
            available_kib=None,
            sufficient=True,
            detail=(
                "available memory could not be determined; proceeding without a check"
            ),
        )

    needed = int(required * MEMORY_HEADROOM)
    if available_kib >= needed:
        return MemoryCheck(
            required_kib=required,
            available_kib=available_kib,
            sufficient=True,
            detail=(
                f"{available_kib // 1024} MiB available, "
                f"{needed // 1024} MiB needed including headroom"
            ),
        )

    return MemoryCheck(
        required_kib=required,
        available_kib=available_kib,
        sufficient=False,
        detail=(
            f"this vault needs {required // 1024} MiB for key derivation "
            f"({needed // 1024} MiB including headroom) but only "
            f"{available_kib // 1024} MiB is available. Close other programs "
            f"(Syncthing is a likely candidate) and try again."
        ),
    )


def require_memory_available(
    params: KdfParams = DEFAULT_KDF_PARAMS,
    *,
    available_kib: int | None = None,
    meminfo: Path | str = "/proc/meminfo",
) -> MemoryCheck:
    """Like :func:`check_memory_available`, but raise when insufficient."""
    result = check_memory_available(
        params, available_kib=available_kib, meminfo=meminfo
    )
    if not result.sufficient:
        raise InsufficientMemoryError(result.detail)
    return result


# ----------------------------------------------------------------------- hygiene


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare two secrets without leaking their contents through timing."""
    return hmac.compare_digest(a, b)


def wipe(buffer: bytearray) -> None:
    """Best-effort overwrite of a mutable buffer.

    Honest about the limitation: this only works on ``bytearray``. Python ``bytes``
    and ``str`` are immutable and may be copied freely by the interpreter, so key
    material that has ever been a ``bytes`` object cannot be reliably erased. The
    threat model excludes an attacker reading process memory while the vault is
    unlocked precisely because that is not solvable here (requirements, T-out-of-scope).

    It is still worth doing for the buffers we do control, and it makes the intent
    explicit at the call sites in ``Vault.close``.
    """
    if not isinstance(buffer, bytearray):
        raise ParameterError("wipe requires a bytearray")
    for i in range(len(buffer)):
        buffer[i] = 0


def _urandom_available() -> bool:  # pragma: no cover - sanity helper
    try:
        os.urandom(1)
        return True
    except NotImplementedError:
        return False
