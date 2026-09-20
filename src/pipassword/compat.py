"""Python version compatibility shims.

The target hardware forced this module into existence. The Beepy's recommended OS
image is 32-bit Raspberry Pi OS **Bullseye**, which ships **Python 3.9.2** — not the
3.11 originally assumed. Rather than require an OS reinstall that would also mean
rebuilding the working sharp-drm, fbterm, fcitx and Google Pinyin stack, the floor
was lowered to 3.9.

Two things are needed for that, and both are kept narrow on purpose so the rest of
the codebase reads the same on every version.
"""

from __future__ import annotations

import sys

__all__ = ["SLOTS", "load_toml", "TomlDecodeError", "PY_VERSION"]

PY_VERSION = sys.version_info[:2]

SLOTS: dict[str, bool] = {"slots": True} if PY_VERSION >= (3, 10) else {}
"""``dataclass`` keyword arguments for slotted classes, where available.

``@dataclass(slots=True)`` arrived in 3.10. Spreading this dict means 3.10+ still
gets the smaller instances — which matters a little when folding ten thousand
``Record`` objects on a board with under 300 MB free — while 3.9 simply gets
ordinary ``__dict__``-backed dataclasses.

Usage::

    @dataclass(frozen=True, **SLOTS)
    class Thing: ...
"""

if PY_VERSION >= (3, 11):
    import tomllib as _toml

    TomlDecodeError = _toml.TOMLDecodeError
else:  # pragma: no cover - exercised on 3.9/3.10 only
    try:
        import tomli as _toml  # type: ignore[no-redef]

        TomlDecodeError = _toml.TOMLDecodeError  # type: ignore[attr-defined]
    except ImportError:  # pragma: no cover
        _toml = None  # type: ignore[assignment]

        class TomlDecodeError(ValueError):  # type: ignore[no-redef]
            """Raised when TOML cannot be parsed and no parser is installed."""


def load_toml(text: str) -> dict:
    """Parse TOML from a string.

    ``tomllib`` is standard library from 3.11; ``tomli`` is the identical backport
    for older versions and is declared as a conditional dependency.

    A missing parser is reported as a parse failure rather than an ImportError,
    because the only TOML this project reads is its own small non-secret config
    file. Failing to read it must never be the reason a vault cannot be opened.
    """
    if _toml is None:  # pragma: no cover
        raise TomlDecodeError(
            "no TOML parser available; install tomli (pip install tomli)"
        )
    return _toml.loads(text)
