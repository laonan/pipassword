"""Platform enforcement for supported targets.

Requirement 1.4 asks that an unsupported platform fail with an explanatory message
*before* a dependency import fails with a confusing one. That forces two properties
on this module:

1. It imports only the standard library, so it can run before ``cryptography`` or
   ``argon2-cffi`` are touched.
2. It is invoked from the entry point, never at package import. Otherwise the test
   suite and :file:`recover.py` could not run on a development machine, and pytest
   collection would die during import rather than reporting a skip.

The escape hatch exists for exactly that development case. It is intentionally
awkward to set by accident, and it warns every time it is honoured.
"""

from __future__ import annotations

import os
import platform
import sys

#: Minimum interpreter. Raspberry Pi OS Bookworm ships 3.11, which sets the floor.
REQUIRED_PYTHON: tuple[int, int] = (3, 11)

#: Only 64-bit ARM Linux is supported (requirement 1.1, 1.3). 32-bit Raspberry Pi OS
#: and ARMv6 boards are excluded because the required manylinux aarch64 wheels do not
#: apply to them, which would mean compiling cryptography on a Pi Zero.
SUPPORTED_SYSTEM = "Linux"
SUPPORTED_MACHINES = frozenset({"aarch64"})

#: Set to "1" to bypass enforcement. For development on a non-target machine only.
OVERRIDE_ENV = "PIPASSWORD_ALLOW_UNSUPPORTED"

_DOC_HINT = (
    "pipassword targets 64-bit Raspberry Pi OS (aarch64) only.\n"
    "32-bit Raspberry Pi OS and ARMv6 boards (original Pi Zero / Zero W) are\n"
    "unsupported: the required manylinux aarch64 wheels do not apply, so\n"
    "cryptography and argon2 would have to compile from source on the device.\n"
    f"For development on another machine, set {OVERRIDE_ENV}=1."
)


def check_platform(
    *,
    system: str | None = None,
    machine: str | None = None,
    python_version: tuple[int, ...] | None = None,
) -> list[str]:
    """Return a list of human-readable problems. Empty means supported.

    Arguments are injectable so the checks can be tested without a matching host.
    """
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    python_version = (
        sys.version_info[:2] if python_version is None else tuple(python_version)
    )

    problems: list[str] = []

    if python_version < REQUIRED_PYTHON:
        have = ".".join(str(p) for p in python_version)
        need = ".".join(str(p) for p in REQUIRED_PYTHON)
        problems.append(f"Python {need} or later is required (found {have}).")

    if system != SUPPORTED_SYSTEM:
        problems.append(
            f"{SUPPORTED_SYSTEM} is required (found {system or 'unknown'})."
        )

    if machine not in SUPPORTED_MACHINES:
        expected = ", ".join(sorted(SUPPORTED_MACHINES))
        problems.append(
            f"An {expected} CPU is required (found {machine or 'unknown'})."
        )

    return problems


def override_active(env: dict[str, str] | None = None) -> bool:
    """True when the development override is set."""
    source = os.environ if env is None else env
    return source.get(OVERRIDE_ENV, "") == "1"


def enforce(
    *,
    env: dict[str, str] | None = None,
    stream=None,
    **kwargs,
) -> None:
    """Exit with status 1 on an unsupported platform, unless overridden.

    ``kwargs`` are forwarded to :func:`check_platform` for testing.
    """
    stream = sys.stderr if stream is None else stream
    problems = check_platform(**kwargs)
    if not problems:
        return

    if override_active(env):
        print(
            f"warning: unsupported platform, continuing because {OVERRIDE_ENV}=1",
            file=stream,
        )
        for problem in problems:
            print(f"warning:   {problem}", file=stream)
        return

    print("error: unsupported platform.", file=stream)
    for problem in problems:
        print(f"  - {problem}", file=stream)
    print(file=stream)
    print(_DOC_HINT, file=stream)
    raise SystemExit(1)
