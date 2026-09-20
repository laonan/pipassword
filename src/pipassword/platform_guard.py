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

#: Minimum interpreter. The Beepy's recommended image is 32-bit Raspberry Pi OS
#: Bullseye, which ships Python 3.9.2 -- so 3.9 is the real floor, not 3.11.
REQUIRED_PYTHON: tuple[int, int] = (3, 9)

SUPPORTED_SYSTEM = "Linux"

#: Architectures that work. 32-bit ARM is included: piwheels provides prebuilt
#: cryptography for armv6l/armv7l, and argon2-cffi-bindings builds from source in a
#: couple of minutes because it is plain C with cffi and needs no Rust toolchain.
SUPPORTED_MACHINES = frozenset({"aarch64", "armv7l", "armv6l"})

#: Architectures that work but will be slow. ARMv6 is single-core at ~1 GHz, so
#: Argon2id at the default 64 MiB will take a while. Worth a warning, not a refusal:
#: it is the user's device and `pipw calibrate` gives them the real number.
SLOW_MACHINES = frozenset({"armv6l"})

#: Set to "1" to bypass enforcement. For development on a non-target machine only.
OVERRIDE_ENV = "PIPASSWORD_ALLOW_UNSUPPORTED"

_DOC_HINT = (
    "pipassword runs on Linux on aarch64, armv7l or armv6l, with Python 3.9 or\n"
    "later. That covers both 32-bit and 64-bit Raspberry Pi OS from Bullseye on.\n"
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
            f"An ARM Linux CPU is required, one of {expected} "
            f"(found {machine or 'unknown'})."
        )

    return problems


def performance_warnings(machine: str | None = None) -> list[str]:
    """Non-fatal notes about a platform that works but will be slow."""
    machine = platform.machine() if machine is None else machine
    if machine in SLOW_MACHINES:
        return [
            f"{machine} is single-core and slow. Key derivation at the default "
            f"64 MiB may take many seconds; run 'pipw calibrate' before creating "
            f"a vault, since the setting is stored in the keyfile."
        ]
    return []


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
