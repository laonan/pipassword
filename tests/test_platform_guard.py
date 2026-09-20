"""Tests for platform enforcement (requirements 1.1, 1.3, 1.4, 1.6)."""

from __future__ import annotations

import pytest

from pipassword import platform_guard as guard

SUPPORTED = {"system": "Linux", "machine": "aarch64", "python_version": (3, 11)}


def test_supported_target_has_no_problems():
    assert guard.check_platform(**SUPPORTED) == []


def test_newer_python_still_supported():
    assert guard.check_platform(**{**SUPPORTED, "python_version": (3, 13)}) == []


def test_old_python_rejected():
    problems = guard.check_platform(**{**SUPPORTED, "python_version": (3, 10)})
    assert len(problems) == 1
    assert "3.11" in problems[0]


def test_macos_rejected():
    """Requirement 1.3: macOS is explicitly out of scope."""
    problems = guard.check_platform(
        system="Darwin", machine="arm64", python_version=(3, 13)
    )
    assert any("Linux" in p for p in problems)
    assert any("aarch64" in p for p in problems)


@pytest.mark.parametrize("machine", ["armv6l", "armv7l", "x86_64", "i686"])
def test_non_aarch64_rejected(machine):
    """32-bit Raspberry Pi OS and ARMv6 boards have no usable wheels."""
    problems = guard.check_platform(
        system="Linux", machine=machine, python_version=(3, 11)
    )
    assert any("aarch64" in p for p in problems)


def test_enforce_is_silent_on_supported_target(capsys):
    guard.enforce(env={}, **SUPPORTED)
    assert capsys.readouterr().err == ""


def test_enforce_exits_with_status_1_and_explains(capsys):
    with pytest.raises(SystemExit) as excinfo:
        guard.enforce(
            env={}, system="Darwin", machine="arm64", python_version=(3, 13)
        )
    assert excinfo.value.code == 1

    err = capsys.readouterr().err
    assert "unsupported platform" in err
    # Requirement 1.4: the message must name the requirement, not just fail.
    assert "aarch64" in err
    assert guard.OVERRIDE_ENV in err


def test_override_permits_unsupported_platform_with_warning(capsys):
    guard.enforce(
        env={guard.OVERRIDE_ENV: "1"},
        system="Darwin",
        machine="arm64",
        python_version=(3, 13),
    )
    err = capsys.readouterr().err
    assert "warning" in err
    assert guard.OVERRIDE_ENV in err


def test_override_requires_exact_value():
    """A truthy-looking value must not silently disable enforcement."""
    for value in ["0", "", "true", "yes"]:
        assert not guard.override_active({guard.OVERRIDE_ENV: value})
    assert guard.override_active({guard.OVERRIDE_ENV: "1"})


def test_importing_package_does_not_enforce():
    """Requirement: package import must be side-effect free.

    The legacy minipassword.commands ran parse_args() at import time, so importing the
    library parsed sys.argv and could exit. Importing must never do that, and must not
    run the platform check either, or the test suite could not run off-target.
    """
    import importlib

    import pipassword

    importlib.reload(pipassword)  # must not raise SystemExit on this dev machine


def test_cli_import_has_no_side_effects():
    """Importing the CLI must not parse arguments."""
    import importlib

    from pipassword import cli

    importlib.reload(cli)
    parser = cli.build_parser()
    assert parser.prog == "pipw"
