"""Tests for platform enforcement (requirements 1.1, 1.3, 1.4, 1.6)."""

from __future__ import annotations

import pytest

from pipassword import platform_guard as guard

SUPPORTED = {"system": "Linux", "machine": "aarch64", "python_version": (3, 11)}

#: The Beepy's recommended image: 32-bit Raspberry Pi OS Bullseye.
BEEPY = {"system": "Linux", "machine": "armv7l", "python_version": (3, 9)}


def test_supported_target_has_no_problems():
    assert guard.check_platform(**SUPPORTED) == []


def test_newer_python_still_supported():
    assert guard.check_platform(**{**SUPPORTED, "python_version": (3, 13)}) == []


def test_old_python_rejected():
    problems = guard.check_platform(**{**SUPPORTED, "python_version": (3, 8)})
    assert len(problems) == 1
    assert "3.9" in problems[0]


def test_python_39_is_supported():
    """Raspberry Pi OS Bullseye ships 3.9.2, and that is what the Beepy runs."""
    assert guard.check_platform(**{**SUPPORTED, "python_version": (3, 9)}) == []


def test_macos_rejected():
    """Requirement 1.3: macOS is explicitly out of scope."""
    problems = guard.check_platform(
        system="Darwin", machine="arm64", python_version=(3, 13)
    )
    assert any("Linux" in p for p in problems)
    assert any("aarch64" in p for p in problems)


@pytest.mark.parametrize("machine", ["aarch64", "armv7l", "armv6l"])
def test_arm_architectures_are_supported(machine):
    """32-bit ARM works: piwheels prebuilds cryptography, and argon2-cffi-bindings
    is plain C with cffi so it builds from source without a Rust toolchain."""
    assert (
        guard.check_platform(
            system="Linux", machine=machine, python_version=(3, 9)
        )
        == []
    )


@pytest.mark.parametrize("machine", ["x86_64", "i686", "riscv64"])
def test_non_arm_rejected(machine):
    problems = guard.check_platform(
        system="Linux", machine=machine, python_version=(3, 11)
    )
    assert any("ARM" in p for p in problems)


def test_beepy_configuration_is_accepted():
    """The exact platform in production: armv7l, Bullseye, Python 3.9.2."""
    assert guard.check_platform(**BEEPY) == []
    assert guard.enforce(env={}, **BEEPY) is None


def test_armv6_warns_about_speed_without_refusing():
    assert guard.performance_warnings("armv6l"), "ARMv6 should warn"
    assert "calibrate" in guard.performance_warnings("armv6l")[0]


@pytest.mark.parametrize("machine", ["aarch64", "armv7l"])
def test_faster_architectures_do_not_warn(machine):
    assert guard.performance_warnings(machine) == []


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
    assert "armv7l" in err  # must not tell a 32-bit user to reinstall their OS
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
