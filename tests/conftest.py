"""Shared fixtures.

The legacy project's ``tests/test_manager.py`` constructed ``PasswordManager()`` with
no arguments, which resolved to the developer's real vault. Its ``test_delete_password``
deleted record id 1 and ``test_update_password`` overwrote it. The live legacy database
contains exactly one row, which is consistent with that having run.

So isolation here is autouse and unconditional rather than opt-in: a test cannot reach
a real vault path by forgetting a fixture. ``isolate_home`` is the mechanism, and
``test_isolation.py`` verifies it actually holds.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

#: Paths that must never be touched by the test suite. The legacy vault is listed
#: because the import tests (task 10) read from a path of that shape, and a fixture
#: mistake there would mean reading real credentials.
REAL_PATHS_FORBIDDEN = (
    "~/.minipassword",
    "~/.config/pipassword",
    "~/.local/share/pipassword",
)


@pytest.fixture(autouse=True)
def isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect HOME and the XDG base directories into a per-test temp directory.

    Autouse, so every test is isolated whether it asks or not.
    """
    home = tmp_path / "home"
    (home / ".config").mkdir(parents=True)
    (home / ".local" / "share").mkdir(parents=True)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))

    # Do not let an ambient override leak into a test run.
    monkeypatch.delenv("PIPASSWORD_VAULT", raising=False)
    monkeypatch.delenv("PIPASSWORD_ALLOW_UNSUPPORTED", raising=False)

    return home


@pytest.fixture
def vault_dir(isolate_home: Path) -> Path:
    """An empty vault directory inside the isolated home."""
    path = isolate_home / ".local" / "share" / "pipassword" / "vault"
    path.mkdir(parents=True)
    (path / "log").mkdir()
    return path


@pytest.fixture
def config_dir(isolate_home: Path) -> Path:
    """The per-device config directory, which must stay outside the vault.

    Device identity lives here rather than in the vault because a synced device id
    would give two devices the same log filename, which is what makes Syncthing
    conflicts impossible (requirement 3.4).
    """
    path = isolate_home / ".config" / "pipassword"
    path.mkdir(parents=True)
    return path


@pytest.fixture
def assert_untouched():
    """Assert a set of files is byte-identical and mtime-identical after an action.

    Used by the legacy import tests to prove read-only access (requirement 5.2).
    """
    import hashlib

    def snapshot(paths: list[Path]) -> dict[Path, tuple[bytes, int]]:
        state = {}
        for path in paths:
            data = path.read_bytes()
            state[path] = (hashlib.sha256(data).digest(), path.stat().st_mtime_ns)
        return state

    def check(before: dict[Path, tuple[bytes, int]]) -> None:
        for path, (digest, mtime) in before.items():
            now_digest = hashlib.sha256(path.read_bytes()).digest()
            assert now_digest == digest, f"{path} contents changed"
            assert path.stat().st_mtime_ns == mtime, f"{path} mtime changed"

    snapshot.check = check  # type: ignore[attr-defined]
    return snapshot


@pytest.fixture(autouse=True)
def _assert_home_is_temporary(isolate_home: Path, tmp_path: Path) -> None:
    """Belt and braces: prove the redirect took effect before the test body runs.

    If ``isolate_home`` is ever broken or reordered, every test fails immediately with
    a clear reason, instead of a test quietly writing into the developer's real home.
    """
    resolved = Path(os.path.expanduser("~")).resolve()
    assert resolved == isolate_home.resolve(), (
        f"HOME redirect failed: expanduser('~') is {resolved}"
    )
    assert tmp_path.resolve() in resolved.parents or resolved == tmp_path.resolve(), (
        f"HOME {resolved} is not inside the pytest temp directory {tmp_path}"
    )
