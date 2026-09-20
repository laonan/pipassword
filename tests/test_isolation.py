"""Verify the test suite cannot reach real vault paths.

This exists because the legacy suite did reach them: ``tests/test_manager.py``
instantiated ``PasswordManager()`` with no arguments, binding to the developer's live
vault, and ``test_delete_password`` deleted record id 1.
"""

from __future__ import annotations

import os
from pathlib import Path


def test_home_is_redirected(isolate_home: Path):
    assert Path(os.path.expanduser("~")) == isolate_home


def test_xdg_directories_are_redirected(isolate_home: Path):
    assert os.environ["XDG_CONFIG_HOME"] == str(isolate_home / ".config")
    assert os.environ["XDG_DATA_HOME"] == str(isolate_home / ".local" / "share")


def test_real_legacy_vault_is_not_visible():
    """~/.minipassword must not resolve to the developer's real legacy vault."""
    legacy = Path(os.path.expanduser("~/.minipassword"))
    assert not legacy.exists()


def test_vault_fixture_is_inside_temp(vault_dir: Path, tmp_path: Path):
    assert tmp_path in vault_dir.parents
    assert (vault_dir / "log").is_dir()


def test_config_dir_is_outside_vault(config_dir: Path, vault_dir: Path):
    """Requirement 3.4: device identity must never live inside the synced vault."""
    assert vault_dir not in config_dir.parents
    assert config_dir not in vault_dir.parents


def test_assert_untouched_detects_modification(tmp_path: Path, assert_untouched):
    target = tmp_path / "legacy.db"
    target.write_bytes(b"original")

    before = assert_untouched([target])
    assert_untouched.check(before)  # unchanged: passes

    target.write_bytes(b"modified")
    try:
        assert_untouched.check(before)
    except AssertionError as exc:
        assert "contents changed" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("modification was not detected")
