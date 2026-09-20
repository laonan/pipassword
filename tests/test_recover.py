"""Tests for the standalone recovery tool (requirements 6.2, 6.3, 6.4).

These are the tests that back the promise "you will never be locked out". They run
``recover.py`` as a genuinely separate program, against vaults produced by the
package, and require its output to match the package's own export byte for byte.

That equivalence is what keeps FORMAT.md honest: ``recover.py`` is an independent
implementation of the document, so if the two drift apart, one of these fails.
"""

from __future__ import annotations

import ast
import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from pipassword import crypto
from pipassword.vault import Vault

FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)
PW = "master passphrase"
RECOVER = Path(__file__).resolve().parent.parent / "recover.py"


@pytest.fixture
def populated(isolate_home: Path):
    """A vault with awkward content: CJK, unicode, empty fields, a deletion."""
    vault_dir = isolate_home / "vault"
    config_dir = isolate_home / ".config" / "pipassword"
    vault, recovery_key = Vault.create(
        vault_dir, PW, params=FAST, config_dir=config_dir,
        device_name="beepy", check_memory=False,
    )
    vault.add("Google", login="a@gmail.com", password="p1", url="https://g.com",
              memo="work")
    vault.add("企业邮箱", login="alan@corp.cn", password="密码123",
              memo="备用地址", pinyin={"name": "qyyx qiyeyouxiang"})
    vault.add("Minimal")
    vault.add("With TOTP", password="p", totp="JBSWY3DPEHPK3PXP")
    vault.add("Migrated", password="p", legacy_id=42)
    doomed = vault.add("Doomed", password="gone")
    vault.delete(doomed.id)

    expected = vault.export_plaintext()
    vault.close()
    return vault_dir, recovery_key, expected


def run_recover(vault_dir: Path, secret: str, *extra: str):
    return subprocess.run(
        [sys.executable, str(RECOVER), str(vault_dir), "--password-stdin", *extra],
        input=secret + "\n",
        capture_output=True,
        text=True,
    )


class TestIndependence:
    """Requirement 6.3: it must survive the package breaking."""

    def test_imports_nothing_from_the_package(self):
        tree = ast.parse(RECOVER.read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
                if node.level:  # relative import
                    pytest.fail("recover.py must not use relative imports")

        assert "pipassword" not in imported, (
            "recover.py must not import the package it is meant to outlive"
        )
        allowed_third_party = {"cryptography", "argon2"}
        stdlib = set(sys.stdlib_module_names)
        unexpected = imported - stdlib - allowed_third_party
        assert not unexpected, f"unexpected dependencies: {sorted(unexpected)}"

    def test_runs_with_the_package_import_blocked(self, populated):
        """Simulate the package being uninstalled or broken at runtime.

        An import hook makes any ``import pipassword`` raise, then recover.py is
        executed as ``__main__``. If it had any hidden dependency on the package,
        this would fail. ``cryptography`` and ``argon2`` remain importable because
        they are genuine, documented requirements.
        """
        vault_dir, _, _ = populated
        bootstrap = (
            "import sys, runpy\n"
            "class Block:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] == 'pipassword':\n"
            "            raise ImportError('pipassword is blocked for this test')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Block())\n"
            f"sys.argv = [{str(RECOVER)!r}, {str(vault_dir)!r}, '--password-stdin']\n"
            f"runpy.run_path({str(RECOVER)!r}, run_name='__main__')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", bootstrap],
            input=PW + "\n",
            capture_output=True,
            text=True,
            cwd="/",  # also proves it does not depend on the project cwd
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["records"]

    def test_the_import_blocker_actually_blocks(self):
        """Guard against the previous test passing for the wrong reason."""
        bootstrap = (
            "import sys\n"
            "class Block:\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name.split('.')[0] == 'pipassword':\n"
            "            raise ImportError('blocked')\n"
            "        return None\n"
            "sys.meta_path.insert(0, Block())\n"
            "import pipassword\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", bootstrap], capture_output=True, text=True
        )
        assert result.returncode != 0
        assert "blocked" in result.stderr

    def test_is_executable(self):
        assert RECOVER.stat().st_mode & stat.S_IXUSR, "recover.py should be chmod +x"

    def test_has_a_shebang(self):
        assert RECOVER.read_bytes().startswith(b"#!/usr/bin/env python3")


class TestMatchesPackageExport:
    """The equivalence that keeps FORMAT.md and the implementation in step."""

    def test_output_matches_export_exactly(self, populated):
        vault_dir, _, expected = populated
        result = run_recover(vault_dir, PW)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == expected

    def test_recovery_key_path_matches_too(self, populated):
        vault_dir, recovery_key, expected = populated
        result = run_recover(
            vault_dir, crypto.format_recovery_key(recovery_key), "--recovery-key"
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == expected

    def test_cjk_survives_the_round_trip(self, populated):
        vault_dir, _, _ = populated
        records = json.loads(run_recover(vault_dir, PW).stdout)["records"]
        entry = next(r for r in records if r["name"] == "企业邮箱")
        assert entry["password"] == "密码123"
        assert entry["memo"] == "备用地址"

    def test_deleted_records_are_absent(self, populated):
        vault_dir, _, _ = populated
        records = json.loads(run_recover(vault_dir, PW).stdout)["records"]
        assert all(r["name"] != "Doomed" for r in records)

    def test_legacy_id_preserved(self, populated):
        vault_dir, _, _ = populated
        records = json.loads(run_recover(vault_dir, PW).stdout)["records"]
        assert next(r for r in records if r["name"] == "Migrated")["legacy_id"] == 42

    def test_transcribed_recovery_key_accepted(self, populated):
        """Lowercase, spaces instead of dashes: as typed off paper."""
        vault_dir, recovery_key, expected = populated
        typed = crypto.format_recovery_key(recovery_key).lower().replace("-", " ")
        result = run_recover(vault_dir, typed, "--recovery-key")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == expected


class TestMultiDeviceRecovery:
    def test_folds_every_device_log(self, isolate_home: Path):
        vault_dir = isolate_home / "vault"
        config_a = isolate_home / ".config" / "beepy"
        config_b = isolate_home / ".config" / "pi4"

        vault, _ = Vault.create(
            vault_dir, PW, params=FAST, config_dir=config_a,
            device_name="beepy", check_memory=False,
        )
        vault.add("from-beepy", password="b")
        vault.close()

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_b,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.add("from-pi4", password="p")

        records = json.loads(run_recover(vault_dir, PW).stdout)["records"]
        assert {r["name"] for r in records} == {"from-beepy", "from-pi4"}

    def test_survives_a_rotated_password(self, isolate_home: Path):
        """After rotation, recover must use the newest generation."""
        from pipassword import format as fmt

        vault_dir = isolate_home / "vault"
        config_dir = isolate_home / ".config" / "pipassword"
        vault, _ = Vault.create(
            vault_dir, PW, params=FAST, config_dir=config_dir, check_memory=False
        )
        vault.add("entry", password="p")
        dek = vault.dek
        keyfile = vault.keyfile
        vault.close()

        fmt.rotate_keyfile(vault_dir, keyfile, dek, "new passphrase", check_memory=False)

        assert run_recover(vault_dir, "new passphrase").returncode == 0
        assert run_recover(vault_dir, PW).returncode == 1  # old password rejected


class TestResilience:
    def test_truncated_log_still_recovers_earlier_records(self, populated):
        vault_dir, _, _ = populated
        log = next((vault_dir / "log").glob("*.mpl"))
        log.write_bytes(log.read_bytes()[:-7])

        result = run_recover(vault_dir, PW)
        assert result.returncode == 0
        assert json.loads(result.stdout)["records"]
        assert "interrupted write" in result.stderr

    def test_corrupt_newest_keyfile_falls_back(self, populated):
        from pipassword import format as fmt

        vault_dir, _, _ = populated
        (vault_dir / "keys.2.mpk").write_bytes(b"garbage")
        result = run_recover(vault_dir, PW)
        assert result.returncode == 0
        assert "keys.1.mpk" in result.stderr

    def test_archive_directory_is_ignored(self, populated):
        """An archived generation must not be used, per FORMAT.md."""
        vault_dir, _, _ = populated
        archive = vault_dir / "archive"
        archive.mkdir()
        (archive / "keys.99.mpk").write_bytes(
            (vault_dir / "keys.1.mpk").read_bytes()
        )
        result = run_recover(vault_dir, PW)
        assert result.returncode == 0
        assert "keys.1.mpk" in result.stderr

    def test_wrong_password_exits_nonzero(self, populated):
        vault_dir, _, _ = populated
        result = run_recover(vault_dir, "wrong")
        assert result.returncode == 1
        assert "wrong password" in result.stderr

    def test_missing_vault_exits_nonzero(self, isolate_home: Path):
        result = run_recover(isolate_home / "nope", PW)
        assert result.returncode == 1
        assert "no keys" in result.stderr

    def test_empty_vault_produces_empty_records(self, isolate_home: Path):
        vault_dir = isolate_home / "vault"
        vault, _ = Vault.create(
            vault_dir, PW, params=FAST,
            config_dir=isolate_home / ".config" / "pipassword",
            check_memory=False,
        )
        vault.close()
        result = run_recover(vault_dir, PW)
        assert result.returncode == 0
        assert json.loads(result.stdout)["records"] == []


class TestOutputHandling:
    def test_stdout_is_pure_json(self, populated):
        """Progress must go to stderr so the output stays pipeable."""
        vault_dir, _, _ = populated
        result = run_recover(vault_dir, PW)
        json.loads(result.stdout)  # would raise if diagnostics leaked in
        assert result.stderr.strip()

    def test_output_file_is_mode_0600(self, populated, tmp_path: Path):
        """It contains every password in cleartext."""
        vault_dir, _, expected = populated
        target = tmp_path / "export.json"
        result = run_recover(vault_dir, PW, "--output", str(target))
        assert result.returncode == 0
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert json.loads(target.read_text()) == expected

    def test_does_not_modify_the_vault(self, populated):
        """Requirement: recovery is strictly read-only."""
        import hashlib

        vault_dir, _, _ = populated
        files = sorted(p for p in vault_dir.rglob("*") if p.is_file())
        before = {
            p: (hashlib.sha256(p.read_bytes()).digest(), p.stat().st_mtime_ns)
            for p in files
        }

        assert run_recover(vault_dir, PW).returncode == 0

        for path, (digest, mtime) in before.items():
            assert hashlib.sha256(path.read_bytes()).digest() == digest
            assert path.stat().st_mtime_ns == mtime
        assert sorted(p for p in vault_dir.rglob("*") if p.is_file()) == files
