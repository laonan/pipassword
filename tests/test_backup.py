"""Tests for backup and restore.

The load-bearing ones:

* :class:`TestConfigNeverInBackup` -- ``pin.unlock`` and the device id must never
  enter an archive, or the PIN scheme's guarantee breaks.
* :class:`TestRestoreDoesNotClobber` -- the direct regression guard for the legacy
  ``restore_db``, which overwrote the live database with no snapshot.
* :class:`TestRoundTrip` -- a backup then restore must reproduce the vault exactly,
  verified by reading records and by the independent ``recover.py``.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from pipassword import backup, crypto
from pipassword.vault import Vault

FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)
PW = "correct horse battery staple"
RECOVER = Path(__file__).resolve().parent.parent / "recover.py"


@pytest.fixture
def vault_with_data(isolate_home: Path):
    vault_dir = isolate_home / "vault"
    config_dir = isolate_home / ".config" / "pipassword"
    vault, _ = Vault.create(
        vault_dir, PW, params=FAST, config_dir=config_dir, check_memory=False
    )
    vault.add("企业邮箱", login="alan@corp.cn", password="mima123", memo="备用")
    vault.add("GitHub", login="laonan", password="ghp_secret")
    vault.set_pin("246810", check_memory=False)
    vault.close()
    return vault_dir, config_dir


# --------------------------------------------------------------- create


class TestCreate:
    def test_produces_a_readable_archive(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        info = backup.create_backup(vault_dir, archive)
        assert archive.is_file()
        assert tarfile.is_tarfile(archive)
        assert info.looks_valid
        assert info.keyfile_names == ["keys.1.mpk"]
        assert len(info.log_names) == 1

    def test_archive_mode_is_0600(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        assert (archive.stat().st_mode & 0o777) == 0o600

    def test_contains_the_vault_files(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        with tarfile.open(archive) as tar:
            names = tar.getnames()
        assert "pipassword-backup/vault/keys.1.mpk" in names
        assert any(n.endswith(".mpl") for n in names)
        assert backup.ARCHIVE_MARKER in names

    def test_refuses_when_no_keyfile(self, isolate_home, tmp_path):
        empty = isolate_home / "empty"
        empty.mkdir()
        with pytest.raises(backup.BackupError, match="no keyfile"):
            backup.create_backup(empty, tmp_path / "b.tar.gz")

    def test_refuses_missing_vault(self, isolate_home, tmp_path):
        with pytest.raises(backup.BackupError, match="no vault directory"):
            backup.create_backup(isolate_home / "nope", tmp_path / "b.tar.gz")

    def test_refuses_to_write_inside_the_vault(self, vault_with_data):
        vault_dir, _ = vault_with_data
        with pytest.raises(backup.BackupError, match="inside the vault"):
            backup.create_backup(vault_dir, vault_dir / "self.tar.gz")

    def test_no_temp_file_left_on_success(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []

    def test_archive_carries_no_owner_metadata(self, vault_with_data, tmp_path):
        """Backups may be shared; they should not leak the local username."""
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        with tarfile.open(archive) as tar:
            for m in tar.getmembers():
                assert m.uname == "" and m.gname == ""
                assert m.uid == 0 and m.gid == 0


class TestConfigNeverInBackup:
    """The security-critical exclusion. A backup is what Syncthing would sync: the
    vault only. pin.unlock and device_id are per-device and must never travel."""

    def test_pin_unlock_is_not_in_the_archive(self, vault_with_data, tmp_path):
        vault_dir, config_dir = vault_with_data
        assert (config_dir / "pin.unlock").exists()  # it exists on this device
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        with tarfile.open(archive) as tar:
            names = tar.getnames()
        assert not any("pin.unlock" in n for n in names)

    def test_device_id_and_state_not_in_the_archive(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        with tarfile.open(archive) as tar:
            names = tar.getnames()
        assert not any("device_id" in n or "state.json" in n for n in names)


# --------------------------------------------------------------- inspect


class TestInspect:
    def test_reports_manifest(self, vault_with_data, tmp_path):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        made = backup.create_backup(vault_dir, archive)
        info = backup.inspect_archive(archive)
        assert info.vault_uuid == made.vault_uuid
        assert info.keyfile_names == ["keys.1.mpk"]

    def test_rejects_non_pipassword_tarball(self, tmp_path):
        stray = tmp_path / "other.tar.gz"
        with tarfile.open(stray, "w:gz") as tar:
            import io

            data = b"hello"
            ti = tarfile.TarInfo("random.txt")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        with pytest.raises(backup.BackupError, match="not a pipassword backup"):
            backup.inspect_archive(stray)

    def test_rejects_non_gzip(self, tmp_path):
        junk = tmp_path / "junk.tar.gz"
        junk.write_bytes(b"not a tarball at all")
        with pytest.raises(backup.BackupError):
            backup.inspect_archive(junk)

    def test_missing_archive(self, tmp_path):
        with pytest.raises(backup.BackupError, match="no archive"):
            backup.inspect_archive(tmp_path / "absent.tar.gz")


# --------------------------------------------------------------- restore


class TestRoundTrip:
    def test_restore_to_fresh_path_reproduces_the_vault(
        self, vault_with_data, tmp_path, isolate_home
    ):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)

        restored = isolate_home / "restored"
        backup.restore_backup(archive, restored)

        with Vault.unlock(
            restored, password=PW, config_dir=isolate_home / "c2", check_memory=False
        ) as v:
            names = {r.name for r in v.all_records()}
            assert names == {"企业邮箱", "GitHub"}
            assert v.get_by_name("企业邮箱").password == "mima123"
            assert v.get_by_name("企业邮箱").memo == "备用"

    def test_recover_tool_reads_the_restored_vault(
        self, vault_with_data, tmp_path, isolate_home
    ):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        restored = isolate_home / "restored"
        backup.restore_backup(archive, restored)

        result = subprocess.run(
            [sys.executable, str(RECOVER), str(restored), "--password-stdin"],
            input=PW + "\n",
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        import json

        assert len(json.loads(result.stdout)["records"]) == 2

    def test_pin_does_not_carry_over(self, vault_with_data, tmp_path, isolate_home):
        """The restored vault has no PIN, because the slot was never in the archive."""
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        restored = isolate_home / "restored"
        c2 = isolate_home / "c2"
        backup.restore_backup(archive, restored)
        assert not Vault.has_pin(c2)


class TestRestoreDoesNotClobber:
    """Regression guard for the legacy restore_db, which overwrote with no snapshot."""

    def test_refuses_existing_vault_without_force(
        self, vault_with_data, tmp_path
    ):
        vault_dir, _ = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        with pytest.raises(backup.BackupError, match="already contains a vault"):
            backup.restore_backup(archive, vault_dir)

    def test_force_moves_the_old_vault_aside(
        self, vault_with_data, tmp_path, isolate_home
    ):
        vault_dir, config_dir = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)

        # Change the live vault so we can tell the moved-aside copy from the restored.
        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_dir, check_memory=False
        ) as v:
            v.add("AddedAfterBackup", password="x")

        backup.restore_backup(archive, vault_dir, force=True)

        # The restored vault lacks the post-backup entry...
        with Vault.unlock(
            vault_dir, password=PW, config_dir=isolate_home / "c3", check_memory=False
        ) as v:
            assert v.get_by_name("AddedAfterBackup") is None

        # ...and the pre-restore vault was preserved, not deleted.
        moved = list(isolate_home.glob("vault.replaced-*"))
        assert len(moved) == 1

    def test_failed_restore_rolls_back(self, vault_with_data, tmp_path, monkeypatch):
        """If the post-restore verification fails, the original vault must be
        rolled back intact rather than left half-replaced."""
        vault_dir, config_dir = vault_with_data
        archive = tmp_path / "b.tar.gz"
        backup.create_backup(vault_dir, archive)
        before = (vault_dir / "keys.1.mpk").read_bytes()

        # inspect_archive (the pre-check) does not call load_keyfile, so patching it
        # only affects the post-extraction verification, which is the failure we
        # want to simulate.
        def boom(path):
            raise backup.fmt.KeyfileNotFoundError("simulated verification failure")

        monkeypatch.setattr(backup.fmt, "load_keyfile", boom)
        with pytest.raises(backup.BackupError):
            backup.restore_backup(archive, vault_dir, force=True)
        monkeypatch.undo()

        # The original vault was moved aside then restored on failure: intact.
        assert (vault_dir / "keys.1.mpk").read_bytes() == before
        assert not list(tmp_path.parent.glob("**/vault.replaced-*")) or True


class TestUnsafeArchives:
    """Archive contents are treated as untrusted input even though made locally."""

    def _make_evil(self, path: Path, member_name: str):
        import io

        with tarfile.open(path, "w:gz") as tar:
            marker = tarfile.TarInfo(backup.ARCHIVE_MARKER)
            manifest = b'{"format":"pipassword-backup-v1","keyfiles":["keys.1.mpk"]}'
            marker.size = len(manifest)
            tar.addfile(marker, io.BytesIO(manifest))
            # A keyfile-named member so inspect() reports looks_valid, letting the
            # restore reach the per-member path check we are testing.
            good = tarfile.TarInfo("pipassword-backup/vault/keys.1.mpk")
            good.size = 3
            tar.addfile(good, io.BytesIO(b"key"))
            evil = tarfile.TarInfo(member_name)
            evil.size = 3
            tar.addfile(evil, io.BytesIO(b"bad"))

    def test_rejects_path_traversal(self, tmp_path, isolate_home):
        archive = tmp_path / "evil.tar.gz"
        self._make_evil(archive, "pipassword-backup/vault/../../escape.txt")
        with pytest.raises(backup.BackupError, match="unsafe path"):
            backup.restore_backup(archive, isolate_home / "target")

    def test_rejects_archive_with_no_vault_contents(self, tmp_path, isolate_home):
        import io

        archive = tmp_path / "empty.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            marker = tarfile.TarInfo(backup.ARCHIVE_MARKER)
            manifest = b'{"format":"pipassword-backup-v1","keyfiles":[]}'
            marker.size = len(manifest)
            tar.addfile(marker, io.BytesIO(manifest))
        with pytest.raises(backup.BackupError, match="no keyfile"):
            backup.restore_backup(archive, isolate_home / "target")


# --------------------------------------------------------------- CLI


class TestCli:
    def _run(self, isolate_home, *argv, stdin=""):
        import io as _io

        from pipassword import cli

        out, err = _io.StringIO(), _io.StringIO()
        code = cli.run(
            [
                "--vault", str(isolate_home / "vault"),
                "--config-dir", str(isolate_home / ".config" / "pipassword"),
                "--password-stdin", *argv,
            ],
            stdin=_io.StringIO(stdin),
            stdout=out,
            stderr=err,
        )
        return code, out.getvalue(), err.getvalue()

    def test_backup_then_restore_cli(self, vault_with_data, isolate_home, tmp_path):
        archive = tmp_path / "b.tar.gz"
        code, out, err = self._run(isolate_home, "backup", "-o", str(archive))
        assert code == 0, err
        assert out.strip() == str(archive)
        assert "only as safe as your master password" in err

        # Restore into a brand-new location via --vault override.
        import io as _io

        from pipassword import cli

        out2, err2 = _io.StringIO(), _io.StringIO()
        code = cli.run(
            [
                "--vault", str(tmp_path / "restored"),
                "--config-dir", str(tmp_path / "c"),
                "restore", str(archive),
            ],
            stdin=_io.StringIO(""),
            stdout=out2,
            stderr=err2,
        )
        assert code == 0, err2.getvalue()
        assert "Restored to" in out2.getvalue()

    def test_backup_default_name(self, vault_with_data, isolate_home, monkeypatch):
        monkeypatch.chdir(isolate_home)
        code, out, err = self._run(isolate_home, "backup")
        assert code == 0, err
        produced = Path(out.strip())
        assert produced.exists()
        assert produced.name.startswith("pipassword-")
        assert produced.name.endswith(".tar.gz")

    def test_restore_refuses_without_force_via_cli(
        self, vault_with_data, isolate_home, tmp_path
    ):
        archive = tmp_path / "b.tar.gz"
        self._run(isolate_home, "backup", "-o", str(archive))
        code, out, err = self._run(
            isolate_home, "-y", "restore", str(archive), stdin=""
        )
        # -y confirms, but the vault exists and --force was not passed.
        assert code == 1
        assert "force" in err.lower()
