"""Tests for the legacy minipassword import (requirements 5.1-5.10).

The two that carry the most weight:

* :class:`TestReadOnly` proves the legacy vault cannot be modified, by AST
  inspection of the module and by hash/mtime comparison after a real run.
* :class:`TestVerification` proves a mismatch is reported and exits non-zero,
  rather than success being inferred from the absence of an exception.
"""

from __future__ import annotations

import ast
import configparser
import hashlib
import io
import json
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from pipassword import cli, crypto, importer
from pipassword.vault import Vault

PW = "four unrelated words here"
FAST_ARGS = ["--time-cost", "1", "--memory-cost", "64", "--parallelism", "1"]

# A faithful copy of the legacy rows, including the CJK entry seen in the real
# importfromjsonfile.py, a NULL memo/url row, and a multi-line memo.
LEGACY_ROWS = [
    ("Google Account", "name@google.com", "myfancygooglepassword",
     "Google Account", "https://www.google.com"),
    ("企业邮箱", "alan@corp.cn", "密码123", "备用地址\n第二行", "https://mail.corp.cn"),
    ("Bare Minimum", "user", "pw", None, None),
    ("GitHub", "laonan", "ghp_token", "recovery codes: 1234 5678", ""),
]


@pytest.fixture
def legacy(isolate_home: Path):
    """Build a legacy ~/.minipassword the way the old code would have."""
    base = isolate_home / ".minipassword"
    base.mkdir(parents=True)

    key = Fernet.generate_key()
    fernet = Fernet(key)
    db_path = base / "minipassword.db"

    connection = sqlite3.connect(db_path)
    connection.execute(
        """CREATE TABLE passwords (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               name VARCHAR(200) NOT NULL UNIQUE,
               login_name TEXT NOT NULL,
               password TEXT NOT NULL,
               memo TEXT NULL,
               url VARCHAR(255) NULL)"""
    )
    for name, login, password, memo, url in LEGACY_ROWS:
        connection.execute(
            "INSERT INTO passwords (name, login_name, password, memo, url) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                name,
                fernet.encrypt(login.encode()).decode(),
                fernet.encrypt(password.encode()).decode(),
                memo,
                url,
            ),
        )
    connection.commit()
    connection.close()

    parser = configparser.ConfigParser()
    parser.add_section("common")
    parser.set("common", "aes_key", key.decode())
    parser.add_section("db")
    parser.set("db", "database_file", str(db_path))
    with open(base / "config.ini", "w") as handle:
        parser.write(handle)
    # The legacy default: world-readable, holding the key in cleartext.
    (base / "config.ini").chmod(0o644)

    return base, db_path, key


class Runner:
    def __init__(self, vault_dir: Path, config_dir: Path):
        self.vault_dir = vault_dir
        self.config_dir = config_dir

    def __call__(self, *argv: str, stdin: str | None = None):
        if stdin is None:
            stdin = f"{PW}\n"
        out, err = io.StringIO(), io.StringIO()
        code = cli.run(
            ["--vault", str(self.vault_dir), "--config-dir", str(self.config_dir),
             "--password-stdin", *argv],
            stdin=io.StringIO(stdin), stdout=out, stderr=err,
        )
        return code, out.getvalue(), err.getvalue()


@pytest.fixture
def run(isolate_home: Path):
    runner = Runner(isolate_home / "vault", isolate_home / ".config" / "pipassword")
    assert runner("-y", "init", *FAST_ARGS)[0] == 0
    return runner


# ---------------------------------------------------------------- read-only


class TestReadOnly:
    """Requirement 5.2, the reason this project is a separate codebase."""

    def test_module_has_no_write_operations(self):
        """Structural, not a promise: inspect the AST for mutating calls."""
        source = Path(importer.__file__).read_text()
        tree = ast.parse(source)

        banned_funcs = {"remove", "unlink", "rmdir", "replace", "rename", "truncate"}
        banned_modules = {"shutil"}

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    assert name.split(".")[0] not in banned_modules, (
                        f"importer.py must not import {name}"
                    )

            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name in banned_funcs:
                    pytest.fail(f"importer.py calls {name}() at line {node.lineno}")
                if name == "open":
                    # open() is allowed only for reading.
                    mode = None
                    for keyword in node.keywords:
                        if keyword.arg == "mode" and isinstance(
                            keyword.value, ast.Constant
                        ):
                            mode = keyword.value.value
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        mode = node.args[1].value
                    if mode is not None:
                        assert "w" not in mode and "a" not in mode and "+" not in mode, (
                            f"write-mode open() at line {node.lineno}"
                        )

    def test_legacy_files_unchanged_by_a_real_import(self, run, legacy):
        base, db_path, _ = legacy
        files = sorted(p for p in base.rglob("*") if p.is_file())
        before = {
            p: (hashlib.sha256(p.read_bytes()).digest(), p.stat().st_mtime_ns)
            for p in files
        }

        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0, err + out

        for path, (digest, mtime) in before.items():
            assert hashlib.sha256(path.read_bytes()).digest() == digest, (
                f"{path} contents changed"
            )
            assert path.stat().st_mtime_ns == mtime, f"{path} mtime changed"

    def test_no_new_files_beside_the_legacy_database(self, run, legacy):
        """SQLite must not leave a -wal or -journal behind."""
        base, _, _ = legacy
        before = {p.name for p in base.iterdir()}
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0
        assert {p.name for p in base.iterdir()} == before

    def test_dry_run_writes_nothing_at_all(self, run, legacy):
        base, _, _ = legacy
        vault_logs = sorted((run.vault_dir / "log").glob("*.mpl"))
        before = {p: p.read_bytes() for p in vault_logs}

        code, out, err = run("import-legacy", "--legacy-dir", str(base), "--dry-run")
        assert code == 0, err
        assert "nothing was written" in err
        for path, content in before.items():
            assert path.read_bytes() == content


# ------------------------------------------------------------------ reading


class TestReadLegacy:
    def test_decrypts_every_row(self, legacy):
        base, db_path, key = legacy
        records, failures = importer.read_legacy_records(db_path, key.decode())
        assert failures == []
        assert len(records) == len(LEGACY_ROWS)

        by_name = {r.name: r for r in records}
        assert by_name["Google Account"].login == "name@google.com"
        assert by_name["Google Account"].password == "myfancygooglepassword"
        assert by_name["企业邮箱"].password == "密码123"
        assert by_name["企业邮箱"].memo == "备用地址\n第二行"

    def test_null_memo_and_url_become_empty(self, legacy):
        _, db_path, key = legacy
        records, _ = importer.read_legacy_records(db_path, key.decode())
        bare = next(r for r in records if r.name == "Bare Minimum")
        assert bare.memo == ""
        assert bare.url == ""

    def test_preserves_legacy_ids(self, legacy):
        """Requirement 5.5."""
        _, db_path, key = legacy
        records, _ = importer.read_legacy_records(db_path, key.decode())
        assert [r.legacy_id for r in records] == [1, 2, 3, 4]

    def test_undecryptable_row_is_skipped_not_fatal(self, legacy):
        """Requirement 5.4: one bad row must not abort the import."""
        base, db_path, key = legacy
        connection = sqlite3.connect(db_path)
        connection.execute(
            "INSERT INTO passwords (name, login_name, password) VALUES (?,?,?)",
            ("Broken", "not-a-fernet-token", "also-not-one"),
        )
        connection.commit()
        connection.close()

        records, failures = importer.read_legacy_records(db_path, key.decode())
        assert len(records) == len(LEGACY_ROWS)  # the good rows all survived
        assert len(failures) == 1
        assert "Broken" in failures[0][0]
        assert "decrypted" in failures[0][1]

    def test_missing_key_explains_the_consequence(self, legacy):
        base, _, _ = legacy
        (base / "config.ini").write_text("[db]\ndatabase_file = /tmp/x\n")
        with pytest.raises(importer.ImportError_, match="backups"):
            importer.read_legacy_key(base / "config.ini")

    def test_invalid_key_is_reported(self, legacy):
        _, db_path, _ = legacy
        with pytest.raises(importer.ImportError_, match="not a valid Fernet key"):
            importer.read_legacy_records(db_path, "obviously-not-a-key")

    def test_missing_config(self, isolate_home: Path):
        with pytest.raises(importer.ImportError_, match="--legacy-dir"):
            importer.find_legacy_paths(isolate_home / "absent")

    def test_finds_db_path_from_config(self, legacy):
        base, db_path, _ = legacy
        found_config, found_db = importer.find_legacy_paths(base)
        assert found_config == base / "config.ini"
        assert found_db == db_path

    def test_wrong_schema_is_reported(self, isolate_home: Path):
        base = isolate_home / "fake"
        base.mkdir()
        db = base / "minipassword.db"
        sqlite3.connect(db).close()
        key = Fernet.generate_key().decode()
        with pytest.raises(importer.ImportError_, match="does not look like"):
            importer.read_legacy_records(db, key)


class TestCjkDetection:
    @pytest.mark.parametrize("text", ["企业邮箱", "メール", "abc企业"])
    def test_detects(self, text):
        assert importer.contains_cjk(text)

    @pytest.mark.parametrize("text", ["", "plain ascii", "café"])
    def test_rejects(self, text):
        assert not importer.contains_cjk(text)


# ------------------------------------------------------------------ dry run


class TestDryRun:
    """Requirement 5.3."""

    def test_reports_the_statistics(self, run, legacy):
        base, _, _ = legacy
        code, out, err = run("import-legacy", "--legacy-dir", str(base), "--dry-run")
        assert code == 0, err
        assert "rows found         4" in out
        assert "would import       4" in out
        assert "containing CJK     1" in out
        assert "with a memo        3" in out
        assert "with a url         2" in out

    def test_reports_decryption_failures(self, run, legacy):
        base, db_path, _ = legacy
        connection = sqlite3.connect(db_path)
        connection.execute(
            "INSERT INTO passwords (name, login_name, password) VALUES (?,?,?)",
            ("Broken", "garbage", "garbage"),
        )
        connection.commit()
        connection.close()

        code, out, err = run("import-legacy", "--legacy-dir", str(base), "--dry-run")
        assert code == 1  # a failure means not ok
        assert "FAILED to read     1" in out
        assert "Broken" in out

    def test_reports_duplicate_names(self, run, legacy):
        base, db_path, key = legacy
        fernet = Fernet(key)
        connection = sqlite3.connect(db_path)
        connection.execute(
            "INSERT INTO passwords (name, login_name, password) VALUES (?,?,?)",
            ("github", fernet.encrypt(b"x").decode(), fernet.encrypt(b"y").decode()),
        )
        connection.commit()
        connection.close()

        code, out, _ = run("import-legacy", "--legacy-dir", str(base), "--dry-run")
        assert "duplicate names    1" in out


# ------------------------------------------------------------- real import


class TestImport:
    def test_imports_every_record(self, run, legacy):
        base, _, _ = legacy
        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0, err + out
        assert "added              4" in out
        assert "verification       PASSED" in out

        code, listed, _ = run("list")
        for name, *_ in LEGACY_ROWS:
            assert name in listed

    def test_fields_survive_exactly(self, run, legacy):
        base, _, _ = legacy
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0

        code, out, _ = run("export", "--plaintext")
        records = {r["name"]: r for r in json.loads(out)["records"]}

        cjk = records["企业邮箱"]
        assert cjk["login"] == "alan@corp.cn"
        assert cjk["password"] == "密码123"
        assert cjk["memo"] == "备用地址\n第二行"
        assert cjk["url"] == "https://mail.corp.cn"
        assert records["GitHub"]["memo"] == "recovery codes: 1234 5678"

    def test_legacy_ids_preserved_end_to_end(self, run, legacy):
        base, _, _ = legacy
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0
        code, out, _ = run("export", "--plaintext")
        records = {r["name"]: r for r in json.loads(out)["records"]}
        assert records["Google Account"]["legacy_id"] == 1
        assert records["企业邮箱"]["legacy_id"] == 2

    def test_prints_rotation_advice(self, run, legacy):
        """Requirement 5.10."""
        base, _, _ = legacy
        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0
        assert "Rotate high-value credentials" in err
        assert "0644" in err
        assert "shred" in err

    def test_does_not_erase_the_legacy_vault(self, run, legacy):
        base, db_path, _ = legacy
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0
        assert db_path.is_file()
        assert (base / "config.ini").is_file()

    def test_idempotent_on_reimport(self, run, legacy):
        """Requirement 5.9."""
        base, _, _ = legacy
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0

        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0, err
        assert "added              0" in out
        assert "already current    4" in out

        code, listed, _ = run("list")
        assert listed.count("Google Account") == 1

    def test_reimport_updates_a_changed_row(self, run, legacy):
        base, db_path, key = legacy
        assert run("import-legacy", "--legacy-dir", str(base))[0] == 0

        connection = sqlite3.connect(db_path)
        connection.execute(
            "UPDATE passwords SET password=? WHERE name=?",
            (Fernet(key).encrypt(b"rotated-in-legacy").decode(), "GitHub"),
        )
        connection.commit()
        connection.close()

        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0, err
        assert "updated            1" in out

        code, value, _ = run("get", "GitHub", "--field", "password")
        assert value == "rotated-in-legacy\n"

    def test_partial_failure_still_imports_the_rest(self, run, legacy):
        base, db_path, _ = legacy
        connection = sqlite3.connect(db_path)
        connection.execute(
            "INSERT INTO passwords (name, login_name, password) VALUES (?,?,?)",
            ("Broken", "garbage", "garbage"),
        )
        connection.commit()
        connection.close()

        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 1  # not ok: a row failed
        assert "added              4" in out
        assert "FAILED to read     1" in out
        assert "legacy data is untouched" in err

        code, listed, _ = run("list")
        assert "Google Account" in listed  # the good rows did land


# ------------------------------------------------------------ verification


class TestVerification:
    """Requirements 5.6, 5.7. Success is never inferred from a clean exit."""

    def test_verifies_against_a_reopened_vault(self, run, legacy):
        base, _, _ = legacy
        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0
        assert "Verifying against the source" in err
        assert "every field of every record matches" in err

    def test_detects_a_missing_record(self, legacy, isolate_home: Path):
        base, db_path, key = legacy
        records, _ = importer.read_legacy_records(db_path, key.decode())

        vault, _ = Vault.create(
            isolate_home / "v", PW,
            params=crypto.KdfParams(1, 64, 1),
            config_dir=isolate_home / "c", check_memory=False,
        )
        try:
            importer.apply_records(vault, records[:2], source="partial")
            mismatches = importer.verify_against(vault, records)
        finally:
            vault.close()

        assert len(mismatches) == 2
        assert all("missing" in m for m in mismatches)

    def test_detects_a_corrupted_field(self, legacy, isolate_home: Path):
        base, db_path, key = legacy
        records, _ = importer.read_legacy_records(db_path, key.decode())

        vault, _ = Vault.create(
            isolate_home / "v", PW,
            params=crypto.KdfParams(1, 64, 1),
            config_dir=isolate_home / "c", check_memory=False,
        )
        try:
            importer.apply_records(vault, records, source="x")
            target = vault.all_records()[0]
            vault.update(target.id, password="tampered")
            mismatches = importer.verify_against(vault, records)
        finally:
            vault.close()

        assert len(mismatches) == 1
        assert "differs in password" in mismatches[0]

    def test_mismatch_message_does_not_leak_values(self, legacy, isolate_home: Path):
        """Field names only; the values are exactly what we are protecting."""
        _, db_path, key = legacy
        records, _ = importer.read_legacy_records(db_path, key.decode())

        vault, _ = Vault.create(
            isolate_home / "v", PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=isolate_home / "c", check_memory=False,
        )
        try:
            importer.apply_records(vault, records, source="x")
            target = next(
                r for r in vault.all_records() if r.name == "Google Account"
            )
            vault.update(target.id, password="tampered")
            mismatches = importer.verify_against(vault, records)
        finally:
            vault.close()

        joined = " ".join(mismatches)
        assert "myfancygooglepassword" not in joined
        assert "tampered" not in joined

    def test_digest_covers_every_field(self):
        base = importer.LegacyRecord(1, "n", "l", "p", "m", "u")
        for changed in [
            importer.LegacyRecord(1, "N", "l", "p", "m", "u"),
            importer.LegacyRecord(1, "n", "L", "p", "m", "u"),
            importer.LegacyRecord(1, "n", "l", "P", "m", "u"),
            importer.LegacyRecord(1, "n", "l", "p", "M", "u"),
            importer.LegacyRecord(1, "n", "l", "p", "m", "U"),
        ]:
            assert changed.digest() != base.digest()

    def test_digest_is_not_confused_by_field_boundaries(self):
        """A NUL separator cannot occur inside a value, so 'ab|c' != 'a|bc'."""
        left = importer.LegacyRecord(1, "ab", "c", "", "", "")
        right = importer.LegacyRecord(1, "a", "bc", "", "", "")
        assert left.digest() != right.digest()


# ----------------------------------------------------------------- JSON path


class TestJsonImport:
    """Requirement 5.8."""

    @pytest.fixture
    def json_file(self, isolate_home: Path):
        path = isolate_home / "export.json"
        path.write_text(
            json.dumps(
                [
                    {"name": "企业邮箱", "login_name": "alan@corp.cn",
                     "password": "密码123", "memo": "备用", "url": ""},
                    {"name": "GitHub", "login_name": "laonan",
                     "password": "ghp", "memo": "", "url": "https://github.com"},
                ],
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        return path

    def test_imports_and_verifies(self, run, json_file):
        code, out, err = run("import-json", str(json_file))
        assert code == 0, err + out
        assert "added              2" in out
        assert "verification       PASSED" in out

    def test_warns_the_file_is_cleartext(self, run, json_file):
        code, _, err = run("import-json", str(json_file), "--dry-run")
        assert "cleartext" in err

    def test_reports_each_record_by_its_own_name(self, json_file):
        """The legacy script incremented its seed before printing, so every
        success line named the following record."""
        records, failures = importer.read_json_records(json_file)
        assert [r.name for r in records] == ["企业邮箱", "GitHub"]
        assert failures == []

    def test_idempotent_by_name(self, run, json_file):
        assert run("import-json", str(json_file))[0] == 0
        code, out, _ = run("import-json", str(json_file))
        assert code == 0
        assert "already current    2" in out

    def test_entry_without_a_name_is_reported(self, isolate_home: Path):
        path = isolate_home / "bad.json"
        path.write_text(json.dumps([{"password": "p"}, "not an object"]))
        records, failures = importer.read_json_records(path)
        assert records == []
        assert len(failures) == 2

    def test_not_a_list(self, isolate_home: Path):
        path = isolate_home / "bad.json"
        path.write_text('{"name": "x"}')
        with pytest.raises(importer.ImportError_, match="JSON list"):
            importer.read_json_records(path)

    def test_missing_file(self, isolate_home: Path):
        with pytest.raises(importer.ImportError_, match="could not read"):
            importer.read_json_records(isolate_home / "absent.json")


# --------------------------------------------------------------------- scale


class TestScale:
    def test_imports_a_thousand_rows(self, run, isolate_home: Path):
        base = isolate_home / "big"
        base.mkdir()
        key = Fernet.generate_key()
        fernet = Fernet(key)
        db_path = base / "minipassword.db"

        connection = sqlite3.connect(db_path)
        connection.execute(
            """CREATE TABLE passwords (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name VARCHAR(200) NOT NULL UNIQUE,
                   login_name TEXT NOT NULL, password TEXT NOT NULL,
                   memo TEXT NULL, url VARCHAR(255) NULL)"""
        )
        connection.executemany(
            "INSERT INTO passwords (name, login_name, password, memo, url) "
            "VALUES (?,?,?,?,?)",
            [
                (
                    f"entry {i:04d}",
                    fernet.encrypt(f"user{i}".encode()).decode(),
                    fernet.encrypt(f"pw{i}".encode()).decode(),
                    f"memo {i}",
                    f"https://example.com/{i}",
                )
                for i in range(1000)
            ],
        )
        connection.commit()
        connection.close()

        parser = configparser.ConfigParser()
        parser.add_section("common")
        parser.set("common", "aes_key", key.decode())
        parser.add_section("db")
        parser.set("db", "database_file", str(db_path))
        with open(base / "config.ini", "w") as handle:
            parser.write(handle)

        code, out, err = run("import-legacy", "--legacy-dir", str(base))
        assert code == 0, err
        assert "added              1000" in out
        assert "verification       PASSED" in out
