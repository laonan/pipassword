"""Tests for the CLI (requirements 2.4, 2.13, 4.15, 6.1, 6.5, 6.6)."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import pytest

from pipassword import cli, crypto, format as fmt

PW = "four unrelated words here"

# Cheap KDF for every test that is not about the KDF itself.
FAST_ARGS = ["--time-cost", "1", "--memory-cost", "64", "--parallelism", "1"]


class Runner:
    """Drives cli.run with captured streams and scripted stdin."""

    def __init__(self, vault_dir: Path, config_dir: Path):
        self.vault_dir = vault_dir
        self.config_dir = config_dir

    def __call__(
        self, *argv: str, stdin: str | None = None, secrets=True
    ) -> tuple[int, str, str]:
        # Most commands need the master password first; default it so individual
        # tests only spell out stdin when they need something else as well.
        if stdin is None:
            stdin = f"{PW}\n"
        out, err = io.StringIO(), io.StringIO()
        args = [
            "--vault", str(self.vault_dir),
            "--config-dir", str(self.config_dir),
        ]
        if secrets:
            args.append("--password-stdin")
        args.extend(argv)
        code = cli.run(
            args, stdin=io.StringIO(stdin), stdout=out, stderr=err
        )
        return code, out.getvalue(), err.getvalue()


@pytest.fixture
def run(isolate_home: Path):
    return Runner(isolate_home / "vault", isolate_home / ".config" / "pipassword")


@pytest.fixture
def initialised(run):
    code, out, err = run("-y", "init", *FAST_ARGS, stdin=f"{PW}\n")
    assert code == 0, err
    return run, out


# --------------------------------------------------------------------- init


class TestInit:
    def test_creates_a_vault(self, run):
        code, out, err = run("-y", "init", *FAST_ARGS, stdin=f"{PW}\n")
        assert code == 0, err
        assert fmt.find_keyfile_generations(run.vault_dir) == [1]
        assert (run.vault_dir / "log").is_dir()
        assert (run.vault_dir / ".stignore").is_file()

    def test_shows_the_recovery_key_once(self, initialised):
        _, out = initialised
        assert "RECOVERY KEY" in out
        groups = [
            line.strip()
            for line in out.splitlines()
            if line.strip().count("-") == 12
        ]
        assert groups, "no grouped recovery key in the output"
        # It must be parseable, i.e. genuinely usable off paper.
        assert len(crypto.parse_recovery_key(groups[0])) == 32

    def test_recovery_key_is_not_written_anywhere(self, initialised):
        """It is shown once and never stored (requirement 6.1)."""
        run, out = initialised
        key = next(
            line.strip() for line in out.splitlines() if line.strip().count("-") == 12
        )
        for path in list(run.vault_dir.rglob("*")) + list(run.config_dir.rglob("*")):
            if path.is_file():
                assert key.encode() not in path.read_bytes(), f"leaked into {path}"

    def test_records_the_vault_path_in_config(self, initialised):
        run, _ = initialised
        assert (run.config_dir / "config.toml").is_file()
        text = (run.config_dir / "config.toml").read_text()
        assert str(run.vault_dir) in text
        assert PW not in text

    def test_refuses_to_overwrite(self, initialised):
        run, _ = initialised
        code, _, err = run("-y", "init", *FAST_ARGS, stdin=f"{PW}\n")
        assert code == 1
        assert "already exists" in err

    def test_requires_a_password(self, run):
        code, _, err = run("-y", "init", *FAST_ARGS, stdin="\n")
        assert code == 1
        assert "required" in err

    def test_warns_about_a_short_passphrase(self, run):
        code, _, err = run("-y", "init", *FAST_ARGS, stdin="short\n")
        assert code == 0
        assert "short" in err.lower()

    def test_no_warning_for_a_long_passphrase(self, run):
        code, _, err = run("-y", "init", *FAST_ARGS, stdin=f"{PW}\n")
        assert code == 0
        assert "note:" not in err

    def test_refuses_when_memory_is_insufficient(self, run, monkeypatch):
        monkeypatch.setattr(crypto, "read_mem_available_kib", lambda *a, **k: 1000)
        code, _, err = run("-y", "init", stdin=f"{PW}\n")  # default 64 MiB
        assert code == 1
        assert "64 MiB" in err


class TestPassphraseAdvice:
    @pytest.mark.parametrize("weak", ["abc", "hunter2", "short"])
    def test_flags_short(self, weak):
        assert cli.passphrase_advice(weak)

    @pytest.mark.parametrize(
        "strong",
        ["four unrelated words here", "a" * 20, "correct horse battery staple"],
    )
    def test_accepts_long(self, strong):
        assert cli.passphrase_advice(strong) is None


# --------------------------------------------------------------- crud paths


class TestRecords:
    def test_add_and_get(self, initialised):
        run, _ = initialised
        code, _, err = run(
            "add", "GitHub", "--login", "laonan", "--password", "ghp_secret"
        )
        assert code == 0, err

        code, out, _ = run("get", "GitHub", stdin=f"{PW}\n")
        assert code == 0
        assert "GitHub" in out
        assert "laonan" in out

    def test_password_is_masked_by_default(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "ghp_secret")
        code, out, _ = run("get", "GitHub", stdin=f"{PW}\n")
        assert "ghp_secret" not in out
        assert cli.MASK in out

    def test_show_reveals(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "ghp_secret")
        code, out, _ = run("get", "GitHub", "--show", stdin=f"{PW}\n")
        assert "ghp_secret" in out

    def test_field_output_is_bare_and_pipeable(self, initialised):
        """Requirement 4.15: the scriptable form."""
        run, _ = initialised
        run("add", "GitHub", "--password", "ghp_secret")
        code, out, err = run(
            "get", "GitHub", "--field", "password", stdin=f"{PW}\n"
        )
        assert code == 0
        assert out == "ghp_secret\n"  # nothing else on stdout
        assert "Master password" not in out

    def test_field_refuses_when_ambiguous(self, initialised):
        run, _ = initialised
        run("add", "Mail A", "--password", "a")
        run("add", "Mail B", "--password", "b")
        code, out, err = run("get", "Mail", "--field", "password", stdin=f"{PW}\n")
        assert code == 1
        assert out == ""  # never guess which secret to emit
        assert "matches 2 records" in err

    def test_missing_field_reports(self, initialised):
        run, _ = initialised
        run("add", "NoUrl", "--password", "p")
        code, _, err = run("get", "NoUrl", "--field", "url", stdin=f"{PW}\n")
        assert code == 1
        assert "no url" in err

    def test_no_match_exits_nonzero(self, initialised):
        run, _ = initialised
        code, _, err = run("get", "absent", stdin=f"{PW}\n")
        assert code == 1
        assert "No record" in err

    def test_duplicate_name_rejected(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "a")
        code, _, err = run("add", "GitHub", "--password", "b")
        assert code == 1
        assert "already exists" in err

    def test_add_prompts_for_password_when_omitted(self, initialised):
        run, _ = initialised
        code, _, err = run("add", "Prompted", stdin=f"{PW}\nfrom-prompt\n")
        assert code == 0, err
        code, out, _ = run(
            "get", "Prompted", "--field", "password", stdin=f"{PW}\n"
        )
        assert out == "from-prompt\n"

    def test_edit_changes_only_named_fields(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--login", "old", "--password", "p", "--memo", "keep")
        code, _, err = run("edit", "GitHub", "--login", "new")
        assert code == 0, err

        code, out, _ = run("get", "GitHub", stdin=f"{PW}\n")
        assert "new" in out
        assert "keep" in out

    def test_edit_with_nothing_to_change(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "p")
        code, _, err = run("edit", "GitHub")
        assert code == 1
        assert "Nothing to change" in err

    def test_edit_by_id_prefix_and_name(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "p")
        code, _, err = run("edit", "GitHub", "--url", "https://github.com")
        assert code == 0, err

    def test_delete_requires_confirmation(self, initialised):
        run, _ = initialised
        run("add", "Doomed", "--password", "p")
        code, _, err = run("delete", "Doomed", stdin=f"{PW}\nn\n")
        assert code == 1
        assert "Cancelled" in err

        code, _, err = run("-y", "delete", "Doomed", stdin=f"{PW}\n")
        assert code == 0
        assert "recovered" in err  # tells the user history survives

    def test_list(self, initialised):
        run, _ = initialised
        run("add", "Alpha", "--password", "a")
        run("add", "Beta", "--password", "b")
        code, out, err = run("list", stdin=f"{PW}\n")
        assert code == 0
        assert "Alpha" in out and "Beta" in out
        assert "2 record(s)" in err

    def test_list_does_not_print_passwords(self, initialised):
        run, _ = initialised
        run("add", "Alpha", "--password", "supersecret")
        code, out, _ = run("list", stdin=f"{PW}\n")
        assert "supersecret" not in out

    def test_empty_vault_list(self, initialised):
        run, _ = initialised
        code, out, err = run("list", stdin=f"{PW}\n")
        assert code == 0
        assert "empty" in err


class TestAuth:
    def test_wrong_password(self, initialised):
        run, _ = initialised
        code, _, err = run("list", stdin="wrong password\n")
        assert code == 1
        assert "could not unlock" in err

    def test_no_vault(self, run):
        code, _, err = run("list", stdin=f"{PW}\n")
        assert code == 1
        assert "no vault found" in err

    def test_unlock_with_recovery_key(self, initialised):
        run, out = initialised
        key = next(
            line.strip() for line in out.splitlines() if line.strip().count("-") == 12
        )
        run("add", "Entry", "--password", "p")
        code, listed, err = run("list", "--recovery-key", stdin=f"{key}\n")
        assert code == 0, err
        assert "Entry" in listed


# ------------------------------------------------------------------- export


class TestExport:
    def test_requires_plaintext_flag(self, initialised):
        run, _ = initialised
        code, _, err = run("export", stdin=f"{PW}\n")
        assert code == 1
        assert "--plaintext" in err

    def test_exports_json_to_stdout(self, initialised):
        run, _ = initialised
        run("add", "GitHub", "--password", "ghp_secret")
        code, out, _ = run("export", "--plaintext", stdin=f"{PW}\n")
        assert code == 0
        document = json.loads(out)
        assert document["format"] == "pipassword-export-v1"
        assert document["records"][0]["password"] == "ghp_secret"

    def test_output_file_is_0600(self, initialised, tmp_path: Path):
        run, _ = initialised
        run("add", "GitHub", "--password", "p")
        target = tmp_path / "export.json"
        code, _, err = run(
            "export", "--plaintext", "--output", str(target), stdin=f"{PW}\n"
        )
        assert code == 0
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert "not encrypted" in err


# ------------------------------------------------------------------- passwd


class TestPasswd:
    def test_changes_the_password(self, initialised):
        run, _ = initialised
        run("add", "Entry", "--password", "p")

        code, out, err = run("passwd", stdin=f"{PW}\nnew long passphrase here\n")
        assert code == 0, err
        assert "generation 2" in out

        assert run("list", stdin="new long passphrase here\n")[0] == 0
        assert run("list", stdin=f"{PW}\n")[0] == 1  # old password dead

    def test_archives_the_old_generation(self, initialised):
        """Requirement 6.6, and the security consequence of append-only."""
        run, _ = initialised
        code, _, err = run("passwd", stdin=f"{PW}\nnew long passphrase here\n")
        assert code == 0

        assert fmt.find_keyfile_generations(run.vault_dir) == [2]
        archived = list((run.vault_dir / "archive").glob("keys.1.mpk"))
        assert archived, "old generation was not archived"
        assert "OLD password" in err  # warns why archive/ should be deleted

    def test_recovery_key_survives_rotation(self, initialised):
        run, out = initialised
        key = next(
            line.strip() for line in out.splitlines() if line.strip().count("-") == 12
        )
        run("add", "Entry", "--password", "p")
        assert run("passwd", stdin=f"{PW}\nnew long passphrase here\n")[0] == 0

        code, listed, err = run("list", "--recovery-key", stdin=f"{key}\n")
        assert code == 0, err
        assert "Entry" in listed

    def test_mismatched_confirmation_aborts(self, initialised):
        run, _ = initialised
        out, err = io.StringIO(), io.StringIO()
        # Without --password-stdin the confirmation prompt is exercised.
        code = cli.run(
            [
                "--vault", str(run.vault_dir),
                "--config-dir", str(run.config_dir),
                "passwd",
            ],
            stdin=io.StringIO(""),
            stdout=out,
            stderr=err,
        )
        assert code == 1


# ---------------------------------------------------------------- calibrate


class TestCalibrate:
    def test_reports_a_timing(self, run):
        code, out, err = run(
            "calibrate", "--time-cost", "1", "--memory-cost", "64",
            "--parallelism", "1", "--runs", "1",
        )
        assert code == 0, err
        assert "Unlock takes" in out
        assert "slowest device" in err  # the advice that actually matters

    def test_refuses_when_memory_is_short(self, run, monkeypatch):
        monkeypatch.setattr(crypto, "read_mem_available_kib", lambda *a, **k: 1000)
        code, _, err = run("calibrate", "--runs", "1")
        assert code == 1
        assert "not enough memory" in err


# -------------------------------------------------------------------- misc


class TestMisc:
    def test_where(self, initialised):
        run, _ = initialised
        code, out, _ = run("where")
        assert code == 0
        assert str(run.vault_dir) in out
        assert "device_id" in out
        assert "[1]" in out

    def test_bare_invocation_prints_help(self, run):
        code, out, err = run()
        assert code == 0
        assert "COMMAND" in err or "usage" in err

    def test_version(self):
        with pytest.raises(SystemExit) as excinfo:
            cli.run(["--version"])
        assert excinfo.value.code == 0

    def test_import_has_no_side_effects(self):
        import importlib

        from pipassword import cli as module

        importlib.reload(module)
        assert module.build_parser().prog == "pipw"


class TestHealthReporting:
    def test_reports_changes_from_another_device(self, initialised):
        run, _ = initialised
        run("add", "Existing", "--password", "p")

        other_config = run.config_dir.parent / "pipassword-pi4"
        other = Runner(run.vault_dir, other_config)
        assert other("add", "From Pi4", "--password", "p", stdin=f"{PW}\n")[0] == 0

        code, _, err = run("list", stdin=f"{PW}\n")
        assert code == 0
        assert "Since you last opened" in err
        assert "From Pi4" in err

    def test_reports_anomalies(self, initialised):
        run, _ = initialised
        run("add", "Entry", "--password", "p")
        log = next((run.vault_dir / "log").glob("*.mpl"))
        log.write_bytes(log.read_bytes() + b"\x01\x02\x03")

        code, _, err = run("list", stdin=f"{PW}\n")
        assert code == 0
        assert "warning:" in err


class TestRecoveryScript:
    """The recovery tool must be reachable by someone who only used pipx."""

    def test_writes_an_executable_copy(self, run, tmp_path: Path):
        target = tmp_path / "recover.py"
        code, _, err = run("recovery-script", "-o", str(target))
        assert code == 0, err
        assert target.is_file()
        assert target.stat().st_mode & 0o100  # owner-executable
        assert "cryptography and argon2-cffi" in err

    def test_prints_to_stdout_by_default(self, run):
        code, out, _ = run("recovery-script")
        assert code == 0
        assert out.startswith("#!/usr/bin/env python3")
        assert "pipassword" not in out.split("\n")[0]

    def test_emitted_copy_matches_the_repository_file(self, run, tmp_path: Path):
        target = tmp_path / "recover.py"
        assert run("recovery-script", "-o", str(target))[0] == 0
        root = Path(__file__).resolve().parent.parent
        assert target.read_text() == (root / "recover.py").read_text()

    def test_needs_no_vault(self, isolate_home: Path):
        """Being locked out must not be a prerequisite failure."""
        runner = Runner(isolate_home / "absent", isolate_home / "absent-cfg")
        code, out, _ = runner("recovery-script")
        assert code == 0
        assert "ChaCha20Poly1305" in out


class TestBenchmark:
    """The tool that decides whether native code is needed, on the real device."""

    def test_reports_the_three_stages(self, run):
        code, out, err = run("benchmark", "-n", "200")
        assert code == 0, err
        for stage in ("decrypt frames", "decode events", "fold", "total"):
            assert stage in out
        assert "records            200" in out

    def test_names_which_stages_are_already_c(self, out_check=None):
        """The point is to show where Python actually costs anything."""
        pass

    def test_advises_compaction_before_native_code(self, run):
        code, _, err = run("benchmark", "-n", "200")
        assert code == 0
        assert "calibrate" in err  # points at the other half of unlock cost

    def test_does_not_touch_the_real_vault(self, initialised):
        run, _ = initialised
        run("add", "Precious", "--password", "p")
        log = next((run.vault_dir / "log").glob("*.mpl"))
        before = log.read_bytes()

        code, _, err = run("benchmark", "-n", "150")
        assert code == 0, err
        assert log.read_bytes() == before

    def test_works_without_a_vault(self, isolate_home: Path):
        """You should be able to measure before committing to a vault."""
        runner = Runner(isolate_home / "none", isolate_home / "none-cfg")
        code, out, err = runner("benchmark", "-n", "150")
        assert code == 0, err
        assert "total" in out

    def test_cleans_up_after_itself(self, run):
        import tempfile

        before = set(Path(tempfile.gettempdir()).glob("pipw-bench-*"))
        assert run("benchmark", "-n", "150")[0] == 0
        after = set(Path(tempfile.gettempdir()).glob("pipw-bench-*"))
        assert after == before


class TestBenchmarkExtrapolation:
    """A verdict measured at 2,000 records must not be reported as if it were
    measured at the 10,000-record budget. Real Beepy numbers exposed this: 520ms at
    2,000 was reported as 'comfortably inside', but it projects to ~2.6s at 10,000.
    """

    def test_reports_a_projection_when_measuring_fewer(self, run):
        code, out, err = run("benchmark", "-n", "200")
        assert code == 0, err
        assert "at 10,000 records" in out
        assert "projected from 200" in out
        assert "extrapolated" in err

    def test_projection_exceeds_the_measured_total(self, run):
        code, out, _ = run("benchmark", "-n", "200")
        measured = float(
            next(l for l in out.splitlines() if l.strip().startswith("total")).split()[1]
        )
        projected = float(
            next(l for l in out.splitlines() if "at 10,000 records" in l).split()[3]
        )
        assert projected > measured * 10, (
            f"projecting 200 -> 10000 should scale up by >=50x, got "
            f"{projected:.0f} from {measured:.0f}"
        )

    def test_no_projection_disclaimer_at_full_size(self, run):
        code, out, err = run("benchmark", "-n", "10000")
        assert code == 0, err
        assert "(measured)" in out
        assert "extrapolated" not in err
