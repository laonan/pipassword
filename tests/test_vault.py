"""Tests for the Vault API (requirements 2.11, 3.1, 3.2, 3.4, 3.11, 3.12, 4.17, 7.3)."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from pipassword import crypto, events as ev, format as fmt
from pipassword.vault import (
    DeviceIdentity,
    DeviceState,
    DuplicateNameError,
    RecordNotFoundError,
    Vault,
    VaultConfig,
    VaultError,
    default_config_dir,
    default_vault_dir,
)

FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)
PW = "master passphrase"


@pytest.fixture
def paths(isolate_home: Path):
    return isolate_home / "vault", isolate_home / ".config" / "pipassword"


@pytest.fixture
def vault(paths):
    vault_dir, config_dir = paths
    v, recovery = Vault.create(
        vault_dir,
        PW,
        params=FAST,
        config_dir=config_dir,
        device_name="beepy",
        check_memory=False,
    )
    v.recovery_key_for_test = recovery  # type: ignore[attr-defined]
    yield v
    v.close()


def reopen(paths, *, device_name="beepy", **kw):
    vault_dir, config_dir = paths
    return Vault.unlock(
        vault_dir,
        password=PW,
        config_dir=config_dir,
        device_name=device_name,
        check_memory=False,
        **kw,
    )


# ------------------------------------------------------------------ locations


class TestLocations:
    def test_config_dir_follows_xdg(self, isolate_home: Path):
        assert default_config_dir() == isolate_home / ".config" / "pipassword"

    def test_vault_dir_follows_xdg(self, isolate_home: Path):
        expected = isolate_home / ".local" / "share" / "pipassword" / "vault"
        assert default_vault_dir() == expected

    def test_vault_dir_env_override(self, isolate_home: Path, monkeypatch):
        monkeypatch.setenv("PIPASSWORD_VAULT", "/tmp/elsewhere")
        assert default_vault_dir() == Path("/tmp/elsewhere")


# ----------------------------------------------------------- device identity


class TestDeviceIdentity:
    def test_created_once_and_reused(self, paths):
        _, config_dir = paths
        first = DeviceIdentity.load_or_create(config_dir, name="beepy")
        second = DeviceIdentity.load_or_create(config_dir, name="beepy")
        assert first.uuid == second.uuid
        assert len(first.uuid) == 16

    def test_stored_outside_the_vault(self, vault, paths):
        """Requirement 3.4: a synced device id would collapse two logs into one."""
        vault_dir, config_dir = paths
        assert (config_dir / "device_id").is_file()
        assert not (vault_dir / "device_id").exists()
        assert config_dir not in vault_dir.parents
        assert vault_dir not in config_dir.parents

    def test_corrupt_device_id_explains_the_fix(self, paths):
        _, config_dir = paths
        fmt.ensure_dir(config_dir)
        (config_dir / "device_id").write_bytes(b"too short")
        with pytest.raises(VaultError, match="Delete it"):
            DeviceIdentity.load_or_create(config_dir)

    def test_log_filename_includes_uuid_prefix(self, paths):
        _, config_dir = paths
        device = DeviceIdentity.load_or_create(config_dir, name="beepy")
        assert device.log_filename.startswith("beepy-")
        assert device.uuid.hex()[:8] in device.log_filename


# ------------------------------------------------------------------- config


class TestConfig:
    def test_roundtrip(self, paths):
        _, config_dir = paths
        VaultConfig(
            vault_path=Path("/srv/vault"), device_name="pi4", reveal_seconds=30
        ).save(config_dir)
        loaded = VaultConfig.load(config_dir)
        assert loaded.vault_path == Path("/srv/vault")
        assert loaded.device_name == "pi4"
        assert loaded.reveal_seconds == 30

    def test_missing_file_gives_defaults(self, paths):
        _, config_dir = paths
        assert VaultConfig.load(config_dir).vault_path is None

    def test_contains_no_secrets(self, vault, paths):
        """Requirement 2.11, the defect that motivated the whole rewrite.

        The legacy config.ini held the Fernet key in cleartext at mode 0644.
        """
        _, config_dir = paths
        VaultConfig(vault_path=Path("/srv/vault"), device_name="beepy").save(config_dir)
        text = (config_dir / "config.toml").read_text()

        assert PW not in text
        assert vault.dek.hex() not in text
        assert crypto.format_recovery_key(vault.recovery_key_for_test) not in text
        for banned in ("key", "secret", "password"):
            for line in text.splitlines():
                if line.startswith("#"):
                    continue
                assert banned not in line.lower(), f"suspicious config line: {line}"

    def test_invalid_toml_is_reported(self, paths):
        _, config_dir = paths
        fmt.ensure_dir(config_dir)
        (config_dir / "config.toml").write_text("not = = toml")
        with pytest.raises(VaultError, match="not valid TOML"):
            VaultConfig.load(config_dir)


# ------------------------------------------------------------ create/unlock


class TestCreateAndUnlock:
    def test_creates_expected_layout(self, vault, paths):
        vault_dir, _ = paths
        assert fmt.keyfile_path(vault_dir, 1).is_file()
        assert (vault_dir / "log").is_dir()
        assert (vault_dir / ".stignore").is_file()
        assert vault.own_log.is_file()

    def test_stignore_excludes_conflict_files(self, vault, paths):
        vault_dir, _ = paths
        assert "sync-conflict" in (vault_dir / ".stignore").read_text()

    def test_refuses_to_create_over_existing_vault(self, vault, paths):
        vault_dir, config_dir = paths
        with pytest.raises(VaultError, match="already contains a keyfile"):
            Vault.create(
                vault_dir, "other", params=FAST, config_dir=config_dir,
                check_memory=False,
            )

    def test_unlock_with_password(self, vault, paths):
        vault.add("Google", password="p")
        vault.close()
        with reopen(paths) as reopened:
            assert reopened.get_by_name("Google").password == "p"

    def test_unlock_with_recovery_key(self, vault, paths):
        vault.add("Google", password="p")
        recovery = vault.recovery_key_for_test
        vault.close()
        vault_dir, config_dir = paths
        with Vault.unlock(
            vault_dir, recovery_key=recovery, config_dir=config_dir
        ) as reopened:
            assert reopened.get_by_name("Google").password == "p"

    def test_wrong_password_rejected(self, vault, paths):
        vault.close()
        vault_dir, config_dir = paths
        with pytest.raises(crypto.AuthenticationError):
            Vault.unlock(
                vault_dir, password="wrong", config_dir=config_dir,
                check_memory=False,
            )

    def test_requires_exactly_one_credential(self, vault, paths):
        vault_dir, config_dir = paths
        with pytest.raises(VaultError, match="exactly one"):
            Vault.unlock(vault_dir, config_dir=config_dir)
        with pytest.raises(VaultError, match="exactly one"):
            Vault.unlock(
                vault_dir, password=PW, recovery_key=bytes(32), config_dir=config_dir
            )


class TestLifecycle:
    """Requirement 4.17: no daemon, key dies with the session."""

    def test_close_zeroes_the_key(self, vault):
        vault.close()
        with pytest.raises(VaultError, match="closed"):
            vault.dek

    def test_operations_fail_after_close(self, vault):
        vault.close()
        for call in (
            lambda: vault.all_records(),
            lambda: vault.add("x"),
            lambda: vault.search("x"),
            lambda: vault.export_plaintext(),
        ):
            with pytest.raises(VaultError, match="closed"):
                call()

    def test_close_is_idempotent(self, vault):
        vault.close()
        vault.close()

    def test_context_manager_closes(self, paths):
        vault_dir, config_dir = paths
        with Vault.create(
            vault_dir, PW, params=FAST, config_dir=config_dir, check_memory=False
        )[0] as v:
            v.add("x")
        with pytest.raises(VaultError):
            v.dek


# --------------------------------------------------------------------- CRUD


class TestCrud:
    def test_add_and_get(self, vault):
        record = vault.add(
            "Google", login="a@g.com", password="p", url="https://g.com", memo="m"
        )
        assert vault.get(record.id).name == "Google"
        assert record.login == "a@g.com"
        assert record.url == "https://g.com"

    def test_add_requires_name(self, vault):
        with pytest.raises(VaultError, match="name is required"):
            vault.add("   ")

    def test_duplicate_name_rejected_by_default(self, vault):
        vault.add("Google")
        with pytest.raises(DuplicateNameError):
            vault.add("Google")

    def test_duplicate_name_allowed_explicitly(self, vault):
        vault.add("Google")
        vault.add("Google", allow_duplicate_name=True)
        assert len(vault.search("Google")) == 2

    def test_update_writes_only_the_delta(self, vault):
        record = vault.add("Google", login="a", password="p", memo="m")
        vault.update(record.id, password="new")

        history = vault.history(record.id)
        assert len(history) == 2
        assert set(history[1].fields) == {"password"}
        assert vault.get(record.id).memo == "m"

    def test_update_with_no_change_writes_nothing(self, vault):
        record = vault.add("Google", password="p")
        vault.update(record.id, password="p")
        assert len(vault.history(record.id)) == 1

    def test_update_rejects_unknown_field(self, vault):
        record = vault.add("Google")
        with pytest.raises(VaultError, match="unknown field"):
            vault.update(record.id, nonsense="x")

    def test_update_rejects_empty_name(self, vault):
        record = vault.add("Google")
        with pytest.raises(VaultError, match="name cannot be empty"):
            vault.update(record.id, name="  ")

    def test_update_unknown_record(self, vault):
        with pytest.raises(RecordNotFoundError):
            vault.update("nope", password="x")

    def test_delete_and_history_survives(self, vault):
        record = vault.add("Google", password="secret")
        vault.delete(record.id)

        assert vault.get_by_name("Google") is None
        assert record.id in vault.deleted_ids()
        # Requirement 3.7: the value is still recoverable from history.
        history = vault.history(record.id)
        assert any(e.fields.get("password") == "secret" for e in history)

    def test_delete_unknown_record(self, vault):
        with pytest.raises(RecordNotFoundError):
            vault.delete("nope")

    def test_add_many_is_one_append(self, vault):
        records = vault.add_many(
            [{"name": f"entry {i}", "password": f"p{i}"} for i in range(50)]
        )
        assert len(records) == 50
        assert len(vault.all_records()) == 50

    def test_add_many_requires_names(self, vault):
        with pytest.raises(VaultError, match="name is required"):
            vault.add_many([{"password": "p"}])

    def test_records_sorted_by_name(self, vault):
        for name in ["zebra", "Apple", "mango"]:
            vault.add(name)
        assert [r.name for r in vault.all_records()] == ["Apple", "mango", "zebra"]

    def test_legacy_id_preserved(self, vault):
        record = vault.add("Old", legacy_id=42)
        assert vault.get(record.id).legacy_id == 42


class TestSearch:
    def test_matches_name_url_memo(self, vault):
        vault.add("Google", url="https://google.com", memo="work account")
        assert vault.search("goog")
        assert vault.search("google.com")
        assert vault.search("work")
        assert not vault.search("absent")

    def test_is_case_insensitive(self, vault):
        vault.add("GitHub")
        assert vault.search("github") and vault.search("GITHUB")

    def test_does_not_match_password(self, vault):
        """Searching must not leak whether a password contains a substring."""
        vault.add("Bank", password="hunter2")
        assert vault.search("hunter2") == []

    def test_empty_query_returns_everything(self, vault):
        vault.add("a")
        vault.add("b")
        assert len(vault.search("  ")) == 2

    def test_matches_pinyin_index(self, vault):
        """Requirement 4.13, via the index the vault already consults."""
        vault.add("企业邮箱", pinyin={"name": "qyyx qiyeyouxiang"})
        assert vault.search("qyyx")
        assert vault.search("qiyeyouxiang")
        assert vault.search("企业")


# ------------------------------------------------------------ multi-device


class TestMultiDevice:
    """Requirements 3.1, 3.2, 3.3: the core sync claim."""

    def _second_device(self, paths, name="pi4"):
        vault_dir, config_dir = paths
        other_config = config_dir.parent / f"pipassword-{name}"
        return vault_dir, other_config

    def test_each_device_writes_only_its_own_log(self, vault, paths):
        vault.add("from-beepy")
        beepy_log = vault.own_log
        vault.close()

        vault_dir, other_config = self._second_device(paths)
        with Vault.unlock(
            vault_dir,
            password=PW,
            config_dir=other_config,
            device_name="pi4",
            check_memory=False,
        ) as pi4:
            before = beepy_log.read_bytes()
            pi4.add("from-pi4")
            assert pi4.own_log != beepy_log
            assert beepy_log.read_bytes() == before  # untouched

        logs = fmt.find_logs(vault_dir / "log")
        assert len(logs) == 2

    def test_both_devices_see_the_unified_vault(self, vault, paths):
        vault.add("from-beepy", password="b")
        vault.close()

        vault_dir, other_config = self._second_device(paths)
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.add("from-pi4", password="p")
            assert {r.name for r in pi4.all_records()} == {"from-beepy", "from-pi4"}

        with reopen(paths) as beepy:
            assert {r.name for r in beepy.all_records()} == {
                "from-beepy",
                "from-pi4",
            }
            assert beepy.get_by_name("from-pi4").password == "p"

    def test_concurrent_field_edits_both_survive(self, vault, paths):
        """The worked example from the design discussion, end to end on disk."""
        record = vault.add("Bank A", password="p1", memo="m1")
        rid = record.id
        vault.close()

        vault_dir, other_config = self._second_device(paths)
        with reopen(paths) as beepy:
            beepy.update(rid, password="from-beepy")
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.update(rid, memo="from-pi4")

        with reopen(paths) as final:
            merged = final.get(rid)
            assert merged.password == "from-beepy"
            assert merged.memo == "from-pi4"
            assert merged.name == "Bank A"

    def test_one_device_can_edit_a_record_created_elsewhere(self, vault, paths):
        record = vault.add("shared", password="original")
        vault.close()

        vault_dir, other_config = self._second_device(paths)
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.update(record.id, password="changed-by-pi4")

        with reopen(paths) as beepy:
            assert beepy.get(record.id).password == "changed-by-pi4"

    def test_one_device_can_delete_a_record_created_elsewhere(self, vault, paths):
        record = vault.add("doomed")
        vault.close()

        vault_dir, other_config = self._second_device(paths)
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.delete(record.id)

        with reopen(paths) as beepy:
            assert beepy.get_by_name("doomed") is None

    def test_log_from_another_vault_is_ignored(self, vault, paths):
        vault.add("mine")
        vault_dir, _ = paths
        stray = vault_dir / "log" / "stranger-deadbeef.mpl"
        fmt.create_log(stray, uuid.uuid4().bytes, uuid.uuid4().bytes)
        vault.close()

        with reopen(paths) as reopened:
            assert [r.name for r in reopened.all_records()] == ["mine"]
            assert any("different vault" in a for a in reopened.anomalies)


class TestConflictDetection:
    """Requirement 3.12: a conflict file should be impossible, so say so loudly."""

    def test_no_conflicts_normally(self, vault):
        assert vault.conflicts == []

    def test_conflict_file_is_reported(self, vault, paths):
        vault.add("x")
        vault_dir, _ = paths
        vault.close()

        conflict = vault_dir / "log" / "beepy-aaaaaaaa.sync-conflict-20260920-1200-ABC.mpl"
        conflict.write_bytes(b"whatever")

        with reopen(paths) as reopened:
            assert len(reopened.conflicts) == 1
            assert any("device_id" in a for a in reopened.anomalies)


class TestDamagedLogs:
    def test_truncated_log_still_loads_earlier_records(self, vault, paths):
        vault.add("first")
        vault.add("second")
        log = vault.own_log
        vault.close()

        log.write_bytes(log.read_bytes()[:-5])  # cut the last frame

        with reopen(paths) as reopened:
            assert [r.name for r in reopened.all_records()] == ["first"]
            assert reopened.anomalies

    def test_malformed_event_is_skipped_not_fatal(self, vault, paths):
        vault.add("good")
        log = vault.own_log
        dek = vault.dek
        vault.close()

        fmt.append_frame(log, dek, b"{this is not a valid event}")

        with reopen(paths) as reopened:
            assert [r.name for r in reopened.all_records()] == ["good"]
            assert any("unreadable event" in a for a in reopened.anomalies)


# ------------------------------------------------------- change summary


class TestChangeSummary:
    def test_empty_on_a_fresh_vault(self, vault):
        assert vault.changes_since_last_open().is_empty

    def test_reports_additions_from_another_device(self, vault, paths):
        vault.add("existing")
        vault.close()

        vault_dir, config_dir = paths
        other_config = config_dir.parent / "pipassword-pi4"
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.add("brand new")
            pi4.add("also new")
            pi4_uuid = pi4.device.uuid

        with reopen(paths) as beepy:
            summary = beepy.changes_since_last_open()
            assert {r.name for r in summary.added} == {"brand new", "also new"}
            assert summary.by_device[pi4_uuid] == 2
            assert summary.total == 2

    def test_distinguishes_updates_from_additions(self, vault, paths):
        record = vault.add("existing")
        vault.close()

        vault_dir, config_dir = paths
        other_config = config_dir.parent / "pipassword-pi4"
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.update(record.id, password="changed")
            pi4.add("fresh")

        with reopen(paths) as beepy:
            summary = beepy.changes_since_last_open()
            assert [r.name for r in summary.updated] == ["existing"]
            assert [r.name for r in summary.added] == ["fresh"]

    def test_reports_deletions(self, vault, paths):
        record = vault.add("doomed")
        vault.close()

        vault_dir, config_dir = paths
        other_config = config_dir.parent / "pipassword-pi4"
        with Vault.unlock(
            vault_dir, password=PW, config_dir=other_config,
            device_name="pi4", check_memory=False,
        ) as pi4:
            pi4.delete(record.id)

        with reopen(paths) as beepy:
            assert beepy.changes_since_last_open().deleted == (record.id,)


# ------------------------------------------------------ clock and state


class TestClockState:
    def test_last_known_good_time_advances_on_write(self, vault):
        before = vault.last_known_good_time
        vault.add("x")
        assert vault.last_known_good_time > before

    def test_state_persists_across_sessions(self, vault, paths):
        vault.add("x")
        recorded = vault.last_known_good_time
        vault.close()
        with reopen(paths) as reopened:
            assert reopened.last_known_good_time >= recorded

    def test_state_lives_outside_the_vault(self, vault, paths):
        vault_dir, config_dir = paths
        vault.add("x")
        assert (config_dir / "state.json").is_file()
        assert not (vault_dir / "state.json").exists()

    def test_clock_behind_is_detected(self, vault, paths):
        """A Beepy booting with a stale fake-hwclock time."""
        vault.add("x")
        vault.close()

        _, config_dir = paths
        state = DeviceState.load(config_dir)
        state.last_known_good_time = ev.now_micros() + 7 * 24 * 3600 * 1_000_000
        state.save(config_dir)

        with reopen(paths) as reopened:
            assert reopened.clock_is_behind

    def test_clock_normally_not_behind(self, vault):
        vault.add("x")
        assert not vault.clock_is_behind

    def test_corrupt_state_does_not_block_unlock(self, vault, paths):
        """State is a cache; losing it must never cost access."""
        vault.add("x")
        vault.close()
        _, config_dir = paths
        (config_dir / "state.json").write_text("{ broken")

        with reopen(paths) as reopened:
            assert reopened.get_by_name("x") is not None

    def test_edits_sort_after_remote_edits_despite_stale_clock(self, vault, paths):
        """End-to-end HLC: a stale-clocked device's edit still wins."""
        record = vault.add("shared", password="original")
        vault.close()

        _, config_dir = paths
        far_future = ev.now_micros() + 30 * 24 * 3600 * 1_000_000
        state = DeviceState.load(config_dir)
        state.last_known_good_time = far_future
        state.save(config_dir)

        with reopen(paths) as stale_device:
            stale_device.update(record.id, password="written-with-bad-clock")
            assert stale_device.get(record.id).password == "written-with-bad-clock"

        with reopen(paths) as final:
            assert final.get(record.id).password == "written-with-bad-clock"


# ------------------------------------------------------------------ export


class TestExport:
    def test_includes_every_field(self, vault):
        vault.add(
            "Google", login="a@g.com", password="p", url="https://g.com",
            memo="note", totp="JBSWY3DPEHPK3PXP",
        )
        exported = vault.export_plaintext()
        assert exported["format"] == "pipassword-export-v1"
        record = exported["records"][0]
        assert record["name"] == "Google"
        assert record["password"] == "p"
        assert record["totp"] == "JBSWY3DPEHPK3PXP"

    def test_excludes_deleted_records(self, vault):
        record = vault.add("gone")
        vault.add("stays")
        vault.delete(record.id)
        names = [r["name"] for r in vault.export_plaintext()["records"]]
        assert names == ["stays"]

    def test_is_json_serialisable(self, vault):
        vault.add("企业邮箱", password="p")
        json.dumps(vault.export_plaintext(), ensure_ascii=False)


# -------------------------------------------------------------------- scale


class TestScale:
    def test_two_thousand_records_roundtrip(self, vault, paths):
        vault.add_many(
            [{"name": f"entry {i:04d}", "password": f"pw{i}"} for i in range(2000)]
        )
        vault.close()
        with reopen(paths) as reopened:
            assert len(reopened.all_records()) == 2000
            assert reopened.get_by_name("entry 1999").password == "pw1999"
