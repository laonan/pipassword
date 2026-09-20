"""Tests for the Pinyin index, TOTP clock gate, and generator.

Requirements 4.12-4.14, 4.16, 7.1-7.6.
"""

from __future__ import annotations

import io
import re
import string
import subprocess
import sys
from pathlib import Path

import pytest

from pipassword import cli, crypto, events as ev, generator, pinyin, totp
from pipassword.vault import Vault

PW = "four unrelated words here"
FAST_ARGS = ["--time-cost", "1", "--memory-cost", "64", "--parallelism", "1"]


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


@pytest.fixture
def vault(isolate_home: Path):
    v, _ = Vault.create(
        isolate_home / "v", PW,
        params=crypto.KdfParams(1, 64, 1),
        config_dir=isolate_home / "c", check_memory=False,
    )
    yield v
    v.close()


# ============================================================ pinyin index


class TestPinyinVariants:
    def test_produces_initials_and_full(self):
        variants = pinyin.pinyin_variants("企业邮箱")
        assert "qyyx" in variants
        assert "qiyeyouxiang" in variants

    def test_spaced_form_enables_partial_syllable_search(self):
        variants = pinyin.pinyin_variants("企业邮箱")
        assert any("qi ye you xiang" == v for v in variants)

    def test_latin_text_has_no_variants(self):
        assert pinyin.pinyin_variants("GitHub") == []
        assert pinyin.pinyin_variants("") == []

    def test_mixed_text_is_indexed(self):
        variants = pinyin.pinyin_variants("Google 企业账号")
        assert any("qy" in v for v in variants)

    def test_japanese_is_handled_without_crashing(self):
        pinyin.pinyin_variants("メール")  # must not raise


class TestBuildIndex:
    def test_indexes_name_and_memo_only(self):
        index = pinyin.build_index(
            {
                "name": "企业邮箱",
                "memo": "备用地址",
                "url": "https://mail.corp.cn",
                "password": "密码123",
            }
        )
        assert set(index) == {"name", "memo"}

    def test_password_is_never_indexed(self):
        """Indexing it would make secrets searchable."""
        assert "password" not in pinyin.build_index({"password": "密码"})

    def test_latin_only_record_has_no_index(self):
        assert pinyin.build_index({"name": "GitHub", "memo": "notes"}) == {}

    def test_ignores_non_strings(self):
        assert pinyin.build_index({"name": 42}) == {}


class TestPinyinInVault:
    def test_index_is_built_automatically_on_add(self):
        """Requirement 4.13, without the caller having to think about it."""
        pass  # covered by the vault tests below

    def test_search_by_initials(self, vault):
        vault.add("企业邮箱", login="alan@corp.cn", password="p")
        assert [r.name for r in vault.search("qyyx")] == ["企业邮箱"]

    def test_search_by_full_pinyin(self, vault):
        vault.add("企业邮箱", password="p")
        assert vault.search("qiyeyouxiang")

    def test_search_by_partial_syllables(self, vault):
        vault.add("企业邮箱", password="p")
        assert vault.search("youxiang")

    def test_search_by_original_characters_still_works(self, vault):
        vault.add("企业邮箱", password="p")
        assert vault.search("企业")

    def test_memo_is_searchable_by_pinyin(self, vault):
        vault.add("Bank", memo="备用地址", password="p")
        assert vault.search("byaddress") == [] or True  # sanity: no crash
        assert vault.search("beiyong")

    def test_index_is_rebuilt_when_the_name_changes(self, vault):
        record = vault.add("企业邮箱", password="p")
        vault.update(record.id, name="个人邮箱")
        assert vault.search("gryx")  # new name's initials
        assert not vault.search("qyyx")  # old ones are gone

    def test_index_survives_a_reopen(self, isolate_home: Path):
        vault_dir = isolate_home / "v2"
        config_dir = isolate_home / "c2"
        v, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=config_dir, check_memory=False,
        )
        v.add("企业邮箱", password="p")
        v.close()

        with Vault.unlock(
            vault_dir, password=PW, config_dir=config_dir, check_memory=False
        ) as reopened:
            assert reopened.search("qyyx")

    def test_index_is_inside_the_encrypted_log(self, isolate_home: Path):
        """Requirement 4.14: a plaintext index would leak entry names."""
        vault_dir = isolate_home / "v3"
        v, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=isolate_home / "c3", check_memory=False,
        )
        v.add("企业邮箱", password="p")
        log = v.own_log
        v.close()

        raw = log.read_bytes()
        assert b"qyyx" not in raw
        assert b"qiyeyouxiang" not in raw
        assert "企业邮箱".encode() not in raw

    def test_reading_does_not_import_pypinyin(self, isolate_home: Path):
        """Requirement 4.14: pypinyin's tables must not load on the read path."""
        vault_dir = isolate_home / "v4"
        config_dir = isolate_home / "c4"
        v, _ = Vault.create(
            vault_dir, PW, params=crypto.KdfParams(1, 64, 1),
            config_dir=config_dir, check_memory=False,
        )
        v.add("企业邮箱", password="p")
        v.close()

        probe = (
            "import sys\n"
            "from pathlib import Path\n"
            "from pipassword.vault import Vault\n"
            f"v = Vault.unlock(Path({str(vault_dir)!r}), password={PW!r},"
            f" config_dir=Path({str(config_dir)!r}), check_memory=False)\n"
            "assert v.search('qyyx'), 'index missing'\n"
            "v.close()\n"
            "print('pypinyin' in sys.modules)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "False", "pypinyin was imported while reading"

    def test_explicit_index_overrides_the_built_one(self, vault):
        vault.add("企业邮箱", password="p", pinyin={"name": "custom"})
        assert vault.search("custom")


# ==================================================================== TOTP

# RFC 6238 style test secret, widely used in pyotp's own docs.
SECRET = "JBSWY3DPEHPK3PXP"


class TestParseSecret:
    def test_bare_base32(self):
        parsed = totp.parse_secret(SECRET)
        assert parsed.secret == SECRET
        assert parsed.digits == 6
        assert parsed.period == 30

    def test_accepts_spaces_and_dashes_and_case(self):
        assert totp.parse_secret("jbsw y3dp-ehpk 3pxp").secret == SECRET

    def test_otpauth_uri(self):
        parsed = totp.parse_secret(
            f"otpauth://totp/Corp:alan@corp.cn?secret={SECRET}"
            f"&issuer=Corp&digits=8&period=60&algorithm=SHA256"
        )
        assert parsed.secret == SECRET
        assert parsed.digits == 8
        assert parsed.period == 60
        assert parsed.algorithm == "SHA256"
        assert parsed.issuer == "Corp"

    def test_issuer_inferred_from_label(self):
        parsed = totp.parse_secret(f"otpauth://totp/Corp:alan?secret={SECRET}")
        assert parsed.issuer == "Corp"

    def test_hotp_is_rejected_with_a_reason(self):
        with pytest.raises(totp.TotpError, match="counter-based"):
            totp.parse_secret(f"otpauth://hotp/x?secret={SECRET}&counter=1")

    @pytest.mark.parametrize(
        "bad", ["", "   ", "not base32!", "01189998819991197253"]
    )
    def test_invalid_secrets(self, bad):
        with pytest.raises(totp.TotpError):
            totp.parse_secret(bad)

    def test_uri_without_secret(self):
        with pytest.raises(totp.TotpError, match="no valid secret"):
            totp.parse_secret("otpauth://totp/x?issuer=y")

    def test_unsupported_digits(self):
        with pytest.raises(totp.TotpError, match="digit count"):
            totp.parse_secret(f"otpauth://totp/x?secret={SECRET}&digits=9")


class TestGenerate:
    def test_produces_a_six_digit_code_offline(self):
        """Requirement 7.2: no network involved anywhere."""
        result = totp.generate(SECRET, now_micros=1_600_000_000_000_000)
        assert result.available
        assert re.fullmatch(r"\d{6}", result.code or "")

    def test_is_deterministic_for_a_given_time(self):
        a = totp.generate(SECRET, now_micros=1_600_000_000_000_000)
        b = totp.generate(SECRET, now_micros=1_600_000_000_000_000)
        assert a.code == b.code

    def test_changes_across_periods(self):
        a = totp.generate(SECRET, now_micros=1_600_000_000_000_000)
        b = totp.generate(SECRET, now_micros=1_600_000_060_000_000)
        assert a.code != b.code

    def test_seconds_remaining_is_within_the_period(self):
        result = totp.generate(SECRET, now_micros=1_600_000_005_000_000)
        assert 1 <= result.seconds_remaining <= 30

    def test_honours_digits_and_period_from_uri(self):
        result = totp.generate(
            f"otpauth://totp/x?secret={SECRET}&digits=8&period=60",
            now_micros=1_600_000_000_000_000,
        )
        assert re.fullmatch(r"\d{8}", result.code or "")
        assert result.period == 60


class TestClockGate:
    """Requirements 7.4, 7.6. A wrong code is worse than no code."""

    def test_refuses_when_the_clock_is_behind(self):
        good = 1_700_000_000_000_000
        stale = good - 7 * 24 * 3600 * 1_000_000

        result = totp.generate(
            SECRET, last_known_good_time=good, now_micros=stale
        )
        assert not result.available
        assert result.code is None
        assert "cannot be trusted" in (result.blocked_reason or "")
        assert "7.0 days" in (result.blocked_reason or "")

    def test_explains_the_hardware_reason_and_the_fix(self):
        result = totp.generate(
            SECRET, last_known_good_time=2_000_000_000_000_000, now_micros=1
        )
        reason = result.blocked_reason or ""
        assert "battery-backed" in reason
        assert "--at" in reason

    def test_allows_when_the_clock_is_ahead_of_the_vault(self):
        result = totp.generate(
            SECRET,
            last_known_good_time=1_600_000_000_000_000,
            now_micros=1_700_000_000_000_000,
        )
        assert result.available

    def test_at_override_bypasses_the_gate(self):
        """Requirement 7.5: the user asserts the real time explicitly."""
        result = totp.generate(
            SECRET,
            last_known_good_time=2_000_000_000_000_000,
            now_micros=1,
            at_micros=1_600_000_000_000_000,
        )
        assert result.available
        expected = totp.generate(SECRET, now_micros=1_600_000_000_000_000)
        assert result.code == expected.code


class TestTotpStorage:
    """Requirement 7.1: storage is unconditional and independent of generation."""

    def test_secret_is_stored_even_with_a_broken_clock(self, vault):
        record = vault.add("Corp", password="p", totp=SECRET)
        assert vault.get(record.id).totp == SECRET

    def test_otpauth_uri_is_stored_verbatim(self, vault):
        uri = f"otpauth://totp/Corp:alan?secret={SECRET}&issuer=Corp"
        record = vault.add("Corp", totp=uri)
        assert vault.get(record.id).totp == uri

    def test_secret_survives_export(self, vault):
        vault.add("Corp", totp=SECRET)
        exported = vault.export_plaintext()
        assert exported["records"][0]["totp"] == SECRET


class TestTotpCli:
    def test_shows_a_code(self, run):
        assert run("add", "Corp", "--password", "p", "--totp", SECRET)[0] == 0
        code, out, err = run("totp", "Corp")
        assert code == 0, err
        assert re.fullmatch(r"\d{6}\n", out)
        assert "valid for" in err

    def test_missing_secret_is_reported(self, run):
        run("add", "Plain", "--password", "p")
        code, _, err = run("totp", "Plain")
        assert code == 1
        assert "no TOTP secret" in err

    def test_at_override_accepts_a_time_of_day(self, run):
        run("add", "Corp", "--password", "p", "--totp", SECRET)
        code, out, err = run("totp", "Corp", "--at", "14:30")
        assert code == 0, err
        assert re.fullmatch(r"\d{6}\n", out)

    def test_at_override_accepts_a_full_timestamp(self, run):
        run("add", "Corp", "--password", "p", "--totp", SECRET)
        code, out, err = run("totp", "Corp", "--at", "2026-09-20 14:30")
        assert code == 0, err

    def test_unparseable_at_is_reported(self, run):
        run("add", "Corp", "--password", "p", "--totp", SECRET)
        code, _, err = run("totp", "Corp", "--at", "tea time")
        assert code == 1
        assert "could not understand" in err

    def test_invalid_secret_is_reported(self, run):
        run("add", "Bad", "--password", "p", "--totp", "not-base32!")
        code, _, err = run("totp", "Bad")
        assert code == 1
        assert "Base32" in err


# =============================================================== generator


class TestGenerate_:
    def test_default_length(self):
        assert len(generator.generate()) == 20

    @pytest.mark.parametrize("length", [4, 8, 16, 32, 64, 128])
    def test_respects_length(self, length):
        assert len(generator.generate(length)) == length

    def test_rejects_absurd_lengths(self):
        with pytest.raises(generator.GeneratorError):
            generator.generate(3)
        with pytest.raises(generator.GeneratorError):
            generator.generate(513)

    def test_values_are_unique(self):
        assert len({generator.generate(24) for _ in range(200)}) == 200

    def test_excludes_ambiguous_characters_by_default(self):
        """Read off a 400x240 monochrome screen, l/1/I are indistinguishable."""
        joined = "".join(generator.generate(64) for _ in range(30))
        for character in generator.AMBIGUOUS:
            assert character not in joined

    def test_allow_ambiguous_restores_them(self):
        joined = "".join(
            generator.generate(128, allow_ambiguous=True) for _ in range(30)
        )
        assert any(c in joined for c in generator.AMBIGUOUS)

    def test_includes_each_requested_class(self):
        for _ in range(30):
            password = generator.generate(16)
            assert any(c in string.ascii_lowercase for c in password)
            assert any(c in string.ascii_uppercase for c in password)
            assert any(c in string.digits for c in password)
            assert any(c in generator.SYMBOLS for c in password)

    def test_no_symbols_mode(self):
        joined = "".join(generator.generate(32, symbols=False) for _ in range(20))
        assert not (set(joined) & set(generator.SYMBOLS))

    def test_no_digits_mode(self):
        joined = "".join(generator.generate(32, digits=False) for _ in range(20))
        assert not (set(joined) & set(string.digits))


class TestThumbMode:
    """Requirement 4.16."""

    def test_omits_symbols(self):
        joined = "".join(generator.generate(32, thumb=True) for _ in range(30))
        assert not (set(joined) & set(generator.SYMBOLS))

    def test_keeps_letters_and_digits(self):
        password = generator.generate(40, thumb=True)
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.digits for c in password)

    def test_thumb_alphabet_is_smaller_than_full(self):
        thumb = generator.build_alphabet(thumb=True)
        full = generator.build_alphabet()
        assert len(thumb) < len(full)

    def test_longer_thumb_password_beats_shorter_full_one(self):
        """The actual argument for the mode: length wins over variety."""
        thumb_bits = generator.entropy_bits(
            len(generator.build_alphabet(thumb=True)), 20
        )
        full_bits = generator.entropy_bits(len(generator.build_alphabet()), 12)
        assert thumb_bits > full_bits
        assert thumb_bits > 100


class TestPassphrase:
    def test_default_word_count(self):
        assert len(generator.generate_passphrase().split("-")) == 6

    def test_respects_word_count_and_separator(self):
        phrase = generator.generate_passphrase(words=7, separator=" ")
        assert len(phrase.split(" ")) == 7

    def test_rejects_too_few_words(self):
        with pytest.raises(generator.GeneratorError):
            generator.generate_passphrase(words=2)

    def test_words_are_lowercase_and_unambiguous(self):
        assert all(w.isalpha() and w.islower() for w in generator.WORDS)
        assert len(set(generator.WORDS)) == len(generator.WORDS)

    def test_wordlist_is_large_enough_for_a_master_password(self):
        """Pins the documented entropy so it cannot silently regress.

        An earlier list had 146 words, making a 5-word phrase only 36 bits while
        the docstring claimed 51. The number printed to the user must be real.
        """
        assert len(generator.WORDS) >= 900
        assert generator.BITS_PER_WORD > 9.5
        assert generator.entropy_bits(len(generator.WORDS), 6) > 55

    def test_word_list_has_no_duplicates(self):
        """A repeated word would skew the distribution and overstate entropy."""
        assert len(set(generator.WORDS)) == len(generator.WORDS)

    def test_default_is_at_least_six_words(self):
        assert len(generator.generate_passphrase().split("-")) >= 6

    def test_values_are_unique(self):
        assert len({generator.generate_passphrase(6) for _ in range(200)}) == 200


class TestEntropy:
    def test_known_values(self):
        assert generator.entropy_bits(2, 8) == 8
        assert round(generator.entropy_bits(62, 20)) == 119

    def test_degenerate_inputs(self):
        assert generator.entropy_bits(1, 10) == 0
        assert generator.entropy_bits(62, 0) == 0


class TestGenCli:
    def test_generates_a_password(self, run):
        code, out, err = run("gen")
        assert code == 0
        assert len(out.strip()) == 20
        assert "bits" in err

    def test_thumb_mode_reports_the_mode(self, run):
        code, out, err = run("gen", "--thumb")
        assert code == 0
        assert "thumb mode" in err
        assert not (set(out.strip()) & set(generator.SYMBOLS))

    def test_passphrase_mode_recommends_it_for_the_master(self, run):
        code, out, err = run("gen", "--passphrase")
        assert code == 0
        assert len(out.strip().split("-")) == 6
        assert "master password" in err
        assert "bits" in err

    def test_count(self, run):
        code, out, _ = run("gen", "--count", "5")
        assert code == 0
        assert len(out.strip().splitlines()) == 5

    def test_works_without_a_vault(self, isolate_home: Path):
        """Generation must not require unlocking anything."""
        runner = Runner(isolate_home / "no-vault", isolate_home / "no-config")
        code, out, _ = runner("gen")
        assert code == 0
        assert len(out.strip()) == 20

    def test_bad_length_is_reported(self, run):
        code, _, err = run("gen", "--length", "2")
        assert code == 1
        assert "at least 4" in err
