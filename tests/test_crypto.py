"""Tests for cryptographic primitives (requirements 2.1, 2.2, 2.5, 2.6, 2.8, 2.9, 6.1).

The ChaCha20-Poly1305 vector below is the official one from RFC 8439 section 2.8.2,
which makes it a true known-answer test against the specification rather than a
regression test against our own output. The Argon2id and BLAKE2b vectors are labelled
as regression vectors, because neither construction as used here has a published
vector that matches our parameters.
"""

from __future__ import annotations

import pytest

from pipassword import crypto

# --------------------------------------------------------------------------- KATs

# RFC 8439 section 2.8.2. Verified to match the cryptography library exactly.
RFC8439_KEY = bytes(range(0x80, 0xA0))
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you "
    b"only one tip for the future, sunscreen would be it."
)
RFC8439_CIPHERTEXT_AND_TAG = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
    "1ae10b594f09e26a7e902ecbd0600691"
)

# Regression vectors: pinned so a dependency upgrade or an accidental parameter change
# is caught immediately. A change here means existing vaults would stop opening.
ARGON2ID_REGRESSION = bytes.fromhex(
    "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e"
)
BLAKE2B_RKEK_REGRESSION = bytes.fromhex(
    "25f52a5916a5c140e376ccac8c70dae6df36d17dd37640dfa3273232423d4fc4"
)


class TestAeadKnownAnswer:
    def test_rfc8439_encrypt(self):
        got = crypto.aead_encrypt(
            RFC8439_KEY, RFC8439_NONCE, RFC8439_PLAINTEXT, RFC8439_AAD
        )
        assert got == RFC8439_CIPHERTEXT_AND_TAG

    def test_rfc8439_decrypt(self):
        got = crypto.aead_decrypt(
            RFC8439_KEY, RFC8439_NONCE, RFC8439_CIPHERTEXT_AND_TAG, RFC8439_AAD
        )
        assert got == RFC8439_PLAINTEXT


class TestKdfKnownAnswer:
    def test_argon2id_regression_vector(self):
        got = crypto.derive_kek(
            "correct horse battery staple",
            salt=bytes(range(16)),
            params=crypto.KdfParams(time_cost=3, memory_cost_kib=65536, parallelism=4),
        )
        assert got == ARGON2ID_REGRESSION

    def test_rkek_regression_vector(self):
        assert crypto.derive_rkek(bytes(range(32))) == BLAKE2B_RKEK_REGRESSION


# ------------------------------------------------------------------- AAD binding


class TestAadBinding:
    """Requirement 2.9: every ciphertext is bound to its header."""

    def setup_method(self):
        self.key = crypto.generate_dek()
        self.nonce = crypto.generate_nonce()
        self.aad = b"header-bytes"
        self.ct = crypto.aead_encrypt(self.key, self.nonce, b"secret", self.aad)

    def test_roundtrip(self):
        assert crypto.aead_decrypt(self.key, self.nonce, self.ct, self.aad) == b"secret"

    def test_modified_aad_fails(self):
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, self.nonce, self.ct, b"header-bytez")

    def test_empty_aad_fails_when_aad_was_used(self):
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, self.nonce, self.ct, b"")

    def test_modified_ciphertext_fails(self):
        tampered = bytearray(self.ct)
        tampered[0] ^= 0x01
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, self.nonce, bytes(tampered), self.aad)

    def test_modified_tag_fails(self):
        tampered = bytearray(self.ct)
        tampered[-1] ^= 0x01
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, self.nonce, bytes(tampered), self.aad)

    def test_wrong_key_fails(self):
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(crypto.generate_dek(), self.nonce, self.ct, self.aad)

    def test_wrong_nonce_fails(self):
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, crypto.generate_nonce(), self.ct, self.aad)

    def test_truncated_ciphertext_fails(self):
        with pytest.raises(crypto.AuthenticationError):
            crypto.aead_decrypt(self.key, self.nonce, self.ct[:8], self.aad)

    def test_error_message_leaks_nothing(self):
        """Design section 10: secrets never appear in an exception message."""
        with pytest.raises(crypto.AuthenticationError) as excinfo:
            crypto.aead_decrypt(crypto.generate_dek(), self.nonce, self.ct, self.aad)
        message = str(excinfo.value)
        assert "secret" not in message
        assert self.key.hex() not in message


# ----------------------------------------------------------------- KDF behaviour


class TestKdfParams:
    def test_defaults_match_requirement_2_2(self):
        params = crypto.DEFAULT_KDF_PARAMS
        assert params.time_cost == 3
        assert params.memory_cost_kib == 65536
        assert params.memory_cost_mib == 64
        assert params.parallelism == 4

    def test_rejects_zero_time_cost(self):
        with pytest.raises(crypto.ParameterError):
            crypto.KdfParams(time_cost=0)

    def test_rejects_zero_parallelism(self):
        with pytest.raises(crypto.ParameterError):
            crypto.KdfParams(parallelism=0)

    def test_rejects_memory_below_8p(self):
        """Argon2 requires m >= 8p; catch it with our message, not a library crash."""
        with pytest.raises(crypto.ParameterError, match="8 \\* parallelism"):
            crypto.KdfParams(memory_cost_kib=16, parallelism=4)

    def test_accepts_memory_exactly_8p(self):
        assert crypto.KdfParams(memory_cost_kib=32, parallelism=4).memory_cost_kib == 32

    def test_is_immutable(self):
        with pytest.raises(AttributeError):
            crypto.DEFAULT_KDF_PARAMS.time_cost = 9  # type: ignore[misc]


class TestDeriveKek:
    FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)

    def test_deterministic(self):
        salt = crypto.generate_salt()
        a = crypto.derive_kek("hunter2", salt, self.FAST)
        b = crypto.derive_kek("hunter2", salt, self.FAST)
        assert a == b
        assert len(a) == crypto.KEY_SIZE

    def test_salt_changes_output(self):
        a = crypto.derive_kek("hunter2", crypto.generate_salt(), self.FAST)
        b = crypto.derive_kek("hunter2", crypto.generate_salt(), self.FAST)
        assert a != b

    def test_password_changes_output(self):
        salt = crypto.generate_salt()
        a = crypto.derive_kek("hunter2", salt, self.FAST)
        b = crypto.derive_kek("hunter3", salt, self.FAST)
        assert a != b

    @pytest.mark.parametrize(
        "params",
        [
            crypto.KdfParams(time_cost=2, memory_cost_kib=64, parallelism=1),
            crypto.KdfParams(time_cost=1, memory_cost_kib=128, parallelism=1),
            crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=2),
        ],
    )
    def test_each_parameter_changes_output(self, params):
        """Guards against a parameter being silently dropped on the way to Argon2."""
        salt = crypto.generate_salt()
        assert crypto.derive_kek("hunter2", salt, self.FAST) != crypto.derive_kek(
            "hunter2", salt, params
        )

    def test_rejects_wrong_salt_length(self):
        for bad in [b"", b"short", bytes(15), bytes(17)]:
            with pytest.raises(crypto.ParameterError, match="salt must be"):
                crypto.derive_kek("hunter2", bad, self.FAST)

    def test_accepts_bytes_password(self):
        salt = crypto.generate_salt()
        assert crypto.derive_kek(b"hunter2", salt, self.FAST) == crypto.derive_kek(
            "hunter2", salt, self.FAST
        )

    def test_rejects_non_string_password(self):
        with pytest.raises(crypto.ParameterError):
            crypto.derive_kek(12345, crypto.generate_salt(), self.FAST)  # type: ignore[arg-type]


class TestUnicodeNormalisation:
    """A Chinese or accented passphrase must derive the same key on every device.

    Relevant here specifically: entries and possibly the passphrase are typed through
    Google Pinyin under fcitx, and different input paths can emit different Unicode
    normalisation forms for visually identical text.
    """

    FAST = crypto.KdfParams(time_cost=1, memory_cost_kib=64, parallelism=1)

    def test_nfc_and_nfd_agree(self):
        salt = crypto.generate_salt()
        composed = "café"  # U+00E9
        decomposed = "cafe\u0301"  # e + combining acute
        assert composed != decomposed
        assert crypto.derive_kek(composed, salt, self.FAST) == crypto.derive_kek(
            decomposed, salt, self.FAST
        )

    def test_chinese_passphrase_roundtrips(self):
        salt = crypto.generate_salt()
        key = crypto.derive_kek("企业邮箱密码", salt, self.FAST)
        assert len(key) == crypto.KEY_SIZE
        assert key == crypto.derive_kek("企业邮箱密码", salt, self.FAST)

    def test_distinct_passphrases_still_differ(self):
        """Normalisation must not collapse genuinely different strings."""
        salt = crypto.generate_salt()
        assert crypto.derive_kek("企业邮箱", salt, self.FAST) != crypto.derive_kek(
            "企业邮件", salt, self.FAST
        )


class TestDeriveRkek:
    def test_deterministic_and_correct_length(self):
        key = crypto.generate_recovery_key()
        assert crypto.derive_rkek(key) == crypto.derive_rkek(key)
        assert len(crypto.derive_rkek(key)) == crypto.KEY_SIZE

    def test_distinct_inputs_give_distinct_outputs(self):
        a = crypto.derive_rkek(crypto.generate_recovery_key())
        b = crypto.derive_rkek(crypto.generate_recovery_key())
        assert a != b

    def test_rejects_wrong_length(self):
        for bad in [b"", bytes(31), bytes(33)]:
            with pytest.raises(crypto.ParameterError, match="recovery key must be"):
                crypto.derive_rkek(bad)

    def test_domain_separated_from_raw_key(self):
        """The RKEK must not equal the recovery key itself."""
        key = crypto.generate_recovery_key()
        assert crypto.derive_rkek(key) != key


# --------------------------------------------------------------- key generation


class TestGeneration:
    def test_sizes(self):
        assert len(crypto.generate_dek()) == crypto.KEY_SIZE
        assert len(crypto.generate_salt()) == crypto.SALT_SIZE
        assert len(crypto.generate_nonce()) == crypto.NONCE_SIZE
        assert len(crypto.generate_recovery_key()) == crypto.RECOVERY_KEY_SIZE

    @pytest.mark.parametrize(
        "factory",
        [
            crypto.generate_dek,
            crypto.generate_salt,
            crypto.generate_nonce,
            crypto.generate_recovery_key,
        ],
    )
    def test_values_are_unique(self, factory):
        values = {factory() for _ in range(100)}
        assert len(values) == 100


# ---------------------------------------------------- recovery key transcription


class TestRecoveryKeyFormatting:
    def test_roundtrip(self):
        key = crypto.generate_recovery_key()
        assert crypto.parse_recovery_key(crypto.format_recovery_key(key)) == key

    def test_formatted_shape(self):
        text = crypto.format_recovery_key(crypto.generate_recovery_key())
        groups = text.split("-")
        assert len(groups) == 13  # 52 chars in groups of 4
        assert all(len(g) == 4 for g in groups)
        assert len(text.replace("-", "")) == 52

    def test_alphabet_excludes_confusable_characters(self):
        """RFC 4648 Base32 has no 0, 1, 8 or 9, so 0/O and 1/l cannot be confused."""
        for _ in range(50):
            text = crypto.format_recovery_key(crypto.generate_recovery_key())
            body = text.replace("-", "")
            assert set(body) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            assert not (set(body) & set("0189"))

    @pytest.mark.parametrize(
        "mangle",
        [
            lambda s: s.lower(),
            lambda s: s.replace("-", ""),
            lambda s: s.replace("-", " "),
            lambda s: f"  {s}  ",
            lambda s: s.replace("-", "\n"),
            lambda s: s.replace("-", "").lower(),
        ],
        ids=["lower", "nodash", "spaces", "padded", "newlines", "lower-nodash"],
    )
    def test_parsing_tolerates_transcription_variation(self, mangle):
        """This will be read off paper and typed on a BBQ20 thumb keyboard."""
        key = crypto.generate_recovery_key()
        assert crypto.parse_recovery_key(mangle(crypto.format_recovery_key(key))) == key

    def test_rejects_dropped_character(self):
        text = crypto.format_recovery_key(crypto.generate_recovery_key())
        with pytest.raises(crypto.ParameterError, match="52 characters"):
            crypto.parse_recovery_key(text.replace("-", "")[:-1])

    def test_rejects_extra_character(self):
        text = crypto.format_recovery_key(crypto.generate_recovery_key())
        with pytest.raises(crypto.ParameterError, match="52 characters"):
            crypto.parse_recovery_key(text + "A")

    def test_rejects_empty(self):
        with pytest.raises(crypto.ParameterError, match="empty"):
            crypto.parse_recovery_key("   ")

    def test_rejects_invalid_characters(self):
        with pytest.raises(crypto.ParameterError, match="invalid characters"):
            crypto.parse_recovery_key("!" * 52)

    def test_rejects_wrong_input_length_to_format(self):
        with pytest.raises(crypto.ParameterError):
            crypto.format_recovery_key(bytes(31))

    def test_recovery_key_unwraps_via_rkek(self):
        """End to end: the printed key must recover a wrapped DEK (requirement 6.2)."""
        dek = crypto.generate_dek()
        recovery_key = crypto.generate_recovery_key()
        printed = crypto.format_recovery_key(recovery_key)

        nonce = crypto.generate_nonce()
        aad = b"keyfile-header"
        wrapped = crypto.aead_encrypt(
            crypto.derive_rkek(recovery_key), nonce, dek, aad
        )

        # Later, on paper, on another device:
        rkek = crypto.derive_rkek(crypto.parse_recovery_key(printed))
        assert crypto.aead_decrypt(rkek, nonce, wrapped, aad) == dek


# ------------------------------------------------------------------ memory check


class TestMemoryCheck:
    """Requirement 2.5: refuse before an OOM kill, with a message that helps."""

    PARAMS = crypto.KdfParams(time_cost=3, memory_cost_kib=65536, parallelism=4)

    def test_sufficient_memory_passes(self):
        result = crypto.check_memory_available(self.PARAMS, available_kib=400_000)
        assert result.sufficient
        assert result.determinable

    def test_insufficient_memory_fails_with_actionable_detail(self):
        result = crypto.check_memory_available(self.PARAMS, available_kib=40_000)
        assert not result.sufficient
        assert "64 MiB" in result.detail
        assert "39 MiB" in result.detail
        assert "Syncthing" in result.detail

    def test_headroom_is_enforced(self):
        """Exactly memory_cost is not enough; 25% headroom is required."""
        exact = crypto.check_memory_available(self.PARAMS, available_kib=65_536)
        assert not exact.sufficient

        with_headroom = crypto.check_memory_available(self.PARAMS, available_kib=81_920)
        assert with_headroom.sufficient

    def test_undeterminable_memory_is_permissive(self):
        """A missing /proc/meminfo must not make the vault unopenable."""
        result = crypto.check_memory_available(
            self.PARAMS, meminfo="/nonexistent/meminfo"
        )
        assert result.sufficient
        assert not result.determinable
        assert "could not be determined" in result.detail

    def test_require_raises_when_insufficient(self):
        with pytest.raises(crypto.InsufficientMemoryError, match="64 MiB"):
            crypto.require_memory_available(self.PARAMS, available_kib=1000)

    def test_require_returns_when_sufficient(self):
        assert crypto.require_memory_available(
            self.PARAMS, available_kib=400_000
        ).sufficient

    def test_reads_meminfo_format(self, tmp_path):
        meminfo = tmp_path / "meminfo"
        meminfo.write_text(
            "MemTotal:         444444 kB\n"
            "MemFree:           12345 kB\n"
            "MemAvailable:     318492 kB\n"
            "Buffers:            5000 kB\n"
        )
        assert crypto.read_mem_available_kib(meminfo) == 318492

    def test_missing_meminfo_returns_none(self, tmp_path):
        assert crypto.read_mem_available_kib(tmp_path / "absent") is None

    def test_meminfo_without_memavailable_returns_none(self, tmp_path):
        """Very old kernels lack MemAvailable; treat that as undeterminable."""
        meminfo = tmp_path / "meminfo"
        meminfo.write_text("MemTotal: 444444 kB\nMemFree: 12345 kB\n")
        assert crypto.read_mem_available_kib(meminfo) is None

    def test_directory_as_meminfo_returns_none(self, tmp_path):
        assert crypto.read_mem_available_kib(tmp_path) is None

    def test_real_meminfo_does_not_raise(self):
        """On Linux this returns an int; on this dev machine, None. Neither raises."""
        result = crypto.read_mem_available_kib()
        assert result is None or result > 0


# ----------------------------------------------------------------------- hygiene


class TestHygiene:
    def test_constant_time_equal(self):
        assert crypto.constant_time_equal(b"abc", b"abc")
        assert not crypto.constant_time_equal(b"abc", b"abd")
        assert not crypto.constant_time_equal(b"abc", b"ab")

    def test_wipe_zeroes_bytearray(self):
        buffer = bytearray(b"super secret key")
        crypto.wipe(buffer)
        assert bytes(buffer) == bytes(len(buffer))

    def test_wipe_rejects_immutable(self):
        with pytest.raises(crypto.ParameterError, match="bytearray"):
            crypto.wipe(b"immutable")  # type: ignore[arg-type]


class TestNonceReuseSurface:
    def test_nonces_do_not_repeat_across_many_events(self):
        """Sanity check on the random-nonce choice for per-event encryption."""
        nonces = {crypto.generate_nonce() for _ in range(20_000)}
        assert len(nonces) == 20_000


class TestMemoryHuman:
    """Tiny test parameters must not render as a confusing "0 MiB"."""

    def test_below_one_mib_shows_kib(self):
        assert crypto.KdfParams(
            time_cost=1, memory_cost_kib=64, parallelism=1
        ).memory_human == "64 KiB"

    def test_at_and_above_one_mib_shows_mib(self):
        assert crypto.KdfParams(memory_cost_kib=1024).memory_human == "1 MiB"
        assert crypto.DEFAULT_KDF_PARAMS.memory_human == "64 MiB"
