"""Tests for secure key storage."""

import pytest

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from sealed.keystore import Keystore, KeystoreError


class TestKeystore:
    def test_generate_plaintext(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        key = ks.generate()
        assert (tmp_path / "test.key").exists()
        assert not ks.is_encrypted()

    def test_generate_encrypted(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        key = ks.generate(passphrase="mypassword")
        assert ks.is_encrypted()

    def test_load_plaintext(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        original = ks.generate()
        loaded = ks.load()
        assert original.encode() == loaded.encode()

    def test_load_encrypted(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        original = ks.generate(passphrase="secret123")
        loaded = ks.load(passphrase="secret123")
        assert original.encode() == loaded.encode()

    def test_wrong_passphrase_fails(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        ks.generate(passphrase="correct")
        with pytest.raises(KeystoreError, match="Wrong passphrase"):
            ks.load(passphrase="wrong", prompt=False)

    def test_encrypted_no_passphrase_fails(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        ks.generate(passphrase="secret")
        with pytest.raises(KeystoreError, match="encrypted"):
            ks.load(passphrase=None, prompt=False)

    def test_change_passphrase(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        original = ks.generate(passphrase="old")

        ks.change_passphrase("old", "new")
        loaded = ks.load(passphrase="new")
        assert original.encode() == loaded.encode()

        with pytest.raises(KeystoreError):
            ks.load(passphrase="old", prompt=False)

    def test_remove_passphrase(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        original = ks.generate(passphrase="secret")
        assert ks.is_encrypted()

        ks.change_passphrase("secret", None)
        assert not ks.is_encrypted()

        loaded = ks.load()
        assert original.encode() == loaded.encode()

    def test_missing_key_file(self, tmp_path):
        ks = Keystore(tmp_path / "nonexistent.key")
        with pytest.raises(KeystoreError, match="not found"):
            ks.load()

    def test_backwards_compatible_hex(self, tmp_path):
        """Old-style plaintext hex keys should still load."""
        key = SigningKey.generate()
        key_hex = key.encode(HexEncoder).decode()
        key_path = tmp_path / "legacy.key"
        key_path.write_text(key_hex)

        ks = Keystore(key_path)
        loaded = ks.load()
        assert key.encode() == loaded.encode()

    def test_public_key_derivation(self, tmp_path):
        ks = Keystore(tmp_path / "test.key")
        key = ks.generate()
        expected_pub = key.verify_key.encode(HexEncoder).decode()

        # Load and derive
        loaded = ks.load()
        actual_pub = loaded.verify_key.encode(HexEncoder).decode()
        assert actual_pub == expected_pub
