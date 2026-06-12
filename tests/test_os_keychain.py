"""Tests for OS keychain integration."""

import platform
import pytest

from sealed.os_keychain import OSKeychain, KeychainError


class TestOSKeychain:
    def test_available_returns_bool(self):
        result = OSKeychain.available()
        assert isinstance(result, bool)

    @pytest.mark.skipif(
        not OSKeychain.available(),
        reason="OS keychain not available on this platform",
    )
    def test_store_and_load(self):
        from nacl.signing import SigningKey
        key = SigningKey.generate()

        try:
            OSKeychain.store(key)
            loaded = OSKeychain.load()
            assert key.encode() == loaded.encode()
        finally:
            OSKeychain.delete()

    def test_load_missing_key(self):
        if not OSKeychain.available():
            pytest.skip("OS keychain not available")
        # Delete first to ensure clean state
        OSKeychain.delete()
        with pytest.raises(KeychainError):
            OSKeychain.load()
