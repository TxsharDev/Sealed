"""Tests for seal authority and signature verification."""

import tempfile
from pathlib import Path

import pytest

from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority, Seal, SealError


class TestSealAuthority:
    def test_keygen(self):
        auth = SealAuthority()
        assert len(auth.public_key) == 64  # 32 bytes hex

    def test_seal_and_verify(self):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "aaa", "bbb")
        chain.add("build", "bbb", "ccc")

        seal = auth.seal(chain)
        assert seal.package_name == "test"
        assert seal.chain_hash == chain.chain_hash()

        # Verify succeeds
        assert SealAuthority.verify_seal(seal, chain) is True

    def test_verify_fails_on_tampered_chain(self):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "aaa", "bbb")
        seal = auth.seal(chain)

        # Tamper with chain
        chain.records[0].output_hash = "TAMPERED"
        with pytest.raises(SealError, match="Chain hash mismatch"):
            SealAuthority.verify_seal(seal, chain)

    def test_verify_fails_on_wrong_key(self):
        auth1 = SealAuthority()
        auth2 = SealAuthority()

        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "a", "b")

        # Sign with auth1
        seal = auth1.seal(chain)

        # Forge: replace public key with auth2's
        seal.public_key = auth2.public_key
        with pytest.raises(SealError, match="Signature verification failed"):
            SealAuthority.verify_seal(seal, chain)

    def test_key_persistence(self, tmp_path):
        auth1 = SealAuthority()
        key_path = tmp_path / "test.key"
        auth1.save_key(key_path)

        auth2 = SealAuthority.from_key_file(key_path)
        assert auth1.public_key == auth2.public_key

        # Sign with original, verify with loaded
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("build", "x", "y")
        seal = auth1.seal(chain)
        assert SealAuthority.verify_seal(seal, chain) is True


class TestSeal:
    def test_json_roundtrip(self):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="pkg", package_version="3.0")
        chain.add("source", "a", "b")
        seal = auth.seal(chain)

        j = seal.to_json()
        restored = Seal.from_json(j)
        assert restored.chain_hash == seal.chain_hash
        assert restored.signature == seal.signature
        assert restored.public_key == seal.public_key

    def test_file_roundtrip(self, tmp_path):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="pkg", package_version="1.0")
        chain.add("build", "x", "y")
        seal = auth.seal(chain)

        seal_path = tmp_path / "test.seal.json"
        seal.save(seal_path)
        loaded = Seal.load(seal_path)
        assert loaded.signature == seal.signature
