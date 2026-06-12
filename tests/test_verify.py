"""Tests for end-to-end verification."""

import json
from pathlib import Path

import pytest

from sealed.chain import ProvenanceChain, _hash_file
from sealed.seal import SealAuthority, Seal
from sealed.verify import SealVerifier, VerifyResult


def _make_sealed_artifact(tmp_path, authority=None):
    """Helper: create a fake sealed artifact for testing."""
    authority = authority or SealAuthority()

    # Fake artifact
    artifact = tmp_path / "pkg-1.0-py3-none-any.whl"
    artifact.write_bytes(b"fake wheel content")
    artifact_hash = _hash_file(artifact)

    # Build chain
    chain = ProvenanceChain(package_name="pkg", package_version="1.0")
    chain.add("source_verify", "src_archive_hash", "src_dir_hash", source_dir="/tmp/src")
    chain.add("toolchain_capture", "python_hash", "python_hash", python="/usr/bin/python3")
    chain.add("build", "src_dir_hash", artifact_hash, artifact=artifact.name)

    # Seal
    seal = authority.seal(chain)
    seal_path = tmp_path / "pkg-1.0.seal.json"
    chain_path = tmp_path / "pkg-1.0.chain.json"
    seal.save(seal_path)
    chain_path.write_text(chain.to_json())

    return seal_path, chain_path, artifact, authority


class TestSealVerifier:
    def test_valid_seal(self, tmp_path):
        seal_path, chain_path, artifact, auth = _make_sealed_artifact(tmp_path)
        verifier = SealVerifier()
        result = verifier.verify(seal_path, artifact, chain_path)
        assert result.ok
        assert result.package_name == "pkg"
        assert result.chain_length == 3

    def test_tampered_artifact(self, tmp_path):
        seal_path, chain_path, artifact, _ = _make_sealed_artifact(tmp_path)

        # Tamper with artifact
        artifact.write_bytes(b"TAMPERED content")

        verifier = SealVerifier()
        result = verifier.verify(seal_path, artifact, chain_path)
        assert not result.ok
        assert any("hash mismatch" in e for e in result.errors)

    def test_tampered_chain_record(self, tmp_path):
        seal_path, chain_path, artifact, _ = _make_sealed_artifact(tmp_path)

        # Tamper with a record in the chain file
        chain_data = json.loads(chain_path.read_text())
        chain_data["records"][0]["output_hash"] = "TAMPERED"
        chain_path.write_text(json.dumps(chain_data))

        verifier = SealVerifier()
        result = verifier.verify(seal_path, artifact, chain_path)
        assert not result.ok

    def test_tampered_chain_hash_detected(self, tmp_path):
        """Tamper with record but also update stored hash -- seal signature catches it."""
        seal_path, chain_path, artifact, _ = _make_sealed_artifact(tmp_path)

        # Load, tamper, recompute hash (but can't re-sign)
        chain, _ = ProvenanceChain.from_json(chain_path.read_text())
        chain.records[0].output_hash = "TAMPERED"
        chain_path.write_text(chain.to_json())  # new hash, but seal signed old hash

        verifier = SealVerifier()
        result = verifier.verify(seal_path, artifact, chain_path)
        assert not result.ok
        assert any("Seal verification" in e or "Chain hash mismatch" in e for e in result.errors)

    def test_untrusted_key(self, tmp_path):
        seal_path, chain_path, artifact, auth = _make_sealed_artifact(tmp_path)

        other = SealAuthority()
        verifier = SealVerifier(trusted_keys=[other.public_key])
        result = verifier.verify(seal_path, artifact, chain_path)
        assert not result.ok
        assert any("not in trusted keys" in e for e in result.errors)

    def test_trusted_key_passes(self, tmp_path):
        auth = SealAuthority()
        seal_path, chain_path, artifact, _ = _make_sealed_artifact(tmp_path, auth)

        verifier = SealVerifier(trusted_keys=[auth.public_key])
        result = verifier.verify(seal_path, artifact, chain_path)
        assert result.ok

    def test_missing_seal_file(self, tmp_path):
        verifier = SealVerifier()
        result = verifier.verify(tmp_path / "nonexistent.json")
        assert not result.ok
        assert any("Cannot load seal" in e for e in result.errors)

    def test_verify_json(self, tmp_path):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="x", package_version="1.0")
        chain.add("build", "a", "b")
        seal = auth.seal(chain)

        verifier = SealVerifier()
        result = verifier.verify_json(seal.to_json(), chain.to_json())
        assert result.ok

    def test_verify_json_tampered(self):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="x", package_version="1.0")
        chain.add("build", "a", "b")
        seal = auth.seal(chain)

        # Tamper seal
        seal_data = json.loads(seal.to_json())
        seal_data["chain_hash"] = "0" * 64
        tampered_seal_json = json.dumps(seal_data)

        verifier = SealVerifier()
        result = verifier.verify_json(tampered_seal_json, chain.to_json())
        assert not result.ok

    def test_cross_package_seal_rejected(self):
        """Seal from package A should not verify against package B's chain."""
        auth = SealAuthority()

        chain_a = ProvenanceChain(package_name="pkg_a", package_version="1.0")
        chain_a.add("build", "a", "b")
        seal_a = auth.seal(chain_a)

        chain_b = ProvenanceChain(package_name="pkg_b", package_version="1.0")
        chain_b.add("build", "a", "b")

        verifier = SealVerifier()
        result = verifier.verify_json(seal_a.to_json(), chain_b.to_json())
        assert not result.ok

    def test_replay_old_seal_on_new_version(self):
        """Seal from v1.0 should not verify against v2.0 chain."""
        auth = SealAuthority()

        chain_v1 = ProvenanceChain(package_name="pkg", package_version="1.0")
        chain_v1.add("build", "a", "b")
        seal_v1 = auth.seal(chain_v1)

        chain_v2 = ProvenanceChain(package_name="pkg", package_version="2.0")
        chain_v2.add("build", "a", "b")

        verifier = SealVerifier()
        result = verifier.verify_json(seal_v1.to_json(), chain_v2.to_json())
        assert not result.ok


class TestVerifyResult:
    def test_ok_true(self):
        r = VerifyResult(valid=True, package_name="a", package_version="1", chain_length=2, errors=[])
        assert r.ok

    def test_ok_false_with_errors(self):
        r = VerifyResult(valid=True, package_name="a", package_version="1", chain_length=2, errors=["bad"])
        assert not r.ok

    def test_ok_false_invalid(self):
        r = VerifyResult(valid=False, package_name="a", package_version="1", chain_length=2, errors=[])
        assert not r.ok
