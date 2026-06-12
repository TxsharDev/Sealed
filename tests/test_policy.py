"""Tests for trust policy engine."""

import json
import pytest

from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority
from sealed.registry import SealRegistry
from sealed.policy import PolicyEngine, PolicyConfig, PolicyResult


def _setup(tmp_path, **config_kwargs):
    registry = SealRegistry(tmp_path / "test.db")
    config = PolicyConfig(**config_kwargs)
    engine = PolicyEngine(config, registry)
    return engine, registry


def _make_sealed(pkg="test", ver="1.0", auth=None):
    auth = auth or SealAuthority()
    chain = ProvenanceChain(package_name=pkg, package_version=ver)
    chain.add("build", "a", "b")
    seal = auth.seal(chain)
    return seal, chain, auth


class TestPolicyEngine:
    def test_default_policy_accepts(self, tmp_path):
        engine, reg = _setup(tmp_path)
        seal, chain, _ = _make_sealed()
        result = engine.evaluate(seal, chain)
        assert result.accepted
        reg.close()

    def test_signature_failure_rejects(self, tmp_path):
        engine, reg = _setup(tmp_path)
        seal, chain, _ = _make_sealed()
        chain.records[0].output_hash = "TAMPERED"
        result = engine.evaluate(seal, chain)
        assert not result.accepted
        assert any("Signature" in e or "signature" in e for e in result.errors)
        reg.close()

    def test_tofu_pins_on_first_use(self, tmp_path):
        engine, reg = _setup(tmp_path, tofu_enabled=True)
        seal, chain, auth = _make_sealed()
        result = engine.evaluate(seal, chain)
        assert result.accepted
        # Key should now be pinned
        pin = reg.check_pin("test", auth.public_key)
        assert pin.status == "ok"
        reg.close()

    def test_tofu_pin_mismatch_rejects(self, tmp_path):
        engine, reg = _setup(tmp_path, tofu_enabled=True, enforce_pins=True)
        auth1 = SealAuthority()
        auth2 = SealAuthority()

        # First seal pins auth1's key
        seal1, chain1, _ = _make_sealed(auth=auth1)
        result1 = engine.evaluate(seal1, chain1)
        assert result1.accepted

        # Second seal from auth2 should be rejected (key mismatch)
        seal2, chain2, _ = _make_sealed(auth=auth2)
        result2 = engine.evaluate(seal2, chain2)
        assert not result2.accepted
        assert any("MISMATCH" in e for e in result2.errors)
        reg.close()

    def test_revoked_key_rejected(self, tmp_path):
        engine, reg = _setup(tmp_path, check_revocations=True)
        seal, chain, auth = _make_sealed()
        reg.revoke_key(auth.public_key, "compromised")
        result = engine.evaluate(seal, chain)
        assert not result.accepted
        reg.close()

    def test_multi_party_insufficient(self, tmp_path):
        engine, reg = _setup(tmp_path, min_signatures=3)
        seal, chain, _ = _make_sealed()
        result = engine.evaluate(seal, chain)
        assert not result.accepted
        assert any("signatures" in e for e in result.errors)
        reg.close()

    def test_multi_party_sufficient(self, tmp_path):
        engine, reg = _setup(tmp_path, min_signatures=2)
        auth1 = SealAuthority()
        auth2 = SealAuthority()

        # Store first signer's seal in registry
        seal1, chain1, _ = _make_sealed(auth=auth1)
        reg.store(seal1, chain1)

        # Evaluate second signer's seal
        seal2, chain2, _ = _make_sealed(auth=auth2)
        result = engine.evaluate(seal2, chain2)
        assert result.accepted
        reg.close()

    def test_attestation_requirement(self, tmp_path):
        engine, reg = _setup(tmp_path, require_attestation=["tpm2"])
        seal, chain, _ = _make_sealed()
        result = engine.evaluate(seal, chain, attestation_method="software")
        assert not result.accepted
        assert any("attestation" in e.lower() for e in result.errors)
        reg.close()

    def test_attestation_accepted(self, tmp_path):
        engine, reg = _setup(tmp_path, require_attestation=["software", "tpm2"])
        seal, chain, _ = _make_sealed()
        result = engine.evaluate(seal, chain, attestation_method="software")
        assert result.accepted
        reg.close()


class TestPolicyConfig:
    def test_defaults(self):
        config = PolicyConfig()
        assert config.min_signatures == 1
        assert config.tofu_enabled is True
        assert config.enforce_pins is True

    def test_roundtrip(self, tmp_path):
        config = PolicyConfig(min_signatures=3, tofu_enabled=False)
        path = tmp_path / "policy.json"
        config.save(path)
        loaded = PolicyConfig.load(path)
        assert loaded.min_signatures == 3
        assert loaded.tofu_enabled is False

    def test_from_dict_ignores_extra(self):
        config = PolicyConfig.from_dict({
            "min_signatures": 2,
            "unknown_field": "ignored",
        })
        assert config.min_signatures == 2
