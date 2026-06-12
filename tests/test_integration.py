"""Integration tests: full pipeline on real PyPI packages.

Tests the entire flow: fetch -> build -> attest -> seal -> verify -> registry -> policy.
Requires network access for PyPI downloads.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from sealed.attestation import create_attestation, SoftwareAttestor
from sealed.builder import IsolatedBuilder
from sealed.chain import ProvenanceChain, _hash_file
from sealed.policy import PolicyConfig, PolicyEngine
from sealed.registry import SealRegistry
from sealed.resolver import DependencyResolver
from sealed.seal import SealAuthority, Seal, SealError
from sealed.source import SourceFetcher, SourceFetchError
from sealed.verify import SealVerifier


# Use `six` for integration tests: pure Python, tiny, fast to build, no deps
TEST_PKG = "six"
TEST_VER = "1.17.0"


@pytest.fixture
def work_dir(tmp_path):
    return tmp_path


@pytest.fixture
def registry(tmp_path):
    reg = SealRegistry(tmp_path / "test.db")
    yield reg
    reg.close()


def _fetch_source(work_dir):
    """Helper: fetch source, return SourceResult."""
    fetcher = SourceFetcher(cache_dir=work_dir / "cache")
    return fetcher.fetch(TEST_PKG, TEST_VER)


def _build_and_seal(work_dir, source, authority=None):
    """Helper: build from source, seal, return everything."""
    authority = authority or SealAuthority()
    builder = IsolatedBuilder(work_dir=work_dir / "build")
    result = builder.build(
        source.source_dir, source.archive_hash,
        source.package, source.version,
    )
    seal = authority.seal(result.chain)
    return result, seal, authority


# ─── 1. Source Fetching ───────────────────────────────────────────────

class TestSourceFetchLive:
    @pytest.mark.network
    def test_fetch_real_package(self, work_dir):
        source = _fetch_source(work_dir)
        assert source.package == TEST_PKG
        assert source.version == TEST_VER
        assert source.source_dir.exists()
        assert len(source.archive_hash) == 64
        assert source.archive_hash == source.pypi_hash  # hash matches PyPI

    @pytest.mark.network
    def test_fetch_nonexistent_package(self, work_dir):
        fetcher = SourceFetcher(cache_dir=work_dir / "cache")
        with pytest.raises(SourceFetchError, match="not found"):
            fetcher.fetch("this-package-definitely-does-not-exist-sealed-test")

    @pytest.mark.network
    def test_pypi_hash_verified(self, work_dir):
        """The archive hash must match PyPI's reported SHA-256."""
        source = _fetch_source(work_dir)
        computed = _hash_file(source.archive_path)
        assert computed == source.pypi_hash


# ─── 2. Build + Attestation ──────────────────────────────────────────

class TestBuildLive:
    @pytest.mark.network
    def test_build_produces_artifact(self, work_dir):
        source = _fetch_source(work_dir)
        builder = IsolatedBuilder(work_dir=work_dir / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )
        assert result.artifact.exists()
        assert result.artifact.suffix == ".whl"
        assert len(result.artifact_hash) == 64

    @pytest.mark.network
    def test_build_includes_attestation(self, work_dir):
        source = _fetch_source(work_dir)
        builder = IsolatedBuilder(work_dir=work_dir / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )
        assert result.attestation is not None
        assert result.attestation.method == "software"
        assert "python_binary" in result.attestation.measurements

    @pytest.mark.network
    def test_chain_has_four_steps(self, work_dir):
        source = _fetch_source(work_dir)
        builder = IsolatedBuilder(work_dir=work_dir / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )
        steps = [r.step for r in result.chain.records]
        assert steps == [
            "environment_attestation",
            "source_audit",
            "source_verify",
            "toolchain_capture",
            "build",
        ]

    @pytest.mark.network
    def test_artifact_hash_matches_chain(self, work_dir):
        source = _fetch_source(work_dir)
        builder = IsolatedBuilder(work_dir=work_dir / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )
        build_record = [r for r in result.chain.records if r.step == "build"][0]
        assert build_record.output_hash == _hash_file(result.artifact)


# ─── 3. Seal + Verify ────────────────────────────────────────────────

class TestSealVerifyLive:
    @pytest.mark.network
    def test_seal_and_verify_clean(self, work_dir):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        # Verify signature
        assert SealAuthority.verify_seal(seal, result.chain) is True

        # Verify via SealVerifier (file-based)
        seal_path = work_dir / "seal.json"
        chain_path = work_dir / "chain.json"
        seal.save(seal_path)
        chain_path.write_text(result.chain.to_json())

        verifier = SealVerifier()
        vr = verifier.verify(seal_path, result.artifact, chain_path)
        assert vr.ok, f"Verification failed: {vr.errors}"

    @pytest.mark.network
    def test_tampered_artifact_detected(self, work_dir):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        seal_path = work_dir / "seal.json"
        chain_path = work_dir / "chain.json"
        seal.save(seal_path)
        chain_path.write_text(result.chain.to_json())

        # Tamper: append one byte to artifact
        tampered = work_dir / "tampered.whl"
        data = result.artifact.read_bytes()
        tampered.write_bytes(data + b"\x00")

        verifier = SealVerifier()
        vr = verifier.verify(seal_path, tampered, chain_path)
        assert not vr.ok
        assert any("hash mismatch" in e.lower() for e in vr.errors)

    @pytest.mark.network
    def test_tampered_chain_detected(self, work_dir):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        seal_path = work_dir / "seal.json"
        chain_path = work_dir / "chain.json"
        seal.save(seal_path)

        # Tamper: modify a record, reserialize
        result.chain.records[-1].output_hash = "0" * 64
        chain_path.write_text(result.chain.to_json())

        verifier = SealVerifier()
        vr = verifier.verify(seal_path, result.artifact, chain_path)
        assert not vr.ok

    @pytest.mark.network
    def test_wrong_key_detected(self, work_dir):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        # Forge: sign with different key
        imposter = SealAuthority()
        fake_seal = imposter.seal(result.chain)

        # Replace signature but keep original public key (forged)
        fake_seal.public_key = auth.public_key

        verifier = SealVerifier()
        vr = verifier.verify_json(fake_seal.to_json(), result.chain.to_json())
        assert not vr.ok


# ─── 4. Registry + TOFU ──────────────────────────────────────────────

class TestRegistryLive:
    @pytest.mark.network
    def test_store_and_retrieve(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        registry.store(seal, result.chain, result.attestation.method)
        entries = registry.lookup(TEST_PKG, TEST_VER)
        assert len(entries) == 1
        assert entries[0].seal.package_name == TEST_PKG
        assert entries[0].attestation_method == "software"

    @pytest.mark.network
    def test_tofu_pinning_flow(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        # First check: should be first_use
        pin = registry.check_pin(TEST_PKG, auth.public_key)
        assert pin.is_first_use

        # Pin the key
        registry.pin_key(TEST_PKG, auth.public_key)

        # Same key: ok
        pin = registry.check_pin(TEST_PKG, auth.public_key)
        assert pin.status == "ok"

        # Different key: mismatch
        other = SealAuthority()
        pin = registry.check_pin(TEST_PKG, other.public_key)
        assert pin.status == "mismatch"

    @pytest.mark.network
    def test_revocation_flow(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        registry.revoke_key(auth.public_key, "test revocation")
        pin = registry.check_pin(TEST_PKG, auth.public_key)
        assert pin.status == "revoked"
        assert not pin.ok

    @pytest.mark.network
    def test_export_import_roundtrip(self, work_dir, tmp_path):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        # Store in registry 1
        reg1 = SealRegistry(tmp_path / "src.db")
        reg1.store(seal, result.chain)
        exported = reg1.export_seals()
        reg1.close()

        # Import into registry 2
        reg2 = SealRegistry(tmp_path / "dst.db")
        count = reg2.import_seals(exported)
        assert count == 1

        entries = reg2.lookup(TEST_PKG, TEST_VER)
        assert len(entries) == 1
        assert entries[0].seal.chain_hash == seal.chain_hash
        reg2.close()


# ─── 5. Policy Engine ────────────────────────────────────────────────

class TestPolicyLive:
    @pytest.mark.network
    def test_default_policy_accepts(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        engine = PolicyEngine(PolicyConfig(), registry)
        pr = engine.evaluate(seal, result.chain, result.attestation.method)
        assert pr.accepted

    @pytest.mark.network
    def test_multi_party_rejects_single_signer(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        config = PolicyConfig(min_signatures=2)
        engine = PolicyEngine(config, registry)
        pr = engine.evaluate(seal, result.chain)
        assert not pr.accepted
        assert any("signatures" in e for e in pr.errors)

    @pytest.mark.network
    def test_multi_party_accepts_two_signers(self, work_dir, registry):
        source = _fetch_source(work_dir)

        # Signer 1
        auth1 = SealAuthority()
        result1, seal1, _ = _build_and_seal(work_dir, source, auth1)
        registry.store(seal1, result1.chain)

        # Signer 2
        auth2 = SealAuthority()
        result2, seal2, _ = _build_and_seal(
            work_dir / "build2", source, auth2,
        )

        config = PolicyConfig(min_signatures=2)
        engine = PolicyEngine(config, registry)
        pr = engine.evaluate(seal2, result2.chain)
        assert pr.accepted

    @pytest.mark.network
    def test_revoked_key_rejected_by_policy(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        registry.revoke_key(auth.public_key, "compromised in test")

        config = PolicyConfig(check_revocations=True)
        engine = PolicyEngine(config, registry)
        pr = engine.evaluate(seal, result.chain)
        assert not pr.accepted

    @pytest.mark.network
    def test_tofu_pins_automatically(self, work_dir, registry):
        source = _fetch_source(work_dir)
        result, seal, auth = _build_and_seal(work_dir, source)

        config = PolicyConfig(tofu_enabled=True, enforce_pins=True)
        engine = PolicyEngine(config, registry)

        # First eval: pins the key
        pr1 = engine.evaluate(seal, result.chain)
        assert pr1.accepted

        # Same key again: ok
        pr2 = engine.evaluate(seal, result.chain)
        assert pr2.accepted

        # Different key: rejected
        auth2 = SealAuthority()
        result2, seal2, _ = _build_and_seal(work_dir / "b2", source, auth2)
        pr3 = engine.evaluate(seal2, result2.chain)
        assert not pr3.accepted
        assert any("MISMATCH" in e for e in pr3.errors)


# ─── 6. Dependency Resolution ────────────────────────────────────────

class TestResolverLive:
    @pytest.mark.network
    def test_resolve_six(self):
        """six has zero deps, should resolve to just itself."""
        resolver = DependencyResolver()
        deps = resolver.resolve(TEST_PKG, TEST_VER)
        assert len(deps) >= 1
        names = [d.name for d in deps]
        assert "six" in names

    @pytest.mark.network
    def test_resolve_requests(self):
        """requests has 4-5 transitive deps."""
        resolver = DependencyResolver()
        deps = resolver.resolve("requests", "2.32.3")
        names = [d.name for d in deps]
        assert "requests" in names
        # Should include at least urllib3 and certifi
        assert any("urllib3" in n for n in names)
        assert any("certifi" in n for n in names)
        # requests should be last (depends on the others)
        assert names[-1] == "requests"

    @pytest.mark.network
    def test_resolve_order_is_topological(self):
        """Dependencies must come before dependents."""
        resolver = DependencyResolver()
        deps = resolver.resolve("requests", "2.32.3")
        names = [d.name for d in deps]
        req_idx = names.index("requests")
        for dep in deps:
            if dep.name != "requests":
                dep_idx = names.index(dep.name)
                assert dep_idx < req_idx, \
                    f"{dep.name} should come before requests"


# ─── 7. Full Pipeline ────────────────────────────────────────────────

class TestFullPipeline:
    @pytest.mark.network
    def test_complete_flow(self, work_dir):
        """The complete sealed flow: fetch -> build -> attest -> seal -> verify -> registry -> policy."""
        # Setup
        authority = SealAuthority()
        db = work_dir / "registry.db"
        registry = SealRegistry(db)
        config = PolicyConfig(tofu_enabled=True)
        policy = PolicyEngine(config, registry)
        verifier = SealVerifier()

        # 1. Fetch
        fetcher = SourceFetcher(cache_dir=work_dir / "cache")
        source = fetcher.fetch(TEST_PKG, TEST_VER)
        assert source.archive_hash == source.pypi_hash

        # 2. Build (includes attestation)
        builder = IsolatedBuilder(work_dir=work_dir / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )
        assert result.attestation.method == "software"
        assert len(result.chain.records) == 5

        # 3. Seal
        seal = authority.seal(result.chain)
        seal_path = work_dir / "seal.json"
        chain_path = work_dir / "chain.json"
        seal.save(seal_path)
        chain_path.write_text(result.chain.to_json())

        # 4. Verify (clean)
        vr = verifier.verify(seal_path, result.artifact, chain_path)
        assert vr.ok, f"Clean verify failed: {vr.errors}"

        # 5. Policy (TOFU)
        pr = policy.evaluate(seal, result.chain, result.attestation.method)
        assert pr.accepted

        # 6. Registry
        registry.store(seal, result.chain, result.attestation.method)
        entries = registry.lookup(TEST_PKG, TEST_VER)
        assert len(entries) == 1

        # 7. Tamper detection
        tampered = work_dir / "tampered.whl"
        tampered.write_bytes(result.artifact.read_bytes() + b"X")
        vr_tampered = verifier.verify(seal_path, tampered, chain_path)
        assert not vr_tampered.ok
        assert any("hash" in e.lower() for e in vr_tampered.errors)

        # 8. Key pin holds
        pin = registry.check_pin(TEST_PKG, authority.public_key)
        assert pin.status == "ok"

        # 9. Imposter rejected
        imposter = SealAuthority()
        fake_seal = imposter.seal(result.chain)
        fake_seal.public_key = authority.public_key  # forge the key field
        vr_forged = verifier.verify_json(fake_seal.to_json(), result.chain.to_json())
        assert not vr_forged.ok

        registry.close()
