"""Tests for provenance chain."""

import json

import pytest

from sealed.chain import (
    ProvenanceChain,
    ProvenanceRecord,
    BuildEnvironment,
    _hash_file,
    _hash_bytes,
    _hash_directory,
)


class TestHashing:
    def test_hash_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        h = _hash_file(f)
        assert len(h) == 64  # sha256 hex
        assert h == _hash_bytes(b"hello world")

    def test_hash_file_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_bytes(b"sealed")
        assert _hash_file(f) == _hash_file(f)

    def test_hash_directory(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"aaa")
        (tmp_path / "b.txt").write_bytes(b"bbb")
        h1 = _hash_directory(tmp_path)
        assert len(h1) == 64

        # Same content = same hash
        d2 = tmp_path / "copy"
        d2.mkdir()
        (d2 / "a.txt").write_bytes(b"aaa")
        (d2 / "b.txt").write_bytes(b"bbb")
        assert _hash_directory(d2) == h1

    def test_hash_directory_different_content(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"aaa")
        h1 = _hash_directory(tmp_path)
        (tmp_path / "a.txt").write_bytes(b"bbb")
        h2 = _hash_directory(tmp_path)
        assert h1 != h2

    def test_hash_directory_skips_symlinks(self, tmp_path):
        (tmp_path / "real.txt").write_bytes(b"data")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(tmp_path / "real.txt")
        except OSError:
            pytest.skip("symlinks not supported")
        h1 = _hash_directory(tmp_path)
        # Remove symlink, hash should stay the same (only real.txt counted)
        link.unlink()
        h2 = _hash_directory(tmp_path)
        assert h1 == h2

    def test_hash_directory_empty(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        h = _hash_directory(empty)
        assert len(h) == 64  # valid hash of nothing


class TestProvenanceRecord:
    def test_roundtrip(self):
        r = ProvenanceRecord(
            step="build",
            input_hash="abc123",
            output_hash="def456",
            metadata={"key": "value"},
        )
        d = r.to_dict()
        assert d["step"] == "build"
        assert d["input_hash"] == "abc123"
        assert d["metadata"]["key"] == "value"

    def test_canonical_bytes_deterministic(self):
        r = ProvenanceRecord(
            step="build", input_hash="a", output_hash="b",
            timestamp=1000.0, metadata={"x": 1, "y": 2},
        )
        assert r.canonical_bytes() == r.canonical_bytes()

    def test_canonical_bytes_different_for_different_records(self):
        r1 = ProvenanceRecord(step="build", input_hash="a", output_hash="b", timestamp=1.0)
        r2 = ProvenanceRecord(step="build", input_hash="a", output_hash="c", timestamp=1.0)
        assert r1.canonical_bytes() != r2.canonical_bytes()


class TestProvenanceChain:
    def test_add_records(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "aaa", "bbb")
        chain.add("build", "bbb", "ccc")
        assert len(chain.records) == 2

    def test_chain_hash_deterministic(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "aaa", "bbb")
        assert chain.chain_hash() == chain.chain_hash()

    def test_chain_hash_changes_on_tamper(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "aaa", "bbb")
        h1 = chain.chain_hash()

        chain.records[0].output_hash = "TAMPERED"
        h2 = chain.chain_hash()
        assert h1 != h2

    def test_chain_hash_includes_environment(self):
        chain1 = ProvenanceChain(
            package_name="test", package_version="1.0",
            environment=BuildEnvironment(
                python_version="3.12", platform="Linux",
                architecture="x86_64", hostname="host1",
            ),
        )
        chain2 = ProvenanceChain(
            package_name="test", package_version="1.0",
            environment=BuildEnvironment(
                python_version="3.12", platform="Linux",
                architecture="x86_64", hostname="host2",
            ),
        )
        chain1.add("build", "a", "b")
        chain2.add("build", "a", "b")
        assert chain1.chain_hash() != chain2.chain_hash()

    def test_json_roundtrip(self):
        chain = ProvenanceChain(package_name="pkg", package_version="2.0")
        chain.add("source", "a", "b", url="https://example.com")
        chain.add("build", "b", "c", flags=["--release"])

        j = chain.to_json()
        restored, stored_hash = ProvenanceChain.from_json(j)
        assert restored.package_name == "pkg"
        assert restored.package_version == "2.0"
        assert len(restored.records) == 2
        assert restored.records[0].metadata["url"] == "https://example.com"
        assert restored.chain_hash() == chain.chain_hash()
        assert stored_hash == chain.chain_hash()

    def test_verify_integrity_clean(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "a", "b")
        stored_hash = chain.chain_hash()
        assert chain.verify_integrity(stored_hash)

    def test_verify_integrity_tampered(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "a", "b")
        stored_hash = chain.chain_hash()
        # Tamper after storing hash
        chain.records[0].output_hash = "TAMPERED"
        assert not chain.verify_integrity(stored_hash)

    def test_verify_integrity_wrong_hash(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("source", "a", "b")
        assert not chain.verify_integrity("0" * 64)

    def test_verify_integrity_empty(self):
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        stored_hash = chain.chain_hash()
        assert chain.verify_integrity(stored_hash)


class TestBuildEnvironment:
    def test_captures_system_info(self):
        env = BuildEnvironment()
        d = env.to_dict()
        assert "python_version" in d
        assert "platform" in d
        assert "architecture" in d
