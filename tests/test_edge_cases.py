"""Edge case tests for sealed. All self-contained, no network access."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from sealed.chain import (
    BuildEnvironment,
    ProvenanceChain,
    ProvenanceRecord,
    _hash_directory,
    _hash_file,
    _hash_bytes,
)
from sealed.seal import Seal, SealAuthority, SealError
from sealed.source import SourceFetcher, SourceFetchError, SourceResult
from sealed.verify import SealVerifier, VerifyResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chain(name: str = "testpkg", version: str = "1.0.0",
                steps: int = 1) -> ProvenanceChain:
    chain = ProvenanceChain(package_name=name, package_version=version)
    for i in range(steps):
        chain.add(
            step=f"step_{i}",
            input_hash=hashlib.sha256(f"in_{i}".encode()).hexdigest(),
            output_hash=hashlib.sha256(f"out_{i}".encode()).hexdigest(),
        )
    return chain


def _seal_chain(chain: ProvenanceChain,
                authority: SealAuthority | None = None) -> Seal:
    auth = authority or SealAuthority()
    return auth.seal(chain)


# ---------------------------------------------------------------------------
# 1. Empty package name / empty version
# ---------------------------------------------------------------------------

class TestEmptyPackageNameVersion:
    def test_empty_name_creates_chain(self):
        chain = ProvenanceChain(package_name="", package_version="1.0")
        chain.add(step="s", input_hash="a" * 64, output_hash="b" * 64)
        # chain_hash should still be deterministic
        assert len(chain.chain_hash()) == 64

    def test_empty_version_creates_chain(self):
        chain = ProvenanceChain(package_name="pkg", package_version="")
        chain.add(step="s", input_hash="a" * 64, output_hash="b" * 64)
        assert len(chain.chain_hash()) == 64

    def test_both_empty(self):
        chain = ProvenanceChain(package_name="", package_version="")
        assert chain.chain_hash()  # doesn't crash

    def test_empty_name_seal_roundtrip(self):
        chain = _make_chain(name="", version="")
        auth = SealAuthority()
        seal = auth.seal(chain)
        assert seal.package_name == ""
        assert seal.package_version == ""
        # Verification still works
        assert SealAuthority.verify_seal(seal, chain) is True

    def test_empty_name_json_roundtrip(self):
        chain = _make_chain(name="", version="")
        restored, stored_hash = ProvenanceChain.from_json(chain.to_json())
        assert restored.package_name == ""
        assert restored.chain_hash() == chain.chain_hash()


# ---------------------------------------------------------------------------
# 2. Package that has no sdist on PyPI (wheels only)
# ---------------------------------------------------------------------------

class TestNoSdist:
    def test_find_sdist_raises_when_only_wheels(self):
        fetcher = SourceFetcher()
        meta = {
            "info": {"version": "1.0.0"},
            "urls": [
                {"packagetype": "bdist_wheel", "filename": "pkg-1.0.0-py3-none-any.whl"},
                {"packagetype": "bdist_wheel", "filename": "pkg-1.0.0-cp311-linux.whl"},
            ],
        }
        with pytest.raises(SourceFetchError, match="No source distribution"):
            fetcher._find_sdist(meta, "fakepkg")

    def test_find_sdist_raises_on_empty_urls(self):
        fetcher = SourceFetcher()
        meta = {"info": {"version": "2.0"}, "urls": []}
        with pytest.raises(SourceFetchError, match="No source distribution"):
            fetcher._find_sdist(meta, "emptypkg")


# ---------------------------------------------------------------------------
# 3. Corrupted archive (not a valid tar.gz/zip)
# ---------------------------------------------------------------------------

class TestCorruptedArchive:
    def test_corrupt_tar_gz(self, tmp_path):
        corrupt = tmp_path / "bad.tar.gz"
        corrupt.write_bytes(b"this is not a real tar.gz file\x00\xff")
        fetcher = SourceFetcher(cache_dir=tmp_path)
        with pytest.raises(Exception):
            fetcher._extract(corrupt)

    def test_corrupt_zip(self, tmp_path):
        corrupt = tmp_path / "bad.zip"
        corrupt.write_bytes(b"PK\x03\x04garbage_data_here")
        fetcher = SourceFetcher(cache_dir=tmp_path)
        with pytest.raises(Exception):
            fetcher._extract(corrupt)

    def test_unknown_archive_format(self, tmp_path):
        unknown = tmp_path / "pkg-1.0.0.rar"
        unknown.write_bytes(b"data")
        fetcher = SourceFetcher(cache_dir=tmp_path)
        with pytest.raises(SourceFetchError, match="Unknown archive format"):
            fetcher._extract(unknown)


# ---------------------------------------------------------------------------
# 4. Source directory with symlinks
# ---------------------------------------------------------------------------

class TestSymlinks:
    @pytest.mark.skipif(sys.platform == "win32" and not os.environ.get("CI"),
                        reason="Symlinks may require elevated privileges on Windows")
    def test_hash_directory_with_symlink(self, tmp_path):
        real_file = tmp_path / "real.txt"
        real_file.write_text("hello")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(real_file)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")
        # _hash_directory follows symlinks (is_file returns True for symlinks)
        h = _hash_directory(tmp_path)
        assert len(h) == 64
        # Both files contribute to the hash
        real_only = tmp_path / "sub"
        real_only.mkdir()
        (real_only / "real.txt").write_text("hello")
        h_real = _hash_directory(real_only)
        assert h == h_real  # symlinks are skipped, so both hash only real.txt

    @pytest.mark.skipif(sys.platform == "win32" and not os.environ.get("CI"),
                        reason="Symlinks may require elevated privileges on Windows")
    def test_symlink_to_directory(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "a.txt").write_text("a")
        link = tmp_path / "linked_sub"
        try:
            link.symlink_to(subdir)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")
        # Hashing the parent includes both the real and linked subtree files
        h = _hash_directory(tmp_path)
        assert len(h) == 64


# ---------------------------------------------------------------------------
# 5. Very large metadata dicts in ProvenanceRecord
# ---------------------------------------------------------------------------

class TestLargeMetadata:
    def test_large_metadata_roundtrip(self):
        big_meta = {f"key_{i}": f"value_{i}" * 100 for i in range(500)}
        record = ProvenanceRecord(
            step="big", input_hash="a" * 64, output_hash="b" * 64,
            metadata=big_meta,
        )
        d = record.to_dict()
        assert len(d["metadata"]) == 500
        # canonical_bytes must be deterministic
        b1 = record.canonical_bytes()
        b2 = record.canonical_bytes()
        assert b1 == b2

    def test_large_metadata_in_chain(self):
        chain = ProvenanceChain(package_name="big", package_version="0.1")
        chain.add(step="load", input_hash="0" * 64, output_hash="1" * 64,
                  **{f"k{i}": list(range(50)) for i in range(100)})
        j = chain.to_json()
        restored, stored_hash = ProvenanceChain.from_json(j)
        assert restored.chain_hash() == chain.chain_hash()

    def test_nested_metadata(self):
        nested = {"a": {"b": {"c": {"d": [1, 2, {"e": "f"}]}}}}
        record = ProvenanceRecord(
            step="nest", input_hash="x" * 64, output_hash="y" * 64,
            metadata=nested,
        )
        canon = json.loads(record.canonical_bytes().decode())
        assert canon["metadata"]["a"]["b"]["c"]["d"][2]["e"] == "f"


# ---------------------------------------------------------------------------
# 6. Chain with 0 records being sealed and verified
# ---------------------------------------------------------------------------

class TestEmptyChain:
    def test_seal_empty_chain(self):
        chain = ProvenanceChain(package_name="empty", package_version="0.0.0")
        assert chain.records == []
        auth = SealAuthority()
        seal = auth.seal(chain)
        # Seal is valid over an empty chain
        assert SealAuthority.verify_seal(seal, chain) is True

    def test_verify_empty_chain_json(self):
        chain = _make_chain(steps=0)
        auth = SealAuthority()
        seal = auth.seal(chain)
        verifier = SealVerifier()
        result = verifier.verify_json(seal.to_json(), chain.to_json())
        assert result.valid is True
        assert result.chain_length == 0

    def test_empty_chain_hash_is_stable(self):
        c1 = ProvenanceChain(package_name="p", package_version="1")
        c2 = ProvenanceChain(package_name="p", package_version="1")
        assert c1.chain_hash() == c2.chain_hash()

    def test_empty_chain_verify_integrity(self):
        chain = ProvenanceChain(package_name="x", package_version="0")
        assert chain.verify_integrity(chain.chain_hash()) is True


# ---------------------------------------------------------------------------
# 7. Seal JSON with missing fields
# ---------------------------------------------------------------------------

class TestSealMissingFields:
    def test_missing_signature(self):
        d = {
            "chain_hash": "a" * 64,
            "public_key": "b" * 64,
            "timestamp": 1.0,
            "package_name": "pkg",
            "package_version": "1.0",
            # "signature" missing
        }
        with pytest.raises((TypeError, KeyError)):
            Seal.from_dict(d)

    def test_missing_chain_hash(self):
        d = {
            "signature": "ab" * 32,
            "public_key": "cd" * 32,
            "timestamp": 1.0,
            "package_name": "pkg",
            "package_version": "1.0",
        }
        with pytest.raises((TypeError, KeyError)):
            Seal.from_dict(d)

    def test_missing_package_name(self):
        d = {
            "chain_hash": "a" * 64,
            "signature": "b" * 128,
            "public_key": "c" * 64,
            "timestamp": 1.0,
            "package_version": "1.0",
        }
        with pytest.raises((TypeError, KeyError)):
            Seal.from_dict(d)

    def test_invalid_json_string(self):
        with pytest.raises(Exception):
            Seal.from_json("{not valid json")

    def test_empty_json_object(self):
        with pytest.raises((TypeError, KeyError)):
            Seal.from_json("{}")


# ---------------------------------------------------------------------------
# 8. Chain JSON with extra/missing fields
# ---------------------------------------------------------------------------

class TestChainExtraMissingFields:
    def test_extra_fields_ignored_on_load(self):
        chain = _make_chain()
        d = chain.to_dict()
        d["extra_field"] = "should be ignored"
        d["another"] = [1, 2, 3]
        # from_dict only picks the fields it needs
        restored, stored_hash = ProvenanceChain.from_dict(d)
        assert restored.package_name == chain.package_name

    def test_missing_records_key(self):
        d = {
            "package_name": "pkg",
            "package_version": "1.0",
            "environment": BuildEnvironment().to_dict(),
            # "records" missing
        }
        with pytest.raises(KeyError):
            ProvenanceChain.from_dict(d)

    def test_missing_environment(self):
        d = {
            "package_name": "pkg",
            "package_version": "1.0",
            "records": [],
            # "environment" missing
        }
        with pytest.raises(KeyError):
            ProvenanceChain.from_dict(d)

    def test_record_missing_step(self):
        d = {
            "package_name": "pkg",
            "package_version": "1.0",
            "environment": BuildEnvironment().to_dict(),
            "records": [{"input_hash": "a" * 64, "output_hash": "b" * 64,
                         "timestamp": 1.0}],
            "chain_hash": "ignored",
        }
        with pytest.raises(KeyError):
            ProvenanceChain.from_dict(d)

    def test_extra_fields_in_record(self):
        d = {
            "package_name": "pkg",
            "package_version": "1.0",
            "environment": BuildEnvironment().to_dict(),
            "records": [{
                "step": "s", "input_hash": "a" * 64, "output_hash": "b" * 64,
                "timestamp": 1.0, "metadata": {},
                "bonus_field": "hi",
            }],
            "chain_hash": "ignored",
        }
        # from_dict picks specific keys, extra keys in record are ignored
        chain, stored_hash = ProvenanceChain.from_dict(d)
        assert len(chain.records) == 1


# ---------------------------------------------------------------------------
# 9. Concurrent seal creation (two seals from same chain)
# ---------------------------------------------------------------------------

class TestConcurrentSeals:
    def test_two_seals_same_authority(self):
        chain = _make_chain()
        auth = SealAuthority()
        seal1 = auth.seal(chain)
        seal2 = auth.seal(chain)
        # Same chain_hash (deterministic)
        assert seal1.chain_hash == seal2.chain_hash
        # Same signature bytes (Ed25519 is deterministic for same key+message)
        assert seal1.signature == seal2.signature
        # Timestamps differ (unless very fast)
        # Both verify
        assert SealAuthority.verify_seal(seal1, chain) is True
        assert SealAuthority.verify_seal(seal2, chain) is True

    def test_two_seals_different_authorities(self):
        chain = _make_chain()
        auth1 = SealAuthority()
        auth2 = SealAuthority()
        seal1 = auth1.seal(chain)
        seal2 = auth2.seal(chain)
        assert seal1.chain_hash == seal2.chain_hash
        # Different keys produce different signatures
        assert seal1.signature != seal2.signature
        assert seal1.public_key != seal2.public_key
        # Each verifies
        assert SealAuthority.verify_seal(seal1, chain) is True
        assert SealAuthority.verify_seal(seal2, chain) is True

    def test_cross_authority_verification_fails(self):
        """seal1 verified with seal2's public key embedded should fail."""
        chain = _make_chain()
        auth1 = SealAuthority()
        auth2 = SealAuthority()
        seal1 = auth1.seal(chain)
        # Tamper: replace public_key with auth2's key
        tampered = Seal(
            chain_hash=seal1.chain_hash,
            signature=seal1.signature,
            public_key=auth2.public_key,
            timestamp=seal1.timestamp,
            package_name=seal1.package_name,
            package_version=seal1.package_version,
        )
        with pytest.raises(SealError, match="Signature verification failed"):
            SealAuthority.verify_seal(tampered, chain)


# ---------------------------------------------------------------------------
# 10. Unicode in package names
# ---------------------------------------------------------------------------

class TestUnicodePackageNames:
    def test_unicode_name_chain(self):
        chain = ProvenanceChain(
            package_name="\u00fc\u00f1\u00ee\u00e7\u00f6\u00f0\u00e9-pkg",
            package_version="1.0.0-\u03b1",
        )
        chain.add(step="s", input_hash="a" * 64, output_hash="b" * 64)
        h = chain.chain_hash()
        assert len(h) == 64

    def test_unicode_roundtrip(self):
        name = "\u4e2d\u6587\u5305"  # Chinese characters
        chain = _make_chain(name=name, version="\u03b2")
        j = chain.to_json()
        restored, stored_hash = ProvenanceChain.from_json(j)
        assert restored.package_name == name
        assert restored.chain_hash() == chain.chain_hash()

    def test_unicode_seal(self):
        chain = _make_chain(name="\U0001f4e6-pkg")  # emoji in name
        auth = SealAuthority()
        seal = auth.seal(chain)
        assert seal.package_name == "\U0001f4e6-pkg"
        assert SealAuthority.verify_seal(seal, chain) is True

    def test_unicode_metadata(self):
        chain = ProvenanceChain(package_name="u", package_version="1")
        chain.add(step="s", input_hash="a" * 64, output_hash="b" * 64,
                  description="\u00e9\u00e8\u00ea\u00eb \u00e0\u00e2 \u00f4\u00f9\u00fb")
        j = chain.to_json()
        restored, stored_hash = ProvenanceChain.from_json(j)
        assert restored.records[0].metadata["description"] == "\u00e9\u00e8\u00ea\u00eb \u00e0\u00e2 \u00f4\u00f9\u00fb"


# ---------------------------------------------------------------------------
# 11. Replay attack: valid seal from old version applied to new version
# ---------------------------------------------------------------------------

class TestReplayAttack:
    def test_old_seal_on_new_chain(self):
        auth = SealAuthority()
        old_chain = _make_chain(version="1.0.0")
        old_seal = auth.seal(old_chain)

        new_chain = _make_chain(version="2.0.0")
        # The old seal's chain_hash won't match the new chain
        with pytest.raises(SealError, match="Chain hash mismatch"):
            SealAuthority.verify_seal(old_seal, new_chain)

    def test_old_seal_same_version_different_content(self):
        auth = SealAuthority()
        chain_v1 = ProvenanceChain(package_name="pkg", package_version="1.0")
        chain_v1.add(step="s", input_hash="a" * 64, output_hash="b" * 64)
        seal_v1 = auth.seal(chain_v1)

        chain_v1_modified = ProvenanceChain(package_name="pkg", package_version="1.0")
        chain_v1_modified.add(step="s", input_hash="a" * 64, output_hash="c" * 64)
        with pytest.raises(SealError, match="Chain hash mismatch"):
            SealAuthority.verify_seal(seal_v1, chain_v1_modified)

    def test_replay_via_json_verifier(self):
        auth = SealAuthority()
        old = _make_chain(version="1.0")
        seal = auth.seal(old)
        new = _make_chain(version="1.1")
        verifier = SealVerifier()
        result = verifier.verify_json(seal.to_json(), new.to_json())
        assert result.valid is False
        assert any("Chain hash mismatch" in e or "Seal verification" in e
                    for e in result.errors)


# ---------------------------------------------------------------------------
# 12. Signature from one package applied to different package's chain
# ---------------------------------------------------------------------------

class TestCrossPackageSignature:
    def test_seal_from_pkg_a_on_chain_b(self):
        auth = SealAuthority()
        chain_a = _make_chain(name="package-a")
        chain_b = _make_chain(name="package-b")
        seal_a = auth.seal(chain_a)
        with pytest.raises(SealError, match="Chain hash mismatch"):
            SealAuthority.verify_seal(seal_a, chain_b)

    def test_cross_package_via_verifier(self):
        auth = SealAuthority()
        chain_a = _make_chain(name="alpha")
        chain_b = _make_chain(name="beta")
        seal_a = auth.seal(chain_a)
        verifier = SealVerifier()
        result = verifier.verify_json(seal_a.to_json(), chain_b.to_json())
        assert result.valid is False

    def test_forged_seal_name_still_fails(self):
        """Changing package_name in seal but keeping signature still fails."""
        auth = SealAuthority()
        chain_a = _make_chain(name="real")
        seal_a = auth.seal(chain_a)
        chain_b = _make_chain(name="fake")
        # Forge: copy seal but change package_name to "fake"
        forged = Seal(
            chain_hash=seal_a.chain_hash,
            signature=seal_a.signature,
            public_key=seal_a.public_key,
            timestamp=seal_a.timestamp,
            package_name="fake",
            package_version=seal_a.package_version,
        )
        # chain_hash is computed from chain_b which differs
        with pytest.raises(SealError, match="Chain hash mismatch"):
            SealAuthority.verify_seal(forged, chain_b)


# ---------------------------------------------------------------------------
# 13. verify_integrity after manual chain_hash override
# ---------------------------------------------------------------------------

class TestVerifyIntegrityTamper:
    def test_integrity_passes_normally(self):
        chain = _make_chain(steps=3)
        assert chain.verify_integrity(chain.chain_hash()) is True

    def test_integrity_after_record_tamper(self):
        chain = _make_chain(steps=2)
        original_json = chain.to_json()
        d = json.loads(original_json)
        # Tamper with a record's output_hash
        d["records"][0]["output_hash"] = "f" * 64
        # The stored chain_hash is now stale
        tampered_json = json.dumps(d)
        restored, stored_hash = ProvenanceChain.from_json(tampered_json)
        assert restored.verify_integrity(stored_hash) is False

    def test_integrity_after_name_tamper(self):
        chain = _make_chain(name="original", steps=1)
        d = json.loads(chain.to_json())
        d["package_name"] = "tampered"
        tampered = json.dumps(d)
        restored, stored_hash = ProvenanceChain.from_json(tampered)
        assert restored.verify_integrity(stored_hash) is False

    def test_integrity_after_version_tamper(self):
        chain = _make_chain(version="1.0.0", steps=1)
        d = json.loads(chain.to_json())
        d["package_version"] = "9.9.9"
        tampered = json.dumps(d)
        restored, stored_hash = ProvenanceChain.from_json(tampered)
        assert restored.verify_integrity(stored_hash) is False


# ---------------------------------------------------------------------------
# 14. _hash_directory on empty directory
# ---------------------------------------------------------------------------

class TestHashEmptyDirectory:
    def test_empty_dir_returns_hash(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        h = _hash_directory(empty)
        # Should be hash of empty input (just init state of sha256)
        assert len(h) == 64
        assert h == hashlib.sha256().hexdigest()

    def test_empty_dir_is_deterministic(self, tmp_path):
        d1 = tmp_path / "d1"
        d2 = tmp_path / "d2"
        d1.mkdir()
        d2.mkdir()
        assert _hash_directory(d1) == _hash_directory(d2)

    def test_adding_file_changes_hash(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        h_empty = _hash_directory(d)
        (d / "file.txt").write_text("content")
        h_with_file = _hash_directory(d)
        assert h_empty != h_with_file


# ---------------------------------------------------------------------------
# 15. _hash_file on binary file with null bytes
# ---------------------------------------------------------------------------

class TestHashBinaryFile:
    def test_null_bytes(self, tmp_path):
        f = tmp_path / "nulls.bin"
        f.write_bytes(b"\x00" * 1024)
        h = _hash_file(f)
        assert len(h) == 64
        expected = hashlib.sha256(b"\x00" * 1024).hexdigest()
        assert h == expected

    def test_mixed_binary(self, tmp_path):
        f = tmp_path / "mixed.bin"
        data = bytes(range(256)) * 10 + b"\x00\xff" * 500
        f.write_bytes(data)
        h = _hash_file(f)
        assert h == hashlib.sha256(data).hexdigest()

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        h = _hash_file(f)
        assert h == hashlib.sha256(b"").hexdigest()

    def test_large_binary_file(self, tmp_path):
        f = tmp_path / "large.bin"
        # Just over the 64KB chunk boundary
        data = os.urandom(65537)
        f.write_bytes(data)
        h = _hash_file(f)
        assert h == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 16. SourceResult slots access
# ---------------------------------------------------------------------------

class TestSourceResultSlots:
    def test_all_slots_accessible(self, tmp_path):
        sr = SourceResult(
            package="mypkg",
            version="1.2.3",
            source_dir=tmp_path / "src",
            archive_path=tmp_path / "archive.tar.gz",
            archive_hash="abc123",
            pypi_hash="def456",
        )
        assert sr.package == "mypkg"
        assert sr.version == "1.2.3"
        assert sr.source_dir == tmp_path / "src"
        assert sr.archive_path == tmp_path / "archive.tar.gz"
        assert sr.archive_hash == "abc123"
        assert sr.pypi_hash == "def456"

    def test_no_dict_on_slots_object(self, tmp_path):
        sr = SourceResult(
            package="p", version="v", source_dir=tmp_path,
            archive_path=tmp_path, archive_hash="h", pypi_hash="p",
        )
        assert not hasattr(sr, "__dict__")

    def test_cannot_set_arbitrary_attribute(self, tmp_path):
        sr = SourceResult(
            package="p", version="v", source_dir=tmp_path,
            archive_path=tmp_path, archive_hash="h", pypi_hash="p",
        )
        with pytest.raises(AttributeError):
            sr.nonexistent_attr = "boom"

    def test_slots_match_init_params(self):
        expected = {"package", "version", "source_dir",
                    "archive_path", "archive_hash", "pypi_hash"}
        assert set(SourceResult.__slots__) == expected


# ---------------------------------------------------------------------------
# 17. BuildEnvironment on different platforms
# ---------------------------------------------------------------------------

class TestBuildEnvironment:
    def test_default_captures_current(self):
        env = BuildEnvironment()
        assert env.python_version == sys.version
        assert env.platform == platform.platform()
        assert env.architecture == platform.machine()
        assert env.hostname == platform.node()

    def test_custom_values(self):
        env = BuildEnvironment(
            python_version="3.99.0",
            platform="FakeOS-42",
            architecture="riscv128",
            hostname="builder-node-7",
        )
        d = env.to_dict()
        assert d["python_version"] == "3.99.0"
        assert d["platform"] == "FakeOS-42"
        assert d["architecture"] == "riscv128"
        assert d["hostname"] == "builder-node-7"

    def test_to_dict_roundtrip(self):
        env = BuildEnvironment()
        d = env.to_dict()
        env2 = BuildEnvironment(**d)
        assert env2.to_dict() == d

    def test_environment_in_chain(self):
        env = BuildEnvironment(
            python_version="3.11.0",
            platform="Linux-6.1",
            architecture="aarch64",
            hostname="ci-arm",
        )
        chain = ProvenanceChain(
            package_name="test", package_version="1.0",
            environment=env,
        )
        d = json.loads(chain.to_json())
        assert d["environment"]["architecture"] == "aarch64"
        restored, stored_hash = ProvenanceChain.from_json(chain.to_json())
        assert restored.environment.architecture == "aarch64"


# ---------------------------------------------------------------------------
# 18. Seal timestamp manipulation
# ---------------------------------------------------------------------------

class TestSealTimestamp:
    def test_timestamp_is_recorded(self):
        chain = _make_chain()
        before = time.time()
        seal = SealAuthority().seal(chain)
        after = time.time()
        assert before <= seal.timestamp <= after

    def test_tampered_timestamp_still_verifies(self):
        """Timestamps are not covered by the signature (signature is over chain_hash only)."""
        chain = _make_chain()
        auth = SealAuthority()
        seal = auth.seal(chain)
        # Forge timestamp
        forged = Seal(
            chain_hash=seal.chain_hash,
            signature=seal.signature,
            public_key=seal.public_key,
            timestamp=0.0,  # epoch
            package_name=seal.package_name,
            package_version=seal.package_version,
        )
        # Signature only covers chain_hash, so this still verifies
        assert SealAuthority.verify_seal(forged, chain) is True

    def test_future_timestamp_in_seal(self):
        chain = _make_chain()
        auth = SealAuthority()
        seal = auth.seal(chain)
        far_future = Seal(
            chain_hash=seal.chain_hash,
            signature=seal.signature,
            public_key=seal.public_key,
            timestamp=9999999999.0,
            package_name=seal.package_name,
            package_version=seal.package_version,
        )
        # No timestamp validation in current code
        assert SealAuthority.verify_seal(far_future, chain) is True

    def test_negative_timestamp(self):
        chain = _make_chain()
        auth = SealAuthority()
        seal = auth.seal(chain)
        neg = Seal(
            chain_hash=seal.chain_hash,
            signature=seal.signature,
            public_key=seal.public_key,
            timestamp=-1.0,
            package_name=seal.package_name,
            package_version=seal.package_version,
        )
        assert SealAuthority.verify_seal(neg, chain) is True

    def test_timestamp_json_roundtrip(self):
        chain = _make_chain()
        seal = SealAuthority().seal(chain)
        j = seal.to_json()
        restored = Seal.from_json(j)
        assert restored.timestamp == seal.timestamp


# ---------------------------------------------------------------------------
# Additional: Seal save/load file roundtrip
# ---------------------------------------------------------------------------

class TestSealFileRoundtrip:
    def test_save_and_load(self, tmp_path):
        chain = _make_chain()
        auth = SealAuthority()
        seal = auth.seal(chain)
        path = tmp_path / "seal.json"
        seal.save(path)
        loaded = Seal.load(path)
        assert loaded.chain_hash == seal.chain_hash
        assert loaded.signature == seal.signature
        assert loaded.public_key == seal.public_key

    def test_key_save_and_load(self, tmp_path):
        auth1 = SealAuthority()
        key_path = tmp_path / "key.ed25519"
        auth1.save_key(key_path)
        auth2 = SealAuthority.from_key_file(key_path)
        assert auth1.public_key == auth2.public_key
        # Same key produces same seal
        chain = _make_chain()
        s1 = auth1.seal(chain)
        s2 = auth2.seal(chain)
        assert s1.signature == s2.signature


# ---------------------------------------------------------------------------
# Additional: VerifyResult properties
# ---------------------------------------------------------------------------

class TestVerifyResult:
    def test_ok_when_valid_and_no_errors(self):
        r = VerifyResult(valid=True, package_name="p", package_version="1",
                         chain_length=3, errors=[])
        assert r.ok is True

    def test_not_ok_when_invalid(self):
        r = VerifyResult(valid=False, package_name="p", package_version="1",
                         chain_length=0, errors=["bad"])
        assert r.ok is False

    def test_not_ok_when_valid_but_has_errors(self):
        r = VerifyResult(valid=True, package_name="p", package_version="1",
                         chain_length=1, errors=["warning"])
        assert r.ok is False
