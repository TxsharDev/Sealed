"""Tests for lockfile."""

import json
import pytest

from sealed.lockfile import Lockfile, LockEntry, LockCheck


class TestLockEntry:
    def test_roundtrip(self):
        e = LockEntry("pkg", "1.0", "abc", "def", "key1")
        d = e.to_dict()
        restored = LockEntry.from_dict(d)
        assert restored.name == "pkg"
        assert restored.artifact_hash == "abc"

    def test_from_dict_ignores_extra(self):
        d = {"name": "x", "version": "1.0", "artifact_hash": "a",
             "chain_hash": "b", "public_key": "c", "extra": "ignored"}
        e = LockEntry.from_dict(d)
        assert e.name == "x"


class TestLockfile:
    def test_add_and_get(self):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))
        assert lf.get("pkg") is not None
        assert lf.get("pkg").version == "1.0"
        assert lf.get("missing") is None

    def test_check_ok(self):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))
        result = lf.check("pkg", "1.0", "abc")
        assert result.ok

    def test_check_new_package(self):
        lf = Lockfile()
        result = lf.check("unknown", "1.0", "abc")
        assert result.is_new

    def test_check_version_mismatch(self):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))
        result = lf.check("pkg", "2.0", "abc")
        assert result.status == "version_mismatch"
        assert not result.ok

    def test_check_hash_mismatch(self):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))
        result = lf.check("pkg", "1.0", "DIFFERENT")
        assert result.status == "hash_mismatch"

    def test_json_roundtrip(self):
        lf = Lockfile()
        lf.add(LockEntry("a", "1.0", "h1", "c1", "k1"))
        lf.add(LockEntry("b", "2.0", "h2", "c2", "k2"))

        j = lf.to_json()
        restored = Lockfile.from_json(j)
        assert len(restored.entries) == 2
        assert restored.get("a").artifact_hash == "h1"

    def test_file_roundtrip(self, tmp_path):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))

        path = tmp_path / "sealed.lock"
        lf.save(path)
        loaded = Lockfile.load(path)
        assert loaded.get("pkg").version == "1.0"

    def test_digest_deterministic(self):
        lf1 = Lockfile()
        lf1.add(LockEntry("a", "1.0", "h", "c", "k"))
        lf2 = Lockfile()
        lf2.add(LockEntry("a", "1.0", "h", "c", "k"))
        assert lf1.digest == lf2.digest

    def test_digest_changes(self):
        lf1 = Lockfile()
        lf1.add(LockEntry("a", "1.0", "h1", "c", "k"))
        lf2 = Lockfile()
        lf2.add(LockEntry("a", "1.0", "h2", "c", "k"))
        assert lf1.digest != lf2.digest

    def test_verify_integrity(self):
        lf = Lockfile()
        lf.add(LockEntry("pkg", "1.0", "abc", "def", "key1"))
        assert lf.verify_integrity()

    def test_empty_lockfile(self):
        lf = Lockfile()
        assert len(lf.entries) == 0
        j = lf.to_json()
        assert "packages" in j
