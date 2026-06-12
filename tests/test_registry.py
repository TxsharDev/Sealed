"""Tests for shared seal registry."""

import json
import pytest

from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority, Seal
from sealed.registry import SealRegistry, PinResult


def _make_chain_and_seal(pkg="test", ver="1.0", auth=None):
    auth = auth or SealAuthority()
    chain = ProvenanceChain(package_name=pkg, package_version=ver)
    chain.add("build", "a", "b")
    seal = auth.seal(chain)
    return seal, chain, auth


class TestSealRegistry:
    def test_store_and_lookup(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            seal, chain, _ = _make_chain_and_seal()
            reg.store(seal, chain)
            results = reg.lookup("test", "1.0")
            assert len(results) == 1
            assert results[0].seal.package_name == "test"

    def test_lookup_nonexistent(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            results = reg.lookup("nonexistent")
            assert results == []

    def test_lookup_by_name_only(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            seal1, chain1, _ = _make_chain_and_seal("pkg", "1.0")
            seal2, chain2, _ = _make_chain_and_seal("pkg", "2.0")
            reg.store(seal1, chain1)
            reg.store(seal2, chain2)
            results = reg.lookup("pkg")
            assert len(results) == 2

    def test_list_packages(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            seal, chain, _ = _make_chain_and_seal("mylib", "3.0")
            reg.store(seal, chain)
            packages = reg.list_packages()
            assert len(packages) == 1
            assert packages[0]["package"] == "mylib"

    def test_store_replaces_on_duplicate(self, tmp_path):
        auth = SealAuthority()
        with SealRegistry(tmp_path / "test.db") as reg:
            seal1, chain1, _ = _make_chain_and_seal("pkg", "1.0", auth)
            seal2, chain2, _ = _make_chain_and_seal("pkg", "1.0", auth)
            reg.store(seal1, chain1)
            reg.store(seal2, chain2)
            results = reg.lookup("pkg", "1.0")
            assert len(results) == 1

    def test_multiple_signers_stored(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            seal1, chain1, _ = _make_chain_and_seal("pkg", "1.0", SealAuthority())
            seal2, chain2, _ = _make_chain_and_seal("pkg", "1.0", SealAuthority())
            reg.store(seal1, chain1)
            reg.store(seal2, chain2)
            results = reg.lookup("pkg", "1.0")
            assert len(results) == 2


class TestKeyPinning:
    def test_first_use(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            result = reg.check_pin("pkg", "abc123")
            assert result.status == "first_use"
            assert result.ok
            assert result.is_first_use

    def test_pin_and_verify(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            reg.pin_key("pkg", "abc123")
            result = reg.check_pin("pkg", "abc123")
            assert result.status == "ok"
            assert result.ok

    def test_pin_mismatch(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            reg.pin_key("pkg", "abc123")
            result = reg.check_pin("pkg", "xyz789")
            assert result.status == "mismatch"
            assert not result.ok

    def test_revoke_key(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            reg.revoke_key("badkey", "compromised")
            result = reg.check_pin("pkg", "badkey")
            assert result.status == "revoked"
            assert not result.ok

    def test_get_pins(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            reg.pin_key("pkg", "key1", "tofu")
            reg.pin_key("pkg", "key2", "manual", "team lead")
            pins = reg.get_pins("pkg")
            assert len(pins) == 2


class TestExportImport:
    def test_export_import_seals(self, tmp_path):
        db1 = tmp_path / "src.db"
        db2 = tmp_path / "dst.db"

        with SealRegistry(db1) as reg1:
            seal, chain, _ = _make_chain_and_seal("pkg", "1.0")
            reg1.store(seal, chain)
            exported = reg1.export_seals()

        with SealRegistry(db2) as reg2:
            count = reg2.import_seals(exported)
            assert count == 1
            results = reg2.lookup("pkg", "1.0")
            assert len(results) == 1

    def test_export_import_pins(self, tmp_path):
        db1 = tmp_path / "src.db"
        db2 = tmp_path / "dst.db"

        with SealRegistry(db1) as reg1:
            reg1.pin_key("pkg", "key1", "manual")
            exported = reg1.export_pins()

        with SealRegistry(db2) as reg2:
            count = reg2.import_pins(exported)
            assert count == 1
            result = reg2.check_pin("pkg", "key1")
            assert result.status == "ok"

    def test_export_specific_packages(self, tmp_path):
        with SealRegistry(tmp_path / "test.db") as reg:
            s1, c1, _ = _make_chain_and_seal("a", "1.0")
            s2, c2, _ = _make_chain_and_seal("b", "1.0")
            reg.store(s1, c1)
            reg.store(s2, c2)
            exported = reg.export_seals(["a"])
            data = json.loads(exported)
            assert len(data["entries"]) == 1
            assert data["entries"][0]["seal"]["package_name"] == "a"
