"""Tests for CLI commands."""

import json
from pathlib import Path

import pytest

from sealed.cli import cmd_keygen, cmd_inspect, cmd_audit
from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority


class TestKeygen:
    def test_keygen_creates_file(self, tmp_path):
        key_path = tmp_path / "test.key"
        args = type("Args", (), {"output": str(key_path), "force": False, "passphrase": False})()
        ret = cmd_keygen(args)
        assert ret == 0
        assert key_path.exists()
        assert len(key_path.read_text().strip()) == 64

    def test_keygen_no_overwrite(self, tmp_path):
        key_path = tmp_path / "test.key"
        key_path.write_text("existing")
        args = type("Args", (), {"output": str(key_path), "force": False, "passphrase": False})()
        ret = cmd_keygen(args)
        assert ret == 1
        assert key_path.read_text() == "existing"

    def test_keygen_force_overwrite(self, tmp_path):
        key_path = tmp_path / "test.key"
        key_path.write_text("old")
        args = type("Args", (), {"output": str(key_path), "force": True, "passphrase": False})()
        ret = cmd_keygen(args)
        assert ret == 0
        assert key_path.read_text() != "old"


class TestInspect:
    def test_inspect_seal(self, tmp_path, capsys):
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="test", package_version="1.0")
        chain.add("build", "a", "b")
        seal = auth.seal(chain)

        seal_path = tmp_path / "test.seal.json"
        seal.save(seal_path)

        args = type("Args", (), {"file": str(seal_path)})()
        ret = cmd_inspect(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "test" in out
        assert "1.0" in out

    def test_inspect_chain(self, tmp_path, capsys):
        chain = ProvenanceChain(package_name="mylib", package_version="2.0")
        chain.add("source", "a", "b")
        chain.add("build", "b", "c")

        chain_path = tmp_path / "test.chain.json"
        chain_path.write_text(chain.to_json())

        args = type("Args", (), {"file": str(chain_path)})()
        ret = cmd_inspect(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "mylib" in out
        assert "Steps: 2" in out


class TestAudit:
    def test_audit_empty(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setattr("sealed.cli.STORE_DIR", tmp_path / "empty")
        args = type("Args", (), {})()
        ret = cmd_audit(args)
        assert ret == 0

    def test_audit_with_packages(self, tmp_path, capsys, monkeypatch):
        from sealed.chain import ProvenanceChain
        from sealed.seal import SealAuthority
        from sealed.registry import SealRegistry

        # Create registry with a seal
        db_path = tmp_path / "test.db"
        reg = SealRegistry(db_path)
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="fakepkg", package_version="1.0")
        chain.add("build", "a", "b")
        seal = auth.seal(chain)
        reg.store(seal, chain)
        reg.close()

        # Monkeypatch _get_registry to use our test db
        monkeypatch.setattr("sealed.cli._get_registry", lambda: SealRegistry(db_path))

        args = type("Args", (), {})()
        ret = cmd_audit(args)
        assert ret == 0
        out = capsys.readouterr().out
        assert "fakepkg" in out
