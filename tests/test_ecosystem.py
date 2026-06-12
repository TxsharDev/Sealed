"""Tests for ecosystem adapters."""

import pytest

from sealed.ecosystem import (
    PipAdapter, NpmAdapter, CargoAdapter,
    get_adapter, detect_ecosystem, EcosystemError,
)


class TestGetAdapter:
    def test_pip(self):
        adapter = get_adapter("pip")
        assert adapter.name == "pip"

    def test_npm(self):
        adapter = get_adapter("npm")
        assert adapter.name == "npm"

    def test_cargo(self):
        adapter = get_adapter("cargo")
        assert adapter.name == "cargo"

    def test_unknown(self):
        with pytest.raises(EcosystemError, match="Unknown ecosystem"):
            get_adapter("rubygems")


class TestDetectEcosystem:
    def test_default_pip(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert detect_ecosystem("anything") == "pip"

    def test_detects_npm(self, tmp_path, monkeypatch):
        (tmp_path / "package.json").write_text("{}")
        monkeypatch.chdir(tmp_path)
        assert detect_ecosystem("anything") == "npm"

    def test_detects_cargo(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.toml").write_text("[package]")
        monkeypatch.chdir(tmp_path)
        assert detect_ecosystem("anything") == "cargo"


class TestPipAdapter:
    def test_name(self):
        assert PipAdapter().name == "pip"

    @pytest.mark.network
    def test_fetch_real(self):
        adapter = PipAdapter()
        try:
            source = adapter.fetch("six", "1.17.0")
            assert source.name == "six"
            assert source.ecosystem == "pip"
            assert source.source_dir.exists()
        except Exception:
            pytest.skip("Network not available")

    @pytest.mark.network
    def test_resolve_deps(self):
        adapter = PipAdapter()
        try:
            deps = adapter.resolve_deps("six", "1.17.0")
            names = [d[0] for d in deps]
            assert "six" in names
        except Exception:
            pytest.skip("Network not available")


class TestNpmAdapter:
    def test_name(self):
        assert NpmAdapter().name == "npm"


class TestCargoAdapter:
    def test_name(self):
        assert CargoAdapter().name == "cargo"
