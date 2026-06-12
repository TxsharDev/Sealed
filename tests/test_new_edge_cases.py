"""Edge case tests for sandbox, consensus, watchdog, and trust_graph modules."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

import pytest

from sealed.sandbox import BehavioralSandbox, SandboxResult, SandboxBehavior
from sealed.consensus import ConsensusBuilder, ConsensusResult, ConsensusBuild
from sealed.watchdog import IntegrityWatchdog, WatchdogSnapshot, IntegrityViolation
from sealed.trust_graph import (
    TrustGraphBuilder, TrustGraph, TrustNode, _score_bar,
)
from sealed.registry import SealRegistry
from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority


# ---------------------------------------------------------------------------
# Sandbox edge cases
# ---------------------------------------------------------------------------

class TestSandboxTimeout:
    """Package that times out during sandbox analysis."""

    def test_timeout_sets_flag_and_behavior(self):
        sandbox = BehavioralSandbox(timeout=1)
        # Patch subprocess.run to raise TimeoutExpired
        with patch("sealed.sandbox.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=1)):
            result = sandbox.analyze("slowpkg", "1.0.0")
        assert result.timeout is True
        assert any(b.type == "timeout" for b in result.behaviors)
        assert any(b.severity == "high" for b in result.behaviors)
        assert not result.safe  # timeout behavior is "high" severity

    def test_timeout_details_contain_seconds(self):
        sandbox = BehavioralSandbox(timeout=5)
        with patch("sealed.sandbox.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="t", timeout=5)):
            result = sandbox.analyze("slowpkg", "1.0.0")
        timeout_b = [b for b in result.behaviors if b.type == "timeout"][0]
        assert timeout_b.details["seconds"] == "5"


class TestSandboxNonexistentPackage:
    """Package that doesn't exist: analyze should still return a result."""

    def test_nonexistent_package_returns_result(self):
        sandbox = BehavioralSandbox(timeout=10)
        result = sandbox.analyze("sealed_definitely_not_a_real_package_xyz", "0.0.0")
        # Should not crash; returns either an import error behavior or an error string
        assert result.package == "sealed_definitely_not_a_real_package_xyz"
        assert result.version == "0.0.0"
        # It will either have an import_error behavior or an error field
        has_import_error = any(b.type == "import_error" for b in result.behaviors)
        has_error_field = result.error is not None
        assert has_import_error or has_error_field


class TestSandboxEmptyBehaviorList:
    """SandboxResult with empty behavior list."""

    def test_empty_behaviors_is_safe(self):
        r = SandboxResult(package="pkg", version="1.0", behaviors=[])
        assert r.safe is True

    def test_empty_behaviors_digest_is_deterministic(self):
        r1 = SandboxResult(package="a", version="1.0", behaviors=[])
        r2 = SandboxResult(package="b", version="2.0", behaviors=[])
        # Same behaviors (empty) -> same digest
        assert r1.digest == r2.digest

    def test_empty_behaviors_to_dict(self):
        r = SandboxResult(package="pkg", version="1.0", behaviors=[])
        d = r.to_dict()
        assert d["behaviors"] == []
        assert d["critical"] == 0
        assert d["high"] == 0
        assert d["safe"] is True


class TestSandboxWheelPathNotExists:
    """Sandbox with wheel_path that doesn't exist on disk."""

    def test_nonexistent_wheel_path_returns_error(self, tmp_path):
        fake_wheel = tmp_path / "no_such_file.whl"
        sandbox = BehavioralSandbox(timeout=10)
        result = sandbox.analyze("pkg", "1.0", wheel_path=fake_wheel)
        # Should not crash. Will have an error from pip install failing
        assert result.package == "pkg"
        # pip install of nonexistent wheel should produce either error or import_error
        has_issue = (
            result.error is not None
            or any(b.type == "import_error" for b in result.behaviors)
        )
        assert has_issue


# ---------------------------------------------------------------------------
# Consensus edge cases
# ---------------------------------------------------------------------------

class TestConsensusZeroSuccessfulBuilds:
    """All builds fail -> no consensus."""

    def test_zero_successful_builds(self):
        result = ConsensusResult(
            package="broken", version="0.1",
            total_builds=3, threshold=0.67,
            builds=[
                ConsensusBuild(i, "", "", False, error="fail") for i in range(3)
            ],
        )
        assert not result.ok
        assert result.consensus_hash is None


class TestConsensusAllBuildsFail:
    """ConsensusBuilder where every build raises an exception."""

    def test_all_builds_fail_no_consensus(self):
        builder = ConsensusBuilder(num_builds=3, threshold=0.67)
        # Mock the entire build method's internals: SourceFetcher returns source,
        # but IsolatedBuilder.build always throws
        mock_source = MagicMock()
        mock_source.package = "broken"
        mock_source.version = "1.0"
        mock_source.source_dir = Path("/tmp/fake")
        mock_source.archive_hash = "fakehash"

        with patch("sealed.consensus.SourceFetcher") as MockFetcher:
            MockFetcher.return_value.fetch.return_value = mock_source
            with patch("sealed.consensus.IsolatedBuilder") as MockBuilder:
                MockBuilder.return_value.build.side_effect = RuntimeError("build broke")
                result = builder.build("broken", "1.0")

        assert result.package == "broken"
        assert len(result.builds) == 3
        assert all(not b.success for b in result.builds)
        assert not result.consensus_reached
        assert result.consensus_hash is None


class TestConsensusThresholdOneFull:
    """threshold=1.0 requires 100% agreement."""

    def test_threshold_one_all_agree(self):
        r = ConsensusResult(
            package="pkg", version="1.0",
            total_builds=3, threshold=1.0,
            consensus_reached=True,
            consensus_hash="aaa",
            agreement_count=3,
            builds=[ConsensusBuild(i, "aaa", "aaa", True) for i in range(3)],
        )
        assert r.ok

    def test_threshold_one_partial_fails(self):
        """Even 2/3 agreement should fail at threshold=1.0."""
        # Patch ReproducibilityChecker before ConsensusBuilder.__init__
        with patch("sealed.consensus.ReproducibilityChecker") as MR:
            checker = MR.return_value
            checker._normalize_wheel_hash.side_effect = ["aaa", "aaa", "bbb"]
            builder = ConsensusBuilder(num_builds=3, threshold=1.0)

            mock_source = MagicMock()
            mock_source.package = "pkg"
            mock_source.version = "1.0"
            mock_source.source_dir = Path("/tmp/fake")
            mock_source.archive_hash = "h"

            with patch("sealed.consensus.SourceFetcher") as MF:
                MF.return_value.fetch.return_value = mock_source
                with patch("sealed.consensus.IsolatedBuilder") as MB:
                    mock_result = MagicMock()
                    mock_result.artifact = Path("/tmp/fake.whl")
                    mock_result.artifact_hash = "hash"
                    MB.return_value.build.return_value = mock_result
                    result = builder.build("pkg", "1.0")

        assert result.agreement_count == 2
        assert not result.consensus_reached  # 2/3 < 1.0


class TestConsensusThresholdZero:
    """threshold=0.0 means any build counts as consensus."""

    def test_threshold_zero_single_success(self):
        with patch("sealed.consensus.ReproducibilityChecker") as MR:
            MR.return_value._normalize_wheel_hash.return_value = "norm1"
            builder = ConsensusBuilder(num_builds=3, threshold=0.0)

            mock_source = MagicMock()
            mock_source.package = "pkg"
            mock_source.version = "1.0"
            mock_source.source_dir = Path("/tmp/fake")
            mock_source.archive_hash = "h"

            with patch("sealed.consensus.SourceFetcher") as MF:
                MF.return_value.fetch.return_value = mock_source
                with patch("sealed.consensus.IsolatedBuilder") as MB:
                    result_ok = MagicMock()
                    result_ok.artifact = Path("/tmp/fake.whl")
                    result_ok.artifact_hash = "hash1"
                    MB.return_value.build.side_effect = [
                        result_ok,
                        RuntimeError("fail"),
                        RuntimeError("fail"),
                    ]
                    result = builder.build("pkg", "1.0")

        # 1/3 >= 0.0 -> consensus reached
        assert result.consensus_reached
        assert result.agreement_count == 1


class TestConsensusSingleBuild:
    """Only one build requested."""

    def test_single_build_consensus(self):
        r = ConsensusResult(
            package="pkg", version="1.0",
            total_builds=1, threshold=0.67,
            consensus_reached=True,
            consensus_hash="aaa",
            agreement_count=1,
            builds=[ConsensusBuild(0, "aaa", "aaa", True)],
        )
        # 1/1 = 1.0 >= 0.67
        assert r.ok

    def test_single_build_failure(self):
        r = ConsensusResult(
            package="pkg", version="1.0",
            total_builds=1, threshold=0.67,
            consensus_reached=False,
            agreement_count=0,
            builds=[ConsensusBuild(0, "", "", False, error="err")],
        )
        assert not r.ok


# ---------------------------------------------------------------------------
# Watchdog edge cases
# ---------------------------------------------------------------------------

class TestWatchdogEmptyDirectory:
    """Snapshot of a directory with no files."""

    def test_snapshot_empty_dir(self, tmp_path):
        pkg_dir = tmp_path / "emptypkg"
        pkg_dir.mkdir()

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        snap = watchdog.snapshot("emptypkg", "1.0", pkg_dir)
        assert snap.file_hashes == {}
        assert snap.package == "emptypkg"

    def test_check_empty_dir_no_violations(self, tmp_path):
        pkg_dir = tmp_path / "emptypkg"
        pkg_dir.mkdir()

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        watchdog.snapshot("emptypkg", "1.0", pkg_dir)
        violations = watchdog.check("emptypkg")
        assert violations == []


class TestWatchdogSubdirectories:
    """Snapshot with nested subdirectories."""

    def test_snapshot_captures_subdirectory_files(self, tmp_path):
        pkg_dir = tmp_path / "nested"
        pkg_dir.mkdir()
        sub = pkg_dir / "sub" / "deep"
        sub.mkdir(parents=True)
        (pkg_dir / "top.py").write_text("top\n")
        (sub / "inner.py").write_text("inner\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        snap = watchdog.snapshot("nested", "1.0", pkg_dir)
        assert "top.py" in snap.file_hashes
        assert "sub/deep/inner.py" in snap.file_hashes
        assert len(snap.file_hashes) == 2

    def test_detects_tamper_in_subdirectory(self, tmp_path):
        pkg_dir = tmp_path / "nested"
        pkg_dir.mkdir()
        sub = pkg_dir / "sub"
        sub.mkdir()
        (sub / "mod.py").write_text("original\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        watchdog.snapshot("nested", "1.0", pkg_dir)

        (sub / "mod.py").write_text("tampered\n")
        violations = watchdog.check("nested")
        assert len(violations) == 1
        assert "sub/mod.py" in violations[0].file


class TestWatchdogDeletedPackageDir:
    """Check after the entire package directory is deleted."""

    def test_check_after_dir_deleted_no_crash(self, tmp_path):
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        (pkg_dir / "a.py").write_text("data\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        watchdog.snapshot("pkg", "1.0", pkg_dir)

        # Remove the entire package directory
        import shutil
        shutil.rmtree(pkg_dir)

        # Should not crash; the code skips if install_path doesn't exist
        violations = watchdog.check("pkg")
        assert violations == []  # skipped because path is gone


class TestWatchdogMultipleSnapshots:
    """Multiple snapshots of the same package (different versions)."""

    def test_two_versions_independent(self, tmp_path):
        pkg_dir_v1 = tmp_path / "pkg_v1"
        pkg_dir_v1.mkdir()
        (pkg_dir_v1 / "a.py").write_text("v1\n")

        pkg_dir_v2 = tmp_path / "pkg_v2"
        pkg_dir_v2.mkdir()
        (pkg_dir_v2 / "a.py").write_text("v2\n")

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        watchdog.snapshot("pkg", "1.0", pkg_dir_v1)
        watchdog.snapshot("pkg", "2.0", pkg_dir_v2)

        snaps = watchdog.list_snapshots()
        assert len(snaps) == 2

        # Tamper v2 only
        (pkg_dir_v2 / "a.py").write_text("tampered\n")
        violations = watchdog.check("pkg")
        assert len(violations) == 1
        assert violations[0].package == "pkg"


class TestWatchdogBinaryFiles:
    """Snapshot with binary (non-text) files."""

    def test_snapshot_includes_binary_files(self, tmp_path):
        pkg_dir = tmp_path / "binpkg"
        pkg_dir.mkdir()
        (pkg_dir / "data.bin").write_bytes(bytes(range(256)))
        (pkg_dir / "lib.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        snap = watchdog.snapshot("binpkg", "1.0", pkg_dir)
        assert "data.bin" in snap.file_hashes
        assert "lib.so" in snap.file_hashes

    def test_detects_binary_file_tamper(self, tmp_path):
        pkg_dir = tmp_path / "binpkg"
        pkg_dir.mkdir()
        (pkg_dir / "data.bin").write_bytes(b"\x00" * 100)

        watchdog = IntegrityWatchdog(snapshot_dir=tmp_path / "snaps")
        watchdog.snapshot("binpkg", "1.0", pkg_dir)

        (pkg_dir / "data.bin").write_bytes(b"\xff" * 100)
        violations = watchdog.check("binpkg")
        assert len(violations) == 1


# ---------------------------------------------------------------------------
# Trust graph edge cases
# ---------------------------------------------------------------------------

class TestTrustGraphNoRegistry:
    """TrustGraphBuilder with no registry."""

    def test_build_without_registry(self):
        builder = TrustGraphBuilder(registry=None)
        # Mock the resolver to return a fake dep
        with patch("sealed.trust_graph.DependencyResolver") as MR:
            mock_dep = MagicMock()
            mock_dep.name = "dep"
            mock_dep.version = "1.0"
            mock_dep.dependencies = []
            MR.return_value.resolve.return_value = [mock_dep]
            graph = builder.build("dep", "1.0")

        assert "dep" in graph.nodes
        # Without registry, nothing is sealed -> trust = 0
        assert graph.nodes["dep"].trust_score == 0.0
        assert graph.nodes["dep"].sealed is False


class TestTrustGraphUnsealedPackages:
    """Graph where all packages are unsealed."""

    def test_all_unsealed(self):
        g = TrustGraph(root="app", nodes={
            "a": TrustNode("a", "1.0", sealed=False, trust_score=0.0),
            "b": TrustNode("b", "2.0", sealed=False, trust_score=0.0),
        })
        assert g.sealed_count == 0
        assert g.unsealed_count == 2
        assert g.average_trust == 0.0
        w = g.weakest_link
        assert w is not None
        assert w.trust_score == 0.0

    def test_to_dict_all_unsealed(self):
        g = TrustGraph(root="app", nodes={
            "x": TrustNode("x", "1.0", sealed=False, trust_score=0.0),
        })
        d = g.to_dict()
        assert d["sealed"] == 0
        assert d["unsealed"] == 1
        assert d["average_trust"] == 0.0


class TestTrustNodeMaximumTrust:
    """Node with maximum trust score (1.0)."""

    def test_max_trust_node(self):
        builder = TrustGraphBuilder()
        node = TrustNode(
            name="perfect", version="1.0",
            sealed=True,            # +0.40
            attestation="tpm2",     # +0.15
            audited=True,           # +0.15
            pinned=True,
            pin_type="manual",      # +0.15
            signer_count=3,         # +0.15
        )
        score = builder._compute_trust(node)
        assert score == 1.0

    def test_max_trust_clamped(self):
        """Even if individual components sum > 1.0, result is clamped."""
        builder = TrustGraphBuilder()
        node = TrustNode(
            name="over", version="1.0",
            sealed=True,
            attestation="tpm2",
            audited=True,
            pinned=True,
            pin_type="manual",
            signer_count=100,  # still only +0.15
        )
        score = builder._compute_trust(node)
        assert score == 1.0


class TestTrustNodeZeroTrust:
    """Node with zero trust."""

    def test_zero_trust_defaults(self):
        builder = TrustGraphBuilder()
        node = TrustNode(name="untrusted", version="0.1")
        score = builder._compute_trust(node)
        assert score == 0.0

    def test_zero_trust_in_graph(self):
        g = TrustGraph(root="app", nodes={
            "untrusted": TrustNode("untrusted", "0.1", trust_score=0.0),
        })
        assert g.weakest_link.name == "untrusted"
        assert g.average_trust == 0.0


class TestTrustGraphRenderTextEmpty:
    """render_text on a graph with no nodes."""

    def test_render_empty_graph(self):
        g = TrustGraph(root="empty")
        text = g.render_text()
        assert "empty" in text
        assert "Packages: 0" in text
        # No weakest link line when graph is empty
        assert "Weakest link" not in text

    def test_render_empty_average_trust(self):
        g = TrustGraph(root="empty")
        text = g.render_text()
        assert "Average trust: 0%" in text


class TestTrustGraphCircularDependency:
    """Nodes with circular dependency references."""

    def test_circular_deps_in_graph(self):
        """Graph can represent circular deps without infinite loops."""
        g = TrustGraph(root="a", nodes={
            "a": TrustNode("a", "1.0", dependencies=["b"], trust_score=0.5),
            "b": TrustNode("b", "1.0", dependencies=["a"], trust_score=0.3),
        })
        # Graph structures should still work
        assert g.total_packages == 2
        assert g.weakest_link.name == "b"
        assert g.average_trust == pytest.approx(0.4)

    def test_circular_deps_render_text(self):
        """render_text doesn't loop infinitely on circular deps."""
        g = TrustGraph(root="a", nodes={
            "a": TrustNode("a", "1.0", dependencies=["b", "c"], trust_score=0.5),
            "b": TrustNode("b", "1.0", dependencies=["c", "a"], trust_score=0.3),
            "c": TrustNode("c", "1.0", dependencies=["a"], trust_score=0.1),
        })
        text = g.render_text()
        # All three nodes appear
        assert "a" in text
        assert "b" in text
        assert "c" in text

    def test_circular_deps_to_dict(self):
        g = TrustGraph(root="x", nodes={
            "x": TrustNode("x", "1.0", dependencies=["y"], trust_score=0.6),
            "y": TrustNode("y", "1.0", dependencies=["x"], trust_score=0.4),
        })
        d = g.to_dict()
        assert d["nodes"]["x"]["dependencies"] == ["y"]
        assert d["nodes"]["y"]["dependencies"] == ["x"]


class TestTrustGraphScoreBarEdgeCases:
    """Additional _score_bar edge cases."""

    def test_score_bar_tiny(self):
        assert _score_bar(0.05) == "----------"

    def test_score_bar_almost_full(self):
        assert _score_bar(0.99) == "#########-"

    def test_score_bar_custom_width(self):
        assert _score_bar(0.5, width=4) == "##--"
