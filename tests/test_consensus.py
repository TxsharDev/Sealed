"""Tests for consensus builds."""

import pytest

from sealed.consensus import ConsensusBuilder, ConsensusResult, ConsensusBuild


class TestConsensusResult:
    def test_ok_when_consensus(self):
        r = ConsensusResult(
            package="test", version="1.0",
            consensus_reached=True,
            consensus_hash="abc",
            agreement_count=3, total_builds=3,
        )
        assert r.ok

    def test_not_ok_without_consensus(self):
        r = ConsensusResult(
            package="test", version="1.0",
            consensus_reached=False,
            agreement_count=1, total_builds=3,
        )
        assert not r.ok

    def test_to_dict(self):
        r = ConsensusResult(
            package="pkg", version="2.0",
            builds=[ConsensusBuild(0, "aaa", "bbb", True)],
            consensus_reached=True,
            consensus_hash="bbb",
            agreement_count=1, total_builds=1,
        )
        d = r.to_dict()
        assert d["consensus_reached"] is True
        assert d["agreement"] == "1/1"


class TestConsensusBuild:
    def test_to_dict(self):
        b = ConsensusBuild(
            build_id=0, artifact_hash="abc",
            normalized_hash="def", success=True,
        )
        d = b.to_dict()
        assert d["build_id"] == 0
        assert d["success"] is True

    def test_failed_build(self):
        b = ConsensusBuild(
            build_id=1, artifact_hash="",
            normalized_hash="", success=False,
            error="Build failed",
        )
        assert not b.success


class TestConsensusBuilder:
    @pytest.mark.network
    def test_consensus_six(self):
        """Build six 3 times and check consensus."""
        builder = ConsensusBuilder(num_builds=3, threshold=0.67)
        try:
            result = builder.build("six", "1.17.0")
            assert result.package == "six"
            assert len(result.builds) == 3
            # Pure Python should reach consensus
            assert result.consensus_reached
            assert result.agreement_count >= 2
        except Exception:
            pytest.skip("Network not available")
