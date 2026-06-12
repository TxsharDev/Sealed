"""Tests for trust graph."""

import pytest

from sealed.trust_graph import (
    TrustGraphBuilder, TrustGraph, TrustNode, _score_bar,
)
from sealed.registry import SealRegistry
from sealed.chain import ProvenanceChain
from sealed.seal import SealAuthority


class TestTrustNode:
    def test_default_score_zero(self):
        node = TrustNode(name="test", version="1.0")
        assert node.trust_score == 0.0

    def test_to_dict(self):
        node = TrustNode(name="pkg", version="2.0", sealed=True, trust_score=0.7)
        d = node.to_dict()
        assert d["name"] == "pkg"
        assert d["sealed"] is True
        assert d["trust_score"] == 0.7


class TestTrustGraph:
    def test_empty_graph(self):
        g = TrustGraph(root="test")
        assert g.total_packages == 0
        assert g.weakest_link is None
        assert g.average_trust == 0.0

    def test_weakest_link(self):
        g = TrustGraph(root="app", nodes={
            "a": TrustNode("a", "1.0", trust_score=0.9),
            "b": TrustNode("b", "1.0", trust_score=0.2),
            "c": TrustNode("c", "1.0", trust_score=0.7),
        })
        assert g.weakest_link.name == "b"

    def test_counts(self):
        g = TrustGraph(root="app", nodes={
            "a": TrustNode("a", "1.0", sealed=True, trust_score=0.5),
            "b": TrustNode("b", "1.0", sealed=False, trust_score=0.0),
        })
        assert g.sealed_count == 1
        assert g.unsealed_count == 1
        assert g.total_packages == 2

    def test_render_text(self):
        g = TrustGraph(root="app", nodes={
            "dep": TrustNode("dep", "1.0", sealed=True, trust_score=0.5),
        })
        text = g.render_text()
        assert "dep" in text
        assert "SEALED" in text

    def test_to_dict(self):
        g = TrustGraph(root="app", nodes={
            "a": TrustNode("a", "1.0", trust_score=0.8),
        })
        d = g.to_dict()
        assert d["root"] == "app"
        assert d["total_packages"] == 1


class TestScoreBar:
    def test_full(self):
        assert _score_bar(1.0) == "##########"

    def test_empty(self):
        assert _score_bar(0.0) == "----------"

    def test_half(self):
        assert _score_bar(0.5) == "#####-----"


class TestTrustGraphBuilder:
    def test_compute_trust_unsealed(self):
        builder = TrustGraphBuilder()
        node = TrustNode(name="x", version="1.0")
        score = builder._compute_trust(node)
        assert score == 0.0

    def test_compute_trust_fully_sealed(self):
        builder = TrustGraphBuilder()
        node = TrustNode(
            name="x", version="1.0",
            sealed=True,
            attestation="tpm2",
            audited=True,
            pinned=True, pin_type="manual",
            signer_count=3,
        )
        score = builder._compute_trust(node)
        assert score == 1.0

    def test_compute_trust_basic_seal(self):
        builder = TrustGraphBuilder()
        node = TrustNode(
            name="x", version="1.0",
            sealed=True,
            attestation="software",
            signer_count=1,
        )
        score = builder._compute_trust(node)
        assert 0.4 < score < 0.7  # sealed + software + 1 signer

    def test_build_with_registry(self, tmp_path):
        reg = SealRegistry(tmp_path / "test.db")
        auth = SealAuthority()
        chain = ProvenanceChain(package_name="six", package_version="1.17.0")
        chain.add("source_audit", "a", "b", safe=True)
        chain.add("build", "c", "d")
        seal = auth.seal(chain)
        reg.store(seal, chain, "software")

        builder = TrustGraphBuilder(registry=reg)
        graph = builder.build("six", "1.17.0")
        assert "six" in graph.nodes
        assert graph.nodes["six"].sealed
        assert graph.nodes["six"].audited
        reg.close()
