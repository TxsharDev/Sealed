"""Trust graph: visualize your dependency tree with trust scores.

Shows the entire transitive dependency graph with trust level per node:
sealed vs unsealed, TOFU vs manual pin, single vs multi-party,
audited vs not. Highlights the weakest link.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.registry import SealRegistry
from sealed.resolver import DependencyResolver, _normalize


@dataclass
class TrustNode:
    """A node in the trust graph."""
    name: str
    version: str
    sealed: bool = False
    attestation: str = "none"
    audited: bool = False
    pinned: bool = False
    pin_type: str = "none"          # tofu, manual, none
    signer_count: int = 0
    dependencies: list[str] = field(default_factory=list)
    trust_score: float = 0.0        # 0.0 (no trust) to 1.0 (full trust)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "sealed": self.sealed,
            "attestation": self.attestation,
            "audited": self.audited,
            "pinned": self.pinned,
            "pin_type": self.pin_type,
            "signer_count": self.signer_count,
            "dependencies": self.dependencies,
            "trust_score": round(self.trust_score, 2),
        }


@dataclass
class TrustGraph:
    """The full trust graph for a package and its dependencies."""
    root: str
    nodes: dict[str, TrustNode] = field(default_factory=dict)

    @property
    def weakest_link(self) -> TrustNode | None:
        """Find the node with the lowest trust score."""
        if not self.nodes:
            return None
        return min(self.nodes.values(), key=lambda n: n.trust_score)

    @property
    def total_packages(self) -> int:
        return len(self.nodes)

    @property
    def sealed_count(self) -> int:
        return sum(1 for n in self.nodes.values() if n.sealed)

    @property
    def unsealed_count(self) -> int:
        return sum(1 for n in self.nodes.values() if not n.sealed)

    @property
    def average_trust(self) -> float:
        if not self.nodes:
            return 0.0
        return sum(n.trust_score for n in self.nodes.values()) / len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        weakest = self.weakest_link
        return {
            "root": self.root,
            "total_packages": self.total_packages,
            "sealed": self.sealed_count,
            "unsealed": self.unsealed_count,
            "average_trust": round(self.average_trust, 2),
            "weakest_link": weakest.name if weakest else None,
            "weakest_score": round(weakest.trust_score, 2) if weakest else None,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
        }

    def render_text(self) -> str:
        """Render the trust graph as text."""
        lines = [
            f"Trust Graph: {self.root}",
            f"  Packages: {self.total_packages} "
            f"({self.sealed_count} sealed, {self.unsealed_count} unsealed)",
            f"  Average trust: {self.average_trust:.0%}",
        ]
        weakest = self.weakest_link
        if weakest:
            lines.append(f"  Weakest link: {weakest.name} ({weakest.trust_score:.0%})")
        lines.append("")

        for name in sorted(self.nodes):
            node = self.nodes[name]
            score_bar = _score_bar(node.trust_score)
            status = "SEALED" if node.sealed else "UNSEALED"
            pin = f"pin={node.pin_type}" if node.pinned else "no pin"
            signers = f"{node.signer_count} signers" if node.signer_count > 1 else ""
            parts = [f"[{score_bar}]", f"{name}=={node.version}", status, pin]
            if signers:
                parts.append(signers)
            if node.audited:
                parts.append("audited")
            lines.append("  " + "  ".join(parts))

        return "\n".join(lines)


def _score_bar(score: float, width: int = 10) -> str:
    filled = int(score * width)
    return "#" * filled + "-" * (width - filled)


class TrustGraphBuilder:
    """Build a trust graph for a package and its dependencies."""

    def __init__(self, registry: SealRegistry | None = None):
        self.registry = registry

    def build(self, package: str,
              version: str | None = None) -> TrustGraph:
        """Resolve dependencies and compute trust for each."""
        resolver = DependencyResolver()
        try:
            deps = resolver.resolve(package, version)
        except Exception:
            deps = []

        graph = TrustGraph(root=package)

        for dep in deps:
            node = TrustNode(
                name=dep.name,
                version=dep.version,
                dependencies=[_normalize(d) for d in dep.dependencies],
            )

            # Check registry for seal info
            if self.registry:
                entries = self.registry.lookup(dep.name, dep.version)
                if entries:
                    node.sealed = True
                    node.signer_count = len({e.seal.public_key for e in entries})
                    node.attestation = entries[0].attestation_method

                    # Check audit
                    chain = entries[0].chain
                    node.audited = any(
                        r.step == "source_audit" for r in chain.records
                    )

                pins = self.registry.get_pins(dep.name)
                if pins:
                    node.pinned = True
                    node.pin_type = pins[0].get("pin_type", "unknown")

            # Compute trust score
            node.trust_score = self._compute_trust(node)
            graph.nodes[dep.name] = node

        # If root package wasn't in deps, add it
        root_norm = _normalize(package)
        if root_norm not in graph.nodes:
            node = TrustNode(name=root_norm, version=version or "?")
            if self.registry:
                entries = self.registry.lookup(root_norm, version)
                if entries:
                    node.sealed = True
                    node.signer_count = len({e.seal.public_key for e in entries})
            node.trust_score = self._compute_trust(node)
            graph.nodes[root_norm] = node

        return graph

    def _compute_trust(self, node: TrustNode) -> float:
        """Compute a trust score from 0.0 to 1.0."""
        score = 0.0

        # Base: sealed or not (40%)
        if node.sealed:
            score += 0.4

        # Attestation method (15%)
        if node.attestation == "tpm2":
            score += 0.15
        elif node.attestation == "software":
            score += 0.10

        # Source audited (15%)
        if node.audited:
            score += 0.15

        # Key pinned (15%)
        if node.pinned:
            if node.pin_type == "manual":
                score += 0.15
            elif node.pin_type == "tofu":
                score += 0.10

        # Multi-party (15%)
        if node.signer_count >= 3:
            score += 0.15
        elif node.signer_count >= 2:
            score += 0.10
        elif node.signer_count == 1:
            score += 0.05

        return min(score, 1.0)
