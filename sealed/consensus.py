"""Consensus builds: N independent builds, accept only if they agree.

Not just multi-party signing. Multiple machines build the same source
and compare binary outputs. If 2/3 produce identical results, accept.
If they diverge, something is non-deterministic or compromised.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.builder import IsolatedBuilder
from sealed.chain import _hash_file
from sealed.reproduce import ReproducibilityChecker
from sealed.source import SourceFetcher


@dataclass
class ConsensusBuild:
    """Result of a single build in a consensus round."""
    build_id: int
    artifact_hash: str
    normalized_hash: str
    success: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "build_id": self.build_id,
            "artifact_hash": self.artifact_hash,
            "normalized_hash": self.normalized_hash,
            "success": self.success,
            "error": self.error,
        }


@dataclass
class ConsensusResult:
    """Result of consensus build verification."""
    package: str
    version: str
    builds: list[ConsensusBuild] = field(default_factory=list)
    consensus_hash: str | None = None
    consensus_reached: bool = False
    agreement_count: int = 0
    total_builds: int = 0
    threshold: float = 0.67  # 2/3 agreement required

    @property
    def ok(self) -> bool:
        return self.consensus_reached

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "consensus_reached": self.consensus_reached,
            "consensus_hash": self.consensus_hash,
            "agreement": f"{self.agreement_count}/{self.total_builds}",
            "threshold": self.threshold,
            "builds": [b.to_dict() for b in self.builds],
        }


class ConsensusBuilder:
    """Build a package N times independently and check for agreement."""

    def __init__(self, num_builds: int = 3, threshold: float = 0.67):
        self.num_builds = num_builds
        self.threshold = threshold
        self._checker = ReproducibilityChecker()

    def build(self, package: str,
              version: str | None = None) -> ConsensusResult:
        """Run N independent builds and check for consensus."""
        # Fetch source once
        cache_dir = Path(tempfile.mkdtemp(prefix="sealed_consensus_cache_"))
        fetcher = SourceFetcher(cache_dir=cache_dir)
        source = fetcher.fetch(package, version)

        result = ConsensusResult(
            package=source.package,
            version=source.version,
            total_builds=self.num_builds,
            threshold=self.threshold,
        )

        # Build N times
        for i in range(self.num_builds):
            work_dir = Path(tempfile.mkdtemp(prefix=f"sealed_consensus_{i}_"))
            try:
                builder = IsolatedBuilder(work_dir=work_dir)
                build_result = builder.build(
                    source.source_dir, source.archive_hash,
                    source.package, source.version,
                    audit=False,  # skip audit on consensus builds for speed
                )
                norm_hash = self._checker._normalize_wheel_hash(build_result.artifact)

                result.builds.append(ConsensusBuild(
                    build_id=i,
                    artifact_hash=build_result.artifact_hash,
                    normalized_hash=norm_hash,
                    success=True,
                ))
            except Exception as e:
                result.builds.append(ConsensusBuild(
                    build_id=i,
                    artifact_hash="",
                    normalized_hash="",
                    success=False,
                    error=str(e)[:500],
                ))

        # Check consensus using normalized hashes
        successful = [b for b in result.builds if b.success]
        if not successful:
            return result

        # Count agreement on normalized hash
        hash_counts: dict[str, int] = {}
        for b in successful:
            hash_counts[b.normalized_hash] = hash_counts.get(b.normalized_hash, 0) + 1

        # Find the most common hash
        best_hash = max(hash_counts, key=hash_counts.get)
        best_count = hash_counts[best_hash]

        result.agreement_count = best_count
        result.consensus_hash = best_hash

        # Check if threshold is met
        if best_count / self.num_builds >= self.threshold:
            result.consensus_reached = True

        return result
