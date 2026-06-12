"""Reproducibility verification: rebuild and compare.

Strips non-determinism where possible and compares build outputs
across runs to verify reproducibility.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.chain import _hash_file, _hash_directory
from sealed.source import SourceFetcher
from sealed.builder import IsolatedBuilder


@dataclass
class ReproduceResult:
    """Result of a reproducibility check."""
    package: str
    version: str
    reproducible: bool
    build1_hash: str
    build2_hash: str
    differences: list[str] = field(default_factory=list)
    normalized_match: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "reproducible": self.reproducible,
            "build1_hash": self.build1_hash,
            "build2_hash": self.build2_hash,
            "normalized_match": self.normalized_match,
            "differences": self.differences,
        }


class ReproducibilityChecker:
    """Build twice and compare to verify reproducibility."""

    def check(self, package: str, version: str | None = None) -> ReproduceResult:
        """Build a package twice and compare the outputs."""
        work1 = Path(tempfile.mkdtemp(prefix="sealed_repro1_"))
        work2 = Path(tempfile.mkdtemp(prefix="sealed_repro2_"))

        # Fetch source once (same source for both builds)
        fetcher = SourceFetcher(cache_dir=work1 / "cache")
        source = fetcher.fetch(package, version)

        # Build 1
        builder1 = IsolatedBuilder(work_dir=work1 / "build")
        result1 = builder1.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )

        # Build 2 (same source, different work dir)
        builder2 = IsolatedBuilder(work_dir=work2 / "build")
        result2 = builder2.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )

        hash1 = result1.artifact_hash
        hash2 = result2.artifact_hash
        exact_match = hash1 == hash2

        differences = []
        normalized_match = False

        if not exact_match:
            # Compare normalized (strip timestamps, paths)
            differences = self._diff_wheels(result1.artifact, result2.artifact)
            norm1 = self._normalize_wheel_hash(result1.artifact)
            norm2 = self._normalize_wheel_hash(result2.artifact)
            normalized_match = norm1 == norm2

        return ReproduceResult(
            package=source.package,
            version=source.version,
            reproducible=exact_match,
            build1_hash=hash1,
            build2_hash=hash2,
            differences=differences,
            normalized_match=normalized_match,
        )

    def check_against_seal(self, seal_dir: Path) -> ReproduceResult:
        """Rebuild a sealed package and compare to the stored artifact."""
        chain_path = seal_dir / "chain.json"
        chain_data = json.loads(chain_path.read_text())
        package = chain_data["package_name"]
        version = chain_data["package_version"]

        # Find stored artifact
        artifacts = [f for f in seal_dir.iterdir()
                     if f.suffix == ".whl" or f.name.endswith(".tar.gz")]
        if not artifacts:
            return ReproduceResult(
                package=package, version=version,
                reproducible=False, build1_hash="", build2_hash="",
                differences=["No stored artifact found"],
            )

        stored_hash = _hash_file(artifacts[0])

        # Rebuild
        work = Path(tempfile.mkdtemp(prefix="sealed_repro_"))
        fetcher = SourceFetcher(cache_dir=work / "cache")
        source = fetcher.fetch(package, version)

        builder = IsolatedBuilder(work_dir=work / "build")
        result = builder.build(
            source.source_dir, source.archive_hash,
            source.package, source.version,
        )

        rebuild_hash = result.artifact_hash
        exact_match = stored_hash == rebuild_hash

        differences = []
        normalized_match = False

        if not exact_match:
            differences = self._diff_wheels(artifacts[0], result.artifact)
            norm1 = self._normalize_wheel_hash(artifacts[0])
            norm2 = self._normalize_wheel_hash(result.artifact)
            normalized_match = norm1 == norm2

        return ReproduceResult(
            package=package, version=version,
            reproducible=exact_match,
            build1_hash=stored_hash,
            build2_hash=rebuild_hash,
            differences=differences,
            normalized_match=normalized_match,
        )

    def _diff_wheels(self, wheel1: Path, wheel2: Path) -> list[str]:
        """Compare two wheel files and report differences."""
        diffs = []
        try:
            with zipfile.ZipFile(wheel1) as z1, zipfile.ZipFile(wheel2) as z2:
                names1 = set(z1.namelist())
                names2 = set(z2.namelist())

                only_in_1 = names1 - names2
                only_in_2 = names2 - names1
                if only_in_1:
                    diffs.append(f"Files only in build 1: {sorted(only_in_1)}")
                if only_in_2:
                    diffs.append(f"Files only in build 2: {sorted(only_in_2)}")

                for name in sorted(names1 & names2):
                    data1 = z1.read(name)
                    data2 = z2.read(name)
                    if data1 != data2:
                        diffs.append(f"Content differs: {name}")
        except (zipfile.BadZipFile, Exception) as e:
            diffs.append(f"Cannot compare: {e}")
        return diffs

    def _normalize_wheel_hash(self, wheel: Path) -> str:
        """Hash a wheel after stripping timestamps and variable metadata."""
        h = hashlib.sha256()
        try:
            with zipfile.ZipFile(wheel) as zf:
                for name in sorted(zf.namelist()):
                    data = zf.read(name)
                    # Strip RECORD file (contains hashes that vary)
                    if name.endswith("/RECORD"):
                        continue
                    # Strip timestamps from METADATA
                    if name.endswith("/METADATA") or name.endswith("/WHEEL"):
                        data = re.sub(rb"(?m)^Date:.*$", b"", data)
                    h.update(name.encode())
                    h.update(data)
        except Exception:
            h.update(_hash_file(wheel).encode())
        return h.hexdigest()
