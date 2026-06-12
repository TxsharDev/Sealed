"""Recursive dependency resolver: seal every transitive dependency.

`sealed install requests` doesn't just seal requests. It seals
urllib3, charset-normalizer, idna, certifi -- everything.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from sealed.source import SourceFetcher, SourceFetchError


@dataclass
class DepNode:
    """A node in the dependency tree."""
    name: str
    version: str
    dependencies: list[str] = field(default_factory=list)
    sealed: bool = False
    error: str | None = None


class DependencyResolver:
    """Resolve and order transitive dependencies for sealing."""

    def resolve(self, package: str,
                version: str | None = None) -> list[DepNode]:
        """Resolve all transitive dependencies of a package.

        Returns a list in install order (dependencies first, package last).
        """
        tree = self._get_dep_tree(package, version)
        ordered = self._topological_sort(tree)
        return ordered

    def _get_dep_tree(self, package: str,
                      version: str | None = None) -> dict[str, DepNode]:
        """Use pip to resolve the dependency tree."""
        import tempfile
        # Write report to file to avoid Windows encoding issues with stdout
        report_file = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w",
        )
        report_path = report_file.name
        report_file.close()

        try:
            cmd = [
                sys.executable, "-m", "pip", "install",
                "--dry-run", "--report", report_path,
                "--ignore-installed",
                "--quiet",
            ]
            if version:
                cmd.append(f"{package}=={version}")
            else:
                cmd.append(package)

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )

            if result.returncode != 0:
                raise SourceFetchError(
                    f"Dependency resolution failed for {package}: {result.stderr}"
                )

            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        finally:
            Path(report_path).unlink(missing_ok=True)
        tree: dict[str, DepNode] = {}

        for item in report.get("install", []):
            meta = item.get("metadata", {})
            name = _normalize(meta.get("name", item.get("name", "")))
            ver = meta.get("version", "")
            requires = []

            # Parse requires_dist for dependency names
            for req_str in meta.get("requires_dist", []):
                # Skip extras and markers we don't need
                if "; extra ==" in req_str:
                    continue
                dep_name = _normalize(req_str.split()[0].split(";")[0].split("[")[0])
                if dep_name:
                    requires.append(dep_name)

            tree[name] = DepNode(
                name=name,
                version=ver,
                dependencies=requires,
            )

        return tree

    def _topological_sort(self, tree: dict[str, DepNode]) -> list[DepNode]:
        """Sort dependencies so each package is installed after its deps."""
        visited: set[str] = set()
        result: list[DepNode] = []

        def visit(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            node = tree.get(name)
            if node is None:
                return
            for dep in node.dependencies:
                dep_norm = _normalize(dep)
                if dep_norm in tree:
                    visit(dep_norm)
            result.append(node)

        for name in tree:
            visit(name)

        return result


def _normalize(name: str) -> str:
    """Normalize package name (PEP 503)."""
    return name.lower().replace("-", "_").replace(".", "_").strip()
