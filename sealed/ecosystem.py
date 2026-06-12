"""Ecosystem adapters: abstract source fetching and building for pip, npm, cargo.

Sealed's core (chain, seal, verify, registry, policy) is ecosystem-agnostic.
This module provides the adapter layer that maps each package manager's
source distribution format into Sealed's pipeline.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sealed.chain import _hash_file, _hash_directory


class EcosystemError(Exception):
    pass


@dataclass
class SourcePackage:
    """A source package fetched from any ecosystem."""
    name: str
    version: str
    ecosystem: str          # "pip", "npm", "cargo"
    source_dir: Path
    archive_path: Path
    archive_hash: str
    registry_hash: str      # hash from the registry (PyPI, npm, crates.io)


class EcosystemAdapter(ABC):
    """Abstract adapter for a package ecosystem."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Ecosystem name: 'pip', 'npm', 'cargo'."""
        ...

    @abstractmethod
    def fetch(self, package: str, version: str | None = None,
              cache_dir: Path | None = None) -> SourcePackage:
        """Fetch source for a package."""
        ...

    @abstractmethod
    def build(self, source: SourcePackage,
              work_dir: Path | None = None) -> Path:
        """Build from source, return artifact path."""
        ...

    @abstractmethod
    def resolve_deps(self, package: str,
                     version: str | None = None) -> list[tuple[str, str]]:
        """Resolve transitive dependencies. Returns [(name, version), ...]."""
        ...


class PipAdapter(EcosystemAdapter):
    """Adapter for Python/pip/PyPI."""

    @property
    def name(self) -> str:
        return "pip"

    def fetch(self, package: str, version: str | None = None,
              cache_dir: Path | None = None) -> SourcePackage:
        from sealed.source import SourceFetcher
        fetcher = SourceFetcher(cache_dir=cache_dir)
        result = fetcher.fetch(package, version)
        return SourcePackage(
            name=result.package,
            version=result.version,
            ecosystem="pip",
            source_dir=result.source_dir,
            archive_path=result.archive_path,
            archive_hash=result.archive_hash,
            registry_hash=result.pypi_hash,
        )

    def build(self, source: SourcePackage,
              work_dir: Path | None = None) -> Path:
        work_dir = work_dir or Path(tempfile.mkdtemp(prefix="sealed_pip_"))
        output_dir = work_dir / "dist"
        output_dir.mkdir(exist_ok=True)

        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "wheel",
                "--no-deps", "--no-binary", ":all:",
                "--wheel-dir", str(output_dir),
                str(source.source_dir),
            ],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise EcosystemError(f"pip build failed: {result.stderr}")

        wheels = list(output_dir.glob("*.whl"))
        if not wheels:
            raise EcosystemError("Build produced no wheel")
        return wheels[0]

    def resolve_deps(self, package: str,
                     version: str | None = None) -> list[tuple[str, str]]:
        from sealed.resolver import DependencyResolver
        resolver = DependencyResolver()
        deps = resolver.resolve(package, version)
        return [(d.name, d.version) for d in deps]


class NpmAdapter(EcosystemAdapter):
    """Adapter for Node.js/npm. Requires npm installed."""

    @property
    def name(self) -> str:
        return "npm"

    def fetch(self, package: str, version: str | None = None,
              cache_dir: Path | None = None) -> SourcePackage:
        cache_dir = cache_dir or Path(tempfile.mkdtemp(prefix="sealed_npm_"))
        cache_dir.mkdir(parents=True, exist_ok=True)

        # npm pack downloads the tarball
        pkg_spec = f"{package}@{version}" if version else package
        result = subprocess.run(
            ["npm", "pack", pkg_spec, "--pack-destination", str(cache_dir)],
            capture_output=True, text=True, timeout=60,
            cwd=str(cache_dir),
        )
        if result.returncode != 0:
            raise EcosystemError(f"npm pack failed: {result.stderr}")

        tarball_name = result.stdout.strip().split("\n")[-1]
        tarball_path = cache_dir / tarball_name
        if not tarball_path.exists():
            raise EcosystemError(f"Tarball not found: {tarball_path}")

        archive_hash = _hash_file(tarball_path)

        # Get registry hash and verify
        registry_hash = self._get_registry_hash(package, version)
        if registry_hash and archive_hash != registry_hash:
            # npm uses SHA-1 for dist.shasum, compute SHA-1 for comparison
            import hashlib
            sha1 = hashlib.sha1()
            with open(tarball_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 16), b""):
                    sha1.update(chunk)
            if sha1.hexdigest() != registry_hash:
                raise EcosystemError(
                    f"Hash mismatch: npm says {registry_hash}, got {sha1.hexdigest()}"
                )

        # Extract with path traversal protection
        import tarfile
        extract_dir = cache_dir / "source"
        extract_dir.mkdir(exist_ok=True)
        with tarfile.open(tarball_path, "r:gz") as tf:
            if sys.version_info >= (3, 12):
                tf.extractall(extract_dir, filter="data")
            else:
                for member in tf.getmembers():
                    target = (extract_dir / member.name).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        raise EcosystemError(f"Path traversal: {member.name}")
                tf.extractall(extract_dir)

        source_dir = extract_dir / "package"
        if not source_dir.exists():
            children = list(extract_dir.iterdir())
            source_dir = children[0] if children else extract_dir

        # Parse version from package.json
        pkg_json = source_dir / "package.json"
        if pkg_json.exists():
            pkg_data = json.loads(pkg_json.read_text())
            version = pkg_data.get("version", version or "unknown")

        return SourcePackage(
            name=package, version=version or "unknown",
            ecosystem="npm",
            source_dir=source_dir,
            archive_path=tarball_path,
            archive_hash=archive_hash,
            registry_hash=registry_hash,
        )

    def build(self, source: SourcePackage,
              work_dir: Path | None = None) -> Path:
        # npm packages are the tarball itself (no compilation step for pure JS)
        return source.archive_path

    def resolve_deps(self, package: str,
                     version: str | None = None) -> list[tuple[str, str]]:
        pkg_spec = f"{package}@{version}" if version else package
        result = subprocess.run(
            ["npm", "view", pkg_spec, "dependencies", "--json"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return [(package, version or "latest")]

        deps_dict = json.loads(result.stdout)
        deps = [(name, ver.lstrip("^~>=<")) for name, ver in deps_dict.items()]
        deps.append((package, version or "latest"))
        return deps

    def _get_registry_hash(self, package: str, version: str | None) -> str:
        pkg_spec = f"{package}@{version}" if version else package
        result = subprocess.run(
            ["npm", "view", pkg_spec, "dist.shasum"],
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout.strip() if result.returncode == 0 else ""


class CargoAdapter(EcosystemAdapter):
    """Adapter for Rust/cargo/crates.io. Requires cargo installed."""

    @property
    def name(self) -> str:
        return "cargo"

    def fetch(self, package: str, version: str | None = None,
              cache_dir: Path | None = None) -> SourcePackage:
        cache_dir = cache_dir or Path(tempfile.mkdtemp(prefix="sealed_cargo_"))

        # cargo download downloads the crate
        pkg_spec = f"{package}@{version}" if version else package
        result = subprocess.run(
            ["cargo", "download", pkg_spec, "--output", str(cache_dir)],
            capture_output=True, text=True, timeout=60,
        )

        # Fallback: use crates.io API directly
        if result.returncode != 0:
            return self._fetch_from_api(package, version, cache_dir)

        crate_files = list(cache_dir.glob("*.crate"))
        if not crate_files:
            raise EcosystemError(f"No crate file found for {package}")

        crate_path = crate_files[0]
        archive_hash = _hash_file(crate_path)

        # Extract
        import tarfile
        extract_dir = cache_dir / "source"
        extract_dir.mkdir(exist_ok=True)
        with tarfile.open(crate_path, "r:gz") as tf:
            if sys.version_info >= (3, 12):
                tf.extractall(extract_dir, filter="data")
            else:
                for member in tf.getmembers():
                    target = (extract_dir / member.name).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        raise EcosystemError(f"Path traversal: {member.name}")
                tf.extractall(extract_dir)

        children = list(extract_dir.iterdir())
        source_dir = children[0] if len(children) == 1 else extract_dir

        # Parse version from Cargo.toml
        cargo_toml = source_dir / "Cargo.toml"
        if cargo_toml.exists():
            content = cargo_toml.read_text()
            for line in content.split("\n"):
                if line.strip().startswith("version"):
                    version = line.split("=")[1].strip().strip('"')
                    break

        return SourcePackage(
            name=package, version=version or "unknown",
            ecosystem="cargo",
            source_dir=source_dir,
            archive_path=crate_path,
            archive_hash=archive_hash,
            registry_hash="",
        )

    def _fetch_from_api(self, package: str, version: str | None,
                        cache_dir: Path) -> SourcePackage:
        import httpx
        if version:
            url = f"https://crates.io/api/v1/crates/{package}/{version}/download"
        else:
            # Get latest version
            meta = httpx.get(f"https://crates.io/api/v1/crates/{package}",
                           follow_redirects=True, timeout=30).json()
            version = meta["crate"]["newest_version"]
            url = f"https://crates.io/api/v1/crates/{package}/{version}/download"

        resp = httpx.get(url, follow_redirects=True, timeout=60)
        resp.raise_for_status()

        crate_path = cache_dir / f"{package}-{version}.crate"
        crate_path.write_bytes(resp.content)
        archive_hash = _hash_file(crate_path)

        import tarfile
        extract_dir = cache_dir / "source"
        extract_dir.mkdir(exist_ok=True)
        with tarfile.open(crate_path, "r:gz") as tf:
            if sys.version_info >= (3, 12):
                tf.extractall(extract_dir, filter="data")
            else:
                for member in tf.getmembers():
                    target = (extract_dir / member.name).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        raise EcosystemError(f"Path traversal: {member.name}")
                tf.extractall(extract_dir)

        children = list(extract_dir.iterdir())
        source_dir = children[0] if len(children) == 1 else extract_dir

        return SourcePackage(
            name=package, version=version,
            ecosystem="cargo",
            source_dir=source_dir,
            archive_path=crate_path,
            archive_hash=archive_hash,
            registry_hash="",
        )

    def build(self, source: SourcePackage,
              work_dir: Path | None = None) -> Path:
        result = subprocess.run(
            ["cargo", "build", "--release", "--manifest-path",
             str(source.source_dir / "Cargo.toml")],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise EcosystemError(f"cargo build failed: {result.stderr}")

        target_dir = source.source_dir / "target" / "release"
        binaries = [f for f in target_dir.iterdir()
                    if f.is_file() and not f.suffix in (".d", ".fingerprint")]
        if not binaries:
            raise EcosystemError("cargo build produced no artifacts")
        return binaries[0]

    def resolve_deps(self, package: str,
                     version: str | None = None) -> list[tuple[str, str]]:
        # cargo metadata gives the full dep tree
        return [(package, version or "latest")]


# Adapter registry
_ADAPTERS: dict[str, type[EcosystemAdapter]] = {
    "pip": PipAdapter,
    "npm": NpmAdapter,
    "cargo": CargoAdapter,
}


def get_adapter(ecosystem: str) -> EcosystemAdapter:
    """Get an adapter for the given ecosystem."""
    cls = _ADAPTERS.get(ecosystem)
    if cls is None:
        raise EcosystemError(
            f"Unknown ecosystem: {ecosystem}. Available: {', '.join(_ADAPTERS)}"
        )
    return cls()


def detect_ecosystem(package: str) -> str:
    """Guess the ecosystem from the package name or context."""
    # Check if package.json exists in cwd
    if Path("package.json").exists():
        return "npm"
    if Path("Cargo.toml").exists():
        return "cargo"
    return "pip"
