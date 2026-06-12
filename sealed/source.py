"""Fetch package source from PyPI. No pre-built binaries, ever."""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from pathlib import Path

import httpx

from sealed.chain import _hash_file

PYPI_API = "https://pypi.org/pypi"


class SourceFetchError(Exception):
    pass


class SourceFetcher:
    """Fetch and verify source distributions from PyPI."""

    def __init__(self, cache_dir: Path | None = None):
        self.cache_dir = cache_dir or Path(tempfile.mkdtemp(prefix="sealed_"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def fetch(self, package: str, version: str | None = None) -> SourceResult:
        """Download the source distribution for a package.

        Returns the extracted source directory and metadata.
        """
        meta = self._get_metadata(package, version)
        sdist = self._find_sdist(meta, package)
        archive_path = self._download(sdist["url"], sdist["filename"])
        archive_hash = _hash_file(archive_path)

        # Verify against PyPI's reported digest (fail-closed)
        pypi_hash = sdist.get("digests", {}).get("sha256", "")
        if not pypi_hash:
            raise SourceFetchError(
                f"PyPI returned no SHA-256 digest for {package}. "
                "Sealed requires a hash to verify the download. "
                "This package may be too old or the registry may be compromised."
            )
        if archive_hash != pypi_hash:
            raise SourceFetchError(
                f"Hash mismatch: PyPI says {pypi_hash}, got {archive_hash}"
            )

        source_dir = self._extract(archive_path)
        return SourceResult(
            package=package,
            version=meta["info"]["version"],
            source_dir=source_dir,
            archive_path=archive_path,
            archive_hash=archive_hash,
            pypi_hash=pypi_hash,
        )

    def _get_metadata(self, package: str, version: str | None) -> dict:
        url = f"{PYPI_API}/{package}/json"
        if version:
            url = f"{PYPI_API}/{package}/{version}/json"
        resp = httpx.get(url, follow_redirects=True, timeout=30)
        if resp.status_code == 404:
            raise SourceFetchError(f"Package not found: {package}")
        resp.raise_for_status()
        return resp.json()

    def _find_sdist(self, meta: dict, package: str) -> dict:
        """Find the source distribution (sdist), reject wheels."""
        for url_info in meta["urls"]:
            if url_info["packagetype"] == "sdist":
                return url_info
        raise SourceFetchError(
            f"No source distribution for {package} {meta['info']['version']}. "
            "Only pre-built wheels available. Sealed requires source."
        )

    def _download(self, url: str, filename: str) -> Path:
        dest = self.cache_dir / filename
        if dest.exists():
            return dest
        resp = httpx.get(url, follow_redirects=True, timeout=120)
        resp.raise_for_status()
        dest.write_bytes(resp.content)
        return dest

    def _extract(self, archive_path: Path) -> Path:
        # Unique extract dir per archive to prevent cache collisions
        extract_dir = self.cache_dir / f"source_{archive_path.stem}"
        extract_dir.mkdir(exist_ok=True)
        name = archive_path.name

        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                # filter="data" requires Python 3.12+, fall back to manual check
                import sys
                if sys.version_info >= (3, 12):
                    tf.extractall(extract_dir, filter="data")
                else:
                    # Manual path traversal check for Python 3.10-3.11
                    for member in tf.getmembers():
                        target = (extract_dir / member.name).resolve()
                        if not str(target).startswith(str(extract_dir.resolve())):
                            raise SourceFetchError(
                                f"Tar path traversal detected: {member.name}"
                            )
                    tf.extractall(extract_dir)
        elif name.endswith(".zip"):
            with zipfile.ZipFile(archive_path) as zf:
                # Validate all paths to prevent zip path traversal (CVE-2007-4559)
                for member in zf.namelist():
                    target = (extract_dir / member).resolve()
                    if not str(target).startswith(str(extract_dir.resolve())):
                        raise SourceFetchError(
                            f"Zip path traversal detected: {member}"
                        )
                zf.extractall(extract_dir)
        else:
            raise SourceFetchError(f"Unknown archive format: {name}")

        # Find the extracted directory (usually <package>-<version>/)
        children = list(extract_dir.iterdir())
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return extract_dir


class SourceResult:
    """Result of fetching a package source."""

    __slots__ = (
        "package", "version", "source_dir",
        "archive_path", "archive_hash", "pypi_hash",
    )

    def __init__(self, package: str, version: str, source_dir: Path,
                 archive_path: Path, archive_hash: str, pypi_hash: str):
        self.package = package
        self.version = version
        self.source_dir = source_dir
        self.archive_path = archive_path
        self.archive_hash = archive_hash
        self.pypi_hash = pypi_hash
