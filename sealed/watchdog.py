"""Runtime integrity watchdog: continuously verify installed package files.

After installation, monitors sealed packages for modifications.
If malware or a rogue process modifies an installed .py file,
the watchdog catches it.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.chain import _hash_file


@dataclass
class IntegrityViolation:
    """A detected integrity violation."""
    package: str
    file: str
    expected_hash: str
    actual_hash: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "file": self.file,
            "expected_hash": self.expected_hash[:16] + "...",
            "actual_hash": self.actual_hash[:16] + "...",
            "timestamp": self.timestamp,
        }


@dataclass
class WatchdogSnapshot:
    """A snapshot of all files in a sealed package for integrity monitoring."""
    package: str
    version: str
    install_path: str
    file_hashes: dict[str, str]  # relative_path -> sha256
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "install_path": self.install_path,
            "file_count": len(self.file_hashes),
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps({
            "package": self.package,
            "version": self.version,
            "install_path": self.install_path,
            "file_hashes": self.file_hashes,
            "created_at": self.created_at,
        }, indent=2)

    @classmethod
    def from_json(cls, s: str) -> WatchdogSnapshot:
        d = json.loads(s)
        return cls(
            package=d["package"],
            version=d["version"],
            install_path=d["install_path"],
            file_hashes=d["file_hashes"],
            created_at=d.get("created_at", 0),
        )


class IntegrityWatchdog:
    """Monitor installed packages for post-install modifications."""

    def __init__(self, snapshot_dir: Path | None = None):
        self.snapshot_dir = snapshot_dir or Path.home() / ".sealed" / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    def snapshot(self, package: str, version: str,
                 install_path: Path) -> WatchdogSnapshot:
        """Take a snapshot of all files in an installed package."""
        file_hashes = {}
        install_path = install_path.resolve()

        for f in sorted(install_path.rglob("*")):
            if f.is_symlink() or not f.is_file():
                continue
            rel = f.relative_to(install_path).as_posix()
            file_hashes[rel] = _hash_file(f)

        snap = WatchdogSnapshot(
            package=package,
            version=version,
            install_path=str(install_path),
            file_hashes=file_hashes,
        )

        # Save snapshot
        snap_path = self.snapshot_dir / f"{package}-{version}.json"
        snap_path.write_text(snap.to_json())
        return snap

    def check(self, package: str | None = None) -> list[IntegrityViolation]:
        """Check all (or one) snapshots against current file state."""
        violations = []

        if package:
            snap_files = list(self.snapshot_dir.glob(f"{package}-*.json"))
        else:
            snap_files = list(self.snapshot_dir.glob("*.json"))

        for snap_file in snap_files:
            snap = WatchdogSnapshot.from_json(snap_file.read_text())
            install_path = Path(snap.install_path)

            if not install_path.exists():
                continue

            for rel_path, expected_hash in snap.file_hashes.items():
                full_path = install_path / rel_path
                if not full_path.exists():
                    violations.append(IntegrityViolation(
                        package=snap.package,
                        file=rel_path,
                        expected_hash=expected_hash,
                        actual_hash="FILE_DELETED",
                    ))
                    continue

                actual_hash = _hash_file(full_path)
                if actual_hash != expected_hash:
                    violations.append(IntegrityViolation(
                        package=snap.package,
                        file=rel_path,
                        expected_hash=expected_hash,
                        actual_hash=actual_hash,
                    ))

        return violations

    def list_snapshots(self) -> list[dict[str, Any]]:
        """List all snapshots."""
        snapshots = []
        for snap_file in sorted(self.snapshot_dir.glob("*.json")):
            snap = WatchdogSnapshot.from_json(snap_file.read_text())
            snapshots.append(snap.to_dict())
        return snapshots
