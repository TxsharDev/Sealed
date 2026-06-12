"""Lockfile: pin exact versions and hashes for reproducible installs.

`sealed install requests` produces a `sealed.lock` that records every
package-version-hash. Subsequent installs verify against it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.chain import _hash_bytes


@dataclass
class LockEntry:
    """A single locked package."""
    name: str
    version: str
    artifact_hash: str
    chain_hash: str
    public_key: str
    ecosystem: str = "pip"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "artifact_hash": self.artifact_hash,
            "chain_hash": self.chain_hash,
            "public_key": self.public_key,
            "ecosystem": self.ecosystem,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LockEntry:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Lockfile:
    """A complete lockfile for a project."""
    entries: dict[str, LockEntry] = field(default_factory=dict)  # name -> entry
    created_at: float = field(default_factory=time.time)
    sealed_version: str = "0.1.0"

    def add(self, entry: LockEntry) -> None:
        self.entries[entry.name] = entry

    def get(self, name: str) -> LockEntry | None:
        return self.entries.get(name)

    def check(self, name: str, version: str, artifact_hash: str) -> LockCheck:
        """Check if a package matches the lockfile."""
        entry = self.entries.get(name)
        if entry is None:
            return LockCheck("new", f"{name} not in lockfile")

        if entry.version != version:
            return LockCheck(
                "version_mismatch",
                f"{name}: locked {entry.version}, got {version}",
            )

        if entry.artifact_hash != artifact_hash:
            return LockCheck(
                "hash_mismatch",
                f"{name}: artifact hash differs from lockfile",
            )

        return LockCheck("ok", f"{name}=={version} matches lockfile")

    @property
    def digest(self) -> str:
        """Hash of the entire lockfile for integrity."""
        data = json.dumps(
            {k: v.to_dict() for k, v in sorted(self.entries.items())},
            sort_keys=True, separators=(",", ":"),
        )
        return _hash_bytes(data.encode())

    def to_json(self) -> str:
        return json.dumps({
            "sealed_version": self.sealed_version,
            "created_at": self.created_at,
            "lockfile_hash": self.digest,
            "packages": {k: v.to_dict() for k, v in sorted(self.entries.items())},
        }, indent=2)

    @classmethod
    def from_json(cls, s: str) -> Lockfile:
        d = json.loads(s)
        lf = cls(
            created_at=d.get("created_at", 0),
            sealed_version=d.get("sealed_version", "unknown"),
        )
        for name, entry_data in d.get("packages", {}).items():
            lf.entries[name] = LockEntry.from_dict(entry_data)
        return lf

    def save(self, path: Path) -> None:
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> Lockfile:
        return cls.from_json(path.read_text())

    def verify_integrity(self) -> bool:
        """Check that the lockfile hasn't been tampered with."""
        stored = json.loads(self.to_json()).get("lockfile_hash", "")
        return stored == self.digest


@dataclass
class LockCheck:
    """Result of checking a package against the lockfile."""
    status: str  # "ok", "new", "version_mismatch", "hash_mismatch"
    message: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def is_new(self) -> bool:
        return self.status == "new"
