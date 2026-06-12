"""Provenance chain: the full audit trail from source to binary."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def _hash_file(path: Path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _hash_bytes(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()


def _hash_directory(path: Path, algo: str = "sha256") -> str:
    """Hash every file in a directory tree, sorted for determinism.

    Skips symlinks to prevent traversal outside the source tree.
    """
    h = hashlib.new(algo)
    for p in sorted(path.rglob("*")):
        if p.is_symlink():
            continue
        if p.is_file():
            rel = p.relative_to(path).as_posix()
            h.update(rel.encode())
            h.update(_hash_file(p, algo).encode())
    return h.hexdigest()


@dataclass
class BuildEnvironment:
    """Snapshot of the machine that ran the build."""
    python_version: str = field(default_factory=lambda: sys.version)
    platform: str = field(default_factory=lambda: platform.platform())
    architecture: str = field(default_factory=lambda: platform.machine())
    hostname: str = field(default_factory=lambda: platform.node())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProvenanceRecord:
    """One link in the provenance chain."""
    step: str                    # e.g. "source_fetch", "build", "package"
    input_hash: str              # hash of what went in
    output_hash: str             # hash of what came out
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization for signing."""
        d = self.to_dict()
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class ProvenanceChain:
    """Full chain from source to binary. Each record links to the previous."""
    package_name: str
    package_version: str
    records: list[ProvenanceRecord] = field(default_factory=list)
    environment: BuildEnvironment = field(default_factory=BuildEnvironment)

    def add(self, step: str, input_hash: str, output_hash: str,
            **metadata: Any) -> ProvenanceRecord:
        record = ProvenanceRecord(
            step=step,
            input_hash=input_hash,
            output_hash=output_hash,
            metadata=metadata,
        )
        self.records.append(record)
        return record

    def chain_hash(self) -> str:
        """Hash the entire chain for tamper detection.

        Includes: package identity, environment, and every record.
        """
        h = hashlib.sha256()
        h.update(f"{self.package_name}:{self.package_version}".encode())
        # Environment is part of the hash (prevents metadata swap attacks)
        env_bytes = json.dumps(self.environment.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        h.update(env_bytes)
        for record in self.records:
            h.update(record.canonical_bytes())
        return h.hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "package_version": self.package_version,
            "environment": self.environment.to_dict(),
            "records": [r.to_dict() for r in self.records],
            "chain_hash": self.chain_hash(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> tuple[ProvenanceChain, str]:
        """Deserialize a chain dict. Returns (chain, stored_hash).

        The stored_hash is the chain_hash from the serialized data,
        which can be compared against chain.chain_hash() to detect tampering.
        """
        env = BuildEnvironment(**d["environment"])
        chain = cls(
            package_name=d["package_name"],
            package_version=d["package_version"],
            environment=env,
        )
        for r in d["records"]:
            chain.records.append(ProvenanceRecord(
                step=r["step"],
                input_hash=r["input_hash"],
                output_hash=r["output_hash"],
                timestamp=r["timestamp"],
                metadata=r.get("metadata", {}),
            ))
        stored_hash = d.get("chain_hash", "")
        return chain, stored_hash

    @classmethod
    def from_json(cls, s: str) -> tuple[ProvenanceChain, str]:
        return cls.from_dict(json.loads(s))

    def verify_integrity(self, stored_hash: str) -> bool:
        """Check that recomputed chain hash matches the stored hash.

        The stored_hash comes from the serialized chain data (from_dict/from_json).
        If someone tampered with any record after serialization, the hashes diverge.
        """
        return self.chain_hash() == stored_hash
