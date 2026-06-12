"""Transparency log: append-only hash chain for seal operations.

Every seal, revocation, and key pin is recorded in an append-only log.
Each entry includes the hash of the previous entry, forming a hash chain.
If anyone tampers with history, the chain breaks.

Detects equivocation: signing two different binaries for the same
package-version is visible in the log.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class LogEntry:
    """A single entry in the transparency log."""
    sequence: int
    timestamp: float
    action: str          # "seal", "revoke", "pin", "unpin"
    package_name: str
    package_version: str
    chain_hash: str      # hash of the sealed chain (for seal actions)
    public_key: str
    prev_hash: str       # hash of previous log entry (chain link)
    entry_hash: str      # hash of this entry

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "chain_hash": self.chain_hash,
            "public_key": self.public_key,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LogEntry:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class EquivocationAlert:
    """Alert when the same package-version has multiple different chain hashes."""
    package: str
    version: str
    chain_hashes: list[str]
    public_keys: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "chain_hashes": self.chain_hashes,
            "public_keys": self.public_keys,
        }


class TransparencyLog:
    """Append-only hash-chained log of all seal operations."""

    GENESIS_HASH = "0" * 64  # hash of the "previous" entry for the first entry

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or Path.home() / ".sealed" / "transparency.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS log_entries (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                action TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_log_package
                ON log_entries(package_name, package_version);
            CREATE INDEX IF NOT EXISTS idx_log_action
                ON log_entries(action);
        """)
        self._conn.commit()

    def append(self, action: str, package_name: str, package_version: str,
               chain_hash: str, public_key: str) -> LogEntry:
        """Append a new entry to the log. Returns the entry."""
        prev_hash = self._get_last_hash()

        entry_data = {
            "action": action,
            "package_name": package_name,
            "package_version": package_version,
            "chain_hash": chain_hash,
            "public_key": public_key,
            "prev_hash": prev_hash,
            "timestamp": time.time(),
        }

        entry_hash = self._compute_hash(entry_data)

        self._conn.execute(
            """INSERT INTO log_entries
               (timestamp, action, package_name, package_version,
                chain_hash, public_key, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry_data["timestamp"], action, package_name, package_version,
                chain_hash, public_key, prev_hash, entry_hash,
            ),
        )
        self._conn.commit()

        row = self._conn.execute(
            "SELECT sequence FROM log_entries WHERE entry_hash=?",
            (entry_hash,),
        ).fetchone()

        return LogEntry(
            sequence=row[0],
            timestamp=entry_data["timestamp"],
            action=action,
            package_name=package_name,
            package_version=package_version,
            chain_hash=chain_hash,
            public_key=public_key,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the entire log chain. Returns (valid, errors)."""
        errors = []
        rows = self._conn.execute(
            "SELECT sequence, timestamp, action, package_name, package_version, "
            "chain_hash, public_key, prev_hash, entry_hash "
            "FROM log_entries ORDER BY sequence"
        ).fetchall()

        if not rows:
            return True, []

        expected_prev = self.GENESIS_HASH

        for row in rows:
            entry = LogEntry(
                sequence=row[0], timestamp=row[1], action=row[2],
                package_name=row[3], package_version=row[4],
                chain_hash=row[5], public_key=row[6],
                prev_hash=row[7], entry_hash=row[8],
            )

            # Check prev_hash links correctly
            if entry.prev_hash != expected_prev:
                errors.append(
                    f"Entry {entry.sequence}: prev_hash mismatch "
                    f"(expected {expected_prev[:16]}..., got {entry.prev_hash[:16]}...)"
                )

            # Check entry_hash is correct
            entry_data = {
                "action": entry.action,
                "package_name": entry.package_name,
                "package_version": entry.package_version,
                "chain_hash": entry.chain_hash,
                "public_key": entry.public_key,
                "prev_hash": entry.prev_hash,
                "timestamp": entry.timestamp,
            }
            computed = self._compute_hash(entry_data)
            if computed != entry.entry_hash:
                errors.append(
                    f"Entry {entry.sequence}: entry_hash mismatch "
                    f"(expected {computed[:16]}..., got {entry.entry_hash[:16]}...)"
                )

            expected_prev = entry.entry_hash

        return len(errors) == 0, errors

    def detect_equivocation(self) -> list[EquivocationAlert]:
        """Find packages where the same version has multiple different chain hashes."""
        rows = self._conn.execute(
            """SELECT package_name, package_version,
                      GROUP_CONCAT(DISTINCT chain_hash) as hashes,
                      GROUP_CONCAT(DISTINCT public_key) as keys
               FROM log_entries
               WHERE action = 'seal'
               GROUP BY package_name, package_version
               HAVING COUNT(DISTINCT chain_hash) > 1"""
        ).fetchall()

        alerts = []
        for row in rows:
            alerts.append(EquivocationAlert(
                package=row[0],
                version=row[1],
                chain_hashes=row[2].split(","),
                public_keys=row[3].split(","),
            ))
        return alerts

    def get_history(self, package: str | None = None,
                    limit: int = 100) -> list[LogEntry]:
        """Get log entries, optionally filtered by package."""
        if package:
            rows = self._conn.execute(
                "SELECT sequence, timestamp, action, package_name, package_version, "
                "chain_hash, public_key, prev_hash, entry_hash "
                "FROM log_entries WHERE package_name=? "
                "ORDER BY sequence DESC LIMIT ?",
                (package, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT sequence, timestamp, action, package_name, package_version, "
                "chain_hash, public_key, prev_hash, entry_hash "
                "FROM log_entries ORDER BY sequence DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [
            LogEntry(
                sequence=r[0], timestamp=r[1], action=r[2],
                package_name=r[3], package_version=r[4],
                chain_hash=r[5], public_key=r[6],
                prev_hash=r[7], entry_hash=r[8],
            )
            for r in rows
        ]

    def export_log(self) -> str:
        """Export the full log as JSON."""
        entries = self.get_history(limit=999999)
        entries.reverse()  # chronological order
        return json.dumps({
            "version": 1,
            "entries": [e.to_dict() for e in entries],
        }, indent=2)

    def size(self) -> int:
        """Number of entries in the log."""
        row = self._conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()
        return row[0]

    def _get_last_hash(self) -> str:
        """Get the hash of the most recent entry, or genesis hash."""
        row = self._conn.execute(
            "SELECT entry_hash FROM log_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else self.GENESIS_HASH

    def _compute_hash(self, entry_data: dict) -> str:
        """Compute the hash of a log entry."""
        canonical = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
