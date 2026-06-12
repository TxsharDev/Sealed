"""Shared seal registry: SQLite-backed store for seals and chains.

Supports export/import for team sharing, querying by package/version/key,
and trust-on-first-use (TOFU) key pinning.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from sealed.chain import ProvenanceChain
from sealed.seal import Seal


DEFAULT_DB_PATH = Path.home() / ".sealed" / "registry.db"


class SealRegistry:
    """SQLite-backed registry of seals, chains, and key pins."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS seals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                public_key TEXT NOT NULL,
                seal_json TEXT NOT NULL,
                chain_json TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                attestation_method TEXT DEFAULT 'software',
                created_at REAL NOT NULL,
                UNIQUE(package_name, package_version, public_key)
            );

            CREATE TABLE IF NOT EXISTS key_pins (
                package_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                pinned_at REAL NOT NULL,
                pin_type TEXT NOT NULL DEFAULT 'tofu',
                note TEXT DEFAULT '',
                PRIMARY KEY(package_name, public_key)
            );

            CREATE TABLE IF NOT EXISTS key_revocations (
                public_key TEXT PRIMARY KEY,
                revoked_at REAL NOT NULL,
                reason TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_seals_package
                ON seals(package_name, package_version);
            CREATE INDEX IF NOT EXISTS idx_seals_key
                ON seals(public_key);
        """)
        self._conn.commit()

    def store(self, seal: Seal, chain: ProvenanceChain,
              attestation_method: str = "software") -> None:
        """Store a seal and its chain in the registry."""
        self._conn.execute(
            """INSERT OR REPLACE INTO seals
               (package_name, package_version, public_key,
                seal_json, chain_json, chain_hash,
                attestation_method, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                seal.package_name,
                seal.package_version,
                seal.public_key,
                seal.to_json(),
                chain.to_json(),
                seal.chain_hash,
                attestation_method,
                time.time(),
            ),
        )
        self._conn.commit()

    def lookup(self, package: str,
               version: str | None = None) -> list[RegistryEntry]:
        """Find seals for a package."""
        if version:
            rows = self._conn.execute(
                "SELECT seal_json, chain_json, attestation_method, created_at "
                "FROM seals WHERE package_name=? AND package_version=?",
                (package, version),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT seal_json, chain_json, attestation_method, created_at "
                "FROM seals WHERE package_name=? ORDER BY created_at DESC",
                (package,),
            ).fetchall()

        return [
            RegistryEntry(
                seal=Seal.from_json(row[0]),
                chain=ProvenanceChain.from_json(row[1])[0],
                attestation_method=row[2],
                created_at=row[3],
            )
            for row in rows
        ]

    def list_packages(self) -> list[dict[str, Any]]:
        """List all packages in the registry."""
        rows = self._conn.execute(
            """SELECT package_name, package_version, public_key,
                      attestation_method, created_at
               FROM seals ORDER BY package_name, package_version"""
        ).fetchall()
        return [
            {
                "package": row[0],
                "version": row[1],
                "public_key": row[2][:16] + "...",
                "attestation": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    # == Key pinning (TOFU) ---

    def pin_key(self, package: str, public_key: str,
                pin_type: str = "tofu", note: str = "") -> None:
        """Pin a public key to a package (trust-on-first-use)."""
        self._conn.execute(
            """INSERT OR REPLACE INTO key_pins
               (package_name, public_key, pinned_at, pin_type, note)
               VALUES (?, ?, ?, ?, ?)""",
            (package, public_key, time.time(), pin_type, note),
        )
        self._conn.commit()

    def check_pin(self, package: str, public_key: str) -> PinResult:
        """Check if a key matches the pinned key for a package.

        Returns PinResult with status:
        - "ok": key matches pin
        - "first_use": no pin exists, should pin this key
        - "mismatch": key doesn't match existing pin (danger!)
        - "revoked": key has been revoked
        """
        # Check revocation first
        revoked = self._conn.execute(
            "SELECT reason FROM key_revocations WHERE public_key=?",
            (public_key,),
        ).fetchone()
        if revoked:
            return PinResult("revoked", f"Key revoked: {revoked[0]}")

        pins = self._conn.execute(
            "SELECT public_key FROM key_pins WHERE package_name=?",
            (package,),
        ).fetchall()

        if not pins:
            return PinResult("first_use", "No key pinned for this package")

        pinned_keys = {row[0] for row in pins}
        if public_key in pinned_keys:
            return PinResult("ok", "Key matches pin")

        return PinResult(
            "mismatch",
            f"Key {public_key[:16]}... not in pinned keys for {package}. "
            f"Pinned: {', '.join(k[:16] + '...' for k in pinned_keys)}"
        )

    def revoke_key(self, public_key: str, reason: str = "") -> None:
        """Revoke a key. All future verifications against it will fail."""
        self._conn.execute(
            "INSERT OR REPLACE INTO key_revocations (public_key, revoked_at, reason) "
            "VALUES (?, ?, ?)",
            (public_key, time.time(), reason),
        )
        self._conn.commit()

    def get_pins(self, package: str) -> list[dict[str, Any]]:
        """Get all pinned keys for a package."""
        rows = self._conn.execute(
            "SELECT public_key, pinned_at, pin_type, note "
            "FROM key_pins WHERE package_name=?",
            (package,),
        ).fetchall()
        return [
            {
                "public_key": row[0],
                "pinned_at": row[1],
                "pin_type": row[2],
                "note": row[3],
            }
            for row in rows
        ]

    # == Export/Import for team sharing ---

    def export_seals(self, packages: list[str] | None = None) -> str:
        """Export seals as JSON for sharing with a team."""
        if packages:
            placeholders = ",".join("?" * len(packages))
            rows = self._conn.execute(
                f"SELECT seal_json, chain_json, attestation_method "
                f"FROM seals WHERE package_name IN ({placeholders})",
                packages,
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT seal_json, chain_json, attestation_method FROM seals"
            ).fetchall()

        entries = [
            {
                "seal": json.loads(row[0]),
                "chain": json.loads(row[1]),
                "attestation_method": row[2],
            }
            for row in rows
        ]
        return json.dumps({"version": 1, "entries": entries}, indent=2)

    def import_seals(self, data: str, verify: bool = True) -> int:
        """Import seals from JSON. Verifies signatures before storing.

        Returns count of successfully imported entries.
        """
        from sealed.seal import SealAuthority, SealError

        parsed = json.loads(data)
        count = 0
        for entry in parsed["entries"]:
            seal = Seal.from_dict(entry["seal"])
            chain, _ = ProvenanceChain.from_dict(entry["chain"])
            if verify:
                try:
                    SealAuthority.verify_seal(seal, chain)
                except SealError:
                    continue  # Skip seals with invalid signatures
            self.store(seal, chain, entry.get("attestation_method", "software"))
            count += 1
        return count

    def export_pins(self) -> str:
        """Export key pins as JSON."""
        rows = self._conn.execute(
            "SELECT package_name, public_key, pinned_at, pin_type, note "
            "FROM key_pins"
        ).fetchall()
        pins = [
            {
                "package": row[0],
                "public_key": row[1],
                "pinned_at": row[2],
                "pin_type": row[3],
                "note": row[4],
            }
            for row in rows
        ]
        return json.dumps({"version": 1, "pins": pins}, indent=2)

    def import_pins(self, data: str) -> int:
        """Import key pins from JSON. Returns count."""
        parsed = json.loads(data)
        count = 0
        for pin in parsed["pins"]:
            self.pin_key(
                pin["package"], pin["public_key"],
                pin.get("pin_type", "imported"), pin.get("note", ""),
            )
            count += 1
        return count

    def close(self) -> None:
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class RegistryEntry:
    """A seal+chain pair from the registry."""
    __slots__ = ("seal", "chain", "attestation_method", "created_at")

    def __init__(self, seal: Seal, chain: ProvenanceChain,
                 attestation_method: str, created_at: float):
        self.seal = seal
        self.chain = chain
        self.attestation_method = attestation_method
        self.created_at = created_at


class PinResult:
    """Result of checking a key pin."""
    __slots__ = ("status", "message")

    def __init__(self, status: str, message: str):
        self.status = status
        self.message = message

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "first_use")

    @property
    def is_first_use(self) -> bool:
        return self.status == "first_use"
