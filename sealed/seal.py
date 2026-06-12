"""Seal: Ed25519 signatures over the provenance chain."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

from sealed.chain import ProvenanceChain


class SealError(Exception):
    pass


@dataclass
class Seal:
    """A cryptographic seal over a provenance chain."""
    chain_hash: str
    signature: str        # hex-encoded Ed25519 signature
    public_key: str       # hex-encoded public key
    timestamp: float
    package_name: str
    package_version: str

    def to_dict(self) -> dict:
        return {
            "chain_hash": self.chain_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "timestamp": self.timestamp,
            "package_name": self.package_name,
            "package_version": self.package_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    _fields = {"chain_hash", "signature", "public_key", "timestamp", "package_name", "package_version"}

    @classmethod
    def from_dict(cls, d: dict) -> Seal:
        filtered = {k: v for k, v in d.items() if k in cls._fields}
        return cls(**filtered)

    @classmethod
    def from_json(cls, s: str) -> Seal:
        return cls.from_dict(json.loads(s))

    def save(self, path: Path) -> None:
        path.write_text(self.to_json())

    @classmethod
    def load(cls, path: Path) -> Seal:
        return cls.from_json(path.read_text())


class SealAuthority:
    """Signs and verifies provenance chains with Ed25519."""

    def __init__(self, signing_key: SigningKey | None = None):
        self._signing_key = signing_key or SigningKey.generate()

    @property
    def public_key(self) -> str:
        return self._signing_key.verify_key.encode(HexEncoder).decode()

    @property
    def private_key_hex(self) -> str:
        return self._signing_key.encode(HexEncoder).decode()

    @classmethod
    def from_key_file(cls, path: Path) -> SealAuthority:
        key_hex = path.read_text().strip()
        signing_key = SigningKey(key_hex.encode(), encoder=HexEncoder)
        return cls(signing_key)

    def save_key(self, path: Path) -> None:
        path.write_text(self.private_key_hex)

    def seal(self, chain: ProvenanceChain) -> Seal:
        """Sign the provenance chain, producing a seal."""
        chain_hash = chain.chain_hash()
        message = chain_hash.encode()
        signed = self._signing_key.sign(message, encoder=HexEncoder)

        return Seal(
            chain_hash=chain_hash,
            signature=signed.signature.decode(),
            public_key=self.public_key,
            timestamp=time.time(),
            package_name=chain.package_name,
            package_version=chain.package_version,
        )

    @staticmethod
    def verify_seal(seal: Seal, chain: ProvenanceChain) -> bool:
        """Verify a seal against a provenance chain.

        Returns True if valid, raises SealError if tampered.
        """
        # Check chain hash matches
        computed_hash = chain.chain_hash()
        if computed_hash != seal.chain_hash:
            raise SealError(
                f"Chain hash mismatch: seal says {seal.chain_hash}, "
                f"chain computes {computed_hash}"
            )

        # Verify Ed25519 signature
        verify_key = VerifyKey(seal.public_key.encode(), encoder=HexEncoder)
        try:
            verify_key.verify(
                seal.chain_hash.encode(),
                bytes.fromhex(seal.signature),
            )
        except (BadSignatureError, ValueError, TypeError) as e:
            raise SealError(f"Signature verification failed: {e}") from e

        return True
