"""Verifier: check a sealed artifact end-to-end."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sealed.chain import ProvenanceChain, _hash_file
from sealed.seal import Seal, SealAuthority, SealError


@dataclass
class VerifyResult:
    """Result of verifying a sealed artifact."""
    valid: bool
    package_name: str
    package_version: str
    chain_length: int
    errors: list[str]

    @property
    def ok(self) -> bool:
        return self.valid and len(self.errors) == 0


class SealVerifier:
    """Verify sealed artifacts: signature, chain integrity, artifact hash."""

    def __init__(self, trusted_keys: list[str] | None = None):
        self.trusted_keys = set(trusted_keys or [])

    def add_trusted_key(self, public_key_hex: str) -> None:
        self.trusted_keys.add(public_key_hex)

    def verify(self, seal_path: Path, artifact_path: Path | None = None,
               chain_path: Path | None = None) -> VerifyResult:
        """Full verification of a sealed artifact."""
        errors: list[str] = []

        # Load seal
        try:
            seal = Seal.load(seal_path)
        except Exception as e:
            return VerifyResult(
                valid=False, package_name="?", package_version="?",
                chain_length=0, errors=[f"Cannot load seal: {e}"],
            )

        # Load chain
        if chain_path is None:
            chain_path = seal_path.with_suffix(".chain.json")
        try:
            chain, stored_hash = ProvenanceChain.from_json(chain_path.read_text())
        except Exception as e:
            return VerifyResult(
                valid=False, package_name=seal.package_name,
                package_version=seal.package_version,
                chain_length=0, errors=[f"Cannot load chain: {e}"],
            )

        # 1. Verify chain integrity (stored hash vs recomputed)
        if not chain.verify_integrity(stored_hash):
            errors.append("Chain integrity check failed: stored hash doesn't match recomputed hash")

        # 2. Verify seal signature over chain
        try:
            SealAuthority.verify_seal(seal, chain)
        except SealError as e:
            errors.append(f"Seal verification failed: {e}")

        # 3. Check trusted keys (if configured)
        if self.trusted_keys and seal.public_key not in self.trusted_keys:
            errors.append(
                f"Signing key {seal.public_key[:16]}... not in trusted keys"
            )

        # 4. Verify artifact hash (if artifact provided)
        if artifact_path is not None:
            build_records = [r for r in chain.records if r.step == "build"]
            if build_records:
                expected_hash = build_records[-1].output_hash
                actual_hash = _hash_file(artifact_path)
                if actual_hash != expected_hash:
                    errors.append(
                        f"Artifact hash mismatch: expected {expected_hash[:16]}..., "
                        f"got {actual_hash[:16]}..."
                    )
            else:
                errors.append("No build record in chain")

        # 5. Verify chain links (build input should match source output)
        for record in chain.records:
            if record.step == "build":
                source_records = [
                    r for r in chain.records if r.step == "source_verify"
                ]
                if source_records:
                    source_hash = source_records[-1].output_hash
                    if record.input_hash != source_hash:
                        errors.append(
                            "Build input hash doesn't match source hash"
                        )

        return VerifyResult(
            valid=len(errors) == 0,
            package_name=seal.package_name,
            package_version=seal.package_version,
            chain_length=len(chain.records),
            errors=errors,
        )

    def verify_json(self, seal_json: str, chain_json: str) -> VerifyResult:
        """Verify from raw JSON strings (no file I/O)."""
        errors: list[str] = []

        try:
            seal = Seal.from_json(seal_json)
        except Exception as e:
            return VerifyResult(
                valid=False, package_name="?", package_version="?",
                chain_length=0, errors=[f"Invalid seal JSON: {e}"],
            )

        try:
            chain, stored_hash = ProvenanceChain.from_json(chain_json)
        except Exception as e:
            return VerifyResult(
                valid=False, package_name=seal.package_name,
                package_version=seal.package_version,
                chain_length=0, errors=[f"Invalid chain JSON: {e}"],
            )

        if not chain.verify_integrity(stored_hash):
            errors.append("Chain integrity check failed")

        try:
            SealAuthority.verify_seal(seal, chain)
        except SealError as e:
            errors.append(str(e))

        if self.trusted_keys and seal.public_key not in self.trusted_keys:
            errors.append("Untrusted signing key")

        return VerifyResult(
            valid=len(errors) == 0,
            package_name=seal.package_name,
            package_version=seal.package_version,
            chain_length=len(chain.records),
            errors=errors,
        )
