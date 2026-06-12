"""Trust policy: rules for accepting or rejecting sealed packages.

Combines key pinning, multi-party requirements, attestation level,
and revocation checks into a single policy engine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.registry import SealRegistry, PinResult, RegistryEntry
from sealed.seal import Seal, SealAuthority, SealError
from sealed.chain import ProvenanceChain


@dataclass
class PolicyConfig:
    """Trust policy configuration."""
    # Minimum number of independent signers required
    min_signatures: int = 1
    # Require specific attestation methods
    require_attestation: list[str] = field(default_factory=lambda: ["software"])
    # Auto-pin keys on first use (TOFU)
    tofu_enabled: bool = True
    # Reject packages with revoked keys
    check_revocations: bool = True
    # Reject on key pin mismatch
    enforce_pins: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "min_signatures": self.min_signatures,
            "require_attestation": self.require_attestation,
            "tofu_enabled": self.tofu_enabled,
            "check_revocations": self.check_revocations,
            "enforce_pins": self.enforce_pins,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PolicyConfig:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> PolicyConfig:
        return cls.from_dict(json.loads(path.read_text()))


@dataclass
class PolicyResult:
    """Result of a policy evaluation."""
    accepted: bool
    package_name: str
    package_version: str
    checks: list[PolicyCheck]

    @property
    def errors(self) -> list[str]:
        return [c.message for c in self.checks if not c.passed]

    @property
    def warnings(self) -> list[str]:
        return [c.message for c in self.checks if c.passed and c.warning]


@dataclass
class PolicyCheck:
    """A single policy check result."""
    name: str
    passed: bool
    message: str
    warning: bool = False


class PolicyEngine:
    """Evaluate trust policies against sealed packages."""

    def __init__(self, config: PolicyConfig, registry: SealRegistry):
        self.config = config
        self.registry = registry

    def evaluate(self, seal: Seal, chain: ProvenanceChain,
                 attestation_method: str = "software") -> PolicyResult:
        """Run all policy checks against a sealed package.

        TOFU key pinning is deferred: the key is only pinned if ALL checks pass.
        This prevents a malicious seal from poisoning the pin database.
        """
        checks: list[PolicyCheck] = []
        pending_tofu_pin = False

        # 1. Signature verification
        checks.append(self._check_signature(seal, chain))

        # 2. Key pin check (TOFU, deferred)
        pin_check, pending_tofu_pin = self._check_key_pin(seal)
        checks.append(pin_check)

        # 3. Revocation check
        if self.config.check_revocations:
            checks.append(self._check_revocation(seal))

        # 4. Attestation level check
        checks.append(self._check_attestation(attestation_method))

        # 5. Multi-party signature check
        checks.append(self._check_multi_party(seal))

        accepted = all(c.passed for c in checks)

        # Only pin the key if ALL checks passed (prevent pin poisoning)
        if accepted and pending_tofu_pin:
            self.registry.pin_key(
                seal.package_name, seal.public_key, pin_type="tofu"
            )

        return PolicyResult(
            accepted=accepted,
            package_name=seal.package_name,
            package_version=seal.package_version,
            checks=checks,
        )

    def _check_signature(self, seal: Seal,
                         chain: ProvenanceChain) -> PolicyCheck:
        try:
            SealAuthority.verify_seal(seal, chain)
            return PolicyCheck("signature", True, "Ed25519 signature valid")
        except SealError as e:
            return PolicyCheck("signature", False, f"Signature failed: {e}")

    def _check_key_pin(self, seal: Seal) -> tuple[PolicyCheck, bool]:
        """Check key pin. Returns (check, pending_tofu_pin).

        pending_tofu_pin is True if this is a first-use key that should be
        pinned ONLY after all other checks pass.
        """
        pin_result = self.registry.check_pin(
            seal.package_name, seal.public_key
        )

        if pin_result.status == "ok":
            return PolicyCheck("key_pin", True, "Key matches pin"), False

        if pin_result.status == "first_use":
            if self.config.tofu_enabled:
                # Don't pin yet, defer until all checks pass
                return PolicyCheck(
                    "key_pin", True,
                    f"First use: will pin key {seal.public_key[:16]}... if all checks pass",
                    warning=True,
                ), True
            return PolicyCheck(
                "key_pin", True,
                "No pin exists, TOFU disabled, accepting",
                warning=True,
            ), False

        if pin_result.status == "mismatch":
            if self.config.enforce_pins:
                return PolicyCheck(
                    "key_pin", False,
                    f"KEY PIN MISMATCH: {pin_result.message}",
                ), False
            return PolicyCheck(
                "key_pin", True,
                f"Key pin mismatch (not enforced): {pin_result.message}",
                warning=True,
            ), False

        if pin_result.status == "revoked":
            return PolicyCheck("key_pin", False, pin_result.message), False

        return PolicyCheck("key_pin", False, f"Unknown pin status: {pin_result.status}"), False

    def _check_revocation(self, seal: Seal) -> PolicyCheck:
        pin_result = self.registry.check_pin(
            seal.package_name, seal.public_key
        )
        if pin_result.status == "revoked":
            return PolicyCheck(
                "revocation", False,
                f"Key {seal.public_key[:16]}... is revoked",
            )
        return PolicyCheck("revocation", True, "Key not revoked")

    def _check_attestation(self, method: str) -> PolicyCheck:
        required = self.config.require_attestation
        if method in required or not required:
            return PolicyCheck(
                "attestation", True,
                f"Attestation method '{method}' is acceptable",
            )
        return PolicyCheck(
            "attestation", False,
            f"Attestation '{method}' not in required: {required}",
        )

    def _check_multi_party(self, seal: Seal) -> PolicyCheck:
        """Check if enough independent signers have sealed this package."""
        if self.config.min_signatures <= 1:
            return PolicyCheck(
                "multi_party", True,
                "Single signature sufficient (min_signatures=1)",
            )

        entries = self.registry.lookup(
            seal.package_name, seal.package_version
        )
        unique_keys = {e.seal.public_key for e in entries}
        # Include current seal
        unique_keys.add(seal.public_key)

        if len(unique_keys) >= self.config.min_signatures:
            return PolicyCheck(
                "multi_party", True,
                f"{len(unique_keys)} signatures meet minimum of {self.config.min_signatures}",
            )
        return PolicyCheck(
            "multi_party", False,
            f"Only {len(unique_keys)} signatures, need {self.config.min_signatures}",
        )
