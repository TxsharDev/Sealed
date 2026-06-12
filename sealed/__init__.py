"""Sealed: Cryptographic supply chain attestation."""

__version__ = "0.1.0"

from sealed.chain import ProvenanceChain, ProvenanceRecord
from sealed.seal import SealAuthority, Seal
from sealed.source import SourceFetcher
from sealed.builder import IsolatedBuilder
from sealed.verify import SealVerifier
from sealed.attestation import Attestation, SoftwareAttestor, TPMAttestor, create_attestation
from sealed.registry import SealRegistry, PinResult
from sealed.resolver import DependencyResolver
from sealed.policy import PolicyEngine, PolicyConfig
from sealed.audit_source import SourceAuditor, AuditResult
from sealed.keystore import Keystore
from sealed.reproduce import ReproducibilityChecker
from sealed.sandbox import BehavioralSandbox, SandboxResult
from sealed.consensus import ConsensusBuilder, ConsensusResult
from sealed.watchdog import IntegrityWatchdog
from sealed.trust_graph import TrustGraphBuilder, TrustGraph
from sealed.transparency import TransparencyLog
from sealed.ecosystem import get_adapter, PipAdapter, NpmAdapter, CargoAdapter
from sealed.os_keychain import OSKeychain
from sealed.lockfile import Lockfile, LockEntry

__all__ = [
    "ProvenanceChain", "ProvenanceRecord",
    "SealAuthority", "Seal",
    "SourceFetcher", "IsolatedBuilder", "SealVerifier",
    "Attestation", "SoftwareAttestor", "TPMAttestor", "create_attestation",
    "SealRegistry", "PinResult",
    "DependencyResolver",
    "PolicyEngine", "PolicyConfig",
    "SourceAuditor", "AuditResult",
    "Keystore",
    "ReproducibilityChecker",
    "BehavioralSandbox", "SandboxResult",
    "ConsensusBuilder", "ConsensusResult",
    "IntegrityWatchdog",
    "TrustGraphBuilder", "TrustGraph",
    "TransparencyLog",
    "get_adapter", "PipAdapter", "NpmAdapter", "CargoAdapter",
    "OSKeychain",
]
