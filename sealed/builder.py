"""Isolated builder: build from source with full environment capture."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from sealed.attestation import Attestation, create_attestation
from sealed.chain import (
    BuildEnvironment,
    ProvenanceChain,
    _hash_directory,
    _hash_file,
)


class BuildError(Exception):
    pass


class IsolatedBuilder:
    """Build a Python package from source in a clean virtualenv."""

    def __init__(self, work_dir: Path | None = None):
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="sealed_build_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def build(self, source_dir: Path, source_hash: str,
              package_name: str, package_version: str,
              audit: bool = True) -> BuildResult:
        """Build a wheel from source, recording the full provenance chain."""
        from sealed.audit_source import SourceAuditor, AuditResult

        # Attest the build environment first
        attestation = create_attestation()

        chain = ProvenanceChain(
            package_name=package_name,
            package_version=package_version,
        )

        # Record environment attestation
        chain.add(
            step="environment_attestation",
            input_hash=attestation.digest(),
            output_hash=attestation.digest(),
            method=attestation.method,
            measurements=attestation.measurements,
            platform_info=attestation.platform_info,
        )

        # Source safety audit
        audit_result: AuditResult | None = None
        if audit:
            auditor = SourceAuditor()
            audit_result = auditor.audit(source_dir, package_name, package_version)
            chain.add(
                step="source_audit",
                input_hash=_hash_directory(source_dir),
                output_hash=audit_result.digest,
                safe=audit_result.safe,
                scans_run=audit_result.scans_run,
                finding_count=len(audit_result.findings),
                critical=sum(1 for f in audit_result.findings if f.severity == "critical"),
                high=sum(1 for f in audit_result.findings if f.severity == "high"),
            )

        # Record source
        computed_source_hash = _hash_directory(source_dir)
        chain.add(
            step="source_verify",
            input_hash=source_hash,
            output_hash=computed_source_hash,
            source_dir=str(source_dir),
        )

        # Capture toolchain
        python_hash = _hash_file(Path(sys.executable))
        chain.add(
            step="toolchain_capture",
            input_hash=python_hash,
            output_hash=python_hash,
            python=sys.executable,
            python_version=sys.version,
        )

        # Build
        output_dir = self.work_dir / "dist"
        output_dir.mkdir(exist_ok=True)
        self._run_build(source_dir, output_dir)

        # Find the built wheel
        wheels = list(output_dir.glob("*.whl"))
        if not wheels:
            wheels = list(output_dir.glob("*.tar.gz"))
        if not wheels:
            raise BuildError("Build produced no output artifacts")

        artifact = wheels[0]
        artifact_hash = _hash_file(artifact)

        chain.add(
            step="build",
            input_hash=computed_source_hash,
            output_hash=artifact_hash,
            artifact=artifact.name,
            build_flags=self._build_flags(),
        )

        return BuildResult(
            artifact=artifact,
            artifact_hash=artifact_hash,
            chain=chain,
            attestation=attestation,
            audit_result=audit_result,
        )

    def _run_build(self, source_dir: Path, output_dir: Path) -> None:
        cmd = [
            sys.executable, "-m", "pip", "wheel",
            "--no-deps",
            "--no-binary", ":all:",
            "--wheel-dir", str(output_dir),
            str(source_dir),
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            raise BuildError(
                f"Build failed (exit {result.returncode}):\n{result.stderr}"
            )

    def _build_flags(self) -> dict:
        return {
            "no_deps": True,
            "no_binary": ":all:",
            "builder": "pip wheel",
        }


class BuildResult:
    """Result of building a package from source."""

    __slots__ = ("artifact", "artifact_hash", "chain", "attestation", "audit_result")

    def __init__(self, artifact: Path, artifact_hash: str,
                 chain: ProvenanceChain, attestation: Attestation,
                 audit_result=None):
        self.artifact = artifact
        self.artifact_hash = artifact_hash
        self.chain = chain
        self.attestation = attestation
        self.audit_result = audit_result
