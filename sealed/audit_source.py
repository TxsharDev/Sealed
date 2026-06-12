"""Source code safety analysis: scan for known vulnerabilities and dangerous patterns.

Runs before building. If the source fails safety checks, the build is blocked.
Not a full code audit, but catches known CVEs and obvious red flags.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sealed.chain import _hash_bytes


@dataclass
class AuditFinding:
    """A single finding from source analysis."""
    severity: str       # "critical", "high", "medium", "low", "info"
    category: str       # "cve", "pattern", "dependency"
    message: str
    file: str = ""
    line: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class AuditResult:
    """Result of source code analysis."""
    package: str
    version: str
    findings: list[AuditFinding] = field(default_factory=list)
    scans_run: list[str] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        """No critical or high severity findings."""
        return not any(
            f.severity in ("critical", "high") for f in self.findings
        )

    @property
    def digest(self) -> str:
        """Hash of all findings for chain recording."""
        data = json.dumps(
            [f.to_dict() for f in self.findings],
            sort_keys=True, separators=(",", ":"),
        )
        return _hash_bytes(data.encode())

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "safe": self.safe,
            "scans_run": self.scans_run,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
        }


class SourceAuditor:
    """Scan source code for known vulnerabilities and dangerous patterns."""

    # Patterns that indicate potentially dangerous code
    DANGEROUS_PATTERNS = [
        (r'\beval\s*\(', "eval() call", "high"),
        (r'\bexec\s*\(', "exec() call", "high"),
        (r'\b__import__\s*\(', "dynamic __import__() call", "medium"),
        (r'\bos\.system\s*\(', "os.system() call (shell injection risk)", "high"),
        (r'\bsubprocess\.call\s*\(.*shell\s*=\s*True', "subprocess with shell=True", "high"),
        (r'\bpickle\.loads?\s*\(', "pickle deserialization (arbitrary code execution)", "high"),
        (r'\byaml\.load\s*\((?!.*Loader)', "yaml.load without safe Loader", "medium"),
        (r'\bsocket\.socket\s*\(', "raw socket creation", "low"),
    ]

    # Setup.py patterns that run code at install time
    SETUP_PATTERNS = [
        (r'\bos\.system\s*\(', "os.system in setup.py (runs at install time)", "critical"),
        (r'\bsubprocess\b', "subprocess in setup.py (runs at install time)", "high"),
        (r'\burllib\b', "network access in setup.py (runs at install time)", "high"),
        (r'\brequests\b', "HTTP library in setup.py (runs at install time)", "high"),
    ]

    def audit(self, source_dir: Path, package: str, version: str) -> AuditResult:
        """Run all available scans on the source directory."""
        result = AuditResult(package=package, version=version)

        # 1. Pattern scan (always available)
        self._scan_patterns(source_dir, result)
        result.scans_run.append("pattern_scan")

        # 2. Setup.py analysis
        self._scan_setup(source_dir, result)
        result.scans_run.append("setup_scan")

        # 3. Known CVE check via pip-audit (if installed)
        if self._has_pip_audit():
            self._scan_cves(package, version, result)
            result.scans_run.append("cve_scan")

        return result

    def _scan_patterns(self, source_dir: Path, result: AuditResult) -> None:
        """Scan Python files for dangerous patterns."""
        for py_file in source_dir.rglob("*.py"):
            # Skip test files
            rel = py_file.relative_to(source_dir).as_posix()
            if "test" in rel.lower() or "example" in rel.lower():
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for pattern, message, severity in self.DANGEROUS_PATTERNS:
                    if re.search(pattern, line):
                        result.findings.append(AuditFinding(
                            severity=severity,
                            category="pattern",
                            message=message,
                            file=rel,
                            line=i,
                        ))

    def _scan_setup(self, source_dir: Path, result: AuditResult) -> None:
        """Scan setup.py for install-time code execution."""
        setup_files = [
            source_dir / "setup.py",
            source_dir / "setup.cfg",
        ]
        for setup_file in setup_files:
            if not setup_file.exists():
                continue
            try:
                content = setup_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = setup_file.name
            for i, line in enumerate(content.split("\n"), 1):
                for pattern, message, severity in self.SETUP_PATTERNS:
                    if re.search(pattern, line):
                        result.findings.append(AuditFinding(
                            severity=severity,
                            category="setup",
                            message=message,
                            file=rel,
                            line=i,
                        ))

    def _has_pip_audit(self) -> bool:
        """Check if pip-audit is installed."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--version"],
                capture_output=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _scan_cves(self, package: str, version: str,
                   result: AuditResult) -> None:
        """Check for known CVEs using pip-audit."""
        try:
            proc = subprocess.run(
                [
                    sys.executable, "-m", "pip_audit",
                    "--desc",
                    "--format", "json",
                ],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                for vuln in data.get("dependencies", []):
                    if vuln.get("name", "").lower() == package.lower():
                        for v in vuln.get("vulns", []):
                            result.findings.append(AuditFinding(
                                severity="critical",
                                category="cve",
                                message=f"{v.get('id', '?')}: {v.get('description', '')[:200]}",
                            ))
        except Exception:
            pass
