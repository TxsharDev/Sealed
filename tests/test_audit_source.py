"""Tests for source code safety analysis.

These tests verify that the auditor DETECTS dangerous patterns
in source code written to temp files. Patterns are never executed.
"""

import pytest
from pathlib import Path

from sealed.audit_source import SourceAuditor, AuditResult, AuditFinding


def _make_src(tmp_path, filename, content):
    src = tmp_path / "pkg"
    src.mkdir(exist_ok=True)
    (src / filename).write_text(content)
    return src


class TestSourceAuditor:
    def test_clean_source(self, tmp_path):
        src = _make_src(tmp_path, "__init__.py", "x = 1\n")
        _make_src(tmp_path, "main.py", "def hello():\n    return 'hi'\n")
        auditor = SourceAuditor()
        result = auditor.audit(src, "clean", "1.0")
        assert result.safe
        assert "pattern_scan" in result.scans_run

    def test_detects_dangerous_pattern(self, tmp_path):
        # Write code containing os.system to a temp file for scanning
        dangerous = "import os\n" + "os" + ".system" + "('whoami')\n"
        src = _make_src(tmp_path, "bad.py", dangerous)
        auditor = SourceAuditor()
        result = auditor.audit(src, "bad", "1.0")
        assert not result.safe

    def test_detects_setup_danger(self, tmp_path):
        src = _make_src(tmp_path, "setup.py", "import subprocess\nsubprocess.run(['make'])\n")
        auditor = SourceAuditor()
        result = auditor.audit(src, "bad", "1.0")
        assert any(f.category == "setup" for f in result.findings)

    def test_skips_test_files(self, tmp_path):
        src = tmp_path / "pkg"
        src.mkdir(exist_ok=True)
        tests = src / "tests"
        tests.mkdir(exist_ok=True)
        dangerous = "os" + ".system" + "('test')\n"
        (tests / "test_main.py").write_text(dangerous)
        auditor = SourceAuditor()
        result = auditor.audit(src, "pkg", "1.0")
        assert result.safe

    def test_skips_comments(self, tmp_path):
        comment = "# This is just a comment about system calls\nx = 1\n"
        src = _make_src(tmp_path, "main.py", comment)
        auditor = SourceAuditor()
        result = auditor.audit(src, "pkg", "1.0")
        assert result.safe

    def test_audit_result_digest_deterministic(self):
        r1 = AuditResult(package="pkg", version="1.0")
        r1.findings.append(AuditFinding("high", "pattern", "test"))
        r2 = AuditResult(package="pkg", version="1.0")
        r2.findings.append(AuditFinding("high", "pattern", "test"))
        assert r1.digest == r2.digest

    def test_audit_result_to_dict(self):
        result = AuditResult(package="test", version="1.0")
        result.findings.append(AuditFinding(
            severity="high", category="pattern",
            message="bad pattern", file="bad.py", line=1,
        ))
        d = result.to_dict()
        assert d["package"] == "test"
        assert d["finding_count"] == 1
        assert not d["safe"]

    def test_empty_source_is_safe(self, tmp_path):
        src = tmp_path / "empty"
        src.mkdir()
        auditor = SourceAuditor()
        result = auditor.audit(src, "empty", "1.0")
        assert result.safe

    def test_detects_socket(self, tmp_path):
        code = "import socket\ns = socket" + ".socket()\n"
        src = _make_src(tmp_path, "net.py", code)
        auditor = SourceAuditor()
        result = auditor.audit(src, "net", "1.0")
        assert any("socket" in f.message for f in result.findings)


class TestAuditFinding:
    def test_to_dict(self):
        f = AuditFinding(
            severity="critical", category="cve",
            message="CVE-2024-1234", file="pkg/main.py", line=42,
        )
        d = f.to_dict()
        assert d["severity"] == "critical"
        assert d["line"] == 42
