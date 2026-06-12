"""Tests for behavioral sandbox."""

import pytest

from sealed.sandbox import BehavioralSandbox, SandboxResult, SandboxBehavior


class TestSandboxResult:
    def test_safe_when_no_behaviors(self):
        r = SandboxResult(package="test", version="1.0")
        assert r.safe

    def test_safe_with_info_only(self):
        r = SandboxResult(package="test", version="1.0", behaviors=[
            SandboxBehavior(type="import_success", severity="info"),
        ])
        assert r.safe

    def test_unsafe_with_critical(self):
        r = SandboxResult(package="test", version="1.0", behaviors=[
            SandboxBehavior(type="network_connect", severity="critical",
                          details={"address": "evil.com:443"}),
        ])
        assert not r.safe

    def test_unsafe_with_high(self):
        r = SandboxResult(package="test", version="1.0", behaviors=[
            SandboxBehavior(type="subprocess", severity="high"),
        ])
        assert not r.safe

    def test_to_dict(self):
        r = SandboxResult(package="pkg", version="2.0", behaviors=[
            SandboxBehavior(type="import_success", severity="info"),
        ])
        d = r.to_dict()
        assert d["package"] == "pkg"
        assert d["safe"] is True
        assert d["critical"] == 0

    def test_digest_deterministic(self):
        r1 = SandboxResult(package="a", version="1.0", behaviors=[
            SandboxBehavior(type="x", severity="info"),
        ])
        r2 = SandboxResult(package="a", version="1.0", behaviors=[
            SandboxBehavior(type="x", severity="info"),
        ])
        assert r1.digest == r2.digest


class TestBehavioralSandbox:
    def test_analyze_safe_package(self):
        """six is a safe, pure Python package with no network/file/process activity."""
        sandbox = BehavioralSandbox(timeout=15)
        result = sandbox.analyze("six", "1.17.0")
        assert result.safe or result.error  # safe, or import error (not installed in sandbox)

    def test_restricted_env(self):
        sandbox = BehavioralSandbox()
        env = sandbox._restricted_env()
        assert "SEALED_SANDBOX" in env
        assert env["SEALED_SANDBOX"] == "1"
        # Secrets should not leak
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "GITHUB_TOKEN" not in env


class TestSandboxBehavior:
    def test_to_dict(self):
        b = SandboxBehavior(
            type="network_connect",
            severity="critical",
            details={"address": "evil.com:443"},
        )
        d = b.to_dict()
        assert d["type"] == "network_connect"
        assert d["address"] == "evil.com:443"
