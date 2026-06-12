"""Tests for environment attestation."""

import pytest

from sealed.attestation import (
    Attestation,
    SoftwareAttestor,
    TPMAttestor,
    create_attestation,
)


class TestSoftwareAttestor:
    def test_produces_attestation(self):
        attestor = SoftwareAttestor()
        att = attestor.attest()
        assert att.method == "software"
        assert "python_binary" in att.measurements
        assert "python_version" in att.measurements
        assert "os_kernel" in att.measurements
        assert "cpu_arch" in att.measurements
        assert "build_env" in att.measurements
        assert "compiler" in att.measurements
        assert att.raw_quote is None

    def test_measurements_are_hex_hashes(self):
        att = SoftwareAttestor().attest()
        for key, value in att.measurements.items():
            assert len(value) == 64, f"{key} is not a sha256 hex string"
            int(value, 16)  # should not raise

    def test_platform_info_populated(self):
        att = SoftwareAttestor().attest()
        assert "python" in att.platform_info
        assert "platform" in att.platform_info
        assert "machine" in att.platform_info

    def test_digest_deterministic(self):
        att = SoftwareAttestor().attest()
        assert att.digest() == att.digest()
        assert len(att.digest()) == 64

    def test_digest_changes_with_measurements(self):
        att = SoftwareAttestor().attest()
        d1 = att.digest()
        att.measurements["extra"] = "abc123" + "0" * 58
        d2 = att.digest()
        assert d1 != d2


class TestAttestation:
    def test_to_dict_roundtrip(self):
        att = Attestation(
            method="software",
            measurements={"a": "b", "c": "d"},
            platform_info={"python": "3.12"},
        )
        d = att.to_dict()
        restored = Attestation.from_dict(d)
        assert restored.method == "software"
        assert restored.measurements == {"a": "b", "c": "d"}

    def test_digest_sorted(self):
        att1 = Attestation(
            method="software",
            measurements={"z": "1", "a": "2"},
            platform_info={},
        )
        att2 = Attestation(
            method="software",
            measurements={"a": "2", "z": "1"},
            platform_info={},
        )
        assert att1.digest() == att2.digest()

    def test_tpm_not_available(self):
        # TPM is almost certainly not available in test env
        assert TPMAttestor.available() is False


class TestCreateAttestation:
    def test_returns_software_by_default(self):
        att = create_attestation()
        assert att.method == "software"
        assert len(att.measurements) >= 5
