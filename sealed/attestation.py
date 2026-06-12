"""Platform attestation: prove the build environment's state.

Software attestation is always available. TPM attestation activates
when tpm2-tools is installed and a TPM is accessible.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from sealed.chain import _hash_file as _chain_hash_file


@dataclass
class Attestation:
    """A cryptographic measurement of the build environment."""
    method: str                  # "software" or "tpm2"
    measurements: dict[str, str] # named hashes of measured components
    platform_info: dict[str, str]
    raw_quote: str | None = None # TPM quote bytes (hex), None for software

    def digest(self) -> str:
        """Single hash over all measurements, sorted for determinism."""
        h = hashlib.sha256()
        for key in sorted(self.measurements):
            h.update(f"{key}={self.measurements[key]}".encode())
        return h.hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Attestation:
        return cls(**d)


class SoftwareAttestor:
    """Measure the build environment using software hashes.

    Captures: Python binary, pip version, OS kernel, CPU features,
    environment variables that affect builds, installed compilers.
    """

    def attest(self) -> Attestation:
        measurements = {}
        platform_info = {}

        # Python binary hash
        python_path = Path(sys.executable).resolve()
        measurements["python_binary"] = self._hash_file(python_path)

        # Python version (exact)
        measurements["python_version"] = hashlib.sha256(
            sys.version.encode()
        ).hexdigest()

        # pip version
        pip_version = self._get_pip_version()
        if pip_version:
            measurements["pip_version"] = hashlib.sha256(
                pip_version.encode()
            ).hexdigest()

        # OS kernel
        measurements["os_kernel"] = hashlib.sha256(
            platform.platform().encode()
        ).hexdigest()

        # CPU architecture
        measurements["cpu_arch"] = hashlib.sha256(
            platform.machine().encode()
        ).hexdigest()

        # Build-affecting env vars
        build_vars = {}
        for var in sorted([
            "CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS",
            "ARCHFLAGS", "MACOSX_DEPLOYMENT_TARGET",
            "PKG_CONFIG_PATH", "CMAKE_PREFIX_PATH",
        ]):
            val = os.environ.get(var)
            if val:
                build_vars[var] = val
        measurements["build_env"] = hashlib.sha256(
            json.dumps(build_vars, sort_keys=True).encode()
        ).hexdigest()

        # Compiler presence and version
        compiler_info = self._get_compiler_info()
        measurements["compiler"] = hashlib.sha256(
            json.dumps(compiler_info, sort_keys=True).encode()
        ).hexdigest()

        # Platform info (not hashed, informational)
        platform_info["python"] = sys.version
        platform_info["platform"] = platform.platform()
        platform_info["machine"] = platform.machine()
        platform_info["hostname"] = platform.node()
        platform_info["pip"] = pip_version or "unknown"

        return Attestation(
            method="software",
            measurements=measurements,
            platform_info=platform_info,
        )

    def _hash_file(self, path: Path) -> str:
        try:
            return _chain_hash_file(path)
        except (OSError, PermissionError):
            return hashlib.sha256(f"unreadable:{path}".encode()).hexdigest()

    def _get_pip_version(self) -> str | None:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip().split()[1]
        except Exception:
            pass
        return None

    def _get_compiler_info(self) -> dict[str, str]:
        info = {}
        for compiler in ["gcc", "g++", "clang", "clang++", "cl", "cc"]:
            path = shutil.which(compiler)
            if path:
                try:
                    result = subprocess.run(
                        [path, "--version"],
                        capture_output=True, text=True, timeout=5,
                    )
                    if result.returncode == 0:
                        info[compiler] = result.stdout.split("\n")[0]
                except Exception:
                    info[compiler] = f"found at {path}"
        return info


class TPMAttestor:
    """Measure the build environment using TPM 2.0 hardware.

    Requires tpm2-tools installed and accessible TPM device.
    Uses PCR values to prove the machine's boot state and
    extends a custom PCR with the build environment hash.
    """

    PCR_BUILD = 23  # PCR index for build measurements

    @staticmethod
    def available() -> bool:
        """Check if TPM attestation is possible on this system."""
        if not shutil.which("tpm2_pcrread"):
            return False
        try:
            result = subprocess.run(
                ["tpm2_pcrread", "sha256:0"],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def attest(self, software_attestation: Attestation) -> Attestation:
        """Extend TPM PCR with build measurements and get a quote.

        Takes a software attestation as input and binds it to hardware.
        """
        measurements = dict(software_attestation.measurements)
        platform_info = dict(software_attestation.platform_info)

        # Read boot PCRs (0-7: firmware, bootloader, kernel)
        pcr_values = self._read_pcrs([0, 1, 2, 3, 4, 5, 6, 7])
        for pcr_idx, pcr_val in pcr_values.items():
            measurements[f"tpm_pcr_{pcr_idx}"] = pcr_val

        # Extend PCR 23 with our build environment digest
        build_digest = software_attestation.digest()
        self._extend_pcr(self.PCR_BUILD, bytes.fromhex(build_digest))

        # Get a TPM quote over all measured PCRs
        pcr_list = list(pcr_values.keys()) + [self.PCR_BUILD]
        raw_quote = self._get_quote(pcr_list)

        measurements["tpm_build_pcr"] = build_digest
        platform_info["tpm"] = "tpm2"

        return Attestation(
            method="tpm2",
            measurements=measurements,
            platform_info=platform_info,
            raw_quote=raw_quote,
        )

    def _read_pcrs(self, indices: list[int]) -> dict[int, str]:
        """Read PCR values from the TPM."""
        pcr_spec = ",".join(str(i) for i in indices)
        result = subprocess.run(
            ["tpm2_pcrread", f"sha256:{pcr_spec}"],
            capture_output=True, text=True, timeout=10,
        )
        values = {}
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if ":" in line and "0x" in line:
                    parts = line.split(":")
                    idx = int(parts[0].strip())
                    val = parts[1].strip().replace("0x", "")
                    values[idx] = val
        return values

    def _extend_pcr(self, index: int, data: bytes) -> None:
        """Extend a PCR with data."""
        hex_data = data.hex()
        subprocess.run(
            ["tpm2_pcrextend", f"{index}:sha256={hex_data}"],
            capture_output=True, timeout=10, check=True,
        )

    def _get_quote(self, pcr_indices: list[int]) -> str:
        """Get a TPM quote over specified PCRs."""
        import tempfile
        pcr_spec = ",".join(str(i) for i in pcr_indices)
        with tempfile.NamedTemporaryFile(suffix=".quote", delete=False) as f:
            quote_path = f.name
        try:
            subprocess.run(
                [
                    "tpm2_quote",
                    "-c", "0x81000001",  # attestation key handle
                    "-l", f"sha256:{pcr_spec}",
                    "-m", quote_path,
                ],
                capture_output=True, timeout=10, check=True,
            )
            return Path(quote_path).read_bytes().hex()
        except Exception:
            return ""
        finally:
            Path(quote_path).unlink(missing_ok=True)


def create_attestation() -> Attestation:
    """Create the best available attestation for the current environment.

    Uses TPM if available, falls back to software attestation.
    """
    software = SoftwareAttestor().attest()

    if TPMAttestor.available():
        try:
            return TPMAttestor().attest(software)
        except Exception:
            pass  # Fall back to software

    return software
