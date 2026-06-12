"""OS keychain integration: store keys in platform-native secure storage.

Windows: DPAPI (Data Protection API)
macOS: Keychain via security CLI
Linux: libsecret via secret-tool CLI
Fallback: encrypted file via keystore.py
"""

from __future__ import annotations

import platform
import subprocess
import sys
from pathlib import Path

from nacl.signing import SigningKey
from nacl.encoding import HexEncoder


class KeychainError(Exception):
    pass


SERVICE_NAME = "sealed"
ACCOUNT_NAME = "signing_key"


class OSKeychain:
    """Platform-native keychain access."""

    @staticmethod
    def available() -> bool:
        """Check if OS keychain is usable on this platform."""
        system = platform.system()
        if system == "Darwin":
            return _macos_available()
        elif system == "Windows":
            return _windows_available()
        elif system == "Linux":
            return _linux_available()
        return False

    @staticmethod
    def store(key: SigningKey) -> None:
        """Store a signing key in the OS keychain."""
        key_hex = key.encode(HexEncoder).decode()
        system = platform.system()

        if system == "Darwin":
            _macos_store(key_hex)
        elif system == "Windows":
            _windows_store(key_hex)
        elif system == "Linux":
            _linux_store(key_hex)
        else:
            raise KeychainError(f"Unsupported platform: {system}")

    @staticmethod
    def load() -> SigningKey:
        """Load a signing key from the OS keychain."""
        system = platform.system()

        if system == "Darwin":
            key_hex = _macos_load()
        elif system == "Windows":
            key_hex = _windows_load()
        elif system == "Linux":
            key_hex = _linux_load()
        else:
            raise KeychainError(f"Unsupported platform: {system}")

        return SigningKey(key_hex.encode(), encoder=HexEncoder)

    @staticmethod
    def delete() -> None:
        """Remove the signing key from the OS keychain."""
        system = platform.system()

        if system == "Darwin":
            _macos_delete()
        elif system == "Windows":
            _windows_delete()
        elif system == "Linux":
            _linux_delete()


# macOS Keychain via security CLI

def _macos_available() -> bool:
    try:
        result = subprocess.run(
            ["security", "help"], capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def _macos_store(key_hex: str) -> None:
    result = subprocess.run(
        [
            "security", "add-generic-password",
            "-a", ACCOUNT_NAME,
            "-s", SERVICE_NAME,
            "-w", key_hex,
            "-U",  # update if exists
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise KeychainError(f"macOS Keychain store failed: {result.stderr}")


def _macos_load() -> str:
    result = subprocess.run(
        [
            "security", "find-generic-password",
            "-a", ACCOUNT_NAME,
            "-s", SERVICE_NAME,
            "-w",
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise KeychainError("Key not found in macOS Keychain")
    return result.stdout.strip()


def _macos_delete() -> None:
    subprocess.run(
        [
            "security", "delete-generic-password",
            "-a", ACCOUNT_NAME,
            "-s", SERVICE_NAME,
        ],
        capture_output=True, timeout=10,
    )


# Windows DPAPI

def _windows_available() -> bool:
    try:
        import ctypes
        return hasattr(ctypes.windll, "crypt32")
    except Exception:
        return False


def _windows_store(key_hex: str) -> None:
    """Store key using Windows DPAPI encryption to a protected file."""
    import ctypes
    import ctypes.wintypes

    key_bytes = key_hex.encode("utf-16-le")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    input_blob = DATA_BLOB()
    input_blob.cbData = len(key_bytes)
    input_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(key_bytes, len(key_bytes)),
        ctypes.POINTER(ctypes.c_byte),
    )

    output_blob = DATA_BLOB()

    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(input_blob), "sealed_key", None, None, None, 0,
        ctypes.byref(output_blob),
    ):
        raise KeychainError("DPAPI CryptProtectData failed")

    encrypted = ctypes.string_at(output_blob.pbData, output_blob.cbData)
    ctypes.windll.kernel32.LocalFree(output_blob.pbData)

    dpapi_path = Path.home() / ".sealed" / "key.dpapi"
    dpapi_path.parent.mkdir(parents=True, exist_ok=True)
    dpapi_path.write_bytes(encrypted)


def _windows_load() -> str:
    """Load key from DPAPI-encrypted file."""
    import ctypes
    import ctypes.wintypes

    dpapi_path = Path.home() / ".sealed" / "key.dpapi"
    if not dpapi_path.exists():
        raise KeychainError("No DPAPI key file found")

    encrypted = dpapi_path.read_bytes()

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_byte)),
        ]

    input_blob = DATA_BLOB()
    input_blob.cbData = len(encrypted)
    input_blob.pbData = ctypes.cast(
        ctypes.create_string_buffer(encrypted, len(encrypted)),
        ctypes.POINTER(ctypes.c_byte),
    )

    output_blob = DATA_BLOB()

    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None, 0,
        ctypes.byref(output_blob),
    ):
        raise KeychainError("DPAPI CryptUnprotectData failed")

    decrypted = ctypes.string_at(output_blob.pbData, output_blob.cbData)
    ctypes.windll.kernel32.LocalFree(output_blob.pbData)

    return decrypted.decode("utf-16-le")


def _windows_delete() -> None:
    dpapi_path = Path.home() / ".sealed" / "key.dpapi"
    dpapi_path.unlink(missing_ok=True)


# Linux libsecret via secret-tool

def _linux_available() -> bool:
    try:
        result = subprocess.run(
            ["secret-tool", "--help"], capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def _linux_store(key_hex: str) -> None:
    result = subprocess.run(
        [
            "secret-tool", "store",
            "--label", "Sealed signing key",
            "service", SERVICE_NAME,
            "account", ACCOUNT_NAME,
        ],
        input=key_hex, capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise KeychainError(f"secret-tool store failed: {result.stderr}")


def _linux_load() -> str:
    result = subprocess.run(
        [
            "secret-tool", "lookup",
            "service", SERVICE_NAME,
            "account", ACCOUNT_NAME,
        ],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise KeychainError("Key not found in Linux keyring")
    return result.stdout.strip()


def _linux_delete() -> None:
    subprocess.run(
        [
            "secret-tool", "clear",
            "service", SERVICE_NAME,
            "account", ACCOUNT_NAME,
        ],
        capture_output=True, timeout=10,
    )
