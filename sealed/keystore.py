"""Secure key storage: encrypted keys with passphrase or OS keychain.

Replaces plaintext key files with encrypted storage.
Falls back to plaintext if no passphrase provided (backwards compatible).
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random


class KeystoreError(Exception):
    pass


class Keystore:
    """Manage Ed25519 signing keys with optional encryption."""

    ENCRYPTED_HEADER = b"SEALED_KEY_V1"

    def __init__(self, key_path: Path):
        self.key_path = key_path

    def generate(self, passphrase: str | None = None) -> SigningKey:
        """Generate a new key and save it (encrypted if passphrase given)."""
        key = SigningKey.generate()
        self.save(key, passphrase)
        return key

    def save(self, key: SigningKey, passphrase: str | None = None) -> None:
        """Save a key to disk, optionally encrypted with a passphrase."""
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key_bytes = key.encode()

        if passphrase:
            encrypted = self._encrypt(key_bytes, passphrase)
            self.key_path.write_bytes(encrypted)
        else:
            self.key_path.write_text(key.encode(HexEncoder).decode())

        # Set restrictive permissions on Unix
        try:
            os.chmod(self.key_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows or permission error

    def load(self, passphrase: str | None = None,
             prompt: bool = True) -> SigningKey:
        """Load a key from disk, decrypting if needed.

        If the key is encrypted and no passphrase is given, prompts interactively
        (unless prompt=False, in which case it raises KeystoreError).
        """
        if not self.key_path.exists():
            raise KeystoreError(f"Key file not found: {self.key_path}")

        raw = self.key_path.read_bytes()

        if raw.startswith(self.ENCRYPTED_HEADER):
            if passphrase is None:
                if prompt and sys.stdin.isatty():
                    passphrase = getpass.getpass("Key passphrase: ")
                else:
                    raise KeystoreError(
                        "Key is encrypted. Provide passphrase or use interactive mode."
                    )
            key_bytes = self._decrypt(raw, passphrase)
            return SigningKey(key_bytes)
        else:
            # Plaintext hex key (backwards compatible)
            key_hex = raw.decode().strip()
            return SigningKey(key_hex.encode(), encoder=HexEncoder)

    def is_encrypted(self) -> bool:
        """Check if the stored key is encrypted."""
        if not self.key_path.exists():
            return False
        return self.key_path.read_bytes().startswith(self.ENCRYPTED_HEADER)

    def change_passphrase(self, old_passphrase: str | None,
                          new_passphrase: str | None) -> None:
        """Change the passphrase on an existing key."""
        key = self.load(passphrase=old_passphrase, prompt=False)
        self.save(key, new_passphrase)

    def export_public_key(self) -> str:
        """Export the public key as hex (no passphrase needed for encrypted keys?
        Actually we need the private key to derive public. So yes, passphrase needed.)"""
        # For encrypted keys, we need to decrypt first
        key = self.load()
        return key.verify_key.encode(HexEncoder).decode()

    def _encrypt(self, key_bytes: bytes, passphrase: str) -> bytes:
        """Encrypt key bytes with a passphrase using NaCl SecretBox.

        Derives a 32-byte encryption key from the passphrase via SHA-256.
        Uses a random 24-byte nonce.
        """
        # Derive encryption key from passphrase
        salt = nacl_random(16)
        enc_key = self._derive_key(passphrase, salt)
        box = SecretBox(enc_key)
        encrypted = box.encrypt(key_bytes)

        # Format: HEADER | salt(16) | encrypted(variable)
        return self.ENCRYPTED_HEADER + salt + encrypted

    def _decrypt(self, data: bytes, passphrase: str) -> bytes:
        """Decrypt key bytes with a passphrase."""
        header_len = len(self.ENCRYPTED_HEADER)
        if len(data) < header_len + 16:
            raise KeystoreError("Corrupted key file")

        salt = data[header_len:header_len + 16]
        encrypted = data[header_len + 16:]

        enc_key = self._derive_key(passphrase, salt)
        box = SecretBox(enc_key)
        try:
            return box.decrypt(encrypted)
        except Exception:
            raise KeystoreError("Wrong passphrase or corrupted key file")

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        """Derive a 32-byte key from passphrase + salt via PBKDF2."""
        return hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode(), salt, iterations=100_000
        )
