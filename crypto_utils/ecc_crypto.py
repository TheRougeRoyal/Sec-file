"""
Secure Elliptic Curve Cryptography (ECC) Module for File Encryption

This module implements hybrid encryption combining ECC key exchange with AES-256-GCM:
- ECC (SECP256R1) is used for secure key exchange
- AES-256-GCM provides authenticated symmetric encryption
- Each file gets a unique ephemeral key pair for forward secrecy
"""

import os
import secrets
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


# Use SECP256R1 (P-256) curve - widely supported and secure
CURVE = ec.SECP256R1()


@dataclass
class EncryptedPayload:
    """
    Container for encrypted file data.

    Attributes:
        ciphertext: The encrypted file content (includes AES-GCM tag)
        ephemeral_public_key: The ephemeral public key in PEM format (for ECDH)
        nonce: The AES-GCM nonce/IV used for encryption
    """
    ciphertext: bytes
    ephemeral_public_key: str  # PEM format
    nonce: str  # Hex encoded


class ECCCryptoManager:
    """
    Manages ECC key generation and hybrid encryption operations.

    Uses ECDH (Elliptic Curve Diffie-Hellman) for key exchange and
    AES-256-GCM for symmetric encryption of file data.
    """

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generate a new ECC key pair using SECP256R1 curve.

        Returns:
            Tuple of (private_key_pem, public_key_pem) in PEM format
        """
        # Generate private key
        private_key = ec.generate_private_key(CURVE, default_backend())

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        # Get public key and serialize to PEM
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return private_pem, public_pem

    @staticmethod
    def _derive_shared_key(
        private_key: ec.EllipticCurvePrivateKey,
        public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        """
        Derive a shared secret using ECDH key exchange.

        The shared secret is then hashed using SHA-256 to create
        a 256-bit AES key.

        Args:
            private_key: The private key for ECDH
            public_key: The peer's public key for ECDH

        Returns:
            32-byte AES key derived from the shared secret
        """
        # Perform ECDH key exchange
        shared_secret = private_key.exchange(ec.ECDH(), public_key)

        # Hash the shared secret to get a uniform 256-bit key
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_secret)
        aes_key = digest.finalize()

        return aes_key

    @staticmethod
    def encrypt_file(file_bytes: bytes, receiver_public_key_pem: str) -> EncryptedPayload:
        """
        Encrypt file using hybrid encryption (ECDH + AES-256-GCM).

        Steps:
        1. Generate ephemeral ECC key pair
        2. Derive shared secret using ECDH with receiver's public key
        3. Generate random AES key from shared secret
        4. Encrypt file with AES-256-GCM using a random nonce
        5. Return ciphertext + ephemeral public key + nonce

        Args:
            file_bytes: The file content to encrypt
            receiver_public_key_pem: Receiver's ECC public key in PEM format

        Returns:
            EncryptedPayload containing ciphertext and metadata
        """
        # Load receiver's public key
        receiver_public_key = serialization.load_pem_public_key(
            receiver_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Generate ephemeral key pair for this encryption
        ephemeral_private_key = ec.generate_private_key(CURVE, default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Derive shared AES key using ECDH
        aes_key = ECCCryptoManager._derive_shared_key(
            ephemeral_private_key,
            receiver_public_key
        )

        # Generate random 12-byte nonce for AES-GCM
        nonce = secrets.token_bytes(12)

        # Encrypt file with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(nonce, file_bytes, None)

        # Serialize ephemeral public key
        ephemeral_public_pem = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        return EncryptedPayload(
            ciphertext=ciphertext,
            ephemeral_public_key=ephemeral_public_pem,
            nonce=nonce.hex()
        )

    @staticmethod
    def decrypt_file(
        ciphertext: bytes,
        receiver_private_key_pem: str,
        ephemeral_public_key_pem: str,
        nonce_hex: str
    ) -> bytes:
        """
        Decrypt file using hybrid decryption (ECDH + AES-256-GCM).

        Steps:
        1. Load receiver's private key
        2. Load ephemeral public key
        3. Derive shared secret using ECDH
        4. Decrypt file with AES-256-GCM

        Args:
            ciphertext: The encrypted file content
            receiver_private_key_pem: Receiver's ECC private key in PEM format
            ephemeral_public_key_pem: Ephemeral public key from encryption in PEM
            nonce_hex: The nonce used for encryption (hex encoded)

        Returns:
            Decrypted file bytes
        """
        # Load receiver's private key
        receiver_private_key = serialization.load_pem_private_key(
            receiver_private_key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )

        # Load ephemeral public key
        ephemeral_public_key = serialization.load_pem_public_key(
            ephemeral_public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Derive shared AES key using ECDH
        aes_key = ECCCryptoManager._derive_shared_key(
            receiver_private_key,
            ephemeral_public_key
        )

        # Decode nonce
        nonce = bytes.fromhex(nonce_hex)

        # Decrypt with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext


# Convenience functions for backward compatibility
def generate_key_pair() -> Tuple[str, str]:
    """Generate ECC key pair - wrapper for ECCCryptoManager."""
    return ECCCryptoManager.generate_keypair()


def encrypt_bytes(plain_bytes: bytes, receiver_public_key: str) -> EncryptedPayload:
    """Encrypt bytes - wrapper for ECCCryptoManager."""
    return ECCCryptoManager.encrypt_file(plain_bytes, receiver_public_key)


def decrypt_bytes(
    ciphertext: bytes,
    receiver_private_key: str,
    ephemeral_public_key: str,
    nonce_hex: str
) -> bytes:
    """Decrypt bytes - wrapper for ECCCryptoManager."""
    return ECCCryptoManager.decrypt_file(
        ciphertext,
        receiver_private_key,
        ephemeral_public_key,
        nonce_hex
    )
