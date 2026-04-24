"""
Crypto Utilities Module

Provides secure ECC-based hybrid encryption for file storage.
"""

from .ecc_crypto import (
    ECCCryptoManager,
    EncryptedPayload,
    decrypt_bytes,
    encrypt_bytes,
    generate_key_pair,
)

__all__ = [
    'ECCCryptoManager',
    'EncryptedPayload',
    'generate_key_pair',
    'encrypt_bytes',
    'decrypt_bytes',
]
