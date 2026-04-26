"""
Crypto Services Module

This module wraps the secure ECC crypto utilities for use within the Django app.
Replaces the insecure tinyec-based implementation with proper cryptography library.
"""

# Import from crypto_utils (secure implementation using cryptography library)
from crypto_utils.ecc_crypto import (
    EncryptedPayload,
    decrypt_bytes,
    encrypt_bytes,
    encrypt_private_key_pem,
    decrypt_private_key_pem,
    generate_key_pair,
)

__all__ = [
    'generate_key_pair',
    'encrypt_bytes',
    'decrypt_bytes',
    'encrypt_private_key_pem',
    'decrypt_private_key_pem',
    'EncryptedPayload',
]
