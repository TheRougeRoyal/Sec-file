import os

from django.conf import settings
from django.db import models


class PrivateKeyCipher:
    """
    Descriptor that decrypts the stored private key on first access and caches it.

    The passphrase is read from PRIVATE_KEY_PASSPHRASE env var on first access.
    If no passphrase is configured, private keys are stored and returned as-is
    (development mode only).

    Thread-safe via attribute-level caching on the descriptor instance.
    """

    def __get__(self, instance, owner):
        if instance is None:
            return self

        encrypted = instance.__dict__.get('_private_key_encrypted')
        if encrypted is None:
            # Field has no value yet
            return None

        passphrase = os.environ.get('PRIVATE_KEY_PASSPHRASE')
        if not passphrase:
            # No passphrase configured — return stored value as-is
            return encrypted

        if instance.is_encrypted:
            from crypto.services import decrypt_private_key_pem
            return decrypt_private_key_pem(encrypted, passphrase)

        # is_encrypted=False: stored value is already a plaintext PEM
        return encrypted

    def __set__(self, instance, value):
        instance.__dict__['_private_key_encrypted'] = value


class UserKeyPair(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='ecc_keypair',
    )
    public_key = models.TextField()
    _private_key_encrypted = models.TextField(db_column='private_key')
    is_encrypted = models.BooleanField(
        default=False,
        help_text='Whether the stored private key is encrypted with PRIVATE_KEY_PASSPHRASE.',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Descriptor: accessing .private_key returns the decrypted PEM transparently.
    # Storing via .private_key = pem encrypts it first if a passphrase is set.
    private_key = PrivateKeyCipher()

    def save(self, *args, **kwargs):
        # Auto-encrypt on first save if passphrase is configured and not already encrypted.
        passphrase = os.environ.get('PRIVATE_KEY_PASSPHRASE')
        raw = self.__dict__.get('_private_key_encrypted', '')
        if passphrase and raw and not self.is_encrypted:
            from crypto.services import encrypt_private_key_pem
            self.__dict__['_private_key_encrypted'] = encrypt_private_key_pem(raw, passphrase)
            self.is_encrypted = True
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"ECC keys for {self.user.username}"
