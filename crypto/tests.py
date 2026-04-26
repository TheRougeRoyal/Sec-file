import os
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase

from .models import UserKeyPair
from .services import (
    decrypt_bytes,
    encrypt_bytes,
    encrypt_private_key_pem,
    decrypt_private_key_pem,
    generate_key_pair,
)


class CryptoServiceTests(TestCase):
	def test_encrypt_then_decrypt_returns_original(self):
		private_key, public_key = generate_key_pair()
		plain = b"secure payload"
		payload = encrypt_bytes(plain, public_key)
		restored = decrypt_bytes(
			ciphertext=payload.ciphertext,
			receiver_private_key=private_key,
			ephemeral_public_key=payload.ephemeral_public_key,
			nonce_hex=payload.nonce,
		)
		self.assertEqual(restored, plain)


class PrivateKeyEncryptionTests(TestCase):
	def test_encrypt_then_decrypt_round_trip(self):
		private_key, _ = generate_key_pair()
		encrypted = encrypt_private_key_pem(private_key, 'test-passphrase')
		restored = decrypt_private_key_pem(encrypted, 'test-passphrase')
		self.assertEqual(restored, private_key)

	def test_encrypted_output_differs_from_plaintext(self):
		private_key, _ = generate_key_pair()
		encrypted = encrypt_private_key_pem(private_key, 'test-passphrase')
		self.assertNotEqual(encrypted, private_key)

	def test_wrong_passphrase_raises(self):
		private_key, _ = generate_key_pair()
		encrypted = encrypt_private_key_pem(private_key, 'correct')
		with self.assertRaises(Exception):
			decrypt_private_key_pem(encrypted, 'wrong')

	def test_userkeypair_private_key_unencrypted_without_passphrase(self):
		"""When no passphrase is set, private key is stored as-is."""
		user = User.objects.create_user(username='alice', password='pass')
		private_key, public_key = generate_key_pair()
		with patch.dict(os.environ, {}, clear=True):
			UserKeyPair.objects.create(
				user=user,
				public_key=public_key,
				private_key=private_key,
			)
		# Read back without passphrase — should return as stored
		keypair = UserKeyPair.objects.get(user=user)
		self.assertEqual(keypair.private_key, private_key)
		self.assertFalse(keypair.is_encrypted)

	def test_userkeypair_private_key_encrypted_on_save_with_passphrase(self):
		"""When a passphrase is set, private key is encrypted on save."""
		user = User.objects.create_user(username='bob', password='pass')
		private_key, public_key = generate_key_pair()
		with patch.dict(os.environ, {'PRIVATE_KEY_PASSPHRASE': 'secret123'}):
			UserKeyPair.objects.create(
				user=user,
				public_key=public_key,
				private_key=private_key,
			)
		keypair = UserKeyPair.objects.get(user=user)
		# Stored value is encrypted
		self.assertNotEqual(keypair._private_key_encrypted, private_key)
		self.assertTrue(keypair.is_encrypted)
		# Accessing .private_key with passphrase set returns decrypted PEM
		self.assertEqual(keypair.private_key, private_key)

	def test_userkeypair_private_key_access_via_descriptor(self):
		"""The private_key descriptor returns the decrypted PEM transparently."""
		user = User.objects.create_user(username='carol', password='pass')
		private_key, public_key = generate_key_pair()
		UserKeyPair.objects.create(
			user=user,
			public_key=public_key,
			private_key=private_key,
		)
		keypair = UserKeyPair.objects.get(user=user)
		# Descriptor returns the raw value when no passphrase
		self.assertEqual(keypair.private_key, private_key)
