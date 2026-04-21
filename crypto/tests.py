from django.test import TestCase

from .services import decrypt_bytes, encrypt_bytes, generate_key_pair


class CryptoServiceTests(TestCase):
	def test_encrypt_then_decrypt_returns_original(self):
		private_key, public_key = generate_key_pair()
		plain = b"secure payload"
		payload = encrypt_bytes(plain, public_key)
		restored = decrypt_bytes(
			ciphertext=payload.ciphertext,
			receiver_private_key=private_key,
			ephemeral_public_key=payload.ephemeral_public_key,
			nonce_hex=payload.nonce_hex,
		)
		self.assertEqual(restored, plain)
