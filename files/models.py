import uuid

from django.conf import settings
from django.db import models


def encrypted_upload_path(_instance, filename):
	"""
	Generate a unique path for encrypted file storage.
	Files are stored with .enc extension to indicate encryption.
	"""
	ext = filename.split('.')[-1] if '.' in filename else 'bin'
	return f"encrypted/{uuid.uuid4().hex}.{ext}.enc"


class EncryptedFile(models.Model):
	"""
	Model for storing encrypted files with metadata.

	Each file is encrypted using hybrid encryption:
	- AES-256-GCM for file content encryption
	- ECC (SECP256R1) for key exchange

	The ephemeral_public_key and nonce are required for decryption.
	"""
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='encrypted_files',
	)
	original_filename = models.CharField(
		max_length=255,
		help_text="Original filename before encryption"
	)
	description = models.CharField(max_length=255, blank=True)
	file = models.FileField(
		upload_to=encrypted_upload_path,
		help_text="Encrypted file content"
	)
	content_type = models.CharField(
		max_length=120,
		help_text="MIME type of the original file"
	)
	file_size = models.PositiveBigIntegerField(default=0)
	# ECC ephemeral public key in PEM format (for ECDH)
	ephemeral_public_key = models.TextField(
		help_text="Ephemeral ECC public key (PEM format)"
	)
	# AES-GCM nonce in hex format
	nonce = models.CharField(
		max_length=64,
		default='',
		help_text="AES-GCM nonce (hex encoded)"
	)
	uploaded_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-uploaded_at']
		verbose_name = "Encrypted File"
		verbose_name_plural = "Encrypted Files"

	def __str__(self) -> str:
		return f"{self.original_filename} ({self.owner.username})"

	@property
	def file_extension(self) -> str:
		"""Extract the original file extension."""
		if '.' in self.original_filename:
			return self.original_filename.split('.')[-1].lower()
		return ''

	@property
	def is_image(self) -> bool:
		"""Check if the original file was an image."""
		return self.content_type.startswith('image/')

	@property
	def is_text(self) -> bool:
		"""Check if the original file was text-based."""
		return self.content_type.startswith('text/') or self.content_type == 'application/json'
