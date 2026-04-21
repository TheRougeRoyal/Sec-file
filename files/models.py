import uuid

from django.conf import settings
from django.db import models


def encrypted_upload_path(_instance, filename):
	ext = filename.split('.')[-1] if '.' in filename else 'bin'
	return f"encrypted/{uuid.uuid4().hex}.{ext}.enc"


class EncryptedFile(models.Model):
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='encrypted_files',
	)
	original_filename = models.CharField(max_length=255)
	description = models.CharField(max_length=255, blank=True)
	file = models.FileField(upload_to=encrypted_upload_path)
	content_type = models.CharField(max_length=120)
	file_size = models.PositiveBigIntegerField(default=0)
	ephemeral_public_key = models.TextField()
	nonce_hex = models.CharField(max_length=64)
	uploaded_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ['-uploaded_at']

	def __str__(self) -> str:
		return f"{self.original_filename} ({self.owner.username})"
