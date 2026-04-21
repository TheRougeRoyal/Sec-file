from django.conf import settings
from django.db import models


class UserKeyPair(models.Model):
	user = models.OneToOneField(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='ecc_keypair',
	)
	public_key = models.TextField()
	private_key = models.TextField()
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	def __str__(self) -> str:
		return f"ECC keys for {self.user.username}"
