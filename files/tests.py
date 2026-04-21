from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from crypto.models import UserKeyPair
from crypto.services import generate_key_pair

from .models import EncryptedFile


class FileFlowTests(TestCase):
	def setUp(self):
		self.user = User.objects.create_user(username='bob', password='S3curePass!123')
		private_key, public_key = generate_key_pair()
		UserKeyPair.objects.create(user=self.user, private_key=private_key, public_key=public_key)

	def test_upload_and_download_text_file(self):
		self.client.login(username='bob', password='S3curePass!123')
		upload = SimpleUploadedFile('note.txt', b'hello world', content_type='text/plain')
		response = self.client.post(
			reverse('files:upload'),
			{'file': upload, 'description': 'test note'},
			follow=True,
		)
		self.assertEqual(response.status_code, 200)
		stored = EncryptedFile.objects.get(owner=self.user)
		download = self.client.get(reverse('files:download', args=[stored.id]))
		self.assertEqual(download.status_code, 200)
		self.assertEqual(download.content, b'hello world')

	def test_other_user_cannot_access_file(self):
		self.client.login(username='bob', password='S3curePass!123')
		upload = SimpleUploadedFile('note.txt', b'secret', content_type='text/plain')
		self.client.post(reverse('files:upload'), {'file': upload, 'description': ''}, follow=True)
		stored = EncryptedFile.objects.get(owner=self.user)

		other = User.objects.create_user(username='eve', password='S3curePass!123')
		private_key, public_key = generate_key_pair()
		UserKeyPair.objects.create(user=other, private_key=private_key, public_key=public_key)
		self.client.logout()
		self.client.login(username='eve', password='S3curePass!123')

		response = self.client.get(reverse('files:download', args=[stored.id]))
		self.assertEqual(response.status_code, 404)
