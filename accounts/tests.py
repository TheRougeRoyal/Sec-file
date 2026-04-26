from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from crypto.models import UserKeyPair


class AccountFlowTests(TestCase):
	def test_register_creates_user_and_keys(self):
		response = self.client.post(
			reverse('accounts:register'),
			{
				'username': 'alice',
				'email': 'alice@example.com',
				'password1': 'S3curePass!123',
				'password2': 'S3curePass!123',
			},
			follow=True,
		)
		self.assertEqual(response.status_code, 200)
		user = User.objects.get(username='alice')
		self.assertTrue(UserKeyPair.objects.filter(user=user).exists())

	def test_registration_key_failure_leaves_no_partial_account(self):
		with patch('accounts.views.generate_key_pair', side_effect=Exception('Key gen failed')):
			response = self.client.post(
				reverse('accounts:register'),
				{
					'username': 'bob',
					'email': 'bob@example.com',
					'password1': 'S3curePass!123',
					'password2': 'S3curePass!123',
				},
			)
		self.assertEqual(response.status_code, 200)  # re-renders form with error
		self.assertFalse(User.objects.filter(username='bob').exists())
