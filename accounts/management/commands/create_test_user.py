from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from crypto.models import UserKeyPair
from crypto.services import generate_key_pair


class Command(BaseCommand):
    help = "Create a sample test user with ECC keys"

    def handle(self, *args, **options):
        username = "testuser"
        password = "Test@12345"
        email = "testuser@example.com"

        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": email},
        )
        if created:
            user.set_password(password)
            user.save()

        if not UserKeyPair.objects.filter(user=user).exists():
            private_key, public_key = generate_key_pair()
            UserKeyPair.objects.create(
                user=user,
                private_key=private_key,
                public_key=public_key,
            )

        self.stdout.write(
            self.style.SUCCESS(
                "Sample user ready: username=testuser password=Test@12345"
            )
        )
