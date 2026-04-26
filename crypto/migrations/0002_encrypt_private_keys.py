from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crypto', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userkeypair',
            name='is_encrypted',
            field=models.BooleanField(
                default=False,
                help_text='Whether the stored private key is encrypted with PRIVATE_KEY_PASSPHRASE.',
            ),
        ),
        migrations.AlterField(
            model_name='userkeypair',
            name='private_key',
            field=models.TextField(db_column='private_key'),
        ),
    ]
