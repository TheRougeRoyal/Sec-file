from django.contrib import admin

from .models import EncryptedFile


@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
	list_display = ('original_filename', 'owner', 'content_type', 'uploaded_at')
	search_fields = ('original_filename', 'owner__username', 'owner__email')
	list_filter = ('uploaded_at', 'content_type')
