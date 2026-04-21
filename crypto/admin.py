from django.contrib import admin

from .models import UserKeyPair


@admin.register(UserKeyPair)
class UserKeyPairAdmin(admin.ModelAdmin):
	list_display = ('user', 'created_at', 'updated_at')
	search_fields = ('user__username', 'user__email')
