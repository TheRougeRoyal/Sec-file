from django import forms

from .models import EncryptedFile


class EncryptedFileUploadForm(forms.ModelForm):
    class Meta:
        model = EncryptedFile
        fields = ("file", "description")

    def clean_file(self):
        upload = self.cleaned_data["file"]
        content_type = (upload.content_type or "").lower()

        allowed_prefixes = ("text/", "image/")
        allowed_exact = {"application/json"}
        if content_type not in allowed_exact and not content_type.startswith(allowed_prefixes):
            raise forms.ValidationError("Only text and image files are allowed.")

        if upload.size > 5 * 1024 * 1024:
            raise forms.ValidationError("File size must be 5 MB or less.")

        return upload
