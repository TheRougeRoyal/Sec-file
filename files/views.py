"""
File Views - Secure File Transfer System

Handles file upload, download, and viewing with ECC-based encryption.
"""

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from crypto.services import decrypt_bytes, encrypt_bytes

from .forms import EncryptedFileUploadForm
from .models import EncryptedFile

logger = logging.getLogger(__name__)


def home_redirect(request):
    """Redirect authenticated users to dashboard, others to login."""
    if request.user.is_authenticated:
        return redirect('files:dashboard')
    return redirect('accounts:login')


@login_required
def dashboard_view(request):
    """
    User dashboard showing file statistics and recent uploads.
    """
    files_count = EncryptedFile.objects.filter(owner=request.user).count()
    recent_files = EncryptedFile.objects.filter(owner=request.user)[:5]
    return render(
        request,
        'files/dashboard.html',
        {
            'files_count': files_count,
            'recent_files': recent_files,
        },
    )


@login_required
def upload_file_view(request):
    """
    Handle secure file upload.

    Process:
    1. Validate file type and size
    2. Read file content
    3. Get user's ECC public key
    4. Encrypt file using hybrid encryption (ECDH + AES-256-GCM)
    5. Store encrypted file and metadata
    """
    form = EncryptedFileUploadForm(request.POST or None, request.FILES or None)

    if request.method == 'POST' and form.is_valid():
        incoming_file = form.cleaned_data['file']

        # Read file content into memory
        try:
            plain_bytes = incoming_file.read()
        except Exception as e:
            logger.error(f"Failed to read uploaded file: {e}")
            messages.error(request, 'Failed to read the uploaded file.')
            return render(request, 'files/upload.html', {'form': form})

        # Check if user has ECC keypair
        keypair = getattr(request.user, 'ecc_keypair', None)
        if not keypair:
            messages.error(
                request,
                'No ECC key pair found for your account. Please contact support.'
            )
            return redirect('files:dashboard')

        # Encrypt the file using hybrid encryption
        try:
            payload = encrypt_bytes(plain_bytes, keypair.public_key)
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            messages.error(request, 'Failed to encrypt the file. Please try again.')
            return render(request, 'files/upload.html', {'form': form})

        # Save encrypted file record
        encrypted_record = form.save(commit=False)
        encrypted_record.owner = request.user
        encrypted_record.original_filename = incoming_file.name
        encrypted_record.content_type = incoming_file.content_type or 'application/octet-stream'
        encrypted_record.file_size = incoming_file.size
        encrypted_record.ephemeral_public_key = payload.ephemeral_public_key
        encrypted_record.nonce = payload.nonce

        # Save encrypted file to storage
        encrypted_record.file.save(
            f"{incoming_file.name}.enc",
            content=ContentFile(payload.ciphertext),
            save=False,
        )
        encrypted_record.save()

        messages.success(
            request,
            f"'{incoming_file.name}' was encrypted and stored securely."
        )
        return redirect('files:list')

    return render(request, 'files/upload.html', {'form': form})


@login_required
def files_list_view(request):
    """
    List all encrypted files owned by the current user.
    """
    user_files = EncryptedFile.objects.filter(owner=request.user)
    return render(
        request,
        'files/list.html',
        {'files': user_files}
    )


def _decrypt_owned_file(user, file_id):
    """
    Helper function to decrypt a file owned by the user.

    Args:
        user: The requesting user
        file_id: ID of the encrypted file

    Returns:
        Tuple of (EncryptedFile instance, decrypted bytes)

    Raises:
        Http404: If file not found or user doesn't have access
    """
    # Get file and verify ownership
    secure_file = get_object_or_404(EncryptedFile, id=file_id)
    if secure_file.owner != user:
        raise Http404('File not found')

    # Get user's ECC keypair
    keypair = getattr(user, 'ecc_keypair', None)
    if not keypair:
        raise Http404('No ECC key pair configured for your account')

    # Read encrypted file content
    try:
        secure_file.file.open('rb')
        ciphertext = secure_file.file.read()
        secure_file.file.close()
    except Exception as e:
        logger.error(f"Failed to read encrypted file: {e}")
        raise Http404('Failed to read encrypted file')

    # Decrypt using hybrid decryption
    try:
        plain_bytes = decrypt_bytes(
            ciphertext=ciphertext,
            receiver_private_key=keypair.private_key,
            ephemeral_public_key=secure_file.ephemeral_public_key,
            nonce_hex=secure_file.nonce,
        )
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise Http404('Failed to decrypt file. The file may be corrupted.')

    return secure_file, plain_bytes


@login_required
def download_file_view(request, file_id):
    """
    Download a decrypted file.

    Process:
    1. Verify file ownership
    2. Decrypt file using ECC private key
    3. Return as download response
    """
    try:
        secure_file, plain_bytes = _decrypt_owned_file(request.user, file_id)
    except Http404:
        messages.error(request, 'File not found or access denied.')
        return redirect('files:list')

    # Create response with proper headers for download
    response = HttpResponse(
        plain_bytes,
        content_type=secure_file.content_type
    )
    response['Content-Disposition'] = (
        f'attachment; filename="{secure_file.original_filename}"'
    )
    response['Content-Length'] = len(plain_bytes)

    return response


@login_required
def view_file_view(request, file_id):
    """
    View a file inline (for images and text) or download as fallback.

    Process:
    1. Verify file ownership
    2. Decrypt file using ECC private key
    3. Return inline for images/text, or download for other types
    """
    try:
        secure_file, plain_bytes = _decrypt_owned_file(request.user, file_id)
    except Http404 as e:
        messages.error(request, str(e) if str(e) else 'File not found.')
        return redirect('files:list')

    content_type = secure_file.content_type.lower()

    # For images: return as inline image
    if content_type.startswith('image/'):
        response = HttpResponse(plain_bytes, content_type=secure_file.content_type)
        response['Content-Length'] = len(plain_bytes)
        return response

    # For text files: render in viewer template
    if content_type.startswith('text/') or content_type == 'application/json':
        try:
            text_content = plain_bytes.decode('utf-8', errors='replace')
        except Exception:
            text_content = plain_bytes.decode('latin-1', errors='replace')

        return render(
            request,
            'files/view_text.html',
            {
                'file': secure_file,
                'text_content': text_content,
            },
        )

    # For other types: force download
    response = HttpResponse(
        plain_bytes,
        content_type='application/octet-stream'
    )
    response['Content-Disposition'] = (
        f'attachment; filename="{secure_file.original_filename}"'
    )
    response['Content-Length'] = len(plain_bytes)
    return response
