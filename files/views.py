from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from crypto.services import decrypt_bytes, encrypt_bytes

from .forms import EncryptedFileUploadForm
from .models import EncryptedFile


def home_redirect(request):
	if request.user.is_authenticated:
		return redirect('files:dashboard')
	return redirect('accounts:login')


@login_required
def dashboard_view(request):
	files_count = EncryptedFile.objects.filter(owner=request.user).count()
	recent_files = EncryptedFile.objects.filter(owner=request.user)[:5]
	return render(
		request,
		'files/dashboard.html',
		{'files_count': files_count, 'recent_files': recent_files},
	)


@login_required
def upload_file_view(request):
	form = EncryptedFileUploadForm(request.POST or None, request.FILES or None)
	if request.method == 'POST' and form.is_valid():
		incoming_file = form.cleaned_data['file']
		plain_bytes = incoming_file.read()

		keypair = getattr(request.user, 'ecc_keypair', None)
		if not keypair:
			messages.error(request, 'No ECC key pair found for your account.')
			return redirect('files:dashboard')

		payload = encrypt_bytes(plain_bytes, keypair.public_key)

		encrypted_record = form.save(commit=False)
		encrypted_record.owner = request.user
		encrypted_record.original_filename = incoming_file.name
		encrypted_record.content_type = incoming_file.content_type or 'application/octet-stream'
		encrypted_record.file_size = incoming_file.size
		encrypted_record.ephemeral_public_key = payload.ephemeral_public_key
		encrypted_record.nonce_hex = payload.nonce_hex
		encrypted_record.file.save(
			f"{incoming_file.name}.enc",
			content=ContentFile(payload.ciphertext),
			save=False,
		)
		encrypted_record.save()
		messages.success(request, 'File encrypted and stored successfully.')
		return redirect('files:list')

	return render(request, 'files/upload.html', {'form': form})


@login_required
def files_list_view(request):
	user_files = EncryptedFile.objects.filter(owner=request.user)
	return render(request, 'files/list.html', {'files': user_files})


def _decrypt_owned_file(user, file_id):
	secure_file = get_object_or_404(EncryptedFile, id=file_id)
	if secure_file.owner != user:
		raise Http404('File not found')

	keypair = getattr(user, 'ecc_keypair', None)
	if not keypair:
		raise Http404('No ECC key pair configured')

	secure_file.file.open('rb')
	ciphertext = secure_file.file.read()
	secure_file.file.close()

	plain_bytes = decrypt_bytes(
		ciphertext=ciphertext,
		receiver_private_key=keypair.private_key,
		ephemeral_public_key=secure_file.ephemeral_public_key,
		nonce_hex=secure_file.nonce_hex,
	)
	return secure_file, plain_bytes


@login_required
def download_file_view(request, file_id):
	secure_file, plain_bytes = _decrypt_owned_file(request.user, file_id)
	response = HttpResponse(plain_bytes, content_type=secure_file.content_type)
	response['Content-Disposition'] = f'attachment; filename="{secure_file.original_filename}"'
	return response


@login_required
def view_file_view(request, file_id):
	secure_file, plain_bytes = _decrypt_owned_file(request.user, file_id)
	content_type = secure_file.content_type.lower()

	if content_type.startswith('image/'):
		return HttpResponse(plain_bytes, content_type=secure_file.content_type)

	if content_type.startswith('text/') or content_type == 'application/json':
		return render(
			request,
			'files/view_text.html',
			{
				'file': secure_file,
				'text_content': plain_bytes.decode('utf-8', errors='replace'),
			},
		)

	response = HttpResponse(plain_bytes, content_type='application/octet-stream')
	response['Content-Disposition'] = f'attachment; filename="{secure_file.original_filename}"'
	return response
