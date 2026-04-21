from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render

from crypto.models import UserKeyPair
from crypto.services import generate_key_pair

from .forms import LoginForm, ProfileEditForm, RegistrationForm
from .models import UserProfile


class CustomLoginView(LoginView):
	template_name = 'accounts/login.html'
	authentication_form = LoginForm


def register_view(request):
	if request.user.is_authenticated:
		return redirect('files:dashboard')

	form = RegistrationForm(request.POST or None)
	if request.method == 'POST' and form.is_valid():
		user = form.save()
		UserProfile.objects.get_or_create(user=user)
		private_key, public_key = generate_key_pair()
		UserKeyPair.objects.create(
			user=user,
			private_key=private_key,
			public_key=public_key,
		)
		login(request, user)
		messages.success(request, 'Registration successful. ECC keys were generated for your account.')
		return redirect('files:dashboard')
	return render(request, 'accounts/register.html', {'form': form})


@login_required
def logout_view(request):
	logout(request)
	messages.info(request, 'You have been logged out.')
	return redirect('accounts:login')


@login_required
def profile_view(request):
	form = ProfileEditForm(request.POST or None, instance=request.user)
	if request.method == 'POST' and form.is_valid():
		form.save()
		messages.success(request, 'Profile updated successfully.')
		return redirect('accounts:profile')
	return render(request, 'accounts/profile.html', {'form': form})
