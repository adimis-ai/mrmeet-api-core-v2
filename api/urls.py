from django.urls import path

from .auth.views import (
	LoginView,
	RegisterView,
	PasswordResetView,
	PasswordResetConfirmView,
	PasswordChangeView,
	VerifyEmailConfirmView,
	ResendVerificationEmailView,
	TokenRefreshView,
	TokenVerifyView,
	TokenBlacklistView,
	MeView,
	MeDeleteView,
)

urlpatterns = [
	path("auth/login/", LoginView.as_view()),
	path("auth/register/", RegisterView.as_view()),
	path("auth/password/reset/", PasswordResetView.as_view()),
	path("auth/password/reset/confirm/<str:uidb64>/<str:token>/", PasswordResetConfirmView.as_view()),
	path("auth/password/change/", PasswordChangeView.as_view()),
	path("auth/verify-email/confirm/", VerifyEmailConfirmView.as_view()),
	path("auth/verify-email/resend/", ResendVerificationEmailView.as_view()),
	path("auth/token/refresh/", TokenRefreshView.as_view()),
	path("auth/token/verify/", TokenVerifyView.as_view()),
	path("auth/token/blacklist/", TokenBlacklistView.as_view()),
	path("auth/me/", MeView.as_view()),
	path("auth/me/delete/", MeDeleteView.as_view()),
]

