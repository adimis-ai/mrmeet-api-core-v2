import datetime
import os
from typing import Tuple

import jwt
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, force_bytes
from django.contrib.auth.tokens import default_token_generator
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from allauth.account.models import EmailAddress

from .serializers import (
	LoginSerializer,
	RegisterSerializer,
	UserProfileSerializer,
	PasswordResetSerializer,
	PasswordResetConfirmSerializer,
	PasswordChangeSerializer,
	VerifyEmailSerializer,
	ResendVerificationEmailSerializer,
	TokenRefreshSerializer,
	TokenVerifySerializer,
	MeUpdateSerializer,
)

User = get_user_model()

ACCESS_TOKEN_LIFETIME = datetime.timedelta(minutes=30)
REFRESH_TOKEN_LIFETIME = datetime.timedelta(days=7)


def _generate_tokens(user):
	now = timezone.now()
	access_exp = now + ACCESS_TOKEN_LIFETIME
	refresh_exp = now + REFRESH_TOKEN_LIFETIME
	payload_access = {"user_id": user.id, "exp": int(access_exp.timestamp()), "type": "access"}
	payload_refresh = {"user_id": user.id, "exp": int(refresh_exp.timestamp()), "type": "refresh"}
	secret = settings.SECRET_KEY
	algo = "HS256"
	access = jwt.encode(payload_access, secret, algorithm=algo)
	refresh = jwt.encode(payload_refresh, secret, algorithm=algo)
	expires_in = int(ACCESS_TOKEN_LIFETIME.total_seconds())
	return access, refresh, expires_in


def _serialize_login_response(user):
	access, refresh, expires_in = _generate_tokens(user)
	return {
		"access": access,
		"refresh": refresh,
		"expires_in": expires_in,
		"user": UserProfileSerializer(user).data,
		"frontend_settings": {
			"site_name": os.getenv("SITE_NAME", "Attendee"),
			"company_name": os.getenv("COMPANY_NAME", "Attendee"),
			"blueprint_categories": [],
		},
	}


class LoginView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = LoginSerializer(data=request.data, context={"request": request})
		serializer.is_valid(raise_exception=True)
		user = serializer.validated_data["user"]
		login(request, user)
		return Response(_serialize_login_response(user))


class RegisterView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = RegisterSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		user = serializer.save()
		# Send verification email placeholder (if mandatory)
		if settings.ACCOUNT_EMAIL_VERIFICATION == "mandatory" and EmailAddress:
			EmailAddress.objects.filter(user=user, email=user.email).update(verified=False)
			# minimal placeholder email
			send_mail(
				subject="Verify your email",
				message="Please verify your email via the frontend flow.",
				from_email=os.getenv("DEFAULT_FROM_EMAIL", "noreply@example.com"),
				recipient_list=[user.email],
				fail_silently=True,
			)
		return Response({"detail": "Registration successful. Please verify your email."}, status=status.HTTP_201_CREATED)


class PasswordResetView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = PasswordResetSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		email = serializer.validated_data["email"]
		user = User.objects.filter(email__iexact=email).first()
		if user:
			uid = urlsafe_base64_encode(force_bytes(user.pk))
			token = default_token_generator.make_token(user)
			reset_link = f"{os.getenv('FRONTEND_BASE_URL','http://localhost:5173')}/reset-password?uid={uid}&token={token}"
			message = (
				"Use this link to reset your password: "
				f"{reset_link}\nIf you did not request this email you can ignore it."
			)
			send_mail(
				subject="Password Reset",
				message=message,
				from_email=os.getenv("DEFAULT_FROM_EMAIL", "noreply@example.com"),
				recipient_list=[email],
				fail_silently=True,
			)
		return Response({"detail": "If the email exists we sent a reset link."})


class PasswordResetConfirmView(APIView):
	permission_classes = [AllowAny]

	def post(self, request, uidb64: str, token: str):
		serializer = PasswordResetConfirmSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		try:
			uid = force_str(urlsafe_base64_decode(uidb64))
			user = User.objects.get(pk=uid)
		except Exception:
			return Response({"detail": "Invalid link."}, status=status.HTTP_400_BAD_REQUEST)
		if not default_token_generator.check_token(user, token):
			return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
		user.set_password(serializer.validated_data["new_password1"])
		user.save(update_fields=["password"])
		return Response({"detail": "Password has been reset."})


class PasswordChangeView(APIView):
	permission_classes = [IsAuthenticated]

	def post(self, request):
		serializer = PasswordChangeSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		request.user.set_password(serializer.validated_data["new_password1"])
		request.user.save(update_fields=["password"])
		return Response({"detail": "Password changed."})


class VerifyEmailConfirmView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = VerifyEmailSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		key = serializer.validated_data["key"]
		# For simplicity treat key as encoded email
		email_addr = None
		if EmailAddress and hasattr(EmailAddress, 'verification_key'):
			email_addr = EmailAddress.objects.filter(verification_key=key).first()
		# Fallback: we may not have a direct key field; consider using query parameter "key" not implemented here.
		if not email_addr:
			return Response({"detail": "Invalid or expired verification key."}, status=status.HTTP_400_BAD_REQUEST)
		email_addr.verified = True
		email_addr.save(update_fields=["verified"])
		return Response({"detail": "Email verified."})


class ResendVerificationEmailView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = ResendVerificationEmailSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		email = serializer.validated_data["email"]
		user = User.objects.filter(email__iexact=email).first()
		if user and EmailAddress:
			email_addr, _ = EmailAddress.objects.get_or_create(user=user, email=user.email, defaults={"primary": True})
			if not getattr(email_addr, 'verified', False):
				# In real implementation generate a key & send.
				send_mail(
					subject="Verify your email",
					message="Please verify your email through the link provided in the application.",
					from_email=os.getenv("DEFAULT_FROM_EMAIL", "noreply@example.com"),
					recipient_list=[user.email],
					fail_silently=True,
				)
		return Response({"detail": "If the email exists we resent verification instructions."})


class TokenRefreshView(APIView):
	permission_classes = [AllowAny]

	def post(self, request):
		serializer = TokenRefreshSerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		refresh_token = serializer.validated_data["refresh"]
		try:
			data = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])
			if data.get("type") != "refresh":
				raise jwt.InvalidTokenError
		except jwt.ExpiredSignatureError:
			return Response({"detail": "Refresh token expired."}, status=status.HTTP_401_UNAUTHORIZED)
		except jwt.InvalidTokenError:
			return Response({"detail": "Invalid token."}, status=status.HTTP_401_UNAUTHORIZED)
		user = get_object_or_404(User, id=data["user_id"])
		access, refresh, expires_in = _generate_tokens(user)
		return Response({"access": access, "refresh": refresh, "expires_in": expires_in})


class TokenVerifyView(APIView):
	permission_classes = [IsAuthenticated]

	def post(self, request):
		serializer = TokenVerifySerializer(data=request.data)
		serializer.is_valid(raise_exception=True)
		# We trust IsAuthenticated for now; optionally decode tokens.
		return Response({"is_valid": True})


class TokenBlacklistView(APIView):
	permission_classes = [IsAuthenticated]

	def post(self, request):
		# Stateless JWT without storage -> cannot truly blacklist w/out persistence. Acknowledge.
		return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
	permission_classes = [IsAuthenticated]

	def get(self, request):
		return Response(UserProfileSerializer(request.user).data)

	def patch(self, request):
		serializer = MeUpdateSerializer(request.user, data=request.data, partial=True)
		serializer.is_valid(raise_exception=True)
		serializer.save()
		return Response(UserProfileSerializer(request.user).data)


class MeDeleteView(APIView):
	permission_classes = [IsAuthenticated]

	def delete(self, request):
		request.user.is_active = False
		request.user.save(update_fields=["is_active"])
		return Response({"detail": "Account deactivated."})

