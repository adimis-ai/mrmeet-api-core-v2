from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
try:
	from allauth.account.models import EmailAddress  # type: ignore
except Exception:  # pragma: no cover
	EmailAddress = None  # type: ignore
from django.conf import settings

User = get_user_model()


class UserShortSerializer(serializers.ModelSerializer):
	pk = serializers.IntegerField(source="id", read_only=True)
	logo = serializers.SerializerMethodField()
	username = serializers.CharField(allow_null=True, required=False)

	class Meta:
		model = User
		fields = [
			"pk",
			"username",
			"first_name",
			"last_name",
			"email",
			"logo",
		]

	def get_logo(self, obj):  # placeholder for future avatar/logo field
		return None


class UserProfileSerializer(UserShortSerializer):
	metadata = serializers.SerializerMethodField()
	is_active = serializers.BooleanField(read_only=True)
	date_joined = serializers.DateTimeField(read_only=True)
	email_verified_at = serializers.SerializerMethodField()
	is_email_verified = serializers.SerializerMethodField()
	is_superuser = serializers.BooleanField(read_only=True)
	last_login = serializers.DateTimeField(read_only=True)
	workspaces = serializers.SerializerMethodField()

	class Meta(UserShortSerializer.Meta):
		fields = UserShortSerializer.Meta.fields + [
			"metadata",
			"is_active",
			"date_joined",
			"email_verified_at",
			"is_email_verified",
			"is_superuser",
			"last_login",
			"workspaces",
		]

	def get_metadata(self, obj):
		return {}

	def get_email_verified_at(self, obj):
		if not EmailAddress:
			return None
		email_addr = EmailAddress.objects.filter(user=obj, primary=True).first()
		if email_addr and email_addr.verified:
			return getattr(email_addr, "last_updated", None)
		return None

	def get_is_email_verified(self, obj):
		if not EmailAddress:
			return False
		email_addr = EmailAddress.objects.filter(user=obj, primary=True).first()
		return bool(email_addr and getattr(email_addr, "verified", False))

	def get_workspaces(self, obj):
		# No workspaces concept yet – return empty list for compatibility
		return []


class LoginSerializer(serializers.Serializer):
	email = serializers.EmailField()
	password = serializers.CharField(write_only=True)

	def validate(self, attrs):
		user = authenticate(
			request=self.context.get("request"),
			email=attrs.get("email"),
			username=attrs.get("email"),  # In case backend still expects username
			password=attrs.get("password"),
		)
		if not user:
			raise serializers.ValidationError({"detail": _("Invalid email or password.")})
		if not user.is_active:
			raise serializers.ValidationError({"detail": _("This account is inactive.")})
		attrs["user"] = user
		return attrs


class RegisterSerializer(serializers.Serializer):
	email = serializers.EmailField()
	username = serializers.CharField(required=False, allow_blank=True)
	first_name = serializers.CharField(required=False, allow_blank=True)
	last_name = serializers.CharField(required=False, allow_blank=True)
	password1 = serializers.CharField(write_only=True)
	password2 = serializers.CharField(write_only=True)

	def validate_email(self, value):
		if User.objects.filter(email__iexact=value).exists():
			raise serializers.ValidationError("A user with this email already exists.")
		return value

	def validate(self, attrs):
		if attrs.get("password1") != attrs.get("password2"):
			raise serializers.ValidationError({"password2": "Passwords do not match."})
		if len(attrs.get("password1", "")) < 12:
			raise serializers.ValidationError({"password1": "Password must be at least 12 characters."})
		return attrs

	def create(self, validated_data):
		password = validated_data.pop("password1")
		validated_data.pop("password2", None)
		user = User.objects.create_user(
			email=validated_data.get("email"),
			username=validated_data.get("username") or validated_data.get("email"),
			first_name=validated_data.get("first_name", ""),
			last_name=validated_data.get("last_name", ""),
			password=password,
		)
		# Ensure EmailAddress entry for verification flow
		if EmailAddress:
			EmailAddress.objects.get_or_create(user=user, email=user.email, defaults={"primary": True, "verified": False})
		return user


class PasswordResetSerializer(serializers.Serializer):
	email = serializers.EmailField()

	def validate_email(self, value):
		if not User.objects.filter(email__iexact=value).exists():
			# Do NOT reveal user existence; still accept to avoid enumeration
			pass
		return value


class PasswordResetConfirmSerializer(serializers.Serializer):
	new_password1 = serializers.CharField(write_only=True)
	new_password2 = serializers.CharField(write_only=True)

	def validate(self, attrs):
		if attrs["new_password1"] != attrs["new_password2"]:
			raise serializers.ValidationError({"new_password2": "Passwords do not match."})
		if len(attrs["new_password1"]) < 12:
			raise serializers.ValidationError({"new_password1": "Password must be at least 12 characters."})
		return attrs


class PasswordChangeSerializer(serializers.Serializer):
	new_password1 = serializers.CharField(write_only=True)
	new_password2 = serializers.CharField(write_only=True)

	def validate(self, attrs):
		if attrs["new_password1"] != attrs["new_password2"]:
			raise serializers.ValidationError({"new_password2": "Passwords do not match."})
		if len(attrs["new_password1"]) < 12:
			raise serializers.ValidationError({"new_password1": "Password must be at least 12 characters."})
		return attrs


class VerifyEmailSerializer(serializers.Serializer):
	key = serializers.CharField()


class ResendVerificationEmailSerializer(serializers.Serializer):
	email = serializers.EmailField()


class TokenRefreshSerializer(serializers.Serializer):
	refresh = serializers.CharField()


class TokenVerifySerializer(serializers.Serializer):
	access = serializers.CharField(required=False, allow_blank=True)
	refresh = serializers.CharField(required=False, allow_blank=True)


class MeUpdateSerializer(serializers.ModelSerializer):
	class Meta:
		model = User
		fields = ["first_name", "last_name", "username"]
		extra_kwargs = {f: {"required": False} for f in fields}

