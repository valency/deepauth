from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import NotFound, NotAuthenticated

from .models import *
from .utils.captcha import validate_captcha
from .utils.password import validate_password


def validate_id(model, account, oid, allow_none=True):
    if oid is not None:
        try:
            obj = model.objects.get(pk=oid)
            if getattr(model, 'public', False) and obj.public is True:
                pass
            elif account is not None and obj.account != account:
                raise serializers.ValidationError(NotAuthenticated.default_detail)
        except ObjectDoesNotExist:
            raise serializers.ValidationError(NotFound.default_detail)
    elif not allow_none:
        raise serializers.ValidationError(NotFound.default_detail)
    return oid


# Model serializers

class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        exclude = ('password',)


class AccessSerializer(serializers.ModelSerializer):
    class Meta:
        model = Access
        fields = '__all__'


class PasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Password
        fields = '__all__'


class InvitationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invitation
        fields = '__all__'


# View serializers

class RegisterViewSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=30, help_text='First name of the user, maximum: 30 bytes')
    last_name = serializers.CharField(max_length=30, required=False, default='', help_text='Last name of the user, maximum: 30 bytes')
    username = serializers.CharField(max_length=150, required=False, default=None, help_text='User name, will be randomly generated if not provided, maximum: 150 bytes')
    password = serializers.CharField(help_text='Password, hashed via MD5 is recommended')
    email = serializers.EmailField(required=False, default='', help_text='Email')
    tel = serializers.CharField(max_length=32, required=False, default=None, help_text='Telephone number')
    country = serializers.CharField(max_length=8, required=False, default=None, help_text='Country code, maximum: 8 bytes')
    invitation = serializers.CharField(max_length=32, required=False, default=None, help_text='Invitation code')
    captcha_key = serializers.CharField(max_length=40, min_length=40, required=getattr(settings, 'DEEPAUTH_CAPTCHA_NEED', False), help_text='Captcha key (should hide from user), expires in 5 minutes')
    captcha_value = serializers.CharField(max_length=4, min_length=4, required=getattr(settings, 'DEEPAUTH_CAPTCHA_NEED', False), help_text='Captcha value provided by user')

    def validate_username(self, value):
        if value is None:
            value = 'u' + str(int(timezone.now().timestamp() * 1000))
        try:
            Account.objects.get(username=value)
            raise serializers.ValidationError('User name already exists')
        except ObjectDoesNotExist:
            return value

    def validate_password(self, value):
        return validate_password(value)

    def validate_email(self, value):
        if value:
            accounts = Account.objects.filter(email=value)
            if accounts.count():
                raise serializers.ValidationError('Email already exists')
        return value

    def validate_tel(self, value):
        if value:
            accounts = Account.objects.filter(tel=value)
            if accounts.count():
                raise serializers.ValidationError('Telephone already exists')
        return value

    def validate_invitation(self, value):
        if value is not None:
            try:
                Account.objects.get(invitation_code=value)
            except ObjectDoesNotExist:
                raise serializers.ValidationError(NotFound.default_detail)
        return value

    def validate(self, data):
        if getattr(settings, 'DEEPAUTH_CAPTCHA_NEED', False):
            validate_captcha(data)
        if getattr(settings, 'DEEPAUTH_INVITATION_ONLY', False) and data['invitation'] is None and Account.objects.all().count():
            raise serializers.ValidationError('Invitation code is required')
        if getattr(settings, 'DEEPAUTH_EMAIL_CONF', False) and settings.DEEPAUTH_EMAIL_CONF['required'] is True and data['email'] is None:
            raise serializers.ValidationError('Email is required')
        return data


class AccountPutViewSerializer(serializers.Serializer):
    avatar = serializers.URLField(required=False, help_text='Avatar image URL')
    first_name = serializers.CharField(max_length=RegisterViewSerializer.first_name.max_length, required=False, help_text=RegisterViewSerializer.first_name.help_text)
    last_name = serializers.CharField(max_length=RegisterViewSerializer.last_name.max_length, required=False, help_text=RegisterViewSerializer.first_name.help_text)
    email = serializers.EmailField(required=False, help_text=RegisterViewSerializer.email.help_text)
    tel = serializers.CharField(max_length=RegisterViewSerializer.tel.max_length, required=False, help_text=RegisterViewSerializer.tel.help_text)
    country = serializers.CharField(max_length=RegisterViewSerializer.country.max_length, required=False, help_text=RegisterViewSerializer.country.help_text)
    unique_auth = serializers.BooleanField(required=False, help_text='Whether the account is allowed to be logged in from different devices simultaneously')


class AccessPostViewSerializer(serializers.Serializer):
    certification = serializers.CharField(max_length=150, help_text='User name or email or telephone')
    password = RegisterViewSerializer.password
    captcha_key = RegisterViewSerializer.captcha_key
    captcha_value = RegisterViewSerializer.captcha_value

    def validate_password(self, value):
        return validate_password(value)

    def validate(self, data):
        if getattr(settings, 'DEEPAUTH_CAPTCHA_NEED', False):
            validate_captcha(data)
        return data


class PasswordPostViewSerializer(serializers.Serializer):
    password_old = serializers.CharField(help_text='Current password')
    password_new = serializers.CharField(help_text='New password')
    password_confirm = serializers.CharField(help_text='Repeat new password')

    def validate_password_old(self, value):
        return validate_password(value)

    def validate_password_new(self, value):
        return validate_password(value)

    def validate_password_confirm(self, value):
        return validate_password(value)

    def validate(self, data):
        if data['password_old'] == data['password_new']:
            raise serializers.ValidationError('The new password must be different from the old password')
        if data['password_new'] != data['password_confirm']:
            raise serializers.ValidationError('The two new passwords must be the same')
        else:
            return data


class AdminAccountPutViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Account ID')
    avatar = AccountPutViewSerializer.avatar
    first_name = AccountPutViewSerializer.first_name
    last_name = AccountPutViewSerializer.last_name
    email = AccountPutViewSerializer.email
    tel = AccountPutViewSerializer.tel
    country = AccountPutViewSerializer.country
    unique_auth = AccountPutViewSerializer.unique_auth
    password = serializers.CharField(required=False, help_text=RegisterViewSerializer.password.help_text)
    is_active = serializers.BooleanField(required=False, help_text='Whether the account is allowed to be logged in')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class EmailVerificationPostViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Account ID')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class EmailVerificationPutViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Account ID')
    code = serializers.CharField(max_length=6, help_text='Activation code')

    def validate_id(self, value):
        return validate_id(Account, None, value)
