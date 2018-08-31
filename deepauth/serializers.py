from deeputils.serializers import *
from django.conf import settings
from django.utils import timezone

from .models import *
from .utils.captcha import validate_captcha
from .utils.password import validate_password


# Model serializers

class AccountSerializer(serializers.ModelSerializer):
    password = serializers.HiddenField(default=None)

    class Meta:
        model = Account
        fields = '__all__'


class AccessLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessLog
        fields = '__all__'


class PasswordLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordLog
        fields = '__all__'


class InvitationCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvitationCode
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
    invitation_code = serializers.UUIDField(required=False, default=None, help_text='Invitation code')
    captcha_key = serializers.CharField(max_length=40, min_length=40, required=getattr(settings, 'CAPTCHA_NEED', False), help_text='Captcha key (should hide from user), expires in 5 minutes')
    captcha_value = serializers.CharField(max_length=4, min_length=4, required=getattr(settings, 'CAPTCHA_NEED', False), help_text='Captcha value provided by user')

    def validate_username(self, value):
        if value is None:
            value = 'u' + str(int(timezone.now().timestamp() * 1000))
        try:
            Account.objects.get(username=value)
            raise serializers.ValidationError('Content is conflict.')
        except ObjectDoesNotExist:
            return value

    def validate_password(self, value):
        return validate_password(value)

    def validate_email(self, value):
        if value:
            accounts = Account.objects.filter(email=value)
            if accounts.count():
                raise serializers.ValidationError('Content is conflict.')
        return value

    def validate_invitation_code(self, value):
        if value is not None:
            try:
                InvitationCode.objects.get(id=value, user=None)
            except ObjectDoesNotExist:
                raise serializers.ValidationError(NotFound.default_detail)
        return value

    def validate(self, data):
        if getattr(settings, 'CAPTCHA_NEED', False):
            validate_captcha(data)
        if getattr(settings, 'DEEPAUTH_INVITATION_ONLY', False) and data['invitation_code'] is None and Account.objects.all().count():
            raise serializers.ValidationError('Invitation code is required.')
        if getattr(settings, 'DEEPAUTH_EMAIL_CONF', False) and settings.DEEPAUTH_EMAIL_CONF['required'] is True and data['email'] is None:
            raise serializers.ValidationError('Email is required.')
        return data


class LoginViewSerializer(serializers.Serializer):
    certification = serializers.CharField(max_length=150, help_text='User name or email or telephone')
    password = serializers.CharField(help_text='Password, hashed via MD5 is recommended')
    captcha_key = serializers.CharField(max_length=40, min_length=40, required=getattr(settings, 'CAPTCHA_NEED', False), help_text='Captcha key (should hide from user), expires in 5 minutes')
    captcha_value = serializers.CharField(max_length=4, min_length=4, required=getattr(settings, 'CAPTCHA_NEED', False), help_text='Captcha value provided by user')

    def validate_password(self, value):
        return validate_password(value)

    def validate(self, data):
        if getattr(settings, 'CAPTCHA_NEED', False):
            validate_captcha(data)
        return data


class LogoutViewSerializer(serializers.Serializer):
    pass


class PasswordGetViewSerializer(serializers.Serializer):
    pass


class PasswordPutViewSerializer(serializers.Serializer):
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
            raise serializers.ValidationError('The new password must be different from the old password.')
        if data['password_new'] != data['password_confirm']:
            raise serializers.ValidationError('The two new passwords must be the same.')
        else:
            return data


class DetailGetViewSerializer(serializers.Serializer):
    pass


class DetailPutViewSerializer(ModifyViewSerializer):
    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar', 'country', 'tel')
        super().__init__(*args, **kwargs)


class AdminAccountGetViewSerializer(serializers.Serializer):
    pass


class AdminAccountPutViewSerializer(ModifyViewSerializer):
    id = serializers.IntegerField(help_text='Account ID')

    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar', 'country', 'tel', 'password', 'is_active')
        super().__init__(*args, **kwargs)

    def validate_id(self, value):
        return validate_id(Account, None, value)


# class AdminAccountTreeViewSerializer(serializers.Serializer):
#     id = serializers.IntegerField()
#
#     def validate_id(self, value):
#         if value == 1:
#             raise serializers.ValidationError('Admin has no invitationCode.')
#         if getattr(settings, 'DEEPAUTH_INVITATION_ONLY', False) is False:
#             raise serializers.ValidationError('No need for invitationCode.')
#         return validate_id(Account, None, value)


class ActivateEmailViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Account ID')
    prefix = serializers.URLField(help_text='Callback URL, e.g., a link "http://example.org/?code=a&id=1" will be generated when set to "http://example.org/"')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class ValidateEmailViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='Account ID')
    code = serializers.UUIDField(help_text='The generated activation code')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class CaptchaGetViewSerializer(serializers.Serializer):
    pass
