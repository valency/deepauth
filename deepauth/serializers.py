from captcha.models import CaptchaStore
from deeputils.serializers import *
from django.conf import settings
from django.utils import timezone

from .models import *
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
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30, required=False, default='')
    username = serializers.CharField(max_length=150, required=False, default=None)
    password = serializers.CharField()
    email = serializers.EmailField(required=False, default='')
    tel = serializers.CharField(max_length=32, required=False, default=None)
    country = serializers.CharField(max_length=8, required=False, default=None)
    invitation_code = serializers.UUIDField(required=False, default=None)  # 邀请码，可以不提供
    hashkey = serializers.CharField(max_length=40, min_length=40)  # 验证码 hashkey 该字段需在前端页面隐藏
    response = serializers.CharField(max_length=4, min_length=4)  # 验证码答案

    def validate_username(self, value):
        if value is None:
            value = 'u' + str(timezone.now().timestamp())
            return value
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
        hashkey = data['hashkey']
        response = data['response'].lower()
        CaptchaStore.remove_expired()
        captcha = CaptchaStore.objects.filter(hashkey=hashkey, response=response)
        if captcha.count() <= 0:
            raise serializers.ValidationError('The value of captcha is not correct.')
        if getattr(settings, 'DEEPAUTH_INVITATION_ONLY', False) and data['invitation_code'] is None \
                and Account.objects.all().count():
            # 需要邀请码
            raise serializers.ValidationError('Invitation code is required.')
        if hasattr(settings, 'DEEPAUTH_EMAIL_CONF') and data['email'] is None:
            # 需要邮箱
            raise serializers.ValidationError('Email is required.')
        return data


class LoginViewSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField()
    hashkey = serializers.CharField(max_length=40, min_length=40)  # 验证码 hashkey 该字段需在前端页面隐藏
    response = serializers.CharField(max_length=4, min_length=4)  # 验证码答案

    def validate_password(self, value):
        return validate_password(value)

    def validate(self, data):
        hashkey = data['hashkey']
        response = data['response'].lower()
        CaptchaStore.remove_expired()
        captcha = CaptchaStore.objects.filter(hashkey=hashkey, response=response)
        if captcha.count() <= 0:
            raise serializers.ValidationError('The value of captcha is not correct.')
        if 'username' not in data and 'email' not in data:
            raise serializers.ValidationError('Email or username is required.')
        return data


class PasswordViewSerializer(serializers.Serializer):
    password_old = serializers.CharField()
    password_new = serializers.CharField()
    password_confirm = serializers.CharField()

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


class DetailViewSerializer(ModifyViewSerializer):
    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar', 'country', 'tel')
        super().__init__(*args, **kwargs)


class AdminAccountViewSerializer(ModifyViewSerializer):
    id = serializers.IntegerField()

    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar', 'country', 'tel', 'password', 'is_active')
        super().__init__(*args, **kwargs)

    def validate_id(self, value):
        return validate_id(Account, None, value)


class ActivateEmailViewSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    prefix = serializers.URLField()

    def validate_id(self, value):
        return validate_id(Account, None, value)


class ValidateEmailViewSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    code = serializers.UUIDField()

    def validate_id(self, value):
        return validate_id(Account, None, value)
