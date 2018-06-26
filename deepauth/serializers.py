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
    first_name = serializers.CharField(max_length=30, help_text='用户称呼（名），不能超过 30 个字符')
    last_name = serializers.CharField(max_length=30, required=False, default='', help_text='用户称呼（姓），不能超过 30 个字符')
    username = serializers.CharField(max_length=150, required=False, default=None, help_text='用户名，不能超过 150 个字符，如不提供则会依照当前时间生成一个')
    password = serializers.CharField(help_text='密码，建议为 MD5 哈希结果')
    email = serializers.EmailField(required=False, default='', help_text='邮箱')
    tel = serializers.CharField(max_length=32, required=False, default=None, help_text='手机号码')
    country = serializers.CharField(max_length=8, required=False, default=None, help_text='国家')
    invitation_code = serializers.UUIDField(required=False, default=None, help_text='邀请码，可以不提供')
    captcha_key = serializers.CharField(max_length=40, min_length=40, required=getattr(settings, 'CAPTCHA_NEED', True), help_text='验证码的哈希值，建议隐藏，失效时间为 5 分钟')
    captcha_value = serializers.CharField(max_length=4, min_length=4, required=getattr(settings, 'CAPTCHA_NEED', True), help_text='验证码的答案')

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
        if getattr(settings, 'CAPTCHA_NEED', True):
            validate_captcha(data)
        if getattr(settings, 'DEEPAUTH_INVITATION_ONLY', False) and data['invitation_code'] is None and Account.objects.all().count():
            # 需要邀请码
            raise serializers.ValidationError('Invitation code is required.')
        if getattr(settings, 'DEEPAUTH_EMAIL_CONF', False) and settings.DEEPAUTH_EMAIL_CONF['required'] is True and data['email'] is None:
            raise serializers.ValidationError('Email is required.')
        return data


class LoginViewSerializer(serializers.Serializer):
    certification = serializers.CharField(max_length=150, help_text='用户名或邮箱或手机号')
    password = serializers.CharField(help_text='密码，建议为 MD5 哈希结果')
    captcha_key = serializers.CharField(max_length=40, min_length=40, required=getattr(settings, 'CAPTCHA_NEED', True), help_text='验证码 hash key 该字段需在前端页面隐藏')
    captcha_value = serializers.CharField(max_length=4, min_length=4, required=getattr(settings, 'CAPTCHA_NEED', True), help_text='验证码答案')

    def validate_password(self, value):
        return validate_password(value)

    def validate(self, data):
        if getattr(settings, 'CAPTCHA_NEED', True):
            validate_captcha(data)
        return data


class LogoutViewSerializer(serializers.Serializer):
    pass


class PasswordGetViewSerializer(serializers.Serializer):
    pass


class PasswordPutViewSerializer(serializers.Serializer):
    password_old = serializers.CharField(help_text='当前密码')
    password_new = serializers.CharField(help_text='新密码')
    password_confirm = serializers.CharField(help_text='重复新密码')

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
    field = serializers.CharField(help_text='修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、`email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）、`avatar` 用户头像、`country` 国家、`tel` 手机号码')
    value = serializers.CharField(help_text='修改内容，逗号分隔，必须与 `field` 长度相同')
    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar', 'country', 'tel')
        super().__init__(*args, **kwargs)


class AdminAccountGetViewSerializer(serializers.Serializer):
    pass


class AdminAccountPutViewSerializer(ModifyViewSerializer):
    id = serializers.IntegerField(help_text='用户 ID')
    field = serializers.CharField(help_text='修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、`email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）、`avatar` 用户头像、`country` 国家、`tel` 手机号码、`password` 密码、`is_active` 是否活跃')
    value = serializers.CharField(help_text='修改内容，逗号分隔，必须与 `field` 长度相同')

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
    id = serializers.IntegerField(help_text='用户 id')
    prefix = serializers.URLField(help_text='url 地址')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class ValidateEmailViewSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text='用户 ID')
    code = serializers.UUIDField(help_text='用户的激活码')

    def validate_id(self, value):
        return validate_id(Account, None, value)


class CaptchaGetViewSerializer(serializers.Serializer):
    pass
