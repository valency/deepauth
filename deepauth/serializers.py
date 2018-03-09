from deeputils.serializers import *

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


class AccountAvatarSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountAvatar
        fields = '__all__'


# View serializers

class RegisterViewSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30, required=False, default="")
    username = serializers.CharField(max_length=150, required=False)
    password = serializers.CharField()
    email = serializers.EmailField(required=False)
    invitation_code = serializers.CharField(max_length=40, required=False)
    phone_number = serializers.CharField(max_length=20, required=False)

    def validate_username(self, value):
        try:
            Account.objects.get(username=value)
            raise serializers.ValidationError('Content is conflict.')
        except ObjectDoesNotExist:
            return value

    def validate_password(self, value):
        return validate_password(value)

    def validate(self, data):
        from django.conf import settings
        if not settings.get('DEEPAUTH_INVITATION_ONLY'):      # 不需要邀请码
            if settings.get('DEEPAUTH_EMAIL_VERIFICATION'):   # 需要邮箱激活验证码
                if 'email' not in data:
                    raise serializers.ValidationError('Need a email')
            return data
        else:
            if settings.get('DEEPAUTH_EMAIL_VERIFICATION'):
                if 'email' not in data:
                    raise serializers.ValidationError('Need a email')
            if Account.objects.count() <= 0:   # 管理员不需要邀请码
                return data
            if 'invitation_code' not in data:
                raise serializers.ValidationError('Need a invitation code')
            elif InvitationCode.objects.filter(code=data['invitation_code']) is None:
                raise serializers.ValidationError('Invitation code error')
            else:
                return data


class LoginViewSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField()

    def validate_password(self, value):
        return validate_password(value)


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
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'avatar_url')
        super().__init__(*args, **kwargs)


class AdminAccountViewSerializer(ModifyViewSerializer):
    id = serializers.IntegerField()

    def __init__(self, *args, **kwargs):
        self.model = Account
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name', 'password', 'is_active')
        super().__init__(*args, **kwargs)

    def validate_id(self, value):
        return validate_id(Account, None, value)


class AvatarGetViewSerializer(serializers.Serializer):
    id = serializers.IntegerField()

    def validate_password(self, value):
        return validate_password(value)


class AvatarPostViewSerializer(serializers.Serializer):
    avatar = serializers.ImageField()
    public = models.BooleanField(default=False)
    t_create = models.DateTimeField(auto_now_add=True)
    t_modify = models.DateTimeField(auto_now=True)
    status = models.IntegerField()


class ActivateViewSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    prefix = serializers.URLField()

    def validate_id(self, value):
        obj = Account.objects.filter(pk=id)
        if obj is None:
            raise serializers.ValidationError(NotFound.default_detail)
        return value


class ValidateViewSerializer(ObjectGetViewSerializer):
    id = serializers.IntegerField()
    code = serializers.CharField(min_length=36, max_length=40)

    def validate_id(self, value):
        obj = Account.objects.filter(pk=id)
        if obj is None:
            raise serializers.ValidationError(NotFound.default_detail)
        return value


class InvitationCodeViewSerializer(ObjectGetViewSerializer):
    user_id = serializers.IntegerField()

    def validate_id(self, value):
        obj = Account.objects.filter(pk=id)
        if obj is None:
            raise serializers.ValidationError(NotFound.default_detail)
        return value

class ImagePostViewSerializer(serializers.Serializer):
    avatar = serializers.ImageField(max_length=1024 * 1024)
