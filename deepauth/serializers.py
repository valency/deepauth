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


# View serializers

class RegisterViewSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30, required=False, default="")
    username = serializers.CharField(max_length=150)
    password = serializers.CharField()
    email = serializers.EmailField(required=False)

    def validate_username(self, value):
        try:
            Account.objects.get(username=value)
            raise serializers.ValidationError(Conflict.default_detail)
        except ObjectDoesNotExist:
            return value

    def validate_password(self, value):
        return validate_password(value)


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
        self.allowed_fields = ('unique_auth', 'email', 'first_name', 'last_name')
        self.model = Account
        super().__init__(*args, **kwargs)


class AdminAccountViewSerializer(ObjectModifyViewSerializer):
    def __init__(self, *args, **kwargs):
        self.allowed_fields = ('password', 'is_active', 'unique_auth', 'email', 'nickname')
        self.model = Account
        super().__init__(*args, **kwargs)
