from captcha.models import CaptchaStore
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from rest_framework.exceptions import NotFound, NotAuthenticated

EMPTY_MD5 = 'd41d8cd98f00b204e9800998ecf8427e'


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


def validate_password(value):
    value = value.lower()
    if value == EMPTY_MD5:
        raise serializers.ValidationError('This field may not be empty MD5 value.')
    else:
        return value


def validate_captcha(key, value):
    value = value.lower()
    CaptchaStore.remove_expired()
    captcha = CaptchaStore.objects.filter(hashkey=key, response=value)
    if not captcha.count():
        raise serializers.ValidationError('Captcha is not correct.')
