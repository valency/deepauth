from rest_framework import serializers

from ..models import Account

EMPTY_MD5 = 'd41d8cd98f00b204e9800998ecf8427e'


def validate_password(value):
    value = value.lower()
    if value == EMPTY_MD5:
        raise serializers.ValidationError('This field may not be empty encryption value.')
    else:
        return value


def change_password(account, password):
    account.set_password(password)
    account.save()
    try:
        account.auth_token.delete()
    except Account.auth_token.RelatedObjectDoesNotExist:
        pass
