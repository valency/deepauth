from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers

from deepauth.models import Account

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


def auth_password(identities, password):
    """
    Authentication using password
    :param identities: An array containing dictionaries with identity field and value, e.g., [{'username':'u001'}]
    :param password: Password of the corresponding account
    :return: Account ORM if authenticated, or None if not
    """
    if not len(identities):
        return None
    else:
        identity = identities[0]
        if next(iter(identity.values())) is not None:
            try:
                account = authenticate(username=Account.objects.get(**identity).username, password=password)
                if account is None:
                    return auth_password(identities[1:], password)
                else:
                    return account
            except ObjectDoesNotExist:
                return auth_password(identities[1:], password)
        else:
            return auth_password(identities[1:], password)
