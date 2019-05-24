from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist

from deepauth.models import Account


def auth_password(identities: list, password):
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
