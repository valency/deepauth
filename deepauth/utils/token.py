from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

TOKEN_LIFETIME = 7


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User is not active.'))
        if timezone.now() > (token.created + timedelta(days=TOKEN_LIFETIME)):
            raise exceptions.AuthenticationFailed(_('Token is expired.'))
        return token.user, token


class GeneralTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            user = model.objects.select_related('user').get(key=key).user
        except model.DoesNotExist:
            user = AnonymousUser
        return user, key
