import json
from datetime import timedelta
from io import BytesIO

import pycurl
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

TOKEN_LIFETIME = 7


class DeepauthAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        e = BytesIO()
        c = pycurl.Curl()
        c.setopt(pycurl.URL, settings.DEEPAUTH_URL + 'detail/')
        c.setopt(pycurl.HTTPHEADER, ['Authorization: Token ' + key])
        c.setopt(c.WRITEFUNCTION, e.write)
        c.perform()
        resp_body = e.getvalue().decode('UTF-8')
        resp_status = c.getinfo(pycurl.HTTP_CODE)
        if resp_status != 200:
            # TODO: what if not json?
            raise exceptions.AuthenticationFailed(json.loads(resp_body))
        else:
            # TODO: should return user and token
            return None


class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))
        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))
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
