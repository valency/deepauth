from django.contrib.auth.models import AbstractUser
from django.db import models

VERIFICATION_TIME_LIMIT = 24 * 60 * 60


class Account(AbstractUser):
    avatar = models.URLField(null=True, blank=True)
    country = models.CharField(max_length=8, null=True, blank=True)
    tel = models.CharField(max_length=32, null=True, blank=True)
    unique_auth = models.BooleanField(default=True)
    verified_email = models.BooleanField(default=False)
    verified_tel = models.BooleanField(default=False)
    verification_email_code = models.CharField(max_length=6, null=True, blank=True)
    verification_email_t = models.DateTimeField(null=True, blank=True)
    verification_tel_code = models.CharField(max_length=6, null=True, blank=True)
    verification_tel_t = models.DateTimeField(null=True, blank=True)
    invitation_code = models.CharField(max_length=32, null=True, blank=True, unique=True)


class Access(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    t = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    token = models.CharField(max_length=40)


class Password(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    t = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    password = models.CharField(max_length=128)


class Invitation(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='invitation_account')
    user = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, blank=True, related_name='invitation_user')
