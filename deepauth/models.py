from django.contrib.auth.models import AbstractUser
from django.db import models

INVITATION_LIMIT = 10
VALIDATION_TIME_LIMIT = 24 * 60 * 60

class Account(AbstractUser):
    unique_auth = models.BooleanField(default=True)
    verified_email = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=40, null=True, blank=True)
    verification_created = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)
    avatar_url = models.URLField(null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)


class AccessLog(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    t = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    token = models.CharField(max_length=40)


class PasswordLog(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    t = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    password = models.CharField(max_length=32)


class InvitationCode(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    code = models.CharField(max_length=40, unique=True)
    is_used = models.BooleanField(default=False)


class AccountAvatar(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    avatar = models.BinaryField()
    public = models.BooleanField(default=False)
    t_create = models.DateTimeField(auto_now_add=True)
    t_modify = models.DateTimeField(auto_now=True)
    status = models.IntegerField()
