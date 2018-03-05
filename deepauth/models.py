from django.contrib.auth.models import AbstractUser
from django.db import models

INVITATION_LIMIT = 10


class Account(AbstractUser):
    unique_auth = models.BooleanField(default=True)
    verified_email = models.BooleanField(default=False)


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
