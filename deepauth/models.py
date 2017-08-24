from django.contrib.auth.models import AbstractUser
from django.db import models


class Account(AbstractUser):
    unique_auth = models.BooleanField(default=True)


class AccessLog(models.Model):
    account = models.ForeignKey(Account)
    t = models.DateTimeField(auto_now=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    token = models.CharField(max_length=40)
