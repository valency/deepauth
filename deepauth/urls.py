from django.conf.urls import url

from .views import *

urlpatterns = [
    # Public
    url(r'register/$', RegisterView.as_view({
        'post': 'create',
    })),
    url(r'login/$', LogInView.as_view({
        'post': 'create',
    })),
    url(r'captcha/$', CaptchaView.as_view({
        'get': 'list'
    })),
    # Private
    url(r'account/$', AccountView.as_view({
        'get': 'list',
        'put': 'update'
    })),
    url(r'access/$', AccessView.as_view({
        'get': 'list',
        'delete': 'destroy'
    })),
    url(r'password/$', PasswordView.as_view({
        'put': 'update'
    })),
    url(r'verify/email/$', EmailVerificationView.as_view({
        'post': 'create',
        'put': 'update'
    })),
    # Admin
    url(r'admin/account/$', AdminAccountView.as_view({
        'get': 'list',
        'put': 'update'
    })),
]
