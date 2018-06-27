from django.conf.urls import url

from .views import *

urlpatterns = [
    # ------- Single User Management -------
    url(r'register/$', RegisterView.as_view({
        'post': 'create'
    })),
    url(r'login/$', LoginView.as_view({
        'get': 'list'
    })),
    url(r'logout/$', LogoutView.as_view({
        'post': 'create'
    })),
    url(r'password/$', PasswordView.as_view({
        'get': 'list',
        'put': 'update'
    })),
    url(r'detail/$', DetailView.as_view({
        'get': 'list',
        'put': 'update'
    })),
    url(r'captcha/$', CaptchaView.as_view({
        'get': 'list'
    })),
    url(r'email/activate/$', ActivateEmailView.as_view({
        'get': 'list'
    })),
    url(r'email/validate/$', ValidateEmailView.as_view({
        'get': 'list'
    })),
    # ------- Multiple User Management (Admin Only) -------
    url(r'admin/account/$', AdminAccountView.as_view({
        'get': 'list',
        'post': 'update'
    })),
    # url(r'admin/account/tree/$', AdminAccountTreeView.as_view()),
]
