from django.conf.urls import url

from deepauth.views import *

urlpatterns = [
    # ------- Single User Management -------
    url(r'register/$', RegisterView.as_view()),
    url(r'login/$', LoginView.as_view()),
    url(r'logout/$', LogoutView.as_view()),
    url(r'password/$', PasswordView.as_view()),
    url(r'detail/$', DetailView.as_view()),
    url(r'captcha/$', CaptchaView.as_view()),
    url(r'email/activate/$', ActivateEmailView.as_view()),
    url(r'email/validate/$', ValidateEmailView.as_view()),
    # ------- Multiple User Management (Admin Only) -------
    url(r'admin/account/$', AdminAccountView.as_view()),
    # url(r'admin/account/tree/$', AdminAccountTreeView.as_view()),
]
