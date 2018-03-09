from django.conf.urls import url

from deepauth.views import *

urlpatterns = [
    # ------- Single User Management -------
    url(r'register/$', RegisterView.as_view()),
    url(r'login/$', LoginView.as_view()),
    url(r'logout/$', LogoutView.as_view()),
    url(r'password/$', PasswordView.as_view()),
    url(r'detail/$', DetailView.as_view()),
    # url(r'upload/$', UploadView.as_view()),
    url(r'invitaioncodes/', InvitationCodeView.as_view()),
    url(r'activate/', ActivateView.as_view()),
    url(r'validate/', ValidateView.as_view()),
    url(r'upavatar/', AvatarView.as_view()),
    # ------- Multiple User Management (Admin Only) -------
    url(r'admin/account/$', AdminAccountView.as_view())
]
