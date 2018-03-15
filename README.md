# Deepera Authentication System
To use captcha, install the following items:
- apt-get -y install libz-dev libjpeg-dev libfreetype6-dev python-dev
- pip3 install  django-simple-captcha

To install, add the following items to your Django settings:
- `deepauth` to `INSTALLED_APPS`
- `captcha` to `INSTALLED_APPS`
- `AUTH_USER_MODEL = 'deepauth.Account'`

```
DEEPAUTH_INVITATION_ONLY = True
Invatitation code must be provided if set to true.

AUTO_LOGIN = True
User will auto login in when verify success if set to true.

DEEPAUTH_EMAIL_CONF = {
    'server': '',
    'port':465,
    'username': '',
    'password': '',
    'content':'Dear {0},\nPlease verify your account by clicking the following link:\n{1}\nYours sincerely,\nDeepauth Team',
}
```

0: name
1: link

To enable access, add the following code to your url patterns:
```
url(r'auth/', include('deepauth.urls'))
url(r'^captcha/', include('captcha.urls'))
```

To show docs, add the following code to your urls:
```
from rest_framework.documentation import include_docs_urls
urlpatterns = [
    url(r'docs/', include_docs_urls('API Docs'))
]
```

