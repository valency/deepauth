# Deepera Authentication System
To use captcha, install the following items:
- apt-get -y install libz-dev libjpeg-dev libfreetype6-dev python-dev

To install, add the following items to your Django settings:
- `deepauth` to `INSTALLED_APPS`
- `captcha` to `INSTALLED_APPS`
- `AUTH_USER_MODEL = 'deepauth.Account'`

```
DEEPAUTH_INVITATION_ONLY = True
Invatitation code must be provided if set to true.

DEEPAUTH_AUTO_LOGIN = True
User will auto login in when verify success if set to true.

TEAM_NAME = 'AgileQuant'
Customize user emails with this parameter.

TOKEN_LIFETIME = 7
Set token expired time in django.settings.py, default 7 days if not set, token will not expired if set None.

USERNAME_NEED = False
Set whether username is needed when register in django.settings.py, default False.

EMAIL_NEED = False
Set whether email is needed when register in django.settings.py, default False.

PHONE_NEED = False
Set whether phone is needed when register in django.settings.py, default False.

CAPTCHA_NEED = False
Set whether captcha is needed when register and login in django.settings.py, default False.

DEEPAUTH_EMAIL_CONF = {
    'required': True,
    'server': 'smtp.agilequant.io',
    'port': 465,
    'username': 'noreply@agilequant.io',
    'password': '06rS1T#c$42i',
    'subject': 'Activate Your Account',
    'content': 'Dear {0},\nPlease verify your account by clicking the following link:\n{1}\nYours sincerely,\nAgileQuant Team',
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

