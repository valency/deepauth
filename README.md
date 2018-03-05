# Deepera Authentication System
To install, add the following items to your Django settings:
- `deepauth` to `INSTALLED_APPS`
- `AUTH_USER_MODEL = 'deepauth.Account'`
```
DEEPAUTH_INVITATION_ONLY = True
DEEPAUTH_EMAIL_VERIFICATION = {
    'server': '',
    'username': '',
    'password': ''
}
```

To enable access, add the following code to your url patterns:
```
url(r'auth/', include('deepauth.urls'))
```

To show docs, add the following code to your urls:
```
from rest_framework.documentation import include_docs_urls
urlpatterns = [
    url(r'docs/', include_docs_urls('API Docs'))
]
```
