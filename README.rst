=============================
Deepera Authentication System
=============================

To use captcha, install the following packages:

.. code:: bash

    sudo apt install libz-dev libjpeg-dev libfreetype6-dev python-dev

To install, add `deepauth` and `captcha` to `INSTALLED_APPS`  in your Django settings.

Compulsory configurations:

.. code:: python

    AUTH_USER_MODEL = 'deepauth.Account'
    DEEPAUTH_EMAIL_CONF = {
        'required': True,
        'server': 'smtp.example.com',
        'port': 465,
        'username': 'noreply@example.com',
        'password': 'moc.elpmaxe',
        'subject': 'Activate Your Account',
        'content': 'Dear {0},\nPlease verify your account by clicking the following link:\n{1}\nYours sincerely,\nExample.com',
    }


Optional configurations:

.. code:: python

    DEEPAUTH_INVITATION_ONLY = False
    # Invatitation code must be provided if set to true.

    DEEPAUTH_AUTO_LOGIN = False
    # User will be logged in after certain actions (currently only work for updating email).

    TOKEN_LIFETIME = 7
    # Token will be expired after certain days.

To enable access, add the following URLs to your URL patterns:

.. code:: python

    url(r'^auth/', include('deepauth.urls')),
    url(r'^captcha/', include('captcha.urls'))


To show docs, add the following code to your URLs:

.. code:: python

    from rest_framework.documentation import include_docs_urls
    urlpatterns = [
        url(r'^docs/', include_docs_urls('API Docs'))
    ]


