from distutils.core import setup

setup(
    name='deepauth',
    version='1.4.29',
    packages=['deepauth', 'deepauth.utils'],
    url='https://github.com/valency/deepauth',
    download_url='https://github.com/valency/deepauth/releases/download/v1.4.29/deepauth-1.4.29.tar.gz',
    license='CPL-3.0',
    author='Deepera Co., Ltd.',
    author_email='yding@deepera.com',
    description='Deepera Authentication System',
    install_requires=[
        'django',
        'django-ipware',
        'djangorestframework',
        'django-simple-captcha'
    ],
)
