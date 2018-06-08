from distutils.core import setup

setup(
    name='deepauth',
    version='1.6.8',
    packages=['deepauth', 'deepauth.utils'],
    url='https://github.com/valency/deepauth',
    download_url='https://github.com/valency/deepauth/releases/download/v1.6.8/deepauth-1.6.8.tar.gz',
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
