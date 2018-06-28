from distutils.core import setup

setup(
    name='deepauth',
    version='1.6.28',
    packages=['deepauth', 'deepauth.utils'],
    url='https://github.com/valency/deepauth',
    license='CPL-3.0',
    author='Deepera Co., Ltd.',
    author_email='yding@deepera.com',
    description='Deepera Authentication System',
    install_requires=[
        'django',
        'django-ipware',
        'djangorestframework',
        'django-simple-captcha',
        'deeputils'
    ],
)
