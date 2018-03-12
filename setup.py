from distutils.core import setup

setup(
    name='deepauth',
    version='1.3.12',
    packages=['deepauth', 'deepauth.utils'],
    url='http://open.deepera.com',
    license='CPL-3.0',
    author='Deepera Co., Ltd.',
    author_email='yding@deepera.com',
    description='Deepera Authentication System',
    install_requires=[
        'django',
        'django-ipware',
        'djangorestframework'
    ],
)
