from os import path

from setuptools import setup, find_packages

with open(path.join(path.abspath(path.dirname(__file__)), 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='deepauth',
    version='1.9.1',
    packages=find_packages(),
    include_package_data=True,
    url='https://github.com/valency/deepauth/',
    author='Deepera Co., Ltd.',
    author_email='yding@deepera.com',
    description='Deepera Authentication System',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    keywords=['tokenetf', 'tokenmds', 'mds'],
    install_requires=[
        'django',
        'django-ipware',
        'djangorestframework',
        'django-simple-captcha',
        'deeputils'
    ]
)
