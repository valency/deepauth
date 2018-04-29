from captcha.models import CaptchaStore
from rest_framework import serializers


def validate_captcha(data):
    captcha_key = data['captcha_key']
    captcha_value = data['captcha_value'].lower()
    CaptchaStore.remove_expired()
    captcha = CaptchaStore.objects.filter(hashkey=captcha_key, response=captcha_value)
    if captcha.count() <= 0:
        raise serializers.ValidationError('Captcha is not correct.')
