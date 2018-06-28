from datetime import timedelta

from captcha.helpers import captcha_image_url
from captcha.models import CaptchaStore
from deeputils.schemas import RefinedViewSet
from django.contrib.auth import authenticate
from ipware.ip import get_ip
from rest_framework import status
from rest_framework.authentication import BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ParseError, NotAcceptable
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response

from .serializers import *
from .utils.mailbox import send_mail
from .utils.password import change_password, auth_password
from .utils.token import TOKEN_LIFETIME, ExpiringTokenAuthentication


class RegisterView(RefinedViewSet):
    """
        create:
        Register a new account. Returns:

        ```json
        {
            "id": 13,
            "username": "eva"
        }
        ```
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)

    serializer_classes = {
        'create': RegisterViewSerializer,
    }

    def create(self, request):
        pp = self.get_serializer(data=request.data)
        if pp.is_valid():
            first_name = pp.validated_data['first_name']
            last_name = pp.validated_data['last_name']
            username = pp.validated_data['username']
            password = pp.validated_data['password']
            email = pp.validated_data['email']
            tel = pp.validated_data['tel']
            country = pp.validated_data['country']
            invitation_code = pp.validated_data['invitation_code']
            # Create user
            conf = dict(username=username, password=password, first_name=first_name, last_name=last_name, email=email, tel=tel, country=country)
            if Account.objects.count():
                account = Account.objects.create_user(**conf)
            else:
                account = Account.objects.create_superuser(**conf)
            account.save()
            # Update password log
            password_log = PasswordLog(account=account, ip=get_ip(request), password=account.password)
            password_log.save()
            if invitation_code:
                # 用户注册完后, 邀请码失效
                invitation_code = InvitationCode.objects.get(id=invitation_code, user=None)
                invitation_code.user = account
                invitation_code.save()
            # 赠送邀请码
            for i in range(INVITATION_LIMIT):
                # for i in range(getattr(settings, 'DEEPAUTH_INVITATION_ONLY', 10)):
                invitation_code = InvitationCode(account=account)
                invitation_code.save()
            return Response({'id': account.id, 'username': account.username}, status=status.HTTP_201_CREATED)
        else:
            raise ParseError(pp.errors)


class LoginView(RefinedViewSet):
    """
        list:
        Log in. Returns:

        ```json
        {
            "id": 13,
            "token": "618639977ca9ee3dc13adb528386ee79f7ef35ac"
        }
        ```
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)

    serializer_classes = {
        'list': LoginViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            certification = pp.validated_data['certification']
            password = pp.validated_data['password']
            # 用户优先以用户名账号登录
            account = auth_password([{'username': certification}, {'email': certification}, {'tel': certification}], password)
            if account is not None:
                token, has_created = Token.objects.get_or_create(user=account)
                if account.unique_auth or timezone.now() > (token.created + timedelta(days=TOKEN_LIFETIME)):
                    Token.objects.filter(user=account).update(key=token.generate_key(), created=timezone.now())
                token = Token.objects.get(user=account)
                access_log = AccessLog(account=account, ip=get_ip(request), token=token)
                access_log.save()
                return Response({'id': account.id, 'token': token.key})
            else:
                raise NotAuthenticated()
        else:
            raise ParseError(pp.errors)


class LogoutView(RefinedViewSet):
    """
        create:
        Log out.
    """

    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    serializer_classes = {
        'create': LogoutViewSerializer,
    }

    def create(self, request):
        pp = self.get_serializer(data=request.data)
        if pp.is_valid():
            request.user.auth_token.delete()
            return Response()
        else:
            raise ParseError(pp.errors)


class PasswordView(RefinedViewSet):
    """
        list:
        Retrieve password history. Returns:

        ```json
        [
            {
                "id": 13,
                "t": "2018-06-27T07:20:34.733891Z",
                "ip": "192.168.1.129",
                "password": "pbkdf2_sha256$100000$1uV5KjDca2sF$Hh/19HvjlfdcBvOMg/OWPutQlnRJ2Wjw8otXz+xCWAg=",
                "account": 13
            }
        ]
        ```

        update:
        Change password. Returns 202 if successful.
    """

    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    serializer_classes = {
        'list': PasswordGetViewSerializer,
        'update': PasswordPutViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            account = Account.objects.get(pk=request.user.pk)
            return Response(PasswordLogSerializer(PasswordLog.objects.filter(account=account)[:10], many=True).data)
        else:
            raise ParseError(pp.errors)

    def update(self, request):
        pp = self.get_serializer(data=request.data)
        if pp.is_valid():
            username = request.user.username
            password_old = pp.validated_data['password_old']
            password_new = pp.validated_data['password_new']
            account = authenticate(username=username, password=password_old)
            if account is not None:
                change_password(account, password_new)
                password_log = PasswordLog(account=account, ip=get_ip(request), password=account.password)
                password_log.save()
                return Response(status=status.HTTP_202_ACCEPTED)
            else:
                raise NotAuthenticated()
        else:
            raise ParseError(pp.errors)


class DetailView(RefinedViewSet):
    """
        list:
        <span class='badge'><i class='fa fa-lock'></i></span>
        Get account details. Returns:

        ```json
        {
            "id": 13,
            "last_login": null,
            "is_superuser": false,
            "username": "eva",
            "first_name": "eva",
            "last_name": "",
            "email": "",
            "is_staff": false,
            "is_active": true,
            "date_joined": "2018-06-27T07:20:34.623735Z",
            "avatar": null,
            "country": null,
            "tel": null,
            "unique_auth": true,
            "verified_email": false,
            "verified_tel": false,
            "verification_email_code": null,
            "verification_email_t": null,
            "groups": [],
            "user_permissions": [],
            "access_log": [
                {
                    "id": 14,
                    "t": "2018-06-27T07:21:27.486975Z",
                    "ip": "192.168.1.129",
                    "token": "618639977ca9ee3dc13adb528386ee79f7ef35ac",
                    "account": 13
                }
            ],
            "invitation_code": [
                {
                    "id": "15665b7a-dfdd-440d-8777-b69b59567988",
                    "account": 13,
                    "user": null
                }
            ]
        }
        ```

        update:
        <span class='badge'><i class='fa fa-lock'></i></span>
        Update account details. Returns 202 if successful. Allowed fields: `unique_auth`, `email`, `first_name`, `last_name`, `avatar`, `country`, `tel`.
    """

    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    serializer_classes = {
        'list': DetailGetViewSerializer,
        'update': DetailPutViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            account = Account.objects.get(pk=request.user.pk)
            resp = AccountSerializer(account).data
            resp['access_log'] = AccessLogSerializer(AccessLog.objects.filter(account=account)[:10], many=True).data
            resp['invitation_code'] = InvitationCodeSerializer(InvitationCode.objects.filter(account=account, user=None), many=True).data
            return Response(resp)
        else:
            raise ParseError(pp.errors)

    def update(self, request):
        account = Account.objects.get(pk=request.user.pk)
        pp = self.get_serializer(data=request.data)
        if pp.is_valid():
            if 'email' in pp.validated_data:
                email = pp.validated_data['email']
                try:
                    Account.objects.get(email=email)
                    raise NotAcceptable('Email has already been registered.')
                except ObjectDoesNotExist:
                    account.email = email
                    account.verified_email = False
                    account.save()
                    del pp.validated_data['email']
            Account.objects.filter(pk=request.user.pk).update(**dict(pp.validated_data))
            return Response(status=status.HTTP_202_ACCEPTED)
        else:
            raise ParseError(pp.errors)


class AdminAccountView(RefinedViewSet):
    """
        list:
        <span class='badge'><i class='fa fa-lock'></i></span>
        <span class='badge'><i class='fa fa-cog'></i></span>
        Retrieve the details of all accounts. Returns:

        ```json
        [
            {
                "id": 1,
                "last_login": null,
                "is_superuser": true,
                "username": "u1529547733083",
                "first_name": "user",
                "last_name": "",
                "email": "",
                "is_staff": true,
                "is_active": true,
                "date_joined": "2018-06-21T02:22:13.086712Z",
                "avatar": null,
                "country": null,
                "tel": null,
                "unique_auth": true,
                "verified_email": false,
                "verified_tel": false,
                "verification_email_code": null,
                "verification_email_t": null,
                "groups": [],
                "user_permissions": []
            }
        ]
        ```

        update:
        <span class='badge'><i class='fa fa-lock'></i></span>
        <span class='badge'><i class='fa fa-cog'></i></span>
        Update the details of a specific account. Returns 202 if successful. Allowed fields: `unique_auth`, `email`, `first_name`, `last_name`, `avatar`, `country`, `tel`, `password`, `is_active`.
    """

    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAdminUser,)

    serializer_classes = {
        'list': AdminAccountGetViewSerializer,
        'update': AdminAccountPutViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            return Response(AccountSerializer(Account.objects.all(), many=True).data)
        else:
            raise ParseError(pp.errors)

    def update(self, request):
        pp = self.get_serializer(data=request.data)
        if pp.is_valid():
            uid = pp.validated_data['id']
            account = Account.objects.get(pk=uid)
            del pp.validated_data['id']
            if 'password' in pp.validated_data:
                password = pp.validated_data['password']
                change_password(account, password)
                del pp.validated_data['password']
            if 'email' in pp.validated_data:
                email = pp.validated_data['email']
                try:
                    Account.objects.get(email=email)
                    raise NotAcceptable('Email has already been registered.')
                except ObjectDoesNotExist:
                    account.email = email
                    account.verified_email = False
                    account.save()
                    del pp.validated_data['email']
            Account.objects.filter(pk=uid).update(**dict(pp.validated_data))
            return Response(status=status.HTTP_202_ACCEPTED)
        else:
            raise ParseError(pp.errors)


# class AdminAccountTreeView(RefinedViewSet):
#     """
#     get:
#     - <span class='badge'>R</span> `id` 用户 ID
#     """
#     authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
#     permission_classes = (IsAdminUser,)
#     serializer_class = AdminAccountTreeViewSerializer
#
#     def get(self, request):
#         pp = self.serializer_class(data=request.GET)
#         if pp.is_valid():
#             account = Account.objects.get(pk=pp.validated_data['id'])
#             invitation_code = InvitationCode.objects.get(user=account)
#             account_list = [account]
#             while invitation_code.account.id != 1:
#                 account = invitation_code.account
#                 account_list.append(account)
#                 invitation_code = InvitationCode.objects.get(user=account)
#             account_list.append(invitation_code.account)
#             return Response(AccountSerializer(account_list, many=True).data)
#         else:
#             raise ParseError(pp.errors)


class ActivateEmailView(RefinedViewSet):
    """
        list:
        Activate email. Returns 200 if successful.
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = ActivateEmailViewSerializer

    serializer_classes = {
        'list': ActivateEmailViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            uid = pp.validated_data['id']
            prefix = pp.validated_data['prefix']
            account = Account.objects.get(pk=uid)
            # 确定邮箱设定有提供
            if getattr(settings, 'DEEPAUTH_EMAIL_CONF', None) is None:
                raise NotImplementedError
            email_conf = settings.DEEPAUTH_EMAIL_CONF
            # 已经激活的用户不再发激活码
            if account.verified_email:
                raise NotAcceptable('Email has already been verified.')
            account.verification_email_code = uuid.uuid4()
            account.verification_email_t = timezone.now()
            account.save()
            content = email_conf['content'].format(account.first_name, prefix + '?' + 'code=' + str(account.verification_email_code) + '&' + 'id=' + str(uid))
            try:
                send_mail(email_conf['server'], email_conf['port'], email_conf['username'], email_conf['password'], account.email, email_conf['subject'], content)
            except Exception as exp:
                raise exp
            return Response(status=status.HTTP_200_OK)
        else:
            raise ParseError(pp.errors)


class ValidateEmailView(RefinedViewSet):
    """
        list:
        Update email. Returns 202 if successful.
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)

    serializer_classes = {
        'list': ValidateEmailViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            uid = pp.validated_data['id']
            code = pp.validated_data['code']
            account = Account.objects.get(pk=uid)
            if account.verified_email:
                raise NotAcceptable('Email has already been verified.')
            if account.verification_email_t is None or account.verification_email_code is None:
                raise NotAcceptable('Verification code has not been generated yet.')
            if timezone.now().timestamp() - account.verification_email_t.timestamp() <= VALIDATION_TIME_LIMIT:
                if code == account.verification_email_code:
                    account.verified_email = True
                    account.verification_email_code = None
                    account.verification_email_t = None
                    account.save()
                    if not getattr(settings, 'DEEPAUTH_AUTO_LOGIN', None):
                        return Response(status=status.HTTP_200_OK)
                    else:
                        token, has_created = Token.objects.get_or_create(user=account)
                        if account.unique_auth or timezone.now() > (token.created + timedelta(days=TOKEN_LIFETIME)):
                            Token.objects.filter(user=account).update(key=token.generate_key(),
                                                                      created=timezone.now())
                        token = Token.objects.get(user=account)
                        access_log = AccessLog(account=account, ip=get_ip(request), token=token)
                        access_log.save()
                        return Response({'token': token.key})
                else:
                    raise NotAcceptable('Verification code is not correct.')
            else:
                raise NotAcceptable('Verification code is expired.')
        else:
            raise ParseError(pp.errors)


class CaptchaView(RefinedViewSet):
    """
        list:
        <span class='badge'><i class='fa fa-lock'></i></span>
        Generate and get a captcha. Returns:

        ```json
        {
            "key": "da8fa92734b779bcb6d2cac4b96b83cf002e07cf",
            "url": "/captcha/image/da8fa92734b779bcb6d2cac4b96b83cf002e07cf/"
        }
        ```
    """

    authentication_classes = ()
    permission_classes = (AllowAny,)

    serializer_classes = {
        'list': CaptchaGetViewSerializer,
    }

    def list(self, request):
        pp = self.get_serializer(data=request.GET)
        if pp.is_valid():
            CaptchaStore.remove_expired()  # 删除失效的验证码，过期时间为五分钟
            captcha_key = CaptchaStore.pick()
            to_json_response = {
                'key': captcha_key,
                'url': captcha_image_url(captcha_key),
            }
            return Response(to_json_response)
        else:
            raise ParseError(pp.errors)
