import os
from django.contrib.auth import authenticate
import uuid
import time
from deepauth.utils.email_send import send_mail
from ipware.ip import get_ip
from rest_framework import status
from rest_framework.authentication import BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ParseError
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import *
from .utils.password import *
from .utils.token import *

FILE_PATH = settings['STATICFILES_DIRS']
FILE_URL = settings['STATIC_URL']

class RegisterView(APIView):
    """
    post:
    **注册用户**

    - <span class='badge'>R</span> `username` 用户名，不能超过 150 个字符
    - <span class='badge'>R</span> `password` 密码，建议为 MD5 哈希结果
    - <span class='badge'>R</span> `first_name` 用户称呼（名），不能超过 30 个字符
    - `email` 邮箱
    - `last_name` 用户称呼（姓），不能超过 30 个字符
    - `invitation_code` 邀请码
    - `phone_number` 手机号码
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = RegisterViewSerializer

    def post(self, request):
        pp = self.serializer_class(data=request.data)
        if pp.is_valid():
            first_name = pp.validated_data['first_name']
            last_name = pp.validated_data['last_name']
            username = pp.validated_data['username']
            password = pp.validated_data['password']
            email = pp.validated_data['email'] if 'email' in pp.validated_data else None
            from django.conf import settings
            if not settings.get('DEEPAUTH_EMAIL_VERIFICATION'):  # 不需要邮箱激活验证码
                if Account.objects.count() <= 0:
                    account = Account.objects.create_superuser(first_name=first_name, last_name=last_name,
                                                               username=username, password=password,
                                                               email=email, is_verified=True)
                else:
                    account = Account.objects.create_user(first_name=first_name, last_name=last_name,
                                                          username=username, password=password,
                                                          email=email, is_verified=True)
                account.save()
            else:
                verification_code = str(uuid.uuid4())
                if Account.objects.count() <= 0:
                    account = Account.objects.create_superuser(first_name=first_name, last_name=last_name,
                                                               username=username, password=password, email=email)
                else:
                    account = Account.objects.create_user(first_name=first_name, last_name=last_name, username=username,
                                                          password=password, email=email,
                                                          verification_code=verification_code)
                account.save()
            if settings.get('DEEPAUTH_INVITATION_ONLY'):    # 需要邀请码
                for i in range(INVITATION_LIMIT):           # 赠送10个邀请码
                    code = str(uuid.uuid4())
                    invitation_code = InvitationCode(code=code, account=account)
                    invitation_code.save()
                # 用户注册完后, 邀请码失效
                obj = InvitationCode.objects.filter(code=pp.validated_data['invitation_code'])
                obj.is_used = True
                obj.save()
            return Response(status=status.HTTP_201_CREATED)
        else:
            raise ParseError(pp.errors)


class LoginView(APIView):
    """
    get:
    **登录**

    - <span class='badge'>R</span> `username` 用户名，不能超过 150 个字符
    - <span class='badge'>R</span> `password` 密码，建议为 MD5 哈希结果
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = LoginViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
        if pp.is_valid():
            username = pp.validated_data['username']
            password = pp.validated_data['password']
            account = authenticate(username=username, password=password)
            if account is not None:
                if not account.is_verified:
                    raise NotAuthenticated()
                token, has_created = Token.objects.get_or_create(user=account)
                if account.unique_auth or timezone.now() > (token.created + timedelta(days=TOKEN_LIFETIME)):
                    Token.objects.filter(user=account).update(key=token.generate_key(), created=timezone.now())
                token = Token.objects.get(user=account)
                account.last_login = timezone.now()
                account.save()
                access_log = AccessLog(account=account, ip=get_ip(request), token=token)
                access_log.save()
                return Response({'token': token.key})
            else:
                raise NotAuthenticated()
        else:
            raise ParseError(pp.errors)


class LogoutView(APIView):
    """
    post:
    <span class='badge'><i class='fa fa-lock'></i></span> **登出**
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        request.user.auth_token.delete()
        return Response()


class PasswordView(APIView):
    """
    get:
    <span class='badge'><i class='fa fa-lock'></i></span> **获取用户密码修改历史**

    put:
    <span class='badge'><i class='fa fa-lock'></i></span> **修改密码**

    - <span class='badge'>R</span> `password_old` 当前密码
    - <span class='badge'>R</span> `password_new` 新密码
    - <span class='badge'>R</span> `password_confirm` 重复新密码
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordViewSerializer

    def get(self, request):
        account = Account.objects.get(pk=request.user.pk)
        return Response(PasswordLogSerializer(PasswordLog.objects.filter(account=account)[:10], many=True).data)

    def put(self, request):
        pp = self.serializer_class(data=request.data)
        if pp.is_valid():
            username = request.user.username
            password_old = pp.validated_data['password_old']
            password_new = pp.validated_data['password_new']
            account = authenticate(username=username, password=password_old)
            if account is not None:
                change_password(account, password_new)
                return Response(status=status.HTTP_202_ACCEPTED)
            else:
                raise NotAuthenticated()
        else:
            raise ParseError(pp.errors)


class DetailView(APIView):
    """
    get:
    <span class='badge'><i class='fa fa-lock'></i></span> **获取用户信息**

    put:
    <span class='badge'><i class='fa fa-lock'></i></span> **修改用户信息**

    - <span class='badge'>R</span> `field` 修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、`email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）
    - <span class='badge'>R</span> `value` 修改内容，逗号分隔，必须与 `field` 长度相同
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = DetailViewSerializer

    def get(self, request):
        account = Account.objects.get(pk=request.user.pk)
        resp = AccountSerializer(account).data
        resp['access_log'] = AccessLogSerializer(AccessLog.objects.filter(account=account)[:10], many=True).data
        return Response(resp)

    def put(self, request):
        pp = self.serializer_class(data=request.data)
        if pp.is_valid():
            Account.objects.filter(pk=request.user.pk).update(**dict(pp.validated_data))
            return Response(status=status.HTTP_202_ACCEPTED)
        else:
            raise ParseError(pp.errors)


class AdminAccountView(APIView):
    """
    get:
    <span class='badge'><i class='fa fa-lock'></i></span> <span class='badge'><i class='fa fa-cog'></i></span> **获取全部用户信息**

    put:
    <span class='badge'><i class='fa fa-lock'></i></span> <span class='badge'><i class='fa fa-cog'></i></span> **修改用户信息**

    - <span class='badge'>R</span> `id` 用户 ID
    - <span class='badge'>R</span> `field` 修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、`email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）
    - <span class='badge'>R</span> `value` 修改内容，逗号分隔，必须与 `field` 长度相同
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAdminUser,)
    serializer_class = AdminAccountViewSerializer

    def get(self, request):
        return Response(AccountSerializer(Account.objects.all(), many=True).data)

    def put(self, request):
        pp = self.serializer_class(data=request.data)
        if pp.is_valid():
            uid = pp.validated_data['id']
            account = Account.objects.get(pk=uid)
            del pp.validated_data['id']
            if 'password' in pp.validated_data:
                password = pp.validated_data['password']
                change_password(account, password)
                del pp.validated_data['password']
                return Response(status=status.HTTP_202_ACCEPTED)
            Account.objects.filter(pk=uid).update(**dict(pp.validated_data))
            return Response(status=status.HTTP_202_ACCEPTED)
        else:
            raise ParseError(pp.errors)


class AvatarView(APIView):
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = ImagePostViewSerializer

    def post(self, request):
        account = Account.objects.get(pk=request.user.pk)
        pp = self.serializer_class(request.data)
        if pp.is_valid():
            avatar = pp.validated_data['avatar']
            path = FILE_PATH + '/avatars/'
            if not os.path.exists(path):
                os.makedirs(path)
            path += avatar.name
            with open(path, 'wb+') as destination:
                for chunk in avatar.chunks():
                    destination.write(chunk)
            url = FILE_URL + '/avatars/' + avatar.name
            account.avatar_url = url
            account.save()
            return Response(url, status.HTTP_201_CREATED)
        else:
            raise ParseError(pp.errors)


class ActivateView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = ActivateViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
        if pp.is_valid():
            from django.conf import settings
            if not settings.get('DEEPAUTH_EMAIL_VERIFICATION'):  # 不需要邮箱验证
                raise NotAuthenticated
            prefix_url = pp.validated_data['prefix']
            user_id = pp.validated_data['id']
            obj = Account.objects.get(pk=user_id)
            if obj.verification_code is None:      # 已经激活的用户不再发激活码
                raise NotAuthenticated
            from django.conf import settings
            deepauth_email_verification = settings.get('DEEPAUTH_EMAIL_VERIFICATION')
            host_mail =  deepauth_email_verification['server']
            email_user = deepauth_email_verification['username']
            email_pwd = deepauth_email_verification['password']
            email_recv = obj.email
            subject = 'Please activate account'
            content = prefix_url + '?' + 'code=' + obj.verification_code + '&' + 'id=' + str(user_id)
            send_mail(email_user, email_pwd, [email_recv, ], subject, content, host_mail)
            # from django.core.mail import send_mail
            # send_mail('Subject here', 'Here is the message.', 'from@example.com', ['to@example.com'])
            return Response(status=status.HTTP_200_OK)
        else:
            raise ParseError(pp.errors)


class ValidateView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = ValidateViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
        if pp.is_valid():
            from django.conf import settings
            if not settings.get('DEEPAUTH_EMAIL_VERIFICATION'):  # 不需要邮箱验证
                raise NotAuthenticated
            user_id = pp.validated_data['id']
            code = pp.validated_data['code']
            obj = Account.objects.get(pk=user_id)
            create_time = int(obj.verification_created.timestamp())
            now_time = int(time.time())
            delta = now_time - create_time
            if code == obj.verfication_code and delta <= VALIDATION_TIME_LIMIT:
                obj.is_verified = True
                obj.verification_code = None
                obj.save()
                return Response(status=status.HTTP_200_OK)
            else:
                raise NotAuthenticated
        else:
            raise ParseError(pp.errors)

class InvitationCodeView(APIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = InvitationCodeViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
        if pp.is_valid():
            user_id = pp.validated_data['user_id']
            obj = Account.objects.get(pk=user_id)
            from django.conf import settings
            if settings.get('DEEPAUTH_INVITATION_ONLY') and obj.is_verified:
                invitation_list = obj.invitationcode_set.query(is_used=False)
                return Response(invitation_list)
            else:
                return Response(NotFound)
        else:
            raise ParseError(pp.errors)