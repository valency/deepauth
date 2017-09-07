from django.contrib.auth import authenticate
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


class RegisterView(APIView):
    """
    post:
        **注册用户**

        - <span class='badge'>R</span> `username` 用户名，不能超过 150 个字符
        - <span class='badge'>R</span> `password` 密码，建议为 MD5 哈希结果
        - `email` 邮箱
        - `last_name` 用户称呼（姓），不能超过 30 个字符
        - <span class='badge'>R</span> `first_name` 用户称呼（名），不能超过 30 个字符
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
            if Account.objects.count() <= 0:
                account = Account.objects.create_superuser(first_name=first_name, last_name=last_name, username=username, password=password, email=email)
            else:
                account = Account.objects.create_user(first_name=first_name, last_name=last_name, username=username, password=password, email=email)
            account.save()
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
    put:
        <span class='badge'><i class='fa fa-lock'></i></span> **修改密码**

        - <span class='badge'>R</span> `password_old` 当前密码
        - <span class='badge'>R</span> `password_new` 新密码
        - <span class='badge'>R</span> `password_confirm` 重复新密码
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = PasswordViewSerializer

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
