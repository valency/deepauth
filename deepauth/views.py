from datetime import timedelta

from captcha.helpers import captcha_image_url
from captcha.models import CaptchaStore
from django.contrib.auth import authenticate
from ipware.ip import get_ip
from rest_framework import status
from rest_framework.authentication import BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ParseError, NotAcceptable
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from deepauth.serializers import *
from deepauth.utils.mailbox import send_mail
from deepauth.utils.password import change_password, auth_password
from deepauth.utils.token import TOKEN_LIFETIME, ExpiringTokenAuthentication


class RegisterView(APIView):
    """
    post:
    **注册用户**
    - <span class='badge'>R</span> `password` 密码，建议为 MD5 哈希结果
    - <span class='badge'>R</span> `first_name` 用户称呼（名），不能超过 30 个字符
    - `username` 用户名，不能超过 150 个字符，如不提供则会依照当前时间生成一个
    - `last_name` 用户称呼（姓），不能超过 30 个字符
    - `email` 邮箱
    - `tel` 手机号码
    - `country` 国家
    - `invitation_code` 邀请码
    - `captcha_key` 验证码的哈希值，建议隐藏，失效时间为 5 分钟
    - `captcha_value` 验证码的答案
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
            return Response({'id': account.id}, status=status.HTTP_201_CREATED)
        else:
            raise ParseError(pp.errors)


class LoginView(APIView):
    """
    get:
    **登录**
    - <span class='badge'>R</span> `certification` 用户名或邮箱或手机号
    - <span class='badge'>R</span> `password` 密码，建议为 MD5 哈希结果
    - `captcha_key` 验证码的哈希值，建议隐藏，失效时间为 5 分钟
    - `captcha_value` 验证码的答案
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = LoginViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
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
                password_log = PasswordLog(account=account, ip=get_ip(request), password=account.password)
                password_log.save()
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

    - <span class='badge'>R</span> `field` 修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、
    `email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）、`avatar` 用户头像、
    `country` 国家、`tel` 手机号码
    - <span class='badge'>R</span> `value` 修改内容，逗号分隔，必须与 `field` 长度相同
    """
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = DetailViewSerializer

    def get(self, request):
        account = Account.objects.get(pk=request.user.pk)
        resp = AccountSerializer(account).data
        resp['access_log'] = AccessLogSerializer(AccessLog.objects.filter(account=account)[:10], many=True).data
        resp['invitation_code'] = InvitationCodeSerializer(InvitationCode.objects.filter(account=account, user=None), many=True).data
        return Response(resp)

    def put(self, request):
        account = Account.objects.get(pk=request.user.pk)
        pp = self.serializer_class(data=request.data)
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


class AdminAccountView(APIView):
    """
    get:
    <span class='badge'><i class='fa fa-lock'></i></span> <span class='badge'><i class='fa fa-cog'></i></span> **获取全部用户信息**

    put:
    <span class='badge'><i class='fa fa-lock'></i></span> <span class='badge'><i class='fa fa-cog'></i></span> **修改用户信息**

    - <span class='badge'>R</span> `id` 用户 ID
    - <span class='badge'>R</span> `field` 修改键值，逗号分隔：`unique_auth` 是否仅限单一客户端登录、
    `email` 邮箱、`last_name` 用户称呼（姓）、`first_name` 用户称呼（名）、`avatar` 用户头像、`country` 国家、
    `tel` 手机号码、`password` 密码、`is_active` 是否活跃
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


# class AdminAccountTreeView(APIView):
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


class ActivateEmailView(APIView):
    """
    get:
    - <span class='badge'>R</span> `id` 用户 id ,
    - <span class='badge'>R</span> `prefix` url 地址
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = ActivateEmailViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
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


class ValidateEmailView(APIView):
    """
    get:
    - <span class='badge'>R</span> `id` 用户 ID ,
    - <span class='badge'>R</span> `code` 用户的激活码
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = ValidateEmailViewSerializer

    def get(self, request):
        pp = self.serializer_class(data=request.GET)
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


class CaptchaView(APIView):
    """
        get:
        <span class='badge'><i class='fa fa-lock'></i></span> **获取验证码**
    """
    authentication_classes = ()
    permission_classes = (AllowAny,)

    def get(self, request):
        CaptchaStore.remove_expired()  # 删除失效的验证码，过期时间为 5 分钟
        captcha_key = CaptchaStore.pick()
        to_json_response = {
            'key': captcha_key,
            'url': captcha_image_url(captcha_key),
        }
        return Response(to_json_response)
