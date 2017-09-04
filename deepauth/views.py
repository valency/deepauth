from django.contrib.auth import authenticate
from ipware.ip import get_ip
from rest_framework import status
from rest_framework.authentication import BasicAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ParseError, NotAuthenticated
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import *
from .utils.password import *
from .utils.token import *


class RegisterView(APIView):
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
    authentication_classes = (ExpiringTokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        request.user.auth_token.delete()
        return Response()


class PasswordView(APIView):
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
