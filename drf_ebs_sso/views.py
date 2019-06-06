from drf_util.decorators import serialize_decorator
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny

from .helpers import confirm_restore_sso_user, restore_sso_user, sso_login, change_password, \
    refresh_token, firebase_check
from .serializers import ConfirmRestoreUserSerializer, RestoreUserSerializer, AuthSerializer, \
    ChangePasswordSerializer, RefreshTokenSerializer, FirebaseIdSerializer


class AuthUser(GenericAPIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = AuthSerializer

    @serialize_decorator(AuthSerializer)
    def post(self, request):
        sso_response = sso_login(
            username=request.valid['email'],
            password=request.valid['password'],
            lang=request.LANGUAGE_CODE
        )
        return sso_response


class RestoreUserPassword(GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = RestoreUserSerializer

    @serialize_decorator(RestoreUserSerializer)
    def post(self, request, *args, **kwargs):
        sso_response = restore_sso_user(
            lang=request.LANGUAGE_CODE,
            username=request.valid["email"],
            redirect_url=request.valid["redirect_url"]
        )
        return sso_response


class ConfirmUserPassword(GenericAPIView):
    authentication_classes = ()
    permission_classes = ()
    serializer_class = ConfirmRestoreUserSerializer

    @serialize_decorator(ConfirmRestoreUserSerializer)
    def post(self, request, *args, **kwargs):
        sso_response = confirm_restore_sso_user(lang=request.LANGUAGE_CODE, **request.valid)
        return sso_response


class ChangePassword(GenericAPIView):
    serializer_class = ChangePasswordSerializer

    @serialize_decorator(ChangePasswordSerializer)
    def post(self, request, *args, **kwargs):
        sso_response = change_password(request, {
            "password": request.valid.pop("password"),
            "new_password": request.valid.pop("new_password"),
            "confirm_password": request.valid.pop("confirm_password", None)
        })
        return sso_response


class RefreshToken(GenericAPIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = RefreshTokenSerializer

    @serialize_decorator(RefreshTokenSerializer)
    def post(self, request, *args, **kwargs):
        sso_response = refresh_token(request.serializer.validated_data)
        return sso_response



class FirebaseCheck(GenericAPIView):
    authentication_classes = ()
    permission_classes = (AllowAny,)
    serializer_class = FirebaseIdSerializer

    @serialize_decorator(FirebaseIdSerializer)
    def post(self, request, *args, **kwargs):
        return firebase_check(request.serializer.validated_data)
