import logging
from json import JSONDecodeError

import requests
from django.conf import settings
from drf_util.utils import join_url
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response

logger = logging.getLogger(__name__)

SSO_HEADER = "Bearer"
SSO_DOMAIN = settings.SSO_DOMAIN

# SSO_DOMAIN = 'http://127.0.0.1:8000'
AUTH_PATH_SITE = join_url(SSO_DOMAIN, "authorization/token/service/verify/")
AUTH_REFRESH = join_url(SSO_DOMAIN, "authorization/token/refresh/")
FIREBASE_CHECK = join_url(SSO_DOMAIN, "firebase/check/")
PASS_PATH_SITE = join_url(SSO_DOMAIN, "account/user/")
LOGIN_PATH_SITE = join_url(SSO_DOMAIN, "authorization/token/")
CREATE_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/create/")
CREATE_ACTIVATED_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/create-activated/")
RESTORE_PATH_SITE = join_url(SSO_DOMAIN, "authorization/user/restore/")
CONFIRM_RESTORE_PATH_SITE = join_url(SSO_DOMAIN, "account/confirm-restore/")


def get_token(request):
    authorization = request.META.get('HTTP_AUTHORIZATION', "")
    if authorization.startswith('Token'):
        return authorization.split(" ")[-1]


def get_sso_response(url, function_method, data={}, headers={}):
    try:
        request = function_method(url, json=data, headers=headers)
        response = Response(request.json(), status=request.status_code)
    except (requests.exceptions.RequestException, JSONDecodeError):
        logger.warning("Response error from: %s", url)
        response = Response({"detail": "SSO error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return response


def get_sso_user(request):
    data = {}
    token = get_token(request)
    if token:
        response = get_sso_response(AUTH_PATH_SITE, requests.post,
                                    {"token": token, "service_token": settings.AUTH_SERVICE_TOKEN},
                                    headers={"Accept-Language": request.LANGUAGE_CODE})
        if response.status_code == status.HTTP_200_OK:
            data = response.data
        elif response.status_code == status.HTTP_401_UNAUTHORIZED:
            raise AuthenticationFailed()

    return data


def change_password(request, data):
    token = get_token(request)
    response = get_sso_response(PASS_PATH_SITE, requests.patch, data,
                                {"Authorization": "%s %s" % (SSO_HEADER, token),
                                 "Accept-Language": request.LANGUAGE_CODE})
    return response


def sso_login(username, password, lang=settings.LANGUAGE_CODE):
    response = get_sso_response(LOGIN_PATH_SITE, requests.post,
                                {"username": username, "password": password,
                                 "service_token": settings.AUTH_SERVICE_TOKEN},
                                headers={"Accept-Language": lang})
    return response


def create_sso_user(lang=settings.LANGUAGE_CODE, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    # kwargs["redirect_url"] = settings.AUTH_REDIRECT_URL
    response = get_sso_response(CREATE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def create_activated_user(lang=settings.LANGUAGE_CODE, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(CREATE_ACTIVATED_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def confirm_restore_sso_user(lang=settings.LANGUAGE_CODE, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(CONFIRM_RESTORE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def restore_sso_user(lang=settings.LANGUAGE_CODE, **kwargs):
    kwargs["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(RESTORE_PATH_SITE, requests.post, kwargs, headers={"Accept-Language": lang})
    return response


def refresh_token(data, lang=settings.LANGUAGE_CODE):
    data["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(AUTH_REFRESH, requests.post, data, headers={"Accept-Language": lang})
    return response


def firebase_check(data, lang=settings.LANGUAGE_CODE):
    data["service_token"] = settings.AUTH_SERVICE_TOKEN
    response = get_sso_response(FIREBASE_CHECK, requests.post, data, headers={"Accept-Language": lang})
    return response


class SSOUser:
    id = None
    pk = None
    username = ''
    is_staff = False
    is_active = False
    is_superuser = False

    def __str__(self):
        return 'SSOUser'

    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __hash__(self):
        return 1  # instances always return the same hash value

    def save(self):
        raise NotImplementedError(_("Django doesn't provide a DB representation for AnonymousUser."))

    def delete(self):
        raise NotImplementedError(_("Django doesn't provide a DB representation for AnonymousUser."))

    def set_password(self, raw_password):
        raise NotImplementedError(_("Django doesn't provide a DB representation for AnonymousUser."))

    def check_password(self, raw_password):
        raise NotImplementedError(_("Django doesn't provide a DB representation for AnonymousUser."))

    @property
    def groups(self):
        return []

    @property
    def user_permissions(self):
        return []

    def get_group_permissions(self, obj=None):
        return set()

    def get_all_permissions(self, obj=None):
        return []

    def has_perm(self, perm, obj=None):
        return False

    def has_perms(self, perm_list, obj=None):
        return all(self.has_perm(perm, obj) for perm in perm_list)

    def has_module_perms(self, module):
        return False

    def get_username(self):
        return self.username

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True
