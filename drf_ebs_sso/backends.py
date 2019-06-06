from django.contrib.auth import get_user_model
from django.db.models import Model
from rest_framework.authentication import BaseAuthentication

from .helpers import get_token, get_sso_user
from django.conf import settings
from django.utils.module_loading import import_string

mongoengine_document = getattr(settings, 'AUTH_USER_DOCUMENT', None)
mongoengine_user = import_string(mongoengine_document) if mongoengine_document else None


class SSOAuthentication(BaseAuthentication):
    token = None

    def get_user(self, sso_response):
        email = sso_response.get('email')

        if mongoengine_user:
            return mongoengine_user.objects(email=email).first()
        else:
            user_model = get_user_model()
            return user_model.objects.filter(email=email).first()

    def authenticate(self, request, **kwargs):

        self.token = get_token(request)

        user = get_sso_user(request)

        if user:
            user_object = self.get_user(user)
            if user_object:
                return user_object, self.token

        return None
