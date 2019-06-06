from django.contrib.auth import get_user_model
from django.db.models import Model
from rest_framework.authentication import BaseAuthentication

from .helpers import get_token, get_sso_user


class SSOAuthentication(BaseAuthentication):
    token = None

    def get_user(self, sso_response):
        user_model = get_user_model()
        email = sso_response.get('email')

        if issubclass(user_model, Model):
            return user_model.objects.filter(email=email).first()
        else:
            return user_model.objects(email=email).first()

    def authenticate(self, request, **kwargs):

        self.token = get_token(request)

        user = get_sso_user(request)

        if user:
            user_object = self.get_user(user)
            if user_object:
                return user_object, self.token

        return None
