from drf_util.exceptions import ValidationException
from django.utils.translation import gettext as _
from rest_framework import serializers


class AuthSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()


class RestoreUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    redirect_url = serializers.URLField(required=True)


class ConfirmRestoreUserSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data.get("password") != data.get("confirm_password"):
            raise ValidationException({"confirm_password": [_("Not match."), ]})
        return data


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class FirebaseIdSerializer(serializers.Serializer):
    firebase_id = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data.get("new_password") != data.get("confirm_password"):
            raise ValidationException({"confirm_password": [_("Not match."), ]})
        return data
