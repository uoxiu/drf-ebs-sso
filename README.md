# Integration of EBS SSO in Django Rest Framework 

A set of views, backends for authorization with SSO

### Setup

1. Install the package
    ```bash
    pip install git+https://git2.devebs.net/ebs-platform/drf-ebs-sso.git
    ```

2. Change Authentication in Django Rest Framework settings
    ```python
    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': (
            'drf_ebs_sso.backends.SSOAuthentication',
        )
    }
    ```

3. Add in settings the SSO settings:
    ```text
    SSO_DOMAIN = 'http://ebs-sso-host-example.com/'
    SSO_SERVICE_TOKEN = "ebs-sso-secret-example"
    ```

4. If you use Django ORM and standard User model skip this step. 

    If you use custom model set the default model:
    ```python
    AUTH_USER_MODEL = 'users.User'
    ```
    
    If you use MongoEngine document set:
    ```python
    AUTH_USER_DOCUMENT = 'apps.users.models.User'
    ```
    
5. Set the desired views
    ```python
    from drf_ebs_sso.views import (
        AuthUser, ConfirmUserPassword, RestoreUserPassword, ChangePassword, RefreshToken, FirebaseCheck
    )

    urlpatterns = [
        path("login", AuthUser.as_view(), name="users_login"),
        path("confirm-restore-password", ConfirmUserPassword.as_view()),
        path("restore-password", RestoreUserPassword.as_view()),
        path("change-password", ChangePassword.as_view()),
        path("refresh", RefreshToken.as_view()),
        path("firebase-check", FirebaseCheck.as_view()),
    ]
    ```

6. Enjoy!