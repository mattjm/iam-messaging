## Various contribs to Django.

### RemoteUserIfExistsMiddleware

Edited version of Django 1.7.3 RemoteUserMiddleware that does not automatically log out a session if REMOTE_USER is not present.  This supports a common pattern where only the login path is protected by REMOTE_USER.

To use, replace the MIDDLEWARE_CLASS RemoteUserMiddleware with:

    'uw_django.auth.middleware.RemoteUserIfExistsMiddleware',

