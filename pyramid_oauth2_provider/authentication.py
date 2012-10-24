#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found·
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any waranty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

import base64

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy

from pyramid.httpexceptions import HTTPBadRequest

from .models import Oauth2Token
from .models import DBSession as db

from .errors import InvalidToken

@implementer(IAuthenticationPolicy)
class OauthAuthenticationPolicy(CallbackAuthenticationPolicy):
    def _get_bearer_token(self, request):
        if 'Authorization' in request.headers:
            auth = request.headers.get('Authorization')
        elif 'authorization' in request.headers:
            auth = request.headers.get('authorization')
        else:
            return False

        if not auth.lower() in ('bearer', 'basic'):
            return False

        parts = auth.split()
        if len(parts) != 2:
            return False

        token = base64.decodestring(auth[1])
        token_type = auth[0].lower()

        if token_type == 'basic':
            client_id, client_secret = base64.decodestring(token).split(':')
            request.client_id = client_id
            request.client_secret = client_secret

        return token_type, token

    def _isOauth(self, request):
        return bool(self._get_bearer_token(request))

    def unauthenticated_userid(self, request):
        token_type, token = self._get_bearer_token(request)
        if token_type != 'bearer':
            return None

        auth_token = db.query(Oauth2Token).filter_by(access_token=token).first()
        if not auth_token:
            raise HTTPBadRequest(InvalidToken())

        return auth_token.user_id

    def remember(self, request, principal, **kw):
        """
        I don't think there is anything to do for an oauth request here.
        """

    def forget(self, request):
        """
        You could revoke the access token on a call to forget.
        """


@implementer(IAuthenticationPolicy)
class OauthTktAuthenticationPolicy(OauthAuthenticationPolicy,
                                   AuthTktAuthenticationPolicy):
    def __init__(self, *args, **kwargs):
        OauthAuthenticationPolicy.__init__(self)
        AuthTktAuthenticationPolicy.__init__(self, *args, **kwargs)

    def unauthenticated_userid(self, request):
        if self._isOauth(request):
            return OauthAuthenticationPolicy.unauthenticated_userid(
                self, request)
        else:
            return AuthTktAuthenticationPolicy.unauthenticated_userid(
                self, request)

    def remember(self, request, principal, **kw):
        if self._isOauth(request):
            return OauthAuthenticationPolicy.remember(
                self, request, principal, **kw)
        else:
            return AuthTktAuthenticationPolicy.remember(
                self, request, principal, **kw)

    def forget(self, request):
        if self._isOauth(request):
            return OauthAuthenticationPolicy.forget(
                self, request)
        else:
            return AuthTktAuthenticationPolicy.forget(
                self, request)
