#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any waranty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

import logging

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy

from pyramid.httpexceptions import HTTPBadRequest

from .models import Oauth2Token
from .models import DBSession as db

from .errors import InvalidToken

from .util import getClientCredentials

log = logging.getLogger('pyramid_oauth2_provider.authentication')

@implementer(IAuthenticationPolicy)
class OauthAuthenticationPolicy(CallbackAuthenticationPolicy):
    def _isOauth(self, request):
        return bool(getClientCredentials(request))

    def _get_auth_token(self, request):
        token_type, token = getClientCredentials(request)
        if token_type != 'bearer':
            return None

        auth_token = db.query(Oauth2Token).filter_by(access_token=token).first()
        if not auth_token:
            raise HTTPBadRequest(InvalidToken())

        return auth_token

    def unauthenticated_userid(self, request):
        auth_token = self._get_auth_token(request)
        if not auth_token:
            return None

        return auth_token.user_id

    def remember(self, request, principal, **kw):
        """
        I don't think there is anything to do for an oauth request here.
        """

    def forget(self, request):
        auth_token = self._get_auth_token(request)
        if not auth_token:
            return None

        auth_token.revoke()


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
