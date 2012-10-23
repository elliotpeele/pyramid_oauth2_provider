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

from zope.interface import implementer

from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authentication import CallbackAuthenticationPolicy

@implementer(IAuthenticationPolicy)
class OauthAuthenticationPolicy(CallbackAuthenticationPolicy):
    def _isOauth(self, request):
        return False

    def unauthenticated_userid(self, request):
        pass

    def remember(self, request, principal, **kw):
        pass

    def forget(self, request):
        pass


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
