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

import base64
import unittest
import transaction

from sqlalchemy import create_engine

from zope.interface import implementer

from pyramid import testing
from pyramid import httpexceptions

from .views import oauth2_token
from .models import DBSession
from .models import Oauth2Token
from .models import Oauth2Client
from .models import initialize_sql
from .interfaces import IAuthCheck

_auth_value = None
@implementer(IAuthCheck)
class AuthCheck(object):
    def checkauth(self, username, password):
        return _auth_value


class TestCase(unittest.TestCase):
    def setUp(self):
        self.config = testing.setUp()
        self.config.registry.registerUtility(AuthCheck, IAuthCheck)

        engine = create_engine('sqlite://')
        initialize_sql(engine, self.config)

        self.auth = 1

    def _get_auth(self):
        global _auth_value
        return _auth_value

    def _set_auth(self, value):
        global _auth_value
        _auth_value = value

    auth = property(_get_auth, _set_auth)

    def tearDown(self):
        DBSession.remove()
        testing.tearDown()

    def getAuthHeader(self, username, password, scheme='Basic'):
        return {'Authorization': '%s %s'
            % (scheme, base64.b64encode('%s:%s' % (username, password)))}


class TestTokenEndpoint(TestCase):
    def setUp(self):
        TestCase.setUp(self)
        self.client = self._create_client()
        self.request = self._create_request()

    def tearDown(self):
        TestCase.tearDown(self)
        self.client = None
        self.request = None

    def _create_client(self):
        with transaction.manager:
            client = Oauth2Client()
            DBSession.add(client)
            client_id = client.client_id

        client = DBSession.query(Oauth2Client).filter_by(
            client_id=client_id).first()
        return client

    def _create_request(self):
        headers = self.getAuthHeader(
            self.client.client_id,
            self.client.client_secret)

        data = {
            'grant_type': 'password',
            'username': 'john',
            'password': 'foo',
        }

        request = testing.DummyRequest(post=data, headers=headers)
        request.scheme = 'https'

        return request

    def _create_refresh_token_request(self, refresh_token, user_id):
        headers = self.getAuthHeader(
            self.client.client_id,
            self.client.client_secret)

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'user_id': str(user_id),
        }

        request = testing.DummyRequest(post=data, headers=headers)
        request.scheme = 'https'

        return request

    def _process_view(self):
        with transaction.manager:
            token = oauth2_token(self.request)
        return token

    def _validate_token(self, token):
        self.failUnless(isinstance(token, dict))
        self.failUnlessEqual(token.get('user_id'), self.auth)
        self.failUnlessEqual(token.get('expires_in'), 3600)
        self.failUnlessEqual(token.get('token_type'), 'bearer')
        self.failUnlessEqual(len(token.get('access_token')), 64)
        self.failUnlessEqual(len(token.get('refresh_token')), 64)
        self.failUnlessEqual(len(token), 5)

        dbtoken = DBSession.query(Oauth2Token).filter_by(
            access_token=token.get('access_token')).first()

        self.failUnlessEqual(dbtoken.user_id, token.get('user_id'))
        self.failUnlessEqual(dbtoken.expires_in, token.get('expires_in'))
        self.failUnlessEqual(dbtoken.access_token, token.get('access_token'))
        self.failUnlessEqual(dbtoken.refresh_token, token.get('refresh_token'))

    def testTokenRequest(self):
        self.auth = 500
        token = self._process_view()
        self._validate_token(token)

    def testInvalidMethod(self):
        self.request.method = 'GET'
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPMethodNotAllowed))

    def testInvalidScheme(self):
        self.request.scheme = 'http'
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testDisableSchemeCheck(self):
        self.request.scheme = 'http'
        self.config.get_settings()['oauth2_provider.require_ssl'] = False
        token = self._process_view()
        self._validate_token(token)

    def testNoClientCreds(self):
        self.request.headers = {}
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPUnauthorized))

    def testInvalidClientCreds(self):
        self.request.headers = self.getAuthHeader(
            self.client.client_id, 'abcde')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testInvalidGrantType(self):
        self.request.POST['grant_type'] = 'foo'
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testCacheHeaders(self):
        self._process_view()
        self.failUnlessEqual(
            self.request.response.headers.get('Cache-Control'), 'no-store')
        self.failUnlessEqual(
            self.request.response.headers.get('Pragma'), 'no-cache')

    def testMissingUsername(self):
        self.request.POST.pop('username')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testMissingPassword(self):
        self.request.POST.pop('password')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testFailedPassword(self):
        self.auth = False
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPUnauthorized))

    def testRefreshToken(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            token.get('refresh_token'), token.get('user_id'))
        token = self._process_view()
        self._validate_token(token)

    def testMissingRefreshToken(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            token.get('refresh_token'), token.get('user_id'))
        self.request.POST.pop('refresh_token')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testMissingUserId(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            token.get('refresh_token'), token.get('user_id'))
        self.request.POST.pop('user_id')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testInvalidRefreshToken(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            'abcd', token.get('user_id'))
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPUnauthorized))

    def testRefreshInvalidClientId(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            token.get('refresh_token'), token.get('user_id'))
        self.request.headers = self.getAuthHeader(
            '1234', self.client.client_secret)
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))

    def testUserIdMissmatch(self):
        token = self._process_view()
        self._validate_token(token)
        self.request = self._create_refresh_token_request(
            token.get('refresh_token'), '2')
        token = self._process_view()
        self.failUnless(isinstance(token, httpexceptions.HTTPBadRequest))
