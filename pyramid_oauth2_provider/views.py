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

from pyramid.view import view_config
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPMethodNotAllowed

from pyramid_oauth2_provider.models import DBSession as db
from pyramid_oauth2_provider.models import Oauth2Token
from pyramid_oauth2_provider.models import Oauth2Client

from pyramid_oauth2_provider.errors import InvalidToken
from pyramid_oauth2_provider.errors import InvalidClient
from pyramid_oauth2_provider.errors import InvalidRequest
from pyramid_oauth2_provider.errors import UnsupportedGrantType

from pyramid_oauth2_provider.util import oauth2_settings
from pyramid_oauth2_provider.util import getClientCredentials
from pyramid_oauth2_provider.interfaces import IAuthCheck

log = logging.getLogger('pyramid_oauth2_provider.views')

@view_config(route_name='oauth2_provider_token', renderer='json',
             permission=NO_PERMISSION_REQUIRED)
def oauth2_token(request):
    """
    * In the case of an incoming authentication request a POST is made
    with the following structure.

        POST /token HTTP/1.1
        Host: server.example.com
        Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        Content-Type: application/x-www-form-urlencoded

        grant_type=password&username=johndoe&password=A3ddj3w

    The basic auth header contains the client_id:client_secret base64
    encoded for client authentication.

    The username and password are form encoded as part of the body. This
    request *must* be made over https.

    The response to this request will be, assuming no error:

        HTTP/1.1 200 OK
        Content-Type: application/json;charset=UTF-8
        Cache-Control: no-store
        Pragma: no-cache

        {
          "access_token":"2YotnFZFEjr1zCsicMWpAA",
          "token_type":"bearer",
          "expires_in":3600,
          "refresh_token":"tGzv3JOkF0XG5Qx2TlKW",
          "user_id":1234,
        }

    * In the case of a token refresh request a POST with the following
    structure is required:

        POST /token HTTP/1.1
        Host: server.example.com
        Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        Content-Type: application/x-www-form-urlencoded

        grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKW&user_id=1234

    The response will be the same as above with a new access_token and
    refresh_token.
    """

    # Make sure this is a POST.
    if request.method != 'POST':
        log.info('rejected request due to invalid method: %s' % request.method)
        return HTTPMethodNotAllowed(
            'This endpoint only supports the POST method.')

    # This check should be taken care of via the authorization policy, but in
    # case someone has configured a different policy, check again. HTTPS is
    # required for all Oauth2 authenticated requests to ensure the security of
    # client credentials and authorization tokens.
    if (request.scheme != 'https' and
        oauth2_settings('require_ssl', default=True)):
        log.info('rejected request due to unsupported scheme: %s'
            % request.scheme)
        return HTTPBadRequest(InvalidRequest(error_description='Oauth2 '
            'requires all requests to be made via HTTPS.'))

    getClientCredentials(request)

    # Make sure we got a client_id and secret through the authorization
    # policy. Note that you should only get here if not using the Oauth2
    # authorization policy or access was granted through the AuthTKt policy.
    if (not hasattr(request, 'client_id') or
        not hasattr(request, 'client_secret')):
        log.info('did not receive client credentials')
        return HTTPUnauthorized('Invalid client credentials')

    client = db.query(Oauth2Client).filter_by(
        client_id=request.client_id).first()

    # Again, the authorization policy should catch this, but check again.
    if not client or client.client_secret != request.client_secret:
        log.info('received invalid client credentials')
        return HTTPBadRequest(InvalidRequest(
            error_description='Invalid client credentials'))

    # Check for supported grant type. This is a required field of the form
    # submission.
    resp = None
    grant_type = request.POST.get('grant_type')
    if grant_type == 'password':
        resp = handle_password(request, client)
    elif grant_type == 'refresh_token':
        resp = handle_refresh_token(request, client)
    else:
        log.info('invalid grant type: %s' % grant_type)
        return HTTPBadRequest(UnsupportedGrantType(error_description='Only '
            'password and refresh_token grant types are supported by this '
            'authentication server'))

    add_cache_headers(request)
    return resp

def handle_password(request, client):
    if 'username' not in request.POST or 'password' not in request.POST:
        log.info('missing username or password')
        return HTTPBadRequest(InvalidRequest(error_description='Both username '
            'and password are required to obtain a password based grant.'))

    auth_check = request.registry.queryUtility(IAuthCheck)
    user_id = auth_check().checkauth(request.POST.get('username'),
                                     request.POST.get('password'))

    if not user_id:
        log.info('could not validate user credentials')
        return HTTPUnauthorized(InvalidClient(error_description='Username and '
            'password are invalid.'))

    auth_token = Oauth2Token(client, user_id)
    db.add(auth_token)
    db.flush()
    return auth_token.asJSON(token_type='bearer')

def handle_refresh_token(request, client):
    if 'refresh_token' not in request.POST:
        log.info('refresh_token field missing')
        return HTTPBadRequest(InvalidRequest(error_description='refresh_token '
            'field required'))

    if 'user_id' not in request.POST:
        log.info('user_id field missing')
        return HTTPBadRequest(InvalidRequest(error_description='user_id '
            'field required'))

    auth_token = db.query(Oauth2Token).filter_by(
        refresh_token=request.POST.get('refresh_token')).first()

    if not auth_token:
        log.info('invalid refresh_token')
        return HTTPUnauthorized(InvalidToken(error_description='Provided '
            'refresh_token is not valid.'))

    if auth_token.client.client_id != client.client_id:
        log.info('invalid client_id')
        return HTTPBadRequest(InvalidClient(error_description='Client does '
            'not own this refresh_token.'))

    if str(auth_token.user_id) != request.POST.get('user_id'):
        log.info('invalid user_id')
        return HTTPBadRequest(InvalidClient(error_description='The given '
            'user_id does not match the given refresh_token.'))

    new_token = auth_token.refresh()
    db.add(new_token)
    db.flush()
    return new_token.asJSON(token_type='bearer')

def add_cache_headers(request):
    """
    The Oauth2 draft spec requires that all token endpoint traffic be marked
    as uncacheable.
    """

    resp = request.response
    resp.headerlist.append(('Cache-Control', 'no-store'))
    resp.headerlist.append(('Pragma', 'no-cache'))
    return request
