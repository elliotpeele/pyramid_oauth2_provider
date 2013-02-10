#
# Copyright (c) Elliot Peele <elliot@bentlogic.net>
#
# This program is distributed under the terms of the MIT License as found
# in a file called LICENSE. If it is not present, the license
# is always available at http://www.opensource.org/licenses/mit-license.php.
#
# This program is distributed in the hope that it will be useful, but
# without any warrenty; without even the implied warranty of merchantability
# or fitness for a particular purpose. See the MIT License for full details.
#

class BaseOauth2Error(dict):
    error_name = None

    def __init__(self, **kw):
        dict.__init__(self)
        if kw:
            self.update(kw)
        self['error'] = self.error_name

        if 'error_description' not in self:
            self['error_description'] = self.__doc__


class InvalidRequest(BaseOauth2Error):
    """
    The request is missing a required parameter, includes an unsupported
    parameter or parameter value, repeats the same parameter, uses more
    than one method for including an access token, or is otherwise
    malformed.  The resource server SHOULD respond with the HTTP 400
    (Bad Request) status code.

    http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-23#section-3.1
    """
    error_name = 'invalid_request'


class InvalidClient(BaseOauth2Error):
    """
    The provided authorization grant is invalid, expired, revoked, or
    was issued to another cilent.

    http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-5.2
    """
    error_name = 'invalid_client'


class UnauthorizedClient(BaseOauth2Error):
    """
    The authenticated user is not authorized to use this authorization
    grant type.

    http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-5.2
    """
    error_name = 'unauthorized_client'


class UnsupportedGrantType(BaseOauth2Error):
    """
    The authorizaiton grant type is not supported by the authorization
    server.

    http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-5.2
    """
    error_name = 'unsupported_grant_type'


class InvalidToken(BaseOauth2Error):
    """
    The access token provided is expired, revoked, malformed, or
    invalid for other reasons.  The resource SHOULD respond with the
    HTTP 401 (Unauthorized) status code.  The client MAY request a new
    access token and retry the protected resource request.

    http://tools.ietf.org/html/draft-ietf-oauth-v2-bearer-23#section-3.1
    """
    error_name = 'invalid_token'
