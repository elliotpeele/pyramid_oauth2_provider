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
import logging

from pyramid.threadlocal import get_current_registry

log = logging.getLogger('pyramid_oauth2_provider.util')

def oauth2_settings(key=None, default=None):
    settings = get_current_registry().settings

    if key:
        value = settings.get('oauth2_provider.%s' % key, default)
        if value == 'true':
            return True
        elif value == 'false':
            return False
        else:
            return value
    else:
        return dict((x.split('.', 1)[1], y) for x, y in settings.iteritems()
            if x.startswith('oauth2_provider.'))

def getClientCredentials(request):
    if 'Authorization' in request.headers:
        auth = request.headers.get('Authorization')
    elif 'authorization' in request.headers:
        auth = request.headers.get('authorization')
    else:
        log.debug('no authorization header found')
        return False

    if (not auth.lower().startswith('bearer') and
        not auth.lower().startswith('basic')):
        log.debug('authorization header not of type bearer or basic: %s'
            % auth.lower())
        return False

    parts = auth.split()
    if len(parts) != 2:
        return False

    token_type = parts[0].lower()
    token = base64.b64decode(parts[1])

    if token_type == 'basic':
        client_id, client_secret = token.split(':')
        request.client_id = client_id
        request.client_secret = client_secret

    return token_type, token
