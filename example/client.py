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

import sys
import copy
import base64
import logging
import requests
from collections import namedtuple

log = logging.getLogger('example_client')

class Token(namedtuple('Token', 'token_type access_token expires_in '
    'refresh_token user_id')):
    __slots__ = ()

    @classmethod
    def fromdict(cls, d):
        return cls(
            d['token_type'],
            d['access_token'],
            d['expires_in'],
            d['refresh_token'],
            d['user_id']
        )


class Client(object):
    def __init__(self, client_id, client_secret, token_endpoint,
        verifySSL=True):

        self.client_id = client_id
        self.client_secret = client_secret
        self.token_endpoint = token_endpoint
        self.verifySSL = verifySSL

        self.token = None

    def _get_client_auth_header(self):
        return {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic %s' % base64.b64encode('%s:%s'
                % (self.client_id, self.client_secret)),
        }

    def login(self, username, password):
        data = {
            'grant_type': 'password',
            'username': username,
            'password': password,
        }
        resp = requests.post(self.token_endpoint, data=data,
            headers=self._get_client_auth_header,
            verify=self.verifySSL, config=dict(verbose=log.debug))

        self.token = Token.fromdict(resp.json)

    def refresh_login(self):
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.token.refresh_token,
            'user_id': self.token.user_id,
        }
        resp = requests.post(self.token_endpoint, data=data,
            headers=self._get_client_auth_header,
            verify=self.verifySSL, config=dict(verbose=log.debug))

        self.token = Token.fromdict(resp.json)

    def _get_token_auth_header(self):
        return {
            'Authorization': '%s %s' % (self.token.token_type,
                base64.b64encode(self.token.access_token))
        }

    def _handle_request(self, method, uri, data=None, headers=None):
        if not headers:
            headers = {}
        else:
            headers = copy.copy(headers)

        headers.update(self._get_token_auth_header())

        handler = getattr(requests, method)
        resp = handler(uri, data=data, headers=headers, verify=self.verifySSL,
            config=dict(verbose=log.debug))

        return resp

    def get(self, *args, **kwargs):
        return self._handle_request('get', *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._handle_request('post', *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._handle_request('put', *args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._handle_request('delete', *args, **kwargs)


def usage(args):
    print >>sys.stderr, ('usage: %s <client_id> <client_secret> <token_uri> '
        '<username> <password>' % args[0])
    return 1

def main(args):
    if len(args) != 6:
        return usage(args)

    client_id = args[1]
    client_secret = args[2]
    token_uri = args[3]
    username = args[4]
    password = args[5]

    client = Client(client_id, client_secret, token_uri, verifySSL=False)
    client.login(username, password)
    client.refresh_login()

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
