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

import time
import random
import hashlib

def _get_hash():
    sha = hashlib.sha256()
    sha.update(str(random.random()))
    sha.update(str(time.time()))
    return sha

def gen_client_id():
    return _get_hash().hexdigest()

def gen_client_secret():
    return _get_hash().hexdigest()

def gen_token(client):
    sha = _get_hash()
    sha.update(client.client_id)
    return sha.hexdigest()
