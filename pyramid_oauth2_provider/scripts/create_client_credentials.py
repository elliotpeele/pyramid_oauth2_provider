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

import os
import sys

import transaction

from sqlalchemy import engine_from_config

from pyramid.paster import (
    get_appsettings,
    setup_logging,
    )

from pyramid_oauth2_provider.models import (
    DBSession,
    initialize_sql,
    Oauth2Client,
    )

def create_client():
    client = Oauth2Client()
    DBSession.add(client)
    return client.client_id, client.client_secret

def usage(argv):
    cmd = os.path.basename(argv[0])
    print('usage: %s <config_uri> <section>\n'
          '(example: "%s development.ini myproject")' % (cmd, cmd)) 
    sys.exit(1)

def main(argv=sys.argv):
    if len(argv) != 3:
        usage(argv)
    config_uri = argv[1]
    section = argv[2]
    setup_logging(config_uri)
    settings = get_appsettings(config_uri, section)
    engine = engine_from_config(settings, 'sqlalchemy.')
    initialize_sql(engine, settings)

    with transaction.manager:
        id, secret = create_client()
        print 'client_id:', id
        print 'client_secret:', secret

if __name__ == '__main__':
    import epdb
    sys.excepthook = epdb.excepthook()

    main()
