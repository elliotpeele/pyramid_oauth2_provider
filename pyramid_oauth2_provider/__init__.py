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

from sqlalchemy import engine_from_config

from pyramid.config import Configurator
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.authentication import OauthAuthenticationPolicy

from .models import DBSession

def includeme(config):
    settings = config.registry.settings
    engine = engine_from_config(settings, 'sqlalchemy.')
    DBSession.configure(bind=engine)

    if not config.registry.queryUtility(IAuthenticationPolicy):
        config.set_authentication_policy(OauthAuthenticationPolicy())

    config.add_route('oauth2_provider_token', '/oauth2/token')
    config.scan()
    return config.make_wsgi_app()

def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    includeme(config)
    return config.make_wsgi_app()
