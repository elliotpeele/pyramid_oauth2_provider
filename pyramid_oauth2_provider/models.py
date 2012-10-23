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

from sqlalchemy import Column
from sqlalchemy import ForeignKey

from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import Boolean

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import backref
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session

from zope.sqlalchemy import ZopeTransactionExtension

from pyramid_oauth2_provider.generators import gen_token
from pyramid_oauth2_provider.generators import gen_client_id
from pyramid_oauth2_provider.generators import gen_client_secret

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()

class Oauth2Client(Base):
    __tablename__ = 'oauth2_provider_clients'
    id = Column(Integer, primary_key=True)
    client_id = Column(String(64), unique=True, nullable=False)
    client_secret = Column(String(64), unique=True, nullable=False)
    revoked = Column(Boolean, default=False)

    def __init__(self):
        self.client_id = gen_client_id()
        self.client_secret = gen_client_secret()

    def revoke(self):
        self.revoked = True


class Oauth2Token(Base):
    __tablename__ = 'oauth2_provider_tokens'
    id = Column(Integer, primary_key=True)
    access_token = Column(String(64), unique=True, nullable=False)
    refresh_token = Column(String(64), unique=True, nullable=False)
    expires_in = Column(Integer, nullable=False, default=60*60)
    revoked = Column(Boolean, default=False)

    client_id = Column(Integer, ForeignKey(Oauth2Client.id))
    client = relationship(Oauth2Client, backref=backref('tokens'))

    def __init__(self, client):
        self.client = client

        self.access_token = gen_token(self.client)
        self.refresh_token = gen_token(self.client)

    def revoke(self):
        self.revoked = True
