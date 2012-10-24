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

from sqlalchemy import func

from sqlalchemy import Column
from sqlalchemy import ForeignKey

from sqlalchemy import String
from sqlalchemy import Integer
from sqlalchemy import Boolean
from sqlalchemy import DateTime

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
    revocation_date = Column(DateTime)

    def __init__(self):
        self.client_id = gen_client_id()
        self.client_secret = gen_client_secret()

    def revoke(self):
        self.revoked = True
        self.revocation_date = func.now()

    def isRevoked(self):
        return self.revoked


class Oauth2Token(Base):
    __tablename__ = 'oauth2_provider_tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    access_token = Column(String(64), unique=True, nullable=False)
    refresh_token = Column(String(64), unique=True, nullable=False)
    expires_in = Column(Integer, nullable=False, default=60*60)

    revoked = Column(Boolean, default=False)
    revocation_date = Column(DateTime)

    creation_date = Column(DateTime, default=func.now())

    client_id = Column(Integer, ForeignKey(Oauth2Client.id))
    client = relationship(Oauth2Client, backref=backref('tokens'))

    def __init__(self, client, user_id):
        self.client = client
        self.user_id = user_id

        self.access_token = gen_token(self.client)
        self.refresh_token = gen_token(self.client)

    def revoke(self):
        self.revoked = True
        self.revocation_date = func.now()

    def isRevoked(self):
        if self.creation_date + self.expires_in > func.now():
            self.revoke()
        return self.revoked

    def refresh(self):
        """
        Generate a new token for this client.
        """

        cls = self.__class__
        self.revoke()
        return cls(self.client, self.user_id)

    def asJSON(self, **kwargs):
        token = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'user_id': self.user_id,
            'expires_in': self.expires_in,
        }
        kwargs.update(token)
        return kwargs


def initialize_sql(engine, settings):
    DBSession.configure(bind=engine)
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)
