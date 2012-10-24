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

from zope.interface import Interface

class IAuthCheck(Interface):
    """
    This interface is for verifying authentication information with your
    backing store of choice. In the short term this will be limited to
    usernames and passwords, but may grow to support other authentication
    methods.
    """

    def checkauth(self, username, password):
        """
        Validate a given username and password against some kind of store,
        usually a relational database. Return the users user_id if credentials
        are valid, otherwise False or None.
        """
