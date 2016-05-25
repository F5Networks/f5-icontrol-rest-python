# Copyright 2015-2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
"""A requests-compatible system for BIG-IP token-based authentication.

BIG-IP only allows users with the Administrator role to authenticate to
iControl using HTTP Basic auth.  Non-Administrator users can use the
token-based authentication scheme described at:

  https://devcentral.f5.com/wiki/icontrol.authentication_with_the_f5_rest_api.ashx

Use this module with requests to automatically get a new token, and attach
:class:`requests.Session` object, so that it is used to authenticate future
requests.

Instead of using this module directly, it is easiest to enable it by passing
a ``token=True`` argument when creating the
:class:`.iControlRESTSession`:

>>> iCRS = iControlRESTSession('bob', 'secret', token=True)
"""

from icontrol.exceptions import iControlUnexpectedHTTPError
from icontrol.exceptions import InvalidScheme
import requests
from requests.auth import AuthBase
from requests.auth import HTTPBasicAuth
import time
try:
    # Python 3
    from urllib.parse import urlsplit
except ImportError:
    # Python 2
    from urlparse import urlsplit


class iControlRESTTokenAuth(AuthBase):
    """Acquire and renew BigIP iControl REST authentication tokens.

    :param str username: The username on BigIP
    :param str password: The password for username on BigIP
    :param str login_provider_name: The name of the login provider that \
    BigIP should consult when creating the token.

    If ``username`` is configured locally on the BigIP,
    ``login_provider_name`` should be ``"tmos"`` (default).  Otherwise
    (for example, ``username`` is configured on LDAP that BigIP consults),
    consult BigIP documentation or your system administrator for the value
    of ``login_provider_name``.
    """
    def __init__(self, username, password, login_provider_name='tmos'):
        self.username = username
        self.password = password
        self.login_provider_name = login_provider_name
        self.token = None
        self.expiration = None
        self.attempts = 0
        # We don't actually do auth at this point because we don't have a
        # hostname to authenticate to.

    def _check_token_validity(self):
        if not self.token:
            return False
        if self.expiration and time.time() > self.expiration:
            return False
        return True

    def get_new_token(self, netloc):
        """Get a new token from BIG-IP and store it internally.

        Throws relevant exception if it fails to get a new token.

        This method will be called automatically if a request is attempted
        but there is no authentication token, or the authentication token
        is expired.  It is usually not necessary for users to call it, but
        it can be called if it is known that the authentication token has
        been invalidated by other means.
        """
        login_body = {
            'username': self.username,
            'password': self.password,
            'loginProviderName': self.login_provider_name,
        }
        login_url = "https://%s/mgmt/shared/authn/login" % (netloc)
        req_start_time = time.time()
        response = requests.post(login_url,
                                 json=login_body,
                                 verify=False,
                                 auth=HTTPBasicAuth(self.username,
                                                    self.password))
        self.attempts += 1
        if not response.ok or not hasattr(response, "json"):
            error_message = '%s Unexpected Error: %s for uri: %s\nText: %r' %\
                            (response.status_code,
                             response.reason,
                             response.url,
                             response.text)
            raise iControlUnexpectedHTTPError(error_message,
                                              response=response)
        respJson = response.json()

        expiration_bigip, created_bigip = None, None
        try:
            self.token = respJson['token']['token']
            expiration_bigip = int(respJson['token']['expirationMicros']) / \
                1000000.0
            created_bigip = int(respJson['token']['lastUpdateMicros']) / \
                1000000.0
        except (KeyError, ValueError):
            error_message = \
                '%s Unparseable Response: %s for uri: %s\nText: %r' %\
                (response.status_code,
                 response.reason,
                 response.url,
                 response.text)
            raise iControlUnexpectedHTTPError(error_message,
                                              response=response)

        # Set our token expiration time.
        # The expirationMicros field is when BIG-IP will expire the token
        # relative to its local clock.  To avoid issues caused by incorrect
        # clocks or network latency, we'll compute an expiration time that is
        # referenced to our local clock, and expires slightly before the token
        # should actually expire on BIG-IP

        # Reference to our clock: compute for how long this token is valid as
        # the difference between when it expires and when it was created,
        # according to BIG-IP.
        if expiration_bigip < created_bigip:
            error_message = \
                '%s Token already expired: %s for uri: %s\nText: %r' % \
                (response.status_code,
                 time.ctime(expiration_bigip),
                 response.url,
                 response.text)
            raise iControlUnexpectedHTTPError(error_message,
                                              response=response)
        valid_duration = expiration_bigip - created_bigip

        # Assign new expiration time that is 1 minute earlier than BIG-IP's
        # expiration time, as long as that would still be at least a minute in
        # the future.  This should account for clock skew between us and
        # BIG-IP.  By default tokens last for 60 minutes so getting one every
        # 59 minutes instead of 60 is harmless.
        if valid_duration > 120.0:
            valid_duration -= 60.0
        self.expiration = req_start_time + valid_duration

    def __call__(self, request):
        if not self._check_token_validity():
            scheme, netloc, path, _, _ = urlsplit(request.url)
            if scheme != "https":
                raise InvalidScheme(scheme)
            self.get_new_token(netloc)
        request.headers['X-F5-Auth-Token'] = self.token
        return request
