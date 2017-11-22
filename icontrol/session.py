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
"""A BigIP-RESTServer URI handler. REST-APIs use it on the :mod:`requests`
library.

Use this module to make calls to a BigIP-REST server.  It will handle:

#. URI Sanitization uri's produced by this module are checked to ensure
   compliance with the BigIP-REST server interface

#. Session Construction -- the :class:`iControlRESTSession` wraps a
   :class:`requests.Session` object.

#. Logging -- pre- and post- request state is logged.

#. Exception generation -- Errors in URL construction generate
   :class:`BigIPInvalidURL` subclasses; unexpected HTTP status codes raise
   :class:`iControlUnexpectedHTTPError`.

The core functionality of the module is implemented via the
:class:`iControlRESTSession` class.  Calls to its' HTTP-methods are checked,
pre-logged, submitted, and post-logged.

There are 2 modes of operation "full_uri", and "uri_as_parts", toggled by the
`uri_as_parts` boolean keyword param that can be passed to methods. It defaults
to `False`.   Use `uri_as_parts` when you want to leverage the full
functionality of this library, and have it construct your uri for you.
Example Use in `uri_as_parts` mode:

>>> iCRS = iControlRESTSession('jrandomhacker', 'insecure')
>>> iCRS.get('https://192.168.1.1/mgmt/tm/ltm/nat/', \
partition='Common', name='VALIDNAME', uri_as_parts=True)

In `full_uri` mode:

>>> iCRS.get('https://192.168.1.1/mgmt/tm/ltm/nat/~Common~VALIDNAME')

NOTE: If used via the :mod:`f5-common-python` library the typical mode is
"full_uri" since that library binds uris to Python objects.

Available functions:

- iCRS.{get, post, put, delete, patch}: requests.Session.VERB wrappers
- decorate_HTTP_verb_method: this function preps, logs, and handles requests
against the BigIP REST Server, by pre- and post- processing the above methods.

"""

from icontrol import __version__ as version
from icontrol.authtoken import iControlRESTTokenAuth
from icontrol.exceptions import iControlUnexpectedHTTPError
from icontrol.exceptions import InvalidBigIP_ICRURI
from icontrol.exceptions import InvalidInstanceNameOrFolder
from icontrol.exceptions import InvalidPrefixCollection
from icontrol.exceptions import InvalidScheme
from icontrol.exceptions import InvalidSuffixCollection
from icontrol.exceptions import InvalidURIComponentPart

import functools
import logging
import requests

try:
    # Python 3
    from urllib.parse import urlsplit
except ImportError:
    # Python 2
    from urlparse import urlsplit


def _validate_icruri(base_uri):
    # The icr_uri should specify https, the server name/address, and the path
    # to the REST-or-tm management interface "/mgmt/tm/"
    scheme, netloc, path, _, _ = urlsplit(base_uri)
    if scheme != 'https':
        raise InvalidScheme(scheme)

    if path.startswith('/mgmt/tm/'):
        # Most of the time this is BIG-IP
        sub_path = path[9:]
    elif path.startswith('/mgmt/cm/'):
        # This can also be in iWorkflow or BIG-IQ
        sub_path = path[9:]
    elif path.startswith('/mgmt/shared/'):
        # This can be iWorkflow or BIG-IQ
        sub_path = path[13:]
    else:
        error_message = "The path must start with either '/mgmt/tm/'," \
                        "'/mgmt/cm/', or '/mgmt/shared/'!  But it's:" \
                        " '%s'" % path
        raise InvalidBigIP_ICRURI(error_message)
    return _validate_prefix_collections(sub_path)


def _validate_prefix_collections(prefix_collections):
    # The prefix collections are everything in the URI after /mgmt/tm/ and
    # before the 'partition'  It must not start with '/' because it's relative
    # to the /mgmt/tm REST management path, and it must end with '/' since the
    # subequent components expect to be addressed relative to it.
    # Additionally the first '/' delimited component of the prefix collection
    # must be an "organizing collection". See the REST users guide:
    # https://devcentral.f5.com/d/icontrol-rest-user-guide-version-1150
    if not prefix_collections.endswith('/'):
        error_message =\
            "prefix_collections path element must end with '/', but it's: %s"\
            % prefix_collections
        raise InvalidPrefixCollection(error_message)
    return True


def _validate_name_partition_subpath(element):
    # '/' and '~' are illegal characters in most cases, however there are
    # few exceptions (GTM Regions endpoint being one of them where the
    # validation of name should not apply.
    if element == '':
        return True
    if '~' in element:
        error_message =\
            "instance names and partitions cannot contain '~', but it's: %s"\
            % element
        raise InvalidInstanceNameOrFolder(error_message)
    elif '/' in element:
        error_message =\
            "instance names and partitions cannot contain '/', but it's: %s"\
            % element
        raise InvalidInstanceNameOrFolder(error_message)
    return True


def _validate_suffix_collections(suffix_collections):
    # These collections must start with '/' since they may come after a name
    # and/or partition and I do not know whether '~partition~name/' is a legal
    # ending for a URI.
    # The suffix must not endwith '/' as it is the last component that can
    # be appended to the URI path.
    if not suffix_collections.startswith('/'):
        error_message =\
            "suffix_collections path element must start with '/', but" \
            " it's: %s" % suffix_collections
        raise InvalidSuffixCollection(error_message)
    if suffix_collections.endswith('/'):
        error_message =\
            "suffix_collections path element must not end with '/', but" \
            " it's: %s" % suffix_collections
        raise InvalidSuffixCollection(error_message)
    return True


def _validate_uri_parts(
        base_uri, partition, name, sub_path, suffix_collections,
        **kwargs):
    # Apply the above validators to the correct components.
    _validate_icruri(base_uri)
    _validate_name_partition_subpath(partition)
    if not kwargs.get('transform_name', False):
        _validate_name_partition_subpath(name)
    _validate_name_partition_subpath(sub_path)
    if suffix_collections:
        _validate_suffix_collections(suffix_collections)
    return True


def generate_bigip_uri(base_uri, partition, name, sub_path, suffix, **kwargs):
    '''(str, str, str) --> str

    This function checks the supplied elements to see if each conforms to
    the specification for the appropriate part of the URI. These validations
    are conducted by the helper function _validate_uri_parts.
    After validation the parts are assembled into a valid BigIP REST URI
    string which is then submitted with appropriate metadata.

    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/', \
    'CUSTOMER1', 'nat52', params={'a':1})
    'https://0.0.0.0/mgmt/tm/ltm/nat/~CUSTOMER1~nat52'
    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/', \
    'CUSTOMER1', 'nat52', params={'a':1}, suffix='/wacky')
    'https://0.0.0.0/mgmt/tm/ltm/nat/~CUSTOMER1~nat52/wacky'
    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/', '', '', \
    params={'a':1}, suffix='/thwocky')
    'https://0.0.0.0/mgmt/tm/ltm/nat/thwocky'

    ::Warning: There are cases where '/' and '~' characters are valid in the
        object name. This is indicated by passing 'transform_name' boolean as
        True, by default this is set to False.
    '''

    _validate_uri_parts(base_uri, partition, name, sub_path, suffix,
                        **kwargs)

    if kwargs.get('transform_name', False):
        if name != '':
            name = name.replace('/', '~')
    if partition != '':
        partition = '~' + partition
    else:
        if sub_path:
            msg = 'When giving the subPath component include partition ' \
                'as well.'
            raise InvalidURIComponentPart(msg)
    if sub_path != '' and partition != '':
        sub_path = '~' + sub_path
    if name != '' and partition != '':
        name = '~' + name
    tilded_partition_and_instance = partition + sub_path + name
    if suffix and not tilded_partition_and_instance:
        suffix = suffix.lstrip('/')

    REST_uri = base_uri + tilded_partition_and_instance + suffix
    return REST_uri


def decorate_HTTP_verb_method(method):
    """Prepare and Post-Process HTTP VERB method for BigIP-RESTServer request.

    This function decorates all of the HTTP VERB methods in the
    iControlRESTSession class.  It provides the core logic for this module.
    If necessary it validates and assembles a uri from parts with a call to
    `generate_bigip_uri`.

    Then it:

    1. pre-logs the details of the request
    2. submits the request
    3. logs the response, included expected status codes
    4. raises exceptions for unexpected status codes. (i.e. not doc'd as BigIP
       RESTServer codes.)
    """
    @functools.wraps(method)
    def wrapper(self, RIC_base_uri, **kwargs):
        partition = kwargs.pop('partition', '')
        sub_path = kwargs.pop('subPath', '')
        suffix = kwargs.pop('suffix', '')
        identifier, kwargs = _unique_resource_identifier_from_kwargs(**kwargs)
        uri_as_parts = kwargs.pop('uri_as_parts', False)
        transform_name = kwargs.pop('transform_name', False)
        if uri_as_parts:
            REST_uri = generate_bigip_uri(RIC_base_uri, partition, identifier,
                                          sub_path, suffix,
                                          transform_name=transform_name,
                                          **kwargs)
        else:
            REST_uri = RIC_base_uri
        pre_message = "%s WITH uri: %s AND suffix: %s AND kwargs: %s" %\
            (method.__name__, REST_uri, suffix, kwargs)
        logging.debug(pre_message)
        response = method(self, REST_uri, **kwargs)
        post_message =\
            "RESPONSE::STATUS: %s Content-Type: %s Content-Encoding:"\
            " %s\nText: %r" % (response.status_code,
                               response.headers.get('Content-Type', None),
                               response.headers.get('Content-Encoding', None),
                               response.text)
        logging.debug(post_message)
        if response.status_code not in range(200, 207):
            error_message = '%s Unexpected Error: %s for uri: %s\nText: %r' %\
                            (response.status_code,
                             response.reason,
                             response.url,
                             response.text)
            raise iControlUnexpectedHTTPError(error_message, response=response)
        return response
    return wrapper


def _unique_resource_identifier_from_kwargs(**kwargs):
    """Chooses an identifier given different choices

    The unique identifier in BIG-IP's REST API at the time of this writing
    is called 'name'. This is in contrast to the unique identifier that is
    used by iWorkflow and BIG-IQ which at some times is 'name' and other
    times is 'uuid'.

    For example, in iWorkflow, there consider this URI

      * https://10.2.2.3/mgmt/cm/cloud/tenants/{0}/services/iapp

    Then consider this iWorkflow URI

      * https://localhost/mgmt/cm/cloud/connectors/local/{0}

    In the first example, the identifier, {0}, is what we would normally
    consider a name. For example, "tenant1". In the second example though,
    the value is expected to be what we would normally consider to be a
    UUID. For example, '244bd478-374e-4eb2-8c73-6e46d7112604'.

    This method only tries to rectify the problem of which to use.

    I believe there might be some change that the two can appear together,
    although I have not yet experienced it. If it is possible, I believe it
    would happen in BIG-IQ/iWorkflow land where the UUID and Name both have
    significance. That's why I deliberately prefer the UUID when it exists
    in the parameters sent to the URL.

    :param kwargs:
    :return:
    """
    name = kwargs.pop('name', '')
    uuid = kwargs.pop('uuid', '')
    id = kwargs.pop('id', '')
    if uuid:
        return uuid, kwargs
    elif id:
        # Used for /mgmt/cm/system/authn/providers/tmos on BIG-IP
        return id, kwargs
    else:
        return name, kwargs


class iControlRESTSession(object):
    """Represents a :class:`requests.Session` that communicates with a BigIP.

    Instantiate one of these when you want to communicate with a BigIP-REST
    Server, it will handle BigIP-specific details of the uri's. In the
    f5-common-python library, an :class:`iControlRESTSession` is instantiated
    during BigIP instantiation and associated with it as an attribute of the
    BigIP (a compositional vs. inheritable association).

    Objects instantiated from this class provide an HTTP 1.1 style session, via
    the :class:`requests.Session` object, and HTTP-methods that are specialized
    to the BigIP-RESTServer interface.

    Pass ``token=True`` in ``**kwargs`` to use token-based authentication.
    This is required for users that do not have the Administrator role on
    BigIP.
    """
    def __init__(self, username, password, **kwargs):
        """Instantiation associated with requests.Session via composition.

        All transactions are Trust On First Use (TOFU) to the BigIP device,
        since no PKI exists for this purpose in general, hence the
        "disable_warnings" statement.

        Attributes:
            username (str): The user to connect with.
            password (str): The password of the user.
            timeout (int): The timeout, in seconds, to wait before closing
                the session.
            token (bool|str): True or False, specifying whether to use token
                authentication or not.
            token_to_use (str): String containing the token itself to use.
                This is particularly useful in situations where you want to
                mimic the behavior of a browser insofar as storing the token
                in a cookie and retrieving it for use "later". This is used
                in situations such as automation tools to prevent token
                abuse on the BIG-IP. There is a limit that users may not go
                beyond when creating tokens and their re-use is an attempt
                to mitigate this scenario.
            user_agent (str): A string to append to the user agent header
                that is sent during a session.
            verify (str): The path to a CA bundle containing the CA
                certificate for SSL validation
            auth_provider: String specifying the specific auth provider to
                authenticate the username/password against. If this argument
                is specified, the `token` argument is ignored. This keyword
                implies that token based authentication is used. The strings
                "none" and "default" are reserved words that imply no specific
                auth provider is to be used; the system will default to one.
                On BIG-IQ systems, the value 'local' can be used to refer to
                local user authentication.
        """
        verify = kwargs.pop('verify', False)
        timeout = kwargs.pop('timeout', 30)
        token_auth = kwargs.pop('token', None)
        user_agent = kwargs.pop('user_agent', None)
        token_to_use = kwargs.pop('token_to_use', None)
        auth_provider = kwargs.pop('auth_provider', None)

        if kwargs:
            raise TypeError('Unexpected **kwargs: %r' % kwargs)
        requests.packages.urllib3.disable_warnings()

        # Compose with a Session obj
        self.session = requests.Session()

        # Configure with passed parameters
        self.session.timeout = timeout

        # Handle token-based auth.
        if token_to_use:
            self.session.auth = iControlRESTTokenAuth('admin', 'admin')
            self.session.auth.token = token_to_use
        else:
            if auth_provider:
                self.session.auth = iControlRESTTokenAuth(
                    username, password, auth_provider=auth_provider, verify=verify
                )
            else:
                if token_auth is True:
                    self.session.auth = iControlRESTTokenAuth(
                        username, password, verify=verify
                    )
                elif token_auth:
                    # Truthy but not true: non-default loginAuthProvider
                    self.session.auth = iControlRESTTokenAuth(
                        username, password, token_auth, verify=verify
                    )
                else:
                    self.session.auth = (username, password)

        # Set state as indicated by ancestral code.
        self.session.verify = verify
        self.session.headers.update({'Content-Type': 'application/json'})

        # Add a user agent for this library and any specified UA
        self.append_user_agent('f5-icontrol-rest-python/' + version)
        if user_agent:
            self.append_user_agent(user_agent)

    @decorate_HTTP_verb_method
    def delete(self, uri, **kwargs):
        """Sends a HTTP DELETE command to the BIGIP REST Server.

        Use this method to send a DELETE command to the BIGIP.  When calling
        this method with the optional arguments ``name`` and ``partition``
        as part of ``**kwargs`` they will be added to the ``uri`` passed
        in separated by ~ to create a proper BIGIP REST API URL for objects.

        All other parameters passed in as ``**kwargs`` are passed directly
        to the :meth:`requests.Session.delete`

        :param uri: A HTTP URI
        :type uri: str
        :param name: The object name that will be appended to the uri
        :type name: str
        :arg partition: The partition name that will be appened to the uri
        :type partition: str
        :param \**kwargs: The :meth:`reqeusts.Session.delete` optional params
        """
        return self.session.delete(uri, **kwargs)

    @decorate_HTTP_verb_method
    def get(self, uri, **kwargs):
        """Sends a HTTP GET command to the BIGIP REST Server.

        Use this method to send a GET command to the BIGIP.  When calling
        this method with the optional arguments ``name`` and ``partition``
        as part of ``**kwargs`` they will be added to the ``uri`` passed
        in separated by ~ to create a proper BIGIP REST API URL for objects.

        All other parameters passed in as ``**kwargs`` are passed directly
        to the :meth:`requests.Session.get`

        :param uri: A HTTP URI
        :type uri: str
        :param name: The object name that will be appended to the uri
        :type name: str
        :arg partition: The partition name that will be appened to the uri
        :type partition: str
        :param \**kwargs: The :meth:`reqeusts.Session.get` optional params
        """
        return self.session.get(uri, **kwargs)

    @decorate_HTTP_verb_method
    def patch(self, uri, data=None, **kwargs):
        """Sends a HTTP PATCH command to the BIGIP REST Server.

        Use this method to send a PATCH command to the BIGIP.  When calling
        this method with the optional arguments ``name`` and ``partition``
        as part of ``**kwargs`` they will be added to the ``uri`` passed
        in separated by ~ to create a proper BIGIP REST API URL for objects.

        All other parameters passed in as ``**kwargs`` are passed directly
        to the :meth:`requests.Session.patch`

        :param uri: A HTTP URI
        :type uri: str
        :param data: The data to be sent with the PATCH command
        :type data: str
        :param name: The object name that will be appended to the uri
        :type name: str
        :arg partition: The partition name that will be appened to the uri
        :type partition: str
        :param \**kwargs: The :meth:`reqeusts.Session.patch` optional params
        """
        return self.session.patch(uri, data=data, **kwargs)

    @decorate_HTTP_verb_method
    def post(self, uri, data=None, json=None, **kwargs):
        """Sends a HTTP POST command to the BIGIP REST Server.

        Use this method to send a POST command to the BIGIP.  When calling
        this method with the optional arguments ``name`` and ``partition``
        as part of ``**kwargs`` they will be added to the ``uri`` passed
        in separated by ~ to create a proper BIGIP REST API URL for objects.

        All other parameters passed in as ``**kwargs`` are passed directly
        to the :meth:`requests.Session.post`

        :param uri: A HTTP URI
        :type uri: str
        :param data: The data to be sent with the POST command
        :type data: str
        :param json: The JSON data to be sent with the POST command
        :type json: dict
        :param name: The object name that will be appended to the uri
        :type name: str
        :arg partition: The partition name that will be appened to the uri
        :type partition: str
        :param \**kwargs: The :meth:`reqeusts.Session.post` optional params
        """
        return self.session.post(uri, data=data, json=json, **kwargs)

    @decorate_HTTP_verb_method
    def put(self, uri, data=None, **kwargs):
        """Sends a HTTP PUT command to the BIGIP REST Server.

        Use this method to send a PUT command to the BIGIP.  When calling
        this method with the optional arguments ``name`` and ``partition``
        as part of ``**kwargs`` they will be added to the ``uri`` passed
        in separated by ~ to create a proper BIGIP REST API URL for objects.

        All other parameters passed in as ``**kwargs`` are passed directly
        to the :meth:`requests.Session.put`

        :param uri: A HTTP URI
        :type uri: str
        :param data: The data to be sent with the PUT command
        :type data: str
        :param json: The JSON data to be sent with the PUT command
        :type json: dict
        :param name: The object name that will be appended to the uri
        :type name: str
        :arg partition: The partition name that will be appended to the uri
        :type partition: str
        :param **kwargs: The :meth:`reqeusts.Session.put` optional params
        """
        return self.session.put(uri, data=data, **kwargs)

    def append_user_agent(self, user_agent):
        """Append text to the User-Agent header for the request.

        Use this method to update the User-Agent header by appending the
        given string to the session's User-Agent header separated by a space.

        :param user_agent: A string to append to the User-Agent header
        :type user_agent: str
        """
        old_ua = self.session.headers.get('User-Agent', '')
        ua = old_ua + ' ' + user_agent
        self.session.headers['User-Agent'] = ua.strip()

    @property
    def token(self):
        """Convenience wrapper around returning the current token

        Returns:
             result (str): The current token being sent in session headers.
        """
        return self.session.auth.token

    @token.setter
    def token(self, value):
        """Convenience wrapper around overwriting the current token

        Useful in situations where you have an existing iControlRESTSession
        object which you want to set a new token on. This token could have
        been read from a stored value for example.
        """
        self.session.auth.token = value
