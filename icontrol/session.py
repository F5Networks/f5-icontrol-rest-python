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

from distutils.version import StrictVersion
import functools
import logging
import requests
import urlparse


class iControlUnexpectedHTTPError(requests.HTTPError):
    # The Status Code was in the range 207-399
    pass


class BigIPInvalidURL(Exception):
    # Some component to be incorporated into the uri is illegal
    pass


class InvalidScheme(BigIPInvalidURL):
    # The only acceptable scheme is https
    pass


class InvalidBigIP_ICRURI(BigIPInvalidURL):
    # This must contain the servername/address and /mgmt/tm/
    pass


class InvalidPrefixCollection(BigIPInvalidURL):
    # Must not start with '/' because it's relative to the icr_uri
    # must end with a '/' since there may be names or suffixes
    # following and they are relative, to the prefix
    pass


class InvalidInstanceNameOrFolder(BigIPInvalidURL):
    # instance names and partitions must not contain the '~' or '/' chars
    pass


class InvalidSuffixCollection(BigIPInvalidURL):
    # must start with a '/' since there may be a partition or name before it
    pass


def _validate_icruri(base_uri):
    # The icr_uri should specify https, the server name/address, and the path
    # to the REST-or-tm management interface "/mgmt/tm/"
    scheme, netloc, path, _, _ = urlparse.urlsplit(base_uri)
    if scheme != 'https':
        raise InvalidScheme(scheme)
    if not path.startswith('/mgmt/tm/'):
        error_message = "The path must start with '/mgmt/tm/'!!  But it's:" +\
            " '%s'" % path[:10]
        raise InvalidBigIP_ICRURI(error_message)
    return _validate_prefix_collections(path[9:])


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


def _validate_name_or_partition(inst_or_partition):
    # '/' and '~' are illegal characters
    if inst_or_partition == '':
        return True
    if '~' in inst_or_partition:
        error_message =\
            "instance names and partitions cannot contain '~', but it's: %s"\
            % inst_or_partition
        raise InvalidInstanceNameOrFolder(error_message)
    elif '/' in inst_or_partition:
        error_message =\
            "instance names and partitions cannot contain '/', but it's: %s"\
            % inst_or_partition
        raise InvalidInstanceNameOrFolder(error_message)
    return True


def _validate_suffix_collections(suffix_collections):
    # These collections must startwith '/' since they may come after a name
    # and/or partition and I do not know whether '~partition~name/' is a legal
    # ending for a URI.
    # The suffix must not endwith '/' as it is the last component that can
    # be appended to the URI path.
    if not suffix_collections.startswith('/'):
        error_message =\
            "suffix_collections path element must start with '/', but it's: %s"\
            % suffix_collections
        raise InvalidSuffixCollection(error_message)
    if suffix_collections.endswith('/'):
        error_message =\
            "suffix_collections path element must not end with '/', but" +\
            " it's: %s" % suffix_collections
        raise InvalidSuffixCollection(error_message)
    return True


def _validate_uri_parts(base_uri, partition, name, suffix_collections):
    # Apply the above validators to the correct components.
    _validate_icruri(base_uri)
    _validate_name_or_partition(partition)
    _validate_name_or_partition(name)
    if suffix_collections:
        _validate_suffix_collections(suffix_collections)
    return True


def generate_bigip_uri(base_uri, partition, name, suffix, **kwargs):
    '''(str, str, str) --> str

    This function checks the supplied elements to see if each conforms to
    the specifiction for the appropriate part of the URI. These validations
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
    '''
    _validate_uri_parts(base_uri, name, partition, suffix)
    if partition != '':
        partition = '~'+partition
    if name != '' and partition != '':
        name = '~'+name
    tilded_partition_and_instance = partition+name
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
        name = kwargs.pop('name', '')
        suffix = kwargs.pop('suffix', '')
        uri_as_parts = kwargs.pop('uri_as_parts', False)
        if uri_as_parts:
            REST_uri = generate_bigip_uri(RIC_base_uri, partition, name,
                                          suffix, **kwargs)
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
    """
    def __init__(self, username, password, **kwargs):
        """Instantiation associated with requests.Session via composition.

        All transactions are Trust On First Use (TOFU) to the BigIP device,
        since no PKI exists for this purpose in general, hence the
        "disable_warnings" statement.
        """
        timeout = kwargs.pop('timeout', 30)
        if kwargs:
            raise TypeError('Unexpected **kwargs: %r' % kwargs)
        requests_version = requests.__version__
        if StrictVersion(requests_version) < '2.9.1':
            requests.packages.urllib3.disable_warnings()

        # Compose with a Session obj
        self.session = requests.Session()

        # Configure with passed parameters
        self.session.auth = (username, password)
        self.session.timeout = timeout

        # Set state as indicated by ancestral code.
        self.session.verify = False  # XXXmake TOFU
        self.session.headers.update({'Content-Type': 'application/json'})

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
        :arg partition: The partition name that will be appened to the uri
        :type partition: str
        :param **kwargs: The :meth:`reqeusts.Session.put` optional params
        """
        return self.session.put(uri, data=data, **kwargs)
