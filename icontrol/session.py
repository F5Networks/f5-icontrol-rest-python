# Copyright 2015 F5 Networks Inc.
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

import functools
import logging
import os
import requests
import time
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

    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/',\
            'CUSTOMER1', 'nat52', params={'a':1})
    'https://0.0.0.0/mgmt/tm/ltm/nat/~CUSTOMER1~nat52'
    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/',\
            'CUSTOMER1', 'nat52', params={'a':1}, suffix='/wacky')
    'https://0.0.0.0/mgmt/tm/ltm/nat/~CUSTOMER1~nat52/wacky'
    >>> generate_bigip_uri('https://0.0.0.0/mgmt/tm/ltm/nat/', '', '',\
            params={'a':1}, suffix='/thwocky')
    'https://0.0.0.0/mgmt/tm/ltm/nat/thwocky'
    '''
    _validate_uri_parts(base_uri, name, partition, suffix)
    if partition != '':
        partition = '~'+partition
    if name != '':
        name = '~'+name
    tilded_partition_and_instance = partition+name
    if suffix and not tilded_partition_and_instance:
        suffix = suffix.lstrip('/')
    REST_uri = base_uri + tilded_partition_and_instance + suffix
    return REST_uri


def _config_logging(logdir, methodname, level, cls_name):
    # Configure output handler for the HTTP method's log
    log_path = os.path.join(logdir, methodname)
    logfile_handler = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s PID: %(process)s %(message)s')
    logfile_handler.setFormatter(formatter)
    # Configure logger
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    logger.addHandler(logfile_handler)
    return logger


def _log_HTTP_verb_method_precall(logger, methodname, level, cls_name,
                                  request_uri, suffix, **kwargs):
    pre_message = "%s.%s WITH uri: %s AND suffix: %s AND kwargs: %s" %\
        (cls_name, methodname, request_uri, suffix, kwargs)
    logger.log(level, pre_message)


def _log_HTTP_verb_method_postcall(logger, level, response):
    post_message = "RESPONSE::STATUS:" +\
                   " %s Content-Type: %s Content-Encoding: %s\nText: %r" %\
        (response.status_code,
         response.headers.get('Content-Type', None),
         response.headers.get('Content-Encoding', None),
         response.text)
    logger.log(level, post_message)


def decorate_HTTP_verb_method(method):
    # NOTE:  "self" refers to a RESTInterfaceCollection instance!
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
        logger = _config_logging(self.log_dir, method.__name__, self.log_level,
                                 self.__class__.__name__)
        _log_HTTP_verb_method_precall(logger, method.__name__,
                                      self.log_level, self.__class__.__name__,
                                      REST_uri, suffix, **kwargs)
        response = method(self, REST_uri, **kwargs)
        _log_HTTP_verb_method_postcall(logger, self.log_level, response)
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
    """XXX

    XXXX
    """
    def __init__(self, username, password, **kwargs):
        timeout = kwargs.pop('timeout', 30)
        loglevel = kwargs.pop('loglevel', logging.DEBUG)
        if kwargs:
            raise TypeError('Unexpected **kwargs: %r' % kwargs)
        requests.packages.urllib3.disable_warnings()

        # Compose with a Session obj
        self.session = requests.Session()

        # Configure with passed parameters
        self.session.auth = (username, password)
        self.session.timeout = timeout

        # Set state as indicated by ancestral code.
        self.session.verify = False  # XXXmake TOFU
        self.session.headers.update({'Content-Type': 'application/json'})

        # Set new state not specified in callers
        self.log_level = loglevel
        self.log_dir = self._make_log_dir()

    def _make_log_dir(self):
        second = '%0.f' % time.time()
        full_name = os.path.join('logs', self.__class__.__name__, second)
        dirname = os.path.abspath(full_name)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        return dirname

    @decorate_HTTP_verb_method
    def delete(self, uri, **kwargs):
        return self.session.delete(uri, **kwargs)

    @decorate_HTTP_verb_method
    def get(self, uri, **kwargs):
        return self.session.get(uri, **kwargs)

    @decorate_HTTP_verb_method
    def patch(self, uri, data=None, **kwargs):
        return self.session.patch(uri, data=data, **kwargs)

    @decorate_HTTP_verb_method
    def post(self, uri, data=None, json=None, **kwargs):
        return self.session.post(uri, data=data, json=json, **kwargs)

    @decorate_HTTP_verb_method
    def put(self, uri, data=None, **kwargs):
        return self.session.put(uri, data=data, **kwargs)
