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


class CustomHTTPError(requests.HTTPError):
    pass


class BigIPInvalidURL(Exception):
    pass


class InvalidScheme(BigIPInvalidURL):
    pass


class InvalidBigIP_ICRURI(BigIPInvalidURL):
    pass


class InvalidPrefixCollection(BigIPInvalidURL):
    pass


class InvalidInstanceNameOrFolder(BigIPInvalidURL):
    pass


class InvalidSuffixCollection(BigIPInvalidURL):
    pass


def _validate_icruri(bigip_icr_uri):
    scheme, netloc, path, _, _ = urlparse.urlsplit(bigip_icr_uri)
    if scheme != 'https':
        raise InvalidScheme(scheme)
    if path != '/mgmt/tm/':
        if not path.endswith('/'):
            error_message =\
                "The bigip_icr_uri must end with '/'!!  But it's: %s" % path
        else:
            error_message = path
        raise InvalidBigIP_ICRURI(error_message)
    return True


def _validate_prefix_collections(prefix_collections):
    if prefix_collections.startswith('/'):
        error_message =\
            "prefix_collections element must not start with '/', but it's: %s"\
            % prefix_collections
        raise InvalidPrefixCollection(error_message)

    if not prefix_collections.endswith('/'):
        error_message =\
            "prefix_collections path element must end with '/', but it's: %s"\
            % prefix_collections
        raise InvalidPrefixCollection(error_message)

    organizing_collections = [
        'actions', 'analytics', 'apm', 'asm', 'auth',
        'cli', 'cm', 'gtm', 'ltm', 'net', 'pem',
        'security', 'sys', 'transaction', 'util', 'vcmp',
        'wam', 'wom']
    root_collection = prefix_collections.split('/')[0]
    if root_collection not in organizing_collections:
        error_message = '%s is not in the list of root collections: %s'\
                        % (root_collection, organizing_collections)
        raise InvalidPrefixCollection(error_message)
    return True


def _validate_instance_name_or_folder(inst_or_folder):
    if inst_or_folder == '':
        return True
    if '~' in inst_or_folder:
        error_message =\
            "instance names and folders cannot contain '~', but it's: %s"\
            % inst_or_folder
        raise InvalidInstanceNameOrFolder(error_message)
    elif '/' in inst_or_folder:
        error_message =\
            "instance names and folders cannot contain '/', but it's: %s"\
            % inst_or_folder
        raise InvalidInstanceNameOrFolder(error_message)
    return True


def _validate_suffix_collections(suffix_collections):
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


def _validate_uri_parts(bigip_icr_uri, prefix_collections, folder,
                        instance_name, suffix_collections):
    _validate_icruri(bigip_icr_uri)
    _validate_prefix_collections(prefix_collections)
    _validate_instance_name_or_folder(folder)
    _validate_instance_name_or_folder(instance_name)
    if suffix_collections:
        _validate_suffix_collections(suffix_collections)
    return True


def generate_bigip_uri(bigip_icr_uri, prefix_collections, folder,
                       instance_name,  *args, **kwargs):
    suffix_collections = kwargs.pop('suffix', '')
    _validate_uri_parts(bigip_icr_uri, prefix_collections, instance_name,
                        folder, suffix_collections)
    if folder != '':
        folder = '~'+folder
    if instance_name != '':
        instance_name = '~'+instance_name
    tilded_folder_and_instance = folder+instance_name
    if suffix_collections and not tilded_folder_and_instance:
        suffix_collections = suffix_collections.lstrip('/')
    REST_uri = bigip_icr_uri+prefix_collections+tilded_folder_and_instance +\
        suffix_collections
    return REST_uri


def _config_logging(logdir, methodname, level, cls_name, *args, **kwargs):
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


def _log_HTTP_verb_method_precall(logger, methodname, level, cls_name, *args,
                                  **kwargs):
    pre_message = "%s.%s WITH args: %s, kwargs: %s" %\
        (cls_name, methodname, args, kwargs)
    logger.log(level, pre_message)


def _log_HTTP_verb_method_postcall(logger, level, response):
    post_message = "RESPONSE::STATUS:" +\
                   " %s Content-Type: %s Content-Encoding: %s" %\
        (response.status_code,
         response.headers.get('Content-Type', None),
         response.headers.get('Content-Encoding', None))
    logger.log(level, post_message)


def decorate_HTTP_verb_method(method):
    @functools.wraps(method)
    def wrapper(self, prefix_collections, folder, instance_name, *args,
                **kwargs):
        REST_uri = generate_bigip_uri(self.bigip.icr_url, prefix_collections,
                                      folder, instance_name, *args, **kwargs)
        logger = _config_logging(self.log_dir, method.__name__, self.log_level,
                                 self.__class__.__name__, *args, **kwargs)
        _log_HTTP_verb_method_precall(logger, method.__name__,
                                      self.log_level, self.__class__.__name__,
                                      *args, **kwargs)
        response = method(self, REST_uri, *args, **kwargs)
        _log_HTTP_verb_method_postcall(logger, self.log_level, response)
        response.raise_for_status()
        if response.status_code not in range(200, 207):
            error_message = '%s Unexpected Error: %s for uri: %s' %\
                            (response.status_code,
                             response.reason,
                             response.uri)
            raise CustomHTTPError(error_message, response=response)
        return response
    return wrapper


class IControlRESTSession(object):
    """XXX

    XXXX
    """
    def __init__(self, bigip, username, password, timeout=30,
                 log_level=logging.DEBUG):
        # Compose with a Session obj
        self.bigip = bigip
        self.session = requests.Session()

        self.bigip_version = None  # XXXimplement call to get this
        # Configure with passed parameters
        self.session.auth = (username, password)
        self.session.timeout = timeout

        # Set state as indicated by ancestral code.
        self.session.verify = False  # XXXmake TOFU
        self.session.headers.update({'Content-Type': 'application/json'})

        # Set new state not specified in callers
        self.log_level = log_level
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
        return self.session.patch(uri, data=None, **kwargs)

    @decorate_HTTP_verb_method
    def post(self, uri, data=None, json=None, **kwargs):
        return self.session.post(uri, data=None, json=None, **kwargs)

    @decorate_HTTP_verb_method
    def put(self, uri, data=None, **kwargs):
        return self.session.put(uri, data=None, **kwargs)
