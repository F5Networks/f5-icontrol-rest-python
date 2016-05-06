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
"""Exceptions that can be emitted by the icontrol package."""

from requests import HTTPError


class iControlUnexpectedHTTPError(HTTPError):
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
