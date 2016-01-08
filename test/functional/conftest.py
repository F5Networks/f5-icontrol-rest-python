# Copyright 2015-2016 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from icontrol.session import iControlRESTSession

import pytest


def pytest_addoption(parser):
    parser.addoption("--bigip", action="store",
                     help="BIG-IP hostname or IP address")
    parser.addoption("--username", action="store", help="BIG-IP REST username",
                     default="admin")
    parser.addoption("--password", action="store", help="BIG-IP REST password",
                     default="admin")


def pytest_generate_tests(metafunc):
    assert metafunc.config.option.bigip


@pytest.fixture
def opt_bigip(request):
    return request.config.getoption("--bigip")


@pytest.fixture
def opt_username(request):
    return request.config.getoption("--username")


@pytest.fixture
def opt_password(request):
    return request.config.getoption("--password")


@pytest.fixture
def ICR(opt_bigip, opt_username, opt_password):
    icr = iControlRESTSession(opt_username, opt_password)
    return icr


@pytest.fixture
def GET_URL(opt_bigip):
    url = 'https://' + opt_bigip + '/mgmt/tm/ltm/nat/'
    return url


@pytest.fixture
def POST_URL(opt_bigip):
    url = 'https://' + opt_bigip + '/mgmt/tm/ltm/nat/'
    return url


@pytest.fixture
def FAKE_URL(opt_bigip):
    fake_url = 'https://' + opt_bigip + '/mgmt/tm/bogus/'
    return fake_url
