# Copyright 2019 F5 Networks Inc.
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

'''This test suite attempts to test the things that a real BIGIP device is
required for that unit testing cannot test.  For example the unit tests can
cover the case in which the beginning of the URL is correct up to the
collection object i.e. https://192.168.1.1/mgmt/tm/  It cannot test that
the collection objects that are after that are correct
i.e https://192.168.1.1/mgmt/tm/boguscollection
'''

from distutils.version import LooseVersion
from icontrol.authtoken import iControlRESTTokenAuth
from icontrol.session import iControlRESTSession
from requests.exceptions import HTTPError
from requests.exceptions import SSLError

import os
import pytest
import time


@pytest.fixture
def modules():
    result = [
        'am', 'afm', 'apm', 'asm', 'avr', 'fps', 'gtm', 'ilx',
        'lc', 'ltm', 'pem', 'sam', 'swg', 'vcmp'
    ]
    return result


@pytest.fixture(autouse=True)
def skip_module_missing(request, modules, opt_bigip, opt_username, opt_password, opt_port):
    if request.node.get_marker('skip_module_missing'):
        marker = request.node.get_marker('skip_module_missing').args[0]
        if marker in modules:
            try:
                from f5.bigip import ManagementRoot
            except ImportError:
                pytest.skip('Skipping test because I cannot determine if "{0}" is not provisioned'.format(marker))
            mgmt = ManagementRoot(opt_bigip, opt_username, opt_password, port=opt_port, token=True)
            provision = mgmt.tm.sys.provision
            resource = getattr(provision, marker)
            resource = resource.load()
            result = resource.attrs
            if str(result['level']) == 'none':
                pytest.skip('Skipping test because "{0}" is not provisioned'.format(marker))


nat_data = {
    'name': 'foo',
    'partition': 'Common',
    'originatingAddress': '192.168.1.1',
    'translationAddress': '192.168.2.1',
}

topology_data = {
    'name': 'ldns: subnet 192.168.110.0/24 server: subnet 192.168.100.0/24'
}

iapp_templ_data = {
    "name": "test_templ",
    "partition": "Common",
    "actions": {
        "definition":
        {
            "implementation": '''tmsh::create {
            ltm pool /Common/test_serv.app/test_pool
            load-balancing-mode least-connections-node
            members replace-all-with {128.0.0.2:8080{address 128.0.0.2}}
            }''',
            "presentation": ""
        }
    }
}


iapp_serv_data = {
    "name": "test_serv",
    "partition": "Common",
    "template": "/Common/test_templ"
}


iapp_templ_data_subpath_v11 = {
    "name": "test_templ_subpath",
    "partition": "Common",
    "actions": {
        "definition":
        {
            "implementation": '''tmsh::create { net vlan v102 }
                tmsh::create { net self self.v102 address 192.168.1.5/24 vlan v102 }
                tmsh::create { gtm datacenter dc1 }
                tmsh::create { auth partition part1 }
                tmsh::cd { /part1 }
                tmsh::create { ltm virtual v1 destination 192.168.1.100:80 }
                tmsh::cd { /Common }
                tmsh::create { gtm server ltm11 addresses add { 192.168.1.5 } datacenter dc1
                virtual-servers replace-all-with { /part1/v1 { destination 192.168.1.100:80 } } }
                tmsh::cd { /part1 }
                tmsh::create { gtm pool p1 members replace-all-with { /Common/ltm11:/part1/v1 } }''',
            "presentation": ""
        }
    }
}


iapp_serv_data_subpath = {
    "name": "test_serv_subpath",
    "partition": "Common",
    "template": "/Common/test_templ_subpath"
}


@pytest.fixture
def setup_subpath(request, ICR, BASE_URL):
    app_templ_url = BASE_URL + 'sys/application/template/'
    app_serv_url = BASE_URL + 'sys/application/service/'

    def teardown_iapp():
        try:
            ICR.delete(
                app_serv_url, uri_as_parts=True,
                name='test_serv', partition='Common',
                subPath='test_serv.app')
        except Exception:
            pass

        try:
            ICR.delete(
                app_templ_url, uri_as_parts=True,
                name='test_templ', partition='Common')
        except Exception:
            pass

    teardown_iapp()
    ICR.post(app_templ_url, json=iapp_templ_data)
    try:
        ICR.post(app_serv_url, json=iapp_serv_data)
    except HTTPError as ex:
        # The creation of an iapp service does cause a 404 error in bigip
        # versions up to but excluding 12.0
        if ex.response.status_code == 404:
            pass
    request.addfinalizer(teardown_iapp)
    return app_serv_url


@pytest.fixture
def setup_subpath_alt(request, ICR, BASE_URL):
    app_templ_url = BASE_URL + 'sys/application/template/'
    app_serv_url = BASE_URL + 'sys/application/service/'

    def teardown_iapp():
        try:
            ICR.delete(
                app_serv_url, uri_as_parts=True,
                name='test_serv_subpath', partition='Common',
                subPath='test_serv_subpath.app')
        except Exception:
            pass

        try:
            ICR.delete(
                app_templ_url, uri_as_parts=True,
                name='test_templ_subpath', partition='Common')
        except Exception:
            pass

    teardown_iapp()
    ICR.post(app_templ_url, json=iapp_templ_data_subpath_v11)
    try:
        ICR.post(app_serv_url, json=iapp_serv_data_subpath)
    except HTTPError as ex:
        # The creation of an iapp service does cause a 404 error in bigip
        # versions up to but excluding 12.0
        if ex.response.status_code == 404:
            pass
    request.addfinalizer(teardown_iapp)
    return app_serv_url


def teardown_nat(request, icr, url, name, partition):
    '''Remove the nat object that we create during a test '''
    def teardown():
        icr.delete(url, uri_as_parts=True, name=name, partition=partition)
    request.addfinalizer(teardown)


def teardown_topology(request, icr, url, name):
    """Remove the topology object that we create during a test."""
    def teardown():
        icr.delete(url, uri_as_parts=True, transform_name=True, name=name)
    request.addfinalizer(teardown)


def invalid_url(func, url):
    '''Reusable test to make sure that we get 404 for invalid URL '''
    with pytest.raises(HTTPError) as err:
        func(url)
    return (err.value.response.status_code == 404 and 'Unexpected Error: Not Found for uri: ' + url in str(err.value))


def invalid_credentials(user, password, url):
    '''Reusable test to make sure that we get 401 for invalid creds '''
    icr = iControlRESTSession(user, password)
    with pytest.raises(HTTPError) as err:
        icr.get(url)
    return (err.value.response.status_code == 401 and '401 Client Error: F5 Authorization Required' in str(err.value))


def invalid_token_credentials(user, password, url):
    '''Reusable test to make sure that we get 401 for invalid token creds '''
    icr = iControlRESTSession(user, password, token=True)
    with pytest.raises(HTTPError) as err:
        icr.get(url)
    return (err.value.response.status_code == 401 and 'Authentication required!' in str(err.value))


def test_get_with_subpath(setup_subpath, ICR, BASE_URL):
    # The iapp creates a pool. We should be able to get that pool with subPath
    app_serv_url = setup_subpath
    res = ICR.get(
        app_serv_url, name='test_serv',
        partition='Common', subPath='test_serv.app')
    assert res.status_code == 200
    pool_uri = BASE_URL + 'ltm/pool/'
    pool_res = ICR.get(
        pool_uri, name='test_pool',
        partition='Common', subPath='test_serv.app')
    assert pool_res.status_code == 200
    data = pool_res.json()
    assert data['items'][0]['subPath'] == 'test_serv.app'
    assert data['items'][0]['name'] == 'test_pool'


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) >= LooseVersion(
        '12.0.0'),
    reason='No GTM Pool type, introduced in 12.0+'
)
def test_get_with_subpath_transform(setup_subpath_alt, ICR, BASE_URL):
    app_serv_url = setup_subpath_alt
    res = ICR.get(
        app_serv_url, name='test_serv_subpath',
        partition='Common', subPath='test_serv_subpath.app')
    assert res.status_code == 200
    pool_uri = BASE_URL + 'gtm/pool/~part1~p1/members/'
    poolmem_res = ICR.get(pool_uri, name='v1', partition='Common', subPath='ltm11:/part1')
    assert poolmem_res.status_code == 200
    data = poolmem_res.json()
    assert data['items'][0]['name'] == 'v1'
    assert data['items'][0]['subPath'] == 'ltm11:/part1'


def test_get(ICR, GET_URL):
    '''Test a GET request to a valid url

    Pass: Returns a 200 with proper json
    '''
    response = ICR.get(GET_URL)
    assert response.status_code == 200
    assert response.json()


def test_get_invalid_url(ICR, FAKE_URL):
    '''Test a GET to an invalid URL.

    Pass: Returns a 404 with a proper message
    '''
    assert invalid_url(ICR.get, FAKE_URL)


def test_post(request, ICR, POST_URL):
    '''Test a POST request to a valid url

    Pass: Returns a 200 and the json object is set correctly
    '''
    teardown_nat(
        request, ICR, POST_URL, nat_data['name'], nat_data['partition'])
    response = ICR.post(POST_URL, json=nat_data)
    response_data = response.json()
    assert response.status_code == 200
    assert(response_data['name'] == nat_data['name'])
    assert(response_data['partition'] == nat_data['partition'])
    assert(response_data['originatingAddress'] == nat_data['originatingAddress'])
    assert(response_data['translationAddress'] == nat_data['translationAddress'])


def test_post_invalid_url(ICR, FAKE_URL):
    '''Test a POST request to an invalid url.

    Pass: Returns a 404 with a proper message
    '''
    assert invalid_url(ICR.post, FAKE_URL)


def test_put(request, ICR, POST_URL):
    '''Test a PUT request to a valid url.

    Pass: Returns a 200 and the json object is set correctly
    '''
    data = {'originatingAddress': '192.168.1.50'}
    teardown_nat(
        request, ICR, POST_URL, nat_data['name'], nat_data['partition'])
    ICR.post(POST_URL, json=nat_data)
    response = ICR.put(
        POST_URL,
        name=nat_data['name'],
        partition=nat_data['partition'],
        uri_as_parts=True,
        json=data)
    response_data = response.json()
    assert response.status_code == 200
    assert response_data['originatingAddress'] == data['originatingAddress']
    assert response_data['name'] == nat_data['name']
    assert response_data['partition'] == nat_data['partition']
    assert response_data['translationAddress'] == \
        nat_data['translationAddress']


def test_put_invalid_url(ICR, FAKE_URL):
    '''Test a PUT request to an invalid url.

    Pass: Return a 404 with a proper error message
    '''
    assert invalid_url(ICR.put, FAKE_URL)


def test_patch(request, ICR, POST_URL):
    '''Test a PATCH request to a valid url.

    Pass: Returns a 200 and the json object is set correctly
    '''
    data = {'originatingAddress': '192.168.1.50'}
    teardown_nat(
        request, ICR, POST_URL, nat_data['name'], nat_data['partition'])
    ICR.post(POST_URL, json=nat_data)
    response = ICR.patch(
        POST_URL,
        name=nat_data['name'],
        partition=nat_data['partition'],
        uri_as_parts=True,
        json=data)
    response_data = response.json()
    assert response.status_code == 200
    assert response_data['originatingAddress'] == data['originatingAddress']
    assert response_data['name'] == nat_data['name']
    assert response_data['partition'] == nat_data['partition']
    assert response_data['translationAddress'] == \
        nat_data['translationAddress']


def test_patch_invalid_url(ICR, FAKE_URL):
    '''Test a PATCH request to an invalid url.

    Pass: Return a 404 with a proper error message
    '''
    assert invalid_url(ICR.patch, FAKE_URL)


def test_delete(request, ICR, POST_URL):
    '''Test a DELETE request to a valid url.

    Pass: Return a 200 and the json is empty.  Subsequent GET returns a 404
    error because the object is no longer found.
    '''
    ICR.post(POST_URL, json=nat_data)
    response = ICR.delete(
        POST_URL,
        name=nat_data['name'],
        partition=nat_data['partition'],
        uri_as_parts=True)
    assert response.status_code == 200
    with pytest.raises(ValueError):
        response.json()

    with pytest.raises(HTTPError) as err:
        ICR.get(
            POST_URL,
            name=nat_data['name'],
            partition=nat_data['partition'],
            uri_as_parts=True)
    assert err.value.response.status_code == 404


def test_delete_invalid_url(ICR, FAKE_URL):
    '''Test a DELETE request to an invalid url.

    Pass: Return a 404 with a proper error message
    '''
    assert invalid_url(ICR.delete, FAKE_URL)


def test_invalid_user(opt_password, GET_URL):
    '''Test login with an invalid username and valid password

    Pass: Returns 401 with authorization required message
    '''
    invalid_credentials('fakeuser', opt_password, GET_URL)


def test_invalid_password(opt_username, GET_URL):
    '''Test login with a valid username and invalid password

    Pass: Returns 401 with authorization required message
    '''
    invalid_credentials(opt_username, 'fakepassword', GET_URL)


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) == LooseVersion(
        '11.5.4'),
    reason='Endpoint does not exist in 11.5.4'
)
def test_token_auth(opt_username, opt_password, GET_URL):
    icr = iControlRESTSession(opt_username, opt_password, token=True)
    response = icr.get(GET_URL)
    assert response.status_code == 200


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) == LooseVersion(
        '11.5.4'),
    reason='Endpoint does not exist in 11.5.4'
)
def test_token_auth_twice(opt_username, opt_password, GET_URL):
    icr = iControlRESTSession(opt_username, opt_password, token=True)
    assert icr.session.auth.attempts == 0
    response = icr.get(GET_URL)
    assert response.status_code == 200
    assert icr.session.auth.attempts == 1
    response = icr.get(GET_URL)
    assert response.status_code == 200
    # This token should still be valid, so we should reuse it.
    assert icr.session.auth.attempts == 1


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) == LooseVersion(
        '11.5.4'),
    reason='Endpoint does not exist in 11.5.4'
)
def test_token_auth_expired(opt_username, opt_password, GET_URL):
    icr = iControlRESTSession(opt_username, opt_password, token=True)
    assert icr.session.auth.attempts == 0
    response = icr.get(GET_URL)
    assert response.status_code == 200
    assert icr.session.auth.attempts == 1
    assert icr.session.auth.expiration >= time.time()

    # Artificially expire the token
    icr.session.auth.expiration = time.time() - 1.0

    # Since token is expired, we should get a new one.
    response = icr.get(GET_URL)
    assert response.status_code == 200
    assert icr.session.auth.attempts == 2


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) == LooseVersion(
        '11.5.4'),
    reason='Endpoint does not exist in 11.5.4'
)
def test_token_invalid_user(opt_password, GET_URL):
    invalid_token_credentials('fakeuser', opt_password, GET_URL)


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) == LooseVersion(
        '11.5.4'),
    reason='Endpoint does not exist in 11.5.4'
)
def test_token_invalid_password(opt_username, GET_URL):
    invalid_token_credentials(opt_username, 'fakepassword', GET_URL)


# You must configure a user that has a non-admin role in a partition for
# test_nonadmin tests to be effective.  For instance:
#
# auth user bob {
#    description bob
#    encrypted-password $6$LsSnHp7J$AIJ2IC8kS.YDrrn/sH6BsxQ...
#    partition Common
#    partition-access {
#        bobspartition {
#            role operator
#        }
#    }
#    shell tmsh
# }
#
# Then instantiate with --nonadmin-username=bob --nonadmin-password=changeme
def test_nonadmin_token_auth(opt_nonadmin_username, opt_nonadmin_password,
                             GET_URL):
    if not opt_nonadmin_username or not opt_nonadmin_password:
        pytest.skip("No non-admin username/password configured")
    icr = iControlRESTSession(opt_nonadmin_username,
                              opt_nonadmin_password,
                              token=True)
    response = icr.get(GET_URL)
    assert response.status_code == 200


def test_nonadmin_token_auth_invalid_password(opt_nonadmin_username,
                                              GET_URL):
    if not opt_nonadmin_username:
        pytest.skip("No non-admin username/password configured")
    invalid_token_credentials(opt_nonadmin_username,
                              'fakepassword',
                              GET_URL)


def test_nonadmin_token_auth_invalid_username(opt_nonadmin_password,
                                              GET_URL):
    if not opt_nonadmin_password:
        pytest.skip("No non-admin username/password configured")
    invalid_token_credentials('fakeuser',
                              opt_nonadmin_password,
                              GET_URL)


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) > LooseVersion('12.0.0'),
    reason='Issue with spaces in the name parameter has been resolved post '
           '12.1.x, therefore another test needs running'
)
@pytest.mark.skip_module_missing('gtm')
def test_get_special_name_11_x_12_0(request, ICR, BASE_URL):
    """Get the object with '/' characters in name

    Due to a bug name kwarg needs to have space in front of "ldns" and
    "server" key words when using GET method. We also need to catch and
    ignore 404 response to POST due to a bug with topology creation in 11.5.4
    """

    ending = 'gtm/topology/'
    topology_url = BASE_URL + ending
    load_name = ' ldns: subnet 192.168.110.0/24  server: subnet ' \
                '192.168.100.0/24'
    teardown_topology(request, ICR, topology_url, load_name)
    try:
        ICR.post(topology_url, json=topology_data)

    except HTTPError as err:
        if err.response.status_code == 404:
            pass
        else:
            raise

    response = ICR.get(topology_url, uri_as_parts=True, transform_name=True,
                       name=load_name)
    assert response.status_code == 200
    data = response.json()
    assert data['name'] == load_name
    assert data['kind'] == 'tm:gtm:topology:topologystate'


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) < LooseVersion(
        '12.1.0'),
    reason='Issue with paces in the name parameter has been resolved in '
           '12.1.x and up, any lower version will fail this test otherwise'
)
@pytest.mark.skip_module_missing('gtm')
def test_get_special_name_12_1(request, ICR, BASE_URL):
    """Get the object with '/' characters in name

    Since the blank space issue was fixed in 12.1.0,
    this test had to change.
    """

    ending = 'gtm/topology/'
    topology_url = BASE_URL + ending
    load_name = 'ldns: subnet 192.168.110.0/24 server: subnet ' \
                '192.168.100.0/24'
    teardown_topology(request, ICR, topology_url, load_name)
    try:
        ICR.post(topology_url, json=topology_data)

    except HTTPError as err:
        if err.response.status_code == 404:
            pass
        else:
            raise

    response = ICR.get(topology_url, uri_as_parts=True, transform_name=True,
                       name=load_name)
    assert response.status_code == 200
    data = response.json()
    assert data['name'] == load_name
    assert data['kind'] == 'tm:gtm:topology:topologystate'


@pytest.mark.skipif(
    LooseVersion(pytest.config.getoption('--release')) < LooseVersion('12.1.0'),
    reason='GTM must be provisioned for this test'
)
@pytest.mark.skip_module_missing('gtm')
def test_delete_special_name(request, ICR, BASE_URL):
    """Test a DELETE request to a valid url.

    Pass: Return a 200 and the json is empty.  Subsequent GET returns a 404
    error because the object is no longer found.
    """
    ending = 'gtm/topology/'
    topology_url = BASE_URL + ending

    try:
        ICR.post(topology_url, json=topology_data)

    except HTTPError as err:
        if err.response.status_code == 404:
            pass
        else:
            raise

    response = ICR.delete(
        topology_url,
        name=topology_data['name'],
        uri_as_parts=True,
        transform_name=True)
    assert response.status_code == 200
    with pytest.raises(ValueError):
        response.json()

    with pytest.raises(HTTPError) as err:
        ICR.get(
            topology_url,
            name=topology_data['name'],
            uri_as_parts=True,
            transform_name=True)
    assert err.value.response.status_code == 404


def test_ssl_verify(opt_username, opt_password, GET_URL, opt_ca_bundle):
    """Test connection with a trusted certificate"""
    if not opt_ca_bundle:
        pytest.skip("No CA bundle configured")
    icr = iControlRESTSession(opt_username, opt_password,
                              token=True, verify=opt_ca_bundle)
    icr.get(GET_URL)


def test_ssl_verify_fail(opt_username, opt_password, GET_URL):
    """Test connection with an untrusted certificate"""
    dir_path = os.path.dirname(os.path.realpath(__file__))
    ca_bundle = '%s/dummy-ca-cert.pem' % dir_path
    icr = iControlRESTSession(opt_username, opt_password,
                              verify=ca_bundle)
    with pytest.raises(SSLError) as excinfo:
        icr.get(GET_URL)
    assert 'certificate verify failed' in str(excinfo.value)


def test_get_token_ssl_verify_fail(opt_username, opt_password, opt_bigip, opt_port):
    """Test token retrival with an untrusted certificate"""
    dir_path = os.path.dirname(os.path.realpath(__file__))
    ca_bundle = '%s/dummy-ca-cert.pem' % dir_path
    icr = iControlRESTTokenAuth(opt_username, opt_password,
                                verify=ca_bundle)
    with pytest.raises(SSLError) as excinfo:
        icr.get_new_token('{0}:{1}'.format(opt_bigip, opt_port))
    assert 'certificate verify failed' in str(excinfo.value)


def test_using_stashed_tokens(GET_URL, opt_bigip, opt_username, opt_password):
    icr1 = iControlRESTSession(opt_username, opt_password, token='tmos')
    icr2 = iControlRESTSession(opt_username, opt_password, token='tmos')

    # Trigger token creation
    icr1.get(GET_URL)
    icr2.get(GET_URL)

    # Ensure we have two completely different sessions here
    assert icr1.token != icr2.token

    # Ensure that both of them are valid
    response = icr1.get(GET_URL)
    assert response.status_code == 200
    assert response.json()
    response = icr2.get(GET_URL)
    assert response.status_code == 200
    assert response.json()

    # Overwrite one session with another. This is illustrating the behavior
    # one might see when loading a cookie from disk.
    icr1.token = icr2.token

    # Ensure we indeed overwrote the tokens
    assert icr1.token == icr2.token

    # Recheck to make sure that all web requests still work
    response = icr1.get(GET_URL)
    assert response.status_code == 200
    assert response.json()
    response = icr2.get(GET_URL)
    assert response.status_code == 200
    assert response.json()

    # Create new object with no token data
    icr3 = iControlRESTSession(opt_username, opt_password, token='tmos')
    assert icr3.token is None

    # Give token to new session
    icr3.token = icr2.token

    # Ensure new object can talk
    response = icr1.get(GET_URL)
    assert response.status_code == 200
    assert response.json()

    # Ensure new object did not get new token but used existing one
    assert icr3.token == icr2.token

    # Provide the token via object instantiation
    icr4 = iControlRESTSession(
        opt_username, opt_password, token='tmos',
        token_to_use=icr2.token
    )

    # Ensure the token was actually given
    assert icr4.token == icr2.token

    # Ensure the provided token works
    response = icr4.get(GET_URL)
    assert response.status_code == 200
    assert response.json()


def test_using_tmos_token(GET_URL, opt_bigip, opt_username, opt_password):
    icr1 = iControlRESTSession(opt_username, opt_password, token='tmos')
    response = icr1.get(GET_URL)
    assert response.status_code == 200
    assert response.json()


def test_using_tmos_auth_provider(GET_URL, opt_bigip, opt_username, opt_password):
    icr1 = iControlRESTSession(opt_username, opt_password, auth_provider='tmos')
    response = icr1.get(GET_URL)
    assert response.status_code == 200
    assert response.json()


def test_debug_tracing(request, POST_URL, GET_URL, opt_bigip, opt_username, opt_password):
    icr1 = iControlRESTSession(opt_username, opt_password, auth_provider='tmos')
    icr1.debug = True
    icr1.get(GET_URL)
    response = icr1.post(POST_URL, json=nat_data)
    response.json()
    teardown_nat(request, icr1, POST_URL, nat_data['name'], nat_data['partition'])
    assert len(icr1.debug_output) > 0
