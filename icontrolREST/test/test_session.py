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

import mock
import pytest

from icontrolREST import session


@pytest.fixture()
def ICRS():
    mock_BigIP = mock.MagicMock()
    mock_BigIP.icr_url = 'https://0.0.0.0/mgmt/tm/'
    fake_ICRS = session.IControlRESTSession(mock_BigIP, 'admin', 'admin')
    fake_ICRS.session = mock.MagicMock()
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    fake_ICRS.session.delete.return_value = mock_response
    fake_ICRS.session.get.return_value = mock_response
    fake_ICRS.session.patch.return_value = mock_response
    fake_ICRS.session.post.return_value = mock_response
    fake_ICRS.session.put.return_value = mock_response
    return fake_ICRS


@pytest.fixture()
def uparts():
    parts_dict = {'bigip_icr_uri': 'https://0.0.0.0/mgmt/tm/',
                  'prefix_collections': 'ltm/bar/',
                  'folder': 'BIGCUSTOMER',
                  'instance_name': 'foobar1',
                  'suffix': '/members/m1'}
    return parts_dict


# Test uri component validation
def test_incorrect_uri_construction_bad_scheme(uparts):
    uparts['bigip_icr_uri'] = 'hryttps://0.0.0.0/mgmt/tm/'
    with pytest.raises(session.InvalidScheme) as IS:
        session.generate_bigip_uri(**uparts)
    assert IS.value.message == 'hryttps'


def test_incorrect_uri_construction_bad_mgmt_path(uparts):
    uparts['bigip_icr_uri'] = 'https://0.0.0.0/magmt/tm/'
    with pytest.raises(session.InvalidBigIP_ICRURI) as IR:
        session.generate_bigip_uri(**uparts)
    assert IR.value.message == '/magmt/tm/'


def test_incorrect_uri_construction_bad_base_nonslash_last(uparts):
    uparts['bigip_icr_uri'] = 'https://0.0.0.0/mgmt/tm'
    with pytest.raises(session.InvalidBigIP_ICRURI) as IR:
        session.generate_bigip_uri(**uparts)
    test_value = "The bigip_icr_uri must end with '/'!!  But it's: /mgmt/tm"
    assert IR.value.message == test_value


def test_incorrect_uri_construction_bad_prefix_collection_wrong_start(uparts):
    uparts['prefix_collections'] = '/actions/bar/'
    with pytest.raises(session.InvalidPrefixCollection) as IR:
        session.generate_bigip_uri(**uparts)
    test_value =\
        "prefix_collections element must not start with '/', but it's: %s"\
        % uparts['prefix_collections']
    assert IR.value.message == test_value


def test_incorrect_uri_construction_bad_prefix_collection_wrong_root(uparts):
    uparts['prefix_collections'] = 'foo/bar/'
    with pytest.raises(session.InvalidPrefixCollection) as IR:
        session.generate_bigip_uri(**uparts)
    test_value = "foo is not in the list of root collections: ['actions'," +\
        " 'analytics', 'apm', 'asm', 'auth', 'cli', 'cm', 'gtm', 'ltm'," +\
        " 'net', 'pem', 'security', 'sys', 'transaction', 'util', 'vcmp'," +\
        " 'wam', 'wom']"
    assert IR.value.message == test_value


def test_incorrect_uri_construction_bad_prefix_collection_wrong_end(uparts):
    uparts['prefix_collections'] = 'actions/bar'
    with pytest.raises(session.InvalidPrefixCollection) as IR:
        session.generate_bigip_uri(**uparts)
    test_value =\
        "prefix_collections path element must end with '/', but it's: %s"\
        % uparts['prefix_collections']
    assert IR.value.message == test_value


def test_incorrect_uri_construction_illegal_slash_folder_char(uparts):
    uparts['folder'] = 'spam/ham'
    with pytest.raises(session.InvalidInstanceNameOrFolder) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "instance names and folders cannot contain '/', but it's: %s"\
                 % uparts['folder']
    assert II.value.message == test_value


def test_incorrect_uri_construction_illegal_tilde_folder_char(uparts):
    uparts['folder'] = 'spam~ham'
    with pytest.raises(session.InvalidInstanceNameOrFolder) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "instance names and folders cannot contain '~', but it's: %s"\
                 % uparts['folder']
    assert II.value.message == test_value


def test_incorrect_uri_construction_illegal_suffix_nonslash_first(uparts):
    uparts['suffix'] = 'ham'
    with pytest.raises(session.InvalidSuffixCollection) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "suffix_collections path element must start with '/', but " +\
                 "it's: %s" % uparts['suffix']
    assert II.value.message == test_value


def test_incorrect_uri_construction_illegal_suffix_slash_last(uparts):
    uparts['suffix'] = '/ham/'
    with pytest.raises(session.InvalidSuffixCollection) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "suffix_collections path element must not end with '/', " +\
                 "but it's: %s" % uparts['suffix']
    assert II.value.message == test_value


# Test uri construction
def test_correct_uri_construction_folderless(uparts):
    uparts['folder'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/ltm/bar/~foobar1/members/m1'


def test_correct_uri_construction_nameless(uparts):
    uparts['instance_name'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == "https://0.0.0.0/mgmt/tm/ltm/bar/~BIGCUSTOMER/members/m1"


def test_correct_uri_construction_folderless_and_nameless(uparts):
    uparts['folder'] = ''
    uparts['instance_name'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == "https://0.0.0.0/mgmt/tm/ltm/bar/members/m1"


def test_correct_uri_construction_folder_name_and_suffixless(uparts):
    uparts['folder'] = ''
    uparts['instance_name'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == "https://0.0.0.0/mgmt/tm/ltm/bar/"


def test_correct_uri_construction_folderless_and_suffixless(uparts):
    uparts['folder'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/ltm/bar/~foobar1'


def test_correct_uri_construction_nameless_and_suffixless(uparts):
    uparts['instance_name'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/ltm/bar/~BIGCUSTOMER'


# Test exception handling
def test_wrapped_delete_success(ICRS):
    ICRS.delete('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')


def test_wrapped_delete_207_fail(ICRS):
    ICRS.session.delete.return_value.status_code = 207
    with pytest.raises(session.CustomHTTPError) as CHE:
        ICRS.delete('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')
    assert CHE.value.message.startswith('207 Unexpected Error: ')


def test_wrapped_get_success(ICRS):
    ICRS.get('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')


def test_wrapped_get_207_fail(ICRS):
    ICRS.session.get.return_value.status_code = 207
    with pytest.raises(session.CustomHTTPError) as CHE:
        ICRS.get('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')
    assert CHE.value.message.startswith('207 Unexpected Error: ')


def test_wrapped_patch_success(ICRS):
    ICRS.patch('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')


def test_wrapped_patch_207_fail(ICRS):
    ICRS.session.patch.return_value.status_code = 207
    with pytest.raises(session.CustomHTTPError) as CHE:
        ICRS.patch('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')
    assert CHE.value.message.startswith('207 Unexpected Error: ')


def test_wrapped_post_success(ICRS):
    ICRS.post('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')


def test_wrapped_post_207_fail(ICRS):
    ICRS.session.post.return_value.status_code = 207
    with pytest.raises(session.CustomHTTPError) as CHE:
        ICRS.post('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')
    assert CHE.value.message.startswith('207 Unexpected Error: ')


def test_wrapped_put_success(ICRS):
    ICRS.put('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')


def test_wrapped_put_207_fail(ICRS):
    ICRS.session.put.return_value.status_code = 207
    with pytest.raises(session.CustomHTTPError) as CHE:
        ICRS.put('ltm/nat/', 'A_FOLDER_NAME', 'AN_INSTANCE_NAME')
    assert CHE.value.message.startswith('207 Unexpected Error: ')
