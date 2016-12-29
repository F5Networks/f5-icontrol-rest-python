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

import mock
import pytest

from icontrol import __version__ as VERSION
from icontrol import session

UA = 'f5-icontrol-rest-python/%s' % VERSION


@pytest.fixture()
def iCRS():
    fake_iCRS = session.iControlRESTSession('admin', 'admin')
    fake_iCRS.session = mock.MagicMock()
    mock_response = mock.MagicMock()
    mock_response.status_code = 200
    fake_iCRS.session.delete.return_value = mock_response
    fake_iCRS.session.get.return_value = mock_response
    fake_iCRS.session.patch.return_value = mock_response
    fake_iCRS.session.post.return_value = mock_response
    fake_iCRS.session.put.return_value = mock_response
    return fake_iCRS


@pytest.fixture()
def uparts():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/tm/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1',
                  'sub_path': '',
                  'suffix': '/members/m1',
                  'transform_name': False}
    return parts_dict


@pytest.fixture()
def transform_name():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/tm/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1: 1.1.1.1/24 bar1: /Common/DC1',
                  'sub_path': '',
                  'suffix': '/members/m1',
                  'transform_name': True}
    return parts_dict


@pytest.fixture()
def uparts_with_subpath():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/tm/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1',
                  'sub_path': 'sp',
                  'suffix': '/members/m1',
                  'transform_name': False}
    return parts_dict


@pytest.fixture()
def transform_name_w_subpath():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/tm/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1: 1.1.1.1/24 bar1: /Common/DC1',
                  'sub_path': 'sp',
                  'suffix': '/members/m1',
                  'transform_name': True}
    return parts_dict


@pytest.fixture()
def uparts_shared():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/shared/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1',
                  'sub_path': '',
                  'suffix': '/members/m1'}
    return parts_dict


@pytest.fixture()
def uparts_cm():
    parts_dict = {'base_uri': 'https://0.0.0.0/mgmt/cm/root/RESTiface/',
                  'partition': 'BIGCUSTOMER',
                  'name': 'foobar1',
                  'sub_path': '',
                  'suffix': '/members/m1'}
    return parts_dict


# Test invalid args
def test_iCRS_with_invalid_construction():
    with pytest.raises(TypeError) as UTE:
        session.iControlRESTSession('admin', 'admin', what='foble')
    assert str(UTE.value) == "Unexpected **kwargs: {'what': 'foble'}"


# Test uri component validation
def test_incorrect_uri_construction_bad_scheme(uparts):
    uparts['base_uri'] = 'hryttps://0.0.0.0/mgmt/tm/root/RESTiface/'
    with pytest.raises(session.InvalidScheme) as IS:
        session.generate_bigip_uri(**uparts)
    assert str(IS.value) == 'hryttps'


def test_incorrect_uri_construction_bad_mgmt_path(uparts):
    uparts['base_uri'] = 'https://0.0.0.0/magmt/tm/root/RESTiface'
    with pytest.raises(session.InvalidBigIP_ICRURI) as IR:
        session.generate_bigip_uri(**uparts)
    assert "But it's: '/magmt/tm/root/RESTiface'" in str(IR.value)


def test_incorrect_uri_construction_bad_base_nonslash_last(uparts):
    uparts['base_uri'] = 'https://0.0.0.0/mgmt/tm/root/RESTiface'
    with pytest.raises(session.InvalidPrefixCollection) as IR:
        session.generate_bigip_uri(**uparts)
    test_value = "prefix_collections path element must end with '/', but" +\
        " it's: root/RESTiface"
    assert str(IR.value) == test_value


def test_incorrect_uri_construction_illegal_slash_partition_char(uparts):
    uparts['partition'] = 'spam/ham'
    with pytest.raises(session.InvalidInstanceNameOrFolder) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "instance names and partitions cannot contain '/', but" +\
        " it's: %s" % uparts['partition']
    assert str(II.value) == test_value


def test_incorrect_uri_construction_illegal_tilde_partition_char(uparts):
    uparts['partition'] = 'spam~ham'
    with pytest.raises(session.InvalidInstanceNameOrFolder) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "instance names and partitions cannot contain '~', but" +\
        " it's: %s" % uparts['partition']
    assert str(II.value) == test_value


def test_incorrect_uri_construction_illegal_suffix_nonslash_first(uparts):
    uparts['suffix'] = 'ham'
    with pytest.raises(session.InvalidSuffixCollection) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "suffix_collections path element must start with '/', but " +\
                 "it's: %s" % uparts['suffix']
    assert str(II.value) == test_value


def test_incorrect_uri_construction_illegal_suffix_slash_last(uparts):
    uparts['suffix'] = '/ham/'
    with pytest.raises(session.InvalidSuffixCollection) as II:
        session.generate_bigip_uri(**uparts)
    test_value = "suffix_collections path element must not end with '/', " +\
                 "but it's: %s" % uparts['suffix']
    assert str(II.value) == test_value


# Test uri construction
def test_correct_uri_construction_partitionless(uparts):
    uparts['partition'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/foobar1/members/m1'


def test_correct_uri_construction_partitionless_subpath(uparts_with_subpath):
    uparts_with_subpath['partition'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**uparts_with_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_construction_nameless(uparts):
    uparts['name'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri ==\
        "https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER/members/m1"


def test_correct_uri_construction_nameless_subpath(uparts_with_subpath):
    uparts_with_subpath['name'] = ''
    uri = session.generate_bigip_uri(**uparts_with_subpath)
    assert uri ==\
        "https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER~sp/members/m1"


def test_correct_uri_construction_partitionless_and_nameless(uparts):
    uparts['partition'] = ''
    uparts['name'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == "https://0.0.0.0/mgmt/tm/root/RESTiface/members/m1"


def test_correct_uri_construction_partitionless_and_nameless_subpath(
        uparts_with_subpath):
    uparts_with_subpath['partition'] = ''
    uparts_with_subpath['name'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**uparts_with_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_construction_partition_name_and_suffixless(uparts):
    uparts['partition'] = ''
    uparts['name'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == "https://0.0.0.0/mgmt/tm/root/RESTiface/"


def test_correct_uri_construction_partition_name_and_suffixless_subpath(
        uparts_with_subpath):
    uparts_with_subpath['partition'] = ''
    uparts_with_subpath['name'] = ''
    uparts_with_subpath['suffix'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**uparts_with_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_construction_partitionless_and_suffixless(uparts):
    uparts['partition'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/foobar1'


def test_correct_uri_construction_partitionless_and_suffixless_subpath(
        uparts_with_subpath):
    uparts_with_subpath['partition'] = ''
    uparts_with_subpath['suffix'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**uparts_with_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_construction_nameless_and_suffixless(uparts):
    uparts['name'] = ''
    uparts['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER'


def test_correct_uri_construction_nameless_and_suffixless_subpath(
        uparts_with_subpath):
    uparts_with_subpath['name'] = ''
    uparts_with_subpath['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts_with_subpath)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER~sp'


def test_correct_uri_construction_partitionless_transform_name(transform_name):
    transform_name['partition'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri == \
        'https://0.0.0.0/mgmt/tm/root/RESTiface/foobar1: ' \
        '1.1.1.1~24 bar1: ~Common~DC1/members/m1'


def test_correct_uri_transformed_partitionless_subpath(
        transform_name_w_subpath):
    transform_name_w_subpath['partition'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**transform_name_w_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_transformed_nameless(transform_name):
    transform_name['name'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri ==\
        "https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER/members/m1"


def test_correct_uri_transformed_nameless_subpath(transform_name_w_subpath):
    transform_name_w_subpath['name'] = ''
    uri = session.generate_bigip_uri(**transform_name_w_subpath)
    assert uri ==\
        "https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER~sp/members/m1"


def test_correct_uri_transformed_partitionless_and_nameless(transform_name):
    transform_name['partition'] = ''
    transform_name['name'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri == "https://0.0.0.0/mgmt/tm/root/RESTiface/members/m1"


def test_correct_uri_transformed_partitionless_and_nameless_subpath(
        transform_name_w_subpath):
    transform_name_w_subpath['partition'] = ''
    transform_name_w_subpath['name'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**transform_name_w_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_transformed_partition_name_and_suffixless(transform_name):
    transform_name['partition'] = ''
    transform_name['name'] = ''
    transform_name['suffix'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri == "https://0.0.0.0/mgmt/tm/root/RESTiface/"


def test_correct_uri_transformed_partition_name_and_suffixless_subpath(
        transform_name_w_subpath):
    transform_name_w_subpath['partition'] = ''
    transform_name_w_subpath['name'] = ''
    transform_name_w_subpath['suffix'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**transform_name_w_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_transformed_partitionless_and_suffixless(transform_name):
    transform_name['partition'] = ''
    transform_name['suffix'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri == \
        'https://0.0.0.0/mgmt/tm/root/RESTiface/foobar1: ' \
        '1.1.1.1~24 bar1: ~Common~DC1'


def test_correct_uri_transformed_partitionless_and_suffixless_subpath(
        transform_name_w_subpath):
    transform_name_w_subpath['partition'] = ''
    transform_name_w_subpath['suffix'] = ''
    with pytest.raises(session.InvalidURIComponentPart) as IC:
        session.generate_bigip_uri(**transform_name_w_subpath)
    assert str(IC.value) == \
        'When giving the subPath component include partition as well.'


def test_correct_uri_transformed_nameless_and_suffixless(transform_name):
    transform_name['name'] = ''
    transform_name['suffix'] = ''
    uri = session.generate_bigip_uri(**transform_name)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER'


def test_correct_uri_transformed_nameless_and_suffixless_subpath(
        transform_name_w_subpath):
    transform_name_w_subpath['name'] = ''
    transform_name_w_subpath['suffix'] = ''
    uri = session.generate_bigip_uri(**transform_name_w_subpath)
    assert uri == 'https://0.0.0.0/mgmt/tm/root/RESTiface/~BIGCUSTOMER~sp'


def test_correct_uri_construction_mgmt_shared(uparts_shared):
    uparts_shared['name'] = ''
    uparts_shared['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts_shared)
    assert uri == 'https://0.0.0.0/mgmt/shared/root/RESTiface/~BIGCUSTOMER'


def test_correct_uri_construction_mgmt_cm(uparts_cm):
    uparts_cm['name'] = ''
    uparts_cm['suffix'] = ''
    uri = session.generate_bigip_uri(**uparts_cm)
    assert uri == 'https://0.0.0.0/mgmt/cm/root/RESTiface/~BIGCUSTOMER'


# Test exception handling
def test_wrapped_delete_success(iCRS, uparts):
    iCRS.delete(uparts['base_uri'], partition='AFN', name='AIN',
                uri_as_parts=True)
    assert iCRS.session.delete.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN')


def test_wrapped_delete_207_fail(iCRS, uparts):
    iCRS.session.delete.return_value.status_code = 207
    with pytest.raises(session.iControlUnexpectedHTTPError) as CHE:
        iCRS.delete(uparts['base_uri'], partition='A_FOLDER_NAME',
                    name='AN_INSTANCE_NAME')
    assert str(CHE.value).startswith('207 Unexpected Error: ')


def test_wrapped_get_success(iCRS, uparts):
    iCRS.get(uparts['base_uri'], partition='AFN', name='AIN',
             uri_as_parts=True)
    assert iCRS.session.get.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN')


def test_wrapped_get_success_with_suffix(iCRS, uparts):
    iCRS.get(uparts['base_uri'], partition='AFN', name='AIN',
             suffix=uparts['suffix'],
             uri_as_parts=True)
    assert iCRS.session.get.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN/members/m1')


def test_wrapped_get_207_fail(iCRS, uparts):
    iCRS.session.get.return_value.status_code = 207
    with pytest.raises(session.iControlUnexpectedHTTPError) as CHE:
        iCRS.get(uparts['base_uri'], partition='A_FOLDER_NAME',
                 name='AN_INSTANCE_NAME')
    assert str(CHE.value).startswith('207 Unexpected Error: ')


def test_wrapped_patch_success(iCRS, uparts):
    iCRS.patch(uparts['base_uri'], partition='AFN', name='AIN',
               uri_as_parts=True)
    assert iCRS.session.patch.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN', data=None)


def test_wrapped_patch_207_fail(iCRS, uparts):
    iCRS.session.patch.return_value.status_code = 207
    with pytest.raises(session.iControlUnexpectedHTTPError) as CHE:
        iCRS.patch(uparts['base_uri'], partition='A_FOLDER_NAME',
                   name='AN_INSTANCE_NAME')
    assert str(CHE.value).startswith('207 Unexpected Error: ')


def test_wrapped_put_207_fail(iCRS, uparts):
    iCRS.session.put.return_value.status_code = 207
    with pytest.raises(session.iControlUnexpectedHTTPError) as CHE:
        iCRS.put(uparts['base_uri'], partition='A_FOLDER_NAME',
                 name='AN_INSTANCE_NAME')
    assert str(CHE.value).startswith('207 Unexpected Error: ')


def test_wrapped_post_207_fail(iCRS, uparts):
    iCRS.session.post.return_value.status_code = 207
    with pytest.raises(session.iControlUnexpectedHTTPError) as CHE:
        iCRS.post(uparts['base_uri'], partition='A_FOLDER_NAME',
                  name='AN_INSTANCE_NAME')
    assert str(CHE.value).startswith('207 Unexpected Error: ')


def test_wrapped_post_success(iCRS, uparts):
    iCRS.post(uparts['base_uri'], partition='AFN', name='AIN',
              uri_as_parts=True)
    assert iCRS.session.post.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN', data=None,
                  json=None)


def test_wrapped_post_success_with_data(iCRS, uparts):
    iCRS.post(uparts['base_uri'], partition='AFN', name='AIN', data={'a': 1},
              uri_as_parts=True)
    assert iCRS.session.post.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN',
                  data={'a': 1}, json=None)


def test_wrapped_post_success_with_json(iCRS, uparts):
    iCRS.post(uparts['base_uri'], partition='AFN', name='AIN', json='{"a": 1}',
              uri_as_parts=True)
    assert iCRS.session.post.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN', data=None,
                  json='{"a": 1}')


def test_wrapped_post_success_with_json_and_data(iCRS, uparts):
    iCRS.post(uparts['base_uri'], partition='AFN', name='AIN', data={'a': 1},
              json='{"a": 1}', uri_as_parts=True)
    assert iCRS.session.post.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN',
                  data={'a': 1}, json='{"a": 1}')


def test_wrapped_put_success(iCRS, uparts):
    iCRS.put(uparts['base_uri'], partition='AFN', name='AIN',
             uri_as_parts=True)
    assert iCRS.session.put.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN', data=None)


def test_wrapped_put_success_with_data(iCRS, uparts):
    iCRS.put(uparts['base_uri'], partition='AFN', name='AIN', data={'b': 2},
             uri_as_parts=True)
    assert iCRS.session.put.call_args ==\
        mock.call('https://0.0.0.0/mgmt/tm/root/RESTiface/~AFN~AIN',
                  data={'b': 2})


def test___init__with_newer_requests_pkg():
    with mock.patch('icontrol.session.requests') as mock_requests:
        mock_requests.__version__ = '2.9.9'
        session.iControlRESTSession('test_name', 'test_pw')
        assert mock_requests.packages.urllib3.disable_warnings.called is False


def test___init__with_older_requests_pkg():
    with mock.patch('icontrol.session.requests') as mock_requests:
        mock_requests.__version__ = '2.1.1'
        session.iControlRESTSession('test_name', 'test_pw')
        assert mock_requests.packages.urllib3.disable_warnings.called is True


def test___init__with_2_9_1_requests_pkg():
    with mock.patch('icontrol.session.requests') as mock_requests:
        mock_requests.__version__ = '2.9.1'
        session.iControlRESTSession('test_name', 'test_pw')
        assert mock_requests.packages.urllib3.disable_warnings.called is False


def test___init__user_agent():
    icrs = session.iControlRESTSession('admin', 'admin')
    assert UA in icrs.session.headers['User-Agent']


def test__append_user_agent():
    icrs = session.iControlRESTSession('admin', 'admin')
    icrs.append_user_agent('test-user-agent/1.1.1')
    assert icrs.session.headers['User-Agent'].endswith('test-user-agent/1.1.1')
    assert UA in icrs.session.headers['User-Agent']


def test_append_user_agent_empty_start():
    icrs = session.iControlRESTSession('admin', 'admin')
    icrs.session.headers['User-Agent'] = ''
    icrs.append_user_agent('test-agent')
    assert icrs.session.headers['User-Agent'] == 'test-agent'


def test___init__with_additional_user_agent():
    icrs = session.iControlRESTSession(
        'admin',
        'admin',
        user_agent='test-agent/1.2.3'
    )
    assert icrs.session.headers['User-Agent'].endswith('test-agent/1.2.3')
    assert 'f5-icontrol-rest-python' in icrs.session.headers['User-Agent']
