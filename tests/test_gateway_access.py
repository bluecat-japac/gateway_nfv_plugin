
# Copyright 2021 BlueCat Networks (USA) Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# pylint: disable=missing-docstring
import unittest
import sys  # pylint:disable=import-error
import context
from unittest import mock  # pylint: disable=import-error

sys.modules["requests"] = mock.Mock()


class TestGatewayAccess(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """

    @mock.patch('statistics_collection.gateway.gateway_access.common')
    def test_request_data_not_username_password(self, mock_common):
        """
        :param :
        :return:
        """
        mock_common.get_configuration.return_value = None, None, "aaa", 1
        api = ""
        bam_ip = "192.168.88.54"
        from statistics_collection.gateway.gateway_access import request_data  # pylint:disable=import-error
        actual = request_data(api, bam_ip)
        expected = None
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.gateway.gateway_access.json')
    @mock.patch('statistics_collection.gateway.gateway_access.login')
    @mock.patch('statistics_collection.gateway.gateway_access.common')
    def test_request_data_with_exception(self, mock_common, mock_login, mock_json):
        """
        :param:
        :return:
        """
        mock_common.get_configuration.return_value = "gateway-user", "13246", "aaa", 1
        api = ""
        bam_ip = "192.168.88.54"

        login_session = mock.Mock()
        ts_request = ""
        login_session.get.return_value = ts_request
        mock_login.return_value = login_session
        result = None
        mock_json.loads.return_value = result
        from statistics_collection.gateway.gateway_access import request_data  # pylint:disable=import-error
        actual = request_data(api, bam_ip)
        expected = None
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.gateway.gateway_access.logger')
    @mock.patch('statistics_collection.gateway.gateway_access.common')
    def test_request(self, mock_common, mock_logger):
        """
        :param:
        :return:
        """
        mock_common.get_configuration.side_effect = Exception("exception")
        api = ""
        bam_ip = "192.168.88.54"
        mock_logger.error.side_effect = Exception("exception")
        from statistics_collection.gateway.gateway_access import request_data  # pylint:disable=import-error
        with self.assertRaises(Exception):
            request_data(api, bam_ip)

    def test_login_not_username_and_password(self):
        """
        :param:
        :return:
        """
        username = None
        password = ""
        bam_url = ""
        gateway_url = ""
        from statistics_collection.gateway.gateway_access import login  # pylint:disable=import-error
        expect = login(username, password, gateway_url, bam_url)
        actual = None
        self.assertEqual(actual, expect)

    @mock.patch('statistics_collection.gateway.gateway_access.requests')
    def test_login_not_200(self, mock_requests):
        """
        :param:
        :return:
        """
        username = "gateway-user"
        password = "132456"
        bam_url = ""
        gateway_url = ""
        scheduler_session = mock.Mock()
        mock_requests.Session.return_value = scheduler_session
        login_request = mock.MagicMock()
        login_request.status_code = 500
        from statistics_collection.gateway.gateway_access import login  # pylint:disable=import-error
        expect = login(username, password, gateway_url, bam_url)
        actual = None
        self.assertEqual(actual, expect)

    def test_logout(self):
        """
        :param:
        :return:
        """
        login_session = mock.MagicMock()
        gateway_url = "http://192.168.88.54/Services/REST/v1/login?"
        from statistics_collection.gateway.gateway_access import logout  # pylint:disable=import-error
        logout(login_session, gateway_url)


if __name__ == "__main__":
    # pylint:disable=import-error
    unittest.main()
