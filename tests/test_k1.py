
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
import sys # pylint:disable=import-error
import context
from unittest import mock  # pylint: disable=import-error

sys.modules["requests"] = mock.Mock()
sys.modules["cryptography.fernet"] = mock.Mock()


class TestK1(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """
    def test_payload_false(self):
        """
        :param :
        :return:
        """
        payload = {
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10}
            ]
        }
        from statistics_collection.k1 import is_kpi_none  # pylint:disable=import-error
        actual = is_kpi_none(payload)
        expected = False
        self.assertEqual(expected, actual)

    def test_payload_true(self):
        """
        :param :
        :return:
        """
        payload = {
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": None}
            ]
        }
        from statistics_collection.k1 import is_kpi_none  # pylint:disable=import-error
        actual = is_kpi_none(payload)
        expected = True
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.k1.ServerType')
    def test_prepare_payload_for_k1_bam(self, mock_server_type):
        """
        :param :
        :return:
        """
        result_statictis = {
            "server_name": "bam54",
            "server_type": "bam",
            "cpu_usage": 10,
            "memory_usage": 10,
        }
        mock_server_type.BAM = result_statictis['server_type']

        from statistics_collection.k1 import prepare_payload_for_k1  # pylint:disable=import-error
        actual = prepare_payload_for_k1(result_statictis)
        expected = {
            "vm_type": "bam",
            "vm_name": "bam54",
            "app_status": "ready",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10}
            ]
        }
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.k1.ServerType')
    def test_prepare_payload_for_k1_bdds(self, mock_server_type):
        """
        :param :
        :return:
        """
        result_statictis = {
            "server_name": "bdds169",
            "server_type": "bdds",
            "cpu_usage": 10,
            "memory_usage": 10,
            "queries": 0,
            "app_status": "success"
        }
        mock_server_type.BDDS = result_statictis['server_type']

        from statistics_collection.k1 import prepare_payload_for_k1  # pylint:disable=import-error
        actual = prepare_payload_for_k1(result_statictis)
        expected = {
            "vm_type": "bdds",
            "vm_name": "bdds169",
            "app_status": "success",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10},
                {"kpi_name": "dns_queries", "kpi_value": 0}
            ]
        }
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.k1.ServerType')
    def test_prepare_payload_for_k1_vmhost(self, mock_server_type):
        """
        :param :
        :return:
        """
        result_statictis = {
            "server_name": "vmhost_01",
            "server_type": "vmhost",
            "cpu_usage": 10,
            "memory_usage": 10,
        }
        mock_server_type.VM_HOST = result_statictis['server_type']

        from statistics_collection.k1 import prepare_payload_for_k1  # pylint:disable=import-error
        actual = prepare_payload_for_k1(result_statictis)
        expected = {
            "vm_type": "vmhost",
            "vm_name": "vmhost_01",
            "app_status": "ready",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10},
            ]
        }
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.k1.ServerType')
    def test_prepare_payload_for_k1_with_udf(self, mock_server_type):
        """
        :param :
        :return:
        """
        result_statictis = {
            "server_name": "bam54",
            "server_type": "bam",
            "cpu_usage": 10,
            "memory_usage": 10,
            "udf": "nhii:"
        }
        mock_server_type.BAM = result_statictis['server_type']
        from statistics_collection.k1 import prepare_payload_for_k1  # pylint:disable=import-error
        actual = prepare_payload_for_k1(result_statictis)
        expected = {
            "vm_type": "bam",
            "vm_name": "bam54",
            "app_status": "ready",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10}
            ],
            "nhii": ""
        }
        self.assertEqual(expected, actual)

    def test_call_k1_api_not_oject(self):
        """
        :param :
        :return:
        """
        result_object = None
        from statistics_collection.k1 import call_k1_api  # pylint:disable=import-error
        actual = call_k1_api(result_object)
        expected = None
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.k1.read_config_json_file')
    @mock.patch('statistics_collection.k1.prepare_payload_for_k1')
    @mock.patch('statistics_collection.k1.is_kpi_none')
    def test_call_k1_api_kpi_none(self, mock_is_kpi_none, mock_prepare_payload_for_k1,
                                  mock_read_config_json_file):
        """
        :param :
        :return:
        """
        result_object = "nhii"
        payload = {
            "vm_type": "bdds",
            "vm_name": "bdds169",
            "app_status": "ready",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10}
            ]
        }
        mock_prepare_payload_for_k1.return_value = payload  # pylint:disable=import-error
        mock_is_kpi_none.return_value = True
        data_config = {
            "k1_api": {
                "address": "192.168.88.161",
                "port": 5555,
                "uri": "/api/v1.0/srvo/instances/realtime_load"
            }
        }
        mock_read_config_json_file.return_value = data_config
        from statistics_collection.k1 import call_k1_api  # pylint:disable=import-error
        expect = None
        actual = call_k1_api(result_object)
        self.assertEqual(actual, expect)

    @mock.patch('statistics_collection.k1.requests')
    @mock.patch('statistics_collection.k1.read_config_json_file')
    @mock.patch('statistics_collection.k1.prepare_payload_for_k1')
    @mock.patch('statistics_collection.k1.is_kpi_none')
    def test_call_k1_api_kpi(self, mock_is_kpi_none, mock_prepare_payload_for_k1,
                             mock_read_config_json_file, mock_requests):
        """
        :param :
        :return:
        """
        result_object = "nhii"
        payload = {
            "vm_type": "bdds",
            "vm_name": "bdds169",
            "app_status": "ready",
            "kpi_load": [
                {"kpi_name": "cpu_load", "kpi_value": 10},
                {"kpi_name": "mem_load", "kpi_value": 10}
            ]
        }
        mock_prepare_payload_for_k1.return_value = payload
        mock_is_kpi_none.return_value = False
        data_config = {
            "k1_api": {
                "address": "192.168.88.161",
                "port": 5555,
                "uri": "/api/v1.0/srvo/instances/realtime_load"
            }
        }
        mock_read_config_json_file.return_value = data_config
        response = "hii"
        mock_requests.post.return_value = response
        from statistics_collection.k1 import call_k1_api  # pylint:disable=import-error
        with self.assertRaises(Exception):
            call_k1_api(result_object)


if __name__ == "__main__":
    unittest.main()
