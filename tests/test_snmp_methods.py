
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

sys.modules["client"] = mock.Mock()
sys.modules["pysnmp"] = mock.Mock()
sys.modules["pysnmp.hlapi"] = mock.Mock()


class TestSNMPMethods(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """

    def test_empty_to_none(self):
        """
        :param:
        :return:
        """
        value = "nhii"
        from statistics_collection.snmp.snmp_methods import empty_to_none  # pylint:disable=import-error
        actual = empty_to_none(value)
        expected = "nhii"
        self.assertEqual(expected, actual)

    def test_empty_to_none_with_value_none(self):
        """
        :param:
        :return:
        """
        value = ""
        from statistics_collection.snmp.snmp_methods import empty_to_none  # pylint:disable=import-error
        actual = empty_to_none(value)
        expected = None
        self.assertEqual(expected, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.getCmd')
    def test_get_snmp_without_auth(self, mock_get_cmd):
        """
        :param:
        :return:
        """
        template_oids = ""
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        port = "80"
        snmp_community = ""
        snmp_version = "v1"
        timeout = 5
        retries = ""
        mock_get_cmd.return_value = iter(['a', 'b', 'c'])
        from statistics_collection.snmp.snmp_methods import get_snmp_without_auth  # pylint:disable=import-error
        actual = get_snmp_without_auth(template_oids, ip, port, snmp_community, snmp_version, timeout, retries)
        expected = 'a'
        self.assertEqual(expected, actual)
        mock_get_cmd.assert_called_once()

    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_without_auth')
    @mock.patch('statistics_collection.snmp.snmp_methods.map')
    def test_get_snmp_multiple_oid_with_keyerror(self, mock_map, mock_get_snmp_without_auth):
        """
        :param:
        :return:
        """
        oids = "1.1.1.1"
        ip = "0.0.0.0"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "123",
            "port": 1111,
            "snmp_community": "nhii"
        }
        template_oids = "11.11.11.11"
        mock_map.return_value = template_oids
        errorIndication, errorStatus, errorIndex, varBinds = 'a', 'b', 'c', 'd'  # pylint:disable=invalid-name
        mock_get_snmp_without_auth.return_value = errorIndication, errorStatus, errorIndex, varBinds  # pylint:disable=invalid-name
        from statistics_collection.snmp.snmp_methods import get_snmp_multiple_oid  # pylint:disable=import-error
        with self.assertRaises(KeyError):
            get_snmp_multiple_oid(oids, ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_without_auth')
    @mock.patch('statistics_collection.snmp.snmp_methods.map')
    def test_get_snmp_multiple_oid_exception_error_indication(self, mock_map, mock_get_snmp_without_auth):
        """
        :param:
        :return:
        """
        oids = "1.1.1.1"
        ip = "0.0.0.0"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "port": 1111,
            "snmp_community": "nhii"
        }
        template_oids = "11.11.11.11"
        mock_map.return_value = template_oids
        errorIndication, errorStatus, errorIndex, varBinds = 'a', '', 'c', 'd'  # pylint:disable=invalid-name
        mock_get_snmp_without_auth.return_value = errorIndication, errorStatus, errorIndex, varBinds  # pylint:disable=invalid-name
        from statistics_collection.snmp.snmp_methods import get_snmp_multiple_oid  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_snmp_multiple_oid(oids, ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_without_auth')
    @mock.patch('statistics_collection.snmp.snmp_methods.map')
    def test_get_snmp_multiple_oid_exception_error_status(self, mock_map, mock_get_snmp_without_auth):
        """
        :param:
        :return:
        """
        oids = "1.1.1.1"
        ip = "0.0.0.0"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "port": 1111,
            "snmp_community": "nhii"
        }
        template_oids = "11.11.11.11"
        mock_map.return_value = template_oids
        errorIndication, errorStatus, errorIndex, varBinds = '', 'b', 'c', 'd'  # pylint:disable=invalid-name
        mock_get_snmp_without_auth.return_value = errorIndication, errorStatus, errorIndex, varBinds  # pylint:disable=invalid-name
        from statistics_collection.snmp.snmp_methods import get_snmp_multiple_oid  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_snmp_multiple_oid(oids, ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_without_auth')
    @mock.patch('statistics_collection.snmp.snmp_methods.map')
    def test_get_snmp_multiple_oid(self, mock_map, mock_get_snmp_without_auth):
        """
        :param:
        :return:
        """
        oids = "1.1.1.1"
        ip = "0.0.0.0"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "port": 1111,
            "snmp_community": "nhii"
        }
        template_oids = "11.11.11.11"
        mock_map.return_value = template_oids
        errorIndication, errorStatus, errorIndex, varBinds = '', '', 'c', 'd'  # pylint:disable=invalid-name
        mock_get_snmp_without_auth.return_value = errorIndication, errorStatus, errorIndex, varBinds
        from statistics_collection.snmp.snmp_methods import get_snmp_multiple_oid  # pylint:disable=import-error
        actual = get_snmp_multiple_oid(oids, ip, snmp_config_data)
        expect = 'd'
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_without_auth')
    @mock.patch('statistics_collection.snmp.snmp_methods.map')
    def test_get_snmp_multiple_oid_version_v3(self, mock_map, mock_get_snmp_without_auth):
        """
        :param:
        :return:
        """
        oids = "1.1.1.1"
        ip = "0.0.0.0"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v3",
            "port": 1111,
            "user_name": "root",
            "authen_protocol": "AES",
            "authen_password": "MTIzNDU2Nzh4QFg=",
            "priv_protocol": "",
            "priv_password": "MTIzNDU2Nzh4QFg="
        }
        template_oids = "11.11.11.11"
        mock_map.return_value = template_oids
        errorIndication, errorStatus, errorIndex, varBinds = '', '', 'c', 'd'  # pylint:disable=invalid-name
        mock_get_snmp_without_auth.return_value = errorIndication, errorStatus, errorIndex, varBinds
        from statistics_collection.snmp.snmp_methods import get_snmp_multiple_oid  # pylint:disable=import-error
        with self.assertRaises(KeyError):
            get_snmp_multiple_oid(oids, ip, snmp_config_data)

    def test_get_memory_usage_exception(self):
        """
        :param:
        :return:
        """

        var_binds = None
        from statistics_collection.snmp.snmp_methods import get_memory_usage  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = get_memory_usage(var_binds)
            expect = {None, None}
            self.assertEqual(expect, actual)

    def test_get_memory_usage(self):
        """
        :param:
        :return:
        """
        var_binds = [('1.1.1.1', 90), ('1.2.3.4', 80)]
        from statistics_collection.snmp.snmp_methods import get_memory_usage  # pylint:disable=import-error
        actual = get_memory_usage(var_binds)
        expect = 11.11111111111111
        self.assertEqual(expect, actual)

    def test_server_number_queries_exception(self):
        """
        :param:
        :return:
        """
        var_binds = "v111111111111111111"
        from statistics_collection.snmp.snmp_methods import server_number_queries  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = server_number_queries(var_binds)
            expect = {None}
            self.assertEqual(expect, actual)

    def test_server_number_queries(self):
        """
        :param:
        :return:
        """
        var_binds = [('1.1.1.1', 90), ('1.2.3.4', 80), ('1.2.3.5', 80), ('1.2.3.6', 80),
                     ('1.2.3.7', 80), ('1.2.3.8', 80), ('1.2.3.9', 80)]
        from statistics_collection.snmp.snmp_methods import server_number_queries  # pylint:disable=import-error
        actual = server_number_queries(var_binds)
        expect = 400
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.bulkCmd')
    def test_get_bulk_snmp(self, mock_bulk_cmd):
        """
        :param:
        :return:
        """
        template_oid = "11.11.11.11"
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "port": 1111,
            "snmp_community": "nhii"
        }
        snmp_iter = "test"
        mock_bulk_cmd.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_bulk_snmp  # pylint:disable=import-error
        actual = get_bulk_snmp(template_oid, ip, snmp_config_data)
        expect = "test"
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.bulkCmd')
    def test_get_bulk_snmp_with_version_keyerror(self, mock_bulk_cmd):
        """
        :param:
        :return:
        """
        template_oid = "11.11.11.11"
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v111",
            "port": 1111,
            "snmp_community": "nhii"
        }
        snmp_iter = "test"
        mock_bulk_cmd.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_bulk_snmp  # pylint:disable=import-error
        with self.assertRaises(KeyError):
            actual = get_bulk_snmp(template_oid, ip, snmp_config_data)
            expect = "test"
            self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.bulkCmd')
    def test_get_bulk_snmp_with_exception(self, mock_bulk_cmd):
        """
        :param:
        :return:
        """
        template_oid = "11.11.11.11"
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "snmp_community": "nhii"
        }
        snmp_iter = "test"
        mock_bulk_cmd.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_bulk_snmp  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = get_bulk_snmp(template_oid, ip, snmp_config_data)
            expect = "test"
            self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.bulkCmd')
    def test_get_bulk_snmp_with_version_v3(self, mock_bulk_cmd):
        """
        :param:
        :return:
        """
        template_oid = "11.11.11.11"
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v3",
            "snmp_community": "nhii",
            "port": 1111,
            "user_name": "root",
            "authen_protocol": "AES",
            "authen_password": "MTIzNDU2Nzh4QFg=",
            "priv_protocol": "",
            "priv_password": "MTIzNDU2Nzh4QFg="
        }
        snmp_iter = "test"
        mock_bulk_cmd.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_bulk_snmp  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = get_bulk_snmp(template_oid, ip, snmp_config_data)
            expect = "test"
            self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_bulk_snmp')
    def test_get_cpu_process(self, mock_get_bulk_snmp):
        """
        :param:
        :return:
        """
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "snmp_community": "nhii"
        }
        snmp_iter = [(None, None, 1, [('1.1.1.1', 90), ('1.2.3.4', 80)]),
                     ('', "", 1, [('1.1.1.1', 90), ('1.2.3.4', 80)])]
        mock_get_bulk_snmp.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_cpu_process  # pylint:disable=import-error
        actual = get_cpu_process(ip, snmp_config_data)
        expect = 85
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_bulk_snmp')
    def test_get_cpu_process_with_error_indication(self, mock_get_bulk_snmp):
        """
        :param:
        :return:
        """
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "snmp_community": "nhii"
        }
        snmp_iter = [(None, None, 1, [('1.1.1.1', 90), ('1.2.3.4', 80)]),
                     ('a', '', 1, [('1.1.1.1', 90), ('1.2.3.4', 80)])]
        mock_get_bulk_snmp.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_cpu_process  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_cpu_process(ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_bulk_snmp')
    def test_get_cpu_process_with_error_status(self, mock_get_bulk_snmp):
        """
        :param:
        :return:
        """
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "snmp_community": "nhii"
        }
        snmp_iter = [(None, None, 1, [('1.1.1.1', 90), ('1.2.3.4', 80)]),
                     ('', "a", 1, [('1.1.1.1', 90), ('1.2.3.4', 80)])]
        mock_get_bulk_snmp.return_value = snmp_iter
        from statistics_collection.snmp.snmp_methods import get_cpu_process  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_cpu_process(ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_cpu_process')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_memory_usage')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_multiple_oid')
    def test_server_bam_statistic(self, mock_get_snmp_multiple_oid, mock_get_memory_usage, mock_get_cpu_process):
        """
        :param:
        :return:
        """
        ip = "1.1.1.1"  # pylint:disable=invalid-name
        snmp_config_data = {
            "snmp_version": "v1",
            "snmp_community": "nhii"
        }
        var_binds = [('1.1.1.1', 90), ('1.2.3.4', 80)]
        mock_get_snmp_multiple_oid.return_value = var_binds
        server_memory_usage = 5
        mock_get_memory_usage.return_value = server_memory_usage
        server_cpu_usage = 5
        mock_get_cpu_process.return_value = server_cpu_usage
        from statistics_collection.snmp.snmp_methods import server_bam_statistic  # pylint:disable=import-error
        actual = server_bam_statistic(ip, snmp_config_data)
        expect = 5, 5
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_cpu_process')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_memory_usage')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_multiple_oid')
    def test_server_bam_statistic_exception(self, mock_get_snmp_multiple_oid, mock_get_memory_usage,
                                            mock_get_cpu_process):
        """
        :param:
        :return:
        """
        ip = ""  # pylint:disable=invalid-name
        snmp_config_data = None
        mock_get_snmp_multiple_oid.side_effect = Exception("exeption")
        mock_get_memory_usage.side_effect = Exception("exeption")
        mock_get_cpu_process.side_effect = Exception("exeption")
        from statistics_collection.snmp.snmp_methods import server_bam_statistic  # pylint:disable=import-error
        with self.assertRaises(Exception):
            server_bam_statistic(ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_cpu_process')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_memory_usage')
    @mock.patch('statistics_collection.snmp.snmp_methods.server_number_queries')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_multiple_oid')
    def test_server_bdds_statistic_exception(self, mock_get_snmp_multiple_oid, mock_server_number_queries,
                                             mock_get_memory_usage, mock_get_cpu_process):
        """
        :param:
        :return:
        """
        ip = ""  # pylint:disable=invalid-name
        snmp_config_data = None
        mock_get_snmp_multiple_oid.side_effect = Exception("exeption")
        mock_server_number_queries.side_effect = Exception("exception")
        mock_get_memory_usage.side_effect = Exception("exeption")
        mock_get_cpu_process.side_effect = Exception("exeption")
        from statistics_collection.snmp.snmp_methods import server_bdds_statistic  # pylint:disable=import-error
        with self.assertRaises(Exception):
            server_bdds_statistic(ip, snmp_config_data)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_cpu_process')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_memory_usage')
    @mock.patch('statistics_collection.snmp.snmp_methods.server_number_queries')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_multiple_oid')
    def test_server_bdds_statistic_state_running(self, mock_get_snmp_multiple_oid, mock_server_number_queries,
                                   mock_get_memory_usage, mock_get_cpu_process):
        """
        :param:
        :return:
        """
        ip = ""  # pylint:disable=invalid-name
        snmp_config_data = None
        var_binds = [('1.2.3.{}'.format(str(i)), 80 + i) for i in range(7)]
        # Mock index = 7 for dns operate state
        var_binds.append(('1.2.3.9', 1))
        mock_get_snmp_multiple_oid.return_value = var_binds
        queries = 5
        mock_server_number_queries.return_value = queries
        server_memory_usage = 5
        mock_get_memory_usage.return_value = server_memory_usage
        server_cpu_usage = 5
        mock_get_cpu_process.return_value = server_cpu_usage
        from statistics_collection.snmp.snmp_methods import server_bdds_statistic  # pylint:disable=import-error
        actual = server_bdds_statistic(ip, snmp_config_data)
        expect = 5, 5, 1, 5
        self.assertEqual(actual, expect)

    @mock.patch('statistics_collection.snmp.snmp_methods.get_cpu_process')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_memory_usage')
    @mock.patch('statistics_collection.snmp.snmp_methods.server_number_queries')
    @mock.patch('statistics_collection.snmp.snmp_methods.get_snmp_multiple_oid')
    def test_server_bdds_statistic_state_not_running(self, mock_get_snmp_multiple_oid, mock_server_number_queries,
                                   mock_get_memory_usage, mock_get_cpu_process):
        """
        :param:
        :return:
        """
        ip = ""  # pylint:disable=invalid-name
        snmp_config_data = None
        var_binds = [('1.2.3.{}'.format(str(i)), 80 + i) for i in range(7)]
        # Mock index = 7 for dns operate state
        var_binds.append(('1.2.3.9', 2))
        mock_get_snmp_multiple_oid.return_value = var_binds
        queries = 5
        mock_server_number_queries.return_value = queries
        server_memory_usage = 5
        mock_get_memory_usage.return_value = server_memory_usage
        server_cpu_usage = 5
        mock_get_cpu_process.return_value = server_cpu_usage
        from statistics_collection.snmp.snmp_methods import server_bdds_statistic  # pylint:disable=import-error
        actual = server_bdds_statistic(ip, snmp_config_data)
        expect = 5, 5, 2, 0
        self.assertEqual(actual, expect)


if __name__ == "__main__":
    # pylint:disable=import-error
    unittest.main()