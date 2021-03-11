
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
import sys
import context
from unittest import mock  # pylint: disable=import-error

from memcached.server import Bdds  # pylint:disable=import-error

sys.modules["gateway"] = mock.Mock()
sys.modules["snmp.snmp_methods"] = mock.Mock()
sys.modules["k1"] = mock.Mock()
sys.modules["apscheduler"] = mock.Mock()
sys.modules["apscheduler.schedulers"] = mock.Mock()
sys.modules["apscheduler.schedulers.blocking"] = mock.Mock()
sys.modules["apscheduler.executors"] = mock.Mock()
sys.modules["apscheduler.executors.pool"] = mock.Mock()


class TestStatisticCollectionRun(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """

    @mock.patch('statistics_collection.statistic_collection_run.read_config_json_file')
    def test_get_memcached_config(self, mock_read_config_json_file):
        """
        :param:
        :return:
        """
        data_config = {
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211
        }
        mock_read_config_json_file.return_value = data_config
        from statistics_collection.statistic_collection_run import get_memcached_config  # pylint:disable=import-error
        actual = get_memcached_config()
        expect = "192.168.88.170", 11211
        self.assertLessEqual(expect, actual)

    @mock.patch('statistics_collection.statistic_collection_run.gateway_access')
    @mock.patch('statistics_collection.statistic_collection_run.read_config_json_file')
    def test_init_server_cached_list_api(self, mock_read_config_json_file, mock_gateway_access):
        """
        :param:
        :return:
        """
        data_config = {
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211,
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ]
        }
        mock_read_config_json_file.return_value = data_config
        result = "nhii"
        mock_gateway_access.request_data.return_value = result
        from statistics_collection.statistic_collection_run import init_server_cached_list_api  # pylint:disable=import-error
        init_server_cached_list_api()
        mock_read_config_json_file.assert_called_once()

    def test_make_template_statistic_object(self):
        """
        :param:
        :return:
        """
        address = "nhii"
        server_type = "bdds"
        server_name = "bdds169"
        memory_usage = 10
        cpu_usage = 5

        from statistics_collection.statistic_collection_run import make_template_statistic_object  # pylint:disable=import-error
        actual = make_template_statistic_object(address, server_type, server_name, memory_usage, cpu_usage)
        expect = {
            "address": "nhii",
            "server_type": "bdds",
            "server_name": "bdds169",
            "udf": "",
            "memory_usage": 10,
            "cpu_usage": 5
        }
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.statistic_collection_run.ServerType')
    def test_make_template_statistic_object_with_type_bdds(self, mock_server_type):
        """
        :param:
        :return:
        """
        address = "nhii"
        server_type = "bdds"
        server_name = "bdds169"
        memory_usage = 10
        cpu_usage = 5
        queries = 0
        mock_server_type.BDDS = "bdds"
        from statistics_collection.statistic_collection_run import make_template_statistic_object  # pylint:disable=import-error
        actual = make_template_statistic_object(address, server_type, server_name, memory_usage, cpu_usage, queries)
        expect = {
            "address": "nhii",
            "server_type": "bdds",
            'app_status': 'fail',
            "server_name": "bdds169",
            "udf": "",
            "memory_usage": 10,
            "cpu_usage": 5,
            "queries": 0
        }
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.statistic_collection_run.make_template_statistic_object')
    @mock.patch('statistics_collection.statistic_collection_run.server_bam_statistic')
    @mock.patch('statistics_collection.statistic_collection_run.ServerType')
    def test_get_server_statistic_with_server_type_bam(self, mock_server_type, mock_server_bam_statistic,
                                                       mock_make_template_statistic_object):
        """
        :param:
        :return:
        """

        server = {
            "address": "nhii",
            "server_type": "bam",
            "server_name": "bam54",
            "snmp_config_data": "",

        }
        mock_server_type.BAM = "bam"
        memory_usage, cpu_usage = 10, 5
        mock_server_bam_statistic.return_value = memory_usage, cpu_usage
        result_object = {
            "address": "nhii",
            "server_type": "bam",
            "server_name": "bam54",
            "udf": "",
            "memory_usage": 10,
            "cpu_usage": 5,
        }
        mock_make_template_statistic_object.return_value = result_object
        from statistics_collection.statistic_collection_run import get_server_statistic  # pylint:disable=import-error
        actual = get_server_statistic(server)
        expect = result_object
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.statistic_collection_run.logger')
    @mock.patch('statistics_collection.statistic_collection_run.make_template_statistic_object')
    @mock.patch('statistics_collection.statistic_collection_run.server_bdds_statistic')
    @mock.patch('statistics_collection.statistic_collection_run.ServerType')
    def test_get_server_statistic_with_server_type_bdds(self, mock_server_type, mock_server_bdds_statistic,
                                                        mock_make_template_statistic_object, mock_logger):
        """
        :param:
        :return:
        """
        server = {
            "address": "nhii",
            "server_type": "bdds",
            "server_name": "bdds169",
            "snmp_config_data": "",
            "udf": "nhii",
            "queries": 0
        }
        mock_server_type.BDDS = "bdds"
        memory_usage, cpu_usage, queries = 10, 5, 0
        mock_server_bdds_statistic.return_value = memory_usage, cpu_usage
        result_object = {
            "address": "nhii",
            "server_type": "bdds",
            "server_name": "bdds169",
            "udf": "",
            "memory_usage": 10,
            "cpu_usage": 5,
            "queries": 0
        }
        mock_make_template_statistic_object.return_value = result_object
        mock_logger.error.side_effect = Exception("exception")
        from statistics_collection.statistic_collection_run import get_server_statistic  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_server_statistic(server)

    def test_get_snmp_server_config_name(self):
        """
        :param:
        :return:
        """
        config = "aaa"
        name = 1
        from statistics_collection.statistic_collection_run import get_snmp_server_config_name  # pylint:disable=import-error
        actual = get_snmp_server_config_name(config, name)
        expect = 1
        self.assertEqual(expect, actual)

    @mock.patch('statistics_collection.statistic_collection_run.collect_statistics')
    def test_scheduler_get_statistic_job(self, mock_collect_statistics):
        """
        :param:
        :return:
        """
        statistics = {'address': '192.168.88.54', 'server_type': 'BAM', 'server_name': '', 'udf': '',
                      'memory_usage': 96, 'cpu_usage': 2.5}
        mock_collect_statistics.return_value = statistics
        from statistics_collection.statistic_collection_run import scheduler_get_statistic_job  # pylint:disable=import-error
        scheduler_get_statistic_job()

    @mock.patch('statistics_collection.statistic_collection_run.BlockingScheduler')
    @mock.patch('statistics_collection.statistic_collection_run.read_config_json_file')
    @mock.patch('statistics_collection.statistic_collection_run.MemcachedNFV')
    @mock.patch('statistics_collection.statistic_collection_run.get_memcached_config')
    def test_main(self, mock_get_memcached_config, mock_memcached_nfv, mock_read_config_json_file,
                  mock_blocking_scheduler):
        """
        :param:
        :return:
        """
        memcached_host, memcached_port = "192.168.88.170", 11211
        mock_get_memcached_config.return_value = memcached_host, memcached_port
        mem_nfv = mock.MagicMock()
        mock_memcached_nfv.return_value = mem_nfv
        data_config = {
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211,
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "interval": 1
        }
        scheduler = mock.Mock()
        mock_blocking_scheduler.return_value = scheduler
        mock_read_config_json_file.return_value = data_config
        from statistics_collection.statistic_collection_run import main  # pylint:disable=import-error
        main()

    @mock.patch('statistics_collection.statistic_collection_run.get_snmp_server_config_name')
    @mock.patch('statistics_collection.statistic_collection_run.read_config_json_file')
    @mock.patch('statistics_collection.statistic_collection_run.MemcachedNFV')
    @mock.patch('statistics_collection.statistic_collection_run.get_memcached_config')
    def test_collect_statistics_with_none(self, mock_get_memcached_config, mock_memcached_nfv, mock_read_config_json_file,
                                mock_get_snmp_server_config_name):
        """
        :param:
        :return:
        """
        memcached_host, memcached_port = "192.168.88.170", 11211
        mock_get_memcached_config.return_value = memcached_host, memcached_port
        mem_nfv = mock.MagicMock()
        mock_memcached_nfv.return_value = mem_nfv
        list_bdds, list_bam, list_vmhosts = ([], [], [])
        mem_nfv.get_list_servers.return_value = list_bdds, list_bam, list_vmhosts
        snmp_config = {
            "bbds_01": {
                "port": 161,
                "snmp_version": "v2c",
                "snmp_community": "bcnCommunityV2C",
                "user_name": "gateway-user",
                "authen_protocol": "MD5",
                "authen_password": "MTIzNDU2Nzh4QFg=",
                "priv_protocol": "AES",
                "priv_password": "MTIzNDU2Nzh4QFg="
            }
        }
        mock_read_config_json_file.return_value = snmp_config
        bdds_config_name = "DemoConfig"
        mock_get_snmp_server_config_name.rerurn_value = bdds_config_name
        from statistics_collection.statistic_collection_run import collect_statistics  # pylint:disable=import-error
        actual = collect_statistics()
        expect = []
        self.assertEqual(actual, expect)

    @mock.patch('statistics_collection.statistic_collection_run.get_snmp_server_config_name')
    @mock.patch('statistics_collection.statistic_collection_run.read_config_json_file')
    @mock.patch('statistics_collection.statistic_collection_run.MemcachedNFV')
    @mock.patch('statistics_collection.statistic_collection_run.get_memcached_config')
    def test_collect_statistics(self, mock_get_memcached_config, mock_memcached_nfv, mock_read_config_json_file,
                                          mock_get_snmp_server_config_name):
        """
        :param:
        :return:
        """
        memcached_host, memcached_port = "192.168.88.170", 11211
        mock_get_memcached_config.return_value = memcached_host, memcached_port
        mem_nfv = mock.MagicMock()
        mock_memcached_nfv.return_value = mem_nfv

        id = 1111  # pylint:disable=invalid-name
        name = "BDDS1"
        udf = "aaa"
        ipv4_address = "192.1.1.1"
        bam_ip = "192.2.2.2"
        bdds = Bdds(id, name, udf, ipv4_address, bam_ip)
        bdds.name = mock.Mock()

        name = "BAM1"
        bam = mock.MagicMock()
        bam.name = mock.Mock()
        bam.ipv4_address = mock.Mock()
        
        name = "VM_HOST"
        vm = mock.MagicMock()
        vm.name = mock.Mock()
        vm.ipv4_address = mock.Mock()
        
        list_bdds, list_bam, list_vmhosts = ([bdds], [bam], [vm])
        mem_nfv.get_list_servers.return_value = list_bdds, list_bam, list_vmhosts
        snmp_config = {
            "common":{
                "port":161,
                "snmp_version": "v2c",
                "snmp_community": "bcnCommunityV2C",
                "user_name":"gateway-user",
                "authen_protocol": "MD5",
                "authen_password": "MTIzNDU2Nzh4QFg=",
                "priv_protocol":"AES",
                "priv_password": "MTIzNDU2Nzh4QFg="
            },
            "bbds_01": {
                "port": 161,
                "snmp_version": "v2c",
                "snmp_community": "bcnCommunityV2C",
                "user_name": "gateway-user",
                "authen_protocol": "MD5",
                "authen_password": "MTIzNDU2Nzh4QFg=",
                "priv_protocol": "AES",
                "priv_password": "MTIzNDU2Nzh4QFg="
            }
        }
        mock_read_config_json_file.return_value = snmp_config
        bdds_config_name = "DemoConfig"
        mock_get_snmp_server_config_name.rerurn_value = bdds_config_name
        from statistics_collection.statistic_collection_run import collect_statistics  # pylint:disable=import-error
        actual = collect_statistics()
        expect = []
        self.assertEqual(actual, expect)

    