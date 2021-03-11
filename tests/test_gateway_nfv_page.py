
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

# pylint:disable = missing-docstring
import unittest
import sys
from unittest import mock   # pylint:disable=import-error, ungrouped-imports

sys.modules["pymemcache"] = mock.Mock()
sys.modules["cryptography"] = mock.Mock()
sys.modules["pymemcache.client"] = mock.Mock()
sys.modules["cryptography.fernet"] = mock.Mock()

import GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page as nfv_plugin_page  # pylint:disable=import-error,wrong-import-position

NFV_CONFIG = {
    "bam": [
        {
            "ip": "192.168.88.54",
            "name": "DNS_999_BAM_0001"
        }
    ],
    "server_deployment_password": "Ymx1ZWNhdA==",
    "workflow_name": "gateway_nfv_plugin",
    "bam_config_name": "DemoConfig",
    "dns_view_names": [
        "default",
        "testView",
        "secondView",
        "srvview"
    ],
    "udfs_for_server": [
        {
            "name": "can_scale_in",
            "default_value": "true"
        }
    ],
    "server_ssh_username": "root",
    "server_ssh_password": "ZDhlOGZjYQ==",
    "server_cap_profile": "DNS_DHCP_SERVER_60",
    "server_deploy_role": "RECURSION",
    "server_dns_raw_option": [
        "empty-zones-enable no;"
    ],
    "user_name": "gateway-user",
    "gateway_address": "192.168.88.161:5000",
    "secret_file": ".secret",
    "secretkey_file": ".secretkey",
    "interval": 2,
    "sync_interval": 1,
    "memcached_host": "192.168.88.170",
    "memcached_port": 11211,
    "k1_api": {
        "address": "192.168.88.161",
        "port": 5555,
        "uri": "/api/v1.0/srvo/instances/realtime_load"
    },
    "vm_host_ip":  "192.168.88.252",
    "vm_host_name": "VMHOST_0005",
    "log_level": "DEBUG"
}

VM_CONFIG = [
    "bam_num=1", "OM_0002=192.168.94.251",
    "SERVER_0001=192.168.94.251", "SERVER_V6_0001=fdac:1400:1::001F",
    "SERVER_NET_MASK=24", "SERVER_V6_PREFIX=64"]


class TestGatewayNFVPage(unittest.TestCase):
    # pylint: disable=missing-docstring
    @mock.patch('common.common.read_config_json_file')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_init_server_cached_list_successful(self, mock_jsonify, mock_g, mock_read_config_file):
        # pylint: disable=missing-docstring
        mock_read_config_file.return_value = NFV_CONFIG
        jsonify = {"Status": "SUCCESS"}
        mock_jsonify.return_value = jsonify

        actual = nfv_plugin_page.init_server_cached_list()
        expected = {"Status": "SUCCESS"}
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.abort')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    def test_nfv_api_scale_out_successful(self, mock_nfv_management, mock_g, mock_request, mock_abort):
        # pylint: disable=missing-docstring
        mock_request.method = "POST"
        mock_nfv_management.scale_out.return_value = (
            {"status": "Successful", "message": "Scale out successfully", "error": ""}, 200)

        actual = nfv_plugin_page.nfv_api_scale_out()
        expected = ({"status": "Successful",
                     "message": "Scale out successfully", "error": ""}, 200)
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.abort')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_nfv_api_scale_out_request_json_none(self, mock_jsonify, mock_g, mock_request, mock_abort):
        # pylint: disable=missing-docstring
        mock_request.json = None
        jsonify = []
        mock_jsonify.return_value = jsonify

        actual = nfv_plugin_page.nfv_api_scale_out()
        expected = ([], 200)
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.abort')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    def test_nfv_api_scale_in_successful(self, mock_nfv_management, mock_g, mock_request, mock_abort):
        # pylint: disable=missing-docstring
        mock_request.method = "POST"
        mock_nfv_management.scale_in.return_value = (
            {"status": "Successful", "message": "Scale in successfully", "error": ""}, 200)

        actual = nfv_plugin_page.nfv_api_scale_in()
        expected = ({"status": "Successful",
                     "message": "Scale in successfully", "error": ""}, 200)
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.abort')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_nfv_api_scale_in_request_json_none(self, mock_jsonify, mock_g, mock_request, mock_abort):
        # pylint: disable=missing-docstring
        mock_request.json = None
        jsonify = []
        mock_jsonify.return_value = jsonify

        actual = nfv_plugin_page.nfv_api_scale_in()
        expected = ([], 200)
        self.assertEqual(expected, actual)

    @mock.patch('common.common.read_text_file')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.get_metadata')
    def test_get_vm_config_data(self, mock_get_metadata, mock_read_text_file):
        # pylint: disable=missing-docstring
        mock_read_text_file.return_value = NFV_CONFIG
        vm_name = "VMHOST_0001"
        metadata = "can_scale_in=true"
        mock_get_metadata.return_value = metadata

        actual = nfv_plugin_page.get_vm_config_data(vm_name)
        expected = {'metadata': 'can_scale_in=true',
                    'mgnt_server_ip': '192.168.94.251',
                    'server_name': 'VMHOST_0001',
                    'service_server_ipv4': '192.168.94.251',
                    'service_server_ipv6': 'fdac:1400:1::001F',
                    'service_server_netmask': 24,
                    'service_server_v6_prefix': '64'}
        self.assertEqual(expected, actual)

    @mock.patch('common.common.read_config_json_file')
    def test_get_metadata(self, mock_read_config_file):
        # pylint: disable=missing-docstring
        mock_read_config_file.return_value = NFV_CONFIG
        
        actual = nfv_plugin_page.get_metadata()
        expected = "can_scale_in=true"
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.read_config_json_file')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_init_server_cached_list_with_exception(self, mock_jsonify, mock_request, mock_read_config_json_file,
                                                    mock_gateway_nfv_management, mock_g):
        # pylint: disable=missing-docstring
        mock_request.method = 'POST'
        mock_read_config_json_file.side_effect = Exception("exception")
        mock_gateway_nfv_management.get_configuration_id.side_effect = Exception("exception")
        mock_gateway_nfv_management.get_list_servers.side_effect = Exception("exception")
        mock_g.user.logger.error.side_effect = Exception("exception")
        jsonify = {"Status": "FAIL"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page import init_server_cached_list  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = init_server_cached_list()
            expect = jsonify
            self.assertEqual(expect, actual)
            mock_jsonify.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.read_config_json_file')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_init_server_cached_list_successfully(self, mock_jsonify, mock_request, mock_read_config_json_file,
                                                  mock_gateway_nfv_management, mock_memcached_nfv, mock_g):
        # pylint: disable=missing-docstring
        mock_request.method = 'POST'
        data_config = {
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211,
            "bam_config_name": "DemoConfig",
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "udfs_for_server": ["ups1", "ups2"],
            "vm_host_ip": "192.168.88.252",
            "vm_host_name": "VM_Host"
        }
        mock_read_config_json_file.return_value = data_config
        configuration_id = 102728
        mock_gateway_nfv_management.get_configuration_id.return_value = configuration_id
        list_servers = [
            {
                "id": 124707,
                "name": "srv2",
                "type": "Server",
                "properties": "ups_snmp_configuration={'snmp_config': {'v2c': {'status': 'enable', 'community_string': 'aaaaaaaaaaaaaaaa'}}, 'trap_oid': {'upsOverload': '1.3.6.1.4.1.318.0.2'}}|defaultInterfaceAddress=192.168.1.1|fullHostName=admin|profile=DNS_DHCP_INTEGRITY_BRANCH|"
            },
            {
                "id": 161908,
                "name": "BDDS82",
                "type": "Server",
                "properties": "defaultInterfaceAddress=192.168.22.1|fullHostName=BDDS82|profile=DNS_DHCP_INTEGRITY_BRANCH|"
            },
        ]
        mock_gateway_nfv_management.get_list_servers.return_value = list_servers
        mem_nfv = mock.Mock()
        mock_memcached_nfv.return_value = mem_nfv

        jsonify = {"Status": "SUCCESS"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page import init_server_cached_list  # pylint:disable=import-error
        actual = init_server_cached_list()
        expect = jsonify
        self.assertEqual(expect, actual)
        mock_jsonify.assert_called_once()
        mock_g.user.logger.debug.assert_called()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.get_vm_config_data')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_nfv_api_app_vm_successfully(self, mock_jsonify, mock_request, mock_get_vm_config_data,
                                         mock_gateway_nfv_management, mock_g):
        # pylint: disable=missing-docstring
        mock_request.json = True
        mock_request.method = "DELETE"
        data = {
            "vm_info":
                [
                    {
                        "vm_type": "bdds",
                        "vm_name": "bdds_01"
                    }
                ]
        }
        mock_request.get_json.return_value = data
        response = mock.MagicMock()
        mock_gateway_nfv_management.scale_in.return_value = response
        message = "Scale in successfully"
        response.return_value.get_json.reurn_value.return_value = message
        status = "Successfully"
        response.return_value.get_json.reurn_value.return_value = status
        error = ""
        response.return_value.get_json.reurn_value.return_value = error
        mock_gateway_nfv_management.scale_out = response
        jsonify = {"status": "Successful"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page import nfv_api_app_vm  # pylint:disable=import-error
        actual = nfv_api_app_vm()
        expect = (jsonify, 200)
        self.assertEqual(expect, actual)
        mock_g.user.logger.info.assert_called()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.gateway_nfv_management')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.get_vm_config_data')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.request')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page.jsonify')
    def test_nfv_api_app_vm_failed(self, mock_jsonify, mock_request, mock_get_vm_config_data,
                                   mock_gateway_nfv_management, mock_g):
        # pylint: disable=missing-docstring
        mock_request.json = True
        mock_request.method = "POST"
        data = {
            "vm_info":
                [
                    {
                        "vm_type": "bdds",
                        "vm_name": "bdds_01"
                    }
                ]
        }
        mock_request.get_json.return_value = data
        scale_out_data = {
            "server_name": "bdds_01",
            "mgnt_server_ip": "",
            "service_server_ipv4": "192.168.88.252",
            "service_server_ipv6": "",
            "service_server_netmask": 24,
            "service_server_v6_prefix": "",
            "metadata": ""
        }
        mock_get_vm_config_data.return_value = scale_out_data
        response = mock.MagicMock()
        message = "Scale out successfully"
        response.return_value.get_json.reurn_value.return_value = message
        status = "Successfully"
        response.return_value.get_json.reurn_value.return_value = status
        error = ""
        response.return_value.get_json.reurn_value.return_value = error
        mock_gateway_nfv_management.scale_out = response
        jsonify = {"status": "Successfully"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_plugin_page import nfv_api_app_vm  # pylint:disable=import-error
        actual = nfv_api_app_vm()
        expect = (jsonify, 200)
        self.assertEqual(expect, actual)
        mock_g.user.logger.info.assert_called()


if __name__ == "__main__":
    unittest.main()

