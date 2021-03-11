
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

# pylint: disable=missing-docstring, missing-final-newline
import unittest
import sys
import context
from unittest import mock  # pylint: disable=import-error

sys.modules["flask"] = mock.Mock()
sys.modules["suds"] = mock.Mock()


class TestGatewayNFVManagement(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configurations')
    def test_get_configuration_id(self, mock_get_configuration):
        # pylint: disable=missing-docstring
        configuration_list = [[124707, 'DemoConfig']]
        configuration_name = "DemoConfig"
        mock_get_configuration.return_value = configuration_list
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_configuration_id  # pylint:disable=import-error
        actual = get_configuration_id(configuration_name)
        expected = 124707
        self.assertEqual(expected, actual)
        mock_get_configuration.assert_called_once_with()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configurations')
    def test_get_configuration_id_none(self, mock_get_configuration):
        # pylint: disable=missing-docstring
        configuration_list = [["", "DemoConfig"]]
        configuration_name = "DemoConfig"
        mock_get_configuration.return_value = configuration_list
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_configuration_id  # pylint:disable=import-error
        actual = get_configuration_id(configuration_name)
        expected = None
        self.assertEqual(expected, actual)
        mock_get_configuration.assert_called_once_with()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    def test_scale_out_with_not_config_id(self, mock_get_configuration_id, mock_jsonify):
        # pylint: disable=missing-docstring
        config_id = None
        data = ""
        mock_get_configuration_id.return_value = config_id
        jsonify = {"status": "Failed",
                   "message": "Configuration id not found!"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 404)
        self.assertEqual(expect, actual)
        mock_get_configuration_id.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_not_available_server(self, mock_read_config_json_file, mock_get_configuration_id, mock_jsonify, mock_is_check_available_server):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = False
        mock_is_check_available_server.return_value = avail_server
        jsonify = {"status": "Failed", "message": "No available server ip!"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 404)
        self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_exception_metadata(self, mock_read_config_json_file, mock_get_configuration_id,
                                          mock_is_check_available_server, mock_process_password, mock_g):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": None
        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        with self.assertRaises(Exception):
            scale_out(data)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_exception_service_server_netmask(self, mock_read_config_json_file, mock_get_configuration_id,
                                                             mock_is_check_available_server, mock_process_password, mock_g):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "nhii",
            "service_server_netmask": 555,
            "service_server_ipv4": None
        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        with self.assertRaises(Exception):
            scale_out(data)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_exception_service_ipv6(self, mock_read_config_json_file, mock_get_configuration_id,
                                                    mock_is_check_available_server, mock_process_password, mock_g):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "aaa",
            "service_server_netmask": 24,
            "service_server_ipv4": "1.1.1.1",
            "service_server_v6_prefix": None,
            "service_server_ipv6": None

        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        with self.assertRaises(Exception):
            scale_out(data)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.create_deployment_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.add_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_none_role_id(self, mock_read_config_json_file, mock_get_configuration_id, mock_is_check_available_server,
                                            mock_add_server, mock_create_deployment_roles, mock_process_password, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "can_scale_in=True",
            "service_server_netmask": 24,
            "service_server_ipv4": "1.1.1.1",
            "service_server_v6_prefix": "nhii",
            "service_server_ipv6": "11.11.11.11",
            "server_name": "bdds"

        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456",
            "server_cap_profile": True,
            "dns_view_names": "view",
            "server_deploy_role": "server"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        server_id = 334498
        mock_add_server.return_value = server_id
        role_id = 123
        mock_create_deployment_roles.return_value = role_id
        jsonify = {"status": "Failed", "message": "Create deployment role failed"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 500)
        self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.create_deployment_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.add_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_none_server_cap_profile(self, mock_read_config_json_file, mock_get_configuration_id, mock_is_check_available_server,
                                                    mock_add_server, mock_create_deployment_roles, mock_process_password, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "can_scale_in=True",
            "service_server_netmask": 24,
            "service_server_ipv4": "1.1.1.1",
            "service_server_v6_prefix": "nhii",
            "service_server_ipv6": "11.11.11.11",
            "server_name": "bdds"

        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456",
            "server_cap_profile": None,
            "dns_view_names": "view",
            "server_deploy_role": "server"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        server_id = 334498
        mock_add_server.return_value = server_id
        role_id = None
        mock_create_deployment_roles.return_value = role_id
        jsonify = {"status": "Failed", "message": "Create deployment role failed"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 500)
        self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.create_deployment_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.add_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_with_dns_view(self, mock_read_config_json_file, mock_get_configuration_id, mock_is_check_available_server, mock_add_server,
                                     mock_create_deployment_roles, mock_process_password, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "can_scale_in=True",
            "service_server_netmask": 24,
            "service_server_ipv4": "1.1.1.1",
            "service_server_v6_prefix": "nhii",
            "service_server_ipv6": "11.11.11.11",
            "server_name": "bdds"

        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456",
            "server_cap_profile": None,
            "dns_view_names": "aaa",
            "server_deploy_role": "server"
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        server_id = 334498
        mock_add_server.return_value = server_id
        role_id = None
        mock_create_deployment_roles.return_value = role_id
        jsonify = {"status": "Failed", "message": "Create deployment role failed"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 500)
        self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.wait_for_deployment')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.deploy_server_config')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.create_deployment_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.add_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.is_check_available_server')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_out_successfully(self, mock_read_config_json_file, mock_get_configuration_id, mock_is_check_available_server,
                                    mock_add_server, mock_create_deployment_roles, mock_deploy_server_config,
                                    mock_wait_for_deployment, mock_process_password, mock_memcached_nfv, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "mgnt_server_ip": "192.168.88.169",
            "metadata": "aaa",
            "service_server_netmask": 24,
            "service_server_ipv4": "1.1.1.1",
            "service_server_v6_prefix": "nhii",
            "service_server_ipv6": "11.11.11.11",
            "server_name": "bdds"

        }
        data_config = {
            "server_ssh_username": "root",
            "server_ssh_password": "123456",
            "bam_config_name": "bam54",
            "mgnt_server_ip": "192.168.88.169",
            "server_deployment_password": "123456",
            "server_cap_profile": True,
            "dns_view_names": "view",
            "server_deploy_role": "server",
            "anycast_config": True,
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211,
        }
        mock_read_config_json_file.return_value = data_config
        config_id = 102728
        mock_get_configuration_id.return_value = config_id
        avail_server = True
        mock_is_check_available_server.return_value = avail_server
        server_id = 334498
        server_properties = "nhiii"
        mock_process_password.return_value = server_properties
        mock_add_server.return_value = server_id
        role_id = 111
        mock_create_deployment_roles.return_value = role_id
        deploy_server = True
        mock_deploy_server_config.return_value = deploy_server
        deploy_status = True
        mock_wait_for_deployment.return_value = deploy_status
        mem_nfv = []
        mock_memcached_nfv.return_value = mem_nfv
        jsonify = {"status": "Successful", "message": "Scale out successfully", "error": ""}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_out  # pylint:disable=import-error
        actual = scale_out(data)
        expect = (jsonify, 500)
        self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    def test_scale_in_with_not_config_id(self, mock_get_configuration_id, mock_jsonify):
        # pylint: disable=missing-docstring
        config_id = None
        data = ""
        mock_get_configuration_id.return_value = config_id
        jsonify = {"status": "Failed",
                   "message": "Configuration id not found!"}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_in  # pylint:disable=import-error
        actual = scale_in(data)
        expect = (jsonify, 404)
        self.assertEqual(expect, actual)
        mock_get_configuration_id.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.wait_for_deployment')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.deploy_server_config')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_server_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_by_name')
    def test_scale_in_failed_remove_roles_false(self, mock_get_server_by_name, mock_delete_server_roles, mock_deploy_server_config, mock_wait_for_deployment,
                                                mock_delete_entity, mock_memcache_nfv, mock_g, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "metadata": "",
            "service_server_netmask": "",
            "service_server_v6_prefix": "",
            "service_server_ipv6": "",
            "server_cap_profile": "",
            "server_name": "bdds169",
            "server_deploy_role": "",
            "dns_view_names": "",
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "memcached_host": "192.168.88.170",
            "memcached_port": "11211"
        }
        server = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_get_server_by_name.return_value = server
        remove_roles = False
        mock_delete_server_roles.return_value = remove_roles
        deploy_server = True
        mock_deploy_server_config.return_value = deploy_server
        deploy_status = 1
        mock_wait_for_deployment.return_value = deploy_status
        delete_server = True
        mock_delete_entity.return_value = delete_server
        mem_nfv = mock.Mock()
        mock_memcache_nfv.return_value = mem_nfv
        mock_g.user.logger.error.side_effect = Exception("exception")
        exception = mock.Mock()
        jsonify = {"status": "Failed",
                   "message": "Scale in failed", "error": str(exception)}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_in # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = scale_in(data)
            expect = (jsonify, 500)
            self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.wait_for_deployment')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.deploy_server_config')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_server_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_by_name')
    def test_scale_in_failed_with_default_interface_address_not_correct_position(self, mock_get_server_by_name, mock_delete_server_roles,
                                                                                 mock_deploy_server_config, mock_wait_for_deployment, mock_delete_entity, mock_memcache_nfv, mock_g, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "metadata": "",
            "service_server_netmask": "",
            "service_server_v6_prefix": "",
            "service_server_ipv6": "",
            "server_cap_profile": "",
            "server_name": "bdds169",
            "server_deploy_role": "",
            "dns_view_names": "",
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "memcached_host": "192.168.88.170",
            "memcached_port": "11211"
        }
        server = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_get_server_by_name.return_value = server
        remove_roles = False
        server['properties'].split('|')[0].split('=')[0] = "nhiii"
        mock_delete_server_roles.return_value = remove_roles
        deploy_server = True
        mock_deploy_server_config.return_value = deploy_server
        deploy_status = 1
        mock_wait_for_deployment.return_value = deploy_status
        delete_server = True
        mock_delete_entity.return_value = delete_server
        mem_nfv = mock.Mock()
        mock_memcache_nfv.return_value = mem_nfv
        mock_g.user.logger.error.side_effect = Exception("exception")
        exception = mock.Mock()
        jsonify = {"status": "Failed",
                   "message": "Scale in failed", "error": str(exception)}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_in # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = scale_in(data)
            expect = (jsonify, 500)
            self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.wait_for_deployment')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.deploy_server_config')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_server_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_by_name')
    def test_scale_in_failed_with_deploy_server_false(self, mock_get_server_by_name, mock_delete_server_roles, mock_deploy_server_config, mock_wait_for_deployment,
                                                      mock_delete_entity, mock_memcache_nfv, mock_g, mock_jsonify):
        # pylint: disable=missing-docstring
        data = {
            "metadata": "",
            "service_server_netmask": "",
            "service_server_v6_prefix": "",
            "service_server_ipv6": "",
            "server_cap_profile": "",
            "server_name": "bdds169",
            "server_deploy_role": "",
            "dns_view_names": "",
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "memcached_host": "192.168.88.170",
            "memcached_port": "11211"
        }
        server = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_get_server_by_name.return_value = server
        remove_roles = False
        server['properties'].split('|')[0].split('=')[0] = "nhiii"
        mock_delete_server_roles.return_value = remove_roles
        deploy_server = False
        mock_deploy_server_config.return_value = deploy_server
        deploy_status = 1
        mock_wait_for_deployment.return_value = deploy_status
        delete_server = True
        mock_delete_entity.return_value = delete_server
        mem_nfv = mock.Mock()
        mock_memcache_nfv.return_value = mem_nfv
        mock_g.user.logger.error.side_effect = Exception("exception")
        exception = mock.Mock()
        jsonify = {"status": "Failed",
                   "message": "Scale in failed", "error": str(exception)}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_in # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = scale_in(data)
            expect = (jsonify, 500)
            self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.jsonify')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.MemcachedNFV')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.wait_for_deployment')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.deploy_server_config')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_server_roles')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_by_name')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_configuration_id')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_scale_in_failed_with_delete_server_false(self, mock_read_config_json_file, mock_get_configuration_id,
                                                      mock_get_server_by_name, mock_delete_server_roles, mock_deploy_server_config, mock_wait_for_deployment,
                                                      mock_delete_entity, mock_memcache_nfv, mock_g, mock_jsonify):

        # pylint: disable=missing-docstring
        data = {
            "metadata": "",
            "service_server_netmask": "",
            "service_server_v6_prefix": "",
            "service_server_ipv6": "",
            "server_cap_profile": "",
            "server_name": "bdds169",
            "server_deploy_role": "",
            "dns_view_names": "",
            "bam": [
                {
                    "ip": "192.168.88.54",
                    "name": "DNS_999_BAM_0001"
                }
            ],
            "memcached_host": "192.168.88.170",
            "memcached_port": "11211"
        }
        server = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_get_server_by_name.return_value = server
        remove_roles = False
        server['properties'].split('|')[0].split('=')[0] = "nhiii"
        mock_delete_server_roles.return_value = remove_roles
        deploy_server = False
        mock_deploy_server_config.return_value = deploy_server
        deploy_status = 1
        mock_wait_for_deployment.return_value = deploy_status
        delete_server = False
        mock_delete_entity.return_value = delete_server
        mem_nfv = mock.Mock()
        mock_memcache_nfv.return_value = mem_nfv
        mock_g.user.logger.error.side_effect = Exception("exception")
        exception = mock.Mock()
        jsonify = {"status": "Failed",
                   "message": "Scale in failed", "error": str(exception)}
        mock_jsonify.return_value = jsonify
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import scale_in # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = scale_in(data)
            expect = (jsonify, 500)
            self.assertEqual(expect, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password.decrypt_password')
    def test_stop_anycast_services_true(self, mock_decrypt_password, mock_run_ssh_command, mock_g):
        # pylint: disable=missing-docstring
        mock_decrypt_password.return_value = "d8e8fca"
        mock_run_ssh_command.return_value = b'retcode=ok', None
        server_id = 334498
        username = "root"
        pwd = "d8e8fca"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import stop_anycast_service # pylint:disable=import-error
        stop_anycast_service(server_id, username, pwd)
        mock_g.user.logger.debug.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password.decrypt_password')
    def test_stop_anycast_services_false(self, mock_decrypt_password, mock_run_ssh_command, mock_g):
        # pylint: disable=missing-docstring
        mock_decrypt_password.return_value = "d8e8fca"
        mock_run_ssh_command.return_value = b'retcode=nhii', b'error'
        server_id = 334498
        username = "root"
        pwd = "d8e8fca"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import stop_anycast_service # pylint:disable=import-error
        stop_anycast_service(server_id, username, pwd)
        self.assertEqual(mock_g.user.logger.error.call_count, 2)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_get_server_by_name(self, mock_g):
        # pylint: disable=missing-docstring
        server = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        config_id = 102728
        server_name = "bdds169"
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_server_by_name # pylint:disable=import-error
        actual = get_server_by_name(config_id, server_name)
        expected = server
        self.assertEqual(expected, actual)
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.BAMException', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_get_server_by_name_with_exception(self, mock_g):
        # pylint: disable=missing-docstring
        config_id = 102728
        server_name = "bdds169"
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_server_by_name  # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_server_by_name(config_id, server_name)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_roles')
    def test_delete_server_roles_with_delete_entity_true(self, mock_get_server_roles, mock_delete_entity):
        # pylint: disable=missing-docstring
        roles = [335958, 335957]
        mock_get_server_roles.return_value = roles
        server_id = "334498"
        mock_delete_entity.return_value = True
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import delete_server_roles # pylint:disable=import-error
        actual = delete_server_roles(server_id)
        expected = True
        self.assertEqual(expected, actual)
        mock_get_server_roles.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.delete_entity')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.get_server_roles')
    def test_delete_server_roles_with_delete_entity_false(self, mock_get_server_roles, mock_delete_entity):
        # pylint: disable=missing-docstring
        roles = [335958, 335957]
        mock_get_server_roles.return_value = roles
        server_id = "334498"
        mock_delete_entity.return_value = False
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import delete_server_roles # pylint:disable=import-error
        actual = delete_server_roles(server_id)
        expected = False
        self.assertEqual(expected, actual)
        mock_get_server_roles.assert_called_once_with(server_id)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_get_server_roles(self, mock_g):
        # pylint: disable=missing-docstring
        server_id = "334498"
        roles = [
            {
                "id": 335958,
                "entityId": 160080,
                "serverInterfaceId": 332455,
                "type": "NONE",
                "service": "DHCP",
                "properties": "readOnly=false|secondaryServerInterfaceId=334499|"
            },
            {
                "id": 335957,
                "entityId": 160080,
                "serverInterfaceId": 332455,
                "type": "NONE",
                "service": "DHCP",
                "properties": "readOnly=false|secondaryServerInterfaceId=334499|"
            }]
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentRoles.return_value = roles
        roles_id = [335958, 335957]
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_server_roles # pylint:disable=import-error
        actual = get_server_roles(server_id)
        expected = roles_id
        self.assertEqual(expected, actual)
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentRoles.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_get_server_roles_none(self, mock_g):
        # pylint: disable=missing-docstring
        server_id = "334498"
        mock_g.user.logger.warning.side_effect = Exception("exception")
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentRoles.side_effect = Exception(
            "exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_server_roles # pylint:disable=import-error
        with self.assertRaises(Exception) as context:
            actual = get_server_roles(server_id)
            expect = []
            self.assertEqual(actual, expect)
        self.assertTrue("exception" in str(context.exception))
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentRoles.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_delete_entity_true(self, mock_g):
        # pylint: disable=missing-docstring
        entity_id = "334498"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import delete_entity # pylint:disable=import-error
        actual = delete_entity(entity_id)
        expected = True
        self.assertEqual(expected, actual)
        mock_g.user.get_api.return_value._api_client.service.delete.assert_called_once_with(
            entity_id)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_delete_entity_false(self, mock_g):
        # pylint: disable=missing-docstring
        entity_id = "334498"
        mock_g.user.get_api.return_value._api_client.service.delete.side_effect = Exception("exception")
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import delete_entity  # pylint:disable=import-error
        with self.assertRaises(Exception) as context:
            delete_entity(entity_id)
        self.assertTrue('except' in str(context.exception))

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.paramiko')
    def test_is_check_available_server_with_true(self, mock_paramiko, mock_process_password):
        # pylint: disable=missing-docstring
        ssh = mock.Mock()
        mock_paramiko.SSHClient.return_value = ssh
        pwd_decrypt = "d8e8fca"
        server_ip = "192.168.88.169"
        username = "root"
        password = "d8e8fca"
        mock_process_password.decrypt_password.return_value = pwd_decrypt
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import is_check_available_server # pylint:disable=import-error
        actual = is_check_available_server(server_ip, username, password)
        expected = True
        self.assertEqual(actual, expected)
        mock_process_password.decrypt_password.assert_called_once_with(
            password)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.NoValidConnectionsError', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.paramiko')
    def test_is_check_available_server_with_false(self, mock_paramiko, mock_process_password):
        # pylint: disable=missing-docstring
        ssh = mock.Mock()
        mock_paramiko.SSHClient.return_value = ssh
        pwd_decrypt = None
        server_ip = "192.168.88.169"
        username = "root"
        password = "d8e8fca"
        mock_process_password.decrypt_password.return_value = pwd_decrypt
        ssh.connect.side_effect = OSError('exception'), Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import is_check_available_server # pylint:disable=import-error
        actual = is_check_available_server(server_ip, username, password)
        expect = False
        self.assertEqual(actual, expect)
        mock_process_password.decrypt_password.assert_called_once_with(
            password)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.time')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_add_server(self, mock_g, mock_time):
        # pylint: disable=missing-docstring
        properties = "password=bluecat|connected=true|upgrade=False"
        server_id = "3334498"
        server_name = "bdds_169"
        server_ip = "192.168.88.169"
        config_id = "102728"
        profile = 'DNS_DHCP_SERVER_60'
        mock_g.user.get_api.return_value._api_client.service.addServer.return_value = server_id
        start = 15
        mock_time.time.return_value = start
        mock_g.user.get_api.return_value.get_entity_by_id.return_value.get_id.return_value = server_id
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import add_server # pylint:disable=import-error
        actual = add_server(server_ip, server_name,
                            config_id, profile, properties)
        expected = server_id
        self.assertEqual(expected, actual)
        mock_g.user.get_api.return_value.get_entity_by_id.return_value.get_id.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.PortalException', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.time')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_add_server_with_portal_exception(self, mock_g, mock_time):
        # pylint: disable=missing-docstring
        properties = "password=bluecat|connected=true|upgrade=False"
        server_id = "3334498"
        server_name = "bdds_169"
        server_ip = "192.168.88.169"
        config_id = "102728"
        profile = 'DNS_DHCP_SERVER_60'
        mock_g.user.get_api.return_value._api_client.service.addServer.side_effect = Exception(
            "exception")
        start = 15
        mock_time.time.return_value = start
        mock_g.user.get_api.return_value.get_entity_by_id.return_value.get_id.return_value = server_id
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import add_server  # pylint:disable=import-error
        with self.assertRaises(Exception) as context:
            add_server(server_ip, server_name,
                       config_id, profile, properties)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.time')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_add_server_with_webdefault_exception(self, mock_g, mock_time):
        # pylint: disable=missing-docstring
        properties = "password=bluecat|connected=true|upgrade=False"
        server_id = "3334498"
        server_name = "bdds_169"
        server_ip = "192.168.88.169"
        config_id = "102728"
        profile = 'DNS_DHCP_SERVER_60'
        mock_g.user.get_api.return_value._api_client.service.addServer.side_effect = Exception(
            "exception")
        start = 15
        mock_time.time.return_value = start
        mock_g.user.get_api.return_value.get_entity_by_id.return_value.get_id.return_value = server_id
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import add_server # pylint:disable=import-error
        with self.assertRaises(Exception) as context:
            add_server(server_ip, server_name,
                       config_id, profile, properties)
        self.assertTrue('except' in str(context.exception))

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.PortalException', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_false(self, mock_g):
        # pylint: disable=missing-docstring
        mock_g.user.get_api.return_value.get_entity_by_id.side_effect = Exception(
            "exception")
        server_name = "bdds169"
        server_id = 334498
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        mock_g.user.logger.warning.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = create_deployment_roles(
                server_name, server_id, config_id, view_name, role_type, properties)
            expect = False
            self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.PortalException', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_with_server_id_none(self, mock_g):
        # pylint: disable=missing-docstring
        configuration = mock.Mock()
        mock_g.user.get_api.return_value.get_entity_by_id.return_value = configuration
        server_id = None
        server_obj = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server_obj
        server_nsf = {
            "id": 111
        }
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server_nsf
        server_name = "bdds169"
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        role_id = None
        mock_g.user.get_api.return_value._api_client.service.addDNSDeploymentRole.return_value = role_id
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        actual = create_deployment_roles(
            server_name, server_id, config_id, view_name, role_type, properties)
        expected = False
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_successfully(self, mock_g):
        # pylint: disable=missing-docstring
        configuration = mock.Mock()
        mock_g.user.get_api.return_value.get_entity_by_id.return_value = configuration
        server_id = 334498
        server_nsf = {
            "id": 111
        }
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server_nsf
        server_name = "bdds169"
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        role_id = 111
        mock_g.user.get_api.return_value._api_client.service.addDNSDeploymentRole.return_value = role_id
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        actual = create_deployment_roles(
            server_name, server_id, config_id, view_name, role_type, properties)
        expected = role_id
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_with_none_server_id(self, mock_g):
        # pylint: disable=missing-docstring
        configuration = mock.Mock()
        mock_g.user.get_api.return_value.get_entity_by_id.return_value = configuration
        server_id = None
        server_obj = {
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server_obj
        server_nsf = {
            "id": 111
        }
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.return_value = server_nsf
        server_name = "bdds169"
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        mock_g.user.get_api.return_value._api_client.service.addDNSDeploymentRole.return_value = None
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        actual = create_deployment_roles(
            server_name, server_id, config_id, view_name, role_type, properties)
        expected = False
        self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_with_webfault_exception(self, mock_g):
        # pylint: disable=missing-docstring
        configuration = mock.Mock()
        mock_g.user.get_api.return_value.get_entity_by_id.return_value = configuration
        mock_g.user.get_api.return_value._api_client.service.getEntityByName.side_effect = Exception(
            "exception")
        server_name = "bdds169"
        server_id = 334498
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        mock_g.user.get_api.return_value._api_client.service.addDNSDeploymentRole.side_effect = Exception(
            "exception")
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = create_deployment_roles(
                server_name, server_id, config_id, view_name, role_type, properties)
            expected = False
            self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.PortalException', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_create_deployment_roles_with_portal_exception(self, mock_g):
        # pylint: disable=missing-docstring
        mock_g.user.get_api.return_value.get_entity_by_id.side_effect = Exception(
            "exception")
        mock_g.user.logger.warning.side_effect = Exception("exception")
        server_name = "bdds169"
        server_id = 334498
        config_id = 102728
        view_name = "default"
        role_type = "SLAVE_STEALTH"
        properties = ""
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import create_deployment_roles # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = create_deployment_roles(
                server_name, server_id, config_id, view_name, role_type, properties)
            expected = False
            self.assertEqual(expected, actual)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_get_list_servers(self, mock_g):
        # pylint: disable=missing-docstring
        list_server = [{
            "id": 334498,
            "name": "bdds169",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }, {
            "id": 332454,
            "name": "bdds141",
            "type": "Server",
            "properties": "defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }]
        configuration_id = 102728
        mock_g.user.get_api.return_value._api_client.service.getEntities.return_value = list_server
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_list_servers # pylint:disable=import-error
        actual = get_list_servers(configuration_id)
        expected = list_server
        self.assertEqual(expected, actual)
        mock_g.user.get_api.return_value._api_client.service.getEntities.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_get_memcached_config(self, mock_read_config_json_file):
        # pylint: disable=missing-docstring
        data_config = {
            "sync_interval": 1,
            "memcached_host": "192.168.88.170",
            "memcached_port": 11211,
            "k1_api": {
                "address": "192.168.88.161",
                "port": 5555,
                "uri": "/api/v1.0/srvo/instances/realtime_load"
            }
        }
        mock_read_config_json_file.return_value = data_config
        memcached_host = "192.168.88.170"
        memcached_port = 11211
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_memcached_config # pylint:disable=import-error
        actual = get_memcached_config()
        expected = memcached_host, int(memcached_port)
        self.assertEqual(expected, actual)
        mock_read_config_json_file.assert_called_once()

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.read_config_json_file')
    def test_get_memcached_config_with_exception(self, mock_read_config_json_file):
        # pylint: disable=missing-docstring
        data_config = {}
        mock_read_config_json_file.return_value = data_config
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import get_memcached_config # pylint:disable=import-error
        with self.assertRaises(Exception):
            get_memcached_config()
        mock_read_config_json_file.assert_called_once()

    def test_deploy_server_config_true(self):
        # pylint: disable=missing-docstring
        server_id = 334498
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import deploy_server_config # pylint:disable=import-error
        actual = deploy_server_config(server_id)
        expect = True
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_deploy_server_config_false(self, mock_g):
        # pylint: disable=missing-docstring
        server_id = 334498
        mock_g.user.get_api.return_value._api_client.service.deployServerConfig.side_effect = Exception(
            "exception")
        mock_g.user.logger.error.side_effect = Exception("exception")
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import deploy_server_config # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = deploy_server_config(server_id)
            expect = False
            self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_wait_for_deployment_fail_with_web_default(self, mock_g):
        # pylint: disable=missing-docstring
        status = None
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentStatus.return_value = status
        server_id = "334498"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import wait_for_deployment  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = wait_for_deployment(server_id)
            expect = False
            self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_wait_for_deployment_successfully(self, mock_g):
        # pylint: disable=missing-docstring
        status = 2
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentStatus.return_value = status
        server_id = "334498"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import wait_for_deployment # pylint:disable=import-error
        actual = wait_for_deployment(server_id)
        expect = status
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_wait_for_deployment_with_big_count(self, mock_g):
        """

        :param mock_g:
        :return:
        """
        status = 9
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentStatus.return_value = status
        server_id = "334498"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import wait_for_deployment # pylint:disable=import-error
        actual = wait_for_deployment(server_id)
        expect = status
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.WebFault', Exception)
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.g')
    def test_wait_for_deployment_fail_with_status_not_in_list(self, mock_g):
        # pylint: disable=missing-docstring
        mock_g.user.get_api.return_value._api_client.service.getServerDeploymentStatus.side_effect = Exception(
            "exception")
        server_id = "334498"
        result = False
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import wait_for_deployment # pylint:disable=import-error
        actual = wait_for_deployment(server_id)
        expect = result
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.set')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.re')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_psmclient_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    def test_configure_anycast_with_protocol_ospfd_and_ipv6(self, mock_process_password, mock_run_psmclient_cmd,
                                                            mock_re, mock_set, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        mock_process_password.decrypt_password = mock.Mock()
        server_ip = "192.168.88.169"
        username = "root"
        server_ipv6 = "FDAC:1400:1::20"
        pwd = "d8e8fca"
        anycast_config = {
            "anycast_protocol": "ospfd",
            "anycast_ipv4": "192.18.88.169",
            "anycast_ipv6": "FDAC:1400:1::20",
            "ospf_authenticate": "nhii",
            "ospf_dead_interval": "",
            "ospf_hello_interval": "",
            "ospf_password": "",
            "ospf_area": "nhii",
            "ospf_stub": "123",
            "ospfv3_hello_interval": "",
            "ospfv3_dead_interval": "",
            "ospfv3_area": "",
            "ospfv3_range": ""
        }
        m = mock.Mock()  # pylint:disable=invalid-name
        mock_re.match.return_value = m
        psm_overrides = {'anycast', 'nhiii'}
        mock_set.return_value = psm_overrides
        output, error = "nhiii", "info"
        mock_run_ssh_cmd.return_value = output, error
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import configure_anycast # pylint:disable=import-error
        configure_anycast(server_ip, server_ipv6,
                          username, pwd, anycast_config)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.set')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.re')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_psmclient_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    def test_configure_anycast_with_protocol_ospfd_and_ipv4(self, mock_process_password, mock_run_psmclient_cmd,
                                                            mock_re, mock_set, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        mock_process_password.decrypt_password = mock.Mock()
        server_ip = "192.168.88.169"
        username = "root"
        server_ipv6 = None
        pwd = "d8e8fca"
        anycast_config = {
            "anycast_protocol": "ospfd",
            "anycast_ipv4": "192.18.88.169",
            "anycast_ipv6": "FDAC:1400:1::20",
            "ospf_authenticate": "nhii",
            "ospf_dead_interval": "",
            "ospf_hello_interval": "",
            "ospf_password": "",
            "ospf_area": "nhii",
            "ospf_stub": "123",
            "ospfv3_hello_interval": "",
            "ospfv3_dead_interval": "",
            "ospfv3_area": "",
            "ospfv3_range": ""
        }
        m = mock.Mock()  # pylint:disable=invalid-name
        mock_re.match.return_value = m
        psm_overrides = {'anycast', 'nhiii'}
        mock_set.return_value = psm_overrides
        output, error = "nhiii", "info"
        mock_run_ssh_cmd.return_value = output, error
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import configure_anycast # pylint:disable=import-error
        configure_anycast(server_ip, server_ipv6,
                          username, pwd, anycast_config)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.set')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.re')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_psmclient_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    def test_configure_anycast_with_protocol_bgp(self, mock_process_password, mock_run_psmclient_cmd,
                                                 mock_re, mock_set, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        mock_process_password.decrypt_password = mock.Mock()
        server_ip = "192.168.88.169"
        username = "root"
        server_ipv6 = "FDAC:1400:1::20"
        pwd = "d8e8fca"
        anycast_config = {
            "anycast_protocol": "bgp",
            "anycast_ipv4": "192.18.88.169",
            "anycast_ipv6": "FDAC:1400:1::20",
            "prefix_lists": None,
            "bgp_local_asn": "nhii",
            "bgp_telnet_password": "",
            "bgp_keepalive_time": "",
            "bgp_command_line_interface": "",
            "bgp_hold_time": "",
            "bgp_ipv6_address": "",
            "bgp_ipv4_address": "",
            "bgp_remote_asn_in_ipv4": "",
            "bgp_ipv4_hop_limit": "",
            "bgp_next_hop_self_ipv4": "",
            "bgp_md5_ipv4": "",
            "bgp_remote_asn_in_ipv6": "",
            "bgp_ipv6_hop_limit": "",
            "bgp_next_hop_self_ipv6": "",
            "bgp_md5_ipv6": "",

        }
        m = mock.Mock()  # pylint:disable=invalid-name
        mock_re.match.return_value = m
        psm_overrides = {'anycast', 'nhiii'}
        mock_set.return_value = psm_overrides
        output, error = "nhiii", "info"
        mock_run_ssh_cmd.return_value = output, error
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import configure_anycast  # pylint:disable=import-error
        configure_anycast(server_ip, server_ipv6,
                          username, pwd, anycast_config)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.set')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.re')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_psmclient_cmd')
    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.process_password')
    def test_configure_anycast_with_protocol_rip(self, mock_process_password, mock_run_psmclient_cmd,
                                                 mock_re, mock_set, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        mock_process_password.decrypt_password = mock.Mock()
        server_ip = "192.168.88.169"
        username = "root"
        server_ipv6 = "FDAC:1400:1::20"
        pwd = "d8e8fca"
        anycast_config = {
            "anycast_protocol": "rip",
            "anycast_ipv4": "192.18.88.169",
            "anycast_ipv6": "FDAC:1400:1::20",
            "prefix_lists": None,
            "rip_authenticate": "nhii",
            "rip_password": "",
        }
        m = mock.Mock()  # pylint:disable=invalid-name
        mock_re.match.return_value = m
        psm_overrides = {'anycast', 'nhiii'}
        mock_set.return_value = psm_overrides
        output, error = "nhiii", "info"
        mock_run_ssh_cmd.return_value = output, error
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import configure_anycast # pylint:disable=import-error
        configure_anycast(server_ip, server_ipv6,
                          username, pwd, anycast_config)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    def test_run_psmclient_cmd_with_output_ok(self, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        output, error = b'retcode=ok', b''
        mock_run_ssh_cmd.return_value = output, error
        server_ip = "192.168.88.169"
        username = "root"
        password = "d8e8fca"
        cmd = ""
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import run_psmclient_cmd # pylint:disable=import-error
        actual = run_psmclient_cmd(server_ip, username, password, cmd)
        expect = output
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.run_ssh_cmd')
    def test_run_psmclient_not_ok(self, mock_run_ssh_cmd):
        # pylint: disable=missing-docstring
        output, error = b'retcode=false', b''
        mock_run_ssh_cmd.return_value = output, error
        server_ip = "192.168.88.169"
        username = "root"
        password = "d8e8fca"
        cmd = ""
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import run_psmclient_cmd # pylint:disable=import-error
        actual = run_psmclient_cmd(server_ip, username, password, cmd)
        expect = output
        self.assertEqual(actual, expect)

    @mock.patch('GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management.socket')
    def test_cidr_to_netmask(self, mock_socket):
        # pylint: disable=missing-docstring
        net_bits = 24
        mock_socket.inet_ntoa.return_value = "255.255.255.0"
        from GatewayNFVPlugin.gateway_nfv_plugin.gateway_nfv_management import cidr_to_netmask  # pylint:disable=import-error
        actual = cidr_to_netmask(net_bits)
        expect = "255.255.255.0"
        self.assertEqual(actual, expect)


if __name__ == "__main__":
    unittest.main()
