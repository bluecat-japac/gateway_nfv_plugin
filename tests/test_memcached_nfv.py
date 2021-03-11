
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

import unittest
import sys
import context
from unittest import mock  # pylint: disable=import-error

from memcached.memcached_nfv import MemcachedNFV  # pylint:disable=import-error

sys.modules["client"] = mock.Mock()


class TestMemcachedNFV(unittest.TestCase):
    # pylint: disable=missing-docstring
    @mock.patch('memcached.memcached_nfv.MemcachedNFV._get_connection')
    @mock.patch('memcached.memcached_nfv.base')
    @mock.patch('logging.Logger.error')
    def test_init_memcached_nfv_failed(self, mock_log, mock_base, mock_get_connetion):
        # pylint: disable=missing-docstring
        host = mock.Mock()
        port = mock.Mock()
        exception_msg = "Cannot connect to memcached"
        exception = Exception(exception_msg)
        mock_get_connetion.side_effect = exception
        memcached_nfv = MemcachedNFV(host, port)
        # mock_log.assert_called_with(
        #     'MemcachedNFV-Init-{}'.format(exception_msg))
        self.assertEqual(mock_log.call_count, 2)

    @mock.patch('memcached.memcached_nfv.base')
    def test__get_connection(self, mock_base):
        # pylint: disable=missing-docstring
        connection = True
        mock_base.Client = connection
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        with self.assertRaises(Exception):
            memcached_nfv._get_connection()

    def test_disconnect(self):
        # pylint: disable=missing-docstring
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.client.close()

    @mock.patch('memcached.server.ServerType')
    @mock.patch('logging.Logger.info')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_set_server_bam_successful(self, mock_log, mock_server_type):
        # pylint: disable=missing-docstring
        server = {
            'name': mock.Mock(),
            'ipv4_address': mock.Mock()
        }
        server_type = "BAM"
        mock_server_type.BAM.return_value = server_type
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.set_server(server, server_type)
        key = "{}|{}".format(mock_server_type.BAM, server['ipv4_address'])
        mock_log.assert_called_with('Added {} to memcache'.format(key))

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_set_server_bdds_successful(self, mock_server_type):
        # pylint: disable=missing-docstring
        server = {
            'name': mock.Mock(),
            'ipv4_address': mock.Mock()
        }
        server_type = "BDDS"
        mock_server_type.BAM.return_value = server_type
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.set_server(server, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_set_server_bam_exception(self, mock_server_type):
        # pylint: disable=missing-docstring
        server = {
            'name': mock.Mock(),
            'ipv4_address': mock.Mock()
        }
        server_type = "BAM"
        mock_server_type.BAM.return_value = server_type
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.set_server(server, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_set_server_vmhost_successful(self, mock_server_type):
        server = {
            'name': mock.Mock(),
            'ipv4_address': mock.Mock()
        }
        server_type = "VMHost"
        mock_server_type.VMHost.return_value = server_type
        MemcachedNFV.client = mock.Mock()
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.set_server(server, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_server_bdds(self, mock_server_type):
        # pylint: disable=missing-docstring
        server_id = 334498
        server_type = "BDDS"
        mock_server_type.BDDS.return_value = server_type
        server = None
        MemcachedNFV.client.get.return_value = server
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.get_server(server_id, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_server_bam(self, mock_server_type):
        # pylint: disable=missing-docstring
        server_id = 334498
        server_type = "BAM"
        mock_server_type.BAM.return_value = server_type
        server = None
        MemcachedNFV.client.get.return_value = server
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.get_server(server_id, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch('logging.Logger.info')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_server_exception(self, mock_log, mock_server_type):
        # pylint: disable=missing-docstring
        server_id = 334498
        server_type = "BDDS"
        mock_server_type.BDDS.return_value = server_type
        MemcachedNFV.client.get.side_effect = Exception("exception")
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())

        with self.assertRaises(Exception) as exception:
            memcached_nfv.get_server(server_id, server_type)
            mock_log.assert_called_with('Added {} to memcached'.format(exception))

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_delete_server_bdds(self, mock_server_type):
        # pylint: disable=missing-docstring
        server_id = 334498
        server_type = "BDDS"
        bam_ip = None
        mock_server_type.BDDS.return_value = server_type
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        key = "{}|{}|{}".format(server_type, bam_ip, server_id)
        memcached_nfv.client.delete(key)
        memcached_nfv.get_server(server_id, server_type)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_list_servers_bdds(self, mock_server_type):
        # pylint: disable=missing-docstring
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        keys = mock.MagicMock()
        memcached_nfv.get_list_server_keys = keys
        key = mock.Mock()
        key.decode.return_value.split.return_value.return_value = mock_server_type.BDDS
        actual = memcached_nfv.get_list_servers()
        expect = ([], [], [])
        self.assertEqual(expect, actual)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_list_servers_bam(self, mock_server_type):
        # pylint: disable=missing-docstring
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        keys = mock.MagicMock()
        memcached_nfv.get_list_server_keys = keys
        key = mock.Mock()
        key.decode.return_value.split.return_value.return_value = mock_server_type.BAM
        actual = memcached_nfv.get_list_servers()
        expect = ([], [], [])
        self.assertEqual(expect, actual)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_get_list_servers(self, mock_server_type):
        # pylint: disable=missing-docstring
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        keys = mock.MagicMock()
        memcached_nfv.get_list_server_keys = keys
        key = mock.Mock()
        key.decode.return_value.split.return_value.return_value = mock_server_type.VMHost
        actual = memcached_nfv.get_list_servers()
        expect = ([], [], [])
        self.assertEqual(expect, actual)

    @mock.patch('memcached.server.ServerType')
    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_delete_server_bam(self, mock_server_type):
        # pylint: disable=missing-docstring
        server_type = "BDDS"
        bam_ip = None
        server_id = 334498
        mock_server_type.BDDS.return_value = server_type
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        key = "{}|{}|{}".format(server_type, bam_ip, server_id)
        memcached_nfv.client.delete(key)
        memcached_nfv.delete_server(server_id, server_type)

    @mock.patch.object(MemcachedNFV, "__init__", lambda self, host, port: None)
    def test_clean_memcached(self):
        # pylint: disable=missing-docstring
        memcached_nfv = MemcachedNFV(mock.Mock(), mock.Mock())
        memcached_nfv.client.flush_all()
        memcached_nfv.clean_memcached()


if __name__ == "__main__":
    unittest.main()
