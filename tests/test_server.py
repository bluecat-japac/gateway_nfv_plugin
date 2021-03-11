
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
import context
from unittest import mock  # pylint: disable=import-error

from memcached.server import Bdds  # pylint:disable=import-error
from memcached.server import Bam  # pylint:disable=import-error
from memcached.server import VMHost  # pylint:disable=import-error


class TestServer(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """
    @mock.patch.object(Bdds, '__init__', lambda x, y, z, t, m: None)  # mock init
    def test_set_from_bam_data(self):
        """
        :param:
        :return:
        """
        call_class = Bdds("1", "2", "3", "4")
        server_bam_data = {
            "id": "123",
            "name": "bdds169",
            "properties": "ups_ip_address=192.168.88.1,192.168.88.2|ups_snmp_configuration={'snmp_config': {'v1': {'status': 'enable', 'community_string': 'qqqq'}}, 'trap_oid': {'lowBattery': '1.3.6.1.4.1.318.0.7'}}|defaultInterfaceAddress=192.168.88.169|servicesIPv4Address=192.168.89.169|servicesIPv6Address=FDAC:1400:1::20|fullHostName=bdds169|profile=DNS_DHCP_INTEGRITY_BRANCH|"
        }
        call_class.set_from_bam_data(server_bam_data)

    @mock.patch.object(Bdds, '__init__', lambda x, y, z, t, m: None)  # mock init
    def test_set_from_memcache(self):
        """
        :param:
        :return:
        """
        call_class = Bdds("1", "2", "3", "4")
        key = "key|bam_ip|bam_id"
        value = "name|192.168.88.54|udf"
        call_class.set_from_memcache(key, value)

    def test_bdds_get_memcache_value(self):
        """
        :param:
        :return:
        """
        id = 1111  # pylint:disable=invalid-name
        name = "BDDS1"
        udf = "aaa"
        ipv4_address = "192.1.1.1"
        bam_ip = "192.2.2.2"
        bdds = Bdds(id, name, udf, ipv4_address, bam_ip)
        actual = bdds.get_memcache_value()
        expected = "{}|{}|{}".format(name, ipv4_address, udf)
        self.assertEqual(expected, actual)

    @mock.patch('memcached.server.ServerType')
    def test_bdds_get_memcache_key(self, mock_type_bdds):
        """
        :param:
        :return:
        """
        id = 1111  # pylint:disable=invalid-name
        name = "BDDS1"
        udf = "aaa"
        ipv4_address = "192.1.1.1"
        bam_ip = "192.2.2.2"
        BDDS = "BDDS"    # pylint:disable=invalid-name
        mock_type_bdds.BDDS = BDDS
        bdds = Bdds(id, name, udf, ipv4_address, bam_ip)
        actual = bdds.get_memcache_key()
        expected = "{}|{}|{}".format(BDDS, bam_ip, id)
        self.assertEqual(expected, actual)

    def test__str__(self):
        id = 1111  # pylint:disable=invalid-name
        name = "BDDS1"
        udf = "aaa"
        ipv4_address = "192.1.1.1"
        bam_ip = "192.2.2.2"
        bdds = Bdds(id, name, udf, ipv4_address, bam_ip)
        expected = "{}|{}|{}|{}|{}".format(
            id, name, bam_ip, ipv4_address, udf
        )
        self.assertEqual(expected, str(bdds))

    def test_set_from_memcache_bam_not_mock_init(self):
        """
        :param:
        :return:
        """
        id = 1111  # pylint:disable=invalid-name
        name = "BAM54"
        ipv4_address = "192.1.1.1"
        key = "key|bam_ip|bam_id"
        value = "name|192.168.88.54|udf"
        bam = Bam(id, name, ipv4_address)
        bam.set_from_memcache(key, value)

    def test_get_memcache_value_bam(self):
        """
        :param:
        :return:
        """
        name = "BAM54"
        ipv4_address = "192.1.1.1"
        id = ipv4_address  # pylint:disable=invalid-name
        bam = Bam(id, name, ipv4_address)
        actual = bam.get_memcache_value()
        expected = "{}|{}|{}".format(id, name, ipv4_address)
        self.assertEqual(expected, actual)

    @mock.patch('memcached.server.ServerType')
    def test_get_memcache_key_bam(self, mock_type_bam):
        """
        :param:
        :return:
        """
        name = "BAM54"
        ipv4_address = "192.1.1.1"
        id = ipv4_address  # pylint:disable=invalid-name
        BAM = "BAM"  # pylint:disable=invalid-name
        mock_type_bam.BAM = BAM
        bam = Bam(id, name, ipv4_address)
        actual = bam.get_memcache_key()
        expected = "{}|{}".format(BAM, id)
        self.assertEqual(expected, actual)

    def test__str___bam(self):
        name = "BAM54"
        ipv4_address = "192.1.1.1"
        id = ipv4_address   # pylint:disable=invalid-name
        bam = Bam(id, name, ipv4_address)
        expected = "{}|{}|{}".format(id, name, ipv4_address)
        self.assertEqual(expected, str(bam))

    def test_set_from_memcache_vmhost(self):
        """
        :param:
        :return:
        """
        name = "VMHost"
        ipv4_address = "192.1.1.1"
        id = ipv4_address  # pylint:disable=invalid-name
        key = "key|bam_ip|bam_id"
        value = "name|127.0.0.1|udf"
        vmhost = VMHost(id, name, ipv4_address)
        vmhost.set_from_memcache(key, value)

    def test_get_memcache_value_vmhost(self):
        """
        :param:
        :return:
        """
        name = "VMHost"
        ipv4_address = "192.1.1.1"
        id = ipv4_address  # pylint:disable=invalid-name
        vmhost = VMHost(id, name, ipv4_address)
        actual = vmhost.get_memcache_value()
        expected = "{}|{}|{}".format(id, name, ipv4_address)
        self.assertEqual(expected, actual)

    def test__str___vmhost(self):
        name = "VMHost"
        ipv4_address = "192.1.1.1"
        id = ipv4_address  # pylint:disable=invalid-name
        vmhost = VMHost(id, name, ipv4_address)
        expected = "{}|{}|{}".format(id, name, ipv4_address)
        self.assertEqual(expected, str(vmhost))


if __name__ == "__main__":
    # pylint:disable=import-error
    unittest.main()
