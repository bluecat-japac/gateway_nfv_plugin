
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

# Lib
import logging
import traceback
from pymemcache.client import base  # pylint:disable=import-error

# Internal
from memcached.server import (ServerType, Bam, Bdds, VMHost)  # pylint:disable=import-error


class MemcachedNFV():
    """
    Memcached NFV
    """

    def __init__(self, host, port):
        """[Init MemcachedNFV]
        Arguments:
            host {[string]} -- [dns or ip of memache server]
            port {[int]} -- [port of memache server]
        """
        try:
            self.host = host
            self.port = port
            self.client = self._get_connection()
        except Exception as exception:
            logging.error("MemcachedNFV-Init-{}".format(exception))
            logging.error(traceback.format_exc())
            self.client.close()

    def _get_connection(self):
        """[Get connection]
        """
        try:
            connection = base.Client((self.host, self.port), connect_timeout=5)
        except Exception:
            raise Exception("Cannot connect to memcached")
        return connection

    def disconnect(self):
        """
        Disconnect
        """
        self.client.close()

    def set_server(self, server, server_type, bam_ip=None, list_udf_names=[]):
        """[Set server to memcache]
        Arguments:
            server {[dict]} -- [server include:
                - bdds: id, name, type, properties
                - bam: id, name, ipv4_address]
            server_type {string} -- [BDDS or BAM] 
            bam_ip {string} -- [bam ipv4] (default: None)
            udf {dict} -- [description] (default: [])
        """
        logging.debug("MemcachedNFV-Set_server-Server infor: {}-ServerType: {}-Bam_ip: {} ".format(
            str(server), server_type, bam_ip))

        try:
            if server_type == ServerType.BDDS:
                bdds = Bdds(bam_ip=bam_ip)
                bdds.set_from_bam_data(server, list_udf_names)
                key = bdds.get_memcache_key()
                value = bdds.get_memcache_value()
            elif server_type == ServerType.BAM:
                bam = Bam(name=server['name'], ipv4_address=server['ipv4_address'])
                key = bam.get_memcache_key()
                value = bam.get_memcache_value()
            else:
                vm_host = VMHost(name=server['name'], ipv4_address=server['ipv4_address'])
                key = vm_host.get_memcache_key()
                value = vm_host.get_memcache_value()

            # Update to list server key
            self.update_list_server_key(server_type, key)
            self.client.set(key, value)
            logging.info("Added {} to memcache".format(key))
        except Exception as exception:
            logging.error("MemcachedNFV-Set_server-{}".format(exception))
            logging.error(traceback.format_exc())
            self.client.close()

    def get_server(self, server_id, server_type, bam_ip=None):
        """[Get server by key = "server_type|server_id"]
        Arguments:
            server_id {[string]} -- [id of server]
            server_type {[string]} -- [ServerType]
        """
        if server_type == ServerType.BDDS:
            key = "{}|{}|{}".format(server_type, bam_ip, server_id)
        else:
            key = "{}|{}".format(server_type, server_id)
        try:
            server = self.client.get(key)
            if server:
                return server.decode()
            return None
        except Exception as exception:
            logging.error("MemcachedNFV-Get_server-{}".format(exception))
            logging.error(traceback.format_exc())
            self.client.close()

    def set_network(self, key, value, expire=0):
        """[Set network to memcache]
        Arguments:
            network_config {[dict]} -- [server include:
                - bdds: id, name, type, properties
                - bam: id, name, ipv4_address]
        """
        logging.debug("MemcachedNFV-Set_network-Network infor: {}: {}".format(key, value))
        try:
            self.client.set(key=key, value=value, expire=expire)
            logging.info("Added {} to memcache".format(key))
        except Exception as exception:
            logging.error("MemcachedNFV-Set_Network-{}".format(exception))
            logging.error(traceback.format_exc())
            self.client.close()

    def get_network(self, network_id):
        """[Get server by key = "server_type|server_id"]
        Arguments:
            server_id {[string]} -- [id of server]
            server_type {[string]} -- [ServerType]
        """
        try:
            addresses = self.client.get(network_id)
            if addresses:
                str_address = addresses.decode('ascii')
                return str_address.split(",")
            return []
        except Exception as exception:
            logging.error("MemcachedNFV-Get_server-{}".format(exception))
            logging.error(traceback.format_exc())
            return []

    def clean_network(self, network_id):
        try:
            return self.client.delete(network_id)
        except Exception as exception:
            logging.error("MemcachedNFV-Get_server-{}".format(exception))
            logging.error(traceback.format_exc())

    def update_list_server_key(self, server_type, server_key, is_delete=False):
        """[Update list server key by Server Type]
        
        Arguments:
            server_type {[string]} -- [Server Type: BDDS, BAM, VM_HOST]
            server_key {[String]} -- [Server key: BDDS|192.168.88.238|101554]
        """
        list_server_key = []
        mem_list_server_key = self.client.get(server_type)
        if mem_list_server_key:
            list_server_key = mem_list_server_key.decode().split(',')

        if is_delete and server_key in list_server_key:
            # remove key if exist in memcached
            list_server_key.remove(server_key)
        elif not is_delete and server_key not in list_server_key:
            # Add new key if not exist in memcached
            list_server_key.append(server_key)

        str_list_server_key = ",".join(list_server_key)
        self.client.set(server_type, str_list_server_key)

    def get_list_server_keys(self):
        """[Get list server keys in memcache]
            Get all server key in all server_type(BDDS, BAM, VM_HOST)
        Returns:
            [list] -- [list keys server in memcache]
        """
        list_keys = []
        list_sever_type = [ServerType.BDDS, ServerType.BAM, ServerType.VM_HOST]
        # Get keys from ServerType
        for type in list_sever_type:
            str_keys_by_type = self.client.get(type)
            if str_keys_by_type:
                list_keys += str_keys_by_type.decode().split(",")
        return list_keys

    def get_list_servers(self):
        """[summary]

        Returns:
            [dict] -- [description]
        """

        keys = self.get_list_server_keys()
        list_bdds = []
        list_bams = []
        list_vmhosts = []
        for key in keys:
            if key.split('|')[0] == ServerType.BDDS:
                bdds = Bdds()
                bdds.set_from_memcache(
                    key, self.client.get(key).decode())
                list_bdds.append(bdds)
            elif key.split('|')[0] == ServerType.BAM:
                bam = Bam()
                bam.set_from_memcache(
                    key, self.client.get(key).decode())
                list_bams.append(bam)
            elif key.split('|')[0] == ServerType.VM_HOST:
                vm_host = VMHost()
                vm_host.set_from_memcache(
                    key, self.client.get(key).decode())
                list_vmhosts.append(vm_host)
        return list_bdds, list_bams, list_vmhosts

    def delete_server(self, server_id, server_type, bam_ip=None):
        """[Delete server by key = "server_type|server_id"]

        Arguments:
            server_id {[string]} -- [id of server]
            server_type {[string]} -- [ServerType]
        """
        if server_type == ServerType.BDDS:
            key = "{}|{}|{}".format(server_type, bam_ip, server_id)
        else:
            key = "{}|{}".format(server_type, server_id)
        try:
            self.client.delete(key)
            self.update_list_server_key(server_type, key, is_delete=True)
            logging.info("Deleted {} in memcache".format(key))
        except Exception as exception:
            logging.error("MemcachedNFV-Delete_server-{}".format(exception))
            logging.error(traceback.format_exc())
            self.client.close()

    def clean_memcached(self):
        """[Clean memcached]
        Raises:
            Exception -- [Cannot clean memcached]
        """

        try:
            self.client.flush_all()
        except Exception:
            raise Exception("Cannot clean memcached")
