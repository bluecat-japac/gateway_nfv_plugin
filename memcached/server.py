
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

"""[Server]
"""


class ServerType():
    BDDS = "BDDS"
    BAM = "BAM"
    VM_HOST = "VM_HOST"


class Bdds():
    """
    BDDS
    """
    def __init__(self, id=None, name=None, udf=None, ipv4_address=None, bam_ip=None):
        """[Init]
        """
        self.id = id
        self.name = name
        self.udf = udf
        self.ipv4_address = ipv4_address
        self.bam_ip = bam_ip

    def set_from_bam_data(self, server_bam_data, list_udf_names=[]):
        """[set_from_bam_data]

        Arguments:
            server_bam_data {[type]} -- [description]

        Keyword Arguments:
            udf {dict} -- [description] (default: [])
        """
        self.id = server_bam_data['id']
        self.name = server_bam_data['name']
        properties = server_bam_data['properties'].split('|')
        self.udf = ''
        for udf_name in list_udf_names:
            self.udf = self.udf + "," + "{}:{}".format(udf_name, next((prop.split(
                '=')[1] for prop in properties if prop.split('=')[0] == udf_name), ''))
        # Remove first comma
        self.udf = self.udf[1:]
        self.ipv4_address = [prop.split(
            '=')[1] for prop in properties if prop.split('=')[0] == "defaultInterfaceAddress"][0]

    def set_from_memcache(self, key, value):
        """[set_from_memcache]

        Arguments:
            key {[string]} -- [key get from memcache]
            value {[string]} -- [value get from memcache]
        """
        self.bam_ip = key.split('|')[1]
        self.id = key.split('|')[2]
        self.name = value.split('|')[0]
        self.ipv4_address = value.split('|')[1]
        self.udf = value.split('|')[2]

    def get_memcache_value(self):
        """[Get value bdds which add to memcache]

        Returns:
            [String] -- [value bdds]
        """
        return "{}|{}|{}".format(self.name, self.ipv4_address, self.udf)

    def get_memcache_key(self):
        """[Get key bdds which add to memcache]

        Returns:
            [String] -- [key bdds]
        """
        return "{}|{}|{}".format(ServerType.BDDS, self.bam_ip, self.id)

    def __str__(self):
        """
        :return:
        """
        return "{}|{}|{}|{}|{}".format(
            self.id, self.name, self.bam_ip, self.ipv4_address, self.udf
        )


class Bam():
    """
    BAM
    """
    def __init__(self, id='', name='', ipv4_address=None):
        """
        Init
        """
        self.id = ipv4_address
        self.name = name
        self.ipv4_address = ipv4_address

    def set_from_memcache(self, key, value):
        """[set_from_memcache]

        Arguments:
            key {[string]} -- [key get from memcache]
            value {[string]} -- [value get from memcache]
        """
        self.id = key.split('|')[1]
        self.name = value.split('|')[1]
        self.ipv4_address = value.split('|')[2]

    def get_memcache_value(self):
        """[Get value bam which add to memcache]

        Returns:
            [String] -- [value bam]
        """
        return "{}|{}|{}".format(self.id, self.name, self.ipv4_address)

    def get_memcache_key(self):
        """[Get key bam which add to memcache]

        Returns:
            [String] -- [key bam]
        """
        return "{}|{}".format(ServerType.BAM, self.id)

    def __str__(self):
        """
        :return:
        """
        return "{}|{}|{}".format(
            self.id, self.name, self.ipv4_address
        )


class VMHost():
    """
    VMHost
    """
    def __init__(self, id='', name='', ipv4_address=None):
        """
        :param id:
        :param name:
        :param ipv4_address:
        """
        self.id = ipv4_address
        self.name = name
        self.ipv4_address = ipv4_address

    def set_from_memcache(self, key, value):
        """[set_from_memcache]

        Arguments:
            key {[string]} -- [key get from memcache]
            value {[string]} -- [value get from memcache]
        """
        self.id = key.split('|')[1]
        self.name = value.split('|')[1]
        self.ipv4_address = value.split('|')[2]

    def get_memcache_value(self):
        """[Get value vmhost which add to memcache]
        Returns:
            [String] -- [value vmhost]
        """
        return "{}|{}|{}".format(self.id, self.name, self.ipv4_address)

    def get_memcache_key(self):
        """[Get key vmhost which add to memcache]
        Returns:
            [String] -- [key vmhost]
        """
        return "{}|{}".format(ServerType.VM_HOST, self.id)

    def __str__(self):
        """
        :return:
        """
        return "{}|{}|{}".format(
            self.id, self.name, self.ipv4_address
        )
