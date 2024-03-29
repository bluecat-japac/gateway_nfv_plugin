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

CONFIG_PATH = '../config'
NFV_CONFIG_PATH = '../config/nfv_config.json'
SNMP_CONFIG_PATH = '../config/snmp_config.json'
VM_CONFIG_PATH = '../config/vm_config.ini'

MAX_SERVER = 20
CAN_SCALE_IN = 'can_scale_in'


class ServerProfile():
    DNS_DHCP_SERVER_60 = 'DNS_DHCP_SERVER_60'
