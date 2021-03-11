
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

import os
import re
import socket
import struct
import sys
import time
import traceback

import paramiko  # pylint:disable=import-error
import ipaddress
import urllib
from urllib.error import URLError

from flask import g, jsonify  # pylint:disable=import-error
from paramiko.ssh_exception import NoValidConnectionsError  # pylint:disable=ungrouped-imports
from suds import WebFault  # pylint:disable=import-error
from bluecat import entity  # pylint:disable=import-error
from bluecat.api_exception import BAMException  # pylint:disable=import-error
from bluecat.api_exception import PortalException  # pylint:disable=import-error
from bluecat.util import safe_str, parse_properties  # pylint:disable=import-error
from bluecat.util.util import get_configurations  # pylint:disable=import-error
from bluecat.util.util import run_ssh_cmd  # pylint:disable=import-error
from main_app import app  # pylint:disable=import-error

from common.logger import Logger  # pylint:disable=no-name-in-module,import-error
from memcached.memcached_nfv import MemcachedNFV  # pylint:disable=import-error
from memcached.server import ServerType  # pylint:disable=import-error
from common.common import read_config_json_file  # pylint:disable=import-error, no-name-in-module, ungrouped-imports
from common.constants import NFV_CONFIG_PATH  # pylint:disable=import-error, no-name-in-module
from common import process_password  # pylint:disable=import-error, no-name-in-module

sys.path.append(os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../..')))

base_dir = os.path.dirname(os.path.abspath(__file__))
logger = Logger('gateway-nfv-management', base_dir)

# Const variable
MAX_SERVER = 20


def get_configuration_id(configuration_name):
    """
    :param configuration_name: configuration name
    :return: configuration_id
    """
    configuration_list = get_configurations()
    for config in configuration_list:
        g.user.logger.debug("BAM config: {}".format(config))
        if config[1] == configuration_name:
            g.user.logger.debug("Config name: {}".format(configuration_name))
            configuration_id = config[0]
            g.user.logger.debug("Config ID: {}".format(configuration_id))
            break
    if not configuration_id:
        g.user.logger.debug("Can not find Config ID. Please check bam_config_name name in nfv_config file.")
        return None
    return configuration_id


def scale_out(data):
    """
    :param data: request in json
    for example:
    {
    "server_name": "bdd240s",
    "mgnt_server_ip": "192.168.88.240",
    "service_server_ipv4": "192.168.89.240",
    "service_server_ipv6": fdac::12,
    "service_server_netmask": 24,
    "service_server_v6_prefix": 64,
    "metadata": "can_scale_in=True"
    }
    :return: successful message
    """
    try:
        g.user.logger.debug("Scale out request data: {}".format(data))
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        g.user.logger.debug("NFV config data: {}".format(data_config))
        config_name = data_config['bam_config_name']
        config_id = get_configuration_id(config_name)
        if not config_id:
            return jsonify({"status": "Failed", "message": "Configuration id not found!"}), 404

        g.user.logger.info('Starting check available server')
        server_ip = data['mgnt_server_ip']
        server_ipv6 = None
        avail_server = is_check_available_server(server_ip, data_config['server_ssh_username'],
                                                 data_config['server_ssh_password'])
        if not avail_server:
            return jsonify({"status": "Failed", "message": "No available server ip!"}), 404

        g.user.logger.info('Starting add server')
        server_properties = f"password={process_password.decrypt_password(data_config['server_deployment_password'])}|connected=true|upgrade=False"
        try:
            if data['metadata']:
                server_properties = f"{server_properties}|{data['metadata']}"
        except KeyError as exception:
            g.user.logger.error(str(exception))
            g.user.logger.error(traceback.format_exc())

        try:
            if (int(data['service_server_netmask']) <= 32) and (int(data['service_server_netmask']) > 0) and data[
                'service_server_ipv4']:
                server_properties = f"{server_properties}|servicesIPv4Address={data['service_server_ipv4']}|servicesIPv4Netmask={cidr_to_netmask(data['service_server_netmask'])}"
        except KeyError as exception:
            g.user.logger.error(str(exception))
            g.user.logger.error(traceback.format_exc())

        try:
            if data['service_server_v6_prefix'] and data['service_server_ipv6']:
                server_ipv6 = data['service_server_ipv6'] + \
                              '/' + data['service_server_v6_prefix']
                server_properties = f"{server_properties}|servicesIPv6Address={data['service_server_ipv6']}|servicesIPv6Subnet={data['service_server_v6_prefix']}"
        except KeyError as exception:
            g.user.logger.error(str(exception))
            g.user.logger.error(traceback.format_exc())

        if data_config['server_cap_profile']:
            g.user.logger.debug(
                f"Add server name {data['server_name']} server_ip {server_ip} profile {data_config['server_cap_profile']} properties {server_properties}")
            server_id = add_server(server_ip=server_ip, server_name=data['server_name'], config_id=config_id,
                                   profile=data_config['server_cap_profile'], properties=server_properties)
        else:
            g.user.logger.debug(
                f"Add server name {data['server_name']} server_ip {server_ip} properties {server_properties}")
            server_id = add_server(server_ip=server_ip, server_name=data['server_name'], config_id=config_id,
                                   properties=server_properties)

        g.user.logger.info('Starting create deployment roles')
        deploy_role = False
        if data_config['dns_view_names']:
            role_type = data.get("deploy_role", data_config['server_deploy_role'])
            for view_name in data_config['dns_view_names']:
                g.user.logger.debug(
                    f"Create deployment role for server {data['server_name']} view_name {view_name} role_type {role_type}")
                role_id = create_deployment_roles(server_name=data['server_name'], server_id=server_id,
                                                  config_id=config_id,
                                                  view_name=view_name, role_type=role_type)
                if not role_id:
                    g.user.logger.info(
                        'Cannot create deployment role for view name: %s' % view_name)
                    continue
                deploy_role = True
        else:
            g.user.logger.info('dns_view_names not found!')
        if not deploy_role:
            g.user.logger.info('Cannot create any deployment roles!')
            return jsonify({"status": "Failed", "message": "Create deployment role failed"}), 500

        g.user.logger.info('Starting add raw option')
        g.user.logger.info(
            'Starting deploy DNS configuration for server name: %s' % data['server_name'])
        deploy_server = deploy_server_config(server_id)
        if not deploy_server:
            g.user.logger.info('Deploy DNS configuration is failed!')

        g.user.logger.info(
            'Starting wait for DNS deployment for server name: %s' % data['server_name'])
        deploy_status = wait_for_deployment(server_id)
        g.user.logger.info(
            'Deployment status for server name %s, deploy status id %s' % (data['server_name'], deploy_status))

        if 'anycast_config' in data_config:
            g.user.logger.info('Starting configure any cast')
            configure_anycast(server_ip, server_ipv6, data_config['server_ssh_username'],
                              data_config['server_ssh_password'],
                              data_config['anycast_config'])

        g.user.logger.info('Adding server to cache list')
        # Add BDDS to memcached
        bam_ip = data_config['bam'][0]['ip']
        memcached_host = data_config['memcached_host']
        memcached_port = int(data_config['memcached_port'])
        mem_nfv = MemcachedNFV(memcached_host, memcached_port)
        list_udf_name = [value.split('=')[0].strip()
                         for value in data['metadata'].split('|')]
        mem_nfv.set_server(
            {'id': server_id, 'name': data['server_name'], 'type': ServerType.BDDS,
             'properties': f"defaultInterfaceAddress={server_ip}|{server_properties}"},
            ServerType.BDDS, bam_ip, list_udf_name)
        g.user.logger.info(
            f"SUCCESS: Add server to memcached with info 'id': {server_id}, 'name': {data['server_name']}, 'type': {ServerType.BDDS}, 'bam_ip': {bam_ip}")
        g.user.logger.debug(f"'properties': {server_properties}")

        # Remove used candidate address on memcache
        mem_nfv.clean_network(data["mgnt_server_ip"])
        mem_nfv.clean_network(data["service_server_ipv4"])
        mem_nfv.clean_network(data["service_server_ipv6"])

        # Add addresses to used list on memcache
        used_ipv4_memcache = mem_nfv.get_network("used_ipv4")
        used_ipv6_memcache = mem_nfv.get_network("used_ipv6")
        used_ipv4_memcache.append(data["mgnt_server_ip"])
        if data["service_server_ipv4"]:
            used_ipv4_memcache.append(data["service_server_ipv4"])
        if data["service_server_ipv6"]:
            used_ipv6_memcache.append(data["service_server_ipv6"])
            ipv6_str = ",".join(used_ipv6_memcache)
            mem_nfv.set_network("used_ipv6", ipv6_str)
        ipv4_str = ",".join(used_ipv4_memcache)
        mem_nfv.set_network("used_ipv4", ipv4_str)

    except Exception as exception:
        g.user.logger.error(str(exception))
        g.user.logger.error(
            f"Failed: Haven't add server to mem cached {exception}")
        g.user.logger.error(traceback.format_exc())
        return jsonify({"status": "Failed", "message": "Scale out failed", "error": str(exception)}), 500
    return jsonify({"status": "Successful", "message": "Scale out successfully", "error": ""}), 200


def scale_in(data):
    """
    :param data: request in json
    example
    {
        "server_name": "bdd240s"
    }
    :return: successful message
    """
    try:
        g.user.logger.debug("Scale out request data: {}".format(data))
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        g.user.logger.debug("NFV config data: {}".format(data_config))
        config_name = data_config['bam_config_name']
        config_id = get_configuration_id(config_name)
        if not config_id:
            return jsonify({"message": "Configuration id not found!"}), 404

        server_name = data['server_name']
        server = get_server_by_name(config_id, server_name)
        server_id = server['id']
        if server_id == 0:
            return jsonify({"status": "Failed", "message": "Scale in failed",
                            "error": str('Server {} not found!'.format(server_name))}), 403
        if server['properties'].split('|')[0].split('=')[0] == "defaultInterfaceAddress":
            server_ip = server['properties'].split('|')[0].split('=')[1]
        else:
            server_ip = server['properties'].split('|')[1].split('=')[1]
        # delete server roles
        g.user.logger.info(
            'Starting remove server roles for server name: %s' % server_name)
        remove_roles = delete_server_roles(server_id)
        if not remove_roles:
            g.user.logger.info(
                'Remove server roles failed! Starting stop anycast service ...')

        if 'anycast_config' in data_config:
            stop_anycast_service(
                server_ip, data_config['server_ssh_username'], data_config['server_ssh_password'])

        # deploy DNS server
        g.user.logger.info(
            'Starting deploy DNS server for server name: %s' % server_name)
        deploy_server = deploy_server_config(server_id)
        if not deploy_server:
            g.user.logger.info('Deploy DNS server is failed!')

        # wait for deployment
        g.user.logger.info(
            'Starting wait for DNS deployment for server name: %s' % server_name)
        deploy_status = wait_for_deployment(server_id)
        g.user.logger.info('Deployment status for server name %s, deploy status id %s' % (
            server_name, deploy_status))
        g.user.logger.info('Anycast service stopped')

        # delete server from BAM
        g.user.logger.info('Deleting server %s from BAM' % server_name)
        delete_server = delete_entity(server_id)
        if not delete_server:
            g.user.logger.info('Delete server %s failed' % server_name)

        g.user.logger.info('Deleting server from cache list')

        bam_ip = data_config['bam'][0]['ip']
        memcached_host = data_config['memcached_host']
        memcached_port = int(data_config['memcached_port'])
        mem_nfv = MemcachedNFV(memcached_host, memcached_port)
        mem_nfv.delete_server(server_id, ServerType.BDDS, bam_ip)
        g.user.logger.info(
            f"SUCCESS: Delete server from memcached with info 'id': {server_id}")

    except Exception as exception:
        g.user.logger.error(str(exception))
        g.user.logger.error(f"Failed: Can't delete server from memcached")
        g.user.logger.error(traceback.format_exc())
        return jsonify({"status": "Failed", "message": "Scale in failed", "error": str(exception)}), 500
    return jsonify({"status": "Successful", "message": "Scale in successfully", "error": ""}), 200


def stop_anycast_service(server_ip, username, pwd):
    """
    Stop Anycast service
    """
    password = process_password.decrypt_password(pwd)
    command = '/usr/local/bluecat/PsmClient node set anycast-enable=0'
    output, error = run_ssh_cmd(server_ip, username, password, command)
    if b'retcode=ok' in output:
        g.user.logger.debug('BDDS %s successfully executed %s.' %
                            (server_ip, command))
    else:
        g.user.logger.error('BDDS %s failed to execute %s:\n%s' %
                            (server_ip, command, output + error))
        g.user.logger.error(traceback.format_exc())


def get_server_by_name(config_id, server_name):
    """
    Get server by name
    :param config_id: id of configuration
    :param server_name: name of server
    :return:
    """
    try:
        server = g.user.get_api()._api_client.service.getEntityByName(
            config_id, server_name, entity.Entity.Server)
        g.user.logger.debug("Server: {}".format(server))
    except WebFault as exception:
        raise BAMException(safe_str(exception))
    return server


def delete_server_roles(server_id):
    """
    Delete server roles
    :param server_id: id of server
    :return:
    """
    roles = get_server_roles(server_id)
    for role in roles:
        if not delete_entity(role):
            return False
    return True


def get_server_roles(server_id):
    """
    Get server roles
    :param server_id: id of server
    :return:
    """
    try:
        roles = g.user.get_api()._api_client.service.getServerDeploymentRoles(server_id)
    except WebFault as exception:
        g.user.logger.warning(safe_str(exception))
        return []
    roles_id = [role['id'] for role in roles]
    return roles_id


def delete_entity(entity_id):
    """
    Delete entity
    :param entity_id: Id of entity
    :return:
    """
    try:
        g.user.get_api()._api_client.service.delete(entity_id)
        return True
    except WebFault as exception:
        g.user.logger.error(safe_str(exception))
        g.user.logger.error(traceback.format_exc())
        return False


def is_check_available_server(server_ip, username, password):
    """
    Check server available
    :param server_ip: IP address of server
    :param username: user name
    :param password: password
    :return:
    [True]- boolean
    [False]- boolean
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pwd_decrypt = process_password.decrypt_password(password)
        ssh.connect(server_ip, username=username,
                    password=pwd_decrypt, timeout=10)
        ssh.close()
        return True
    except (OSError, NoValidConnectionsError) as exception:
        g.user.logger.info('Not available for server IP : %s' % server_ip)
        return False


def add_server(server_ip, server_name, config_id, profile='DNS_DHCP_SERVER_60',
               properties='password=bluecat|connected=true|upgrade=False'):
    """
    Add server
    :param server_ip: server ip
    :param server_name: server name
    :param config_id: configuration id
    :param profile: ADONIS_1200, ADONIS_XMB3
    :param properties: contain password, servicesIPv4Address...
    :return: server_id
    """
    try:
        properties = parse_properties(properties)
        server_id = g.user.get_api()._api_client.service.addServer(config_id, server_name, server_ip,
                                                                   server_name.replace("_", ""),
                                                                   profile, properties)
        start = time.time()
        max_timeout = 30
        while time.time() - start < max_timeout:
            try:
                g.user.logger.debug(
                    f"Check time out add server {server_name} server_ip {server_ip}")
                return g.user.get_api().get_entity_by_id(server_id).get_id()
            except PortalException as exception:
                if 'No such entity exists.:%d' % server_id in exception.get_message():
                    pass
                else:
                    raise exception
    except WebFault as exception:
        raise BAMException(safe_str(exception))


def create_deployment_roles(server_name, server_id, config_id, view_name, role_type, properties=''):
    """
    Create deployment roles
    :param server_name: server name
    :param server_id: server id
    :param config_id: configuration id
    :param view_name: view name
    :param role_type: SLAVE_STEALTH, RECURSION
    :param properties: user-defined fields
    :return: role_id
    """
    try:
        g.user.logger.debug(
            f"Get view of creating deployment roles {server_name} config_id {config_id} view_name {view_name}")
        configuration = g.user.get_api().get_entity_by_id(config_id)
        view = configuration.get_view(view_name)
    except PortalException as exception:
        g.user.logger.warning(
            '%s' % exception, msg_type=g.user.logger.EXCEPTION)
        return False

    try:
        if not server_id:
            server_obj = g.user.get_api()._api_client.service.getEntityByName(config_id, server_name,
                                                                              entity.Entity.Server)
            server_id = server_obj['id']

        properties = parse_properties(properties)
        g.user.logger.debug(
            f"Get server interface of creating deployment roles {server_name} server_id {server_id}")
        server_nsf = g.user.get_api()._api_client.service.getEntityByName(server_id, server_name,
                                                                          entity.Entity.NetworkServerInterface)

        role_id = g.user.get_api()._api_client.service.addDNSDeploymentRole(view.get_id(), server_nsf['id'],
                                                                            role_type, properties)
        if role_id:
            g.user.logger.debug("Role ID: {}".format(role_id))
            return role_id
        else:
            g.user.logger.error('Role creation for %s and server %s was unsuccessful!' % (
                view_name, server_name))
            g.user.logger.error(traceback.format_exc())
            return False
    except WebFault as exception:
        g.user.logger.error(safe_str(exception))
        g.user.logger.error(traceback.format_exc())
        return False


def get_list_servers(configuration_id):
    """[Get list server in bam with this configure]
    Returns:
        [list] -- [list of servers entity object]
    """
    list_servers = g.user.get_api()._api_client.service.getEntities(
        configuration_id, entity.Entity.Server, 0, MAX_SERVER)

    return list_servers


def get_memcached_config():
    """[Get memcached config from nfv_config.json]
    Raises:
        Exception -- [Can not get config memcached from nfv_config.json]
    Returns:
        [String] -- [memcached_host]
        [Int] -- [memcached_host]
    """

    data_config = read_config_json_file(NFV_CONFIG_PATH)
    try:
        memcached_host = data_config["memcached_host"]
        memcached_port = data_config["memcached_port"]
    except KeyError:
        raise KeyError(
            "Can not get config memcached from nfv_config.json")
    return memcached_host, int(memcached_port)


def deploy_server_config(server_id):
    """
    Deploy server
    :param server_id: server id
    :return: True
    """
    try:
        g.user.get_api()._api_client.service.deployServerConfig(
            server_id, 'services=DNS|forceDNSFullDeployment=False')
        return True
    except WebFault as exception:
        g.user.logger.error(safe_str(exception))
        g.user.logger.error(traceback.format_exc())
        return False


def wait_for_deployment(server_id):
    """
    # DEPLOYMENT STATUS PARAMS
    EXECUTING = -1
    INITIALIZING = 0
    QUEUED = 1
    CANCELLED = 2
    FAILED = 3
    NOT_DEPLOYED = 4
    WARNING = 5
    INVALID = 6
    DONE = 7
    NO_RECENT_DEPLOYMENT = 8
    CANCELLING = 9

    :param server_id: server id
    :return: status id
    """
    try:
        status = g.user.get_api()._api_client.service.getServerDeploymentStatus(server_id)
    except WebFault as exception:
        g.user.logger.error(safe_str(exception))
        g.user.logger.error(traceback.format_exc())
        return False
    counter = 1
    while status not in [2, 3, 4, 5, 6, 7, 8]:
        time.sleep(2)
        counter += 1
        if counter > 5:
            break
        try:
            status = g.user.get_api()._api_client.service.getServerDeploymentStatus(server_id)
        except WebFault as exception:
            g.user.logger.error(safe_str(exception))
            g.user.logger.error(traceback.format_exc())
            return False
    return status


def configure_anycast(server_ip, server_ipv6, username, pwd, anycast_config):
    """
    Config anycast
    :param server_ip: server ip
    :param username: username
    :param password: password
    :param anycast_config: configuration of anycast
    :return:
    """
    # Add SNMP enable here
    password = process_password.decrypt_password(pwd)
    cmd = 'node set snmp-enable=1'
    run_psmclient_cmd(server_ip, username, password, cmd)

    # Add anycast settings here
    if anycast_config['anycast_protocol'] == 'ospfd':
        if server_ipv6:
            psm_overrides = set()
            cmd = 'node get manual-override'
            output = run_psmclient_cmd(server_ip, username, password, cmd)
            m = re.match(r'manual-override=(.*)', output.decode('utf-8'))
            if m:
                psm_overrides = set(m.group(1).split(','))
                # Disable manual-override for anycast, so that config files are generated
                if 'anycast' in psm_overrides:
                    psm_overrides.remove('anycast')
                    cmd = 'node set manual-override=' + ','.join(psm_overrides)
                    run_psmclient_cmd(server_ip, username, password, cmd)

            list_ipv4 = ','.join(anycast_config['anycast_ipv4'])
            list_ipv6 = ','.join(anycast_config['anycast_ipv6'])
            cmd = 'anycast set anycast-ipv4=' + list_ipv4 + ' anycast-ipv6=' + list_ipv6 + \
                  ' service-ipv6=' + server_ipv6 + ' component=common vtysh-enable=1'
            g.user.logger.debug(f'Setting anycast : {cmd}')
            run_psmclient_cmd(server_ip, username, password, cmd)

            cmd = f"anycast set area={anycast_config['ospf_area']} authenticate={anycast_config['ospf_authenticate']}\
            component=ospfd dead-interval={anycast_config['ospf_dead_interval']} enabled=1 \
            hello-interval={anycast_config['ospf_hello_interval']} password={process_password.decrypt_password(anycast_config['ospf_password'])} \
            stub={anycast_config['ospf_stub']}"

            g.user.logger.debug(f'Setting OSPF : {cmd}')
            run_psmclient_cmd(server_ip, username, password, cmd)

            # Temporarily enable anycast to write zebra and ospfv2 configuration files
            cmd = 'node set anycast-enable=1'
            run_psmclient_cmd(server_ip, username, password, cmd)
            cmd = 'node set anycast-enable=0'
            run_psmclient_cmd(server_ip, username, password, cmd)

            # Enable manual-override before adding OSPFv3
            psm_overrides.add('anycast')
            cmd = 'node set manual-override=' + ','.join(psm_overrides)
            run_psmclient_cmd(server_ip, username, password, cmd)

            cmd = f"""
            echo '! -- ospf6d.conf generated by Gateway NFV plug-in
            debug ospf6 lsa unknown
            !
            interface eth0
             ipv6 ospf6 hello-interval {anycast_config['ospfv3_hello_interval']}
             ipv6 ospf6 dead-interval {anycast_config['ospfv3_dead_interval']}
             ipv6 ospf6 network broadcast
            !
            router ospf6
             router-id {server_ip}
             area {anycast_config['ospfv3_area']} range {anycast_config['ospfv3_range']}
             interface eth0 area {anycast_config['ospfv3_area']}
            !
            line vty
            ' > /etc/quagga/ospf6d.conf
            chown quagga:quagga /etc/quagga/ospf6d.conf
            chmod 644 /etc/quagga/ospf6d.conf
            echo '# etc/quagga/daemons generated by Gateway NFV plug-in
            # in practice, ospf6d setting is ignored by PSM
            zebra=yes
            ripd=no
            ospfd=yes
            bgpd=no
            ospf6d=yes
            isisd=no
            ripngd=no
            ' > /etc/quagga/daemons
            mkdir -p /etc/systemd/system/zebra.service.wants/
            ln -sf /lib/systemd/system/ospf6d.service /etc/systemd/system/zebra.service.wants/
            """
            output, error = run_ssh_cmd(server_ip, username, password, cmd)
            g.user.logger.debug('BDDS %s executed command output: %s' %
                                (server_ip, output + error))

        else:
            list_ipv4 = ','.join(anycast_config['anycast_ipv4'])
            cmd = 'anycast set anycast-ipv4=' + list_ipv4 + ' component=common vtysh-enable=1'
            g.user.logger.debug(f'Setting anycast : {cmd}')
            run_psmclient_cmd(server_ip, username, password, cmd)

            cmd = f"anycast set area={anycast_config['ospf_area']} authenticate={anycast_config['ospf_authenticate']}\
            component=ospfd dead-interval={anycast_config['ospf_dead_interval']} enabled=1 \
            hello-interval={anycast_config['ospf_hello_interval']} password={process_password.decrypt_password(anycast_config['ospf_password'])} \
            stub={anycast_config['ospf_stub']}"

            g.user.logger.debug(f'Setting OSPF : {cmd}')
            run_psmclient_cmd(server_ip, username, password, cmd)

    elif anycast_config['anycast_protocol'] == 'bgp':
        list_ipv4 = ','.join(anycast_config['anycast_ipv4'])
        list_ipv6 = ','.join(anycast_config['anycast_ipv6'])
        cmd = 'anycast set anycast-ipv4=' + list_ipv4 + ' anycast-ipv6=' + \
              list_ipv6 + ' component=common vtysh-enable=1'
        g.user.logger.debug(f'Setting anycast : {cmd}')
        run_psmclient_cmd(server_ip, username, password, cmd)

        if anycast_config['prefix_lists']:
            prefix_lists = []
            for item in anycast_config['prefix_lists']:
                if item['type'] not in prefix_lists:
                    prefix_lists.append(item['type'])
            prefix_lists = ','.join(prefix_lists)
            cmd = f"anycast set asn={anycast_config['bgp_local_asn']} authenticate={anycast_config['bgp_command_line_interface']} \
            password={process_password.decrypt_password(anycast_config['bgp_telnet_password'])} keepalive={anycast_config['bgp_keepalive_time']} \
            holdtime={anycast_config['bgp_hold_time']} neighbors-ipv4={anycast_config['bgp_ipv4_address']} component=bgpd \
            enabled=1 prefix-lists={prefix_lists} neighbors-ipv6={anycast_config['bgp_ipv6_address']}"
        else:
            cmd = f"anycast set asn={anycast_config['bgp_local_asn']} authenticate={anycast_config['bgp_command_line_interface']} \
            password={process_password.decrypt_password(anycast_config['bgp_telnet_password'])} keepalive={anycast_config['bgp_keepalive_time']} \
            holdtime={anycast_config['bgp_hold_time']} neighbors-ipv4={anycast_config['bgp_ipv4_address']} component=bgpd \
            enabled=1 neighbors-ipv6={anycast_config['bgp_ipv6_address']}"

        g.user.logger.debug(f'Setting BGP : {cmd}')
        run_psmclient_cmd(server_ip, username, password, cmd)

        cmd = f"anycast set asn={anycast_config['bgp_remote_asn_in_ipv4']} neighbor-ipv4={anycast_config['bgp_ipv4_address']} \
        ebgp-multihop={anycast_config['bgp_ipv4_hop_limit']} next-hop-self={anycast_config['bgp_next_hop_self_ipv4']} \
        component=bgpd password={process_password.decrypt_password(anycast_config['bgp_md5_ipv4'])}"

        g.user.logger.debug(f'Continue Setting BGP : {cmd}')
        run_psmclient_cmd(server_ip, username, password, cmd)

        cmd = f"anycast set asn={anycast_config['bgp_remote_asn_in_ipv6']} neighbor-ipv6={anycast_config['bgp_ipv6_address']} \
        ebgp-multihop={anycast_config['bgp_ipv6_hop_limit']} next-hop-self={anycast_config['bgp_next_hop_self_ipv6']} \
        component=bgpd password={process_password.decrypt_password(anycast_config['bgp_md5_ipv6'])}"

        run_psmclient_cmd(server_ip, username, password, cmd)

        if anycast_config['prefix_lists']:
            for item in anycast_config['prefix_lists']:
                cmd = f"anycast set component=bgpd action={item['action']} network={item['network']} prefix-list={item['type']} seq=5"
                g.user.logger.debug(f'Setting : {cmd}')
                run_psmclient_cmd(server_ip, username, password, cmd)

    elif anycast_config['anycast_protocol'] == 'rip':
        list_ipv4 = ','.join(anycast_config['anycast_ipv4'])
        cmd = 'anycast set anycast-ipv4=' + list_ipv4 + ' component=common vtysh-enable=1'
        g.user.logger.debug(f'Setting anycast : {cmd}')
        run_psmclient_cmd(server_ip, username, password, cmd)

        cmd = f"anycast set authenticate={anycast_config['rip_authenticate']} component=ripd \
               password={process_password.decrypt_password(anycast_config['rip_password'])} enabled=1"

        g.user.logger.debug(f'Setting RIP : {cmd}')
        run_psmclient_cmd(server_ip, username, password, cmd)

    cmd = 'node set anycast-enable=1'
    run_psmclient_cmd(server_ip, username, password, cmd)


def run_psmclient_cmd(server_ip, username, password, cmd, **kwargs):
    """
    Run command
    """
    base_path = '/usr/local/bluecat/PsmClient '
    command = base_path + cmd
    output, error = run_ssh_cmd(server_ip, username, password, command)
    if b'retcode=ok' in output:
        g.user.logger.debug('BDDS %s successfully executed %s: %s' %
                            (server_ip, command, output + error))
    else:
        g.user.logger.error('BDDS %s failed to execute %s: %s' %
                            (server_ip, command, output + error))
        g.user.logger.error(traceback.format_exc())
    return output


def cidr_to_netmask(net_bits):
    """
    :param net_bits: netbit
    ex: 24
    :return: netmask
    ex: 255.255.255.0
    """
    host_bits = 32 - int(net_bits)
    return socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << host_bits)))


def is_check_available_bam():
    """
    Check bam available
    :return:
    [True]- boolean
    [False]- boolean
    """
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    bam_ip = data_config['bam'][0]['ip']
    try:
        check_status = urllib.request.urlopen(f"http://{bam_ip}").getcode()
        if check_status == 200:
            g.user.logger.info('Available for BAM IP : %s' % bam_ip)
            return True
    except URLError as ex:
        g.user.logger.info(f"Not available for BAM IP : {bam_ip} {ex}")
        return False


def get_list_ip_in_bam(server, type_ip):
    properties = server["properties"].split("|")
    for p in properties:
        if p.split("=")[0] == type_ip:
            return p.split("=")[1]


def get_ip_in_list_in_used_ips(mem_nvf, start_network_ip, end_network_ip, list_network_ip):
    network_ip = ipaddress.ip_address(start_network_ip)
    while True:
        if (str(network_ip) in list_network_ip) or (mem_nvf.get_network(str(network_ip))):
            network_ip += 1
            if network_ip > ipaddress.ip_address(end_network_ip):
                return ""
        else:
            return str(network_ip)


def update_to_list_candidate_ip(raw_data, cird, ip, list_ip):
    list_candidate_ip = raw_data.get(cird, [])
    if str(ip) not in list_candidate_ip:
        list_candidate_ip.append(str(ip))
        list_ip.update({cird: list_candidate_ip})


def get_network_detail(networks):
    cidr = networks.get("cidr", "")
    start_ip = networks.get("start_ip", "")
    end_ip = networks.get("end_ip", "")
    gateway = networks.get("gateway", "")
    return cidr, start_ip, end_ip, gateway


def get_used_addresses_on_bam(memcache):
    used_ipv4 = memcache.get_network("used_ipv4")
    used_ipv6 = memcache.get_network("used_ipv6")
    if used_ipv4:
        return used_ipv4, used_ipv6
    if not is_check_available_bam():
        return [], []
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    configuration_name = data_config['bam_config_name']
    configuration_id = get_configuration_id(configuration_name)
    g.user.logger.info('Get list server of configure_id {}'.format(configuration_id))
    servers = get_list_servers(configuration_id)
    ipv4_addresses, ipv6_addresses = [], []
    for server in servers:
        server_mng_ip = get_list_ip_in_bam(server, "defaultInterfaceAddress")
        server_srv_ipv4 = get_list_ip_in_bam(server, "servicesIPv4Address")
        server_srv_ipv6 = get_list_ip_in_bam(server, "servicesIPv6Address")
        if server_mng_ip not in ipv4_addresses:
            ipv4_addresses.append(server_mng_ip)
        if server_srv_ipv4 is not None and server_srv_ipv4 not in ipv4_addresses:
            ipv4_addresses.append(server_srv_ipv4)
        if server_srv_ipv6 is not None and server_srv_ipv6 not in ipv6_addresses:
            ipv6_addresses.append(server_srv_ipv6)
    if ipv4_addresses:
        ipv4_str = ",".join(ipv4_addresses)
        memcache.set_network("used_ipv4", ipv4_str)
    if ipv6_addresses:
        ipv6_str = ",".join(ipv6_addresses)
        memcache.set_network("used_ipv6", ipv6_str)
    return ipv4_addresses, ipv6_addresses


def get_candidate_addresses(memcache, mng_ipv4_cird, mng_ipv6_cird, srv_ipv4_cird, srv_ipv6_cird):
    candidate_mng_ipv4 = memcache.get_network(mng_ipv4_cird)
    candidate_mng_ipv6 = memcache.get_network(mng_ipv6_cird)
    candidate_srv_ipv4 = memcache.get_network(srv_ipv4_cird)
    candidate_srv_ipv6 = memcache.get_network(srv_ipv6_cird)
    return candidate_mng_ipv4, candidate_mng_ipv6, candidate_srv_ipv4, candidate_srv_ipv6


def get_available_addresses(management_network, service_network):
    management_ipv4_network = management_network.get("ip_v4", {})
    if not management_ipv4_network:
        raise ValueError('Invalid management network data')
    management_ipv6_network = management_network.get("ip_v6", {})
    mgnt_ipv4_cidr, mgnt_ipv4_start_ip, mgnt_ipv4_end_ip, mgnt_ipv4_gateway = get_network_detail(
        management_ipv4_network)
    mngt_ipv4_net_size = mgnt_ipv4_cidr.split("/")[1]
    mgnt_ipv6_cidr, mgnt_ipv6_start_ip, mgnt_ipv6_end_ip, mgnt_ipv6_gateway = get_network_detail(
        management_ipv6_network)
    if mgnt_ipv6_cidr:
        mngt_ipv6_net_size = mgnt_ipv6_cidr.split("/")[1]
    if all(e != "" for e in [mgnt_ipv4_cidr, mgnt_ipv4_start_ip, mgnt_ipv4_end_ip, mgnt_ipv4_gateway]):
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        memcached_host = data_config['memcached_host']
        memcached_port = int(data_config['memcached_port'])
        mem_nfv = MemcachedNFV(memcached_host, memcached_port)
        srv_ipv4_network = service_network.get("ip_v4", {})
        srv_ipv6_network = service_network.get("ip_v6", {})
        srv_cidr, srv_start_ip, srv_end_ip, srv_gateway = get_network_detail(srv_ipv4_network)
        srv_ipv6_cidr, srv_ipv6_start_ip, srv_ipv6_end_ip, srv_ipv6_gateway = get_network_detail(srv_ipv6_network)
        used_ipv4, used_ipv6 = get_used_addresses_on_bam(mem_nfv)
        if mgnt_ipv4_gateway:
            used_ipv4.append(mgnt_ipv4_gateway)
        if mgnt_ipv6_gateway:
            used_ipv6.append(mgnt_ipv6_gateway)
        if srv_gateway:
            used_ipv4.append(srv_gateway)
        if srv_ipv6_gateway:
            used_ipv6.append(srv_ipv6_gateway)

        mgnt_ipv4 = get_ip_in_list_in_used_ips(mem_nfv, mgnt_ipv4_start_ip, mgnt_ipv4_end_ip, used_ipv4)
        mgnt_ipv4_str = mgnt_ipv4 + "/" + mngt_ipv4_net_size
        mem_nfv.set_network(mgnt_ipv4, "0", 1800)
        if mgnt_ipv6_cidr:
            mgnt_ipv6 = get_ip_in_list_in_used_ips(mem_nfv, mgnt_ipv6_start_ip, mgnt_ipv6_end_ip, used_ipv6)
            mgnt_ipv6_str = mgnt_ipv6 + "/" + mngt_ipv6_net_size
            mem_nfv.set_network(mgnt_ipv6, "0", 1800)
        srv_ip_str = ""
        srv_ipv6_str = ""
        srv_ip = ""
        srv_ipv6_ip = ""
        if srv_cidr:
            srv_ip = get_ip_in_list_in_used_ips(mem_nfv, srv_start_ip, srv_end_ip, used_ipv4)
        if srv_ipv6_cidr:
            srv_ipv6_ip = get_ip_in_list_in_used_ips(mem_nfv, srv_ipv6_start_ip, srv_ipv6_end_ip, used_ipv6)
        if srv_ip:
            srv_ipv4_net_size = srv_cidr.split("/")[1]
            srv_ip_str = srv_ip + "/" + srv_ipv4_net_size
            mem_nfv.set_network(srv_ip, "0", 1800)
        if srv_ipv6_ip:
            srv_ipv6_net_size = srv_ipv6_cidr.split("/")[1]
            srv_ipv6_str = srv_ipv6_ip + "/" + srv_ipv6_net_size
            mem_nfv.set_network(srv_ipv6_ip, "0", 1800)
        result = dict()
        result["management"] = {}
        result["management"]["ip_v4"] = {
            "cidr": mgnt_ipv4_cidr,
            "gateway": mgnt_ipv4_gateway,
            "management_ipv4": mgnt_ipv4_str
        }
        if mgnt_ipv6_cidr:
            result["management"]["ip_v6"] = {
                "cidr": mgnt_ipv6_cidr,
                "gateway": mgnt_ipv6_gateway,
                "management_ipv6": mgnt_ipv6_str
            }
        if srv_cidr or srv_ipv6_cidr:
            result["service"] = {}
            if srv_cidr:
                tmp = {
                    "cidr": srv_cidr,
                    "gateway": srv_gateway,
                    "service_ipv4": srv_ip_str
                }
                result["service"]["ip_v4"] = tmp
            if srv_ipv6_cidr:
                tmp = {
                    "cidr": srv_ipv6_cidr,
                    "gateway": srv_ipv6_gateway,
                    "service_ipv6": srv_ipv6_str
                }
                result["service"]["ip_v6"] = tmp
        return result
    else:
        raise ValueError('Invalid management network data')
