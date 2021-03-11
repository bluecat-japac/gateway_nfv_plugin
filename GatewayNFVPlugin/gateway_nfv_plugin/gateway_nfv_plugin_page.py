
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
import sys
import traceback
from flask import request, g, abort, jsonify  # pylint:disable=import-error

# Import from memcached module
sys.path.append(os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../..')))
from memcached.server import ServerType  # pylint:disable=import-error
from memcached.memcached_nfv import MemcachedNFV  # pylint:disable=import-error

from bluecat import route, util  # pylint:disable=import-error
from main_app import app  # pylint:disable=import-error
from common.constants import (NFV_CONFIG_PATH, VM_CONFIG_PATH)  # pylint:disable=no-name-in-module,import-error
from common.common import (read_config_json_file, read_text_file, autologin_func)  # pylint:disable=no-name-in-module
from . import gateway_nfv_management  # pylint:disable=import-error


@route(app, '/gateway_nfv_plugin/init_server_cached_list', methods=['GET', 'POST'])
@util.rest_workflow_permission_required('gateway_nfv_plugin_page')
@util.rest_exception_catcher
def init_server_cached_list():
    """[init_server_cached_list: call api get servers in bam with CONFIGURATION_NAME]

    Returns:
        [json] -- [
                    Success:    return  {"Status": "SUCCESS"}
                    Fail:       return  {"Status": "FAIL"}]
    """
    try:
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        memcached_host = data_config['memcached_host']
        memcached_port = int(data_config['memcached_port'])
        configuration_name = data_config['bam_config_name']
        g.user.logger.debug(
            'Init_server_cached_list - configuration_name: {}'.format(configuration_name))
        configuration_id = gateway_nfv_management.get_configuration_id(
            configuration_name)
        g.user.logger.info(
            'Get list server of configure_id {}'.format(configuration_id))
        list_servers = gateway_nfv_management.get_list_servers(
            configuration_id)
        g.user.logger.info(
            'Init_server_cached_list - Number of get list server: {}'.format(len(list_servers)))
        # Init memcached
        mem_nfv = MemcachedNFV(memcached_host, memcached_port)
        # Set bam server info to memcached server
        bam_ip = data_config['bam'][0]['ip']
        bam_name = data_config['bam'][0]['name']
        mem_nfv.set_server({'name': bam_name, 'ipv4_address': bam_ip}, ServerType.BAM)
        # Set bdds server info to memcached server
        list_udf_name = [udf['name'] for udf in data_config['udfs_for_server']]
        for server in list_servers:
            mem_nfv.set_server(server, ServerType.BDDS, bam_ip, list_udf_name)
        # Set VM_HOST server info to memcached server
        vm_host_ip = data_config["vm_host_ip"]
        vm_name = data_config['vm_host_name']
        mem_nfv.set_server({'name': vm_name, 'ipv4_address': vm_host_ip}, ServerType.VM_HOST)
        mem_nfv.disconnect()
    except Exception as exception:
        g.user.logger.error('Init_server_cached_list - {}'.format(exception))
        g.user.logger.error(traceback.format_exc())
        return jsonify({"Status": "FAIL"})
    return jsonify({"Status": "SUCCESS"})


@route(app, '/gateway_nfv_plugin/scale_out', methods=['POST'])
@util.autologin(autologin_func)
@util.rest_workflow_permission_required('gateway_nfv_plugin_page')
@util.rest_exception_catcher
def nfv_api_scale_out():
    """
    API to call scale out
    :return:
    """
    if not request.json:
        abort(400)
    data = request.get_json()
    if request.method == "POST":
        g.user.logger.info('Starting scale out')
        return gateway_nfv_management.scale_out(data)
    return jsonify([]), 200


@route(app, '/gateway_nfv_plugin/scale_in', methods=['POST'])
@util.autologin(autologin_func)
@util.rest_workflow_permission_required('gateway_nfv_plugin_page')
@util.rest_exception_catcher
def nfv_api_scale_in():
    """
    API to call scale in
    :return:
    """
    if not request.json:
        abort(400)
    data = request.get_json()
    if request.method == "POST":
        g.user.logger.info('Starting scale in')
        return gateway_nfv_management.scale_in(data)
    return jsonify([]), 200


@route(app, '/api/v1.0/srvo/instances/app_vm', methods=['POST', 'DELETE'])
@util.autologin(autologin_func)
@util.rest_workflow_permission_required('gateway_nfv_plugin_page')
@util.rest_exception_catcher
def nfv_api_app_vm():
    """
    API to call scale in and scale out
    POST - Scale out
    DELETE - Scale in
    """
    if not request.json:
        abort(400)
    data = request.get_json()
    response_status = []
    errors = ''
    if request.method == "POST":
        for vm in data['vm_info']:
            vm_name = vm['vm_name']
            scale_out_data = get_vm_config_data(vm_name)
            g.user.logger.info('Starting scale out')
            response = gateway_nfv_management.scale_out(scale_out_data)
            message = response[0].get_json()['message'] + f' for server {vm_name}'
            status = response[0].get_json()['status']
            error = response[0].get_json()['error']
            g.user.logger.info(message)
            response_status.append(status)
            if error:
                errors += error + f'({vm_name})\n'
    if request.method == "DELETE":
        for vm in data['vm_info']:
            vm_name = vm['vm_name']
            scale_in_data = {
                "server_name": vm_name
            }
            g.user.logger.info('Starting scale in')
            response = gateway_nfv_management.scale_in(scale_in_data)
            message = response[0].get_json()['message'] + f' for server {vm_name}'
            status = response[0].get_json()['status']
            error = response[0].get_json()['error']
            g.user.logger.info(message)
            response_status.append(status)
            if error:
                errors += error + f' ({vm_name})\n'

    for status in response_status:
        if status == 'Failed':
            g.user.logger.info(f'Summary: Failed\nErrors: {errors}')
            return jsonify({"status": "Failed"}), 500
    g.user.logger.info('Summary: Successful')
    return jsonify({"status": "Successful"}), 200


def get_vm_config_data(vm_name):
    """
    Get data of VM config
    :param vm_name: name of VM (get from NFV_CONFIG_PATH)
    :return:
    """
    config = read_text_file(VM_CONFIG_PATH)
    for line in config:
        if line.startswith('bam_num'):
            bam_num = line.split('=')[1].strip()
        elif line.startswith('SERVER_NET_MASK'):
            netmask = line.split('=')[1].strip()
        elif line.startswith('SERVER_V6_PREFIX'):
            v6_prefix = line.split('=')[1].strip()

    vm_id = vm_name.split('_')[-1]
    for line in config:
        if line.startswith('OM') and 'V6' not in line and 'NET_MASK' not in line and 'GATEWAY' not in line:
            if int((line.split('=')[0]).split('_')[-1]) == int(vm_id) + int(bam_num):
                vm_mgnt_ip = line.split('=')[1].strip()

        elif line.startswith('SERVER') and 'V6' not in line and 'NET_MASK' not in line and 'GATEWAY' not in line:
            if int((line.split('=')[0]).split('_')[-1]) == int(vm_id):
                vm_service_ipv4 = line.split('=')[1].strip()

        elif line.startswith('SERVER_V6') and 'PREFIX' not in line and 'GATEWAY' not in line:
            if int((line.split('=')[0]).split('_')[-1]) == int(vm_id):
                vm_service_ipv6 = line.split('=')[1].strip()

    metadata = get_metadata()
    scale_out_data = {
        "server_name": vm_name,
        "mgnt_server_ip": vm_mgnt_ip,
        "service_server_ipv4": vm_service_ipv4,
        "service_server_ipv6": vm_service_ipv6,
        "service_server_netmask": int(netmask),
        "service_server_v6_prefix": v6_prefix,
        "metadata": metadata
    }
    return scale_out_data


def get_metadata():
    """
    Get metadata from NFV_CONFIG_PATH
    :return: metadata
    """
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    list_metadata = []

    for udf in data_config['udfs_for_server']:
        tmp = udf['name'] + '=' + str(udf['default_value'])
        list_metadata.append(tmp)

    metadata = '|'.join(list_metadata)
    return metadata


@route(app, '/gateway_nfv_plugin/get_available_ip_address', methods=['GET'])
@util.autologin(autologin_func)
@util.rest_workflow_permission_required('gateway_nfv_plugin_page')
@util.rest_exception_catcher
def get_available_ip_address():
    """
    API to get avalable ip address
    :return: example
    [json] -- [
            "management_ip": "192.168.88.2"
            "service": "192.168.89.2"
        ]
    """
    if not request.json:
        abort(400)
    data = request.get_json()
    network_management = data.get("management", None)
    if network_management is None:
        return jsonify(
            {"status": "Failed", "message": "Invalid management network"}), 500
    try:
        service_networks = data.get("service", {})
        result = gateway_nfv_management.get_available_addresses(network_management,
                                                                service_networks)
        return jsonify(result), 200
    except ValueError as ex:
        g.user.logger.error('Init_server_cached_list - {}'.format(ex))
        g.user.logger.error(traceback.format_exc())
        return jsonify(
            {"status": "Failed", "message": "Invalid management network"}), 500
