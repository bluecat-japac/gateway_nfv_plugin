
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
import os
import sys
import traceback

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from concurrent.futures import ThreadPoolExecutor as PoolExecutor  # pylint:disable=import-error

# Internal module
from apscheduler.schedulers.blocking import BlockingScheduler  # pylint:disable=import-error,no-name-in-module
from apscheduler.executors.pool import ProcessPoolExecutor  # pylint:disable=import-error,no-name-in-module

from gateway import gateway_access  # pylint:disable=import-error,no-name-in-module
from snmp.snmp_methods import server_bam_statistic, server_bdds_statistic  # pylint:disable=import-error,no-name-in-module
from memcached.server import ServerType  # pylint:disable=import-error,no-name-in-module
from memcached.memcached_nfv import MemcachedNFV  # pylint:disable=import-error,no-name-in-module
from common.constants import NFV_CONFIG_PATH, SNMP_CONFIG_PATH # pylint:disable=import-error,no-name-in-module
from common.common import read_config_json_file  # pylint:disable=import-error,no-name-in-module
from nfv_logger import logger  # pylint:disable=import-error,no-name-in-module
import k1  # pylint:disable=import-error,no-name-in-module


def get_memcached_config():
    """[Get memcached config from NFV_CONFIG_PATH]
    Raises:
        Exception -- [Can not get config memcached from NFV_CONFIG_PATH]
    Returns:
        [String] -- [memcached_host]
        [Int] -- [memcached_host]
    """
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    try:
        memcached_host = data_config['memcached_host']
        memcached_port = data_config['memcached_port']
    except KeyError:
        raise KeyError(
            "Can not get config memcached from NFV_CONFIG_PATH")
    logger.debug("Memcached_host: {} - Memcached_port: {}".format(memcached_host, memcached_port))
    return memcached_host, int(memcached_port)


def init_server_cached_list_api():
    """[Call api to gateway init server bam and bdds to memcached]
    """
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    logger.info("Statistics collection-init_server_cached_list_api")
    result = gateway_access.request_data(
        'gateway_nfv_plugin/init_server_cached_list', data_config['bam'][0]['ip'])
    logger.info(
        "Statistics collection-init_server_cached_list_api - {}".format(result))


def make_template_statistic_object(address, server_type, server_name, memory_usage, cpu_usage, queries=0, udf='', dns_oper_state=2):
    """[Make template statistic object]
    :param address: address of Server -- string
    :param server_type:  Type of Server -- string
    :param server_name: Name of Server -- string
    :param memory_usage: Memory usage of Server -- int
    :param cpu_usage: CPU usage of Server -- int
    :param queries: default 0
    :param udf: default ''
    :return:
    [result_object] -- dict
    """
    result_object = dict(
        address=address,
        server_type=server_type,
        server_name=server_name,
        udf=udf,
        memory_usage=memory_usage,
        cpu_usage=cpu_usage
    )
    if server_type == ServerType.BDDS:
        result_object.update(queries=queries)
        app_status = 'success' if dns_oper_state == 1 else 'fail'
        result_object.update(app_status=app_status)
    logger.debug("Result object: {}".format(result_object))
    return result_object


def get_server_statistic(server, call_k1=True):
    """
    :param server: Json object
    :param call_k1: bool
    :return: template statistic object -- Json

    """
    result_object = None
    try:
        if server['server_type'] == ServerType.BAM or server['server_type'] == ServerType.VM_HOST:
            memory_usage, cpu_usage = server_bam_statistic(
                server['address'], server['snmp_config_data'])
            result_object = make_template_statistic_object(server['address'], server['server_type'], server['server_name'], memory_usage, cpu_usage)
        elif server['server_type'] == ServerType.BDDS:
            memory_usage, cpu_usage, dns_oper_state, queries = server_bdds_statistic(
                server['address'], server['snmp_config_data'])
            result_object = make_template_statistic_object(
                server['address'], server['server_type'], server['server_name'], memory_usage, cpu_usage, queries, server['udf'], dns_oper_state)
    except Exception as ex:
        logger.error("{}: {}-{}".format(server['server_name'], type(ex), ex))
        logger.error(traceback.format_exc())

    logger.info(f'get_server_statistic: {result_object}')

    if call_k1:
        k1.call_k1_api(result_object, 5)

    return result_object


def get_snmp_server_config_name(config, name):
    """
    :param config:
    :param name:
    :return:
    """
    try:
        config[name]
        server_config_name = name
    except KeyError as exception:
        server_config_name = 'common'
    return server_config_name


def collect_statistics(mem_nfv):
    """
    :return: Array of statistic results
    """
    # Get server list from memcached
    list_bdds, list_bam, list_vmhosts = mem_nfv.get_list_servers()
    
    logger.debug("List_bdds: {}\nList_bam: {}\nList_vmhost: {}".format(list_bdds, list_bam, list_vmhosts))
    snmp_config = read_config_json_file(SNMP_CONFIG_PATH)
    logger.debug("Snmp config: {}".format(snmp_config))
    list_servers = []

    logger.info(f'List BDDS Size: {len(list_bdds)}')
    logger.info(f'Begin loop through list_bdds')
    for bdds in list_bdds:
        logger.debug(f'BDDS: {bdds}')
        bdds_config_name = get_snmp_server_config_name(snmp_config, bdds.name)
        logger.debug(f'BDDS config name {bdds_config_name}')
        try:
            list_servers.append({
                'server_type': ServerType.BDDS, 'server_name': bdds.name, 'address': bdds.ipv4_address,
                'snmp_config_data': snmp_config[bdds_config_name], 'udf': bdds.udf})
        except KeyError as exception:
            logger.error(f'Exception Key Error {exception}')
            logger.error(traceback.format_exc())
            continue
    logger.info(f'List BAM Size: {len(list_bam)}')
    logger.info(f'Begin loop through list_bam')
    for bam in list_bam:
        try:
            logger.debug(f'BAM: {bam}')
            logger.debug(f'bam_name: {bam.name}')
            bam_config_name = get_snmp_server_config_name(snmp_config, bam.name)
            logger.debug(f'Bam config name {bam_config_name}')
            try:
                logger.info(f'Begin Append BAM server list Server {list_servers}  ')
                list_servers.append({
                    'server_type': ServerType.BAM, 'server_name': bam.name, 'address': bam.ipv4_address,
                    'snmp_config_data': snmp_config[bam_config_name]})
                logger.info(f'End append BAM ===> List Server {list_servers}')
            except KeyError as exception:
                logger.error(f'Exception Key Error {exception}')
                logger.error(traceback.format_exc())
                continue
        except Exception as exception:
            logger.info(f'Cant get bam.ipv4_address: {exception}')
    logger.info(f'List VMHOST Size: {len(list_vmhosts)}')
    logger.info(f'Begin loop through list_vmhosts')
    for vm_host in list_vmhosts:
        try:
            logger.debug(f'VM_HOST: {vm_host}')
            logger.debug(f'vm_name: {vm_host.name}')
            vm_host_config_name = get_snmp_server_config_name(snmp_config, vm_host.name)
            logger.debug(f'VM_HOST config name {vm_host_config_name}')
            try:
                logger.info(f'Begin Append VM_HOST server list Server {list_servers}  ')
                list_servers.append({
                    'server_type': ServerType.VM_HOST, 'server_name': vm_host.name, 'address': vm_host.ipv4_address,
                    'snmp_config_data': snmp_config[vm_host_config_name]})
                logger.info(f'End append  VM_HOST  ===> List Server {list_servers}')
            except KeyError as exception:
                logger.error(f'Exception Key Error {exception}')
                logger.error(traceback.format_exc())
                continue
        except Exception as exception:
            logger.info(f'Can not get vm_host.ip_address: {exception}')

    logger.info(f'Begin get statistic with list server {list_servers}')
    result = []
    with PoolExecutor(max_workers=10) as executor:
        for result_object in executor.map(get_server_statistic, list_servers):
            result.append(result_object)
    return result


def scheduler_get_statistic_job():
    """
    Scheduler to get statistic job
    """
    # init
    memcached_host, memcached_port = get_memcached_config()
    mem_nfv = MemcachedNFV(memcached_host, memcached_port)
    statistics = collect_statistics(mem_nfv)
    # Close 
    mem_nfv.disconnect()
    logger.info('Get statistic: %s' % statistics)


def main():
    # Clean
    logger.info("Clean memcached before init")
    memcached_host, memcached_port = get_memcached_config()
    mem_nfv = MemcachedNFV(memcached_host, memcached_port)
    mem_nfv.clean_memcached()
    mem_nfv.disconnect()
    # Init server list
    init_server_cached_list_api()

    # Scheduler for get statistic
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    interval = int(data_config['interval'])

    executors = {
        'default': {'type': 'threadpool', 'max_workers': 20},
        'processpool': ProcessPoolExecutor(max_workers=5)
    }
    job_defaults = {
        'coalesce': False,
        'max_instances': 3
    }
    scheduler = BlockingScheduler()
    scheduler.configure(executors=executors, job_defaults=job_defaults)
    scheduler.add_job(scheduler_get_statistic_job, 'interval', seconds=interval)
    scheduler.start()


if __name__ == '__main__':
    main()

