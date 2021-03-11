
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

import sys
import os
import traceback
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, \
    getCmd, UsmUserData, ObjectType, ObjectIdentity, bulkCmd

from common import process_password  # pylint:disable=no-name-in-module,import-error
from nfv_logger import logger  # pylint:disable=no-name-in-module,import-error

from .map_protocol import AUTH_PROTOCOL, PRIV_PROTOCOL  # pylint:disable=import-error

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

processor_load_oid = '1.3.6.1.2.1.25.3.3.1.2'

oids_bam = ['1.3.6.1.4.1.2021.4.5.0',  # total_mem
            '1.3.6.1.4.1.2021.4.6.0',  # total_mem_free
            ]

oids_bdds = ['1.3.6.1.4.1.2021.4.5.0',  # total_mem
             '1.3.6.1.4.1.2021.4.6.0',  # total_mem_free
             '1.3.6.1.4.1.13315.3.1.2.2.2.1.1.0',  # query_success
             '1.3.6.1.4.1.13315.3.1.2.2.2.1.2.0',  # query_referral
             '1.3.6.1.4.1.13315.3.1.2.2.2.1.3.0',  # query_nxrrset
             '1.3.6.1.4.1.13315.3.1.2.2.2.1.4.0',  # query_nxdomain
             '1.3.6.1.4.1.13315.3.1.2.2.2.1.6.0',  # query_failure,
             '1.3.6.1.4.1.13315.3.1.2.2.1.1.0'  # dns_server_operate_state
             ]

map_snmp_version = {
    'v1': 0,
    'v2c': 1,
    'v3': 2,
}


def empty_to_none(value):
    """
    :param value:
    :return:
    """
    if value.strip() == "" or value is None:
        return None
    return value


def get_snmp_without_auth(template_oids, ip, port, snmp_community, snmp_version, timeout, retries):
    """
    :param template_oids:
    :param ip:
    :param port:
    :param snmp_community:
    :param snmp_version:
    :param timeout:
    :param retries:
    :return:
     errorIndication, errorStatus, errorIndex, varBinds
    """
    return next(
        getCmd(SnmpEngine(),
               CommunityData(snmp_community, mpModel=map_snmp_version[snmp_version]),
               UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
               ContextData(),
               *template_oids
               ))


def get_snmp_with_auth(template_oids, ip, port, user_name, authen_protocol, authen_password, priv_protocol,
                       priv_password, timeout, retries):
    """
    :param template_oids:
    :param ip:
    :param port:
    :param user_name:
    :param authen_protocol:
    :param authen_password:
    :param priv_protocol:
    :param priv_password:
    :param timeout:
    :param retries:
    :return:
            errorIndication, errorStatus, errorIndex, varBinds
    """
    return next(
        getCmd(SnmpEngine(),
               UsmUserData(user_name,
                           authKey=process_password.decrypt_password(empty_to_none(authen_password)),
                           privKey=process_password.decrypt_password(empty_to_none(priv_password)),
                           authProtocol=AUTH_PROTOCOL[empty_to_none(authen_protocol)],
                           privProtocol=PRIV_PROTOCOL[empty_to_none(priv_protocol)]),
               UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
               ContextData(),
               *template_oids
               ))


def get_snmp_multiple_oid(oids, ip, snmp_config_data, timeout=1, retries=0):
    """
     GET METHOD SNMP WITH MULTIPLE OID
     :param oids: type: array => list oid for example: ['1.3.6.1.4.1.2021.4.5.0', '1.3.6.1.4.1.2021.4.6.0']
    :param ip: type: str => ip for example: '192.168.88.251'
    :param snmp_config_data: type: dict => snmp config get from config file
    :param timeout: type: int => timeout for get snmp method
    :param retries: type: int => it means that how many time recall get method if it fail at the last call
    :return:
    :return: list varBinds
    """
    template_oids = map(lambda oid: ObjectType(ObjectIdentity(oid)), oids)
    try:
        snmp_version = snmp_config_data['snmp_version']
        port = snmp_config_data['port']

        if snmp_version == "v1" or snmp_version == "v2c":
            snmp_community = snmp_config_data['snmp_community']
            errorIndication, errorStatus, errorIndex, varBinds = get_snmp_without_auth(template_oids, ip, port,
                                                                                       snmp_community, snmp_version,
                                                                                       timeout, retries)
        elif snmp_version == "v3":
            user_name = snmp_config_data['user_name']
            authen_protocol = snmp_config_data['authen_protocol']
            authen_password = snmp_config_data['authen_password']
            priv_protocol = snmp_config_data['priv_protocol']
            priv_password = snmp_config_data['priv_password']

            errorIndication, errorStatus, errorIndex, varBinds = get_snmp_with_auth(template_oids, ip, port, user_name,
                                                                                    authen_protocol, authen_password,
                                                                                    priv_protocol, priv_password,
                                                                                    timeout,
                                                                                    retries)
        else:
            raise KeyError("'{}' wrong format snmp_version".format(snmp_version))

    except KeyError as key_error:
        raise KeyError("Can not find {} in snmp_config_data".format(key_error))

    if errorIndication:  # SNMP engine errors
        raise Exception(errorIndication)
    elif errorStatus:  # SNMP agent errors
        raise Exception('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
    return varBinds


def get_memory_usage(var_binds):
    """
    :param var_binds:
    :return:
    """
    try:
        total_mem = var_binds[0][-1]
        total_mem_free = var_binds[1][-1]
        used_mem = total_mem - total_mem_free
        used_mem_percent = (float(used_mem) / float(total_mem)) * 100
        logger.debug("Memory_usage: {}".format(used_mem_percent))
        return float(used_mem_percent)
    except IndexError:
        logger.error(traceback.format_exc())
        return None, None


def server_number_queries(var_binds):
    """
    :param var_binds:
    :return:
    """
    if var_binds:
        try:
            success = var_binds[2][-1]
            referral = var_binds[3][-1]
            nxrrset = var_binds[4][-1]
            nxdomain = var_binds[5][-1]
            failure = var_binds[6][-1]
            return int(success + referral + nxrrset + nxdomain + failure)
        except IndexError as exception:
            logger.error(traceback.format_exc())
            return None


def get_bulk_snmp(template_oid, ip, snmp_config_data, timeout=1, retries=0, lexicographicMode=False):
    """[Get bulk Snmp]
    Arguments:
        template_oid {[string]} -- [OID]
        ip {[string]} -- [ip of server(ex: 192.168.88.88)]
        snmp_config_data {[type]} -- [snmp config get from config file]
    Keyword Arguments:
        timeout {int} -- [timeout in seconds] (default: {1})
        retries {int} -- [Maximum number of request retries, 0 retries means just a single request.] (default: {0})
        lexicographicMode {bool} -- [walk SNMP agent’s MIB till the end (if True), 
            otherwise (if False) stop iteration when all response MIB variables leave the scope of initial MIB variables in varBinds] (default: {False})
    Raises:
        KeyError: [snmp_version input wrong format. Not match in map_snmp_version]
        KeyError: [property is not exist in snmp_config_data]
    Returns:
        [generator] -- [result generator data get by snmp]
    """
    try:
        snmp_version = snmp_config_data['snmp_version']
        port = snmp_config_data['port']

        if snmp_version == "v1" or snmp_version == "v2c":
            snmp_community = snmp_config_data['snmp_community']

            snmp_iter = bulkCmd(
                SnmpEngine(),
                CommunityData(snmp_community, mpModel=map_snmp_version[snmp_version]),
                UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
                ContextData(),
                0, 10,
                ObjectType(ObjectIdentity(template_oid)),
                lexicographicMode=lexicographicMode
            )
        elif snmp_version == "v3":
            user_name = snmp_config_data['user_name']
            auth_key = process_password.decrypt_password(empty_to_none(snmp_config_data['authen_password']))
            priv_key = process_password.decrypt_password(empty_to_none(snmp_config_data['priv_password']))
            auth_protocol = AUTH_PROTOCOL[empty_to_none(snmp_config_data['authen_protocol'])]
            priv_protocol = PRIV_PROTOCOL[empty_to_none(snmp_config_data['priv_protocol'])]

            snmp_iter = bulkCmd(
                SnmpEngine(),
                UsmUserData(user_name,
                            authKey=auth_key, privKey=priv_key,
                            authProtocol=auth_protocol, privProtocol=priv_protocol),
                UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
                ContextData(),
                0, 10,
                ObjectType(ObjectIdentity(template_oid)),
                lexicographicMode=lexicographicMode
            )
        else:
            raise KeyError("'{}' wrong format snmp_version".format(snmp_version))
    except KeyError as key_error:
        raise KeyError("Can not find {} in snmp_config_data".format(key_error))
    except Exception as ex:
        raise ex
    return snmp_iter


def get_cpu_process(ip, snmp_config_data):
    """[Get cpu process by bulksnmp]
    Arguments:
        ip {[string]} -- [ip of server(ex: 192.168.88.88)]
        snmp_config_data {[dict]} -- [snmp config get from config file]
    Raises:
        Exception: [errorIndication: True value indicates SNMP engine error]
        Exception: [errorStatus: True value indicates SNMP PDU error]
    Returns:
        [float] -- [cpu process usage]
    """
    # Call bulk get snmp data of cpu processor
    snmp_iter = get_bulk_snmp(processor_load_oid, ip, snmp_config_data)

    list_cpu_process = []
    for errorIndication, errorStatus, errorIndex, varBinds in snmp_iter:
        # Check for errors and print out results
        if errorIndication:  # SNMP engine errors
            raise Exception(errorIndication)
        elif errorStatus:  # SNMP agent errors
            raise Exception(
                '%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex) - 1] if errorIndex else '?'))
        for varBind in varBinds:
            logger.debug("{}-varBind-{}".format(ip, varBind))
            list_cpu_process.append(int(varBind[1]))

    if len(list_cpu_process) > 0:
        cpu_process = sum(list_cpu_process) / len(list_cpu_process)
    else:
        cpu_process = 0
    return cpu_process


def server_bam_statistic(ip, snmp_config_data):
    """
    :param ip:
    :param snmp_config_data:
    :return:
    """
    try:
        var_binds = get_snmp_multiple_oid(oids=oids_bam, ip=ip, snmp_config_data=snmp_config_data)
        server_memory_usage = get_memory_usage(var_binds)
        server_cpu_usage = get_cpu_process(ip=ip, snmp_config_data=snmp_config_data)
    except Exception as ex:
        raise ex
    logger.debug("Server_bam_statistic: mem_usage: {} - cpu_usage: {}".format(server_memory_usage, server_cpu_usage))
    return server_memory_usage, server_cpu_usage


def server_bdds_statistic(ip, snmp_config_data):
    """
    :param ip:
    :param snmp_config_data:
    :return:
    """
    try:
        var_binds = get_snmp_multiple_oid(oids=oids_bdds, ip=ip, snmp_config_data=snmp_config_data)
        dns_oper_state = var_binds[7][-1] # Index of OID dns oper state is 7 in oids_bdds
        # Just get queries when dns_oper_state = 1 (Running)
        queries = server_number_queries(var_binds) if dns_oper_state == 1 else 0
        server_memory_usage = get_memory_usage(var_binds)
        server_cpu_usage = get_cpu_process(ip=ip, snmp_config_data=snmp_config_data)
    except Exception as ex:
        raise ex
    logger.debug("Server_bdds_statistic {}: mem_usage: {} - cpu_usage: {} - DNS State: {} - queries: {}".format(
        ip, server_memory_usage, server_cpu_usage, dns_oper_state, queries))
    return server_memory_usage, server_cpu_usage, dns_oper_state, queries
