
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

import json
import requests  # pylint:disable=import-error
import traceback

from common.common import read_config_json_file  # pylint:disable=import-error,no-name-in-module
from memcached.server import ServerType  # pylint:disable=import-error,no-name-in-module
from common.constants import NFV_CONFIG_PATH  # pylint:disable=import-error,no-name-in-module,ungrouped-imports

from nfv_logger import logger  # pylint:disable=import-error,no-name-in-module


def is_kpi_none(payload):
    """[Check KPI none or not]
    :param payload: payload type JSON object
    :return:
    [True] -- boolean
    [False] -- boolean
    """
    for item in payload['kpi_load']:
        if item['kpi_value'] is None:
            return True
    return False


def prepare_payload_for_k1(result_statictis):
    """[Prepare payload for k1]
    :param result_statictis:
    :return:
    [payload] -- Json object
    """
    vmname = result_statictis['server_name']
    if result_statictis['server_type'] == ServerType.BAM:
        kpi_load = [
            {"kpi_name": "cpu_load", "kpi_value": min(100, round(result_statictis['cpu_usage'])) if result_statictis['cpu_usage'] is not None else None},
            {"kpi_name": "mem_load", "kpi_value": round(result_statictis['memory_usage']) if result_statictis['memory_usage'] else None}
        ]
    elif result_statictis['server_type'] == ServerType.VM_HOST:
        kpi_load = [
            {"kpi_name": "cpu_load", "kpi_value": min(100, round(result_statictis['cpu_usage'])) if result_statictis['cpu_usage'] is not None else None},
            {"kpi_name": "mem_load", "kpi_value": round(result_statictis['memory_usage']) if result_statictis['memory_usage'] else None}
        ]
    elif result_statictis['server_type'] == ServerType.BDDS:
        kpi_load = [
            {"kpi_name": "cpu_load", "kpi_value": min(100, round(result_statictis['cpu_usage'])) if result_statictis['cpu_usage'] is not None else None},
            {"kpi_name": "mem_load", "kpi_value": round(result_statictis['memory_usage']) if result_statictis['memory_usage'] else None},
            {"kpi_name": "dns_queries", "kpi_value": round(result_statictis['queries']) if result_statictis['queries'] is not None else None}
        ]
    try:
        udf_object = {}
        for udf_string in result_statictis['udf'].split(','):
            logger.info(udf_string)
            try:
                udf_string_array = udf_string.split(':')
                udf_object.update({udf_string_array[0]: udf_string_array[1]})
            except KeyError as exeption:
                logger.info(f'UDF string has incorrect format')
                continue
    except Exception as exeption:
        logger.info(f'result statistic does not have udf')
        pass
    app_status = result_statictis.get('app_status', 'ready')
    payload = {
        # "vm_id": " ",
        "vm_type": result_statictis['server_type'],
        "vm_name": vmname,
        "app_status": app_status,
        "kpi_load": kpi_load
    }
    payload.update(udf_object)
    logger.info(f'Payload {payload}')
    return payload


def call_k1_api(result_object, timeout=1):
    """[Call K1 API]
    :param result_object:
    :param timeout: default 1
    :return:
    """
    if not result_object:
        logger.debug("Result_object is none")
        return

    payload = prepare_payload_for_k1(result_object)
    logger.info(f'Payload of K1: {payload}')

    if is_kpi_none(payload):
        logger.info(f'KPIs are none. Do not call api k1')
        return

    data_config = read_config_json_file(NFV_CONFIG_PATH)
    headers = {
        'Content-Type': 'application/json;charset=UTF-8',
    }
    try:
        host = data_config['k1_api']['address']
        port = data_config['k1_api']['port']
        uri = data_config['k1_api']['uri']
        response = requests.post(f"http://{host}:{port}{uri}",
                                 headers=headers, data=json.dumps(payload), timeout=timeout)
        result_call = {'content': response.content.decode('utf-8'), 'status_code': response.status_code}
        logger.info(f'Result call api k1: {result_call}')
    except KeyError as key_error:
        logger.error("Cannot get {} in config file {}".format(key_error))
        logger.debug(traceback.format_exc())
    except requests.RequestException:
        logger.error("Cannot request api to {}".format(data_config['k1_api']['address']))
        logger.error("Payload of the failed request: {}".format(payload))
        logger.debug(traceback.format_exc())
