
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
import traceback
import requests  # pylint:disable=import-error
from common import common  # pylint:disable=no-name-in-module
from nfv_logger import logger  # pylint:disable=import-error


def request_data(api, bam_ip):
    """
    Request data
    :param api: API
    :param bam_ip: IP of BAM -- IPv4
    :return:
    [Result] -- String
    """
    result = None
    try:
        user_name, password, gateway_url, _ = common.get_configuration()
        if not user_name or not password:
            return
        bam_url = "http://{}/Services/API?wsdl".format(bam_ip)
        login_session = login(user_name, password, gateway_url, bam_url)
        if not login_session:
            return
        url = "{}/{}".format(gateway_url, api)
        logger.info(
            "Gateway_access-request_data - {}".format(url))
        ts_request = login_session.get(url)
        logout(login_session, gateway_url)
        if ts_request.status_code != 200:
            return
        result = json.loads(ts_request.text)
    except Exception as exception:
        logger.error(
            "Gateway_access-request_data - {}".format(exception))
        logger.error(traceback.format_exc())
    return result


def login(user_name, password, gateway_url, bam_url):
    """
    Login
    :param user_name:
    :param password:
    :param gateway_url:
    :param bam_url:
    :return:
    """
    if not user_name or not password:
        return
    login_data = {
        'username': user_name,
        'password': password,
        # 'bam_list': bam_url
    }
    login_url = "{}/{}".format(gateway_url, "login")
    scheduler_session = requests.Session()
    login_request = scheduler_session.post(login_url, login_data)
    if login_request.status_code == 200:
        return scheduler_session
    return


def logout(login_session, gateway_url):
    """
    :param login_session:
    :param gateway_url:
    :return:
    """
    logout_url = "{}/{}".format(gateway_url, "logout")
    login_session.get(logout_url)