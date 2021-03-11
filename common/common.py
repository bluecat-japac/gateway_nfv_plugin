
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
import json
import base64
import re
from cryptography.fernet import Fernet, InvalidToken # pylint:disable=import-error

from .constants import (
    NFV_CONFIG_PATH,
    CONFIG_PATH
)


def read_config_json_file(file_path):
    """
     Read config from json file
    :param file_path: path of file
    :return: None
    """
    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), file_path))) as json_file:
        return json.load(json_file)


def read_text_file(file_path):
    """
    Read text file
    :param file_path: path of text file
    :return: None
    """
    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), file_path))) as file:
        return file.read().split('\n')


def autologin_func():
    """
    Automatically login
    :return:
    [username] - String
    [password] - String
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), CONFIG_PATH))
    data_config = read_config_json_file(NFV_CONFIG_PATH)
    user_name = data_config["user_name"]
    password_file = data_config["secret_file"]
    password_path = os.path.join(base_dir, password_file)
    password = decrypt_key_from_file(path=password_path)
    return user_name, password


def get_configuration():
    """
    get configuration from NFV_CONFIG_PATH
    :return:
    """
    try:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), CONFIG_PATH))
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        user_name = data_config["user_name"]
        password_file = data_config["secret_file"]
        password_path = os.path.join(base_dir, password_file)
        password = decrypt_key_from_file(path=password_path)
        gateway_address = data_config["gateway_address"]
        gateway_url = "http://{}".format(gateway_address)
        interval = data_config["interval"]
        return user_name, password, gateway_url, interval
    except:
        return None, None, None, 1


def decrypt_key_from_file(name=None, path=os.path.join('customizations', '.secret'), key=None):
    """
    Decrypt the file given in path and find the key associated with the given name. Returns the key if found, otherwise
    will throw a PortalException.

    :param name: A human readable name for the desired key that was used in the encrypt_key_to_file method for the key.
        If no name is provided the method will return the entire unencrypted contents of the file.
    :param path: The path (including the filename) where the encrypted file is stored.
    :param key: The secret token for decrypting the encrypted file. The default token for the Portal server will be
        used if nothing is provided. The token must be a URL-safe base64-encoded 32-byte string; config.secret_key will
        be used if key is not provided.
    :return: The found key as a string.
    """
    key = get_secret(key)
    path = check_path(path)
    crypto_suite = Fernet(key)
    with open(path, 'r') as secret_file:
        encrypted_contents = secret_file.read()
    try:
        try:
            contents = crypto_suite.decrypt(encrypted_contents)
        except TypeError:
            contents = crypto_suite.decrypt(encrypted_contents.encode())
    except InvalidToken:
        raise Exception('Secret key is not valid! Please check the secret_key in the Portal config file!')

    if name is None:
        token = base64.urlsafe_b64decode(contents)
        return token

    try:
        contents = contents.decode()
    except AttributeError:
        pass

    try:
        name = name.decode()
    except AttributeError:
        pass

    safe_id = re.escape(name)
    result = re.search('(^%s=.+$)' % safe_id, contents, re.MULTILINE)
    if result:
        key_pair = result.group(0)
        token = key_pair.split('=', 1)[1]
    else:
        raise Exception('Given name is not associated with any encrypted keys!')

    token = base64.urlsafe_b64decode(token)
    return token


def get_secret(secret=None):
    """
    Encodes secret using Base64.
    """
    if secret is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), CONFIG_PATH))
        data_config = read_config_json_file(NFV_CONFIG_PATH)
        key_path = data_config["secretkey_file"]
        secretkey_path = os.path.join(base_dir, key_path)
        with open(secretkey_path, 'r') as secret_key_file:
            secret = secret_key_file.read()
    safe_secret = str(secret)
    safe_secret.zfill(32)
    key = base64.b64encode(safe_secret[:32].encode())
    return key


def check_path(path, base_directory=''):
    """
    Verifies Path for storing external files.
    """
    file_path = os.path.normpath(path)
    if not file_path.startswith(base_directory):
        raise Exception('%s is not a valid path for storing external files!' % path)
    return file_path


def map_text_log_level(logging_text):
    """
    :param logging_text: content of log
    :return:
    [dict_log] - String
    """
    dict_log = dict(
        CRITICAL=50,
        FATAL=50,
        ERROR=40,
        WARNING=30,
        WARN=30,
        INFO=20,
        DEBUG=10,
        NOTSET=0
    )
    return dict_log[logging_text]
