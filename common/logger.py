
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
import datetime
import logging
import time
import sys

from logging.handlers import RotatingFileHandler

from common.constants import NFV_CONFIG_PATH  # pylint:disable=no-name-in-module,import-error

from common.common import read_config_json_file, map_text_log_level # pylint:disable=no-name-in-module,import-error

from .APIException import PortalException  # pylint:disable=import-error

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class Logger(object):
    """
    NFV Logger
    """

    def get_log_level(self):
        """
        Get level log
        :return:
        """
        nfv_config = read_config_json_file(NFV_CONFIG_PATH)
        logging_text_level = nfv_config["log_level"]
        return map_text_log_level(logging_text_level)

    def __init__(self, log_name='nfv', base_dir=''):
        """
        Init
        """
        self.log_name = log_name
        self._datetime = None
        log_format = '[%(asctime)s][PID:%(process)d] %(levelname)s: %(message)s'
        log_level = self.get_log_level()
        log_timestamp_format = '%Y-%m-%dT%H:%M:%SZ'
        log_file_timestamp_format = "%d-%m-%Y-%I%p"
        if base_dir == '':
            base_dir = os.path.dirname(os.path.dirname(__file__))
        log_path = os.path.join(base_dir, "logs")
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        try:
            self._logger = self.create_logger_object(log_format, log_level, log_path,
                                                     log_timestamp_format, log_file_timestamp_format)
        except Exception as exception:
            try:
                self._logger = self.create_logger_object(log_format, log_level, log_path,
                                                         log_timestamp_format, log_file_timestamp_format)
            # pylint: disable=broad-except
            except Exception as exception:
                raise PortalException(str(exception))

    def __del__(self):
        """
        :return:
        """
        self.remove_handlers()

    def create_logger_object(self, log_module_format, log_module_level, log_module_path, log_timestamp_format,
                             log_file_timestamp_format):
        """
        Create log
        """
        self._datetime = datetime.datetime.utcnow()
        log_name = '{0}'.format(self.log_name)
        log_path = os.path.join(log_module_path, '%s.log' % (log_name))
        if not os.path.isfile(log_path):
            open(log_path, 'a').close()
        try:
            log_module_format = str(log_module_format)
        except UnicodeDecodeError:
            log_module_format = log_module_format.decode('utf-8')
        logger = logging.getLogger(log_name)
        logger.setLevel(log_module_level)
        formatter = logging.Formatter(log_module_format, log_timestamp_format)
        formatter.converter = time.gmtime
        handler = RotatingFileHandler(log_path, maxBytes=20000000, backupCount=10)
        handler.setLevel(log_module_level)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def debug(self, message, msg_type=None):
        """ wrapper for python debug"""
        message = self.prepend_message_type(message, msg_type)
        self._logger.debug(message)

    def info(self, message, msg_type=None):
        """ wrapper for python info"""
        message = self.prepend_message_type(message, msg_type)
        self._logger.info(message)

    def warning(self, message, msg_type=None):
        """ wrapper for python warning"""
        message = self.prepend_message_type(message, msg_type)
        self._logger.warning(message)

    def error(self, message, msg_type=None):
        """ wrapper for python error"""
        message = self.prepend_message_type(message, msg_type)
        self._logger.error(message)

    def critical(self, message, msg_type=None):
        """ wrapper for python critical"""
        message = self.prepend_message_type(message, msg_type)
        self._logger.critical(message)

    # pylint: disable=no-self-use
    def prepend_message_type(self, message, msg_type):
        """ formats logger message"""
        if msg_type:
            message = '%s: %s' % (msg_type, message)
        return message

    def remove_handlers(self):
        """ Remove handlers"""
        handlers = self._logger.handlers
        for handler in handlers:
            handler.close()
            self._logger.removeHandler(handler)
