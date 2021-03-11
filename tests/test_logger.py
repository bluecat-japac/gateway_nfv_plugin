
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

# pylint: disable=missing-docstring
import unittest
import sys  # pylint:disable=import-error
import context
from unittest import mock  # pylint: disable=import-error

from common.logger import Logger  # pylint:disable=import-error, import-error

sys.modules["cryptography"] = mock.Mock()
sys.modules["_logger"] = mock.Mock()


class TestLogger(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """
    @mock.patch.object(Logger, '__init__', lambda x, y: None)  # mock init
    @mock.patch('common.logger.read_config_json_file')
    def test_get_log_level(self, mock_read_config_json_file):
        """
        :param:
        :return:
        """
        call_class = Logger("1")
        nfv_config = {
            "log_level": "INFO"
        }
        mock_read_config_json_file.return_value = nfv_config
        call_class.get_log_level()

    @mock.patch.object(Logger, '__init__', lambda x, y: None)  # mock init
    def test_debug(self):
        """
        :param:
        :return:
        """
        logger = Logger(mock.Mock())
        message = logger.prepend_message_type(mock.Mock(), mock.Mock())
        logger._logger = mock.Mock()
        logger._logger.debug(message)


if __name__ == "__main__":
    unittest.main()
