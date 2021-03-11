
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
import context
from unittest import mock  # pylint: disable=import-error


class TestProcessPassword(unittest.TestCase):
    """
    Test Gateway NFV Plugin Management
    """

    @mock.patch('common.process_password.base64')
    def test_encrypt_password(self, mock_base64):
        """
        :param:
        :return:
        """
        password = "bbb"
        mock_base64.b64encode.return_value.decode.return_value = 'sss'
        from common.process_password import encrypt_password  # pylint:disable=import-error, no-name-in-module
        actual = encrypt_password(password)
        expected = 'sss'
        self.assertEqual(expected, actual)

    @mock.patch('common.process_password.base64')
    def test_decrypt_password(self, mock_base64):
        """
        :param :
        :return:
        """
        encoded = "MTIzNDU2"
        mock_base64.b64decode.return_value.decode.return_value = '123456'
        from common.process_password import decrypt_password  # pylint:disable=import-error, no-name-in-module
        actual = decrypt_password(encoded)
        expected = "123456"
        self.assertEqual(expected, actual)
        mock_base64.b64decode.return_value.decode.assert_called_once()

    @mock.patch('common.process_password.input')
    @mock.patch('common.process_password.encrypt_password')
    def test_main_run(self, mock_encrypt_password, mock_input):
        """
        :param :
        :return:
        """
        password = "132456"
        mock_input.return_value = password
        from common.process_password import main  # pylint:disable=import-error, no-name-in-module
        main()
        mock_encrypt_password.assert_called_once()


if __name__ == "__main__":
    # pylint:disable=import-error
    unittest.main()
