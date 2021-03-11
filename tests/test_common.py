
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



class TestCommon(unittest.TestCase):
    # pylint: disable=missing-docstring
    @mock.patch('common.common.decrypt_key_from_file')
    @mock.patch('common.common.read_config_json_file')
    @mock.patch('common.common.os')
    def test_read_text_file(self, mock_os, mock_read_config_json_file, mock_decrypt_key_from_file):
        # pylint: disable=missing-docstring
        bash_dir = mock.Mock()
        mock_os.path.abspath.return_value = bash_dir
        data_config = {
            "user_name": "gateway_user",
            "secret_file": ""
        }
        mock_read_config_json_file.return_value = data_config
        password = "13456"
        mock_decrypt_key_from_file.return_value = password
        from common.common import autologin_func  # pylint:disable=import-error
        actual = autologin_func()
        expect = "132456", "d8e8fca"
        self.assertLessEqual(expect, actual)
        mock_os.path.abspath.assert_called_once()
        mock_decrypt_key_from_file.assert_called_once()

    @mock.patch('common.common.decrypt_key_from_file')
    @mock.patch('common.common.read_config_json_file')
    @mock.patch('common.common.os')
    def test_get_configuration_not_none(self, mock_os, mock_read_config_json_file, mock_decrypt_key_from_file):
        # pylint: disable=missing-docstring
        bash_dir = mock.Mock()
        mock_os.path.abspath.return_value = bash_dir
        data_config = {
            "user_name": "gateway_user",
            "secret_file": "",
            "gateway_address": "192.168.88.54",
            "interval": 2
        }
        mock_read_config_json_file.return_value = data_config
        password = "13456"
        mock_decrypt_key_from_file.return_value = password
        from common.common import get_configuration  # pylint:disable=import-error
        actual = get_configuration()
        expect = "132456", "d8e8fca", "192.168.88.54", 2
        self.assertLessEqual(expect, actual)
        mock_os.path.abspath.assert_called_once()
        mock_decrypt_key_from_file.assert_called_once()

    @mock.patch('common.common.decrypt_key_from_file')
    @mock.patch('common.common.read_config_json_file')
    @mock.patch('common.common.os')
    def test_get_configuration_none(self, mock_os, mock_read_config_json_file, mock_decrypt_key_from_file):
        # pylint: disable=missing-docstring
        bash_dir = None
        mock_os.path.abspath.return_value = bash_dir
        data_config = None
        mock_read_config_json_file.return_value = data_config
        password = None
        mock_decrypt_key_from_file.return_value = password
        from common.common import get_configuration  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = get_configuration()
            expect = None, None, None, None
            self.assertLessEqual(expect, actual)
        mock_os.path.abspath.assert_called_once()

    @mock.patch('common.common.open')
    @mock.patch('common.common.base64')
    @mock.patch('common.common.Fernet')
    @mock.patch('common.common.check_path')
    @mock.patch('common.common.get_secret')
    def test_decrypt_key_from_file_with_name_exception(self, mock_get_secret, mock_check_path, mock_fernrt, mock_base64,
                                                      mock_open):
        # pylint: disable=missing-docstring
        key = None
        mock_get_secret.return_value = key
        path = "D:/portal/bluecat_portal/workflows/gateway_nfv_plugin"
        mock_check_path.return_value = path
        crypto_suite = mock.Mock()
        mock_fernrt.return_value = crypto_suite
        name = "nhii"
        encrypted_contents = ".secretkey"
        mock_open.return_value.__enter__.return_value.read.return_value = encrypted_contents
        contents = b'aaaa'
        crypto_suite.decrypt.return_value = contents
        token = "nhiii"
        mock_base64.urlsafe_b64decode.return_value = token
        from common.common import decrypt_key_from_file  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = decrypt_key_from_file(name, path, key)
            expect = token
            self.assertLessEqual(expect, actual)
        mock_open.assert_called()

    @mock.patch('common.common.AttributeError', Exception)
    @mock.patch('common.common.open')
    @mock.patch('common.common.base64')
    @mock.patch('common.common.Fernet')
    @mock.patch('common.common.check_path')
    @mock.patch('common.common.get_secret')
    def test_decrypt_key_from_file_attribute_error(self, mock_get_secret, mock_check_path,
                                                   mock_fernrt, mock_base64, mock_open):
        # pylint: disable=missing-docstring
        key = None
        mock_get_secret.return_value = key
        path = "D:/portal/bluecat_portal/workflows/gateway_nfv_plugin"
        mock_check_path.return_value = path
        crypto_suite = mock.Mock()
        mock_fernrt.return_value = crypto_suite
        name = None
        encrypted_contents = ".secretkey"
        mock_open.return_value.__enter__.return_value.read.return_value = encrypted_contents
        crypto_suite.decrypt.side_effect = Exception("exception")
        token = "nhiii"
        mock_base64.urlsafe_b64decode.side_effect = Exception("exception")
        from common.common import decrypt_key_from_file  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = decrypt_key_from_file(name, path, key)
            expect = token
            self.assertLessEqual(expect, actual)
            mock_open.assert_called()

    @mock.patch('common.common.InvalidToken', Exception)
    @mock.patch('common.common.TypeError', Exception)
    @mock.patch('common.common.open')
    @mock.patch('common.common.base64')
    @mock.patch('common.common.Fernet')
    @mock.patch('common.common.check_path')
    @mock.patch('common.common.get_secret')
    def test_decrypt_key_from_file_except(self, mock_get_secret, mock_check_path,
                                                   mock_fernrt, mock_base64, mock_open):
        # pylint: disable=missing-docstring
        key = None
        mock_get_secret.return_value = key
        path = "D:/portal/bluecat_portal/workflows/gateway_nfv_plugin"
        mock_check_path.return_value = path
        crypto_suite = mock.Mock()
        mock_fernrt.return_value = crypto_suite
        name = None
        encrypted_contents = ".secretkey"
        mock_open.return_value.__enter__.return_value.read.return_value = encrypted_contents
        crypto_suite.decrypt.side_effect = Exception("exception")
        token = "nhiii"
        mock_base64.urlsafe_b64decode.side_effect = Exception("exception")
        from common.common import decrypt_key_from_file  # pylint:disable=import-error
        with self.assertRaises(Exception):
            actual = decrypt_key_from_file(name, path, key)
            expect = token
            self.assertLessEqual(expect, actual)
            mock_open.assert_called()

    @mock.patch('common.common.open')
    @mock.patch('common.common.base64')
    @mock.patch('common.common.Fernet')
    @mock.patch('common.common.check_path')
    @mock.patch('common.common.get_secret')
    def test_decrypt_key_from_file_name_none(self, mock_get_secret, mock_check_path,
                                          mock_fernrt, mock_base64, mock_open):
        # pylint: disable=missing-docstring
        key = None
        mock_get_secret.return_value = key
        path = "D:/portal/bluecat_portal/workflows/gateway_nfv_plugin"
        mock_check_path.return_value = path
        crypto_suite = mock.Mock()
        mock_fernrt.return_value = crypto_suite
        name = None
        encrypted_contents = ".secretkey"
        mock_open.return_value.__enter__.return_value.read.return_value = encrypted_contents
        crypto_suite.decrypt.return_value = "nhii"
        token = "nhii"
        mock_base64.urlsafe_b64decode.return_value = "nhii"
        from common.common import decrypt_key_from_file  # pylint:disable=import-error
        actual = decrypt_key_from_file(name, path, key)
        expect = token
        self.assertLessEqual(expect, actual)
        mock_open.assert_called()

    @mock.patch('common.common.base64')
    @mock.patch('common.common.open')
    @mock.patch('common.common.read_config_json_file')
    @mock.patch('common.common.os')
    def test_get_secret_none(self, mock_os, mock_read_config_json_file, mock_open, mock_base64):
        # pylint: disable=missing-docstring
        bash_dir = mock.Mock()
        mock_os.path.abspath.return_value = bash_dir
        data_config = {
            "secretkey_file": ".secretkey"
        }
        mock_read_config_json_file.return_value = data_config

        secret = "one fish two fish red fish blue fish"
        mock_open.return_value.__enter__.return_value.read.return_value = secret
        key = b'b25lIGZpc2ggdHdvIGZpc2ggcmVkIGZpc2ggYmx1ZSA='
        mock_base64.b64encode.return_value = key
        from common.common import get_secret # pylint:disable=import-error
        actual = get_secret()
        expect = key
        self.assertLessEqual(expect, actual)
        mock_base64.b64encode.assert_called()
        mock_open.assert_called()

    def test_get_secret_not_none(self):
        # pylint: disable=missing-docstring
        secret = "one fish two fish red fish blue fish"
        from common.common import get_secret  # pylint:disable=import-error
        actual = get_secret(secret)
        expect = b'b25lIGZpc2ggdHdvIGZpc2ggcmVkIGZpc2ggYmx1ZSA='
        self.assertEqual(expect, actual)

    @mock.patch('common.common.os')
    def test_check_path(self, mock_os):
        # pylint: disable=missing-docstring
        file_path = "nhi.json"
        path = "D:/"
        mock_os.path.normpath.return_value = file_path
        base_directory = ''
        from common.common import check_path  # pylint:disable=import-error
        actual = check_path(path, base_directory)
        expect = file_path
        self.assertLessEqual(expect, actual)
        mock_os.path.normpath.assert_called()

    def test_map_text_log_level(self):
        # pylint: disable=missing-docstring
        logging_text = "CRITICAL"
        from common.common import map_text_log_level  # pylint:disable=import-error
        actual = map_text_log_level(logging_text)
        expect = 50
        self.assertLessEqual(expect, actual)


if __name__ == "__main__":
    unittest.main()
