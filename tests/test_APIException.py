
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

from common.APIException import APIException


class TestAPIException(unittest.TestCase):
    # pylint: disable=missing-docstring
    def test_safe_str(self):
        # pylint: disable=missing-docstring
        obj = ""
        from common.APIException import safe_str # pylint: disable=import-error
        actual = safe_str(obj)
        expect = str(obj)
        self.assertLessEqual(expect, actual)

    @mock.patch('common.APIException.safe_str')
    def test__str__(self, mock_safe_str):
        message = "nhii"
        details = "nhiii"
        api_exception = APIException(message, details)
        mock_safe_str.return_value = "test"
        expected = "test"
        self.assertEqual(expected, str(api_exception))


if __name__ == "__main__":
    unittest.main()