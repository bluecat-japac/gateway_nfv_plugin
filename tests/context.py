
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

import sys  # pylint: disable=missing-docstring
import os
from unittest import mock  # pylint: disable=import-error

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.modules["main_app"] = mock.Mock()
sys.modules["app"] = mock.Mock()
sys.modules["bluecat"] = mock.Mock()
sys.modules["paramiko.ssh_exception"] = mock.Mock()
sys.modules["bluecat.api_exception"] = mock.Mock()
sys.modules["bluecat.util.util"] = mock.Mock()
sys.modules["jsonify"] = mock.Mock()
sys.modules["logger"] = mock.Mock()
sys.modules["config"] = mock.Mock()
sys.modules["config.default_config"] = mock.Mock()
sys.modules["scp"] = mock.Mock()
sys.modules["paramiko"] = mock.Mock()
sys.modules["bluecat.util"] = mock.Mock()
sys.modules["nfv_logger"] = mock.Mock()
sys.modules["apscheduler"] = mock.Mock()


def route_fake(app, path, methods=None):
    # pylint: disable=missing-docstring
    def func_wrapper(func):
        # pylint: disable=missing-docstring
        return func

    return func_wrapper


def rest_workflow_permission_required_fake(path):
    def func_wrapper(func):
        # pylint: disable=missing-docstring
        return func

    return func_wrapper


def autologin_func_fake(path):
    def func_wrapper(func):
        # pylint: disable=missing-docstring
        return func
    return func_wrapper


mock.patch('bluecat.route', route_fake).start()
mock.patch('bluecat.util.rest_workflow_permission_required', rest_workflow_permission_required_fake).start()
mock.patch('bluecat.util.rest_exception_catcher', lambda x: x).start()
mock.patch('bluecat.util.autologin', autologin_func_fake).start()
