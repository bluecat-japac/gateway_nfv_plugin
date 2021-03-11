
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

def safe_str(obj):
    """ Return the byte string representation of obj """

    try:
        return str(obj)
    except UnicodeEncodeError:
        # obj is unicode
        return str(obj).encode('unicode_escape')


class APIException(Exception):
    """
    Create a new instance with a message and optional details. The content of these fields
    is not intended to be interpreted by software, but to appear
    near the top of a program to be easily seen and consumed by the user.

    :param message: Primary string describing why the exception was raised.
    :param details: Details, where available, of the specific exception .

    """

    def __init__(self, message, details=None):
        super(APIException, self).__init__()
        self._message = message
        self._details = details

    def __str__(self):
        """
        Return a string representation of the exception including the message and details (if any)
        """

        res = "BlueCat API exception:" + self._message
        if self._details is not None:
            res += ":" + str(self._details)
        return safe_str(res)

    def get_message(self):
        """Get a message describing the exception.
        """
        return self._message

    def get_details(self):
        """Get further details about the exception (may be *None*)
        """
        return self._details


class PortalException(APIException):
    """
    A class representing exceptions raised by the BlueCat Gateway.
    """

    def __init__(self, message, details=None):
        """
        Create a new instance with a message and optional details. The content of these fields
        is not intended to be interpreted by software, but to appear
        near the top of a program to be easily seen and consumed by the user.

        :param message: Primary string describing why the exception was raised.
        :param details: Details, where available, of the specific exception .
        """
        super(PortalException, self).__init__(message, details)
