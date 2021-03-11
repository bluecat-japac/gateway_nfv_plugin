
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

import base64


def encrypt_password(password):
    """
    Encrypt password with base64
    """
    password_bytes = str.encode(password.strip(), encoding='utf-8')
    return base64.b64encode(password_bytes).decode()


def decrypt_password(encoded):
    """
    Decrypt password with base64
    """
    password_decypt_bytes = base64.b64decode(encoded)
    return password_decypt_bytes.decode('utf-8')


def main():
    while True:
        password = input("Let's type a new password:")
        if password.strip() is not "":
            break
    pwd_encrypt = encrypt_password(password)
    print("{0} {1}".format("Your password is encrypted as:", pwd_encrypt))
    print("Please update your encrypted password in nfv_config.json file\n")


if __name__ == '__main__':
    main()
