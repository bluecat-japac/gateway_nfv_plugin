# gateway-nfv-plugin

## Architecture

Below is the architecture diagram:
![Architecture](images/nfv_plugin_architecture.jpg?raw=true)

## Requirements

- BlueCat Gateway Version: 20.6.1
- BAM/BDDS Version: 9.2

## Setup 
### BAM Setup
#### Create UDF for Servers object

1. Access to BAM then select **Administration** tab
2. From **Data Management** section choose **Object Types**
3. From **Servers** category choose **Server** object
4. In **Server** object type page, select **New** and create an **User-Defined Field** from Fields table

    ![Server_object_type](images/Server_Object_Type.png?raw=true)

5. Input the required fields for the new **User-Defined Field**

    ![UDF_can_scale_in](images/can_scale_in_udf.png?raw=true)

6. Click **Add** button to finish

7. Repeat step 4-5-6 to create more **User-Defined Fields**

## Setup workflow

1. SSH to the host which has gateway container running and extract **gateway_nfv_plugin.tar.gz** to the gateway workflow directory:

    ```bash
    tar -xzvf gateway_nfv_plugin.tar.gz
    ```

2. Modify `extracted-directory/gateway_nfv_plugin/config/nfv_config.json` and input the corresponding information:

    | Fields | Description |
    | --- | --- |
    | `bam` | List of bam include ip and name of bam |
    | `server_deployment_password` | The default encrypted password is used when creating a new server |
    | `bam_config_name` | The configuration name for creating new server |
    | `dns_view_names` | The list of view name(s) in the configuration |
    | `udfs_for_server` | The information of user-defined fields |
    | `server_ssh_username` | The user name for connecting to bdds via ssh |
    | `server_ssh_password` | The encrypted password for connecting to bdds via ssh |
    | `server_cap_profile` | The server capability profile for creating a new server |
    | `server_deploy_role` | The DNS deployment role type for creating deployment role(s) |
    | `anycast_config` | The configuration of any cast. The default setting for anycast config is `ospf`. With the setting for `bgp` and `rip`, follow the setting in `anycast_config_bgp` and `anycast_config_rip`, respectively (If not have anycast_config scale in and out which will not enforce anycast related features) |
    | `user_name` | The gateway username |
    | `gateway_address` | The ip address of gateway container|
    | `secret_file` | The name of secret file |
    | `secretkey_file` | The name of secret key file |
    | `interval` | The interval time of scheduler container to get statistics (in seconds). If the response time of K1 api or SNMP request is slow, this interval time should be more than 2 seconds. |
    | `memcached_host` | The ip address of memcached server which is the same with the ip address of scheduler container|
    | `memcached_port` | The port of memcached server |
    | `k1_api` | The necessary information for k1 api |
    | `vm_host_ip` | The ip address of vm host |
    | `vm_host_name` | The name of vm host |
    | `log_level` | The log text level (ex: ERROR, INFO, WARNING..) |

3. Modify `extracted-directory/gateway_nfv_plugin/config/snmp_config.json` and input the corresponding information for each BAM and BDDS:

    | Fields | Description |
    | --- | --- |
    | `port` | The port of BDDS |
    | `snmp_version` | The snmp version of BDDS |
    | `user_name` | The username for setting in BDDS |
    | `authen_protocol` | Authenticated protocol |
    | `authen_password` | Encrypted authentication password |
    | `priv_protocol` | Privacy protocol |
    | `priv_password` | Encrypted privacy password |

    If the bam or bdds name is not included in this **.json** file, `common` config is automatically used.

4. For configuration memcached server, change it in `extracted-directory/gateway_nfv_plugin/config/memcached.conf` file.

5. Modify injected file contains management IP and service IP of the BDDS in the path `extracted-directory/gateway_nfv_plugin/config/vm_config.ini`

## Configure Docker Compose

 Modify in `extracted-directory/gateway_nfv_plugin/docker-compose.yml` and input the corresponding information

1. Configure **bridge network**:

    ![DC Network](images/docker_compose_network.png?raw=true)

    Table overview of IPAddress configuration for each services in **docker-compose.yml**:

    | Services | ipv4_address | ipv6_address |
    | --- | --- |  --- |
    | `memcached_server` | 192.0.2.11 | 2001:DB8::2001:DB8:0:1 |
    | `gateway_nfv_scheduler` | 192.0.2.12 | 2001:DB8::2001:DB8:0:2 |
    | `nfv_gateway` | 192.0.2.13 | 2001:DB8::2001:DB8:0:3 |

2. Configure **Gateway Container**:

    ![DC BlueCat Gateway](images/docker_compose_nfv_gateway_arm64.png?raw=true)

    Where: 
    
    | Fields | Description |
    | --- | --- |
    | `image` | docker images and version of Gateway Container |
    | `container_name` | The name of container |
    | `ports` | Port want to expose to external machine |
    | `ipv4_address` | IPv4Address  of container |
    | `ipv6_address` | IPv6Address  of container |
    | `enviroment` | Environment of container includes BAM_IP and LOCAL_USER_ID |
    | `volumes` | config gateway directory and logs want to mount here |

    > Note: Remember to configure **BAM_IP**, **LOCAL_USER_ID** and **PATH OF NFV_GATEWAY** 

3. Configure **Memcached** container

    ![DC Memcached](images/docker_compose_memcache.png?raw=true)

    | Fields | Description |
    | --- | --- |
    | `image` | docker images and version of Memcached |
    | `container_name` | The name of container |
    | `ipv4_address` | IPv4 address of container |
    | `ipv6_address` | IPv6 address of container |

4. Configure **Scheduler Statistic Collection** container

    ![DC Scheduler](images/docker_compose_nfv_scheduler.png?raw=true)

    | Fields | Description |
    | --- | --- |
    | `image` | docker images of scheduler |
    | `container_name` | The name of container |
    | `ipv4_address` | IPv4 address of container |
    | `ipv6_address` | IPv6 address of container |
    | `volumes` | Config and logs folder want to mount here |


> Note: Remember to set the permissions to external volumes with the **data** and **logs** directories:

```
chmod -R o=rwx <mapped volume>
```

## Build the docker Scheduler Statistic Collection image

Using when you want to change code scheduler and rebuild it or not have **gateway_nfv_scheduler.tar**.

Run this command:
```
cd extracted-directory/gateway_nfv_plugin/
docker build -t gateway_nfv_scheduler .
```

## Setup Scheduler Statistic Collection Container

1. SSH to the host which has gateway container running and move **gateway_nfv_scheduler.tar** to the gateway workflow directory.

2. Create and modify `.secret` and `.secretkey` files with the correct name in `nfv_config.json`. It must be in the same directory.

3. Set the permissions for **logging** and **config** directories. Users are recommended to map them on your host machine in order to modify in the future. You must do it before running the **Scheduler** container.

    ```bash
    chmod -R o=rwx <directory>
    ```

4. Get ip for the container(s)

    Copy and paste the IPAddress of container configured in **docker-compose.yml** to `nfv_config.json` file.

    ![NFV Config](images/nfv_config.png?raw=true)

> Make sure the permissions of directories is allowed before running the scheduler.

## Deploy by Docker Compose Command

1. Make sure to configured all the files with corresponding information before running build all of the containers: 

    ```bash
    cd extracted-directory/gateway_nfv_plugin/
    docker-compose up -d
    ```

    > Note: Can run each of service in **docker-compose.yml** by command:
    
    ```bash
    docker-compose up -d <name-of-service>
    ```

2. To remove all of containers in docker compose, run command:

    ```bash
    docker-compose down --remove-orphans
    ```

## Install 3rd Python libraries for Gateway Container

1. Execute this command to install 3rd Python libraries with correct path of gateway and gateway-nfv-plugin workflow directories:

    ```bash
    ocker exec nfv_gateway pip install -r /bluecat_gateway/workflows/gateway_nfv_plugin/requirements.txt
    ```

2. Access to Gateway UI. In the left sidebar, navigate to **Administration** and **Encrypt Password** action. Input the path `workflows/gateway_nfv_plugin/config/.secret` set in `config.ini` and the password of `user_name` user.

    ![Encrypt Password](images/gateway_encrypt_pwd.png?raw=true)

> Note: Ports of Gateway UI configured in the **docker-compose.yml** above

3. Navigate to **Workflow Permission**. Add permission to access traffic steering workflow.

    ![Workflow Permission](images/workflow_permission_gate_nfv.png?raw=true)

    If the permission for gateway_nfv_plugin disappears, restart the gateway container and check again.

4. Restart the containers:

    ```
    docker restart nfv_gateway
    docker restart nfv_scheduler
    ```

## Generate Encrypted Password

1. Run `extracted-directory/gateway_nfv_plugin/common/process_password.py`:

    ```bash
    python process_password.py
    or
    python3 process_password.py
    ```

2. Input the plaintext password and get the encrypted password.

    ```
    Example:
    Let's type a new password: example
    Your password is encrypted as: ZXhhbXBsZQ==
    Please update your encrypted password in nfv_config.json file
    ```

3. Copy it and save in `config` files.

4. Restart the containers:

    ```
    docker restart nfv_gateway
    ```
## API
### VM Scaling API

1. Request format

    | HTTP Request Method | URI |
    | --- | --- |
    | POST | /gateway_nfv_plugin/app_vm |
    | DELETE | /gateway_nfv_plugin/app_vm |

2. Request parameters

    | Parameter Name | Description |
    | --- | --- |
    | vm_info | VM Information List |
    | --vm_type | Type of the VM |
    | --vm_name | Name of the VM. The value of this parameter has 1 to 16 bytes(including '\0'). At least one of vm_name or vm_id parameter should be exist.

3. Response parameter

    | Parameter Name | Description |
    | --- | --- |
    | Result | OK or FAIL |

4. Scale out sample

    ```
    POST /gateway_nfv_plugin/app_vm HTTP/1.1
    Host: example.com:5000
    Content-Type: application/json
    cache-control: no-cache
    Postman-Token: 0d883cb4-c64f-4a96-bdc6-c584cb32f195
    {
        "vm_info": [
            {
                "vm_type": "bdds",
                "vm_name": "bdds_01"
            },
            {
                "vm_type": "bdds",
                "vm_name": "bdds_02"
            }
        ]
    }

    Successful response result:
    HTTP/1.1 200 OK
    {
        "status": "Successful"
    }
    ```

5. Scale in sample

    ```
    DELETE /gateway_nfv_plugin/app_vm HTTP/1.1
    Host: example.com:5000
    Content-Type: application/json
    cache-control: no-cache
    Postman-Token: 1e77f51a-759b-4b2e-ab41-c8a0c0aefb26
    {
        "vm_info": [
            {
                "vm_type": "bdds",
                "vm_name": "bdds_01"
            },
            {
                "vm_type": "bdds",
                "vm_name": "bdds_02"
            }
        ]
    }

    Successful response result:
    HTTP/1.1 200 OK
    {
        "status": "Successful"
    }
    ```

### VM Pre_Instantiate API

#### get_available_ip_address

1. API allocate ID’s of management IP and service IP

2. Input parameter

    | Parameter Name | Description |
    | --- | --- |
    | Management IPv4 | MANDATORY |
    | Management IPv6 | OPTIONAL |
    | Service IPv4 | OPTIONAL |
    | Service IPv6 | OPTIONAL |

3. Sample

    ```
    GET /gateway_nfv_plugin/get_available_ip_address HTTP/1.1
    Host: example.com:5000
    Content-Type: application/json
    cache-control: no-cache
    Postman-Token: 1e77f51a-759b-4b2e-ab41-c8a0c0aefb26
    {
        "management": {
            "ip_v4":{
                "start_ip":"192.168.88.10",
                "cidr":"192.168.88.0/24",
                "end_ip":"192.168.88.255",
                "gateway":"192.168.88.233"
            },
            "ip_v6":{
                "cidr": "2500:8100:c::b0/125",
                "start_ip": "2500:8100:c::b10",
                "end_ip": "2500:8100:c::b20"
                "gateway": "2500:8100:c::b16",
            }
        },
        "service": {
            "ip_v4": {
                "cidr": "192.168.89.0/24",
                "start_ip": "192.168.89.11",
                "end_ip": "192.168.89.254",
                "gateway": "192.168.89.1"
            },
            "ip_v6": {
                "gateway": "2402:8100:c::b5",
                "cidr": "2402:8100:c::b0/125",
                "start_ip": "2402:8100:c::b6",
                "end_ip": "2402:8100:c::b15"
            }
        }
    }

    Successful response result:
    HTTP/1.1 200 OK
    {
        "management": {
            "ip_v4": {
                "cidr": "192.168.88.0/24",
                "gateway": "192.168.88.233",
                "management_ipv4": "192.168.88.10/24"
            },
            "ip_v6": {
                "cidr": "2500:8100:c::b0/125",
                "gateway": "2500:8100:c::b16",
                "management_ipv6": "2500:8100:c::b10/125"
            }
        },
        "service": {
            "ip_v4": {
                "cidr": "192.168.89.0/24",
                "gateway": "192.168.89.1",
                "service_ipv4": "192.168.89.11/24"
            },
            "ip_v6": {
                "cidr": "2402:8100:c::b0/125",
                "gateway": "2402:8100:c::b5",
                "service_ipv6": "2402:8100:c::b7/125"
            }
        }
    }
    ```


