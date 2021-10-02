# gateway-nfv-plugin

## Architecture

Below is the architecture diagram:
![Architecture](images/nfv_plugin_architecture.jpg?raw=true)

## Requirements

- BlueCat Gateway Version: 20.6.1 or grater
- BAM/BDDS Version: 9.2 or grater

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

Before to setup `config` for Gateway NFV Plugin workflow, make sure you have the following file formats: `nfv_config.json`, `snmp_config.json` & `vm_config.ini`

1. Modify `config/nfv_config.json` and input the corresponding information:

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
    | `log_setting` | The necessary information for log setting |

2. Modify `config/snmp_config.json` and input the corresponding information for each BAM and BDDS:

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

3. Modify injected file contains management IP and service IP of the BDDS in the path `config/vm_config.ini`

4. Create and modify `.secret` and `.secretkey` files with the correct name in `nfv_config.json`. It must be in the same directory.

## Deployment
### Setup for docker compose

1. Pull NFV Gateway and NFV Scheduler image from Registry:

    ```
    docker login registry.bluecatlabs.net
    docker pull <image-registry-name>:<tag>
    ```
    
    > Example: docker pull registry.bluecatlabs.net/professional-services/japac-tma/
    gateway_nfv_plugin:nfv-gateway-master

    Or copy the <nfv-image>.tar.gz file to the host machine and run cmd:
    
    ```
    docker load -i <nfv-image>.tar.gz
    ```

### Configure Docker Compose

 Modify in `deployment/dockerfiles/docker-compose.yml` and input the corresponding information

1. Configure **bridge network**:

    ![DC Network](images/docker_compose_network.png?raw=true)

    Table overview of IPAddress configuration for each services in **docker-compose.yml**:

    | Services | ipv4_address | ipv6_address |
    | --- | --- |  --- |
    | `memcached_server` | 192.0.2.11 | 2001:DB8::2001:DB8:0:1 |
    | `gateway_nfv_scheduler` | 192.0.2.12 | 2001:DB8::2001:DB8:0:2 |
    | `nfv_gateway` | 192.0.2.13 | 2001:DB8::2001:DB8:0:3 |

2. Configure **Gateway Container**:

    ![DC BlueCat Gateway](images/docker_compose_nfv_gateway.png?raw=true)

    Where: 
    
    | Fields | Description | Example |
    | --- | --- | --- |
    | `image` | Docker images and version of Gateway Container. Currently, use the docker image from *Trouble Shooting UI* | trouble-shooting-ui|
    | `container_name` | The name of container | Default name: `nfv_gateway`|
    | `ports` | Port want to expose to external machine | Default port: `8088` |
    | `ipv4_address` | IPv4Address of container | Default IPv4: `192.0.2.13` |
    | `ipv6_address` | IPv6Address of container | Default IPv6: `2001:DB8::2001:DB8:0:3`|
    | `enviroment` | Environment of container | Mandatory for BAM_IP & LOCAL_USER_ID. Optional for SESSION_COOKIE_SECURE (use for Gateway v20.12.1 or greater) |
    | `volumes` | Configure mount directories | `<gw-logs-dir>:/logs` <br> `<nfv-config-dir>:/builtin/workflows/gateway_nfv_plugin/config/` |

3. Configure **Memcached** container

    ![DC Memcached](images/docker_compose_memcache.png?raw=true)

    | Fields | Description |
    | --- | --- | 
    | `image` | docker images and version of `memcached` |
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
>```
>chmod -R o=rwx <mapped volume>
>```


## Build the docker Scheduler Statistic Collection image

Using when you want to change code scheduler and rebuild it or not have Scheduler image from registry or **gateway_nfv_scheduler.tar**.

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

### Deploy by Docker Compose Command

1. Make sure to configured all the files with corresponding information before running build all of the containers: 

    ```bash
    docker-compose up -d
    ```

    > Note: Run each of service in **docker-compose.yml** by command:
    > ```bash
    > docker-compose up -d <name-of-service>
    > ```

2. To remove all of containers in docker compose, run command:

    ```bash
    docker-compose down --remove-orphans
    ```

## Generate Encrypted Password

1. Exc `nfv_gateway` to encrypted password by cmd:

    ```bash
     docker exec -it nfv_gateway  python3 /builtin/workflows/gateway_nfv_plugin/common/process_password.py
     ```
     
    > Note: or encrypt from `extracted-directory/gateway_nfv_plugin/common/process_password.py`:
    >```bash
    > python3 process_password.py
    > ```

2. Input the plaintext password and get the encrypted password.

    ```
    Example:
    Let's type a new password: example
    Your password is encrypted as: ZXhhbXBsZQ==
    Please update your encrypted password in nfv_config.json file
    ```

3. Copy it and save in `config/nfv_config.json` files.

4. Restart container:

    ```
    docker restart nfv_gateway
    ```
    
    ```
## API

### Scaling API

Request format:

| HTTP Request Method | URI |
| --- | --- |
| POST | /gateway_nfv_plugin/scale_out |
| POST | /gateway_nfv_plugin/scale_in |
    
#### Scale out API

1. Request parameters

    | Parameter Name | Description | Note |
    | --- | --- | --- |
    | server_name | Name of server | MANDATORY |
    | mgnt_server_ip | IPv4 address of server | OPTIONAL |
    | service_server_ipv4 | IPv4 address of server | OPTIONAL |
    | service_server_ipv6 | IPv6 address of server | OPTIONAL |
    | service_server_netmask | Netmask of IPv4 address | MANDATORY |
    | service_server_v6_prefix | Prefix of IPv6 address | OPTIONAL |
    | metadata | Currently only support `can_scale_in=true/false` UDF| OPTIONAL |

2. Response parameter

     Parameter Name | Description |
    | --- | --- |
    | error | Error message. If having error after scaling |
    | message | Success message |
    | status | Status after scaling |

3.  Sample

    ```
    POST /gateway_nfv_plugin/app_vm HTTP/1.1
    Host: example.com:5000
    Content-Type: application/json
    cache-control: no-cache
    Postman-Token: 0d883cb4-c64f-4a96-bdc6-c584cb32f195
     {
        "server_name": "bdds13",
        "mgnt_server_ip": "192.168.122.13",
        "service_server_ipv4": "192.168.122.12",
        "service_server_ipv6": "",
        "service_server_netmask": 24,
        "service_server_v6_prefix": "",
        "metadata": "can_scale_in=true"
    }

    Successful response result:
    HTTP/1.1 200 OK
    {
        "error": "",
        "message": "Scale out successfully",
        "status": "Successful"
    }
    ```

#### Scale in API

1. Request parameters

    | Parameter Name | Description |
    | --- | --- |
    | server_name | Name of server |

2. Response parameter

     Parameter Name | Description |
    | --- | --- |
    | error | Error message. If having error after scaling |
    | message | Success message |
    | status | Status after scaling |

3.  Sample

    ```
    POST /gateway_nfv_plugin/app_vm HTTP/1.1
    Host: example.com:5000
    Content-Type: application/json
    cache-control: no-cache
    Postman-Token: 0d883cb4-c64f-4a96-bdc6-c584cb32f195
     {
        "server_name": "bdds13"
    }

    Successful response result:
    HTTP/1.1 200 OK
    {
        "error": "",
        "message": "Scale in successfully",
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


